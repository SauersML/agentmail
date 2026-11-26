#!/usr/bin/env python3
"""Rooms across three hosts on loopback, every key a throwaway made here.

  python3 tests/rooms.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]

Hosts: "mac" (names hypha), "pod" (names ops.) and "lab" (names lab.), each trusting the others. Agents get their
keys and certificates from their first islandmail.py command. Checks: DM ids are symmetric; a plain thread works as
an open room; in a private room a member added later reads the earlier history through a key grant, while a
"since-join" room gives it none; after a leave or a removal no further room mail reaches that agent, and only the
creator removes others; @mentions wake `watch --mine` and `room watch --mentions`; MCPL registers rooms as channels,
folds room traffic in as ambient channels/incoming and wakes on a mention or a DM; `reply` round-trips reply_to with a
quote in the same room and privacy; /ui serves its page and its JSON endpoints list rooms and members.
Needs `websockets` (pip) for the MCPL checks.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, req, run, wait_for, work_directory  # noqa: E402

SYNC = 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    im = os.path.abspath(a.islandmail)
    work = work_directory(a.workdir)
    os.makedirs(os.path.join(work, "keys"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    hosts = ("mac", "pod", "lab")
    names = {"mac": ["hypha"], "pod": ["ops."], "lab": ["lab."]}
    pub = {h: run(bin_, "keygen", k(h)) for h in hosts}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts}
    api = {h: free_port() for h in hosts}
    network = run(bin_, "network-id")
    trust = {"v": 1, "network": network, "seq": 1, "members": [],
             "nodes": [{"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": names[h]} for h in hosts]}
    with open(os.path.join(work, "trust.json"), "w") as f:
        json.dump(trust, f)
    nodes = {h: Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                     "iroh_port": udp[h], "node_key_file": k(h),
                                     "members_file": os.path.join(work, "trust.json"), "sync_secs": SYNC})
             for h in hosts}
    home = {"hypha": "mac", "ops.orchestrator": "pod", "lab.carol": "lab"}
    user = {"hypha": "agent", "ops.orchestrator": "orchestrator", "lab.carol": "carol"}

    def cl(agent, *args, timeout=60):
        h = home[agent]
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=user[agent],
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h], ISLANDMAIL_AS=agent)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def bg(agent, *args):
        h = home[agent]
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=user[agent],
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h], ISLANDMAIL_AS=agent)
        return subprocess.Popen([sys.executable, im, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def js(agent, *args):
        rc, out = cl(agent, *args, "--json")
        try:
            return json.loads(out) if rc == 0 else None
        except ValueError:
            return None

    def token(agent):
        return cl(agent, "selftoken", "--ttl", "600")[1]

    def texts(agent, room):
        r = js(agent, "room", "read", room, "--latest", "200")
        return [m["text"] for m in r["messages"]] if r else []

    def rooms(agent):
        return {r["id"]: r for r in js(agent, "rooms") or []}

    try:
        for h in hosts:
            check("%s node starts" % h, nodes[h].start())
        for agent in home:
            rc, out = cl(agent, "whoami")
            check("%s gets its key and certificate" % agent, rc == 0, out[-160:])
        everyone = set(home)
        for agent in home:
            got, t = wait_for(lambda: everyone <= {x["name"] for x in req("GET", api[home[agent]], "/api/agents",
                                                                          token(agent))[1].get("agents", [])}, timeout=30)
            check("%s's host knows every agent" % agent, got, "%.1fs" % t)

        # DMs: one room whoever starts it; `send --private` to one agent with no thread lands there too.
        rc, out = cl("hypha", "dm", "ops.orchestrator", "hi from hypha")
        check("dm posts", rc == 0 and "your DM with ops.orchestrator" in out, out[-160:])
        rc, out = cl("ops.orchestrator", "send", "--private", "--to", "hypha", "hi back")
        check("private send to one agent goes to the DM room", rc == 0, out[-160:])
        dm = "dm:hypha+ops.orchestrator"
        for agent in ("hypha", "ops.orchestrator"):
            got, t = wait_for(lambda: rooms(agent).get(dm, {}).get("n") == 2, timeout=20)
            check("DM id is the same for both (%s sees 2 messages in %s)" % (agent, dm), got, "%.1fs" % t)
        r = rooms("ops.orchestrator").get(dm, {})
        check("a DM is listed under the other agent's name", r.get("label") == "hypha" and r.get("kind") == "dm", json.dumps(r)[:200])
        check("the third agent does not see the DM", dm not in rooms("lab.carol"))

        # A plain thread is an open room.
        rc, out = cl("hypha", "send", "--to", "all", "--thread", "release", "plan v1 is out")
        rc2, out2 = cl("ops.orchestrator", "room", "send", "release", "ack from ops")
        check("thread mail and a room post in the same open room", rc == 0 and rc2 == 0, (out + out2)[-200:])
        got, t = wait_for(lambda: texts("lab.carol", "release") == ["plan v1 is out", "ack from ops"], timeout=20)
        check("a third agent reads the open room in order", got, "%.1fs" % t)
        info = js("lab.carol", "room", "info", "release")
        check("open room info lists participants", info and info["kind"] == "open"
              and set(info["members"]) == {"hypha", "ops.orchestrator"}, json.dumps(info)[:200])
        unread = rooms("lab.carol").get("release", {}).get("unread")
        check("rooms shows unread counts (read marks them read)", unread == 0, str(unread))

        # A private room; carol, added later, reads the earlier history through a key grant.
        rc, out = cl("hypha", "room", "create", "plan", "--private", "--with", "ops.orchestrator", "--topic", "ship it")
        check("create a private room", rc == 0 and "hypha/plan" in out, out[-160:])
        cl("hypha", "room", "send", "hypha/plan", "secret one")
        got, t = wait_for(lambda: "secret one" in texts("ops.orchestrator", "hypha/plan"), timeout=20)
        check("the invited member reads it on its own host", got, "%.1fs" % t)
        rc, out = cl("ops.orchestrator", "room", "send", "hypha/plan", "secret two")
        check("any member posts", rc == 0, out[-160:])
        got, _ = wait_for(lambda: "secret two" in texts("hypha", "hypha/plan"), timeout=20)
        time.sleep(SYNC * 2)
        rc, out = cl("lab.carol", "room", "read", "hypha/plan")
        check("a non-member cannot see the private room", rc != 0 and "404" in out, out[-160:])
        rc, out = cl("lab.carol", "room", "send", "hypha/plan", "let me in")
        check("nor post in it", rc != 0, out[-160:])
        check("and it is not in its room list", "hypha/plan" not in rooms("lab.carol"))
        rc, out = cl("ops.orchestrator", "room", "add", "hypha/plan", "lab.carol")
        check("a member (not the creator) adds carol with full history", rc == 0 and "earlier messages" in out, out[-200:])
        got, t = wait_for(lambda: {"secret one", "secret two"} <= set(texts("lab.carol", "hypha/plan")), timeout=25)
        check("the joiner reads the earlier history through the grant", got, "%.1fs" % t)
        info = js("lab.carol", "room", "info", "hypha/plan")
        check("room state: members, topic, creator", info and info["members"] == ["hypha", "lab.carol", "ops.orchestrator"]
              and info["topic"] == "ship it" and info["creator"] == "hypha", json.dumps(info)[:240])

        # "since join": no grants, no history.
        rc, out = cl("hypha", "room", "create", "quiet", "--private", "--history", "since-join", "--with", "ops.orchestrator")
        cl("hypha", "room", "send", "hypha/quiet", "before carol")
        rc, out = cl("hypha", "room", "add", "hypha/quiet", "lab.carol")
        check("adding to a since-join room says so", rc == 0 and "only messages from now on" in out, out[-200:])
        cl("hypha", "room", "send", "hypha/quiet", "after carol")
        got, t = wait_for(lambda: "after carol" in texts("lab.carol", "hypha/quiet"), timeout=20)
        check("since-join: the joiner reads later messages", got, "%.1fs" % t)
        time.sleep(SYNC * 2)
        check("since-join: but none from before", "before carol" not in texts("lab.carol", "hypha/quiet"),
              str(texts("lab.carol", "hypha/quiet")))

        # Leave and remove: nothing sent afterwards reaches them; only the creator removes others.
        rc, out = cl("lab.carol", "room", "remove", "hypha/quiet", "hypha")
        check("a non-creator cannot remove others", rc != 0 and "creator" in out, out[-160:])
        rc, out = cl("lab.carol", "room", "leave", "hypha/plan")
        check("carol leaves hypha/plan", rc == 0, out[-160:])
        got, _ = wait_for(lambda: "lab.carol" not in (js("hypha", "room", "info", "hypha/plan") or {}).get("members", ["lab.carol"]), timeout=20)
        check("the leave replicates to the creator's host", got)
        cl("hypha", "room", "send", "hypha/plan", "after carol left")
        got, _ = wait_for(lambda: "after carol left" in texts("ops.orchestrator", "hypha/plan"), timeout=20)
        check("the remaining member gets it", got)
        rc, out = cl("hypha", "room", "remove", "hypha/quiet", "ops.orchestrator")
        check("the creator removes a member", rc == 0, out[-160:])
        cl("hypha", "room", "send", "hypha/quiet", "after ops removed")
        got, _ = wait_for(lambda: "after ops removed" in texts("lab.carol", "hypha/quiet"), timeout=20)
        check("a remaining member gets the next message", got)
        time.sleep(SYNC * 3)
        check("the leaver gets nothing sent after the leave", "after carol left" not in texts("lab.carol", "hypha/plan"))
        check("the removed member gets nothing sent after the removal",
              "after ops removed" not in texts("ops.orchestrator", "hypha/quiet"))
        st, raw = req("GET", api["pod"], "/api/messages?thread=hypha/quiet&limit=200", token("ops.orchestrator"))
        check("(not even as a row it may read)", st == 200 and all(m["text"] != "after ops removed" for m in raw["messages"]))

        # Mentions wake watchers.
        w = bg("ops.orchestrator", "watch", "--mine", "--until", "--name", "mention")
        rw = bg("ops.orchestrator", "room", "watch", "release", "--mentions", "--until")
        time.sleep(2)
        cl("hypha", "room", "send", "release", "a note for nobody in particular")
        time.sleep(SYNC * 2)
        check("an unaddressed room post wakes no one", w.poll() is None and rw.poll() is None)
        cl("hypha", "room", "send", "release", "@ops.orchestrator please look at the release")
        try:
            out, _ = w.communicate(timeout=30)
            check("an @mention wakes watch --mine", w.returncode == 0 and "please look" in out, out[-200:])
            out, _ = rw.communicate(timeout=30)
            check("and room watch --mentions", rw.returncode == 0 and "please look" in out and "mentions you" in out, out[-200:])
        except subprocess.TimeoutExpired:
            check("an @mention wakes watch --mine", False, "timed out")
            w.kill()
            rw.kill()

        # reply: same room and privacy, reply_to and a quote.
        msgs = js("ops.orchestrator", "room", "read", "hypha/plan")["messages"]
        orig = [m for m in msgs if m["text"] == "secret one"][0]
        rc, out = cl("ops.orchestrator", "reply", str(orig["id"]), "re: secret one, agreed")
        check("reply posts", rc == 0 and "hypha/plan" in out, out[-160:])
        got, t = wait_for(lambda: [m for m in (js("hypha", "room", "read", "hypha/plan") or {}).get("messages", [])
                                   if m["text"] == "re: secret one, agreed"], timeout=20)
        m = got[0] if got else {}
        check("reply_to round trip with a quote, in the same private room", m.get("reply_to") == orig["env"]
              and m.get("quote", {}).get("from") == "hypha" and m.get("mode") == "private" and m.get("thread") == "hypha/plan",
              json.dumps(m)[:300])
        legacy = [m for m in js("lab.carol", "room", "read", "release")["messages"] if m["text"] == "plan v1 is out"][0]
        rc, out = cl("lab.carol", "reply", str(legacy["id"]), "nice")
        got, _ = wait_for(lambda: [m for m in js("hypha", "room", "read", "release")["messages"]
                                   if m["text"] == "nice" and m.get("quote", {}).get("text") == "plan v1 is out"
                                   and m["to"] == "hypha"], timeout=20)
        check("reply to plain thread mail goes back to its sender in its thread", rc == 0 and got, out[-160:])

        mcpl_checks(api, cl, token)

        # /ui: the page, a view key, JSON rooms and members.
        with urllib.request.urlopen("http://127.0.0.1:%d/ui" % api["mac"], timeout=10) as r:
            page = r.read().decode()
            check("/ui serves an HTML page", r.status == 200 and r.headers["Content-Type"].startswith("text/html")
                  and "<html" in page.lower() and "default-src 'none'" in r.headers["Content-Security-Policy"])
        rc, out = cl("hypha", "ui")
        key = out.split("#k=")[1].split()[0] if "#k=" in out else ""
        check("islandmail.py ui prints a link with a view key", rc == 0 and key, out[-160:])
        st, body = req("GET", api["mac"], "/ui/api/rooms", "ui." + key)
        ids = {r["id"]: r for r in body.get("rooms", [])}
        check("/ui/api/rooms lists the viewer's rooms", st == 200 and {"hypha/plan", "hypha/quiet", "release", dm} <= set(ids),
              str(sorted(ids)))
        check("with members and unread counts", ids.get("hypha/plan", {}).get("members") == ["hypha", "ops.orchestrator"]
              and "unread" in ids.get("hypha/plan", {}), json.dumps(ids.get("hypha/plan"))[:240])
        st, body = req("GET", api["mac"], "/ui/api/messages?room=hypha/plan&limit=50", "ui." + key)
        check("/ui/api/messages returns the room and its messages", st == 200 and body["room"]["kind"] == "private"
              and any(m["text"] == "secret one" for m in body["messages"]), str(st))
        st, _ = req("GET", api["mac"], "/ui/api/rooms", "ui.wrong")
        st2, _ = req("GET", api["mac"], "/ui/api/rooms", token("hypha"))
        check("/ui JSON needs a view key (an agent token is not one)", st == 401 and st2 == 401, "%d %d" % (st, st2))
        st, _ = req("POST", api["mac"], "/ui/api/rooms", "ui." + key, {})
        check("/ui is read-only", st == 405, str(st))
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


def mcpl_checks(api, cl, token):
    """An MCPL 0.5 host as ops.orchestrator: rooms register as channels; ambient room traffic arrives as
    channels/incoming; a mention on a closed channel and a DM arrive as push/event that wakes."""
    try:
        import asyncio
        import websockets
    except ImportError:
        check("MCPL checks (websockets not installed)", False)
        return

    async def go():
        url = "ws://127.0.0.1:%d/mcpl" % api["pod"]
        hdr = {"Authorization": "Bearer " + token("ops.orchestrator")}
        try:
            ws = await websockets.connect(url, additional_headers=hdr)
        except TypeError:
            ws = await websockets.connect(url, extra_headers=hdr)
        seen = []

        async def recv_until(pred, timeout=25):
            end = time.time() + timeout
            while time.time() < end:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=max(0.1, end - time.time()))
                except asyncio.TimeoutError:
                    break
                for line in raw.split("\n"):
                    if not line.strip():
                        continue
                    m = json.loads(line)
                    seen.append(m)
                    if m.get("method") == "channels/incoming":
                        msgs = m["params"]["messages"]
                        await ws.send(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {
                            "results": [{"messageId": x["messageId"], "accepted": True} for x in msgs]}}))
                    elif m.get("method") == "push/event":
                        await ws.send(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"accepted": True}}))
                    elif m.get("method") == "channels/register":
                        await ws.send(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {}}))
                    if pred(m):
                        return m
            return None

        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {"experimental": {"mcpl": {"version": "0.5"}}},
            "clientInfo": {"name": "rooms-test", "version": "0"}}}))
        init = await recv_until(lambda m: m.get("id") == 1)
        caps = (init or {}).get("result", {}).get("capabilities", {}).get("experimental", {}).get("mcpl", {})
        check("MCPL advertises rooms as channels", caps.get("channels", {}).get("incoming") is True
              and "rooms" in caps.get("featureSets", {}), json.dumps(caps)[:200])
        await ws.send(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "featureSets/update", "params": {
            "effectiveCapabilities": ["tools", "pushEvents", "channels"]}}))
        reg = await recv_until(lambda m: m.get("method") == "channels/register")
        chans = {c["id"]: c for c in (reg or {}).get("params", {}).get("channels", [])}
        check("each room is a registered channel", {"room:hypha/plan", "room:release", "room:dm:hypha+ops.orchestrator"} <= set(chans),
              str(sorted(chans)))
        check("rooms the agent is in start open", chans.get("room:hypha/plan", {}).get("initiallyOpen") is True)
        # Drain the backlog: earlier room traffic on open channels is delivered first.
        await recv_until(lambda m: False, timeout=4)
        mark = len(seen)
        cl("hypha", "room", "send", "release", "ambient chatter kumquat")
        m = await recv_until(lambda m: m.get("method") == "channels/incoming"
                             and "kumquat" in m["params"]["messages"][0]["content"][0]["text"])
        tags = m["params"]["messages"][0]["tags"] if m else []
        check("room traffic arrives as ambient channels/incoming", m and "chat:ambient" in tags
              and m["params"]["messages"][0]["channelId"] == "room:release", str(tags))
        cl("hypha", "room", "send", "hypha/plan", "@ops.orchestrator mention on an open channel")
        m = await recv_until(lambda m: m.get("method") == "channels/incoming"
                             and "mention on an open" in m["params"]["messages"][0]["content"][0]["text"])
        md = m["params"]["messages"][0] if m else {}
        check("a mention on an open channel is flagged to wake", "chat:mention" in md.get("tags", [])
              and md.get("metadata", {}).get("isMention") is True, str(md.get("tags")))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "channels/close", "params": {"channelId": "room:hypha/plan"}}))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "channels/close", "params": {"channelId": "room:dm:hypha+ops.orchestrator"}}))
        await recv_until(lambda m: m.get("id") == 4)
        cl("hypha", "room", "send", "hypha/plan", "no mention here on a closed channel")
        cl("hypha", "room", "send", "hypha/plan", "@ops.orchestrator closed-channel mention")
        m = await recv_until(lambda m: m.get("method") == "push/event"
                             and "closed-channel mention" in m["params"]["payload"]["content"][0]["text"])
        check("a mention on a closed channel wakes via push/event", m and "chat:mention" in m["params"]["tags"]
              and m["params"]["origin"].get("isMention") is True, str(m and m["params"]["tags"]))
        cl("hypha", "dm", "ops.orchestrator", "a dm for the host")
        m = await recv_until(lambda m: m.get("method") == "push/event"
                             and "a dm for the host" in m["params"]["payload"]["content"][0]["text"])
        check("a DM wakes via push/event", m and "chat:dm" in m["params"]["tags"] and m["params"]["origin"].get("isDM") is True)
        quiet = [x for x in seen[mark:] if x.get("method") in ("push/event", "channels/incoming")
                 and "no mention here" in json.dumps(x)]
        check("unmentioned traffic on a closed channel is not pushed", not quiet)
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 5, "method": "channels/publish", "params": {
            "channelId": "room:release", "conversationId": "c", "content": [{"type": "text", "text": "from the host"}]}}))
        r = await recv_until(lambda m: m.get("id") == 5)
        # The node signs channel posts only for agents whose identity file it holds (identities_dir).
        check("channels/publish answers (refused here: no identities_dir)", r is not None, json.dumps(r)[:200])
        await ws.close()

    asyncio.run(go())


if __name__ == "__main__":
    main()
