#!/usr/bin/env python3
"""Rooms across three hosts on loopback, every key a throwaway made here.

  python3 tests/rooms.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]

Hosts: "mac" (names alice), "pod" (names ops.) and "dev" (names dev.), each trusting the others. Agents get their
keys and certificates from their first islandmail.py command. Checks: DM ids are symmetric; a plain thread works as
an open room; in a private room a member added later reads the earlier history through a key grant, while a
"since-join" room gives it none; after a leave or a removal no further room mail reaches that agent, and only the
creator removes others; @mentions wake `watch --mine` and `room watch --mentions`; MCPL registers rooms as channels,
folds room traffic in as ambient channels/incoming and wakes on a mention or a DM; `reply` round-trips reply_to with a
quote in the same room and privacy; /ui serves its page and its JSON endpoints list rooms and members.
Needs `websockets` (pip) for the MCPL checks.
"""
import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
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
    hosts = ("mac", "pod", "dev")
    names = {"mac": ["alice"], "pod": ["ops."], "dev": ["dev."]}
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
    home = {"alice": "mac", "ops.bob": "pod", "dev.carol": "dev"}
    user = {"alice": "agent", "ops.bob": "bob", "dev.carol": "carol"}

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

    def chat(agent, *args, stdin="", timeout=60):
        h = home[agent]
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=user[agent],
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h], ISLANDMAIL_AS=agent)
        p = subprocess.run([sys.executable, im, "chat", *args], input=stdin, env=env, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def chat_bg(agent, *args):
        h = home[agent]
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=user[agent],
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h], ISLANDMAIL_AS=agent)
        return subprocess.Popen([sys.executable, im, "chat", *args], env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

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

        # DMs: one room whoever starts it; `send` to one agent with no thread lands there too.
        rc, out = cl("alice", "dm", "ops.bob", "hi from alice")
        check("dm posts", rc == 0 and "your DM with ops.bob" in out, out[-160:])
        rc, out = cl("ops.bob", "send", "--to", "alice", "hi back")
        check("private send to one agent goes to the DM room", rc == 0, out[-160:])
        dm = "dm:alice+ops.bob"
        for agent in ("alice", "ops.bob"):
            got, t = wait_for(lambda: rooms(agent).get(dm, {}).get("n") == 2, timeout=20)
            check("DM id is the same for both (%s sees 2 messages in %s)" % (agent, dm), got, "%.1fs" % t)
        r = rooms("ops.bob").get(dm, {})
        check("a DM is listed under the other agent's name", r.get("label") == "alice" and r.get("kind") == "dm", json.dumps(r)[:200])
        check("the third agent does not see the DM", dm not in rooms("dev.carol"))

        # A plain thread is an open room.
        rc, out = cl("alice", "send", "--open", "--to", "all", "--thread", "release", "plan v1 is out")
        rc2, out2 = cl("ops.bob", "room", "send", "release", "ack from ops")
        check("thread mail and a room post in the same open room", rc == 0 and rc2 == 0, (out + out2)[-200:])
        got, t = wait_for(lambda: texts("dev.carol", "release") == ["plan v1 is out", "ack from ops"], timeout=20)
        check("a third agent reads the open room in order", got, "%.1fs" % t)
        info = js("dev.carol", "room", "info", "release")
        check("open room info lists participants", info and info["kind"] == "open"
              and set(info["members"]) == {"alice", "ops.bob"}, json.dumps(info)[:200])
        unread = rooms("dev.carol").get("release", {}).get("unread")
        check("rooms shows unread counts (read marks them read)", unread == 0, str(unread))

        # A private room; carol, added later, reads the earlier history through a key grant.
        rc, out = cl("alice", "room", "create", "plan", "--with", "ops.bob", "--topic", "ship it")
        check("create a private room", rc == 0 and "alice/plan" in out, out[-160:])
        cl("alice", "room", "send", "alice/plan", "secret one")
        got, t = wait_for(lambda: "secret one" in texts("ops.bob", "alice/plan"), timeout=20)
        check("the invited member reads it on its own host", got, "%.1fs" % t)
        rc, out = cl("ops.bob", "room", "send", "alice/plan", "secret two")
        check("any member posts", rc == 0, out[-160:])
        got, _ = wait_for(lambda: "secret two" in texts("alice", "alice/plan"), timeout=20)
        time.sleep(SYNC * 2)
        rc, out = cl("dev.carol", "room", "read", "alice/plan")
        check("a non-member cannot see the private room", rc != 0 and "404" in out, out[-160:])
        rc, out = cl("dev.carol", "room", "send", "alice/plan", "let me in")
        check("nor post in it", rc != 0, out[-160:])
        check("and it is not in its room list", "alice/plan" not in rooms("dev.carol"))
        rc, out = cl("ops.bob", "room", "add", "alice/plan", "dev.carol")
        check("a member (not the creator) adds carol with full history", rc == 0 and "earlier messages" in out, out[-200:])
        got, t = wait_for(lambda: {"secret one", "secret two"} <= set(texts("dev.carol", "alice/plan")), timeout=25)
        check("the joiner reads the earlier history through the grant", got, "%.1fs" % t)
        info = js("dev.carol", "room", "info", "alice/plan")
        check("room state: members, topic, creator", info and info["members"] == ["alice", "dev.carol", "ops.bob"]
              and info["topic"] == "ship it" and info["creator"] == "alice", json.dumps(info)[:240])

        # "since join": no grants, no history.
        rc, out = cl("alice", "room", "create", "quiet", "--history", "since-join", "--with", "ops.bob")
        cl("alice", "room", "send", "alice/quiet", "before carol")
        rc, out = cl("alice", "room", "add", "alice/quiet", "dev.carol")
        check("adding to a since-join room says so", rc == 0 and "only messages from now on" in out, out[-200:])
        cl("alice", "room", "send", "alice/quiet", "after carol")
        got, t = wait_for(lambda: "after carol" in texts("dev.carol", "alice/quiet"), timeout=20)
        check("since-join: the joiner reads later messages", got, "%.1fs" % t)
        time.sleep(SYNC * 2)
        check("since-join: but none from before", "before carol" not in texts("dev.carol", "alice/quiet"),
              str(texts("dev.carol", "alice/quiet")))

        # Leave and remove: nothing sent afterwards reaches them; only the creator removes others.
        rc, out = cl("dev.carol", "room", "remove", "alice/quiet", "alice")
        check("a non-creator cannot remove others", rc != 0 and "creator" in out, out[-160:])
        rc, out = cl("dev.carol", "room", "leave", "alice/plan")
        check("carol leaves alice/plan", rc == 0, out[-160:])
        got, _ = wait_for(lambda: "dev.carol" not in (js("alice", "room", "info", "alice/plan") or {}).get("members", ["dev.carol"]), timeout=20)
        check("the leave replicates to the creator's host", got)
        cl("alice", "room", "send", "alice/plan", "after carol left")
        got, _ = wait_for(lambda: "after carol left" in texts("ops.bob", "alice/plan"), timeout=20)
        check("the remaining member gets it", got)
        rc, out = cl("alice", "room", "remove", "alice/quiet", "ops.bob")
        check("the creator removes a member", rc == 0, out[-160:])
        cl("alice", "room", "send", "alice/quiet", "after ops removed")
        got, _ = wait_for(lambda: "after ops removed" in texts("dev.carol", "alice/quiet"), timeout=20)
        check("a remaining member gets the next message", got)
        time.sleep(SYNC * 3)
        check("the leaver gets nothing sent after the leave", "after carol left" not in texts("dev.carol", "alice/plan"))
        check("the removed member gets nothing sent after the removal",
              "after ops removed" not in texts("ops.bob", "alice/quiet"))
        st, raw = req("GET", api["pod"], "/api/messages?thread=alice/quiet&limit=200", token("ops.bob"))
        check("(not even as a row it may read)", st == 200 and all(m["text"] != "after ops removed" for m in raw["messages"]))

        # Mentions wake watchers.
        w = bg("ops.bob", "watch", "--mine", "--until", "--name", "mention")
        rw = bg("ops.bob", "room", "watch", "release", "--mentions", "--until")
        time.sleep(2)
        cl("alice", "room", "send", "release", "a note for nobody in particular")
        time.sleep(SYNC * 2)
        check("an unaddressed room post wakes no one", w.poll() is None and rw.poll() is None)
        cl("alice", "room", "send", "release", "@ops.bob please look at the release")
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
        msgs = js("ops.bob", "room", "read", "alice/plan")["messages"]
        orig = [m for m in msgs if m["text"] == "secret one"][0]
        rc, out = cl("ops.bob", "reply", orig["id"], "re: secret one, agreed")
        check("reply posts", rc == 0 and "alice/plan" in out, out[-160:])
        got, t = wait_for(lambda: [m for m in (js("alice", "room", "read", "alice/plan") or {}).get("messages", [])
                                   if m["text"] == "re: secret one, agreed"], timeout=20)
        m = got[0] if got else {}
        check("reply_to round trip with a quote, in the same private room", m.get("reply_to") == orig["id"]
              and m.get("quote", {}).get("from") == "alice" and m.get("mode") == "private" and m.get("thread") == "alice/plan",
              json.dumps(m)[:300])
        legacy = [m for m in js("dev.carol", "room", "read", "release")["messages"] if m["text"] == "plan v1 is out"][0]
        rc, out = cl("dev.carol", "reply", legacy["id"], "nice")
        got, _ = wait_for(lambda: [m for m in js("alice", "room", "read", "release")["messages"]
                                   if m["text"] == "nice" and m.get("quote", {}).get("text") == "plan v1 is out"
                                   and m["to"] == "alice"], timeout=20)
        check("reply to plain thread mail goes back to its sender in its thread", rc == 0 and got, out[-160:])

        issue12_checks(cl, js, req, api, token, bg, orig)
        owner_cfg = os.path.join(work, "mac-owner.json")
        with open(owner_cfg, "w") as f:
            json.dump({"api_listen": "127.0.0.1:%d" % api["mac"], "node_key_file": k("mac"),
                       "members_file": os.path.join(work, "trust.json")}, f)
        group_chat_checks(cl, js, req, api, chat, chat_bg, owner_cfg, bin_)
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-mac"), USER="agent",
                   ISLANDMAIL_URL="https://mail.example.invalid", ISLANDMAIL_AS="alice")
        p = subprocess.run([sys.executable, im, "ui", "--post"], env=env, capture_output=True, text=True, timeout=60)
        check("ui --post never sends the agent key to a node off this machine", p.returncode != 0
              and "loopback" in p.stderr, (p.stdout + p.stderr)[-160:])
        mcpl_checks(api, cl, token)

        # /ui: the page, a view key, JSON rooms and members.
        with urllib.request.urlopen("http://127.0.0.1:%d/ui" % api["mac"], timeout=10) as r:
            page = r.read().decode()
            check("/ui shows a reply's parent as a quote, its id only on hover", "'\u21b3 re ' + m.reply_to" not in page
                  and "'Reply to ' + (m.quote.id" in page)
            check("/ui puts network text into the page as text only (no innerHTML)", "innerHTML" not in page
                  and "outerHTML" not in page and "insertAdjacentHTML" not in page)
            check("/ui serves an HTML page", r.status == 200 and r.headers["Content-Type"].startswith("text/html")
                  and "<html" in page.lower() and "default-src 'none'" in r.headers["Content-Security-Policy"])
        rc, out = cl("alice", "ui")
        key = out.split("#k=")[1].split()[0] if "#k=" in out else ""
        check("islandmail.py ui prints a link with a view key", rc == 0 and key, out[-160:])
        st, body = req("GET", api["mac"], "/ui/api/rooms", "ui." + key)
        ids = {r["id"]: r for r in body.get("rooms", [])}
        check("/ui/api/rooms lists the viewer's rooms", st == 200 and {"alice/plan", "alice/quiet", "release", dm} <= set(ids),
              str(sorted(ids)))
        check("with members and unread counts", ids.get("alice/plan", {}).get("members") == ["alice", "ops.bob"]
              and "unread" in ids.get("alice/plan", {}), json.dumps(ids.get("alice/plan"))[:240])
        st, body = req("GET", api["mac"], "/ui/api/messages?room=alice/plan&limit=50", "ui." + key)
        check("/ui/api/messages returns the room and its messages", st == 200 and body["room"]["kind"] == "private"
              and any(m["text"] == "secret one" for m in body["messages"]), str(st))
        cli_order = [m["env"] for m in (js("alice", "room", "read", "alice/plan", "--latest", "50") or {}).get("messages", [])]
        check("/ui gets the same display order as room read", [m["env"] for m in body["messages"]] == cli_order,
              "%d vs %d" % (len(body["messages"]), len(cli_order)))
        since = max(m["seq"] for m in body["messages"])
        cl("alice", "room", "send", "alice/plan", "for the ui poll")
        st, body = req("GET", api["mac"], "/ui/api/messages?room=alice/plan&since=%d" % since, "ui." + key)
        check("/ui since=SEQ returns what arrived after it", st == 200 and [m["text"] for m in body["messages"]] == ["for the ui poll"],
              json.dumps(body)[:200])
        st, _ = req("GET", api["mac"], "/ui/api/rooms", "ui.wrong")
        st2, _ = req("GET", api["mac"], "/ui/api/rooms", token("alice"))
        check("/ui JSON needs a view key (an agent token is not one)", st == 401 and st2 == 401, "%d %d" % (st, st2))
        st, _ = req("POST", api["mac"], "/ui/api/rooms", "ui." + key, {})
        check("/ui is read-only", st == 405, str(st))
        # A local agent of a member's node that is not in the room learns nothing about it from /ui, as from GET /api/room.
        home["ops.eve"], user["ops.eve"] = "pod", "eve"
        rc, out = cl("ops.eve", "ui")
        ekey = out.split("#k=")[1].split()[0] if "#k=" in out else ""
        st, body = req("GET", api["pod"], "/ui/api/messages?room=alice/plan&limit=50", "ui." + ekey)
        check("/ui/api/messages hides a private room from a non-member", rc == 0 and ekey and st == 404
              and "ops.bob" not in json.dumps(body), "%s %s" % (st, json.dumps(body)[:200]))
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


def b32(env):
    return base64.b32encode(bytes.fromhex(env)).decode().lower().rstrip("=")


def group_chat_checks(cl, js, req, api, chat, chat_bg, owner_cfg, bin_):
    """Rooms as a group chat: room new in one line, chat in a terminal (piped here), and posting from /ui."""
    rc, out = cl("alice", "room", "new", "crew", "@ops.bob", "dev.carol", "@nobody.here", "--topic", "ship it")
    check("room new NAME @a @b makes the room with its members", rc == 0
          and "created alice/crew with @ops.bob, @dev.carol" in out, out[-240:])
    check("without the node key, it prints the exact invite command for a name not on the network",
          "@nobody.here is not on this network yet" in out and "islandmail.py invite --name nobody.here --room alice/crew" in out
          and "chat: islandmail.py chat alice/crew" in out, out[-240:])
    rc, out = cl("alice", "room", "new", "crew2", "@ops.bob", "@ghost.x", "--config", owner_cfg)
    inv = next((w for w in out.split() if w.startswith("im1")), "")
    try:
        body = json.loads(subprocess.run([bin_, "invite-info", inv], capture_output=True, text=True).stdout)
    except ValueError:
        body = {}
    check("as the node operator, room new prints a ready invite into the new room", rc == 0
          and body.get("name") == "ghost.x" and body.get("room") == "alice/crew2" and body.get("from") == "alice"
          and "islandmail.py accept REPLY" in out, json.dumps(body)[:200] + out[-200:])
    check("and still makes the room with the members it knows", (js("alice", "room", "info", "alice/crew2") or {})
          .get("members") == ["alice", "ops.bob"])
    info = js("alice", "room", "info", "alice/crew") or {}
    check("a group chat: private, full history, every member", info.get("kind") == "private" and info.get("history") == "full"
          and info.get("members") == ["alice", "dev.carol", "ops.bob"] and info.get("topic") == "ship it", json.dumps(info)[:200])
    wait_for(lambda: (js("ops.bob", "room", "info", "alice/crew") or {}).get("member"), timeout=20)

    # A live chat that stays open while another member posts: the post scrolls in.
    live = chat_bg("alice", "alice/crew", "--no-tty")
    time.sleep(3)
    cl("dev.carol", "room", "send", "alice/crew", "carol here, posting from the CLI")
    time.sleep(SYNC * 3)
    try:
        out, _ = live.communicate("/quit\n", timeout=30)
    except subprocess.TimeoutExpired:
        live.kill()
        out, _ = live.communicate()
    tail = out.split("/help for commands)", 1)[-1]
    check("chat shows messages as they arrive", "dev.carol: carol here, posting from the CLI" in tail, out[-300:])
    check("with the room, its members and topic on top", out.startswith("alice/crew \u00b7 private \u00b7 alice, dev.carol, ops.bob")
          and "ship it" in out.splitlines()[1], out[:200])

    # Piped input: each line is a message or a /command; @prefixes complete to member names.
    first = [m for m in js("ops.bob", "room", "read", "alice/crew")["messages"] if m["text"].startswith("carol here")][0]
    rc, out = chat("ops.bob", "alice/crew", stdin="hello crew @dev, tests are green\n/topic ship friday\n"
                   "/reply %s seen it\n/members\n" % first["id"][:5])
    check("chat posts typed lines and echoes them", rc == 0 and "ops.bob: hello crew @dev.carol, tests are green" in out, out[-400:])
    check("/members lists the room", "members: alice, dev.carol, ops.bob" in out, out[-300:])
    got, _ = wait_for(lambda: [m for m in js("alice", "room", "read", "alice/crew")["messages"] if m["from"] == "ops.bob"],
                      timeout=20)
    texts = [m["text"] for m in got or []]
    hello = [m for m in got or [] if m["text"].startswith("hello crew")]
    check("@dev completed to a real mention", hello and hello[0].get("mentions") == ["dev.carol"], json.dumps(hello)[:200])
    check("/topic sets the topic", (js("alice", "room", "info", "alice/crew") or {}).get("topic") == "ship friday")
    reply = [m for m in got or [] if m["text"] == "seen it"]
    check("/reply ID answers in place", reply and reply[0].get("reply_to") == first["id"], str(texts))
    rc, out = chat("alice", "alice/crew", stdin="")
    lines = out.splitlines()
    i = next((k for k, l in enumerate(lines) if ": seen it" in l), 0)
    check("chat shows a reply under a \u21b3 line", i and lines[i - 1].strip().startswith("\u21b3 re %s dev.carol: carol here" % first["id"]),
          "\n".join(lines[max(0, i - 2):i + 1]))

    # /add (with the history) and /leave from the chat; chat @NAME is the DM.
    cl("alice", "room", "new", "duo", "@ops.bob")
    cl("alice", "room", "send", "alice/duo", "before carol")
    rc, out = chat("alice", "alice/duo", stdin="/add dev.carol\n")
    check("/add adds a member", rc == 0 and "added dev.carol" in out and "earlier messages" in out, out[-200:])
    got, _ = wait_for(lambda: "before carol" in [m["text"] for m in (js("dev.carol", "room", "read", "alice/duo") or {}).get("messages", [])],
                      timeout=30)
    check("who then reads the history", got)
    rc, out = chat("dev.carol", "alice/duo", stdin="/leave\n")
    got, _ = wait_for(lambda: "dev.carol" in (js("alice", "room", "info", "alice/duo") or {}).get("former", []), timeout=30)
    check("/leave leaves", rc == 0 and "you left alice/duo" in out and got, out[-200:])
    rc, out = chat("dev.carol", "@alice", stdin="hi from the chat\n")
    got, _ = wait_for(lambda: "hi from the chat" in [m["text"] for m in (js("alice", "room", "read", "dm:alice+dev.carol") or {})
                                                      .get("messages", [])], timeout=30)
    check("chat @agent is the DM, a two-person room", rc == 0 and got, out[-200:])

    # /ui with a posting key: post, reply, start a room, clear unread; a read-only key cannot post.
    rc, out = cl("alice", "ui", "--post")
    key = out.split("#k=")[1].split()[0] if "#k=" in out else ""
    rc2, out2 = cl("alice", "ui")
    ro = out2.split("#k=")[1].split()[0] if "#k=" in out2 else ""
    st, me = req("GET", api["mac"], "/ui/api/me", "ui." + key)
    check("ui --post gives a key that can post", rc == 0 and st == 200 and me.get("post") is True and "dev.carol" in me.get("agents", []),
          out[-160:])
    st, r = req("POST", api["mac"], "/ui/api/messages", "ui." + key, {"room": "alice/crew", "text": "from the browser @ops.bob"})
    check("/ui posts into a room as the agent", st == 201 and r["message"]["from"] == "alice" and r["message"]["mentions"] == ["ops.bob"],
          json.dumps(r)[:200])
    got, _ = wait_for(lambda: "from the browser @ops.bob" in [m["text"] for m in js("ops.bob", "room", "read", "alice/crew")
                                                                        ["messages"]], timeout=30)
    check("signed, so other nodes accept it", got)
    st, r = req("POST", api["mac"], "/ui/api/messages", "ui." + key, {"room": "alice/crew", "text": "agreed", "reply_to": first["id"][:6]})
    check("/ui replies in place", st == 201 and r["message"].get("reply_to") == first["id"] and r["message"]["mode"] == "private",
          json.dumps(r)[:200])
    st, r = req("POST", api["mac"], "/ui/api/messages", "ui." + ro, {"room": "alice/crew", "text": "nope"})
    check("a read-only key cannot post", st == 403, str(st))
    st, r = req("POST", api["mac"], "/ui/api/rooms/new", "ui." + key, {"name": "from-ui", "members": ["@ops.bob", "ghost"]})
    check("/ui starts a room (New room)", st == 201 and r.get("room") == "alice/from-ui" and r.get("unknown") == ["ghost"], json.dumps(r))
    got, _ = wait_for(lambda: "alice/from-ui" in {x["id"] for x in js("ops.bob", "rooms") or []}, timeout=30)
    check("and its members see it", got)
    st, r = req("POST", api["mac"], "/ui/api/rooms/new", "ui." + key, {"name": "bad/name", "members": []})
    check("room names are checked", st == 400, str(st))
    cl("ops.bob", "room", "send", "alice/crew", "unread for alice")
    wait_for(lambda: any(x["id"] == "alice/crew" and x["unread"] for x in req("GET", api["mac"], "/ui/api/rooms", "ui." + key)[1]["rooms"]),
             timeout=30)
    seq = max(m["seq"] for m in req("GET", api["mac"], "/ui/api/messages?room=alice/crew&limit=200", "ui." + key)[1]["messages"])
    st, _ = req("POST", api["mac"], "/ui/api/read", "ui." + ro, {"room": "alice/crew", "seq": seq})
    rooms_now = {x["id"]: x for x in req("GET", api["mac"], "/ui/api/rooms", "ui." + key)[1]["rooms"]}
    check("opening a room in /ui clears its unread dot", st == 200 and rooms_now["alice/crew"]["unread"] == 0,
          json.dumps(rooms_now.get("alice/crew"))[:200])


def issue12_checks(cl, js, req, api, token, bg, orig):
    """#12: shared short ids, reply (same room, never less private; --dm), display order with replies under parents."""
    # Shared ids: 8 base32 characters of the envelope hash, the same on every node; seq only in --json.
    on_mac = {m["env"]: m for m in js("alice", "room", "read", "alice/plan", "--latest", "100")["messages"]}
    on_pod = {m["env"]: m for m in js("ops.bob", "room", "read", "alice/plan", "--latest", "100")["messages"]}
    both = set(on_mac) & set(on_pod)
    check("a message has the same id on every node: 8 base32 chars of its hash", both and all(
        on_mac[e]["id"] == on_pod[e]["id"] == b32(e)[:8] for e in both), "%d shared" % len(both))
    check("--json keeps the local seq for cursors", all(isinstance(m.get("seq"), int) for m in on_mac.values()))
    rc, out = cl("alice", "room", "read", "alice/plan")
    check("human output shows ids, never local numbers", rc == 0 and orig["id"] in out and not re.search(r"#\d", out), out[:200])
    rc, out = cl("ops.bob", "get", orig["id"][:5])
    check("get takes any unique prefix (on another node too)", rc == 0 and out.startswith(orig["id"] + " ") and "secret one" in out,
          out[:160])
    rc, out = cl("alice", "get", orig["env"])
    check("and the full envelope hash", rc == 0 and "secret one" in out)
    ids = sorted(m["id"] for m in js("alice", "read", "--latest", "200"))
    pre = next((a[:n] for n in (1, 2) for a, b in zip(ids, ids[1:]) if a[:n] == b[:n]), None)
    rc, out = cl("alice", "get", pre or "a")
    check("an ambiguous prefix asks for more of the id", rc != 0 and "more than one" in out, "%s: %s" % (pre, out[-120:]))
    rc, out = cl("alice", "get", "zzzzzzzz")
    check("an unknown id is not found", rc != 0 and "no message" in out, out[-120:])

    # Reply privacy: a reply to a private message cannot be posted where more agents read it.
    rc, out = cl("ops.bob", "room", "send", "release", "leak it", "--reply-to", orig["id"])
    check("a reply never downgrades privacy (private -> open room refused)", rc != 0 and "must be private" in out, out[-160:])
    # reply --dm: to the author alone, in the DM room, quoting the original.
    w = bg("alice", "watch", "--mine", "--until", "--name", "dmreply", "--from-now")
    time.sleep(2)
    rc, out = cl("ops.bob", "reply", orig["id"], "--dm", "just between us")
    dm = "dm:alice+ops.bob"
    check("reply --dm posts in the author's DM room", rc == 0 and "DM" in out, out[-160:])
    got, _ = wait_for(lambda: [m for m in (js("alice", "room", "read", dm, "--latest", "20") or {}).get("messages", [])
                               if m["text"] == "just between us"], timeout=20)
    m = got[0] if got else {}
    check("as a private reply with the quote", m.get("mode") == "private" and m.get("reply_to") == orig["id"]
          and (m.get("quote") or {}).get("text") == "secret one", json.dumps(m)[:200])
    try:
        out, _ = w.communicate(timeout=30)
        check("and wakes the author", w.returncode == 0 and "just between us" in out, out[-160:])
    except subprocess.TimeoutExpired:
        w.kill()
        check("and wakes the author", False, "timed out")
    rc, out = cl("alice", "reply", orig["id"], "--dm", "x")
    check("--dm to your own message is refused", rc != 0, out[-120:])

    # Order: by signed time, replies right under their parent; watch still fires on arrival.
    cl("alice", "room", "create", "order", "--open")
    cl("alice", "room", "send", "alice/order", "A first")
    cl("alice", "room", "send", "alice/order", "B second")
    a = [m for m in js("alice", "room", "read", "alice/order")["messages"] if m["text"] == "A first"][0]
    got, _ = wait_for(lambda: any(m["text"] == "A first" for m in (js("ops.bob", "room", "read", "alice/order") or {})
                                  .get("messages", [])), timeout=20)
    w = bg("alice", "watch", "--mine", "--until", "--name", "order", "--from-now")
    time.sleep(2)
    rc, out = cl("ops.bob", "reply", a["id"], "C answers A")
    try:
        wout, _ = w.communicate(timeout=30)
        check("a reply to an old message wakes its author on arrival", w.returncode == 0 and "C answers A" in wout, wout[-160:])
    except subprocess.TimeoutExpired:
        w.kill()
        check("a reply to an old message wakes its author on arrival", False, "timed out")
    want = ["A first", "C answers A", "B second"]
    got, _ = wait_for(lambda: [m["text"] for m in js("alice", "room", "read", "alice/order")["messages"]
                               if m.get("kind") != "event"] == want, timeout=20)
    check("display order: by time, a reply right under its parent", got)
    envs = lambda agent: [m["env"] for m in js(agent, "room", "read", "alice/order")["messages"]]
    check("the same order on another node", envs("alice") == envs("ops.bob"))
    rc, out = cl("alice", "room", "read", "alice/order")
    lines = out.splitlines()
    i = next((k for k, l in enumerate(lines) if "C answers A" in l), 0)
    check("a reply shows '\u21b3 re ID' and a quote", i >= 2 and lines[i - 2] == "\u21b3 re %s from alice" % a["id"]
          and lines[i - 1] == "  | A first", "\n".join(lines[max(0, i - 3):i + 1]))

    # Attachments by message id.
    cl("alice", "room", "send", "alice/order", "notes attached", "--file", __file__)
    f = [m for m in js("alice", "room", "read", "alice/order")["messages"] if m["text"] == "notes attached"][0]
    dest = os.path.join(tempfile.mkdtemp(prefix="islandmail-dl-"), "copy.py")
    rc, out = cl("alice", "download", f["id"][:6], "-o", dest)
    ok = rc == 0 and os.path.exists(dest) and open(dest, "rb").read() == open(__file__, "rb").read()
    check("download takes a message id prefix", ok, out[-160:])
    if os.path.exists(dest):
        os.remove(dest)


def mcpl_checks(api, cl, token):
    """An MCPL 0.5 host as ops.bob: rooms register as channels; ambient room traffic arrives as
    channels/incoming; a mention on a closed channel and a DM arrive as push/event that wakes."""
    try:
        import asyncio
        import websockets
    except ImportError:
        check("MCPL checks (websockets not installed)", False)
        return

    async def go():
        url = "ws://127.0.0.1:%d/mcpl" % api["pod"]
        hdr = {"Authorization": "Bearer " + token("ops.bob")}
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
        check("each room is a registered channel", {"room:alice/plan", "room:release", "room:dm:alice+ops.bob"} <= set(chans),
              str(sorted(chans)))
        check("rooms the agent is in start open", chans.get("room:alice/plan", {}).get("initiallyOpen") is True)
        # Drain the backlog: earlier room traffic on open channels is delivered first.
        await recv_until(lambda m: False, timeout=4)
        mark = len(seen)
        cl("alice", "room", "send", "release", "ambient chatter kumquat")
        m = await recv_until(lambda m: m.get("method") == "channels/incoming"
                             and "kumquat" in m["params"]["messages"][0]["content"][0]["text"])
        tags = m["params"]["messages"][0]["tags"] if m else []
        check("room traffic arrives as ambient channels/incoming", m and "chat:ambient" in tags
              and m["params"]["messages"][0]["channelId"] == "room:release", str(tags))
        cl("alice", "room", "send", "alice/plan", "@ops.bob mention on an open channel")
        m = await recv_until(lambda m: m.get("method") == "channels/incoming"
                             and "mention on an open" in m["params"]["messages"][0]["content"][0]["text"])
        md = m["params"]["messages"][0] if m else {}
        check("a mention on an open channel is flagged to wake", "chat:mention" in md.get("tags", [])
              and md.get("metadata", {}).get("isMention") is True, str(md.get("tags")))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "channels/close", "params": {"channelId": "room:alice/plan"}}))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "channels/close", "params": {"channelId": "room:dm:alice+ops.bob"}}))
        await recv_until(lambda m: m.get("id") == 4)
        cl("alice", "room", "send", "alice/plan", "no mention here on a closed channel")
        cl("alice", "room", "send", "alice/plan", "@ops.bob closed-channel mention")
        m = await recv_until(lambda m: m.get("method") == "push/event"
                             and "closed-channel mention" in m["params"]["payload"]["content"][0]["text"])
        check("a mention on a closed channel wakes via push/event", m and "chat:mention" in m["params"]["tags"]
              and m["params"]["origin"].get("isMention") is True, str(m and m["params"]["tags"]))
        cl("alice", "dm", "ops.bob", "a dm for the host")
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
