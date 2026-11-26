#!/usr/bin/env python3
"""Two-node integration test for islandmail-node. Run on a Linux box with the release binary built:

  python3 tests/two_nodes.py --bin target/debug/islandmail-node --islandmail /path/to/islandmail.py [--workdir DIR]

Everything is throwaway: node keys and agent identities in --workdir.
Needs `websockets` (pip) for the MCPL check; skipped if missing.
"""
import argparse
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

RESULTS = []


def write_private_json(path, obj):
    # Owner-only on every platform (mode 600, or a Windows access list with only this user), as the client writes it.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "islandmail", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients", "islandmail.py"))
    im = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(im)
    im.write_private(path, json.dumps(obj))


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)
    return ok


def work_directory(path):
    if not path:
        return tempfile.mkdtemp(prefix="islandmail-")
    path = os.path.abspath(path)
    os.makedirs(path, mode=0o700, exist_ok=False)
    return path


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run(bin_, *args):
    return subprocess.run([bin_, *args], check=True, capture_output=True, text=True).stdout.strip()


def req(method, port, path, token=None, body=None, timeout=10):
    h = {}
    data = None
    if token:
        h["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_for(fn, timeout=20, every=0.2):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            return v, time.time() - t0
        time.sleep(every)
    return None, time.time() - t0


class Node:
    def __init__(self, bin_, work, name, cfg):
        self.bin, self.work, self.name, self.cfg = bin_, work, name, cfg
        self.proc = None
        self.port = int(cfg["api_listen"].split(":")[1])

    def start(self):
        path = os.path.join(self.work, self.name + ".json")
        with open(path, "w") as f:
            json.dump(self.cfg, f, indent=1)
        log = open(os.path.join(self.work, self.name + ".log"), "a")
        self.proc = subprocess.Popen([self.bin, "run", path], stdout=log, stderr=subprocess.STDOUT,
                                     env=dict(os.environ, RUST_LOG=os.environ.get("ISLANDMAIL_NODE_LOG", "islandmail_node=info,iroh=warn,iroh_gossip=warn")))
        ok, _ = wait_for(lambda: self._up(), timeout=30)
        return ok

    def _up(self):
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
            return True
        except OSError:
            return False

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


def sse_reader(port, token, after, out, stop):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    c.request("GET", "/api/stream?after=%d" % after, headers={"Authorization": "Bearer " + token})
    r = c.getresponse()
    out.append(("status", r.status, r.getheader("Content-Type")))
    while not stop.is_set():
        line = r.fp.readline()
        if not line:
            break
        line = line.decode().rstrip("\n")
        if line.startswith("data: "):
            out.append(("data", json.loads(line[6:])))
    c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = work_directory(a.workdir)
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    os.makedirs(os.path.join(work, "keys"))

    # Throwaway keys: two nodes, three agents.
    pub = {n: run(bin_, "keygen", k(n)) for n in ["nodeA", "nodeB", "alice", "bob", "carol"]}
    agents = {"alice": "t.alice", "bob": "t.bob", "carol": "u.carol"}
    ports = {"apiA": free_port(), "apiB": free_port(), "udpA": free_port(socket.SOCK_DGRAM), "udpB": free_port(socket.SOCK_DGRAM)}
    roster = {
        "v": 1, "network": run(bin_, "network-id"), "seq": 1,
        "members": [{"name": agents[n], "sub": "agent:%s@test" % n, "key": pub[n]} for n in agents],
        "nodes": [{"name": "A", "key": pub["nodeA"], "addrs": ["127.0.0.1:%d" % ports["udpA"]]},
                  {"name": "B", "key": pub["nodeB"], "addrs": ["127.0.0.1:%d" % ports["udpB"]]}],
    }
    with open(os.path.join(work, "members.json"), "w") as f:
        json.dump(roster, f)


    # islandmail.py-style identity folders: node A hosts alice, node B hosts bob (their keys open private mail).
    for host, who in (("A", "alice"), ("B", "bob"), ("B", "carol")):
        d = os.path.join(work, "ids" + host, "identities")
        os.makedirs(d, exist_ok=True)
        seed = open(k(who)).read().strip()
        # nodes skip identity files others can read
        write_private_json(os.path.join(d, agents[who] + ".json"),
                           {"name": agents[who], "sub": "agent:%s@test" % who, "id": pub[who], "seed": seed})

    def cfg(host):
        return {
            "data_dir": os.path.join(work, "data" + host),
            "api_listen": "127.0.0.1:%d" % ports["api" + host],
            "iroh_port": ports["udp" + host],
            "node_key_file": k("node" + host),

            "members_file": os.path.join(work, "members.json"),
            "identities_dir": os.path.join(work, "ids" + host, "identities"),
            "sync_secs": 3,
        }

    def token(host, agent):
        folder = "idsA" if agent == "alice" else "idsB"
        identity = os.path.join(work, folder, "identities", agents[agent] + ".json")
        return run(bin_, "agent-token", identity, pub["node" + host])

    A = Node(bin_, work, "A", cfg("A"))
    B = Node(bin_, work, "B", cfg("B"))
    try:
        check("node A starts", A.start())
        check("node B starts", B.start())
        pa, pb = A.port, B.port

        def has_peer_encryption_keys():
            _, reply = req("GET", pa, "/api/recipients?to=all&mode=members", token("A", "alice"))
            records = reply.get("node_encryption_keys", [])
            actual = {r["node"]: r for r in records}
            return all(actual.get(pub[key]) == req("GET", port, "/api/node")[1]["encryption_key"]
                       for key, port in [("nodeA", pa), ("nodeB", pb)]) and len(actual) == 2
        found, _ = wait_for(has_peer_encryption_keys)
        check("senders obtain both nodes' current signed encryption records", found)

        # Auth, exactly like the old server.
        st, me = req("GET", pa, "/api/me", token("A", "alice"))
        check("GET /api/me", st == 200 and me.get("name") == "t.alice" and me.get("island") == roster["network"], json.dumps(me))
        st, e = req("GET", pa, "/api/me")
        check("no token -> 401", st == 401, json.dumps(e))
        # Post on A, read on B.
        st, r = req("POST", pa, "/api/messages", token("A", "alice"), {"to": "t.bob", "thread": "t1", "text": "hello from A"})
        check("POST /api/messages on A -> 201", st == 201 and r["message"]["text"] == "hello from A", "id #%s" % r.get("message", {}).get("id"))
        env1 = r["message"]["env"]
        got, dt = wait_for(lambda: [m for m in req("GET", pb, "/api/messages?thread=t1", token("B", "bob"))[1]["messages"] if m["env"] == env1])
        check("message replicated to B (gossip)", got and got[0]["text"] == "hello from A" and got[0]["from"] == "t.alice", "%.2fs" % dt)
        st, r2 = req("POST", pa, "/api/messages", token("A", "alice"), {"to": "t.bob", "thread": "t1", "text": "hello from A"})
        check("identical resend within 10 min -> 200 repeated", st == 200 and r2.get("repeated") is True)

        # SSE on B sees a message posted on A.
        stop = threading.Event()
        events = []
        last_b = req("GET", pb, "/api/me", token("B", "bob"))[1]["last_seq"]
        th = threading.Thread(target=sse_reader, args=(pb, token("B", "bob"), last_b, events, stop), daemon=True)
        th.start()
        time.sleep(0.5)
        st, r = req("POST", pa, "/api/messages", token("A", "alice"), {"to": "t.", "thread": "t1", "text": "stream me"})
        got, dt = wait_for(lambda: [e for e in events if e[0] == "data" and e[1]["text"] == "stream me"])
        check("SSE on B delivers mail posted on A", got and events[0][1] == 200, "%.2fs" % dt)
        stop.set()

        # Private mode: only the sender and the recipients can read it, and only on nodes holding their keys.
        st, r = req("POST", pa, "/api/messages", token("A", "alice"), {"to": "t.bob", "thread": "secret", "text": "for bob only", "mode": "private"})
        check("private POST on A", st == 201 and r["message"]["mode"] == "private")
        got, dt = wait_for(lambda: req("GET", pb, "/api/messages?thread=secret", token("B", "bob"))[1]["messages"])
        check("private: bob reads it on B (B holds bob's key)", got and got[0]["text"] == "for bob only", "%.2fs" % dt)
        check("private: carol cannot see it on B", req("GET", pb, "/api/messages?thread=secret", token("B", "carol"))[1]["messages"] == [])
        check("private: carol cannot see it on A", req("GET", pa, "/api/messages?thread=secret", token("A", "carol"))[1]["messages"] == [])
        check("private: alice (sender) sees it on A", len(req("GET", pa, "/api/messages?thread=secret", token("A", "alice"))[1]["messages"]) == 1)
        st, raw = req("GET", pb, "/api/messages?thread=secret", token("B", "bob"))
        check("private: replicated row on B is marked mode private",
              raw["messages"] and raw["messages"][0]["mode"] == "private")

        # Kill B, post on A, restart B: anti-entropy catches up.
        B.stop()
        sent = []
        for i in range(3):
            st, r = req("POST", pa, "/api/messages", token("A", "alice"), {"to": "all", "thread": "t1", "text": "while B was down %d" % i})
            sent.append(r["message"]["env"])
        check("posted 3 while B down", len(sent) == 3)
        check("node B restarts", B.start())
        def caught_up():
            envs = {m["env"] for m in req("GET", pb, "/api/messages?thread=t1", token("B", "bob"))[1]["messages"]}
            return all(s in envs for s in sent)
        got, dt = wait_for(caught_up, timeout=40)
        check("B caught up after restart (anti-entropy)", got, "%.2fs" % dt)
        # Both nodes now hold the same envelopes and agree on the thread's order.
        oa = [m["env"] for m in req("GET", pa, "/api/messages?thread=t1&order=causal", token("A", "alice"))[1]["messages"]]
        ob = [m["env"] for m in req("GET", pb, "/api/messages?thread=t1&order=causal", token("B", "bob"))[1]["messages"]]
        check("same causal thread order on A and B", oa == ob and len(oa) == 5, "%d messages" % len(oa))
        route = "/api/messages?thread=t1&order=causal"
        first = req("GET", pa, route + "&limit=2", token("A", "alice"))[1]
        rest = req("GET", pa, route + "&after=%d" % first["messages"][-1]["seq"], token("A", "alice"))[1]
        check("causal pages resume after the last delivered message", first["more"] and not rest["more"]
              and len(first["messages"]) == 2 and [m["env"] for m in first["messages"] + rest["messages"]] == oa)

        st, th_ = req("GET", pb, "/api/threads", token("B", "bob"))
        check("GET /api/threads on B", st == 200 and any(t["thread"] == "t1" and t["n"] == 5 for t in th_["threads"]))
        st, nm = req("GET", pb, "/api/names?prefix=t.", token("B", "bob"))
        check("GET /api/names on B lists replicated senders", st == 200 and "t.alice" in [n["name"] for n in nm["names"]],
              ",".join(n["name"] for n in nm["names"]))

        # islandmail.py against node A, unchanged, only ISLANDMAIL_URL/ISLANDMAIL_DIR set.
        def im(port, who, *args, timeout=30):
            env = dict(os.environ, ISLANDMAIL_URL="http://127.0.0.1:%d" % port, ISLANDMAIL_DIR=os.path.join(work, "idsA" if who == "alice" else "idsB"), ISLANDMAIL_AS=agents[who])
            p = subprocess.run([sys.executable, a.islandmail, *args], capture_output=True, text=True, env=env, timeout=timeout)
            return p.returncode, (p.stdout + p.stderr).strip()

        rc, out = im(pa, "alice", "whoami")
        check("islandmail.py whoami (A)", rc == 0 and "t.alice" in out, out)
        # bob waits on B for his next mail; alice sends it with islandmail.py on A.
        envb = dict(os.environ, ISLANDMAIL_URL="http://127.0.0.1:%d" % pb, ISLANDMAIL_DIR=os.path.join(work, "idsB"), ISLANDMAIL_AS="t.bob")
        wrong_pin = dict(envb, ISLANDMAIL_NODE_KEY=pub["nodeA"])
        offline = subprocess.run([sys.executable, a.islandmail, "selftoken"],
                                 env=dict(wrong_pin, ISLANDMAIL_URL="http://127.0.0.1:1"),
                                 capture_output=True, timeout=10)
        check("selftoken with an explicit audience works offline", offline.returncode == 0 and offline.stdout.startswith(b"v4.public."))
        mismatch = subprocess.run([sys.executable, a.islandmail, "whoami"], env=wrong_pin,
                                  capture_output=True, text=True, timeout=10)
        check("an online command detects a mismatched public key before sign-in",
              mismatch.returncode == 1 and "does not match ISLANDMAIL_NODE_KEY" in mismatch.stderr)
        def watch():
            return subprocess.Popen([sys.executable, a.islandmail, "watch", "--mine", "--until", "--name", "it"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=envb)
        watcher = watch()
        try:
            ready, _ = wait_for(lambda: any(f.endswith("-t.bob-it.last") for f in os.listdir(envb["ISLANDMAIL_DIR"])), timeout=5)
            check("idle watcher checkpoints its starting cursor", bool(ready))
        finally:
            watcher.terminate()
            watcher.communicate(timeout=5)
        rc, out = im(pa, "alice", "send", "--to", "t.bob", "--thread", "t2", "sent with islandmail.py")
        check("islandmail.py send (A)", rc == 0 and re.match(r"sent [a-z2-7]{8} to ", out) and "stored here for t.bob, copied to their nodes as they sync" in out, out)
        delivered, _ = wait_for(lambda: req("GET", pb, "/api/messages?thread=t2", token("B", "bob"))[1]["messages"])
        check("message reached B while watcher was stopped", bool(delivered))
        watcher = watch()
        try:
            wout, _ = watcher.communicate(timeout=20)
            check("islandmail.py watch --mine --until (B) gets it", "sent with islandmail.py" in wout, wout.splitlines()[0] if wout else "")
        except subprocess.TimeoutExpired:
            watcher.kill()
            watcher.communicate()
            check("islandmail.py watch --mine --until (B) gets it", False, "timeout")
        rc, out = im(pa, "alice", "read", "--thread", "t2", "--latest", "5")
        check("islandmail.py read (A)", rc == 0 and "> sent with islandmail.py" in out, out.splitlines()[0] if out else "")
        num = out.split()[0][:5] if out else "x"
        rc, out = im(pa, "alice", "get", num)
        check("islandmail.py get (A)", rc == 0 and "sent with islandmail.py" in out)
        rc, out = im(pa, "alice", "threads")
        check("islandmail.py threads (A)", rc == 0 and "t1" in out and "t2" in out)
        rc, out = im(pa, "alice", "who")
        check("islandmail.py who (A)", rc == 0 and "t.bob" in out and "1970-01-01" not in out, out)
        rc, out = im(pb, "bob", "read", "--to-me", "--thread", "t1")
        check("islandmail.py read --to-me (B)", rc == 0 and "hello from A" in out)

        # A newer visible message to another agent must not displace Bob's latest inbox item.
        rc, _ = im(pb, "bob", "send", "--to", "t.alice", "--thread", "t2", "reply to Alice")
        check("Bob sends his reply", rc == 0)
        rc, out = im(pb, "bob", "read", "--to-me", "--thread", "t2", "--latest", "1", "--json")
        check("latest counts addressed messages", rc == 0 and [m["text"] for m in json.loads(out)] == ["sent with islandmail.py"])

        # MCPL on node B: tools, push/event of mail posted on A, cursor moves on {accepted:true}.
        try:
            from websockets.sync.client import connect
        except ImportError:
            connect = None
            check("MCPL (websockets not installed: skipped)", True)
        if connect:
            def rpc_session(token):
                ws = connect("ws://127.0.0.1:%d/mcpl" % pb, additional_headers={"Authorization": "Bearer " + token})
                ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {"experimental": {"mcpl": {"version": "0.4"}}}}}))
                init = json.loads(ws.recv(timeout=5))
                ws.send(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
                return ws, init
            ws, init = rpc_session(token("B", "bob"))
            check("MCPL initialize", init["result"]["serverInfo"]["name"] == "islandmail" and "mcpl" in init["result"]["capabilities"]["experimental"])
            ws.send(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            tl = json.loads(ws.recv(timeout=5))
            check("MCPL tools/list", [t["name"] for t in tl["result"]["tools"]] == ["send", "inbox", "thread", "threads", "who", "search", "get", "rooms", "room_send"])
            ws.send(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "thread", "arguments": {"thread": "t1"}}}))
            tc = json.loads(ws.recv(timeout=5))
            check("MCPL tools/call thread", "hello from A" in tc["result"]["content"][0]["text"])
            req("POST", pa, "/api/messages", token("A", "alice"), {"to": "t.bob", "thread": "t3", "text": "push me"})
            push = None
            t0 = time.time()
            while time.time() - t0 < 15:
                m = json.loads(ws.recv(timeout=15))
                if m.get("method") == "push/event":
                    push = m
                    break
            check("MCPL push/event of mail posted on A", push and "push me" in push["params"]["payload"]["content"][0]["text"],
                  push["params"]["eventId"] if push else "none")
            if push:
                ws.send(json.dumps({"jsonrpc": "2.0", "id": push["id"], "result": {"accepted": True}}))
                time.sleep(0.5)
            ws.close()
            # Reconnect: the accepted push is not sent again; a new one sent while away is.
            req("POST", pa, "/api/messages", token("A", "alice"), {"to": "t.bob", "thread": "t3", "text": "while you were away"})
            time.sleep(2)
            ws, _ = rpc_session(token("B", "bob"))
            texts = []
            t0 = time.time()
            while time.time() - t0 < 4:
                try:
                    m = json.loads(ws.recv(timeout=1))
                except TimeoutError:
                    continue
                if m.get("method") == "push/event":
                    texts.append(m["params"]["payload"]["content"][0]["text"])
            ws.close()
            check("MCPL backlog on reconnect: only the unacknowledged mail", len(texts) == 1 and "while you were away" in texts[0],
                  "%d pushed" % len(texts))
            # The same with an agent token (a Connectome host with no home): `islandmail-node agent-token` mints it from bob's
            # identity file. B holds bob's key, so it signs his MCPL sends with it.
            node_b = req("GET", pb, "/api/node")[1]["node"]
            bob_id = os.path.join(work, "idsB", "identities", "t.bob.json")
            ws, init = rpc_session(run(bin_, "agent-token", bob_id, node_b, "600"))
            ws.send(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "send", "arguments": {
                "to": "t.alice", "thread": "t4", "text": "sent over MCPL with an agent token"}}}))
            sent = None
            t0 = time.time()
            while time.time() - t0 < 5 and not sent:
                m = json.loads(ws.recv(timeout=5))
                if m.get("id") == 4:
                    sent = m
            ws.close()
            check("MCPL with an agent token: initialize and send", init.get("result") and sent and not sent["result"].get("isError"),
                  sent["result"]["content"][0]["text"] if sent else "no answer")
            got, dt = wait_for(lambda: [m for m in req("GET", pa, "/api/messages?thread=t4", token("A", "alice"))[1]["messages"]])
            check("its mail reaches A, signed by bob's key", bool(got), "%.2fs" % dt)
    finally:
        A.stop()
        B.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
