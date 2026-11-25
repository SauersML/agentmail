#!/usr/bin/env python3
"""Integration test: three nodes on loopback with relays off, every key a throwaway made here.

  python3 tests/network.py --bin target/debug/mailnode [--workdir DIR]

It checks that an agent's first `islandmail.py send` on a host with a node just works (key made, certified by its
node, mail delivered to another host), and the rules around it: certificates are accepted network-wide, names outside
a host's namespace and names taken by another key are refused, agent tokens are single-use and bound to one node,
private mail, attachments, catch-up after a restart, revocation, and a node that joins later. Needs `websockets`
(pip) for the MCPL checks; they are skipped without it.
"""
import argparse
import hashlib
import json
import os
import shutil
import socket
import stat
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import Client, Node, check, finish, free_port, member_list, req, run, sse_reader, wait_for  # noqa: E402


def msgs(client, q=""):
    rc, out = client.stdout("read", "--json", "--limit", "200", *q.split())
    return json.loads(out) if rc == 0 and out.startswith("[") else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = os.path.abspath(a.workdir or "net-%d" % int(time.time()))
    if os.path.exists(work):
        shutil.move(work, work + ".old-%d" % int(time.time()))
    os.makedirs(os.path.join(work, "keys"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    pub = {n: run(bin_, "keygen", k(n)) for n in ("operator", "nodeA", "nodeB", "nodeC")}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in "ABC"}
    entry = {"A": ("A", pub["nodeA"], ["a.", "solo"], ["127.0.0.1:%d" % udp["A"]]),
             "B": ("b", pub["nodeB"], None, ["127.0.0.1:%d" % udp["B"]]),  # default namespace: "b."
             "C": ("c", pub["nodeC"], None, ["127.0.0.1:%d" % udp["C"]])}

    # Namespaces may not overlap: the operator cannot sign a list where two hosts could certify the same name.
    rc, out = run(bin_, "sign-members", k("operator"), _unsigned(work, [entry["A"], ("x", pub["nodeB"], ["a.bob"], [])]),
                  os.path.join(work, "bad.json"), ok=False)
    check("a member list with overlapping namespaces is refused", rc != 0, out[-120:])
    members = member_list(bin_, work, k("operator"), 1, [entry["A"], entry["B"]])

    def cfg(h, members_file):
        own = os.path.join(work, "members-%s.json" % h)  # each node reads its own copy of the list
        shutil.copy(members_file, own)
        return {"operator_key": pub["operator"], "data_dir": os.path.join(work, "data" + h), "node_key_file": k("node" + h),
                "members_file": own, "api_listen": "127.0.0.1:%d" % free_port(), "iroh_port": udp[h],
                "relay": "disabled", "sync_secs": 3}

    A, B = Node(bin_, work, "A", cfg("A", members)), Node(bin_, work, "B", cfg("B", members))
    # Node B holds two identity files (the Connectome-host path): one private, one other users could read.
    ids = os.path.join(work, "idsB")
    os.makedirs(ids, mode=0o700)
    held = os.path.join(ids, "b.host.json")
    for path, mode in ((held, 0o600), (os.path.join(ids, "b.leaky.json"), 0o644)):
        with open(path, "w") as f:
            json.dump({"name": os.path.basename(path)[:-5], "seed": os.urandom(32).hex()}, f)
        os.chmod(path, mode)
    B.cfg["identities_dir"] = ids
    C = None
    try:
        check("node A starts", A.start())
        check("node B starts", B.start())
        st, info = req("GET", A.port, "/api/node")
        check("GET /api/node (no token) gives the key and this host's names",
              st == 200 and info.get("node") == pub["nodeA"] and info.get("names") == ["a.", "solo"], json.dumps(info))

        # The one-second path: a fresh agent on host A, no key, no operator step.
        alice = Client(work, "alice", A)
        rc, out = alice("send", "--to", "b.bob", "--thread", "t1", "hello from A")
        check("first use: `islandmail.py send` works with no key yet", rc == 0 and "sent #" in out, out.replace("\n", " | "))
        path = alice.identity_file()
        check("the client made a key named from the namespace and the user", path and path.endswith("a.alice.json"), path or "")
        check("the key file is mode 600", path and stat.S_IMODE(os.stat(path).st_mode) == 0o600)
        ident = json.load(open(path)) if path else {}
        cert = (ident.get("certs") or {}).get(pub["nodeA"], {})
        check("the identity file holds node A's certificate", cert.get("name") == "a.alice" and cert.get("node") == pub["nodeA"])
        bob = Client(work, "bob", B)
        got, dt = wait_for(lambda: [m for m in msgs(bob, "--thread t1") if m["text"] == "hello from A"], timeout=30)
        check("bob's first read on B gets it (cert accepted by another node)", got and got[0]["from"] == "a.alice"
              and got[0].get("attest") == "agent", "%.1fs" % dt)
        st, ag = req("GET", B.port, "/api/agents", bob.token())
        check("B lists a.alice as certified by node A", st == 200 and any(
            x["name"] == "a.alice" and x["node"] == pub["nodeA"] and not x.get("revoked") for x in ag.get("agents", [])), str(st))

        # Names: another host's namespace, a name taken by another key, the same key again.
        rc, out = Client(work, "mallory", A, name="b.mallory")("whoami")
        check("a name in another host's namespace is refused (403)", rc != 0 and "403" in out, out[-120:])
        rc, out = Client(work, "alice2", A, name="a.alice")("whoami")
        check("a name already bound to another key is refused (409)", rc != 0 and "409" in out, out[-120:])
        ident["certs"] = {}
        json.dump(ident, open(path, "w"))
        rc, out = alice("whoami")
        check("re-certifying the same key is idempotent", rc == 0 and "a.alice" in out, out)
        rc, out = Client(work, "solo", A, name="solo")("whoami")
        check("an exact name in the namespace can be taken", rc == 0 and "solo" in out, out)

        # Agent tokens: single use, one node.
        t = alice.token()
        check("agent token works once", req("GET", A.port, "/api/me", t)[0] == 200)
        st, e = req("GET", A.port, "/api/me", t)
        check("agent token replay is refused (401)", st == 401 and "used" in e.get("error", ""), e.get("error", ""))
        st, e = req("GET", B.port, "/api/me", alice.token())
        check("a token for node A is refused at node B", st in (401, 403), e.get("error", ""))
        st, e = req("GET", B.port, "/api/me", alice.token(node_key=pub["nodeB"]))
        check("a token for B by an agent B did not certify is refused (403)", st == 403, e.get("error", ""))
        st, e = req("GET", A.port, "/api/me")
        check("no token -> 401", st == 401)

        # SSE on B sees mail posted on A.
        stop, events = threading.Event(), []
        last_b = req("GET", B.port, "/api/me", bob.token())[1]["last_id"]
        th = threading.Thread(target=sse_reader, args=(B.port, bob.token(3600), last_b, events, stop), daemon=True)
        th.start()
        time.sleep(0.5)
        alice("send", "--to", "b.", "--thread", "t1", "stream me")
        got, dt = wait_for(lambda: [e for e in events if e[0] == "data" and e[1]["text"] == "stream me"])
        check("SSE on B delivers mail posted on A", got and events[0][1] == 200, "%.2fs" % dt)
        stop.set()

        # Private: the addressees and their host nodes only.
        carol, dave = Client(work, "carol", B), Client(work, "dave", A)
        carol("whoami"), dave("whoami")
        rc, out = alice("send", "--to", "b.bob", "--thread", "secret", "--private", "for bob only")
        check("private send on A", rc == 0, out)
        got, dt = wait_for(lambda: msgs(bob, "--thread secret"), timeout=30)
        check("private: bob reads it on B", got and got[0]["text"] == "for bob only" and got[0]["mode"] == "private", "%.1fs" % dt)
        check("private: b.carol on B cannot see it", msgs(carol, "--thread secret") == [])
        check("private: a.dave on A cannot see it", msgs(dave, "--thread secret") == [])
        check("private: alice (sender) sees it on A", len(msgs(alice, "--thread secret")) == 1)
        rc, out = alice("send", "--to", "z.nobody", "--private", "to no one")
        check("private mail to no known agent is refused", rc != 0, out[-100:])

        # Attachments across nodes.
        blob = os.urandom(300_000)
        fpath = os.path.join(work, "blob.bin")
        open(fpath, "wb").write(blob)
        rc, out = alice("send", "--to", "b.bob", "--thread", "files", "--file", fpath, "see attached")
        got, dt = wait_for(lambda: [m for m in msgs(bob, "--thread files") if m.get("files")], timeout=30)
        fid = got[0]["files"][0]["id"] if got else None
        out_path = os.path.join(work, "blob.out")
        ok = fid and wait_for(lambda: bob("download", fid, "-o", out_path)[0] == 0, timeout=30)[0]
        check("attachment posted on A downloads on B, byte for byte", ok and open(out_path, "rb").read() == blob,
              hashlib.sha256(blob).hexdigest()[:12])

        # Catch-up: B down, mail on A, B back.
        B.stop()
        for i in range(3):
            dave("send", "--to", "all", "--thread", "t1", "while B was down %d" % i)
        check("node B restarts", B.start())
        got, dt = wait_for(lambda: len([m for m in msgs(bob, "--thread t1") if "while B was down" in m["text"]]) == 3, timeout=40)
        check("B caught up after restart (anti-entropy)", got, "%.1fs" % dt)
        oa = [m["env"] for m in req("GET", A.port, "/api/messages?thread=t1&order=causal", alice.token())[1]["messages"]]
        ob = [m["env"] for m in req("GET", B.port, "/api/messages?thread=t1&order=causal", bob.token())[1]["messages"]]
        check("same causal thread order on A and B", oa == ob and len(oa) == 5, "%d messages" % len(oa))

        # watch --mine --until on B wakes on mail from A.
        w = bob.popen("watch", "--mine", "--until", "--name", "it")
        time.sleep(2)
        alice("send", "--to", "b.bob", "--thread", "t2", "wake up")
        try:
            wout, _ = w.communicate(timeout=30)
            check("watch --mine --until on B gets mail sent on A", "wake up" in wout, wout.splitlines()[0] if wout else "")
        except Exception:
            w.kill()
            check("watch --mine --until on B gets mail sent on A", False, "timeout")

        _mcpl(A, B, alice, bob)
        _held_identity(bin_, A, B, alice, bob, held)

        # Revocation: the host owner revokes a.alice; her key stops working everywhere; the name can be taken again.
        rc, out = run(bin_, "revoke", A.path, "a.alice", ok=False)
        check("mailnode revoke on A", rc == 0, out[-160:])
        rc, out = alice("whoami")
        check("a revoked key cannot sign in", rc != 0 and ("401" in out or "403" in out), out[-120:])
        got, dt = wait_for(lambda: any(x["name"] == "a.alice" and x.get("revoked") for x in
                                       req("GET", B.port, "/api/agents", bob.token())[1].get("agents", [])), timeout=30)
        check("B learns of the revocation", got, "%.1fs" % dt)
        alice_new = Client(work, "alice-new", A, user="alice")
        rc, out = alice_new("send", "--to", "b.bob", "--thread", "t5", "new key, same name")
        check("after revocation the name takes a new key", rc == 0, out[-120:])
        got, dt = wait_for(lambda: [m for m in msgs(bob, "--thread t5") if m["from"] == "a.alice"], timeout=30)
        check("B accepts mail from the new key", got, "%.1fs" % dt)

        # A node not on the list does not run; added by a list given to A only, it joins and reads the history.
        C = Node(bin_, work, "C", cfg("C", members))
        check("a node that is not on the member list refuses to start", not C.start(timeout=10))
        C.stop()
        members2 = member_list(bin_, work, k("operator"), 2, [entry["A"], entry["B"], entry["C"]], name="members2.json")
        shutil.copy(members2, A.cfg["members_file"])  # only A is given it; A re-reads members_file every sync_secs
        got, dt = wait_for(lambda: req("GET", B.port, "/api/node")[1].get("members_seq") == 2, timeout=30)
        check("B adopts the new list from the network", got, "%.1fs" % dt)
        C = Node(bin_, work, "C", cfg("C", members2))
        check("node C starts", C.start())
        erin = Client(work, "erin", C)
        got, dt = wait_for(lambda: len([m for m in msgs(erin, "--thread t1")]) >= 5, timeout=60)
        check("C reads history written before it joined (grants)", got, "%.1fs" % dt)
        rc, out = erin("send", "--to", "a.dave", "--thread", "t6", "from the new host")
        got, dt = wait_for(lambda: [m for m in msgs(dave, "--thread t6")], timeout=30)
        check("an agent on the new host reaches A", rc == 0 and got, "%.1fs" % dt)
    finally:
        for n in (A, B, C):
            if n:
                n.stop()
    finish(work)


def _unsigned(work, nodes):
    path = os.path.join(work, "bad-unsigned.json")
    json.dump({"v": 2, "network": "test", "seq": 1, "issued": "", "operator": "", "sig": "", "nodes": [
        dict({"name": n, "key": k, "addrs": ad}, **({"names": ns} if ns else {})) for n, k, ns, ad in nodes]}, open(path, "w"))
    return path


def _mcpl(A, B, alice, bob):
    try:
        from websockets.sync.client import connect
    except ImportError:
        print("SKIP MCPL checks: pip install websockets")
        return

    def session(token):
        ws = connect("ws://127.0.0.1:%d/mcpl?token=%s" % (B.port, token), max_size=None)
        ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {"experimental": {"mcpl": {"version": "0.4"}}}}}))
        init = json.loads(ws.recv(timeout=5))
        ws.send(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        return ws, init

    ws, init = session(bob.token(3600))
    check("MCPL initialize with an agent token", "mcpl" in init["result"]["capabilities"].get("experimental", {}))
    ws.send(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    tl = json.loads(ws.recv(timeout=5))
    check("MCPL tools/list", [t["name"] for t in tl["result"]["tools"]] == ["send", "inbox", "thread", "threads", "who", "search", "get"])
    alice("send", "--to", "b.bob", "--thread", "t3", "push me")
    push, t0 = None, time.time()
    while time.time() - t0 < 15 and not push:
        m = json.loads(ws.recv(timeout=15))
        if m.get("method") == "push/event":
            push = m
    check("MCPL push/event of mail posted on A", push and "push me" in push["params"]["payload"]["content"][0]["text"])
    if push:
        ws.send(json.dumps({"jsonrpc": "2.0", "id": push["id"], "result": {"accepted": True}}))
    ws.send(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "send", "arguments": {
        "to": "a.alice", "thread": "t4", "text": "sent over MCPL, unsigned"}}}))
    sent, t0 = None, time.time()
    while time.time() - t0 < 5 and not sent:
        m = json.loads(ws.recv(timeout=5))
        if m.get("id") == 4:
            sent = m
    ws.close()
    check("MCPL send (unsigned)", sent and not sent["result"].get("isError"), json.dumps(sent)[:160] if sent else "no answer")
    got, dt = wait_for(lambda: [m for m in msgs(alice, "--thread t4")], timeout=30)
    check("its mail reaches A, vouched for by node B", got and got[0]["attest"] == "node" and got[0]["from"] == "b.bob",
          "%.1fs" % dt)


def _held_identity(bin_, A, B, alice, bob, held):
    # A node with identities_dir certifies the identities it holds when it starts, and signs their MCPL sends with
    # their own keys; the host mints the MCPL token from the identity file.
    st, ag = req("GET", B.port, "/api/agents", bob.token())
    names = {x["name"]: x for x in ag.get("agents", [])} if st == 200 else {}
    check("B certified the identity it holds (identities_dir)", names.get("b.host", {}).get("node") == B.key(), str(st))
    check("B skips an identity file other users can read", "b.leaky" not in names)
    try:
        from websockets.sync.client import connect
    except ImportError:
        print("SKIP held-identity MCPL check: pip install websockets")
        return
    tok = run(bin_, "agent-token", held, B.key(), "600")
    ws = connect("ws://127.0.0.1:%d/mcpl?token=%s" % (B.port, tok), max_size=None)
    ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {}}}))
    json.loads(ws.recv(timeout=5))
    ws.send(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    ws.send(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "send", "arguments": {
        "to": "a.alice", "thread": "t7", "text": "from a held identity"}}}))
    sent, t0 = None, time.time()
    while time.time() - t0 < 5 and not sent:
        m = json.loads(ws.recv(timeout=5))
        if m.get("id") == 2:
            sent = m
    ws.close()
    check("MCPL send with a token from `mailnode agent-token`", sent and not sent["result"].get("isError"),
          json.dumps(sent)[:160] if sent else "no answer")
    got, dt = wait_for(lambda: msgs(alice, "--thread t7"), timeout=30)
    check("its mail reaches A signed with the held identity's key", got and got[0]["from"] == "b.host"
          and got[0]["attest"] == "agent", "%.1fs" % dt)


if __name__ == "__main__":
    main()
