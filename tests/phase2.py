#!/usr/bin/env python3
"""Phase 2 integration test: sender signatures, attachments, the history bridge against a fake old server, and member
list replication (a third node joins through a list only one node was given). All keys are throwaway.

  python3 tests/phase2.py --bin target/debug/mailnode --repo . [--workdir DIR]
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, req, run, wait_for  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    repo = os.path.abspath(a.repo)
    client = os.path.join(repo, "clients", "islandmail.py")
    work = os.path.abspath(a.workdir or "p2-%d" % int(time.time()))
    if os.path.exists(work):
        shutil.move(work, work + ".old-%d" % int(time.time()))
    os.makedirs(os.path.join(work, "keys"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    names = ["home", "operator", "nodeA", "nodeB", "nodeC", "bridgekey", "alice", "bob", "carol", "dave", "bridge"]
    pub = {n: run(bin_, "keygen", k(n)) for n in names}
    iss = "home.test"
    agents = {"alice": "t.alice", "bob": "t.bob", "carol": "u.carol", "bridge": "t.bridge"}
    P = {x: free_port() for x in ("apiA", "apiB", "apiC", "old")}
    P.update({x: free_port(socket.SOCK_DGRAM) for x in ("udpA", "udpB", "udpC")})

    def member_list(seq, nodes, extra_members=()):
        lst = {
            "v": 1, "network": "test", "seq": seq, "issued": "", "operator": "",
            "members": [{"name": agents[n], "sub": "agent:%s@test" % n, "key": pub[n]} for n in agents]
                       + [{"name": "u.dave", "sub": "agent:dave@test", "key": pub["dave"]} for _ in extra_members],
            "nodes": [{"name": h, "key": pub["node" + h], "addrs": ["127.0.0.1:%d" % P["udp" + h]]} for h in nodes],
            "bridges": [pub["bridgekey"]], "sig": "",
        }
        raw = os.path.join(work, "members.%d.unsigned.json" % seq)
        out = os.path.join(work, "members.%d.json" % seq)
        json.dump(lst, open(raw, "w"))
        run(bin_, "sign-members", k("operator"), raw, out)
        return out

    m1 = member_list(1, ["A", "B"])
    for h in "ABC":
        shutil.copy(m1, os.path.join(work, "members.%s.json" % h))

    def cfg(h, **extra):
        c = {
            "data_dir": os.path.join(work, "data" + h), "api_listen": "127.0.0.1:%d" % P["api" + h],
            "iroh_port": P["udp" + h], "node_key_file": k("node" + h), "operator_key": pub["operator"],
            "members_file": os.path.join(work, "members.%s.json" % h), "home": {"key": pub["home"], "iss": iss},
            "relay": "disabled", "sync_secs": 2, "id_floor": 1000,
        }
        c.update(extra)
        return c

    tok = {n: run(bin_, "mint-token", k("home"), iss, agents[n], "agent:%s@test" % n, "3600") for n in agents}
    # islandmail.py identities + cached tokens (it never calls a home)
    im_dir = os.path.join(work, "islandmail")
    os.makedirs(os.path.join(im_dir, "identities"))
    os.makedirs(os.path.join(im_dir, "tokens"))
    for n in agents:
        json.dump({"name": agents[n], "sub": "agent:%s@test" % n, "home": iss, "id": pub[n], "seed": open(k(n)).read().strip()},
                  open(os.path.join(im_dir, "identities", agents[n] + ".json"), "w"))
        json.dump({"token": tok[n], "exp": time.time() + 3600}, open(os.path.join(im_dir, "tokens", agents[n] + ".mail.json"), "w"))

    def im(port, who, *args, timeout=60):
        env = dict(os.environ, ISLANDMAIL_URL="http://127.0.0.1:%d" % port, ISLANDMAIL_DIR=im_dir, ISLANDMAIL_AS=agents[who])
        p = subprocess.run([sys.executable, client, *args], capture_output=True, text=True, env=env, timeout=timeout, cwd=work)
        return p.returncode, (p.stdout + p.stderr).strip()

    def msgs(port, who, q=""):
        return req("GET", port, "/api/messages?" + q, tok[who])[1].get("messages", [])

    # Fake old server with history: gaps in the numbers and one unverified legacy row.
    old_tokens = {"old-alice": {"name": "t.alice", "sub": "agent:alice@test"},
                  "old-bridge": {"name": "t.bridge", "sub": "agent:bridge@test"}}
    history = [
        {"id": 1, "ts": "2026-10-01T10:00:00.000Z", "from": "t.alice", "to": "all", "thread": "general", "text": "first ever", "files": [], "sub": "agent:alice@test", "verified": True},
        {"id": 2, "ts": "2026-10-01T10:05:00.000Z", "from": "someone", "to": "all", "thread": "general", "text": "legacy row", "files": [], "sub": "agentmail:msg.gnome.science", "verified": False},
        {"id": 3, "ts": "2026-10-02T09:00:00.000Z", "from": "u.carol", "to": "t.alice", "thread": "plans", "text": "plan A", "files": [{"id": "AAAAAAAAAAAAAAAAAAAAAA", "name": "plan.pdf", "type": "application/pdf", "size": 10}], "sub": "agent:carol@test", "verified": True},
        {"id": 5, "ts": "2026-10-03T09:00:00.000Z", "from": "t.alice", "to": "u.carol", "thread": "plans", "text": "plan B", "files": [], "sub": "agent:alice@test", "verified": True},
        {"id": 8, "ts": "2026-11-01T09:00:00.000Z", "from": "t.bob", "to": "t.", "thread": "general", "text": "eighth", "files": [], "sub": "agent:bob@test", "verified": True},
    ]
    json.dump(old_tokens, open(os.path.join(work, "old-tokens.json"), "w"))
    json.dump(history, open(os.path.join(work, "old-history.json"), "w"))
    open(os.path.join(work, "old-bridge.token"), "w").write("old-bridge")
    open(os.path.join(work, "node-bridge.token"), "w").write(tok["bridge"])
    oldsrv = subprocess.Popen([sys.executable, os.path.join(repo, "tests", "fake_old_server.py"), "--port", str(P["old"]),
                               "--tokens", os.path.join(work, "old-tokens.json"), "--seed", os.path.join(work, "old-history.json")])

    def old_get(path, token="old-alice"):
        r = urllib.request.Request("http://127.0.0.1:%d%s" % (P["old"], path), headers={"Authorization": "Bearer " + token})
        return json.loads(urllib.request.urlopen(r, timeout=10).read())

    def old_post(text, to="t.bob", thread="general", token="old-alice"):
        r = urllib.request.Request("http://127.0.0.1:%d/api/messages" % P["old"], method="POST",
                                   data=json.dumps({"to": to, "thread": thread, "text": text}).encode(),
                                   headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(r, timeout=10).read())

    bridge_cmd = [sys.executable, os.path.join(repo, "bridge", "bridge.py"), "--old", "http://127.0.0.1:%d" % P["old"],
                  "--old-token-file", os.path.join(work, "old-bridge.token"), "--node", "http://127.0.0.1:%d" % P["apiA"],
                  "--node-token-file", os.path.join(work, "node-bridge.token"), "--state", os.path.join(work, "bridge.sqlite"),
                  "--interval", "1"]

    A = Node(bin_, work, "A", cfg("A", bridge={"key_file": k("bridgekey"), "sub": "agent:bridge@test"}))
    B = Node(bin_, work, "B", cfg("B"))
    C = Node(bin_, work, "C", cfg("C", refuse_token_only=True))
    bridge = None
    try:
        time.sleep(0.5)
        check("node A starts", A.start())
        check("node B starts", B.start())
        pa, pb, pc = A.port, B.port, C.port

        # 1. History import: old numbers kept, legacy row still unverified, on A and (replicated) on B.
        p = subprocess.run(bridge_cmd + ["--import-only"], capture_output=True, text=True, timeout=60)
        check("bridge --import-only", p.returncode == 0 and '"imported": 5' in p.stdout, (p.stdout + p.stderr).strip()[-200:])
        ida = {m["id"]: m for m in msgs(pa, "alice")}
        check("A holds old ids 1,2,3,5,8", sorted(ida) == [1, 2, 3, 5, 8], str(sorted(ida)))
        check("imported rows: attest import, legacy row unverified", ida[2]["attest"] == "import" and ida[2]["verified"] is False and ida[1]["verified"] is True)
        check("old file metadata kept on import", ida[3]["files"] and ida[3]["files"][0]["name"] == "plan.pdf")
        got, dt = wait_for(lambda: sorted(m["id"] for m in msgs(pb, "bob")) == [1, 2, 3, 5, 8], timeout=30)
        check("B holds the same old ids after replication", got, "%.1fs" % dt)
        p = subprocess.run(bridge_cmd + ["--import-only"], capture_output=True, text=True, timeout=60)
        check("re-running the import adds nothing", '"imported": 0' in p.stdout and len(msgs(pa, "alice")) == 5, p.stdout.strip()[-120:])

        # 2. Signed posts (islandmail.py signs with the agent key) vs token-only posts.
        rc, out = im(pa, "alice", "send", "--to", "t.bob", "--thread", "signed", "signed by alice's key")
        check("islandmail.py signed send on A", rc == 0 and "reaches t.bob" in out, out)
        got, dt = wait_for(lambda: [m for m in msgs(pb, "bob", "thread=signed")])
        check("B shows it attest=agent", got and got[0]["attest"] == "agent" and got[0]["text"] == "signed by alice's key", "%.2fs" % dt)
        st, r = req("POST", pa, "/api/messages", tok["alice"], {"to": "t.bob", "thread": "signed", "text": "token only"})
        check("raw token-only post is flagged attest=token", st == 201 and r["message"]["attest"] == "token")
        st, r = req("POST", pa, "/api/messages", tok["alice"], {"to": "t.bob", "thread": "signed", "text": "x",
                                                                "signed": {"ts": r["message"]["ts"], "salt": "AAAAAAAAAAAAAAAAAAAAAA", "sig": "AAAA"}})
        check("forged signed block refused", st == 401, r.get("error", ""))
        rc, out = im(pa, "alice", "send", "--private", "--to", "t.bob", "--thread", "signed", "private and signed")
        check("islandmail.py --private on a node", rc == 0, out)

        # 3. Attachments: upload with islandmail.py on A, download on B.
        payload = os.urandom(300_000)
        open(os.path.join(work, "blob.bin"), "wb").write(payload)
        rc, out = im(pa, "alice", "send", "--to", "t.bob", "--thread", "files", "--file", os.path.join(work, "blob.bin"), "see attached")
        check("islandmail.py send --file on A", rc == 0, out)
        got, dt = wait_for(lambda: [m for m in msgs(pb, "bob", "thread=files") if m["files"]])
        fid = got[0]["files"][0]["id"] if got else ""
        check("attachment listed on B (no key exposed)", got and "key" not in got[0]["files"][0] and got[0]["files"][0]["size"] == 300_000, "%.2fs" % dt)
        def dl():
            rc, out = im(pb, "bob", "download", fid, "-o", os.path.join(work, "got.bin"))
            return rc == 0 and open(os.path.join(work, "got.bin"), "rb").read() == payload
        got, dt = wait_for(dl, timeout=30, every=1)
        check("islandmail.py download on B returns the same bytes", got, "%.1fs" % dt)
        big = urllib.request.Request("http://127.0.0.1:%d/api/files?name=big" % pa, data=b"x" * (25 * 1024 * 1024 + 10), method="POST",
                                     headers={"Authorization": "Bearer " + tok["alice"], "Content-Type": "application/octet-stream"})
        try:
            urllib.request.urlopen(big, timeout=60)
            code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        check("upload over 25 MiB refused (413)", code == 413, str(code))

        # 4. Dual-send: old -> p2p and p2p -> old, each once, no echo.
        bridge = subprocess.Popen(bridge_cmd, stdout=open(os.path.join(work, "bridge.log"), "w"), stderr=subprocess.STDOUT)
        time.sleep(2)
        r = old_post("new on the old server")
        old_new = r["message"]["id"]
        got, dt = wait_for(lambda: [m for m in msgs(pb, "bob") if m["text"] == "new on the old server"], timeout=30)
        # New mail exists by now, so the import gets a new local number (numbers only grow) and keeps the old one in
        # `imported`.
        check("old -> p2p: new old mail reaches B, numbered after existing mail, old number in imported",
              got and got[0]["imported"] == old_new and got[0]["id"] > 1000 and got[0]["attest"] == "import",
              "old #%d, B #%s, %.1fs" % (old_new, got[0]["id"] if got else "-", dt))
        rc, out = im(pb, "bob", "send", "--to", "t.alice", "--thread", "general", "new on the p2p network")
        check("p2p send on B", rc == 0, out)
        def on_old():
            return [m for m in old_get("/api/messages?after=0")["messages"] if "new on the p2p network" in m["text"]]
        got, dt = wait_for(on_old, timeout=30)
        check("p2p -> old: B's mail reaches the old server as the bridge, naming the sender",
              got and got[0]["from"] == "t.bridge" and "from t.bob [agent:bob@test]" in got[0]["text"], "%.1fs" % dt)
        time.sleep(5)  # several bridge cycles
        n_old = len(on_old())
        n_node = len([m for m in msgs(pa, "alice") if "new on the p2p network" in m["text"]])
        n_old_new = len([m for m in msgs(pa, "alice") if m["text"] == "new on the old server"])
        check("no echo: one copy each side after 5 s of cycles", (n_old, n_node, n_old_new) == (1, 1, 1), "%d/%d/%d" % (n_old, n_node, n_old_new))
        private_on_old = [m for m in old_get("/api/messages?after=0")["messages"] if "private and signed" in m["text"]]
        check("private p2p mail never copied to the old server", private_on_old == [])
        bridge.terminate()
        bridge.wait(10)
        bridge = subprocess.Popen(bridge_cmd, stdout=open(os.path.join(work, "bridge2.log"), "w"), stderr=subprocess.STDOUT)
        time.sleep(4)
        check("bridge restart adds no duplicates", len(on_old()) == 1 and
              len([m for m in msgs(pa, "alice") if m["text"] == "new on the old server"]) == 1)

        # 5. Member list replication: seq 2 (adds node C and member u.dave) given only to A.
        m2 = member_list(2, ["A", "B", "C"], extra_members=["dave"])
        shutil.copy(m2, os.path.join(work, "members.A.json"))
        got, dt = wait_for(lambda: req("GET", pb, "/api/me", tok["bob"])[1].get("members_seq") == 2, timeout=30)
        check("B adopts seq 2 from the network (its own file still says 1)", got, "%.1fs" % dt)
        shutil.copy(m2, os.path.join(work, "members.C.json"))
        check("node C (only in seq 2; refuse_token_only) starts", C.start())
        got, dt = wait_for(lambda: [m for m in msgs(pc, "carol", "thread=signed") if m["attest"] == "agent"], timeout=40)
        check("C catches up the agent-signed mail (sealed before C joined; read through a grant)", got, "%.1fs" % dt)
        hist = {m["id"]: m["text"] for m in msgs(pc, "carol")}
        check("C reads the imported history under the old numbers", hist.get(1) == "first ever" and hist.get(8) == "eighth", str(sorted(hist))[:80])
        rc, out = im(pc, "carol", "download", fid, "-o", os.path.join(work, "gotC.bin"))
        check("C downloads the attachment sent before it joined", rc == 0 and open(os.path.join(work, "gotC.bin"), "rb").read() == payload, out)
        rc, out = im(pc, "carol", "read", "--thread", "signed", "--json")
        check("C cannot read the private mail between alice and bob", rc == 0 and "private and signed" not in out)
        check("C stored no token-only mail", not [m for m in msgs(pc, "carol") if m["attest"] == "token"])
        st, r = req("POST", pc, "/api/messages", tok["carol"], {"to": "all", "thread": "c", "text": "token only on C"})
        check("C refuses a token-only post", st == 400, r.get("error", ""))
        rc, out = im(pc, "carol", "send", "--to", "all", "--thread", "c", "signed from C")
        check("C accepts a signed post", rc == 0, out)
        got, dt = wait_for(lambda: [m for m in msgs(pb, "bob", "thread=c")], timeout=30)
        check("B (accepting C only through the adopted list) receives C's mail", got and got[0]["text"] == "signed from C", "%.1fs" % dt)
    finally:
        if bridge:
            bridge.terminate()
        oldsrv.terminate()
        for n in (A, B, C):
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
