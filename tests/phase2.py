#!/usr/bin/env python3
"""Direct-peer integration tests for sender signatures, attachments and membership changes.

  python3 tests/phase2.py --bin target/debug/mailnode --repo . [--workdir DIR]
"""
import argparse
import importlib.util
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
    names = ["operator", "nodeA", "nodeB", "nodeC", "alice", "bob", "carol", "dave"]
    pub = {n: run(bin_, "keygen", k(n)) for n in names}
    agents = {"alice": "t.alice", "bob": "t.bob", "carol": "u.carol"}
    P = {x: free_port() for x in ("apiA", "apiB", "apiC")}
    P.update({x: free_port(socket.SOCK_DGRAM) for x in ("udpA", "udpB", "udpC")})

    def member_list(seq, nodes, extra_members=()):
        lst = {
            "v": 1, "network": "test", "seq": seq, "issued": "", "operator": "",
            "members": [{"name": agents[n], "sub": "agent:%s@test" % n, "key": pub[n]} for n in agents]
                       + [{"name": "u.dave", "sub": "agent:dave@test", "key": pub["dave"]} for _ in extra_members],
            "nodes": [{"name": h, "key": pub["node" + h], "addrs": ["127.0.0.1:%d" % P["udp" + h]]} for h in nodes],
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
            "members_file": os.path.join(work, "members.%s.json" % h),
            "sync_secs": 2,
        }
        c.update(extra)
        return c

    # islandmail.py identities + cached tokens (it never calls a home)
    im_dir = os.path.join(work, "islandmail")
    os.makedirs(os.path.join(im_dir, "identities"))
    for n in agents:
        path = os.path.join(im_dir, "identities", agents[n] + ".json")
        json.dump({"name": agents[n], "sub": "agent:%s@test" % n, "id": pub[n], "seed": open(k(n)).read().strip()},
                  open(path, "w"))
        os.chmod(path, 0o600)  # the client refuses identity files other users can read
    def im(port, who, *args, timeout=60):
        env = dict(os.environ, ISLANDMAIL_URL="http://127.0.0.1:%d" % port, ISLANDMAIL_DIR=im_dir,
                   ISLANDMAIL_AS=agents[who])
        p = subprocess.run([sys.executable, client, *args], capture_output=True, text=True, env=env, timeout=timeout, cwd=work)
        return p.returncode, (p.stdout + p.stderr).strip()

    # Agent tokens minted the way the client mints them (single-use, for one node's key).
    spec = importlib.util.spec_from_file_location("islandmail", client)
    imc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imc)

    def atok(port, who, ttl=300, seed_of=None):
        key = req("GET", port, "/api/node")[1]["node"]
        ident = {"name": agents[who], "sub": "agent:%s@test" % who, "seed": open(k(seed_of or who)).read().strip()}
        return imc.agent_token(ident, key, ttl)


    def msgs(port, who, q=""):
        t = atok(port, who)
        return req("GET", port, "/api/messages?" + q, t)[1].get("messages", [])

    A, B, C = [Node(bin_, work, h, cfg(h)) for h in "ABC"]
    try:
        time.sleep(0.5)
        check("node A starts", A.start())
        check("node B starts", B.start())
        pa, pb, pc = A.port, B.port, C.port

        rc, out = im(pa, "alice", "send", "--to", "t.bob", "--thread", "signed", "signed by alice's key")
        check("islandmail.py signed send on A", rc == 0 and "reaches t.bob" in out, out)
        got, dt = wait_for(lambda: [m for m in msgs(pb, "bob", "thread=signed")])
        check("B shows it attest=agent", got and got[0]["attest"] == "agent" and got[0]["text"] == "signed by alice's key", "%.2fs" % dt)
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
                                     headers={"Authorization": "Bearer " + atok(pa, "alice"), "Content-Type": "application/octet-stream"})
        try:
            urllib.request.urlopen(big, timeout=60)
            code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        check("upload over 25 MiB refused (413)", code == 413, str(code))

        # 5. Member list replication: seq 2 (adds node C and member u.dave) given only to A.
        m2 = member_list(2, ["A", "B", "C"], extra_members=["dave"])
        shutil.copy(m2, os.path.join(work, "members.A.json"))
        got, dt = wait_for(lambda: req("GET", pb, "/api/me", atok(pb, "bob"))[1].get("members_seq") == 2, timeout=30)
        check("B adopts seq 2 from the network (its own file still says 1)", got, "%.1fs" % dt)
        shutil.copy(m2, os.path.join(work, "members.C.json"))
        check("node C (only in seq 2; refuse_token_only) starts", C.start())
        got, dt = wait_for(lambda: [m for m in msgs(pc, "carol", "thread=signed") if m["attest"] == "agent"], timeout=40)
        check("C catches up the agent-signed mail (sealed before C joined; read through a grant)", got, "%.1fs" % dt)
        rc, out = im(pc, "carol", "download", fid, "-o", os.path.join(work, "gotC.bin"))
        check("C downloads the attachment sent before it joined", rc == 0 and open(os.path.join(work, "gotC.bin"), "rb").read() == payload, out)
        rc, out = im(pc, "carol", "read", "--thread", "signed", "--json")
        check("C cannot read the private mail between alice and bob", rc == 0 and "private and signed" not in out)
        check("C stored no token-only mail", not [m for m in msgs(pc, "carol") if m["attest"] == "token"])
        st, r = req("POST", pc, "/api/messages", atok(pc, "carol"), {"to": "all", "thread": "c", "text": "token only on C"})
        check("C refuses an unsigned post", st == 400, r.get("error", ""))
        rc, out = im(pc, "carol", "send", "--to", "all", "--thread", "c", "signed from C")
        check("C accepts a signed post from a client with only its agent key", rc == 0, out)
        got, dt = wait_for(lambda: [m for m in msgs(pb, "bob", "thread=c")], timeout=30)
        check("B (accepting C only through the adopted list) receives C's mail", got and got[0]["text"] == "signed from C", "%.1fs" % dt)

        rc, out = im(pc, "carol", "whoami")
        check("islandmail.py whoami on C with only the agent key", rc == 0 and "u.carol" in out, out)
        t = atok(pc, "carol")
        st, r = req("GET", pc, "/api/me", t)
        check("/api/me reports auth agent-token", st == 200 and r.get("auth") == "agent-token" and r.get("name") == "u.carol", str(r)[:120])
        st, r = req("GET", pc, "/api/me", t)
        check("an agent token works once (replay refused)", st == 401 and "already used" in r.get("error", ""), r.get("error", ""))
        st, r = req("GET", pc, "/api/me", atok(pa, "carol"))
        check("a token minted for node A is refused on C", st == 401 and "another node" in r.get("error", ""), r.get("error", ""))
        st, r = req("GET", pc, "/api/me", atok(pc, "carol", seed_of="bob"))
        check("a token claiming carol but signed by bob's key is refused", st == 401 and "signature" in r.get("error", ""), r.get("error", ""))
        stranger = imc.agent_token({"name": "x.eve", "sub": "agent:eve@test", "seed": os.urandom(32).hex()},
                                   req("GET", pc, "/api/node")[1]["node"])
        st, r = req("GET", pc, "/api/me", stranger)
        check("a name not on the member list is refused (403)", st == 403, r.get("error", ""))
        st, r = req("POST", pa, "/api/messages", atok(pa, "alice"), {"to": "t.bob", "thread": "signed", "text": "unsigned"})
        check("an unsigned post with an agent token is refused on A too (no bearer token goes into envelopes)",
              st == 400 and "sign" in r.get("error", ""), r.get("error", ""))
        rc, out = im(pc, "carol", "selftoken", "--ttl", "120")
        st, r = req("GET", pc, "/api/threads", out) if rc == 0 else (0, {"error": out})
        check("islandmail.py selftoken prints a token C accepts", st == 200 and "threads" in r, r.get("error", ""))
        rc, out = im(pc, "carol", "send", "--private", "--to", "t.alice", "--thread", "nohome-private", "private, no home")
        check("private send from C with only the agent key", rc == 0, out)
        rc, out = im(pc, "carol", "send", "--to", "t.alice", "--thread", "nohome", "sent with no home")
        got, dt = wait_for(lambda: [m for m in msgs(pa, "alice", "thread=nohome")], timeout=30)
        check("A delivers carol's mail to alice", rc == 0 and got and got[0]["text"] == "sent with no home" and got[0]["attest"] == "agent", "%.1fs" % dt)
        rc, out = im(pa, "alice", "send", "--to", "u.carol", "--thread", "nohome", "reply via A")
        got, dt = wait_for(lambda: (lambda r: r if r[0] == 0 and "> reply via A" in r[1] else None)(
            im(pc, "carol", "read", "--thread", "nohome")), timeout=30, every=1)
        check("carol reads alice's reply on C with only her key", got, "%.1fs" % dt)
        log = open(os.path.join(work, "C.log")).read()
        check("C logs the sign-in kind (agent-token) and never a token", "signed in with an agent-token token" in log and "v4.public." not in log)
    finally:
        for n in (A, B, C):
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
