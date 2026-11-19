#!/usr/bin/env python3
"""Two nodes with relay "n0" and NO addresses in the member list: they must find each other through n0's address
lookup and relays (the setup for hosts with no open port). Throwaway keys.

  python3 tests/n0_pair.py --bin target/debug/mailnode [--workdir DIR]
"""
import argparse
import json
import os
import shutil
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, req, run, wait_for  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = os.path.abspath(a.workdir or "n0-%d" % int(time.time()))
    if os.path.exists(work):
        shutil.move(work, work + ".old-%d" % int(time.time()))
    os.makedirs(os.path.join(work, "keys"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    pub = {n: run(bin_, "keygen", k(n)) for n in ("home", "operator", "nodeA", "nodeB", "alice", "bob")}
    lst = {"v": 1, "network": "n0test", "seq": 1, "issued": "", "operator": "",
           "members": [{"name": "t." + n, "sub": "agent:%s@test" % n, "key": pub[n]} for n in ("alice", "bob")],
           "nodes": [{"name": h, "key": pub["node" + h], "addrs": []} for h in "AB"], "bridges": [], "sig": ""}
    json.dump(lst, open(os.path.join(work, "members.unsigned.json"), "w"))
    run(bin_, "sign-members", k("operator"), os.path.join(work, "members.unsigned.json"), os.path.join(work, "members.json"))
    nodes = {}
    for h in "AB":
        nodes[h] = Node(bin_, work, h, {
            "data_dir": os.path.join(work, "data" + h), "api_listen": "127.0.0.1:%d" % free_port(),
            "iroh_port": free_port(socket.SOCK_DGRAM), "node_key_file": k("node" + h), "operator_key": pub["operator"],
            "members_file": os.path.join(work, "members.json"), "home": {"key": pub["home"], "iss": "home.test"},
            "relay": "n0", "sync_secs": 5})
    tok = {n: run(bin_, "mint-token", k("home"), "home.test", "t." + n, "agent:%s@test" % n, "3600") for n in ("alice", "bob")}
    try:
        check("A starts (relay n0)", nodes["A"].start())
        check("B starts (relay n0)", nodes["B"].start())
        st, _ = req("POST", nodes["A"].port, "/api/messages", tok["alice"], {"to": "t.bob", "text": "over n0"})
        check("post on A", st == 201)
        got, dt = wait_for(lambda: [m for m in req("GET", nodes["B"].port, "/api/messages?after=0", tok["bob"])[1]["messages"]
                                    if m["text"] == "over n0"], timeout=120, every=1)
        check("B receives it with no configured addresses (n0 lookup + relay)", got, "%.1fs" % dt)
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
