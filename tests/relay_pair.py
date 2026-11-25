#!/usr/bin/env python3
"""Two nodes with NO addresses in the member list and the given relay setting ("n0", our relay URL, or a JSON list):
they must find each other through the relays alone (the setup for hosts with no open port). Throwaway keys.

  python3 tests/relay_pair.py --bin target/debug/mailnode --relay '["http://IP:PORT"]' [--workdir DIR]
"""
import argparse
import json
import os
import shutil
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import Client, Node, check, finish, free_port, member_list, run, wait_for  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--relay", default="\"n0\"", help="JSON: \"n0\", \"http://...\" or a list")
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = os.path.abspath(a.workdir or "relay-%d" % int(time.time()))
    if os.path.exists(work):
        shutil.move(work, work + ".old-%d" % int(time.time()))
    os.makedirs(os.path.join(work, "keys"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    pub = {n: run(bin_, "keygen", k(n)) for n in ("operator", "nodeA", "nodeB")}
    members = member_list(bin_, work, k("operator"), 1, [(h.lower(), pub["node" + h], None, []) for h in "AB"],
                          network="n0test")
    nodes = {}
    for h in "AB":
        nodes[h] = Node(bin_, work, h, {
            "data_dir": os.path.join(work, "data" + h), "api_listen": "127.0.0.1:%d" % free_port(),
            "iroh_port": free_port(socket.SOCK_DGRAM), "node_key_file": k("node" + h), "operator_key": pub["operator"],
            "members_file": members, "relay": json.loads(a.relay), "sync_secs": 5})
    alice, bob = Client(work, "alice", nodes["A"]), Client(work, "bob", nodes["B"])
    try:
        check("A starts (relay %s)" % a.relay, nodes["A"].start())
        check("B starts", nodes["B"].start())
        rc, out = alice("send", "--to", "b.bob", "over n0")
        check("post on A", rc == 0, out)
        got, dt = wait_for(lambda: "over n0" in bob.stdout("read", "--latest", "5")[1], timeout=120, every=1)
        check("B receives it with no configured addresses (relays only)", got, "%.1fs" % dt)
    finally:
        for n in nodes.values():
            n.stop()
    finish(work)

if __name__ == "__main__":
    main()
