#!/usr/bin/env python3
"""Gossip neighbours settle. Eight nodes on loopback (the friends network's size), every one listing every other. After
a settle period no node may log a "gossip neighbor down" for 60 s, and every node has all seven others as neighbours.
With iroh-gossip's default active view of 5 slots, each periodic join from a node outside a full view evicted a
random neighbour, which rejoined and evicted another: hundreds of up/down pairs a minute that never stopped.

  python3 tests/gossip_churn.py --bin target/release/islandmail-node [--workdir DIR] [--nodes 8] [--watch 60]
"""
import argparse
import json
import os
import re
import shutil
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, work_directory  # noqa: E402

EVENT = re.compile(r"gossip neighbor (up|down) (\S+)")


def events(path):
    with open(path, errors="replace") as f:
        return EVENT.findall(re.sub(r"\x1b\[[0-9;]*m", "", f.read()))


def neighbours(evs):
    now = set()
    for kind, peer in evs:
        (now.add if kind == "up" else now.discard)(peer)
    return now


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--nodes", type=int, default=8)
    ap.add_argument("--settle", type=int, default=30)
    ap.add_argument("--watch", type=int, default=60)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = work_directory(a.workdir)
    os.makedirs(os.path.join(work, "keys"))
    hosts = ["n%d" % i for i in range(a.nodes)]
    seed = {h: os.path.join(work, "keys", h + ".seed") for h in hosts}
    pub = {h: run(bin_, "keygen", seed[h]) for h in hosts}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts}
    api = {h: free_port() for h in hosts}
    trust = {"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [], "nodes": [
        {"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": []} for h in hosts]}
    nodes = {}
    for h in hosts:
        path = os.path.join(work, "trust-%s.json" % h)
        with open(path, "w") as f:
            json.dump(trust, f)
        # A short sync interval: each one re-joins the topic, which is what evicted neighbours on a full view.
        nodes[h] = Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                        "iroh_port": udp[h], "node_key_file": seed[h], "members_file": path, "sync_secs": 3})
    log = {h: os.path.join(work, h + ".log") for h in hosts}
    try:
        for h in hosts:
            check("node %s starts" % h, nodes[h].start())
        time.sleep(a.settle)
        before = {h: len(events(log[h])) for h in hosts}
        time.sleep(a.watch)
        downs = {}
        for h in hosts:
            evs = events(log[h])
            downs[h] = sum(1 for kind, _ in evs[before[h]:] if kind == "down")
            check("%s has all %d other nodes as gossip neighbours" % (h, a.nodes - 1),
                  len(neighbours(evs)) == a.nodes - 1, "%d neighbours" % len(neighbours(evs)))
        total = sum(downs.values())
        check("no gossip neighbour goes down in %d s after a %d s settle" % (a.watch, a.settle), total == 0,
              "%d downs: %s" % (total, downs))
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    if not failed:
        shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
