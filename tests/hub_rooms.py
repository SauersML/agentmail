#!/usr/bin/env python3
"""A room across nodes that trust only a hub, every key a throwaway made here.

  python3 tests/hub_rooms.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]

Hosts: "hub" (names alice) trusts "north" (names n.) and "south" (names s.); north and south each trust only the hub.
alice makes a private room with n.bob and s.carol; her client vouches for their keys and home nodes. Checks: mail in
the room goes both ways between north and south (through the hub); an envelope north cannot take (carol's mail to
alice alone) is logged once, not on every sync; after alice removes carol, a post carol's node wrote without knowing
of the removal reaches the hub but north refuses it.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, wait_for, work_directory  # noqa: E402

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
    hosts = ("hub", "north", "south")
    names = {"hub": ["alice"], "north": ["n."], "south": ["s."]}
    trusts = {"hub": hosts, "north": ("hub", "north"), "south": ("hub", "south")}
    pub = {h: run(bin_, "keygen", k(h)) for h in hosts}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts}
    api = {h: free_port() for h in hosts}
    network = run(bin_, "network-id")
    for h in hosts:
        trust = {"v": 1, "network": network, "seq": 1, "members": [],
                 "nodes": [{"name": n, "key": pub[n], "addrs": ["127.0.0.1:%d" % udp[n]], "names": names[n]} for n in trusts[h]]}
        with open(os.path.join(work, "trust-%s.json" % h), "w") as f:
            json.dump(trust, f)
    nodes = {h: Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                     "iroh_port": udp[h], "node_key_file": k(h),
                                     "members_file": os.path.join(work, "trust-%s.json" % h), "sync_secs": SYNC})
             for h in hosts}
    home = {"alice": "hub", "n.bob": "north", "s.carol": "south"}
    room = "alice/plan"

    def cl(agent, *args, timeout=60):
        h = home[agent]
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=agent.split(".")[-1],
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h])
        p = subprocess.run([sys.executable, im, "--as", agent, *args], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def texts(agent):
        rc, out = cl(agent, "room", "read", room, "--latest", "200", "--json")
        try:
            return [m["text"] for m in json.loads(out)["messages"]] if rc == 0 else []
        except ValueError:
            return []

    def refusals(host):
        with open(os.path.join(work, host + ".log")) as f:
            return re.findall(r"refused envelope ([0-9a-f]{12})", f.read())

    try:
        for h in hosts:
            check("%s node starts" % h, nodes[h].start())
        for agent in home:
            rc, out = cl(agent, "whoami")
            check("%s gets its key and certificate" % agent, rc == 0, out[-160:])
        got, t = wait_for(lambda: all(n in cl("alice", "who")[1] for n in ("n.bob", "s.carol")), timeout=40)
        check("the hub knows every agent", got, "%.1fs" % t)
        rc, out = cl("n.bob", "who")
        check("north does not know south's agent", rc == 0 and "s.carol" not in out, out[-200:])

        # Mail north cannot take: carol's private note to alice reaches north through the hub and is refused.
        rc, out = cl("s.carol", "send", "--to", "alice", "--thread", "note", "just for alice")
        check("carol writes to alice alone", rc == 0, out[-160:])

        rc, out = cl("alice", "room", "new", "plan", "@n.bob", "@s.carol")
        check("alice makes a room with n.bob and s.carol", rc == 0 and "n.bob" in out and "s.carol" in out, out[-300:])
        got, t = wait_for(lambda: any("vouched for the nodes of" in x for x in texts("n.bob")), timeout=40)
        check("north reads the room and alice's vouch", got, "%.1fs" % t)
        got, t = wait_for(lambda: any("vouched for the nodes of" in x for x in texts("s.carol")), timeout=40)
        check("south reads it too", got, "%.1fs" % t)

        rc, out = cl("s.carol", "room", "send", room, "hello from the south")
        check("carol posts at south", rc == 0, out[-200:])
        got, t = wait_for(lambda: "hello from the south" in texts("n.bob"), timeout=40)
        check("bob reads it at north (south's node vouched in this room)", got, "%.1fs" % t)
        rc, out = cl("n.bob", "room", "send", room, "hello from the north")
        check("bob posts at north", rc == 0, out[-200:])
        got, t = wait_for(lambda: "hello from the north" in texts("s.carol"), timeout=40)
        check("carol reads it at south", got, "%.1fs" % t)
        rc, out = cl("n.bob", "who")
        check("a vouch gives no names: north's who still lacks s.carol", rc == 0 and "s.carol" not in out, out[-200:])

        # Several sync rounds later each refused envelope is still logged once.
        time.sleep(SYNC * 5)
        seen = refusals("north")
        counts = {i: seen.count(i) for i in set(seen)}
        check("north refuses mail outside the room (carol's note to alice)", len(counts) >= 1, counts)
        check("and logs each refused envelope once, not on every sync", counts and max(counts.values()) == 1, counts)

        # Removal: south is down while alice removes carol, and the hub is down while carol (not knowing) posts.
        with open(os.path.join(work, "north.log")) as f:
            before = len(f.read())
        nodes["south"].stop()
        rc, out = cl("alice", "room", "remove", room, "s.carol")
        check("alice removes carol", rc == 0, out[-200:])
        def north_dropped():
            rc, out = cl("n.bob", "room", "info", room, "--json")
            return rc == 0 and "s.carol" not in json.loads(out).get("members", {})
        got, t = wait_for(north_dropped, timeout=40)
        check("north sees carol removed", got, "%.1fs" % t)
        nodes["hub"].stop()
        check("south starts while the hub is down", nodes["south"].start())
        rc, out = cl("s.carol", "room", "send", room, "after my removal")
        check("carol's node, not knowing, still writes her post", rc == 0, out[-200:])
        check("the hub starts again", nodes["hub"].start())
        got, t = wait_for(lambda: "after my removal" in texts("alice"), timeout=60)
        check("her post reaches the hub", got, "%.1fs" % t)

        def why():
            with open(os.path.join(work, "north.log")) as f:
                return [l for l in f.read()[before:].splitlines() if "refused envelope" in l and "s.carol" in l]
        # After the hub's restart north may take a few sync rounds to be offered it.
        got, t = wait_for(why, timeout=60)
        time.sleep(SYNC * 3)
        check("north does not take it: carol's node is no longer vouched for there", "after my removal" not in texts("n.bob"))
        check("north says why, once", len(why()) == 1, "%.1fs %s" % (t, why()[-2:]))
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
