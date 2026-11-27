#!/usr/bin/env python3
"""An open room on a hub, used by three outside hosts that each trust only the hub, two of them trusted by the hub
only after the room was made. Every key is a throwaway made here.

  python3 tests/late_rooms.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]

Hosts: "hub" (names alice) trusts "north" (n.) from the start; "south" (s.) and "east" (e.) are added to the hub's
trust file later. north, south and east each trust only the hub. alice makes the open room alice/town while only
north is trusted, so its create event is sealed to the hub and north alone. Checks: alice adds s.carol once south is
trusted, and south has the room right away, with its members from before it was trusted (the add's key grant of the
room's membership events). East is the stuck case of builds before that grant: alice adds e.dave before east is
trusted, so nothing east can open names the room; east logs "kept sealed: no key" once; the creator's `room vouch`
repairs it with no rejoin. Then bob, carol and dave each post and each reads the others; the room's posts from
before a host was trusted are not granted.
"""
import argparse
import json
import os
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
    hosts = ("hub", "north", "south", "east")
    names = {"hub": ["alice"], "north": ["n."], "south": ["s."], "east": ["e."]}
    pub = {h: run(bin_, "keygen", k(h)) for h in hosts}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts}
    api = {h: free_port() for h in hosts}
    network = run(bin_, "network-id")

    def write_trust(h, trusted, seq):
        trust = {"v": 1, "network": network, "seq": seq, "members": [],
                 "nodes": [{"name": n, "key": pub[n], "addrs": ["127.0.0.1:%d" % udp[n]], "names": names[n]} for n in trusted]}
        path = os.path.join(work, "trust-%s.json" % h)
        with open(path + ".tmp", "w") as f:
            json.dump(trust, f)
        os.replace(path + ".tmp", path)

    write_trust("hub", ("hub", "north"), 1)
    for h in hosts[1:]:
        write_trust(h, ("hub", h), 1)
    nodes = {h: Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                     "iroh_port": udp[h], "node_key_file": k(h),
                                     "members_file": os.path.join(work, "trust-%s.json" % h), "sync_secs": SYNC})
             for h in hosts}
    home = {"alice": "hub", "n.bob": "north", "s.carol": "south", "e.dave": "east"}
    room = "alice/town"

    def cl(agent, *args, timeout=60):
        h = home[agent]
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=agent.split(".")[-1],
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h], ISLANDMAIL_AS=agent)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def info(agent):
        rc, out = cl(agent, "room", "info", room, "--json")
        try:
            return json.loads(out) if rc == 0 else {}
        except ValueError:
            return {}

    def usable(agent):
        i = info(agent)
        return bool(i.get("created") and i.get("member"))

    def texts(agent):
        rc, out = cl(agent, "room", "read", room, "--latest", "200", "--json")
        try:
            return [m["text"] for m in json.loads(out)["messages"]] if rc == 0 else []
        except ValueError:
            return []

    def log(host):
        with open(os.path.join(work, host + ".log")) as f:
            return f.read()

    def knows(agent, name):
        return name in cl(agent, "who")[1]

    try:
        for h in hosts:
            check("%s node starts" % h, nodes[h].start())
        for agent in home:
            rc, out = cl(agent, "whoami")
            check("%s gets its key and certificate" % agent, rc == 0, out[-160:])
        got, t = wait_for(lambda: knows("alice", "n.bob"), timeout=40)
        check("the hub knows north's agent", got, "%.1fs" % t)

        # The room is made while the hub trusts north only.
        rc, out = cl("alice", "room", "create", "town", "--open")
        check("alice makes the open room alice/town", rc == 0, out[-200:])
        rc, out = cl("alice", "room", "send", room, "early post")
        check("and posts in it", rc == 0, out[-200:])
        rc, out = cl("alice", "room", "add", room, "n.bob")
        check("alice adds n.bob", rc == 0, out[-200:])
        got, t = wait_for(lambda: usable("n.bob"), timeout=60)
        check("north has the room with bob in it", got, "%.1fs" % t)

        # South is trusted after the room was made: its add carries the room's membership events.
        write_trust("hub", ("hub", "north", "south"), 2)
        got, t = wait_for(lambda: knows("alice", "s.carol"), timeout=60)
        check("the hub trusts south now and knows its agent", got, "%.1fs" % t)
        rc, out = cl("alice", "room", "add", room, "s.carol")
        check("alice adds s.carol", rc == 0, out[-200:])
        got, t = wait_for(lambda: usable("s.carol"), timeout=60)
        check("south, trusted after the room was made, has it with carol in it", got, "%.1fs" % t)
        i = info("s.carol")
        check("south folds the events from before it was trusted (alice made it, bob is in it)",
              i.get("creator") == "alice" and {"alice", "n.bob", "s.carol"} <= set(i.get("members") or []), i)
        rc, out = cl("s.carol", "room", "send", room, "carol right after her add")
        check("carol posts right after her add", rc == 0, out[-200:])

        # East: added before the hub trusts it, so no envelope east can open names the room (the stuck case).
        rc, out = cl("alice", "room", "add", room, "e.dave")
        check("alice adds e.dave before east is trusted", rc == 0, out[-200:])
        write_trust("hub", ("hub", "north", "south", "east"), 3)
        got, t = wait_for(lambda: knows("alice", "e.dave"), timeout=60)
        check("the hub trusts east now and knows its agent", got, "%.1fs" % t)
        got, t = wait_for(lambda: "kept sealed: no key" in log("east"), timeout=60)
        check("east keeps the room's envelopes sealed and says so", got, "%.1fs" % t)
        time.sleep(SYNC * 3)
        check("east has no room yet: its create event has no key for east", not usable("e.dave"), info("e.dave"))
        rc, out = cl("e.dave", "room", "send", room, "too early")
        check("and dave cannot post there, told where the room will come from", rc != 0 and "no room" in out
              and "room vouch " + room in out, out[-200:])
        rc, out = cl("alice", "room", "vouch", room)
        check("alice vouches again", rc == 0, out[-200:])
        got, t = wait_for(lambda: usable("e.dave"), timeout=60)
        check("east has the room now, with no rejoin", got, "%.1fs" % t)
        lines = [l for l in log("east").splitlines() if "kept sealed: no key" in l]
        check("east logged the sealed envelopes once", len(lines) == 1, lines[-3:])

        # Everyone posts; everyone reads the others.
        posts = {"n.bob": "hello from the north", "s.carol": "hello from the south", "e.dave": "hello from the east"}
        for agent, text in posts.items():
            rc, out = cl(agent, "room", "send", room, text)
            check("%s posts" % agent, rc == 0, out[-200:])
        for agent in posts:
            for other, text in posts.items():
                if other == agent:
                    continue
                got, t = wait_for(lambda: text in texts(agent), timeout=60)
                check("%s reads %s's post" % (agent, other), got, "%.1fs" % t)
        got, t = wait_for(lambda: all(x in texts("alice") for x in posts.values()), timeout=60)
        check("alice reads all three", got, "%.1fs" % t)
        check("south and east do not get the room's posts from before they were trusted",
              "early post" not in texts("s.carol") and "early post" not in texts("e.dave"))
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
