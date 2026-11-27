#!/usr/bin/env python3
"""Upgrade without rejoin. Three hosts (alice, bob, carol) on the previous release, with private and open mail, a
private room, an outsider (dave) who joined with an invite, and a pending invite for erin. Bob's host swaps to this
build (node and client) with its data, trust file and config as they are: old mail, the room and new mail work both
ways between the two builds. Then every other host swaps; erin joins with the invite issued before the upgrade, and
nobody rejoins.

  python3 tests/upgrade.py --old-bin OLD/islandmail-node --old-islandmail OLD/clients/islandmail.py \
      --bin target/release/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, wait_for, work_directory  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-bin", required=True)
    ap.add_argument("--old-islandmail", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    old_bin, old_im = os.path.abspath(a.old_bin), os.path.abspath(a.old_islandmail)
    new_bin, new_im = os.path.abspath(a.bin), os.path.abspath(a.islandmail)
    work = work_directory(a.workdir)
    os.makedirs(os.path.join(work, "keys"))
    names = {"a": "alice", "b": "bob", "c": "carol"}
    seed = {h: os.path.join(work, "keys", h + ".seed") for h in names}
    pub = {h: run(old_bin, "keygen", seed[h]) for h in names}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in names}
    api = {h: free_port() for h in "abcde"}
    trust = {"v": 1, "network": run(old_bin, "network-id"), "seq": 1, "members": [], "nodes": [
        {"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": [names[h]]} for h in names]}
    nodes, trust_file = {}, {}
    for h in names:
        trust_file[h] = os.path.join(work, "trust-%s.json" % h)
        with open(trust_file[h], "w") as f:
            json.dump(trust, f)
        nodes[h] = Node(old_bin, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                           "iroh_port": udp[h], "node_key_file": seed[h], "members_file": trust_file[h],
                                           "sync_secs": 2})
    a_cfg = os.path.join(work, "a.json")
    client = {h: old_im for h in "abcd"}
    client["e"] = new_im
    joined = {h: (os.path.join(work, h, "node", "config.json"), free_port(socket.SOCK_DGRAM)) for h in "de"}

    def cl(h, *args, timeout=150):
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h])
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, client[h], *args], env=env, capture_output=True, text=True, timeout=timeout, cwd=work)
        return p.returncode, (p.stdout + p.stderr).strip()

    def texts(h):
        rc, out = cl(h, "read", "--json", "--latest", "100")
        try:
            return [m.get("text") for m in json.loads(out)] if rc == 0 else []
        except ValueError:
            return []

    def room_texts(h):
        rc, out = cl(h, "room", "read", "alice/plan", "--json", "--latest", "100")
        try:
            return [m.get("text") for m in json.loads(out)["messages"]] if rc == 0 else []
        except (ValueError, KeyError, TypeError):
            return []

    def arrives(h, text, room=False, timeout=60):
        got, _ = wait_for(lambda: text in (room_texts(h) if room else texts(h)) or None, timeout=timeout, every=1)
        return bool(got)

    def send(h, to, text, *extra):
        got, _ = wait_for(lambda: cl(h, "send", *extra, "--to", to, text)[0] == 0 or None, timeout=60, every=2)
        return bool(got)

    def join(h, invite, bin_):
        # A loaded machine can miss the dial window (or the client's HTTP timeout): join again, up to three times. The
        # invite stays unspent until the inviting node answers, and a second join uses the node the first one made.
        cfg, port = joined[h]
        for _ in range(3):
            rc, out = cl(h, "join", invite, "--config", cfg, "--bin", bin_, "--api", "127.0.0.1:%d" % api[h],
                         "--listen", "127.0.0.1:%d" % port, "--wait", "120", timeout=300)
            if rc == 0 and "joined as" in out:
                break
            print("(join of %s did not complete, trying again: %s)" % (h, out[-200:].strip()), flush=True)
        return rc, out

    def joined_pid(h):
        try:
            with open(os.path.join(os.path.dirname(joined[h][0]), "node.pid")) as f:
                return int(f.read())
        except (OSError, ValueError):
            return None

    swapped = []

    def invite_in(out):
        m = re.search(r"(?m)^im1\S+", out)
        return m.group(0) if m else ""

    def swap_joined(h):
        # A node join started (detached): stop it, start this build on the same config.
        pid = joined_pid(h)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            wait_for(lambda: not alive(pid), timeout=20)
        log = open(os.path.join(work, h + "-new.log"), "a")
        p = subprocess.Popen([new_bin, "run", joined[h][0]], stdout=log, stderr=subprocess.STDOUT)
        swapped.append(p)
        client[h] = new_im
        return bool(wait_for(lambda: cl(h, "whoami")[0] == 0 or None, timeout=30, every=1)[0])

    def alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def swap(h):
        nodes[h].stop()
        nodes[h].bin = new_bin
        client[h] = new_im
        return nodes[h].start()

    def seq(path):
        with open(path) as f:
            return json.load(f)["seq"]

    try:
        # The previous release, with some history.
        for h in names:
            check("old node %s starts" % h, nodes[h].start())
        for h in names:
            check("%s is certified at %s" % (names[h], h), cl(h, "whoami")[0] == 0)
        check("alice sends bob private mail (old)", send("a", "bob", "old private"))
        check("carol sends open mail (old)", send("c", "all", "old open", "--open"))
        made, _ = wait_for(lambda: cl("a", "room", "create", "plan", "--with", "bob")[0] == 0 or None, timeout=60, every=2)
        check("alice makes the private room alice/plan with bob (old)", made)
        check("and posts in it", cl("a", "room", "send", "alice/plan", "old room")[0] == 0)
        check("bob reads the private mail (old)", arrives("b", "old private"))
        check("bob reads the room (old)", arrives("b", "old room", room=True))
        rc, out = cl("a", "invite", "--name", "dave", "--room", "plan", "--config", a_cfg)
        inv = invite_in(out)
        check("alice invites dave into alice/plan (old)", rc == 0 and inv, out[-200:])
        rc, out = join("d", inv, old_bin)
        check("dave's host joins (old)", rc == 0 and "joined as dave" in out, out[-300:])
        check("dave sends alice mail (old)", send("d", "alice", "old from dave"))
        check("alice reads it (old)", arrives("a", "old from dave"))
        rc, out = cl("a", "invite", "--name", "erin", "--config", a_cfg)
        pending = invite_in(out)
        check("an invite for erin waits, unused", rc == 0 and pending, out[-200:])
        seqs = {h: seq(trust_file[h]) for h in "bc"}
        seqs["d"] = seq(os.path.join(os.path.dirname(joined["d"][0]), "members.json"))

        # Bob's host takes this build: same data, trust file and config, no rejoin.
        check("bob's node restarts on the new build", swap("b"))
        check("bob (new) still reads the old private mail", arrives("b", "old private", timeout=20))
        check("bob (new) still reads the old open mail", arrives("b", "old open", timeout=20))
        check("bob (new) still reads the old room", arrives("b", "old room", room=True, timeout=20))
        check("alice (old) -> bob (new)", send("a", "bob", "old to new") and arrives("b", "old to new"))
        check("bob (new) -> alice (old)", send("b", "alice", "new to old") and arrives("a", "new to old"))
        check("bob (new) -> carol (old), open", send("b", "all", "new open", "--open") and arrives("c", "new open"))
        check("bob (new) posts in the room, alice (old) reads it",
              cl("b", "room", "send", "alice/plan", "room from new")[0] == 0 and arrives("a", "room from new", room=True))
        check("alice (old) posts in the room, bob (new) reads it",
              cl("a", "room", "send", "alice/plan", "room from old")[0] == 0 and arrives("b", "room from old", room=True))

        # Everyone else swaps.
        check("alice's node restarts on the new build", swap("a"))
        check("carol's node restarts on the new build", swap("c"))
        check("dave's joined node restarts on the new build", swap_joined("d"))
        check("alice (new) still reads dave's old mail", arrives("a", "old from dave", timeout=20))
        check("dave (new) still reads the room", arrives("d", "old room", room=True))
        check("alice -> dave after the upgrade", send("a", "dave", "after upgrade") and arrives("d", "after upgrade"))
        check("carol (new) reads bob's mail", arrives("c", "new open", timeout=20))
        rc, out = join("e", pending, new_bin)
        check("erin joins with the invite issued before the upgrade", rc == 0 and "joined as erin" in out, out[-300:])
        check("erin -> alice", send("e", "alice", "erin here") and arrives("a", "erin here"))
        check("the room carries on", cl("a", "room", "send", "alice/plan", "room after")[0] == 0
              and arrives("b", "room after", room=True) and arrives("d", "room after", room=True))
        now = {h: seq(trust_file[h]) for h in "bc"}
        now["d"] = seq(os.path.join(os.path.dirname(joined["d"][0]), "members.json"))
        check("nobody rejoined: bob's, carol's and dave's trust files are as they were", now == seqs, "%s %s" % (seqs, now))
    finally:
        for n in nodes.values():
            n.stop()
        for p in swapped:
            p.terminate()
        for h in "de":
            pid = joined_pid(h)
            if pid and alive(pid):
                os.kill(pid, signal.SIGTERM)
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    if not failed:
        shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
