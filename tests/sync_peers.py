#!/usr/bin/env python3
"""An unreachable peer does not delay sync with a live one. Nodes a and b on loopback, plus a listed peer whose UDP
port swallows every packet (its QUIC handshake never completes). An attachment posted at a (attachments travel only
by periodic sync, not gossip) must reach b within a few sync intervals although b's session with the dead peer hangs.

  python3 tests/sync_peers.py --bin target/release/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, wait_for, work_directory  # noqa: E402


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
    hosts = {"a": "alice", "b": "bob", "dead": "ghost"}
    seed = {h: os.path.join(work, "keys", h + ".seed") for h in hosts}
    pub = {h: run(bin_, "keygen", seed[h]) for h in hosts}
    black_hole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    black_hole.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def swallow():
        black_hole.settimeout(0.5)
        while not stop.is_set():
            try:
                black_hole.recv(65536)
            except OSError:
                pass
    threading.Thread(target=swallow, daemon=True).start()
    udp = {"a": free_port(socket.SOCK_DGRAM), "b": free_port(socket.SOCK_DGRAM), "dead": black_hole.getsockname()[1]}
    api = {h: free_port() for h in ("a", "b")}
    trust = {"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [], "nodes": [
        {"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": [hosts[h]]} for h in hosts]}
    nodes = {}
    for h in ("a", "b"):
        path = os.path.join(work, "trust-%s.json" % h)
        with open(path, "w") as f:
            json.dump(trust, f)
        nodes[h] = Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                        "iroh_port": udp[h], "node_key_file": seed[h], "members_file": path, "sync_secs": 2})

    def cl(h, *args):
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h])
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=120, cwd=work)
        return p.returncode, (p.stdout + p.stderr).strip()

    try:
        for h in ("a", "b"):
            check("node %s starts" % h, nodes[h].start())
        check("bob is certified at b", cl("b", "whoami")[0] == 0)
        time.sleep(5)  # b's sessions with the dead peer are under way and hanging
        path = os.path.join(work, "note.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(200_000))
        for i in range(2):
            rc, out = cl("a", "send", "--open", "--to", "bob", "--file", path, "attachment %d" % i)
            check("alice sends attachment %d at a" % i, rc == 0 and re.search(r"(?m)^sent \S+ to bob", out), out[-200:])
            t0 = time.time()

            def arrived():
                rc, out = cl("b", "read", "--json", "--latest", "5")
                files = [f for m in (json.loads(out) if rc == 0 else []) if m.get("text") == "attachment %d" % i
                         for f in m.get("files", [])]
                if not files:
                    return None
                dest = os.path.join(work, "got-%d" % i)
                return cl("b", "download", files[0]["id"], "-o", dest)[0] == 0
            got, _ = wait_for(arrived, timeout=60, every=0.5)
            took = time.time() - t0
            check("bob gets attachment %d at b within a few sync intervals despite the dead peer" % i,
                  got and took < 12, "%.1fs" % took)
            time.sleep(8)
    finally:
        stop.set()
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    if not failed:
        shutil.rmtree(work, ignore_errors=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
