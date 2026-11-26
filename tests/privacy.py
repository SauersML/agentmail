#!/usr/bin/env python3
"""Sealed metadata between three nodes. alice (at a) writes private mail to bob (at b) in a thread with a telling
name; node c, a trusted member outside that message's audience, syncs and keeps it, but its store holds no sender,
recipient, thread or text for it and the stored envelope names none of them. Members mail stays readable at c.
Envelope sizes fall on the padding buckets.

  python3 tests/privacy.py --bin target/release/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import base64
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, wait_for, work_directory  # noqa: E402

BUCKETS = [1 << 10, 4 << 10, 16 << 10, 64 << 10]


def padded(n):
    return n in BUCKETS or (n > BUCKETS[-1] and n % (64 << 10) == 0)


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
    hosts = {"a": "alice", "b": "bob", "c": "carol"}
    seed = {h: os.path.join(work, "keys", h + ".seed") for h in hosts}
    pub = {h: run(bin_, "keygen", seed[h]) for h in hosts}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts}
    api = {h: free_port() for h in hosts}
    trust = {"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [], "nodes": [
        {"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": [hosts[h]]} for h in hosts]}
    nodes = {}
    for h in hosts:
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

    def rows(h):
        db = sqlite3.connect("file:%s?mode=ro" % os.path.join(work, "data-" + h, "mail.sqlite"), uri=True, timeout=10)
        try:
            return db.execute("SELECT sender, recipient, thread, mode, text, env FROM messages").fetchall()
        finally:
            db.close()

    def texts(h):
        rc, out = cl(h, "read", "--json", "--latest", "20")
        return [m.get("text") for m in json.loads(out)] if rc == 0 else []

    try:
        for h in hosts:
            check("node %s starts" % h, nodes[h].start())
        for h in hosts:
            check("%s is certified at %s" % (hosts[h], h), cl(h, "whoami")[0] == 0)
        # Certificates replicate first, so alice's node knows bob's key.
        got, _ = wait_for(lambda: cl("a", "send", "--to", "bob", "--thread", "merger-talks",
                                     "the quiet words")[0] == 0 or None, timeout=30, every=1)
        check("alice sends private mail to bob", got)
        check("alice sends members mail", cl("a", "send", "--open", "--to", "all", "--thread", "lunch", "hello everyone")[0] == 0)
        got, _ = wait_for(lambda: "the quiet words" in texts("b") or None, timeout=30)
        check("bob reads it at b", got)
        got, _ = wait_for(lambda: len(rows("c")) >= 2 or None, timeout=30)
        check("c holds both envelopes", got)
        got, _ = wait_for(lambda: "hello everyone" in texts("c") or None, timeout=30)
        check("carol reads the members mail at c", got)
        check("carol does not see the private mail", "the quiet words" not in texts("c"))
        sealed = [r for r in rows("c") if r[3] == "sealed"]
        check("c keeps the private mail as one sealed row", len(sealed) == 1, str([r[:5] for r in rows("c")]))
        if sealed:
            sender, recipient, thread, _, text, env = sealed[0]
            check("the sealed row has no sender, recipient, thread or text", (sender, recipient, thread, text) == ("", "", "", None))
            leaks = [w for w in ("alice", "bob", "merger", "quiet", "private", '"to"', '"from"', '"thread"') if w in env]
            check("the stored envelope names none of them", not leaks, str(leaks))
            e = json.loads(env)
            ct = base64.urlsafe_b64decode(e["ciphertext"] + "=" * (-len(e["ciphertext"]) % 4))
            check("its ciphertext is a padding bucket", padded(len(ct) - 40), str(len(ct)))
            check("its slots are a power of two", len(e["keys"]) >= 2 and len(e["keys"]) & (len(e["keys"]) - 1) == 0)
        sizes = {len(json.loads(r[5])["ciphertext"]) for r in rows("c")}
        check("a short and a shorter message have the same size", len(sizes) == 1, str(sizes))
        log = open(os.path.join(work, "c.log")).read() if os.path.exists(os.path.join(work, "c.log")) else ""
        check("c's log does not show the private thread", "merger" not in log)
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
