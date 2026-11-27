#!/usr/bin/env python3
"""Attachments up to the one 100 MiB limit cross between two nodes; one byte over is refused. Throwaway keys, two
nodes on loopback, agents certified on first use.

  python3 tests/big_files.py --bin target/release/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, agent_token, check, free_port, run, wait_for, work_directory  # noqa: E402

MiB = 1024 * 1024
LIMIT = 100 * MiB


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
    hosts = {"a": "alice", "b": "bob"}
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
        nodes[h] = Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "identities_dir": os.path.join(work, "client-" + h, "identities"),
                  "api_listen": "127.0.0.1:%d" % api[h],
                                        "iroh_port": udp[h], "node_key_file": seed[h], "members_file": path, "sync_secs": 3})

    def cl(h, *args, timeout=300):
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h])
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=timeout, cwd=work)
        return p.returncode, (p.stdout + p.stderr).strip()

    def blob(name, size):
        path = os.path.join(work, name)
        with open(path, "wb") as f:
            for i in range(0, size, MiB):
                f.write(os.urandom(min(MiB, size - i)))
        return path

    def sha(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(MiB):
                h.update(chunk)
        return h.hexdigest()

    try:
        for h in hosts:
            check("node %s starts" % h, nodes[h].start())
        check("bob is certified at b", cl("b", "whoami")[0] == 0)
        for name, size in (("thirty.bin", 30 * MiB), ("just-under.bin", LIMIT - 1024), ("exactly.bin", LIMIT)):
            path = blob(name, size)
            rc, out = cl("a", "send", "--open", "--to", "bob", "--file", path, name)
            check("alice sends %s (%d bytes) at a" % (name, size), rc == 0 and re.search(r"(?m)^sent \S+ to bob", out), out[-300:])

            def arrived():
                rc, out = cl("b", "read", "--json", "--latest", "20")
                files = [f for m in (json.loads(out) if rc == 0 else []) for f in m.get("files", []) if f["name"] == name]
                if not files:
                    return None
                dest = os.path.join(work, "got-" + name)
                if os.path.exists(dest):
                    os.unlink(dest)
                rc, out = cl("b", "download", files[0]["id"], "-o", dest)
                return rc == 0 and dest
            got, t = wait_for(arrived, timeout=180, every=3)
            check("bob downloads %s at b, byte for byte" % name, got and sha(got) == sha(path), "%.1fs" % t)
            for p in (path, got):
                if p and os.path.exists(p):
                    os.unlink(p)

        over = blob("over.bin", LIMIT + 1)
        rc, out = cl("a", "send", "--open", "--to", "bob", "--file", over, "too big")
        check("a send one byte over 100 MiB fails (the node's 413)", rc != 0 and "413" in out, out[-200:])
        token = agent_token(os.path.join(work, "client-a"), api["a"])
        with open(over, "rb") as f:
            body = f.read()
        r = urllib.request.Request("http://127.0.0.1:%d/api/files?name=over" % api["a"], data=body, method="POST",
                                   headers={"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream"})
        try:
            urllib.request.urlopen(r, timeout=120)
            code = 200
        except urllib.error.HTTPError as e:
            code = e.code
        except (ConnectionError, urllib.error.URLError) as e:
            code = str(e)
        check("the node refuses an upload one byte over 100 MiB (413)", code == 413, str(code))
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
