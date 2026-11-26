#!/usr/bin/env python3
"""A node with "certify": "identities_dir" refuses POST /api/agents and certifies only the identity files its
operator put in identities_dir. One node on loopback, throwaway keys.

  python3 tests/certify_held.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import json
import os
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, work_directory, write_private_json  # noqa: E402


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
    seed = os.path.join(work, "keys", "lab.seed")
    pub = run(bin_, "keygen", seed)
    udp, port = free_port(socket.SOCK_DGRAM), free_port()
    trust = os.path.join(work, "trust.json")
    with open(trust, "w") as f:
        json.dump({"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [], "nodes": [
            {"name": "lab", "key": pub, "addrs": ["127.0.0.1:%d" % udp], "names": ["lab."]}]}, f)
    operator, held = os.path.join(work, "operator"), os.path.join(work, "operator", "identities")
    user_dir = os.path.join(work, "user")

    def cl(directory, *args):
        env = dict(os.environ, ISLANDMAIL_DIR=directory, ISLANDMAIL_URL="http://127.0.0.1:%d" % port, USER="walkin")
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=60)
        return p.returncode, (p.stdout + p.stderr).strip()

    # The operator makes lab.alice's key (no node needed) and keeps it in the node's identities_dir.
    rc, out = cl(operator, "newkey", "lab.alice")
    check("operator makes a key for lab.alice", rc == 0, out[-200:])
    os.makedirs(os.path.join(user_dir, "identities"), mode=0o700)
    with open(os.path.join(held, "lab.alice.json")) as f:  # the operator hands lab.alice its key file
        write_private_json(os.path.join(user_dir, "identities", "lab.alice.json"), json.load(f))
    cfg = {"data_dir": os.path.join(work, "data"), "api_listen": "127.0.0.1:%d" % port, "iroh_port": udp,
           "node_key_file": seed, "members_file": trust, "sync_secs": 3, "identities_dir": held}

    def refused(name, c):
        path = os.path.join(work, name + ".json")
        with open(path, "w") as f:
            json.dump(c, f)
        try:
            p = subprocess.run([bin_, "run", path], capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            return False, "still running"
        return p.returncode != 0, (p.stdout + p.stderr)[-200:]

    bad = dict(cfg, certify="identities_dir")
    bad.pop("identities_dir")
    check("certify identities_dir without identities_dir is refused at startup", *refused("bad", bad))
    check("an unknown certify value is refused at startup", *refused("typo", dict(cfg, certify="closed")))

    node = Node(bin_, work, "lab", dict(cfg, certify="identities_dir"))
    try:
        check("node starts with certify identities_dir", node.start())
        rc, out = cl(user_dir, "--as", "lab.alice", "whoami")
        check("the held identity signs in (certified at startup)", rc == 0 and "lab.alice" in out, out[-200:])
        walkin = os.path.join(work, "walkin")
        rc, out = cl(walkin, "--as", "lab.mallory", "whoami")
        check("a walk-in name is refused with 403", rc != 0 and "403" in out and "identities_dir" in out, out[-240:])
        check("and its uncertified key is not kept", not os.path.exists(os.path.join(walkin, "identities", "lab.mallory.json")))
        rc, out = cl(walkin, "whoami")
        check("first use with the default name is refused too", rc != 0 and "403" in out, out[-240:])
        rc, out = cl(user_dir, "--as", "lab.alice", "send", "--to", "lab.alice", "note to self")
        check("the held identity sends mail", rc == 0 and out.startswith("sent "), out[-200:])
    finally:
        node.stop()

    # Default (no "certify"): any local user still gets a name, as before.
    node = Node(bin_, work, "open", dict(cfg, data_dir=os.path.join(work, "data-open")))
    try:
        check("node starts with the default", node.start())
        rc, out = cl(os.path.join(work, "walkin2"), "--as", "lab.bob", "whoami")
        check("by default a local user certifies a free name", rc == 0 and "lab.bob" in out, out[-200:])
    finally:
        node.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
