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
from two_nodes import RESULTS, Node, check, free_port, run, wait_for, work_directory, write_private_json  # noqa: E402


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
    seed = os.path.join(work, "keys", "dev.seed")
    pub = run(bin_, "keygen", seed)
    udp, port = free_port(socket.SOCK_DGRAM), free_port()
    trust = os.path.join(work, "trust.json")
    with open(trust, "w") as f:
        json.dump({"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [], "nodes": [
            {"name": "dev", "key": pub, "addrs": ["127.0.0.1:%d" % udp], "names": ["dev."]}]}, f)
    operator, held = os.path.join(work, "operator"), os.path.join(work, "operator", "identities")
    user_dir = os.path.join(work, "user")

    def cl(directory, *args):
        env = dict(os.environ, ISLANDMAIL_DIR=directory, ISLANDMAIL_URL="http://127.0.0.1:%d" % port, USER="walkin")
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=60)
        return p.returncode, (p.stdout + p.stderr).strip()

    # The operator makes dev.alice's key (no node needed) and keeps it in the node's identities_dir.
    rc, out = cl(operator, "newkey", "dev.alice")
    check("operator makes a key for dev.alice", rc == 0, out[-200:])
    os.makedirs(os.path.join(user_dir, "identities"), mode=0o700)
    with open(os.path.join(held, "dev.alice.json")) as f:  # the operator hands dev.alice its key file
        alice = json.load(f)
        write_private_json(os.path.join(user_dir, "identities", "dev.alice.json"), alice)
    check("newkey writes sub agent:NAME", alice.get("sub") == "agent:dev.alice", alice.get("sub"))
    # A held file whose sub is not agent:NAME would get a certificate its tokens then fail; the node refuses it.
    carol = {"name": "dev.carol", "sub": "agent:dev.carol@elsewhere", "seed": os.urandom(32).hex()}
    write_private_json(os.path.join(held, "dev.carol.json"), carol)
    os.makedirs(os.path.join(work, "carol", "identities"), mode=0o700)
    write_private_json(os.path.join(work, "carol", "identities", "dev.carol.json"), carol)
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

    node = Node(bin_, work, "dev", dict(cfg, certify="identities_dir"))
    try:
        check("node starts with certify identities_dir", node.start())
        rc, out = cl(user_dir, "--as", "dev.alice", "whoami")
        check("the held identity signs in (certified at startup)", rc == 0 and "dev.alice" in out, out[-200:])
        with open(os.path.join(work, "dev.log")) as f:
            log = f.read()
        check("a held file with another sub is refused at startup, naming the file and the fix",
              "refusing identity file" in log and "dev.carol.json" in log and '"agent:dev.carol"' in log,
              [l for l in log.splitlines() if "dev.carol" in l][-1:])
        rc, out = cl(os.path.join(work, "carol"), "--as", "dev.carol", "whoami")
        check("and it does not sign in", rc != 0 and "403" in out, out[-200:])
        # identities_dir is re-read while the node runs: a fixed file and a new one are certified with no restart.
        carol["sub"] = "agent:dev.carol"
        write_private_json(os.path.join(held, "dev.carol.json"), carol)
        write_private_json(os.path.join(work, "carol", "identities", "dev.carol.json"), carol)
        rc, out = cl(operator, "newkey", "dev.erin")
        os.makedirs(os.path.join(work, "erin", "identities"), mode=0o700)
        with open(os.path.join(held, "dev.erin.json")) as f:
            write_private_json(os.path.join(work, "erin", "identities", "dev.erin.json"), json.load(f))
        pid = node.proc.pid
        for who in ("carol", "erin"):
            ok, t = wait_for(lambda: cl(os.path.join(work, who), "--as", "dev." + who, "whoami")[0] == 0, timeout=20)
            check("a %s held file is certified while the node runs" % ("fixed" if who == "carol" else "new"), ok, "%.1fs" % t)
        check("with no restart", node.proc.pid == pid and node.proc.poll() is None)
        walkin = os.path.join(work, "walkin")
        rc, out = cl(walkin, "--as", "dev.mallory", "whoami")
        check("a walk-in name is refused with 403", rc != 0 and "403" in out and "identities_dir" in out, out[-240:])
        check("and its uncertified key is not kept", not os.path.exists(os.path.join(walkin, "identities", "dev.mallory.json")))
        rc, out = cl(walkin, "whoami")
        check("first use with the default name is refused too", rc != 0 and "403" in out, out[-240:])
        rc, out = cl(user_dir, "--as", "dev.alice", "send", "--to", "dev.alice", "note to self")
        check("the held identity sends mail", rc == 0 and out.startswith("sent "), out[-200:])
    finally:
        node.stop()

    # Default (no "certify"): any local user still gets a name, as before.
    node = Node(bin_, work, "open", dict(cfg, data_dir=os.path.join(work, "data-open")))
    try:
        check("node starts with the default", node.start())
        rc, out = cl(os.path.join(work, "walkin2"), "--as", "dev.bob", "whoami")
        check("by default a local user certifies a free name", rc == 0 and "dev.bob" in out, out[-200:])
    finally:
        node.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
