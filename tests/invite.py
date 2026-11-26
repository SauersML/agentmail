#!/usr/bin/env python3
"""Invite, join, accept: one host invites an agent name, a host with no node at all joins with one command, the
inviter accepts the reply; then private mail both ways and the room the invite named. Refusals: an expired invite, a
tampered invite, a tampered reply, and an accept for a name the inviter holds.

  python3 tests/invite.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, wait_for, work_directory  # noqa: E402


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def tamper(sealed, prefix, change):
    # The same signature over a changed payload.
    p, sig = sealed[len(prefix):].split(".")
    obj = json.loads(unb64u(p))
    change(obj)
    return prefix + b64u(json.dumps(obj).encode()) + "." + sig


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_, im = os.path.abspath(a.bin), os.path.abspath(a.islandmail)
    work = work_directory(a.workdir)

    # Host A: a node set up the usual way (key, trust file, config), names "alice".
    adir = os.path.join(work, "a")
    os.makedirs(adir)
    a_key = run(bin_, "keygen", os.path.join(adir, "node.seed"))
    a_udp, a_api = free_port(socket.SOCK_DGRAM), free_port()
    network = run(bin_, "network-id")
    a_trust = os.path.join(adir, "members.json")
    with open(a_trust, "w") as f:
        json.dump({"v": 1, "network": network, "seq": 1, "members": [],
                   "nodes": [{"name": "a", "key": a_key, "addrs": ["127.0.0.1:%d" % a_udp], "names": ["alice"]}]}, f)
    node_a = Node(bin_, adir, "config", {"data_dir": "data", "api_listen": "127.0.0.1:%d" % a_api, "iroh_port": a_udp,
                                         "node_key_file": "node.seed", "members_file": "members.json", "sync_secs": 3})
    a_cfg = os.path.join(adir, "config.json")

    # Host B: nothing yet. Its node folder and client folder are made by join.
    bdir = os.path.join(work, "b")
    b_cfg = os.path.join(bdir, "node", "config.json")
    b_udp, b_api = free_port(socket.SOCK_DGRAM), free_port()

    def cl(host, *args, timeout=90):
        api = a_api if host == "a" else b_api
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, host, "client"), ISLANDMAIL_URL="http://127.0.0.1:%d" % api)
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()

    def js(host, *args):
        rc, out, _ = cl(host, *args, "--json")
        try:
            return json.loads(out) if rc == 0 else None
        except ValueError:
            return None

    def join(invite):
        return cl("b", "join", invite, "--config", b_cfg, "--bin", bin_, "--api", "127.0.0.1:%d" % b_api,
                  "--listen", "127.0.0.1:%d" % b_udp)

    def b_pid():
        try:
            with open(os.path.join(bdir, "node", "node.pid")) as f:
                return int(f.read())
        except OSError:
            return None

    try:
        check("A's node starts", node_a.start())
        rc, out, err = cl("a", "room", "create", "plan", "--private")
        check("alice makes a private room alice/plan", rc == 0, (out + err)[-200:])
        rc, out, err = cl("a", "room", "send", "alice/plan", "before bob")
        check("and posts in it", rc == 0, err[-200:])

        # Refused before anything is set up on B.
        rc, out, err = cl("a", "invite", "--name", "alice", "--config", a_cfg)
        check("no invite for a name this node holds", rc != 0 and "409" in err, err[-200:])
        rc, short, err = cl("a", "invite", "--name", "bob", "--ttl", "1", "--config", a_cfg)
        check("a one-second invite", rc == 0 and short.startswith("islandmail-invite1."), err[-200:])
        time.sleep(2)
        rc, out, err = join(short)
        check("join refuses an expired invite", rc != 0 and "expired" in err, err[-200:])
        check("and sets nothing up", not os.path.exists(b_cfg))

        rc, inv, err = cl("a", "invite", "--name", "bob", "--room", "plan", "--config", a_cfg)
        check("alice invites bob into alice/plan", rc == 0 and inv.startswith("islandmail-invite1."), err[-200:])
        check("the invite is one compact line", "\n" not in inv and len(inv) < 1500, "%d chars" % len(inv))
        bad = tamper(inv, "islandmail-invite1.", lambda o: o.update(name="mallory"))
        rc, out, err = join(bad)
        check("join refuses a tampered invite", rc != 0 and "signature" in err, err[-200:])
        check("and sets nothing up", not os.path.exists(b_cfg))

        # One command on B: node key, trust file, config, node started, inviter trusted, bob's key certified.
        rc, reply, err = join(inv)
        check("join on a host with no node", rc == 0 and reply.startswith("islandmail-reply1."), err[-400:])
        check("join started B's node", b_pid() is not None)
        with open(b_cfg) as f:
            cfg = json.load(f)
        with open(os.path.join(bdir, "node", "members.json")) as f:
            bt = json.load(f)
        check("B's config takes the inviter's relay", cfg["relay"] == [], json.dumps(cfg))
        check("B's trust file: A's network, seq 2", bt["network"] == network and bt["seq"] == 2, json.dumps(bt)[:200])
        ent = {n["key"]: n for n in bt["nodes"]}
        check("B trusts A as A listed itself", ent.get(a_key, {}).get("names") == ["alice"]
              and ent[a_key]["addrs"] == ["127.0.0.1:%d" % a_udp], json.dumps(bt["nodes"]))
        check("join tells what it set", "trusts node 'a'" in err and "network" in err, err[-300:])
        check("bob's key is made at join", os.path.exists(os.path.join(bdir, "client", "identities", "bob.json")))

        bad = tamper(reply, "islandmail-reply1.", lambda o: o["node"].update(names=["alice"]))
        rc, out, err = cl("a", "accept", bad, "--config", a_cfg)
        check("accept refuses a tampered reply", rc != 0 and "signature" in err, err[-200:])

        rc, out, err = cl("a", "accept", reply, "--config", a_cfg)
        check("alice accepts", rc == 0 and "for exactly bob" in out, (out + err)[-300:])
        check("and adds bob to alice/plan", "added bob to alice/plan" in out, out[-300:])
        with open(a_trust) as f:
            at = json.load(f)
        b_ent = [n for n in at["nodes"] if n["key"] != a_key]
        check("A trusts B's node for exactly bob", len(b_ent) == 1 and b_ent[0]["names"] == ["bob"] and at["seq"] == 2,
              json.dumps(at["nodes"]))

        # Private mail both ways.
        got, t = wait_for(lambda: cl("b", "send", "--to", "alice", "--private", "hi alice, bob here")[0] == 0, timeout=30, every=1)
        check("bob sends alice private mail", got, "%.1fs" % t)
        got, t = wait_for(lambda: [m for m in js("a", "read", "--to-me") or [] if m.get("text") == "hi alice, bob here"], timeout=30)
        check("alice reads it", got and got[0]["from"] == "bob", json.dumps(got)[:200])
        rc, out, err = cl("a", "send", "--to", "bob", "--private", "welcome, bob")
        check("alice answers in private", rc == 0, err[-200:])
        got, t = wait_for(lambda: [m for m in js("b", "read", "--to-me") or [] if m.get("text") == "welcome, bob"], timeout=30)
        check("bob reads it", bool(got), "%.1fs" % t)

        # The room the invite named.
        got, t = wait_for(lambda: [r for r in js("b", "rooms") or [] if r.get("id") == "alice/plan"], timeout=30)
        check("bob is in alice/plan", bool(got), "%.1fs" % t)
        posted = []
        got, t = wait_for(lambda: posted.append(cl("b", "room", "send", "alice/plan", "thanks for the invite")) or posted[-1][0] == 0,
                          timeout=30, every=1)
        check("bob posts there", got, "%.1fs %s" % (t, posted[-1][2][-200:]))
        got, t = wait_for(lambda: [m for m in (js("a", "room", "read", "alice/plan") or {}).get("messages", []) if m.get("text") == "thanks for the invite"],
                          timeout=30)
        check("alice reads bob's room post", bool(got), "%.1fs" % t)
        got = [m for m in (js("b", "room", "read", "alice/plan") or {}).get("messages", []) if m.get("text") == "before bob"]
        check("bob reads the room's earlier post (full history)", bool(got))

        # Accept for a name we hold: an invite for carol, then carol becomes one of A's own names before the accept.
        rc, inv2, err = cl("a", "invite", "--name", "carol", "--config", a_cfg)
        rc2, reply2, err2 = join(inv2)
        check("bob's node joins a second invite (carol)", rc == 0 and rc2 == 0, (err + err2)[-200:])
        with open(a_trust) as f:
            at = json.load(f)
        at["seq"] += 1
        next(n for n in at["nodes"] if n["key"] == a_key)["names"].append("carol")
        with open(a_trust + ".tmp", "w") as f:
            json.dump(at, f)
        os.replace(a_trust + ".tmp", a_trust)
        time.sleep(2)
        rc, out, err = cl("a", "accept", reply2, "--config", a_cfg)
        check("accept refuses a name this node holds", rc != 0 and "409" in err and "carol" in err, err[-200:])
        with open(a_trust) as f:
            at2 = json.load(f)
        check("and leaves the trust file alone", at2 == at, "seq %d" % at2["seq"])
    finally:
        node_a.stop()
        pid = b_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
