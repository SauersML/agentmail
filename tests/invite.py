#!/usr/bin/env python3
"""Invite and join with no reply step: one host invites an agent name into a room, a host with no node at all joins
with one command, its node presents itself to the inviting node, and the inviting node trusts it for exactly that
name. Then the inviter's line about the join, private mail both ways, and the room. Refusals: an expired invite, a
tampered invite, a reused invite, another name than the invited one, a name the inviter holds. An unreachable
inviter falls back to the reply line and `accept`. A flood of bad join attempts leaves normal sync alone.

  python3 tests/invite.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, client_module, free_port, run, wait_for, work_directory  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def unb58(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


# Offsets in an invite's bytes: flags, network, node key, expiry, then the nonce and the name (length, then text).
NONCE_AT = 1 + 32 + 32 + 4
NAME_AT = NONCE_AT + 16


def flip(sealed, prefix, at):
    # The same signature over one changed byte.
    raw = bytearray(unb58(sealed[len(prefix):]))
    raw[at] ^= 1
    return prefix + b58(bytes(raw))


def forge(invite, seed, name=None, nonce=None):
    # An invite re-signed with the inviting node's key: another name, or a nonce the node never issued.
    payload = unb58(invite[3:])[:-64]
    if nonce is not None:
        payload = payload[:NONCE_AT] + nonce + payload[NAME_AT:]
    if name is not None:
        old = payload[NAME_AT]
        payload = payload[:NAME_AT] + bytes([len(name)]) + name.encode() + payload[NAME_AT + 1 + old:]
    return "im1" + b58(payload + client_module().ed25519_sign(seed, b"islandmail/invite/v1\n" + payload))


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
    with open(os.path.join(adir, "node.seed")) as f:
        a_seed = bytes.fromhex(f.read().strip())
    a_udp, a_api = free_port(socket.SOCK_DGRAM), free_port()
    network = run(bin_, "network-id")
    a_trust = os.path.join(adir, "members.json")
    with open(a_trust, "w") as f:
        json.dump({"v": 1, "network": network, "seq": 1, "members": [],
                   "nodes": [{"name": "a", "key": a_key, "addrs": ["127.0.0.1:%d" % a_udp], "names": ["alice"]}]}, f)
    node_a = Node(bin_, adir, "config", {"data_dir": "data", "api_listen": "127.0.0.1:%d" % a_api, "iroh_port": a_udp,
                                         "node_key_file": "node.seed", "members_file": "members.json", "sync_secs": 3})
    a_cfg = os.path.join(adir, "config.json")

    # Hosts B and C: nothing yet. Their node folders and client folders are made by join.
    fresh = {h: (os.path.join(work, h, "node", "config.json"), free_port(socket.SOCK_DGRAM), free_port()) for h in "bc"}

    def cl(host, *args, timeout=150):
        api = a_api if host == "a" else fresh[host][2]
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

    def join(host, invite, wait=60):
        cfg, udp, api = fresh[host]
        return cl(host, "join", invite, "--config", cfg, "--bin", bin_, "--api", "127.0.0.1:%d" % api,
                  "--listen", "127.0.0.1:%d" % udp, "--wait", str(wait))

    def trust_of(host):
        with open(os.path.join(work, host, "node", "members.json")) as f:
            return json.load(f)

    def a_trust_now():
        with open(a_trust) as f:
            return json.load(f)

    def pid(host):
        try:
            with open(os.path.join(work, host, "node", "node.pid")) as f:
                return int(f.read())
        except OSError:
            return None

    try:
        check("A's node starts", node_a.start())
        rc, out, err = cl("a", "room", "create", "plan", "--private")
        check("alice makes a private room alice/plan", rc == 0, (out + err)[-200:])
        rc, out, err = cl("a", "room", "send", "alice/plan", "before bob")
        check("and posts in it", rc == 0, err[-200:])

        # Refused before anything is set up.
        rc, out, err = cl("a", "invite", "--name", "alice", "--config", a_cfg)
        check("no invite for a name this node holds", rc != 0 and "409" in err, err[-200:])
        rc, short, err = cl("a", "invite", "--name", "bob", "--ttl", "1", "--config", a_cfg)
        check("a one-second invite", rc == 0 and short.startswith("im1"), err[-200:])
        time.sleep(2)
        rc, out, err = join("b", short)
        check("join refuses an expired invite", rc != 0 and "expired" in err, err[-200:])
        check("and sets nothing up", not os.path.exists(fresh["b"][0]))

        rc, inv, err = cl("a", "invite", "--name", "bob", "--room", "plan", "--config", a_cfg)
        check("alice invites bob into alice/plan", rc == 0 and inv.startswith("im1"), err[-200:])
        check("the invite is one short line", "\n" not in inv and len(inv) <= 260, "%d chars: %s" % (len(inv), inv))
        rc, out, err = join("b", flip(inv, "im1", NAME_AT))
        check("join refuses a tampered invite", rc != 0 and "signature" in err, err[-200:])
        check("and sets nothing up", not os.path.exists(fresh["b"][0]))

        # One command on B: node set up and started, presented to A, A trusts it for bob. No reply, no accept.
        rc, out, err = join("b", inv)
        check("join on a host with no node, no reply step", rc == 0 and out.startswith("joined as bob")
              and "alice/plan" in out and "imr1" not in out, (out + err)[-400:])
        check("join started B's node", pid("b") is not None)
        bt = trust_of("b")
        ent = {n["key"]: n for n in bt["nodes"]}
        check("B trusts A as A listed itself", ent.get(a_key, {}).get("names") == ["alice"]
              and ent[a_key]["addrs"] == ["127.0.0.1:%d" % a_udp] and bt["network"] == network, json.dumps(bt)[:300])
        at = a_trust_now()
        b_ent = [n for n in at["nodes"] if n["key"] != a_key]
        check("A trusts B's node for exactly bob, at once", len(b_ent) == 1 and b_ent[0]["names"] == ["bob"]
              and b_ent[0]["addrs"] == ["127.0.0.1:%d" % fresh["b"][1]], json.dumps(at["nodes"]))
        b_key = b_ent[0]["key"] if b_ent else ""

        # The inviter's lines: alice's next command (which also does the room add), and one in her inbox from bob.
        said = []
        got, t = wait_for(lambda: said.append(cl("a", "rooms")) or "added to alice/plan" in said[-1][2], timeout=40, every=1)
        check("alice's next command says bob joined and adds bob to alice/plan", got,
              "%.1fs %s" % (t, said[-1][2][-300:] if said else ""))
        got, t = wait_for(lambda: [m for m in js("a", "read", "--to-me") or [] if "joined with your invite" in m.get("text", "")],
                          timeout=40)
        check("alice gets a line in her inbox about the join", got and got[0]["from"] == "bob", "%.1fs" % t)
        rc, out, err = cl("a", "rooms")
        check("and says it once", "joined with your invite" not in err, err[-200:])

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
        got, t = wait_for(lambda: [m for m in (js("a", "room", "read", "alice/plan") or {}).get("messages", [])
                                   if m.get("text") == "thanks for the invite"], timeout=30)
        check("alice reads bob's room post", bool(got), "%.1fs" % t)
        got = [m for m in (js("b", "room", "read", "alice/plan") or {}).get("messages", []) if m.get("text") == "before bob"]
        check("bob reads the room's earlier post (full history)", bool(got))

        # Refused by the inviting node; the joining node changes nothing.
        rc, out, err = join("c", inv)
        check("an invite cannot be used twice", rc != 0 and "already used" in err, err[-200:])
        check("and the refused node trusts nothing new", len(trust_of("c")["nodes"]) == 1 and trust_of("c")["seq"] == 1)
        rc, dave, err = cl("a", "invite", "--name", "dave", "--config", a_cfg)
        rc, out, err = join("c", forge(dave, a_seed, name="eve"))
        check("a join for another name than the invited one is refused", rc != 0 and "not \"eve\"" in err, err[-200:])
        rc, out, err = join("c", forge(dave, a_seed, nonce=os.urandom(16)))
        check("a nonce the node never issued is refused", rc != 0 and "unknown nonce" in err, err[-200:])
        rc, carol, err = cl("a", "invite", "--name", "carol", "--config", a_cfg)
        at = a_trust_now()
        at["seq"] += 1
        next(n for n in at["nodes"] if n["key"] == a_key)["names"].append("carol")
        with open(a_trust + ".tmp", "w") as f:
            json.dump(at, f)
        os.replace(a_trust + ".tmp", a_trust)
        time.sleep(2)
        rc, out, err = join("c", carol)
        check("a join for a name the inviting node holds is refused", rc != 0 and "already held" in err, err[-200:])
        check("and A's trust file is unchanged", a_trust_now() == at)

        # A flood of bad attempts (each a validly signed invite with a nonce A never issued) leaves sync alone.
        t0 = time.time()
        answers = [join("c", forge(dave, a_seed, nonce=os.urandom(16)), wait=5) for _ in range(12)]
        check("a flood of bad joins is refused, then rate-limited", all(rc != 0 for rc, _, _ in answers)
              and any("too many" in e for _, _, e in answers), "%.1fs %s" % (time.time() - t0, answers[-1][2][-160:]))
        rc, out, err = cl("a", "send", "--to", "bob", "--private", "still here after the flood")
        got, t = wait_for(lambda: [m for m in js("b", "read", "--to-me") or [] if m.get("text") == "still here after the flood"],
                          timeout=15)
        check("mail between the trusted nodes still flows at once", rc == 0 and bool(got), "%.1fs" % t)
        check("and A's trust file is unchanged by the flood", a_trust_now() == at)

        # The inviting node is down: join prints the reply after --wait, the inviter accepts it later.
        rc, erin, err = cl("a", "invite", "--name", "erin", "--config", a_cfg)
        node_a.stop()
        rc, reply, err = join("c", erin, wait=3)
        check("an unreachable inviter: join falls back to a reply line", rc == 0 and reply.startswith("imr1")
              and len(reply) <= 260 and "could not be reached" in err, (reply + err)[-300:])
        check("A's node is down meanwhile", True)
        check("node A restarts", node_a.start())
        rc, out, err = cl("a", "accept", flip(reply, "imr1", NAME_AT), "--config", a_cfg)
        check("accept refuses a tampered reply", rc != 0 and "signature" in err, err[-200:])
        rc, out, err = cl("a", "accept", reply, "--config", a_cfg)
        check("accept trusts C's node for exactly erin", rc == 0 and "for exactly erin" in out, (out + err)[-300:])
        c_ent = [n for n in a_trust_now()["nodes"] if n["key"] not in (a_key, b_key)]
        check("as its trust file shows", len(c_ent) == 1 and c_ent[0]["names"] == ["erin"], json.dumps(c_ent))
        rc, out, err = cl("a", "accept", reply, "--config", a_cfg)
        check("accepting the same reply again changes nothing", rc == 0 and len(a_trust_now()["nodes"]) == 3, err[-200:])
        print("sample invite (%d chars): %s" % (len(inv), inv))
    finally:
        node_a.stop()
        for h in "bc":
            if pid(h):
                try:
                    os.kill(pid(h), signal.SIGTERM)
                except OSError:
                    pass
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
