#!/usr/bin/env python3
"""islandmail.py invite-check, offline: invites signed here (no node runs) compared with an expected network and node
keys, from flags or a binding file. Match (exit 0), wrong network and wrong node (exit 1), and malformed input: a
damaged, tampered or expired invite, a binding that is not JSON, not version 1, names no node, or holds a bad
encoding (exit 2). Nothing is written under ISLANDMAIL_DIR.

  python3 tests/invite_check.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import client_module  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
FROM = 16


def b58(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def s(t):
    return bytes([len(t)]) + t.encode()


def make_invite(seed, network, exp_s, name="bob", frm="alice"):
    # The smallest invite: flags (from only), network, node key, expiry, nonce, names, from; signed by the node key.
    im = client_module()
    payload = (bytes([FROM]) + network + im.ed25519_public(seed) + int(exp_s).to_bytes(4, "big") + os.urandom(16)
               + s(name) + s(frm))
    return "im1" + b58(payload + im.ed25519_sign(seed, b"islandmail/invite/v1\n" + payload))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", required=True)
    a = ap.parse_args()
    im = client_module()
    bin_, client = os.path.abspath(a.bin), os.path.abspath(a.islandmail)
    work = tempfile.mkdtemp(prefix="islandmail-invite-check-")
    home = os.path.join(work, "home")
    env = dict(os.environ, ISLANDMAIL_DIR=home, ISLANDMAIL_URL="http://127.0.0.1:9")

    def run(*args):
        p = subprocess.run([sys.executable, client, "invite-check", "--bin", bin_, *args], capture_output=True,
                           text=True, env=env, timeout=60)
        return p.returncode, p.stdout + p.stderr

    def expect(code, text, *args):
        got, out = run(*args)
        assert got == code and text in out, "invite-check %s: exit %d (wanted %d, %r)\n%s" % (
            " ".join(x[:24] for x in args), got, code, text, out)
        return out

    def binding(name, rec):
        path = os.path.join(work, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(rec if isinstance(rec, str) else json.dumps(rec))
        return path

    seed, other_seed = os.urandom(32), os.urandom(32)
    net_raw = os.urandom(32)
    net, other_net = im.b64u(net_raw), im.b64u(os.urandom(32))
    key, other_key = "ed25519:" + im.b64u(im.ed25519_public(seed)), "ed25519:" + im.b64u(im.ed25519_public(other_seed))
    inv = make_invite(seed, net_raw, time.time() + 3600)

    # Match: network alone, network and node, one of several nodes, padded encodings, a binding file either way.
    expect(0, "any node of the network matches", inv, "--expect-network", net)
    out = expect(0, "match: network %s, issued by node %s" % (net, key), inv, "--expect-network", net, "--expect-node", key)
    assert "nothing was looked up" in out and "not admission" in out and "for bob" in out, out
    expect(0, "match", inv, "--expect-network", net, "--expect-node", other_key, "--expect-node", key)
    expect(0, "match", inv, "--expect-network", net + "=", "--expect-node", key + "=")
    expect(0, "binding file", inv, "--binding", binding("nodes.json", {"v": 1, "network": net, "nodes": [other_key, key]}))
    expect(0, "match", inv, "--binding", binding("node.json", {"v": 1, "network": net, "node": key}))
    _, out = run(inv, "--expect-network", net, "--expect-node", key, "--json")
    j = json.loads(out)
    assert j["result"] == "match" and j["invite"] == {"network": net, "node": key, "names": ["bob"],
                                                      "exp": j["invite"]["exp"]} and j["expected"]["nodes"] == [key], j

    # Wrong network, wrong node: exit 1, saying which and what was expected.
    expect(1, "network mismatch: the invite is for network %s, expected %s" % (net, other_net),
           inv, "--expect-network", other_net, "--expect-node", key)
    expect(1, "network mismatch", inv, "--binding", binding("net.json", {"v": 1, "network": other_net, "node": key}))
    expect(1, "node mismatch: the invite was issued by node %s, expected %s" % (key, other_key),
           inv, "--expect-network", net, "--expect-node", other_key)
    out = expect(1, "node mismatch", inv, "--binding", binding("key.json", {"v": 1, "network": net, "nodes": [other_key]}))
    assert "do not join" in out, out
    _, out = run(inv, "--expect-network", net, "--expect-node", other_key, "--json")
    assert json.loads(out)["result"] == "node_mismatch", out

    # Malformed: the invite (not one, damaged, re-signed by another key, expired) and the binding.
    expect(2, "invalid invite: that is not an invite", "hello", "--expect-network", net)
    expect(2, "invalid invite", inv[:-5] + "0OIl0", "--expect-network", net)
    tampered = inv[:40] + ("2" if inv[40] != "2" else "3") + inv[41:]
    expect(2, "invalid invite", tampered, "--expect-network", net)
    expect(2, "invalid invite: invite expired", make_invite(seed, net_raw, time.time() - 60), "--expect-network", net)
    expect(2, "invalid binding: no network", inv)
    expect(2, "network ID is not 32 bytes", inv, "--expect-network", net[:-2])
    expect(2, "network ID is not 32 bytes", inv, "--expect-network", net[:-1] + "+")
    expect(2, "ed25519:<base64url>", inv, "--expect-network", net, "--expect-node", key[len("ed25519:"):])
    expect(2, "node key is not 32 bytes", inv, "--expect-network", net, "--expect-node", key + "AA")
    expect(2, "not both", inv, "--expect-network", net, "--binding", binding("ok.json", {"v": 1, "network": net, "node": key}))
    expect(2, "cannot read binding", inv, "--binding", binding("bad.json", '{"v": 1, "network": '))
    expect(2, "cannot read binding", inv, "--binding", os.path.join(work, "missing.json"))
    expect(2, "not version 1", inv, "--binding", binding("v2.json", {"v": 2, "network": net, "node": key}))
    expect(2, "not version 1", inv, "--binding", binding("list.json", [net, key]))
    expect(2, "names no node", inv, "--binding", binding("none.json", {"v": 1, "network": net}))
    expect(2, "names no node", inv, "--binding", binding("empty.json", {"v": 1, "network": net, "nodes": []}))
    expect(2, "both node and nodes", inv, "--binding", binding("both.json", {"v": 1, "network": net, "node": key, "nodes": [key]}))
    expect(2, "node key must look like", inv, "--binding", binding("int.json", {"v": 1, "network": net, "nodes": [7]}))
    expect(2, "network ID is not 32 bytes", inv, "--binding", binding("nonet.json", {"v": 1, "network": 7, "node": key}))
    _, out = run(inv, "--json")
    assert json.loads(out)["result"] == "invalid_binding", out

    assert not os.path.exists(home), "invite-check wrote under ISLANDMAIL_DIR"
    shutil.rmtree(work)
    print("invite_check: all checks passed")


if __name__ == "__main__":
    main()
