#!/usr/bin/env python3
"""Integration test for identity homes: two hosts on loopback whose trust files pin two test homes (aid1 issuers made
here: "id.test" vouching for @id.test, "other.test" for @other.test). Every key is a throwaway.

  python3 tests/homes.py --bin target/debug/mailnode [--islandmail clients/islandmail.py] [--workdir DIR]

Checks: an agent enrolls as fable@id.test with a key-bound aid1 token and mails an agent on the other host, which
accepts the certificate against its own trust file; names outside the home's suffix are refused (a bare name, another
home's suffix, a suffix no home has); expired, wrong-audience, wrong-generation, tampered, unbound and wrongly-bound
tokens are refused; a new key for a known name is refused without the old key's signature (on both hosts) and
accepted with it. The homes' domains are reserved .test names that resolve nowhere: verification is offline.
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, req, run, wait_for, work_directory  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def kid(priv):
    return "ed25519:" + b64u(raw_pub(priv))


def canon_ts(t=None):
    t = time.time() if t is None else t
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % (int(t * 1000) % 1000)


class Home:
    """A test issuer minting aid1 tokens the way archipelago-home's mintToken does."""

    def __init__(self, iss, kg=1):
        self.iss, self.kg, self.priv = iss, kg, Ed25519PrivateKey.generate()

    def entry(self, name):
        return {"name": name, "iss": self.iss, "key": kid(self.priv), "kg": self.kg, "suffix": "@" + self.iss}

    def mint(self, local, cnf, **over):
        now = int(time.time())
        p = {"v": 1, "iss": self.iss, "sub": "agent:%s@guest" % local, "kind": "agent", "name": local,
             "aud": "agentmail", "scopes": ["mail:send"], "iat": now, "exp": now + 600, "kg": self.kg, "cnf": cnf}
        p.update(over)
        p = {k: v for k, v in p.items() if v is not None}
        signed = "aid1." + b64u(json.dumps(p).encode())
        return signed + "." + b64u(self.priv.sign(signed.encode()))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", default=os.path.join(here, "..", "clients", "islandmail.py"))
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    im = os.path.abspath(a.islandmail)
    work = work_directory(a.workdir)
    os.makedirs(os.path.join(work, "keys"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    hosts = ("mac", "pod")
    pub = {h: run(bin_, "keygen", k(h)) for h in hosts}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts}
    api = {h: free_port() for h in hosts}
    network = run(bin_, "network-id")
    home, other = Home("id.test"), Home("other.test")
    names = {"mac": ["m."], "pod": ["p."]}

    def trust(h):
        nodes = [{"name": n, "key": pub[n], "addrs": ["127.0.0.1:%d" % udp[n]], "names": names[n]} for n in hosts]
        path = os.path.join(work, "trust-%s.json" % h)
        with open(path, "w") as f:
            json.dump({"v": 2, "network": network, "seq": 1, "members": [], "nodes": nodes,
                       "homes": [home.entry("test"), other.entry("other")]}, f)
        return path

    nodes = {h: Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                     "iroh_port": udp[h], "node_key_file": k(h), "members_file": trust(h), "sync_secs": 2})
             for h in hosts}

    def cl(h, *args, timeout=60):
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER="agent",
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h])
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def enroll(h, priv, name, token, *, holder=None, aud="agentmail", iss=None, rekey_from=None):
        # POST /api/agents as islandmail.py enroll sends it; `holder` signs the proof of possession instead.
        node = req("GET", api[h], "/api/node")[1]["node"]
        ts, jti = canon_ts(), b64u(os.urandom(16))
        st = "agent-mail-certify|v1|%s|%s|%s|%s" % (name, kid(priv), node, ts)
        present = "archipelago-present|v1|%s|%s|%s|%s|%s" % (
            iss or home.iss, aud, ts, jti, b64u(hashlib.sha256(token.encode()).digest()))
        body = {"name": name, "key": kid(priv), "ts": ts, "sig": b64u(priv.sign(st.encode())), "aid1": token,
                "jti": jti, "pop": b64u((holder or priv).sign(present.encode()))}
        if rekey_from:
            msg = "agent-mail-rekey|v1|%s|%s|%s" % (name.lower(), kid(rekey_from), kid(priv))
            body["rekey"] = {"key": kid(rekey_from), "sig": b64u(rekey_from.sign(msg.encode()))}
        return req("POST", api[h], "/api/agents", body=body)

    def agents(h, as_):
        rc, tok = cl(h, "--as", as_, "selftoken", "--ttl", "60")
        return {x["name"]: x for x in req("GET", api[h], "/api/agents", token=tok)[1].get("agents", [])} if rc == 0 else {}

    def read(h, as_):
        rc, out = cl(h, "--as", as_, "read", "--json", "--limit", "200")
        try:
            return json.loads(out) if rc == 0 else []
        except ValueError:
            return []

    try:
        for h in hosts:
            check("%s node starts" % h, nodes[h].start())

        # Enroll with the client: key first, then a token from the home bound to it.
        rc, out = cl("mac", "newkey", "fable@id.test")
        fable_key = next((json.loads(x)["key"] for x in out.splitlines() if x.startswith("{")), "") if rc == 0 else ""
        check("newkey makes a key for a home name", rc == 0 and fable_key.startswith("ed25519:"), out[-200:])
        rc, out = cl("mac", "--as", "fable@id.test", "enroll", home.mint("fable", fable_key))
        check("enroll with a key-bound aid1 token", rc == 0 and "enrolled fable@id.test" in out, out[-200:])
        rc, out = cl("mac", "--as", "fable@id.test", "whoami")
        check("fable@id.test signs in at its node", rc == 0 and "fable@id.test" in out, out[-200:])

        # Mail between hosts: the pod accepts fable's certificate against its own trust file's homes.
        rc, out = cl("pod", "--as", "p.bob", "whoami")
        check("a local agent on the pod", rc == 0, out[-160:])
        got, t = wait_for(lambda: "fable@id.test" in agents("pod", "p.bob") and "p.bob" in agents("mac", "fable@id.test"),
                          timeout=20)
        check("the pod accepts fable@id.test (and the mac p.bob)", bool(got), "%.1fs" % t)
        rc, out = cl("mac", "--as", "fable@id.test", "send", "--to", "p.bob", "hello from a home agent")
        check("fable sends to the pod", rc == 0, out[-200:])
        got, t = wait_for(lambda: [m for m in read("pod", "p.bob") if m.get("from") == "fable@id.test"], timeout=20)
        check("p.bob reads fable's mail on the other host", got and got[0]["text"] == "hello from a home agent", "%.1fs" % t)
        rc, out = cl("pod", "--as", "p.bob", "send", "--private", "--to", "fable@id.test", "private reply")
        got, t = wait_for(lambda: [m for m in read("mac", "fable@id.test") if m.get("text") == "private reply"], timeout=20)
        check("fable reads p.bob's private reply", rc == 0 and bool(got), out[-160:])

        # Suffixes: a home vouches only for local@its-suffix.
        m = Ed25519PrivateKey.generate()
        s, body = enroll("mac", m, "mallory", home.mint("mallory", kid(m)))
        check("a bare name with a token is refused", s == 400, "%s %s" % (s, body))
        s, body = enroll("mac", m, "mallory@other.test", home.mint("mallory", kid(m)))
        check("id.test's token for other.test's suffix is refused", s == 403, "%s %s" % (s, body))
        s, body = enroll("mac", m, "mallory@id.test", other.mint("mallory", kid(m), iss="id.test"), iss="id.test")
        check("other.test cannot vouch under @id.test", s == 403 and "signature" in str(body), "%s %s" % (s, body))
        s, body = enroll("mac", m, "mallory@nohome.test", home.mint("mallory", kid(m)))
        check("a suffix no home has is refused", s == 403, "%s %s" % (s, body))
        rc, out = cl("mac", "--as", "m.ok", "whoami")
        check("local names still certify with no token", rc == 0, out[-160:])
        s, body = enroll("mac", m, "m.mallory", home.mint("mallory", kid(m)))
        check("a local name with a token is refused", s == 400, "%s %s" % (s, body))
        n = Ed25519PrivateKey.generate()
        s, body = enroll("mac", n, "nell@other.test", other.mint("nell", kid(n)), iss="other.test")
        check("a second home's agent enrolls under its own suffix", s == 201, "%s %s" % (s, body))

        # Token checks, all offline against the pinned issuer key.
        v = Ed25519PrivateKey.generate()
        cases = [
            ("expired", home.mint("vic", kid(v), exp=int(time.time()) - 5), "expired"),
            ("wrong aud", home.mint("vic", kid(v), aud="docs"), "audience mismatch"),
            ("wrong kg", home.mint("vic", kid(v), kg=2), "key generation mismatch"),
            ("missing kg", home.mint("vic", kid(v), kg=None), "missing key generation"),
            ("not bound (no cnf)", home.mint("vic", None), "not bound"),
            ("bound to another key", home.mint("vic", kid(Ed25519PrivateKey.generate())), "not bound"),
            ("for another agent", home.mint("someone", kid(v)), "not vic"),
            ("not an agent", home.mint("vic", kid(v), kind="human"), "not an agent"),
        ]
        good = home.mint("vic", kid(v))
        seg = good.split(".")[1]
        i = len(seg) // 2
        tampered = "aid1." + seg[:i] + ("A" if seg[i] != "A" else "B") + seg[i + 1:] + "." + good.split(".")[2]
        cases.append(("tampered byte", tampered, "signature verify failed"))
        for what, tok, why in cases:
            s, body = enroll("mac", v, "vic@id.test", tok)
            check("%s token refused" % what, s == 403 and why in body.get("error", json.dumps(body)), "%s %s" % (s, body))
        s, body = enroll("mac", v, "vic@id.test", good, holder=Ed25519PrivateKey.generate())
        check("a proof of possession by another key is refused", s == 403 and "proof" in str(body), "%s %s" % (s, body))
        s, body = enroll("mac", v, "vic@id.test", good)
        check("the untampered token enrolls", s == 201, "%s %s" % (s, body))

        # Key continuity: fable@id.test is pinned to its first key on both hosts.
        k2 = Ed25519PrivateKey.generate()
        s, body = enroll("mac", k2, "fable@id.test", home.mint("fable", kid(k2)))
        check("a new key without the old key's signature is refused", s == 409, "%s %s" % (s, body))
        s, body = enroll("pod", k2, "fable@id.test", home.mint("fable", kid(k2)))
        check("and refused at the other host too", s == 409, "%s %s" % (s, body))
        fake_old = Ed25519PrivateKey.generate()
        s, body = enroll("mac", k2, "fable@id.test", home.mint("fable", kid(k2)), rekey_from=fake_old)
        check("a handover signed by some other key is refused", s == 409, "%s %s" % (s, body))
        logs = open(os.path.join(work, "mac.log"), encoding="utf-8", errors="replace").read()
        check("the refusal is logged loudly", "REFUSED a new key for fable@id.test" in logs)
        rc, out = cl("mac", "--as", "fable@id.test", "rekey")
        new_key = next((x for x in out.splitlines() if x.startswith("ed25519:")), "") if rc == 0 else ""
        check("rekey makes a pending key", rc == 0 and new_key.startswith("ed25519:") and new_key != fable_key, out[-200:])
        rc, out = cl("mac", "--as", "fable@id.test", "enroll", home.mint("fable", new_key))
        check("the new key with the old key's signature is accepted", rc == 0 and "new key" in out, out[-200:])
        got, t = wait_for(lambda: agents("pod", "p.bob").get("fable@id.test", {}).get("key") == new_key, timeout=20)
        check("the pod moves fable to the new key", bool(got), "%.1fs" % t)
        rc, out = cl("mac", "--as", "fable@id.test", "send", "--to", "p.bob", "from my new key")
        got, t = wait_for(lambda: [m for m in read("pod", "p.bob") if m.get("text") == "from my new key"], timeout=20)
        check("mail from the new key reaches the pod", rc == 0 and bool(got), out[-160:])
        old = [m for m in read("pod", "p.bob") if m.get("text") == "hello from a home agent"]
        check("mail from the old key still verifies there", bool(old))
    finally:
        for nd in nodes.values():
            nd.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
