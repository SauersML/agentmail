#!/usr/bin/env python3
"""Integration test for node-certified agents: three hosts on loopback, each with its own trust file, every key a
throwaway made here.

  python3 tests/network.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]

Hosts: "mac" (names alice, s.), "pod" (names alice: a second home for alice) and "ops" (names ops.). The mac's trust
file also lists an offline peer. Checks: an agent's first `islandmail.py send` on a host just works (key made with
mode 600, certified by its node, mail delivered to another host) with no per-agent pins; names outside a host's names
are refused; one agent served by two homes signs in and reads its private mail at either; a node's revocation ends
its agent's sign-in at once and replicates; and a trust-file edit cuts off an idle stream within seconds although a
peer is offline.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import http.client  # noqa: E402
from two_nodes import RESULTS, Node, check, client_module, free_port, owner_only, req, run, wait_for, work_directory  # noqa: E402


def stream_until_closed(port, token, out):
    # Reads an SSE stream through the chunked decoding until the node ends it.
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    c.request("GET", "/api/stream", headers={"Authorization": "Bearer " + token})
    r = c.getresponse()
    out.append(("status", r.status))
    while r.readline():
        pass
    out.append(("closed", time.time()))
    c.close()


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
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    hosts = ("mac", "pod", "ops")
    pub = {h: run(bin_, "keygen", k(h)) for h in hosts + ("ghost",)}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts + ("ghost",)}
    api = {h: free_port() for h in hosts}
    network = run(bin_, "network-id")
    long_prefix = "a" * 46 + "."
    names = {"mac": ["alice", "s."], "pod": ["x" * 47 + ".", long_prefix, "alice"], "ops": ["ops."]}

    def node_entry(h, names_=None):
        return {"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": names_ if names_ is not None else names.get(h, [])}

    def trust(h, seq=1, mac_names=None):
        # Each host's own file. The mac also trusts a peer that never comes up.
        nodes = [node_entry(n, mac_names if n == "mac" else None) for n in hosts]
        if h == "mac":
            nodes.append(node_entry("ghost", []))
        path = os.path.join(work, "trust-%s.json" % h)
        with open(path + ".tmp", "w") as f:
            json.dump({"v": 1, "network": network, "seq": seq, "members": [], "nodes": nodes}, f)
        os.replace(path + ".tmp", path)
        return path

    nodes = {}
    for h in hosts:
        nodes[h] = Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                        "iroh_port": udp[h], "node_key_file": k(h), "members_file": trust(h), "sync_secs": 3})

    def cl(h, *args, user="agent", timeout=60, client_dir=None):
        env = dict(os.environ, ISLANDMAIL_DIR=client_dir or os.path.join(work, "client-" + h), USER=user,
                   ISLANDMAIL_URL="http://127.0.0.1:%d" % api[h])
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        p = subprocess.run([sys.executable, im, *args], env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def ident(h, name):
        return os.path.join(work, "client-" + h, "identities", name + ".json")

    def read(h, *args):
        rc, out = cl(h, *args, "read", "--json", "--limit", "200")
        try:
            return json.loads(out) if rc == 0 else []
        except ValueError:
            return []

    try:
        for h in hosts:
            check("%s node starts" % h, nodes[h].start())

        with ThreadPoolExecutor(max_workers=2) as pool:
            directory = os.path.join(work, "concurrent-client")
            calls = [pool.submit(cl, "pod", "whoami", client_dir=directory) for _ in range(2)]
            results = [call.result() for call in calls]
        check("concurrent first commands share a key under a 47-character prefix",
              all(rc == 0 and long_prefix + "a" in out for rc, out in results)
              and os.listdir(os.path.join(directory, "identities")) == [long_prefix + "a.json"],
              "%r %r" % (results, os.listdir(os.path.join(directory, "identities"))))

        # The first command on a fresh host: key, certificate, delivery. No pins anywhere.
        t0 = time.time()
        rc, out = cl("ops", "send", "--open", "--to", "alice", "first words from ops", user="bob")
        check("first `send` on a host works with no setup", rc == 0, out[-200:])
        check("it took about a second", time.time() - t0 < 5, "%.1fs" % (time.time() - t0))
        path = ident("ops", "ops.bob")
        check("the key is made under the host's names, owner-only", owner_only(path))
        rc, out = cl("mac", "send", "--open", "--to", "ops.bob", "hi ops, from alice")
        check("the mac's first command makes alice (its first name)", rc == 0 and os.path.exists(ident("mac", "alice")), out[-200:])
        got, t = wait_for(lambda: [m for m in read("ops") if m.get("from") == "alice"], timeout=15)
        check("ops reads alice's mail on another host", got and got[0]["text"] == "hi ops, from alice", "%.1fs" % t)
        rc, out = cl("ops", "send", "--open", "--to", "alice", "a reply", user="bob")
        got, t = wait_for(lambda: [m for m in read("mac") if m.get("text") == "a reply"], timeout=15)
        check("and alice reads ops's reply", rc == 0 and bool(got), "%.1fs" % t)

        # Outside the host's names: refused, and the uncertified key is dropped.
        rc, out = cl("ops", "--as", "s.mallory", "send", "--open", "--to", "alice", "spoof")
        check("a name outside the host's names is refused", rc != 0 and "403" in out, out[-160:])
        check("the refused key is not kept", not os.path.exists(ident("ops", "s.mallory")))
        rc, out = cl("pod", "--as", "s.other", "whoami")
        check("the pod may not certify the mac's other names", rc != 0 and "403" in out, out[-160:])

        # Two homes: alice's key on the pod too. Its first use there gets the pod's certificate.
        with open(ident("mac", "alice")) as f:
            client_module().write_private(ident("pod", "alice"), f.read())
        # Resume an existing stream cursor: this path opens /api/stream without first calling /api/me.
        cursor = "watch-%s-alice-main.last" % hashlib.sha256(pub["pod"].encode()).hexdigest()
        with open(os.path.join(work, "client-pod", cursor), "w") as f:
            f.write("0")
        # Send after alice's mac certificate has replicated, so its key is in the signed recipient list.
        rc, out = cl("ops", "send", "--open", "--to", "alice", "watch at the second home")
        check("mail posted for second-home watch", rc == 0, out[-160:])
        rc, out = cl("pod", "watch", "--mine", "--until", timeout=25)
        check("resumed watch gets the second home's certificate", rc == 0 and "> " in out, out[-160:])
        rc, out = cl("pod", "whoami")
        check("alice signs in at its second home", rc == 0 and "alice" in out, out[-200:])
        homes = lambda: [x["homes"] for x in req("GET", api["ops"], "/api/agents", token=cl(
            "ops", "selftoken", "--ttl", "60", user="bob")[1])[1].get("agents", []) if x["name"] == "alice"]
        got, t = wait_for(lambda: [sorted(h) for h in homes()] == [["mac", "pod"]], timeout=15)
        check("ops's host sees alice with two homes", bool(got), "%.1fs" % t)
        rc, out = cl("ops", "send", "--to", "alice", "for alice only", user="bob")
        check("ops sends private mail to alice", rc == 0, out[-200:])
        for h in ("mac", "pod"):
            got, t = wait_for(lambda: [m for m in read(h) if m.get("text") == "for alice only"], timeout=15)
            check("alice reads the private mail at the %s" % h, bool(got), "%.1fs" % t)
        rc, out = cl("pod", "send", "--to", "ops.bob", "private reply from the pod")
        got, t = wait_for(lambda: [m for m in read("ops") if m.get("text") == "private reply from the pod"], timeout=15)
        check("alice writes private mail from the pod", rc == 0 and bool(got), out[-120:])
        got, _ = wait_for(lambda: [m for m in read("mac") if m.get("text") == "private reply from the pod"], timeout=15)
        check("and reads its own private mail at the mac", bool(got))

        # Revocation by ops's node: sign-in ends there at once, and other hosts learn it.
        rc, out = cl("ops", "--as", "ops.temp", "whoami", user="temp")
        check("a second agent on ops's host", rc == 0, out[-120:])
        p = subprocess.run([bin_, "revoke", os.path.join(work, "ops.json"), "ops.temp"], capture_output=True, text=True)
        check("islandmail-node revoke", p.returncode == 0 and "revoked ops.temp" in p.stdout, (p.stdout + p.stderr)[-160:])
        rc, out = cl("ops", "--as", "ops.temp", "whoami", user="temp")
        check("the revoked agent cannot sign in", rc != 0 and "403" in out, out[-160:])
        tok = lambda: cl("mac", "selftoken", "--ttl", "60")[1]
        gone, t = wait_for(lambda: not [x for x in req("GET", api["mac"], "/api/agents", token=tok())[1].get("agents", [])
                                        if x["name"] == "ops.temp"], timeout=15)
        check("the revocation replicates", bool(gone), "%.1fs" % t)

        # Trust-file reload on its own timer: drop "s." from the mac's names while the ghost peer is offline; an idle
        # stream of s.idle at the mac ends within seconds.
        rc, out = cl("mac", "--as", "s.idle", "whoami")
        check("s.idle on the mac", rc == 0, out[-120:])
        rc, token = cl("mac", "--as", "s.idle", "selftoken", "--ttl", "600")
        events = []
        reader = threading.Thread(target=stream_until_closed, args=(api["mac"], token, events), daemon=True)
        reader.start()
        wait_for(lambda: events, timeout=5)
        check("idle stream open", events and events[0][1] == 200, str(events[:1]))
        time.sleep(4)  # a periodic sync with the offline peer is under way
        check("the stream is still open before the edit", reader.is_alive())
        t0 = time.time()
        trust("mac", seq=2, mac_names=["alice"])
        reader.join(30)
        took = events[-1][1] - t0 if events[-1][0] == "closed" else 99
        check("the idle stream is cut off promptly after the trust change", 0 <= took < 3, "%.2fs" % took)
        rc, out = cl("mac", "--as", "s.idle", "whoami")
        check("and s.idle no longer signs in", rc != 0 and "403" in out, out[-120:])
        rc, out = cl("mac", "--as", "alice", "whoami")
        check("alice still does", rc == 0, out[-120:])
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
