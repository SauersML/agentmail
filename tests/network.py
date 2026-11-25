#!/usr/bin/env python3
"""Integration test for node-certified agents: three hosts on loopback, each with its own trust file, every key a
throwaway made here.

  python3 tests/network.py --bin target/debug/mailnode --islandmail clients/islandmail.py [--workdir DIR]

Hosts: "mac" (names hypha, s.), "pod" (names hypha: a second home for hypha) and "will" (names will.). The mac's trust
file also lists an offline peer. Checks: an agent's first `islandmail.py send` on a host just works (key made with
mode 600, certified by its node, mail delivered to another host) with no per-agent pins; names outside a host's names
are refused; one agent served by two homes signs in and reads its private mail at either; a node's revocation ends
its agent's sign-in at once and replicates; and a trust-file edit cuts off an idle stream within seconds although a
peer is offline.
"""
import argparse
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import http.client  # noqa: E402
from two_nodes import RESULTS, Node, check, free_port, req, run, wait_for, work_directory  # noqa: E402


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
    hosts = ("mac", "pod", "will")
    pub = {h: run(bin_, "keygen", k(h)) for h in hosts + ("ghost",)}
    udp = {h: free_port(socket.SOCK_DGRAM) for h in hosts + ("ghost",)}
    api = {h: free_port() for h in hosts}
    network = run(bin_, "network-id")
    names = {"mac": ["hypha", "s."], "pod": ["hypha"], "will": ["will."]}

    def node_entry(h, names_=None):
        return {"name": h, "key": pub[h], "addrs": ["127.0.0.1:%d" % udp[h]], "names": names_ if names_ is not None else names.get(h, [])}

    def trust(h, seq=1, mac_names=None):
        # Each host's own file. The mac also trusts a peer that never comes up.
        nodes = [node_entry(n, mac_names if n == "mac" else None) for n in hosts]
        if h == "mac":
            nodes.append(node_entry("ghost", []))
        path = os.path.join(work, "trust-%s.json" % h)
        with open(path + ".tmp", "w") as f:
            json.dump({"v": 2, "network": network, "seq": seq, "members": [], "nodes": nodes}, f)
        os.replace(path + ".tmp", path)
        return path

    nodes = {}
    for h in hosts:
        nodes[h] = Node(bin_, work, h, {"data_dir": os.path.join(work, "data-" + h), "api_listen": "127.0.0.1:%d" % api[h],
                                        "iroh_port": udp[h], "node_key_file": k(h), "members_file": trust(h), "sync_secs": 3})

    def cl(h, *args, user="agent", timeout=60):
        env = dict(os.environ, ISLANDMAIL_DIR=os.path.join(work, "client-" + h), USER=user,
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

        # The first command on a fresh host: key, certificate, delivery. No pins anywhere.
        t0 = time.time()
        rc, out = cl("will", "send", "--to", "hypha", "first words from will", user="orchestrator")
        check("first `send` on a host works with no setup", rc == 0, out[-200:])
        check("it took about a second", time.time() - t0 < 5, "%.1fs" % (time.time() - t0))
        path = ident("will", "will.orchestrator")
        check("the key is made under the host's names, mode 600",
              os.path.exists(path) and stat.S_IMODE(os.stat(path).st_mode) == 0o600)
        rc, out = cl("mac", "send", "--to", "will.orchestrator", "hi will, from hypha")
        check("the mac's first command makes hypha (its first name)", rc == 0 and os.path.exists(ident("mac", "hypha")), out[-200:])
        got, t = wait_for(lambda: [m for m in read("will") if m.get("from") == "hypha"], timeout=15)
        check("will reads hypha's mail on another host", got and got[0]["text"] == "hi will, from hypha", "%.1fs" % t)
        rc, out = cl("will", "send", "--to", "hypha", "a reply", user="orchestrator")
        got, t = wait_for(lambda: [m for m in read("mac") if m.get("text") == "a reply"], timeout=15)
        check("and hypha reads will's reply", rc == 0 and bool(got), "%.1fs" % t)

        # Outside the host's names: refused, and the uncertified key is dropped.
        rc, out = cl("will", "--as", "s.mallory", "send", "--to", "hypha", "spoof")
        check("a name outside the host's names is refused", rc != 0 and "403" in out, out[-160:])
        check("the refused key is not kept", not os.path.exists(ident("will", "s.mallory")))
        rc, out = cl("pod", "--as", "s.other", "whoami")
        check("the pod may not certify the mac's other names", rc != 0 and "403" in out, out[-160:])

        # Two homes: hypha's key on the pod too. Its first use there gets the pod's certificate.
        os.makedirs(os.path.dirname(ident("pod", "hypha")), mode=0o700, exist_ok=True)
        with open(ident("mac", "hypha")) as f:
            data = f.read()
        fd = os.open(ident("pod", "hypha"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        # Resume an existing stream cursor: this path opens /api/stream without first calling /api/me.
        cursor = "watch-%s-hypha-main.last" % hashlib.sha256(pub["pod"].encode()).hexdigest()
        with open(os.path.join(work, "client-pod", cursor), "w") as f:
            f.write("0")
        # Send after hypha's mac certificate has replicated, so its key is in the signed recipient list.
        rc, out = cl("will", "send", "--to", "hypha", "watch at the second home")
        check("mail posted for second-home watch", rc == 0, out[-160:])
        rc, out = cl("pod", "watch", "--mine", "--until", timeout=25)
        check("resumed watch gets the second home's certificate", rc == 0 and "> " in out, out[-160:])
        rc, out = cl("pod", "whoami")
        check("hypha signs in at its second home", rc == 0 and "hypha" in out, out[-200:])
        homes = lambda: [x["homes"] for x in req("GET", api["will"], "/api/agents", token=cl(
            "will", "selftoken", "--ttl", "60", user="orchestrator")[1])[1].get("agents", []) if x["name"] == "hypha"]
        got, t = wait_for(lambda: [sorted(h) for h in homes()] == [["mac", "pod"]], timeout=15)
        check("will's host sees hypha with two homes", bool(got), "%.1fs" % t)
        rc, out = cl("will", "send", "--private", "--to", "hypha", "for hypha only", user="orchestrator")
        check("will sends private mail to hypha", rc == 0, out[-200:])
        for h in ("mac", "pod"):
            got, t = wait_for(lambda: [m for m in read(h) if m.get("text") == "for hypha only"], timeout=15)
            check("hypha reads the private mail at the %s" % h, bool(got), "%.1fs" % t)
        rc, out = cl("pod", "send", "--private", "--to", "will.orchestrator", "private reply from the pod")
        got, t = wait_for(lambda: [m for m in read("will") if m.get("text") == "private reply from the pod"], timeout=15)
        check("hypha writes private mail from the pod", rc == 0 and bool(got), out[-120:])
        got, _ = wait_for(lambda: [m for m in read("mac") if m.get("text") == "private reply from the pod"], timeout=15)
        check("and reads its own private mail at the mac", bool(got))

        # Revocation by will's node: sign-in ends there at once, and other hosts learn it.
        rc, out = cl("will", "--as", "will.temp", "whoami", user="temp")
        check("a second agent on will's host", rc == 0, out[-120:])
        p = subprocess.run([bin_, "revoke", os.path.join(work, "will.json"), "will.temp"], capture_output=True, text=True)
        check("mailnode revoke", p.returncode == 0 and "revoked will.temp" in p.stdout, (p.stdout + p.stderr)[-160:])
        rc, out = cl("will", "--as", "will.temp", "whoami", user="temp")
        check("the revoked agent cannot sign in", rc != 0 and "403" in out, out[-160:])
        tok = lambda: cl("mac", "selftoken", "--ttl", "60")[1]
        gone, t = wait_for(lambda: not [x for x in req("GET", api["mac"], "/api/agents", token=tok())[1].get("agents", [])
                                        if x["name"] == "will.temp"], timeout=15)
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
        trust("mac", seq=2, mac_names=["hypha"])
        reader.join(30)
        took = events[-1][1] - t0 if events[-1][0] == "closed" else 99
        check("the idle stream is cut off promptly after the trust change", 0 <= took < 3, "%.2fs" % took)
        rc, out = cl("mac", "--as", "s.idle", "whoami")
        check("and s.idle no longer signs in", rc != 0 and "403" in out, out[-120:])
        rc, out = cl("mac", "--as", "hypha", "whoami")
        check("hypha still does", rc == 0, out[-120:])
    finally:
        for n in nodes.values():
            n.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
