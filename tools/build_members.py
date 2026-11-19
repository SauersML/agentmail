#!/usr/bin/env python3
"""Build an unsigned member list from a home's principals.json: every principal with the mail:use scope and an
Ed25519 key (public keys only), plus the given nodes and bridge keys. Sign the output with `mailnode sign-members`.

  python3 build_members.py --principals principals.json --network agaric --seq 1 \
      --node pod=ed25519:... --node mac=ed25519:... [--node-addr pod=1.2.3.4:4433] --bridge ed25519:... -o members.unsigned.json
"""
import argparse
import datetime
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--principals", required=True)
    ap.add_argument("--network", required=True)
    ap.add_argument("--seq", type=int, required=True)
    ap.add_argument("--node", action="append", default=[], help="NAME=ed25519:KEY")
    ap.add_argument("--node-addr", action="append", default=[], help="NAME=IP:PORT (optional, repeatable)")
    ap.add_argument("--bridge", action="append", default=[], help="ed25519:KEY")
    ap.add_argument("-o", required=True)
    a = ap.parse_args()
    d = json.load(open(a.principals))
    members, skipped, names = [], 0, set()
    for p in d["principals"]:
        key = p.get("key") or ""
        if "mail:use" not in (p.get("scopes") or []):
            continue
        if not key.startswith("ed25519:") or not p.get("name") or not p.get("sub"):
            skipped += 1
            continue
        if p["name"] in names:
            raise SystemExit("duplicate name %s" % p["name"])
        names.add(p["name"])
        members.append({"name": p["name"], "sub": p["sub"], "key": key})
    addrs = {}
    for na in a.node_addr:
        n, _, ad = na.partition("=")
        addrs.setdefault(n, []).append(ad)
    nodes = []
    for nk in a.node:
        n, _, k = nk.partition("=")
        if not k.startswith("ed25519:"):
            raise SystemExit("--node wants NAME=ed25519:KEY")
        nodes.append({"name": n, "key": k, "addrs": addrs.get(n, [])})
    now = datetime.datetime.now(datetime.timezone.utc)
    lst = {"v": 1, "network": a.network, "seq": a.seq,
           "issued": now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000), "operator": "",
           "members": sorted(members, key=lambda m: m["name"]), "nodes": nodes, "bridges": a.bridge, "sig": ""}
    with open(a.o, "w") as f:
        json.dump(lst, f, indent=1)
    print("%d members (%d mail principals without a usable key skipped), %d nodes, %d bridges -> %s" % (
        len(members), skipped, len(nodes), len(a.bridge), a.o))


if __name__ == "__main__":
    main()
