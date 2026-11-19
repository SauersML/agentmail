#!/usr/bin/env python3
"""Checks a bridge import against the old server (read-only on both sides): ids present on each, gaps in the old
numbering, unverified rows, and a random sample compared field by field.

  python3 verify_import.py --old https://mail.gnome.science --node http://127.0.0.1:8787 --token-file T [--sample 20]
"""
import argparse
import json
import random
import urllib.parse
import urllib.request


def get(base, path, token):
    req = urllib.request.Request(base.rstrip("/") + path, headers={"Authorization": "Bearer " + token,
                                                                   "User-Agent": "agent-mail-verify/1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def all_messages(base, token):
    out, after = {}, 0
    while True:
        page = get(base, "/api/messages?" + urllib.parse.urlencode({"after": after, "limit": 1000}), token)
        for m in page["messages"]:
            out[m["id"]] = m
            after = m["id"]
        if not page.get("more") or not page["messages"]:
            return out, page.get("last_id")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--sample", type=int, default=20)
    a = ap.parse_args()
    tok = open(a.token_file).read().strip()
    old, last = all_messages(a.old, tok)
    node, _ = all_messages(a.node, tok)
    imported = {i: m for i, m in node.items() if m.get("attest") == "import"}
    gaps = (max(old) if old else 0) - len(old)
    print("old server: %d messages, ids 1..%d (last_id %s), %d gaps in the numbering" % (len(old), max(old), last, gaps))
    print("node: %d rows, %d imported; imported ids == old ids: %s" % (len(node), len(imported), set(imported) == set(old)))
    missing = sorted(set(old) - set(imported))
    extra = sorted(set(imported) - set(old))
    if missing or extra:
        print("missing on node: %d %s; extra on node: %d %s" % (len(missing), missing[:10], len(extra), extra[:10]))
    old_unv = sorted(i for i, m in old.items() if not m.get("verified", True))
    node_unv = sorted(i for i, m in imported.items() if not m.get("verified", True))
    print("unverified (legacy) rows: old %d, node %d, same ids: %s" % (len(old_unv), len(node_unv), old_unv == node_unv))
    files_old = sum(1 for m in old.values() if m.get("files"))
    files_node = sum(1 for i, m in imported.items() if m.get("files"))
    print("rows with file metadata: old %d, node %d" % (files_old, files_node))
    random.seed()
    sample = sorted(random.sample(sorted(old), min(a.sample, len(old))))
    bad = []
    for i in sample:
        o, n = old[i], node.get(i)
        fields = ("text", "from", "to", "thread", "ts", "sub", "verified")
        diff = [f for f in fields if n is None or o.get(f) != n.get(f)]
        if diff:
            bad.append((i, diff))
    print("sample of %d ids %s: %d differ %s" % (len(sample), sample, len(bad), bad))


if __name__ == "__main__":
    main()
