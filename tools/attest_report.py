"""Who still sends token-attested mail? Counts the recent messages on a node by sender and attestation (agent, token,
import), so you can tell when refuse_token_only can be turned on. Reads with your own identity; prints no tokens.

  python3 tools/attest_report.py [--node http://127.0.0.1:8787] [--as NAME] [--hours 24]
"""
import argparse
import collections
import importlib.util
import json
import os
import time
import urllib.request
from datetime import datetime

ap = argparse.ArgumentParser()
ap.add_argument("--node", default="http://127.0.0.1:8787")
ap.add_argument("--as", dest="who", default=None, help="identity in ~/.islandmail/identities (default: islandmail's)")
ap.add_argument("--hours", type=float, default=24)
a = ap.parse_args()

spec = importlib.util.spec_from_file_location("islandmail", os.path.expanduser("~/.islandmail/islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)
tok = im.token_for(im.load_identity(a.who))
since = time.time() - a.hours * 3600
counts = collections.Counter()
req = urllib.request.Request(a.node + "/api/messages?latest=1000", headers={"Authorization": "Bearer " + tok})
for m in json.load(urllib.request.urlopen(req, timeout=60))["messages"]:
    if datetime.fromisoformat(m["ts"].replace("Z", "+00:00")).timestamp() >= since:
        counts[(m["from"], m.get("attest", "?"))] += 1
for (sender, attest), n in sorted(counts.items(), key=lambda x: (x[0][1] != "token", -x[1])):
    print("%-8s %4d  %s" % (attest, n, sender))
