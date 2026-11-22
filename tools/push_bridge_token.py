"""Mint (or reuse) the mail tokens the bridge needs and write them to the pod, 0600. Tokens are never printed.

  python3 tools/push_bridge_token.py [SENDERS.json]

- sauersml.bridge, with islandmail.py (the identity stays on this Mac) -> /workspace/agent-mail/secrets/bridge.token
- each sender in SENDERS.json ([{"name": ..., "key_pem": PATH, "home": ...}], kept outside this repo): agents on this
  Mac that write on the p2p network. Their token, minted from their own host key, lets the bridge post their mail on
  the old server as themselves -> /workspace/agent-mail/secrets/senders/NAME.token
Run hourly while dual-send runs (tokens last 24 h; a fresh one is minted when under 3 h are left).
"""
import base64
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

POD = "hypha-standby"
SECRETS = "/workspace/agent-mail/secrets"
spec = importlib.util.spec_from_file_location("islandmail", os.path.expanduser("~/.islandmail/islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)


def fresh(name):
    cache = os.path.join(im.DIR, "tokens", "%s.mail.json" % name)
    try:
        return json.load(open(cache)).get("exp", 0) - time.time() < 3 * 3600
    except (FileNotFoundError, ValueError):
        return True


def push(token, path):
    d = os.path.dirname(path)
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", POD,
                        "umask 077 && mkdir -p %s && cat > %s && chmod 600 %s && wc -c < %s" % (d, path, path, path)],
                       input=token, capture_output=True, text=True, timeout=60)
    print("%s: pod copy rc=%d, %s bytes" % (os.path.basename(path), p.returncode, p.stdout.strip()))


def pem_seed(path):
    """The 32-byte ed25519 seed of a PKCS#8 PEM key (the fixed 16-byte prefix, then the seed)."""
    der = base64.b64decode("".join(l for l in open(path).read().splitlines() if not l.startswith("-----")))
    if len(der) != 48 or der[:16] != bytes.fromhex("302e020100300506032b657004220420"):
        raise SystemExit("%s is not an ed25519 PKCS#8 key" % path)
    return der[16:]


ident = im.load_identity("sauersml.bridge")
push(im.token_for(ident, fresh=fresh(ident["name"])), SECRETS + "/bridge.token")

for s in json.load(open(sys.argv[1])) if len(sys.argv) > 1 else []:
    if not re.fullmatch(r"[a-z0-9.-]+", s["name"]):
        raise SystemExit("bad sender name %r" % s["name"])
    seed = pem_seed(s["key_pem"])
    ident = {"name": s["name"], "home": s["home"], "seed": seed.hex(), "id": "ed25519:" + im.b64u(im.ed25519_public(seed))}
    push(im.token_for(ident, fresh=fresh(s["name"])), "%s/senders/%s.token" % (SECRETS, s["name"]))
