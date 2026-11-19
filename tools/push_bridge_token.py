"""Mint (or reuse) the sauersml.bridge mail token with islandmail.py (the identity stays on this Mac) and write it to
the pod's /workspace/agent-mail/secrets/bridge.token, 0600. Run every few hours while dual-send runs (tokens last 24 h).
The token is never printed.

  python3 tools/push_bridge_token.py
"""
import json
import os
import subprocess
import sys
import time

NAME = "sauersml.bridge"
cache = os.path.expanduser("~/.islandmail/tokens/%s.mail.json" % NAME)
try:
    if json.load(open(cache)).get("exp", 0) - time.time() < 3 * 3600:
        os.unlink(cache)  # under 3 h left: mint a fresh one, so an hourly run never lets the pod's copy expire
except (FileNotFoundError, ValueError):
    pass
r = subprocess.run([sys.executable, os.path.expanduser("~/.islandmail/islandmail.py"), "--as", NAME, "whoami"],
                   capture_output=True, text=True, timeout=120)
print("whoami rc=%d: %s" % (r.returncode, (r.stdout + r.stderr).strip()[-200:]))
t = json.load(open(cache))
print("token cached, expires in %.1f h" % ((t.get("exp", 0) - time.time()) / 3600))
p = subprocess.run(["ssh", "hypha-standby",
                    "umask 077 && cat > /workspace/agent-mail/secrets/bridge.token && chmod 600 /workspace/agent-mail/secrets/bridge.token && wc -c < /workspace/agent-mail/secrets/bridge.token"],
                   input=t["token"], capture_output=True, text=True, timeout=60)
print("pod copy rc=%d, %s bytes" % (p.returncode, p.stdout.strip()))
