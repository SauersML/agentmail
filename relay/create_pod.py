#!/usr/bin/env python3
"""Create the relay pod (RunPod REST v2) with relay/boot.sh as its start command. The API key comes from the macOS
keychain item `runpod-api-key` and is never printed. Prints the pod id, cost and port mappings.

  python3 relay/create_pod.py [--name agent-mail-relay-1] [--dc EU-RO-1] [--get POD_ID]
"""
import argparse
import json
import os
import subprocess
import urllib.error
import urllib.request

API = "https://api.runpod.io/v2"


def key():
    return subprocess.run(["security", "find-generic-password", "-s", "runpod-api-key", "-w"],
                          capture_output=True, text=True, check=True).stdout.strip()


def call(method, path, body=None):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + key(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise SystemExit("%s %s: %s" % (e.code, path, e.read().decode()[:500]))


def show(p):
    p = dict(p)
    p.pop("env", None)
    for k in ("cmd", "args", "entrypoint"):
        p.pop(k, None)
    print(json.dumps(p, indent=1)[:3000])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="agent-mail-relay-1")
    ap.add_argument("--dc", default="EU-RO-1")
    ap.add_argument("--get", help="only show this pod")
    a = ap.parse_args()
    if a.get:
        return show(call("GET", "/pods/" + a.get))
    here = os.path.dirname(os.path.abspath(__file__))
    script = open(os.path.join(here, "boot.sh")).read()
    pub = open(os.path.expanduser("~/.ssh/runpod_agent_ed25519.pub")).read().strip()
    body = {
        "name": a.name, "cpu": {"id": "cpu3c", "vcpuCount": 2}, "cloud": "SECURE", "dataCenterIds": [a.dc],
        "image": "runpod/base:2.1.0-ubuntu2404", "disk": 5, "ports": ["3340/tcp", "22/tcp"],
        "entrypoint": ["/bin/bash", "-c"], "cmd": [script], "env": {"PUBLIC_KEY": pub},
    }
    show(call("POST", "/pods", body))


if __name__ == "__main__":
    main()
