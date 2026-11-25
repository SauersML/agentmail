#!/usr/bin/env python3
"""Runs the real connectome-host (headless, mock provider: no model calls, no spend) as the MCPL client of one
mailnode, with a throwaway test agent. Checks the MCPL 0.5 handshake (initialize + featureSets/update), that a mail
posted to the agent is pushed as push/event and accepted, and that the push reaches the agent (an inference runs on it).

  python3 tests/host_run.py --bin target/debug/mailnode --host-dir HOST_PKG --bun BUN [--workdir DIR]

HOST_PKG is node_modules/@animalabs/connectome-host of an installed host. HOME and DATA_DIR point into the workdir.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import Client, Node, check, finish, free_port, member_list, req, run, wait_for  # noqa: E402


def grep(path, needle):
    try:
        return [l for l in open(path, errors="replace") if needle in l]
    except FileNotFoundError:
        return []


def grep_tree(root, needle):
    hits = []
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            try:
                if os.path.getsize(p) < 50_000_000 and needle in open(p, errors="replace").read():
                    hits.append(os.path.relpath(p, root))
            except OSError:
                pass
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--host-dir", required=True)
    ap.add_argument("--bun", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = os.path.abspath(a.workdir or "host-%d" % int(time.time()))
    if os.path.exists(work):
        shutil.move(work, work + ".old-%d" % int(time.time()))
    os.makedirs(os.path.join(work, "keys"))
    os.makedirs(os.path.join(work, "home"))  # the host's HOME
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    pub = {n: run(bin_, "keygen", k(n)) for n in ("operator", "nodeA")}
    api, udp = free_port(), free_port(socket.SOCK_DGRAM)
    members = member_list(bin_, work, k("operator"), 1, [("t", pub["nodeA"], None, ["127.0.0.1:%d" % udp])])
    A = Node(bin_, work, "A", {
        "data_dir": os.path.join(work, "dataA"), "api_listen": "127.0.0.1:%d" % api, "iroh_port": udp,
        "node_key_file": k("nodeA"), "operator_key": pub["operator"], "members_file": members, "relay": "disabled",
        "sync_secs": 5})
    alice, hostagent = Client(work, "alice", A), Client(work, "hostagent", A)
    recipe = {
        "name": "agent-mail host test",
        "description": "Throwaway: mock provider, one MCPL server (an agent-mail node).",
        "agent": {"name": "hostagent", "provider": "mock", "systemPrompt": "You are a mock agent for an agent-mail test."},
        "mcpServers": {"mail": {"url": "ws://127.0.0.1:%d/mcpl" % api, "token": ""}},
        "modules": {"subagents": False, "lessons": False, "retrieval": False, "wake": False, "workspace": False},
    }
    rpath = os.path.join(work, "recipe.json")
    json.dump(recipe, open(rpath, "w"), indent=1)
    os.chmod(rpath, 0o600)
    data = os.path.join(work, "hostdata")
    env = dict(os.environ, HOME=os.path.join(work, "home"), DATA_DIR=data)
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
        env.pop(v, None)
    host = None
    nlog = os.path.join(work, "A.log")
    try:
        check("node starts", A.start())
        # The host agent's key, certified by the node; the host dials with an agent token minted from it.
        tok_agent = hostagent.token(3600)
        recipe["mcpServers"]["mail"]["token"] = tok_agent
        json.dump(recipe, open(rpath, "w"), indent=1)
        host = subprocess.Popen(["nice", "-n", "19", a.bun, "src/index.ts", rpath, "--headless"], cwd=a.host_dir, env=env,
                                stdout=open(os.path.join(work, "host.out"), "w"), stderr=subprocess.STDOUT)
        got, dt = wait_for(lambda: grep(nlog, "mcpl t.hostagent: initialize"), timeout=120, every=1)
        check("host dials the node and sends initialize", got, (got[0].split("mailnode::mcpl")[-1].strip()[:160] if got else "") + " after %.0fs" % dt)
        got, dt = wait_for(lambda: grep(nlog, "featureSets/update grant"), timeout=60, every=1)
        line = got[0].split("mailnode::mcpl")[-1].strip()[:200] if got else ""
        check("MCPL 0.5 featureSets/update grant arrives", got, line)
        check("grant gives full mode (push enabled)", bool(got) and "full" in line.rsplit("->", 1)[-1], line)
        st, r = req("POST", api, "/api/messages", alice.token(), {"to": "t.hostagent", "thread": "hosttest",
                                                               "text": "ping from alice: kumquat-7"})
        mid = r.get("message", {}).get("id")
        check("alice posts to the agent", st == 201, "#%s" % mid)
        got, dt = wait_for(lambda: grep(nlog, "push of #%s accepted" % mid), timeout=60, every=1)
        check("node pushes push/event and the host accepts it", got, "%.1fs" % dt)
        got, dt = wait_for(lambda: grep_tree(data, "kumquat-7"), timeout=90, every=2)
        check("the pushed mail reaches the agent (host data holds it)", got, ", ".join(got[:4]) + " after %.0fs" % dt)
    finally:
        if host:
            host.terminate()
            try:
                host.wait(20)
            except subprocess.TimeoutExpired:
                host.kill()
        A.stop()
    for l in grep(nlog, "mailnode::mcpl"):
        print("  node:", l.split("mailnode::mcpl")[-1].strip()[:200])
    finish(work)

if __name__ == "__main__":
    main()
