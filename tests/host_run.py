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
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, req, run, wait_for, work_directory  # noqa: E402


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
    work = work_directory(a.workdir)
    os.makedirs(os.path.join(work, "keys"))
    os.makedirs(os.path.join(work, "home"))
    k = lambda n: os.path.join(work, "keys", n + ".seed")
    pub = {n: run(bin_, "keygen", k(n)) for n in ("nodeA", "alice", "hostagent")}
    ids = os.path.join(work, "identities")
    os.mkdir(ids, 0o700)
    for name in ("alice", "hostagent"):
        path = os.path.join(ids, name + ".json")
        with open(path, "x") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump({"name": "t." + name, "sub": "agent:%s@test" % name, "seed": open(k(name)).read().strip()}, f)
    api, udp = free_port(), free_port(socket.SOCK_DGRAM)
    lst = {"v": 2, "network": run(bin_, "network-id"), "seq": 1,
           "members": [{"name": "t.alice", "sub": "agent:alice@test", "key": pub["alice"]},
                       {"name": "t.hostagent", "sub": "agent:hostagent@test", "key": pub["hostagent"]}],
           "nodes": [{"name": "A", "key": pub["nodeA"], "addrs": ["127.0.0.1:%d" % udp]}]}
    json.dump(lst, open(os.path.join(work, "members.json"), "w"))

    A = Node(bin_, work, "A", {
        "data_dir": os.path.join(work, "dataA"), "api_listen": "127.0.0.1:%d" % api, "iroh_port": udp,
        "node_key_file": k("nodeA"), "members_file": os.path.join(work, "members.json"),
        "identities_dir": ids, "sync_secs": 5})
    tok_agent, tok_alice = [run(bin_, "agent-token", os.path.join(ids, n + ".json"), pub["nodeA"]) for n in ("hostagent", "alice")]
    recipe = {
        "name": "agent-mail host test",
        "description": "Throwaway: mock provider, one MCPL server (an agent-mail node).",
        "agent": {"name": "hostagent", "provider": "mock", "systemPrompt": "You are a mock agent for an agent-mail test."},
        "mcpServers": {"mail": {"url": "ws://127.0.0.1:%d/mcpl" % api, "tokenTransport": "header", "token": tok_agent}},
        "modules": {"subagents": False, "lessons": False, "retrieval": False, "wake": False, "workspace": False},
    }
    rpath = os.path.join(work, "recipe.json")
    json.dump(recipe, open(rpath, "w"), indent=1)
    os.chmod(rpath, 0o600)
    data = os.path.join(work, "hostdata")
    env = dict(os.environ, HOME=os.path.join(work, "home"), DATA_DIR=data, CONNECTOME_UPDATE_CHECK="0")
    for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
        env.pop(v, None)
    host = None
    nlog = os.path.join(work, "A.log")
    try:
        check("node starts", A.start())
        host = subprocess.Popen(["nice", "-n", "19", a.bun, "src/index.ts", rpath, "--headless"], cwd=a.host_dir, env=env,
                                stdout=open(os.path.join(work, "host.out"), "w"), stderr=subprocess.STDOUT)
        got, dt = wait_for(lambda: grep(nlog, "mcpl t.hostagent: initialize"), timeout=120, every=1)
        check("host dials the node and sends initialize", got, (got[0].split("mailnode::mcpl")[-1].strip()[:160] if got else "") + " after %.0fs" % dt)
        got, dt = wait_for(lambda: grep(nlog, "featureSets/update grant"), timeout=60, every=1)
        line = got[0].split("mailnode::mcpl")[-1].strip()[:200] if got else ""
        check("MCPL 0.5 featureSets/update grant arrives", got, line)
        check("grant gives full mode (push enabled)", bool(got) and "full" in line.rsplit("->", 1)[-1], line)
        st, r = req("POST", api, "/api/messages", tok_alice, {"to": "t.hostagent", "thread": "hosttest", "text": "ping from alice: kumquat-7"})
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
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
