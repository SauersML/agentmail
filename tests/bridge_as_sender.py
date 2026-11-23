#!/usr/bin/env python3
"""bridge.py p2p -> old: token-attested mail goes as its sender only while fresh; an old (possibly backdated) one goes as
the bridge with the header naming the sender. No network: http is replaced. Run: python3 tests/bridge_as_sender.py"""
import argparse
import importlib.util
import os
import tempfile
import time

spec = importlib.util.spec_from_file_location("bridge", os.path.join(os.path.dirname(__file__), "..", "bridge", "bridge.py"))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def ts(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


now = time.time()
msgs = [
    {"id": 1, "env": "e1", "ts": ts(now - 5), "from": "a.x", "sub": "agent:x@t", "to": "all", "thread": "t",
     "text": "fresh", "mode": "members", "attest": "token"},
    {"id": 2, "env": "e2", "ts": ts(now - 3 * 86400), "from": "a.x", "sub": "agent:x@t", "to": "all", "thread": "t",
     "text": "backdated", "mode": "members", "attest": "token"},
    {"id": 3, "env": "e3", "ts": "garbage", "from": "a.x", "sub": "agent:x@t", "to": "all", "thread": "t",
     "text": "bad ts", "mode": "members", "attest": "token"},
    {"id": 4, "env": "e4", "ts": ts(now - 5), "from": "a.x", "sub": "agent:x@t", "to": "all", "thread": "t",
     "text": "signed", "mode": "members", "attest": "agent"},
]
posts = []


def fake_http(method, base, path, token, body=None, timeout=60):
    if method == "GET":
        return {"messages": msgs, "more": False}
    posts.append((token, body["text"]))
    return {"message": {"id": 100 + len(posts)}}


bridge.http = fake_http
b = bridge.Bridge.__new__(bridge.Bridge)
b.a = argparse.Namespace(old="http://old", node="http://node")
b.st = bridge.State(os.path.join(tempfile.mkdtemp(), "state.sqlite"))
b.st.set("p2p_after", 0)
b.old_token, b.node_token = "BRIDGE", "NODE"
b.senders = {"agent:x@t": "SENDER"}
b.stats = {"imported": 0, "to_old": 0, "to_old_as_sender": 0, "skipped_own": 0, "skipped_private": 0}
b.p2p_to_old()
assert posts[0] == ("SENDER", "fresh"), posts
assert posts[1][0] == "BRIDGE" and posts[1][1].startswith("[agent-mail: from a.x [agent:x@t]") and posts[1][1].endswith("backdated"), posts
assert posts[2][0] == "BRIDGE", posts
assert posts[3] == ("SENDER", "signed"), posts  # agent-signed mail goes as its sender too
print("ok: fresh (token or agent-signed) as sender, old and unparseable as the bridge")
