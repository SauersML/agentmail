#!/usr/bin/env python3
"""A long-running client (watch) proves the node again after every reconnect: a process that takes the API port while
the node restarts gets no stream token (an hour-long agent token) and cannot feed the watch forged mail.
Run: python3 tests/client_reprove.py"""
import base64
import http.server
import importlib.util
import json
import os
import sys
import tempfile
import threading
import urllib.parse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

spec = importlib.util.spec_from_file_location("im", os.path.join(os.path.dirname(__file__), "..", "clients", "islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


node = Ed25519PrivateKey.generate()
NODE_KEY = "ed25519:" + b64u(node.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
state = {"impostor": False, "streams": 0, "stolen": []}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/api/node":
            ts = "2026-01-01T00:00:00.000Z"
            # The impostor knows the public key but cannot sign with it.
            sig = b"\0" * 64 if state["impostor"] else node.sign(("islandmail-node-proof|v1|%s|%s" % (q["nonce"], ts)).encode())
            return self.reply(200, {"node": NODE_KEY, "envelope_version": 1, "auth": ["agent-token"],
                                    "proof": {"ts": ts, "sig": b64u(sig)}})
        if url.path == "/api/me":
            return self.reply(200, {"last_seq": 0})
        if url.path == "/api/invites/joined":
            return self.reply(200, {"joined": []})
        if url.path == "/api/stream":
            if state["impostor"]:
                state["stolen"].append(self.headers.get("Authorization"))
                return self.reply(400, {"error": "impostor"})
            state["streams"] += 1
            # The real node's stream ends (it is restarting); another process takes the port before it is back.
            state["impostor"] = True
            body = b"retry: 2000\n: connected\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.reply(404, {"error": "no"})


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
im.MAIL = "http://127.0.0.1:%d" % srv.server_address[1]
im.time.sleep = lambda s: None

with tempfile.TemporaryDirectory() as d:
    im.DIR = d
    seed = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                      serialization.NoEncryption())
    im.write_private(im.ident_path("t.alice"), json.dumps({"name": "t.alice", "sub": "agent:t.alice", "seed": seed.hex()}))
    sys.argv = ["islandmail.py", "--as", "t.alice", "watch", "--mine"]
    try:
        im.main()
    except SystemExit:
        pass
    except im.Fail:
        pass
srv.shutdown()
assert state["streams"] == 1, state
assert state["stolen"] == [], "the watch sent its stream token to a server that did not prove the node key: %s" % state
print("ok: watch proves the node again before each reconnect")
