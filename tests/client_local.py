#!/usr/bin/env python3
"""islandmail.py behaviour that needs no node: reading identity files on POSIX and on Windows; send confirmations;
CLI options.
Run: python3 tests/client_local.py"""
import importlib.util
import json
import os
import tempfile

spec = importlib.util.spec_from_file_location("im", os.path.join(os.path.dirname(__file__), "..", "clients", "islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)

with tempfile.TemporaryDirectory() as d:
    im.DIR = os.path.join(d, "keys")
    path = im.ident_path("t.alice")
    im.write_private(path, json.dumps({"name": "t.alice", "sub": "agent:t.alice", "seed": "ab" * 32}))
    assert im._read_identity("t.alice")["name"] == "t.alice"
    # Open it to another user, by mode bits on POSIX or by an access list entry for Everyone on Windows.
    if os.name == "nt":
        im.win_set_dacl(path, "D:P(A;;FA;;;%s)(A;;FR;;;WD)" % im._win_user_sid())
    else:
        os.chmod(path, 0o644)
    try:
        im._read_identity("t.alice")
    except im.Fail as e:
        assert "can access it" in str(e), e
    else:
        raise AssertionError("an identity other users can read was accepted")
    im.restrict(path)
    assert im._read_identity("t.alice")["name"] == "t.alice"
    assert im._IDENT_OPEN & os.O_RDONLY == os.O_RDONLY

me = "S-1-5-21-1-2-3-1001"
assert im.sddl_others("O:%sD:P(A;;FA;;;%s)" % (me, me), me) is None
assert im.sddl_others("O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;OICIID;FA;;;%s)" % me, me) is None
assert im.sddl_others("O:BAD:P(A;OICIIO;GA;;;CO)(D;;FA;;;WD)", me) is None
assert im.sddl_others("O:%sD:P(A;;FR;;;WD)" % me, me) == "WD"
assert im.sddl_others("O:%sD:AI(A;ID;0x1200a9;;;BU)" % me, me) == "BU"
assert im.sddl_others("O:%sD:P(A;;FA;;;S-1-5-21-1-2-3-1002)" % me, me) == "S-1-5-21-1-2-3-1002"
assert im.sddl_others("O:%sD:NO_ACCESS_CONTROL" % me, me) and im.sddl_others("O:" + me, me)
print("ok: identity files must be owner-only (mode bits on POSIX, access list on Windows)")

# A send confirms that this node stored the message, not that the recipients' nodes have it (they may be offline).
note = im.send_note(["t.bob"], "t.bob")
assert note == "; stored here for t.bob, copied to their nodes as they sync" and "reaches" not in note, note
assert im.send_note(["n%d" % i for i in range(14)], "n.").endswith("n11 and 2 more, copied to their nodes as they sync")
assert "no other trusted agent" in im.send_note([], "t.nobody") and im.send_note(None, "t.bob") == ""
print("ok: send confirmations say stored, not delivered")

# who: an agent that has not sent mail yet shows "never", not the Unix epoch.
assert im.who_line({"name": "t.new", "sub": "agent:t.new", "last_active": "1970-01-01T00:00:00.000Z"}).endswith("last active never")
assert im.who_line({"name": "t.old", "sub": "agent:t.old", "last_active": "2026-11-25T10:20:30.000Z"}).endswith("last active 2026-11-25T10:20Z")
print("ok: who shows never for agents with no mail yet")

# The node proves it holds its key before anything is sent: a server that only claims the key (a replayed proof, a
# bad signature or none) is refused, and so is a server with another key at a URL this client knows or has pinned.
import http.server  # noqa: E402
import threading  # noqa: E402
import urllib.parse  # noqa: E402

real_seed, other_seed = os.urandom(32), os.urandom(32)
key_of = lambda seed: "ed25519:" + im.b64u(im.ed25519_public(seed))
REAL = key_of(real_seed)
mode = {"seed": real_seed, "claim": REAL, "proof": "good"}
captured = {}


class FakeNode(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        nonce = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("nonce", [""])[0]
        info = {"node": mode["claim"], "envelope_version": 1, "auth": ["agent-token"], "names": []}
        ts = im.canon_ts()
        if mode["proof"] == "good":
            info["proof"] = {"ts": ts, "sig": im.b64u(im.ed25519_sign(mode["seed"], (
                "islandmail-node-proof|v1|%s|%s" % (nonce, ts)).encode()))}
            captured.setdefault("proof", info["proof"])
        elif mode["proof"] == "replay":
            info["proof"] = captured["proof"]
        elif mode["proof"] == "garbage":
            info["proof"] = {"ts": ts, "sig": im.b64u(os.urandom(64))}
        body = json.dumps(info).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeNode)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def info_fails(**m):
    mode.update(m)
    im._node_info.clear()
    try:
        im.node_info()
    except im.Fail as e:
        return str(e)
    return None


with tempfile.TemporaryDirectory() as d:
    im.DIR, im.MAIL = os.path.join(d, "keys"), "http://127.0.0.1:%d" % srv.server_address[1]
    os.environ.pop("ISLANDMAIL_NODE_KEY", None)
    assert info_fails() is None and im.node_key() == REAL
    with open(im.known_nodes_path()) as f:
        assert json.load(f) == {im.MAIL: REAL}
    # Someone else on the port claims the real key without holding it.
    for how in ("none", "garbage", "replay"):
        e = info_fails(seed=other_seed, claim=REAL, proof=how)
        assert e and "does not prove it holds the node key" in e, (how, e)
    e = info_fails(seed=real_seed, claim=REAL, proof="good")
    assert e is None, e
    # A server with a key of its own (and a good proof for it) at a URL this client knows.
    e = info_fails(seed=other_seed, claim=key_of(other_seed), proof="good")
    assert e and "not %s" % REAL in e and "nodes.json" in e, e
    os.environ["ISLANDMAIL_NODE_KEY"] = key_of(os.urandom(32))
    e = info_fails(seed=real_seed, claim=REAL, proof="good")
    assert e and "ISLANDMAIL_NODE_KEY" in e, e
    os.environ.pop("ISLANDMAIL_NODE_KEY")
srv.shutdown()
print("ok: the node signs a fresh nonce with the expected key before anything is sent")
