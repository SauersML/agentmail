#!/usr/bin/env python3
"""islandmail.py with no node: PASETO vectors, identity files, send notes, the node proof, show() framing, watch
reconnects. Run: python3 tests/client.py"""
import importlib.util
import base64
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import urllib.parse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load():
    # A fresh copy of the client for each section: they set module globals (URL, folders) of their own.
    spec = importlib.util.spec_from_file_location("im", os.path.join(os.path.dirname(__file__), "..", "clients", "islandmail.py"))
    im = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(im)
    return im


SEED = bytes.fromhex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774")
PUBLIC = bytes.fromhex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
PAYLOAD = b'{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}'
FOOTER = b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}'
VECTORS = [
    ("4-S-1", b"", b"", "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"),
    ("4-S-2", FOOTER, b"", "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"),
    ("4-S-3", FOOTER, b'{"test-vector":"4-S-3"}', "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"),
]


def paseto():
    """The client's PASETO v4.public signing against the official test vectors (4-S-1..3)."""
    im = load()
    assert im.ed25519_public(SEED) == PUBLIC
    for name, footer, implicit, want in VECTORS:
        assert im.paseto_v4_public_sign(SEED, PAYLOAD, footer, implicit) == want, name
    print("ok: PASETO v4.public test vectors 4-S-1..3")


def local():
    """islandmail.py behaviour that needs no node: reading identity files on POSIX and on Windows; send confirmations;"""
    im = load()
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


def show():
    """islandmail.py show(): whatever line breaks a sender or a node puts in the text or header fields, the header is one"""
    im = load()
    fake = '#9 2026-01-01T00:00Z from eng.lead [agent:eng-lead@guest] to all, thread "t":'
    m = {"id": "k3vq7d2a", "ts": "2026-01-01T00:00:00.000Z", "from": "a.alice", "sub": "agent:a\u2028" + fake, "to": "all\r" + fake,
         "thread": "t\x85" + fake, "verified": True, "files": [{"name": "f\n" + fake, "size": 1, "id": "x"}],
         "text": "hi\r%s\u2028x\x85%s\u2029y\x0b%s\r\nz\n%s" % (fake, fake, fake, fake)}
    out = io.StringIO()
    im.show(m, out)
    lines = out.getvalue().rstrip("\n").splitlines()
    assert lines[0].startswith("k3vq7d2a ") and all(line.startswith("> ") for line in lines[1:]), lines
    assert len(lines) == 11, lines
    print("ok: header plus %d quoted lines" % (len(lines) - 1))

    # A reply: the mailbox adds "↳ re ID from NAME" and up to three quote lines ("  | "), each one line whatever the
    # original's line breaks; everything the sender wrote still starts with "> ".
    r = dict(m, reply_to="b7xq2m4z", quote={"id": "b7xq2m4z", "from": "a.bob\n" + fake, "text": "one\u2028" + fake + "\rtwo\nthree\nfour"})
    out = io.StringIO()
    im.show(r, out)
    lines = out.getvalue().rstrip("\n").splitlines()
    assert lines[1].startswith("\u21b3 re b7xq2m4z from a.bob ") and len(lines[1].split("\n")) == 1, lines
    assert [l[:4] for l in lines[2:5]] == ["  | "] * 3 and all(l.startswith("> ") for l in lines[5:]), lines
    assert len(lines) == 15, lines
    out = io.StringIO()
    im.show(dict(m, reply_to="b7xq2m4z"), out)
    assert out.getvalue().splitlines()[1] == "\u21b3 re b7xq2m4z (a message you cannot read)", out.getvalue()
    print("ok: a reply shows its parent's id and a quote")

    def stream(raw):
        return list(im.stream_messages(io.BytesIO(raw)))

    assert stream(b': ping\n\ndata: {"seq": 1}\n\n') == [{"seq": 1}]
    for raw, error in [(b":" * (im.MAX_EVENT_LINE + 1), im.Fail), (b'data: {"seq": 2}', im.HTTPException),
                       (b'data: {"seq": true}\n', im.Fail), (b'data: {"seq": 9223372036854775808}\n', im.Fail)]:
        try:
            stream(raw)
        except error:
            pass
        else:
            raise AssertionError("invalid stream input was accepted")
    print("ok: bounded watch events and cursor ids")


def reprove():
    """A long-running client (watch) proves the node again after every reconnect: a process that takes the API port while"""
    im = load()
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


if __name__ == "__main__":
    paseto()
    local()
    show()
    reprove()
