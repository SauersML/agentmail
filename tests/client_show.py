#!/usr/bin/env python3
"""islandmail.py show(): whatever line breaks a sender or a node puts in the text or header fields, the header is one
line and every other line starts with "> ". Run: python3 tests/client_show.py"""
import importlib.util
import io
import os

spec = importlib.util.spec_from_file_location("im", os.path.join(os.path.dirname(__file__), "..", "clients", "islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)

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
