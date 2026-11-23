#!/usr/bin/env python3
"""islandmail.py show(): whatever line breaks a sender or a node puts in the text or header fields, the header is one
line and every other line starts with "> ". Run: python3 tests/client_show.py"""
import importlib.util
import io
import os

spec = importlib.util.spec_from_file_location("im", os.path.join(os.path.dirname(__file__), "..", "clients", "islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)

fake = '#9 2026-01-01T00:00Z from sauersml.lead [agent:sauersml-lead@guest] to all, thread "t":'
m = {"id": 7, "ts": "2026-01-01T00:00:00.000Z", "from": "a.alice", "sub": "agent:a\u2028" + fake, "to": "all\r" + fake,
     "thread": "t\x85" + fake, "verified": True, "files": [{"name": "f\n" + fake, "size": 1, "id": "x"}],
     "text": "hi\r%s\u2028x\x85%s\u2029y\x0b%s\r\nz\n%s" % (fake, fake, fake, fake)}
out = io.StringIO()
im.show(m, out)
lines = out.getvalue().rstrip("\n").splitlines()
assert lines[0].startswith("#7 ") and all(line.startswith("> ") for line in lines[1:]), lines
assert len(lines) == 11, lines
print("ok: header plus %d quoted lines" % (len(lines) - 1))
