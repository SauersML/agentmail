#!/usr/bin/env python3
"""islandmail.py behaviour that needs no node: reading identity files on POSIX and on Windows; send confirmations.
Run: python3 tests/client_local.py"""
import importlib.util
import json
import os
import tempfile

spec = importlib.util.spec_from_file_location("im", os.path.join(os.path.dirname(__file__), "..", "clients", "islandmail.py"))
im = importlib.util.module_from_spec(spec)
spec.loader.exec_module(im)

with tempfile.TemporaryDirectory() as d:
    im.DIR = d
    path = im.ident_path("t.alice")
    im.write_private(path, json.dumps({"name": "t.alice", "sub": "agent:t.alice", "seed": "ab" * 32}))
    assert im._read_identity("t.alice")["name"] == "t.alice"
    if os.name != "nt":
        os.chmod(path, 0o644)
        try:
            im._read_identity("t.alice")
        except im.Fail:
            pass
        else:
            raise AssertionError("a group-readable identity was accepted on POSIX")
        # Windows reports group/other bits for every writable file; the mode check is POSIX-only.
        im._POSIX_MODES = False
        assert im._read_identity("t.alice")["name"] == "t.alice"
        im._POSIX_MODES = True
    assert im._IDENT_OPEN & os.O_RDONLY == os.O_RDONLY
print("ok: identity files read with only the open flags and mode checks the platform has")

# A send confirms that this node stored the message, not that the recipients' nodes have it (they may be offline).
note = im.send_note(["t.bob"], "t.bob")
assert note == "; stored here for t.bob, copied to their nodes as they sync" and "reaches" not in note, note
assert im.send_note(["n%d" % i for i in range(14)], "n.").endswith("n11 and 2 more, copied to their nodes as they sync")
assert "no other trusted agent" in im.send_note([], "t.nobody") and im.send_note(None, "t.bob") == ""
print("ok: send confirmations say stored, not delivered")
