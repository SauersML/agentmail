#!/usr/bin/env python3
"""islandmail.py behaviour that needs no node: reading identity files on POSIX and on Windows; send confirmations;
CLI options.
Run: python3 tests/client_local.py"""
import importlib.util
import json
import os
import sys
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

# ask takes --private like send (send() reads a.private).
seen = []
im.cmd_ask = seen.append
sys.argv = ["islandmail.py", "ask", "--private", "--to", "t.bob", "a question"]
im.main()
assert seen and seen[0].private and seen[0].to == "t.bob", seen
print("ok: ask --private")

# who: an agent that has not sent mail yet shows "never", not the Unix epoch.
assert im.who_line({"name": "t.new", "sub": "agent:t.new", "last_active": "1970-01-01T00:00:00.000Z"}).endswith("last active never")
assert im.who_line({"name": "t.old", "sub": "agent:t.old", "last_active": "2026-11-25T10:20:30.000Z"}).endswith("last active 2026-11-25T10:20Z")
print("ok: who shows never for agents with no mail yet")
