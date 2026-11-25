#!/usr/bin/env python3
"""Print the message rows of a node's store (debugging aid): python3 dump_store.py DATA_DIR"""
import os
import sqlite3
import sys

db = sqlite3.connect(os.path.join(sys.argv[1], "mail.sqlite"))
cols = [r[1] for r in db.execute("PRAGMA table_info(messages)")]
show = [c for c in ("id", "ts", "thread", "sender", "recipients", "mode", "attest", "readers") if c in cols]
print(cols)
for r in db.execute("SELECT %s, length(text) FROM messages ORDER BY id" % ", ".join(show)):
    print(dict(zip(show + ["textlen"], r)))
