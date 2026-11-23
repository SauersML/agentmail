#!/usr/bin/env python3
"""History bridge and dual-send between the old mail server and an agent-mail node. Standard library only.

  python3 bridge.py --old https://OLD --old-token-file T1 --node http://127.0.0.1:8787 --node-token-file T2 \
      --state bridge.sqlite [--sender-tokens DIR] [--once] [--interval 3]

The bridge runs as one identity on both sides (a member; on the node its token's sub must be the node's
`bridge.sub`). The node must have `bridge.key_file` set to a key listed under `bridges` in the member list.

1. Import: every message on the old server (GET /api/messages?after=N, paged) goes to the node's
   POST /api/bridge/import, which keeps the old number, marks it imported, and signs it with the bridge key.
2. Dual-send, while both run, every --interval seconds:
   - old -> p2p: new old-server messages, imported the same way. Messages the bridge itself posted on the old
     server (copies of p2p mail) are skipped.
   - p2p -> old: new members-mode node messages that were not imported (attest != import) are posted to the old
     server. If --sender-tokens holds a live token of the sender (one *.token file each, refreshed from the host that
     holds the sender's key), the copy is posted as the sender, unchanged; otherwise as the bridge identity, with a
     first line naming the real sender. Private mail is never copied: the old server shows every message to everyone.
     Old-server messages the bridge posted either way are not imported back.
Each message crosses once: the state file maps old ids to envelope ids and envelope ids to old ids, and both cursors
are saved after every message. Re-running is safe: the node answers an already-imported old id with the same row,
and the old server answers an identical resend within 10 minutes with the first copy.
"""
import argparse
import calendar
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "agent-mail-bridge/1"
# Token-attested p2p mail is posted on the old server as its sender only while it is this fresh. A token-attested
# envelope is checked against the token's lifetime at the envelope's own ts, so a member node that once saw a sender's
# token can write "from" that sender, backdated into the token's window, at any later time; posting that as the sender
# with a fresh token would make an old-token forgery look current and first-hand there. Older mail goes as the bridge,
# with the header line naming the real sender and the attestation.
AS_SENDER_MAX_AGE_S = 600


def ts_epoch(ts):
    """Seconds since the epoch of an envelope ts (YYYY-MM-DDTHH:MM:SS.mmmZ); None if it is not one."""
    try:
        return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) + int(ts[20:23]) / 1000.0
    except (TypeError, ValueError):
        return None


class Fail(Exception):
    pass


def http(method, base, path, token, body=None, timeout=60):
    h = {"User-Agent": UA, "Authorization": "Bearer " + token}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base.rstrip("/") + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except Exception:
            msg = e.reason
        raise Fail("%s %s%s: %s" % (e.code, base, path.split("?")[0], msg))
    except urllib.error.URLError as e:
        raise Fail("cannot reach %s (%s)" % (base, e.reason))


class State:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS old_to_env (old_id INTEGER PRIMARY KEY, env TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS env_to_old (env TEXT PRIMARY KEY, old_id INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);")

    def get(self, k, default=None):
        r = self.db.execute("SELECT v FROM kv WHERE k = ?", (k,)).fetchone()
        return json.loads(r[0]) if r else default

    def set(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (k, json.dumps(v)))
        self.db.commit()

    def imported(self, old_id):
        return self.db.execute("SELECT env FROM old_to_env WHERE old_id = ?", (old_id,)).fetchone() is not None

    def sent(self, env):
        return self.db.execute("SELECT old_id FROM env_to_old WHERE env = ?", (env,)).fetchone() is not None

    def map_import(self, old_id, env):
        self.db.execute("INSERT OR REPLACE INTO old_to_env (old_id, env) VALUES (?, ?)", (old_id, env))
        self.db.commit()

    def posted(self, old_id):
        return self.db.execute("SELECT 1 FROM env_to_old WHERE old_id = ?", (old_id,)).fetchone() is not None

    def map_sent(self, env, old_id):
        self.db.execute("INSERT OR REPLACE INTO env_to_old (env, old_id) VALUES (?, ?)", (env, old_id))
        self.db.commit()


class Bridge:
    def __init__(self, a):
        self.a = a
        for url in (a.old, a.node):  # tokens go in a header: never in the clear off this host
            u = urllib.parse.urlparse(url)
            if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise Fail("%s: use https (only a loopback node may be plain http)" % url)
        self.old_token = open(a.old_token_file).read().strip()
        self.node_token = open(a.node_token_file).read().strip()
        self.st = State(a.state)
        self.old_me = http("GET", a.old, "/api/me", self.old_token)
        node_me = http("GET", a.node, "/api/me", self.node_token)
        if "features" not in node_me:
            raise Fail("%s is not an agent-mail node" % a.node)
        self.stats = {"imported": 0, "to_old": 0, "to_old_as_sender": 0, "skipped_own": 0, "skipped_private": 0}
        self.senders, self.token_sub = {}, {}

    def load_senders(self):
        """sub -> token for every live token in --sender-tokens (checked once per token with the old server's /api/me)."""
        d = self.a.sender_tokens
        if not d or not os.path.isdir(d):
            self.senders = {}
            return
        senders, present = {}, set()
        for f in sorted(os.listdir(d)):
            if not f.endswith(".token"):
                continue
            tok = open(os.path.join(d, f)).read().strip()
            present.add(tok)
            if tok not in self.token_sub:
                try:
                    self.token_sub[tok] = http("GET", self.a.old, "/api/me", tok).get("sub")
                except Fail as e:
                    sys.stderr.write("bridge: sender token %s refused (%s); its mail goes as the bridge\n" % (f, e))
                    self.token_sub[tok] = None
            if self.token_sub[tok]:
                senders[self.token_sub[tok]] = tok
        self.token_sub = {t: s for t, s in self.token_sub.items() if t in present}  # forget replaced tokens
        self.senders = senders

    def as_sender(self, m):
        """Post m on the old server with its sender's own token. False (and that token dropped) if the old server
        refuses the token, so the message goes as the bridge instead of stalling the pass."""
        try:
            r = http("POST", self.a.old, "/api/messages", self.senders[m["sub"]],
                     {"to": m["to"], "thread": m["thread"], "text": m["text"]})
        except Fail as e:
            if not str(e).startswith(("401 ", "403 ")):
                raise
            sys.stderr.write("bridge: %s's token refused (%s); posting as the bridge\n" % (m["from"], e))
            del self.senders[m["sub"]]
            return False
        self.st.map_sent(m["env"], r["message"]["id"])
        return True

    def old_to_p2p(self):
        """Import every old-server message after the saved cursor. Returns how many pages were read."""
        after = self.st.get("old_after", 0)
        while True:
            page = http("GET", self.a.old, "/api/messages?" + urllib.parse.urlencode({"after": after, "limit": 1000}), self.old_token)
            for m in page["messages"]:
                if m.get("sub") == self.old_me["sub"] or self.st.posted(m["id"]):
                    self.stats["skipped_own"] += 1  # a p2p message the bridge copied there
                elif not self.st.imported(m["id"]):
                    r = http("POST", self.a.node, "/api/bridge/import", self.node_token, {
                        "id": m["id"], "ts": m["ts"], "from": m["from"], "to": m["to"], "thread": m["thread"],
                        "text": m["text"], "files": m.get("files", []), "sub": m.get("sub", ""),
                        "verified": m.get("verified", False)})
                    self.st.map_import(m["id"], r["message"]["env"])
                    self.stats["imported"] += 1
                after = m["id"]
                self.st.set("old_after", after)
            if not page.get("more"):
                return

    def p2p_to_old(self):
        after = self.st.get("p2p_after")
        if after is None:
            # First dual-send pass: only mail written from now on crosses (history went the other way).
            after = http("GET", self.a.node, "/api/me", self.node_token)["last_id"]
            self.st.set("p2p_after", after)
        while True:
            page = http("GET", self.a.node, "/api/messages?" + urllib.parse.urlencode({"after": after, "limit": 1000}), self.node_token)
            for m in page["messages"]:
                if m.get("attest") == "import" or self.st.sent(m["env"]):
                    pass
                elif m.get("mode") == "private":
                    self.stats["skipped_private"] += 1
                elif (m.get("attest", "token") == "token" and m.get("sub") in self.senders
                      and abs(time.time() - (ts_epoch(m.get("ts")) or 0)) <= AS_SENDER_MAX_AGE_S
                      and self.as_sender(m)):
                    self.stats["to_old_as_sender"] += 1
                else:
                    head = "[agent-mail: from %s [%s], #%d on the p2p network, %s-attested]" % (
                        m["from"], m["sub"], m["id"], m.get("attest", "token"))
                    r = http("POST", self.a.old, "/api/messages", self.old_token,
                             {"to": m["to"], "thread": m["thread"], "text": head + "\n" + m["text"]})
                    self.st.map_sent(m["env"], r["message"]["id"])
                    self.stats["to_old"] += 1
                after = m["id"]
                self.st.set("p2p_after", after)
            if not page.get("more"):
                return

    def run(self):
        self.load_senders()
        self.old_to_p2p()
        if self.a.import_only:
            return
        self.p2p_to_old()
        while not self.a.once:
            time.sleep(self.a.interval)
            try:
                # Token files may be refreshed by another process (tokens last a day).
                self.old_token = open(self.a.old_token_file).read().strip()
                self.node_token = open(self.a.node_token_file).read().strip()
                self.load_senders()
                self.old_to_p2p()
                self.p2p_to_old()
            except Fail as e:
                sys.stderr.write("bridge: %s; retrying\n" % e)
            print("bridge: %s" % json.dumps(self.stats), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", required=True, help="old server base URL")
    ap.add_argument("--old-token-file", required=True)
    ap.add_argument("--node", required=True, help="agent-mail node base URL (its compat API)")
    ap.add_argument("--node-token-file", required=True)
    ap.add_argument("--state", required=True, help="SQLite file holding the id maps and cursors")
    ap.add_argument("--sender-tokens", help="directory of *.token files: senders whose p2p mail is posted as themselves")
    ap.add_argument("--interval", type=float, default=3)
    ap.add_argument("--once", action="store_true", help="one import + one dual-send pass, then exit")
    ap.add_argument("--import-only", action="store_true", help="import history, no dual-send")
    a = ap.parse_args()
    try:
        b = Bridge(a)
        b.run()
        print("bridge: %s" % json.dumps(b.stats), flush=True)
    except Fail as e:
        sys.stderr.write("bridge: %s\n" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
