#!/usr/bin/env python3
"""A stand-in for the old mail server (islandmail src/index.js) with the routes the bridge uses: GET /api/me,
GET /api/messages (after/before/latest/limit/thread/from), POST /api/messages (with the 10-minute identical-resend
rule). Tokens are looked up in a JSON file {token: {name, sub}}; history is seeded from a JSON list.

  python3 fake_old_server.py --port P --tokens tokens.json --seed history.json
"""
import argparse
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

LOCK = threading.Lock()
MESSAGES = []
TOKENS = {}


def now_iso():
    t = datetime.datetime.now(datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def who(self):
        t = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        return TOKENS.get(t)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        w = self.who()
        if not w:
            return self.reply(401, {"error": "sign in first"})
        with LOCK:
            last = max([m["id"] for m in MESSAGES] or [0])
            if u.path == "/api/me":
                return self.reply(200, {"name": w["name"], "sub": w["sub"], "kind": "agent", "island": "old.test", "last_id": last})
            if u.path == "/api/messages":
                rows = sorted(MESSAGES, key=lambda m: m["id"])
                if "after" in q:
                    rows = [m for m in rows if m["id"] > int(q["after"] or 0)]
                if "before" in q:
                    rows = [m for m in rows if m["id"] < int(q["before"])]
                if "thread" in q:
                    rows = [m for m in rows if m["thread"] == q["thread"]]
                if "from" in q:
                    rows = [m for m in rows if m["from"].startswith(q["from"])]
                limit = min(int(q.get("latest") or q.get("limit") or 1000), 1000)
                rows = rows[-limit:] if "latest" in q else rows[:limit]
                return self.reply(200, {"messages": rows, "more": len(rows) == limit, "last_id": last})
        self.reply(404, {"error": "no such endpoint"})

    def do_POST(self):
        u = urlsplit(self.path)
        w = self.who()
        if not w:
            return self.reply(401, {"error": "sign in first"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if u.path != "/api/messages":
            return self.reply(404, {"error": "no such endpoint"})
        with LOCK:
            cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)).isoformat()
            for m in reversed(MESSAGES):
                if (m["sub"] == w["sub"] and m["to"] == body["to"] and m["thread"] == body.get("thread", "general")
                        and m["text"] == body["text"] and m["ts"] > cutoff[:23]):
                    return self.reply(200, {"message": m, "reaches": [], "repeated": True})
            m = {"id": max([x["id"] for x in MESSAGES] or [0]) + 1, "ts": now_iso(), "from": w["name"], "to": body["to"],
                 "thread": body.get("thread", "general"), "text": body["text"], "files": [], "len": len(body["text"]),
                 "sub": w["sub"], "verified": True}
            MESSAGES.append(m)
        self.reply(201, {"message": m, "reaches": []})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--seed", required=True)
    a = ap.parse_args()
    TOKENS.update(json.load(open(a.tokens)))
    MESSAGES.extend(json.load(open(a.seed)))
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
