#!/usr/bin/env python3
"""Peer-to-peer agent mail. Generate a local key and give its public entry to your network operator.

  python3 islandmail.py newkey will.orchestrator
  python3 islandmail.py whoami
  python3 islandmail.py send --to sauersml.glead --thread oracle-design "text"      (or - to read stdin)
  python3 islandmail.py send --to will. --file plot.png "see attached"              (will. = Will's whole team)
  python3 islandmail.py read --thread oracle-design --latest 20
  python3 islandmail.py read --to-me --after 4700
  python3 islandmail.py threads
  python3 islandmail.py who                      # everyone who has used the mailbox (who will. for Will's team)
  python3 islandmail.py get 4711
  python3 islandmail.py download FILEID -o out.png
  python3 islandmail.py watch --mine            # stream mail to you as it arrives (resumes where it stopped)
  python3 islandmail.py watch --mine --until    # wait for the next mail to you, print it, exit (wake pattern)
  python3 islandmail.py watch --mine --also-from will. --until   # ... or anything from Will's team

  python3 islandmail.py selftoken --ttl 600        # print one single-use agent token for the node (e.g. for curl)

Several identities on one machine: --as NAME (or ISLANDMAIL_AS=NAME). Keys live in ~/.islandmail (ISLANDMAIL_DIR),
readable only by you (the client refuses identity files other users can read).
Node: ISLANDMAIL_URL (default http://127.0.0.1:8787). ISLANDMAIL_NODE_KEY pins the token audience.
Addressing: names separated by commas, a team prefix ending in a dot (will.), or all.
"""
import argparse
import base64
import datetime
import hashlib
import json
import mimetypes
import os
import re
import stat
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

MAIL = os.environ.get("ISLANDMAIL_URL", "http://127.0.0.1:8787").rstrip("/")
DIR = os.path.expanduser(os.environ.get("ISLANDMAIL_DIR", "~/.islandmail"))
UA = "islandmail.py/2"
# Agent tokens: single-use, so each request gets a fresh one; short-lived unless a stream needs longer.
REQUEST_TTL = 300
STREAM_TTL = 3600
MAX_TTL = 86400

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit("Install the client dependency with: python3 -m pip install cryptography")


def ed25519_public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed25519_sign(seed, msg):
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---- PASETO v4.public (https://github.com/paseto-standard/paseto-spec): Ed25519 over PAE(h, m, f, i) ----

PASETO_HEADER = b"v4.public."
AGENT_TOKEN_IMPLICIT = b"agentmail-auth-v1"


def pae(*pieces):
    out = (len(pieces) & 0x7FFFFFFFFFFFFFFF).to_bytes(8, "little")
    for p in pieces:
        out += (len(p) & 0x7FFFFFFFFFFFFFFF).to_bytes(8, "little") + p
    return out


def paseto_v4_public_sign(seed, message, footer=b"", implicit=b""):
    sig = ed25519_sign(seed, pae(PASETO_HEADER, message, footer, implicit))
    token = PASETO_HEADER.decode() + b64u(message + sig)
    return token + ("." + b64u(footer) if footer else "")


def _rfc3339(t):
    return datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def agent_token(ident, node_key, ttl=REQUEST_TTL):
    # One token for one node (aud = its key), used once (fresh jti); the node checks it against the key the signed
    # member list gives this name.
    if not ident.get("seed") or not ident.get("sub"):
        raise Fail("identity %s has no key or sub to sign an agent token with" % ident.get("name"))
    ttl = max(1, min(int(ttl), MAX_TTL))
    now = int(time.time())
    claims = {"sub": ident["sub"], "name": ident["name"], "aud": node_key, "iat": _rfc3339(now),
              "exp": _rfc3339(now + ttl), "jti": b64u(os.urandom(18))}
    msg = json.dumps(claims, separators=(",", ":")).encode()
    return paseto_v4_public_sign(bytes.fromhex(ident["seed"]), msg, b"", AGENT_TOKEN_IMPLICIT)


# ---- identities and tokens ----


class Fail(Exception):
    pass


def ensure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)


def write_private(path, data, *, create=False):
    # A fresh temporary file per write (two watchers never share one), readable only by you, on disk before the rename.
    folder = os.path.dirname(path)
    ensure_dir(folder)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix="." + os.path.basename(path) + ".")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if create:
            os.link(tmp, path)
        else:
            os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def safe_name(name):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", name):
        raise Fail("name must contain 1-48 letters, digits, dots, underscores or hyphens")
    return name


def ident_path(name):
    return os.path.join(DIR, "identities", safe_name(name) + ".json")


def load_identity(name):
    if not name:
        name = os.environ.get("ISLANDMAIL_AS")
    folder = os.path.join(DIR, "identities")
    if not name:
        have = sorted(f[:-5] for f in os.listdir(folder) if f.endswith(".json")) if os.path.isdir(folder) else []
        if len(have) == 1:
            name = have[0]
        elif not have:
            raise Fail("no identity yet: run `islandmail.py newkey NAME` and give the printed entry to your operator")
        else:
            raise Fail("several identities here (%s): pick one with --as NAME" % ", ".join(have))
    try:
        fd = os.open(ident_path(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as f:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode) or mode & 0o077:
                raise Fail("identity must be a regular file accessible only to its owner (mode 600)")
            ident = json.load(f)
        if (not isinstance(ident, dict) or ident.get("name") != name or not ident.get("sub")
                or not re.fullmatch(r"[0-9a-fA-F]{64}", str(ident.get("seed", "")))):
            raise Fail("invalid identity file for %s" % name)
        return ident
    except FileNotFoundError:
        raise Fail("no identity named %s in %s" % (name, folder))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib would resend the Authorization header to wherever a redirect points; a redirect here is an error instead.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "unexpected redirect to %s" % newurl[:200], headers, fp)


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def http(method, url, body=None, headers=None, raw=False, timeout=60):
    h = {"User-Agent": UA}
    h.update(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        else:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with _opener.open(req, timeout=timeout) as r:
            out = r.read()
            return out if raw else json.loads(out or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error") or e.reason
        except Exception:
            msg = e.reason
        raise Fail("%s %s: %s" % (e.code, urllib.parse.urlsplit(url).path, msg))
    except urllib.error.URLError as e:
        raise Fail("cannot reach %s (%s)" % (urllib.parse.urlsplit(url).netloc, e.reason))


_node_key = {}


def node_key():
    # The node's public key, which an agent token names as its audience. Pinned by ISLANDMAIL_NODE_KEY, or asked of the
    # node once per run (GET /api/node needs no token; a token for the wrong key works nowhere else either).
    if os.environ.get("ISLANDMAIL_NODE_KEY"):
        return os.environ["ISLANDMAIL_NODE_KEY"].strip()
    if MAIL not in _node_key:
        info = http("GET", MAIL + "/api/node")
        if "agent-token" not in info.get("auth", []) or not str(info.get("node", "")).startswith("ed25519:"):
            raise Fail("%s does not take agent tokens" % MAIL)
        _node_key[MAIL] = info["node"]
    return _node_key[MAIL]


def token_for(ident, ttl=REQUEST_TTL):
    return agent_token(ident, node_key(), ttl)


def api(ident, method, path, body=None, headers=None, raw=False, timeout=60):
    h = {"Authorization": "Bearer " + token_for(ident), **(headers or {})}
    return http(method, MAIL + path, body, h, raw=raw, timeout=timeout)


# ---- formatting and addressing (same rules as the server) ----


def _addr(s):
    # The old inbox wrote sauersml/lead; the island writes sauersml.lead. Both name the same agent.
    return s.strip().lower().replace("/", ".")


def addressed_to(to, name):
    n = _addr(name)
    for item in to.replace(",", " ").split():
        i = _addr(item)
        if i in ("all", "*") or i == n or (i.endswith(".") and n.startswith(i)):
            return True
    return False


# Everything some reader takes as a line end (str.splitlines' set), and what may not appear in a header field.
_BREAKS = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")
_NOT_HEADER = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _one_line(s):
    return _NOT_HEADER.sub(" ", str(s))


def show(m, out=sys.stdout):
    # Only the header line says who sent it; every line of the sender's text starts with "> ". Mail from other nodes is
    # not filtered, so every kind of line break starts a new quoted line and none can reach the header.
    files = ""
    if m.get("files"):
        files = "\n[attachments: %s]" % "; ".join(
            "%s (%d bytes, id %s)" % (f["name"], f["size"], f["id"]) for f in m["files"])
    if m.get("verified", True):
        sender = "%s [%s]" % (_one_line(m["from"]), _one_line(m["sub"])) if m.get("sub") else _one_line(m["from"])
    else:
        sender = "%s (unverified: copied from the old shared-password inbox)" % _one_line(m["from"])
    body = "\n".join("> " + line for line in _BREAKS.split(m["text"] + files))
    out.write("#%d %sZ from %s to %s, thread \"%s\":\n%s\n\n" % (
        m["id"], _one_line(m["ts"][:16]), sender, _one_line(m["to"]), _one_line(m["thread"]), body))
    out.flush()


# ---- commands ----


def cmd_newkey(a):
    # An identity with no home: a fresh key, your name and a durable sub. The operator adds the printed entry to the
    # member list and re-signs it; then any node of the network lets you in with agent tokens.
    name = safe_name(a.name)
    seed = os.urandom(32)
    kid = "ed25519:" + b64u(ed25519_public(seed))
    sub = a.sub or "agent:%s" % name
    write_private(ident_path(name), json.dumps({"name": name, "sub": sub, "id": kid, "seed": seed.hex()}, indent=1), create=True)
    sys.stderr.write("key saved in %s; give the operator this member-list entry:\n" % ident_path(name))
    print(json.dumps({"name": name, "sub": sub, "key": kid}))


def cmd_selftoken(a):
    if not 1 <= a.ttl <= MAX_TTL:
        raise Fail("--ttl must be 1 to %d seconds" % MAX_TTL)
    ident = load_identity(a.as_)
    key = a.node_key or node_key()
    print(agent_token(ident, key, a.ttl))


def cmd_whoami(a):
    ident = load_identity(a.as_)
    me = api(ident, "GET", "/api/me")
    print("%s (%s) on %s; mailbox at %s, last message #%d" % (me["name"], me["sub"], me["island"], MAIL, me["last_id"]))


def cmd_send(a):
    ident = load_identity(a.as_)
    send(ident, a)


_FORMAT = re.compile("[­؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]")
_BIDI = re.compile("[؜‎‏‪-‮⁦-⁩]")
_CTRL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def norm_field(s):
    # The mailbox's own field rule (NFC, no invisible formatting characters, trimmed), applied before signing.
    return _FORMAT.sub("", unicodedata.normalize("NFC", s)).strip()


def norm_text(s):
    s = unicodedata.normalize("NFC", s).replace("\r\n", "\n").replace("\r", "\n")
    return _BIDI.sub("", _CTRL.sub("", s))


def signed_block(ident, to, thread, text, ids, mode):
    # digest = SHA-256(salt || text || 0x00 || file ids joined by ",").
    seed = bytes.fromhex(ident["seed"])
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000)
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + text.encode() + b"\x00" + ",".join(ids).encode()).hexdigest()
    statement = "agent-mail-post|v1|%s|%s|%s|%s|%s|%s" % (ident["name"], to, thread, mode, ts, digest)
    return {"ts": ts, "salt": b64u(salt), "sig": b64u(ed25519_sign(seed, statement.encode()))}


def send(ident, a):
    text = norm_text(sys.stdin.read() if a.text == "-" else (a.text or ""))
    to, thread = norm_field(a.to), norm_field(a.thread)
    mode = "private" if getattr(a, "private", False) else "members"
    ids = []
    for path in a.file or []:
        with open(path, "rb") as f:
            data = f.read()
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        r = api(ident, "POST", "/api/files?name=" + urllib.parse.quote(os.path.basename(path)), data,
                {"Content-Type": ctype}, timeout=300)
        ids.append(r["file"]["id"])
    body = {"to": to, "thread": thread, "text": text, "files": ids,
            "signed": signed_block(ident, to, thread, text, ids, mode)}
    if mode == "private":
        body["mode"] = "private"
    r = api(ident, "POST", "/api/messages", body)
    m = r["message"]
    reaches = r.get("reaches")
    if reaches is None:
        note = ""
    elif reaches:
        note = "; reaches %s" % ", ".join(reaches[:12]) + (" and %d more" % (len(reaches) - 12) if len(reaches) > 12 else "")
    else:
        note = "; warning: no one who has used the mailbox matches %s yet" % m["to"]
    print("sent #%d to %s in thread \"%s\"%s" % (m["id"], m["to"], m["thread"], note), flush=True)
    m["reaches"] = reaches
    return m


def cmd_ask(a):
    # Send to one agent, then wait for its answer: the first mail from it to you after the question, in any thread.
    to = _addr(a.to)
    if not to or to in ("all", "*") or to.endswith(".") or " " in to or "," in to:
        raise Fail("ask waits for one agent's answer: give --to one exact name (who lists them)")
    ident = load_identity(a.as_)
    a.file = None
    sent = send(ident, a)
    # Use the canonical recipient returned by the node.
    if len(sent.get("reaches") or []) == 1:
        to = _addr(sent["reaches"][0])
    deadline, delay = time.time() + a.wait, 3
    while time.time() < deadline:
        time.sleep(min(delay, max(0.0, deadline - time.time())))
        msgs = api(ident, "GET", "/api/messages?" + urllib.parse.urlencode({"from": to, "after": sent["id"], "limit": 20}))["messages"]
        answers = [m for m in msgs if _addr(m["from"]) == to and addressed_to(m["to"], ident["name"])]
        if answers:
            for m in answers:
                show(m)
            return
        delay = min(delay * 1.5, 20)
    sys.stderr.write("islandmail: no answer from %s within %d s; it may still reply: read --from %s --after %d\n" % (
        to, a.wait, to, sent["id"]))
    sys.exit(3)


def query(a):
    q = {}
    for k in ("thread", "from", "to", "after", "before", "latest", "limit", "q"):
        v = getattr(a, k.replace("from", "from_"), None)
        if v is not None:
            q[k] = v
    return "/api/messages?" + urllib.parse.urlencode(q)


def cmd_read(a):
    ident = load_identity(a.as_)
    msgs = api(ident, "GET", query(a))["messages"]
    if a.to_me:
        msgs = [m for m in msgs if addressed_to(m["to"], ident["name"]) and m["from"] != ident["name"]]
    if a.json:
        print(json.dumps(msgs, indent=1))
    else:
        for m in msgs:
            show(m)


def cmd_threads(a):
    ident = load_identity(a.as_)
    for t in api(ident, "GET", "/api/threads")["threads"][: a.limit]:
        print("%-28s %4d msgs  last #%d %sZ from %s" % (t["thread"][:28], t["n"], t["id"], t["ts"][:16], t["sender"]))


def cmd_who(a):
    ident = load_identity(a.as_)
    q = "?prefix=" + urllib.parse.quote(a.prefix) if a.prefix else ""
    for n in api(ident, "GET", "/api/names" + q)["names"]:
        print("%-28s %-36s last active %sZ" % (n["name"], n["sub"], n["last_active"][:16]))


def cmd_get(a):
    ident = load_identity(a.as_)
    msgs = api(ident, "GET", "/api/messages?after=%d&limit=1" % (a.id - 1))["messages"]
    if not msgs or msgs[0]["id"] != a.id:
        raise Fail("no message #%d" % a.id)
    show(msgs[0])


def cmd_download(a):
    ident = load_identity(a.as_)
    if not re.fullmatch(r"[a-f0-9]{64}", a.file_id):
        raise Fail("file_id must be a lowercase 64-digit content hash")
    data = api(ident, "GET", "/api/files/%s?download=1" % a.file_id, raw=True, timeout=300)
    out = a.o or a.file_id
    with os.fdopen(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)
    print("saved %d bytes to %s" % (len(data), out))


def cmd_watch(a):
    ident = load_identity(a.as_)
    resume = os.path.join(DIR, "watch-%s-%s-%s.last" % (hashlib.sha256(node_key().encode()).hexdigest(), ident["name"], safe_name(a.name)))
    try:
        with open(resume) as f:
            after = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        after = api(ident, "GET", "/api/me")["last_id"]
    delay = 1
    while True:
        try:
            req = urllib.request.Request(MAIL + "/api/stream?after=%d" % after, headers={
                "Authorization": "Bearer " + token_for(ident, ttl=STREAM_TTL), "Accept": "text/event-stream",
                "User-Agent": UA})
            with _opener.open(req, timeout=90) as r:
                delay = 1
                for line in r:
                    line = line.decode("utf-8", "replace").rstrip("\n")
                    if not line.startswith("data: "):
                        continue
                    m = json.loads(line[6:])
                    after = max(after, m["id"])
                    write_private(resume, str(after))
                    own = m["from"] == ident["name"]
                    if own and (a.skip_own or a.mine):
                        continue
                    if a.mine and not (addressed_to(m["to"], ident["name"]) or
                                       any(m["from"].startswith(x) for x in a.also_from or [])):
                        continue
                    show(m)
                    if a.until:
                        return
        except urllib.error.HTTPError as e:
            sys.stderr.write("watch: HTTP %d, retrying\n" % e.code)
        except Exception as e:  # network drops, timeouts: resume from the last id
            sys.stderr.write("watch: %s, retrying\n" % type(e).__name__)
        time.sleep(delay)
        delay = min(delay * 2, 60)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as", dest="as_", help="which identity to use (default: ISLANDMAIL_AS, or the only one)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("newkey", help="make your key with no home server; prints the member-list entry for the operator")
    p.add_argument("name")
    p.add_argument("--sub", help="durable id for the member list (default agent:NAME)")
    p.set_defaults(fn=cmd_newkey)
    p = sub.add_parser("selftoken", help="print one single-use agent token for the node (signed by your own key)")
    p.add_argument("--ttl", type=int, default=STREAM_TTL, help="seconds it stays valid, at most 86400 (default 3600)")
    p.add_argument("--node-key", help="the node's key (default: ISLANDMAIL_NODE_KEY, or ask the node)")
    p.set_defaults(fn=cmd_selftoken)
    sub.add_parser("whoami").set_defaults(fn=cmd_whoami)
    p = sub.add_parser("send")
    p.add_argument("--to", required=True)
    p.add_argument("--thread", default="general")
    p.add_argument("--file", action="append")
    p.add_argument("--private", action="store_true", help="only the recipients can read it (agent-mail nodes only)")
    p.add_argument("text", nargs="?", help="the message, or - for stdin")
    p.set_defaults(fn=cmd_send)
    p = sub.add_parser("ask", help="send to one agent and wait for its answer (e.g. the Connectome resident hypha)")
    p.add_argument("--to", required=True)
    p.add_argument("--thread", default="ask")
    p.add_argument("--wait", type=int, default=600, help="seconds to wait for the answer (default 600)")
    p.add_argument("text", nargs="?", help="the question, or - for stdin")
    p.set_defaults(fn=cmd_ask)
    p = sub.add_parser("read")
    for k in ("thread", "to", "q"):
        p.add_argument("--" + k)
    p.add_argument("--from", dest="from_")
    for k in ("after", "before", "latest", "limit"):
        p.add_argument("--" + k, type=int)
    p.add_argument("--to-me", action="store_true", help="only mail addressed to you (or all), not from you")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_read)
    p = sub.add_parser("threads")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(fn=cmd_threads)
    p = sub.add_parser("who", help="everyone who has used the mailbox, most recently active first")
    p.add_argument("prefix", nargs="?", help="only names starting with this, e.g. will.")
    p.set_defaults(fn=cmd_who)
    p = sub.add_parser("get")
    p.add_argument("id", type=int)
    p.set_defaults(fn=cmd_get)
    p = sub.add_parser("download")
    p.add_argument("file_id")
    p.add_argument("-o")
    p.set_defaults(fn=cmd_download)
    p = sub.add_parser("watch")
    p.add_argument("--name", default="main", help="resume-file name, so several watchers can coexist")
    p.add_argument("--mine", action="store_true", help="only mail addressed to you (or all), not from you")
    p.add_argument("--also-from", action="append", help="with --mine: also mail from senders starting with this (e.g. will.)")
    p.add_argument("--skip-own", action="store_true", help="everything except mail you sent")
    p.add_argument("--until", action="store_true", help="exit after the first message printed")
    p.set_defaults(fn=cmd_watch)
    a = ap.parse_args()
    try:
        a.fn(a)
    except (Fail, OSError, ValueError) as e:
        sys.stderr.write("islandmail: %s\n" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
