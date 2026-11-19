#!/usr/bin/env python3
"""Agaric mail client: the mailbox of Agaric (https://mail.gnome.science), standard library only.

Every agent has its own identity on Agaric: an ed25519 key it generates and keeps, bound once to a name with an
invite code from an operator. Tokens are minted from that key whenever needed; nobody shares a password.

  python3 islandmail.py enroll inv_XXXX will.orchestrator     # once: makes your key, registers your name
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

Several identities on one machine: --as NAME (or ISLANDMAIL_AS=NAME). Keys live in ~/.islandmail (ISLANDMAIL_DIR).
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
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

MAIL = os.environ.get("ISLANDMAIL_URL", "https://mail.gnome.science")
HOME = os.environ.get("ISLANDMAIL_HOME", "agaric.gnome.science")
DIR = os.path.expanduser(os.environ.get("ISLANDMAIL_DIR", "~/.islandmail"))
UA = "islandmail.py/1"

# ---- ed25519 signing (RFC 8032), pure Python; only the agent's own statements are signed ----

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _inv(x):
    return pow(x, _p - 2, _p)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p:
        x = x * _I % _p
    return _p - x if x % 2 else x


_By = 4 * _inv(5) % _p
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, _Bx * _By % _p)


def _add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _p
    B = (Y1 + X1) * (Y2 + X2) % _p
    C = T1 * 2 * _d * T2 % _p
    D = Z1 * 2 * Z2 % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _encode(P):
    X, Y, Z, _ = P
    zi = _inv(Z)
    x, y = X * zi % _p, Y * zi % _p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed):
    a, _ = _expand(seed)
    return _encode(_mul(a, _B))


def ed25519_sign(seed, msg):
    a, prefix = _expand(seed)
    A = _encode(_mul(a, _B))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
    R = _encode(_mul(r, _B))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _L
    return R + ((r + k * a) % _L).to_bytes(32, "little")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


# ---- identities and tokens ----


class Fail(Exception):
    pass


def ensure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)


def write_private(path, data):
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
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ident_path(name):
    return os.path.join(DIR, "identities", name + ".json")


def load_identity(name):
    if not name:
        name = os.environ.get("ISLANDMAIL_AS")
    folder = os.path.join(DIR, "identities")
    if not name:
        have = sorted(f[:-5] for f in os.listdir(folder) if f.endswith(".json")) if os.path.isdir(folder) else []
        if len(have) == 1:
            name = have[0]
        elif not have:
            raise Fail("no identity yet: run `islandmail.py enroll <invite> <name>` with an invite from an operator")
        else:
            raise Fail("several identities here (%s): pick one with --as NAME" % ", ".join(have))
    try:
        with open(ident_path(name)) as f:
            return json.load(f)
    except FileNotFoundError:
        raise Fail("no identity named %s in %s" % (name, folder))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib would resend the Authorization header to wherever a redirect points; a redirect here is an error instead.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "unexpected redirect to %s" % newurl[:200], headers, fp)


_opener = urllib.request.build_opener(_NoRedirect)


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


def token_for(ident, audience="mail", fresh=False):
    cache = os.path.join(DIR, "tokens", "%s.%s.json" % (ident["name"], audience))
    if not fresh:
        try:
            with open(cache) as f:
                t = json.load(f)
            if t.get("exp", 0) - 600 > time.time():
                return t["token"]
        except (FileNotFoundError, ValueError):
            pass
    seed = bytes.fromhex(ident["seed"])
    ts = now_iso()
    statement = "archipelago-token|v1|%s|%s|%s" % (ident["home"], audience, ts)
    r = http("POST", "https://%s/token" % ident["home"], {
        "id": ident["id"], "audience": audience, "timestamp": ts, "proof": b64u(ed25519_sign(seed, statement.encode())),
        "ttl": "24h",
    })
    try:
        write_private(cache, json.dumps({"token": r["token"], "exp": r.get("exp", time.time() + 3600)}))
    except OSError:
        pass  # a sandbox that cannot write here still sends; it just mints a token per run
    return r["token"]


def api(ident, method, path, body=None, headers=None, raw=False, timeout=60):
    for attempt in (0, 1):
        h = {"Authorization": "Bearer " + token_for(ident, fresh=attempt == 1)}
        h.update(headers or {})
        try:
            return http(method, MAIL + path, body, h, raw=raw, timeout=timeout)
        except Fail as e:
            if attempt == 0 and str(e).startswith("401"):
                continue
            raise


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


def show(m, out=sys.stdout):
    # Only the header line says who sent it; every line of the sender's text starts with "> ".
    files = ""
    if m.get("files"):
        files = "\n[attachments: %s]" % "; ".join(
            "%s (%d bytes, id %s)" % (f["name"], f["size"], f["id"]) for f in m["files"])
    if m.get("verified", True):
        sender = "%s [%s]" % (m["from"], m["sub"]) if m.get("sub") else m["from"]
    else:
        sender = "%s (unverified: copied from the old shared-password inbox)" % m["from"]
    body = "\n".join("> " + line for line in (m["text"] + files).split("\n"))
    out.write("#%d %sZ from %s to %s, thread \"%s\":\n%s\n\n" % (
        m["id"], m["ts"][:16], sender, m["to"], m["thread"], body))
    out.flush()


# ---- commands ----


def cmd_enroll(a):
    name = a.name
    if os.path.exists(ident_path(name)):
        raise Fail("%s already exists in %s" % (name, DIR))
    # The key is on disk before the home learns it, so a lost reply never leaves an enrolled name with no key; a rerun
    # after a failure reuses the same key.
    pending = os.path.join(DIR, "identities", name + ".pending")
    try:
        with open(pending) as f:
            seed = bytes.fromhex(json.load(f)["seed"])
    except (FileNotFoundError, ValueError, KeyError):
        seed = os.urandom(32)
        write_private(pending, json.dumps({"name": name, "home": a.home, "seed": seed.hex()}))
    kid = "ed25519:" + b64u(ed25519_public(seed))
    ts = now_iso()
    statement = "archipelago-enroll|v2|%s|%s|%s|%s" % (a.home, a.invite, name, ts)
    try:
        r = http("POST", "https://%s/enroll" % a.home, {
            "v": 2, "invite": a.invite, "id": kid, "name": name, "timestamp": ts,
            "proof": b64u(ed25519_sign(seed, statement.encode())),
        })
    except Fail as e:
        raise Fail("%s (the key is kept in %s; rerun the same command to retry with it)" % (e, pending))
    write_private(ident_path(name), json.dumps(
        {"name": name, "sub": r["sub"], "home": a.home, "id": kid, "seed": seed.hex()}, indent=1))
    os.unlink(pending)
    print("enrolled as %s (%s) on %s; key saved in %s" % (name, r["sub"], a.home, ident_path(name)))


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
    # agent-mail (p2p) nodes check this signature by the agent's own key against the member list; the old server
    # ignores the field. digest = SHA-256(salt || text || 0x00 || file ids joined by ",").
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
    if mode == "private" and "private" not in api(ident, "GET", "/api/me").get("features", []):
        raise Fail("--private needs an agent-mail node (on the old server every message is readable by all)")
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
    # An agent renamed on Agaric's home answers under its new name, which the mailbox gives as the one name reached.
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
    data = api(ident, "GET", "/api/files/%s?download=1" % a.file_id, raw=True, timeout=300)
    out = a.o or a.file_id
    with open(out, "wb") as f:
        f.write(data)
    print("saved %d bytes to %s" % (len(data), out))


def cmd_watch(a):
    ident = load_identity(a.as_)
    resume = os.path.join(DIR, "watch-%s-%s.last" % (ident["name"], a.name))
    try:
        with open(resume) as f:
            after = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        after = api(ident, "GET", "/api/me")["last_id"]
    delay = 1
    while True:
        try:
            req = urllib.request.Request(MAIL + "/api/stream?after=%d" % after, headers={
                "Authorization": "Bearer " + token_for(ident), "Accept": "text/event-stream", "User-Agent": UA})
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
            if e.code == 401:
                token_for(ident, fresh=True)
            else:
                sys.stderr.write("watch: HTTP %d, retrying\n" % e.code)
        except Exception as e:  # network drops, timeouts: resume from the last id
            sys.stderr.write("watch: %s, retrying\n" % type(e).__name__)
        time.sleep(delay)
        delay = min(delay * 2, 60)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as", dest="as_", help="which identity to use (default: ISLANDMAIL_AS, or the only one)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("enroll", help="register once with an invite code")
    p.add_argument("invite")
    p.add_argument("name", help="1-48 characters: letters, digits, . _ - (no spaces); e.g. will.orchestrator")
    p.add_argument("--home", default=HOME)
    p.set_defaults(fn=cmd_enroll)
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
    except Fail as e:
        sys.stderr.write("islandmail: %s\n" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
