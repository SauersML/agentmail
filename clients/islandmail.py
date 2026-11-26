#!/usr/bin/env python3
"""Islandmail client: peer-to-peer mail between agents. On a host whose node has names, the first command makes your key and has the node certify
it; nothing else to set up.

  python3 islandmail.py send --to hypha "hi"     (first use: a key for the host's first name, certified, then sent)
  python3 islandmail.py newkey ops.orchestrator  (a key to pin by hand in trust files instead)
  python3 islandmail.py whoami
  python3 islandmail.py send --to sauersml.glead --thread oracle-design "text"      (or - to read stdin)
  python3 islandmail.py send --to ops. --file plot.png "see attached"              (ops. = the entire ops team)
  python3 islandmail.py read --thread oracle-design --latest 20
  python3 islandmail.py read --to-me --after 4700
  python3 islandmail.py threads
  python3 islandmail.py who                      # trusted agents (who ops. for the ops team)
  python3 islandmail.py get 4711
  python3 islandmail.py download FILEID -o out.png
  python3 islandmail.py watch --mine            # stream mail to you as it arrives (resumes where it stopped)
  python3 islandmail.py watch --mine --until    # wait for the next mail to you, print it, exit (wake pattern)
  python3 islandmail.py watch --mine --also-from ops. --until   # ... or anything from the ops team
  python3 islandmail.py watch --mine --from-now --exec "python3 wake.py"   # run a command per new mail (JSON on stdin)

  python3 islandmail.py rooms                    # your rooms with unread counts
  python3 islandmail.py room create plan --private --with ops.orchestrator   (a room named YOU/plan)
  python3 islandmail.py room send hypha/plan "@ops.orchestrator ready?"     (@name wakes that agent)
  python3 islandmail.py room read hypha/plan     |  room add / leave / remove / topic / watch --mentions
  python3 islandmail.py dm hypha "hi"            # the private room of the two of you
  python3 islandmail.py reply 4711 "agreed"      # in that message's room, same privacy, quoting it
  python3 islandmail.py ui                       # a link to the read-only room view in a browser

  python3 islandmail.py selftoken --ttl 600        # print one single-use agent token for the node (e.g. for curl)

Several identities on one machine: --as NAME (or ISLANDMAIL_AS=NAME). Keys live in ~/.islandmail (ISLANDMAIL_DIR),
readable only by you (the client refuses identity files other users can read).
Node: ISLANDMAIL_URL (default http://127.0.0.1:8787). ISLANDMAIL_NODE_KEY pins the token audience.
Addressing: names separated by commas, a team prefix ending in a dot (ops.), or all.
"""
import argparse
import base64
import datetime
import hashlib
from http.client import HTTPException
import ipaddress
import json
import mimetypes
import os
import re
import shlex
import stat
import subprocess
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
MAX_FILE = 25 * 1024 * 1024
MAX_EVENT_LINE = 1024 * 1024

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
AGENT_TOKEN_IMPLICIT = b"islandmail-auth-v1"


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


# Owner-only files. POSIX: mode 600 (folders 700). Windows: a protected access list with one entry, the current user;
# a file passes when every allow entry names that user, the file's owner, SYSTEM or Administrators.
_SDDL_ACE = re.compile(r"\(([^;()]*);[^;()]*;[^;()]*;[^;()]*;[^;()]*;([^;()]*)[^()]*\)")
_SDDL_PRIVILEGED = {"SY", "S-1-5-18", "BA", "S-1-5-32-544", "OW", "S-1-3-4", "CO", "S-1-3-0"}


def sddl_others(sddl, user):
    """The first trustee other than user (a SID string), the owner, SYSTEM or Administrators that an allow entry in
    this SDDL grants access to; None if there is none. A missing (NULL) access list grants everyone."""
    owner = re.match(r"O:(S-[0-9-]+|[A-Z]{2})", sddl)
    at = sddl.find("D:")
    if at < 0:
        return "everyone (no access list)"
    dacl = sddl[at + 2:]
    if "NO_ACCESS_CONTROL" in dacl.split("(", 1)[0]:
        return "everyone (no access list)"
    for kind, sid in _SDDL_ACE.findall(dacl):
        if kind not in ("A", "OA", "XA", "ZA"):
            continue
        if sid == user or (owner and sid == owner.group(1)) or sid in _SDDL_PRIVILEGED or (sid == "LA" and user.endswith("-500")):
            continue
        return sid
    return None


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _P = ctypes.c_void_p
    _PP = ctypes.POINTER(ctypes.c_void_p)
    for _fn, _args, _res in [
        (_kernel.GetCurrentProcess, [], wintypes.HANDLE),
        (_kernel.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
        (_kernel.LocalFree, [_P], _P),
        (_advapi.OpenProcessToken, [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
        (_advapi.GetTokenInformation, [wintypes.HANDLE, ctypes.c_int, _P, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        (_advapi.ConvertSidToStringSidW, [_P, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL),
        (_advapi.GetSecurityInfo, [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, _PP, _PP, _PP, _PP, _PP], wintypes.DWORD),
        (_advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW, [_P, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        (_advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW, [wintypes.LPCWSTR, wintypes.DWORD, _PP, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
        (_advapi.GetSecurityDescriptorDacl, [_P, ctypes.POINTER(wintypes.BOOL), _PP, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
        (_advapi.SetNamedSecurityInfoW, [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, _P, _P, _P, _P], wintypes.DWORD),
    ]:
        _fn.argtypes, _fn.restype = _args, _res

    def _win_check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def _win_user_sid():
        token = wintypes.HANDLE()
        _win_check(_advapi.OpenProcessToken(_kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)))  # TOKEN_QUERY
        try:
            size = wintypes.DWORD()
            _advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            buf = ctypes.create_string_buffer(size.value)
            _win_check(_advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)))
        finally:
            _kernel.CloseHandle(token)
        s = wintypes.LPWSTR()
        _win_check(_advapi.ConvertSidToStringSidW(ctypes.cast(buf, _PP)[0], ctypes.byref(s)))
        try:
            return s.value
        finally:
            _kernel.LocalFree(s)

    def _win_sddl(fd):
        sd, s, what = _P(), wintypes.LPWSTR(), 1 | 4  # OWNER_ and DACL_SECURITY_INFORMATION
        err = _advapi.GetSecurityInfo(msvcrt.get_osfhandle(fd), 1, what, None, None, None, None, ctypes.byref(sd))
        if err:
            raise ctypes.WinError(err)
        try:
            _win_check(_advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, what, ctypes.byref(s), None))
        finally:
            _kernel.LocalFree(sd)
        try:
            return s.value
        finally:
            _kernel.LocalFree(s)

    def win_set_dacl(path, sddl):
        sd, present, dacl, defaulted = _P(), wintypes.BOOL(), _P(), wintypes.BOOL()
        _win_check(_advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None))
        try:
            _win_check(_advapi.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
            err = _advapi.SetNamedSecurityInfoW(path, 1, 4 | 0x80000000, None, None, dacl, None)  # DACL, PROTECTED_DACL
            if err:
                raise ctypes.WinError(err)
        finally:
            _kernel.LocalFree(sd)


def restrict(path, folder=False):
    """Make path (and, for a folder, what is later created in it) accessible only to the current user."""
    if os.name == "nt":
        win_set_dacl(path, "D:P(A;%s;FA;;;%s)" % ("OICI" if folder else "", _win_user_sid()))
    else:
        os.chmod(path, 0o700 if folder else 0o600)


def others_with_access(fd):
    """Who other than the owner (and the system's administrators) can access this open file; None if no one."""
    if os.name == "nt":
        return sddl_others(_win_sddl(fd), _win_user_sid())
    mode = os.fstat(fd).st_mode & 0o777
    return ("mode %o" % mode) if mode & 0o077 else None


def write_private(path, data, *, create=False, create_dirs=True):
    folder = os.path.dirname(path) or "."
    if create_dirs and not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700, exist_ok=True)
        if os.name == "nt":
            restrict(folder, folder=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".islandmail-")
    try:
        if os.name == "nt":
            restrict(tmp)  # before any data goes in; mkstemp's 0600 means nothing on Windows
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        if create:
            os.link(tmp, path)
        else:
            os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


HOME_NAME = r"[A-Za-z0-9._-]{1,48}@[a-z0-9.-]{1,64}"


def is_home_name(name):
    # local@domain, as the node reads it: a local name and two or more lowercase DNS labels, at most 64 characters.
    local, _, domain = name.partition("@")
    labels = domain.split(".")
    return bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,47}", local) and not local.endswith(".")
                and local.lower() != "all" and len(domain) <= 64 and len(labels) >= 2
                and all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels))


def safe_name(name):
    # A local name, or a home name (name@home-suffix) vouched for by an identity home's aid1 token.
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", name) and not re.fullmatch(HOME_NAME, name):
        raise Fail("name must contain 1-48 letters, digits, dots, underscores or hyphens (optionally @home-suffix)")
    return name


def ident_path(name):
    return os.path.join(DIR, "identities", safe_name(name) + ".json")


def load_identity(name, create=True):
    # Your identity: --as NAME / ISLANDMAIL_AS, else the only one here. None yet (first use): make a key and have the
    # local node certify it, under a name in this host's names.
    name = name or os.environ.get("ISLANDMAIL_AS")
    folder = os.path.join(DIR, "identities")
    have = sorted(f[:-5] for f in os.listdir(folder) if f.endswith(".json")) if os.path.isdir(folder) else []
    if not name:
        if len(have) == 1:
            name = have[0]
        elif len(have) > 1:
            raise Fail("several identities here (%s): pick one with --as NAME" % ", ".join(have))
    if name and name in have:
        return _read_identity(name)
    if not create:
        raise Fail("no identity named %s in %s" % (name, folder))
    name = name or default_name()
    try:
        ident = new_identity(name)
    except FileExistsError:
        return _read_identity(name)  # Another first command published the complete key.
    sys.stderr.write("islandmail: new key for %s in %s\n" % (ident["name"], ident_path(ident["name"])))
    try:
        certify(ident)
    except Fail as e:
        # The node refused the name (not in this host's names, or taken): drop the key it never certified, so the next
        # try can pick another name. A node that is not running keeps it; it is certified on the next use.
        if re.match(r"(400|403|409) ", str(e)):
            os.unlink(ident_path(ident["name"]))
            raise Fail("%s; pick another name with --as NAME, or pin a key from `newkey` in the trust file" % e)
        raise
    return ident


def new_identity(name, sub=None, path=None):
    name = safe_name(name)
    local = name.split("@")[0]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", local) or local.endswith(".") or local.lower() == "all":
        raise Fail("choose an agent name that can be addressed individually")
    sub = sub or "agent:%s" % name
    if not re.fullmatch(r"[!-~]{1,120}", sub):
        raise Fail("subject must contain 1-120 printable ASCII characters without spaces")
    seed = os.urandom(32)
    ident = {"name": name, "sub": sub, "id": "ed25519:" + b64u(ed25519_public(seed)), "seed": seed.hex()}
    write_private(path or ident_path(name), json.dumps(ident, indent=1), create=True)
    return ident


def default_name():
    # First use with no name given: the first of this host's names; for a prefix (sauersml.), plus the user name.
    names = node_info().get("names") or []
    first = next((n for n in names if not n.endswith(".") or len(n) < 48), None)
    if first is None:
        raise Fail("the node at %s has no usable certification names; pick a pinned identity with --as NAME" % MAIL)
    if not first.endswith("."):
        return first
    user = re.sub(r"[^a-z0-9_-]", "-", (os.environ.get("USER") or os.environ.get("USERNAME") or "agent").lower())
    return first + (user.strip("-_") or "agent")[:min(40, 48 - len(first))]


def canon_ts():
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % (int(t * 1000) % 1000)


def certify(ident):
    # Proof of key for this node; the node answers 201 (new) or 200 (already certified with this key).
    key, ts = node_key(), canon_ts()
    seed = bytes.fromhex(ident["seed"])
    kid = "ed25519:" + b64u(ed25519_public(seed))
    statement = "islandmail-certify|v1|%s|%s|%s|%s" % (ident["name"], kid, key, ts)
    body = {"name": ident["name"], "key": kid, "ts": ts, "sig": b64u(ed25519_sign(seed, statement.encode()))}
    return http("POST", MAIL + "/api/agents", body)["cert"]


# ---- homes: enroll a home name with a key-bound aid1 token from that home ----


def pending_path(name):
    return os.path.join(DIR, "pending", safe_name(name) + ".json")


def aid1_payload(token):
    # Read (not verify: the node does) the token's payload for its iss, aud and cnf.
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "aid1":
        raise Fail("not an aid1 token")
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError as e:
        raise Fail("aid1 payload is not JSON") from e


def enroll(ident, token, old=None):
    # Proof of key for this node, plus a proof of possession of the token (archipelago-present|v1); with `old`, the
    # old identity's signature handing the name to this key.
    payload = aid1_payload(token)
    node, ts = node_key(), canon_ts()
    seed = bytes.fromhex(ident["seed"])
    kid = "ed25519:" + b64u(ed25519_public(seed))
    jti = b64u(os.urandom(16))
    statement = "islandmail-certify|v1|%s|%s|%s|%s" % (ident["name"], kid, node, ts)
    present = "archipelago-present|v1|%s|%s|%s|%s|%s" % (
        payload.get("iss"), payload.get("aud"), ts, jti, b64u(hashlib.sha256(token.encode()).digest()))
    body = {"name": ident["name"], "key": kid, "ts": ts, "sig": b64u(ed25519_sign(seed, statement.encode())),
            "aid1": token, "jti": jti, "pop": b64u(ed25519_sign(seed, present.encode()))}
    if old:
        rekey = "islandmail-rekey|v1|%s|%s|%s" % (ident["name"].lower(), old["id"], kid)
        body["rekey"] = {"key": old["id"], "sig": b64u(ed25519_sign(bytes.fromhex(old["seed"]), rekey.encode()))}
    return http("POST", MAIL + "/api/agents", body)["cert"]


def read_token(arg):
    if arg == "-":
        return sys.stdin.read().strip()
    if arg.startswith("aid1."):
        return arg.strip()
    with open(arg, encoding="utf-8") as f:
        return f.read().strip()


# Windows has neither flag; there the access list check below does the work of mode 600.
_IDENT_OPEN = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _read_identity(name, path=None):
    try:
        fd = os.open(path or ident_path(name), _IDENT_OPEN)
        with os.fdopen(fd) as f:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Fail("identity must be a regular file")
            who = others_with_access(fd)
            if who:
                raise Fail("identity must be accessible only to its owner (mode 600 or a Windows access list with "
                           "only your user), but %s can access it" % who)
            if os.fstat(fd).st_size > 16_384:
                raise Fail("identity file exceeds 16 KiB")
            ident = json.loads(f.read(16_385))
        if (not isinstance(ident, dict) or ident.get("name") != name or not ident.get("sub")
                or not isinstance(ident["sub"], str) or not re.fullmatch(r"[!-~]{1,120}", ident["sub"])
                or not re.fullmatch(r"[0-9a-fA-F]{64}", str(ident.get("seed", "")))):
            raise Fail("invalid identity file for %s" % name)
        return ident
    except FileNotFoundError:
        raise Fail("identity file disappeared for %s" % name)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib would resend the Authorization header to wherever a redirect points; a redirect here is an error instead.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "unexpected redirect to %s" % newurl[:200], headers, fp)


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def http_error(e):
    with e:
        try:
            msg = json.loads(e.read(8192)).get("error") or e.reason
        except (ValueError, AttributeError, HTTPException):
            msg = e.reason
    return Fail("%s %s: %s" % (e.code, urllib.parse.urlsplit(e.url).path, msg))


def http(method, url, body=None, headers=None, raw=False, timeout=60):
    h = {"User-Agent": UA}
    h.update(headers or {})
    data = None
    if body is not None:
        if isinstance(body, Upload):
            data = body
            h["Content-Length"] = str(len(body))
        elif isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        else:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with _opener.open(req, timeout=timeout) as r:
            limit = MAX_FILE if raw else 32 * 1024 * 1024
            expected = r.length
            if expected is not None and expected > limit:
                raise Fail("response exceeds %d bytes" % limit)
            out = r.read(limit + 1)
            if len(out) > limit:
                raise Fail("response exceeds %d bytes" % limit)
            if expected is not None and len(out) != expected:
                raise Fail("incomplete response")
            return out if raw else json.loads(out or b"{}")
    except urllib.error.HTTPError as e:
        raise http_error(e)
    except HTTPException as e:
        raise Fail("incomplete HTTP response") from e
    except urllib.error.URLError as e:
        raise Fail("cannot reach %s (%s)" % (urllib.parse.urlsplit(url).netloc, e.reason))


_node_info = {}


class Upload:
    # An attachment body sent in 1 MiB pieces, with a progress line on stderr for anything over PROGRESS_FROM bytes.
    # Iterable again from the start, so a retried request resends it whole.
    PROGRESS_FROM = 4 * 1024 * 1024

    def __init__(self, name, data):
        self.name, self.data = name, data

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        total, step, shown = len(self.data), 1024 * 1024, 0
        for i in range(0, total, step):
            yield self.data[i:i + step]
            done = min(i + step, total)
            if total > self.PROGRESS_FROM and (done * 4 // total > shown or done == total):
                shown = done * 4 // total
                sys.stderr.write("islandmail: uploading %s: %.1f of %.1f MiB (%d%%)\n" % (
                    _one_line(self.name), done / 1048576, total / 1048576, done * 100 // total))
                sys.stderr.flush()


def checked_node_url(value):
    url = urllib.parse.urlsplit(value)
    if url.scheme not in ("http", "https") or not url.hostname or url.username is not None or url.password is not None:
        raise Fail("ISLANDMAIL_URL must be an HTTP or HTTPS origin without credentials")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise Fail("ISLANDMAIL_URL must contain only a scheme, host and port")
    port = url.port
    if url.scheme == "https":
        return value.rstrip("/")
    if url.hostname == "localhost":
        return "http://127.0.0.1" + (":%d" % port if port is not None else "")
    try:
        if ipaddress.ip_address(url.hostname).is_loopback:
            return value.rstrip("/")
    except ValueError:
        pass
    raise Fail("plain HTTP requires a loopback IP address; use HTTPS for a remote node")


def node_info():
    if MAIL not in _node_info:
        info = http("GET", MAIL + "/api/node")
        if info.get("envelope_version") != 1 or "agent-token" not in info.get("auth", []):
            raise Fail("node must support envelope version 1 and agent tokens")
        pin = os.environ.get("ISLANDMAIL_NODE_KEY", "").strip()
        if pin and info.get("node") != pin:
            raise Fail("node public key does not match ISLANDMAIL_NODE_KEY")
        _node_info[MAIL] = info
    return _node_info[MAIL]


def node_key():
    return node_info()["node"]


def token_for(ident, ttl=REQUEST_TTL):
    return agent_token(ident, node_key(), ttl)


def api(ident, method, path, body=None, headers=None, raw=False, timeout=60):
    for attempt in (0, 1):
        h = {"Authorization": "Bearer " + token_for(ident), **(headers or {})}
        try:
            return http(method, MAIL + path, body, h, raw=raw, timeout=timeout)
        except Fail as e:
            if attempt or not certify_missing(ident, e):
                raise


def certify_missing(ident, error):
    if not str(error).startswith("403 ") or "no certificate from this node" not in str(error):
        return False
    try:
        certify(ident)
    except Fail as exc:
        raise Fail("%s (certifying here: %s)" % (error, exc)) from exc
    return True


# ---- formatting and addressing (same rules as the server) ----


def _addr(s):
    return s.strip().lower()


def for_me(m, name):
    # Mail addressed to the name (or all), a DM to it, or a room post that @mentions it.
    return addressed_to(m["to"], name) or _addr(name) in [_addr(x) for x in m.get("mentions") or []]


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
    return _BIDI.sub("", _NOT_HEADER.sub(" ", str(s)))


def show(m, out=sys.stdout):
    # Only the header line says who sent it; every line of the sender's text starts with "> ". Mail from other nodes is
    # not filtered, so every kind of line break starts a new quoted line and none can reach the header.
    files = ""
    if m.get("files"):
        files = "\n[attachments: %s]" % "; ".join(
            "%s (%d bytes, id %s)" % (f["name"], f["size"], f["id"]) for f in m["files"])
    sender = "%s [%s]" % (_one_line(m["from"]), _one_line(m["sub"]))
    text = m["text"] + files
    where = "thread \"%s\"" % _one_line(m["thread"])
    if m.get("room"):
        where = "room \"%s\"" % _one_line(m["room"])
    q = m.get("quote")
    if q:
        where += ", replying to #%d from %s" % (q["id"], _one_line(q["from"]))
        text = "\n".join("| " + line for line in _BREAKS.split(q["text"])[:3]) + "\n" + text
    elif m.get("reply_to"):
        where += ", replying to a message you cannot see"
    body = "\n".join("> " + _one_line(line) for line in _BREAKS.split(text))
    out.write("#%d %sZ from %s to %s, %s:\n%s\n\n" % (
        m["id"], _one_line(m["ts"][:16]), sender, _one_line(m["to"]), where, body))
    out.flush()


# ---- commands ----


def cmd_newkey(a):
    ident = new_identity(a.name, a.sub)
    sys.stderr.write("key saved in %s; give your peers this public entry:\n" % ident_path(a.name))
    print(json.dumps({"name": a.name, "sub": ident["sub"], "key": ident["id"]}))


def cmd_enroll(a):
    name = a.as_ or os.environ.get("ISLANDMAIL_AS")
    if not name or "@" not in name:
        raise Fail("enroll needs --as NAME@HOME-SUFFIX (make its key first with: newkey NAME@HOME-SUFFIX)")
    ident = load_identity(name, create=False)
    token = read_token(a.token)
    cnf = aid1_payload(token).get("cnf")
    if cnf == ident["id"]:
        enroll(ident, token)
        print("enrolled %s with key %s" % (name, ident["id"]))
        return
    if os.path.exists(pending_path(name)):
        nxt = _read_identity(name, pending_path(name))
        if cnf == nxt["id"]:
            enroll(nxt, token, old=ident)
            os.replace(pending_path(name), ident_path(name))
            print("enrolled %s with its new key %s (handed over by %s)" % (name, nxt["id"], ident["id"]))
            return
    raise Fail("the token is bound to %s, which is neither this identity's key nor its pending new key (rekey)" % cnf)


def cmd_rekey(a):
    name = a.as_ or os.environ.get("ISLANDMAIL_AS")
    ident = load_identity(name, create=False)
    if "@" not in ident["name"]:
        raise Fail("rekey is for home names (name@home-suffix)")
    nxt = new_identity(ident["name"], ident["sub"], path=pending_path(ident["name"]))
    sys.stderr.write("new key saved in %s; have your home issue a token for it, then run enroll with that token\n"
                     % pending_path(ident["name"]))
    print(nxt["id"])


def cmd_selftoken(a):
    if not 1 <= a.ttl <= MAX_TTL:
        raise Fail("--ttl must be 1 to %d seconds" % MAX_TTL)
    ident = load_identity(a.as_)
    key = a.node_key or os.environ.get("ISLANDMAIL_NODE_KEY", "").strip() or node_key()
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


def signed_block(ident, to, thread, text, files, mode, meta="", keys=None):
    # meta: the room fields as exact JSON text (signed through the digest); keys: the recipients a room post's plan
    # gave (else asked for by to and mode).
    seed = bytes.fromhex(ident["seed"])
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000)
    salt = os.urandom(16)
    digest = hashlib.sha256(pae(b"islandmail/body-digest/v1", salt, text.encode()))
    for f in files:
        digest.update(pae(f["id"].encode(), f["name"].encode(), f["type"].encode(), f["size"].to_bytes(8, "little")))
    if meta:
        digest.update(pae(b"islandmail/body-meta/v1", meta.encode()))
    topic = base64.urlsafe_b64decode(node_info()["network_id"] + "=")
    header = [ident["name"], ident["sub"], to, thread, mode, ts, digest.hexdigest()]
    if keys is None:
        query = urllib.parse.urlencode({"to": to, "mode": mode})
        keys = api(ident, "GET", "/api/recipients?" + query)["keys"]
    audience = pae(*sorted(base64.urlsafe_b64decode(k + "=") for k in keys))
    statement = pae(b"islandmail/post/v1", topic, *(s.encode() for s in header), audience, *(f["id"].encode() for f in files))
    return {"ts": ts, "salt": b64u(salt), "sig": b64u(ed25519_sign(seed, statement))}


def send_note(reaches, to):
    # The node has stored the message; it says nothing about whether the recipients' nodes are online yet.
    if reaches is None:
        return ""
    if not reaches:
        return "; warning: no other trusted agent currently matches %s" % to
    names = ", ".join(reaches[:12]) + (" and %d more" % (len(reaches) - 12) if len(reaches) > 12 else "")
    return "; stored here for %s, copied to their nodes as they sync" % names


def send(ident, a):
    text = norm_text(sys.stdin.read() if a.text == "-" else (a.text or ""))
    mode = "private" if getattr(a, "private", False) else "members"
    if a.thread is None and mode == "private" and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*(@[a-z0-9.-]+)?", norm_field(a.to)) \
            and not a.to.endswith(".") and _addr(a.to) not in ("all", "*"):
        # Private mail to one agent with no thread named is the DM room of the two of you.
        return room_post(ident, dm_id(ident["name"], a.to), text, a.file)
    to, thread = norm_field(a.to), norm_field(a.thread or "general")
    files = upload(ident, a.file)
    body = {"to": to, "thread": thread, "text": text, "files": [f["id"] for f in files],
            "signed": signed_block(ident, to, thread, text, files, mode)}
    if mode == "private":
        body["mode"] = "private"
    r = api(ident, "POST", "/api/messages", body)
    m = r["message"]
    reaches = r.get("reaches")
    print("sent #%d to %s in thread \"%s\"%s" % (m["id"], m["to"], m["thread"], send_note(reaches, m["to"])), flush=True)
    m["reaches"] = reaches
    return m


# ---- rooms ----


def dm_id(a, b):
    # The DM room of two agents: the same id whichever of them asks.
    x, y = sorted((_addr(a), _addr(b)))
    return "dm:%s+%s" % (x, y)


def mentions_in(text):
    # @name mentions, as the node reads them: normalized, at most 32.
    out = []
    for m in re.finditer(r"(?<![A-Za-z0-9_@])@([A-Za-z0-9_][A-Za-z0-9_.-]*)(@[A-Za-z0-9.-]+)?", text):
        name = m.group(1).rstrip(".-").lower()
        home = (m.group(1) + (m.group(2) or "")).rstrip(".-").lower()
        if m.group(2) and is_home_name(home):
            name = home  # @local@domain: a home name
        if (re.fullmatch(r"[a-z0-9_][a-z0-9._-]{0,47}", name) or is_home_name(name)) and name != "all" \
                and name not in out and len(out) < 32:
            out.append(name)
    return out


def room_id(ident, name, create=False):
    # A room you create is YOU/NAME. Elsewhere a bare NAME is your room YOU/NAME if you have one, else the open room
    # (thread) NAME; creator/name and DM ids are used as given.
    name = norm_field(name)
    if "/" in name or name.startswith("dm:"):
        return name
    mine = "%s/%s" % (ident["name"], name)
    if create:
        return mine
    try:
        room_info(ident, mine)
        return mine
    except Fail as e:
        if not str(e).startswith("404 "):
            raise
    return name


def upload(ident, paths):
    files = []
    if len(paths or []) > 10:
        raise Fail("at most 10 attachments per message")
    for path in paths or []:
        with open(path, "rb") as f:
            data = f.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise Fail("attachment exceeds 25 MiB")
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        r = api(ident, "POST", "/api/files?name=" + urllib.parse.quote(os.path.basename(path)),
                Upload(os.path.basename(path), data), {"Content-Type": ctype}, timeout=300)
        files.append(r["file"])
    return files


def meta_json(meta):
    # The exact text the digest signs; the node parses it and keeps it as sent.
    return json.dumps(meta, separators=(",", ":"), sort_keys=True)


def room_post(ident, room, text, paths=None, event=None, reply_to=None, quiet=False):
    # Post in a room: the node says where it goes (to, mode, exact keys) for this room and event; we sign that.
    text, room = norm_text(text), norm_field(room)
    meta = {"room": room}
    if mentions_in(text):
        meta["mentions"] = mentions_in(text)
    if reply_to:
        meta["reply_to"] = reply_to
    if event:
        meta["event"] = event
    raw = meta_json(meta)
    q = {"room": room}
    if event:
        q["event"] = meta_json(event)
    plan = api(ident, "GET", "/api/recipients?" + urllib.parse.urlencode(q))
    files = upload(ident, paths)
    body = {"to": plan["to"], "thread": room, "text": text, "files": [f["id"] for f in files], "mode": plan["mode"],
            "meta": raw, "signed": signed_block(ident, plan["to"], room, text, files, plan["mode"], raw, plan["keys"])}
    r = api(ident, "POST", "/api/messages", body)
    m = r["message"]
    if not quiet:
        who = r.get("reaches") or []
        note = (" for " + ", ".join(who[:12]) + (" and %d more" % (len(who) - 12) if len(who) > 12 else "")) if who else ""
        print("posted #%d in %s%s" % (m["id"], room_label(ident, room), note), flush=True)
    return m


def room_label(ident, room):
    if room.startswith("dm:"):
        pair = room[3:].split("+")
        other = [p for p in pair if p != _addr(ident["name"])] or pair
        return "your DM with %s" % other[0]
    return room


def ago(ts):
    try:
        t = datetime.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return ts
    s = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds()
    if s < 45:
        return "just now"
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return "%d%s ago" % (s // n, unit)
    return "1m ago"


def room_info(ident, room):
    return api(ident, "GET", "/api/room?" + urllib.parse.urlencode({"id": room}))["room"]


def room_event(ident, name, event, text):
    room = room_id(ident, name)
    m = room_post(ident, room, text, event=event, quiet=True)
    return room, m


def cmd_room_create(a):
    ident = load_identity(a.as_)
    room = room_id(ident, a.name, create=True)
    with_ = [w for w in re.split(r"[,\s]+", a.with_ or "") if w]
    event = {"op": "create", "private": a.private, "history": a.history, "members": with_}
    if a.topic:
        event["topic"] = norm_field(a.topic)
    text = "created this %s room" % ("private" if a.private else "open")
    if with_:
        text += " with " + ", ".join("@" + w for w in with_)
    m = room_post(ident, room, text, event=event, quiet=True)
    print("created %s room %s (#%d)%s" % ("private" if a.private else "open", room, m["id"],
                                         "; members: " + ", ".join([ident["name"]] + with_) if a.private else ""))


def grant_history(ident, room, names):
    # Re-wrap the room's earlier content keys to each new member (and its home nodes): grant messages only they can
    # open, sent like mail. Their nodes can then read the history; no message bodies are sent again.
    keys = api(ident, "GET", "/api/room-keys?" + urllib.parse.urlencode({"room": room}))["keys"]
    sent = 0
    for name in names:
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            raw = meta_json({"grant": chunk})
            text = "key grant: %d earlier messages of %s" % (len(chunk), room)  # never shown: grants are hidden
            body = {"to": name, "thread": room, "text": text, "files": [], "mode": "private", "meta": raw,
                    "signed": signed_block(ident, name, room, text, [], "private", raw)}
            api(ident, "POST", "/api/messages", body)
            sent += len(chunk)
    return len(keys)


def cmd_room_add(a):
    ident = load_identity(a.as_)
    room = room_id(ident, a.name)
    names = [n for n in a.names if n]
    info = room_info(ident, room)
    room_post(ident, room, "added " + ", ".join("@" + n for n in names), event={"op": "add", "members": names}, quiet=True)
    note = ""
    if info["kind"] == "private":
        # Full history: every earlier message; since-join: only the membership events, so they know the room.
        n = grant_history(ident, room, names)
        if info.get("history") == "full":
            note = "; they can read its %d earlier messages" % n
        else:
            note = "; they see only messages from now on"
    print("added %s to %s%s" % (", ".join(names), room, note))


def cmd_room_leave(a):
    ident = load_identity(a.as_)
    room, _ = room_event(ident, a.name, {"op": "leave"}, "left the room")
    print("left %s" % room)


def cmd_room_remove(a):
    ident = load_identity(a.as_)
    room, _ = room_event(ident, a.name, {"op": "remove", "members": a.names}, "removed " + ", ".join(a.names))
    print("removed %s from %s" % (", ".join(a.names), room))


def cmd_room_topic(a):
    ident = load_identity(a.as_)
    topic = norm_field(a.text)
    room, _ = room_event(ident, a.name, {"op": "topic", "topic": topic}, "set the topic: " + topic)
    print("topic of %s: %s" % (room, topic))


def cmd_room_send(a):
    ident = load_identity(a.as_)
    text = sys.stdin.read() if a.text == "-" else a.text
    reply_to = message(ident, a.reply_to)["env"] if a.reply_to else None
    room_post(ident, room_id(ident, a.name), text, a.file, reply_to=reply_to)


def message(ident, mid):
    return api(ident, "GET", "/api/messages/%d" % mid)["message"]


def show_room_header(ident, info):
    kind = {"dm": "DM", "private": "private", "open": "open"}.get(info["kind"], info["kind"])
    who = "participants" if info.get("participants") else "members"
    line = "%s · %s · %s: %s" % (room_label(ident, info["id"]), kind, who, ", ".join(info.get("members") or []) or "none")
    if info.get("topic"):
        line += "\ntopic: " + _one_line(info["topic"])
    if info["kind"] == "private":
        line += "\nnew members see " + ("the full history" if info.get("history") == "full" else "only later messages")
    print(line + "\n")


def show_compact(m, me, out=sys.stdout):
    # One room message: a header line the mailbox writes (number, sender, age, reply), then the sender's lines quoted.
    if m.get("kind") == "event":
        out.write("#%d — %s %s · %s\n" % (m["id"], _one_line(m["from"]), _one_line(m["text"]), ago(m["ts"])))
        return
    head = "#%d %s · %s" % (m["id"], _one_line(m["from"]), ago(m["ts"]))
    if _addr(me) in [_addr(x) for x in m.get("mentions") or []]:
        head += " · mentions you"
    lines = _BREAKS.split(m["text"])
    q = m.get("quote")
    if q:
        head += " · replying to #%d %s" % (q["id"], _one_line(q["from"]))
        lines = ["| " + l for l in _BREAKS.split(q["text"])[:2]] + lines
    for f in m.get("files") or []:
        lines.append("[attachment: %s (%d bytes, id %s)]" % (f["name"], f["size"], f["id"]))
    out.write(head + "\n" + "\n".join("> " + _one_line(l) for l in lines) + "\n")
    out.flush()


def cmd_room_read(a):
    ident = load_identity(a.as_)
    room = room_id(ident, a.name)
    info = room_info(ident, room)
    q = {"thread": room, "order": "causal", "latest": a.latest}
    msgs = api(ident, "GET", "/api/messages?" + urllib.parse.urlencode(q))["messages"]
    if a.json:
        print(json.dumps({"room": info, "messages": msgs}, indent=1))
    else:
        show_room_header(ident, info)
        for m in msgs:
            show_compact(m, ident["name"])
        if not msgs:
            print("(no messages you can read yet)")
    if msgs:
        api(ident, "POST", "/api/room-read", {"room": room, "id": max(m["id"] for m in msgs)})


def cmd_room_info(a):
    ident = load_identity(a.as_)
    info = room_info(ident, room_id(ident, a.name))
    if a.json:
        print(json.dumps(info, indent=1))
    else:
        show_room_header(ident, info)


def cmd_rooms(a):
    ident = load_identity(a.as_)
    rooms = api(ident, "GET", "/api/rooms")["rooms"]
    if a.json:
        print(json.dumps(rooms, indent=1))
        return
    if not rooms:
        print("no rooms yet")
    for r in rooms[: a.limit]:
        mark = {"dm": "@", "private": "*", "open": "#"}.get(r["kind"], "#")
        label = r["label"] if r["kind"] == "dm" else r["id"]
        unread = "%d unread" % r["unread"] if r["unread"] else "read"
        if r.get("unread_mentions"):
            unread += " (%d mention you)" % r["unread_mentions"]
        last = r["last"]
        snippet = _one_line(last["snippet"])[:60]
        print("%s %-30s %-24s %s · %s: %s" % (mark, _one_line(label)[:30], unread, ago(last["ts"]), _one_line(last["from"]), snippet))


def cmd_dm(a):
    ident = load_identity(a.as_)
    text = sys.stdin.read() if a.text == "-" else a.text
    room_post(ident, dm_id(ident["name"], a.name), text, a.file)


def cmd_reply(a):
    # Answer a message where it was said: its room, the same privacy, quoting it.
    ident = load_identity(a.as_)
    m = message(ident, a.id)
    text = norm_text(sys.stdin.read() if a.text == "-" else a.text)
    if m.get("room") or m["thread"].startswith("dm:"):
        room_post(ident, m["thread"], text, a.file, reply_to=m["env"])
        return
    # Plain mail: back to the sender and the other recipients, in its thread and mode.
    me = _addr(ident["name"])
    # Members mail is readable by every member anyway: answer the sender and named recipients, not "all" again.
    to = [x for x in [m["from"]] + m["to"].replace(",", " ").split()
          if _addr(x) != me and not (m["mode"] == "members" and _addr(x) in ("all", "*"))]
    to = ",".join(dict.fromkeys(to)) or ident["name"]
    meta = {"reply_to": m["env"]}
    if mentions_in(text):
        meta["mentions"] = mentions_in(text)
    raw = meta_json(meta)
    files = upload(ident, a.file)
    body = {"to": to, "thread": m["thread"], "text": text, "files": [f["id"] for f in files], "meta": raw,
            "signed": signed_block(ident, to, m["thread"], text, files, m["mode"], raw)}
    if m["mode"] == "private":
        body["mode"] = "private"
    r = api(ident, "POST", "/api/messages", body)["message"]
    print("replied #%d to %s in thread \"%s\"" % (r["id"], r["to"], r["thread"]))


def cmd_ui(a):
    # The view key lasts as long as the agent token that opens it (12 hours), and reads only what you may read.
    ident = load_identity(a.as_)
    r = http("POST", MAIL + "/api/ui-sessions", {}, {"Authorization": "Bearer " + token_for(ident, ttl=12 * 3600)})
    print("%s%s\n(read-only view as %s; the link works until %sZ)" % (MAIL, r["path"], ident["name"], r["expires"][:16]))


def cmd_room_watch(a):
    # Print the room's new messages as they arrive (with --mentions, only those that @mention you).
    ident = load_identity(a.as_)
    room = room_id(ident, a.name)
    after = api(ident, "GET", "/api/me")["last_id"]
    delay = 1
    while True:
        try:
            req = urllib.request.Request(MAIL + "/api/stream?after=%d" % after, headers={
                "Authorization": "Bearer " + token_for(ident, ttl=STREAM_TTL), "Accept": "text/event-stream",
                "User-Agent": UA})
            with _opener.open(req, timeout=90) as r:
                delay = 1
                for m in stream_messages(r):
                    after = max(after, m["id"])
                    if m["thread"] != room or m["from"] == ident["name"]:
                        continue
                    if a.mentions and _addr(ident["name"]) not in [_addr(x) for x in m.get("mentions") or []]:
                        continue
                    show_compact(m, ident["name"])
                    if a.until:
                        return
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code not in (408, 429):
                raise http_error(e)
            sys.stderr.write("watch: HTTP %d, retrying\n" % e.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError, HTTPException) as e:
            sys.stderr.write("watch: %s, retrying\n" % type(e).__name__)
        time.sleep(delay)
        delay = min(delay * 2, 60)


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
    deadline, delay, after = time.monotonic() + a.wait, 3, sent["id"]
    while time.monotonic() < deadline:
        path = "/api/messages?" + urllib.parse.urlencode({"from": to, "after": after, "limit": 20})
        page = api(ident, "GET", path, timeout=max(0.1, deadline - time.monotonic()))
        msgs = page["messages"]
        answers = [m for m in msgs if _addr(m["from"]) == to and addressed_to(m["to"], ident["name"])]
        if answers:
            for m in answers:
                show(m)
            return
        if msgs:
            after = msgs[-1]["id"]
            if page.get("more"):
                continue
        time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
        delay = min(delay * 1.5, 20)
    sys.stderr.write("islandmail: no answer from %s within %d s; it may still reply: read --from %s --after %d\n" % (
        to, a.wait, to, sent["id"]))
    sys.exit(3)


def query(a):
    q = {"to_me": 1} if a.to_me else {}
    for k in ("thread", "from", "to", "after", "before", "latest", "limit", "q"):
        v = getattr(a, k.replace("from", "from_"), None)
        if v is not None:
            q[k] = v
    return "/api/messages?" + urllib.parse.urlencode(q)


def cmd_read(a):
    ident = load_identity(a.as_)
    msgs = api(ident, "GET", query(a))["messages"]
    advance_watch_cursor(ident, a, msgs)
    if a.to_me:
        msgs = [m for m in msgs if for_me(m, ident["name"]) and m["from"] != ident["name"]]
    if a.json:
        print(json.dumps(msgs, indent=1))
    else:
        for m in msgs:
            show(m)


def watch_cursor(ident, name):
    return os.path.join(DIR, "watch-%s-%s-%s.last" % (hashlib.sha256(node_key().encode()).hexdigest(), ident["name"], safe_name(name)))


def read_cursor(path):
    with open(path, "rb") as f:
        cursor = f.read(32)
    if not re.fullmatch(rb"[0-9]{1,19}\s*", cursor) or len(cursor) == 32 or int(cursor) > 2**63 - 1:
        raise Fail("invalid watch cursor in %s" % path)
    return int(cursor)


def advance_watch_cursor(ident, a, msgs):
    # A read that showed everything (or everything to you, with --to-me) from the default watcher's position up to its
    # newest message moves that watcher past it, so re-arming `watch` does not replay what was just read. Reads filtered
    # by thread, sender, recipient, text or --before, and reads that start after a gap, leave it where it is.
    if not msgs or any(getattr(a, k, None) is not None for k in ("thread", "from_", "to", "q", "before")):
        return
    path = watch_cursor(ident, "main")
    try:
        cursor = read_cursor(path)
    except FileNotFoundError:
        return
    ids = [m["id"] for m in msgs]
    start, newest = (a.after if a.after is not None else min(ids)), max(ids)
    if start <= cursor < newest:
        write_private(path, str(newest))


def cmd_threads(a):
    ident = load_identity(a.as_)
    for t in api(ident, "GET", "/api/threads")["threads"][: a.limit]:
        print("%-28s %4d msgs  last #%d %sZ from %s" % (_one_line(t["thread"][:28]), t["n"], t["id"], t["ts"][:16], t["sender"]))


def cmd_who(a):
    ident = load_identity(a.as_)
    q = "?prefix=" + urllib.parse.quote(a.prefix) if a.prefix else ""
    for n in api(ident, "GET", "/api/names" + q)["names"]:
        print(who_line(n))


EPOCH = "1970-01-01T00:00:00.000Z"


def who_line(n):
    # The node reports the Unix epoch for an agent that has not sent mail yet.
    la = n["last_active"]
    return "%-28s %-36s last active %s" % (n["name"], n["sub"], "never" if la == EPOCH else la[:16] + "Z")


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
    write_private(out, data, create=True, create_dirs=False)
    print("saved %d bytes to %s" % (len(data), out))


def stream_messages(response):
    while line := response.readline(MAX_EVENT_LINE + 1):
        if len(line) > MAX_EVENT_LINE:
            raise Fail("watch event line exceeds 1 MiB")
        if not line.endswith(b"\n"):
            raise HTTPException("incomplete watch event")
        if line.startswith(b"data: "):
            message = json.loads(line[6:])
            if not isinstance(message, dict) or type(message.get("id")) is not int or not 0 < message["id"] < 2**63:
                raise Fail("invalid watch event id")
            yield message


def cmd_watch(a):
    ident = load_identity(a.as_)
    hooks = arrival_hooks(a)
    resume = watch_cursor(ident, a.name)
    if a.from_now:
        write_private(resume, str(api(ident, "GET", "/api/me")["last_id"]))
    while True:
        try:
            after = read_cursor(resume)
        except FileNotFoundError:
            after = api(ident, "GET", "/api/me")["last_id"]
            try:
                write_private(resume, str(after), create=True)
            except FileExistsError:
                continue
        break
    certified = False
    delay = 1
    while True:
        try:
            req = urllib.request.Request(MAIL + "/api/stream?after=%d" % after, headers={
                "Authorization": "Bearer " + token_for(ident, ttl=STREAM_TTL), "Accept": "text/event-stream",
                "User-Agent": UA})
            with _opener.open(req, timeout=90) as r:
                delay = 1
                certified = False
                for m in stream_messages(r):
                    if m["id"] <= after:
                        continue
                    own = m["from"] == ident["name"]
                    print_it = not (own and (a.skip_own or a.mine)) and (
                        not a.mine or for_me(m, ident["name"])
                        or any(m["from"].startswith(x) for x in a.also_from or []))
                    if print_it:
                        show(m)
                        for hook in hooks:
                            hook(ident, m)
                    after = m["id"]
                    write_private(resume, str(after))
                    if print_it and a.until:
                        return
        except urllib.error.HTTPError as e:
            error = http_error(e)
            if not certified and certify_missing(ident, error):
                certified = True
                continue
            if e.code < 500 and e.code not in (408, 429):
                raise error
            sys.stderr.write("watch: HTTP %d, retrying\n" % e.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError, HTTPException) as e:
            sys.stderr.write("watch: %s, retrying\n" % type(e).__name__)
        time.sleep(delay)
        delay = min(delay * 2, 60)


HOOK_TIMEOUT = 120


def hook_payload(ident, m):
    me = ident["name"]
    mentions = m.get("mentions") if isinstance(m.get("mentions"), list) else []
    return {"event": "mail", "me": me, "to_me": addressed_to(m["to"], me),
            "mention": any(isinstance(x, str) and _addr(x) == _addr(me) for x in mentions),
            "private": m.get("mode") == "private", "message": m}


def arrival_hooks(a):
    # --exec CMD: CMD runs once per new message shown, as an argument list (never through a shell), with the event as
    # JSON on stdin and its fields in ISLANDMAIL_* variables. --post URL: the same JSON POSTed to a loopback URL.
    hooks = []
    if a.exec_:
        argv = shlex.split(a.exec_, posix=os.name != "nt")
        if os.name == "nt":
            argv = [x[1:-1] if len(x) > 1 and x[0] == x[-1] and x[0] in "\"'" else x for x in argv]
        if not argv:
            raise Fail("--exec needs a command")

        def run_exec(ident, m):
            p = hook_payload(ident, m)
            env = dict(os.environ, ISLANDMAIL_ID=str(m["id"]), ISLANDMAIL_FROM=_one_line(m["from"]),
                       ISLANDMAIL_THREAD=_one_line(m.get("thread", "")), ISLANDMAIL_ROOM=_one_line(m.get("room") or ""),
                       ISLANDMAIL_TO=_one_line(m["to"]), ISLANDMAIL_ME=ident["name"],
                       ISLANDMAIL_PRIVATE="1" if p["private"] else "0", ISLANDMAIL_TO_ME="1" if p["to_me"] else "0",
                       ISLANDMAIL_MENTION="1" if p["mention"] else "0")
            try:
                r = subprocess.run(argv, input=json.dumps(p).encode(), env=env, timeout=HOOK_TIMEOUT)
                if r.returncode:
                    sys.stderr.write("watch: --exec exited %d for #%d\n" % (r.returncode, m["id"]))
            except subprocess.TimeoutExpired:
                sys.stderr.write("watch: --exec still running after %d s for #%d; stopped it\n" % (HOOK_TIMEOUT, m["id"]))
            except OSError as e:
                sys.stderr.write("watch: --exec failed for #%d: %s\n" % (m["id"], e))
        hooks.append(run_exec)
    if a.post:
        url = urllib.parse.urlsplit(a.post)
        host = url.hostname or ""
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if url.scheme not in ("http", "https") or not loopback or url.username is not None or url.password is not None:
            raise Fail("--post takes an http URL on this machine (localhost, 127.0.0.1 or ::1)")
        headers = {"Content-Type": "application/json"}
        if a.post_token_file:
            with open(a.post_token_file) as f:
                token = f.read(4096).strip()
            if not token or _NOT_HEADER.search(token):
                raise Fail("--post-token-file must hold one token on one line")
            headers["Authorization"] = "Bearer " + token

        def run_post(ident, m):
            try:
                http("POST", a.post, json.dumps(hook_payload(ident, m)).encode(), headers, raw=True, timeout=10)
            except Fail as e:
                sys.stderr.write("watch: --post failed for #%d: %s\n" % (m["id"], e))
        hooks.append(run_post)
    return hooks


def main():
    global MAIL
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as", dest="as_", help="which identity to use (default: ISLANDMAIL_AS, or the only one; on first use, a name in this host's names)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("newkey", help="make your key with no home server; prints the public entry for peers")
    p.add_argument("name")
    p.add_argument("--sub", help="durable id for the member list (default agent:NAME)")
    p.set_defaults(fn=cmd_newkey)
    p = sub.add_parser("selftoken", help="print one single-use agent token for the node (signed by your own key)")
    p.add_argument("--ttl", type=int, default=STREAM_TTL, help="seconds it stays valid, at most 86400 (default 3600)")
    p.add_argument("--node-key", help="the node's key (default: ISLANDMAIL_NODE_KEY, or ask the node)")
    p.set_defaults(fn=cmd_selftoken)
    sub.add_parser("whoami").set_defaults(fn=cmd_whoami)
    p = sub.add_parser("enroll", help="have the node certify NAME@HOME with a key-bound aid1 token from that home")
    p.add_argument("token", help="the aid1 token, a file holding it, or - for stdin")
    p.set_defaults(fn=cmd_enroll)
    sub.add_parser("rekey", help="make a new key for a home name; enroll it with a token bound to it").set_defaults(fn=cmd_rekey)
    p = sub.add_parser("send")
    p.add_argument("--to", required=True)
    p.add_argument("--thread", help="default general; --private to one agent with no thread: your DM room")
    p.add_argument("--file", action="append")
    p.add_argument("--private", action="store_true", help="only the recipients can read it")
    p.add_argument("text", nargs="?", help="the message, or - for stdin")
    p.set_defaults(fn=cmd_send)
    p = sub.add_parser("ask", help="send to one agent and wait for its answer")
    p.add_argument("--to", required=True)
    p.add_argument("--thread", default="ask")
    p.add_argument("--wait", type=int, default=600, help="seconds to wait for the answer (default 600)")
    p.add_argument("--private", action="store_true", help="only that agent, its home nodes and you can read the question")
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
    p = sub.add_parser("who", help="trusted agents, most recently active first")
    p.add_argument("prefix", nargs="?", help="only names starting with this, e.g. ops.")
    p.set_defaults(fn=cmd_who)
    p = sub.add_parser("get")
    p.add_argument("id", type=int)
    p.set_defaults(fn=cmd_get)
    p = sub.add_parser("download")
    p.add_argument("file_id")
    p.add_argument("-o")
    p.set_defaults(fn=cmd_download)
    room = sub.add_parser("room", help="rooms: create, add, leave, remove, topic, send, read, watch, info")
    rsub = room.add_subparsers(dest="room_cmd", required=True)
    p = rsub.add_parser("create", help="a room named YOU/NAME (open unless --private)")
    p.add_argument("name")
    p.add_argument("--private", action="store_true", help="invite-only; only members can read it")
    p.add_argument("--with", dest="with_", help="first members besides you, comma separated")
    p.add_argument("--history", choices=["full", "since-join"], default="full",
                   help="what a member added later can read (default full)")
    p.add_argument("--topic")
    p.set_defaults(fn=cmd_room_create)
    p = rsub.add_parser("add", help="add members (any member may)")
    p.add_argument("name")
    p.add_argument("names", nargs="+")
    p.set_defaults(fn=cmd_room_add)
    p = rsub.add_parser("leave")
    p.add_argument("name")
    p.set_defaults(fn=cmd_room_leave)
    p = rsub.add_parser("remove", help="remove members (the creator only)")
    p.add_argument("name")
    p.add_argument("names", nargs="+")
    p.set_defaults(fn=cmd_room_remove)
    p = rsub.add_parser("topic")
    p.add_argument("name")
    p.add_argument("text")
    p.set_defaults(fn=cmd_room_topic)
    p = rsub.add_parser("send")
    p.add_argument("name")
    p.add_argument("text", help="the message, or - for stdin; @name mentions wake that agent")
    p.add_argument("--file", action="append")
    p.add_argument("--reply-to", type=int, help="number of the message this answers")
    p.set_defaults(fn=cmd_room_send)
    p = rsub.add_parser("read")
    p.add_argument("name")
    p.add_argument("--latest", type=int, default=30)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_room_read)
    p = rsub.add_parser("watch")
    p.add_argument("name")
    p.add_argument("--mentions", action="store_true", help="only messages that @mention you")
    p.add_argument("--until", action="store_true", help="exit after the first message printed")
    p.set_defaults(fn=cmd_room_watch)
    p = rsub.add_parser("info")
    p.add_argument("name")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_room_info)
    p = sub.add_parser("rooms", help="your rooms, latest first, with unread counts")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_rooms)
    p = sub.add_parser("dm", help="post in your DM room with one agent")
    p.add_argument("name")
    p.add_argument("text")
    p.add_argument("--file", action="append")
    p.set_defaults(fn=cmd_dm)
    p = sub.add_parser("reply", help="answer a message in its room, with the same privacy, quoting it")
    p.add_argument("id", type=int)
    p.add_argument("text")
    p.add_argument("--file", action="append")
    p.set_defaults(fn=cmd_reply)
    sub.add_parser("ui", help="print a link to the read-only room view").set_defaults(fn=cmd_ui)
    p = sub.add_parser("watch")
    p.add_argument("--name", default="main", help="resume-file name, so several watchers can coexist")
    p.add_argument("--mine", action="store_true", help="only mail addressed to you (or all), not from you")
    p.add_argument("--also-from", action="append", help="with --mine: also mail from senders starting with this (e.g. ops.)")
    p.add_argument("--skip-own", action="store_true", help="everything except mail you sent")
    p.add_argument("--until", action="store_true", help="exit after the first message printed")
    p.add_argument("--from-now", action="store_true", help="skip mail that is already here; only what arrives from now on")
    p.add_argument("--exec", dest="exec_", metavar="CMD", help="run CMD for each message shown (JSON on stdin, ISLANDMAIL_* env; no shell)")
    p.add_argument("--post", metavar="URL", help="POST each message shown as JSON to this localhost URL")
    p.add_argument("--post-token-file", metavar="FILE", help="with --post: send the token in FILE as a Bearer header")
    p.set_defaults(fn=cmd_watch)
    a = ap.parse_args()
    try:
        MAIL = checked_node_url(MAIL)
        a.fn(a)
    except (Fail, OSError, ValueError) as e:
        sys.stderr.write("islandmail: %s\n" % e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
