"""Shared helpers for the integration tests: throwaway keys, a signed member list, nodes as subprocesses, and
islandmail.py clients that each have their own key folder."""
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

RESULTS = []
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CLIENT = os.path.join(REPO, "clients", "islandmail.py")


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)
    return ok


def finish(work):
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run(bin_, *args, ok=True):
    p = subprocess.run([bin_, *args], capture_output=True, text=True)
    if ok and p.returncode:
        raise RuntimeError("%s %s failed: %s" % (os.path.basename(bin_), " ".join(args), p.stderr.strip()))
    return p.stdout.strip() if ok else (p.returncode, (p.stdout + p.stderr).strip())


def req(method, port, path, token=None, body=None, timeout=10):
    h = {}
    data = None
    if token:
        h["Authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_for(fn, timeout=20, every=0.2):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            return v, time.time() - t0
        time.sleep(every)
    return None, time.time() - t0


def member_list(bin_, work, operator_seed, seq, nodes, network="test", name="members.json"):
    """nodes: [(name, key, names or None, addrs)]. Signs with the operator seed; returns the signed file's path."""
    unsigned = {"v": 2, "network": network, "seq": seq, "issued": "", "operator": "", "sig": "", "nodes": [
        dict({"name": n, "key": k, "addrs": addrs}, **({"names": names} if names else {})) for n, k, names, addrs in nodes]}
    src = os.path.join(work, "unsigned-%d.json" % seq)
    with open(src, "w") as f:
        json.dump(unsigned, f)
    out = os.path.join(work, name)
    run(bin_, "sign-members", operator_seed, src, out)
    return out


class Node:
    def __init__(self, bin_, work, name, cfg):
        self.bin, self.work, self.name, self.cfg = bin_, work, name, cfg
        self.proc = None
        self.port = int(cfg["api_listen"].split(":")[1])
        self.path = os.path.join(work, name + ".json")

    def start(self, timeout=30):
        with open(self.path, "w") as f:
            json.dump(self.cfg, f, indent=1)
        log = open(os.path.join(self.work, self.name + ".log"), "a")
        self.proc = subprocess.Popen([self.bin, "run", self.path], stdout=log, stderr=subprocess.STDOUT, env=dict(
            os.environ, RUST_LOG=os.environ.get("MAILNODE_LOG", "mailnode=info,iroh=warn,iroh_gossip=warn")))
        ok, _ = wait_for(lambda: self.proc.poll() is not None or self._up(), timeout=timeout)
        return ok and self.proc.poll() is None

    def _up(self):
        try:
            socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
            return True
        except OSError:
            return False

    def key(self):
        return req("GET", self.port, "/api/node")[1]["node"]

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


class Client:
    """islandmail.py with its own ISLANDMAIL_DIR (its own keys), pointed at one node, as one local user."""

    def __init__(self, work, label, node, user=None, name=None):
        self.dir = os.path.join(work, "im-" + label)
        self.node, self.user, self.name = node, user or label, name

    def env(self, node=None):
        env = dict(os.environ, ISLANDMAIL_URL="http://127.0.0.1:%d" % (node or self.node).port, ISLANDMAIL_DIR=self.dir,
                   USER=self.user)
        env.pop("ISLANDMAIL_AS", None)
        env.pop("ISLANDMAIL_NODE_KEY", None)
        if self.name:
            env["ISLANDMAIL_AS"] = self.name
        return env

    def __call__(self, *args, timeout=60, node=None):
        p = subprocess.run([sys.executable, CLIENT, *args], capture_output=True, text=True, env=self.env(node),
                           timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()

    def stdout(self, *args, timeout=60):
        p = subprocess.run([sys.executable, CLIENT, *args], capture_output=True, text=True, env=self.env(), timeout=timeout)
        return p.returncode, p.stdout.strip()

    def popen(self, *args):
        return subprocess.Popen([sys.executable, CLIENT, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=self.env())

    def token(self, ttl=300, node_key=None):
        args = ["selftoken", "--ttl", str(ttl)] + (["--node-key", node_key] if node_key else [])
        p = subprocess.run([sys.executable, CLIENT, *args], capture_output=True, text=True, env=self.env(), timeout=60)
        if p.returncode:
            raise RuntimeError("selftoken: " + p.stderr.strip())
        return p.stdout.strip()

    def identity_file(self):
        d = os.path.join(self.dir, "identities")
        files = [f for f in os.listdir(d) if f.endswith(".json")] if os.path.isdir(d) else []
        return os.path.join(d, files[0]) if len(files) == 1 else None


def sse_reader(port, token, after, out, stop):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    c.request("GET", "/api/stream?after=%d" % after, headers={"Authorization": "Bearer " + token})
    r = c.getresponse()
    out.append(("status", r.status, r.getheader("Content-Type")))
    while not stop.is_set():
        line = r.fp.readline()
        if not line:
            break
        line = line.decode().rstrip("\n")
        if line.startswith("data: "):
            out.append(("data", json.loads(line[6:])))
    c.close()
