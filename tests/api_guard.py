#!/usr/bin/env python3
"""The loopback API against a hostile local process and a hostile web page, on one throwaway node:
- the node refuses to start when its config or trust file (or the trust file's folder) can be written by other users
  (Unix), and says how to fix it;
- a request whose Host is not this node's (DNS rebinding) or names another port gets 403, GETs included; loopback
  names with the API port pass, also through a forwarder as an ssh tunnel to 127.0.0.1 would be;
- a connection that trickles its headers (slowloris) is closed;
- hundreds of idle connections (the node limited to 256 open files) neither stop it answering for long nor stop it
  adopting a trust file change.

  python3 tests/api_guard.py --bin target/release/islandmail-node [--workdir DIR]
"""
import argparse
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, check, free_port, run, wait_for, work_directory  # noqa: E402

IDLE = 300


def get(port, path, host=None, timeout=10):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        c.putrequest("GET", path, skip_host=True)
        if host != "":
            c.putheader("Host", host or "127.0.0.1:%d" % port)
        c.endheaders()
        r = c.getresponse()
        return r.status, r.read()
    except (OSError, http.client.HTTPException) as e:
        return None, repr(e).encode()
    finally:
        c.close()


def forwarder(target):
    # A plain TCP forwarder on another port: what `ssh -L PORT:127.0.0.1:PORT` hands the node (bytes unchanged).
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def loop():
        while True:
            c, _ = srv.accept()
            u = socket.create_connection(("127.0.0.1", target))
            threading.Thread(target=pipe, args=(c, u), daemon=True).start()
            threading.Thread(target=pipe, args=(u, c), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    work = work_directory(a.workdir)
    seed = os.path.join(work, "node.seed")
    key = run(bin_, "keygen", seed)
    trust_path, cfg_path = os.path.join(work, "members.json"), os.path.join(work, "config.json")
    trust = {"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [],
             "nodes": [{"name": "a", "key": key, "addrs": [], "names": ["alice"]}]}
    port = free_port()

    def write(path, obj, mode=0o600):
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    write(trust_path, trust)
    write(cfg_path, {"data_dir": "data", "api_listen": "127.0.0.1:%d" % port, "iroh_port": 0,
                     "node_key_file": "node.seed", "members_file": "members.json"})
    log_path = os.path.join(work, "node.log")

    def limit():
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

    def start():
        return subprocess.Popen([bin_, "run", cfg_path], stdout=open(log_path, "a"), stderr=subprocess.STDOUT,
                                preexec_fn=limit if os.name != "nt" else None)

    if os.name != "nt":
        for path, mode, fix in ((trust_path, 0o664, "chmod go-w"), (trust_path, 0o606, "chmod go-w"),
                                (cfg_path, 0o620, "chmod go-w"), (work, 0o777, "replace")):
            os.chmod(path, mode)
            p = start()
            try:
                code = p.wait(20)
            except subprocess.TimeoutExpired:
                p.kill()
                code = None
            os.chmod(path, 0o700 if path == work else 0o600)
            last = open(log_path).read().strip().splitlines()[-1]
            check("the node refuses to start with %s mode %o, saying how to fix it" % (os.path.basename(path), mode),
                  code not in (None, 0) and fix in last, "exit %s: %s" % (code, last[-200:]))

    node = start()
    try:
        up, _ = wait_for(lambda: get(port, "/api/node")[0] == 200, timeout=30)
        check("node starts", up)
        st, _ = get(port, "/api/node", host="rebind.example:%d" % port)
        st_ui, _ = get(port, "/ui", host="rebind.example")
        check("a foreign Host gets 403 on GET /api/node and /ui (DNS rebinding)", st == 403 and st_ui == 403,
              "%s %s" % (st, st_ui))
        st, _ = get(port, "/api/node", host="127.0.0.1:%d" % (port + 1))
        st2, _ = get(port, "/api/node", host="")
        check("another port in Host, or no Host, is refused", st == 403 and st2 in (400, 403), "%s %s" % (st, st2))
        st, _ = get(port, "/ui", host="localhost:%d" % port)
        st2, _ = get(port, "/api/node", host="[::1]:%d" % port)
        check("loopback Hosts with the API port are served", st == 200 and st2 == 200, "%s %s" % (st, st2))
        fwd = forwarder(port)
        st, body = get(fwd, "/ui", host="127.0.0.1:%d" % port)
        check("/ui through a tunnel to 127.0.0.1 (same port) is served", st == 200 and b"<html" in body.lower(), st)

        # Slowloris: headers that never finish are cut off.
        s = socket.create_connection(("127.0.0.1", port), timeout=30)
        s.sendall(b"GET /api/node HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % port)
        t0, closed = time.time(), False
        try:
            while time.time() - t0 < 40:
                time.sleep(2)
                s.sendall(b"X-a: b\r\n")
                s.settimeout(0.1)
                try:
                    if s.recv(4096) == b"":
                        closed = True
                        break
                except socket.timeout:
                    pass
                s.settimeout(30)
        except OSError:
            closed = True
        s.close()
        check("a connection trickling its headers is closed", closed, "after %.0f s" % (time.time() - t0))

        idle = []
        for _ in range(IDLE):
            try:
                idle.append(socket.create_connection(("127.0.0.1", port), timeout=2))
            except OSError:
                break
        t0 = time.time()
        ok, t = wait_for(lambda: get(port, "/api/node", timeout=5)[0] == 200, timeout=60, every=0.5)
        check("with %d idle connections held, the node still answers" % len(idle), ok, "after %.0f s" % t)
        trust["seq"] = 2
        trust["nodes"][0]["names"] = ["alice", "bob"]
        write(trust_path, trust)

        def adopted():
            st, body = get(port, "/api/node", timeout=5)
            return st == 200 and "bob" in json.loads(body).get("names", [])
        ok, t = wait_for(adopted, timeout=60, every=0.5)
        check("and adopts a trust file change", ok, "after %.0f s" % t)
        log = open(log_path).read()
        check("without running out of file descriptors", "Too many open files" not in log,
              "%d lines mention it" % log.count("Too many open files"))
        for s in idle:
            s.close()
        print("(%d idle connections held for %.0f s)" % (len(idle), time.time() - t0))
        if os.name != "nt":
            # A trust file made group-writable while running is not adopted; fixed, the next change is.
            trust["seq"] = 3
            trust["nodes"][0]["names"] = ["alice", "bob", "carol"]
            write(trust_path, trust, 0o664)
            time.sleep(4)
            st, body = get(port, "/api/node")
            kept = st == 200 and "carol" not in json.loads(body).get("names", [])
            os.chmod(trust_path, 0o600)

            def carol():
                st, body = get(port, "/api/node", timeout=5)
                return st == 200 and "carol" in json.loads(body).get("names", [])
            ok, _ = wait_for(carol, timeout=20)
            check("a running node ignores a group-writable trust file, and adopts it once fixed", kept and ok,
                  "kept %s adopted %s" % (kept, ok))
    finally:
        node.terminate()
        try:
            node.wait(10)
        except subprocess.TimeoutExpired:
            node.kill()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
