#!/usr/bin/env python3
"""Waking agents: `watch --from-now`, `read` moving the default watch cursor, arrival hooks (`watch --exec`) and the upload progress line. One node on loopback, throwaway keys.

  python3 tests/client_wake.py --bin target/debug/islandmail-node --islandmail clients/islandmail.py [--workdir DIR]
"""
import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from two_nodes import RESULTS, Node, check, free_port, run, work_directory  # noqa: E402

HOOK = r'''import json, os, sys
event = json.load(sys.stdin)
if os.environ.get("FAILS_FILE"):  # a hook that is down: exits 75 while FAILS_FILE counts down
    fails = int(open(os.environ["FAILS_FILE"]).read() or 0)
    if fails:
        open(os.environ["FAILS_FILE"], "w").write(str(fails - 1))
        sys.exit(75)
with open(sys.argv[1], "a") as f:
    f.write(json.dumps({"argv": sys.argv[2:], "event": event}) + "\n")
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--islandmail", required=True)
    ap.add_argument("--workdir", default=None)
    a = ap.parse_args()
    bin_ = os.path.abspath(a.bin)
    im = os.path.abspath(a.islandmail)
    work = work_directory(a.workdir)
    os.makedirs(os.path.join(work, "keys"))
    seed = os.path.join(work, "keys", "mac.seed")
    pub = run(bin_, "keygen", seed)
    udp, port = free_port(socket.SOCK_DGRAM), free_port()
    trust = os.path.join(work, "trust.json")
    with open(trust, "w") as f:
        json.dump({"v": 1, "network": run(bin_, "network-id"), "seq": 1, "members": [], "nodes": [
            {"name": "mac", "key": pub, "addrs": ["127.0.0.1:%d" % udp], "names": ["alice", "s."]}]}, f)
    node = Node(bin_, work, "mac", {"data_dir": os.path.join(work, "data"), "api_listen": "127.0.0.1:%d" % port,
                                    "iroh_port": udp, "node_key_file": seed, "members_file": trust, "sync_secs": 3})
    client_dir = os.path.join(work, "client")
    env = dict(os.environ, ISLANDMAIL_DIR=client_dir, ISLANDMAIL_URL="http://127.0.0.1:%d" % port)

    def cl(who, *args, timeout=60):
        p = subprocess.run([sys.executable, im, "--as", who, *args], env=env, capture_output=True, text=True,
                           timeout=timeout, cwd=work)
        return p.returncode, p.stdout, p.stderr

    def send(text, thread="general"):
        rc, out, err = cl("s.peer", "send", "--open", "--to", "alice", "--thread", thread, text)
        m = re.search(r"sent ([a-z2-7]{8}) ", out)
        return m.group(1) if rc == 0 and m else None

    def seq(mid):
        # Cursors are local seq numbers (only in --json); people see the shared id.
        rc, out, _ = cl("alice", "get", mid or "x", "--json")
        return json.loads(out)["seq"] if rc == 0 else None

    def watch(*args, timeout=20):
        return cl("alice", "watch", "--mine", "--until", *args, timeout=timeout)

    def background_watch(*args):
        p = subprocess.Popen([sys.executable, im, "--as", "alice", "watch", "--mine", "--until", *args], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=work)
        time.sleep(3)  # it has read its starting point and opened the stream
        return p

    def finish(p, timeout=20):
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        return p.returncode, out, err

    cursor = lambda name: os.path.join(client_dir, "watch-%s-alice-%s.last" % (hashlib.sha256(pub.encode()).hexdigest(), name))
    try:
        check("node starts", node.start())
        check("two agents", cl("alice", "whoami")[0] == 0 and cl("s.peer", "whoami")[0] == 0)

        # read moves the default watch cursor; re-arming watch does not replay what was read.
        with open(cursor("main"), "w") as f:
            f.write("0")  # a watcher armed before any mail
        m1 = send("one")
        rc, out, _ = watch()
        check("first watch arms the cursor at the first mail", rc == 0 and "> one" in out, out[-200:])
        with open(cursor("side"), "w") as f:
            f.write(str(seq(m1)))
        m2, m3 = send("two"), send("three")
        rc, out, _ = cl("alice", "read", "--to-me", "--latest", "20")
        check("read shows the new mail", rc == 0 and "> two" in out and "> three" in out, out[-200:])
        check("read moved the default cursor to the newest mail it showed", open(cursor("main")).read().strip() == str(seq(m3)))
        send("four")
        rc, out, _ = watch()
        check("re-armed watch wakes for new mail only, not what was read", rc == 0 and "> four" in out and "> two" not in out, out[-200:])
        rc, out, _ = watch("--name", "side")
        check("a named cursor is untouched by read", rc == 0 and "> two" in out, out[-200:])

        # A read filtered by thread does not move the cursor past mail it did not show.
        send("in thread x", "x")
        send("in thread y", "y")
        rc, out, _ = cl("alice", "read", "--thread", "y")
        check("thread read shows its mail", rc == 0 and "> in thread y" in out, out[-200:])
        rc, out, _ = watch()
        check("watch still wakes for the other thread's mail", rc == 0 and "> in thread x" in out, out[-200:])
        rc, out, _ = cl("alice", "read", "--after", "0", "--limit", "1")
        rc2, out2, _ = watch()
        check("a read that starts before the cursor but stops below it changes nothing",
              rc == 0 and rc2 == 0 and "> in thread y" in out2, out2[-200:])

        # --from-now skips mail already here.
        send("backlog")
        p = background_watch("--from-now")
        send("fresh")
        rc, out, _ = finish(p)
        check("watch --from-now skips the backlog and wakes for new mail", rc == 0 and "> fresh" in out and "> backlog" not in out, out[-200:])

        # --exec: argv list, never a shell; JSON on stdin.
        hook = os.path.join(work, "hook.py")
        with open(hook, "w") as f:
            f.write(HOOK)
        got = os.path.join(work, "hook.jsonl")
        pwned = os.path.join(work, "PWNED")
        nasty = "hello $(touch %s) `touch %s`; touch %s && echo 'q' \"dq\"" % (pwned, pwned, pwned)
        p = background_watch("--exec", "%s %s %s 'two words' $HOME" % (sys.executable, hook, got))
        mid = send(nasty, "wake")
        rc, out, err = finish(p)
        events = [json.loads(line) for line in open(got)] if os.path.exists(got) else []
        ev = events[0] if events else {}
        check("--exec ran once for the new mail", rc == 0 and len(events) == 1, err[-200:])
        check("the hook got the message as JSON on stdin", ev.get("event", {}).get("message", {}).get("text") == nasty
              and ev["event"]["me"] == "alice" and ev["event"]["to_me"] is True and ev["event"]["private"] is False)
        check("arguments are split like a shell would, but nothing is expanded", ev.get("argv") == ["two words", "$HOME"], str(ev.get("argv")))
        m = ev.get("event", {}).get("message", {})
        check("the JSON names the message, sender and thread", str(m.get("id")) == str(mid) and m.get("from") == "s.peer"
              and m.get("thread") == "wake" and ev["event"]["mention"] is False, str(ev)[:300])
        check("no shell ran the sender's text", not os.path.exists(pwned))
        p = background_watch("--exec", "%s %s %s" % (sys.executable, hook, got))
        rc_s, _, _ = cl("s.peer", "send", "--to", "alice", "secret")
        rc, out, err = finish(p)
        events = [json.loads(line) for line in open(got)]
        check("private mail is flagged", rc_s == 0 and rc == 0 and len(events) == 2
              and events[1]["event"]["private"] is True, err[-200:])

        # A failed hook does not lose the wake (issue #23): it is retried, and if it stays down watch exits non-zero
        # with the cursor before the message, so the next watch with that --name delivers it again.
        fails = os.path.join(work, "fails")
        open(fails, "w").write("1")
        env["FAILS_FILE"] = fails
        got2 = os.path.join(work, "hook2.jsonl")
        p = background_watch("--name", "hooks", "--from-now", "--exec", "%s %s %s" % (sys.executable, hook, got2))
        m_flaky = send("hook down once")
        rc, out, err = finish(p, timeout=40)
        events = [json.loads(line) for line in open(got2)] if os.path.exists(got2) else []
        check("a hook that fails once is retried and gets the mail once", rc == 0 and len(events) == 1
              and str(events[0]["event"]["message"]["id"]) == str(m_flaky) and "exited 75" in err, err[-300:])
        check("and the cursor moves past it", open(cursor("hooks")).read().strip() == str(seq(m_flaky)))
        open(fails, "w").write("100")
        p = background_watch("--name", "hooks", "--exec", "%s %s %s" % (sys.executable, hook, got2))
        m_down = send("hook stays down")
        rc, out, err = finish(p, timeout=60)
        check("a hook that stays down: watch exits non-zero and says so", rc != 0 and "delivers it again" in err
              and str(m_down) in err, err[-300:])
        check("and the cursor stays before that mail", open(cursor("hooks")).read().strip() == str(seq(m_flaky)))
        del env["FAILS_FILE"]
        rc, out, err = cl("alice", "watch", "--mine", "--until", "--name", "hooks", "--exec",
                          "%s %s %s" % (sys.executable, hook, got2), timeout=30)
        events = [json.loads(line) for line in open(got2)]
        check("re-armed without --from-now, the working hook gets the mail it missed", rc == 0 and len(events) == 2
              and str(events[1]["event"]["message"]["id"]) == str(m_down), err[-300:])
        check("and now the cursor moves past it", open(cursor("hooks")).read().strip() == str(seq(m_down)))
        with open(cursor("main"), "w") as f:
            f.write(str(seq(m_down)))  # the default watcher below starts after these


        # Upload progress: a line for a big attachment, none for a small one; the file arrives intact.
        big = os.path.join(work, "big.bin")
        data = os.urandom(6 * 1024 * 1024 + 123)
        with open(big, "wb") as f:
            f.write(data)
        rc, out, err = cl("s.peer", "send", "--open", "--to", "alice", "--file", big, "big file", timeout=120)
        check("big upload prints progress", rc == 0 and "uploading big.bin" in err and "(100%)" in err, (out + err)[-300:])
        small = os.path.join(work, "small.txt")
        with open(small, "w") as f:
            f.write("tiny")
        rc, out, err = cl("s.peer", "send", "--open", "--to", "alice", "--file", small, "small file")
        check("small upload prints none", rc == 0 and "uploading" not in err, err[-200:])
        rc, out, _ = cl("alice", "read", "--json", "--latest", "2")
        files = [f for m in (json.loads(out) if rc == 0 else []) for f in m.get("files", []) if f["name"] == "big.bin"]
        dest = os.path.join(work, "big.out")
        rc, out, err = cl("alice", "download", files[0]["id"], "-o", dest) if files else (1, "", "no file")
        check("the big attachment downloads byte for byte", rc == 0 and open(dest, "rb").read() == data, (out + err)[-200:])
    finally:
        node.stop()
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed; logs in %s" % (len(RESULTS), len(failed), work))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
