#!/usr/bin/env python3
"""Every test: the client on its own, then each scenario on real nodes (loopback, throwaway keys and folders).

  python3 tests/run.py --bin target/debug/islandmail-node [ONLY ...]
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = ["client", "two_nodes", "phase2", "network", "client_wake", "big_files", "sync_peers", "rooms",
          "invite", "hub_rooms", "late_rooms", "privacy", "notify", "api_guard", "gossip_churn"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("only", nargs="*", help="run only these suites")
    a = ap.parse_args()
    root = tempfile.mkdtemp(prefix="islandmail-tests-")
    repo = os.path.dirname(HERE)
    failed = []
    for name in a.only or SUITES:
        argv = [sys.executable, os.path.join(HERE, name + ".py")]
        if name != "client":
            argv += ["--bin", a.bin, "--workdir", os.path.join(root, name)]
            argv += ["--repo", repo] if name == "phase2" else [] if name in ("api_guard", "gossip_churn") \
                else ["--islandmail", os.path.join(repo, "clients", "islandmail.py")]
        start = time.time()
        rc = subprocess.run(argv).returncode
        print("== %s: %s in %.0f s" % (name, "ok" if rc == 0 else "FAILED (exit %d)" % rc, time.time() - start), flush=True)
        if rc:
            failed.append(name)
    print("\n%d suites, %d failed%s; logs in %s" % (len(a.only or SUITES), len(failed),
                                                     ": " + ", ".join(failed) if failed else "", root))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
