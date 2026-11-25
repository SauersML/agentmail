#!/usr/bin/env python3
"""The client's PASETO v4.public signing against the official test vectors (paseto-standard/test-vectors v4.json,
4-S-1..3), with the pure-Python Ed25519 and, when installed, pyca/cryptography. No node needed.

  python3 tests/client_paseto.py --repo .
"""
import argparse
import importlib.util
import os
import sys

SEED = bytes.fromhex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774")
PUBLIC = bytes.fromhex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
PAYLOAD = b'{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}'
FOOTER = b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}'
VECTORS = [
    ("4-S-1", b"", b"", "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"),
    ("4-S-2", FOOTER, b"", "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"),
    ("4-S-3", FOOTER, b'{"test-vector":"4-S-3"}', "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    a = ap.parse_args()
    spec = importlib.util.spec_from_file_location("islandmail", os.path.join(a.repo, "clients", "islandmail.py"))
    im = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(im)
    impls = [("pure Python", None)] + ([("pyca/cryptography", im._PycaKey)] if im._PycaKey else [])
    failed = 0
    for label, pyca in impls:
        im._PycaKey = pyca
        ok = im.ed25519_public(SEED) == PUBLIC
        print("%s public key (%s)" % ("PASS" if ok else "FAIL", label))
        failed += not ok
        for name, footer, implicit, want in VECTORS:
            ok = im.paseto_v4_public_sign(SEED, PAYLOAD, footer, implicit) == want
            print("%s %s (%s)" % ("PASS" if ok else "FAIL", name, label))
            failed += not ok
    if len(impls) == 1:
        print("note: pyca/cryptography not installed; only the pure-Python signer was checked")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
