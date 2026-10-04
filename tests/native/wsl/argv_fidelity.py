#!/usr/bin/env python3
"""Remote-argument fidelity cases for the G03 harness (stdlib only).

Usage: argv_fidelity.py --cases FILE --out-dir DIR -- <client argv prefix incl. destination alias>

For each case in FILE (tests/native/windows/fixtures/quoting-cases.json,
"remote_argument_cases") runs  <prefix> "printf '[%s]\\n' <POSIX-single-quoted value>"
with an exact argv (no shell) and checks the remote output byte-for-byte.
When the client is Windows ssh.exe launched from WSL, this exercises WSL
interop's argv -> Windows command line conversion plus ssh.exe's parsing.
Prints a JSON summary; per-case stdout/stderr go to --out-dir.
"""
import argparse
import json
import os
import subprocess
import sys


def posix_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cases", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--timeout", type=float, default=60)
    p.add_argument("prefix", nargs=argparse.REMAINDER)
    a = p.parse_args()
    prefix = a.prefix[1:] if a.prefix and a.prefix[0] == "--" else a.prefix
    if not prefix:
        p.error("client argv prefix required after --")
    with open(a.cases, encoding="utf-8") as fh:
        cases = json.load(fh)["remote_argument_cases"]
    os.makedirs(a.out_dir, exist_ok=True)
    rows = []
    for c in cases:
        value = c["value"]
        remote = "printf '[%s]\\n' " + posix_quote(value)
        expected = ("[%s]\n" % value).encode("utf-8")
        try:
            r = subprocess.run(prefix + [remote], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=a.timeout)
            out, err, rc = r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired:
            out, err, rc = b"", b"timeout", None
        base = os.path.join(a.out_dir, "argv-" + c["id"])
        with open(base + ".stdout", "wb") as fh:
            fh.write(out)
        with open(base + ".stderr", "wb") as fh:
            fh.write(err)
        norm = out.replace(b"\r\n", b"\n")
        rows.append({"case": c["id"], "exit_code": rc, "exact": out == expected,
                     "exact_after_crlf_normalization": norm == expected})
    print(json.dumps({"cases": rows, "all_exact": all(r["exact"] for r in rows),
                      "all_exit_zero": all(r["exit_code"] == 0 for r in rows)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
