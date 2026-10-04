#!/usr/bin/env python3
"""Measure one program's wall time and peak RSS (K15 checks of tests/g02/conformance.py).

Usage: rss_wrap.py REPORT_JSON -- program [args...]

Runs the program with inherited stdin/stdout/stderr, reaps it with os.wait4() (whose rusage
covers exactly that child and the descendants it waited for), writes
{"wall_s", "ru_maxrss_raw", "maxrss_bytes", "status", "exit_code", "signal", "platform"} to
REPORT_JSON and exits with the program's exit code (128+N if it died by signal N).
ru_maxrss is bytes on macOS and KiB on Linux; maxrss_bytes is normalised.
Python standard library only.
"""
import json
import os
import subprocess
import sys
import time


def main():
    report = sys.argv[1]
    sep = sys.argv.index("--")
    cmd = sys.argv[sep + 1:]
    t0 = time.monotonic()
    try:
        p = subprocess.Popen(cmd)
    except OSError as exc:
        with open(report, "w") as fh:
            json.dump({"launch_error": exc.__class__.__name__}, fh)
        return 127
    while True:
        try:
            _pid, status, ru = os.wait4(p.pid, 0)
            break
        except InterruptedError:
            continue
    wall = time.monotonic() - t0
    p.returncode = 0   # reaped here; keep Popen from trying again
    raw = ru.ru_maxrss
    rss = raw if sys.platform == "darwin" else raw * 1024
    code = os.waitstatus_to_exitcode(status)
    out = {"wall_s": round(wall, 4), "ru_maxrss_raw": raw, "maxrss_bytes": rss, "status": status,
           "exit_code": code if code >= 0 else None, "signal": -code if code < 0 else None,
           "platform": sys.platform}
    with open(report, "w") as fh:
        json.dump(out, fh)
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
