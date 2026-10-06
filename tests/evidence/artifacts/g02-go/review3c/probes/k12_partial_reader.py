#!/usr/bin/env python3
"""Review-3c K12 probe, Linux only: a reader that closes after part of the output.

usage: k12_partial_reader.py LABEL=BIN [...]
stdout is a pipe shrunk to 4096 bytes (F_SETPIPE_SZ); the reader waits until the
pipe is full (the program is blocked in a write), reads 100 bytes, closes its
end, and the wait status is recorded with and without --json. large-100 output
is 4503 bytes plain / 11842 bytes --json, both above the pipe size, so both
modes hit EPIPE mid-output deterministically.
"""
import fcntl
import os
import signal
import subprocess
import sys
import time

F_SETPIPE_SZ = 1031
FIX = os.path.join(os.path.dirname(__file__), *[".."] * 6, "tests/fixtures/g02/profiles/large-100.toml")


def st(rc):
    return "signal " + signal.Signals(-rc).name if rc < 0 else "exit %d" % rc


for spec in sys.argv[1:]:
    label, b = spec.split("=", 1)
    for js in (False, True):
        r, w = os.pipe()
        fcntl.fcntl(w, F_SETPIPE_SZ, 4096)
        argv = [b, "profile", "show", "--file", FIX] + (["--json"] if js else [])
        p = subprocess.Popen(argv, stdout=w, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                             restore_signals=True)
        os.close(w)
        time.sleep(0.5)  # program fills the 4096-byte pipe and blocks in write
        got = os.read(r, 100)
        os.close(r)
        rc = p.wait(10)
        print("%s %s read=%d status=%s" % (label, "json " if js else "plain", len(got), st(rc)), flush=True)
