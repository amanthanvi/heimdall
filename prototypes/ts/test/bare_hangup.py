#!/usr/bin/env python3
"""Bare terminal hangup driver for tui.test.ts (K10).

Runs the command as the foreground job of a fresh pty under the repository's job-control
shim (tests/g02/pty_shim.py, used read-only) with --no-hup-forward: the session leader is
not a shell, so closing the pty master gives the job only EOF/EIO, never SIGHUP.
Waits for the first frame ("filter:"), closes the master, and prints one JSON line:
{"frame": bool, "rc": wait status or null, "selected": bool}.

Usage: bare_hangup.py COMMAND [ARGS...]
"""
import fcntl
import json
import os
import select
import struct
import subprocess
import sys
import termios
import time

SHIM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "tests", "g02", "pty_shim.py")


def main():
    master, slave = os.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 10, 80, 0, 0))
    ctl_r, ctl_w = os.pipe()
    st_r, st_w = os.pipe()
    shim = subprocess.Popen(
        [sys.executable, SHIM, str(ctl_r), str(st_w), "--no-hup-forward", "--"] + sys.argv[1:],
        stdin=slave, stdout=slave, stderr=subprocess.DEVNULL,
        start_new_session=True, pass_fds=(ctl_r, st_w))
    os.close(ctl_r)
    os.close(st_w)
    os.close(slave)
    out = bytearray()
    status = b""
    pid = rc = None

    def read_status(timeout):
        nonlocal status, pid, rc
        r, _, _ = select.select([st_r], [], [], timeout)
        if not r:
            return
        status += os.read(st_r, 4096)
        while b"\n" in status:
            line, status = status.split(b"\n", 1)
            ev = json.loads(line)
            if ev.get("event") == "started":
                pid = ev["pid"]
            elif ev.get("event") == "exited":
                rc = ev["rc"]

    end = time.monotonic() + 8
    while b"filter:" not in out and rc is None and time.monotonic() < end:
        r, _, _ = select.select([master], [], [], 0.02)
        if r:
            try:
                out += os.read(master, 65536)
            except OSError:
                break
        read_status(0)
    frame = b"filter:" in out
    os.close(master)  # terminal hangup; the shim does not forward it
    end = time.monotonic() + 5
    while rc is None and time.monotonic() < end:
        read_status(0.05)
    if rc is None and pid is not None:
        try:
            os.killpg(pid, 9)  # the job's own process group (shim made it pgid == pid)
        except (ProcessLookupError, PermissionError):
            pass
    os.close(ctl_w)  # lets the shim exit
    try:
        shim.wait(timeout=5)
    except subprocess.TimeoutExpired:
        shim.kill()
        shim.wait()
    print(json.dumps({"frame": frame, "rc": rc, "selected": b"SELECTED" in out}))


if __name__ == "__main__":
    main()
