#!/usr/bin/env python3
"""Review-3 probe: does `heimdall-proto tui` draw its first frame under a given environment?

usage: tui_first_frame.py HEIMDALL_BIN PROFILE OUT_JSON CASE=VAR=VAL[;VAR=VAL...] ...

Base environment: PATH=/usr/bin:/bin, HOME=<sandbox>, TERM=xterm-256color, LANG=C.UTF-8.
Each CASE adds its variables. The TUI runs in a pty (24x80); the probe waits up to 6 s
for the text 'lab-server' (homelab fixture alias), presses q, and waits up to 3 s for
exit. If no frame or no exit, it sends SIGTERM to the exact TUI pid, then SIGKILL after
2 s. Raw output bytes (head and tail, escaped) are recorded.
"""
import json
import os
import pty
import select
import signal
import sys
import tempfile
import time

HP, PROFILE, OUT = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]), sys.argv[3]
CASES = sys.argv[4:]


def read_for(fd, secs, buf, until=None):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                return buf, "eio"
            if not d:
                return buf, "eof"
            buf += d
            if until and until in buf:
                return buf, "found"
    return buf, "timeout"


def one(case):
    name, _, spec = case.partition("=")
    env = {"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp(prefix="hp-rv3-ff-"), "TERM": "xterm-256color",
           "LANG": "C.UTF-8"}
    for kv in filter(None, spec.split(";")):
        k, _, v = kv.partition("=")
        env[k] = v
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(HP, [HP, "tui", "--file", PROFILE], env)
    import fcntl, struct, termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    t0 = time.monotonic()
    buf, why = read_for(fd, 6, b"", b"lab-server")
    res = {"case": name, "env_added": spec, "first_frame_s": round(time.monotonic() - t0, 3) if why == "found" else None}
    if why == "found":
        time.sleep(0.2)
        os.write(fd, b"q")
    buf, _ = read_for(fd, 3, buf)
    p, st = 0, 0
    for _ in range(60):  # up to 3 s for the exit to become reapable
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            break
        time.sleep(0.05)
    if not p:
        res["needed_sigterm"] = True
        os.kill(pid, signal.SIGTERM)  # the exact TUI pid forked above
        buf, _ = read_for(fd, 2, buf)
        p, st = os.waitpid(pid, os.WNOHANG)
        if not p:
            res["needed_sigkill"] = True
            os.kill(pid, signal.SIGKILL)
            p, st = os.waitpid(pid, 0)
    res["exit"] = os.waitstatus_to_exitcode(st)
    os.close(fd)
    res["out_len"] = len(buf)
    res["out_head"] = repr(buf[:400])
    res["out_tail"] = repr(buf[-300:])
    return res


results = [one(c) for c in CASES]
json.dump(results, open(OUT, "w"), indent=1)
for r in results:
    print(json.dumps({k: r[k] for k in ("case", "first_frame_s", "exit", "out_len") if k in r},),
          "sigterm" if r.get("needed_sigterm") else "")
