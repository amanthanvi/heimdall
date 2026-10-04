#!/usr/bin/env python3
"""Job-control probe: does `run` steal the terminal from the other members of
its own shell pipeline? Interactive bash (no rc files) in a fresh pty.

Usage: pipeline_tty_probe.py <bin> <out-json>
"""
import json, os, pty, select, signal, sys, time, tempfile

BIN, OUT = sys.argv[1], sys.argv[2]
tmp = tempfile.mkdtemp(prefix="hrg-pty-")


def session(cmdline, feed_after=0.6, feed=b"hello\n", wait=6.0):
    pid, fd = pty.fork()
    if pid == 0:
        sh_keep = os.environ.get("PROBE_SHELL", "/bin/bash"); os.environ.clear(); os.environ["PROBE_SHELL"] = sh_keep
        os.environ.update({"PATH": "/usr/bin:/bin", "HOME": tmp, "TERM": "xterm", "PS1": "PROMPT$ ", "LANG": "C.UTF-8"})
        sh = os.environ.get("PROBE_SHELL", "/bin/bash"); os.execv(sh, [sh, "-i"] if not sh.endswith("bash") else ["bash", "--norc", "--noprofile", "-i"])
    buf = bytearray()

    def pump(t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    b = os.read(fd, 4096)
                except OSError:
                    return
                if not b:
                    return
                buf.extend(b)

    pump(0.8)
    os.write(fd, cmdline.encode() + b"\n")
    pump(feed_after)
    os.write(fd, feed)
    t0 = time.monotonic()
    got_at = None
    end = t0 + wait
    while time.monotonic() < end:
        pump(0.1)
        if b"GOT:hello" in buf and got_at is None:
            got_at = time.monotonic() - t0
            pump(0.5)
            break
    # try to recover: fg any stopped job, feed again
    for c in (b"jobs -l\n", b"exit\n", b"exit\n"):
        try:
            os.write(fd, c)
        except OSError:
            break
        pump(0.5)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(fd)
    text = buf.decode("utf-8", "replace")
    return {"cmd": cmdline, "got_line_after_s": None if got_at is None else round(got_at, 3),
            "transcript_tail": text[-900:]}


rd = "/bin/sh -c 'sleep 0.3; read x </dev/tty; echo GOT:$x'"
cases = {
    "control_sleep_pipe_tty_reader": session("sleep 1.5 | " + rd),
    "heimdall_run_pipe_tty_reader": session(BIN + " run -- sleep 1.5 | " + rd),
    "control_tty_reader_pipe_cat": session(rd + " | cat"),
    "heimdall_tty_reader_pipe_run_cat": session(rd + " | " + BIN + " run -- cat"),
    "control_slow_tty_reader_pipe_sleep": session("/bin/sh -c 'sleep 1; read x </dev/tty; echo GOT:$x >/dev/tty' | sleep 3", feed_after=1.6),
    "heimdall_slow_tty_reader_pipe_run_sleep": session("/bin/sh -c 'sleep 1; read x </dev/tty; echo GOT:$x >/dev/tty' | " + BIN + " run -- sleep 3", feed_after=1.6),
}
cases["heimdall_first_slow_reader"] = session(BIN + " run -- sleep 3 | /bin/sh -c 'sleep 1; read x </dev/tty; echo GOT:$x'", feed_after=1.6)
json.dump({"bin": BIN, "cases": cases}, open(OUT, "w"), indent=1)
for k, v in cases.items():
    print(k, "GOT after", v["got_line_after_s"])
    print("  tail:", repr(v["transcript_tail"][-400:]))
