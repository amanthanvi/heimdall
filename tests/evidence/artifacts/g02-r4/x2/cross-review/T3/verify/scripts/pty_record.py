"""M00-T05-r4-x2-xrev-T3-verify: run one heimdall-proto build in a fresh pty of a given size, send keys
one at a time, and record the exact bytes the program writes to the pty after each key. Nothing
interprets the bytes here; the recording is fed to xterm.js (xterm_replay.js) afterwards.

Usage: python3 -I pty_record.py --bin <path> --profile <toml> --size <cols>x<rows> --term <TERM>
                              --sandbox-root <dir> --out <file.json> <key>...
  keys: enter, bs, esc, ctrl-c, up, down, or a literal character (UTF-8).

Environment of the program (the same as the cross-review's pyte sessions): PATH=/usr/bin:/bin, a private
HOME and TMPDIR under a fresh sandbox, LANG=LC_ALL=en_US.UTF-8, TERM as given; no SSH_AUTH_SOCK.
The profile is copied into the sandbox. After the keys, Ctrl-C is sent and the exit status recorded.
Output JSON: per-key chunks (base64 and a readable escape), the full stream (base64), rc, and a redacted
stderr tail. Paths in the output are redacted to <sandbox>.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

KEYS = {"enter": b"\r", "bs": b"\x7f", "esc": b"\x1b", "ctrl-c": b"\x03", "up": b"\x1b[A", "down": b"\x1b[B"}


def drain(master, quiet, maxwait, poll_exit=None):
    """Read from the master until no byte arrived for `quiet` s (or `maxwait` s in total)."""
    buf = bytearray()
    t_end = time.monotonic() + maxwait
    last = time.monotonic()
    while time.monotonic() < t_end:
        r, _, _ = select.select([master], [], [], 0.02)
        if r:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            buf += data
            last = time.monotonic()
        elif time.monotonic() - last >= quiet:
            break
        if poll_exit is not None and poll_exit() is not None and not r:
            break
    return bytes(buf)


def esc(b):
    return b.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--size", required=True)
    ap.add_argument("--term", default="xterm-256color")
    ap.add_argument("--sandbox-root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--settle", type=float, default=0.4, help="quiet time after a key before the next one")
    ap.add_argument("keys", nargs="+")
    a = ap.parse_args()
    cols, rows = map(int, a.size.split("x"))

    sandbox = tempfile.mkdtemp(prefix="hv-", dir=a.sandbox_root)
    os.mkdir(os.path.join(sandbox, "home"))
    os.mkdir(os.path.join(sandbox, "tmp"))
    prof = os.path.join(sandbox, os.path.basename(a.profile))
    shutil.copyfile(a.profile, prof)
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(sandbox, "home"), "LANG": "en_US.UTF-8",
           "LC_ALL": "en_US.UTF-8", "TMPDIR": os.path.join(sandbox, "tmp"), "TERM": a.term}

    master, slave = os.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    p = subprocess.Popen([a.bin, "tui", "--file", prof], env=env, cwd=sandbox, stdin=slave, stdout=slave,
                         stderr=subprocess.PIPE, start_new_session=True)
    os.close(slave)
    chunks = []
    full = bytearray()
    t0 = time.monotonic()
    data = drain(master, quiet=0.5, maxwait=5.0, poll_exit=p.poll)
    chunks.append({"key": "start", "ms": round((time.monotonic() - t0) * 1000), "n": len(data),
                   "b64": base64.b64encode(data).decode(), "esc": esc(data)})
    full += data
    for k in a.keys:
        b = KEYS.get(k, k.encode("utf-8"))
        t0 = time.monotonic()
        os.write(master, b)
        data = drain(master, quiet=a.settle, maxwait=2.5, poll_exit=p.poll)
        chunks.append({"key": k, "sent": esc(b), "ms": round((time.monotonic() - t0) * 1000), "n": len(data),
                       "b64": base64.b64encode(data).decode(), "esc": esc(data)})
        full += data
    # exit: Ctrl-C, then wait; only our own child is ever signalled
    rc = None
    try:
        os.write(master, b"\x03")
    except OSError:
        pass
    data = drain(master, quiet=0.3, maxwait=3.0, poll_exit=p.poll)
    full += data
    try:
        rc = p.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        p.send_signal(signal.SIGTERM)
        try:
            rc = p.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = p.wait(timeout=2.0)
    # drain whatever is left so the child never blocks on exit
    try:
        os.set_blocking(master, False)
        while True:
            d = os.read(master, 65536)
            if not d:
                break
            full += d
    except OSError:
        pass
    os.close(master)
    err = b""
    if p.stderr is not None:
        try:
            err = p.stderr.read() or b""
        except Exception:  # noqa
            err = b""
    def red(s):
        return s.replace(sandbox, "<sandbox>").replace(os.path.expanduser("~"), "<home>")
    out = {"bin": red(a.bin), "sha256": hashlib.sha256(open(a.bin, "rb").read()).hexdigest(),
           "size": a.size, "term": a.term, "profile": os.path.basename(a.profile), "keys": a.keys,
           "chunks": chunks, "full_b64": base64.b64encode(bytes(full)).decode(), "rc": rc,
           "exit_tail_esc": esc(data), "stderr_tail": red(err[-400:].decode("utf-8", "replace"))}
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    shutil.rmtree(sandbox, ignore_errors=True)
    print("%s rc=%s chunks=%s" % (os.path.basename(a.out), rc, [c["n"] for c in chunks]))


if __name__ == "__main__":
    main()
