#!/usr/bin/env python3
"""pty-drive.py TRANSCRIPT TIMEOUT NEEDLE ANSWER [NEEDLE ANSWER ...] -- PROGRAM ARG...: run PROGRAM on a
fresh pseudo-terminal and type ANSWER once per new occurrence of NEEDLE (non-secret answers only).
The exit code is the program's, 124 on timeout. Copied from tests/native/m03/scenario-managed.sh."""
import os, pty, select, signal, sys, time
a = sys.argv[1:]
sep = a.index("--")
transcript, timeout, pairs, program = a[0], float(a[1]), a[2:sep], a[sep + 1:]
pairs = [(pairs[i].encode(), pairs[i + 1].encode() + b"\n") for i in range(0, len(pairs), 2)]
pid, fd = pty.fork()
if pid == 0:
    try:
        os.execvp(program[0], program)
    finally:
        os._exit(127)
out, seen, status = bytearray(), {}, None
deadline = time.monotonic() + timeout
while status is None:
    r, _, _ = select.select([fd], [], [], 0.05)
    if r:
        try:
            out.extend(os.read(fd, 4096))
        except OSError:
            pass
    for needle, answer in pairs:
        if out.count(needle) > seen.get(needle, 0):
            seen[needle] = out.count(needle)
            time.sleep(0.2)
            os.write(fd, answer)
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        status = st
        while select.select([fd], [], [], 0.1)[0]:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out.extend(chunk)
    elif time.monotonic() >= deadline:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        status = -1
open(transcript, "wb").write(bytes(out))
sys.exit(124 if status == -1 else (os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)))
