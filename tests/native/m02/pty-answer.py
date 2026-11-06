#!/usr/bin/env python3
"""Run one command on a fresh pseudo-terminal and answer its confirmation prompts.

Usage: pty-answer.py TRANSCRIPT ANSWER TIMEOUT_S -- PROGRAM [ARG]...

Whenever a new `[y/N]` prompt appears on the terminal, ANSWER and a newline are typed
once (the heimdall CLI's typed-yes contract, ADR-0006 §3.1). The whole terminal output
is written to TRANSCRIPT. The exit status is the program's; 124 when it did not exit
within TIMEOUT_S seconds (it is then killed through its own PID, the forked child);
128+N when a signal N ended it. Used by scenario-ordinary-ssh.sh (m02-plan §4).
"""

import os
import pty
import select
import signal
import sys
import time


def main(argv):
    if len(argv) < 6 or argv[4] != "--":
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    transcript, answer, timeout = argv[1], argv[2].encode() + b"\n", float(argv[3])
    program = argv[5:]
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(program[0], program)
        finally:
            os._exit(127)
    out = bytearray()
    answered = 0
    deadline = time.monotonic() + timeout
    status = None
    while True:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if chunk:
                out.extend(chunk)
        if out.count(b"[y/N]") > answered:
            os.write(fd, answer)
            answered += 1
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            # Drain what is left on the terminal.
            while True:
                r, _, _ = select.select([fd], [], [], 0.1)
                if not r:
                    break
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out.extend(chunk)
            break
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            with open(transcript, "wb") as f:
                f.write(bytes(out))
            return 124
    with open(transcript, "wb") as f:
        f.write(bytes(out))
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 128 + os.WTERMSIG(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
