#!/usr/bin/env python3
"""Job-control shim used by the TUI checks (tests/g02/harness_lib.PtySession).

Acts like an interactive shell for ONE foreground job:
  * becomes the session leader owning the pty as controlling terminal
    (the harness passes the pty slave as stdin/stdout),
  * runs the command in its own process group and makes that group the
    foreground group of the terminal (so Ctrl-C reaches it exactly as in a shell),
  * reports the command pid and its wait status as JSON lines on a status pipe,
  * like a shell, passes a terminal hangup (SIGHUP to the session leader when
    the pty master is closed) on to the job's process group as SIGHUP,
  * stays alive (keeping the terminal un-hung-up) until the harness closes the
    control pipe, so the harness can still read the pty's termios after the
    command exited.  On macOS the tty is revoked when the session leader exits,
    which is why the command cannot itself be the session leader.

Usage: pty_shim.py CTL_FD STATUS_FD [--no-hup-forward] -- command [args...]
  --no-hup-forward  do not pass a hangup on (models a session leader that is not a
                    shell: the job then only sees EOF/EIO on the terminal)
"""
import fcntl
import json
import os
import signal
import subprocess
import sys
import termios


def main():
    ctl, status = int(sys.argv[1]), int(sys.argv[2])
    sep = sys.argv.index("--")
    cmd = sys.argv[sep + 1:]
    hup_forward = "--no-hup-forward" not in sys.argv[3:sep]
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    def pre():
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTTOU, signal.SIGTTIN})
        os.setpgid(0, 0)
        os.tcsetpgrp(0, os.getpid())
        signal.pthread_sigmask(signal.SIG_SETMASK, old)
        for sg in (signal.SIGTTOU, signal.SIGTTIN, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
            signal.signal(sg, signal.SIG_DFL)   # SIG_IGN would survive exec; the job gets defaults

    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    signal.signal(signal.SIGTTIN, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)   # the shim itself must survive terminal signals
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
    try:
        p = subprocess.Popen(cmd, preexec_fn=pre, restore_signals=True)
    except OSError as exc:
        os.write(status, (json.dumps({"event": "launch_failed", "error": repr(exc)}) + "\n").encode())
        return 127
    def on_hup(signum, frame):
        # Like an interactive shell: a terminal hangup (SIGHUP to the session leader when
        # the pty master closes) is passed on to the foreground job.
        for sg in (signal.SIGHUP, signal.SIGCONT):
            try:
                os.killpg(p.pid, sg)
            except (ProcessLookupError, PermissionError):
                pass

    if hup_forward:
        signal.signal(signal.SIGHUP, on_hup)
    os.write(status, (json.dumps({"event": "started", "pid": p.pid}) + "\n").encode())
    rc = p.wait()
    os.write(status, (json.dumps({"event": "exited", "rc": rc}) + "\n").encode())
    try:
        os.read(ctl, 1)  # block until the harness closes the control pipe
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
