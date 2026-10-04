#!/usr/bin/env python3
"""Reviewer-2 TUI probe: signals outside K10's list (QUIT, TSTP/CONT, USR1) and K10 ones (TERM, HUP, INT
by kill) sent to the TUI pid; checks exit status, stdout bytes after the last alternate-screen leave,
and whether the pty's termios equals the original afterwards.
Usage: tui_signal_probe.py BIN PROFILE OUT.json"""
import json, os, select, signal, struct, sys, termios, time, fcntl, tty
BIN, PROF, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
res = []


def drain(fd, t):
    out = b""
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                b = os.read(fd, 65536)
            except OSError:
                break
            if not b:
                break
            out += b
    return out


def case(name, sigs):
    m, s = os.openpty()
    fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    orig = termios.tcgetattr(s)
    pid = os.fork()
    if pid == 0:
        os.setsid()
        fcntl.ioctl(s, termios.TIOCSCTTY, 0)
        for fd in (0, 1, 2):
            os.dup2(s, fd)
        os.close(m)
        os.execve(BIN, [BIN, "tui", "--file", PROF], {"PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "C.UTF-8", "NO_COLOR": "1"})
    out = drain(m, 1.0)
    st = None
    steps = []
    for sg in sigs:
        os.kill(pid, sg)
        out += drain(m, 0.4)
        done, stt = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        if done:
            if os.WIFSTOPPED(stt):
                steps.append(("stopped", os.WSTOPSIG(stt)))
            else:
                st = stt
                steps.append(("exited", os.waitstatus_to_exitcode(stt)))
                break
        else:
            steps.append(("running", None))
    if st is None:
        # still running: quit with 'q'
        try:
            os.write(m, b"q")
            steps.append(("sent_q", None))
        except OSError as e:
            steps.append(("write_q_failed", e.errno))
        done = 0
        end = time.time() + 5
        while not done and time.time() < end:
            out += drain(m, 0.1)
            done, st = os.waitpid(pid, os.WNOHANG)
        if not done:
            os.kill(pid, signal.SIGKILL)
            _, st = os.waitpid(pid, 0)
            steps.append(("killed_by_probe", None))
        steps.append(("final", os.waitstatus_to_exitcode(st)))
    out += drain(m, 0.2)
    try:
        now = termios.tcgetattr(s)
    except termios.error:
        now = None  # darwin revokes the slave when the session leader exits
    last_leave = out.rfind(b"\x1b[?1049l")
    r = {"case": name, "steps": steps, "final_exit": os.waitstatus_to_exitcode(st),
         "termios_restored": (now == orig) if now is not None else "unobservable (slave revoked)", "left_alt_screen": last_leave >= 0,
         "cursor_shown_after": b"\x1b[?25h" in out[last_leave:] if last_leave >= 0 else False,
         "bytes_after_leave_hex": out[last_leave + 8:][:80].hex() if last_leave >= 0 else None}
    res.append(r)
    print(json.dumps(r), flush=True)
    os.close(m); os.close(s)


case("kill_TERM", [signal.SIGTERM])
case("kill_HUP", [signal.SIGHUP])
case("kill_INT", [signal.SIGINT])
case("kill_QUIT", [signal.SIGQUIT])
case("kill_USR1", [signal.SIGUSR1])
case("kill_TSTP_then_CONT", [signal.SIGTSTP, signal.SIGCONT])
case("kill_WINCH_x3", [signal.SIGWINCH, signal.SIGWINCH, signal.SIGWINCH])
json.dump({"bin": BIN, "platform": sys.platform, "results": res}, open(OUT, "w"), indent=1)
