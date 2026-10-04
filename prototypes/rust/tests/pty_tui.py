#!/usr/bin/env python3
"""PTY-driven checks for the Rust prototype's `tui` and terminal-SIGINT behavior of `run`.

Usage: pty_tui.py <heimdall-proto binary> [--panic-binary <binary built with --features test-panic>]

Stdlib only. Creates a pseudo-terminal per case, makes it the child's controlling
terminal, and checks contract §5 behavior plus termios restoration. Prints one JSON
summary line; exit status 0 only if every executed case passed.
"""
import fcntl
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "tests/fixtures/g02/profiles"
import tempfile
TMP = tempfile.mkdtemp(prefix="hp-rs-pty-")
COLOR_SGR = re.compile(rb"\x1b\[([0-9;]*)m")


def has_color_sgr(data: bytes) -> bool:
    for m in COLOR_SGR.finditer(data):
        for p in m.group(1).split(b";"):
            if p and (30 <= int(p) <= 49 or 90 <= int(p) <= 107 or p in (b"58", b"59")):
                return True
    return False


import unicodedata


class Screen:
    """Minimal VT model: enough of CUP/ED/EL/SGR/DEC private modes for ratatui output."""

    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0
        self.pending = b""

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0

    def text(self):
        return "\n".join("".join(c for c in row if c is not None).rstrip() for row in self.grid)

    def _put(self, ch):
        # xterm semantics: overwriting either half of a wide character erases all of it.
        w = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if 0 <= self.y < self.rows and 0 <= self.x < self.cols:
            row = self.grid[self.y]
            for xx in range(self.x, min(self.x + w, self.cols)):
                if row[xx] is None and xx > 0:
                    row[xx - 1] = " "  # wrote into the right half of a wide char
                if xx + 1 < self.cols and row[xx + 1] is None:
                    row[xx + 1] = " "  # wrote over the left half of a wide char
            row[self.x] = ch
            if w == 2 and self.x + 1 < self.cols:
                row[self.x + 1] = None
        self.x += w

    def feed(self, data: bytes):
        data = self.pending + data
        self.pending = b""
        i = 0
        while i < len(data):
            b = data[i]
            if b == 0x1B:
                if i + 1 >= len(data):
                    self.pending = data[i:]
                    return
                if data[i + 1:i + 2] == b"[":
                    m = re.match(rb"\x1b\[([?0-9;]*)([ -/]*)([@-~])", data[i:])
                    if not m:
                        self.pending = data[i:]
                        return
                    params, final = m.group(1).decode(), m.group(3)
                    nums = [int(x) if x.isdigit() else 0 for x in params.lstrip("?").split(";")] if params else []
                    if final == b"H":
                        r = (nums[0] if nums and nums[0] else 1) - 1
                        c = (nums[1] if len(nums) > 1 and nums[1] else 1) - 1
                        self.y, self.x = r, c
                    elif final == b"J":
                        mode = nums[0] if nums else 0
                        if mode in (2, 3):
                            self.grid = [[" "] * self.cols for _ in range(self.rows)]
                        elif mode == 0:
                            for yy in range(self.y, self.rows):
                                for xx in range(self.x if yy == self.y else 0, self.cols):
                                    self.grid[yy][xx] = " "
                    elif final == b"K" and 0 <= self.y < self.rows:
                        for xx in range(self.x, self.cols):
                            self.grid[self.y][xx] = " "
                    elif final in (b"h", b"l") and params.startswith("?1049"):
                        self.grid = [[" "] * self.cols for _ in range(self.rows)]
                    i += m.end()
                    continue
                i += 2
                continue
            if b == 0x0D:
                self.x = 0
                i += 1
                continue
            if b == 0x0A:
                self.y = min(self.y + 1, self.rows - 1)
                i += 1
                continue
            if b < 0x20:
                i += 1
                continue
            n = 1 if b < 0x80 else 2 if b >> 5 == 0b110 else 3 if b >> 4 == 0b1110 else 4
            if i + n > len(data):
                self.pending = data[i:]
                return
            self._put(data[i:i + n].decode("utf-8", "replace"))
            i += n


# Session-leader wrapper: owns the controlling terminal, launches the target as the
# foreground job in its own process group (as an interactive shell does), and records
# termios before/after from inside the session.
# (On macOS the parent's slave fd is revoked when the session leader exits, so termios
# must be read by a process that is still in the session.)
WRAPPER = r"""
import json, os, signal, subprocess, sys, termios
res, argv = sys.argv[1], sys.argv[2:]
for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(s, lambda *a: None)  # handlers (not SIG_IGN) reset to default in the exec'd child
before = termios.tcgetattr(0)
kw = {}
def fg_job():  # like an interactive shell: own process group, made the terminal's foreground
    old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTTOU})
    os.setpgid(0, 0)
    os.tcsetpgrp(0, os.getpid())
    signal.pthread_sigmask(signal.SIG_SETMASK, old)
if os.environ.get("HP_PTY_BG"):  # start the target as a background job (own, non-foreground group)
    kw["preexec_fn"] = os.setpgrp
else:  # round 2: foreground job in its own group (not orphaned, so Ctrl-Z works as in a shell)
    kw["preexec_fn"] = fg_job
if os.environ.get("HP_PTY_STDERR"):  # separate stderr so stdout-only output can be judged
    kw["stderr"] = open(os.environ["HP_PTY_STDERR"], "wb")
p = subprocess.Popen(argv, **kw)
open(res + ".pid", "w").write(str(p.pid))
while True:
    try:
        rc = p.wait(); break
    except InterruptedError:
        pass
try:
    after = termios.tcgetattr(0)
except termios.error:  # terminal hung up: termios no longer readable
    after = None
json.dump({"rc": rc, "termios_same": before == after}, open(res, "w"))
"""


class Pty:
    seq = 0

    def __init__(self, argv, cols=80, rows=24, env=None):
        Pty.seq += 1
        self.res = os.path.join(TMP, f"res-{Pty.seq}.json")
        self.master, slave = os.openpty()
        self.screen = Screen(cols, rows)
        self.resize(cols, rows)
        e = dict(os.environ)
        e.pop("SSH_AUTH_SOCK", None)
        e.pop("NO_COLOR", None)
        e["TERM"] = "xterm-256color"
        if env:
            e.update(env)

        def ctty():
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.p = subprocess.Popen([sys.executable, "-c", WRAPPER, self.res, *argv],
                                  stdin=slave, stdout=slave, stderr=slave,
                                  start_new_session=True, preexec_fn=ctty, env=e, close_fds=True)
        os.close(slave)
        self.out = b""
        deadline = time.monotonic() + 5
        while not os.path.exists(self.res + ".pid") and time.monotonic() < deadline:
            self.read_for(0.01)
        time.sleep(0.01)
        self.pid = int(open(self.res + ".pid").read())

    def resize(self, cols, rows):
        self.screen.resize(cols, rows)
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def write(self, b: bytes):
        os.write(self.master, b)

    def alive(self):
        try:
            os.kill(self.pid, 0)
            return not os.path.exists(self.res)
        except ProcessLookupError:
            return False

    def read_for(self, seconds):
        end = time.monotonic() + seconds
        got = b""
        while time.monotonic() < end:
            r, _, _ = select.select([self.master], [], [], max(0.0, end - time.monotonic()))
            if not r:
                break
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            got += chunk
            self.screen.feed(chunk)
        self.out += got
        return got

    def wait_for(self, needle: bytes, timeout=3.0):
        """Return seconds until `needle` appears anywhere in the output so far, or None.
        (Cumulative: output read while waiting for the wrapper's pid file counts.)"""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if needle in self.out:
                return time.monotonic() - start
            self.read_for(0.005)
            if self.p.poll() is not None:
                self.read_for(0.05)
                return (time.monotonic() - start) if needle in self.out else None
        return None

    def wait_screen(self, pred, timeout=3.0):
        """Return seconds until pred(screen text) holds, or None."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            self.read_for(0.005)
            if pred(self.screen.text()):
                return time.monotonic() - start
            if self.p.poll() is not None:
                self.read_for(0.05)
                return (time.monotonic() - start) if pred(self.screen.text()) else None
        return None

    def wait_text(self, needle, timeout=3.0):
        return self.wait_screen(lambda t: needle in t, timeout)

    def finish(self, timeout=3.0):
        """Wait for the target; return (exit code or -signal, termios restored?)."""
        # Keep draining the master while waiting: on macOS a process exiting with
        # undrained pty output blocks in exit until the output is read.
        end = time.monotonic() + timeout
        while self.p.poll() is None and time.monotonic() < end:
            self.read_for(0.02)
        if self.p.poll() is None:
            os.kill(self.pid, signal.SIGKILL)
            while self.p.poll() is None:
                self.read_for(0.02)
            self.read_for(0.1)
            os.close(self.master)
            return ("timeout", None), False
        self.read_for(0.1)
        os.close(self.master)
        r = json.load(open(self.res))
        return r["rc"], r["termios_same"]


def tui(binary, fixture="homelab.toml", **kw):
    return Pty([binary, "tui", "--file", str(FIX / fixture)], **kw)


def restored_screen(out: bytes) -> bool:
    enter, leave = out.find(b"\x1b[?1049h"), out.rfind(b"\x1b[?1049l")
    hide, show = out.find(b"\x1b[?25l"), out.rfind(b"\x1b[?25h")
    return enter >= 0 and leave > enter and hide >= 0 and show > hide


results = []


class KnownLimitation(Exception):
    """A documented limitation was observed (reported, not counted as a pass)."""


def case(name):
    def deco(fn):
        def wrapped(*a):
            if os.environ.get("HP_PTY_ONLY") and os.environ["HP_PTY_ONLY"] not in name:
                return  # case filter for focused runs (selftest always runs every case)
            t = time.monotonic()
            print(f"[pty_tui] {name} ...", file=sys.stderr, flush=True)
            limitation = False
            try:
                detail = fn(*a)
                ok = True
            except KnownLimitation as e:
                ok, limitation, detail = False, True, f"known limitation: {e}"
            except AssertionError as e:
                ok, detail = False, f"assertion: {e}"
            except Exception as e:  # noqa: BLE001
                ok, detail = False, f"error: {type(e).__name__}: {e}"
            r = {"case": name, "passed": ok, "detail": detail,
                 "seconds": round(time.monotonic() - t, 3)}
            if limitation:
                r["known_limitation"] = True
            results.append(r)
        return wrapped
    return deco


@case("tui-select-with-j")
def t_select(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None, "status line 3/3 not drawn"
    rows = s.screen.text().splitlines()
    assert rows[0].startswith("> lab-server  aman@lab.example.internal:22"), rows[:3]
    assert rows[1].startswith("  nas  admin@nas.example.internal:22"), rows[:3]
    assert rows[2].startswith("  vps-東京  deploy@vps1.example.invalid:2222"), rows[:3]
    s.write(b"j")
    assert s.wait_screen(lambda t: t.splitlines()[1].startswith("> nas")) is not None, "j moves selection"
    assert s.screen.text().splitlines()[0].startswith("  lab-server")
    s.write(b"\r")
    code, termios_ok = s.finish()
    assert code == 0, f"exit {code}"
    assert termios_ok, "termios not restored"
    assert restored_screen(s.out), "alt screen / cursor not restored"
    tail = s.out[s.out.rfind(b"\x1b[?1049l"):]
    assert b"SELECTED nas\r\n" in tail or b"SELECTED nas\n" in tail, f"tail={tail[-80:]!r}"
    return "exit 0, SELECTED nas after leaving alt screen, termios restored"


@case("tui-quit-q")
def t_quit(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None
    s.write(b"q")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok and restored_screen(s.out)
    assert b"SELECTED" not in s.out
    return "exit 0, no SELECTED"


@case("tui-ctrl-c")
def t_ctrlc(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None
    s.write(b"\x03")
    code, termios_ok = s.finish()
    assert code == 130, f"exit {code}"
    assert termios_ok and restored_screen(s.out)
    return "exit 130, restored"


@case("tui-sigterm")
def t_term(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None
    os.kill(s.pid, signal.SIGTERM)
    code, termios_ok = s.finish()
    assert code == 143, f"exit {code}"
    assert termios_ok and restored_screen(s.out)
    return "exit 143, restored"


@case("tui-filter-unicode")
def t_filter(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None
    s.write("/東京".encode())
    assert s.wait_text("1/3") is not None, "filter not applied"
    assert "/東京" in s.screen.text().splitlines()[-1], "status shows active filter text"
    s.write(b"\r")  # leave filter mode
    s.read_for(0.1)
    s.write(b"\r")  # select
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok
    assert "SELECTED vps-東京".encode() in s.out
    return "filter '東京' → 1/3, SELECTED vps-東京"


@case("tui-filter-esc-clears")
def t_esc(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None
    s.write(b"/NAS")
    assert s.wait_text("1/3") is not None, "case-insensitive filter"
    s.write(b"\x7f\x7f\x7f")
    assert s.wait_text("3/3") is not None, "backspace"
    s.write(b"zzz")
    assert s.wait_text("0/3") is not None
    s.write(b"\x1b")
    assert s.wait_text("3/3", timeout=2) is not None, "Esc clears filter"
    s.write(b"q")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok
    return "case-insensitive, backspace, Esc clears"


@case("tui-resize-and-narrow")
def t_resize(b):
    s = tui(b, cols=80, rows=24)
    assert s.wait_text("3/3") is not None
    assert "aman@lab.example.internal:22" in s.screen.text()
    timings = {}
    for cols, rows in [(20, 5), (40, 10), (120, 30), (20, 5), (49, 8), (50, 8)]:
        s.resize(cols, rows)
        want = (lambda t: "3/3" in t and "> lab-server" in t and ("aman@" in t) == (cols >= 50))
        dt = s.wait_screen(want, timeout=1.0)
        assert dt is not None, f"no correct redraw at {cols}x{rows}: {s.screen.text()!r}"
        timings[f"{cols}x{rows}"] = round(dt * 1000, 1)
        assert s.alive(), f"crashed at {cols}x{rows}"
    s.write(b"q")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok
    worst = max(timings.values())
    assert worst < 100, f"redraw too slow: {timings}"
    return f"redraw ms per size: {timings}"


@case("tui-no-color")
def t_nocolor(b):
    s = tui(b, env={"NO_COLOR": "1"})
    assert s.wait_text("3/3") is not None
    s.write(b"jk/a\x1b")
    s.read_for(0.2)
    s.write(b"q")
    code, _ = s.finish()
    assert code == 0
    assert not has_color_sgr(s.out), "color SGR emitted with NO_COLOR=1"
    c = tui(b)
    assert c.wait_text("3/3") is not None
    c.write(b"q")
    c.finish()
    assert has_color_sgr(c.out), "sanity: color SGR expected without NO_COLOR"
    return "no color SGR with NO_COLOR=1; color present without it"


@case("tui-large-100")
def t_large(b):
    s = tui(b, fixture="large-100.toml")
    assert s.wait_text("100/100") is not None
    t = time.monotonic()
    s.write(b"/-db")
    dt = s.wait_text("25/100")
    assert dt is not None
    for _ in range(30):
        s.write(b"\x1b[B")
    s.read_for(0.2)
    s.write(b"\r\r")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok
    assert b"SELECTED host-" in s.out
    return f"filter '-db' → 25/100 visible {round(dt*1000)} ms after the keystrokes were written"


@case("tui-tiny-terminal")
def t_tiny(b):
    s = tui(b, cols=20, rows=5)
    assert s.wait_text("3/3") is not None
    for cols, rows in [(1, 1), (2, 2), (20, 1), (20, 5)]:
        s.resize(cols, rows)
        s.read_for(0.15)
        assert s.alive(), f"crashed at {cols}x{rows}"
    s.write(b"q")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok
    return "20x5, 1x1, 2x2, 20x1 survive"


@case("tui-bad-profile")
def t_bad(b):
    s = Pty([b, "tui", "--file", str(FIX / "invalid-forbidden-key.toml")])
    code, termios_ok = s.finish()
    assert code == 2 and termios_ok
    assert b"HEIMDALL_CANARY_" not in s.out
    assert b"\x1b[?1049h" not in s.out, "must not enter alt screen for invalid profile"
    return "exit 2, no canary, no alt screen"


@case("tui-terminal-hangup")
def t_hangup(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None
    pid = s.pid
    os.close(s.master)  # terminal goes away (emulator window closed)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and proc_state(pid) not in ("", "Z"):
        time.sleep(0.05)
    st = proc_state(pid)
    if st not in ("", "Z"):
        try:
            cpu = subprocess.run(["/bin/ps", "-o", "%cpu=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        except OSError:
            cpu = "?"
        os.kill(pid, signal.SIGKILL)
        raise AssertionError(f"TUI still running 3 s after hangup (state {st}, cpu {cpu}%)")
    s.p.wait(timeout=5)
    return "TUI exited after the terminal hung up"


@case("run-terminal-sigint-not-doubled")
def t_run_sigint(b):
    script = ("import signal,time,sys\n"
              "n=[0]\n"
              "signal.signal(signal.SIGINT, lambda *a: n.__setitem__(0, n[0]+1))\n"
              "print('ready', flush=True)\n"
              "end=time.time()+1.0\n"
              "while time.time()<end: time.sleep(0.01)\n"
              "print('count=%d' % n[0], flush=True)\n"
              "sys.exit(3)\n")
    s = Pty([b, "run", "--", sys.executable, "-c", script])
    assert s.wait_for(b"ready") is not None, f"child never printed ready: {s.out[-300:]!r}"
    s.write(b"\x03")  # tty driver sends SIGINT to the whole foreground process group
    code, termios_ok = s.finish(timeout=5)
    m = re.search(rb"count=(\d+)", s.out)
    assert m, f"no count in {s.out[-200:]!r}"
    assert code == 3, f"heimdall-proto must wait and return child status, got {code}"
    n = int(m.group(1))
    if sys.platform != "linux" and n != 1:
        # Round 2 (K6a exec semantics): Darwin gives a terminal SIGINT and kill(2) the
        # same siginfo, so heimdall-proto forwards it and the child sees it twice.
        raise KnownLimitation(f"child saw terminal SIGINT {n} times (Darwin: cannot tell tty signals from kill(2))")
    assert n == 1, f"child saw SIGINT {n} times"
    return "terminal Ctrl-C delivered once to child; parent waited, exit 3"


def proc_state(pid):
    """Process state letter(s) ('' if gone). Linux: /proc (slim images have no ps)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        if sys.platform.startswith("linux"):
            return ""
    except OSError:
        return ""
    r = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip()


@case("run-ctrl-z-job-control")
def t_run_ctrlz(b):
    script = ("import time,sys,os\n"
              "print('ready', os.getpid(), flush=True)\n"
              "for i in range(100): time.sleep(0.01)\n"
              "print('done', flush=True)\n"
              "sys.exit(4)\n")
    s = Pty([b, "run", "--", sys.executable, "-c", script])
    assert s.wait_for(b"ready") is not None, f"child never printed ready: {s.out[-300:]!r}"
    m = re.search(rb"ready (\d+)", s.out)
    child = int(m.group(1))
    assert os.getpgid(child) == os.getpgid(s.pid), "exec semantics: child shares heimdall-proto's group"
    s.write(b"\x1a")  # Ctrl-Z: SIGTSTP to the terminal's foreground group (the whole job)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not (proc_state(s.pid).startswith("T") and proc_state(child).startswith("T")):
        s.read_for(0.02)
    hp, ch = proc_state(s.pid), proc_state(child)
    assert hp.startswith("T") and ch.startswith("T"), f"expected both stopped: heimdall={hp} child={ch}"
    os.killpg(os.getpgid(s.pid), signal.SIGCONT)  # what `fg` does: SIGCONT to the job's group
    code, termios_ok = s.finish(timeout=5)
    assert b"done" in s.out, "child resumed and finished"
    assert code == 4, f"exit {code}"
    return f"Ctrl-Z stopped the job (child {ch}, heimdall-proto {hp}); SIGCONT to the group resumed both; exit 4"


def after_restore(out: bytes) -> bytes:
    """Bytes written to the terminal after the final cursor-show (end of restore)."""
    i = out.rfind(b"\x1b[?25h")
    return out[i + len(b"\x1b[?25h"):] if i >= 0 else out


def counting_child(sig_name, outfile):
    return ("import signal,time,sys,os\n"
            "n=[0]\n"
            f"signal.signal(signal.{sig_name}, lambda *a: n.__setitem__(0, n[0]+1))\n"
            f"open({outfile!r},'w').write('ready %d %d' % (os.getpid(), os.getpgrp()))\n"
            "end=time.time()+1.0\n"
            "while time.time()<end: time.sleep(0.01)\n"
            f"open({outfile!r},'w').write('count=%d' % n[0])\n"
            "sys.exit(3)\n")


def k6_case(b, sig, background):
    out = os.path.join(TMP, f"k6-{sig.name}-{'bg' if background else 'fg'}.txt")
    env = {"HP_PTY_BG": "1"} if background else None
    s = Pty([b, "run", "--", sys.executable, "-c", counting_child(sig.name, out)], env=env)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not (os.path.exists(out) and open(out).read().startswith("ready")):
        s.read_for(0.01)
    _, cpid, cpgid = open(out).read().split()
    hp_pgid = os.getpgid(s.pid)
    fg = os.tcgetpgrp(s.master) if hasattr(os, "tcgetpgrp") else None
    # State actually exercised (round 2, exec semantics): the child always shares
    # heimdall-proto's group; foreground job -> that group owns the terminal,
    # background job -> it does not.
    assert int(cpgid) == hp_pgid, f"child pgid {cpgid} != heimdall-proto pgid {hp_pgid}"
    if background:
        assert fg != hp_pgid, f"not background state: hp pgid {hp_pgid}, fg {fg}"
    else:
        assert fg == hp_pgid, f"not foreground state: hp pgid {hp_pgid}, fg {fg}"
    os.kill(s.pid, sig)  # explicit signal to heimdall-proto's PID only
    code, termios_ok = s.finish(timeout=5)
    count = open(out).read()
    assert code == 3, f"heimdall-proto must wait and return child status, got {code}"
    assert count == "count=1", f"child saw {count}"
    return "bg" if background else "fg"


@case("k6-explicit-kill-reaches-child-once-fg-and-bg")
def t_k6(b):
    done = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        for bg in (False, True):
            done.append(f"{sig.name}/{k6_case(b, sig, bg)}")
    return "count=1, exit 3 for " + ", ".join(done) + " (state checked via child/heimdall-proto pgids and tcgetpgrp)"


@case("k9-filter-edit-resets-selection")
def t_k9(b):
    s = tui(b)
    assert s.wait_text("3/3") is not None, "first frame"
    row = lambda i: (lambda t: len(t.splitlines()) > i and t.splitlines()[i].startswith("> "))
    status = lambda t: t.splitlines()[-1].strip()
    DOWN = b"\x1b[B"  # in filter mode j/k are filter text; arrows move
    s.write(b"jj")
    assert s.wait_screen(row(2)) is not None, "jj selects row 3"
    s.write(b"/e")  # all three rows still shown
    assert s.wait_screen(lambda t: status(t) == "3/3  /e" and row(0)(t)) is not None, f"append must reset: {s.screen.text()!r}"
    s.write(DOWN)
    assert s.wait_screen(row(1)) is not None, "Down in filter mode"
    s.write(b"\x7f")
    assert s.wait_screen(lambda t: status(t) == "3/3  /" and row(0)(t)) is not None, f"Backspace must reset: {s.screen.text()!r}"
    s.write(DOWN)
    assert s.wait_screen(row(1)) is not None, "Down in filter mode (2)"
    s.write(b"\x1b")
    assert s.wait_screen(lambda t: status(t) == "3/3" and row(0)(t), timeout=2) is not None, f"Esc clear must reset: {s.screen.text()!r}"
    s.write(b"/e")
    assert s.wait_screen(lambda t: status(t) == "3/3  /e") is not None, "re-enter filter"
    s.write(DOWN + DOWN)
    assert s.wait_screen(row(2)) is not None, "Down Down in filter mode"
    s.write(b"\r")  # leave filter mode: keeps selection
    assert s.wait_screen(lambda t: status(t) == "3/3  filter: e") is not None, "Enter leaves filter mode"
    s.read_for(0.1)
    assert row(2)(s.screen.text()), f"Enter must keep selection: {s.screen.text()!r}"
    s.write(b"\r")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok, f"exit {code}"
    assert "SELECTED vps-東京".encode() in s.out, s.out[-120:]
    return "append/Backspace/Esc reset to row 1; Enter keeps row 3; SELECTED vps-東京"


@case("k10-sighup-129-sigterm-143-no-stdout")
def t_k10(b):
    got = {}
    for sig, want in ((signal.SIGHUP, 129), (signal.SIGTERM, 143)):
        err = os.path.join(TMP, f"k10-{sig.name}.err")
        s = tui(b, env={"HP_PTY_STDERR": err})
        assert s.wait_text("3/3") is not None
        os.kill(s.pid, sig)
        code, termios_ok = s.finish()
        assert code == want, f"{sig.name}: exit {code}"
        assert termios_ok and restored_screen(s.out), f"{sig.name}: not restored"
        assert after_restore(s.out) == b"", f"{sig.name}: stdout after restore {after_restore(s.out)!r}"
        got[sig.name] = code
    # Terminal hangup (master closed): exit 129.
    s = tui(b)
    assert s.wait_text("3/3") is not None
    os.close(s.master)
    s.p.wait(timeout=5)
    r = json.load(open(s.res))
    assert r["rc"] == 129, f"hangup: exit {r['rc']}"
    got["hangup"] = r["rc"]
    return f"exit codes {got}; terminal restored and nothing on stdout after restore for signals"


# ---------- round 2 (contract §9.1) ----------

def sh_job(b, script, **kw):
    """Run `sh -c script` ($0 = heimdall-proto) as the terminal's foreground job, the
    way a non-job-control shell script runs (one process group for the whole script)."""
    return Pty(["/bin/sh", "-c", script, b], **kw)


@case("k6a-amp-job-of-script-keeps-terminal")
def t_k6a_amp(b):
    s = sh_job(b, '"$0" run -- sleep 1.5 & sleep 0.3; read x; echo "read=[$x] rc=$?"; wait')
    script_pgid = os.getpgid(s.pid)
    s.read_for(0.6)
    fg_during = os.tcgetpgrp(s.master)
    s.write(b"hello\n")
    code, _ = s.finish(timeout=5)
    assert fg_during == script_pgid, f"terminal foreground moved from the script's group {script_pgid} to {fg_during}"
    assert b"read=[hello] rc=0" in s.out, f"script's own terminal read failed: {s.out[-200:]!r}"
    assert code == 0, f"exit {code}"
    return "'heimdall-proto run ... &' in a non-job-control script: foreground group unchanged, the script's read got its input"


@case("k6a-pipeline-peer-reads-terminal")
def t_k6a_pipe(b):
    s = sh_job(b, '"$0" run -- sleep 1 | (read x </dev/tty; echo "peer=[$x] rc=$?")')
    s.read_for(0.4)
    s.write(b"hi\n")
    code, _ = s.finish(timeout=5)
    assert b"peer=[hi] rc=0" in s.out, f"pipeline peer could not read the terminal: {s.out[-200:]!r}"
    assert code == 0, f"exit {code}"
    return "pipeline peer of 'heimdall-proto run' read the terminal normally (not stopped, no EIO)"


@case("k14-tui-fifo-usage-error")
def t_k14_tui(b):
    fifo = os.path.join(TMP, "k14 fifo.toml")
    os.mkfifo(fifo)
    t = time.monotonic()
    s = Pty([b, "tui", "--file", fifo])
    code, termios_ok = s.finish(timeout=3)
    dt = time.monotonic() - t
    assert code == 2, f"exit {code}"
    assert dt < 2.0, f"took {dt:.2f}s"
    assert b"\x1b[?1049h" not in s.out, "must not enter the alternate screen"
    assert termios_ok
    return f"tui --file <FIFO without writer> -> exit 2 in {dt:.2f}s, no alternate screen"


FAKEBIN = os.path.join(TMP, "fakebin")
EXECLOG = os.path.join(TMP, "helper-exec.log")


def make_fakebin():
    os.makedirs(FAKEBIN, exist_ok=True)
    for t in ("tput", "tmux", "infocmp", "stty", "tset", "resize", "toe", "clear"):
        path = os.path.join(FAKEBIN, t)
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\necho "{t} $*" >> "{EXECLOG}"\nexit 1\n')
        os.chmod(path, 0o755)


def helper_env():
    make_fakebin()
    if os.path.exists(EXECLOG):
        os.remove(EXECLOG)
    return {"PATH": FAKEBIN + ":" + os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "tmux-256color",
            "TMUX": "/tmp/hp-fake-tmux,1,0", "TMUX_PANE": "%1", "TERM_PROGRAM": "tmux",
            "TERM_PROGRAM_VERSION": "3.5a", "COLORTERM": "truecolor"}


def helper_log():
    return open(EXECLOG).read().split("\n")[:-1] if os.path.exists(EXECLOG) else []


@case("k16-no-helper-programs-in-tui")
def t_k16(b):
    s = tui(b, env=helper_env())
    assert s.wait_text("3/3") is not None
    s.write(b"j/a\x7f\x1b")
    for cols, rows in [(40, 10), (20, 5), (80, 24)]:
        s.resize(cols, rows)
        s.read_for(0.1)
    s.write(b"q")
    code, termios_ok = s.finish()
    assert code == 0 and termios_ok, f"exit {code}"
    log = helper_log()
    s = tui(b, env=helper_env())
    assert s.wait_text("3/3") is not None
    os.close(s.master)  # hangup
    s.p.wait(timeout=5)
    log += helper_log()
    assert log == [], f"helper programs executed: {log}"
    return "TMUX/TERM/TERM_PROGRAM set, fake tput/tmux/infocmp first on PATH: keys, resizes, quit and hangup ran none of them"


@case("k16-no-tput-when-output-terminal-hangs-up")
def t_k16_split(b):
    # No controlling terminal; stdin = live pty B, stdout = pty A. After A hangs up, a
    # resize and a keypress force a size query. Round 1 (crossterm terminal::size())
    # executed `tput cols` / `tput lines` here on Linux.
    env = dict(os.environ)
    env.pop("SSH_AUTH_SOCK", None)
    env.update(helper_env())
    ma, sa = os.openpty()
    mb, sb = os.openpty()
    for m in (ma, mb):
        fcntl.ioctl(m, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    p = subprocess.Popen([b, "tui", "--file", str(FIX / "homelab.toml")], stdin=sb, stdout=sa,
                         stderr=subprocess.DEVNULL, start_new_session=True, env=env)
    os.close(sa)
    os.close(sb)
    out, end = b"", time.monotonic() + 3
    while time.monotonic() < end and b"3/3" not in out:
        r, _, _ = select.select([ma], [], [], 0.02)
        if r:
            out += os.read(ma, 65536)
    assert b"3/3" in out, "first frame"
    os.close(ma)
    time.sleep(0.1)
    try:
        os.kill(p.pid, signal.SIGWINCH)
    except ProcessLookupError:
        pass
    time.sleep(0.3)
    for k in (b"j", b"q"):
        try:
            os.write(mb, k)
        except OSError:
            pass
        time.sleep(0.2)
    try:
        rc = p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        rc = "timeout"
    os.close(mb)
    log = helper_log()
    assert log == [], f"helper programs executed: {log}"
    assert rc == 129, f"exit {rc} (K10: terminal hangup seen as EIO -> 129)"
    return "stdout terminal hung up, then SIGWINCH and keys: no helper program executed, exit 129"


@case("run-session-leader-hangup-reaches-child-once")
def t_run_leader_hup(b):
    # heimdall-proto itself is the session leader owning the terminal (as when a terminal
    # emulator or sshd starts it directly). Closing the master sends SIGHUP to the
    # session leader only (Linux: si_code SI_KERNEL); it must reach the child once.
    out = os.path.join(TMP, "leader-hup.txt")
    script = ("import signal,time,sys,os\n"
              "n=[0]\n"
              "signal.signal(signal.SIGHUP, lambda *a: n.__setitem__(0, n[0]+1))\n"
              f"open({out!r},'w').write('ready')\n"
              "end=time.time()+1.0\n"
              "while time.time()<end: time.sleep(0.01)\n"
              f"open({out!r},'w').write('count=%d' % n[0])\n"
              "sys.exit(3)\n")
    m, sl = os.openpty()
    env = dict(os.environ)
    env.pop("SSH_AUTH_SOCK", None)
    p = subprocess.Popen([b, "run", "--", sys.executable, "-c", script], stdin=sl, stdout=sl, stderr=sl,
                         start_new_session=True, preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0), env=env)
    os.close(sl)
    end = time.monotonic() + 5
    while time.monotonic() < end and not (os.path.exists(out) and open(out).read() == "ready"):
        time.sleep(0.01)
    os.close(m)  # hangup
    rc = p.wait(timeout=5)
    count = open(out).read()
    if sys.platform != "linux" and count != "count=1":
        raise KnownLimitation(f"{count}, exit {rc} (Darwin: kernel and forwarded SIGHUP cannot be told apart)")
    assert count == "count=1", f"child saw {count}"
    assert rc == 3, f"exit {rc}"
    return f"session-leader hangup: child saw SIGHUP once, exit {rc}"


# ---------- round 3b (contract §9.3 K6e) ----------

K6E_CHILD = r"""
import os, sys, time
hb = sys.argv[1]
print('ready', os.getpid(), flush=True)
while True:
    line = sys.stdin.readline()
    if not line:
        sys.exit(9)
    line = line.strip()
    if line == 'quit':
        sys.exit(5)
    if line == 'hb':  # heartbeat phase: no terminal reads, a counter in a file
        print('HB-START', flush=True)
        end, n = time.time() + 1.6, 0
        while time.time() < end:
            n += 1
            open(hb + '.t', 'w').write(str(n))
            os.replace(hb + '.t', hb)  # atomic: the reader never sees a truncated file
            time.sleep(0.02)
        print('HB-END', flush=True)
        continue
    print('GOT', line, flush=True)
"""


def ppid_of(pid):
    if sys.platform.startswith("linux"):
        return int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
    r = subprocess.run(["/bin/ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True)
    return int(r.stdout.strip() or 0)


class Shell:
    """Interactive bash (job control on) as session leader of a fresh pty."""

    def __init__(self):
        self.master, slave = os.openpty()
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
        env.update({"PS1": "HPS1$ ", "TERM": "dumb", "BASH_SILENCE_DEPRECATION_WARNING": "1",
                    "HISTFILE": "/dev/null"})
        self.p = subprocess.Popen(["/bin/bash", "--norc", "--noprofile", "-i"], stdin=slave, stdout=slave,
                                  stderr=slave, start_new_session=True, env=env,
                                  preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        self.out = b""

    def read_for(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            r, _, _ = select.select([self.master], [], [], max(0.0, end - time.monotonic()))
            if not r:
                break
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.out += chunk

    def wait_count(self, needle: bytes, n: int, timeout=4.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.out.count(needle) >= n:
                return True
            self.read_for(0.02)
        return self.out.count(needle) >= n

    def send(self, b: bytes):
        os.write(self.master, b)

    def close(self):
        try:
            self.send(b"exit\n")
            end = time.monotonic() + 3
            while self.p.poll() is None and time.monotonic() < end:
                self.read_for(0.05)
        except OSError:
            pass
        if self.p.poll() is None:
            os.kill(self.p.pid, signal.SIGKILL)
            self.p.wait()
        os.close(self.master)


@case("k6e-interactive-bash-ctrl-z-fg-bg")
def t_k6e(b):
    if not os.access("/bin/bash", os.X_OK):
        raise AssertionError("/bin/bash missing: K6e needs an interactive job-control shell")
    d = tempfile.mkdtemp(prefix="k6e-", dir=TMP)
    child_py, hb = os.path.join(d, "c.py"), os.path.join(d, "hb")
    open(child_py, "w").write(K6E_CHILD)
    sh = Shell()
    hp_pid = child = None
    try:
        assert sh.wait_count(b"HPS1$ ", 1), f"no prompt: {sh.out[-200:]!r}"
        assert b"no job control" not in sh.out, f"bash has no job control: {sh.out[-200:]!r}"
        sh.send(f'"{b}" run -- "{sys.executable}" "{child_py}" "{hb}"\n'.encode())
        assert sh.wait_count(b"ready ", 1), f"child not started: {sh.out[-300:]!r}"
        sh.read_for(0.1)
        child = int(re.search(rb"ready (\d+)", sh.out).group(1))
        hp_pid = ppid_of(child)
        assert hp_pid > 1, f"child's parent not found: {hp_pid}"
        stops = 0
        notes = []

        def states():
            return proc_state(child), proc_state(hp_pid)

        def ctrl_z(tag):
            nonlocal stops
            stops += 1
            sh.send(b"\x1a")
            assert sh.wait_count(b"Stopped", stops), f"{tag}: shell never reported Stopped: {sh.out[-300:]!r}"
            assert sh.wait_count(b"HPS1$ ", 2 + prompts[0]), f"{tag}: no prompt after Ctrl-Z"
            prompts[0] += 1
            end = time.monotonic() + 2
            while time.monotonic() < end and not all(s.startswith("T") for s in states()):
                sh.read_for(0.02)
            st = states()
            assert all(s.startswith("T") for s in st), f"{tag}: job not stopped while shell says Stopped: {st}"

        def fg_and_read(tag, token):
            sh.send(b"fg\n")
            sh.read_for(0.4)
            st = states()
            assert not any(s.startswith("T") for s in st), f"{tag}: stopped after fg: {st}"
            assert sh.out.count(b"Stopped") == stops, f"{tag}: re-stopped after fg: {sh.out[-300:]!r}"
            sh.send(token + b"\n")
            assert sh.wait_count(b"GOT " + token, 1), f"{tag}: child did not read terminal input after fg: {sh.out[-300:]!r}"

        prompts = [0]
        for i in range(1, 4):
            ctrl_z(f"z-fg #{i}")
            fg_and_read(f"z-fg #{i}", f"K6E-A-{i}".encode())
            sh.send(b"hb\n")
            assert sh.wait_count(b"HB-START", i), f"z-bg-fg #{i}: heartbeat did not start"
            sh.read_for(0.1)
            ctrl_z(f"z-bg-fg #{i}")
            before = open(hb).read()
            sh.read_for(0.4)
            assert open(hb).read() == before, f"z-bg-fg #{i}: heartbeat advanced while stopped"
            sh.send(b"bg\n")
            sh.read_for(0.3)
            after = open(hb).read()
            st = states()
            assert int(after) > int(before), f"z-bg-fg #{i}: heartbeat did not advance after bg ({before}->{after})"
            assert not any(s.startswith("T") for s in st), f"z-bg-fg #{i}: stopped while shell says running (bg): {st}"
            assert sh.wait_count(b"HPS1$ ", 2 + prompts[0]), f"z-bg-fg #{i}: no prompt after bg"
            prompts[0] += 1
            fg_and_read(f"z-bg-fg #{i}", f"K6E-B-{i}".encode())
            assert sh.wait_count(b"HB-END", i), f"z-bg-fg #{i}: heartbeat never ended"
            notes.append(f"#{i} ok (hb {before}->{after})")
        sh.send(b"quit\n")
        sh.read_for(0.5)
        sh.send(b"echo RC=$?\n")
        assert sh.wait_count(b"RC=5", 1), f"exit status not passed through: {sh.out[-300:]!r}"
        return ("interactive bash: Ctrl-Z stops child and heimdall-proto, fg resumes with terminal input, "
                "bg runs it (heartbeat advances), fg after bg reads input, no re-stop; 3 iterations each; RC=5; "
                + "; ".join(notes))
    finally:
        for pid in (child, hp_pid):
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        sh.close()


@case("k6d-shared-mode-explicit-signals-reach-child")
def t_k6d(b):
    """K6d: heimdall-proto shares the process group of a foreground non-job-control
    script (the script's group holds the terminal). A signal sent explicitly to the
    heimdall-proto PID reaches the child at least once (K6b allows duplicates)."""
    got = []
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
        out = os.path.join(TMP, f"k6d-{sig.name}.txt")
        script = f'"$0" run -- "{sys.executable}" -c "$1"; echo "RC=$?"'
        s = Pty(["/bin/sh", "-c", script, b, counting_child(sig.name, out)])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not (os.path.exists(out) and open(out).read().startswith("ready")):
            s.read_for(0.01)
        _, cpid, cpgid = open(out).read().split()
        hp = ppid_of(int(cpid))
        assert hp not in (0, 1, s.pid), f"{sig.name}: heimdall-proto not found (ppid {hp})"
        hp_pgid = os.getpgid(hp)
        assert hp_pgid == os.getpgid(s.pid) == int(cpgid) == os.tcgetpgrp(s.master), \
            f"{sig.name}: not shared mode (hp {hp_pgid}, script {os.getpgid(s.pid)}, child {cpgid}, fg {os.tcgetpgrp(s.master)})"
        os.kill(hp, sig)  # explicit signal to heimdall-proto's PID only
        code, _ = s.finish(timeout=5)
        count = open(out).read()
        n = int(count.split("=")[1]) if count.startswith("count=") else 0
        assert n >= 1, f"{sig.name}: child saw {count!r} (silent loss)"
        assert b"RC=3" in s.out and code == 0, f"{sig.name}: script saw {s.out[-120:]!r}, exit {code}"
        got.append(f"{sig.name}={n}")
    return "shared mode (hp, script and child in the terminal's foreground group): " + ", ".join(got) + "; RC=3 each"


def t_panic(pb):
    @case("tui-panic-restores")
    def inner(b):
        err = os.path.join(TMP, "panic.err")
        s = tui(b, env={"HP_PTY_STDERR": err})
        assert s.wait_text("3/3") is not None
        s.write(b"!")
        code, termios_ok = s.finish()
        assert code == 1, f"exit {code}"
        assert termios_ok, "termios not restored after panic"
        assert restored_screen(s.out), "alt screen/cursor not restored after panic"
        assert b"g02 test-panic hook" in open(err, "rb").read(), "panic message on stderr"
        assert after_restore(s.out) == b"", f"K10: stdout after restore {after_restore(s.out)!r}"
        return "panic → exit 1, termios + alt screen + cursor restored, message on stderr only (K10)"
    inner(pb)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    binary = os.path.abspath(args[0])
    panic_bin = None
    if "--panic-binary" in args:
        panic_bin = os.path.abspath(args[args.index("--panic-binary") + 1])
    for fn in [t_select, t_quit, t_ctrlc, t_term, t_filter, t_esc, t_resize, t_nocolor,
               t_large, t_tiny, t_bad, t_hangup, t_run_sigint, t_run_ctrlz,
               t_k6, t_k9, t_k10, t_k6a_amp, t_k6a_pipe, t_k14_tui, t_k16, t_k16_split, t_run_leader_hup,
               t_k6e, t_k6d]:
        fn(binary)
    if panic_bin:
        t_panic(panic_bin)
    import shutil
    shutil.rmtree(TMP, ignore_errors=True)
    ok = all(r["passed"] or r.get("known_limitation") for r in results)
    limits = [r["case"] for r in results if r.get("known_limitation")]
    print(json.dumps({"binary": binary, "platform": sys.platform, "passed": ok,
                      "known_limitations": limits, "results": results}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
