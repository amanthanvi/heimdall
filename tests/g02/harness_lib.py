"""Shared plumbing for the G02 conformance harness: process spawning, the
instrumented fake agent controller, a pty/terminal-emulator session, and pure
parsers (unit-tested by the harness.* checks).  Python standard library only,
plus optional pyte (pinned in requirements.txt) for the TUI checks.
"""
import base64
import fcntl
import glob
import hashlib
import json
import os
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FAKE_AGENT = REPO / "tests" / "fixtures" / "fake-agent" / "fake_agent.py"
CANARY_PREFIX = b"HEIMDALL_CANARY_"
SSH_KEYGEN = "/usr/bin/ssh-keygen"


# --------------------------------------------------------------------------
# optional pyte
def load_pyte():
    try:
        import pyte  # noqa
        return pyte
    except ImportError:
        pass
    for sp in glob.glob(str(HERE / ".venv" / "lib" / "python*" / "site-packages")):
        if sp not in sys.path:
            sys.path.insert(0, sp)
    try:
        import pyte  # noqa
        return pyte
    except ImportError:
        return None


# --------------------------------------------------------------------------
# text helpers
def now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def safe_text(s):
    """Make str safe to serialise as UTF-8 JSON (lone surrogates from fsdecode become \\udcXX text)."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def redact_bytes(data):
    return re.sub(rb"HEIMDALL_CANARY_[A-Za-z0-9_]*", b"[REDACTED_CANARY]", data)


# A full canary value is the prefix followed by at least one value character.  The bare prefix
# (used as a scan pattern, e.g. "no HEIMDALL_CANARY_ in stdout") is allowed in evidence
# (tests/evidence/README.md, canary rule).
CANARY_VALUE_RE = re.compile(rb"HEIMDALL_CANARY_[A-Za-z0-9]")


def canary_hits(data, values):
    """Labels of the canaries found in `data` (bytes).

    `values` maps each known full canary value (str) to a label that names it by fixture and key
    path, never by value.  Any other prefix+value-character occurrence is reported as
    'unregistered HEIMDALL_CANARY_ value'.  Returns a sorted list of labels (no values)."""
    hits = set()
    rest = data
    for val in sorted(values, key=len, reverse=True):
        enc = val.encode("utf-8")
        if enc in rest:
            hits.add(values[val])
            rest = rest.replace(enc, b"[REDACTED_CANARY]")
    if CANARY_VALUE_RE.search(rest):
        hits.add("unregistered HEIMDALL_CANARY_ value")
    return sorted(hits)


def redact_values(data, values):
    """Remove every known canary value and any prefix+value occurrence from `data` (bytes)."""
    for val in sorted(values, key=len, reverse=True):
        data = data.replace(val.encode("utf-8"), b"[REDACTED_CANARY]")
    return redact_bytes(data)


def printable(data, limit=1500):
    """Redacted, truncated, escaped text rendering of captured bytes."""
    data = redact_bytes(data)
    cut = data[:limit]
    txt = cut.decode("utf-8", errors="backslashreplace")
    txt = "".join(c if (c in "\n\t" or c.isprintable()) else "\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c)
                  for c in txt)
    if len(data) > limit:
        txt += "...[+%d bytes]" % (len(data) - limit)
    return txt


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# hard wall-clock bounds (defect (c): no single check may hang the run)
class CheckTimeout(BaseException):
    """Raised from SIGALRM when a check or its cleanup exceeds its hard wall-clock bound.

    A BaseException so that the many `except Exception` / `except OSError` blocks inside
    checks and helpers cannot swallow it; it also interrupts blocking syscalls (waitpid,
    read, select), because a Python signal handler that raises aborts the retry (PEP 475)."""


def _on_alarm(signum, frame):
    raise CheckTimeout("hard wall-clock bound exceeded")


def install_alarm_handler():
    signal.signal(signal.SIGALRM, _on_alarm)


def arm(seconds):
    """Arm (seconds > 0) or disarm (0) the one-shot hard bound."""
    signal.setitimer(signal.ITIMER_REAL, max(0.0, float(seconds)))


# --------------------------------------------------------------------------
# process registry: every process group the harness creates, so a check that
# timed out or crashed can be cleaned up without waiting on anything.
_TRACKED = []   # list of (pgid, Popen)


def track(proc, pgid=None):
    _TRACKED.append((pgid if pgid is not None else proc.pid, proc))
    return proc


def kill_tracked(budget=3.0):
    """SIGKILL the process group of every tracked process that is still unreaped, then reap
    with a bounded wait.

    Only processes whose Popen has not been reaped are touched: an unreaped process keeps its
    pid (= its process-group id, every tracked process is a session leader), so the signal can
    never reach a recycled pid.  Groups whose leader already exited were checked for leftovers
    right after the exit (run_capture, PtySession.close).  Returns the killed pgids."""
    killed = []
    for pgid, proc in list(_TRACKED):
        if proc.poll() is None and pgid == proc.pid:
            killed.append(pgid)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    end = time.monotonic() + budget
    for pgid, proc in list(_TRACKED):
        while proc.poll() is None and time.monotonic() < end:
            time.sleep(0.01)
    _TRACKED[:] = [(g, p) for g, p in _TRACKED if p.poll() is None]
    return killed


# --------------------------------------------------------------------------
# environment / spawning
def normalize_signal_dispositions():
    """Children inherit SIG_IGN; make sure the harness does not pass any on."""
    signal.signal(signal.SIGINT, signal.default_int_handler)
    for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        if signal.getsignal(s) == signal.SIG_IGN:
            signal.signal(s, signal.SIG_DFL)


def kill_group(pgid, sig=signal.SIGKILL):
    """Signal a process group that WE created (start_new_session)."""
    try:
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def group_alive(pgid, settle=0.15):
    """True if any process remains in the group; waits briefly for reparented exits."""
    end = time.monotonic() + settle
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        if time.monotonic() >= end:
            return True
        time.sleep(0.01)


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def spawn(argv, env, cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw):
    return track(subprocess.Popen(argv, env=env, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr,
                                  start_new_session=True, **kw))


def ignore_signals_preexec(signums):
    """preexec_fn that sets SIG_IGN for `signums` in the child (the disposition survives exec),
    modelling `nohup` / `trap '' HUP` / the SIGINT+SIGQUIT ignore of a non-interactive `&` job."""
    sigs = tuple(signums)

    def pre():
        for s in sigs:
            signal.signal(s, signal.SIG_IGN)
    return pre


def pid_in_session(pid, sid):
    """True if `pid` is alive and a member of session `sid` (a session the harness created)."""
    try:
        return os.getsid(pid) == sid
    except (ProcessLookupError, PermissionError, OSError):
        return False


def kill_session_pids(pids, sid):
    """SIGKILL each listed pid, but only after verifying it is still a member of the session the
    harness created (identity check: never a recycled or foreign pid).  Returns the killed pids."""
    killed = []
    for pid in pids:
        if pid and pid_in_session(pid, sid):
            for sg in (signal.SIGCONT, signal.SIGKILL):
                try:
                    os.kill(pid, sg)
                except (ProcessLookupError, PermissionError):
                    pass
            killed.append(pid)
    return killed


def proc_state(pid):
    """One-letter scheduler state of `pid` ('T' = stopped), or None.  Linux: /proc/<pid>/stat;
    elsewhere `/bin/ps -o stat=` (only the state field is read, never the command line)."""
    try:
        if sys.platform.startswith("linux"):
            data = Path("/proc/%d/stat" % pid).read_text()
            return data.rsplit(")", 1)[1].split()[0]
        r = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(int(pid))], capture_output=True, text=True,
                           timeout=5)
        st = r.stdout.strip()
        return st[:1] or None
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


def maxrss_bytes(ru_maxrss):
    """ru_maxrss is bytes on macOS/BSD and KiB on Linux."""
    return int(ru_maxrss) if sys.platform == "darwin" else int(ru_maxrss) * 1024


def bounded_communicate(proc, input=None, timeout=20.0):
    """communicate() that can never block forever.

    Returns (stdout, stderr, timed_out, pipes_held).  On timeout the process group is
    SIGKILLed; if the pipes are still held open afterwards (a descendant escaped the
    group with setsid) they are closed and pipes_held is True."""
    try:
        out, err = proc.communicate(input=input, timeout=timeout)
        return out or b"", err or b"", False, False
    except subprocess.TimeoutExpired:
        pass
    kill_group(proc.pid)
    try:
        out, err = proc.communicate(timeout=5)
        return out or b"", err or b"", True, False
    except subprocess.TimeoutExpired:
        for fh in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if fh:
                    fh.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return b"", b"", True, True


class Cap:
    """Result of one captured process run."""

    def __init__(self, label, argv):
        self.label = label
        self.argv = [safe_text(os.fsdecode(a)) for a in argv]
        self.rc = None
        self.stdout = b""
        self.stderr = b""
        self.elapsed = 0.0
        self.timed_out = False
        self.leftover = False
        self.exit_wall = None  # time.time() when exit was observed
        self.extra = {}

    def summary(self):
        return {
            "label": self.label,
            "argv": self.argv,
            "exit_code": self.rc,
            "elapsed_ms": round(self.elapsed * 1000, 1),
            "timed_out": self.timed_out,
            "leftover_processes": self.leftover,
            "stdout_bytes": len(self.stdout),
            "stdout_sha256": sha256_hex(self.stdout),
            "stdout_excerpt": printable(self.stdout),
            "stderr_bytes": len(self.stderr),
            "stderr_sha256": sha256_hex(self.stderr),
            "stderr_excerpt": printable(self.stderr),
        }


def run_capture(label, argv, env, cwd, stdin_data=None, timeout=20.0, pre=None, post=None, preexec_fn=None):
    """Run a command in its own session, capture everything, clean the group.

    pre(proc)   - called right after spawn (may send signals / wait for readiness)
    preexec_fn  - run in the child before exec (e.g. ignore_signals_preexec)
    The call never raises on timeout; it kills the group and sets cap.timed_out.
    """
    cap = Cap(label, argv)
    t0 = time.monotonic()
    stdin = subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL
    kw = {"preexec_fn": preexec_fn} if preexec_fn else {}
    proc = spawn(argv, env, cwd, stdin=stdin, **kw)
    cap.pid = proc.pid
    try:
        if pre:
            pre(proc)
        out, err, cap.timed_out, held = bounded_communicate(proc, stdin_data, timeout)
        if held:
            cap.extra["pipes_held_after_kill"] = True
        cap.exit_wall = time.time()
        cap.elapsed = time.monotonic() - t0
        cap.stdout, cap.stderr = out, err
        cap.rc = proc.returncode
        if post:
            post(cap)
        cap.leftover = group_alive(proc.pid)
        if cap.leftover:
            kill_group(proc.pid)
    finally:
        if proc.poll() is None:
            kill_group(proc.pid)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    return cap


# --------------------------------------------------------------------------
# instrumented fake agent controller
class FakeAgent:
    def __init__(self, sandbox, workdir, name, mode, pubkeys=(), sock_path=None):
        self.mode = mode
        self.dir = Path(workdir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sock = str(sock_path) if sock_path else str(self.dir / ("%s.sock" % name))
        self.log_path = str(self.dir / ("%s.contact.jsonl" % name))
        self.ready = str(self.dir / ("%s.ready" % name))
        self.err_path = str(self.dir / ("%s.stderr.txt" % name))
        argv = [sys.executable, str(FAKE_AGENT), "--socket", self.sock, "--mode", mode,
                "--log", self.log_path, "--ready-file", self.ready]
        for p in pubkeys:
            argv += ["--pubkey", str(p)]
        self.errfh = open(self.err_path, "wb")
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=self.errfh, start_new_session=True,
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "en_US.UTF-8"})
        track(self.proc)
        end = time.monotonic() + 10
        while not os.path.exists(self.ready):
            if self.proc.poll() is not None:
                raise RuntimeError("fake agent exited early (rc=%s): %s" % (self.proc.returncode, self.stderr_text()))
            if time.monotonic() > end:
                self.stop()
                raise RuntimeError("fake agent did not become ready")
            time.sleep(0.005)
        self.stopped = False

    def stderr_text(self):
        try:
            return Path(self.err_path).read_text(errors="replace")[:500]
        except OSError:
            return ""

    def events(self):
        out = []
        try:
            with open(self.log_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        except FileNotFoundError:
            pass
        return out

    def wait_event(self, pred, timeout=3.0):
        end = time.monotonic() + timeout
        while True:
            ev = [e for e in self.events() if pred(e)]
            if ev:
                return ev[0]
            if time.monotonic() > end:
                return None
            time.sleep(0.005)

    def wait_disconnect(self, timeout=2.0):
        return self.wait_event(lambda e: e["event"] == "disconnect", timeout)

    def stop(self):
        """SIGTERM the agent we started and report (rc, socket_removed)."""
        if getattr(self, "stopped", False):
            return self.proc.returncode, not os.path.lexists(self.sock)
        self.stopped = True
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_group(self.proc.pid)
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self.errfh.close()
        removed = not os.path.lexists(self.sock)
        if not removed:
            try:
                os.unlink(self.sock)
            except OSError:
                pass
        return self.proc.returncode, removed


def passive_report(events, conn_expected=1):
    """Analyse a contact log for passivity: exactly one type-11 request and nothing else.

    Returns (ok, details_dict)."""
    connects = [e for e in events if e["event"] == "connect"]
    msgs = [e for e in events if e["event"] == "message"]
    disc = [e for e in events if e["event"] == "disconnect"]
    problems = []
    if len(connects) != conn_expected:
        problems.append("connections=%d (expected %d)" % (len(connects), conn_expected))
    if len(msgs) != 1:
        problems.append("messages=%d (expected exactly 1)" % len(msgs))
    for m in msgs:
        if m.get("type") != 11 or m.get("bytes") != 5:
            problems.append("message type=%r bytes=%r (expected type 11, 5 bytes)" % (m.get("type"), m.get("bytes")))
    for d in disc:
        if d.get("bytes_received") != 5 * len(msgs) or d.get("partial_bytes"):
            problems.append("bytes_received=%r partial=%r" % (d.get("bytes_received"), d.get("partial_bytes")))
    return (not problems), {
        "connections": len(connects),
        "message_types": [m.get("type") for m in msgs],
        "message_bytes": [m.get("bytes") for m in msgs],
        "disconnect_reasons": [d.get("reason") for d in disc],
        "problems": problems,
    }


# --------------------------------------------------------------------------
# disposable keys
def ssh_string(b):
    return struct.pack(">I", len(b)) + b


def fingerprint_of_blob(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def blob_key_type(blob):
    (n,) = struct.unpack(">I", blob[:4])
    return blob[4:4 + n].decode("ascii")


def generate_keys(keydir):
    """Generate disposable public keys with ssh-keygen; private halves are deleted at once.

    Returns list of dicts: pub, blob, key_type, comment, sshkeygen_fingerprint, computed_fingerprint."""
    keydir = Path(keydir)
    keydir.mkdir(parents=True, exist_ok=True)
    specs = [("ed25519", [], "lab key ü 東京 spaced"),
             ("ecdsa", ["-b", "256"], "second"),
             ("rsa", ["-b", "2048"], "")]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(keydir), "LANG": "en_US.UTF-8"}
    out = []
    for kind, extra, comment in specs:
        priv = keydir / ("k_" + kind)
        r = subprocess.run([SSH_KEYGEN, "-q", "-t", kind] + extra + ["-N", "", "-C", comment, "-f", str(priv)],
                           env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError("ssh-keygen failed: %s" % r.stderr.decode(errors="replace")[:200])
        try:
            os.unlink(priv)  # delete the private half immediately
        finally:
            pass
        pub = Path(str(priv) + ".pub")
        line = pub.read_bytes().strip().split(None, 2)
        blob = base64.b64decode(line[1])
        lf = subprocess.run([SSH_KEYGEN, "-lf", str(pub)], env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=30)
        if lf.returncode != 0:
            raise RuntimeError("ssh-keygen -lf failed")
        fp = lf.stdout.decode().split()[1]
        out.append({"pub": str(pub), "blob": blob, "key_type": blob_key_type(blob),
                    "comment": comment, "sshkeygen_fingerprint": fp,
                    "computed_fingerprint": fingerprint_of_blob(blob), "kind": kind})
    for f in keydir.glob("k_*"):
        if not f.name.endswith(".pub"):
            raise RuntimeError("private key material left behind: %s" % f.name)
    return out


# --------------------------------------------------------------------------
# terminal output analysis (pure functions)
PRIV_RE = re.compile(rb"\x1b\[\?([0-9;]*)([hl])")
CSI_RE = re.compile(rb"\x1b\[([0-9;:?<=>]*)([ -/]*)([@-~])")
SGR_RE = re.compile(rb"\x1b\[([0-9;:]*)m")
ALT_MODES = {47, 1047, 1049}


def mode_events(raw):
    """List of (offset, mode_number, is_set) for DEC private mode set/reset."""
    out = []
    for m in PRIV_RE.finditer(raw):
        for p in m.group(1).split(b";"):
            if p.isdigit():
                out.append((m.start(), int(p), m.group(2) == b"h"))
    return out


def final_state(raw):
    ev = mode_events(raw)
    alt = [e for e in ev if e[1] in ALT_MODES]
    cur = [e for e in ev if e[1] == 25]
    return {
        "alt_entered": any(e[2] for e in alt),
        "alt_active_at_end": bool(alt) and alt[-1][2],
        "cursor_hidden_ever": any(not e[2] for e in cur),
        "cursor_hidden_at_end": bool(cur) and not cur[-1][2],
        "app_cursor_keys": bool([e for e in ev if e[1] == 1]) and [e for e in ev if e[1] == 1][-1][2],
        "last_restore_offset": max([e[0] for e in alt if not e[2]] + [e[0] for e in cur if e[2]] or [-1]),
    }


def tail_after_restore(raw):
    """Bytes emitted after the last alt-screen-leave / cursor-show sequence."""
    st = final_state(raw)
    off = st["last_restore_offset"]
    if off < 0:
        return raw
    m = PRIV_RE.match(raw, off)
    return raw[m.end():] if m else raw[off:]


def disallowed_tail_sequences(tail):
    """Escape sequences after the restore that would corrupt the main screen."""
    bad = []
    for m in CSI_RE.finditer(tail):
        final = m.group(3)
        priv = m.group(1).startswith(b"?")
        if final == b"m":
            continue
        if priv and final == b"l":
            continue
        bad.append(m.group(0))
    stripped = CSI_RE.sub(b"", tail)
    if b"\x1b" in stripped:
        bad.append(b"<non-CSI escape>")
    return bad


def strip_csi(data):
    return CSI_RE.sub(b"", data)


def color_sgr_found(raw):
    """Return the list of color-setting SGR sequences (fg/bg/underline color)."""
    hits = []
    for m in SGR_RE.finditer(raw):
        params = [p for p in re.split(rb"[;:]", m.group(1)) if p != b""]
        for p in params:
            if not p.isdigit():
                continue
            n = int(p)
            if 30 <= n <= 38 or 40 <= n <= 48 or 90 <= n <= 97 or 100 <= n <= 107 or n == 58:
                hits.append(m.group(0))
                break
    return hits


# --------------------------------------------------------------------------
# pty session with terminal emulation
def render_cells(cells, wcwidth):
    """Render one emulator line (list of cell data strings) with xterm double-width semantics.

    pyte 0.8.2 stores a double-width character in its cell and an empty-string "stub" in the
    next cell, and its Screen.display assumes the pair is never split.  Real terminals (xterm,
    and what Ratatui/Bubble Tea diffs rely on) erase the WHOLE double-width character when
    either half is overwritten or erased.  pyte instead leaves an orphan stub (display then
    raises IndexError) or a lone left half (display then hides the following cell).
    Defect (a): both are rendered here as xterm shows them - the damaged half becomes a blank.
    """
    out = []
    n = len(cells)
    x = 0
    while x < n:
        d = cells[x]
        if d == "":                      # orphan right half: its left half was overwritten/erased
            out.append(" ")
            x += 1
            continue
        if wcwidth(d[0]) == 2:
            if x + 1 < n and cells[x + 1] == "":
                out.append(d)            # intact double-width character
                x += 2
                continue
            if x + 1 == n:               # pyte placed it in the last column without a stub
                out.append(d)
                x += 1
                continue
            out.append(" ")              # right half was overwritten: the character is gone
            x += 1
            continue
        out.append(d)
        x += 1
    return "".join(out)


def make_screen(pyte_mod, cols, rows, reply_fd=None):
    """pyte Screen that answers terminal queries (DA, DSR) and renders wide cells like xterm."""
    from wcwidth import wcwidth as _wcw   # pyte's own (pinned) dependency

    class _Screen(pyte_mod.Screen):
        def write_process_input(self, data):
            if reply_fd is None:
                return
            try:
                os.write(reply_fd, data.encode("utf-8"))
            except OSError:
                pass

        @property
        def display(self):
            return [render_cells([self.buffer[y][x].data for x in range(self.columns)], _wcw)
                    for y in range(self.lines)]

        # SU / SD (CSI Ps S, CSI Ps T): scroll the scrolling region up/down by Ps lines, cursor unchanged.
        # pyte 0.8.2 does not implement them and silently drops them; Bubble Tea v2's renderer scrolls the
        # list with exactly these inside a DECSTBM region, so the emulated screen kept stale rows (found in harness
        # round 5, M00-T05-harness-r3-fix, when K17 started judging the list rows: harness defect (g)).
        def _scroll_count(self, params, private):
            if private or len(params) > 1:       # CSI ? ... S is XTSMGRAPHICS; CSI Ps;Ps;... T is mouse tracking
                return 0
            return max(params[0] if params else 1, 1)

        def scroll_up(self, *params, private=False):
            n = self._scroll_count(params, private)
            if not n:
                return
            top, bottom = self.margins or (0, self.lines - 1)
            n = min(n, bottom - top + 1)
            self.dirty.update(range(self.lines))
            for y in range(top, bottom + 1):
                if y + n <= bottom:
                    self.buffer[y] = self.buffer[y + n]
                else:
                    self.buffer.pop(y, None)

        def scroll_down(self, *params, private=False):
            n = self._scroll_count(params, private)
            if not n:
                return
            top, bottom = self.margins or (0, self.lines - 1)
            n = min(n, bottom - top + 1)
            self.dirty.update(range(self.lines))
            for y in range(bottom, top - 1, -1):
                if y - n >= top:
                    self.buffer[y] = self.buffer[y - n]
                else:
                    self.buffer.pop(y, None)

    return _Screen(cols, rows)


SCROLL_SUPPORT = True     # selftest only: harness mutation emulator_no_scroll sets it False (stock pyte behaviour)


def make_stream(pyte_mod, screen):
    """pyte ByteStream that also dispatches SU (CSI S) and SD (CSI T) to make_screen's handlers."""
    if not SCROLL_SUPPORT:
        return pyte_mod.ByteStream(screen)
    class _Stream(pyte_mod.ByteStream):
        csi = dict(pyte_mod.ByteStream.csi, S="scroll_up", T="scroll_down")
        events = frozenset(pyte_mod.ByteStream.events | {"scroll_up", "scroll_down"})

    return _Stream(screen)


class HarnessStall(Exception):
    """The program under test stopped consuming terminal input within the harness's bound."""


class PtySession:
    """A command running as the foreground job of a fresh pty (see pty_shim.py).

    .pid  - pid of the command under test (reported by the shim)
    .rc   - its wait status once known (negative = killed by that signal)

    Every operation is bounded in time.  The pty master is drained whenever the harness waits
    (defect (b)): on macOS a process that exits - or a session leader that closes its
    controlling terminal - with undrained pty output blocks in exit until somebody reads it."""

    def __init__(self, pyte_mod, argv, env, cwd, rows, cols, stderr=subprocess.PIPE, hup_forward=True,
                 stderr_tty=False):
        self.pyte = pyte_mod
        self.rows, self.cols = rows, cols
        self.master, self.slave = os.openpty()
        if stderr_tty:              # e.g. an interactive shell: prompt and job notices go to the terminal
            stderr = self.slave
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.attr_before = termios.tcgetattr(self.slave)
        self.raw = bytearray()
        self.screen = make_screen(pyte_mod, cols, rows, self.master)
        self.stream = make_stream(pyte_mod, self.screen)
        self.feed_errors = []
        ctl_r, self.ctl_w = os.pipe()
        self.status_r, status_w = os.pipe()
        self.t_spawn = time.monotonic()
        self.shim = subprocess.Popen(
            [sys.executable, str(HERE / "pty_shim.py"), str(ctl_r), str(status_w)]
            + ([] if hup_forward else ["--no-hup-forward"]) + ["--"] + list(argv),
            env=env, cwd=cwd, stdin=self.slave, stdout=self.slave, stderr=stderr,
            start_new_session=True, pass_fds=(ctl_r, status_w))
        track(self.shim)
        os.close(ctl_r)
        os.close(status_w)
        # The command inherits the shim's stderr.  Drain it with the master so a program that writes
        # a lot to stderr can never block on a full pipe, and keep it for the canary scan.
        self.err = bytearray()
        self.err_fd = self.shim.stderr.fileno() if self.shim.stderr is not None else None
        if self.err_fd is not None:
            os.set_blocking(self.err_fd, False)
        self.pid = None
        self.rc = None
        self.exit_wall = None
        self._status_buf = b""
        self.closed = False
        self.master_closed = False
        self.saved = False
        self.close_report = {}
        end = time.monotonic() + 10
        while self.pid is None and time.monotonic() < end:
            self._read_status(0.01)
            if self.shim.poll() is not None and self.pid is None:
                break
        if self.pid is None:
            self.close()
            raise RuntimeError("pty shim did not report a started command")

    def _read_status(self, timeout):
        r, _, _ = select.select([self.status_r], [], [], timeout)
        if not r:
            return
        try:
            data = os.read(self.status_r, 4096)
        except OSError:
            return
        self._status_buf += data
        while b"\n" in self._status_buf:
            line, self._status_buf = self._status_buf.split(b"\n", 1)
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("event") == "started":
                self.pid = ev["pid"]
            elif ev.get("event") == "exited":
                self.rc = ev["rc"]
                self.exit_wall = time.time()
            elif ev.get("event") == "launch_failed":
                raise RuntimeError("shim could not launch the command: %s" % ev.get("error"))

    # -- io
    def poll(self):
        self._read_status(0.0)
        return self.rc

    def _feed(self, data):
        self.raw += data
        try:
            self.stream.feed(data)
        except Exception as exc:  # noqa - an emulator problem must not abort the drain
            self.feed_errors.append(repr(exc)[:200])

    def _read_err(self):
        if self.err_fd is None:
            return
        try:
            while True:
                chunk = os.read(self.err_fd, 65536)
                if not chunk:
                    self.err_fd = None
                    return
                self.err += chunk
                if len(self.err) > 4 * 1024 * 1024:     # keep memory bounded; the head is what matters
                    del self.err[2 * 1024 * 1024:]
        except BlockingIOError:
            return
        except (OSError, ValueError):
            self.err_fd = None

    def pump(self, timeout=0.0):
        fds = [self.status_r] + ([] if self.master_closed else [self.master]) + \
            ([] if self.err_fd is None else [self.err_fd])
        r, _, _ = select.select(fds, [], [], timeout)
        n = 0
        if self.status_r in r:
            self._read_status(0.0)
        if self.err_fd is not None and self.err_fd in r:
            self._read_err()
        if not self.master_closed and self.master in r:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                data = b""
            if data:
                self._feed(data)
                n = len(data)
        return n

    def drain(self, secs=0.0):
        """Read everything currently queued on the master (and keep reading for `secs`)."""
        end = time.monotonic() + secs
        total = 0
        while True:
            n = self.pump(0.0 if secs <= 0 else 0.01)
            total += n
            if n == 0 and time.monotonic() >= end:
                return total

    def settle(self, secs=0.1):
        end = time.monotonic() + secs
        while time.monotonic() < end:
            self.pump(0.01)

    def lines(self):
        return [l.rstrip() for l in self.screen.display]

    def text(self):
        return "\n".join(self.lines())

    def wait_for(self, pred, timeout=5.0, t_start=None):
        """Return elapsed seconds (from t_start) when pred(self) became true, else None."""
        t0 = t_start if t_start is not None else time.monotonic()
        end = time.monotonic() + timeout
        while True:
            if pred(self):
                return time.monotonic() - t0
            if time.monotonic() > end:
                return None
            if self.poll() is not None:
                self.pump(0.0)
                return (time.monotonic() - t0) if pred(self) else None
            self.pump(0.002)

    def send(self, data, timeout=5.0):
        """Write keystrokes without ever blocking: the master is written non-blocking while the
        output side keeps being drained.  Raises HarnessStall if the program stops reading."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        view = memoryview(data)
        end = time.monotonic() + timeout
        os.set_blocking(self.master, False)
        try:
            while view:
                try:
                    n = os.write(self.master, view)
                    view = view[n:]
                    continue
                except BlockingIOError:
                    pass
                if time.monotonic() > end:
                    raise HarnessStall("program did not consume %d byte(s) of terminal input within %.1f s"
                                       % (len(view), timeout))
                r, w, _ = select.select([self.master], [self.master], [], 0.01)
                if r:
                    self.pump(0.0)
        finally:
            os.set_blocking(self.master, True)

    def key(self, name):
        app = final_state(bytes(self.raw))["app_cursor_keys"]
        table = {"up": b"\x1bOA" if app else b"\x1b[A", "down": b"\x1bOB" if app else b"\x1b[B",
                 "esc": b"\x1b", "enter": b"\r", "backspace": b"\x7f", "ctrl-c": b"\x03"}
        self.send(table[name])

    def signal(self, signum):
        """Signal the command under test (pid reported by our own shim)."""
        os.kill(self.pid, signum)

    def resize(self, rows, cols):
        self.rows, self.cols = rows, cols
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.screen.resize(rows, cols)

    def wait_exit(self, timeout=5.0):
        end = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() > end:
                return None
            self.pump(0.005)
        self.pump(0.05)
        self.settle(0.1)
        return self.rc

    def hangup(self, timeout=5.0):
        """Terminal hangup: close the pty master.  With hup_forward (default) the shim, acting like
        a shell, forwards the resulting SIGHUP to the job; otherwise the job only sees EOF/EIO.
        Returns the command's wait status or None."""
        self.drain()
        if not self.master_closed:
            self.master_closed = True
            try:
                os.close(self.master)
            except OSError:
                pass
        end = time.monotonic() + timeout
        while self.poll() is None and time.monotonic() < end:
            self.pump(0.01)
        return self.rc

    def termios_after(self):
        return termios.tcgetattr(self.slave)

    def stderr_bytes(self):
        """Everything the command (and the shim) wrote to stderr so far (never blocks)."""
        self._read_err()
        return bytes(self.err)

    def close(self, budget=8.0):
        """Tear the session down within `budget` seconds, never blocking in wait().

        Returns True if a process of the command's group had to be killed afterwards."""
        if self.closed:
            return False
        self.closed = True
        t0 = time.monotonic()
        end = t0 + budget
        leftover = False
        if self.rc is None and self.pid is not None:
            try:
                os.killpg(self.pid, signal.SIGKILL)   # the command's own process group
            except (ProcessLookupError, PermissionError):
                pass
        try:
            os.close(self.ctl_w)   # lets the shim exit
        except OSError:
            pass
        # Drain while the job and the shim exit: their exit may block on queued pty output.
        while self.shim.poll() is None and time.monotonic() < end - 2.0:
            self.pump(0.01)
        if self.shim.poll() is None:
            self.close_report["shim_kill"] = True
            kill_group(self.shim.pid)
            while self.shim.poll() is None and time.monotonic() < end - 1.0:
                self.pump(0.01)
        if self.shim.poll() is None and not self.master_closed:
            # last resort: hang the terminal up so nothing can wait on its output queue
            self.close_report["master_closed_to_unblock"] = True
            self.master_closed = True
            try:
                os.close(self.master)
            except OSError:
                pass
            while self.shim.poll() is None and time.monotonic() < end:
                time.sleep(0.01)
        if self.shim.poll() is None:
            self.close_report["shim_unreaped"] = True
        if self.pid is not None:
            leftover = group_alive(self.pid, settle=0.05)
            if leftover:
                kill_group(self.pid)
        if group_alive(self.shim.pid, settle=0.0):
            kill_group(self.shim.pid)
        self._read_err()
        # A blocking close of the last slave descriptor waits for queued output to drain (defect (b)
        # again, this time in the harness itself); with O_NONBLOCK the tty flushes instead.
        try:
            os.set_blocking(self.slave, False)
        except OSError:
            pass
        fds = ([] if self.master_closed else [self.master]) + [self.slave, self.status_r]
        self.master_closed = True
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if self.shim.stderr:
            try:
                self.shim.stderr.close()
            except OSError:
                pass
        self.err_fd = None
        self.close_report["seconds"] = round(time.monotonic() - t0, 3)
        return leftover


def normalize_termios(attrs):
    """Copy of tcgetattr() output without the kernel-managed PENDIN flag.

    PENDIN (0x20000000 on macOS/BSD, 0x4000 on Linux) is set by the kernel after any
    mode change to mark pending input for re-processing; it is not a mode the
    application sets, so it must not make an otherwise identical restore look different."""
    attrs = list(attrs)
    pendin = getattr(termios, "PENDIN", 0x20000000 if sys.platform == "darwin" else 0x4000)
    attrs[3] &= ~pendin
    return attrs


def make_sandbox():
    """Short, plain root under /tmp so Unix socket paths stay below 104 bytes."""
    return Path(tempfile.mkdtemp(prefix="hmg02-", dir="/tmp"))


def rm_tree(path):
    """Remove a sandbox we created, fixing permissions of anything the tests chmod'ed."""
    def onerr(func, p, _exc):
        try:
            os.chmod(os.path.dirname(p), 0o700)
            os.chmod(p, 0o700)
        except OSError:
            pass
        try:
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerr)
