"""Shared helpers for the G02 round-4 X2 hidden acceptance tests.

Black-box only: every check runs the binary under test and judges what it observes (exit status,
stdout/stderr bytes, files, process states, terminal screen).  Nothing here reads prototype source.

vendor/harness_lib.py and vendor/pty_shim.py are byte copies of tests/g02/harness_lib.py and
tests/g02/pty_shim.py (harness 2.4.2; sha256 in ../README.md), reused read-only for the pty session,
the pyte screen and SGR parsing.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "vendor"))
import harness_lib as H  # noqa: E402

PLATFORMS = {"darwin": "darwin", "linux": "linux"}


def load_pyte():
    """pyte from the interpreter, else from $HM_G02_VENV (a venv with pyte, e.g. <repo>/tests/g02/.venv)."""
    p = H.load_pyte()
    if p is not None:
        return p
    venv = os.environ.get("HM_G02_VENV")
    if venv:
        import glob
        for sp in glob.glob(os.path.join(venv, "lib", "python*", "site-packages")):
            if sp not in sys.path:
                sys.path.insert(0, sp)
        try:
            import pyte  # noqa
            return pyte
        except ImportError:
            return None
    return None


class Abort(Exception):
    """A failed precondition inside a check (already recorded)."""


class Check:
    def __init__(self, cid, title):
        self.id = cid
        self.title = title
        self.assertions = []
        self.notes = []
        self.error = None
        self.t0 = time.monotonic()

    def check(self, name, ok, expected, observed):
        self.assertions.append({"name": name, "ok": bool(ok), "expected": _short(expected),
                                "observed": _short(observed)})
        return bool(ok)

    def eq(self, name, observed, expected):
        return self.check(name, observed == expected, expected, observed)

    def require(self, name, ok, expected, observed):
        if not self.check(name, ok, expected, observed):
            raise Abort(name)

    def precondition(self, name, ok, observed):
        """A failed precondition of the test environment (e.g. the plain-exec control misbehaved):
        the check is reported as `error`, never as `fail`."""
        if not ok:
            self.error = "precondition failed: %s; observed %s" % (name, _short(observed))
            raise Abort(name)

    def note(self, s):
        self.notes.append(_short(s, 2000))

    @property
    def status(self):
        if self.error:
            return "error"
        return "pass" if self.assertions and all(a["ok"] for a in self.assertions) else "fail"


def _short(v, n=600):
    try:
        s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=repr)
    except Exception:  # noqa
        s = repr(v)
    return s if len(s) <= n else s[:n] + "...(%d chars)" % len(s)


class Ctx:
    """Per-run context: binary, platform, private sandbox with its own HOME/TMPDIR."""

    def __init__(self, binpath, platform, keep=False):
        self.bin = str(Path(binpath).resolve())
        self.platform = platform
        self.sandbox = Path(tempfile.mkdtemp(prefix="hm-r4x2-"))
        self.home = self.sandbox / "home"
        self.tmp = self.sandbox / "tmp"
        self.home.mkdir()
        self.tmp.mkdir()
        self.keep = keep
        self.counter = 0
        self.pyte = None

    def env(self, extra=None):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home),
               "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TMPDIR": str(self.tmp),
               "TERM": "xterm-256color"}
        env.update(extra or {})
        return env

    def new_dir(self, name):
        self.counter += 1
        d = self.sandbox / ("%03d-%s" % (self.counter, name))
        d.mkdir(parents=True)
        return d

    def run(self, args, env=None, cwd=None, timeout=20.0, stdin=b""):
        """Run the binary; returns (rc, stdout, stderr, elapsed_s). rc None = killed after timeout."""
        t0 = time.monotonic()
        p = subprocess.Popen([self.bin] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=self.env(env), cwd=str(cwd or self.sandbox),
                             start_new_session=True)
        try:
            out, err = p.communicate(stdin, timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            out, err = p.communicate()
            rc = None
        return rc, out, err, time.monotonic() - t0

    def cleanup(self):
        if not self.keep:
            H.rm_tree(self.sandbox)

    def scrub(self, s):
        """Remove machine-specific paths from text that goes into a report (see scrub_text)."""
        home = os.environ.get("HOME")
        pairs = [(str(self.sandbox), "<sandbox>"), (self.bin, "<bin>"), (home, "<home>")]
        user = os.path.basename(home.rstrip("/")) if home else ""
        if len(user) >= 6:
            # A transcript tail may start or end inside the home path; the user name alone is not
            # a path, but it is machine-specific (fix round 2026-10-06).
            pairs.append((user, "<user>"))
        return scrub_text(s, pairs, edge_paths=[home])


# Between two characters of a path, a terminal transcript or a JSON-encoded string may hold a line
# wrap: whitespace (pyte joins wrapped rows with a space or a newline), a JSON escape (\n, \r, \t,
# \u00XX) or a CSI sequence.  Fix round (2026-10-06): a plain str.replace missed a home path split by
# a wrap in darwin T1 transcripts.
_GAP = r"(?:\s|\\[nrt]|\\u00[0-9a-fA-F]{2}|\x1b\[[0-9;?]*[ -/]*[@-~]|\\u001b\[[0-9;?]*[ -/]*[@-~])*"


_GAPPY = {}


def _gappy(path, anchor=""):
    key = (path, anchor)
    if key not in _GAPPY:
        body = _GAP.join(re.escape(c) for c in path)
        _GAPPY[key] = re.compile({"": body, "start": r"\A" + body, "end": body + r"\Z"}[anchor])
    return _GAPPY[key]


def scrub_text(s, pairs, edge_paths=()):
    """Replace each (path, token) in s, also where a wrap splits the path.  Longer paths first, so a
    sandbox or binary path under HOME keeps its own token.  For each path in edge_paths, a piece of
    at least 8 characters cut off by the start or the end of s (a truncated transcript tail) is
    replaced by "<home-part>"."""
    if not isinstance(s, str):
        return s
    for path, token in sorted((p for p in pairs if p[0] and len(p[0]) > 1), key=lambda p: -len(p[0])):
        s = s.replace(path, token)
        s = _gappy(path).sub(token, s)
    for path in edge_paths:
        if not path or len(path) < 9:
            continue
        for k in range(len(path) - 1, 7, -1):
            s = _gappy(path[:k], "end").sub("<home-part>", s)
            s = _gappy(path[-k:], "start").sub("<home-part>", s)
    return s


def contains_path(s, path):
    """True if s holds path, also split by a wrap (used as the last guard before a record is written)."""
    return bool(path and len(path) > 1 and isinstance(s, str) and _gappy(path).search(s))


def parse_one_json(t, out, label="stdout"):
    """Exactly one JSON document followed by a single newline; no ANSI escapes."""
    t.check("%s ends with exactly one newline" % label, out.endswith(b"\n") and not out.endswith(b"\n\n"),
            "one trailing \\n", out[-40:].decode("utf-8", "replace"))
    t.check("%s has no ESC byte" % label, b"\x1b" not in out, "no ESC", "ESC present" if b"\x1b" in out else "")
    try:
        doc = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        t.check("%s is one JSON document" % label, False, "JSON", "%r: %s" % (e, out[:300]))
        raise Abort("no json")
    t.check("%s is a JSON object" % label, isinstance(doc, dict), "object", type(doc).__name__)
    if not isinstance(doc, dict):
        raise Abort("not an object")
    return doc


def check_envelope(t, doc, state, code):
    t.eq("envelope keys", sorted(doc.keys()), sorted(["schema_version", "state", "code", "data", "warnings", "next"]))
    t.eq("schema_version", doc.get("schema_version"), "1")
    t.eq("state", doc.get("state"), state)
    t.eq("code", doc.get("code"), code)
    t.eq("warnings", doc.get("warnings"), [])
    t.eq("next", doc.get("next"), None)


REGISTRY = {}


def check(task, cid, title):
    def deco(fn):
        REGISTRY.setdefault(task, []).append((cid, title, fn))
        return fn
    return deco


def run_task(task, ctx, only=None, log=print):
    results = []
    for cid, title, fn in REGISTRY.get(task, []):
        if only and not any(re.fullmatch(pat.replace("*", ".*"), cid) for pat in only):
            continue
        t = Check(cid, title)
        try:
            fn(t, ctx)
        except Abort:
            pass
        except Exception as e:  # noqa - a crash in a check is an error of the check, not a pass
            t.error = "exception: %s" % ctx.scrub("".join(traceback.format_exception_only(type(e), e)).strip())
            t.note(ctx.scrub(traceback.format_exc()[-1500:]))
        finally:
            H.kill_tracked(2.0)
        rec = {"id": cid, "title": title, "status": t.status, "error": t.error,
               "seconds": round(time.monotonic() - t.t0, 2),
               "assertions": [{k: ctx.scrub(v) if isinstance(v, str) else v for k, v in a.items()}
                              for a in t.assertions],
               "notes": [ctx.scrub(n) for n in t.notes]}
        results.append(rec)
        failed = [a["name"] for a in t.assertions if not a["ok"]]
        log("%-5s %s (%.1fs)%s" % (t.status.upper(), cid, rec["seconds"],
                                   (" :: " + "; ".join(failed[:4])) if failed else
                                   (" :: " + t.error if t.error else "")))
    return results


def proc_state(pid):
    """One-letter process state, 'gone', or None; never reads command lines."""
    if pid is None:
        return None
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            return s[s.rindex(")") + 2:].split()[0]
        except OSError:
            return "gone"
    r = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return (r.stdout.strip()[:1] or "gone") if r.stdout.strip() else "gone"


def proc_ppid(pid):
    if pid is None:
        return None
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            return int(s[s.rindex(")") + 2:].split()[1])
        except OSError:
            return None
    r = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return None


def kill_exact(pids):
    """SIGCONT + SIGKILL exactly these PIDs if they are still alive (not gone, not zombie)."""
    n = 0
    for p in pids:
        if p and proc_state(p) not in (None, "gone", "Z"):
            n += 1
            for s in (signal.SIGCONT, signal.SIGKILL):
                try:
                    os.kill(p, s)
                except OSError:
                    pass
    return n
