#!/usr/bin/env python3
"""G02 shared conformance harness: judges every candidate identically against
docs/g02/slice-contract.md and writes a plan.md section 6.6 evidence record.

  conformance.py --bin <path> --candidate <go|rust|ts> --out <record.json>
                 [--artifacts-dir <dir>] [--only <id,id,prefix.*>]
                 [--pass-env NAME,NAME] [--selftest] [--list] [--list-md]

Exit code: 0 only if every selected check ran and passed; 1 if any check
failed, errored or was skipped; 2 for harness usage errors; 3 if the final
canary self-check found a full HEIMDALL_CANARY_ value in the record or in an
artifact this run wrote (values are redacted before writing; evidence invalid).

Record (tests/evidence/README.md gate-probe convention): status `verified` when
the full catalogue ran with no errored/skipped check (whatever the outcome),
otherwise `in_progress`; observed_result.verdict is pass | fail | inconclusive.
Every check runs under a hard wall-clock bound (DEFAULT_BUDGET, FINISH_BUDGET).

Python standard library only; the TUI checks additionally need pyte (pinned in
requirements.txt).  Disposable fixtures only: no real ~/.ssh, no real agent
(SSH_AUTH_SOCK is never inherited), no network listeners other than Unix
sockets inside a private sandbox directory.
"""
import argparse
import datetime
import json
import os
import platform
import random
import re
import secrets
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import tomllib
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_lib as H  # noqa: E402
import minischema  # noqa: E402

HARNESS_VERSION = "2.4.2"
REPO = H.REPO
FIX = REPO / "tests" / "fixtures" / "g02" / "profiles"
SPACED = FIX / "spaced dir ü" / "prøfile homelab.toml"
RESULT_SCHEMA = json.loads((REPO / "schemas" / "g02" / "result.schema.json").read_text(encoding="utf-8"))
RECORD_SCHEMA = json.loads((REPO / "tests" / "evidence" / "record.schema.json").read_text(encoding="utf-8"))
REQUIREMENTS = ["R-SS-04", "R-SS-02", "R-SE-05", "R-QU-07"]
# Canary rule (tests/evidence/README.md): no record or artifact may contain a full HEIMDALL_CANARY_
# value; assertion text names a canary by fixture and key path only.  Values live in memory only:
# the fixture canaries are read from the fixtures at run time, the others are generated per run.
SECRET_ENV_NAME = "HM_G02_SECRET_ENV"      # carries a per-run canary into every binary's environment
FIXTURE_CANARIES = [("invalid-forbidden-key.toml", ("private_key",)),
                    ("invalid-unknown-dest-key.toml", ("destinations", 0, "identity_file"))]
EXIT_CANARY_SELFCHECK = 3                  # the harness's own record/artifacts contained a canary

HOMELAB = {"profile": {"name": "homelab", "revision": 3, "destinations": [
    {"id": "dst_lab_server", "alias": "lab-server", "host": "lab.example.internal", "port": 22,
     "account": "aman", "labels": ["homelab", "fixed-auth"]},
    {"id": "dst_nas", "alias": "nas", "host": "nas.example.internal", "port": 22,
     "account": "admin", "labels": ["homelab"]},
    {"id": "dst_vps_ünïcode", "alias": "vps-東京", "host": "vps1.example.invalid", "port": 2222,
     "account": "deploy", "labels": []}]}}
HOMELAB_DESTS = HOMELAB["profile"]["destinations"]

PY = sys.executable

# ---- child programs used by the `run` checks ------------------------------
CHILD_COPY = (
    "import sys\n"
    "data = sys.stdin.buffer.read()\n"
    "out, err = sys.stdout.buffer, sys.stderr.buffer\n"
    "for i in range(0, len(data), 65536):\n"
    "    c = data[i:i+65536]\n"
    "    out.write(c); out.flush()\n"
    "    err.write(c[::-1]); err.flush()\n")
CHILD_EXIT = "import sys; sys.exit(int(sys.argv[1]))"
CHILD_ARGV = ("import sys, os, json\n"
              "sys.stdout.write(json.dumps([os.fsencode(a).hex() for a in sys.argv[1:]]) + '\\n')\n")
CHILD_ENVCWD = ("import os, json\n"
                "print(json.dumps({'cwd': os.path.realpath(os.getcwd()), 'env': os.environ.get('HM_ENV_PROBE')}))\n")
CHILD_SELFKILL = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
CHILD_PIDFILE = ("import os, sys\n"
                 "open(sys.argv[1], 'w').write(str(os.getpid()))\n")
CHILD_TRAP = r"""
import os, signal, sys, time
d, mode = sys.argv[1], sys.argv[2]
# Count deliveries with the wakeup fd: CPython's C-level handler writes one byte per delivery,
# so two deliveries are counted twice even if the Python-level handler runs only once.
r, w = os.pipe()
os.set_blocking(r, False)
os.set_blocking(w, False)
signal.set_wakeup_fd(w, warn_on_full_buffer=False)
def h(sig, frame):
    pass
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
    signal.signal(s, h)
def note(name):
    with open(os.path.join(d, 'signals'), 'a') as f:
        f.write(name + '\n')
def finish():
    with open(os.path.join(d, 'child_exit_time'), 'w') as f:
        f.write(repr(time.time()))
    os._exit(7)
with open(os.path.join(d, 'pid'), 'w') as f:
    f.write(str(os.getpid()))
with open(os.path.join(d, 'ready'), 'w') as f:
    f.write('1')
first = None
grace = 0.3 if mode == 'exit' else 0.6
end = time.time() + 30
while time.time() < end:
    time.sleep(0.01)
    try:
        data = os.read(r, 256)
    except BlockingIOError:
        data = b''
    for b in data:
        note(signal.Signals(b).name)
        if b != signal.SIGWINCH and first is None:
            first = time.time()
    if first is not None and time.time() - first >= grace:
        finish()
os._exit(99)
"""

OUTCOMES = ("pass", "fail", "error", "skipped")


class Abort(Exception):
    """Stop the current check early (the reason was already recorded)."""


class PreconditionFailed(Exception):
    """A harness precondition (environment, fixture or harness self-consistency) does not hold: the check's
    evidence is invalid.  Recorded as outcome 'error' (never 'fail', which would read as a candidate failure)."""


# --------------------------------------------------------------------------
class Ctx:
    def __init__(self, binpath, candidate, artifacts_dir, pass_env):
        self.bin = str(binpath)
        self.candidate = candidate
        self.artifacts_dir = Path(artifacts_dir)
        self.sandbox = H.make_sandbox()
        self.cwd_ro = self.sandbox / "cwd ü ro"
        self.home = self.sandbox / "home"
        self.tmp = self.sandbox / "tmp"
        self.run_cwd = self.sandbox / "run cwd"
        for d in (self.cwd_ro, self.home, self.tmp, self.run_cwd):
            d.mkdir(parents=True)
        self.pass_env = {k: os.environ[k] for k in pass_env if k in os.environ}
        self.harness_mutate = set()        # selftest-only injected harness defects (HM_G02_HARNESS_MUTATE)
        self.env_canary = "HEIMDALL_CANARY_ENV_" + secrets.token_hex(8)
        self.meta_canary = "HEIMDALL_CANARY_META_" + secrets.token_hex(8)
        self.src_canary = "HEIMDALL_CANARY_SRC_" + secrets.token_hex(8)
        self.canaries = {self.env_canary: "per-run canary in the %s environment variable" % SECRET_ENV_NAME,
                         self.meta_canary: "per-run canary inside [meta] of a generated profile",
                         self.src_canary: "per-run canary on the malformed line of a generated profile"}
        self.fixture_canary_values = {}
        self.canary_load_errors = []
        for fname, keypath in FIXTURE_CANARIES:
            label = "fixture %s key %s" % (fname, dotted(keypath))
            try:
                v = tomllib.loads((FIX / fname).read_text(encoding="utf-8"))
                for k in keypath:
                    v = v[k]
                if not (isinstance(v, str) and v.startswith("HEIMDALL_CANARY_") and len(v) > 16):
                    raise ValueError("not a HEIMDALL_CANARY_ value")
                self.fixture_canary_values[(fname, keypath)] = v
                self.canaries[v] = label
            except (OSError, KeyError, IndexError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
                self.canary_load_errors.append("%s: %s" % (label, type(exc).__name__))
        self.written_artifacts = []
        self.pyte = H.load_pyte()
        self._keys = None
        self.canary_hits = []
        self.dir_counter = 0
        self.fix_snapshot = self.snapshot(FIX)
        self.captures_total = 0
        self.observations = {}
        self.stray_hits = []      # K11: (check id, invocation label, [stray paths])
        self.invocations_scanned = 0
        self.ran_ids = []

    def env(self, extra=None):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home),
               "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TMPDIR": str(self.tmp),
               "TERM": "xterm-256color", SECRET_ENV_NAME: self.env_canary}
        env.update(self.pass_env)
        env.update(extra or {})
        return env

    def new_dir(self, name):
        self.dir_counter += 1
        d = self.sandbox / ("%03d-%s" % (self.dir_counter, name))
        d.mkdir(parents=True)
        return d

    def keys(self):
        if self._keys is None:
            self._keys = H.generate_keys(self.sandbox / "keys")
        return self._keys

    @staticmethod
    def snapshot(root):
        snap = []
        for p in sorted(Path(root).rglob("*")):
            try:
                st = p.stat()
            except OSError:
                continue
            snap.append((str(p.relative_to(root)), st.st_size, st.st_mtime_ns))
        return snap

    def k11_roots(self, cwd, argv=()):
        """HOME, TMPDIR, the working directory and (R3) the directory of a --meta-file argument: a file
        left next to the named meta file (e.g. '<meta>.tmp') is a write outside the named paths (section 1)."""
        roots = [("HOME", self.home), ("TMPDIR", self.tmp), ("cwd", Path(cwd))]
        argv = [os.fsdecode(a) if isinstance(a, (bytes, str)) else str(a) for a in argv]
        for i, a in enumerate(argv[:-1]):
            if a == "--":
                break
            if a == "--meta-file":
                parent = Path(argv[i + 1]).parent
                if parent.is_dir() and all(os.path.realpath(parent) != os.path.realpath(r) for _n, r in roots):
                    roots.append(("metadir", parent))
                break
        return tuple(roots)

    def k11_snapshot(self, cwd, argv=()):
        """Set of '<ROOT>/<relative path>' entries below HOME, TMPDIR, the working directory and the
        --meta-file directory."""
        out = set()
        for name, root in self.k11_roots(cwd, argv):
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                for n in dirnames + filenames:
                    out.add("%s/%s" % (name, os.path.relpath(os.path.join(dirpath, n), root)))
        return out

    def cleanup(self):
        H.rm_tree(self.sandbox)


def dotted(keypath):
    out = ""
    for k in keypath:
        out += ("[%d]" % k) if isinstance(k, int) else ("." + k if out else k)
    return out


def short(x, n=400):
    try:
        s = x if isinstance(x, str) else json.dumps(x, ensure_ascii=False, default=repr)
    except (TypeError, ValueError):
        s = repr(x)
    s = H.safe_text(re.sub(r"HEIMDALL_CANARY_[A-Za-z0-9_]*", "[REDACTED_CANARY]", s))
    return s if len(s) <= n else s[:n] + "...[+%d]" % (len(s) - n)


def walk_strings(doc):
    if isinstance(doc, str):
        yield doc
    elif isinstance(doc, dict):
        for k, v in doc.items():
            yield from walk_strings(k)
            yield from walk_strings(v)
    elif isinstance(doc, list):
        for v in doc:
            yield from walk_strings(v)


class T:
    """Per-check recorder."""

    def __init__(self, ctx, cid, clause, title):
        self.ctx, self.id, self.clause, self.title = ctx, cid, clause, title
        self.assertions = []
        self.caps = []
        self.notes = {}
        self.sessions = []
        self.agents = []
        self.artifact_files = []
        self.art_dir = ctx.artifacts_dir / cid
        self.n = 0
        self.k11_pending = []     # (label, snapshot, cwd, argv) for pty sessions, checked at finish

    # -- assertions
    def check(self, desc, ok, expected=None, observed=None, gating=True):
        self.assertions.append({"desc": desc, "ok": bool(ok), "gating": gating,
                                "expected": short(expected), "observed": short(observed)})
        return bool(ok)

    def eq(self, desc, observed, expected, gating=True):
        return self.check(desc, observed == expected, expected, observed, gating)

    def require(self, desc, ok, expected=None, observed=None):
        if not self.check(desc, ok, expected, observed):
            raise Abort(desc)

    def precondition(self, desc, ok, expected=None, observed=None):
        """Harness precondition: not a judgement of the candidate.  Recorded as a non-gating assertion marked
        `precondition`; when it does not hold the check stops with outcome 'error' (invalid evidence)."""
        self.assertions.append({"desc": desc, "ok": bool(ok), "gating": False, "precondition": True,
                                "expected": short(expected), "observed": short(observed)})
        if not ok:
            raise PreconditionFailed(desc)
        return True

    def note(self, key, value):
        """Free-form note (may hold candidate output): canary values are redacted like captures."""
        try:
            txt = json.dumps(value, ensure_ascii=False, default=repr)
            red = H.redact_values(txt.encode("utf-8"), self.ctx.canaries).decode("utf-8")
            value = json.loads(red) if red != txt else value
        except (TypeError, ValueError):
            value = short(value)
        self.notes[key] = value

    # -- artifacts
    def save(self, name, data, limit=65536):
        self.art_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode("utf-8")
        data = H.redact_bytes(data)
        if len(data) > limit:
            data = data[:limit] + b"\n...[truncated %d bytes]\n" % (len(data) - limit)
        p = self.art_dir / name
        p.write_bytes(data)
        self.artifact_files.append(str(p))
        self.ctx.written_artifacts.append(p)

    def _record_cap(self, cap):
        self.n += 1
        self.caps.append(cap)
        self.ctx.captures_total += 1
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", cap.label)[:40]
        self.save("%02d-%s.stdout.txt" % (self.n, safe), cap.stdout)
        self.save("%02d-%s.stderr.txt" % (self.n, safe), cap.stderr)
        self.scan(cap.label + ".stdout", cap.stdout)
        self.scan(cap.label + ".stderr", cap.stderr)

    def scan(self, label, data):
        if H.CANARY_PREFIX in data:
            self.ctx.canary_hits.append("%s/%s" % (self.id, label))
            self.check("no HEIMDALL_CANARY_ in %s" % label, False, "absent", "PRESENT")
        else:
            self.check("no HEIMDALL_CANARY_ in %s" % label, True, "absent", "absent")

    # -- K11: no new files in HOME, TMPDIR or the working directory after an invocation
    def k11_check(self, label, before, cwd, argv):
        after = self.ctx.k11_snapshot(cwd, argv)
        named = set()
        for a in argv:
            try:
                named.add(os.path.realpath(os.fsdecode(a)))
            except (TypeError, ValueError):
                pass
        stray = []
        for entry in sorted(after - before):
            root, rel = entry.split("/", 1)
            base = dict(self.ctx.k11_roots(cwd, argv))[root]
            if os.path.realpath(os.path.join(base, rel)) not in named:
                stray.append(entry)
        self.ctx.invocations_scanned += 1
        if stray:
            self.ctx.stray_hits.append({"check": self.id, "invocation": label, "stray_paths": stray})
        self.check("[%s] K11 no new file in HOME, TMPDIR, the working directory or the --meta-file directory "
                   "(outside paths named on the command line)" % label, not stray, [], stray)
        return stray

    # -- running the binary
    def proto(self, *args, label=None, stdin_data=None, env=None, cwd=None, timeout=20.0, pre=None,
              post=None, ok_leftover=False, wrap=None, preexec_fn=None, stdout_fd=None):
        """Run the binary under test.  wrap: argv prefix of a measuring wrapper (rss_wrap.py);
        preexec_fn: run in the child before exec (e.g. inherited SIG_IGN dispositions)."""
        argv = list(wrap or []) + [self.ctx.bin] + list(args)
        cwd = str(cwd or self.ctx.cwd_ro)
        before = self.ctx.k11_snapshot(cwd, argv)
        cap = H.run_capture(label or " ".join(os.fsdecode(a) for a in args[:2]) or "proto", argv,
                            self.ctx.env(env), cwd, stdin_data=stdin_data,
                            timeout=timeout, pre=pre, post=post, preexec_fn=preexec_fn, stdout_fd=stdout_fd)
        self.k11_check(cap.label, before, cwd, argv)
        self._record_cap(cap)
        self.check("[%s] completed within %ss" % (cap.label, timeout), not cap.timed_out, "no timeout",
                   "TIMED OUT" if cap.timed_out else "ok")
        if not ok_leftover:
            self.check("[%s] no process left in the process group after exit" % cap.label, not cap.leftover,
                       "none left", "LEFTOVER (killed by harness)" if cap.leftover else "none left")
        return cap

    def parse_doc(self, data, label="stdout"):
        try:
            text = data.decode("utf-8")
            return json.loads(text)
        except (UnicodeDecodeError, ValueError) as exc:
            self.check("%s is one valid UTF-8 JSON document" % label, False, "valid JSON", repr(exc)[:200])
            return None

    def result(self, cap, exit_code, code, state=None, label=None):
        """Assert exit code and a schema-valid JSON result on stdout; return the document."""
        lb = label or cap.label
        self.check("[%s] exit code" % lb, cap.rc == exit_code, exit_code, cap.rc)
        data = cap.stdout
        shape_ok = data.endswith(b"\n") and not data.endswith(b"\n\n") and data[:1] == b"{"
        self.check("[%s] stdout is one JSON document followed by exactly one newline" % lb, shape_ok,
                   "{...}\\n", H.printable(data[:60] + (b"..." if len(data) > 60 else b"") + data[-8:]))
        doc = self.parse_doc(data, "[%s] stdout" % lb)
        if doc is None:
            return None
        errs = minischema.validate(RESULT_SCHEMA, doc)
        self.check("[%s] validates against schemas/g02/result.schema.json" % lb, not errs, "no errors", errs[:5])
        esc = [s for s in walk_strings(doc) if "\x1b" in s]
        self.check("[%s] no ANSI escape in any JSON string" % lb, not esc, "none", short(esc))
        if isinstance(doc, dict):
            self.check("[%s] code" % lb, doc.get("code") == code, code, doc.get("code"))
            if state:
                self.check("[%s] state" % lb, doc.get("state") == state, state, doc.get("state"))
        return doc

    def plain_error(self, cap, label=None):
        """Usage error without --json: exit 2, stdout empty, stderr text."""
        lb = label or cap.label
        self.check("[%s] exit code" % lb, cap.rc == 2, 2, cap.rc)
        self.check("[%s] stdout empty (stderr text only)" % lb, cap.stdout == b"", "empty",
                   H.printable(cap.stdout, 200))
        self.check("[%s] stderr carries a message" % lb, len(cap.stderr.strip()) > 0, "non-empty", "empty")

    def read_meta(self, path, label="meta"):
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            self.check("%s file was written" % label, False, "present", repr(exc)[:100])
            return None
        self.save("%s.json" % label, data)
        self.scan(label, data)
        doc = self.parse_doc(data, label)
        if doc is None:
            return None
        errs = minischema.validate(RESULT_SCHEMA, doc)
        self.check("%s validates against result schema" % label, not errs, "no errors", errs[:5])
        return doc

    def pty(self, argv, rows=24, cols=80, env=None, cwd=None, label=None, hup_forward=True, stderr_tty=False):
        """Start `argv` as the foreground job of a fresh pty; K11-scanned when the check finishes."""
        cwd = str(cwd or self.ctx.cwd_ro)
        before = self.ctx.k11_snapshot(cwd, argv)
        s = H.PtySession(self.ctx.pyte, argv, self.ctx.env(env), cwd, rows, cols, hup_forward=hup_forward,
                         stderr_tty=stderr_tty)
        s.label = label or "pty%d" % (len(self.sessions) + 1)
        self.sessions.append(s)
        self.k11_pending.append((s.label, before, cwd, argv))
        return s

    def finish(self):
        """Release everything the check started.  Bounded: PtySession.close and FakeAgent.stop
        never block indefinitely, and the caller arms a hard alarm around this method too."""
        for s in self.sessions:
            try:
                leftover = s.close()
                if leftover:
                    self.check("[%s] no process of the command's group left after the session" % s.label,
                               False, "none", "LEFTOVER (killed by harness)")
                if s.close_report.get("shim_unreaped"):
                    self.note("%s_close" % s.label, s.close_report)
            except Exception as exc:  # noqa
                self.note("%s_close_error" % getattr(s, "label", "pty"), repr(exc)[:200])
            if not s.saved:
                try:
                    self.save("%s.raw.bin" % s.label, bytes(s.raw), limit=262144)
                    self.scan(s.label + ".pty", bytes(s.raw))
                    s.saved = True
                except Exception:  # noqa
                    pass
            try:
                err = s.stderr_bytes()
                self.save("%s.stderr.txt" % s.label, err)
                self.scan(s.label + ".stderr", err)
            except Exception:  # noqa
                pass
            if s.feed_errors:
                self.note("%s_emulator_feed_errors" % s.label, s.feed_errors[:5])
        for label, before, cwd, argv in self.k11_pending:
            self.k11_check(label, before, cwd, argv)
        self.k11_pending = []
        for a in self.agents:
            try:
                a.stop()
            except Exception:  # noqa
                pass


# --------------------------------------------------------------------------
CHECKS = []   # (id, group, clause, title, needs, fn)


CLAUSE_RE = re.compile(r"^((?:§\d+|K\d+[a-z]?)(?:/(?:§?\d+|K\d+[a-z]?))*)\s+(.*)$")
DEFAULT_BUDGET = 120.0     # hard wall-clock bound per check (seconds), defect (c)
FINISH_BUDGET = 30.0       # hard bound for a check's cleanup
BUDGETS = {}


def check(cid, desc, needs=None, budget=None):
    """Register a check.  `desc` starts with the contract clause (e.g. "§3 ...", "§3/K1 ...") or is a
    harness self-check.  `budget` overrides the hard wall-clock bound (seconds)."""
    m = CLAUSE_RE.match(desc)
    clause, title = (m.group(1), m.group(2)) if m else ("harness", desc)

    def deco(fn):
        CHECKS.append((cid, cid.split(".")[0], clause, title, needs, fn))
        BUDGETS[cid] = budget or DEFAULT_BUDGET
        return fn
    return deco


# ===== harness self-validation (judge the judge) ==========================
@check("harness.schema_validator", "validator + contract schema sanity")
def _(t):
    minischema._selftest()
    t.check("minischema selftest", True)
    good = {"schema_version": "1", "state": "succeeded", "code": "PROFILE_OK", "warnings": [], "next": None,
            "data": HOMELAB}
    t.eq("good PROFILE_OK document accepted", minischema.validate(RESULT_SCHEMA, good), [])
    bad_cases = {
        "missing next": {k: v for k, v in good.items() if k != "next"},
        "wrong state for PROFILE_OK": dict(good, state="failed"),
        "extra destination key": dict(good, data={"profile": dict(HOMELAB["profile"], destinations=[
            dict(HOMELAB_DESTS[0], extra=1)])}),
        "port out of range": dict(good, data={"profile": dict(HOMELAB["profile"], destinations=[
            dict(HOMELAB_DESTS[0], port=70000)])}),
        "bad fingerprint": {"schema_version": "1", "state": "succeeded", "code": "AGENT_OK", "warnings": [],
                            "next": None, "data": {"identities": [
                                {"key_type": "x", "fingerprint": "SHA256:abc=", "comment": ""}]}},
        "error without data.error": {"schema_version": "1", "state": "failed", "code": "SCHEMA_INVALID",
                                     "warnings": [], "next": None, "data": {}},
        "unknown code": dict(good, code="NOPE"),
        "schema_version int": dict(good, schema_version=1),
        "cancelled state mismatch": {"schema_version": "1", "state": "failed", "code": "CANCELLED",
                                     "warnings": [], "next": None, "data": None},
    }
    for name, doc in bad_cases.items():
        t.check("schema rejects: %s" % name, bool(minischema.validate(RESULT_SCHEMA, doc)), "errors", "accepted")
    rec = {"case_id": "x", "status": "blocked", "requirement_ids": [], "build_commit": None,
           "artifact_digest": None, "environment": None, "provider_versions": [], "started_at": None,
           "commands_or_harness": None, "observed_result": None, "evidence_paths": [], "limitations": []}
    t.check("record schema: blocked without blocked_on rejected", bool(minischema.validate(RECORD_SCHEMA, rec)))
    t.check("record schema: unknown status rejected",
            bool(minischema.validate(RECORD_SCHEMA, dict(rec, status="passed"))))


@check("harness.expected_data", "hard-coded expectations equal the frozen fixtures")
def _(t):
    doc = tomllib.loads((FIX / "homelab.toml").read_text(encoding="utf-8"))
    derived = []
    for d in doc["destinations"]:
        derived.append({"id": d["id"], "alias": d["alias"], "host": d["host"], "port": d.get("port", 22),
                        "account": d["account"], "labels": d.get("labels", [])})
    t.eq("HOMELAB literal equals tomllib(homelab.toml) with defaults applied", derived, HOMELAB_DESTS)
    t.eq("spaced fixture identical to homelab.toml", SPACED.read_bytes(), (FIX / "homelab.toml").read_bytes())
    big = tomllib.loads((FIX / "large-100.toml").read_text(encoding="utf-8"))
    t.eq("large-100 fixture has 100 destinations", len(big["destinations"]), 100)


@check("harness.ansi_parsers", "terminal-sequence parsers (restore order, color SGR)")
def _(t):
    ok_seq = b"\x1b[?1049h\x1b[?25lFRAME\x1b[?1049l\x1b[?25hSELECTED nas\r\n"
    st = H.final_state(ok_seq)
    t.check("alt entered/left, cursor hidden/shown",
            st["alt_entered"] and not st["alt_active_at_end"] and st["cursor_hidden_ever"] and not st["cursor_hidden_at_end"],
            "restored", st)
    t.eq("tail after restore", H.tail_after_restore(ok_seq), b"SELECTED nas\r\n")
    t.check("combined mode list handled", not H.final_state(b"\x1b[?1049;25h\x1b[?1049;25l")["alt_active_at_end"])
    bad = b"\x1b[?1049h\x1b[?25lX\x1b[?25h\x1b[?1049l\x1b[?25l"
    t.check("cursor hidden at end detected", H.final_state(bad)["cursor_hidden_at_end"])
    t.check("alt still active detected", H.final_state(b"\x1b[?1049h\x1b[?25l\x1b[?25h")["alt_active_at_end"])
    t.check("tail with cursor addressing is flagged",
            bool(H.disallowed_tail_sequences(b"\x1b[3;1Hjunk")))
    t.check("tail with SGR reset / mouse-off tolerated",
            not H.disallowed_tail_sequences(b"\x1b[0m\x1b[?1000lSELECTED a\n"))
    for seq, expect in ((b"\x1b[31m", True), (b"\x1b[1;32m", True), (b"\x1b[38;5;12m", True),
                        (b"\x1b[48;2;1;2;3m", True), (b"\x1b[38:2::1:2:3m", True), (b"\x1b[94m", True),
                        (b"\x1b[1m", False), (b"\x1b[7m", False), (b"\x1b[0m", False), (b"\x1b[m", False),
                        (b"\x1b[4:3m", False), (b"\x1b[39m", False), (b"\x1b[2;4m", False)):
        t.eq("color detector %r" % seq, bool(H.color_sgr_found(seq)), expect)


@check("harness.keygen", "disposable keys; ssh-keygen fingerprint equals independent computation")
def _(t):
    keys = t.ctx.keys()
    t.eq("three keys generated", [k["kind"] for k in keys], ["ed25519", "ecdsa", "rsa"])
    for k in keys:
        t.eq("fingerprint (%s) ssh-keygen -lf == sha256(blob)" % k["kind"], k["computed_fingerprint"],
             k["sshkeygen_fingerprint"])
    left = [p.name for p in (t.ctx.sandbox / "keys").iterdir() if not p.name.endswith(".pub")]
    t.eq("no private key files remain", left, [])


@check("harness.fake_agent", "instrumented fake agent: protocol, contact log, SIGTERM cleanup")
def _(t):
    keys = t.ctx.keys()
    d = t.ctx.new_dir("fa")
    sockdir = d / "fa dir ü"
    fa = H.FakeAgent(t.ctx.sandbox, sockdir, "fa", "normal", [k["pub"] for k in keys],
                     sock_path=sockdir / "agént 東.sock")
    t.agents.append(fa)
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect(fa.sock)
    s.sendall(struct.pack(">IB", 1, 11))
    hdr = s.recv(4)
    (n,) = struct.unpack(">I", hdr)
    body = b""
    while len(body) < n:
        body += s.recv(n - len(body))
    t.eq("answer type is 12 (IDENTITIES_ANSWER)", body[0], 12)
    t.eq("answer nkeys", struct.unpack(">I", body[1:5])[0], 3)
    s.sendall(struct.pack(">IB", 1, 13))  # a SIGN_REQUEST-typed frame (garbage): must never be honoured
    resp = s.recv(9)
    t.eq("non-11 request answered with SSH_AGENT_FAILURE", resp, struct.pack(">IB", 1, 5))
    s.close()
    fa.wait_disconnect()
    rc, removed = fa.stop()
    t.eq("SIGTERM exit status", rc, 0)
    t.check("SIGTERM removes the socket", removed, True, removed)
    ev = fa.events()
    kinds = [(e["event"], e.get("type")) for e in ev]
    t.eq("contact log sequence", kinds, [("listen", None), ("connect", None), ("message", 11), ("message", 13),
                                         ("disconnect", None), ("shutdown", None)])
    t.save("fake-agent.contact.jsonl", Path(fa.log_path).read_bytes())
    t.check("spaced/Unicode socket path used", " " in fa.sock and "ü" in fa.sock and "東" in fa.sock)


PTY_PROBE = r"""
import os, sys, tty, termios, select, time
if os.getpgrp() != os.tcgetpgrp(0):
    sys.exit(97)
open('/dev/tty', 'rb').close()
old = termios.tcgetattr(0)
tty.setraw(0)
os.write(1, b"\x1b[6n\x1b[c")
buf = b""
end = time.time() + 3
while time.time() < end and not (b"R" in buf and b"c" in buf):
    r, _, _ = select.select([0], [], [], 0.1)
    if r:
        buf += os.read(0, 100)
termios.tcsetattr(0, termios.TCSADRAIN, old)
os.write(1, b"GOT " + buf.replace(b"\x1b", b"<ESC>") + b"\r\n")
sys.exit(42)
"""


@check("harness.pty_session", "pty shim: controlling tty, foreground group, terminal queries answered, rc and termios readable after exit", "pyte")
def _(t):
    s = H.PtySession(t.ctx.pyte, [PY, "-c", PTY_PROBE], t.ctx.env(), str(t.ctx.cwd_ro), 24, 80)
    t.sessions.append(s)
    rc = s.wait_exit(8.0)
    t.eq("probe exit status (97 = not foreground job, 1 = no controlling tty)", rc, 42)
    t.check("device-attributes and cursor-position replies reached the program",
            "[?6c" in s.text().replace("<ESC>", "") or "<ESC>[?6c" in s.text(), "DA reply", s.lines()[:3])
    t.check("cursor-position reply present", "<ESC>[1;1R" in s.text(), "<ESC>[1;1R", s.lines()[:3])
    t.eq("termios readable after the job exited and equal to before", H.normalize_termios(s.termios_after()),
         H.normalize_termios(s.attr_before))
    s.close()


def _fake_agent_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("hm_fake_agent", str(H.FAKE_AGENT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _raw_exchange(sock_path, timeout=3.0, with_end=False):
    """Send one type-11 request and read until end of stream or timeout.

    Returns (bytes, eof_seen), or with with_end=True (bytes, end) where end is "EOF", "ECONNRESET"
    or None (timeout / complete frame)."""
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(sock_path)
    s.sendall(struct.pack(">IB", 1, 11))
    data, end_kind = b"", None
    end = time.monotonic() + timeout
    try:
        while time.monotonic() < end:
            chunk = s.recv(65536)
            if not chunk:
                end_kind = "EOF"
                break
            data += chunk
            if len(data) >= 4 and len(data) >= 4 + struct.unpack(">I", data[:4])[0]:
                break
    except ConnectionResetError:
        end_kind = "ECONNRESET"
    except socket.timeout:
        pass
    s.close()
    if with_end:
        return data, end_kind
    return data, end_kind is not None


@check("harness.fake_agent_modes", "fake-agent modes added for K1/K3/K3a/K4 put exactly the intended bytes on the wire")
def _(t):
    fa_mod = _fake_agent_module()
    d = t.ctx.new_dir("fam")
    for mode in ("reset_before_reply", "reset_after_byte"):
        fa = H.FakeAgent(t.ctx.sandbox, d, mode, mode)
        t.agents.append(fa)
        data, end = _raw_exchange(fa.sock, with_end=True)
        want = b"" if mode == "reset_before_reply" else b"\x00"
        t.eq("[%s] reply bytes before the connection ended" % mode, data, want)
        t.check("[%s] the connection ended (reset or EOF) instead of hanging" % mode, end in ("EOF", "ECONNRESET"),
                "EOF|ECONNRESET", end)
        t.check("[%s] how this OS delivers the agent's reset to the reader (non-gating observation; Linux: "
                "ECONNRESET, Darwin AF_UNIX: EOF)" % mode, True, None, {"os": platform.system(), "delivery": end},
                gating=False)
        t.ctx.observations.setdefault("k3a_reset_delivery", {})[mode] = end
        fa.wait_disconnect()
        fa.stop()
        ev = fa.events()
        disc = [e for e in ev if e["event"] == "disconnect"]
        t.check("[%s] contact log: request logged (type 11) but left unread, server reset the connection" % mode,
                [e.get("type") for e in ev if e["event"] == "message"] == [11]
                and [(x.get("reason"), x.get("request_left_unread")) for x in disc] == [("server_reset", True)],
                "message [11], disconnect server_reset", [e for e in ev if e["event"] in ("message", "disconnect")])
    for mode in ("control_chars", "close_silent", "partial_header", "failure_payload"):
        fa = H.FakeAgent(t.ctx.sandbox, d, mode, mode)
        t.agents.append(fa)
        data, eof = _raw_exchange(fa.sock)
        if mode == "control_chars":
            body = data[4:]
            t.eq("[control_chars] reply type 12, nkeys 1", (body[:1], body[1:5]), (b"\x0c", b"\x00\x00\x00\x01"))
            (bl,) = struct.unpack(">I", body[5:9])
            blob = body[9:9 + bl]
            (kl,) = struct.unpack(">I", blob[:4])
            t.eq("[control_chars] key type bytes inside the blob", blob[4:4 + kl], fa_mod.K1_KEY_TYPE)
            (cl,) = struct.unpack(">I", body[9 + bl:13 + bl])
            t.eq("[control_chars] comment bytes", body[13 + bl:13 + bl + cl], fa_mod.K1_COMMENT)
            for name, raw in (("key type", fa_mod.K1_KEY_TYPE), ("comment", fa_mod.K1_COMMENT)):
                txt = raw.decode("utf-8", "replace")
                t.check("[control_chars] %s holds ESC, TAB, DEL, a C1 code point and invalid UTF-8" % name,
                        all(c in txt for c in "\x1b\t\x7f") and any(0x80 <= ord(c) <= 0x9f for c in txt)
                        and "\ufffd" in txt, True, txt.encode("unicode_escape").decode())
        elif mode == "close_silent":
            t.eq("[close_silent] zero reply bytes, then EOF", (data, eof), (b"", True))
        elif mode == "partial_header":
            t.eq("[partial_header] exactly one reply byte, then EOF", (data, eof), (b"\x00", True))
        else:
            t.eq("[failure_payload] type-5 frame of length 5", data, b"\x00\x00\x00\x05\x05\x00\x00\x00\x00")
        fa.wait_disconnect()
        fa.stop()
        ev = fa.events()
        t.eq("[%s] contact log: one type-11 message" % mode,
             [e.get("type") for e in ev if e["event"] == "message"], [11])
    # round-3 framing modes: exact bytes on the wire (the connection stays open, the reader stops at the
    # declared frame end)
    dummy_blob, dummy_comment = fa_mod.dummy_key()
    want = {"zero_length_frame": b"\x00\x00\x00\x00",
            "answer_type_only": b"\x00\x00\x00\x01\x0c",
            "answer_short": b"\x00\x00\x00\x03\x0c\x00\x00",
            "nkeys_short": fa_mod.frame(b"\x0c" + struct.pack(">I", 3) + fa_mod.ssh_string(dummy_blob)
                                        + fa_mod.ssh_string(dummy_comment))}
    for mode, exp in want.items():
        fa = H.FakeAgent(t.ctx.sandbox, d, mode, mode)
        t.agents.append(fa)
        data, _eof = _raw_exchange(fa.sock)
        t.eq("[%s] reply bytes" % mode, data, exp)
        fa.stop()
    t.check("[nkeys_short] declared nkeys (3) is within the 1024 bound and exceeds the keys present (1)",
            struct.unpack(">I", want["nkeys_short"][5:9])[0] == 3, 3, struct.unpack(">I", want["nkeys_short"][5:9])[0])
    fa = H.FakeAgent(t.ctx.sandbox, d, "drip", "drip")
    t.agents.append(fa)
    t0 = time.monotonic()
    data, _eof = _raw_exchange(fa.sock, timeout=1.0)
    el = time.monotonic() - t0
    t.check("[drip] within 1 s the agent sent the first bytes of the reply but not the whole frame",
            0 < len(data) < 4 + len(fa_mod.Agent.identities_payload([fa_mod.dummy_key()])), "partial frame",
            {"bytes": len(data), "elapsed_s": round(el, 3)})
    t.check("[drip] the bytes are a prefix of the normal answer",
            fa_mod.frame(fa_mod.Agent.identities_payload([fa_mod.dummy_key()])).startswith(data), True, H.printable(data))
    fa.stop()


@check("harness.screen_wide_chars", "defect (a): emulator renders split double-width cells like xterm (no IndexError, nothing hidden)", "pyte")
def _(t):
    pyte = t.ctx.pyte
    cases = [
        # (name, bytes fed after "vps-東京" was drawn on row 1, expected row 1)
        ("narrow char over the left half of a wide char (Ratatui diff)", b"\x1b[1;5Hx", "vps-x 京"),
        ("narrow char over the right half of a wide char", b"\x1b[1;6Hy", "vps- y京"),
        ("wide char over the right half of one wide char and the left half of the next", "\x1b[1;6H日".encode("utf-8"),
         "vps- 日"),
        ("erase-in-line starting at the right half of a wide char", b"\x1b[1;6H\x1b[K", "vps-"),
        ("intact wide characters", b"", "vps-東京"),
        ("narrow chars fully replacing a wide char", b"\x1b[1;5Hab", "vps-ab京"),
    ]
    for name, seq, want in cases:
        scr = H.make_screen(pyte, 20, 3)
        st = pyte.ByteStream(scr)
        st.feed("\x1b[1;1Hvps-東京".encode("utf-8") + seq)
        try:
            got = scr.display[0].rstrip()
        except Exception as exc:  # noqa
            got = "EXCEPTION %r" % exc
        t.eq("harness screen: %s" % name, got, want)
        stock = pyte.Screen(20, 3)
        pyte.ByteStream(stock).feed("\x1b[1;1Hvps-東京".encode("utf-8") + seq)
        try:
            sgot = stock.display[0].rstrip()
        except Exception as exc:  # noqa
            sgot = "EXCEPTION %r" % exc
        t.check("stock pyte 0.8.2 on the same input (documents why the override exists; non-gating)",
                True, want, sgot, gating=False)
    t.eq("render_cells: orphan stub at line start", H.render_cells(["", "a"], lambda c: 1), " a")
    # The exact byte sequence the Rust/Ratatui prototype emitted (2026-10-03) when the row 'vps-東京' was
    # blanked by a filter: only the left halves of the wide characters are overwritten.
    ratatui = ("\x1b[3;3Hvps-東\x1b[3;9H京\x1b[3;13Hdeploy@vps1.example.invalid:2222"
               "\x1b[3;3H     \x1b[3;9H \x1b[3;13H                                ").encode("utf-8")
    scr = H.make_screen(pyte, 80, 24)
    pyte.ByteStream(scr).feed(ratatui)
    try:
        got = scr.display[2]
    except Exception as exc:  # noqa
        got = "EXCEPTION %r" % exc
    t.eq("harness screen: Ratatui diff blanking 'vps-東京' leaves a blank row", got, " " * 80)
    stock = pyte.Screen(80, 24)
    pyte.ByteStream(stock).feed(ratatui)
    try:
        sgot = stock.display[2]
    except Exception as exc:  # noqa
        sgot = "EXCEPTION %r" % exc
    t.check("stock pyte 0.8.2 on the Ratatui sequence (the original defect; non-gating)", True, "IndexError",
            sgot, gating=False)


def _scroll_frames():
    """The structure of the Go/Bubble Tea v2 prototype's output (observed 2026-10-04, large-100 at 80x24) when the
    list scrolls by 8 rows and back: full frame of rows 0-22 plus a status line, then SU 8 inside DECSTBM 1;23 and
    the 8 new bottom rows, then SD 8 inside the same region and the 8 new top rows."""
    rows = ["  row-%02d" % i for i in range(31)]
    first = "\x1b[H\x1b[2J" + "\r\n".join(rows[0:23]) + "\r\n100/100"
    down = "\x1b[1;23r\x1b[23;1H\x1b[8S\x1b[1;24r\x1b[16;1H" + "\r\n".join(rows[23:31])
    up = "\x1b[1;23r\x1b[H\x1b[8T\x1b[1;24r\x1b[H" + "\r\n".join(rows[0:8])
    return first.encode(), down.encode(), up.encode(), rows


@check("harness.screen_scroll_region", "defect (g): emulator implements SU/SD (CSI S / CSI T) inside a DECSTBM scrolling region (Bubble Tea v2 scrolls lists this way; stock pyte 0.8.2 drops them and keeps stale rows)", "pyte")
def _(t):
    pyte = t.ctx.pyte
    first, down, up, rows = _scroll_frames()
    scr = H.make_screen(pyte, 80, 24)
    st = H.make_stream(pyte, scr)
    st.feed(first + down)
    t.eq("harness screen: after SU 8 in region 1-23 the list shows rows 8-30 and the status line is untouched",
         [x.rstrip() for x in scr.display], [r for r in rows[8:31]] + ["100/100"])
    st.feed(up)
    t.eq("harness screen: after SD 8 in the same region the list shows rows 0-22 again and the status line is "
         "untouched", [x.rstrip() for x in scr.display], [r for r in rows[0:23]] + ["100/100"])
    t.eq("harness screen: cursor position is not changed by SU/SD (next write lands where the cursor was)",
         (scr.cursor.y, scr.cursor.x), (7, len(rows[7])))
    for name, seq, want in (("CSI 0 S scrolls one line (0 means 1)", b"\x1b[H\x1b[2Ja\r\nb\r\nc\x1b[0S", ["b", "c", ""]),
                            ("CSI T without parameter scrolls down one line", b"\x1b[H\x1b[2Ja\r\nb\r\nc\x1b[T",
                             ["", "a", "b"]),
                            ("private CSI ? 1;1;0 S (XTSMGRAPHICS query) does not scroll",
                             b"\x1b[H\x1b[2Ja\r\nb\r\nc\x1b[?1;1;0S", ["a", "b", "c"]),
                            ("SU larger than the region blanks it", b"\x1b[H\x1b[2Ja\r\nb\r\nc\x1b[9S", ["", "", ""])):
        s3 = H.make_screen(pyte, 10, 3)
        H.make_stream(pyte, s3).feed(seq)
        t.eq("harness screen: %s" % name, [x.rstrip() for x in s3.display], want)
    stock = pyte.Screen(80, 24)
    pyte.ByteStream(stock).feed(first + down + up)
    t.check("stock pyte 0.8.2 on the same frames (documents why the override exists; non-gating: it keeps stale rows)",
            True, [r.strip() for r in rows[0:23]], [x.strip() for x in stock.display[:23]], gating=False)


PTY_FLOOD = "import os, time\nos.write(1, b'x' * 4096)\nwhile True:\n    os.write(1, b'y' * 65536)\n"


@check("harness.pty_close_undrained", "defect (b): tearing down a pty session with undrained output finishes in bounded time", "pyte", budget=60)
def _(t):
    for mode in ("killed-while-writing", "exited-with-queued-output"):
        prog = PTY_FLOOD if mode == "killed-while-writing" else \
            "import os, sys\nos.write(1, b'z' * 3000)\nsys.exit(3)\n"
        s = H.PtySession(t.ctx.pyte, [PY, "-c", prog], t.ctx.env(), str(t.ctx.cwd_ro), 24, 80)
        t.sessions.append(s)
        s.label = mode
        time.sleep(0.5)          # deliberately do NOT read the master
        t0 = time.monotonic()
        leftover = s.close()
        dt = time.monotonic() - t0
        t.check("[%s] close() returned within 10 s without reading first" % mode, dt < 10.0, "< 10 s",
                "%.2f s" % dt)
        t.check("[%s] shim reaped, no process left" % mode,
                not leftover and not s.close_report.get("shim_unreaped") and s.shim.poll() is not None,
                "reaped", s.close_report)
    # Regression proof: the legacy teardown (close the control pipe, then wait for the shim WITHOUT
    # reading the master) on the same scenario.  On macOS it blocks until the output is drained.
    s = H.PtySession(t.ctx.pyte, [PY, "-c", "import os, sys\nos.write(1, b'z' * 3000)\nsys.exit(3)\n"],
                     t.ctx.env(), str(t.ctx.cwd_ro), 24, 80)
    t.sessions.append(s)
    s.label = "legacy-teardown"
    time.sleep(0.5)
    os.close(s.ctl_w)
    s.ctl_w = -1                     # never close a recycled descriptor number later
    t0 = time.monotonic()
    try:
        s.shim.wait(timeout=2.0)
        legacy = "finished in %.2f s" % (time.monotonic() - t0)
    except subprocess.TimeoutExpired:
        legacy = "still blocked after 2.0 s (the original defect)"
    t.check("legacy non-draining teardown on this OS (%s; non-gating observation)" % platform.system(), True,
            "still blocked on macOS", legacy, gating=False)
    t.note("legacy_teardown", legacy)
    t0 = time.monotonic()
    s.close()
    t.check("[legacy-teardown] the fixed close() still finishes it within 10 s", time.monotonic() - t0 < 10.0,
            "< 10 s", "%.2f s" % (time.monotonic() - t0))
    s = H.PtySession(t.ctx.pyte, [PY, "-c", "import tty, time\ntty.setraw(0)\nprint('raw', flush=True)\n"
                                  "time.sleep(60)\n"], t.ctx.env(), str(t.ctx.cwd_ro), 24, 80)
    t.sessions.append(s)
    s.label = "stalled-reader"
    t.require("non-reading raw-mode program started", s.wait_for(lambda x: "raw" in x.text(), 5.0) is not None,
              "raw", s.lines()[:2])
    t0 = time.monotonic()
    try:
        s.send(b"y" * 200000, timeout=1.0)
        stalled = False
    except H.HarnessStall:
        stalled = True
    t.check("send() to a program that stopped reading raises HarnessStall instead of blocking",
            stalled and time.monotonic() - t0 < 5.0, "HarnessStall within 5 s",
            {"stalled": stalled, "seconds": round(time.monotonic() - t0, 2)})


@check("harness.check_bound", "defect (c): a blocked check and a blocked cleanup are cut off by the hard wall-clock bound")
def _(t):
    blocked = {}

    def hangs_in_waitpid(inner):
        p = H.spawn([PY, "-c", "import time; time.sleep(60)"], t.ctx.env(), str(t.ctx.cwd_ro))
        blocked["proc"] = p
        os.waitpid(p.pid, 0)          # would block for 60 s

    inner = T(t.ctx, "harness.check_bound.inner", "harness", "inner")
    t0 = time.monotonic()
    outcome, error = run_one(inner, hangs_in_waitpid, 1.0, 2.0)
    dt = time.monotonic() - t0
    H.arm(BUDGETS[t.id])              # run_one disarmed the outer bound; re-arm it
    t.eq("blocked check recorded as error", outcome, "error")
    t.check("error names the hard bound", "hard wall-clock bound" in (error or ""), "hard bound", error)
    t.check("returned within 6 s (1 s bound + bounded reaping)", dt < 6.0, "< 6 s", "%.2f s" % dt)
    p = blocked.get("proc")
    t.check("the blocked check's process was killed and reaped", p is not None and p.poll() is not None,
            "reaped", p.poll() if p else None)

    inner2 = T(t.ctx, "harness.check_bound.inner2", "harness", "inner2")
    inner2.finish = lambda: time.sleep(60)
    t0 = time.monotonic()
    outcome2, error2 = run_one(inner2, lambda x: x.check("ok", True), 5.0, 1.0)
    dt2 = time.monotonic() - t0
    H.arm(BUDGETS[t.id])
    t.eq("blocked cleanup recorded as error", outcome2, "error")
    t.check("error names the cleanup bound", "cleanup exceeded" in (error2 or ""), "cleanup bound", error2)
    t.check("returned within 6 s", dt2 < 6.0, "< 6 s", "%.2f s" % dt2)


# ===== usage (contract section 1) ==========================================
@check("usage.unknown_subcommand_json", "§1 usage errors with --json")
def _(t):
    c = t.proto("frobnicate", "--json")
    t.result(c, 2, "USAGE_ERROR", "failed")


@check("usage.unknown_subcommand_plain", "§1 usage errors without --json: stderr only")
def _(t):
    t.plain_error(t.proto("frobnicate"))


@check("usage.unknown_flag_json", "§1 usage errors with --json")
def _(t):
    c = t.proto("profile", "show", "--file", str(FIX / "homelab.toml"), "--bogus-flag", "--json")
    t.result(c, 2, "USAGE_ERROR", "failed")


@check("usage.unknown_flag_plain", "§1 usage errors without --json: stderr only")
def _(t):
    t.plain_error(t.proto("profile", "show", "--file", str(FIX / "homelab.toml"), "--bogus-flag"))


@check("usage.missing_argument_json", "§1 usage errors with --json")
def _(t):
    t.result(t.proto("profile", "show", "--json", label="profile-no-file"), 2, "USAGE_ERROR", "failed")
    t.result(t.proto("agent", "list", "--json", label="agent-no-socket"), 2, "USAGE_ERROR", "failed")


@check("usage.missing_argument_plain", "§1 usage errors without --json: stderr only")
def _(t):
    t.plain_error(t.proto("profile", "show", label="profile-no-file"))
    t.plain_error(t.proto("agent", "list", label="agent-no-socket"))


# ===== profile (contract section 2) ========================================
def profile_ok(t, path, expected=HOMELAB, label=None):
    c = t.proto("profile", "show", "--file", str(path), "--json", label=label or "profile-ok")
    doc = t.result(c, 0, "PROFILE_OK", "succeeded")
    if doc:
        t.eq("data equals expected profile", doc.get("data"), expected)
        t.eq("warnings", doc.get("warnings"), [])
        t.eq("next", doc.get("next"), None)
    return doc


@check("profile.homelab_exact", "§2 exact data, order, default port, Unicode alias, labels default")
def _(t):
    doc = profile_ok(t, FIX / "homelab.toml")
    if doc and isinstance(doc.get("data"), dict):
        dests = doc["data"].get("profile", {}).get("destinations", [])
        t.eq("destination order preserved", [d.get("alias") for d in dests], ["lab-server", "nas", "vps-東京"])
        t.eq("default port 22 applied to nas", [d.get("port") for d in dests][1:2], [22])
        t.eq("labels default to []", [d.get("labels") for d in dests][2:3], [[]])
    # stdout must be valid UTF-8 containing the Unicode alias (not escaped garbage)
    t.check("stdout is UTF-8 text containing the alias", "vps-東京".encode("utf-8") in t.caps[-1].stdout
            or b"\\u6771" in t.caps[-1].stdout.lower())


@check("profile.spaced_unicode_path", "§1/§2 paths with spaces and non-ASCII")
def _(t):
    profile_ok(t, SPACED)


@check("profile.large_100", "§2 large fixture (100 destinations)")
def _(t):
    big = tomllib.loads((FIX / "large-100.toml").read_text(encoding="utf-8"))
    exp = {"profile": {"name": "large", "revision": 1, "destinations": [
        {"id": d["id"], "alias": d["alias"], "host": d["host"], "port": d.get("port", 22),
         "account": d["account"], "labels": d.get("labels", [])} for d in big["destinations"]]}}
    doc = profile_ok(t, FIX / "large-100.toml", exp)
    if doc and isinstance(doc.get("data"), dict):
        t.eq("100 destinations", len(doc["data"]["profile"]["destinations"]), 100)


def assert_values_not_in_result(t, label, doc, cap, values, allow_in_warnings=(), offending=True):
    """Section 2: an error result never includes the offending value (nor, for the schema_version
    warning, the value of another key).  `values`: {description: bytes/str marker}.  Gating on every
    string of the JSON result (message, key_path, warnings, ...).  K18 (section 9.3, settles Q9): every
    offending input value counts as potentially secret and must not appear on stdout or stderr either, so
    with offending=True the stderr check gates too.  offending=False marks the values of OTHER keys (the
    schema_version case): K18 does not name them, so on stderr they stay a non-gating observation (Q11)."""
    strings = list(walk_strings(doc)) if doc is not None else []
    warn = [w for w in ((doc or {}).get("warnings") or []) if isinstance(w, str)] if isinstance(doc, dict) else []
    for what, marker in values.items():
        m = marker.decode("utf-8") if isinstance(marker, bytes) else marker
        pool = [x for x in strings if not (what in allow_in_warnings and x in warn)]
        hit = [x for x in pool if m in x]
        t.check("[%s] JSON result never contains %s (section 2)" % (label, what), not hit, "absent", short(hit, 200))
        on_err = m.encode("utf-8") in cap.stderr
        if offending:
            t.check("[%s] stderr never contains %s (K18: offending values count as secret)" % (label, what),
                    not on_err, "absent", "PRESENT" if on_err else "absent")
            on_out = m.encode("utf-8") in cap.stdout and what not in allow_in_warnings
            t.check("[%s] stdout never contains %s (K18)" % (label, what), not on_out, "absent",
                    "PRESENT" if on_out else "absent")
        else:
            t.check("[%s] %s on stderr (non-gating observation: a value of another key, not named by K18; Q11)"
                    % (label, what), True, "absent", "PRESENT" if on_err else "absent", gating=False)
        if on_err:
            t.ctx.observations.setdefault("value_on_stderr", []).append(
                {"check": t.id, "case": label, "value": what, "gating": offending})


def invalid_case(t, name, expect_key_fragment=None, expect_warning_fragment=None, forbid_canary=None,
                 forbid_values=None, allow_in_warnings=(), offending=True):
    c = t.proto("profile", "show", "--file", str(FIX / name), "--json", label=name)
    doc = t.result(c, 2, "SCHEMA_INVALID", "failed")
    if forbid_values:
        assert_values_not_in_result(t, name, doc, c, forbid_values, allow_in_warnings, offending=offending)
    blob = c.stdout + c.stderr
    if forbid_canary is not None:
        # The canary is named by fixture and key path; its value exists only in memory (canary rule).
        val = t.ctx.fixture_canary_values.get((name, forbid_canary))
        kp = dotted(forbid_canary)
        t.precondition("[%s] harness precondition: canary value of key %s loaded from the fixture" % (name, kp),
                  val is not None, "loaded", t.ctx.canary_load_errors)
        if "canary_in_desc" in t.ctx.harness_mutate:
            # selftest-only injected harness defect (the round-1 leak): the value in assertion text
            t.check("[%s] output never contains the offending value %s" % (name, val), val.encode() not in blob)
        t.check("[%s] output never contains the full value of key %s (canary)" % (name, kp),
                val.encode() not in blob, "absent", "PRESENT" if val.encode() in blob else "absent")
        rest = val[len("HEIMDALL_CANARY_"):].encode()
        t.check("[%s] output never contains the value of key %s without its HEIMDALL_CANARY_ prefix" % (name, kp),
                rest not in blob, "absent", "PRESENT" if rest in blob else "absent")
    if doc and isinstance(doc.get("data"), dict):
        err = doc["data"].get("error", {})
        if expect_key_fragment:
            kp = err.get("key_path")
            t.check("[%s] key_path names the offending key" % name,
                    isinstance(kp, str) and all(f in kp for f in expect_key_fragment), expect_key_fragment, kp)
        if expect_warning_fragment:
            w = doc.get("warnings") or []
            t.check("[%s] a warning names the unsupported version" % name,
                    any(expect_warning_fragment in x for x in w), expect_warning_fragment, w)
    return c


@check("profile.invalid_forbidden_key", "§2 forbidden key -> SCHEMA_INVALID; value never echoed (canary)")
def _(t):
    invalid_case(t, "invalid-forbidden-key.toml", forbid_canary=("private_key",))


@check("profile.invalid_unknown_dest_key", "§2 unknown destination key -> SCHEMA_INVALID with key path")
def _(t):
    invalid_case(t, "invalid-unknown-dest-key.toml", expect_key_fragment=["destinations", "identity_file"],
                 forbid_canary=("destinations", 0, "identity_file"))


@check("profile.invalid_malformed", "§2 malformed TOML -> SCHEMA_INVALID")
def _(t):
    invalid_case(t, "invalid-malformed.toml")


@check("profile.invalid_schema_version", "§2 schema_version != 1 -> SCHEMA_INVALID + warning naming the version, not the value of other keys")
def _(t):
    invalid_case(t, "invalid-schema-version.toml", expect_warning_fragment="2",
                 forbid_values={"the value of key name ('homelab')": "homelab"}, offending=False)


@check("profile.invalid_duplicate_alias", "§2 duplicate alias -> SCHEMA_INVALID")
def _(t):
    invalid_case(t, "invalid-duplicate-alias.toml")


@check("profile.invalid_port", "§2/K18 port outside 1..65535 -> SCHEMA_INVALID; the value (70000) is not echoed in the result, on stdout or on stderr")
def _(t):
    invalid_case(t, "invalid-port.toml", forbid_values={"the offending port value 70000": "70000"})


def write_profile(dirpath, name, text_or_bytes):
    p = Path(dirpath) / name
    p.write_bytes(text_or_bytes if isinstance(text_or_bytes, bytes) else text_or_bytes.encode("utf-8"))
    return p


MIN_TOP = 'schema_version = 1\nname = "x"\nrevision = 1\n'
MIN_DEST = '\n[[destinations]]\nid = "a"\nalias = "a"\nhost = "h.example.internal"\naccount = "u"\n'
MIN_DEST_EXPECT = {"id": "a", "alias": "a", "host": "h.example.internal", "port": 22, "account": "u", "labels": []}


def dest_with(**over):
    keys = {"id": '"a"', "alias": '"a"', "host": '"h.example.internal"', "account": '"u"'}
    keys.update(over)
    return MIN_TOP + "\n[[destinations]]\n" + "".join("%s = %s\n" % (k, v) for k, v in keys.items() if v is not None)


@check("profile.generated_invalid_matrix", "§2 required keys, ranges, types, duplicates, unknown keys")
def _(t):
    d = t.ctx.new_dir("profiles")
    cases = {
        "missing_name": 'schema_version = 1\nrevision = 1\n' + MIN_DEST,
        "missing_revision": 'schema_version = 1\nname = "x"\n' + MIN_DEST,
        "missing_schema_version": 'name = "x"\nrevision = 1\n' + MIN_DEST,
        "revision_zero": 'schema_version = 1\nname = "x"\nrevision = 0\n' + MIN_DEST,
        "revision_float": 'schema_version = 1\nname = "x"\nrevision = 1.5\n' + MIN_DEST,
        "revision_string": 'schema_version = 1\nname = "x"\nrevision = "1"\n' + MIN_DEST,
        "revision_bool": 'schema_version = 1\nname = "x"\nrevision = true\n' + MIN_DEST,
        "schema_version_bool": 'schema_version = true\nname = "x"\nrevision = 1\n' + MIN_DEST,
        "port_bool": dest_with(port="true"),
        "schema_version_string": 'schema_version = "1"\nname = "x"\nrevision = 1\n' + MIN_DEST,
        "schema_version_float": 'schema_version = 1.0\nname = "x"\nrevision = 1\n' + MIN_DEST,
        "unknown_top_key": MIN_TOP + 'colour = "red"\n' + MIN_DEST,
        "dest_missing_id": dest_with(id=None),
        "dest_missing_alias": dest_with(alias=None),
        "dest_missing_host": dest_with(host=None),
        "dest_missing_account": dest_with(account=None),
        "port_zero": dest_with(port="0"),
        "port_negative": dest_with(port="-1"),
        "port_string": dest_with(port='"22"'),
        "port_65536": dest_with(port="65536"),
        "duplicate_id": MIN_TOP + MIN_DEST + MIN_DEST.replace('alias = "a"', 'alias = "b"'),
        "duplicate_alias": MIN_TOP + MIN_DEST + MIN_DEST.replace('id = "a"', 'id = "b"'),
        "unknown_key_outside_meta_table": MIN_TOP + '[other]\nx = 1\n' + MIN_DEST,
        "empty_file_garbage_bytes": b"\xff\xfe\x00\x01 not toml",
    }
    for name, text in cases.items():
        p = write_profile(d, name + ".toml", text)
        c = t.proto("profile", "show", "--file", str(p), "--json", label=name)
        t.result(c, 2, "SCHEMA_INVALID", "failed", label=name)


# (case, TOML text, {description: marker}, values allowed in warnings).  Every offending value carries a
# distinctive marker so an echo is detectable without matching ordinary words ("dup" in "duplicate").
def _echo_cases():
    two = lambda k, v: (MIN_TOP + MIN_DEST.replace('%s = "a"' % k, '%s = "%s"' % (k, v))
                        + MIN_DEST.replace('%s = "a"' % k, '%s = "%s"' % (k, v))
                        .replace('id = "a"' if k == "alias" else 'alias = "a"', 'id = "b"' if k == "alias" else 'alias = "b"'))
    return [
        ("port_70123", dest_with(port="70123"), {"the port value 70123": "70123"}),
        ("port_negative", dest_with(port="-31337"), {"the port value -31337": "31337"}),
        ("port_string", dest_with(port='"zqv-port-str"'), {"the port string value": "zqv-port-str"}),
        ("revision_negative", 'schema_version = 1\nname = "x"\nrevision = -48213\n' + MIN_DEST,
         {"the revision value -48213": "48213"}),
        ("revision_string", 'schema_version = 1\nname = "x"\nrevision = "zqv-rev-str"\n' + MIN_DEST,
         {"the revision string value": "zqv-rev-str"}),
        ("revision_float", 'schema_version = 1\nname = "x"\nrevision = 271828.5\n' + MIN_DEST,
         {"the revision value 271828.5": "271828"}),
        ("duplicate_alias", two("alias", "zqv-dup-alias"), {"the duplicated alias value": "zqv-dup-alias"}),
        ("duplicate_id", two("id", "zqv-dup-id"), {"the duplicated id value": "zqv-dup-id"}),
        ("unknown_top_key", MIN_TOP + 'colour = "zqv-unknown-top"\n' + MIN_DEST,
         {"the unknown key's value": "zqv-unknown-top"}),
        ("unknown_dest_key", dest_with(nickname='"zqv-unknown-dest"'), {"the unknown key's value": "zqv-unknown-dest"}),
        ("schema_version_other_keys",
         'schema_version = 7\nname = "zqv-name"\nrevision = 1\n' + MIN_DEST.replace('"h.example.internal"',
                                                                                    '"zqv-host.example.internal"'),
         {"the value of key name": "zqv-name", "the value of a destination host": "zqv-host"}),
    ]


@check("profile.error_value_not_echoed", "§1/§2/K18 error results never include the offending value: range/type errors, duplicates, unknown keys (the result and, K18, stdout and stderr), the schema_version warning (no other key's value in the result), and malformed TOML whose offending line holds a secret (never on stdout or stderr)")
def _(t):
    d = t.ctx.new_dir("profiles-echo")
    for name, text, values in _echo_cases():
        p = write_profile(d, name + ".toml", text)
        t.precondition("[%s] harness precondition: tomllib parses the file (a value error, not a syntax error)" % name,
                _toml_ok(p), "parses", "does not parse")
        c = t.proto("profile", "show", "--file", str(p), "--json", label=name)
        doc = t.result(c, 2, "SCHEMA_INVALID", "failed", label=name)
        assert_values_not_in_result(t, name, doc, c, values, offending=name != "schema_version_other_keys")
        if name == "schema_version_other_keys" and isinstance(doc, dict):
            w = doc.get("warnings") or []
            t.check("[%s] a warning names the unsupported version 7" % name,
                    any(isinstance(x, str) and "7" in x for x in w), "7", w)
    # Section 1: a secret on the line a TOML parser reports must not be reproduced (source snippets).
    canary = t.ctx.src_canary
    malformed = [
        ("malformed_secret_line", MIN_TOP + 'private_key = "%s" trailing junk\n' % canary + MIN_DEST),
        ("malformed_secret_unterminated", MIN_TOP + 'token = "%s\n' % canary + MIN_DEST),
        ("malformed_secret_bad_escape", MIN_TOP + 'token = "%s\\q"\n' % canary + MIN_DEST),
    ]
    rest = canary[len("HEIMDALL_CANARY_"):].encode()
    for name, text in malformed:
        p = write_profile(d, name + ".toml", text)
        t.precondition("[%s] harness precondition: tomllib rejects the file" % name, not _toml_ok(p), "syntax error",
                "parses")
        c = t.proto("profile", "show", "--file", str(p), "--json", label=name)
        t.result(c, 2, "SCHEMA_INVALID", "failed", label=name)
        blob = c.stdout + c.stderr
        t.check("[%s] stdout/stderr never contain the secret on the malformed line (per-run canary, section 1)" % name,
                canary.encode() not in blob, "absent", "PRESENT" if canary.encode() in blob else "absent")
        t.check("[%s] stdout/stderr never contain that secret without its HEIMDALL_CANARY_ prefix" % name,
                rest not in blob, "absent", "PRESENT" if rest in blob else "absent")


@check("profile.generated_valid_variants", "§2 port bounds, defaults, CRLF, [meta] tolerated and not echoed")
def _(t):
    d = t.ctx.new_dir("profiles")
    meta_text = "tolerated-meta-text-xyz"
    cases = {
        "port_1": (dest_with(port="1"), dict(MIN_DEST_EXPECT, port=1)),
        "port_65535": (dest_with(port="65535"), dict(MIN_DEST_EXPECT, port=65535)),
        "defaults": (dest_with(), MIN_DEST_EXPECT),
        "labels_given": (dest_with(labels='["x", "y"]'), dict(MIN_DEST_EXPECT, labels=["x", "y"])),
        "crlf": (dest_with().replace("\n", "\r\n"), MIN_DEST_EXPECT),
        "order_unsorted": (
            MIN_TOP + "".join('\n[[destinations]]\nid = "%s"\nalias = "%s"\nhost = "%s.example.internal"\naccount = "u"\n'
                              % (n, n, n) for n in ("zulu", "alpha", "mike", "bravo")),
            None),
        "meta_nested_and_odd": (
            MIN_TOP + '\n[meta]\nnote = "%s"\nnested = { a = 1, b = ["%s"] }\n'
            '[meta.deeper]\nanything = true\nunknown_key_inside_meta = 1\n' % (meta_text, t.ctx.meta_canary)
            + MIN_DEST, MIN_DEST_EXPECT),
    }
    for name, (text, dest) in cases.items():
        p = write_profile(d, name + ".toml", text)
        c = t.proto("profile", "show", "--file", str(p), "--json", label=name)
        doc = t.result(c, 0, "PROFILE_OK", "succeeded", label=name)
        dests = [dest] if dest is not None else [
            {"id": n, "alias": n, "host": n + ".example.internal", "port": 22, "account": "u", "labels": []}
            for n in ("zulu", "alpha", "mike", "bravo")]
        if doc:
            t.eq("[%s] data" % name, doc.get("data"), {"profile": {"name": "x", "revision": 1, "destinations": dests}})
        if name.startswith("meta"):
            t.check("[meta] content not echoed", meta_text.encode() not in c.stdout + c.stderr
                    and b"meta" not in c.stdout.lower().replace(b'"name"', b""), "absent", "PRESENT?")


# K2 cases: (name, key under test, TOML value text, key_path fragments).  Each value carries a unique
# marker so an echo of the value is detectable; control characters are written as TOML escapes
# (\u001b, \u007f, \u009b, \n) or, for TAB, literally - both are legal TOML basic strings.
K2_CASES = [
    ("alias_esc", "alias", '"k2val-alias\\u001b[31m-x"', ["destinations", "alias"]),
    ("host_tab", "host", '"k2val-host\t-x.example.internal"', ["destinations", "host"]),
    ("account_del", "account", '"k2val-account\\u007f-x"', ["destinations", "account"]),
    ("label_c1", "labels", '["ok", "k2val-label\\u009b-x"]', ["destinations", "labels"]),
    ("alias_c1_nel", "alias", '"k2val-alias2\\u0085-x"', ["destinations", "alias"]),
    ("id_newline", "id", '"k2val-id\\n-x"', ["destinations", "id"]),
    ("host_bel", "host", '"k2val-host2\\u0007-x"', ["destinations", "host"]),
]


@check("profile.control_chars_rejected", "§2/K2 C0/DEL/C1 control in alias/host/account/label/id/name -> SCHEMA_INVALID, key_path names the key, value never echoed")
def _(t):
    d = t.ctx.new_dir("profiles-k2")
    cases = [(n, dest_with(**{k: v}), frag) for n, k, v, frag in K2_CASES]
    cases.append(("name_esc", 'schema_version = 1\nname = "k2val-name\\u001b-x"\nrevision = 1\n' + MIN_DEST, ["name"]))
    for name, text, frag in cases:
        p = write_profile(d, name + ".toml", text)
        t.precondition("[%s] harness precondition: tomllib parses the file" % name, _toml_ok(p), "parses", "does not parse")
        c = t.proto("profile", "show", "--file", str(p), "--json", label=name)
        doc = t.result(c, 2, "SCHEMA_INVALID", "failed", label=name)
        if doc and isinstance(doc.get("data"), dict):
            kp = (doc["data"].get("error") or {}).get("key_path")
            t.check("[%s] key_path names the key" % name, isinstance(kp, str) and all(f in kp for f in frag),
                    frag, kp)
        blob = c.stdout + c.stderr
        t.check("[%s] stdout/stderr never contain the value (marker k2val-)" % name, b"k2val-" not in blob,
                "absent", "PRESENT" if b"k2val-" in blob else "absent")


@check("profile.control_chars_in_meta_ok", "§2/K2 the same control characters inside [meta] are tolerated (PROFILE_OK) and not echoed")
def _(t):
    d = t.ctx.new_dir("profiles-k2meta")
    text = (MIN_TOP + '\n[meta]\nnote = "k2meta-a\\u001b[31m b\tc\\u007f d\\u009b e\\u0085 f\\n g"\n'
            'list = ["k2meta-\\u0007"]\n[meta.sub]\n"k\\u001bey" = "k2meta-x"\n' + MIN_DEST)
    p = write_profile(d, "meta_controls.toml", text)
    t.precondition("harness precondition: tomllib parses the file", _toml_ok(p), "parses", "does not parse")
    c = t.proto("profile", "show", "--file", str(p), "--json")
    doc = t.result(c, 0, "PROFILE_OK", "succeeded")
    if doc:
        t.eq("data", doc.get("data"), {"profile": {"name": "x", "revision": 1, "destinations": [MIN_DEST_EXPECT]}})
    t.check("[meta] content not echoed", b"k2meta" not in c.stdout + c.stderr, "absent",
            "PRESENT" if b"k2meta" in c.stdout + c.stderr else "absent")


def _toml_ok(p):
    try:
        tomllib.loads(Path(p).read_text(encoding="utf-8"))
        return True
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return False


@check("profile.meta_not_echoed_homelab", "§2 [meta] tolerated and not echoed (fixture)")
def _(t):
    c = t.proto("profile", "show", "--file", str(FIX / "homelab.toml"), "--json")
    for needle in (b"free-form metadata", b"owner_hint", b"personal", b"meta"):
        t.check("stdout/stderr do not contain %r" % needle, needle not in c.stdout + c.stderr, "absent",
                "PRESENT" if needle in c.stdout + c.stderr else "absent")


def sized_profile(dirpath, name, total, valid=True):
    base = MIN_TOP + MIN_DEST
    if valid:
        pad = total - len(base.encode())
        assert pad >= 2
        text = (base + "#" + "p" * (pad - 2) + "\n").encode()
    else:
        text = random.Random(7).randbytes(total)
    assert len(text) == total
    return write_profile(dirpath, name, text)


@check("profile.oversize_garbage", "§2 > 1 MiB -> INPUT_TOO_LARGE without parsing")
def _(t):
    d = t.ctx.new_dir("sized")
    p = sized_profile(d, "oversize.toml", 2 * 1024 * 1024 + 123, valid=False)
    t.result(t.proto("profile", "show", "--file", str(p), "--json"), 2, "INPUT_TOO_LARGE", "failed")


@check("profile.size_boundary_plus_one", "§2 exactly 1 MiB + 1 byte -> INPUT_TOO_LARGE")
def _(t):
    d = t.ctx.new_dir("sized")
    p = sized_profile(d, "plus1.toml", 1048577)
    t.result(t.proto("profile", "show", "--file", str(p), "--json"), 2, "INPUT_TOO_LARGE", "failed")


@check("profile.size_boundary_exact", "§2 exactly 1,048,576 bytes is accepted")
def _(t):
    d = t.ctx.new_dir("sized")
    p = sized_profile(d, "exact.toml", 1048576)
    c = t.proto("profile", "show", "--file", str(p), "--json")
    t.result(c, 0, "PROFILE_OK", "succeeded")


@check("profile.missing_file", "§2 missing file -> USAGE_ERROR exit 2")
def _(t):
    t.result(t.proto("profile", "show", "--file", str(t.ctx.sandbox / "does not exist ü.toml"), "--json"),
             2, "USAGE_ERROR", "failed")


@check("profile.unreadable_file", "§2 unreadable file -> USAGE_ERROR exit 2")
def _(t):
    d = t.ctx.new_dir("unreadable")
    p = write_profile(d, "locked.toml", MIN_TOP + MIN_DEST)
    os.chmod(p, 0)
    try:
        if os.access(p, os.R_OK):
            t.check("file is unreadable to the harness user (not root)", False, "unreadable", "readable")
            return
        t.result(t.proto("profile", "show", "--file", str(p), "--json"), 2, "USAGE_ERROR", "failed")
    finally:
        os.chmod(p, 0o600)


# ===== version (contract section 6) ========================================
@check("version.valid", "§6 version --json: VERSION_OK, candidate matches")
def _(t):
    c = t.proto("version", "--json")
    doc = t.result(c, 0, "VERSION_OK", "succeeded")
    if doc and isinstance(doc.get("data"), dict):
        d = doc["data"]
        t.eq("candidate equals --candidate", d.get("candidate"), t.ctx.candidate)
        t.eq("name", d.get("name"), "heimdall-proto")
        t.eq("version", d.get("version"), "0.0.0-g02")
        for k in ("runtime", "tui_framework", "tui_framework_version"):
            t.check("%s is a non-empty string" % k, isinstance(d.get(k), str) and d.get(k).strip() != "",
                    "non-empty", d.get(k))
        t.note("version_data", d)


# ===== agent (contract section 3) ==========================================
def agent_run(t, mode, *, keys=None, extra=(), pre_factory=None, sock_path=None, timeout=20.0, label=None,
              wait_peer_close=True, name=None):
    """Start a fake agent, run `agent list` against it, stop the agent.

    Returns (cap, events, fa)."""
    keys = t.ctx.keys() if keys is None else keys
    d = t.ctx.new_dir("agent-" + mode)
    fa = H.FakeAgent(t.ctx.sandbox, d, name or mode, mode, [k["pub"] for k in keys],
                     sock_path=sock_path(d) if sock_path else None)
    t.agents.append(fa)
    pre = pre_factory(fa) if pre_factory else None
    cap = t.proto("agent", "list", "--socket", fa.sock, *extra, "--json", label=label or "agent-" + mode,
                  timeout=timeout, pre=pre)
    if wait_peer_close:
        fa.wait_disconnect(2.0)
    fa.stop()
    ev = fa.events()
    t.save("%s.contact.jsonl" % (name or mode), Path(fa.log_path).read_bytes())
    return cap, ev, fa


def assert_passive(t, ev, closed_by_peer=True):
    ok, det = H.passive_report(ev)
    t.check("contact log: exactly one connection and exactly one type-11 request, nothing else", ok,
            "1 connection, [11], 5 bytes", det)
    if closed_by_peer:
        t.check("contact log: the client closed the connection (peer EOF/reset)",
                bool(det["disconnect_reasons"]) and det["disconnect_reasons"][0] in ("peer_eof", "peer_reset"),
                "peer_eof|peer_reset", det["disconnect_reasons"])
    return det


def expected_ids(keys, comment_override=None):
    return [{"key_type": k["key_type"], "fingerprint": k["sshkeygen_fingerprint"],
             "comment": k["comment"] if comment_override is None else comment_override} for k in keys]


@check("agent.normal_identities", "§3 identities in order: key_type, fingerprint, comment")
def _(t):
    keys = t.ctx.keys()
    cap, ev, _ = agent_run(t, "normal")
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    if doc:
        t.eq("data.identities equals ssh-keygen-derived expectation", (doc.get("data") or {}).get("identities"),
             expected_ids(keys))
        t.check("raw key blob is not emitted", all("blob" not in json.dumps(i) for i in (doc.get("data") or {}).get("identities", [])))
    assert_passive(t, ev)


@check("agent.fingerprint_ssh_keygen", "§3 fingerprint == SHA256 of ssh-keygen -lf (disposable keys, run time)")
def _(t):
    keys = t.ctx.keys()
    cap, ev, _ = agent_run(t, "normal")
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    ids = ((doc or {}).get("data") or {}).get("identities", [])
    t.eq("count", len(ids), len(keys))
    for k, i in zip(keys, ids):
        t.eq("fingerprint of %s key" % k["kind"], i.get("fingerprint"), k["sshkeygen_fingerprint"])
        t.eq("key_type of %s key" % k["kind"], i.get("key_type"), k["key_type"])


@check("agent.empty", "§3 zero identities -> AGENT_OK with []")
def _(t):
    cap, ev, _ = agent_run(t, "empty")
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    if doc:
        t.eq("identities", (doc.get("data") or {}).get("identities"), [])
    assert_passive(t, ev)


@check("agent.fragmented_reply", "§3 reply delivered in 3-byte pieces is reassembled")
def _(t):
    keys = t.ctx.keys()
    cap, ev, _ = agent_run(t, "fragmented")
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    if doc:
        t.eq("identities", (doc.get("data") or {}).get("identities"), expected_ids(keys))
    assert_passive(t, ev)


@check("agent.passive_contact_log", "§3 never sends anything but one type-11; R-SS-02 contact recording")
def _(t):
    cap, ev, fa = agent_run(t, "normal")
    t.result(cap, 0, "AGENT_OK", "succeeded")
    det = assert_passive(t, ev)
    t.note("contact", det)
    t.check("no sign-related traffic (types 13/17/18/19/20/22/23...)", all(m.get("type") == 11 for m in ev if m["event"] == "message"))


def malformed_check(mode, note):
    @check("agent.malformed_" + mode, "§3 bounds: " + note)
    def _(t):
        cap, ev, _ = agent_run(t, mode, timeout=15.0)
        t.result(cap, 5, "AGENT_PROTOCOL_ERROR", "failed")
        t.check("[%s] fails closed within 2 s" % mode, cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)
        assert_passive(t, ev, closed_by_peer=(mode != "truncated"))
    return _


for _m, _n in (("oversize", "frame length 0x7fffffff > 262144"), ("huge_nkeys", "nkeys 100000 > 1024"),
               ("truncated", "truncated frame after >= 1 reply byte (K3: stays PROTOCOL_ERROR)"), ("trailing_bytes", "trailing bytes after last key"),
               ("wrong_type", "unexpected message type"), ("string_overrun", "key-blob string length exceeds frame"),
               ("comment_overrun", "comment string length exceeds frame"),
               ("zero_length_frame", "zero-length frame (no message type byte)"),
               ("answer_type_only", "type-12 frame of length 1 (no nkeys)"),
               ("answer_short", "type-12 frame of length 3 (nkeys cut short)"),
               ("nkeys_short", "nkeys 3 (within the bound) but only one key present")):
    malformed_check(_m, _n)


@check("agent.failure_refused", "§3 SSH_AGENT_FAILURE -> AGENT_REFUSED exit 5")
def _(t):
    cap, ev, _ = agent_run(t, "failure")
    t.result(cap, 5, "AGENT_REFUSED", "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)
    assert_passive(t, ev)


@check("agent.nkeys_boundary", "§3 nkeys 1024 accepted, 1025 rejected")
def _(t):
    keys = t.ctx.keys()[:1]
    cap, ev, _ = agent_run(t, "nkeys_max", keys=keys)
    doc = t.result(cap, 0, "AGENT_OK", "succeeded", label="nkeys=1024")
    if doc:
        ids = (doc.get("data") or {}).get("identities", [])
        t.eq("1024 identities returned", len(ids), 1024)
    cap2, ev2, _ = agent_run(t, "nkeys_over", keys=keys)
    t.result(cap2, 5, "AGENT_PROTOCOL_ERROR", "failed", label="nkeys=1025")


@check("agent.frame_boundary", "§3 frame length 262144 accepted, 262145 rejected")
def _(t):
    keys = t.ctx.keys()[:1]
    cap, ev, _ = agent_run(t, "frame_max", keys=keys, timeout=30)
    doc = t.result(cap, 0, "AGENT_OK", "succeeded", label="frame=262144")
    if doc:
        ids = (doc.get("data") or {}).get("identities", [])
        t.eq("one identity", len(ids), 1)
        if ids:
            t.eq("fingerprint", ids[0].get("fingerprint"), keys[0]["sshkeygen_fingerprint"])
            t.check("comment is the full 'x' run", set(ids[0].get("comment", "")) == {"x"}
                    and len(ids[0]["comment"]) > 262000, ">262000 x", len(ids[0].get("comment", "")))
    cap2, ev2, _ = agent_run(t, "frame_over", keys=keys, timeout=30)
    t.result(cap2, 5, "AGENT_PROTOCOL_ERROR", "failed", label="frame=262145")


@check("agent.missing_socket", "§3 connect failure -> AGENT_UNAVAILABLE exit 5")
def _(t):
    p = t.ctx.sandbox / "no such dir ü" / "none.sock"
    cap = t.proto("agent", "list", "--socket", str(p), "--json")
    t.result(cap, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)


@check("agent.stale_socket", "§3 connect refused (stale socket file) -> AGENT_UNAVAILABLE")
def _(t):
    d = t.ctx.new_dir("stale")
    p = d / "stale.sock"
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(p))
    s.close()  # leaves the socket inode with no listener
    t.check("stale socket file exists", os.path.exists(p))
    cap = t.proto("agent", "list", "--socket", str(p), "--json")
    t.result(cap, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)


@check("agent.slow_timeout", "§3 no reply within --timeout-ms -> AGENT_UNAVAILABLE in bounded time")
def _(t):
    cap, ev, _ = agent_run(t, "slow", extra=("--timeout-ms", "300"), timeout=15, label="timeout-300")
    t.result(cap, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("gives up no earlier than ~timeout and within 2 s", 0.25 <= cap.elapsed < 2.0, "0.25..2.0 s",
            "%.3f s" % cap.elapsed)
    assert_passive(t, ev)
    cap2, ev2, _ = agent_run(t, "slow", extra=("--timeout-ms", "1200"), timeout=15, label="timeout-1200")
    t.result(cap2, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("--timeout-ms is honoured (1200 ms -> 1.1..3.0 s)", 1.1 <= cap2.elapsed < 3.0, "1.1..3.0 s",
            "%.3f s" % cap2.elapsed)
    t.note("timeouts", {"300": round(cap.elapsed, 3), "1200": round(cap2.elapsed, 3)})


@check("agent.timeout_whole_response", "§3 --timeout-ms bounds the whole response: a reply dripped one byte per 100 ms (bytes keep arriving, never complete within the timeout) -> AGENT_UNAVAILABLE at ~timeout")
def _(t):
    fa_mod = _fake_agent_module()
    keys = t.ctx.keys()[:1]
    total = 4 + len(fa_mod.Agent.identities_payload([fa_mod.load_pubkey(keys[0]["pub"])]))
    t.precondition("harness precondition: the dripped reply needs far longer than the 1000 ms timeout",
            total * fa_mod.DRIP_INTERVAL >= 3.0, ">= 3 s", "%.1f s (%d bytes)" % (total * fa_mod.DRIP_INTERVAL, total))
    cap, ev, _ = agent_run(t, "drip", keys=keys, extra=("--timeout-ms", "1000"), timeout=30, label="drip-timeout-1000")
    t.result(cap, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("gives up at ~1000 ms although bytes keep arriving (0.9..2.0 s; an idle/per-read timeout never fires)",
            0.9 <= cap.elapsed < 2.0, "0.9..2.0 s", "%.3f s" % cap.elapsed)
    msgs = [e for e in ev if e["event"] == "message"]
    t.check("the agent had sent part of the reply, not all of it, when the client gave up (the client stopped reading mid-reply)",
            bool(msgs) and 0 < (msgs[0].get("sent_bytes") or 0) < total, "0 < sent < %d" % total,
            [m.get("sent_bytes") for m in msgs])
    assert_passive(t, ev)
    t.note("drip", {"elapsed_s": round(cap.elapsed, 3), "reply_bytes": total,
                    "sent_bytes": [m.get("sent_bytes") for m in msgs]})


@check("agent.timeout_default_5000", "§3 without --timeout-ms the timeout is 5000 ms: a silent agent -> AGENT_UNAVAILABLE after 4.75..7.0 s", budget=60)
def _(t):
    cap, ev, _ = agent_run(t, "slow", timeout=15, label="default-timeout")
    t.result(cap, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("gives up after the default 5000 ms (4.75..7.0 s)", 4.75 <= cap.elapsed < 7.0, "4.75..7.0 s",
            "%.3f s" % cap.elapsed)
    assert_passive(t, ev)
    t.note("default_timeout_s", round(cap.elapsed, 3))


@check("agent.slow_sigint_cancel", "§3 SIGINT while waiting -> CANCELLED exit 130 within 500 ms (best of 3), connection closed")
def _(t):
    lats = []
    for attempt in range(3):
        sig = {}

        def pre_factory(fa, sig=sig):
            def pre(proc):
                ev = fa.wait_event(lambda e: e["event"] == "message", 10)
                if ev is None:
                    raise RuntimeError("agent never saw the request")
                time.sleep(0.05)
                sig["t"] = time.time()
                os.kill(proc.pid, 2)
            return pre

        label = "slow-sigint-%d" % (attempt + 1)
        cap, ev, _ = agent_run(t, "slow", extra=("--timeout-ms", "30000"), pre_factory=pre_factory, timeout=10,
                               label=label, name="slow%d" % attempt)
        t.result(cap, 130, "CANCELLED", "cancelled")
        lat = (cap.exit_wall - sig["t"]) if "t" in sig else None
        if lat is not None:
            lats.append(lat)
        assert_passive(t, ev)  # includes: the fake agent observed the disconnect (peer EOF/reset)
    ms = [round(x * 1000, 1) for x in lats]
    t.note("sigint_latency_ms", ms)
    t.ctx.observations["agent_sigint_exit_latency_ms"] = ms
    t.check("best of 3 SIGINT-to-exit latency is under 500 ms (wall clock; load-sensitive)",
            bool(lats) and min(lats) < 0.5, "< 500 ms", ms)


@check("agent.invalid_utf8_comment", "§3 invalid UTF-8 comment -> U+FFFD, output stays valid JSON")
def _(t):
    keys = t.ctx.keys()[:1]
    cap, ev, _ = agent_run(t, "invalid_utf8_comment", keys=keys)
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    if doc:
        t.eq("identities", (doc.get("data") or {}).get("identities"), [
            {"key_type": keys[0]["key_type"], "fingerprint": keys[0]["sshkeygen_fingerprint"],
             "comment": "bad-\ufffd-comment"}])
    t.check("stdout is valid UTF-8", cap.stdout.decode("utf-8", errors="replace").encode() == cap.stdout)
    assert_passive(t, ev)


def k1_sanitize(raw):
    """Independent statement of contract K1: invalid UTF-8 and every C0, DEL and C1 code point -> U+FFFD."""
    return "".join("\ufffd" if (ord(c) <= 0x1f or 0x7f <= ord(c) <= 0x9f) else c
                   for c in raw.decode("utf-8", "replace"))


def control_code_points(text):
    return ["U+%04X" % ord(c) for c in text if ord(c) <= 0x1f or 0x7f <= ord(c) <= 0x9f]


@check("agent.control_chars_sanitized", "§3/K1 ESC, TAB, DEL, C1 and invalid UTF-8 in key_type and comment -> U+FFFD; no control code point in the decoded JSON")
def _(t):
    fa_mod = _fake_agent_module()
    blob = fa_mod.k1_blob()
    cap, ev, _ = agent_run(t, "control_chars", keys=[])
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    exp = {"key_type": k1_sanitize(fa_mod.K1_KEY_TYPE), "fingerprint": H.fingerprint_of_blob(blob),
           "comment": k1_sanitize(fa_mod.K1_COMMENT)}
    t.precondition("harness precondition: expectation contains U+FFFD and no control code point",
            "\ufffd" in exp["key_type"] and "\ufffd" in exp["comment"]
            and not control_code_points(exp["key_type"] + exp["comment"]), True, exp)
    if doc:
        ids = (doc.get("data") or {}).get("identities")
        t.eq("identities (each control code point and the invalid byte became one U+FFFD)", ids, [exp])
        bad = {}
        for sv in walk_strings(doc):
            cps = control_code_points(sv)
            if cps:
                bad[sv[:40]] = cps
        t.check("decoded JSON contains no C0/DEL/C1 code point in any string (JSON escaping is not enough)",
                not bad, "none", bad)
    t.check("stdout bytes contain no raw ESC/DEL or UTF-8 encoded C1", not re.search(rb"[\x1b\x7f]|\xc2[\x80-\x9f]",
                                                                              cap.stdout), "none",
            H.printable(cap.stdout[:200]))
    assert_passive(t, ev)


@check("agent.eof_before_reply", "§3/K3 peer closes after reading the request without sending a byte -> AGENT_UNAVAILABLE")
def _(t):
    cap, ev, _ = agent_run(t, "close_silent", keys=[])
    t.result(cap, 5, "AGENT_UNAVAILABLE", "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)
    assert_passive(t, ev, closed_by_peer=False)


@check("agent.eof_after_partial_header", "§3/K3 EOF after 1 byte of the frame header -> AGENT_PROTOCOL_ERROR")
def _(t):
    cap, ev, _ = agent_run(t, "partial_header", keys=[])
    t.result(cap, 5, "AGENT_PROTOCOL_ERROR", "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)
    assert_passive(t, ev, closed_by_peer=False)


@check("agent.failure_with_payload", "§3/K4 SSH_AGENT_FAILURE frame with a payload (length 5) -> AGENT_PROTOCOL_ERROR")
def _(t):
    cap, ev, _ = agent_run(t, "failure_payload", keys=[])
    t.result(cap, 5, "AGENT_PROTOCOL_ERROR", "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)
    assert_passive(t, ev)


def k3a_delivery(t, mode):
    """How this OS delivers the fake agent's reset (SO_LINGER 0, request unread) to a plain reader."""
    d = t.ctx.new_dir("k3a-probe")
    fa = H.FakeAgent(t.ctx.sandbox, d, "probe", mode)
    t.agents.append(fa)
    try:
        data, end = _raw_exchange(fa.sock, with_end=True)
    finally:
        fa.stop()
    t.ctx.observations.setdefault("k3a_reset_delivery", {})[mode] = end
    return data, end


def reset_check(t, mode, code, nbytes):
    data, end = k3a_delivery(t, mode)
    t.precondition("harness precondition: the agent sent exactly %d reply byte(s) before the reset" % nbytes,
            len(data) == nbytes, nbytes, len(data))
    if platform.system() == "Linux":
        # K13: K3a is judged on Linux, where the kernel reports the reset; without it the check proves nothing
        t.precondition("harness precondition (Linux): the agent's reset reaches the reader as ECONNRESET, so the K3a "
                "reset path is exercised", end == "ECONNRESET", "ECONNRESET", end)
    else:
        t.check("kernel delivery of the reset to the reader on %s (non-gating observation; ECONNRESET exercises "
                "the K3a reset path, EOF means this OS cannot produce an AF_UNIX reset; K3a is judged on Linux, K13)"
                % platform.system(), True, "ECONNRESET", end, gating=False)
    t.note("kernel_delivery", end)
    cap, ev, _ = agent_run(t, mode, keys=[])
    t.result(cap, 5, code, "failed")
    t.check("returns promptly", cap.elapsed < 2.0, "< 2.0 s", "%.3f s" % cap.elapsed)
    assert_passive(t, ev, closed_by_peer=False)


@check("agent.reset_before_reply", "§3/K3a agent resets the connection (SO_LINGER 0, request unread) before any reply byte -> AGENT_UNAVAILABLE")
def _(t):
    reset_check(t, "reset_before_reply", "AGENT_UNAVAILABLE", 0)


@check("agent.reset_after_partial_header", "§3/K3a agent sends 1 header byte, then resets the connection -> AGENT_PROTOCOL_ERROR")
def _(t):
    reset_check(t, "reset_after_byte", "AGENT_PROTOCOL_ERROR", 1)


@check("agent.unicode_spaced_socket_path", "§1/§3 socket path with spaces and non-ASCII")
def _(t):
    keys = t.ctx.keys()

    def sp(d):
        return d / "sock dir ü 東" / "agént sock.sock"

    cap, ev, fa = agent_run(t, "normal", sock_path=sp)
    t.check("socket path has spaces and Unicode and fits in sun_path", " " in fa.sock and "ü" in fa.sock
            and len(os.fsencode(fa.sock)) < 104, "yes", fa.sock)
    doc = t.result(cap, 0, "AGENT_OK", "succeeded")
    if doc:
        t.eq("identities", (doc.get("data") or {}).get("identities"), expected_ids(keys))
    assert_passive(t, ev)


# ===== run (contract section 4) ============================================
def meta_path(t):
    d = t.ctx.new_dir("meta ü dir")
    return d / "meta ü.json"


def run_args(meta, *argv):
    a = ["run"]
    if meta is not None:
        a += ["--meta-file", str(meta)]
    return a + ["--"] + list(argv)


@check("run.stdio_passthrough", "§4 1 MiB random binary stdin->stdout, stderr passthrough, byte-exact (sha256)")
def _(t):
    data = random.Random(20261002).randbytes(1024 * 1024)
    exp_err = b"".join(data[i:i + 65536][::-1] for i in range(0, len(data), 65536))
    meta = meta_path(t)
    c = t.proto(*run_args(meta, PY, "-c", CHILD_COPY), stdin_data=data, timeout=60, cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 0)
    t.eq("stdout bytes", len(c.stdout), len(data))
    t.eq("stdout sha256 identical", H.sha256_hex(c.stdout), H.sha256_hex(data))
    t.eq("stderr sha256 identical (no extra bytes from heimdall-proto)", H.sha256_hex(c.stderr),
         H.sha256_hex(exp_err))
    t.check("input contained NUL and invalid UTF-8 (so text mangling would show)",
            b"\x00" in data and not _is_utf8(data))
    m = t.read_meta(meta)
    if m:
        t.eq("meta code", m.get("code"), "CHILD_EXITED")
        t.eq("meta data", m.get("data"), {"launched": True, "exit_code": 0, "signal": None})


def _is_utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


@check("run.exit_codes", "§4 child exit codes 0/1/42/255 propagate; heimdall-proto is silent")
def _(t):
    for n in (0, 1, 42, 255):
        meta = meta_path(t)
        c = t.proto(*run_args(meta, PY, "-c", CHILD_EXIT, str(n)), label="exit-%d" % n, cwd=t.ctx.run_cwd)
        t.eq("[exit-%d] exit code" % n, c.rc, n)
        t.eq("[exit-%d] stdout empty" % n, c.stdout, b"")
        t.eq("[exit-%d] stderr empty" % n, c.stderr, b"")
        m = t.read_meta(meta, "meta-%d" % n)
        if m:
            t.eq("[exit-%d] meta" % n, [m.get("code"), m.get("state"), m.get("data")],
                 ["CHILD_EXITED", "succeeded", {"launched": True, "exit_code": n, "signal": None}])


@check("run.meta_child_exited", "§4 --meta-file CHILD_EXITED on normal exit")
def _(t):
    meta = meta_path(t)
    c = t.proto(*run_args(meta, PY, "-c", CHILD_EXIT, "3"), cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 3)
    m = t.read_meta(meta)
    if m:
        t.eq("code", m.get("code"), "CHILD_EXITED")
        t.eq("state (K5: 'succeeded' whatever the child's exit status)", m.get("state"), "succeeded")
        t.eq("data", m.get("data"), {"launched": True, "exit_code": 3, "signal": None})
    c2 = t.proto(*run_args(None, PY, "-c", CHILD_EXIT, "0"), cwd=t.ctx.run_cwd, label="no-meta-flag")
    t.eq("without --meta-file stdout stays empty", c2.stdout, b"")
    t.eq("without --meta-file exit code", c2.rc, 0)


ARGV_CASES = ["with space", "it's", 'say "hi"', "$HOME", "$(echo pwned)", "`echo pwned`", "a;b", "a|b", "a&b",
              "*", "?", "~", "line1\nline2", "", " ", "ünïcode 東京", "back\\slash", "trailing\\", "tab\there",
              "--", "-x", "--meta-file", "--json", "%PATH%", "!", "{a,b}", "a  b   c", "'", '"', "\r\n"]


@check("run.argv_exact", "§4 argv with spaces/quotes/$/;/*/newline/empty/Unicode reproduced exactly, no shell")
def _(t):
    d = t.ctx.new_dir("argv")
    sentinel1, sentinel2 = d / "pwned-1", d / "pwned-2"
    args = ARGV_CASES + ["; touch %s" % sentinel1, "$(touch %s)" % sentinel2, "x; touch %s" % sentinel1]
    meta = meta_path(t)
    c = t.proto(*run_args(meta, PY, "-c", CHILD_ARGV, *args), cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 0)
    doc = t.parse_doc(c.stdout, "child stdout")
    expect = [os.fsencode(a).hex() for a in args]
    if doc is not None:
        t.eq("argument count", len(doc), len(expect))
        bad = [(i, args[i]) for i, (a, b) in enumerate(zip(doc, expect)) if a != b]
        t.check("every argument byte-identical", doc == expect and not bad, "all equal", bad[:5])
    t.check("no shell executed injected commands", not sentinel1.exists() and not sentinel2.exists(),
            "no sentinel files", [p.name for p in (sentinel1, sentinel2) if p.exists()])
    t.eq("heimdall-proto stderr empty", c.stderr, b"")


INVALID_UTF8_ARGS = [b"\xff\xfe-x", b"caf\xe9", b"trunc\xc3", b"\xed\xa0\x80surrogate", b"cont\x80inuation",
                     b"over\xc0\xafl", b"mix \xff \xe6\x9d\xb1"]


@check("run.argv_invalid_utf8", "§4/K8 argv elements that are not valid UTF-8 are passed byte-for-byte (gating)")
def _(t):
    meta = meta_path(t)
    # Popen passes bytes argv elements to execve untouched
    c = t.proto(*run_args(meta, PY, "-c", CHILD_ARGV, *INVALID_UTF8_ARGS, "valid ü"), cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 0)
    doc = t.parse_doc(c.stdout, "child stdout")
    expect = [a.hex() for a in INVALID_UTF8_ARGS] + ["valid ü".encode().hex()]
    if doc is not None:
        bad = [i for i, (a, b) in enumerate(zip(doc, expect)) if a != b]
        t.check("every argument byte-identical, including the invalid UTF-8 ones", doc == expect, expect,
                {"observed_hex": doc, "differing_indexes": bad})
    t.precondition("harness precondition: the test arguments are not valid UTF-8",
            not any(_is_utf8(a) for a in INVALID_UTF8_ARGS), True, None)
    t.eq("heimdall-proto stderr empty", c.stderr, b"")
    m = t.read_meta(meta)
    if m:
        t.eq("meta", [m.get("code"), m.get("data")], ["CHILD_EXITED", {"launched": True, "exit_code": 0, "signal": None}])


@check("run.meta_state", "§4/K5 meta state: CHILD_EXITED -> succeeded for any child status; CHILD_LAUNCH_FAILED -> failed")
def _(t):
    cases = [("exit-0", [PY, "-c", CHILD_EXIT, "0"], "CHILD_EXITED", "succeeded"),
             ("exit-9", [PY, "-c", CHILD_EXIT, "9"], "CHILD_EXITED", "succeeded"),
             ("killed", [PY, "-c", CHILD_SELFKILL], "CHILD_EXITED", "succeeded"),
             ("missing", [str(t.ctx.sandbox / "no such program")], "CHILD_LAUNCH_FAILED", "failed")]
    for label, argv, code, state in cases:
        meta = meta_path(t)
        t.proto(*run_args(meta, *argv), cwd=t.ctx.run_cwd, label=label)
        m = t.read_meta(meta, "meta-" + label)
        if m:
            t.eq("[%s] meta code and state" % label, [m.get("code"), m.get("state")], [code, state])


@check("run.path_lookup", "§4 argv[0] resolved through PATH without a shell")
def _(t):
    if " " in PY:
        t.check("python path has no spaces (needed for the shebang of the helper)", False, "no spaces", PY)
        return
    d = t.ctx.new_dir("bin")
    exe = d / "hm-child-path-probe"
    exe.write_text("#!%s\nimport sys, os, json\nprint(json.dumps(sys.argv[1:]))\n" % PY)
    os.chmod(exe, 0o755)
    c = t.proto("run", "--", "hm-child-path-probe", "a b", env={"PATH": "%s:%s" % (d, os.environ.get("PATH", ""))},
                cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 0)
    t.eq("child output", t.parse_doc(c.stdout, "child stdout"), ["a b"])


@check("run.launch_failure_missing_absolute", "§4 missing executable -> 127, CHILD_LAUNCH_FAILED, empty stdout")
def _(t):
    launch_failure(t, str(t.ctx.sandbox / "no" / "such exe ü"))


@check("run.launch_failure_missing_path", "§4 command not found on PATH -> 127, CHILD_LAUNCH_FAILED")
def _(t):
    launch_failure(t, "hm-definitely-not-a-command-xyz")


@check("run.launch_failure_not_executable", "§4 non-executable file -> 127, CHILD_LAUNCH_FAILED")
def _(t):
    d = t.ctx.new_dir("noexec")
    p = d / "script ü.sh"
    p.write_text("#!/bin/sh\necho hi\n")
    os.chmod(p, 0o644)
    launch_failure(t, str(p))


def launch_failure(t, exe):
    meta = meta_path(t)
    c = t.proto(*run_args(meta, exe, "arg"), cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 127)
    t.eq("stdout empty", c.stdout, b"")
    t.check("stderr carries a message", len(c.stderr.strip()) > 0, "non-empty", "empty")
    m = t.read_meta(meta)
    if m:
        t.eq("meta code", m.get("code"), "CHILD_LAUNCH_FAILED")
        t.eq("meta state (K5)", m.get("state"), "failed")
        t.check("meta launched is false", isinstance(m.get("data"), dict) and m["data"].get("launched") is False,
                False, m.get("data"))
        t.check("meta exit_code/signal recorded as non-gating observation", True, None,
                {k: (m.get("data") or {}).get(k) for k in ("exit_code", "signal")}, gating=False)


@check("run.child_killed_by_signal", "§4 child self-SIGKILL -> exit 137, meta signal 9")
def _(t):
    meta = meta_path(t)
    c = t.proto(*run_args(meta, PY, "-c", CHILD_SELFKILL), cwd=t.ctx.run_cwd)
    t.eq("exit code 128+9", c.rc, 137)
    t.eq("stdout empty", c.stdout, b"")
    m = t.read_meta(meta)
    if m:
        d = m.get("data") or {}
        t.eq("meta code", m.get("code"), "CHILD_EXITED")
        t.eq("meta state (K5)", m.get("state"), "succeeded")
        t.eq("meta launched", d.get("launched"), True)
        t.eq("meta signal", d.get("signal"), 9)
        t.check("meta exit_code (non-gating observation; Q1)", True, None, d.get("exit_code"), gating=False)


def trap_run(t, sequence, mode="exit", group=False, label=None, gap=0.05):
    """Run the signal-trapping child under heimdall-proto and deliver `sequence`.

    sequence: list of signal numbers sent to the heimdall-proto PID (or its process group)."""
    import signal as sg
    d = t.ctx.new_dir("trap")
    meta = meta_path(t)
    sent = []

    def pre(proc):
        end = time.monotonic() + 10
        while not (d / "ready").exists():
            if proc.poll() is not None or time.monotonic() > end:
                raise RuntimeError("child never became ready")
            time.sleep(0.005)
        for i, s in enumerate(sequence):
            time.sleep(0.05 if i == 0 else gap)
            if group:
                os.killpg(proc.pid, s)
            else:
                os.kill(proc.pid, s)
            sent.append((s, time.time()))
            if s == sg.SIGWINCH:
                end2 = time.monotonic() + 3
                while time.monotonic() < end2 and "SIGWINCH" not in _read_lines(d / "signals"):
                    time.sleep(0.005)
                if proc.poll() is not None:
                    return

    c = t.proto(*run_args(meta, PY, "-c", CHILD_TRAP, str(d), mode), pre=pre, timeout=20, cwd=t.ctx.run_cwd,
                label=label or "trap", ok_leftover=False)
    signals = _read_lines(d / "signals")
    cet = None
    time.sleep(0.15)
    try:
        cet = float((d / "child_exit_time").read_text())
    except (OSError, ValueError):
        pass
    pid = None
    try:
        pid = int((d / "pid").read_text())
    except (OSError, ValueError):
        pass
    return c, signals, cet, pid, meta


def _read_lines(p):
    try:
        return Path(p).read_text().split()
    except OSError:
        return []


def forward_check(signame):
    import signal as sg
    sig = getattr(sg, signame)

    @check("run.forward_" + signame.lower(), "§4/K6 %s sent explicitly to the heimdall-proto pid (no controlling terminal) reaches the child exactly once; heimdall-proto waits and exits with the child's status" % signame)
    def _(t):
        seq = [sig] if signame != "SIGWINCH" else [sig, sg.SIGTERM]
        c, signals, cet, pid, meta = trap_run(t, seq)
        t.eq("exit code is the child's (7)", c.rc, 7)
        t.eq("child received exactly the forwarded signal(s), once each", signals,
             [signame] if signame != "SIGWINCH" else ["SIGWINCH", "SIGTERM"])
        t.check("heimdall-proto did not exit before the child", cet is not None and c.exit_wall is not None
                and cet <= c.exit_wall + 0.001, "child_exit_time <= proto exit",
                {"child_exit_time": cet, "proto_exit": c.exit_wall})
        t.eq("heimdall-proto wrote nothing to stdout", c.stdout, b"")
        t.check("child process no longer alive", pid is not None and not H.pid_alive(pid), "dead", pid)
        m = t.read_meta(meta)
        if m:
            t.eq("meta", [m.get("code"), m.get("data")],
                 ["CHILD_EXITED", {"launched": True, "exit_code": 7, "signal": None}])
    return _


for _s in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGWINCH"):
    forward_check(_s)


@check("run.repeated_signals", "§4/K6 a second SIGINT/SIGTERM sent explicitly to the heimdall-proto pid while the child is still running is forwarded too; heimdall-proto keeps waiting and exits with the child's status (no 'press again to force quit')")
def _(t):
    import signal as sg
    for seq in ([sg.SIGINT, sg.SIGINT], [sg.SIGTERM, sg.SIGTERM], [sg.SIGINT, sg.SIGTERM], [sg.SIGTERM, sg.SIGINT]):
        names = [sg.Signals(x).name for x in seq]
        lb = "+".join(n.lower() for n in names)
        # linger child: exits 0.6 s after the first signal; the second follows 0.15 s after the first
        c, signals, cet, pid, meta = trap_run(t, seq, mode="linger", label="trap-" + lb, gap=0.15)
        t.eq("[%s] exit code is the child's (7)" % lb, c.rc, 7)
        t.eq("[%s] child received both signals, once each, in order" % lb, signals, names)
        t.check("[%s] heimdall-proto did not exit before the child" % lb, cet is not None and c.exit_wall is not None
                and cet <= c.exit_wall + 0.001, "child_exit_time <= proto exit",
                {"child_exit_time": cet, "proto_exit": c.exit_wall})
        t.eq("[%s] heimdall-proto wrote nothing to stdout" % lb, c.stdout, b"")
        t.check("[%s] child process no longer alive" % lb, pid is not None and not H.pid_alive(pid), "dead", pid)


@check("run.sigint_process_group", "§4 terminal-style SIGINT (whole process group) still ends with the child's status")
def _(t):
    import signal as sg
    c, signals, cet, pid, meta = trap_run(t, [sg.SIGINT], mode="linger", group=True, label="trap-group-sigint")
    t.eq("exit code is the child's (7)", c.rc, 7)
    t.check("child saw SIGINT at least once", len(signals) >= 1 and set(signals) == {"SIGINT"}, ">=1 SIGINT", signals)
    t.check("SIGINT delivery count to the child (non-gating observation; Q3)", True, None, len(signals), gating=False)
    t.note("group_sigint_deliveries", len(signals))
    t.eq("stdout empty", c.stdout, b"")


def _wait_file(path, timeout, session=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if Path(path).exists():
            return True
        if session is not None:
            session.pump(0.01)
            if session.poll() is not None:
                return Path(path).exists()
        else:
            time.sleep(0.01)
    return False


@check("run.explicit_signal_with_tty", "§4/K6 as the foreground job of a terminal, a signal sent explicitly to the heimdall-proto pid reaches the child exactly once; exit is the child's", "pyte", budget=120)
def _(t):
    import signal as sg
    observed = {}
    for signame in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"):
        sig = getattr(sg, signame)
        d = t.ctx.new_dir("ttytrap")
        s = t.pty([t.ctx.bin, "run", "--", PY, "-c", CHILD_TRAP, str(d), "linger"], cwd=t.ctx.run_cwd,
                  label="tty-" + signame.lower())
        if not _wait_file(d / "ready", 10, s):
            t.check("[%s] child started under heimdall-proto" % signame, False, "ready", s.poll())
            continue
        time.sleep(0.05)
        s.signal(sig)                       # explicit kill(<heimdall-proto pid>, sig)
        expected = [signame]
        if sig == sg.SIGWINCH:
            end = time.monotonic() + 3
            while time.monotonic() < end and "SIGWINCH" not in _read_lines(d / "signals"):
                s.pump(0.01)
            s.signal(sg.SIGTERM)
            expected = ["SIGWINCH", "SIGTERM"]
        rc = s.wait_exit(8.0)
        time.sleep(0.05)
        sigs = _read_lines(d / "signals")
        observed[signame] = {"child_signals": sigs, "proto_wait_status": rc}
        t.eq("[%s] the child received the explicitly sent signal exactly once" % signame, sigs, expected)
        t.eq("[%s] heimdall-proto exited with the child's status (7)" % signame, rc, 7)
        tail = H.strip_csi(bytes(s.raw)).strip()
        t.check("[%s] nothing written to the terminal (non-gating: stdout and stderr share the pty)" % signame,
                tail == b"", b"", H.printable(tail, 200), gating=False)
    # a second explicit SIGINT while the child is still running (no "press again to force quit")
    d = t.ctx.new_dir("ttytrap")
    s = t.pty([t.ctx.bin, "run", "--", PY, "-c", CHILD_TRAP, str(d), "linger"], cwd=t.ctx.run_cwd,
              label="tty-sigint-twice")
    if _wait_file(d / "ready", 10, s):
        time.sleep(0.05)
        s.signal(sg.SIGINT)
        end = time.monotonic() + 0.15
        while time.monotonic() < end:
            s.pump(0.01)
        s.signal(sg.SIGINT)
        rc = s.wait_exit(8.0)
        time.sleep(0.05)
        sigs = _read_lines(d / "signals")
        observed["SIGINT_twice"] = {"child_signals": sigs, "proto_wait_status": rc}
        t.eq("[SIGINT twice] the child received both explicitly sent signals, once each", sigs, ["SIGINT", "SIGINT"])
        t.eq("[SIGINT twice] heimdall-proto exited with the child's status (7)", rc, 7)
    else:
        t.check("[SIGINT twice] child started under heimdall-proto", False, "ready", s.poll())
    # terminal Ctrl-C pressed twice while the child is still running
    d = t.ctx.new_dir("ttytrap")
    s = t.pty([t.ctx.bin, "run", "--", PY, "-c", CHILD_TRAP, str(d), "linger"], cwd=t.ctx.run_cwd,
              label="tty-ctrl-c-twice")
    if _wait_file(d / "ready", 10, s):
        time.sleep(0.05)
        s.key("ctrl-c")
        end = time.monotonic() + 0.15
        while time.monotonic() < end:
            s.pump(0.01)
        s.key("ctrl-c")
        rc = s.wait_exit(8.0)
        sigs = _read_lines(d / "signals")
        observed["terminal_ctrl_c_twice"] = {"child_signals": sigs, "proto_wait_status": rc}
        t.eq("[terminal Ctrl-C twice] heimdall-proto exited with the child's status (7)", rc, 7)
        t.check("[terminal Ctrl-C twice] the child saw SIGINT only", sigs[:1] == ["SIGINT"] and set(sigs) == {"SIGINT"},
                ">= 1 SIGINT", sigs)
        t.check("[terminal Ctrl-C twice] SIGINT delivery count (non-gating observation; K6b)", True, "2..4",
                len(sigs), gating=False)
    else:
        t.check("[terminal Ctrl-C twice] child started under heimdall-proto", False, "ready", s.poll())
    # terminal-generated Ctrl-C (whole foreground process group or the child's own group)
    d = t.ctx.new_dir("ttytrap")
    s = t.pty([t.ctx.bin, "run", "--", PY, "-c", CHILD_TRAP, str(d), "linger"], cwd=t.ctx.run_cwd, label="tty-ctrl-c")
    if _wait_file(d / "ready", 10, s):
        time.sleep(0.05)
        s.key("ctrl-c")
        rc = s.wait_exit(8.0)
        sigs = _read_lines(d / "signals")
        observed["terminal_ctrl_c"] = {"child_signals": sigs, "proto_wait_status": rc}
        t.eq("[terminal Ctrl-C] heimdall-proto exited with the child's status (7)", rc, 7)
        t.check("[terminal Ctrl-C] the child saw SIGINT", sigs[:1] == ["SIGINT"] and set(sigs) == {"SIGINT"},
                ">= 1 SIGINT", sigs)
        t.check("[terminal Ctrl-C] SIGINT delivery count (non-gating observation; Q3)", True, 1, len(sigs),
                gating=False)
    else:
        t.check("[terminal Ctrl-C] child started under heimdall-proto", False, "ready", s.poll())
    t.note("k6_observed", observed)


CHILD_FDS = ("import json, os, stat, sys\n"
             "rep = {}\n"
             "for fd in (0, 1, 2):\n"
             "    st = os.fstat(fd)\n"
             "    rep[str(fd)] = {'dev': st.st_dev, 'ino': st.st_ino, 'fmt': stat.S_IFMT(st.st_mode),\n"
             "                    'isatty': os.isatty(fd), 'tty': os.ttyname(fd) if os.isatty(fd) else None}\n"
             "open(sys.argv[1], 'w').write(json.dumps(rep))\n"
             "os.write(1, b'child-out\\n'); os.write(2, b'child-err\\n')\n")
# exec the program with fds 0/1/2 replaced by the three named files (no shell)
REDIRECT_EXEC = ("import os, sys\n"
                 "for fd, (path, flags) in enumerate(((sys.argv[1], os.O_RDONLY), (sys.argv[2], os.O_WRONLY | os.O_APPEND),\n"
                 "                                   (sys.argv[3], os.O_WRONLY | os.O_APPEND))):\n"
                 "    n = os.open(path, flags)\n"
                 "    os.dup2(n, fd)\n"
                 "    os.close(n)\n"
                 "os.execv(sys.argv[4], sys.argv[4:])\n")


@check("run.stdio_inherited", "§4 the child inherits heimdall-proto's stdin, stdout and stderr themselves (same open files; a pty stays a tty for the child), not pipes copied by heimdall-proto", "pyte")
def _(t):
    d = t.ctx.new_dir("stdio inherit")
    f0, f1, f2 = d / "stdin.bin", d / "stdout ü.bin", d / "stderr.bin"
    f0.write_bytes(b"in\n")
    f1.write_bytes(b"")
    f2.write_bytes(b"")
    rep = d / "fds.json"
    c = t.proto(*run_args(None, PY, "-c", CHILD_FDS, str(rep)), wrap=[PY, "-c", REDIRECT_EXEC, str(f0), str(f1), str(f2)],
                cwd=t.ctx.run_cwd, label="files")
    t.eq("[files] exit code", c.rc, 0)
    got = _read_json(rep)
    t.require("[files] the child reported its descriptors", isinstance(got, dict), "report", got)
    for fd, f in ((0, f0), (1, f1), (2, f2)):
        st = os.stat(f)
        g = got.get(str(fd)) or {}
        t.check("[files] child fd %d is the very file heimdall-proto was given (same device and inode)" % fd,
                (g.get("dev"), g.get("ino")) == (st.st_dev, st.st_ino),
                {"dev": st.st_dev, "ino": st.st_ino, "regular_file": True},
                {"dev": g.get("dev"), "ino": g.get("ino"), "regular_file": g.get("fmt") == 0o100000})
    t.eq("[files] stdout file holds exactly the child's output", f1.read_bytes(), b"child-out\n")
    t.eq("[files] stderr file holds exactly the child's output", f2.read_bytes(), b"child-err\n")
    # under a pty: stdin, stdout and stderr all the terminal
    rep2 = d / "fds-pty.json"
    s = t.pty([t.ctx.bin, "run", "--", PY, "-c", CHILD_FDS, str(rep2)], cwd=t.ctx.run_cwd, label="pty",
              stderr_tty=True)
    rc = s.wait_exit(10.0)
    t.eq("[pty] exit code", rc, 0)
    got = _read_json(rep2)
    t.require("[pty] the child reported its descriptors", isinstance(got, dict), "report", got)
    tty = os.ttyname(s.slave)
    for fd in (0, 1, 2):
        g = got.get(str(fd)) or {}
        t.check("[pty] child fd %d is the terminal (isatty, same tty device)" % fd,
                g.get("isatty") is True and g.get("tty") == tty, {"isatty": True, "tty": tty},
                {"isatty": g.get("isatty"), "tty": g.get("tty")})


@check("run.proto_silent_stdout", "§4 heimdall-proto writes nothing to stdout in run (silent child)")
def _(t):
    for with_meta in (True, False):
        meta = meta_path(t) if with_meta else None
        c = t.proto(*run_args(meta, PY, "-c", "pass"), label="silent-meta" if with_meta else "silent",
                    cwd=t.ctx.run_cwd)
        t.eq("[%s] stdout empty" % c.label, c.stdout, b"")
        t.eq("[%s] stderr empty" % c.label, c.stderr, b"")
        t.eq("[%s] exit 0" % c.label, c.rc, 0)


@check("run.cwd_env_inherited", "§4 child inherits working directory and environment")
def _(t):
    cwd = t.ctx.new_dir("cwd ü dir")
    c = t.proto(*run_args(None, PY, "-c", CHILD_ENVCWD), cwd=cwd, env={"HM_ENV_PROBE": "v ünï=1; x"})
    t.eq("exit code", c.rc, 0)
    doc = t.parse_doc(c.stdout, "child stdout")
    if doc:
        t.eq("cwd", doc.get("cwd"), os.path.realpath(cwd))
        t.eq("env var", doc.get("env"), "v ünï=1; x")


@check("run.no_surviving_child", "§4 no zombie or orphaned child after heimdall-proto exits")
def _(t):
    d = t.ctx.new_dir("pid")
    pidfile = d / "child.pid"
    c = t.proto(*run_args(None, PY, "-c", CHILD_PIDFILE, str(pidfile)), cwd=t.ctx.run_cwd)
    t.eq("exit code", c.rc, 0)
    pid = int(pidfile.read_text()) if pidfile.exists() else None
    t.check("child pid recorded and gone", pid is not None and not H.pid_alive(pid), "dead", pid)


@check("run.usage_errors", "§4 missing -- or empty argv -> exit 2, stderr only, child not started")
def _(t):
    d = t.ctx.new_dir("usage")
    marker = d / "ran"
    touch = "open(%r, 'w').write('x')" % str(marker)
    t.plain_error(t.proto("run", "--", label="empty-argv", cwd=t.ctx.run_cwd))
    t.plain_error(t.proto("run", label="bare-run", cwd=t.ctx.run_cwd))
    t.plain_error(t.proto("run", PY, "-c", touch, label="no-dashdash", cwd=t.ctx.run_cwd))
    t.plain_error(t.proto("run", "--meta-file", str(d / "m.json"), label="meta-only", cwd=t.ctx.run_cwd))
    t.check("the child was never started", not marker.exists(), "marker absent", marker.exists())


# ===== tui (contract section 5) ===========================================
ALIASES = [d["alias"] for d in HOMELAB_DESTS]
LARGE = tomllib.loads((FIX / "large-100.toml").read_text(encoding="utf-8"))["destinations"]
STATUS_RE = re.compile(r"(?<![\d.])(\d+)/(\d+)(?!\d)")
BOX = "\u2500-\u257f"


def status_of(s):
    """(shown,total) from the last screen line containing N/M, else None."""
    for line in reversed(s.lines()):
        m = STATUS_RE.search(line)
        if m:
            return int(m.group(1)), int(m.group(2))
    return None


def has_status(shown, total):
    return lambda s: status_of(s) == (shown, total)


def row_prefix(s, alias):
    """Text before `alias` on the first screen line containing it (leading box drawing removed)."""
    for line in s.lines():
        i = line.find(alias)
        if i >= 0:
            return re.sub("^[%s]" % BOX, "", line[:i]), line
    return None, None


def tui_env(t, extra=None):
    return t.ctx.env(extra)


def start_tui(t, profile=FIX / "homelab.toml", rows=24, cols=80, env=None, args=None, expect=None,
              hup_forward=True):
    if t.ctx.pyte is None:
        raise RuntimeError("pyte missing")
    argv = [t.ctx.bin] + (args or ["tui", "--file", str(profile)])
    s = t.pty(argv, rows, cols, env=env, label="tui%d" % (len(t.sessions) + 1), hup_forward=hup_forward)
    pred = expect or (lambda x: all(a in x.text() for a in ALIASES) and status_of(x) == (3, 3))
    lat = s.wait_for(pred, 10.0, t_start=s.t_spawn)
    if lat is None:
        t.check("first frame appears within 10 s", False, "frame", "no frame; screen=%r exit=%r" % (s.text()[:300], s.poll()))
        raise Abort("no first frame")
    s.settle(0.1)
    return s, lat


def finish_session(t, s, label="session"):
    """Save terminal evidence for the session."""
    t.save("%s.raw.bin" % label, bytes(s.raw), limit=262144)
    t.save("%s.screen.txt" % label, s.text())
    t.scan(label + ".pty", bytes(s.raw))
    s.saved = True


def cleanup(t, s):
    if s.poll() is None:
        s.send(b"\x03")
        if s.wait_exit(3.0) is None:
            t.check("cleanup: process exits after Ctrl-C", False, "exit", "still running (killed)")
            s.close()
    else:
        s.wait_exit(0.5)


def assert_restored(t, s, tag):
    raw = bytes(s.raw)
    st = H.final_state(raw)
    t.check("[%s] entered the alternate screen" % tag, st["alt_entered"], True, st)
    t.check("[%s] hid the cursor while active" % tag, st["cursor_hidden_ever"], True, st)
    t.check("[%s] left the alternate screen on exit" % tag, not st["alt_active_at_end"], "left", st)
    t.check("[%s] cursor shown again on exit (last cursor mode is 'show')" % tag, not st["cursor_hidden_at_end"],
            "visible", st)
    t.check("[%s] terminal emulator reports cursor visible" % tag, not s.screen.cursor.hidden, "visible",
            "hidden" if s.screen.cursor.hidden else "visible")
    bad = H.disallowed_tail_sequences(H.tail_after_restore(raw))
    t.check("[%s] restore sequences are last (nothing but text/SGR after them)" % tag, not bad, "none", bad[:5])
    after = H.normalize_termios(s.termios_after())
    before = H.normalize_termios(s.attr_before)
    same = after == before
    diff = {}
    if not same:
        names = ["iflag", "oflag", "cflag", "lflag", "ispeed", "ospeed"]
        for i, n in enumerate(names):
            if after[i] != before[i]:
                diff[n] = [before[i], after[i]]
        if after[6] != before[6]:
            diff["cc"] = "differs"
    t.check("[%s] termios of the pty slave equal before/after" % tag, same, "identical", diff)


def tail_text(s):
    return H.strip_csi(H.tail_after_restore(bytes(s.raw))).replace(b"\r\n", b"\n")


@check("tui.non_tty", "§5 requires a TTY on stdin and stdout, else exit 2 (stderr)", "pyte")
def _(t):
    import fcntl, termios as tm
    c = t.proto("tui", "--file", str(FIX / "homelab.toml"), label="all-pipes", timeout=10)
    t.plain_error(c)
    for which in ("stdin-tty", "stdout-tty"):
        master, slave = os.openpty()
        fcntl.ioctl(master, tm.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        kw = {"stdin": slave, "stdout": subprocess.PIPE} if which == "stdin-tty" else \
            {"stdin": subprocess.PIPE, "stdout": slave}
        argv = [t.ctx.bin, "tui", "--file", str(FIX / "homelab.toml")]
        before = t.ctx.k11_snapshot(t.ctx.cwd_ro)
        p = H.spawn(argv, t.ctx.env(), str(t.ctx.cwd_ro), stderr=subprocess.PIPE, **kw)
        out, err, timed_out, _held = H.bounded_communicate(p, b"" if which == "stdout-tty" else None, 10)
        if timed_out:
            t.check("[%s] exits instead of waiting" % which, False, "exit", "timeout")
        t.k11_check(which, before, t.ctx.cwd_ro, argv)
        import select as sel
        seen = b""
        while sel.select([master], [], [], 0.05)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
        os.close(master)
        os.close(slave)
        t.check("[%s] exit code 2" % which, p.returncode == 2, 2, p.returncode)
        t.check("[%s] stderr carries a message" % which, len(err.strip()) > 0, "non-empty", "empty")
        t.check("[%s] no alternate-screen sequences emitted" % which, not H.final_state(seen)["alt_entered"],
                "none", H.printable(seen, 100))
        t.scan(which + ".out", out + err + seen)


@check("tui.first_frame", "§5 first frame: all aliases, N/M status, '> ' prefix, row format; latency recorded", "pyte")
def _(t):
    s, lat = start_tui(t)
    t.note("first_frame_latency_ms", round(lat * 1000, 1))
    t.ctx.observations["first_frame_latency_ms"] = round(lat * 1000, 1)
    t.check("first frame shows every alias and '3/3'", True, ALIASES, s.lines())
    for i, d in enumerate(HOMELAB_DESTS):
        pre, line = row_prefix(s, d["alias"])
        want = "> " if i == 0 else "  "
        t.check("row %d (%s) prefix %r" % (i, d["alias"], want), pre == want, repr(want), repr(pre))
        tail = "%s@%s:%d" % (d["account"], d["host"], d["port"])
        t.check("row %d shows 'alias  account@host:port'" % i,
                line is not None and re.search(re.escape(d["alias"]) + r"\s+" + re.escape(tail), line) is not None,
                d["alias"] + "  " + tail, line)
    t.check("exactly one row carries the '> ' marker", sum(1 for l in s.lines() if re.match("^[%s]?> " % BOX, l)) == 1,
            1, s.lines())
    cleanup(t, s)
    finish_session(t, s)


@check("tui.filter_basic", "§5 '/' filter 'nas' -> 1/3, status shows filter text, other rows hidden", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("nas")
    lat = s.wait_for(has_status(1, 3), 5.0)
    t.require("status becomes 1/3", lat is not None, "1/3", status_of(s))
    s.settle(0.15)
    txt = s.text()
    t.check("nas row visible", "nas" in txt)
    t.check("lab-server and vps rows hidden", "lab-server" not in txt and "vps-東京" not in txt, "hidden", s.lines())
    t.check("status line shows the filter text", any(STATUS_RE.search(l) and "nas" in l for l in s.lines()),
            "status line contains 'nas'", s.lines()[-3:])
    cleanup(t, s)


@check("tui.filter_unicode", "§5 non-ASCII filter characters (東京 -> 1/3)", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("東京")
    lat = s.wait_for(has_status(1, 3), 5.0)
    t.require("status becomes 1/3", lat is not None, "1/3", status_of(s))
    s.settle(0.1)
    t.check("vps-東京 visible, others hidden", "vps-東京" in s.text() and "nas" not in s.text()
            and "lab-server" not in s.text(), "only vps", s.lines())
    cleanup(t, s)


@check("tui.filter_case_insensitive", "§5 filter is case-insensitive (NAS)", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("NAS")
    lat = s.wait_for(has_status(1, 3), 5.0)
    t.check("status becomes 1/3", lat is not None, "1/3", status_of(s))
    cleanup(t, s)


@check("tui.filter_matches_host", "§5 filter matches host as well as alias", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("lab.example")
    lat = s.wait_for(has_status(1, 3), 5.0)
    t.require("status becomes 1/3", lat is not None, "1/3", status_of(s))
    s.settle(0.1)
    t.check("lab-server visible only", "lab-server" in s.text() and "nas" not in s.text(), "lab-server", s.lines())
    cleanup(t, s)


@check("tui.filter_backspace", "§5 Backspace deletes a filter character", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("nasx")
    t.require("nasx -> 0/3", s.wait_for(has_status(0, 3), 5.0) is not None, "0/3", status_of(s))
    s.key("backspace")
    t.check("backspace -> 1/3", s.wait_for(has_status(1, 3), 5.0) is not None, "1/3", status_of(s))
    cleanup(t, s)


@check("tui.esc_clears_filter", "§5 Esc clears the filter and leaves filter mode (q then quits)", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("nas")
    t.require("filtered to 1/3", s.wait_for(has_status(1, 3), 5.0) is not None, "1/3", status_of(s))
    s.key("esc")
    t.check("Esc restores 3/3", s.wait_for(has_status(3, 3), 5.0) is not None, "3/3", status_of(s))
    s.settle(0.15)
    t.check("all aliases visible again", all(a in s.text() for a in ALIASES), ALIASES, s.lines())
    s.send("q")
    rc = s.wait_exit(3.0)
    t.check("'q' after Esc quits (so Esc left filter mode)", rc == 0, 0, rc)
    finish_session(t, s)


@check("tui.filter_enter_keeps_filter", "§5 Enter leaves filter mode keeping the filter; next Enter selects", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("nas")
    t.require("filtered to 1/3", s.wait_for(has_status(1, 3), 5.0) is not None, "1/3", status_of(s))
    s.key("enter")
    s.settle(0.3)
    t.check("filter kept after Enter (still 1/3)", status_of(s) == (1, 3), "1/3", status_of(s))
    t.check("still running", s.poll() is None, "running", s.poll())
    s.key("enter")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 0)
    t.eq("stdout tail is 'SELECTED nas\\n'", tail_text(s), b"SELECTED nas\n")
    finish_session(t, s)


@check("tui.select_down_enter", "§5 Down+Enter -> 'SELECTED nas' on stdout, exit 0; terminal restored", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.key("down")
    lat = s.wait_for(lambda x: (row_prefix(x, "nas")[0] == "> "), 5.0)
    t.check("selection marker moved to 'nas'", lat is not None, "'> nas'", s.lines())
    s.key("enter")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 0)
    t.eq("output after restore is exactly 'SELECTED nas\\n'", tail_text(s), b"SELECTED nas\n")
    t.eq("SELECTED printed exactly once", bytes(s.raw).count(b"SELECTED"), 1)
    t.check("SELECTED appears after the alternate screen was left",
            bytes(s.raw).rfind(b"SELECTED") > H.final_state(bytes(s.raw))["last_restore_offset"], True, None)
    assert_restored(t, s, "select")
    finish_session(t, s)


@check("tui.select_jk_keys", "§5 j/k move the selection", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("j")
    s.send("j")
    s.settle(0.1)
    s.send("k")
    t.check("marker on 'nas' after j j k", s.wait_for(lambda x: row_prefix(x, "nas")[0] == "> ", 3.0) is not None,
            "'> nas'", s.lines())
    s.key("enter")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 0)
    t.eq("tail", tail_text(s), b"SELECTED nas\n")
    finish_session(t, s)


@check("tui.quit_q", "§5 q -> exit 0, no SELECTED, no stdout; terminal restored", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("q")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 0)
    t.check("no SELECTED anywhere", b"SELECTED" not in bytes(s.raw), "absent", H.printable(bytes(s.raw)[-80:]))
    t.eq("nothing printed after restore", tail_text(s), b"")
    assert_restored(t, s, "quit")
    finish_session(t, s)


@check("tui.ctrl_c", "§5 Ctrl-C -> exit 130, no SELECTED; terminal restored", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.key("ctrl-c")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 130)
    t.check("no SELECTED anywhere", b"SELECTED" not in bytes(s.raw))
    assert_restored(t, s, "ctrl-c")
    finish_session(t, s)


@check("tui.ctrl_c_in_filter_mode", "§5 Ctrl-C while typing a filter -> exit 130; terminal restored", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.send("/")
    s.settle(0.1)
    s.send("na")
    s.settle(0.1)
    s.key("ctrl-c")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 130)
    assert_restored(t, s, "ctrl-c-filter")
    finish_session(t, s)


def k10_exit_form(t, tag, rc, code, sig):
    """K10 exit form (section 9.3): a process exit status `code` and a death by the re-raised signal both conform;
    record which one the program used."""
    form = "exit %d" % code if rc == code else "killed by %s" % signal.Signals(sig).name if rc == -sig else repr(rc)
    t.ctx.observations.setdefault("k10_exit_form", {})[tag] = form


@check("tui.sigterm_restores_terminal", "§5/K10 SIGTERM -> terminal restored, exit 143, no stdout", "pyte")
def _(t):
    import signal as sg
    s, _ = start_tui(t)
    s.key("down")
    s.wait_for(lambda x: row_prefix(x, "nas")[0] == "> ", 3.0)
    s.signal(sg.SIGTERM)
    rc = s.wait_exit(3.0)
    t.note("sigterm_wait_status", rc)
    t.check("K10: exit status 143, or killed by a re-raised SIGTERM (wait status %d; K10 exit form, section 9.3)"
            % -sg.SIGTERM, rc in (143, -sg.SIGTERM), [143, -sg.SIGTERM], rc)
    k10_exit_form(t, "sigterm", rc, 143, sg.SIGTERM)
    t.check("no SELECTED anywhere", b"SELECTED" not in bytes(s.raw), "absent", H.printable(bytes(s.raw)[-80:]))
    t.eq("nothing printed after restore (no stdout)", tail_text(s), b"")
    assert_restored(t, s, "sigterm")
    finish_session(t, s)


@check("tui.sighup_exit_129", "§5/K10 SIGHUP -> exit 129, no stdout; terminal (still present) restored", "pyte")
def _(t):
    import signal as sg
    s, _ = start_tui(t)
    s.key("down")
    s.wait_for(lambda x: row_prefix(x, "nas")[0] == "> ", 3.0)
    s.signal(sg.SIGHUP)
    rc = s.wait_exit(3.0)
    t.note("sighup_wait_status", rc)
    t.check("K10: exit status 129, or killed by a re-raised SIGHUP (wait status %d; K10 exit form, section 9.3)"
            % -sg.SIGHUP, rc in (129, -sg.SIGHUP), [129, -sg.SIGHUP], rc)
    k10_exit_form(t, "sighup", rc, 129, sg.SIGHUP)
    t.check("no SELECTED anywhere", b"SELECTED" not in bytes(s.raw), "absent", H.printable(bytes(s.raw)[-80:]))
    t.eq("nothing printed after restore (no stdout)", tail_text(s), b"")
    assert_restored(t, s, "sighup")
    finish_session(t, s)


@check("tui.hangup_exit_129", "§5/K10 terminal hangup (pty master closed) -> exit 129, both with a shell-like session leader (SIGHUP + EOF) and without one (EOF/EIO only)", "pyte")
def _(t):
    for variant, fwd in (("shell-like", True), ("bare", False)):
        s, _ = start_tui(t, hup_forward=fwd)
        s.label = "hangup-" + variant
        rc = s.hangup(5.0)
        t.note("hangup_%s_wait_status" % variant, rc)
        t.check("[%s hangup] K10: exit status 129, or killed by a re-raised SIGHUP (wait status %d; K10 exit form)"
                % (variant, -signal.SIGHUP), rc in (129, -signal.SIGHUP), [129, -signal.SIGHUP], rc)
        k10_exit_form(t, "hangup-" + variant, rc, 129, signal.SIGHUP)
        t.check("[%s hangup] no SELECTED in the output read before the hangup" % variant,
                b"SELECTED" not in bytes(s.raw), "absent", None)


@check("tui.filter_edit_resets_selection", "§5/K9 an appended filter character, Backspace and the Esc clear each move '> ' to the first shown row", "pyte")
def _(t):
    s, _ = start_tui(t)
    first = "lab-server"

    def marker_on(alias, timeout=3.0):
        return s.wait_for(lambda x: row_prefix(x, alias)[0] == "> ", timeout) is not None

    def one_marker():
        return sum(1 for l in s.lines() if re.match("^[%s]?> " % BOX, l)) == 1

    s.key("down")
    s.key("down")
    t.require("Down Down -> '> vps-東京'", marker_on("vps-東京"), "'> vps-東京'", s.lines())
    s.send("/")
    s.settle(0.1)
    s.send("a")                     # matches all three rows (alias or host)
    t.check("[append] after typing 'a' the first shown row is selected", marker_on(first), "'> %s'" % first,
            s.lines())
    t.check("[append] status 3/3 and exactly one '> ' row", status_of(s) == (3, 3) and one_marker(), "3/3, one",
            s.lines())
    s.key("enter")                  # leave filter mode, keep the filter and the selection
    s.settle(0.2)
    t.check("[Enter] leaving filter mode keeps the selection", row_prefix(s, first)[0] == "> ", "'> %s'" % first,
            s.lines())
    s.key("down")
    s.key("down")
    t.require("Down Down -> '> vps-東京' (filter 'a' active)", marker_on("vps-東京"), "'> vps-東京'", s.lines())
    s.send("/")
    s.settle(0.1)
    s.key("backspace")              # filter 'a' -> ''
    t.check("[Backspace] after deleting the filter character the first shown row is selected", marker_on(first),
            "'> %s'" % first, s.lines())
    s.send("e")                     # filter 'e' (matches every host)
    t.require("filter 'e' shows 3/3", s.wait_for(has_status(3, 3), 3.0) is not None, "3/3", status_of(s))
    s.key("enter")
    s.settle(0.2)
    s.key("down")
    t.require("Down -> '> nas' (filter 'e' active)", marker_on("nas"), "'> nas'", s.lines())
    s.send("/")
    s.settle(0.1)
    s.key("esc")                    # clears the filter
    t.check("[Esc] after clearing the filter the first shown row is selected", marker_on(first), "'> %s'" % first,
            s.lines())
    s.send("q")
    t.eq("q exits 0", s.wait_exit(3.0), 0)
    finish_session(t, s)


@check("tui.no_color", "§5 NO_COLOR set -> no color SGR sequences at all; selection not color-only", "pyte")
def _(t):
    s, _ = start_tui(t, env={"NO_COLOR": "1"})
    s.key("down")
    s.settle(0.2)
    s.key("up")
    s.settle(0.2)
    s.send("/")
    s.settle(0.1)
    s.send("nas")
    s.wait_for(has_status(1, 3), 5.0)
    s.key("esc")
    s.settle(0.2)
    pre, _ = row_prefix(s, "lab-server")
    t.eq("selected row still carries '> '", pre, "> ")
    s.send("q")
    s.wait_exit(3.0)
    hits = H.color_sgr_found(bytes(s.raw))
    t.check("no color SGR in the whole session output", not hits, "none", [h for h in hits[:5]])
    finish_session(t, s)


def _rows_with_host(x):
    """For each alias: does its screen row carry account@host (an '@' after the alias)?"""
    out = {}
    for a in ALIASES:
        _pre, line = row_prefix(x, a)
        out[a] = None if line is None else ("@" in line[line.find(a) + len(a):])
    return out


@check("tui.resize_narrow_hides_host", "§5 width < 50 shows only alias, at 50 and wider each row shows account@host: 40, 49 (narrow) and 50, 80 (wide) columns, both directions across the boundary", "pyte")
def _(t):
    s, _ = start_tui(t)
    t.check("wide layout shows account@host", "@" in s.text(), "@", s.lines())
    narrow = lambda x: all(v is False for v in _rows_with_host(x).values())
    wide = lambda x: all(v is True for v in _rows_with_host(x).values())
    for rows, cols, pred, what in ((10, 40, narrow, "hides account@host but keeps every alias"),
                                   (24, 50, wide, "(exactly 50 columns, not < 50) shows account@host on every row"),
                                   (24, 49, narrow, "(49 columns, < 50) hides account@host but keeps every alias"),
                                   (24, 50, wide, "(back to 50 columns) shows account@host on every row again"),
                                   (24, 80, wide, "shows account@host on every row")):
        s.resize(rows, cols)
        lat = s.wait_for(pred, 3.0)
        t.check("%dx%d %s" % (cols, rows, what), lat is not None, what, {"rows": _rows_with_host(s), "screen": s.lines()})
        t.check("%dx%d status still shows 3/3" % (cols, rows), status_of(s) == (3, 3), "3/3", status_of(s))
    t.check("still running", s.poll() is None, "running", s.poll())
    cleanup(t, s)


@check("tui.resize_relayout_latency", "§5 resize re-lays out within 100 ms (best of 5 narrow/wide cycles)", "pyte")
def _(t):
    s, _ = start_tui(t)
    lats = []
    for _i in range(5):
        t0 = time.monotonic()
        s.resize(10, 40)
        a = s.wait_for(lambda x: "@" not in x.text() and "lab-server" in x.text(), 3.0, t_start=t0)
        s.settle(0.1)
        t0 = time.monotonic()
        s.resize(24, 80)
        b = s.wait_for(lambda x: "@" in x.text(), 3.0, t_start=t0)
        s.settle(0.1)
        lats += [a, b]
    t.require("every resize produced a re-layout", all(x is not None for x in lats), "all re-laid out", lats)
    ms = [round(x * 1000, 1) for x in lats]
    t.note("resize_latencies_ms", ms)
    t.ctx.observations["resize_relayout_ms"] = ms
    narrow, wide = ms[0::2], ms[1::2]
    t.check("best narrow re-layout <= 100 ms", min(narrow) <= 100, "<= 100 ms", narrow)
    t.check("best widen re-layout <= 100 ms", min(wide) <= 100, "<= 100 ms", wide)
    cleanup(t, s)


@check("tui.resize_tiny_no_crash", "§5 resize to 20x5 never crashes; layout recovers", "pyte")
def _(t):
    s, _ = start_tui(t)
    s.resize(5, 20)
    s.settle(0.6)
    t.check("process still running at 20x5", s.poll() is None, "running", s.poll())
    s.resize(3, 10)
    s.settle(0.4)
    t.check("process still running at 10x3", s.poll() is None, "running", s.poll())
    s.resize(24, 80)
    lat = s.wait_for(lambda x: all(a in x.text() for a in ALIASES) and status_of(x) == (3, 3), 3.0)
    t.check("frame recovers at 80x24", lat is not None, "full frame", s.lines())
    s.send("q")
    rc = s.wait_exit(3.0)
    t.eq("q exits 0 after the tiny phase", rc, 0)
    finish_session(t, s)


@check("tui.start_tiny_no_crash", "§5 starting at 20x5 does not crash; q exits 0", "pyte")
def _(t):
    s = t.pty([t.ctx.bin, "tui", "--file", str(FIX / "homelab.toml")], 5, 20, label="tiny")
    s.wait_for(lambda x: bool(x.text().strip()), 5.0, t_start=s.t_spawn)
    s.settle(0.5)
    t.check("process running and has drawn something", s.poll() is None and bool(s.text().strip()),
            "running + drawn", {"exit": s.poll(), "screen": s.lines()})
    t.check("selected marker visible when rows fit", any("> " in l for l in s.lines()), "'> ' row", s.lines())
    s.send("q")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 0)
    assert_restored(t, s, "tiny-quit")
    finish_session(t, s)


def large_expected_count(prefix):
    f = prefix.lower()
    return sum(1 for d in LARGE if f in d["alias"].lower() or f in d["host"].lower())


K17_P95_MS = 100        # contract section 9.3 K17 (spec section 15.1 key budget)
K17_CYCLES = 5         # 5 filter sessions x (3 typed characters + 3 Backspaces) = 30 measured edits
K17_EDITS = 6 * K17_CYCLES
LARGE_ALIAS_RE = re.compile(r"host-\d{3}-[a-z]+")
LARGE_ALIASES = set(d["alias"] for d in LARGE)


def large_expected_aliases(prefix):
    f = prefix.lower()
    return [d["alias"] for d in LARGE if f in d["alias"].lower() or f in d["host"].lower()]


def large_rows(s):
    """large-100 aliases shown in the list rows, top to bottom (one per screen line)."""
    out = []
    for line in s.lines():
        m = [a for a in LARGE_ALIAS_RE.findall(line) if a in LARGE_ALIASES]
        if m:
            out.append(m[0])
    return out


def large_screen_matches(typed, cap):
    """K17 'screen update' predicate: the status count AND the list rows show the result of filter `typed`: the
    first min(N, cap) matching destinations in fixture order (K9 resets the selection to the first shown row, so
    the list starts at the first match), cap being the list capacity measured in filter mode at 100/100."""
    exp = large_expected_aliases(typed)
    want_rows = exp[:min(len(exp), cap)]
    return lambda s: status_of(s) == (len(exp), 100) and large_rows(s) == want_rows


def p95_nearest_rank(values):
    """95th percentile, nearest-rank method (the smallest value with at least 95 % of the samples at or below it)."""
    v = sorted(values)
    if not v:
        return None
    k = -(-95 * len(v) // 100)          # ceil(0.95 * n)
    return v[max(k, 1) - 1]


@check("tui.large_100_filter_latency", "§5/K17 100-destination fixture: immediate filtering - p95 keystroke-to-screen-update latency in filter mode at most %d ms over %d edits in %d filter sessions (each: `/`, typing 7, 0, 5, three Backspaces, Esc; an update counts when the pty emulator shows both the N/100 status and the list rows of the new result); scrolling; Down-key latency recorded" % (K17_P95_MS, K17_EDITS, K17_CYCLES), "pyte", budget=150)
def _(t):
    s, lat = start_tui(t, FIX / "large-100.toml", expect=lambda x: status_of(x) == (100, 100))
    t.note("large100_first_frame_ms", round(lat * 1000, 1))
    s.settle(0.1)
    # navigation latency + scrolling beyond the visible window
    nav = []
    for i in range(1, 31):
        alias = LARGE[i]["alias"]
        t0 = time.monotonic()
        s.key("down")
        r = s.wait_for(lambda x, a=alias: row_prefix(x, a)[0] == "> ", 3.0, t_start=t0)
        if r is None:
            t.check("selection reaches row %d (%s) and stays visible" % (i, alias), False, "'> %s'" % alias, s.lines())
            break
        nav.append(round(r * 1000, 1))
    else:
        t.check("selection followed 30 Down presses through the scrolled list", True)
    for _i in range(30):
        s.key("up")
    s.settle(0.2)
    # K17: keystroke -> screen update latency for each filter edit, over several filter sessions so that the first
    # keystroke after `/` is weighted per session (round-3 review: one pooled session let a slow first keystroke
    # pass).  An update counts only when the list rows show the new result too, not just the N/M count (round-3
    # review: rows redrawn 150 ms after the count passed).
    t.precondition("harness precondition: filter counts 100 -> 19 -> 1 -> 0 are strictly decreasing (no stale reads)",
                   [100, 19, 1, 0] == [100] + [large_expected_count(p) for p in ("7", "70", "705")], [100, 19, 1, 0],
                   [100] + [large_expected_count(p) for p in ("7", "70", "705")])
    lats, sessions, cap = [], [], None
    for cyc in range(1, K17_CYCLES + 1):
        s.send("/")
        s.settle(0.15)
        if cap is None:
            # list capacity in filter mode with an empty filter: the first `cap` destinations, in fixture order
            rows0 = large_rows(s)
            cap = len(rows0)
            if not t.check("[session 1] in filter mode with an empty filter the list shows the first destinations of "
                           "large-100 in fixture order, from the first (list capacity measured: %d rows)" % cap,
                           cap >= 2 and rows0 == [d["alias"] for d in LARGE[:cap]] and status_of(s) == (100, 100),
                           "host-000-web, host-001-db, ...; 100/100", {"rows": rows0, "status": status_of(s)}):
                break
        typed, slat = "", []
        edits = [("type", ch) for ch in "705"] + [("backspace", None)] * 3
        for kind, ch in edits:
            typed = typed + ch if kind == "type" else typed[:-1]
            pred = large_screen_matches(typed, cap)
            t0 = time.monotonic()
            if kind == "type":
                s.send(ch)
            else:
                s.key("backspace")
            r = s.wait_for(pred, 3.0, t_start=t0)
            exp = large_expected_aliases(typed)
            t.check("[session %d] after %s %r the screen shows status %d/100 and the list rows of the result (%d rows "
                    "from %s)" % (cyc, "typing" if kind == "type" else "backspace to", typed, len(exp),
                                  min(len(exp), cap), exp[0] if exp else "-"), r is not None,
                    {"status": "%d/100" % len(exp), "rows": exp[:min(len(exp), cap)]},
                    {"status": status_of(s), "rows": large_rows(s)})
            if r is not None:
                slat.append(round(r * 1000, 1))
        lats += slat
        sessions.append(slat)
        s.key("esc")
        s.settle(0.3)                      # Esc alone, never merged with the next `/` into an Alt sequence
    p95 = p95_nearest_rank(lats)
    first = [x[0] for x in sessions if x]
    t.check("K17: every one of the %d filter edits produced its screen update (status and rows)" % K17_EDITS,
            len(lats) == K17_EDITS, K17_EDITS, len(lats))
    t.check("K17: p95 keystroke-to-screen-update latency in filter mode (nearest rank over %d edits in %d filter "
            "sessions) <= %d ms" % (K17_EDITS, K17_CYCLES, K17_P95_MS), p95 is not None and p95 <= K17_P95_MS,
            "<= %d ms" % K17_P95_MS, {"p95_ms": p95, "max_ms": max(lats) if lats else None,
                                      "first_keystroke_per_session_ms": first, "samples_ms": lats})
    t.note("large100_filter_keystroke_ms", lats)
    t.note("large100_filter_sessions_ms", sessions)
    t.note("large100_list_capacity_rows", cap)
    t.note("large100_down_key_ms", nav)
    t.ctx.observations["large100_keystroke_to_update_ms"] = {"filter": lats, "down": nav, "filter_p95": p95,
                                                             "k17_bound_ms": K17_P95_MS, "sessions": sessions,
                                                             "first_keystroke_per_session": first,
                                                             "update_predicate": "status N/100 and list rows"}
    cleanup(t, s)


@check("tui.no_agent_contact", "§5 TUI never contacts an SSH agent (contact log), no file writes; R-SS-02", "pyte")
def _(t):
    d = t.ctx.new_dir("tui-agent")
    fa = H.FakeAgent(t.ctx.sandbox, d, "tui", "normal", [k["pub"] for k in t.ctx.keys()])
    t.agents.append(fa)
    s, _ = start_tui(t, env={"SSH_AUTH_SOCK": fa.sock})
    s.key("down")
    s.settle(0.3)
    s.key("enter")
    rc = s.wait_exit(3.0)
    t.eq("exit code", rc, 0)
    s.settle(0.2)
    fa.stop()
    ev = fa.events()
    t.save("tui.contact.jsonl", Path(fa.log_path).read_bytes())
    t.eq("no connection to the fake agent", [e for e in ev if e["event"] in ("connect", "message")], [])
    finish_session(t, s)


# ===== common / canary =====================================================
@check("common.exit_codes_without_json", "§1/K12 without --json the exit codes equal the --json ones (output not judged)")
def _(t):
    d = t.ctx.new_dir("k12")
    big = sized_profile(d, "big.toml", 1048577)
    cases = [("profile-ok", ["profile", "show", "--file", str(FIX / "homelab.toml")], 0),
             ("profile-schema-invalid", ["profile", "show", "--file", str(FIX / "invalid-forbidden-key.toml")], 2),
             ("profile-malformed", ["profile", "show", "--file", str(FIX / "invalid-malformed.toml")], 2),
             ("profile-too-large", ["profile", "show", "--file", str(big)], 2),
             ("profile-missing", ["profile", "show", "--file", str(d / "missing.toml")], 2),
             ("agent-missing-socket", ["agent", "list", "--socket", str(d / "none.sock")], 5),
             ("version", ["version"], 0)]
    for label, args, rc in cases:
        c = t.proto(*args, label=label)
        t.eq("[%s] exit code without --json" % label, c.rc, rc)
    for mode, rc in (("normal", 0), ("failure", 5), ("truncated", 5)):
        dd = t.ctx.new_dir("k12-agent")
        fa = H.FakeAgent(t.ctx.sandbox, dd, mode, mode, [k["pub"] for k in t.ctx.keys()])
        t.agents.append(fa)
        c = t.proto("agent", "list", "--socket", fa.sock, label="agent-" + mode)
        t.eq("[agent-%s] exit code without --json" % mode, c.rc, rc)
        fa.stop()


def wait_status_text(rc):
    """'exit N', 'signal SIGNAME' (death by signal) or None (no status: timed out)."""
    if rc is None:
        return None
    if rc < 0:
        try:
            return "signal " + signal.Signals(-rc).name
        except ValueError:
            return "signal %d" % -rc
    return "exit %d" % rc


# K12 closed stdout for ERROR results (round-4 harness review).  Q17 (contract section 9.4, owner ruling, harness
# 2.4.2): the closed-stdout parity covers failure results (exit 2/5) and usage errors too, so these cases are part of
# the GATING verdict of k12.closed_stdout_exit_parity (one assertion per case, after the three success-result
# cases); observations.k12_closed_stdout_errors still records the wait statuses.  Kept as a switch only so the
# record states which rule applied (observations.k12_closed_stdout_errors.gating).
K12_ERROR_RESULTS_GATING = True


def _k12_closed_run(t, label, args, agent_mode, missing_socket=None):
    """Run `args` with and without --json, stdout the write end of a pipe whose read end is already closed.
    Returns {"json": {...}, "plain": {...}}."""
    per = {}
    for variant in ("json", "plain"):
        argv = list(args)
        fa = None
        if agent_mode:
            fa = H.FakeAgent(t.ctx.sandbox, t.ctx.new_dir("k12c-agent"), agent_mode, agent_mode,
                             [k["pub"] for k in t.ctx.keys()])
            t.agents.append(fa)
            argv.append(fa.sock)
        elif missing_socket is not None:
            argv.append(str(missing_socket))
        if variant == "json":
            argv.append("--json")
        r, w = os.pipe()
        os.close(r)               # no reader exists before the program starts: the first write fails, no race
        try:
            c = t.proto(*argv, label="%s-%s-closed-stdout" % (label, variant), stdout_fd=w)
        finally:
            os.close(w)
            if fa:
                fa.stop()
        per[variant] = {"wait_status": wait_status_text(c.rc), "rc": c.rc}
    return per


@check("k12.closed_stdout_exit_parity", "§1/K12 closed stdout (contract section 9.4): version, profile show (valid fixture) and agent list (fake agent, normal mode) run with stdout the write end of a pipe whose read end was closed before the program started (deterministic EPIPE / SIGPIPE on the first write; SIGPIPE at its default disposition, as a shell starts a command); the wait status without --json equals the one with --json, death by signal included (which status is not specified). Error results on a closed stdout (profile show of a missing file and of a schema-invalid file, agent list on a missing socket, a usage error) are judged the same way and are GATING too (Q17, section 9.4: a --json error result that dies of SIGPIPE or EPIPE while the plain run exits 2 or 5 fails; wait statuses in observations.k12_closed_stdout_errors)")
def _(t):
    # environment fact behind 'deterministic': this harness's own write into such a pipe fails at once
    r, w = os.pipe()
    os.close(r)
    try:
        os.write(w, b"x")
        probe = "write succeeded"
    except BrokenPipeError:
        probe = "EPIPE"
    finally:
        os.close(w)
    t.precondition("harness precondition: a write into a pipe whose read end is closed fails with EPIPE (the "
                   "harness ignores SIGPIPE; the program under test starts with SIGPIPE at its default)",
                   probe == "EPIPE", "EPIPE", probe)
    cases = (("version", ["version"], None),
             ("profile-show-homelab", ["profile", "show", "--file", str(FIX / "homelab.toml")], None),
             ("agent-list-normal", ["agent", "list", "--socket"], "normal"))
    seen = {}
    for label, args, agent_mode in cases:
        per = _k12_closed_run(t, label, args, agent_mode)
        seen[label] = per
        t.check("[%s] stdout closed by its reader: the wait status without --json equals the one with --json"
                % label, per["json"]["rc"] is not None and per["plain"]["rc"] == per["json"]["rc"],
                per["json"]["wait_status"], per["plain"]["wait_status"])
    t.note("sigpipe_disposition_given_to_program", "default (subprocess restore_signals)")
    t.ctx.observations["k12_closed_stdout"] = seen
    # Error results (Q17, answered yes: section 9.4): the base K12 rule ("exit codes are the same as with --json")
    # covers them, common.exit_codes_without_json gates their exit 2/5 with a normal stdout, and section 9.4 extends
    # the rule to a closed stdout.  Same method as above; gating while K12_ERROR_RESULTS_GATING (True).
    d = t.ctx.new_dir("k12c-err")
    err_cases = (("profile-missing", ["profile", "show", "--file", str(d / "missing.toml")], None, None, 2),
                 ("profile-schema-invalid", ["profile", "show", "--file", str(FIX / "invalid-forbidden-key.toml")],
                  None, None, 2),
                 ("agent-unavailable", ["agent", "list", "--socket"], None, d / "none.sock", 5),
                 ("usage-unknown-flag", ["version", "--no-such-flag"], None, None, 2))
    errs = {}
    gate = K12_ERROR_RESULTS_GATING
    for label, args, agent_mode, sock, code in err_cases:
        per = _k12_closed_run(t, label, args, agent_mode, missing_socket=sock)
        per["equal"] = per["json"]["rc"] is not None and per["plain"]["rc"] == per["json"]["rc"]
        per["exit_code_with_open_stdout"] = code
        errs[label] = per
        t.check("[%s] error result, stdout closed by its reader: the wait status without --json equals the one with "
                "--json%s" % (label, "" if gate else " (non-gating observation)"), per["equal"],
                per["json"]["wait_status"], per["plain"]["wait_status"], gating=gate)
    t.ctx.observations["k12_closed_stdout_errors"] = {
        "gating": gate, "question": "Q17", "cases": errs,
        "all_equal": all(v["equal"] for v in errs.values())}


TRIPWIRE_NAMES = ("tmux", "tput", "infocmp", "stty", "sh", "bash", "ssh", "git")
TRIPWIRE_SRC = (
    "#!%(py)s\n"
    "import json, os, sys\n"
    "with open(%(log)r, 'a') as f:\n"
    "    f.write(json.dumps({'name': os.path.basename(sys.argv[0]), 'argv': sys.argv[1:8], 'ppid': os.getppid()}) + '\\n')\n"
    "sys.exit(1)\n")
K16_ENV = {"TMUX": "/tmp/tmux-1000/default,4242,0", "TMUX_PANE": "%1", "TERM_PROGRAM": "tmux",
           "TERM_PROGRAM_VERSION": "3.5a", "COLORTERM": "truecolor"}
K16_VARIANTS = [
    ("tmux-env", dict(K16_ENV, TERM="xterm-256color")),
    ("tmux-term", dict(K16_ENV, TERM="tmux-256color")),
    ("screen-term", {"TERM": "screen-256color", "STY": "4242.pts-0.hm", "WINDOW": "0"}),
    ("screen-plain", {"TERM": "screen"}),
]


@check("common.no_helper_processes", "§1/K16 apart from the run child, heimdall-proto never executes another program: tripwire tmux/tput/infocmp/stty/sh/bash/ssh/git on PATH (prepended; for run after the child's own directory) under four environments (TMUX/TERM_PROGRAM/COLORTERM with TERM=xterm-256color and TERM=tmux-256color; TERM=screen-256color with STY; TERM=screen), for version, profile show (ok, invalid), a usage error, agent list, tui and run", "pyte", budget=180)
def _(t):
    t.precondition("harness precondition: the python path has no spaces (tripwire shebang)", " " not in PY, "no spaces", PY)
    d = t.ctx.new_dir("k16")
    trip = d / "tripwire-bin"
    trip.mkdir()
    log = d / "tripwire.jsonl"
    for n in TRIPWIRE_NAMES:
        p = trip / n
        p.write_text(TRIPWIRE_SRC % {"py": PY, "log": str(log)})
        os.chmod(p, 0o755)
    probe = subprocess.run([str(trip / "tput"), "colors"], env={"PATH": "/usr/bin:/bin"}, capture_output=True, timeout=20)
    entries = [json.loads(x) for x in (_read_text(log) or "").splitlines() if x.strip()]
    t.precondition("harness precondition: a tripwire records its invocation and exits 1", probe.returncode == 1
            and [e.get("name") for e in entries] == ["tput"], "logged tput, exit 1",
            {"rc": probe.returncode, "names": [e.get("name") for e in entries]})
    log.write_text("")
    base_path = os.environ.get("PATH", "/usr/bin:/bin")
    seen = {"n": 0}
    hits = []

    def tripped(label):
        lines = [json.loads(x) for x in (_read_text(log) or "").splitlines() if x.strip()]
        new = lines[seen["n"]:]
        seen["n"] = len(lines)
        if new:
            hits.append({"invocation": label, "programs": [e.get("name") for e in new]})
        t.check("[%s] no helper program executed (tripwire log empty)" % label, not new, [],
                [{"name": e.get("name"), "argv": short(e.get("argv"), 120)} for e in new])

    childdir = d / "child-bin"
    childdir.mkdir()
    child = childdir / "hm-k16-child"
    child.write_text("#!%s\nimport sys\nsys.exit(0)\n" % PY)
    os.chmod(child, 0o755)
    # K16: "whatever TMUX, TERM, TERM_PROGRAM or similar variables say" - every invocation runs under each
    # variant (R3: TERM was fixed to xterm-256color before, so a TERM-triggered probe went unseen)
    for vname, venv in K16_VARIANTS:
        env = dict(venv, PATH="%s:%s" % (trip, base_path))
        t.result(t.proto("version", "--json", env=env, label="k16-%s-version" % vname), 0, "VERSION_OK", "succeeded")
        tripped("k16-%s-version" % vname)
        t.result(t.proto("profile", "show", "--file", str(FIX / "homelab.toml"), "--json", env=env,
                         label="k16-%s-profile-ok" % vname), 0, "PROFILE_OK", "succeeded")
        tripped("k16-%s-profile-ok" % vname)
        t.result(t.proto("profile", "show", "--file", str(FIX / "invalid-forbidden-key.toml"), "--json", env=env,
                         label="k16-%s-profile-invalid" % vname), 2, "SCHEMA_INVALID", "failed")
        tripped("k16-%s-profile-invalid" % vname)
        t.result(t.proto("frobnicate", "--json", env=env, label="k16-%s-usage-error" % vname), 2, "USAGE_ERROR",
                 "failed")
        tripped("k16-%s-usage-error" % vname)
        fa = H.FakeAgent(t.ctx.sandbox, t.ctx.new_dir("k16-agent"), "k16", "normal", [k["pub"] for k in t.ctx.keys()])
        t.agents.append(fa)
        t.result(t.proto("agent", "list", "--socket", fa.sock, "--json", env=env, label="k16-%s-agent-list" % vname),
                 0, "AGENT_OK", "succeeded")
        fa.stop()
        tripped("k16-%s-agent-list" % vname)
        s, _lat = start_tui(t, env=env)
        s.send("/")
        s.settle(0.1)
        s.send("nas")
        t.check("[k16-%s-tui] filter works under TERM=%s" % (vname, venv.get("TERM")),
                s.wait_for(has_status(1, 3), 5.0) is not None, "1/3", status_of(s))
        s.key("esc")
        s.settle(0.1)
        s.send("q")
        t.eq("[k16-%s-tui] q exits 0" % vname, s.wait_exit(3.0), 0)
        tripped("k16-%s-tui" % vname)
        meta = meta_path(t)
        c = t.proto("run", "--meta-file", str(meta), "--", "hm-k16-child", label="k16-%s-run" % vname,
                    cwd=t.ctx.run_cwd, env=dict(venv, PATH="%s:%s:%s" % (childdir, trip, base_path)))
        t.eq("[k16-%s-run] exit code is the child's (0)" % vname, c.rc, 0)
        tripped("k16-%s-run" % vname)
    t.note("k16_tripwire_hits", hits)
    t.ctx.observations["k16_tripwire_hits"] = hits


@check("common.no_stray_writes", "§1/K11 no new files in HOME, TMPDIR or the working directory after any invocation; fixtures unchanged")
def _(t):
    ctx = t.ctx
    t.check("K11: every invocation in this run left HOME, TMPDIR and its working directory without new files "
            "(%d invocations scanned; stray paths listed per check and invocation)" % ctx.invocations_scanned,
            not ctx.stray_hits, [], ctx.stray_hits)
    t.check("K11 scan covered at least one invocation", ctx.invocations_scanned > 0 or len(ctx.ran_ids) <= 1,
            "> 0", ctx.invocations_scanned)
    for name, d in (("working directory", ctx.cwd_ro), ("HOME", ctx.home), ("TMPDIR", ctx.tmp)):
        left = sorted(str(p.relative_to(d)) for p in d.rglob("*"))
        t.check("%s is still empty at the end of the run" % name, not left, [], left)
    t.eq("fixture directory unchanged (names, sizes, mtimes)", ctx.snapshot(FIX), ctx.fix_snapshot)


@check("canary.no_canary_anywhere", "§1 no HEIMDALL_CANARY_ in any captured stdout/stderr/meta/pty stream")
def _(t):
    hits = t.ctx.canary_hits
    t.check("scanned %d process captures, none contained the canary" % t.ctx.captures_total, not hits, "no hits", hits)


# ===== round-2 rulings (contract section 9.1) ==============================
RSS_WRAP = str(Path(__file__).resolve().parent / "rss_wrap.py")
MIB = 1024 * 1024


def _read_json(p):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_text(p):
    try:
        return Path(p).read_text(encoding="utf-8")
    except OSError:
        return None


def _session_leftovers(t, s, pids, label, gating=True):
    """After a pty session's job finished: which of `pids` (processes the check started) are still
    alive in the session the harness created?  They are SIGKILLed after that identity check."""
    pids = [p for p in pids if isinstance(p, int) and p > 0]
    alive = [p for p in pids if H.pid_in_session(p, s.shim.pid)]
    states = {p: H.proc_state(p) for p in alive}
    H.kill_session_pids(alive, s.shim.pid)
    t.check("[%s] no process of the job left behind (alive members are killed after an identity check)%s"
            % (label, "" if gating else " (non-gating observation)"), not alive, [], {"alive_pids_with_state": states},
            gating=gating)
    return alive


# -- K6a ------------------------------------------------------------------
K6A_CHILD = r'''
import os, sys, time
d = os.path.dirname(os.path.abspath(__file__))
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 1.5
def put(name, text):
    with open(os.path.join(d, name), "w") as f:
        f.write(text)
put("child.pid", "%d %d %d" % (os.getpid(), os.getppid(), os.getpgrp()))
put("child.ready", "1")
time.sleep(secs)
put("child.done", "1")
'''

K6A_PEER = r'''
import json, os, sys, time
d = os.path.dirname(os.path.abspath(__file__))
def put(name, obj):
    with open(os.path.join(d, name), "w") as f:
        f.write(json.dumps(obj))
put("peer.pid", os.getpid())
end = time.time() + 10
while not os.path.exists(os.path.join(d, "child.ready")) and time.time() < end:
    time.sleep(0.01)
time.sleep(0.3)
fd = os.open("/dev/tty", os.O_RDONLY)
info = {"pgrp": os.getpgrp(), "fg_before_read": os.tcgetpgrp(fd)}
put("peer.reading", info)
try:
    info["read"] = os.read(fd, 200).decode("utf-8", "replace")
except OSError as e:
    info["read_errno"] = e.errno
info["fg_after_read"] = os.tcgetpgrp(fd)
put("peer.result", info)
sys.stdin.buffer.read()          # the pipe from heimdall-proto: EOF once it and its child are gone
info["stdin_eof"] = True
put("peer.result", info)
'''

K6A_SCRIPT = r'''
import errno, json, os, signal, subprocess, sys, time
d, proto, py, variant = sys.argv[1:5]
res = {"variant": variant, "pgrp": os.getpgrp(), "fg0": os.tcgetpgrp(0)}
def pre():
    # what a non-interactive shell does for `cmd &`: same process group (no job control),
    # SIGINT and SIGQUIT ignored
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
stdin = subprocess.DEVNULL if variant == "stdin-devnull" else None
p = subprocess.Popen([proto, "run", "--", py, os.path.join(d, "c.py"), "1.0"], stdin=stdin, preexec_fn=pre)
end = time.time() + 10
while not os.path.exists(os.path.join(d, "child.ready")) and time.time() < end:
    time.sleep(0.01)
time.sleep(0.2)
res["fg1"] = os.tcgetpgrp(0)
signal.signal(signal.SIGTTIN, signal.SIG_IGN)   # a read from the background then fails with EIO instead of stopping
with open(os.path.join(d, "script.reading"), "w") as f:
    f.write("1")
try:
    res["read"] = os.read(0, 200).decode("utf-8", "replace")
except OSError as e:
    res["read_error"] = errno.errorcode.get(e.errno, str(e.errno))
res["fg_after_read"] = os.tcgetpgrp(0)
res["proto_rc"] = p.wait()
res["fg2"] = os.tcgetpgrp(0)
res["child_done"] = os.path.exists(os.path.join(d, "child.done"))
with open(os.path.join(d, "script.result"), "w") as f:
    f.write(json.dumps(res))
'''

K6A_IGN_CHILD = r"""
import json, os, signal, sys, time
d = sys.argv[1]
report = [n for n in sys.argv[2].split(",") if n]
count = [n for n in sys.argv[3].split(",") if n]
def put(name, obj):
    with open(os.path.join(d, name), "w") as f:
        f.write(json.dumps(obj))
def disp(h):
    return "SIG_IGN" if h == signal.SIG_IGN else "SIG_DFL" if h == signal.SIG_DFL else "handler"
rep = {"pid": os.getpid(), "ppid": os.getppid(),
       "getsignal": {n: disp(signal.getsignal(getattr(signal, n))) for n in report},
       "blocked": sorted(signal.Signals(s).name for s in signal.pthread_sigmask(signal.SIG_BLOCK, []))}
try:
    with open("/proc/self/status") as f:
        for line in f:
            for field, key in (("SigIgn:", "proc_sigign"), ("SigBlk:", "proc_sigblk")):
                if line.startswith(field):
                    mask = int(line.split()[1], 16)
                    rep[key] = {n: bool(mask >> (int(getattr(signal, n)) - 1) & 1) for n in report + ["SIGUSR2"]}
except OSError:
    pass
put("report1", rep)
# phase 1: no handler installed - a forwarded signal kills this process unless it is ignored
end = time.time() + 15
while not os.path.exists(os.path.join(d, "phase2")) and time.time() < end:
    time.sleep(0.01)
# phase 2: count deliveries; a signal heimdall-proto inherited as ignored must not be forwarded
r, w = os.pipe()
os.set_blocking(r, False)
os.set_blocking(w, False)
signal.set_wakeup_fd(w, warn_on_full_buffer=False)
for n in count:
    signal.signal(getattr(signal, n), lambda s, f: None)
put("armed", {"survived_phase1": True})
got = []
end = time.time() + 15
def drain():
    try:
        return [signal.Signals(b).name for b in os.read(r, 64)]
    except BlockingIOError:
        return []
while not os.path.exists(os.path.join(d, "stop")) and time.time() < end:
    time.sleep(0.01)
    got += drain()
time.sleep(0.05)
got += drain()
put("report2", {"phase2_deliveries": got})
sys.exit(0)
"""


@check("run.k6a_pipeline_peer_not_stopped", "§4/K6a `heimdall-proto run -- <child> | <peer that reads the tty>` as one job of an interactive job-control shell (bash -i in a pty): the peer keeps the terminal foreground and is never stopped (no SIGTTIN, no 'Stopped'); the pipeline completes", "pyte", budget=90)
def _(t):
    bash = "/bin/bash"
    t.precondition("harness precondition: %s is executable" % bash, os.access(bash, os.X_OK), "executable", bash)
    d = t.ctx.new_dir("k6a-pipe")
    (d / "c.py").write_text(K6A_CHILD)
    (d / "p.py").write_text(K6A_PEER)
    env = {"P": t.ctx.bin, "Y": PY, "D": str(d), "PS1": "HMPS1$ ", "HISTFILE": str(d / "bash-history"),
           "BASH_SILENCE_DEPRECATION_WARNING": "1"}
    s = t.pty([bash, "--norc", "--noprofile", "-i"], env=env, cwd=t.ctx.run_cwd, label="bash-i", stderr_tty=True)
    t.precondition("interactive bash printed its prompt", s.wait_for(lambda x: b"HMPS1$ " in bytes(x.raw), 10.0) is not None,
              "prompt", H.printable(bytes(s.raw)[-200:]))
    t.precondition("harness precondition: bash enabled job control (no 'no job control' notice)",
              b"no job control" not in bytes(s.raw), "job control on", H.printable(bytes(s.raw)[-200:]))
    mark = len(s.raw)
    s.send('"$P" run -- "$Y" "$D/c.py" 1.5 | "$Y" "$D/p.py"; echo "PIPE_DONE ${PIPESTATUS[*]}"\r')
    reading = _wait_file(d / "peer.reading", 10, s)
    t.check("the pipeline peer reached its tty read while heimdall-proto's child runs", reading, True, reading)
    if reading:
        s.settle(0.1)
        s.send("K6A-PEER-INPUT\r")
    done_re = re.compile(rb"PIPE_DONE (\d+) (\d+)")
    s.wait_for(lambda x: done_re.search(bytes(x.raw)[mark:]) is not None, 15.0)
    s.settle(0.3)
    out = bytes(s.raw)[mark:]
    m = done_re.search(out)
    peer = _read_json(d / "peer.result") or {}
    peer_pid = _read_json(d / "peer.pid")
    cp = (_read_text(d / "child.pid") or "").split()
    child_pid, proto_pid = (int(cp[0]), int(cp[1])) if len(cp) >= 2 else (None, None)
    peer_state = H.proc_state(peer_pid) if isinstance(peer_pid, int) and H.pid_in_session(peer_pid, s.shim.pid) else None
    t.check("the pipeline completed (shell printed PIPE_DONE with both exit statuses)", m is not None,
            "PIPE_DONE <rc> <rc>", H.printable(out[-300:]))
    if m:
        t.eq("pipeline exit statuses (heimdall-proto, peer); a stopped member shows 128+SIGTTIN", [m.group(1), m.group(2)],
             [b"0", b"0"])
    t.check("the shell never reported a stopped job", b"Stopped" not in out, "no 'Stopped'",
            "Stopped" if b"Stopped" in out else "none")
    t.check("the peer was not left in the stopped state", peer_state != "T", "not stopped", peer_state)
    t.eq("the peer's tty read returned the typed line (not stopped by SIGTTIN, no EIO)",
         [peer.get("read"), peer.get("read_errno")], ["K6A-PEER-INPUT\n", None])
    t.check("while heimdall-proto ran, the job's own process group owned the terminal foreground",
            peer.get("fg_before_read") is not None and peer.get("fg_before_read") == peer.get("pgrp"),
            "fg == peer pgrp", {k: peer.get(k) for k in ("pgrp", "fg_before_read", "fg_after_read")})
    t.check("the child ran to completion", (d / "child.done").exists(), True, (d / "child.done").exists())
    t.note("k6a_pipeline", {"peer": peer, "peer_state": peer_state,
                            "statuses": [x.decode() for x in m.groups()] if m else None})
    s.send("exit\r")
    s.wait_exit(3.0)
    _session_leftovers(t, s, [child_pid, proto_pid, peer_pid], "pipeline")


@check("run.k6a_background_script_tty", "§4/K6a a non-job-control script in a pty runs `heimdall-proto run -- <sleep 1> &` (same process group, SIGINT/SIGQUIT ignored, stdin the tty or /dev/null), then reads the tty itself: its read gets the typed line (no EIO) and the terminal foreground group never changes", "pyte", budget=90)
def _(t):
    for variant in ("stdin-tty", "stdin-devnull"):
        d = t.ctx.new_dir("k6a-bg-" + variant)
        (d / "c.py").write_text(K6A_CHILD)
        (d / "s.py").write_text(K6A_SCRIPT)
        s = t.pty([PY, str(d / "s.py"), str(d), t.ctx.bin, PY, variant], cwd=t.ctx.run_cwd, label="script-" + variant)
        reading = _wait_file(d / "script.reading", 10, s)
        t.check("[%s] the script reached its tty read while heimdall-proto's child runs" % variant, reading, True, reading)
        if reading:
            s.settle(0.1)
            s.send("K6A-SCRIPT-INPUT\r")
        rc = s.wait_exit(10.0)
        res = _read_json(d / "script.result") or {}
        t.eq("[%s] the script exited 0 (was never stopped)" % variant, rc, 0)
        t.eq("[%s] the script's tty read returned the typed line (no EIO)" % variant,
             [res.get("read"), res.get("read_error")], ["K6A-SCRIPT-INPUT\n", None])
        fg = {k: res.get(k) for k in ("pgrp", "fg0", "fg1", "fg_after_read", "fg2")}
        t.check("[%s] terminal foreground group unchanged before, during and after heimdall-proto (the script's own)"
                % variant, res.get("fg0") is not None and res.get("fg0") == res.get("pgrp")
                and res.get("fg1") == res.get("fg0") == res.get("fg_after_read") == res.get("fg2"), "all == pgrp", fg)
        t.eq("[%s] heimdall-proto exited with the child's status (0) and the child completed" % variant,
             [res.get("proto_rc"), res.get("child_done")], [0, True])
        t.note("k6a_background_%s" % variant, res)
        cp = (_read_text(d / "child.pid") or "").split()
        _session_leftovers(t, s, [int(x) for x in cp[:2]] if len(cp) >= 2 else [], variant)


# K6a with a child-initiated stop (harness 2.4.1, round-4 harness review rv_mirror_killpg): a launcher that reports
# its child's self-stop to the shell by stopping its whole process group (kill(0, SIGTSTP), the vim suspend idiom)
# stops the other members of its own job too.  Child: waits until the harness writes <tag>.go, then stops itself
# with SIGTSTP (OpenSSH's ~^Z); exits 0 once continued.  Peer: a job member that only waits.
K6AS_CHILD = r"""
import json, os, signal, sys, time
d, tag = sys.argv[1], sys.argv[2]
def put(name, text):
    p = os.path.join(d, tag + "." + name)
    with open(p + ".part", "w") as f:
        f.write(text)
    os.replace(p + ".part", p)
put("child.json", json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "pgrp": os.getpgrp()}))
end = time.monotonic() + 30
while not os.path.exists(os.path.join(d, tag + ".go")) and time.monotonic() < end:
    time.sleep(0.02)
put("stopping", "1")
os.kill(os.getpid(), signal.SIGTSTP)
put("resumed", "1")
"""
K6AS_PEER = r"""
import os, sys, time
d, tag = sys.argv[1], sys.argv[2]
with open(os.path.join(d, tag + ".peer.pid"), "w") as f:
    f.write(str(os.getpid()))
end = time.monotonic() + 60
while not os.path.exists(os.path.join(d, tag + ".end")) and time.monotonic() < end:
    time.sleep(0.05)
"""
K6AS_WINDOW_S = 4.0     # how long the other job member is watched: the 4 s run.k6e_child_self_stop allows for the
                        # stop notice (K6ES_NOTICE_S), so a launcher that reports the stop late is still observed
# (layout, command with {run} where heimdall-proto's `run --` goes, the other job member)
K6AS_LAYOUTS = (
    ("pipeline-first", '{run}"$Y" "$D/s.py" "$D" {tag} | "$Y" "$D/p.py" "$D" {tag}', "pipeline peer (after it)"),
    ("pipeline-last", '"$Y" "$D/p.py" "$D" {tag} | {run}"$Y" "$D/s.py" "$D" {tag}', "pipeline peer (before it)"),
    ("script", '/bin/sh -c \'echo $$ > "$D/{tag}.peer.pid"; {run}"$Y" "$D/s.py" "$D" {tag}; echo "K6AS_SCRIPT_RC=$?"\'',
     "the non-job-control `sh -c` script that started it"),
)


@check("run.k6a_child_self_stop_not_spread", "§4/K6a a child that stops ITSELF (kill(getpid(), SIGTSTP), OpenSSH's ~^Z) under `heimdall-proto run`, as a job of `bash -i` in a pty: however heimdall-proto reports the stop (section 9.4), it never stops another member of its own job - the pipeline peer after it, the pipeline peer before it, or the non-job-control `sh -c` script that started it; each other member is sampled for %.1f s after the child's self-stop and is never in the stopped state (a direct-exec control of each layout, in which the child stops alone, is a harness precondition)" % K6AS_WINDOW_S, "pyte", budget=150)
def _(t):
    bash = "/bin/bash"
    t.precondition("harness precondition: %s is executable" % bash, os.access(bash, os.X_OK), "executable", bash)
    d = t.ctx.new_dir("k6a-selfstop")
    (d / "s.py").write_text(K6AS_CHILD)
    (d / "p.py").write_text(K6AS_PEER)
    env = {"P": t.ctx.bin, "Y": PY, "D": str(d), "PS1": "HMPS1$ ", "HISTFILE": str(d / "bash-history"),
           "BASH_SILENCE_DEPRECATION_WARNING": "1"}
    seen = {}
    for layout, tmpl, member in K6AS_LAYOUTS:
        for via_proto in (False, True):
            tag = "%s-%s" % (layout, "hp" if via_proto else "ctl")
            lbl = "[%s, %s]" % (layout, "heimdall-proto" if via_proto else "direct-exec control")
            s = t.pty([bash, "--norc", "--noprofile", "-i"], env=env, cwd=t.ctx.run_cwd, label="k6as-" + tag,
                      stderr_tty=True)
            t.precondition("%s interactive bash printed its prompt" % lbl,
                           s.wait_for(lambda x: b"HMPS1$ " in bytes(x.raw), 10.0) is not None, "prompt",
                           H.printable(bytes(s.raw)[-200:]))
            t.precondition("%s harness precondition: bash enabled job control (no 'no job control' notice)" % lbl,
                           b"no job control" not in bytes(s.raw), "job control on", H.printable(bytes(s.raw)[-200:]))

            def judge(desc, ok, expected=None, observed=None, lbl=lbl, via_proto=via_proto):
                if via_proto:
                    return t.check("%s %s" % (lbl, desc), ok, expected, observed)
                return t.precondition("%s harness precondition: the direct-exec control behaves: %s" % (lbl, desc),
                                      ok, expected, observed)

            mark = len(s.raw)
            s.send(tmpl.format(run='"$P" run -- ' if via_proto else "", tag=tag) + "\r")
            up = _wait_file(d / (tag + ".child.json"), 10, s) and _wait_file(d / (tag + ".peer.pid"), 10, s)
            judge("the child and the other job member (%s) started" % member, up, True, up)
            ids = _read_json(d / (tag + ".child.json")) or {}
            child, parent = ids.get("pid"), ids.get("ppid")
            try:
                peer = int((_read_text(d / (tag + ".peer.pid")) or "0").strip() or 0)
            except ValueError:
                peer = 0
            pids = [x for x in (child, parent if via_proto else None, peer) if isinstance(x, int) and x > 0]
            s.settle(0.3)
            (d / (tag + ".go")).write_text("1")
            stopping = _wait_file(d / (tag + ".stopping"), 5, s)
            judge("the child reached its self-stop (kill(getpid(), SIGTSTP))", stopping, True, stopping)
            samples, stopped_at = 0, None
            t0 = time.monotonic()
            while time.monotonic() - t0 < K6AS_WINDOW_S:
                st = H.proc_state(peer) if peer and H.pid_in_session(peer, s.shim.pid) else None
                samples += 1
                if st == "T" and stopped_at is None:
                    stopped_at = round(time.monotonic() - t0, 2)
                s.pump(0.1)
            out = bytes(s.raw)[mark:]
            info = {"member": member, "peer_stopped_after_s": stopped_at, "samples": samples,
                    "child_state": H.proc_state(child) if isinstance(child, int) else None,
                    "heimdall_proto_state": H.proc_state(parent) if via_proto and isinstance(parent, int) else None,
                    "shell_reported_stop": b"Stopped" in out}
            seen[tag] = info
            judge("the other member of the job (%s) is never stopped within %.1f s of the child's self-stop (K6a: "
                  "only the job's own stop may stop it)" % (member, K6AS_WINDOW_S), stopped_at is None,
                  "never in state T", {"first_seen_stopped_after_s": stopped_at, "samples": samples})
            # release the job: the peer ends by itself; the stopped processes are continued (identity-checked pids)
            (d / (tag + ".end")).write_text("1")
            for x in pids:
                if H.pid_in_session(x, s.shim.pid):
                    try:
                        os.kill(x, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
            end = time.monotonic() + 5
            while time.monotonic() < end and any(H.pid_in_session(x, s.shim.pid) for x in pids):
                s.pump(0.05)
            H.kill_session_pids(pids, s.shim.pid)
            s.send("exit\r")
            s.settle(0.3)
            s.send("exit\r")
            s.wait_exit(3.0)
    t.ctx.observations["k6a_child_self_stop"] = seen
    t.note("k6a_child_self_stop", seen)


def _ignore_and_block_preexec(ignore, block):
    def pre():
        for s_ in ignore:
            signal.signal(s_, signal.SIG_IGN)
        if block:
            signal.pthread_sigmask(signal.SIG_BLOCK, block)
    return pre


# (variant, signals heimdall-proto inherits as SIG_IGN, signals sent to it, signals blocked when it starts, gated)
# K6c: the inherited-ignore requirement gates SIGHUP (nohup) and SIGINT (non-interactive & job) only; other
# inherited ignores (SIGQUIT, SIGTERM, SIGWINCH, SIGPIPE) and the blocked mask are recorded, not gated.
K6A_IGNORE_VARIANTS = [
    ("nohup", ["SIGHUP"], ["SIGHUP"], [], True),
    ("async-job", ["SIGINT", "SIGQUIT"], ["SIGINT"], [], True),
    # SIGPIPE is not in this (CPython) variant: CPython sets SIGPIPE to SIG_IGN itself at start-up, so a Python
    # child reports SIG_IGN whatever it inherited (the round-2 review's finding).  The inherited SIGPIPE ignore is
    # observed with a non-Python child instead (_k6c_sigpipe_probe).
    ("other-ignores-K6c", ["SIGQUIT", "SIGTERM", "SIGWINCH"], [], ["SIGUSR2"], False),
]


# K6c SIGPIPE observation (round 3): the child must not be CPython (it ignores SIGPIPE itself at start-up).
# The wrapper runs ARGV with SIGPIPE ignored or default, its stdout a pipe whose read end it closes after
# the first bytes, and reports how ARGV ended.  `yes` then either dies of SIGPIPE (default disposition) or
# gets EPIPE and exits 1 (ignored): the disposition shows as behaviour on every OS.
PIPE_CLOSER = r"""
import json, os, signal, subprocess, sys
report, mode, argv = sys.argv[1], sys.argv[2], sys.argv[3:]
r, w = os.pipe()
def pre():
    signal.signal(signal.SIGPIPE, signal.SIG_IGN if mode == "ignore" else signal.SIG_DFL)
p = subprocess.Popen(argv, stdout=w, preexec_fn=pre)
os.close(w)
got = os.read(r, 4096)
os.close(r)
try:
    rc = p.wait(timeout=10)
except subprocess.TimeoutExpired:
    p.kill()
    rc = "timeout"
    p.wait()
with open(report, "w") as f:
    f.write(json.dumps({"rc": rc, "read_bytes": len(got)}))
"""


def _sigign_bit(status_text, signum):
    for line in (status_text or "").splitlines():
        if line.startswith("SigIgn:"):
            try:
                return bool(int(line.split()[1], 16) >> (signum - 1) & 1)
            except (IndexError, ValueError):
                return None
    return None


K6C_SIGPIPE_CLASSES = {
    "inherited_disposition_kept": "exec semantics: the child keeps the SIGPIPE disposition heimdall-proto inherited "
                                  "(ignored -> EPIPE exit 1, default -> killed by SIGPIPE)",
    "child_always_default": "the inherited SIGPIPE ignore is reset: the child dies of SIGPIPE in both variants",
    "child_always_ignores": "every child runs with SIGPIPE ignored, also when heimdall-proto inherited the default "
                            "disposition (the runtime's own ignore leaks into the child)",
    "other": "neither pattern (see via_heimdall_proto)",
    "probe_invalid": "a probe precondition did not hold on this host; nothing is concluded",
}


def _k6c_sigpipe_probe(t):
    """Non-gating K6c observation: which SIGPIPE disposition does a non-Python run child get, for each disposition
    heimdall-proto inherited (ignored, default)?  Classified as one of K6C_SIGPIPE_CLASSES; only
    'inherited_disposition_kept' sets inherited_sigpipe_ignore_kept.  The probe's own preconditions (a `yes` on
    PATH that, run directly, dies of SIGPIPE with the default disposition and exits 1 with SIGPIPE ignored) are
    recorded as non-gating: K6c is non-gating, so an invalid probe never fails or errors the enclosing gated
    K6a check; it yields classification 'probe_invalid'."""
    import signal as sg
    mut = t.ctx.harness_mutate
    yes = None if "k6c_probe_no_yes" in mut else shutil.which("yes", path=t.ctx.env()["PATH"])
    out = {"probe": "yes writing into a pipe whose reader closes", "yes": yes}

    def invalid(desc, expected, observed):
        t.check("K6c SIGPIPE probe precondition (non-gating; probe invalid, nothing concluded): " + desc, False,
                expected, observed, gating=False)
        out.update(classification="probe_invalid", inherited_sigpipe_ignore_kept=None, probe_invalid_reason=desc)
        t.note("k6c_sigpipe", out)
        return out

    if yes is None:
        return invalid("a `yes` executable is on PATH", "found", yes)
    d = t.ctx.new_dir("k6c-sigpipe")
    direct = {}
    for mode in ("default", "ignore"):
        rep = d / ("direct-%s.json" % mode)
        cap = H.run_capture("direct-yes-" + mode, [PY, "-c", PIPE_CLOSER, str(rep), mode, yes], t.ctx.env(),
                            str(t.ctx.run_cwd), timeout=20)
        t._record_cap(cap)
        direct[mode] = (_read_json(rep) or {}).get("rc")
    out["direct"] = direct
    if [direct.get("default"), direct.get("ignore")] != [-sg.SIGPIPE, 1]:
        return invalid("run directly, `yes` dies of SIGPIPE with the default disposition (-13) and exits 1 (EPIPE) "
                       "with SIGPIPE ignored", [-sg.SIGPIPE, 1], [direct.get("default"), direct.get("ignore")])
    t.check("K6c SIGPIPE probe precondition (non-gating): run directly, `yes` dies of SIGPIPE with the default "
            "disposition (-13) and exits 1 (EPIPE) with SIGPIPE ignored", True, [-sg.SIGPIPE, 1],
            [direct.get("default"), direct.get("ignore")], gating=False)
    via = {}
    for mode in ("default", "ignore"):
        rep = d / ("via-%s.json" % mode)
        meta = d / ("meta-%s.json" % mode)
        t.proto("run", "--meta-file", str(meta), "--", yes, label="via-proto-yes-" + mode, cwd=t.ctx.run_cwd,
                wrap=[PY, "-c", PIPE_CLOSER, str(rep), mode], timeout=20)
        m = _read_json(meta) or {}
        md = m.get("data") if isinstance(m.get("data"), dict) else {}
        via[mode] = {"proto_rc": (_read_json(rep) or {}).get("rc"), "child_exit_code": md.get("exit_code"),
                     "child_signal": md.get("signal")}
    out["via_heimdall_proto"] = via

    def ended(v):
        if v["child_signal"] is None and v["child_exit_code"] == 1:
            return "epipe_exit_1"           # SIGPIPE ignored in the child
        if v["child_signal"] == int(sg.SIGPIPE) and v["child_exit_code"] is None:
            return "killed_by_sigpipe"      # SIGPIPE default in the child
        return "other"

    pattern = (ended(via["ignore"]), ended(via["default"]))
    cls = {("epipe_exit_1", "killed_by_sigpipe"): "inherited_disposition_kept",
           ("killed_by_sigpipe", "killed_by_sigpipe"): "child_always_default",
           ("epipe_exit_1", "epipe_exit_1"): "child_always_ignores"}.get(pattern, "other")
    out["classification"] = cls
    out["classification_meaning"] = K6C_SIGPIPE_CLASSES[cls]
    # kept only when the ignore variant keeps the ignore AND the default variant keeps the default: a child that
    # ignores SIGPIPE whatever heimdall-proto inherited is not "keeping an inherited ignore" (round-3 review)
    out["inherited_sigpipe_ignore_kept"] = cls == "inherited_disposition_kept"
    t.check("K6c observation (non-gating): the `yes` child keeps the SIGPIPE disposition heimdall-proto inherited - "
            "SIGPIPE ignored -> EPIPE, exit 1; SIGPIPE default -> killed by SIGPIPE (classification %s)" % cls, True,
            {"ignore": "epipe_exit_1", "default": "killed_by_sigpipe"},
            {"ignore": dict(via["ignore"], ended=pattern[0]), "default": dict(via["default"], ended=pattern[1])},
            gating=False)
    if platform.system() == "Linux":
        cat = "/bin/cat"
        bits = {}
        for mode, ign in (("ignore", [sg.SIGPIPE]), ("default", [])):
            c = t.proto("run", "--", cat, "/proc/self/status", label="via-proto-cat-status-" + mode, cwd=t.ctx.run_cwd,
                        preexec_fn=_ignore_and_block_preexec(ign, []))
            bits[mode] = _sigign_bit(c.stdout.decode("utf-8", "replace"), int(sg.SIGPIPE))
        out["linux_proc_sigign_sigpipe_in_child"] = bits["ignore"]
        out["linux_proc_sigign_sigpipe_in_child_default"] = bits["default"]
        t.check("K6c observation (non-gating): /proc/self/status SigIgn of a non-Python run child has SIGPIPE set "
                "exactly when heimdall-proto inherited it as ignored", True, {"ignore": True, "default": False}, bits,
                gating=False)
    t.note("k6c_sigpipe", out)
    return out


@check("run.k6a_inherited_ignore", "§4/K6a a signal heimdall-proto inherited as ignored stays SIG_IGN in the child and is not forwarded; heimdall-proto survives it. Gated (K6c): SIGHUP (nohup) and SIGINT (non-interactive & job, started with SIGINT+SIGQUIT ignored). Recorded, not gated: SIGQUIT, SIGTERM, SIGWINCH ignores and the blocked mask (CPython child) and the SIGPIPE ignore (non-Python `yes`/`cat` child)", budget=120)
def _(t):
    import signal as sg
    k6c = {}
    for variant, ignored, send, blocked, gated in K6A_IGNORE_VARIANTS:
        sigs = [getattr(sg, n) for n in send]
        d = t.ctx.new_dir("k6a-ign-" + variant)
        (d / "c.py").write_text(K6A_IGN_CHILD)
        flow = {}

        def pre(proc, d=d, sigs=sigs, flow=flow):
            end = time.monotonic() + 10
            while not (d / "report1").exists():
                if proc.poll() is not None or time.monotonic() > end:
                    raise RuntimeError("child never reported its signal dispositions")
                time.sleep(0.01)
            for s_ in sigs:                       # phase 1: the child has no handler
                os.kill(proc.pid, s_)
                time.sleep(0.15)
            if sigs:
                time.sleep(0.4)
            flow["proto_alive_after_phase1"] = proc.poll() is None
            (d / "phase2").write_text("1")
            end = time.monotonic() + 5
            while not (d / "armed").exists() and proc.poll() is None and time.monotonic() < end:
                time.sleep(0.01)
            for s_ in sigs:                       # phase 2: the child counts deliveries
                if proc.poll() is None:
                    os.kill(proc.pid, s_)
                    time.sleep(0.15)
            if sigs:
                time.sleep(0.4)
            (d / "stop").write_text("1")

        c = t.proto("run", "--", PY, str(d / "c.py"), str(d), ",".join(ignored), ",".join(send),
                    label="ignored-" + variant, cwd=t.ctx.run_cwd, pre=pre, timeout=30,
                    preexec_fn=_ignore_and_block_preexec([getattr(sg, n) for n in ignored],
                                                         [getattr(sg, n) for n in blocked]))
        r1 = _read_json(d / "report1") or {}
        armed = _read_json(d / "armed")
        r2 = _read_json(d / "report2") or {}
        disp = r1.get("getsignal") or {}
        if gated:
            t.eq("[%s] heimdall-proto exited 0 (child's status: neither it nor the child died of the signal)" % variant,
                 c.rc, 0)
            t.check("[%s] heimdall-proto still alive after the signal(s) of phase 1" % variant,
                    flow.get("proto_alive_after_phase1") is True, True, flow.get("proto_alive_after_phase1"))
            t.eq("[%s] child's inherited disposition (signal.getsignal at start) is SIG_IGN for %s" % (variant, send),
                 {n: disp.get(n) for n in send}, {n: "SIG_IGN" for n in send})
            if platform.system() == "Linux":
                t.eq("[%s] child's /proc/self/status SigIgn mask has %s set" % (variant, send),
                     {n: (r1.get("proc_sigign") or {}).get(n) for n in send}, {n: True for n in send})
            t.check("[%s] child survived the signal(s) sent to heimdall-proto while it had no handler" % variant,
                    bool(armed and armed.get("survived_phase1")), True, armed)
            t.eq("[%s] signal(s) sent to heimdall-proto while the child had handlers were not forwarded" % variant,
                 r2.get("phase2_deliveries"), [])
            t.eq("[%s] heimdall-proto wrote nothing to stdout" % variant, c.stdout, b"")
        ungated = [n for n in ignored if n not in send]
        if ungated or blocked:
            seen = {n: disp.get(n) for n in ungated}
            kept_block = [n for n in blocked if n in (r1.get("blocked") or [])]
            t.check("[%s] K6c observation (non-gating): child's disposition of the other inherited ignores %s and "
                    "whether the inherited blocked signals %s stay blocked" % (variant, ungated, blocked), True,
                    {"dispositions": {n: "SIG_IGN" for n in ungated}, "still_blocked": blocked},
                    {"dispositions": seen, "still_blocked": kept_block, "proto_exit": c.rc}, gating=False)
            k6c[variant] = {"dispositions": seen, "inherited_blocked": blocked, "still_blocked": kept_block,
                            "proto_exit": c.rc}
        t.note("k6a_ignore_%s" % variant, {"report1": r1, "report2": r2, "flow": flow})
    k6c["sigpipe-non-python"] = _k6c_sigpipe_probe(t)
    t.ctx.observations["k6c_other_inherited_signal_state"] = k6c


# -- K6d / K6e (contract section 9.3, round 3) --------------------------------
K6D_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH")

# Child for K6d: counts deliveries of the five forwarded signals with the wakeup fd (one byte per delivery),
# reports its pid/ppid/pgrp and whether stdin/stdout are pipes, and exits 7 once the harness writes `stop`.
K6D_CHILD = r'''
import json, os, signal, stat, sys, time
d = sys.argv[1]
r, w = os.pipe()
os.set_blocking(r, False)
os.set_blocking(w, False)
signal.set_wakeup_fd(w, warn_on_full_buffer=False)
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
    signal.signal(s, lambda n, f: None)
def put(name, text):
    p = os.path.join(d, name)
    with open(p + ".part", "w") as f:
        f.write(text)
    os.replace(p + ".part", p)
def piped(fd):
    try:
        m = os.fstat(fd).st_mode
        return stat.S_ISFIFO(m) or stat.S_ISSOCK(m)
    except OSError:
        return None
put("ready", json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "pgrp": os.getpgrp(),
                         "stdin_pipe": piped(0), "stdout_pipe": piped(1)}))
got = []
def drain():
    try:
        data = os.read(r, 256)
    except BlockingIOError:
        return False
    got.extend(signal.Signals(b).name for b in data)
    put("signals", "".join(x + "\n" for x in got))
    return bool(data)
end = time.time() + 30
while time.time() < end and not os.path.exists(os.path.join(d, "stop")):
    time.sleep(0.01)
    drain()
time.sleep(0.05)
drain()
os._exit(7)
'''

# First member of the "heimdall-proto last" pipeline: keeps the job's process group populated until `stop` and
# reports its pid/pgrp (peer.json: the harness precondition that the pipeline job holds the terminal foreground).
K6D_FEEDER = r'''
import json, os, sys, time
d = sys.argv[1]
p = os.path.join(d, "peer.json")
with open(p + ".part", "w") as f:
    f.write(json.dumps({"pid": os.getpid(), "pgrp": os.getpgrp()}))
os.replace(p + ".part", p)
end = time.time() + 30
while time.time() < end and not os.path.exists(os.path.join(d, "stop")):
    time.sleep(0.01)
'''


# Last member of the "heimdall-proto first" pipeline (a `cat` that reports its pid/pgrp, see K6D_FEEDER).
K6D_SINK = r'''
import json, os, sys
d = sys.argv[1]
p = os.path.join(d, "peer.json")
with open(p + ".part", "w") as f:
    f.write(json.dumps({"pid": os.getpid(), "pgrp": os.getpgrp()}))
os.replace(p + ".part", p)
while os.read(0, 65536):
    pass
'''


def _tcgetpgrp(fd):
    try:
        return os.tcgetpgrp(fd)
    except OSError:
        return None


def _getpgid(pid):
    try:
        return os.getpgid(pid)
    except (OSError, TypeError):
        return None


def _k6d_deliver(t, s, d, signame, tag):
    """Wait for the K6d child, send `signame` explicitly to heimdall-proto's PID (the child's parent, after
    an identity check that it is a live member of the harness's terminal session), wait for the delivery
    and release the child.  Returns the setup facts (or None when the child never started)."""
    sig = getattr(signal, signame)
    if not _wait_file(d / "ready", 10, s):
        t.check("[%s] the child started under heimdall-proto" % tag, False, "ready", {"wait_status": s.poll()})
        (d / "stop").write_text("1")
        return None
    info = _read_json(d / "ready") or {}
    proto = info.get("ppid")
    alive = isinstance(proto, int) and proto > 1 and H.pid_in_session(proto, s.shim.pid)
    t.check("[%s] the child's parent (heimdall-proto) is still alive in the terminal session the harness created "
            "(it waits for its child)" % tag, alive, True, {"ppid": proto})
    setup = dict(info, proto_pid=proto, proto_pgrp=_getpgid(proto), fg_pgrp=_tcgetpgrp(s.master),
                 job_leader_pgrp=_getpgid(s.pid))
    if "k6d_env_not_shared" in t.ctx.harness_mutate:
        setup["fg_pgrp"] = -1              # selftest: simulate a layout whose job does not hold the foreground
    if not alive:
        (d / "stop").write_text("1")
        return setup
    s.settle(0.1)
    os.kill(proto, sig)                    # explicit: kill(<heimdall-proto pid>, sig), never the group
    end = time.monotonic() + 3.0
    while time.monotonic() < end and signame not in _read_lines(d / "signals"):
        s.pump(0.01)
    s.settle(0.3)                          # late duplicates are counted too (K6b allows them)
    (d / "stop").write_text("1")
    return setup


@check("run.k6d_shared_mode_explicit_signals", "§4/K6d heimdall-proto sharing its process group with the terminal's foreground job (child of a foreground non-job-control `sh -c` script; first and last member of a `bash -i` pipeline job): SIGINT, SIGTERM, SIGHUP, SIGQUIT and SIGWINCH sent explicitly to the heimdall-proto pid each reach the child at least once (count recorded; duplicates allowed, K6b; silent loss fails); exit statuses are the child's", "pyte", budget=240)
def _(t):
    deliveries = {}
    setups = {}
    env_bad = []
    # (1) a foreground non-job-control script (`sh -c`, like a Makefile recipe): heimdall-proto is in sh's group
    for signame in K6D_SIGNALS:
        tag = "sh-c/" + signame
        d = t.ctx.new_dir("k6d-sh-" + signame.lower())
        (d / "c.py").write_text(K6D_CHILD)
        script = '"$P" run -- "$Y" "$D/c.py" "$D"; echo "RC=$?" > "$D/rc"'
        s = t.pty(["/bin/sh", "-c", script], env={"P": t.ctx.bin, "Y": PY, "D": str(d)}, cwd=t.ctx.run_cwd,
                  label="sh-c-" + signame.lower())
        setup = _k6d_deliver(t, s, d, signame, tag)
        rc = s.wait_exit(10.0)
        sigs = _read_lines(d / "signals")
        rcf = (_read_text(d / "rc") or "").strip()
        t.check("[%s] the child received the signal sent explicitly to heimdall-proto at least once, and no other "
                "signal" % tag, len(sigs) >= 1 and set(sigs) == {signame}, ">= 1 x %s" % signame, sigs)
        t.eq("[%s] heimdall-proto exited with the child's status (the script saw RC=7) and the script exited 0" % tag,
             [rcf, rc], ["RC=7", 0])
        deliveries.setdefault("sh-c", {})[signame] = len(sigs)
        if setup:
            # harness precondition (environment): the script's process group holds the terminal foreground
            setup["env_foreground"] = setup.get("job_leader_pgrp") is not None and \
                setup.get("fg_pgrp") == setup.get("job_leader_pgrp")
            # candidate fact: heimdall-proto stayed in that group (shared mode as K6d describes it)
            setup["shared"] = setup["env_foreground"] and setup.get("proto_pgrp") == setup.get("job_leader_pgrp")
            setups[tag] = setup
            env_bad += [] if setup["env_foreground"] else [tag]
            t.check("[%s] setup (non-gating observation): heimdall-proto is in the script's process group, which holds "
                    "the terminal foreground (shared mode)" % tag, True, True, setup["shared"], gating=False)
        cp = [x for x in ((setup or {}).get("pid"), (setup or {}).get("proto_pid")) if isinstance(x, int)]
        _session_leftovers(t, s, cp, tag)
    # (2)/(3) members of a pipeline job of an interactive job-control shell
    bash = "/bin/bash"
    t.precondition("harness precondition: %s is executable" % bash, os.access(bash, os.X_OK), "executable", bash)
    for layout in ("pipeline-first", "pipeline-last"):
        base = t.ctx.new_dir("k6d-" + layout)
        env = {"P": t.ctx.bin, "Y": PY, "PS1": "HMPS1$ ", "HISTFILE": str(base / "bash-history"),
               "BASH_SILENCE_DEPRECATION_WARNING": "1"}
        s = t.pty([bash, "--norc", "--noprofile", "-i"], env=env, cwd=t.ctx.run_cwd, label="bash-i-" + layout,
                  stderr_tty=True)
        t.precondition("[%s] interactive bash printed its prompt" % layout,
                  s.wait_for(lambda x: b"HMPS1$ " in bytes(x.raw), 10.0) is not None, "prompt",
                  H.printable(bytes(s.raw)[-200:]))
        t.precondition("[%s] harness precondition: bash enabled job control" % layout, b"no job control" not in bytes(s.raw),
                  "job control on", H.printable(bytes(s.raw)[-200:]))
        pids = []
        for signame in K6D_SIGNALS:
            tag = "%s/%s" % (layout, signame)
            d = t.ctx.new_dir("k6d-%s-%s" % (layout, signame.lower()))
            (d / "c.py").write_text(K6D_CHILD)
            (d / "w.py").write_text(K6D_FEEDER)
            q = shlex.quote
            if layout == "pipeline-first":
                (d / "sink.py").write_text(K6D_SINK)
                cmd = '"$P" run -- "$Y" %s %s | "$Y" %s %s; echo "K6D_DONE ${PIPESTATUS[*]}"' % (
                    q(str(d / "c.py")), q(str(d)), q(str(d / "sink.py")), q(str(d)))
                want = [b"7", b"0"]
            else:
                cmd = '"$Y" %s %s | "$P" run -- "$Y" %s %s; echo "K6D_DONE ${PIPESTATUS[*]}"' % (
                    q(str(d / "w.py")), q(str(d)), q(str(d / "c.py")), q(str(d)))
                want = [b"0", b"7"]
            mark = len(s.raw)
            s.send(cmd + "\r")
            setup = _k6d_deliver(t, s, d, signame, tag)
            done_re = re.compile(rb"K6D_DONE (\d+) (\d+)")
            s.wait_for(lambda x: done_re.search(bytes(x.raw)[mark:]) is not None, 10.0)
            s.settle(0.1)
            m = done_re.search(bytes(s.raw)[mark:])
            sigs = _read_lines(d / "signals")
            t.check("[%s] the child received the signal sent explicitly to heimdall-proto at least once, and no other "
                    "signal" % tag, len(sigs) >= 1 and set(sigs) == {signame}, ">= 1 x %s" % signame, sigs)
            t.eq("[%s] pipeline exit statuses (the heimdall-proto member exits with the child's 7)" % tag,
                 list(m.groups()) if m else None, want)
            deliveries.setdefault(layout, {})[signame] = len(sigs)
            if setup:
                peer = _read_json(d / "peer.json") or {}
                setup["peer_pgrp"] = peer.get("pgrp")
                setup["shell_pgrp"] = setup.get("job_leader_pgrp")       # s.pid is the interactive bash here
                # harness precondition (environment): the pipeline job (its other member) holds the terminal
                # foreground, not the interactive shell
                setup["env_foreground"] = setup.get("peer_pgrp") is not None and \
                    setup.get("fg_pgrp") == setup.get("peer_pgrp") and setup.get("fg_pgrp") != setup.get("shell_pgrp")
                pipe = setup.get("stdout_pipe") if layout == "pipeline-first" else setup.get("stdin_pipe")
                setup["shared"] = setup["env_foreground"] and bool(pipe) and \
                    setup.get("proto_pgrp") == setup.get("peer_pgrp")
                setups[tag] = setup
                env_bad += [] if setup["env_foreground"] else [tag]
                t.check("[%s] setup (non-gating observation): heimdall-proto is a pipeline member whose process group "
                        "holds the terminal foreground (shared mode)" % tag, True, True, setup["shared"], gating=False)
                pids += [x for x in (setup.get("pid"), setup.get("proto_pid")) if isinstance(x, int)]
            if not m:
                break
        s.send("exit\r")
        s.wait_exit(3.0)
        _session_leftovers(t, s, pids, layout)
    t.check("K6d delivery counts per layout and signal (non-gating observation; duplicates are allowed by K6b)", True,
            ">= 1 each", deliveries, gating=False)
    t.note("k6d_setups", setups)
    t.ctx.observations["k6d_shared_mode_deliveries"] = deliveries
    t.ctx.observations["k6d_shared_setups"] = {k: {"env_foreground": v.get("env_foreground"), "shared": v.get("shared")}
                                               for k, v in setups.items()}
    # Without the layout the check would pass on delivery alone and never test shared mode (a silent skip):
    # the job holding the terminal foreground is a harness precondition (outcome 'error', evidence invalid).
    t.precondition("harness precondition: in every K6d layout run the job that contains heimdall-proto holds the "
                   "terminal foreground (sh -c: the script's group; pipelines: the other member's group, not the "
                   "shell's)", not env_bad, "all %d setups" % len(setups), {"not_in_foreground": env_bad})


# Child for K6e: N rounds of (A) a blocking terminal read, (B) a heartbeat loop (no terminal access) until the
# harness writes go-b.<i>, then another blocking terminal read.  Every line read is appended to `got`.
K6E_CHILD = r'''
import json, os, sys, time
d, n = sys.argv[1], int(sys.argv[2])
def put(name, text):
    p = os.path.join(d, name)
    with open(p + ".part", "w") as f:
        f.write(text)
    os.replace(p + ".part", p)
put("child.json", json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "pgrp": os.getpgrp()}))
got = []
def take():
    got.append(os.read(0, 4096).decode("utf-8", "replace"))
    put("got", json.dumps(got))
beat = 0
for i in range(1, n + 1):
    put("ready-a.%d" % i, "1")
    take()
    put("wait-b.%d" % i, "1")
    while not os.path.exists(os.path.join(d, "go-b.%d" % i)):
        beat += 1
        put("beat", str(beat))
        time.sleep(0.02)
    put("ready-b.%d" % i, "1")
    take()
put("done", "1")
sys.exit(0)
'''
K6E_ITERATIONS = 5
# After every `fg` the job must stay un-stopped for at least this long (checked before the next step; K6e "never
# re-stopped right after fg").  The round-3 review's re-stop came 700 ms after `fg`; 1.5 s covers it with margin.
K6E_RESTOP_WINDOW_S = 1.5
# The run job as a simple command, and inside a command list (`run ...; echo`): the round-2 Go review saw the
# re-stop after `fg` with the list form on Linux (bash continues a list when its job stops).
K6E_FORMS = (("simple", '"$P" run -- "$Y" "$D/c.py" "$D" %d'),
             ("list", '"$P" run -- "$Y" "$D/c.py" "$D" %d; echo "K6E_LIST_RC=$?"'))
K6E_SHELLS = {
    # name: (argv, environment additions, job-stopped notice, expression for the number of jobs left)
    "bash": (["/bin/bash", "--norc", "--noprofile", "-i"], {"BASH_SILENCE_DEPRECATION_WARNING": "1"}, b"Stopped",
             "$(jobs -p | wc -l)"),
    "zsh": (["/bin/zsh", "-f", "-i"], {}, b"suspended", "${#jobstates}"),
}


def _k6e_form(t, form, cmdline, shell="bash", gate=True):
    """One K6e form under `shell`.  gate=False (zsh, round-3 coverage addition pending a gating decision): every
    assertion is a non-gating observation and a missing/unsuitable shell ends the form without an error."""
    argv, env_extra, stopw, jobs_expr = K6E_SHELLS[shell]
    ftag = form if shell == "bash" else "%s %s" % (shell, form)

    def chk(desc, ok, expected=None, observed=None):
        return t.check(desc if gate else "%s (non-gating observation)" % desc, ok, expected, observed, gating=gate)

    def chk_eq(desc, observed, expected):
        return chk(desc, observed == expected, expected, observed)

    def pre(desc, ok, expected, observed):
        if gate:
            return t.precondition(desc, ok, expected, observed)
        if not ok:
            t.check("%s (non-gating; form not run)" % desc, False, expected, observed, gating=False)
        return ok

    d = t.ctx.new_dir("k6e-" + ftag.replace(" ", "-"))
    (d / "c.py").write_text(K6E_CHILD)
    if not pre("[%s] harness precondition: %s is executable" % (ftag, argv[0]), os.access(argv[0], os.X_OK),
               "executable", argv[0]):
        return {"shell": shell, "ok": None, "not_run": "%s not executable" % argv[0]}
    env = dict({"P": t.ctx.bin, "Y": PY, "D": str(d), "PS1": "HMPS1$ ", "HISTFILE": str(d / "shell-history")},
               **env_extra)
    s = t.pty(argv, env=env, cwd=t.ctx.run_cwd, label="%s-i-%s" % (shell, form), stderr_tty=True)
    prompt = b"HMPS1$ "
    if not pre("[%s] interactive %s printed its prompt" % (ftag, shell),
               s.wait_for(lambda x: prompt in bytes(x.raw), 10.0) is not None, "prompt",
               H.printable(bytes(s.raw)[-200:])):
        return {"shell": shell, "ok": None, "not_run": "no prompt"}
    jc_notice = b"no job control" in bytes(s.raw) or "bash_no_job_control" in t.ctx.harness_mutate
    if not pre("[%s] harness precondition: %s enabled job control (no 'no job control' notice)" % (ftag, shell),
               not jc_notice, "job control on", H.printable(bytes(s.raw)[-200:])):
        return {"shell": shell, "ok": None, "not_run": "no job control"}
    s.send(cmdline % K6E_ITERATIONS + "\r")
    started = _wait_file(d / "ready-a.1", 10, s)
    if not chk("[%s] the child started under heimdall-proto and reached its first terminal read" % ftag, started,
               True, started):
        if gate:
            raise Abort("child did not start")
        return {"shell": shell, "ok": False, "first_failed_step": "child did not start"}
    ids = _read_json(d / "child.json") or {}
    child, proto = ids.get("pid"), ids.get("ppid")
    log = []

    def since(m):
        return bytes(s.raw)[m:]

    def states():
        return {"child": H.proc_state(child) if isinstance(child, int) else None,
                "proto": H.proc_state(proto) if isinstance(proto, int) else None}

    def beat():
        try:
            return int(_read_text(d / "beat") or "0")
        except ValueError:
            return 0

    last_fg = {}

    def no_restop_since_fg():
        """K6e "never re-stopped right after fg": the 0.5 s look in fg() misses a job that re-stops later (round-3
        review: 700 ms) and the failure then surfaced at a later step with the wrong blame.  Before the next step
        that could itself stop the job (the next Ctrl-Z, the final job check), wait until K6E_RESTOP_WINDOW_S have
        passed since that `fg` and assert that nothing has stopped the job since it, naming the `fg` step."""
        if not last_fg:
            return True
        fg_tag, m, t_fg = last_fg.pop("tag"), last_fg.pop("mark"), last_fg.pop("t")
        rest = K6E_RESTOP_WINDOW_S - (time.monotonic() - t_fg)
        if rest > 0:
            s.settle(rest)
        out = since(m)
        st = states()
        waited = round(time.monotonic() - t_fg, 2)
        log.append({"step": fg_tag + " fg window", "seconds_since_fg": waited, "stopped_notice": stopw in out,
                    "states": st})
        return chk("[%s] the job is not stopped again after `fg`: no 'Stopped' notice and the child is not stopped "
                       "from the `fg` until the next step (%.1f s window, observed %.2f s)"
                       % (fg_tag, K6E_RESTOP_WINDOW_S, waited), stopw not in out and st["child"] != "T",
                       "no 'Stopped', child not T", {"states": st, "output": H.printable(H.strip_csi(out)[-160:])})

    def ctrl_z(tag):
        if not no_restop_since_fg():
            return False
        m = len(s.raw)
        s.send(b"\x1a")
        r = s.wait_for(lambda x: stopw in since(m) and prompt in since(m)[since(m).find(stopw):], 5.0)
        log.append({"step": tag + " ctrl-z", "shell_reported_stop": r is not None, "states": states()})
        return chk("[%s] Ctrl-Z stops the job: the shell reports it stopped and prompts again" % tag, r is not None,
                       "'Stopped' then the prompt", H.printable(H.strip_csi(since(m))[-200:]))

    def fg(tag):
        m = len(s.raw)
        s.send("fg\r")
        last_fg.update(tag=tag, mark=m, t=time.monotonic())
        s.settle(0.5)
        out = since(m)
        st = states()
        restop = stopw in out or prompt in out
        log.append({"step": tag + " fg", "restopped_or_prompt": restop, "states": st})
        ok = chk("[%s] after `fg` the job is not stopped again: no 'Stopped' notice and no prompt (the job holds "
                     "the terminal)" % tag, not restop, "no 'Stopped', no prompt", H.printable(H.strip_csi(out)[-200:]))
        ok = chk("[%s] after `fg` the child is not in the stopped state" % tag, st["child"] not in (None, "T"),
                     "not T", st) and ok
        t.check("[%s] after `fg` heimdall-proto is not in the stopped state (non-gating observation: K6e speaks of "
                "the child; a stuck heimdall-proto still fails the final job-status check)" % tag,
                True, "not T", st["proto"], gating=False)
        return ok

    def line(tag, text, n):
        s.send(text + "\r")
        r = s.wait_for(lambda x: len(_read_json(d / "got") or []) >= n, 3.0)
        got = _read_json(d / "got") or []
        log.append({"step": tag + " line", "received": r is not None, "got": got[n - 1] if len(got) >= n else None})
        return chk("[%s] the child reads the line typed after `fg` (terminal input reaches it)" % tag,
                       r is not None and len(got) >= n and got[n - 1] == text + "\n", text + "\\n",
                       got[n - 1] if len(got) >= n else {"lines_received": len(got)})

    n = 0
    ok = True
    for i in range(1, K6E_ITERATIONS + 1):
        # A: Ctrl-Z while the child is blocked in a terminal read, then fg
        tag = "%s: iteration %d z-fg" % (ftag, i)
        ready = _wait_file(d / ("ready-a.%d" % i), 5, s)
        if not chk("[%s] the child is back in its terminal read" % tag, ready, True, ready):
            ok = False
            break
        s.settle(0.15)
        ok = ctrl_z(tag) and fg(tag)
        if ok:
            ok = line(tag, "K6E-A-%d" % i, n + 1)
            n += 1 if ok else 0
        if not ok:
            break
        # B: Ctrl-Z while the child runs (heartbeat, no terminal access), bg, fg
        tag = "%s: iteration %d z-bg-fg" % (ftag, i)
        ready = _wait_file(d / ("wait-b.%d" % i), 5, s)
        if not chk("[%s] the child reached its heartbeat phase" % tag, ready, True, ready):
            ok = False
            break
        s.settle(0.1)
        if not ctrl_z(tag):
            ok = False
            break
        b0 = beat()
        s.settle(0.4)
        b1 = beat()
        ok = chk("[%s] while the shell reports the job stopped, the child is stopped too (heartbeat frozen)" % tag,
                     b1 == b0, "heartbeat unchanged", {"before": b0, "after_0.4s": b1, "states": states()})
        m = len(s.raw)
        s.send("bg\r")
        # the shell acknowledged `bg`: bash prints the job and its prompt; zsh prints "[1]  + continued ..." from
        # the bg builtin itself, and zsh 5.9 sometimes does not redraw its prompt after it (seen in the Linux
        # container in 5 of 35 self-test runs, the reference child running normally), so for zsh that notice counts
        r = s.wait_for(lambda x: prompt in since(m) or (shell == "zsh" and b"continued" in since(m)), 3.0)
        s.settle(0.3)
        b2 = beat()
        s.settle(0.4)
        b3 = beat()
        st = states()
        log.append({"step": tag + " bg", "shell_ack": r is not None, "beat": [b2, b3], "states": st,
                    "shell_output": H.printable(H.strip_csi(since(m))[-120:])})
        ok = chk("[%s] after `bg` the child runs again (heartbeat advances) and is not left stopped while the shell "
                     "believes the job is running" % tag, r is not None and b3 > b2 and st["child"] not in (None, "T")
                     and stopw not in since(m), "shell acknowledged bg, heartbeat advancing, child not T, no '%s'"
                     % stopw.decode(), {"shell_ack": r is not None, "beat": [b2, b3], "states": st}) and ok
        ok = ok and fg(tag)
        if not ok:
            break
        (d / ("go-b.%d" % i)).write_text("1")
        ready = _wait_file(d / ("ready-b.%d" % i), 3, s)
        if not chk("[%s] the child left its heartbeat phase after `fg`" % tag, ready, True, ready):
            ok = False
            break
        s.settle(0.05)
        if not line(tag, "K6E-B-%d" % i, n + 1):
            ok = False
            break
        n += 1
    if ok:
        ok = no_restop_since_fg()
    chk("[%s] all %d iterations completed without a re-stop or lost input" % (ftag, K6E_ITERATIONS),
            ok and n == 2 * K6E_ITERATIONS, 2 * K6E_ITERATIONS, {"lines_delivered": n})
    if ok:
        done = _wait_file(d / "done", 5, s)
        s.wait_for(lambda x: bytes(x.raw).rstrip().endswith(prompt.rstrip()), 5.0)
        m = len(s.raw)
        s.send('echo "K6E_RC=$? K6E_JOBS=%s"\r' % jobs_expr)
        res_re = re.compile(rb"K6E_RC=(\d+) K6E_JOBS=\s*(\d+)")
        s.wait_for(lambda x: res_re.search(since(m)) is not None, 5.0)
        mm = res_re.search(since(m))
        chk_eq("[%s] the job finished: the child completed, the job's exit status is 0 and no job is left" % ftag,
             [done, list(mm.groups()) if mm else None], [True, [b"0", b"0"]])
    t.note("k6e_steps_" + ftag.replace(" ", "_"), log)
    first_bad = next((x for x in t.assertions if not x["ok"] and x["desc"].startswith("[%s:" % ftag)
                      or not x["ok"] and x["desc"].startswith("[%s]" % ftag)), None)
    first_bad = {"desc": first_bad["desc"], "observed": first_bad["observed"]} if first_bad else None
    s.send("exit\r")
    s.settle(0.3)
    s.send("exit\r")
    s.wait_exit(3.0)
    if ok:
        _session_leftovers(t, s, [x for x in (child, proto) if isinstance(x, int)], ftag, gating=gate)
    else:
        # the job was abandoned mid-way: release it (identity-checked SIGKILL), not judged again
        H.kill_session_pids([x for x in (child, proto) if isinstance(x, int)], s.shim.pid)
    return {"shell": shell, "gating": gate, "iterations": K6E_ITERATIONS, "lines_delivered": n, "ok": bool(ok),
            "first_failed_step": first_bad}


@check("run.k6e_job_control", "§4/K6e `heimdall-proto run -- <child>` as a job of an interactive job-control shell (bash -i in a pty; the same under zsh -f -i recorded as a non-gating observation), as a simple command and inside a command list (`run ...; echo`), %d iterations each of: Ctrl-Z stops the job (shell reports it, the child stops), `fg` resumes it without a re-stop and the child reads the next typed line; Ctrl-Z, `bg` (the child runs again, nothing left stopped while the shell believes the job runs), `fg` (no re-stop) and the child reads the next line; after every `fg` no re-stop within %.1f s (asserted before the next step, blaming that `fg`); finally the job exits 0 and no job is left" % (K6E_ITERATIONS, K6E_RESTOP_WINDOW_S), "pyte", budget=420)
def _(t):
    res = {}
    for form, cmdline in K6E_FORMS:
        res[form] = _k6e_form(t, form, cmdline)
    # zsh (the default interactive shell on macOS; installed in the Linux runner image): same forms, recorded as
    # non-gating observations until the gating question is decided (round-3 review coverage gap; see README)
    for form, cmdline in K6E_FORMS:
        res["zsh-" + form] = _k6e_form(t, form, cmdline, shell="zsh", gate=False)
    t.ctx.observations["k6e_job_control"] = res


# -- K6e child-initiated stop (contract section 9.4) --------------------------------------------------------------
# Child for run.k6e_child_self_stop: `stops` rounds of (heartbeat until the harness writes <tag>.go.<j>, print a
# heartbeat line to the terminal, stop ITSELF with kill(getpid(), SIG) - how OpenSSH's ~^Z escape works - and,
# once continued, read one line from the terminal); finally exit with the code given as the last argument.
K6ES_CHILD = r'''
import json, os, signal, sys, time
d, tag, stops, sig, rc = sys.argv[1], sys.argv[2], int(sys.argv[3]), getattr(signal, sys.argv[4]), int(sys.argv[5])
def put(name, text):
    p = os.path.join(d, tag + "." + name)
    with open(p + ".part", "w") as f:
        f.write(text)
    os.replace(p + ".part", p)
put("child.json", json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "pgrp": os.getpgrp()}))
got, beat = [], 0
for j in range(1, stops + 1):
    put("wait.%d" % j, "1")
    while not os.path.exists(os.path.join(d, "%s.go.%d" % (tag, j))):
        beat += 1
        put("beat", str(beat))
        time.sleep(0.02)
    sys.stdout.write("K6ES-BEAT %s %d %d\n" % (tag, j, beat))
    sys.stdout.flush()
    put("stopping.%d" % j, "1")
    os.kill(os.getpid(), sig)
    put("resumed.%d" % j, "1")
    got.append(os.read(0, 4096).decode("utf-8", "replace"))
    put("got", json.dumps(got))
put("done", "1")
sys.exit(rc)
'''
K6ES_RC = 42            # the child's exit status: the job's status as `fg` reports it at the end
K6ES_JOBS = 5           # heimdall-proto jobs in the gated form (each a fresh launch: start-up races)
K6ES_STOPS = 2          # self-stops per job (a later stop of the same launcher: state races)
K6ES_NOTICE_S = 4.0     # time allowed from the child's stop to the shell's stop notice and prompt
# (shell, stop signal, heimdall-proto jobs, gating): section 9.4 gates SIGTSTP under bash; SIGSTOP and zsh are
# recorded, not gated
K6ES_FORMS = (("bash", "SIGTSTP", K6ES_JOBS, True), ("bash", "SIGSTOP", 2, False),
              ("zsh", "SIGTSTP", 2, False), ("zsh", "SIGSTOP", 2, False))


def _k6es_form(t, shell, signame, jobs, gate):
    """One shell / stop-signal form of run.k6e_child_self_stop: a direct-exec control job, then `jobs`
    heimdall-proto jobs, all in the same interactive shell session; each child stops itself K6ES_STOPS times."""
    argv, env_extra, stopw, jobs_expr = K6E_SHELLS[shell]
    ftag = "%s %s" % (shell, signame)
    res = {"shell": shell, "signal": signame, "gating": gate, "proto_jobs": jobs, "stops_per_job": K6ES_STOPS,
           "ok": None, "first_failed_step": None, "control": None, "jobs": []}

    def note_fail(desc, expected, observed):
        t.check("%s (non-gating; form not run)" % desc, False, expected, observed, gating=False)

    if not os.access(argv[0], os.X_OK):
        desc = "[%s] harness precondition: %s is executable" % (ftag, argv[0])
        if gate:
            t.precondition(desc, False, "executable", argv[0])
        note_fail(desc, "executable", argv[0])
        res["not_run"] = "%s not executable" % argv[0]
        return res
    d = t.ctx.new_dir("k6es-%s-%s" % (shell, signame.lower()))
    (d / "s.py").write_text(K6ES_CHILD)
    env = dict({"P": t.ctx.bin, "Y": PY, "D": str(d), "PS1": "HMPS1$ ", "HISTFILE": str(d / "shell-history")},
               **env_extra)
    s = t.pty(argv, env=env, cwd=t.ctx.run_cwd, label="k6es-%s-%s" % (shell, signame.lower()), stderr_tty=True)
    prompt = b"HMPS1$ "
    started = []          # every pid a job of this session reported (child, its parent unless that is the shell)

    def release():
        H.kill_session_pids([p for p in started if p != s.pid], s.shim.pid)

    def env_pre(desc, ok, expected, observed):
        if ok:
            if gate:
                t.precondition(desc, True, expected, observed)
            return True
        release()
        if gate:
            t.precondition(desc, False, expected, observed)
        note_fail(desc, expected, observed)
        return False

    if not env_pre("[%s] harness precondition: interactive %s printed its prompt" % (ftag, shell),
                   s.wait_for(lambda x: prompt in bytes(x.raw), 10.0) is not None, "prompt",
                   H.printable(bytes(s.raw)[-200:])):
        res["not_run"] = "no prompt"
        return res
    jc_notice = b"no job control" in bytes(s.raw) or "bash_no_job_control" in t.ctx.harness_mutate
    if not env_pre("[%s] harness precondition: %s enabled job control (no 'no job control' notice)" % (ftag, shell),
                   not jc_notice, "job control on", H.printable(bytes(s.raw)[-200:])):
        res["not_run"] = "no job control"
        return res

    def since(m):
        return bytes(s.raw)[m:]

    notice_re = re.compile(re.escape(stopw) + rb"(?: ?\([^)\r\n]{1,24}\))?")

    def notice_line(out):
        """The shell's stop word with its optional '(signal)' suffix (the rest of the line is the command text,
        which differs between the control and the heimdall-proto job)."""
        mm = notice_re.search(H.strip_csi(out))
        return mm.group(0).decode("ascii", "replace") if mm else None

    def run_job(tag, via_proto):
        """One job.  For the control (via_proto False) every expectation is a harness precondition (gated form:
        outcome 'error'; recorded form: the form is not run); for heimdall-proto it is a K6e assertion."""
        info = {"tag": tag, "via": "heimdall-proto run" if via_proto else "direct exec (control)", "stops": []}
        t_job = time.monotonic()
        kind = "heimdall-proto" if via_proto else "control (direct exec)"

        def judge(desc, ok, expected=None, observed=None):
            desc = "[%s: %s] %s" % (ftag, tag, desc)
            if via_proto:
                if not ok and res.get("first_failed_step") is None:
                    res["first_failed_step"] = {"desc": desc, "observed": short(observed)}
                return t.check(desc if gate else "%s (non-gating observation)" % desc, ok, expected, observed,
                               gating=gate)
            return env_pre("harness precondition: the direct-exec control behaves: " + desc, ok, expected, observed)

        sig_arg = signame
        if not via_proto and "k6es_control_no_stop" in t.ctx.harness_mutate:
            sig_arg = "SIGWINCH"          # selftest-only fault: the control child does not stop at all
        cmd = '"$Y" "$D/s.py" "$D" %s %d %s %d' % (tag, K6ES_STOPS, sig_arg, K6ES_RC)
        if via_proto:
            cmd = '"$P" run -- ' + cmd
        s.send(cmd + "\r")
        ok = judge("the child started (%s) and reached its heartbeat" % kind,
                   _wait_file(d / (tag + ".wait.1"), 10, s), True, None)
        ids = _read_json(d / (tag + ".child.json")) or {}
        child, parent = ids.get("pid"), ids.get("ppid")
        started.extend(x for x in (child, parent) if isinstance(x, int) and x != s.pid)
        info["pids_reported"] = isinstance(child, int)

        def states():
            return {"child": H.proc_state(child) if isinstance(child, int) else None,
                    "parent": (H.proc_state(parent) if isinstance(parent, int) and parent != s.pid else "shell")}

        for j in range(1, K6ES_STOPS + 1):
            if not ok:
                break
            step = {"stop": j}
            info["stops"].append(step)
            if j > 1:
                ok = judge("stop %d: the child is back in its heartbeat after reading the previous line" % j,
                           _wait_file(d / ("%s.wait.%d" % (tag, j)), 5, s), True, None)
                if not ok:
                    break
            s.settle(0.1)
            m = len(s.raw)
            t_go = time.monotonic()
            (d / ("%s.go.%d" % (tag, j))).write_text("1")
            ok = judge("stop %d: the child printed its heartbeat and stopped itself with %s" % (j, signame),
                       _wait_file(d / ("%s.stopping.%d" % (tag, j)), 3, s), True, None)
            if not ok:
                break
            r = s.wait_for(lambda x: stopw in since(m) and prompt in since(m)[since(m).find(stopw):],
                           K6ES_NOTICE_S - (time.monotonic() - t_go), t_start=t_go)
            st = states()
            step.update(shell_reported_stop=r is not None, notice=notice_line(since(m)), states_at_notice=st,
                        notice_after_go_s=None if r is None else round(r, 3))
            ok = judge("stop %d: the shell reports the job stopped ('%s') and prompts again, with no user action, "
                       "within %.1f s of the harness's go to the child (as for the direct run)" % (j, stopw.decode(),
                                                                                         K6ES_NOTICE_S),
                       r is not None, "'%s' then the prompt" % stopw.decode(),
                       {"terminal": H.printable(H.strip_csi(since(m))[-240:]), "states": st})
            if not ok:
                break
            t.check("[%s: %s] stop %d: the child itself is stopped while the shell reports the job stopped "
                    "(non-gating observation)" % (ftag, tag, j), st["child"] == "T", "T", st, gating=False)
            m2 = len(s.raw)
            s.send('echo "K6ES_STOPRC=$?"\r')
            rc_re = re.compile(rb"K6ES_STOPRC=(\d+)")
            s.wait_for(lambda x: rc_re.search(H.strip_csi(since(m2))) is not None
                       and H.strip_csi(since(m2)).rstrip().endswith(prompt.rstrip()), 3.0)
            mm = rc_re.search(H.strip_csi(since(m2)))
            step["shell_status_of_stopped_job"] = int(mm.group(1)) if mm else None
            early = (d / ("%s.resumed.%d" % (tag, j))).exists()
            step["resumed_before_fg"] = early
            t.check("[%s: %s] stop %d: the child is not resumed before `fg` while the shell lists the job as stopped "
                    "(non-gating observation, escalated as Q16)" % (ftag, tag, j), not early, False, early,
                    gating=False)
            m3 = len(s.raw)
            s.send("fg\r")
            t_fg = time.monotonic()
            resumed = _wait_file(d / ("%s.resumed.%d" % (tag, j)), 3, s)
            step["resumed_after_fg"] = resumed
            ok = judge("stop %d: `fg` resumes the child" % j, resumed, True, {"states": states()})
            if not ok:
                break
            s.settle(0.3)
            out = since(m3)
            restop = stopw in out or prompt in out
            ok = judge("stop %d: after `fg` the job is not stopped again: no '%s' notice and no prompt (the job holds "
                       "the terminal)" % (j, stopw.decode()), not restop, "no notice, no prompt",
                       H.printable(H.strip_csi(out)[-200:]))
            if not ok:
                break
            text = "K6ES-%s-%d" % (tag.upper(), j)
            s.send(text + "\r")
            s.wait_for(lambda x: len(_read_json(d / (tag + ".got")) or []) >= j, 3.0)
            got = _read_json(d / (tag + ".got")) or []
            ok = judge("stop %d: the child reads the line typed after `fg` (terminal input reaches it)" % j,
                       len(got) >= j and got[j - 1] == text + "\n", text + "\\n",
                       got[j - 1] if len(got) >= j else {"lines_received": len(got)})
            if not ok:
                break
            rest = K6E_RESTOP_WINDOW_S - (time.monotonic() - t_fg)
            if rest > 0:
                s.settle(rest)
            st = states()
            ok = judge("stop %d: no re-stop within %.1f s of `fg`: no '%s' notice since the `fg` and the child is not "
                       "stopped" % (j, K6E_RESTOP_WINDOW_S, stopw.decode()),
                       stopw not in since(m3) and st["child"] != "T", "no notice, child not T",
                       {"states": st, "terminal": H.printable(H.strip_csi(since(m3))[-200:])})
        if ok:
            done = _wait_file(d / (tag + ".done"), 5, s)
            s.wait_for(lambda x: H.strip_csi(bytes(x.raw)[-200:]).rstrip().endswith(prompt.rstrip()), 5.0)
            m = len(s.raw)
            s.send('echo "K6ES_RC=$? K6ES_JOBS=%s"\r' % jobs_expr)
            res_re = re.compile(rb"K6ES_RC=(\d+) K6ES_JOBS=\s*(\d+)")
            s.wait_for(lambda x: res_re.search(since(m)) is not None, 5.0)
            mm = res_re.search(since(m))
            final = [done, [int(x) for x in mm.groups()] if mm else None]
            info["final"] = final
            ok = judge("the job finished: the child completed, the job's status (as `fg` reports it) is %d and no "
                       "job is left" % K6ES_RC, final == [True, [K6ES_RC, 0]], [True, [K6ES_RC, 0]], final)
        info["ok"] = bool(ok)
        info["seconds"] = round(time.monotonic() - t_job, 2)
        if not ok:
            release()           # abandoned mid-way: identity-checked SIGCONT+SIGKILL of the job's processes
            s.settle(0.5)
        return info

    ctl = run_job("ctl", False)
    res["control"] = ctl
    if not ctl["ok"]:
        res["not_run"] = "direct-exec control did not behave"
        s.send("exit\r")
        s.wait_exit(3.0)
        return res
    ok = True
    for i in range(1, jobs + 1):
        info = run_job("hp%d" % i, True)
        res["jobs"].append(info)
        if not info["ok"]:
            ok = False
            break
    res["ok"] = ok
    ctl_view = sorted({(x.get("notice"), x.get("shell_status_of_stopped_job")) for x in ctl["stops"]}, key=repr)
    hp_view = sorted({(x.get("notice"), x.get("shell_status_of_stopped_job")) for j in res["jobs"]
                      for x in j["stops"] if x.get("shell_reported_stop")}, key=repr)
    same = bool(hp_view) and hp_view == ctl_view
    res["notice_and_status_same_as_control"] = same
    res["notice_and_status"] = {"control": ctl_view, "heimdall_proto": hp_view}
    t.check("[%s] the stop notice word and the shell's status of the stopped job ($?) equal the direct-exec "
            "control's (non-gating observation: section 9.4 requires that the shell reports the job stopped, not "
            "which stop signal it names)" % ftag, same, ctl_view, hp_view, gating=False)
    s.send("exit\r")
    s.settle(0.3)
    s.send("exit\r")
    s.wait_exit(3.0)
    if ok:
        _session_leftovers(t, s, [p for p in started if p != s.pid], ftag, gating=gate)
    else:
        release()
    return res


@check("run.k6e_child_self_stop", "§4/K6e child-initiated stop (contract section 9.4): `heimdall-proto run -- <child>` as a job of `bash -i` in a pty, %d jobs; each child prints a heartbeat, stops ITSELF with kill(getpid(), SIGTSTP) (OpenSSH's ~^Z) %d times and, after each `fg`, reads a typed line, then exits %d. Each self-stop: the shell reports the job stopped and prompts again with no user action (like a direct-exec control run in the same session, a harness precondition), `fg` resumes the child, no re-stop (no notice/prompt after `fg`, none within %.1f s), the child reads the line; finally `fg` reports status %d and no job is left. SIGSTOP and zsh -f -i are recorded as non-gating observations" % (K6ES_JOBS, K6ES_STOPS, K6ES_RC, K6E_RESTOP_WINDOW_S, K6ES_RC), "pyte", budget=360)
def _(t):
    res = {}
    for shell, signame, jobs, gate in K6ES_FORMS:
        res["%s-%s" % (shell, signame)] = _k6es_form(t, shell, signame, jobs, gate)
    t.ctx.observations["k6e_child_self_stop"] = res


# -- K14 ------------------------------------------------------------------
def k14_targets(t):
    """(label, path) for a FIFO without writer, a listening socket, a directory and a character device,
    plus the objects to keep alive while they are used."""
    d = t.ctx.new_dir("k14")
    fifo = d / "fifo ü.toml"
    os.mkfifo(fifo)
    sock_path = d / "sock.toml"
    sk = socket.socket(socket.AF_UNIX)
    sk.bind(str(sock_path))
    sk.listen(1)
    dirp = d / "dir.toml"
    dirp.mkdir()
    return [("fifo", fifo), ("socket", sock_path), ("directory", dirp), ("device", Path("/dev/null"))], [sk]


@check("profile.non_regular_file", "§2/K14 --file naming a FIFO (no writer), a socket, a directory or a device -> exit 2 USAGE_ERROR within 2 s, never blocking")
def _(t):
    targets, keep = k14_targets(t)
    try:
        for label, path in targets:
            c = t.proto("profile", "show", "--file", str(path), "--json", label="k14-" + label, timeout=8)
            t.result(c, 2, "USAGE_ERROR", "failed")
            t.check("[k14-%s] finished within 2 s" % label, c.elapsed < 2.0 and not c.timed_out, "< 2.0 s",
                    "%.3f s%s" % (c.elapsed, " (timed out, killed)" if c.timed_out else ""))
    finally:
        for k in keep:
            k.close()


@check("tui.non_regular_file", "§5/K14 tui --file naming a FIFO, a socket, a directory or a device (in a pty) -> exit 2 within 2 s, never blocking; the terminal is left as found", "pyte")
def _(t):
    targets, keep = k14_targets(t)
    try:
        for label, path in targets:
            s = t.pty([t.ctx.bin, "tui", "--file", str(path)], label="k14-" + label)
            end = s.t_spawn + 6.0
            while s.poll() is None and time.monotonic() < end:
                s.pump(0.005)
            el = time.monotonic() - s.t_spawn
            rc = s.wait_exit(0.2)
            t.eq("[k14-%s] exit status 2" % label, rc, 2)
            t.check("[k14-%s] exited within 2 s of start (includes the pty shim's start-up)" % label,
                    rc is not None and el < 2.0, "< 2.0 s", "%.3f s" % el if rc is not None else "still running (killed)")
            st = H.final_state(bytes(s.raw))
            t.check("[k14-%s] alternate screen not left active, cursor not left hidden" % label,
                    not st["alt_active_at_end"] and not st["cursor_hidden_at_end"], "restored", st)
            if rc is not None:
                t.eq("[k14-%s] termios of the pty slave equal before/after" % label,
                     H.normalize_termios(s.termios_after()), H.normalize_termios(s.attr_before))
            t.check("[k14-%s] stderr message (non-gating observation)" % label, True, "non-empty",
                    H.printable(s.stderr_bytes(), 120), gating=False)
            s.close()
    finally:
        for k in keep:
            k.close()


# -- K15 ------------------------------------------------------------------
K15_FILE_LIMIT = 1048576
K15_TIME_S = 2.0
K15_RSS_BYTES = 256 * MIB


def _k15_fit(body_builder, per_unit):
    """Largest n with len(MIN_TOP + [meta] + body(n) + MIN_DEST) <= 1 MiB."""
    overhead = len((MIN_TOP + "\n[meta]\n" + MIN_DEST).encode()) + 16
    n = (K15_FILE_LIMIT - overhead) // per_unit
    while len((MIN_TOP + "\n[meta]\n" + body_builder(n) + MIN_DEST).encode()) > K15_FILE_LIMIT:
        n -= max(1, n // 200)
    return n


def k15_shapes():
    """(name, [meta] body): deep inline tables / arrays / mixtures, deep dotted keys and table headers,
    and wide shapes, each sized so the whole profile is at most 1 MiB."""
    inl = lambda n: "d = " + "{a = " * n + "1" + "}" * n + "\n"
    arr = lambda n: "d = " + "[" * n + "1" + "]" * n + "\n"
    aot = lambda n: "d = " + "[{a = " * n + "1" + "}]" * n + "\n"
    toa = lambda n: "d = " + "{a = [" * n + "1" + "]}" * n + "\n"
    dot = lambda n: ".".join(["a"] * n) + " = 1\n"
    hdr = lambda n: "[meta." + ".".join(["a"] * n) + "]\nx = 1\n"
    flat = lambda n: "d = {" + ", ".join("k%d = %d" % (i, i) for i in range(n)) + "}\n"
    wide = lambda n: "d = [" + ", ".join("{a = %d}" % i for i in range(n)) + "]\n"
    keys = lambda n: "".join("k%d = %d\n" % (i, i) for i in range(n))
    shapes = [("inline_tables_depth_8000", inl(8000))]
    n = _k15_fit(inl, 6)
    shapes.append(("inline_tables_depth_%d" % n, inl(n)))
    shapes.append(("arrays_depth_8000", arr(8000)))
    n = _k15_fit(arr, 2)
    shapes.append(("arrays_depth_%d" % n, arr(n)))
    shapes.append(("arrays_of_inline_tables_depth_8000", aot(8000)))
    n = _k15_fit(aot, 8)
    shapes.append(("arrays_of_inline_tables_depth_%d" % n, aot(n)))
    shapes.append(("inline_tables_of_arrays_depth_8000", toa(8000)))
    shapes.append(("dotted_key_8000_segments", dot(8000)))
    n = _k15_fit(dot, 2)
    shapes.append(("dotted_key_%d_segments" % n, dot(n)))
    shapes.append(("table_header_8000_segments", hdr(8000)))
    shapes.append(("flat_inline_table_60000_keys", flat(60000)))
    n = _k15_fit(wide, 11)
    shapes.append(("array_of_%d_inline_tables" % n, wide(n)))
    n = _k15_fit(keys, 15)
    shapes.append(("meta_table_%d_keys" % n, keys(n)))
    return shapes


def k15_write(d, name, body):
    text = MIN_TOP + "\n[meta]\n" + body + MIN_DEST
    return write_profile(d, name + ".toml", text), len(text.encode())


def k15_measure(t, report, label):
    rep = _read_json(report) or {}
    wall, rss = rep.get("wall_s"), rep.get("maxrss_bytes")
    t.check("[%s] measured by rss_wrap (os.wait4 rusage)" % label, wall is not None and rss is not None, "report",
            rep)
    return wall, rss, rep


@check("profile.parser_resource_bound", "§2/K15 profiles up to 1 MiB with deep inline-table/array nesting (and deep dotted keys, wide tables) inside [meta]: each finishes within 2 s below 256 MiB peak RSS, exit 0 PROFILE_OK or 2 SCHEMA_INVALID", budget=240)
def _(t):
    d = t.ctx.new_dir("k15")
    obs = {}
    for name, body in k15_shapes():
        p, size = k15_write(d, name, body)
        t.precondition("[%s] harness precondition: file is at most 1 MiB" % name, size <= K15_FILE_LIMIT, "<= 1048576", size)
        report = d / (name + ".rusage.json")
        c = t.proto("profile", "show", "--file", str(p), "--json", label="k15-" + name, timeout=8,
                    wrap=[PY, RSS_WRAP, str(report), "--"])
        wall, rss, rep = k15_measure(t, report, name)
        t.check("[%s] finished within 2 s (wall time of the binary)" % name, wall is not None and wall < K15_TIME_S
                and not c.timed_out, "< 2.0 s", wall)
        t.check("[%s] peak RSS below 256 MiB" % name, rss is not None and rss < K15_RSS_BYTES, "< 256 MiB",
                None if rss is None else "%.1f MiB" % (rss / MIB))
        if c.rc == 0:
            doc = t.result(c, 0, "PROFILE_OK", "succeeded", label="k15-" + name)
            if doc:
                t.eq("[%s] accepted: data equals the profile outside [meta]" % name, doc.get("data"),
                     {"profile": {"name": "x", "revision": 1, "destinations": [MIN_DEST_EXPECT]}})
        elif c.rc == 2:
            t.result(c, 2, "SCHEMA_INVALID", "failed", label="k15-" + name)
        else:
            t.check("[k15-%s] exit 0 (PROFILE_OK) or 2 (SCHEMA_INVALID)" % name, False, "0 or 2", c.rc)
        obs[name] = {"bytes": size, "exit": c.rc, "wall_ms": None if wall is None else round(wall * 1000, 1),
                     "maxrss_mib": None if rss is None else round(rss / MIB, 1)}
    t.note("k15", obs)
    t.ctx.observations["k15_profile_show"] = obs


@check("tui.parser_resource_bound", "§5/K15 tui --file with the two deepest 1 MiB nesting shapes: first frame or exit 2 within 2 s, peak RSS below 256 MiB", "pyte", budget=120)
def _(t):
    d = t.ctx.new_dir("k15-tui")
    obs = {}
    shapes = [x for x in k15_shapes() if re.match(r"(inline_tables|arrays)_depth_\d+$", x[0])
              and not x[0].endswith("_8000")]
    t.precondition("harness precondition: two deepest shapes selected", len(shapes) == 2, 2, [x[0] for x in shapes])
    for name, body in shapes:
        p, size = k15_write(d, name, body)
        report = d / (name + ".rusage.json")
        s = t.pty([PY, RSS_WRAP, str(report), "--", t.ctx.bin, "tui", "--file", str(p)], label="k15-" + name)
        lat = s.wait_for(lambda x: x.poll() is not None or status_of(x) == (1, 1), 6.0, t_start=s.t_spawn)
        if s.poll() is None and status_of(s) == (1, 1):
            t.check("[%s] accepted: first frame within 2 s of start (includes shim and wrapper start-up)" % name,
                    lat is not None and lat < K15_TIME_S, "< 2.0 s", lat)
            s.send("q")
            rc = s.wait_exit(3.0)
            t.eq("[%s] q exits 0" % name, rc, 0)
        else:
            rc = s.wait_exit(2.0)
            t.eq("[%s] rejected: exit status 2" % name, rc, 2)
        wall, rss, rep = k15_measure(t, report, name)
        if rc == 2:
            t.check("[%s] rejected within 2 s (wall time of the binary)" % name, wall is not None and wall < K15_TIME_S,
                    "< 2.0 s", wall)
        t.check("[%s] peak RSS below 256 MiB" % name, rss is not None and rss < K15_RSS_BYTES, "< 256 MiB",
                None if rss is None else "%.1f MiB" % (rss / MIB))
        obs[name] = {"exit": rc, "first_frame_s": lat if rc == 0 else None, "wall_ms": None if wall is None
                     else round(wall * 1000, 1), "maxrss_mib": None if rss is None else round(rss / MIB, 1)}
        s.close()
    t.note("k15_tui", obs)
    t.ctx.observations["k15_tui"] = obs


@check("harness.rss_probe", "measurement used by the K15 checks: rss_wrap reports wall time, peak RSS (bytes on macOS, KiB on Linux, normalised) and the exit status of one child")
def _(t):
    d = t.ctx.new_dir("rssprobe")
    cases = [("alloc-96MiB", "b = b'x' * (96 << 20)\nimport time\ntime.sleep(0.2)\n", 0),
             ("idle-0.3s", "import time\ntime.sleep(0.3)\n", 0),
             ("exit-3", "raise SystemExit(3)\n", 3)]
    for label, prog, rc in cases:
        rep_path = d / (label + ".json")
        cap = H.run_capture(label, [PY, RSS_WRAP, str(rep_path), "--", PY, "-c", prog], t.ctx.env(), str(d), timeout=20)
        rep = _read_json(rep_path) or {}
        t.eq("[%s] wrapper exit status is the child's" % label, cap.rc, rc)
        t.eq("[%s] report exit_code" % label, rep.get("exit_code"), rc)
        rss = rep.get("maxrss_bytes") or 0
        if label == "alloc-96MiB":
            t.check("[%s] peak RSS >= 96 MiB and < 256 MiB (units normalised)" % label, 96 * MIB <= rss < 256 * MIB,
                    "96..256 MiB", "%.1f MiB (raw %s)" % (rss / MIB, rep.get("ru_maxrss_raw")))
        else:
            t.check("[%s] peak RSS < 96 MiB" % label, 0 < rss < 96 * MIB, "0..96 MiB", "%.1f MiB" % (rss / MIB))
        if label == "idle-0.3s":
            t.check("[%s] wall time 0.3..2 s" % label, 0.3 <= (rep.get("wall_s") or 0) < 2.0, "0.3..2 s",
                    rep.get("wall_s"))


# -- can this OS show a back-to-back duplicate forward? ------------------------
SIGNAL_MERGE_PROBE_KEY = "harness_os_probe_back_to_back_signal_merge"
SIGNAL_MERGE_PROBE_WHAT = ("harness self-probe of the OS, NOT a heimdall-proto measurement: a Python wrapper written by "
                           "the harness sends each signal twice back to back with kill() to the harness's signal-counting "
                           "child (heimdall-proto is not involved); deliveries_per_trial counts what that child saw, i.e. "
                           "whether this kernel merges two identical pending standard signals. It bounds what the "
                           "run.forward_* / run.explicit_signal_with_tty exactly-once assertions can observe. "
                           "heimdall-proto's own delivery counts are in the run.* checks and observations.k6d_*")
DOUBLE_FORWARDER = r"""
import signal, subprocess, sys
child = subprocess.Popen(sys.argv[1:])
def fwd(s, f):
    child.send_signal(s)
    child.send_signal(s)          # deliberately twice, back to back (what a double-forwarding wrapper does)
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    signal.signal(s, fwd)
sys.exit(child.wait())
"""


@check("harness.signal_duplicate_probe", "observability probe for the K6 exactly-once checks (the harness's own OS probe; heimdall-proto is not involved): a double-forwarding wrapper written by the harness (two back-to-back kill() calls per signal) runs the signal-counting child; records whether this OS delivers both or merges them (standard signals do not queue) in observations.harness_os_probe_back_to_back_signal_merge")
def _(t):
    import signal as sg
    counts = []
    for signame in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT") * 2 + ("SIGTERM", "SIGINT"):
        d = t.ctx.new_dir("dupprobe")

        def pre(proc, d=d, sig=getattr(sg, signame)):
            end = time.monotonic() + 10
            while not (d / "ready").exists():
                if proc.poll() is not None or time.monotonic() > end:
                    raise RuntimeError("probe child never became ready")
                time.sleep(0.005)
            time.sleep(0.05)
            os.kill(proc.pid, sig)

        cap = H.run_capture("dup-" + signame, [PY, "-c", DOUBLE_FORWARDER, PY, "-c", CHILD_TRAP, str(d), "exit"],
                            t.ctx.env(), str(t.ctx.run_cwd), timeout=20, pre=pre)
        sigs = _read_lines(d / "signals")
        t.check("[%s] probe ran: child saw the signal at least once and exited 7" % signame,
                cap.rc == 7 and len(sigs) >= 1 and set(sigs) == {signame}, "rc 7, >= 1 delivery",
                {"rc": cap.rc, "signals": sigs})
        counts.append(len(sigs))
    n2 = sum(1 for c in counts if c == 2)
    obs = {"what": SIGNAL_MERGE_PROBE_WHAT, "measures_heimdall_proto": False,
           "deliveries_per_trial": counts, "trials_with_duplicate": "%d/%d" % (n2, len(counts)),
           "duplicates_observable": n2 > 0, "always_observable": bool(counts) and n2 == len(counts),
           "os": platform.system()}
    # Renamed in harness 2.4.0 (was observations.signal_duplicates, which the round-3b stage summary misread as a
    # heimdall-proto duplicate count): this is the harness's own OS probe, not a measurement of the candidate.
    t.ctx.observations[SIGNAL_MERGE_PROBE_KEY] = obs
    t.note(SIGNAL_MERGE_PROBE_KEY, obs)
    t.check("harness OS probe, not heimdall-proto: back-to-back duplicate deliveries from the harness's own "
            "double-forwarding wrapper observed on %s (non-gating observation: in a trial with 1 delivery the "
            "kernel merged the two signals, so a heimdall-proto that forwards twice back to back would look like a single "
            "forward)" % platform.system(), True, "2 per trial", counts, gating=False)


# -- canary self-check (unit) ----------------------------------------------
@check("harness.canary_selfcheck", "canary rule: fixture canaries load by key path, the scanner finds registered and unregistered full canary values (not the bare prefix) and redaction removes them; labels never hold a value")
def _(t):
    ctx = t.ctx
    t.eq("fixture canaries loaded by fixture and key path", ctx.canary_load_errors, [])
    t.eq("number of registered canaries (2 fixture keys, env, [meta], malformed-line source)", len(ctx.canaries), 5)
    t.check("the per-run canaries (env, [meta], malformed-line source) are registered",
            all(v in ctx.canaries for v in (ctx.env_canary, ctx.meta_canary, ctx.src_canary)), True, None)
    t.check("no label holds a canary value", not any(H.CANARY_VALUE_RE.search(l.encode()) for l in ctx.canaries.values()),
            "none", sorted(ctx.canaries.values()))
    pre = "HEIMDALL_CANARY_"
    some = next(iter(ctx.fixture_canary_values.values()), pre + "x")
    t.eq("scanner finds a registered value (reported by label)", H.canary_hits(("x " + some + " y").encode(), ctx.canaries),
         [ctx.canaries.get(some, "unregistered HEIMDALL_CANARY_ value")])
    t.eq("scanner finds an unregistered prefix+value", H.canary_hits((pre + "Zq9").encode(), ctx.canaries),
         ["unregistered HEIMDALL_CANARY_ value"])
    t.eq("bare prefix used as a scan pattern is allowed", H.canary_hits(("no " + pre + " in x").encode(), ctx.canaries), [])
    t.eq("redaction marker is not a hit", H.canary_hits(b"[REDACTED_CANARY]", ctx.canaries), [])
    red = H.redact_values(("a " + ctx.env_canary + " b " + pre + "Zq9 c").encode(), ctx.canaries)
    t.eq("redaction removes registered and unregistered values", H.canary_hits(red, ctx.canaries), [])
    t.check("short() redacts expected/observed text", not H.CANARY_VALUE_RE.search(short(some).encode()), True, None)


# --------------------------------------------------------------------------
ORDER = ["harness", "usage", "version", "profile", "agent", "run", "tui", "common", "k12", "canary"]


def ordered_checks():
    return sorted(CHECKS, key=lambda c: ORDER.index(c[1]))   # stable: keeps definition order inside a group


def select_checks(only):
    allc = ordered_checks()
    if not only:
        return allc, False
    wanted = []
    for pat in only:
        if pat.endswith("*"):
            m = [c for c in allc if c[0].startswith(pat[:-1])]
        else:
            m = [c for c in allc if c[0] == pat]
        if not m:
            raise SystemExit("unknown check id: %s" % pat)
        wanted += m
    seen, out = set(), []
    for c in allc:
        if c in wanted and c[0] not in seen:
            seen.add(c[0])
            out.append(c)
    return out, True


def run_one(t, fn, budget, finish_budget=FINISH_BUDGET):
    """Run one check function under a hard wall-clock bound, then its cleanup under another.

    Returns (outcome or None, error or None).  Never blocks longer than budget + finish_budget
    (+ a few seconds of bounded process reaping): defect (c)."""
    outcome, error = None, None
    t0 = time.monotonic()
    try:
        H.arm(budget)
        try:
            fn(t)
        finally:
            H.arm(0)
    except Abort:
        pass
    except PreconditionFailed as exc:
        outcome = "error"
        error = "harness precondition failed (invalid evidence, not a candidate result): %s" % exc
    except H.CheckTimeout:
        outcome = "error"
        error = "check exceeded its hard wall-clock bound of %.0f s (aborted; see traceback.txt)" % budget
        t.save("traceback.txt", traceback.format_exc())
    except Exception as exc:  # harness-side/unexpected error in the check
        outcome = "error"
        error = "".join(traceback.format_exception_only(type(exc), exc)).strip()[:600]
        t.save("traceback.txt", traceback.format_exc())
    t.note("check_seconds", round(time.monotonic() - t0, 3))
    try:
        H.arm(finish_budget)
        try:
            t.finish()
        finally:
            H.arm(0)
    except H.CheckTimeout:
        outcome = "error"
        error = (error + "; " if error else "") + "cleanup exceeded its hard bound of %.0f s" % finish_budget
    except Exception as exc:  # noqa
        outcome = "error"
        error = (error + "; " if error else "") + "cleanup failed: %r" % exc
    killed = H.kill_tracked()
    if killed:
        t.note("processes_killed_after_check", len(killed))
    return outcome, error


def run_checks(ctx, selected):
    results = []
    H.install_alarm_handler()
    for cid, group, clause, title, needs, fn in selected:
        ctx.ran_ids.append(cid)
        t = T(ctx, cid, clause, title)
        t0 = time.monotonic()
        outcome, error = None, None
        if needs == "pyte" and ctx.pyte is None:
            outcome, error = "skipped", "pyte not importable (install tests/g02/requirements.txt into tests/g02/.venv)"
        else:
            outcome, error = run_one(t, fn, BUDGETS.get(cid, DEFAULT_BUDGET))
            if outcome is None:
                gating = [a for a in t.assertions if a["gating"]]
                if not gating:
                    outcome, error = "error", "check made no gating assertion"
                else:
                    outcome = "pass" if all(a["ok"] for a in gating) else "fail"
        res = {
            "id": cid, "group": group, "clause": clause, "title": title, "outcome": outcome,
            "hard_bound_s": BUDGETS.get(cid, DEFAULT_BUDGET),
            "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            "error": error,
            "assertions": t.assertions,
            "failed_assertions": [a["desc"] for a in t.assertions if a["gating"] and not a["ok"]],
            "captures": [c.summary() for c in t.caps],
            "notes": t.notes,
            "artifacts": [os.path.relpath(p, ctx.artifacts_dir.parent) if ctx.artifacts_dir.parent in Path(p).parents
                          else p for p in t.artifact_files],
        }
        results.append(res)
        mark = {"pass": "PASS", "fail": "FAIL", "error": "ERR ", "skipped": "SKIP"}[outcome]
        line = "%s  %-44s %6.0f ms  %s" % (mark, cid, res["duration_ms"],
                                           "" if outcome == "pass" else (error or "; ".join(res["failed_assertions"][:2]))[:110])
        print(H.redact_values(line.encode("utf-8", "backslashreplace"), ctx.canaries).decode("utf-8", "replace"),
              flush=True)     # console logs may be kept as artifacts: canary rule
    return results


def git(*args):
    try:
        r = subprocess.run(["git", "-C", str(REPO)] + list(args), capture_output=True, text=True, timeout=20)
        return r.stdout.strip() if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def pkg_version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:  # noqa
        return "unknown"


def tool_version(argv):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return (r.stdout + r.stderr).strip().splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


STATIC_LIMITATIONS = [
    "Windows is NOT covered: named-pipe agent path, CommandLineToArgvW quoting, console Ctrl-C and ConPTY behaviour need a native Windows run (blocked_on: native Windows host).",
    "WSL is NOT covered (blocked_on: Windows host with WSL).",
    "Section 7 / K11 build and sidecar rules (clean machine without toolchain, manifest sidecars, sidecar loading from the executable's own directory, environment overrides ignored) are NOT judged by this harness.",
    "K11 stray-file detection covers the sandbox HOME, TMPDIR and the working directory of each invocation; writes elsewhere (for example a hard-coded /tmp or the per-user temp directory outside TMPDIR) are not detected.",
    "TUI is judged through a pty plus the pyte VT emulator (with an xterm-compatible double-width cell renderer, see harness.screen_wide_chars), which answers DA and cursor-position queries but not OSC colour/XTVERSION/kitty-keyboard queries (a framework that waits for those answers will show a slower first frame); real terminal emulators may differ. stdout and the TUI frames share the tty, so stdout-vs-stderr separation of TUI output cannot be proven; SELECTED and 'no stdout' are judged on the text after the alternate screen is left.",
    "Restoration and exit 1 after an internal panic/uncaught exception (K10) cannot be induced black-box and are NOT tested; select, quit, Ctrl-C (also in filter mode), SIGTERM, SIGHUP and terminal hangup paths are.",
    "After a terminal hangup only the exit status is judged (the terminal is gone, so restoration cannot be observed).",
    "'No network' and 'no shell invocation' (contract section 1) cannot be proven black-box; only observable effects are tested (no shell metacharacter expansion, sentinel files, no fake-agent contact, no stray files).",
    "Allocation behaviour ('never allocate from an untrusted length first') is inferred from fast, correct failure on 0x7fffffff / nkeys 100000 frames, not measured.",
    "Timing thresholds (500 ms SIGINT, 100 ms resize, 100 ms p95 filter update (K17), 2 s malformed-agent failure) are wall-clock on a possibly loaded machine; SIGINT uses best-of-3, resize best-of-5, and the record stores the load average before/after so a loaded run can be recognised and repeated.",
    "Signal counts use the child's wakeup fd (one byte per delivery), but the kernel still merges two identical standard signals sent while the first is pending, so a heimdall-proto that forwards twice back-to-back may be seen once; exact-once is reliable for deliveries that are separated in time (terminal vs forwarded) and is a best-effort lower bound otherwise.",
    "Invalid UTF-8 handling uses isolated invalid bytes (each one U+FFFD); runs of invalid bytes are deliberately not tested because the contract does not define replacement-character counting.",
    "Every check runs under a hard wall-clock bound (default 120 s, cleanup 30 s); a check that hits it is recorded as 'error', never as pass.",
    "The disposable keys are generated per run, private halves deleted immediately; fingerprints are cross-checked against /usr/bin/ssh-keygen -lf.",
    "K6b precedence (K6a, then K6, then the section 4 terminal-SIGINT rule) is reflected as follows: run.k6a_* gate K6a; run.forward_* and run.explicit_signal_with_tty gate exactly-once for signals sent to the heimdall-proto PID; terminal and killpg duplicate counts are non-gating observations. Giving the child its own foreground group is not penalised where heimdall-proto is alone in its process group (run.explicit_signal_with_tty) and is caught where it is not (run.k6a_pipeline_peer_not_stopped, run.k6a_background_script_tty).",
    "K6a is judged on four scenarios only: a pipeline job of bash -i (bash 3.2 on macOS, the image's bash 5.2 on Linux) whose peer reads the tty, a non-job-control script whose `&` job is heimdall-proto (stdin the tty or /dev/null), a child that stops itself with SIGTSTP while heimdall-proto is the first or the last member of a bash -i pipeline or runs under a non-job-control `sh -c` script (run.k6a_child_self_stop_not_spread: the other member is sampled every 0.1 s for 4 s and must never be stopped; a direct-exec control of each layout is a harness precondition; SIGSTOP self-stops, terminal-generated stops and longer windows are not covered there), and inherited SIG_IGN for SIGHUP and for SIGINT (gated, K6c; SIGQUIT, SIGTERM, SIGWINCH, SIGPIPE ignores and an inherited blocked SIGUSR2 are recorded non-gating in observations.k6c_other_inherited_signal_state). Other shells (zsh, fish, dash) are not tested for K6a (zsh only for K6e, non-gating) and nested job control is not tested; with an ignoring child, 'not forwarded' is observed only through the child's own handler in phase 2.",
    "K14 uses a FIFO without a writer, a listening AF_UNIX socket, a directory and /dev/null; other devices (blocking or infinite ones such as /dev/zero) are deliberately not used.",
    "K15 wall time is measured by tests/g02/rss_wrap.py from spawn to reap (includes process start-up); peak RSS is the os.wait4 rusage of the binary and the descendants it waited for (descendants it did not wait for are not counted). The tui variant's first-frame time also includes the pty shim's and the wrapper's start-up. Shapes: deep inline tables, arrays, arrays of inline tables, inline tables of arrays, dotted keys, a table header, and wide tables, each at most 1 MiB.",
    "K16 detects only executions resolved through PATH of the names tmux, tput, infocmp, stty, sh, bash, ssh and git; an execution by absolute path (for example /usr/bin/tput) or of another name is not detected.",
    "K6d (shared mode) is judged in three layouts: heimdall-proto as the child of a foreground non-job-control `/bin/sh -c` script (sh is bash 3.2 in POSIX mode on macOS, dash in the Linux image), and as the first and as the last member of a `bash -i` pipeline job; one explicit kill(<pid>, sig) per signal and layout, delivery awaited 3 s. That the job containing heimdall-proto holds the terminal foreground (sh -c: the script's group; pipelines: the other member's group, reported by that member, not the shell's) is a harness precondition: if any layout misses it the check is 'error' (invalid evidence), never a silent pass on delivery alone; whether heimdall-proto itself stayed in that group is recorded per setup (observations.k6d_shared_setups). Other shells, Makefiles proper, nested scripts and rapid repeats are not exercised. A delivery that the kernel merges with a pending identical signal is counted once.",
    "K6e (job control) is judged under `bash -i` (bash 3.2 on macOS, bash 5.2 in the Linux image), 5 iterations of Ctrl-Z/fg (child blocked in a terminal read) and Ctrl-Z/bg/fg (child running without terminal access); 'not re-stopped' is judged 0.5 s after `fg` and again, blaming that `fg`, before the next step once at least 1.5 s have passed since it (shell output and the /bin/ps or /proc state of the child). The same forms run under `zsh -f -i` (zsh 5.9 on macOS and in the Linux image) as NON-GATING observations (observations.k6e_job_control, keys zsh-*) until the gating question is decided. A re-stop later than 1.5 s after `fg` that does not disturb a later step, races needing more iterations, fish/dash job control and a background terminal read (Q12) are not covered. In particular a launcher that mirrors a child stop report without a grace period (reference mutation run_mirror_nograce, race mutation in the self-test) re-stops the job only when it is itself stopped between reading the report and stopping itself; the harness cannot force that interleaving and catches it only by chance (Q18).",
    "K17 is measured like the earlier latency observation: from writing the keystroke to the pty master until the pyte emulator shows the expected status line AND the expected list rows (the first min(N, capacity) matching destinations in fixture order; 2 ms polling), 30 edits on large-100.toml in 5 filter sessions (`/`, 3 characters, 3 Backspaces, Esc) so the first keystroke after `/` is weighted per session, p95 by nearest rank; it includes pty and emulator overhead and is wall-clock on a possibly loaded machine (load average recorded). The session weighting (6 edits per session) is a harness sampling choice, not a contract figure.",
    "K6e child-initiated stop (section 9.4) is judged by run.k6e_child_self_stop under `bash -i` only (bash 3.2 on macOS, 5.2 in the Linux image): %d heimdall-proto jobs, each child stopping itself %d times with kill(getpid(), SIGTSTP) after a heartbeat and reading a typed line after each `fg`, preceded by a direct-exec control job in the same shell session (a harness precondition: if the control does not stop, resume and read, the check is 'error'). SIGSTOP self-stops and the same under `zsh -f -i` (2 jobs each) are NON-GATING observations (observations.k6e_child_self_stop). Not covered: a self-stop while the job is in the background, a self-stop of a child in a pipeline or command list, stops by SIGTTIN/SIGTTOU, other shells; whether the child stays stopped until `fg` (resumed_before_fg) is recorded, not gated (Q16)." % (K6ES_JOBS, K6ES_STOPS),
    "K12 closed stdout (section 9.4) is judged by k12.closed_stdout_exit_parity for version, profile show (homelab fixture) and agent list (fake agent, normal mode), each with and without --json, stdout being the write end of a pipe whose read end the harness closed before the start; heimdall-proto starts with SIGPIPE at its default disposition (as from a shell). Error results on a closed stdout (profile show of a missing file and of a schema-invalid file, agent list on a missing socket, a usage error) are judged the same way and are GATING in the same check since harness 2.4.2 (Q17 answered yes, section 9.4; observations.k12_closed_stdout_errors, K12_ERROR_RESULTS_GATING = True). Not covered: an inherited SIGPIPE ignore, a reader that closes after part of the output, stderr closed.",
    "K6c SIGPIPE: the SIGPIPE disposition of a non-Python child is observed for both dispositions heimdall-proto can inherit (ignored and default): `yes` writing into a pipe whose reader closes exits 1 on EPIPE (ignored) or dies of SIGPIPE (default); on Linux also /bin/cat /proc/self/status SigIgn. Classified as inherited_disposition_kept (exec semantics), child_always_default (inherited ignore reset), child_always_ignores (the runtime's ignore leaks into every child) or other; inherited_sigpipe_ignore_kept is true only for the first. Non-gating (K6c); whether a default disposition must stay default in the child is not stated by the contract (escalated). The probe's own preconditions are non-gating too (classification probe_invalid), so they never affect the gated K6a check.",
]
OPEN_QUESTIONS = [
    "Q1 meta for a signal-killed child: contract gives exit_code int|null and signal int|null; harness gates only on signal==9 and launched==true and records exit_code (non-gating).",
    "Q3 (settled by K6b, recorded here for traceability): duplicate delivery of a terminal-generated signal, or of a group-directed signal from another process (killpg), is recorded and not gated; the harness gates on the child's exit status and records the delivery count (run.sigint_process_group, run.explicit_signal_with_tty).",
    "Q11 (round 4) K18 makes every OFFENDING input value secret on stdout and stderr; it does not name the values of OTHER keys that an error diagnostic might quote (the unsupported-schema_version case: the profile name, a destination host). The harness gates them in the JSON result (section 2) and records them on stderr as a non-gating observation (observations.value_on_stderr, gating=false). Escalated: confirm, or extend the stderr gate to every input value.",
    "Q12 (round 4) K6e: after `bg`, a child that reads the terminal is stopped by the kernel (SIGTTIN). A wrapper that does not mirror that stop leaves the child stopped while the shell lists the job as running, until `fg`. run.k6e_job_control avoids that case (the child does not touch the terminal while in the background) and gates 'never left stopped while the shell believes the job is running' only for a child that is not reading the terminal. Escalated: does K6e also require mirroring a background tty-input stop to the shell?",
    "Q13 (round 5) K6e says 'an interactive job-control shell'. The harness gates K6e under bash (3.2 macOS, 5.2 Linux) and runs the same forms under zsh 5.9 (the macOS default shell; added to the Linux image) as non-gating observations (observations.k6e_job_control zsh-*). Whether zsh (or every common job-control shell) is gating is not decided by the contract; escalated.",
    "Q14 (round 5) K6c: K6a/K6c speak of inherited IGNORED dispositions. Whether a DEFAULT SIGPIPE disposition heimdall-proto inherited must stay default in the child (a runtime that ignores SIGPIPE itself and leaks that into every child: classification child_always_ignores) is not stated in section 4, K6a or K6c. Recorded non-gating; escalated as an ADR-0002 input.",
    "Q15 (round 5) K17 does not define the keystroke population of the p95. The harness samples 5 filter sessions of 6 edits (the first keystroke after `/` is 1 in 6), so a TUI slow only on the first keystroke of a session fails; with one pooled session it passed. Sampling choice made by the harness and escalated for confirmation.",
    "Q16 (round 6) K6e child-initiated stop (section 9.4): the harness gates that the shell reports the job stopped, that `fg` resumes the child, no re-stop and that the child reads the typed line. Whether the child must also STAY stopped until `fg` (a launcher that reports the stop to the shell but continues the child at once) is recorded per stop (resumed_before_fg, non-gating), not gated. Escalated: gate it (exec semantics) or not.",
    "Q18 (round 7, harness limitation, not a contract question) K6e 'never re-stopped right after fg': a launcher that mirrors its child's stop report at once, without a grace for a report made stale by the shell's group continue, re-stops the job only in a scheduling race (it must be stopped between reading 'child still stopped' and stopping itself). The harness cannot force that interleaving black-box; run.k6e_job_control catches it only by chance (measured 2026-10-05 on darwin-arm64, selftest-results/2026-10-05-r7/nograce-experiments: 0 of 15 Ctrl-Z/fg cycles in each of six bash -i variants, idle and under CPU load, and 0 of 12 killpg cycles; one earlier unpreserved run 1 of 15; harness 2.4.0's stress record: 2 of 160 cycles under 20 CPU burners). The self-test runs mutation run_mirror_nograce as a RACE mutation (reported, not required). Escalated: accept this residual (code review of the candidate's stop-mirroring instead), or require a stress run.",
    "Resolved by contract section 9 (no longer open): Q2 invalid UTF-8 argv -> K8 (gating), Q4 TUI SIGTERM code -> K10, Q5 EOF before any reply byte -> K3, Q6 control characters in agent comments -> K1, Q7 output without --json -> K12; by section 9.3: Q8 -> K10 exit form (exit 143/129 or a death by the re-raised signal both pass), Q9 -> K18 (offending values gated on stdout and stderr), Q10 -> K17 (p95 <= 100 ms, gating); by section 9.4: the round-3b child self-stop finding -> K6e covers child-initiated stops (SIGTSTP under bash gated: run.k6e_child_self_stop), the closed-stdout K12 finding -> k12.closed_stdout_exit_parity; by the owner ruling Q17 (section 9.4, harness 2.4.2): the closed-stdout parity covers error results too -> GATING in k12.closed_stdout_exit_parity (a --json error result that dies of SIGPIPE/EPIPE while the plain run exits 2/5 fails).",
]


def platform_label():
    """darwin-arm64, linux-arm64, linux-x64, ... (the K13 platform names)."""
    osn = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system(), platform.system().lower())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(platform.machine().lower(),
                                                                                       platform.machine().lower())
    return "%s-%s" % (osn, arch)


def platform_limitations(args):
    plat = platform_label()
    out = []
    if plat.startswith("darwin"):
        out.append("K13: the G02 verdict needs the full harness to pass on darwin-arm64 AND linux-arm64; this record "
                   "covers %s only. The Linux run is a separate record produced by tests/g02/linux/run.sh with the "
                   "candidate's linux-arm64 artifact." % plat)
    elif plat.startswith("linux"):
        extra = args.environment_extra or {}
        cont = extra.get("container") if isinstance(extra, dict) else None
        out.append("K13: this record covers %s only (%s); the darwin-arm64 run is a separate record. Linux runs "
                   "of tests/g02/linux/run.sh use Docker Desktop's arm64 Linux VM (linuxkit kernel, native arm64, not "
                   "emulation), a digest-pinned image, --network none, a non-root user and a read-only repository "
                   "mount; behaviour on other kernels/distributions is not covered." %
                   (plat, "container image %s" % cont.get("image_ref") if cont else "no container metadata given"))
    else:
        out.append("K13: platform %s is not one of the G02 verdict platforms (darwin-arm64, linux-arm64)." % plat)
    return out


def build_record(ctx, args, selected, partial, results, started, t_start, binpath, loadavg_start):
    counts = {o: sum(1 for r in results if r["outcome"] == o) for o in OUTCOMES}
    all_pass = bool(results) and counts["pass"] == len(results)
    complete = bool(results) and not partial and counts["error"] == 0 and counts["skipped"] == 0
    # tests/evidence/README.md gate-probe convention: status describes the evidence, verdict the criterion.
    status = "verified" if complete else "in_progress"
    if all_pass and not partial:
        verdict = "pass"
    elif counts["fail"]:
        verdict = "fail"
    else:
        verdict = "inconclusive"
    limitations = list(STATIC_LIMITATIONS) + platform_limitations(args)
    if not complete:
        limitations.append("Evidence incomplete (status in_progress): partial selection, skipped or errored checks; "
                           "verdict %s." % verdict)
    if partial:
        limitations.append("Partial run (--only %s): %d of %d checks selected; cannot be 'verified'." %
                           (",".join(args.only), len(selected), len(CHECKS)))
    skipped = [r["id"] for r in results if r["outcome"] == "skipped"]
    if skipped:
        limitations.append("%d checks skipped (pyte unavailable): %s" % (len(skipped), ", ".join(skipped)))
    if max(loadavg_start + os.getloadavg()) > 0.75 * (os.cpu_count() or 1):
        limitations.append("Machine load was high during the run (load average %s on %s CPUs); timing-gated checks "
                           "(SIGINT 500 ms, resize 100 ms) may be unreliable - repeat on an idle machine before trusting a timing failure." %
                           ([round(x, 2) for x in loadavg_start + os.getloadavg()], os.cpu_count()))
    k3a = ctx.observations.get("k3a_reset_delivery") or {}
    if k3a and any(v != "ECONNRESET" for v in k3a.values()):
        limitations.append("K3a: on this OS (%s) the fake agent's connection reset (SO_LINGER 0 with the request unread) "
                           "reaches the reader as %s, not ECONNRESET (Darwin AF_UNIX stream sockets never report a "
                           "reset), so agent.reset_* exercised the EOF-equivalent path only; the ECONNRESET code path is "
                           "blocked_on: Linux host run." % (platform.system(), sorted(set(map(str, k3a.values())))))
    dup = ctx.observations.get(SIGNAL_MERGE_PROBE_KEY) or {}
    if dup and not dup.get("always_observable"):
        limitations.append("K6 exactly-once on %s: harness.signal_duplicate_probe (observations.%s: the harness's own "
                           "OS probe, not a heimdall-proto measurement) ran a known double-forwarding wrapper written by "
                           "the harness (two back-to-back kill() calls) and the child saw both signals in %s trials (deliveries per "
                           "trial %s); in the other trials the kernel merged them (standard signals do not queue). A "
                           "heimdall-proto that forwards twice back to back is therefore caught only probabilistically by "
                           "the run.forward_* / run.explicit_signal_with_tty exact-once assertions on this OS%s; the "
                           "assertions themselves are unchanged and judge what the child observes."
                           % (platform.system(), SIGNAL_MERGE_PROBE_KEY, dup.get("trials_with_duplicate"),
                              dup.get("deliveries_per_trial"),
                              " (here: not at all)" if not dup.get("duplicates_observable") else ""))
    failed = [r["id"] for r in results if r["outcome"] in ("fail", "error")]
    if failed:
        limitations.append("FAILED/ERRORED checks (see observed_result): " + ", ".join(failed))
    precond = [r["id"] for r in results if r["outcome"] == "error" and
               str(r.get("error") or "").startswith("harness precondition failed")]
    if precond:
        limitations.append("Harness precondition failed (environment/fixture, evidence invalid - not a candidate "
                           "result; fix the environment and repeat): " + ", ".join(precond))
    digest = None
    try:
        digest = "sha256:" + H.sha256_hex(Path(binpath).read_bytes())
    except OSError:
        pass
    if args.build_commit:
        build_commit = args.build_commit
    else:
        commit = git("rev-parse", "HEAD")
        dirty = git("status", "--porcelain")
        build_commit = (commit + ("+dirty" if dirty else "")) if commit else None
    ev_paths = [str(args.out)]
    if ctx.artifacts_dir.exists():
        ev_paths.append(str(ctx.artifacts_dir))
    ev_paths = [map_path(args, p) for p in ev_paths]
    ev_paths = [os.path.relpath(p, REPO) if str(p).startswith(str(REPO) + os.sep) else str(p) for p in ev_paths]
    environment = {
        "os": platform.system(), "os_release": platform.release(), "machine": platform.machine(),
        "platform": platform_label(), "platform_detail": platform.platform(), "python": sys.version.split()[0],
        "pyte": ("available" if ctx.pyte else "missing"),
        "harness_version": HARNESS_VERSION, "binary": map_path(args, str(binpath)), "candidate": args.candidate,
        "pty_size_default": "80x24", "sandbox": "private dir under /tmp, deleted after run",
        "cpu_count": os.cpu_count(), "loadavg_start": [round(x, 2) for x in loadavg_start],
        "loadavg_end": [round(x, 2) for x in os.getloadavg()],
    }
    if isinstance(args.environment_extra, dict):
        environment.update(args.environment_extra)
    rec = {
        "case_id": args.case_id,
        "status": status,
        "requirement_ids": [] if args.selftest else REQUIREMENTS,
        "build_commit": build_commit,
        "artifact_digest": digest,
        "environment": environment,
        "provider_versions": [
            {"name": "openssh (ssh-keygen used for fingerprints; version from /usr/bin/ssh -V)", "path": H.SSH_KEYGEN, "version": tool_version(["/usr/bin/ssh", "-V"])},
            {"name": "python", "version": sys.version.split()[0]},
            {"name": "pyte", "version": pkg_version("pyte") if ctx.pyte else None},
            {"name": "wcwidth", "version": pkg_version("wcwidth") if ctx.pyte else None},
        ],
        "started_at": started,
        "commands_or_harness": [
            " ".join([sys.executable, "tests/g02/conformance.py"] + sys.argv[1:]),
            "harness_lib.py / minischema.py / tests/fixtures/fake-agent/fake_agent.py (sha256 %s)" %
            H.sha256_hex(H.FAKE_AGENT.read_bytes()),
        ],
        "observed_result": {
            "verdict": verdict,
            "criterion": "every check of the full catalogue passes against docs/g02/slice-contract.md incl. section 9",
            "summary": dict(counts, total=len(results), duration_s=round(time.monotonic() - t_start, 1)),
            "checks": results,
            "observations": ctx.observations,
            "open_contract_questions": OPEN_QUESTIONS,
            "not_covered": ["native Windows (named pipe, CommandLineToArgvW, console Ctrl-C)", "WSL"]
            + (["linux-arm64 (separate record, K13)"] if platform_label().startswith("darwin") else
               ["darwin-arm64 (separate record, K13)"]),
        },
        "evidence_paths": ev_paths,
        "limitations": limitations,
    }
    return rec


def map_path(args, path):
    """Translate a path seen inside a container to the host path (--path-map CONTAINER=HOST)."""
    path = str(path)
    for c, h in getattr(args, "path_maps", []):
        if path == c or path.startswith(c.rstrip("/") + "/"):
            return h.rstrip("/") + path[len(c.rstrip("/")):]
    return path


def _walk_strings_with_path(obj, path="$"):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            ks = H.redact_bytes(str(k).encode("utf-8", "backslashreplace")).decode("utf-8", "replace")
            yield path + "." + ks + "<key>", str(k)
            yield from _walk_strings_with_path(v, path + "." + ks)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings_with_path(v, "%s[%d]" % (path, i))


def _redact_obj(obj, values):
    if isinstance(obj, str):
        return H.redact_values(obj.encode("utf-8", "surrogatepass"), values).decode("utf-8", "surrogatepass")
    if isinstance(obj, dict):
        return {_redact_obj(k, values): _redact_obj(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v, values) for v in obj]
    return obj


def canary_scan_record(ctx, rec):
    """[{json_path, canary label}] for every string in the record holding a full canary value."""
    hits = []
    for path, sv in _walk_strings_with_path(rec):
        for label in H.canary_hits(sv.encode("utf-8", "surrogatepass"), ctx.canaries):
            hits.append({"json_path": path[:200], "canary": label})
    return hits


def canary_scan_artifacts(ctx, before, redact=False):
    """Scan every artifact file this run wrote (tracked writes plus any new or modified file below the
    artifacts directory).  Returns (files_scanned, [{path, canary label}]); redact=True rewrites a
    leaking file with the values removed."""
    files = {Path(p) for p in ctx.written_artifacts}
    if ctx.artifacts_dir.exists():
        for p in ctx.artifacts_dir.rglob("*"):
            if p.is_file():
                try:
                    key = (str(p), p.stat().st_mtime_ns, p.stat().st_size)
                except OSError:
                    continue
                if key not in before:
                    files.add(p)
    hits = []
    for p in sorted(files):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        labels = H.canary_hits(data, ctx.canaries)
        for label in labels:
            hits.append({"path": os.path.relpath(p, ctx.artifacts_dir), "canary": label})
        if labels and redact:
            p.write_bytes(H.redact_values(data, ctx.canaries))
    return len(files), hits


def artifacts_snapshot(d):
    snap = set()
    if Path(d).exists():
        for p in Path(d).rglob("*"):
            if p.is_file():
                try:
                    snap.add((str(p), p.stat().st_mtime_ns, p.stat().st_size))
                except OSError:
                    pass
    return snap


def dumps_record(rec):
    try:
        text = json.dumps(rec, indent=2, ensure_ascii=False) + "\n"
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(rec, indent=2, ensure_ascii=True) + "\n"
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(description="G02 shared conformance harness")
    ap.add_argument("--bin")
    ap.add_argument("--candidate", choices=("go", "rust", "ts"))
    ap.add_argument("--out")
    ap.add_argument("--artifacts-dir")
    ap.add_argument("--only")
    ap.add_argument("--case-id", help="record case_id (default G02-<candidate>-conformance, "
                                      "G02-harness-selftest-<candidate> with --selftest)")
    ap.add_argument("--build-commit", help="build commit to record (default: git rev-parse HEAD of the repository)")
    ap.add_argument("--environment-extra", help="JSON object merged into the record's environment (Linux runner: "
                                                "container image, digests)")
    ap.add_argument("--path-map", action="append", default=[], metavar="CONTAINER=HOST",
                    help="translate container paths in evidence_paths/environment.binary to host paths")
    ap.add_argument("--pass-env", default="", help="comma list of harness env vars to pass to the binary (self-test only)")
    ap.add_argument("--selftest", action="store_true",
                    help="harness self-test run against reference_impl.py: record carries no requirement ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--list-md", action="store_true")
    args = ap.parse_args(argv)
    if args.list or args.list_md:
        rows = ordered_checks()
        if args.list:
            for c in rows:
                print(c[0])
        else:
            print("| Check id | Contract clause | What it asserts |\n|---|---|---|")
            for c in rows:
                print("| `%s` | %s | %s%s |" % (c[0], c[2], c[3].replace("|", "\\|"), " (needs pyte)" if c[4] else ""))
        return 0
    if os.name != "posix":
        print("conformance.py supports POSIX hosts only (Windows is blocked: needs a native Windows harness)", file=sys.stderr)
        return 2
    for need in ("bin", "candidate", "out"):
        if not getattr(args, need):
            ap.error("--%s is required" % need)
    try:
        args.environment_extra = json.loads(args.environment_extra) if args.environment_extra else None
    except ValueError:
        ap.error("--environment-extra must be a JSON object")
    if args.environment_extra is not None and not isinstance(args.environment_extra, dict):
        ap.error("--environment-extra must be a JSON object")
    args.path_maps = []
    for m in args.path_map:
        if "=" not in m:
            ap.error("--path-map needs CONTAINER=HOST")
        args.path_maps.append(tuple(m.split("=", 1)))
    harness_mutate = set(x for x in os.environ.get("HM_G02_HARNESS_MUTATE", "").split(",") if x)
    if harness_mutate and not args.selftest:
        print("HM_G02_HARNESS_MUTATE injects harness defects and is accepted only with --selftest", file=sys.stderr)
        return 2
    binpath = Path(args.bin).absolute()
    if not (binpath.is_file() and os.access(binpath, os.X_OK)):
        print("not an executable file: %s" % binpath, file=sys.stderr)
        return 2
    args.out = Path(args.out).absolute()
    args.only = [x for x in (args.only or "").split(",") if x]
    if not args.case_id:
        args.case_id = ("G02-harness-selftest-%s" % args.candidate) if args.selftest else \
            "G02-%s-conformance" % args.candidate
    artifacts = Path(args.artifacts_dir).absolute() if args.artifacts_dir else args.out.parent / "artifacts" / args.case_id
    artifacts.mkdir(parents=True, exist_ok=True)
    art_before = artifacts_snapshot(artifacts)
    H.normalize_signal_dispositions()
    selected, partial = select_checks(args.only)
    started = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    t_start = time.monotonic()
    loadavg_start = os.getloadavg()
    ctx = Ctx(binpath, args.candidate, artifacts, [x for x in args.pass_env.split(",") if x])
    ctx.harness_mutate = harness_mutate
    if "emulator_no_scroll" in harness_mutate:
        H.SCROLL_SUPPORT = False         # selftest: the round-5 emulator defect (g) re-injected

    def on_term(signum, frame):        # an outer timeout must not leak the sandbox
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, on_term)
    print("G02 conformance: candidate=%s platform=%s bin=%s checks=%d pyte=%s" % (
        args.candidate, platform_label(), binpath, len(selected), "yes" if ctx.pyte else "NO"), flush=True)
    try:
        results = run_checks(ctx, selected)
        rec = build_record(ctx, args, selected, partial, results, started, t_start, binpath, loadavg_start)
    finally:
        ctx.cleanup()
    if "canary_in_artifact" in ctx.harness_mutate:
        # selftest-only injected harness defect: an artifact written without redaction
        (artifacts / "harness-mutation-unredacted.txt").write_text("leak %s\n" % ctx.env_canary, encoding="utf-8")

    # ---- canary self-check (tests/evidence/README.md canary rule) ----
    rec_hits = canary_scan_record(ctx, rec)
    n_files, art_hits = canary_scan_artifacts(ctx, art_before, redact=True)
    serialised = H.canary_hits(dumps_record(rec).encode("utf-8"), ctx.canaries)
    if serialised and not rec_hits:      # a hit only the serialised form shows (escaping): still a leak
        rec_hits = [{"json_path": "(serialised record)", "canary": label} for label in serialised]
    leaked = bool(rec_hits or art_hits)
    ctx.observations["canary_selfcheck"] = {
        "registered_canaries": sorted(ctx.canaries.values()), "pattern": "the canary prefix followed by [A-Za-z0-9]",
        "artifact_files_scanned": n_files, "record_hits": rec_hits, "artifact_hits": art_hits,
        "result": "LEAK FOUND - values redacted, evidence invalid" if leaked else "clean"}
    if leaked:
        rec = _redact_obj(rec, ctx.canaries)
        rec["status"] = "in_progress"
        rec["observed_result"]["verdict"] = "inconclusive"
        rec["limitations"].append(
            "HARNESS DEFECT: the canary self-check found full canary values in this record (%d strings) and/or in "
            "artifacts written by this run (%d hits); they were redacted before writing and the evidence is invalid "
            "(observed_result.observations.canary_selfcheck lists the JSON paths, files and canary labels)."
            % (len(rec_hits), len(art_hits)))
    errs = minischema.validate(RECORD_SCHEMA, rec)
    if errs:
        print("INTERNAL: evidence record does not validate: %s" % errs[:5], file=sys.stderr)
        return 2
    text = dumps_record(rec)
    if H.canary_hits(text.encode("utf-8"), ctx.canaries):            # belt and braces before anything is written
        text = H.redact_values(text.encode("utf-8"), ctx.canaries).decode("utf-8")
        if not leaked:                   # cannot happen after the scans above; never write such a record as valid
            print("CANARY SELF-CHECK: unexpected canary in the serialised record; nothing written", file=sys.stderr)
            return EXIT_CANARY_SELFCHECK
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    written = H.canary_hits(args.out.read_bytes(), ctx.canaries)
    _n2, art_after = canary_scan_artifacts(ctx, art_before, redact=True)
    if written or art_after:
        try:
            args.out.unlink()
        except OSError:
            pass
        print("CANARY SELF-CHECK: the written record/artifacts still contain canary values (%s); record deleted" %
              sorted(set(written) | {h["canary"] for h in art_after}), file=sys.stderr)
        return EXIT_CANARY_SELFCHECK
    s = rec["observed_result"]["summary"]
    print("\nsummary: %s  status=%s verdict=%s  record=%s" % (
        {k: s[k] for k in ("total", "pass", "fail", "error", "skipped")}, rec["status"],
        rec["observed_result"]["verdict"], args.out), flush=True)
    if leaked:
        print("CANARY SELF-CHECK FAILED: %d record strings and %d artifact hits held full canary values (labels: %s); "
              "values were redacted before writing; exit %d" % (
                  len(rec_hits), len(art_hits), sorted({h["canary"] for h in rec_hits + art_hits}),
                  EXIT_CANARY_SELFCHECK), file=sys.stderr, flush=True)
        return EXIT_CANARY_SELFCHECK
    return 0 if (results and s["pass"] == s["total"]) else 1


if __name__ == "__main__":
    sys.exit(main())
