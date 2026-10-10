"""M00-T05-r4-x2-xrev-T3: shared driver, model simulator and screen oracle for the T3 cross-review probes.

Black-box: every probe runs a `heimdall-proto tui` binary in a pty (tests/g02 harness_lib PtySession, harness
2.4.2) and reads the screen through pyte with the same input normalisation as the hidden T3 tests (SGR colon
sub-parameters normalised; CSI-with-private-prefix 'm' sequences such as XTMODKEYS removed before pyte).

The oracle is the same for every build and both languages.  After every key it checks the whole screen:
  * not in help: the list rows are a contiguous run of the expected rows (prefix '> '/'  ', alias, and at
    width >= 50 '  account@host:port', truncated to the terminal width by display cells), starting at row 0,
    with no other text; the run holds the expected selection and is a full window (min(shown, rows));
    exactly the cells of the first case-insensitive filter match in the alias (and in the host when shown) are
    underlined, nothing else on screen is; the status row equals the language's status text, truncated;
  * in help: the nine help lines in order, one per row (when they fit), else a clipped prefix of them, and no
    destination alias on screen.
The expected selection follows spec T3 part C (cells) or contract K9 (baselines).  Only the window position is
left free (scrolling policy differs by design), but it must hold the selection and be full.
"""
import json
import os
import re
import signal
import shutil
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[7]
assert (REPO / "tests" / "g02" / "harness_lib.py").exists(), REPO
sys.path.insert(0, str(REPO / "tests" / "g02"))
import harness_lib as H  # noqa: E402
from wcwidth import wcwidth  # noqa: E402  (pyte's pinned dependency, tests/g02/.venv)

PYTE = H.load_pyte()
assert PYTE is not None, "run with tests/g02/.venv/bin/python"

INCOMPLETE_CSI = re.compile(rb"\x1b(\[[0-9;:?<=>]*[ -/]*)?$")
SGR = re.compile(rb"\x1b\[([0-9;:]*)m")
PRIVATE_M = re.compile(rb"\x1b\[[<=>?][0-9;:]*m")
HELP_LINES = ["Keys", "Up / k move up", "Down / j move down", "/ filter", "Enter select",
              "Esc clear filter", "q quit", "? close help", "Ctrl-C cancel"]


def _norm_sgr(m):
    out = []
    for p in m.group(1).split(b";"):
        if b":" in p:
            head, _, sub = p.partition(b":")
            if head == b"4":
                out.append(b"24" if sub in (b"0", b"") else b"4")
            continue
        out.append(p)
    return b"\x1b[" + b";".join(out) + b"m"


class Session(H.PtySession):
    """PtySession with the hidden T3 tests' emulator input normalisation (identical code), plus two emulator
    fixes applied to every build alike: pyte 0.8.2 binds HPA to "'" instead of "`" (ECMA-48/xterm CSI Pn `), so
    it ignores HPA; and it does not implement REP (CSI Pn b, repeat the preceding graphic character).  Bubble
    Tea's renderer emits both for some TERM values (csi_audit.py); without these fixes the emulated screen is
    wrong where a real xterm-compatible terminal is right."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        scr = self.screen
        orig_draw = scr.draw
        state = {"last": None}

        def draw(data):
            orig_draw(data)
            for ch in reversed(data):
                if wcwidth(ch) > 0:
                    state["last"] = ch
                    break

        def repeat_last(*params, private=False):
            if private or not state["last"]:
                return
            orig_draw(state["last"] * max(params[0] if params else 1, 1))

        scr.draw = draw
        scr.repeat_last = repeat_last
        base = type(self.stream)

        class _Stream(base):
            csi = dict(base.csi, **{"`": "cursor_to_column", "b": "repeat_last"})
            events = frozenset(base.events | {"repeat_last"})

        self.stream = _Stream(scr)

    def _feed(self, data):
        self.raw += data
        buf = getattr(self, "_pend", b"") + data
        m = INCOMPLETE_CSI.search(buf)
        self._pend = buf[m.start():] if m else b""
        buf = buf[:m.start()] if m else buf
        try:
            self.stream.feed(SGR.sub(_norm_sgr, PRIVATE_M.sub(b"", buf)))
        except Exception as exc:  # noqa
            self.feed_errors.append(repr(exc)[:200])


# ------------------------------------------------------------------ profiles (disposable fixtures)
class Dest:
    def __init__(self, alias, account, host, port=22):
        self.alias, self.account, self.host, self.port = alias, account, host, port


def toml_str(s):
    out = []
    for ch in s:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7f or not ch.isprintable() and unicodedata.category(ch) in ("Cc",):
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def write_profile(path, dests, name="probe"):
    lines = ["schema_version = 1", 'name = "%s"' % name, "revision = 1", ""]
    for i, d in enumerate(dests):
        lines += ["[[destinations]]", 'id = "dst_%03d"' % i, "alias = " + toml_str(d.alias),
                  "host = " + toml_str(d.host), "port = %d" % d.port, "account = " + toml_str(d.account), ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def load_fixture(name):
    import tomllib
    with open(REPO / "tests" / "fixtures" / "g02" / "profiles" / name, "rb") as fh:
        t = tomllib.load(fh)
    return [Dest(d["alias"], d["account"], d["host"], d.get("port", 22)) for d in t["destinations"]]


PROFILES = {
    "homelab": lambda: load_fixture("homelab.toml"),
    "large100": lambda: load_fixture("large-100.toml"),
    "long": lambda: [
        Dest("alpha-very-long-alias-name-for-truncation-tests-xyz", "operator",
             "deep.sub.domain.very-long-hostname.example.internal", 65535),
        Dest("東京東京東京東京東京東京東京東京", "user", "tokyo.東京.example.jp", 2222),
        Dest("beta", "b", "beta.example", 22),
        Dest("ab東c", "u", "x東y.example", 22),
    ],
    "wide": lambda: [
        Dest("東京-サーバー-本番", "deploy", "db.東京.example", 22),
        Dest("lab-server", "aman", "lab.example.internal", 22),
        Dest("大阪", "ops", "osaka.example.jp", 2200),
        Dest("nas", "admin", "nas.example.internal", 22),
        Dest("名古屋-backup-東", "root", "ngy.example.invalid", 22),
    ],
    "uni": lambda: [
        Dest("cafe\u0301-bar", "u", "cafe.example", 22),
        Dest("\u039f\u0394\u039f\u03a3", "u", "greek.example", 22),
        Dest("\u0130stanbul", "u", "ist.example", 22),
        Dest("\uff26\uff35\uff2c\uff2c-w", "u", "fw.example", 22),
        Dest("plain", "u", "plain.example", 22),
    ],
    # zero-width / bidi code points: pyte 0.8.2 stops drawing a chunk at a zero-width non-combining character,
    # so this profile is judged by process state and raw bytes only (contract 9.2: not gated)
    "zw": lambda: [
        Dest("dev-\U0001F469\u200d\U0001F4BB-box", "u", "dev.example", 22),
        Dest("rtl-\u202eabc-x", "u", "rtl.example", 22),
        Dest("zw\u200bsp-y", "u", "zw.example", 22),
        Dest("plain", "u", "plain.example", 22),
    ],
}


# ------------------------------------------------------------------ model simulator (spec T3 / contract §5)
def lower(s, lang):
    """The prototype's filter lowering: Rust str::to_lowercase (full Unicode, final sigma, like Python's str.lower);
    Go strings.ToLower (rune by rune, simple case mapping: U+0130 -> 'i', no final-sigma rule)."""
    if lang == "rust":
        return s.lower()
    return "".join("i" if c == "\u0130" else (c.lower() if len(c.lower()) == 1 else c) for c in s)


def match_chars(text, f, lang):
    """Char indices of `text` in the first case-insensitive occurrence of f (whole characters)."""
    if not f:
        return set()
    whole, fl = lower(text, lang), lower(f, lang)
    pos = whole.find(fl)
    if pos < 0:
        return set()
    out, lo = set(), 0
    for i, c in enumerate(text):
        n = len(lower(c, lang))
        if lo < pos + len(fl) and lo + n > pos:
            out.add(i)
        lo += n
    return out


class Sim:
    def __init__(self, dests, rule="C", help_ok=True, lang="go"):
        self.d = dests
        self.f = ""
        self.filtering = False
        self.help = False
        self.shown = list(range(len(dests)))
        self.sel = 0 if dests else None      # destination index (None: nothing shown)
        self.rule = rule                     # "C" (T3 part C) or "K9" (baseline)
        self.help_ok = help_ok
        self.lang = lang
        self.exit = None                     # ("rc", n) or ("selected", alias)

    def matches(self, i, f):
        fl = lower(f, self.lang)
        return fl == "" or fl in lower(self.d[i].alias, self.lang) or fl in lower(self.d[i].host, self.lang)

    def refilter(self):
        prev = self.sel if self.shown else None
        self.shown = [i for i in range(len(self.d)) if self.matches(i, self.f)]
        if self.rule == "C" and prev is not None and prev in self.shown:
            self.sel = prev
        else:
            self.sel = self.shown[0] if self.shown else None

    def move(self, delta):
        if not self.shown:
            return
        p = max(0, min(len(self.shown) - 1, self.shown.index(self.sel) + delta))
        self.sel = self.shown[p]

    def key(self, k):
        if self.exit:
            return
        if k == "ctrl-c":
            self.exit = ("rc", 130)
            return
        if self.help:
            if k in ("esc", "?"):
                self.help = False
            return
        if k in ("up", "down"):
            self.move(-1 if k == "up" else 1)
            return
        if self.filtering:
            if k == "enter":
                self.filtering = False
            elif k == "esc":
                self.filtering = False
                self.f = ""
                self.refilter()
            elif k == "bs":
                if self.f:
                    self.f = self.f[:-1]
                    self.refilter()
                elif self.lang == "rust" and self.rule == "K9":
                    self.refilter()
            elif len(k) == 1 and k.isprintable():
                self.f += k
                self.refilter()
            return
        if k == "enter":
            if self.shown:
                self.exit = ("selected", self.d[self.sel].alias)
        elif k == "k":
            self.move(-1)
        elif k == "j":
            self.move(1)
        elif k == "/":
            self.filtering = True
        elif k == "?" and self.help_ok:
            self.help = True
        elif k == "q":
            self.exit = ("rc", 0)

    def status(self, w):
        n, t = len(self.shown), len(self.d)
        if self.lang == "go":
            s = "%d/%d" % (n, t) + (" /" + self.f if self.filtering else (" filter:" + self.f if self.f else ""))
        else:
            s = "%d/%d" % (n, t) + ("  /" + self.f if self.filtering else ("  filter: " + self.f if self.f else ""))
        return truncate(s, w)[0]


def cw(ch):
    w = wcwidth(ch)
    return max(w, 0)


def truncate(s, w):
    """(visible text, [(char_index, column)]) of s cut to w display cells (a wide char that does not fit is dropped)."""
    out, cols, x = [], [], 0
    for i, ch in enumerate(s):
        c = cw(ch)
        if x + c > w:
            break
        out.append(ch)
        cols.append((i, x))
        x += c
    return "".join(out), cols


def expected_row(sim, i, w, underline=True):
    d = sim.d[i]
    prefix = "> " if i == sim.sel else "  "
    full = prefix + d.alias
    f = sim.f if underline else ""
    marked = {2 + i for i in match_chars(d.alias, f, sim.lang)}
    if w >= 50:
        head = full + "  " + d.account + "@"
        full = head + d.host + ":%d" % d.port
        marked |= {len(head) + i for i in match_chars(d.host, f, sim.lang)}
    text, cols = truncate(full, w)
    ul = sorted(x for (ci, x) in cols if ci in marked and cw(full[ci]) > 0)
    return _canon(text.rstrip()), ul


STRIP_MN = False   # P11 only: compare rows without combining marks (the Go baseline renderer drops them; P15 records it)


def _canon(t):
    t = unicodedata.normalize("NFC", t)
    if STRIP_MN:
        t = "".join(c for c in unicodedata.normalize("NFD", t) if unicodedata.category(c) != "Mn")
        t = unicodedata.normalize("NFC", t)
    return t


def screen_rows(s):
    return [_canon(l.rstrip()) for l in s.screen.display]


def underlined_cols(s, y):
    row = s.screen.buffer[y]
    return sorted(x for x in range(s.screen.columns) if row[x].data != "" and row[x].underscore)


def norm(l):
    return " ".join(l.split())


def check_screen(s, sim, rows, cols, lang, help_layout):
    """Return a list of issue strings (empty = the screen is what the oracle expects)."""
    issues = []
    lines = screen_rows(s)
    if len(lines) != rows:
        return ["screen has %d rows, expected %d" % (len(lines), rows)]
    if sim.help:
        vis = rows if help_layout == "full" else rows - 1
        body = [norm(l) for l in lines[:vis]]
        if vis >= 9 and cols >= 30:
            pos = []
            for want in HELP_LINES:
                cand = [y for y, l in enumerate(body) if want in l and (not pos or y > pos[-1])]
                if not cand:
                    issues.append("help line %r missing or out of order" % want)
                    break
                pos.append(cand[0])
        else:
            nonempty = [l for l in body if l]
            for k, l in enumerate(nonempty):
                if k >= len(HELP_LINES) or not norm(HELP_LINES[k]).startswith(l):
                    issues.append("clipped help row %d %r is not a prefix of %r" % (k, l, HELP_LINES[k] if k < 9 else None))
                    break
        for d in sim.d:
            # the help area only: the Go cells keep the status line (which may show the filter text) below it
            if len(d.alias) >= 3 and any(d.alias in l for l in lines[:vis]):
                issues.append("alias %r visible while help is open" % d.alias)
                break
        return issues
    nrows = rows - 1
    want_n = min(len(sim.shown), max(nrows, 0))
    list_lines = lines[:nrows]
    k = 0
    while k < nrows and list_lines[k] != "":
        k += 1
    if any(l != "" for l in list_lines[k:]):
        issues.append("non-empty list row after a blank one: %r" % [l for l in list_lines[k:] if l][:2])
    if k != want_n:
        issues.append("list shows %d rows, expected a full window of %d" % (k, want_n))
    exp_rows = [expected_row(sim, i, cols) for i in sim.shown]
    if cols <= 2:
        # an unselected row is only its two-space prefix: blank rows are expected, check the status only
        issues = [i for i in issues if not i.startswith(("list shows", "non-empty list row"))]
        k = 0
    start = None
    if k > len(exp_rows):
        issues.append("%d list rows on screen but only %d destinations shown" % (k, len(exp_rows)))
    else:
        for j in range(0, len(exp_rows) - k + 1):
            if all(list_lines[y] == exp_rows[j + y][0] for y in range(k)):
                start = j
                break
    if k and start is None and k <= len(exp_rows):
        # report the first differing row against the window that holds the selection
        issues.append("rows do not match any contiguous window of the expected rows; first rows %r; expected e.g. %r"
                      % (list_lines[:min(k, 3)], [r[0] for r in exp_rows[:3]]))
    elif k and start is not None:
        win = sim.shown[start:start + k]
        if sim.sel not in win:
            issues.append("selected %r not in the visible window" % sim.d[sim.sel].alias if sim.sel is not None else "")
        for y in range(k):
            got = underlined_cols(s, y)
            want = exp_rows[start + y][1]
            if got != want:
                issues.append("row %d %r underline cols %s, expected %s" % (y, list_lines[y], got, want))
    for y in range(k, rows):
        got = underlined_cols(s, y)
        if got:
            issues.append("row %d (not a list row) has underlined cols %s" % (y, got))
    st = lines[rows - 1] if rows >= 1 else ""
    if nrows >= 0 and st != sim.status(cols).rstrip():
        issues.append("status %r, expected %r" % (st, sim.status(cols).rstrip()))
    return issues


# ------------------------------------------------------------------ runner
KEYS = {"up": "up", "down": "down", "enter": "enter", "esc": "esc", "bs": "backspace", "ctrl-c": "ctrl-c"}


class Run:
    """One pty session of one build, with the simulator and a step log."""

    def __init__(self, build, binpath, lang, profile, rows=24, cols=80, env=None, rule="C", help_ok=True,
                 help_layout=None, underline=True):
        self.build, self.lang = build, lang
        self.sandbox = Path(tempfile.mkdtemp(prefix="hm-xrevT3-", dir="/tmp"))
        (self.sandbox / "home").mkdir()
        (self.sandbox / "tmp").mkdir()
        self.dests = PROFILES[profile]()
        self.pfile = self.sandbox / ("%s.toml" % profile)
        write_profile(self.pfile, self.dests, profile)
        e = {"PATH": "/usr/bin:/bin", "HOME": str(self.sandbox / "home"), "LANG": "en_US.UTF-8",
             "LC_ALL": "en_US.UTF-8", "TMPDIR": str(self.sandbox / "tmp"), "TERM": "xterm-256color"}
        for k, v in (env or {}).items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
        self.rows, self.cols = rows, cols
        self.sim = Sim(self.dests, rule=rule, help_ok=help_ok, lang=lang)
        self.underline = underline
        self.help_layout = help_layout or ("full" if lang == "rust" else "list")
        self.steps = []
        self.s = Session(PYTE, [binpath, "tui", "--file", str(self.pfile)], e, str(self.sandbox), rows, cols)

    def issues(self):
        sim = self.sim
        if not self.underline:
            saved = sim.f
            # baseline: expected screen has no underline; the oracle still expects the filter text in the status
            iss = check_screen_no_ul(self.s, sim, self.rows, self.cols, self.lang, self.help_layout)
            sim.f = saved
            return iss
        return check_screen(self.s, sim, self.rows, self.cols, self.lang, self.help_layout)

    def wait_ok(self, label, timeout=2.0, settle=0.25, record_screen=False):
        t0 = time.monotonic()
        ok_at = self.s.wait_for(lambda x: not self.issues(), timeout)
        self.s.settle(settle)
        iss = self.issues()
        step = {"step": label, "ok": not iss, "first_ok_ms": None if ok_at is None else round(ok_at * 1000),
                "size": "%dx%d" % (self.cols, self.rows), "filter": self.sim.f, "filtering": self.sim.filtering,
                "help": self.sim.help,
                "selected": None if self.sim.sel is None else self.dests[self.sim.sel].alias}
        if iss:
            step["issues"] = iss[:6]
        if iss or record_screen:
            step["screen"] = screen_rows(self.s)
            step["underlined"] = {y: underlined_cols(self.s, y) for y in range(self.rows) if underlined_cols(self.s, y)}
        alive = self.s.poll() is None
        if not alive:
            step["exited_rc"] = self.s.rc
        self.steps.append(step)
        return not iss

    def start(self):
        return self.wait_ok("start", timeout=10.0)

    def key(self, k, label=None):
        if k in KEYS:
            self.s.key(KEYS[k])
        else:
            self.s.send(k)
        self.sim.key(k)
        if k == "esc":
            self.s.settle(0.08)
        if self.sim.exit:
            return self.finish_exit(label or k)
        return self.wait_ok(label or ("key %r" % k))

    def keys(self, seq):
        ok = True
        for k in seq:
            ok = self.key(k) and ok
            if self.sim.exit:
                break
        return ok

    def batch(self, ks, label=None):
        """Send several keys in one write; check only the final state."""
        data = b""
        app = H.final_state(bytes(self.s.raw))["app_cursor_keys"]
        tab = {"up": b"\x1bOA" if app else b"\x1b[A", "down": b"\x1bOB" if app else b"\x1b[B", "esc": b"\x1b",
               "enter": b"\r", "bs": b"\x7f", "ctrl-c": b"\x03"}
        for k in ks:
            data += tab[k] if k in tab else k.encode("utf-8")
            self.sim.key(k)
        self.s.send(data)
        if self.sim.exit:
            return self.finish_exit(label or "batch %r" % ks)
        return self.wait_ok(label or "batch %r" % (ks,))

    def resize(self, rows, cols, label=None):
        self.rows, self.cols = rows, cols
        self.s.resize(rows, cols)
        self.s.signal(signal.SIGWINCH)
        return self.wait_ok(label or "resize %dx%d" % (cols, rows))

    def alive_after(self, label, secs=0.4):
        self.s.settle(secs)
        alive = self.s.poll() is None
        self.steps.append({"step": label, "ok": alive, "alive": alive, "rc": self.s.rc,
                           "stderr_tail": H.redact_bytes(self.s.stderr_bytes())[-300:].decode("utf-8", "replace")
                           if not alive else None})
        return alive

    def restore_report(self):
        raw = bytes(self.s.raw)
        st = H.final_state(raw)
        tail = H.tail_after_restore(raw)
        try:
            termios_ok = H.normalize_termios(self.s.termios_after()) == H.normalize_termios(self.s.attr_before)
        except Exception as exc:  # noqa
            termios_ok = "n/a: %r" % exc
        return {"alt_left": not st["alt_active_at_end"], "cursor_shown": not st["cursor_hidden_at_end"],
                "termios_restored": termios_ok, "bad_tail": [b.decode("latin-1") for b in H.disallowed_tail_sequences(tail)][:4]}

    def finish_exit(self, label, expect_rc=None, expect_stdout=None):
        kind, val = self.sim.exit if self.sim.exit else ("rc", expect_rc)
        rc = self.s.wait_exit(3.0)
        raw = bytes(self.s.raw)
        rep = self.restore_report()
        exp_rc = 0 if kind == "selected" else val
        sel_line = ("SELECTED %s" % val).encode() if kind == "selected" else None
        ok = (rc == exp_rc and rep["alt_left"] and rep["cursor_shown"] and rep["termios_restored"] is True
              and not rep["bad_tail"])
        if sel_line is not None:
            ok = ok and raw.rstrip().endswith(sel_line)
        else:
            ok = ok and b"SELECTED" not in raw
        self.steps.append({"step": label, "ok": ok, "rc": rc, "expected_rc": exp_rc, "restore": rep,
                           "selected_line": sel_line.decode() if sel_line else None,
                           "stdout_has_selected": b"SELECTED" in raw})
        return ok

    def signal_exit(self, sig, expect_rc, label):
        self.s.signal(sig)
        rc = self.s.wait_exit(3.0)
        rep = self.restore_report()
        raw = bytes(self.s.raw)
        ok = rc == expect_rc and rep["alt_left"] and rep["cursor_shown"] and rep["termios_restored"] is True \
            and not rep["bad_tail"] and b"SELECTED" not in raw
        self.steps.append({"step": label, "ok": ok, "rc": rc, "expected_rc": expect_rc, "restore": rep})
        return ok

    def hangup_exit(self, expect_rc, label):
        rc = self.s.hangup(5.0)
        self.steps.append({"step": label, "ok": rc == expect_rc, "rc": rc, "expected_rc": expect_rc})
        return rc == expect_rc

    def close(self):
        if self.s.poll() is None:
            try:
                self.s.send(b"\x03")
            except Exception:  # noqa
                pass
            self.s.wait_exit(2.0)
        left = self.s.close()
        H.rm_tree(self.sandbox) if hasattr(H, "rm_tree") else shutil.rmtree(self.sandbox, ignore_errors=True)
        return left

    def colour_sgr(self):
        return [h.decode("latin-1") for h in H.color_sgr_found(bytes(self.s.raw))][:5]

    def raw_has(self, pat):
        return re.search(pat, bytes(self.s.raw)) is not None


def check_screen_no_ul(s, sim, rows, cols, lang, help_layout):
    """Baseline oracle: like check_screen, but no cell may be underlined at all."""
    iss = []
    # run the normal oracle with an empty filter for the underline part only
    class _V:
        pass
    real = check_screen(s, sim, rows, cols, lang, help_layout)
    for i in real:
        if "underline cols" in i:
            m = re.search(r"underline cols (\[[^\]]*\])", i)
            if m and m.group(1) != "[]":
                iss.append(i)
            continue
        iss.append(i)
    return iss
