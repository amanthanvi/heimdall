"""T3 hidden tests: TUI filter highlight, '?' help overlay, selection kept across filter edits (specs/T3.md).

Terminal: the harness's pty + pyte emulator (vendor/harness_lib.py).  Underline is read from pyte's
per-cell `underscore` attribute.  SGR colon sub-parameters (ITU T.416 style, e.g. 4:1 for a single
underline) are normalised before they reach pyte, so any standard underline encoding counts.
"""
import re
import shutil
import signal
import time
from pathlib import Path

import hm
from hm import check, Abort

T = "T3"
FIXDIR = Path(__file__).resolve().parent.parent / "t2" / "fixtures"
HOMELAB = FIXDIR / "clean.toml"            # byte copy of tests/fixtures/g02/profiles/homelab.toml
DESTS = [("lab-server", "aman", "lab.example.internal", 22),
         ("nas", "admin", "nas.example.internal", 22),
         ("vps-東京", "deploy", "vps1.example.invalid", 2222)]
ALIASES = [d[0] for d in DESTS]
HELP_LINES = ["Keys", "Up / k move up", "Down / j move down", "/ filter", "Enter select",
              "Esc clear filter", "q quit", "? close help", "Ctrl-C cancel"]
HELP_MARKERS = ("move down", "close help", "clear filter")
STATUS_RE = re.compile(r"(?<![\d.])(\d+)/(\d+)(?!\d)")
BOX = "─-╿"
INCOMPLETE_CSI = re.compile(rb"\x1b(\[[0-9;:?<=>]*[ -/]*)?$")
SGR = re.compile(rb"\x1b\[([0-9;:]*)m")
# CSI with a private prefix and final 'm' is not SGR (e.g. XTMODKEYS "CSI > 4 ; 2 m", which Bubble Tea v2 emits);
# pyte 0.8.2 would apply it as SGR 4 (underline).  Removed before the emulator sees it.
PRIVATE_M = re.compile(rb"\x1b\[[<=>?][0-9;:]*m")


def _norm_sgr(m):
    out = []
    for p in m.group(1).split(b";"):
        if b":" in p:
            head, _, sub = p.partition(b":")
            if head == b"4":
                out.append(b"24" if sub in (b"0", b"") else b"4")
            # other colon forms (38:2:..., 58:...) are colours: irrelevant here, dropped
            continue
        out.append(p)
    return b"\x1b[" + b";".join(out) + b"m"


class Session(hm.H.PtySession):
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


def start(t, ctx, profile=HOMELAB, rows=24, cols=80, env=None, expect=None):
    p = ctx.new_dir("prof") / Path(profile).name
    shutil.copyfile(profile, p)
    s = Session(ctx.pyte, [ctx.bin, "tui", "--file", str(p)], ctx.env(env), str(ctx.sandbox), rows, cols)
    ctx.sessions = getattr(ctx, "sessions", []) + [s]
    pred = expect or (lambda x: all(a in x.text() for a in ALIASES) and status_of(x) == (3, 3))
    if s.wait_for(pred, 10.0) is None:
        t.check("first frame within 10 s", False, "frame", "screen=%r rc=%r" % (s.text()[:300], s.poll()))
        s.close()
        raise Abort("no first frame")
    s.settle(0.15)
    return s


def status_of(s):
    for line in reversed(s.lines()):
        m = STATUS_RE.search(line)
        if m:
            return int(m.group(1)), int(m.group(2))
    return None


def has_status(a, b):
    return lambda s: status_of(s) == (a, b)


def row_cells(s, y):
    """[(x, ch)] of the non-stub cells of screen row y."""
    row = s.screen.buffer[y]
    return [(x, row[x].data) for x in range(s.screen.columns) if row[x].data != ""]


def find_row(s, alias):
    """(y, cells, p): first row whose text has `alias` right after a 2-character prefix ('> ' or '  ')."""
    for y in range(s.screen.lines):
        cells = row_cells(s, y)
        text = "".join(ch for _, ch in cells)
        p = text.find(alias)
        while p >= 0:
            pre = re.sub("^[%s]" % BOX, "", text[:p])
            if pre[-2:] in ("> ", "  ") and pre[:-2].strip() == "":
                return y, cells, p
            p = text.find(alias, p + 1)
    return None, None, None


def prefix_of(s, alias):
    y, cells, p = find_row(s, alias)
    if y is None:
        return None
    return "".join(ch for _, ch in cells)[p - 2:p]


def underlined(s, y):
    row = s.screen.buffer[y]
    return sorted(x for x in range(s.screen.columns) if row[x].data != "" and row[x].underscore)


def expected_ul(cells, p, dest, flt, with_host):
    alias, account, host, port = dest
    text = "".join(ch for _, ch in cells)
    f = flt.lower()
    exp = set()
    i = alias.lower().find(f)
    if f and i >= 0:
        exp |= {cells[p + k][0] for k in range(i, i + len(f))}
    if f and with_host:
        h = text.find("@" + host + ":", p + len(alias))
        j = host.lower().find(f)
        if h >= 0 and j >= 0:
            exp |= {cells[h + 1 + k][0] for k in range(j, j + len(f))}
    return sorted(exp)


def check_highlight(t, s, flt, shown, with_host=True, label=""):
    """Every shown row: exactly the cells of the first match in alias (and host when shown) are underlined."""
    for dest in DESTS:
        y, cells, p = find_row(s, dest[0])
        if dest[0] not in shown:
            t.check("%s row %s not shown" % (label, dest[0]), y is None, "absent", "present")
            continue
        if y is None:
            t.check("%s row %s on screen" % (label, dest[0]), False, "present", s.lines())
            continue
        if with_host:
            t.check("%s row %s shows account@host:port" % (label, dest[0]),
                    ("@" + dest[2] + ":") in "".join(ch for _, ch in cells), "host shown", "".join(ch for _, ch in cells))
        exp = expected_ul(cells, p, dest, flt, with_host)
        t.eq("%s row %s: underlined columns for filter %r" % (label, dest[0], flt), underlined(s, y), exp)


def wait_ul(s, flt, shown, with_host=True, timeout=3.0):
    """Wait until the underline state matches (renderers may draw in more than one write)."""
    def ok(x):
        for dest in DESTS:
            y, cells, p = find_row(x, dest[0])
            if (dest[0] in shown) != (y is not None):
                return False
            if y is not None and underlined(x, y) != expected_ul(cells, p, dest, flt, with_host):
                return False
        return True
    s.wait_for(ok, timeout)
    s.settle(0.1)


def finish(t, s, ok_exit=0):
    if s.poll() is None:
        s.send(b"\x03")
        s.wait_exit(3.0)
    s.close()


def typ(s, text, gap=0.05):
    for ch in text:
        s.send(ch)
        s.settle(gap)


# ---------------------------------------------------------------- highlight
@check(T, "T3.no_highlight_without_filter", "no list cell is underlined while the filter is empty")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.key("down")
        s.settle(0.3)
        check_highlight(t, s, "", ALIASES)
        s.send("/")
        s.settle(0.3)
        check_highlight(t, s, "", ALIASES, label="[filter mode, empty filter]")
    finally:
        finish(t, s)


@check(T, "T3.highlight_single_char", "filter 'a': first match in alias and in host underlined, account not")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("/")
        s.settle(0.1)
        s.send("a")
        s.wait_for(has_status(3, 3), 3.0)
        wait_ul(s, "a", ALIASES)
        check_highlight(t, s, "a", ALIASES)
    finally:
        finish(t, s)


@check(T, "T3.highlight_case_insensitive", "filters 'LAB' and 'EXAMPLE': case-insensitive match underlined")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("/")
        typ(s, "LAB")
        t.check("'LAB' shows 1/3", s.wait_for(has_status(1, 3), 3.0) is not None, "1/3", status_of(s))
        wait_ul(s, "LAB", ["lab-server"])
        check_highlight(t, s, "LAB", ["lab-server"], label="[LAB]")
        for _ in range(3):
            s.key("backspace")
            s.settle(0.05)
        typ(s, "EXAMPLE")
        t.check("'EXAMPLE' shows 3/3", s.wait_for(has_status(3, 3), 3.0) is not None, "3/3", status_of(s))
        wait_ul(s, "EXAMPLE", ALIASES)
        check_highlight(t, s, "EXAMPLE", ALIASES, label="[EXAMPLE]")
    finally:
        finish(t, s)


@check(T, "T3.highlight_wide_chars", "filter '東' underlines the double-width match only")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("/")
        s.settle(0.1)
        s.send("東")
        t.check("'東' shows 1/3", s.wait_for(has_status(1, 3), 3.0) is not None, "1/3", status_of(s))
        wait_ul(s, "東", ["vps-東京"])
        check_highlight(t, s, "東", ["vps-東京"])
    finally:
        finish(t, s)


@check(T, "T3.highlight_after_enter_and_esc", "highlight stays after Enter (filter kept), disappears after Esc clear")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("/")
        typ(s, "as")
        s.wait_for(has_status(1, 3), 3.0)
        s.key("enter")
        s.settle(0.3)
        wait_ul(s, "as", ["nas"])
        check_highlight(t, s, "as", ["nas"], label="[after Enter]")
        s.send("/")
        s.settle(0.1)
        s.key("esc")
        t.check("Esc shows 3/3", s.wait_for(has_status(3, 3), 3.0) is not None, "3/3", status_of(s))
        wait_ul(s, "", ALIASES)
        check_highlight(t, s, "", ALIASES, label="[after Esc]")
    finally:
        finish(t, s)


@check(T, "T3.highlight_narrow", "width < 50: only the alias is shown and only its match is underlined")
def _(t, ctx):
    s = start(t, ctx, cols=40)
    try:
        s.send("/")
        s.settle(0.1)
        s.send("a")
        s.wait_for(has_status(3, 3), 3.0)
        wait_ul(s, "a", ALIASES, with_host=False)
        for dest in DESTS:
            y, cells, p = find_row(s, dest[0])
            t.check("row %s has no host" % dest[0], y is not None and "@" not in "".join(ch for _, ch in cells),
                    "alias only", None if y is None else "".join(ch for _, ch in cells))
        check_highlight(t, s, "a", ALIASES, with_host=False)
    finally:
        finish(t, s)


@check(T, "T3.highlight_no_color", "NO_COLOR=1: the match is still underlined; no colour SGR in the session")
def _(t, ctx):
    s = start(t, ctx, env={"NO_COLOR": "1"})
    try:
        t.eq("selection is not colour-only: the selected row carries '> '", prefix_of(s, "lab-server"), "> ")
        s.send("/")
        s.settle(0.1)
        s.send("e")
        s.wait_for(has_status(3, 3), 3.0)
        wait_ul(s, "e", ALIASES)
        check_highlight(t, s, "e", ALIASES)
        s.key("esc")
        s.settle(0.2)
        s.send("q")
        t.eq("q exits 0", s.wait_exit(3.0), 0)
        hits = hm.H.color_sgr_found(bytes(s.raw))
        t.check("no colour SGR", not hits, "none", [h.decode("latin-1") for h in hits[:5]])
    finally:
        finish(t, s)


# ---------------------------------------------------------------- help overlay
def help_shown(s):
    lines = [" ".join(l.split()) for l in s.lines()]
    pos = []
    for want in HELP_LINES:
        rows = [y for y, l in enumerate(lines) if want in l and y not in pos]
        rows = [y for y in rows if not pos or y > pos[-1]]
        if not rows:
            return False
        pos.append(rows[0])
    return True


def help_gone(s):
    txt = " ".join(s.text().split())
    return not any(m in txt for m in HELP_MARKERS)


def check_help_lines(t, s):
    ok = s.wait_for(help_shown, 3.0) is not None
    t.check("help overlay shows every key line in order", ok, HELP_LINES, s.lines())
    return ok


@check(T, "T3.help_toggle", "'?' opens the help overlay; '?' closes it; list and selection unchanged")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.key("down")
        s.wait_for(lambda x: prefix_of(x, "nas") == "> ", 3.0)
        s.send("?")
        check_help_lines(t, s)
        s.send("?")
        t.check("second '?' closes the overlay", s.wait_for(help_gone, 3.0) is not None, "closed", s.lines())
        s.wait_for(lambda x: all(a in x.text() for a in ALIASES), 3.0)
        s.settle(0.2)
        t.eq("selection unchanged ('> nas')", prefix_of(s, "nas"), "> ")
        t.eq("status 3/3", status_of(s), (3, 3))
        s.key("enter")
        t.eq("Enter selects nas: exit 0", s.wait_exit(3.0), 0)
        t.check("stdout ends with 'SELECTED nas'", bytes(s.raw).rstrip().endswith(b"SELECTED nas"),
                "SELECTED nas", bytes(s.raw)[-60:].decode("utf-8", "replace"))
    finally:
        finish(t, s)


@check(T, "T3.help_esc_keeps_filter", "Esc closes the overlay without clearing an active filter")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("/")
        typ(s, "nas")
        s.wait_for(has_status(1, 3), 3.0)
        s.key("enter")
        s.settle(0.2)
        s.send("?")
        check_help_lines(t, s)
        s.key("esc")
        t.check("Esc closes the overlay", s.wait_for(help_gone, 3.0) is not None, "closed", s.lines())
        s.settle(0.3)
        t.eq("filter still active: status 1/3", status_of(s), (1, 3))
        t.check("filter text 'nas' still on the status line",
                any(STATUS_RE.search(l) and "nas" in l for l in s.lines()), "nas", s.lines()[-3:])
    finally:
        finish(t, s)


@check(T, "T3.help_ignores_other_keys", "while the overlay is open, j/k/q/Enter/'/'/Down do nothing")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("?")
        if not check_help_lines(t, s):
            raise Abort("no help")
        for k in ("j", "q", "/", "k"):
            s.send(k)
            s.settle(0.15)
        s.key("down")
        s.settle(0.15)
        s.key("enter")
        s.settle(0.4)
        t.eq("process still running", s.poll(), None)
        t.check("overlay still open", help_shown(s), "open", s.lines())
        s.send("?")
        s.wait_for(help_gone, 3.0)
        s.settle(0.3)
        t.eq("selection still on the first row", prefix_of(s, "lab-server"), "> ")
        t.eq("not in filter mode, no filter: status 3/3", status_of(s), (3, 3))
        s.send("q")
        t.eq("q now quits: exit 0", s.wait_exit(3.0), 0)
        t.check("no SELECTED output", b"SELECTED" not in bytes(s.raw), "none", "SELECTED printed")
    finally:
        finish(t, s)


@check(T, "T3.help_ctrl_c", "Ctrl-C while the overlay is open: exit 130, terminal restored")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("?")
        check_help_lines(t, s)
        s.send(b"\x03")
        t.eq("exit 130", s.wait_exit(3.0), 130)
        st = hm.H.final_state(bytes(s.raw))
        t.eq("alternate screen left", st["alt_active_at_end"], False)
        t.eq("cursor shown at end", st["cursor_hidden_at_end"], False)
        t.eq("termios restored", hm.H.normalize_termios(s.termios_after()), hm.H.normalize_termios(s.attr_before))
    finally:
        finish(t, s)


@check(T, "T3.question_mark_in_filter_mode", "in filter mode '?' is filter text, not the help key")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.send("/")
        s.settle(0.1)
        s.send("?")
        t.check("filter '?' shows 0/3", s.wait_for(has_status(0, 3), 3.0) is not None, "0/3", status_of(s))
        t.check("no help overlay", help_gone(s), "no overlay", s.lines())
        t.check("status line shows the '?' filter text", any(STATUS_RE.search(l) and "?" in l for l in s.lines()),
                "?", s.lines()[-3:])
    finally:
        finish(t, s)


@check(T, "T3.help_tiny_terminal", "20x5 terminal: '?' and Esc do not crash; q exits 0")
def _(t, ctx):
    s = start(t, ctx, rows=5, cols=20, expect=lambda x: status_of(x) == (3, 3))
    try:
        s.send("?")
        s.settle(0.5)
        t.eq("still running after '?'", s.poll(), None)
        s.resize(6, 22)
        s.signal(signal.SIGWINCH)
        s.settle(0.3)
        s.key("esc")
        s.settle(0.4)
        t.eq("still running after Esc", s.poll(), None)
        s.send("q")
        t.eq("q exits 0", s.wait_exit(3.0), 0)
    finally:
        finish(t, s)


# ---------------------------------------------------------------- selection across filter edits
def marker_on(s, alias, timeout=3.0):
    return s.wait_for(lambda x: prefix_of(x, alias) == "> ", timeout) is not None


@check(T, "T3.selection_kept_when_visible", "append, Backspace and Esc clear keep the selected destination "
                                            "while it is still shown")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.key("down")
        s.key("down")
        t.require("Down Down -> '> vps-東京'", marker_on(s, "vps-東京"), "> vps-東京", s.lines())
        s.send("/")
        s.settle(0.1)
        s.send("e")
        s.wait_for(has_status(3, 3), 3.0)
        s.settle(0.2)
        t.check("[append 'e'] vps-東京 still selected", marker_on(s, "vps-東京", 1.0), "> vps-東京", s.lines())
        s.send("x")
        s.wait_for(has_status(3, 3), 3.0)
        s.settle(0.2)
        t.check("[append 'x'] vps-東京 still selected", marker_on(s, "vps-東京", 1.0), "> vps-東京", s.lines())
        s.key("backspace")
        s.settle(0.3)
        t.check("[Backspace] vps-東京 still selected", marker_on(s, "vps-東京", 1.0), "> vps-東京", s.lines())
        s.key("esc")
        s.wait_for(has_status(3, 3), 3.0)
        s.settle(0.2)
        t.check("[Esc clear] vps-東京 still selected", marker_on(s, "vps-東京", 1.0), "> vps-東京", s.lines())
        t.check("exactly one '> ' row", sum(1 for a in ALIASES if prefix_of(s, a) == "> ") == 1, 1, s.lines())
        s.key("enter")
        t.eq("Enter exits 0", s.wait_exit(3.0), 0)
        t.check("SELECTED vps-東京", bytes(s.raw).rstrip().endswith("SELECTED vps-東京".encode()),
                "SELECTED vps-東京", bytes(s.raw)[-60:].decode("utf-8", "replace"))
    finally:
        finish(t, s)


@check(T, "T3.selection_falls_back_to_first", "a filter that hides the selected destination selects the first "
                                              "shown row; widening again keeps that new selection")
def _(t, ctx):
    s = start(t, ctx)
    try:
        s.key("down")
        t.require("Down -> '> nas'", marker_on(s, "nas"), "> nas", s.lines())
        s.send("/")
        typ(s, "vps")
        t.check("'vps' shows 1/3", s.wait_for(has_status(1, 3), 3.0) is not None, "1/3", status_of(s))
        t.check("[nas hidden] first shown row vps-東京 selected", marker_on(s, "vps-東京"), "> vps-東京", s.lines())
        for _ in range(3):
            s.key("backspace")
            s.settle(0.1)
        s.wait_for(has_status(3, 3), 3.0)
        s.settle(0.2)
        t.check("[filter emptied] vps-東京 still selected", marker_on(s, "vps-東京", 1.0), "> vps-東京", s.lines())
        typ(s, "zz")
        t.check("'zz' shows 0/3", s.wait_for(has_status(0, 3), 3.0) is not None, "0/3", status_of(s))
        s.key("backspace")
        s.key("backspace")
        s.wait_for(has_status(3, 3), 3.0)
        s.settle(0.2)
        t.check("[after an empty list] first shown row selected", marker_on(s, "lab-server", 1.0), "> lab-server",
                s.lines())
        s.key("enter")
        s.settle(0.2)
        s.key("enter")
        t.eq("Enter exits 0", s.wait_exit(3.0), 0)
        t.check("SELECTED lab-server", bytes(s.raw).rstrip().endswith(b"SELECTED lab-server"), "SELECTED lab-server",
                bytes(s.raw)[-60:].decode("utf-8", "replace"))
    finally:
        finish(t, s)


@check(T, "T3.selection_kept_large", "100 destinations: a selected row far down stays selected (and visible) "
                                     "when a filter keeps it")
def _(t, ctx):
    large = Path(hm.HERE).parent / "t3" / "large-100.toml"
    s = start(t, ctx, profile=large, expect=lambda x: status_of(x) == (100, 100))
    try:
        for _ in range(37):
            s.key("down")
            s.settle(0.01)
        t.require("37 x Down -> '> host-037-db'", marker_on(s, "host-037-db", 5.0), "> host-037-db", s.lines())
        s.send("/")
        typ(s, "-db", gap=0.1)
        t.check("'-db' shows 25/100", s.wait_for(has_status(25, 100), 3.0) is not None, "25/100", status_of(s))
        s.settle(0.2)
        t.check("host-037-db still selected and on screen", marker_on(s, "host-037-db", 1.0), "> host-037-db",
                s.lines())
        s.key("enter")
        s.settle(0.2)
        s.key("enter")
        t.eq("Enter exits 0", s.wait_exit(3.0), 0)
        t.check("SELECTED host-037-db", bytes(s.raw).rstrip().endswith(b"SELECTED host-037-db"),
                "SELECTED host-037-db", bytes(s.raw)[-60:].decode("utf-8", "replace"))
    finally:
        finish(t, s)


# ---------------------------------------------------------------- K17 under part C
LARGE_ALIAS_RE = re.compile(r"host-\d{3}-[a-z]+")


def large_dests():
    import tomllib
    with open(Path(__file__).resolve().parent / "large-100.toml", "rb") as fh:
        return tomllib.load(fh)["destinations"]


def large_rows(s):
    out = []
    for line in s.lines():
        m = LARGE_ALIAS_RE.findall(line)
        if m:
            out.append(m[0])
    return out


def p95(values):
    v = sorted(values)
    if not v:
        return None
    k = -(-95 * len(v) // 100)
    return v[max(k, 1) - 1]


@check(T, "T3.k17_filter_latency", "K17 with part C: p95 keystroke-to-update <= 100 ms over 30 filter edits "
                                   "(5 sessions of /, 7, 0, 5, 3 x Backspace, Esc on large-100); an update counts when "
                                   "the status, a full contiguous window of the result and the expected '> ' row show")
def _(t, ctx):
    L = large_dests()
    aliases = [d["alias"] for d in L]

    def result(f):
        f = f.lower()
        return [d["alias"] for d in L if f in d["alias"].lower() or f in d["host"].lower()]

    large = Path(__file__).resolve().parent / "large-100.toml"
    s = start(t, ctx, profile=large, expect=lambda x: status_of(x) == (100, 100))
    try:
        for i in range(1, 31):
            s.key("down")
            if s.wait_for(lambda x, a=aliases[i]: prefix_of(x, a) == "> ", 3.0) is None:
                t.check("selection reaches row %d (%s) and stays visible" % (i, aliases[i]), False,
                        "> " + aliases[i], s.lines())
                raise Abort("navigation")
        for _ in range(30):
            s.key("up")
        s.settle(0.3)
        t.require("30 x Up back to '> host-000-web'", marker_on(s, "host-000-web"), "> host-000-web", s.lines())
        sel = "host-000-web"
        lats, cap = [], None
        for cyc in range(1, 6):
            s.send("/")
            s.settle(0.15)
            if cap is None:
                cap = len(large_rows(s))
                t.require("[session 1] list capacity measured (>= 2 rows) at 100/100", cap >= 2 and
                          status_of(s) == (100, 100), ">= 2", cap)
            typed = ""
            for kind, ch in [("type", c) for c in "705"] + [("bs", None)] * 3:
                before = sel
                typed = typed + ch if kind == "type" else typed[:-1]
                exp = result(typed)
                sel = before if (before is not None and before in exp) else (exp[0] if exp else None)
                n = min(len(exp), cap)

                def ok(x, exp=exp, n=n, sel=sel):
                    if status_of(x) != (len(exp), 100):
                        return False
                    rows = large_rows(x)
                    if len(rows) != n:
                        return False
                    if not exp:
                        return True
                    k = exp.index(rows[0]) if rows[0] in exp else -1
                    return k >= 0 and exp[k:k + n] == rows and prefix_of(x, sel) == "> "
                t0 = time.monotonic()
                if kind == "type":
                    s.send(ch)
                else:
                    s.key("backspace")
                r = s.wait_for(ok, 3.0, t_start=t0)
                t.check("[session %d] %s %r: status %d/100, %d contiguous result rows, '> %s'"
                        % (cyc, "typing" if kind == "type" else "backspace to", typed, len(exp), n, sel),
                        r is not None, {"status": "%d/100" % len(exp), "selected": sel},
                        {"status": status_of(s), "rows": large_rows(s)[:6]})
                if r is not None:
                    lats.append(round(r * 1000, 1))
            s.key("esc")
            s.settle(0.3)
        q95 = p95(lats)
        t.check("every one of the 30 edits produced its update", len(lats) == 30, 30, len(lats))
        t.check("p95 keystroke-to-update <= 100 ms (nearest rank)", q95 is not None and q95 <= 100, "<= 100 ms",
                {"p95_ms": q95, "max_ms": max(lats) if lats else None, "samples_ms": lats})
    finally:
        finish(t, s)
