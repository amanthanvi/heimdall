"""T3 POSITIVE CONTROL (validation only): reference_tui.py + filter highlight, help overlay,
selection kept across filter edits (specs/T3.md).  Original docstring:
Minimal raw-ANSI stand-in for the G02 `tui` subcommand (contract section 5).

Exists ONLY so the TUI checks of tests/g02/conformance.py can be exercised and
mutation-tested before any prototype exists.  It is not a prototype and says
nothing about Bubble Tea / Ratatui / OpenTUI.  Python standard library only.
"""
import os
import select
import signal
import sys
import termios
import time
import tty
import unicodedata

ENTER_ALT = b"\x1b[?1049h"
LEAVE_ALT = b"\x1b[?1049l"
HIDE_CUR = b"\x1b[?25l"
SHOW_CUR = b"\x1b[?25h"


class _Term(Exception):
    pass


class _Hup(Exception):
    pass


def _w(ch):
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else (0 if unicodedata.combining(ch) else 1)


def run(dests, MUT, usage):
    if "tui_no_tty_check" not in MUT and not (os.isatty(0) and os.isatty(1)):
        usage("tui requires a TTY on stdin and stdout", False)
        return 2
    orig = termios.tcgetattr(0)
    color = ("tui_color_always" in MUT) or not os.environ.get("NO_COLOR")
    st = {"filter": "", "filtering": False, "sel": 0, "top": 0, "dirty": True, "term": False,
          "row_filter": "", "lag_until": 0.0, "edits": 0, "help": False}
    big = len(dests) > 50
    rows_lag = "tui_rows_lag" in MUT and big

    def shown(f=None):
        f = st["filter"] if f is None else f
        if "tui_case_sensitive" not in MUT:
            f = f.lower()
        res = []
        for d in dests:
            a, h = d["alias"], d["host"]
            if "tui_case_sensitive" not in MUT:
                a, h = a.lower(), h.lower()
            if f in a or ("tui_filter_alias_only" not in MUT and f in h):
                res.append(d)
        return res

    # Cell-diff renderer modelled on Ratatui's Buffer::diff (as observed in the G02 Rust prototype's
    # output): only changed cells are written, the trailing half of a double-width character is a
    # plain " " cell that is never written on its own.  Replacing "vps-東京" by blanks therefore
    # overwrites only the LEFT half of 東/京 - legal (xterm blanks the whole wide character) and
    # exactly the stream that made stock pyte raise IndexError (harness defect (a)).  The baseline
    # TUI checks thus exercise the harness's double-width handling end to end.
    SEL_STYLE = "\x1b[0;1;31m" if color else "\x1b[0;1m"
    scr = {"prev": None, "size": None}

    def compose(cols, rows):
        sh_all = shown()
        # mutation tui_rows_lag: the list rows show the result of an older filter until the lag has passed
        sh = shown(st["row_filter"]) if rows_lag else sh_all
        st["sel"] = max(0, min(st["sel"], len(sh) - 1)) if sh else 0
        h = max(rows - 1, 0)
        if st["sel"] < st["top"]:
            st["top"] = st["sel"]
        if h and st["sel"] >= st["top"] + h:
            st["top"] = st["sel"] - h + 1
        st["top"] = max(0, min(st["top"], max(len(sh) - h, 0)))
        lines = []
        narrow = cols < (60 if "tui_narrow_threshold_60" in MUT else 50) and "tui_ignore_resize_hide" not in MUT
        for r in range(h):
            idx = st["top"] + r
            if idx >= len(sh):
                break
            d = sh[idx]
            prefix = "> " if (idx == st["sel"] and "tui_no_prefix" not in MUT) else "  "
            body = d["alias"] if narrow else "%s  %s@%s:%d" % (d["alias"], d["account"], d["host"], d["port"])
            ul = set()
            f = st["filter"].lower()
            if f:
                i = d["alias"].lower().find(f)
                if i >= 0:
                    ul |= set(range(2 + i, 2 + i + len(f)))
                if not narrow:
                    hs = 2 + len(d["alias"]) + 2 + len(d["account"]) + 1
                    j = d["host"].lower().find(f)
                    if j >= 0:
                        ul |= set(range(hs + j, hs + j + len(f)))
            base = "sel" if idx == st["sel"] else None
            lines.append((r, prefix + body, [(base or "") + ("ul" if k in ul else "") or None
                                             for k in range(len(prefix + body))]))
        if st["help"]:
            HELP = ["Keys", "Up / k      move up", "Down / j    move down", "/           filter",
                    "Enter       select", "Esc         clear filter", "q           quit",
                    "?           close help", "Ctrl-C      cancel"]
            lines = [(r, "  " + HELP[r], None) for r in range(min(h, len(HELP)))]
        status = "%d/%d  /%s%s" % (len(sh_all), len(dests), st["filter"], "_" if st["filtering"] else "")
        if "tui_status_missing" in MUT:
            status = "filter: %s" % st["filter"]
        lines.append((rows - 1, status, None))
        grid = [[(" ", None, 1)] * cols for _ in range(rows)]
        for y, text, style in lines:
            x = 0
            for ci, ch in enumerate(text):
                cst = style[ci] if isinstance(style, list) else style
                w = _w(ch)
                if w == 0:
                    continue
                if x + w > cols:
                    break
                grid[y][x] = (ch, cst, w)
                for k in range(1, w):
                    grid[y][x + k] = (" ", None, 1)      # Ratatui resets the hidden trailing cell
                x += w
        return grid

    def render():
        try:
            cols, rows = os.get_terminal_size(1)
        except OSError:
            cols, rows = 80, 24
        if "tui_crash_small" in MUT and cols < 30:
            raise RuntimeError("simulated crash")
        st["dirty"] = False
        if cols <= 0 or rows <= 0:
            return
        grid = compose(cols, rows)
        out = []
        if scr["prev"] is None or scr["size"] != (cols, rows):
            out.append("\x1b[0m\x1b[H\x1b[2J")              # full redraw on start and resize
            scr["prev"] = [[(" ", None, 1)] * cols for _ in range(rows)]
            scr["size"] = (cols, rows)
        elif scr.get("top") is not None and st["top"] != scr["top"] and 0 < abs(st["top"] - scr["top"]) < rows - 1:
            # Scroll the list like Bubble Tea v2's renderer: SU/SD inside a DECSTBM region over the list rows,
            # then diff against the shifted previous frame.  The baseline thus exercises the harness emulator's
            # SU/SD support end to end (harness defect (g): stock pyte drops SU/SD and keeps stale rows).
            k, h = st["top"] - scr["top"], rows - 1
            blank = [(" ", None, 1)] * cols
            out.append("\x1b[0m\x1b[1;%dr" % h)
            if k > 0:
                out.append("\x1b[%d;1H\x1b[%dS" % (h, k))
                scr["prev"][0:h] = scr["prev"][k:h] + [list(blank) for _ in range(k)]
            else:
                out.append("\x1b[H\x1b[%dT" % -k)
                scr["prev"][0:h] = [list(blank) for _ in range(-k)] + scr["prev"][0:h + k]
            out.append("\x1b[1;%dr" % rows)                 # DECSTBM homes the cursor
        scr["top"] = st["top"]
        prev = scr["prev"]
        cur_pos, cur_style = None, None
        for y in range(rows):
            skip = 0
            for x in range(cols):
                cell = grid[y][x]
                if skip:
                    skip -= 1
                    continue
                skip = cell[2] - 1
                if cell[:2] == prev[y][x][:2]:
                    continue
                if cur_pos != (y, x):
                    out.append("\x1b[%d;%dH" % (y + 1, x + 1))
                if cell[1] != cur_style:
                    out.append({"sel": SEL_STYLE, "ul": "\x1b[0;4m", "selul": SEL_STYLE + "\x1b[4m"}.get(cell[1], "\x1b[0m"))
                    cur_style = cell[1]
                out.append(cell[0])
                cur_pos = (y, x + cell[2])
        if cur_style is not None:
            out.append("\x1b[0m")
        scr["prev"] = grid
        if out:
            os.write(1, "".join(out).encode("utf-8"))

    def on_winch(signum, frame):
        if "tui_slow_resize" in MUT:
            time.sleep(0.4)
        st["dirty"] = True

    def on_term(signum, frame):
        if "tui_sigterm_no_restore" in MUT:
            os._exit(143)
        raise _Term

    def on_hup(signum, frame):
        raise _Hup

    result = {"exit": 0, "selected": None}

    def filter_edit_delay():
        """Injected filter-edit latencies on profiles with more than 50 destinations (K17 harness validation)."""
        if not big:
            return
        if "tui_slow_first_filter_key" in MUT and st["edits"] == 0:
            time.sleep(0.15)          # mutation: the first edit after `/` takes 150 ms, later ones are immediate
        if "tui_filter_70ms" in MUT:
            time.sleep(0.07)          # conforming variant: every edit takes 70 ms, inside the 100 ms K17 bound
        st["edits"] += 1
        st["lag_until"] = time.monotonic() + 0.15

    def feed_key(key):
        """Return True when the program should stop."""
        sh = shown()
        if key == "CTRLC":
            if st["filtering"] and "tui_exit0_on_ctrlc_in_filter" in MUT:
                return False
            result["exit"] = 130
            if "tui_ctrlc_exit1" in MUT:
                result["exit"] = 1
            return True
        if st["help"]:
            if key in ("?", "ESC"):
                st["help"] = False
                st["dirty"] = True
            return False
        prev = sh[st["sel"]]["alias"] if sh else None

        def keep():
            now = shown()
            names = [d["alias"] for d in now]
            st["sel"] = names.index(prev) if prev in names else 0

        if st["filtering"]:
            if key == "ENTER":
                if "tui_enter_in_filter_selects" in MUT and sh:
                    result["selected"] = sh[st["sel"]]["alias"]
                    return True
                st["filtering"] = False
            elif key == "ESC":
                st["filtering"] = False
                if "tui_esc_keeps_filter" not in MUT:
                    st["filter"] = ""
                    keep()
            elif key == "BACKSPACE":
                if "tui_slow_filter" in MUT and len(dests) > 50:
                    time.sleep(0.15)
                filter_edit_delay()
                st["filter"] = st["filter"][:-1]
                keep()
            elif len(key) == 1 and key.isprintable():
                if ord(key) > 127 and "tui_no_unicode_filter" in MUT:
                    return False
                if "tui_slow_filter" in MUT and len(dests) > 50:
                    time.sleep(0.15)
                filter_edit_delay()
                st["filter"] += key
                keep()
            st["dirty"] = True
            return False
        if key in ("DOWN", "j"):
            st["sel"] = min(st["sel"] + 1, max(len(sh) - 1, 0))
        elif key in ("UP", "k"):
            st["sel"] = max(st["sel"] - 1, 0)
        elif key == "?":
            st["help"] = True
        elif key == "/":
            st["filtering"] = True
            st["edits"] = 0
        elif key == "ENTER":
            if sh:
                result["selected"] = sh[st["sel"]]["alias"]
                return True
        elif key == "q":
            if "tui_quit_prints_selected" in MUT and sh:
                result["selected"] = sh[st["sel"]]["alias"]
            return True
        st["dirty"] = True
        return False

    def tokens(buf):
        """Split buf into (key, consumed) items; stop at an incomplete sequence."""
        out = []
        i = 0
        while i < len(buf):
            b = buf[i]
            if b == 0x1B:
                rest = buf[i:i + 3]
                if rest in (b"\x1b[A", b"\x1bOA"):
                    out.append("UP"); i += 3; continue
                if rest in (b"\x1b[B", b"\x1bOB"):
                    out.append("DOWN"); i += 3; continue
                if len(buf) - i == 1:
                    out.append("ESC"); i += 1; continue
                if len(buf) - i == 2 and buf[i + 1:i + 2] in (b"[", b"O"):
                    break  # incomplete CSI
                out.append("ESC"); i += 1; continue
            if b == 3:
                out.append("CTRLC"); i += 1; continue
            if b in (10, 13):
                out.append("ENTER"); i += 1; continue
            if b in (8, 127):
                out.append("BACKSPACE"); i += 1; continue
            if b < 0x80:
                out.append(chr(b)); i += 1; continue
            n = 2 if b >> 5 == 0b110 else 3 if b >> 4 == 0b1110 else 4 if b >> 3 == 0b11110 else 1
            if len(buf) - i < n:
                break
            out.append(buf[i:i + n].decode("utf-8", "replace")); i += n
        return out, buf[i:]

    old_term = signal.signal(signal.SIGTERM, on_term)
    if "tui_sighup_unhandled" not in MUT:
        signal.signal(signal.SIGHUP, on_hup)
    signal.signal(signal.SIGWINCH, on_winch)
    if "tui_stderr_canary" in MUT:
        os.write(2, ("debug env %s\n" % os.environ.get("HM_G02_SECRET_ENV", "")).encode("utf-8"))
    if "tui_tmux_probe" in MUT and os.environ.get("TMUX"):
        import subprocess
        try:
            subprocess.run(["tmux", "display-message", "-p", "#{client_termname}"], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
    if "tui_term_probe" in MUT and os.environ.get("TERM", "").startswith(("tmux", "screen")):
        import subprocess
        try:
            subprocess.run(["infocmp", "-1"], capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
    if "tui_stray_home_write" in MUT:
        with open(os.path.join(os.environ.get("HOME", "/nonexistent"), ".hm-ref-tui-state"), "w") as fh:
            fh.write("x")
    started = False
    try:
        tty.setraw(0)
        if "tui_no_alt_screen" not in MUT:
            os.write(1, ENTER_ALT)
        if "tui_no_hide_cursor" not in MUT:
            os.write(1, HIDE_CUR)
        started = True
        pending = b""
        done = False
        while not done:
            if st["row_filter"] != st["filter"] and (not rows_lag or time.monotonic() >= st["lag_until"]):
                st["row_filter"] = st["filter"]
                st["dirty"] = True
            if st["dirty"]:
                render()
            r, _, _ = select.select([0], [], [], 0.02)
            if not r:
                continue
            try:
                chunk = os.read(0, 1024)
            except OSError:          # EIO after a terminal hangup
                chunk = b""
            if not chunk:            # terminal hangup (K10)
                result["exit"] = 130 if "tui_hangup_exit130" in MUT else 129
                break
            pending += chunk
            keys, pending = tokens(pending)
            for k in keys:
                if feed_key(k):
                    done = True
                    break
    except _Term:
        result["exit"] = 0 if "tui_sigterm_exit0" in MUT else 143
        if "tui_sigterm_prints" in MUT:
            sh = shown()
            result["selected"] = sh[st["sel"]]["alias"] if sh else None
    except _Hup:
        result["exit"] = 129
    except OSError:              # EIO writing to a hung-up terminal
        result["exit"] = 129
    finally:
        # already exiting: a late SIGHUP/SIGTERM (e.g. hangup EOF and the shell's SIGHUP racing)
        # must not interrupt the restore
        for sg in (signal.SIGHUP, signal.SIGTERM):
            signal.signal(sg, signal.SIG_IGN)
        if started:
            # restore what is possible: after a hangup the tty may return EIO (K10)
            try:
                if "tui_no_alt_leave" not in MUT and "tui_no_alt_screen" not in MUT:
                    os.write(1, LEAVE_ALT)
                if "tui_no_cursor_restore" not in MUT:
                    os.write(1, SHOW_CUR)
            except OSError:
                pass
            if "tui_termios_not_restored" not in MUT:
                try:
                    termios.tcsetattr(0, termios.TCSADRAIN, orig)
                except (OSError, termios.error):
                    pass
    if "tui_reraise_signal" in MUT and result["exit"] in (143, 129):
        # conforming variant (K10 exit form): terminal restored above, now die by the signal itself
        sig = signal.SIGTERM if result["exit"] == 143 else signal.SIGHUP
        signal.signal(sig, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {sig})
        os.kill(os.getpid(), sig)
        time.sleep(2)
    if result["selected"] is not None:
        word = "SELECT" if "tui_select_wrong_text" in MUT else "SELECTED"
        try:
            os.write(1, ("%s %s\n" % (word, result["selected"])).encode("utf-8"))
        except OSError:
            pass
    return result["exit"]
