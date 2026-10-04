#!/usr/bin/env python3
"""Inject review-r3 defects (names rv_*) into /tmp copies of the reference implementation.
Each defect is gated by `"rv_x" in MUT`, so the patched copy with no rv_* active behaves like the original."""
import sys
from pathlib import Path

src = Path(sys.argv[1])
out = Path(sys.argv[2])
impl = (src / "reference_impl.py").read_text()
tui = (src / "reference_tui.py").read_text()


def rep(text, old, new):
    assert text.count(old) == 1, ("anchor not unique", old[:60], text.count(old))
    return text.replace(old, new)


# ---------------- run: job-control alternative (rv_jc) needs the child in its own group before exec
impl = rep(impl, """        else:
            child = subprocess.Popen(argv, **popen_kw)""", """        else:
            if "rv_child_sigpipe_ignored" in MUT:
                popen_kw["restore_signals"] = False       # defect: child inherits the runtime's SIGPIPE ignore
            if JC:
                def _jc_pre():
                    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                    os.setpgid(0, 0)
                    try:
                        os.tcsetpgrp(0, os.getpid())
                    except OSError:
                        pass
                    signal.signal(signal.SIGTTOU, signal.SIG_DFL)
                popen_kw["preexec_fn"] = _jc_pre
                signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            child = subprocess.Popen(argv, **popen_kw)""")

impl = rep(impl, """    try:
        if "run_shell" in MUT:""", """    JC = False
    if "rv_jc" in MUT and os.isatty(0) and os.isatty(1):
        try:
            JC = os.getpgrp() == os.getpid() and os.tcgetpgrp(0) == os.getpgrp()
        except OSError:
            JC = False
    try:
        if "run_shell" in MUT:""")

# ---------------- K6d shared-mode defects
impl = rep(impl, """    shared_drop = set()
""", """    shared_drop = set()
    rv_shared = False
    try:
        _tfd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        _tfd = None
    _stdin_pipe = _stdout_pipe = False
    for _fd in (0, 1):
        try:
            _m = os.fstat(_fd).st_mode
            if stat.S_ISFIFO(_m) or stat.S_ISSOCK(_m):
                if _fd == 0:
                    _stdin_pipe = True
                else:
                    _stdout_pipe = True
        except OSError:
            pass
    if _tfd is not None:
        try:
            rv_shared = (_stdin_pipe or _stdout_pipe or os.getpgrp() != os.getpid()) and \\
                os.tcgetpgrp(_tfd) == os.getpgrp()
        except OSError:
            rv_shared = False
        finally:
            os.close(_tfd)
    if rv_shared:
        if "rv_shared_sigint_only" in MUT:          # defect: shared mode forwards SIGINT only
            shared_drop = {signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH}
        if "rv_shared_drop_winch" in MUT:           # defect: SIGWINCH assumed terminal-generated in shared mode
            shared_drop = {signal.SIGWINCH}
        if "rv_shared_drop_pipe_stdin" in MUT and _stdin_pipe:   # defect: drop all when fed by a pipeline peer
            shared_drop = set(FORWARD)
        if "rv_shared_drop_sh_c" in MUT and not (_stdin_pipe or _stdout_pipe):  # defect: non-leader, no pipes
            shared_drop = set(FORWARD)
""")

impl = rep(impl, """        if signum in shared_drop:
            return                            # mutation run_shared_drop: silently lost
""", """        if signum in shared_drop:
            return                            # mutation run_shared_drop: silently lost
        if "rv_dedupe_500ms" in MUT:          # defect: duplicate suppression - same signal within 500 ms dropped
            now = time.monotonic()
            last = seen.setdefault("last", {})
            if now - last.get(signum, -10) < 0.5:
                return
            last[signum] = now
        if "rv_hup_exit_early" in MUT and signum == signal.SIGHUP:   # defect: forward SIGHUP, then exit 129
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass
            os._exit(129)
""")

# ---------------- K6e re-stop defects (base, non-job-control reference)
impl = rep(impl, """    if "run_fg_restop" in MUT and os.isatty(0):""", """    if ("rv_restop_linux" in MUT and sys.platform.startswith("linux") or "rv_restop_700ms" in MUT) \\
            and os.isatty(0) and not JC:
        rvc = {"n": 0}

        def rv_on_cont(signum, frame):
            end = time.monotonic() + 0.2
            while True:
                try:
                    if os.tcgetpgrp(0) == os.getpgrp():
                        break
                except OSError:
                    return
                if time.monotonic() > end:
                    return              # a `bg` continue
                time.sleep(0.005)
            rvc["n"] += 1
            if rvc["n"] == 2:
                if "rv_restop_700ms" in MUT:
                    time.sleep(0.7)     # defect: re-stop 700 ms after the second `fg`
                os.kill(0, signal.SIGTSTP)
        signal.signal(signal.SIGCONT, rv_on_cont)
    if "run_fg_restop" in MUT and os.isatty(0):""")

# ---------------- K6e job-control alternative wait loop
impl = rep(impl, """    rc = child.wait()
""", """    if JC:
        def jc_on_cont(signum, frame):
            end = time.monotonic() + 0.2
            fgnow = False
            while True:
                try:
                    if os.tcgetpgrp(0) == os.getpgrp():
                        fgnow = True
                        break
                except OSError:
                    break
                if time.monotonic() > end:
                    break
                time.sleep(0.005)
            if fgnow and "rv_jc_no_tty_after_fg" not in MUT:
                try:
                    os.tcsetpgrp(0, child.pid)
                except OSError:
                    pass
            if fgnow or "rv_jc_bg_no_cont" not in MUT:
                try:
                    os.killpg(child.pid, signal.SIGCONT)
                except OSError:
                    pass
        signal.signal(signal.SIGCONT, jc_on_cont)
        while True:
            _pid, _st = os.waitpid(child.pid, os.WUNTRACED)
            if os.WIFSTOPPED(_st):
                # bash does not send SIGCONT when `fg` takes a job that is already running (after `bg`):
                # the child then stops with SIGTTIN on its next terminal read; if we hold the foreground
                # now, hand the terminal over and continue it (v2 of the alternative).
                if os.WSTOPSIG(_st) in (signal.SIGTTIN, signal.SIGTTOU) and "rv_jc_no_tty_after_fg" not in MUT:
                    try:
                        _isfg = os.tcgetpgrp(0) == os.getpgrp()
                    except OSError:
                        _isfg = False
                    if _isfg:
                        try:
                            os.tcsetpgrp(0, child.pid)
                        except OSError:
                            pass
                        os.killpg(child.pid, signal.SIGCONT)
                        continue
                if "rv_jc_no_selfstop" in MUT:
                    continue
                try:
                    os.tcsetpgrp(0, os.getpgrp())
                except OSError:
                    pass
                os.kill(os.getpid(), signal.SIGSTOP)
                continue
            rc = -os.WTERMSIG(_st) if os.WIFSIGNALED(_st) else os.WEXITSTATUS(_st)
            child.returncode = rc
            break
        try:
            os.tcsetpgrp(0, os.getpgrp())
        except OSError:
            pass
    else:
        rc = child.wait()
""")

# ---------------- K17 TUI defects
tui = rep(tui, """    st = {"filter": "", "filtering": False, "sel": 0, "top": 0, "dirty": True, "term": False}

    def shown():
        f = st["filter"]""", """    st = {"filter": "", "filtering": False, "sel": 0, "top": 0, "dirty": True, "term": False,
          "row_filter": "", "lag_until": 0.0, "edits": 0}

    def shown(f=None):
        f = st["filter"] if f is None else f""")
tui = rep(tui, """        sh = shown()
        st["sel"] = max(0, min(st["sel"], len(sh) - 1)) if sh else 0""", """        sh_all = shown()
        sh = shown(st["row_filter"]) if "rv_rows_lag" in MUT else sh_all   # defect: rows lag the status line
        st["sel"] = max(0, min(st["sel"], len(sh) - 1)) if sh else 0""")
tui = rep(tui, """        status = "%d/%d  /%s%s" % (len(sh), len(dests),""", """        status = "%d/%d  /%s%s" % (len(sh_all), len(dests),""")
tui = rep(tui, """            st["dirty"] = True
            return False
        if key in ("DOWN", "j"):""", """            if key == "BACKSPACE" or (len(key) == 1 and key.isprintable()):
                if "rv_delay_bigresult" in MUT and len(shown()) > 50:
                    time.sleep(0.15)                 # defect: slow only when the result has more than 50 rows
                if "rv_delay_first_key" in MUT and st["edits"] == 0:
                    time.sleep(0.15)                 # defect: slow first keystroke after entering filter mode
                if "rv_delay_backspace" in MUT and key == "BACKSPACE":
                    time.sleep(0.15)                 # defect: slow Backspace
                if "rv_delay_90ms" in MUT:
                    time.sleep(0.09)                 # control: slow but within the 100 ms bound
                st["edits"] += 1
                st["lag_until"] = time.monotonic() + 0.15
            st["dirty"] = True
            return False
        if key in ("DOWN", "j"):""")
tui = rep(tui, """            st["filtering"] = True
""", """            st["filtering"] = True
            st["edits"] = 0
""")
tui = rep(tui, """            if st["dirty"]:
                render()""", """            if "rv_rows_lag" in MUT and st["row_filter"] != st["filter"] and time.monotonic() >= st["lag_until"]:
                st["row_filter"] = st["filter"]
                st["dirty"] = True
            elif "rv_rows_lag" not in MUT:
                st["row_filter"] = st["filter"]
            if st["dirty"]:
                render()""")

out.mkdir(parents=True, exist_ok=True)
(out / "reference_impl.py").write_text(impl)
(out / "reference_tui.py").write_text(tui)
