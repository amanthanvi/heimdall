#!/usr/bin/env python3
"""parity-r3c probe 3 (extended form of review3c probe.py sc_nested_shell).

usage: nested.py SHELL OUTDIR LABEL=BIN [LABEL=BIN ...]

Outer interactive SHELL (bash|zsh) in a fresh pty runs `[BIN run -- ]bash --norc --noprofile -i`
in the foreground (control "plain": the nested bash directly).  Inside the nested shell: set
W=nested and record its PID; then `suspend`.  Records: stop notice, outer prompt, whether the
OUTER shell is still alive (it can lose the terminal), states/pgids/tty foreground group of the
nested shell, the launcher and the outer shell.  If the outer prompt is back: `fg`, then
`echo ALIVE-$W-$((40+2))` -- "ALIVE-nested-42" means the nested shell answered, "ALIVE--42" means
the OUTER shell answered (the nested shell did not get the terminal back).  If the nested shell
answered, `exit 3` in it and record the outer shell's $?.  Otherwise record what the shell shows,
then SIGCONT the nested shell PID (diagnostic) and check again.  Exact-PID cleanup at the end.
Writes OUTDIR/<shell>-nested.json and OUTDIR/<shell>-nested-<label>.txt.
"""
import json
import os
import re
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyshell import Shell, PROMPT, STOPRE, stat, state, kill_exact, clean  # noqa: E402

KIND, OUT = sys.argv[1], sys.argv[2]
TARGETS = [("plain", None)] + [tuple(a.split("=", 1)) for a in sys.argv[3:]]


def snap(sh, n, h):
    return {"nested": stat(n), "launcher": stat(h) if h else None, "outer": stat(sh.pid),
            "outer_alive": sh.alive(), "outer_exit": sh.exit_status, "pty_eof": sh.eof}


def alive_check(sh, r, key):
    sh.mark = len(sh.buf)
    if not sh.send("echo ALIVE-$W-$((40+2))\n"):
        r[key] = "send failed"
        return
    m = sh.expect(r"ALIVE-(nested)?-42", 3)
    r[key] = ("nested answered" if m.group(1) else "outer shell answered") if m else "no answer"


def one(label, binpath):
    sh = Shell(KIND)
    r = {"shell": KIND, "via": label}
    n = h = None
    try:
        pre = "" if binpath is None else "%s run -- " % binpath
        sh.send("%sbash --norc --noprofile -i\n" % pre)
        time.sleep(1.0)
        sh.send("PS1='@N@ '; W=nested\n")
        r["nested_prompt"] = bool(sh.expect(r"@N@ ", 3))
        sh.send("echo NPID=$$\n")
        m = sh.expect(r"NPID=(\d+)", 3)
        n = int(m.group(1)) if m else None
        h = stat(n).get("ppid") if (binpath and n) else None
        sh.expect(r"@N@ ", 2)
        r["before_suspend"] = snap(sh, n, h)
        m0 = len(sh.buf)
        sh.send("suspend\n")
        r["stop_notice"] = bool(sh.expect(STOPRE, 3))
        r["outer_prompt"] = bool(sh.expect(re.escape(PROMPT), 2))
        time.sleep(0.5)
        sh.read(0.1)
        r["after_suspend"] = snap(sh, n, h)
        r["shell_text_after_suspend"] = clean(sh.buf[m0:], 300).strip()
        if r["outer_prompt"] and r["after_suspend"]["outer_alive"]:
            m1 = len(sh.buf)
            sh.send("fg\n")
            time.sleep(1.0)
            sh.read(0.1)
            r["after_fg"] = snap(sh, n, h)
            alive_check(sh, r, "after_fg_answer")
            r["shell_text_after_fg"] = clean(sh.buf[m1:], 300).strip()
            if r["after_fg_answer"] == "nested answered":
                sh.expect(r"@N@ ", 2)
                sh.send("exit 3\n")
                sh.expect(re.escape(PROMPT), 4)
                sh.send("echo RC=$?\n")
                m = sh.expect(r"RC=(\d+)", 4)
                r["outer_rc_after_nested_exit_3"] = int(m.group(1)) if m else None
        if n and state(n) == "T":
            # diagnostic: what if someone continues the nested shell directly?
            os.kill(n, signal.SIGCONT)
            time.sleep(0.8)
            sh.read(0.1)
            r["after_manual_cont_of_nested"] = snap(sh, n, h)
            if sh.alive() and not sh.eof:
                alive_check(sh, r, "after_manual_cont_answer")
        r["final"] = snap(sh, n, h)
    except Exception as e:  # record, do not hide
        r["exception"] = repr(e)
    finally:
        sh.read(0.3)
        with open(os.path.join(OUT, "%s-nested-%s.txt" % (KIND, label)), "w") as f:
            f.write(sh.transcript([(binpath or "\0", "<BIN>")]))
        r["leftover_killed"] = kill_exact([n, h])
        sh.close()
        r["outer_exit_at_close"] = sh.exit_status
        r["outer_killed_by_probe_at_close"] = sh.killed_by_probe
    return r


os.makedirs(OUT, exist_ok=True)
res = {"shell": KIND, "platform": sys.platform, "runs": []}
for label, binpath in TARGETS:
    r = one(label, binpath)
    print(json.dumps(r), flush=True)
    res["runs"].append(r)
with open(os.path.join(OUT, "%s-nested.json" % KIND), "w") as f:
    json.dump(res, f, indent=1)
