#!/usr/bin/env python3
"""parity-r3c probe 2 (clean form of review3c probe.py sc_explicit's last part).

usage: contlauncher.py SHELL OUTDIR LABEL=BIN [LABEL=BIN ...]

Fresh interactive SHELL per target.  Runs child.py (review3c, unchanged) in the foreground,
`[BIN run -- ]python3 child.py PF`; the child stops itself (input line "tstp" ->
kill(getpid(), SIGTSTP)); after the shell's stop notice + prompt, this probe sends SIGCONT to the
LAUNCHER PID only (control "plain": to the job's only process, the child, as probe.py does).
After 0.6 s it runs `jobs` and records what the shell says (Running/Stopped) against the real
states, then re-samples after 2 s (launcher CPU, child still stopped?).  Recovery as the user
would need it: SIGCONT to the child, `fg`, a line the child echoes.  Unlike probe.py there are no
earlier explicit-signal steps in the same job, and the `jobs` text is taken from the command's
output, not from the terminal echo of the typed command (probe.py harness defect).
Writes OUTDIR/<shell>-contlauncher.json and OUTDIR/<shell>-contlauncher-<label>.txt.
"""
import json
import os
import re
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyshell import Shell, PROMPT, STOPRE, stat, state, cputime, kill_exact, clean  # noqa: E402

KIND, OUT = sys.argv[1], sys.argv[2]
TARGETS = [("plain", None)] + [tuple(a.split("=", 1)) for a in sys.argv[3:]]
CHILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "child.py")


def jobs(sh):
    sh.mark = len(sh.buf)
    sh.send("jobs; echo JE-$((40+2))\n")
    e = sh.expect(re.escape("jobs; echo JE-$((40+2))"), 3)
    m = sh.expect(r"JE-42", 3)
    t = sh.buf[e.end():m.start()] if (e and m) else ""
    return {"text": clean(t, 300).strip(),
            "running": bool(re.search(r"Running|running", t)),
            "stopped": bool(re.search(r"Stopped|suspended", t))}


def one(label, binpath):
    sh = Shell(KIND)
    r = {"shell": KIND, "via": label}
    c = h = None
    try:
        pf = os.path.join(sh.tmp, "pf")
        pre = "" if binpath is None else "%s run -- " % binpath
        sh.send("%spython3 %s %s\n" % (pre, CHILD, pf))
        end = time.time() + 6
        while time.time() < end and c is None:
            sh.read(0.05)
            try:
                c = int(open(pf).read().strip())
            except (OSError, ValueError):
                pass
        h = stat(c).get("ppid") if binpath else None
        r["ready"] = bool(sh.expect(r"READY-1", 5))
        sh.send("tstp\n")
        r["stop_notice"] = bool(sh.expect(STOPRE, 3))
        r["prompt_after_stop"] = bool(sh.expect(re.escape(PROMPT), 3))
        time.sleep(0.3)
        r["states_stopped"] = {"child": state(c), "launcher": state(h)}
        target = h if binpath else c
        m0 = len(sh.buf)
        os.kill(target, signal.SIGCONT)
        time.sleep(0.6)
        sh.read(0.1)
        r["shell_notice_after_cont"] = clean(sh.buf[m0:], 200).strip()
        r["states_after_cont"] = {"child": state(c), "launcher": state(h)}
        r["jobs"] = jobs(sh)
        t0 = cputime(h) if h else None
        time.sleep(2.0)
        r["after_2s"] = {"child": state(c), "launcher": state(h),
                         "launcher_cpu": [t0, cputime(h) if h else None],
                         "child_printed_BACK": "BACK-tstp" in sh.buf}
        r["jobs_after_2s"] = jobs(sh)
        r["shell_believes_running_while_child_stopped"] = (r["jobs_after_2s"]["running"]
                                                            and r["after_2s"]["child"] == "T")
        # recovery
        sh.expect(re.escape(PROMPT), 1)
        if state(c) == "T":
            os.kill(c, signal.SIGCONT)
        sh.send("fg\n")
        time.sleep(0.5)
        sh.send("probe42\n")
        r["child_reads_after_recovery"] = bool(sh.expect(r"GOT-probe42", 3))
        sh.send("exit 5\n")
        sh.expect(re.escape(PROMPT), 5)
        sh.send("echo RC=$?\n")
        m = sh.expect(r"RC=(\d+)", 5)
        r["rc"] = int(m.group(1)) if m else None
    except Exception as e:  # record, do not hide
        r["exception"] = repr(e)
    finally:
        sh.read(0.2)
        with open(os.path.join(OUT, "%s-contlauncher-%s.txt" % (KIND, label)), "w") as f:
            f.write(sh.transcript([(binpath or "\0", "<BIN>"), (CHILD, "<probes>/child.py")]))
        r["leftover_killed"] = kill_exact([c, h])
        sh.close()
    return r


os.makedirs(OUT, exist_ok=True)
res = {"shell": KIND, "platform": sys.platform, "runs": []}
for label, binpath in TARGETS:
    r = one(label, binpath)
    print(json.dumps(r), flush=True)
    res["runs"].append(r)
with open(os.path.join(OUT, "%s-contlauncher.json" % KIND), "w") as f:
    json.dump(res, f, indent=1)
