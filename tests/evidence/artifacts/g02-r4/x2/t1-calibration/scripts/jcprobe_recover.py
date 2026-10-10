"""M00-T05-r4-x2-t1cal: escalating terminal recovery after a third-party stop of a background
job's child (P1x: redirected stdio, P2x: stdio on the terminal). Same CLI as jcprobe.py.

After the stop the user types `fg`; if the job does not finish within 8 s, the probe tries, in
order and each with 5 s to show a prompt: ^C (SIGINT), ^Z (SIGTSTP), ^\\ (SIGQUIT), and records
which key gave the prompt back and whether the child then completed (`fg` again if stopped).
Usage: python3 -I -B jcprobe_recover.py --bin PATH|plain --label L --reps 2 --out J --only P1x-TSTP,P2x-TSTP
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jcprobe as J  # noqa: E402


def sc_x(ctx, sh, tr, redirect):
    pf = ctx.pf()
    r = {"steps": []}
    red = " </dev/null >/dev/null 2>&1" if redirect else ""
    sh.cmd(ctx.line(pf, "sleep", 6, 0) + red + " &")
    c, j = J.learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    sh.sync()
    time.sleep(0.3)
    os.kill(c, J.SIG["TSTP"])
    time.sleep(0.8)
    r["jobs"], _ = sh.jobs(j)
    start = sh.cmd("fg")
    m = sh.expect(re.escape(J.PROMPT), 8)
    r["fg"] = "prompt" if m else "hung"
    got = None
    if m:
        got = "fg"
    else:
        for name, key in (("ctrl-c", "\x03"), ("ctrl-z", "\x1a"), ("ctrl-backslash", "\x1c")):
            sh.read(0.05)
            sh.mark = len(sh.buf)
            sh.send(key)
            ok = sh.expect(re.escape(J.PROMPT), 5) is not None
            st = J.states(C=c, L=j if ctx.bin else None)
            r["steps"].append({"key": name, "prompt": ok, "states": st})
            if ok:
                got = name
                break
    r["prompt_back_by"] = got
    if got:
        r["rc_then"] = sh.rc()
        r["jobs_then"], _ = sh.jobs(j)
        if r["jobs_then"].startswith("stopped"):
            rec = J.recover(sh, j, attempts=("fg", "ctrlc"))
            r["then_fg"] = rec
    time.sleep(0.2)
    r["child_completed"] = os.path.exists(pf + ".done")
    r["end_states"] = J.states(C=c, L=j if ctx.bin else None)
    r["cmp"] = {"jobs": r["jobs"], "fg": r["fg"], "prompt_back_by": got,
                "child_completed": r["child_completed"]}
    return r


J.SCENARIOS["P1x-TSTP"] = ("shell", lambda ctx, sh, tr: sc_x(ctx, sh, tr, True))
J.SCENARIOS["P2x-TSTP"] = ("shell", lambda ctx, sh, tr: sc_x(ctx, sh, tr, False))

if __name__ == "__main__":
    sys.exit(J.main())
