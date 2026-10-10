"""M00-T05-r4-x2-t1cal: P9e follow-up (added after the independent check): does a repeated `fg`
give the job-control child the terminal back? Same CLI as jcprobe.py.

P9e0-fg3 / P9e-bg-fg3: as P9e0 / P9e-bg, but after the outer `fg` the probe checks whether the job
stopped again at once; up to three `fg` are typed, each followed by `xq-ping N`. Records after which
`fg` the child answered (0 = never) and where each ping went (child, shell, or nowhere).
Usage: python3 -I -B jcprobe_p9e.py --bin PATH|plain --label L --reps 2 --out J --only P9e0-fg3,P9e-bg-fg3
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jcprobe as J  # noqa: E402


def sc(ctx, sh, tr, with_bg):
    pf = ctx.pf()
    r = {"tries": []}
    sh.cmd(ctx.line(pf, "jcsh"))
    c, j = J.learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    sh.read(0.3)
    sh.mark = len(sh.buf)
    sh.send("xq-ping 1\n")
    r["child_up"] = sh.expect("PONG-1", 3) is not None
    sh.mark = len(sh.buf)
    sh.send("suspend\n")
    r["suspend_prompt"], r["suspend_notice"] = J.wait_stop_prompt(sh, 3)
    if with_bg:
        sh.cmd("bg")
        time.sleep(1.0)
    answered = 0
    for n in (2, 3, 4):
        start = sh.cmd("fg")
        time.sleep(0.8)
        st = J.states(C=c, L=j if ctx.bin else None)
        sh.read(0.05)
        sh.mark = len(sh.buf)
        sh.send("xq-ping %d\n" % n)
        got = sh.expect(r"PONG-%d|xq-ping: command not found|command not found: xq-ping" % n, 3)
        where = "nowhere" if not got else ("child" if got.group(0).startswith("PONG") else "shell")
        text = J.clean(sh.buf[start:])
        r["tries"].append({"fg": n - 1, "states_after_fg": st, "ping_went_to": where,
                           "stop_notice_after_fg": bool(re.search(J.STOPRE, text.split("\n", 1)[-1]))})
        if where == "child":
            answered = n - 1
            break
        if where == "nowhere":
            break
    r["answered_after_fg_number"] = answered
    if answered:
        sh.mark = len(sh.buf)
        sh.send("exit 3\n")
        ok = sh.expect(re.escape(J.PROMPT), 3) is not None
        r["rc_after_exit"] = sh.rc() if ok else "no-prompt"
    r["cmp"] = {"answered_after_fg_number": answered,
                "ping_destinations": [t["ping_went_to"] for t in r["tries"]],
                "rc_after_exit": r.get("rc_after_exit")}
    return r


J.SCENARIOS["P9e0-fg3"] = ("shell", lambda ctx, sh, tr: sc(ctx, sh, tr, False))
J.SCENARIOS["P9e-bg-fg3"] = ("shell", lambda ctx, sh, tr: sc(ctx, sh, tr, True))

if __name__ == "__main__":
    sys.exit(J.main())
