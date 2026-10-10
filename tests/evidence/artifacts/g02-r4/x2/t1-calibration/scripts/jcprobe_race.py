"""M00-T05-r4-x2-t1cal: repeated race probes (stale-stop re-stop after `fg`), same CLI as jcprobe.py.

P10r: P10 (^Z, 1.5 s, `bg` of a terminal reader -> SIGTTIN, `fg`) x3 per run; after each `fg`
      it checks whether the job stopped again at once (a stale stop mirrored after the resume:
      K6e) and, if so, types `fg` once more to see whether that recovers.
P11r: P11 (arm: third-party SIGTSTP of the child, SIGCONT to the launcher / plain: the child, `fg`;
      then ^Z / 1.2 s / `fg` x3) with the same re-stop check after every `fg`.
Usage: python3 -I -B jcprobe_race.py --bin PATH|plain --label L --shell bash --reps 10 --out J
       --only P10r,P11r
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jcprobe as J  # noqa: E402


def fg_check(sh, ctx, c, j):
    """Type `fg`; report whether the job is running 0.6 s later, and recover a re-stop with one
    more `fg`. Returns dict(restopped, second_fg_runs)."""
    start = sh.cmd("fg")
    time.sleep(0.6)
    st = J.states(C=c, L=j if ctx.bin else None)
    text = J.clean(sh.buf[start:])
    restopped = st.get("C") == "T" or st.get("L") == "T" or bool(re.search(J.STOPRE, text.split("\n", 1)[-1]))
    out = {"after_fg": st, "restopped": restopped}
    if restopped:
        sh.cmd("fg")
        time.sleep(0.6)
        st2 = J.states(C=c, L=j if ctx.bin else None)
        out["after_second_fg"] = st2
        out["second_fg_runs"] = st2.get("C") != "T" and st2.get("L") != "T"
    return out


def sc_p10r(ctx, sh, tr):
    pf = ctx.pf()
    r = {"cycles": []}
    sh.cmd(ctx.line(pf, "cat"))
    c, j = J.learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    for i in range(3):
        time.sleep(0.3)
        sh.read(0.05)
        sh.mark = len(sh.buf)
        sh.send("\x1a")
        cy = {}
        cy["ctrlz_prompt"], cy["notice"] = J.wait_stop_prompt(sh)
        time.sleep(1.5)
        sh.cmd("bg")
        time.sleep(1.0)
        cy["after_bg"] = J.states(C=c, L=j if ctx.bin else None)
        cy.update(fg_check(sh, ctx, c, j))
        r["cycles"].append(cy)
    sh.read(0.05)
    sh.mark = len(sh.buf)
    sh.send("hello-cat\n")
    r["echoed"] = sh.expect(r"hello-cat\r?\n\r?hello-cat", 3) is not None
    sh.send("\x04")
    r["prompt_after_eof"] = sh.expect(re.escape(J.PROMPT), 4) is not None
    r["rc"] = sh.rc() if r["prompt_after_eof"] else "no-prompt"
    if not r["prompt_after_eof"]:
        r["recovery"] = J.recover(sh, j, attempts=("ctrlz+fg", "ctrlc"))
    r["cmp"] = {"restops": sum(1 for cy in r["cycles"] if cy["restopped"]),
                "restop_recovered_by_second_fg": all(cy.get("second_fg_runs", True) for cy in r["cycles"]),
                "child_after_bg": [cy["after_bg"].get("C") for cy in r["cycles"]]}
    return r


def sc_p11r(ctx, sh, tr):
    pf = ctx.pf()
    r = {"cycles": []}
    sh.cmd(ctx.line(pf, "sleep", 12, 0))
    c, j = J.learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    time.sleep(0.3)
    os.kill(c, J.SIG["TSTP"])
    r["arm_prompt"], r["arm_notice"] = J.wait_stop_prompt(sh)
    os.kill(j, J.SIG["CONT"])
    time.sleep(0.5)
    r["arm"] = fg_check(sh, ctx, c, j)
    for i in range(3):
        sh.read(0.05)
        sh.mark = len(sh.buf)
        sh.send("\x1a")
        cy = {}
        cy["ctrlz_prompt"], cy["notice"] = J.wait_stop_prompt(sh)
        time.sleep(1.2)
        cy.update(fg_check(sh, ctx, c, j))
        r["cycles"].append(cy)
    m = sh.expect(re.escape(J.PROMPT), 12)
    r["finished"] = m is not None
    r["rc"] = sh.rc() if m else "no-prompt"
    if not m:
        r["recovery"] = J.recover(sh, j, attempts=("ctrlz+fg", "ctrlc"))
    allc = [r["arm"]] + r["cycles"]
    r["cmp"] = {"restops": sum(1 for cy in allc if cy["restopped"]),
                "restop_recovered_by_second_fg": all(cy.get("second_fg_runs", True) for cy in allc),
                "finished": r["finished"], "rc": r["rc"]}
    return r


J.SCENARIOS["P10r"] = ("shell", sc_p10r)
J.SCENARIOS["P11r"] = ("shell", sc_p11r)

if __name__ == "__main__":
    sys.exit(J.main())
