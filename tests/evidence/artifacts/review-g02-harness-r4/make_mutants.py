#!/usr/bin/env python3
"""Reviewer-built wrong implementations for M00-T05-review-harness-r4 (harness 2.4.0 checks
run.k6e_child_self_stop and k12.closed_stdout_exit_parity).  Each mutant is a copy of
tests/g02/reference_impl.py with exact-match source edits (each anchor must match exactly once),
written to OUT/<name>/heimdall-proto (+ reference_tui.py) so it can be used as --bin on darwin and
as --artifact-dir on Linux (tests/g02/linux/run.sh).  The mutation is baked in (no env var)."""
import os, stat, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SRC = (REPO / "tests/g02/reference_impl.py").read_text()
TUI = (REPO / "tests/g02/reference_tui.py").read_text()
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/rv4/mut")

MIRROR = "                os.kill(os.getpid(), sig)\n                break\n"
STILL = "            if _pid == 0:                     # still stopped: mirror the stop to the shell\n"
GRACE = "STOP_GRACE_S = 0.2\n"
JC_EN = 'if ("run_job_control_own_group" in MUT or "run_child_stop_no_continue" in MUT) and os.isatty(0) and os.isatty(1):'
SIGPIPE_IF = '    if "run_child_sigpipe_ignored" in MUT:\n'
COPIERS = "    copiers = []\n"
JC_CONT = ("            try:\n                os.killpg(child.pid, signal.SIGCONT)\n            except OSError:\n"
           "                pass\n        signal.signal(signal.SIGCONT, jc_on_cont)\n")
JC_TC = "            if fgnow:\n                try:\n                    os.tcsetpgrp(0, child.pid)\n"
JC_TTIN = "                if os.WSTOPSIG(_st) in (signal.SIGTTIN, signal.SIGTTOU):\n"
EXC = "\n    except BrokenPipeError:\n"
TRY = "    try:\n        sys.stdout.buffer.write(data)\n"

MUTANTS = {
    # ---- K6e child-initiated stop (section 9.4)
    "rv_mirror_first_only": ("mirrors only the first child self-stop of a launch; later stops of the same child go "
                             "unreported (per-launch state flag)",
                             [(GRACE, GRACE + "_RV = {'n': 0}\n"),
                              (STILL, "            if _pid == 0 and _RV['n'] >= 1:\n                break\n"
                                      "            if _pid == 0:\n                _RV['n'] += 1\n")]),
    "rv_mirror_tstp_only": ("mirrors a child stop only when the stop signal is SIGTSTP; a SIGSTOP self-stop goes "
                            "unreported (gated form unaffected; section 9.4 records SIGSTOP as non-gating)",
                            [(STILL, "            if _pid == 0 and os.WSTOPSIG(st) != signal.SIGTSTP:\n"
                                     "                break\n" + STILL)]),
    "rv_mirror_killpg": ("mirrors the stop with kill(0, SIG) to its whole process group (the vim suspend idiom) "
                         "instead of stopping only itself",
                         [(MIRROR, "                os.kill(0, sig)\n                break\n")]),
    "rv_cont_child_first": ("on a child stop sends SIGCONT to the child, then stops itself: the child runs again "
                            "while the shell lists the job as stopped",
                            [(MIRROR, "                os.kill(child.pid, signal.SIGCONT)\n" + MIRROR)]),
    "rv_auto_resume": ("supervisor style: a stopped child is continued at once and heimdall-proto never stops "
                       "itself (the shell never learns of the stop)",
                       [(MIRROR, "                os.kill(child.pid, signal.SIGCONT)\n                break\n")]),
    "rv_stop_as_exit": ("naive waitpid(WUNTRACED): a child stop is taken for termination, heimdall-proto exits "
                        "128+stopsig and leaves the child stopped",
                        [(MIRROR, "                child.returncode = 128 + sig\n                return 128 + sig\n")]),
    "rv_nograce": ("mirrors a child stop at once, without the 200 ms grace for a stale stop report (the reference's "
                   "documented darwin race after a terminal Ctrl-Z / fg)",
                   [(GRACE, "STOP_GRACE_S = 0.0\n")]),
    "rv_own_pgrp_no_cont": ("child always in its own (background) process group without the terminal (to avoid "
                            "duplicate terminal signals); stops are mirrored, but the shell's SIGCONT reaches only "
                            "heimdall-proto's group and is not passed on",
                            [(SIGPIPE_IF, '    popen_kw["process_group"] = 0\n' + SIGPIPE_IF)]),
    "rv_own_pgrp_fwd_cont": ("as rv_own_pgrp_no_cont, but SIGCONT is forwarded to the child (which is still in a "
                             "background group without the terminal)",
                             [(SIGPIPE_IF, '    popen_kw["process_group"] = 0\n' + SIGPIPE_IF),
                              (COPIERS, "    signal.signal(signal.SIGCONT, lambda s, f: os.kill(child.pid, "
                                        "signal.SIGCONT))\n" + COPIERS)]),
    "rv_jc_no_sigcont": ("job-control launcher (child its own foreground group): on `fg` it hands the terminal to "
                         "the child but never continues it",
                         [(JC_EN, "if os.isatty(0) and os.isatty(1):"),
                          (JC_CONT, "            pass\n        signal.signal(signal.SIGCONT, jc_on_cont)\n")]),
    "rv_jc_no_tcsetpgrp": ("job-control launcher: on `fg` it continues the child but never gives it the terminal, "
                           "and treats the child's resulting SIGTTIN like any stop",
                           [(JC_EN, "if os.isatty(0) and os.isatty(1):"),
                            (JC_TC, "            if False:\n                try:\n                    os.tcsetpgrp(0, child.pid)\n"),
                            (JC_TTIN, "                if False:\n")]),
    # ---- K12 closed stdout (section 9.4)
    "rv_k12_json_error_epipe": ("--json failure results (exit 2 SCHEMA_INVALID/USAGE_ERROR, exit 5 AGENT_*) die on "
                                "EPIPE with exit 1; success results and plain mode (writes nothing to stdout on "
                                "failure) are fine",
                                [(EXC, EXC + '        if not plain and doc.get("state") == "failed":\n'
                                             "            exit_code = 1\n")]),
    "rv_k12_agent_plain_only": ("only `agent list` without --json treats EPIPE as fatal (exit 1); version and profile "
                                "show are fine",
                                [(EXC, EXC + '        if plain and len(sys.argv) > 1 and sys.argv[1] == "agent":\n'
                                             "            exit_code = 1\n")]),
    "rv_k12_json_sigpipe": ("--json only: SIGPIPE reset to default before writing (death by SIGPIPE); plain ignores "
                            "the write error",
                            [(TRY, "    if not plain:\n        signal.signal(signal.SIGPIPE, signal.SIG_DFL)\n" + TRY)]),
    "rv_k12_exit141_vs_signal": ("plain dies by SIGPIPE; --json catches EPIPE and exits 141 (128+SIGPIPE) - same "
                                 "number, different wait status",
                                 [(TRY, "    if plain:\n        signal.signal(signal.SIGPIPE, signal.SIG_DFL)\n" + TRY),
                                  (EXC, EXC + "        if not plain:\n            exit_code = 141\n")]),
    "rv_k12_plain_unflushed": ("plain mode writes through the buffered stream and never flushes: the EPIPE surfaces "
                               "at interpreter shutdown (CPython exit 120); --json flushes and handles it",
                               [(TRY, "    if plain:\n        sys.stdout.buffer.write(data)\n        sys.exit(exit_code)\n"
                                 + TRY)]),
    # ---- added in the resumed review (2026-10-05)
    "rv_rc_lost_after_stop": ("after any mirrored stop the final status is lost: heimdall-proto exits 0 instead of "
                              "the child's status",
                              [(GRACE, GRACE + "_RVS = {'stopped': False}\n"),
                               (MIRROR, "                _RVS['stopped'] = True\n" + MIRROR),
                               ("        child.returncode = rc\n        return rc\n",
                                "        child.returncode = rc\n        return 0 if _RVS['stopped'] else rc\n")]),
    "ctl_mirror_sigstop_always": ("CONFORMING control: always mirrors with SIGSTOP (notice word differs, non-gating)",
                                  [(MIRROR, "                os.kill(os.getpid(), signal.SIGSTOP)\n                break\n")]),
    "ctl_mirror_delay_1s": ("CONFORMING control: mirrors the stop 1 s late (no time bound in section 9.4; harness "
                            "allows 4 s)",
                            [(MIRROR, "                time.sleep(1.0)\n" + MIRROR)]),
    "rv_k12_plain_hang": ("plain mode: on EPIPE retries/sleeps 40 s (no wait status within the 20 s budget); --json "
                          "exits normally",
                          [(EXC, EXC + "        if plain:\n            time.sleep(40)\n")]),
    "rv_k12_plain_stderr_json_sigpipe": ("plain mode writes its result to stderr (exit normally); --json resets "
                                         "SIGPIPE and dies by it on the closed stdout",
                                         [(TRY, "    if plain:\n        sys.stderr.buffer.write(data)\n"
                                                "        sys.stderr.buffer.flush()\n        sys.exit(exit_code)\n"
                                                "    signal.signal(signal.SIGPIPE, signal.SIG_DFL)\n" + TRY)]),
    "rv_k12_profile_json_only": ("only `profile show --json` treats EPIPE as fatal (exit 1)",
                                 [(EXC, EXC + '        if not plain and len(sys.argv) > 1 and sys.argv[1] == "profile":\n'
                                              "            exit_code = 1\n")]),
}


def build(name):
    desc, edits = MUTANTS[name]
    s = SRC
    for old, new in edits:
        n = s.count(old)
        if n != 1:
            raise SystemExit("%s: anchor matched %d times: %r" % (name, n, old[:60]))
        s = s.replace(old, new)
    d = OUT / name
    d.mkdir(parents=True, exist_ok=True)
    p = d / "heimdall-proto"
    p.write_text(s)
    p.chmod(0o755)
    (d / "reference_tui.py").write_text(TUI)
    return p


if __name__ == "__main__":
    for n in MUTANTS:
        print(n, build(n))
