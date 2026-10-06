#!/usr/bin/env python3
"""parity-r3c probe 1a: extstop.py (rust review3c) plus reaping/completion fields.

usage: extstop_plus.py OUT.json LABEL=BIN [LABEL=BIN ...]

Same procedure as tests/evidence/artifacts/g02-rust/review3c/probes/scripts/extstop.py:
a non-interactive parent (this script) runs `BIN run -- sh -c '...'` (and the same command
directly, label "plain", as the control), sends SIGSTOP (and, separately, SIGTSTP) to the child
PID, waits 0.5 s, sends SIGCONT to the child PID only, then waits up to 6 s for the launcher to
exit.  Differences from extstop.py (all additive):
  * the child writes "$1.done" just before `exit 7`, so completion is observable even when the
    launcher exits early or hangs;
  * the launcher result is recorded with the elapsed time;
  * after the launcher exits (or is recovered), the child's state and PPID are sampled for 3 s
    ("gone" = reaped by someone, "Z" = zombie, "T"/"S" = still alive) and child_completed says
    whether the child reached `exit 7`;
  * leftovers: exact child PID SIGCONT+SIGKILL if still alive at the end (recorded).
A hung launcher is SIGCONT'ed (exact PID) and reaped, as in extstop.py.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

OUT = sys.argv[1]
TARGETS = [("plain", None)] + [tuple(a.split("=", 1)) for a in sys.argv[2:]]
LINUX = sys.platform.startswith("linux")


def stat(pid):
    """(state, ppid) or ('gone', None)."""
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            rest = s[s.rindex(")") + 2:].split()
            return rest[0], int(rest[1])
        except OSError:
            return "gone", None
    r = subprocess.run(["ps", "-o", "stat=,ppid=", "-p", str(pid)], capture_output=True, text=True)
    f = r.stdout.split()
    return (f[0][:1], int(f[1])) if len(f) >= 2 else ("gone", None)


def state(pid):
    return stat(pid)[0]


def fmt(rc):
    return "exit %d" % rc if rc >= 0 else "signal %d" % -rc


def one(label, binpath, sig):
    d = tempfile.mkdtemp(prefix="pr3c-ext-")
    pf = os.path.join(d, "pf")
    cmd = ["sh", "-c", 'echo $$ > "$1"; sleep 1; echo x > "$1.done"; exit 7', "sh", pf]
    argv = ([binpath, "run", "--"] + cmd) if binpath else cmd
    t0 = time.monotonic()
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    c = None
    for _ in range(250):
        try:
            c = int(open(pf).read().strip())
            break
        except (OSError, ValueError):
            time.sleep(0.02)
    r = {"via": label, "signal": signal.Signals(sig).name, "my_pid_is_1": os.getpid() == 1,
         "child_ppid_at_start": stat(c)[1], "launcher_is_child_parent": (stat(c)[1] == p.pid) if binpath else None}
    os.kill(c, sig)
    time.sleep(0.5)
    r["states_after_stop"] = {"child": state(c), "launcher": state(p.pid) if binpath else None}
    r["launcher_exited_before_cont"] = p.poll() is not None
    if r["launcher_exited_before_cont"]:
        r["launcher_early_result"] = fmt(p.returncode)
    os.kill(c, signal.SIGCONT)
    time.sleep(0.2)
    r["states_after_cont"] = {"child": state(c), "launcher": state(p.pid) if binpath else None}
    try:
        rc = p.wait(timeout=6)
        r["result"] = fmt(rc)
        r["result_after_s"] = round(time.monotonic() - t0, 2)
    except subprocess.TimeoutExpired:
        r["result"] = "hung"
        r["states_when_hung"] = {"child": state(c), "launcher": state(p.pid)}
        os.kill(p.pid, signal.SIGCONT)  # exact PID we started
        try:
            rc = p.wait(timeout=5)
            r["after_manual_cont_of_launcher"] = fmt(rc)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            r["after_manual_cont_of_launcher"] = "still hung; SIGKILLed"
    samples = []
    for _ in range(15):
        s, pp = stat(c)
        samples.append("%s(ppid=%s)" % (s, "self" if pp == os.getpid() else ("1" if pp == 1 else ("launcher" if pp == p.pid else pp))))
        time.sleep(0.2)
    # collapse consecutive duplicates
    r["child_after_launcher_end_3s"] = [x for i, x in enumerate(samples) if i == 0 or samples[i - 1] != x]
    r["child_completed"] = os.path.exists(pf + ".done")
    left = state(c)
    r["child_left_alive_at_end"] = left not in ("gone", "Z")
    if r["child_left_alive_at_end"]:
        os.kill(c, signal.SIGCONT)
        os.kill(c, signal.SIGKILL)
        r["cleanup"] = "SIGKILLed exact child pid"
    subprocess.run(["rm", "-rf", d])
    return r


res = {"platform": sys.platform, "runs": []}
for label, binpath in TARGETS:
    for sig in (signal.SIGSTOP, signal.SIGTSTP):
        res["runs"].append(one(label, binpath, sig))
with open(OUT, "w") as f:
    json.dump(res, f, indent=1)
print(json.dumps(res, indent=1))
