#!/usr/bin/env python3
"""review3c: third-party stop/continue of the CHILD by PID, no job-control shell.

usage: extstop.py HP OUT.json
Non-interactive parent (this script) runs `HP run -- sh -c 'echo $$ >pf; sleep 1; exit 7'`
(and the same command directly, as the control), sends SIGSTOP (and, separately, SIGTSTP)
to the child PID, waits 0.5 s, sends SIGCONT to the child PID only, then waits up to 6 s
for the launcher to exit. Records the exit status or 'hung' plus process states.
A hung launcher is SIGCONT'ed (exact PID) and reaped so nothing is left behind.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

HP, OUT = sys.argv[1], sys.argv[2]
LINUX = sys.platform.startswith("linux")


def state(pid):
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            return s[s.rindex(")") + 2]
        except OSError:
            return "gone"
    r = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip()[:1] or "gone"


def one(via, sig):
    d = tempfile.mkdtemp(prefix="r3c-ext-")
    pf = os.path.join(d, "pf")
    cmd = ["sh", "-c", 'echo $$ > "$1"; sleep 1; exit 7', "sh", pf]
    argv = ([HP, "run", "--"] + cmd) if via == "hp" else cmd
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    c = None
    for _ in range(250):
        try:
            c = int(open(pf).read().strip())
            break
        except (OSError, ValueError):
            time.sleep(0.02)
    r = {"via": via, "signal": signal.Signals(sig).name}
    os.kill(c, sig)
    time.sleep(0.5)
    r["states_after_stop"] = {"child": state(c), "launcher": state(p.pid) if via == "hp" else None}
    os.kill(c, signal.SIGCONT)
    time.sleep(0.2)
    r["states_after_cont"] = {"child": state(c), "launcher": state(p.pid) if via == "hp" else None}
    try:
        rc = p.wait(timeout=6)
        r["result"] = "exit %d" % rc if rc >= 0 else "signal %d" % -rc
    except subprocess.TimeoutExpired:
        r["result"] = "hung"
        r["states_when_hung"] = {"child": state(c), "launcher": state(p.pid)}
        os.kill(p.pid, signal.SIGCONT)  # exact PID we started
        try:
            rc = p.wait(timeout=5)
            r["after_manual_cont_of_launcher"] = "exit %d" % rc if rc >= 0 else "signal %d" % -rc
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            r["after_manual_cont_of_launcher"] = "still hung; SIGKILLed"
    return r


res = {"platform": sys.platform, "runs": []}
for via in ("plain", "hp"):
    for sig in (signal.SIGSTOP, signal.SIGTSTP):
        res["runs"].append(one(via, sig))
with open(OUT, "w") as f:
    json.dump(res, f, indent=1)
print(json.dumps(res, indent=1))
