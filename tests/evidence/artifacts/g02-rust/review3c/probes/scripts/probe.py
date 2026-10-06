#!/usr/bin/env python3
"""review3c independent job-control probes (reviewer-written, not the fixer's tests).

usage: probe.py HP SHELL OUTDIR [scenario,...]
Drives an interactive SHELL (bash or zsh) in a fresh pty and records, per scenario, what
the shell reported, the process states and whether the child kept reading input.
Every scenario is also run with the child exec'd directly ("plain") for comparison where
noted. Writes OUTDIR/<shell>-results.json and OUTDIR/<shell>-transcript-<scenario>.txt.
"""
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

HP, SHELL, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
ONLY = set(sys.argv[4].split(",")) if len(sys.argv) > 4 and sys.argv[4] else None
HERE = os.path.dirname(os.path.abspath(__file__))
CHILD = os.path.join(HERE, "child.py")
PY = "python3"
LINUX = sys.platform.startswith("linux")
PROMPT = "@P@ "
STOPRE = r"(Stopped|suspended)"


def state(pid):
    if pid is None:
        return None
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            return s[s.rindex(")") + 2]
        except OSError:
            return "gone"
    r = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip()[:1] or "gone"


def cputicks(pid):
    if LINUX:
        with open("/proc/%d/stat" % pid) as f:
            s = f.read()
        fields = s[s.rindex(")") + 2:].split()
        return int(fields[11]) + int(fields[12])  # utime+stime clock ticks
    r = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip()


def ppid(pid):
    if LINUX:
        with open("/proc/%d/stat" % pid) as f:
            s = f.read()
        return int(s[s.rindex(")") + 2:].split()[1])
    r = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True)
    return int(r.stdout.strip())


class Shell:
    def __init__(self, name):
        self.tmp = tempfile.mkdtemp(prefix="r3c-")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp,
               "TERM": "xterm", "LANG": "C", "PS1": PROMPT}
        if SHELL == "bash":
            argv = ["bash", "--norc", "--noprofile", "-i"]
        else:
            argv = ["zsh", "-f", "-i"]
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(self.tmp)
            os.execvpe(argv[0], argv, env)
        self.pid, self.fd = pid, fd
        self.buf = ""
        self.log = []
        self.mark = 0
        self.expect(re.escape(PROMPT), 10)
        if SHELL == "zsh":
            self.send("unsetopt zle; PS1='%s'; PROMPT_EOL_MARK=''\n" % PROMPT)
        else:
            self.send("bind 'set enable-bracketed-paste off' 2>/dev/null; PS1='%s'\n" % PROMPT)
        self.expect(re.escape(PROMPT), 10)

    def read(self, t):
        end = time.time() + t
        while True:
            r, _, _ = select.select([self.fd], [], [], max(0, end - time.time()))
            if not r:
                return
            try:
                d = os.read(self.fd, 65536).decode("utf-8", "replace")
            except OSError:
                return
            if not d:
                return
            self.buf += d
            self.log.append(d)
            if time.time() >= end:
                return

    def expect(self, rx, t=5):
        end = time.time() + t
        c = re.compile(rx)
        while True:
            m = c.search(self.buf, self.mark)
            if m:
                self.mark = m.end()
                return m
            left = end - time.time()
            if left <= 0:
                return None
            self.read(min(left, 0.1))

    def send(self, s):
        self.log.append("<<SEND %r>>" % s)
        os.write(self.fd, s.encode())

    def close(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass


STARTED = []


def cleanup():
    """SIGKILL exactly the child/launcher PIDs this probe started, if still present."""
    left = []
    for p in STARTED:
        if state(p) not in (None, "gone", "Z"):
            left.append(p)
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
    STARTED.clear()
    return left


def sample(pids, dur=0.8, step=0.05):
    """States of pids over dur seconds; returns list of tuples."""
    out = []
    end = time.time() + dur
    while time.time() < end:
        out.append(tuple(state(p) for p in pids))
        time.sleep(step)
    return out


def child_pid(pf, t=5):
    end = time.time() + t
    while time.time() < end:
        try:
            with open(pf) as f:
                s = f.read().strip()
            if s:
                return int(s)
        except OSError:
            pass
        time.sleep(0.02)
    return None


def launch(sh, cmdprefix, plain, extra="", tail=""):
    pf = os.path.join(sh.tmp, "pid-%d" % time.time_ns())
    pre = "" if plain else "%s run -- " % HP
    sh.send("%s%s%s %s %s%s\n" % (cmdprefix, pre, PY, CHILD, pf, extra) + tail)
    c = child_pid(pf)
    h = None
    if c is not None and not plain:
        p = ppid(c)
        h = p
    STARTED.extend([x for x in (c, h) if x])
    return pf, c, h


def stop_resume_cycle(sh, res, c, h, cmd, i):
    """Send a self-stop command; expect shell stop notice + prompt, then fg and check."""
    rec = {"cmd": cmd, "i": i}
    if not sh.expect(r"READY-\d+", 5):
        rec["ready_before"] = False
    sh.send(cmd + "\n")
    m = sh.expect(STOPRE, 3)
    rec["shell_stop_notice"] = bool(m)
    rec["prompt_after_stop"] = bool(sh.expect(re.escape(PROMPT), 3))
    time.sleep(0.3)
    rec["states_stopped"] = [state(c), state(h)]
    sh.send("fg\n")
    rec["back"] = bool(sh.expect(r"BACK-%s-\d+" % cmd, 3))
    s = sample([c, h], 0.8)
    rec["restopped_after_fg"] = any("T" in x for x in s)
    rec["states_after_fg_last"] = list(s[-1])
    rec["ready_after"] = bool(sh.expect(r"READY-\d+", 3))
    return rec


def finish(sh, rec, code=5):
    sh.send("exit %d\n" % code)
    sh.expect(re.escape(PROMPT), 5)
    sh.send("echo RC=$?; jobs; echo JOBS-END\n")
    m = sh.expect(r"RC=(\d+)", 5)
    rec["rc"] = int(m.group(1)) if m else None
    j = sh.expect(r"JOBS-END", 3)
    rec["jobs_left"] = bool(re.search(r"\[\d+\]", sh.buf[m.end() if m else 0:j.start() if j else len(sh.buf)])) if m else None


def sc_selfstop(sh, plain=False):
    res = {"plain": plain, "cycles": []}
    pf, c, h = launch(sh, "", plain)
    res["child"] = c is not None
    for i, cmd in enumerate(["tstp", "tstp", "tstp", "stop", "stop", "ttin"]):
        res["cycles"].append(stop_resume_cycle(sh, res, c, h, cmd, i))
    finish(sh, res)
    ok = all(x["shell_stop_notice"] and x["prompt_after_stop"] and x["back"]
             and not x["restopped_after_fg"] and x["ready_after"]
             and x["states_stopped"][0] == "T" and (plain or x["states_stopped"][1] == "T")
             for x in res["cycles"]) and res["rc"] == 5 and not res["jobs_left"]
    res["ok"] = ok
    return res


def sc_ctrlz_fg_bg(sh, plain=False):
    res = {"plain": plain}
    pf, c, h = launch(sh, "", plain)
    sh.expect(r"READY-\d+", 5)
    sh.send("\x1a")
    res["stop_notice"] = bool(sh.expect(STOPRE, 3))
    sh.expect(re.escape(PROMPT), 3)
    time.sleep(0.3)
    res["states_stopped"] = [state(c), state(h)]
    sh.send("bg\n")
    # child resumes its read in the background -> SIGTTIN
    res["ttin_notice"] = bool(sh.expect(r"(Stopped|suspended) \(tty input\)|tty input", 4))
    time.sleep(0.4)
    res["states_after_bg"] = [state(c), state(h)]
    sh.send("fg\n")
    s = sample([c, h], 0.8)
    res["restopped_after_fg"] = any("T" in x for x in s)
    sh.send("hello\n")
    res["child_reads_after_fg"] = bool(sh.expect(r"GOT-hello", 3))
    finish(sh, res)
    res["ok"] = (res["stop_notice"] and res["child_reads_after_fg"] and not res["restopped_after_fg"]
                 and res["rc"] == 5 and not res["jobs_left"])
    return res


def sc_ctrlz_in_grace(sh, plain=False, reps=10, delay=0.05):
    """Child self-stops; Ctrl-Z arrives while the launcher is still in its grace window."""
    res = {"plain": plain, "reps": [], "delay": delay}
    pf, c, h = launch(sh, "", plain)
    for i in range(reps):
        r = {}
        sh.expect(r"READY-\d+", 5)
        sh.send("tstp\n")
        time.sleep(delay)
        sh.send("\x1a")
        r["stop_notice"] = bool(sh.expect(STOPRE, 3))
        sh.expect(re.escape(PROMPT), 3)
        time.sleep(0.3)
        r["states_stopped"] = [state(c), state(h)]
        sh.send("fg\n")
        r["back"] = bool(sh.expect(r"BACK-tstp-\d+", 3))
        s = sample([c, h], 0.8)
        r["restopped_after_fg"] = any("T" in x for x in s)
        if r["restopped_after_fg"]:
            # recover: fg again
            sh.expect(re.escape(PROMPT), 2)
            sh.send("fg\n")
            time.sleep(0.5)
        res["reps"].append(r)
    finish(sh, res)
    res["restops"] = sum(1 for r in res["reps"] if r["restopped_after_fg"])
    res["ok"] = res["restops"] == 0 and res["rc"] == 5
    return res


def sc_ttou(sh, plain=False):
    res = {"plain": plain}
    sh.send("stty tostop\n")
    sh.expect(re.escape(PROMPT), 3)
    pre = "" if plain else "%s run -- " % HP
    sh.send("%ssh -c 'sleep 0.3; echo TTOU-OUT-$((6*7))' &\n" % pre)
    res["stop_notice"] = bool(sh.expect(r"(Stopped|suspended).*\(tty output\)|tty output", 4))
    sh.expect(re.escape(PROMPT), 3)
    sh.send("fg\n")
    res["output_after_fg"] = bool(sh.expect(r"TTOU-OUT-42", 3))
    sh.expect(re.escape(PROMPT), 3)
    sh.send("echo RC=$?; stty -tostop\n")
    m = sh.expect(r"RC=(\d+)", 3)
    res["rc"] = int(m.group(1)) if m else None
    res["ok"] = res["stop_notice"] and res["output_after_fg"] and res["rc"] == 0
    return res


def sc_ttin_bg(sh, plain=False):
    res = {"plain": plain}
    pf, c, h = launch(sh, "", plain, extra=" &")
    res["stop_notice"] = bool(sh.expect(r"tty input", 4))
    sh.expect(re.escape(PROMPT), 3)
    time.sleep(0.3)
    res["states_stopped"] = [state(c), state(h)]
    sh.send("fg\n")
    sh.send("hello\n")
    res["child_reads_after_fg"] = bool(sh.expect(r"GOT-hello", 3))
    finish(sh, res)
    res["ok"] = res["stop_notice"] and res["child_reads_after_fg"] and res["rc"] == 5 and not res["jobs_left"]
    return res


def sc_explicit(sh, plain=False):
    """Explicit SIGTSTP/SIGSTOP to the launcher PID (recorded, §9.4 not gated), then
    child self-stop followed by SIGCONT sent to the launcher PID only."""
    res = {"plain": plain}
    pf, c, h = launch(sh, "", plain)
    target = c if plain else h
    for sig in (signal.SIGTSTP, signal.SIGSTOP):
        r = {}
        sh.expect(r"READY-\d+", 5)
        os.kill(target, sig)
        r["stop_notice"] = bool(sh.expect(STOPRE, 3))
        sh.expect(re.escape(PROMPT), 3)
        time.sleep(0.3)
        r["states"] = [state(c), state(h)]
        sh.send("fg\n")
        sh.send("ping\n")
        r["child_reads_after_fg"] = bool(sh.expect(r"GOT-ping", 3))
        res[signal.Signals(sig).name] = r
    # self-stop, then SIGCONT to the launcher PID only
    sh.expect(r"READY-\d+", 5)
    sh.send("tstp\n")
    sh.expect(STOPRE, 3)
    sh.expect(re.escape(PROMPT), 3)
    time.sleep(0.3)
    os.kill(target, signal.SIGCONT)
    time.sleep(0.6)
    sh.send("jobs; echo JOBS-END2\n")
    j = sh.expect(r"JOBS-END2", 3)
    tail = sh.buf[max(0, (j.start() if j else len(sh.buf)) - 300):(j.start() if j else len(sh.buf))]
    res["cont_to_launcher"] = {
        "states": [state(c), state(h)],
        "jobs_says_running": bool(re.search(r"Running|running", tail)),
        "jobs_says_stopped": bool(re.search(r"Stopped|suspended", tail)),
    }
    if not plain and h is not None:
        t0 = cputicks(h)
        time.sleep(2.0)
        t1 = cputicks(h)
        res["cont_to_launcher"]["launcher_cpu_before_after_2s"] = [t0, t1]
    # recover: continue the child (as the user would have to), then the job finishes.
    os.kill(c, signal.SIGCONT)
    sh.send("fg\n")
    time.sleep(0.5)
    sh.send("ping\n")
    res["cont_to_launcher"]["child_reads_after_recovery"] = bool(sh.expect(r"GOT-ping", 3))
    finish(sh, res)
    return res


def sc_nohup(sh, plain=False):
    res = {"plain": plain}
    pf, c, h = launch(sh, "nohup ", plain, extra=" 2>/dev/null")
    res["cycles"] = [stop_resume_cycle(sh, res, c, h, "tstp", 0), stop_resume_cycle(sh, res, c, h, "stop", 1)]
    finish(sh, res)
    res["ok"] = all(x["shell_stop_notice"] and x["back"] and not x["restopped_after_fg"] for x in res["cycles"]) and res["rc"] == 5
    return res


def sc_nohup_tty(sh, plain=False):
    """GNU nohup redirects a terminal stdin from /dev/null; the child re-opens /dev/tty."""
    res = {"plain": plain}
    pf = os.path.join(sh.tmp, "pid-%d" % time.time_ns())
    pre = "" if plain else "%s run -- " % HP
    sh.send("nohup %ssh -c 'exec %s %s %s </dev/tty' 2>/dev/null\n" % (pre, PY, CHILD, pf))
    c = child_pid(pf)
    # the child exec'd sh's PID; the launcher is its parent
    h = None if plain or c is None else ppid(c)
    STARTED.extend([x for x in (c, h) if x])
    res["cycles"] = [stop_resume_cycle(sh, res, c, h, "tstp", 0), stop_resume_cycle(sh, res, c, h, "stop", 1)]
    finish(sh, res)
    res["ok"] = all(x["shell_stop_notice"] and x["back"] and not x["restopped_after_fg"] for x in res["cycles"]) and res["rc"] == 5
    return res


def sc_pipeline(sh, plain=False):
    """Self-stop of a pipeline member (child | cat). Recorded against plain."""
    res = {"plain": plain}
    pf, c, h = launch(sh, "", plain, extra=" | cat")
    sh.expect(r"READY-\d+", 5)
    sh.send("tstp\n")
    res["stop_notice"] = bool(sh.expect(STOPRE, 3))
    res["prompt"] = bool(sh.expect(re.escape(PROMPT), 1))
    time.sleep(0.3)
    res["states"] = [state(c), state(h)]
    if res["prompt"]:
        sh.send("fg\n")
        res["back"] = bool(sh.expect(r"BACK-tstp", 3))
    else:
        os.kill(c, signal.SIGCONT)
        res["back_after_manual_cont"] = bool(sh.expect(r"BACK-tstp", 3))
        if h is not None:
            # the launcher mirrored the stop; continue it as well
            os.kill(h, signal.SIGCONT)
    s = sample([c, h], 0.6)
    res["any_T_after"] = any("T" in x for x in s)
    sh.send("exit 5\n")
    sh.expect(re.escape(PROMPT), 5)
    sh.send("echo PS=${PIPESTATUS[*]}${pipestatus[*]}\n")
    m = sh.expect(r"PS=([\d ]+)", 5)
    res["pipestatus"] = m.group(1) if m else None
    return res


def sc_sh_c(sh, plain=False):
    """sh -c 'X; echo AFTER=$?' where X self-stops. Recorded against plain."""
    res = {"plain": plain}
    pf = os.path.join(sh.tmp, "pid-%d" % time.time_ns())
    pre = "" if plain else "%s run -- " % HP
    sh.send("sh -c '%s%s %s %s; echo AFTER=$?'\n" % (pre, PY, CHILD, pf))
    c = child_pid(pf)
    h = None if plain else ppid(c)
    STARTED.extend([x for x in (c, h) if x])
    sh.expect(r"READY-\d+", 5)
    sh.send("tstp\n")
    res["stop_notice"] = bool(sh.expect(STOPRE, 2))
    res["prompt"] = bool(sh.expect(re.escape(PROMPT), 1))
    time.sleep(0.3)
    res["states"] = [state(c), state(h)]
    if res["prompt"]:
        sh.send("fg\n")
    else:
        os.kill(c, signal.SIGCONT)
        if h is not None:
            os.kill(h, signal.SIGCONT)
    res["back"] = bool(sh.expect(r"BACK-tstp", 3))
    sh.send("exit 5\n")
    m = sh.expect(r"AFTER=(\d+)", 5)
    res["after"] = int(m.group(1)) if m else None
    return res


def sc_nested_shell(sh, plain=False):
    """A job-control shell as the child, which 'suspend's itself (SIGSTOP to itself).
    Recorded against plain: the nested shell moves itself to its own process group."""
    res = {"plain": plain}
    pre = "" if plain else "%s run -- " % HP
    sh.send("%sbash --norc --noprofile -i\n" % pre)
    time.sleep(1.0)
    sh.send("PS1='@N@ '\n")
    res["nested_prompt"] = bool(sh.expect(r"@N@ ", 3))
    sh.send("echo NPID=$$\n")
    m = sh.expect(r"NPID=(\d+)", 3)
    n = int(m.group(1)) if m else None
    h = None if plain or n is None else ppid(n)
    STARTED.extend([x for x in (n, h) if x])
    sh.send("suspend\n")
    res["stop_notice"] = bool(sh.expect(STOPRE, 3))
    res["outer_prompt"] = bool(sh.expect(re.escape(PROMPT), 2))
    time.sleep(0.3)
    res["states_after_suspend"] = [state(n), state(h)]
    if res["outer_prompt"]:
        sh.send("fg\n")
        time.sleep(1.0)
        res["states_after_fg"] = [state(n), state(h)]
        sh.send("echo NESTED-ALIVE-$((40+2))\n")
        res["nested_responds_after_fg"] = bool(sh.expect(r"NESTED-ALIVE-42", 3))
    # cleanup: kill exactly the nested shell (we know its PID) and our launcher.
    for p in (n, h):
        if p:
            try:
                os.kill(p, signal.SIGCONT)
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
    time.sleep(0.5)
    res["outer_prompt_after_cleanup"] = bool(sh.expect(re.escape(PROMPT), 3))
    return res


SCEN = {
    "selfstop": sc_selfstop,
    "ctrlz_fg_bg": sc_ctrlz_fg_bg,
    "ctrlz_in_grace": sc_ctrlz_in_grace,
    "ttou": sc_ttou,
    "ttin_bg": sc_ttin_bg,
    "explicit": sc_explicit,
    "nohup": sc_nohup,
    "nohup_tty": sc_nohup_tty,
    "pipeline": sc_pipeline,
    "sh_c": sc_sh_c,
    "nested_shell": sc_nested_shell,
}

os.makedirs(OUT, exist_ok=True)
results = {"shell": SHELL, "platform": sys.platform, "hp": HP, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
for name, fn in SCEN.items():
    for plain in (False, True):
        key = name + ("-plain" if plain else "-hp")
        if ONLY and name not in ONLY and key not in ONLY:
            continue
        sh = Shell(SHELL)
        try:
            r = fn(sh, plain)
        except Exception as e:  # record, do not hide
            r = {"exception": repr(e)}
        finally:
            sh.read(0.2)
            with open(os.path.join(OUT, "%s-transcript-%s.txt" % (SHELL, key)), "w") as f:
                f.write("".join(sh.log))
            sh.close()
            time.sleep(0.2)
            r["leftover_killed"] = cleanup() if isinstance(r, dict) else None
        results[key] = r
        print(key, json.dumps(r), flush=True)
results["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
with open(os.path.join(OUT, "%s-results.json" % SHELL), "w") as f:
    json.dump(results, f, indent=1)
