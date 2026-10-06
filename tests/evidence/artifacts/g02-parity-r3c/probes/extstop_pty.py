#!/usr/bin/env python3
"""parity-r3c probe 1b: third-party stop/continue of the CHILD PID while the job is in the
foreground of an interactive job-control shell in a fresh pty.

usage: extstop_pty.py SHELL OUTDIR LABEL=BIN [LABEL=BIN ...]      (SHELL = bash | zsh)

For each target (label "plain" = the child exec'd directly, the control) and each signal
(SIGSTOP, SIGTSTP): start SHELL -i (same set-up as probe.py's Shell class), run in the
foreground
    [BIN run -- ]sh -c 'echo $$ > "$1"; sleep 1; echo x > "$1.done"; exit 7' sh PF
then this probe (a third party) sends SIG to the child PID, waits 0.5 s, records the states and
whether the shell printed a stop notice and a prompt, sends SIGCONT to the child PID only, then
pumps the pty for 6 s and records: launcher state, child state (gone / Z / alive), whether the
child completed, and what the shell shows (`echo RC=$?; jobs`).  If `jobs` still lists the job
as stopped, it sends `fg` (what a user would do) and records the result.  Every PID this probe
learned (child, launcher) is SIGCONT+SIGKILLed by exact PID if still alive at the end.
v2 (parity-r3c): SIGCONT to an already-gone child is recorded (cont_sent=false) instead of
aborting the run (v1 raised ProcessLookupError for the Go darwin SIGSTOP case).
Writes OUTDIR/<shell>-extstop-pty.json and OUTDIR/<shell>-extstop-pty-<label>-<sig>.txt.
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

SHELL, OUT = sys.argv[1], sys.argv[2]
TARGETS = [("plain", None)] + [tuple(a.split("=", 1)) for a in sys.argv[3:]]
LINUX = sys.platform.startswith("linux")
PROMPT = "@P@ "
STOPRE = r"(Stopped|suspended)"


def stat(pid):
    if pid is None:
        return None, None
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


class Shell:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="pr3c-pty-")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp,
               "TERM": "xterm", "LANG": "C", "PS1": PROMPT}
        argv = ["bash", "--norc", "--noprofile", "-i"] if SHELL == "bash" else ["zsh", "-f", "-i"]
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(self.tmp)
            os.execvpe(argv[0], argv, env)
        self.pid, self.fd = pid, fd
        self.buf, self.log, self.mark = "", [], 0
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


def one(label, binpath, sig):
    sh = Shell()
    r = {"shell": SHELL, "via": label, "signal": signal.Signals(sig).name}
    pf = os.path.join(sh.tmp, "pf")
    pre = "" if binpath is None else "%s run -- " % binpath
    sh.send("%ssh -c 'echo $$ > \"$1\"; sleep 1; echo x > \"$1.done\"; exit 7' sh %s\n" % (pre, pf))
    c = None
    end = time.time() + 5
    while time.time() < end and c is None:
        sh.read(0.02)
        try:
            c = int(open(pf).read().strip())
        except (OSError, ValueError):
            pass
    h = stat(c)[1] if binpath else None
    r["launcher_is_child_parent"] = None if binpath is None else (h is not None and h != sh.pid)
    m0 = sh.mark
    try:
        os.kill(c, sig)
        time.sleep(0.5)
        sh.read(0.05)
        seg = sh.buf[m0:]
        r["after_stop"] = {"child": state(c), "launcher": state(h),
                           "shell_stop_notice": bool(re.search(STOPRE, seg)),
                           "shell_prompt": PROMPT in seg}
        try:  # harness fix v2: the child may already be gone (e.g. launcher exited, child got SIGHUP)
            os.kill(c, signal.SIGCONT)
            r["cont_sent"] = True
        except ProcessLookupError:
            r["cont_sent"] = False
        time.sleep(0.2)
        r["after_cont"] = {"child": state(c), "launcher": state(h)}
        t = time.time()
        sh.read(6.0)
        seg = sh.buf[m0:]
        r["after_6s"] = {"child": "%s(ppid=%s)" % stat(c), "launcher": state(h),
                         "child_completed": os.path.exists(pf + ".done"),
                         "shell_prompt": PROMPT in seg,
                         "shell_text": re.sub(r"[^\x20-\x7e]", " ", seg.replace(sh.tmp, "<tmp>"))[-300:]}
        sh.mark = len(sh.buf)
        sh.send("echo RC=$?; jobs; echo JOBS-END\n")
        m = sh.expect(r"RC=(\d+)", 4)
        r["rc_after"] = int(m.group(1)) if m else None
        j = sh.expect(r"JOBS-END", 3)
        jt = sh.buf[m.end():j.start()] if (m and j) else ""
        r["jobs_text"] = re.sub(r"[^\x20-\x7e]", " ", jt.replace(sh.tmp, "<tmp>").replace(pre, "")).strip()[:200]
        r["jobs_says_stopped"] = bool(re.search(r"Stopped|suspended", jt))
        r["jobs_says_running"] = bool(re.search(r"Running|running", jt))
        r["states_at_jobs"] = {"child": "%s(ppid=%s)" % stat(c), "launcher": state(h)}
        if r["jobs_says_stopped"]:
            sh.expect(re.escape(PROMPT), 2)
            sh.mark = len(sh.buf)
            sh.send("fg\n")
            p = sh.expect(re.escape(PROMPT), 4)
            sh.send("echo RC2=$?\n")
            m2 = sh.expect(r"RC2=(\d+)", 4)
            r["user_fg"] = {"prompt_returned": bool(p), "rc": int(m2.group(1)) if m2 else None,
                            "child": "%s(ppid=%s)" % stat(c), "launcher": state(h)}
    except Exception as e:  # record, do not hide
        r["exception"] = repr(e)
    finally:
        sh.read(0.2)
        name = "%s-extstop-pty-%s-%s.txt" % (SHELL, label, signal.Signals(sig).name)
        with open(os.path.join(OUT, name), "w") as f:
            f.write("".join(sh.log).replace(sh.tmp, "<tmp>"))
        left = []
        for x in (c, h):
            if x and state(x) not in (None, "gone", "Z"):
                left.append(x)
                try:
                    os.kill(x, signal.SIGCONT)
                    os.kill(x, signal.SIGKILL)
                except OSError:
                    pass
        r["leftover_killed"] = len(left)
        sh.close()
        subprocess.run(["rm", "-rf", sh.tmp])
    return r


os.makedirs(OUT, exist_ok=True)
res = {"shell": SHELL, "platform": sys.platform, "runs": []}
for label, binpath in TARGETS:
    for sig in (signal.SIGSTOP, signal.SIGTSTP):
        r = one(label, binpath, sig)
        print(json.dumps(r), flush=True)
        res["runs"].append(r)
with open(os.path.join(OUT, "%s-extstop-pty.json" % SHELL), "w") as f:
    json.dump(res, f, indent=1)
