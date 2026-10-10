"""M00-T05-r4-x2-t1cal: identical job-control probes for every X2 T1 build and a plain-exec control.

Usage: python3 -I -B jcprobe.py --bin PATH|plain --label NAME --shell bash|zsh --reps N
                                --out JSON [--only P1-TSTP,P3-STOP,...]
Every scenario runs in a fresh interactive shell on a fresh pty (or, for P0/P6/P13, under a
non-shell parent written here).  The probe is the "third party": it signals exactly one PID with
kill(2).  Every PID the probe learns is recorded with its start time and is killed (SIGCONT then
SIGKILL) only if the same process still exists.  Nothing prints command lines or environments;
transcripts replace the scratch dir, the binary path and the python path with placeholders.
"""
import argparse
import ctypes
import fcntl
import json
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

LINUX = sys.platform.startswith("linux")
PROMPT = "@P@ "
STOPRE = r"(Stopped|suspended)"
PY = sys.executable
HERE = os.path.dirname(os.path.abspath(__file__))
SIG = {n: getattr(signal, "SIG" + n) for n in ("STOP", "TSTP", "TTIN", "TTOU", "CONT", "KILL")}
REAPED = {}  # Linux PID-1 only: pid -> raw wait status of reparented orphans we reaped

# ----------------------------------------------------------------------------- process helpers
if not LINUX:
    _libc = ctypes.CDLL(None, use_errno=True)


def fast_state(pid):
    """One letter: T stopped, Z zombie, R/S alive otherwise, 'gone'. Cheap enough to sample."""
    if pid is None:
        return None
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            st = s[s.rindex(")") + 2:].split()[0]
            return "T" if st in ("T", "t") else st
        except OSError:
            return "gone"
    mib = (ctypes.c_int * 4)(1, 14, 1, pid)  # CTL_KERN, KERN_PROC, KERN_PROC_PID
    buf = ctypes.create_string_buffer(1024)
    sz = ctypes.c_size_t(1024)
    if _libc.sysctl(mib, 4, buf, ctypes.byref(sz), None, ctypes.c_size_t(0)) != 0 or sz.value == 0:
        return "gone"
    raw = buf.raw
    if int.from_bytes(raw[40:44], "little") != pid:
        return "gone"
    return {1: "S", 2: "R", 3: "S", 4: "T", 5: "Z"}.get(raw[36], "?")


def pinfo(pid):
    """dict(ppid, pgid, start) or None. start identifies the process for exact-PID kills."""
    if pid is None:
        return None
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            x = s[s.rindex(")") + 2:].split()
            return {"ppid": int(x[1]), "pgid": int(x[2]), "start": x[19]}
        except OSError:
            return None
    r = subprocess.run(["/bin/ps", "-o", "ppid=,pgid=,lstart=", "-p", str(pid)],
                       capture_output=True, text=True)
    f = r.stdout.split(None, 2)
    if len(f) < 3:
        return None
    return {"ppid": int(f[0]), "pgid": int(f[1]), "start": f[2].strip()}


class Tracked:
    """PIDs this probe learned, with identity, for exact-PID cleanup."""

    def __init__(self):
        self.ids = {}

    def add(self, name, pid):
        if pid and pid not in [p for p, _ in self.ids.values()]:
            i = pinfo(pid)
            if i:
                self.ids[name] = (pid, i["start"])

    def same(self, pid, start):
        i = pinfo(pid)
        return i is not None and i["start"] == start and fast_state(pid) not in ("gone", "Z")

    def kill_all(self):
        n = []
        for name, (pid, start) in self.ids.items():
            if self.same(pid, start):
                n.append(name)
                for s in (SIG["CONT"], SIG["KILL"]):
                    try:
                        os.kill(pid, s)
                    except OSError:
                        pass
        return n

    def leftovers(self, wait=3.0):
        end = time.time() + wait
        while True:
            reap_orphans()
            left = [name for name, (pid, start) in self.ids.items() if self.same(pid, start)]
            if not left or time.time() > end:
                return left
            time.sleep(0.05)


def reap_orphans():
    """When this probe is PID 1 (Linux container), orphans are reparented to it: reap them."""
    if not (LINUX and os.getpid() == 1):
        return
    while True:
        try:
            p, st = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if p == 0:
            return
        REAPED[p] = st


def default_signals():
    """Python ignores SIGPIPE/SIGXFSZ; exec'd shells and jobs must not inherit that."""
    for s in ("SIGPIPE", "SIGXFSZ", "SIGTTOU", "SIGTTIN", "SIGTSTP"):
        if hasattr(signal, s):
            signal.signal(getattr(signal, s), signal.SIG_DFL)


def decode(st):
    if os.WIFEXITED(st):
        return os.WEXITSTATUS(st)
    if os.WIFSIGNALED(st):
        return "signal %d" % os.WTERMSIG(st)
    return "status %d" % st


def wait_pf(path, t, pump=None):
    end = time.time() + t
    while time.time() < end:
        try:
            with open(path) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            pass
        (pump or time.sleep)(0.02)
    return None


def states(**pids):
    return {k: fast_state(v) for k, v in pids.items() if v}


def clean(s):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]", "", s).replace("\r", "")


# ----------------------------------------------------------------------------- the shell
class Shell:
    def __init__(self, kind, tmp):
        self.kind, self.tmp = kind, tmp
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": tmp, "TERM": "dumb", "LANG": "C",
               "PS1": PROMPT, "BASH_SILENCE_DEPRECATION_WARNING": "1"}
        argv = ["/bin/bash", "--norc", "--noprofile", "-i"] if kind == "bash" else ["/bin/zsh", "-f", "-i"]
        pid, fd = pty.fork()
        if pid == 0:
            default_signals()
            os.chdir(tmp)
            os.execve(argv[0], argv, env)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 2000, 0, 0))
        self.pid, self.fd = pid, fd
        self.buf, self.mark, self.n, self.eof, self.status = "", 0, 0, False, None
        self.expect(re.escape(PROMPT), 10)
        if kind == "zsh":
            self.send("unsetopt zle prompt_sp prompt_cr bang_hist; PS1='%s'; PROMPT_EOL_MARK=''\n" % PROMPT)
        else:
            self.send("set +H; bind 'set enable-bracketed-paste off' 2>/dev/null; PS1='%s'\n" % PROMPT)
        self.sync()

    def read(self, t):
        end = time.time() + t
        while not self.eof:
            r, _, _ = select.select([self.fd], [], [], max(0, end - time.time()))
            if not r:
                return
            try:
                d = os.read(self.fd, 65536).decode("utf-8", "replace")
            except OSError:
                d = ""
            if not d:
                self.eof = True
                self.buf += "<<PTY EOF>>"
                return
            self.buf += d
            if time.time() >= end:
                return

    def pump(self, t):
        self.read(t)

    def expect(self, rx, t=5):
        end = time.time() + t
        c = re.compile(rx)
        while True:
            m = c.search(self.buf, self.mark)
            if m:
                self.mark = m.end()
                return m
            left = end - time.time()
            if left <= 0 or self.eof:
                return None
            self.read(min(left, 0.05))

    def send(self, s):
        try:
            os.write(self.fd, s.encode())
            return True
        except OSError:
            return False

    def cmd(self, line, idle=1.0):
        """Wait (bounded) for the prompt, skip pending output, then type one line.
        Returns the buffer offset before it."""
        end = time.time() + idle
        while time.time() < end and not self.eof and not self.buf.endswith(PROMPT):
            self.read(0.02)
        self.read(0.05)
        self.mark = len(self.buf)
        self.send(line + "\n")
        return self.mark

    def sync(self, t=5):
        self.n += 1
        self.cmd('echo "@M""K%d@"' % self.n)
        return self.expect("@MK%d@" % self.n, t) is not None

    def rc(self, t=5):
        self.n += 1
        self.cmd('echo "@R""C%d=$?@"' % self.n)
        m = self.expect(r"@RC%d=(\d+)@" % self.n, t)
        return int(m.group(1)) if m else "no-prompt"

    def jobs(self, j=None, t=5):
        """`jobs -l` -> (summary, cleaned text). summary: stopped(<detail>)|running|done|none|no-prompt"""
        self.n += 1
        start = self.cmd('jobs -l; echo "@J""B%d@"' % self.n)
        m = self.expect("@JB%d@" % self.n, t)
        if not m:
            return "no-prompt", clean(self.buf[start:])[-300:]
        text = clean(self.buf[start:m.start()])
        lines = [l for l in text.split("\n") if re.match(r"^\[\d+\]", l.strip())]
        if j is not None:
            lj = [l for l in lines if re.search(r"\b%d\b" % j, l)]
            lines = lj or lines
        if not lines:
            return "none", text
        return classify_job(lines[-1]), text

    def alive(self):
        if self.status is not None:
            return False
        try:
            p, st = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.status = "reaped-elsewhere"
            return False
        if p == 0:
            return True
        self.status = decode(st)
        return False

    def close(self):
        if self.alive():
            try:
                os.kill(self.pid, SIG["KILL"])
            except OSError:
                pass
            end = time.time() + 10
            while time.time() < end and self.alive():
                self.eof = False
                self.read(0.05)
        try:
            os.close(self.fd)
        except OSError:
            pass


def classify_job(line):
    """'stopped[<status as printed>]', 'running', 'done[<status>]' or 'other[...]'."""
    m = re.match(r"^\s*\[\d+\]\s*[+-]?\s*\d+\s+(.*)$", line)
    rest = m.group(1) if m else line
    m2 = re.match(r"((?:Running|running|Done|done|Exit|exit|Stopped|stopped|Suspended|suspended|continued|"
                  r"Killed|killed|Terminated|terminated|Hangup|hangup)(?: \d+)?(?: \([a-z ]+\))?(?:: ?\d+)?)",
                  rest)
    raw = re.sub(r"\s+", " ", (m2.group(1) if m2 else rest[:30])).strip()
    l = raw.lower()
    if "stopped" in l or "suspended" in l:
        return "stopped[%s]" % raw
    if "running" in l:
        return "running"
    if "done" in l or "exit" in l or "killed" in l or "terminated" in l:
        return "done[%s]" % raw
    return "other[%s]" % raw


# ----------------------------------------------------------------------------- scenario support
class Ctx:
    def __init__(self, binpath, shell, label):
        self.bin, self.shell, self.label = binpath, shell, label
        self.tmp = tempfile.mkdtemp(prefix="t1c-", dir="/tmp")
        self.child = os.path.join(self.tmp, "child.py")
        shutil.copy(os.path.join(HERE, "child.py"), self.child)
        self.k = 0

    def pf(self):
        self.k += 1
        return os.path.join(self.tmp, "pf%d" % self.k)

    def pre(self):
        return (self.bin + " run -- ") if self.bin else ""

    def argv(self, pf, *mode):
        a = [PY, "-I", "-B", self.child, pf] + [str(x) for x in mode]
        return ([self.bin, "run", "--"] + a) if self.bin else a

    def line(self, pf, *mode):
        return self.pre() + " ".join([PY, "-I", "-B", self.child, pf] + [str(x) for x in mode])

    def redact(self, s):
        s = s.replace("/private" + self.tmp, "<tmp>").replace(self.tmp, "<tmp>")
        if self.bin:
            s = s.replace(self.bin, "<bin>")
        s = s.replace(PY, "<py>")
        home = os.environ.get("HOME")
        if home and len(home) > 3:
            s = s.replace(home, "<home>")
        return s

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def learn(ctx, sh, tr, pf, t=5):
    """Child PID from its pid file; job PID J = launcher (or the child itself under plain exec)."""
    c = wait_pf(pf, t, sh.pump if sh else None)
    if c is None:
        return None, None
    tr.add("child", c)
    j = c
    if ctx.bin:
        i = pinfo(c)
        j = i["ppid"] if i else None
        tr.add("launcher", j)
    return c, j


def wait_stop_prompt(sh, t=3):
    """After a foreground job stops: did the shell print a stop notice and a prompt?"""
    start = sh.mark
    m = sh.expect(re.escape(PROMPT), t)
    text = clean(sh.buf[start:sh.mark if m else len(sh.buf)])
    n = re.search(r"(Stopped[^\n]*|suspended[^\n]*)", text)
    notice = None
    if n:
        notice = re.sub(r"\s+", " ", n.group(1)).strip()
        notice = re.sub(r" (/|<|\S*python).*$", "", notice)
    return bool(m), notice


def recover(sh, j=None, feed=None, expect_out=None, fg_wait=8, attempts=("fg", "fg", "ctrlz+fg", "ctrlc")):
    """Uniform recovery with the shell's own job control. Returns dict(how, rc, steps)."""
    steps = []
    for how in attempts:
        if how == "ctrlc":
            sh.read(0.05)
            sh.mark = len(sh.buf)
            sh.send("\x03")
            ok = sh.expect(re.escape(PROMPT), 3) is not None
            steps.append(("ctrlc", "prompt" if ok else "no-prompt"))
            if ok:
                return {"how": "ctrlc", "rc": sh.rc(), "steps": steps}
            continue
        if how == "ctrlz+fg":
            sh.read(0.05)
            sh.mark = len(sh.buf)
            sh.send("\x1a")
            ok = sh.expect(re.escape(PROMPT), 3) is not None
            steps.append(("ctrlz", "prompt" if ok else "no-prompt"))
            if not ok:
                continue
        start = sh.cmd("fg")
        if feed:
            time.sleep(0.5)
            sh.send(feed)
        m = sh.expect(re.escape(PROMPT), fg_wait)
        text = clean(sh.buf[start:sh.mark if m else len(sh.buf)])
        if not m:
            steps.append((how, "hung"))
            continue
        if re.search(r"no (such|current) job", text):
            steps.append((how, "no-job"))
            return {"how": "none-needed", "rc": None, "steps": steps}
        rc = sh.rc()
        if re.search(STOPRE, text.split("\n", 1)[-1]):
            steps.append((how, "stopped-again rc=%s" % rc))
            continue
        out_ok = None if expect_out is None else (expect_out in text)
        steps.append((how, "done rc=%s" % rc + ("" if out_ok is None else " out=%s" % out_ok)))
        return {"how": how, "rc": rc, "out_ok": out_ok, "steps": steps}
    return {"how": "failed", "rc": None, "steps": steps}


# ----------------------------------------------------------------------------- scenarios
def sc_p0(ctx, sig):
    """S1 with pipes: a non-shell parent, launcher in its own non-orphaned group, stdio pipes."""
    tr = Tracked()
    pf = ctx.pf()
    p = subprocess.Popen(ctx.argv(pf, "sleep", 1.5, 7), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=ctx.tmp, process_group=0,
                         preexec_fn=default_signals,
                         env={"PATH": "/usr/bin:/bin", "HOME": ctx.tmp, "LANG": "C"})
    tr.add("launcher", p.pid)
    r = {}
    try:
        c = wait_pf(pf, 5)
        if c is None:
            return {"error": "no child pid"}, tr
        tr.add("child", c)
        time.sleep(0.3)
        os.kill(c, SIG[sig])
        time.sleep(0.5)
        r["after_stop"] = states(C=c, L=p.pid if ctx.bin else None)
        os.kill(c, SIG["CONT"])
        t1 = time.monotonic()
        try:
            r["rc"] = p.wait(timeout=6)
            r["exit_after_cont_s"] = round(time.monotonic() - t1, 1)
        except subprocess.TimeoutExpired:
            r["rc"] = "hung"
            r["hung_states"] = states(C=c, L=p.pid)
        r["child_completed"] = os.path.exists(pf + ".done")
        time.sleep(0.2)
        r["child_after"] = fast_state(c)
    finally:
        if p.poll() is None:
            tr.kill_all()
            p.wait()
        for f in (p.stdin, p.stdout, p.stderr):
            f.close()
    r["cmp"] = {"rc": r.get("rc"), "child_completed": r.get("child_completed"),
                "child_reaped": r.get("child_after") == "gone"}
    return r, tr


def sc_bg(ctx, sh, tr, sig, redirect, via_ctrlz=False, kcont=False):
    """P1 (redirected) / P2 (terminal) / P5 (^Z then bg): third party stops a background job's child."""
    pf = ctx.pf()
    r = {}
    red = " </dev/null >/dev/null 2>&1" if redirect else ""
    if via_ctrlz:
        sh.cmd(ctx.line(pf, "sleep", 6, 0) + red)
    else:
        sh.cmd(ctx.line(pf, "sleep", 6, 0) + red + " &")
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    if via_ctrlz:
        time.sleep(0.3)
        sh.send("\x1a")
        r["ctrlz_prompt"], r["ctrlz_notice"] = wait_stop_prompt(sh)
        sh.cmd("bg")
        time.sleep(0.6)
        r["after_bg"] = states(C=c, L=j if ctx.bin else None)
    else:
        sh.sync()
        time.sleep(0.3)
    os.kill(c, SIG[sig])
    time.sleep(0.8)
    r["after_stop"] = states(C=c, L=j if ctx.bin else None)
    r["jobs"], r["jobs_text"] = sh.jobs(j)
    time.sleep(0.3)
    r["after_jobs"] = states(C=c, L=j if ctx.bin else None)
    if kcont:
        sh.cmd("kill -CONT %1")
        time.sleep(1.0)
        r["after_kill_cont_jobspec"] = states(C=c, L=j if ctx.bin else None)
        r["jobs_after_kill_cont"], _ = sh.jobs(j)
    r["recovery"] = recover(sh, j)
    r["child_completed"] = os.path.exists(pf + ".done")
    r["cmp"] = {"jobs": r["jobs"], "child_state": r["after_stop"].get("C"),
                "job_stopped_consistent": consistent(r["after_stop"], ctx),
                "recovery": r["recovery"]["how"], "rc": r["recovery"]["rc"],
                "child_completed": r["child_completed"]}
    if kcont:
        r["cmp"]["child_after_kill_cont_jobspec"] = r["after_kill_cont_jobspec"].get("C")
    return r


def consistent(st, ctx):
    """True if the job's processes agree: either all stopped or none stopped."""
    v = [x for x in st.values() if x not in (None, "gone", "Z")]
    return len(set(x == "T" for x in v)) <= 1


def sc_p2n(ctx, sh, tr):
    """P2n: background job (stdio on the terminal) whose child reads the terminal: kernel SIGTTIN."""
    pf = ctx.pf()
    r = {}
    sh.cmd(ctx.line(pf, "read", 4) + " &")
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    sh.sync()
    time.sleep(1.0)
    r["after_ttin"] = states(C=c, L=j if ctx.bin else None)
    r["jobs"], r["jobs_text"] = sh.jobs(j)
    r["recovery"] = recover(sh, j, feed="hello\n", expect_out="GOT=hello")
    r["child_completed"] = os.path.exists(pf + ".done")
    r["cmp"] = {"jobs": r["jobs"], "child_state": r["after_ttin"].get("C"),
                "job_stopped_consistent": consistent(r["after_ttin"], ctx),
                "recovery": r["recovery"]["how"], "rc": r["recovery"]["rc"],
                "out_ok": r["recovery"].get("out_ok"), "child_completed": r["child_completed"]}
    return r


def sc_p3(ctx, sh, tr, sig):
    """P3: a non-job-control parent (bash -c) on the terminal; stop the child, continue the child only."""
    pf = ctx.pf()
    r = {}
    inner = ctx.line(pf, "sleep", 2, 7)
    sh.cmd("/bin/bash --norc --noprofile -c \"%s; echo @R''C3=\\$?@\"" % inner)
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    bc = pinfo(j)["ppid"] if pinfo(j) else None
    tr.add("bash_c", bc)
    time.sleep(0.3)
    os.kill(c, SIG[sig])
    time.sleep(0.5)
    r["after_stop"] = states(C=c, L=j if ctx.bin else None)
    os.kill(c, SIG["CONT"])
    t1 = time.monotonic()
    m = sh.expect(r"@RC3=(\d+)@", 6)
    if m:
        r["rc"] = int(m.group(1))
        r["after_cont_s"] = round(time.monotonic() - t1, 1)
        sh.expect(re.escape(PROMPT), 3)
        r["recovery"] = {"how": "none-needed", "rc": r["rc"]}
    else:
        r["rc"] = "hung"
        r["hung_states"] = states(C=c, L=j if ctx.bin else None)
        r["recovery"] = recover(sh, None, attempts=("ctrlz+fg", "ctrlc"))
        m2 = re.search(r"@RC3=(\d+)@", clean(sh.buf))
        r["recovery"]["inner_rc"] = int(m2.group(1)) if m2 else None
    r["child_completed"] = os.path.exists(pf + ".done")
    r["cmp"] = {"rc": r["rc"], "recovery": r["recovery"]["how"],
                "inner_rc_after_recovery": r["recovery"].get("inner_rc", r["rc"]),
                "child_completed": r["child_completed"]}
    return r


def sc_fgstop(ctx, sh, tr, sig, redirect):
    """P4 (redirected) / P4t (terminal) / P7 (SIGTTOU/SIGTTIN): third party stops a foreground child."""
    pf = ctx.pf()
    r = {}
    red = " </dev/null >/dev/null 2>&1" if redirect else ""
    sh.cmd(ctx.line(pf, "sleep", 5, 0) + red)
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    time.sleep(0.3)
    os.kill(c, SIG[sig])
    r["prompt_returned"], r["notice"] = wait_stop_prompt(sh, 3)
    r["after_stop"] = states(C=c, L=j if ctx.bin else None)
    if r["prompt_returned"]:
        r["rc_at_prompt"] = sh.rc()
        r["jobs"], r["jobs_text"] = sh.jobs(j)
        r["recovery"] = recover(sh, j)
    else:
        r["rc_at_prompt"] = "no-prompt"
        r["jobs"] = "no-prompt"
        r["recovery"] = recover(sh, j, attempts=("ctrlz+fg", "ctrlz+fg", "ctrlc"))
    r["child_completed"] = os.path.exists(pf + ".done")
    r["cmp"] = {"prompt_returned": r["prompt_returned"], "notice": r["notice"],
                "rc_at_prompt": r["rc_at_prompt"], "jobs": r["jobs"],
                "child_state": r["after_stop"].get("C"),
                "job_stopped_consistent": consistent(r["after_stop"], ctx),
                "recovery": r["recovery"]["how"], "rc": r["recovery"]["rc"],
                "child_completed": r["child_completed"]}
    return r


def sc_p6(ctx, sig):
    """P6: a non-shell parent on a pty that puts the job in its own group in the foreground and
    waits without WUNTRACED; a third party stops the child, then continues the child only."""
    tr = Tracked()
    pf = ctx.pf()
    m, s = pty.openpty()
    rd, wr = os.pipe()
    sync_r, sync_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(m)
            os.close(rd)
            os.setsid()
            fcntl.ioctl(s, termios.TIOCSCTTY, 0)
            signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            argv = ctx.argv(pf, "sleep", 2, 7)
            lp = os.fork()
            if lp == 0:
                default_signals()
                os.setpgid(0, 0)
                os.read(sync_r, 1)
                for fd in (0, 1, 2):
                    os.dup2(s, fd)
                os.chdir(ctx.tmp)
                os.execve(argv[0], argv, {"PATH": "/usr/bin:/bin", "HOME": ctx.tmp, "LANG": "C", "TERM": "dumb"})
            try:
                os.setpgid(lp, lp)
            except OSError:
                pass
            os.tcsetpgrp(s, lp)
            os.write(sync_w, b"x")
            os.write(wr, b"L%d\n" % lp)
            _, st = os.waitpid(lp, 0)
            os.write(wr, b"S%d\n" % st)
        finally:
            os._exit(0)
    os.close(s)
    os.close(wr)
    os.close(sync_r)
    os.close(sync_w)
    tr.add("parent", pid)
    r = {}
    buf = b""

    def readpipe(t, want=b"S"):
        nonlocal buf
        end = time.time() + t
        while time.time() < end:
            rr, _, _ = select.select([rd, m], [], [], max(0, end - time.time()))
            if m in rr:
                try:
                    os.read(m, 65536)
                except OSError:
                    pass
            if rd in rr:
                d = os.read(rd, 4096)
                if not d:
                    return
                buf += d
                if want in buf:
                    return
    try:
        readpipe(2, b"\n")
        mm = re.search(rb"L(\d+)", buf)
        lp = int(mm.group(1)) if mm else None
        tr.add("launcher", lp)
        c = wait_pf(pf, 5, lambda t: readpipe(t, b"S"))
        if c is None:
            return {"error": "no child pid"}, tr
        tr.add("child", c)
        time.sleep(0.3)
        os.kill(c, SIG[sig])
        time.sleep(0.5)
        r["after_stop"] = states(C=c, L=lp if ctx.bin else None)
        os.kill(c, SIG["CONT"])
        readpipe(6)
        ms = re.search(rb"S(\d+)", buf)
        r["rc"] = decode(int(ms.group(1))) if ms else "hung"
        if not ms:
            r["hung_states"] = states(C=c, L=lp)
        r["child_completed"] = os.path.exists(pf + ".done")
    finally:
        tr.kill_all()
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(rd)
        os.close(m)
    r["cmp"] = {"rc": r.get("rc"), "child_completed": r.get("child_completed")}
    return r, tr


def sc_p7n(ctx, sh, tr):
    """P7n: a background job (stdio on the terminal) whose child calls tcsetattr: kernel SIGTTOU."""
    pf = ctx.pf()
    r = {}
    sh.cmd(ctx.line(pf, "ttou", 3) + " &")
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    sh.sync()
    time.sleep(1.0)
    r["after_ttou"] = states(C=c, L=j if ctx.bin else None)
    r["child_completed_in_bg"] = os.path.exists(pf + ".done")
    r["jobs"], r["jobs_text"] = sh.jobs(j)
    r["recovery"] = recover(sh, j)
    r["child_completed"] = os.path.exists(pf + ".done")
    r["cmp"] = {"jobs": r["jobs"], "child_state": r["after_ttou"].get("C"),
                "completed_in_bg": r["child_completed_in_bg"],
                "job_stopped_consistent": consistent(r["after_ttou"], ctx),
                "recovery": r["recovery"]["how"], "rc": r["recovery"]["rc"]}
    return r


def sc_p8(ctx, sh, tr):
    """P8: terminal ^Z (whole foreground group), then a third party continues only the launcher
    (plain exec: the child, the job's only process)."""
    pf = ctx.pf()
    r = {}
    sh.cmd(ctx.line(pf, "sleep", 4, 0))
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    time.sleep(0.3)
    sh.send("\x1a")
    r["ctrlz_prompt"], r["ctrlz_notice"] = wait_stop_prompt(sh)
    r["after_ctrlz"] = states(C=c, L=j if ctx.bin else None)
    os.kill(j, SIG["CONT"])
    time.sleep(1.0)
    r["after_cont_1s"] = states(C=c, L=j if ctx.bin else None)
    r["jobs_1s"], _ = sh.jobs(j)
    time.sleep(4.0)
    r["after_cont_5s"] = states(C=c, L=j if ctx.bin else None)
    r["child_completed_by_5s"] = os.path.exists(pf + ".done")
    r["jobs_5s"], r["jobs_text"] = sh.jobs(j)
    r["recovery"] = recover(sh, j)
    r["cmp"] = {"child_1s": r["after_cont_1s"].get("C"), "jobs_1s": r["jobs_1s"],
                "completed_by_5s": r["child_completed_by_5s"], "jobs_5s": r["jobs_5s"],
                "recovery": r["recovery"]["how"]}
    return r


def whoami(sh, ctx, nested):
    """Which shell reads the terminal now: 'nested', 'outer' or None (no answer in 3 s)."""
    sh.n += 1
    sh.cmd('echo "@W""HO%d-$$@"' % sh.n)
    m = sh.expect(r"@WHO%d-(\d+)@" % sh.n, 3)
    if not m:
        return None
    return "nested" if int(m.group(1)) == nested else "outer"


def sc_p9(ctx, sh, tr):
    """P9: nested interactive bash: `suspend`, outer `bg`, then outer `fg`, then `exit 3`.
    Records which shell reads the terminal after each step."""
    pf = ctx.pf()
    r = {}
    sh.cmd(ctx.pre() + "/bin/bash --norc --noprofile -i")
    time.sleep(1.0)
    sh.cmd('echo $$ > %s; echo "@N""1@"' % pf)
    r["nested_up"] = sh.expect("@N1@", 5) is not None
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no nested pid"}
    time.sleep(0.3)
    sh.cmd("suspend")
    r["suspend_prompt"], r["suspend_notice"] = wait_stop_prompt(sh, 3)
    r["after_suspend"] = states(N=c, L=j if ctx.bin else None)
    sh.cmd("bg")
    time.sleep(1.0)
    sh.read(0.3)
    r["after_bg"] = states(N=c, L=j if ctx.bin else None)
    r["who_after_bg"] = whoami(sh, ctx, c) if not sh.eof else None
    r["jobs_after_bg"] = None
    r["who_after_fg"] = None
    r["rc_after_exit"] = None
    if r["who_after_bg"] == "outer":
        r["jobs_after_bg"], r["jobs_text"] = sh.jobs(j)
        sh.cmd("fg")
        time.sleep(1.0)
        r["who_after_fg"] = whoami(sh, ctx, c) if not sh.eof else None
        r["after_fg"] = states(N=c, L=j if ctx.bin else None)
    if r["who_after_bg"] == "nested" or r["who_after_fg"] == "nested":
        sh.cmd("exit 3")
        sh.expect(re.escape(PROMPT), 3)
        time.sleep(0.3)
        r["rc_after_exit"] = sh.rc() if not sh.eof else "outer-gone"
    sh.read(0.3)
    r["outer_shell_alive_at_end"] = sh.alive() and not sh.eof
    r["cmp"] = {"suspend_notice": bool(r["suspend_notice"]), "who_after_bg": r["who_after_bg"],
                "jobs_after_bg": r["jobs_after_bg"], "who_after_fg": r["who_after_fg"],
                "rc_after_exit": r["rc_after_exit"], "outer_shell_alive_at_end": r["outer_shell_alive_at_end"]}
    return r


def sc_p9e(ctx, sh, tr, with_bg):
    """P9e: a minimal job-control child (own group, holds the terminal) `suspend`s itself with
    SIGSTOP; outer `bg` (P9e-bg only), then outer `fg`: does the child get the terminal back?"""
    pf = ctx.pf()
    r = {}
    sh.cmd(ctx.line(pf, "jcsh"))
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    sh.read(0.3)
    sh.mark = len(sh.buf)
    sh.send("xq-ping 1\n")
    r["child_up"] = sh.expect("PONG-1", 3) is not None
    sh.mark = len(sh.buf)
    sh.send("suspend\n")
    r["suspend_prompt"], r["suspend_notice"] = wait_stop_prompt(sh, 3)
    r["rc_at_prompt"] = sh.rc() if r["suspend_prompt"] else "no-prompt"
    r["after_suspend"] = states(C=c, L=j if ctx.bin else None)
    if with_bg:
        sh.cmd("bg")
        time.sleep(1.0)
        r["after_bg"] = states(C=c, L=j if ctx.bin else None)
        r["jobs_after_bg"], r["jobs_text"] = sh.jobs(j)
    sh.cmd("fg")
    time.sleep(0.8)
    r["after_fg"] = states(C=c, L=j if ctx.bin else None)
    sh.read(0.05)
    sh.mark = len(sh.buf)
    sh.send("xq-ping 2\n")
    r["child_answers_after_fg"] = sh.expect("PONG-2", 3) is not None
    if r["child_answers_after_fg"]:
        sh.mark = len(sh.buf)
        sh.send("exit 3\n")
        ok = sh.expect(re.escape(PROMPT), 3) is not None
        r["rc_after_exit"] = sh.rc() if ok else "no-prompt"
        r["recovery"] = {"how": "none-needed"}
    else:
        r["rc_after_exit"] = None
        r["recovery"] = recover(sh, j, feed="exit 3\n", attempts=("ctrlz+fg", "ctrlc"))
    r["cmp"] = {"suspend_notice": bool(r["suspend_notice"]), "rc_at_prompt": r["rc_at_prompt"],
                "jobs_after_bg": r.get("jobs_after_bg"), "child_after_bg": r.get("after_bg", {}).get("C"),
                "child_answers_after_fg": r["child_answers_after_fg"], "rc_after_exit": r["rc_after_exit"],
                "recovery": r["recovery"]["how"]}
    return r


def sc_p10(ctx, sh, tr):
    """P10: ^Z, wait 1.5 s, `bg` of a terminal reader (immediate SIGTTIN), x3; then fg, input, ^D."""
    pf = ctx.pf()
    r = {"cycles": []}
    sh.cmd(ctx.line(pf, "cat"))
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    for i in range(3):
        time.sleep(0.3)
        sh.read(0.05)
        sh.mark = len(sh.buf)
        sh.send("\x1a")
        cy = {}
        cy["ctrlz_prompt"], cy["notice"] = wait_stop_prompt(sh)
        time.sleep(1.5)
        sh.cmd("bg")
        time.sleep(1.0)
        cy["after_bg"] = states(C=c, L=j if ctx.bin else None)
        cy["jobs"], _ = sh.jobs(j)
        cy["consistent"] = consistent(cy["after_bg"], ctx)
        sh.cmd("fg")
        time.sleep(0.6)
        cy["after_fg"] = states(C=c, L=j if ctx.bin else None)
        r["cycles"].append(cy)
    sh.read(0.05)
    sh.mark = len(sh.buf)
    sh.send("hello-cat\n")
    r["echoed"] = sh.expect(r"hello-cat\r?\n\r?hello-cat", 3) is not None
    sh.send("\x04")
    r["prompt_after_eof"] = sh.expect(re.escape(PROMPT), 4) is not None
    r["rc"] = sh.rc() if r["prompt_after_eof"] else "no-prompt"
    if not r["prompt_after_eof"]:
        r["recovery"] = recover(sh, j, attempts=("ctrlz+fg", "ctrlc"))
    r["cmp"] = {"jobs": [cy["jobs"] for cy in r["cycles"]],
                "child_after_bg": [cy["after_bg"].get("C") for cy in r["cycles"]],
                "consistent": all(cy["consistent"] for cy in r["cycles"]),
                "child_after_fg": [cy["after_fg"].get("C") for cy in r["cycles"]],
                "echoed": r["echoed"], "rc": r["rc"]}
    return r


def sc_p11(ctx, sh, tr):
    """P11: arm (third-party SIGTSTP of the child, SIGCONT to the launcher / plain: the child, fg),
    then three ^Z / 1.2 s / fg cycles; the job must run after each fg and finish with 0."""
    pf = ctx.pf()
    r = {"cycles": []}
    t0 = time.monotonic()
    sh.cmd(ctx.line(pf, "sleep", 10, 0))
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    time.sleep(0.3)
    os.kill(c, SIG["TSTP"])
    r["arm_prompt"], r["arm_notice"] = wait_stop_prompt(sh)
    os.kill(j, SIG["CONT"])
    time.sleep(0.5)
    sh.cmd("fg")
    time.sleep(0.5)
    r["after_arm_fg"] = states(C=c, L=j if ctx.bin else None)
    for i in range(3):
        sh.read(0.05)
        sh.mark = len(sh.buf)
        sh.send("\x1a")
        cy = {}
        cy["ctrlz_prompt"], cy["notice"] = wait_stop_prompt(sh)
        time.sleep(1.2)
        sh.cmd("fg")
        time.sleep(0.4)
        cy["after_fg"] = states(C=c, L=j if ctx.bin else None)
        time.sleep(0.4)
        cy["after_fg_0_8s"] = states(C=c, L=j if ctx.bin else None)
        r["cycles"].append(cy)
    m = sh.expect(re.escape(PROMPT), 10)
    r["finished"] = m is not None
    r["rc"] = sh.rc() if m else "no-prompt"
    r["elapsed_s"] = round(time.monotonic() - t0, 1)
    if not m:
        r["recovery"] = recover(sh, j, attempts=("ctrlz+fg", "ctrlc"))
    r["cmp"] = {"arm_notice": bool(r["arm_notice"]), "child_after_arm_fg": r["after_arm_fg"].get("C"),
                "cycle_notices": [bool(cy["notice"]) for cy in r["cycles"]],
                "running_after_each_fg": all(cy["after_fg"].get("C") != "T" and cy["after_fg"].get("L") != "T"
                                             and cy["after_fg_0_8s"].get("C") != "T"
                                             and cy["after_fg_0_8s"].get("L") != "T" for cy in r["cycles"]),
                "finished": r["finished"], "rc": r["rc"]}
    return r


def sc_p12(ctx, sh, tr):
    """P12 (S3): the child stops itself with SIGTSTP; a third party continues the launcher (plain:
    the child). Sample process states for 1 s; then jobs, fg, typed line, $?."""
    pf = ctx.pf()
    r = {}
    sh.cmd(ctx.line(pf, "selftstp", 6))
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    r["prompt"], r["notice"] = wait_stop_prompt(sh)
    r["rc_at_prompt"] = sh.rc() if r["prompt"] else "no-prompt"
    time.sleep(0.3)
    r["before_cont"] = states(C=c, L=j if ctx.bin else None)
    os.kill(j, SIG["CONT"])
    t0 = time.monotonic()
    samples = []
    last = None
    while time.monotonic() - t0 < 1.0:
        cur = (fast_state(c), fast_state(j) if ctx.bin else None)
        if cur != last:
            samples.append((round((time.monotonic() - t0) * 1000, 1),) + cur)
            last = cur
    r["transitions_ms"] = samples
    # window: launcher not stopped while the child is still stopped, after the SIGCONT
    win = 0.0
    if ctx.bin:
        for i, (t, cs, ls) in enumerate(samples):
            if ls != "T" and cs == "T":
                tn = samples[i + 1][0] if i + 1 < len(samples) else 1000.0
                win += tn - t
    r["launcher_running_child_stopped_ms"] = round(win, 1)
    r["after_1s"] = states(C=c, L=j if ctx.bin else None)
    r["jobs"], r["jobs_text"] = sh.jobs(j)
    r["recovery"] = recover(sh, j, feed="hi-s3\n", expect_out="GOT=hi-s3")
    r["cmp"] = {"rc_at_prompt": r["rc_at_prompt"], "child_after_1s": r["after_1s"].get("C"),
                "job_stopped_consistent": consistent(r["after_1s"], ctx), "jobs": r["jobs"],
                "recovery": r["recovery"]["how"], "rc": r["recovery"]["rc"],
                "out_ok": r["recovery"].get("out_ok")}
    return r


def sc_p13(ctx, sig):
    """P13: S1 in an orphaned process group (the launcher's parent has exited)."""
    tr = Tracked()
    pf = ctx.pf()
    rd, wr = os.pipe()
    ip = os.fork()
    if ip == 0:
        try:
            os.close(rd)
            os.setsid()
            argv = ctx.argv(pf, "sleep", 1.5, 7)
            lp = os.fork()
            if lp == 0:
                default_signals()
                nul = os.open("/dev/null", os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(nul, fd)
                os.chdir(ctx.tmp)
                os.execve(argv[0], argv, {"PATH": "/usr/bin:/bin", "HOME": ctx.tmp, "LANG": "C"})
            os.write(wr, b"L%d\n" % lp)
        finally:
            os._exit(0)
    os.close(wr)
    os.waitpid(ip, 0)
    d = os.read(rd, 64)
    os.close(rd)
    mm = re.search(rb"L(\d+)", d)
    lp = int(mm.group(1)) if mm else None
    tr.add("launcher", lp)
    r = {}
    c = wait_pf(pf, 5)
    if c is None:
        tr.kill_all()
        return {"error": "no child pid"}, tr
    tr.add("child", c)
    time.sleep(0.3)
    os.kill(c, SIG[sig])
    time.sleep(0.5)
    r["after_stop"] = states(C=c, L=lp if ctx.bin else None)
    os.kill(c, SIG["CONT"])
    end = time.time() + 6
    while time.time() < end:
        reap_orphans()
        if fast_state(c) in ("gone",) and (fast_state(lp) in ("gone",)):
            break
        time.sleep(0.05)
    r["child_completed"] = os.path.exists(pf + ".done")
    r["end_states"] = states(C=c, L=lp)
    r["all_gone"] = all(v == "gone" for v in r["end_states"].values())
    if lp in REAPED:
        r["launcher_rc"] = decode(REAPED[lp])
    r["cmp"] = {"child_completed": r["child_completed"], "all_gone": r["all_gone"],
                "launcher_rc": r.get("launcher_rc")}
    return r, tr


def sc_p14(ctx, sh, tr):
    """P14: the child joins another job's (stopped) process group and stops itself; a third party
    continues the launcher (plain: the child). Is the other job left stopped, as under plain exec?"""
    pf = ctx.pf()
    r = {}
    sh.n += 1
    sh.cmd('/bin/sleep 30 & echo "@B""%d=$!@"' % sh.n)
    m = sh.expect(r"@B%d=(\d+)@" % sh.n, 5)
    if not m:
        return {"error": "no B pid"}
    b = int(m.group(1))
    tr.add("other_job", b)
    sh.sync()
    os.kill(b, SIG["STOP"])
    time.sleep(0.3)
    sh.sync()
    sh.cmd(ctx.line(pf, "joingrp", b, 1.5, 0))
    c, j = learn(ctx, sh, tr, pf)
    if c is None:
        return {"error": "no child pid"}
    r["prompt"], r["notice"] = wait_stop_prompt(sh, 3)
    r["after_selfstop"] = states(C=c, L=j if ctx.bin else None, B=b)
    os.kill(j, SIG["CONT"])
    time.sleep(1.0)
    r["after_cont"] = states(C=c, L=j if ctx.bin else None, B=b)
    r["other_job_left_stopped"] = r["after_cont"].get("B") == "T"
    try:
        os.kill(b, SIG["KILL"]) if tr.same(b, tr.ids["other_job"][1]) else None
    except OSError:
        pass
    time.sleep(0.2)
    r["recovery"] = recover(sh, j, attempts=("fg", "ctrlz+fg", "ctrlc")) if r["prompt"] else \
        recover(sh, j, attempts=("ctrlz+fg", "ctrlc"))
    r["cmp"] = {"notice": bool(r["notice"]), "other_job_left_stopped": r["other_job_left_stopped"]}
    return r


SCENARIOS = {
    "P0-STOP": ("noshell", lambda ctx: sc_p0(ctx, "STOP")),
    "P0-TSTP": ("noshell", lambda ctx: sc_p0(ctx, "TSTP")),
    "P1-STOP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "STOP", True)),
    "P1-TSTP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "TSTP", True)),
    "P2-STOP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "STOP", False)),
    "P2-TSTP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "TSTP", False)),
    "P1k-TSTP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "TSTP", True, kcont=True)),
    "P2k-TSTP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "TSTP", False, kcont=True)),
    "P2n-TTIN": ("shell", sc_p2n),
    "P3-STOP": ("shell", lambda ctx, sh, tr: sc_p3(ctx, sh, tr, "STOP")),
    "P3-TSTP": ("shell", lambda ctx, sh, tr: sc_p3(ctx, sh, tr, "TSTP")),
    "P4-STOP": ("shell", lambda ctx, sh, tr: sc_fgstop(ctx, sh, tr, "STOP", True)),
    "P4-TSTP": ("shell", lambda ctx, sh, tr: sc_fgstop(ctx, sh, tr, "TSTP", True)),
    "P4t-STOP": ("shell", lambda ctx, sh, tr: sc_fgstop(ctx, sh, tr, "STOP", False)),
    "P4t-TSTP": ("shell", lambda ctx, sh, tr: sc_fgstop(ctx, sh, tr, "TSTP", False)),
    "P5-STOP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "STOP", False, via_ctrlz=True)),
    "P5-TSTP": ("shell", lambda ctx, sh, tr: sc_bg(ctx, sh, tr, "TSTP", False, via_ctrlz=True)),
    "P6-STOP": ("noshell", lambda ctx: sc_p6(ctx, "STOP")),
    "P6-TSTP": ("noshell", lambda ctx: sc_p6(ctx, "TSTP")),
    "P7-TTOU": ("shell", lambda ctx, sh, tr: sc_fgstop(ctx, sh, tr, "TTOU", False)),
    "P7-TTIN": ("shell", lambda ctx, sh, tr: sc_fgstop(ctx, sh, tr, "TTIN", False)),
    "P7n-TTOU": ("shell", sc_p7n),
    "P8": ("shell", sc_p8),
    "P9": ("shell", sc_p9),
    "P9e0": ("shell", lambda ctx, sh, tr: sc_p9e(ctx, sh, tr, False)),
    "P9e-bg": ("shell", lambda ctx, sh, tr: sc_p9e(ctx, sh, tr, True)),
    "P10": ("shell", sc_p10),
    "P11": ("shell", sc_p11),
    "P12-S3": ("shell", sc_p12),
    "P13-STOP": ("noshell", lambda ctx: sc_p13(ctx, "STOP")),
    "P13-TSTP": ("noshell", lambda ctx: sc_p13(ctx, "TSTP")),
    "P14": ("shell", sc_p14),
}


def run_one(name, ctx):
    kind, fn = SCENARIOS[name]
    t0 = time.monotonic()
    rec = {"scenario": name, "via": ctx.label, "shell": ctx.shell if kind == "shell" else None}
    tr = None
    sh = None
    try:
        if kind == "noshell":
            res, tr = fn(ctx)
        else:
            tr = Tracked()
            sh = Shell(ctx.shell, ctx.tmp)
            tr.add("shell", sh.pid)
            res = fn(ctx, sh, tr)
        rec.update(json.loads(ctx.redact(json.dumps(res))))
    except Exception as e:  # recorded, never hidden
        rec["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        killed = tr.kill_all() if tr else []
        if sh:
            rec["transcript"] = re.sub(r" {8,}", "    ", ctx.redact(clean(sh.buf)))[-6000:]
            sh.close()
        left = tr.leftovers() if tr else []
        rec["cleanup"] = {"killed_by_probe": killed, "left_after_cleanup": left}
        rec["duration_s"] = round(time.monotonic() - t0, 1)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--shell", default="bash")
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--only", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    binpath = None if a.bin == "plain" else os.path.abspath(a.bin)
    names = [n for n in SCENARIOS if not a.only or n in a.only.split(",")]
    out = {"label": a.label, "platform": "linux-arm64" if LINUX else "darwin-arm64", "shell": a.shell,
           "pid1": os.getpid() == 1, "runs": []}
    for rep in range(1, a.reps + 1):
        for n in names:
            ctx = Ctx(binpath, a.shell, a.label)
            rec = run_one(n, ctx)
            rec["rep"] = rep
            ctx.cleanup()
            out["runs"].append(rec)
            print("%s rep%d %s %s %.1fs%s" % (a.label, rep, n, json.dumps(rec.get("cmp")), rec["duration_s"],
                                              " ERROR " + rec["error"] if "error" in rec else ""), flush=True)
            with open(a.out, "w") as f:
                json.dump(out, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
