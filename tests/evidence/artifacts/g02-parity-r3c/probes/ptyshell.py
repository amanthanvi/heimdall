"""parity-r3c shared helpers: an interactive bash/zsh in a fresh pty (same set-up as
review3c probe.py's Shell class) plus process-state helpers that never print command lines."""
import os
import pty
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

LINUX = sys.platform.startswith("linux")
PROMPT = "@P@ "
STOPRE = r"(Stopped|suspended)"


def stat(pid):
    """dict(state, ppid, pgid, tpgid) or state 'gone'."""
    if pid is None:
        return {"state": None}
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            x = s[s.rindex(")") + 2:].split()
            return {"state": x[0], "ppid": int(x[1]), "pgid": int(x[2]), "tpgid": int(x[5])}
        except OSError:
            return {"state": "gone"}
    r = subprocess.run(["ps", "-o", "stat=,ppid=,pgid=,tpgid=", "-p", str(pid)], capture_output=True, text=True)
    f = r.stdout.split()
    if len(f) < 4:
        return {"state": "gone"}
    return {"state": f[0][:1], "ppid": int(f[1]), "pgid": int(f[2]), "tpgid": int(f[3])}


def state(pid):
    return stat(pid)["state"]


def cputime(pid):
    if LINUX:
        try:
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            x = s[s.rindex(")") + 2:].split()
            return int(x[11]) + int(x[12])
        except OSError:
            return None
    r = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip() or None


class Shell:
    def __init__(self, kind):
        self.kind = kind
        self.tmp = tempfile.mkdtemp(prefix="pr3c-")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp,
               "TERM": "xterm", "LANG": "C", "PS1": PROMPT}
        argv = ["bash", "--norc", "--noprofile", "-i"] if kind == "bash" else ["zsh", "-f", "-i"]
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(self.tmp)
            os.execvpe(argv[0], argv, env)
        self.pid, self.fd = pid, fd
        self.buf, self.log, self.mark = "", [], 0
        self.eof = False
        self.exit_status = None
        self.expect(re.escape(PROMPT), 10)
        if kind == "zsh":
            self.send("unsetopt zle; PS1='%s'; PROMPT_EOL_MARK=''\n" % PROMPT)
        else:
            self.send("bind 'set enable-bracketed-paste off' 2>/dev/null; PS1='%s'\n" % PROMPT)
        self.expect(re.escape(PROMPT), 10)

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
                self.eof = True  # every slave fd closed: the shell (and its jobs) left the terminal
                self.log.append("<<PTY EOF>>")
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
            if left <= 0 or self.eof:
                return None
            self.read(min(left, 0.1))

    def send(self, s):
        self.log.append("<<SEND %r>>" % s)
        try:
            os.write(self.fd, s.encode())
            return True
        except OSError as e:
            self.log.append("<<SEND FAILED %r>>" % e)
            return False

    def alive(self):
        if self.exit_status is not None:
            return False
        p, st = os.waitpid(self.pid, os.WNOHANG)
        if p == 0:
            return True
        self.exit_status = ("exit %d" % os.WEXITSTATUS(st)) if os.WIFEXITED(st) else ("signal %d" % os.WTERMSIG(st))
        return False

    def close(self):
        """SIGKILL the shell if still alive and reap it.  The master is drained while waiting:
        on darwin an exiting process with unread pty output can sit in state E (tty drain) and a
        blocking waitpid() then deadlocks (harness defect hit in run 2, fixed here)."""
        self.killed_by_probe = False
        if self.alive():
            self.killed_by_probe = True
            try:
                os.kill(self.pid, signal.SIGKILL)
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
        if self.exit_status is None:
            try:
                os.waitpid(self.pid, 0)
            except OSError:
                pass

    def transcript(self, extra=()):
        s = "".join(self.log).replace(self.tmp, "<tmp>")
        for a, b in extra:
            s = s.replace(a, b)
        return s


def kill_exact(pids):
    """SIGCONT+SIGKILL exactly these PIDs if still alive (not gone/zombie); returns how many."""
    n = 0
    for p in pids:
        if p and state(p) not in (None, "gone", "Z"):
            n += 1
            for s in (signal.SIGCONT, signal.SIGKILL):
                try:
                    os.kill(p, s)
                except OSError:
                    pass
    return n


def clean(s, n=400):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", s).replace("\r", "")[-n:]
