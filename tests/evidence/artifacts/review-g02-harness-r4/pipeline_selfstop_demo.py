#!/usr/bin/env python3
"""Reviewer demo (M00-T05-review-harness-r4): a child that stops itself (kill(getpid(), SIGTSTP)) while it is the
first member of a pipeline `<launcher> run -- child | peer` under `bash -i` in a pty.  Records the peer's scheduler
state ~1.5 s after the self-stop and whether bash printed 'Stopped'.  Compares: direct exec (no launcher), the
unmutated reference, and the given mutant(s).  Only processes started here are signalled (by recorded PID)."""
import os, pty, select, signal, subprocess, sys, tempfile, time

CHILD = r'''
import os, signal, sys, time
d = sys.argv[1]
open(os.path.join(d, "child.pid"), "w").write(str(os.getpid()))
open(os.path.join(d, "child.ppid"), "w").write(str(os.getppid()))
time.sleep(0.5)
sys.stdout.write("beat\n"); sys.stdout.flush()
os.kill(os.getpid(), signal.SIGTSTP)
open(os.path.join(d, "child.resumed"), "w").write("1")
sys.exit(0)
'''
PEER = r'''
import os, sys
d = sys.argv[1]
open(os.path.join(d, "peer.pid"), "w").write(str(os.getpid()))
for line in sys.stdin:
    pass
'''

def state(pid):
    if os.path.exists("/proc/%d/stat" % pid):
        return open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()[0]
    r = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip()[:1] or None

def sid_of(p):
    try:
        return os.getsid(p)
    except OSError:
        return None

def run(label, launcher):
    d = tempfile.mkdtemp(prefix="rv4pipe-")
    open(os.path.join(d, "c.py"), "w").write(CHILD)
    open(os.path.join(d, "p.py"), "w").write(PEER)
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "PS1": "PS1$ ", "HOME": d, "TERM": "xterm",
           "PYTHONDONTWRITEBYTECODE": "1", "BASH_SILENCE_DEPRECATION_WARNING": "1"}
    pid, fd = pty.fork()
    if pid == 0:
        os.execve("/bin/bash", ["/bin/bash", "--norc", "--noprofile", "-i"], env)
    buf = b""
    def pump(t):
        nonlocal buf
        end = time.monotonic() + t
        while time.monotonic() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    buf += os.read(fd, 65536)
                except OSError:
                    return
    pump(1.0)
    py = sys.executable
    cmd = ('%s %s/c.py %s | %s %s/p.py %s' % (py, d, d, py, d, d))
    if launcher:
        cmd = '%s run -- %s' % (launcher, cmd.split(" | ")[0]) + " | " + cmd.split(" | ")[1]
    m = len(buf)
    os.write(fd, (cmd + "\r").encode())
    pump(4.0)
    out = buf[m:]
    def rd(n):
        try:
            return int(open(os.path.join(d, n)).read())
        except (OSError, ValueError):
            return None
    cpid, ppid = rd("child.pid"), rd("peer.pid")
    lpid = rd("child.ppid") if launcher else None
    res = {"case": label, "bash_printed_Stopped": b"Stopped" in out, "prompt_after": out.rstrip().endswith(b"PS1$"),
           "child_state": state(cpid) if cpid else None, "peer_state": state(ppid) if ppid else None,
           "launcher_state": state(lpid) if lpid else None}
    print(res, flush=True)
    for p in (cpid, ppid, lpid):    # only processes this demo started, by recorded PID
        if p and sid_of(p) == pid:
            for s in (signal.SIGCONT, signal.SIGKILL):
                try:
                    os.kill(p, s)
                except ProcessLookupError:
                    pass
    pump(0.5)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    # the launcher (if any) is a child of the killed bash and in its session; it dies with SIGHUP/its child's death

if __name__ == "__main__":
    run("direct exec (control)", None)
    for b in sys.argv[1:]:
        run(b, b)
