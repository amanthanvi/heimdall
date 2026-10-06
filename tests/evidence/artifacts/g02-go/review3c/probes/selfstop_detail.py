#!/usr/bin/env python3
"""Review-3c targeted probe: one child self-stop under an interactive shell, full detail.

usage: selfstop_detail.py HEIMDALL_BIN SHELL SIG [LAYOUT=exclusive|control] [TRIGGER=read|usr2|ext]

Starts SHELL (bash|zsh) interactively in a fresh pty, runs child3c.py in read
mode under `heimdall-proto run --meta-file M` (or directly for control), makes
the child stop itself with SIG (input line "~z", or SIGUSR2 from this probe),
then records for 3 s: the tty text, the shell's $? after the prompt returns,
the child's log (START/SIG/SELFSTOP/CONT/READERR/EOF/EXIT lines), process
states, and the meta file. Prints one JSON object. Raw observation only.
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

HP, KIND, SIG = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3]
LAYOUT = sys.argv[4] if len(sys.argv) > 4 else "exclusive"
TRIGGER = sys.argv[5] if len(sys.argv) > 5 else "read"
CHILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "child3c.py")
W = tempfile.mkdtemp(prefix="hp-rv3c-d-")
LOG, META = os.path.join(W, "c.log"), os.path.join(W, "meta.json")


def pstate(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            b = f.read()
        return b[b.rindex(b")") + 2:].split()[0].decode()
    except FileNotFoundError:
        if os.path.isdir("/proc/self"):
            return "gone"
    except Exception:
        pass
    r = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip() or "gone"


argv = {"bash": ["bash", "--norc", "--noprofile", "-i"], "zsh": ["zsh", "-f", "-i"]}[KIND]
env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": W, "TERM": "xterm", "LANG": "C",
       "PS1": "PRMPT$ "}
pid, fd = pty.fork()
if pid == 0:
    os.chdir(W)
    os.execvpe(argv[0], argv, env)
buf = ""


def pump(t):
    global buf
    end = time.monotonic() + t
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], max(0, end - time.monotonic()))
        if not r:
            break
        try:
            d = os.read(fd, 65536)
        except OSError:
            break
        if not d:
            break
        buf += d.decode("utf-8", "replace")


def expect(pat, t):
    end = time.monotonic() + t
    while time.monotonic() < end:
        m = re.search(pat, buf)
        if m:
            return m
        pump(0.05)
    return None


pump(1.0)
os.write(fd, b"PS1='PRMPT$ '\n")
pump(0.5)
mark = len(buf)
py = sys.executable
if LAYOUT == "control":
    cmd = "%s %s %s read %s" % (py, CHILD, LOG, SIG)
else:
    cmd = "%s run --meta-file %s -- %s %s %s read %s" % (HP, META, py, CHILD, LOG, SIG)
os.write(fd, (cmd + "\n").encode())
t0 = time.monotonic()
start = None
while time.monotonic() - t0 < 8 and not start:
    pump(0.05)
    try:
        start = re.search(r"^START pid=(\d+) ppid=(\d+)", open(LOG).read(), re.M)
    except FileNotFoundError:
        pass
child, parent = int(start.group(1)), int(start.group(2))
pump(0.5)
res = {"shell": KIND, "sig": SIG, "layout": LAYOUT, "trigger": TRIGGER, "uname": os.uname().sysname}
tt = time.monotonic()
if TRIGGER == "usr2":
    os.kill(child, signal.SIGUSR2)
elif TRIGGER == "ext":
    os.kill(child, getattr(signal, SIG))  # external stop signal to the exact child pid (not a self-stop)
else:
    os.write(fd, b"~z\n")
states = []
for i in range(12):
    pump(0.25)
    states.append({"t": round(time.monotonic() - tt, 2), "child": pstate(child),
                   "hp": pstate(parent) if LAYOUT != "control" else None})
res["states"] = states
res["stop_reported"] = bool(re.search(r"Stopped|suspended", buf[mark:]))
os.write(fd, b"echo RC=$?\n")
m = expect(r"RC=(\d+)", 3)
res["rc_line"] = m.group(0) if m else None
res["tty"] = buf[mark:][-700:]
res["child_log"] = [l.rstrip("\n") for l in open(LOG)] if os.path.exists(LOG) else None
res["meta"] = json.load(open(META)) if os.path.exists(META) else None
# cleanup: resume and end the exact child if still there, then the shell
if pstate(child) != "gone":
    os.kill(child, signal.SIGCONT)
    os.kill(child, signal.SIGKILL)
os.write(fd, b"fg\n")
pump(0.3)
os.write(fd, b"quit\nexit\nexit\n")
pump(0.5)
os.close(fd)
for _ in range(20):
    if os.waitpid(pid, os.WNOHANG)[0]:
        break
    time.sleep(0.05)
else:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
res["child_log"] = [re.sub(r"pid=\d+ ppid=\d+ pgid=\d+ ", "", l) for l in (res["child_log"] or [])]
print(json.dumps(res))
subprocess.run(["rm", "-rf", W])
