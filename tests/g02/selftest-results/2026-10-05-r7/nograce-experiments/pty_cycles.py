#!/usr/bin/env python3
"""Ctrl-Z / fg cycles of `heimdall-proto run -- <child>` as a job of `bash -i` in a pty; counts re-stops after fg.

  pty_cycles.py LAUNCHER LAYOUT N [PEERS]      LAYOUT: simple | grandkids
Environment: REF_MUTATE (passed to the launcher), CREAD=1 (the child blocks in a terminal read instead of sleeping).
`grandkids`: the child is a /bin/sh wrapper that starts PEERS waiting processes in the job's process group, then
execs the child.  Only processes started here are signalled, by recorded PID after a session check."""
import os, pty, select, signal, sys, tempfile, time

launcher, layout, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
k = sys.argv[4] if len(sys.argv) > 4 else "100"
d = tempfile.mkdtemp(prefix="hm-nograce-")
home = tempfile.mkdtemp(prefix="hm-nograce-home-")
loop = "while True: os.read(0, 100)\n" if os.environ.get("CREAD") else "while True: time.sleep(0.02)\n"
open(d + "/c.py", "w").write("import os, time\nopen(%r, 'w').write(str(os.getpid()))\n%s" % (d + "/child.ready", loop))
open(d + "/peers.py", "w").write('''import os, signal, sys, time
n = int(sys.argv[1]); r, w = os.pipe()
for _ in range(n):
    if os.fork() == 0:
        try:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            os.close(w)
            while os.read(r, 1):
                pass
        finally:
            os._exit(0)
open(sys.argv[2], "w").write("1")
pp = os.getppid()
while os.getppid() == pp:
    time.sleep(0.2)
''')
py = sys.executable
cmds = {
    "simple": '"$P" run -- "$Y" "$D/c.py"',
    "grandkids": ('"$P" run -- /bin/sh -c \'"$Y" "$D/peers.py" %s "$D/peers.ready" </dev/null & '
                  'while [ ! -e "$D/peers.ready" ]; do sleep 0.05; done; exec "$Y" "$D/c.py"\'' % k),
}
env = {"PATH": os.path.dirname(py) + ":/usr/bin:/bin", "P": launcher, "Y": py, "D": d, "PS1": "PS1$ ", "HOME": home,
       "TERM": "xterm", "BASH_SILENCE_DEPRECATION_WARNING": "1"}
if os.environ.get("REF_MUTATE"):
    env["REF_MUTATE"] = os.environ["REF_MUTATE"]
pid, fd = pty.fork()
if pid == 0:
    os.execve("/bin/bash", ["/bin/bash", "--norc", "--noprofile", "-i"], env)
buf = bytearray()


def pump(t, until=None):
    end = time.monotonic() + t
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try:
                buf.extend(os.read(fd, 65536))
            except OSError:
                return False
        if until and until():
            return True
    return False


pump(1.0)
os.write(fd, (cmds[layout] + "\r").encode())
end = time.monotonic() + 15
while not os.path.exists(d + "/child.ready") and time.monotonic() < end:
    pump(0.05)
pump(0.5)
restops = 0
done = 0
for i in range(n):
    m = len(buf)
    os.write(fd, b"\x1a")
    if not pump(5, lambda: b"Stopped" in buf[m:] and b"PS1$" in buf[m:][buf[m:].find(b"Stopped"):]):
        print("no stop at cycle %d" % (i + 1))
        break
    pump(0.1)
    m = len(buf)
    os.write(fd, b"fg\r")
    pump(0.6)
    done += 1
    if b"Stopped" in buf[m:]:
        restops += 1
        os.write(fd, b"fg\r")
        pump(0.6)
print("launcher=%s REF_MUTATE=%s layout=%s peers=%s CREAD=%s cycles=%d restops_after_fg=%d" % (
    os.path.basename(launcher), os.environ.get("REF_MUTATE", ""), layout, k if layout == "grandkids" else "-",
    bool(os.environ.get("CREAD")), done, restops), flush=True)
os.write(fd, b"\x03")
pump(0.3)
# release: every process of this pty session (identity: same session id as the bash started here)
try:
    import subprocess
    out = subprocess.run(["/bin/ps", "-A", "-o", "pid=,sess="] if sys.platform == "darwin" else
                         ["ps", "-e", "-o", "pid=,sess="], capture_output=True, text=True).stdout.split()
except OSError:
    out = []
for p, sid in zip(out[0::2], out[1::2]):
    try:
        if int(p) != pid and os.getsid(int(p)) == pid:
            os.kill(int(p), signal.SIGKILL)
    except (OSError, ValueError):
        pass
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)
