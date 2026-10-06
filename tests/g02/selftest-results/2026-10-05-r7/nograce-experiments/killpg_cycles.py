#!/usr/bin/env python3
"""The same `grandkids` layout without a shell: this script starts `LAUNCHER run -- /bin/sh -c ...` in a new process
group, stops it with killpg(SIGTSTP) and continues it with killpg(SIGCONT) N times, and counts the cycles after
which the launcher stopped itself again.  REF_MUTATE is passed to the launcher.

  killpg_cycles.py LAUNCHER N [PEERS]"""
import os, signal, subprocess, sys, tempfile, time

launcher, n = sys.argv[1], int(sys.argv[2])
k = int(sys.argv[3]) if len(sys.argv) > 3 else 100
d = tempfile.mkdtemp(prefix="hm-nograce-kp-")
open(d + "/peers.py", "w").write('''import os, signal, sys, time
n = int(sys.argv[1]); r, w = os.pipe()
for _ in range(n):
    if os.fork() == 0:
        try:
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
script = ('"$0" "$1/peers.py" %d "$1/peers.ready" </dev/null & while [ ! -e "$1/peers.ready" ]; do sleep 0.05; '
          'done; exec /bin/sleep 600' % k)
env = {"PATH": "/usr/bin:/bin"}
if os.environ.get("REF_MUTATE"):
    env["REF_MUTATE"] = os.environ["REF_MUTATE"]
w = subprocess.Popen([sys.executable, launcher, "run", "--", "/bin/sh", "-c", script, sys.executable, d],
                     process_group=0, stdin=subprocess.DEVNULL, env=env)
g = w.pid
end = time.monotonic() + 15
while not os.path.exists(d + "/peers.ready") and time.monotonic() < end:
    time.sleep(0.01)
time.sleep(0.3)


def drain():
    stopped = False
    while True:
        r, st = os.waitpid(g, os.WUNTRACED | os.WCONTINUED | os.WNOHANG)
        if not r:
            return stopped
        stopped = stopped or os.WIFSTOPPED(st)


restops = 0
for i in range(n):
    os.killpg(g, signal.SIGTSTP)
    os.waitpid(g, os.WUNTRACED)
    time.sleep(0.05)
    os.killpg(g, signal.SIGCONT)
    time.sleep(0.4)
    if drain():
        restops += 1
        os.killpg(g, signal.SIGCONT)
        time.sleep(0.2)
        drain()
print("launcher=%s REF_MUTATE=%s killpg cycles=%d restops=%d peers=%d" % (
    os.path.basename(launcher), os.environ.get("REF_MUTATE", ""), n, restops, k), flush=True)
os.killpg(g, signal.SIGKILL)          # the process group this script created
w.wait()
time.sleep(0.5)
try:
    os.killpg(g, signal.SIGKILL)
except ProcessLookupError:
    pass
