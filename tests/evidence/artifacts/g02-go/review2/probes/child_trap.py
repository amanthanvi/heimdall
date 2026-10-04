import os, signal, sys, time
d = sys.argv[1]
linger = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
got = []
def h(s, f):
    got.append(signal.Signals(s).name)
    with open(os.path.join(d, "signals"), "a") as fh:
        fh.write(signal.Signals(s).name + "\n")
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
    signal.signal(s, h)
with open(os.path.join(d, "ready"), "w") as fh:
    fh.write("%d %d %d\n" % (os.getpid(), os.getppid(), os.getpgrp()))
end = time.time() + linger
while time.time() < end:
    time.sleep(0.01)
sys.exit(7)
