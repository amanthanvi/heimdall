import signal, time, os, sys
f = sys.argv[1]
def h(n, fr):
    with open(f, "a") as fh: fh.write("CONT fg=%s\n" % (os.tcgetpgrp(0) == os.getpgrp()))
signal.signal(signal.SIGCONT, h)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
end = time.time() + 4
while time.time() < end: time.sleep(0.05)
