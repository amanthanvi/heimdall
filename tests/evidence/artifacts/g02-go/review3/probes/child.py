#!/usr/bin/env python3
"""Review-3 probe child. argv: LOG MODE(read|beat).

Logs START with its pid, ppid, pgid and the inherited dispositions of the five
forwarded signals, then counts every one of them it receives (unless inherited
ignored). MODE read: reads lines from stdin, prints 'GOT <line>', exits on
'quit' or EOF. MODE beat: appends a heartbeat counter to LOG.beat every 100 ms
without touching the terminal; exits on SIGUSR1.
"""
import os
import signal
import sys
import time

LOG, MODE = sys.argv[1], sys.argv[2]
NAMES = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"]


def w(s):
    with open(LOG, "a") as f:
        f.write(s + "\n")


disp = {}
for n in NAMES:
    disp[n] = "ign" if signal.getsignal(getattr(signal, n)) == signal.SIG_IGN else "dfl"
w("START pid=%d ppid=%d pgid=%d disp=%s" % (os.getpid(), os.getppid(), os.getpgrp(),
                                           ",".join("%s:%s" % (k, v) for k, v in disp.items())))


def h(num, _fr):
    w("SIG %s %.3f" % (signal.Signals(num).name, time.monotonic()))


for n in NAMES:
    if disp[n] != "ign":
        signal.signal(getattr(signal, n), h)

if MODE == "read":
    while True:
        try:
            line = sys.stdin.readline()
        except OSError as e:
            w("READERR %s" % e.errno)
            break
        if not line:
            w("EOF")
            break
        line = line.strip()
        w("GOT " + line)
        try:
            print("GOT", line, flush=True)
        except OSError:
            pass
        if line == "quit":
            break
else:
    stop = []
    signal.signal(signal.SIGUSR1, lambda *_: stop.append(1))
    i = 0
    while not stop:
        i += 1
        with open(LOG + ".beat", "w") as f:
            f.write(str(i))
        time.sleep(0.1)
w("EXIT")
