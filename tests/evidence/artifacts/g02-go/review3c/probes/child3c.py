#!/usr/bin/env python3
"""Review-3c probe child. argv: LOG MODE(read|beat) [SELFSIG]

Like review3/probes/child.py, plus:
- a heartbeat thread in both modes that rewrites LOG.beat every 50 ms with a
  counter (so a reviewer can see whether the child runs while its job is
  reported stopped);
- self-stop like OpenSSH's ~^Z: in read mode the input line "~z", and in both
  modes SIGUSR2, make the child send SELFSIG (default SIGTSTP) to its own pid
  with kill(getpid(), SELFSIG). Each self-stop is logged as SELFSTOP n and each
  resume as CONT n (SIGCONT handler).
"""
import os
import signal
import sys
import threading
import time

LOG, MODE = sys.argv[1], sys.argv[2]
SELFSIG = getattr(signal, sys.argv[3]) if len(sys.argv) > 3 else signal.SIGTSTP
NAMES = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"]
lock = threading.RLock()  # re-entrant: a handler can interrupt w() in the main thread (nested delivery)


def w(s):
    with lock:
        with open(LOG, "a") as f:
            f.write(s + "\n")


disp = {n: "ign" if signal.getsignal(getattr(signal, n)) == signal.SIG_IGN else "dfl" for n in NAMES}
for n in ("SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGPIPE"):
    h = signal.getsignal(getattr(signal, n))
    disp[n] = "ign" if h == signal.SIG_IGN else "dfl"
w("START pid=%d ppid=%d pgid=%d disp=%s" % (os.getpid(), os.getppid(), os.getpgrp(),
                                           ",".join("%s:%s" % kv for kv in disp.items())))


def h(num, _fr):
    w("SIG %s %.3f" % (signal.Signals(num).name, time.monotonic()))


for n in NAMES:
    if disp[n] != "ign":
        signal.signal(getattr(signal, n), h)

nstop = [0]
ncont = [0]


def selfstop():
    nstop[0] += 1
    w("SELFSTOP %d %s %.3f" % (nstop[0], signal.Signals(SELFSIG).name, time.monotonic()))
    os.kill(os.getpid(), SELFSIG)


def oncont(_n, _f):
    ncont[0] += 1
    w("CONT %d %.3f" % (ncont[0], time.monotonic()))


signal.signal(signal.SIGCONT, oncont)
signal.signal(signal.SIGUSR2, lambda *_: selfstop())

stop = []


def beat():
    # keep process-directed signals on the main thread, so a handled signal
    # interrupts the main thread's blocking read and its handler runs at once
    signal.pthread_sigmask(signal.SIG_BLOCK, {getattr(signal, n) for n in NAMES}
                           | {signal.SIGUSR1, signal.SIGUSR2, signal.SIGCONT})
    i = 0
    while not stop:
        i += 1
        with open(LOG + ".beat", "w") as f:
            f.write(str(i))
        time.sleep(0.05)


threading.Thread(target=beat, daemon=True).start()

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
        if line == "~z":
            selfstop()
        if line == "quit":
            break
else:
    signal.signal(signal.SIGUSR1, lambda *_: stop.append(1))
    while not stop:
        time.sleep(0.05)
stop.append(1)
w("EXIT")
