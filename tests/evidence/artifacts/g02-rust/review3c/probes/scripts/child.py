#!/usr/bin/env python3
"""review3c probe child: an ssh-like program that stops itself on request.

argv[1] = pid file. Writes its own PID there, then loops: prints READY-<n> to /dev/tty,
reads one line from stdin (the terminal) and acts on it:
  tstp      kill(getpid(), SIGTSTP)   (what OpenSSH's ~^Z does)
  stop      kill(getpid(), SIGSTOP)
  ttin      kill(getpid(), SIGTTIN)
  exit N    exit with status N
After a self-stop returns it prints BACK-<cmd>-<n>.
"""
import os
import signal
import sys

tty = os.open("/dev/tty", os.O_WRONLY)


def say(s):
    os.write(tty, (s + "\r\n").encode())


with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
n = 0
while True:
    n += 1
    say("READY-%d" % n)
    line = sys.stdin.readline()
    if not line:
        say("EOF-%d" % n)
        sys.exit(3)
    cmd = line.split()
    if not cmd:
        continue
    if cmd[0] in ("tstp", "stop", "ttin"):
        sig = {"tstp": signal.SIGTSTP, "stop": signal.SIGSTOP, "ttin": signal.SIGTTIN}[cmd[0]]
        os.kill(os.getpid(), sig)
        say("BACK-%s-%d" % (cmd[0], n))
    elif cmd[0] == "exit":
        sys.exit(int(cmd[1]))
    else:
        say("GOT-%s" % cmd[0])
