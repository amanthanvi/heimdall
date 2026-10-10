# M00-T05-r4-x2-t1cal probe child: one process (no grandchildren), so a signal to its PID
# reaches the whole job when run under plain exec.  Writes its PID to PF first and PF.done on
# normal completion.  Usage: child.py PF MODE ARGS...
#   sleep N RC          sleep N seconds (monotonic deadline), exit RC
#   read RC             read one line from stdin, print GOT=<line>, exit RC
#   selftstp RC         kill(getpid(), SIGTSTP), then as `read RC` (OpenSSH ~^Z pattern)
#   ttou RC             tcsetattr(0) with the current settings (SIGTTOU when in background), exit RC
#   cat                 copy stdin to stdout until EOF, exit 0
#   joingrp PGID N RC   setpgid(0, PGID), kill(getpid(), SIGTSTP), sleep N, exit RC
#   jcsh                minimal job-control shell (see below)
import os
import signal
import sys
import time

pf, mode, args = sys.argv[1], sys.argv[2], sys.argv[3:]
with open(pf + ".tmp", "w") as f:
    f.write(str(os.getpid()))
os.rename(pf + ".tmp", pf)


def done(rc):
    open(pf + ".done", "w").close()
    os._exit(rc)


def readline():
    b = b""
    while not b.endswith(b"\n"):
        c = os.read(0, 1)
        if not c:
            break
        b += c
    return b.decode("utf-8", "replace").strip()


if mode == "sleep":
    time.sleep(float(args[0]))
    done(int(args[1]))
elif mode == "read":
    x = readline()
    os.write(1, ("GOT=%s\n" % x).encode())
    done(int(args[0]))
elif mode == "selftstp":
    os.kill(os.getpid(), signal.SIGTSTP)
    x = readline()
    os.write(1, ("GOT=%s\n" % x).encode())
    done(int(args[0]))
elif mode == "ttou":
    import termios
    import errno
    while True:  # SIGTTOU stop, then continue: the call is interrupted (EINTR) and retried
        try:
            termios.tcsetattr(0, termios.TCSANOW, termios.tcgetattr(0))
            break
        except termios.error as e:
            if e.args[0] != errno.EINTR:
                raise
    done(int(args[0]))
elif mode == "cat":
    while True:
        b = os.read(0, 4096)
        if not b:
            break
        os.write(1, b)
    done(0)
elif mode == "joingrp":
    os.setpgid(0, int(args[0]))
    os.kill(os.getpid(), signal.SIGTSTP)
    time.sleep(float(args[1]))
    done(int(args[2]))
elif mode == "jcsh":
    # A minimal job-control "shell": own process group, takes the terminal, `suspend` stops its
    # own group with SIGSTOP (as bash's suspend does), `xq-ping N` answers PONG-N, `exit N`.
    # Unlike bash it never re-takes the terminal when continued: a background read stops it
    # with SIGTTIN, as any ordinary program.
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    os.setpgid(0, 0)
    os.tcsetpgrp(0, os.getpgrp())
    signal.signal(signal.SIGTTOU, signal.SIG_DFL)
    while True:
        x = readline()
        if x == "suspend":
            os.killpg(os.getpgrp(), signal.SIGSTOP)
        elif x.startswith("xq-ping"):
            os.write(1, ("PONG-%s\n" % x.split()[-1]).encode())
        elif x.startswith("exit"):
            done(int(x.split()[1]))
else:
    os._exit(64)
