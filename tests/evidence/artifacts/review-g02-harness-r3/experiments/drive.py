import os, pty, time, sys, select
log = "/tmp/r3rev/exp/cont-%s.log" % sys.argv[1]
if os.path.exists(log): os.unlink(log)
pid, fd = pty.fork()
if pid == 0:
    os.execve("/bin/bash", ["bash", "--norc", "--noprofile", "-i"], {"PATH": "/usr/local/bin:/usr/bin:/bin", "PS1": "P$ ", "BASH_SILENCE_DEPRECATION_WARNING": "1"})
def rd(t):
    end = time.time() + t; out = b""
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: out += os.read(fd, 4096)
            except OSError: break
    return out
rd(1)
os.write(fd, ("python3 /tmp/r3rev/exp/logcont.py %s &\r" % log).encode()); rd(0.8)
os.write(fd, b"fg\r"); rd(1.0)
os.write(fd, b"\x1a"); rd(0.6)
os.write(fd, b"bg\r"); rd(0.6)
os.write(fd, b"fg\r"); rd(3)
os.write(fd, b"exit\r"); rd(0.5)
print(open(log).read() if os.path.exists(log) else "no SIGCONT logged")
