import json, os, pty, re, select, sys, tempfile, time
P = sys.argv[1]; PY = sys.executable; HERE = os.path.dirname(os.path.abspath(__file__))
def pump(fd, buf, t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try: buf.extend(os.read(fd, 65536))
            except OSError: return
def st(pid):
    try:
        b = open("/proc/%d/stat" % pid).read()
        f = b[b.rindex(")") + 2:].split()
        return {"state": f[0], "pgrp": int(f[2]), "tpgid": int(f[5])}
    except OSError as e:
        return str(e)
def wchan(pid):
    try:
        s = open("/proc/%d/status" % pid).read()
        return {l.split(":")[0]: l.split(":")[1].strip() for l in s.splitlines() if l.split(":")[0] in ("SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt", "State")}
    except OSError as e:
        return str(e)
d = tempfile.mkdtemp(prefix="hm-r2-jobdbg-")
env = {"PATH": "/usr/bin:/bin", "HOME": d, "TERM": "xterm", "PS1": "HMPS$ ", "P": P, "Y": PY, "R": os.path.join(HERE, "reader.py"), "D": d, "HISTFILE": os.path.join(d, "h")}
pid, fd = pty.fork()
if pid == 0:
    os.execve("/bin/bash", ["/bin/bash", "--norc", "--noprofile", "-i"], env)
buf = bytearray(); pump(fd, buf, 1.0)
os.write(fd, b'"$P" run -- "$Y" "$R" "$D"; echo "JOBRC=$?"\r')
end = time.time() + 10
while not os.path.exists(os.path.join(d, "ready")) and time.time() < end: pump(fd, buf, 0.05)
cpid, cpgrp, hpid = map(int, open(os.path.join(d, "ready")).read().split())
log = []
def snap(tag):
    log.append({"tag": tag, "t": round(time.time(), 3), "heimdall": st(hpid), "child": st(cpid), "tty_fg": os.tcgetpgrp(fd), "bash_pgrp": os.getpgid(pid), "h_status": wchan(hpid), "c_status": wchan(cpid)})
snap("running")
os.write(fd, b"\x1a"); pump(fd, buf, 0.5); snap("after ^Z")
os.write(fd, b"fg\r")
for i in range(8):
    pump(fd, buf, 0.05); snap("after fg +%d" % i)
pump(fd, buf, 0.5); snap("after fg +0.9s")
print(json.dumps(log, indent=1))
print(re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", bytes(buf).decode("utf-8", "replace"))[-500:])
os.kill(cpid, 9); os.kill(hpid, 9); os.kill(pid, 9)
