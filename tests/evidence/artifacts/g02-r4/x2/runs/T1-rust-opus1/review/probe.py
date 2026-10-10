import os, sys, pty, time, select, signal, subprocess, fcntl, termios, struct, re, json
P = sys.argv[1]; W = sys.argv[2]
CHILD = r'''
import os, sys, time
open(sys.argv[1] + "/pid", "w").write(str(os.getpid()))
end = time.monotonic() + 2.0
while time.monotonic() < end: time.sleep(0.02)
open(sys.argv[1] + "/done", "w").close()
sys.exit(7)
'''
open(W + "/c.py", "w").write(CHILD)
class Sh:
    def __init__(self):
        self.m, s = os.openpty()
        fcntl.ioctl(self.m, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
        env.update(PS1="HPS1$ ", TERM="dumb", BASH_SILENCE_DEPRECATION_WARNING="1", HISTFILE="/dev/null", P=P, D=W, Y=sys.executable)
        self.p = subprocess.Popen(["/bin/bash", "--norc", "--noprofile", "-i"], stdin=s, stdout=s, stderr=s,
            start_new_session=True, env=env, preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(s); self.out = b""
        self.pump(1.0)
    def pump(self, t):
        end = time.monotonic() + t
        while True:
            r, _, _ = select.select([self.m], [], [], max(0, min(0.02, end - time.monotonic())))
            if r:
                try: self.out += os.read(self.m, 65536)
                except OSError: pass
            if time.monotonic() >= end: break
    def line(self, t):
        try: os.write(self.m, t.encode() + b"\n")
        except OSError as e: self.out += b"<<write error %r>>" % (e,)
    def wait(self, mark, needle, t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            if needle in self.out[mark:]: return True
            self.pump(0.05)
        return needle in self.out[mark:]
    def close(self):
        try: os.killpg(self.p.pid, signal.SIGKILL)
        except Exception: pass
        self.p.wait(); os.close(self.m)

def bgfg(via):
    sh = Sh(); r = {}
    try:
        pre = '"$P" run -- ' if via else ''
        m = len(sh.out); sh.line('PS1="INNER> " ' + pre + '/bin/bash --norc --noprofile -i')
        r["inner_prompt"] = sh.wait(m, b"INNER> ", 5)
        m = len(sh.out); sh.line('echo INPID=$$'); sh.wait(m, b"INPID=", 3)
        mm = re.search(rb"INPID=(\d+)", sh.out[m:]); r["inner"] = int(mm.group(1)) if mm else None
        if r["inner"]:
            pp = int(subprocess.run(["/bin/ps","-o","ppid=","-p",str(r["inner"])],capture_output=True,text=True).stdout.strip() or 0)
            r["launcher"] = pp if via else None
        m = len(sh.out); sh.line("suspend"); r["notice1"] = sh.wait(m, b"Stopped", 4); sh.pump(0.3)
        m = len(sh.out); sh.line("bg"); sh.pump(1.0)
        m = len(sh.out); sh.line("jobs; echo JE"); sh.wait(m, b"JE", 3); r["jobs_after_bg"] = sh.out[m:].decode(errors="replace")[-200:]
        m = len(sh.out); sh.line("fg"); sh.pump(1.0)
        m = len(sh.out); sh.line("echo BACK=$((60+3))"); r["inner_answers_after_bg_fg"] = sh.wait(m, b"BACK=63", 3)
        r["tail"] = sh.out[-600:].decode(errors="replace")
        r["outer_alive"] = sh.p.poll() is None
        return r
    finally:
        for k in ("inner", "launcher"):
            if r.get(k):
                try: os.kill(r[k], signal.SIGKILL)
                except Exception: pass
        sh.close()

def script(via):
    sh = Sh(); r = {}
    for f in ("pid", "done"):
        try: os.unlink(W + "/" + f)
        except FileNotFoundError: pass
    child = None
    try:
        pre = '"$P" run -- ' if via else ''
        m = len(sh.out); sh.line("/bin/bash -c '" + pre + "\"$Y\" \"$D/c.py\" \"$D\"; echo RC=$?'")
        end = time.monotonic() + 5
        while not os.path.exists(W + "/pid") and time.monotonic() < end: sh.pump(0.05)
        child = int(open(W + "/pid").read()); r["jobpg"] = os.getpgid(child)
        sh.pump(0.3); os.kill(child, signal.SIGSTOP); sh.pump(0.5); os.kill(child, signal.SIGCONT)
        r["rc7_within_6s"] = sh.wait(m, b"RC=7", 6)
        r["completed"] = os.path.exists(W + "/done")
        r["tail"] = sh.out[m:].decode(errors="replace")[-200:]
        return r
    finally:
        pg = r.get("jobpg")
        if pg and pg != os.getpgrp():
            try: os.killpg(pg, signal.SIGKILL)
            except ProcessLookupError: pass
        sh.close()

which = sys.argv[3]
res = {}
for via in (False, True):
    res["hp" if via else "control"] = (bgfg if which == "bgfg" else script)(via)
print(json.dumps(res, indent=1))
