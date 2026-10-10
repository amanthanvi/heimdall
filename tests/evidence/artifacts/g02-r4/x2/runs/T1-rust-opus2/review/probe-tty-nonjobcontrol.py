import os, sys, time, signal, subprocess, fcntl, termios, tempfile
binp, fg = sys.argv[1], sys.argv[2]
def ps(*a):
    return subprocess.run(["ps","-o","pid=,ppid=,pgid=,stat=,comm="]+list(a),capture_output=True,text=True).stdout
def trial(via, sig):
    d = tempfile.mkdtemp(dir=os.path.dirname(__file__))
    pf = os.path.join(d, "pid"); rcf = os.path.join(d, "rc")
    inner = f'echo $$ > {pf}; i=0; while [ $i -lt 30 ]; do sleep 0.05; i=$((i+1)); done; exit 7'
    cmd = (f'"{binp}" run -- sh -c \'{inner}\'' if via else f'sh -c \'{inner}\'') + f'; echo $? > {rcf}'
    m, s = os.openpty()
    env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
    lead = subprocess.Popen(["/bin/sh", "-c", f'"{sys.executable}" -I "{fg}" "$1"; sleep 30', "x", cmd],
                            stdin=s, stdout=s, stderr=s, start_new_session=True, env=env,
                            preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
    os.close(s)
    import threading
    def drain():
        while True:
            try:
                if not os.read(m, 4096): break
            except OSError: break
    threading.Thread(target=drain, daemon=True).start()
    t = time.monotonic()
    while not (os.path.exists(pf) and open(pf).read().strip()):
        time.sleep(0.02)
        if time.monotonic() - t > 5: return "no start"
    child = int(open(pf).read())
    launcher = int(subprocess.run(["ps","-o","ppid=","-p",str(child)],capture_output=True,text=True).stdout.strip() or 0) if via else 0
    time.sleep(0.2)
    os.kill(child, sig); time.sleep(0.5); os.kill(child, signal.SIGCONT)
    t = time.monotonic(); res = None
    while time.monotonic() - t < 6:
        if os.path.exists(rcf) and open(rcf).read().strip():
            res = f"exit {open(rcf).read().strip()} after {time.monotonic()-t:.2f}s"; break
        time.sleep(0.05)
    if res is None:
        res = "HUNG >6s after SIGCONT; group: " + ps("-g", str(lead.pid)).replace("\n", " | ") + " others: " + ps("-p", str(child)).strip()
    # cleanup: only this probe's session
    out = ps("-s", str(lead.pid)) if False else ""
    for line in subprocess.run(["ps","-o","pid=,sess=","-A"],capture_output=True,text=True).stdout.splitlines():
        pass
    try: os.killpg(lead.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError): pass
    try:
        g = os.getpgid(child)
        os.killpg(g, signal.SIGCONT); os.killpg(g, signal.SIGKILL)
    except (ProcessLookupError, PermissionError): pass
    if launcher:
        for sg in (signal.SIGCONT, signal.SIGKILL):
            try: os.kill(launcher, sg)
            except (ProcessLookupError, PermissionError): pass
    lead.wait(timeout=40)
    return res
for sig in (signal.SIGSTOP, signal.SIGTSTP):
    for via in (False, True):
        print(sig.name, "heimdall-proto" if via else "plain exec", "->", trial(via, sig), flush=True)
