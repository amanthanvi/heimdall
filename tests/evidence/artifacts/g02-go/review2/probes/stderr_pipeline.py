# K6a: heimdall-proto with stdin/stdout on the tty and only stderr piped into a
# tty-reading peer of the same job (bash -i). REPORT gap 3 says the mode check can
# miss late-joining peers; this measures how often the peer loses the terminal.
import json, os, pty, re, select, sys, tempfile, time
P = sys.argv[1]; PY = sys.executable; HERE = os.path.dirname(os.path.abspath(__file__)); N = int(sys.argv[2]) if len(sys.argv) > 2 else 10
CONTROL = len(sys.argv) > 3 and sys.argv[3] == 'control'
def pump(fd, buf, t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try: buf.extend(os.read(fd, 65536))
            except OSError: return
res = []
for i in range(N):
    d = tempfile.mkdtemp(prefix="hm-r2-sp-")
    env = {"PATH": "/usr/bin:/bin", "HOME": d, "TERM": "xterm", "PS1": "HMPS$ ", "P": P, "Y": PY, "C": os.path.join(HERE, "child_trap.py"), "Q": os.path.join(HERE, "peer_tty.py"), "D": d, "HISTFILE": os.path.join(d, "h"), "BASH_SILENCE_DEPRECATION_WARNING": "1"}
    pid, fd = pty.fork()
    if pid == 0:
        os.execve("/bin/bash", ["/bin/bash", "--norc", "--noprofile", "-i"], env)
    buf = bytearray(); pump(fd, buf, 0.8)
    LAYOUT = sys.argv[4] if len(sys.argv) > 4 else "stderr"
    run_ = '' if CONTROL else '"$P" run -- '
    if LAYOUT == "stderr":
        cmdline = (run_ + '"$Y" "$C" "$D" 1.2 2>&1 >/dev/tty | "$Y" "$Q" "$D"; echo "PDONE ${PIPESTATUS[*]}"\r').encode()
    else:  # peer first, heimdall-proto last (stdin is the pipe)
        cmdline = ('"$Y" "$Q" "$D" </dev/null | ' + run_ + '"$Y" "$C" "$D" 1.2; echo "PDONE ${PIPESTATUS[*]}"\r').encode()
    os.write(fd, cmdline)
    end = time.time() + 6
    while not os.path.exists(os.path.join(d, "peer.reading")) and time.time() < end: pump(fd, buf, 0.05)
    pump(fd, buf, 0.3)
    os.write(fd, b"PEERLINE\r")
    end = time.time() + 6
    while b"PDONE" not in buf and time.time() < end: pump(fd, buf, 0.05)
    pump(fd, buf, 0.2)
    try:
        import subprocess
        res_ps = {}
        for pp in os.listdir("/proc"):
            if pp.isdigit():
                try:
                    b = open("/proc/%s/stat" % pp).read(); comm = b[b.index("(")+1:b.rindex(")")]; f = b[b.rindex(")")+2:].split()
                    if comm in ("python3", "heimdall-proto", "bash"): res_ps[pp] = [comm, f[0], f[2], f[5]]
                except OSError: pass
    except Exception as e:
        res_ps = str(e)
    pr = json.load(open(os.path.join(d, "peer.result"))) if os.path.exists(os.path.join(d, "peer.result")) else None
    m = re.search(rb"PDONE ([\d ]+)", bytes(buf))
    res.append({"ps": res_ps if not os.path.exists("/System") else None, "tail": re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", bytes(buf).decode("utf-8","replace"))[-400:], "peer": pr, "stopped_reported": b"Stopped" in buf, "statuses": m.group(1).decode().strip() if m else None})
    os.write(fd, b"\x03\rkill -9 %1 2>/dev/null; exit\r"); pump(fd, buf, 0.3)
    try: os.kill(pid, 9); os.waitpid(pid, 0)
    except OSError: pass
bad = [r for r in res if r["stopped_reported"] or not r["peer"] or r["peer"].get("read") != "PEERLINE\n"]
print(json.dumps({"runs": N, "bad": len(bad), "results": res}, indent=1))
