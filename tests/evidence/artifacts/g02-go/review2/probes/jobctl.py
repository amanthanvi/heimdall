# Ctrl-Z / fg / bg with heimdall-proto run as a job of an interactive bash (modeExclusive)
import json, os, pty, re, select, sys, tempfile, time
P = sys.argv[1]; PY = sys.executable; HERE = os.path.dirname(os.path.abspath(__file__))
BASH = sys.argv[2] if len(sys.argv) > 2 else "/bin/bash"
def pump(fd, buf, t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try: buf.extend(os.read(fd, 65536))
            except OSError: return
def wait_re(fd, buf, pat, t, start=0):
    end = time.time() + t
    while time.time() < end:
        if re.search(pat, bytes(buf[start:])): return True
        pump(fd, buf, 0.05)
    return bool(re.search(pat, bytes(buf[start:])))
res = {}
for scenario in ("z-fg", "z-bg-fg", "z-fg-z-fg"):
    d = tempfile.mkdtemp(prefix="hm-r2-job-")
    env = {"PATH": "/usr/bin:/bin", "HOME": d, "TERM": "xterm", "PS1": "HMPS$ ", "P": P, "Y": PY, "R": os.path.join(HERE, "reader.py"), "D": d,
           "BASH_SILENCE_DEPRECATION_WARNING": "1", "HISTFILE": os.path.join(d, "h")}
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(BASH, [BASH, "--norc", "--noprofile", "-i"], env)
    buf = bytearray()
    ok = wait_re(fd, buf, rb"HMPS\$ ", 10)
    mark = len(buf)
    os.write(fd, b'"$P" run -- "$Y" "$R" "$D"; echo "JOBRC=$?"\r')
    steps = {"prompt": ok, "ready": wait_re(fd, buf, rb"READY", 10, mark)}
    time.sleep(0.2)
    seq = {"z-fg": ["z", "fg"], "z-bg-fg": ["z", "bg", "fg"], "z-fg-z-fg": ["z", "fg", "z", "fg"]}[scenario]
    for i, st in enumerate(seq):
        m2 = len(buf)
        if st == "z":
            os.write(fd, b"\x1a")
            steps["stopped_%d" % i] = wait_re(fd, buf, rb"Stopped", 5, m2)
            wait_re(fd, buf, rb"HMPS\$ ", 3, m2)
        elif st == "bg":
            os.write(fd, b"bg\r")
            pump(fd, buf, 1.0)
            steps["after_bg_%d" % i] = bytes(buf[m2:]).decode("utf-8", "replace")[-200:]
        elif st == "fg":
            os.write(fd, b"fg\r")
            pump(fd, buf, 0.8)
    m3 = len(buf)
    os.write(fd, b"LINE-AFTER-RESUME\r")
    steps["jobrc"] = wait_re(fd, buf, rb"JOBRC=\d+", 8, m3)
    m = re.search(rb"JOBRC=(\d+)", bytes(buf[mark:]))
    steps["jobrc_value"] = m.group(1).decode() if m else None
    got = os.path.join(d, "got")
    steps["child_got"] = open(got).read() if os.path.exists(got) else None
    m4 = len(buf)
    os.write(fd, b'echo "PROMPT_OK $(jobs | wc -l)"\r')
    steps["shell_usable_after"] = wait_re(fd, buf, rb"PROMPT_OK\s+\d", 5, m4)
    mm = re.search(rb"PROMPT_OK\s+(\d+)", bytes(buf[m4:]))
    steps["jobs_left"] = mm.group(1).decode() if mm else None
    os.write(fd, b"exit\r"); pump(fd, buf, 0.5)
    try: os.kill(pid, 9)
    except OSError: pass
    try: os.waitpid(pid, 0)
    except OSError: pass
    steps["transcript_tail"] = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", bytes(buf[mark:]).decode("utf-8", "replace"))[-600:]
    res[scenario] = steps
print(json.dumps(res, indent=1))
