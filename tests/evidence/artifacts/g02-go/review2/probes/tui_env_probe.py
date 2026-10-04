# TUI startup under environment variables read by linked dependencies
# (colorprofile -> xo/terminfo: TERM, TERMINFO, TERMINFO_DIRS, $HOME/.terminfo) and
# fake helper programs on PATH (K16).
import fcntl, struct, termios, json, os, pty, select, signal, subprocess, sys, tempfile, time, platform, resource
P = sys.argv[1]; FIX = sys.argv[2]
def rss_kib(pid):
    try:
        if platform.system() == "Linux":
            for l in open("/proc/%d/status" % pid):
                if l.startswith("VmRSS:"): return int(l.split()[1])
        out = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        return int(out) if out else None
    except Exception:
        return None
def run(name, env_extra, setup=None, wait=4.0):
    d = tempfile.mkdtemp(prefix="hm-r2-tuienv-")
    home = os.path.join(d, "home"); os.mkdir(home)
    fakebin = os.path.join(d, "bin"); os.mkdir(fakebin)
    log = os.path.join(d, "exec.log")
    for tool in ("tmux", "tput", "infocmp", "stty", "screen", "sh", "bash", "ps", "uname", "sw_vers", "defaults", "open", "xdg-open", "sysctl", "ioreg", "ls", "cat", "env", "id", "whoami", "git", "ssh", "ssh-agent", "ssh-add", "locale", "getent", "launchctl", "osascript", "reattach-to-user-namespace", "tic", "toe"):
        p = os.path.join(fakebin, tool)
        open(p, "w").write("#!/bin/sh\necho \"%s $*\" >> '%s'\nsleep 5\n" % (tool, log)); os.chmod(p, 0o755)
    env = {"PATH": fakebin + ":/usr/bin:/bin", "HOME": home, "LANG": "en_US.UTF-8", "TERM": "xterm-256color", "TMPDIR": d}
    env.update(env_extra)
    if setup: setup(d, home, env)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(d); os.execve(P, [P, "tui", "--file", os.path.join(FIX, "homelab.toml")], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0)); os.kill(pid, signal.SIGWINCH)
    buf = bytearray(); t0 = time.monotonic(); first = None; peak = 0
    while time.monotonic() - t0 < wait:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                x = os.read(fd, 65536); buf.extend(x)
                if first is None and b"lab-server" in buf: first = time.monotonic() - t0
                if b"\x1b[6n" in x: os.write(fd, b"\x1b[24;80R")
            except OSError: break
        k = rss_kib(pid); peak = max(peak, k or 0)
        w, st = os.waitpid(pid, os.WNOHANG)
        if w: break
    os.write(fd, b"q") if first else None
    t1 = time.monotonic(); w = 0
    while time.monotonic() - t1 < 2.0:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try: os.read(fd, 65536)
            except OSError: pass
        w, st = os.waitpid(pid, os.WNOHANG)
        if w: break
    rc = None
    if not w:
        os.kill(pid, signal.SIGKILL); _, st = os.waitpid(pid, 0); rc = "killed-by-reviewer"
    else:
        rc = os.waitstatus_to_exitcode(st)
    execs = open(log).read().splitlines() if os.path.exists(log) else []
    return {"first_frame_s": round(first, 3) if first is not None else None, "exit": rc, "peak_rss_kib_sampled": peak,
            "helper_execs": execs, "stray_files": sorted(set(os.listdir(d)) - {"home", "bin", "exec.log", "ti", "fifo"})[:20],
            "home_files": os.listdir(home)}
def fifo_terminfo(d, home, env):
    os.makedirs(os.path.join(d, "ti", "x"), exist_ok=True); os.mkfifo(os.path.join(d, "ti", "x", "xterm-hm"))
    env["TERMINFO"] = os.path.join(d, "ti"); env["TERM"] = "xterm-hm"
def home_fifo(d, home, env):
    os.makedirs(os.path.join(home, ".terminfo", "x"), exist_ok=True); os.mkfifo(os.path.join(home, ".terminfo", "x", "xterm-hm2")); env["TERM"] = "xterm-hm2"
def garbage_terminfo(d, home, env):
    os.makedirs(os.path.join(d, "ti", "x"), exist_ok=True)
    import struct
    # legacy terminfo magic 0432 with absurd section sizes
    open(os.path.join(d, "ti", "x", "xterm-bad"), "wb").write(struct.pack("<hhhhhh", 0o432, 32767, 32767, 32767, 32767, 32767) + b"\x00" * 64)
    env["TERMINFO"] = os.path.join(d, "ti"); env["TERM"] = "xterm-bad"
cases = {
 "baseline": ({}, None),
 "tmux_env": ({"TMUX": "/tmp/fake,1,0", "TERM": "tmux-256color", "TERM_PROGRAM": "tmux"}, None),
 "screen_env": ({"STY": "1.pts", "TERM": "screen-256color"}, None),
 "term_dumb": ({"TERM": "dumb"}, None),
 "term_unset": ({"TERM": ""}, None),
 "term_traversal_dev_zero": ({"TERM": "../../../../../../../../dev/zero"}, None),
 "terminfo_fifo": ({}, fifo_terminfo),
 "home_terminfo_fifo": ({}, home_fifo),
 "terminfo_garbage": ({}, garbage_terminfo),
 "no_color": ({"NO_COLOR": "1", "TERM": "../../../../../../../../dev/zero"}, None),
 "colorterm_truecolor": ({"COLORTERM": "truecolor", "TERM": "../../../../../../../../dev/zero"}, None),
}
out = {"platform": platform.system() + "-" + platform.machine(), "cases": {}}
for name, (e, setup) in cases.items():
    out["cases"][name] = run(name, e, setup)
print(json.dumps(out, indent=1))
