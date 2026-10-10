#!/usr/bin/env python3
"""Side experiment: during the hung `fg` of P1 (Go cell, darwin), what are the pty's
termios (ISIG, VINTR, VQUIT, VSUSP), which process group holds the terminal, and which
signals does the stopped child ignore/catch?  Then send ^C and look again.
usage: exp_fg_termios.py <shell: bash|zsh> <binary>   (run from the scratch root)"""
import os, pty, select, signal, subprocess, sys, termios, time, json

PROMPT = "__PS" + "1__ "


POS = 0  # search position in the pty buffer: text before it has been consumed


def read_until(fd, buf, needle, timeout):
    """Read until `needle` appears after POS; advance POS past it. (buf, found)."""
    global POS
    end = time.monotonic() + timeout
    while buf.find(needle, POS) < 0:
        left = end - time.monotonic()
        if left <= 0:
            return buf, False
        r, _, _ = select.select([fd], [], [], min(left, 0.2))
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return buf, False
            buf += data.decode("utf-8", "replace")
    POS = buf.find(needle, POS) + len(needle)
    return buf, True


def ps(pids):
    out = subprocess.run(["ps", "-o", "pid=,pgid=,tpgid=,stat=,sigignore=,sigcatch=,pending=,comm=", "-p", ",".join(map(str, pids))],
                         capture_output=True, text=True).stdout
    return [l.strip() for l in out.splitlines() if l.strip()]


def kids(pid):
    out = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True).stdout
    return [int(l.split()[0]) for l in out.splitlines() if len(l.split()) == 2 and l.split()[1] == str(pid)]


def tio(fd):
    a = termios.tcgetattr(fd)
    cc = a[6]
    def ch(c):
        return None if c == b"\x00" or c == 0 else (c if isinstance(c, str) else repr(c))
    return {"ISIG": bool(a[3] & termios.ISIG), "ICANON": bool(a[3] & termios.ICANON),
            "VINTR": repr(cc[termios.VINTR]), "VQUIT": repr(cc[termios.VQUIT]), "VSUSP": repr(cc[termios.VSUSP]),
            "fg_pgrp": os.tcgetpgrp(fd)}


def main():
    shell, binary = sys.argv[1], sys.argv[2]
    argv = {"bash": ["bash", "--norc", "--noprofile", "-i"], "zsh": ["zsh", "-f", "-i"]}[shell]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp", "TERM": "dumb", "LANG": "C", "LC_ALL": "C"}
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env)
    buf = ""
    setup = "PS1='__PS''1__ '; PS2=''; unset PROMPT_COMMAND; set +H\n" if shell == "bash" else \
        "unsetopt zle promptsp promptcr banghist beep; PROMPT='__PS''1__ '; PS2=''\n"
    os.write(fd, setup.encode())
    buf, _ = read_until(fd, buf, PROMPT, 5)
    rec = {"shell": shell, "binary": binary, "shell_pid": pid, "tio_at_prompt": tio(fd)}
    os.write(fd, f"{binary} run -- sleep 3 </dev/null >/dev/null 2>&1 &\n".encode())
    buf, _ = read_until(fd, buf, PROMPT, 5)
    mark = len(buf)
    os.write(fd, b'echo "__PID""__ $!"\n')
    buf, _ = read_until(fd, buf, PROMPT, 5)
    pidlines = [l.strip() for l in buf.replace("\r", "").splitlines() if l.strip().startswith("__PID__ ")]
    if not pidlines:
        print(json.dumps({"error": "no __PID__ line", "tail": buf[-600:]}))
        os.kill(pid, signal.SIGKILL)
        return
    jobpid = int(pidlines[-1].split()[1])
    time.sleep(0.3)
    child = kids(jobpid)[0]
    rec.update(launcher=jobpid, child=child)
    os.kill(child, signal.SIGTSTP)
    time.sleep(0.7)
    rec["after_stop"] = {"ps": ps([jobpid, child]), "tio": tio(fd)}
    # argv[3]: pre-steps before ^C, letters z = ^Z, f = typed "fg\n" (default none);
    # argv[4]: seconds to wait for a prompt after the first `fg` (default 3);
    # argv[5]: comma list of seconds to wait after each pre-step (default 2 each).
    pre = sys.argv[3] if len(sys.argv) > 3 else ""
    fg_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 3.0
    waits = [float(x) for x in sys.argv[5].split(",")] if len(sys.argv) > 5 else [2.0] * len(pre)
    rec.update(pre_steps=pre, fg_wait=fg_wait, pre_waits=waits)
    t0 = time.monotonic()
    os.write(fd, b"fg\n")
    buf, got = read_until(fd, buf, PROMPT, fg_wait)
    rec["fg_prompt_returned"] = got
    rec["during_fg"] = {"ps": ps([jobpid, child]), "tio": tio(fd)}
    for step, w in zip(pre, waits):
        os.write(fd, {"z": b"\x1a", "f": b"fg\n"}[step])
        buf, got = read_until(fd, buf, PROMPT, w)
        rec.setdefault("after_pre", []).append({"step": step, "prompt": got, "ps": ps([jobpid, child]), "tio": tio(fd),
                                                "t_since_fg": round(time.monotonic() - t0, 1)})
    rec["t_ctrl_c_since_fg"] = round(time.monotonic() - t0, 1)
    os.write(fd, b"\x03")
    time.sleep(1.0)
    buf, got = read_until(fd, buf, PROMPT, 2)
    rec["after_ctrl_c"] = {"prompt": got, "ps": ps([jobpid, child]), "tio": tio(fd)}
    if not got:
        os.write(fd, b"\x1c")
        time.sleep(1.0)
        buf, got = read_until(fd, buf, PROMPT, 2)
        rec["after_ctrl_backslash"] = {"prompt": got, "ps": ps([jobpid, child])}
    # cleanup by exact pid, identity re-checked via comm
    for p, comm in ((child, "sleep"), (jobpid, os.path.basename(binary))):
        rows = ps([p])
        if rows and rows[0].endswith(comm):
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # Let the shell exit, draining the pty meanwhile: a session leader's exit on darwin
    # waits for the terminal's output queue to drain, so an unread master would hang it.
    try:
        os.write(fd, b"\nexit\n")
    except OSError:
        pass
    end = time.monotonic() + 3
    while time.monotonic() < end:
        p, _ = os.waitpid(pid, os.WNOHANG)
        if p == pid:
            break
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                os.read(fd, 65536)
            except OSError:
                pass
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        end = time.monotonic() + 3
        while time.monotonic() < end:
            p, _ = os.waitpid(pid, os.WNOHANG)
            if p == pid:
                break
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    os.read(fd, 65536)
                except OSError:
                    pass
    os.close(fd)
    rec["leftover"] = ps([jobpid, child])
    print(json.dumps(rec, indent=1))


if __name__ == "__main__":
    main()
