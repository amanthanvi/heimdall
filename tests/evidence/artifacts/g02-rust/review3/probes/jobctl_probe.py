#!/usr/bin/env python3
"""Review3 independent job-control probe (M00-T05-review3-rust).

Runs an interactive shell (bash -i or zsh -i) as session leader of a fresh pty and drives
heimdall-proto `run` through it, comparing with the same command launched directly
(exec semantics baseline). Prints one JSON object. No network, disposable temp dir only.
usage: jobctl_probe.py <shell> <heimdall-proto path|NONE> <workdir>
"""
import json, os, pty, select, signal, subprocess, sys, time

SHELL, HP, WD = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(WD, exist_ok=True)


def proc_state(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
        return s[s.rindex(")") + 2]
    except FileNotFoundError:
        pass
    except OSError:
        return "?"
    try:
        out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
        return out.stdout.strip()[:1] or "gone"
    except Exception:
        return "?"


class Sess:
    def __init__(self):
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": WD, "TERM": "xterm", "PS1": "PROMPT> ",
               "LANG": "C"}
        argv = [SHELL, "--norc", "--noprofile", "-i"] if SHELL.endswith("bash") else [SHELL, "-f", "-i"]
        pid, fd = pty.fork()
        if pid == 0:
            os.execve(SHELL, argv, env)
        self.pid, self.fd, self.buf = pid, fd, b""
        self.read(1.0)
        if SHELL.endswith("zsh"):
            self.send("PS1='PROMPT> '; unsetopt zle 2>/dev/null; setopt nonotify 2>/dev/null\n")
            self.read(0.5)

    def read(self, t):
        end = time.time() + t
        while True:
            left = end - time.time()
            if left <= 0:
                break
            r, _, _ = select.select([self.fd], [], [], left)
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except OSError:
                    break
                if not d:
                    break
                self.buf += d
        return self.buf

    def send(self, s):
        os.write(self.fd, s.encode() if isinstance(s, str) else s)

    def close(self):
        try:
            self.send("exit\n")
            self.read(0.3)
            os.kill(self.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass

    def text(self):
        return self.buf.decode("utf-8", "replace")


def prefix():
    return "" if HP == "NONE" else f"{HP} run -- "


def scenario_self_stop():
    """Child stops ITSELF (kill -TSTP $$), like ssh's ~^Z escape or a raw-mode program."""
    pf = os.path.join(WD, "selfstop.pids")
    if os.path.exists(pf):
        os.unlink(pf)
    s = Sess()
    s.buf = b""
    s.send(f"{prefix()}/bin/sh -c 'echo $$ $PPID > {pf}; echo C_START; kill -TSTP $$; echo C_RESUMED; exit 5'; echo RC=$?\n")
    s.read(2.0)
    pids = open(pf).read().split() if os.path.exists(pf) else []
    after_self_stop = s.text()
    st = {"child": proc_state(int(pids[0])) if pids else None,
          "parent_of_child": proc_state(int(pids[1])) if pids else None}
    shell_saw_stop = "Stopped" in after_self_stop or "suspended" in after_self_stop
    prompt_back = after_self_stop.rstrip().endswith("PROMPT>")
    # recovery attempt 1: plain fg if the shell got the prompt back, else Ctrl-Z then fg
    steps = []
    if not prompt_back:
        s.send(b"\x1a")
        s.read(1.0)
        steps.append("ctrl-z")
    s.send("fg\n")
    s.read(2.0)
    steps.append("fg")
    final = s.text()
    s.close()
    return {"pids_seen": bool(pids), "states_1.5s_after_self_stop": st,
            "shell_reported_stop_without_user_action": shell_saw_stop,
            "prompt_returned_without_user_action": prompt_back,
            "recovery_steps": steps, "child_resumed": "C_RESUMED" in final,
            "rc5_reported": "RC=5" in final, "transcript_tail": final[-600:]}


def scenario_ctrlz_fg_bg():
    """Ctrl-Z, bg, fg, then terminal input reaches the child."""
    s = Sess()
    s.buf = b""
    s.send(f"{prefix()}/bin/sh -c 'echo C_READY; read x; echo GOT=$x; exit 4'; echo RC=$?\n")
    s.read(1.0)
    s.send(b"\x1a")
    s.read(1.0)
    t1 = s.text()
    s.send("bg\n")
    s.read(1.0)
    t2 = s.text()
    s.send("fg\n")
    s.read(1.0)
    s.send("hello\n")
    s.read(1.5)
    final = s.text()
    s.close()
    return {"stopped_after_ctrl_z": ("Stopped" in t1 or "suspended" in t1),
            "bg_output_tail": t2[len(t1):][-200:],
            "got_input_after_fg": "GOT=hello" in final, "rc4": "RC=4" in final,
            "restopped_after_fg": final[len(t2):].count("Stopped") + final[len(t2):].count("suspended"),
            "transcript_tail": final[-500:]}


def scenario_ctrl_c_count(seq=b"\x03", sig="INT"):
    """Terminal-generated signal count seen by the child in shared (foreground job) mode."""
    cf = os.path.join(WD, f"count.{sig}")
    if os.path.exists(cf):
        os.unlink(cf)
    s = Sess()
    s.buf = b""
    sf = os.path.join(WD, f"count-{sig}.sh")
    with open(sf, "w") as f:
        f.write(f"n=0\ntrap 'n=$((n+1)); echo $n > {cf}' {sig}\necho C_READY\n"
                f"i=0; while [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done; exit 3\n")
    s.send(f"{prefix()}/bin/sh {sf}; echo RC=$?\n")
    s.read(1.0)
    s.send(seq)
    s.read(4.5)
    final = s.text()
    s.close()
    c = open(cf).read().strip() if os.path.exists(cf) else "0"
    return {"signal": sig, "child_count": int(c), "rc3": "RC=3" in final}


def scenario_explicit_tstp_to_launcher():
    """kill -TSTP <launcher pid> (explicit, not one of the 5 forwarded signals)."""
    pf = os.path.join(WD, "tstp.pids")
    if os.path.exists(pf):
        os.unlink(pf)
    s = Sess()
    s.buf = b""
    s.send(f"{prefix()}/bin/sh -c 'echo $$ $PPID > {pf}; i=0; while [ $i -lt 40 ]; do sleep 0.1; i=$((i+1)); done; exit 6'; echo RC=$?\n")
    s.read(1.0)
    pids = open(pf).read().split() if os.path.exists(pf) else []
    if not pids:
        s.close()
        return {"error": "no pids"}
    target = int(pids[1]) if HP != "NONE" else int(pids[0])
    os.kill(target, signal.SIGTSTP)
    s.read(1.0)
    st = {"child": proc_state(int(pids[0])), "launcher": proc_state(int(pids[1]))}
    t = s.text()
    s.send("fg\n")
    s.read(5.0)
    final = s.text()
    s.close()
    return {"states_after_tstp": st, "shell_saw_stop": ("Stopped" in t or "suspended" in t),
            "rc6_after_fg": "RC=6" in final}


out = {"shell": SHELL, "hp": HP, "platform": sys.platform, "uname": os.uname().machine}
for name, fn in [("self_stop", scenario_self_stop), ("ctrlz_fg_bg", scenario_ctrlz_fg_bg),
                 ("ctrl_c", lambda: scenario_ctrl_c_count(b"\x03", "INT")),
                 ("ctrl_backslash", lambda: scenario_ctrl_c_count(b"\x1c", "QUIT")),
                 ("explicit_tstp", scenario_explicit_tstp_to_launcher)]:
    try:
        out[name] = fn()
    except Exception as e:  # recorded, not hidden
        out[name] = {"exception": repr(e)}
print(json.dumps(out, indent=1))
