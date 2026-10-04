#!/usr/bin/env python3
"""Review-3 independent probe of `heimdall-proto run` signal / job-control transparency.

usage: sigjob_probe.py HEIMDALL_BIN OUT_JSON [SHELLS(comma, default bash)] [SCENARIOS(comma, default all)]

Every scenario starts a fresh interactive shell in its own pty, runs probes/child.py
directly (control) or under `heimdall-proto run`, and records what the child logged
(per-signal delivery counts, START dispositions, GOT lines), the shell's job reports,
and process states. Nothing here judges the contract; the output is raw observation.
"""
import fcntl
import json
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

HP = os.path.abspath(sys.argv[1])
OUT = sys.argv[2]
SHELLS = (sys.argv[3] if len(sys.argv) > 3 else "bash").split(",")
ONLY = set(sys.argv[4].split(",")) if len(sys.argv) > 4 and sys.argv[4] else None
CHILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "child.py")
PY = shutil.which("python3")
WORK = tempfile.mkdtemp(prefix="hp-rv3-")
CUR = None  # the active Shell: drained while waiting so a chatty shell never blocks on a full pty
STARTED = []  # exact pids observed (shells, heimdall, children) for the leftover check
SIGS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"]


def pstate(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            b = f.read()
        return b[b.rindex(b")") + 2:].split()[0].decode()
    except FileNotFoundError:
        if os.path.isdir("/proc/self"):
            return "gone"
    except Exception:
        pass
    r = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return r.stdout.strip() or "gone"


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    s = pstate(pid)
    return s not in ("gone",) and not s.startswith("Z")


class Shell:
    def __init__(self, kind, rows=24, cols=80):
        argv = {"bash": ["bash", "--norc", "--noprofile", "-i"], "zsh": ["zsh", "-f", "-i"],
                "dash": ["dash", "-i"]}[kind]
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": WORK, "TERM": "xterm",
               "LANG": "C", "HP": HP, "PS1": "PRMPT$ "}
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(WORK)
            os.execvpe(argv[0], argv, env)
        self.pid, self.fd, self.kind, self.buf, self.mark = pid, fd, kind, "", 0
        self.closed = False
        global CUR
        CUR = self
        STARTED.append(("shell", pid))
        self.winsz(rows, cols)
        self.expect(r"\$ |% |# ", 5)
        self.send("PS1='PRMPT$ '\n")
        self.expect(r"PRMPT\$ ", 5)
        self.mark = len(self.buf)

    def winsz(self, rows, cols):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def pump(self, t):
        end = time.monotonic() + t
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            r, _, _ = select.select([self.fd], [], [], left)
            if not r:
                return
            try:
                d = os.read(self.fd, 65536)
            except OSError:
                return
            if not d:
                return
            self.buf += d.decode("utf-8", "replace")

    def expect(self, pat, timeout):
        end = time.monotonic() + timeout
        rx = re.compile(pat)
        while True:
            m = rx.search(self.buf, self.mark)
            if m:
                self.mark = m.end()
                return m
            left = end - time.monotonic()
            if left <= 0:
                return None
            self.pump(min(left, 0.05))

    def send(self, s):
        os.write(self.fd, s.encode())

    def since(self, pos):
        return self.buf[pos:]

    def close(self):
        try:
            self.send("\x03")
            self.send("exit\n")
            self.pump(0.3)
            self.send("exit\n")
            self.pump(0.3)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.closed = True
        for _ in range(20):
            p, _ = os.waitpid(self.pid, os.WNOHANG)
            if p:
                return
            time.sleep(0.05)
        os.kill(self.pid, signal.SIGKILL)  # the exact shell pid this probe forked
        os.waitpid(self.pid, 0)


def wait_log(log, pat, timeout):
    end = time.monotonic() + timeout
    rx = re.compile(pat, re.M)
    while time.monotonic() < end:
        try:
            with open(log) as f:
                m = rx.search(f.read())
            if m:
                return m
        except FileNotFoundError:
            pass
        if CUR is not None and not CUR.closed:
            CUR.pump(0.03)
        else:
            time.sleep(0.03)
    return None


def counts(log):
    c = {s: 0 for s in SIGS}
    try:
        for line in open(log):
            if line.startswith("SIG "):
                c[line.split()[1]] += 1
    except FileNotFoundError:
        pass
    return c


def start_info(log):
    m = wait_log(log, r"^START pid=(\d+) ppid=(\d+) pgid=(\d+) disp=(\S+)", 8)
    if not m:
        return None
    d = {"child": int(m.group(1)), "ppid": int(m.group(2)), "pgid": int(m.group(3)), "disp": m.group(4)}
    STARTED.append(("child", d["child"]))
    return d


def cmdline(layout, log, mode="read"):
    run = '"$HP" run -- %s %s %s %s' % (PY, CHILD, log, mode)
    direct = "%s %s %s %s" % (PY, CHILD, log, mode)
    return {
        "control": direct,
        "exclusive": run,
        "pipeline_first": run + " | cat",
        "pipeline_last": "cat /dev/null | " + run,
        "wrapper": "./wrap.sh %s %s" % (log, mode),
        "sh_c": "sh -c '%s; echo SHDONE'" % run.replace('"$HP"', HP),
        "make": 'make -s -f %s/Makefile HP="$HP" PY=%s CHILD=%s LOG=%s MODE=%s' % (WORK, PY, CHILD, log, mode),
        "nohup": 'nohup %s > %s.out 2>&1' % (run, log),
        "stdin_file": run + " < /dev/null",
    }[layout]


def setup_files():
    with open(os.path.join(WORK, "wrap.sh"), "w") as f:
        f.write('#!/bin/sh\n"$HP" run -- %s %s "$1" "$2"\necho WRAPDONE\n' % (PY, CHILD))
    os.chmod(os.path.join(WORK, "wrap.sh"), 0o755)
    with open(os.path.join(WORK, "Makefile"), "w") as f:
        f.write('all:\n\t"$(HP)" run -- $(PY) $(CHILD) $(LOG) $(MODE)\n')


def newlog(name):
    return os.path.join(WORK, name + ".log")


BEAT_LAYOUTS = ("pipeline_last", "stdin_file", "nohup")  # GNU nohup makes a terminal stdin unreadable


def finish(sh, info, res, mode="read"):
    if mode == "beat":
        os.kill(info["child"], signal.SIGUSR1)
    else:
        sh.send("quit\n")
    sh.expect(r"PRMPT\$ ", 5)
    pos = len(sh.buf)
    sh.send("echo RC=$?\n")
    m = sh.expect(r"RC=(\d+)", 5)
    res["final_rc"] = int(m.group(1)) if m else None
    if info:
        res["child_alive_after"] = alive(info["child"])
        if info["ppid"] != sh.pid:
            res["heimdall_alive_after"] = alive(info["ppid"])


# ---------------------------------------------------------------- scenarios

def sc_explicit(kind, layout):
    """SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH sent with kill(2) to the heimdall-proto pid."""
    if layout == "make" and not shutil.which("make"):
        return {"blocked": "make not installed in this environment"}
    sh = Shell(kind)
    log = newlog("explicit-%s-%s" % (kind, layout))
    res = {"layout": layout}
    mode = "beat" if layout in BEAT_LAYOUTS else "read"
    try:
        sh.send(cmdline(layout, log, mode) + "\n")
        info = start_info(log)
        res["start"] = info
        if not info:
            res["error"] = "child did not start"
            res["tty"] = sh.since(0)[-600:]
            return res
        hp = info["ppid"]
        res["hp_pgid"] = os.getpgid(hp)
        res["hp_pgid_equals_child_pgid"] = res["hp_pgid"] == info["pgid"]
        time.sleep(0.4)
        for s in SIGS:
            os.kill(hp, getattr(signal, s))
            time.sleep(0.4)
        time.sleep(0.3)
        res["deliveries"] = counts(log)
        res["heimdall_alive_after_signals"] = alive(hp)
        finish(sh, info, res, mode)
    finally:
        sh.close()
    return res


def sc_terminal(kind, layout, what):
    """Terminal-generated SIGINT (^C) or SIGWINCH (resize of the pty)."""
    sh = Shell(kind)
    log = newlog("term-%s-%s-%s" % (what, kind, layout))
    res = {"layout": layout, "what": what}
    mode = "beat" if layout in BEAT_LAYOUTS else "read"
    try:
        sh.send(cmdline(layout, log, mode) + "\n")
        info = start_info(log)
        res["start"] = info
        if not info:
            res["error"] = "child did not start"
            return res
        time.sleep(0.5)
        trials = []
        for i in range(3):
            before = counts(log)
            if what == "ctrl_c":
                sh.send("\x03")
            else:
                sh.winsz(30 + i, 90 + i)
            time.sleep(0.7)
            after = counts(log)
            key = "SIGINT" if what == "ctrl_c" else "SIGWINCH"
            trials.append(after[key] - before[key])
            if what == "ctrl_c" and layout.startswith("pipeline"):
                break  # cat is gone after the first ^C
        res["per_trial_deliveries"] = trials
        finish(sh, info, res, mode)
    finally:
        sh.close()
    return res


def stopped_report(text):
    m = re.findall(r"(Stopped[^\r\n]*|suspended[^\r\n]*|Running[^\r\n]*|running[^\r\n]*)", text)
    return m


def sc_jobctl_fg(kind, layout, iters=3):
    """^Z then fg, child blocked in a terminal read; typed line must arrive after each fg."""
    sh = Shell(kind)
    log = newlog("jobfg-%s-%s" % (kind, layout))
    res = {"layout": layout, "iterations": []}
    try:
        sh.send(cmdline(layout, log) + "\n")
        info = start_info(log)
        res["start"] = info
        if not info:
            res["error"] = "child did not start"
            return res
        time.sleep(0.5)
        for i in range(iters):
            it = {}
            pos = len(sh.buf)
            sh.send("\x1a")
            it["shell_reported_stop"] = bool(sh.expect(r"Stopped|suspended", 3))
            sh.expect(r"PRMPT\$ ", 3)
            time.sleep(0.2)
            it["child_state_stopped"] = pstate(info["child"])
            sh.send("fg\n")
            time.sleep(0.6)
            it["child_state_after_fg"] = pstate(info["child"])
            line = "line%d" % i
            sh.send(line + "\n")
            it["got_line"] = bool(wait_log(log, "^GOT %s$" % line, 3))
            time.sleep(1.0)
            it["restopped_after_fg"] = bool(re.search(r"Stopped|suspended", sh.since(sh.mark)))
            it["tty_tail"] = sh.since(pos)[-300:]
            res["iterations"].append(it)
        res["deliveries"] = counts(log)
        finish(sh, info, res)
    finally:
        sh.close()
    return res


def sc_q12(kind, layout):
    """^Z, bg while the child is blocked in a terminal read (kernel SIGTTIN), jobs, fg, typed line."""
    sh = Shell(kind)
    log = newlog("q12-%s-%s" % (kind, layout))
    res = {"layout": layout}
    try:
        sh.send(cmdline(layout, log) + "\n")
        info = start_info(log)
        res["start"] = info
        if not info:
            res["error"] = "child did not start"
            return res
        time.sleep(0.5)
        sh.send("\x1a")
        res["stop_reported"] = bool(sh.expect(r"Stopped|suspended", 3))
        sh.expect(r"PRMPT\$ ", 3)
        pos = len(sh.buf)
        sh.send("bg\n")
        time.sleep(1.5)
        sh.send("jobs\n")
        sh.expect(r"PRMPT\$ ", 3)
        time.sleep(0.3)
        sh.send("jobs\n")
        sh.expect(r"PRMPT\$ ", 3)
        res["after_bg_tty"] = sh.since(pos)[-500:]
        res["after_bg_job_reports"] = stopped_report(sh.since(pos))
        res["child_state_after_bg"] = pstate(info["child"])
        if info["ppid"] != sh.pid:
            res["hp_state_after_bg"] = pstate(info["ppid"])
        sh.send("fg\n")
        time.sleep(0.6)
        sh.send("hello\n")
        res["got_line_after_fg"] = bool(wait_log(log, "^GOT hello$", 3))
        res["child_state_after_fg"] = pstate(info["child"])
        finish(sh, info, res)
    finally:
        sh.close()
    return res


def sc_explicit_tstp(kind, layout):
    """kill -TSTP sent to the heimdall-proto pid (or to the child for control); child heartbeats."""
    sh = Shell(kind)
    log = newlog("tstp-%s-%s" % (kind, layout))
    res = {"layout": layout}
    try:
        sh.send(cmdline(layout, log, "beat") + "\n")
        info = start_info(log)
        res["start"] = info
        if not info:
            res["error"] = "child did not start"
            return res
        target = info["child"] if layout == "control" else info["ppid"]
        time.sleep(0.5)
        pos = len(sh.buf)
        os.kill(target, signal.SIGTSTP)
        res["shell_reported_stop"] = bool(sh.expect(r"Stopped|suspended", 3))
        time.sleep(0.3)
        b1 = int(open(log + ".beat").read() or 0)
        time.sleep(1.0)
        b2 = int(open(log + ".beat").read() or 0)
        res["child_beats_while_job_stopped"] = b2 - b1
        res["child_state"] = pstate(info["child"])
        res["target_state"] = pstate(target)
        sh.send("fg\n")
        time.sleep(0.6)
        b3 = int(open(log + ".beat").read() or 0)
        time.sleep(0.5)
        b4 = int(open(log + ".beat").read() or 0)
        res["child_beats_after_fg"] = b4 - b3
        os.kill(info["child"], signal.SIGUSR1)
        sh.expect(r"PRMPT\$ ", 5)
        sh.send("echo RC=$?\n")
        m = sh.expect(r"RC=(\d+)", 5)
        res["final_rc"] = int(m.group(1)) if m else None
        res["tty"] = sh.since(pos)[-400:]
    finally:
        sh.close()
    return res


def sc_hangup(kind, layout):
    """Close the pty master while the job runs in the foreground; count SIGHUP in the child."""
    sh = Shell(kind)
    log = newlog("hup-%s-%s" % (kind, layout))
    res = {"layout": layout, "child_mode": "beat (does not read the terminal; ends on SIGUSR1)"}
    sh.send(cmdline(layout, log, "beat") + "\n")
    info = start_info(log)
    res["start"] = info
    if not info:
        res["error"] = "child did not start"
        sh.close()
        return res
    time.sleep(0.6)
    os.close(sh.fd)
    sh.closed = True
    time.sleep(2.0)
    res["deliveries"] = counts(log)
    res["child_alive_2s_after_hangup"] = alive(info["child"])
    if info["ppid"] != sh.pid:
        res["heimdall_alive_2s_after_hangup"] = alive(info["ppid"])
    try:
        res["child_log_tail"] = [l.strip() for l in open(log)][-4:]
    except Exception:
        pass
    if alive(info["child"]):
        os.kill(info["child"], signal.SIGUSR1)  # exact child pid from its START line: end the heartbeat
        time.sleep(0.5)
    res["heimdall_alive_after_child_end"] = alive(info["ppid"]) if info["ppid"] != sh.pid else None
    for _ in range(40):
        p, _ = os.waitpid(sh.pid, os.WNOHANG)
        if p:
            break
        time.sleep(0.05)
    else:
        os.kill(sh.pid, signal.SIGKILL)
        os.waitpid(sh.pid, 0)
    return res


def main():
    setup_files()
    plan = []
    for k in SHELLS:
        for lay in ["exclusive", "pipeline_first", "pipeline_last", "wrapper", "sh_c", "make", "nohup", "stdin_file"]:
            plan.append(("explicit", k, lay, lambda k=k, lay=lay: sc_explicit(k, lay)))
        for lay in ["control", "exclusive", "pipeline_first", "wrapper", "stdin_file"]:
            plan.append(("ctrl_c", k, lay, lambda k=k, lay=lay: sc_terminal(k, lay, "ctrl_c")))
            plan.append(("winch", k, lay, lambda k=k, lay=lay: sc_terminal(k, lay, "winch")))
        for lay in ["control", "exclusive", "pipeline_first"]:
            plan.append(("jobctl_fg", k, lay, lambda k=k, lay=lay: sc_jobctl_fg(k, lay)))
        for lay in ["control", "exclusive"]:
            plan.append(("q12", k, lay, lambda k=k, lay=lay: sc_q12(k, lay)))
            plan.append(("tstp", k, lay, lambda k=k, lay=lay: sc_explicit_tstp(k, lay)))
        for lay in ["control", "exclusive", "pipeline_first"]:
            plan.append(("hangup", k, lay, lambda k=k, lay=lay: sc_hangup(k, lay)))
    results = []
    for name, k, lay, fn in plan:
        if ONLY and name not in ONLY:
            continue
        t0 = time.monotonic()
        try:
            r = fn()
        except Exception as e:  # recorded, never hidden
            r = {"exception": repr(e)}
        r.update({"scenario": name, "shell": k, "layout": lay, "secs": round(time.monotonic() - t0, 2)})
        results.append(r)
        print(json.dumps({x: r.get(x) for x in ("scenario", "shell", "layout", "deliveries",
                                                 "per_trial_deliveries", "final_rc", "error", "blocked",
                                                 "exception")}),
              flush=True)
    time.sleep(0.5)
    left = [(kind, pid) for kind, pid in STARTED if alive(pid)]
    for kind, pid in left:
        if kind == "child":
            os.kill(pid, signal.SIGKILL)  # exact child pid this probe observed via its own START line
    out = {"heimdall_bin": HP, "uname": os.uname().sysname + " " + os.uname().machine,
           "shell_versions": {k: subprocess.run([k, "--version"] if k != "dash" else ["sh", "-c", "true"],
                                                capture_output=True, text=True).stdout.splitlines()[:1]
                              for k in SHELLS},
           "results": results, "leftover_processes": left}
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
