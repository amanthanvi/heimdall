#!/usr/bin/env python3
"""M00-T05-r4-x2-t1cal-verify probe, scenario P1 (written from scratch for this task).

An interactive shell on a pty starts a background job whose stdin/stdout/stderr are
/dev/null.  The job is either the program itself (plain exec) or
``<binary> run -- <program>``.  A third party (this probe) then sends SIGTSTP or
SIGSTOP to the *program's* PID (under the launcher: the launcher's child).  The probe
records process states and ``jobs -l``, then tries recovery as a user would:
  ladder mode:  (a) fg  (b) ^Z then fg  (c) ^C  (d) ^\\   -- stop at the first that
                brings the prompt back with the job gone from `jobs -l`
  cont mode:    kill -CONT %1, wait, then fg
Every run writes one JSON record to --out.  Everything the probe starts is killed by
exact PID at the end (identity re-checked first) and the record says what was left.
Stdlib only; runs on macOS (ps) and Linux (/proc).
"""
import argparse, json, os, pty, select, signal, subprocess, sys, time

PROMPT = "__PS" + "1__ "          # typed as '__PS''1__ ' so the echoed command never matches
PROGRAM = ["sleep", "3"]          # runs ~3 s, exits 0, never reads the terminal
IS_DARWIN = sys.platform == "darwin"


# ---------------------------------------------------------------- process inspection
def proc_info(pid):
    """dict(pid, ppid, pgid, sid, tpgid, state, comm) or None if the pid does not exist."""
    if pid is None:
        return None
    if IS_DARWIN:
        try:
            out = subprocess.run(["ps", "-o", "pid=,ppid=,pgid=,sess=,tpgid=,stat=,comm=", "-p", str(pid)],
                                 capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception as e:  # pragma: no cover
            return {"pid": pid, "error": repr(e)}
        if not out:
            return None
        f = out.split(None, 6)
        info = {"pid": int(f[0]), "ppid": int(f[1]), "pgid": int(f[2]), "sid": f[3],
                "tpgid": int(f[4]), "state": f[5], "comm": os.path.basename(f[6]) if len(f) > 6 else ""}
        # macOS ps has no ignored-signals keyword; tools/sigign (Go, sysctl kern.proc.pid,
        # built by this task) prints "<p_sigignore> <p_sigcatch>" in hex.
        tool = os.environ.get("SIGIGN_TOOL", "tools/sigign")
        info["sigign"] = None
        if os.access(tool, os.X_OK):
            r = subprocess.run([tool, str(pid)], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.split():
                info["sigign"] = ign_names(int(r.stdout.split()[0], 16))
        return info
    try:
        with open(f"/proc/{pid}/stat") as fh:
            s = fh.read()
        with open(f"/proc/{pid}/status") as fh:
            status = fh.read()
    except (FileNotFoundError, ProcessLookupError):
        return None
    comm = s[s.index("(") + 1:s.rindex(")")]
    rest = s[s.rindex(")") + 2:].split()
    # rest[0]=state rest[1]=ppid rest[2]=pgrp rest[3]=session rest[4]=tty_nr rest[5]=tpgid
    ign = [l.split()[1] for l in status.splitlines() if l.startswith("SigIgn:")]
    return {"pid": pid, "ppid": int(rest[1]), "pgid": int(rest[2]), "sid": int(rest[3]),
            "tpgid": int(rest[5]), "state": rest[0], "comm": comm,
            "sigign": ign_names(int(ign[0], 16)) if ign else None}


def ign_names(mask):
    """Names of the signals set in a signal mask (bit n-1 = signal n), limited to the
    job-control-relevant ones so the record stays readable."""
    names = []
    for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGHUP, signal.SIGTERM, signal.SIGPIPE,
              signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU, signal.SIGCONT, signal.SIGWINCH):
        if mask & (1 << (int(s) - 1)):
            names.append(s.name)
    return names


def children_of(pid):
    kids = []
    if IS_DARWIN:
        out = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            f = line.split()
            if len(f) == 2 and f[1] == str(pid):
                kids.append(int(f[0]))
        return sorted(kids)
    for d in os.listdir("/proc"):
        if d.isdigit():
            info = proc_info(int(d))
            if info and info["ppid"] == pid:
                kids.append(int(d))
    return sorted(kids)


def snapshot(pids):
    return {name: proc_info(pid) for name, pid in pids.items()}


# ---------------------------------------------------------------- pty shell driver
RESET_SIGNALS = [signal.SIGINT, signal.SIGQUIT, signal.SIGHUP, signal.SIGTERM, signal.SIGPIPE,
                 signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU, signal.SIGCONT, signal.SIGCHLD,
                 signal.SIGUSR1, signal.SIGUSR2, signal.SIGALRM, signal.SIGWINCH]


def harness_dispositions():
    """The probe's own dispositions of the signals that matter, as inherited from the
    harness that started it (a `&` job of a non-interactive sh has INT and QUIT ignored)."""
    out = {}
    for s in RESET_SIGNALS:
        h = signal.getsignal(s)
        out[s.name] = "IGN" if h is signal.SIG_IGN else "DFL" if h is signal.SIG_DFL else "handler" if h else str(h)
    return out


class Shell:
    def __init__(self, argv, log, reset_signals=True):
        self.log = log
        self.buf = ""
        self.mark = 0
        self.async_text = []
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"),
               "TERM": "dumb", "LANG": "C", "LC_ALL": "C"}
        pid, fd = pty.fork()
        if pid == 0:  # child: session leader, pty is the controlling tty
            try:
                if reset_signals:
                    # The shell must start with default dispositions whatever the harness
                    # inherited: bash gives its children the dispositions it was started
                    # with, so an inherited SIG_IGN for SIGINT would make ^C inert for the
                    # job (observed in run 1 of this task, see README).
                    for s in RESET_SIGNALS:
                        signal.signal(s, signal.SIG_DFL)
                else:
                    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
                os.execvpe(argv[0], argv, env)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd

    def _drain(self, timeout):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return False
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        text = data.decode("utf-8", "replace")
        self.buf += text
        self.log.write(text)
        return True

    def send(self, s):
        self.log.write(f"\n<<SEND {s!r}>>\n")
        os.write(self.fd, s.encode())

    def expect_prompt(self, timeout):
        """Wait until PROMPT appears after the current mark. Returns the text between
        the mark and the prompt, or None on timeout (mark then stays put)."""
        deadline = time.monotonic() + timeout
        while True:
            i = self.buf.find(PROMPT, self.mark)
            if i >= 0:
                text = self.buf[self.mark:i]
                self.mark = i + len(PROMPT)
                return text
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            self._drain(min(left, 0.25))

    def skip_async_prompts(self):
        """Consume prompts the shell printed on its own (zsh redraws the prompt after an
        asynchronous stop/done notice) so the next command's output is attributed right."""
        self._drain(0.05)
        while True:
            i = self.buf.find(PROMPT, self.mark)
            if i < 0:
                return
            self.async_text.append(self.buf[self.mark:i])
            self.mark = i + len(PROMPT)

    def command(self, line, timeout):
        """Type a line, wait for the next prompt. Returns the output (None on timeout)."""
        self.skip_async_prompts()
        self.send(line + "\n")
        return self.expect_prompt(timeout)

    def settle(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self._drain(max(0.0, end - time.monotonic()))

    def alive(self):
        try:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            return False
        return pid == 0

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


# ---------------------------------------------------------------- helpers
def kill_exact(pid, expect_comm, expect_ppid, note):
    """Kill one process by exact PID after re-checking its identity. Returns a note."""
    info = proc_info(pid)
    if info is None:
        return {"pid": pid, "action": "none", "reason": "gone"}
    if info["state"].startswith("Z"):
        return {"pid": pid, "action": "none", "reason": "zombie", "info": info}
    if info["comm"] != expect_comm or (expect_ppid is not None and info["ppid"] != expect_ppid):
        return {"pid": pid, "action": "none", "reason": "identity mismatch", "info": info}
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    time.sleep(0.2)
    return {"pid": pid, "action": "SIGKILL", "note": note, "before": info, "after": proc_info(pid)}


def clean(out):
    return out.strip() if out is not None else None


def body(out, cmd=None):
    """Non-empty output lines, without the shell's echo of the typed command (matched by
    content after dropping bracketed-paste escapes, since zsh may print an asynchronous
    job notice before the echo)."""
    if out is None:
        return []
    lines = []
    dropped = False
    for l in out.replace("\x1b[?2004h", "").replace("\x1b[?2004l", "").splitlines():
        s = l.strip()
        if not s:
            continue
        if cmd is not None and not dropped and s == cmd.strip():
            dropped = True
            continue
        lines.append(l)
    if cmd is not None and not dropped and lines:   # echo not found verbatim: drop the first line
        lines = lines[1:]
    return lines


LIVE_JOB_WORDS = ("running", "stopped", "suspended")


def jobs_listed(out):
    """True if `jobs -l` output lists a live (running/stopped) job; a `[1]+ Done ...`
    completion notice printed by the shell does not count. None if the command timed out."""
    if out is None:
        return None
    return any(l.lstrip().startswith("[") and any(w in l.lower() for w in LIVE_JOB_WORDS) for l in body(out, "jobs -l"))


# ---------------------------------------------------------------- the scenario
def run_once(args, rep, log):
    sig = {"TSTP": signal.SIGTSTP, "STOP": signal.SIGSTOP}[args.signal]
    shell_argv = {"bash": ["bash", "--norc", "--noprofile", "-i"], "zsh": ["zsh", "-f", "-i"]}[args.shell]
    rec = {"build": args.build, "binary": args.binary, "shell": args.shell, "platform": args.platform,
           "signal": args.signal, "mode": args.mode, "rep": rep, "program": " ".join(PROGRAM),
           "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": [],
           "harness_dispositions": harness_dispositions(),
           "shell_started_with_default_dispositions": not args.no_reset_signals}
    sh = Shell(shell_argv, log, reset_signals=not args.no_reset_signals)
    rec["shell_pid"] = sh.pid
    pids = {"launcher": None, "program": None, "shell": sh.pid}
    try:
        if args.shell == "bash":
            sh.send("PS1='__PS''1__ '; PS2=''; unset PROMPT_COMMAND; set +H\n")
        else:
            # no ZLE (plain line reads, no redraw/bracketed-paste noise), no PROMPT_SP '%'
            # padding, and no history expansion (zsh would mangle the `$!` typed below)
            sh.send("unsetopt zle promptsp promptcr banghist beep; PROMPT='__PS''1__ '; PS2=''\n")
        if sh.expect_prompt(5) is None:
            rec["error"] = "no prompt after setup"
            return rec

        prog = " ".join(PROGRAM)
        job = prog if args.binary == "exec" else f"{args.binary} run -- {prog}"
        rec["job_line"] = f"{job} </dev/null >/dev/null 2>&1 &"
        out = sh.command(rec["job_line"], 5)
        rec["job_start_output"] = clean(out)
        out = sh.command('echo "__PID""__ $!"', 5)
        jobpid = None
        for line in body(out):
            if line.startswith("__PID__ "):
                jobpid = int(line.split()[1])
        rec["job_pid"] = jobpid
        if jobpid is None:
            rec["error"] = "could not read $!"
            return rec
        if args.binary == "exec":
            progpid = jobpid
        else:
            progpid = None
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                kids = children_of(jobpid)
                if kids:
                    rec["launcher_children"] = kids
                    progpid = kids[0]
                    break
                time.sleep(0.05)
            pids["launcher"] = jobpid
        pids["program"] = progpid
        rec["program_pid"] = progpid
        rec["before_signal"] = snapshot(pids)
        if progpid is None:
            rec["error"] = "launcher child not found"
            return rec

        # the third party: this probe sends the signal to the program's own PID
        os.kill(progpid, sig)
        rec["signal_sent_to"] = progpid
        sh.settle(0.7)
        rec["after_signal"] = snapshot(pids)
        out = sh.command("jobs -l", 5)
        rec["jobs_after_signal"] = clean(out)
        rec["after_jobs"] = snapshot(pids)

        def check(step, prompt_out):
            """Record a recovery step; True if the prompt came back with no job listed."""
            st = {"step": step, "prompt_returned": prompt_out is not None, "output": clean(prompt_out)}
            if prompt_out is not None:
                rc = sh.command('echo "__RC""__ $?"', 5)
                for line in body(rc):
                    if line.startswith("__RC__ "):
                        st["rc"] = line.split()[1]
                j = sh.command("jobs -l", 5)
                st["jobs"] = clean(j)
                st["job_listed"] = jobs_listed(j)
            st["procs"] = snapshot(pids)
            st["shell_done"] = bool(prompt_out is not None and st.get("job_listed") is False)
            st["leftover"] = {k: v for k, v in st["procs"].items() if k != "shell" and v is not None}
            rec["steps"].append(st)
            return st["shell_done"]

        worked = "none"
        if args.mode == "ladder":
            if check("a:fg", sh.command("fg", 9)):
                worked = "a"
            else:
                sh.send("\x1a")
                z = sh.expect_prompt(4)
                rec["steps"].append({"step": "b:^Z", "prompt_returned": z is not None,
                                     "output": clean(z), "procs": snapshot(pids)})
                if check("b:fg", sh.command("fg", 9)):
                    worked = "b"
                else:
                    sh.send("\x03")
                    if check("c:^C", sh.expect_prompt(6)):
                        worked = "c"
                    else:
                        sh.send("\x1c")
                        if check("d:^\\", sh.expect_prompt(6)):
                            worked = "d"
        else:
            out = sh.command("kill -CONT %1", 5)
            rec["steps"].append({"step": "kill -CONT %1", "prompt_returned": out is not None,
                                 "output": clean(out), "procs": snapshot(pids)})
            sh.settle(4.5)
            j = sh.command("jobs -l", 5)
            rec["steps"].append({"step": "after 4.5 s", "procs": snapshot(pids), "jobs": clean(j),
                                 "job_listed": jobs_listed(j)})
            out = sh.command("fg", 9)
            if check("fg", out):
                txt = "\n".join(body(out))
                worked = "cont-alone" if ("no such job" in txt or "no current job" in txt or "no job" in txt) else "cont+fg"
        rec["worked"] = worked
        last = rec["steps"][-1] if rec["steps"] else {}
        rec["leftover_at_end"] = last.get("leftover", {})
        rec["final"] = snapshot(pids)
    finally:
        cleanup = []
        if pids["program"]:
            cleanup.append(kill_exact(pids["program"], PROGRAM[0], None, "program (may be reparented)"))
        if pids["launcher"]:
            cleanup.append(kill_exact(pids["launcher"], os.path.basename(args.binary), sh.pid, "launcher"))
        try:
            sh.send("\nexit\n")
        except OSError:
            pass
        end = time.monotonic() + 3
        while time.monotonic() < end and sh.alive():
            sh.settle(0.1)
        if sh.alive():
            os.kill(sh.pid, signal.SIGKILL)
            cleanup.append({"pid": sh.pid, "action": "SIGKILL", "note": "shell did not exit"})
            try:
                os.waitpid(sh.pid, 0)
            except ChildProcessError:
                pass
        sh.close()
        try:  # reap anything reparented to us (relevant when this probe is PID 1)
            while True:
                p, _ = os.waitpid(-1, os.WNOHANG)
                if p == 0:
                    break
        except ChildProcessError:
            pass
        rec["cleanup"] = cleanup
        rec["leftover_after_cleanup"] = {k: proc_info(v) for k, v in pids.items()
                                         if k != "shell" and v and proc_info(v) is not None}
        rec["async_text"] = [t for t in sh.async_text if t.strip()]
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", required=True)
    ap.add_argument("--binary", required=True, help="path to heimdall-proto, or 'exec'")
    ap.add_argument("--shell", choices=["bash", "zsh"], default="bash")
    ap.add_argument("--platform", required=True)
    ap.add_argument("--signal", choices=["TSTP", "STOP"], required=True)
    ap.add_argument("--mode", choices=["ladder", "cont"], required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", required=True, help="output dir for json + pty logs")
    ap.add_argument("--no-reset-signals", action="store_true",
                    help="start the shell with the probe's inherited dispositions (reproduces the run-1 harness artifact)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    stem = f"{args.build}.{args.platform}.{args.shell}.{args.signal}.{args.mode}"
    recs = []
    for rep in range(1, args.reps + 1):
        with open(os.path.join(args.out, f"{stem}.r{rep}.pty.log"), "w") as log:
            rec = run_once(args, rep, log)
        recs.append(rec)
        print(json.dumps({k: rec.get(k) for k in ("build", "platform", "shell", "signal", "mode", "rep",
                                                   "worked", "error", "leftover_at_end", "leftover_after_cleanup")}), flush=True)
    with open(os.path.join(args.out, f"{stem}.json"), "w") as fh:
        json.dump(recs, fh, indent=1)


if __name__ == "__main__":
    main()
