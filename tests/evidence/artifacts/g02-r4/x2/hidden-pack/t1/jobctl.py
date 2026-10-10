"""T1 hidden tests: exec-equivalent job control for `heimdall-proto run` (specs/T1.md).

Every check runs the same scenario twice in the same environment: once with the command executed
directly (the plain-exec control) and once as `heimdall-proto run [--meta-file M] -- <command>`.  If
the control does not show the expected plain-exec behaviour, the check is an `error` (environment
problem), never a `fail`.  Scenarios are the round-3c parity probes
(tests/evidence/artifacts/g02-parity-r3c/probes): child_tstp.py = child.py, child_read.py = child3c.py
and ptyshell.py are byte copies; the procedures follow extstop_plus.py + nonorphan.py (1a),
extstop_pty.py (1b), contlauncher.py (2), nested.py (3) and selfstop_detail.py (4), extended with an
end-to-end completion step.  Only PIDs a check learned itself are signalled, by exact PID.
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import hm
from hm import check, Abort, proc_state, proc_ppid, kill_exact

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ptyshell import Shell, PROMPT, STOPRE, clean  # noqa: E402

T = "T1"
HERE = Path(__file__).resolve().parent
CHILD_TSTP = str(HERE / "child_tstp.py")
CHILD_READ = str(HERE / "child_read.py")
PY = sys.executable
SH_CMD = 'echo $$ > "$1"; sleep 1; echo x > "$1.done"; exit 7'


def stopsig_rc(sig):
    return 128 + int(sig)


def q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def wait_file_int(path, timeout, pump=None):
    end = time.time() + timeout
    while time.time() < end:
        try:
            return int(open(path).read().strip())
        except (OSError, ValueError):
            pass
        if pump:
            pump(0.02)
        else:
            time.sleep(0.02)
    return None


def gone_or_reaped(pid, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc_state(pid) == "gone":
            return True
        time.sleep(0.05)
    return proc_state(pid) == "gone"


# ------------------------------------------------------------------------------------------- 1a
def nonint_once(ctx, binpath, sig):
    d = ctx.new_dir("nonint")
    pf = str(d / "pf")
    cmd = ["sh", "-c", SH_CMD, "sh", pf]
    argv = ([binpath, "run", "--"] + cmd) if binpath else cmd
    t0 = time.monotonic()
    # process_group=0: the job runs in a new process group whose parent (this process) is in another
    # group of the same session, so the group is not orphaned and SIGTSTP is not discarded (parity-r3c H6).
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env=ctx.env(), cwd=str(d), process_group=0)
    hm.H.track(p)
    r = {"via": "heimdall-proto" if binpath else "plain"}
    c = wait_file_int(pf, 5)
    if c is None:
        r["error"] = "child pid file not written"
        p.kill()
        p.wait()
        return r
    r["child_parent_is_launcher"] = proc_ppid(c) == p.pid
    os.kill(c, sig)
    time.sleep(0.5)
    r["after_stop"] = {"child": proc_state(c), "launcher": proc_state(p.pid) if binpath else None,
                       "launcher_exited": p.poll() is not None}
    try:
        os.kill(c, signal.SIGCONT)
    except ProcessLookupError:
        r["cont_target_gone"] = True
    t1 = time.monotonic()
    try:
        rc = p.wait(timeout=6)
        r["rc"] = rc
        r["exit_after_cont_s"] = round(time.monotonic() - t1, 2)
    except subprocess.TimeoutExpired:
        r["rc"] = "hung"
        r["states_when_hung"] = {"child": proc_state(c), "launcher": proc_state(p.pid)}
        try:
            os.kill(p.pid, signal.SIGCONT)
            p.wait(timeout=5)
            r["after_manual_cont_of_launcher"] = p.returncode
        except (subprocess.TimeoutExpired, OSError):
            p.kill()
            p.wait()
    r["child_completed"] = os.path.exists(pf + ".done")
    r["child_reaped"] = gone_or_reaped(c, 2.0)
    r["leftover_killed"] = kill_exact([c])
    return r


def nonint_check(t, ctx, sig):
    ctl = nonint_once(ctx, None, sig)
    t.note("control: %s" % json.dumps(ctl))
    t.precondition("control: plain exec exits 7 and the child completes",
                   ctl.get("rc") == 7 and ctl.get("child_completed"), ctl)
    r = nonint_once(ctx, ctx.bin, sig)
    t.note("subject: %s" % json.dumps(r))
    t.eq("launcher exit status after the third-party SIGCONT (control: 7)", r.get("rc"), 7)
    t.check("launcher exits within 6 s of the SIGCONT", isinstance(r.get("rc"), int), "exited", r.get("rc"))
    t.check("child completed its work", r.get("child_completed"), True, r.get("child_completed"))
    t.check("child reaped (no zombie, no orphan) once the launcher has exited", r.get("child_reaped"), True,
            r.get("child_reaped"))


@check(T, "T1.nonint_stop_cont_SIGSTOP", "1a non-interactive: third-party SIGSTOP then SIGCONT of the child PID")
def _(t, ctx):
    nonint_check(t, ctx, signal.SIGSTOP)


@check(T, "T1.nonint_stop_cont_SIGTSTP", "1a non-interactive: third-party SIGTSTP then SIGCONT of the child PID")
def _(t, ctx):
    nonint_check(t, ctx, signal.SIGTSTP)


# ------------------------------------------------------------------------------------------- 1b
def jobs(sh):
    sh.mark = len(sh.buf)
    sh.send("jobs; echo JE-$((40+2))\n")
    e = sh.expect(re.escape("jobs; echo JE-$((40+2))"), 3)
    m = sh.expect(r"JE-42", 3)
    txt = sh.buf[e.end():m.start()] if (e and m) else ""
    return {"text": clean(txt, 200).strip(), "running": bool(re.search(r"Running|running", txt)),
            "stopped": bool(re.search(r"Stopped|suspended", txt))}


def rc_of(sh, tag="RC"):
    sh.mark = len(sh.buf)
    sh.send("echo %s=$?\n" % tag)
    m = sh.expect(r"%s=(\d+)" % tag, 4)
    return int(m.group(1)) if m else None


def pty_stop_once(ctx, kind, binpath, sig):
    sh = Shell(kind)
    r = {"via": "heimdall-proto" if binpath else "plain"}
    c = h = None
    try:
        pf = os.path.join(sh.tmp, "pf")
        pre = "" if binpath is None else "%s run -- " % q(binpath)
        sh.send("%ssh -c %s sh %s\n" % (pre, q(SH_CMD), q(pf)))
        c = wait_file_int(pf, 6, sh.read)
        if c is None:
            r["error"] = "child pid file not written"
            return r
        h = proc_ppid(c) if binpath else None
        m0 = len(sh.buf)
        os.kill(c, sig)
        time.sleep(0.5)
        sh.read(0.1)
        seg = sh.buf[m0:]
        r["stop_notice"] = bool(re.search(STOPRE, seg))
        r["after_stop"] = {"child": proc_state(c), "launcher": proc_state(h)}
        try:
            os.kill(c, signal.SIGCONT)
            r["cont_sent"] = True
        except ProcessLookupError:
            r["cont_sent"] = False
        sh.read(6.0)
        r["child_completed"] = os.path.exists(pf + ".done")
        r["rc_after"] = rc_of(sh)
        sh.expect(re.escape(PROMPT), 2)
        r["jobs"] = jobs(sh)
        r["needed_fg"] = r["jobs"]["stopped"]
        if r["jobs"]["stopped"]:
            sh.expect(re.escape(PROMPT), 2)
            sh.mark = len(sh.buf)
            sh.send("fg\n")
            sh.expect(re.escape(PROMPT), 5)
            r["rc_after_fg"] = rc_of(sh, "RC2")
            sh.expect(re.escape(PROMPT), 2)
            r["jobs_after_fg"] = jobs(sh)
        r["shell_alive"] = sh.alive() and not sh.eof
        time.sleep(0.3)
        r["final"] = {"child": proc_state(c), "launcher": proc_state(h)}
    except Exception as e:  # noqa
        r["exception"] = repr(e)
    finally:
        sh.read(0.2)
        r["transcript_tail"] = clean(sh.transcript([(binpath or "\0", "<bin>")]), 500)
        r["leftover_killed"] = kill_exact([c, h])
        sh.close()
        subprocess.run(["rm", "-rf", sh.tmp])
    return r


def pty_stop_check(t, ctx, kind, sig):
    ctl = pty_stop_once(ctx, kind, None, sig)
    t.note("control: %s" % json.dumps(ctl, ensure_ascii=False))
    t.precondition("control: stop notice, child completes after the SIGCONT, no stopped job left",
                   ctl.get("stop_notice") and ctl.get("child_completed") and not ctl.get("needed_fg")
                   and ctl.get("rc_after") is not None, ctl)
    r = pty_stop_once(ctx, kind, ctx.bin, sig)
    t.note("subject: %s" % ctx.scrub(json.dumps(r, ensure_ascii=False)))
    t.check("shell reports the job stopped (as with plain exec)", r.get("stop_notice"), True, r.get("stop_notice"))
    t.eq("$? after the stop equals plain exec's (%s)" % ctl.get("rc_after"), r.get("rc_after"), ctl.get("rc_after"))
    t.check("child was continued and completed its work", r.get("child_completed"), True, r.get("child_completed"))
    if r.get("needed_fg"):
        # permitted deviation (specs/T1.md): the job may stay listed as stopped until the user's `fg`
        t.eq("[stayed stopped] `fg` ends the job with the child's status 7", r.get("rc_after_fg"), 7)
        t.check("[stayed stopped] no job left after `fg`",
                not r.get("jobs_after_fg", {}).get("stopped") and not r.get("jobs_after_fg", {}).get("running"),
                "no job", r.get("jobs_after_fg"))
    else:
        t.check("[finished by itself] `jobs` lists no running or stopped job",
                not r.get("jobs", {}).get("running"), "no running job", r.get("jobs"))
    t.check("interactive shell still alive", r.get("shell_alive"), True, r.get("shell_alive"))
    t.check("no launcher or child process left", r.get("final", {}).get("child") in ("gone",)
            and r.get("final", {}).get("launcher") in ("gone", None) and r.get("leftover_killed") == 0,
            "all gone", {"final": r.get("final"), "leftover_killed": r.get("leftover_killed")})


for _kind in ("bash", "zsh"):
    for _sig in (signal.SIGSTOP, signal.SIGTSTP):
        def _mk(kind, sig):
            def fn(t, ctx):
                pty_stop_check(t, ctx, kind, sig)
            return fn
        check(T, "T1.pty_stop_cont_%s_%s" % (_kind, _sig.name),
              "1b interactive %s, foreground job: third-party %s then SIGCONT of the child PID"
              % (_kind, _sig.name))(_mk(_kind, _sig))


# ------------------------------------------------------------------------------------------- 2
def cont_launcher_once(ctx, kind, binpath):
    sh = Shell(kind)
    r = {"via": "heimdall-proto" if binpath else "plain"}
    c = h = None
    try:
        pf = os.path.join(sh.tmp, "pf")
        pre = "" if binpath is None else "%s run -- " % q(binpath)
        sh.send("%s%s %s %s\n" % (pre, q(PY), q(CHILD_TSTP), q(pf)))
        c = wait_file_int(pf, 6, sh.read)
        if c is None:
            r["error"] = "child pid file not written"
            return r
        h = proc_ppid(c) if binpath else None
        r["ready"] = bool(sh.expect(r"READY-1", 5))
        sh.send("tstp\n")
        r["stop_notice"] = bool(sh.expect(STOPRE, 3))
        r["prompt_after_stop"] = bool(sh.expect(re.escape(PROMPT), 3))
        time.sleep(0.3)
        r["states_stopped"] = {"child": proc_state(c), "launcher": proc_state(h)}
        os.kill(h if binpath else c, signal.SIGCONT)
        time.sleep(2.6)
        sh.read(0.1)
        r["child_resumed"] = "BACK-tstp" in sh.buf
        r["states_after_cont"] = {"child": proc_state(c), "launcher": proc_state(h)}
        r["jobs"] = jobs(sh)
        sh.expect(re.escape(PROMPT), 1)
        sh.send("fg\n")
        time.sleep(0.6)
        sh.send("probe42\n")
        r["child_reads_after_fg"] = bool(sh.expect(r"GOT-probe42", 3))
        sh.send("exit 5\n")
        sh.expect(re.escape(PROMPT), 5)
        r["rc"] = rc_of(sh)
        time.sleep(0.3)
        r["final"] = {"child": proc_state(c), "launcher": proc_state(h)}
    except Exception as e:  # noqa
        r["exception"] = repr(e)
    finally:
        sh.read(0.2)
        r["transcript_tail"] = clean(sh.transcript([(binpath or "\0", "<bin>"), (CHILD_TSTP, "<child>")]), 500)
        r["leftover_killed"] = kill_exact([c, h])
        sh.close()
        subprocess.run(["rm", "-rf", sh.tmp])
    return r


def cont_launcher_check(t, ctx, kind):
    ctl = cont_launcher_once(ctx, kind, None)
    t.note("control: %s" % json.dumps(ctl, ensure_ascii=False))
    t.precondition("control: stop reported, child resumes on SIGCONT, `jobs` says stopped (tty input), fg works",
                   ctl.get("stop_notice") and ctl.get("child_resumed") and ctl.get("jobs", {}).get("stopped")
                   and not ctl.get("jobs", {}).get("running") and ctl.get("child_reads_after_fg")
                   and ctl.get("rc") == 5, ctl)
    r = cont_launcher_once(ctx, kind, ctx.bin)
    t.note("subject: %s" % ctx.scrub(json.dumps(r, ensure_ascii=False)))
    t.check("self-stop reported by the shell", r.get("stop_notice"), True, r.get("stop_notice"))
    t.check("SIGCONT to the launcher PID resumes the child (it prints BACK)", r.get("child_resumed"), True,
            {"resumed": r.get("child_resumed"), "states": r.get("states_after_cont")})
    t.check("`jobs` 2.6 s later says stopped, as with plain exec (never running while the child is stopped)",
            r.get("jobs", {}).get("stopped") and not r.get("jobs", {}).get("running"), "stopped", r.get("jobs"))
    t.check("`fg` gives the terminal back: the child reads the next line", r.get("child_reads_after_fg"), True,
            r.get("child_reads_after_fg"))
    t.eq("exit status after `exit 5`", r.get("rc"), 5)
    t.check("no launcher or child process left", r.get("leftover_killed") == 0 and
            r.get("final", {}).get("child") == "gone", "all gone",
            {"final": r.get("final"), "leftover_killed": r.get("leftover_killed")})


for _kind in ("bash", "zsh"):
    def _mk2(kind):
        def fn(t, ctx):
            cont_launcher_check(t, ctx, kind)
        return fn
    check(T, "T1.cont_launcher_only_%s" % _kind,
          "2 interactive %s: child self-stop reported, then SIGCONT sent only to the launcher PID" % _kind)(_mk2(_kind))


# ------------------------------------------------------------------------------------------- 3
def nested_once(ctx, kind, binpath):
    sh = Shell(kind)
    r = {"via": "heimdall-proto" if binpath else "plain"}
    n = h = None
    try:
        pre = "" if binpath is None else "%s run -- " % q(binpath)
        sh.send("%sbash --norc --noprofile -i\n" % pre)
        time.sleep(1.0)
        sh.send("PS1='@N@ '; W=nested\n")
        r["nested_prompt"] = bool(sh.expect(r"@N@ ", 4))
        sh.send("echo NPID=$$\n")
        m = sh.expect(r"NPID=(\d+)", 3)
        n = int(m.group(1)) if m else None
        h = proc_ppid(n) if (binpath and n) else None
        sh.expect(r"@N@ ", 2)
        sh.send("suspend\n")
        r["stop_notice"] = bool(sh.expect(STOPRE, 3))
        r["outer_prompt"] = bool(sh.expect(re.escape(PROMPT), 2))
        time.sleep(0.5)
        sh.read(0.1)
        r["outer_alive_after_suspend"] = sh.alive() and not sh.eof
        r["after_suspend"] = {"nested": proc_state(n), "launcher": proc_state(h)}
        if r["outer_prompt"] and r["outer_alive_after_suspend"]:
            sh.send("fg\n")
            time.sleep(1.0)
            sh.read(0.1)
            sh.mark = len(sh.buf)
            sh.send("echo ALIVE-$W-$((40+2))\n")
            m = sh.expect(r"ALIVE-(nested)?-42", 3)
            r["answer_after_fg"] = ("nested" if m.group(1) else "outer") if m else "none"
            if r["answer_after_fg"] == "nested":
                sh.expect(r"@N@ ", 2)
                sh.send("exit 3\n")
                sh.expect(re.escape(PROMPT), 4)
                r["outer_rc_after_nested_exit_3"] = rc_of(sh)
        r["outer_alive_end"] = sh.alive() and not sh.eof
        time.sleep(0.3)
        r["final"] = {"nested": proc_state(n), "launcher": proc_state(h)}
    except Exception as e:  # noqa
        r["exception"] = repr(e)
    finally:
        sh.read(0.2)
        r["transcript_tail"] = clean(sh.transcript([(binpath or "\0", "<bin>")]), 500)
        r["leftover_killed"] = kill_exact([n, h])
        sh.close()
        subprocess.run(["rm", "-rf", sh.tmp])
    return r


def nested_check(t, ctx, kind):
    ctl = nested_once(ctx, kind, None)
    t.note("control: %s" % json.dumps(ctl, ensure_ascii=False))
    t.precondition("control: stop notice, outer prompt, nested shell answers after fg, exit 3 seen",
                   ctl.get("stop_notice") and ctl.get("outer_prompt") and ctl.get("answer_after_fg") == "nested"
                   and ctl.get("outer_rc_after_nested_exit_3") == 3, ctl)
    r = nested_once(ctx, kind, ctx.bin)
    t.note("subject: %s" % ctx.scrub(json.dumps(r, ensure_ascii=False)))
    t.check("`suspend` in the nested shell: stop notice", r.get("stop_notice"), True, r.get("stop_notice"))
    t.check("outer shell prompt returns and the outer shell survives",
            r.get("outer_prompt") and r.get("outer_alive_after_suspend"), True,
            {"prompt": r.get("outer_prompt"), "alive": r.get("outer_alive_after_suspend")})
    t.eq("after `fg` the nested shell answers", r.get("answer_after_fg"), "nested")
    t.eq("outer $? after `exit 3` in the nested shell", r.get("outer_rc_after_nested_exit_3"), 3)
    t.check("no nested shell or launcher left", r.get("leftover_killed") == 0, "none left",
            {"final": r.get("final"), "leftover_killed": r.get("leftover_killed")})


for _kind in ("bash", "zsh"):
    def _mk3(kind):
        def fn(t, ctx):
            nested_check(t, ctx, kind)
        return fn
    check(T, "T1.nested_shell_%s" % _kind,
          "3 outer %s runs `run -- bash -i`; `suspend` in it, then `fg`" % _kind)(_mk3(_kind))


# ------------------------------------------------------------------------------------------- 4
def sigstop_once(ctx, kind, binpath, trigger):
    sh = Shell(kind)
    r = {"via": "heimdall-proto" if binpath else "plain", "trigger": trigger}
    c = h = None
    log = os.path.join(sh.tmp, "c.log")
    meta = os.path.join(sh.tmp, "meta.json")
    try:
        pre = "" if binpath is None else "%s run --meta-file %s -- " % (q(binpath), q(meta))
        sh.send("%s%s %s %s read SIGSTOP\n" % (pre, q(PY), q(CHILD_READ), q(log)))
        end = time.time() + 8
        start = None
        while time.time() < end and not start:
            sh.read(0.05)
            try:
                start = re.search(r"^START pid=(\d+) ppid=(\d+)", open(log).read(), re.M)
            except OSError:
                pass
        if not start:
            r["error"] = "child did not start"
            return r
        c = int(start.group(1))
        h = int(start.group(2)) if binpath else None
        sh.read(0.5)
        m0 = len(sh.buf)
        if trigger == "ext":
            os.kill(c, signal.SIGSTOP)
        else:
            sh.send("~z\n")
        states = []
        for _ in range(12):
            sh.read(0.25)
            states.append((proc_state(c), proc_state(h)))
        r["states"] = sorted(set("%s/%s" % s for s in states))
        r["child_stopped_throughout"] = all(s[0] == "T" for s in states[2:])
        r["launcher_alive_throughout"] = binpath is None or all(s[1] not in ("gone", None) for s in states)
        r["stop_reported"] = bool(re.search(STOPRE, sh.buf[m0:]))
        r["rc_after_stop"] = rc_of(sh)
        sh.expect(re.escape(PROMPT), 2)
        sh.send("fg\n")
        time.sleep(0.6)
        sh.send("hello42\n")
        end = time.time() + 3
        got = False
        while time.time() < end and not got:
            sh.read(0.1)
            try:
                got = "GOT hello42" in open(log).read()
            except OSError:
                pass
        r["child_reads_after_fg"] = got
        sh.send("quit\n")
        sh.expect(re.escape(PROMPT), 5)
        r["rc_after_quit"] = rc_of(sh, "RC2")
        time.sleep(0.3)
        if binpath:
            try:
                r["meta"] = json.load(open(meta))
            except (OSError, ValueError) as e:
                r["meta"] = "unreadable: %s" % type(e).__name__
        r["final"] = {"child": proc_state(c), "launcher": proc_state(h)}
    except Exception as e:  # noqa
        r["exception"] = repr(e)
    finally:
        sh.read(0.2)
        r["transcript_tail"] = clean(sh.transcript([(binpath or "\0", "<bin>"), (CHILD_READ, "<child>")]), 500)
        r["leftover_killed"] = kill_exact([c, h])
        sh.close()
        subprocess.run(["rm", "-rf", sh.tmp])
    return r


def sigstop_check(t, ctx, kind, trigger):
    ctl = sigstop_once(ctx, kind, None, trigger)
    t.note("control: %s" % json.dumps(ctl, ensure_ascii=False))
    t.precondition("control: stop reported, child stays stopped, fg resumes it, quit gives $? 0",
                   ctl.get("stop_reported") and ctl.get("child_stopped_throughout") and ctl.get("child_reads_after_fg")
                   and ctl.get("rc_after_quit") == 0, ctl)
    r = sigstop_once(ctx, kind, ctx.bin, trigger)
    t.note("subject: %s" % ctx.scrub(json.dumps(r, ensure_ascii=False)))
    t.check("shell reports the job stopped", r.get("stop_reported"), True, r.get("stop_reported"))
    t.eq("$? after the stop equals plain exec's (%s)" % ctl.get("rc_after_stop"), r.get("rc_after_stop"),
         ctl.get("rc_after_stop"))
    t.check("child stays stopped and the launcher stays alive until `fg`",
            r.get("child_stopped_throughout") and r.get("launcher_alive_throughout"), True, r.get("states"))
    t.check("after `fg` the child reads the terminal again", r.get("child_reads_after_fg"), True,
            r.get("child_reads_after_fg"))
    t.eq("$? after the child's normal exit", r.get("rc_after_quit"), 0)
    meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
    t.eq("meta file: code", meta.get("code"), "CHILD_EXITED")
    t.eq("meta file: data", meta.get("data"), {"launched": True, "exit_code": 0, "signal": None})
    t.check("no launcher or child process left", r.get("leftover_killed") == 0, "none left",
            {"final": r.get("final"), "leftover_killed": r.get("leftover_killed")})


for _kind in ("bash", "zsh"):
    for _trig in ("read", "ext"):
        def _mk4(kind, trig):
            def fn(t, ctx):
                sigstop_check(t, ctx, kind, trig)
            return fn
        check(T, "T1.sigstop_meta_%s_%s" % (_kind, _trig),
              "4 interactive %s, run --meta-file: the child is stopped by SIGSTOP (%s)"
              % (_kind, "it stops itself" if _trig == "read" else "a third party stops it"))(_mk4(_kind, _trig))
