#!/usr/bin/env python3
"""Reviewer-2 probes for `heimdall-proto run` beyond the shared harness (darwin + Linux).

Usage: run_probe.py BIN OUT.json
Every case records the real exit status and observations. Disposable temp dirs only.
"""
import json, os, signal, subprocess, sys, tempfile, time, shutil

BIN = os.path.abspath(sys.argv[1])
OUT = sys.argv[2]
PY = sys.executable
results = []
TMP = tempfile.mkdtemp(prefix="hp-rv2-run-")


def rec(name, **kw):
    kw["case"] = name
    results.append(kw)
    print(json.dumps(kw), flush=True)


def status_of(rc):
    return {"returncode": rc}


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def wait_file(path, timeout=5.0):
    t = time.time() + timeout
    while time.time() < t:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
        time.sleep(0.01)
    return False


# Child script: writes its pid/pgid, counts signals, exits on demand.
COUNTER = r'''
import os, signal, sys, time
out = sys.argv[1]
sigs = [int(x) for x in sys.argv[2].split(",")]
hold = float(sys.argv[3])
counts = {s: 0 for s in sigs}
def h(n, f):
    counts[n] += 1
for s in sigs:
    signal.signal(s, h)
with open(out + ".pid", "w") as f:
    f.write("%d %d %d" % (os.getpid(), os.getpgrp(), os.getppid()))
end = time.time() + hold
while time.time() < end:
    time.sleep(0.02)
with open(out, "w") as f:
    f.write(",".join("%d=%d" % (k, v) for k, v in counts.items()))
'''
cfile = os.path.join(TMP, "counter.py")
open(cfile, "w").write(COUNTER)


def counter_case(name, sig, hold=1.5, extra_env=None, deliver_to="parent"):
    out = os.path.join(TMP, name)
    p = subprocess.Popen([BIN, "run", "--", PY, cfile, out, str(int(sig)), str(hold)],
                         stdin=subprocess.DEVNULL, start_new_session=True,
                         env=dict(os.environ, **(extra_env or {})))
    ok = wait_file(out + ".pid")
    cpid, cpgid, cppid = (int(x) for x in open(out + ".pid").read().split())
    time.sleep(0.1)
    if deliver_to == "parent":
        os.kill(p.pid, sig)
    elif deliver_to == "group":
        os.killpg(os.getpgid(p.pid), sig)
    rc = p.wait(timeout=10)
    counts = open(out).read() if os.path.exists(out) else None
    rec(name, sig=int(sig), deliver_to=deliver_to, exit=rc, child_counts=counts,
        child_pgid_eq_parent_pgid=(cpgid == os.getpgid(p.pid) if alive(p.pid) else cpgid == p.pid),
        child_ppid_is_hp=(cppid == p.pid), child_alive_after=alive(cpid))


# 1. explicit signals to heimdall-proto PID: each reaches child exactly once
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
    counter_case("explicit_%s" % s.name, s)
# 2. killpg from another process (K6b: may be twice, recorded)
for s in (signal.SIGINT, signal.SIGTERM):
    counter_case("killpg_%s" % s.name, s, deliver_to="group")

# 3. signals heimdall-proto does NOT handle: does heimdall-proto die and orphan the child?
for s in (signal.SIGUSR1, signal.SIGUSR2, signal.SIGALRM):
    out = os.path.join(TMP, "unhandled_" + s.name)
    p = subprocess.Popen([BIN, "run", "--", "sleep", "3"], start_new_session=True,
                         stdin=subprocess.DEVNULL)
    time.sleep(0.3)
    # find child of p via pgrep -P (pgrep exists on macOS and procps)
    try:
        kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
    except FileNotFoundError:
        kids = [l.split()[0] for l in open("/proc/%d/task/%d/children" % (p.pid, p.pid)).read().split()] if os.path.exists("/proc") else []
    os.kill(p.pid, s)
    rc = p.wait(timeout=5)
    time.sleep(0.1)
    orphans = [int(k) for k in kids if alive(int(k))]
    rec("unhandled_" + s.name, exit=rc, child_pids=kids, child_still_running_after_hp_exit=bool(orphans))
    for k in orphans:
        os.kill(k, signal.SIGKILL)

# 4. SIGKILL to heimdall-proto: child orphaned? (no PDEATHSIG / no supervisor)
p = subprocess.Popen([BIN, "run", "--", "sleep", "3"], start_new_session=True, stdin=subprocess.DEVNULL)
time.sleep(0.3)
try:
    kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
except FileNotFoundError:
    kids = open("/proc/%d/task/%d/children" % (p.pid, p.pid)).read().split()
os.kill(p.pid, signal.SIGKILL)
rc = p.wait(timeout=5)
time.sleep(0.1)
orph = [int(k) for k in kids if alive(int(k))]
rec("sigkill_hp_pid", exit=rc, child_pids=kids, child_still_running=bool(orph))
for k in orph:
    os.kill(k, signal.SIGKILL)

# 5. nohup / trap '' HUP INT: inherited ignores reach child, and kill -HUP hp is not forwarded
SH = "/bin/sh"
script = ("trap '' HUP INT; exec %s run -- %s -c "
          "'import signal,os,time; print([int(signal.getsignal(s)==signal.SIG_IGN) for s in (1,2,3,15,13)], flush=True); time.sleep(1.0); print(\"survived\")'" % (BIN, PY))
p = subprocess.Popen([SH, "-c", script], stdout=subprocess.PIPE, text=True, start_new_session=True)
time.sleep(0.5)
os.kill(p.pid, signal.SIGHUP)
os.kill(p.pid, signal.SIGINT)
o, _ = p.communicate(timeout=10)
rec("inherited_ignore_hup_int", exit=p.returncode, stdout=o.strip(),
    note="list = ignored flags for HUP,INT,QUIT,TERM,PIPE in child")

# nohup with real nohup binary
nh = shutil.which("nohup")
if nh:
    p = subprocess.Popen([nh, BIN, "run", "--", PY, "-c",
                          "import signal,os,time; os.kill(os.getpid(),1); time.sleep(0.2); print('survived', flush=True)"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, cwd=TMP)
    o, e = p.communicate(timeout=10)
    rec("nohup_child_self_hup", exit=p.returncode, stdout=o.strip())

# 6. background job of non-interactive shell: SIGINT/SIGQUIT ignored in child (sh & semantics)
script = ("%s run -- %s -c 'import signal; print([int(signal.getsignal(s)==signal.SIG_IGN) for s in (2,3)])' & wait" % (BIN, PY))
o = subprocess.run([SH, "-c", script], capture_output=True, text=True, start_new_session=True)
rec("amp_job_int_quit_ignored", exit=o.returncode, stdout=o.stdout.strip())

# 7. caller-blocked signal mask (K6c observation)
code = ("import signal,os,sys; signal.pthread_sigmask(signal.SIG_BLOCK,[signal.SIGUSR1]); "
        "os.execv(sys.argv[1], [sys.argv[1],'run','--',sys.argv[2],'-c','import signal; print(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])))'])")
o = subprocess.run([PY, "-c", code, BIN, PY], capture_output=True, text=True)
rec("blocked_mask_in_child", exit=o.returncode, stdout=o.stdout.strip(), note="caller blocked SIGUSR1 (30 darwin / 10 linux)")

# 8. HANDLED signals not blocked in child (main() blocks them early)
o = subprocess.run([BIN, "run", "--", PY, "-c", "import signal; print(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, [])))"], capture_output=True, text=True)
rec("child_mask_no_leak_from_block_early", exit=o.returncode, stdout=o.stdout.strip())

# 9. hp waits for child that traps TERM and keeps running
out = os.path.join(TMP, "trapterm")
p = subprocess.Popen([BIN, "run", "--", SH, "-c", "trap 'echo got >> %s' TERM; sleep 1 & wait; sleep 0.5; echo done >> %s; exit 7" % (out, out)],
                     start_new_session=True)
time.sleep(0.3)
t0 = time.time()
os.kill(p.pid, signal.SIGTERM)
rc = p.wait(timeout=10)
rec("waits_for_child_trapping_term", exit=rc, elapsed_after_term_s=round(time.time() - t0, 3),
    child_log=open(out).read().split() if os.path.exists(out) else None)

# 10. stdin EOF + large binary passthrough both ways, child exits early on closed stdout
import hashlib
data = os.urandom(8 * 1024 * 1024) + b"\x00\xff\xfe"
p = subprocess.run([BIN, "run", "--", "cat"], input=data, capture_output=True)
rec("binary_8mib_roundtrip", exit=p.returncode, equal=(p.stdout == data), stderr_len=len(p.stderr))
# stdin EOF reaches child (cat terminates) with stdin from /dev/null
p = subprocess.run([BIN, "run", "--", "cat"], stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
rec("stdin_devnull_eof", exit=p.returncode, out_len=len(p.stdout))
# SIGPIPE: child writing into a closed pipe dies by SIGPIPE like under a shell
o = subprocess.run([SH, "-c", "%s run --meta-file %s/m.json -- yes | head -n 1 >/dev/null; echo ${PIPESTATUS:-x}" % (BIN, TMP)], capture_output=True, text=True)
meta = open(os.path.join(TMP, "m.json")).read().strip() if os.path.exists(os.path.join(TMP, "m.json")) else None
rec("child_sigpipe_default", exit=o.returncode, meta=meta)
# backpressure: slow reader, fast writer, nothing lost
p = subprocess.Popen([BIN, "run", "--", PY, "-c", "import sys; sys.stdout.buffer.write(b'x'*(4*1024*1024)); sys.stdout.flush()"], stdout=subprocess.PIPE)
got = 0
while True:
    b = p.stdout.read(4096)
    if not b:
        break
    got += len(b)
    if got < 65536:
        time.sleep(0.001)
rc = p.wait()
rec("backpressure_4mib_slow_reader", exit=rc, bytes=got)

# 11. zombie check: child exits; hp exits; no zombie left under hp (hp itself reaped by us)
p = subprocess.Popen([BIN, "run", "--", SH, "-c", "sleep 0.2 & exit 3"], start_new_session=True)
rc = p.wait()
rec("exit_status_passthrough_with_grandchild", exit=rc)

# 12. meta file: path with spaces and non-ASCII; FIFO without reader
mpath = os.path.join(TMP, "dir é 東", "meta file.json")
os.makedirs(os.path.dirname(mpath))
p = subprocess.run([BIN, "run", "--meta-file", mpath, "--", SH, "-c", "kill -TERM $$"], capture_output=True)
rec("meta_unicode_path_signal", exit=p.returncode, meta=open(mpath).read().strip())
fifo = os.path.join(TMP, "fifo")
os.mkfifo(fifo)
t0 = time.time()
p = subprocess.run([BIN, "run", "--meta-file", fifo, "--", "true"], capture_output=True, timeout=10)
rec("meta_fifo_no_reader", exit=p.returncode, elapsed_s=round(time.time() - t0, 3), stderr=p.stderr.decode(errors="replace")[:200])

# 13. RUST_MIN_STACK (std env var) impact on run: forwarder thread spawn
for v in ("1", "999999999999999"):
    p = subprocess.Popen([BIN, "run", "--", "sleep", "1.5"], env=dict(os.environ, RUST_MIN_STACK=v),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    time.sleep(0.5)
    try:
        kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
    except FileNotFoundError:
        kids = []
    o, e = p.communicate(timeout=10)
    rec("rust_min_stack_" + v[:6], exit=p.returncode, stderr=e.decode(errors="replace")[:300],
        kids_at_0_5s=kids)

# 14. launch failure: not executable, directory, missing
nx = os.path.join(TMP, "notexec")
open(nx, "w").write("#!/bin/sh\necho hi\n")
for name, argv in (("missing", ["heimdall-no-such-prog-ü"]), ("notexec", [nx]), ("dir", [TMP])):
    mp = os.path.join(TMP, "meta-" + name)
    p = subprocess.run([BIN, "run", "--meta-file", mp, "--"] + argv, capture_output=True)
    rec("launch_fail_" + name, exit=p.returncode, stdout_len=len(p.stdout), meta=open(mp).read().strip())

# 15. pgrp: child in same pgrp as hp (exec semantics), and hp never calls tcsetpgrp (no tty here)
out = os.path.join(TMP, "pg")
p = subprocess.Popen([BIN, "run", "--", PY, "-c", "import os; open('%s','w').write('%%d %%d' %% (os.getpgrp(), os.getsid(0)))" % out], start_new_session=True)
p.wait()
pg, sid = open(out).read().split()
rec("child_same_pgrp_and_session", exit=p.returncode, child_pgrp=int(pg), hp_pid=p.pid, same=(int(pg) == p.pid and int(sid) == p.pid))

json.dump({"bin": BIN, "platform": sys.platform, "results": results}, open(OUT, "w"), indent=1)
shutil.rmtree(TMP, ignore_errors=True)
