#!/usr/bin/env python3
"""Independent probes for heimdall-proto run (reviewer-owned, disposable). macOS host, no tty."""
import hashlib, json, os, signal, subprocess, sys, tempfile, time

BIN = sys.argv[1]
OUT = sys.argv[2]
PY = sys.executable
results = []
ENV = {"PATH": "/usr/bin:/bin:" + os.path.dirname(PY), "HOME": tempfile.mkdtemp(prefix="hr home "), "LANG": "C.UTF-8"}


def rec(r):
    results.append(r)
    print(json.dumps(r, ensure_ascii=False)[:400])


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


# 1. stdin EOF propagation + binary passthrough
data = bytes(range(256)) * 4096  # 1 MiB incl NUL, invalid UTF-8
p = subprocess.run([BIN, "run", "--", "/bin/cat"], input=data, capture_output=True, env=ENV, timeout=30)
rec({"case": "stdin_eof_and_binary_roundtrip_1MiB", "exit_code": p.returncode, "out_sha_equal": hashlib.sha256(p.stdout).hexdigest() == hashlib.sha256(data).hexdigest(), "stderr_len": len(p.stderr), "verdict": "pass" if p.returncode == 0 and p.stdout == data and not p.stderr else "fail"})
p = subprocess.run([BIN, "run", "--", "/bin/sh", "-c", "cat >/dev/null; echo eof-seen"], stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=10)
rec({"case": "stdin_devnull_eof", "exit_code": p.returncode, "stdout": p.stdout.decode(), "verdict": "pass" if p.returncode == 0 and p.stdout == b"eof-seen\n" else "fail"})

# 2. large stderr while stdout is blocked (two writer threads in child)
child = r'''
import os, threading
N = 4*1024*1024
def w(fd, b):
    v = memoryview(b)
    while v:
        n = os.write(fd, v); v = v[n:]
a = threading.Thread(target=w, args=(1, b"O"*N)); b = threading.Thread(target=w, args=(2, b"E"*N))
a.start(); b.start(); a.join(); b.join()
'''
for label, argv in (("direct", [PY, "-c", child]), ("via_heimdall", [BIN, "run", "--", PY, "-c", child])):
    t0 = time.monotonic()
    pr = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    # read ALL of stderr first while stdout is left unread (blocked after the pipe buffer fills)
    err = b""
    deadline = time.monotonic() + 20
    os.set_blocking(pr.stderr.fileno(), True)
    while len(err) < 4 * 1024 * 1024 and time.monotonic() < deadline:
        chunk = os.read(pr.stderr.fileno(), 1 << 16)
        if not chunk:
            break
        err += chunk
    t_err = time.monotonic() - t0
    out = pr.stdout.read()
    pr.wait(timeout=20)
    rec({"case": "large_stderr_while_stdout_blocked_" + label, "exit_code": pr.returncode, "stderr_bytes": len(err), "stdout_bytes": len(out), "stderr_complete_s": round(t_err, 3), "verdict": "pass" if pr.returncode == 0 and len(err) == 4 * 1024 * 1024 and len(out) == 4 * 1024 * 1024 else "fail"})

# 3. exit status mapping + meta
d = tempfile.mkdtemp(prefix="hr meta ü ")
for name, argv, want_rc, want_meta in (
    ("exit_0", ["/bin/sh", "-c", "exit 0"], 0, {"launched": True, "exit_code": 0, "signal": None}),
    ("exit_255", ["/bin/sh", "-c", "exit 255"], 255, {"launched": True, "exit_code": 255, "signal": None}),
    ("sigkill_self", ["/bin/sh", "-c", "kill -KILL $$"], 137, {"launched": True, "exit_code": None, "signal": 9}),
    ("sigsegv_self", ["/bin/sh", "-c", "kill -SEGV $$"], 139, {"launched": True, "exit_code": None, "signal": 11}),
    ("not_found", ["heimdall-review-nonexistent-ü"], 127, {"launched": False, "exit_code": None, "signal": None}),
    ("not_executable", ["/etc/hosts"], 127, {"launched": False, "exit_code": None, "signal": None}),
    ("directory", ["/tmp"], 127, {"launched": False, "exit_code": None, "signal": None}),
):
    m = os.path.join(d, name + " meta.json")
    p = subprocess.run([BIN, "run", "--meta-file", m, "--", *argv], capture_output=True, env=ENV, timeout=10)
    meta = json.load(open(m)) if os.path.exists(m) else None
    ok = p.returncode == want_rc and meta is not None and meta["data"] == want_meta and p.stdout == b""
    rec({"case": "status_" + name, "exit_code": p.returncode, "meta_code": meta and meta["code"], "meta_state": meta and meta["state"], "meta_data": meta and meta["data"], "stdout_len": len(p.stdout), "verdict": "pass" if ok else "fail"})

# 3b. meta file edge cases
p = subprocess.run([BIN, "run", "--meta-file", os.path.join(d, "no such dir", "m.json"), "--", "/bin/sh", "-c", "echo side-effect > \"$0\"", os.path.join(d, "side effect.txt")], capture_output=True, env=ENV, timeout=10)
rec({"case": "meta_unwritable_dir_detected_only_after_child_ran", "exit_code": p.returncode, "child_side_effect_happened": os.path.exists(os.path.join(d, "side effect.txt")), "stderr": p.stderr.decode()[-120:], "observation": "exit code is the child's (0) although the requested meta file was not written"})
fifo = os.path.join(d, "meta fifo")
os.mkfifo(fifo)
try:
    p = subprocess.run([BIN, "run", "--meta-file", fifo, "--", "/usr/bin/true"], capture_output=True, env=ENV, timeout=3)
    rec({"case": "meta_file_is_fifo_no_reader", "exit_code": p.returncode, "hung": False})
except subprocess.TimeoutExpired as e:
    rec({"case": "meta_file_is_fifo_no_reader", "exit_code": None, "hung": True, "observation": "blocked >3 s opening FIFO meta path after the child exited (killed by subprocess timeout)"})
target = os.path.join(d, "symlink target.txt")
open(target, "w").write("original\n")
link = os.path.join(d, "meta link")
os.symlink(target, link)
p = subprocess.run([BIN, "run", "--meta-file", link, "--", "/usr/bin/true"], capture_output=True, env=ENV, timeout=10)
rec({"case": "meta_file_symlink_followed", "exit_code": p.returncode, "target_overwritten": open(target).read() != "original\n", "link_still_symlink": os.path.islink(link)})

# 4. inherited signal dispositions (macOS: python reports inherited SIG_IGN)
probe = "import signal;print(int(signal.getsignal(signal.SIGHUP)==signal.SIG_IGN),int(signal.getsignal(signal.SIGINT)==signal.SIG_IGN),int(signal.getsignal(signal.SIGQUIT)==signal.SIG_IGN),int(signal.getsignal(signal.SIGTERM)==signal.SIG_IGN))"


def ign_pre():
    for s_ in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(s_, signal.SIG_IGN)


direct = subprocess.run([PY, "-c", probe], capture_output=True, env=ENV, preexec_fn=ign_pre).stdout.decode().strip()
via = subprocess.run([BIN, "run", "--", PY, "-c", probe], capture_output=True, env=ENV, preexec_fn=ign_pre)
rec({"case": "inherited_SIG_IGN_HUP_INT_QUIT_TERM_preserved", "direct_HUP_INT_QUIT_TERM_ignored": direct, "via_heimdall": via.stdout.decode().strip(), "exit_code": via.returncode, "verdict": "pass" if direct == via.stdout.decode().strip() else "fail"})

# 4b. nohup-style: parent ignores SIGHUP, then SIGHUP is sent to heimdall-proto's pid
sf = os.path.join(d, "hup_child_alive")
child = f"import time,os;open({sf!r},'w').write(str(os.getpid()));time.sleep(1.5);open({sf!r}+'.done','w').write('survived')"
pr = subprocess.Popen([BIN, "run", "--", PY, "-c", child], env=ENV, preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(0.5)
pr.send_signal(signal.SIGHUP)
pr.wait(timeout=10)
rec({"case": "nohup_style_SIGHUP_ignored_by_caller", "exit_code": pr.returncode, "child_survived": os.path.exists(sf + ".done"), "expected_for_transparent_wrapper": "child survives (SIGHUP ignored, as with direct exec)", "verdict": "pass" if os.path.exists(sf + ".done") and pr.returncode == 0 else "fail"})

# 5. explicit-signal race sweep (no tty): TERM to heimdall-proto pid at 0..24 ms; child counts TERMs
sweep = []
for i in range(25):
    cf = os.path.join(d, f"cnt{i}")
    child = f"""import signal,os,time,sys
c=[0]
def h(s,f): c[0]+=1
signal.signal(signal.SIGTERM,h)
open({cf!r}+'.pid','w').write(str(os.getpid()))
t=time.time()
while time.time()-t<0.6: time.sleep(0.01)
open({cf!r},'w').write(str(c[0]))
sys.exit(3)"""
    pr = subprocess.Popen([BIN, "run", "--", PY, "-c", child], env=ENV, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(i / 1000)
    pr.send_signal(signal.SIGTERM)
    pr.wait(timeout=10)
    cpid = int(open(cf + ".pid").read()) if os.path.exists(cf + ".pid") else None
    time.sleep(0.05)
    sweep.append({"delay_ms": i, "exit_code": pr.returncode, "child_count": open(cf).read() if os.path.exists(cf) else None, "child_pid_written": cpid is not None, "child_alive_after_parent_exit": bool(cpid and alive(cpid))})
bad = [x for x in sweep if x["child_alive_after_parent_exit"] or x["child_count"] not in (None, "1") or (x["child_count"] == "1" and x["exit_code"] != 3)]
rec({"case": "sigterm_race_sweep_no_tty", "n": len(sweep), "outcomes": sorted(set((x["exit_code"], x["child_count"]) for x in sweep), key=str), "bad": bad, "verdict": "pass" if not bad else "fail"})

# 6. process-group semantics (no tty): killpg on heimdall-proto's group
for sig in (signal.SIGTERM, signal.SIGKILL):
    pf = os.path.join(d, f"pg_{sig.name}")
    child = f"import os,time,signal;signal.signal(signal.SIGTERM,lambda *a:(open({pf!r}+'.term','a').write('x'),os._exit(7)));open({pf!r},'w').write(str(os.getpid())+' '+str(os.getpgrp()));time.sleep(5)"
    pr = subprocess.Popen([BIN, "run", "--", PY, "-c", child], env=ENV, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        if os.path.exists(pf):
            break
        time.sleep(0.02)
    time.sleep(0.1)
    cpid, cpg = map(int, open(pf).read().split())
    hp_pg = os.getpgid(pr.pid)
    os.killpg(hp_pg, sig)
    pr.wait(timeout=10)
    time.sleep(0.2)
    still = alive(cpid)
    terms = open(pf + ".term").read() if os.path.exists(pf + ".term") else ""
    rec({"case": f"killpg_{sig.name}_on_heimdall_group", "heimdall_pgid_eq_pid": hp_pg == pr.pid, "child_in_own_pgid": cpg == cpid, "exit_code": pr.returncode, "child_terms_received": len(terms), "child_alive_after": still})
    if still:
        # reviewer cleanup: exact pid verified as the child we started (pid file written by it, pgid matches)
        if os.getpgid(cpid) == cpg:
            os.kill(cpid, signal.SIGKILL)
            rec({"case": f"cleanup_orphan_{sig.name}", "killed_pid_verified_by_pidfile_and_pgid": True})

# 7. K7 observation: empty PATH entry resolves to cwd
wd = tempfile.mkdtemp(prefix="hr k7 ")
open(os.path.join(wd, "hrk7tool"), "w").write("#!/bin/sh\necho ran-from-cwd\n")
os.chmod(os.path.join(wd, "hrk7tool"), 0o755)
e2 = dict(ENV, PATH="/usr/bin::/bin")
p = subprocess.run([BIN, "run", "--", "hrk7tool"], capture_output=True, env=e2, cwd=wd, timeout=10)
rec({"case": "k7_empty_path_entry_observation", "exit_code": p.returncode, "stdout": p.stdout.decode().strip()})

json.dump(results, open(OUT, "w"), indent=1, ensure_ascii=False)
fails = [r["case"] for r in results if r.get("verdict") == "fail"]
print("FAILS:", fails)
sys.exit(1 if fails else 0)
