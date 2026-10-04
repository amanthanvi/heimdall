#!/usr/bin/env python3
"""Reviewer's `run` probes (M00-T05-review-go). Stdlib only, no tty.

Usage: run_probe.py <bin> <out-json>
"""
import json, os, signal, subprocess, sys, tempfile, threading, time, random

BIN, OUT = sys.argv[1], sys.argv[2]
SH = "/bin/sh"
res = []


def rec(name, ok, **kw):
    kw.update(case=name, ok=bool(ok))
    res.append(kw)
    print(("OK   " if ok else "FAIL ") + name + " " + json.dumps({k: v for k, v in kw.items() if k not in ("case", "ok")})[:400], flush=True)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def pstate(pid):
    try:
        return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    except Exception:
        return "?"


tmp = tempfile.mkdtemp(prefix="hrg-run-")
env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "TMPDIR": tmp, "LANG": "C.UTF-8"}

# 1 stdin EOF propagation
t0 = time.monotonic()
p = subprocess.run([BIN, "run", "--", "cat"], input=b"abc\x00\xff", capture_output=True, env=env, timeout=10)
rec("stdin_eof_cat", p.returncode == 0 and p.stdout == b"abc\x00\xff", rc=p.returncode, out=p.stdout.hex(), s=round(time.monotonic() - t0, 3))

# 2 child sees EOF on stdin when stdin is /dev/null
p = subprocess.run([BIN, "run", "--", SH, "-c", "if read x; then exit 9; else exit 4; fi"], stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=10)
rec("stdin_devnull_eof", p.returncode == 4, rc=p.returncode)

# 3 large stderr while stdout is not being read
pp = subprocess.Popen([BIN, "run", "--", SH, "-c", "head -c 3000000 /dev/zero >&2; head -c 300000 /dev/zero; echo end >&2"],
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
errbuf = bytearray()
def rd():
    while True:
        b = pp.stderr.read(65536)
        if not b:
            break
        errbuf.extend(b)
th = threading.Thread(target=rd); th.start()
time.sleep(1.0)  # stdout not read during this period
outb = pp.stdout.read()
pp.wait(20); th.join(5)
rec("large_stderr_stdout_blocked", pp.returncode == 0 and len(errbuf) == 3000004 and len(outb) == 300000,
    rc=pp.returncode, err=len(errbuf), out=len(outb))

# 4 grandchild holding stdout must not delay heimdall exit
t0 = time.monotonic()
pp = subprocess.Popen([BIN, "run", "--", SH, "-c", "sleep 3 & echo $! > " + tmp + "/gc.pid; exit 6"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
rc = pp.wait(10)
el = time.monotonic() - t0
gc = int(open(tmp + "/gc.pid").read())
rec("exit_not_delayed_by_grandchild", rc == 6 and el < 1.5, rc=rc, s=round(el, 3))
pp.stdout.close(); pp.stderr.close()

# 5 SIGPIPE child
p = subprocess.run(SH + " -c '" + BIN + " run --meta-file " + tmp + "/m5.json -- yes | head -c 5 >/dev/null; echo ${PIPESTATUS:-x}'", shell=True, capture_output=True, env=env, timeout=10)
meta = json.load(open(tmp + "/m5.json"))
rec("sigpipe_child_meta", meta["data"]["signal"] == 13, meta=meta["data"])

# 6 SIGTERM race right after spawn: never heimdall killed by signal, child never orphaned
script = 'echo $$ > "$1"; trap "exit 3" TERM; i=0; while [ $i -lt 40 ]; do sleep 0.05; i=$((i+1)); done; exit 0'
bad = []
outcomes = {}
for i in range(60):
    pf = f"{tmp}/c{i}.pid"
    pp = subprocess.Popen([BIN, "run", "--", SH, "-c", script, "x", pf], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    time.sleep(random.choice([0, 0, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05]))
    os.kill(pp.pid, signal.SIGTERM)
    rc = pp.wait(10)
    pp.stderr.close()
    outcomes[rc] = outcomes.get(rc, 0) + 1
    cpid = None
    for _ in range(20):
        if os.path.exists(pf) and open(pf).read().strip():
            cpid = int(open(pf).read()); break
        time.sleep(0.01)
    if rc < 0:
        bad.append(("heimdall_killed_by_signal", i, rc))
    if cpid and alive(cpid) and "Z" not in pstate(cpid):
        time.sleep(0.2)
        if alive(cpid):
            bad.append(("child_alive_after_exit", i, cpid, pstate(cpid)))
            try: os.kill(cpid, signal.SIGKILL)
            except Exception: pass
rec("sigterm_race_60", not bad, outcomes={str(k): v for k, v in outcomes.items()}, bad=bad[:5])

# 7 process group and killpg(SIGKILL) orphan (documented limitation)
pf = tmp + "/pg.pid"
pp = subprocess.Popen([BIN, "run", "--", SH, "-c", 'echo $$ > "$1"; sleep 5', "x", pf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
time.sleep(0.4)
cpid = int(open(pf).read())
hpg = os.getpgid(pp.pid); cpg = os.getpgid(cpid)
os.killpg(hpg, signal.SIGKILL)
pp.wait(5)
time.sleep(0.2)
orphan = alive(cpid)
rec("killpg_sigkill_leaves_child (limitation probe; ok=child survived)", orphan, heimdall_pgid_eq_pid=hpg == pp.pid, child_pgid_eq_child_pid=cpg == cpid, child_alive_after_heimdall_sigkill=orphan)
if orphan:
    os.kill(cpid, signal.SIGKILL)

# 8 killpg(SIGTERM) of heimdall's group reaches child exactly once (by forwarding)
pf = tmp + "/pg2.pid"; cnt = tmp + "/cnt"
open(cnt, "w").close()
pp = subprocess.Popen([BIN, "run", "--", SH, "-c", 'echo $$ > "$1"; trap "echo t >> $2" TERM; i=0; while [ $i -lt 20 ]; do sleep 0.05; i=$((i+1)); done; exit 0', "x", pf, cnt],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
time.sleep(0.4)
os.killpg(os.getpgid(pp.pid), signal.SIGTERM)
rc = pp.wait(10)
n = open(cnt).read().count("t")
rec("killpg_sigterm_once", n == 1 and rc == 0, rc=rc, deliveries=n)

# 9 closed stdout at launch: does the child inherit a closed fd 1 or something else?
p = subprocess.run(SH + " -c '" + BIN + " run -- /bin/sh -c \"echo hi; echo rc=\\$? >&2\" >&-'", shell=True, capture_output=True, env=env, timeout=10)
rec("closed_stdout_inherited (observation)", True, rc=p.returncode, stderr=p.stderr.decode()[:200])
p = subprocess.run(SH + " -c '/bin/sh -c \"echo hi; echo rc=\\$? >&2\" >&-'", shell=True, capture_output=True, env=env, timeout=10)
rec("closed_stdout_control_without_heimdall (observation)", True, rc=p.returncode, stderr=p.stderr.decode()[:200])

# 10 extra inherited fd 3 (observation)
r, w = os.pipe()
os.set_inheritable(w, True)
p = subprocess.run([BIN, "run", "--", SH, "-c", "echo x >&3 && echo fd3-open || echo fd3-closed"], pass_fds=(w,), capture_output=True, env=env, timeout=10) if w == 3 else None
os.close(r); os.close(w)

# 11 unwritable meta-file: child still runs; heimdall exit status
p = subprocess.run([BIN, "run", "--meta-file", "/nonexistent-dir/m.json", "--", SH, "-c", "echo ran >&2; exit 3"], capture_output=True, env=env, timeout=10)
rec("meta_unwritable (observation)", True, rc=p.returncode, stderr=p.stderr.decode()[:200])

# 12 SIGTSTP to heimdall without a tty (observation: not forwarded)
pf = tmp + "/ts.pid"
pp = subprocess.Popen([BIN, "run", "--", SH, "-c", 'echo $$ > "$1"; sleep 1.5; exit 0', "x", pf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
time.sleep(0.3)
os.kill(pp.pid, signal.SIGTSTP)
time.sleep(0.2)
st_h = pstate(pp.pid); cpid = int(open(pf).read()); st_c = pstate(cpid)
os.kill(pp.pid, signal.SIGCONT)
rc = pp.wait(10)
rec("sigtstp_no_tty (observation)", True, heimdall_state=st_h, child_state=st_c, rc=rc)

# 13 env vars that change program identity: GODEBUG=execerrdot=0 lets PATH '.' resolve
d2 = tempfile.mkdtemp(prefix="hrg-dot-")
with open(d2 + "/dotcmd", "w") as f:
    f.write("#!/bin/sh\necho DOT-RAN >&2\nexit 0\n")
os.chmod(d2 + "/dotcmd", 0o755)
e1 = dict(env, PATH=".:/usr/bin:/bin")
p1 = subprocess.run([BIN, "run", "--", "dotcmd"], capture_output=True, env=e1, cwd=d2, timeout=10)
e2 = dict(e1, GODEBUG="execerrdot=0")
p2 = subprocess.run([BIN, "run", "--", "dotcmd"], capture_output=True, env=e2, cwd=d2, timeout=10)
rec("godebug_execerrdot (observation)", True, default_rc=p1.returncode, default_err=p1.stderr.decode()[:120], godebug_rc=p2.returncode, godebug_err=p2.stderr.decode()[:120])

json.dump({"bin": BIN, "uname": list(os.uname()), "results": res}, open(OUT, "w"), indent=1)
fails = [r for r in res if not r["ok"]]
print("total", len(res), "fail", len(fails))
sys.exit(1 if fails else 0)
