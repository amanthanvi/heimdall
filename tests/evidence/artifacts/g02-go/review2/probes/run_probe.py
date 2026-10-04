import hashlib, json, os, platform, signal, subprocess, sys, tempfile, time
P = sys.argv[1]; PY = sys.executable
env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
out = {"platform": platform.system()}
d = tempfile.mkdtemp(prefix="hm-r2-run-")
def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False
    except PermissionError: return True
# 1 large binary stream through stdin->stdout with a slow consumer (backpressure), byte-exact
data = os.urandom(1 << 20) * 48 + bytes(range(256)) * 4096
p = subprocess.Popen([P, "run", "--", "/bin/cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
import threading
got = bytearray()
def rd():
    while True:
        x = p.stdout.read(65536)
        if not x: break
        got.extend(x); time.sleep(0.0005)
t = threading.Thread(target=rd); t.start(); p.stdin.write(data); p.stdin.close(); t.join(); p.wait()
out["stream_50MiB_slow_reader"] = {"rc": p.returncode, "sha_equal": hashlib.sha256(got).digest() == hashlib.sha256(data).digest(), "bytes": len(got)}
# 2 stdin EOF reaches child
r = subprocess.run([P, "run", "--", PY, "-c", "import sys; d=sys.stdin.buffer.read(); print(len(d))"], input=b"abc", capture_output=True, env=env)
out["stdin_eof"] = {"rc": r.returncode, "stdout": r.stdout.decode().strip()}
# 3 SIGPIPE: child writes into a closed pipe
t0 = time.monotonic()
r = subprocess.run(["/bin/sh", "-c", '"$0" run -- yes | head -c 10 >/dev/null; echo "${PIPESTATUS:-x}"', P], capture_output=True, env=env, timeout=20)
p = subprocess.Popen([P, "run", "--", "yes"], stdout=subprocess.PIPE, env=env); p.stdout.read(10); p.stdout.close(); rc = p.wait(10)
out["sigpipe_child"] = {"proto_rc": rc, "expected": 128 + 13, "elapsed_s": round(time.monotonic() - t0, 3)}
# 4 GODEBUG=execerrdot=0 with PATH "." still refused
os.makedirs(os.path.join(d, "bin"), exist_ok=True)
x = os.path.join(d, "bin", "hmdot"); open(x, "w").write("#!/bin/sh\necho DOT_RAN\n"); os.chmod(x, 0o755)
r = subprocess.run([P, "run", "--", "hmdot"], cwd=os.path.join(d, "bin"), capture_output=True, env={"PATH": ".:/usr/bin", "GODEBUG": "execerrdot=0"})
out["godebug_execerrdot"] = {"rc": r.returncode, "ran": b"DOT_RAN" in r.stdout}
# 5 SIGKILL of heimdall-proto (no tty): child survives? (disclosed)
pidf = os.path.join(d, "c.pid")
p = subprocess.Popen([P, "run", "--", PY, "-c", "import os,time; open(%r,'w').write(str(os.getpid())); time.sleep(5)" % pidf], env=env)
for _ in range(200):
    if os.path.exists(pidf) and open(pidf).read(): break
    time.sleep(0.01)
cpid = int(open(pidf).read()); p.kill(); p.wait(); time.sleep(0.2)
out["sigkill_proto_child_survives"] = alive(cpid)
if alive(cpid): os.kill(cpid, signal.SIGKILL)
# 6 child sees closed stdout as open (Go runtime reopens fds 0-2)
r = subprocess.run(["/bin/sh", "-c", 'exec "$0" run -- /bin/sh -c "echo x; echo rc=\\$? >&2" >&-', P], capture_output=True, env=env)
out["closed_stdout"] = {"stderr": r.stderr.decode().strip()[-60:], "rc": r.returncode}
r = subprocess.run(["/bin/sh", "-c", 'exec /bin/sh -c "echo x; echo rc=\\$? >&2" >&-'], capture_output=True, env=env)
out["closed_stdout_control"] = {"stderr": r.stderr.decode().strip()[-60:]}
# 7 FIFO meta file without reader does not block; child status kept
fifo = os.path.join(d, "meta.fifo"); os.mkfifo(fifo)
t0 = time.monotonic(); r = subprocess.run([P, "run", "--meta-file", fifo, "--", "/bin/sh", "-c", "exit 4"], capture_output=True, env=env, timeout=10)
out["meta_fifo_no_reader"] = {"rc": r.returncode, "elapsed_s": round(time.monotonic() - t0, 3), "stderr": r.stderr.decode()[:80]}
# 8 meta to a symlink pointing elsewhere (writes through symlink: recorded, contract leaves it unspecified)
tgt = os.path.join(d, "elsewhere.json"); ln = os.path.join(d, "meta-link.json"); os.symlink(tgt, ln)
r = subprocess.run([P, "run", "--meta-file", ln, "--", "/usr/bin/true"], capture_output=True, env=env)
out["meta_symlink_followed"] = os.path.exists(tgt)
# 9 nohup-style grandchild keeps running after child exits; heimdall returns promptly
t0 = time.monotonic()
r = subprocess.run([P, "run", "--", "/bin/sh", "-c", "sleep 2 >/dev/null 2>&1 </dev/null & echo $!"], capture_output=True, env=env, timeout=10)
out["grandchild_background"] = {"rc": r.returncode, "elapsed_s": round(time.monotonic() - t0, 3)}
# 10 exit statuses 0..255 sample + signal deaths
codes = {}
for c in (0, 1, 126, 127, 128, 255):
    codes[c] = subprocess.run([P, "run", "--", "/bin/sh", "-c", "exit %d" % c], env=env).returncode
for s in (signal.SIGSEGV, signal.SIGABRT, signal.SIGKILL, signal.SIGUSR1):
    codes["sig%d" % s] = subprocess.run([P, "run", "--", "/bin/sh", "-c", "kill -%d $$" % s], env=env).returncode
out["exit_mapping"] = codes
# 11 zombie check: after heimdall exits, no child of heimdall remains as zombie (heimdall gone => n/a); check heimdall reaps before exit
r = subprocess.run([P, "run", "--", PY, "-c", "import os; print(os.getpid())"], capture_output=True, env=env)
zp = int(r.stdout); out["child_reaped"] = not alive(zp)
print(json.dumps(out, indent=1))
