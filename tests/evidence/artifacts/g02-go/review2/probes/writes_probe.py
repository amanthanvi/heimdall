# Runs every subcommand with HOME/TMPDIR/cwd in a fresh dir; reports every file
# that exists afterwards except the named --meta-file and the probe's own socket.
import fcntl, struct, termios, json, os, pty, select, signal, socket, subprocess, sys, tempfile, threading, time, platform
P = sys.argv[1]; FIX = sys.argv[2]; ROOT = sys.argv[3] if len(sys.argv) > 3 else tempfile.mkdtemp(prefix="hm-r2-writes-")
work = os.path.join(ROOT, "work dir ü"); home = os.path.join(ROOT, "home"); tmp = os.path.join(ROOT, "tmp")
for x in (work, home, tmp): os.makedirs(x, exist_ok=True)
env = {"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": tmp, "LANG": "en_US.UTF-8", "TERM": "xterm-256color",
       "TEA_TRACE": os.path.join(ROOT, "tea-trace.log"), "TEA_DEBUG": "1", "GOTRACEBACK": "all", "UV_DEBUG": os.path.join(ROOT, "uv-debug.log")}
res = {}
def call(name, argv, **kw):
    pr = subprocess.run([P] + argv, cwd=work, env=env, capture_output=True, timeout=20, **kw)
    res[name] = pr.returncode
call("version", ["version", "--json"])
for f in ("homelab.toml", "invalid-forbidden-key.toml", "large-100.toml"):
    call("profile:" + f, ["profile", "show", "--file", os.path.join(FIX, f), "--json"])
sock = os.path.join(tmp, "agent.sock")
srv = socket.socket(socket.AF_UNIX); srv.bind(sock); srv.listen(1)
def serve():
    c, _ = srv.accept(); c.recv(5); c.sendall(struct.pack(">I", 5) + bytes([12, 0, 0, 0, 0])); c.close()
th = threading.Thread(target=serve); th.start()
call("agent", ["agent", "list", "--socket", sock, "--json"]); th.join(); srv.close()
call("agent-missing", ["agent", "list", "--socket", os.path.join(tmp, "none"), "--json"])
meta = os.path.join(work, "meta ü.json")
call("run", ["run", "--meta-file", meta, "--", "/bin/sh", "-c", "exit 3"])
call("run-launchfail", ["run", "--", "/nonexistent/x"])
pid, fd = pty.fork()
if pid == 0:
    os.chdir(work); os.execve(P, [P, "tui", "--file", os.path.join(FIX, "homelab.toml")], env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
t0 = time.monotonic(); buf = bytearray()
while time.monotonic() - t0 < 1.5:
    r, _, _ = select.select([fd], [], [], 0.05)
    if r:
        try: buf.extend(os.read(fd, 65536))
        except OSError: break
os.write(fd, b"\r")
t0 = time.monotonic(); st = None
while time.monotonic() - t0 < 3:
    r, _, _ = select.select([fd], [], [], 0.05)
    if r:
        try: buf.extend(os.read(fd, 65536))
        except OSError: pass
    w, s = os.waitpid(pid, os.WNOHANG)
    if w: st = os.waitstatus_to_exitcode(s); break
res["tui-select"] = st
os.unlink(sock)
found = []
for base, dirs, files in os.walk(ROOT):
    for n in files + [d for d in dirs]:
        p = os.path.join(base, n)
        if p in (work, home, tmp, meta): continue
        found.append(os.path.relpath(p, ROOT))
print(json.dumps({"platform": platform.system(), "exit_codes": res, "unexpected_paths": found}, indent=1))
