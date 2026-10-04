#!/usr/bin/env python3
"""Reviewer-2 Linux syscall probe: every program heimdall-proto executes, every file it opens
(read or write), every socket it creates/connects/binds, for each command path.

Usage (inside heimdall-review2-strace image): strace_probe.py BIN FIXTURES_DIR OUT.json
"""
import json, os, pty, re, select, signal, socket, struct, subprocess, sys, tempfile, threading, time

BIN, FIX, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
W = tempfile.mkdtemp(prefix="hp-rv2-st ü ")
HOME = os.path.join(W, "home"); os.mkdir(HOME)
TRACE = "execve,execveat,fork,vfork,clone,clone3,open,openat,openat2,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,symlink,symlinkat,link,linkat,truncate,ftruncate,chmod,fchmodat,socket,connect,bind,listen,memfd_create,mmap"
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": HOME, "TMPDIR": W, "LANG": "C.UTF-8",
       "TERM": "tmux-256color", "TMUX": "/tmp/tmux-1/default,1,0", "TERM_PROGRAM": "tmux",
       "TERMINFO": os.path.join(W, "terminfo"), "COLORTERM": "truecolor"}
results = []


def traced(name, argv, stdin=None, tty=None, extra_env=None, keys=None, kill_after=None, timeout=15):
    log = os.path.join(W, name + ".strace")
    cmd = ["strace", "-f", "-qq", "-s", "200", "-e", "trace=" + TRACE, "-o", log] + argv
    env = dict(ENV, **(extra_env or {}))
    if tty:
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe(cmd[0], cmd, env)
        # set size
        import fcntl, termios
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        out = b""
        t0 = time.time()
        sent = False
        while time.time() - t0 < timeout:
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    b = os.read(fd, 65536)
                except OSError:
                    break
                if not b:
                    break
                out += b
            if not sent and time.time() - t0 > 1.0:
                for k in keys or []:
                    if k == "WINCH":
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 5, 20, 0, 0))
                    elif k == "HANGUP":
                        os.close(fd); fd = None; break
                    else:
                        os.write(fd, k)
                    time.sleep(0.2)
                sent = True
                if fd is None:
                    break
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                break
        else:
            pass
        try:
            _, st = os.waitpid(pid, 0)
        except ChildProcessError:
            st = 0
        rc = os.waitstatus_to_exitcode(st)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    else:
        p = subprocess.run(cmd, input=stdin, capture_output=True, env=env, timeout=timeout)
        rc = p.returncode
    lines = open(log, errors="replace").read().splitlines()
    execs = [l for l in lines if re.search(r"\bexecve(at)?\(", l)]
    opens = [l for l in lines if re.search(r"\b(open|openat|openat2|creat)\(", l)]
    writes = [l for l in opens if re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC", l) or "creat(" in l]
    mut = [l for l in lines if re.search(r"\b(mkdir|mkdirat|rename|renameat2?|unlink|unlinkat|symlink|symlinkat|link|linkat|truncate|chmod|fchmodat|memfd_create)\(", l)]
    socks = [l for l in lines if re.search(r"\b(socket|connect|bind|listen)\(", l)]
    paths_read = sorted(set(re.findall(r'open(?:at)?\((?:AT_FDCWD, )?"([^"]*)"', "\n".join(opens))))
    r = {"case": name, "exit": rc, "execve": [e[:220] for e in execs], "write_opens": [w[:220] for w in writes],
         "mutating_calls": [m[:220] for m in mut], "socket_calls": [s[:220] for s in socks], "paths_opened": paths_read}
    results.append(r)
    print(json.dumps(r)[:1500], flush=True)


good = os.path.join(FIX, "profiles", "homelab.toml")
if not os.path.exists(good):
    cands = [os.path.join(FIX, "profiles", f) for f in sorted(os.listdir(os.path.join(FIX, "profiles"))) if f.startswith("valid") and f.endswith(".toml")]
    good = cands[0]
bad = [os.path.join(FIX, "profiles", f) for f in sorted(os.listdir(os.path.join(FIX, "profiles"))) if f.startswith("invalid")][0]
traced("version", [BIN, "version", "--json"])
traced("profile_ok", [BIN, "profile", "show", "--file", good, "--json"])
traced("profile_invalid", [BIN, "profile", "show", "--file", bad, "--json"])
traced("usage_error", [BIN, "frobnicate", "--json"])
fifo = os.path.join(W, "fifo"); os.mkfifo(fifo)
traced("profile_fifo", [BIN, "profile", "show", "--file", fifo, "--json"])

# agent
sp = os.path.join(W, "agent sock")
srv = socket.socket(socket.AF_UNIX); srv.bind(sp); srv.listen(1)
def serve():
    c, _ = srv.accept(); c.recv(5); c.sendall(struct.pack(">I", 5) + b"\x0c\x00\x00\x00\x00"); c.close()
threading.Thread(target=serve, daemon=True).start()
traced("agent_ok", [BIN, "agent", "list", "--socket", sp, "--json"])
traced("agent_missing", [BIN, "agent", "list", "--socket", os.path.join(W, "nope"), "--json", "--timeout-ms", "300"])

# run
meta = os.path.join(W, "meta é.json")
traced("run_true_meta", [BIN, "run", "--meta-file", meta, "--", "true"])
traced("run_missing", [BIN, "run", "--meta-file", meta, "--", "no-such-prog"])

# tui in a pty: keys, resize, quit; then hangup variant; stdout not-a-tty variant
traced("tui_keys_resize_quit", [BIN, "tui", "--file", good], tty=True, keys=[b"j", b"/", b"a", b"\x1b", "WINCH", b"q"])
traced("tui_hangup", [BIN, "tui", "--file", good], tty=True, keys=["HANGUP"])
traced("tui_select", [BIN, "tui", "--file", good], tty=True, keys=[b"\r"])
traced("tui_no_tty", [BIN, "tui", "--file", good])

json.dump({"bin": BIN, "env": {k: v for k, v in ENV.items() if k != "HOME"}, "results": results}, open(OUT, "w"), indent=1)
