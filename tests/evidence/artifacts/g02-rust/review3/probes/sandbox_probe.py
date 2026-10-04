#!/usr/bin/env python3
"""Review3 darwin probe: run each non-`run` command under sandbox-exec with every file write
outside the named paths (and every exec of another program) denied, with environment
variables that could select helpers (TERM/TMUX/TERM_PROGRAM, fake tput first on PATH).
A denied operation is observable through the program's behaviour/exit code and through
the kernel sandbox log (checked separately). Prints JSON.
usage: sandbox_probe.py <hp> <fixtures dir> <workdir>
"""
import json, os, pty, select, signal, subprocess, sys, time

HP, FX, WD = sys.argv[1:4]
WD = os.path.realpath(WD) if os.path.exists(WD) else os.path.join(os.path.realpath(os.path.dirname(WD)), os.path.basename(WD))
os.makedirs(WD, exist_ok=True)
meta = os.path.join(WD, "meta.json")
fakebin = os.path.join(WD, "fakebin")
os.makedirs(fakebin, exist_ok=True)
marker = os.path.join(WD, "helper-ran")
for t in ("tput", "tmux", "infocmp", "stty", "tset", "resize", "toe", "clear", "sh", "ls"):
    p = os.path.join(fakebin, t)
    with open(p, "w") as f:
        f.write(f"#!/bin/sh\necho {t} >> {marker}\n")
    os.chmod(p, 0o755)

profile = f"""(version 1)
(allow default)
(deny file-write*
  (require-all
    (require-not (literal "{meta}"))
    (require-not (literal "/dev/null"))
    (require-not (literal "/dev/tty"))
    (require-not (regex #"^/dev/ttys[0-9]+$"))
    (require-not (regex #"^/dev/fd/[0-9]+$"))
    (require-not (regex #"^/private/var/folders/.*/com\\.apple\\.dyld/"))))
(deny process-exec (require-not (literal "{os.path.realpath(HP)}")))
"""
sb = os.path.join(WD, "deny.sb")
open(sb, "w").write(profile)
env = {"PATH": f"{fakebin}:/usr/bin:/bin", "HOME": WD, "TMPDIR": WD + "/tmp", "TERM": "tmux-256color",
       "TMUX": "/tmp/fake-tmux,1,0", "TERM_PROGRAM": "tmux", "COLORTERM": "truecolor", "LANG": "C"}


def sbrun(args, **kw):
    return subprocess.run(["/usr/bin/sandbox-exec", "-f", sb, HP] + args, env=env, capture_output=True,
                          timeout=20, **kw)


res = {}
res["version"] = sbrun(["version", "--json"]).returncode
res["profile_show"] = sbrun(["profile", "show", "--file", os.path.join(FX, "large-100.toml"), "--json"]).returncode
res["profile_invalid"] = sbrun(["profile", "show", "--file", os.path.join(FX, "invalid-port.toml"), "--json"]).returncode
res["agent_missing"] = sbrun(["agent", "list", "--socket", os.path.join(WD, "nosock"), "--json"]).returncode
# run with meta file: the child itself is denied exec except heimdall-proto itself -> use heimdall-proto as child
r = sbrun(["run", "--meta-file", meta, "--", os.path.realpath(HP), "version", "--json"])
res["run_meta"] = {"exit": r.returncode, "meta_written": os.path.exists(meta)}

# TUI in a pty under the sandbox: keys, filter, resize, quit
pid, fd = pty.fork()
if pid == 0:
    os.execve("/usr/bin/sandbox-exec", ["/usr/bin/sandbox-exec", "-f", sb, HP, "tui", "--file",
              os.path.join(FX, "large-100.toml")], env)
buf = b""


def rd(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                return
            if not d:
                return
            buf += d


rd(1.0)
import fcntl, struct, termios
for cols, rows in ((40, 10), (120, 40)):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    os.kill(pid, signal.SIGWINCH)  # sandbox-exec execs the target, so pid is heimdall-proto
    rd(0.3)
os.write(fd, b"/vps")
rd(0.3)
os.write(fd, b"\x1b")
rd(0.2)
os.write(fd, b"q")
rd(1.0)
_, st = os.waitpid(pid, 0)
res["tui_exit"] = os.waitstatus_to_exitcode(st)
res["helper_marker_exists"] = os.path.exists(marker)
res["helper_marker"] = open(marker).read() if os.path.exists(marker) else ""
created = []
for root, dirs, files in os.walk(WD):
    for n in files + dirs:
        created.append(os.path.relpath(os.path.join(root, n), WD))
res["files_in_workdir"] = sorted(created)
print(json.dumps(res, indent=1))
# positive controls: the sandbox really denies exec of other programs and writes elsewhere
pc1 = sbrun(["run", "--", "/bin/echo", "x"])
pc2 = sbrun(["run", "--meta-file", os.path.join(WD, "other-meta.json"), "--", os.path.realpath(HP), "version"])
print(json.dumps({"control_exec_other_denied_exit": pc1.returncode,
                  "control_write_elsewhere_written": os.path.exists(os.path.join(WD, "other-meta.json")),
                  "control_write_elsewhere_stderr": pc2.stderr.decode(errors="replace").strip()[-80:]}))
