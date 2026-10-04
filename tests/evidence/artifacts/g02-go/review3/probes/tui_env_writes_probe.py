#!/usr/bin/env python3
"""Review-3 probe: environment-driven behavior, helper processes and stray writes of
every heimdall-proto subcommand, with emphasis on the TUI.

usage: tui_env_writes_probe.py HEIMDALL_BIN PROFILE OUT_JSON

All of HOME, TMPDIR, XDG_*, cwd point into one fresh sandbox directory. Debug/trace
variables of the linked libraries (TEA_TRACE, TEA_DEBUG, UV_DEBUG) point at files in a
separate sandbox directory, and a PATH-first directory holds logging stubs for tmux,
tput, infocmp, stty, screen, ps, sh, bash, open, xdg-open. After each command the probe
lists every file present in both directories (anything new is a stray write or a helper
invocation). The TUI runs in a pty with TMUX, TERM_PROGRAM=tmux, TERM=tmux-256color,
COLORTERM, and TERMINFO pointing into the sandbox.
"""
import json
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HP = os.path.abspath(sys.argv[1])
PROFILE = os.path.abspath(sys.argv[2])
OUT = sys.argv[3]
STUBS = ["tmux", "tput", "infocmp", "stty", "screen", "ps", "sh", "bash", "open", "xdg-open", "less", "git"]


def snapshot(*dirs):
    found = []
    for d in dirs:
        for root, _dirs, files in os.walk(d):
            for n in files + _dirs:
                found.append(os.path.relpath(os.path.join(root, n), d) + " @" + os.path.basename(d))
    return sorted(found)


def main():
    base = tempfile.mkdtemp(prefix="hp-rv3-env-")
    box = os.path.join(base, "box")
    dbg = os.path.join(base, "dbg")
    stubdir = os.path.join(base, "stubs")
    for d in (box, dbg, stubdir):
        os.makedirs(d)
    marker = os.path.join(dbg, "helper-invoked")
    for s in STUBS:
        p = os.path.join(stubdir, s)
        with open(p, "w") as f:
            f.write("#!/bin/sh\necho \"$0 $*\" >> '%s'\nexit 0\n" % marker)
        os.chmod(p, 0o755)
    env = {
        "PATH": stubdir + ":/usr/bin:/bin", "HOME": box, "TMPDIR": box, "XDG_CONFIG_HOME": box,
        "XDG_CACHE_HOME": box, "XDG_RUNTIME_DIR": box, "XDG_STATE_HOME": box, "XDG_DATA_HOME": box,
        "TEA_TRACE": os.path.join(dbg, "tea-trace.log"), "TEA_DEBUG": "1",
        "UV_DEBUG": os.path.join(dbg, "uv-debug.log"), "TMUX": "/tmp/tmux-fake,1,0",
        "TERM_PROGRAM": "tmux", "TERM": "tmux-256color", "COLORTERM": "truecolor",
        "TERMINFO": os.path.join(box, "terminfo"), "LANG": "C.UTF-8", "GOTRACEBACK": "crash",
        "GODEBUG": "inittrace=1",
    }
    res = {"env_keys": sorted(env), "commands": []}
    before = snapshot(box, dbg)

    def plain(argv):
        p = subprocess.run([HP] + argv, cwd=box, env=env, capture_output=True, timeout=20)
        res["commands"].append({"argv": argv, "rc": p.returncode, "stdout_bytes": len(p.stdout),
                                "stderr_head": p.stderr.decode("utf-8", "replace")[:300],
                                "new_files": [x for x in snapshot(box, dbg) if x not in before]})

    plain(["version", "--json"])
    plain(["profile", "show", "--file", PROFILE, "--json"])
    plain(["agent", "list", "--socket", os.path.join(box, "nosock"), "--timeout-ms", "200", "--json"])
    plain(["run", "--", "/usr/bin/true"])

    # TUI in a pty: wait for the first frame, press q.
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(box)
        os.execve(HP, [HP, "tui", "--file", PROFILE], env)
    import fcntl, struct, termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    buf = b""
    t0 = time.monotonic()
    first = None
    while time.monotonic() - t0 < 6:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                break
            if not d:
                break
            buf += d
            if first is None and b"lab-server" in buf:
                first = time.monotonic() - t0
                time.sleep(0.3)
                os.write(fd, b"q")
        if first is not None and time.monotonic() - t0 > first + 2:
            break
    for _ in range(60):
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            break
        time.sleep(0.05)
    else:
        os.kill(pid, signal.SIGTERM)  # exact TUI pid forked above; recorded as no exit on q
        res["tui_needed_sigterm"] = True
        _, st = os.waitpid(pid, 0)
    os.close(fd)
    res["commands"].append({"argv": ["tui", "--file", "<profile>"], "rc": os.waitstatus_to_exitcode(st),
                            "first_frame_s": round(first, 3) if first else None,
                            "inittrace_on_tty": b"init " in buf,
                            "new_files": [x for x in snapshot(box, dbg) if x not in before]})
    res["helper_invocations"] = open(marker).read().splitlines() if os.path.exists(marker) else []
    with open(OUT, "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))
    shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    main()
