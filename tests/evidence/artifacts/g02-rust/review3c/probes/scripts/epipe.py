#!/usr/bin/env python3
"""review3c closed-stdout parity probes (reviewer-written).

usage: epipe.py HP FIXDIR OUT.json
Each case runs plain and --json with the same stdout/stderr setup and records the wait
status. SIGPIPE is at its default disposition in the child (subprocess restore_signals).
"""
import json
import os
import subprocess
import sys

HP, FIX, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
LINUX = sys.platform.startswith("linux")


def closed_pipe():
    r, w = os.pipe()
    os.close(r)
    return w


def run(args, setup):
    fds = {}
    if setup == "stdout_closed_pipe":
        fds["stdout"] = closed_pipe()
        fds["stderr"] = subprocess.DEVNULL
    elif setup == "stdout_and_stderr_closed_pipe":
        w = closed_pipe()
        fds["stdout"] = w
        fds["stderr"] = w
    elif setup == "stdout_dev_full":
        fds["stdout"] = os.open("/dev/full", os.O_WRONLY)
        fds["stderr"] = subprocess.DEVNULL
    elif setup == "open":
        fds["stdout"] = subprocess.DEVNULL
        fds["stderr"] = subprocess.DEVNULL
    if setup == "stdout_fd_closed":
        p = subprocess.run(["sh", "-c", 'exec "$@" >&-', "sh", HP] + args,
                           stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    else:
        p = subprocess.run([HP] + args, stdin=subprocess.DEVNULL, timeout=20, **fds)
    for k in ("stdout", "stderr"):
        v = fds.get(k)
        if isinstance(v, int) and v >= 0:
            try:
                os.close(v)
            except OSError:
                pass
    rc = p.returncode
    return "signal %d" % -rc if rc < 0 else "exit %d" % rc


env_sock = "/nonexistent-r3c/agent.sock"
cases = {
    "version": ["version"],
    "profile-homelab": ["profile", "show", "--file", os.path.join(FIX, "homelab.toml")],
    "profile-large-100": ["profile", "show", "--file", os.path.join(FIX, "large-100.toml")],
    "profile-missing": ["profile", "show", "--file", os.path.join(FIX, "does-not-exist.toml")],
    "profile-invalid-port": ["profile", "show", "--file", os.path.join(FIX, "invalid-port.toml")],
    "profile-malformed": ["profile", "show", "--file", os.path.join(FIX, "invalid-malformed.toml")],
    "agent-unavailable": ["agent", "list", "--socket", env_sock],
    "usage-unknown-flag": ["version", "--bogus"],
}
setups = ["open", "stdout_closed_pipe", "stdout_and_stderr_closed_pipe", "stdout_fd_closed"]
if LINUX:
    setups.append("stdout_dev_full")
res = {"platform": sys.platform, "cases": {}}
mism = []
for name, args in cases.items():
    for s in setups:
        plain = run(args, s)
        js = run(args + ["--json"], s)
        res["cases"]["%s/%s" % (name, s)] = {"plain": plain, "json": js, "equal": plain == js}
        if plain != js:
            mism.append("%s/%s" % (name, s))
# help has no --json form; recorded only
for s in setups:
    res["cases"]["help/%s" % s] = {"plain": run(["--help"], s)}
res["mismatches"] = mism
with open(OUT, "w") as f:
    json.dump(res, f, indent=1)
print(json.dumps({"mismatches": mism, "n": len(res["cases"])}))
sys.exit(1 if mism else 0)
