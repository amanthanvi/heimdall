#!/usr/bin/env python3
"""Review-3c independent K12 closed-stdout probe (slice-contract §9.4, Q17).

usage: k12_probe.py OUT_JSON LABEL=BIN [LABEL=BIN ...]

For every case and every binary, runs the case with and without --json under
several broken-output setups and records the raw wait status ("exit N" or
"signal NAME"). Nothing is judged here except a per-case "parity" flag
(plain status == --json status), which is a plain comparison of observations.

Setups:
  stdout_closed_reader  stdout = pipe write end whose read end is closed first
  stderr_closed_reader  stderr = such a pipe (stdout to /dev/null)
  both_closed_reader    both stdout and stderr such pipes
  stdout_fd_closed      fd 1 not open at all
  stdout_closed_sigpipe_ign  stdout_closed_reader with SIGPIPE inherited ignored
  stdout_normal         stdout a normal pipe that is read (baseline exit code)

Disposable inputs only: fixture profiles from the repo, a fake agent from the
repo on a socket in a fresh temp dir, a per-run ed25519 key in that temp dir.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), *[".."] * 6))
FIX = os.path.join(REPO, "tests/fixtures/g02/profiles")
AGENT = os.path.join(REPO, "tests/fixtures/fake-agent/fake_agent.py")
OUT = sys.argv[1]
BINS = dict(a.split("=", 1) for a in sys.argv[2:])
TMP = tempfile.mkdtemp(prefix="hp-rv3c-k12-")


def status(rc):
    if rc < 0:
        return "signal " + signal.Signals(-rc).name
    return "exit %d" % rc


def run_one(argv, setup):
    pre = None
    stdout = subprocess.DEVNULL
    stderr = subprocess.DEVNULL
    closers = []
    if setup in ("stdout_closed_reader", "both_closed_reader", "stdout_closed_sigpipe_ign"):
        r, w = os.pipe()
        os.close(r)
        stdout = w
        closers.append(w)
    if setup in ("stderr_closed_reader", "both_closed_reader"):
        r, w = os.pipe()
        os.close(r)
        stderr = w
        closers.append(w)
    if setup == "stdout_fd_closed":
        def pre():
            os.close(1)
    if setup == "stdout_closed_sigpipe_ign":
        def pre():
            signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    if setup == "stdout_normal":
        stdout = subprocess.PIPE
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                           preexec_fn=pre, timeout=20, env=ENV, restore_signals=True)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        rc = None
    for c in closers:
        os.close(c)
    return {"status": status(rc) if rc is not None else "timeout",
            "ms": round((time.monotonic() - t0) * 1000)}


ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": TMP}

# fresh disposable agent with one per-run key
key = os.path.join(TMP, "k")
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "rv3c", "-f", key], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
agents = {}
for mode in ("normal", "failure", "truncated"):
    sock = os.path.join(TMP, mode + ".sock")
    ready = os.path.join(TMP, mode + ".ready")
    p = subprocess.Popen([sys.executable, AGENT, "--socket", sock, "--mode", mode, "--pubkey", key + ".pub",
                          "--log", os.path.join(TMP, mode + ".log"), "--ready-file", ready],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(ready):
            break
        time.sleep(0.05)
    agents[mode] = (p, sock)
fifo = os.path.join(TMP, "fifo.toml")
os.mkfifo(fifo)

CASES = [
    ("version", ["version"]),
    ("profile-ok-homelab", ["profile", "show", "--file", os.path.join(FIX, "homelab.toml")]),
    ("profile-ok-large-100", ["profile", "show", "--file", os.path.join(FIX, "large-100.toml")]),
    ("profile-missing", ["profile", "show", "--file", os.path.join(TMP, "missing.toml")]),
    ("profile-schema-invalid", ["profile", "show", "--file", os.path.join(FIX, "invalid-forbidden-key.toml")]),
    ("profile-malformed", ["profile", "show", "--file", os.path.join(FIX, "invalid-malformed.toml")]),
    ("profile-fifo-k14", ["profile", "show", "--file", fifo]),
    ("profile-no-file-flag", ["profile", "show"]),
    ("agent-ok", ["agent", "list", "--socket", agents["normal"][1]]),
    ("agent-refused", ["agent", "list", "--socket", agents["failure"][1]]),
    ("agent-protocol-error", ["agent", "list", "--socket", agents["truncated"][1]]),
    ("agent-unavailable", ["agent", "list", "--socket", os.path.join(TMP, "none.sock")]),
    ("agent-bad-timeout", ["agent", "list", "--socket", "x", "--timeout-ms", "0"]),
    ("usage-unknown-subcommand", ["frobnicate"]),
    ("usage-no-subcommand", []),
    ("usage-profile-no-show", ["profile"]),
    ("usage-unknown-flag", ["version", "--no-such-flag"]),
    ("usage-run-missing-dashdash", ["run", "true"]),
    ("usage-tui-unknown-flag", ["tui", "--file", os.path.join(FIX, "homelab.toml"), "--bogus"]),
]
SETUPS = ["stdout_normal", "stdout_closed_reader", "stderr_closed_reader", "both_closed_reader",
          "stdout_fd_closed", "stdout_closed_sigpipe_ign"]

results = []
try:
    for label, b in BINS.items():
        for name, args in CASES:
            for setup in SETUPS:
                plain = run_one([b] + args, setup)
                js = run_one([b] + args + ["--json"], setup)
                results.append({"bin": label, "case": name, "setup": setup, "plain": plain["status"],
                                "json": js["status"], "parity": plain["status"] == js["status"]})
                print("%-6s %-28s %-26s plain=%-16s json=%-16s %s" % (
                    label, name, setup, plain["status"], js["status"],
                    "" if plain["status"] == js["status"] else "MISMATCH"), flush=True)
finally:
    for p, _ in agents.values():
        p.terminate()  # exact Popen children started by this probe
        p.wait(5)
with open(OUT, "w") as f:
    json.dump({"uname": " ".join(os.uname()[i] for i in (0, 2, 4)), "bins": list(BINS),
               "setups": SETUPS, "results": results}, f, indent=1)
subprocess.run(["rm", "-rf", TMP])
