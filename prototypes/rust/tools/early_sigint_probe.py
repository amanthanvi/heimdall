#!/usr/bin/env python3
"""Round-2 probe: SIGINT shortly after `agent list` starts (round-1 review minor).

Usage: early_sigint_probe.py <heimdall-proto> [iterations-per-delay]

A fake agent accepts and never answers. For each delay, the probe starts
`agent list --socket <s> --json`, sends SIGINT after the delay, and classifies the
outcome: `cancelled` (exit 130 with a CANCELLED JSON document) or `killed` (terminated
by SIGINT's default action, no JSON). Prints one JSON summary line. Stdlib only.
Never touches a real agent (SSH_AUTH_SOCK is removed from the child environment).
"""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = os.path.abspath(sys.argv[1])
iters = int(sys.argv[2]) if len(sys.argv) > 2 else 20
tmp = tempfile.mkdtemp(prefix="hp-esig-")
path = os.path.join(tmp, "a.sock")
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(64)
held = []


def accept_loop():
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        held.append(c)  # never answer


threading.Thread(target=accept_loop, daemon=True).start()
env = dict(os.environ)
env.pop("SSH_AUTH_SOCK", None)
delays_ms = [0, 0.25, 0.5, 1, 2, 3, 5, 10]
summary = {}
for d in delays_ms:
    counts = {"cancelled": 0, "killed": 0, "other": 0}
    for _ in range(iters):
        p = subprocess.Popen([binary, "agent", "list", "--socket", path, "--timeout-ms", "3000", "--json"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        if d:
            time.sleep(d / 1000.0)
        p.send_signal(signal.SIGINT)
        out, _ = p.communicate(timeout=10)
        if p.returncode == -signal.SIGINT:
            counts["killed"] += 1
        elif p.returncode == 130 and b'"CANCELLED"' in out:
            counts["cancelled"] += 1
        else:
            counts["other"] += 1
    summary[str(d)] = counts
srv.close()
for c in held:
    c.close()
os.unlink(path)
os.rmdir(tmp)
print(json.dumps({"binary": binary, "platform": sys.platform, "iterations_per_delay": iters,
                  "delay_ms_to_outcomes": summary}))
