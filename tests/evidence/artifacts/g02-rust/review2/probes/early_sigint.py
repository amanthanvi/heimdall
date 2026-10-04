#!/usr/bin/env python3
"""Reviewer-2: SIGINT at small delays after spawning `agent list` against a hanging agent.
Counts outcomes: CANCELLED/130 vs killed by signal (no JSON). Usage: early_sigint.py BIN OUT.json"""
import json, os, signal, socket, subprocess, sys, tempfile, threading, time
BIN, OUT = sys.argv[1], sys.argv[2]
d = tempfile.mkdtemp(); sp = os.path.join(d, "s")
srv = socket.socket(socket.AF_UNIX); srv.bind(sp); srv.listen(64)
conns = []
def acc():
    while True:
        try:
            c, _ = srv.accept(); conns.append(c)
        except OSError:
            return
threading.Thread(target=acc, daemon=True).start()
res = {}
for delay_ms in (0, 0.5, 1, 2, 5):
    tally = {}
    for _ in range(30):
        p = subprocess.Popen([BIN, "agent", "list", "--socket", sp, "--timeout-ms", "3000", "--json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if delay_ms:
            time.sleep(delay_ms / 1000)
        p.send_signal(signal.SIGINT)
        o, _ = p.communicate(timeout=10)
        try:
            code = json.loads(o)["code"]
        except Exception:
            code = "no-json"
        k = "%s/%s" % (p.returncode, code)
        tally[k] = tally.get(k, 0) + 1
    res[str(delay_ms)] = tally
    print(delay_ms, tally, flush=True)
json.dump({"bin": BIN, "platform": sys.platform, "results_by_delay_ms": res}, open(OUT, "w"), indent=1)
