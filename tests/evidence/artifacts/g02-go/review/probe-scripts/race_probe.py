#!/usr/bin/env python3
"""SIGTERM-at-startup race: does heimdall ever die by the signal AFTER the child started (orphan)?"""
import json, os, signal, subprocess, sys, tempfile, time

BIN, OUT, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
tmp = tempfile.mkdtemp(prefix="hrg-race-")
env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "TMPDIR": tmp}
rows = []
delays = [0, 0.0005, 0.001, 0.002, 0.003, 0.004, 0.006, 0.008, 0.012, 0.02]
for i in range(N):
    d = delays[i % len(delays)]
    pf = f"{tmp}/c{i}.pid"
    # child writes its pid FIRST, then sleeps; SIGTERM default kills it
    pp = subprocess.Popen([BIN, "run", "--", "/bin/sh", "-c", 'echo $$ > "$1"; exec sleep 1', "x", pf],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    if d:
        time.sleep(d)
    os.kill(pp.pid, signal.SIGTERM)
    rc = pp.wait(10)
    time.sleep(0.05)
    cpid = int(open(pf).read()) if os.path.exists(pf) and open(pf).read().strip() else None
    alive = False
    if cpid:
        try:
            os.kill(cpid, 0); alive = True
        except ProcessLookupError:
            pass
    if alive:
        os.kill(cpid, signal.SIGKILL)
    rows.append({"i": i, "delay_s": d, "heimdall_rc": rc, "child_started": cpid is not None, "child_alive_after_heimdall_exit": alive})
summary = {}
for r in rows:
    k = f"rc={r['heimdall_rc']} child_started={r['child_started']} orphan={r['child_alive_after_heimdall_exit']}"
    summary[k] = summary.get(k, 0) + 1
json.dump({"bin": BIN, "n": N, "summary": summary, "rows": rows}, open(OUT, "w"), indent=1)
print(json.dumps(summary, indent=1))
orph = [r for r in rows if r["child_alive_after_heimdall_exit"]]
sys.exit(1 if orph else 0)
