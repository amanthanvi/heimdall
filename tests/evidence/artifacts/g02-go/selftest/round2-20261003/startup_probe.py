#!/usr/bin/env python3
"""Startup time and peak RSS: 10 warm-up + 50 measured runs per command.
Usage: startup_probe.py <bin> <repo>"""
import os, statistics, subprocess, sys, time
BIN, REPO = sys.argv[1], sys.argv[2]
cases = {"version --json": [BIN, "version", "--json"],
         "profile show large-100": [BIN, "profile", "show", "--file", os.path.join(REPO, "tests/fixtures/g02/profiles/large-100.toml"), "--json"]}
for name, argv in cases.items():
    ts, rss = [], []
    for i in range(60):
        t0 = time.perf_counter()
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"})
        _, st, ru = os.wait4(p.pid, 0)
        el = time.perf_counter() - t0
        if i >= 10:
            ts.append(el * 1000); rss.append(ru.ru_maxrss / (1024 * 1024) if sys.platform == "darwin" else ru.ru_maxrss / 1024)
        assert os.waitstatus_to_exitcode(st) == 0
    print("%-24s median %.2f ms  p90 %.2f ms  max RSS %.1f MiB (n=50)" % (name, statistics.median(ts), sorted(ts)[44], max(rss)))
