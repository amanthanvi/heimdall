#!/usr/bin/env python3
"""Summarize sigjob3c_probe console lines (JSON per line) into a compact table.

usage: summarize_jc.py CONSOLE.txt [CONSOLE.txt ...]
Prints one line per scenario with the fields a reviewer compares across builds.
"""
import json
import sys

for path in sys.argv[1:]:
    print("==", path.rsplit("/", 1)[-1])
    for line in open(path):
        line = line.strip()
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        key = "%s %s %s" % (r["scenario"], r["shell"], r["layout"])
        bits = []
        if r.get("it") is not None:
            bits.append("it=" + ";".join(
                "stop=%s beats=%s got=%s restop=%s" % (
                    "Y" if i.get("shell_reported_stop") else "n", i.get("child_beats_1s_while_reported_stopped"),
                    "Y" if i.get("got_line_after_fg") else "n", "Y" if i.get("restopped_after_fg") else "n")
                for i in r["it"]))
        for f in ("deliveries", "per_trial_deliveries", "final_rc", "producer_status", "sh_c_pipeline_rc",
                  "shell_reported_stop", "error", "blocked", "exception"):
            v = r.get(f)
            if v is None:
                continue
            if f == "deliveries":
                v = ",".join("%s%d" % (k[3:6], n) for k, n in v.items())
            bits.append("%s=%s" % (f, v))
        print("%-46s %s" % (key, " ".join(bits)))
