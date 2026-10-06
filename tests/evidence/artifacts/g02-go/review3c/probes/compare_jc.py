#!/usr/bin/env python3
"""Compare two sigjob3c_probe result JSONs (round-3b build vs round-3c build) on the
behavioural fields only (no pids, timings, tty bytes).

usage: compare_jc.py A.json B.json
Prints DIFF lines for scenarios whose behavioural fields differ, then a count.
Scenarios present in only one file are listed as ONLY_A / ONLY_B.
"""
import json
import sys

FIELDS_IT = ("selfstop_logged", "shell_reported_stop", "prompt_back", "got_line_after_fg", "got_line",
             "restopped_after_fg", "shell_reported_stop")


def norm(r):
    out = {}
    for k in ("deliveries", "per_trial_deliveries", "final_rc", "producer_status", "sh_c_pipeline_rc",
              "shell_reported_stop", "error", "blocked", "exception", "selfstops", "conts",
              "child_alive_after", "heimdall_alive_after", "stop_reported", "got_line_after_fg",
              "hp_hp_pgid_equals_child_pgid", "hp_pgid_equals_child_pgid", "heimdall_alive_after_signals",
              "child_alive_2s_after_hangup", "heimdall_alive_2s_after_hangup"):
        if k in r:
            out[k] = r[k]
    if "start" in r and r["start"]:
        out["start_disp"] = r["start"].get("disp")
    for i, it in enumerate(r.get("iterations", [])):
        for f in FIELDS_IT:
            if f in it:
                out["it%d.%s" % (i, f)] = it[f]
        b = it.get("child_beats_1s_while_reported_stopped")
        if b is not None:
            out["it%d.child_ran_while_reported_stopped" % i] = b > 0
    for f in ("child_beats_while_job_stopped", "child_beats_1s_while_reported_stopped"):
        if f in r:
            out[f + ">0"] = r[f] > 0
    return out


a, b = (json.load(open(p)) for p in sys.argv[1:3])
ka = {(r["scenario"], r["shell"], r["layout"]): r for r in a["results"]}
kb = {(r["scenario"], r["shell"], r["layout"]): r for r in b["results"]}
n = 0
for k in ka:
    if k not in kb:
        print("ONLY_A", *k)
        continue
    x, y = norm(ka[k]), norm(kb[k])
    for f in sorted(set(x) | set(y)):
        if x.get(f) != y.get(f):
            n += 1
            print("DIFF", *k, f, "A=%s" % json.dumps(x.get(f)), "B=%s" % json.dumps(y.get(f)))
for k in kb:
    if k not in ka:
        print("ONLY_B", *k)
print("scenarios_compared=%d differing_fields=%d" % (len(set(ka) & set(kb)), n))
