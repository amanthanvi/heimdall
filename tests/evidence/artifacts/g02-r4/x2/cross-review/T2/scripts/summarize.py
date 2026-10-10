#!/usr/bin/env python3
"""Print the probe matrix (markdown) from probe.py's results JSON.

usage: python3 -I summarize.py RESULTS.json
"""
import json
import sys

d = json.load(open(sys.argv[1], encoding="utf-8"))
r = d["results"]
CELLS = ["T2-go-opus1", "T2-go-opus2", "T2-go-sonnet1", "T2-rust-opus1", "T2-rust-opus2", "T2-rust-sonnet1"]
BASES = ["base-go", "base-rust"]


def row(label, vals):
    print("| %s | %s |" % (label, " | ".join(vals)))


print("| probe | " + " | ".join(c.replace("T2-", "") for c in CELLS) + " |")
print("|---|" + "---|" * len(CELLS))

p1 = r["P1_differential"]
row("P1 random profiles vs reference model (%d profiles, seed %d; %d with findings)" % (
    p1["profiles"], p1["seed"], p1["profiles_with_findings"]),
    ["%d/%d match" % (p1["profiles"] - p1["per_bin"][c]["failed_profiles"], p1["profiles"]) for c in CELLS])
row("P1 plain-mode exit equals --json exit (%d runs)" % p1["per_bin"][CELLS[0]]["plain_runs"],
    ["yes" if not p1["per_bin"][c]["plain_exit_mismatch"] else "NO" for c in CELLS])
row("P1 stderr empty on success", ["yes" if p1["per_bin"][c]["stderr_nonempty_runs"] == 0 else "NO (%d)" %
                                   p1["per_bin"][c]["stderr_nonempty_runs"] for c in CELLS])
p2 = r["P2_determinism"]["per_bin"]
row("P2 same output in 40 runs (interleaved groups)", ["1 distinct, correct" if p2[c]["distinct_outputs"] == 1 and
                                                       p2[c]["runs_not_matching_reference"] == 0 else "NO" for c in CELLS])
p3 = r["P3_edge_profiles"]["per_bin"]
row("P3 hand-made edge profiles (%d)" % len(p3[CELLS[0]]), ["%d/%d" % (sum(x["ok"] for x in p3[c]), len(p3[c])) for c in CELLS])
p4 = r["P4_non_echo"]["per_bin"]
row("P4 no profile value (incl. canary-prefixed) on stdout/stderr, 4 runs",
    ["none echoed" if all(not v["echoed_values"] for v in p4[c].values()) else "ECHOED" for c in CELLS])
row("P4 ids printed without --json", ["no" if not any(v.get("ids_in_plain_output") for v in p4[c].values()) else "yes" for c in CELLS])
p5 = r["P5_inputs_vs_show"]
row("P5 inputs (%d) where lint differs from show / >2 s / echo" % len(p5["inputs"]),
    [str(sum(1 for x in p5["per_bin"][c] if x["problems"])) for c in CELLS])
p6 = r["P6_argv_vs_show"]
row("P6 argv templates (%d) where lint differs from show" % len(p6["templates"]),
    [", ".join(x["argv"] for x in p6["per_bin"][c] if not x["match"]) or "0" for c in CELLS])
p7 = r["P7_resources"]
worst = {}
for c in CELLS:
    rows = [x for x in p7["per_bin"][c]]
    worst[c] = (max(x["lint"]["secs"] for x in rows), max(x["lint"]["max_rss_mib"] for x in rows),
                all(x["lint"]["within_K15"] for x in rows),
                sum(1 for x in rows if not x["lint"]["matches_reference"]))
row("P7 1 MiB adversarial profiles (%d): worst wall s / peak RSS MiB, K15" % len(p7["cases"]),
    ["%.2f s / %.0f MiB, %s" % (w[0], w[1], "within" if w[2] else "EXCEEDED") for c, w in worst.items()])
row("P7 cases where lint output != reference (all = show rejects too)",
    [str(worst[c][3]) for c in CELLS])
p8 = r["P8_K12_closed_stdout"]["per_bin"]
row("P8 closed-stdout exit parity (5 cases)", ["%d/5" % sum(x["parity"] for x in p8[c]) for c in CELLS])
p9 = r["P9_no_writes"]["per_bin"]
row("P9 files changed in cwd/profile dir/HOME/TMPDIR", [str(len(p9[c]["changed"])) for c in CELLS])
p10 = r["P10_stdin_not_read"]["per_bin"]
row("P10 stdin pipe held open: exit, seconds", ["%s, %.2f" % (p10[c]["exit"], p10[c]["secs"]) for c in CELLS])
p12 = r["P12_existing_behaviour"]
row("P12 commands (%d) whose output differs from the baseline" % len(p12["commands"]),
    [str(p12["per_bin"][c]["commands_differing"]) for c in CELLS])

print()
print("P7 per case (lint --json; worst of %d runs): secs / peak RSS MiB" % d["meta"]["reps"])
print()
print("| case | " + " | ".join(c.replace("T2-", "") for c in BASES + CELLS) + " |")
print("|---|" + "---|" * (len(BASES) + len(CELLS)))
for k, case in enumerate(p7["cases"]):
    vals = []
    for c in BASES + CELLS:
        x = p7["per_bin"][c][k]
        if "lint" in x:
            v = x["lint"]
            vals.append("%s: %.2f / %.0f" % (v["exit"], v["secs"], v["max_rss_mib"]))
        else:
            v = x["show"]
            vals.append("show %s: %.2f / %.0f" % (v["exit"], v["secs"], v["max_rss_mib"]))
    print("| %s (%d B, %d findings, %d key paths) | %s |" % (case["case"], case["bytes"], case["findings"],
                                                           case["key_paths"], " | ".join(vals)))
