#!/usr/bin/env python3
"""Summarise reviewer records: per record, per check outcome, first failing gating assertion (truncated),
failing non-gating observation count, and for k6e the per-form ok/first_failed_step and Q16 resumed_before_fg."""
import json, sys
from pathlib import Path
for plat_dir in sys.argv[1:]:
    for p in sorted(Path(plat_dir).glob("*.json")):
        try:
            d = json.loads(p.read_text())
        except Exception as e:
            print(p.name, "UNREADABLE", e); continue
        o = d["observed_result"]
        for c in o["checks"]:
            fg = [a for a in c["assertions"] if not a["ok"] and (a.get("gating", True) or a.get("precondition"))]
            ng = [a for a in c["assertions"] if not a["ok"] and not a.get("gating", True) and not a.get("precondition")]
            first = fg[0]["desc"][:150] if fg else ""
            print("%s/%s | %s | %s | gating_fail=%d nongating_fail=%d | %s" % (Path(plat_dir).name, p.stem, c["id"],
                  c["outcome"], len(fg), len(ng), first))
        k = o.get("observations", {}).get("k6e_child_self_stop")
        if k:
            for form, r in k.items():
                rb = [s.get("resumed_before_fg") for j in r.get("jobs", []) for s in j.get("stops", [])]
                print("    %s ok=%s not_run=%s resumed_before_fg=%s notice=%s" % (form, r.get("ok"), r.get("not_run"),
                      rb, r.get("notice_and_status")))
        k12 = o.get("observations", {}).get("k12_closed_stdout")
        if k12:
            print("    k12:", {a: (b["json"]["wait_status"], b["plain"]["wait_status"]) for a, b in k12.items()})
