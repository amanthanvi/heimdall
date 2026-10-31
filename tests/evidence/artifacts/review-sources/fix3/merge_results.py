#!/usr/bin/env python3
"""M00-T02-fix3: merge two fetch result files for the live compare (provenance of the merged file).

Usage: python3 -I -B merge_results.py <base.json> <patch.json> <out.json>
Every record of <patch.json> replaces the record with the same id in <base.json>. The merged file is a
synthetic combination (it was never produced by a single `fetch` run) and is labelled as such in the README.
"""
import json
import sys

base, patch, out = sys.argv[1:4]
b = json.load(open(base))
p = {r["id"]: r for r in json.load(open(patch))["results"]}
b["results"] = [p.get(r["id"], r) for r in b["results"]]
b["tool"] = "fetch_pins.py (merged: %d records replaced by merge_results.py)" % len(p)
with open(out, "w") as f:
    json.dump(b, f, indent=1, sort_keys=True)
    f.write("\n")
print("replaced", sorted(p))
