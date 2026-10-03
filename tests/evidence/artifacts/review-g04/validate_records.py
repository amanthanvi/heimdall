#!/usr/bin/env python3
"""Review-g04: validate tests/evidence/g04-*.json against record.schema.json and the
gate-probe convention in tests/evidence/README.md (verdict required when observed_result is a
non-null object; self-test/smoke records carry no product requirement IDs)."""
import glob, json, os, sys
import jsonschema
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
schema = json.load(open(os.path.join(REPO, "tests/evidence/record.schema.json")))
v = jsonschema.Draft202012Validator(schema)
bad = 0
for p in sorted(glob.glob(os.path.join(REPO, "tests/evidence/g04-*.json"))):
    r = json.load(open(p))
    errs = [e.message for e in v.iter_errors(r)]
    notes = []
    o = r.get("observed_result")
    if isinstance(o, dict) and o.get("verdict") not in ("pass", "fail", "inconclusive"):
        notes.append("gate-probe convention: observed_result.verdict missing")
    if "smoke" in r.get("case_id", "").lower() and r.get("requirement_ids"):
        notes.append("gate-probe convention: smoke/self-test record carries product requirement IDs %s" % r["requirement_ids"])
    if r.get("status") == "blocked" and not r.get("blocked_on"):
        notes.append("blocked without blocked_on")
    if r.get("status") == "blocked" and r.get("observed_result") is not None:
        notes.append("blocked but observed_result non-null")
    print("%s schema=%s %s" % (os.path.basename(p), "valid" if not errs else "INVALID:" + ";".join(errs), "; ".join(notes) or "convention-ok"))
    bad += bool(errs)
sys.exit(1 if bad else 0)
