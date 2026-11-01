#!/usr/bin/env python3
"""Validate every evidence record in tests/evidence/ against record.schema.json.

minischema.validate(schema, value) returns a list of error strings and does not
raise, so this script fails (exit 1) when any record yields a non-empty list, and
also when it finds no records at all. A self-check first proves that a known-bad
record is rejected, so a validator that accepts everything cannot pass.
Run with `python3 -I tools/validation/validate-records.py` from the repo root.
"""
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tests", "g02"))
import minischema  # noqa: E402

schema_path = os.path.join(ROOT, "tests", "evidence", "record.schema.json")
with open(schema_path, encoding="utf-8") as f:
    schema = json.load(f)

# Self-check: a record missing required fields with an invalid status must fail.
if not minischema.validate(schema, {"status": "not-a-status"}):
    print("validate-records: self-check failed: an invalid record was accepted")
    sys.exit(1)

paths = sorted(
    p
    for p in glob.glob(os.path.join(ROOT, "tests", "evidence", "*.json"))
    if os.path.basename(p) != "record.schema.json"
)
if not paths:
    print("validate-records: no evidence records found")
    sys.exit(1)

invalid = 0
for path in paths:
    with open(path, encoding="utf-8") as f:
        try:
            record = json.load(f)
        except json.JSONDecodeError as exc:
            invalid += 1
            print(f"INVALID {os.path.relpath(path, ROOT)}: not JSON ({exc.msg})")
            continue
    errors = minischema.validate(schema, record)
    if errors:
        invalid += 1
        print(f"INVALID {os.path.relpath(path, ROOT)}: {len(errors)} error(s)")
        for err in errors[:5]:
            print(f"  - {err}")

print(f"validate-records: {len(paths)} records, {invalid} invalid")
sys.exit(1 if invalid else 0)
