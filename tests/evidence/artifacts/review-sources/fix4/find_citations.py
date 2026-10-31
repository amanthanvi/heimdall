#!/usr/bin/env python3
"""M00-T02-fix4: list where each source id (S01-S34, A01-A04) is cited in the repository.

Usage (repository root): python3 -I -B find_citations.py
Read-only, offline. Searches tracked, non-generated documents (spec.md, plan.md, docs/**, progress.md, tests/evidence/README.md,
tests/evidence/*.json top-level records) but not docs/sources/** (the pin files themselves) and not tests/evidence/artifacts/**.
A spec acceptance scenario id (A01-A36 in spec.md section 17 and plan.md) is NOT an auxiliary source id; the auxiliary ids are
only counted where the line says "auxiliary", "pins.json", "Pins" column context, "A01-A04", or in docs/decisions/0003.
Output: file:line  section-heading  ids  (clipped line)
"""
import re
import subprocess
import sys

FILES = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
SKIP_PREFIX = ("docs/sources/", "tests/evidence/artifacts/", "prototypes/")
SRC = re.compile(r"(?<![A-Za-z0-9-])S(0[1-9]|[12][0-9]|3[0-4])(?![0-9])")
AUX = re.compile(r"(?<![A-Za-z0-9-])A0[1-4](?![0-9])")
for f in FILES:
    if f.startswith(SKIP_PREFIX) or not f.endswith((".md", ".json", ".py", ".ps1", ".sh")):
        continue
    if f.startswith("tests/evidence/") and f.count("/") > 2:
        continue
    try:
        lines = open(f, encoding="utf-8").read().split("\n")
    except Exception:
        continue
    heading = ""
    for n, line in enumerate(lines, 1):
        if line.startswith("#"):
            heading = line.strip("# ").strip()[:60]
        ids = ["S" + m.group(1) for m in SRC.finditer(line)]
        if f != "spec.md" and f != "plan.md":
            ids += [m.group(0) for m in AUX.finditer(line)]
        if ids:
            print("%s:%d  [%s]  %s  |  %s" % (f, n, heading, ",".join(sorted(set(ids))), line.strip()[:170]))
