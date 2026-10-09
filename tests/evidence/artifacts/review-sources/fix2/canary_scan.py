#!/usr/bin/env python3
"""M00-T02-fix2: scan every modified or untracked file in the task's write scope (gz files decompressed) and every
snapshot for the canary prefix. Prints the count only, never a match's content.
Usage (repository root): python3 -I canary_scan.py   Exit 0 = no hits, 1 = hits.
"""
import gzip
import os
import subprocess

PREFIX = b"HEIMDALL_" + b"CANARY_"
scope = ["docs/sources", "docs/decisions/0003-source-pins.md", "docs/compatibility/matrix.md",
         "tests/evidence/artifacts/review-sources/fix2"]
files = subprocess.run(["git", "ls-files", "-m", "-o", "--exclude-standard"] + scope,
                       capture_output=True, text=True, check=True).stdout.split()
snaps = ["docs/sources/snapshots/" + f for f in os.listdir("docs/sources/snapshots") if f.endswith(".gz")]
hits = []
for f in sorted(set(files + snaps)):
    data = open(f, "rb").read()
    if f.endswith(".gz"):
        data = gzip.decompress(data)
    if PREFIX in data:
        hits.append(f)
print("files scanned: %d  canary-prefix hits: %d %s" % (len(set(files + snaps)), len(hits), hits))
raise SystemExit(1 if hits else 0)
