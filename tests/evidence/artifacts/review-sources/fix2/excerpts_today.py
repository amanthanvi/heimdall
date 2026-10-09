#!/usr/bin/env python3
"""M00-T02-fix2 helper: check each listed source's pins.json excerpt fragments
against a directory of freshly generated snapshots (today's text), using the
repository fetcher's excerpt_fragments() and loose() matching (docs/sources/tools/fetch_pins.py).

Usage: python3 -I excerpts_today.py <repo_root> <snapshot_dir> <id> [<id> ...]
Exit 0 = every fragment found, 2 = at least one missing.
"""
import gzip
import importlib.util
import json
import os
import sys

root, sdir = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("fetch_pins", os.path.join(root, "docs/sources/tools/fetch_pins.py"))
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)
with open(os.path.join(root, "docs/sources/pins.json")) as f:
    d = json.load(f)
by = {s["id"]: s for s in d["sources"] + d.get("auxiliary_sources", [])}
rc = 0
for i in sys.argv[3:]:
    with gzip.open(os.path.join(sdir, i + ".txt.gz"), "rb") as g:
        txt = fp.loose(g.read().decode("utf-8"))
    frs = fp.excerpt_fragments(by[i]["excerpt"])
    miss = [p for p in frs if fp.loose(p) not in txt]
    print(i, "today's text: %d/%d excerpt fragments present" % (len(frs) - len(miss), len(frs)))
    for p in miss:
        print("   missing:", repr(p[:100]))
    if miss:
        rc = 2
sys.exit(rc)
