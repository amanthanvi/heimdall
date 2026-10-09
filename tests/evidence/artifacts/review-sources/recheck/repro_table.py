#!/usr/bin/env python3
"""M00-T02-recheck: per-source reproducibility table, committed pin vs today's run.

Usage: python3 -I repro_table.py <repo_root> <run1.json> <run2.json>
Prints a markdown table. Classification is computed from hashes/status; the
explanatory text for each class is fixed below and was checked by hand
(snapdiff.py for S28, marker values for S06/S09/S12, 403 page title for OpenAI).
"""
import json, os, sys

root, r1p, r2p = sys.argv[1:4]
pins = json.load(open(os.path.join(root, "docs/sources/pins.json")))
r1 = {x["id"]: x for x in json.load(open(r1p))["results"]}
r2 = {x["id"]: x for x in json.load(open(r2p))["results"]}
print("| ID | Primary | Pinned primary (16) | HTTP today | Raw = pin | Norm = pin | Markers = pin | run3 = run4 | Result / classification |")
print("|---|---|---|---|---|---|---|---|---|")
counts = {}
for s in pins["sources"]:
    i, v, x, y = s["id"], s["pin_v2"], r1[s["id"]], r2[s["id"]]
    prim = "raw" if v["primary"] == "raw_body_sha256" else "norm"
    ph = v["raw_body_sha256"] if prim == "raw" else v["normalized_text_sha256"]
    raw = x["raw_body_sha256"] == v["raw_body_sha256"]
    nrm = x["normalized_text_sha256"] == v["normalized_text_sha256"]
    mk = x["markers"] == v["markers"]
    stable = x["raw_body_sha256"] == y["raw_body_sha256"] and x["normalized_text_sha256"] == y["normalized_text_sha256"]
    prim_ok = raw if prim == "raw" else nrm
    if x["http_status"] != 200:
        c = "NOT FETCHABLE: HTTP 403 'Vercel Security Checkpoint' (bot challenge) for pins UA, curl UA and curl binary; .md and HTML URLs. Snapshot is the only copy; content not re-verifiable from this host. Not a pin error."
    elif prim_ok and raw and mk:
        c = "MATCH (primary and raw identical)"
    elif prim_ok and not mk:
        c = "MATCH on primary (raw %s); `compare` still reports normalized_same=False because a date marker moved (%s). Compare gap: volatile markers counted as content." % ("identical" if raw else "differs", ", ".join(sorted(k for k in set(x["markers"]) | set(v["markers"]) if x["markers"].get(k) != v["markers"].get(k))))
    elif prim_ok:
        c = "MATCH on primary; raw differs (page chrome) - expected mutable doc"
    elif prim == "raw" and nrm:
        c = "PRIMARY MISMATCH, text identical: raw page bytes changed (site rebuild, -284 bytes), normalized text identical. Expected mutable doc; raw primary was too brittle for this HTML page (pin-kind choice)."
    elif i == "S26":
        c = "PRIMARY MISMATCH: content edit on 2026-10-08 (Last-Modified 23:50Z) to Fast-mode/data-residency text (+10 words, 12 ops, two copies of one passage); claim-relevant sections and all S26 excerpt quotes still present. Expected mutable doc; snapshot keeps the pinned text."
    elif i == "S28":
        c = "PRIMARY MISMATCH: only live counters changed (crates 6000+->6200+, stars, downloads; snapdiff 8 numeric tokens). Expected mutable doc, pre-labelled in pins.json S28 note; drift detector will keep firing."
    else:
        c = "PRIMARY MISMATCH (unclassified)"
    key = c.split(":")[0].split(" (")[0].split(" on primary")[0]
    counts[key] = counts.get(key, 0) + 1
    yn = lambda b: "yes" if b else "no"
    print("| %s | %s | `%s` | %s | %s | %s | %s | %s | %s |" % (i, prim, ph[:16], x["http_status"], yn(raw), yn(nrm), yn(mk), yn(stable), c))
print()
print("Counts: " + "; ".join("%s=%d" % kv for kv in sorted(counts.items())))
