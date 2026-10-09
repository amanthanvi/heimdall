#!/usr/bin/env python3
"""M00-T02-recheck: every double-quoted fragment (>=12 chars) of every pins.json
excerpt must occur in that source's pinned copy (committed snapshot, or the body
fetched at the pinned commit for the 7 GitHub sources). Detects misattribution
of the S26 kind. Fragments are split at '...'/'…' and matched loosely (quote style,
markdown emphasis/links, whitespace, the normalizer's space before ':').

Usage: python3 -I excerpt_all.py <repo_root> <content_dir>
"""
import gzip, json, os, re, sys

root, cdir = sys.argv[1], sys.argv[2]
def loose(t):
    # word-sequence match: drop all punctuation/markup (quotes, colons, bullets,
    # parentheses, markdown links/emphasis); only the order of words must match.
    t = t.replace('","', " ").replace("’", "'")
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    return " ".join(re.sub(r"[^0-9a-z']+", " ", t.lower()).replace("'", "").split())
pins = json.load(open(os.path.join(root, "docs/sources/pins.json")))
copies = {}
for s in pins["sources"]:
    sn = s["pin_v2"].get("snapshot")
    if sn:
        copies[s["id"]] = gzip.open(os.path.join(root, sn["path"]), "rb").read().decode("utf-8")
    else:
        p = os.path.join(cdir, s["id"])
        if os.path.exists(p):
            copies[s["id"]] = open(p, "rb").read().decode("utf-8")
L = {i: loose(t) for i, t in copies.items()}
rows, miss = [], []
for s in pins["sources"]:
    i = s["id"]
    if i not in L:
        rows.append({"id": i, "status": "no pinned copy available"}); continue
    fr = re.findall(r'"([^"]{12,})"', s["excerpt"])
    parts = [p for f in fr for p in re.split(r"\s*(?:\.\.\.|…)\s*", f) if len(p) >= 12]
    found = [p for p in parts if loose(p) in L[i]]
    nf = [p for p in parts if loose(p) not in L[i]]
    elsewhere = {p[:60]: [j for j in L if j != i and loose(p) in L[j]] for p in nf}
    rows.append({"id": i, "fragments": len(parts), "found": len(found), "not_found": [p[:100] for p in nf], "not_found_but_in": elsewhere})
    if nf:
        miss.append(i)
print(json.dumps(rows, indent=1))
print("sources=%d with_fragments=%d all_found=%d missing_in=%s" % (len(rows), sum(1 for r in rows if r.get("fragments")), sum(1 for r in rows if r.get("fragments") and not r["not_found"]), miss))
sys.exit(1 if miss else 0)
