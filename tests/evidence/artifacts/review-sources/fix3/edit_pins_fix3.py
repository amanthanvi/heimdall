#!/usr/bin/env python3
"""M00-T02-fix3: the edits applied to docs/sources/pins.json, kept for provenance.

Run once from the repository root, on the pins.json of 3622c56, with `python3 -I`:
  1. n13: add `upstream` {url, ref} to each of the 7 GitHub sources (S16-S19, S27, S29, S34), inserted
     after `fetched_url`. The values are not typed here: they come from fetch_pins.upstream_url_for(),
     the function `fetch_pins.py upstream` uses to build the URL it GETs.
  2. n2, n3, n5: reopen_conditions[0] and [1] and reproducibility.verify say the single rule that
     README and ADR-0003 say (off-pin and GONE and the exit-4 re-read policy).
  3. fix3_edited_at_utc.
The file is rewritten with json.dumps(indent=1) + "\n", the format it already had.
"""
import json
import sys

sys.path.insert(0, "docs/sources/tools")
import fetch_pins as fp  # noqa: E402

P = "docs/sources/pins.json"
d = json.load(open(P, encoding="utf-8"))

# 1. n13
done = []
for idx, s in enumerate(d["sources"]):
    if not fp.GITHUB_PERMALINK.match(s.get("pin", {}).get("permalink", "") or ""):
        continue
    assert "upstream" not in s, s["id"]
    url, ref = fp.upstream_url_for(s)
    new = {}
    for k, v in s.items():
        new[k] = v
        if k == "fetched_url":
            new["upstream"] = {"url": url, "ref": ref}
    assert "upstream" in new, s["id"]
    d["sources"][idx] = new
    done.append((s["id"], url, ref))
assert [x[0] for x in done] == ["S16", "S17", "S18", "S19", "S27", "S29", "S34"], done

# 2. rule text
RULE0_OLD_START = "`fetch_pins.py compare` against docs/sources/fetch-baseline.json"
assert d["reopen_conditions"][0].startswith(RULE0_OLD_START)
d["reopen_conditions"][0] = (
    "`fetch_pins.py compare` against docs/sources/fetch-baseline.json (or fetch-baseline-aux.json) classifies a "
    "source cited by a gate that is still open as CONTENT (normalized text changed), GONE (HTTP 404 or 410, after "
    "one confirming re-run) or MISSING; read docs/sources/snapshots/<id>.txt.gz to see what the pin said. "
    "primary_same=no is the off-pin flag (the second file does not reproduce the pinned primary hash): compare "
    "always prints such a line and exits 5 when nothing worse was found. Against the baseline, off-pin with class "
    "RAW_ONLY or MARKER_ONLY means the text equals the pin and only the raw bytes of a raw-primary source moved: "
    "that is pin maintenance (run `verify`, then re-pin with a dated note), not drift, and not a reopen. An "
    "off-pin normalized-primary source is CONTENT, so it is drift. MARKER_ONLY, and RAW_ONLY with primary_same=yes, "
    "are not drift. FETCH_FAILED means re-run, not drift, unless the same source is FETCH_FAILED on runs at least "
    "24 h apart: then treat it as GONE and investigate."
)
assert d["reopen_conditions"][1].startswith("`fetch_pins.py upstream` reports a GitHub source drifted")
d["reopen_conditions"][1] = (
    "`fetch_pins.py upstream` exits 2 (a GitHub source drifted on the branch its spec URL names and lost a quoted "
    "fragment or has none to check, or its file is gone), or exits 4 (drifted, quotes intact, claim not re-read) "
    "for a source cited by a gate that is still open and the re-read shows that the claim changed. Exit 4 does not "
    "show that the claim still holds. Before anyone relies on `main` for a source cited by a still-open gate, read "
    "the branch file against the claim and record the outcome (date, `claim re-read: holds` or `changed`) in the "
    "source's note; the pinned permalink stays the citation of record until then (on 2026-10-09 S16, S17, S18 and "
    "S34 had drifted on main with all fragments present; their claims were not re-read)."
)
old_verify = d["reproducibility"]["verify"]
assert "(exit 0 = all IDENTICAL; 4 = text identical, only raw bytes or date markers moved; 3 = a fetch failed; 2 = CONTENT change or missing source;" in old_verify
d["reproducibility"]["verify"] = old_verify.replace(
    "(exit 0 = all IDENTICAL; 4 = text identical, only raw bytes or date markers moved; 3 = a fetch failed; "
    "2 = CONTENT change or missing source;",
    "(exit 0 = all IDENTICAL and none off-pin; 4 = text identical, only raw bytes or date markers moved, every "
    "source on-pin; 5 = off-pin (a source's primary_same=no) with nothing worse; 3 = a fetch failed; "
    "2 = CONTENT change, GONE (404/410) or missing source;",
)
assert d["reproducibility"]["verify"] != old_verify

# 3
d["fix3_edited_at_utc"] = "2026-10-31"

with open(P, "w", encoding="utf-8") as f:
    f.write(json.dumps(d, indent=1) + "\n")
for i, u, r in done:
    print(i, r, u)
