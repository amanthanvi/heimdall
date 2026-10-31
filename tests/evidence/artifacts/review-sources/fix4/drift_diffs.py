#!/usr/bin/env python3
"""M00-T02-fix4: word-level differences between each pinned copy and the live page, for the drift ledger.

Usage (repository root): <python> -I -B drift_diffs.py <fresh_snapshots_dir> <fresh_fetch_result.json>
  - For every source with a committed snapshot (27 spec sources, A01-A04): the committed snapshot
    (docs/sources/snapshots/<id>.txt.gz, normalized text of the pin) against the fresh snapshot of the same id
    from <fresh_snapshots_dir>. All differing word runs are printed (each clipped to 500 characters).
  - For the 7 GitHub sources: GET the pinned-commit raw file (pin_v2.fetched_url) and the branch raw file
    (upstream.url), normalize both with the tool's normalizer, and print the differing word runs. Only
    the 5 sources whose branch blob differs from the pin have a diff.
Read-only: GET only, no file is written. Exit 0 = ran to the end, 1 = a fetch or an input file failed.
The output is the input of the ledger docs/sources/drift-2026-10-31.md; it is not a claim check by itself.
"""
import difflib
import gzip
import json
import os
import sys

sys.path.insert(0, "docs/sources/tools")
import fetch_pins as fp  # noqa: E402

snapdir, resfile = sys.argv[1], sys.argv[2]
pins = json.load(open("docs/sources/pins.json", encoding="utf-8"))
res = {r["id"]: r for r in json.load(open(resfile, encoding="utf-8"))["results"]}
bad = 0


def show(label, old, new):
    ops = [(t, " ".join(old[a:b]), " ".join(new[c:d])) for t, a, b, c, d in
           difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes() if t != "equal"]
    print("== %s: %d changed word runs" % (label, len(ops)))
    for t, o, n in ops:
        print("  %-7s - %s" % (t, o[:500]))
        print("  %-7s + %s" % ("", n[:500]))


for s in pins["sources"] + pins["auxiliary_sources"]:
    i = s["id"]
    if s["pin_v2"].get("snapshot"):
        old_p = os.path.join("docs/sources/snapshots", i + ".txt.gz")
        new_p = os.path.join(snapdir, i + ".txt.gz")
        if not os.path.exists(new_p):
            print("== %s: no fresh snapshot (fetch status %s)" % (i, res.get(i, {}).get("http_status")))
            bad += 1
            continue
        old = gzip.decompress(open(old_p, "rb").read()).decode("utf-8").split()
        new = gzip.decompress(open(new_p, "rb").read()).decode("utf-8").split()
        if old == new:
            print("== %s: text identical to the committed snapshot" % i)
        else:
            show("%s pinned snapshot -> live page" % i, old, new)
    elif s.get("upstream"):
        a = fp.http_get(s["pin_v2"]["fetched_url"])
        b = fp.http_get(s["upstream"]["url"])
        if a["status"] != 200 or b["status"] != 200:
            print("== %s: GET failed (pinned %s, branch %s)" % (i, a["status"], b["status"]))
            bad += 1
            continue
        if fp.git_blob_sha1(a["body"]) == fp.git_blob_sha1(b["body"]):
            print("== %s: branch %s equals the pinned blob" % (i, s["upstream"]["ref"]))
            continue
        old = fp.normalize(a["body"], "text/markdown", s["pin_v2"]["fetched_url"]).split()
        new = fp.normalize(b["body"], "text/markdown", s["upstream"]["url"]).split()
        show("%s pinned commit -> branch %s" % (i, s["upstream"]["ref"]), old, new)
sys.exit(1 if bad else 0)
