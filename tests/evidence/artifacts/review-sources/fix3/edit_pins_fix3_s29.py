#!/usr/bin/env python3
"""M00-T02-fix3: add the dated drift note for S29 to docs/sources/pins.json (kept for provenance).

Run from the repository root with `python3 -I -B`, after edit_pins_fix3.py. It was run twice: first with the
first live `upstream` run of the task (20:28Z), then again with the retained final run (20:39Z) whose outputs are
in this directory; both runs saw the same blobs and fragment counts, so only the timestamp in the note changed. Source of the facts: the
`upstream` run of this task (data_upstream.json: HEAD blob, pinned blob, fragments 1/2) and a one-off read of
the S29 README on HEAD against the pinned README (3 changed regions), both on 2026-10-31 (the diff read is saved as 62_s29_head_vs_pinned.out, produced by s29_head_vs_pinned.py). The note records an
observation; it does not reopen anything (that is for the owner of a gate that cites S29).
"""
import json

P = "docs/sources/pins.json"
d = json.load(open(P, encoding="utf-8"))
up = {r["id"]: r for r in json.load(open("tests/evidence/artifacts/review-sources/fix3/data_upstream.json"))["results"]}
u = up["S29"]
assert u["result"] == "drifted" and (u["fragments_found"], u["fragments_total"]) == (1, 2)
s29 = [s for s in d["sources"] if s["id"] == "S29"][0]
assert s29["note"] == "" or s29["note"].startswith("Drift on HEAD observed"), "S29 note is not the original or a previous run of this script"
assert u["pinned_blob"] == s29["pin"]["blob_sha"]
s29["note"] = (
    "Drift on HEAD observed by `fetch_pins.py upstream` at %s (M00-T02-fix3: fix3/data_upstream.json; the README diff is in fix3/62_s29_head_vs_pinned.out): the HEAD blob is %s, "
    "not the pinned blob %s. The pin is the commit permalink de8dc97; `fetch` reads that commit and its blob sha1 matches. "
    "Quoted excerpt fragments on HEAD: 1/2. The missing one is \"Development requires Bun 1.4.1 or later and Zig 0.16.0.\": "
    "HEAD says Zig 0.17.0. The README on HEAD differs from the pinned one in 3 places (the words anomalyco/opentui are "
    "replaced by https://opentui.com, an added paragraph about the skill and `npx skills update`, and the Zig version). Claim "
    "re-read (diff read by the fix3 author, not independently reviewed): the claim as stated here (TS-facing TUI candidate; "
    "native/runtime packaging considerations) is unchanged and still supported on HEAD; only the Zig requirement moved. "
    "`upstream` exits 2 while the fragment is missing from HEAD. Whether a gate that is still open relies on the Zig "
    "version is not checked here."
) % (u["retrieved_at_utc"], u["branch_blob"], u["pinned_blob"])
d["fix3_edited_at_utc"] = "2026-10-31"
with open(P, "w", encoding="utf-8") as f:
    f.write(json.dumps(d, indent=1) + "\n")
print(s29["note"][:200])
