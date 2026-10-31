#!/usr/bin/env python3
"""M00-T02-fix4: consistency checks for the drift ledger and the other fix4 edits.

Usage (repository root): python3 -I -B ledger_check.py [<data_dir>]
  <data_dir> (optional) holds data_fresh.json and data_upstream.json from a live run of run_fix4.sh. With it, the set of
  sources that must have a ledger row is recomputed from the raw results (fetch_pins.classify against
  docs/sources/fetch-baseline.json and fetch-baseline-aux.json, and the `upstream` results), not from printed text.
Checks (each prints OK or FAIL):
  1. every ledger row has a known class and one of the three dispositions; row ids are unique
  2. the counts table in the ledger equals the counts of the rows
  3. [with data] the ledger ids equal: spec CONTENT + aux CONTENT + upstream drifted ids (any exit 4 or 2 source)
  4. S34 and S29: the required dispositions are present in the ledger, pins.json, ADR-0003 (S34 also in matrix row 13)
  5. M5 in the matrix says "login in v3"
  6. no pinned value changed: `pin` and `pin_v2` of every source, `candidates` and `tag_pins` equal the git HEAD version
     of pins.json; only `note` text, `reopen_conditions` and `fix4_edited_at_utc` differ from the fix3 state
  7. no home path or user name appears in the files fix4 wrote
Exit 0 = all OK, 1 = at least one FAIL.
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, "docs/sources/tools")
import fetch_pins as fp  # noqa: E402

LEDGER = "docs/sources/drift-2026-10-31.md"
DISP = ("claim unchanged, pin kept", "qualification recorded", "changed/inconclusive: gate owner to re-read")
CLASSES = ("CONTENT", "CONTENT (aux)", "Branch drift", "Lost fragment")
fails = []


def check(name, ok, detail=""):
    print(("OK   " if ok else "FAIL ") + name + ((" - " + detail) if detail and not ok else ""))
    if not ok:
        fails.append(name)


text = open(LEDGER, encoding="utf-8").read()
rows = []
for line in text.split("\n"):
    m = re.match(r"^\| ((?:S|A)\d\d) \| ([^|]+) \| (.*) \| ([^|]+) \|$", line)
    if m:
        rows.append((m.group(1), m.group(2).strip(), m.group(3), m.group(4).strip()))
ids = [r[0] for r in rows]
check("ledger rows parsed", len(rows) > 0, "no rows")
check("row ids unique", len(ids) == len(set(ids)))
check("every class is known", all(r[1] in CLASSES for r in rows), str([r[1] for r in rows if r[1] not in CLASSES]))
check("every disposition is known (the prefix before ';')", all(r[3].split(";")[0].strip() in DISP for r in rows),
      str([r[3] for r in rows if r[3].split(";")[0].strip() not in DISP]))
check("every row names a citing document or gate", all(re.search(r"spec|plan|matrix|ADR|research|§", r[2]) for r in rows))

n_by_disp = {d: sum(1 for r in rows if r[3].split(";")[0].strip() == d) for d in DISP}
n_by_class = {c: sum(1 for r in rows if r[1] == c) for c in CLASSES}
want = {
    "rows": len(rows),
    "spec content": n_by_class["CONTENT"],
    "aux content": n_by_class["CONTENT (aux)"],
    "branch": n_by_class["Branch drift"],
    "lost": n_by_class["Lost fragment"],
}
counts_ok = (
    ("| Rows (changed sources) | %d |" % want["rows"]) in text
    and re.search(r"Class `CONTENT`, spec sources \| %d:" % want["spec content"], text)
    and re.search(r"Class `CONTENT`, auxiliary sources \| %d:" % want["aux content"], text)
    and re.search(r"Class branch drift \(quotes intact\) \| %d:" % want["branch"], text)
    and re.search(r"Class lost fragment \| %d:" % want["lost"], text)
    and ("| Disposition: claim unchanged, pin kept | %d |" % n_by_disp[DISP[0]]) in text
    and re.search(r"Disposition: qualification recorded \| %d:" % n_by_disp[DISP[1]], text)
    and ("| Disposition: changed/inconclusive: gate owner to re-read | %d |" % n_by_disp[DISP[2]]) in text
)
check("counts table equals the rows", bool(counts_ok), "rows=%s dispositions=%s classes=%s" % (len(rows), n_by_disp, n_by_class))
print("     rows=%d dispositions=%s classes=%s" % (len(rows), list(n_by_disp.values()), list(n_by_class.values())))

data_dir = sys.argv[1] if len(sys.argv) > 1 else None
if data_dir and os.path.exists(os.path.join(data_dir, "data_fresh.json")):
    fresh = {r["id"]: r for r in json.load(open(os.path.join(data_dir, "data_fresh.json")))["results"]}
    up = json.load(open(os.path.join(data_dir, "data_upstream.json")))["results"]
    need = set()
    for base in ("docs/sources/fetch-baseline.json", "docs/sources/fetch-baseline-aux.json"):
        for r in json.load(open(base))["results"]:
            cls, _ = fp.classify(r, fresh.get(r["id"]))
            if cls in (fp.CONTENT, fp.GONE, fp.MISSING, fp.FETCH_FAILED):
                need.add(r["id"])
    for r in up:
        if r["result"] != "same":
            need.add(r["id"])
    check("ledger ids equal the sources that CONTENT/GONE/MISSING/FETCH_FAILED or upstream drift flag",
          set(ids) == need, "only in ledger: %s; only in data: %s" % (sorted(set(ids) - need), sorted(need - set(ids))))
    print("     data ids (%d): %s" % (len(need), ",".join(sorted(need))))
else:
    print("SKIP ledger ids against raw results (no data_fresh.json in the data dir)")

pins_text = open("docs/sources/pins.json", encoding="utf-8").read()
pins = json.loads(pins_text)
S = {s["id"]: s for s in pins["sources"]}
row = {r[0]: r for r in rows}
check("S34 row: qualification recorded and G07 retained", "S34" in row and row["S34"][3].startswith("qualification recorded") and "G07" in row["S34"][3])
check("S29 row: qualification recorded", "S29" in row and row["S29"][3].startswith("qualification recorded"))
check("ledger has the S34 and S29 sections", "## S34: default pairing grants" in text and "## S29: OpenTUI README requires Zig 0.17.0" in text)
n34, n29 = S["S34"]["note"], S["S29"]["note"]
check("pins.json S34 note: dated, qualification, G07, pin stays baseline",
      all(k in n34 for k in ("2026-10-31", "qualification recorded", "G07", "immutable pin stays the experiment baseline")))
check("pins.json S29 note: orchestrator disposition, no re-test",
      all(k in n29 for k in ("2026-10-31", "orchestrator", "qualification recorded", "not re-tested", "ADR-0002 section 3 and 3.3")))
adr = open("docs/decisions/0003-source-pins.md", encoding="utf-8").read()
check("ADR-0003 has the S34 line", "S34 (T3 Code environment authentication" in adr and "retained and reopened" in adr)
check("ADR-0003 has the S29 line", "S29 (OpenTUI): orchestrator disposition" in adr and "no re-test" in adr)
mx = open("docs/compatibility/matrix.md", encoding="utf-8").read()
check("matrix row 13 has the S34 source note", "**Source note (2026-10-31):** S34" in mx)
m5 = [ln for ln in mx.split("\n") if ln.startswith("| M5 ")]
check("matrix M5 says login in v3 only", len(m5) == 1 and "login in v3 only" in m5[0] and "signs and logs in" not in m5[0])

head = json.loads(subprocess.run(["git", "show", "HEAD:docs/sources/pins.json"], capture_output=True, text=True, check=True).stdout)
Hs = {s["id"]: s for s in head["sources"] + head["auxiliary_sources"]}
Ns = {s["id"]: s for s in pins["sources"] + pins["auxiliary_sources"]}
same_pins = all(Hs[i].get("pin") == Ns[i].get("pin") and Hs[i].get("pin_v2") == Ns[i].get("pin_v2") for i in Hs)
check("pin and pin_v2 of all 38 sources equal git HEAD", same_pins and set(Hs) == set(Ns))
check("candidates and tag_pins equal git HEAD", head["candidates"] == pins["candidates"] and head["tag_pins"] == pins["tag_pins"])
check("excerpt and claim fields equal git HEAD", all(Hs[i].get("excerpt") == Ns[i].get("excerpt") and Hs[i].get("claim") == Ns[i].get("claim") for i in Hs))

written = [LEDGER, "docs/sources/README.md", "docs/decisions/0003-source-pins.md", "docs/compatibility/matrix.md",
           "docs/sources/pins.json", "docs/sources/tools/fetch_pins.py"]
fix4 = "tests/evidence/artifacts/review-sources/fix4"
written += [os.path.join(fix4, f) for f in sorted(os.listdir(fix4)) if f.endswith((".md", ".py", ".sh", ".out", ".json"))]
bad = []
pat = re.compile("|".join(["/Us" + "ers/", "/ho" + "me/[a-z]", "C:" + r"\\" + "Us" + "ers", "aman" + "thanvi"]), re.I)  # pieces joined, so this file does not contain the strings it looks for
for f in written:
    for n, ln in enumerate(open(f, encoding="utf-8", errors="replace").read().split("\n"), 1):
        if pat.search(ln):
            bad.append("%s:%d" % (f, n))
check("no home path or user name in the files fix4 wrote", not bad, ", ".join(bad[:8]))
sys.exit(1 if fails else 0)
