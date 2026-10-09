#!/usr/bin/env python3
"""M00-T02-fix2 offline consistency check (repository files only, no network).

Checks:
  1. pins.json pin_v2 (S01-S34) equals docs/sources/fetch-baseline.json (status, raw, normalized, markers, URL);
     auxiliary A01-A04 pin_v2 equals docs/sources/fetch-baseline-aux.json.
  2. every snapshot file: gz sha256 equals pins.json, decompressed text sha256 equals pin_v2 normalized hash.
  3. primary kinds: 14 raw (7 GitHub + S01-S05, S10, S30), 20 normalized; S23 normalized with primary_change.
  4. legacy labels: no `pin.value` holds a 64-hex hash; the 6 .md sources carry legacy_raw_body_sha256_v1 equal to
     the v2 raw hash and no legacy_text_sha256_unreproducible; raw_reproduced_vs_v1_pin true for exactly 21.
  5. tag_pins: every entry has 40-hex ref_sha and commit.
  6. ADR-0003 source and auxiliary tables: id, URL, primary kind and 16-hex prefix equal pins.json.
  7. matrix.md: every S/A id exists in pins.json, every G03-Sxx id exists in the G03 source pins, every cited
     evidence record exists, and every observation-table row whose status cell starts with a status word matches
     the record(s) it cites (status, and verdict where the cell gives one).
Usage: python3 -I static_check_fix2.py <repo_root>   Exit 0 = all pass, 1 = failures.
"""
import gzip
import hashlib
import itertools
import json
import os
import re
import sys

root = sys.argv[1]
P = lambda *a: os.path.join(root, *a)
fails, notes = [], []


def check(cond, msg):
    (notes if cond else fails).append(("ok   " if cond else "FAIL ") + msg)


pins = json.load(open(P("docs/sources/pins.json")))
base = {r["id"]: r for r in json.load(open(P("docs/sources/fetch-baseline.json")))["results"]}
baux = {r["id"]: r for r in json.load(open(P("docs/sources/fetch-baseline-aux.json")))["results"]}
srcs, aux = pins["sources"], pins.get("auxiliary_sources", [])

# 1
for s, b in [(s, base[s["id"]]) for s in srcs] + [(a, baux[a["id"]]) for a in aux]:
    v = s["pin_v2"]
    same = all(v[k] == b[k] for k in ("http_status", "raw_body_sha256", "normalized_text_sha256", "markers", "fetched_url"))
    check(same, "%s pin_v2 equals its baseline record" % s["id"])
# 2
for s in srcs + aux:
    sn = s["pin_v2"].get("snapshot")
    if not sn:
        continue
    data = open(P(sn["path"]), "rb").read()
    check(hashlib.sha256(data).hexdigest() == sn["gz_sha256"], "%s snapshot gz sha256" % s["id"])
    check(hashlib.sha256(gzip.decompress(data)).hexdigest() == s["pin_v2"]["normalized_text_sha256"],
          "%s snapshot text = normalized pin" % s["id"])
snapfiles = sorted(f for f in os.listdir(P("docs/sources/snapshots")) if f.endswith(".txt.gz"))
check(len(snapfiles) == 31, "31 snapshot files present (found %d)" % len(snapfiles))
# 3
raw = sorted(s["id"] for s in srcs if s["pin_v2"]["primary"] == "raw_body_sha256")
want_raw = sorted(["S01", "S02", "S03", "S04", "S05", "S10", "S30", "S16", "S17", "S18", "S19", "S27", "S29", "S34"])
check(raw == want_raw, "raw-primary set is the 14 expected ids (%s)" % ",".join(raw))
s23 = [s for s in srcs if s["id"] == "S23"][0]["pin_v2"]
check(s23["primary"] == "normalized_text_sha256" and "primary_change" in s23, "S23 normalized-primary with primary_change")
check(all(a["pin_v2"]["primary"] == "normalized_text_sha256" for a in aux), "A01-A04 normalized-primary")
# 4
hexre = re.compile(r"\b[0-9a-f]{64}\b")
for s in srcs:
    check(not hexre.search(s["pin"].get("value", "")), "%s pin.value holds no 64-hex hash" % s["id"])
for i in ("S24", "S25", "S26", "S31", "S32", "S33"):
    s = [x for x in srcs if x["id"] == i][0]
    check("legacy_text_sha256_unreproducible" not in s["pin"] and
          s["pin"].get("legacy_raw_body_sha256_v1") == s["pin_v2"]["raw_body_sha256"] and
          s["pin_v2"].get("raw_reproduced_vs_v1_pin") is True, "%s v1 hash relabelled as reproduced raw .md hash" % i)
rr = [s["id"] for s in srcs if s["pin_v2"].get("raw_reproduced_vs_v1_pin") is True]
check(len(rr) == 21, "raw_reproduced_vs_v1_pin true for 21 sources (found %d)" % len(rr))
check("WITHDRAWN" in pins["method"] and "all 34 stable" in pins["method"], "method marks the v1 '10 minutes' sentence withdrawn")
check("Mdocdate" not in json.dumps(pins["reopen_conditions"]), "reopen conditions use v2 terms")
# 5
h40 = re.compile(r"^[0-9a-f]{40}$")
for t in pins["tag_pins"]:
    check(bool(h40.match(t.get("ref_sha") or "")) and bool(h40.match(t.get("commit") or "")),
          "tag %s %s resolved to 40-hex ids" % (t["repo"], t["tag"]))
# 6
adr = open(P("docs/decisions/0003-source-pins.md"), encoding="utf-8").read()
for s in srcs + aux:
    m = re.search(r"^\| %s \| (\S+) \|[^|]*\| (raw|norm) `([0-9a-f]{16})`" % s["id"], adr, re.M)
    kind = "raw" if s["pin_v2"]["primary"] == "raw_body_sha256" else "norm"
    ok = bool(m) and m.group(1) == s["url"] and m.group(2) == kind and s["pin_v2"][
        "raw_body_sha256" if kind == "raw" else "normalized_text_sha256"].startswith(m.group(3))
    check(ok, "ADR row %s matches pins.json (url, kind, prefix)" % s["id"])
# 7
mx = open(P("docs/compatibility/matrix.md"), encoding="utf-8").read()
ids = {s["id"] for s in srcs + aux}
for i in sorted(set(re.findall(r"(?<![-\w])([SA]\d\d)\b", mx))):  # not P-A05 or G03-S01
    check(i in ids, "matrix id %s exists in pins.json" % i)
g03 = {s["id"] for s in json.load(open(P("tests/evidence/artifacts/g03/sources/source-pins.json")))["sources"]}
for i in sorted(set(re.findall(r"\b(G03-S\d\d)\b", mx))):
    check(i in g03, "matrix id %s exists in G03 source pins" % i)


def expand(name):
    m = re.match(r"^(.*)\{([^}]*)\}(.*)$", name)
    if not m:
        return [name]
    return list(itertools.chain.from_iterable(expand(m.group(1) + p + m.group(3)) for p in m.group(2).split(",")))


recs = {}
for name in set(re.findall(r"`((?:g0[234]|m00)-[^`]*?\.json)`", mx)):
    for f in expand(name):
        if "*" in f:
            continue
        exists = os.path.exists(P("tests/evidence", f))
        check(exists, "matrix cites existing record %s" % f)
        if exists:
            recs[f] = json.load(open(P("tests/evidence", f)))
STAT = ("not_started", "in_progress", "blocked", "implemented_unverified", "verified", "deferred_with_decision")
for line in mx.splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) < 4 or not re.match(r"^[WLM]\d+$", cells[0]):
        continue
    files = [f for n in re.findall(r"`([^`]*?\.json)`", cells[2]) for f in expand(n)]
    st = cells[3]
    m = re.match(r"^(%s)(?: / (pass|fail|inconclusive))?" % "|".join(STAT), st)
    if not m or not files or any("*" in f for f in files) or re.match(r"^\d", st):
        continue
    for f in files:
        r = recs.get(f)
        if r is None:
            continue
        o = r.get("observed_result")
        v = o.get("verdict") if isinstance(o, dict) else None
        ok = r["status"] == m.group(1) and (m.group(2) is None or m.group(2) == v or len(files) > 1)
        check(ok, "matrix %s status cell '%s' vs %s (%s/%s)" % (cells[0], st[:40], f, r["status"], v))
    # multi-record cells: an ordered verdict list ("verified / pass, pass, **fail**") is checked file by file
    vl = re.match(r"^(%s) / ((?:\*\*)?(?:pass|fail|inconclusive)(?:\*\*)?(?:, (?:\*\*)?(?:pass|fail|inconclusive)(?:\*\*)?)+)$"
                  % "|".join(STAT), st)
    if vl and len(files) > 1:
        verdicts = [x.strip("* ") for x in vl.group(2).split(",")]
        got = [(recs[f]["status"], recs[f]["observed_result"].get("verdict")) for f in files if f in recs]
        check(got == [(vl.group(1), x) for x in verdicts], "matrix %s ordered verdicts %s vs records %s" % (cells[0], verdicts, got))


# glob cells (M4, M5): count statuses over every matching record
def glob_records(pattern):
    rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
    return [json.load(open(P("tests/evidence", f))) for f in sorted(os.listdir(P("tests/evidence"))) if rx.match(f)]


for line in mx.splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) < 4 or cells[0] not in ("M4", "M5"):
        continue
    pat = re.findall(r"`([^`]*\*[^`]*\.json)`", cells[2])[0]
    rs = glob_records(pat)
    if cells[0] == "M4":
        tally = sorted((r["status"], (r.get("observed_result") or {}).get("verdict")) for r in rs)
        want = sorted([("verified", "pass")] * 5 + [("in_progress", "inconclusive")] * 2)
        check(tally == want and cells[3].startswith("5 verified / pass, 2 in_progress / inconclusive"),
              "matrix M4 tally %s vs cell '%s'" % (tally, cells[3]))
    else:
        rs = [r for r in rs if "lock-probe-smoke" not in r["case_id"]]
        check(len(rs) == 6 and all(r["status"] == "blocked" for r in rs) and cells[3].startswith("blocked"),
              "matrix M5: %d non-smoke g04-macos probe records, statuses %s" % (len(rs), sorted({r["status"] for r in rs})))

# main table: label not-tested, floor blocked, gate status allowed; a row whose note names a blocked input or cites
# a blocked record must be blocked
notes_by_row = {}
cur = None
for line in mx.split("## Mechanism observations")[0].split("### Row notes")[1].splitlines():
    m = re.match(r"^(\d+)\. ", line)
    if m:
        cur = int(m.group(1))
        notes_by_row[cur] = ""
    if cur:
        notes_by_row[cur] += line + "\n"
main = [c for c in ([x.strip() for x in ln.strip().strip("|").split("|")] for ln in mx.splitlines())
        if len(c) == 9 and re.match(r"^\d+$", c[0])]
check(len(main) == 16, "main table has 16 rows (found %d)" % len(main))
for c in main:
    row, label, gate, floor = int(c[0]), c[5], c[6], c[7]
    check(label == "not-tested", "row %d label is not-tested (%s)" % (row, label))
    check(floor == "blocked", "row %d G01 floor is blocked (%s)" % (row, floor))
    check(gate in STAT, "row %d gate evidence uses an allowed status (%s)" % (row, gate))
    note = notes_by_row.get(row, "")
    cited = [f for n in re.findall(r"`((?:g0[234]|m00)-[^`]*?\.json)`", note) for f in expand(n) if "*" not in f]
    blocked_cited = [f for f in cited if f in recs and recs[f]["status"] == "blocked"]
    if "**Blocked on:**" in note or blocked_cited or re.search(r"`blocked`: W|`blocked` \(L", note):
        check(gate == "blocked", "row %d names a blocked input/record and is blocked (%s)" % (row, gate))
    if gate == "not_started":
        check("**Evidence:** none" in note and "**Blocked on:**" not in note,
              "row %d not_started only with no evidence and no named blocked input" % row)
for n in notes + fails:
    print(n)
print("checks: %d ok, %d failed" % (len(notes), len(fails)))
sys.exit(1 if fails else 0)
