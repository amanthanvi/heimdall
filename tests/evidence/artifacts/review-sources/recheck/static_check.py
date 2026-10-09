#!/usr/bin/env python3
"""M00-T02-recheck: offline consistency checks of the committed M00-T02 artifacts.

Read-only. Usage (repo root): python3 -I <this> <repo_root>
Checks:
  1. pins.json pin_v2 vs fetch-baseline.json (raw, normalized, markers, status, fetched_url).
  2. fetch-baseline.json vs fetch-repeat.json.
  3. snapshot files: gz sha256 vs pins.json; decompressed text sha256 vs pin_v2 normalized hash.
  4. primary-kind counts and lists vs ADR claims (15 raw / 19 normalized).
  5. ADR table rows (id, url, primary kind, 16-hex prefix) vs pins.json.
  6. GitHub permalink pins: 40-hex commit, blob sha present, baseline git_blob_matches_pin.
  7. Canary scan over docs/sources and the ADR.
"""
import gzip, hashlib, json, os, re, sys

root = sys.argv[1]
P = lambda *a: os.path.join(root, *a)
pins = json.load(open(P("docs/sources/pins.json")))
base = {x["id"]: x for x in json.load(open(P("docs/sources/fetch-baseline.json")))["results"]}
rep = {x["id"]: x for x in json.load(open(P("docs/sources/fetch-repeat.json")))["results"]}
problems = []
out = {"checks": {}}

# 1
c1 = []
for s in pins["sources"]:
    v, b = s["pin_v2"], base.get(s["id"])
    if b is None:
        problems.append((s["id"], "missing in baseline")); continue
    row = {"id": s["id"]}
    for k in ("raw_body_sha256", "normalized_text_sha256"):
        row[k] = v.get(k) == b.get(k)
    row["markers"] = v.get("markers") == b.get("markers")
    row["status200"] = b.get("http_status") == 200 and v.get("http_status") == 200
    row["fetched_url"] = v.get("fetched_url") == b.get("fetched_url")
    if not all(row[k] for k in row if k != "id"):
        problems.append((s["id"], "pin_v2 vs baseline mismatch", row))
    c1.append(row)
out["checks"]["pin_v2_vs_baseline_all_equal"] = sum(all(r[k] for k in r if k != "id") for r in c1)

# 2
c2 = 0
for i, b in base.items():
    r = rep.get(i)
    if r and r["raw_body_sha256"] == b["raw_body_sha256"] and r["normalized_text_sha256"] == b["normalized_text_sha256"] and r["markers"] == b["markers"]:
        c2 += 1
    else:
        problems.append((i, "baseline vs repeat differ"))
out["checks"]["baseline_vs_repeat_identical"] = c2
out["checks"]["baseline_retrieved"] = [min(x["retrieved_at_utc"] for x in base.values()), max(x["retrieved_at_utc"] for x in base.values())]
out["checks"]["repeat_retrieved"] = [min(x["retrieved_at_utc"] for x in rep.values()), max(x["retrieved_at_utc"] for x in rep.values())]

# 3
snaps = []
for s in pins["sources"]:
    sn = s["pin_v2"].get("snapshot")
    if not sn:
        continue
    path = P(sn["path"])
    data = open(path, "rb").read()
    gz_ok = hashlib.sha256(data).hexdigest() == sn["gz_sha256"]
    text = gzip.decompress(data)
    norm_ok = hashlib.sha256(text).hexdigest() == s["pin_v2"]["normalized_text_sha256"]
    snaps.append({"id": s["id"], "gz_sha256_matches_pin": gz_ok, "text_sha256_matches_pin_v2": norm_ok, "chars": len(text.decode("utf-8"))})
    if not (gz_ok and norm_ok):
        problems.append((s["id"], "snapshot mismatch", gz_ok, norm_ok))
out["checks"]["snapshots"] = {"count": len(snaps), "all_ok": all(x["gz_sha256_matches_pin"] and x["text_sha256_matches_pin_v2"] for x in snaps), "ids": [x["id"] for x in snaps]}
files = sorted(f for f in os.listdir(P("docs/sources/snapshots")) if f.endswith(".txt.gz"))
out["checks"]["snapshot_files_on_disk"] = len(files)

# 4
raw = [s["id"] for s in pins["sources"] if s["pin_v2"]["primary"] == "raw_body_sha256"]
nrm = [s["id"] for s in pins["sources"] if s["pin_v2"]["primary"] == "normalized_text_sha256"]
out["checks"]["primary_raw"] = raw
out["checks"]["primary_normalized"] = nrm
rr = [s["id"] for s in pins["sources"] if s["pin_v2"].get("raw_reproduced_vs_v1_pin") is True]
out["checks"]["raw_reproduced_vs_v1_true"] = rr

# 5
adr = open(P("docs/decisions/0003-source-pins.md")).read()
rows = re.findall(r"^\| (S\d\d) \| (\S+) \| .*? \| (raw|norm) `([0-9a-f]{16})` \| (\w+) \| (\w+) \|$", adr, re.M)
adr_bad = []
byid = {s["id"]: s for s in pins["sources"]}
for i, url, kind, pref, copy, claim in rows:
    s = byid[i]; v = s["pin_v2"]
    h = v["raw_body_sha256"] if kind == "raw" else v["normalized_text_sha256"]
    exp_kind = "raw" if v["primary"] == "raw_body_sha256" else "norm"
    exp_copy = "snapshot" if v.get("snapshot") else "permalink"
    ok = url == s["url"] and h.startswith(pref) and kind == exp_kind and copy == exp_copy and claim == s["claim_status"]
    if not ok:
        adr_bad.append(i)
out["checks"]["adr_rows_parsed"] = len(rows)
out["checks"]["adr_rows_mismatch"] = adr_bad

# 6
gh = []
for s in pins["sources"]:
    pl = s["pin"].get("permalink")
    if pl:
        m = re.match(r"^https://github\.com/[^/]+/[^/]+/blob/([0-9a-f]{40})/", pl)
        gh.append({"id": s["id"], "commit40": bool(m), "blob": s["pin"].get("blob_sha"), "baseline_blob_matches": base[s["id"]].get("git_blob_matches_pin")})
out["checks"]["github_pins"] = gh

# 7
CANARY = ("HEIMDALL_" + "CANARY").encode()  # built at runtime so this file holds no canary-shaped literal
hits = 0
for dp, dn, fn in os.walk(P("docs/sources")):
    for f in fn:
        b = open(os.path.join(dp, f), "rb").read()
        if f.endswith(".gz"):
            b = gzip.decompress(b)
        hits += b.count(CANARY)
hits += adr.count(CANARY.decode())
out["checks"]["canary_hits"] = hits

out["problems"] = problems
print(json.dumps(out, indent=1))
sys.exit(1 if problems else 0)
