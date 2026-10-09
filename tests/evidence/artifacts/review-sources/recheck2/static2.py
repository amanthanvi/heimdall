"""Offline consistency check of the fix2 working tree (recheck2). Reads repo files as data only."""
import gzip, hashlib, json, os, re, subprocess, sys

root = sys.argv[1]
J = lambda p: json.load(open(os.path.join(root, p)))
pins = J("docs/sources/pins.json")
head_pins = json.loads(subprocess.run(["git", "-C", root, "show", "HEAD:docs/sources/pins.json"], capture_output=True, check=True).stdout)
base = {x["id"]: x for x in J("docs/sources/fetch-baseline.json")["results"]}
rep = {x["id"]: x for x in J("docs/sources/fetch-repeat.json")["results"]}
aux = {x["id"]: x for x in J("docs/sources/fetch-baseline-aux.json")["results"]}
fails = []
def chk(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ((" :: " + detail) if detail and not ok else ""))
    if not ok:
        fails.append(name)

H40 = re.compile(r"^[0-9a-f]{40}$")
H64 = re.compile(r"^[0-9a-f]{64}$")
headsrc = {s["id"]: s for s in head_pins["sources"]}
prim_count = {}
for s in pins["sources"] + pins.get("auxiliary_sources", []):
    i = s["id"]
    v = s.get("pin_v2") or {}
    ref = base.get(i) or aux.get(i)
    chk(i + " has baseline", ref is not None)
    if not ref:
        continue
    p = v.get("primary")
    prim_count[p] = prim_count.get(p, 0) + 1
    chk(i + " primary kind valid", p in ("raw_body_sha256", "normalized_text_sha256"), str(p))
    for k in ("raw_body_sha256", "normalized_text_sha256"):
        chk(i + " pin_v2." + k + " == baseline", v.get(k) == ref.get(k), "%s vs %s" % (v.get(k), ref.get(k)))
        chk(i + " pin_v2." + k + " is 64-hex", bool(H64.match(v.get(k) or "")))
    if i in headsrc:
        hv = headsrc[i].get("pin_v2") or {}
        for k in ("raw_body_sha256", "normalized_text_sha256"):
            chk(i + " " + k + " unchanged vs HEAD", hv.get(k) == v.get(k))
        if hv.get("primary") != p:
            print("     note: %s primary changed %s -> %s; primary_change=%s" % (i, hv.get("primary"), p, json.dumps(v.get("primary_change"))[:200]))
    sn = v.get("snapshot")
    if sn:
        fp = os.path.join(root, sn["path"])
        data = open(fp, "rb").read()
        chk(i + " snapshot gz sha == pin", hashlib.sha256(data).hexdigest() == sn.get("gz_sha256"), sn.get("gz_sha256"))
        txt = gzip.decompress(data)
        chk(i + " snapshot text sha == baseline normalized", hashlib.sha256(txt).hexdigest() == ref["normalized_text_sha256"])
    pin = s.get("pin") or {}
    if pin.get("permalink"):
        m = re.match(r"^https://github\.com/[^/]+/[^/]+/blob/([0-9a-f]{40})/", pin["permalink"])
        chk(i + " permalink is a 40-hex commit", bool(m), pin["permalink"])
        chk(i + " baseline blob == pin blob", ref.get("git_blob_sha1") == pin.get("blob_sha"), "%s %s" % (ref.get("git_blob_sha1"), pin.get("blob_sha")))
    # legacy labels
    val = pin.get("value")
    if isinstance(val, str) and H64.match(val):
        print("     note: %s pin.value is still a bare 64-hex value %s" % (i, val[:16]))
print("primary kinds:", prim_count)
# baseline vs repeat unchanged
chk("fetch-baseline.json unchanged vs HEAD", subprocess.run(["git", "-C", root, "diff", "--quiet", "HEAD", "--", "docs/sources/fetch-baseline.json", "docs/sources/fetch-repeat.json"]).returncode == 0)
# tag pins
for t in pins.get("tag_pins", []):
    lab = "%s %s" % (t.get("repo"), t.get("tag"))
    chk("tag " + lab + " commit 40-hex", bool(H40.match(t.get("commit") or "")), str(t.get("commit")))
    chk("tag " + lab + " ref_sha 40-hex", bool(H40.match(t.get("ref_sha") or "")), str(t.get("ref_sha")))
    if t.get("annotated") is False:
        chk("tag " + lab + " lightweight => ref_sha == commit", t.get("ref_sha") == t.get("commit"))
    if t.get("annotated") is True:
        chk("tag " + lab + " annotated => ref_sha != commit", t.get("ref_sha") != t.get("commit"))
print("tag_pins fields:", sorted({k for t in pins.get("tag_pins", []) for k in t}))
# snapshot dir: files vs pins
snapfiles = sorted(f for f in os.listdir(os.path.join(root, "docs/sources/snapshots")) if f.endswith(".txt.gz"))
pinned = sorted(os.path.basename(s["pin_v2"]["snapshot"]["path"]) for s in pins["sources"] + pins.get("auxiliary_sources", []) if (s.get("pin_v2") or {}).get("snapshot"))
chk("snapshot files == pinned snapshot paths", snapfiles == pinned, "%s vs %s" % (snapfiles, pinned))
print("snapshot count", len(snapfiles))
print("FAILED:", len(fails))
sys.exit(1 if fails else 0)
