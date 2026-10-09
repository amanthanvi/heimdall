import json, glob, os, sys
root = sys.argv[1]
for p in sorted(glob.glob(os.path.join(root, "tests/evidence/*.json"))):
    if p.endswith("record.schema.json"):
        continue
    try:
        d = json.load(open(p))
    except Exception as e:
        print(os.path.basename(p), "JSON ERROR", e)
        continue
    o = d.get("observed_result") or {}
    v = o.get("verdict") if isinstance(o, dict) else None
    bo = d.get("blocked_on")
    keys = sorted(o.keys()) if isinstance(o, dict) else []
    sub = [k for k in keys if k.startswith("per_") or k in ("rows", "sub_probes", "subprobes", "probes")]
    print("%-55s status=%-22s verdict=%-12s blocked_on=%s" % (os.path.basename(p), d.get("status"), v, (str(bo)[:160] if bo else "-")))
    if sub:
        print("    per-row keys:", sub)
