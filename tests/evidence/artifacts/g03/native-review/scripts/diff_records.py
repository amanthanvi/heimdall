"""Compare promoted records with their source run records (review M00-T04-G03-native-review).
Usage: python3 -I diff_records.py PROMOTED_DIR SOURCE_DIR GLOB"""
import json, sys, glob, os

def flat(o, p=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from flat(v, f"{p}.{k}" if p else k)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from flat(v, f"{p}[{i}]")
    else:
        yield p, o

prom, src, pat = sys.argv[1:4]
for f in sorted(glob.glob(os.path.join(prom, pat))):
    s = os.path.join(src, os.path.basename(f))
    a = json.load(open(f, encoding="utf-8"))
    print(f"== {os.path.basename(f)} status={a.get('status')} verdict={(a.get('observed_result') or {}).get('verdict')}")
    if not os.path.exists(s):
        print("   (no source record)")
        continue
    b = json.load(open(s, encoding="utf-8"))
    fa, fb = dict(flat(a)), dict(flat(b))
    diffs = [k for k in sorted(set(fa) | set(fb)) if fa.get(k, "<absent>") != fb.get(k, "<absent>")]
    for k in diffs[:25]:
        va, vb = str(fa.get(k, "<absent>"))[:110], str(fb.get(k, "<absent>"))[:110]
        print(f"   {k}: promoted={va!r} source={vb!r}")
    if len(diffs) > 25:
        print(f"   ... {len(diffs)} differing leaves")
