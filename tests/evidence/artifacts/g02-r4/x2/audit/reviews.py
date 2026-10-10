import json, sys
from collections import Counter
for path in sys.argv[1:]:
    st = {}
    for l in open(path):
        e = json.loads(l)
        if e["type"] == "started": st[e["key"]] = e["label"]
        elif e["type"] == "result" and st.get(e["key"], "").startswith("review-"):
            r = e["result"]; c = Counter(d["severity"] for d in r["defects"])
            print(st[e["key"]][7:], f"blocker={c['blocker']} major={c['major']} minor={c['minor']}",
                  f"conf={r['spec_conformance']} tests={r['test_quality']} clarity={r['clarity']}")
            for d in r["defects"]:
                if d["severity"] != "minor": print("    ", d["severity"].upper(), d["description"][:300].replace("\n", " "))
