import json, sys, glob, os
base = "$HOME/GitRepos/heimdall/tests/evidence/artifacts/review-g02-harness-r3"
pat = sys.argv[1] if len(sys.argv) > 1 else "*"
for plat in ("darwin", "linux"):
    for f in sorted(glob.glob(os.path.join(base, plat, pat + ".json"))):
        r = json.load(open(f))
        lab = os.path.basename(f)[:-5]
        outs = []
        for c in r["observed_result"]["checks"]:
            fa = c.get("failed_assertions") or []
            first = ""
            if c["outcome"] != "pass":
                first = (fa[0].get("desc") if fa and isinstance(fa[0], dict) else str(fa[:1]) or c.get("error") or "")[:150]
            outs.append("%s=%s%s" % (c["id"].split(".")[1][:22], c["outcome"], (" [" + first + "]") if first else ""))
        print(plat, lab, r["observed_result"]["summary"]["pass"], "/", r["observed_result"]["summary"]["total"])
        for o in outs:
            if "=pass" not in o:
                print("    ", o)
