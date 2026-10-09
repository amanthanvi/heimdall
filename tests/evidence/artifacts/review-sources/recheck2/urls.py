"""List every URL the fetcher subcommands would GET and whether it is listed verbatim in pins.json."""
import importlib.util, json, re, sys
tool, pins_path = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("fp", tool)
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)
pins = json.load(open(pins_path))
blob = json.dumps(pins)
listed = set(re.findall(r'https://[^"\s\\)]+', blob))
rows = []
for s in pins["sources"] + pins.get("auxiliary_sources", []):
    u = fp.fetch_url_for(s)
    rows.append(("fetch", s["id"], u))
    if fp.GITHUB_PERMALINK.match((s.get("pin") or {}).get("permalink", "") or ""):
        uu, ref = fp.upstream_url_for(s)
        rows.append(("upstream", s["id"], uu))
for t in pins.get("tag_pins", []):
    rows.append(("tags", t["repo"] + " " + t["tag"], "https://github.com/%s.git/info/refs?service=git-upload-pack" % t["repo"]))
seen = set()
for kind, i, u in rows:
    if (kind, u) in seen:
        continue
    seen.add((kind, u))
    status = "listed" if u in listed else "NOT-LISTED"
    print(kind, i, status, u)
