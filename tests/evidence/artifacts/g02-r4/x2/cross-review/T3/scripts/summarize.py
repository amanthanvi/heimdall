"""M00-T05-r4-x2-xrev-T3: probe matrix from the per-build probe records.

Usage: python3 -I summarize.py <probe-out-dir> <matrix.md> <matrix.json> [<merged-out-dir>]
Cell value: 'pass', 'FAIL n' (n failing steps), 'skip' (not applicable), 'ERR' (probe error).
"""
import json
import sys
from pathlib import Path

ORDER = ["base-go-pinned", "base-go", "T3-go-opus1", "T3-go-opus2", "T3-go-sonnet1",
         "base-rust", "T3-rust-opus1", "T3-rust-opus2", "T3-rust-sonnet1"]


def main():
    src, md_out, js_out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    recs = {}
    for b in ORDER:
        f = src / ("%s.json" % b)
        if f.exists():
            recs[b] = json.loads(f.read_text(encoding="utf-8"))
            # later partial re-runs (<build>-<P..>.json) replace the probes they contain
            for g in sorted(src.glob("%s-P*.json" % b)):
                part = json.loads(g.read_text(encoding="utf-8"))
                ids = {p["probe"] for p in part["probes"]}
                recs[b]["probes"] = [p for p in recs[b]["probes"] if p["probe"] not in ids] + part["probes"]
                recs[b].setdefault("reruns", []).append({"file": g.name, "probes": sorted(ids),
                                                         "started_utc": part["started_utc"]})
    builds = [b for b in ORDER if b in recs]
    rows, keys = {}, []
    for b in builds:
        for p in recs[b]["probes"]:
            k = (p["probe"], p["variant"])
            if k not in rows:
                rows[k] = {}
                keys.append(k)
            if p.get("skipped"):
                v = "skip"
            elif p.get("probe_error"):
                v = "ERR"
            elif p.get("ok"):
                v = "pass"
            else:
                v = "FAIL %d" % p.get("failed_steps", 0)
            first = None
            for s in p.get("steps", []):
                if not s.get("ok"):
                    first = {"step": s.get("step"), "issues": s.get("issues"), "rc": s.get("rc"),
                             "restore": s.get("restore"), "hits": s.get("hits")}
                    break
            rows[k][b] = {"v": v, "first_failure": first}
    pos = {k: i for i, k in enumerate(keys)}
    keys.sort(key=lambda k: (k[0], pos[k]))
    lines = ["| probe | variant | " + " | ".join(builds) + " |", "|---|---|" + "---|" * len(builds)]
    for k in keys:
        lines.append("| %s | %s | " % k + " | ".join(rows[k].get(b, {}).get("v", "-") for b in builds) + " |")
    md_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    js_out.write_text(json.dumps({"builds": {b: recs[b]["darwin_arm64_sha256"] for b in builds},
                                  "rows": [{"probe": k[0], "variant": k[1], "results": rows[k]} for k in keys]},
                                 ensure_ascii=False, indent=1), encoding="utf-8")
    if len(sys.argv) > 4:
        mo = Path(sys.argv[4])
        mo.mkdir(parents=True, exist_ok=True)
        for b in builds:
            (mo / ("%s.json" % b)).write_text(json.dumps(recs[b], ensure_ascii=False, indent=1), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
