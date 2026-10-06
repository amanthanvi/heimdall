"""Compare per-check statuses across review rounds and the author's recorded matrix.

usage: python3 -I summarize.py OUT.json ROUNDDIR... -- AUTHOR_RESULT_DIR...
Prints one line per (platform, task, subject): pass counts per round and the checks whose status
differs between any two runs (flaky) or from the author's records.
"""
import json
import sys
from pathlib import Path

args = sys.argv[1:]
out = Path(args[0])
sep = args.index("--")
rounds = [Path(a) for a in args[1:sep]]
authors = [Path(a) for a in args[sep + 1:]]


def load(d):
    res = {}
    for plat in ("darwin", "linux"):
        for f in sorted((d / plat).glob("T*.json")):
            task, subj = f.stem.split("-", 1)
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except ValueError:
                continue
            res[(plat, task, subj)] = {c["id"]: c["status"] for c in doc["checks"]}
    return res


R = [load(d) for d in rounds]
A = {}
for d in authors:  # later author dirs override earlier ones (t3v2 supersedes matrix T3)
    A.update(load(d))
keys = sorted(set().union(*[set(r) for r in R]))
summary = []
for k in keys:
    runs = [r.get(k) for r in R]
    ids = sorted(set().union(*[set(x or {}) for x in runs]))
    counts = [None if x is None else sum(1 for v in x.values() if v == "pass") for x in runs]
    flaky = [i for i in ids if len({(x or {}).get(i) for x in runs if x is not None}) > 1]
    a = A.get(k)
    vs_author = [i for i in ids if a is not None and any(x is not None and x.get(i) != a.get(i) for x in runs)]
    errors = sorted({i for x in runs if x for i, v in x.items() if v == "error"})
    fails = sorted({i for x in runs if x for i, v in x.items() if v != "pass"})
    row = {"platform": k[0], "task": k[1], "subject": k[2], "total": len(ids), "pass_per_round": counts,
           "author_pass": None if a is None else sum(1 for v in a.values() if v == "pass"),
           "flaky_checks": flaky, "differs_from_author": vs_author, "error_checks": errors,
           "non_pass_checks": fails}
    summary.append(row)
    print("%-6s %s %-12s pass/round=%s author=%s flaky=%s vs_author=%s errors=%s" % (
        k[0], k[1], k[2], counts, row["author_pass"], flaky, vs_author, errors))
out.write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
