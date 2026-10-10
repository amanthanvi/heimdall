"""Consolidate the X2 cell results (implementer report, evaluation, code review, usage) from the workflow
journals into one JSON file and one Markdown table.

usage: python3 -I aggregate.py OUT_JSON OUT_MD WF_DIR[=EXCLUDE,...] [WF_DIR...]

WF_DIRs are given oldest first; for each cell and role (impl/eval/review) the result of the latest
WF_DIR wins.  `=T1-go-opus1,...` after a WF_DIR drops those cells from that run (the contaminated T1
opus1 cells of x2c).  Usage numbers come from the implementer transcript of the winning impl result.
Home paths and canary values are scrubbed from everything written."""
import json, os, re, sys
from collections import Counter
from datetime import datetime

HOME = os.path.expanduser("~")


def scrub(v):
    if isinstance(v, str):
        return re.sub(r"HEIMDALL_CANARY_\w+", "HEIMDALL_CANARY_<redacted>", v.replace(HOME, "<home>"))
    if isinstance(v, list):
        return [scrub(x) for x in v]
    if isinstance(v, dict):
        return {k: scrub(x) for k, x in v.items()}
    return v


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def usage(path):
    calls = 0; t0 = t1 = None; seen = {}; model = None
    for l in open(path):
        e = json.loads(l)
        if e.get("timestamp"):
            t = ts(e["timestamp"]); t0 = t0 or t; t1 = t
        m = e.get("message") or {}
        if m.get("role") != "assistant":
            continue
        model = m.get("model") or model
        c = m.get("content")
        if isinstance(c, list):
            calls += sum(1 for x in c if isinstance(x, dict) and x.get("type") == "tool_use")
        u = m.get("usage")
        if u:  # streamed entries repeat one message id; keep the largest usage seen for it
            prev = seen.get(m.get("id"), (0, 0, 0, 0))
            seen[m.get("id")] = tuple(max(a, b) for a, b in zip(prev, (
                u.get("input_tokens", 0), u.get("cache_creation_input_tokens", 0),
                u.get("cache_read_input_tokens", 0), u.get("output_tokens", 0))))
    return {"model": model, "tool_calls": calls,
            "input_tokens_incl_cache": sum(v[0] + v[1] + v[2] for v in seen.values()),
            "output_tokens": sum(v[3] for v in seen.values()),
            "wall_min": round((t1 - t0).total_seconds() / 60, 1) if t0 else None}


cells = {}
for spec in sys.argv[3:]:
    wf, _, excl = spec.partition("=")
    excl = set(filter(None, excl.split(",")))
    lab = {}; aid = {}
    for l in open(os.path.join(wf, "journal.jsonl")):
        e = json.loads(l)
        if e["type"] == "started":
            lab[e["key"]] = e["label"]; aid[e["key"]] = e.get("agentId")
        elif e["type"] == "result" and e.get("result"):
            label = lab.get(e["key"], "")
            role, _, cell = label.partition("-")
            cell = cell[:-len("-retry")] if cell.endswith("-retry") else cell
            if role not in ("impl", "eval", "review") or cell in excl:
                continue
            c = cells.setdefault(cell, {})
            c[role] = e["result"]
            c[role + "_source"] = {"workflow": os.path.basename(wf), "agent": e.get("agentId") or aid.get(e["key"])}
            if role == "impl":
                c["usage"] = usage(os.path.join(wf, f"agent-{c['impl_source']['agent']}.jsonl"))

rows = []
for cell in sorted(cells):
    c = cells[cell]; t, lang, run = cell.split("-")
    ev = c.get("eval") or {}; rv = c.get("review") or {}; im = c.get("impl") or {}
    sev = Counter(d["severity"] for d in rv.get("defects", []))
    h = ev.get("hidden", {}); hr = ev.get("harness", {})
    rows.append({
        "cell": cell, "task": t, "lang": lang, "run": run,
        "sources": {k: c[k] for k in ("impl_source", "eval_source", "review_source") if k in c},
        "usage": c.get("usage"),
        "impl": {"status": im.get("status"), "files_changed": len(im.get("files_changed", [])),
                 "escalations": im.get("escalations", []), "limitations": im.get("limitations", []),
                 "summary": im.get("summary")},
        "eval": {k: ev.get(k) for k in ("built", "hidden", "harness", "unit_tests", "all_targets_build", "diff_stats", "summary")},
        "review": {"blocker": sev["blocker"], "major": sev["major"], "minor": sev["minor"],
                   "spec_conformance": rv.get("spec_conformance"), "test_quality": rv.get("test_quality"),
                   "clarity": rv.get("clarity"), "defects": rv.get("defects", []), "summary": rv.get("summary")},
    })
json.dump(scrub({"cells": rows}), open(sys.argv[1], "w"), indent=1)


def pt(d):
    return f"{d.get('passed')}/{d.get('total')}" if d else "-"


md = ["| cell | model | built | hidden darwin | hidden linux | harness darwin | harness linux | unit | diff +/- | blocker/major/minor | conf/tests/clarity | tool calls | out tokens | in tokens (incl. cache) |",
      "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    e = r["eval"]; v = r["review"]; u = r["usage"] or {}; d = e.get("diff_stats") or {}
    md.append(f"| {r['cell']} | {u.get('model')} | {e.get('built')} | {pt((e.get('hidden') or {}).get('darwin'))} | {pt((e.get('hidden') or {}).get('linux'))} "
              f"| {pt((e.get('harness') or {}).get('darwin'))} | {pt((e.get('harness') or {}).get('linux'))} | {(e.get('unit_tests') or {}).get('exit_code')} "
              f"| +{d.get('insertions')}/-{d.get('deletions')} | {v['blocker']}/{v['major']}/{v['minor']} "
              f"| {v['spec_conformance']}/{v['test_quality']}/{v['clarity']} | {u.get('tool_calls')} | {u.get('output_tokens')} | {u.get('input_tokens_incl_cache')} |")
md.append("")
for r in rows:
    for dft in r["review"]["defects"]:
        if dft["severity"] != "minor":
            md.append(f"- **{r['cell']} {dft['severity']}** ({dft.get('location')}): {dft['description']}")
open(sys.argv[2], "w").write(scrub("\n".join(md)) + "\n")
print(len(rows), "cells")
