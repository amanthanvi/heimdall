"""Per-implementer metrics from workflow transcripts: tool calls, tokens (input incl. cache, output), wall time.
usage: metrics.py WF_DIR [WF_DIR...]   (labels taken from each journal; implementers only)"""
import json, sys, os
from datetime import datetime
def ts(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))
rows = []
for wf in sys.argv[1:]:
    lab = {}; ok = set()
    for l in open(os.path.join(wf, "journal.jsonl")):
        e = json.loads(l)
        if e["type"] == "started": lab[e["agentId"]] = e["label"]
        elif e["type"] == "result": ok.add(e["agentId"])
    for a, label in lab.items():
        if not label.startswith("impl-") or a not in ok: continue
        p = os.path.join(wf, f"agent-{a}.jsonl")
        calls = 0; t0 = t1 = None; seen_u = {}; model = None
        for l in open(p):
            e = json.loads(l)
            if e.get("timestamp"):
                t = ts(e["timestamp"]); t0 = t0 or t; t1 = t
            m = e.get("message") or {}
            if m.get("role") != "assistant": continue
            model = m.get("model") or model
            mid = m.get("id")
            c = m.get("content")
            if isinstance(c, list): calls += sum(1 for x in c if isinstance(x, dict) and x.get("type") == "tool_use")
            u = m.get("usage")
            if u:
                # streamed entries repeat one message id; keep the largest usage seen for it
                prev = seen_u.get(mid, (0, 0, 0, 0))
                seen_u[mid] = tuple(max(a, b) for a, b in zip(prev, (u.get("input_tokens", 0), u.get("cache_creation_input_tokens", 0), u.get("cache_read_input_tokens", 0), u.get("output_tokens", 0))))
        inp = sum(v[0] for v in seen_u.values()); cc = sum(v[1] for v in seen_u.values())
        cr = sum(v[2] for v in seen_u.values()); out = sum(v[3] for v in seen_u.values())
        rows.append((label[5:], os.path.basename(wf), a, model, calls, inp + cc + cr, out, round((t1 - t0).total_seconds() / 60, 1)))
print("cell wf agent model tool_calls input_tokens_incl_cache output_tokens wall_min")
for r in sorted(rows): print(*r)
