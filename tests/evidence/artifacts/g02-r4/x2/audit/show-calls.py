"""Print the flagged tool calls of one audited transcript: index, reasons, and the tool input (truncated).
usage: python3 -I show-calls.py AUDIT_JSON TRANSCRIPT_DIR [maxlen]"""
import json, sys, os
audit = json.load(open(sys.argv[1])); tdir = sys.argv[2]; maxlen = int(sys.argv[3]) if len(sys.argv) > 3 else 500
cache = {}
def lines(f):
    if f not in cache:
        cache[f] = open(os.path.join(tdir, f)).read().splitlines()
    return cache[f]
for c in audit["offending_calls"]:
    e = json.loads(lines(c["file"])[c["line"] - 1])
    inp = None
    for part in e.get("message", {}).get("content", []):
        if isinstance(part, dict) and part.get("type") == "tool_use":
            inp = part.get("input"); break
    if isinstance(inp, dict):
        txt = inp.get("command") or inp.get("file_path") or inp.get("path") or json.dumps(inp)
    else:
        txt = str(inp)
    print(f"[{c['index']}] {c['tool']} {','.join(c['reasons'])}")
    print("    " + txt[:maxlen].replace("\n", "\n    "))
for e in audit.get("entries", []):
    print("ENTRY", e)
print("VERDICT", audit["verdict"])
