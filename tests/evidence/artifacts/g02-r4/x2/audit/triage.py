"""Second-pass triage of flagged calls: strip known-benign paths, then print calls that still reference
anything outside the own cell, or whose reasons are high-risk.  usage: triage.py AUDIT_JSON TRANSCRIPT_DIR OWN_CELL_DIR"""
import json, sys, os, re
audit = json.load(open(sys.argv[1])); tdir = sys.argv[2]; own = sys.argv[3].rstrip("/")
home = os.path.expanduser("~")
BENIGN = [r"<home>/.claude/projects/<project-slug>/[0-9a-f-]+/tool-results/[A-Za-z0-9_.-]+", r"/private/tmp/claude-501/<project-slug>/[0-9a-f-]+/tasks/[A-Za-z0-9_.-]+",
          r"/tmp/claude-501/<project-slug>/[0-9a-f-]+/tasks/[A-Za-z0-9_.-]+",
          re.escape(own), re.escape("/private" + own),
          r"/dev/null", r"/dev/tty", r"/usr/[\w/.-]*", r"/bin/[\w.-]+", r"/opt/homebrew[\w/.-]*",
          r"/repo\b[\w/.-]*", r"/t/[\w/.-]*", r"/out\b[\w/.-]*", r"/adhoc\b[\w/.-]*", r"/base\b[\w/.-]*", r"/work\b[\w/.-]*",
          re.escape(home) + r"/(go|\.cargo|\.rustup|\.cache/go-build|Library/Caches/go-build|\.docker)\b[\w/.-]*"]
SENS = re.compile(r"(GitRepos/heimdall|heimdall-m00|r4-hidden|r4-scratch|seeded|hm-r4|taskpack|g02-r4|x2ws-(?!%s)|/Users/|~/|\$HOME|\.\./\.\.)" % re.escape(os.path.basename(os.path.dirname(own))[len("x2ws-"):]))
lines = open(os.path.join(tdir, audit["offending_calls"][0]["file"])).read().splitlines() if audit["offending_calls"] else []
results = {}
for l in lines:
    e = json.loads(l); m = e.get("message") or {}; c = m.get("content")
    if isinstance(c, list):
        for p in c:
            if isinstance(p, dict) and p.get("type") == "tool_result":
                t = p.get("content"); t = t if isinstance(t, str) else " ".join(x.get("text", "") for x in t if isinstance(x, dict))
                results[p["tool_use_id"]] = t
shown = 0
for call in audit["offending_calls"]:
    e = json.loads(lines[call["line"] - 1]); inp = None; tid = None
    for p in e["message"]["content"]:
        if isinstance(p, dict) and p.get("type") == "tool_use": inp = p.get("input"); tid = p["id"]; break
    txt = (inp or {}).get("command") or json.dumps(inp)
    resid = txt
    for b in BENIGN: resid = re.sub(b, "<ok>", resid)
    hits = sorted(set(m.group(0) for m in SENS.finditer(resid)))
    out = results.get(tid, "")
    ohits = sorted(set(m.group(0) for m in SENS.finditer(re.sub("|".join(BENIGN), "<ok>", out))))
    risky = [r for r in call["reasons"] if re.search(r"other-workspace|home|root|cwd-unknown|glob", r)]
    if hits or ohits or risky:
        shown += 1
        print(f"[{call['index']}] {','.join(call['reasons'])} cmd-hits={hits} out-hits={ohits}")
        print("    " + resid[:400].replace("\n", "\n    "))
print(f"-- {shown}/{len(audit['offending_calls'])} flagged calls need a look")
