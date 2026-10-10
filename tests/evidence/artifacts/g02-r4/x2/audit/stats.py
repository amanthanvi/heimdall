"""Summary statistics for X2 from aggregate.py's results.json.  usage: python3 -I stats.py RESULTS_JSON"""
import json, statistics as st, sys
from collections import defaultdict

cells = json.load(open(sys.argv[1]))["cells"]
by = defaultdict(list)
for c in cells:
    by[c["lang"]].append(c)


def hp(c, plat):
    d = (c["eval"].get("hidden") or {}).get(plat) or {}
    return d.get("passed") is not None and d.get("passed") == d.get("total")


def harness_ok(c):
    exp = 136 if c["task"] == "T3" else 139
    hr = c["eval"].get("harness") or {}
    return all((hr.get(p) or {}).get("passed") == exp and (hr.get(p) or {}).get("total") == 139 for p in ("darwin", "linux"))


print("lang cells built hidden_all_pass(darwin&linux) harness_expected unit_exit0 all_targets blocker major minor "
      "mean_conf mean_tests mean_clarity sum_calls med_calls sum_out med_out sum_in sum_ins sum_del")
for lang, cs in sorted(by.items()):
    u = [c["usage"] for c in cs]
    r = [c["review"] for c in cs]
    print(lang, len(cs), sum(bool(c["eval"].get("built")) for c in cs),
          sum(hp(c, "darwin") and hp(c, "linux") for c in cs), sum(harness_ok(c) for c in cs),
          sum((c["eval"].get("unit_tests") or {}).get("exit_code") == 0 for c in cs),
          sum(bool(c["eval"].get("all_targets_build")) for c in cs),
          sum(x["blocker"] for x in r), sum(x["major"] for x in r), sum(x["minor"] for x in r),
          round(st.mean(x["spec_conformance"] for x in r), 2), round(st.mean(x["test_quality"] for x in r), 2),
          round(st.mean(x["clarity"] for x in r), 2),
          sum(x["tool_calls"] for x in u), st.median(x["tool_calls"] for x in u),
          sum(x["output_tokens"] for x in u), st.median(x["output_tokens"] for x in u),
          sum(x["input_tokens_incl_cache"] for x in u),
          sum((c["eval"].get("diff_stats") or {}).get("insertions", 0) for c in cs),
          sum((c["eval"].get("diff_stats") or {}).get("deletions", 0) for c in cs))

print("\npaired by task+run: go/rust ratio of output tokens and tool calls")
idx = {(c["task"], c["run"], c["lang"]): c for c in cells}
wins = defaultdict(int); ratios_out = []; ratios_calls = []
for (t, run, lang), c in sorted(idx.items()):
    if lang != "go" or (t, run, "rust") not in idx:
        continue
    g, r = c["usage"], idx[(t, run, "rust")]["usage"]
    ro = g["output_tokens"] / r["output_tokens"]; rc = g["tool_calls"] / r["tool_calls"]
    ratios_out.append(ro); ratios_calls.append(rc)
    wins["go fewer out"] += g["output_tokens"] < r["output_tokens"]
    wins["go fewer calls"] += g["tool_calls"] < r["tool_calls"]
    print(f"  {t} {run}: out {g['output_tokens']}/{r['output_tokens']} = {ro:.2f}; calls {g['tool_calls']}/{r['tool_calls']} = {rc:.2f}")
n = len(ratios_out)
print(f"  pairs {n}; go used fewer output tokens in {wins['go fewer out']}, fewer tool calls in {wins['go fewer calls']}; "
      f"geometric-mean ratio out {st.geometric_mean(ratios_out):.2f}, calls {st.geometric_mean(ratios_calls):.2f}")

print("\nper task: mean output tokens and tool calls (go | rust)")
for t in ("T1", "T2", "T3", "T4"):
    row = []
    for lang in ("go", "rust"):
        cs = [c for c in by[lang] if c["task"] == t]
        row.append(f"{lang} n={len(cs)} out {round(st.mean(c['usage']['output_tokens'] for c in cs))} calls {round(st.mean(c['usage']['tool_calls'] for c in cs))} "
                   f"minor {sum(c['review']['minor'] for c in cs)} major {sum(c['review']['major'] for c in cs)}")
    print(" ", t, " | ".join(row))

print("\nper model family (go | rust): sum output tokens, sum tool calls, majors")
for fam in ("opus", "sonnet"):
    row = []
    for lang in ("go", "rust"):
        cs = [c for c in by[lang] if c["run"].startswith(fam)]
        row.append(f"{lang} n={len(cs)} out {sum(c['usage']['output_tokens'] for c in cs)} calls {sum(c['usage']['tool_calls'] for c in cs)} major {sum(c['review']['major'] for c in cs)}")
    print(" ", fam, " | ".join(row))
