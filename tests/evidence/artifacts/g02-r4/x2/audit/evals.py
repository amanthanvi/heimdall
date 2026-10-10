import json, sys
def pt(d): return f"{d.get('passed')}/{d.get('total')}"
for path in sys.argv[1:]:
    st = {}
    for l in open(path):
        e = json.loads(l)
        if e["type"] == "started": st[e["key"]] = e["label"]
        elif e["type"] == "result" and st.get(e["key"], "").startswith("eval-"):
            r = e["result"]; h = r["hidden"]; hr = r["harness"]
            hf = sorted(set(h["darwin"].get("failed_ids", [])) | set(h["linux"].get("failed_ids", [])))
            rf = sorted(set(hr["darwin"].get("failed_ids", [])) | set(hr["linux"].get("failed_ids", [])))
            t1 = h.get("t1_fixed_regressed")
            print(st[e["key"]][5:], "built", r.get("built"), "hidden", pt(h["darwin"]), pt(h["linux"]), hf or "",
                  "| harness", pt(hr["darwin"]), pt(hr["linux"]), rf or "",
                  "| unit", (r.get("unit_tests") or {}).get("exit_code"), "all-targets", r.get("all_targets_build"),
                  "| diff", r.get("diff_stats"), ("| t1 " + json.dumps(t1)[:300]) if t1 else "")
