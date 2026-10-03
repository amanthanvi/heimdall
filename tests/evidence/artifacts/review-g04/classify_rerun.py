#!/usr/bin/env python3
"""review-g04: apply tests/native/g04/make_records.py's classify() to a rerun directory WITHOUT
writing any record (make_records.main() would overwrite tests/evidence/g04-exp-*.json)."""
import importlib.util, os, sys
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
spec = importlib.util.spec_from_file_location("mr", os.path.join(REPO, "tests/native/g04/make_records.py"))
mr = importlib.util.module_from_spec(spec); spec.loader.exec_module(mr)
out = os.path.abspath(sys.argv[1])
codes = dict(l.split() for l in open(os.path.join(out, "exit-codes.txt")) if l.strip())
for e in mr.EXPERIMENTS:
    rc = int(codes[e["script"]])
    checks, obs, facts, cleanup, exitrow, setup = mr.parse_results(os.path.join(out, e["name"] + ".results.tsv"))
    st, verdict, reason = mr.classify(e, rc, checks, obs, exitrow, setup)
    roles = {}
    for c in checks + obs:
        roles.setdefault(c["role"], []).append("%s=%s" % (c["name"], c["result"]))
    unclean = [c for c in cleanup if any(w in c for w in ("still_running", "socket_still_present", "still_present", "not_signalled"))]
    print("%s exit=%d status=%s verdict=%s checks=%d obs=%d unclean_cleanup=%s" % (e["case_id"], rc, st, verdict, len(checks), len(obs), unclean or "none"))
    print("   findings(non-criterion OBS): %s" % "; ".join(roles.get("finding", [])))
