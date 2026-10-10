#!/usr/bin/env python3
"""Score one hidden-test record against the pinned baseline of the same task, language and platform.

usage: python3 -I -B score.py --task T1|T2|T3|T4 --lang go|rust --platform darwin|linux
                              --expect-sha256 HEX RESULT.json [--baseline-dir DIR]

Why (fix-round review, 2026-10-06): the Go and Rust baselines start from different deficits (T1:
Go 6/14 darwin, 8/14 linux; Rust 8/14 both), so raw pass counts are not comparable across
languages.  Score per language by:
  - all_pass: every check passes (the primary yes/no outcome);
  - fixed: checks that fail on the baseline and pass now, out of the baseline's failing checks;
  - regressed: checks that pass on the baseline and fail now (should be 0).
Checks listed in UNPROVEN have no Go/Rust build that passes them on that platform; only the Python
positive control does, so feasibility under the Go runtime and Rust std constraints (K16) is not
shown.  They are scored, but also reported separately (all_pass_excluding_unproven,
fixed_excluding_unproven): a both-languages-fail outcome on them does not discriminate.

The baseline is DIR/<platform>/<task>-<subject>.json with subject base-<lang> (T1-T3) or
seeded-<lang> (T4); DIR defaults to baseline/ next to this file (copied from the verify-matrix run
on the pinned base, results/2026-10-06-fix2/matrix since fix round 2).  The baseline record must carry the sha256 that
BASE.json pins for that subject and platform, so a record of a drifted build is never used as the
baseline.  --expect-sha256 (required, fix round 2) is the sha256 of the implementer's heimdall-proto
for this platform (the evaluator takes it from the build, before running hidden.sh); the result
record must carry it as binary_sha256 and binary_sha256_after.  The result record must also carry
"lang" equal to --lang (run.py --lang, fix round 2), and so must the baseline record (baseline/ was
refreshed from the fix-round-2 matrix run, whose records carry "lang"; per-check statuses are
identical to the fix-round-1 runs).
Output: one JSON object on stdout.  Exit status: 0 scored; 2 usage error, or the record is invalid
(wrong task/platform, an `error` check, a verdict other than pass/fail, a baseline that is not the
pinned base, or a result for another binary): rerun the evaluation instead of scoring it.
"""
import sys
sys.dont_write_bytecode = True   # no __pycache__ even without -B
import argparse  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
UNPROVEN = {("T1", "darwin"): ["T1.nested_shell_bash", "T1.nested_shell_zsh"]}


def statuses(path):
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return doc, {c["id"]: c["status"] for c in doc["checks"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--task", required=True, choices=["T1", "T2", "T3", "T4"])
    ap.add_argument("--lang", required=True, choices=["go", "rust"])
    ap.add_argument("--platform", required=True, choices=["darwin", "linux"])
    ap.add_argument("--baseline-dir", default=str(HERE / "baseline"))
    ap.add_argument("--expect-sha256", required=True,
                    help="sha256 of the implementer's heimdall-proto for --platform (64 hex)")
    ap.add_argument("result")
    a = ap.parse_args()
    exp = a.expect_sha256.strip().lower()
    if len(exp) != 64 or any(c not in "0123456789abcdef" for c in exp):
        print("score.py: --expect-sha256 must be 64 hex digits", file=sys.stderr)
        return 2
    subj = ("seeded-" if a.task == "T4" else "base-") + a.lang
    bpath = Path(a.baseline_dir) / a.platform / ("%s-%s.json" % (a.task, subj))
    try:
        bdoc, base = statuses(bpath)
        doc, now = statuses(a.result)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print("score.py: cannot read a record: %s" % type(e).__name__, file=sys.stderr)
        return 2
    pin = json.loads((HERE / "BASE.json").read_text(encoding="utf-8"))["binaries"][subj][a.platform]["sha256"]
    problems = []
    if bdoc.get("binary_sha256") != pin or bdoc.get("task") != a.task or bdoc.get("platform") != a.platform \
            or bdoc.get("verdict") not in ("pass", "fail") or any(v == "error" for v in base.values()):
        problems.append("baseline record is not a valid run of the pinned %s %s build" % (subj, a.platform))
    if doc.get("binary_sha256") != exp or doc.get("binary_sha256_after") != exp:
        problems.append("result record is for another binary")
    if doc.get("lang") != a.lang:
        problems.append("result record lang %r is not --lang %s" % (doc.get("lang"), a.lang))
    if bdoc.get("lang") != a.lang:
        problems.append("baseline record lang %r is not --lang %s" % (bdoc.get("lang"), a.lang))
    if doc.get("task") != a.task or doc.get("platform") != a.platform:
        problems.append("record is for %s/%s" % (doc.get("task"), doc.get("platform")))
    if doc.get("verdict") not in ("pass", "fail"):
        problems.append("verdict %r" % doc.get("verdict"))
    errs = sorted(k for k, v in now.items() if v == "error")
    if errs:
        problems.append("error checks: %s" % ", ".join(errs))
    missing = sorted(set(base) - set(now))
    if missing:
        problems.append("checks missing from the record: %s" % ", ".join(missing))
    unproven = UNPROVEN.get((a.task, a.platform), [])
    bfail = sorted(k for k, v in base.items() if v != "pass")
    bpass = sorted(k for k, v in base.items() if v == "pass")
    fixed = [k for k in bfail if now.get(k) == "pass"]
    still = [k for k in bfail if now.get(k) != "pass"]
    regressed = [k for k in bpass if now.get(k) != "pass"]
    new_checks = sorted(set(now) - set(base))
    out = {
        "task": a.task, "lang": a.lang, "record_lang": doc.get("lang"), "platform": a.platform,
        "result_binary_sha256": doc.get("binary_sha256"),
        "baseline_subject": subj, "baseline_binary_sha256": bdoc.get("binary_sha256"),
        "baseline_pinned": bdoc.get("binary_sha256") == pin,
        "valid": not problems, "problems": problems,
        "total": len(now), "pass": sum(1 for v in now.values() if v == "pass"),
        "all_pass": not problems and all(v == "pass" for v in now.values()),
        "baseline_pass": len(bpass), "baseline_fail": len(bfail),
        "fixed": "%d/%d" % (len(fixed), len(bfail)), "fixed_checks": fixed,
        "still_failing_checks": still,
        "regressed": len(regressed), "regressed_checks": regressed,
        "checks_not_in_baseline": new_checks,
        "unproven_checks": unproven,
        "all_pass_excluding_unproven": not problems and all(v == "pass" for k, v in now.items() if k not in unproven),
        "fixed_excluding_unproven": "%d/%d" % (len([k for k in fixed if k not in unproven]),
                                              len([k for k in bfail if k not in unproven])),
    }
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0 if not problems else 2


if __name__ == "__main__":
    sys.exit(main())
