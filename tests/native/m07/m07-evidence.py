#!/usr/bin/env python3
"""M07-U9: the native harnesses' run plan, the required inventory and the evidence records
for M07 (m07-plan §6, §6.1).

This is tests/native/m06/m06-evidence.py with the M07 constants, over the same generator
(tests/native/m02/m02-evidence.py, loaded by path through the M06 and M05 modules; ADR-0009:
generalized, never copied). Every mode, rule and check is the M02 one, documented there: the
case index (tests/native/m07/case-index.json) resolved against the build host's sources into
tests/native/m07/required-inventory.json, the lowest-row rule, the coverage guard, schema
validation before anything is written, and no record for a run whose logs do not exist. So: a
row whose platform did not run (`unavailable` in runs.json) is `blocked` on that exact platform;
a required test missing from a platform that ran is `in_progress`; a failed test or command is
`in_progress` whatever else the row holds. M06's `feature-blocked-<target>` host facts are read
as they are there; no M07 target requires a feature, so M06's feature-built unit target
(FEATURE_UNIT) is not selected here and every target is listed from the default build.

M07 additions:
  * runs.json platforms: macos (the build host), linux (the devbox) and windows (Windows 11
    native), all cargo platforms.
  * The case index's own rows (`blocked_rows` of a group or an exit claim) are rows that no
    native run produces: a row for something not built yet (revision 7: verified-hello
    discovery, U3, U4b, U5b, U5h, U6, U7), an owner input, or a decision. The index check
    (check_index, so --check-inventory and every evaluation) refuses such a row unless it is
    `blocked` with a non-empty `blocked_on`, `not_started` with a non-empty `not_configured`,
    or `deferred_with_decision` with a non-empty `decision`. So a row not built yet is reported
    blocked with its reason and can never be written as verified, in_progress or
    implemented_unverified from the index.
  * A30 (m07-plan §6.1, controlling): it stays `blocked` on owner inputs B14 and B7 at M07's
    exit, never passing. OWNER_BLOCKED holds that row and evaluate() adds it to A30 whatever the
    case index says: when the index has an A30 group (U2a's deterministic checks), its tested
    rows are kept and the owner row is added beside them; when it has none, A30 is a section of
    the summary with that one row. The row is also added to every exit claim that lists A30 and
    to the exit record (case_id EXIT_CASE_ID), so by the lowest-row rule neither A30's record nor
    M07's exit record can read anything but blocked. records() refuses to return either one
    otherwise, and refuses a runs.json record that names no section or whose file name lacks the
    `m07-` prefix.
  * OBSERVATION_LINE also keeps `m07 observation:` lines; the earlier milestones' are kept.
  * G08 ratification (m07-plan §6.1: every A19 and A32 native row verified on all three
    platforms, excusing only rows blocked solely on B2, B3 or B8 and the deferred LLM metrics)
    is read from the A19 and A32 rows by the integrator; this generator does not compute it.

HM_SKIP_TARGETS (a comma-separated list of Cargo test target names; m05-evidence.py) drops
those targets from the case index before anything is resolved, for a commit that does not
contain every target the case index names yet. Records are never generated with it: the
generator refuses --write while it is set.

Usage: as m02-evidence.py, e.g.
  python3 -I tests/native/m07/m07-evidence.py --config tests/native/m07/runs.json --check-inventory
  python3 -I tests/native/m07/m07-evidence.py --config <artifacts_root>/runs.json --write
"""

import copy
import importlib.util
import sys
from pathlib import Path

# The modules loaded by path below write no bytecode beside the sources (python3 -I ignores
# PYTHONDONTWRITEBYTECODE, and refresh-inventory.sh runs the generator without -B).
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load_m06():
    argv = sys.argv
    spec = importlib.util.spec_from_file_location("m06_evidence", HERE.parent / "m06" / "m06-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    sys.argv = ["m06-evidence.py"]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = argv
    return mod


m06 = load_m06()
m05 = m06.m05
ev = m06.ev
ev.MILESTONE = "M07"
ev.PLAN_REF = "m07-plan §6"
ev.GENERATOR = "m07-evidence.py"
ev.OBSERVATION_LINE = ev.re.compile(r"^\s*(?:m0[3567] )?observation\b")
# No M07 target requires a feature: every unit target is listed from the default build.
m06.FEATURE_UNIT = {}

# The rows a case index may carry itself, and the reason each must name.
INDEX_ROW_REASON = {"blocked": "blocked_on", "not_started": "not_configured", "deferred_with_decision": "decision"}

# m07-plan §6.1: the cases that stay blocked on owner inputs at M07's exit whatever their tests do.
OWNER_BLOCKED = {
    "A30": {
        "platform": "macos, linux and windows: A30's participant session (m07-plan §6.1)",
        "status": "blocked",
        "blocked_on": "owner inputs B14 (one person unfamiliar with Heimdall; the session runs inside "
        "M09-T01's normal-week study) and B7 (the baseline worksheet)",
        "rule": "m07-plan §6.1: M07's exit record reports A30 as blocked, never as passing",
    },
}
# The case_id of M07's exit record (m07-plan §6: m07-exit-claims.json).
EXIT_CASE_ID = "m07-exit-claims"
RECORD_PREFIX = "m07-"


def index_row_problems(index):
    """Problems (strings) in the case index's own rows (blocked_rows)."""
    problems = []
    for kind in ("groups", "exit_claims"):
        for sid, sec in (index.get(kind) or {}).items():
            rows = sec.get("blocked_rows", [])
            if not isinstance(rows, list):
                problems.append(f"{sid}: blocked_rows is not a list")
                continue
            for i, r in enumerate(rows):
                where = f"{sid}: blocked_rows[{i}]"
                if not isinstance(r, dict):
                    problems.append(f"{where} is not an object")
                    continue
                if not isinstance(r.get("platform"), str) or not r["platform"].strip():
                    problems.append(f"{where} names no platform")
                status = r.get("status")
                if status not in INDEX_ROW_REASON:
                    problems.append(f"{where} is {status!r}: a row no native run produced is blocked, "
                                    "not_started or deferred_with_decision, never anything a run decides")
                    continue
                reason = INDEX_ROW_REASON[status]
                if not isinstance(r.get(reason), str) or not r[reason].strip():
                    problems.append(f"{where} is {status} without its {reason}")
    return problems


def install_index_rows():
    check = ev.check_index

    def check_index(index):
        return check(index) + index_row_problems(index)

    ev.check_index = check_index


install_index_rows()


def owner_row(gid):
    return dict(OWNER_BLOCKED[gid])


def add_owner_row(rows, gid):
    row = owner_row(gid)
    if row not in rows:
        rows.append(row)


def install_owner_blocked():
    """evaluate() with OWNER_BLOCKED's rows in their cases, in the exit claims that list them and
    in the exit record's claim."""
    evaluate = ev.evaluate

    def evaluate_m07(cfg, index, inv):
        absent = {gid for gid in OWNER_BLOCKED if gid not in index["groups"]}
        listed = {claim: set(c.get("groups", [])) for claim, c in index["exit_claims"].items()}
        if absent:
            # m02's evaluate() reads a listed group from its own summary: a case the index does
            # not hold is left out there and added below.
            index = copy.deepcopy(index)
            for c in index["exit_claims"].values():
                if "groups" in c:
                    c["groups"] = [g for g in c["groups"] if g not in absent]
        summary, plats, rc = evaluate(cfg, index, inv)
        for gid in OWNER_BLOCKED:
            g = summary["groups"].setdefault(gid, {"tests": 0, "rows": [], "status": ev.NOT_COUNTED})
            add_owner_row(g["rows"], gid)
            g["status"] = ev.lowest([r["status"] for r in g["rows"]])
        exit_claims = {sid for sid, meta in (cfg.get("records") or {}).items() if meta.get("case_id") == EXIT_CASE_ID}
        for claim, c in summary["exit_claims"].items():
            for gid in OWNER_BLOCKED:
                if gid in listed.get(claim, set()) and gid not in absent:
                    # m02 copied the case's rows before the owner row was added.
                    add_owner_row(c["rows"], gid)
                elif gid in listed.get(claim, set()) or claim in exit_claims:
                    g = summary["groups"][gid]
                    for r in g["rows"]:
                        if r not in c["rows"]:
                            c["rows"].append(dict(r))
                    c["tests"] += g["tests"]
                else:
                    continue
                c["status"] = ev.lowest([r["status"] for r in c["rows"]])
        return summary, plats, rc

    ev.evaluate = evaluate_m07


install_owner_blocked()


def install_record_checks():
    records = ev.records

    def records_m07(cfg, summary, plats):
        for sid, meta in cfg["records"].items():
            if sid not in summary["groups"] and sid not in summary["exit_claims"]:
                raise ev.RunError(f"{sid}: runs.json names a record that no section of the case index produces")
            if not Path(meta["path"]).name.startswith(RECORD_PREFIX):
                raise ev.RunError(f"{sid}: record path {meta['path']} does not start with {RECORD_PREFIX}")
        out = records(cfg, summary, plats)
        for path, rec in out:
            if (rec["case_id"] in OWNER_BLOCKED or rec["case_id"] == EXIT_CASE_ID) and rec["status"] != "blocked":
                raise ev.RunError(f"{path}: {rec['case_id']} reads {rec['status']}; m07-plan §6.1 keeps it blocked on A30's owner inputs")
        return out

    ev.records = records_m07


install_record_checks()


if __name__ == "__main__":
    skip = m05.skip_targets()
    if skip:
        if "--write" in sys.argv[1:]:
            print("HM_SKIP_TARGETS is set: records are never written from a reduced case index", file=sys.stderr)
            sys.exit(2)
        m05.install_skip(skip)
        m06.install_skip_listing(skip)
    sys.exit(ev.main())
