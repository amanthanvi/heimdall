#!/usr/bin/env python3
"""M01-U10: check the case index against real run logs and write evidence records.

Usage (from the repository root, with `python3 -I`):
  tests/native/m01/m01-evidence.py --config tests/native/m01/runs.json [--write]

runs.json names, per platform, the run log(s), the artifact paths, exit codes and
digests. Logs are parsed as they were saved:
  * cargo/check.sh output: `Running <src> (target/.../deps/<bin>-<hash>)` then
    `test <name> ... ok|FAILED|ignored` lines;
  * remote runner output (tests.txt): `### <target>` then the same test lines.
Lib/bin unit-test binaries are named `<crate>-unit`.

For every case group and platform the row lists each indexed test as passed,
failed, ignored, or absent (not built for or not run on that platform), and the
row status follows the evidence rules (AGENTS.md): verified only when every
applicable indexed test ran and passed on that platform in this run; a test that
could not run there makes the row blocked (with the platform and reason); a
failing (or gap-ignored) case makes it in_progress. The record status is its
lowest row. Nothing here invents results: a test absent from a log is absent.

A platform whose `predates_build` is set ran an older build of the tree than the
one this record describes (its log was not re-run after a change): a test absent
from its log is listed under `not_run_since_build` (not "not run on this
platform") and the row is in_progress, never blocked or verified, with the note
attached. `harness_gap` likewise makes absent tests in_progress: the platform was
available and the harness did not run them (gap G05/G09); `blocked` is only for a
genuinely missing platform.
"""

import argparse
import json
import re
import sys
from pathlib import Path

ORDER = ["not_started", "in_progress", "blocked", "implemented_unverified", "verified"]


def parse_log(path):
    """Return {target: {test: result}}."""
    results = {}
    current = None
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw).rstrip("\r")
        m = re.match(r"^\s*Running (.+?) \((?:.*[/\\])?([A-Za-z0-9_-]+?)-[0-9a-f]+(?:\.exe)?\)$", line)
        if m:
            src, binary = m.groups()
            current = binary if src.startswith("../") or src.startswith("tests") else binary + "-unit"
            results.setdefault(current, {})
            continue
        m = re.match(r"^\s*Doc-tests ", line)
        if m:
            current = None
            continue
        m = re.match(r"^### ([A-Za-z0-9_-]+)$", line)
        if m:
            current = m.group(1)
            results.setdefault(current, {})
            continue
        m = re.match(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b", line)
        if m and current is not None:
            results[current][m.group(1)] = m.group(2)
    return results


def merge(into, more):
    for target, tests in more.items():
        into.setdefault(target, {}).update(tests)


def expand(spec, logs_union):
    """{target: [names] | "*"} -> [(target, name)] using every platform's logs for "*"."""
    out = []
    for target, names in spec.items():
        if names == "*":
            seen = sorted(logs_union.get(target, {}).keys())
            out.extend((target, n) for n in seen)
        else:
            out.extend((target, n) for n in names)
    return out


def applicable(target, name, platform, group):
    po = group.get("platform_only", {})
    for key, plats in po.items():
        if "::" in key:
            t, prefix = key.split("::", 1)
            if t == target and name.startswith(prefix):
                return platform in plats
        elif key == target:
            return platform in plats
    # Windows pipe unit tests exist only in the Windows build of heimdall_ipc;
    # integration_ipc_unix is `#![cfg(unix)]` (0 tests on Windows by design).
    if target == "heimdall_ipc-unit" and name.startswith("windows::"):
        return platform == "windows"
    if target == "integration_ipc_unix":
        return platform in ("macos", "linux")
    return True


def row_for(platform, pconf, logs, tests, gaps, group):
    passed, failed, ignored, absent, neutral = [], [], [], [], []
    skipped_neutral = set(pconf.get("platform_neutral_not_run", []))
    for target, name in tests:
        if not applicable(target, name, platform, group):
            continue
        r = logs.get(target, {}).get(name)
        qual = f"{target}::{name}"
        if r == "ok":
            passed.append(qual)
        elif r == "FAILED":
            failed.append(qual)
        elif r == "ignored":
            ignored.append(qual)
        elif target in skipped_neutral or qual in skipped_neutral:
            neutral.append(qual)
        else:
            absent.append(qual)
    gap_rows = []
    gap_logs = pconf.get("_gap_logs", {})
    for target, name in gaps:
        r = gap_logs.get(target, {}).get(name)
        gap_rows.append({"test": f"{target}::{name}", "with_ignored": r or "not run"})
    if not (passed or failed or ignored or absent):
        # Nothing indexed applies here (platform-neutral checks run elsewhere).
        return None
    stale = pconf.get("predates_build")
    harness_gap = pconf.get("harness_gap")
    if failed or ignored or (gaps and platform == "macos"):
        status = "in_progress"
    elif stale or (absent and harness_gap):
        # A row from an older build never verifies this build.
        status = "in_progress"
    elif absent:
        status = "blocked"
    else:
        status = "verified"
    row = {
        "platform": pconf["label"],
        "status": status,
        "passed": len(passed),
        "failed": failed,
        "ignored": ignored,
        "not_run_on_this_platform": absent,
        "platform_neutral_run_elsewhere": neutral,
        "exit_codes": pconf["exit_codes"],
        "artifact_digest": pconf["artifact_digest"],
        "logs": pconf["logs"],
    }
    if gaps:
        row["gap_cases"] = gap_rows
    if stale:
        row["not_run_since_build"] = row.pop("not_run_on_this_platform")
        row["predates_build"] = stale
    elif absent and harness_gap:
        row["harness_gap"] = harness_gap
    elif absent:
        row["blocked_on"] = pconf.get("blocked_reason", "listed tests did not run on this platform")
    return row


def lowest(statuses):
    return min(statuses, key=ORDER.index)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    index = json.loads(Path(cfg["case_index"]).read_text())

    plat_logs = {}
    union = {}
    current = {}
    for pname, p in cfg["platforms"].items():
        logs = {}
        for path in p["logs"]:
            merge(logs, parse_log(path))
        p["_gap_logs"] = {}
        for path in p.get("gap_logs", []):
            merge(p["_gap_logs"], parse_log(path))
        plat_logs[pname] = logs
        if not p.get("predates_build"):
            merge(current, logs)
    # "*" expands over the logs of this build; older builds' logs only when no
    # platform ran this build (a test renamed or removed since is not indexed).
    union = current if current else union
    if not union:
        for logs in plat_logs.values():
            merge(union, logs)

    summary = {}
    rc = 0
    groups = dict(index["groups"])
    for gid, g in groups.items():
        tests = expand(g["tests"], union)
        gaps = expand(g.get("gaps", {}), union)
        # Every indexed name must exist somewhere (a typo is a defect, not a gap).
        for target, name in tests:
            if not any(name in plat_logs[p].get(target, {}) for p in plat_logs):
                print(f"{gid}: {target}::{name} not found in any log", file=sys.stderr)
                rc = 1
        rows = [r for pn in cfg["platforms"] if (r := row_for(pn, cfg["platforms"][pn], plat_logs[pn], tests, gaps, g))]
        for extra in cfg.get("extra_rows", {}).get(gid, []):
            rows.append(extra)
        summary[gid] = {"tests": len(tests), "rows": rows}

    # Exit claims: rows over the union of their tests and groups.
    claim_rows = {}
    for claim, c in index["exit_claims"].items():
        tests = []
        g_extra = []
        for gid in c.get("groups", []):
            tests.extend(expand(groups[gid]["tests"], union))
            g_extra.extend(cfg.get("extra_rows", {}).get(gid, []))
        tests.extend(expand(c.get("tests", {}), union))
        gaps = []
        for gid in c.get("groups", []):
            gaps.extend(expand(groups[gid].get("gaps", {}), union))
        merged_group = {"platform_only": {}}
        for gid in c.get("groups", []):
            merged_group["platform_only"].update(groups[gid].get("platform_only", {}))
        rows = [r for pn in cfg["platforms"] if (r := row_for(pn, cfg["platforms"][pn], plat_logs[pn], tests, gaps, merged_group))]
        rows.extend({k: v for k, v in r.items()} for r in g_extra)
        claim_rows[claim] = {"tests": len(tests), "rows": rows, "note": c.get("note")}

    out = {"groups": summary, "exit_claims": claim_rows}
    Path(cfg["summary_out"]).write_text(json.dumps(out, indent=2) + "\n")
    for gid, s in summary.items():
        print(gid, s["tests"], [(r["platform"], r["status"], r.get("passed")) for r in s["rows"]])
    for claim, s in claim_rows.items():
        print("claim:", claim, [(r["platform"], r["status"]) for r in s["rows"]])

    if args.write:
        for gid, meta in cfg["records"].items():
            if gid == "M01-exit":
                rows = []
                claims = {}
                for claim, s in claim_rows.items():
                    st = lowest([r["status"] for r in s["rows"]])
                    claims[claim] = {"status": st, "rows": s["rows"], "note": s["note"]}
                    rows.extend(s["rows"])
                status = lowest([v["status"] for v in claims.values()])
                observed = {"claims": claims}
            else:
                rows = summary[gid]["rows"]
                status = lowest([r["status"] for r in rows])
                observed = {"indexed_tests": summary[gid]["tests"], "rows": rows}
            blocked = sorted({r["blocked_on"] for r in rows if r.get("blocked_on")})
            observed["summary"] = meta["summary"]
            rec = {
                "case_id": meta["case_id"],
                "status": status,
                "requirement_ids": meta["requirement_ids"],
                "build_commit": cfg["build_commit"],
                "artifact_digest": cfg["artifact_digest"],
                "environment": cfg["environment"],
                "provider_versions": [],
                "started_at": cfg["started_at"],
                "commands_or_harness": cfg["commands"],
                "observed_result": observed,
                "evidence_paths": cfg["evidence_paths"] + [cfg["case_index"], cfg["summary_out"]],
                "limitations": meta["limitations"] + cfg["common_limitations"],
                "blocked_on": "; ".join(blocked) if status == "blocked" or blocked else None,
            }
            Path(meta["path"]).write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n")
            print("wrote", meta["path"], status)
    return rc


if __name__ == "__main__":
    sys.exit(main())
