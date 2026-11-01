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

Required inventory (review C02). The tests a row must show are never derived
from run logs. `required-inventory.json` (next to the case index, or the
config's `required_inventory`) lists, per case group, gap list and exit claim,
every required test of every target: the indexed names, and for a wildcard
target ("*") the names the current sources define, generated once with
`--generate-inventory` (`cargo test -- --list` on the build host) and committed.
Generation refuses a wildcard target that lists zero tests. A check run refuses
an inventory that is missing, disagrees with the case index, or has an empty
wildcard list, and reports a current-build log test outside the inventory
(regenerate). A required target absent from a platform's log leaves its tests
absent and is listed under `missing_targets`: the row is in_progress, never
verified.

Command exits (review C03). `exit_codes` are the platform's required validation
commands: any value other than the integer 0 (or no recorded command at all)
prevents verified and is listed under `failed_commands`. Intentionally failing
negative probes (a pre-fix run, a refusal probe) go under `negative_probes` as
{"name": {"expected_exit": N, "observed_exit": M}} with N nonzero; a probe that
did not exit exactly as expected is listed under `failed_negative_probes` and
also prevents verified.
"""

import argparse
import json
import re
import subprocess
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


class InventoryError(Exception):
    """The required inventory cannot be built or does not match the index."""


def expand_required(spec, inv_spec):
    """{target: [names] | "*"} -> [(target, name)]; "*" from the required inventory."""
    out = []
    for target, names in spec.items():
        if names == "*":
            out.extend((target, n) for n in inv_spec[target])
        else:
            out.extend((target, n) for n in names)
    return out


def _sections(index):
    """Yield (kind, id, part, spec, group) for every test list in the index."""
    for gid, g in index["groups"].items():
        for part in ("tests", "gaps"):
            if part in g:
                yield "groups", gid, part, g[part], g
    for claim, c in index["exit_claims"].items():
        if "tests" in c:
            yield "exit_claims", claim, "tests", c["tests"], c


def host_platform():
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"


def build_inventory(index, lister, host="macos"):
    """The required inventory from the case index and the current sources.

    `lister(target)` returns the test names the sources define for a target
    (None or [] when it defines none). A wildcard target listing zero tests, or
    an indexed name the sources do not define (where it applies to `host`), is
    an InventoryError.
    """
    listed = {}

    def names_of(target):
        if target not in listed:
            listed[target] = sorted(set(lister(target) or []))
        return listed[target]

    inv = {
        "description": "M01 required test inventory (review C02): generated by m01-evidence.py "
        "--generate-inventory from the case index and the current sources; compared against every run.",
        "groups": {},
        "exit_claims": {},
    }
    problems = []
    for kind, sid, part, spec, group in _sections(index):
        out = {}
        for target, names in spec.items():
            have = names_of(target)
            if names == "*":
                if not have:
                    problems.append(f"{sid}: wildcard target {target} discovers zero tests")
                out[target] = have
            else:
                for n in names:
                    if applicable(target, n, host, group) and n not in have:
                        problems.append(f"{sid}: {target}::{n} is not defined by the sources")
                out[target] = sorted(set(names))
        inv[kind].setdefault(sid, {})[part] = out
    if problems:
        raise InventoryError("; ".join(problems))
    return inv


def check_inventory(index, inv):
    """Problems (strings) between the case index and a committed inventory."""
    problems = []
    seen = set()
    for kind, sid, part, spec, _ in _sections(index):
        seen.add((kind, sid, part))
        got = inv.get(kind, {}).get(sid, {}).get(part)
        if not isinstance(got, dict):
            problems.append(f"{sid}: no required inventory for {part}")
            continue
        for target in sorted(set(spec) | set(got)):
            if target not in spec:
                problems.append(f"{sid}: inventory target {target} is not in the case index")
                continue
            if target not in got:
                problems.append(f"{sid}: target {target} is missing from the required inventory")
                continue
            names = got[target]
            if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                problems.append(f"{sid}: inventory for {target} is not a list of names")
            elif spec[target] == "*":
                if not names:
                    problems.append(f"{sid}: wildcard target {target} has an empty required inventory")
            elif set(names) != set(spec[target]):
                problems.append(f"{sid}: inventory for {target} differs from the case index")
    for kind in ("groups", "exit_claims"):
        for sid, parts in inv.get(kind, {}).items():
            for part in parts:
                if (kind, sid, part) not in seen:
                    problems.append(f"{sid}: inventory {part} is not in the case index")
    return problems


def cargo_lister(root):
    """lister(target) through `cargo test ... -- --list` (build host sources)."""
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=root, check=True, capture_output=True, text=True,
        ).stdout
    )
    where = {}
    for pkg in meta["packages"]:
        for t in pkg["targets"]:
            if "test" in t["kind"]:
                where[t["name"]] = (pkg["name"], ["--test", t["name"]])
            elif "lib" in t["kind"]:
                where[t["name"] + "-unit"] = (pkg["name"], ["--lib"])
            elif "bin" in t["kind"]:
                where[t["name"] + "-unit"] = (pkg["name"], ["--bin", t["name"]])

    def lister(target):
        if target not in where:
            return []
        pkg, sel = where[target]
        r = subprocess.run(
            ["cargo", "test", "--locked", "-p", pkg, *sel, "--", "--list"],
            cwd=root, capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise InventoryError(f"cargo test --list for {target} exited {r.returncode}")
        return [m.group(1) for m in re.finditer(r"^(\S+): test$", r.stdout, re.M)]

    return lister


def inventory_path(cfg):
    if cfg.get("required_inventory"):
        return Path(cfg["required_inventory"])
    return Path(cfg["case_index"]).with_name("required-inventory.json")


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


def command_failures(pconf):
    """(failed required commands, failed negative probes) of a platform run."""
    required = pconf.get("exit_codes")
    if not isinstance(required, dict) or not required:
        failed = ["(no required command exit recorded)"]
    else:
        # bool is an int subclass: only an actual integer 0 is a pass.
        failed = [k for k, v in required.items() if type(v) is not int or v != 0]
    bad_probes = []
    for name, probe in (pconf.get("negative_probes") or {}).items():
        exp = probe.get("expected_exit") if isinstance(probe, dict) else None
        obs = probe.get("observed_exit") if isinstance(probe, dict) else None
        if type(exp) is not int or exp == 0 or type(obs) is not int or obs != exp:
            bad_probes.append(name)
    return failed, bad_probes


def row_for(platform, pconf, logs, tests, gaps, group):
    passed, failed, ignored, absent, neutral = [], [], [], [], []
    missing_targets = set()
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
            if not logs.get(target):
                # The whole target is missing from this platform's run.
                missing_targets.add(target)
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
    failed_commands, failed_probes = command_failures(pconf)
    if failed or ignored or (gaps and platform == "macos"):
        status = "in_progress"
    elif failed_commands or failed_probes or missing_targets:
        # A failed required command, a negative probe that did not fail as
        # expected, or a required target that never ran: never verified.
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
        "exit_codes": pconf.get("exit_codes"),
        "artifact_digest": pconf["artifact_digest"],
        "logs": pconf["logs"],
    }
    if failed_commands:
        row["failed_commands"] = failed_commands
    if pconf.get("negative_probes"):
        row["negative_probes"] = pconf["negative_probes"]
    if failed_probes:
        row["failed_negative_probes"] = failed_probes
    if missing_targets:
        row["missing_targets"] = sorted(missing_targets)
    if gaps:
        row["gap_cases"] = gap_rows
    if stale:
        row["not_run_since_build"] = row.pop("not_run_on_this_platform")
        row["predates_build"] = stale
    elif absent and harness_gap:
        row["harness_gap"] = harness_gap
    elif absent and status == "blocked":
        row["blocked_on"] = pconf.get("blocked_reason", "listed tests did not run on this platform")
    return row


def lowest(statuses):
    return min(statuses, key=ORDER.index)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--write", action="store_true")
    ap.add_argument(
        "--generate-inventory",
        action="store_true",
        help="write the required inventory from the case index and the current sources, then exit",
    )
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    index = json.loads(Path(cfg["case_index"]).read_text())
    inv_path = inventory_path(cfg)

    if args.generate_inventory:
        try:
            inv = build_inventory(index, cargo_lister(Path.cwd()), host_platform())
        except (InventoryError, subprocess.CalledProcessError) as e:
            print(f"inventory not generated: {e}", file=sys.stderr)
            return 1
        inv_path.write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n")
        for kind in ("groups", "exit_claims"):
            for sid, parts in inv[kind].items():
                print(kind, sid, {p: sum(len(v) for v in t.values()) for p, t in parts.items()})
        print("wrote", inv_path)
        return 0

    if not inv_path.is_file():
        print(f"no required inventory at {inv_path}; run --generate-inventory and commit it", file=sys.stderr)
        return 2
    inventory = json.loads(inv_path.read_text())
    problems = check_inventory(index, inventory)
    if problems:
        for p in problems:
            print(f"required inventory: {p}", file=sys.stderr)
        return 1

    plat_logs = {}
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

    rc = 0
    # A current-build test in a wildcard target that the inventory lacks: the
    # inventory is stale (regenerate it; a removed test is caught as absent).
    for kind, sid, part, spec, _ in _sections(index):
        for target, names in spec.items():
            if names != "*":
                continue
            extra = sorted(set(current.get(target, {})) - set(inventory[kind][sid][part][target]))
            for n in extra:
                print(f"{sid}: {target}::{n} ran but is not in the required inventory (regenerate)", file=sys.stderr)
                rc = 1

    def required(kind, sid, part):
        spec = (index[kind][sid]).get(part, {})
        return expand_required(spec, inventory[kind][sid].get(part, {}))

    extra_rows = cfg.get("extra_rows", {})
    for gid, extras in extra_rows.items():
        for extra in extras:
            if extra.get("status") == "verified":
                # A configured row carries no test log: it cannot verify anything.
                print(f"{gid}: extra row {extra.get('platform')!r} claims verified without a log", file=sys.stderr)
                extra["status"] = "in_progress"
                rc = 1

    summary = {}
    groups = dict(index["groups"])
    for gid, g in groups.items():
        tests = required("groups", gid, "tests")
        gaps = required("groups", gid, "gaps")
        # Every required name must exist somewhere (a typo or a target that no
        # longer runs is a defect, not a gap).
        for target, name in tests:
            if not any(name in plat_logs[p].get(target, {}) for p in plat_logs):
                print(f"{gid}: {target}::{name} not found in any log", file=sys.stderr)
                rc = 1
        rows = [r for pn in cfg["platforms"] if (r := row_for(pn, cfg["platforms"][pn], plat_logs[pn], tests, gaps, g))]
        for extra in extra_rows.get(gid, []):
            rows.append(extra)
        summary[gid] = {"tests": len(tests), "rows": rows}

    # Exit claims: rows over the union of their tests and groups.
    claim_rows = {}
    for claim, c in index["exit_claims"].items():
        tests = []
        g_extra = []
        for gid in c.get("groups", []):
            tests.extend(required("groups", gid, "tests"))
            g_extra.extend(extra_rows.get(gid, []))
        if "tests" in c:
            tests.extend(required("exit_claims", claim, "tests"))
        gaps = []
        for gid in c.get("groups", []):
            gaps.extend(required("groups", gid, "gaps"))
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
