#!/usr/bin/env python3
"""M02-U11: the native harnesses' run plan, the required inventory, and the evidence
records (generalized from tests/native/m01/m01-evidence.py; m02-plan §3, §4).

Usage (from the repository root, with `python3 -I`):
  m02-evidence.py --skip-plan PLATFORM --case-index C --targets all.tsv \\
      --run-out run.tsv --skips-out skips.tsv --report-out skipped.txt
  m02-evidence.py --list-targets DIR
  m02-evidence.py --config tests/native/m02/runs.json --generate-inventory \\
      [--scan linux=REPORT --scan windows=REPORT]
  m02-evidence.py --config tests/native/m02/runs.json --check-inventory
  m02-evidence.py --config tests/native/m02/runs.json [--write]

Required tests never come from run logs (review C02). They come from the case index
(tests/native/m02/case-index.json) resolved against the build host's sources into
required-inventory.json: `--generate-inventory` lists every target with `cargo test --
--list`, resolves each pattern (`*`, `prefix*`, `*suffix`, a full or last-segment name),
and refuses a pattern that resolves to nothing. platform-tests.py scans of the
cross-built binaries (`--scan PLATFORM=REPORT`) add which tests `#[cfg]` removes on each
platform (`platform_only`) and the platform-only tests a pattern covers
(`platform_extra`). The inventory records the digest of the sources it was generated
from; a check against changed sources is refused (regenerate).

Observations. A test that settles an ADR-0007 `[I]` or `[U]` fact prints one line that
starts with `observation` (stderr; the harnesses run every binary with `--show-output`, so
a passing test's lines are kept). parse_observations() reads them from the same logs, under
the `---- <test> stdout ----` header of the test that printed them, and a row carries the
lines of its passed required tests in `observations` (deduplicated, bounded), so a record
shows what each platform observed, not only that the test passed. case-index.json
`observation_targets` lists the targets that print them; run-macos.sh runs those once more
through cargo with `--show-output`, because check.sh's own run discards passing output.

Rows (per case, per platform): each applicable required test is passed, failed,
ignored or absent in that platform's logs. verified only when every applicable
required test ran and passed there, every required command exited 0 and every negative
probe exited exactly as expected. A failed or ignored test, a test missing from a
current run, a build-host-path test that is a harness gap (build_host_paths, neutral
false), a nonzero command or a predates_build log keep the row in_progress. blocked is
only for a missing platform (`unavailable`), a capability named in
`missing_capabilities`, or the case's owner-input rows (`blocked_rows`), each with
blocked_on naming the exact input. A record's status is its lowest row, lowest first:
blocked, not_started, in_progress, implemented_unverified, verified
(tests/evidence/README.md); deferred_with_decision rows do not count.

The coverage guard (ADR-0007 §12.47 item 1). Applicability alone would let a platform row
read verified on whatever few tests survive the `#[cfg]` scan, so on a platform a section
declares:
  * (R1) every required test that does not apply there is counted in
    `excluded_on_this_platform`. One excluded by a case-index `platform_only` entry (each
    carries a `rationale`, validated) is listed by entry in `excluded_by_rationale`; one
    excluded by the inventory scan alone has no reason on record, is listed in
    `excluded_without_rationale`, and keeps the row in_progress;
  * (R2) a section's `platform_required` {platform: {target: [exact name]}} names tests that
    must pass on that platform. They are never resolved against the inventory, so a planned
    test that does not exist yet reads as not run: `platform_required_not_passed`, and the
    row is in_progress.
A case-index exclusion of a test that did run on that platform is stale (exit 1). Every record is
validated against tests/evidence/record.schema.json before it is written. A configured
log or commands file that does not exist is an error: nothing is written for a run that
did not happen.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

# Lowest first (tests/evidence/README.md, ADR-0004 §4).
ORDER = ["blocked", "not_started", "in_progress", "implemented_unverified", "verified"]
NOT_COUNTED = "deferred_with_decision"
ROOT = Path(__file__).resolve().parents[3]


class PlanError(Exception):
    """The case index cannot produce a run plan."""


class InventoryError(Exception):
    """The required inventory cannot be built or does not match the index."""


class RunError(Exception):
    """A configured run artifact is missing or malformed."""


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# --- patterns --------------------------------------------------------------------------


def leaf(name):
    return name.rsplit("::", 1)[-1]


def is_pattern(item):
    return item.startswith("*") or item.endswith("*")


def matches(item, name):
    """A case-index item against a full test name: `*` (all), `prefix*` (the full name or
    its last segment starts with prefix), `*suffix` (the full name ends with suffix),
    `*infix*`, or a name equal to the full name or its last segment."""
    if item == "*":
        return True
    if item.startswith("*") and item.endswith("*") and len(item) > 1:
        return item[1:-1] in name
    if item.endswith("*"):
        p = item[:-1]
        return name.startswith(p) or leaf(name).startswith(p)
    if item.startswith("*"):
        return name.endswith(item[1:])
    return name == item or leaf(name) == item


def spec_items(spec):
    return ["*"] if spec == "*" else list(spec)


# --- the run plan ----------------------------------------------------------------------


def skip_plan(index, platform, targets):
    """(run [(name, exe)], skips [(target, test)], report lines) for one platform.

    build_host_paths entries are tests (or whole targets) that read the repository at its
    compile-time path; they cannot run on another host. On the build host they run like
    every other test.
    """
    plats = index.get("platforms", {})
    if platform not in plats:
        raise PlanError(f"unknown platform {platform!r}")
    if plats[platform].get("runs") != "cargo":
        raise PlanError(f"platform {platform!r} runs no cargo test binaries")
    entries = index.get("build_host_paths", {})
    on_build_host = platform == index.get("build_host")
    names = {n for n, _ in targets}
    for key, meta in sorted(entries.items()):
        if key.split("::", 1)[0] not in names:
            raise PlanError(f"build_host_paths entry {key} names no built target")
        if not isinstance(meta, dict) or not isinstance(meta.get("neutral"), bool) or not meta.get("reason"):
            raise PlanError(f"build_host_paths entry {key} needs neutral (bool) and reason")

    def kind(meta):
        return "platform-neutral, run on the build host" if meta["neutral"] else "harness gap"

    run, skips, report = [], [], []
    for name, exe in targets:
        whole = entries.get(name)
        if whole and not on_build_host:
            report.append(f"{name}: not run on {platform} ({kind(whole)}): {whole['reason']}")
            continue
        run.append((name, exe))
        if on_build_host:
            continue
        for key, meta in sorted(entries.items()):
            t, _, test = key.partition("::")
            if test and t == name:
                skips.append((name, test))
                report.append(f"{key}: skipped on {platform} ({kind(meta)}): {meta['reason']}")
    return run, skips, report


def cmd_skip_plan(a):
    index = load_json(a.case_index)
    targets = []
    for line in Path(a.targets).read_text(encoding="utf-8").splitlines():
        if line.strip():
            name, exe = line.split("\t", 1)
            targets.append((name, exe))
    try:
        run, skips, report = skip_plan(index, a.skip_plan, targets)
    except PlanError as e:
        print(f"run plan: {e}", file=sys.stderr)
        return 2
    Path(a.run_out).write_text("".join(f"{n}\t{e}\n" for n, e in run), encoding="utf-8")
    Path(a.skips_out).write_text("".join(f"{t}\t{n}\n" for t, n in skips), encoding="utf-8")
    with open(a.report_out, "a", encoding="utf-8") as f:
        for line in report:
            f.write(line + "\n")
    return 0


# --- the required inventory ------------------------------------------------------------


def sections(index):
    """(kind, id, spec, section) for every test list of the index."""
    for gid, g in index["groups"].items():
        if "tests" in g:
            yield "groups", gid, g["tests"], g
    for claim, c in index["exit_claims"].items():
        if "tests" in c:
            yield "exit_claims", claim, c["tests"], c


def sources_digest(root):
    h = hashlib.sha256()
    files = []
    for base in ("tests", "crates"):
        files.extend(p for p in (root / base).rglob("*.rs") if "target" not in p.parts)
    for p in sorted(files):
        h.update(str(p.relative_to(root)).encode() + b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def build_inventory(index, lister, host, scans=None, digest=None):
    """The required inventory from the case index, the build host's sources (`lister`)
    and optional platform scans {platform: platform-tests.py report}."""
    scans = scans or {}
    scenario = index.get("scenario_targets", {})
    child = set(index.get("child_entries", {}))
    listed = {}

    def have(target):
        if target not in listed:
            names = sorted(set(lister(target) or []))
            listed[target] = [n for n in names if f"{target}::{n}" not in child]
        return listed[target]

    inv = {
        "description": "M02 required test inventory (review C02): generated by m02-evidence.py "
        "--generate-inventory from the case index, the build host's sources and the platform scans; "
        "compared against every run, never derived from one.",
        "build_host": host,
        "sources_sha256": digest,
        "scanned_platforms": sorted(scans),
        "groups": {},
        "exit_claims": {},
        "platform_extra": {},
        "platform_only": {},
    }
    problems = []
    for kind, sid, spec, _ in sections(index):
        out = {}
        for target, raw in spec.items():
            items = spec_items(raw)
            if target in scenario:
                steps = scenario[target].get("steps", {})
                for item in items:
                    if is_pattern(item) or item not in steps:
                        problems.append(f"{sid}: {target}::{item} is not a step of the scenario")
                out[target] = sorted(set(items))
                continue
            names = have(target)
            got = set()
            for item in items:
                hit = [n for n in names if matches(item, n)]
                beyond = [n for rep in scans.values() for n in (rep.get(target) or {}).get("extra", [])
                          if n not in names and is_pattern(item) and matches(item, n)]
                if not hit and not beyond:
                    problems.append(f"{sid}: {target}::{item} resolves to no test on the build host or a scanned platform")
                elif not is_pattern(item) and len(hit) > 1:
                    problems.append(f"{sid}: {target}::{item} is ambiguous ({len(hit)} tests)")
                got.update(hit)
            out[target] = sorted(got)
            for plat, rep in scans.items():
                extra = (rep.get(target) or {}).get("extra", [])
                add = sorted(n for n in extra if n not in names and any(is_pattern(i) and matches(i, n) for i in items))
                if add:
                    inv["platform_extra"].setdefault(sid, {}).setdefault(plat, {})[target] = add
        inv[kind][sid] = {"tests": out}
    if scans:
        inv["platform_only"] = scan_platform_only(host, have, scans, inv)
    if problems:
        raise InventoryError("; ".join(problems))
    return inv


def scan_platform_only(host, have, scans, inv):
    """platform_only entries {"target::name": [platforms]} for every required test that a
    scan found absent, and for every platform-only extra (where it exists)."""
    plats = sorted({host} | set(scans))
    out = {}
    required = set()
    for kind in ("groups", "exit_claims"):
        for sec in inv[kind].values():
            for target, names in sec["tests"].items():
                required.update((target, n) for n in names)
    for target, name in sorted(required):
        reps = {p: r[target] for p, r in scans.items() if target in r}
        if not reps:
            continue
        where = [host] + [p for p, r in reps.items() if name not in r["absent"]]
        where += [p for p in scans if target not in scans[p]]
        if sorted(set(where)) != plats:
            out[f"{target}::{name}"] = sorted(set(where))
    for sid, by_plat in inv["platform_extra"].items():
        for plat, by_target in by_plat.items():
            for target, names in by_target.items():
                for n in names:
                    key = f"{target}::{n}"
                    out[key] = sorted(set(out.get(key, [])) | {plat})
    return out


def check_index(index):
    """Problems (strings) in the case index's guard entries: every `platform_only` entry is
    {"platforms": [...], "rationale": "..."} (ADR-0006 §13.13 item 5; ADR-0007 §12.47 item
    1), and every `platform_required` list names exact tests on a platform its section
    declares."""
    problems = []
    plats = index.get("platforms", {})
    cargo = {p for p, m in plats.items() if m.get("runs") == "cargo"}
    scenario = index.get("scenario_targets", {})
    for key, entry in sorted((index.get("platform_only") or {}).items()):
        if not isinstance(entry, dict) or set(entry) != {"platforms", "rationale"}:
            problems.append(f"platform_only {key}: needs exactly platforms and rationale")
            continue
        where = entry["platforms"]
        if not isinstance(where, list) or not where or not all(isinstance(p, str) for p in where) \
                or len(set(where)) != len(where) or not set(where) <= cargo:
            problems.append(f"platform_only {key}: platforms must be distinct cargo platforms of the index")
        if not isinstance(entry["rationale"], str) or not entry["rationale"].strip():
            problems.append(f"platform_only {key}: the rationale is empty")
    if "platform_only_rationale" in index:
        problems.append("platform_only_rationale is withdrawn: each platform_only entry carries its rationale")
    for kind, sid, _, sec in sections(index):
        req = sec.get("platform_required")
        if req is None:
            continue
        if not isinstance(req, dict):
            problems.append(f"{sid}: platform_required is not a map")
            continue
        for plat, by_target in sorted(req.items()):
            if plat not in sec.get("declared_platforms", []):
                problems.append(f"{sid}: platform_required names {plat}, which the section does not declare")
            if not isinstance(by_target, dict) or not by_target:
                problems.append(f"{sid}: platform_required {plat} is not a non-empty map of targets")
                continue
            for target, names in sorted(by_target.items()):
                if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
                    problems.append(f"{sid}: platform_required {plat} {target} is not a list of names")
                    continue
                if len(set(names)) != len(names):
                    problems.append(f"{sid}: platform_required {plat} {target} repeats a name")
                for n in names:
                    if is_pattern(n):
                        problems.append(f"{sid}: platform_required {plat} {target}::{n} is a pattern, not an exact name")
                if target in scenario:
                    if plat not in scenario[target].get("platforms", []):
                        problems.append(f"{sid}: platform_required {plat} {target}: the scenario does not run on {plat}")
                    for n in names:
                        if n not in scenario[target].get("steps", {}):
                            problems.append(f"{sid}: platform_required {plat} {target}::{n} is not a step of the scenario")
                elif plat not in cargo:
                    problems.append(f"{sid}: platform_required {plat} {target}: {plat} runs no cargo test binaries")
    return problems


def check_inventory(index, inv):
    """Problems (strings) between the case index and a committed inventory (structure
    only; evaluate() also requires the inventory's sources digest to match). The case
    index's own guard entries are checked first (check_index)."""
    problems = check_index(index)
    seen = set()
    scenario = index.get("scenario_targets", {})
    for kind, sid, spec, _ in sections(index):
        seen.add((kind, sid))
        got = (inv.get(kind, {}).get(sid) or {}).get("tests")
        if not isinstance(got, dict):
            problems.append(f"{sid}: no required inventory")
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
                continue
            if not names and not any(target in by_t for by_t in (inv.get("platform_extra", {}).get(sid) or {}).values()):
                problems.append(f"{sid}: inventory for {target} is empty")
                continue
            extra = [n for by_t in (inv.get("platform_extra", {}).get(sid) or {}).values() for n in by_t.get(target, [])]
            for item in spec_items(spec[target]):
                if target in scenario:
                    if item not in names:
                        problems.append(f"{sid}: scenario step {target}::{item} missing from the inventory")
                elif not any(matches(item, n) for n in names + extra):
                    problems.append(f"{sid}: {target}::{item} matches nothing in the inventory")
            for n in names:
                if target not in scenario and not any(matches(i, n) for i in spec_items(spec[target])):
                    problems.append(f"{sid}: inventory name {target}::{n} is not covered by the case index")
    for kind in ("groups", "exit_claims"):
        for sid in inv.get(kind, {}):
            if (kind, sid) not in seen:
                problems.append(f"{sid}: inventory section is not in the case index")
    return problems


def cargo_targets(root):
    """{target name: (package, cargo selector)} for every test-bearing target of the
    workspace, named as the harness logs them (lib and bin unit tests are `<name>-unit`)."""
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
                where[t["name"].replace("-", "_") + "-unit"] = (pkg["name"], ["--lib"])
            elif "bin" in t["kind"]:
                where[t["name"] + "-unit"] = (pkg["name"], ["--bin", t["name"]])
    return where


def cargo_lister(root, where=None):
    """lister(target) through `cargo test ... -- --list` (build host sources)."""
    where = cargo_targets(root) if where is None else where

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


def cmd_list_targets(out_dir):
    """Write DIR/<target>.txt (one test name per line) for every target, from the build
    host's sources: the listings platform-tests.py compares each cross-built binary with."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    where = cargo_targets(ROOT)
    lister = cargo_lister(ROOT, where)
    for target in sorted(where):
        names = sorted(set(lister(target) or []))
        (d / f"{target}.txt").write_text("".join(n + "\n" for n in names), encoding="utf-8")
    print(f"listed {len(where)} targets into {d}")
    return 0


def inventory_path(cfg):
    if cfg.get("required_inventory"):
        return Path(cfg["required_inventory"])
    return Path(cfg["case_index"]).with_name("required-inventory.json")


# --- applicability and rows ------------------------------------------------------------


def index_platform_only(index):
    """{key: [platforms]} of the case index's platform_only entries ({"platforms",
    "rationale"}; check_index validates the form)."""
    return {k: (e.get("platforms") if isinstance(e, dict) else e) for k, e in (index.get("platform_only") or {}).items()}


def most_specific(entries, target, name):
    """(key, platforms) of the most specific entry of {key: platforms} covering a test, or
    (None, None): the exact name, else the longest `target::prefix::` or `target::prefix*`,
    else the bare target."""
    full = f"{target}::{name}"
    if full in entries:
        return full, entries[full]
    best, best_len = (None, None), -1
    for key, plats in entries.items():
        t, sep, rest = key.partition("::")
        if t != target:
            continue
        if not sep:
            ok, length = True, 0
        elif rest.endswith("::"):
            ok, length = name.startswith(rest), len(rest)
        elif rest.endswith("*"):
            ok, length = name.startswith(rest[:-1]), len(rest) - 1
        else:
            ok, length = False, 0
        if ok and length > best_len:
            best, best_len = (key, plats), length
    return best


def platform_only_lookup(index, inv, target, name):
    """The platforms the most specific platform_only entry allows, or None (case-index
    entries override inventory entries with the same key)."""
    entries = dict(inv.get("platform_only", {}))
    entries.update(index_platform_only(index))
    return most_specific(entries, target, name)[1]


def applicable(index, inv, target, name, platform):
    scenario = index.get("scenario_targets", {})
    if target in scenario:
        return platform in scenario[target].get("platforms", [])
    if index.get("platforms", {}).get(platform, {}).get("runs") != "cargo":
        return False
    if f"{target}::{name}" in index.get("child_entries", {}):
        return False
    plats = platform_only_lookup(index, inv, target, name)
    return True if plats is None else platform in plats


def required(index, inv, kind, sid, platform):
    """[(target, name)] a section requires on a platform."""
    names = inv[kind][sid]["tests"]
    out = [(t, n) for t, ns in names.items() for n in ns]
    extra = inv.get("platform_extra", {}).get(sid, {}).get(platform, {})
    out += [(t, n) for t, ns in extra.items() for n in ns]
    return [(t, n) for t, n in out if applicable(index, inv, t, n, platform)]


def coverage_guard(index, inv, kind, sid, platform, logs):
    """R1 and R2 of ADR-0007 §12.47 item 1 for one section on one platform.

    {"excluded": [qual], "by_rationale": {case-index key: count}, "unjustified": [qual],
     "required_not_passed": {qual: result}, "stale": [(key, qual, result)]}

    R1 applies on a cargo platform the section declares: a required test (the section's
    inventory names; platform_extra tests exist only where they apply, scenario steps and
    child entry points are never cargo tests here) that does not apply on the platform is
    excluded. The most specific case-index platform_only entry justifies the exclusion when
    it leaves the platform out; anything else excluded it through the inventory scan alone.
    A justified exclusion of a test that has a result in this platform's logs is stale.
    R2 reads the section's platform_required names for the platform from the logs, exactly."""
    sec = index[kind][sid]
    out = {"excluded": [], "by_rationale": {}, "unjustified": [], "required_not_passed": {}, "stale": []}
    is_cargo = index.get("platforms", {}).get(platform, {}).get("runs") == "cargo"
    if is_cargo and platform in sec.get("declared_platforms", []):
        scenario = index.get("scenario_targets", {})
        child = index.get("child_entries", {})
        own = index_platform_only(index)
        for target, names in sorted(inv[kind][sid]["tests"].items()):
            if target in scenario:
                continue
            for n in names:
                qual = f"{target}::{n}"
                if qual in child or applicable(index, inv, target, n, platform):
                    continue
                out["excluded"].append(qual)
                key, where = most_specific(own, target, n)
                if key is not None and platform not in where:
                    out["by_rationale"][key] = out["by_rationale"].get(key, 0) + 1
                    result = logs.get(target, {}).get(n)
                    if result is not None:
                        out["stale"].append((key, qual, result))
                else:
                    out["unjustified"].append(qual)
    for target, names in sorted(((sec.get("platform_required") or {}).get(platform) or {}).items()):
        for n in names:
            result = logs.get(target, {}).get(n)
            if result != "ok":
                out["required_not_passed"][f"{target}::{n}"] = result or "absent"
    return out


def build_host_path(index, target, name):
    entries = index.get("build_host_paths", {})
    return entries.get(f"{target}::{name}") or entries.get(target)


def parse_log(path):
    """{target: {test: result}} from cargo output or a harness tests.txt."""
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
        if re.match(r"^\s*Doc-tests ", line):
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


OBSERVATION_LINES_PER_TEST = 40
OBSERVATION_LINES_PER_ROW = 300


def parse_observations(path):
    """{target: {test: [observation lines]}} from cargo output or a harness tests.txt.

    A line belongs to the test named by the closest `---- <test> stdout ----` header above
    it (libtest's `--show-output` and failure reports); a line before any header is kept
    under the empty test name. Lines are stripped and deduplicated, in order."""
    out = {}
    target = None
    test = ""
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw).rstrip("\r")
        m = re.match(r"^\s*Running (.+?) \((?:.*[/\\])?([A-Za-z0-9_-]+?)-[0-9a-f]+(?:\.exe)?\)$", line)
        if m:
            src, binary = m.groups()
            target = binary if src.startswith("../") or src.startswith("tests") else binary + "-unit"
            test = ""
            continue
        if re.match(r"^\s*Doc-tests ", line):
            target = None
            continue
        m = re.match(r"^### ([A-Za-z0-9_-]+)$", line)
        if m:
            target = m.group(1)
            test = ""
            continue
        m = re.match(r"^---- (\S+) stdout ----$", line)
        if m:
            test = m.group(1)
            continue
        if re.match(r"^(successes|failures):$", line) or line.startswith("test result:"):
            test = ""
            continue
        if target is not None and re.match(r"^\s*observation\b", line):
            lines = out.setdefault(target, {}).setdefault(test, [])
            text = line.strip()
            if text not in lines and len(lines) < OBSERVATION_LINES_PER_TEST:
                lines.append(text)
    return out


def parse_commands(path):
    """{command: exit} from a harness commands.txt ("exit N: command")."""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^exit (-?\d+): (.+)$", line)
        if m:
            out[m.group(2)] = int(m.group(1))
    return out


def parse_facts(path):
    """key=value lines of a harness host.txt (versions, classifications, counts)."""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)=(.*)$", line)
        if m:
            out.setdefault(m.group(1), m.group(2))
    return out


def merge(into, more):
    for target, tests in more.items():
        into.setdefault(target, {}).update(tests)


def command_failures(pconf):
    """(failed required commands, failed negative probes) of a platform run."""
    req = pconf.get("exit_codes")
    if not isinstance(req, dict) or not req:
        failed = ["(no required command exit recorded)"]
    else:
        # bool is an int subclass: only an actual integer 0 is a pass.
        failed = [k for k, v in req.items() if type(v) is not int or v != 0]
    bad = []
    for name, probe in (pconf.get("negative_probes") or {}).items():
        exp = probe.get("expected_exit") if isinstance(probe, dict) else None
        obs = probe.get("observed_exit") if isinstance(probe, dict) else None
        if type(exp) is not int or exp == 0 or type(obs) is not int or obs != exp:
            bad.append(name)
    return failed, bad


def missing_capability(pconf, target, name):
    caps = pconf.get("missing_capabilities") or {}
    reason = caps.get(f"{target}::{name}", caps.get(target))
    return reason if isinstance(reason, str) and reason else None


def row_observations(passed, obs):
    """({qualified test: [lines]}, truncated) for the passed required tests that printed
    observation lines, at most OBSERVATION_LINES_PER_ROW lines in all."""
    out, total, truncated = {}, 0, False
    for qual in passed:
        target, _, name = qual.partition("::")
        # Tests are keyed by their full name; `qual` is `target::<full name>`.
        lines = (obs.get(target) or {}).get(name)
        if not lines:
            continue
        room = OBSERVATION_LINES_PER_ROW - total
        if room <= 0:
            truncated = True
            continue
        keep = lines[:room]
        truncated = truncated or len(keep) < len(lines)
        out[qual] = keep
        total += len(keep)
    return out, truncated


def guard_fields(guard):
    """The row fields of a coverage_guard() result (excluded_on_this_platform always)."""
    out = {"excluded_on_this_platform": len(guard["excluded"])}
    if guard["by_rationale"]:
        out["excluded_by_rationale"] = dict(sorted(guard["by_rationale"].items()))
    if guard["unjustified"]:
        out["excluded_without_rationale"] = list(guard["unjustified"])
    if guard["required_not_passed"]:
        out["platform_required_not_passed"] = dict(guard["required_not_passed"])
    return out


def guard_gap(guard):
    return bool(guard and (guard["unjustified"] or guard["required_not_passed"]))


def row_for(index, platform, pconf, logs, tests, obs=None, guard=None):
    passed, failed, ignored, absent, neutral, gap = [], [], [], [], [], []
    incomplete, reasons, missing_targets = [], set(), set()
    build_host = platform == index.get("build_host")
    for target, name in tests:
        qual = f"{target}::{name}"
        r = logs.get(target, {}).get(name)
        if r == "ok":
            passed.append(qual)
        elif r == "FAILED":
            failed.append(qual)
        elif r == "ignored":
            ignored.append(qual)
        else:
            bhp = None if build_host else build_host_path(index, target, name)
            if bhp and bhp["neutral"]:
                neutral.append(qual)
                continue
            if bhp:
                gap.append(qual)
                continue
            absent.append(qual)
            reason = missing_capability(pconf, target, name)
            if reason:
                reasons.add(reason)
                continue
            incomplete.append(qual)
            if not logs.get(target):
                missing_targets.add(target)
    if not (passed or failed or ignored or absent or gap):
        return None
    stale = pconf.get("predates_build")
    unavailable = pconf.get("unavailable")
    ran = bool(passed or failed or ignored)
    failed_commands, failed_probes = command_failures(pconf)
    if unavailable and not ran and not stale:
        status = "blocked"
    elif unavailable or failed or ignored:
        status = "in_progress"
    elif failed_commands or failed_probes or missing_targets or gap or stale or incomplete or guard_gap(guard):
        # An unexplained exclusion or a declared test that did not pass is a coverage gap
        # (ADR-0007 §12.47 item 1), like an incomplete run: it outranks a missing capability.
        status = "in_progress"
    elif reasons:
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
        "artifact_digest": pconf.get("artifact_digest"),
        "logs": pconf.get("logs", []),
    }
    if guard is not None:
        row.update(guard_fields(guard))
    seen, truncated = row_observations(passed, obs or {})
    if seen:
        row["observations"] = seen
        if truncated:
            row["observations_truncated"] = True
    if gap:
        row["harness_gap_not_run"] = gap
    if incomplete and not stale and not (unavailable and not ran):
        row["incomplete_run"] = incomplete
    if failed_commands and not (status == "blocked" and unavailable):
        row["failed_commands"] = failed_commands
    if pconf.get("negative_probes"):
        row["negative_probes"] = pconf["negative_probes"]
    if failed_probes:
        row["failed_negative_probes"] = failed_probes
    if missing_targets:
        row["missing_targets"] = sorted(missing_targets)
    if stale:
        row["not_run_since_build"] = row.pop("not_run_on_this_platform")
        row["predates_build"] = stale
    if status == "blocked":
        if unavailable and not ran:
            row["blocked_on"] = unavailable
            row.pop("missing_targets", None)
        else:
            row["blocked_on"] = "; ".join(sorted(reasons))
    elif reasons and not stale:
        row["missing_capabilities"] = sorted(reasons)
    return row


def lowest(statuses):
    counted = [s for s in statuses if s != NOT_COUNTED]
    if not counted:
        return NOT_COUNTED
    return min(counted, key=ORDER.index)


def validate_record(rec):
    sys.path.insert(0, str(ROOT / "tests" / "g02"))
    import minischema  # noqa: E402

    schema = load_json(ROOT / "tests" / "evidence" / "record.schema.json")
    return minischema.validate(schema, rec)


# --- evaluation ------------------------------------------------------------------------


def load_platforms(cfg):
    """{platform: (pconf, logs)} with commands and facts read from the artifacts."""
    base = Path(cfg.get("artifacts_root", "."))
    out = {}
    for pname, p in cfg["platforms"].items():
        p = dict(p)
        logs = {}
        if not p.get("unavailable"):
            for key in ("logs", "commands_logs", "facts"):
                for rel in p.get(key, []):
                    if not (base / rel).is_file():
                        raise RunError(f"{pname}: {key} entry {rel} does not exist under {base} (not executed or not saved)")
            for rel in p.get("logs", []):
                merge(logs, parse_log(base / rel))
            codes = {}
            for rel in p.get("commands_logs", []):
                codes.update(parse_commands(base / rel))
            codes.update(p.get("exit_codes") or {})
            p["exit_codes"] = codes
            facts = {}
            for rel in p.get("facts", []):
                facts.update(parse_facts(base / rel))
            p["_facts"] = facts
            seen = {}
            for rel in p.get("logs", []):
                for target, by_test in parse_observations(base / rel).items():
                    for test, lines in by_test.items():
                        have = seen.setdefault(target, {}).setdefault(test, [])
                        have.extend(x for x in lines if x not in have)
            p["_observations"] = seen
        out[pname] = (p, logs)
    return out


def evaluate(cfg, index, inv):
    """(summary, rc) over every section and platform."""
    plats = load_platforms(cfg)
    rc = 0
    # A current-build test in a whole-target ("*") spec that the inventory lacks: the
    # inventory is stale (regenerate; a removed test shows up as absent).
    for kind, sid, spec, _ in sections(index):
        for target, raw in spec.items():
            if "*" not in spec_items(raw):
                continue
            for pname, (p, logs) in plats.items():
                if p.get("predates_build"):
                    continue
                known = set(inv[kind][sid]["tests"].get(target, []))
                known |= set(inv.get("platform_extra", {}).get(sid, {}).get(pname, {}).get(target, []))
                known |= {k.split("::", 1)[1] for k in index.get("child_entries", {}) if k.startswith(target + "::")}
                for n in sorted(set(logs.get(target, {})) - known):
                    print(f"{sid}: {target}::{n} ran on {pname} but is not in the required inventory (regenerate)", file=sys.stderr)
                    rc = 1

    def rows_for(kind, sid, extra_rows, declared):
        nonlocal rc
        rows = []
        for pname, (p, logs) in plats.items():
            tests = required(index, inv, kind, sid, pname)
            guard = coverage_guard(index, inv, kind, sid, pname, logs)
            for key, qual, result in guard["stale"]:
                print(f"{sid}: case-index platform_only {key} leaves out {pname}, but {qual} ran there ({result}); "
                      "add the platform to the entry or remove the entry", file=sys.stderr)
                rc = 1
            r = row_for(index, pname, p, logs, tests, p.get("_observations"), guard)
            if r:
                rows.append(r)
            elif pname in declared:
                # m02-plan §4 declares a row here, but no indexed test applies: a
                # coverage gap, never a pass (blocked when the platform itself is missing).
                gap = {"platform": p["label"], "status": "in_progress",
                       "no_applicable_test": "m02-plan §4 declares this platform row; no indexed test applies on it"}
                gap.update(guard_fields(guard))
                if p.get("unavailable"):
                    gap.update(status="blocked", blocked_on=p["unavailable"])
                rows.append(gap)
        for pname in declared:
            if pname not in plats:
                rows.append({"platform": pname, "status": "not_started",
                             "not_configured": "m02-plan §4 declares this platform row; runs.json has no run for it"})
        rows.extend(dict(r) for r in extra_rows)
        return rows

    def check_found(kind, sid):
        """A required test that applies to a platform that ran (ADR-0007 §12.32 item 10: a
        platform the run marks `unavailable` ran nothing, so its tests are never looked
        for; its rows are `blocked` instead) must appear in some log."""
        nonlocal rc
        ran = [pn for pn, (p, _) in plats.items() if not p.get("unavailable")]
        for target, names in inv[kind][sid]["tests"].items():
            for n in names:
                anywhere = any(n in logs.get(target, {}) for _, logs in plats.values())
                applies = any(applicable(index, inv, target, n, pn) for pn in ran)
                neutral_elsewhere = build_host_path(index, target, n)
                if applies and not anywhere and not neutral_elsewhere:
                    print(f"{sid}: {target}::{n} not found in any log", file=sys.stderr)
                    rc = 1

    run_extra = cfg.get("extra_rows", {})
    for sid, extras in run_extra.items():
        for extra in extras:
            if extra.get("status") == "verified":
                print(f"{sid}: extra row {extra.get('platform')!r} claims verified without a log", file=sys.stderr)
                extra["status"] = "in_progress"
                rc = 1
    summary = {"groups": {}, "exit_claims": {}}
    for gid, g in index["groups"].items():
        check_found("groups", gid)
        extra = list(g.get("blocked_rows", [])) + list(run_extra.get(gid, []))
        rows = rows_for("groups", gid, extra, g.get("declared_platforms", []))
        n = sum(len(v) for v in inv["groups"][gid]["tests"].values())
        summary["groups"][gid] = {"tests": n, "rows": rows, "status": lowest([r["status"] for r in rows])}
    for claim, c in index["exit_claims"].items():
        rows = []
        n = 0
        if "tests" in c:
            check_found("exit_claims", claim)
            extra = list(c.get("blocked_rows", [])) + list(run_extra.get(claim, []))
            rows.extend(rows_for("exit_claims", claim, extra, c.get("declared_platforms", [])))
            n += sum(len(v) for v in inv["exit_claims"][claim]["tests"].values())
        for gid in c.get("groups", []):
            rows.extend(summary["groups"][gid]["rows"])
            n += summary["groups"][gid]["tests"]
        summary["exit_claims"][claim] = {
            "tests": n,
            "rows": rows,
            "status": lowest([r["status"] for r in rows]) if rows else "not_started",
            "note": c.get("note"),
        }
    return summary, plats, rc


def environment_of(cfg, plats):
    env = dict(cfg.get("environment") or {})
    facts = {}
    # mode, build-target, build-commit and toolchain*: the Windows local-mode runner's facts
    # (run-windows-local.ps1; ADR-0007 §12.32 item 17), which name the target honestly.
    keep = re.compile(r"^(os|glibc|nproc|script|scratch-fs|integrity|developer-mode|ssh-V.*|sshd-V.*|git-version.*|fixture-sshd.*|leftover-test-processes|test-pipes-.*|localappdata-heimdall-.*|inherited-.*|home-fs|rename-exchange|birth-time|sshd-accepted-logins|default-identity-guard|time-confirmation|mode|build-target|build-commit|toolchain.*)$")
    for pname, (p, _) in plats.items():
        f = {k: v for k, v in p.get("_facts", {}).items() if keep.match(k)}
        if f:
            facts[pname] = f
    if facts:
        env["host_facts"] = facts
    return env


def provider_versions(plats):
    out = []
    for pname, (p, _) in plats.items():
        for k, v in sorted(p.get("_facts", {}).items()):
            if k.startswith(("ssh-V", "sshd-V", "git-version", "fixture-sshd-V")):
                out.append(f"{pname} {k}: {v}")
    return out


def records(cfg, summary, plats):
    out = []
    for sid, meta in cfg["records"].items():
        if sid in summary["groups"]:
            s = summary["groups"][sid]
            observed = {"indexed_tests": s["tests"], "rows": s["rows"]}
        else:
            s = summary["exit_claims"][sid]
            observed = {"indexed_tests": s["tests"], "rows": s["rows"], "note": s["note"]}
        status = s["status"]
        counts = {}
        for r in s["rows"]:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        observed["row_statuses"] = counts
        observed["summary"] = meta["summary"]
        blocked = sorted({r["blocked_on"] for r in s["rows"] if r.get("status") == "blocked" and r.get("blocked_on")})
        rec = {
            "case_id": meta["case_id"],
            "status": status,
            "requirement_ids": meta["requirement_ids"],
            "build_commit": cfg.get("build_commit"),
            "artifact_digest": cfg.get("artifact_digest"),
            "environment": environment_of(cfg, plats),
            "provider_versions": provider_versions(plats),
            "started_at": cfg.get("started_at"),
            "commands_or_harness": cfg.get("commands"),
            "observed_result": observed,
            "evidence_paths": list(cfg.get("evidence_paths", [])) + [cfg["case_index"], cfg["summary_out"]],
            "limitations": list(meta.get("limitations", [])) + list(cfg.get("common_limitations", [])),
            "blocked_on": "; ".join(blocked) if blocked else None,
        }
        if status == "blocked" and not rec["blocked_on"]:
            raise RunError(f"{sid}: blocked without a named input")
        out.append((meta["path"], rec))
    return out


# --- commands --------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-plan", metavar="PLATFORM")
    ap.add_argument("--case-index")
    ap.add_argument("--targets")
    ap.add_argument("--run-out")
    ap.add_argument("--skips-out")
    ap.add_argument("--report-out")
    ap.add_argument("--config")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--generate-inventory", action="store_true")
    ap.add_argument("--check-inventory", action="store_true")
    ap.add_argument("--scan", action="append", default=[], metavar="PLATFORM=REPORT")
    ap.add_argument("--list-targets", metavar="DIR")
    a = ap.parse_args(argv)
    if a.skip_plan:
        return cmd_skip_plan(a)
    if a.list_targets:
        try:
            return cmd_list_targets(a.list_targets)
        except (InventoryError, subprocess.CalledProcessError) as e:
            print(f"targets not listed: {e}", file=sys.stderr)
            return 1
    if not a.config:
        ap.error("--config is required")
    cfg = load_json(a.config)
    index = load_json(cfg["case_index"])
    inv_path = inventory_path(cfg)
    digest = sources_digest(Path(cfg.get("sources_root", ROOT)))

    if a.generate_inventory:
        scans = {}
        for item in a.scan:
            plat, _, path = item.partition("=")
            scans[plat] = load_json(path)
        try:
            inv = build_inventory(index, cargo_lister(ROOT), index.get("build_host", "macos"), scans, digest)
        except (InventoryError, subprocess.CalledProcessError) as e:
            print(f"inventory not generated: {e}", file=sys.stderr)
            return 1
        inv_path.write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        for kind in ("groups", "exit_claims"):
            for sid, sec in inv[kind].items():
                print(kind, sid, sum(len(v) for v in sec["tests"].values()))
        print("wrote", inv_path)
        return 0

    if not inv_path.is_file():
        print(f"no required inventory at {inv_path}; run --generate-inventory and commit it", file=sys.stderr)
        return 2
    inv = load_json(inv_path)
    problems = check_inventory(index, inv)
    if problems:
        for p in problems:
            print(f"required inventory: {p}", file=sys.stderr)
        return 1
    if a.check_inventory:
        same = "the same" if inv.get("sources_sha256") == digest else "other"
        print(f"required inventory matches the case index (generated from {same} sources)")
        return 0
    if inv.get("sources_sha256") != digest:
        # Records describe one build: the inventory must come from exactly its sources.
        print("required inventory: generated from other sources (sources_sha256 differs); regenerate at the build commit", file=sys.stderr)
        return 1
    try:
        summary, plats, rc = evaluate(cfg, index, inv)
    except RunError as e:
        print(f"runs: {e}", file=sys.stderr)
        return 2
    Path(cfg["summary_out"]).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    for kind in ("groups", "exit_claims"):
        for sid, s in summary[kind].items():
            print(kind, sid, s["tests"], s["status"], [(r["platform"], r["status"]) for r in s["rows"]])
    if a.write:
        try:
            recs = records(cfg, summary, plats)
        except RunError as e:
            print(f"records: {e}", file=sys.stderr)
            return 2
        for path, rec in recs:
            errors = validate_record(rec)
            if errors:
                print(f"{path}: invalid record: {errors[:3]}", file=sys.stderr)
                return 1
        for path, rec in recs:
            Path(path).write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print("wrote", path, rec["status"])
    return rc


if __name__ == "__main__":
    sys.exit(main())
