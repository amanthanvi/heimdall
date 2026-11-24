#!/usr/bin/env python3
"""M06-U7: the native harnesses' run plan, the required inventory and the evidence records
for M06 (m06-plan §1 U7, §3, §4).

This is tests/native/m05/m05-evidence.py with the M06 constants, over the same generator
(tests/native/m02/m02-evidence.py, loaded by path through the M05 module; ADR-0009:
generalized, never copied). Every mode, rule and check is the M02 one, documented there: the
case index (tests/native/m06/case-index.json) resolved against the build host's sources into
tests/native/m06/required-inventory.json, the lowest-row rule, the coverage guard, schema
validation before anything is written, and no record for a run whose logs do not exist. So:
a row whose platform did not run (`unavailable` in runs.json) is `blocked` on that exact
platform; a required test missing from a platform that ran is `in_progress`; a failed test or
command is `in_progress` whatever else the row holds (a failure is never hidden behind a
blocked reason).

M06 additions:
  * The `iroh`-feature targets (m06-plan U7: every Cargo test target with required-features =
    ["iroh"], such as integration_transport_supervise_m06 and e2e_exit_m06_iroh). The
    harnesses build them in a second, feature-enabled build (tests/native/m02/lib.sh
    m02_feature_build; HM_FEATURE=iroh) and run them with the rest. When a platform cannot
    build them, the harness writes one host fact per target, `feature-blocked-<target>=<reason>`
    (cargo's real exit code and its first error line). This module reads those facts as that
    platform's `missing_capabilities` for the target: the row is `blocked` with that exact
    reason, never verified and never silently missing. A target that was neither run nor
    recorded as blocked reads as absent, so its row is `in_progress`.
  * runs.json platforms: macos (logs check.txt, observations.txt and features.txt), linux and
    windows. The container rows, the n0-public capture row and the owner-input rows of
    m06-plan §3 and §7 are the case index's `blocked_rows`, never rows of this generator.
  * The `harness = false` targets (integration_transport_supervise_m06, integration_route_m06)
    answer `--list` themselves with libtest's `<name>: test` lines, so the inventory lists them
    as every other target (m02-evidence.py cargo_lister) and never runs a case to learn a name.
  * heimdall-transport-iroh's own unit tests exist almost only under the feature. They are one
    target name on every platform, `heimdall_transport_iroh-unit`, built with the feature
    (FEATURE_UNIT): listed so here, run so by check.sh's iroh-check on macOS and by the Linux
    and Windows harnesses (HM_FEATURE_UNIT, -FeatureUnit), and blocked like any feature target
    where that build fails.
  * OBSERVATION_LINE also keeps the `m06 observation:` lines the exit journeys print (one per
    step of a §3 row, so platforms can be compared); the earlier milestones' lines are kept.
  * EXTRA_FACT_KEYS keeps the feature facts (`feature-targets`, `feature-cli`,
    `feature-blocked-*`).

  * ⟨M06 exit⟩ A test whose output says `m06 observation: <case> journey: blocked (<reason>)`
    (the journey could not start, and libtest reported it ok) is not counted as passed: its
    row is blocked on that platform with the logged reason (install_journey_blocked).
  * ⟨M06 exit⟩ The windows-controller platform's exit code comes only from the recorder's
    commands.txt (record-windows-controller.ps1, imported by import-windows-controller.py),
    checked against the journey's own trailer; a configured exit_codes map is refused there.
  * ⟨M06 exit⟩ --write refuses a run configuration whose identity fields (build_commit,
    artifact_digest, started_at, environment, each run platform's artifact_digest) are not
    filled (fill-run-facts.py fills them from real inputs).

HM_SKIP_TARGETS (a comma-separated list of Cargo test target names; m05-evidence.py) drops
those targets from the case index before anything is resolved, for a commit that does not
contain every target the case index names yet. Records are never generated with it: the
generator refuses --write while it is set.

Usage: as m02-evidence.py, e.g.
  python3 -I tests/native/m06/m06-evidence.py --config tests/native/m06/runs.json --write
"""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FEATURE_BLOCKED = "feature-blocked-"


def load_m05():
    spec = importlib.util.spec_from_file_location("m05_evidence", HERE.parent / "m05" / "m05-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m05 = load_m05()
ev = m05.ev
ev.MILESTONE = "M06"
ev.PLAN_REF = "m06-plan §3"
ev.GENERATOR = "m06-evidence.py"
ev.OBSERVATION_LINE = ev.re.compile(r"^\s*(?:m0[356] )?observation\b")
ev.EXTRA_FACT_KEYS = list(ev.EXTRA_FACT_KEYS) + ["feature-targets", "feature-cli", "feature-blocked-.*"]


def feature_blocked(facts):
    """{target: reason} from a platform's `feature-blocked-<target>=<reason>` host facts."""
    out = {}
    for key, value in facts.items():
        if key.startswith(FEATURE_BLOCKED) and key[len(FEATURE_BLOCKED):] and value.strip():
            out[key[len(FEATURE_BLOCKED):]] = value.strip()
    return out


def install_feature_blocked():
    """load_platforms(), with every platform's feature-blocked facts added to its
    missing_capabilities. A reason runs.json already gives for a target is kept, and the
    harness's fact is appended to it: neither replaces the other."""
    load = ev.load_platforms

    def load_platforms(cfg):
        plats = load(cfg)
        for pname, (p, logs) in plats.items():
            blocked = feature_blocked(p.get("_facts", {}))
            if not blocked:
                continue
            caps = dict(p.get("missing_capabilities") or {})
            for target, reason in sorted(blocked.items()):
                text = f"{pname}: {reason}"
                caps[target] = f"{caps[target]}; {text}" if caps.get(target) else text
                if logs.get(target):
                    # The harness recorded the target as not built, yet a log holds results for
                    # it: the artifacts disagree, and nothing is written from them.
                    raise ev.RunError(f"{pname}: {target} is recorded as feature-blocked but its tests are in the logs")
            p["missing_capabilities"] = caps
        return plats

    ev.load_platforms = load_platforms


install_feature_blocked()


# ⟨M06 exit⟩ A journey that cannot start prints `m06 observation: <case> journey: blocked
# (<reason>)` (tests/e2e/exit_m06/m06.rs `blocked`) and returns, so libtest reports it `ok`. Such
# a test is not evidence: its `ok` is dropped and the logged reason becomes the platform's
# missing capability for exactly that test, so its row is blocked with that reason (or
# in_progress when the row has another gap; a failure still outranks it). The logs are read
# here in full, not through the observation lines a row keeps (those are capped per test).
JOURNEY_BLOCKED = ev.re.compile(r"^m06 observation: (\S+) journey: blocked \((.*)\)$")


def scan_journey_blocked(path):
    """{(target, test): reason} for every `journey: blocked` line of a log, under the test
    named by the closest `---- <test> stdout ----` header (parse_observations' attribution)."""
    out = {}
    target, test = None, ""
    for raw in ev.Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = ev.re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw).rstrip("\r")
        m = ev.re.match(r"^\s*Running (.+?) \((?:.*[/\\])?([A-Za-z0-9_-]+?)-[0-9a-f]+(?:\.exe)?\)$", line)
        if m:
            src, binary = m.groups()
            target = binary if src.startswith("../") or src.startswith("tests") else binary + "-unit"
            test = ""
            continue
        if ev.re.match(r"^\s*Doc-tests ", line):
            target = None
            continue
        m = ev.re.match(r"^### ([A-Za-z0-9_-]+)$", line)
        if m:
            target, test = m.group(1), ""
            continue
        m = ev.re.match(r"^---- (\S+) stdout ----$", line)
        if m:
            test = m.group(1)
            continue
        if ev.re.match(r"^(successes|failures):$", line) or line.startswith("test result:"):
            test = ""
            continue
        m = JOURNEY_BLOCKED.match(line.strip())
        if m and target is not None:
            out.setdefault((target, test), f"{m.group(1)} journey: blocked ({m.group(2) or 'no reason logged'})")
    return out


def install_journey_blocked():
    load = ev.load_platforms

    def load_platforms(cfg):
        plats = load(cfg)
        base = ev.Path(cfg.get("artifacts_root", "."))
        for pname, (p, logs) in plats.items():
            if p.get("unavailable"):
                continue
            found = {}
            for rel in p.get("logs", []):
                for key, why in scan_journey_blocked(base / rel).items():
                    found.setdefault(key, why)
            if not found:
                continue
            caps = dict(p.get("missing_capabilities") or {})
            for (target, test), why in sorted(found.items()):
                if not test:
                    # A blocked line outside any test's output cannot be attributed: nothing
                    # is written from these logs.
                    raise ev.RunError(f"{pname}: a `journey: blocked` line in {target} names no test")
                if logs.get(target, {}).get(test) == "ok":
                    del logs[target][test]
                    if not logs[target]:
                        del logs[target]
                qual = f"{target}::{test}"
                text = f"{pname}: {qual} printed `{why}`"
                caps[qual] = f"{caps[qual]}; {text}" if caps.get(qual) else text
            p["missing_capabilities"] = caps
        return plats

    ev.load_platforms = load_platforms


install_journey_blocked()


# ⟨M06 exit⟩ The Windows controller journey's exit code is the one its recorder wrote
# (tests/native/m06/record-windows-controller.ps1: commands.txt, from the journey process's own
# exit status), checked against the journey's own `### windows-controller-journey exit=N`
# trailer. A configured `exit_codes` map is a value typed into the run configuration, not
# observed: it is refused for this platform, and so is a platform that ran with no commands log.
CONTROLLER = "windows-controller"
CONTROLLER_TARGET = "windows-controller-journey"
CONTROLLER_SCRIPT = "run-windows-controller.ps1"


def check_controller(cfg, pconf):
    base = ev.Path(cfg.get("artifacts_root", "."))
    if pconf.get("exit_codes"):
        raise ev.RunError(f"{CONTROLLER}: a configured exit_codes map is refused; the exit code is the recorder's "
                          "commands.txt (import it with tests/native/m06/import-windows-controller.py)")
    if not pconf.get("commands_logs"):
        raise ev.RunError(f"{CONTROLLER}: no commands log; the recorder's commands.txt holds the journey's real exit code "
                          "(tests/native/m06/import-windows-controller.py)")
    codes = {}
    for rel in pconf["commands_logs"]:
        for command, code in ev.parse_commands(base / rel).items():
            if CONTROLLER_SCRIPT in command:
                codes[command] = code
    if len(codes) != 1:
        raise ev.RunError(f"{CONTROLLER}: the commands log holds {len(codes)} journey exit lines, not exactly one")
    recorded = next(iter(codes.values()))
    trailers = []
    for rel in pconf.get("logs", []):
        trailers += [int(x) for x in ev.re.findall(rf"(?m)^### {CONTROLLER_TARGET} exit=(-?\d+)$",
                                                   (base / rel).read_text(encoding="utf-8", errors="replace"))]
    if len(trailers) != 1:
        raise ev.RunError(f"{CONTROLLER}: the logs hold {len(trailers)} `### {CONTROLLER_TARGET} exit=N` trailers, not exactly one")
    if recorded == 0 and trailers[0] != 0:
        raise ev.RunError(f"{CONTROLLER}: the commands log records exit 0 but the journey's own trailer says exit={trailers[0]}")


def install_controller_check():
    load = ev.load_platforms

    def load_platforms(cfg):
        plats = load(cfg)  # every configured file exists past this point
        p = cfg.get("platforms", {}).get(CONTROLLER)
        if p is not None and not p.get("unavailable"):
            check_controller(cfg, p)
        return plats

    ev.load_platforms = load_platforms


install_controller_check()


# ⟨M06 exit⟩ The record identity fields are filled from real inputs
# (tests/native/m06/fill-run-facts.py) and never written as null: --write refuses a run
# configuration whose build_commit is not 40 hex digits, whose artifact_digest is not a sha256,
# whose started_at is not RFC 3339 with an offset, whose environment is empty, or in which a
# platform that ran has no sha256 artifact_digest.
RFC3339 = ev.re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
SHA256 = ev.re.compile(r"[0-9a-f]{64}")


def identity_problems(cfg):
    out = []
    if not (isinstance(cfg.get("build_commit"), str) and ev.re.fullmatch(r"[0-9a-f]{40}", cfg["build_commit"])):
        out.append("build_commit is not a 40-hex commit")
    if not (isinstance(cfg.get("artifact_digest"), str) and SHA256.fullmatch(cfg["artifact_digest"])):
        out.append("artifact_digest is not a sha256")
    if not (isinstance(cfg.get("started_at"), str) and RFC3339.fullmatch(cfg["started_at"])):
        out.append("started_at is not RFC 3339 with an offset")
    if not (isinstance(cfg.get("environment"), dict) and cfg["environment"]):
        out.append("environment is empty")
    for pname, p in cfg.get("platforms", {}).items():
        if p.get("unavailable"):
            continue
        if not (isinstance(p.get("artifact_digest"), str) and SHA256.fullmatch(p["artifact_digest"])):
            out.append(f"platforms.{pname}.artifact_digest is not a sha256")
    return out


def install_identity_check():
    records = ev.records

    def checked(cfg, summary, plats):
        problems = identity_problems(cfg)
        if problems:
            raise ev.RunError("the run identity is not filled (tests/native/m06/fill-run-facts.py): " + "; ".join(problems))
        return records(cfg, summary, plats)

    ev.records = checked


install_identity_check()


def install_drop_targets():
    """m05's drop_targets(), then without the `platform_required` maps it emptied: a platform
    whose only required target was dropped requires nothing (check_index refuses an empty map)."""
    drop = m05.drop_targets

    def drop_targets(index, skip):
        index = drop(index, skip)
        for sec in list(index.get("groups", {}).values()) + list(index.get("exit_claims", {}).values()):
            req = sec.get("platform_required")
            if isinstance(req, dict):
                kept = {plat: tests for plat, tests in req.items() if tests}
                if kept:
                    sec["platform_required"] = kept
                else:
                    del sec["platform_required"]
        return index

    m05.drop_targets = drop_targets


install_drop_targets()


# ⟨M06 W5c⟩ The packages whose own unit tests the harnesses build and run with a feature
# (HM_FEATURE_UNIT in tests/native/m06/run-linux.sh and refresh-inventory.sh, -FeatureUnit in
# run-windows-local.ps1; check.sh's iroh-check on macOS): {package: feature}. Their
# `<crate>-unit` target is listed from that build, so the inventory holds the tests that exist
# only under the feature and no platform verifies the name from a default-feature build.
FEATURE_UNIT = {"heimdall-transport-iroh": "iroh"}


def install_feature_unit_listing():
    """cargo_targets() (m02-evidence.py), with FEATURE_UNIT's unit targets selected with
    their feature."""
    targets = ev.cargo_targets

    def cargo_targets(root):
        where = targets(root)
        for package, feature in FEATURE_UNIT.items():
            name = package.replace("-", "_") + "-unit"
            if name in where:
                pkg, sel = where[name]
                where[name] = (pkg, [*sel, "--features", feature])
        return where

    ev.cargo_targets = cargo_targets


install_feature_unit_listing()


def install_skip_listing(skip):
    """--list-targets without the skipped targets: a target the manifest registers but whose
    source the commit does not contain yet cannot be listed (cargo refuses the selection)."""
    targets = ev.cargo_targets

    def cargo_targets(root):
        return {name: sel for name, sel in targets(root).items() if name not in skip}

    ev.cargo_targets = cargo_targets


if __name__ == "__main__":
    skip = m05.skip_targets()
    if skip:
        if "--write" in sys.argv[1:]:
            print("HM_SKIP_TARGETS is set: records are never written from a reduced case index", file=sys.stderr)
            sys.exit(2)
        m05.install_skip(skip)
        install_skip_listing(skip)
    sys.exit(ev.main())
