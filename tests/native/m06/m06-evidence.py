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
