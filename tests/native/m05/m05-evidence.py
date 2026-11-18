#!/usr/bin/env python3
"""M05-U10: the native harnesses' run plan, the required inventory and the evidence
records for M05 (m05-plan §3, §4).

This is tests/native/m03/m03-evidence.py with the M05 constants, over the same generator
(tests/native/m02/m02-evidence.py, loaded by path; ADR-0009: generalized, never copied). Every
mode, rule and check is the M02 one, documented there: the case index
(tests/native/m05/case-index.json) resolved against the build host's sources into
tests/native/m05/required-inventory.json, the lowest-row rule, the coverage guard
(excluded_without_rationale, platform_required_not_passed, platform_only_stale,
ran_not_in_inventory), schema validation before anything is written, and no record for a run
whose logs do not exist.

M05 additions are data, not code:
  * runs.json platforms: macos, linux, windows and wsl-distro. The wsl-distro platform runs one
    scenario target, wsl_hook_m05 (tests/native/m05/wsl-hook-journeys.sh: the bash and zsh hook
    journeys inside a disposable distribution; ruling I-19), whose steps are the rows' checks;
  * the case index's `blocked_rows` carry the owner inputs B2, B7, B9 and B12 (m05-plan §7), and
    its `deferred_with_decision` rows the A16 and A28 rows that M04's exit closes (plan Q9);
  * OBSERVATION_LINE also keeps the `m05 observation:` lines the M05 tests print (the I-13
    first-ssh outcome, the hook's warm-up timing);
  * EXTRA_FACT_KEYS keeps the M05 host facts (shell versions, zsh presence, the build profile and
    store kind).

HM_SKIP_TARGETS (a comma-separated list of Cargo test target names) drops those targets from
the case index before anything is resolved. It exists for one case: building and checking an
inventory at a commit that does not contain every target the case index names yet (the three W4
targets written beside this harness). Records are never generated with it: the generator
refuses --write while it is set.

Usage: as m02-evidence.py, e.g.
  python3 -I tests/native/m05/m05-evidence.py --config tests/native/m05/runs.json --write
"""

import importlib.util
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_m02():
    spec = importlib.util.spec_from_file_location("m02_evidence", HERE.parent / "m02" / "m02-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = load_m02()
ev.MILESTONE = "M05"
ev.PLAN_REF = "m05-plan §3"
ev.GENERATOR = "m05-evidence.py"
# The M05 tests' `m05 observation: …` lines (the I-13 first-ssh outcome per platform, the hook's
# warm-up timing) are row observations too; M03's are kept as well, since A29 re-runs M01 rows.
ev.OBSERVATION_LINE = ev.re.compile(r"^\s*(?:m0[35] )?observation\b")
ev.EXTRA_FACT_KEYS = [
    "shell-.*", "zsh-.*", "bash-.*", "build-profile", "store-kind", "fixture-forms",
    "registered-distributions-.*", "pipes-.*", "leftover-.*",
]


def skip_targets():
    return {t for t in os.environ.get("HM_SKIP_TARGETS", "").split(",") if t}


def drop_targets(index, skip):
    """The case index without the named targets, wherever it lists them."""

    def keep(tests):
        return {t: v for t, v in tests.items() if t not in skip}

    for sec in list(index.get("groups", {}).values()) + list(index.get("exit_claims", {}).values()):
        if "tests" in sec:
            sec["tests"] = keep(sec["tests"])
        for plat, tests in (sec.get("platform_required") or {}).items():
            sec["platform_required"][plat] = keep(tests)
    index["observation_targets"] = [t for t in index.get("observation_targets", []) if t not in skip]
    return index


def install_skip(skip):
    load = ev.load_json

    def load_json(path):
        data = load(path)
        if isinstance(data, dict) and "groups" in data and "platforms" in data and "build_host" in data:
            return drop_targets(data, skip)
        return data

    ev.load_json = load_json


if __name__ == "__main__":
    skip = skip_targets()
    if skip:
        if "--write" in sys.argv[1:]:
            print("HM_SKIP_TARGETS is set: records are never written from a reduced case index", file=sys.stderr)
            sys.exit(2)
        install_skip(skip)
    sys.exit(ev.main())
