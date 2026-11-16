#!/usr/bin/env python3
"""M03-U13: the native harnesses' run plan, the required inventory and the evidence
records for M03 (m03-plan §3, §4.5).

This is tests/native/m02/m02-evidence.py, generalized rather than copied (ADR-0009;
the brief of M03 wave 6): the M02 module is loaded by path, its milestone constants are
set for M03, and its command line runs unchanged. Every mode, rule and check is the M02
one, documented there: the case index (tests/native/m03/case-index.json) resolved against
the build host's sources into tests/native/m03/required-inventory.json, the lowest-row
rule, the coverage guard (excluded_without_rationale, platform_required_not_passed,
platform_only_stale, ran_not_in_inventory), schema validation before anything is written,
and no record for a run whose logs do not exist.

M03 additions are data, not code:
  * runs.json platforms for the lock procedure (tests/native/m03/lock-macos.sh,
    lock-windows.ps1) are scenario platforms whose steps are the A03 checks; an unverified
    lock is configured as `missing_capabilities` (blocked, never failed or verified);
  * the case index's `blocked_rows` carry the owner inputs B1–B13 (m03-plan §7);
  * OBSERVATION_LINE also keeps the `m03 observation:` lines the M03 tests print (W6-R02);
  * EXTRA_FACT_KEYS keeps the M03 host facts (ptrace scope, memlock limit, time sync,
    the lock procedure's idle and lock-state observations, the build profile and store kind).

Usage: as m02-evidence.py, e.g.
  python3 -I tests/native/m03/m03-evidence.py --config tests/native/m03/runs.json --write
"""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_m02():
    spec = importlib.util.spec_from_file_location("m02_evidence", HERE.parent / "m02" / "m02-evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = load_m02()
ev.MILESTONE = "M03"
ev.PLAN_REF = "m03-plan §4"
ev.GENERATOR = "m03-evidence.py"
# W6-R02: the M03 tests' `m03 observation: …` lines (A10 reachability facts, A33's
# unobservable surfaces, the issuer lifecycle, the lock driver) are row observations too.
ev.OBSERVATION_LINE = ev.re.compile(r"^\s*(?:m03 )?observation\b")
ev.EXTRA_FACT_KEYS = [
    "ptrace-scope", "memlock-limit", "ntp-synchronized", "w32tm-.*", "gnome-keyring",
    "lock-.*", "idle-.*", "build-profile", "store-kind", "docker-.*", "keychain-.*",
    "registered-distributions-.*", "pipes-.*", "fixture-forms",
]

if __name__ == "__main__":
    sys.exit(ev.main())
