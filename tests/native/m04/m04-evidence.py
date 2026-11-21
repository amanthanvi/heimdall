#!/usr/bin/env python3
"""M04-U7: the native harnesses' run plan, the required inventory and the evidence
records for M04 (m04-plan §3, §4).

This is tests/native/m02/m02-evidence.py, generalized rather than copied (ADR-0009; as
tests/native/m03/m03-evidence.py did for M03): the M02 module is loaded by path, its
milestone constants are set for M04, and its command line runs unchanged. Every mode, rule
and check is the M02 one, documented there: the case index (tests/native/m04/case-index.json)
resolved against the build host's sources into tests/native/m04/required-inventory.json, the
lowest-row rule, the coverage guard (excluded_without_rationale, platform_required_not_passed,
platform_only_stale, ran_not_in_inventory), schema validation before anything is written, and
no record for a run whose logs do not exist.

M04 additions are data, not code:
  * runs.json platforms for the Windows-hosted WSL runs (tests/native/m04/run-mode-b-windows.ps1:
    its mode-b, containers, systemd-login and lock scenarios) are scenario platforms
    (windows-modeb, wsl-containers, wsl-login, windows-lock) whose targets are the runner's own
    `### <plan name>` sections and whose steps are the cargo test names printed under them (the
    runner's tests.txt names each section after its plan command, and cargo's `Running` line
    follows the test output, so the sections are not cargo targets);
  * the case index's `blocked_rows` carry the owner inputs B1–B13 (m03-plan §7; M04 adds none);
  * OBSERVATION_LINE also keeps the `m04 observation:` lines the M04 tests print;
  * EXTRA_FACT_KEYS keeps the M04 host facts the Windows and WSL bundles carry (the run root's
    ACL, the WSL version and networking, systemd, the container engines and images, the lock
    procedure's observations, the prebuilt binaries' digests).

Usage: as m02-evidence.py, e.g.
  python3 -I tests/native/m04/m04-evidence.py --config tests/native/m04/runs.json --write
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
ev.MILESTONE = "M04"
ev.PLAN_REF = "m04-plan §3"
ev.GENERATOR = "m04-evidence.py"
# The M04 tests print `m04 observation: …` lines (the container run's engine, uid map and uid rows;
# the Mode B and login-entry facts); M03's world prints `m03 observation: …` and M02's bare ones.
ev.OBSERVATION_LINE = ev.re.compile(r"^\s*(?:m0[34] )?observation\b")
ev.EXTRA_FACT_KEYS = [
    "run-root-sddl", "wsl-version", "wslconfig-networking", "systemd", "podman-version", "docker-version",
    "subid", "docker-group", "image-.*", "lock-.*", "idle-.*", "heimdalltest-parent", "prebuilt-.*",
    "seconds-before-tests", "w32tm-.*", "build-profile", "store-kind",
]

if __name__ == "__main__":
    sys.exit(ev.main())
