#!/usr/bin/env bash
# M06-U7 (m06-plan §1 U7, §3): the Linux x86-64 row (the devbox, "the runner"). The M02 harness
# (tests/native/m02/run-linux.sh, documented there) generalized for M06 as M05's wrapper is:
# the same zig cross-build, scratch directory, single tar stream, per-binary timeout and nice,
# redaction, leak, canary and owner-digest checks, with
#   * the M06 case index and generator (tests/native/m06/case-index.json, m06-evidence.py) for
#     the run plan;
#   * the scratch directory ~/hm-m06-<random>;
#   * HM_FEATURE=iroh: the test targets with required-features = ["iroh"] (for example
#     integration_transport_supervise_m06 and e2e_exit_m06_iroh), which the workspace build
#     never builds, are cross-built too and run natively with the rest, against that build's
#     own heimdall. A target that does not build is recorded as blocked with cargo's exit code
#     and first error (host.txt `feature-blocked-<target>`), never as passed or skipped.
# No Docker: the Linux rows use LoopbackSshd. The container rows of §3 are not this harness's.
#
# Usage: tests/native/m06/run-linux.sh <artifact-dir> <ssh-host-alias>
#   HM_BUILD_ONLY, HM_ONLY, HM_TIMEOUT_S: as tests/native/m02/run-linux.sh.
# Output: as tests/native/m02/run-linux.sh. Exit codes: its own, and 6 when everything that ran
# passed but an iroh-feature target did not build.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m06-evidence.py HM_RUN_PREFIX=hm-m06 HM_FEATURE=iroh HM_FEATURE_UNIT=heimdall-transport-iroh
exec bash "$here/../m02/run-linux.sh" "$@"
