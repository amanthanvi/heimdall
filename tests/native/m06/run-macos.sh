#!/usr/bin/env bash
# M06-U7 (m06-plan §1 U7, §3): the macOS arm64 row on the build host ("the controller"). The
# M02 harness (tests/native/m02/run-macos.sh: check.sh with every workspace test, the
# observation pass, facts, owner digests, redaction, leak and canary scans; documented there)
# generalized for M06 as M05's wrapper is, plus HM_FEATURE=iroh: the test targets with
# required-features = ["iroh"], which check.sh's workspace test does not build, are built and
# run per package with --show-output (features.txt). A package whose iroh build fails is
# recorded as blocked with cargo's exit code and first error (host.txt
# `feature-blocked-<target>`), never as passed or skipped. No Docker phase: the container rows
# of §3 (the limited client, the Iroh container networks, n0-public) are not this harness's.
# The case index's observation targets run once more with --show-output.
#
# Usage: tests/native/m06/run-macos.sh <artifact-root>
#   writes <artifact-root>/macos/{check,observations,features,host,commands,canary-scan}.txt.
#   HM_BUILD_ONLY: as tests/native/m02/run-macos.sh (the iroh targets are built too).
# Exit: the M02 harness's, and 6 when everything that ran passed but an iroh-feature target did
# not build.
set -euo pipefail
root=${1:?usage: run-macos.sh <artifact-root>}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$root/macos"
out=$(cd "$root/macos" && pwd)
unset CARGO_TARGET_DIR
TMPDIR=/tmp HM_HARNESS_DIR="$here" HM_FEATURE=iroh exec bash "$here/../m02/run-macos.sh" "$out"
