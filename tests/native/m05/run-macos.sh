#!/usr/bin/env bash
# M05-U10 (m05-plan §3): the macOS arm64 row on the build host. The M02 harness
# (tests/native/m02/run-macos.sh: check.sh with every workspace test, the observation pass,
# facts, owner digests, redaction, leak and canary scans; documented there) generalized for
# M05 as M03's wrapper is, without M03's Docker phase: no M05 row needs a container (the
# container rows of A16 and A28 are M04's exit, plan Q9). The case index's observation targets
# (e2e_hook_m05, e2e_exit_m05) run once more with --show-output.
#
# Usage: tests/native/m05/run-macos.sh <artifact-root>
#   writes <artifact-root>/macos/{check,observations,host,commands,canary-scan}.txt.
# Exit: the M02 harness's.
set -euo pipefail
root=${1:?usage: run-macos.sh <artifact-root>}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$root/macos"
out=$(cd "$root/macos" && pwd)
unset CARGO_TARGET_DIR
TMPDIR=/tmp HM_HARNESS_DIR="$here" exec bash "$here/../m02/run-macos.sh" "$out"
