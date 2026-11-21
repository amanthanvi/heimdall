#!/usr/bin/env bash
# M04-U7 (m04-plan §3): the macOS arm64 row on the build host. The M02 harness
# (tests/native/m02/run-macos.sh: check.sh with every workspace test, the observation pass,
# facts, owner digests, redaction, leak and canary scans; documented there) generalized for M04
# rather than copied, as tests/native/m03/run-macos.sh did for M03 (without that file's Docker
# phase: M04's container engine rows run inside a disposable WSL distribution, never here):
#   tests/native/m02/run-macos.sh <out>/macos with the M04 case index's observation targets
#   (HM_HARNESS_DIR) and TMPDIR=/tmp (the tests' Unix socket paths stay under SUN_LEN).
#
# Usage: tests/native/m04/run-macos.sh <artifact-root>
#   writes <artifact-root>/macos/{check,observations,host,commands,canary-scan}.txt (the M02 harness).
#   HM_BUILD_ONLY, HM_DOCKER_FALLBACK: as tests/native/m02/run-macos.sh (the Docker fallback stays
#   off by default; no M04 row needs Docker on the build host).
# Exit: the M02 harness's exit code.
set -euo pipefail
root=${1:?usage: run-macos.sh <artifact-root>}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$root/macos"
out=$(cd "$root/macos" && pwd)
unset CARGO_TARGET_DIR
TMPDIR=/tmp HM_HARNESS_DIR="$here" exec bash "$here/../m02/run-macos.sh" "$out"
