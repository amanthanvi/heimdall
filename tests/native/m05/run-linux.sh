#!/usr/bin/env bash
# M05-U10 (m05-plan §3): the Linux x86-64 row. The M02 harness (tests/native/m02/run-linux.sh,
# documented there) generalized for M05 as M03's wrapper is: the same zig cross-build, scratch
# directory, single tar stream, per-binary timeout and nice, redaction, leak, canary and
# owner-digest checks, with
#   * the M05 case index and generator (tests/native/m05/case-index.json, m05-evidence.py) for
#     the run plan;
#   * the scratch directory ~/hm-m05-<random>;
#   * the stable zig shims (target/hm-zig-shims) and the lean `native-test` profile, so the
#     cross build is incremental and every test binary of the workspace runs in one batch.
# No Docker: the Linux rows use LoopbackSshd. M05 needs no M03-style host facts.
#
# Usage: tests/native/m05/run-linux.sh <artifact-dir> <ssh-host-alias>
#   HM_BUILD_ONLY, HM_ONLY, HM_TIMEOUT_S: as tests/native/m02/run-linux.sh.
# Output and exit codes: as tests/native/m02/run-linux.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m05-evidence.py HM_RUN_PREFIX=hm-m05
exec bash "$here/../m02/run-linux.sh" "$@"
