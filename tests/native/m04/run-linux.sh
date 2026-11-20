#!/usr/bin/env bash
# M04-U7 (m04-plan §3): the Linux x86-64 row (the devbox). The M02 harness
# (tests/native/m02/run-linux.sh, documented there) generalized for M04 rather than copied, as
# tests/native/m03/run-linux.sh did for M03: the same zig cross-build, scratch directory, single
# tar stream, per-binary timeout and nice, redaction, leak, canary and owner-digest checks, with
#   * the M04 case index and generator (tests/native/m04/case-index.json, m04-evidence.py) for the
#     run plan;
#   * the scratch directory ~/hm-m04-<random>;
#   * the stable zig shims (target/hm-zig-shims) and the lean `native-test` profile (ADR-0009
#     §2.7), so the cross build is incremental. HM_ONLY batches the targets when space is tight.
# No extra remote facts (HM_EXTRA_REMOTE): the M03 file's ptrace scope, memlock limit, time sync
# and keyring facts are M03 rows' inputs; M04's route rows read the M02 facts (ssh -V, sshd -V,
# git --version).
#
# Usage: tests/native/m04/run-linux.sh <artifact-dir> <ssh-host-alias>
#   HM_BUILD_ONLY, HM_ONLY, HM_TIMEOUT_S: as tests/native/m02/run-linux.sh.
# Output and exit codes: as tests/native/m02/run-linux.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m04-evidence.py HM_RUN_PREFIX=hm-m04
exec bash "$here/../m02/run-linux.sh" "$@"
