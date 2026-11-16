#!/usr/bin/env bash
# M03-U13 (m03-plan §4.1, §4.3): the Linux x86-64 row. The M02 harness
# (tests/native/m02/run-linux.sh, documented there) generalized for M03 rather than copied:
# the same zig cross-build, scratch directory, single tar stream, per-binary timeout and
# nice, redaction, leak, canary and owner-digest checks, with
#   * the M03 case index and generator (tests/native/m03/case-index.json, m03-evidence.py)
#     for the run plan;
#   * the scratch directory ~/hm-m03-<random>;
#   * the M03 host facts (remote-facts.sh: ptrace scope, memlock limit, NTP sync,
#     gnome-keyring presence; read-only);
#   * ⟨ADR-0009 §2.7⟩ the stable zig shims (target/hm-zig-shims) and the lean
#     `native-test` profile, so the cross build is incremental and every test binary of
#     the workspace runs in one batch on a host with a few GB free.
# No Docker (B8): the Linux rows use LoopbackSshd per form.
#
# Usage: tests/native/m03/run-linux.sh <artifact-dir> <ssh-host-alias>
#   HM_BUILD_ONLY, HM_ONLY, HM_TIMEOUT_S: as tests/native/m02/run-linux.sh.
# Output and exit codes: as tests/native/m02/run-linux.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m03-evidence.py HM_RUN_PREFIX=hm-m03 \
    HM_EXTRA_REMOTE="$here/remote-facts.sh"
exec bash "$here/../m02/run-linux.sh" "$@"
