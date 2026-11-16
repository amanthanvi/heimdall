#!/usr/bin/env bash
# M03-U13 (m03-plan §4.2 "WSL disposable distribution", §4.3 `run-wsl-distro.sh`): the M02
# disposable-distribution harness (tests/native/m02/run-wsl-distro.sh, documented there:
# pinned image, `wsl --import hm-m03-<random>`, terminate and unregister of that
# distribution only, the registered-set comparison, the EXIT trap, redaction, canary and
# leak scans, local mode) run with
#   * the distribution name prefix hm-m03;
#   * the managed-credential scenario (scenario-managed.sh beside this file) as the
#     disposable non-root user;
#   * root phases around it (tests/native/m02/target-root.sh): `m03-sshd-start` before
#     (the root sshds on 127.0.0.1 in both enrollment forms, StrictModes yes) and
#     `m03-sshd-stop` after, run even when the scenario fails.
#
# Usage: tests/native/m03/run-wsl-distro.sh <artifact-dir>
#   Every variable of tests/native/m02/run-wsl-distro.sh (HM_LOCAL, HM_PREBUILT_HEIMDALL,
#   HM_PREBUILT_SHA256, HM_WSL_ROOTFS or HM_WSL_DOWNLOAD, HM_WSL_ALLOW_APT, HM_BUILD_ONLY, ...);
#   HM_TASK defaults to M03-U13-wsl.
# Output and exit codes: as tests/native/m02/run-wsl-distro.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_RUN_PREFIX=hm-m03 HM_SCENARIO="$here/scenario-managed.sh" \
    HM_ROOT_PHASES=m03-sshd-start:m03-sshd-stop HM_TASK="${HM_TASK:-M03-U13-wsl}"
exec bash "$here/../m02/run-wsl-distro.sh" "$@"
