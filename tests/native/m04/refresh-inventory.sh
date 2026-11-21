#!/usr/bin/env bash
# M04-U7: regenerate tests/native/m04/required-inventory.json at the build commit, right before
# the native runs (tests/native/m02/refresh-inventory.sh, documented there: the build host's
# `--list` names, the Linux and Windows cross-builds scanned by platform-tests.py, then
# m04-evidence.py --generate-inventory with both scans). The cross builds use the stable zig
# shims and the native-test profile, so they reuse the M02/M03 harnesses' builds.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m04-evidence.py
exec bash "$here/../m02/refresh-inventory.sh" "$@"
