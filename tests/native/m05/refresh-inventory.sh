#!/usr/bin/env bash
# M05-U10: regenerate tests/native/m05/required-inventory.json at the build commit, right
# before the native runs (tests/native/m02/refresh-inventory.sh, documented there: the build
# host's `--list` names, the Linux and Windows cross-builds scanned by platform-tests.py, then
# m05-evidence.py --generate-inventory with both scans). As M03's wrapper: the cross builds use
# the stable zig shims and the native-test profile, so they reuse run-linux.sh's build.
#
# HM_SKIP_TARGETS=<target>,<target>... (m05-evidence.py) resolves the case index without those
# Cargo test targets, for a commit that does not contain them yet. The inventory it writes then
# lacks them and the check without the variable fails until it is regenerated at the candidate;
# never use it at the commit the native runs build.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m05-evidence.py
exec bash "$here/../m02/refresh-inventory.sh" "$@"
