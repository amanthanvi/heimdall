#!/usr/bin/env bash
# M07-U9: regenerate tests/native/m07/required-inventory.json at the build commit, right
# before the native runs (tests/native/m02/refresh-inventory.sh, documented there: the build
# host's `--list` names, the Linux and Windows cross-builds scanned by platform-tests.py, then
# m07-evidence.py --generate-inventory with both scans). As M05's wrapper: no M07 target
# requires a feature, so neither HM_FEATURE nor HM_FEATURE_UNIT is set.
#
# HM_SKIP_TARGETS=<target>,<target>... (m07-evidence.py, as m05-evidence.py) resolves the case
# index without those Cargo test targets, for a commit that does not contain them yet. The
# inventory it writes then lacks them and the check without the variable fails until it is
# regenerated at the candidate; never use it at the commit the native runs build.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m07-evidence.py
unset HM_FEATURE HM_FEATURE_UNIT
exec bash "$here/../m02/refresh-inventory.sh" "$@"
