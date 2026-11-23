#!/usr/bin/env bash
# M06-U7: regenerate tests/native/m06/required-inventory.json at the build commit, right
# before the native runs (tests/native/m02/refresh-inventory.sh, documented there: the build
# host's `--list` names, the Linux and Windows cross-builds scanned by platform-tests.py, then
# m06-evidence.py --generate-inventory with both scans). As M05's wrapper, plus HM_FEATURE=iroh:
# the Linux cross-build also builds and scans the iroh-feature targets. The Windows scan is a
# x86_64-pc-windows-gnu cross-build without the feature (documented in the M02 script).
#
# HM_SKIP_TARGETS=<target>,<target>... (m06-evidence.py, as m05-evidence.py) resolves the case
# index without those Cargo test targets, for a commit that does not contain them yet. The
# inventory it writes then lacks them and the check without the variable fails until it is
# regenerated at the candidate; never use it at the commit the native runs build.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export HM_HARNESS_DIR="$here" HM_EVIDENCE=m06-evidence.py HM_FEATURE=iroh HM_FEATURE_UNIT=heimdall-transport-iroh
exec bash "$here/../m02/refresh-inventory.sh" "$@"
