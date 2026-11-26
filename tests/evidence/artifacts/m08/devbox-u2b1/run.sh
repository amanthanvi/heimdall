#!/usr/bin/env bash
# M08 U2b-1 devbox steps at a9b038a7. Everything in this scratch dir; HOME and TMPDIR are scratch.
set -u
D=$(cd "$(dirname "$0")" && pwd -P)
mkdir -p "$D/home" "$D/tmp"
export HOME="$D/home" TMPDIR="$D/tmp" HEIMDALL_E2E_BIN="$D/heimdall"
unset SSH_AUTH_SOCK
cd "$D"
step() { name=$1; shift; echo "== $name"; nice -n 10 "$@" >"$D/$name.log" 2>&1; rc=$?; echo "== $name: exit $rc"; grep -E "^test result|panicked|FAILED" "$D/$name.log" | head -6; }
step stategen-unit "$D/stategen_unit"
step stategen-faults "$D/stategen_faults"
# The path guard scans the repository's tests/ sources, which are not on this host: run on the Mac only.
step store-generations "$D/store_generations" --skip no_test_builds_the_state_database_path_by_hand
step e2e-store-generations "$D/e2e_store_generations"
