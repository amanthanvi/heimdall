#!/usr/bin/env bash
# M08 U2b-2 devbox steps at 065f3a45. Everything in this scratch dir; HOME and TMPDIR are scratch.
set -u
D=$(cd "$(dirname "$0")" && pwd -P)
mkdir -p "$D/home" "$D/tmp"
export HOME="$D/home" TMPDIR="$D/tmp" HEIMDALL_E2E_BIN="$D/heimdall"
unset SSH_AUTH_SOCK
cd "$D"
echo "python3: $(python3 --version 2>&1)"
step() { name=$1; shift; echo "== $name"; nice -n 10 "$@" >"$D/$name.log" 2>&1; rc=$?; echo "== $name: exit $rc"; grep -E "^test |^test result|panicked|FAILED" "$D/$name.log" | sed "s#$D#<scratch>#g"; }
step request-epoch "$D/request_epoch"
step e2e-request-epoch "$D/e2e_request_epoch"
step store-fence "$D/store_lib" fence::
step stategen-unit "$D/stategen_unit"
step stategen-faults "$D/stategen_faults"
