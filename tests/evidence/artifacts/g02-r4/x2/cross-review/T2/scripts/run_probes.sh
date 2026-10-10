#!/bin/sh
# usage: run_probes.sh REPO SCRATCH GRP [extra probe.py args...]
# Runs probe.py on the eight builds in SCRATCH/bin (base-go, base-rust, six T2 cells).
set -u
REPO=$1; SCRATCH=$2; GRP=$3; shift 3
X="$REPO/tests/evidence/artifacts/g02-r4/x2"
unset SSH_AUTH_SOCK
BINARGS=""
for c in base-go base-rust T2-go-opus1 T2-go-opus2 T2-go-sonnet1 T2-rust-opus1 T2-rust-opus2 T2-rust-sonnet1; do
  BINARGS="$BINARGS --bin $c=$SCRATCH/bin/$c/heimdall-proto"
done
# shellcheck disable=SC2086
exec python3 -I -B "$X/cross-review/T2/scripts/probe.py" --work "$SCRATCH/probe/work-$GRP" \
  --out "$SCRATCH/probe/out" --ref "$X/hidden-pack/t2/lint_ref.py" \
  --fixtures "$REPO/tests/fixtures/g02/profiles" $BINARGS --groups "$GRP" "$@"
