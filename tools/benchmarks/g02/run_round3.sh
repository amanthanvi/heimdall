#!/bin/bash
# Round 3: re-measure the go and rust darwin-arm64 artifacts only (ts is frozen; its round-2 rows are kept).
# Same scripts and arguments as run_round2.sh; HM_G02_CANDS restricts the candidate set.
cd "$(dirname "$0")/../../.." || exit 99
export HM_G02_CANDS=go,rust
PY=tests/g02/.venv/bin/python
A=tests/evidence/artifacts/g02-measure/round3
mkdir -p $A
echo "START $(date -u +%Y-%m-%dT%H:%M:%SZ)"
$PY tools/benchmarks/g02/measure.py --idle-s 30 --idle-reps 2 --out-dir $A > $A/measure-run.log 2>&1; echo "measure rc=$? $(date -u +%Y-%m-%dT%H:%M:%SZ)"
$PY tools/benchmarks/g02/idle_long.py --idle-s 300 --reps 3 --out-dir $A > $A/idle-long-run.log 2>&1; echo "idle_long rc=$? $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "END"
