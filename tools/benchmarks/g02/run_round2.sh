#!/bin/bash
cd "$(dirname "$0")/../../.." || exit 99
PY=tests/g02/.venv/bin/python
A=tests/evidence/artifacts/g02-measure
echo "START $(date -u +%Y-%m-%dT%H:%M:%SZ)"
$PY tools/benchmarks/g02/measure.py --idle-s 30 --idle-reps 2 > $A/measure-run.log 2>&1; echo "measure rc=$? $(date -u +%Y-%m-%dT%H:%M:%SZ)"
$PY tools/benchmarks/g02/clean_env.py windows > $A/clean-windows-run.log 2>&1; echo "clean windows rc=$?"
HM_G02_CANDS=go,rust $PY tools/benchmarks/g02/clean_env.py darwin > $A/clean-darwin-run.log 2>&1; echo "clean darwin rc=$?"
HM_G02_CANDS=go,rust $PY tools/benchmarks/g02/clean_env.py linux > $A/clean-linux-run.log 2>&1; echo "clean linux rc=$?"
$PY tools/benchmarks/g02/idle_long.py --idle-s 300 --reps 3 > $A/idle-long-run.log 2>&1; echo "idle_long rc=$? $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "END"
