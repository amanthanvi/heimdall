#!/bin/sh
# runhost.sh LABEL BIN ONLY  -> record + artifacts under the review dir (host, darwin)
set -u
R=$HOME/GitRepos/heimdall
O=$R/tests/evidence/artifacts/review-g02-harness-r3/darwin
mkdir -p "$O"
label=$1; bin=$2; only=$3
cd "$R"
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
env -u SSH_AUTH_SOCK -u REF_MUTATE PYTHONDONTWRITEBYTECODE=1 python3 tests/g02/conformance.py --bin "$bin" --candidate go \
  --out "$O/$label.json" --artifacts-dir "$O/$label-artifacts" --only "$only" --selftest \
  --case-id "REVIEW-r3-$label-darwin" > "$O/$label.stdout.txt" 2> "$O/$label.stderr.txt"
rc=$?
echo "$label start=$start end=$(date -u +%Y-%m-%dT%H:%M:%SZ) exit=$rc" | tee -a "$O/runs.log"
