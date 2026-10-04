#!/bin/sh
# runlinux.sh LABEL (ref|ARTDIR) ONLY  -> record + artifacts under the review dir (linux-arm64 container)
set -u
R=$HOME/GitRepos/heimdall
O=$R/tests/evidence/artifacts/review-g02-harness-r3/linux
mkdir -p "$O/$1-artifacts"
label=$1; subj=$2; only=$3
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ "$subj" = ref ]; then
  env -u REF_MUTATE -u SSH_AUTH_SOCK sh "$R/tests/g02/linux/run.sh" --reference --candidate go --out "$O/$label.json" \
    --artifacts-out "$O/$label-artifacts" --only "$only" --case-id "REVIEW-r3-$label-linux" > "$O/$label.stdout.txt" 2> "$O/$label.stderr.txt"
else
  env -u SSH_AUTH_SOCK sh "$R/tests/g02/linux/run.sh" --artifact-dir "$subj" --candidate go --out "$O/$label.json" \
    --artifacts-out "$O/$label-artifacts" --only "$only" --case-id "REVIEW-r3-$label-linux" > "$O/$label.stdout.txt" 2> "$O/$label.stderr.txt"
fi
rc=$?
echo "$label start=$start end=$(date -u +%Y-%m-%dT%H:%M:%SZ) exit=$rc" | tee -a "$O/runs.log"
