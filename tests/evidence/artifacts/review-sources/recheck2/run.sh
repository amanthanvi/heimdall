#!/bin/bash
# recheck2 runner: GET-only fetcher runs from the repo root; outputs to $D; exit codes appended.
set -u
R=$(cd "$(dirname "$0")/../../../../.." && pwd -P)  # repository root (was an absolute home path; redacted at commit)
D="$1"
T="python3 -I docs/sources/tools/fetch_pins.py"
SPEC_SNAPS=S01,S02,S03,S04,S05,S06,S07,S08,S09,S10,S11,S12,S13,S14,S15,S20,S21,S22,S23,S24,S25,S26,S28,S30,S31,S32,S33
AUX_SNAPS=A01,A02,A03,A04
cd "$R" || exit 99
step() { # name, command...
  local name="$1"; shift
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  env -u SSH_AUTH_SOCK "$@" > "$D/$name.out" 2>&1
  local rc=$?
  local end; end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf 'window=%s..%s\nexit=%d\n' "$start" "$end" "$rc" >> "$D/$name.out"
  printf '%-34s exit=%d  %s..%s\n' "$name" "$rc" "$start" "$end" | tee -a "$D/steps.log"
}
step 01_selftest            $T selftest
step 02_fetch_run1          $T fetch --out "$D/run1.json" --snapshots-dir "$D/snap1" --snapshot-ids $SPEC_SNAPS
step 03_compare_base_run1   $T compare docs/sources/fetch-baseline.json "$D/run1.json" --all
step 04_fetch_run2          $T fetch --out "$D/run2.json" --snapshots-dir "$D/snap2" --snapshot-ids $SPEC_SNAPS
step 05_compare_run1_run2   $T compare "$D/run1.json" "$D/run2.json" --all
step 06_compare_base_repeat $T compare docs/sources/fetch-baseline.json docs/sources/fetch-repeat.json
step 07_fetch_aux           $T fetch --set aux --out "$D/aux1.json" --snapshots-dir "$D/snapaux" --snapshot-ids $AUX_SNAPS
step 08_compare_auxbase_aux $T compare docs/sources/fetch-baseline-aux.json "$D/aux1.json" --all
step 09_upstream_listed     $T upstream --only S16,S17,S18,S34 --out "$D/upstream.json"
step 10_tags                $T tags --out "$D/tags.json"
step 11_excerpts_all_git    $T excerpts --set all --fetch-git
step 12_excerpts_all_nogit  $T excerpts --set all
# verify every committed snapshot (offline)
for id in ${SPEC_SNAPS//,/ }; do
  step "13_verify_$id" $T verify --fetch-result docs/sources/fetch-baseline.json --id "$id" --snapshot "docs/sources/snapshots/$id.txt.gz"
done
for id in ${AUX_SNAPS//,/ }; do
  step "13_verify_$id" $T verify --fetch-result docs/sources/fetch-baseline-aux.json --id "$id" --snapshot "docs/sources/snapshots/$id.txt.gz"
done
# error-path exit codes (offline)
step 14_usage_error         $T compare
step 15_input_error         $T compare docs/sources/fetch-baseline.json "$D/does-not-exist.json"
step 16_compare_badpins     $T compare docs/sources/fetch-baseline.json docs/sources/fetch-repeat.json --pins "$D/nope.json"
step 17_verify_wrong_id     $T verify --fetch-result docs/sources/fetch-baseline.json --id S25 --snapshot docs/sources/snapshots/S26.txt.gz
