#!/bin/bash
# M00-T02-fix3: verification suite. From the repository root:
#   [ALT_PYTHON=python3.13] bash tests/evidence/artifacts/review-sources/fix3/run_fix3.sh <scratch_dir_outside_repo> <out_dir> offline|live
# Each command's stdout+stderr goes to <out_dir>/<name>.out followed by a line "exit=<code>".
# "offline" makes no request except the one marked [GET]; "live" adds GET requests to the sources pinned in
# pins.json (fetch, upstream, tags, excerpts --fetch-git, the normalizer probe).
set -u
SCR=$1
OUT=$2
MODE=${3:-offline}
F=tests/evidence/artifacts/review-sources/fix3
T="python3 -I -B docs/sources/tools/fetch_pins.py"
mkdir -p "$SCR/cases" "$OUT"
run() { name=$1; shift; { echo "\$ $*" | sed "s#$SCR#<tmp>#g"; env -u SSH_AUTH_SOCK "$@" 2>&1 | sed "s#$SCR#<tmp>#g"; echo "exit=${PIPESTATUS[0]}"; } > "$OUT/$name.out"; }

# --- offline
run 01_selftest $T selftest
run 02_static_check_fix2 python3 -I -B tests/evidence/artifacts/review-sources/fix2/static_check_fix2.py .
python3 -I -B $F/make_cases.py "$SCR/cases" > "$OUT/03_make_cases.out" 2>&1
C="$SCR/cases"
run 10_compare_baseline_repeat $T compare docs/sources/fetch-baseline.json docs/sources/fetch-repeat.json
run 11_compare_aux_self $T compare docs/sources/fetch-baseline-aux.json docs/sources/fetch-baseline-aux.json
run 12_compare_gone404 $T compare docs/sources/fetch-baseline.json "$C/case_gone.json"
run 13_compare_gone410 $T compare docs/sources/fetch-baseline.json "$C/case_gone410.json"
run 14_compare_failed403 $T compare docs/sources/fetch-baseline.json "$C/case_failed.json"
run 15_compare_rawmoved_rawprimary $T compare docs/sources/fetch-baseline.json "$C/case_rawmoved_rawprimary.json"
run 16_compare_rawmoved_normprimary $T compare docs/sources/fetch-baseline.json "$C/case_rawmoved_normprimary.json"
run 17_compare_both_rawmoved $T compare docs/sources/fetch-baseline.json "$C/case_both_rawmoved.json"
run 18_compare_fresh_vs_fresh_offpin $T compare "$C/case_offpin_ident_A.json" "$C/case_offpin_ident_B.json"
run 19_compare_fresh_vs_fresh_offpin_nopins $T compare "$C/case_offpin_ident_A.json" "$C/case_offpin_ident_B.json" --no-pins
run 20_compare_content $T compare docs/sources/fetch-baseline.json "$C/case_content.json"
run 21_compare_content_and_gone $T compare docs/sources/fetch-baseline.json "$C/case_content_and_gone.json"
run 22_compare_rawmoved_nopins $T compare docs/sources/fetch-baseline.json "$C/case_rawmoved_rawprimary.json" --no-pins
run 23_upstream_bad_recorded_url $T upstream --pins "$C/pins_badupstream.json" --only S19
run 24_fetch_deadline_zero_is_usage_error $T fetch --only S01 --deadline 0 --out "$C/x.json"
run 25_fetch_tiny_deadline $T fetch --only S01 --deadline 0.001 --out "$C/deadline.json"
run 26_excerpts_snapshots_only $T excerpts --set all
run 27_verify_all_snapshots bash -c '
  for f in docs/sources/snapshots/S*.txt.gz; do i=$(basename "$f" .txt.gz); python3 -I -B docs/sources/tools/fetch_pins.py verify --fetch-result docs/sources/fetch-baseline.json --id "$i" --snapshot "$f"; echo "exit=$?"; done
  for f in docs/sources/snapshots/A*.txt.gz; do i=$(basename "$f" .txt.gz); python3 -I -B docs/sources/tools/fetch_pins.py verify --fetch-result docs/sources/fetch-baseline-aux.json --id "$i" --snapshot "$f"; echo "exit=$?"; done'
run 28_fetch_blob_mismatch_S29 $T fetch --only S29 --pins "$C/pins_badblob.json" --out "$C/badblob.json"   # [GET] one pinned raw URL
run 29_mutation_check python3 -I -B $F/mutation_check.py "$SCR/mut"   # copies the tool into the scratch dir, breaks it 18 ways, expects selftest to fail each time

[ "$MODE" = live ] || exit 0

# --- live
SNAPIDS=$(python3 -I -B -c 'import json;print(",".join(s["id"] for s in json.load(open("docs/sources/pins.json"))["sources"] if s["pin_v2"].get("snapshot")))')
run 40_normalizer_old_vs_new python3 -I -B $F/normalizer_old_vs_new.py "$SCR/probe"
run 41_fetch_runA $T fetch --out "$SCR/runA.json" --snapshots-dir "$SCR/snapA" --snapshot-ids "$SNAPIDS"
run 42_fetch_runB $T fetch --out "$SCR/runB.json" --snapshots-dir "$SCR/snapB" --snapshot-ids "$SNAPIDS"
run 43_compare_baseline_runA $T compare docs/sources/fetch-baseline.json "$SCR/runA.json"
run 44_compare_runA_runB $T compare "$SCR/runA.json" "$SCR/runB.json"
run 45_fetch_aux $T fetch --set aux --out "$SCR/aux.json" --snapshots-dir "$SCR/snapAux" --snapshot-ids A01,A02,A03,A04
run 46_compare_aux_baseline $T compare docs/sources/fetch-baseline-aux.json "$SCR/aux.json"
cmpsnap() { # committed snapshot vs a fresh one: "=" same bytes, "!=" different bytes, "no fresh snapshot" when the fetch failed
  for f in docs/sources/snapshots/$1*.txt.gz; do i=$(basename "$f" .txt.gz); g="$2/$i.txt.gz"
    if [ ! -f "$g" ]; then echo "$i no fresh snapshot ($3)"; elif cmp -s "$f" "$g"; then echo "$i committed = fresh ($3)"; else echo "$i committed != fresh ($3)"; fi; done; }
{ cmpsnap S "$SCR/snapA" runA; cmpsnap A "$SCR/snapAux" aux
  for f in "$SCR"/snapA/*.txt.gz; do i=$(basename "$f"); cmp -s "$f" "$SCR/snapB/$i" && echo "${i%.txt.gz} runA = runB" || echo "${i%.txt.gz} runA != runB"; done; } > "$OUT/47_snapshot_cmp.out" 2>&1
run 48_upstream $T upstream --out "$SCR/upstream.json"
run 49_tags $T tags --out "$SCR/tags.json"
run 50_excerpts_all_git $T excerpts --set all --fetch-git
for f in runA runB aux upstream tags; do sed "s#$SCR#<tmp>#g" "$SCR/$f.json" > "$OUT/data_$f.json"; done
if [ -n "${ALT_PYTHON:-}" ]; then
  FAILED=$(python3 -I -B -c 'import json,sys;print(",".join(r["id"] for r in json.load(open(sys.argv[1]))["results"] if r["http_status"]!=200 or "error" in r))' "$SCR/runA.json")
  if [ -n "$FAILED" ]; then
    run 51_fetch_failed_ids_alt_python "$ALT_PYTHON" -I -B docs/sources/tools/fetch_pins.py fetch --only "$FAILED" --out "$SCR/alt.json" --snapshots-dir "$SCR/snapAlt" --snapshot-ids "$FAILED"
    python3 -I -B $F/merge_results.py "$SCR/runA.json" "$SCR/alt.json" "$SCR/runA_merged.json" > "$OUT/52_merge_results.out" 2>&1
    run 53_compare_baseline_merged $T compare docs/sources/fetch-baseline.json "$SCR/runA_merged.json"
    { cmpsnap S "$SCR/snapAlt" alt_python | grep -E "^($(echo "$FAILED" | sed 's/,/|/g')) "; } > "$OUT/54_snapshot_cmp_alt_python.out" 2>&1
    sed "s#$SCR#<tmp>#g" "$SCR/alt.json" > "$OUT/data_alt.json"
  fi
  run 55_normalizer_old_vs_new_alt_python "$ALT_PYTHON" -I -B $F/normalizer_old_vs_new.py "$SCR/probe_alt"
fi
