#!/bin/bash
# M00-T02-fix2: final verification with the revised fetcher (GET only). Usage, from the repository root:
#   bash tests/evidence/artifacts/review-sources/fix2/run_final.sh <scratch_dir_outside_repo> <out_dir>
# Each command's stdout+stderr goes to <out_dir>/<name>.out followed by a line "exit=<code>".
set -u
SCR=$1
OUT=$2
T="python3 -I docs/sources/tools/fetch_pins.py"
mkdir -p "$SCR/final" "$OUT"
SNAPIDS=$(python3 -I -c 'import json;print(",".join(s["id"] for s in json.load(open("docs/sources/pins.json"))["sources"] if s["pin_v2"].get("snapshot")))')
run() { name=$1; shift; { echo "\$ $*" | sed "s#$SCR#<tmp>#g"; echo "# start $(date -u +%Y-%m-%dT%H:%M:%SZ)"; env -u SSH_AUTH_SOCK "$@" 2>&1 | sed "s#$SCR#<tmp>#g"; echo "exit=${PIPESTATUS[0]}"; } > "$OUT/$name.out"; }
run final_selftest $T selftest
run final_fetch_runA $T fetch --out "$SCR/final/runA.json" --snapshots-dir "$SCR/final/snapA" --snapshot-ids "$SNAPIDS"
run final_fetch_runB $T fetch --out "$SCR/final/runB.json" --snapshots-dir "$SCR/final/snapB" --snapshot-ids "$SNAPIDS"
run final_compare_baseline_runA $T compare docs/sources/fetch-baseline.json "$SCR/final/runA.json"
run final_compare_runA_runB $T compare "$SCR/final/runA.json" "$SCR/final/runB.json"
run final_compare_baseline_repeat $T compare docs/sources/fetch-baseline.json docs/sources/fetch-repeat.json
run final_fetch_aux $T fetch --set aux --out "$SCR/final/aux.json" --snapshots-dir "$SCR/final/snapAux" --snapshot-ids A01,A02,A03,A04
run final_compare_aux_baseline $T compare docs/sources/fetch-baseline-aux.json "$SCR/final/aux.json"
{ for f in docs/sources/snapshots/S*.txt.gz; do i=$(basename "$f" .txt.gz); $T verify --fetch-result docs/sources/fetch-baseline.json --id "$i" --snapshot "$f"; echo "exit=$?"; done
  for f in docs/sources/snapshots/A*.txt.gz; do i=$(basename "$f" .txt.gz); $T verify --fetch-result docs/sources/fetch-baseline-aux.json --id "$i" --snapshot "$f"; echo "exit=$?"; done; } > "$OUT/final_verify_snapshots.out" 2>&1
{ for f in docs/sources/snapshots/S*.txt.gz; do i=$(basename "$f" .txt.gz); cmp -s "$f" "$SCR/final/snapA/$i.txt.gz" && echo "$i committed = fresh runA" || echo "$i committed != fresh runA"; done
  for f in docs/sources/snapshots/A*.txt.gz; do i=$(basename "$f" .txt.gz); cmp -s "$f" "$SCR/final/snapAux/$i.txt.gz" && echo "$i committed = fresh aux" || echo "$i committed != fresh aux"; done
  for f in "$SCR"/final/snapA/*.txt.gz; do i=$(basename "$f"); cmp -s "$f" "$SCR/final/snapB/$i" && echo "${i%.txt.gz} runA = runB" || echo "${i%.txt.gz} runA != runB"; done; } > "$OUT/final_snapshot_cmp.out" 2>&1
run final_upstream $T upstream --out "$SCR/final/upstream.json"
run final_tags $T tags --out "$SCR/final/tags.json"
run final_excerpts $T excerpts --set all --fetch-git
cp "$SCR/final/upstream.json" "$OUT/final_upstream.json"
cp "$SCR/final/tags.json" "$OUT/final_tags.json"
for f in runA runB aux; do sed "s#$SCR#<tmp>#g" "$SCR/final/$f.json" > "$OUT/final_fetch_$f.json"; done
