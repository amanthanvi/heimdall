#!/bin/bash
# M00-T02-fix4: verification suite. From the repository root:
#   bash tests/evidence/artifacts/review-sources/fix4/run_fix4.sh <scratch_dir_outside_repo> <out_dir> offline|live
# Each command's stdout+stderr goes to <out_dir>/<name>.out, first line "$ <command>", last line "exit=<code>".
# "offline" makes no request. "live" adds GET requests to the sources pinned in pins.json (fetch, upstream, tags,
# excerpts --fetch-git, the normalizer probe, the drift diffs). PY13 (default python3.13) is the interpreter for
# every live step: python3 (3.15.2, OpenSSL 4.1.0) cannot complete the TLS handshake with man.openbsd.org and
# www.openssh.org (docs/sources/README.md, "Environment").
set -u
SCR=$1
OUT=$2
MODE=${3:-offline}
PY13=${PY13:-python3.13}
F=tests/evidence/artifacts/review-sources/fix4
T="python3 -I -B docs/sources/tools/fetch_pins.py"
T13="$PY13 -I -B docs/sources/tools/fetch_pins.py"
mkdir -p "$SCR" "$OUT"
run() { name=$1; shift; { echo "\$ $*" | sed "s#$SCR#<tmp>#g"; env -u SSH_AUTH_SOCK "$@" 2>&1 | sed "s#$SCR#<tmp>#g"; echo "exit=${PIPESTATUS[0]}"; } > "$OUT/$name.out"; }

# --- offline
run 01_selftest_python3 $T selftest
run 02_selftest_python313 $T13 selftest
run 03_static_check_fix2 python3 -I -B tests/evidence/artifacts/review-sources/fix2/static_check_fix2.py .
run 04_mutation_check python3 -I -B $F/mutation_check.py "$SCR/mut"
run 05_verify_all_snapshots bash -c '
  for f in docs/sources/snapshots/S*.txt.gz; do i=$(basename "$f" .txt.gz); python3 -I -B docs/sources/tools/fetch_pins.py verify --fetch-result docs/sources/fetch-baseline.json --id "$i" --snapshot "$f"; echo "exit=$?"; done
  for f in docs/sources/snapshots/A*.txt.gz; do i=$(basename "$f" .txt.gz); python3 -I -B docs/sources/tools/fetch_pins.py verify --fetch-result docs/sources/fetch-baseline-aux.json --id "$i" --snapshot "$f"; echo "exit=$?"; done'
run 06_excerpts_snapshots_only $T excerpts --set all
run 07_compare_baseline_repeat $T compare docs/sources/fetch-baseline.json docs/sources/fetch-repeat.json
run 08_compare_aux_self $T compare docs/sources/fetch-baseline-aux.json docs/sources/fetch-baseline-aux.json
run 09_ledger_check_no_live_data python3 -I -B $F/ledger_check.py
run 10_find_citations python3 -I -B $F/find_citations.py

[ "$MODE" = live ] || exit 0

# --- live (python3.13)
SNAPIDS=$(python3 -I -B -c 'import json;p=json.load(open("docs/sources/pins.json"));print(",".join(s["id"] for s in p["sources"]+p["auxiliary_sources"] if s["pin_v2"].get("snapshot")))')
run 20_normalizer_fix3_vs_fix4 "$PY13" -I -B $F/normalizer_fix3_vs_fix4.py "$SCR/probe"
run 21_fetch_all $T13 fetch --set all --out "$SCR/fresh.json" --snapshots-dir "$SCR/snap" --snapshot-ids "$SNAPIDS"
run 22_compare_baseline_spec $T13 compare docs/sources/fetch-baseline.json "$SCR/fresh.json" --all
run 23_compare_baseline_aux $T13 compare docs/sources/fetch-baseline-aux.json "$SCR/fresh.json" --all
run 24_upstream $T13 upstream --out "$SCR/upstream.json"
run 25_tags $T13 tags --out "$SCR/tags.json"
run 26_excerpts_all_git $T13 excerpts --set all --fetch-git
run 27_drift_diffs "$PY13" -I -B $F/drift_diffs.py "$SCR/snap" "$SCR/fresh.json"
sed "s#$SCR#<tmp>#g" "$SCR/fresh.json" > "$OUT/data_fresh.json"
sed "s#$SCR#<tmp>#g" "$SCR/upstream.json" > "$OUT/data_upstream.json"
sed "s#$SCR#<tmp>#g" "$SCR/tags.json" > "$OUT/data_tags.json"
run 28_ledger_check_with_live_data python3 -I -B $F/ledger_check.py "$OUT"
