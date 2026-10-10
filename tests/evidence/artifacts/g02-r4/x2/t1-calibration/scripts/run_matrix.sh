#!/bin/sh
# M00-T05-r4-x2-t1cal: run jcprobe.py for every build on one platform/shell.
# Usage: sh run_matrix.sh <scratch-root> darwin|linux bash|zsh <reps> <parallel> [scenario,list]
# darwin: binaries are private copies under /tmp/t1cb/<label>/heimdall-proto (no home path in
# transcripts). linux: heimdall-g02-harness:d0c8e448a3a7, --network none, caps dropped, the probe
# is PID 1 so it reaps orphans; binaries from <scratch-root>/bins/<label>/linux-arm64 (read-only).
set -u
S=$1; PLAT=$2; SH=$3; REPS=$4; PAR=$5; ONLY=${6:-}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$S/out/$PLAT-$SH"
mkdir -p "$OUT"
LABELS="plain base-go base-go-pinned base-rust T1-go-opus1 T1-go-opus2 T1-go-sonnet1 T1-rust-opus1 T1-rust-opus2 T1-rust-sonnet1"
one() {
  label=$1
  if [ "$PLAT" = darwin ]; then
    b=/tmp/t1cb/$label/heimdall-proto; [ "$label" = plain ] && b=plain
    python3 -I -B "$HERE/jcprobe.py" --bin "$b" --label "$label" --shell "$SH" --reps "$REPS" \
      ${ONLY:+--only "$ONLY"} --out "$OUT/$label.json" >"$OUT/$label.log" 2>&1
  else
    b=/b/$label/linux-arm64/heimdall-proto; [ "$label" = plain ] && b=plain
    docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
      --user "$(id -u):$(id -g)" -v "$S/bins:/b:ro" -v "$HERE:/p:ro" -v "$OUT:/o" \
      heimdall-g02-harness:d0c8e448a3a7 python3 -I -B /p/jcprobe.py --bin "$b" --label "$label" \
      --shell "$SH" --reps "$REPS" ${ONLY:+--only "$ONLY"} --out "/o/$label.json" >"$OUT/$label.log" 2>&1
  fi
  echo "$label exit=$?" >>"$OUT/exit-codes.txt"
}
: >"$OUT/exit-codes.txt"
running=0
for l in $LABELS; do
  one "$l" &
  running=$((running + 1))
  if [ "$running" -ge "$PAR" ]; then wait; running=0; fi
done
wait
cat "$OUT/exit-codes.txt"
