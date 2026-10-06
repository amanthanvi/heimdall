#!/bin/sh
# parity-r3c: dedicated probes 2 and 3 (contlauncher.py, nested.py), added after run 1 showed
# probe.py's explicit/nested scenarios are contaminated (see RESULTS.md, harness notes).
#   run_extra.sh OUTDIR GO_BIN RUST_BIN       (appends to OUTDIR/exit-codes.txt)
set -u
P=$(cd "$(dirname "$0")" && pwd -P)
OUT=$1; GO=$2; RS=$3
unset SSH_AUTH_SOCK
PY=${PY:-python3}
EC="$OUT/exit-codes.txt"
rec() { echo "$1 exit=$2" >> "$EC"; }
mkdir -p "$OUT/cont" "$OUT/nested"
for sh in bash zsh; do
    $PY "$P/contlauncher.py" $sh "$OUT/cont" go="$GO" rust="$RS" > "$OUT/cont/$sh-console.txt" 2>&1; rec "contlauncher.py $sh" $?
    $PY "$P/nested.py" $sh "$OUT/nested" go="$GO" rust="$RS" > "$OUT/nested/$sh-console.txt" 2>&1; rec "nested.py $sh" $?
done
