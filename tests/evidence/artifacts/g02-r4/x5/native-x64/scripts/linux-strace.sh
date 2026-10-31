#!/bin/sh
# strace -ff (network syscalls, every thread/process in its own file) of one selftest and
# one x5-gosup run. Usage: linux-strace.sh <variant> <out-dir>. Raw traces stay in
# <out-dir>/raw (WSL scratch only); a summary is printed (redact before storing).
set -u
D=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
V=$1; O=$2; rm -rf "$O"; mkdir -p "$O/raw"
H=$D/bin/$V/x5-iroh; G=$D/bin/x5-gosup
for mode in selftest gosup; do
  mkdir -p "$O/raw/$mode"
  if [ $mode = selftest ]; then
    strace -ff -qq -yy -e trace=%network -o "$O/raw/$mode/t" env -i PATH=/usr/bin:/bin "$H" selftest > "$O/$mode.out" 2> "$O/$mode.err"; rc=$?
  else
    strace -ff -qq -yy -e trace=%network -o "$O/raw/$mode/t" env -i PATH=/usr/bin:/bin "$G" -helper "$H" > "$O/$mode.out" 2> "$O/$mode.err"; rc=$?
  fi
  echo "## strace $mode variant=$V exit=$rc trace_files=$(ls "$O/raw/$mode" | wc -l)"
  echo "stdout: $(cat "$O/$mode.out")"
  python3 -I "$D/scripts/strace_summary.py" "$O"/raw/$mode/t.*
done
