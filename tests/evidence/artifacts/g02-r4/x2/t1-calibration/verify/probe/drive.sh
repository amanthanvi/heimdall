#!/bin/sh
# drive.sh <platform> <shell> <outdir>  -- run probe.py for every build x signal x mode, 3 reps.
# Run from the directory that holds bin/<build>/<platform>/heimdall-proto and probe/probe.py
# (relative binary paths keep home paths out of the records).
set -u
unset SSH_AUTH_SOCK
platform=$1; shell=$2; out=$3
reps=${REPS:-3}
mkdir -p "$out"
for build in exec base-go base-rust T1-go-opus1 T1-go-opus2 T1-go-sonnet1 T1-rust-opus1 T1-rust-opus2 T1-rust-sonnet1; do
  if [ "$build" = exec ]; then bin=exec; else bin="bin/$build/$platform/heimdall-proto"; fi
  for sig in TSTP STOP; do
    for mode in ladder cont; do
      python3 -I probe/probe.py --build "$build" --binary "$bin" --platform "$platform" --shell "$shell" \
        --signal "$sig" --mode "$mode" --reps "$reps" --out "$out"
      echo "probe exit $? ($build $sig $mode)" >> "$out/driver.log"
    done
  done
done
echo "DONE $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out/driver.log"
