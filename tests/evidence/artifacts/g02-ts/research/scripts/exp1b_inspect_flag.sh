#!/bin/sh
# Experiment 1b: does BUN_OPTIONS=--inspect=... open a listener in a compiled hello (loopback only)?
set -u
R=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W=/tmp/ts-research; mkdir -p $W/bin $W/home; E=$W/bin/long
bun build --compile --no-compile-autoload-dotenv --no-compile-autoload-bunfig "$R/src/long.ts" --outfile "$E" >/dev/null 2>&1; echo "build rc=$?"
echo "date=$(date -u +%FT%TZ)"
n=47490
for V in "--inspect=ws://127.0.0.1:%P/hmres" "--inspect=%P" "--inspect-wait=ws://127.0.0.1:%P/hmres"; do
  n=$((n+1)); O=$(echo "$V" | sed "s/%P/$n/")
  env -i PATH=/usr/bin:/bin HOME="$W/home" BUN_OPTIONS="$O" "$E" >"$W/o.out" 2>&1 &
  P=$!; sleep 1.5
  echo "BUN_OPTIONS=$O listeners_by_pid: $(/usr/sbin/lsof -nP -a -p $P -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $9}' | tr '\n' ' ')"
  # stop only the exact PID this script started
  kill $P 2>/dev/null; wait $P 2>/dev/null; echo "out: $(head -c 250 $W/o.out | tr '\n' ' ')"
done
