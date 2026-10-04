#!/bin/sh
# Experiment 1: can a `bun build --compile` hello-world ignore BUN_OPTIONS / BUN_INSPECT /
# BUN_INSPECT_PRELOAD / BUN_BE_BUN?  Run from anywhere. Work dir /tmp/ts-research.
# Only loopback inspector URLs are used; the process is killed by exact PID if it outlives the test.
set -u
R=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W=/tmp/ts-research; rm -rf "$W"; mkdir -p "$W/home" "$W/bin"
cp "$R/src/hello.ts" "$R/src/pre.ts" "$W/"
cd "$W" || exit 1
echo "date=$(date -u +%FT%TZ)"; echo "bun=$(bun --version) rev=$(bun --revision)"
CF="--no-compile-autoload-dotenv --no-compile-autoload-bunfig --no-compile-autoload-tsconfig --no-compile-autoload-package-json"
bun build --compile hello.ts --outfile bin/A_default >/dev/null 2>&1; echo "build A_default rc=$?"
bun build --compile $CF hello.ts --outfile bin/B_noautoload >/dev/null 2>&1; echo "build B_noautoload rc=$?"
bun build --compile $CF --compile-exec-argv="--smol" hello.ts --outfile bin/C_execargv >/dev/null 2>&1; echo "build C_execargv rc=$?"
bun build --compile $CF --bytecode hello.ts --outfile bin/D_bytecode >/dev/null 2>&1; echo "build D_bytecode rc=$?"
run() { # label, then env assignments..., exe ; clean env
  env -i PATH=/usr/bin:/bin HOME="$W/home" "$@"
}
PORT=47461
for V in A_default B_noautoload C_execargv D_bytecode; do
  E="$W/bin/$V"
  echo "=== $V"
  echo "-- baseline";               run "$E" 2>&1 | tr '\n' ' '; echo "rc=$?"
  echo "-- BUN_OPTIONS=--preload";  run BUN_OPTIONS="--preload $W/pre.ts" "$E" 2>&1 | tr '\n' ' '; echo
  echo "-- BUN_INSPECT_PRELOAD";    run BUN_INSPECT_PRELOAD="$W/pre.ts" "$E" 2>&1 | tr '\n' ' '; echo
  echo "-- BUN_BE_BUN=1 --version"; run BUN_BE_BUN=1 "$E" --version 2>&1 | head -c 200 | tr '\n' ' '; echo
  echo "-- BUN_BE_BUN=1 -e";        run BUN_BE_BUN=1 "$E" -e 'console.log("BE_BUN_EVAL_RAN")' 2>&1 | head -c 200 | tr '\n' ' '; echo
  PORT=$((PORT+1))
  echo "-- BUN_INSPECT=ws://127.0.0.1:$PORT/hmres"
  # NB: not via run(): backgrounding a shell function would make $! a subshell, not the program
  env -i PATH=/usr/bin:/bin HOME="$W/home" BUN_INSPECT="ws://127.0.0.1:$PORT/hmres" "$E" >"$W/insp.out" 2>&1 &
  P=$!; sleep 1
  echo "listeners_by_pid: $(/usr/sbin/lsof -nP -a -p $P -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $9}' | tr '\n' ' ')"
  wait $P; echo "rc=$? out: $(head -c 200 "$W/insp.out" | tr '\n' ' ')"
  PORT=$((PORT+1))
  echo "-- BUN_OPTIONS=--inspect=127.0.0.1:$PORT/hmres"
  env -i PATH=/usr/bin:/bin HOME="$W/home" BUN_OPTIONS="--inspect=127.0.0.1:$PORT/hmres" "$E" >"$W/insp.out" 2>&1 &
  P=$!; sleep 1
  echo "listeners_by_pid: $(/usr/sbin/lsof -nP -a -p $P -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $9}' | tr '\n' ' ')"
  wait $P; echo "rc=$? out: $(head -c 300 "$W/insp.out" | tr '\n' ' ')"
done
