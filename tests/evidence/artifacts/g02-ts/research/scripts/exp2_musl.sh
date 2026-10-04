#!/bin/sh
# Experiment 2: Bun 1.4.2 musl compile targets, and OpenTUI 0.5.14 musl native packages.
# Cross-compiles hello-worlds on the host, runs them in alpine:3.22 containers (no network,
# read-only mount, removed on exit). arm64 container is native to the Docker VM; the amd64
# container is QEMU/Rosetta emulation (supplementary only, per CLAUDE.md it closes no claim).
set -u
R=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
P=$R/../../../../../prototypes/ts/node_modules/@opentui
W=/tmp/ts-research/musl; rm -rf "$W"; mkdir -p "$W"
echo "date=$(date -u +%FT%TZ)"; echo "bun=$(bun --version)"
for t in linux-arm64-musl linux-x64-musl linux-arm64; do
  bun build --compile --target=bun-$t --no-compile-autoload-dotenv --no-compile-autoload-bunfig "$R/src/hello_musl.ts" --outfile "$W/hello-$t" >"$W/build-hello-$t.log" 2>&1
  echo "build hello bun-$t rc=$? size=$(wc -c <"$W/hello-$t" 2>/dev/null)"
  case $t in *musl) bun build --compile --target=bun-$t --no-compile-autoload-dotenv --no-compile-autoload-bunfig "$R/src/ffi_probe.ts" --outfile "$W/ffi-$t" >"$W/build-ffi-$t.log" 2>&1; echo "build ffi bun-$t rc=$?";; esac
  head -c 300 "$W/build-hello-$t.log" | tr '\n' ' '; echo
done
cp "$P/core-linux-arm64-musl/libopentui.so" "$W/libopentui-arm64-musl.so"
cp "$P/core-linux-x64-musl/libopentui.so" "$W/libopentui-x64-musl.so"
cp "$P/core-linux-arm64/libopentui.so" "$W/libopentui-arm64-glibc.so"
file "$W"/hello-* "$W"/ffi-* 2>/dev/null | sed "s#$W/##" | cut -c1-200
# Containers run with default (outbound-only) networking solely so `apk add` can fetch
# libstdc++/libgcc from the Alpine CDN; nothing listens. Each run first records the result
# BEFORE installing them, then installs and re-runs.
d() { img=$1; plat=$2; shift 2
  docker run --rm --pull never --platform "$plat" -v "$W":/t:ro "$img" sh -c '
    for c in "$@"; do
      echo "[before apk add libstdc++ libgcc] $c"; sh -c "/t/$c" 2>&1 | head -c 300; echo "rc=$?"
    done
    apk add --no-cache libstdc++ libgcc >/dev/null 2>&1; echo "apk rc=$? $(apk info -e libstdc++ libgcc | tr "\n" " ")"
    for c in "$@"; do
      echo "[after apk add] $c"; sh -c "/t/$c" 2>&1 | head -c 300; echo "rc=$?"
    done' sh "$@"
}
echo "=== alpine:3.22 arm64 (native to Docker VM)"
d alpine:3.22 linux/arm64 "hello-linux-arm64-musl" "hello-linux-arm64" "ffi-linux-arm64-musl /t/libopentui-arm64-musl.so" "ffi-linux-arm64-musl /t/libopentui-arm64-glibc.so"
echo "=== alpine:3.22 amd64 (emulated; supplementary only)"
d hp-g02-alpine-amd64:3.22 linux/amd64 "hello-linux-x64-musl" "ffi-linux-x64-musl /t/libopentui-x64-musl.so"
