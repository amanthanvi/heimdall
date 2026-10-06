#!/bin/sh
# X5 build matrix: variants x targets. POSIX sh. Writes $OUT/results.tsv and per-build logs.
# Usage: build.sh <out-dir> [variant ...]
# Requires: rustc 1.99.0, zig on PATH, $CARGO_ZIGBUILD (cargo-zigbuild 0.23.4).
# Target dir and outputs live outside the repo (scratch); only logs/summary are copied in.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
OUT=${1:?out dir}; shift
mkdir -p "$OUT/logs" "$OUT/bin"
VARIANTS=${*:-"iroh-default iroh-ring-min iroh-awslc-min none"}
TARGETS="aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu"
TD=${CARGO_TARGET_DIR:-/tmp/hm-r4/M00-T05-r4-x5/target}
CH=${CARGO_HOME:-$HOME/.cargo}
SYSROOT=$(rustc --print sysroot)
RH=$(rustc -vV | sed -n 's/^commit-hash: //p')
export RUSTFLAGS="--remap-path-prefix=$CH/registry/src=/cargo/registry/src --remap-path-prefix=$SYSROOT/lib/rustlib/src/rust=/rustc/$RH --remap-path-prefix=$TD=/target --remap-path-prefix=$HERE=/x5"
cd "$HERE" || exit 1
for v in $VARIANTS; do
  if [ "$v" = none ]; then FEAT="--no-default-features"; else FEAT="--no-default-features --features $v"; fi
  for t in $TARGETS; do
    if [ "$t" = aarch64-apple-darwin ]; then CMD="cargo build"; else CMD="$CARGO_ZIGBUILD zigbuild"; fi
    exe=x5-iroh; case $t in *windows*) exe=x5-iroh.exe;; esac
    log="$OUT/logs/$v.$t.log"
    s=$(date -u +%s)
    CARGO_TARGET_DIR="$TD/$v" $CMD --locked --release --target "$t" $FEAT > "$log" 2>&1
    rc=$?
    e=$(date -u +%s)
    bytes=-; sha=-
    if [ $rc -eq 0 ] && [ -f "$TD/$v/$t/release/$exe" ]; then
      mkdir -p "$OUT/bin/$v/$t"; cp "$TD/$v/$t/release/$exe" "$OUT/bin/$v/$t/$exe"
      bytes=$(wc -c < "$OUT/bin/$v/$t/$exe" | tr -d ' ')
      sha=$(shasum -a 256 "$OUT/bin/$v/$t/$exe" | cut -d' ' -f1)
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$t" "$rc" "$((e-s))" "$bytes" "$sha" | tee -a "$OUT/results.tsv"
  done
done
