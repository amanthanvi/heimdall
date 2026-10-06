#!/bin/sh
# Native C/asm crate census per variant x target: cargo tree package sets + native_crates.py.
# Usage: native-census.sh <scratch-dir>
set -u
W=${1:?scratch dir}; mkdir -p "$W"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$HERE/../rust-embed" || exit 1
cargo metadata --locked --all-features --format-version 1 > "$W/meta.json"
for v in iroh-default iroh-ring-min iroh-awslc-min; do
  for t in aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu; do
    echo "## $v $t"
    cargo tree --locked -q --no-default-features --features "$v" --target "$t" -e normal,build --prefix none -f '{p}' \
      | sed 's/ (\*)//; s/ (proc-macro)//' | sort -u > "$W/pk.txt"
    python3 -I "$HERE/native_crates.py" "$W/pk.txt" < "$W/meta.json"
  done
done
