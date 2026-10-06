#!/usr/bin/env bash
# Cross-compile both X4 Windows spikes for x86_64 Windows from a non-Windows host (compile-only evidence).
# usage: build.sh <out-dir>      env: CARGO_ZIGBUILD=/path/to/cargo-zigbuild (needs zig on PATH)
# Go:   GOOS=windows GOARCH=amd64 CGO_ENABLED=0, no external toolchain.
# Rust: target x86_64-pc-windows-gnu linked by zig via cargo-zigbuild (no mingw install needed).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?out dir}
mkdir -p "$OUT"
rc=0

echo "== go vet (windows/amd64)"
(cd "$HERE/go" && GOOS=windows GOARCH=amd64 go vet ./...) ; echo "go_vet_exit=$?"
echo "== go build"
(cd "$HERE/go" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/x4-go.exe" .) ; g=$?
echo "go_build_exit=$g"; [ $g -eq 0 ] || rc=1

echo "== cargo clippy (-D warnings)"
(cd "$HERE/rust" && CARGO_TARGET_DIR="$OUT/rust-target" cargo clippy --locked --target x86_64-pc-windows-gnu -- -D warnings) ; echo "clippy_exit=$?"
echo "== cargo zigbuild --release"
ZB=${CARGO_ZIGBUILD:-cargo-zigbuild}
(cd "$HERE/rust" && CARGO_TARGET_DIR="$OUT/rust-target" RUSTFLAGS="--remap-path-prefix=$HERE=/x4 --remap-path-prefix=$HOME=/home -C link-arg=-Wl,/Brepro" "$ZB" zigbuild --release --locked --target x86_64-pc-windows-gnu) ; r=$?
echo "rust_build_exit=$r"; [ $r -eq 0 ] || rc=1
[ $r -eq 0 ] && cp "$OUT/rust-target/x86_64-pc-windows-gnu/release/x4-rust.exe" "$OUT/x4-rust.exe"
ls -l "$OUT"/*.exe 2>/dev/null
exit $rc
