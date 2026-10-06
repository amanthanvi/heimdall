#!/bin/bash
# G02 round-4 X4 (macOS): can a Linux build host produce the darwin spike binaries?
# Runs in throwaway containers (--rm, no published ports). Toolchains: Go 1.27.1 linux-arm64 and
# Zig 0.16.0 aarch64-linux tarballs (sha256-verified, mounted read-only); rust:1.98.1-bookworm image.
# No macOS SDK is provided to either container, which is the situation of a stock Linux CI runner.
# Usage: bash cross-linux.sh 2>&1 | sed -e "s#$SCR#<scratch>#g" -e "s#$HOME#<home>#g" > cross-linux.log
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCR=/tmp/hm-r4/M00-T05-r4-x4-macos
TOOLS=$SCR/tools/linux
WORK=$SCR/xwork
rm -rf "$WORK"; mkdir -p "$WORK"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
D="docker run --rm --label heimdall.x4.scratch=1 -v $HERE:/src:ro -v $TOOLS:/tools:ro -v $WORK:/work -e HOME=/work"
# The slim image has no CA bundle; the purego module is supplied from the host scratch module cache
# (populated by `go mod tidy`, verified against go.sum), mounted read-only, with GOPROXY=off.
GOMOD="-v $SCR/gomod:/gomod:ro"

echo "$(ts) docker $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')"

echo "== Go (debian:bookworm-slim + go1.27.1 linux-arm64 + zig 0.16.0)"
$D $GOMOD -w /src/go debian:bookworm-slim bash -c '
export PATH=/tools/go/bin:/tools/zig-aarch64-linux-0.16.0:$PATH GOCACHE=/work/gocache GOPATH=/work/gopath GOTOOLCHAIN=local GOFLAGS=
r() { echo "\$ $1"; shift; "$@" 2>&1 | sed "s/^/    /"; echo "[exit=${PIPESTATUS[0]}]"; }
go version; zig version
r "hello: GOOS=darwin GOARCH=arm64 CGO_ENABLED=0" env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o /work/hello-go-darwin ./baseline-hello
[ -e /work/hello-go-darwin ] && echo "    hello-go-darwin magic=$(od -An -tx1 -N4 /work/hello-go-darwin | tr -d " ") (cffaedfe = Mach-O 64-bit LE)"
r "spike: GOOS=darwin GOARCH=arm64 CGO_ENABLED=0" env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o /work/hm-x4-go-darwin-nocgo .
r "spike: GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 CC=zig cc -target aarch64-macos (no SDK)" env GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 CC="zig cc -target aarch64-macos" go build -trimpath -o /work/hm-x4-go-darwin-cgo .
cd /src/go-purego
r "purego spike: GOOS=darwin GOARCH=arm64 CGO_ENABLED=0" env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 GOMODCACHE=/gomod GOPROXY=off GOFLAGS=-mod=readonly go build -trimpath -o /work/hm-x4-go-purego-darwin .
[ -e /work/hm-x4-go-purego-darwin ] && echo "    hm-x4-go-purego-darwin magic=$(od -An -tx1 -N4 /work/hm-x4-go-purego-darwin | tr -d " ") sha256=$(sha256sum /work/hm-x4-go-purego-darwin | cut -c1-16)"
'
echo "$(ts) [go container] exit=$?"

echo "== Rust (rust:1.98.1-bookworm + zig 0.16.0 + cargo-zigbuild 0.23.4)"
$D -w /src/rust rust:1.98.1-bookworm bash -c '
export PATH=/tools/zig-aarch64-linux-0.16.0:/work/cargo-home/bin:$PATH CARGO_HOME=/work/cargo-home
r() { echo "\$ $1"; shift; "$@" 2>&1 | grep -v -E "^\s+(Compiling|Downloaded|Downloading|Updating|Locking|Adding|Installing|Fresh|Checking) " | tail -25 | sed "s/^/    /"; echo "[exit=${PIPESTATUS[0]}]"; }
rustc --version; cargo --version; zig version
r "rustup target add aarch64-apple-darwin" rustup target add aarch64-apple-darwin
r "hello: cargo build --target aarch64-apple-darwin (system cc linker)" env CARGO_TARGET_DIR=/work/t-hello-cc cargo build --release --locked --target aarch64-apple-darwin --manifest-path baseline-hello/Cargo.toml
r "spike: cargo build --target aarch64-apple-darwin (system cc linker)" env CARGO_TARGET_DIR=/work/t-spike-cc cargo build --release --locked --target aarch64-apple-darwin
r "cargo install cargo-zigbuild 0.23.4 --locked" cargo install cargo-zigbuild --version 0.23.4 --locked --quiet
r "hello: cargo zigbuild --target aarch64-apple-darwin" env CARGO_TARGET_DIR=/work/t-hello-zig cargo zigbuild --release --locked --target aarch64-apple-darwin --manifest-path baseline-hello/Cargo.toml
f=/work/t-hello-zig/aarch64-apple-darwin/release/hm-x4-rust-hello; [ -e $f ] && echo "    hello-rust-darwin magic=$(od -An -tx1 -N4 $f | tr -d " ")"
r "spike: cargo zigbuild --target aarch64-apple-darwin" env CARGO_TARGET_DIR=/work/t-spike-zig cargo zigbuild --release --locked --target aarch64-apple-darwin
'
echo "$(ts) [rust container] exit=$?"
echo "== Run the Linux-built cgo-free purego binary on this Mac (no re-signing)"
B=$WORK/hm-x4-go-purego-darwin
if [ -e "$B" ]; then
	codesign -dv "$B" 2>&1 | grep -E '^(Signature|CodeDirectory)' | sed 's/^/    /'
	unset SSH_AUTH_SOCK
	for c in se dpprobe; do
		perl -e 'alarm 60; exec @ARGV' "$B" "$c" 2>&1 | sed 's/^/    /'
		echo "$(ts) [linux-built purego $c] exit=${PIPESTATUS[0]}"
	done
fi
echo "$(ts) done"
