#!/usr/bin/env bash
# M00-T04-x4-stores: cross-build the X4 Windows spikes for x86_64 Windows on the Mac (scratch only).
# Derived from x4/windows/build.sh. Differences: Rust sources are the adapted copy (store checks), the
# Go sources are unmodified; CARGO_HOME, GOCACHE, GOMODCACHE and cargo's default target/ live in the scratch dir;
# cargo-zigbuild 0.23.4 was installed into the scratch dir (the prototype's copy no longer exists).
# usage: build-stores.sh <scratch-dir>
set -u
S=${1:?scratch dir}
OUT="$S/out"; mkdir -p "$OUT"; rc=0
# Go modules: the shared module cache holds only extracted sources (no download zips), so GOPROXY=off
# fails; the two go.sum-pinned modules are downloaded from the default proxy into a scratch GOMODCACHE.
# Cargo crates (Cargo.lock-pinned) were fetched once with `cargo fetch --locked` into the scratch CARGO_HOME.
export CARGO_HOME="$S/cargo-home" CARGO_NET_OFFLINE=true GOCACHE="$S/gocache" GOMODCACHE="$S/gomodcache" GOFLAGS="-mod=readonly -modcacherw"
echo "== versions"; go version; rustc --version; cargo --version; zig version; "$S/tools/bin/cargo-zigbuild" --version
echo "== go vet (windows/amd64)"
(cd "$S/go" && GOOS=windows GOARCH=amd64 go vet ./...) ; echo "go_vet_exit=$?"
echo "== go build"
(cd "$S/go" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$OUT/x4-go.exe" .) ; g=$?
echo "go_build_exit=$g"; [ $g -eq 0 ] || rc=1
echo "== cargo clippy (-D warnings)"
(cd "$S/rust" && cargo clippy --locked --target x86_64-pc-windows-gnu -- -D warnings) ; echo "clippy_exit=$?"
echo "== cargo zigbuild --release"
(cd "$S/rust" && RUSTFLAGS="--remap-path-prefix=$S=/x4 --remap-path-prefix=$HOME=/home -C link-arg=-Wl,/Brepro" "$S/tools/bin/cargo-zigbuild" zigbuild --release --locked --target x86_64-pc-windows-gnu) ; r=$?
echo "rust_build_exit=$r"; [ $r -eq 0 ] || rc=1
[ $r -eq 0 ] && cp "$S/rust/target/x86_64-pc-windows-gnu/release/x4-rust.exe" "$OUT/x4-rust.exe"
echo "== outputs"; for f in "$OUT"/*.exe; do printf '%s %s %s\n' "$(basename "$f")" "$(stat -f %z "$f")" "$(shasum -a 256 "$f" | cut -d' ' -f1)"; done
echo "== home-path leak check (count of /Users/ in each binary)"; for f in "$OUT"/*.exe; do printf '%s %s\n' "$(basename "$f")" "$(grep -c -a /Users/ "$f")"; done
echo "build_exit=$rc"; exit $rc
