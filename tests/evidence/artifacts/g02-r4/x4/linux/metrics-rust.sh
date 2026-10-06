#!/bin/bash
# Crate counts and crude unsafe/FFI surface for the Rust spike (target linux musl arm64, normal+build deps).
# usage: metrics-rust.sh <scratch-copy-of-rust-dir>   (Cargo.lock is used with --locked)
set -u
cd "$1" || exit 1
T=aarch64-unknown-linux-musl
for feat in "--no-default-features" "" "--features facade"; do
  echo "== features: ${feat:-default}"
  echo -n "crates linked into the binary (normal edges, no proc-macros, excl. root): "
  cargo tree --locked $feat --target $T -e normal,no-proc-macro --prefix none -f '{p}' 2>/dev/null | sed 's/ (.*//' | sort -u | grep -v '^x4spike' | wc -l | tr -d ' '
  echo -n "all crates incl. proc-macro/build-time (excl. root): "
  cargo tree --locked $feat --target $T -e normal,build --prefix none -f '{p}' 2>/dev/null | sed 's/ (.*//' | sort -u | grep -v '^x4spike' | wc -l | tr -d ' '
done
echo "== direct deps (default features)"; cargo tree --locked --target $T -e normal --depth 1 --prefix none 2>/dev/null
echo "== crude unsafe census over crates linked into the default-feature binary (grep of src/**/*.rs; cfg not applied; includes tests/other-OS code)"
cargo fetch --locked --target $T >/dev/null 2>&1
REG=$(ls -d "$HOME"/.cargo/registry/src/*/ | head -1)
cargo tree --locked --target $T -e normal,no-proc-macro --prefix none -f '{p}' 2>/dev/null | sed 's/ (.*//' | sort -u | grep -v '^x4spike' | while read -r name ver; do
  d="$REG$name-${ver#v}"; [ -d "$d/src" ] || { echo "$name $ver (source dir not found)"; continue; }
  n=$(grep -rE '\bunsafe\b' "$d/src" --include='*.rs' 2>/dev/null | grep -vE '^\s*[^:]*:\s*//' | wc -l | tr -d ' ')
  forbid=$(grep -rE 'forbid\(unsafe_code\)' "$d/src" --include='*.rs' 2>/dev/null | wc -l | tr -d ' ')
  echo "$name ${ver#v} unsafe_lines=$n forbid_unsafe_attr=$forbid"
done | sort -t= -k2 -n -r
echo "== linux-keyutils direct deps"; cargo tree --locked --target $T -e normal -p linux-keyutils --depth 1 --prefix none 2>/dev/null
echo "== secret-service direct deps"; cargo tree --locked --target $T -e normal -p secret-service --depth 1 --prefix none 2>/dev/null
echo "== any crate in linked graph with a build.rs that compiles C (cc crate)?"; cargo tree --locked --target $T -e normal,build,no-proc-macro --prefix none -f '{p}' 2>/dev/null | sed 's/ (.*//' | sort -u | grep -E '^(cc|cmake|pkg-config|bindgen|openssl-sys|libdbus-sys|vcpkg) ' || echo "none of cc/cmake/pkg-config/bindgen/openssl-sys/libdbus-sys present"
