#!/bin/bash
# Runs inside rust:1.98.1-bookworm (linux/arm64). /src = copy of ./rust, /out = scratch.
set -u
rustc --version; cargo --version
export CARGO_TARGET_DIR=/out/target CARGO_HOME=/out/cargo-home
for tgt in aarch64-unknown-linux-gnu aarch64-unknown-linux-musl; do
  [ "$tgt" = aarch64-unknown-linux-musl ] && { rustup target add $tgt 2>&1 | tail -1; }
  cd /src
  echo "=== BUILD $tgt spike (backends, +facade bin) ==="
  cargo build --locked --release --target $tgt --features facade 2>&1 | tail -3; echo "exit=${PIPESTATUS[0]}"
  echo "=== BUILD $tgt baseline (no backends) ==="
  cargo build --locked --release --target $tgt --no-default-features --bin x4spike 2>&1 | tail -2; echo "exit=${PIPESTATUS[0]}"
  mkdir -p /out/$tgt
  cp /out/target/$tgt/release/x4spike-keyring /out/$tgt/x4spike-keyring
  cp /out/target/$tgt/release/x4spike /out/$tgt/x4spike-baseline  # baseline built last
  # rebuild with backends to overwrite x4spike (cargo reuses cache per feature set)
  cargo build --locked --release --target $tgt --bin x4spike 2>&1 | tail -1
  cp /out/target/$tgt/release/x4spike /out/$tgt/x4spike
done
ls -l /out/*/
