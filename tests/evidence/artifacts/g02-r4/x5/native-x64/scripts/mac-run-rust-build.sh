#!/bin/sh
S=$HOME/.local/share/heimdall-m00/r4-scratch/M00-T05-r5-x5
export RUSTUP_HOME=$S/rustup CARGO_HOME=$S/cargo
export PATH=$S/zig/zig-aarch64-macos-0.16.0:$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin
export CARGO_ZIGBUILD=$S/tools/bin/cargo-zigbuild CARGO_TARGET_DIR=$S/target
export CARGO_ZIGBUILD_CACHE_DIR=$S/zb-cache ZIG_GLOBAL_CACHE_DIR=$S/zig-cache ZIG_LOCAL_CACHE_DIR=$S/zig-cache
unset SSH_AUTH_SOCK
{ echo "rustc: $(rustc --version)"; echo "zig: $(zig version) ($(command -v zig | sed "s#$HOME#<home>#"))"; echo "cargo-zigbuild: $($CARGO_ZIGBUILD --version)"; } > $S/logs/toolchain.txt
$S/src/rust-embed/build.sh $S/out "$@"
echo "build_sh_exit=$?"
