#!/bin/sh
set -u
export PATH=/opt/zig:/usr/local/cargo/bin:$PATH
curl -fsSL -o /tmp/zig.tar.xz https://ziglang.org/download/0.16.0/zig-aarch64-linux-0.16.0.tar.xz && mkdir -p /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; echo "zig fetch rc=$? version=$(zig version 2>&1)"
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu >/out/rustup.log 2>&1; echo "rustup target add rc=$?"
cargo install --locked cargo-zigbuild --version 0.23.4 >/out/zigbuild-install.log 2>&1; echo "cargo-zigbuild install rc=$?"
cp -R /src/prototypes/rust /work && cd /work && rustc --version && sh build.sh >/out/build.log 2>&1; echo "build.sh rc=$?"
cp dist/manifest.json /out/manifest.json; cp dist/logs/*.log /out/ 2>/dev/null
mkdir -p /out/bin && cp dist/linux-arm64/heimdall-proto /out/bin/linux-arm64 && cp dist/linux-x64/heimdall-proto /out/bin/linux-x64 && cp dist/windows-x64/heimdall-proto.exe /out/bin/windows-x64.exe; cp dist/manifest.json /out/manifest-run2.json
