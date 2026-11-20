#!/bin/sh
# Disposable G06 probe build. Runs inside a rust container (see harness/run.sh) or natively.
# Writes only under this directory's target/ (AGENTS.md build hygiene: one target/ per checkout).
#   ./build.sh prepare        extract + checksum-verify + patch netdev 0.47.0 into target/patched/
#   ./build.sh <cargo args>   prepare, then cargo build --release --locked <args>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
NETDEV_SHA256=98a4d13f8061600697d721c5fd45262aba533a7d4a7670e7c64fd02d68e4a9fb  # crates.io checksum, netdev 0.47.0
dst=target/patched/netdev-0.47.0
if [ ! -f "$dst/.hm-patched" ]; then
  mkdir -p target/patched
  crate=target/patched/netdev-0.47.0.crate
  [ -f "$crate" ] || curl -fsSL -A heimdall-g06-probe -o "$crate" https://static.crates.io/crates/netdev/netdev-0.47.0.crate
  got=$( (sha256sum "$crate" 2>/dev/null || shasum -a 256 "$crate") | cut -d' ' -f1)
  [ "$got" = "$NETDEV_SHA256" ] || { echo "netdev checksum mismatch: $got" >&2; exit 1; }
  rm -rf "$dst"
  tar xzf "$crate" -C target/patched
  (cd "$dst" && patch -p1 < "$here/patches/netdev-0.47.0-hm-no-route-probe.patch")
  touch "$dst/.hm-patched"
fi
[ "${1:-}" = prepare ] && exit 0
exec cargo build --release --locked "$@"
