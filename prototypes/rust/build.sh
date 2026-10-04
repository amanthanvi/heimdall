#!/bin/sh
# Build heimdall-proto (Rust + Ratatui G02 prototype) for the contract §7 targets and
# write dist/manifest.json. POSIX sh; run from anywhere.
#
# Targets and toolchains:
#   darwin-arm64  aarch64-apple-darwin        native cargo (macOS host)
#   linux-x64     x86_64-unknown-linux-musl   cargo-zigbuild (zig as linker), static
#   linux-arm64   aarch64-unknown-linux-musl  cargo-zigbuild (zig as linker), static
#   windows-x64   x86_64-pc-windows-gnu       cargo-zigbuild (zig as mingw linker)
#
# cargo-zigbuild is looked up as $CARGO_ZIGBUILD, then target/tools/bin/cargo-zigbuild
# (installed with: cargo install --locked cargo-zigbuild --version 0.23.4 --root target/tools),
# then PATH. Nothing is downloaded by this script. A target that fails is recorded in the
# manifest with built:false and the real error; the script exits 0 if at least one
# target was built, 1 otherwise. python3 is used only to write manifest.json and the
# notices file.
#
# Round 2 release hygiene (round-1 review):
#   * --remap-path-prefix for the cargo registry, the toolchain's rust-src, this checkout
#     and the target dir, so no artifact embeds the builder's home path (checked below:
#     the build fails if one does);
#   * darwin: -oso_prefix=<target dir> (the LC_UUID no longer depends on the checkout
#     path) and an ad-hoc signature with the hardened runtime (dyld ignores DYLD_*);
#   * windows: /Brepro (PE TimeDateStamp is a content hash, not the wall clock);
#   * the toolchain must be rustc $PINNED_RUSTC (no rust-toolchain.toml: that would make
#     rustup download a separately named toolchain); a different rustc is refused;
#   * dist/THIRD-PARTY-NOTICES.txt (tools/gen_notices.py) ships the license texts.
set -u

PINNED_RUSTC="1.99.0"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$HERE" || exit 1
DIST="$HERE/dist"
rm -rf "$DIST"
mkdir -p "$DIST/logs"
RESULTS="$DIST/logs/results.tsv"
: > "$RESULTS"

RUSTC_V=$(rustc --version 2>/dev/null | awk '{print $2}')
if [ "$RUSTC_V" != "$PINNED_RUSTC" ]; then
  echo "build.sh: rustc $RUSTC_V found, $PINNED_RUSTC required (pinned toolchain)" >&2
  exit 1
fi
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
SYSROOT=$(rustc --print sysroot)
RUSTC_HASH=$(rustc -vV | sed -n 's/^commit-hash: //p')
TARGET_DIR="$HERE/target"
REMAP="--remap-path-prefix=$CARGO_HOME_DIR/registry/src=/cargo/registry/src --remap-path-prefix=$CARGO_HOME_DIR/git/checkouts=/cargo/git/checkouts --remap-path-prefix=$SYSROOT/lib/rustlib/src/rust=/rustc/$RUSTC_HASH --remap-path-prefix=$TARGET_DIR=/target --remap-path-prefix=$HERE=/heimdall-proto"

ZB="${CARGO_ZIGBUILD:-}"
if [ -z "$ZB" ]; then
  if [ -x "$HERE/target/tools/bin/cargo-zigbuild" ]; then
    ZB="$HERE/target/tools/bin/cargo-zigbuild"
  elif command -v cargo-zigbuild >/dev/null 2>&1; then
    ZB=$(command -v cargo-zigbuild)
  fi
fi

# build_one <name> <rust-triple> <native|zig> <exe-suffix>
build_one() {
  name=$1; triple=$2; method=$3; suffix=$4
  log="$DIST/logs/$name.log"
  echo "== $name ($triple, $method)" >&2
  start=$(date +%s)
  case $triple in
    *-apple-darwin) flags="$REMAP -C link-arg=-Wl,-oso_prefix,$TARGET_DIR/" ;;
    *-windows-gnu) flags="$REMAP -C link-arg=-Wl,/Brepro" ;;
    *) flags="$REMAP" ;;
  esac
  case $method in
    native)
      RUSTFLAGS="$flags" cargo build --release --locked --target "$triple" >"$log" 2>&1
      rc=$?
      if [ "$rc" -eq 0 ]; then
        # Hardened runtime (ad-hoc): dyld ignores DYLD_* variables for this binary.
        codesign --force --sign - --options runtime "$HERE/target/$triple/release/heimdall-proto$suffix" >>"$log" 2>&1
        rc=$?
      fi ;;
    zig)
      if [ -z "$ZB" ]; then
        echo "cargo-zigbuild not found (set CARGO_ZIGBUILD or install into target/tools)" >"$log"
        rc=127
      else
        RUSTFLAGS="$flags" "$ZB" zigbuild --release --locked --target "$triple" >"$log" 2>&1
        rc=$?
      fi ;;
  esac
  src="$HERE/target/$triple/release/heimdall-proto$suffix"
  # No artifact may embed the builder's home directory (round-1 review).
  if [ "$rc" -eq 0 ] && [ -f "$src" ] && LC_ALL=C grep -q -F "$HOME" "$src"; then
    echo "artifact embeds the builder home path" >>"$log"
    rc=86
  fi
  end=$(date +%s)
  if [ "$rc" -eq 0 ] && [ -f "$src" ]; then
    mkdir -p "$DIST/$name"
    cp "$src" "$DIST/$name/heimdall-proto$suffix"
    printf '%s\t%s\t1\t%s\t%s\n' "$name" "$name/heimdall-proto$suffix" "$rc" "$((end - start))" >>"$RESULTS"
    echo "   built in $((end - start))s" >&2
  else
    printf '%s\t%s\t0\t%s\t%s\n' "$name" "$name/heimdall-proto$suffix" "$rc" "$((end - start))" >>"$RESULTS"
    echo "   FAILED (exit $rc); see $log" >&2
  fi
}

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) build_one darwin-arm64 aarch64-apple-darwin native "" ;;
  *) printf 'darwin-arm64\tdarwin-arm64/heimdall-proto\t0\thost-not-macos-arm64\t0\n' >>"$RESULTS"
     echo "darwin-arm64 requires a macOS arm64 host (Apple SDK)" >"$DIST/logs/darwin-arm64.log" ;;
esac
build_one linux-x64 x86_64-unknown-linux-musl zig ""
build_one linux-arm64 aarch64-unknown-linux-musl zig ""
build_one windows-x64 x86_64-pc-windows-gnu zig ".exe"

python3 tools/gen_notices.py "$DIST/THIRD-PARTY-NOTICES.txt" >"$DIST/logs/notices.log" 2>&1 \
  || echo "notices generation failed; see dist/logs/notices.log" >&2

python3 - "$DIST" "$RUSTC_V" <<'PY'
import hashlib, json, os, sys
dist = sys.argv[1]
targets = []
for line in open(os.path.join(dist, "logs", "results.tsv"), encoding="utf-8"):
    name, path, built, rc, secs = line.rstrip("\n").split("\t")
    entry = {"target": name, "path": path, "bytes": None, "sha256": None,
             "built": built == "1", "error": None, "build_seconds": int(secs)}
    full = os.path.join(dist, path)
    if entry["built"]:
        data = open(full, "rb").read()
        entry["bytes"] = len(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
    else:
        log = os.path.join(dist, "logs", name + ".log")
        text = open(log, encoding="utf-8", errors="replace").read() if os.path.exists(log) else ""
        lines = [l for l in text.splitlines() if l.strip()]
        errs = [l for l in lines if l.lstrip().startswith(("error", "Error", "ld.lld", "zig", "note:"))]
        entry["error"] = f"exit {rc}: " + " | ".join((errs or lines)[-12:])
    targets.append(entry)
manifest = {"candidate": "rust", "rustc": sys.argv[2], "targets": targets}
notices = os.path.join(dist, "THIRD-PARTY-NOTICES.txt")
if os.path.exists(notices):
    data = open(notices, "rb").read()
    # Not a K11 sidecar: documentation shared by all targets, never loaded at runtime.
    manifest["notices"] = {"path": "THIRD-PARTY-NOTICES.txt", "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}
with open(os.path.join(dist, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=1, ensure_ascii=False)
    f.write("\n")
print(json.dumps({t["target"]: t["built"] for t in targets}))
sys.exit(0 if any(t["built"] for t in targets) else 1)
PY
