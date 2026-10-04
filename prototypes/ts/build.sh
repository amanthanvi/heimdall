#!/bin/sh
# Build heimdall-proto (TypeScript + OpenTUI G02 prototype) as standalone executables.
# POSIX sh; run from anywhere. Requires Bun (pinned in REPORT.md). Cross-target builds
# download the target Bun runtime from the npm registry into Bun's cache on first use.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 1

TARGETS=${TARGETS:-"darwin-arm64 linux-x64 linux-arm64 windows-x64"}
DIST="$HERE/dist"
rm -rf "$DIST"
mkdir -p "$DIST/.status"

# Install every platform's optional native package so each target can embed its own
# OpenTUI library; --frozen-lockfile fails if bun.lock would change.
if ! bun install --frozen-lockfile --os='*' --cpu='*' >"$DIST/.status/install.log" 2>&1; then
  echo "build.sh: bun install failed; see $DIST/.status/install.log" >&2
  exit 1
fi

for t in $TARGETS; do
  exe=heimdall-proto
  case "$t" in windows-*) exe=heimdall-proto.exe ;; esac
  # OpenTUI native library, shipped as a sidecar (contract ruling K11) instead of being
  # embedded: an embedded library is extracted to $TMPDIR at runtime and reused there
  # without content verification. The executable loads it only from
  # <its own real directory>/<pkg>/<lib> (src/cli.ts pinNativeAssets).
  case "$t" in
    darwin-*) pkg="@opentui/core-$t"; lib=libopentui.dylib ;;
    linux-*) pkg="@opentui/core-$t"; lib=libopentui.so ;;
    windows-*) pkg="@opentui/core-win32-${t#windows-}"; lib=opentui.dll ;;
  esac
  mkdir -p "$DIST/$t"
  # --no-compile-autoload-*: a compiled Bun binary otherwise reads .env and bunfig.toml
  # from the working directory at startup. --external keeps every OpenTUI native
  # package out of the executable.
  if bun build --compile --target="bun-$t" \
      --no-compile-autoload-dotenv --no-compile-autoload-bunfig \
      --external '@opentui/core-*' \
      src/main.ts --outfile "$DIST/$t/$exe" >"$DIST/.status/$t.log" 2>&1 \
    && mkdir -p "$DIST/$t/$pkg" \
    && cp "node_modules/$pkg/$lib" "$DIST/$t/$pkg/$lib" 2>>"$DIST/.status/$t.log"; then
    echo "ok $t/$exe $t/$pkg/$lib" >"$DIST/.status/$t.result"
  else
    echo "fail $t/$exe" >"$DIST/.status/$t.result"
    rm -rf "$DIST/$t"
  fi
done

bun scripts/manifest.ts "$DIST" $TARGETS
status=$?
rm -rf "$DIST/.status"
exit $status
