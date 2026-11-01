#!/usr/bin/env bash
# Windows-target clippy for the workspace (gap G16): `cargo clippy --target
# x86_64-pc-windows-gnu --workspace --all-targets -- -D warnings`, so cfg(windows)
# code paths (dead imports, unused constants) fail validation on any build host.
# The bundled SQLite needs a C compiler for the target: zig (`zig cc -target
# x86_64-windows-gnu`) through a shim in a mktemp directory removed on exit (same
# shim as tests/native/m01/run-windows.sh). Nothing is linked or run.
#
# Exit codes: clippy's own; 3 when a prerequisite is missing (the rustup target
# x86_64-pc-windows-gnu or zig), with the missing piece named. check.sh treats 3 as
# a failure unless HEIMDALL_SKIP_WINDOWS_CLIPPY=1 is set explicitly.
# Uses the single workspace ./target (no CARGO_TARGET_DIR); remove
# target/x86_64-pc-windows-gnu afterwards to keep it small.

set -u
cd "$(dirname "$0")/../.." || exit 2
unset CARGO_TARGET_DIR
triple=x86_64-pc-windows-gnu

if ! rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
    echo "missing prerequisite: rustup target $triple (rustup target add $triple)"
    exit 3
fi
if ! command -v zig >/dev/null 2>&1; then
    echo "missing prerequisite: zig (C compiler for the bundled SQLite on $triple)"
    exit 3
fi

shim=$(mktemp -d) || exit 2
trap 'rm -rf "$shim"' EXIT
cat >"$shim/zigcc-win-cc.sh" <<'SHIM'
#!/usr/bin/env bash
args=()
for a in "$@"; do
  case "$a" in
    --target=*|-m64|-mthreads) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-windows-gnu "${args[@]}"
SHIM
printf '#!/usr/bin/env bash\nexec zig ar "$@"\n' >"$shim/zigar.sh"
chmod +x "$shim/zigcc-win-cc.sh" "$shim/zigar.sh"

CC_x86_64_pc_windows_gnu="$shim/zigcc-win-cc.sh" AR_x86_64_pc_windows_gnu="$shim/zigar.sh" \
    cargo clippy --target "$triple" --workspace --all-targets --locked -- -D warnings
