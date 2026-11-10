#!/usr/bin/env bash
# Linux-target clippy from a non-Linux build host (M03 wave 1; the Linux twin of
# clippy-windows.sh, which check.sh runs): `cargo clippy --target
# x86_64-unknown-linux-gnu --all-targets -- -D warnings` for the packages named, so
# cfg(target_os = "linux") code (the Secret Service store, logind over zbus, prctl,
# the enrollment step's PR_SET_PDEATHSIG, the ptrace test) type-checks and lints
# before it reaches the devbox. Nothing is linked or run: native Linux tests still run
# on a Linux host (tests/native/m0*/run-linux.sh).
#
#   bash tools/validation/linux-xcheck.sh -p heimdall-enroll [-p heimdall-issuer ...]
#   bash tools/validation/linux-xcheck.sh --workspace
#
# The bundled SQLite and other C code need a C compiler for the target: zig (`zig cc
# -target x86_64-linux-gnu.2.31`, the glibc floor of tests/native/m02/lib.sh's shims)
# through a shim in a mktemp directory removed on exit. Not a check.sh step; run it
# when you change Linux-only code.
#
# Exit codes: clippy's own; 2 for a usage error; 3 when a prerequisite is missing (the
# rustup target x86_64-unknown-linux-gnu or zig), with the missing piece named.
# Uses the single workspace ./target (no CARGO_TARGET_DIR); remove
# target/x86_64-unknown-linux-gnu afterwards to keep it small.

set -u
cd "$(dirname "$0")/../.." || exit 2
unset CARGO_TARGET_DIR
triple=x86_64-unknown-linux-gnu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 -p <package> [-p <package> ...] | --workspace"
    exit 2
fi
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
cat >"$shim/zigcc-linux.sh" <<'SHIM'
#!/usr/bin/env bash
args=()
for a in "$@"; do
  case "$a" in
    --target=*|-m64) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-linux-gnu.2.31 "${args[@]}"
SHIM
printf '#!/usr/bin/env bash\nexec zig ar "$@"\n' >"$shim/zigar.sh"
chmod +x "$shim/zigcc-linux.sh" "$shim/zigar.sh"

CC_x86_64_unknown_linux_gnu="$shim/zigcc-linux.sh" AR_x86_64_unknown_linux_gnu="$shim/zigar.sh" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$shim/zigcc-linux.sh" \
    cargo clippy --target "$triple" --all-targets --locked "$@" -- -D warnings
