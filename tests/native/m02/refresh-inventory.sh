#!/usr/bin/env bash
# M02-U11: regenerate tests/native/m02/required-inventory.json for the tree as it is now
# (run it at the build commit, right before the native runs; the inventory records the
# digest of the sources it was generated from, and m02-evidence.py refuses any other).
#
# Usage (from anywhere): tests/native/m02/refresh-inventory.sh
#
# Steps, all on the build host, nothing run on a target:
#   1. `m02-evidence.py --list-targets`: the test names the build host's sources define,
#      one file per target (`cargo test -- --list`);
#   2. a cross-build of every test binary for x86_64-unknown-linux-gnu and for
#      x86_64-pc-windows-gnu, exactly as run-linux.sh and run-windows.sh build them;
#   3. `platform-tests.py`: which of those tests each cross-built binary contains (its own
#      symbols; `#[cfg]` removes the rest) and which platform-only tests it adds;
#   4. `m02-evidence.py --generate-inventory --scan linux=... --scan windows=...`:
#      resolves every pattern of case-index.json, refuses one that resolves to nothing,
#      and writes required-inventory.json with `platform_only` and `platform_extra`.
# Build output stays in the workspace ./target (no CARGO_TARGET_DIR); the shims and scans
# live in a mktemp directory removed on exit. Afterwards remove target/x86_64-* to keep
# the shared target small (AGENTS.md).

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/lib.sh"
unset CARGO_TARGET_DIR
cd "$repo"

shim=$(mktemp -d)
trap 'rm -rf "$shim"' EXIT
m02_write_shims "$shim"

python3 -I "$here/m02-evidence.py" --list-targets "$shim/listed"
scans=()
for spec in linux:x86_64-unknown-linux-gnu windows:x86_64-pc-windows-gnu; do
    plat=${spec%%:*}
    triple=${spec#*:}
    echo "== cross-build for $triple"
    m02_cargo_build "$triple" "$shim" "$shim/build-$plat.log" || {
        echo "cross-build for $triple failed (last lines of its log, paths unredacted):" >&2
        tail -n 20 "$shim/build-$plat.log" >&2
        exit 1
    }
    python3 -I "$here/platform-tests.py" --build-json "$shim/build.json" --listed-from "$shim/listed" \
        --out "$shim/scan-$plat.json"
    scans+=(--scan "$plat=$shim/scan-$plat.json")
done
python3 -I "$here/m02-evidence.py" --config "$here/runs.json" --generate-inventory "${scans[@]}"
