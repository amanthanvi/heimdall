#!/usr/bin/env bash
# M02-U11: regenerate tests/native/m02/required-inventory.json for the tree as it is now
# (run it at the build commit, right before the native runs; the inventory records the
# digest of the sources it was generated from, and m02-evidence.py refuses any other).
#
# Usage (from anywhere): tests/native/m02/refresh-inventory.sh
#   ⟨M06 W5⟩ HM_FEATURE (a Cargo feature; tests/native/m06/refresh-inventory.sh sets `iroh`):
#   the Linux cross-build also builds the test targets that require it (lib.sh
#   m02_feature_build) and they are scanned with the rest. The Windows scan is a
#   x86_64-pc-windows-gnu cross-build, which is not attempted with the feature (the Windows
#   row builds it natively with msvc on the PC): those targets are absent from the Windows
#   scan, so the inventory treats their tests as applying there, and a test `#[cfg]` removes
#   on Windows needs a case-index platform_only entry with its rationale.
#   ⟨M06 W5c⟩ HM_FEATURE_UNIT (comma-separated package names, with HM_FEATURE): the Linux
#   cross-build also builds those packages' unit tests with the feature, and that build is the
#   one scanned as `<crate>-unit`. The Windows scan's default-feature build of the same unit
#   target is left out of its scan, as the feature targets are: scanned, it would report every
#   test that exists only under the feature as absent on Windows.
#   ⟨M03 wave 6⟩ HM_HARNESS_DIR (the directory holding runs.json and the generator) and
#   HM_EVIDENCE (the generator's name there) select another milestone's inventory;
#   tests/native/m03/refresh-inventory.sh sets them. Default: this directory, m02-evidence.py.
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

hdir=${HM_HARNESS_DIR:-$here}
gen="$hdir/${HM_EVIDENCE:-m02-evidence.py}"
[ -f "$gen" ] && [ -f "$hdir/runs.json" ] || { echo "no generator or runs.json in the harness directory" >&2; exit 2; }
shim=$(mktemp -d)
trap 'rm -rf "$shim"' EXIT
m02_write_shims "$(m02_shim_dir "$repo")"

python3 -I "$gen" --list-targets "$shim/listed"
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
    if [ -n "${HM_FEATURE:-}" ] && [ "$plat" = linux ]; then
        m02_artifacts "$shim" || true
        M02_FEATURE_SKIP=${HM_SKIP_TARGETS:-} M02_FEATURE_UNIT=${HM_FEATURE_UNIT:-} m02_feature_build "$triple" "$shim" "$shim/build-$plat.log" "$HM_FEATURE" || {
            echo "the $HM_FEATURE-feature cross-build for $triple failed or is incomplete:" >&2
            cat "$shim/feature-blocked.tsv" >&2
            exit 1
        }
        cat "$shim/feature.json" >>"$shim/build.json"
    elif [ -n "${HM_FEATURE:-}" ] && [ -n "${HM_FEATURE_UNIT:-}" ]; then
        case "$HM_FEATURE_UNIT" in *[!a-z0-9,-]*) echo "bad HM_FEATURE_UNIT" >&2; exit 2 ;; esac
        jq -c --arg units "$(printf '%s' "$HM_FEATURE_UNIT" | tr '-' '_')" '
            select(((.reason == "compiler-artifact" and .profile.test == true and (.target.kind | index("lib")) != null
                     and (($units | split(",")) | index(.target.name)) != null)) | not)' \
            "$shim/build.json" >"$shim/build.kept" && mv -f -- "$shim/build.kept" "$shim/build.json"
    fi
    python3 -I "$here/platform-tests.py" --build-json "$shim/build.json" --listed-from "$shim/listed" \
        --out "$shim/scan-$plat.json"
    scans+=(--scan "$plat=$shim/scan-$plat.json")
done
python3 -I "$gen" --config "$hdir/runs.json" --generate-inventory "${scans[@]}"
