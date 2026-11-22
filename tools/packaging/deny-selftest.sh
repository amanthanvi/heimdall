#!/usr/bin/env bash
# Known-good and known-bad checks of deny.toml (m08-plan U4a; ADR-0014 section 4.6).
#
# Usage: bash tools/packaging/deny-selftest.sh
# Exit code: 0 when the real workspace and the permissive fixture pass and the copyleft
# fixture is refused for its licence; 1 otherwise; 2 when the pinned cargo-deny is missing.
#
# The fixtures are two tiny workspaces under tools/packaging/deny-fixtures/ (path crates
# only, so nothing is fetched). NOT COVERED: the `[sources]` rules. A git or foreign-registry
# dependency cannot be resolved offline, so no fixture exercises them; they are checked only
# against the real workspace.
set -u
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"
deny="$repo/target/tools/bin/cargo-deny"
want=0.22.0
if [ ! -x "$deny" ] || [ "$("$deny" --version | awk '{print $NF}')" != "$want" ]; then
    echo "deny-selftest: the pinned tool is missing: cargo install --locked --version =$want --root target/tools cargo-deny" >&2
    exit 2
fi
fix=tools/packaging/deny-fixtures
bad=0
run() { # NAME EXPECTED_EXIT MANIFEST [GREP]
    local out code
    out=$("$deny" --manifest-path "$3" --offline --config "$repo/deny.toml" check licenses sources bans 2>&1)
    code=$?
    if { [ "$2" = 0 ] && [ "$code" = 0 ]; } || { [ "$2" != 0 ] && [ "$code" != 0 ] && echo "$out" | grep -q "${4:-.}"; }; then
        echo "ok   $1 (exit $code)"
    else
        echo "FAIL $1 (exit $code)"; bad=1
    fi
}
run "the real workspace passes" 0 Cargo.toml
run "a permissive fixture passes" 0 "$fix/permissive/Cargo.toml"
run "a copyleft crate is refused for its licence" 1 "$fix/copyleft/Cargo.toml" "GPL-3.0"
# cargo writes a lock file beside each fixture manifest; remove exactly those two.
rm -f -- "$fix/permissive/Cargo.lock" "$fix/copyleft/Cargo.lock"
echo "deny-selftest: $([ $bad = 0 ] && echo PASS || echo FAIL)"
exit $bad
