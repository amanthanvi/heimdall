#!/usr/bin/env bash
# Heimdall workspace validation (plan §7.4; M01-T00).
# Runs from any directory; uses the pinned toolchain (rust-toolchain.toml) and the
# single workspace target dir ./target (AGENTS.md build hygiene).
# Exit code: 0 only when every step passes. Each step's real exit code is printed.

set -u
cd "$(dirname "$0")/../.." || exit 2

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
unset CARGO_TARGET_DIR

status=0
run_step() {
    local name="$1"; shift
    echo "== ${name}: $*"
    "$@"
    local rc=$?
    echo "== ${name}: exit ${rc}"
    if [ "${rc}" -ne 0 ]; then status=1; fi
}

run_step fmt     cargo fmt --all --check
run_step clippy  cargo clippy --workspace --all-targets --locked -- -D warnings
run_step test    cargo test --workspace --locked

# Generated-schema consistency (plan section 7.4, M01-T06): the real binary exports the
# public schemas twice; both runs must be byte-identical to each other and to the
# checked-in schemas/public-api (a stale file, a missing file and an extra file all
# fail). In-process equivalents live in tests/contracts/schema_export.rs.
schema_check() {
    local tmp1 tmp2 rc=0
    tmp1="$(mktemp -d)" && tmp2="$(mktemp -d)" || return 1
    cargo run -q --locked -p heimdall -- schema export --out "${tmp1}" >/dev/null || rc=1
    cargo run -q --locked -p heimdall -- schema export --out "${tmp2}" >/dev/null || rc=1
    if [ "${rc}" -eq 0 ]; then
        diff -r "${tmp1}" "${tmp2}" || rc=1
        diff -r "${tmp1}" schemas/public-api || rc=1
    fi
    rm -rf "${tmp1}" "${tmp2}"
    return "${rc}"
}
run_step schema  schema_check

echo "== overall: exit ${status}"
exit "${status}"
