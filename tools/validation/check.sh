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

# Generated-schema consistency (plan §7.4) is enabled by M01-T06 once
# `heimdall schema export` is implemented:
#   run_step schema bash -c 'cargo run -q -p heimdall -- schema export --out "$tmp" && diff -r "$tmp" schemas/public-api'

echo "== overall: exit ${status}"
exit "${status}"
