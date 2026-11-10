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

test_log="$(mktemp)" || exit 2
trap 'rm -f "${test_log}"' EXIT

# `cargo test`, with its combined output (cargo's `Running` lines are on stderr, the
# harness's `running N tests` lines on stdout) shown and also kept for discovery.
# `--no-fail-fast`: a failing target never hides the targets after it (the step still
# exits nonzero when any test fails).
test_step() {
    cargo test --workspace --locked --no-fail-fast "$@" 2>&1 | tee "${test_log}"
    return "${PIPESTATUS[0]}"
}

# Test discovery (review F09): a test target that runs zero tests is a failure, not
# a pass (a mis-wired `[[test]]` path, a whole file behind a false `cfg`, a module
# that is never declared). Pairs each `Running <target>` line with the next
# `running N test(s)` line; `Doc-tests <crate>` groups are exempt (a crate without
# doc examples is fine). A target with no count line at all is also reported.
# Prints every target with its count.
test_discovery() {
    local report rc
    report="$(awk '
        { gsub(/\033\[[0-9;]*[A-Za-z]/, "") }
        function flush_missing() {
            if (pending != "") { print "missing\t-\t" pending; pending = "" }
        }
        /^[[:space:]]*Running / {
            flush_missing()
            line = $0
            sub(/^[[:space:]]*Running /, "", line)
            # "unittests src/lib.rs (target/debug/deps/heimdall_store-0123abcd)"
            # becomes "heimdall_store (unittests src/lib.rs)".
            name = line
            if (match(line, /\(.*\)$/)) {
                bin = substr(line, RSTART + 1, RLENGTH - 2)
                sub(/^.*\//, "", bin)
                sub(/-[0-9a-f]+$/, "", bin)
                name = bin " (" substr(line, 1, RSTART - 2) ")"
            }
            pending = name; kind = "test"; next
        }
        /^[[:space:]]*Doc-tests / {
            flush_missing()
            line = $0
            sub(/^[[:space:]]*Doc-tests /, "", line)
            pending = line " (doc-tests)"; kind = "doc"; next
        }
        /^running [0-9]+ tests?$/ {
            if (pending != "") { print kind "\t" $2 "\t" pending; pending = "" }
        }
        END { flush_missing() }
    ' "${test_log}")"
    rc=0
    if [ -z "${report}" ]; then
        echo "no test targets found in the cargo test output"
        return 1
    fi
    echo "test targets (count, kind, target):"
    printf '%s\n' "${report}" | awk -F '\t' '{ printf "  %6s  %-7s  %s\n", $2, $1, $3 }'
    local offenders
    offenders="$(printf '%s\n' "${report}" | awk -F '\t' '($1 == "test" && $2 == 0) || $1 == "missing" { print "  " $3 }')"
    if [ -n "${offenders}" ]; then
        echo "test targets that ran zero tests or reported no count:"
        printf '%s\n' "${offenders}"
        rc=1
    fi
    return "${rc}"
}

run_step fmt     cargo fmt --all --check
run_step clippy  cargo clippy --workspace --all-targets --locked -- -D warnings
# Windows-target clippy (gap G16): cfg(windows) paths must pass -D warnings too.
# A missing prerequisite (exit 3) fails the step unless explicitly skipped.
clippy_windows() {
    bash tools/validation/clippy-windows.sh
    local rc=$?
    if [ "${rc}" -eq 3 ] && [ "${HEIMDALL_SKIP_WINDOWS_CLIPPY:-0}" = 1 ]; then
        echo "clippy-windows: SKIPPED by HEIMDALL_SKIP_WINDOWS_CLIPPY=1 (prerequisite missing)"
        return 0
    fi
    return "${rc}"
}
run_step clippy-windows clippy_windows
# M03 (m03-plan U0, section 0.6; ADR-0008 sections 13 D12 and 18): the workspace crate
# graph (no production cycle; app, ipc and registry edge rules; its mutant self-tests) and
# the claim table (every entry's record verified for its platform row, release-profile
# product-store rule for custody claims). Cheap, so before the tests.
run_step crate-graph env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I tools/validation/crate_graph.py
run_step claims-table env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I tools/validation/claims_table.py
run_step test    test_step
run_step test-discovery test_discovery

# Generated-schema consistency (plan section 7.4, M01-T06): the real binary exports the
# public schemas and the configuration schema (gap G18) twice; both runs must be
# byte-identical to each other and to the checked-in schemas/public-api and
# schemas/configuration (a stale file, a missing file and an extra file all fail).
# In-process equivalents live in tests/contracts/schema_export.rs and
# integration_runtime::config_schema_export_matches_checked_in_file.
schema_check() {
    local tmp1 tmp2 rc=0
    tmp1="$(mktemp -d)" && tmp2="$(mktemp -d)" || return 1
    cargo run -q --locked -p heimdall -- schema export --out "${tmp1}/public-api" \
        --config-out "${tmp1}/configuration" >/dev/null || rc=1
    cargo run -q --locked -p heimdall -- schema export --out "${tmp2}/public-api" \
        --config-out "${tmp2}/configuration" >/dev/null || rc=1
    if [ "${rc}" -eq 0 ]; then
        diff -r "${tmp1}" "${tmp2}" || rc=1
        diff -r "${tmp1}/public-api" schemas/public-api || rc=1
        diff -r "${tmp1}/configuration" schemas/configuration || rc=1
    fi
    rm -rf "${tmp1}" "${tmp2}"
    return "${rc}"
}
run_step schema  schema_check

# Release-build test-gate refusal (m03-plan U0b row 16, `release_build_refuses_m03_test_gates`):
# builds the release binary once in the single ./target, then every HEIMDALL_TEST_* variable
# (M01/M02 from testcfg.rs and the four M03 ones) must make it exit 2 before anything else.
# Each invocation is guarded by a hard timeout (see the script header).
run_step release-gate bash tools/validation/release-gate.sh

# Native-harness self-test (reviews B01, B03): the Windows harnesses' scratch
# ownership and exit reporting, against stub ssh/scp/cargo and a fake host tree in
# a mktemp directory. Reaches no host and builds nothing.
run_step native-harness-selftest bash tools/validation/native-harness-selftest.sh

# Evidence-generator self-test (reviews C02, C03): required tests come from the
# committed inventory, nonzero required exits and incomplete logs never verify.
# Writes nothing outside its own temp directories.
run_step evidence-selftest env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I tests/native/m01/test_m01_evidence.py

# Every evidence record validates against record.schema.json (plan §6.6).
# minischema.validate returns its errors instead of raising, so the script checks
# the returned list and self-checks that a bad record is rejected.
run_step evidence-records env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I tools/validation/validate-records.py

echo "== overall: exit ${status}"
exit "${status}"
