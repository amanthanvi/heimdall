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
test_step() {
    cargo test --workspace --locked "$@" 2>&1 | tee "${test_log}"
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
run_step test    test_step
run_step test-discovery test_discovery

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
