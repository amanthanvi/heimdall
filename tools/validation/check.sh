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
# M08 U1b (m08-plan U1b; for M09-T03's review): every module that allows `unsafe` is listed in
# docs/security/unsafe-inventory.md with its reason, and nothing else is. Cheap.
run_step unsafe-inventory env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I tools/validation/unsafe_inventory.py --check
# M06 (m06-plan U0; ADR-0012 sections 1 and 13): the feature-gated iroh build and the vendored
# netdev patch (third_party/netdev-0.47.0, [patch.crates-io]) must keep compiling, so neither
# rots between the milestones that exercise them. Compile check only: nothing is bound.
# ⟨M06 W1⟩ The iroh feature's own tests (loopback only, in process) and its clippy, which the
# workspace-wide steps above do not see because the feature is off by default.
iroh_check() {
    cargo check --locked -p heimdall-transport-iroh --features iroh &&
        cargo clippy --locked -p heimdall-transport-iroh --features iroh --all-targets -- -D warnings &&
        cargo test --locked -p heimdall-transport-iroh --features iroh
}
run_step iroh-check iroh_check
# RustSec audit of the whole Cargo.lock (ADR-0012 section 1 item 4; M06-W0-R01/R04 and the
# orchestrator rulings of 2026-11-21): tools/validation/audit_gate.py runs its self-tests,
# then cargo-audit 0.22.1 with the checked-in .cargo/audit.toml and an empty scratch
# CARGO_HOME (no ambient configuration). Any vulnerability fails unless listed in
# tools/validation/audit-ignore.txt; a missing or unreadable database, a tool error or an
# invalid report fails closed; a missing tool fails (exit 3) unless HM_SKIP_AUDIT=1, which
# prints "SKIPPED (not merge evidence)". The database fetch needs the network.
audit_step() {
    PYTHONDONTWRITEBYTECODE=1 python3 -I tools/validation/audit_gate.py
}
run_step audit audit_step
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
        --config-out "${tmp1}/configuration" --project-out "${tmp1}/project" >/dev/null || rc=1
    cargo run -q --locked -p heimdall -- schema export --out "${tmp2}/public-api" \
        --config-out "${tmp2}/configuration" --project-out "${tmp2}/project" >/dev/null || rc=1
    if [ "${rc}" -eq 0 ]; then
        diff -r "${tmp1}" "${tmp2}" || rc=1
        diff -r "${tmp1}/public-api" schemas/public-api || rc=1
        diff -r "${tmp1}/configuration" schemas/configuration || rc=1
        # ⟨rev5⟩ ADR-0006 §17: the trusted-work file formats.
        diff -r "${tmp1}/project" schemas/project || rc=1
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

# ⟨rev7⟩ U0 (ADR-0013 §1.3): the replay corpus driver (tests/contracts/replay_journey.py)
# refuses a store dump that holds a home path, the account's user name, a canary or key armor.
# Self-test only: it calls the refusal on built strings and runs no binary.
run_step replay-driver-selftest env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I -B -m unittest discover -s tests/contracts -p "test_replay_journey.py"

# ⟨M07 U4⟩ m07-plan §5: the optional agent skill names only commands the CLI has (the
# debug binary the test step built answers `<path> --help`, in a scratch home), and never
# an approval, a boundary escape or real data. Self-checks against a known-bad skill first.
run_step skill-lint env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I -B tools/validation/skill_lint.py --heimdall target/debug/heimdall

# ⟨M07 U5a⟩ m07-plan §4: the reference wrapper's own tests (Python standard library; a fake
# server on an owner-only Unix socket in a temp directory), plus its real-binary smoke against
# the debug binary the test step built (one scratch root holding HOME, HEIMDALL_HOME and
# HEIMDALL_TEST_SSH_HOME, checked before launch; the runtime it starts is stopped and the
# root removed by the test).
run_step wrapper-tests env PYTHONDONTWRITEBYTECODE=1 \
    HEIMDALL_WRAPPER_SMOKE_BIN="$(pwd)/target/debug/heimdall" \
    python3 -I -B -m unittest discover -s examples/reference-wrapper/tests

# ⟨M07 U5h⟩ m07-plan §5a: harness H1's own tests (Python standard library; a stub `heimdall`
# in a temp directory), plus its discovery smoke against the debug binary in a scratch home.
run_step harness-h1-tests env PYTHONDONTWRITEBYTECODE=1 \
    HEIMDALL_HARNESS_SMOKE_BIN="$(pwd)/target/debug/heimdall" \
    python3 -I -B -m unittest discover -s examples/harnesses/cli/tests

# ⟨M07 U5h⟩ m07-plan §5a: harness H2's own tests (Python standard library; a stub `heimdall`
# in a temp directory), plus its discovery smoke against the debug binary in a scratch home.
run_step harness-h2-tests env PYTHONDONTWRITEBYTECODE=1 \
    HEIMDALL_HARNESS_SMOKE_BIN="$(pwd)/target/debug/heimdall" \
    python3 -I -B -m unittest discover -s examples/harnesses/goal-loop/tests

# ⟨M07 U6⟩ m07-plan U6: the user-facing adapter page claims nothing beyond the claims table
# and the compatibility matrix (self-checks against over-claiming pages first).
run_step adapter-page env PYTHONDONTWRITEBYTECODE=1 \
    python3 -I -B tools/validation/adapter_page_check.py

echo "== overall: exit ${status}"
exit "${status}"
