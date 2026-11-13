#!/usr/bin/env bash
# Release-build test-gate refusal check (m03-plan U0b row 16; test name
# `release_build_refuses_m03_test_gates`; ADR-0008 section 18 "Revision 3", plan section 17.4 item 12).
#
# Usage: bash tools/validation/release-gate.sh        (from any directory; check.sh calls it)
# Exit code: 0 only when every probe below passes; 1 on any failed probe or a failed build;
# 2 when the script cannot set up (no testcfg.rs, no python3, no scratch).
#
# Builds the release binary once (`cargo build --release --locked -p heimdall`, the single
# ./target dir), then runs it once per HEIMDALL_TEST_* variable and asserts that the build
# refuses with exit code 2 before anything else happens:
#   * the M01/M02 variables are read from crates/heimdall/src/testcfg.rs (`ALL_ENV`:
#     `heimdall service run`; `LAUNCH_ENV`: `heimdall run -- true` and `heimdall connect x`);
#   * the M03 variables (`HEIMDALL_TEST_SECRET_STORE=scratch`, `HEIMDALL_TEST_KEY_SEED=00`,
#     `HEIMDALL_TEST_SESSION_LOCK=<abs scratch path>`, `HEIMDALL_TEST_SCRIPT_PAUSE_DIR=<abs
#     scratch dir>`) run through `heimdall service run`, the command whose
#     `testcfg::requested()` gate they join.
#   * ⟨ADR-0008 section 17.25 item 7 (b)⟩ the product-file selector
#     (`HEIMDALL_TEST_SECRET_STORE=product-file:<abs scratch path>`) through `service run`,
#     `issuer status` and `issuer init --backup-out <scratch>` (the CLI's own store selection).
# A probe passes only when ALL hold: exit code 2; the output carries the fixed refusal text
# (a clap usage error is also exit 2 and must not count); the fresh scratch HEIMDALL_HOME is
# still empty (nothing else happened); the process ended by itself.
#
# Every invocation has a hard 10 s timeout. A release binary that does not refuse a variable
# would start a real service (or a client) in the scratch home and hang: the script kills
# exactly the PID it started (TERM, then KILL after 2 s) and reports the probe as failed
# ("NOT REFUSED"). The invocation runs under `env -i` so no inherited HEIMDALL_* variable can
# change the outcome, with HOME and HEIMDALL_HOME in scratch. Scratch dirs and files are
# removed by exact path on exit. No --target-dir, no CARGO_TARGET_DIR.

set -u
cd "$(dirname "$0")/../.." || exit 2
unset CARGO_TARGET_DIR

TIMEOUT_TENTHS=100        # 10 s
KILL_GRACE_TENTHS=20      # 2 s between TERM and KILL
TESTCFG=crates/heimdall/src/testcfg.rs
BIN=target/release/heimdall

scratch_dirs=()
scratch_files=()
child=""
status=0

cleanup() {
    if [ -n "${child}" ] && kill -0 "${child}" 2>/dev/null; then
        kill -KILL "${child}" 2>/dev/null
    fi
    local d f
    for f in "${scratch_files[@]+"${scratch_files[@]}"}"; do rm -f "${f}"; done
    for d in "${scratch_dirs[@]+"${scratch_dirs[@]}"}"; do rm -rf "${d}"; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Creates a scratch directory (tracked for removal) and sets ${new_dir_path}. Not called in
# a subshell, so the tracking array is kept.
new_dir() {
    new_dir_path="$(mktemp -d)" || { echo "release-gate: cannot create a scratch directory"; exit 2; }
    scratch_dirs+=("${new_dir_path}")
}

# Variables of the M01/M02 test configuration, from testcfg.rs ("all NAME" / "launch NAME").
read_vars() {
    PYTHONDONTWRITEBYTECODE=1 python3 -I - "${TESTCFG}" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
text = re.sub(r"//[^\n]*", "", text)
consts = dict(re.findall(r'pub const (\w+): &str = "(HEIMDALL_TEST_\w+)";', text))
for kind, arr in (("all", "ALL_ENV"), ("launch", "LAUNCH_ENV")):
    m = re.search(r"pub const %s: \[&str; \d+\] = \[(.*?)\];" % arr, text, re.S)
    if not m:
        sys.exit("cannot find %s in testcfg.rs" % arr)
    for ident in re.findall(r"\w+", m.group(1)):
        if ident not in consts:
            sys.exit("%s names %s, which is not a HEIMDALL_TEST_* constant" % (arr, ident))
        print(kind, consts[ident])
PY
}

# Run "$@" in the background with stdout and stderr to $1; sets g_rc and g_hung.
guarded_run() {
    local out="$1" i
    shift
    "$@" >"${out}" 2>&1 </dev/null &
    child=$!
    i=0
    while kill -0 "${child}" 2>/dev/null && [ "${i}" -lt "${TIMEOUT_TENTHS}" ]; do
        sleep 0.1
        i=$((i + 1))
    done
    g_hung=0
    if kill -0 "${child}" 2>/dev/null; then
        g_hung=1
        kill -TERM "${child}" 2>/dev/null
        i=0
        while kill -0 "${child}" 2>/dev/null && [ "${i}" -lt "${KILL_GRACE_TENTHS}" ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if kill -0 "${child}" 2>/dev/null; then kill -KILL "${child}" 2>/dev/null; fi
    fi
    wait "${child}"
    g_rc=$?
    child=""
}

vals=""   # scratch directory for the absolute-path values

# The value a probe sets for a variable (a path value points into ${vals}).
value_for() {
    case "$1" in
        HEIMDALL_TEST_ADAPTER) printf 'prepare' ;;
        HEIMDALL_TEST_LEDGER | HEIMDALL_TEST_HANG_AFTER_EFFECT) printf '%s/%s' "${vals}" "$1" ;;
        HEIMDALL_TEST_SLOW_PREPARE_MS) printf '1' ;;
        HEIMDALL_TEST_TIME_SYNC) printf 'unknown' ;;
        HEIMDALL_TEST_STAGE_FAIL) printf 'before:prepare:INTERNAL_ERROR' ;;
        HEIMDALL_TEST_CLOCK_OFFSET_S) printf '0' ;;
        HEIMDALL_TEST_PRE_EXEC_PAUSE | HEIMDALL_TEST_PRE_CHECK_PAUSE) printf '%s/%s' "${vals}" "$1" ;;
        HEIMDALL_TEST_FORCE_EXEC_FAILURE) printf '1' ;;
        HEIMDALL_TEST_SSH_HOME) printf '%s/account' "${vals}" ;;
        HEIMDALL_TEST_SECRET_STORE) printf 'scratch' ;;
        HEIMDALL_TEST_KEY_SEED) printf '00' ;;
        HEIMDALL_TEST_SESSION_LOCK) printf '%s/session-lock-state' "${vals}" ;;
        HEIMDALL_TEST_SCRIPT_PAUSE_DIR) printf '%s/script-pause' "${vals}" ;;
        *) printf '1' ;;   # a variable this script does not know yet: any value must be refused
    esac
}

probe_count=0
fail_count=0

# probe VARIABLE LABEL ARGS...   (runs: heimdall ARGS... with VARIABLE set)
probe() {
    local var="$1" label="$2" val home out reason verdict
    shift 2
    val="${PROBE_VALUE:-$(value_for "${var}")}"
    new_dir
    home="${new_dir_path}"
    out="$(mktemp)" || { echo "release-gate: cannot create a scratch file"; exit 2; }
    scratch_files+=("${out}")
    guarded_run "${out}" env -i PATH="${PATH}" HOME="${home}" HEIMDALL_HOME="${home}" \
        "${var}=${val}" "${BIN}" "$@"
    reason=""
    if [ "${g_hung}" -eq 1 ]; then
        reason="NOT REFUSED: the release binary kept running and was killed after 10 s (exit ${g_rc})"
    elif [ "${g_rc}" -ne 2 ]; then
        reason="NOT REFUSED: expected exit 2"
    elif ! grep -q 'HEIMDALL_TEST_\|test configuration' "${out}"; then
        reason="exit 2 without the refusal text (a usage error, not the gate)"
    elif [ -n "$(ls -A "${home}" 2>/dev/null)" ]; then
        reason="exit 2, but the scratch HEIMDALL_HOME was written before the refusal"
    fi
    probe_count=$((probe_count + 1))
    if [ -z "${reason}" ]; then
        verdict="PASS"
    else
        verdict="FAIL (${reason})"
        fail_count=$((fail_count + 1))
        status=1
        # A client that was not refused may have started a detached runtime in the scratch
        # home: stop it through the product's own command, scoped to that home.
        if [ -n "$(ls -A "${home}" 2>/dev/null)" ]; then
            local stop_out
            stop_out="$(mktemp)" && scratch_files+=("${stop_out}") &&
                guarded_run "${stop_out}" env -i PATH="${PATH}" HOME="${home}" HEIMDALL_HOME="${home}" \
                    "${BIN}" --home "${home}" service stop
            echo "    cleanup: heimdall service stop in the scratch home -> exit ${g_rc}"
        fi
        # A short, printable excerpt of what the binary said (scratch paths only).
        head -c 300 "${out}" | tr -c '[:print:]\n' '?' | sed 's/^/    output: /'
        echo
    fi
    printf 'release-gate: %-34s %-22s exit %-3s %s\n' "${var}" "${label}" "${g_rc}" "${verdict}"
    rm -rf "${home}"
    rm -f "${out}"
}

[ -f "${TESTCFG}" ] || { echo "release-gate: ${TESTCFG} not found"; exit 2; }
vars_out="$(read_vars)" || { echo "release-gate: cannot read the test variables from ${TESTCFG}"; exit 2; }
[ -n "${vars_out}" ] || { echo "release-gate: no test variables found in ${TESTCFG}"; exit 2; }

echo "release-gate: cargo build --release --locked -p heimdall"
if ! cargo build --release --locked -p heimdall; then
    echo "release-gate: release build FAILED"
    exit 1
fi
[ -x "${BIN}" ] || { echo "release-gate: ${BIN} missing after the build"; exit 1; }

new_dir
vals="${new_dir_path}"
mkdir "${vals}/account" "${vals}/script-pause"

M03_VARS="HEIMDALL_TEST_SECRET_STORE HEIMDALL_TEST_KEY_SEED HEIMDALL_TEST_SESSION_LOCK HEIMDALL_TEST_SCRIPT_PAUSE_DIR"

# `service run` reads ALL_ENV (testcfg::requested) and, from M03, the M03 variables.
service_vars=""
launch_vars=""
while read -r kind name; do
    case "${kind}" in
        all) service_vars="${service_vars} ${name}" ;;
        launch) launch_vars="${launch_vars} ${name}" ;;
    esac
done <<EOF
${vars_out}
EOF
for v in ${M03_VARS}; do
    case " ${service_vars} " in *" ${v} "*) ;; *) service_vars="${service_vars} ${v}" ;; esac
done

echo "release-gate: probes (each: fresh scratch HEIMDALL_HOME, hard timeout 10 s, env -i)"
for v in ${service_vars}; do
    probe "${v}" "service run" service run
done
for v in ${launch_vars}; do
    probe "${v}" "run -- true" run -- true
    probe "${v}" "connect x" connect x
done
# The script pause directory is read CLI-side by `enroll` (U5's SshStepRunner), so a
# release `enroll` must refuse it too (U0b row 16).
probe HEIMDALL_TEST_SCRIPT_PAUSE_DIR "enroll x" enroll x
# The product-file test store (a disposable product-kind store, debug builds only): a release
# build refuses it like every test variable, before any store or runtime is touched.
PROBE_VALUE="product-file:${vals}/test.keychain-db"
probe HEIMDALL_TEST_SECRET_STORE "product-file service run" service run
probe HEIMDALL_TEST_SECRET_STORE "product-file issuer status" issuer status
probe HEIMDALL_TEST_SECRET_STORE "product-file issuer init" issuer init --backup-out "${vals}/b.key"
unset PROBE_VALUE

echo "release-gate: ${probe_count} probes, ${fail_count} failed"
if [ "${status}" -eq 0 ]; then
    echo "release-gate: release_build_refuses_m03_test_gates: PASS"
else
    echo "release-gate: release_build_refuses_m03_test_gates: FAIL"
fi
exit "${status}"
