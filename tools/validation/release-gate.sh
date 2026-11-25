#!/usr/bin/env bash
# Release-build test-gate refusal check (m03-plan U0b row 16; test name
# `release_build_refuses_m03_test_gates`; ADR-0008 section 18 "Revision 3", plan section 17.4 item 12).
#
# Usage: bash tools/validation/release-gate.sh        (from any directory; check.sh calls it)
# Exit code: 0 only when every probe below passes; 1 on any failed probe or a failed build;
# 2 when the script cannot set up (no testcfg.rs, no python3, no scratch).
#
# Builds the release binary once (`cargo build --release --locked --no-default-features -p heimdall`, the single
# ./target dir), then runs it once per HEIMDALL_TEST_* variable and asserts that the build
# refuses with exit code 2 before anything else happens:
#   * the M01/M02 variables are read from crates/heimdall/src/testcfg.rs (`ALL_ENV`:
#     `heimdall service run`; `LAUNCH_ENV`: `heimdall run -- true` and `heimdall connect x`);
#   * the M03 variables (`HEIMDALL_TEST_SECRET_STORE=scratch`, `HEIMDALL_TEST_KEY_SEED=00`,
#     `HEIMDALL_TEST_SESSION_LOCK=<abs scratch path>`, `HEIMDALL_TEST_SCRIPT_PAUSE_DIR=<abs
#     scratch dir>`) run through `heimdall service run`, the command whose
#     `testcfg::requested()` gate they join.
#   * ⟨ADR-0007 section 12.52⟩ the debug pinned-client redirect (`HEIMDALL_TEST_PINNED_CLIENT`,
#     in `LAUNCH_ENV`) also through `heimdall connect alpha` with the value naming a real
#     scratch executable. ⟨M07 W7.3; M07-W7-R06 (b)⟩ The exit-2 and refusal-text check is the
#     oracle: no marker check (see the probe's comment below for why one could never fire).
#   * <M06 W5> the fixture K_iroh store (`HEIMDALL_TEST_IROH_KEY_STORE=<abs owner-only scratch
#     dir>`) through `service run` and `service run --runner`; the store directory must stay
#     empty. (The serve target port is product configuration, `transport enable --serve
#     --sshd-port`: no test variable names it.)
#     Likewise the relay consent of a route is product surface, `route add --iroh <E> --relay
#     <URL>` (ADR-0006 section 18.9 item 9; its flags are pinned by the help golden
#     tests/contracts/golden/cli-help-m06/route-add.txt): no test variable names it, so no
#     probe covers it.)
#   * <M06 W5> the bootstrap's ssh configuration seam (`HEIMDALL_TEST_SSH_HOME` moves
#     `environment add`'s bootstrap `-F` file in a debug build; crates/heimdall/src/m06_cmd.rs
#     `bootstrap_test_config`): a release `environment add` and `environment status` refuse it
#     before the terminal check and before any state.
#   * <M06 W5 w5v> the bootstrap's ssh diagnostic file (`HEIMDALL_TEST_SSH_STDERR_FILE=<abs
#     scratch file>`, in LAUNCH_ENV, so `run` and `connect` are probed with it; also a release
#     `environment add`): the file must not exist afterwards.
#   * <M06 W5 w5m> the fixture K_mgmt store (`HEIMDALL_TEST_MGMT_STORE=fixture-file:<abs scratch
#     path>`, read CLI-side where the K_mgmt store is selected; crates/heimdall/src/m06_cmd.rs
#     `mgmt_store`): a release `service run`, `service run --runner`, `environment status`,
#     `environment join --show-key` (which would create the key) and `device retire` refuse
#     it; the fixture path must not exist afterwards.
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
        HEIMDALL_TEST_SSH_STDERR_FILE) printf '%s/ssh-stderr.txt' "${vals}" ;;
        HEIMDALL_TEST_SECRET_STORE) printf 'scratch' ;;
        HEIMDALL_TEST_KEY_SEED) printf '00' ;;
        HEIMDALL_TEST_SESSION_LOCK) printf '%s/session-lock-state' "${vals}" ;;
        HEIMDALL_TEST_SCRIPT_PAUSE_DIR) printf '%s/script-pause' "${vals}" ;;
        HEIMDALL_TEST_PURGE_TRUSTED_TOP) printf '%s' "${vals}" ;;
        HEIMDALL_TEST_PINNED_CLIENT) printf '%s/pinned-client' "${vals}" ;;
        HEIMDALL_TEST_IROH_KEY_STORE) printf '%s/iroh-key-store' "${vals}" ;;
        HEIMDALL_TEST_MGMT_STORE) printf 'fixture-file:%s/mgmt-store' "${vals}" ;;
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

# --no-default-features, as the release scripts build it (M08 U3c): the gate tests the binary
# with the release feature set, which has no edge to the test kit.
echo "release-gate: cargo build --release --locked --no-default-features -p heimdall"
if ! cargo build --release --locked --no-default-features -p heimdall; then
    echo "release-gate: release build FAILED"
    exit 1
fi
[ -x "${BIN}" ] || { echo "release-gate: ${BIN} missing after the build"; exit 1; }

# ⟨M08 U3c⟩ How this build handles the test configuration: the test kit is compiled out (the
# release feature set has no `test-config`), and every HEIMDALL_TEST_* variable probed below is
# refused at run time by testcfg (exit 2). The first is checked here from cargo's graph.
probe_count=$((probe_count + 1))
# (`cargo tree -i` of a workspace member outside the graph prints nothing and exits 0, so the
# probe reads its output, not its exit code.)
kit_tree="$(cargo tree -q --locked --no-default-features -p heimdall -e normal -i heimdall-testkit 2>&1)"
if [ -n "${kit_tree}" ]; then
    fail_count=$((fail_count + 1))
    status=1
    echo "release-gate: the test kit is in the release feature set's graph: FAIL"
else
    echo "release-gate: the test kit is compiled out of the release build (no heimdall-testkit in cargo tree --no-default-features -e normal): PASS"
fi
echo "release-gate: every HEIMDALL_TEST_* variable below is refused at run time (exit 2) by the release build's testcfg; none is honoured"

new_dir
vals="${new_dir_path}"
mkdir "${vals}/account" "${vals}/script-pause"
# An existing owner-only directory: a debug build would use it as the fixture K_iroh store.
mkdir -m 700 "${vals}/iroh-key-store"

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
# ⟨ADR-0008 §17.33 item 14⟩ The purge's debug-only trusted top is read CLI-side by
# `uninstall`: a release `uninstall` refuses it before anything else.
probe HEIMDALL_TEST_PURGE_TRUSTED_TOP "uninstall" uninstall
# ⟨M07 W7b; ADR-0007 §12.52⟩ The debug pinned-client redirect is in LAUNCH_ENV, so the loop
# above already probes it through `run -- true` and `connect x`. This probe names a real
# executable at that path (a debug build would accept it): a release `connect` refuses the
# variable with exit 2 and the refusal text, the home untouched.
# ⟨M07 W7.3; M07-W7-R06 (b)⟩ That check is the oracle; there is no marker check. The release
# build refuses the variable first thing in `connect` (`testcfg::launch_hooks`), before it
# reads the alias, selects a client or asks the runtime anything. A build that did not
# refuse it would go on to ask a runtime about `alpha`, and in this empty scratch home it
# stops there (no runtime, no destination), before any launch: a marker left by the named
# program could never appear, so its absence would prove nothing. Reaching a launch would
# need a runtime serving a destination `connect` knows in the scratch home, and a release
# runtime there reads the account's real SSH configuration (release builds have no
# redirect), which this script must not do.
printf '#!/bin/sh\nexit 0\n' >"${vals}/pinned-client"
chmod 700 "${vals}/pinned-client"
probe HEIMDALL_TEST_PINNED_CLIENT "connect alpha (wrapper)" connect alpha
# <M06 W5> The fixture K_iroh store (debug builds only): a release `service run` (the
# runtime that would serve with the key) and `service run --runner` refuse it before
# anything else. The store directory exists and is owner-only, so a build that
# honoured the variable would use it; it must still be empty afterwards.
for v in HEIMDALL_TEST_IROH_KEY_STORE; do
    grep -q "\"${v}\"" "${TESTCFG}" || {
        echo "release-gate: ${v} is not a constant of ${TESTCFG}"
        status=1
        fail_count=$((fail_count + 1))
    }
    probe "${v}" "service run" service run
    probe "${v}" "service run --runner" service run --runner
done
probe_count=$((probe_count + 1))
if [ -n "$(ls -A "${vals}/iroh-key-store" 2>/dev/null)" ]; then
    fail_count=$((fail_count + 1))
    status=1
    echo "release-gate: the fixture K_iroh store directory was written by a release build: FAIL"
else
    echo "release-gate: the fixture K_iroh store directory is untouched by the release build: PASS"
fi
# <M06 W5> The bootstrap's ssh configuration seam: in a debug build `HEIMDALL_TEST_SSH_HOME`
# makes `environment add`'s bootstrap session read `<that home>/.ssh/config` instead of the
# account's own. A release `environment` command refuses the variable (and every launch
# variable) before its terminal check, before any state and before any ssh child.
grep -q 'fn bootstrap_test_config' crates/heimdall/src/m06_cmd.rs || {
    echo "release-gate: bootstrap_test_config is not in crates/heimdall/src/m06_cmd.rs"
    status=1
    fail_count=$((fail_count + 1))
}
probe HEIMDALL_TEST_SSH_HOME "environment add" environment add --destination dst_AAAAAAAAAAAAAAAAAAAAAAAAAA \
    --account fixture --runner-program /nonexistent/heimdall --runner-home /nonexistent/home \
    --runner-sha256 0000000000000000000000000000000000000000000000000000000000000000
probe HEIMDALL_TEST_SSH_HOME "environment status" environment status
# <M06 W5 w5v> The bootstrap's ssh diagnostic file (`HEIMDALL_TEST_SSH_STDERR_FILE`, a launch
# variable: `run` and `connect` are probed above from LAUNCH_ENV): a release `environment add`
# refuses it before anything else, and the file is never created.
grep -q '"HEIMDALL_TEST_SSH_STDERR_FILE"' "${TESTCFG}" || {
    echo "release-gate: HEIMDALL_TEST_SSH_STDERR_FILE is not a constant of ${TESTCFG}"
    status=1
    fail_count=$((fail_count + 1))
}
probe HEIMDALL_TEST_SSH_STDERR_FILE "environment add" environment add --destination dst_AAAAAAAAAAAAAAAAAAAAAAAAAA \
    --account fixture --runner-program /nonexistent/heimdall --runner-home /nonexistent/home \
    --runner-sha256 0000000000000000000000000000000000000000000000000000000000000000
probe_count=$((probe_count + 1))
if [ -e "${vals}/ssh-stderr.txt" ]; then
    fail_count=$((fail_count + 1))
    status=1
    echo "release-gate: the bootstrap's ssh diagnostic file was written by a release build: FAIL"
else
    echo "release-gate: the bootstrap's ssh diagnostic file was not written by the release build: PASS"
fi
# <M06 W5 w5m> The fixture K_mgmt store (debug builds only; the ruling on w5k Q4): a release
# build refuses the variable in the runtime's gate and in every command that selects the
# K_mgmt store, before the terminal check and before any key store is read. `environment
# join --show-key` would otherwise create this device's key: the fixture path must not
# exist afterwards (the variable was neither honoured nor ignored in favour of the
# account's own store, which exit 2 before any store selection shows).
grep -q '"HEIMDALL_TEST_MGMT_STORE"' "${TESTCFG}" || {
    echo "release-gate: HEIMDALL_TEST_MGMT_STORE is not a constant of ${TESTCFG}"
    status=1
    fail_count=$((fail_count + 1))
}
grep -q 'mgmt_store_refusal' crates/heimdall/src/m06_cmd.rs || {
    echo "release-gate: mgmt_store_refusal is not checked in crates/heimdall/src/m06_cmd.rs"
    status=1
    fail_count=$((fail_count + 1))
}
probe HEIMDALL_TEST_MGMT_STORE "service run" service run
probe HEIMDALL_TEST_MGMT_STORE "service run --runner" service run --runner
probe HEIMDALL_TEST_MGMT_STORE "environment status" environment status
probe HEIMDALL_TEST_MGMT_STORE "environment join --show-key" environment join --show-key
probe HEIMDALL_TEST_MGMT_STORE "device retire" device retire
probe_count=$((probe_count + 1))
if [ -e "${vals}/mgmt-store" ]; then
    fail_count=$((fail_count + 1))
    status=1
    echo "release-gate: the fixture K_mgmt store path was written by a release build: FAIL"
else
    echo "release-gate: the fixture K_mgmt store path is untouched by the release build: PASS"
fi
# The product-file test store (a disposable product-kind store, debug builds only): a release
# build refuses it like every test variable, before any store or runtime is touched.
PROBE_VALUE="product-file:${vals}/test.keychain-db"
probe HEIMDALL_TEST_SECRET_STORE "product-file service run" service run
probe HEIMDALL_TEST_SECRET_STORE "product-file issuer status" issuer status
probe HEIMDALL_TEST_SECRET_STORE "product-file issuer init" issuer init --backup-out "${vals}/b.key"
unset PROBE_VALUE

# ADR-0008 §17.29 item 6: the test-only localenv hooks of wave 5 round 4 (F1) are library
# fields and functions, not `HEIMDALL_TEST_*` variables, so no binary probe can reach them.
# They stay unreachable in a release build because no production source outside
# `crates/localenv/src/` names them (the release binary keeps the defaults: `None` and
# `LOCAL_QUERY_TIMEOUT`). This static probe fails the gate if one ever does.
hook_hits=$(grep -rlE 'observe_global_within|observe_global_for_within|local_query_timeout|git_observed' \
    --include='*.rs' crates | grep -v '^crates/localenv/src/' || true)
probe_count=$((probe_count + 1))
if [ -n "${hook_hits}" ]; then
    fail_count=$((fail_count + 1))
    status=1
    echo "release-gate: localenv test-only hooks referenced by production sources: FAIL"
    printf '    %s\n' ${hook_hits}
else
    echo "release-gate: localenv test-only hooks (observe_global_within, ProjectionTestConfig.local_query_timeout, ProjectionConfig.git_observed) unreferenced outside crates/localenv/src: PASS"
fi

echo "release-gate: ${probe_count} probes, ${fail_count} failed"
if [ "${status}" -eq 0 ]; then
    echo "release-gate: release_build_refuses_m03_test_gates: PASS"
else
    echo "release-gate: release_build_refuses_m03_test_gates: FAIL"
fi
exit "${status}"
