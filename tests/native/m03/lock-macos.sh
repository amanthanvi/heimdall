#!/usr/bin/env bash
# M03-U13: the macOS lock procedure (m03-plan §4.4; ADR-0004 §2 lock rule; ADR-0005 §9.3 P1).
#
# The orchestrator may lock the build host's screen itself only after the console has
# been idle for at least 15 minutes; the owner unlocks whenever they return. This harness
# enforces that and decides nothing about the product: the A03 checks themselves are the
# lock driver's (`e2e_exit_m03`'s `lock::` tests, tests/e2e/exit_m03/lock.rs), started ONCE
# as one process and driven through handshake files (lock-lib.sh, "the driver and its
# handshake").
#
# Usage: tests/native/m03/lock-macos.sh <artifact-dir>
#   HM_LOCK_DRIVER     the e2e_exit_m03 test binary (default: built here, debug profile)
#   HEIMDALL_E2E_BIN   the heimdall binary of the same build (default: built here)
#   HM_LOCK_SIGNAL_TEST the integration_session_lock test binary (default: built here); its
#                      `macos_lock_signal_observed` (P1, M-F12) runs across the lock
#   HM_LOCK_WAIT_UNLOCK_S  the bound on waiting for the owner's unlock (default and maximum
#                      43200, 12 h)
#   HM_LOCK_VERIFY_S   the bound on the lock's verification (default and maximum 30 s; the
#                      self-test shortens it). The 900 s idle rule has no knob.
#
# Steps:
#   1. Idle: `ioreg -c IOHIDSystem` HIDIdleTime. Below 900 s: exit 3, blocked
#      (console_not_idle), nothing started or locked.
#   2. `heimdall internal session-lock-state` (the product's own read-only query, platform
#      source; no test variable) must read `unlocked` before anything else.
#   3. The driver starts and prepares, unlocked (runtime from this build with the platform
#      session-lock source, time confirm, the issuer on the test store, three loopback hosts
#      with disjoint pairs, grants C (continue, host 1) and R (revoke_on_lock, host 2), the
#      standing policy for N (host 3), the stand-in agent locked, baseline logins), then
#      writes `ready`; `prepare-failed` ends the run (blocked or failed, as it says).
#      Mechanism evidence only: a debug build on the test store never yields the macOS
#      lock_continuity claim (B3; F03).
#   4. Idle is checked again (else `abort`, blocked), then `pmset displaysleepnow`. It
#      locks only where the host asks for a password at once after display sleep; that
#      setting is read, never changed.
#   5. The lock is verified through the product's query within 30 s; otherwise `abort`,
#      blocked (lock_not_verified), with the observations, and the driver cleans up.
#   6. While locked (a sampler records the lock state every 10 s), `locked` lets the driver
#      run its locked steps (fresh logins attributed to C by certificate key ID, a new grant
#      N under the standing policy, R's revocation on the lock and its refused login, the
#      stand-in agent locked throughout, no prompt process) until it writes `locked-done`.
#      A locked-phase login outside the verified-locked window makes the run blocked
#      (lock_interrupted), never verified.
#   7. Wait for the unlock (bounded), then `expect` (each grant's case computed here from
#      its remaining deadline: usable, expired; R terminal) and `unlocked`; the driver runs
#      its post-unlock step and its cleanup and ends.
#   8. The attribution check over the driver's logins.tsv (F09): every accepted login's key
#      ID names the grant of its own host (C on 1, R on 2, N on 3), and none of R's key IDs
#      is accepted after its revocation.
#   9. The owner-digest check (~/.ssh and the keychain search list, digests only),
#      redaction, leak and canary scans.
#
# Output (redacted): lock.txt (idle seconds, method, lock-state samples with seconds since
# the lock, build profile, store kind), tests.txt (the driver's libtest output in the
# harness format "### e2e_exit_m03" ... "exit=N", and the signal test's), commands.txt (one
# line per driver test), host.txt, blocked.txt when blocked. Exit: 0 every test passed with
# a verified lock; 3 blocked; 1 a check failed; 2 usage.

set -euo pipefail

out=${1:?usage: lock-macos.sh <artifact-dir>}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/../m02/lib.sh"
# shellcheck source=tests/native/m02/remote-lib.sh
. "$here/../m02/remote-lib.sh"
# shellcheck source=tests/native/m03/lock-lib.sh
. "$here/lock-lib.sh"
MIN_IDLE_S=900
# The driver's own bounds (tests/e2e/exit_m03/lock.rs): prepare, the locked steps.
PREPARE_S=1800
LOCKED_STEPS_S=10800
wait_unlock_s=${HM_LOCK_WAIT_UNLOCK_S:-43200}
case "$wait_unlock_s" in '' | *[!0-9]*) echo "bad HM_LOCK_WAIT_UNLOCK_S" >&2; exit 2 ;; esac
[ "$wait_unlock_s" -le 43200 ] || wait_unlock_s=43200
verify_s=${HM_LOCK_VERIFY_S:-30}
case "$verify_s" in '' | *[!0-9]*) echo "bad HM_LOCK_VERIFY_S" >&2; exit 2 ;; esac
[ "$verify_s" -ge 1 ] && [ "$verify_s" -le 30 ] || verify_s=30
mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR
export HM_LOCK_PLATFORM=macos
commands="$out/commands.txt"
: >"$commands"
facts="$out/lock.raw"
: >"$facts"
tests_raw="$out/tests.raw"
: >"$tests_raw"

scratch=$(mktemp -d /tmp/hm-m03-lock.XXXXXX)
scratch=$(cd "$scratch" && pwd -P)
chmod 700 "$scratch"
state="$scratch/state"
mkdir -m 700 "$state"
sampler=""
driver_pid=""
driver_rc=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    set +e
    [ -n "$sampler" ] && kill "$sampler" 2>/dev/null && wait "$sampler" 2>/dev/null
    # The signal test ends by itself (its wait is bounded at 120 s): wait for it, never signal it.
    [ -n "${signal_pid:-}" ] && wait "$signal_pid" 2>/dev/null
    if [ -n "$driver_pid" ]; then
        # The driver always cleans up after an `abort` (and after `unlocked`): ask, then
        # wait for it; it is stopped by its exact PID (this shell's child) only if it
        # outlives every bound, and then its runtime through the product's own stop.
        if kill -0 "$driver_pid" 2>/dev/null && [ ! -e "$state/unlocked" ] && [ ! -e "$state/abort" ]; then
            lock_flag abort "harness_ended: the harness stopped before the procedure finished"
        fi
        if lock_driver_wait 900; then
            m02_record "$commands" "the lock driver ended by itself (exit $driver_rc)" 0
        else
            kill "$driver_pid" 2>/dev/null
            wait "$driver_pid" 2>/dev/null
            m02_record "$commands" "the lock driver outlived its bounds and was stopped by its exact PID" 1
            if [ -s "$state/runtime-home.txt" ]; then
                HEIMDALL_HOME=$(cat "$state/runtime-home.txt") "$HEIMDALL_E2E_BIN" --json service stop >/dev/null 2>&1 </dev/null
                m02_record "$commands" "heimdall service stop in the driver's scratch Heimdall home (fallback)" "$?"
            fi
        fi
        printf '### e2e_exit_m03\n%s\n### e2e_exit_m03 exit=%s\n' "$(cat "$scratch/driver.out" 2>/dev/null)" "${driver_rc:-killed}" >>"$tests_raw"
        lock_driver_results "$scratch/driver.out" macos "$commands"
        [ -s "$state/store-kind.txt" ] &&
            echo "store-kind-recorded-by-product=$(head -1 "$state/store-kind.txt") (the CA record's label; the issuer child reads the scratch test store)" >>"$facts"
    fi
    # A run that stopped before the driver started still names why (the importer needs one
    # "### <name> exit=N" line); `lock_procedure` is the harness, never a cargo target.
    [ -s "$tests_raw" ] || printf '### lock_procedure\n(no driver started)\n### lock_procedure exit=%s\n' "$rc" >"$tests_raw"
    lock_finish "$out" "$scratch"
    rm -rf -- "$scratch"
    [ ! -e "$scratch" ]
    m02_record "$commands" "remove exactly the run's scratch directory, then check it is absent" "$?"
    # A failed driver test (other than one not run because the run is blocked), a failed
    # owner-digest, canary or leak check fails a run that would otherwise have passed or
    # been blocked.
    lock_hard_failure "$commands" && rc=1
    exit "$rc"
}
trap cleanup EXIT

# The driver and the binary: given, or built here (debug profile, test store: mechanism
# evidence only on macOS).
if [ -z "${HM_LOCK_DRIVER:-}" ] || [ -z "${HEIMDALL_E2E_BIN:-}" ] || [ -z "${HM_LOCK_SIGNAL_TEST:-}" ]; then
    set +e
    (cd "$repo" && cargo build -p heimdall --bin heimdall --locked >"$scratch/build-bin.log" 2>&1 &&
        cargo test -p heimdall --test e2e_exit_m03 -p heimdall-runtime --test integration_session_lock \
            --no-run --locked --message-format=json-render-diagnostics >"$scratch/build.json" 2>"$scratch/build.log")
    rc=$?
    set -e
    m02_record "$commands" "cargo build -p heimdall --bin heimdall --locked; cargo test -p heimdall --test e2e_exit_m03 -p heimdall-runtime --test integration_session_lock --no-run --locked (debug profile)" "$rc"
    [ "$rc" = 0 ] || exit 1
    HM_LOCK_DRIVER=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "e2e_exit_m03" and .executable != null) | .executable' "$scratch/build.json" | tail -1)
    HM_LOCK_SIGNAL_TEST=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "integration_session_lock" and .executable != null) | .executable' "$scratch/build.json" | tail -1)
    HEIMDALL_E2E_BIN="$repo/target/debug/heimdall"
fi
[ -x "$HM_LOCK_DRIVER" ] && [ -x "$HEIMDALL_E2E_BIN" ] && [ -x "$HM_LOCK_SIGNAL_TEST" ] ||
    { echo "no lock driver, signal test or heimdall binary" >&2; exit 2; }
export HEIMDALL_E2E_BIN
echo "build-profile=debug (test configuration; mechanism evidence only, F03)" >>"$facts"
echo "store-kind=scratch_test (the test store; the login-keychain product row is B3)" >>"$facts"
echo "lock-driver-sha256=$(shasum -a 256 "$HM_LOCK_DRIVER" | cut -d' ' -f1)" >>"$facts"
echo "heimdall-sha256=$(shasum -a 256 "$HEIMDALL_E2E_BIN" | cut -d' ' -f1)" >>"$facts"
echo "lock-driver-protocol=one process (e2e_exit_m03 --ignored --test-threads=16 lock::), handshake files" >>"$facts"
lock_facts_common "$facts"
echo "os=$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null)) $(uname -m)" >>"$facts"
echo "screen-lock-delay=$(sysadminctl -screenLock status 2>&1 | sed -n 's/.*screenLock delay is //p' | head -1)" >>"$facts"
echo "owner-ssh-before=$(hm2_owner_digest "$HOME/.ssh")" >>"$facts"
echo "keychain-list-before=$(security list-keychains -d user 2>/dev/null | shasum -a 256 | cut -c1-24)" >>"$facts"

# 1. Idle.
idle=$(lock_idle_seconds_macos)
echo "idle-seconds-before-prepare=$idle" >>"$facts"
if ! lock_idle_ok "$idle" "$MIN_IDLE_S"; then
    lock_blocked "$out" "console_not_idle: HIDIdleTime ${idle}s < ${MIN_IDLE_S}s; nothing prepared or locked (ADR-0004 §2)"
    m02_record "$commands" "idle check: console idle ${idle}s below ${MIN_IDLE_S}s, run blocked" 3
    exit 3
fi
m02_record "$commands" "idle check: console idle ${idle}s >= ${MIN_IDLE_S}s" 0

# 2. The product's lock query reads unlocked first.
st=$(lock_query_state)
echo "lock-state-before=$st" >>"$facts"
if [ "$st" != unlocked ]; then
    lock_blocked "$out" "lock_state_not_unlocked_before: heimdall internal session-lock-state read $st before the lock"
    m02_record "$commands" "heimdall internal session-lock-state before the lock read $st" 3
    exit 3
fi
m02_record "$commands" "heimdall internal session-lock-state before the lock read unlocked (platform source)" 0

# 3. The driver: start once, wait for its preparation.
lock_driver_start
set +e
flag=$(lock_await_flag "$PREPARE_S" ready prepare-failed)
frc=$?
set -e
case "$frc:$flag" in
    0:ready) m02_record "$commands" "the lock driver prepared (ready)" 0 ;;
    0:prepare-failed)
        why=$(head -1 "$state/prepare-failed")
        case "$why" in
            blocked:*)
                lock_blocked "$out" "prepare_blocked: ${why#blocked: }"
                m02_record "$commands" "the lock driver's preparation is blocked" 3
                exit 3 ;;
        esac
        m02_record "$commands" "the lock driver's preparation failed" 1
        exit 1 ;;
    *)
        m02_record "$commands" "the lock driver prepared within ${PREPARE_S}s ($([ "$frc" = 2 ] && echo 'it ended first' || echo 'timed out'))" 1
        exit 1 ;;
esac

# 4. Idle again, then lock.
idle=$(lock_idle_seconds_macos)
echo "idle-seconds-before-lock=$idle" >>"$facts"
if ! lock_idle_ok "$idle" "$MIN_IDLE_S"; then
    lock_blocked "$out" "console_not_idle: HIDIdleTime ${idle}s < ${MIN_IDLE_S}s after preparing; not locked"
    lock_flag abort "console_not_idle: ${idle}s after preparing; not locked"
    m02_record "$commands" "idle check before the lock: ${idle}s, run blocked" 3
    exit 3
fi
m02_record "$commands" "idle check before the lock: console idle ${idle}s >= ${MIN_IDLE_S}s" 0
echo "lock-method=pmset displaysleepnow (locks only where a password is asked at once after display sleep)" >>"$facts"
# P1 (M-F12): the signal test starts unlocked, then waits for a real `locked` reading.
signal_out="$scratch/signal.out"
(HM_LOCK_WAIT_SECS=120 TMPDIR="$scratch" "$HM_LOCK_SIGNAL_TEST" --exact macos_lock_signal_observed --ignored \
    --test-threads=1 --show-output >"$signal_out" 2>&1 </dev/null; echo "$?" >"$scratch/signal.rc") &
signal_pid=$!
sleep 3
lock_t0=$(date +%s)
set +e
pmset displaysleepnow >/dev/null 2>&1
rc=$?
set -e
m02_record "$commands" "pmset displaysleepnow" "$rc"

# 5. Verify the lock.
if ! lock_await_state locked "$verify_s" "$lock_t0" "$facts"; then
    lock_blocked "$out" "lock_not_verified: heimdall internal session-lock-state did not read locked within ${verify_s} s of pmset displaysleepnow"
    lock_flag abort "lock_not_verified: not locked within ${verify_s} s"
    m02_record "$commands" "lock verified through the product's query within ${verify_s} s" 3
    exit 3
fi
m02_record "$commands" "lock verified through the product's query within ${verify_s} s" 0
lock_start_sampler "$lock_t0" "$out/lock-samples.txt"
lock_flag locked "verified at +$(($(date +%s) - lock_t0))s"
wait "$signal_pid" 2>/dev/null || true
signal_pid=""
src=$(cat "$scratch/signal.rc" 2>/dev/null || echo 1)
printf '### integration_session_lock\n%s\n### integration_session_lock exit=%s\n' "$(cat "$signal_out")" "$src" >>"$tests_raw"
m02_record "$commands" "integration_session_lock macos_lock_signal_observed across the lock (P1)" "$src"

# 6. While locked: the driver's locked steps.
set +e
flag=$(lock_await_flag "$LOCKED_STEPS_S" locked-done)
frc=$?
set -e
locked_end=$(date +%s)
if [ "$frc" != 0 ]; then
    m02_record "$commands" "the lock driver finished its locked steps ($([ "$frc" = 2 ] && echo 'it ended first' || echo "not within ${LOCKED_STEPS_S}s"))" 1
    lock_flag abort "locked_steps_unfinished"
    exit 1
fi
m02_record "$commands" "the lock driver finished its locked steps (locked-done, $((locked_end - lock_t0))s after the lock)" 0

# 7. Wait for the unlock, then the post-unlock step.
if ! lock_await_state unlocked "$wait_unlock_s" "$lock_t0" "$facts"; then
    lock_blocked "$out" "unlock_not_observed: the session did not read unlocked within ${wait_unlock_s}s; post-unlock checks not run"
    lock_flag abort "unlock_not_observed within ${wait_unlock_s}s"
    m02_record "$commands" "unlock observed within ${wait_unlock_s}s" 3
    exit 3
fi
m02_record "$commands" "unlock observed" 0
kill "$sampler" 2>/dev/null || true
wait "$sampler" 2>/dev/null || true
sampler=""
expect=$(lock_expectations "$state/grants.tsv" "$(date +%s)")
echo "post-unlock-expectations=$expect" >>"$facts"
lock_flag expect "$expect"
lock_flag unlocked
if ! lock_driver_wait "$PREPARE_S"; then
    m02_record "$commands" "the lock driver ended within ${PREPARE_S}s of the unlock" 1
    exit 1
fi

# 8. Attribution (F09) and the verified-locked window.
set +e
lock_check_attribution "$state" "$out/lock-samples.txt" "$lock_t0" "$locked_end" >>"$facts"
arc=$?
set -e
m02_record "$commands" "attribution by certificate key ID over logins.tsv (disjoint pairs; nothing of R accepted after its revocation)" "$([ "$arc" = 3 ] && echo 3 || echo "$arc")"
if [ "$arc" = 3 ]; then
    lock_blocked "$out" "lock_interrupted: a locked-phase login fell outside the verified-locked window"
    exit 3
fi
[ "$arc" = 0 ] || exit 1
exit 0
