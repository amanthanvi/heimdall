#!/usr/bin/env bash
# M03-U13: self-test of the M03 native harnesses (m03-plan U13 "Tests"), run by
# tools/validation/native-harness-selftest.sh. Reaches no host, builds nothing, locks
# nothing: `ioreg`, `pmset`, `security` and `sysadminctl` are stubs first on PATH, the
# heimdall binary is a stub answering `internal session-lock-state` from a state file, and
# the lock driver is a stub implementing the one-process handshake (ready, locked or
# abort, locked-done, expect and unlocked or abort) that writes the files the real driver
# writes (grants.tsv, logins.tsv, events.tsv) and prints libtest lines. Everything lives
# under one mktemp directory, removed on exit, pass or fail.
#
# Checks (the names m03-plan U13 gives):
#   lock_harness_refuses_without_idle_15_min      (before preparing, and again before locking)
#   lock_harness_records_unverified_lock_as_blocked (and a blocked preparation)
#   lock_harness_uses_disjoint_pairs_and_attributes_by_key_id
#   lock_harness_post_unlock_checks_follow_remaining_deadline
#   lock_harness_runs_the_p1_signal_test_across_the_lock, lock_harness_starts_one_driver_process,
#   lock_harness_fails_on_a_failed_preparation, lock_harness_fails_on_a_failed_driver_test
#   lock_harness_ends_cleanly_when_the_unlock_never_comes (the 12 h bound's path, shortened)
#   lock_harness_survives_a_signal_to_its_process_group (the driver in its own session)
#   lock_harness_stops_what_a_driver_left_without_its_cleanup (group, runtime, kept reasons)
#   lock_harness_never_passes_a_rehearsal_to_the_driver
#   windows_lock_run_is_release_profile_on_dpapi_store   (lock-windows.ps1 -SelfTest; skip without pwsh)
#   wsl_harness_unregisters_only_its_distribution        (tests/native/m02/selftest.sh's
#       D11/D12 run against tests/native/m03/run-wsl-distro.sh; reported there)
#   m03_linux_wrapper_*                                    (the Linux wrapper's settings)
# Prints one line per check and `m03-selftest: N passed, M failed`; exit 0 only when every
# check passed.

set -u
here=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d) || exit 2
T=$(cd "$T" && pwd -P)
trap 'rm -rf "$T"' EXIT
passes=0
fails=0
check() {
    local name=$1
    shift
    if "$@"; then
        echo "ok   $name"
        passes=$((passes + 1))
    else
        echo "FAIL $name"
        fails=$((fails + 1))
    fi
}
skip() { echo "skip $1 ($2)"; }

# --- the stub world -------------------------------------------------------------------------

# world NAME IDLE_FIRST IDLE_LATER PMSET_LOCKS SCENARIO: a fresh stub world; sets W (root),
# B (stub bin), O (artifacts), L (call log), ST (lock state file). `ioreg` reports
# IDLE_FIRST on its first call and IDLE_LATER after. The driver stub implements the
# handshake (lock-lib.sh): `ready` (or `prepare-failed`), then `locked` or `abort` from the
# harness, `locked-done`, then `unlocked` (with `expect`) or `abort`; it writes the files
# the real driver writes and prints libtest lines (an `aborted:` reason for a skipped test).
# SCENARIO: good, misattributed, late-r, failed-test, prepare-blocked, prepare-failed,
# never-unlocks (the session stays locked), dies-locked (a locked step fails, a child is
# left in its process group, then the driver is killed: no cleanup, no `done`).
world() {
    W="$T/$1"
    B="$W/bin"
    O="$W/out"
    L="$W/calls.log"
    ST="$W/lock-state"
    mkdir -p "$B" "$O"
    : >"$L"
    echo unlocked >"$ST"
    printf '%s\n%s\n' "$2" "$3" >"$W/idle"
    cat >"$B/ioreg" <<EOF
#!/bin/sh
echo "ioreg \$*" >>"$L"
n=\$(cat "$W/idle.n" 2>/dev/null || echo 0)
echo \$((n + 1)) >"$W/idle.n"
v=\$(sed -n "\$((n < 1 ? 1 : 2))p" "$W/idle")
echo "    | |   \"HIDIdleTime\" = \$((v * 1000000000))"
EOF
    cat >"$B/pmset" <<EOF
#!/bin/sh
echo "pmset \$*" >>"$L"
[ "$4" = 1 ] && echo locked >"$ST"
exit 0
EOF
    printf '#!/bin/sh\nexit 0\n' >"$B/security"
    printf '#!/bin/sh\necho "screenLock delay is immediate" >&2\n' >"$B/sysadminctl"
    cat >"$W/heimdall" <<EOF
#!/bin/sh
echo "heimdall \$*" >>"$L"
[ -n "\${HEIMDALL_HOME:-}" ] && echo "heimdall-home \${HEIMDALL_HOME##*/}" >>"$L"
[ "\$*" = "--json service stop" ] && exit 0
[ "\$*" = "--json internal session-lock-state" ] || exit 2
printf '{"state":"OK","code":"OK","data":{"state":"%s","source":"platform","signal":"macos_screen_lock"}}\n' "\$(cat "$ST")"
EOF
    cat >"$W/driver" <<EOF
#!/bin/bash
# The lock driver stub: --ignored --test-threads=16 --show-output lock::
s=\$HM_LOCK_STATE_DIR
scenario=$5
log() { echo "driver \$*" >>"$L"; }
flag() { printf '%s\n' "\${2:-}" >"\$s/.\$1.tmp" && mv "\$s/.\$1.tmp" "\$s/\$1"; }
await() {
    local n=0 f
    while :; do
        for f in "\$@"; do [ -e "\$s/\$f" ] && { echo "\$f"; return 0; }; done
        n=\$((n + 1)); [ "\$n" -gt 600 ] && return 1; sleep 0.2
    done
}
res() { echo "test lock::\$1 ... \$2"; }
fails=""
# fail TEST WHY (WHY without spaces: underscores print as spaces)
fail() { res "\$1" FAILED; fails="\$fails \$1|\$2"; }
finish() {
    rm -f "\$s/runtime-home.txt"
    res a03_lock_cleanup ok; log cleanup; flag done
    if [ -n "\$fails" ]; then
        printf '\nfailures:\n'
        for f in \$fails; do
            t=\${f%%|*}; why=\${f#*|}
            printf '\n---- lock::%s stdout ----\n%s: %s\n' "\$t" "\$t" "\$(echo "\$why" | tr '_' ' ')"
        done
        echo "test result: FAILED."
        exit 101
    fi
    echo "test result: ok."
    exit 0
}
LOCKED="a03_fresh_logins_while_locked_continue a03_new_grant_while_locked_under_standing_policy a03_lock_revokes_ends_grant_and_fresh_login_fails a03_vault_stand_in_locked_agent_does_not_matter"
log "start \$*"
log "rehearsal=\${HM_LOCK_REHEARSAL:-unset}"
log "pgid \$(ps -o pgid= -p \$\$ | tr -d ' ') pid \$\$ harness-pgid \$(ps -o pgid= -p "\$HM_LOCK_HARNESS_PID" | tr -d ' ')"
mkdir -p "\$TMPDIR/hh" && printf '%s\n' "\$TMPDIR/hh" >"\$s/runtime-home.txt"
now=\$(date +%s)
case "\$scenario" in
    prepare-blocked)
        flag prepare-failed "blocked: owner_ssh_in_scope: stub"; log prepare-failed
        fail a03_lock_prepare "blocked:_owner-ssh-in-scope"
        for t in \$LOCKED a03_post_unlock_follows_remaining_deadline; do fail "\$t" "aborted:_the_preparation_is_blocked"; done
        finish ;;
    prepare-failed)
        flag prepare-failed "failed: stub"; log prepare-failed
        fail a03_lock_prepare "a_stub_failure"
        for t in \$LOCKED a03_post_unlock_follows_remaining_deadline; do fail "\$t" "not_run:_the_preparation_failed"; done
        finish ;;
esac
printf 'C\tgc\t1\t%s\nR\tgr\t2\t%s\n' \$((now + 46800)) \$((now + 7200)) >"\$s/grants.tsv"
# The baselines a few seconds before (the real driver's precede R's revocation by minutes).
printf '%s\tprepare\t1\tC\theimdall:env:gc:1\taccepted\n%s\tprepare\t2\tR\theimdall:env:gr:1\taccepted\n' \$((now - 5)) \$((now - 5)) >"\$s/logins.tsv"
: >"\$s/events.tsv"
echo scratch_test >"\$s/store-kind.txt"
flag ready
log ready
res a03_lock_prepare ok
f=\$(await abort locked)
if [ "\$f" != locked ]; then
    log "abort \$(cat "\$s/abort" 2>/dev/null)"
    for t in \$LOCKED a03_post_unlock_follows_remaining_deadline; do fail "\$t" "aborted:_stub"; done
    finish
fi
log locked
now=\$(date +%s)
if [ "\$scenario" = misattributed ]; then key=heimdall:env:gc:9; host=2; else key=heimdall:env:gc:1; host=1; fi
printf '%s\tlocked\t%s\tC\t%s\taccepted\n' "\$now" "\$host" "\$key" >>"\$s/logins.tsv"
printf 'N\tgn\t3\t%s\n' \$((now - 5)) >>"\$s/grants.tsv"
printf '%s\tlocked\t3\tN\theimdall:env:gn:1\taccepted\n' "\$now" >>"\$s/logins.tsv"
printf '%s\trevoked\tR\n' "\$now" >>"\$s/events.tsv"
if [ "\$scenario" = late-r ]; then r=accepted; k=heimdall:env:gr:1; else r=refused; k=-; fi
printf '%s\tlocked\t2\tR\t%s\t%s\n' \$((now + 1)) "\$k" "\$r" >>"\$s/logins.tsv"
if [ "\$scenario" = dies-locked ]; then
    res a03_lock_revokes_ends_grant_and_fresh_login_fails FAILED
    printf '%s\n' "a03_lock_revokes_ends_grant_and_fresh_login_fails: R is revoked within 120 s: reads revoking (stub)" >"\$s/failure-a03_lock_revokes_ends_grant_and_fresh_login_fails.txt"
    sleep 300 &
    log "child \$!"
    kill -KILL \$\$
fi
for t in \$LOCKED; do
    if [ "\$scenario" = failed-test ] && [ "\$t" = a03_new_grant_while_locked_under_standing_policy ]; then
        fail "\$t" "a_stub_failure"
    else
        res "\$t" ok
    fi
done
[ "\$scenario" = never-unlocks ] || echo unlocked >"$ST"
flag locked-done
f=\$(await abort unlocked)
if [ "\$f" != unlocked ]; then
    log "abort \$(cat "\$s/abort" 2>/dev/null)"
    fail a03_post_unlock_follows_remaining_deadline "aborted:_stub"
    finish
fi
cat "\$s/expect" >"$W/expect.seen"
log post
res a03_post_unlock_follows_remaining_deadline ok
finish
EOF
    printf '#!/bin/sh\necho "signal-test $*" >>"%s"\necho "test macos_lock_signal_observed ... ok"\n' "$L" >"$W/signal"
    chmod +x "$B"/* "$W/heimdall" "$W/driver" "$W/signal"
}

# lock: run lock-macos.sh in the current world; sets rc.
lock() {
    env PATH="$B:$PATH" HM_LOCK_DRIVER="$W/driver" HEIMDALL_E2E_BIN="$W/heimdall" HM_LOCK_SIGNAL_TEST="$W/signal" HM_LOCK_VERIFY_S=4 \
        HM_LOCK_WAIT_UNLOCK_S="${WAIT_UNLOCK:-60}" bash "$here/lock-macos.sh" "$O" >"$W/harness.log" 2>&1 </dev/null
    rc=$?
    [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ] && { echo "--- lock-macos.sh exit $rc"; cat "$W/harness.log" "$O/commands.txt"; }
}

# lock_signalled: run lock-macos.sh in a process group of its own (as a terminal would),
# send TERM to that whole group once the driver has its `locked`, and wait; sets rc.
lock_signalled() {
    local hpid n=0
    python3 -I -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
        env PATH="$B:$PATH" HM_LOCK_DRIVER="$W/driver" HEIMDALL_E2E_BIN="$W/heimdall" HM_LOCK_SIGNAL_TEST="$W/signal" \
        HM_LOCK_VERIFY_S=4 HM_LOCK_WAIT_UNLOCK_S=60 bash "$here/lock-macos.sh" "$O" >"$W/harness.log" 2>&1 </dev/null &
    hpid=$!
    while ! grep -q "^driver locked" "$L" && [ "$n" -lt 200 ]; do sleep 0.2; n=$((n + 1)); done
    sleep 1
    echo "harness-pgid $hpid" >>"$L"
    kill -TERM -- "-$hpid" 2>/dev/null
    wait "$hpid"
    rc=$?
    [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ] && { echo "--- lock-macos.sh exit $rc"; cat "$W/harness.log" "$O/commands.txt"; }
}

# --- lock_harness_refuses_without_idle_15_min ----------------------------------------------
world idle 60 60 1 good
lock
check "lock_harness_refuses_without_idle_15_min: 60 s idle -> exit 3, console_not_idle, no driver started, nothing locked" \
    bash -c '[ "$1" = 3 ] && grep -q "console_not_idle" "$2/blocked.txt" && ! grep -q "^pmset" "$3" && ! grep -q "^driver" "$3" &&
        grep -q "^### lock_procedure exit=3" "$2/tests.txt"' _ "$rc" "$O" "$L"
world idle899 899 899 1 good
lock
check "lock_harness_refuses_without_idle_15_min: 899 s is still below the 15-minute rule" \
    bash -c '[ "$1" = 3 ] && grep -q "console_not_idle" "$2/blocked.txt"' _ "$rc" "$O"
world idlelate 1000 30 1 good
lock
check "lock_harness_refuses_without_idle_15_min: idle again before the lock (30 s after preparing) -> abort, the driver cleans up, never locked" \
    bash -c '[ "$1" = 3 ] && grep -q "console_not_idle" "$2/blocked.txt" && ! grep -q "^pmset" "$3" &&
        grep -q "^driver abort console_not_idle" "$3" && grep -q "^driver cleanup" "$3" && ! grep -q "^driver locked" "$3"' _ "$rc" "$O" "$L"

# --- lock_harness_records_unverified_lock_as_blocked ---------------------------------------
world unverified 1000 1000 0 good
lock
check "lock_harness_records_unverified_lock_as_blocked: the query never reads locked -> exit 3, lock_not_verified, abort, cleanup ran, no locked step" \
    bash -c '[ "$1" = 3 ] && grep -q "lock_not_verified" "$2/blocked.txt" && grep -q "^pmset displaysleepnow" "$3" &&
        grep -q "^driver abort lock_not_verified" "$3" && grep -q "^driver cleanup" "$3" && ! grep -q "^driver locked" "$3" &&
        grep -q "^lock-run=blocked" "$2/lock.txt"' _ "$rc" "$O" "$L"
check "lock_harness_records_unverified_lock_as_blocked: never recorded as passed (no exit 0 line for the lock; skipped driver tests recorded 3)" \
    bash -c 'grep -q "^exit 3: lock verified" "$1/commands.txt" && grep -q "^exit 3: driver test lock::a03_fresh_logins_while_locked_continue: FAILED" "$1/commands.txt" &&
        grep -q "^exit 0: driver test lock::a03_lock_cleanup: ok" "$1/commands.txt" && ! grep -q "^exit 1: " "$1/commands.txt"' _ "$O"
world blockedprep 1000 1000 1 prepare-blocked
lock
check "lock_harness_records_unverified_lock_as_blocked: a blocked preparation (prepare-failed: blocked: ...) -> exit 3, never locked" \
    bash -c '[ "$1" = 3 ] && grep -q "prepare_blocked: owner_ssh_in_scope" "$2/blocked.txt" && ! grep -q "^pmset" "$3" &&
        grep -q "^exit 3: driver test lock::a03_lock_prepare: FAILED" "$2/commands.txt"' _ "$rc" "$O" "$L"
world failedprep 1000 1000 1 prepare-failed
lock
check "lock_harness_fails_on_a_failed_preparation: prepare-failed: failed: ... -> exit 1, never locked" \
    bash -c '[ "$1" = 1 ] && ! grep -q "^pmset" "$3" && [ ! -e "$2/blocked.txt" ]' _ "$rc" "$O" "$L"

# --- lock_harness_uses_disjoint_pairs_and_attributes_by_key_id -----------------------------
world good 1000 1000 1 good
HM_LOCK_REHEARSAL=1 lock
check "lock_harness_runs_the_p1_signal_test_across_the_lock: started before pmset, its result in tests.txt" \
    bash -c 'grep -q "^signal-test --exact macos_lock_signal_observed --ignored" "$2" && grep -q "^test macos_lock_signal_observed ... ok" "$1/tests.txt" &&
        [ "$(grep -n "^signal-test" "$2" | cut -d: -f1)" -lt "$(grep -n "^pmset" "$2" | cut -d: -f1)" ]' _ "$T/good/out" "$T/good/calls.log"
check "lock_harness_starts_one_driver_process: one start (lock:: filter, 16 threads); ready < pmset < locked < post < cleanup" \
    bash -c '[ "$(grep -c "^driver start" "$1")" = 1 ] && grep -q "^driver start --ignored --test-threads=16 --show-output lock::$" "$1" &&
        r=$(grep -n "^driver ready" "$1" | cut -d: -f1) && m=$(grep -n "^pmset" "$1" | cut -d: -f1) &&
        l=$(grep -n "^driver locked" "$1" | cut -d: -f1) && p=$(grep -n "^driver post" "$1" | cut -d: -f1) &&
        c=$(grep -n "^driver cleanup" "$1" | cut -d: -f1) &&
        [ "$r" -lt "$m" ] && [ "$m" -lt "$l" ] && [ "$l" -lt "$p" ] && [ "$p" -lt "$c" ]' _ "$T/good/calls.log"
check "lock_harness_never_passes_a_rehearsal_to_the_driver: HM_LOCK_REHEARSAL=1 in the harness's environment is unset for the driver" \
    bash -c 'grep -q "^driver rehearsal=unset$" "$1"' _ "$T/good/calls.log"
check "lock_harness_uses_disjoint_pairs_and_attributes_by_key_id: correct key IDs on their own hosts -> exit 0" \
    bash -c '[ "$1" = 0 ] && grep -q "^attribution-misattributed=0" "$2/lock.txt" && grep -q "^attribution-r-accepted-after-revocation=0" "$2/lock.txt" &&
        grep -q "^test lock::a03_fresh_logins_while_locked_continue ... ok" "$2/tests.txt" && [ ! -e "$2/blocked.txt" ] &&
        [ "$(grep -c "^exit 0: driver test lock::" "$2/commands.txt")" = 7 ]' _ "$rc" "$O"
world mis 1000 1000 1 misattributed
lock
check "lock_harness_uses_disjoint_pairs_and_attributes_by_key_id: grant C's key ID accepted on host 2 -> exit 1" \
    bash -c '[ "$1" = 1 ] && grep -q "^attribution-misattributed=1" "$2/lock.txt"' _ "$rc" "$O"
world late 1000 1000 1 late-r
lock
check "lock_harness_uses_disjoint_pairs_and_attributes_by_key_id: a key ID of R accepted after its revocation -> exit 1" \
    bash -c '[ "$1" = 1 ] && grep -q "^attribution-r-accepted-after-revocation=1" "$2/lock.txt"' _ "$rc" "$O"
world failedtest 1000 1000 1 failed-test
lock
check "lock_harness_fails_on_a_failed_driver_test: one locked test FAILED (not aborted) -> exit 1" \
    bash -c '[ "$1" = 1 ] && grep -q "^exit 1: driver test lock::a03_new_grant_while_locked_under_standing_policy: FAILED" "$2/commands.txt"' _ "$rc" "$O"

# --- lock_harness_ends_cleanly_when_the_unlock_never_comes ---------------------------------
world nounlock 1000 1000 1 never-unlocks
WAIT_UNLOCK=3 lock
check "lock_harness_ends_cleanly_when_the_unlock_never_comes: exit 3 unlock_not_observed; abort; the driver cleaned up by itself; bundle written; scratch removed" \
    bash -c '[ "$1" = 3 ] && grep -q "unlock_not_observed" "$2/blocked.txt" && grep -q "^driver abort unlock_not_observed" "$3" &&
        grep -q "^driver cleanup" "$3" && grep -q "^exit 0: the lock driver ended by itself" "$2/commands.txt" &&
        grep -q "^exit 3: driver test lock::a03_post_unlock_follows_remaining_deadline: FAILED" "$2/commands.txt" &&
        ! grep -q "service stop" "$3" && ! grep -q "own process group" "$2/commands.txt" &&
        grep -q "^### e2e_exit_m03 exit=101" "$2/tests.txt" && [ -s "$2/lock.txt" ] &&
        grep -q "^exit 0: remove exactly the run.s scratch directory" "$2/commands.txt" && ! grep -q "^exit 1: " "$2/commands.txt"' _ "$rc" "$O" "$L"

# --- lock_harness_survives_a_signal_to_its_process_group -----------------------------------
world signalled 1000 1000 1 never-unlocks
lock_signalled
check "lock_harness_survives_a_signal_to_its_process_group: the driver runs in its own process group (not the harness's)" \
    bash -c 'set -- $(grep "^driver pgid" "$1"); [ "$3" = "$5" ] && [ "$3" != "$7" ] && [ -n "$7" ]' _ "$L"
check "lock_harness_survives_a_signal_to_its_process_group: TERM to the harness's group -> exit 3 harness_interrupted; the driver aborted and cleaned up by itself; bundle written" \
    bash -c '[ "$1" = 3 ] && grep -q "harness_interrupted: SIGTERM" "$2/blocked.txt" && grep -q "^driver abort harness_ended" "$3" &&
        grep -q "^driver cleanup" "$3" && grep -q "^exit 0: the lock driver ended by itself" "$2/commands.txt" &&
        ! grep -q "service stop" "$3" && grep -q "^### e2e_exit_m03 exit=" "$2/tests.txt" && [ -s "$2/lock.txt" ] &&
        grep -q "^exit 0: remove exactly the run.s scratch directory" "$2/commands.txt" && ! grep -q "^exit 1: " "$2/commands.txt"' _ "$rc" "$O" "$L"

# --- lock_harness_stops_what_a_driver_left_without_its_cleanup -----------------------------
world died 1000 1000 1 dies-locked
lock
check "lock_harness_stops_what_a_driver_left_without_its_cleanup: its group's leftover stopped by exact PID; the fallback service stop in its home; the kept reason recorded; exit 1" \
    bash -c '[ "$1" = 1 ] && c=$(sed -n "s/^driver child //p" "$3") && [ -n "$c" ] && ! kill -0 "$c" 2>/dev/null &&
        grep -q "^exit 0: the driver ended without its cleanup: processes left in its own process group stopped by exact PID: 1 sleep$" "$2/commands.txt" &&
        grep -q "^heimdall --json service stop" "$3" && grep -q "^heimdall-home hh$" "$3" &&
        grep -q "^exit 0: heimdall service stop in the driver.s scratch Heimdall home (fallback; exit 0; no advertised PID)" "$2/commands.txt" &&
        grep -q "^step-failure=a03_lock_revokes_ends_grant_and_fresh_login_fails: .*reads revoking (stub)" "$2/lock.txt" &&
        grep -q "^---- failure-a03_lock_revokes_ends_grant_and_fresh_login_fails (the reason the driver kept" "$2/tests.txt" &&
        grep -q "^exit 1: driver test lock::a03_lock_cleanup: no result" "$2/commands.txt"' _ "$rc" "$O" "$L"

# --- lock_harness_post_unlock_checks_follow_remaining_deadline -----------------------------
check "lock_harness_post_unlock_checks_follow_remaining_deadline: C with 13 h left usable, N past its deadline expired, R terminal (the expect file)" \
    bash -c '[ "$(cat "$1/expect.seen")" = "C=usable R=terminal N=expired" ]' _ "$T/good"
check "lock_harness_post_unlock_checks_follow_remaining_deadline: 60 s or less left counts as expired" \
    bash -c '. "$1/../m02/lib.sh"; . "$1/lock-lib.sh"; f=$2/g.tsv; printf "C\tg\t1\t1060\nN\tg\t3\t1061\n" >"$f"; [ "$(lock_expectations "$f" 1000)" = "C=expired N=usable" ]' _ "$here" "$T"

# --- windows_lock_run_is_release_profile_on_dpapi_store ------------------------------------
if command -v pwsh >/dev/null 2>&1 && [ -f "$here/lock-windows.ps1" ]; then
    pwsh -NoProfile -File "$here/lock-windows.ps1" -SelfTest >"$T/lockwin.log" 2>&1
    wrc=$?
    [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ] && cat "$T/lockwin.log"
    check "windows_lock_run_is_release_profile_on_dpapi_store: lock-windows.ps1 -SelfTest (a debug product binary or a non-DPAPI store is refused; idle and lock rules)" \
        bash -c '[ "$1" = 0 ] && grep -q "^lock-windows-selftest: [1-9][0-9]* passed, 0 failed$" "$2"' _ "$wrc" "$T/lockwin.log"
else
    skip windows_lock_run_is_release_profile_on_dpapi_store "pwsh or lock-windows.ps1 absent"
fi

# --- the Linux wrapper ------------------------------------------------------------------------
check "m03_linux_wrapper_sets_the_m03_plan_prefix_and_facts" \
    bash -c 'grep -q "HM_EVIDENCE=m03-evidence.py HM_RUN_PREFIX=hm-m03" "$1/run-linux.sh" && grep -q "HM_EXTRA_REMOTE=\"\$here/remote-facts.sh\"" "$1/run-linux.sh"' _ "$here"
check "m03_linux_wrapper_remote_facts_print_key_values_only" \
    bash -c '. "$1/remote-facts.sh"; hm_extra_facts /nonexistent | grep -qvE "^(ptrace-scope|memlock-limit|ntp-synchronized|gnome-keyring)=" && exit 1; exit 0' _ "$here"

echo "m03-selftest: $passes passed, $fails failed"
[ "$fails" = 0 ]
