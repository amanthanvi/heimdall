# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154  # the caller's variables (below) are set and read across files
# Helpers of the M03 lock procedure (m03-plan §4.4), sourced by tests/native/m03/lock-macos.sh
# and by tests/native/m03/selftest.sh. Bash 3.2 compatible. Needs tests/native/m02/lib.sh
# (m02_record, m02_redact, m02_canary_scan, m02_leak_scan) and remote-lib.sh
# (hm2_owner_digest) sourced first, and the caller's variables: out, scratch, state,
# commands, facts, HM_LOCK_DRIVER, HEIMDALL_E2E_BIN, and driver_pid once started.
#
# Nothing here prints a path, user or host name, an environment value or a key: only
# states, counts, seconds and digests.

# lock_idle_seconds_macos: the console's idle time in whole seconds (IOHIDSystem
# HIDIdleTime, nanoseconds), or -1 when it cannot be read.
lock_idle_seconds_macos() {
    local ns
    ns=$(ioreg -c IOHIDSystem 2>/dev/null | awk '/HIDIdleTime/ { print $NF; exit }')
    case "$ns" in '' | *[!0-9]*) echo -1 ;; *) echo $((ns / 1000000000)) ;; esac
}

# lock_idle_ok SECONDS MIN: 0 when SECONDS is a reading of at least MIN.
lock_idle_ok() {
    case "$1" in '' | -* | *[!0-9]*) return 1 ;; esac
    [ "$1" -ge "$2" ]
}

# lock_query_state: the `state` of `heimdall --json internal session-lock-state`, the
# product's read-only query (platform source: no HEIMDALL_TEST_* variable is passed), or
# `query_failed`.
lock_query_state() {
    local json st
    json=$(env -u HEIMDALL_TEST_SESSION_LOCK "$HEIMDALL_E2E_BIN" --json internal session-lock-state 2>/dev/null </dev/null) ||
        { echo query_failed; return 0; }
    st=$(printf '%s\n' "$json" | jq -r '.data.state // empty' 2>/dev/null)
    case "$st" in unlocked | locked | unknown | unavailable) echo "$st" ;; *) echo query_failed ;; esac
}

# lock_await_state WANT SECONDS T0 FACTS: poll the product's query every 2 s until it
# reads WANT (0) or SECONDS pass (1); each reading is appended to FACTS as
# "lock-observation=<seconds since T0> <state>" (only changes, plus the last).
lock_await_state() {
    local want=$1 limit=$2 t0=$3 f=$4 start now st last=""
    start=$(date +%s)
    while :; do
        st=$(lock_query_state)
        now=$(date +%s)
        if [ "$st" != "$last" ]; then
            echo "lock-observation=$((now - t0))s $st" >>"$f"
            last=$st
        fi
        [ "$st" = "$want" ] && return 0
        [ $((now - start)) -ge "$limit" ] && return 1
        sleep 2
    done
}

# lock_start_sampler T0 FILE: sample the product's query every 10 s into FILE
# ("<seconds since T0> <state>") in the background; sets $sampler to its PID (this
# shell's own child, stopped by the caller).
lock_start_sampler() {
    local t0=$1 f=$2
    (
        while :; do
            echo "$(($(date +%s) - t0)) $(lock_query_state)" >>"$f"
            sleep 10
        done
    ) &
    sampler=$!
}

# --- the driver and its handshake (m03-plan §4.4; tests/e2e/exit_m03/lock.rs) ----------------
# The driver is ONE process, `e2e_exit_m03 --ignored --test-threads=16 --show-output lock::`,
# started once. Handshake files in $state: the driver writes `ready` (or `prepare-failed`,
# one line `blocked: …` or `failed: …`), the harness writes `locked` (or `abort` with a
# reason), the driver writes `locked-done`, the harness writes `expect` then `unlocked`,
# and the driver ends after its post-unlock step and cleanup (`done`).

# lock_driver_start: start the driver in the background in a session of its OWN
# (`setsid` through python3, then exec: $driver_pid is the driver itself and still this
# shell's child; its process group ID is its PID). A signal to the harness's process
# group (a terminal's or a session's teardown) then never reaches it: on the harness's
# `abort`, or once it sees the harness gone, it still runs its own cleanup. Stdin closed,
# output to $scratch/driver.out, TMPDIR the run's scratch, HM_LOCK_HARNESS_PID this shell.
lock_driver_start() {
    HM_LOCK_STATE_DIR="$state" HM_LOCK_PLATFORM="${HM_LOCK_PLATFORM:-macos}" HM_LOCK_HARNESS_PID=$$ \
        TMPDIR="$scratch" python3 -I -c 'import os, sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])' \
        "$HM_LOCK_DRIVER" --ignored --test-threads=16 --show-output lock:: \
        >"$scratch/driver.out" 2>&1 </dev/null &
    driver_pid=$!
}

# lock_group_stop GROUP: stop, each by its exact PID, every process of this user still in
# process group GROUP (the driver's own, made by lock_driver_start), never this shell.
# Prints "<count>" then the executable base names. Called only once the driver has ended
# without its cleanup, or right before it is stopped: what it started (the fixture sshds,
# the stand-in agent, the workers) is left in that group; its runtime detaches and is
# lock_runtime_stop's.
lock_group_stop() {
    local g=$1 me pid pg uid name n=0 names=""
    me=$(id -u)
    case "$g" in '' | *[!0-9]*) echo 0; return 0 ;; esac
    while read -r pid pg uid name; do
        [ "$pg" = "$g" ] && [ "$uid" = "$me" ] && [ "$pid" != "$$" ] || continue
        kill "$pid" 2>/dev/null && { n=$((n + 1)); names="$names ${name##*/}"; }
    done < <(ps -A -o pid=,pgid=,uid=,comm= 2>/dev/null)
    echo "$n$names"
}

# lock_runtime_stop: the fallback stop of the driver's runtime, when the driver did not
# stop it itself (it removes runtime-home.txt only after its cleanup's own `service
# stop`). The home it names must lie inside this run's scratch. The product's own
# `service stop` there (exit 0, or 5: nothing running), then, when the PID the runtime
# advertised (<home>/run/instance.json) still lives and runs this build's heimdall
# (the same file), that exact PID. Prints one line for the commands record; returns 0
# when nothing of the runtime is left, 1 otherwise. No runtime-home.txt: nothing to do,
# prints nothing.
lock_runtime_stop() {
    local hh pid src exe i
    [ -s "$state/runtime-home.txt" ] || return 0
    hh=$(head -1 "$state/runtime-home.txt")
    case "$hh" in
        "$scratch"/*) case "$hh" in */../* | */..) echo "runtime-home.txt names a path outside the run's scratch: not used"; return 1 ;; esac ;;
        *) echo "runtime-home.txt names a path outside the run's scratch: not used"; return 1 ;;
    esac
    if [ ! -d "$hh" ]; then
        echo "the driver's scratch Heimdall home is already gone (its world removed it after stopping its runtime)"
        return 0
    fi
    pid=$(jq -r '.pid // empty' "$hh/run/instance.json" 2>/dev/null)
    HEIMDALL_HOME="$hh" "$HEIMDALL_E2E_BIN" --json service stop >/dev/null 2>&1 </dev/null
    src=$?
    case "$pid" in '' | *[!0-9]*)
        echo "heimdall service stop in the driver's scratch Heimdall home (fallback; exit $src; no advertised PID)"
        [ "$src" = 0 ] || [ "$src" = 5 ]
        return ;;
    esac
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 1; i=$((i + 1)); done
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "heimdall service stop in the driver's scratch Heimdall home (fallback; exit $src); its advertised runtime is gone"
        return 0
    fi
    exe=$(ps -o comm= -p "$pid" 2>/dev/null)
    if [ -n "$exe" ] && [ "$exe" -ef "$HEIMDALL_E2E_BIN" ] && [ "$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ')" = "$(id -u)" ]; then
        kill "$pid" 2>/dev/null
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 1; i=$((i + 1)); done
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "heimdall service stop in the driver's scratch Heimdall home (fallback; exit $src) left its runtime running: stopped by its exact advertised PID"
            return 0
        fi
    fi
    echo "the driver's runtime is still running after the fallback stop (exit $src): its scratch is kept for recovery"
    return 1
}

# lock_failure_facts: one fact per failed driver step, from the reasons the driver kept as
# each failed (failure-<test>.txt; lock.rs keep_failure): "step-failure=<test>: <reason
# on one line>".
lock_failure_facts() {
    local f
    for f in "$state"/failure-*.txt; do
        [ -f "$f" ] || continue
        printf 'step-failure=%s\n' "$(head -c 4000 "$f" | tr '\n\r\t' '   ' | cut -c1-1200)"
    done
}

# lock_kept_failures: when the driver's output has no libtest summary (it ended before
# its end: a signal, a kill), the reasons it kept, each under a heading, for tests.txt.
lock_kept_failures() {
    local f
    grep -q '^failures:$' "$scratch/driver.out" 2>/dev/null && return 0
    for f in "$state"/failure-*.txt; do
        [ -f "$f" ] || continue
        printf '\n---- %s (the reason the driver kept as the step failed; its run ended before the libtest summary) ----\n' "$(basename "$f" .txt)"
        head -c 20000 "$f"
    done
}

# lock_flag NAME [TEXT]: write the handshake file NAME whole (a temporary file, a rename).
lock_flag() {
    printf '%s\n' "${2:-}" >"$state/.$1.tmp" && mv -f "$state/.$1.tmp" "$state/$1"
}

# lock_await_flag SECONDS NAME...: wait until one of the handshake files exists (0, its
# name in $flag), the driver ends first (2) or SECONDS pass (1). It runs in this shell,
# never in a command substitution, so a signal's trap runs within a second.
lock_await_flag() {
    local limit=$1 start f
    shift
    flag=""
    start=$(date +%s)
    while :; do
        for f in "$@"; do
            [ -e "$state/$f" ] && { flag=$f; return 0; }
        done
        kill -0 "$driver_pid" 2>/dev/null || {
            for f in "$@"; do [ -e "$state/$f" ] && { flag=$f; return 0; }; done
            return 2
        }
        [ $(($(date +%s) - start)) -ge "$limit" ] && return 1
        sleep 1
    done
}

# lock_driver_wait SECONDS: wait for the driver to end (0, $driver_rc its exit code) or
# SECONDS to pass (1). Never signals it.
lock_driver_wait() {
    local limit=$1 start
    start=$(date +%s)
    while kill -0 "$driver_pid" 2>/dev/null; do
        [ $(($(date +%s) - start)) -ge "$limit" ] && return 1
        sleep 1
    done
    driver_rc=0
    wait "$driver_pid" 2>/dev/null || driver_rc=$?
    return 0
}

# lock_driver_tests PLATFORM: the driver's test names on PLATFORM (macos|windows).
lock_driver_tests() {
    echo a03_lock_prepare a03_fresh_logins_while_locked_continue a03_new_grant_while_locked_under_standing_policy
    [ "$1" = windows ] && echo a03_issuer_restart_dpapi_unprotect_while_locked
    echo a03_lock_revokes_ends_grant_and_fresh_login_fails a03_vault_stand_in_locked_agent_does_not_matter
    echo a03_post_unlock_follows_remaining_deadline a03_lock_cleanup
}

# lock_driver_results OUTPUT PLATFORM COMMANDS: one command line per driver test from its
# libtest output: exit 0 `ok`; exit 3 `FAILED` with an `aborted:` or `blocked:` reason
# (not run, or not runnable: the run is blocked); exit 1 any other failure, or no result.
lock_driver_results() {
    local o=$1 t line rc what
    for t in $(lock_driver_tests "$2"); do
        line=$(grep -E "^test lock::$t \.\.\. " "$o" | tail -1)
        case "$line" in
            *"... ok") rc=0 ;;
            *"... FAILED")
                if grep -qE "^$t: (aborted|blocked): " "$o"; then rc=3; else rc=1; fi ;;
            *) rc=1 ;;
        esac
        if [ -n "$line" ]; then what=${line##* ... }; else what="no result"; fi
        m02_record "$3" "driver test lock::$t: $what" "$rc"
    done
}

# lock_hard_failure COMMANDS: 0 when a line records an exit other than 0 and 3 (blocked).
lock_hard_failure() { grep -qvE '^exit (0|3): ' "$1"; }

# lock_expectations GRANTS NOW: the post-unlock case of each grant from grants.tsv
# (role<TAB>grant<TAB>host<TAB>deadline epoch seconds), as "C=usable N=expired R=terminal":
# R is always terminal; another grant is usable when more than 60 s of its deadline
# remain at NOW, else expired (F09: the checks follow the remaining deadline). A missing
# or malformed file prints nothing.
lock_expectations() {
    local f=$1 now=$2
    [ -f "$f" ] || return 0
    awk -F'\t' -v now="$now" '
        $1 ~ /^[A-Z]$/ && $4 ~ /^[0-9]+$/ {
            if ($1 == "R") v = "terminal"; else if ($4 - now > 60) v = "usable"; else v = "expired"
            out = out (out == "" ? "" : " ") $1 "=" v
        }
        END { print out }' "$f"
}

# lock_check_attribution STATE SAMPLES T0 LOCKED_END: check the driver's logins.tsv
# (epoch<TAB>phase<TAB>host<TAB>role<TAB>key id<TAB>accepted|refused) against grants.tsv
# and events.tsv (epoch<TAB>event<TAB>role):
#   * every accepted login's key ID is `heimdall:<env>:<grant>:<serial>` with the grant of
#     the login's role, and that role's host (disjoint pairs; F09);
#   * no accepted login of R after R's `revoked` event;
#   * every `locked` phase login lies inside the verified-locked window: between the first
#     and the last consecutive `locked` sample (SAMPLES, seconds since T0).
# Prints `attribution-*` facts. Returns 0, 1 (a misattributed or post-revocation login, or
# no data), or 3 (a locked-phase login outside the window: the lock was interrupted).
lock_check_attribution() {
    python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import os, re, sys
state, samples, t0, locked_end = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def rows(name, n):
    p = os.path.join(state, name)
    if not os.path.exists(p):
        return []
    out = []
    for line in open(p, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) == n:
            out.append(f)
    return out
grants = {r[0]: (r[1], r[2]) for r in rows("grants.tsv", 4)}
logins = rows("logins.tsv", 6)
revoked = [int(r[0]) for r in rows("events.tsv", 3) if r[1] == "revoked" and r[2] == "R" and r[0].isdigit()]
bad = 0
for epoch, phase, host, role, key_id, result in logins:
    if result != "accepted":
        continue
    m = re.fullmatch(r"heimdall:[^:]+:([^:]+):[^:]+", key_id)
    want = grants.get(role)
    if not m or not want or m.group(1) != want[0] or host != want[1]:
        bad += 1
        continue
    others = [g for r, (g, _) in grants.items() if r != role]
    if m.group(1) in others:
        bad += 1
late = sum(1 for e, _, _, role, _, res in logins
           if role == "R" and res == "accepted" and revoked and int(e) >= min(revoked))
# The verified-locked window, in epoch seconds.
window = None
if os.path.exists(samples):
    first = last = None
    for line in open(samples, encoding="utf-8"):
        f = line.split()
        if len(f) != 2 or not f[0].lstrip("-").isdigit():
            continue
        s = t0 + int(f[0])
        if f[1] == "locked":
            if first is None:
                first = s
            last = s
        elif first is not None:
            break
    if first is not None:
        window = (first - 10, last + 10)
outside = 0
for epoch, phase, *_ in logins:
    if phase == "locked" and epoch.isdigit():
        if window is None or not (window[0] <= int(epoch) <= window[1]):
            outside += 1
accepted = sum(1 for r in logins if r[5] == "accepted")
print(f"attribution-logins={len(logins)} accepted={accepted}")
print(f"attribution-misattributed={bad}")
print(f"attribution-r-accepted-after-revocation={late}")
print(f"attribution-locked-logins-outside-window={outside}")
if not logins or not grants:
    print("attribution-data=missing")
    sys.exit(1)
if bad or late:
    sys.exit(1)
sys.exit(3 if outside else 0)
PY
}

# lock_blocked OUT REASON: write OUT/blocked.txt (one line) and the fact.
lock_blocked() {
    echo "blocked: $2" >"$1/blocked.txt"
    echo "lock-run=blocked ($2)" >>"$facts"
}

# lock_any_failure COMMANDS: 0 when a line of COMMANDS records a nonzero exit.
lock_any_failure() { grep -qv '^exit 0: ' "$1"; }

# lock_facts_common FACTS: facts every platform records.
lock_facts_common() {
    echo "lock-rule=ADR-0004 §2: locked by the harness only after >= 900 s console idle; the owner unlocks" >>"$1"
}

# lock_finish OUT SCRATCH: the owner-digest check after, redaction of every saved file
# into its final name (lock.txt, tests.txt, host.txt), the canary and leak scans.
lock_finish() {
    local o=$1 s=$2 lhost lshort before after
    echo "owner-ssh-after=$(hm2_owner_digest "$HOME/.ssh")" >>"$facts"
    echo "keychain-list-after=$(security list-keychains -d user 2>/dev/null | shasum -a 256 | cut -c1-24)" >>"$facts"
    lhost=$(hostname)
    lshort=$(hostname -s 2>/dev/null || echo "$lhost")
    m02_redact "$facts" "$o/lock.txt" "$s" "<scratch>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" \
        --word "$lhost" "<host>" --word "$lshort" "<host>" "$(id -un)" "<user>"
    m02_redact "$o/tests.raw" "$o/tests.txt" "$s" "<scratch>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" \
        --word "$lhost" "<host>" --word "$lshort" "<host>" "$(id -un)" "<user>"
    rm -f -- "$facts" "$o/tests.raw"
    grep -E '^(os|owner-|keychain-|build-|store-|screen-|idle-)' "$o/lock.txt" >"$o/host.txt" || true
    before=$(sed -n 's/^owner-ssh-before=//p;s/^keychain-list-before=//p' "$o/lock.txt" | tr '\n' ' ')
    after=$(sed -n 's/^owner-ssh-after=//p;s/^keychain-list-after=//p' "$o/lock.txt" | tr '\n' ' ')
    m02_record "$commands" "the home .ssh directory and the keychain search list unchanged by the run (digests)" \
        "$([ -n "$before" ] && [ "$before" = "$after" ] && echo 0 || echo 1)"
    hits=$(m02_canary_scan "$o")
    m02_record "$commands" "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
    leaks=$(m02_leak_scan "$o" "$HOME" --word "$lhost" --word "$lshort" "$(id -un)") && lrc=0 || lrc=$?
    m02_record "$commands" "leak scan: saved files still naming the host, the user or the home ($leaks)" "$lrc"
}
