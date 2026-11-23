#!/usr/bin/env bash
# The lifecycle journey (m08-plan U2a; A31 journeys 1-3 and 6 of m08-plan section 7.2):
# verify -> install -> setup -> active work -> stop -> update -> restart -> rollback ->
# uninstall, from two archives and the external checksum index.
#
# Usage: journey.sh --build release --index SHA256SUMS --old ARCHIVE --new ARCHIVE
#        journey.sh --build debug --old EXECUTABLE --new EXECUTABLE
#   --build release  the archives hold release builds. NO HEIMDALL_TEST_* variable is set,
#                    and the script REFUSES TO START unless it is inside a container, and
#                    refuses if any HEIMDALL_TEST_* is already in its environment (a stray
#                    export must fail loudly, not be silently refused by the binary).
#                    There is no flag that lets a release build run on a host.
#   --build debug    --old and --new are debug `heimdall` executables (the journey stages
#                    each with install.sh and a manifest; there is no external index, and
#                    the two index steps are reported as skipped). It can run on a host:
#                    all six scratch variables are exported and verified before anything is
#                    started (HOME, HEIMDALL_HOME, HEIMDALL_TEST_SSH_HOME,
#                    HEIMDALL_TEST_SECRET_STORE=scratch,
#                    HEIMDALL_TEST_MGMT_STORE=fixture-file:<scratch>,
#                    HEIMDALL_TEST_IROH_KEY_STORE=<scratch>). Every ssh, scp and git runs
#                    with -F on the scratch configuration and scratch known-hosts files,
#                    and only after a guard has shown that the alias names no identity or
#                    agent outside the scratch root. The account's real ~/.ssh is never
#                    read by a client and never written. A debug run is mechanism evidence.
#   --kill-before-update  the older runtime is ended with SIGKILL instead of `service stop`,
#                    so its write-ahead log is never checkpointed; the journey then checks
#                    that the pre-migration backup the newer build makes still holds the
#                    work done before the kill (a backup must go through SQLite, never copy
#                    the main database file alone).
#   --old and --new may name the same archive: the update and rollback steps are then
#   reported as `skipped (one archive)`, never as passed.
# Output: `test <step> ... ok|FAILED|skipped (...)` and `fact <name>=<value>` lines.
# Exit code: 0 when no step failed; 1 otherwise; 2 on a usage or boundary refusal.
#
# The account it runs as must be disposable (a container account): it writes that
# account's ~/.ssh/config, as a user's install would, and checks that uninstall puts it
# back byte for byte.
set -u
build=""; index=""; old=""; new=""; killfirst=no
while [ $# -gt 0 ]; do
    case "$1" in
        --build) build=${2:-}; shift 2 ;;
        --index) index=${2:-}; shift 2 ;;
        --old) old=${2:-}; shift 2 ;;
        --new) new=${2:-}; shift 2 ;;
        --kill-before-update) killfirst=yes; shift ;;
        *) echo "journey: unknown argument" >&2; exit 2 ;;
    esac
done
in_container() { [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qE '(docker|containerd|kubepods|libpod)' /proc/1/cgroup 2>/dev/null; }
case "$build" in
    release)
        if env | grep -q '^HEIMDALL_TEST_'; then
            echo "journey: refused: a HEIMDALL_TEST_* variable is set in the environment of a release run" >&2; exit 2
        fi
        if ! in_container; then
            echo "journey: refused: a release build runs only inside a container (AGENTS.md); no container was detected" >&2; exit 2
        fi ;;
    debug)
        here=$(cd "$(dirname "$0")" && pwd -P)
        lib=$here/../../m02
        # shellcheck source=tests/native/m02/remote-lib.sh
        . "$lib/remote-lib.sh"
        hm2_sanitize_env >/dev/null
        # /tmp, not $TMPDIR: the runtime's Unix socket paths are limited, and macOS's
        # per-user temporary directory is already too long for them.
        S0=$(mktemp -d /tmp/hmj.XXXXXX) || exit 2
        S0=$(cd "$S0" && pwd -P)
        export HOME="$S0/home" HEIMDALL_HOME="$S0/hm" HEIMDALL_TEST_SSH_HOME="$S0/ssh-home" \
            HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="fixture-file:$S0/mgmt-store" \
            HEIMDALL_TEST_IROH_KEY_STORE="$S0/iroh-key-store" TMPDIR="$S0/tmp"
        mkdir -m 700 "$HOME" "$HEIMDALL_HOME" "$HEIMDALL_TEST_SSH_HOME" "$HEIMDALL_TEST_SSH_HOME/etc-ssh" "$TMPDIR"
        for v in "$HOME" "$HEIMDALL_HOME" "$HEIMDALL_TEST_SSH_HOME" "${HEIMDALL_TEST_MGMT_STORE#fixture-file:}" "$HEIMDALL_TEST_IROH_KEY_STORE"; do
            case "$v" in "$S0"/*) ;; *) echo "journey: refused: a fixture path is outside the scratch root" >&2; rm -rf -- "$S0"; exit 2 ;; esac
        done
        [ "$HEIMDALL_TEST_SECRET_STORE" = scratch ] || { echo "journey: refused: the secret store is not the scratch store" >&2; rm -rf -- "$S0"; exit 2; }
        if [ ${#S0} -gt 48 ]; then echo "journey: refused: the scratch path is too long for Unix socket paths" >&2; rm -rf -- "$S0"; exit 2; fi
        ;;
    *) echo "journey: --build release|debug is required" >&2; exit 2 ;;
esac
if [ "$build" = release ]; then
    [ -f "$index" ] && [ -f "$old" ] && [ -f "$new" ] || { echo "journey: --index, --old and --new must be files" >&2; exit 2; }
    lib=/src/tests/native/m02
    # shellcheck source=tests/native/m02/remote-lib.sh
    . "$lib/remote-lib.sh"
    repo=/src
    SSHHOME=$HOME                     # a disposable account: its own ~/.ssh
    ISO=()
else
    [ -x "$old" ] && [ -x "$new" ] || { echo "journey: --old and --new must be executables" >&2; rm -rf -- "$S0"; exit 2; }
    repo=$(cd "$here/../../../.." && pwd -P)
    SSHHOME=$HEIMDALL_TEST_SSH_HOME   # the scratch account home the product is redirected to
fi
S=$HOME/j
mkdir -m 700 -- "$S" || { echo "journey: scratch exists" >&2; exit 2; }
CFG=$SSHHOME/.ssh/config
KH=$SSHHOME/.ssh/known_hosts
: >"$S/empty_known_hosts"
if [ "$build" = debug ]; then
    ISO=(-F "$CFG" -o "UserKnownHostsFile=$KH" -o "GlobalKnownHostsFile=$S/empty_known_hosts" -o ControlMaster=no -o ControlPath=none)
fi
SSH() { ssh ${ISO[@]+"${ISO[@]}"} "$@"; }
# `heimdall connect` launches the verified ssh with the alias alone, with no -F. In a
# container that is the disposable account's own configuration. On a host it would be the
# real account's ~/.ssh/config and default identities, which a test must never reach
# (AGENTS.md), so in a debug run the step is skipped, never run.
connect_step() { # connect_step NAME
    if [ "$build" = debug ]; then skip "$1" "connect starts ssh without -F: container journey only"; return 0; fi
    "$HM" --json --non-interactive connect hmjourney --allow-provider-interaction </dev/null >"$S/$1.json" 2>&1
    step "$1" "$?"
}
failed=0
step() { if [ "$2" = 0 ]; then echo "test $1 ... ok"; else echo "test $1 ... FAILED"; failed=1; fi; }
skip() { echo "test $1 ... skipped ($2)"; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
size() { python3 -I -c 'import os,sys; print(os.path.getsize(sys.argv[1]) if os.path.exists(sys.argv[1]) else 0)' "$1"; }
# Processes are identified by PIDs this run RECORDED, never found by a name or a command-
# line pattern (review M08-W01 on R08). A PID is recorded when the runtime advertises it
# (`service status`), and only if `ps` shows that exact PID belonging to this account with
# this run's own executable as its command. Later checks and signals use the recorded PIDs.
RECORDED_PIDS=""
pid_is_ours() { # pid_is_ours PID: that exact PID, this account, started from $HM
    [ "$(ps -o user= -p "$1" 2>/dev/null | tr -d ' ')" = "$(id -un)" ] || return 1
    ps -o args= -p "$1" 2>/dev/null | awk -v exe="$HM" '{ exit !($1 == exe) }'
}
recorded_alive() { for p in $RECORDED_PIDS; do if kill -0 "$p" 2>/dev/null && pid_is_ours "$p"; then echo "$p"; fi; done; }
# The runtime's PID as the runtime itself advertises it (`service status`), accepted only
# when that process belongs to this account and was started from this run's own executable.
# Signals go to this PID, never to a name (review M08-W0-R08).
runtime_pid() {
    local p
    hmcli "$S/pid.json" service status
    p=$(jget "$S/pid.json" data pid)
    case "$p" in ''|*[!0-9]*) return 1 ;; esac
    pid_is_ours "$p" || return 1
    case " $RECORDED_PIDS " in *" $p "*) ;; *) RECORDED_PIDS="$RECORDED_PIDS $p" ;; esac
    echo "$p"
}
jget() { python3 -I -c 'import json,sys
env=None
try: lines=open(sys.argv[1],encoding="utf-8",errors="replace").read().splitlines()
except OSError: lines=[]
for line in lines[::-1]:
    line=line.strip()
    if line.startswith("{"):
        try:
            env=json.loads(line); break
        except ValueError: pass
v=env
for k in sys.argv[2:]:
    v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else v)' "$@"; }
BIN=$HOME/.local/bin
HM=$BIN/heimdall
hmcli() { local o=$1; shift; "$HM" --json --non-interactive "$@" >"$o" 2>"$o.err" </dev/null; }
on_pty() { local o=$1; shift; python3 -I "$lib/pty-answer.py" "$o" yes 120 -- "$HM" --json "$@"; }
env_id() { hmcli "$S/st.json" service status; jget "$S/st.json" data environment_id; }

agent_pid=""; decoy_pid=""; held=""
cleanup() {
    [ -x "${HM:-/nonexistent}" ] && "$HM" --json --non-interactive service stop >/dev/null 2>&1 </dev/null
    hm2_sshd_stop 2>/dev/null || true
    for p in $held $agent_pid $decoy_pid; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    # A debug run's scratch root is removed (the exact path it created); a release run's
    # account disappears with its container.
    [ "$build" = debug ] && { cd /; rm -rf -- "$S0"; }
}
trap cleanup EXIT HUP INT TERM

# 1. Verify each archive against the external index BEFORE unpacking it (release), or
#    stage each debug executable with the install script and a manifest (debug).
if [ "$build" = release ]; then
    verify() { local want; want=$(awk -v n="$(basename "$1")" '$2 == n { print $1 }' "$index"); [ -n "$want" ] && [ "$want" = "$(sha "$1")" ]; }
    verify "$old"; step a31_old_archive_matches_the_external_index "$?"
    verify "$new"; step a31_new_archive_matches_the_external_index "$?"
    [ "$failed" = 0 ] || { echo "journey: an archive does not match the index; nothing was unpacked"; exit 1; }
    unpack() { mkdir "$2" && tar -xzf "$1" -C "$2" && echo "$2"/*; }
else
    skip a31_old_archive_matches_the_external_index "debug executables have no index"
    skip a31_new_archive_matches_the_external_index "debug executables have no index"
    unpack() { # stage a debug executable as an unpacked archive
        mkdir -p "$2/stage" && cp -p -- "$1" "$2/stage/heimdall" && cp -- "$repo/tools/packaging/install.sh" "$2/stage/install.sh" &&
            (cd "$2/stage" && for f in heimdall install.sh; do printf '%s  %s\n' "$(sha "$f")" "$f"; done >MANIFEST.sha256) && echo "$2/stage"
    }
fi
OLD=$(unpack "$old" "$S/old"); NEW=$OLD
same=yes
if [ "$(sha "$old")" != "$(sha "$new")" ]; then same=no; NEW=$(unpack "$new" "$S/new"); fi
echo "fact archives=$([ "$same" = yes ] && echo one || echo two)"

# The user's files that an install must not touch exist BEFORE the install, so the checks
# after it mean something (review M08-W0-R09): every shell profile, and ~/.ssh.
mkdir -p -m 700 "$SSHHOME/.ssh" "$HOME/.config/fish"
PROFILES=".bashrc .bash_profile .profile .zshrc .zprofile .zshenv .config/fish/config.fish"
for f in $PROFILES; do printf '# %s, written before the install\n' "$f" >>"$HOME/$f"; done
printf '# written before the install\nHost before-install\n    HostName before.example.invalid\n' >"$CFG"; chmod 600 "$CFG"
profiles_digest() { (cd "$HOME" && cat $PROFILES) >"$S/profiles.cat" 2>/dev/null; sha "$S/profiles.cat"; }
before_profiles=$(profiles_digest)
before_ssh=$(ls -la "$SSHHOME/.ssh" | awk '{print $1, $5, $NF}'; sha "$CFG")

# 2. Install from the archive alone, with its own script.
[ -f "$OLD/install.sh" ]; step a31_archive_carries_its_install_script "$?"
sh "$OLD/install.sh" >"$S/install.out" 2>&1; rc=$?
[ "$rc" = 0 ] && [ -x "$HM" ] && [ "$(sha "$HM")" = "$(sha "$OLD/heimdall")" ]
step a31_install_from_the_archive_alone "$?"
after_profiles=$(profiles_digest)
[ "$after_profiles" = "$before_profiles" ]
step a31_install_edits_no_shell_profile "$?"
[ "$(ls -la "$SSHHOME/.ssh" | awk '{print $1, $5, $NF}'; sha "$CFG")" = "$before_ssh" ]
step a31_install_does_not_touch_dot_ssh "$?"
echo "fact installed-version=$("$HM" --version 2>/dev/null)"

# 3. A user's world before setup: an SSH configuration of their own, a provider agent, a host.
ssh-keygen -q -t ed25519 -N '' -C hm-m08-journey-k0 -f "$S/k0" </dev/null >/dev/null 2>&1
mkdir -m 700 "$S/agent-home" "$S/decoy-home"
HOME="$S/agent-home" ssh-agent -D -a "$S/agent.sock" </dev/null >/dev/null 2>&1 &
agent_pid=$!
HOME="$S/decoy-home" ssh-agent -D -a "$S/decoy.sock" </dev/null >/dev/null 2>&1 &
decoy_pid=$!
i=0; while [ $i -lt 100 ] && { [ ! -S "$S/agent.sock" ] || [ ! -S "$S/decoy.sock" ]; }; do sleep 0.1; i=$((i + 1)); done
SSH_AUTH_SOCK="$S/agent.sock" ssh-add -q "$S/k0" </dev/null >/dev/null 2>&1
{ printf 'restrict '; cat "$S/k0.pub"; } >"$S/authorized_keys"
hm2_sshd_start "$S/sshd" "$S/authorized_keys" "$S/sshd.log"; step fixture_sshd "$?"
port=$HM2_SSHD_PORT
mkdir -p -m 700 "$SSHHOME/.ssh"
cat >"$CFG" <<'CFG'
# the user's own configuration, written before Heimdall was set up
Include conf.d/*
Host unrelated *.example.invalid
    HostName unrelated.example.invalid
    Port 2201
Match host never.example.invalid
    User nobody
CFG
chmod 600 "$CFG"
printf '[127.0.0.1]:%s %s\n' "$port" "$HM2_SSHD_HOSTKEY" >>"$KH"; chmod 600 "$KH"
orig=$(sha "$CFG")
SSH -G unrelated </dev/null >"$S/unrelated.before" 2>/dev/null

# 4. Setup, then active work: one login, and one session held open across the update.
SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
if [ "$(jget "$S/adopt.json" code)" = TIME_UNCERTAIN ]; then
    on_pty "$S/time.txt" time confirm
    SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
fi
identity=$(jget "$S/adopt.json" data identity_id)
hmcli "$S/dest.json" destination add hmjourney --hostname 127.0.0.1 --port "$port" --account "$(id -un)" --identity "$identity"
on_pty "$S/apply.txt" setup apply
[ "$(jget "$S/apply.txt" code)" = OK ] && [ "$(sha "$CFG")" != "$orig" ]
step a31_setup_apply "$?"
export SSH_AUTH_SOCK="$S/decoy.sock"
# The default-identity guard (as tests/native/m02/scenario-ordinary-ssh.sh): before any
# connection, every identity, agent and certificate the alias names must be inside this
# run's scratch (debug) or the disposable account's home (release), and it must name one.
REALHOME=$(python3 -I -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')
ROOT1=$([ "$build" = debug ] && echo "$S0" || echo "$HOME")
SSH -G hmjourney </dev/null 2>/dev/null | awk -v root="$ROOT1" -v real="$REALHOME" '
    $1 == "identityfile" || $1 == "identityagent" || $1 == "certificatefile" {
        v = $2; sub(/^~/, real, v)
        if (v != "none" && index(v, root "/") != 1) bad = 1
        if ($1 == "identityfile") n++
    }
    END { exit (bad || n == 0) }'
guard=$?
step a31_alias_names_only_scratch_identities "$guard"
if [ "$guard" != 0 ]; then echo "journey: the identity guard refused; no connection was made"; exit 1; fi
SSH -o BatchMode=yes hmjourney true </dev/null >/dev/null 2>&1; step a31_login_after_install "$?"
connect_step a31_connect_through_the_runtime
SSH -o BatchMode=yes hmjourney 'sleep 600' </dev/null >/dev/null 2>&1 &
held=$!
sleep 2
kill -0 "$held" 2>/dev/null; step a31_a_session_is_held_open "$?"
id_before=$(env_id)
[ -n "$id_before" ]; step a31_environment_identity_readable "$?"
runtime_pid >/dev/null; step a31_runtime_pid_recorded "$?"

# 5. Update: refused while the runtime runs; then stop, update, restart.
if [ "$same" = no ]; then
    sh "$NEW/install.sh" >"$S/update-refused.out" 2>&1; rc=$?
    [ "$rc" = 1 ] && grep -q 'service stop' "$S/update-refused.out" && [ "$(sha "$HM")" = "$(sha "$OLD/heimdall")" ]
    step a31_update_is_refused_while_the_runtime_runs "$?"
    if [ "$killfirst" = yes ]; then
        # The destination was added and used; nothing has checkpointed it into the main file.
        st=$(dirname "$(find "$HOME" "${HEIMDALL_HOME:-$HOME}" -name state.db -type f 2>/dev/null | head -1)")
        echo "fact before-kill-db-bytes=$(size "$st/state.db") wal-bytes=$(size "$st/state.db-wal")"
        python3 -I -c 'import sys; sys.exit(0 if b"hmjourney" not in open(sys.argv[1],"rb").read() else 1)' "$st/state.db"
        echo "fact before-kill-alias-in-main-db-file=$([ $? = 0 ] && echo no || echo yes)"
        python3 -I -c 'import sys; sys.exit(0 if b"hmjourney" in open(sys.argv[1],"rb").read() else 1)' "$st/state.db-wal"
        echo "fact before-kill-alias-in-wal-file=$([ $? = 0 ] && echo yes || echo no)"
        runtime_pid >/dev/null; rt=$(recorded_alive | tail -1)
        [ -n "$rt" ] && kill -9 "$rt"; step a31_runtime_killed_without_a_clean_close "$?"
        sleep 1
        echo "fact after-kill-db-bytes=$(size "$st/state.db") wal-bytes=$(size "$st/state.db-wal")"
    else
        hmcli "$S/stop.json" service stop; step a31_service_stop "$?"
    fi
    sh "$NEW/install.sh" >"$S/update.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && [ "$(sha "$HM")" = "$(sha "$NEW/heimdall")" ] && [ "$(sha "$BIN/heimdall.previous")" = "$(sha "$OLD/heimdall")" ]
    step a31_update_keeps_the_previous_executable "$?"
    kill -0 "$held" 2>/dev/null; step a31_the_held_session_survives_the_update "$?"
    SSH -o BatchMode=yes hmjourney true </dev/null >/dev/null 2>&1; step a31_login_after_update "$?"
    connect_step a31_connect_after_update
    [ "$(env_id)" = "$id_before" ]; step a31_update_keeps_the_environment_identity "$?"
    runtime_pid >/dev/null
    # The pre-migration backup, read through SQLite: does it hold the work done before the stop?
    bk=$(find "$HOME" "${HEIMDALL_HOME:-$HOME}" -name 'state.db.v*.backup' -type f 2>/dev/null | head -1)
    [ -n "$bk" ]; step a31_a_pre_migration_backup_exists "$?"
    python3 -I - "$bk" >"$S/backup-check.txt" 2>&1 <<'PY'
import sqlite3, sys
con = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro&immutable=1", uri=True)
print("integrity", con.execute("PRAGMA integrity_check").fetchone()[0])
print("user_version", con.execute("PRAGMA user_version").fetchone()[0])
hit = 0
for (name,) in con.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
    cols = [r[1] for r in con.execute(f'PRAGMA table_info("{name}")')]
    for row in con.execute(f'SELECT * FROM "{name}"'):
        if any(isinstance(v, (str, bytes)) and ("hmjourney" in (v if isinstance(v, str) else v.decode("utf-8", "replace"))) for v in row):
            hit += 1
print("rows_naming_the_destination", hit)
sys.exit(0 if hit > 0 else 1)
PY
    rc=$?
    echo "fact backup=$(basename "$bk") bytes=$(size "$bk") $(tr '\n' ' ' <"$S/backup-check.txt")"
    step a31_the_pre_migration_backup_holds_the_work_done_before_the_stop "$rc"
    # 6. Rollback, same store.
    hmcli "$S/stop2.json" service stop
    sh "$NEW/install.sh" --rollback >"$S/rollback.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && [ "$(sha "$HM")" = "$(sha "$OLD/heimdall")" ]; step a31_rollback_puts_the_previous_executable_back "$?"
    rc=0; : >"$S/rb-connect.json"
    if [ "$build" = release ]; then
        "$HM" --json --non-interactive connect hmjourney --allow-provider-interaction </dev/null >"$S/rb-connect.json" 2>&1; rc=$?
    fi
    echo "fact after-rollback-connect-code=$(jget "$S/rb-connect.json" code) (exit $rc)"
    echo "fact after-rollback-connect-reason=$(jget "$S/rb-connect.json" data error reason)"
    echo "fact after-rollback-connect-message=$(jget "$S/rb-connect.json" data error message | cut -c1-200)"
    hmcli "$S/rb-status.json" status
    echo "fact after-rollback-status-code=$(jget "$S/rb-status.json" code); message=$(jget "$S/rb-status.json" data error message | cut -c1-160)"
    "$HM" --json --non-interactive doctor </dev/null >"$S/rb-doctor.json" 2>/dev/null
    echo "fact after-rollback-doctor-code=$(jget "$S/rb-doctor.json" code)"
    runtime_pid >/dev/null
    echo "fact after-rollback-recorded-processes-alive=$(recorded_alive | wc -l | tr -d ' ')"
    after=$(env_id)
    # Either the older build serves the same store with the same identity, or it refuses a
    # newer store and says so. It must never serve a different identity.
    [ -z "$after" ] || [ "$after" = "$id_before" ]; step a31_rollback_never_changes_the_environment_identity "$?"
    # An older build that refuses the newer store must have changed nothing: the newer
    # build, put back, serves the same identity and the same access as before the rollback.
    hmcli "$S/stop3.json" service stop
    left=$(recorded_alive | wc -l | tr -d ' ')
    echo "fact recorded-processes-alive-after-service-stop=$left"
    # Stop exactly the recorded PIDs that are still this run's, one at a time, so the roll
    # forward can proceed; the count above is the finding.
    for p in $(recorded_alive); do kill "$p" 2>/dev/null; done
    [ "$left" = 0 ] || sleep 2
    sh "$NEW/install.sh" --rollback >"$S/forward.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && [ "$(sha "$HM")" = "$(sha "$NEW/heimdall")" ]; step a31_roll_forward_puts_the_newer_executable_back "$?"
    connect_step a31_connect_after_roll_forward
    [ "$(env_id)" = "$id_before" ]; step a31_the_refused_rollback_changed_nothing "$?"
    runtime_pid >/dev/null
else
    for n in a31_update_is_refused_while_the_runtime_runs a31_update_keeps_the_previous_executable \
        a31_the_held_session_survives_the_update a31_update_keeps_the_environment_identity \
        a31_rollback_puts_the_previous_executable_back a31_rollback_never_changes_the_environment_identity; do
        skip "$n" "one archive"
    done
fi

# 7. Uninstall: the user's configuration is back byte for byte; the unrelated alias is unchanged.
kill "$held" 2>/dev/null; wait "$held" 2>/dev/null; held=""
on_pty "$S/uninstall.txt" uninstall
echo "fact uninstall-code=$(jget "$S/uninstall.txt" code)"
echo "fact uninstall-remaining=$(jget "$S/uninstall.txt" data remaining | cut -c1-300)"
[ "$(sha "$CFG")" = "$orig" ]; step a31_uninstall_restores_the_users_ssh_config_byte_for_byte "$?"
SSH -G unrelated </dev/null >"$S/unrelated.after" 2>/dev/null && cmp -s "$S/unrelated.before" "$S/unrelated.after"
step a31_unrelated_alias_unchanged "$?"
"$HM" --json --non-interactive service stop >/dev/null 2>&1 </dev/null
sleep 1
left=$(recorded_alive | wc -l | tr -d ' ')
echo "fact recorded-runtime-pids=$(echo $RECORDED_PIDS | wc -w | tr -d ' ')"
[ "$left" = 0 ] && ! "$HM" --json --non-interactive service status 2>/dev/null | grep -q '"running":true'
step a31_no_runtime_left_running "$?"
[ "$build" = debug ] && echo "fact evidence-class=debug build on fixture stores: mechanism evidence only"
echo "journey: $([ "$failed" = 0 ] && echo PASS || echo FAIL)"
exit "$failed"
