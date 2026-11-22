#!/usr/bin/env bash
# The lifecycle journey (m08-plan U2a; A31 journeys 1-3 and 6 of m08-plan section 7.2):
# verify -> install -> setup -> active work -> stop -> update -> restart -> rollback ->
# uninstall, from two archives and the external checksum index.
#
# Usage: journey.sh --build release|debug --index SHA256SUMS --old ARCHIVE --new ARCHIVE
#   --build release  the archives hold release builds. NO HEIMDALL_TEST_* variable is set,
#                    and the script REFUSES TO START unless it is inside a container, and
#                    refuses if any HEIMDALL_TEST_* is already in its environment (a stray
#                    export must fail loudly, not be silently refused by the binary).
#                    There is no flag that lets a release build run on a host.
#   --build debug    the archives hold debug builds. All six scratch variables are exported
#                    and verified before anything is started: HOME, HEIMDALL_HOME,
#                    HEIMDALL_TEST_SSH_HOME, HEIMDALL_TEST_SECRET_STORE,
#                    HEIMDALL_TEST_MGMT_STORE, HEIMDALL_TEST_IROH_KEY_STORE.
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
        S0=$(mktemp -d "${TMPDIR:-/tmp}/hm-journey.XXXXXX") || exit 2
        export HOME="$S0/home" HEIMDALL_HOME="$S0/hm" HEIMDALL_TEST_SSH_HOME="$S0/ssh-home" \
            HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="fixture-file:$S0/mgmt-store" \
            HEIMDALL_TEST_IROH_KEY_STORE="$S0/iroh-key-store"
        mkdir -m 700 "$HOME" "$HEIMDALL_HOME" "$HEIMDALL_TEST_SSH_HOME"
        for v in "$HOME" "$HEIMDALL_HOME" "$HEIMDALL_TEST_SSH_HOME" "${HEIMDALL_TEST_MGMT_STORE#fixture-file:}" "$HEIMDALL_TEST_IROH_KEY_STORE"; do
            case "$v" in "$S0"/*) ;; *) echo "journey: refused: a fixture path is outside the scratch root" >&2; exit 2 ;; esac
        done
        [ "$HEIMDALL_TEST_SECRET_STORE" = scratch ] || { echo "journey: refused: the secret store is not the scratch store" >&2; exit 2; }
        echo "journey: the debug journey is not implemented yet: only the boundary checks above run" >&2
        rm -rf -- "$S0"
        exit 2 ;;
    *) echo "journey: --build release|debug is required" >&2; exit 2 ;;
esac
[ -f "$index" ] && [ -f "$old" ] && [ -f "$new" ] || { echo "journey: --index, --old and --new must be files" >&2; exit 2; }

lib=/src/tests/native/m02
# shellcheck source=tests/native/m02/remote-lib.sh
. "$lib/remote-lib.sh"
S=$HOME/j
mkdir -m 700 -- "$S" || { echo "journey: scratch exists" >&2; exit 2; }
failed=0
step() { if [ "$2" = 0 ]; then echo "test $1 ... ok"; else echo "test $1 ... FAILED"; failed=1; fi; }
skip() { echo "test $1 ... skipped ($2)"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
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

# 1. Verify each archive against the external index BEFORE unpacking it.
verify() { local want; want=$(awk -v n="$(basename "$1")" '$2 == n { print $1 }' "$index"); [ -n "$want" ] && [ "$want" = "$(sha "$1")" ]; }
verify "$old"; step a31_old_archive_matches_the_external_index "$?"
verify "$new"; step a31_new_archive_matches_the_external_index "$?"
[ "$failed" = 0 ] || { echo "journey: an archive does not match the index; nothing was unpacked"; exit 1; }
unpack() { mkdir "$2" && tar -xzf "$1" -C "$2" && echo "$2"/*; }
OLD=$(unpack "$old" "$S/old"); NEW=$OLD
same=yes
if [ "$(sha "$old")" != "$(sha "$new")" ]; then same=no; NEW=$(unpack "$new" "$S/new"); fi
echo "fact archives=$([ "$same" = yes ] && echo one || echo two)"

# 2. Install from the archive alone, with its own script.
[ -f "$OLD/install.sh" ]; step a31_archive_carries_its_install_script "$?"
sh "$OLD/install.sh" >"$S/install.out" 2>&1; rc=$?
[ "$rc" = 0 ] && [ -x "$HM" ] && [ "$(sha "$HM")" = "$(sha "$OLD/heimdall")" ]
step a31_install_from_the_archive_alone "$?"
! grep -rqs heimdall "$HOME/.bashrc" "$HOME/.profile" 2>/dev/null
step a31_install_edits_no_shell_profile "$?"
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
mkdir -p -m 700 "$HOME/.ssh"
cat >"$HOME/.ssh/config" <<'CFG'
# the user's own configuration, written before Heimdall was set up
Include conf.d/*
Host unrelated *.example.invalid
    HostName unrelated.example.invalid
    Port 2201
Match host never.example.invalid
    User nobody
CFG
chmod 600 "$HOME/.ssh/config"
printf '[127.0.0.1]:%s %s\n' "$port" "$HM2_SSHD_HOSTKEY" >>"$HOME/.ssh/known_hosts"; chmod 600 "$HOME/.ssh/known_hosts"
orig=$(sha "$HOME/.ssh/config")
ssh -G unrelated </dev/null >"$S/unrelated.before" 2>/dev/null

# 4. Setup, then active work: one login, and one session held open across the update.
SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
if [ "$(jget "$S/adopt.json" code)" = TIME_UNCERTAIN ]; then
    on_pty "$S/time.txt" time confirm
    SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
fi
identity=$(jget "$S/adopt.json" data identity_id)
hmcli "$S/dest.json" destination add hmjourney --hostname 127.0.0.1 --port "$port" --account "$(id -un)" --identity "$identity"
on_pty "$S/apply.txt" setup apply
[ "$(jget "$S/apply.txt" code)" = OK ] && [ "$(sha "$HOME/.ssh/config")" != "$orig" ]
step a31_setup_apply "$?"
export SSH_AUTH_SOCK="$S/decoy.sock"
ssh -o BatchMode=yes hmjourney true </dev/null >/dev/null 2>&1; step a31_login_after_install "$?"
"$HM" --json --non-interactive connect hmjourney --allow-provider-interaction </dev/null >/dev/null 2>&1; step a31_connect_through_the_runtime "$?"
ssh -o BatchMode=yes hmjourney 'sleep 600' </dev/null >/dev/null 2>&1 &
held=$!
sleep 2
kill -0 "$held" 2>/dev/null; step a31_a_session_is_held_open "$?"
id_before=$(env_id)
[ -n "$id_before" ]; step a31_environment_identity_readable "$?"

# 5. Update: refused while the runtime runs; then stop, update, restart.
if [ "$same" = no ]; then
    sh "$NEW/install.sh" >"$S/update-refused.out" 2>&1; rc=$?
    [ "$rc" = 1 ] && grep -q 'service stop' "$S/update-refused.out" && [ "$(sha "$HM")" = "$(sha "$OLD/heimdall")" ]
    step a31_update_is_refused_while_the_runtime_runs "$?"
    if [ "$killfirst" = yes ]; then
        # The destination was added and used; nothing has checkpointed it into the main file.
        st=$HOME/.local/state/heimdall
        echo "fact before-kill-db-bytes=$(stat -c %s "$st/state.db") wal-bytes=$(stat -c %s "$st/state.db-wal" 2>/dev/null || echo 0)"
        python3 -I -c 'import sys; sys.exit(0 if b"hmjourney" not in open(sys.argv[1],"rb").read() else 1)' "$st/state.db"
        echo "fact before-kill-alias-in-main-db-file=$([ $? = 0 ] && echo no || echo yes)"
        python3 -I -c 'import sys; sys.exit(0 if b"hmjourney" in open(sys.argv[1],"rb").read() else 1)' "$st/state.db-wal"
        echo "fact before-kill-alias-in-wal-file=$([ $? = 0 ] && echo yes || echo no)"
        rt=$(pgrep -u "$(id -u)" -x heimdall | head -1)
        [ -n "$rt" ] && kill -9 "$rt"; step a31_runtime_killed_without_a_clean_close "$?"
        sleep 1
        echo "fact after-kill-db-bytes=$(stat -c %s "$st/state.db") wal-bytes=$(stat -c %s "$st/state.db-wal" 2>/dev/null || echo 0)"
    else
        hmcli "$S/stop.json" service stop; step a31_service_stop "$?"
    fi
    sh "$NEW/install.sh" >"$S/update.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && [ "$(sha "$HM")" = "$(sha "$NEW/heimdall")" ] && [ "$(sha "$BIN/heimdall.previous")" = "$(sha "$OLD/heimdall")" ]
    step a31_update_keeps_the_previous_executable "$?"
    kill -0 "$held" 2>/dev/null; step a31_the_held_session_survives_the_update "$?"
    ssh -o BatchMode=yes hmjourney true </dev/null >/dev/null 2>&1; step a31_login_after_update "$?"
    "$HM" --json --non-interactive connect hmjourney --allow-provider-interaction </dev/null >/dev/null 2>&1; step a31_connect_after_update "$?"
    [ "$(env_id)" = "$id_before" ]; step a31_update_keeps_the_environment_identity "$?"
    # The pre-migration backup, read through SQLite: does it hold the work done before the stop?
    bk=$(ls "$HOME/.local/state/heimdall"/state.db.v*.backup 2>/dev/null | head -1)
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
    echo "fact backup=$(basename "$bk") bytes=$(stat -c %s "$bk") $(tr '\n' ' ' <"$S/backup-check.txt")"
    step a31_the_pre_migration_backup_holds_the_work_done_before_the_stop "$rc"
    # 6. Rollback, same store.
    hmcli "$S/stop2.json" service stop
    sh "$NEW/install.sh" --rollback >"$S/rollback.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && [ "$(sha "$HM")" = "$(sha "$OLD/heimdall")" ]; step a31_rollback_puts_the_previous_executable_back "$?"
    "$HM" --json --non-interactive connect hmjourney --allow-provider-interaction </dev/null >"$S/rb-connect.json" 2>&1; rc=$?
    echo "fact after-rollback-connect-code=$(jget "$S/rb-connect.json" code) (exit $rc)"
    echo "fact after-rollback-connect-reason=$(jget "$S/rb-connect.json" data error reason)"
    echo "fact after-rollback-connect-message=$(jget "$S/rb-connect.json" data error message | cut -c1-200)"
    hmcli "$S/rb-status.json" status
    echo "fact after-rollback-status-code=$(jget "$S/rb-status.json" code); message=$(jget "$S/rb-status.json" data error message | cut -c1-160)"
    "$HM" --json --non-interactive doctor </dev/null >"$S/rb-doctor.json" 2>/dev/null
    echo "fact after-rollback-doctor-code=$(jget "$S/rb-doctor.json" code)"
    echo "fact after-rollback-processes=$(pgrep -u "$(id -u)" -x heimdall -a 2>/dev/null | cut -d' ' -f2- | sed "s#$HOME#~#g" | tr '\n' ';')"
    echo "fact after-rollback-store-files=$(ls "$HOME/.local/state/heimdall" 2>/dev/null | tr '\n' ' ')"
    after=$(env_id)
    # Either the older build serves the same store with the same identity, or it refuses a
    # newer store and says so. It must never serve a different identity.
    [ -z "$after" ] || [ "$after" = "$id_before" ]; step a31_rollback_never_changes_the_environment_identity "$?"
    # An older build that refuses the newer store must have changed nothing: the newer
    # build, put back, serves the same identity and the same access as before the rollback.
    hmcli "$S/stop3.json" service stop
    left=$(pgrep -u "$(id -u)" -x heimdall 2>/dev/null | wc -l | tr -d ' ')
    echo "fact older-build-processes-after-service-stop=$left"
    if [ "$left" != 0 ]; then
        echo "fact leftover-older-process=$(pgrep -u "$(id -u)" -x heimdall -a | cut -d' ' -f2- | sed "s#$HOME#~#g" | tr '\n' ';')"
        # Stop exactly these, so the roll forward can proceed; the count above is the finding.
        for p in $(pgrep -u "$(id -u)" -x heimdall); do kill "$p" 2>/dev/null; done
        sleep 2
    fi
    sh "$NEW/install.sh" --rollback >"$S/forward.out" 2>&1; rc=$?
    [ "$rc" = 0 ] && [ "$(sha "$HM")" = "$(sha "$NEW/heimdall")" ]; step a31_roll_forward_puts_the_newer_executable_back "$?"
    "$HM" --json --non-interactive connect hmjourney --allow-provider-interaction </dev/null >/dev/null 2>&1; step a31_connect_after_roll_forward "$?"
    [ "$(env_id)" = "$id_before" ]; step a31_the_refused_rollback_changed_nothing "$?"
else
    for n in a31_update_is_refused_while_the_runtime_runs a31_update_keeps_the_previous_executable \
        a31_the_held_session_survives_the_update a31_update_keeps_the_environment_identity \
        a31_rollback_puts_the_previous_executable_back a31_rollback_never_changes_the_environment_identity; do
        skip "$n" "one archive"
    done
fi

# 7. Uninstall: the user's configuration is back byte for byte; the unrelated alias is unchanged.
kill "$held" 2>/dev/null; wait "$held" 2>/dev/null
on_pty "$S/uninstall.txt" uninstall
echo "fact uninstall-code=$(jget "$S/uninstall.txt" code)"
echo "fact uninstall-remaining=$(jget "$S/uninstall.txt" data remaining | cut -c1-300)"
[ "$(sha "$HOME/.ssh/config")" = "$orig" ]; step a31_uninstall_restores_the_users_ssh_config_byte_for_byte "$?"
ssh -G unrelated </dev/null >"$S/unrelated.after" 2>/dev/null && cmp -s "$S/unrelated.before" "$S/unrelated.after"
step a31_unrelated_alias_unchanged "$?"
"$HM" --json --non-interactive service stop >/dev/null 2>&1 </dev/null
left=$(pgrep -u "$(id -u)" -x heimdall 2>/dev/null | wc -l | tr -d ' ')
[ "$left" = 0 ]; step a31_no_runtime_left_running "$?"

# Stop exactly what this script started.
hm2_sshd_stop 2>/dev/null || true
kill "$agent_pid" "$decoy_pid" 2>/dev/null
echo "journey: $([ "$failed" = 0 ] && echo PASS || echo FAIL)"
exit "$failed"
