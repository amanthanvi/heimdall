#!/bin/bash
# Self-test for g04_ctk_probe.sh that never touches the real CTK token store or ssh-keychain.dylib.
#
# Generates a fake sc_auth (state in a temp dir, seeded with an "owner" identity and a leftover
# heimdall-m00-p5-* identity from an imaginary earlier run), runs the probe through its self-test
# hook (HEIMDALL_P5_SELFTEST_SC_AUTH) in several scenarios, and checks exit codes, record fields,
# the fake store afterwards, redaction of the other identities, and process residue:
#   normal                 create -> export refused -> delete -> list equal to the pre-run list
#   create_hang            create never returns: timeout, exact PIDs terminated, nothing left, blocked
#   create_partial_hang    create writes the identity, then hangs: found by label, deleted, blocked
#   export_succeeds        export unexpectedly writes a file: removed, reported as a finding
#   delete_fails           delete refuses: list mismatch, store frozen, cleanup incomplete (exit 4)
#   non_empty_store        other CTK identities present: the probe stops before creating (exit 6)
#   interrupt              SIGTERM during an in-flight sc_auth call: aborted, identity deleted (exit 5)
#   interrupt_in_create    SIGTERM while create is in flight after writing the identity: deleted (exit 5)
#   double_signal          SIGHUP arriving during a TERM-triggered cleanup does not cut it short (exit 5)
#   usage / hook guard     exit 2
# The fake mirrors what the real sc_auth did on macOS 27.0 (26A428): the row format (including a
# local-time "Valid To") and export exiting 0 while refusing. In self-test mode the probe skips every
# ssh-keychain.dylib load (it cannot see fake identities), so agents, signing, sampling, login and
# lock mode are covered only by a rehearsal or a real run.
#
# Usage: g04_ctk_probe_selftest.sh [--log FILE]
#   (default log: tests/evidence/artifacts/g04/p5/selftest/selftest-<UTC stamp>.log)
set -u
umask 077
export LC_ALL=C
unset SSH_AUTH_SOCK SSH_AGENT_PID
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
PROBE="$SCRIPT_DIR/g04_ctk_probe.sh"
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd -P)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG="$REPO_ROOT/tests/evidence/artifacts/g04/p5/selftest/selftest-$STAMP.log"
[ "${1:-}" = "--log" ] && [ -n "${2:-}" ] && LOG=$2
mkdir -p "$(dirname "$LOG")" || exit 3
[ -e "$LOG" ] && { echo "log exists: $LOG" >&2; exit 3; }
: > "$LOG"

ST=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-g04-p5-selftest.XXXXXXXX") || exit 3
chmod 700 "$ST"; mkdir -m 700 "$ST/fake" "$ST/tmp"
PASS=0; FAIL=0
log() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | sed "s#$ST#<selftest-tmp>#g; s#$HOME#<home>#g" | tee -a "$LOG" >&2; }
ok() { PASS=$((PASS+1)); log "  PASS $*"; }
bad() { FAIL=$((FAIL+1)); log "  FAIL $*"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
# pids file lines: "<pid> <lstart>" written by the fake for itself and its sleep children.
alive_same() { [ -n "$1" ] && [ "$(ps -o lstart= -p "$1" 2>/dev/null)" = "$2" ]; }
teardown() {
  local p s
  while read -r p s; do alive_same "$p" "$s" && kill -TERM "$p" 2>/dev/null; done < "$ST/fake/pids" 2>/dev/null
  rm -rf "$ST"
  log "teardown: selftest temp dir removed=$([ -e "$ST" ] && echo no || echo yes)"
}
trap teardown EXIT
trap 'log "interrupted"; exit 130' INT TERM HUP

# ---------------------------------------------------------------- fake sc_auth
OWNER_LABEL="owner-identity-$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
OWNER_HASH=$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n' | tr 'a-f' 'A-F')
OLD_LABEL="heimdall-m00-p5-$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
OLD_HASH=$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n' | tr 'a-f' 'A-F')
b64() { head -c 32 /dev/urandom | /usr/bin/base64 | tr -d '=\n' | cut -c1-43; }
printf '%s\t%s\t%s\t%s\t%s\n' "$OWNER_LABEL" "$OWNER_HASH" "$(b64)" "p-256-ne" "bio" "$OLD_LABEL" "$OLD_HASH" "$(b64)" "p-256-ne" "none" > "$ST/fake/seed.tsv"

cat > "$ST/fake/sc_auth" <<'FAKE'
#!/bin/bash
# Fake sc_auth for g04_ctk_probe_selftest.sh. Store: tab-separated label, hash, ssh hash, type, prot.
# Optional files next to it: mode (scenario), force_hash (hash to give the next created identity).
DIR=$(cd "$(dirname "$0")" && pwd -P); STORE="$DIR/store.tsv"; MODE=$(cat "$DIR/mode" 2>/dev/null || echo normal)
echo "$$ $(ps -o lstart= -p $$)" >> "$DIR/pids"
cmd=${1:-}; [ $# -gt 0 ] && shift
echo "$cmd" >> "$DIR/calls.log"   # sub-command only; never arguments (the export password is an argument)
hang() { sleep 600 & echo "$! $(ps -o lstart= -p $!)" >> "$DIR/pids"; wait $!; }
list() {   # row format as printed by the real ctkcard on macOS 27.0 (local-time "Valid To")
  printf 'Key Type Public Key Hash Prot Label Common Name Email Address Valid To Valid \n'
  while IFS="$(printf '\t')" read -r l h s k p; do
    [ -n "$l" ] || continue
    if [ "$1" = ssh ]; then hh=$s; else hh=$h; fi
    printf '%s %s %s %s %s               10/9/27, 1:36\342\200\257AM YES   \n' "$k" "$hh" "$p" "$l" "$l"
  done < "$STORE"
}
case "$cmd" in
  list-ctk-identities) t=sha1; while getopts t:e: o; do case $o in t) t=$OPTARG;; esac; done; list "$t";;
  pairing_ui) echo "SmartCard Pairing dialog is enabled.";;
  create-ctk-identity)
    while getopts l:k:t:N:E:U:O:L:S:C: o; do case $o in l) label=$OPTARG;; k) kt=$OPTARG;; t) prot=$OPTARG;; esac; done
    [ "$MODE" = create_hang ] && { hang; exit 1; }
    h=$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n' | tr 'a-f' 'A-F')
    [ -s "$DIR/force_hash" ] && h=$(cat "$DIR/force_hash")
    s=$(head -c 32 /dev/urandom | /usr/bin/base64 | tr -d '=\n' | cut -c1-43)
    printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$h" "$s" "$kt" "${prot:-none}" >> "$STORE"
    [ "$MODE" = create_partial_hang ] && { hang; exit 1; }
    echo "Created identity $label"; list sha1   # chatty on purpose: names the other identities too
    ;;
  delete-ctk-identity)
    while getopts h: o; do case $o in h) hash=$OPTARG;; esac; done
    [ "$MODE" = delete_fails ] && { echo "fake: delete refused" >&2; exit 1; }
    [ "$MODE" = export_slow_delete_slow ] && sleep 2
    grep -q -F "$hash" "$STORE" || { echo "No identity found for hash: <$hash>" >&2; exit 1; }
    grep -v -F "$hash" "$STORE" > "$STORE.new"; mv "$STORE.new" "$STORE";;
  export-ctk-identity)
    while getopts h:f:p: o; do case $o in h) hash=$OPTARG;; f) file=$OPTARG;; esac; done
    case "$MODE" in export_slow|export_slow_delete_slow) hang; exit 1;; esac
    [ "$MODE" = export_succeeds ] && { printf 'FAKE-P12' > "$file"; exit 0; }
    # The real ctkcard exits 0 while refusing (observed on macOS 27.0).
    echo "Error: Private key with public key hash  <$hash> is hardware bounded and cannot be exported" >&2; exit 0;;
  delete-all-ctk-identities) : > "$DIR/FORBIDDEN_bulk_delete_called"; exit 1;;
  *) echo "fake sc_auth: unsupported $cmd" >&2; exit 64;;
esac
FAKE
chmod 700 "$ST/fake/sc_auth"

# ---------------------------------------------------------------- helpers
json_parses() {
  /usr/bin/osascript -l JavaScript -e 'function run(a){ObjC.import("Foundation");var s=$.NSString.stringWithContentsOfFileEncodingError(a[0],4,null);if(!s||s.isNil())throw "read";JSON.parse(s.js);return "ok"}' "$1" >/dev/null 2>&1
}
store_is_seed() { cmp -s "$ST/fake/store.tsv" "$ST/fake/seed.tsv"; }
no_fake_alive() {
  local p s
  while read -r p s; do alive_same "$p" "$s" && return 1; done < "$ST/fake/pids"
  return 0
}
no_bulk_delete() { [ ! -e "$ST/fake/FORBIDDEN_bulk_delete_called" ]; }
no_other_identity_in_artifacts() {  # owner/leftover identities never named in artifacts or record
  ! grep -r -q -F -e "$OWNER_LABEL" -e "$OWNER_HASH" -e "$OLD_LABEL" -e "$OLD_HASH" "$1"
}
no_local_time_in_artifacts() { ! LC_ALL=C grep -r -q -E '[0-9]{1,2}:[0-9]{2}.{0,4}[AP]M' "$1"; }  # BSD grep: '.' also matches U+202F bytes
rec_has() { grep -q -F -- "$2" "$1"; }
prepare() { cp "$ST/fake/seed.tsv" "$ST/fake/store.tsv"; echo "$1" > "$ST/fake/mode"; : > "$ST/fake/pids"; : > "$ST/fake/calls.log"; }
run_probe() {  # NAME -> runs probe in foreground, sets RC
  TMPDIR="$ST/tmp" HEIMDALL_P5_SELFTEST_SC_AUTH="$ST/fake/sc_auth" "$PROBE" --mode unlocked --sc-auth-timeout 5 \
    --out-dir "$ST/out-$1" > "$ST/$1.stdout" 2> "$ST/$1.stderr"
  RC=$?
}
start_probe_bg() {  # NAME -> starts probe in background, sets PP
  TMPDIR="$ST/tmp" HEIMDALL_P5_SELFTEST_SC_AUTH="$ST/fake/sc_auth" "$PROBE" --mode unlocked --sc-auth-timeout 120 \
    --out-dir "$ST/out-$1" > "$ST/$1.stdout" 2> "$ST/$1.stderr" &
  PP=$!
}
wait_call() {  # SUBCOMMAND: until the fake has been called with it (max 30 s)
  local i=0
  until grep -q "^$1\$" "$ST/fake/calls.log" 2>/dev/null || [ $i -ge 300 ]; do sleep 0.1; i=$((i+1)); done
}
common_checks() {  # NAME
  local r="$ST/out-$1/run-record.json"
  check "$1: record parses as JSON" json_parses "$r"
  check "$1: bulk delete never called" no_bulk_delete
  check "$1: no fake sc_auth or child process left" no_fake_alive
  check "$1: owner and leftover identities never named in artifacts" no_other_identity_in_artifacts "$ST/out-$1"
  check "$1: no local time of day in artifacts" no_local_time_in_artifacts "$ST/out-$1"
  check "$1: record carries no requirement IDs" rec_has "$r" '"requirement_ids": []'
  check "$1: record marks the fake sc_auth" rec_has "$r" '"selftest_fake_sc_auth": true'
}

log "g04_ctk_probe self-test: probe sha256 $(shasum -a 256 "$PROBE" | cut -d' ' -f1)"
# ---------------------------------------------------------------- static checks
check "probe passes bash -n under /bin/bash $(/bin/bash -c 'echo $BASH_VERSION')" /bin/bash -n "$PROBE"
check "probe never contains the bulk delete subcommand" test "$(grep -c 'delete-all' "$PROBE")" -eq 0
check "probe forces empty askpass answers (no terminal PIN prompt)" grep -q '^export SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=\$ASKPASS_NONE$' "$PROBE"
check "probe has no ownership fallback that skips the key checks" test "$(grep -c 'only_ctk_identity_in_store' "$PROBE")" -eq 0
check "probe has no \$(case ...) (bash 3.2 closes the substitution at the pattern's parenthesis)" test "$(grep -c '\$(case' "$PROBE")" -eq 0
# write_ssh_config under /bin/bash 3.2: SecurityKeyProvider only for sk keys, no stray shell text.
sed -n '/^write_ssh_config() {/,/^}/p' "$PROBE" > "$ST/wsc.sh"
cat > "$ST/wsc-run.sh" <<'EOF'
getv() { eval "printf '%s' \"\${V_$1_$2_$3:-}\""; }
T=$1; FX_PORT1=1; FX_PORT2=2; FX_KNOWN=/dev/null; KC_DYLIB=/usr/lib/ssh-keychain.dylib
V_R_sk_KALG=sk-ecdsa-sha2-nistp256@openssh.com; V_R_pkcs11_KALG=ecdsa-sha2-nistp256
. "$T/wsc.sh"
write_ssh_config sk default; write_ssh_config pkcs11 default
EOF
/bin/bash "$ST/wsc-run.sh" "$ST"
check "write_ssh_config (bash 3.2): sk config sets SecurityKeyProvider" grep -q '^  SecurityKeyProvider /usr/lib/ssh-keychain.dylib$' "$ST/ssh_config-sk-default"
check "write_ssh_config (bash 3.2): non-sk config has no SecurityKeyProvider" test "$(grep -c SecurityKeyProvider "$ST/ssh_config-pkcs11-default")" -eq 0
check "write_ssh_config (bash 3.2): no stray shell text in either config" test "$(cat "$ST/ssh_config-sk-default" "$ST/ssh_config-pkcs11-default" | grep -c -E 'printf|esac|getv')" -eq 0
check "write_ssh_config: ssh parses the sk config (ssh -G)" /usr/bin/ssh -G -F "$ST/ssh_config-sk-default" probe-target >/dev/null 2>&1
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck -S warning clean ($(shellcheck --version | sed -n 's/^version: //p'))" shellcheck -s bash -S warning "$PROBE"
else log "  SKIP shellcheck not installed"; fi

# ---------------------------------------------------------------- usage and hook guard
"$PROBE" --mode bogus >/dev/null 2>&1; RC=$?; check "usage: --mode bogus exits 2 (got $RC)" test "$RC" -eq 2
"$PROBE" --mode unlocked --samples 0 >/dev/null 2>&1; RC=$?; check "usage: --samples 0 exits 2 (got $RC)" test "$RC" -eq 2
HEIMDALL_P5_SELFTEST_SC_AUTH=/usr/bin/true "$PROBE" --mode unlocked >/dev/null 2>&1; RC=$?
check "hook guard: arbitrary path exits 2 (got $RC)" test "$RC" -eq 2
HEIMDALL_P5_SELFTEST_SC_AUTH="$ST/fake/sc_auth" "$PROBE" --mode lock >/dev/null 2>&1; RC=$?
check "hook guard: lock mode refused, exit 2 (got $RC)" test "$RC" -eq 2

# ---------------------------------------------------------------- scenarios
log "scenario normal"
prepare normal; run_probe normal; R="$ST/out-normal/run-record.json"
check "normal: exit 1 (self-test evidence is never verified; got $RC)" test "$RC" -eq 1
check "normal: fake store equals the seed afterwards" store_is_seed
check "normal: identity created" rec_has "$R" '"created": "yes"'
check "normal: pre-run identity count 2" rec_has "$R" '"pre_run_identity_count": 2'
check "normal: leftover prefix row counted, untouched" rec_has "$R" '"pre_run_rows_with_label_prefix": 1'
check "normal: export refused as hardware bounded (fake exits 0 like the real one)" rec_has "$R" '"message_class": "hardware_bounded_cannot_be_exported"'
check "normal: export rc 0 recorded" rec_has "$R" '"export_check": {"rc": 0,'
check "normal: export left no file" rec_has "$R" '"file_created": "absent"'
check "normal: own row gone after delete" rec_has "$R" '"own_row_absent_afterwards": true'
check "normal: identity list equals pre-run list" rec_has "$R" '"ctk_identity_list_vs_pre_run": "matches_pre_run"'
check "normal: cleanup complete" rec_has "$R" '"complete": true'
check "normal: clauses create/export/delete pass" rec_has "$R" '"clauses": {"create_noninteractive": "pass", "export_refused_no_file": "pass", "delete_by_exact_hash_list_restored": "pass"'
check "normal: own row kept, hash shortened" grep -q '<p5-hash:' "$ST/out-normal/identity-row.txt"
check "normal: own row's local time redacted" grep -q '<local-time>' "$ST/out-normal/identity-row.txt"
check "normal: chatty create output had other-identity lines removed" grep -q 'line naming another identity removed' "$ST/out-normal/sc_auth-create.out"
check "normal: own row survives in the create output" grep -q '<p5-hash:' "$ST/out-normal/sc_auth-create.out"
check "normal: exactly two other-identity lines removed" test "$(grep -c 'line naming another identity removed' "$ST/out-normal/sc_auth-create.out")" -eq 2
common_checks normal

log "scenario create_hang"
prepare create_hang; run_probe create_hang; R="$ST/out-create_hang/run-record.json"
check "create_hang: exit 6 blocked (got $RC)" test "$RC" -eq 6
check "create_hang: status blocked" rec_has "$R" '"status": "blocked"'
check "create_hang: create timed out" rec_has "$R" '"create_timed_out": true'
check "create_hang: exact PIDs terminated and named" grep -q 'child:[0-9]*:sleep' "$R"
check "create_hang: nothing created" rec_has "$R" '"own_identity": "none_created"'
check "create_hang: fake store equals the seed" store_is_seed
common_checks create_hang

log "scenario create_partial_hang"
prepare create_partial_hang; run_probe create_partial_hang; R="$ST/out-create_partial_hang/run-record.json"
check "create_partial_hang: exit 6 blocked (got $RC)" test "$RC" -eq 6
check "create_partial_hang: identity marked partial" rec_has "$R" '"created": "partial"'
check "create_partial_hang: identity deleted by cleanup" rec_has "$R" '"own_identity": "deleted"'
check "create_partial_hang: fake store equals the seed" store_is_seed
common_checks create_partial_hang

log "scenario export_succeeds"
prepare export_succeeds; run_probe export_succeeds; R="$ST/out-export_succeeds/run-record.json"
check "export_succeeds: exit 1 (got $RC)" test "$RC" -eq 1
check "export_succeeds: file removed and recorded" rec_has "$R" '"file_created": "created_then_removed_with_rm_P"'
check "export_succeeds: export clause fails" rec_has "$R" '"export_refused_no_file": "fail"'
check "export_succeeds: finding recorded" grep -q 'export-ctk-identity produced a file' "$R"
check "export_succeeds: fake store equals the seed" store_is_seed
common_checks export_succeeds

log "scenario delete_fails"
prepare delete_fails; run_probe delete_fails; R="$ST/out-delete_fails/run-record.json"
check "delete_fails: exit 4 cleanup incomplete (got $RC)" test "$RC" -eq 4
check "delete_fails: list mismatch reported" rec_has "$R" '"ctk_identity_list_vs_pre_run": "MISMATCH"'
check "delete_fails: identity reported as still present" rec_has "$R" '"own_identity": "STILL_PRESENT"'
check "delete_fails: temp dir kept for diagnosis" rec_has "$R" '"temp_dir": "kept_for_diagnosis"'
check "delete_fails: owner and leftover rows untouched" test "$(grep -c -F -e "$OWNER_HASH" -e "$OLD_HASH" "$ST/fake/store.tsv")" -eq 2
check "delete_fails: delete was attempted" test "$(grep -c '^delete-ctk-identity$' "$ST/fake/calls.log")" -ge 1
common_checks delete_fails

log "scenario non_empty_store (guard: other CTK identities present, nothing may be created)"
prepare normal; : > "$ST/fake/enforce_empty_store"; run_probe non_empty_store; rm -f "$ST/fake/enforce_empty_store"
R="$ST/out-non_empty_store/run-record.json"
check "non_empty_store: exit 6 blocked (got $RC)" test "$RC" -eq 6
check "non_empty_store: status blocked" rec_has "$R" '"status": "blocked"'
check "non_empty_store: create never called" test "$(grep -c '^create-ctk-identity$' "$ST/fake/calls.log")" -eq 0
check "non_empty_store: nothing created" rec_has "$R" '"created": "no"'
check "non_empty_store: fake store equals the seed" store_is_seed
common_checks non_empty_store

log "scenario interrupt (SIGTERM during an in-flight sc_auth export call)"
prepare export_slow; start_probe_bg interrupt; wait_call export-ctk-identity
sleep 1; kill -TERM "$PP"; wait "$PP"; RC=$?; R="$ST/out-interrupt/run-record.json"
check "interrupt: exit 5 (got $RC)" test "$RC" -eq 5
check "interrupt: record says interrupted" rec_has "$R" '"interrupted": true'
check "interrupt: identity deleted by cleanup" rec_has "$R" '"own_identity": "deleted"'
check "interrupt: fake store equals the seed" store_is_seed
common_checks interrupt

log "scenario interrupt_in_create (SIGTERM while create is in flight, after it wrote the identity)"
prepare create_partial_hang; start_probe_bg interrupt_in_create; wait_call create-ctk-identity
i=0; until [ "$(grep -c . "$ST/fake/store.tsv")" -gt 2 ] || [ $i -ge 100 ]; do sleep 0.1; i=$((i+1)); done
sleep 0.5; kill -TERM "$PP"; wait "$PP"; RC=$?; R="$ST/out-interrupt_in_create/run-record.json"
check "interrupt_in_create: exit 5 (got $RC)" test "$RC" -eq 5
check "interrupt_in_create: identity found by label and deleted" rec_has "$R" '"own_identity": "deleted"'
check "interrupt_in_create: fake store equals the seed" store_is_seed
common_checks interrupt_in_create

log "scenario double_signal (SIGTERM, then SIGHUP while cleanup is deleting; a repeated SIGTERM is deferred by bash while its own trap runs)"
prepare export_slow_delete_slow; start_probe_bg double_signal; wait_call export-ctk-identity
sleep 1; kill -TERM "$PP"; wait_call delete-ctk-identity; sleep 0.5; kill -HUP "$PP" 2>/dev/null; wait "$PP"; RC=$?; R="$ST/out-double_signal/run-record.json"
check "double_signal: exit 5 (got $RC)" test "$RC" -eq 5
check "double_signal: cleanup completed" rec_has "$R" '"complete": true'
check "double_signal: identity deleted" rec_has "$R" '"own_identity": "deleted"'
check "double_signal: late SIGHUP noted, cleanup not cut short" grep -q 'further TERM/HUP arrived during cleanup' "$R"
check "double_signal: fake store equals the seed" store_is_seed
common_checks double_signal

log "result: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ] && exit 0
exit 1
