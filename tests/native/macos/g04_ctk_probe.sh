#!/bin/bash
# Heimdall gate G04 / task M00-T04-g04-P5: owner-authorized macOS Secure Enclave CTK probe (P5).
#
# Question: can a NON-EXPORTABLE Secure Enclave CryptoTokenKit identity, created with
#   sc_auth create-ctk-identity -l heimdall-m00-p5-<hex> -k p-256-ne -t none
# serve as a Heimdall working key through /usr/lib/ssh-keychain.dylib loaded into a DEDICATED
# ssh-agent, authenticate to the disposable M00-T03 SSH fixture, stay non-exportable, and be
# removed cleanly? Lock mode adds P1-style sampling across an owner-driven screen lock
# (same sampling and evidence shape as tests/native/macos/g04_lock_probe.sh --mode lock).
#
# ssh-keychain.dylib offers two load paths; both are tried, each in its own dedicated agent:
#   pkcs11: ssh-add -s /usr/lib/ssh-keychain.dylib     (PKCS#11 provider, loaded by the agent)
#   sk:     ssh-add -K -S /usr/lib/ssh-keychain.dylib  (FIDO-style security-key provider)
#
# Authority: owner decision D4 (2026-10-06, docs/research/g04-managed-credentials.md section 9.1)
# allows creating, and then deleting, ONE CTK identity per run in the real user token store. That
# is the only change this probe makes outside its own temp dir:
#   - it lists CTK identities before creating anything and keeps that list only in a 0700 temp
#     file and as a digest in memory (never in artifacts or the record; only the count);
#   - it deletes ONLY by the exact public-key hash of the identity it created in this run, after
#     re-checking that exactly one row carries that hash and that the row carries its own unique
#     label; it never calls the bulk delete subcommand and never exports, modifies or uses any
#     other identity;
#   - after cleanup the identity list must equal the pre-run list byte for byte. If it does not,
#     the probe changes nothing more, keeps its temp dir for diagnosis and exits 4.
#
# Never touches: ~/.ssh (agents, ssh-add and ssh-keygen get HOME=<temp>; ssh gets -F <temp
# config>), the caller's SSH_AUTH_SOCK agent (unset), the login keychain, 1Password, or any host
# other than loopback fixture containers. ssh-keychain.dylib falls back to
# ~/.ssh/sshkeychain.plist when KEYCHAIN_CERTIFICATES is unset, so every agent and ssh-add gets
# KEYCHAIN_CERTIFICATES explicitly: the probe's own hash, or a random non-matching hash for the
# filter control. Kills only exact PIDs it started (start time + executable re-checked); on an
# sc_auth timeout it terminates that exact sc_auth PID and its direct children (expected: ctkcard).
#
# Side effect to know about: with the SmartCard pairing dialog enabled (sc_auth pairing_ui), macOS
# may offer to pair the new identity with your account. Dismiss it; do NOT pair. The probe compares
# a digest of your account's AuthenticationAuthority before and after and reports any change.
#
# Self-test hook (tests/native/macos/g04_ctk_probe_selftest.sh only): HEIMDALL_P5_SELFTEST_SC_AUTH
# replaces sc_auth with a fake that keeps its store in the self-test temp dir. In that mode the
# probe never loads ssh-keychain.dylib and never contacts the real token store.
#
# Compatible with macOS /bin/bash 3.2. Uses only tools shipped with macOS, plus Docker (optional,
# read-only `docker logs`/`docker port`) for server-side attribution of fixture logins.
set -u
umask 077
export LC_ALL=C

# v1 (sha256 623bfdca...) ran once on 2026-10-09 (tests/evidence/artifacts/g04/p5/20261009T053616Z-unlocked/);
# its exact bytes are kept as tests/evidence/artifacts/g04/p5/g04_ctk_probe-v1-as-run.sh.txt.
# v2 fixes what that run exposed (patch: tests/evidence/artifacts/g04/p5/probe-v1-to-v2.patch):
#   - ssh ignores an sk-type IdentityFile/CertificateFile unless SecurityKeyProvider is set, even
#     when the agent holds the key, so v1 never offered the key to ca1. v2 sets SecurityKeyProvider
#     (and KEYCHAIN_CERTIFICATES) for sk keys; the agent still does the signing.
#   - sc_auth export-ctk-identity exited 0 while refusing ("hardware bounded and cannot be
#     exported", no file). v2 judges the export check by "no file" plus that refusal message.
#   - ssh-add -K -S ignored KEYCHAIN_CERTIFICATES (a random non-matching hash still loaded the
#     identity). With other CTK identities present the load would also pull in identities this
#     probe did not create, so v2 stops before creating anything when the store is not empty.
# v3 follows an independent review of v2 and a rehearsal (patch: .../g04/p5/probe-v2-to-v3.patch):
#   - The v2 SecurityKeyProvider line used `case` inside $(...), which bash 3.2 cannot parse: every
#     generated ssh_config was broken. v3 computes the line first (rehearsal-v3-20261009T061500Z/).
#   - With a controlling terminal (lock mode), ssh-add's PIN prompt bypassed stdin and blocked on
#     /dev/tty (observed: tests/evidence/artifacts/g04/p5/h2-tty-prompt-check-20261009/). v3 forces
#     askpass to /usr/bin/true for every ssh tool, so an (empty) PIN never waits for a person.
#   - A loaded key is used only if it is proven to be this run's identity (EC-point hash equals the
#     CTK hash, or fingerprint equals sc_auth's SSH hash); the "only identity in store" fallback is
#     gone, and the probe stops before creating anything if a smart card or token is present
#     (ssh-keychain.dylib serves those too).
#   - Cleanup cannot be cut short by a second signal or a closed stderr pipe; an interrupted
#     create gets the same grace re-check as a timed-out one.
#   - Login attempts are classified (not offered / refused at query / refused after signature /
#     accepted); a requested login that was never actually offered makes the evidence invalid
#     instead of a silent fail. Per-clause results are written to the record. Lock-mode validity
#     requires the login controls and treats an owner-reported credential dialog as invalidating.
#   - The lock-mode certificate lives longer and samples taken after it expires are not counted
#     as login failures. Docker calls are time-bounded. Local times of day are redacted (macOS puts
#     U+202F, a narrow no-break space, before AM/PM; the pattern allows it).
#
# If a run is ever killed hard (kill -9, power loss) before cleanup, recover by hand, never in
# bulk: `sc_auth list-ctk-identities`, find the single row whose label is the run's
# heimdall-m00-p5-<hex> label (printed at start), then `sc_auth delete-ctk-identity -h <that
# row's hash>`; stop leftover dedicated agents only by the PIDs the run printed.
PROBE_VERSION="3"
SSH=/usr/bin/ssh; SSH_KEYGEN=/usr/bin/ssh-keygen; SSH_AGENT=/usr/bin/ssh-agent; SSH_ADD=/usr/bin/ssh-add
SC_AUTH=/usr/sbin/sc_auth; KC_DYLIB=/usr/lib/ssh-keychain.dylib
SK_HELPER=/usr/libexec/ssh-sk-helper; P11_HELPER=/usr/libexec/ssh-pkcs11-helper
IOREG=/usr/sbin/ioreg; CAFFEINATE=/usr/bin/caffeinate; OSASCRIPT=/usr/bin/osascript; DSCL=/usr/bin/dscl
SECURITY=/usr/bin/security; ASKPASS_NONE=/usr/bin/true
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS DISPLAY KEYCHAIN_CERTIFICATES
# Every PIN/passphrase/confirmation request from an ssh tool gets an empty answer at once, never a
# terminal prompt (readpassphrase would otherwise open /dev/tty even with stdin /dev/null).
export SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=$ASKPASS_NONE
# Assembled from two parts so this source never contains the contiguous project canary prefix.
CANARY_PREFIX="HEIMDALL""_CANARY_"
LABEL_PREFIX="heimdall-m00-p5-"
SIGN_NS="heimdall-g04-p5"
FX_CA1_CONTAINER="hm-m00t03-ca1"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SCRIPT_FILE="$SCRIPT_DIR/$(basename "$0")"
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd -P)

usage() {
  cat <<'EOF'
Usage: g04_ctk_probe.sh --mode unlocked|lock [options]

Creates ONE non-exportable Secure Enclave CTK identity (sc_auth create-ctk-identity -k p-256-ne
-t none, label heimdall-m00-p5-<random hex>), loads it through /usr/lib/ssh-keychain.dylib into
dedicated ssh-agents (PKCS#11 `ssh-add -s` and FIDO-style `ssh-add -K -S`, each limited by
KEYCHAIN_CERTIFICATES to that identity's hash, with a non-matching-hash filter control), signs,
optionally logs in to fixture ca1 with a short-lived certificate, checks that export fails,
deletes the identity by its exact hash, and verifies that the CTK identity list is back to its
pre-run state. Owner authorization: decision D4.

Modes (required):
  --mode unlocked     Non-interactive. Screen stays unlocked. Takes --samples samples after the
                      checks.
  --mode lock         Interactive (needs a terminal). Baseline samples, then asks you to lock the
                      screen (Control-Command-Q) for about --lock-seconds, then press Enter after
                      unlocking; takes post-unlock samples and asks two yes/no questions.

Options:
  --samples N              Samples in unlocked mode (1-50, default 3).
  --interval SEC           Seconds between samples (1-60, default 5).
  --pre-samples N          Lock mode: baseline samples before locking (1-20, default 3).
  --post-samples N         Lock mode: samples after you return (1-20, default 3).
  --lock-seconds SEC       Lock mode: how long to stay locked (10-3600, default 60). Advisory.
  --fixture-runtime DIR    M00-T03 fixture runtime (tests/fixtures/ssh/runtime after up.sh). Issues
                           a short-lived certificate (principal p-host1) for the CTK key with the
                           fixture CA and logs in to ca1 through the dedicated agent; ca2
                           (principal mismatch) and ca1 without the agent must be refused. Fresh
                           logins are also sampled.
  --sc-auth-timeout SEC    Timeout for each sc_auth call (5-300, default 60).
  --out-dir DIR            Artifact directory, must be empty or absent
                           (default tests/evidence/artifacts/g04/p5/<UTC stamp>-<mode>/).
  --record FILE            Run record path, must not exist (default <out-dir>/run-record.json).
  --no-caffeinate          Lock mode: do not hold an idle-sleep assertion during the run.
  -h, --help               Show this help.

Exit status: 0 status verified, verdict pass, cleanup complete; 1 completed but verdict fail or
evidence not valid; 2 usage error; 3 precondition or setup failure; 4 cleanup incomplete
(including a CTK identity list that differs from the pre-run list); 5 interrupted; 6 blocked
(identity creation failed, hung, or needed an interactive prompt).
EOF
}

die_usage() { printf 'g04_ctk_probe: %s\n' "$1" >&2; usage >&2; exit 2; }
is_uint() { case "$1" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }
in_range() { is_uint "$1" && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; }

MODE=""; SAMPLES_N=3; INTERVAL=5; PRE_SAMPLES=3; POST_SAMPLES=3; LOCK_SECONDS=60; SC_TO=60
FIXTURE_RUNTIME=""; OUT_DIR=""; RECORD=""; USE_CAFFEINATE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) [ $# -ge 2 ] || die_usage "--mode needs a value"; MODE=$2; shift 2;;
    --samples) [ $# -ge 2 ] || die_usage "--samples needs a value"; SAMPLES_N=$2; shift 2;;
    --interval) [ $# -ge 2 ] || die_usage "--interval needs a value"; INTERVAL=$2; shift 2;;
    --pre-samples) [ $# -ge 2 ] || die_usage "--pre-samples needs a value"; PRE_SAMPLES=$2; shift 2;;
    --post-samples) [ $# -ge 2 ] || die_usage "--post-samples needs a value"; POST_SAMPLES=$2; shift 2;;
    --lock-seconds) [ $# -ge 2 ] || die_usage "--lock-seconds needs a value"; LOCK_SECONDS=$2; shift 2;;
    --fixture-runtime) [ $# -ge 2 ] || die_usage "--fixture-runtime needs a value"; FIXTURE_RUNTIME=$2; shift 2;;
    --sc-auth-timeout) [ $# -ge 2 ] || die_usage "--sc-auth-timeout needs a value"; SC_TO=$2; shift 2;;
    --out-dir) [ $# -ge 2 ] || die_usage "--out-dir needs a value"; OUT_DIR=$2; shift 2;;
    --record) [ $# -ge 2 ] || die_usage "--record needs a value"; RECORD=$2; shift 2;;
    --no-caffeinate) USE_CAFFEINATE=0; shift;;
    -h|--help) usage; exit 0;;
    *) die_usage "unknown argument: $1";;
  esac
done
case "$MODE" in unlocked|lock) ;; "") die_usage "--mode is required";; *) die_usage "--mode must be unlocked or lock";; esac
in_range "$SAMPLES_N" 1 50 || die_usage "--samples must be 1..50"
in_range "$INTERVAL" 1 60 || die_usage "--interval must be 1..60"
in_range "$PRE_SAMPLES" 1 20 || die_usage "--pre-samples must be 1..20"
in_range "$POST_SAMPLES" 1 20 || die_usage "--post-samples must be 1..20"
in_range "$LOCK_SECONDS" 10 3600 || die_usage "--lock-seconds must be 10..3600"
in_range "$SC_TO" 5 300 || die_usage "--sc-auth-timeout must be 5..300"

SELFTEST=0
if [ -n "${HEIMDALL_P5_SELFTEST_SC_AUTH:-}" ]; then
  case "$HEIMDALL_P5_SELFTEST_SC_AUTH" in
    /*/heimdall-g04-p5-selftest.*/fake/sc_auth) ;;
    *) die_usage "HEIMDALL_P5_SELFTEST_SC_AUTH must be <self-test temp dir>/fake/sc_auth";;
  esac
  [ -x "$HEIMDALL_P5_SELFTEST_SC_AUTH" ] || die_usage "HEIMDALL_P5_SELFTEST_SC_AUTH is not executable"
  [ "$MODE" = unlocked ] || die_usage "self-test hook supports --mode unlocked only"
  [ -z "$FIXTURE_RUNTIME" ] || die_usage "self-test hook does not use --fixture-runtime"
  SC_AUTH=$HEIMDALL_P5_SELFTEST_SC_AUTH; SELFTEST=1
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RUN_START_EPOCH=$(date -u +%s)
if [ "$SELFTEST" -eq 1 ]; then CASE_ID="G04-macos-ctk-probe-selftest"
elif [ "$MODE" = unlocked ]; then CASE_ID="G04-macos-secure-enclave-ctk-unlocked"
else CASE_ID="G04-macos-secure-enclave-ctk-signing-under-lock"; fi
[ -n "$OUT_DIR" ] || OUT_DIR="$REPO_ROOT/tests/evidence/artifacts/g04/p5/$STAMP-$MODE"
[ -n "$RECORD" ] || RECORD="$OUT_DIR/run-record.json"

# ---------------------------------------------------------------- preconditions (no side effects yet)
pre_fail() { printf 'g04_ctk_probe: precondition failed: %s\n' "$1" >&2; exit 3; }
[ "$(uname -s)" = Darwin ] || pre_fail "this probe is macOS-only"
[ "$(id -u)" -ne 0 ] || pre_fail "do not run as root"
for t in "$SSH" "$SSH_KEYGEN" "$SSH_AGENT" "$SSH_ADD" "$SC_AUTH" "$IOREG" "$OSASCRIPT" "$DSCL" "$SECURITY" "$ASKPASS_NONE"; do
  [ -x "$t" ] || pre_fail "missing $t"
done
if [ "$SELFTEST" -eq 0 ]; then
  [ -f "$KC_DYLIB" ] || pre_fail "missing $KC_DYLIB"
  [ -x "$SK_HELPER" ] || pre_fail "missing $SK_HELPER"
  [ -x "$P11_HELPER" ] || pre_fail "missing $P11_HELPER"
fi
if [ "$MODE" = lock ]; then
  { : < /dev/tty; } 2>/dev/null || pre_fail "lock mode needs an interactive terminal (/dev/tty)"
  [ "$USE_CAFFEINATE" -eq 0 ] || [ -x "$CAFFEINATE" ] || pre_fail "missing $CAFFEINATE (or pass --no-caffeinate)"
fi
[ -e "$RECORD" ] && pre_fail "record already exists: $RECORD"
FX_PORT1=""; FX_PORT2=""; FX_KNOWN=""; FX_CAKEY=""
if [ -n "$FIXTURE_RUNTIME" ]; then
  [ -d "$FIXTURE_RUNTIME" ] || pre_fail "--fixture-runtime is not a directory"
  FIXTURE_RUNTIME=$(cd "$FIXTURE_RUNTIME" && pwd -P)
  # ports.env is data, never sourced: accept only numeric PORT_ca1/PORT_ca2 lines.
  FX_PORT1=$(sed -n 's/^PORT_ca1=\([0-9][0-9]*\)$/\1/p' "$FIXTURE_RUNTIME/ports.env" 2>/dev/null | head -1)
  FX_PORT2=$(sed -n 's/^PORT_ca2=\([0-9][0-9]*\)$/\1/p' "$FIXTURE_RUNTIME/ports.env" 2>/dev/null | head -1)
  in_range "${FX_PORT1:-x}" 1 65535 || pre_fail "fixture ports.env lacks a valid PORT_ca1"
  in_range "${FX_PORT2:-x}" 1 65535 || pre_fail "fixture ports.env lacks a valid PORT_ca2"
  FX_KNOWN="$FIXTURE_RUNTIME/known_hosts"; FX_CAKEY="$FIXTURE_RUNTIME/keys/user_ca"
  [ -f "$FX_KNOWN" ] || pre_fail "fixture known_hosts missing"
  { [ -f "$FX_CAKEY" ] && [ -f "$FX_CAKEY.pub" ]; } || pre_fail "fixture CA key pair missing"
  { grep -q '^hm-ca1 ' "$FX_KNOWN" && grep -q '^hm-ca2 ' "$FX_KNOWN"; } || pre_fail "fixture known_hosts lacks hm-ca1/hm-ca2"
  case "$FIXTURE_RUNTIME" in *'"'*|*[[:space:]]*) pre_fail "fixture path contains a quote or whitespace";; esac
fi
if [ -e "$OUT_DIR" ] && [ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]; then pre_fail "--out-dir is not empty: $OUT_DIR"; fi
mkdir -p "$OUT_DIR" || pre_fail "cannot create --out-dir"
OUT_DIR=$(cd "$OUT_DIR" && pwd -P)
mkdir -p "$(dirname "$RECORD")" || pre_fail "cannot create record directory"
RUNLOG="$OUT_DIR/run.log"; SAMPLES="$OUT_DIR/samples.ndjson"; SAMPLES_TSV="$OUT_DIR/samples.tsv"
: > "$RUNLOG"; : > "$SAMPLES"; : > "$SAMPLES_TSV"

# ---------------------------------------------------------------- state
T=""; LABEL=""; HASH=""; SSHHASH=""; BOGUS=""; OWN_FPS=""; RUN_TAG=""
USER_NAME=$(id -un); HOME_REAL=$HOME; HOST_SHORT=$(hostname -s 2>/dev/null); HOST_FULL=$(hostname 2>/dev/null)
LAUNCHD_SESSION=$(launchctl managername 2>/dev/null)
CREATE_ATTEMPTED=0; CREATE_RC=""; CREATE_TO=0; CREATED="no"; CREATE_KILLED=""
DELETE_RC=""; DELETE_TO=0; DELETED=0; DELETE_NOTE=""; STOP_STORE=0
EXPORT_RC=""; EXPORT_TO=0; EXPORT_FILE="not_checked"; EXPORT_CLASS="not_checked"
PRE_DIGEST=""; PRE_COUNT=""; PRE_PREFIX_ROWS=""; AA_DIGEST_BEFORE=""; AA_TOKENS_BEFORE=""; PAIRING_UI="not_checked"
SSHHASH_NOTE="not_parsed"
AGENT_NAMES=""; SAMPLER_PID=""; CAF_PID=""; CAF_IDENT=""; SC_PID=""; SC_TIMED_OUT=0; SC_KILLED=""
LATE_SIGNAL=0; FINISHED=0; INTERRUPTED=0; SETUP_OK=0; SETUP_FAILED=0; BLOCKED=0; BLOCKED_REASON=""; SETUP_NOTES=""; FINDINGS=""
CLEAN_SAMPLER="not_started"; CLEAN_AGENTS="not_started"; CLEAN_SOCKETS="not_applicable"; CLEAN_IDENTITY="not_applicable"
CLEAN_IDLIST="not_checked"; CLEAN_AA="not_checked"; CLEAN_EXPORT="not_applicable"; CLEAN_CAF="not_started"; CLEAN_TEMP="not_started"
LOCK_INSTRUCTED_EPOCH=""; OWNER_RETURNED_EPOCH=""; ATTEST_LOCK="not_asked"; ATTEST_DIALOG="not_asked"
CERT_VALIDITY="-1m:+10m"; CERT_MINUTES=10; CERT_EXPIRES_EPOCH=""; SAMPLES_AFTER_CERT_EXPIRY=0; SERVER_LOGS="not_collected"
PATHS="pkcs11 sk"

# Per-name values without associative arrays (bash 3.2). Group, name and field are script literals.
setv() { eval "V_$1_$2_$3=\$4"; }
getv() { eval "printf '%s' \"\${V_$1_$2_$3:-}\""; }

# ---------------------------------------------------------------- helpers
# redact: temp dir, home, user and host names, this run's identity hash (kept as an 8-char prefix),
# any other 40-64 hex token, and any SSH SHA256 fingerprint that is not one of this run's own keys.
redact() {
  local fp i=0 s
  s=$(awk -v t="${T:-@@none@@}" -v h="$HOME_REAL" -v u="$USER_NAME" -v hs="$HOST_SHORT" -v hf="$HOST_FULL" -v own="${HASH:-@@none@@}" -v fps="$OWN_FPS" '
    function rep(s, a, b,   i, out) { if (a == "" || length(a) < 4) return s; out = "";
      while ((i = index(s, a)) > 0) { out = out substr(s, 1, i - 1) b; s = substr(s, i + length(a)) } return out s }
    BEGIN { nf = split(fps, fp, " ") }
    { s = $0; s = rep(s, t, "<tmp>"); s = rep(s, h, "<home>"); s = rep(s, own, "@@OWNHASH@@")
      for (k = 1; k <= nf; k++) s = rep(s, fp[k], "@@OWNFP" k "@@")
      s = rep(s, hf, "<host>"); s = rep(s, hs, "<host>"); s = rep(s, u, "<user>"); print s }' |
    sed -E -e 's/[0-9A-Fa-f]{40,64}/<hex>/g' -e 's/[0-9]{1,2}:[0-9]{2}[^0-9A-Za-z]{0,4}[AaPp][Mm]/<local-time>/g' -e 's#SHA256:[A-Za-z0-9+/]{43}#SHA256:<other-fp>#g' -e "s/@@OWNHASH@@/<p5-hash:${HASH:0:8}>/g")
  for fp in $OWN_FPS; do i=$((i+1)); s=$(printf '%s\n' "$s" | sed "s#@@OWNFP$i@@#$fp#g"); done
  printf '%s\n' "$s"
}
log() {
  local line; line="$(date -u +%H:%M:%SZ) $*"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" | redact >> "$RUNLOG"
}
say_tty() { printf '%s\n' "$*" > /dev/tty; printf '%s [owner-prompt] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$RUNLOG"; }
keep() {  # keep FILE NAME: copy a command output into the artifacts, redacted
  [ -f "$1" ] || return 0
  redact < "$1" > "$OUT_DIR/$2"
}
keep_sc() {  # like keep, for sc_auth output: any line that names another identity's hash is dropped
  [ -f "$1" ] || return 0
  redact < "$1" | sed 's/.*<hex>.*/<line naming another identity removed>/' > "$OUT_DIR/$2"
}
json_str() {  # minimal JSON string encoder for short, mostly-ASCII fields
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
  printf '"%s"' "$s"
}
jn() {  # integer or null
  case "$1" in ''|na) printf 'null';; *) if is_uint "${1#-}"; then printf '%s' "$1"; else json_str "$1"; fi;; esac
}
relpath() { case "$1" in "$REPO_ROOT"/*) printf '%s' "${1#"$REPO_ROOT"/}";; *) printf '%s' "$1";; esac; }

# run_with_timeout SECS CMD...: runs CMD in the background and sends TERM to that exact child
# if it outlives SECS. The watcher's stdio is /dev/null so command substitution never waits on it.
run_with_timeout() {
  local secs=$1; shift
  "$@" &
  local cpid=$!
  ( sleep "$secs"; kill -TERM "$cpid" 2>/dev/null ) >/dev/null 2>&1 &
  local wpid=$!
  wait "$cpid" 2>/dev/null; local rc=$?
  kill -TERM "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
  return $rc
}
# Process identity = start time + executable. comm must be the LAST column: macOS ps truncates
# a non-final comm column.
proc_ident() { ps -o lstart= -o comm= -p "$1" 2>/dev/null | sed 's/  */ /g'; }
json_parses() {
  "$OSASCRIPT" -l JavaScript -e 'function run(a){ObjC.import("Foundation");var s=$.NSString.stringWithContentsOfFileEncodingError(a[0],4,null);if(!s||s.isNil())throw "read";JSON.parse(s.js);return "ok"}' "$1" >/dev/null 2>&1
}
kill_exact() {  # pid expected_ident -> echoes outcome; kills only if comm+lstart still match
  local pid=$1 ident=$2 now i
  [ -n "$pid" ] || { echo "not_started"; return; }
  now=$(proc_ident "$pid")
  if [ -z "$now" ]; then echo "already_exited"; return; fi
  if [ "$now" != "$ident" ]; then echo "pid_reused_not_killed"; return; fi
  kill -TERM "$pid" 2>/dev/null
  i=0; while [ $i -lt 50 ] && [ -n "$(proc_ident "$pid")" ]; do sleep 0.1; i=$((i+1)); done
  if [ -z "$(proc_ident "$pid")" ]; then echo "terminated"; else echo "still_running"; fi
}

# sc_abort: terminate the in-flight sc_auth process (exact PID we started) and its exact direct
# children (expected: ctkcard), re-checking each identity before a KILL escalation.
sc_abort() {
  local pid=$SC_PID c cident cname list="" i
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || { SC_PID=""; return 0; }
  for c in $(ps -A -o pid=,ppid= | awk -v p="$pid" '$2 == p {print $1}'); do
    cident=$(proc_ident "$c"); [ -n "$cident" ] || continue
    cname=${cident##* }; cname=${cname##*/}
    list="$list $c"; setv K "c$c" ID "$cident"
    kill -TERM "$c" 2>/dev/null && SC_KILLED="${SC_KILLED}child:$c:$cname "
  done
  kill -TERM "$pid" 2>/dev/null && SC_KILLED="${SC_KILLED}sc_auth:$pid "
  i=0; while [ $i -lt 30 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
  for c in $list; do
    if [ -n "$(proc_ident "$c")" ] && [ "$(proc_ident "$c")" = "$(getv K "c$c" ID)" ]; then
      kill -KILL "$c" 2>/dev/null && SC_KILLED="${SC_KILLED}KILL-child:$c "
    fi
  done
  wait "$pid" 2>/dev/null
  SC_PID=""
}
# sc_run SECS OUTFILE ARGS...: one sc_auth call, stdin /dev/null, bounded by SECS.
sc_run() {
  local secs=$1 out=$2 i rc; shift 2
  SC_TIMED_OUT=0; SC_KILLED=""
  "$SC_AUTH" "$@" </dev/null >"$out" 2>&1 &
  SC_PID=$!
  i=0; while kill -0 "$SC_PID" 2>/dev/null && [ $i -lt $((secs * 10)) ]; do sleep 0.1; i=$((i+1)); done
  if kill -0 "$SC_PID" 2>/dev/null; then
    SC_TIMED_OUT=1
    sc_abort
    log "sc_auth $1 timed out after ${secs}s; terminated exact PIDs: ${SC_KILLED:-none}"
    return 124
  fi
  wait "$SC_PID" 2>/dev/null; rc=$?
  SC_PID=""
  return $rc
}

hash_tokens() { tr -s ' \t' '\n' | grep -E '^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$'; }
label_rows() { awk -v l="$LABEL" '{ for (i = 1; i <= NF; i++) if ($i == l) { print; next } }' "$1"; }
RESOLVED_HASH=""; OWN_ROWS=0
resolve_own_hash() {  # fresh list; RESOLVED_HASH = the single hash token on rows carrying LABEL
  local f="$T/resolve.list" toks n
  RESOLVED_HASH=""; OWN_ROWS=0
  sc_run "$SC_TO" "$f" list-ctk-identities || return 1
  OWN_ROWS=$(label_rows "$f" | grep -c .)
  toks=$(label_rows "$f" | hash_tokens | sort -u)
  n=$(printf '%s' "$toks" | grep -c .)
  [ "$n" -eq 1 ] || return 1
  RESOLVED_HASH=$toks
}
own_row_ok() {  # LISTFILE: exactly one row contains HASH, and that row carries LABEL as a field
  local n m
  n=$(grep -c -F -- "$HASH" "$1")
  m=$(grep -F -- "$HASH" "$1" | awk -v l="$LABEL" '{ for (i = 1; i <= NF; i++) if ($i == l) { c++; next } } END { print c + 0 }')
  [ "$n" -eq 1 ] && [ "$m" -eq 1 ]
}
delete_own() {  # delete exactly this run's identity, by its exact hash, after the own-row check
  [ "$STOP_STORE" -eq 0 ] || { DELETE_NOTE="${DELETE_NOTE}store frozen after list mismatch; "; return 1; }
  [ -n "$HASH" ] || { DELETE_NOTE="${DELETE_NOTE}own hash unknown; "; return 1; }
  if ! sc_run "$SC_TO" "$T/own-check.list" list-ctk-identities; then
    DELETE_NOTE="${DELETE_NOTE}list before delete failed; "; return 1
  fi
  if ! own_row_ok "$T/own-check.list"; then
    DELETE_NOTE="${DELETE_NOTE}own-row check failed (not exactly one row with this hash and label), not deleted; "; return 1
  fi
  sc_run "$SC_TO" "$T/delete.out" delete-ctk-identity -h "$HASH"; DELETE_RC=$?; DELETE_TO=$SC_TIMED_OUT
  keep_sc "$T/delete.out" "sc_auth-delete.out"
  if sc_run "$SC_TO" "$T/after-delete.list" list-ctk-identities && ! grep -q -F -- "$HASH" "$T/after-delete.list"; then
    DELETED=1
  fi
  log "delete-ctk-identity -h <own hash> rc=$DELETE_RC timed_out=$DELETE_TO; own row absent afterwards: $([ "$DELETED" -eq 1 ] && echo yes || echo no)"
  [ "$DELETED" -eq 1 ]
}

# ---------------------------------------------------------------- dedicated agents
start_agent() {  # NAME FILTER: dedicated agent, socket and HOME in the temp dir, provider allow-list = the dylib only
  local name=$1 filt=$2 out pid ident home
  home="$T/home-$name"
  mkdir -m 700 "$home" || return 1
  out=$(/usr/bin/env HOME="$home" KEYCHAIN_CERTIFICATES="$filt" "$SSH_AGENT" -U -P "$KC_DYLIB" -a "$T/$name.sock" -s 2>/dev/null)
  pid=$(printf '%s\n' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9][0-9]*\);.*/\1/p')
  { [ -n "$pid" ] && [ -S "$T/$name.sock" ]; } || { log "ERROR: dedicated agent $name did not start"; return 1; }
  ident=$(proc_ident "$pid")
  case "$ident" in
    */ssh-agent) ;;
    *) log "ERROR: PID $pid reported for agent $name is not ssh-agent; it will NOT be killed. Check it manually."
       ident="unverified";;
  esac
  setv A "$name" PID "$pid"; setv A "$name" IDENT "$ident"; setv A "$name" FILTER "$filt"
  AGENT_NAMES="$AGENT_NAMES $name"
  log "dedicated ssh-agent $name pid=$pid (HOME=<tmp>/home-$name, -U, -P $KC_DYLIB, KEYCHAIN_CERTIFICATES=$([ "$filt" = "$BOGUS" ] && echo '<random non-matching hash>' || echo '<own hash>'))"
  [ "$ident" != unverified ]
}
run_in() {  # NAME SECS OUTFILE CMD...: CMD against agent NAME with its HOME and KEYCHAIN_CERTIFICATES
  local name=$1 secs=$2 out=$3; shift 3
  run_with_timeout "$secs" /usr/bin/env HOME="$T/home-$name" SSH_AUTH_SOCK="$T/$name.sock" \
    KEYCHAIN_CERTIFICATES="$(getv A "$name" FILTER)" SSH_ASKPASS_REQUIRE=force SSH_ASKPASS="$ASKPASS_NONE" "$@" </dev/null >"$out" 2>&1
}
key_count() {  # NAME -> echoes number of identities in that agent (-1 if the agent is unreachable)
  local rc
  run_in "$1" 15 "$T/$1-count.out" "$SSH_ADD" -l; rc=$?
  case $rc in 0) grep -c . "$T/$1-count.out";; 1) echo 0;; *) echo -1;; esac
}
load_cmd() {  # PATH -> the ssh-add arguments for that load path
  case "$1" in pkcs11) printf '%s' "-s $KC_DYLIB";; sk) printf '%s' "-K -S $KC_DYLIB";; esac
}
load_into() {  # PATH AGENTNAME OUTFILE -> rc of the ssh-add load
  case "$1" in
    pkcs11) run_in "$2" 60 "$3" "$SSH_ADD" -s "$KC_DYLIB";;
    sk) run_in "$2" 60 "$3" "$SSH_ADD" -K -S "$KC_DYLIB";;
  esac
}

# ---------------------------------------------------------------- cleanup
cleanup() {
  local i n final_digest aa_now name pid
  if [ -n "$SC_PID" ]; then sc_abort; log "cleanup: aborted an in-flight sc_auth call (${SC_KILLED:-nothing to kill})"; fi
  if [ -n "$SAMPLER_PID" ]; then
    [ -n "$T" ] && : > "$T/stop" 2>/dev/null
    i=0; while [ $i -lt 900 ] && kill -0 "$SAMPLER_PID" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
    if kill -0 "$SAMPLER_PID" 2>/dev/null; then kill -TERM "$SAMPLER_PID" 2>/dev/null; sleep 0.5; fi
    wait "$SAMPLER_PID" 2>/dev/null
    if kill -0 "$SAMPLER_PID" 2>/dev/null; then CLEAN_SAMPLER="still_running"; else CLEAN_SAMPLER="stopped"; fi
  fi
  # Agents first: nothing may keep using the identity while it is deleted.
  if [ -n "$AGENT_NAMES" ]; then
    CLEAN_AGENTS=""; CLEAN_SOCKETS=""
    for name in $AGENT_NAMES; do
      CLEAN_AGENTS="$CLEAN_AGENTS$name:$(kill_exact "$(getv A "$name" PID)" "$(getv A "$name" IDENT)") "
      if [ -S "$T/$name.sock" ]; then CLEAN_SOCKETS="$CLEAN_SOCKETS$name:still_present "; else CLEAN_SOCKETS="$CLEAN_SOCKETS$name:removed "; fi
    done
    CLEAN_AGENTS=${CLEAN_AGENTS% }; CLEAN_SOCKETS=${CLEAN_SOCKETS% }
  fi
  # This run's identity, by exact hash only.
  if [ "$CREATE_ATTEMPTED" -eq 1 ] && [ "$DELETED" -ne 1 ]; then
    if [ -z "$HASH" ]; then
      resolve_own_hash && HASH=$RESOLVED_HASH
      # A timed-out or interrupted create (CREATE_RC unset) may still complete in the token service.
      if [ -z "$HASH" ] && { [ "$CREATE_TO" -eq 1 ] || [ -z "$CREATE_RC" ]; }; then sleep 5; resolve_own_hash && HASH=$RESOLVED_HASH; fi
      [ -n "$HASH" ] && { [ "$CREATED" = no ] && CREATED="partial"; log "cleanup: found this run's identity (label match) after an incomplete create"; }
    fi
    if [ -n "$HASH" ]; then
      delete_own || { sleep 2; delete_own; }
      if [ "$DELETED" -eq 1 ]; then CLEAN_IDENTITY="deleted"; else CLEAN_IDENTITY="STILL_PRESENT"; fi
    elif [ "$OWN_ROWS" -gt 0 ]; then CLEAN_IDENTITY="STILL_PRESENT_HASH_UNRESOLVED"
    else CLEAN_IDENTITY="none_created"; fi
  elif [ "$DELETED" -eq 1 ]; then CLEAN_IDENTITY="deleted"; fi
  if [ -n "$PRE_DIGEST" ]; then
    if sc_run "$SC_TO" "$T/final.list" list-ctk-identities; then
      final_digest=$(shasum -a 256 < "$T/final.list" | cut -d' ' -f1)
      if [ "$final_digest" = "$PRE_DIGEST" ]; then CLEAN_IDLIST="matches_pre_run"; else CLEAN_IDLIST="MISMATCH"; STOP_STORE=1; fi
    else CLEAN_IDLIST="list_failed"; fi
  fi
  if [ -n "$AA_DIGEST_BEFORE" ]; then
    aa_now=$("$DSCL" . -read "/Users/$USER_NAME" AuthenticationAuthority 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
    if [ "$aa_now" = "$AA_DIGEST_BEFORE" ]; then CLEAN_AA="unchanged"; else CLEAN_AA="CHANGED"; fi
  fi
  if [ -n "$T" ] && [ "$EXPORT_FILE" != not_checked ]; then
    if [ -e "$T/export.p12" ]; then rm -P "$T/export.p12" 2>/dev/null; fi
    if [ -e "$T/export.p12" ]; then CLEAN_EXPORT="still_present"; else CLEAN_EXPORT="absent"; fi
  fi
  CLEAN_CAF=$(kill_exact "$CAF_PID" "$CAF_IDENT")
  if [ -n "$T" ] && [ -d "$T" ]; then
    if [ "$CLEAN_IDLIST" = MISMATCH ] || [ "$CLEAN_IDLIST" = list_failed ]; then
      CLEAN_TEMP="kept_for_diagnosis"
      printf 'g04_ctk_probe: CTK identity list check: %s. Nothing more was changed. Temp dir kept for diagnosis (0700): %s\n' "$CLEAN_IDLIST" "$T" >&2
    else
      rm -rf "$T"
      if [ -e "$T" ]; then CLEAN_TEMP="still_present"; else CLEAN_TEMP="removed"; fi
    fi
  fi
}
cleanup_complete() {
  case "$CLEAN_SAMPLER" in stopped|not_started) ;; *) return 1;; esac
  case "$CLEAN_AGENTS" in *still_running*|*pid_reused*) return 1;; esac
  case "$CLEAN_SOCKETS" in *still_present*) return 1;; esac
  case "$CLEAN_IDENTITY" in deleted|none_created|not_applicable) ;; *) return 1;; esac
  case "$CLEAN_IDLIST" in matches_pre_run|not_checked) ;; *) return 1;; esac
  case "$CLEAN_AA" in unchanged|not_checked) ;; *) return 1;; esac
  case "$CLEAN_EXPORT" in absent|not_applicable) ;; *) return 1;; esac
  case "$CLEAN_CAF" in terminated|already_exited|not_started) ;; *) return 1;; esac
  case "$CLEAN_TEMP" in removed|not_started) ;; *) return 1;; esac
  return 0
}

# ---------------------------------------------------------------- finish: cleanup, analyse, record
AGG=""
getn() { local v; v=$(printf '%s\n' "$AGG" | awk -v k="$1" -v p="$2" -v f="$3" '$1 == k && $2 == p { print $f }'); printf '%s' "${v:-0}"; }
outcome() {
  local n=${1:-0} ok=${2:-0}
  if [ "$n" -eq 0 ]; then echo not_measured
  elif [ "$ok" -eq "$n" ]; then echo available_all_samples
  elif [ "$ok" -eq 0 ]; then echo unavailable_all_samples
  else echo intermittent; fi
}
path_json() {
  local p=$1
  printf '{"load_command": %s, "load_rc": %s, "load_output_class": %s, "keys_listed_after_load": %s, "key_algorithm": %s, "fingerprint": %s, "fingerprint_vs_sc_auth_ssh_hash": %s, "ec_point_hash_vs_own_hash": %s, "ownership_basis": %s, ' \
    "$(json_str "ssh-add $(load_cmd "$p")")" "$(jn "$(getv R "$p" LOAD_RC)")" "$(json_str "$(getv R "$p" LOAD_CLASS)")" "$(jn "$(getv R "$p" KEYS)")" \
    "$(json_str "$(getv R "$p" KALG)")" "$(json_str "$(getv R "$p" FP)")" "$(json_str "$(getv R "$p" FPMATCH)")" \
    "$(json_str "$(getv R "$p" PKMATCH)")" "$(json_str "$(getv R "$p" OWNBASIS)")"
  printf '"ssh_add_T_rc": %s, "ssh_keygen_Y_sign_rc": %s, "signature_check_rc": %s, ' \
    "$(jn "$(getv R "$p" TRC)")" "$(jn "$(getv R "$p" SIGNRC)")" "$(jn "$(getv R "$p" VERRC)")"
  printf '"login_ca1_default_cert_rc": %s, "login_ca1_no_touch_required_cert_rc": %s, "cert_variant_used": %s, "neg_ca2_principal_mismatch_rc": %s, "neg_ca1_without_agent_rc": %s, ' \
    "$(jn "$(getv R "$p" LOGDEF)")" "$(jn "$(getv R "$p" LOGNT)")" "$(json_str "$(getv R "$p" VARIANT)")" "$(jn "$(getv R "$p" NEG2)")" "$(jn "$(getv R "$p" NEGNA)")"
  printf '"login_class": {"default_cert": %s, "no_touch_required_cert": %s, "ca2_control": %s, "no_agent_control": %s, "measured": %s, "controls_refused": %s}, ' \
    "$(json_str "$(getv R "$p" LOGDEFCLS)")" "$(json_str "$(getv R "$p" LOGNTCLS)")" "$(json_str "$(getv R "$p" NEG2CLS)")" "$(json_str "$(getv R "$p" NEGNACLS)")" \
    "$([ "$(getv R "$p" LOGMEASURED)" = 1 ] && echo true || echo false)" "$([ "$(getv R "$p" CTRLOK)" = 1 ] && echo true || echo false)"
  printf '"server_accepted_logins_with_run_key_ids": %s, "server_user_presence_rejections": %s, ' "$(jn "$(getv R "$p" SRVACC)")" "$(jn "$(getv R "$p" SRVUP)")"
  printf '"filter_control_non_matching_hash": {"load_rc": %s, "keys_listed": %s, "ssh_add_D_rc": %s}, ' "$(jn "$(getv R "$p" CTLRC)")" "$(jn "$(getv R "$p" CTLKEYS)")" "$(jn "$(getv R "$p" CTLDRC)")"
  printf '"after_identity_delete": {"keys_listed": %s, "ssh_add_T_rc": %s, "ssh_keygen_Y_sign_rc": %s}, ' "$(jn "$(getv R "$p" POSTKEYS)")" "$(jn "$(getv R "$p" POSTTRC)")" "$(jn "$(getv R "$p" POSTSIGN)")"
  printf '"works_unlocked": %s, "note": %s}' "$( [ "$(getv R "$p" WORKS)" = 1 ] && echo true || echo false)" "$(json_str "$(getv R "$p" NOTE)")"
}

finish() {
  [ "$FINISHED" -eq 0 ] || return 0
  FINISHED=1
  # Cleanup must not be cut short. INT/QUIT (terminal) and PIPE are ignored, also by the children
  # cleanup starts; TERM/HUP only set a flag, so sc_abort can still terminate an sc_auth child.
  trap '' INT QUIT PIPE; trap 'LATE_SIGNAL=1' TERM HUP; trap - EXIT
  cleanup
  [ "$LATE_SIGNAL" -eq 1 ] && SETUP_NOTES="${SETUP_NOTES}a further TERM/HUP arrived during cleanup and was ignored; "
  log "cleanup: sampler=$CLEAN_SAMPLER agents=[$CLEAN_AGENTS] sockets=[$CLEAN_SOCKETS] identity=$CLEAN_IDENTITY identity_list=$CLEAN_IDLIST authentication_authority=$CLEAN_AA export_file=$CLEAN_EXPORT caffeinate=$CLEAN_CAF temp_dir=$CLEAN_TEMP"

  # TSV: seq phase epoch ioc cgs | pkcs11: add sign ver ssh | sk: add sign ver ssh
  AGG=$(awk -F'\t' '
    { ph = $2; locked = ($4 == "true" || $5 == "true"); if (locked) Lall++
      for (k = 0; k < 2; k++) { b = 6 + 4 * k; if ($b == "na") continue; key = ph SUBSEP k
        n[key]++; a = ($b == "0" && $(b+1) == "0" && $(b+2) == "0"); na[key] += a
        if ($(b+3) != "na") { sn[key]++; s[key] += ($(b+3) == "0") }
        if (locked) { L[k]++; La[k] += a; if ($(b+3) != "na") { Lsn[k]++; Ls[k] += ($(b+3) == "0") } } }
      if (prev != "") { g = $3 - prev; if (g > maxgap) maxgap = g } prev = $3; total++ }
    END { split("unlocked pre lock_window post", P, " ")
      for (i = 1; i <= 4; i++) for (k = 0; k < 2; k++) { key = P[i] SUBSEP k
        printf "%s %s %d %d %d %d\n", P[i], (k == 0 ? "pkcs11" : "sk"), n[key] + 0, na[key] + 0, sn[key] + 0, s[key] + 0 }
      for (k = 0; k < 2; k++) printf "locked_signal %s %d %d %d %d\n", (k == 0 ? "pkcs11" : "sk"), L[k] + 0, La[k] + 0, Lsn[k] + 0, Ls[k] + 0
      printf "meta all %d %d %d 0\n", total + 0, maxgap + 0, Lall + 0 }' "$SAMPLES_TSV" 2>/dev/null)
  local total maxgap lall src="" lock_evidence="not_applicable" p win_n win_a win_sn win_s
  total=$(getn meta all 3); maxgap=$(getn meta all 4); lall=$(getn meta all 5)
  if [ "$MODE" = unlocked ]; then src=unlocked
  elif [ "$lall" -ge 2 ]; then src=locked_signal; lock_evidence="ioreg_lock_signal"
  elif [ "$ATTEST_LOCK" = yes ] && { [ "$(getn lock_window pkcs11 3)" -ge 2 ] || [ "$(getn lock_window sk 3)" -ge 2 ]; }; then src=lock_window; lock_evidence="owner_attestation_only"
  else lock_evidence="not_established"; fi
  local active=0 all_avail=1 leak="clean" status="in_progress" verdict="inconclusive" valid=0 criterion summary exit_code reqs pathsumm=""
  local login_unmeasured=0 lock_login_unmeasurable=0 controls_failed=0 vnotes=""
  local c_create c_export c_delete c_sign="not_measured" c_limit="not_measured" c_login="not_requested" sign_bad=0 limit_bad=0 login_ok=0 login_meas=0
  for p in $PATHS; do
    win_n=0; win_a=0; win_sn=0; win_s=0
    if [ -n "$src" ]; then win_n=$(getn "$src" "$p" 3); win_a=$(getn "$src" "$p" 4); win_sn=$(getn "$src" "$p" 5); win_s=$(getn "$src" "$p" 6); fi
    setv O "$p" AGENT "$(outcome "$win_n" "$win_a")"; setv O "$p" SSH "$(outcome "$win_sn" "$win_s")"; setv O "$p" N "$win_n"
    if [ -n "$(getv R "$p" VARIANT)" ] && [ "$(getv R "$p" NEG2)" != 0 ] && [ "$(getv R "$p" NEGNA)" != 0 ]; then setv R "$p" CTRLOK 1; fi
    if [ "$(getv R "$p" SAMPLED)" = 1 ]; then
      active=$((active+1))
      [ "$(getv O "$p" AGENT)" = available_all_samples ] || all_avail=0
      if [ -n "$(getv R "$p" VARIANT)" ]; then [ "$(getv O "$p" SSH)" = available_all_samples ] || all_avail=0; fi
      if [ -n "$FIXTURE_RUNTIME" ]; then
        [ "$(getv R "$p" LOGMEASURED)" = 1 ] || login_unmeasured=1
        [ -n "$(getv R "$p" VARIANT)" ] || lock_login_unmeasurable=1
        if [ -n "$(getv R "$p" VARIANT)" ] && [ "$(getv R "$p" CTRLOK)" != 1 ]; then controls_failed=1; fi
      fi
      # Per-path summary for unlocked mode (informational; the verdict uses the clauses below).
      if [ "$(getv O "$p" AGENT)" = available_all_samples ] && [ -n "$(getv R "$p" OWNBASIS)" ]; then
        if [ -z "$FIXTURE_RUNTIME" ]; then setv R "$p" WORKS 1
        elif [ "$(getv R "$p" CTRLOK)" = 1 ] && [ "$(getv O "$p" SSH)" = available_all_samples ]; then setv R "$p" WORKS 1; fi
      fi
      # Clause inputs, over paths that loaded this run's key.
      [ "$(getv O "$p" AGENT)" = available_all_samples ] && c_sign=pass
      [ "$(getv O "$p" AGENT)" = available_all_samples ] || sign_bad=1
      if [ "$(getv R "$p" CTLKEYS)" = 0 ]; then [ "$c_limit" = not_measured ] && c_limit=pass; else limit_bad=1; fi
      [ "$(getv R "$p" LOGMEASURED)" = 1 ] && login_meas=1
      if [ "$(getv R "$p" CTRLOK)" = 1 ] && [ "$(getv O "$p" SSH)" = available_all_samples ]; then login_ok=1; fi
    fi
    pathsumm="$pathsumm $p: load_rc=$(getv R "$p" LOAD_RC) keys=$(getv R "$p" KEYS) alg=$(getv R "$p" KALG) sign=$(getv O "$p" AGENT) login=$(getv O "$p" SSH) login_class=$(getv R "$p" LOGDEFCLS)$([ -n "$(getv R "$p" LOGNTCLS)" ] && echo "/$(getv R "$p" LOGNTCLS)") variant=$(getv R "$p" VARIANT) works=$([ "$(getv R "$p" WORKS)" = 1 ] && echo yes || echo no);"
  done
  # Clauses of the unlocked criterion (pass | fail | not_measured | not_requested).
  if [ "$CREATED" = yes ] && [ "$CREATE_TO" -eq 0 ]; then c_create=pass; elif [ "$CREATE_ATTEMPTED" -eq 1 ]; then c_create=fail; else c_create=not_measured; fi
  if [ "$EXPORT_FILE" = absent ] && [ "$EXPORT_CLASS" = hardware_bounded_cannot_be_exported ]; then c_export=pass
  elif [ "$EXPORT_FILE" = not_checked ]; then c_export=not_measured; else c_export=fail; fi
  if [ "$DELETED" -eq 1 ] && [ "$CLEAN_IDLIST" = matches_pre_run ]; then c_delete=pass; elif [ "$CREATE_ATTEMPTED" -eq 1 ]; then c_delete=fail; else c_delete=not_measured; fi
  if [ "$active" -eq 0 ] && [ "$CREATED" = yes ] && [ "$SELFTEST" -eq 0 ]; then c_sign=fail
  elif [ "$active" -gt 0 ] && [ "$c_sign" != pass ]; then c_sign=fail; fi
  [ "$sign_bad" -eq 1 ] && [ "$c_sign" = pass ] && vnotes="${vnotes}one load path signed in every sample, another did not; "
  [ "$limit_bad" -eq 1 ] && c_limit=fail
  if [ -n "$FIXTURE_RUNTIME" ]; then
    if [ "$login_ok" -eq 1 ]; then c_login=pass; elif [ "$login_meas" -eq 1 ]; then c_login=fail; else c_login=not_measured; fi
  fi
  [ "$SAMPLES_AFTER_CERT_EXPIRY" -eq 1 ] && vnotes="${vnotes}login samples taken after the certificate expired were not counted; "

  if grep -r -l -F "$CANARY_PREFIX" "$OUT_DIR" >/dev/null 2>&1; then leak="LEAK_DETECTED"; fi
  if [ "$MODE" = unlocked ]; then
    criterion="Unlocked (screen stays unlocked), conjunction of clauses (observed_result.clauses): create_noninteractive = sc_auth creates the p-256-ne -t none CTK identity without timing out (stdin /dev/null, askpass answers empty); export_refused_no_file = export-ctk-identity creates no file and prints the hardware-bound refusal (its exit status, observed 0 on refusal, is recorded, not judged); delete_by_exact_hash_list_restored = delete-ctk-identity by the exact hash removes it and the identity list equals the pre-run list; dedicated_agent_signing = at least one /usr/lib/ssh-keychain.dylib load path (PKCS#11 ssh-add -s, FIDO-style ssh-add -K -S) puts this run's key (ownership proven by EC-point hash or fingerprint) into a dedicated agent that signs (ssh-add -T, ssh-keygen -Y sign + check-novalidate) in every setup check and sample, and every path that loaded it does; keychain_certificates_limit = for every path that loaded the key, the same load with a random non-matching KEYCHAIN_CERTIFICATES loads zero keys; fixture_login_with_controls (only with --fixture-runtime) = a fresh certificate login to ca1 through the dedicated agent succeeds in setup and every sample while the ca2 principal-mismatch and ca1-without-agent controls are refused. Verdict pass if every applicable clause passes, fail if any clause fails. Validity: completed without interruption, a requested login was actually offered to the server, controls refused, identity list equal to the pre-run list, AuthenticationAuthority unchanged, agents and temp dir gone, no canary."
  else
    criterion="Lock (A03 substrate, owner-driven screen lock): in the established lock window every CTK load path that signed before the lock signs through its dedicated agent in every sample and, with --fixture-runtime, the fresh ca1 login succeeds in every sample taken while its certificate is valid. Validity: lock window established (IORegistry signal or owner attestation, not denied by the owner), at least one baseline and one post-unlock sample, with --fixture-runtime a login that worked before the lock and refused ca2/no-agent controls, no credential dialog reported by the owner, completed, identity deleted and identity list equal to the pre-run list, AuthenticationAuthority unchanged, agents and temp dir gone, no canary."
  fi
  if [ "$BLOCKED" -eq 1 ]; then status="blocked"
  elif [ "$INTERRUPTED" -eq 0 ] && [ "$SETUP_OK" -eq 1 ] && cleanup_complete && [ "$leak" = clean ] && [ "$SELFTEST" -eq 0 ]; then
    if [ "$MODE" = unlocked ]; then
      valid=1
      # A requested login that never reached the server (key not offered, no connection) is a harness
      # gap, not a measurement.
      if [ -n "$FIXTURE_RUNTIME" ] && [ "$login_unmeasured" -eq 1 ]; then valid=0; vnotes="${vnotes}fixture login requested but not measured (not offered or no connection); "; fi
      if [ "$controls_failed" -eq 1 ]; then valid=0; vnotes="${vnotes}a login negative control was not refused; "; fi
      verdict=pass
      for cl in "$c_create" "$c_export" "$c_delete" "$c_sign" "$c_limit" "$c_login"; do
        case "$cl" in fail) verdict=fail;; not_measured) [ "$verdict" = pass ] && verdict=inconclusive_clause;; esac
      done
      [ "$verdict" = inconclusive_clause ] && { verdict=inconclusive; valid=0; vnotes="${vnotes}a clause was not measured; "; }
    else
      case "$lock_evidence" in ioreg_lock_signal|owner_attestation_only) valid=1;; esac
      [ "$ATTEST_LOCK" = no ] && valid=0
      { [ "$(getn pre pkcs11 3)" -ge 1 ] || [ "$(getn pre sk 3)" -ge 1 ]; } || valid=0
      { [ "$(getn post pkcs11 3)" -ge 1 ] || [ "$(getn post sk 3)" -ge 1 ]; } || valid=0
      [ "$active" -ge 1 ] || valid=0
      if [ -n "$FIXTURE_RUNTIME" ] && [ "$lock_login_unmeasurable" -eq 1 ]; then valid=0; vnotes="${vnotes}fixture login requested but no login worked before the lock, so the window cannot show a lock effect; "; fi
      if [ "$controls_failed" -eq 1 ]; then valid=0; vnotes="${vnotes}a login negative control was not refused; "; fi
      if [ "$ATTEST_DIALOG" = yes ]; then valid=0; vnotes="${vnotes}owner reported a Touch ID/password/pairing/keychain dialog during the run; needs review; "; fi
      if [ "$valid" -eq 1 ]; then verdict=pass; [ "$all_avail" -eq 1 ] || verdict=fail; fi
    fi
  fi
  [ "$valid" -eq 1 ] && status="verified"
  # Not verified: inconclusive, except that in unlocked mode a validly failed clause fails the
  # conjunction even when another clause left the evidence incomplete (status stays in_progress).
  if [ "$status" != verified ] && ! { [ "$MODE" = unlocked ] && [ "$verdict" = fail ] && [ "$BLOCKED" -eq 0 ] \
       && [ "$INTERRUPTED" -eq 0 ] && [ "$SETUP_OK" -eq 1 ] && [ "$SELFTEST" -eq 0 ] && cleanup_complete; }; then
    verdict="inconclusive"
  fi
  if [ "$SELFTEST" -eq 1 ] || [ "$MODE" = unlocked ]; then reqs='[]'; else reqs='["R-CR-02", "R-CR-03", "R-EN-04"]'; fi
  local cc=false; cleanup_complete && cc=true
  summary="mode=$MODE; identity created=$CREATED (create_rc=${CREATE_RC:-none}, timed_out=$CREATE_TO); export_rc=${EXPORT_RC:-none} export_file=$EXPORT_FILE ($EXPORT_CLASS); deleted=$([ "$DELETED" -eq 1 ] && echo yes || echo no);$pathsumm samples=$total; lock_window_evidence=$lock_evidence; identity_list_after_cleanup=$CLEAN_IDLIST; cleanup_complete=$cc; canary_scan=$leak."
  [ "$BLOCKED" -eq 1 ] && summary="BLOCKED: $BLOCKED_REASON. $summary"
  [ "$SETUP_FAILED" -eq 1 ] && summary="SETUP FAILED: ${SETUP_NOTES}$summary"
  [ "$INTERRUPTED" -eq 1 ] && summary="INTERRUPTED before completion. $summary"
  [ "$SELFTEST" -eq 1 ] && summary="SELF-TEST with a fake sc_auth (no real token store, no ssh-keychain.dylib). $summary"

  if [ "$cc" != true ] || [ "$leak" != clean ]; then exit_code=4
  elif [ "$INTERRUPTED" -eq 1 ]; then exit_code=5
  elif [ "$BLOCKED" -eq 1 ]; then exit_code=6
  elif [ "$SETUP_FAILED" -eq 1 ]; then exit_code=3
  elif [ "$status" = verified ] && [ "$verdict" = pass ]; then exit_code=0
  else exit_code=1; fi
  log "result: status=$status verdict=$verdict; $summary"

  local osv osb arch model sshv commit ref script_sha args lock_secs_obs=null blocked_on=null
  osv=$(sw_vers -productVersion 2>/dev/null); osb=$(sw_vers -buildVersion 2>/dev/null); arch=$(uname -m)
  model=$(sysctl -n hw.model 2>/dev/null); sshv=$("$SSH" -V 2>&1 | head -1)
  commit=null
  if [ -f "$REPO_ROOT/.git/HEAD" ]; then
    ref=$(sed -n 's/^ref: //p' "$REPO_ROOT/.git/HEAD")
    if [ -n "$ref" ] && [ -f "$REPO_ROOT/.git/$ref" ]; then commit=$(json_str "$(cat "$REPO_ROOT/.git/$ref")")
    elif [ -z "$ref" ]; then commit=$(json_str "$(cat "$REPO_ROOT/.git/HEAD")"); fi
  fi
  script_sha=$(shasum -a 256 "$SCRIPT_FILE" | cut -d' ' -f1)
  args="--mode $MODE --interval $INTERVAL --sc-auth-timeout $SC_TO"
  if [ "$MODE" = unlocked ]; then args="$args --samples $SAMPLES_N"
  else args="$args --pre-samples $PRE_SAMPLES --post-samples $POST_SAMPLES --lock-seconds $LOCK_SECONDS"; fi
  [ -n "$FIXTURE_RUNTIME" ] && args="$args --fixture-runtime $(relpath "$FIXTURE_RUNTIME")"
  [ "$MODE" = lock ] && [ "$USE_CAFFEINATE" -eq 0 ] && args="$args --no-caffeinate"
  [ -n "$LOCK_INSTRUCTED_EPOCH" ] && [ -n "$OWNER_RETURNED_EPOCH" ] && lock_secs_obs=$((OWNER_RETURNED_EPOCH - LOCK_INSTRUCTED_EPOCH))
  [ "$BLOCKED" -eq 1 ] && blocked_on=$(json_str "$BLOCKED_REASON")
  local own_row="" sep
  [ -f "$OUT_DIR/identity-row.txt" ] && own_row=$(head -3 "$OUT_DIR/identity-row.txt")

  {
    printf '{\n'
    printf '  "case_id": %s,\n' "$(json_str "$CASE_ID")"
    printf '  "status": "%s",\n' "$status"
    printf '  "requirement_ids": %s,\n' "$reqs"
    printf '  "build_commit": %s,\n' "$commit"
    printf '  "artifact_digest": %s,\n' "$(json_str "sha256:$script_sha (tests/native/macos/g04_ctk_probe.sh v$PROBE_VERSION as run)")"
    printf '  "environment": {"platform": "macOS", "os_version": %s, "os_build": %s, "arch": %s, "hardware_model": %s, "bash": %s, "native_host": true, "launchd_session": %s, "human_driven_lock": %s, "selftest_fake_sc_auth": %s},\n' \
      "$(json_str "$osv")" "$(json_str "$osb")" "$(json_str "$arch")" "$(json_str "$model")" "$(json_str "$BASH_VERSION")" "$(json_str "${LAUNCHD_SESSION:-unknown}")" \
      "$([ "$MODE" = lock ] && echo true || echo false)" "$([ "$SELFTEST" -eq 1 ] && echo true || echo false)"
    printf '  "provider_versions": [{"component": "ssh-agent, ssh-add, ssh-keygen, ssh (/usr/bin)", "version": %s}, {"component": "sc_auth / ctkcard, /usr/lib/ssh-keychain.dylib, ssh-sk-helper, ssh-pkcs11-helper", "version": %s}],\n' \
      "$(json_str "$sshv")" "$(json_str "macOS $osv ($osb), shipped with the OS")"
    printf '  "started_at": "%s",\n' "$STARTED_AT"
    printf '  "commands_or_harness": [\n'
    printf '    %s,\n' "$(json_str "tests/native/macos/g04_ctk_probe.sh $args")"
    printf '    %s,\n' "$(json_str "before: sc_auth list-ctk-identities (kept only in a 0700 temp file + SHA-256 in memory; count recorded; stop if not empty); security list-smartcards (count only; stop if any); dscl . -read /Users/<user> AuthenticationAuthority (SHA-256 in memory only); sc_auth pairing_ui -s status")"
    printf '    %s,\n' "$(json_str "create: sc_auth create-ctk-identity -l heimdall-m00-p5-<16 hex> -k p-256-ne -t none (stdin /dev/null, timeout ${SC_TO}s); own hash = the single 40/64-hex token on the row(s) carrying the label; sc_auth list-ctk-identities -t ssh -e b64 for the SSH hash")"
    printf '    %s,\n' "$(json_str "filter control: per load path a dedicated agent with KEYCHAIN_CERTIFICATES=<random non-matching hash>; ssh-add -s /usr/lib/ssh-keychain.dylib and ssh-add -K -S /usr/lib/ssh-keychain.dylib; ssh-add -l")"
    printf '    %s,\n' "$(json_str "per load path: HOME=<tmp>/home-<path> KEYCHAIN_CERTIFICATES=<own hash> /usr/bin/ssh-agent -U -P /usr/lib/ssh-keychain.dylib -a <tmp>/<path>.sock; every ssh tool runs with stdin /dev/null and SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=/usr/bin/true (empty PIN, never a terminal prompt); ssh-add -s|-K -S /usr/lib/ssh-keychain.dylib; ssh-add -l/-L; ssh-add -T; ssh-keygen -Y sign -n $SIGN_NS + -Y check-novalidate")"
    printf '    %s,\n' "$(json_str "$([ -n "$FIXTURE_RUNTIME" ] && echo "login: ssh-keygen -s <fixture CA> -I heimdall-g04-p5-<run>-<path>-<variant> -n p-host1 -V $CERT_VALIDITY [-O no-touch-required, sk keys only, only after the default certificate was refused] <agent pubkey>; /usr/bin/ssh -F <tmp ssh_config> (ca1, IdentitiesOnly=yes, IdentityAgent=<dedicated>, ControlMaster=no, BatchMode=yes) true; controls: ca2 (principal mismatch) and ca1 with IdentityAgent=none; server lines from docker logs $FX_CA1_CONTAINER filtered to this run's key IDs" || echo "fresh SSH login not enabled (no --fixture-runtime)")")"
    printf '    %s,\n' "$(json_str "sampling: per sample and working path ssh-add -T, ssh-keygen -Y sign + check-novalidate, optional fresh ca1 login; ioreg IOConsoleLocked and CGSSessionScreenIsLocked only")"
    printf '    %s,\n' "$(json_str "export check: sc_auth export-ctk-identity -h <own hash> -f <tmp>/export.p12 -p <random, never recorded>; any file created is removed with rm -P")"
    printf '    %s\n' "$(json_str "cleanup: kill exact agent PIDs; own-row check, then sc_auth delete-ctk-identity -h <own hash>; post-delete ssh-add -T / -Y sign on each working agent; sc_auth list-ctk-identities compared byte for byte (SHA-256) with the pre-run list; AuthenticationAuthority digest compared; rm -rf <tmp>")"
    printf '  ],\n'
    printf '  "observed_result": {\n'
    printf '    "verdict": "%s",\n' "$verdict"
    printf '    "criterion": %s,\n' "$(json_str "$criterion")"
    printf '    "summary": %s,\n' "$(json_str "$summary")"
    printf '    "mode": "%s",\n    "probe_exit_code": %s,\n' "$MODE" "$exit_code"
    printf '    "identity": {"label": %s, "public_key_hash_prefix": %s, "key_type_requested": "p-256-ne", "protection_requested": "none", "create_rc": %s, "create_timed_out": %s, "create_terminated_pids": %s, "created": %s, "own_row_redacted": %s, "sc_auth_ssh_hash": %s, "pre_run_identity_count": %s, "pre_run_rows_with_label_prefix": %s, "pairing_ui": %s},\n' \
      "$(json_str "$LABEL")" "$(json_str "${HASH:0:8}")" "$(jn "$CREATE_RC")" "$([ "$CREATE_TO" -eq 1 ] && echo true || echo false)" "$(json_str "${CREATE_KILLED:-none}")" \
      "$(json_str "$CREATED")" "$(json_str "$own_row")" "$(json_str "$SSHHASH_NOTE")" "$(jn "$PRE_COUNT")" "$(jn "$PRE_PREFIX_ROWS")" "$(json_str "$PAIRING_UI")"
    printf '    "load_paths": {"pkcs11": %s, "sk": %s},\n' "$(path_json pkcs11)" "$(path_json sk)"
    printf '    "export_check": {"rc": %s, "timed_out": %s, "file_created": %s, "message_class": %s},\n' \
      "$(jn "$EXPORT_RC")" "$([ "$EXPORT_TO" -eq 1 ] && echo true || echo false)" "$(json_str "$EXPORT_FILE")" "$(json_str "$EXPORT_CLASS")"
    printf '    "delete": {"rc": %s, "timed_out": %s, "own_row_absent_afterwards": %s, "note": %s},\n' \
      "$(jn "$DELETE_RC")" "$([ "$DELETE_TO" -eq 1 ] && echo true || echo false)" "$([ "$DELETED" -eq 1 ] && echo true || echo false)" "$(json_str "${DELETE_NOTE:-none}")"
    printf '    "samples_total": %s,\n    "max_gap_between_samples_s": %s,\n    "interval_s": %s,\n' "$total" "$maxgap" "$INTERVAL"
    printf '    "lock_window_evidence": "%s",\n    "owner_lock_seconds_observed": %s,\n' "$lock_evidence" "$lock_secs_obs"
    printf '    "outcomes_in_window": {'; sep=""
    for p in $PATHS; do printf '%s"%s": {"samples": %s, "dedicated_agent_signing": "%s", "fresh_ssh_login": "%s"}' "$sep" "$p" "$(getv O "$p" N)" "$(getv O "$p" AGENT)" "$(getv O "$p" SSH)"; sep=", "; done
    printf '},\n'
    printf '    "per_phase_counts": ['; sep=""
    for ph in unlocked pre lock_window post locked_signal; do
      for p in $PATHS; do
        [ "$(getn "$ph" "$p" 3)" -eq 0 ] && continue
        printf '%s{"phase": "%s", "path": "%s", "samples": %s, "agent_ok": %s, "ssh_samples": %s, "ssh_ok": %s}' "$sep" "$ph" "$p" "$(getn "$ph" "$p" 3)" "$(getn "$ph" "$p" 4)" "$(getn "$ph" "$p" 5)" "$(getn "$ph" "$p" 6)"; sep=", "
      done
    done
    printf '],\n'
    printf '    "owner_attestation": {"screen_locked": "%s", "credential_dialog_seen": "%s"},\n' "$ATTEST_LOCK" "$ATTEST_DIALOG"
    printf '    "certificate_validity": %s,\n    "server_logs": %s,\n' "$(json_str "$([ -n "$FIXTURE_RUNTIME" ] && echo "$CERT_VALIDITY" || echo none)")" "$(json_str "$SERVER_LOGS")"
    printf '    "cleanup": {"sampler": "%s", "dedicated_agents": %s, "agent_sockets": %s, "own_identity": "%s", "ctk_identity_list_vs_pre_run": "%s", "authentication_authority": "%s", "export_file": "%s", "caffeinate": "%s", "temp_dir": "%s", "complete": %s},\n' \
      "$CLEAN_SAMPLER" "$(json_str "${CLEAN_AGENTS:-none}")" "$(json_str "${CLEAN_SOCKETS:-none}")" "$CLEAN_IDENTITY" "$CLEAN_IDLIST" "$CLEAN_AA" "$CLEAN_EXPORT" "$CLEAN_CAF" "$CLEAN_TEMP" "$cc"
    if [ "$MODE" = unlocked ]; then
      printf '    "clauses": {"create_noninteractive": "%s", "export_refused_no_file": "%s", "delete_by_exact_hash_list_restored": "%s", "dedicated_agent_signing": "%s", "keychain_certificates_limit": "%s", "fixture_login_with_controls": "%s"},\n' \
        "$c_create" "$c_export" "$c_delete" "$c_sign" "$c_limit" "$c_login"
    fi
    printf '    "validity_notes": %s,\n' "$(json_str "${vnotes:-none}")"
    printf '    "findings": %s,\n' "$(json_str "${FINDINGS:-none}")"
    printf '    "canary_scan_of_artifacts": "%s",\n    "interrupted": %s,\n    "setup_notes": %s\n' "$leak" "$([ "$INTERRUPTED" -eq 1 ] && echo true || echo false)" "$(json_str "${SETUP_NOTES:-none}")"
    printf '  },\n'
    printf '  "evidence_paths": [%s, %s, %s],\n' "$(json_str "$(relpath "$OUT_DIR")/")" "$(json_str "$(relpath "$SAMPLES_TSV")")" "$(json_str "$(relpath "$RUNLOG")")"
    printf '  "limitations": [\n'
    printf '    %s,\n' "$(json_str "One CTK identity in the real user token store (owner decision D4), created and deleted in this run. The owner's other identities are counted, never listed, exported, modified or used; the pre-run list stays in a 0700 temp file and as a digest in memory.")"
    printf '    %s,\n' "$(json_str "-t none only: no Touch ID per use. A -t bio identity, an exportable (p-256) identity, logout, sleep, reboot and headless (launchd) operation are not measured here.")"
    printf '    %s,\n' "$(json_str "The export password is random, single-use and protects nothing: sc_auth accepts it only as an argument, so it is visible to same-user processes while that one command runs. It is never written to logs, artifacts or this record.")"
    printf '    %s,\n' "$(json_str "No interactive prompt was answered by anyone: every command ran with stdin /dev/null, BatchMode and a timeout. A non-blocking notification (for example a SmartCard pairing offer) would not be visible to the probe; the AuthenticationAuthority digest check detects a pairing that was accepted.")"
    printf '    %s,\n' "$(json_str "ioreg IOConsoleLocked / CGSSessionScreenIsLocked are undocumented IORegistry properties used only as corroboration (lock mode).")"
    printf '    %s\n' "$(json_str "Status verified means the measurement is valid (completed, cleanup complete including an identity list equal to the pre-run list); it holds even when the verdict is fail. Requirement IDs, where listed, are for traceability only (tests/evidence/README.md).")"
    printf '  ],\n'
    printf '  "blocked_on": %s\n' "$blocked_on"
    printf '}\n'
  } > "$RECORD"
  if json_parses "$RECORD"; then log "record written: $(relpath "$RECORD") (JSON parses)"
  else log "WARNING: record written but did not parse as JSON: $(relpath "$RECORD")"; fi
  if grep -F -q "$CANARY_PREFIX" "$RECORD"; then
    log "ERROR: canary prefix found in record"; exit_code=4
    sed -i '' 's/"probe_exit_code": [0-9]*/"probe_exit_code": 4/' "$RECORD"
  fi
  log "exit=$exit_code"
  exit "$exit_code"
}

on_signal() { trap '' INT QUIT PIPE; trap 'LATE_SIGNAL=1' TERM HUP; INTERRUPTED=1; log "interrupted by signal $1; cleaning up (further signals are ignored until cleanup ends)"; finish; }
setup_fail() { SETUP_NOTES="${SETUP_NOTES}$1; "; SETUP_FAILED=1; log "ERROR: $1"; finish; }
blocked() { BLOCKED=1; BLOCKED_REASON=$1; log "BLOCKED: $1"; finish; }
finding() { FINDINGS="${FINDINGS}$1; "; log "FINDING: $1"; }
trap 'on_signal INT' INT; trap 'on_signal TERM' TERM; trap 'on_signal HUP' HUP; trap 'on_signal QUIT' QUIT
trap 'finish' EXIT

# ---------------------------------------------------------------- setup: snapshots (read-only)
log "g04_ctk_probe v$PROBE_VERSION mode=$MODE launchd_session=${LAUNCHD_SESSION:-unknown} out=$(relpath "$OUT_DIR")$([ "$SELFTEST" -eq 1 ] && echo ' SELF-TEST (fake sc_auth)')"
T=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-g04-p5.XXXXXXXX") || setup_fail "mktemp failed"
chmod 700 "$T"
case "$T" in *[[:space:]]*|*'"'*|*'#'*) T_BAD=$T; T=""; rm -rf "$T_BAD"; setup_fail "temp path contains whitespace, quotes or #; set TMPDIR to a simple path";; esac
log "temp dir created (0700, disposable)"
RUN_TAG="$STAMP-$(od -An -tx1 -N3 /dev/urandom | tr -d ' \n')"
LABEL="$LABEL_PREFIX$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
BOGUS=$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n' | tr 'a-f' 'A-F')

AA_DIGEST_BEFORE=$("$DSCL" . -read "/Users/$USER_NAME" AuthenticationAuthority 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
AA_TOKENS_BEFORE=$("$DSCL" . -read "/Users/$USER_NAME" AuthenticationAuthority 2>/dev/null | grep -o ';tokenidentity;' | wc -l | tr -d ' ')
log "AuthenticationAuthority digest taken (memory only); token-identity pairings before: $AA_TOKENS_BEFORE"
if sc_run 20 "$T/pairing.out" pairing_ui -s status; then
  case "$(cat "$T/pairing.out")" in *"is enabled"*) PAIRING_UI=enabled;; *"is disabled"*) PAIRING_UI=disabled;; *) PAIRING_UI=unknown;; esac
else PAIRING_UI="status_failed"; fi
log "SmartCard pairing dialog: $PAIRING_UI$([ "$PAIRING_UI" = enabled ] && echo ' (if macOS offers to pair heimdall-m00-p5-..., dismiss it; do NOT pair)')"

sc_run "$SC_TO" "$T/pre.list" list-ctk-identities || setup_fail "sc_auth list-ctk-identities failed before anything was created (rc=$?)"
PRE_DIGEST=$(shasum -a 256 < "$T/pre.list" | cut -d' ' -f1)
PRE_COUNT=$(hash_tokens < "$T/pre.list" | wc -l | tr -d ' ')
PRE_PREFIX_ROWS=$(grep -c -F -- "$LABEL_PREFIX" "$T/pre.list")
log "pre-run CTK identities: $PRE_COUNT (list kept only in the 0700 temp dir; digest in memory); rows with prefix $LABEL_PREFIX from earlier runs: $PRE_PREFIX_ROWS (never touched)"
[ "$(label_rows "$T/pre.list" | grep -c .)" -eq 0 ] || setup_fail "fresh random label already present; refusing to continue"
if [ "$PRE_COUNT" != 0 ] && { [ "$SELFTEST" -eq 0 ] || [ -e "$(dirname "$SC_AUTH")/enforce_empty_store" ]; }; then
  blocked "the CTK token store already holds $PRE_COUNT identity(ies); ssh-add -K -S ignores KEYCHAIN_CERTIFICATES (P5 run 20261009T053616Z), so loading would also load identities this probe did not create. Nothing was created. Needs a store without other CTK identities, or an owner decision"
fi
# ssh-keychain.dylib also serves smart cards and other tokens; none may be present (read-only check,
# only the count is kept).
if [ "$SELFTEST" -eq 0 ]; then
  run_with_timeout 20 "$SECURITY" list-smartcards </dev/null > "$T/smartcards.out" 2>&1; SC_LIST_RC=$?
  # Observed on macOS 27.0: rc 44 and "No smartcards found." when none are present.
  if [ "$SC_LIST_RC" -eq 0 ] && [ "$(grep -c . "$T/smartcards.out")" -gt 0 ]; then
    blocked "security list-smartcards reports $(grep -c . "$T/smartcards.out") token(s); ssh-keychain.dylib would offer them to the agents too. Nothing was created. Remove smart cards/tokens and run again"
  elif [ "$SC_LIST_RC" -ne 0 ] && [ "$SC_LIST_RC" -ne 44 ]; then
    blocked "security list-smartcards failed (rc=$SC_LIST_RC), so the absence of other tokens cannot be confirmed. Nothing was created"
  fi
  log "smart cards/tokens: none reported (security list-smartcards rc=$SC_LIST_RC)"
  rm -f "$T/smartcards.out"
fi

# ---------------------------------------------------------------- create (the one authorized write)
log "creating CTK identity label=$LABEL type=p-256-ne protection=none (timeout ${SC_TO}s)"
CREATE_ATTEMPTED=1
sc_run "$SC_TO" "$T/create.out" create-ctk-identity -l "$LABEL" -k p-256-ne -t none; CREATE_RC=$?; CREATE_TO=$SC_TIMED_OUT; CREATE_KILLED=$SC_KILLED
log "create-ctk-identity rc=$CREATE_RC timed_out=$CREATE_TO"
if resolve_own_hash; then HASH=$RESOLVED_HASH
elif [ "$CREATE_TO" -eq 1 ]; then sleep 5; resolve_own_hash && HASH=$RESOLVED_HASH; fi
if [ -n "$HASH" ]; then
  if [ "$CREATE_RC" -eq 0 ]; then CREATED=yes; else CREATED=partial; fi
  label_rows "$T/resolve.list" | redact > "$OUT_DIR/identity-row.txt"
  log "own identity present (hash prefix ${HASH:0:8}); rows with own label: $OWN_ROWS"
fi
keep_sc "$T/create.out" "sc_auth-create.out"   # after the own hash is known, so the own row survives redaction
if [ "$CREATE_TO" -eq 1 ]; then
  blocked "sc_auth create-ctk-identity did not finish within ${SC_TO}s with stdin /dev/null (it may wait for an interactive prompt, a dialog or Touch ID); terminated exact PIDs: ${CREATE_KILLED:-none}"
fi
if [ "$CREATE_RC" -ne 0 ]; then
  blocked "sc_auth create-ctk-identity -k p-256-ne -t none failed (rc=$CREATE_RC; output in sc_auth-create.out)"
fi
[ -n "$HASH" ] || setup_fail "create returned 0 but no single row with the own label and one hash was found (rows with label: $OWN_ROWS)"
if sc_run "$SC_TO" "$T/post-ssh.list" list-ctk-identities -t ssh -e b64; then
  SSHHASH=$(label_rows "$T/post-ssh.list" | tr -s ' \t' '\n' | sed 's/^SHA256://' | grep -E '^[A-Za-z0-9+/]{43}=?$' | sort -u)
  if [ "$(printf '%s' "$SSHHASH" | grep -c .)" -eq 1 ]; then SSHHASH=${SSHHASH%=}; SSHHASH_NOTE="SHA256:$SSHHASH"; OWN_FPS="SHA256:$SSHHASH"
  else SSHHASH=""; SSHHASH_NOTE="not_parsed"; fi
fi
log "sc_auth SSH hash for own identity: $SSHHASH_NOTE"

# ---------------------------------------------------------------- load, sign, login
write_ssh_config() {  # PATH VARIANT -> $T/ssh_config-PATH-VARIANT
  # bash 3.2 mis-parses `case` inside $(...), so the optional line is computed first. ssh ignores an
  # sk-type IdentityFile/CertificateFile without SecurityKeyProvider, even when the agent holds the key.
  local SKP_LINE=""
  case "$(getv R "$1" KALG)" in sk-*) SKP_LINE="  SecurityKeyProvider $KC_DYLIB";; esac
  cat > "$T/ssh_config-$1-$2" <<EOF
Host probe-target
  HostName 127.0.0.1
  Port $FX_PORT1
  User cert
  HostKeyAlias hm-ca1
Host probe-negative
  HostName 127.0.0.1
  Port $FX_PORT2
  User cert
  HostKeyAlias hm-ca2
Host *
  UserKnownHostsFile "$FX_KNOWN"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  CheckHostIP no
  UpdateHostKeys no
  VerifyHostKeyDNS no
  IdentityAgent "$T/$1.sock"
$SKP_LINE
  IdentitiesOnly yes
  IdentityFile "$T/$1-$2.pub"
  CertificateFile "$T/$1-$2-cert.pub"
  PubkeyAuthentication yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  BatchMode yes
  ControlMaster no
  ControlPath none
  ForwardAgent no
  ForwardX11 no
  ConnectTimeout 10
  LogLevel ERROR
EOF
}
issue_cert() {  # PATH VARIANT(default|nt)
  local p=$1 v=$2 kid="heimdall-g04-p5-$RUN_TAG-$1-$2" e
  e=$(( $(date -u +%s) + CERT_MINUTES * 60 ))   # earliest expiry of any certificate issued (conservative)
  if [ -z "$CERT_EXPIRES_EPOCH" ] || [ "$e" -lt "$CERT_EXPIRES_EPOCH" ]; then CERT_EXPIRES_EPOCH=$e; fi
  cp "$T/$p.pub" "$T/$p-$v.pub"
  if [ "$v" = nt ]; then "$SSH_KEYGEN" -q -s "$FX_CAKEY" -I "$kid" -n p-host1 -V "$CERT_VALIDITY" -O no-touch-required "$T/$p-$v.pub" 2>"$T/$p-$v-certgen.out"
  else "$SSH_KEYGEN" -q -s "$FX_CAKEY" -I "$kid" -n p-host1 -V "$CERT_VALIDITY" "$T/$p-$v.pub" 2>"$T/$p-$v-certgen.out"; fi
}
fixture_login() {  # PATH VARIANT HOSTALIAS OUTFILE [extra ssh -o ...] -> rc
  local p=$1 v=$2 h=$3 out=$4; shift 4
  run_with_timeout 30 /usr/bin/env HOME="$T/home-$p" KEYCHAIN_CERTIFICATES="$HASH" "$SSH" -F "$T/ssh_config-$p-$v" "$@" "$h" true </dev/null >"$out" 2>&1
}
login_class() {  # SSH -v OUTFILE RC -> accepted|no_connection|not_offered|refused_at_query|failed_after_query
  if [ "$2" = 0 ]; then echo accepted
  elif ! grep -q 'Connection established' "$1"; then echo no_connection
  elif ! grep -q 'Offering public key' "$1"; then echo not_offered
  elif ! grep -q 'Server accepts key' "$1"; then echo refused_at_query
  else echo failed_after_query; fi
}
pk_hash_check() {  # PUBFILE -> pkhash_match|pkhash_differs|not_parsed: hash of the key's EC point (04||X||Y) vs own hash
  local b i q h
  b=$(awk 'NR == 1 { print $2 }' "$1" | /usr/bin/base64 -D 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
  i=$(awk -v s="$b" 'BEGIN { print index(s, "0000004104") }')   # P-256 point: string length 65, first byte 04
  [ "$i" -gt 0 ] 2>/dev/null || { echo not_parsed; return; }
  q=${b:$((i - 1 + 8)):130}
  [ ${#q} -eq 130 ] || { echo not_parsed; return; }
  if [ ${#HASH} -eq 64 ]; then h=$(printf '%s' "$q" | /usr/bin/xxd -r -p | shasum -a 256 | cut -d' ' -f1)
  else h=$(printf '%s' "$q" | /usr/bin/xxd -r -p | shasum -a 1 | cut -d' ' -f1); fi
  if [ "$(printf '%s' "$h" | tr 'a-f' 'A-F')" = "$(printf '%s' "$HASH" | tr 'a-f' 'A-F')" ]; then echo pkhash_match; else echo pkhash_differs; fi
}
classify_load() {  # OUTFILE -> short class of the ssh-add load message (no key material)
  local f=$1
  if grep -q -i 'agent refused' "$f"; then echo agent_refused
  elif grep -q -i 'returned failure' "$f"; then echo provider_returned_failure
  elif grep -q -i 'Resident identity added' "$f"; then echo resident_identity_added
  elif grep -q -i 'Card added' "$f"; then echo card_added
  elif grep -q -i 'not allowed\|refused by allow' "$f"; then echo provider_not_allowed
  else echo other; fi
}

if [ "$SELFTEST" -eq 1 ]; then
  for p in $PATHS; do setv R "$p" NOTE "skipped in self-test (fake sc_auth; ssh-keychain.dylib never loaded)"; done
  log "self-test: load paths skipped"
else
  if [ -n "$FIXTURE_RUNTIME" ] && [ "$MODE" = lock ]; then
    # Generous: three times the advised lock, plus worst-case sample time, plus 60 min. Login samples
    # taken after expiry are recorded as not measured, never as lock failures.
    CERT_MINUTES=$(( LOCK_SECONDS * 3 / 60 + (PRE_SAMPLES + POST_SAMPLES) * (INTERVAL + 60) / 60 + 60 ))
    CERT_VALIDITY="-1m:+${CERT_MINUTES}m"
  fi
  for p in $PATHS; do
    # Filter control: same load with a random non-matching hash, in its own agent. Must load zero keys.
    start_agent "ctl$p" "$BOGUS" || setup_fail "filter-control agent for $p did not start"
    load_into "$p" "ctl$p" "$T/ctl$p-load.out"; setv R "$p" CTLRC $?
    setv R "$p" CTLKEYS "$(key_count "ctl$p")"
    log "filter control $p (non-matching hash): load rc=$(getv R "$p" CTLRC) keys=$(getv R "$p" CTLKEYS)"
    if [ "$(getv R "$p" CTLKEYS)" != 0 ]; then
      # Whatever was loaded may belong to someone else: keep no raw output, use nothing.
      finding "filter control $p loaded $(getv R "$p" CTLKEYS) key(s) with a non-matching KEYCHAIN_CERTIFICATES; not used, ssh-add -D issued (rc in the record), agent terminated at cleanup"
      run_in "ctl$p" 15 /dev/null "$SSH_ADD" -D; setv R "$p" CTLDRC $?
    else
      keep "$T/ctl$p-load.out" "filter-control-$p-load.out"
    fi
    # Real load, limited to the own hash.
    start_agent "$p" "$HASH" || setup_fail "dedicated agent for $p did not start"
    load_into "$p" "$p" "$T/$p-load.out"; setv R "$p" LOAD_RC $?
    setv R "$p" LOAD_CLASS "$(classify_load "$T/$p-load.out")"
    setv R "$p" KEYS "$(key_count "$p")"
    log "load $p (ssh-add $(load_cmd "$p")) rc=$(getv R "$p" LOAD_RC) class=$(getv R "$p" LOAD_CLASS) keys_in_agent=$(getv R "$p" KEYS)"
    if [ "$(getv R "$p" KEYS)" -gt 1 ]; then
      finding "load path $p put $(getv R "$p" KEYS) keys into an agent limited to one hash (KEYCHAIN_CERTIFICATES limit did not hold); all removed without use"
      run_in "$p" 15 /dev/null "$SSH_ADD" -D
      setv R "$p" NOTE "limit violated; keys removed unused; raw load output not kept"
      continue
    fi
    if [ "$(getv R "$p" KEYS)" -ne 1 ]; then keep "$T/$p-load.out" "load-$p.out"; setv R "$p" NOTE "no key loaded"; continue; fi
    run_in "$p" 15 "$T/$p-l.out" "$SSH_ADD" -l
    setv R "$p" FP "$(awk 'NR == 1 { print $2 }' "$T/$p-l.out")"
    setv R "$p" KTYPE "$(sed -n '1s/.*(\([^()]*\))$/\1/p' "$T/$p-l.out")"
    run_in "$p" 15 "$T/$p.pub" "$SSH_ADD" -L
    setv R "$p" KALG "$(awk 'NR == 1 { print $1 }' "$T/$p.pub")"
    if [ -z "$SSHHASH" ]; then setv R "$p" FPMATCH not_compared
    elif [ "$(getv R "$p" FP)" = "SHA256:$SSHHASH" ]; then setv R "$p" FPMATCH match
    else setv R "$p" FPMATCH differs; fi
    setv R "$p" PKMATCH "$(pk_hash_check "$T/$p.pub")"
    # Use the key only if it is provably this run's identity. No fallback: an unproven key is
    # removed unused and its details are not kept.
    if [ "$(getv R "$p" PKMATCH)" = pkhash_match ]; then setv R "$p" OWNBASIS "public_key_hash_of_ec_point_equals_own_hash"
    elif [ "$(getv R "$p" FPMATCH)" = match ]; then setv R "$p" OWNBASIS "fingerprint_equals_sc_auth_ssh_hash"
    else
      setv R "$p" FP ""; setv R "$p" KALG ""
      finding "load path $p: the one loaded key could not be confirmed as this run's identity; removed unused"
      run_in "$p" 15 /dev/null "$SSH_ADD" -D
      setv R "$p" NOTE "loaded key not confirmed as own; removed unused; raw output not kept"
      continue
    fi
    OWN_FPS="$OWN_FPS $(getv R "$p" FP)"
    keep "$T/$p-load.out" "load-$p.out"; keep "$T/$p-l.out" "agent-list-$p.out"; keep "$T/$p.pub" "agent-pubkey-$p.pub"
    log "$p: agent lists 1 key alg=$(getv R "$p" KALG) fp=$(getv R "$p" FP); fp vs sc_auth SSH hash: $(getv R "$p" FPMATCH); EC-point hash vs own hash: $(getv R "$p" PKMATCH); ownership basis: $(getv R "$p" OWNBASIS)"
    run_in "$p" 30 "$T/$p-T.out" "$SSH_ADD" -T "$T/$p.pub"; setv R "$p" TRC $?
    printf 'heimdall-g04-p5 setup nonce %s\n' "$RUN_TAG" > "$T/$p-msg"; rm -f "$T/$p-msg.sig"
    run_in "$p" 30 "$T/$p-sign.out" "$SSH_KEYGEN" -Y sign -q -f "$T/$p.pub" -n "$SIGN_NS" "$T/$p-msg"; setv R "$p" SIGNRC $?
    if [ "$(getv R "$p" SIGNRC)" = 0 ]; then
      "$SSH_KEYGEN" -Y check-novalidate -n "$SIGN_NS" -s "$T/$p-msg.sig" < "$T/$p-msg" > "$T/$p-verify.out" 2>&1; setv R "$p" VERRC $?
    else setv R "$p" VERRC -1; fi
    keep "$T/$p-T.out" "ssh-add-T-$p.out"; keep "$T/$p-sign.out" "sign-$p.out"; keep "$T/$p-verify.out" "verify-$p.out"
    log "$p: ssh-add -T rc=$(getv R "$p" TRC); -Y sign rc=$(getv R "$p" SIGNRC); check-novalidate rc=$(getv R "$p" VERRC)"
    if [ "$(getv R "$p" TRC)" = 0 ] && [ "$(getv R "$p" SIGNRC)" = 0 ] && [ "$(getv R "$p" VERRC)" = 0 ]; then
      setv R "$p" SAMPLED 1
    fi
    if [ -n "$FIXTURE_RUNTIME" ] && [ "$(getv R "$p" SAMPLED)" = 1 ]; then
      issue_cert "$p" default || finding "certificate issue failed for $p (default)"
      write_ssh_config "$p" default
      fixture_login "$p" default probe-target "$T/$p-login-default.out" -v; setv R "$p" LOGDEF $?
      setv R "$p" LOGDEFCLS "$(login_class "$T/$p-login-default.out" "$(getv R "$p" LOGDEF)")"
      keep "$T/$p-login-default.out" "login-ca1-$p-default.out"
      log "$p: fresh login to ca1 with default-extension certificate rc=$(getv R "$p" LOGDEF) class=$(getv R "$p" LOGDEFCLS)"
      if [ "$(getv R "$p" LOGDEF)" = 0 ]; then setv R "$p" VARIANT default
      else
        case "$(getv R "$p" KALG)" in
          sk-*)
            issue_cert "$p" nt || finding "certificate issue failed for $p (no-touch-required)"
            write_ssh_config "$p" nt
            fixture_login "$p" nt probe-target "$T/$p-login-nt.out" -v; setv R "$p" LOGNT $?
            setv R "$p" LOGNTCLS "$(login_class "$T/$p-login-nt.out" "$(getv R "$p" LOGNT)")"
            keep "$T/$p-login-nt.out" "login-ca1-$p-no-touch-required.out"
            log "$p: fresh login to ca1 with no-touch-required certificate rc=$(getv R "$p" LOGNT) class=$(getv R "$p" LOGNTCLS)"
            [ "$(getv R "$p" LOGNT)" = 0 ] && setv R "$p" VARIANT nt;;
        esac
      fi
      case "$(getv R "$p" LOGDEFCLS) $(getv R "$p" LOGNTCLS)" in
        *accepted*|*refused_at_query*|*failed_after_query*) setv R "$p" LOGMEASURED 1;;
      esac
      if [ -n "$(getv R "$p" VARIANT)" ]; then
        fixture_login "$p" "$(getv R "$p" VARIANT)" probe-negative "$T/$p-neg2.out" -v; setv R "$p" NEG2 $?
        setv R "$p" NEG2CLS "$(login_class "$T/$p-neg2.out" "$(getv R "$p" NEG2)")"
        fixture_login "$p" "$(getv R "$p" VARIANT)" probe-target "$T/$p-negna.out" -v -o IdentityAgent=none; setv R "$p" NEGNA $?
        setv R "$p" NEGNACLS "$(login_class "$T/$p-negna.out" "$(getv R "$p" NEGNA)")"
        keep "$T/$p-neg2.out" "control-ca2-principal-mismatch-$p.out"; keep "$T/$p-negna.out" "control-ca1-without-agent-$p.out"
        log "$p: controls: ca2 principal mismatch rc=$(getv R "$p" NEG2) class=$(getv R "$p" NEG2CLS); ca1 without agent rc=$(getv R "$p" NEGNA) class=$(getv R "$p" NEGNACLS) (both expected non-zero)"
      fi
    fi
  done
fi
SETUP_OK=1

# ---------------------------------------------------------------- sampling
lock_signals() {
  local x ioc cgs
  x=$("$IOREG" -n Root -d1 -a 2>/dev/null)
  ioc=$(printf '%s\n' "$x" | grep -A1 '<key>IOConsoleLocked</key>' | grep -o -E 'true|false' | head -1)
  cgs=$(printf '%s\n' "$x" | grep -A1 '<key>CGSSessionScreenIsLocked</key>' | grep -o -E 'true|false' | head -1)
  x=""
  printf '%s %s\n' "${ioc:-absent}" "${cgs:-absent}"
}
sample_path() {  # PATH SEQ EPOCH -> echoes "add sign ver ssh"
  local p=$1 add sign ver ssh=na
  if [ "$(getv R "$p" SAMPLED)" != 1 ]; then echo "na na na na"; return; fi
  run_in "$p" 15 /dev/null "$SSH_ADD" -T "$T/$p.pub"; add=$?
  printf 'heimdall-g04-p5 nonce %s %s %s\n' "$p" "$2" "$3" > "$T/$p-smsg"; rm -f "$T/$p-smsg.sig"
  run_in "$p" 15 /dev/null "$SSH_KEYGEN" -Y sign -q -f "$T/$p.pub" -n "$SIGN_NS" "$T/$p-smsg"; sign=$?
  if [ "$sign" -eq 0 ]; then "$SSH_KEYGEN" -Y check-novalidate -n "$SIGN_NS" -s "$T/$p-smsg.sig" < "$T/$p-smsg" >/dev/null 2>&1; ver=$?; else ver=-1; fi
  if [ -n "$(getv R "$p" VARIANT)" ]; then
    if [ -n "$CERT_EXPIRES_EPOCH" ] && [ "$(date -u +%s)" -ge $((CERT_EXPIRES_EPOCH - 15)) ]; then ssh=na; : > "$T/cert-expired-sample"
    else fixture_login "$p" "$(getv R "$p" VARIANT)" probe-target /dev/null; ssh=$?; fi
  fi
  echo "$add $sign $ver $ssh"
}
sample_once() {
  local seq=$1 phase=$2 t_utc t_epoch sig ioc cgs r1 r2
  t_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ); t_epoch=$(date -u +%s)
  sig=$(lock_signals); ioc=${sig% *}; cgs=${sig#* }
  r1=$(sample_path pkcs11 "$seq" "$t_epoch"); r2=$(sample_path sk "$seq" "$t_epoch")
  set -- $r1 $r2
  printf '{"seq":%s,"phase":"%s","t_utc":"%s","t_epoch":%s,"lock_signals":{"io_console_locked":"%s","cgs_session_screen_is_locked":"%s"},"pkcs11":{"ssh_add_T_rc":"%s","ssh_keygen_Y_sign_rc":"%s","signature_check_rc":"%s","fresh_ssh_login_rc":"%s"},"sk":{"ssh_add_T_rc":"%s","ssh_keygen_Y_sign_rc":"%s","signature_check_rc":"%s","fresh_ssh_login_rc":"%s"}}\n' \
    "$seq" "$phase" "$t_utc" "$t_epoch" "$ioc" "$cgs" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" >> "$SAMPLES"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$seq" "$phase" "$t_epoch" "$ioc" "$cgs" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" >> "$SAMPLES_TSV"
}
sampler() {
  local seq=0 phase i
  trap - INT TERM HUP EXIT
  while [ ! -e "$T/stop" ]; do
    seq=$((seq+1)); phase=$(cat "$T/phase" 2>/dev/null || echo unknown)
    sample_once "$seq" "$phase"
    i=0; while [ $i -lt "$INTERVAL" ] && [ ! -e "$T/stop" ]; do sleep 1; i=$((i+1)); done
  done
}
sample_count() { wc -l < "$SAMPLES_TSV" | tr -d ' '; }
wait_samples() {
  local limit=$(( ($1 + 2) * (INTERVAL + 150) )) waited=0
  while [ "$(sample_count)" -lt "$1" ] && [ $waited -lt $limit ]; do sleep 1; waited=$((waited+1)); done
}

if [ "$(getv R pkcs11 SAMPLED)" = 1 ] || [ "$(getv R sk SAMPLED)" = 1 ]; then
  if [ "$MODE" = unlocked ]; then
    echo unlocked > "$T/phase"
    sampler & SAMPLER_PID=$!
    log "sampler pid=$SAMPLER_PID; taking $SAMPLES_N samples (screen stays unlocked)"
    wait_samples "$SAMPLES_N"
  else
    if [ "$USE_CAFFEINATE" -eq 1 ]; then
      "$CAFFEINATE" -i -w $$ >/dev/null 2>&1 &
      CAF_PID=$!; disown "$CAF_PID" 2>/dev/null; sleep 0.2; CAF_IDENT=$(proc_ident "$CAF_PID")
      log "caffeinate -i (idle-sleep assertion, exits with this script) pid=$CAF_PID"
    fi
    echo pre > "$T/phase"
    sampler & SAMPLER_PID=$!
    log "sampler pid=$SAMPLER_PID; taking $PRE_SAMPLES baseline samples (screen unlocked)"
    wait_samples "$PRE_SAMPLES"
    say_tty ""
    say_tty ">>> Baseline done. Now LOCK THE SCREEN (Control-Command-Q, or Apple menu > Lock Screen)."
    say_tty ">>> Do NOT log out, sleep, or close the lid. Stay locked for at least $LOCK_SECONDS seconds."
    say_tty ">>> Then unlock, come back to this terminal, and press Enter."
    echo lock_window > "$T/phase"; LOCK_INSTRUCTED_EPOCH=$(date -u +%s)
    log "phase=lock_window (owner instructed to lock)"
    IFS= read -r _owner_enter < /dev/tty   # content ignored; only the time of Enter matters
    OWNER_RETURNED_EPOCH=$(date -u +%s)
    echo post > "$T/phase"
    log "phase=post (owner pressed Enter after $((OWNER_RETURNED_EPOCH - LOCK_INSTRUCTED_EPOCH)) s)"
    base=$(sample_count)
    wait_samples $((base + POST_SAMPLES))
  fi
  : > "$T/stop"; wait "$SAMPLER_PID" 2>/dev/null; SAMPLER_PID=""; CLEAN_SAMPLER="stopped"; rm -f "$T/stop"
  log "sampling stopped; $(sample_count) samples"
  [ -e "$T/cert-expired-sample" ] && SAMPLES_AFTER_CERT_EXPIRY=1
  if [ "$MODE" = lock ]; then
    ask_yn() {
      local a
      while :; do
        printf '%s [y/n]: ' "$1" > /dev/tty
        IFS= read -r a < /dev/tty || { echo no_answer; return; }
        case "$a" in y|Y|yes) echo yes; return;; n|N|no) echo no; return;; esac
      done
    }
    ATTEST_LOCK=$(ask_yn "Did the screen actually lock (password or Touch ID needed to get back) for about $LOCK_SECONDS s?")
    ATTEST_DIALOG=$(ask_yn "Did any Touch ID, password, smart card pairing or keychain dialog appear during the run?")
    log "owner attestation: screen_locked=$ATTEST_LOCK credential_dialog_seen=$ATTEST_DIALOG"
  fi
else
  log "no load path produced a signing key; sampling skipped"
fi

# ---------------------------------------------------------------- server-side attribution (read-only)
if [ -n "$FIXTURE_RUNTIME" ] && command -v docker >/dev/null 2>&1; then
  if [ "$(run_with_timeout 20 docker port "$FX_CA1_CONTAINER" 22/tcp 2>/dev/null | head -1)" = "127.0.0.1:$FX_PORT1" ]; then
    run_with_timeout 30 docker logs --since "$((RUN_START_EPOCH - 5))" "$FX_CA1_CONTAINER" > "$T/ca1.log" 2>&1
    grep -E "heimdall-g04-p5-$RUN_TAG|presence|touch" "$T/ca1.log" > "$T/ca1-run.log"
    keep "$T/ca1-run.log" "sshd-ca1-run-lines.log"
    for p in $PATHS; do
      setv R "$p" SRVACC "$(grep -c "Accepted publickey for cert .* ID heimdall-g04-p5-$RUN_TAG-$p-" "$T/ca1.log")"
      # sshd's user-presence rejection names the key type, not the certificate ID: count it for sk keys only.
      case "$(getv R "$p" KALG)" in sk-*) setv R "$p" SRVUP "$(grep -c -i 'user presence' "$T/ca1.log")";; *) setv R "$p" SRVUP na;; esac
    done
    SERVER_LOGS="docker logs $FX_CA1_CONTAINER since run start, filtered to this run's key IDs and presence/touch lines (sshd-ca1-run-lines.log)"
    log "server-side (ca1): accepted logins with this run's key IDs: pkcs11=$(getv R pkcs11 SRVACC) sk=$(getv R sk SRVACC); presence-related lines: pkcs11=$(getv R pkcs11 SRVUP) sk=$(getv R sk SRVUP)"
  else SERVER_LOGS="not collected: $FX_CA1_CONTAINER not found on 127.0.0.1:$FX_PORT1"; fi
fi

# ---------------------------------------------------------------- export check
EXPW=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
log "export check: sc_auth export-ctk-identity -h <own hash> -f <tmp>/export.p12 -p <random, not recorded>"
EXPORT_FILE="absent"
sc_run "$SC_TO" "$T/export.out" export-ctk-identity -h "$HASH" -f "$T/export.p12" -p "$EXPW"; EXPORT_RC=$?; EXPORT_TO=$SC_TIMED_OUT
EXPW=""
if [ -e "$T/export.p12" ]; then
  rm -P "$T/export.p12" 2>/dev/null
  if [ -e "$T/export.p12" ]; then EXPORT_FILE="created_and_still_present"; else EXPORT_FILE="created_then_removed_with_rm_P"; fi
  finding "export-ctk-identity produced a file for a p-256-ne identity (rc=$EXPORT_RC); file handled: $EXPORT_FILE"
fi
if grep -q 'cannot be exported' "$T/export.out"; then EXPORT_CLASS="hardware_bounded_cannot_be_exported"
elif [ "$EXPORT_TO" -eq 1 ]; then EXPORT_CLASS="timed_out"
else EXPORT_CLASS="other"; fi
keep_sc "$T/export.out" "sc_auth-export.out"
log "export-ctk-identity rc=$EXPORT_RC timed_out=$EXPORT_TO file=$EXPORT_FILE class=$EXPORT_CLASS"

# ---------------------------------------------------------------- delete, then agent behavior afterwards
delete_own || log "ERROR: own identity not deleted yet (${DELETE_NOTE:-see above}); cleanup will retry once"
if [ "$DELETED" -eq 1 ]; then
  for p in $PATHS; do
    [ "$(getv R "$p" SAMPLED)" = 1 ] || continue
    setv R "$p" POSTKEYS "$(key_count "$p")"
    run_in "$p" 30 "$T/$p-postT.out" "$SSH_ADD" -T "$T/$p.pub"; setv R "$p" POSTTRC $?
    printf 'heimdall-g04-p5 after delete %s\n' "$RUN_TAG" > "$T/$p-pmsg"; rm -f "$T/$p-pmsg.sig"
    run_in "$p" 30 "$T/$p-postsign.out" "$SSH_KEYGEN" -Y sign -q -f "$T/$p.pub" -n "$SIGN_NS" "$T/$p-pmsg"; setv R "$p" POSTSIGN $?
    keep "$T/$p-postT.out" "after-delete-ssh-add-T-$p.out"; keep "$T/$p-postsign.out" "after-delete-sign-$p.out"
    log "$p after identity delete: agent lists $(getv R "$p" POSTKEYS) key(s); ssh-add -T rc=$(getv R "$p" POSTTRC); -Y sign rc=$(getv R "$p" POSTSIGN)"
  done
fi
finish
