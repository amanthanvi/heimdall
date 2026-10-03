#!/bin/bash
# Heimdall gate G04 / task M00-T04: owner-run macOS lock-continuity probe.
#
# Measures, every few seconds, whether
#   1. a DEDICATED ssh-agent (started by this script, holding a disposable key whose
#      private file is deleted right after loading) can still sign,
#   2. an item in a DISPOSABLE custom keychain (created in a temp dir with
#      `security create-keychain`; never the login keychain) is still readable, and
#   3. optionally, a fresh SSH login (ControlMaster=no, IdentitiesOnly=yes, dedicated agent
#      only, certificate from the M00-T03 fixture CA) still succeeds,
# while the owner locks and unlocks the screen. Writes an evidence JSON record that follows
# tests/evidence/record.schema.json. Read README.md next to this file before running.
#
# Never touches: ~/.ssh, the caller's SSH_AUTH_SOCK agent, the login keychain, 1Password,
# or any host other than optional loopback fixture containers. Kills only the exact PIDs it
# started (after re-checking executable name and start time).
#
# Compatible with macOS /bin/bash 3.2. Uses only tools shipped with macOS.
set -u
umask 077
export LC_ALL=C

PROBE_VERSION="2"   # v2 (M00-T04-G04-fix): gate-probe convention (status = evidence; observed_result.verdict; no requirement IDs on smoke)
SSH=/usr/bin/ssh; SSH_KEYGEN=/usr/bin/ssh-keygen; SSH_AGENT=/usr/bin/ssh-agent; SSH_ADD=/usr/bin/ssh-add
SECURITY=/usr/bin/security; IOREG=/usr/sbin/ioreg; CAFFEINATE=/usr/bin/caffeinate; OSASCRIPT=/usr/bin/osascript
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS
# Assembled from two parts so this source never contains the contiguous project canary prefix.
CANARY_PREFIX="HEIMDALL""_CANARY_"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
SCRIPT_FILE="$SCRIPT_DIR/$(basename "$0")"
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd -P)

usage() {
  cat <<'EOF'
Usage: g04_lock_probe.sh --mode smoke|lock [options]

Modes (required):
  --mode smoke        Take a few samples with the screen unlocked, clean up, write a record.
                      Non-interactive. Proves the probe and its cleanup work.
  --mode lock         Interactive. Takes baseline samples, asks you to lock the screen
                      (Control-Command-Q) for about --lock-seconds, then press Enter after
                      unlocking; takes post-unlock samples and asks two yes/no questions.

Options:
  --interval SEC           Seconds between samples (1-60, default 5).
  --smoke-samples N        Samples in smoke mode (1-100, default 5).
  --pre-samples N          Baseline samples before locking (1-20, default 3).
  --post-samples N         Samples after you return (1-20, default 3).
  --lock-seconds SEC       How long to stay locked (10-3600, default 60). Advisory.
  --fixture-runtime DIR    Also attempt a fresh SSH login every sample against the M00-T03
                           fixture (tests/fixtures/ssh/runtime after up.sh): ca1 must accept
                           the probe certificate, ca2 must reject it (scope control).
  --out-dir DIR            Artifact directory, must be empty or absent (default under
                           tests/evidence/artifacts/g04/research/lock-probe/).
  --record FILE            Evidence record path, must not exist
                           (default tests/evidence/g04-macos-...-<UTC stamp>.json).
  --no-caffeinate          Do not hold an idle-sleep assertion during the run.
  -h, --help               Show this help.

Exit status: 0 record status verified, verdict pass, cleanup complete; 1 completed but status
in_progress (no valid measurement, e.g. no lock window) or verdict fail; 2 usage error;
3 precondition or setup failure; 4 cleanup incomplete or canary found in artifacts
(see record and terminal); 5 interrupted.
EOF
}

die_usage() { printf 'g04_lock_probe: %s\n' "$1" >&2; usage >&2; exit 2; }
is_uint() { case "$1" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }
in_range() { is_uint "$1" && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]; }

MODE=""; INTERVAL=5; SMOKE_SAMPLES=5; PRE_SAMPLES=3; POST_SAMPLES=3; LOCK_SECONDS=60
FIXTURE_RUNTIME=""; OUT_DIR=""; RECORD=""; USE_CAFFEINATE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) [ $# -ge 2 ] || die_usage "--mode needs a value"; MODE=$2; shift 2;;
    --interval) [ $# -ge 2 ] || die_usage "--interval needs a value"; INTERVAL=$2; shift 2;;
    --smoke-samples) [ $# -ge 2 ] || die_usage "--smoke-samples needs a value"; SMOKE_SAMPLES=$2; shift 2;;
    --pre-samples) [ $# -ge 2 ] || die_usage "--pre-samples needs a value"; PRE_SAMPLES=$2; shift 2;;
    --post-samples) [ $# -ge 2 ] || die_usage "--post-samples needs a value"; POST_SAMPLES=$2; shift 2;;
    --lock-seconds) [ $# -ge 2 ] || die_usage "--lock-seconds needs a value"; LOCK_SECONDS=$2; shift 2;;
    --fixture-runtime) [ $# -ge 2 ] || die_usage "--fixture-runtime needs a value"; FIXTURE_RUNTIME=$2; shift 2;;
    --out-dir) [ $# -ge 2 ] || die_usage "--out-dir needs a value"; OUT_DIR=$2; shift 2;;
    --record) [ $# -ge 2 ] || die_usage "--record needs a value"; RECORD=$2; shift 2;;
    --no-caffeinate) USE_CAFFEINATE=0; shift;;
    -h|--help) usage; exit 0;;
    *) die_usage "unknown argument: $1";;
  esac
done
case "$MODE" in smoke|lock) ;; "") die_usage "--mode is required";; *) die_usage "--mode must be smoke or lock";; esac
in_range "$INTERVAL" 1 60 || die_usage "--interval must be 1..60"
in_range "$SMOKE_SAMPLES" 1 100 || die_usage "--smoke-samples must be 1..100"
in_range "$PRE_SAMPLES" 1 20 || die_usage "--pre-samples must be 1..20"
in_range "$POST_SAMPLES" 1 20 || die_usage "--post-samples must be 1..20"
in_range "$LOCK_SECONDS" 10 3600 || die_usage "--lock-seconds must be 10..3600"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ "$MODE" = smoke ]; then CASE_ID="G04-macos-lock-probe-smoke"; REC_BASE="g04-macos-lock-probe-smoke-$STAMP.json"
else CASE_ID="G04-macos-screen-lock-availability"; REC_BASE="g04-macos-screen-lock-probe-$STAMP.json"; fi
[ -n "$OUT_DIR" ] || OUT_DIR="$REPO_ROOT/tests/evidence/artifacts/g04/research/lock-probe/$STAMP-$MODE"
[ -n "$RECORD" ] || RECORD="$REPO_ROOT/tests/evidence/$REC_BASE"

# ---------------------------------------------------------------- preconditions (no side effects yet)
pre_fail() { printf 'g04_lock_probe: precondition failed: %s\n' "$1" >&2; exit 3; }
[ "$(uname -s)" = Darwin ] || pre_fail "this probe is macOS-only"
[ "$(id -u)" -ne 0 ] || pre_fail "do not run as root"
for t in "$SSH" "$SSH_KEYGEN" "$SSH_AGENT" "$SSH_ADD" "$SECURITY" "$IOREG" "$OSASCRIPT"; do
  [ -x "$t" ] || pre_fail "missing $t"
done
[ "$USE_CAFFEINATE" -eq 0 ] || [ -x "$CAFFEINATE" ] || pre_fail "missing $CAFFEINATE (or pass --no-caffeinate)"
if [ "$MODE" = lock ]; then { : < /dev/tty; } 2>/dev/null || pre_fail "lock mode needs an interactive terminal (/dev/tty)"; fi
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
  case "$FIXTURE_RUNTIME" in *'"'*) pre_fail "fixture path contains a double quote";; esac
fi
if [ -e "$OUT_DIR" ] && [ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]; then pre_fail "--out-dir is not empty: $OUT_DIR"; fi
mkdir -p "$OUT_DIR" || pre_fail "cannot create --out-dir"
OUT_DIR=$(cd "$OUT_DIR" && pwd -P)
mkdir -p "$(dirname "$RECORD")" || pre_fail "cannot create record directory"
RUNLOG="$OUT_DIR/run.log"; SAMPLES="$OUT_DIR/samples.ndjson"; SAMPLES_TSV="$OUT_DIR/samples.tsv"
: > "$RUNLOG"; : > "$SAMPLES"; : > "$SAMPLES_TSV"

# ---------------------------------------------------------------- helpers
log() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$RUNLOG" >&2; }
say_tty() { printf '%s\n' "$*" > /dev/tty; printf '%s [owner-prompt] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >> "$RUNLOG"; }
json_str() {  # minimal JSON string encoder for short, mostly-ASCII fields
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
  printf '"%s"' "$s"
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
# a non-final comm column (observed: "/usr/bin/ssh-age").
proc_ident() { ps -o lstart= -o comm= -p "$1" 2>/dev/null | sed 's/  */ /g'; }
json_parses() {  # validate JSON syntax with JavaScriptCore (always present on macOS)
  "$OSASCRIPT" -l JavaScript -e 'function run(a){ObjC.import("Foundation");var s=$.NSString.stringWithContentsOfFileEncodingError(a[0],4,null);if(!s||s.isNil())throw "read";JSON.parse(s.js);return "ok"}' "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------- state
T=""; KC=""; KC_ACCT="heimdall-g04-probe"; KC_SVC="heimdall-g04-lock-probe"; CANARY=""
AGENT_PID=""; AGENT_IDENT=""; SAMPLER_PID=""; CAF_PID=""; CAF_IDENT=""
KC_LIST_DIGEST_BEFORE=""; KC_DEFAULT_DIGEST_BEFORE=""
FINISHED=0; INTERRUPTED=0; SETUP_OK=0; SETUP_FAILED=0
CLEAN_SAMPLER="not_started"; CLEAN_AGENT="not_started"; CLEAN_AGENT_SOCKET="not_applicable"
CLEAN_KEYCHAIN="not_started"; CLEAN_SEARCHLIST="not_checked"; CLEAN_DEFAULT_KC="not_checked"
CLEAN_CAF="not_started"; CLEAN_TEMP="not_started"
LOCK_INSTRUCTED_EPOCH=""; OWNER_RETURNED_EPOCH=""; ATTEST_LOCK="not_asked"; ATTEST_DIALOG="not_asked"
SETUP_NOTES=""; NEG_SCOPE_RC=""; NEG_NOAGENT_RC=""; KC_SETTINGS=""; CERT_NOTE="none"

setup_fail() { SETUP_NOTES="${SETUP_NOTES}$1; "; SETUP_FAILED=1; log "ERROR: $1"; exit 3; }

# ---------------------------------------------------------------- cleanup
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

cleanup() {
  local i
  if [ -n "$SAMPLER_PID" ]; then
    [ -n "$T" ] && : > "$T/stop" 2>/dev/null
    i=0; while [ $i -lt 600 ] && kill -0 "$SAMPLER_PID" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
    if kill -0 "$SAMPLER_PID" 2>/dev/null; then kill -TERM "$SAMPLER_PID" 2>/dev/null; sleep 0.5; fi
    wait "$SAMPLER_PID" 2>/dev/null
    if kill -0 "$SAMPLER_PID" 2>/dev/null; then CLEAN_SAMPLER="still_running"; else CLEAN_SAMPLER="stopped"; fi
  fi
  CLEAN_AGENT=$(kill_exact "$AGENT_PID" "$AGENT_IDENT")
  if [ -n "$T" ] && [ -n "$AGENT_PID" ]; then
    if [ -S "$T/agent.sock" ]; then CLEAN_AGENT_SOCKET="still_present"; else CLEAN_AGENT_SOCKET="removed"; fi
  fi
  if [ -n "$KC" ]; then
    [ -e "$KC" ] && "$SECURITY" delete-keychain "$KC" >/dev/null 2>&1
    if [ -e "$KC" ]; then CLEAN_KEYCHAIN="file_still_present"; else CLEAN_KEYCHAIN="deleted"; fi
    if "$SECURITY" list-keychains -d user 2>/dev/null | grep -F -q "$KC"; then CLEAN_SEARCHLIST="probe_keychain_still_listed"
    elif [ "$("$SECURITY" list-keychains -d user 2>/dev/null | shasum -a 256)" = "$KC_LIST_DIGEST_BEFORE" ]; then CLEAN_SEARCHLIST="unchanged"
    else CLEAN_SEARCHLIST="changed_not_by_probe_entry"; fi
    if [ "$("$SECURITY" default-keychain -d user 2>/dev/null | shasum -a 256)" = "$KC_DEFAULT_DIGEST_BEFORE" ]; then CLEAN_DEFAULT_KC="unchanged"; else CLEAN_DEFAULT_KC="changed"; fi
  fi
  CLEAN_CAF=$(kill_exact "$CAF_PID" "$CAF_IDENT")
  if [ -n "$T" ] && [ -d "$T" ]; then
    rm -rf "$T"
    if [ -e "$T" ]; then CLEAN_TEMP="still_present"; else CLEAN_TEMP="removed"; fi
  fi
}

cleanup_complete() {
  case "$CLEAN_SAMPLER" in stopped|not_started) ;; *) return 1;; esac
  case "$CLEAN_AGENT" in terminated|not_started) ;; *) return 1;; esac
  case "$CLEAN_AGENT_SOCKET" in removed|not_applicable) ;; *) return 1;; esac
  case "$CLEAN_KEYCHAIN" in deleted|not_started) ;; *) return 1;; esac
  case "$CLEAN_SEARCHLIST" in unchanged|not_checked) ;; *) return 1;; esac
  case "$CLEAN_DEFAULT_KC" in unchanged|not_checked) ;; *) return 1;; esac
  case "$CLEAN_CAF" in terminated|already_exited|not_started) ;; *) return 1;; esac
  case "$CLEAN_TEMP" in removed|not_started) ;; *) return 1;; esac
  return 0
}

# ---------------------------------------------------------------- finish: cleanup, analyse, record
AGG=""
getn() { local v; v=$(printf '%s\n' "$AGG" | awk -v k="$1" -v f="$2" '$1==k {print $f}'); printf '%s' "${v:-0}"; }
outcome() {  # samples ok -> outcome label
  local n=${1:-0} ok=${2:-0}
  if [ "$n" -eq 0 ]; then echo not_measured
  elif [ "$ok" -eq "$n" ]; then echo available_all_samples
  elif [ "$ok" -eq 0 ]; then echo unavailable_all_samples
  else echo intermittent; fi
}

finish() {
  [ "$FINISHED" -eq 0 ] || return 0
  FINISHED=1
  trap - INT TERM HUP EXIT
  cleanup
  CANARY=""
  log "cleanup: sampler=$CLEAN_SAMPLER agent=$CLEAN_AGENT agent_socket=$CLEAN_AGENT_SOCKET keychain=$CLEAN_KEYCHAIN search_list=$CLEAN_SEARCHLIST default_keychain=$CLEAN_DEFAULT_KC caffeinate=$CLEAN_CAF temp_dir=$CLEAN_TEMP"

  # TSV fields: seq phase epoch ioc cgs add_rc sign_rc ver_rc kc_rc kc_match ssh_rc
  AGG=$(awk -F'\t' '
    { n[$2]++; locked = ($4=="true" || $5=="true");
      a = ($6=="0" && $7=="0" && $8=="0"); k = ($9=="0" && $10=="true"); s = ($11=="0");
      na[$2]+=a; nk[$2]+=k; ns[$2]+=s;
      if (locked) { L++; La+=a; Lk+=k; Ls+=s }
      if (prev != "") { g = $3 - prev; if (g > maxgap) maxgap = g } prev = $3; total++ }
    END {
      split("smoke pre lock_window post", ph, " ");
      for (i=1;i<=4;i++) { p=ph[i]; printf "%s %d %d %d %d\n", p, n[p]+0, na[p]+0, nk[p]+0, ns[p]+0 }
      printf "locked_signal %d %d %d %d\n", L+0, La+0, Lk+0, Ls+0
      printf "meta %d %d 0 0\n", total+0, maxgap+0 }' "$SAMPLES_TSV" 2>/dev/null)
  local total maxgap
  total=$(getn meta 2); maxgap=$(getn meta 3)

  local status="in_progress" summary lock_evidence="not_applicable" win_n=0 win_a=0 win_k=0 win_s=0
  local agent_out kc_out ssh_out post_n post_a post_k leak="clean" exit_code valid=0 src verdict="inconclusive" criterion reqs
  if [ "$MODE" = smoke ]; then src=smoke
  elif [ "$(getn locked_signal 2)" -ge 2 ]; then src=locked_signal; lock_evidence="ioreg_lock_signal"
  elif [ "$ATTEST_LOCK" = yes ] && [ "$(getn lock_window 2)" -ge 2 ]; then src=lock_window; lock_evidence="owner_attestation_only"
  else src=""; lock_evidence="not_established"; fi
  if [ -n "$src" ]; then win_n=$(getn $src 2); win_a=$(getn $src 3); win_k=$(getn $src 4); win_s=$(getn $src 5); fi
  agent_out=$(outcome "$win_n" "$win_a"); kc_out=$(outcome "$win_n" "$win_k")
  if [ -n "$FIXTURE_RUNTIME" ]; then ssh_out=$(outcome "$win_n" "$win_s"); else ssh_out=not_measured; fi
  post_n=$(getn post 2); post_a=$(getn post 3); post_k=$(getn post 4)

  # Canary scan over every artifact this run wrote (prefix assembled at runtime).
  if grep -r -l -F "$CANARY_PREFIX" "$OUT_DIR" >/dev/null 2>&1; then leak="LEAK_DETECTED"; fi

  # Gate-probe convention (tests/evidence/README.md): status describes the evidence (verified = ran as
  # designed, valid measurement, cleanup complete, no canary); observed_result.verdict (pass|fail|
  # inconclusive) refers to the stated criterion below and is inconclusive whenever status is not verified.
  if [ "$MODE" = smoke ]; then
    criterion="Smoke (harness check, screen unlocked, no lock): the dedicated agent signs and the disposable keychain item reads in every sample; with --fixture-runtime also a fresh SSH login to ca1 succeeds in every sample while the ca2 principal-mismatch and ca1 no-agent controls are refused. Validity: completed without interruption or setup failure, cleanup complete, no canary in artifacts."
  else
    criterion="Lock (A03 substrate, owner-driven screen lock): in the established lock window the dedicated agent signs in every sample and, with --fixture-runtime, a fresh SSH login to ca1 succeeds in every sample. The disposable keychain outcome is recorded but not part of the verdict. Validity: lock window established (IORegistry signal or owner attestation, not denied by the owner), at least one baseline and one post-unlock sample, completed, cleanup complete, no canary."
  fi
  if [ "$INTERRUPTED" -eq 0 ] && [ "$SETUP_OK" -eq 1 ] && cleanup_complete && [ "$leak" = clean ]; then
    if [ "$MODE" = smoke ]; then
      valid=1
      verdict=pass
      { [ "$agent_out" = available_all_samples ] && [ "$kc_out" = available_all_samples ]; } || verdict=fail
      if [ -n "$FIXTURE_RUNTIME" ]; then
        { [ "$ssh_out" = available_all_samples ] && [ "$NEG_SCOPE_RC" != 0 ] && [ "$NEG_NOAGENT_RC" != 0 ]; } || verdict=fail
      fi
    else
      case "$lock_evidence" in ioreg_lock_signal|owner_attestation_only) valid=1;; esac
      [ "$ATTEST_LOCK" = no ] && valid=0
      { [ "$(getn pre 2)" -ge 1 ] && [ "$post_n" -ge 1 ]; } || valid=0
      if [ "$valid" -eq 1 ]; then
        verdict=pass
        [ "$agent_out" = available_all_samples ] || verdict=fail
        if [ -n "$FIXTURE_RUNTIME" ]; then [ "$ssh_out" = available_all_samples ] || verdict=fail; fi
      fi
    fi
  fi
  [ "$valid" -eq 1 ] && status="verified"
  [ "$status" = verified ] || verdict="inconclusive"
  # Smoke runs are harness checks: no product requirement IDs (gate-probe convention).
  if [ "$MODE" = smoke ]; then reqs='[]'; else reqs='["R-CR-02", "R-CR-03", "R-EN-04"]'; fi
  local cc=false; cleanup_complete && cc=true
  if [ "$MODE" = smoke ]; then
    summary="Smoke run, screen unlocked, no lock exercised: dedicated agent signing=$agent_out; disposable keychain read=$kc_out; fresh SSH login=$ssh_out; $total samples; cleanup_complete=$cc; canary_scan=$leak."
  else
    summary="Screen-lock window evidence=$lock_evidence ($win_n samples). In the window: dedicated agent signing=$agent_out; disposable custom keychain read=$kc_out; fresh SSH login=$ssh_out. After unlock: agent ok $post_a/$post_n, keychain ok $post_k/$post_n. cleanup_complete=$cc; canary_scan=$leak."
  fi
  [ "$SETUP_FAILED" -eq 1 ] && summary="SETUP FAILED: ${SETUP_NOTES}$summary"
  [ "$INTERRUPTED" -eq 1 ] && summary="INTERRUPTED before completion. $summary"

  if [ "$INTERRUPTED" -eq 1 ]; then exit_code=5
  elif [ "$SETUP_FAILED" -eq 1 ]; then exit_code=3
  elif [ "$cc" != true ] || [ "$leak" != clean ]; then exit_code=4
  elif [ "$status" = verified ] && [ "$verdict" = pass ]; then exit_code=0
  else exit_code=1; fi
  log "result: status=$status verdict=$verdict; $summary"

  # Environment: no hostname, user name, or paths outside the repository.
  local osv osb arch model sshv commit ref script_sha args lock_secs_obs=null p first=1
  osv=$(sw_vers -productVersion 2>/dev/null); osb=$(sw_vers -buildVersion 2>/dev/null); arch=$(uname -m)
  model=$(sysctl -n hw.model 2>/dev/null); sshv=$("$SSH" -V 2>&1 | head -1)
  commit=null
  if [ -f "$REPO_ROOT/.git/HEAD" ]; then
    ref=$(sed -n 's/^ref: //p' "$REPO_ROOT/.git/HEAD")
    if [ -n "$ref" ] && [ -f "$REPO_ROOT/.git/$ref" ]; then commit=$(json_str "$(cat "$REPO_ROOT/.git/$ref")")
    elif [ -z "$ref" ]; then commit=$(json_str "$(cat "$REPO_ROOT/.git/HEAD")"); fi
  fi
  script_sha=$(shasum -a 256 "$SCRIPT_FILE" | cut -d' ' -f1)
  args="--mode $MODE --interval $INTERVAL"
  if [ "$MODE" = smoke ]; then args="$args --smoke-samples $SMOKE_SAMPLES"
  else args="$args --pre-samples $PRE_SAMPLES --post-samples $POST_SAMPLES --lock-seconds $LOCK_SECONDS"; fi
  [ -n "$FIXTURE_RUNTIME" ] && args="$args --fixture-runtime $(relpath "$FIXTURE_RUNTIME")"
  [ "$USE_CAFFEINATE" -eq 0 ] && args="$args --no-caffeinate"
  [ -n "$LOCK_INSTRUCTED_EPOCH" ] && [ -n "$OWNER_RETURNED_EPOCH" ] && lock_secs_obs=$((OWNER_RETURNED_EPOCH - LOCK_INSTRUCTED_EPOCH))
  local ssh_cmd="fresh SSH login sampling not enabled (no --fixture-runtime)"
  [ -n "$FIXTURE_RUNTIME" ] && ssh_cmd="per sample: /usr/bin/ssh -F <tmp ssh_config> probe-target true (fixture ca1, IdentitiesOnly=yes, IdentityAgent=dedicated agent, ControlMaster=no, BatchMode=yes); setup negative controls: ca2 (principal mismatch) and ca1 with IdentityAgent=none"

  {
    printf '{\n'
    printf '  "case_id": %s,\n' "$(json_str "$CASE_ID")"
    printf '  "status": "%s",\n' "$status"
    printf '  "requirement_ids": %s,\n' "$reqs"
    printf '  "build_commit": %s,\n' "$commit"
    printf '  "artifact_digest": %s,\n' "$(json_str "sha256:$script_sha (tests/native/macos/g04_lock_probe.sh as run)")"
    printf '  "environment": {"platform": "macOS", "os_version": %s, "os_build": %s, "arch": %s, "hardware_model": %s, "bash": %s, "native_host": true, "human_driven_lock": %s},\n' \
      "$(json_str "$osv")" "$(json_str "$osb")" "$(json_str "$arch")" "$(json_str "$model")" "$(json_str "$BASH_VERSION")" "$([ "$MODE" = lock ] && echo true || echo false)"
    printf '  "provider_versions": [{"component": "ssh-agent, ssh-add, ssh-keygen, ssh (/usr/bin)", "version": %s}, {"component": "file-based custom keychain via /usr/bin/security", "version": %s}],\n' \
      "$(json_str "$sshv")" "$(json_str "macOS $osv ($osb)")"
    printf '  "started_at": "%s",\n' "$STARTED_AT"
    printf '  "commands_or_harness": [\n    %s,\n    %s,\n    %s,\n    %s,\n    %s,\n    %s\n  ],\n' \
      "$(json_str "tests/native/macos/g04_lock_probe.sh $args")" \
      "$(json_str "setup: security -i (stdin) create-keychain in temp dir; security set-keychain-settings (no auto-lock); security -i (stdin) add-generic-password with a random canary")" \
      "$(json_str "setup: HOME=<tmp> /usr/bin/ssh-agent -U -a <tmp>/agent.sock; ssh-keygen -t ed25519; ssh-add -t 14400 <key>; rm <private key file>")" \
      "$(json_str "per sample: ssh-add -T <pub>; ssh-keygen -Y sign -f <pub> via the dedicated agent, then -Y check-novalidate; security find-generic-password -w <tmp keychain> (compared in-process, never printed); ioreg IOConsoleLocked and CGSSessionScreenIsLocked only")" \
      "$(json_str "$ssh_cmd")" \
      "$(json_str "cleanup: kill exact dedicated agent PID (comm+lstart re-checked); security delete-keychain <tmp keychain>; compare user search list and default keychain digests; rm -rf <tmp>")"
    printf '  "observed_result": {\n'
    printf '    "verdict": "%s",\n' "$verdict"
    printf '    "criterion": %s,\n' "$(json_str "$criterion")"
    printf '    "summary": %s,\n' "$(json_str "$summary")"
    printf '    "mode": "%s",\n    "probe_exit_code": %s,\n    "samples_total": %s,\n    "max_gap_between_samples_s": %s,\n    "interval_s": %s,\n' "$MODE" "$exit_code" "$total" "$maxgap" "$INTERVAL"
    printf '    "lock_window_evidence": "%s",\n    "lock_window_samples": %s,\n    "owner_lock_seconds_observed": %s,\n' "$lock_evidence" "$win_n" "$lock_secs_obs"
    printf '    "outcomes_in_window": {"dedicated_agent_signing": "%s", "disposable_keychain_read": "%s", "fresh_ssh_login": "%s"},\n' "$agent_out" "$kc_out" "$ssh_out"
    printf '    "per_phase_counts": ['
    for p in smoke pre lock_window post locked_signal; do
      if [ "$(getn "$p" 2)" -eq 0 ] && { [ "$p" != locked_signal ] || [ "$MODE" = smoke ]; }; then continue; fi
      [ $first -eq 1 ] || printf ', '; first=0
      printf '{"phase": "%s", "samples": %s, "agent_ok": %s, "keychain_ok": %s, "ssh_ok": %s}' "$p" "$(getn "$p" 2)" "$(getn "$p" 3)" "$(getn "$p" 4)" "$(getn "$p" 5)"
    done
    printf '],\n'
    printf '    "ssh_negative_controls": {"ca2_principal_mismatch_rc": %s, "ca1_without_agent_rc": %s, "certificate": %s},\n' "${NEG_SCOPE_RC:-null}" "${NEG_NOAGENT_RC:-null}" "$(json_str "$CERT_NOTE")"
    printf '    "owner_attestation": {"screen_locked": "%s", "probe_keychain_dialog_seen": "%s"},\n' "$ATTEST_LOCK" "$ATTEST_DIALOG"
    printf '    "disposable_keychain_settings": %s,\n' "$(json_str "${KC_SETTINGS:-unknown}")"
    printf '    "cleanup": {"sampler": "%s", "dedicated_agent": "%s", "agent_socket": "%s", "keychain_file": "%s", "user_search_list": "%s", "default_keychain": "%s", "caffeinate": "%s", "temp_dir": "%s", "complete": %s},\n' \
      "$CLEAN_SAMPLER" "$CLEAN_AGENT" "$CLEAN_AGENT_SOCKET" "$CLEAN_KEYCHAIN" "$CLEAN_SEARCHLIST" "$CLEAN_DEFAULT_KC" "$CLEAN_CAF" "$CLEAN_TEMP" "$cc"
    printf '    "canary_scan_of_artifacts": "%s",\n    "interrupted": %s,\n    "setup_notes": %s\n' "$leak" "$([ "$INTERRUPTED" -eq 1 ] && echo true || echo false)" "$(json_str "${SETUP_NOTES:-none}")"
    printf '  },\n'
    printf '  "evidence_paths": [%s, %s, %s],\n' "$(json_str "$(relpath "$SAMPLES")")" "$(json_str "$(relpath "$SAMPLES_TSV")")" "$(json_str "$(relpath "$RUNLOG")")"
    printf '  "limitations": [\n'
    printf '    %s,\n' "$(json_str "Measures a dedicated, script-started OpenSSH ssh-agent and a disposable file-based custom keychain only. Says nothing about the login keychain, the data-protection keychain, Secure Enclave/CTK keys, 1Password, or a launchd-supervised Heimdall signer.")"
    printf '    %s,\n' "$(json_str "Screen lock only. Logout, sleep, reboot and headless operation are separate probes (docs/research/g04-managed-credentials.md).")"
    printf '    %s,\n' "$(json_str "ioreg IOConsoleLocked / CGSSessionScreenIsLocked are undocumented IORegistry properties used only as corroboration; owner attestation is recorded separately.")"
    printf '    %s,\n' "$(json_str "The disposable keychain has auto-lock disabled (no timeout, no lock-on-sleep), so any lock observed is attributable to OS behavior at screen lock, not to keychain settings.")"
    printf '    %s,\n' "$(json_str "On macOS 26.4+ a keychain file may reference a protected entropy file in /var/db/SystemKeys (Apple TN3137); whether delete-keychain removes it cannot be inspected without disabling SIP.")"
    printf '    %s,\n' "$(json_str "Status verified means the measurement is valid (lock window established for lock mode, run completed, cleanup complete, no canary in artifacts); it holds even when the verdict is fail. Availability itself is reported in observed_result.outcomes_in_window and may be negative.")"
    printf '    %s\n' "$(json_str "$([ "$MODE" = smoke ] && echo "Smoke run: harness check only, no screen lock exercised, so no product requirement IDs and no lock-continuity evidence." || echo "Requirement IDs are listed for traceability; this record is not by itself evidence that a product requirement is met (tests/evidence/README.md).")")"
    printf '  ],\n'
    printf '  "blocked_on": null\n'
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

on_signal() { INTERRUPTED=1; log "interrupted by signal $1; cleaning up"; finish; }
trap 'on_signal INT' INT; trap 'on_signal TERM' TERM; trap 'on_signal HUP' HUP
trap 'finish' EXIT

# ---------------------------------------------------------------- setup
log "g04_lock_probe v$PROBE_VERSION mode=$MODE interval=${INTERVAL}s out=$(relpath "$OUT_DIR")"
T=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-g04-lock.XXXXXXXX") || setup_fail "mktemp failed"
chmod 700 "$T"
case "$T" in *[[:space:]]*|*'"'*) setup_fail "temp path contains whitespace or quotes; set TMPDIR to a simple path";; esac
log "temp dir created (disposable)"

if [ "$USE_CAFFEINATE" -eq 1 ]; then
  "$CAFFEINATE" -i -w $$ >/dev/null 2>&1 &
  CAF_PID=$!; disown "$CAF_PID" 2>/dev/null; sleep 0.2; CAF_IDENT=$(proc_ident "$CAF_PID")
  log "caffeinate -i (idle-sleep assertion, exits with this script) pid=$CAF_PID"
fi

# Disposable custom keychain. Password and canary go through `security -i` stdin, never argv.
KC_LIST_DIGEST_BEFORE=$("$SECURITY" list-keychains -d user 2>/dev/null | shasum -a 256)
KC_DEFAULT_DIGEST_BEFORE=$("$SECURITY" default-keychain -d user 2>/dev/null | shasum -a 256)
KC="$T/heimdall-g04-probe.keychain-db"
KC_PW=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
CANARY="${CANARY_PREFIX}G04_LOCKPROBE_$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
printf 'create-keychain -p %s %s\n' "$KC_PW" "$KC" | "$SECURITY" -i >/dev/null 2>&1
KC_PW=""
[ -e "$KC" ] || setup_fail "disposable keychain creation failed"
if "$SECURITY" list-keychains -d user 2>/dev/null | grep -F -q "$KC"; then
  SETUP_NOTES="${SETUP_NOTES}probe keychain appeared in the user search list (removed by delete-keychain at cleanup); "
  log "NOTE: probe keychain appeared in the user search list; delete-keychain removes it at cleanup"
fi
"$SECURITY" set-keychain-settings "$KC" >/dev/null 2>&1 || setup_fail "set-keychain-settings failed"
KC_SETTINGS=$("$SECURITY" show-keychain-info "$KC" 2>&1 | sed -n 's/.*keychain-db" *//p' | head -1)
log "disposable keychain created; settings: ${KC_SETTINGS:-unknown} (auto-lock disabled)"
printf 'add-generic-password -a %s -s %s -w %s %s\n' "$KC_ACCT" "$KC_SVC" "$CANARY" "$KC" | "$SECURITY" -i >/dev/null 2>&1

# Dedicated ssh-agent: socket in the temp dir, HOME pointed at the temp dir, -U so it never
# scans or cleans $HOME/.ssh/agent. The caller's agent is never contacted.
AGENT_OUT=$(HOME="$T" "$SSH_AGENT" -U -a "$T/agent.sock" -s 2>/dev/null)
AGENT_PID=$(printf '%s\n' "$AGENT_OUT" | sed -n 's/^SSH_AGENT_PID=\([0-9][0-9]*\);.*/\1/p')
{ [ -n "$AGENT_PID" ] && [ -S "$T/agent.sock" ]; } || setup_fail "dedicated ssh-agent did not start"
AGENT_IDENT=$(proc_ident "$AGENT_PID")
case "$AGENT_IDENT" in
  */ssh-agent) ;;
  *) # Do not kill something we cannot identify; keep the PID so cleanup reports it as residue.
     log "ERROR: PID $AGENT_PID reported by ssh-agent does not look like ssh-agent; it will NOT be killed. Check it manually."
     AGENT_IDENT="unverified"; setup_fail "started PID could not be verified as ssh-agent";;
esac
log "dedicated ssh-agent pid=$AGENT_PID"
export SSH_AUTH_SOCK="$T/agent.sock"   # child commands only ever see the dedicated agent

"$SSH_KEYGEN" -q -t ed25519 -N '' -C "heimdall-g04-lock-probe-$STAMP" -f "$T/probe" || setup_fail "ssh-keygen failed"
if [ -n "$FIXTURE_RUNTIME" ]; then
  CERT_MIN=$(( (PRE_SAMPLES + POST_SAMPLES + SMOKE_SAMPLES) * INTERVAL / 60 + LOCK_SECONDS / 60 + 30 ))
  "$SSH_KEYGEN" -q -s "$FX_CAKEY" -I "heimdall-g04-lock-probe-$STAMP" -n p-host1 -V "-5m:+${CERT_MIN}m" "$T/probe.pub" \
    || setup_fail "could not sign the probe certificate with the fixture CA"
  CERT_NOTE="principal p-host1, validity -5m:+${CERT_MIN}m, issued by fixture CA"
  log "probe certificate issued ($CERT_NOTE)"
fi
# Lifetime safety net: even if cleanup failed, the agent drops the key after 4 hours.
"$SSH_ADD" -q -t 14400 "$T/probe" >/dev/null 2>&1 || setup_fail "ssh-add to the dedicated agent failed"
rm -f "$T/probe"
log "disposable key loaded into the dedicated agent; private key file removed (key now only in agent memory)"

if [ -n "$FIXTURE_RUNTIME" ]; then
  cat > "$T/ssh_config" <<EOF
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
  IdentityAgent "$T/agent.sock"
  IdentitiesOnly yes
  IdentityFile "$T/probe.pub"
  CertificateFile "$T/probe-cert.pub"
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
  run_with_timeout 25 "$SSH" -F "$T/ssh_config" probe-negative true </dev/null >/dev/null 2>&1; NEG_SCOPE_RC=$?
  run_with_timeout 25 "$SSH" -F "$T/ssh_config" -o IdentityAgent=none probe-target true </dev/null >/dev/null 2>&1; NEG_NOAGENT_RC=$?
  log "negative controls: ca2 with p-host1 cert rc=$NEG_SCOPE_RC (expect non-zero); ca1 without agent rc=$NEG_NOAGENT_RC (expect non-zero)"
fi
SETUP_OK=1

# ---------------------------------------------------------------- sampling
lock_signals() {  # echoes "<IOConsoleLocked> <CGSSessionScreenIsLocked>"; nothing else is kept
  local x ioc cgs
  x=$("$IOREG" -n Root -d1 -a 2>/dev/null)
  ioc=$(printf '%s\n' "$x" | grep -A1 '<key>IOConsoleLocked</key>' | grep -o -E 'true|false' | head -1)
  cgs=$(printf '%s\n' "$x" | grep -A1 '<key>CGSSessionScreenIsLocked</key>' | grep -o -E 'true|false' | head -1)
  x=""
  printf '%s %s\n' "${ioc:-absent}" "${cgs:-absent}"
}
sample_once() {
  local seq=$1 phase=$2 t_utc t_epoch sig ioc cgs add_rc sign_rc ver_rc kc_rc kc_match out ssh_rc
  t_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ); t_epoch=$(date -u +%s)
  sig=$(lock_signals); ioc=${sig% *}; cgs=${sig#* }
  run_with_timeout 10 "$SSH_ADD" -T "$T/probe.pub" >/dev/null 2>&1; add_rc=$?
  printf 'heimdall-g04-lock-probe nonce %s %s\n' "$seq" "$t_epoch" > "$T/msg"
  rm -f "$T/msg.sig"
  run_with_timeout 10 "$SSH_KEYGEN" -Y sign -q -f "$T/probe.pub" -n heimdall-g04-lock-probe "$T/msg" >/dev/null 2>&1; sign_rc=$?
  if [ "$sign_rc" -eq 0 ]; then
    "$SSH_KEYGEN" -Y check-novalidate -n heimdall-g04-lock-probe -s "$T/msg.sig" < "$T/msg" >/dev/null 2>&1; ver_rc=$?
  else ver_rc=-1; fi
  out=$(run_with_timeout 8 "$SECURITY" find-generic-password -a "$KC_ACCT" -s "$KC_SVC" -w "$KC" 2>/dev/null); kc_rc=$?
  if [ "$kc_rc" -eq 0 ] && [ "$out" = "$CANARY" ]; then kc_match=true; else kc_match=false; fi
  out=""
  if [ -n "$FIXTURE_RUNTIME" ]; then
    run_with_timeout 25 "$SSH" -F "$T/ssh_config" probe-target true </dev/null >/dev/null 2>&1; ssh_rc=$?
  else ssh_rc=null; fi
  printf '{"seq":%s,"phase":"%s","t_utc":"%s","t_epoch":%s,"lock_signals":{"io_console_locked":"%s","cgs_session_screen_is_locked":"%s"},"agent":{"ssh_add_T_rc":%s,"ssh_keygen_Y_sign_rc":%s,"signature_check_rc":%s},"keychain":{"find_generic_password_rc":%s,"value_matches":%s},"fresh_ssh_login_rc":%s}\n' \
    "$seq" "$phase" "$t_utc" "$t_epoch" "$ioc" "$cgs" "$add_rc" "$sign_rc" "$ver_rc" "$kc_rc" "$kc_match" "$ssh_rc" >> "$SAMPLES"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$seq" "$phase" "$t_epoch" "$ioc" "$cgs" "$add_rc" "$sign_rc" "$ver_rc" "$kc_rc" "$kc_match" "$ssh_rc" >> "$SAMPLES_TSV"
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
wait_samples() {  # wait until at least N samples exist (bounded)
  local limit=$(( ($1 + 2) * (INTERVAL + 60) )) waited=0
  while [ "$(sample_count)" -lt "$1" ] && [ $waited -lt $limit ]; do sleep 1; waited=$((waited+1)); done
}

if [ "$MODE" = smoke ]; then
  echo smoke > "$T/phase"
  sampler & SAMPLER_PID=$!
  log "sampler pid=$SAMPLER_PID; taking $SMOKE_SAMPLES samples (screen stays unlocked)"
  wait_samples "$SMOKE_SAMPLES"
else
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
: > "$T/stop"; wait "$SAMPLER_PID" 2>/dev/null
log "sampling stopped; $(sample_count) samples"

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
  ATTEST_DIALOG=$(ask_yn "After unlocking, did any keychain or password dialog mention 'heimdall-g04-probe'?")
  log "owner attestation: screen_locked=$ATTEST_LOCK probe_keychain_dialog_seen=$ATTEST_DIALOG"
fi
finish
