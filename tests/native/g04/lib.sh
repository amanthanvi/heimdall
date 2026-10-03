#!/bin/bash
# tests/native/g04/lib.sh - shared harness for the G04 / preliminary G09 OpenSSH mechanism
# experiments (docs/research/g04-managed-credentials.md section 8.1). Source it from an
# experiment script after setting EXP=<name>. bash 3.2 compatible (macOS /bin/bash).
#
# What these experiments measure: OpenSSH client (host /usr/bin/ssh) and sshd (fixture
# containers) mechanisms. They do not run or test Heimdall code.
#
# Safety rules enforced here:
#  - SSH_AUTH_SOCK, SSH_AGENT_PID and askpass variables are unset. /usr/bin/ssh, ssh-keygen,
#    ssh-agent, ssh-add are called by absolute path.
#  - Every ssh call uses -F <per-experiment generated config>: StrictHostKeyChecking yes, the
#    fixture known_hosts, GlobalKnownHostsFile /dev/null, IdentitiesOnly, IdentityAgent set to a
#    dedicated agent started here (or none). The owner's ~/.ssh and agent are never read.
#  - Dedicated agents and ssh masters started here are recorded by PID + start time + executable
#    and are signalled only after that identity is re-checked. No pattern kills.
#  - Only the fixture's loopback ports (tests/fixtures/ssh/runtime/ports.env) are contacted.
#  - Private keys generated here live in a 0700 temp dir and are deleted right after ssh-add.
#  - Logs are redacted (temp dir, fixture runtime dir, repo root and $HOME replaced by tokens).
#
# Output per experiment: tests/evidence/artifacts/g04/experiments/<RUN_STAMP>/<EXP>.log
# (redacted transcript with every command and its real exit code) and <EXP>.results.tsv
# (CHECK / OBS / FACT rows consumed by make_records.py).
# Exit code: 0 = ran to completion and every expectation held; 1 = ran to completion but at
# least one expectation did not hold (finding or harness defect; review the log);
# 3 = setup failure / aborted (incomplete run).

set -u
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY
SSH=/usr/bin/ssh
SSH_KEYGEN=/usr/bin/ssh-keygen
SSH_AGENT=/usr/bin/ssh-agent
SSH_ADD=/usr/bin/ssh-add
PERL=/usr/bin/perl

G04_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$G04_DIR/../../.." && pwd)"
FX_DIR="$REPO_ROOT/tests/fixtures/ssh"
FX_RT="$FX_DIR/runtime"
FX_KEYS="$FX_RT/keys"
FX_KNOWN="$FX_RT/known_hosts"
FX_CA="$FX_KEYS/user_ca"
FX_CA_ROGUE="$FX_KEYS/user_ca_rogue"
CPREFIX="hm-m00t03"

: "${EXP:?EXP must be set before sourcing lib.sh}"
RUN_STAMP="${G04_RUN_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$REPO_ROOT/tests/evidence/artifacts/g04/experiments/$RUN_STAMP"
LOG="$OUT_DIR/$EXP.log"
RES="$OUT_DIR/$EXP.results.tsv"
RUN_ID="$(date -u +%H%M%S)-$$"
mkdir -p "$OUT_DIR"
: >"$LOG"; : >"$RES"

umask 077
T="$(mktemp -d "/tmp/hmg04-${EXP%%-*}.XXXXXX")" || { echo "mktemp failed" >&2; exit 3; }
chmod 700 "$T"

FAILS=0; CHECKS=0; XN=0; RC=0; OUT=""; XT0=0; XT1=0
AG_PID=(); AG_IDENT=(); AG_SOCK=()
MS_PID=(); MS_IDENT=(); MS_SOCK=(); MS_HOST=(); MS_CFG=()

# ------------------------------------------------------------------ basics
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
hr() { "$PERL" -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
vhex() { printf '0x%x' "$1"; }
red() {
  sed -e "s|/private$T|<tmp>|g" -e "s|$T|<tmp>|g" -e "s|$FX_RT|<fixture-runtime>|g" \
      -e "s|$REPO_ROOT|<repo>|g" -e "s|$HOME|<home>|g"
}
oneline() { tr '\t\n\r' '   ' | sed 's/  */ /g; s/^ //; s/ $//'; }
log() { printf '[%s] %s\n' "$(ts)" "$*" | red | tee -a "$LOG"; }
fact() { printf 'FACT\t%s\t%s\n' "$1" "$(printf '%s' "$2" | oneline)" | red >>"$RES"; log "FACT $1 = $2"; }
# check NAME EXPECTED OBSERVED OKFLAG(0 = expectation held)
check() {
  local st=FAIL; [ "$4" = 0 ] && st=PASS
  CHECKS=$((CHECKS+1)); [ "$st" = PASS ] || FAILS=$((FAILS+1))
  printf 'CHECK\t%s\t%s\t%s\t%s\n' "$1" "$(printf '%s' "$2" | oneline)" "$(printf '%s' "$3" | oneline)" "$st" | red >>"$RES"
  log "$st $1 | expected: $2 | observed: $3"
}
# obs NAME HYPOTHESIS OBSERVED CONFIRMEDFLAG(0 = confirmed). A refuted hypothesis is a finding,
# not a harness failure, so it does not change the exit code.
obs() {
  local st=REFUTED; [ "$4" = 0 ] && st=CONFIRMED
  printf 'OBS\t%s\t%s\t%s\t%s\n' "$1" "$(printf '%s' "$2" | oneline)" "$(printf '%s' "$3" | oneline)" "$st" | red >>"$RES"
  log "$st $1 | hypothesis: $2 | observed: $3"
}
die_setup() { log "SETUP FAILURE: $*"; printf 'SETUP_FAILURE\t%s\n' "$*" | red >>"$RES"; exit 3; }

# xrun LABEL CMD... : run CMD (stdin /dev/null), capture stdout+stderr, log it redacted with the
# real exit code. Sets RC, OUT (redacted output), XT0/XT1 (start/end epoch, ms resolution).
xrun() {
  local label=$1; shift
  XN=$((XN+1)); local f="$T/.x.$XN"
  XT0=$(hr); "$@" </dev/null >"$f" 2>&1; RC=$?; XT1=$(hr)
  OUT=$(red <"$f"); rm -f "$f"
  { printf '[%s] $ (%s) %s\n' "$(ts)" "$label" "$*"
    [ -n "$OUT" ] && printf '%s\n' "$OUT" | sed 's/^/    | /'
    printf '    rc=%s t_start=%s t_end=%s\n' "$RC" "$XT0" "$XT1"; } | red >>"$LOG"
  printf '[%s] %s -> rc=%s\n' "$(ts)" "$label" "$RC" | red
}
# xrun_in FILE LABEL CMD... : same, with stdin from FILE (logged by name only).
xrun_in() {
  local in=$1 label=$2; shift 2
  XN=$((XN+1)); local f="$T/.x.$XN"
  XT0=$(hr); "$@" <"$in" >"$f" 2>&1; RC=$?; XT1=$(hr)
  OUT=$(red <"$f"); rm -f "$f"
  { printf '[%s] $ (%s) %s < %s\n' "$(ts)" "$label" "$*" "$in"
    [ -n "$OUT" ] && printf '%s\n' "$OUT" | sed 's/^/    | /'
    printf '    rc=%s t_start=%s t_end=%s\n' "$RC" "$XT0" "$XT1"; } | red >>"$LOG"
  printf '[%s] %s -> rc=%s\n' "$(ts)" "$label" "$RC" | red
}
wait_until() {  # epoch (integer, host clock)
  local target=$1 now; now=$(date -u +%s)
  if [ "$now" -lt "$target" ]; then log "waiting $((target-now)) s (until epoch $target)"; sleep $((target-now)); fi
}

# ------------------------------------------------------------------ process identity
# comm must be the last column: macOS ps truncates a non-final comm column.
proc_ident() { ps -o lstart= -o comm= -p "$1" 2>/dev/null | sed 's/  */ /g'; }
kill_exact() {  # pid ident -> echoes outcome; signals only if lstart+comm still match
  local pid=$1 ident=$2 now i
  [ -n "$pid" ] || { echo "not_started"; return; }
  now=$(proc_ident "$pid")
  [ -n "$now" ] || { echo "already_exited"; return; }
  [ "$now" = "$ident" ] || { echo "pid_reused_not_signalled"; return; }
  kill -TERM "$pid" 2>/dev/null
  i=0; while [ $i -lt 50 ] && [ -n "$(proc_ident "$pid")" ]; do sleep 0.1; i=$((i+1)); done
  if [ -z "$(proc_ident "$pid")" ]; then echo "terminated"; else echo "still_running"; fi
}

# ------------------------------------------------------------------ dedicated agents
# start_agent DIR [debug] -> AGENT_PID, AGENT_SOCK. With "debug", runs ssh-agent -d in the
# foreground of a background job with its debug log in DIR/agent-debug.log (key fingerprints
# and request types only; the agent never logs private material).
start_agent() {
  local d=$1 mode=${2:-} out pid ident i
  mkdir -p "$d"; chmod 700 "$d"
  if [ "$mode" = debug ]; then
    HOME="$d" "$SSH_AGENT" -U -d -a "$d/agent.sock" </dev/null >/dev/null 2>"$d/agent-debug.log" &
    pid=$!
    i=0; while [ $i -lt 50 ] && [ ! -S "$d/agent.sock" ]; do sleep 0.1; i=$((i+1)); done
  else
    out=$(HOME="$d" "$SSH_AGENT" -U -a "$d/agent.sock" -s 2>/dev/null)
    pid=$(printf '%s\n' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9][0-9]*\);.*/\1/p')
  fi
  { [ -n "$pid" ] && [ -S "$d/agent.sock" ]; } || die_setup "dedicated ssh-agent did not start in $d"
  ident=$(proc_ident "$pid")
  case "$ident" in */ssh-agent) ;; *) die_setup "pid $pid not identifiable as ssh-agent; not tracked";; esac
  AG_PID[${#AG_PID[@]}]=$pid; AG_IDENT[${#AG_IDENT[@]}]=$ident; AG_SOCK[${#AG_SOCK[@]}]="$d/agent.sock"
  AGENT_PID=$pid; AGENT_SOCK="$d/agent.sock"
  log "dedicated ssh-agent started: pid=$pid ident='$ident' socket=$d/agent.sock mode=${mode:-daemon}"
}
agent_add() {  # SOCK KEYFILE [ssh-add flags...] : add, then delete the private key file
  local sock=$1 key=$2; shift 2
  xrun "ssh-add $* $(basename "$key")" env SSH_AUTH_SOCK="$sock" "$SSH_ADD" "$@" "$key"
  local addrc=$RC
  rm -f "$key"
  [ -e "$key" ] && die_setup "could not delete private key file $key"
  [ "$addrc" = 0 ] || die_setup "ssh-add failed for $key (rc=$addrc)"
}
agent_list() { xrun "ssh-add -l ($1)" env SSH_AUTH_SOCK="$1" "$SSH_ADD" -l; }

# ------------------------------------------------------------------ keys and certificates
genkey() { "$SSH_KEYGEN" -q -t ed25519 -N '' -C "$2" -f "$1" || die_setup "ssh-keygen failed for $1"; }
# sign_file CAKEY PUB ID PRINCIPALS VALIDITY OUT : sign with a CA private key file (fixture CA)
sign_file() {
  local ca=$1 pub=$2 id=$3 pr=$4 v=$5 outf=$6 gen="${2%.pub}-cert.pub"
  "$SSH_KEYGEN" -q -s "$ca" -I "$id" -n "$pr" -V "$v" "$pub" >/dev/null 2>&1 || die_setup "signing $id failed"
  [ "$gen" = "$outf" ] || mv -f "$gen" "$outf"
  log "certificate $id: $(cert_info "$outf")"
}
# sign_agent ISSUER_SOCK CAPUB PUB ID PRINCIPALS VALIDITY OUT : sign with a CA held in an agent
sign_agent() {
  local sock=$1 capub=$2 pub=$3 id=$4 pr=$5 v=$6 outf=$7 gen="${3%.pub}-cert.pub"
  xrun "issuer signs $id" env SSH_AUTH_SOCK="$sock" "$SSH_KEYGEN" -U -s "$capub" -I "$id" -n "$pr" -V "$v" "$pub"
  [ "$RC" = 0 ] || return 1
  [ "$gen" = "$outf" ] || mv -f "$gen" "$outf"
  log "certificate $id: $(cert_info "$outf")"
}
cert_info() {  # validity printed in UTC (ssh-keygen -L prints local time; TZ=UTC pins it)
  TZ=UTC "$SSH_KEYGEN" -L -f "$1" 2>/dev/null | awk '
    /Key ID:/ {sub(/^ *Key ID: */,""); id=$0}
    /Signing CA:/ {sub(/^ *Signing CA: */,""); ca=$0}
    /Valid:/ {sub(/^ *Valid: */,""); v=$0}
    /Principals:/ {p=1; next}
    p==1 && /^ +[^ ]/ && !/Critical|Extensions/ {gsub(/^ +/,""); pr=pr (pr?",":"") $0; next}
    /Critical Options:/ {p=0}
    END {printf "id=%s principals=%s valid=[%s] ca=%s", id, pr, v, ca}'
}
fp_of() { "$SSH_KEYGEN" -l -f "$1" | awk '{print $2}'; }
# Read back what a certificate actually carries (not what the harness asked for).
cert_principals() {  # CERT -> principals, comma-separated, in certificate order
  "$SSH_KEYGEN" -L -f "$1" 2>/dev/null | awk '/Principals:/ {p=1; next} p==1 && /^ +[^ ]/ && !/Critical|Extensions/ {gsub(/^ +/,""); s=s (s?",":"") $0; next} /Critical Options:/ {p=0} END {print s}'
}
cert_vb_epoch() {  # CERT -> valid_before as epoch seconds (ssh-keygen -L "to" time read in UTC)
  local t; t=$(TZ=UTC "$SSH_KEYGEN" -L -f "$1" 2>/dev/null | sed -n 's/^ *Valid: from [^ ]* to \([0-9T:-]*\)$/\1/p')
  [ -n "$t" ] && TZ=UTC date -j -f '%Y-%m-%dT%H:%M:%S' "$t" +%s 2>/dev/null
}

# ------------------------------------------------------------------ fixture access
load_fixture() {
  [ -f "$FX_RT/ports.env" ] && [ -f "$FX_KNOWN" ] && [ -f "$FX_CA" ] || die_setup "fixture runtime missing; run tests/fixtures/ssh/up.sh"
  # shellcheck disable=SC1091
  . "$FX_RT/ports.env"
  local r; for r in ca1 ca2 enroll; do
    [ "$(docker inspect -f '{{.State.Running}}' "$CPREFIX-$r" 2>/dev/null)" = true ] || die_setup "fixture container $CPREFIX-$r not running"
  done
}
cname() { printf '%s-%s' "$CPREFIX" "$1"; }
account_of() { case "$1" in ca1|ca2) echo cert;; enroll) echo enroll;; fixed) echo fixed;; esac; }
# write_cfg FILE AGENT_SOCK|none IDENTITY|none [extra Host-* lines...]
write_cfg() {
  local f=$1 agent=$2 ident=$3; shift 3
  local r port
  {
    echo "# generated by tests/native/g04 ($EXP, run $RUN_ID); disposable"
    for r in ca1 ca2 enroll fixed; do
      port=$(eval "echo \${PORT_$r:-}")
      [ -n "$port" ] || continue
      printf 'Host g-%s\n  HostName 127.0.0.1\n  Port %s\n  User %s\n  HostKeyAlias hm-%s\n' "$r" "$port" "$(account_of "$r")" "$r"
    done
    echo "Host *"
    # experiment-specific lines first: for single-valued options the first value wins
    for l in "$@"; do echo "  $l"; done
    echo "  UserKnownHostsFile \"$FX_KNOWN\""
    echo "  GlobalKnownHostsFile /dev/null"
    echo "  StrictHostKeyChecking yes"
    echo "  CheckHostIP no"
    echo "  UpdateHostKeys no"
    echo "  VerifyHostKeyDNS no"
    if [ "$agent" = none ]; then echo "  IdentityAgent none"; else echo "  IdentityAgent \"$agent\""; fi
    if [ "$ident" = none ]; then echo "  IdentityFile none"; else echo "  IdentityFile \"$ident\""; fi
    echo "  IdentitiesOnly yes"
    echo "  ControlMaster no"
    echo "  ControlPath none"
    echo "  PreferredAuthentications publickey"
    echo "  PasswordAuthentication no"
    echo "  KbdInteractiveAuthentication no"
    echo "  BatchMode yes"
    echo "  ForwardAgent no"
    echo "  ForwardX11 no"
    echo "  ConnectTimeout 10"
    echo "  LogLevel ERROR"
  } >"$f"
  chmod 600 "$f"
}
# server log helpers (sshd -D -e LogLevel VERBOSE writes to the container log)
srvlog() { docker logs "$(cname "$1")" 2>&1; }
mark() { srvlog "$1" | wc -l | tr -d ' '; }
new_lines() { srvlog "$1" | tail -n +$(( $2 + 1 )); }
# count_new ROLE MARK PATTERN1 [PATTERN2] : new log lines containing all fixed-string patterns
count_new() {
  local role=$1 m=$2 p1=$3 p2=${4:-}
  if [ -n "$p2" ]; then new_lines "$role" "$m" | grep -F -- "$p1" | grep -c -F -- "$p2"
  else new_lines "$role" "$m" | grep -c -F -- "$p1"; fi
}
log_new() {  # ROLE MARK LABEL : copy the new server log lines into the experiment log
  { printf '[%s] server log %s (%s), new lines:\n' "$(ts)" "$(cname "$1")" "$3"
    new_lines "$1" "$2" | grep -v -e 'kex_exchange_identification' | sed 's/^/    > /'; } | red >>"$LOG"
}
clock_offset() {  # ROLE -> echoes "offset_s=<container-host> rtt_s=<x>"
  local h0 c h1
  h0=$(hr); c=$(docker exec "$(cname "$1")" date -u +%s.%N 2>/dev/null); h1=$(hr)
  "$PERL" -e 'printf "offset_s=%.3f rtt_s=%.3f\n", $ARGV[1] - ($ARGV[0]+$ARGV[2])/2, $ARGV[2]-$ARGV[0]' -- "$h0" "$c" "$h1"
}
record_env() {
  fact host_ssh "$("$SSH" -V 2>&1)"
  fact container_sshd "$(docker exec "$(cname ca1)" dpkg-query -W -f='${Package} ${Version}' openssh-server 2>/dev/null)"
  fact docker_server "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  fact ssh_auth_sock_in_harness "${SSH_AUTH_SOCK-unset}"
  fact clock_ca1 "$(clock_offset ca1)"
}

# ------------------------------------------------------------------ ssh control masters
# start_master CFG CTLPATH PERSIST HOST [extra ssh args] -> MASTER_PID (tracked), RC
start_master() {
  local cfg=$1 cp=$2 persist=$3 host=$4; shift 4
  xrun "start master $(basename "$cp")" "$SSH" -F "$cfg" -o ControlMaster=yes -o ControlPath="$cp" -o ControlPersist="$persist" "$@" -N -f "$host"
  MASTER_PID=""
  [ "$RC" = 0 ] || return 1
  MASTER_PID=$(master_pid "$cfg" "$cp" "$host")
  [ -n "$MASTER_PID" ] || return 1
  local ident; ident=$(ssh_lstart "$MASTER_PID")
  if [ -z "$ident" ] || ! ssh_comm_ok "$MASTER_PID"; then log "master pid $MASTER_PID not identifiable as ssh; not tracked"; MASTER_PID=""; return 1; fi
  MS_PID[${#MS_PID[@]}]=$MASTER_PID; MS_IDENT[${#MS_IDENT[@]}]=$ident; MS_SOCK[${#MS_SOCK[@]}]=$cp
  MS_HOST[${#MS_HOST[@]}]=$host; MS_CFG[${#MS_CFG[@]}]=$cfg
  log "master started: pid=$MASTER_PID lstart='$ident' comm='$(ssh_comm "$MASTER_PID")' controlpath=$cp persist=$persist"
}
master_pid() {  # CFG CTLPATH HOST -> pid from "Master running (pid=N)"
  "$SSH" -F "$1" -S "$2" -O check "$3" </dev/null 2>&1 | sed -n 's/^Master running (pid=\([0-9][0-9]*\)).*/\1/p'
}
master_ident_of() {  # PID -> tracked start time (empty if not ours)
  local i=0; while [ $i -lt ${#MS_PID[@]} ]; do [ "${MS_PID[$i]}" = "$1" ] && { echo "${MS_IDENT[$i]}"; return; }; i=$((i+1)); done
}
alive_exact() {  # PID IDENT -> 0 if the same process is still running
  [ -n "$1" ] && [ "$(proc_ident "$1")" = "$2" ]
}
# ssh processes retitle themselves: observed on this host, a master shows "ssh: [stopped mux]" in
# ps comm after -O stop (macOS ps comm follows argv). Their identity is PID + start time, with the
# executable checked loosely (/usr/bin/ssh, ssh, or an "ssh: " title). Zombies show "(ssh)" and fail.
ssh_lstart() { ps -o lstart= -p "$1" 2>/dev/null | sed 's/  */ /g; s/^ //; s/ $//'; }
ssh_comm() { ps -o comm= -p "$1" 2>/dev/null; }
ssh_comm_ok() { case "$(ssh_comm "$1")" in /usr/bin/ssh|ssh|"ssh: "*) return 0;; *) return 1;; esac; }
alive_ssh() { [ -n "$1" ] && [ -n "$2" ] && [ "$(ssh_lstart "$1")" = "$2" ] && ssh_comm_ok "$1"; }
kill_ssh() {  # PID LSTART -> outcome; signals only our own still-identified ssh process
  local i
  if ! alive_ssh "$1" "$2"; then
    if [ -z "$(ssh_lstart "$1")" ]; then echo "already_exited"; else echo "identity_mismatch_not_signalled"; fi; return
  fi
  kill -TERM "$1" 2>/dev/null
  i=0; while [ $i -lt 50 ] && alive_ssh "$1" "$2"; do sleep 0.1; i=$((i+1)); done
  if alive_ssh "$1" "$2"; then echo "still_running"; else echo "terminated"; fi
}

# ------------------------------------------------------------------ cleanup (EXIT trap)
cleanup() {
  local rc=$? i out
  trap - EXIT
  set +e
  i=0; while [ $i -lt ${#MS_PID[@]} ]; do
    if alive_ssh "${MS_PID[$i]}" "${MS_IDENT[$i]}" && [ -S "${MS_SOCK[$i]}" ]; then
      "$SSH" -F "${MS_CFG[$i]}" -S "${MS_SOCK[$i]}" -O exit "${MS_HOST[$i]}" </dev/null >/dev/null 2>&1
      sleep 0.3
    fi
    if alive_ssh "${MS_PID[$i]}" "${MS_IDENT[$i]}"; then out=$(kill_ssh "${MS_PID[$i]}" "${MS_IDENT[$i]}"); else out="not_running"; fi
    printf 'CLEANUP\tmaster pid=%s\t%s\n' "${MS_PID[$i]}" "$out" >>"$RES"
    i=$((i+1))
  done
  i=0; while [ $i -lt ${#AG_PID[@]} ]; do
    out=$(kill_exact "${AG_PID[$i]}" "${AG_IDENT[$i]}")
    if [ -S "${AG_SOCK[$i]}" ]; then out="$out socket_still_present"; else out="$out socket_removed"; fi
    printf 'CLEANUP\tagent pid=%s\t%s\n' "${AG_PID[$i]}" "$out" >>"$RES"
    log "cleanup agent pid=${AG_PID[$i]}: $out"
    i=$((i+1))
  done
  # copy agent debug logs (fingerprints and request types only) before removing the temp dir
  for f in "$T"/*/agent-debug.log; do
    [ -f "$f" ] || continue
    red <"$f" >"$OUT_DIR/$EXP.$(basename "$(dirname "$f")").agent-debug.log"
  done
  rm -rf "$T"
  if [ -e "$T" ]; then printf 'CLEANUP\ttempdir\tstill_present\n' >>"$RES"; else printf 'CLEANUP\ttempdir\tremoved\n' >>"$RES"; fi
  [ "$rc" = 0 ] && [ "$FAILS" -gt 0 ] && rc=1
  printf 'EXIT\t%s\tchecks=%s\tfails=%s\n' "$rc" "$CHECKS" "$FAILS" >>"$RES"
  log "END $EXP exit=$rc checks=$CHECKS fails=$FAILS"
  exit "$rc"
}
trap cleanup EXIT
trap 'log "interrupted"; exit 3' INT TERM HUP

finish() { [ "$FAILS" -eq 0 ] && exit 0; exit 1; }

log "BEGIN $EXP run_stamp=$RUN_STAMP run_id=$RUN_ID"
# number of successful signatures in an ssh-agent -d log (lines end in CRLF, so no $ anchor)
signs() { grep -c -F 'process_sign_request2: good signature' "$1"; }

# ------------------------------------------------------------------ enrollable-registry transactions
# Account-enrollable fixture: account enroll owns ~/.ssh/authorized_keys. The "admin path" is the
# fixture's known-working key file (runtime/keys/user_enroll), used directly, never loaded in an agent.
reg_admin_cfg() { write_cfg "$T/admin.cfg" none "$FX_KEYS/user_enroll"; }
reg_fetch() {  # OUTFILE LABEL -> RC ; raw remote bytes into OUTFILE
  local f=$1 label=$2
  "$SSH" -F "$T/admin.cfg" g-enroll 'cat ~/.ssh/authorized_keys' </dev/null >"$f" 2>"$T/.fetch.err"; RC=$?
  log "registry fetch ($label): rc=$RC bytes=$(wc -c <"$f" | tr -d ' ') lines=$(wc -l <"$f" | tr -d ' ') sha256=$(shasum -a 256 "$f" | awk '{print $1}') err=[$(red <"$T/.fetch.err" | oneline)]"
}
sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }
# reg_add PRE_SHA LINEFILE LABEL : compare-and-swap on the preimage digest; copy + append in a temp
# file next to the registry; chmod 600; atomic rename. Aborts (rc 70) if the registry changed.
reg_add() {
  local pre=$1 linef=$2 label=$3 s="$T/.reg_add.sh"
  { cat <<'EOS'
set -eu
f="$HOME/.ssh/authorized_keys"
pre=$(sha256sum "$f" | cut -d' ' -f1)
[ "$pre" = "$1" ] || { echo "PREIMAGE_MISMATCH current=$pre"; exit 70; }
[ -z "$(tail -c 1 "$f")" ] || { echo "NO_TRAILING_NEWLINE"; exit 71; }
t=$(mktemp "$f.hm-g04.XXXXXX")
trap 'rm -f "$t"' EXIT
cat "$f" >"$t"
cat >>"$t" <<'HM_G04_LINE_EOF'
EOS
    cat "$linef"
    cat <<'EOS'
HM_G04_LINE_EOF
chmod 600 "$t"
mv -f "$t" "$f"
echo "POST sha256=$(sha256sum "$f" | cut -d' ' -f1) owner_mode=$(stat -c '%U:%a' "$f")"
EOS
  } >"$s"
  xrun_in "$s" "$label" "$SSH" -F "$T/admin.cfg" g-enroll "bash -s -- $(printf %q "$pre")"
}
# reg_remove MARKER LABEL : remove exactly the one line containing MARKER from the CURRENT file
# (not from a stale snapshot), temp file + atomic rename. Aborts (rc 72) unless exactly one line matches.
reg_remove() {
  local mk=$1 label=$2 s="$T/.reg_rm.sh"
  cat >"$s" <<'EOS'
set -eu
f="$HOME/.ssh/authorized_keys"
n=$(grep -c -F -- "$1" "$f" || true)
[ "$n" = 1 ] || { echo "MARKER_COUNT $n"; exit 72; }
t=$(mktemp "$f.hm-g04.XXXXXX")
trap 'rm -f "$t"' EXIT
grep -v -F -- "$1" "$f" >"$t" || true
chmod 600 "$t"
mv -f "$t" "$f"
echo "POST sha256=$(sha256sum "$f" | cut -d' ' -f1) owner_mode=$(stat -c '%U:%a' "$f")"
EOS
  xrun_in "$s" "$label" "$SSH" -F "$T/admin.cfg" g-enroll "bash -s -- $(printf %q "$mk")"
}
reg_owner_mode() { "$SSH" -F "$T/admin.cfg" g-enroll 'stat -c "%U:%a" ~/.ssh/authorized_keys; ls -A ~/.ssh | grep -c "hm-g04" || true' </dev/null 2>/dev/null | oneline; }
