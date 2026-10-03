#!/bin/bash
# E7 (preliminary G09, A23, R-AU-05): OpenSSH multiplexing after certificate expiry; -O stop; -O exit.
# Design: docs/research/g04-managed-credentials.md section 8.1 row E7.
#  Certificate valid [now-60, now+VALID]. Master: ControlMaster=yes, ControlPersist=PERSIST, -N -f.
#  S1: long session through the master printing a remote heartbeat every 5 s (no tty).
#  Phase 1 (before expiry): new mux session.
#  Phase 2 (valid_before + 10 s): (a) fresh login; (b) new mux session through the master
#           (b2: same with PubkeyAuthentication=no so no fallback authentication is possible);
#           (c) S1 heartbeat.
#  Phase 3: ssh -O stop; (a) -O check; (b) new client using the old ControlPath (b2: with
#           PubkeyAuthentication=no); (c) S1 heartbeat >= 30 s after stop; (d) does the master
#           exit when S1 (its last session) ends?
#  Phase 4 (strict variant): second master + session S2; ssh -O exit; master, S2, socket and the
#           remote session processes are checked.
# Hypotheses (recorded as CONFIRMED/REFUTED rows, never assumed):
#  H1  certificate expiry alone does not stop new multiplexed sessions on an existing master
#  H2a after -O stop the control socket is gone (-O check fails)
#  H2b after -O stop a NEW client (one that connects to the control path after the stop) makes a
#      fresh connection (new server authentication attempt, rejected because the cert expired),
#      rc 255; no admission via the master.
#  NOTE (M00-review-g04): H2a-H2c only exercise control connections opened AFTER the stop. Control
#  connections the master accepted BEFORE the stop are E7 phase 5 (e7_mux_preconnected.py), where
#  -O stop did not stop admissions (new sessions, forwards). H2 therefore does not show that
#  -O stop is an admission-stopping control.
#  H2c after -O stop the already-open session S1 keeps working
#  H2d the master exits once its last session ends after -O stop (ControlPersist does not keep it),
#      when no other control connection is open (with an idle control connection accepted before the
#      stop, the stopped master stays up: e7_mux_preconnected.py H2d-held)
#  H3  -O exit closes the master and its sessions
#  H3b the remote shell of a no-tty session closed by -O exit is not terminated by sshd (process
#      names/PIDs of the account are listed inside the container before, 7 s and 20 s after)
EXP=e7-mux-after-expiry
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
VALID=${G04_E7_VALID:-90}
PERSIST=${G04_E7_PERSIST:-10m}

cert_procs() {  # name(pid) of processes owned by account cert inside ca1 (names only, no arguments)
  docker exec -i "$(cname ca1)" sh -s <<'EOS' 2>/dev/null
u=$(id -u cert)
for s in /proc/[0-9]*/status; do awk -v u="$u" -v p="${s#/proc/}" '/^Name:/{n=$2} /^Uid:/{if($2==u){sub(/\/status/,"",p); print n "(" p ")"}}' "$s" 2>/dev/null; done | sort | tr '\n' ' '
EOS
}
hb_since() { awk -v t="$2" '/^[0-9]+$/ && $1+0 >= t {n++} END{print n+0}' "$1"; }

load_fixture; record_env
start_agent "$T/agent"; A=$AGENT_SOCK
genkey "$T/k7" "g04-e7-k-$RUN_ID"
NOW=$(date -u +%s); VB=$((NOW+VALID))
ID="g04-e7-$RUN_ID"; ID4="g04-e7-p4-$RUN_ID"
sign_file "$FX_CA" "$T/k7.pub" "$ID" p-host1 "$(vhex $((NOW-60))):$(vhex $VB)" "$T/c7.pub"
sign_file "$FX_CA" "$T/k7.pub" "$ID4" p-host1 "$(vhex $((NOW-60))):$(vhex $((NOW+1800)))" "$T/c7b.pub"
fact cert_valid_before_epoch "$VB"; fact control_persist "$PERSIST"
agent_add "$A" "$T/k7" -t 1800
write_cfg "$T/cfg" "$A" "$T/k7.pub" "CertificateFile \"$T/c7.pub\""
write_cfg "$T/cfg4" "$A" "$T/k7.pub" "CertificateFile \"$T/c7b.pub\""
CM="$T/cm"

# ---- master + S1
m=$(mark ca1)
start_master "$T/cfg" "$CM" "$PERSIST" g-ca1; MPID=$MASTER_PID; MIDENT=$(master_ident_of "$MPID")
sleep 0.3; macc=$(count_new ca1 "$m" "Accepted publickey" "ID $ID ")
[ -n "$MPID" ] && [ "$macc" = 1 ]; ok=$?
check E7-master-authenticated "master started; exactly 1 Accepted line with the short-lived cert ID" "master_pid=${MPID:-none} accepted=$macc" $ok
[ -n "$MPID" ] || die_setup "master did not start"
S1_END=$((VB + 60))
"$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$CM" g-ca1 \
  "while [ \$(date +%s) -lt $S1_END ]; do date -u +%s; sleep 5; done; echo S1-END" </dev/null >"$T/s1.out" 2>"$T/s1.err" &
S1PID=$!; S1IDENT=$(ssh_lstart "$S1PID")
log "S1 started through the master: pid=$S1PID ident='$S1IDENT' remote loop until epoch $S1_END"
sleep 2

# ---- phase 1
m=$(mark ca1)
xrun "P1 new mux session before expiry" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$CM" g-ca1 'echo p1-mux-ok'
p1rc=$RC; p1out=$OUT; sleep 0.3; p1acc=$(count_new ca1 "$m" "Accepted publickey"); p1con=$(count_new ca1 "$m" "Connection from")
[ "$p1rc" = 0 ] && [ "$p1out" = p1-mux-ok ] && [ "$p1acc" = 0 ] && [ "$p1con" = 0 ]; ok=$?
check E7-P1-mux-before-expiry "rc 0 via the master: no new TCP connection, no new Accepted line" "rc=$p1rc out=$p1out new_connections=$p1con new_accepted=$p1acc" $ok

# ---- phase 2
wait_until $((VB + 10))
fact clock_ca1_phase2 "$(clock_offset ca1)"
m=$(mark ca1)
xrun "P2a fresh login after expiry" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath=none g-ca1 true
p2arc=$RC; sleep 0.3; p2aexp=$(count_new ca1 "$m" "Certificate invalid: expired"); p2afail=$(count_new ca1 "$m" "Failed publickey" "ID $ID ")
log_new ca1 "$m" P2a
[ "$p2arc" = 255 ] && [ "$p2aexp" -ge 1 ] && [ "$p2afail" -ge 1 ]; ok=$?
check E7-P2a-fresh-login-rejected "rc 255; server logs 'Certificate invalid: expired' for the cert ID" "rc=$p2arc expired_lines=$p2aexp failed_with_id=$p2afail" $ok

m=$(mark ca1)
xrun "P2b new mux session after expiry" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$CM" g-ca1 'echo p2-mux-after-expiry'
p2brc=$RC; p2bout=$OUT; sleep 0.3; p2bacc=$(count_new ca1 "$m" "Accepted publickey"); p2bcon=$(count_new ca1 "$m" "Connection from")
log_new ca1 "$m" P2b
[ "$p2brc" = 0 ] && [ "$p2bout" = p2-mux-after-expiry ] && [ "$p2bacc" = 0 ] && [ "$p2bcon" = 0 ]; ok=$?
obs H1-mux-admitted-after-expiry "new multiplexed session admitted after valid_before, with no new connection or authentication" "rc=$p2brc out=$p2bout new_connections=$p2bcon new_accepted=$p2bacc" $ok
xrun "P2b2 new mux session after expiry, client has no usable authentication" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$CM" -o PubkeyAuthentication=no g-ca1 'echo p2b2-mux'
p2b2rc=$RC; p2b2out=$OUT
[ "$p2b2rc" = 0 ] && [ "$p2b2out" = p2b2-mux ]; ok=$?
obs H1b-mux-needs-no-client-credential "a client with PubkeyAuthentication=no (cannot authenticate at all) is admitted through the master after expiry" "rc=$p2b2rc out=$p2b2out" $ok

hb2=$(hb_since "$T/s1.out" "$VB"); s1alive=no; alive_ssh "$S1PID" "$S1IDENT" && s1alive=yes
[ "$hb2" -ge 1 ] && [ "$s1alive" = yes ]; ok=$?
check E7-P2c-S1-alive-after-expiry "S1 still running and printing heartbeats after valid_before" "heartbeats_since_valid_before=$hb2 s1_running=$s1alive" $ok

# ---- phase 3: -O stop
xrun "P3 ssh -O stop" "$SSH" -F "$T/cfg" -S "$CM" -O stop g-ca1
stoprc=$RC; stopout=$OUT; STOP_T1=$XT1
sleep 0.5
malive=no; alive_ssh "$MPID" "$MIDENT" && malive=yes
mtitle=$(ssh_comm "$MPID" | red | oneline)
sock=present; [ -e "$CM" ] || sock=removed
fact P3_stop "rc=$stoprc out=[$stopout] master_running_after_stop=$malive master_ps_comm_after_stop=[$mtitle] control_socket=$sock"
xrun "P3a -O check after stop" "$SSH" -F "$T/cfg" -S "$CM" -O check g-ca1
p3arc=$RC; p3aout=$OUT
[ "$p3arc" != 0 ] && [ "$sock" = removed ]; ok=$?
obs H2a-check-fails-after-stop "-O check fails after -O stop; control socket removed" "stop_rc=$stoprc check_rc=$p3arc check_out=[$p3aout] socket=$sock" $ok

m=$(mark ca1)
xrun "P3b new client with the old ControlPath after stop" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$CM" g-ca1 'echo p3b'
p3brc=$RC; p3bout=$OUT; sleep 0.3
p3bcon=$(count_new ca1 "$m" "Connection from"); p3bexp=$(count_new ca1 "$m" "Certificate invalid: expired"); p3bacc=$(count_new ca1 "$m" "Accepted publickey")
log_new ca1 "$m" P3b
[ "$p3brc" = 255 ] && [ "$p3bcon" -ge 1 ] && [ "$p3bexp" -ge 1 ] && [ "$p3bacc" = 0 ]; ok=$?
obs H2b-new-client-falls-back-to-fresh-auth "after stop, a client with the old ControlPath opens a NEW connection, is rejected (expired), rc 255" "rc=$p3brc out=[$p3bout] new_connections=$p3bcon expired_lines=$p3bexp new_accepted=$p3bacc" $ok
xrun "P3b2 same, client has no usable authentication" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$CM" -o PubkeyAuthentication=no g-ca1 'echo p3b2'
p3b2rc=$RC
[ "$p3b2rc" = 255 ]; ok=$?
obs H2b2-no-admission-via-master-after-stop "a NEW client (connecting after stop) with PubkeyAuthentication=no is NOT admitted (rc 255); pre-accepted control connections are not covered here" "rc=$p3b2rc out=[$OUT]" $ok

# (c) wait for S1 to finish on its own (remote loop ends at S1_END)
while alive_ssh "$S1PID" "$S1IDENT" && [ "$(date -u +%s)" -lt $((S1_END + 30)) ]; do sleep 1; done
if alive_ssh "$S1PID" "$S1IDENT"; then log "S1 still running at S1_END+30; terminating exact pid"; kill_ssh "$S1PID" "$S1IDENT" >/dev/null; fi
wait "$S1PID" 2>/dev/null; s1rc=$?; S1_EXIT_T=$(hr)
cp "$T/s1.out" "$OUT_DIR/$EXP.s1-heartbeat.txt"
{ echo "    S1 stdout (remote heartbeat epochs):"; sed 's/^/    | /' "$T/s1.out"; echo "    S1 stderr:"; red <"$T/s1.err" | sed 's/^/    | /'; echo "    S1 rc=$s1rc"; } >>"$LOG"
STOPI=$(printf '%.0f' "$STOP_T1")
hb3=$(hb_since "$T/s1.out" "$STOPI"); last=$(grep -E '^[0-9]+$' "$T/s1.out" | tail -1)
span=$(( ${last:-0} - STOPI )); s1end=$(grep -c '^S1-END$' "$T/s1.out")
[ "$s1rc" = 0 ] && [ "$s1end" = 1 ] && [ "$hb3" -ge 6 ] && [ "$span" -ge 30 ]; ok=$?
obs H2c-open-session-continues-after-stop "S1 keeps running >= 30 s after -O stop and ends normally" "s1_rc=$s1rc heartbeats_after_stop=$hb3 last_heartbeat_minus_stop_s=$span s1_end_marker=$s1end" $ok

# (d) does the master exit after its last session ended?
i=0; while [ $i -lt 40 ] && alive_ssh "$MPID" "$MIDENT"; do sleep 0.5; i=$((i+1)); done
if alive_ssh "$MPID" "$MIDENT"; then
  mexit="still_running_20s_after_last_session"; kres=$(kill_ssh "$MPID" "$MIDENT")
  fact P3d_master "still running 20 s after S1 ended; harness kill_ssh: $kres"
else
  mexit="exited_within_$(( (i+1) / 2 ))s"; fact P3d_master "exited about $(( (i+1) / 2 )) s (poll granularity 0.5 s) after S1 ended"
fi
[ "${mexit#exited}" != "$mexit" ]; ok=$?
obs H2d-master-exits-after-last-session "after -O stop the master exits when its last session ends, despite ControlPersist=$PERSIST (condition: no other control connection open in this run)" "$mexit" $ok

# ---- phase 4: strict variant, -O exit
CM2="$T/cm2"
m=$(mark ca1)
start_master "$T/cfg4" "$CM2" "$PERSIST" g-ca1; M2PID=$MASTER_PID; M2IDENT=$(master_ident_of "$M2PID")
[ -n "$M2PID" ] || die_setup "phase 4 master did not start"
"$SSH" -F "$T/cfg4" -o ControlMaster=no -o ControlPath="$CM2" g-ca1 \
  'i=0; while [ $i -lt 40 ]; do date -u +%s; sleep 3; i=$((i+1)); done; echo S2-END' </dev/null >"$T/s2.out" 2>"$T/s2.err" &
S2PID=$!; S2IDENT=$(ssh_lstart "$S2PID")
sleep 7
before=$(cert_procs); hbb=$(grep -c -E '^[0-9]+$' "$T/s2.out")
fact P4_before_exit "remote cert-owned processes: $before; S2 heartbeats so far: $hbb"
xrun "P4 ssh -O exit" "$SSH" -F "$T/cfg4" -S "$CM2" -O exit g-ca1
exrc=$RC; EXIT_T1=$XT1
sleep 3
m2alive=no; alive_ssh "$M2PID" "$M2IDENT" && m2alive=yes
s2alive=no; alive_ssh "$S2PID" "$S2IDENT" && s2alive=yes
if [ "$s2alive" = yes ]; then sleep 5; alive_ssh "$S2PID" "$S2IDENT" && kill_ssh "$S2PID" "$S2IDENT" >/dev/null; fi
wait "$S2PID" 2>/dev/null; s2rc=$?
sleep 4
after=$(cert_procs)
EXI=$(printf '%.0f' "$EXIT_T1"); hba=$(awk -v t="$EXI" '/^[0-9]+$/ && $1+0 > t+1 {n++} END{print n+0}' "$T/s2.out")
sock2=present; [ -e "$CM2" ] || sock2=removed
{ echo "    S2 stdout:"; sed 's/^/    | /' "$T/s2.out"; echo "    S2 stderr:"; red <"$T/s2.err" | sed 's/^/    | /'; echo "    S2 rc=$s2rc"; } >>"$LOG"
xrun "P4 new client after -O exit (no usable auth)" "$SSH" -F "$T/cfg4" -o ControlMaster=no -o ControlPath="$CM2" -o PubkeyAuthentication=no g-ca1 true
p4nrc=$RC
s2endmark=$(grep -c '^S2-END$' "$T/s2.out")
[ "$exrc" = 0 ] && [ "$m2alive" = no ] && [ "$s2alive" = no ] && [ "$sock2" = removed ] && [ "$hba" = 0 ] && [ "$s2endmark" = 0 ] && [ "$p4nrc" = 255 ]; ok=$?
obs H3-exit-closes-master-and-sessions "-O exit: master gone, open session S2 terminated (no heartbeats after exit, no normal end), socket removed, later client not admitted" \
  "exit_rc=$exrc master_running_3s_after=$m2alive s2_running_3s_after=$s2alive s2_rc=$s2rc s2_heartbeats_after_exit=$hba s2_normal_end=$s2endmark socket=$sock2 new_client_rc=$p4nrc" $ok
sleep 13; after20=$(cert_procs)
fact P4_remote_processes "account cert processes in ca1, before -O exit: [$before] ; 7 s after: [$after] ; 20 s after: [$after20]"
bpid=$(printf '%s\n' "$before" | tr ' ' '\n' | grep '^bash(' | head -1)
[ -n "$bpid" ] && printf '%s\n' "$after20" | tr ' ' '\n' | grep -qxF "$bpid"; ok=$?
obs H3b-remote-command-outlives-exit "the remote shell of no-tty session S2 is NOT terminated when -O exit closes the connection (it keeps running; only writers hit a closed pipe)" "S2 remote shell before exit=[${bpid:-none}] ; still present 20 s after exit=$([ "$ok" = 0 ] && echo yes || echo no) ; lists: before=[$before] 7s=[$after] 20s=[$after20]" $ok
finish
