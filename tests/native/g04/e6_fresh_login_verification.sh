#!/bin/bash
# E6 (G04, A09, R-CR-05, spec 7.5): independent fresh-login verification vs connection reuse.
# Design: docs/research/g04-managed-credentials.md section 8.1 row E6.
# With a live ControlMaster to ca1 open, the verification command (ControlMaster=no,
# ControlPath=none, explicit identity/cert/agent, publickey only, BatchMode) must produce exactly
# one NEW "Accepted publickey ... ID <id>" line. The negative control (ControlMaster=auto through
# the existing control socket) succeeds with NO new accepted line: reuse is not verification.
EXP=e6-fresh-login-verification
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

load_fixture; record_env
start_agent "$T/agent"; A=$AGENT_SOCK
genkey "$T/k" "g04-e6-k-$RUN_ID"
ID="g04-e6-$RUN_ID"; NOW=$(date -u +%s)
sign_file "$FX_CA" "$T/k.pub" "$ID" p-host1 "$(vhex $((NOW-60))):$(vhex $((NOW+900)))" "$T/k-cert.pub"
agent_add "$A" "$T/k" -t 900
write_cfg "$T/cfg" "$A" "$T/k.pub" "CertificateFile \"$T/k-cert.pub\""
CM="$T/cm"

m=$(mark ca1)
start_master "$T/cfg" "$CM" 120 g-ca1; mrc=$RC; MPID=$MASTER_PID
sleep 0.3; macc=$(count_new ca1 "$m" "Accepted publickey" "ID $ID ")
[ "$mrc" = 0 ] && [ -n "$MPID" ] && [ "$macc" = 1 ]; ok=$?
check E6-master-open "ControlMaster=yes master authenticated once (1 Accepted line)" "rc=$mrc master_pid=${MPID:-none} accepted=$macc" $ok
[ -n "$MPID" ] || die_setup "master did not start"

m=$(mark ca1)
xrun "verification command (fresh)" "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes \
  -o IdentityAgent="$A" -o IdentityFile="$T/k.pub" -o CertificateFile="$T/k-cert.pub" \
  -o PreferredAuthentications=publickey -o BatchMode=yes g-ca1 true
vrc=$RC; sleep 0.3
vacc=$(count_new ca1 "$m" "Accepted publickey" "ID $ID "); vall=$(count_new ca1 "$m" "Accepted publickey"); vconn=$(count_new ca1 "$m" "Connection from")
log_new ca1 "$m" verification
[ "$vrc" = 0 ] && [ "$vacc" = 1 ] && [ "$vall" = 1 ]; ok=$?
check E6-verification-is-fresh "rc 0 and exactly 1 new Accepted line carrying ID $ID (a new authentication) while a master is open" "rc=$vrc new_accepted_with_id=$vacc new_accepted_any=$vall new_connections=$vconn" $ok

m=$(mark ca1)
xrun "negative control: reuse via ControlMaster=auto" "$SSH" -F "$T/cfg" -o ControlMaster=auto -o ControlPath="$CM" g-ca1 true
nrc=$RC; sleep 0.3
nacc=$(count_new ca1 "$m" "Accepted publickey"); nconn=$(count_new ca1 "$m" "Connection from")
log_new ca1 "$m" "negative control"
[ "$nrc" = 0 ] && [ "$nacc" = 0 ] && [ "$nconn" = 0 ]; ok=$?
check E6-reuse-is-not-verification "rc 0 with NO new Accepted line and no new TCP connection (session rode the existing master)" "rc=$nrc new_accepted=$nacc new_connections=$nconn" $ok

xrun "-O exit master" "$SSH" -F "$T/cfg" -S "$CM" -O exit g-ca1
erc=$RC; sleep 0.5
gone=no; alive_ssh "$MPID" "$(master_ident_of "$MPID")" || gone=yes
[ "$erc" = 0 ] && [ "$gone" = yes ] && [ ! -e "$CM" ]; ok=$?
check E6-master-closed "-O exit rc 0; master process gone; control socket removed" "rc=$erc master_gone=$gone socket_exists=$([ -e "$CM" ] && echo yes || echo no)" $ok
finish
