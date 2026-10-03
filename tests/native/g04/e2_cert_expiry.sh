#!/bin/bash
# E2 (G04, preliminary A23): certificate validity window enforced by sshd for NEW authentication.
# Design: docs/research/g04-managed-credentials.md section 8.1 row E2.
#  C1a/C1b: valid [now-60, now+LEAD]; C1a loaded with default ssh-add (agent asked to drop the
#  certificate at valid_before + 300 s), C1b loaded with ssh-add -N (no automatic deletion).
#  C2: not yet valid [now+300, now+600]. C3: expired [now-600, now-300].
#  Before expiry: C1a/C1b log in (agent-held cert and on-disk cert variants); C2, C3 rejected.
#  Around valid_before: back-to-back fresh logins with C1a measure where acceptance stops.
#  At valid_before + 5 s: C1a/C1b rejected although both agents still hold the certificates.
#  Optional grace check (G04_E2_GRACE_CHECK=1): at valid_before + 300 + 15 s the default-added
#  certificate is gone from agent A while the -N certificate remains in agent B; then the same
#  expired certificate offered from disk (agent A now holds only the plain key) is rejected the
#  same way, which is the "without the agent still holding the certificate" half of the criterion.
# All logins: fresh connections (ControlMaster no, ControlPath none), BatchMode, publickey only.
EXP=e2-cert-expiry
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
LEAD=${G04_E2_LEAD:-90}
GRACE_CHECK=${G04_E2_GRACE_CHECK:-1}

load_fixture; record_env
OFFS=$(clock_offset ca1); fact clock_ca1_before "$OFFS"
start_agent "$T/aA" debug; AA=$AGENT_SOCK
start_agent "$T/aB" debug; AB=$AGENT_SOCK
start_agent "$T/aC"; AC=$AGENT_SOCK
for k in k1a k1b k2 k3; do genkey "$T/$k" "g04-e2-$k-$RUN_ID"; done
NOW=$(date -u +%s); VA=$((NOW-60)); VB=$((NOW+LEAD))
ID1A="g04-e2-c1a-$RUN_ID"; ID1B="g04-e2-c1b-$RUN_ID"; ID2="g04-e2-c2-$RUN_ID"; ID3="g04-e2-c3-$RUN_ID"
sign_file "$FX_CA" "$T/k1a.pub" "$ID1A" p-host1 "$(vhex $VA):$(vhex $VB)" "$T/k1a-cert.pub"
sign_file "$FX_CA" "$T/k1b.pub" "$ID1B" p-host1 "$(vhex $VA):$(vhex $VB)" "$T/k1b-cert.pub"
sign_file "$FX_CA" "$T/k2.pub" "$ID2" p-host1 "$(vhex $((NOW+300))):$(vhex $((NOW+600)))" "$T/c2.pub"
sign_file "$FX_CA" "$T/k3.pub" "$ID3" p-host1 "$(vhex $((NOW-600))):$(vhex $((NOW-300)))" "$T/c3.pub"
fact c1_valid_after_epoch "$VA"; fact c1_valid_before_epoch "$VB"
fact c1_valid_before_utc "$(date -u -r "$VB" +%Y-%m-%dT%H:%M:%SZ)"

agent_add "$AA" "$T/k1a"; fact ssh_add_default_output "$OUT"
agent_add "$AB" "$T/k1b" -N; fact ssh_add_N_output "$OUT"
agent_add "$AC" "$T/k2"; agent_add "$AC" "$T/k3"
agent_list "$AA"; fact agentA_before "$OUT"
agent_list "$AB"; fact agentB_before "$OUT"

# agent-held variant: the certificate is offered from the agent (IdentitiesOnly no + IdentityFile
# none; each agent holds only that key and its certificate). disk variant: CertificateFile on disk.
write_cfg "$T/agA.cfg" "$AA" none "IdentitiesOnly no"
write_cfg "$T/agB.cfg" "$AB" none "IdentitiesOnly no"
write_cfg "$T/dkA.cfg" "$AA" "$T/k1a.pub" "CertificateFile \"$T/k1a-cert.pub\""
write_cfg "$T/dkB.cfg" "$AB" "$T/k1b.pub" "CertificateFile \"$T/k1b-cert.pub\""
write_cfg "$T/c2.cfg" "$AC" "$T/k2.pub" "CertificateFile \"$T/c2.pub\""
write_cfg "$T/c3.cfg" "$AC" "$T/k3.pub" "CertificateFile \"$T/c3.pub\""

# attempt LABEL CFG ID -> sets A_RC A_ACC A_FAILID A_REASON (fresh login to ca1)
attempt() {
  local label=$1 cfg=$2 id=$3 m; m=$(mark ca1)
  xrun "$label" "$SSH" -F "$cfg" -v g-ca1 'echo e2-ok'
  A_RC=$RC; A_OFFER=$(printf '%s\n' "$OUT" | grep 'Offering public key' | sed 's/SHA256:[^ ]*/<fp>/' | oneline)
  sleep 0.3
  A_ACC=$(count_new ca1 "$m" "Accepted publickey" "ID $id ")
  A_FAILID=$(count_new ca1 "$m" "Failed publickey" "ID $id ")
  A_REASON=$(new_lines ca1 "$m" | grep -o 'Certificate invalid: [a-z ]*' | sort -u | oneline)
  log_new ca1 "$m" "$label"
}

# ---- before expiry
attempt "C1a agent-held, before expiry" "$T/agA.cfg" "$ID1A"
[ "$A_RC" = 0 ] && [ "$A_ACC" = 1 ]; ok=$?; check E2-C1a-agent-before "rc 0 + 1 Accepted line ID c1a" "rc=$A_RC accepted=$A_ACC offered=[$A_OFFER]" $ok
attempt "C1b agent-held, before expiry" "$T/agB.cfg" "$ID1B"
[ "$A_RC" = 0 ] && [ "$A_ACC" = 1 ]; ok=$?; check E2-C1b-agent-before "rc 0 + 1 Accepted line ID c1b" "rc=$A_RC accepted=$A_ACC offered=[$A_OFFER]" $ok
attempt "C1a disk cert, before expiry" "$T/dkA.cfg" "$ID1A"
[ "$A_RC" = 0 ] && [ "$A_ACC" = 1 ]; ok=$?; check E2-C1a-disk-before "rc 0 + 1 Accepted line ID c1a" "rc=$A_RC accepted=$A_ACC" $ok
attempt "C2 not yet valid" "$T/c2.cfg" "$ID2"
[ "$A_RC" = 255 ] && [ "$A_ACC" = 0 ] && [ "$A_FAILID" -ge 1 ] && [ "$A_REASON" = "Certificate invalid: not yet valid" ]
ok=$?; check E2-C2-not-yet-valid-rejected "rc 255; server saw the cert (Failed line with ID) and logged 'Certificate invalid: not yet valid'" "rc=$A_RC accepted=$A_ACC failed_with_id=$A_FAILID reason=[$A_REASON]" $ok
attempt "C3 expired" "$T/c3.cfg" "$ID3"
[ "$A_RC" = 255 ] && [ "$A_ACC" = 0 ] && [ "$A_FAILID" -ge 1 ] && [ "$A_REASON" = "Certificate invalid: expired" ]
ok=$?; check E2-C3-expired-rejected "rc 255; server saw the cert and logged 'Certificate invalid: expired'" "rc=$A_RC accepted=$A_ACC failed_with_id=$A_FAILID reason=[$A_REASON]" $ok

# ---- boundary sampling around valid_before (C1a, agent-held), back-to-back fresh logins
wait_until $((VB - 6))
OFFS=$(clock_offset ca1); fact clock_ca1_at_boundary "$OFFS"
m=$(mark ca1)
: >"$T/boundary.tsv"
END=$((VB + 4))
while [ "$(date -u +%s)" -lt "$END" ]; do
  t0=$(hr); "$SSH" -F "$T/agA.cfg" g-ca1 true </dev/null >/dev/null 2>&1; r=$?; t1=$(hr)
  printf '%s\t%s\t%s\n' "$t0" "$t1" "$r" >>"$T/boundary.tsv"
done
sleep 0.3; log_new ca1 "$m" "boundary sampling"
bacc=$(count_new ca1 "$m" "Accepted publickey" "ID $ID1A "); bexp=$(count_new ca1 "$m" "Certificate invalid: expired")
{ echo "    boundary attempts (t_start t_end rc), valid_before=$VB:"; sed 's/^/    /' "$T/boundary.tsv"; } >>"$LOG"
cp "$T/boundary.tsv" "$OUT_DIR/$EXP.boundary.tsv"
OFFV=$(printf '%s\n' "$OFFS" | sed -n 's/offset_s=\([-0-9.]*\).*/\1/p')
BRES=$(BF="$T/boundary.tsv" "$PERL" -e '
  my ($vb,$off)=@ARGV; $off=abs($off); my $tol=$off+0.05;
  my ($n,$ok,$bad,$ls,$ff,$late_ok,$early_fail)=(0,0,0,undef,undef,0,0);
  open my $f,"<",$ENV{BF} or die; while(<$f>){chomp; my($a,$b,$r)=split /\t/; $n++;
    if($r==0){$ok++; $ls=$b if !defined $ls || $b>$ls; $late_ok++ if $a>=$vb+$tol;}
    else{$bad++; $ff=$a if !defined $ff || $a<$ff; $early_fail++ if $b<$vb-$tol;}}
  printf "attempts=%d accepted=%d rejected=%d last_accept_end_minus_vb=%s first_reject_start_minus_vb=%s accepted_starting_after_vb=%d rejected_ending_before_vb=%d tolerance_s=%.3f",
    $n,$ok,$bad,defined $ls?sprintf("%.3f",$ls-$vb):"none",defined $ff?sprintf("%.3f",$ff-$vb):"none",$late_ok,$early_fail,$tol;' -- "$VB" "${OFFV:-0}")
fact boundary "$BRES server_accepted_lines=$bacc server_expired_lines=$bexp"
late=$(printf '%s' "$BRES" | sed -n 's/.*accepted_starting_after_vb=\([0-9]*\).*/\1/p')
early=$(printf '%s' "$BRES" | sed -n 's/.*rejected_ending_before_vb=\([0-9]*\).*/\1/p')
ffs=$(printf '%s' "$BRES" | sed -n 's/.*first_reject_start_minus_vb=\([-0-9.]*\).*/\1/p')
nok=$(printf '%s' "$BRES" | sed -n 's/.* accepted=\([0-9]*\).*/\1/p'); nbad=$(printf '%s' "$BRES" | sed -n 's/.*rejected=\([0-9]*\).*/\1/p')
lim=$("$PERL" -e 'print abs($ARGV[0])+2' -- "${OFFV:-0}")
[ "${late:-x}" = 0 ] && [ "${early:-x}" = 0 ] && [ "${nok:-0}" -ge 1 ] && [ "${nbad:-0}" -ge 1 ] && [ "$bexp" = "$nbad" ] \
  && "$PERL" -e 'exit(($ARGV[0] ne "" && $ARGV[0] <= $ARGV[1]) ? 0 : 1)' -- "${ffs:-}" "$lim"
ok=$?; check E2-boundary "accepts only while t<valid_before, rejects from valid_before (each rejection logged as expired); first rejection <= 2 s + |offset| after valid_before" "$BRES server_expired_lines=$bexp limit_s=$lim" $ok

# ---- after expiry while the agents still hold the certificates
wait_until $((VB + 5))
agent_list "$AA"; aA=$OUT; aAc=$(printf '%s\n' "$OUT" | grep -c 'ED25519-CERT')
agent_list "$AB"; aB=$OUT; aBc=$(printf '%s\n' "$OUT" | grep -c 'ED25519-CERT')
fact agentA_after_expiry "$aA"; fact agentB_after_expiry "$aB"
[ "$aAc" = 1 ] && [ "$aBc" = 1 ]
ok=$?; check E2-agents-still-hold-certs "both agents still list the expired certificate at valid_before+5 s" "agentA_cert_entries=$aAc agentB_cert_entries=$aBc" $ok
for v in "agA:$ID1A:C1a agent-held" "dkA:$ID1A:C1a disk" "agB:$ID1B:C1b(-N) agent-held" "dkB:$ID1B:C1b(-N) disk"; do
  c=${v%%:*}; rest=${v#*:}; id=${rest%%:*}; lbl=${rest#*:}
  attempt "$lbl, after expiry" "$T/$c.cfg" "$id"
  [ "$A_RC" = 255 ] && [ "$A_ACC" = 0 ] && [ "$A_FAILID" -ge 1 ] && [ "$A_REASON" = "Certificate invalid: expired" ]
  ok=$?; check "E2-after-expiry-$c" "rc 255; cert offered (Failed line with ID) and rejected as expired by sshd" "rc=$A_RC accepted=$A_ACC failed_with_id=$A_FAILID reason=[$A_REASON] offered=[$A_OFFER]" $ok
done

# ---- optional: agent-side automatic certificate removal (default) vs -N
if [ "$GRACE_CHECK" = 1 ]; then
  wait_until $((VB + 300 + 15))
  agent_list "$AA"; aA=$OUT; aAc=$(printf '%s\n' "$OUT" | grep -c 'ED25519-CERT'); aAk=$(printf '%s\n' "$OUT" | grep -c '(ED25519)')
  agent_list "$AB"; aB=$OUT; aBc=$(printf '%s\n' "$OUT" | grep -c 'ED25519-CERT')
  fact agentA_after_grace "$aA"; fact agentB_after_grace "$aB"
  fact agentA_debug_expiry "$(grep -i 'expir' "$T/aA/agent-debug.log" | head -3)"
  [ "$aAc" = 0 ] && [ "$aAk" = 1 ] && [ "$aBc" = 1 ]
  ok=$?; check E2-grace-removal "default ssh-add: cert gone from agent A after valid_before+300 s, plain key kept; ssh-add -N: cert still in agent B" "agentA cert=$aAc key=$aAk; agentB cert=$aBc" $ok
  # The same expired certificate offered from disk, now that agent A no longer holds it (agent A
  # still signs with the plain key): the rejection must be the same as while the agent held it.
  attempt "C1a disk, after expiry, agent A no longer holds the cert" "$T/dkA.cfg" "$ID1A"
  [ "$A_RC" = 255 ] && [ "$A_ACC" = 0 ] && [ "$A_FAILID" -ge 1 ] && [ "$A_REASON" = "Certificate invalid: expired" ] && [ "$aAc" = 0 ]
  ok=$?; check E2-after-expiry-dkA-cert-not-in-agent "rc 255; cert offered from disk and rejected as expired, the same as while the agent held it (agent A lists no certificate)" "rc=$A_RC accepted=$A_ACC failed_with_id=$A_FAILID reason=[$A_REASON] agentA_cert_entries=$aAc offered=[$A_OFFER]" $ok
fi
fact clock_ca1_end "$(clock_offset ca1)"
finish
