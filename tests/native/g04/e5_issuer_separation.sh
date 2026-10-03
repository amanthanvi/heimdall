#!/bin/bash
# E5 (G04, A10/A28, R-CR-04, R-AU-07): issuer separation and attenuation.
# Design: docs/research/g04-managed-credentials.md section 8.1 row E5.
#  Issuer: own 0700 dir + dedicated agent holding the fixture CA (ssh-add of runtime/keys/user_ca,
#          read-only; the fixture file itself is left for down.sh to dispose of).
#  Worker: own 0700 dir + dedicated agent holding K_env and its parent certificate.
#  Child:  own 0700 dir + dedicated agent holding K_child and a narrower, shorter certificate.
#  (a) from an environment with only the worker socket: the CA is not listed and cannot sign
#  (b) the issuer mints a child cert {p-host1} expiring before the parent {p-host1,p-host2};
#      the child is refused on ca2 and, after its own expiry, on ca1 while the parent still works
#  (c) scan worker/child dirs and the worker/child agent processes (argv + environment, counts
#      only, nothing printed) for CA private material
#  Disclosure probe: a same-user process that knows the issuer socket path CAN sign (separation
#  is by endpoint only within one OS user; spec 7.3).
EXP=e5-issuer-separation
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
CHILD_LIFE=${G04_E5_CHILD_LIFE:-60}

load_fixture; record_env
CABLOB=$(awk '{print $2}' "$FX_CA.pub")
mkdir -p "$T/scratch"; chmod 700 "$T/scratch"; cp "$FX_CA.pub" "$T/scratch/ca.pub"

start_agent "$T/issuer"; AI=$AGENT_SOCK
xrun "issuer: ssh-add -t 900 <fixture CA>" env SSH_AUTH_SOCK="$AI" "$SSH_ADD" -t 900 "$FX_CA"
[ "$RC" = 0 ] || die_setup "could not load the fixture CA into the issuer agent"
xrun "issuer: ssh-add -L" env SSH_AUTH_SOCK="$AI" "$SSH_ADD" -L
ok_ca=$(printf '%s\n' "$OUT" | grep -c -F "$CABLOB")
[ "$ok_ca" = 1 ]; ok=$?; check E5-issuer-holds-ca "issuer agent lists the CA public key once" "ca_entries=$ok_ca" $ok

start_agent "$T/worker"; AW=$AGENT_SOCK; WPID=$AGENT_PID
start_agent "$T/child"; ACH=$AGENT_SOCK; CPID=$AGENT_PID
genkey "$T/worker/kenv" "g04-e5-kenv-$RUN_ID"
genkey "$T/child/kchild" "g04-e5-kchild-$RUN_ID"
NOW=$(date -u +%s); PVB=$((NOW+900)); CVB=$((NOW+CHILD_LIFE))
IDP="g04-e5-parent-$RUN_ID"; IDC="g04-e5-child-$RUN_ID"
sign_agent "$AI" "$T/scratch/ca.pub" "$T/worker/kenv.pub" "$IDP" p-host1,p-host2 "$(vhex $((NOW-60))):$(vhex $PVB)" "$T/worker/kenv-cert.pub"; prc=$RC
sign_agent "$AI" "$T/scratch/ca.pub" "$T/child/kchild.pub" "$IDC" p-host1 "$(vhex $((NOW-60))):$(vhex $CVB)" "$T/child/kchild-cert.pub"; crc=$RC
[ "$prc" = 0 ] && [ "$crc" = 0 ]; ok=$?
check E5-issuer-signs-via-agent "issuer agent signs parent and child certificates with no CA private key file in the issuer dir" "parent_rc=$prc child_rc=$crc issuer_dir_files=$(ls "$T/issuer" | oneline)" $ok
[ "$prc" = 0 ] && [ "$crc" = 0 ] || die_setup "issuer signing failed"
PI=$(cert_info "$T/worker/kenv-cert.pub"); CI=$(cert_info "$T/child/kchild-cert.pub")
fact parent_cert "$PI valid_before_epoch=$PVB"; fact child_cert "$CI valid_before_epoch=$CVB"
# what the issued certificates actually carry (read back with ssh-keygen -L, not the request)
PPR=$(cert_principals "$T/worker/kenv-cert.pub"); CPR=$(cert_principals "$T/child/kchild-cert.pub")
PVBR=$(cert_vb_epoch "$T/worker/kenv-cert.pub"); CVBR=$(cert_vb_epoch "$T/child/kchild-cert.pub")
sub=yes; for p_ in $(printf '%s' "$CPR" | tr ',' ' '); do case ",$PPR," in *",$p_,"*) ;; *) sub=no;; esac; done
[ -n "$CPR" ] && [ "$sub" = yes ] && [ "$CPR" != "$PPR" ] && [ -n "$PVBR" ] && [ -n "$CVBR" ] && [ "$CVBR" -lt "$PVBR" ]; ok=$?
check E5-child-cert-narrower "issued child certificate: principals a strict subset of the parent's, valid_before earlier than the parent's" "parent_principals=$PPR child_principals=$CPR parent_valid_before=$PVBR child_valid_before=$CVBR subset=$sub" $ok
agent_add "$AW" "$T/worker/kenv" -t 900
agent_add "$ACH" "$T/child/kchild" -t 900

# (a) worker-only environment
WENV="env -i PATH=/usr/bin:/bin HOME=$T/worker SSH_AUTH_SOCK=$AW"
xrun "worker env: ssh-add -L" $WENV "$SSH_ADD" -L
wl=$(printf '%s\n' "$OUT" | grep -c '^ssh-'); wca=$(printf '%s\n' "$OUT" | grep -c -F "$CABLOB")
[ "$RC" = 0 ] && [ "$wca" = 0 ] && [ "$wl" = 2 ]; ok=$?
check E5a-ca-absent-from-worker-agent "worker agent lists only K_env and its certificate (2 entries); CA public key absent" "rc=$RC entries=$wl ca_entries=$wca" $ok
cp "$T/child/kchild.pub" "$T/scratch/x.pub"
xrun "worker env: try to sign a broad cert via the worker agent" $WENV "$SSH_KEYGEN" -U -s "$T/scratch/ca.pub" -I "g04-e5-forged-$RUN_ID" -n p-host1,p-host2 -V +1h "$T/scratch/x.pub"
frc=$RC; forged=no; [ -e "$T/scratch/x-cert.pub" ] && forged=yes
[ "$frc" != 0 ] && [ "$forged" = no ]; ok=$?
check E5a-worker-cannot-sign "ssh-keygen -U -s <CA pub> through the worker socket fails; no certificate written" "rc=$frc certificate_written=$forged" $ok

# (b) attenuation enforced by the servers
write_cfg "$T/parent.cfg" "$AW" "$T/worker/kenv.pub" "CertificateFile \"$T/worker/kenv-cert.pub\""
write_cfg "$T/child.cfg" "$ACH" "$T/child/kchild.pub" "CertificateFile \"$T/child/kchild-cert.pub\""
login() {  # LABEL CFG HOST ID EXP [REQUIRED_SERVER_REASON]
  local m ok acc accall failid reason want=${6:-}; m=$(mark "$3")
  xrun "$1" "$SSH" -F "$2" "g-$3" 'echo e5-ok'
  local rc=$RC; sleep 0.3
  acc=$(count_new "$3" "$m" "Accepted publickey" "ID $4 "); accall=$(count_new "$3" "$m" "Accepted publickey")
  failid=$(count_new "$3" "$m" "Failed publickey" "ID $4 ")
  reason=$(new_lines "$3" "$m" | grep -o -e 'Certificate does not contain an authorized principal' -e 'Certificate invalid: [a-z ]*' | sort -u | oneline)
  log_new "$3" "$m" "$1"
  if [ "$5" = 0 ]; then [ "$rc" = 0 ] && [ "$acc" = 1 ]; ok=$?
  else [ "$rc" = 255 ] && [ "$accall" = 0 ] && [ "$failid" -ge 1 ] && { [ -z "$want" ] || [ "$reason" = "$want" ]; }; ok=$?; fi
  check "E5b-$1" "rc $5$([ "$5" = 0 ] && echo ' with 1 Accepted line carrying the cert ID' || echo ", no Accepted line, cert presented (Failed line with its ID)${want:+ and refused with '$want'}")" "rc=$rc accepted_with_id=$acc accepted_any=$accall failed_with_id=$failid server_reason=[${reason:-none logged}]" $ok
}
login child-ca1-before-child-expiry "$T/child.cfg" ca1 "$IDC" 0
login child-ca2-principal-not-granted "$T/child.cfg" ca2 "$IDC" 255 "Certificate does not contain an authorized principal"
login parent-ca1 "$T/parent.cfg" ca1 "$IDP" 0
login parent-ca2 "$T/parent.cfg" ca2 "$IDP" 0
wait_until $((CVB + 3))
login child-ca1-after-child-expiry "$T/child.cfg" ca1 "$IDC" 255 "Certificate invalid: expired"
login parent-ca1-after-child-expiry "$T/parent.cfg" ca1 "$IDP" 0
login parent-ca2-after-child-expiry "$T/parent.cfg" ca2 "$IDP" 0

# (c) scan for CA private material (counts only)
grep -v -e '^-----' "$FX_CA" >"$T/scratch/patterns"   # CA private key body lines, kept in a 0700 dir
nfiles=0; hits_body=0; hits_hdr=0; hits_derive=0
for f in $(find "$T/worker" "$T/child" -type f); do
  nfiles=$((nfiles+1))
  grep -q -F -f "$T/scratch/patterns" "$f" && hits_body=$((hits_body+1))
  grep -q -F 'PRIVATE KEY' "$f" && hits_hdr=$((hits_hdr+1))
  d=$("$SSH_KEYGEN" -y -P '' -f "$f" </dev/null 2>/dev/null | awk '{print $2}')
  [ -n "$d" ] && [ "$d" = "$CABLOB" ] && hits_derive=$((hits_derive+1))
done
proc_hits=0
for p in "$WPID" "$CPID"; do
  n1=$(ps -E -o command= -p "$p" 2>/dev/null | grep -c -F -f "$T/scratch/patterns")
  n2=$(ps -E -o command= -p "$p" 2>/dev/null | grep -c -e 'user_ca' -e "$CABLOB")
  proc_hits=$((proc_hits + n1 + n2))
done
envhits=$($WENV /usr/bin/env | grep -c -e 'user_ca' -e "$CABLOB" -e 'PRIVATE')
rm -f "$T/scratch/patterns"
[ "$hits_body" = 0 ] && [ "$hits_hdr" = 0 ] && [ "$hits_derive" = 0 ] && [ "$proc_hits" = 0 ] && [ "$envhits" = 0 ]; ok=$?
check E5c-no-ca-material-in-worker-path "no CA private material in worker/child files, agent argv/environment, or the worker command environment" \
  "files_scanned=$nfiles ca_body_hits=$hits_body private_key_headers=$hits_hdr files_deriving_ca_pub=$hits_derive agent_process_hits=$proc_hits worker_env_hits=$envhits worker_files=[$(cd "$T/worker" && ls | oneline)]" $ok

# disclosure: same OS user + issuer socket path => signing is possible (endpoint separation only)
cp "$T/child/kchild.pub" "$T/scratch/y.pub"
xrun "same-user process that knows the issuer socket path" env -i PATH=/usr/bin:/bin SSH_AUTH_SOCK="$AI" "$SSH_KEYGEN" -U -s "$T/scratch/ca.pub" -I "g04-e5-sameuser-$RUN_ID" -n p-host1,p-host2 -V +5m "$T/scratch/y.pub"
src=$RC; rm -f "$T/scratch/y-cert.pub"
[ "$src" = 0 ]; ok=$?
obs E5-same-user-boundary "a same-user process with the issuer socket path can obtain signatures (separation is by endpoint only, not an OS boundary)" "rc=$src issuer_dir=$(stat -f '%Sp' "$T/issuer") socket=$(stat -f '%Sp' "$AI") owner_is_harness_uid=$([ "$(stat -f %u "$AI")" = "$(id -u)" ] && echo yes || echo no)" $ok
# disclosure: the fixture CA private key FILE stays on disk, readable by the same OS user, for the
# whole experiment (the issuer agent loaded it; down.sh disposes of it). The worker path's separation
# is therefore environment + agent endpoint only. Mode and readability only; contents never read here.
carc=1; env -i PATH=/usr/bin:/bin HOME="$T/worker" SSH_AUTH_SOCK="$AW" /bin/test -r "$FX_CA" && carc=0
camode=$(stat -f '%Sp' "$FX_CA" 2>/dev/null); caown=no; [ "$(stat -f %u "$FX_CA" 2>/dev/null)" = "$(id -u)" ] && caown=yes
[ "$carc" = 0 ]; ok=$?
obs E5-ca-file-readable-by-same-user "the fixture CA private key file remained readable by the same OS user from the worker-only environment (separation is by environment and agent endpoint, not by file access)" "readable_from_worker_env=$([ "$carc" = 0 ] && echo yes || echo no) mode=$camode owned_by_harness_uid=$caown path=<fixture-runtime>/keys/user_ca" $ok
finish
