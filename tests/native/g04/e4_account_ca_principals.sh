#!/bin/bash
# E4 (G04, capability 2, A09/A10, R-CR-05/06/07): account-level CA trust with a principal
# restriction on the account-enrollable fixture (account enroll owns ~/.ssh/authorized_keys).
# Design: docs/research/g04-managed-credentials.md section 8.1 row E4.
#  Adds   cert-authority,principals="hm:fx-enroll:enroll" <fixture CA pub> heimdall-g04-e4-<run>
#  with a spec 7.5-style transaction (preimage digest compare, temp file + atomic rename, marker),
#  tries certificates with principals hm:fx-enroll:enroll / enroll (the username) / ops, and the
#  bare key; then removes only the marker line and compares bytes with the preimage.
#  Controls before the line is added: the hm certificate (no trust yet) and our CA's ops
#  certificate against the seed's own cert-authority,principals="ops" line (a different CA key).
EXP=e4-account-ca-principals
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

load_fixture; record_env
SEED_SHA=$(cat "$FX_RT/seed/enroll_authorized_keys.sha256")
reg_admin_cfg
start_agent "$T/agent"; A=$AGENT_SOCK
genkey "$T/k4" "g04-e4-k4-$RUN_ID"
NOW=$(date -u +%s); V="$(vhex $((NOW-60))):$(vhex $((NOW+900)))"
sign_file "$FX_CA" "$T/k4.pub" "g04-e4-hm-$RUN_ID" "hm:fx-enroll:enroll" "$V" "$T/hm.pub"
sign_file "$FX_CA" "$T/k4.pub" "g04-e4-user-$RUN_ID" enroll "$V" "$T/user.pub"
sign_file "$FX_CA" "$T/k4.pub" "g04-e4-ops-$RUN_ID" ops "$V" "$T/ops.pub"
agent_add "$A" "$T/k4" -t 900
write_cfg "$T/cfg" "$A" "$T/k4.pub"
MARK="heimdall-g04-e4-$RUN_ID"
printf 'cert-authority,principals="hm:fx-enroll:enroll" %s %s\n' "$(awk '{print $1" "$2}' "$FX_CA.pub")" "$MARK" >"$T/line"
fact ca_line "$(cat "$T/line")"

# try LABEL CERT|bare EXPECTED_RC [REASON]
# REASON for a rejected certificate: "principal" = sshd must log the principal reason (our CA
# line matched, its principals= did not); "any" = only require that the certificate was presented
# and refused (Failed line with its ID). A rejection without the certificate being evaluated does
# not count.
PRN="Certificate does not contain an authorized principal"
try() {
  local label=$1 c=$2 exp=$3 want=${4:-any} m rc acc accid failid reason ok desc
  m=$(mark enroll)
  if [ "$c" = bare ]; then xrun "$label" "$SSH" -F "$T/cfg" g-enroll 'echo e4-ok'
  else xrun "$label" "$SSH" -F "$T/cfg" -o CertificateFile="$T/$c.pub" g-enroll 'echo e4-ok'; fi
  rc=$RC; sleep 0.3
  acc=$(count_new enroll "$m" "Accepted publickey")
  accid=$(count_new enroll "$m" "Accepted publickey" "ID g04-e4-$c-$RUN_ID ")
  failid=$(count_new enroll "$m" "Failed publickey" "ID g04-e4-$c-$RUN_ID ")
  reason=$(new_lines enroll "$m" | grep -o -e 'Certificate does not contain an authorized principal' -e 'Certificate invalid: [a-z ]*' | sort -u | oneline)
  log_new enroll "$m" "$label"
  if [ "$exp" = 0 ]; then
    [ "$rc" = 0 ] && [ "$accid" = 1 ]; ok=$?; desc="rc 0 with 1 Accepted line carrying the cert ID"
  elif [ "$c" = bare ]; then
    [ "$rc" = 255 ] && [ "$acc" = 0 ]; ok=$?; desc="rc 255, no Accepted line (plain key)"
  elif [ "$want" = principal ]; then
    [ "$rc" = 255 ] && [ "$acc" = 0 ] && [ "$failid" -ge 1 ] && [ "$reason" = "$PRN" ]; ok=$?
    desc="rc 255, no Accepted line; cert presented (Failed line with its ID) and refused with '$PRN'"
  else
    [ "$rc" = 255 ] && [ "$acc" = 0 ] && [ "$failid" -ge 1 ]; ok=$?
    desc="rc 255, no Accepted line; cert presented (Failed line with its ID) and refused"
  fi
  check "E4-$label" "$desc" "rc=$rc accepted=$acc accepted_with_id=$accid cert_failed_lines=$failid server_reason=[${reason:-none logged}]" $ok
}

reg_fetch "$T/pre" preimage; PRE_SHA=$(sha_of "$T/pre")
[ "$RC" = 0 ] && [ "$PRE_SHA" = "$SEED_SHA" ]
ok=$?; check E4-preimage-is-seed "registry readable over the existing path and equal to the fixture seed" "rc=$RC sha256=$PRE_SHA seed=$SEED_SHA" $ok
[ "$PRE_SHA" = "$SEED_SHA" ] || die_setup "registry is not the seed; run tests/fixtures/ssh/reset.sh"

try hm-before-line hm 255
# control: our CA's "ops" certificate against the seed alone, whose cert-authority,principals="ops"
# line trusts a different CA key. Isolates the CA-key match from our principals= restriction.
try ops-before-line-seed-ca-differs ops 255

reg_add "$PRE_SHA" "$T/line" "add cert-authority line (CAS on preimage)"
[ "$RC" = 0 ]; ok=$?; check E4-add-transaction "rc 0" "rc=$RC out=$OUT" $ok
reg_fetch "$T/after_add" after-add
{ cat "$T/pre"; cat "$T/line"; } | cmp -s - "$T/after_add"
ok=$?; check E4-added-exactly-one-line "after-add bytes == preimage bytes + the marker line" "cmp_rc=$ok lines=$(wc -l <"$T/after_add" | tr -d ' ')" $ok

try hm-principal hm 0
try username-principal user 255 principal
try ops-principal-our-ca ops 255 principal
try bare-key bare 255
reg_fetch "$T/mid" "existing path still works"
[ "$RC" = 0 ]; ok=$?; check E4-existing-access-survives "admin (pre-existing) key still authenticates while the CA line is present" "rc=$RC" $ok

reg_remove "$MARK" "remove marker line"
[ "$RC" = 0 ]; ok=$?; check E4-remove-transaction "rc 0" "rc=$RC out=$OUT" $ok
reg_fetch "$T/after_rm" after-remove
cmp -s "$T/pre" "$T/after_rm"; c=$?
[ "$c" = 0 ] && [ "$(sha_of "$T/after_rm")" = "$SEED_SHA" ]
ok=$?; check E4-bytes-restored "after-remove bytes identical to preimage; sha256 == seed" "cmp_rc=$c sha256=$(sha_of "$T/after_rm")" $ok
om=$(reg_owner_mode)
[ "$om" = "enroll:600 0" ]; ok=$?; check E4-owner-mode-no-temp-left "owner:mode enroll:600 and no hm-g04 temp files left in ~/.ssh" "$om" $ok
try hm-after-removal hm 255
finish
