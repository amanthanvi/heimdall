#!/bin/bash
# E3 (G04, A10, R-CR-07): principal scope across two hosts that trust the same CA
# (system-level TrustedUserCAKeys; ca1 maps account cert -> principal p-host1, ca2 -> p-host2).
# Design: docs/research/g04-managed-credentials.md section 8.1 row E3.
# One disposable key K in a dedicated agent; certificates on disk (CertificateFile per attempt):
#   p1 {p-host1}, p2 {p-host2}, both {p-host1,p-host2}, user {cert} (the account name),
#   rogue {p-host1} signed by an untrusted CA, and the bare key. Each tried on ca1 and ca2.
EXP=e3-principal-scope
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

load_fixture; record_env
start_agent "$T/agent"; A=$AGENT_SOCK
genkey "$T/k" "g04-e3-k-$RUN_ID"
NOW=$(date -u +%s); V="$(vhex $((NOW-60))):$(vhex $((NOW+900)))"
sign_file "$FX_CA" "$T/k.pub" "g04-e3-p1-$RUN_ID" p-host1 "$V" "$T/p1.pub"
sign_file "$FX_CA" "$T/k.pub" "g04-e3-p2-$RUN_ID" p-host2 "$V" "$T/p2.pub"
sign_file "$FX_CA" "$T/k.pub" "g04-e3-both-$RUN_ID" p-host1,p-host2 "$V" "$T/both.pub"
sign_file "$FX_CA" "$T/k.pub" "g04-e3-user-$RUN_ID" cert "$V" "$T/user.pub"
sign_file "$FX_CA_ROGUE" "$T/k.pub" "g04-e3-rogue-$RUN_ID" p-host1 "$V" "$T/rogue.pub"
for c in p1 p2 both user rogue; do fact "cert_$c" "$(cert_info "$T/$c.pub")"; done
agent_add "$A" "$T/k" -t 900
agent_list "$A"; fact agent_contents "$OUT"
write_cfg "$T/cfg" "$A" "$T/k.pub"

# expected rc on ca1 / ca2
expect() { case "$1" in p1) echo "0 255";; p2) echo "255 0";; both) echo "0 0";; *) echo "255 255";; esac; }
TABLE=""
for c in p1 p2 both user rogue bare; do
  set -- $(expect "$c"); e1=$1; e2=$2
  for h in ca1 ca2; do
    if [ "$h" = ca1 ]; then exp=$e1; else exp=$e2; fi
    m=$(mark "$h")
    if [ "$c" = bare ]; then
      xrun "$c -> $h" "$SSH" -F "$T/cfg" -v "g-$h" "echo e3-$c-$h"
    else
      xrun "$c -> $h" "$SSH" -F "$T/cfg" -v -o CertificateFile="$T/$c.pub" "g-$h" "echo e3-$c-$h"
    fi
    rc=$RC; offered=$(printf '%s\n' "$OUT" | grep -c 'Offering public key'); remote=$(printf '%s\n' "$OUT" | grep -c "^e3-$c-$h\$")
    sleep 0.3
    acc=$(count_new "$h" "$m" "Accepted publickey")
    accid=$(count_new "$h" "$m" "Accepted publickey" "ID g04-e3-$c-$RUN_ID ")
    failid=$(count_new "$h" "$m" "Failed publickey" "ID g04-e3-$c-$RUN_ID ")
    reason=$(new_lines "$h" "$m" | grep -o -e 'Certificate does not contain an authorized principal' -e 'Certificate invalid: [a-z ]*' | sort -u | oneline)
    log_new "$h" "$m" "$c -> $h"
    # A rejection only counts if the server evaluated the certificate (Failed line with its ID)
    # and, for a CA-trusted certificate with the wrong principal, logged the principal reason.
    PRN="Certificate does not contain an authorized principal"
    if [ "$exp" = 0 ]; then
      [ "$rc" = 0 ] && [ "$accid" = 1 ] && [ "$remote" = 1 ]; ok=$?
      desc="rc 0 with 1 Accepted line carrying ID g04-e3-$c"
    else
      case "$c" in
        bare)  [ "$rc" = 255 ] && [ "$acc" = 0 ]; ok=$?; desc="rc 255 and no Accepted line (plain key, no certificate)";;
        rogue) [ "$rc" = 255 ] && [ "$acc" = 0 ] && [ "$failid" -ge 1 ]; ok=$?; desc="rc 255, no Accepted line; certificate presented (Failed line with its ID) and refused (untrusted CA)";;
        *)     [ "$rc" = 255 ] && [ "$acc" = 0 ] && [ "$failid" -ge 1 ] && [ "$reason" = "$PRN" ]; ok=$?; desc="rc 255, no Accepted line; certificate presented (Failed line with its ID) and refused with '$PRN'";;
      esac
    fi
    check "E3-$c-$h" "$desc" "rc=$rc accepted=$acc accepted_with_id=$accid failed_with_id=$failid offered_keys=$offered server_reason=[${reason:-none logged}]" $ok
    TABLE="$TABLE $c@$h=rc$rc"
  done
done
fact matrix "$TABLE"
fact scope_caveat "certificate 'both' {p-host1,p-host2} is usable on every host whose principal map contains either name; it is not scoped to one destination"
finish
