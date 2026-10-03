#!/bin/bash
# E1 (G04): dedicated non-personal ssh-agent holding a disposable managed key + certificate.
# Design: docs/research/g04-managed-credentials.md section 8.1 row E1.
#  (a) ssh-add -l on the dedicated socket lists exactly K_env + its certificate
#  (b) fresh login to ca1 (IdentitiesOnly, ControlMaster=no, ControlPath=none) -> rc 0 and a new
#      "Accepted publickey ... ID <key id>" server line; the dedicated agent logs a sign request
#  (c) same with -o IdentityAgent=none -> rc 255 (private key file was deleted after ssh-add)
#  (d) the agent actually used is the temp socket: ssh -G identityagent, agent debug log
#  (e) after the ssh-add -t lifetime: ssh-add -T and a fresh login both fail
#  (f) kill the exact agent PID; process and socket are gone
EXP=e1-dedicated-agent
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
LIFE=${G04_E1_LIFETIME:-120}

load_fixture; record_env
start_agent "$T/agent" debug; A=$AGENT_SOCK; APID=$AGENT_PID; AIDENT=$(proc_ident "$APID")
genkey "$T/kenv" "g04-e1-kenv-$RUN_ID"
KID="g04-e1-$RUN_ID"
NOW=$(date -u +%s)
sign_file "$FX_CA" "$T/kenv.pub" "$KID" p-host1 "$(vhex $((NOW-60))):$(vhex $((NOW+600)))" "$T/kenv-cert.pub"
fact cert "$(cert_info "$T/kenv-cert.pub")"
fact kenv_fingerprint "$(fp_of "$T/kenv.pub")"

# ssh-add loads kenv and kenv-cert.pub (alongside) with a maximum lifetime of $LIFE seconds.
agent_add "$A" "$T/kenv" -t "$LIFE"
ADD_EPOCH=$(date -u +%s)
fact ssh_add_output "$OUT"
[ ! -e "$T/kenv" ]; ok=$?; check E1-private-file-deleted "private key file absent after ssh-add" "exists=$([ -e "$T/kenv" ] && echo yes || echo no)" $ok

# (a)
agent_list "$A"
n=$(printf '%s\n' "$OUT" | grep -c 'SHA256:')
types=$(printf '%s\n' "$OUT" | sed -n 's/.*(\([A-Z0-9-]*\))$/\1/p' | sort | tr '\n' ',' )
fpk=$(fp_of "$T/kenv.pub"); same=$(printf '%s\n' "$OUT" | grep -c -F "$fpk")
[ "$RC" = 0 ] && [ "$n" = 2 ] && [ "$same" = 2 ] && [ "$types" = "ED25519,ED25519-CERT," ]
ok=$?; check E1a-agent-lists-key-and-cert "rc 0; exactly 2 entries (ED25519 + ED25519-CERT) of K_env" "rc=$RC entries=$n types=$types matching_fp=$same" $ok

write_cfg "$T/cfg" "$A" "$T/kenv.pub" "CertificateFile \"$T/kenv-cert.pub\"" "ControlMaster no" "ControlPath none"

# (b)
m=$(mark ca1); s0=$(signs "$T/agent/agent-debug.log")
xrun "E1b fresh login ca1" "$SSH" -F "$T/cfg" g-ca1 'echo e1-login-ok'
rcb=$RC; outb=$OUT; sleep 0.5
acc=$(count_new ca1 "$m" "Accepted publickey" "ID $KID ")
s1=$(signs "$T/agent/agent-debug.log"); log_new ca1 "$m" E1b
[ "$rcb" = 0 ] && [ "$acc" = 1 ] && [ "$outb" = e1-login-ok ]
ok=$?; check E1b-fresh-login "rc 0, output e1-login-ok, exactly 1 new Accepted line with ID $KID" "rc=$rcb out=$outb new_accepted_with_id=$acc" $ok
[ $((s1 - s0)) -ge 1 ]
ok=$?; check E1b-dedicated-agent-signed "dedicated agent debug log shows >=1 new sign request during the login" "sign_requests_before=$s0 after=$s1" $ok

# (c)
m=$(mark ca1)
xrun "E1c login with IdentityAgent=none" "$SSH" -F "$T/cfg" -o IdentityAgent=none g-ca1 true
rcc=$RC; sleep 0.3; accc=$(count_new ca1 "$m" "Accepted publickey"); log_new ca1 "$m" E1c
[ "$rcc" = 255 ] && [ "$accc" = 0 ]
ok=$?; check E1c-no-agent-no-auth "rc 255 and no new Accepted line (no private key file exists)" "rc=$rcc new_accepted=$accc" $ok

# (d)
xrun "E1d ssh -G" "$SSH" -F "$T/cfg" -G g-ca1
ga=$(printf '%s\n' "$OUT" | sed -n 's/^identityagent //p'); gi=$(printf '%s\n' "$OUT" | grep -c '^identityfile ')
gio=$(printf '%s\n' "$OUT" | sed -n 's/^identitiesonly //p'); gcm=$(printf '%s\n' "$OUT" | sed -n 's/^controlmaster //p')
gcp=$(printf '%s\n' "$OUT" | sed -n 's/^controlpath //p')
[ "$ga" = "<tmp>/agent/agent.sock" ] && [ "$gi" = 1 ] && [ "$gio" = yes ] && [ "$gcm" = false ] && { [ -z "$gcp" ] || [ "$gcp" = none ]; }
ok=$?; check E1d-config-uses-temp-socket "ssh -G: identityagent=<tmp>/agent/agent.sock, one identityfile, identitiesonly yes, controlmaster false, controlpath none (ssh -G omits it when none)" "identityagent=$ga identityfile_entries=$gi identitiesonly=$gio controlmaster=$gcm controlpath=${gcp:-<absent>}" $ok
s0=$(signs "$T/agent/agent-debug.log")
xrun "E1d ssh -vvv login" "$SSH" -F "$T/cfg" -vvv g-ca1 true
rcd=$RC
agentlines=$(printf '%s\n' "$OUT" | grep -iE 'agent' | grep -v -e 'ForwardAgent' | head -12)
printf '%s\n' "$agentlines" | sed 's/^/    agent-line: /' >>"$LOG"
foreign=$(printf '%s\n' "$OUT" | grep -iE 'agent|identity file|Will attempt|Offering' | grep -E '/' | grep -v -e '<tmp>' -e '<fixture-runtime>' | grep -c .)
homeref=$(printf '%s\n' "$OUT" | grep -c -e '<home>' -e '/\.ssh/')
s1=$(signs "$T/agent/agent-debug.log")
[ "$rcd" = 0 ] && [ "$foreign" = 0 ] && [ "$homeref" = 0 ] && [ $((s1 - s0)) -ge 1 ]
ok=$?; check E1d-only-temp-agent-used "rc 0; no key/agent path outside <tmp>; no <home> or .ssh path in -vvv; dedicated agent saw a sign request" "rc=$rcd foreign_paths=$foreign home_or_dotssh_refs=$homeref sign_requests_delta=$((s1 - s0))" $ok

# (e) wait past the ssh-add -t lifetime
wait_until $((ADD_EPOCH + LIFE + 3))
agent_list "$A"; rcl=$RC; outl=$OUT
xrun "E1e ssh-add -T after lifetime" env SSH_AUTH_SOCK="$A" "$SSH_ADD" -T "$T/kenv.pub"
rct=$RC
m=$(mark ca1)
xrun "E1e fresh login after lifetime" "$SSH" -F "$T/cfg" g-ca1 true
rce=$RC; sleep 0.3; acce=$(count_new ca1 "$m" "Accepted publickey"); log_new ca1 "$m" E1e
expired_lines=$(grep -c -i -e 'expir' "$T/agent/agent-debug.log")
fact agent_debug_expiry_lines "$(grep -i -e 'expir' "$T/agent/agent-debug.log" | head -4)"
[ "$rct" != 0 ] && [ "$rce" = 255 ] && [ "$acce" = 0 ]
ok=$?; check E1e-lifetime-ends-signing "after -t $LIFE s: ssh-add -T rc!=0, fresh login rc 255, no Accepted line" "ssh-add -l rc=$rcl ($outl); ssh-add -T rc=$rct; login rc=$rce new_accepted=$acce; agent expiry log lines=$expired_lines" $ok

# (f) kill the exact agent PID
res=$(kill_exact "$APID" "$AIDENT")
sock="present"; [ -S "$A" ] || sock="removed"
gone="running"; [ -z "$(proc_ident "$APID")" ] && gone="gone"
[ "$res" = terminated ] && [ "$sock" = removed ] && [ "$gone" = gone ]
ok=$?; check E1f-exact-pid-kill "kill_exact terminated; process gone; socket removed" "kill=$res process=$gone socket=$sock" $ok
finish
