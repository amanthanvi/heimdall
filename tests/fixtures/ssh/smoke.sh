#!/bin/bash
# Exercises every fixture scenario against the running fixtures (run up.sh first).
# Prints one PASS/FAIL line per check with the observed result. Exit 0 only if all pass.
# All ssh calls: /usr/bin/ssh -F runtime/ssh_config (IdentitiesOnly yes, IdentityAgent none,
# StrictHostKeyChecking yes, fixture known_hosts). Nothing reads ~/.ssh or an agent.
set -u
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
need_docker; load_state; load_ports
K="$RUNTIME/keys"; C="$RUNTIME/certs"; mkdir -p "$C"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %-34s %s\n' "$1" "$2"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %-34s %s\n' "$1" "$2"; }
check(){ if [ "$2" = 0 ]; then ok "$1" "$3"; else bad "$1" "$3"; fi; }   # name, 0=good, detail

echo "== smoke start $(ts)"; cat "$RUNTIME/versions.txt" | sed 's/^/  /'
echo "== client config sanity (ssh -G)"
G="$(hm_ssh -G fixed-auth)"
for want in 'stricthostkeychecking true' 'identitiesonly yes' 'identityagent none' 'forwardagent no' 'batchmode yes'; do
  echo "$G" | grep -qx "$want"; check "config:$want" $? "ssh -G"
done
echo "$G" | grep -i '^identityfile ' | grep -q '/\.ssh/'; [ $? -ne 0 ]; check "config:no ~/.ssh identity" $? "$(echo "$G" | grep -ci '^identityfile ') identityfile entries, none under .ssh"
grep -v '^[[:space:]]*#' "$RUNTIME/ssh_config" | grep -Eqi 'accept-new|StrictHostKeyChecking[[:space:]]+(no|off|ask)'; [ $? -ne 0 ]; check "config:no accept-new/no" $? "grep on runtime/ssh_config"

echo "== published ports are loopback-only"
for r in fixed enroll ca1 ca2 bastion; do
  b="$(docker port "$(cname $r)" 22/tcp | tr '\n' ' ')"
  case "$b" in "127.0.0.1:"*) [ "$(echo $b | wc -w | tr -d ' ')" = 1 ]; check "port:$r" $? "$b";; *) check "port:$r" 1 "$b";; esac
done
tp="$(docker port "$(cname target)" 2>&1 | tr '\n' ' ')"; [ -z "${tp// /}" ]; check "port:target unpublished" $? "docker port output='${tp}'"

echo "== (a) fixed-auth host: login ok, key registry not writable"
out="$(hm_ssh fixed-auth 'id -un; stat -c "%U:%G %a" /etc/ssh/authorized_keys.d/fixed' 2>&1)"; rc=$?
check "fixed:login" $rc "exit=$rc out=$(echo $out)"
before="$(docker exec "$(cname fixed)" sha256sum /etc/ssh/authorized_keys.d/fixed | awk '{print $1}')"
out="$(hm_ssh fixed-auth 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACK attacker" >> /etc/ssh/authorized_keys.d/fixed' 2>&1)"; rc=$?
[ $rc -ne 0 ]; check "fixed:append-registry-denied" $? "remote exit=$rc msg=$(echo $out)"
out="$(hm_ssh fixed-auth 'mkdir -p ~/.ssh && echo x > ~/.ssh/authorized_keys' 2>&1)"; rc=$?
[ $rc -ne 0 ]; check "fixed:create-~/.ssh-denied" $? "remote exit=$rc msg=$(echo $out)"
after="$(docker exec "$(cname fixed)" sha256sum /etc/ssh/authorized_keys.d/fixed | awk '{print $1}')"
[ "$before" = "$after" ]; check "fixed:registry-unchanged" $? "sha256 before=$before after=$after"
echo "== wrong key rejected on fixed-auth"
out="$(hm_ssh fixed-wrongkey true 2>&1)"; rc=$?
[ $rc -ne 0 ]; check "fixed:other-key-rejected" $? "exit=$rc msg=$(echo $out)"
echo "== identity files actually offered (-vv) are only fixture keys"
v="$(hm_ssh -vv fixed-auth true 2>&1 | grep -E 'Will attempt key|Offering public key|identity file' )"
echo "$v" | grep -q '/\.ssh/'; [ $? -ne 0 ]; check "fixed:no ~/.ssh key offered" $? "$(echo "$v" | sed "s|$RUNTIME|<runtime>|g" | head -4 | tr '\n' ';')"

echo "== (b) account-enrollable host: add/remove marker key, unrelated lines byte-identical"
EXP="$(cat "$RUNTIME/seed/enroll_authorized_keys.sha256")"
cur="$(hm_ssh enrollable 'cat ~/.ssh/authorized_keys' | shasum -a 256 | awk '{print $1}')"
[ "$cur" = "$EXP" ]; check "enroll:seed-intact" $? "sha256=$cur expected=$EXP"
hm_ssh enrollable-marker true >/dev/null 2>&1; rc=$?; [ $rc -ne 0 ]; check "enroll:marker-not-yet-trusted" $? "exit=$rc"
hm_ssh enrollable 'cat >> ~/.ssh/authorized_keys' < "$K/user_marker.pub"; rc=$?
check "enroll:append-marker" $rc "exit=$rc"
out="$(hm_ssh enrollable-marker 'echo fresh-auth-with-marker-key' 2>&1)"; rc=$?
check "enroll:marker-login(fresh,no-mux)" $rc "exit=$rc out=$out"
# a concurrent administrator edit lands while the marker is present: must survive removal
hm_ssh enrollable 'printf "%s\n" "# concurrent admin edit" >> ~/.ssh/authorized_keys'
hm_ssh enrollable 'f=$HOME/.ssh/authorized_keys; grep -vF heimdall-m00-marker "$f" > "$f.new" && chmod 600 "$f.new" && mv "$f.new" "$f"'; rc=$?
check "enroll:remove-marker(atomic mv)" $rc "exit=$rc"
hm_ssh enrollable-marker true >/dev/null 2>&1; rc=$?; [ $rc -ne 0 ]; check "enroll:marker-rejected-after-removal" $? "exit=$rc"
hm_ssh enrollable 'cat ~/.ssh/authorized_keys' >"$RUNTIME/enroll_after.txt"
{ cat "$RUNTIME/seed/enroll_authorized_keys"; printf '%s\n' "# concurrent admin edit"; } | cmp -s - "$RUNTIME/enroll_after.txt"
check "enroll:unrelated+concurrent-bytes-identical" $? "cmp(seed + admin line, remote) after add+remove"
hm_ssh enrollable 'f=$HOME/.ssh/authorized_keys; grep -vxF "# concurrent admin edit" "$f" > "$f.new" && chmod 600 "$f.new" && mv "$f.new" "$f"'
perm="$(hm_ssh enrollable 'stat -c "%U:%a" ~/.ssh/authorized_keys')"
[ "$perm" = "enroll:600" ]; check "enroll:owner+mode-preserved" $? "stat=$perm"
cur="$(hm_ssh enrollable 'cat ~/.ssh/authorized_keys' | shasum -a 256 | awk '{print $1}')"
[ "$cur" = "$EXP" ]; check "enroll:restored-sha256" $? "sha256=$cur expected=$EXP"

echo "== (c) two CA-trusting hosts with different principal mappings"
sign() { # name principals validity [ca]
  rm -f "$C/$1-cert.pub"
  "$SSH_KEYGEN" -q -s "${4:-$K/user_ca}" -I "hm-fixture-$1" -n "$2" -V "$3" -z "$(date +%s)" -O no-agent-forwarding -O no-port-forwarding -O no-x11-forwarding \
    -O no-user-rc "$K/user_cert.pub" >/dev/null 2>&1 && mv "$K/user_cert-cert.pub" "$C/$1-cert.pub"
}
certssh() { # certname alias [cmd]
  local cn="$1" al="$2"; shift 2
  hm_ssh -o CertificateFile="$C/$cn-cert.pub" "$al" "$@"
}
sign p1 p-host1 +1h;           check "ca:sign p-host1 cert" $? "$("$SSH_KEYGEN" -L -f "$C/p1-cert.pub" | grep -E 'Valid:|Principals' -A1 | tr -s ' ' | tr '\n' ' ')"
sign p2 p-host2 +1h;           check "ca:sign p-host2 cert" $? "ok"
sign both p-host1,p-host2 +1h; check "ca:sign broad cert" $? "ok"
hm_ssh ca-host1 true >/dev/null 2>&1; rc=$?; [ $rc -ne 0 ]; check "ca:bare-key-rejected(no cert)" $? "exit=$rc"
out="$(certssh p1 ca-host1 'echo host1-ok' 2>&1)"; rc=$?; check "ca:p-host1 cert -> host1 accepted" $rc "exit=$rc out=$out"
out="$(certssh p1 ca-host2 'echo host2-ok' 2>&1)"; rc=$?; [ $rc -ne 0 ]; check "ca:p-host1 cert -> host2 REJECTED" $? "exit=$rc msg=$(echo $out)"
out="$(certssh p2 ca-host2 'echo host2-ok' 2>&1)"; rc=$?; check "ca:p-host2 cert -> host2 accepted" $rc "exit=$rc out=$out"
out="$(certssh p2 ca-host1 'echo host1-ok' 2>&1)"; rc=$?; [ $rc -ne 0 ]; check "ca:p-host2 cert -> host1 REJECTED" $? "exit=$rc msg=$(echo $out)"
out="$(certssh both ca-host1 'echo ok' 2>&1)"; r1=$?; out2="$(certssh both ca-host2 'echo ok' 2>&1)"; r2=$?
[ $r1 -eq 0 ] && [ $r2 -eq 0 ]; check "ca:broad cert works on BOTH hosts (scope caveat)" $? "host1 exit=$r1 host2 exit=$r2 (same CA + broad principals => usable everywhere)"
echo "== certificate validity / issuer failures"
sign expired p-host1 -2h:-1h;  check "ca:sign expired cert" $? "$("$SSH_KEYGEN" -L -f "$C/expired-cert.pub" | grep Valid: | tr -s ' ')"
out="$(certssh expired ca-host1 true 2>&1)"; rc=$?; [ $rc -ne 0 ]; check "ca:expired cert REJECTED" $? "exit=$rc msg=$(echo $out)"
logx="$(docker logs --since 2m "$(cname ca1)" 2>&1 | grep -i 'expired' | tail -1 | sed 's/^.*sshd/sshd/')"
[ -n "$logx" ]; check "ca:server-log shows expiry reason" $? "$logx"
sign future p-host1 +1h:+2h;   check "ca:sign not-yet-valid cert" $? "ok"
out="$(certssh future ca-host1 true 2>&1)"; rc=$?; [ $rc -ne 0 ]; check "ca:not-yet-valid cert REJECTED" $? "exit=$rc"
sign rogue p-host1 +1h "$K/user_ca_rogue"; check "ca:sign rogue-CA cert" $? "ok"
out="$(certssh rogue ca-host1 true 2>&1)"; rc=$?; [ $rc -ne 0 ]; check "ca:untrusted-issuer cert REJECTED" $? "exit=$rc"

echo "== (d) bastion + internal-only target"
out="$(hm_ssh internal-target 'echo target-ok; hostname; echo "agent_sock=${SSH_AUTH_SOCK:-unset}"' 2>&1)"; rc=$?
check "bastion:ProxyJump to internal target" $rc "exit=$rc out=$(echo $out)"
echo "$out" | grep -q 'agent_sock=unset'; check "bastion:no agent forwarding reached target" $? "$(echo "$out" | grep agent_sock)"
Gt="$(hm_ssh -G internal-target)"
cfg="$(echo "$Gt" | grep -E '^(forwardagent|proxyjump|identityagent) ' | tr '\n' ';')"
miss=""; for want in 'forwardagent no' 'proxyjump bastion' 'identityagent none'; do echo "$Gt" | grep -qx "$want" || miss="$miss [$want]"; done
[ -z "$miss" ]; check "bastion:effective config" $? "wanted forwardagent no / proxyjump bastion / identityagent none; got ${cfg}${miss:+ MISSING:$miss}"
# -W to a destination outside the bastion's PermitOpen must be refused BY the bastion policy
# (not by a network error): LogLevel=INFO makes ssh print the channel-open failure reason.
out="$(hm_ssh -o LogLevel=INFO -W 127.0.0.1:22 bastion </dev/null 2>&1)"; rc=$?
[ $rc -ne 0 ] && echo "$out" | grep -q 'administratively prohibited'; check "bastion:PermitOpen blocks other destinations" $? "ssh -W 127.0.0.1:22 exit=$rc msg=$(echo $out)"
# positive control: the permitted destination must still open (sshd banner is read through the tunnel)
ban="$(sleep 2 | hm_ssh -W hm-m00t03-target:22 bastion 2>&1 | head -1)"
case "$ban" in SSH-2.0-*) check "bastion:PermitOpen allows target (control)" 0 "banner=$ban";; *) check "bastion:PermitOpen allows target (control)" 1 "banner='$ban'";; esac
nets="$(docker inspect "$(cname target)" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}')"
[ "$(echo $nets)" = "$NET_INT" ]; check "target:only on internal network" $? "networks=$nets"
[ "$(docker network inspect "$NET_INT" --format '{{.Internal}}')" = true ]; check "network:internal flag" $? "Internal=$(docker network inspect "$NET_INT" --format '{{.Internal}}')"
docker exec "$(cname target)" bash -c 'timeout 4 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"' >/dev/null 2>&1; rc=$?; [ $rc -ne 0 ]; check "target:no external egress" $? "connect 1.1.1.1:443 exit=$rc"
tip="$(docker inspect "$(cname target)" --format "{{(index .NetworkSettings.Networks \"$NET_INT\").IPAddress}}")"
timeout 4 bash -c "exec 3<>/dev/tcp/$tip/22" >/dev/null 2>&1; rc=$?; [ $rc -ne 0 ]; check "target:not directly reachable from host" $? "host connect $tip:22 exit=$rc"
hm_ssh -o ProxyJump=none -o HostName="$tip" -o ConnectTimeout=4 internal-target true >/dev/null 2>&1; rc=$?; [ $rc -ne 0 ]; check "target:direct ssh (no jump) fails" $? "exit=$rc"

echo "== host-key substitution route (fixed-auth host gets a different host key)"
KH="$(shasum -a 256 "$RUNTIME/known_hosts" | awk '{print $1}')"
c="$(cname fixed)"
hm_ssh fixed-auth true >/dev/null 2>&1; check "hostkey:baseline login ok" $? "before swap"
docker cp "$RUNTIME/hostkeys/swap/ssh_host_ed25519_key" "$c:/fixture/ssh_host_ed25519_key"
docker exec "$c" bash -c 'install -m 0600 -o root -g root /fixture/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key && kill -HUP "$(cat /run/sshd-fixture.pid)"'; sleep 1.5
out="$(hm_ssh fixed-auth true </dev/null 2>&1)"; rc=$?
[ $rc -eq 255 ]; check "hostkey:swap -> hard failure (exit 255)" $? "exit=$rc msg=$(echo $out)"
echo "$out" | grep -Eqi 'host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED'; check "hostkey:failure reason is verification" $? "message matched"
out="$(hm_ssh -o StrictHostKeyChecking=ask fixed-auth true </dev/null 2>&1)"; rc=$?
[ $rc -ne 0 ]; check "hostkey:even StrictHostKeyChecking=ask fails (no accept path)" $? "exit=$rc"
[ "$KH" = "$(shasum -a 256 "$RUNTIME/known_hosts" | awk '{print $1}')" ]; check "hostkey:known_hosts unmodified" $? "sha256 unchanged"
# restore
docker cp "$RUNTIME/hostkeys/fixed/ssh_host_ed25519_key" "$c:/fixture/ssh_host_ed25519_key"
docker exec "$c" bash -c 'install -m 0600 -o root -g root /fixture/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key && kill -HUP "$(cat /run/sshd-fixture.pid)"'; sleep 1.5
hm_ssh fixed-auth true >/dev/null 2>&1; check "hostkey:restored -> login ok again" $? "after restoring original host key"

echo "== no private material in container images/logs of fixtures"
docker logs "$(cname fixed)" 2>&1 | grep -q 'BEGIN OPENSSH PRIVATE KEY'; [ $? -ne 0 ]; check "logs:no private key blocks" $? "grepped fixed container logs"

echo "== smoke end $(ts): pass=$PASS fail=$FAIL"
[ "$FAIL" = 0 ]
