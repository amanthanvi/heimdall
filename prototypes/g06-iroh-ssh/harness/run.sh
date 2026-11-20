#!/bin/bash
# Disposable G06 harness: ordinary OpenSSH over the embedded-iroh probe, in containers only.
#   run.sh <bin-dir> <out-dir> [local|inet|all]
# <bin-dir> holds g06-stock, g06-patched, g06-portmapper, iroh-relay, pigeons (linux, built by
# the build container). Every fixture key is generated inside a container for this run and dies
# with it. "local" uses only --internal docker networks (no route off the docker host). "inet"
# uses one ordinary bridge with outbound internet for n0's public relay/DNS and Pigeons interop;
# the serving endpoint there admits only allowlisted endpoint IDs.
# Results: <out-dir>/results.tsv (case, exit, elapsed_ms, note) plus per-case logs.
set -u
B=$1; O=$2; MODE=${3:-all}
mkdir -p "$O"
IMG=hm-g06-run:local
T=/probe
RES="$O/results.tsv"
[ -f "$RES" ] || printf 'case\texit\telapsed_ms\tnote\n' > "$RES"
res() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RES"; echo "== $1 exit=$2 ms=$3 $4"; }
now() { python3 -c 'import time;print(int(time.time()*1000))'; }
x() { docker exec "$@"; }
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"; }

start() { # name net [extra nets...]
  local name=$1 net=$2; shift 2
  docker run -d --name "$name" --hostname "$name" --network "$net" --cap-add SYS_PTRACE --cap-add NET_RAW \
    -v "$B":$T:ro "$IMG" sleep infinity >/dev/null
  for n in "$@"; do docker network connect "$n" "$name"; done
  x "$name" mkdir -p /work
}

setup_srv() { # name: fixture sshd on 127.0.0.1:22 only, fresh host key, user hm
  x "$1" sh -c '
    usermod -p "*" hm
    ssh-keygen -q -t ed25519 -N "" -f /work/hostkey -C hm-g06-fixture-host >/dev/null
    cat > /work/sshd_config <<EOF
ListenAddress 127.0.0.1
Port 22
HostKey /work/hostkey
PidFile /work/sshd.pid
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
AllowUsers hm
LogLevel VERBOSE
EOF
    /usr/sbin/sshd -f /work/sshd_config -E /work/sshd.log'
}

setup_cli() { # cli srv: fixture user key, known_hosts entry under the destination alias
  x "$1" sh -c 'ssh-keygen -q -t ed25519 -N "" -f /work/id -C hm-g06-fixture-user >/dev/null; : > /work/ssh_config'
  x "$1" cat /work/id.pub | x -i "$2" sh -c 'mkdir -p /home/hm/.ssh && cat > /home/hm/.ssh/authorized_keys && chown -R hm:hm /home/hm/.ssh && chmod 700 /home/hm/.ssh && chmod 600 /home/hm/.ssh/authorized_keys'
  pin_hostkey "$1" "$2"
}
pin_hostkey() { local k; k=$(x "$2" cat /work/hostkey.pub | cut -d' ' -f1,2); x "$1" sh -c "echo 'hm-dest-1 $k' > /work/known_hosts"; }

# sshc <cli> <case> <proxy-binary> "<proxy args>" "<remote command>"  -> sets RC, MS
sshc() {
  local c=$1 case=$2 bin=$3 px=$4 cmd=$5 t0
  t0=$(now)
  x "$c" env -u SSH_AUTH_SOCK sh -c "timeout 90 ssh -F /work/ssh_config -o IdentityFile=none -o IdentityFile=/work/id \
    -o IdentitiesOnly=yes -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile=/work/known_hosts \
    -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o HostKeyAlias=hm-dest-1 -o UpdateHostKeys=no -o ConnectTimeout=30 \
    -o 'ProxyCommand=sh -c \"echo \\\$\\\$ > /work/proxy.pid; exec ${PXWRAP:-} $T/$bin connect --key /work/cli.key $px 2>>/work/proxy-$case.log\"' \
    hm@dest-1 '$cmd'" > "$O/$case.out" 2> "$O/$case.err"
  RC=$?; MS=$(( $(now) - t0 ))
}

serve_start() { # name binary "args" logname
  x -d "$1" sh -c "echo \$\$ > /work/serve.pid; exec $T/$2 serve --key /work/srv.key $3 --target 127.0.0.1:22 2>>/work/serve-$4.log"
  for _ in $(seq 1 50); do x "$1" grep -q '"event":"ready"' "/work/serve-$4.log" 2>/dev/null && return 0; sleep 0.2; done
  return 1
}
serve_stop() { x "$1" sh -c 'kill "$(cat /work/serve.pid)" 2>/dev/null; sleep 0.5'; }
srv_id() { x "$1" $T/g06-patched id /work/srv.key; }

local_suite() {
  docker network create --internal hm-g06-ab >/dev/null
  docker network create --internal hm-g06-a >/dev/null
  docker network create --internal hm-g06-b >/dev/null
  start srv hm-g06-ab hm-g06-a
  start cli hm-g06-ab hm-g06-b
  setup_srv srv; setup_cli cli srv
  x srv $T/g06-patched keygen /work/srv.key >/dev/null; x cli $T/g06-patched keygen /work/cli.key >/dev/null
  local SIP CIP CID ID1 ID2
  SIP=$(ip_of srv hm-g06-ab); CIP=$(ip_of cli hm-g06-ab); ID1=$(srv_id srv); CID=$(x cli $T/g06-patched id /work/cli.key)
  echo "srv $SIP id $ID1 cli $CID" > "$O/local-ids.txt"
  local DIRECT="--bind $CIP:0 --relay disabled --lookup none --peer $ID1 --addr $SIP:7000"

  # S01 direct path, relays and lookup disabled, allowlist = the client
  serve_start srv g06-patched "--bind $SIP:7000 --relay disabled --lookup none --allow $CID" s01
  sshc cli s01-direct g06-patched "$DIRECT" 'echo ok-direct'; res S01-direct "$RC" "$MS" "$(cat "$O/s01-direct.out")"
  # S02 persistent identity: restart the serving helper with the same key file
  serve_stop srv; serve_start srv g06-patched "--bind $SIP:7000 --relay disabled --lookup none --allow $CID" s02
  ID2=$(srv_id srv)
  sshc cli s02-restart-same-key g06-patched "$DIRECT" 'echo ok-restart'
  res S02-restart-same-key "$RC" "$MS" "id_unchanged=$([ "$ID1" = "$ID2" ] && echo yes || echo no) $(cat "$O/s02-restart-same-key.out")"
  # S03 allowlist: a client with another endpoint key is refused before sshd
  x cli $T/g06-patched keygen /work/other.key >/dev/null
  # (sshc always uses /work/cli.key; swap keys for this one case)
  x cli sh -c 'mv /work/cli.key /work/cli.key.real; cp /work/other.key /work/cli.key; chmod 600 /work/cli.key'
  sshc cli s03-not-allowlisted g06-patched "$DIRECT" 'echo should-not-run'
  x cli sh -c 'mv /work/cli.key.real /work/cli.key'
  res S03-not-allowlisted "$RC" "$MS" "refused_logged=$(x srv grep -c '"event":"refused"' /work/serve-s02.log)"
  # S04 endpoint identity replaced at the same address: the old ID must not reach the new endpoint
  serve_stop srv; x srv sh -c 'mv /work/srv.key /work/srv.key.orig'; x srv $T/g06-patched keygen /work/srv.key >/dev/null
  serve_start srv g06-patched "--bind $SIP:7000 --relay disabled --lookup none --allow $CID" s04
  sshc cli s04-endpoint-replaced g06-patched "$DIRECT --timeout-ms 8000" 'echo should-not-run'
  res S04-endpoint-replaced "$RC" "$MS" "$(tail -c 300 "$O/s04-endpoint-replaced.err" | tr '\n' ' ')"
  serve_stop srv; x srv sh -c 'mv /work/srv.key.orig /work/srv.key'
  serve_start srv g06-patched "--bind $SIP:7000 --relay disabled --lookup none --allow $CID" s05
  # S05 helper (serving side) killed mid-session: the SSH session is lost, not migrated
  x -d cli sh -c "rm -f /work/s05.rc; t0=\$(date +%s%3N); env -u SSH_AUTH_SOCK ssh -F /work/ssh_config -o IdentityFile=none -o IdentityFile=/work/id -o IdentitiesOnly=yes -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile=/work/known_hosts -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=hm-dest-1 -o ServerAliveInterval=2 -o ServerAliveCountMax=2 -o 'ProxyCommand=$T/g06-patched connect --key /work/cli.key $DIRECT 2>>/work/proxy-s05.log' hm@dest-1 'sleep 30' 2>/work/s05.err; echo \$? \$(( \$(date +%s%3N) - t0 )) > /work/s05.rc"
  sleep 3; local tk; tk=$(now); serve_stop srv
  for _ in $(seq 1 60); do x cli test -f /work/s05.rc && break; sleep 0.5; done
  res S05-helper-killed-mid-session "$(x cli cut -d' ' -f1 /work/s05.rc 2>/dev/null || echo none)" "$(( $(now) - tk ))" "ms_after_kill; session_total_ms=$(x cli cut -d' ' -f2 /work/s05.rc 2>/dev/null)"
  x cli cat /work/s05.err > "$O/s05.err" 2>/dev/null
  serve_start srv g06-patched "--bind $SIP:7000 --relay disabled --lookup none --allow $CID" s05b
  sshc cli s05b-after-restart g06-patched "$DIRECT" 'echo ok-after-restart'; res S05b-after-restart "$RC" "$MS" "$(cat "$O/s05b-after-restart.out")"
  # S06 cancellation: the ProxyCommand process is killed mid-session
  x -d cli sh -c "rm -f /work/s06.rc; env -u SSH_AUTH_SOCK ssh -F /work/ssh_config -o IdentityFile=none -o IdentityFile=/work/id -o IdentitiesOnly=yes -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile=/work/known_hosts -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=hm-dest-1 -o 'ProxyCommand=sh -c \"echo \\\$\\\$ > /work/proxy.pid; exec $T/g06-patched connect --key /work/cli.key $DIRECT 2>>/work/proxy-s06.log\"' hm@dest-1 'sleep 30' 2>/work/s06.err; echo \$? > /work/s06.rc"
  sleep 3; tk=$(now); x cli sh -c 'kill "$(cat /work/proxy.pid)"'
  for _ in $(seq 1 40); do x cli test -f /work/s06.rc && break; sleep 0.25; done
  res S06-proxy-cancelled "$(x cli cat /work/s06.rc 2>/dev/null || echo none)" "$(( $(now) - tk ))" "ms_after_kill"
  # S07 unreachable route: bounded failure, distinct exit
  sshc cli s07-unreachable g06-patched "--bind $CIP:0 --relay disabled --lookup none --peer $ID1 --addr 10.99.99.99:7000 --timeout-ms 3000" 'echo should-not-run'
  res S07-unreachable "$RC" "$MS" "proxy=$(x cli grep -o '"code":[0-9]*' /work/proxy-s07-unreachable.log | tail -1)"
  # S08 wildcard-bind trace, stock vs patched (both sides, one ssh each)
  for v in stock patched; do
    serve_stop srv
    x -d srv sh -c "exec strace -f -qq -e trace=socket,bind,connect -o /work/strace-serve-$v.txt sh -c 'echo \$\$ > /work/serve.pid; exec $T/g06-$v serve --key /work/srv.key --bind $SIP:7000 --relay disabled --lookup none --allow $CID --target 127.0.0.1:22 2>>/work/serve-s08-$v.log'"
    sleep 2
    PXWRAP="strace -f -qq -e trace=socket,bind,connect -o /work/strace-connect-$v.txt" sshc cli s08-$v g06-$v "$DIRECT" 'echo ok-trace'
    x srv sh -c 'kill "$(cat /work/serve.pid)"'; sleep 1
    local wb_s wb_c
    wb_s=$(x srv grep -cE 'bind\(.*inet_addr\("0\.0\.0\.0"\)|bind\(.*inet_pton\(AF_INET6, "::"' /work/strace-serve-$v.txt)
    wb_c=$(x cli grep -cE 'bind\(.*inet_addr\("0\.0\.0\.0"\)|bind\(.*inet_pton\(AF_INET6, "::"' /work/strace-connect-$v.txt)
    res S08-trace-$v "$RC" "$MS" "$(cat "$O/s08-$v.out") serve_wildcard_binds=$wb_s connect_wildcard_binds=$wb_c serve_probe_connects=$(x srv grep -c '10.254.254.254' /work/strace-serve-$v.txt) connect_probe_connects=$(x cli grep -c '10.254.254.254' /work/strace-connect-$v.txt)"
  done
  serve_start srv g06-patched "--bind $SIP:7000 --relay disabled --lookup none --allow $CID" s09
  # S09 SSH host key replaced behind an unchanged endpoint ID: ssh must refuse
  x srv sh -c 'kill "$(cat /work/sshd.pid)"; rm -f /work/hostkey /work/hostkey.pub; ssh-keygen -q -t ed25519 -N "" -f /work/hostkey -C hm-g06-fixture-host2 >/dev/null; /usr/sbin/sshd -f /work/sshd_config -E /work/sshd.log'
  sshc cli s09-hostkey-changed g06-patched "$DIRECT" 'echo should-not-run'
  res S09-hostkey-changed "$RC" "$MS" "$(grep -o 'REMOTE HOST IDENTIFICATION HAS CHANGED\|Host key verification failed' "$O/s09-hostkey-changed.err" | sort -u | tr '\n' ';')"
  pin_hostkey cli srv
  serve_stop srv

  # Relay suite: srv only on net a, cli only on net b, relay on both (no direct route a<->b)
  start relay hm-g06-a hm-g06-b
  x -d relay sh -c "echo \$\$ > /work/relay.pid; exec $T/iroh-relay --dev 2>/work/relay.log"
  sleep 2
  docker network disconnect hm-g06-ab srv; docker network disconnect hm-g06-ab cli
  local SA CB; SA=$(ip_of srv hm-g06-a); CB=$(ip_of cli hm-g06-b)
  local RURL=http://relay:3340
  serve_start srv g06-patched "--bind $SA:7000 --relay $RURL --lookup none --allow $CID" s10
  local RELAY="--bind $CB:0 --relay $RURL --lookup none --peer $ID1 --peer-relay $RURL"
  sshc cli s10-relay g06-patched "$RELAY" 'echo ok-relay'
  res S10-relay-path "$RC" "$MS" "$(cat "$O/s10-relay.out") selected=$(x cli grep '"event":"connected"' /work/proxy-s10-relay.log | grep -o '"relay":[a-z]*,"ip":[a-z]*,"selected":true' | head -1)"
  # S11 relay-only, no IP transport at all on the dialing side (Windows no-UDP option), traced
  PXWRAP="strace -f -qq -e trace=socket,bind,connect,sendto,sendmsg -o /work/strace-relayonly.txt" sshc cli s11-relay-only g06-patched "--bind none --relay $RURL --lookup none --peer $ID1 --peer-relay $RURL" 'echo ok-relay-only'
  res S11-relay-only-no-udp "$RC" "$MS" "$(cat "$O/s11-relay-only.out") udp_sockets=$(x cli grep -c 'SOCK_DGRAM' /work/strace-relayonly.txt) udp_binds=$(x cli grep -c 'bind(' /work/strace-relayonly.txt)"
  # S12 relay unavailable: bounded failure; capture shows no other infrastructure attempted
  x relay sh -c 'kill "$(cat /work/relay.pid)"'; sleep 1
  x -d cli sh -c 'echo $$ > /work/tcpdump.pid; exec tcpdump -i any -nn -l -U -w /work/s12.pcap 2>/dev/null'
  sleep 1
  sshc cli s12-relay-down g06-patched "$RELAY --timeout-ms 8000" 'echo should-not-run'
  sleep 1; x cli sh -c 'kill "$(cat /work/tcpdump.pid)"'; sleep 1
  x cli sh -c 'tcpdump -nn -r /work/s12.pcap 2>/dev/null' > "$O/s12-capture.txt"
  res S12-relay-down "$RC" "$MS" "packets=$(wc -l < "$O/s12-capture.txt") iroh_names=$(grep -ci 'iroh\|n0' "$O/s12-capture.txt") dst_set=$(grep -oE '> [0-9.]+\.[0-9]+:' "$O/s12-capture.txt" | sort -u | tr '\n' ' ')"
  serve_stop srv
  for c in srv cli relay; do docker diff $c > "$O/docker-diff-$c.txt"; done
  for c in srv cli; do mkdir -p "$O/$c"; x $c sh -c 'cd /work && tar cf - *.log *.txt' 2>/dev/null | tar xf - -C "$O/$c"; done
  x relay cat /work/relay.log > "$O/relay.log" 2>/dev/null
  docker rm -f srv cli relay >/dev/null
  docker network rm hm-g06-ab hm-g06-a hm-g06-b >/dev/null
}

inet_suite() {
  docker network create hm-g06-inet >/dev/null
  start srv2 hm-g06-inet; start cli2 hm-g06-inet
  setup_srv srv2; setup_cli cli2 srv2
  x srv2 $T/g06-patched keygen /work/srv.key >/dev/null; x cli2 $T/g06-patched keygen /work/cli.key >/dev/null
  local ID CID; ID=$(srv_id srv2); CID=$(x cli2 $T/g06-patched id /work/cli.key)
  for c in srv2 cli2; do x -d $c sh -c 'echo $$ > /work/tcpdump.pid; exec tcpdump -i any -nn -l -U -w /work/inet.pcap 2>/dev/null'; done
  sleep 1
  # I01 iroh's n0 defaults (n0 relays, n0 DNS publish+resolve, default binds, portmapper) on both sides
  serve_start srv2 g06-portmapper "--bind default --relay n0 --lookup n0 --portmapper on --allow $CID" i01
  sleep 8
  sshc cli2 i01-n0-defaults g06-portmapper "--bind default --relay n0 --lookup n0 --portmapper on --peer $ID --timeout-ms 30000" 'echo ok-n0'
  res I01-n0-defaults "$RC" "$MS" "$(cat "$O/i01-n0-defaults.out") connected=$(x cli2 grep -o '"event":"connected".*' /work/proxy-i01-n0-defaults.log | head -c 400)"
  # I02 stock Pigeons client (iroh-pigeons 0.2.3, `pigeons fly --stdio`) against the probe's server
  x cli2 env -u SSH_AUTH_SOCK sh -c "timeout 60 ssh -F /work/ssh_config -o IdentityFile=none -o IdentityFile=/work/id -o IdentitiesOnly=yes -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile=/work/known_hosts -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=hm-dest-1 -o 'ProxyCommand=$T/pigeons fly --stdio $ID 2>>/work/pigeons-fly.log' hm@dest-1 'echo ok-pigeons'" > "$O/i02a.out" 2> "$O/i02a.err"
  local rca=$? PID
  PID=$(x srv2 grep -o '"event":"refused","peer":"[0-9a-f]*"' /work/serve-i01.log | head -1 | grep -o '[0-9a-f]\{64\}')
  res I02a-pigeons-client-not-allowlisted "$rca" 0 "refused_peer_logged=$([ -n "$PID" ] && echo yes || echo no)"
  if [ -n "$PID" ]; then
    serve_stop srv2
    serve_start srv2 g06-portmapper "--bind default --relay n0 --lookup n0 --portmapper on --allow $CID --allow $PID" i02
    sleep 8
    local t0; t0=$(now)
    x cli2 env -u SSH_AUTH_SOCK sh -c "timeout 60 ssh -F /work/ssh_config -o IdentityFile=none -o IdentityFile=/work/id -o IdentitiesOnly=yes -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile=/work/known_hosts -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=hm-dest-1 -o 'ProxyCommand=$T/pigeons fly --stdio $ID 2>>/work/pigeons-fly.log' hm@dest-1 'echo ok-pigeons'" > "$O/i02b.out" 2> "$O/i02b.err"
    res I02b-pigeons-client-interop "$?" "$(( $(now) - t0 ))" "$(cat "$O/i02b.out")"
  fi
  serve_stop srv2; sleep 1
  for c in srv2 cli2; do x $c sh -c 'kill "$(cat /work/tcpdump.pid)"'; done; sleep 1
  for c in srv2 cli2; do
    x $c sh -c 'tcpdump -nn -r /work/inet.pcap 2>/dev/null' > "$O/$c-inet-capture.txt"
    x $c sh -c 'tcpdump -nn -r /work/inet.pcap port 53 2>/dev/null' | grep -oE '(A|AAAA|TXT|HTTPS)\? [A-Za-z0-9._-]+' | sort | uniq -c > "$O/$c-dns-names.txt"
    docker diff $c > "$O/docker-diff-$c.txt"
    x $c cat /work/serve-i01.log > "$O/$c-serve-i01.log" 2>/dev/null || rm -f "$O/$c-serve-i01.log"
    x $c cat /work/serve-i02.log > "$O/$c-serve-i02.log" 2>/dev/null || rm -f "$O/$c-serve-i02.log"
  done
  x cli2 cat /work/proxy-i01-n0-defaults.log > "$O/cli2-proxy-i01.log" 2>/dev/null
  x cli2 cat /work/pigeons-fly.log > "$O/cli2-pigeons-fly.log" 2>/dev/null
  docker rm -f srv2 cli2 >/dev/null
  docker network rm hm-g06-inet >/dev/null
}

interop_suite() { # stock Pigeons roost, container-internal only (internal networks + private dev relay)
  docker network create --internal hm-g06-a >/dev/null; docker network create --internal hm-g06-b >/dev/null
  start srv3 hm-g06-a; start cli3 hm-g06-b; start relay3 hm-g06-a hm-g06-b
  x -d relay3 sh -c "exec $T/iroh-relay --dev 2>/work/relay.log"; sleep 2
  setup_srv srv3; setup_cli cli3 srv3; x cli3 $T/g06-patched keygen /work/cli.key >/dev/null
  local RURL=http://relay3:3340 RID
  x -d srv3 sh -c 'echo $$ > /work/tcpdump.pid; exec tcpdump -i any -nn -l -U -w /work/roost.pcap 2>/dev/null'; sleep 1
  x -d srv3 sh -c "exec $T/pigeons roost --relay-url $RURL > /work/roost.out 2> /work/roost.err"
  for _ in $(seq 1 40); do RID=$(x srv3 grep -o '[0-9a-f]\{64\}' /work/roost.out 2>/dev/null | head -1); [ -n "$RID" ] && break; sleep 0.5; done
  res P00-roost-started "$([ -n "$RID" ] && echo 0 || echo 1)" 0 "id_len=${#RID}"
  sshc cli3 p01-probe-client-to-roost g06-patched "--bind none --relay $RURL --lookup none --peer $RID --peer-relay $RURL" 'echo ok-roost'
  res P01-probe-client-to-pigeons-roost "$RC" "$MS" "$(cat "$O/p01-probe-client-to-roost.out")"
  local t0; t0=$(now)
  x cli3 env -u SSH_AUTH_SOCK sh -c "timeout 40 ssh -F /work/ssh_config -o IdentityFile=none -o IdentityFile=/work/id -o IdentitiesOnly=yes -o IdentityAgent=none -o CertificateFile=none -o UserKnownHostsFile=/work/known_hosts -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o HostKeyAlias=hm-dest-1 -o 'ProxyCommand=$T/pigeons fly --stdio --relay-url $RURL $RID 2>>/work/fly.log' hm@dest-1 'echo ok-fly'" > "$O/p02.out" 2> "$O/p02.err"
  res P02-pigeons-fly-to-roost-no-lookup "$?" "$(( $(now) - t0 ))" "$(cat "$O/p02.out")"
  sleep 1; x srv3 sh -c 'kill "$(cat /work/tcpdump.pid)"'; sleep 1
  x srv3 sh -c 'tcpdump -nn -r /work/roost.pcap port 53 2>/dev/null' | grep -oE '(A|AAAA|TXT|HTTPS)\? [A-Za-z0-9._-]+' | sort | uniq -c > "$O/srv3-roost-dns-names.txt"
  docker diff srv3 > "$O/docker-diff-srv3.txt"; x srv3 cat /work/roost.err > "$O/srv3-roost.err"; x cli3 cat /work/fly.log > "$O/cli3-fly.log"
  x cli3 cat /work/proxy-p01-probe-client-to-roost.log > "$O/cli3-proxy-p01.log"
  docker rm -f srv3 cli3 relay3 >/dev/null; docker network rm hm-g06-a hm-g06-b >/dev/null
}

case "$MODE" in
  local) local_suite ;;
  inet) inet_suite ;;
  interop) interop_suite ;;
  all) local_suite; inet_suite ;;
esac
