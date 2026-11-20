#!/bin/bash
# Disposable G07 probe (M06 design unit). Runs on a Linux runner host inside one scratch directory
# that the driver (drive.sh) created. Everything here is fixture material generated per run:
# two unprivileged loopback sshds (a destination and the runner host's management sshd), fixture
# keys and agents. Nothing reads or changes ~/.ssh, the system sshd, the owner's agent or any
# service. Every ssh below runs with SSH_AUTH_SOCK unset and the fixture options of AGENTS.md; where
# a fixture agent is the point of the test, IdentityAgent names that fixture socket explicitly.
#   probe.sh readout | setup | roles | runner-prep | runner-start | status | cleanup
set -u
unset SSH_AUTH_SOCK
D=$(cd "$(dirname "$0")" && pwd)
cd "$D" || exit 1
U=$(id -un)
now() { date +%s; }
port_free() { ! ss -ltnH "sport = :$1" | grep -q .; }
pick_port() { local p; for _ in $(seq 1 50); do p=$((40000 + RANDOM % 20000)); port_free $p && { echo $p; return; }; done; return 1; }
SSHF() { # fixture ssh; caller adds identity/agent/forward options
  env -u SSH_AUTH_SOCK ssh -F "$D/ssh_config" -o IdentityFile=none -o IdentitiesOnly=yes -o CertificateFile=none \
    -o UserKnownHostsFile="$D/known_hosts" -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none \
    -o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o ConnectTimeout=10 "$@"
}
res() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" | tee -a "$D/results.tsv"; }

readout() { # read-only host facts, nonsecret fields only
  echo "openssh=$(ssh -V 2>&1)"
  echo "kernel=$(uname -sr) arch=$(uname -m)"
  echo "linger=$(loginctl show-user "$U" -p Linger --value 2>/dev/null)"
  echo "kill_user_processes=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses 2>/dev/null)"
  echo "set_self_linger_policy=$(pkaction --action-id org.freedesktop.login1.set-self-linger --verbose 2>/dev/null | grep -E 'implicit (any|inactive|active)' | tr -s ' ' | tr '\n' ';')"
  echo "user_manager=$(systemctl --user is-system-running 2>&1 | head -1)"
  echo "sshd_acceptenv=$(grep -hiE '^\s*AcceptEnv' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr -s ' ' | tr '\n' ';')"
  echo "time_sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
  echo "secret_service=$(busctl --user list 2>/dev/null | grep -c org.freedesktop.secrets)"
  echo "session_type=$(loginctl show-session "${XDG_SESSION_ID:-none}" -p Type --value 2>/dev/null)"
}

sshd_conf() { # name port authorized_keys
  cat > "$D/sshd-$1.conf" <<EOF
ListenAddress 127.0.0.1:$2
HostKey $D/hk-$1
PidFile $D/sshd-$1.pid
AuthorizedKeysFile $D/$3
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
AllowUsers $U
AcceptEnv LANG LC_*
AllowAgentForwarding yes
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
PermitTTY yes
PermitUserRC no
LogLevel VERBOSE
EOF
}

setup() {
  umask 077
  for k in hk-dest hk-run kc_login k_owner k_viewer k_expired k_invited kf kfwd kr; do ssh-keygen -q -t ed25519 -N '' -C "hm-g07-fixture-$k" -f "$D/$k"; done
  : > "$D/ssh_config"
  PD=$(pick_port); PR=$(pick_port); echo "PD=$PD PR=$PR" > "$D/ports"
  printf '[127.0.0.1]:%s %s\n[127.0.0.1]:%s %s\n' "$PD" "$(cut -d' ' -f1,2 hk-dest.pub)" "$PR" "$(cut -d' ' -f1,2 hk-run.pub)" > "$D/known_hosts"
  # management bridge stand-in: authority comes only from argv set by sshd's forced command
  cat > "$D/bridge.sh" <<EOF
#!/bin/sh
cid="\$1"; op=\$(printf '%s' "\${SSH_ORIGINAL_COMMAND:-}" | cut -d' ' -f1)
role=\$(awk -v c="\$cid" '\$1==c{print \$2}' "$D/roles.tsv")
if tty -s; then t=yes; else t=no; fi
printf 'client=%s role=%s op=%s original="%s" tty=%s agent=%s heimdall_home=%s hm_client=%s\n' "\$cid" "\$role" "\$op" "\${SSH_ORIGINAL_COMMAND:-}" "\$t" "\${SSH_AUTH_SOCK:+set}" "\${HEIMDALL_HOME:-unset}" "\${HM_CLIENT:-unset}"
case "\$role:\$op" in
  owner:status|owner:approve|owner:enroll|viewer:status) echo allowed; exit 0 ;;
  *:status|*:approve|*:enroll) echo forbidden; exit 77 ;;
  *) echo unknown-op; exit 64 ;;
esac
EOF
  chmod 700 "$D/bridge.sh"
  printf 'cl_owner owner\ncl_viewer viewer\ncl_expired viewer\ncl_invited viewer\n' > "$D/roles.tsv"
  local fut; fut=$(date -u -d '+1 day' +%Y%m%d%H%M%S)
  {
    echo "restrict,command=\"$D/bridge.sh cl_owner\" $(cat k_owner.pub)"
    echo "restrict,command=\"$D/bridge.sh cl_viewer\" $(cat k_viewer.pub)"
    echo "restrict,expiry-time=\"20260101000000Z\",command=\"$D/bridge.sh cl_expired\" $(cat k_expired.pub)"
    echo "restrict,expiry-time=\"${fut}Z\",command=\"$D/bridge.sh cl_invited\" $(cat k_invited.pub)"
    echo "$(cat kc_login.pub)"
  } > "$D/ak_run"
  # destination: the managed recipe's CA line (CA public key arrives in runner-prep) plus a fixed key
  echo "$(cat kf.pub)" > "$D/ak_dest"; echo "$(cat kfwd.pub)" >> "$D/ak_dest"
  sshd_conf dest "$PD" ak_dest; sshd_conf run "$PR" ak_run
  /usr/sbin/sshd -f "$D/sshd-dest.conf" -E "$D/sshd-dest.log" && /usr/sbin/sshd -f "$D/sshd-run.conf" -E "$D/sshd-run.log"
  echo "setup sshd_rc=$? PD=$PD PR=$PR"
}

mgmt() { # key extra-args... -- remote command
  local k=$1; shift
  SSHF -o IdentityAgent=none -o IdentityFile="$D/$k" -p "$PR" "$@"
}

roles() {
  . "$D/ports"
  local o rc
  o=$(mgmt k_owner "$U@127.0.0.1" status 2>&1); rc=$?; res R1-owner-status $rc "$(echo "$o" | tr '\n' ' ')"
  o=$(mgmt k_owner "$U@127.0.0.1" approve grant-1 2>&1); rc=$?; res R1-owner-approve $rc "$(echo "$o" | tr '\n' ' ')"
  o=$(mgmt k_viewer "$U@127.0.0.1" status 2>&1); rc=$?; res R2-viewer-status $rc "$(echo "$o" | tr '\n' ' ')"
  o=$(mgmt k_viewer "$U@127.0.0.1" approve grant-1 2>&1); rc=$?; res R2-viewer-approve-wrong-role $rc "$(echo "$o" | tr '\n' ' ')"
  o=$(mgmt k_viewer "$U@127.0.0.1" 'id; echo SHOULD-NOT-RUN' 2>&1); rc=$?; res R3-viewer-shell-command $rc "$(echo "$o" | tr '\n' ' ')"
  o=$(mgmt k_viewer -tt "$U@127.0.0.1" status 2>&1 </dev/null); rc=$?; res R3b-viewer-pty $rc "$(echo "$o" | tr -d '\r' | tr '\n' ' ')"
  o=$(mgmt k_viewer -W "127.0.0.1:$PD" "$U@127.0.0.1" 2>&1 </dev/null); rc=$?; res R4-viewer-stdio-forward-W $rc "$(echo "$o" | tr '\n' ' ' | cut -c1-200)"
  local lp; lp=$(pick_port)
  mgmt k_viewer -o ExitOnForwardFailure=yes -N -R "127.0.0.1:$lp:127.0.0.1:$PD" "$U@127.0.0.1" > "$D/r4b.txt" 2>&1 </dev/null; rc=$?
  res R4b-viewer-remote-forward-R $rc "$(tr '\n' ' ' < "$D/r4b.txt" | cut -c1-200)"
  python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(4)
while True:
    c,_=s.accept(); c.sendall(b"control-endpoint-reached\n"); c.close()' "$D/ctl.sock" & local lpid=$!
  for k in kc_login:R4c-control-socket-forward-unrestricted-positive-control k_viewer:R4c-control-socket-forward-viewer; do
    rm -f "$D/fwd.sock"; mgmt "${k%%:*}" -N -L "$D/fwd.sock:$D/ctl.sock" "$U@127.0.0.1" 2>"$D/fwd.err" </dev/null & local spid=$!
    for _ in $(seq 1 30); do [ -S "$D/fwd.sock" ] && break; sleep 0.1; done
    o=$(python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1]); print(s.recv(100).decode().strip() or "closed-without-data")' "$D/fwd.sock" 2>&1 | tail -1)
    # $! is the subshell running the mgmt function; its ssh child must go too (the first run left
    # two such clients behind; they were removed by exact PID)
    kill $(pgrep -P "$spid") "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
    res "${k#*:}" 0 "client_read=$o ssh_stderr=$(tr '\n' ' ' < "$D/fwd.err" | cut -c1-140)"
  done
  kill "$lpid"
  ssh-agent -D -a "$D/viewer-agent.sock" > /dev/null 2>&1 & local vpid=$!; sleep 0.3; o=$(env -u SSH_AUTH_SOCK ssh -F "$D/ssh_config" -o IdentityFile=none -o IdentitiesOnly=yes -o CertificateFile=none -o UserKnownHostsFile="$D/known_hosts" -o GlobalKnownHostsFile=/dev/null -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o IdentityAgent=none -o IdentityFile="$D/k_viewer" -o ForwardAgent="$D/viewer-agent.sock" -o SetEnv="HEIMDALL_HOME=/tmp/evil HM_CLIENT=cl_owner" -p "$PR" "$U@127.0.0.1" 'status --client cl_owner' 2>&1); rc=$?
  kill "$vpid"
  res R5-viewer-identity-override-attempts $rc "$(echo "$o" | tr '\n' ' ')"
  o=$(mgmt k_expired "$U@127.0.0.1" status 2>&1); rc=$?; res R6-expired-invitation-key $rc "$(echo "$o" | tr '\n' ' ' | cut -c1-160) sshd_log_expiry_lines=$(grep -ci 'expir' "$D/sshd-run.log")"
  o=$(mgmt k_invited "$U@127.0.0.1" status 2>&1); rc=$?; res R7-unexpired-invitation-key $rc "$(echo "$o" | tr '\n' ' ')"
  grep -v 'cl_viewer"' "$D/ak_run" > "$D/ak_run.new" && mv "$D/ak_run.new" "$D/ak_run"
  o=$(mgmt k_viewer "$U@127.0.0.1" status 2>&1); rc=$?; res R8-viewer-after-line-removed $rc "$(echo "$o" | tr '\n' ' ' | cut -c1-160)"
}

runner_prep() { # receive the controller's CA public key; emit the runner's K_env public key
  cat >> "$D/ak_dest" < /dev/stdin   # one cert-authority line, written by the driver
  cat "$D/kr.pub"
}

runner_start() { # runs inside the controller's session; the controller leaves when this returns
  . "$D/ports"
  # runner's own agent: K_env + certificate, then the private key file is deleted (memory only)
  setsid nohup ssh-agent -D -a "$D/runner-agent.sock" > /dev/null 2>&1 < /dev/null & echo $! > "$D/runner-agent.pid"
  for _ in $(seq 1 20); do [ -S "$D/runner-agent.sock" ] && break; sleep 0.1; done
  SSH_AUTH_SOCK="$D/runner-agent.sock" ssh-add "$D/kr" > /dev/null 2>&1; echo "runner ssh-add rc=$?"
  shred -u "$D/kr" 2>/dev/null || rm -f "$D/kr"
  echo "runner agent identities: $(SSH_AUTH_SOCK="$D/runner-agent.sock" ssh-add -l | awk '{print $NF}' | tr '\n' ' ')"
  setsid nohup "$D/runner.sh" own > /dev/null 2>&1 < /dev/null & echo $! > "$D/runner-own.pid"
  # forwarded-agent negative control: a fixture "controller" agent forwarded into a nested session
  setsid nohup ssh-agent -D -a "$D/ctl-agent.sock" > /dev/null 2>&1 < /dev/null & echo $! > "$D/ctl-agent.pid"
  for _ in $(seq 1 20); do [ -S "$D/ctl-agent.sock" ] && break; sleep 0.1; done
  SSH_AUTH_SOCK="$D/ctl-agent.sock" ssh-add "$D/kfwd" > /dev/null 2>&1
  fwd_session
  echo "controller_departs_at=$(now)" | tee "$D/departed"
}

fwd_session() { # IdentityAgent=none would disable forwarding (observed, OpenSSH 9.6p1), so the fixture agent is named
  . "$D/ports"
  SSHF -o IdentityAgent="$D/ctl-agent.sock" -o IdentityFile="$D/kc_login" -o ForwardAgent="$D/ctl-agent.sock" -p "$PR" "$U@127.0.0.1" \
    "setsid nohup $D/runner.sh fwd > /dev/null 2>&1 < /dev/null & echo \$! > $D/runner-fwd.pid; sleep 12" ; echo "nested session rc=$? ended_at=$(now)" | tee "$D/fwd-session-ended"
}

status() {
  . "$D/ports"
  echo "== processes"; for p in runner-own runner-fwd runner-agent ctl-agent; do
    pid=$(cat "$D/$p.pid" 2>/dev/null); echo "$p pid=$pid alive=$(ps -o comm= -p "$pid" 2>/dev/null || echo no) cgroup=$(cut -d: -f3 /proc/"$pid"/cgroup 2>/dev/null | sed 's/[0-9]\+/N/g')"; done
  echo "== departed: $(cat "$D/departed" 2>/dev/null)"
  for m in own fwd; do echo "== runner-$m.log"; cat "$D/runner-$m.log" 2>/dev/null; done
}

cleanup() { # exact PIDs from our pidfiles, only if the process's arguments name this scratch dir
  for f in runner-own runner-fwd runner-agent ctl-agent sshd-dest sshd-run; do
    pid=$(cat "$D/$f.pid" 2>/dev/null) || continue
    case "$(ps -o args= -p "$pid" 2>/dev/null)" in *"$D"*) kill "$pid" && echo "killed $f $pid";; *) echo "$f $pid not running";; esac
  done
  sleep 1; cd / && rm -rf "$D" && echo "removed scratch"
}

case "${1:-}" in
  readout) readout ;; setup) setup ;; roles) roles ;; runner-prep) runner_prep ;;
  runner-start) runner_start ;; fwd-rerun) rm -f "$D/runner-fwd.log"; fwd_session ;; status) status ;; cleanup) cleanup ;;
  *) echo "usage" >&2; exit 2 ;;
esac
