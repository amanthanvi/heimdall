#!/bin/bash
# Disposable G07 runner stand-in: every 4 s, onward SSH to the fixture destination.
#   runner.sh own   managed pair via the runner's own agent (K_env + controller-issued certificate)
#                   and a fixed-auth pair via the runner's own key file
#   runner.sh fwd   the same destination via whatever agent the starting session forwarded
# Stops by itself after 45 iterations. Logs one line per attempt with the runner's own clock.
set -u
D=$(cd "$(dirname "$0")" && pwd); . "$D/ports"; MODE=$1; LOG="$D/runner-$MODE.log"
agent=${SSH_AUTH_SOCK:-}
case "$agent" in
  /tmp/ssh-*/agent.*) dep="forwarded_agent_from_ssh_session(controller_dependency)" ;;
  "") dep="none" ;;
  *) dep="local_socket" ;;
esac
echo "$(date +%s) start mode=$MODE inherited_agent=$dep in_ssh_session=${SSH_CONNECTION:+yes}" >> "$LOG"
try() { # label agent idfile [certfile]
  local o rc
  o=$(env -u SSH_AUTH_SOCK ssh -F "$D/ssh_config" -o IdentitiesOnly=yes -o IdentityAgent="$2" -o IdentityFile="$3" \
      ${4:+-o CertificateFile=$4} -o UserKnownHostsFile="$D/known_hosts" -o GlobalKnownHostsFile=/dev/null \
      -o ControlMaster=no -o ControlPath=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 \
      -p "$PD" "$(id -un)@127.0.0.1" true 2>&1); rc=$?
  echo "$(date +%s) $1 rc=$rc $(echo "$o" | tail -1 | cut -c1-90)" >> "$LOG"
}
for _ in $(seq 1 45); do
  if [ "$MODE" = own ]; then
    try managed "$D/runner-agent.sock" "$D/kr.pub" "$D/kr-cert.pub"
    try fixed none "$D/kf"
  else
    try forwarded "${agent:-none}" "$D/kfwd.pub"
  fi
  sleep 4
done
echo "$(date +%s) stop" >> "$LOG"
