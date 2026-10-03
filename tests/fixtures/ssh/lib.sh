#!/bin/bash
# Shared helpers for the M00-T03 disposable SSH fixtures. Source, do not execute.
# bash 3.2 compatible (macOS /bin/bash).
#
# Safety: containers only, ports bound to 127.0.0.1, never reads ~/.ssh, never uses
# the owner's SSH agent. All ssh invocations go through hm_ssh (-F runtime/ssh_config).

FIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$FIX_DIR/runtime"
PREFIX="hm-m00t03"
LABEL_KEY="heimdall.fixture"
LABEL_VAL="m00-t03"
IMAGE="heimdall-m00-t03-sshd:local"
BASE_IMAGE="debian@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1"
NET_EDGE="${PREFIX}-edge"          # normal bridge; only bastion + loopback-published fixtures
NET_INT="${PREFIX}-internal"       # --internal: bastion + final target only
ROLES="fixed enroll ca1 ca2 bastion target"

SSH=/usr/bin/ssh
SSH_KEYGEN=/usr/bin/ssh-keygen

# Never inherit the owner's agent or askpass helpers.
unset SSH_AUTH_SOCK SSH_ASKPASS SSH_ASKPASS_REQUIRE SSH_AGENT_PID DISPLAY

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '[%s] %s\n' "$(ts)" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$(ts)" "$*" >&2; exit 1; }

cname() { printf '%s-%s' "$PREFIX" "$1"; }

account_of() {
  case "$1" in
    fixed) echo fixed ;; enroll) echo enroll ;; ca1|ca2) echo cert ;;
    bastion) echo jump ;; target) echo final ;; *) die "unknown role $1" ;;
  esac
}
keys_mode_of() {
  case "$1" in
    fixed|bastion|target) echo root ;; enroll) echo account ;; ca1|ca2) echo ca ;;
  esac
}

need_docker() {
  docker info >/dev/null 2>&1 || die "docker daemon unavailable"
}

fixture_containers() {   # names of every container carrying our label (running or not)
  docker ps -a --filter "label=${LABEL_KEY}=${LABEL_VAL}" --format '{{.Names}}'
}

load_state() {
  [ -f "$RUNTIME/state.env" ] || die "no runtime state; run up.sh first"
  # shellcheck disable=SC1090,SC1091
  . "$RUNTIME/state.env"
}
load_ports() {
  [ -f "$RUNTIME/ports.env" ] || die "no ports.env; run up.sh first"
  # shellcheck disable=SC1090,SC1091
  . "$RUNTIME/ports.env"
}
port_of() { local v="PORT_$1"; echo "${!v}"; }

# ssh through the generated fixture config only. IdentityAgent none, IdentitiesOnly yes,
# StrictHostKeyChecking yes and the fixture known_hosts all live in runtime/ssh_config.
hm_ssh() {
  "$SSH" -F "$RUNTIME/ssh_config" "$@"
}

# Best-effort disposal of private material. Overwrite then unlink. NOTE: on APFS/SSD
# copy-on-write storage overwrite is not a guarantee; keys are disposable, trusted only by
# containers that are destroyed, and valid only inside this fixture.
dispose_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -n 1 -z -u "$f" 2>/dev/null || rm -f "$f"
  else
    local sz; sz=$(wc -c <"$f" | tr -d ' ')
    dd if=/dev/urandom of="$f" bs=1 count="$sz" conv=notrunc 2>/dev/null || true
    rm -f "$f"
  fi
}

# --- container lifecycle (used by up.sh and reset.sh) -------------------------------------

create_networks() {
  docker network inspect "$NET_EDGE" >/dev/null 2>&1 \
    || docker network create --label "${LABEL_KEY}=${LABEL_VAL}" "$NET_EDGE" >/dev/null
  docker network inspect "$NET_INT" >/dev/null 2>&1 \
    || docker network create --internal --label "${LABEL_KEY}=${LABEL_VAL}" "$NET_INT" >/dev/null
}

start_role() {   # create, populate, start one role container
  local role="$1" c; c="$(cname "$role")"
  local pub=() net
  case "$role" in
    target) net="$NET_INT" ;;           # internal only, nothing published
    bastion) net="$NET_EDGE"; pub=(-p 127.0.0.1::22) ;;
    *) net="$NET_EDGE"; pub=(-p 127.0.0.1::22) ;;
  esac
  docker create --name "$c" --hostname "$c" --init \
    --label "${LABEL_KEY}=${LABEL_VAL}" --label "heimdall.fixture.role=$role" \
    --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
    --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT --cap-add KILL \
    --security-opt no-new-privileges --pids-limit 256 --memory 256m \
    --network "$net" --network-alias "$c" ${pub[@]+"${pub[@]}"} \
    "$IMAGE" >/dev/null
  if [ "$role" = bastion ]; then docker network connect --alias "$c" "$NET_INT" "$c"; fi
  docker cp "$RUNTIME/containers/$role/." "$c:/fixture/" >/dev/null
  docker start "$c" >/dev/null
}

# target must be reachable under the DNS name hm-target on the internal net
wait_ready() {   # wait for an sshd banner on the published loopback port
  local role="$1" port i
  port="$(docker port "$(cname "$role")" 22/tcp | head -1 | sed 's/.*://')"
  for i in $(seq 1 60); do
    if exec 3<>"/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
      local banner; IFS= read -r -t 3 banner <&3 || true
      exec 3<&- 3>&-
      case "$banner" in SSH-2.0-*) return 0 ;; esac
    fi
    sleep 0.5
  done
  return 1
}

wait_target_ready() {  # target has no host port: probe from the bastion over the internal net
  local i
  for i in $(seq 1 60); do
    if docker exec "$(cname bastion)" bash -c 'exec 3<>/dev/tcp/hm-m00t03-target/22 && read -r -t 3 b <&3 && [[ $b == SSH-2.0-* ]]' 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

record_ports() {
  : >"$RUNTIME/ports.env"
  local role binding
  for role in $ROLES; do
    [ "$role" = target ] && continue
    binding="$(docker port "$(cname "$role")" 22/tcp | head -1)"
    case "$binding" in
      127.0.0.1:*) ;;
      *) die "role $role published on unexpected address: $binding" ;;
    esac
    printf 'PORT_%s=%s\n' "$role" "${binding##*:}" >>"$RUNTIME/ports.env"
  done
}

# Generates runtime/ssh_config and runtime/known_hosts from the staged host public keys.
write_client_config() {
  load_ports
  local k="$RUNTIME/keys"
  : >"$RUNTIME/known_hosts"
  local role alias
  for role in $ROLES; do
    alias="hm-$role"
    printf '%s %s\n' "$alias" "$(awk '{print $1" "$2}' "$RUNTIME/hostkeys/$role/ssh_host_ed25519_key.pub")" >>"$RUNTIME/known_hosts"
  done
  : >"$RUNTIME/known_hosts.empty"
  cat >"$RUNTIME/ssh_config" <<EOF
# GENERATED by up.sh/reset.sh. Disposable. Host trust is explicit (known_hosts generated
# from the host public keys created for this run); never accept-new, never "no".
Host fixed-auth
  HostName 127.0.0.1
  Port $PORT_fixed
  User fixed
  IdentityFile "$k/user_fixed"
  HostKeyAlias hm-fixed

Host fixed-wrongkey
  HostName 127.0.0.1
  Port $PORT_fixed
  User fixed
  IdentityFile "$k/user_cert"
  HostKeyAlias hm-fixed

Host enrollable
  HostName 127.0.0.1
  Port $PORT_enroll
  User enroll
  IdentityFile "$k/user_enroll"
  HostKeyAlias hm-enroll

Host enrollable-marker
  HostName 127.0.0.1
  Port $PORT_enroll
  User enroll
  IdentityFile "$k/user_marker"
  HostKeyAlias hm-enroll

Host ca-host1
  HostName 127.0.0.1
  Port $PORT_ca1
  User cert
  IdentityFile "$k/user_cert"
  HostKeyAlias hm-ca1

Host ca-host2
  HostName 127.0.0.1
  Port $PORT_ca2
  User cert
  IdentityFile "$k/user_cert"
  HostKeyAlias hm-ca2

Host bastion
  HostName 127.0.0.1
  Port $PORT_bastion
  User jump
  IdentityFile "$k/user_bastion"
  HostKeyAlias hm-bastion

Host internal-target
  HostName hm-m00t03-target
  User final
  IdentityFile "$k/user_final"
  HostKeyAlias hm-target
  ProxyJump bastion

Host *
  UserKnownHostsFile "$RUNTIME/known_hosts"
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  CheckHostIP no
  VerifyHostKeyDNS no
  UpdateHostKeys no
  IdentitiesOnly yes
  IdentityAgent none
  ForwardAgent no
  ForwardX11 no
  BatchMode yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ControlMaster no
  ControlPath none
  ConnectTimeout 10
  LogLevel ERROR
EOF
  chmod 600 "$RUNTIME/ssh_config"
}
