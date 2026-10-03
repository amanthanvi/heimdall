#!/bin/bash
# Build the fixture image, generate per-run key material, start all fixture containers.
# Containers only. Every published port is bound to 127.0.0.1. Idempotent refusal if already up.
set -eu
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
need_docker

if [ -n "$(fixture_containers)" ] || docker network inspect "$NET_EDGE" >/dev/null 2>&1 \
   || docker network inspect "$NET_INT" >/dev/null 2>&1; then
  die "fixture resources already exist; run reset.sh (keep keys) or down.sh first"
fi
trap 'rc=$?; [ $rc -ne 0 ] && echo "up.sh FAILED (exit $rc); run down.sh to clean partial state" >&2; exit $rc' EXIT

umask 077
mkdir -p "$RUNTIME"; chmod 700 "$RUNTIME"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"

# --- base image pinned by digest ------------------------------------------------------
if docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then BASE_PREEXISTING=1; else BASE_PREEXISTING=0; fi
log "pulling base $BASE_IMAGE (preexisting=$BASE_PREEXISTING)"
docker pull "$BASE_IMAGE" 2>&1 | sed 's/^/  /'
BASE_ID="$(docker image inspect "$BASE_IMAGE" --format '{{.Id}}')"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then die "image $IMAGE already exists; run down.sh"; fi

# --- build (context excludes runtime/ so no key material enters the build) -------------
CTX="$(mktemp -d "${TMPDIR:-/tmp}/hm-m00t03-ctx.XXXXXX")"
cp "$FIX_DIR/Dockerfile" "$FIX_DIR/entrypoint.sh" "$CTX/"
log "building $IMAGE"
docker build --label "${LABEL_KEY}=${LABEL_VAL}" -t "$IMAGE" "$CTX" 2>&1 | sed 's/^/  /' ; [ "${PIPESTATUS[0]}" -eq 0 ] || die "docker build failed"
rm -rf "$CTX"
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
cat >"$RUNTIME/state.env" <<EOS
RUN_ID=$RUN_ID
BASE_PREEXISTING=$BASE_PREEXISTING
BASE_ID=$BASE_ID
IMAGE_ID=$IMAGE_ID
EOS

# --- per-run key material (never committed; runtime/ is gitignored) -------------------
log "generating per-run keys, CA and host keys in $RUNTIME"
mkdir -p "$RUNTIME/keys" "$RUNTIME/hostkeys" "$RUNTIME/containers" "$RUNTIME/seed"
gen() { "$SSH_KEYGEN" -q -t ed25519 -N '' -C "$2" -f "$1"; }
K="$RUNTIME/keys"
gen "$K/user_fixed"   "hm-fixture-fixed-user-$RUN_ID"
gen "$K/user_enroll"  "hm-fixture-enroll-working-path-$RUN_ID"
gen "$K/user_marker"  "heimdall-m00-marker"
gen "$K/user_cert"    "hm-fixture-cert-user-$RUN_ID"
gen "$K/user_bastion" "hm-fixture-bastion-user-$RUN_ID"
gen "$K/user_final"   "hm-fixture-final-user-$RUN_ID"
gen "$K/user_ca"       "hm-fixture-user-ca-$RUN_ID"
gen "$K/user_ca_rogue" "hm-fixture-ROGUE-ca-$RUN_ID"
for n in 1 2 3; do gen "$RUNTIME/seed/unrelated_$n" "unrelated-$n-$RUN_ID"; dispose_file "$RUNTIME/seed/unrelated_$n"; done
for role in $ROLES; do
  mkdir -p "$RUNTIME/hostkeys/$role"
  "$SSH_KEYGEN" -q -t ed25519 -N '' -C "hm-hostkey-$role-$RUN_ID" -f "$RUNTIME/hostkeys/$role/ssh_host_ed25519_key"
done
mkdir -p "$RUNTIME/hostkeys/swap"
"$SSH_KEYGEN" -q -t ed25519 -N '' -C "hm-hostkey-SWAP-$RUN_ID" -f "$RUNTIME/hostkeys/swap/ssh_host_ed25519_key"

# Account-enrollable seed: unrelated keys, options, comments (UTF-8) that must survive edits.
U1="$(cat "$RUNTIME/seed/unrelated_1.pub")"; U2="$(cat "$RUNTIME/seed/unrelated_2.pub")"; U3="$(cat "$RUNTIME/seed/unrelated_3.pub")"
{
  printf '# Hand-maintained by the account owner. Do not reorder. (caf\xc3\xa9 \xc3\xbc\xc3\xb1\xc3\xaf)\n'
  printf 'command="/bin/echo restricted",no-pty,no-port-forwarding %s\n' "$U1"
  printf '\n'
  printf '# options and CA entry below belong to someone else\n'
  printf 'from="192.0.2.0/24",no-agent-forwarding %s\n' "$U2"
  printf 'cert-authority,principals="ops" %s\n' "$U3"
  printf '# existing working path used by the owner\n'
  cat "$K/user_enroll.pub"
  printf '# end of file\n'
} >"$RUNTIME/seed/enroll_authorized_keys"
shasum -a 256 "$RUNTIME/seed/enroll_authorized_keys" | awk '{print $1}' >"$RUNTIME/seed/enroll_authorized_keys.sha256"

# --- stage per-role directories (copied into containers with docker cp) ---------------
sshd_config_for() {   # role account keys_mode
  local role="$1" acct="$2" mode="$3"
  cat <<EOC
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
LogLevel VERBOSE
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PubkeyAuthentication yes
StrictModes yes
AllowUsers $acct
AllowAgentForwarding no
X11Forwarding no
PermitUserEnvironment no
PrintMotd no
# Fixture only: OpenSSH >= 9.8 PerSourcePenalties drops later connections from the (single, shared
# docker-gateway) source address after repeated failed auths, which made negative tests flaky.
PerSourcePenalties no
EOC
  case "$mode" in
    root)    echo "AuthorizedKeysFile /etc/ssh/authorized_keys.d/%u" ;;
    account) echo "AuthorizedKeysFile .ssh/authorized_keys" ;;
    ca)      printf 'AuthorizedKeysFile none\nTrustedUserCAKeys /etc/ssh/user_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%%u\n' ;;
  esac
  if [ "$role" = bastion ]; then
    printf 'AllowTcpForwarding yes\nPermitOpen %s-target:22\nPermitTTY no\n' "$PREFIX"
  else
    echo "AllowTcpForwarding no"
  fi
}
for role in $ROLES; do
  d="$RUNTIME/containers/$role"; mkdir -p "$d"
  acct="$(account_of "$role")"; mode="$(keys_mode_of "$role")"
  printf 'ROLE=%s\nACCOUNT=%s\nKEYS_MODE=%s\n' "$role" "$acct" "$mode" >"$d/role.env"
  cp "$RUNTIME/hostkeys/$role/ssh_host_ed25519_key" "$RUNTIME/hostkeys/$role/ssh_host_ed25519_key.pub" "$d/"
  sshd_config_for "$role" "$acct" "$mode" >"$d/sshd_config"
  case "$role" in
    fixed)   cp "$K/user_fixed.pub"   "$d/authorized_keys" ;;
    enroll)  cp "$RUNTIME/seed/enroll_authorized_keys" "$d/authorized_keys" ;;
    bastion) cp "$K/user_bastion.pub" "$d/authorized_keys" ;;
    target)  cp "$K/user_final.pub"   "$d/authorized_keys" ;;
    ca1) cp "$K/user_ca.pub" "$d/user_ca.pub"; echo "p-host1" >"$d/principals" ;;
    ca2) cp "$K/user_ca.pub" "$d/user_ca.pub"; echo "p-host2" >"$d/principals" ;;
  esac
done

# --- start ---------------------------------------------------------------------------
create_networks
for role in $ROLES; do log "starting $(cname "$role")"; start_role "$role"; done
for role in $ROLES; do [ "$role" = target ] && continue; wait_ready "$role" || die "$role did not become ready"; done
wait_target_ready || die "target did not become ready on the internal network"
record_ports
write_client_config

# --- observed versions ----------------------------------------------------------------
{
  echo "recorded_at=$(ts)"
  echo "docker_server=$(docker version --format '{{.Server.Version}}')"
  echo "base_image=$BASE_IMAGE"
  echo "base_image_id=$BASE_ID"
  echo "base_preexisting=$BASE_PREEXISTING"
  echo "fixture_image_id=$IMAGE_ID"
  echo "openssh_server_pkg=$(docker exec "$(cname fixed)" dpkg-query -W -f='${Package} ${Version}' openssh-server)"
  echo "sshd_version_banner=$(docker run --rm --entrypoint /usr/sbin/sshd --cap-drop ALL "$IMAGE" -V 2>&1 | head -1 || true)"
  echo "host_ssh=$("$SSH" -V 2>&1)"
  echo "host_ssh_path=$SSH"
} >"$RUNTIME/versions.txt"
log "up complete (run $RUN_ID). Ports (loopback only):"; sed 's/^/  /' "$RUNTIME/ports.env"
log "client config: $RUNTIME/ssh_config  (use: /usr/bin/ssh -F runtime/ssh_config <alias>)"
