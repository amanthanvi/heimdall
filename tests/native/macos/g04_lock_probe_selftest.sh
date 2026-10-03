#!/bin/bash
# Self-test for g04_lock_probe.sh --fixture-runtime (fresh SSH login sampling), without the
# M00-T03 fixture. Starts two disposable sshd containers that mirror the fixture's ca1/ca2
# roles (TrustedUserCAKeys + AuthorizedPrincipalsFile p-host1 / p-host2, account "cert"),
# published on 127.0.0.1 ephemeral ports only, writes a fixture-shaped runtime dir in a temp
# dir OUTSIDE the repository (it holds a disposable CA private key), runs the probe in smoke
# mode against it, then removes the containers, the self-test image and the temp dir.
#
# Requires Docker. Base image pinned by digest (same as tests/fixtures/ssh/Dockerfile);
# openssh-server floats with the Debian archive at build time and is recorded at run time.
# Never touches ~/.ssh, the caller's agent, or any keychain. The probe it runs creates and
# deletes its own disposable keychain and dedicated agent.
#
# Usage: g04_lock_probe_selftest.sh [--record FILE] [--out-dir DIR]   (passed to the probe)
set -u
umask 077
export LC_ALL=C
SSH_KEYGEN=/usr/bin/ssh-keygen
unset SSH_AUTH_SOCK SSH_AGENT_PID
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
PROBE="$SCRIPT_DIR/g04_lock_probe.sh"
BASE="debian@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1"
RUN_ID=$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')
LABEL="heimdall.g04.selftest=$RUN_ID"
IMAGE="heimdall-g04-selftest-sshd:$RUN_ID"
T=""; C1=""; C2=""; IMAGE_BUILT=0

log() { printf '%s selftest: %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
teardown() {
  local c n
  for c in "$C1" "$C2"; do [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1; done
  [ "$IMAGE_BUILT" -eq 1 ] && docker image rm "$IMAGE" >/dev/null 2>&1
  n=$(docker ps -a --filter "label=$LABEL" --format '{{.ID}}' 2>/dev/null | wc -l | tr -d ' ')
  log "teardown: containers_remaining=$n image_remaining=$(docker image ls -q "$IMAGE" 2>/dev/null | wc -l | tr -d ' ')"
  if [ -n "$T" ] && [ -d "$T" ]; then rm -rf "$T"; log "teardown: temp_dir_remaining=$([ -e "$T" ] && echo 1 || echo 0)"; fi
}
trap teardown EXIT
trap 'log "interrupted"; exit 130' INT TERM HUP

command -v docker >/dev/null 2>&1 || { log "docker not found"; exit 3; }
docker info >/dev/null 2>&1 || { log "docker daemon not reachable"; exit 3; }
[ -x "$PROBE" ] || { log "probe not executable: $PROBE"; exit 3; }

T=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-g04-selftest.XXXXXXXX"); chmod 700 "$T"
R="$T/runtime"; mkdir -p "$R/keys" "$T/ca1" "$T/ca2"
"$SSH_KEYGEN" -q -t ed25519 -N '' -C "hm-g04-selftest-user-ca-$RUN_ID" -f "$R/keys/user_ca" || exit 3
for role in ca1 ca2; do
  "$SSH_KEYGEN" -q -t ed25519 -N '' -C "hm-g04-selftest-host-$role-$RUN_ID" -f "$T/$role/ssh_host_ed25519_key" || exit 3
  cp "$R/keys/user_ca.pub" "$T/$role/user_ca.pub"
  cat > "$T/$role/sshd_config" <<'EOF'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AuthorizedKeysFile none
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
PerSourcePenalties no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
LogLevel VERBOSE
EOF
done
echo p-host1 > "$T/ca1/principals"; echo p-host2 > "$T/ca2/principals"

log "building self-test image from pinned base (apt-get install openssh-server; network)"
docker build -q --label "$LABEL" -t "$IMAGE" - >/dev/null <<EOF || { log "docker build failed"; exit 3; }
FROM $BASE
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \\
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /selftest \\
 && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \\
 && useradd --create-home --shell /bin/sh cert && usermod -p '*' cert \\
 && printf '%s\\n' '#!/bin/sh' 'set -eu' \\
    'install -m 0600 /selftest/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key' \\
    'install -m 0644 /selftest/user_ca.pub /etc/ssh/user_ca.pub' \\
    'install -d -m 0755 /etc/ssh/principals' \\
    'install -m 0644 /selftest/principals /etc/ssh/principals/cert' \\
    'install -m 0644 /selftest/sshd_config /etc/ssh/sshd_config_selftest' \\
    'exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config_selftest' > /usr/local/bin/selftest-entrypoint \\
 && chmod 0755 /usr/local/bin/selftest-entrypoint
ENTRYPOINT ["/usr/local/bin/selftest-entrypoint"]
EOF
IMAGE_BUILT=1
log "server: $(docker run --rm --cap-drop ALL --entrypoint /usr/sbin/sshd "$IMAGE" -V 2>&1 | head -1)"

start_role() {  # role -> echoes container id
  local role=$1 cid
  cid=$(docker create --label "$LABEL" --name "hm-g04-selftest-$role-$RUN_ID" \
    --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
    --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT --cap-add KILL \
    --security-opt no-new-privileges --pids-limit 128 --memory 128m \
    -p 127.0.0.1::22 "$IMAGE") || return 1
  docker cp "$T/$role/." "$cid:/selftest/" >/dev/null || return 1
  docker start "$cid" >/dev/null || return 1
  printf '%s' "$cid"
}
C1=$(start_role ca1) || { log "ca1 start failed"; exit 3; }
C2=$(start_role ca2) || { log "ca2 start failed"; exit 3; }
port_of() { docker port "$1" 22/tcp | sed -n 's/^127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p' | head -1; }
P1=$(port_of "$C1"); P2=$(port_of "$C2")
[ -n "$P1" ] && [ -n "$P2" ] || { log "containers not published on 127.0.0.1 only"; exit 3; }
printf 'PORT_ca1=%s\nPORT_ca2=%s\n' "$P1" "$P2" > "$R/ports.env"
printf 'hm-ca1 %s\n' "$(awk '{print $1" "$2}' "$T/ca1/ssh_host_ed25519_key.pub")" > "$R/known_hosts"
printf 'hm-ca2 %s\n' "$(awk '{print $1" "$2}' "$T/ca2/ssh_host_ed25519_key.pub")" >> "$R/known_hosts"
for p in "$P1" "$P2"; do
  i=0; until /usr/bin/nc -z 127.0.0.1 "$p" >/dev/null 2>&1 || [ $i -ge 30 ]; do sleep 1; i=$((i+1)); done
done
log "sshd containers up on 127.0.0.1 (ports recorded in temp runtime dir)"

"$PROBE" --mode smoke --interval 2 --smoke-samples 5 --fixture-runtime "$R" "$@"
rc=$?
log "server-side accepted certificate logins on ca1: $(docker logs "$C1" 2>&1 | grep -c 'Accepted publickey for cert')"
log "server-side ca2 principal rejections: $(docker logs "$C2" 2>&1 | grep -c -i 'not in principal\|not permitted\|principal')"
log "probe exit=$rc"
exit "$rc"
