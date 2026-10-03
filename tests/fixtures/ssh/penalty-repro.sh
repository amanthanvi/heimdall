#!/bin/bash
# Deliberate reproduction of OpenSSH PerSourcePenalties (OpenSSH >= 9.8) on DISPOSABLE VARIANTS of the
# `fixed` fixture, to back (or refute) the claim that this is why the fixture sshd sets
# `PerSourcePenalties no`. Needs the fixtures up (run up.sh first). Containers only, loopback only.
#
# Two throwaway containers are started from the fixture image with the `fixed` role material:
#   default : sshd_config WITHOUT the PerSourcePenalties line (OpenSSH default behavior)
#   control : the fixture sshd_config as shipped (PerSourcePenalties no)
# For each: a valid login, N failed authentications (wrong key) from 127.0.0.1 (all arrive from the
# same docker source address), then valid logins again; sshd's own log is excerpted.
# Exit 0 only if: default variant refused at least one valid login after the failures (penalty reproduced)
# AND the control variant never refused one. Otherwise exit 1 (the claim is not reproduced).
# Usage: penalty-repro.sh [FAILED_ATTEMPTS (default 8)] [RECOVERY_POLL_SECONDS (default 60)]
set -u
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
need_docker; load_state; load_ports
N="${1:-8}"; POLL="${2:-60}"
[ -f "$RUNTIME/containers/fixed/sshd_config" ] || die "fixtures not up (run up.sh)"
CREATED=""
cleanup() {
  local c lbl
  for c in $CREATED; do
    lbl="$(docker inspect "$c" --format "{{index .Config.Labels \"$LABEL_KEY\"}}" 2>/dev/null)"
    [ "$lbl" = "$LABEL_VAL" ] && docker rm -f "$c" >/dev/null 2>&1
  done
}
trap cleanup EXIT

echo "== penalty-repro start $(ts) failed_attempts=$N recovery_poll=${POLL}s"
echo "   $(cat "$RUNTIME/versions.txt" | grep -E 'openssh_server_pkg|sshd_version_banner' | tr '\n' ';')"

default_refused=0; control_refused=0; default_recovered="n/a"
for v in default control; do
  c="${PREFIX}-penalty-$v"
  if docker inspect "$c" >/dev/null 2>&1; then die "container $c already exists; remove it (exact name) first"; fi
  d="$RUNTIME/penalty/$v"; rm -rf "$d"; mkdir -p "$d"
  cp -R "$RUNTIME/containers/fixed/." "$d/"
  [ "$v" = default ] && sed -i.bak '/^PerSourcePenalties/d' "$d/sshd_config" && rm -f "$d/sshd_config.bak"
  docker create --name "$c" --hostname "$c" --init \
    --label "${LABEL_KEY}=${LABEL_VAL}" --label "heimdall.fixture.role=penalty-$v" \
    --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
    --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT --cap-add KILL \
    --security-opt no-new-privileges --pids-limit 256 --memory 256m \
    --network "$NET_EDGE" -p 127.0.0.1::22 "$IMAGE" >/dev/null || die "create $c failed"
  CREATED="$CREATED $c"
  docker cp "$d/." "$c:/fixture/" >/dev/null && docker start "$c" >/dev/null || die "start $c failed"
  binding="$(docker port "$c" 22/tcp | head -1)"
  case "$binding" in 127.0.0.1:*) ;; *) die "unexpected published address: $binding" ;; esac
  P="${binding##*:}"
  ready=0; for i in $(seq 1 60); do
    if exec 3<>"/dev/tcp/127.0.0.1/$P" 2>/dev/null; then IFS= read -r -t 3 b <&3 || true; exec 3<&- 3>&-; case "$b" in SSH-2.0-*) ready=1; break;; esac; fi
    sleep 0.5; done
  [ "$ready" = 1 ] || die "$c not ready"
  echo "== variant: $v (container $c, 127.0.0.1:$P)"
  echo "   sshd -T: $(docker exec "$c" /usr/sbin/sshd -T -f /etc/ssh/sshd_config_fixture 2>&1 | grep -i '^persourcepenalties' | tr '\n' ';')"
  one() { hm_ssh -o Port="$P" "$@" 2>&1; }
  out="$(one fixed-auth true)"; rc=$?; echo "   baseline valid login: exit=$rc $(echo $out)"
  for i in $(seq 1 "$N"); do
    out="$(one fixed-wrongkey true)"; rc=$?
    echo "   failed-auth #$i: exit=$rc $(echo $out | cut -c1-110)"
  done
  refused=0
  for i in 1 2 3; do
    out="$(one fixed-auth true)"; rc=$?
    [ $rc -ne 0 ] && refused=$((refused+1))
    echo "   valid login after failures #$i: exit=$rc $(echo $out | cut -c1-140)"
  done
  if [ "$v" = default ]; then
    default_refused=$refused
    if [ "$refused" -gt 0 ]; then
      t0=$(date +%s); default_recovered="no(within ${POLL}s)"
      while [ $(( $(date +%s) - t0 )) -lt "$POLL" ]; do
        sleep 5; one fixed-auth true >/dev/null && { default_recovered="yes after ~$(( $(date +%s) - t0 ))s"; break; }
      done
      echo "   recovery polling (valid login every 5s): $default_recovered"
    fi
  else control_refused=$refused; fi
  echo "   -- sshd log excerpt ($c): lines matching penalty|drop connection|Failed publickey|Connection (closed|reset)"
  docker logs "$c" 2>&1 | grep -iE 'penalty|drop connection|Failed publickey|Connection (closed|reset)|Accepted publickey' | head -40 | sed 's/^/   | /'
  echo "   -- penalty/drop lines in full log: $(docker logs "$c" 2>&1 | grep -ciE 'penalty|drop connection')"
done
echo "== summary: default_valid_logins_refused_after_failures=$default_refused/3 (recovery: $default_recovered) control_refused=$control_refused/3"
if [ "$default_refused" -gt 0 ] && [ "$control_refused" -eq 0 ]; then
  echo "== penalty-repro verdict: REPRODUCED (default sshd refuses valid logins after repeated failed auth from one source; PerSourcePenalties no does not) $(ts)"; exit 0
fi
echo "== penalty-repro verdict: NOT REPRODUCED as hypothesized $(ts)"; exit 1
