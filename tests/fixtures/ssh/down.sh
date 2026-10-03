#!/bin/bash
# Stop and remove everything up.sh created (containers, networks, image) and dispose of the
# runtime key material. Only resources carrying label heimdall.fixture=m00-t03 are touched.
# The pinned base image is removed only if up.sh itself pulled it (state.env BASE_PREEXISTING=0).
set -u
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
need_docker
problems=0

BASE_PREEXISTING=1
[ -f "$RUNTIME/state.env" ] && . "$RUNTIME/state.env"

for c in $(fixture_containers); do
  log "removing container $c"
  docker rm -f "$c" >/dev/null || { log "FAILED to remove $c"; problems=$((problems+1)); }
done
for n in "$NET_EDGE" "$NET_INT"; do
  if docker network inspect "$n" >/dev/null 2>&1; then
    lbl="$(docker network inspect "$n" --format "{{index .Labels \"$LABEL_KEY\"}}")"
    if [ "$lbl" = "$LABEL_VAL" ]; then
      log "removing network $n"; docker network rm "$n" >/dev/null || { log "FAILED to remove $n"; problems=$((problems+1)); }
    else
      log "network $n exists without our label; left alone"; problems=$((problems+1))
    fi
  fi
done
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  lbl="$(docker image inspect "$IMAGE" --format "{{index .Config.Labels \"$LABEL_KEY\"}}")"
  if [ "$lbl" = "$LABEL_VAL" ]; then
    log "removing image $IMAGE"; docker rmi "$IMAGE" >/dev/null || { log "FAILED to remove image"; problems=$((problems+1)); }
  else
    log "image $IMAGE lacks our label; left alone"; problems=$((problems+1))
  fi
fi
if [ "$BASE_PREEXISTING" = 0 ] && docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
  log "removing base image pulled by up.sh"; docker rmi "$BASE_IMAGE" >/dev/null 2>&1 || log "base image not removable (in use elsewhere); left"
fi

# Dispose of private material: every private key (user, CA, rogue CA, host keys, swap key,
# generated certs' keys) is overwritten then unlinked; then the remaining runtime tree is removed.
disposed=0
if [ -d "$RUNTIME" ]; then
  while IFS= read -r f; do dispose_file "$f"; disposed=$((disposed+1)); done < <(
    find "$RUNTIME" -type f \( -name 'user_*' -o -name 'ssh_host_*_key' -o -name '*.key' -o -name 'unrelated_[0-9]' \) ! -name '*.pub' 2>/dev/null)
  rm -rf "$RUNTIME"
fi

remaining_c="$(fixture_containers | wc -l | tr -d ' ')"
remaining_n=0; for n in "$NET_EDGE" "$NET_INT"; do docker network inspect "$n" >/dev/null 2>&1 && remaining_n=$((remaining_n+1)); done
remaining_i=0; docker image inspect "$IMAGE" >/dev/null 2>&1 && remaining_i=1
remaining_k=0; [ -d "$RUNTIME" ] && remaining_k=1

echo "CLEANUP CONFIRMATION $(ts): containers_remaining=$remaining_c networks_remaining=$remaining_n image_remaining=$remaining_i runtime_dir_remaining=$remaining_k private_keys_overwritten_and_removed=$disposed problems=$problems"
if [ "$remaining_c$remaining_n$remaining_i$remaining_k" = "0000" ] && [ "$problems" = 0 ]; then
  echo "CLEANUP CONFIRMED"; exit 0
fi
echo "CLEANUP INCOMPLETE" >&2; exit 1
