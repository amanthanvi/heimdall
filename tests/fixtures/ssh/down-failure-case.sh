#!/bin/bash
# Fault-injected case for down.sh's failure branch. Run with the fixtures DOWN (after down.sh).
# Injects one fault: a docker network named like a fixture network (hm-m00t03-internal) but WITHOUT the
# fixture label, which down.sh must refuse to touch. Expected: down.sh exits 1, prints
# "CLEANUP INCOMPLETE" and networks_remaining=1 problems=1. The injected network is then removed by its exact
# name (after verifying it is the unlabelled one this script created). Exit 0 iff down.sh failed as expected
# AND the injected network is gone at the end.
set -u
D="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$D/lib.sh"
need_docker
[ -z "$(fixture_containers)" ] && ! docker network inspect "$NET_EDGE" >/dev/null 2>&1 \
  && ! docker network inspect "$NET_INT" >/dev/null 2>&1 && [ ! -d "$RUNTIME" ] \
  || die "fixtures are not down; run down.sh first (this case needs a clean slate)"
docker network create "$NET_INT" >/dev/null || die "could not create the injected network"
lbl="$(docker network inspect "$NET_INT" --format "{{index .Labels \"$LABEL_KEY\"}}")"
[ -z "$lbl" ] || { docker network rm "$NET_INT" >/dev/null; die "injected network unexpectedly labelled"; }
log "injected unlabelled network $NET_INT; running down.sh (expecting failure)"
out="$("$D/down.sh" 2>&1)"; rc=$?
echo "$out" | sed 's/^/  down.sh| /'
echo "down.sh exit=$rc"
# remove the injected network by exact name, only if still unlabelled (i.e. still ours)
if docker network inspect "$NET_INT" >/dev/null 2>&1; then
  lbl="$(docker network inspect "$NET_INT" --format "{{index .Labels \"$LABEL_KEY\"}}")"
  [ -z "$lbl" ] && docker network rm "$NET_INT" >/dev/null && log "removed injected network $NET_INT"
fi
gone=0; docker network inspect "$NET_INT" >/dev/null 2>&1 || gone=1
echo "injected_network_removed=$gone"
if [ "$rc" = 1 ] && echo "$out" | grep -q 'CLEANUP INCOMPLETE' && echo "$out" | grep -q 'networks_remaining=1' && [ "$gone" = 1 ]; then
  echo "DOWN-FAILURE-CASE OK (down.sh reported failure with exit 1, left the foreign network alone)"; exit 0
fi
echo "DOWN-FAILURE-CASE UNEXPECTED" >&2; exit 1
