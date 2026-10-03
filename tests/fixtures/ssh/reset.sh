#!/bin/bash
# Reset the fixtures to their pristine state.
#   reset.sh           recreate all containers from the staged material (keeps keys and host keys;
#                      published loopback ports change, so ssh_config is regenerated)
#   reset.sh --rekey   full teardown (down.sh) and a fresh up.sh with all-new keys
set -eu
D="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$D/lib.sh"
need_docker
if [ "${1:-}" = "--rekey" ]; then "$D/down.sh" && exec "$D/up.sh"; fi
load_state
for c in $(fixture_containers); do docker rm -f "$c" >/dev/null; done
create_networks
for role in $ROLES; do log "recreating $(cname "$role")"; start_role "$role"; done
for role in $ROLES; do [ "$role" = target ] && continue; wait_ready "$role" || die "$role did not become ready"; done
wait_target_ready || die "target did not become ready"
record_ports
write_client_config
log "reset complete; ports:"; sed 's/^/  /' "$RUNTIME/ports.env"
