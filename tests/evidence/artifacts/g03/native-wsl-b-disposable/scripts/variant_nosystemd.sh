#!/bin/bash
# usage: variant_nosystemd.sh NAME : /tmp facts under the shipped config (systemd=true), then switch the
# disposable distribution to systemd=false (supplementary r3 configuration only) and re-check.
set -u
. "$(dirname "$0")/lib.sh"
NAME=$1
L=$LOG/variant-nosystemd.txt; : > "$L"
note "$L" "shipped configuration (systemd=true)"
step "$L" -- timeout 300 "$WSLEXE" -d "$NAME" --cd / --exec /bin/bash "$W/scripts/target_tmp.sh" < /dev/null
note "$L" "switch own distribution to systemd=false"
step "$L" -- timeout 120 "$WSLEXE" -d "$NAME" -u root --cd / --exec /bin/bash "$W/scripts/target_nosystemd.sh" < /dev/null
step "$L" -- wslx --terminate "$NAME"
step "$L" -- timeout 300 "$WSLEXE" -d "$NAME" --cd / --exec /bin/bash "$W/scripts/target_facts.sh" < /dev/null
step "$L" -- timeout 300 "$WSLEXE" -d "$NAME" --cd / --exec /bin/bash "$W/scripts/target_tmp.sh" < /dev/null
