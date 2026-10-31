#!/bin/bash
# usage: idle_control.sh NAME LABEL [WATCH_SECONDS]
# Supplementary control for P-B10 (not a harness probe): same polling as probe_idle, but the
# session starts NO background process (/bin/true), so the baseline idle stop time is known.
set -u
. "$(dirname "$0")/lib.sh"
NAME=$1 LABEL=$2 WATCH=${3:-120}
L=$LOG/idle-control-$LABEL.txt; : > "$L"
step "$L" -- wslx --terminate "$NAME"; sleep 3
running "$NAME" && note "$L" "still running after terminate" || note "$L" "not running after terminate"
step "$L" -- "$WSLEXE" -d "$NAME" --cd / --exec /bin/true < /dev/null
i=0; stopped=""
while [ $i -lt "$WATCH" ]; do
  if running "$NAME"; then echo "t+${i}s running" >> "$L"; else echo "t+${i}s stopped" >> "$L"; stopped=$i; break; fi
  sleep 5; i=$((i+5))
done
echo "control_stopped_after_seconds=${stopped:-null} watched_seconds=$WATCH" >> "$L"
