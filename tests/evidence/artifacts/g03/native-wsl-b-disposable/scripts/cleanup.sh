#!/bin/bash
# usage: cleanup.sh NAME : terminate + unregister THIS distribution only, then inventory "after".
set -u
. "$(dirname "$0")/lib.sh"
NAME=$1
L=$LOG/cleanup.txt; : > "$L"
case "$NAME" in hm-g03b-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) echo "refusing name $NAME" >&2; exit 2 ;; esac
step "$L" -- wslx --terminate "$NAME"
step "$L" -- wslx --unregister "$NAME"
step "$L" -- ls -A "$W/distro"
