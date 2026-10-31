#!/bin/bash
# usage: inventory.sh LABEL TARGET_NAME
# wsl --version / -l -v and side-effect counters for TARGET_NAME (counts only; no owner content printed).
set -u
. "$(dirname "$0")/lib.sh"
LABEL=$1 NAME=$2
L=$LOG/inventory-$LABEL.txt; : > "$L"
note "$L" "inventory $LABEL"
step "$L" -- wslx --version
step "$L" -- wslx -l -v
wslx -l -v > "$S/inv/list.$LABEL.txt" 2>&1
step "$L" -- psx -File "$(wslpath -w "$W/scripts/sidefx.ps1")" -Name "$NAME" -Tarball "$(wslpath -w "$W/rootfs/$TARBALL_NAME")"
