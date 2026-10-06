#!/bin/bash
# usage: wrun.sh <pwsh|ps51> <args...>   (runs from /mnt/c so cwd is a Windows path)
T=M00-T04-G03-native-windows
W=$(cat ~/hm-m00/$T/winscratch.path)
cd "$W" || exit 99
which=$1; shift
if [ "$which" = pwsh ]; then exe="/mnt/c/Program Files/PowerShell/7/pwsh.exe"; else exe=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe; fi
"$exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass "$@" < /dev/null
