#!/bin/bash
# usage: rvrun.sh <ps51|ps7> <x1|probes> <outname> [extra args...]   (runs on WSL; review task scratch only)
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1-g02-native-review"
WD=$(wslpath -w "$D")
which=$1; kind=$2; out=$3; shift 3
if [ "$which" = ps7 ]; then PS="/mnt/c/Program Files/PowerShell/7/pwsh.exe"; else PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe; fi
if [ "$kind" = x1 ]; then SCRIPT="$WD\\tools\\Invoke-G02WindowsX1.ps1"; else SCRIPT="$WD\\probes\\Invoke-X1ReviewProbes.ps1"; fi
cd /mnt/c && "$PS" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$SCRIPT" -Root "$WD" -OutDir "$WD\\out\\$out" "$@"
echo "exit=$?"
