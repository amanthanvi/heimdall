#!/bin/bash
# usage: winrun.sh <ps51|ps7> <outname> [extra args...]   (runs on WSL; round-4 go fix verification, task M00-T05-x1b-fix-go; derived from x1/windows-96/winrun.sh)
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1b-fix-go"
WD=$(wslpath -w "$D")
which=$1; out=$2; shift 2
if [ "$which" = ps7 ]; then PS="/mnt/c/Program Files/PowerShell/7/pwsh.exe"; else PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe; fi
cd /mnt/c && "$PS" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$WD\\tools\\Invoke-G02WindowsX1.ps1" -Root "$WD" -OutDir "$WD\\out\\$out" "$@"
echo "exit=$?"
