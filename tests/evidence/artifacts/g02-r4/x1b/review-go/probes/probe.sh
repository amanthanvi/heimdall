#!/bin/bash
# usage: probe.sh <outname>  (WSL; task M00-T05-x1b-review-go)
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" </dev/null 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1b-review-go"
WD=$(wslpath -w "$D")
cp ~/hm-m00/M00-T05-x1b-review-go/PipeSrv.ps1 ~/hm-m00/M00-T05-x1b-review-go/Probe-Review.ps1 "$D/tools/"
rm -rf "$D/probe"
cd /mnt/c && "/mnt/c/Program Files/PowerShell/7/pwsh.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$WD\\tools\\Probe-Review.ps1" -Root "$WD" -Out "$WD\\out\\$1.jsonl" </dev/null
echo "exit=$?"
