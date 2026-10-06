#!/bin/bash
# usage: wsl-tests.sh <label> <test exe relative to root> <proto exe relative to root>
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1b-fix-rust/root"
WD=$(wslpath -w "$D")
cd /mnt/c && /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$WD\\tools\\run-tests.ps1" -Root "$WD" -TestExe "$WD\\${2//\//\\}" -ProtoExe "$WD\\${3//\//\\}" -Label "$1"
echo "exit=$?"
