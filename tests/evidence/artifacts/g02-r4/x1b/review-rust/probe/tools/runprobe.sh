#!/bin/bash
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1b-review-rust"
mkdir -p "$D/probe"; cp ~/hm-m00/M00-T05-x1b-review-rust/probe/*.ps1 "$D/probe/"
WD=$(wslpath -w "$D")
cd /mnt/c && /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$WD\\probe\\Probe-X1bRust.ps1" -Base "$WD" "$@"
echo "exit=$?"
