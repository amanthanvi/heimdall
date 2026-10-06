#!/bin/bash
# usage: runtest.sh <test.exe name in Windows scratch\tb> [test flags...]  (WSL; task M00-T05-x1b-fix-go)
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1b-fix-go"
WD=$(wslpath -w "$D")
exe=$1; shift
q=''; for a in "$@"; do q="$q '$a'"; done
mkdir -p "$D/tmp"
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
cd /mnt/c && "$PS" -NoProfile -NonInteractive -Command "\$env:TEMP='$WD\\tmp'; \$env:TMP='$WD\\tmp'; Set-Location -LiteralPath '$WD\\tmp'; & '$WD\\tb\\$exe'$q; exit \$LASTEXITCODE"
echo "exit=$?"
