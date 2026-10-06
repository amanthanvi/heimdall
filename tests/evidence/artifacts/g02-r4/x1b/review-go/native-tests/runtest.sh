#!/bin/bash
# usage: runtest.sh <test.exe in WSL scratch> [test flags...]  (WSL; task M00-T05-x1b-review-go)
set -u
LAD=$(wslpath "$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" </dev/null 2>/dev/null | tr -d '\r')")
D="$LAD/hm-m00/M00-T05-x1b-review-go"
WD=$(wslpath -w "$D")
exe=$1; shift
mkdir -p "$D/tb" "$D/tmp"; cp ~/hm-m00/M00-T05-x1b-review-go/"$exe" "$D/tb/$exe"
q=''; for a in "$@"; do q="$q '$a'"; done
cd /mnt/c && /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -Command "\$env:TEMP='$WD\\tmp'; \$env:TMP='$WD\\tmp'; Set-Location -LiteralPath '$WD\\tmp'; & '$WD\\tb\\$exe'$q; exit \$LASTEXITCODE" </dev/null
echo "exit=$?"
