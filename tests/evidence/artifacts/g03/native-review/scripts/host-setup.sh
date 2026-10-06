#!/bin/bash
# Review scratch setup on the WSL side; Windows scratch under %LOCALAPPDATA%\hm-m00\<task>.
set -euo pipefail
T=M00-T04-G03-native-review
S=$HOME/hm-m00/$T
cd "$S"; chmod 700 "$S"
mkdir -p repo tmp evid; chmod 700 tmp
tar -xzf bundle.tgz -C repo
tar -xzf evidence.tgz -C evid
LAD=$(cd /mnt/c && /mnt/c/Windows/System32/cmd.exe /d /c 'echo %LOCALAPPDATA%' | tr -d '\r')
W="$(wslpath -u "$LAD")/hm-m00/$T"
mkdir -p "$W/tmp" "$W/repo"
echo "$W" > "$S/winscratch.path"
tar -xzf bundle.tgz -C "$W/repo" tests/native/windows
cp launch-review.ps1 owner-state.ps1 "$W/"
echo setup-ok
