#!/bin/bash
set -euo pipefail
T=M00-T04-G03-native-wsl
S=$HOME/hm-m00/$T
cd "$S"
mkdir -p repo tmp; chmod 700 . tmp
tar -xzf bundle.tgz -C repo
LAD=$(cd /mnt/c && /mnt/c/Windows/System32/cmd.exe /d /c 'echo %LOCALAPPDATA%' | tr -d '\r')
W="$(wslpath -u "$LAD")/hm-m00/$T"
mkdir -p "$W/tmp" "$W/repo"
echo "$W" > "$S/winscratch.path"
tar -xzf bundle.tgz -C "$W/repo" tests/native/windows
cp launch.ps1 psfind.ps1 psstop.ps1 "$W/"
echo setup-ok
