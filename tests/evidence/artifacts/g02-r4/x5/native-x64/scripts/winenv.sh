#!/bin/sh
# Prints the WSL path of %LOCALAPPDATA%\hm-m00\M00-T05-r5-x5 (not echoed to logs by callers).
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
L=$(cd /mnt/c && "$PS" -NoProfile -NonInteractive -Command '[Console]::Out.Write($env:LOCALAPPDATA)' | tr -d '\r')
wslpath -u "$L\\hm-m00\\M00-T05-r5-x5"
