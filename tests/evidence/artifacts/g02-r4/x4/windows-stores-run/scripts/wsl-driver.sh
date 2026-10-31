#!/usr/bin/env bash
# M00-T04-x4-stores WSL-side driver. Runs in WSL2 as the non-root user; Windows is reached through
# WSL interop (cmd.exe, powershell.exe by full path). Scratch: ~/hm-m00/M00-T04-x4-stores (WSL) and
# %LOCALAPPDATA%\hm-m00\M00-T04-x4-stores (Windows). Never prints the Windows profile path.
# usage: wsl-driver.sh stage|run|collect|cleanup
set -u
W="$HOME/hm-m00/M00-T04-x4-stores"
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
CMD=/mnt/c/Windows/System32/cmd.exe
lad_win=$(cd /mnt/c && "$CMD" /d /c 'echo %LOCALAPPDATA%' | tr -d '\r')
[ -n "$lad_win" ] || { echo "LOCALAPPDATA not resolved"; exit 3; }
lad=$(wslpath -u "$lad_win")
WS="$lad/hm-m00/M00-T04-x4-stores"         # Windows scratch, WSL view
WSW="$lad_win\\hm-m00\\M00-T04-x4-stores"  # Windows scratch, Windows view
case "${1:-}" in
  stage)
    mkdir -p "$WS/bin" || exit 1
    cp "$W/x4-go.exe" "$W/x4-rust.exe" "$WS/bin/" && cp "$W/run-x4-stores.ps1" "$WS/" || exit 1
    (cd "$WS/bin" && sha256sum x4-go.exe x4-rust.exe)
    sha256sum "$WS/run-x4-stores.ps1" | cut -d' ' -f1
    ;;
  run)
    cd "$WS" || exit 1
    "$PS" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$WSW\\run-x4-stores.ps1" \
      -BinDir "$WSW\\bin" -OutDir "$WSW\\out" -Iterations 20 > "$W/runner-console.txt" 2>&1
    rc=$?
    echo "runner_exit=$rc"
    exit $rc
    ;;
  collect)
    rm -rf "$W/out" && cp -r "$WS/out" "$W/out" || exit 1
    find "$W/out" -type f | wc -l
    ;;
  cleanup)
    rm -rf "$WS"
    rmdir "$lad/hm-m00" 2>/dev/null || true   # only if empty (other tasks' dirs are left alone)
    [ -e "$WS" ] && echo "windows_scratch_present=yes" || echo "windows_scratch_present=no"
    ;;
  *) echo "usage: $0 stage|run|collect|cleanup"; exit 2 ;;
esac
