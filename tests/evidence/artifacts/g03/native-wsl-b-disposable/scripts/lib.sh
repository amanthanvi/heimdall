# shellcheck shell=bash
# Shared helpers for M00-T04-g03-wsl-b (run inside the owner's WSL distribution, the controller).
# Every step writes "$ <command>", its output and "(exit N)" to a transcript under $LOG.
T=M00-T04-g03-wsl-b
S=$HOME/hm-m00/$T
W=$(cat "$S/winscratch.path")          # %LOCALAPPDATA%\hm-m00\M00-T04-g03-wsl-b as a /mnt/c path
WSLEXE=/mnt/c/Windows/System32/wsl.exe
PSEXE=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
LOG=$S/log; mkdir -p "$LOG"
TARBALL_NAME=ubuntu-24.04.5-wsl-amd64.wsl
# wsl.exe prints UTF-16LE for its own messages; NUL and CR are stripped (ASCII output only).
wslx() { (cd /mnt/c && "$WSLEXE" "$@") | tr -d '\000\r'; return "${PIPESTATUS[0]}"; }
psx() { (cd /mnt/c && "$PSEXE" -NoProfile -NonInteractive -ExecutionPolicy Bypass "$@") | tr -d '\r'; return "${PIPESTATUS[0]}"; }
step() {  # step TRANSCRIPT -- cmd args...
  local f="$1"; shift; [ "${1:-}" = "--" ] && shift
  printf '$ %s\n' "$*" >> "$f"
  "$@" >> "$f" 2>&1; local rc=$?
  printf '(exit %s)\n' "$rc" >> "$f"
  return "$rc"
}
note() { local f="$1"; shift; printf '# %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$f"; }
running() { wslx -l --running -q 2>/dev/null | grep -Fxq "$1"; }
