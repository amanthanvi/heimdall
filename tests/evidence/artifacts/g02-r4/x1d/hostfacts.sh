#!/bin/bash
# X1d: host facts for the record. No environment dump: only the named fields below. Paths under $HOME are printed
# as <home>; the caller redacts the rest (user and host name) before anything reaches the repository.
# usage: bash hostfacts.sh   (read-only; run at the start and at the end of the task)
H=$HOME
red() { sed "s#$H#<home>#g"; }
echo "date_utc=$(date -u +%FT%TZ)"
echo "os=$(. /etc/os-release; echo "$PRETTY_NAME")"
echo "kernel=$(uname -r) machine=$(uname -m)"
echo "glibc=$(ldd --version 2>&1 | head -1)"
echo "virt=$(systemd-detect-virt 2>/dev/null; true)"
echo "nproc=$(nproc) memtotal_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo) memavailable_kb=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)"
echo "loadavg=$(cut -d' ' -f1-4 /proc/loadavg)"
echo "processes=$(ps -e --no-headers | wc -l)"
echo "bash=$(bash --version | head -1)"
echo "zsh=$(command -v zsh >/dev/null 2>&1 && zsh --version || echo 'not installed')"
echo "python3=$(python3 --version 2>&1)"
echo "openssh=$(ssh -V 2>&1)"
echo "LANG=${LANG:-unset} LC_ALL=${LC_ALL:-unset}"
echo "uid_is_root=$([ "$(id -u)" -eq 0 ] && echo yes || echo no)"
echo "non-interactive ssh PATH: $(echo "$PATH" | red)"
echo "toolchain commands, command -v in this non-interactive shell (empty = absent):"
for t in go gofmt rustc cargo rustup; do p=$(command -v "$t" 2>/dev/null); echo "  $t: ${p:-absent}" | red; done
echo "toolchain commands, command -v in a login shell (bash -lc, which reads the profile files; empty = absent):"
bash -lc 'for t in go gofmt rustc cargo rustup; do p=$(command -v "$t" 2>/dev/null); echo "  $t: ${p:-absent}"; done' 2>/dev/null | red
echo "executables named go, gofmt, rustc, cargo or rustup under /usr/local, /opt, /usr/lib and \$HOME (find -maxdepth 5):"
nice -n 10 find /usr/local /opt /usr/lib "$H" -maxdepth 5 -type f -perm -u+x \
  \( -name go -o -name gofmt -o -name rustc -o -name cargo -o -name rustup \) 2>/dev/null | red | sed 's/^/  /'
echo "  (end of list)"
echo "toolchain directories (exists: top-level entries):"
for d in /usr/local/go /usr/lib/go /usr/local/cargo /usr/local/rustup "$H/.cargo" "$H/.rustup" "$H/go" "$H/sdk" "$H/.cache/go-build"; do
  [ -e "$d" ] && echo "  $d: $(ls -A "$d" 2>/dev/null | head -5 | tr '\n' ' ')" | red
done
echo "  (end of list)"
echo "other generic tools (command -v; present/absent):"
for t in gcc cc clang make node npm bun deno perl python3 docker podman bwrap strace tmux file ldd; do
  if command -v "$t" >/dev/null 2>&1; then echo "  $t: present"; else echo "  $t: absent"; fi
done
