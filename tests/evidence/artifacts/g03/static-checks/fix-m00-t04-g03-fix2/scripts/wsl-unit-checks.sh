#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2329,SC2034  # literal stub scripts; stubs called by sourced helpers; globals read by sourced helpers
# M00-T04-G03-fix2 unit checks of WSL-harness helpers with stubs (no WSL, no interop).
# Usage: wsl-unit-checks.sh REPO_ROOT    (bash 3.2+; /proc-dependent keepalive checks run only on Linux)
set -u
REPO="$1"
fail=0
check() { if [ "$2" = "$3" ]; then printf '%-64s got=%s ok\n' "$1" "$2"; else printf '%-64s got=%s want=%s MISMATCH\n' "$1" "$2" "$3"; fail=1; fi; }
W="$(mktemp -d "${TMPDIR:-/tmp}/g03fix2-wsl-XXXXXX")"
# shellcheck source=/dev/null
. "$REPO/tests/native/wsl/g03_common.sh"

echo "--- D4 g03_net_mode_word allowlist"
check 'Mirrored -> mirrored' "$(g03_net_mode_word Mirrored)" mirrored
check 'NAT -> nat' "$(g03_net_mode_word NAT)" nat
check 'consomme' "$(g03_net_mode_word consomme)" consomme
check 'path-like value not recorded' "$(g03_net_mode_word 'C:\Users\someone\x')" '<unrecognized value, not recorded>'
check 'empty' "$(g03_net_mode_word '')" '<empty>'

echo "--- D4 g03_net_mode_obs with stubs (wslinfo absent / present)"
g03_obs() { printf '%s=%s\n' "$2" "$4" >> "$W/obs"; }
g03_win() { printf '%s\r\n' "$W/profile"; }
wslpath() { printf '%s\n' "$2"; }
mkdir -p "$W/profile" "$W/bin"
run_obs() { : > "$W/obs"; ( PATH="$W/bin:/usr/bin:/bin"; g03_net_mode_obs case1 ); cat "$W/obs"; }
printf '[wsl2]\nmemory=4GB\nnetworkingMode = Mirrored\n' > "$W/profile/.wslconfig"
check 'wsl2 key read, word recorded' "$(run_obs | grep '^wslconfig' )" 'wslconfig_networkingMode=mirrored'
check 'wslinfo absent recorded' "$(run_obs | grep '^wslinfo' )" 'wslinfo_networking_mode=unavailable'
printf '[wsl2]\nmemory=4GB\n[experimental]\nnetworkingMode=mirrored\n' > "$W/profile/.wslconfig"
check 'key outside [wsl2] ignored' "$(run_obs | grep '^wslconfig')" 'wslconfig_networkingMode=<key absent: documented default nat>'
printf '[wsl2]\nnetworkingMode="secret-%s"\n' 'value' > "$W/profile/.wslconfig"
check 'unknown value not recorded' "$(run_obs | grep '^wslconfig')" 'wslconfig_networkingMode=<unrecognized value, not recorded>'
check '  no raw value anywhere in obs' "$(run_obs | grep -c secret)" 0
rm -f "$W/profile/.wslconfig"
check 'no .wslconfig' "$(run_obs | grep '^wslconfig')" 'wslconfig_networkingMode=<no .wslconfig: documented default nat>'
printf '#!/bin/sh\necho Mirrored\n' > "$W/bin/wslinfo"; chmod +x "$W/bin/wslinfo"
printf '[wsl2]\nnetworkingMode=nat\n' > "$W/profile/.wslconfig"
check 'wslinfo present -> its word' "$(run_obs | grep '^wslinfo')" 'wslinfo_networking_mode=mirrored'
check '  .wslconfig not read when wslinfo present' "$(run_obs | grep '^wslconfig')" 'wslconfig_networkingMode=<not read: wslinfo available>'
rm -f "$W/bin/wslinfo"

echo "--- D7 g03_wslenv_check"
G03_RUN_ID=t; G03_WIN_DECOY_PIPE_PATH='\\.\pipe\heimdall-g03-decoy-t'
g03_win_sock_env
check 'WENV carries SSH_AUTH_SOCK/w' "${WENV[2]}" 'WSLENV=SSH_AUTH_SOCK/w'
check 'no cmd.exe / no /mnt/c here -> mismatch (refuse ssh.exe)' "$(g03_wslenv_check)" mismatch
# Stub a Win32 side that honours /w: cmd.exe echoes the variable.
printf '#!/bin/sh\nprintf "%%s\\r\\n" "$SSH_AUTH_SOCK"\n' > "$W/bin/cmd.exe"; chmod +x "$W/bin/cmd.exe"
if [ -d /mnt/c ] || mkdir -p /mnt/c 2>/dev/null; then
  # Real g03_wslenv_check with a stub cmd.exe on PATH (needs /mnt/c: Linux container).
  check 'real check, stub cmd.exe echoes value -> ok' "$( PATH="$W/bin:/usr/bin:/bin" g03_wslenv_check )" ok
  printf '#!/bin/sh\nprintf "%%%%SSH_AUTH_SOCK%%%%\\r\\n"\n' > "$W/bin/cmd.exe"
  check 'real check, stub cmd.exe sees no value -> mismatch' "$( PATH="$W/bin:/usr/bin:/bin" g03_wslenv_check )" mismatch
else
  echo "SKIPPED (/mnt/c cannot exist on this host): real g03_wslenv_check against a stub cmd.exe"
fi

echo "--- D8 PYTHONDONTWRITEBYTECODE exported by g03_init"
check 'g03_init exports PYTHONDONTWRITEBYTECODE=1' "$(grep -c '^  export PYTHONDONTWRITEBYTECODE=1$' "$REPO/tests/native/wsl/g03_common.sh")" 1

echo "--- D6 keepalive target scripts (extracted from run_g03_wsl_lifecycle.sh)"
L="$REPO/tests/native/wsl/run_g03_wsl_lifecycle.sh"
awk '/^cat > "\$SH\/t_keep.sh" <<.EOS.$/{f=1;next} /^EOS$/{f=0} f' "$L" > "$W/t_keep.sh"
awk '/^cat > "\$SH\/t_keepstop.sh" <<.EOS.$/{f=1;next} /^EOS$/{f=0} f' "$L" > "$W/t_keepstop.sh"
check 't_keep.sh extracted' "$(head -1 "$W/t_keep.sh")" '#!/usr/bin/env bash'
check 't_keepstop.sh extracted' "$(head -1 "$W/t_keepstop.sh")" '#!/usr/bin/env bash'
bash -n "$W/t_keep.sh"; check 't_keep.sh bash -n' "$?" 0
bash -n "$W/t_keepstop.sh"; check 't_keepstop.sh bash -n' "$?" 0
check 'no pidfile' "$(bash "$W/t_keepstop.sh" "$W/none.pid")" keepalive=no-pidfile
printf 'abc def\n' > "$W/bad.pid"; check 'bad pidfile' "$(bash "$W/t_keepstop.sh" "$W/bad.pid")" keepalive=bad-pidfile
if [ -r /proc/self/stat ]; then
  bash "$W/t_keep.sh" "$W/k.pid" 30 & kp=$!
  i=0; while [ $i -lt 50 ] && [ ! -s "$W/k.pid" ]; do sleep 0.1; i=$((i+1)); done
  read -r rp rt < "$W/k.pid"
  check 'pidfile pid = started pid (exec keeps pid)' "$rp" "$kp"
  sleep 0.2
  check 'comm became sleep' "$(cat "/proc/$kp/comm")" sleep
  printf '%s %s\n' "$rp" "999999999" > "$W/wrong.pid"
  check 'wrong start token -> not stopped' "$(bash "$W/t_keepstop.sh" "$W/wrong.pid")" keepalive=identity-mismatch-not-stopped
  check '  process still alive' "$(kill -0 "$kp" 2>/dev/null && echo alive)" alive
  printf '%s %s\n' "$$" "$(sed -e 's/^.*) //' "/proc/$$/stat" | awk '{print $20}')" > "$W/notsleep.pid"
  check 'matching token but comm != sleep -> not stopped' "$(bash "$W/t_keepstop.sh" "$W/notsleep.pid")" keepalive=identity-mismatch-not-stopped
  check 'exact match -> stopped' "$(bash "$W/t_keepstop.sh" "$W/k.pid")" keepalive=stopped
  wait "$kp" 2>/dev/null
  check 'after stop -> already-exited' "$(bash "$W/t_keepstop.sh" "$W/k.pid")" keepalive=already-exited
  check '  recorded token was non-empty' "$([ -n "$rt" ] && echo yes)" yes
else
  echo "SKIPPED (/proc absent on this host): keepalive start/stop identity checks"
fi
rm -rf "$W"
echo "FAILURES=$fail"
exit $fail
