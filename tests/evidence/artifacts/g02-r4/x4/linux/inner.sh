#!/bin/bash
# Runs inside the private session bus. Args = spike binaries under /spikes (ro mount).
# *keyring* binaries are the keyring-4.x facade (Secret Service only, no mode arg).
set -u
echo "uid=$(id -u) kernel=$(uname -r) arch=$(uname -m)"
for b in "$@"; do echo "LDD $b: $(ldd /spikes/$b 2>&1 | head -1 | tr -s " ")"; done
if [ "${X4_NO_SS:-0}" != 1 ]; then
  echo "--- start gnome-keyring (secrets component, fixture password, never a real secret) ---"
  eval "$(echo -n 'x4fixture' | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)"
  sleep 1
fi
for b in "$@"; do
  case "$b" in
    *keyring*) modes="-" ;;
    *) modes="secret-service keyctl keyctl-user" ;;
  esac
  for mode in $modes; do
    if [ "$mode" = "-" ]; then out=$(/spikes/$b 2>/tmp/err); rc=$?; else out=$(/spikes/$b $mode 2>/tmp/err); rc=$?; fi
    [ "$mode" = "-" ] && mode=none; echo "RUN $b $mode exit=$rc"
    echo "  stdout: $out"
    [ -s /tmp/err ] && echo "  stderr: $(head -c 300 /tmp/err | tr '\n' ' ')"
  done
done
exit 0
