#!/bin/bash
# usage: import.sh TARGET_NAME   (ADR-0004 sec. 3: create ONE disposable distribution)
set -u
. "$(dirname "$0")/lib.sh"
NAME=$1
L=$LOG/import.txt; : > "$L"
case "$NAME" in hm-g03b-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) echo "refusing name $NAME" >&2; exit 2 ;; esac
if wslx -l -q 2>/dev/null | grep -Fxiq "$NAME"; then echo "a distribution named $NAME already exists; abort" | tee -a "$L"; exit 3; fi
[ -z "$(ls -A "$W/distro")" ] || { echo "install dir not empty; abort" | tee -a "$L"; exit 3; }
WD=$(wslpath -w "$W/distro"); WT=$(wslpath -w "$W/rootfs/$TARBALL_NAME")
note "$L" "import"
step "$L" -- wslx --import "$NAME" "$WD" "$WT" --version 2 || exit 4
step "$L" -- wslx -l -v
note "$L" "first launch (root, non-interactive --exec; the image OOBE is interactive-only per WSL docs)"
step "$L" -- timeout 300 "$WSLEXE" -d "$NAME" -u root --cd / --exec /bin/bash "$W/scripts/target_facts.sh" < /dev/null
step "$L" -- timeout 120 "$WSLEXE" -d "$NAME" -u root --cd / --exec /bin/bash "$W/scripts/target_setup.sh" < /dev/null
note "$L" "terminate own distribution so /etc/wsl.conf [user] default applies"
step "$L" -- wslx --terminate "$NAME"
i=0; while [ $i -lt 30 ] && running "$NAME"; do sleep 1; i=$((i+1)); done; note "$L" "not running after ${i}s"
step "$L" -- timeout 300 "$WSLEXE" -d "$NAME" --cd / --exec /bin/bash "$W/scripts/target_facts.sh" < /dev/null
