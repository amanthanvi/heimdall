#!/bin/bash
# X1c linux-x64 native harness runs of the post-fix (X1b) artifacts (WSL2 Ubuntu). Sequential: go then rust.
# Derived from ../x1/linux-x64/run-linux.sh; changes: scratch path, candidate commits (84c7665 / 001a791),
# harness archive commit cfd97d23, case ids and output names (-x1b), runner path, WSL version field.
set -u
T=$HOME/hm-m00/M00-T05-r5-x1c
cd "$T/repo"
PY=$T/repo/tests/g02/.venv/bin/python
KREL=$(uname -r); DISTRO=$(. /etc/os-release; echo "$PRETTY_NAME")
BASHV=$(bash --version | head -1)
ZSHV=$(command -v zsh >/dev/null 2>&1 && zsh --version || echo "not installed (no /bin/zsh)")
SSHV=$(ssh -V 2>&1)
WSLV=$( (command -v wslinfo >/dev/null 2>&1 && wslinfo --wsl-version 2>/dev/null) || echo "not available")
echo "== host kernel=$KREL distro=$DISTRO nproc=$(nproc) memtotal_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo) wsl=$WSLV"
for c in go rust; do
  case $c in go) commit=84c7665;; rust) commit=001a791;; esac
  EXTRA=$(python3 -c 'import json,sys; print(json.dumps({"native_host":{"kind":"WSL2 (native x86_64 kernel, no container, no emulation)","distro":sys.argv[1],"kernel":sys.argv[2],"windows_build":"not queried (X1c did not touch Windows; X1 recorded Windows 11 Pro 26300)","wsl_version":sys.argv[8],"bash":sys.argv[3],"zsh":sys.argv[4],"openssh":sys.argv[5],"runner":"tests/evidence/artifacts/g02-r4/x1c/run-linux.sh (X1c, no container)"},"artifact_dir":"prototypes/%s/dist/linux-x64"%sys.argv[6],"candidate_commit":sys.argv[7],"subject":"artifact"}))' "$DISTRO" "$KREL" "$BASHV" "$ZSHV" "$SSHV" "$c" "$commit" "$WSLV")
  mkdir -p "$T/out/arts-$c"
  echo "== $c start $(date -u +%FT%TZ) loadavg $(cut -d' ' -f1-3 /proc/loadavg) running_tasks $(cut -d' ' -f4 /proc/loadavg)"
  "$PY" tests/g02/conformance.py --bin "$T/art/$c/heimdall-proto" --candidate "$c" \
     --out "$T/out/g02-$c-conformance-linux-x64-x1b.json" --artifacts-dir "$T/out/arts-$c" \
     --case-id "G02-$c-conformance-linux-x64-x1b" --build-commit cfd97d23 --environment-extra "$EXTRA" \
     > "$T/out/console-$c.log" 2>&1
  echo "== $c exit $? $(date -u +%FT%TZ) loadavg $(cut -d' ' -f1-3 /proc/loadavg) running_tasks $(cut -d' ' -f4 /proc/loadavg)"
done
echo DONE
