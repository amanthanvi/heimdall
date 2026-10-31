#!/bin/bash
# X1d linux-x64 native harness runs of the post-fix (X1b) artifacts on hosts without a Go or Rust toolchain.
# Sequential: go then rust, each under nice -n 10. Derived from ../x1c/run-linux.sh; changes: scratch path, host
# label argument, harness archive commit 51413ebb, case ids and output names (-x1d-<label>), runner path,
# native_host fields (virtualisation, glibc instead of the WSL fields), nice -n 10.
# usage: bash run-linux.sh <host-label>
set -u
L=$1
T=$HOME/hm-m00/M00-T05-r5-x1d
cd "$T/repo"
PY=$T/repo/tests/g02/.venv/bin/python
KREL=$(uname -r); DISTRO=$(. /etc/os-release; echo "$PRETTY_NAME")
BASHV=$(bash --version | head -1)
ZSHV=$(command -v zsh >/dev/null 2>&1 && zsh --version || echo "not installed (no /bin/zsh)")
SSHV=$(ssh -V 2>&1)
GLIBC=$(ldd --version 2>&1 | head -1)
VIRT=$(systemd-detect-virt 2>/dev/null; true)
echo "== host label=$L kernel=$KREL distro=$DISTRO nproc=$(nproc) memtotal_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo) virt=$VIRT"
for c in go rust; do
  case $c in go) commit=84c7665;; rust) commit=001a791;; esac
  EXTRA=$(python3 -c 'import json,sys; print(json.dumps({"native_host":{"label":sys.argv[9],"kind":"native x86_64 Linux host without a Go or Rust toolchain (systemd-detect-virt: %s), no container, no emulation"%sys.argv[10],"distro":sys.argv[1],"kernel":sys.argv[2],"glibc":sys.argv[8],"bash":sys.argv[3],"zsh":sys.argv[4],"openssh":sys.argv[5],"nice":10,"runner":"tests/evidence/artifacts/g02-r4/x1d/run-linux.sh (X1d, no container)"},"artifact_dir":"prototypes/%s/dist/linux-x64"%sys.argv[6],"candidate_commit":sys.argv[7],"subject":"artifact"}))' "$DISTRO" "$KREL" "$BASHV" "$ZSHV" "$SSHV" "$c" "$commit" "$GLIBC" "$L" "$VIRT")
  mkdir -p "$T/out/arts-$c"
  echo "== $c start $(date -u +%FT%TZ) loadavg $(cut -d' ' -f1-3 /proc/loadavg) running_tasks $(cut -d' ' -f4 /proc/loadavg)"
  nice -n 10 "$PY" tests/g02/conformance.py --bin "$T/art/$c/heimdall-proto" --candidate "$c" \
     --out "$T/out/g02-$c-conformance-linux-x64-x1d-$L.json" --artifacts-dir "$T/out/arts-$c" \
     --case-id "G02-$c-conformance-linux-x64-x1d-$L" --build-commit 51413ebb --environment-extra "$EXTRA" \
     > "$T/out/console-$c.log" 2>&1
  echo "== $c exit $? $(date -u +%FT%TZ) loadavg $(cut -d' ' -f1-3 /proc/loadavg) running_tasks $(cut -d' ' -f4 /proc/loadavg)"
done
echo DONE
