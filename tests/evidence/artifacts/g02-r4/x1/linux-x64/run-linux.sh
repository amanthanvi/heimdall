#!/bin/bash
# X1 linux-x64 native harness runs (WSL2 Ubuntu). Sequential: go then rust.
set -u
T=$HOME/hm-m00/M00-T05-x1-g02-native
cd "$T/repo"
PY=$T/repo/tests/g02/.venv/bin/python
KREL=$(uname -r); DISTRO=$(. /etc/os-release; echo "$PRETTY_NAME")
BASHV=$(bash --version | head -1)
ZSHV=$(command -v zsh >/dev/null 2>&1 && zsh --version || echo "not installed (no /bin/zsh)")
SSHV=$(ssh -V 2>&1)
for c in go rust; do
  case $c in go) commit=38b6b72;; rust) commit=d8f0cbe;; esac
  EXTRA=$(python3 -c 'import json,sys; print(json.dumps({"native_host":{"kind":"WSL2 (native x86_64 kernel, no container, no emulation)","distro":sys.argv[1],"kernel":sys.argv[2],"windows_build":"Windows 11 Pro 26300","bash":sys.argv[3],"zsh":sys.argv[4],"openssh":sys.argv[5],"runner":"tests/evidence/artifacts/g02-r4/x1/linux-x64/run-linux.sh (X1, no container)"},"artifact_dir":"prototypes/%s/dist/linux-x64"%sys.argv[6],"candidate_commit":sys.argv[7],"subject":"artifact"}))' "$DISTRO" "$KREL" "$BASHV" "$ZSHV" "$SSHV" "$c" "$commit")
  mkdir -p "$T/out/arts-$c"
  echo "== $c start $(date -u +%FT%TZ) loadavg $(cut -d' ' -f1-3 /proc/loadavg)"
  "$PY" tests/g02/conformance.py --bin "$T/art/$c/heimdall-proto" --candidate "$c" \
     --out "$T/out/g02-$c-conformance-linux-x64.json" --artifacts-dir "$T/out/arts-$c" \
     --case-id "G02-$c-conformance-linux-x64" --build-commit 772a6b1 --environment-extra "$EXTRA" \
     > "$T/out/console-$c.log" 2>&1
  echo "== $c exit $? $(date -u +%FT%TZ) loadavg $(cut -d' ' -f1-3 /proc/loadavg)"
done
echo DONE
