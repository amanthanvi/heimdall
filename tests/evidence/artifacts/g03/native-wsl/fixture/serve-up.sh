#!/bin/bash
# Start the Windows instrumented agent (+ decoy) for the WSL probes; fixture pipe names only.
set -euo pipefail
T=M00-T04-G03-native-wsl
S=$HOME/hm-m00/$T
W=$(cat $S/winscratch.path); WW=$(wslpath -w "$W")
SECS=${1:-3000}; LABEL=${2:-serve1}
cd "$W"
setsid nohup "/mnt/c/Program Files/PowerShell/7/pwsh.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File launch.ps1 \
  -Target repo/tests/native/windows/Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl -ServeSeconds "$SECS" -OutDir "$WW\\$LABEL" \
  > "$S/$LABEL.out" 2>&1 < /dev/null &
echo $! > "$S/$LABEL.launcher.pid"
for i in $(seq 1 90); do [ -s "$W/$LABEL/wsl-agent-manifest.json" ] && break; sleep 1; done
[ -s "$W/$LABEL/wsl-agent-manifest.json" ] || { echo "no manifest"; tail -5 "$S/$LABEL.out"; exit 1; }
echo "$W/$LABEL/wsl-agent-manifest.json" > $S/manifest.path
python3 - "$W/$LABEL/wsl-agent-manifest.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8-sig'))
print('pipe', d['pipe_name'], 'decoy', d['decoy_pipe_name'], 'keys', [k.get('fingerprint') for k in d['keys']], 'serve_seconds', d['serve_seconds'])
PY
# authorize manifest key 1 on fixture sshd A (restrict)
PUBW=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8-sig"))["public_key_dir"])' "$W/$LABEL/wsl-agent-manifest.json")
PUB="$(wslpath -u "$PUBW")/probe-key-1.pub"
line=$(tr -d '\r' < "$PUB")
case "$line" in "ecdsa-sha2-nistp256 "*) ;; *) echo "unexpected key format"; exit 1 ;; esac
echo "restrict $line" >> $S/fixture/authorized_keys
echo authorized-key1
