#!/usr/bin/env bash
# One soak lane, run as an unprivileged lane account inside the container (m08-plan U5a).
#
# Usage: lane.sh LANE HEIMDALL OUT SECONDS SEED TICK
#   LANE      S (steady: dependency faults only) or L (lifecycle: stops and kills too)
#   HEIMDALL  the release executable under test (copied into the lane's scratch)
#   OUT       this lane's output directory (samples.ndjson, events.ndjson, status.json)
# It builds the lane's world the way tests/native/m02/scenario-ordinary-ssh.sh does (a
# disposable key, a provider ssh-agent, an empty decoy agent, the unprivileged fixture sshd
# on 127.0.0.1, the account's own ~/.ssh/config, `identity adopt`, `destination add`,
# `setup apply` with a typed yes), then hands over to workload.py. No test variable is set:
# this is the release build's own behaviour. The account's home is disposable: it exists
# only in this container.
set -u
lane=$1; hm_src=$2; out=$3; seconds=$4; seed=$5; tick=$6
lib=/src/tests/native/m02
# shellcheck source=tests/native/m02/remote-lib.sh
. "$lib/remote-lib.sh"
S=$HOME/s
mkdir -m 700 -- "$S" "$out" 2>/dev/null
HM=$S/heimdall
cp -p -- "$hm_src" "$HM" || { echo "lane $lane: cannot copy the binary" >&2; exit 2; }
ALIAS=hmsoak
fail() { printf '{"lane":"%s","phase":"bootstrap","state":"FAILED","reason":"%s"}\n' "$lane" "$1" >"$out/status.json"; exit 1; }
jget() { # jget FILE KEY...: a value from the last JSON envelope line of FILE (a pty transcript also holds text)
    python3 -I -c 'import json,sys
env=None
try: lines=open(sys.argv[1],encoding="utf-8",errors="replace").read().splitlines()
except OSError: lines=[]
for line in lines[::-1]:
    line=line.strip()
    if line.startswith("{"):
        try:
            env=json.loads(line); break
        except ValueError: pass
v=env
for k in sys.argv[2:]:
    v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else v)' "$@"; }
hmcli() { local o=$1; shift; "$HM" --json --non-interactive "$@" >"$o" 2>"$o.err" </dev/null; }
on_pty() { local o=$1; shift; python3 -I "$lib/pty-answer.py" "$o" yes 120 -- "$HM" --json "$@"; }

ssh-keygen -q -t ed25519 -N '' -C hm-m08-soak-k0 -f "$S/k0" </dev/null >/dev/null 2>&1 || fail keygen
mkdir -m 700 "$S/agent-home" "$S/decoy-home"
HOME="$S/agent-home" ssh-agent -D -a "$S/agent.sock" </dev/null >/dev/null 2>&1 &
echo $! >"$S/agent.pid"
HOME="$S/decoy-home" ssh-agent -D -a "$S/decoy.sock" </dev/null >/dev/null 2>&1 &
i=0; while [ $i -lt 100 ] && { [ ! -S "$S/agent.sock" ] || [ ! -S "$S/decoy.sock" ]; }; do sleep 0.1; i=$((i + 1)); done
SSH_AUTH_SOCK="$S/agent.sock" ssh-add -q "$S/k0" </dev/null >/dev/null 2>&1 || fail ssh-add
{ printf 'restrict '; cat "$S/k0.pub"; } >"$S/authorized_keys"
hm2_sshd_start "$S/sshd" "$S/authorized_keys" "$S/sshd.log" || fail "sshd: $HM2_SSHD_WHY"
port=$HM2_SSHD_PORT
mkdir -p -m 700 "$HOME/.ssh"
printf '# disposable user configuration (hm-m08 soak)\nHost unrelated\n    HostName unrelated.example.invalid\n    Port 2201\n' >"$HOME/.ssh/config"
chmod 600 "$HOME/.ssh/config"
printf '[127.0.0.1]:%s %s\n' "$port" "$HM2_SSHD_HOSTKEY" >>"$HOME/.ssh/known_hosts"
chmod 600 "$HOME/.ssh/known_hosts"

SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
if [ "$(jget "$S/adopt.json" code)" = TIME_UNCERTAIN ]; then
    on_pty "$S/time.txt" time confirm
    SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
fi
identity=$(jget "$S/adopt.json" data identity_id)
[ -n "$identity" ] || fail "identity adopt: $(jget "$S/adopt.json" code)"
hmcli "$S/dest.json" destination add "$ALIAS" --hostname 127.0.0.1 --port "$port" --account "$(id -un)" --identity "$identity" ||
    fail "destination add: $(jget "$S/dest.json" code)"
on_pty "$S/apply.txt" setup apply
[ "$(jget "$S/apply.txt" code)" = OK ] || fail "setup apply: $(jget "$S/apply.txt" code)"
SSH_AUTH_SOCK="$S/decoy.sock" ssh -o BatchMode=yes "$ALIAS" true </dev/null >/dev/null 2>&1 || fail "first ordinary ssh login"

exec python3 -I /src/tools/benchmarks/m08/workload.py --lane "$lane" --heimdall "$HM" --scratch "$S" \
    --alias "$ALIAS" --out "$out" --seconds "$seconds" --seed "$seed" --tick "$tick" \
    --sshd-config "$S/sshd/sshd_config" --sshd-log "$S/sshd.log" --sshd-pid "$HM2_SSHD_PID"
