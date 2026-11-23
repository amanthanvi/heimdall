#!/usr/bin/env bash
# The benchmark's world, in the M08 container (m08-plan W2-3; ADR-0014 section 6.1; spec section 15.1).
# Run by bench-entry.sh as the unprivileged account `soaks`, never on a host.
#
# Usage: bench-world.sh HEIMDALL OUT DESTINATIONS SAMPLES SETTLE_S IDLE_WINDOW_S IDLE_WINDOWS
#
# It builds, from nothing: one fixture key, a provider agent holding it and an empty decoy
# agent; one loopback fixture sshd; the identity adopted from the agent; DESTINATIONS managed
# destinations (hmb000, hmb001, ...), all pointing at that sshd; the projection applied; one
# profile holding the first destination; the runtime started; and one owner-approved grant
# for that profile, so later ensures are already authorized. Then bench.py measures.
# Nothing leaves the container (--network none); every key is generated here and discarded.
set -u
case "${1:-}" in "" | -h | --help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;; esac
hm_src=$1; out=$2; dests=$3; samples=$4; settle=$5; window=$6; windows=$7
lib=/src/tests/native/m02
# shellcheck source=tests/native/m02/remote-lib.sh
. "$lib/remote-lib.sh"
S=$HOME/s
mkdir -m 700 -- "$S" 2>/dev/null
mkdir -p -- "$out"
HM=$S/heimdall
cp -p -- "$hm_src" "$HM" || { echo "bench: cannot copy the binary" >&2; exit 2; }
fail() {
    printf '{"phase":"world","state":"FAILED","reason":"%s"}\n' "$1" >"$out/status.json"; echo "bench: $1" >&2
    # The world's own CLI transcripts, for the diagnosis (fixture names and scratch paths only).
    mkdir -p "$out/world-files" && cp -p "$S"/*.json "$S"/*.err "$S"/*.log "$S"/*.txt "$out/world-files/" 2>/dev/null
    exit 1
}
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
    if isinstance(v,list):
        try: v=v[int(k)]
        except (ValueError,IndexError): v=None
    else:
        v=v.get(k) if isinstance(v,dict) else None
print("" if v is None else (json.dumps(v) if isinstance(v,(dict,list)) else v))' "$@"; }
hmcli() { local o=$1; shift; "$HM" --json --non-interactive "$@" >"$o" 2>"$o.err" </dev/null; }
on_pty() { local o=$1; shift; python3 -I "$lib/pty-answer.py" "$o" yes 120 -- "$HM" --json "$@"; }

ssh-keygen -q -t ed25519 -N '' -C hm-m08-bench-k0 -f "$S/k0" </dev/null >/dev/null 2>&1 || fail keygen
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
printf '# disposable user configuration (hm-m08 bench)\nHost unrelated\n    HostName unrelated.example.invalid\n    Port 2201\n' >"$HOME/.ssh/config"
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
# The fixture key in a plain ssh-agent needs no touch or unlock: declare it (an owner decision,
# on a terminal with a typed yes), so a non-interactive ensure can use it.
on_pty "$S/declare.txt" identity declare-interaction "$identity" none
[ "$(jget "$S/declare.txt" code)" = OK ] || fail "declare-interaction: $(jget "$S/declare.txt" code)"
account=$(id -un)
n=0
while [ "$n" -lt "$dests" ]; do
    alias=$(printf 'hmb%03d' "$n")
    hmcli "$S/dest-$n.json" destination add "$alias" --hostname 127.0.0.1 --port "$port" --account "$account" --identity "$identity" ||
        fail "destination add $alias: $(jget "$S/dest-$n.json" code)"
    n=$((n + 1))
done
on_pty "$S/apply.txt" setup apply
[ "$(jget "$S/apply.txt" code)" = OK ] || fail "setup apply: $(jget "$S/apply.txt" code)"
SSH_AUTH_SOCK="$S/decoy.sock" ssh -o BatchMode=yes hmb000 true </dev/null >/dev/null 2>&1 || fail "first ordinary ssh login"

hmcli "$S/profile.json" profile create bench --pair "hmb000:$account" || fail "profile create: $(jget "$S/profile.json" code)"
# The runtime may already run: the world's earlier commands start it on demand.
if ! { hmcli "$S/status0.json" service status && [ -n "$(jget "$S/status0.json" data environment_id)" ]; }; then
    "$HM" service run --detach </dev/null >"$S/service.log" 2>&1 || fail "service run"
fi
i=0; until hmcli "$S/status.json" service status && [ -n "$(jget "$S/status.json" data environment_id)" ]; do
    i=$((i + 1)); [ $i -lt 100 ] || fail "the runtime did not come up"; sleep 0.2
done
environment=$(jget "$S/status.json" data environment_id)
control=$(find "$HOME" -name control.sock -type s 2>/dev/null | head -1)
[ -n "$control" ] || fail "no control socket"

# Standing authority for the profile, as M07's harness world (task 2, "covered") sets it up: a
# personal policy for the profile in this environment (`access allow`, PolicyAction::Create),
# one owner decision on a terminal with a typed yes. Ensures it covers then need none.
python3 -I "$lib/pty-answer.py" "$S/allow.txt" yes 120 -- "$HM" --json access allow --profile bench
[ "$(jget "$S/allow.txt" code)" = OK ] || fail "access allow: $(jget "$S/allow.txt" code)"

# Also a trusted project (M05), for the informational hook row whose manifest asks for it. The
# trust is one owner decision, on a terminal with a typed yes; ensures it covers then need none.
proj=$S/project
mkdir -p "$proj"
printf 'schema_version = 1\nproject = "hm-bench"\n\n[access]\nprofile = "bench"\n' >"$proj/.heimdall.toml"
(cd "$proj" && python3 -I "$lib/pty-answer.py" "$S/trust.txt" yes 120 -- "$HM" --json project trust --cwd "$proj")
[ "$(jget "$S/trust.txt" code)" = OK ] || fail "project trust: $(jget "$S/trust.txt" code)"
# The covered path: the shell hook activates only what the trust already covers.
(cd "$proj" && hmcli "$S/activate.json" activate --hook --cwd "$proj")
echo "activate --hook in the trusted project: $(jget "$S/activate.json" code)" >&2

# The first ensure needs the owner: approve its decision on a terminal with a typed yes.
hmcli "$S/ensure0.json" access ensure --profile bench --work-id bench-work --request-id bench-r0
ready() { case "$1" in OK | ACCESS_READY) return 0 ;; esac; return 1; }
code=$(jget "$S/ensure0.json" code)
if ! ready "$code"; then
    ref=$(jget "$S/ensure0.json" next decision_ref)
    [ -n "$ref" ] || fail "first ensure: $code, and no decision to approve"
    on_pty "$S/approve.txt" decision approve "$ref"
    # The approved operation finishes on its own; its request ID replays its outcome.
    i=0; while :; do
        hmcli "$S/ensure0r.json" access ensure --profile bench --work-id bench-work --request-id bench-r0
        ready "$(jget "$S/ensure0r.json" code)" && break
        i=$((i + 1)); [ $i -lt 60 ] || fail "the approved ensure did not complete: $(jget "$S/ensure0r.json" code)"; sleep 0.5
    done
    # Observed in the tryouts: a new request ID on the same work and profile needs a new
    # decision; only a replay of the approved request ID, or the trusted project's hook, is
    # already authorized. bench.py measures both, and says which is which.
    hmcli "$S/ensure1.json" access ensure --profile bench --work-id bench-work --request-id bench-r1
    echo "a new request ID after approval: $(jget "$S/ensure1.json" code)" >&2
fi
printf '{"phase":"world","state":"READY","destinations":%s}\n' "$dests" >"$out/status.json"

exec python3 -I /src/tools/benchmarks/m08/bench.py --heimdall "$HM" --control "$control" --environment "$environment" \
    --profile bench --work-id bench-work --request-id bench-r0 --project "$proj" --out "$out" --samples "$samples" --destinations "$dests" \
    --settle "$settle" --idle-window "$window" --idle-windows "$windows"
