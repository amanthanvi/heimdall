#!/usr/bin/env bash
# The secret-service probe, step (i) (m08-w3-plan W3-6; ruled 2026-11-24): does a RELEASE build's
# managed recipe find a working Secret Service inside the container, with no test hook? Runs as
# the unprivileged account `soaks` under `dbus-run-session`, started by
# run-secret-service-probe.sh. Output: one JSON line per fact in OUT/facts.ndjson (codes,
# reasons, states and counts only; never a passphrase, a key or a path outside the container).
#
# Usage: secret-service-probe.sh HEIMDALL OUT
set -u
in_container() { [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qE '(docker|containerd|kubepods|libpod)' /proc/1/cgroup 2>/dev/null; }
in_container || { echo "refused: this runs only inside the M08 container (no container was detected)" >&2; exit 2; }
if env | grep -q '^HEIMDALL_TEST_'; then echo "refused: a HEIMDALL_TEST_* variable is set in the environment of a release run" >&2; exit 2; fi
HM=$1; out=$2
S=$HOME/s; mkdir -p "$S" && chmod 700 "$S"
facts=$out/facts.ndjson; : >"$facts"
fact() { python3 -I -c 'import json,sys; print(json.dumps({"fact":sys.argv[1],"value":sys.argv[2]}))' "$1" "$2" >>"$facts"; }
jget() { python3 -I -c 'import json,sys
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
reason() { local r; r=$(jget "$1" data error reason); [ -n "$r" ] || r=$(jget "$1" data reason); echo "$r"; }
hmcli() { local o=$1; shift; "$HM" --json --non-interactive "$@" >"$o" 2>"$o.err" </dev/null; }

fact session-bus "$( [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] && echo present || echo absent )"
# 1. GNOME Keyring's Secret Service, its login collection created and unlocked with a password
#    made here and never shown. The password goes in on stdin only.
pw=$(head -c 24 /dev/urandom | base64)
eval "$(printf '%s' "$pw" | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)"
unset pw
eval "$(gnome-keyring-daemon --start --components=secrets 2>/dev/null)"
sleep 1
printf 'probe-value' | secret-tool store --label='hm-m08 probe item' hm-m08-probe item >/dev/null 2>&1
fact secret-tool-store "exit $?"
[ "$(secret-tool lookup hm-m08-probe item 2>/dev/null)" = probe-value ] && fact secret-tool-lookup ok || fact secret-tool-lookup failed
secret-tool clear hm-m08-probe item >/dev/null 2>&1

# 2. The release build's CA ceremony on a pseudo-terminal: the transcript holds the backup
#    passphrase, so it stays in the container's scratch and is deleted; only its JSON envelope's
#    code and reason are kept.
fact heimdall-version "$("$HM" --version 2>&1 | head -1)"
# `service run --detach` is the runtime itself (it logs to its file sink and does not return), so
# it is started in the background and stopped with `service stop`.
if ! { hmcli "$S/status0.json" service status && [ -n "$(jget "$S/status0.json" data environment_id)" ]; }; then
    "$HM" service run --detach </dev/null >"$S/service.log" 2>&1 &
fi
i=0; until hmcli "$S/status.json" service status && [ -n "$(jget "$S/status.json" data environment_id)" ]; do
    i=$((i + 1)); [ $i -lt 100 ] || { fact runtime "did not come up"; exit 1; }; sleep 0.2
done
fact runtime up
# A fresh environment's clock is not yet confirmed: the owner confirms it once, on a terminal.
python3 -I /src/tools/benchmarks/m08/pty-drive.py "$S/time.txt" 120 "[y/N]" yes -- "$HM" --json time confirm
fact time-confirm "exit $?, $(jget "$S/time.txt" code)"
items() { secret-tool search --all heimdall_application heimdall-issuer 2>/dev/null | grep -c '^\[/' ; }
# The ceremony, run as a function: ATTEMPT names it in the facts.
init_attempt() {
    local n=$1
    python3 -I /src/tools/benchmarks/m08/pty-drive.py "$S/init-$n.txt" 180 "Type 'yes' to register this CA: " yes "Type 'written'" written -- \
        "$HM" --json issuer init --backup-out "$S/ca-backup-$n.key"
    local rc=$?
    python3 -I - "$S/init-$n.txt" "$n" "$rc" >>"$facts" <<'PY'
import json, re, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
t = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", t).replace("\r", "")
shown = "Backup passphrase (shown once" in t
# Only text after the last 'written' prompt is kept when the passphrase was shown: the
# passphrase comes before that prompt.
cut = t.rsplit("Type 'written'", 1)[1] if shown and "Type 'written'" in t else (None if shown else t)
env = None
if cut is not None:
    for line in cut.splitlines()[::-1]:
        line = line.strip()
        if line.startswith("{"):
            try:
                env = json.loads(line); break
            except ValueError:
                pass
err = ((env or {}).get("data") or {}).get("error") or {}
print(json.dumps({"fact": "issuer-init-" + sys.argv[2], "value": {
    "exit": int(sys.argv[3]), "register_prompt": "Type 'yes' to register this CA" in t,
    "passphrase_shown": shown, "written_prompt": "Type 'written'" in t,
    "code": (env or {}).get("code"), "state": (env or {}).get("state"),
    "error_message": err.get("message"), "error_reason": err.get("reason"),
    "ca_state": (((env or {}).get("data") or {}).get("cas") or [{}])[0].get("state")}}))
PY
    shred -u "$S/init-$n.txt" 2>/dev/null || rm -f "$S/init-$n.txt"
    fact "issuer-init-$n-backup-file" "$( [ -e "$S/ca-backup-$n.key" ] && echo written || echo absent )"
    fact "issuer-init-$n-store-items-after" "$(items)"
}
fact store-items-before "$(items)"
envs() { # a summary of `inspect environments`: how many records, and their kinds and permissions
    hmcli "$S/envs.json" inspect environments
    python3 -I - "$S/envs.json" <<'PY'
import json, sys
env = None
for line in open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()[::-1]:
    if line.strip().startswith("{"):
        try:
            env = json.loads(line); break
        except ValueError:
            pass
data = (env or {}).get("data") or {}
rows = data.get("environments") if isinstance(data, dict) else None
if not isinstance(rows, list):
    rows = []
print(json.dumps({"code": (env or {}).get("code"), "count": len(rows),
                  "rows": [{k: r.get(k) for k in ("kind", "permissions", "is_self", "self") if k in r} for r in rows]}))
PY
}
step_env() { # step_env NAME RESULT: record a step's result and the environment records after it
    python3 -I -c 'import json,sys; print(json.dumps({"fact":"prereq-"+sys.argv[1],"value":{"result":sys.argv[2],"environments_after":json.loads(sys.argv[3])}}))' \
        "$1" "$2" "$(envs)" >>"$facts"
}
on_pty() { local o=$1; shift; python3 -I /src/tools/benchmarks/m08/pty-drive.py "$o" 120 "[y/N]" yes -- "$HM" --json "$@"; }
mode=${3:-fresh}
fact mode "$mode"
if [ "$mode" = fresh ]; then
    # A. On a fresh installation, before any other owner command.
    init_attempt A
    # B. Again, after a project trust attempt.
    proj=$S/project; mkdir -p "$proj"
    printf 'schema_version = 1\nproject = "hm-probe"\n' >"$proj/.heimdall.toml"
    (cd "$proj" && python3 -I /src/tools/benchmarks/m08/pty-drive.py "$S/trust.txt" 120 "[y/N]" yes -- "$HM" --json project trust --cwd "$proj")
    fact project-trust "exit $?, $(jget "$S/trust.txt" code)"
    init_attempt B
else
    # Probe step 3 (ruled 2026-11-24): the benchmark world's prerequisites one at a time, each
    # followed by the environment records it left, then the ceremony.
    step_env start "-"
    ssh-keygen -q -t ed25519 -N '' -C hm-m08-probe-k0 -f "$S/k0" </dev/null >/dev/null 2>&1
    mkdir -m 700 "$S/agent-home"
    HOME="$S/agent-home" ssh-agent -D -a "$S/agent.sock" </dev/null >/dev/null 2>&1 &
    i=0; while [ $i -lt 100 ] && [ ! -S "$S/agent.sock" ]; do sleep 0.1; i=$((i + 1)); done
    SSH_AUTH_SOCK="$S/agent.sock" ssh-add -q "$S/k0" </dev/null >/dev/null 2>&1
    SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
    step_env identity-adopt "$(jget "$S/adopt.json" code)"
    identity=$(jget "$S/adopt.json" data identity_id)
    on_pty "$S/declare.txt" identity declare-interaction "$identity" none
    step_env identity-declare-interaction "$(jget "$S/declare.txt" code)"
    hmcli "$S/dest.json" destination add hmp000 --hostname 127.0.0.1 --port 2222 --account "$(id -un)" --identity "$identity"
    step_env destination-add "$(jget "$S/dest.json" code)"
    mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
    printf '# disposable user configuration (hm-m08 probe)\n' >"$HOME/.ssh/config"; chmod 600 "$HOME/.ssh/config"
    on_pty "$S/apply.txt" setup apply
    step_env setup-apply "$(jget "$S/apply.txt" code)"
    hmcli "$S/profile.json" profile create probe --pair "hmp000:$(id -un)"
    step_env profile-create "$(jget "$S/profile.json" code)"
    on_pty "$S/allow.txt" access allow --profile probe
    step_env access-allow "$(jget "$S/allow.txt" code)"
    init_attempt C
fi
hmcli "$S/istatus.json" issuer status
fact issuer-status "$(jget "$S/istatus.json" code); ca state $(jget "$S/istatus.json" data cas 0 state); store kind $(jget "$S/istatus.json" data cas 0 store_kind)"

# 3. A fresh runtime reads the CA key from the store again (the load W3-6 would delay).
hmcli "$S/stop.json" service stop
fact service-stop "$(jget "$S/stop.json" code)"
"$HM" service run --detach </dev/null >"$S/service2.log" 2>&1 &
i=0; until hmcli "$S/status2.json" service status && [ -n "$(jget "$S/status2.json" data environment_id)" ]; do
    i=$((i + 1)); [ $i -lt 100 ] || { fact runtime-restart "did not come up"; exit 1; }; sleep 0.2
done
# `issuer unlock` is a ceremony on the controlling terminal; it never prompts the store.
python3 -I /src/tools/benchmarks/m08/pty-drive.py "$S/unlock.txt" 120 "[y/N]" yes -- "$HM" --json issuer unlock
fact issuer-unlock-after-restart "exit $?, $(jget "$S/unlock.txt" code), $(reason "$S/unlock.txt")"
hmcli "$S/istatus2.json" issuer status
fact issuer-status-after-restart "$(jget "$S/istatus2.json" code); ca state $(jget "$S/istatus2.json" data cas 0 state)"
hmcli "$S/stop2.json" service stop
fact service-stop-2 "$(jget "$S/stop2.json" code)"
# 4. Probe step (ii) (mode `slow`): the runtime's session bus behind a delaying relay.
if [ "$mode" = slow ]; then
    case "${DBUS_SESSION_BUS_ADDRESS:-}" in
        unix:path=*) bus=${DBUS_SESSION_BUS_ADDRESS#unix:path=}; bus=${bus%%,*} ;;
        *) fact slow-bus "the session bus is not a path address ($(printf '%s' "${DBUS_SESSION_BUS_ADDRESS:-none}" | cut -d= -f1))"; exit 1 ;;
    esac
    delay=${SLOW_BUS_DELAY_MS:-500}
    fact slow-bus-delay-ms "$delay"
    start_runtime() { # start_runtime BUS_ADDRESS LOG
        DBUS_SESSION_BUS_ADDRESS="$1" "$HM" service run --detach </dev/null >"$2" 2>&1 &
        i=0; until hmcli "$S/st.json" service status && [ -n "$(jget "$S/st.json" data environment_id)" ]; do
            i=$((i + 1)); [ $i -lt 100 ] || return 1; sleep 0.2
        done
    }
    timed_unlock() { # timed_unlock LABEL: three unlocks, each timed end to end
        local k t0 t1 rc
        for k in 1 2 3; do
            t0=$(date +%s%N)
            python3 -I /src/tools/benchmarks/m08/pty-drive.py "$S/u.txt" 120 "[y/N]" yes -- "$HM" --json issuer unlock
            rc=$?; t1=$(date +%s%N)
            fact "unlock-$1-$k" "exit $rc, $(jget "$S/u.txt" code), $(( (t1 - t0) / 1000000 )) ms"
        done
    }
    start_runtime "$DBUS_SESSION_BUS_ADDRESS" "$S/service-fast.log" || { fact runtime-fast "did not come up"; exit 1; }
    timed_unlock fast-bus
    hmcli "$S/stopf.json" service stop
    python3 -I /src/tools/benchmarks/m08/agent-delay.py "$S/slowbus" "$bus" "$delay" "$(dirname "$bus")" </dev/null >"$S/relay.err" 2>&1 &
    relay=$!
    i=0; while [ $i -lt 100 ] && [ ! -S "$S/slowbus" ]; do sleep 0.1; i=$((i + 1)); done
    [ -S "$S/slowbus" ] || { fact relay "did not start: $(head -c 200 "$S/relay.err")"; exit 1; }
    fact relay started
    start_runtime "unix:path=$S/slowbus" "$S/service-slow.log" || { fact runtime-slow "did not come up"; kill "$relay"; exit 1; }
    timed_unlock slow-bus
    python3 -I /src/tools/benchmarks/m08/slow-store-keys.py --heimdall "$HM" --out "$out" --scratch "$S" --delay-ms "$delay" >"$S/keys.log" 2>&1
    fact slow-store-keys "exit $?"
    hmcli "$S/stops.json" service stop
    kill "$relay" 2>/dev/null; wait "$relay" 2>/dev/null
fi
rm -f "$S"/ca-backup-*.key
exit 0
