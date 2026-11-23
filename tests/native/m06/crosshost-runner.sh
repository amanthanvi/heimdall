#!/usr/bin/env bash
# M06 W5 `w5g` (m06-plan §3 "Runner" rows, §4 "Paired remote Linux runner"): the RUNNER side of
# the cross-host journey (tests/native/m06/run-crosshost.sh). It runs on the runner host (the
# devbox) from the run's staging directory, next to windows-controller-runner.sh and
# crosshost-tool.py, and only ever inside ROOT, a scratch directory of this run.
#
#   crosshost-runner.sh ACTION ROOT [ARGS...]
#
# ROOT is as windows-controller-runner.sh requires it (an absolute hm-m06j-* path). The actions
# of that script (prepare, authorize, sshd-start, sshd-stop, trust-ca, seed, runtime-start,
# runtime-stop, ensure, identities, onward, processes, cleanup) are passed to it unchanged
# (ADR-0009: generalized, never copied). This script adds what the cross-host rows need. Every
# action prints `key=value` facts on stdout (public facts only: counts, codes, states) and
# exits 0, or says why on stderr and exits 1 (2 for a refused argument, 3 for a missing tool).
#
#   runtime-start-with ROOT TIME_SYNC POLICY
#       `heimdall service run --runner` as `runtime-start`, with HEIMDALL_TEST_TIME_SYNC=TIME_SYNC
#       (synchronized | not_synchronized) and the sshd policy check reading ROOT/mgmt/POLICY
#       (sshd_config, or a policy-* file of `policy-config`). Recorded as `runtime-start` records
#       it, so `runtime-stop` and `cleanup` stop exactly it. Facts: runtime.
#   runtime-offered-stop ROOT
#       Stop the runner runtime the BOOTSTRAP's accepted offer started (`remote init
#       --offer-runtime-start`, a detached `service run --runner` this script did not record),
#       through the product's own `service stop` on the runner's scratch home. Refused when a
#       runtime of this script is recorded. Facts: offered_runtime (running | not_running:
#       whether a runtime served before the stop), runtime (stopped). Fails when a runtime
#       still serves afterwards.
#   policy-config ROOT VARIANT
#       ROOT/mgmt/policy-VARIANT: the management sshd's own configuration with one unsupported
#       setting (kc: an AuthorizedKeysCommand; fc: a ForceCommand; ae: `AcceptEnv *`). Nothing
#       listens with it: it is the `sshd -T` check's input. Facts: policy.
#   sshd-check ROOT POLICY
#       The host's own sshd binary over the fixture configuration, as the runner's verification
#       runs it: `sshd -T -f ROOT/mgmt/POLICY -h <the fixture host key> -C user=<account>,
#       host=localhost,addr=127.0.0.1`. Facts: sshd_t_exit, allowagentforwarding,
#       allowtcpforwarding, x11forwarding, permituserenvironment, permituserrc, acceptenv_all,
#       forcecommand, authorizedkeyscommand.
#   json ROOT [NAME=PATH]... -- ARGS...
#       `heimdall --json ARGS` on the runner's home, unattended. Facts: exit, code, reason and
#       one per NAME=PATH (a dotted path into the envelope).
#   attended ROOT [NAME=PATH]... -- ARGS...
#       The same on a pseudo-terminal, typing `yes` at the confirmation: the runner's local
#       owner at its terminal (`decision approve`, `remote issuer-trust add`, `remote policy
#       recheck`). Facts: prompted, exit, code, reason and one per NAME=PATH.
#   issuer-trust ROOT CA_PUBLIC_KEY_LINE CLIENT
#       The runner's local owner trusts a controller's CA for that owner client (`remote
#       issuer-trust add`, attended). Facts: prompted, exit, code, reason.
#   policy ROOT POLICY_ID
#       The runner's own standing policy (`inspect policies`). Facts: present, paused, cutoff.
#   work ROOT WORK_ID REQUEST_ID
#       Runner work through the real `heimdall run`, unattended, launched from THIS process:
#       whatever the calling ssh session left in the environment (SSH_AUTH_SOCK of a forwarded
#       agent, SSH_CONNECTION) and a marker variable are in the launcher's environment. Facts
#       (names and counts only): exit, session_agent (true when this session has an agent),
#       session_agent_keys, session_connection, work_env_extra (names outside the clean
#       launch's set, `none` when there is none), work_has_session_marker,
#       work_has_ssh_connection, work_agent_is_session_agent, work_agent_under_runner_home,
#       work_agent_identities, work_agent_certificates, work_agent_lists_session_key,
#       provenance (what `run` named the inherited agent: controller_dependency | unknown | none).
#   sockets ROOT
#       What this account can read of the host's socket tables about this run. Facts:
#       mgmt_port, mgmt_established (established TCP connections on the management sshd's
#       port), dest_established, unix_listeners_under_root, unix_listeners_under_runner_home,
#       unix_listeners_named_agent_elsewhere (listening sockets of this account outside ROOT
#       whose path looks like an ssh agent), runtime_fd_readable (whether the runtime's own
#       descriptor list is readable: it is not for a non-dumpable process),
#       runtime_fd_unreadable_reason (non_dumpable_process | no_runtime_recorded | none),
#       mgmt_inbound and dest_inbound (established connections ACCEPTED on the management
#       sshd's and the fixture destination's port: the local port is that port; whoever the
#       peer is), controller_host_known (whether this session names its peer), and then, BY
#       DIRECTION (the orchestrator's ruling of 2026-11-22):
#       outbound_to_controller_host (established TCP connections this host opened TO the
#       controller host: the peer is that address and the local port is not one this host
#       listens on), inbound_from_controller_host (the peer is that address and the local port
#       is a listening one: sessions INTO this host, for example to its port 22, which the
#       owner and other work also open: reported, never judged), observation_channel (this
#       session's own connection: 0 or 1), and the undirected counts as before
#       (established_from_controller_host, established_from_controller_host_other).
#   sshd-log ROOT mgmt|dest
#       The fixture sshd's own log. Facts: lines, connections (`Connection from` lines),
#       accepted (`Accepted` lines).
#   host-facts ROOT
#       Facts: kernel, ssh_version, sshd_version, python.
set -u

action=${1:-}
root=${2:-}
case "$root" in
/*/hm-m06j-*) ;;
*) echo "refused: ROOT is not an absolute hm-m06j-* path" >&2; exit 2 ;;
esac
case "$root" in *[!A-Za-z0-9_./-]* | */../* | */./*) echo "refused: ROOT has an unexpected character" >&2; exit 2 ;; esac
here=$(cd "$(dirname "$0")" && pwd)
base=$here/windows-controller-runner.sh
tool=$here/crosshost-tool.py

# The session's own leftovers, read before anything else touches the environment.
session_agent=${SSH_AUTH_SOCK:-}
session_connection=${SSH_CONNECTION:-}

case "$action" in
runtime-start-with | runtime-offered-stop | policy-config | sshd-check | json | attended | issuer-trust | policy | work | sockets | sshd-log | host-facts) ;;
*)
    [ -f "$base" ] || { echo "missing tool: windows-controller-runner.sh" >&2; exit 3; }
    exec bash "$base" "$@"
    ;;
esac
shift 2

bin=$root/bin/heimdall
acct=$root/acct
home=$root/home

die() { echo "$*" >&2; exit 1; }
account() { id -un; }
sshd_bin() { for c in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do [ -x "$c" ] && { echo "$c"; return 0; }; done; command -v sshd; }
py() { python3 -I "$tool" "$@"; }
# The runner's own commands: a cleared environment, scratch homes, never SSH_AUTH_SOCK.
hm_env() {
    env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$acct" HEIMDALL_HOME="$home" \
        HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC=synchronized "$@"
}
policy_file() { # NAME -> the path, or exit 2
    case "$1" in sshd_config | policy-kc | policy-fc | policy-ae) echo "$root/mgmt/$1" ;; *) echo "refused: not a policy file of this run" >&2; exit 2 ;; esac
}
# NAME=PATH arguments up to `--`: prints them one per line; the rest stays for the caller.
split_fields() {
    fields=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        case "$1" in [a-z_]*=[a-z_0-9.]*) fields+=("$1") ;; *) echo "refused: not NAME=PATH" >&2; exit 2 ;; esac
        shift
    done
    [ "${1:-}" = "--" ] || { echo "refused: no -- before the command" >&2; exit 2; }
    shift
    rest=("$@")
    [ ${#rest[@]} -gt 0 ] || { echo "refused: no command" >&2; exit 2; }
}

case "$action" in
runtime-start-with)
    [ $# -eq 2 ] || exit 2
    case "$1" in synchronized | not_synchronized) ;; *) echo "refused: not a time state" >&2; exit 2 ;; esac
    policy=$(policy_file "$2") || exit 2
    [ -d "$home" ] || die "the runner has not been bootstrapped"
    [ -f "$policy" ] || die "the policy file does not exist"
    [ ! -f "$root/runtime.pid" ] || die "the runner runtime is already recorded as started"
    nohup env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$acct" \
        HEIMDALL_HOME="$home" HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC="$1" \
        HEIMDALL_TEST_RUNNER_SSHD_CONFIG="$policy" \
        "$bin" --home "$home" service run --runner </dev/null >/dev/null 2>"$root/runtime.stderr" &
    echo $! >"$root/runtime.pid"
    i=0
    while [ $i -lt 600 ]; do
        if hm_env "$bin" --home "$home" --json service status </dev/null >/dev/null 2>&1; then echo "runtime=running"; exit 0; fi
        kill -0 "$(cat "$root/runtime.pid")" 2>/dev/null || break
        sleep 0.1
        i=$((i + 1))
    done
    die "the runner runtime did not start"
    ;;
runtime-offered-stop)
    [ $# -eq 0 ] || exit 2
    [ -d "$home" ] || die "the runner has not been bootstrapped"
    [ ! -f "$root/runtime.pid" ] || die "a runner runtime of this script is recorded: use runtime-stop"
    if hm_env "$bin" --home "$home" --json service status </dev/null >/dev/null 2>&1; then
        echo "offered_runtime=running"
    else
        echo "offered_runtime=not_running"
    fi
    hm_env "$bin" --home "$home" --json service stop </dev/null >/dev/null 2>&1
    i=0
    while [ $i -lt 100 ]; do
        if ! hm_env "$bin" --home "$home" --json service status </dev/null >/dev/null 2>&1; then echo "runtime=stopped"; exit 0; fi
        sleep 0.1
        i=$((i + 1))
    done
    die "the runtime the bootstrap started still serves after service stop"
    ;;
policy-config)
    [ $# -eq 1 ] || exit 2
    [ -f "$root/mgmt/sshd_config" ] || die "the management sshd was never configured"
    out=$(policy_file "policy-$1") || exit 2
    case "$1" in
    kc) { cat "$root/mgmt/sshd_config"; printf 'AuthorizedKeysCommand /usr/bin/false\nAuthorizedKeysCommandUser nobody\n'; } >"$out" ;;
    fc) { cat "$root/mgmt/sshd_config"; printf 'ForceCommand /usr/bin/true\n'; } >"$out" ;;
    ae) { cat "$root/mgmt/sshd_config"; printf 'AcceptEnv *\n'; } >"$out" ;;
    esac
    echo "policy=policy-$1"
    ;;
sshd-check)
    [ $# -eq 1 ] || exit 2
    policy=$(policy_file "$1") || exit 2
    sshd=$(sshd_bin) || { echo "missing tool: sshd" >&2; exit 3; }
    [ "$(id -u)" != 0 ] || die "refusing to run the check as root"
    out=$("$sshd" -T -f "$policy" -h "$root/mgmt/host_ed25519" -C "user=$(account),host=localhost,addr=127.0.0.1" </dev/null 2>/dev/null)
    echo "sshd_t_exit=$?"
    val() { printf '%s\n' "$out" | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; found = 1; exit } END { if (!found) print "absent" }'; }
    for k in allowagentforwarding allowtcpforwarding x11forwarding permituserenvironment permituserrc; do echo "$k=$(val "$k")"; done
    if printf '%s\n' "$out" | awk '$1 == "acceptenv" { for (i = 2; i <= NF; i++) if ($i == "*") f = 1 } END { exit !f }'; then echo "acceptenv_all=true"; else echo "acceptenv_all=false"; fi
    for k in forcecommand authorizedkeyscommand; do
        case "$(val "$k")" in none | absent) echo "$k=none" ;; *) echo "$k=set" ;; esac
    done
    ;;
json)
    split_fields "$@"
    out=$(hm_env "$bin" --home "$home" --json "${rest[@]}" </dev/null 2>/dev/null)
    echo "exit=$?"
    printf '%s' "$out" | py envelope-facts code=code reason=data.error.reason ${fields[@]+"${fields[@]}"}
    ;;
attended)
    split_fields "$@"
    args=()
    for f in ${fields[@]+"${fields[@]}"}; do args+=(--field "$f"); done
    hm_env python3 -I "$tool" pty --timeout 120 --transcript "$root/attended.transcript" ${args[@]+"${args[@]}"} -- \
        "$bin" --home "$home" --json "${rest[@]}"
    rm -f "$root/attended.transcript"
    ;;
issuer-trust)
    [ $# -eq 2 ] || exit 2
    case "$1" in "ssh-ed25519 AAAA"*) ;; *) echo "refused: not an Ed25519 public key line" >&2; exit 2 ;; esac
    case "$1$2" in *[!A-Za-z0-9+/=\ @._:-]*) echo "refused: unexpected character" >&2; exit 2 ;; esac
    printf '%s\n' "$1" >"$root/issuer-ca.pub"
    hm_env python3 -I "$tool" pty --timeout 120 --transcript "$root/attended.transcript" -- \
        "$bin" --home "$home" --json remote issuer-trust add "$root/issuer-ca.pub" --controller "$2"
    rm -f "$root/attended.transcript"
    ;;
policy)
    [ $# -eq 1 ] || exit 2
    case "$1" in *[!a-z0-9-]*) exit 2 ;; esac
    hm_env "$bin" --home "$home" --json inspect policies </dev/null 2>/dev/null | python3 -I -c '
import json, sys
try:
    items = json.load(sys.stdin)["data"]["items"]
except Exception:
    items = []
p = next((i for i in items if i.get("policy_id") == sys.argv[1]), None)
print("present=%s" % ("true" if p is not None else "false"))
if p is not None:
    print("paused=%s" % ("true" if p.get("paused_since") else "false"))
    print("cutoff=%s" % ("true" if p.get("cutoff_at") else "false"))
' "$1"
    ;;
work)
    [ $# -eq 2 ] || exit 2
    case "$1$2" in *[!A-Za-z0-9_-]*) echo "refused: unexpected character" >&2; exit 2 ;; esac
    w=$root/work
    rm -rf -- "$w"
    mkdir -m 700 "$w" || die "the work scratch could not be created"
    session_keys=""
    if [ -n "$session_agent" ]; then
        session_keys=$(env -i PATH=/usr/bin:/bin SSH_AUTH_SOCK="$session_agent" ssh-add -L 2>/dev/null | grep -E '^(ssh-|ecdsa-|sk-)' | awk '{ print $1 " " $2 }' || true)
    fi
    # The launcher: the runner owner's own command, with what the session left behind.
    launcher=(env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$acct" HEIMDALL_HOME="$home"
        HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC=synchronized HM_XH_SESSION_MARK=1)
    [ -z "$session_agent" ] || launcher+=(SSH_AUTH_SOCK="$session_agent")
    [ -z "$session_connection" ] || launcher+=(SSH_CONNECTION="$session_connection")
    "${launcher[@]}" "$bin" --home "$home" --non-interactive run --profile runner-profile \
        --work-id "$1" --request-id "$2" -- /bin/sh -c '/usr/bin/env; echo hm-xh-agent; ssh-add -L; echo hm-xh-end' \
        </dev/null >"$w/out" 2>"$w/err"
    echo "exit=$?"
    echo "session_agent=$([ -n "$session_agent" ] && echo true || echo false)"
    echo "session_agent_keys=$(printf '%s' "$session_keys" | grep -c . || true)"
    echo "session_connection=$([ -n "$session_connection" ] && echo true || echo false)"
    sed -n '1,/^hm-xh-agent$/p' "$w/out" | grep -v '^hm-xh-agent$' >"$w/env"
    sed -n '/^hm-xh-agent$/,/^hm-xh-end$/p' "$w/out" | grep -E '^(ssh-|ecdsa-|sk-)' >"$w/agent" || true
    extra=$(cut -d= -f1 "$w/env" | grep -vxE 'HOME|USER|LOGNAME|HEIMDALL_HOME|XDG_CONFIG_HOME|XDG_STATE_HOME|XDG_RUNTIME_DIR|TERM|TZ|LANG|LC_ALL|PATH|SSH_AUTH_SOCK|PWD|SHLVL|_|OLDPWD' | sort -u | tr '\n' ',' | sed 's/,$//')
    echo "work_env_extra=${extra:-none}"
    echo "work_has_session_marker=$(grep -q '^HM_XH_SESSION_MARK=' "$w/env" && echo true || echo false)"
    echo "work_has_ssh_connection=$(grep -q '^SSH_CONNECTION=' "$w/env" && echo true || echo false)"
    work_agent=$(sed -n 's/^SSH_AUTH_SOCK=//p' "$w/env" | head -n 1)
    if [ -n "$session_agent" ] && { [ "$work_agent" = "$session_agent" ] || grep -qF -- "$session_agent" "$w/env"; }; then echo "work_agent_is_session_agent=true"; else echo "work_agent_is_session_agent=false"; fi
    under=false
    if [ -n "$work_agent" ]; then
        resolved=$(readlink -f -- "$work_agent" 2>/dev/null || echo "$work_agent")
        case "$resolved" in "$(readlink -f -- "$home")"/*) under=true ;; esac
    fi
    echo "work_agent_under_runner_home=$under"
    echo "work_agent_identities=$(grep -c . "$w/agent" || true)"
    echo "work_agent_certificates=$(grep -c -- '-cert-v01@openssh.com ' "$w/agent" || true)"
    listed=false
    if [ -n "$session_keys" ]; then
        while IFS= read -r k; do [ -n "$k" ] && grep -qF -- "$k" "$w/agent" && listed=true; done <<EOF
$session_keys
EOF
    fi
    echo "work_agent_lists_session_key=$listed"
    if grep -q 'provenance: controller_dependency' "$w/err"; then echo "provenance=controller_dependency"
    elif grep -q 'provenance: unknown' "$w/err"; then echo "provenance=unknown"
    else echo "provenance=none"; fi
    if [ -n "$session_agent" ] && grep -qF -- "$session_agent" "$w/err"; then echo "stderr_names_session_socket=true"; else echo "stderr_names_session_socket=false"; fi
    rm -rf -- "$w"
    ;;
sockets)
    command -v ss >/dev/null 2>&1 || { echo "missing tool: ss" >&2; exit 3; }
    mport=$(cat "$root/mgmt/port" 2>/dev/null) || mport=""
    dport=$(cat "$root/dest/port" 2>/dev/null) || dport=""
    count_tcp() { # PORT: established connections with that local or peer port on loopback
        [ -n "$1" ] || { echo unknown; return; }
        ss -Htn state established "( sport = :$1 or dport = :$1 )" 2>/dev/null | grep -c . || true
    }
    echo "mgmt_port=$([ -n "$mport" ] && echo recorded || echo none)"
    count_in() { # PORT: established connections accepted on that local port
        [ -n "$1" ] || { echo unknown; return; }
        ss -Htn state established "( sport = :$1 )" 2>/dev/null | grep -c . || true
    }
    echo "mgmt_established=$(count_tcp "$mport")"
    echo "dest_established=$(count_tcp "$dport")"
    echo "mgmt_inbound=$(count_in "$mport")"
    echo "dest_inbound=$(count_in "$dport")"
    unix=$(ss -Hxl 2>/dev/null | awk '{ print $5 }')
    real_root=$(readlink -f -- "$root")
    real_home=$(readlink -f -- "$home" 2>/dev/null || echo "$home")
    echo "unix_listeners_under_root=$(printf '%s\n' "$unix" | grep -c -e "^$root/" -e "^$real_root/" || true)"
    echo "unix_listeners_under_runner_home=$(printf '%s\n' "$unix" | grep -c -e "^$home/" -e "^$real_home/" || true)"
    # Sockets of this account elsewhere that look like an ssh agent: a forwarded agent's
    # socket is /tmp/ssh-*/agent.* owned by the account (sshd creates it for the session).
    n=0
    for s in /tmp/ssh-*/agent.*; do
        [ -S "$s" ] && [ -O "$s" ] && n=$((n + 1))
    done
    echo "unix_listeners_named_agent_elsewhere=$n"
    pid=$(cat "$root/runtime.pid" 2>/dev/null) || pid=""
    if [ -n "$pid" ] && ls "/proc/$pid/fd" >/dev/null 2>&1; then
        echo "runtime_fd_readable=true"
        echo "runtime_fd_unreadable_reason=none"
    else
        echo "runtime_fd_readable=false"
        # The runner runtime marks itself non-dumpable (PR_SET_DUMPABLE=0), so /proc/<pid>/fd
        # and /proc/<pid>/environ are root's to read, not this account's.
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "runtime_fd_unreadable_reason=non_dumpable_process"; else echo "runtime_fd_unreadable_reason=no_runtime_recorded"; fi
    fi
    # ⟨W5k, the "No silent controller socket" row, part b⟩ This host's established TCP
    # connections from the CONTROLLER HOST: the peer address of this very session (the harness
    # runs on the controller host, and SSH_CONNECTION is `client_addr client_port server_addr
    # server_port`). That session's own connection is the observation channel: it is counted
    # apart (exactly one peer port and local port) and never subtracted from anything else.
    if [ -n "$session_connection" ]; then
        # shellcheck disable=SC2086
        set -- $session_connection
        if [ $# -eq 4 ]; then
            echo "controller_host_known=true"
            # This host's listening TCP ports: a connection whose local port is one of them
            # was accepted here (inbound); any other was opened from here (outbound).
            listening=$(ss -Htln 2>/dev/null | awk '{ n = split($4, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }' | sort -u | paste -sd, -)
            ss -Htn state established 2>/dev/null | py connections --host "$1" --own "$2:$4" --listening "${listening:-none}" |
                sed -e 's/^established_from_host_other=/established_from_controller_host_other=/' \
                    -e 's/^established_from_host=/established_from_controller_host=/' \
                    -e 's/^own_channel=/observation_channel=/' \
                    -e 's/^inbound_from_host=/inbound_from_controller_host=/' \
                    -e 's/^outbound_to_host=/outbound_to_controller_host=/'
        else
            echo "controller_host_known=false"
        fi
    else
        echo "controller_host_known=false"
    fi
    ;;
sshd-log)
    [ $# -eq 1 ] || exit 2
    case "$1" in mgmt | dest) ;; *) exit 2 ;; esac
    log=$root/$1/sshd.log
    [ -f "$log" ] || die "the $1 sshd has no log"
    echo "lines=$(grep -c '' "$log" || true)"
    echo "connections=$(grep -c 'Connection from ' "$log" || true)"
    echo "accepted=$(grep -c 'Accepted ' "$log" || true)"
    ;;
host-facts)
    echo "kernel=$(uname -sr)"
    echo "ssh_version=$(ssh -V 2>&1 | head -n 1)"
    sshd=$(sshd_bin) && echo "sshd_version=$("$sshd" -V 2>&1 | head -n 1)"
    echo "python=$(python3 -I -c 'import sys; print(sys.version.split()[0])')"
    ;;
esac
