#!/usr/bin/env bash
# M06 W5 (ADR-0012 §2.6, the 2026-11-22 paragraph): the RUNNER side of the Windows controller
# journey (tests/native/m06/run-windows-controller.ps1). It runs as the default, non-root user of
# the PC's EXISTING WSL distribution (or, for the script's rehearsal, on the build host; the
# cross-host journey stages it on its runner host), and only ever inside ROOT, ONE scratch
# directory it creates itself and removes itself. Nothing is installed, no service is enabled and
# no file outside ROOT is written: a tool that is missing is reported (exit 3), never installed.
#
#   windows-controller-runner.sh ACTION ROOT [ARGS...]
#
# ROOT must be an absolute path whose last component starts with `hm-m06j-`. Every action prints
# `key=value` facts on stdout (public facts only) and exits 0, or says why on stderr and exits 1
# (2 for a refused argument, 3 for a missing tool or prerequisite, 4 when ROOT exists already).
#
# Shared with the standard harness (tests/native/m02/remote-lib.sh, the fixture sshds every PC
# job starts in the existing distribution): hm2_sshd_bin (where the sshd program is),
# hm2_port, hm2_start_time, hm2_sanitize_env and hm2_stop_recorded (a recorded sshd is stopped
# only when its PID's start time and configuration path still match). They are the library's
# own definitions when the caller sends that file ahead of this one on stdin (the journey on the
# PC, as the standard harness does) or when it is found beside this script or in ../m02 (the
# rehearsal). Staged alone (the cross-host journey), the copies below are used: they mirror
# remote-lib.sh's functions of the same names exactly (tests/native/m06/selftest.sh compares
# them). The fixture sshd's start is hm2_sshd_start's sequence (`sshd -t`, `sshd -D -f <config>
# -E <log>`, the wait for "Server listening on 127.0.0.1 port N.", DIR/state with pid, start and
# config), with this journey's own configuration, a host key made once and a port that is kept
# across a restart.
#
#   tools ROOT [WIN_HEIMDALL WIN_DRIVER]
#       check, and change nothing: every tool the journey needs here (missing ones are named:
#       `missing=a,b`, exit 3), that the account is not root, that $HOME can hold the scratch
#       directory and that <$HOME>/<last component of ROOT> does not exist; with two Windows
#       paths, that `wslpath` translates them and both files are readable. `blocked=<reason>`
#       and exit 3 otherwise. Facts: root (<$HOME>/<last component of ROOT>), heimdall and
#       driver (the translated paths), ssh, sshd (versions).
#   prepare ROOT HEIMDALL SHA256 DRIVER SHA256
#       create ROOT (mode 700; exit 4 and nothing touched when it exists); copy the Linux
#       `heimdall` and the journey driver (the Linux build of e2e_windows_controller_m06) into
#       ROOT/bin after checking their SHA-256; create the scratch account home ROOT/acct (its own
#       .ssh, mode 700), the runner's Heimdall home path ROOT/home (not created: `remote init`
#       makes it), and per-run Ed25519 host keys for two fixture sshds; check that this host's
#       sshd accepts the fixture configuration unprivileged (`sshd -t`; exit 3 otherwise). A
#       failure after ROOT was created removes it again. Facts: account, runner_program,
#       runner_home, runner_sha256, mgmt_host_key, dest_host_key.
#   authorize ROOT PUBLIC_KEY_LINE | authorize ROOT TYPE BODY
#       the controller's existing access: one plain public key line in ROOT/acct/.ssh/authorized_keys.
#   sshd-serve ROOT mgmt|dest
#       start that fixture sshd, unprivileged, on 127.0.0.1 only (a free high port; the port chosen
#       at the first start is kept, so a restart is the same endpoint), as a child of THIS process,
#       which then waits for it: the caller holds this process for as long as the sshd serves (the
#       standard harness's way; a held `wsl.exe` on the PC). mgmt reads
#       ROOT/acct/.ssh/authorized_keys (where the runner's `remote init` writes its line, through
#       `SetEnv HEIMDALL_TEST_SSH_HOME=ROOT/acct`, so no real ~/.ssh is read or written); dest
#       trusts only ROOT/dest/ca.pub for the principals in ROOT/dest/principals/<account>. Both
#       set the sessions' HOME and ZDOTDIR to ROOT/acct and BASH_ENV empty (sshd's one SetEnv
#       line), so the account's login shell reads none of the account's own startup files.
#       Facts: port, then ready=1 once it listens.
#   sshd-start ROOT mgmt|dest
#       the same sshd, detached (`nohup`), for a caller that does not hold a session (the
#       cross-host journey). Facts: port.
#   sshd-stop ROOT mgmt|dest
#       stop exactly the recorded sshd (its PID must still have the recorded start time and name
#       this ROOT's configuration). Facts: stopped=stopped|gone|none|mismatch|still-running.
#   trust-ca ROOT CA_PUBLIC_KEY_LINE PRINCIPAL | trust-ca ROOT TYPE BODY PRINCIPAL
#       the destination's administrator trusts the controller's CA for PRINCIPAL.
#   seed ROOT
#       the runner's catalog (driver entry seed_runner), after the bootstrap, runtime stopped.
#       Facts: runner_environment.
#   runtime-serve ROOT
#       `heimdall service run --runner` on ROOT/home as a child of THIS process, which then waits
#       for it (held by the caller, as sshd-serve). Facts: runtime=running, then ready=1.
#   runtime-start ROOT | runtime-stop ROOT
#       the same runtime, detached, and its stop through `service stop` on that home (then, only
#       when it still runs and its recorded start time and program still match, a TERM).
#       Facts: runtime=running|stopped.
#   ensure ROOT WORK_ID REQUEST_ID LIFETIME
#       the runner owner's local `access ensure` for the journey's pair. Facts: code, grant,
#       endpoint, refresh_dependency.
#   identities ROOT ENDPOINT
#       what the binding's endpoint lists. Facts: identities (a count), certificate_ca (the
#       signing CA's fingerprint of the first, or none).
#   onward ROOT ENDPOINT
#       one onward login from the runner to the destination sshd through that endpoint, with the
#       fixture isolation options. Facts: onward=ok|refused.
#   processes ROOT
#       Facts: runtime_parent_is_sshd (whether the runner runtime is a child of an sshd session),
#       runtime_has_ssh_auth_sock (whether it was started with SSH_AUTH_SOCK).
#   keepalive-before ROOT | keepalive-record ROOT
#       the caller's keep-alive (on the PC: one held `wsl.exe ... --exec /bin/sleep infinity`).
#       `before` records this account's `sleep infinity` processes (ROOT/keepalive.before);
#       `record`, after the caller started its own, records the ONE new such process
#       (ROOT/keepalive.state: pid, start). Facts: keepalive=recorded|unidentified.
#   cleanup ROOT
#       stop the runtime and both sshds as above; when a keep-alive was recorded, wait for it to
#       be gone (the caller ends it through its own handle first) and, only when the recorded one
#       still runs with the recorded start time, signal it; then remove ROOT. Facts:
#       removed=yes|no and, only when a keep-alive was recorded, keepalive=gone|stopped|left.
#   verify ROOT
#       after the cleanup, changing nothing. Facts: scratch=gone|present, processes_left (the
#       processes whose command line names ROOT).
set -u

action=${1:-}
root=${2:-}
case "$root" in
/*/hm-m06j-*) ;;
*) echo "refused: ROOT is not an absolute hm-m06j-* path" >&2; exit 2 ;;
esac
case "$root" in *[!A-Za-z0-9_./-]* | */../* | */./*) echo "refused: ROOT has an unexpected character" >&2; exit 2 ;; esac
shift 2

bin=$root/bin/heimdall
driver=$root/bin/journey-driver
acct=$root/acct
home=$root/home
# ⟨AGENTS.md "Boundaries"; M06-W5-R04⟩ Every `heimdall` this script starts gets the three
# fixture key stores, in ROOT, even where no store is reachable: never the account's real
# keychain, Secret Service or credential store.
mgmt_store="fixture-file:$root/k_mgmt.fixture"
iroh_store=$root/k_iroh
PAIR_DESTINATION=h1
PROFILE=runner-profile

die() { echo "$*" >&2; exit 1; }
need() { for t in "$@"; do command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 3; }; done; }
account() { id -un; }
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# The standard harness's helpers (see the header): already defined when remote-lib.sh was sent
# ahead of this script, else that file beside this script or in ../m02, else the mirror below.
if ! declare -F hm2_stop_recorded >/dev/null 2>&1 && [ -n "${BASH_SOURCE[0]:-}" ]; then
    lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || lib_dir=""
    for lib in "$lib_dir/remote-lib.sh" "$lib_dir/../m02/remote-lib.sh"; do
        if [ -n "$lib_dir" ] && [ -f "$lib" ]; then
            # shellcheck disable=SC1090,SC1091
            . "$lib"
            break
        fi
    done
fi
if ! declare -F hm2_stop_recorded >/dev/null 2>&1; then
# BEGIN mirror of tests/native/m02/remote-lib.sh (hm2_sanitize_env, hm2_sshd_bin, hm2_port,
# hm2_start_time, hm2_stop_recorded): the same text, compared by tests/native/m06/selftest.sh.
hm2_sanitize_env() {
    local sock=unset n_git=0 n_hm=0 v
    [ -n "${SSH_AUTH_SOCK:-}" ] && sock="set"
    for v in $(env | sed -n 's/^\(GIT_[A-Za-z0-9_]*\)=.*/\1/p'); do
        unset "$v"
        n_git=$((n_git + 1))
    done
    for v in $(env | sed -n 's/^\(HEIMDALL_[A-Za-z0-9_]*\)=.*/\1/p'); do
        unset "$v"
        n_hm=$((n_hm + 1))
    done
    unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY \
        HM_FIXTURE_SSHD_HOST HM_FIXTURE_SSHD_PORT HM_FIXTURE_SSHD_HOST_KEY \
        HM_FIXTURE_SSHD_AUTHORIZED_KEYS HM_FIXTURE_SSHD_LOG HM_FIXTURE_SSHD_USER \
        HM_FIXTURE_SSHD_STRICT_PORT HM_FIXTURE_SSHD_STRICT_HOST_KEY \
        HM_FIXTURE_SSHD_STRICT_AUTHORIZED_KEYS HM_FIXTURE_SSHD_STRICT_LOG HM_FIXTURE_HOOK HM_REPO_ROOT \
        HM_FIXTURE_SSHD_REGISTRY HM_FIXTURE_SSHD_REGISTRY_REMOTE
    echo "inherited-ssh-auth-sock=$sock (unset for the run)"
    echo "inherited-git-variables=$n_git (unset for the run)"
    echo "inherited-heimdall-variables=$n_hm (unset for the run)"
}
hm2_sshd_bin() {
    local p
    p=$(command -v sshd 2>/dev/null) && { echo "$p"; return 0; }
    for p in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}
hm2_port() {
    local r
    r=$(od -An -N2 -tu2 /dev/urandom | tr -d ' \n')
    echo $((20000 + r % 40000))
}
hm2_start_time() {
    if [ -r "/proc/$1/stat" ]; then
        sed -e 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{ print $20 }'
    else
        ps -o lstart= -p "$1" 2>/dev/null | tr -s ' '
    fi
}
hm2_stop_recorded() {
    local pid start cfg now i
    [ -f "$1/state" ] || { echo none; return 0; }
    pid=$(sed -n 's/^pid=//p' "$1/state")
    start=$(sed -n 's/^start=//p' "$1/state")
    cfg=$(sed -n 's/^config=//p' "$1/state")
    case "$pid" in '' | *[!0-9]*) echo none; return 0 ;; esac
    [ -r "/proc/$pid/stat" ] || { echo gone; return 0; }
    now=$(hm2_start_time "$pid")
    if [ -n "$start" ] && [ "$now" = "$start" ] && [ -n "$cfg" ] &&
        tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -qF -- " -f $cfg "; then
        kill "$pid" 2>/dev/null || true
        # Gone, or a zombie waiting to be reaped, counts as stopped.
        i=0
        while [ $i -lt 50 ] && [ -r "/proc/$pid/stat" ] &&
            [ "$(sed -e 's/^.*) //' "/proc/$pid/stat" 2>/dev/null | cut -c1)" != Z ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if [ -r "/proc/$pid/stat" ] && [ "$(sed -e 's/^.*) //' "/proc/$pid/stat" 2>/dev/null | cut -c1)" != Z ]; then
            echo still-running
        else
            echo stopped
        fi
    else
        echo mismatch
    fi
}
# END mirror
fi

command_of() { LC_ALL=C ps -w -w -o command= -p "$1" 2>/dev/null; }
free_port() {
    local p i=0
    while [ $i -lt 50 ]; do
        p=$(hm2_port)
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then echo "$p"; return 0; fi
        i=$((i + 1))
    done
    return 1
}
# The runner's own commands: a cleared environment, scratch homes, never SSH_AUTH_SOCK.
hm() {
    env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$acct" HEIMDALL_HOME="$home" \
        HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC=synchronized \
        HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt_store" \
        HEIMDALL_TEST_IROH_KEY_STORE="$iroh_store" \
        "$bin" --home "$home" "$@"
}
# One string field of a JSON envelope on stdin, by path (a.b.c); `none` when absent.
field() {
    python3 -I -c '
import json, sys
try:
    v = json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        v = v[int(k)] if isinstance(v, list) else v[k]
    print(v if isinstance(v, str) else json.dumps(v))
except Exception:
    print("none")
' "$1"
}

sshd_config() { # NAME PORT
    local d=$root/$1
    cat <<EOF
ListenAddress 127.0.0.1
Port $2
AddressFamily inet
HostKey "$d/host_ed25519"
PidFile none
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
PermitUserRC no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
UseDNS no
LogLevel VERBOSE
EOF
    if [ "$1" = mgmt ]; then
        cat <<EOF
AuthorizedKeysFile "$acct/.ssh/authorized_keys"
SetEnv HOME="$acct" ZDOTDIR="$acct" BASH_ENV= HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC=synchronized HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt_store" HEIMDALL_TEST_IROH_KEY_STORE="$iroh_store"
EOF
    else
        cat <<EOF
AuthorizedKeysFile none
SetEnv HOME="$acct" ZDOTDIR="$acct" BASH_ENV= HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt_store" HEIMDALL_TEST_IROH_KEY_STORE="$iroh_store"
TrustedUserCAKeys "$d/ca.pub"
AuthorizedPrincipalsFile "$d/principals/%u"
EOF
    fi
}

sshd_start() { # NAME detached|held
    local name=$1 mode=$2 d=$root/$1 sshd port pid i
    case "$name" in mgmt | dest) ;; *) echo "refused: not a fixture sshd" >&2; exit 2 ;; esac
    [ "$(id -u)" != 0 ] || die "refusing to run a fixture sshd as root"
    sshd=$(hm2_sshd_bin) || { echo "missing tool: sshd" >&2; exit 3; }
    [ -f "$d/state" ] && die "the $name sshd is already recorded as started"
    port=$(cat "$d/port" 2>/dev/null) || port=""
    [ -n "$port" ] || { port=$(free_port) || die "no free port"; echo "$port" >"$d/port"; }
    sshd_config "$name" "$port" >"$d/sshd_config"
    "$sshd" -t -f "$d/sshd_config" </dev/null >/dev/null 2>&1 || die "sshd -t rejected the $name configuration"
    : >"$d/sshd.log"
    # As the standard harness: nothing of the caller's agent, Git or Heimdall environment reaches it.
    hm2_sanitize_env >/dev/null
    if [ "$mode" = held ]; then
        "$sshd" -D -f "$d/sshd_config" -E "$d/sshd.log" </dev/null >/dev/null 2>&1 &
    else
        nohup "$sshd" -D -f "$d/sshd_config" -E "$d/sshd.log" </dev/null >/dev/null 2>&1 &
    fi
    pid=$!
    i=0
    while [ $i -lt 100 ]; do
        if grep -q "Server listening on 127.0.0.1 port $port\." "$d/sshd.log" 2>/dev/null; then
            printf 'pid=%s\nstart=%s\nconfig=%s\n' "$pid" "$(hm2_start_time "$pid")" "$d/sshd_config" >"$d/state"
            echo "port=$port"
            if [ "$mode" = held ]; then
                echo "ready=1"
                # Held: this process ends when the sshd does (`sshd-stop` from another session).
                wait "$pid" 2>/dev/null || true
            fi
            return 0
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
        i=$((i + 1))
    done
    kill "$pid" 2>/dev/null
    die "the $name sshd did not report listening"
}

# Off Linux (the rehearsal on the build host: no /proc), the same rule as hm2_stop_recorded with
# `ps`: the recorded PID is signalled only when its start time and configuration path match.
stop_recorded_ps() { # DIR -> none|gone|stopped|mismatch|still-running
    local pid start cfg i
    [ -f "$1/state" ] || { echo none; return 0; }
    pid=$(sed -n 's/^pid=//p' "$1/state")
    start=$(sed -n 's/^start=//p' "$1/state")
    cfg=$(sed -n 's/^config=//p' "$1/state")
    case "$pid" in '' | *[!0-9]*) echo none; return 0 ;; esac
    kill -0 "$pid" 2>/dev/null || { echo gone; return 0; }
    if [ -n "$start" ] && [ "$(hm2_start_time "$pid")" = "$start" ] && [ -n "$cfg" ] && command_of "$pid" | grep -qF -- "-f $cfg"; then
        kill "$pid" 2>/dev/null
        i=0
        while [ $i -lt 50 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
        if kill -0 "$pid" 2>/dev/null; then echo still-running; else echo stopped; fi
    else
        echo mismatch
    fi
}

sshd_stop() { # NAME -> prints stopped=...
    local d=$root/$1 r
    case "$1" in mgmt | dest) ;; *) echo "refused: not a fixture sshd" >&2; exit 2 ;; esac
    if [ -r /proc/self/stat ]; then r=$(hm2_stop_recorded "$d"); else r=$(stop_recorded_ps "$d"); fi
    echo "stopped=$r"
    case "$r" in stopped | gone | none) rm -f "$d/state"; return 0 ;; *) return 1 ;; esac
}

runtime_spawn() { # detached|held: starts the runner runtime and records it
    [ -d "$home" ] || die "the runner has not been bootstrapped"
    [ ! -f "$root/runtime.pid" ] || die "the runner runtime is already recorded as started"
    if [ "$1" = held ]; then
        env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$acct" \
            HEIMDALL_HOME="$home" HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC=synchronized \
            HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt_store" \
            HEIMDALL_TEST_IROH_KEY_STORE="$iroh_store" \
            HEIMDALL_TEST_RUNNER_SSHD_CONFIG="$root/mgmt/sshd_config" \
            "$bin" --home "$home" service run --runner </dev/null >/dev/null 2>"$root/runtime.stderr" &
    else
        nohup env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$acct" \
            HEIMDALL_HOME="$home" HEIMDALL_TEST_SSH_HOME="$acct" HEIMDALL_TEST_TIME_SYNC=synchronized \
            HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt_store" \
            HEIMDALL_TEST_IROH_KEY_STORE="$iroh_store" \
            HEIMDALL_TEST_RUNNER_SSHD_CONFIG="$root/mgmt/sshd_config" \
            "$bin" --home "$home" service run --runner </dev/null >/dev/null 2>"$root/runtime.stderr" &
    fi
    runtime_pid=$!
    echo "$runtime_pid" >"$root/runtime.pid"
    hm2_start_time "$runtime_pid" >"$root/runtime.start"
    local i=0
    while [ $i -lt 600 ]; do
        if hm --json service status </dev/null >/dev/null 2>&1; then echo "runtime=running"; return 0; fi
        kill -0 "$runtime_pid" 2>/dev/null || break
        sleep 0.1
        i=$((i + 1))
    done
    die "the runner runtime did not start"
}

runtime_stop() {
    if [ -x "$bin" ] && [ -d "$home" ]; then
        hm --json service stop </dev/null >/dev/null 2>&1
    fi
    local pid start i=0
    pid=$(cat "$root/runtime.pid" 2>/dev/null) || pid=""
    case "$pid" in '' | *[!0-9]*) echo "runtime=stopped"; return 0 ;; esac
    while [ $i -lt 100 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
        # `service stop` did not end it: signal exactly the recorded process, and only when its
        # start time and its program are still the recorded ones.
        start=$(cat "$root/runtime.start" 2>/dev/null) || start=""
        if [ -n "$start" ] && [ "$(hm2_start_time "$pid")" = "$start" ] && command_of "$pid" | grep -qF -- "$bin --home $home service run"; then
            kill "$pid" 2>/dev/null
            i=0
            while [ $i -lt 100 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
        fi
    fi
    if kill -0 "$pid" 2>/dev/null; then echo "runtime=still-running"; return 1; fi
    rm -f "$root/runtime.pid" "$root/runtime.start"
    echo "runtime=stopped"
}

# This account's `sleep infinity` processes, one "pid start" line each (Linux /proc; none
# elsewhere): what the caller's keep-alive looks like from inside.
sleepers() {
    local p pid
    for p in /proc/[0-9]*; do
        [ -O "$p" ] || continue
        case "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)" in
        "/bin/sleep infinity " | "/usr/bin/sleep infinity " | "sleep infinity ") ;;
        *) continue ;;
        esac
        pid=${p#/proc/}
        echo "$pid $(hm2_start_time "$pid")"
    done
}
# The sleepers that were not there at `keepalive-before`.
new_sleepers() {
    local line
    sleepers | while IFS= read -r line; do
        grep -qxF -- "$line" "$root/keepalive.before" 2>/dev/null || echo "$line"
    done
}
# After the caller ended its keep-alive: gone, stopped (the recorded one, signalled), or left.
keepalive_end() {
    local i=0 left pid start
    [ -f "$root/keepalive.before" ] || { echo none; return 0; }
    left=$(new_sleepers)
    while [ -n "$left" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); left=$(new_sleepers); done
    [ -n "$left" ] || { echo gone; return 0; }
    pid=$(sed -n 's/^pid=//p' "$root/keepalive.state" 2>/dev/null)
    start=$(sed -n 's/^start=//p' "$root/keepalive.state" 2>/dev/null)
    case "$pid" in '' | *[!0-9]*) echo left; return 1 ;; esac
    # Only the recorded one, and only while it is still that process (a sleeper, same start).
    if [ -n "$start" ] && printf '%s\n' "$left" | grep -qxF -- "$pid $start"; then
        kill "$pid" 2>/dev/null
        i=0
        while [ -n "$(new_sleepers)" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    fi
    if [ -n "$(new_sleepers)" ]; then echo left; return 1; fi
    echo stopped
}

case "$action" in
tools)
    [ $# -eq 0 ] || [ $# -eq 2 ] || { echo "usage: tools ROOT [WIN_HEIMDALL WIN_DRIVER]" >&2; exit 2; }
    missing=""
    for t in ssh ssh-keygen ssh-add python3 ps awk sed grep env nohup id cp mkdir rm tr cut head cat chmod sleep od; do
        command -v "$t" >/dev/null 2>&1 || missing="$missing,$t"
    done
    hm2_sshd_bin >/dev/null 2>&1 || missing="$missing,sshd"
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || missing="$missing,sha256sum"
    if [ $# -eq 2 ]; then
        command -v wslpath >/dev/null 2>&1 || missing="$missing,wslpath"
        [ -x /bin/sleep ] || missing="$missing,/bin/sleep"
    fi
    if [ -n "$missing" ]; then
        echo "missing=${missing#,}"
        echo "missing tool: ${missing#,}" >&2
        exit 3
    fi
    [ "$(id -u)" != 0 ] || { echo "blocked=root_account"; exit 3; }
    parent=${HOME:-}
    case "$parent" in /*) ;; *) echo "blocked=no_home"; exit 3 ;; esac
    case "$parent" in *[!A-Za-z0-9_./-]* | */../* | */./*) echo "blocked=home_is_not_a_plain_path"; exit 3 ;; esac
    parent=${parent%/}
    if [ ! -d "$parent" ] || [ ! -w "$parent" ] || [ ! -x "$parent" ]; then echo "blocked=home_is_not_writable"; exit 3; fi
    planned=$parent/${root##*/}
    if [ -e "$planned" ] || [ -L "$planned" ]; then echo "blocked=scratch_directory_exists"; exit 3; fi
    if [ $# -eq 2 ]; then
        if ! { h=$(wslpath -u "$1" 2>/dev/null) && d=$(wslpath -u "$2" 2>/dev/null); }; then echo "blocked=windows_path_not_translated"; exit 3; fi
        if [ ! -f "$h" ] || [ ! -r "$h" ] || [ ! -f "$d" ] || [ ! -r "$d" ]; then echo "blocked=linux_binaries_not_readable_from_the_distribution"; exit 3; fi
        echo "heimdall=$h"
        echo "driver=$d"
    fi
    echo "root=$planned"
    echo "ssh=$(ssh -V </dev/null 2>&1 | head -n 1 | tr -d '\r')"
    echo "sshd=$("$(hm2_sshd_bin)" -V </dev/null 2>&1 | head -n 1 | tr -d '\r')"
    ;;
prepare)
    [ $# -eq 4 ] || { echo "usage: prepare ROOT HEIMDALL SHA256 DRIVER SHA256" >&2; exit 2; }
    need ssh ssh-keygen ssh-add python3
    sshd=$(hm2_sshd_bin) || { echo "missing tool: sshd" >&2; exit 3; }
    for sum in "$2" "$4"; do
        case "$sum" in *[!0-9a-f]*) echo "refused: a digest is not lowercase hex" >&2; exit 2 ;; esac
        [ ${#sum} -eq 64 ] || { echo "refused: a digest is not 64 characters" >&2; exit 2; }
    done
    [ "$(sha256_of "$1")" = "$2" ] || die "the heimdall binary does not have the expected SHA-256"
    [ "$(sha256_of "$3")" = "$4" ] || die "the journey driver does not have the expected SHA-256"
    # Exclusive: an existing ROOT is not this run's and is never touched (exit 4).
    mkdir -m 700 -- "$root" 2>/dev/null || { echo "ROOT exists or cannot be created" >&2; exit 4; }
    # From here on ROOT is this call's own: a failure removes it again.
    undo() { rm -rf -- "$root"; echo "$1" >&2; exit "${2:-1}"; }
    mkdir -m 700 "$root/bin" "$acct" "$acct/.ssh" "$root/mgmt" "$root/dest" "$root/dest/principals" "$root/onward" "$iroh_store" || undo "ROOT could not be laid out"
    if ! { cp -- "$1" "$bin" && cp -- "$3" "$driver" && chmod 700 "$bin" "$driver"; }; then undo "the binaries could not be staged"; fi
    (umask 077 && : >"$acct/.ssh/authorized_keys" && : >"$root/dest/ca.pub") || undo "ROOT could not be laid out"
    for n in mgmt dest; do
        ssh-keygen -q -t ed25519 -N '' -C hm-m06j-fixture-host -f "$root/$n/host_ed25519" </dev/null >/dev/null 2>&1 || undo "ssh-keygen failed"
    done
    # Checked, not arranged: this host's sshd must accept the fixture configuration as this
    # user (it needs nothing of the host but what an installed OpenSSH server already has).
    if [ "$(id -u)" != 0 ]; then
        sshd_config mgmt 22222 >"$root/mgmt/sshd_config.check"
        "$sshd" -t -f "$root/mgmt/sshd_config.check" </dev/null >/dev/null 2>&1 ||
            undo "missing prerequisite: sshd does not accept the fixture configuration as this user (sshd -t)" 3
        rm -f "$root/mgmt/sshd_config.check"
    fi
    echo "account=$(account)"
    echo "runner_program=$bin"
    echo "runner_home=$home"
    echo "runner_sha256=$(sha256_of "$bin")"
    echo "mgmt_host_key=$(awk '{ print $1 " " $2 }' "$root/mgmt/host_ed25519.pub")"
    echo "dest_host_key=$(awk '{ print $1 " " $2 }' "$root/dest/host_ed25519.pub")"
    ;;
authorize)
    # One key line, or its type and body as two arguments (the form the journey on the PC sends,
    # so that no argument it hands wsl.exe needs quoting).
    if [ $# -eq 2 ]; then set -- "$1 $2"; fi
    [ $# -eq 1 ] || exit 2
    case "$1" in "ssh-ed25519 AAAA"*) ;; *) echo "refused: not an Ed25519 public key line" >&2; exit 2 ;; esac
    case "$1" in *[!A-Za-z0-9+/=\ @._-]*) echo "refused: unexpected character in the key line" >&2; exit 2 ;; esac
    printf '%s\n' "$1" >"$acct/.ssh/authorized_keys"
    echo "authorized=1"
    ;;
sshd-serve) [ $# -eq 1 ] || exit 2; sshd_start "$1" held ;;
sshd-start) [ $# -eq 1 ] || exit 2; sshd_start "$1" detached ;;
sshd-stop) [ $# -eq 1 ] || exit 2; sshd_stop "$1" ;;
trust-ca)
    # The CA line and the principal, or the line's type and body as two arguments.
    if [ $# -eq 3 ]; then set -- "$1 $2" "$3"; fi
    [ $# -eq 2 ] || exit 2
    case "$1" in "ssh-ed25519 AAAA"*) ;; *) echo "refused: not an Ed25519 public key line" >&2; exit 2 ;; esac
    case "$1$2" in *[!A-Za-z0-9+/=\ @._:-]*) echo "refused: unexpected character" >&2; exit 2 ;; esac
    printf '%s\n' "$1" >"$root/dest/ca.pub"
    printf '%s\n' "$2" >"$root/dest/principals/$(account)"
    echo "trusted=1"
    ;;
seed)
    [ -d "$home" ] || die "the runner has not been bootstrapped"
    env -i PATH=/usr/bin:/bin HOME="$acct" HM_M06J_HOME="$home" HM_M06J_ACCOUNT="$(account)" \
        HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt_store" \
        HEIMDALL_TEST_IROH_KEY_STORE="$iroh_store" \
        HM_M06J_FACTS_OUT="$root/seed.facts" "$driver" --ignored --exact seed_runner </dev/null >"$root/seed.log" 2>&1 ||
        die "the runner seed failed"
    cat "$root/seed.facts"
    ;;
runtime-serve)
    runtime_spawn held
    echo "ready=1"
    # Held: this process ends when the runtime does (`runtime-stop` from another session).
    wait "$runtime_pid" 2>/dev/null || true
    ;;
runtime-start) runtime_spawn detached ;;
runtime-stop) runtime_stop ;;
ensure)
    [ $# -eq 3 ] || exit 2
    out=$(hm --json access ensure --profile "$PROFILE" --pair "$PAIR_DESTINATION:$(account)" \
        --work-id "$1" --for "$3" --request-id "$2" </dev/null 2>/dev/null)
    echo "code=$(printf '%s' "$out" | field code)"
    echo "grant=$(printf '%s' "$out" | field data.grant_id)"
    echo "endpoint=$(printf '%s' "$out" | field data.consumer.signing_endpoint)"
    echo "refresh_dependency=$(printf '%s' "$out" | field data.refresh_dependency)"
    ;;
identities)
    [ $# -eq 1 ] || exit 2
    case "$1" in "$home"/*) ;; *) die "the endpoint is not under the runner's own home" ;; esac
    listed=$(env -i PATH=/usr/bin:/bin SSH_AUTH_SOCK="$1" ssh-add -L </dev/null 2>/dev/null | grep -E '^(ssh-|ecdsa-|sk-)' || true)
    count=$(printf '%s' "$listed" | grep -c . || true)
    echo "identities=$count"
    ca=none
    if [ "$count" -ge 1 ]; then
        printf '%s\n' "$listed" | head -n 1 >"$root/onward/id-cert.pub"
        ca=$(ssh-keygen -L -f "$root/onward/id-cert.pub" 2>/dev/null | sed -n 's/^ *Signing CA: [A-Z0-9-]* \(SHA256:[A-Za-z0-9+/]*\).*/\1/p' | head -n 1)
        [ -n "$ca" ] || ca=none
    fi
    echo "certificate_ca=$ca"
    ;;
onward)
    [ $# -eq 1 ] || exit 2
    port=$(cat "$root/dest/port") || die "the destination sshd was never started"
    : >"$root/onward/ssh_config"
    printf '[127.0.0.1]:%s %s\n' "$port" "$(awk '{ print $1 " " $2 }' "$root/dest/host_ed25519.pub")" >"$root/onward/known_hosts"
    [ -s "$root/onward/id-cert.pub" ] || : >"$root/onward/id-cert.pub"
    if env -i PATH=/usr/bin:/bin HOME="$root/onward" ssh -F "$root/onward/ssh_config" -T -o BatchMode=yes \
        -o IdentityFile="$root/onward/id-cert.pub" -o IdentitiesOnly=yes -o IdentityAgent="$1" \
        -o CertificateFile=none -o UserKnownHostsFile="$root/onward/known_hosts" -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none \
        -o PreferredAuthentications=publickey -o ConnectTimeout=20 -p "$port" "$(account)@127.0.0.1" \
        'echo hm-onward' </dev/null 2>/dev/null | grep -q '^hm-onward$'; then
        echo "onward=ok"
    else
        echo "onward=refused"
    fi
    ;;
processes)
    pid=$(cat "$root/runtime.pid" 2>/dev/null) || die "no runner runtime is recorded"
    parent=$(LC_ALL=C ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    case "$(command_of "${parent:-0}")" in *sshd*) echo "runtime_parent_is_sshd=true" ;; *) echo "runtime_parent_is_sshd=false" ;; esac
    if [ -r "/proc/$pid/environ" ]; then
        if tr '\0' '\n' <"/proc/$pid/environ" | grep -q '^SSH_AUTH_SOCK='; then echo "runtime_has_ssh_auth_sock=true"; else echo "runtime_has_ssh_auth_sock=false"; fi
    else
        echo "runtime_has_ssh_auth_sock=unknown"
    fi
    ;;
keepalive-before)
    [ -d "$root" ] || die "ROOT does not exist"
    [ ! -e "$root/keepalive.before" ] || die "a keep-alive is already recorded"
    sleepers >"$root/keepalive.before"
    echo "keepalive=before"
    ;;
keepalive-record)
    [ -f "$root/keepalive.before" ] || die "keepalive-before did not run"
    i=0
    new=$(new_sleepers)
    while [ -z "$new" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); new=$(new_sleepers); done
    if [ "$(printf '%s' "$new" | grep -c .)" = 1 ]; then
        printf 'pid=%s\nstart=%s\n' "${new%% *}" "${new#* }" >"$root/keepalive.state"
        echo "keepalive=recorded"
    else
        echo "keepalive=unidentified"
    fi
    ;;
cleanup)
    [ -d "$root" ] || { echo "removed=yes"; exit 0; }
    ok=0
    runtime_stop >/dev/null || ok=1
    sshd_stop mgmt >/dev/null || ok=1
    sshd_stop dest >/dev/null || ok=1
    # `keepalive=` only when the caller recorded one (the other callers' output is unchanged).
    keepalive=""
    if [ -f "$root/keepalive.before" ]; then keepalive=$(keepalive_end) || true; fi
    if [ $ok -eq 0 ] && rm -rf -- "$root" && [ ! -e "$root" ]; then
        echo "removed=yes"
        [ -z "$keepalive" ] || echo "keepalive=$keepalive"
        exit 0
    fi
    echo "removed=no"
    [ -z "$keepalive" ] || echo "keepalive=$keepalive"
    exit 1
    ;;
verify)
    if [ -e "$root" ] || [ -L "$root" ]; then echo "scratch=present"; else echo "scratch=gone"; fi
    # Every process whose command line names ROOT, except this process, its ancestors (the
    # caller's own command line names ROOT) and its descendants (the listing itself). Counted,
    # never printed.
    left=$(LC_ALL=C ps -A -w -w -o pid= -o ppid= -o command= 2>/dev/null | awk -v self="$$" -v root="$root" '
        { pid = $1; parent[pid] = $2; $1 = ""; $2 = ""; cmd[pid] = $0 }
        END {
            p = self
            for (d = 0; d < 64 && p != "" && p != 0; d++) { anc[p] = 1; p = parent[p] }
            n = 0
            for (p in cmd) {
                if (p in anc || index(cmd[p], root) == 0) continue
                mine = 0
                q = parent[p]
                for (d = 0; d < 64 && q != "" && q != 0; d++) { if (q == self) { mine = 1; break }; q = parent[q] }
                if (!mine) n++
            }
            print n
        }') || left=unknown
    echo "processes_left=$left"
    ;;
*) echo "unknown action" >&2; exit 2 ;;
esac
