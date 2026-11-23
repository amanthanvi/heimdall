#!/usr/bin/env bash
# M06 W5 `w5g` (m06-plan §3: every "Runner" row; §4 "Paired remote Linux runner"; §7): the
# cross-host exit journey. The CONTROLLER is this Mac: the macOS debug `heimdall` under scratch
# Heimdall and account homes, its production issuer child on the scratch secret store, K_mgmt in
# the debug build's fixture file store and K_iroh in its fixture directory store (never the login
# keychain). The RUNNER is another host (the devbox), reached over the owner's ssh alias: the
# cross-built Linux debug `heimdall` in a scratch directory there, `service run --runner` on a
# scratch home, an unprivileged fixture management sshd and a fixture destination sshd, both on
# that host's loopback.
#
# Usage: tests/native/m06/run-crosshost.sh <artifact-dir> <ssh-host-alias>
#        tests/native/m06/run-crosshost.sh --selftest
#        tests/native/m06/run-crosshost.sh --plan          (the planned steps, one per line)
#   HM_BUILD_ONLY=1        build both sides, record the binaries' hashes, stop (no ssh)
#   HM_XH_ONLY="a24 a07 t06 a25"   the journeys to run (default: all four); a journey that is not
#                          run leaves its steps `ignored`, which the evidence generator never
#                          reads as passed
#   HM_XH_HEIMDALL, HM_XH_DRIVER, HM_XH_LINUX_HEIMDALL, HM_XH_LINUX_DRIVER   prebuilt inputs (all
#                          four, or none: then both sides are built here)
#   HM_XH_SCRATCH          an existing directory for the run directory (default: /tmp; refused
#                          when the controller's socket paths under it would pass 103 bytes)
#   HM_XH_LIFETIME_S       the lifetime of A24's grant (default 240): the journey waits for it
#   HM_XH_DEBUG_DIR        keep the raw transcripts of failed steps there (they hold paths and
#                          names: a scratch directory of the caller, never an artifact)
#
# The owner's ssh configuration and agent are used for exactly two things, both only to reach
# <ssh-host-alias>: the harness's own command channel (as tests/native/m02/run-linux.sh uses it)
# and the `ssh -N -L` forward that carries the controller's management sessions to the fixture
# management sshd on the runner host's loopback (its own connection: ControlMaster=no,
# ControlPath=none, stopped by its exact PID). Nothing of the owner's is test material: the
# controller's existing access is a per-run fixture key in the scratch account home, every ssh the
# product starts reads the scratch configuration (HEIMDALL_TEST_SSH_HOME) and no product process
# has SSH_AUTH_SOCK. One more session uses the alias on purpose: A24's `work-clean-launch` opens
# an ssh session to the runner host that forwards a DISPOSABLE fixture agent (one per-run key,
# started here in the run directory), to show that runner work does not inherit a really
# forwarded agent. The owner's agent is never forwarded.
#
# Journeys. Each has its own runner installation on the runner host and its own controller home
# here (a failed step ends its journey; the others still run). One
# `m06 observation: <case> <step>: <result>` line per step, with the single-host suite's names
# (tests/e2e/exit_m06) where the step is the same:
#   a24  pair, approve, readiness, work-clean-launch, controller-leaves, onward-managed,
#        no-controller-socket, bound
#   a07  pair, issued, disconnected, revoke-pending, reconnect, barrier, no-stale-reactivation,
#        pause-pending, cutoff-pending, uncertain-time, fresh-work-refused
#   t06  pair, first-grant, second-owner, first-controller-gone, narrowing, untrusted-issuer,
#        own-grant, destination-trust     (a second controller home on this Mac)
#   a25  pair, sshd-policy-verified, limited-after-verification, sshd-policy-unverified
#        (the runner host's own `sshd -T` over the fixture configuration; the unverified step
#        pairs one more runner installation per unsupported setting)
# "Disconnected" and "the controller leaves" are what they are between two hosts: the forward is
# closed (and for A24 the controller runtime and its issuer child are stopped), so nothing on
# this host listens for or holds a connection to the runner.
#
# Pairing is the product's `environment add` on a pseudo-terminal, ONE pass: the bootstrap ssh
# session through the forward, confirmed at the runner, and its offer to start the runner's
# runtime accepted with a typed yes (ADR-0012 2.6). The product starts that runtime, the
# controller opens its management session and writes its record, and the pass must end OK. The
# fixture then stops that runtime through the product's `service stop`, seeds the runner and
# starts the fixture's own runtime (a stated fixture step, never a second pairing). The
# fixture state `environment add` requires (the verified enrollment naming the management sshd
# and its host key, the profile, the issuer on the scratch store; on the runner its profile,
# standing policy and destination) is seeded by the entries of e2e_windows_controller_m06, as the
# Windows controller journey seeds it.
#
# Why there is no second `environment add` pass (dropped by W5 `w5m`, confirmed by `w5o`). The
# journey used to DECLINE the offer, fail the first pass, start the runner's runtime by hand and
# run `environment add` again. Once the offer is accepted the first pass pairs, so a second pass
# would be a repair over an existing controller record, which no ruling asks this journey to
# show and which was never rehearsed here. What the two old passes asserted, and where each is
# asserted now:
#   old first pass: prompted, offer declined, runtime stated not started, DESTINATION_UNREACHABLE
#     naming the next step  -> e2e_environment_runner_m06
#     `the_bootstrap_offers_to_start_the_runner_runtime_in_its_attended_session` (declined), and
#     the Windows controller journey's first pass (run-windows-controller.ps1), which still
#     declines;
#   old second pass, `prompted=true`, code OK, the environment, client and role fields
#     -> this journey's one pass (the same `eq`/`fact` checks, on `first`);
#   old second pass, `runtime_offer=not_offered` and `runtime_stated=running` (the session of a
#     runner whose runtime already serves offers nothing)  -> the same single-host test (its
#     `running=stated_no_offer` part) and the Windows controller journey's second pass. This is
#     the runner's own `remote init`, local to the runner host; it is the one statement this
#     journey no longer makes between two hosts;
#   old second pass, the repair of an initialised runner (same client, the line kept)
#     -> e2e_environment_runner_m06, the repair steps after `remote init` (`created=false`);
#   after the pairing: the controller record present, the fixture K_mgmt store written
#     -> unchanged, asserted after the one pass.
#
# Cleanup always runs, pass or fail: the controller runtimes through `service stop` on their own
# scratch homes and their own PIDs, the forward and the fixture agent by exact PID, each runner
# installation through the runner script's cleanup (exact recorded PIDs, then its directory), the
# run's staging directory on the runner host and the run directory here, each by exact name and
# checked absent. At the end the login keychain is checked BY SERVICE NAME ONLY for every
# generic-password service the product can create there (none may exist): the exact list of
# crates/credential/src/lib.rs `MACOS_KEYCHAIN_SERVICES`, and `<MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX>
# <CA fingerprint>` for each CA of this run (`keychain_services`); nothing else is read there.
#
# Output (redacted) in <artifact-dir>: tests.txt (the `### crosshost-journey` section
# m06-evidence.py reads), host.txt (key=value facts), commands.txt (each command with its real
# exit code), build.txt, canary-scan.txt. Exit 0: every planned step passed and the cleanup was
# clean; 1: a step failed, a leak or canary was found, or the cleanup left something; 2: usage;
# 3: blocked (an input, a tool or the host is missing: nothing ran); 4: the host is unreachable.
set -uo pipefail

TARGET=crosshost-journey
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
tool=$here/crosshost-tool.py
# shellcheck source=tests/native/m02/lib.sh
. "$here/../m02/lib.sh"
py() { PYTHONDONTWRITEBYTECODE=1 python3 -I "$tool" "$@"; }

# The planned steps: "<test> <case> <step>", in order. The test name is <case>_<step with _>.
plan() {
    cat <<'EOF'
a24_pair a24 pair
a24_approve a24 approve
a24_readiness a24 readiness
a24_work_clean_launch a24 work-clean-launch
a24_controller_leaves a24 controller-leaves
a24_onward_managed a24 onward-managed
a24_no_controller_socket a24 no-controller-socket
a24_bound a24 bound
a07_pair a07 pair
a07_issued a07 issued
a07_disconnected a07 disconnected
a07_revoke_pending a07 revoke-pending
a07_reconnect a07 reconnect
a07_barrier a07 barrier
a07_no_stale_reactivation a07 no-stale-reactivation
a07_pause_pending a07 pause-pending
a07_cutoff_pending a07 cutoff-pending
a07_uncertain_time a07 uncertain-time
a07_fresh_work_refused a07 fresh-work-refused
t06_pair t06 pair
t06_first_grant t06 first-grant
t06_second_owner t06 second-owner
t06_first_controller_gone t06 first-controller-gone
t06_narrowing t06 narrowing
t06_untrusted_issuer t06 untrusted-issuer
t06_own_grant t06 own-grant
t06_destination_trust t06 destination-trust
a25_pair a25 pair
a25_sshd_policy_verified a25 sshd-policy-verified
a25_limited_after_verification a25 limited-after-verification
a25_sshd_policy_unverified a25 sshd-policy-unverified
EOF
}

# --- pure helpers (the self-test's subjects) -------------------------------------------------------

# fact KEY <<<FACTS: the first value of KEY in `key=value` lines; empty when absent.
fact() { sed -n "s/^$1=//p" | head -n 1; }

# socket_longest PARENT: the length in bytes of the longest controller socket path of a run
# under PARENT: $run (PARENT/hm-m06x-<8 hex>), the longest controller tag (a25kcv), its home's
# runtime directory and a management session's socket (run/mgmt/<12 hex>/a.sock).
# socket_room PARENT: 0 when that path fits a macOS socket address (SOCKET_MAX bytes).
SOCKET_MAX=103
socket_longest() { local LC_ALL=C p="$1/hm-m06x-01234567/c-a25kcv/home/run/mgmt/0123456789ab/a.sock"; echo "${#p}"; }
socket_room() { [ "$(socket_longest "$1")" -le "$SOCKET_MAX" ]; }

# store_guard MGMT IROH RUN: 0 only when both key-store settings name scratch inside RUN: the
# fixture K_mgmt file store and an existing owner-only K_iroh directory. Without them a debug
# `heimdall` on macOS would use the account's login keychain (RULES.md, "KEY STORES").
store_guard() {
    local mgmt=$1 iroh=$2 run=$3
    case "$run" in /*) ;; *) return 1 ;; esac
    case "$mgmt" in "fixture-file:$run"/*) ;; *) return 1 ;; esac
    case "$iroh" in "$run"/*) ;; *) return 1 ;; esac
    case "$mgmt$iroh" in */../* | */./*) return 1 ;; esac
    [ -d "$iroh" ] && [ ! -L "$iroh" ] || return 1
    return 0
}

# ssh_config ALIAS PORT KEY KNOWN: the scratch ssh configuration of a controller's existing
# access to the runner account (read by the product's bootstrap session only).
ssh_config() {
    printf 'Host %s\n    HostName 127.0.0.1\n    Port %s\n    IdentityFile "%s"\n    IdentitiesOnly yes\n    IdentityAgent none\n    CertificateFile none\n    UserKnownHostsFile "%s"\n    GlobalKnownHostsFile /dev/null\n    ControlMaster no\n    ControlPath none\n' \
        "$1" "$2" "$3" "$4"
}

# quote ARGS...: one shell word per argument, for the runner host's shell.
quote() {
    local a out=""
    for a in "$@"; do out+=" $(printf '%q' "$a")"; done
    printf '%s' "${out# }"
}

# run_exit FAILED RAN PLANNED_SELECTED CLEANUP_OK SCANS_OK: the run's exit code.
run_exit() {
    [ "$1" = 0 ] && [ "$2" = "$3" ] && [ "$4" = 1 ] && [ "$5" = 1 ] && { echo 0; return; }
    echo 1
}

# own_remote_dir NAME: 0 for a staging directory name this script creates (hm-m06x-<8 hex>).
own_remote_dir() {
    case "$1" in hm-m06x-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) return 0 ;; esac
    return 1
}

# keychain_services SOURCE [CA_FINGERPRINT...]: one line per macOS keychain service name the
# product can create, read from the one place the code names them (SOURCE:
# crates/credential/src/lib.rs): the exact names of `MACOS_KEYCHAIN_SERVICES`, then
# `MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX` followed by each CA fingerprint given. Nonzero, with
# nothing printed, when the source does not hold both constants (the check is then not run as
# if it had passed).
keychain_services() {
    local src=$1 names prefix fp
    shift
    names=$(awk '/^pub const MACOS_KEYCHAIN_SERVICES: /{ on = 1 } on { print } on && /;[[:space:]]*$/ { exit }' "$src" 2>/dev/null |
        sed 's/^[^=]*=//' | grep -o '"[^"]*"' | tr -d '"')
    prefix=$(sed -n 's/^pub const MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX: &str = "\([^"]*\)";.*$/\1/p' "$src" 2>/dev/null | head -n 1)
    [ -n "$names" ] && [ -n "$prefix" ] || return 1
    case "$names$prefix" in *[!A-Za-z0-9/_.$'\n'-]*) return 1 ;; esac
    printf '%s\n' "$names"
    for fp in "$@"; do [ -z "$fp" ] || printf '%s%s\n' "$prefix" "$fp"; done
}

# same_process PID START NEEDLE: 0 only when PID is alive, its start time (ps lstart) is START
# and its command line holds NEEDLE: the identity check before a PID is ever signalled. 1 when
# the PID is gone; 2 when a process with that PID exists and is NOT the recorded one (it is
# then never signalled).
same_process() {
    local pid=$1 start=$2 needle=$3 now
    case "$pid" in '' | *[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    now=$(LC_ALL=C ps -o lstart= -p "$pid" 2>/dev/null | tr -s ' ' | sed 's/^ //;s/ $//')
    [ -n "$start" ] && [ "$now" = "$start" ] || return 2
    # (The needle is passed in the environment, so no command line carries it twice.)
    LC_ALL=C ps -o command= -p "$pid" 2>/dev/null | HM_XH_NEEDLE="$needle" awk 'BEGIN { n = ENVIRON["HM_XH_NEEDLE"] } index($0, n) { f = 1 } END { exit !f }' || return 2
    return 0
}
start_of() { LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //;s/ $//'; }

# socket_row_obs: the "No silent controller socket" row's observation (the orchestrator's
# ruling): its three parts in this order, each from the facts the steps recorded, or nonzero
# with `reason` when a part does not hold. Arguments, NAME=VALUE:
#   a. runtime_stop forward_stop   how the controller's runtime and its `ssh -L` forward ended
#                                   (`stopped_by_exact_pid_identity_checked` is the only pass)
#      gone_at onward_ok_at         epoch seconds: the controller was gone BEFORE the onward login
#   b. at_onward_outbound at_onward_mgmt at_onward_fixture controller_host_known
#                                   the runner host's connection table at the onward login, BY
#                                   DIRECTION (the ruling of 2026-11-22): connections the runner
#                                   host opened TO the controller host, and connections accepted
#                                   on the management sshd's and the fixture destination's ports
#                                   (the harness holds none there by then: its forward is stopped
#                                   in part a). All three must be 0.
#      at_onward_inbound at_onward_channel
#                                   sessions INTO the runner host from the controller host (its
#                                   port 22: the owner's and other work's sessions, and this
#                                   observation's own channel). Reported, never judged: they are
#                                   not evidence either way.
#   c. window_connections window_sessions window_s   the management sshd's log over the window
#   fd_readable fd_reason           the runner runtime's descriptor table (kept, never a pass or fail)
socket_row_obs() {
    local kv runtime_stop="" forward_stop="" gone_at="" onward_ok_at="" at_onward_mgmt="" at_onward_outbound="" at_onward_fixture=""
    local at_onward_inbound="" at_onward_channel="" controller_host_known="" window_connections="" window_sessions="" window_s="" fd_readable="" fd_reason="" rest=""
    for kv in "$@"; do
        case "$kv" in
        runtime_stop=* | forward_stop=* | gone_at=* | onward_ok_at=* | at_onward_mgmt=* | at_onward_outbound=* | at_onward_fixture=* | \
            at_onward_inbound=* | at_onward_channel=* | \
            controller_host_known=* | window_connections=* | window_sessions=* | window_s=* | fd_readable=* | fd_reason=*)
            printf -v "${kv%%=*}" '%s' "${kv#*=}" ;;
        rest=*) rest=${kv#rest=} ;;
        *) reason="socket_row_argument=unknown"; return 1 ;;
        esac
    done
    # a. The controller fully gone, each process by its exact PID after its identity check,
    #    before the runner's onward ssh succeeded.
    [ "$runtime_stop" = stopped_by_exact_pid_identity_checked ] || { reason="a_controller_runtime_stop=${runtime_stop:-unknown}"; return 1; }
    [ "$forward_stop" = stopped_by_exact_pid_identity_checked ] || { reason="a_management_forward_stop=${forward_stop:-unknown}"; return 1; }
    case "$gone_at" in '' | *[!0-9]*) reason="a_order=unknown"; return 1 ;; esac
    case "$onward_ok_at" in '' | *[!0-9]*) reason="a_order=unknown"; return 1 ;; esac
    [ "$gone_at" -le "$onward_ok_at" ] || { reason="a_controller_gone_before_onward=false"; return 1; }
    # b. At that moment, by direction: the runner host has opened no connection TO the
    #    controller host, and has accepted none on its management or fixture ports. Sessions
    #    INTO the runner host (its port 22) are not judged: a number that is not a count is
    #    still a failure to read the table.
    [ "$controller_host_known" = true ] || { reason="b_controller_host_known=${controller_host_known:-false}"; return 1; }
    [ "$at_onward_outbound" = 0 ] || { reason="b_runner_host_outbound_to_controller_host=${at_onward_outbound:-unknown}"; return 1; }
    [ "$at_onward_mgmt" = 0 ] || { reason="b_runner_host_inbound_on_management_port=${at_onward_mgmt:-unknown}"; return 1; }
    [ "$at_onward_fixture" = 0 ] || { reason="b_runner_host_inbound_on_fixture_port=${at_onward_fixture:-unknown}"; return 1; }
    case "$at_onward_inbound" in '' | *[!0-9]*) reason="b_runner_host_inbound_from_controller_host=unknown"; return 1 ;; esac
    # c. The fixture management sshd logged no connection and no session in the window.
    [ "$window_connections" = 0 ] || { reason="c_mgmt_sshd_connections_in_window=${window_connections:-unknown}"; return 1; }
    [ "$window_sessions" = 0 ] || { reason="c_mgmt_sshd_sessions_in_window=${window_sessions:-unknown}"; return 1; }
    obs="a_controller_gone_before_onward=true controller_runtime=$runtime_stop management_forward=$forward_stop controller_gone_at_s=$gone_at onward_login_ok_at_s=$onward_ok_at"
    obs+=" b_at_onward_login_by_direction runner_host_outbound_to_controller_host=0 runner_host_inbound_on_management_port=0 runner_host_inbound_on_fixture_port=0"
    obs+=" runner_host_inbound_ssh_sessions_from_controller_host=${at_onward_inbound}(not_evidence_either_way;observation_channel=${at_onward_channel:-0})"
    obs+=" c_mgmt_sshd_connections_in_window=0 mgmt_sshd_sessions_in_window=0 window_s=${window_s:-0}"
    obs+=" runner_runtime_fd_table_readable=${fd_readable:-unknown} runner_runtime_fd_table_unreadable_reason=${fd_reason:-unknown}"
    [ -z "$rest" ] || obs+=" $rest"
    return 0
}

selftest() {
    local fails=0 n=0 T
    T=$(mktemp -d) || exit 1
    ok() { n=$((n + 1)); if "${@:2}"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }
    t_plan() {
        local p; p=$(plan)
        [ "$(printf '%s\n' "$p" | wc -l | tr -d ' ')" = 31 ] &&
            [ "$(printf '%s\n' "$p" | cut -d' ' -f1 | sort -u | wc -l | tr -d ' ')" = 31 ] &&
            [ "$(printf '%s\n' "$p" | cut -d' ' -f2 | sort -u | tr '\n' ' ')" = "a07 a24 a25 t06 " ] &&
            ! printf '%s\n' "$p" | awk '{ t = $2 "_" $3; gsub("-", "_", t); if (t != $1) bad = 1 } END { exit !bad }'
    }
    ok "P01 31 planned steps, unique test names, each <case>_<step>, cases a07 a24 a25 t06" t_plan
    t_order() {
        local p; p=$(plan | cut -d' ' -f1 | tr '\n' ' ')
        case "$p" in *"a24_controller_leaves a24_onward_managed a24_no_controller_socket a24_bound "*) ;; *) return 1 ;; esac
        case "$p" in *"a07_disconnected a07_revoke_pending a07_reconnect a07_barrier "*) ;; *) return 1 ;; esac
        case "$p" in *"t06_second_owner t06_first_controller_gone t06_narrowing "*) ;; *) return 1 ;; esac
    }
    ok "P02 the controller leaves before the onward login, the socket row and the bound; the revoke is pending before the reconnect" t_order
    t_fact() {
        local f=$'code=OK\nenvironment=env_1\nnoequals\ncode=LATER\nendpoint=/a=b\n'
        [ "$(fact code <<<"$f")" = OK ] && [ "$(fact endpoint <<<"$f")" = "/a=b" ] && [ -z "$(fact absent <<<"$f")" ]
    }
    ok "F01 facts: the first value wins, values may hold =, an absent key reads empty" t_fact
    mkdir -m 700 "$T/iroh"
    t_guard_ok() { store_guard "fixture-file:$T/k_mgmt.fixture" "$T/iroh" "$T"; }
    ok "G01 the key stores are accepted when both are scratch inside the run directory" t_guard_ok
    t_guard_refuses() {
        ! store_guard "" "$T/iroh" "$T" && ! store_guard "fixture-file:$T/k" "" "$T" &&
            ! store_guard "fixture-file:/elsewhere/k" "$T/iroh" "$T" && ! store_guard "fixture-file:$T/k" "/elsewhere" "$T" &&
            ! store_guard "$T/k" "$T/iroh" "$T" && ! store_guard "fixture-file:$T/k" "$T/absent" "$T" &&
            ! store_guard "fixture-file:$T/../k" "$T/iroh" "$T" && ! store_guard "fixture-file:$T/k" "$T/iroh" "relative"
    }
    ok "G02 an unset, foreign, malformed or missing K_mgmt or K_iroh store is refused (the login keychain is never the fallback)" t_guard_refuses
    t_guard_stops() {
        # The controller command itself refuses before anything is started.
        local out
        out=$(run="$T" heimdall=/usr/bin/false HM_XH_SELFTEST_NO_STORES=1 ctl x service status 2>&1)
        [ $? = 97 ] && [ "$out" = "refused: the controller's key stores are not scratch" ]
    }
    ok "G03 a controller command without its scratch key stores starts nothing (exit 97)" t_guard_stops
    t_config() {
        local c; c=$(ssh_config hm-x 20022 "/s/acct/.ssh/id_fixture" "/s/known")
        grep -qxF "Host hm-x" <<<"$c" && grep -qxF "    Port 20022" <<<"$c" && grep -qxF '    IdentityFile "/s/acct/.ssh/id_fixture"' <<<"$c" &&
            grep -qxF "    IdentitiesOnly yes" <<<"$c" && grep -qxF "    IdentityAgent none" <<<"$c" && grep -qxF "    CertificateFile none" <<<"$c" &&
            grep -qxF "    GlobalKnownHostsFile /dev/null" <<<"$c" && grep -qxF "    ControlMaster no" <<<"$c" && grep -qxF "    ControlPath none" <<<"$c" &&
            grep -qxF "    HostName 127.0.0.1" <<<"$c"
    }
    ok "C01 the scratch ssh configuration names loopback, only the fixture key, no agent, no shared connection" t_config
    t_quote() {
        [ "$(quote a 'b c' "d'e")" = "a b\\ c d\\'e" ] && [ "$(eval "set -- $(quote 'x y' '$(id)' 'a;b')"; echo "$#:$2")" = '3:$(id)' ]
    }
    ok "Q01 arguments reach the runner host's shell as single words, never evaluated" t_quote
    t_exit() {
        [ "$(run_exit 0 5 5 1 1)" = 0 ] && [ "$(run_exit 1 5 5 1 1)" = 1 ] && [ "$(run_exit 0 4 5 1 1)" = 1 ] &&
            [ "$(run_exit 0 5 5 0 1)" = 1 ] && [ "$(run_exit 0 5 5 1 0)" = 1 ] && [ "$(run_exit 0 0 0 1 1)" = 0 ]
    }
    ok "X01 exit 0 only when every selected step passed, the cleanup was clean and the scans found nothing" t_exit
    t_remote() {
        own_remote_dir hm-m06x-0123abcd && ! own_remote_dir hm-m06x-0123ABCD && ! own_remote_dir hm-m06x-0123abcd-1 &&
            ! own_remote_dir hm-m06-0123abcd && ! own_remote_dir "" && ! own_remote_dir "hm-m06x-0123abc*"
    }
    ok "N01 only hm-m06x-<8 hex> is a staging directory of this script" t_remote
    t_socket() {
        # The default /tmp and w5g's /tmp/hm6x fit; a macOS $TMPDIR (49 bytes, the W5 candidate
        # run's) does not: its management agent socket was 105 bytes and its bind failed.
        socket_room /tmp && socket_room /tmp/hm6x && [ "$(socket_longest /tmp)" = 64 ] &&
            ! socket_room /var/folders/zz/0123456789abcdefghijklmn0000gn/T && socket_room "/$(printf 'x%.0s' $(seq 1 42))" &&
            ! socket_room "/$(printf 'x%.0s' $(seq 1 43))"
    }
    ok "N02 a scratch parent is refused when the controller's longest socket path would pass 103 bytes" t_socket
    t_summary() {
        # ⟨`w5s`, PC job 38 diagnostics⟩ A failing first assertion names the result's code, reason
        # and protected message, never a path, address, quote or secret.
        local facts=$'exit=3\nprompted=false\ncode=STATE_UNAVAILABLE\nreason=mgmt_agent_unavailable\nerror_fields=code,message,reason\nmessage=the agent could not start at /home/u/.ssh 127.0.0.1 "s3cretT0ken"'
        reason=""
        eqr first_pass_prompted false true "$facts" && return 1
        case "$reason" in "first_pass_prompted=false wanted=true code=STATE_UNAVAILABLE reason=mgmt_agent_unavailable exit=3 error_fields=code,message,reason message=the agent could not start at "*) ;; *) return 1 ;; esac
        case "$reason" in */* | *127.0.0.1* | *'"'*) return 1 ;; esac
        reason=""
        eqr ok same same "$facts" && [ -z "$reason" ] || return 1
        eqr x a b "" && return 1
        [ "$reason" = "x=a wanted=b code=none reason=none exit=none error_fields=none message=none" ]
    }
    ok "D01 a failed first assertion on a result prints its code, reason and protected message, never a path or secret" t_summary
    t_runner() {
        local r=$here/crosshost-runner.sh a
        bash -n "$r" || return 1
        for a in "sockets relative/hm-m06j-x" "sockets /tmp/other" "work /tmp/hm-m06j-a/../b" "json /tmp/hm-m06j-a b"; do
            # shellcheck disable=SC2086
            bash "$r" $a >/dev/null 2>&1
            [ $? = 2 ] || return 1
        done
        bash "$r" runtime-start-with /tmp/hm-m06j-selftest-absent sideways sshd_config >/dev/null 2>&1; [ $? = 2 ] || return 1
        bash "$r" runtime-start-with /tmp/hm-m06j-selftest-absent synchronized ../../etc/x >/dev/null 2>&1; [ $? = 2 ] || return 1
        bash "$r" policy-config /tmp/hm-m06j-selftest-absent zz >/dev/null 2>&1; [ $? = 1 ] || return 1
        bash "$r" runtime-offered-stop /tmp/hm-m06j-selftest-absent extra >/dev/null 2>&1; [ $? = 2 ] || return 1
        bash "$r" runtime-offered-stop /tmp/hm-m06j-selftest-absent >/dev/null 2>&1; [ $? = 1 ] || return 1
        bash "$r" json /tmp/hm-m06j-selftest-absent 'x=$(id)' -- status >/dev/null 2>&1; [ $? = 2 ] || return 1
        [ "$(bash "$r" cleanup /tmp/hm-m06j-selftest-absent 2>/dev/null)" = "removed=yes" ]
    }
    ok "R01 the runner script parses, refuses a foreign root, a foreign policy file and a malformed field, and passes the base actions through" t_runner
    t_policy() {
        local root=$T/hm-m06j-st r=$here/crosshost-runner.sh
        mkdir -p "$root/mgmt" && printf 'Port 1\nAllowAgentForwarding no\n' >"$root/mgmt/sshd_config"
        [ "$(bash "$r" policy-config "$root" ae)" = "policy=policy-ae" ] && grep -qxF 'AcceptEnv *' "$root/mgmt/policy-ae" &&
            bash "$r" policy-config "$root" fc >/dev/null && grep -qxF 'ForceCommand /usr/bin/true' "$root/mgmt/policy-fc" &&
            bash "$r" policy-config "$root" kc >/dev/null && grep -qxF 'AuthorizedKeysCommand /usr/bin/false' "$root/mgmt/policy-kc" &&
            grep -qxF 'AllowAgentForwarding no' "$root/mgmt/policy-kc" && ! grep -q 'AcceptEnv' "$root/mgmt/sshd_config"
    }
    ok "R02 a policy variant is the management configuration plus exactly one unsupported setting" t_policy
    t_tool() { py selftest >"$T/tool.log" 2>&1 && grep -q '^18 passed, 0 failed$' "$T/tool.log"; }
    ok "T01 the helper tool's own self-test passes (fields, the log format, the pseudo-terminal, the runtime offer, the connection table and its split by direction)" t_tool
    t_keychain() {
        local got
        got=$(keychain_services "$repo/crates/credential/src/lib.rs" "SHA256:abc/d+e") || return 1
        [ "$got" = $'heimdall-mgmt\nheimdall-iroh\nheimdall-issuer/SHA256:abc/d+e' ] || return 1
        [ "$(keychain_services "$repo/crates/credential/src/lib.rs")" = $'heimdall-mgmt\nheimdall-iroh' ] || return 1
        # The values are the stores' own constants (the Rust test pins the list to them).
        grep -q '^pub const ITEM_SERVICE: &str = "heimdall-mgmt";$' "$repo/crates/credential/src/mgmt.rs" &&
            grep -q '^pub const ITEM_SERVICE: &str = "heimdall-iroh";$' "$repo/crates/credential/src/iroh.rs" || return 1
        printf 'pub const OTHER: [&str; 1] = ["x"];\n' >"$T/none.rs"
        ! keychain_services "$T/none.rs" && ! keychain_services "$T/absent.rs" &&
            grep -q 'services=$(keychain_services "$repo/crates/credential/src/lib.rs"' "$here/run-crosshost.sh"
    }
    ok "K01 the keychain check's service names are exactly the code's list plus this run's CA items; an unreadable list is not a pass" t_keychain
    t_identity() {
        local pid start rc
        sleep 30 &
        pid=$!
        start=$(start_of "$pid")
        same_process "$pid" "$start" "sleep 30" || { kill "$pid" 2>/dev/null; return 1; }
        same_process "$pid" "Thu Jan  1 00:00:00 1970" "sleep 30"; rc=$?
        [ $rc = 2 ] || { kill "$pid" 2>/dev/null; return 1; }
        same_process "$pid" "$start" "ssh -N -L 127.0.0.1:1:"; rc=$?
        [ $rc = 2 ] || { kill "$pid" 2>/dev/null; return 1; }
        same_process "$pid" "" "sleep 30"; rc=$?
        [ $rc = 2 ] || { kill "$pid" 2>/dev/null; return 1; }
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        same_process "$pid" "$start" "sleep 30"; rc=$?
        [ $rc = 1 ] || return 1
        same_process "" "$start" "sleep 30"; rc=$?
        [ $rc = 1 ]
    }
    ok "I01 a PID is the recorded process only with its start time and its command; a foreign or dead PID is never a match" t_identity
    t_stop_identity() {
        # controller_stop and forward_close over a foreign process holding the recorded PID:
        # reported as a mismatch and never signalled.
        local pid
        sleep 30 &
        pid=$!
        mkdir -p "$T/c-x/home" "$T/w-x"
        echo "$pid" >"$T/c-x/runtime.pid"; echo "Thu Jan  1 00:00:00 1970" >"$T/c-x/runtime.start"
        echo "$pid" >"$T/w-x/forward.pid"; start_of "$pid" >"$T/w-x/forward.start"; echo 1 >"$T/w-x/lport"
        (run=$T; controller_stop x && [ "$STOP_HOW" = identity_mismatch ] && forward_close x && [ "$FORWARD_HOW" = identity_mismatch ]) || { kill "$pid" 2>/dev/null; return 1; }
        kill -0 "$pid" 2>/dev/null || return 1
        kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        (run=$T; controller_stop x && [ "$STOP_HOW" = not_recorded ])
    }
    ok "I02 a recorded PID now held by another process is a mismatch: not signalled, and never a pass of the row" t_stop_identity
    t_row() {
        local good=(runtime_stop=stopped_by_exact_pid_identity_checked forward_stop=stopped_by_exact_pid_identity_checked gone_at=100 onward_ok_at=103
            controller_host_known=true at_onward_outbound=0 at_onward_mgmt=0 at_onward_fixture=0 at_onward_inbound=3 at_onward_channel=1 window_connections=0 window_sessions=0 window_s=22
            fd_readable=false fd_reason=non_dumpable_process rest="endpoint=under_runner_home")
        obs=""; reason=""
        socket_row_obs "${good[@]}" || return 1
        # All three parts, in the ruled order, then the descriptor line with its reason.
        case "$obs" in "a_controller_gone_before_onward=true controller_runtime=stopped_by_exact_pid_identity_checked management_forward=stopped_by_exact_pid_identity_checked "*" b_at_onward_login_by_direction runner_host_outbound_to_controller_host=0 runner_host_inbound_on_management_port=0 runner_host_inbound_on_fixture_port=0 runner_host_inbound_ssh_sessions_from_controller_host=3(not_evidence_either_way;observation_channel=1) c_mgmt_sshd_connections_in_window=0 mgmt_sshd_sessions_in_window=0 window_s=22 runner_runtime_fd_table_readable=false runner_runtime_fd_table_unreadable_reason=non_dumpable_process endpoint=under_runner_home") ;; *) return 1 ;; esac
        local bad want
        # Inbound sessions to the runner host from the controller host are not judged: any
        # count passes, and the row reports it.
        local inbound
        for inbound in 0 1 7; do
            obs=""; reason=""
            socket_row_obs "${good[@]}" "at_onward_inbound=$inbound" || return 1
            case "$obs" in *" runner_host_inbound_ssh_sessions_from_controller_host=${inbound}(not_evidence_either_way;"*) ;; *) return 1 ;; esac
        done
        while IFS='|' read -r bad want; do
            obs=""; reason=""
            socket_row_obs "${good[@]}" "$bad" && return 1
            [ -z "$obs" ] && [ "$reason" = "$want" ] || return 1
        done <<'CASES'
runtime_stop=already_gone|a_controller_runtime_stop=already_gone
forward_stop=identity_mismatch|a_management_forward_stop=identity_mismatch
gone_at=104|a_controller_gone_before_onward=false
onward_ok_at=|a_order=unknown
controller_host_known=false|b_controller_host_known=false
at_onward_outbound=1|b_runner_host_outbound_to_controller_host=1
at_onward_outbound=|b_runner_host_outbound_to_controller_host=unknown
at_onward_mgmt=1|b_runner_host_inbound_on_management_port=1
at_onward_mgmt=|b_runner_host_inbound_on_management_port=unknown
at_onward_fixture=2|b_runner_host_inbound_on_fixture_port=2
at_onward_inbound=|b_runner_host_inbound_from_controller_host=unknown
window_connections=1|c_mgmt_sshd_connections_in_window=1
window_sessions=2|c_mgmt_sshd_sessions_in_window=2
CASES
    }
    t_offer_accepted() {
        # In the script itself: the pairing answers the bootstrap's runtime offer with yes,
        # requires the session to say the runtime was started and the pairing to be OK in that
        # pass, and only then stops that runtime through the runner's own action. No pairing
        # in this script declines the offer.
        local declines="--offer"
        declines+=" no"
        grep -qF 'first=$(ctl_pty "$w" --offer yes ' "$here/run-crosshost.sh" || return 1
        ! grep -qF -- "$declines" "$here/run-crosshost.sh" || return 1
        grep -qF 'eq pair_runtime_offer "$(fact runtime_offer <<<"$first")" accepted' "$here/run-crosshost.sh" &&
            grep -qF 'eq pair_runtime_stated "$(fact runtime_stated <<<"$first")" started' "$here/run-crosshost.sh" &&
            awk '/first=.*ctl_pty/ { a = NR } /must_runner "\$w" runtime-offered-stop/ { b = NR } /must_runner "\$w" seed / { c = NR } END { exit !(a && b && c && a < b && b < c) }' "$here/run-crosshost.sh"
    }
    ok "P01 the pairing accepts the bootstrap's runtime offer (typed yes), needs the runtime started and the pairing OK in that pass, then stops that runtime before the fixture's seed" t_offer_accepted
    ok "S01 the socket row passes only with all three parts (a controller gone before the onward login; b by direction: nothing outbound to the controller host, nothing inbound on the management or fixture ports, inbound ssh sessions not judged; c no session in the window), printed in that order" t_row
    t_row_order() {
        # In the script itself: the clean launch comes before the controller leaves and says so;
        # part b is read in the onward step; the row is assembled last.
        local p; p=$(plan | cut -d' ' -f1 | tr '\n' ' ')
        case "$p" in *"a24_work_clean_launch a24_controller_leaves a24_onward_managed a24_no_controller_socket "*) ;; *) return 1 ;; esac
        grep -q 'forwarded_agent_provenance=controller_dependency controller=running"$' "$here/run-crosshost.sh" &&
            awk '/^s_a24_onward_managed\(\)/{ on = 1 } on && /onward.sockets/ { f = 1 } on && /^}/ { exit } END { exit !f }' "$here/run-crosshost.sh" &&
            awk '/^s_a24_controller_leaves\(\)/{ on = 1 } on && /gone.at/ { f = 1 } on && /^}/ { exit } END { exit !f }' "$here/run-crosshost.sh"
    }
    ok "S02 the clean launch stays before the controller leaves (controller=running); part a is recorded when it leaves and part b at the onward login" t_row_order
    t_log() {
        printf 'a24_pair\ta24\tpair\tok\towner_enrolled=true\n' >"$T/r.tsv"
        plan | cut -d' ' -f1 >"$T/planned"
        py log --target "$TARGET" --results "$T/r.tsv" --planned "$T/planned" --exit 1 >"$T/tests.txt"
        grep -qxF "### $TARGET" "$T/tests.txt" && grep -qxF "test a24_pair ... ok" "$T/tests.txt" && grep -qxF "test a25_sshd_policy_unverified ... ignored" "$T/tests.txt" &&
            [ "$(grep -c '^test .* \.\.\. ' "$T/tests.txt")" = 31 ] && grep -qxF "test result: ok. 1 passed; 0 failed; 30 ignored" "$T/tests.txt" &&
            grep -qxF "m06 observation: a24 pair: owner_enrolled=true" "$T/tests.txt" && grep -qxF "### $TARGET exit=1" "$T/tests.txt"
    }
    ok "L01 a partial run's log lists every planned step, the ones not run as ignored" t_log
    t_blocked() {
        local out
        out=$(HM_XH_SCRATCH="$T" HM_XH_HEIMDALL="$T/absent" bash "$here/run-crosshost.sh" "$T/art" some-alias 2>&1)
        [ $? = 3 ] && grep -q '^blocked: ' <<<"$out" && [ ! -e "$T/art/tests.txt" ] && [ -z "$(find "$T" -maxdepth 1 -name 'hm-m06x-*')" ]
    }
    ok "B01 a missing prebuilt input is blocked (exit 3) before anything is created or any host is contacted" t_blocked
    t_usage() {
        bash "$here/run-crosshost.sh" >/dev/null 2>&1; [ $? = 2 ] || return 1
        bash "$here/run-crosshost.sh" "$T/art" '-oProxyCommand=x' >/dev/null 2>&1; [ $? = 2 ] || return 1
        bash "$here/run-crosshost.sh" "$T/art" a --container >/dev/null 2>&1; [ $? = 2 ]
    }
    ok "U01 no arguments, an alias that could be read as an option, and --container (not built) are usage errors" t_usage
    rm -rf -- "$T"
    echo "run-crosshost selftest: $((n - fails)) passed, $fails failed"
    [ "$fails" = 0 ]
}

# --- the controller side ---------------------------------------------------------------------------

# ctl TAG ARGS...: one command of the controller installation TAG (its scratch homes, the debug
# build's scratch SSH home, issuer store and BOTH scratch key stores), unattended, a cleared
# environment. Refuses (exit 97) before anything starts when the key stores are not scratch.
ctl_env() { # TAG -> sets the array CE
    local c=$run/c-$1 mgmt iroh
    mgmt="fixture-file:$c/k_mgmt.fixture"
    iroh="$c/iroh-store"
    if [ -n "${HM_XH_SELFTEST_NO_STORES:-}" ]; then mgmt=""; fi
    if ! store_guard "$mgmt" "$iroh" "$run"; then
        echo "refused: the controller's key stores are not scratch" >&2
        return 97
    fi
    CE=(env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$c/acct" HEIMDALL_HOME="$c/home"
        HEIMDALL_TEST_SSH_HOME="$c/acct" HEIMDALL_TEST_TIME_SYNC=synchronized
        HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_MGMT_STORE="$mgmt"
        HEIMDALL_TEST_IROH_KEY_STORE="$iroh")
}
ctl() {
    local tag=$1
    shift
    ctl_env "$tag" || return 97
    "${CE[@]}" "$heimdall" --json --home "$run/c-$tag/home" "$@" </dev/null 2>/dev/null
}
# ctl_pty TAG [--field NAME=PATH]... -- ARGS...: the same on a pseudo-terminal, typing `yes` at
# the confirmation. Prints the tool's facts.
ctl_pty() {
    local tag=$1 rc
    shift
    ctl_env "$tag" || return 97
    local pre=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do pre+=("$1"); shift; done
    shift
    "${CE[@]}" python3 -I "$tool" pty --timeout 240 --transcript "$run/c-$tag/pty.transcript" ${pre[@]+"${pre[@]}"} -- \
        "$heimdall" --json --home "$run/c-$tag/home" "$@" </dev/null 2>/dev/null
    rc=$?
    keep_debug "$run/c-$tag/pty.transcript" "c-$tag-pty"
    rm -f "$run/c-$tag/pty.transcript"
    return $rc
}
keep_debug() { # FILE NAME: a raw transcript for the caller's own scratch, when asked
    [ -n "${HM_XH_DEBUG_DIR:-}" ] && [ -f "$1" ] && cp "$1" "$HM_XH_DEBUG_DIR/$2.$(date +%s).txt" 2>/dev/null
    return 0
}
dbg() { # NAME <<<TEXT
    if [ -n "${HM_XH_DEBUG_DIR:-}" ]; then cat >"$HM_XH_DEBUG_DIR/$1.$(date +%s).txt"; else cat >/dev/null; fi
}

controller_new() { # TAG: the scratch homes of one controller installation
    local c=$run/c-$1
    mkdir -m 700 "$c" "$c/home" "$c/acct" "$c/acct/.ssh" "$c/iroh-store" "$c/facts" || return 1
}
controller_start() { # TAG
    local tag=$1 c=$run/c-$1 i=0 pid
    ctl_env "$tag" || return 1
    "${CE[@]}" "$heimdall" --home "$c/home" service run </dev/null >/dev/null 2>"$c/runtime.stderr" &
    pid=$!
    echo "$pid" >"$c/runtime.pid"
    start_of "$pid" >"$c/runtime.start"
    while [ $i -lt 300 ]; do
        if ctl "$tag" service status >/dev/null; then return 0; fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
        i=$((i + 1))
    done
    reason="controller_runtime=not_started"
    return 1
}
# controller_stop TAG: the controller runtime this script started, by its exact recorded PID and
# only after that PID's identity was checked (`same_process`: its start time, and a command
# line naming this controller's scratch home). `service stop` on its own scratch home first;
# the PID is signalled only when it outlives that and is still the recorded process. Sets
# STOP_HOW: stopped_by_exact_pid_identity_checked | already_gone | not_recorded |
# identity_mismatch (a foreign process holds the PID: never signalled; the recorded one is gone).
controller_stop() {
    local tag=$1 c=$run/c-$1 pid start i=0 rc
    STOP_HOW=not_recorded
    pid=$(cat "$c/runtime.pid" 2>/dev/null) || return 0
    case "$pid" in '' | *[!0-9]*) rm -f "$c/runtime.pid" "$c/runtime.start"; return 0 ;; esac
    start=$(cat "$c/runtime.start" 2>/dev/null)
    same_process "$pid" "$start" "$c/home"
    rc=$?
    if [ $rc = 1 ]; then STOP_HOW=already_gone; rm -f "$c/runtime.pid" "$c/runtime.start"; return 0; fi
    if [ $rc = 2 ]; then STOP_HOW=identity_mismatch; rm -f "$c/runtime.pid" "$c/runtime.start"; return 0; fi
    ctl "$tag" service stop >/dev/null
    while [ $i -lt 300 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    if same_process "$pid" "$start" "$c/home"; then
        kill "$pid" 2>/dev/null
        i=0
        while [ $i -lt 100 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    fi
    same_process "$pid" "$start" "$c/home" && return 1
    wait "$pid" 2>/dev/null
    rm -f "$c/runtime.pid" "$c/runtime.start"
    STOP_HOW=stopped_by_exact_pid_identity_checked
    return 0
}
children_of() { ps -A -o pid= -o ppid= | awk -v p="$1" '$2 == p { print $1 }'; }
any_alive() { local p; for p in "$@"; do kill -0 "$p" 2>/dev/null && return 0; done; return 1; }

# status TAG ENV NAME=PATH...: facts of the controller's record of one runner.
status() {
    local tag=$1 environment=$2
    shift 2
    ctl "$tag" environment status | py environment "$environment" "$@"
}
# forwarded_ensure TAG ENV WORK REQUEST LIFETIME: the controller owner's forwarded request to its
# settled answer (a pending ACCEPTED is followed with `operation wait`, as the single-host suite
# does). Sets ANSWER (the envelope).
forwarded_ensure() {
    local tag=$1 op
    ANSWER=$(ctl "$tag" access ensure --profile runner-profile --environment "$2" --work-id "$3" --for "$5" --request-id "$4")
    if [ "$(py field code <<<"$ANSWER")" = ACCEPTED ]; then
        op=$(py field operation_id <<<"$ANSWER")
        [ "$op" != none ] || { reason="forwarded_ensure=ACCEPTED operation=none"; return 1; }
        ANSWER=$(ctl "$tag" operation wait "$op" --timeout-ms 60000)
    fi
    dbg "ensure-$tag-$4" <<<"$ANSWER"
    return 0
}
af() { py field "$1" <<<"$ANSWER"; }

# eq WHAT GOT WANT: a step's check; sets `reason` and fails when they differ.
eq() { [ "$2" = "$3" ] && return 0; reason="$1=$2 wanted=$3"; return 1; }
# ⟨M06 W5 `w5s`, PC job 38 diagnostics⟩ result_summary FACTS: what a result's facts say about it,
# for a failed step's reason: its code, reason, exit and error fields, and its message protected
# here (codes and words only: never a path, address or quote; 300 characters).
result_summary() {
    local m
    m=$(fact message <<<"$1" | tr -d '\n' | tr -c 'A-Za-z0-9_=,\- ' '?' | cut -c1-300)
    printf 'code=%s reason=%s exit=%s error_fields=%s message=%s' "$(fact code <<<"$1" | grep . || echo none)" \
        "$(fact reason <<<"$1" | grep . || echo none)" "$(fact exit <<<"$1" | grep . || echo none)" \
        "$(fact error_fields <<<"$1" | tr -c 'A-Za-z0-9_,\n' '?' | grep . || echo none)" "${m:-none}"
}
# eqr NAME GOT WANT FACTS: `eq` for a step's first assertion on a result; a failure also says the
# result's code, reason and message (result_summary), never the asserted field alone.
eqr() { [ "$2" = "$3" ] && return 0; reason="$1=$2 wanted=$3 $(result_summary "$4")"; return 1; }

# --- the runner side -------------------------------------------------------------------------------

rssh() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$host" "$@"; }
# runner WORLD ACTION ARGS... (defined once the staging directory exists, below): one action of
# the runner script on the runner host, in that journey's runner installation. Prints its facts;
# its exit code is the action's.
# must_runner: the same; a failed action fails the step with the action's name.
must_runner() {
    local out
    out=$(runner "$@") || { reason="runner_action=$2 failed"; return 1; }
    printf '%s\n' "$out"
}

# The forward of one journey: this host's loopback port LPORT to the management sshd on the
# runner host's loopback, its own ssh connection over the owner's alias.
forward_open() { # WORLD
    local w=$1 lport mport pid i=0
    lport=$(cat "$run/w-$w/lport") && mport=$(cat "$run/w-$w/mport") || return 1
    [ ! -f "$run/w-$w/forward.pid" ] || { reason="forward=already_open"; return 1; }
    ssh -N -o BatchMode=yes -o ConnectTimeout=20 -o ExitOnForwardFailure=yes -o ControlMaster=no -o ControlPath=none \
        -o ServerAliveInterval=15 -o ForwardAgent=no -L "127.0.0.1:$lport:127.0.0.1:$mport" "$host" </dev/null >/dev/null 2>&1 &
    pid=$!
    echo "$pid" >"$run/w-$w/forward.pid"
    start_of "$pid" >"$run/w-$w/forward.start"
    while [ $i -lt 60 ]; do
        if py banner "$lport"; then return 0; fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
        i=$((i + 1))
    done
    reason="forward=not_reachable"
    return 1
}
# forward_close WORLD: stop exactly the recorded forward (this script's own child), by its exact
# PID and only after that PID's identity was checked (`same_process`: its start time, and a
# command line with this journey's `-L 127.0.0.1:<lport>:`). Sets FORWARD_HOW as
# controller_stop sets STOP_HOW.
forward_close() {
    local w=$1 pid start needle i=0 rc
    FORWARD_HOW=not_recorded
    pid=$(cat "$run/w-$w/forward.pid" 2>/dev/null) || return 0
    case "$pid" in '' | *[!0-9]*) rm -f "$run/w-$w/forward.pid" "$run/w-$w/forward.start"; return 0 ;; esac
    start=$(cat "$run/w-$w/forward.start" 2>/dev/null)
    needle="-L 127.0.0.1:$(cat "$run/w-$w/lport"):"
    same_process "$pid" "$start" "$needle"
    rc=$?
    if [ $rc = 1 ]; then FORWARD_HOW=already_gone; rm -f "$run/w-$w/forward.pid" "$run/w-$w/forward.start"; return 0; fi
    if [ $rc = 2 ]; then FORWARD_HOW=identity_mismatch; rm -f "$run/w-$w/forward.pid" "$run/w-$w/forward.start"; return 0; fi
    kill "$pid" 2>/dev/null
    while [ $i -lt 100 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    same_process "$pid" "$start" "$needle" && return 1
    wait "$pid" 2>/dev/null
    rm -f "$run/w-$w/forward.pid" "$run/w-$w/forward.start"
    FORWARD_HOW=stopped_by_exact_pid_identity_checked
    return 0
}
port_listening() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
port_in_use() { lsof -nP -iTCP:"$1" >/dev/null 2>&1; }

# driver ENTRY FACTS_OUT VAR=VALUE...: one fixture entry of e2e_windows_controller_m06 on this
# host (no `heimdall` is started by seed_controller).
driver() {
    local entry=$1 out=$2 rc
    shift 2
    env -i PATH=/usr/bin:/bin HOME="$run" "$@" HM_M06J_FACTS_OUT="$out" "$driver_bin" --ignored --exact "$entry" </dev/null >"$run/driver.log" 2>&1
    rc=$?
    echo "exit $rc: e2e_windows_controller_m06 --ignored --exact $entry" >>"$commands"
    [ $rc = 0 ] && [ -f "$out" ] && return 0
    keep_debug "$run/driver.log" "driver-$entry"
    reason="driver_entry=$entry exit=$rc"
    return 1
}

# world_up WORLD POLICY: one runner installation on the runner host with its two fixture sshds,
# one controller installation here (TAG = WORLD), the forward, and the pairing through the
# product's `environment add`. POLICY is the file the runner's sshd policy check reads
# (sshd_config, or a policy-* variant). Sets, for the journey: ENVIRONMENT, CA, ACCOUNT, PAIR_OBS.
world_up() {
    local w=$1 policy=${2:-sshd_config} c=$run/c-$1 f key pub first second lport
    mkdir -m 700 "$run/w-$w" || return 1
    WORLDS+=("$w")
    f=$(must_runner "$w" prepare "\$STAGE/heimdall" "$linux_heimdall_sha" "\$STAGE/journey-driver" "$linux_driver_sha") || return 1
    ACCOUNT=$(fact account <<<"$f")
    local program rhome rsha mkey
    program=$(fact runner_program <<<"$f"); rhome=$(fact runner_home <<<"$f"); rsha=$(fact runner_sha256 <<<"$f"); mkey=$(fact mgmt_host_key <<<"$f")
    [ -n "$ACCOUNT" ] && [ -n "$program" ] && [ -n "$rhome" ] && [ -n "$mkey" ] || { reason="runner_prepare_facts=incomplete"; return 1; }
    eq runner_sha256 "$rsha" "$linux_heimdall_sha" || return 1
    controller_new "$w" || { reason="controller_home=not_created"; return 1; }
    CONTROLLERS+=("$w")
    # The controller's existing access: a per-run fixture key in its scratch account home.
    key=$c/acct/.ssh/id_fixture
    env -i PATH=/usr/bin:/bin HOME="$c/acct" ssh-keygen -q -t ed25519 -N '' -C hm-m06x-access -f "$key" </dev/null >/dev/null 2>&1 || { reason="ssh_keygen=failed"; return 1; }
    pub=$(awk '{ print $1 " " $2 }' "$key.pub")
    must_runner "$w" authorize "$pub" >/dev/null || return 1
    f=$(must_runner "$w" sshd-start mgmt) || return 1
    fact port <<<"$f" >"$run/w-$w/mport"
    f=$(must_runner "$w" sshd-start dest) || return 1
    case "$policy" in policy-*) must_runner "$w" policy-config "${policy#policy-}" >/dev/null || return 1 ;; esac
    case "$(cat "$run/w-$w/mport")" in '' | *[!0-9]*) reason="mgmt_port=none"; return 1 ;; esac
    lport=$(py free-port) || return 1
    echo "$lport" >"$run/w-$w/lport"
    printf '[127.0.0.1]:%s %s\n' "$lport" "$mkey" >"$c/acct/.ssh/known_hosts"
    ssh_config "$ALIAS" "$lport" "$key" "$c/acct/.ssh/known_hosts" >"$c/acct/.ssh/config"
    chmod 600 "$c/acct/.ssh/config" "$c/acct/.ssh/known_hosts"
    forward_open "$w" || return 1
    driver seed_controller "$c/facts/seed" HM_M06J_HOME="$c/home" HM_M06J_ACCOUNT="$ACCOUNT" HM_M06J_ALIAS="$ALIAS" \
        HM_M06J_MGMT_HOST=127.0.0.1 HM_M06J_MGMT_PORT="$lport" HM_M06J_MGMT_HOST_KEY="$mkey" || return 1
    CA=$(fact ca_fingerprint <"$c/facts/seed")
    CAS+=("$CA")
    fact ca_public_key <"$c/facts/seed" | awk '{ print $1 " " $2 }' >"$run/w-$w/ca.pub"
    fact principal <"$c/facts/seed" >"$run/w-$w/principal"
    must_runner "$w" trust-ca "$(cat "$run/w-$w/ca.pub")" "$(cat "$run/w-$w/principal")" >/dev/null || return 1
    local add=(environment add --destination runner1 --account "$ACCOUNT" --runner-program "$program" --runner-home "$rhome" --runner-sha256 "$rsha")
    # The bootstrap session, confirmed at the runner. The runner's runtime does not run yet (the
    # runner exists only once `remote init` made it): the session SAYS so and OFFERS to start
    # it (ADR-0012 2.6, the 2026-11-22 bullets). The journey ACCEPTS the offer with a typed
    # yes (the orchestrator's ruling of 2026-11-22 on w5k's gap), so the real bootstrap path is
    # what is evidenced: the product starts the runner's runtime, waits until it serves, and
    # the controller opens its management session and writes its record in this one pass.
    first=$(ctl_pty "$w" --offer yes --field environment=data.environment --field client=data.client --field role=data.role -- "${add[@]}")
    eqr pair_prompted "$(fact prompted <<<"$first")" true "$first" || return 1
    eq pair_runtime_offer "$(fact runtime_offer <<<"$first")" accepted || return 1
    eq pair_runtime_stated "$(fact runtime_stated <<<"$first")" started || return 1
    eqr pair_code "$(fact code <<<"$first")" OK "$first" || return 1
    # The rest of the journey needs the FIXTURE's runner: its catalog seed is written only
    # while no runtime runs, and its runtime reads this row's sshd policy file and time state.
    # So the runtime the product just started is stopped through the product's own `service
    # stop` on the runner's scratch home (it must have been serving, and must be gone), the
    # runner is seeded, and the fixture's runtime is started as a recorded process. This is a
    # stated step of the fixture, after the pairing it evidences, never a second pairing pass.
    f=$(must_runner "$w" runtime-offered-stop) || return 1
    eq offered_runtime_before_stop "$(fact offered_runtime <<<"$f")" running || return 1
    eq offered_runtime_after_stop "$(fact runtime <<<"$f")" stopped || return 1
    must_runner "$w" seed >/dev/null || return 1
    f=$(must_runner "$w" runtime-start-with synchronized "$policy") || return 1
    eq runner_runtime "$(fact runtime <<<"$f")" running || return 1
    local second=$first
    ENVIRONMENT=$(fact environment <<<"$second")
    case "$ENVIRONMENT" in env_*) ;; *) reason="pair_environment=none"; return 1 ;; esac
    eq controller_record "$(status "$w" "$ENVIRONMENT" | fact present)" true || return 1
    [ -s "$c/k_mgmt.fixture" ] || { reason="k_mgmt_fixture_store=empty"; return 1; }
    controller_start "$w" || return 1
    PAIR_OBS="controller=environment_add_on_terminal runner=remote_init_confirmed_on_terminal owner_enrolled=true issuer_trusted=true controller_record=written_by_environment_add runtime_offer=accepted_typed_yes runner_runtime=started_by_the_bootstrap_session_and_serving pairing=one_pass code=$(fact code <<<"$first") then_fixture=offered_runtime_stopped_by_service_stop_runner_seeded_fixture_runtime_started management_route=ssh_forward_to_runner_loopback controller_host=macos runner_host=linux k_mgmt_store=fixture_file"
    return 0
}

# world_down WORLD: stop and remove everything of one journey, on both hosts.
world_down() {
    local w=$1 ok=0 f
    controller_stop "$w" || ok=1
    forward_close "$w" || ok=1
    f=$(runner "$w" cleanup)
    [ "$(fact removed <<<"$f")" = yes ] || ok=1
    return $ok
}

# --- the steps --------------------------------------------------------------------------------------

# step TEST CASE STEP FUNCTION: run one step unless its journey already failed. FUNCTION sets
# `obs` and returns 0, or sets `reason` and returns nonzero.
step() {
    local test=$1 case=$2 name=$3 fn=$4
    [ "$journey_failed" = 0 ] || return 0
    obs=""; reason=""
    if "$fn"; then
        printf '%s\t%s\t%s\tok\t%s\n' "$test" "$case" "$name" "$obs" >>"$results"
        echo "m06 observation: $case $name: $obs"
    else
        printf '%s\t%s\t%s\tfailed\t%s\n' "$test" "$case" "$name" "${reason:-no_reason}" >>"$results"
        echo "FAILED $test: $(py protect <<<"${reason:-no_reason}")"
        journey_failed=1
        failed=$((failed + 1))
    fi
    ran=$((ran + 1))
}
selected() { case " $only " in *" $1 "*) return 0 ;; esac; return 1; }

# identities WORLD ENDPOINT -> "count ca_matches"
check_identities() { # WORLD ENDPOINT WANT_COUNT [CA]
    local f
    f=$(must_runner "$1" identities "$2") || return 1
    eq identities "$(fact identities <<<"$f")" "$3" || return 1
    if [ -n "${4:-}" ]; then eq certificate_signed_by_expected_ca "$([ "$(fact certificate_ca <<<"$f")" = "$4" ] && echo true || echo false)" true || return 1; fi
}
check_onward() { # WORLD ENDPOINT WANT
    local f
    f=$(must_runner "$1" onward "$2") || return 1
    eq onward "$(fact onward <<<"$f")" "$3"
}
# runner_ensure WORLD WORK REQUEST LIFETIME: the runner owner's local request; sets R_GRANT,
# R_ENDPOINT, R_DEPENDENCY.
runner_ensure() {
    local f
    f=$(must_runner "$1" ensure "$2" "$3" "$4") || return 1
    case "$(fact code <<<"$f")" in OK | ACCESS_READY) ;; *) reason="runner_ensure=$(fact code <<<"$f")"; return 1 ;; esac
    R_GRANT=$(fact grant <<<"$f"); R_ENDPOINT=$(fact endpoint <<<"$f"); R_DEPENDENCY=$(fact refresh_dependency <<<"$f")
}
epoch() { python3 -I -c 'import sys, datetime; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")).timestamp()))' "$1" 2>/dev/null; }

# ---- A24 ----
s_a24_pair() { world_up a24 || return 1; obs=$PAIR_OBS; }
s_a24_approve() {
    A24_ASKED=$(date +%s)
    forwarded_ensure a24 "$ENVIRONMENT" job-x-a24 x-a24-fwd-1 "${lifetime}s" || return 1
    eq code "$(af code)" OK || return 1
    eq environment "$(af data.environment_id)" "$ENVIRONMENT" || return 1
    eq mechanism "$(af data.credential_mechanism)" managed_certificate || return 1
    A24_GRANT=$(af data.grant_id)
    [ "$A24_GRANT" != none ] || { reason="grant=none"; return 1; }
    A24_READY=$ANSWER
    obs="admitted_by=runner_standing_policy mechanism=managed_certificate issued_by=controller_issuer_child"
}
s_a24_readiness() {
    local expires offline usable f n known_state known_bound i=0
    ANSWER=$A24_READY
    eq refresh_dependency "$(af data.refresh_dependency)" controller || return 1
    expires=$(epoch "$(af data.expires_at)"); offline=$(epoch "$(af data.offline_until)"); usable=$(epoch "$(af data.usable_until)")
    [ -n "$expires" ] && [ -n "$offline" ] && [ -n "$usable" ] || { reason="readiness_instants=absent"; return 1; }
    [ "$offline" -le "$expires" ] && [ "$usable" -le "$expires" ] || { reason="bound_past_the_grant_deadline=true"; return 1; }
    n=$((expires - A24_ASKED))
    [ "$n" -ge 0 ] && [ "$n" -le $((lifetime + 5)) ] || { reason="grant_deadline_is_not_the_asked_lifetime seconds=$n"; return 1; }
    # The controller's own view: the grant within its bound.
    while :; do
        f=$(ctl a24 environment status | python3 -I -c '
import json, sys
env, grant = sys.argv[1], sys.argv[2]
try:
    entries = json.load(sys.stdin)["data"]["environments"]
except Exception:
    entries = []
for e in entries:
    rec = e.get("record") or e
    if rec.get("environment") != env and e.get("environment") != env:
        continue
    views = [e, e.get("remote") or {}]
    for v in views:
        for g in v.get("last_known_readiness") or []:
            if g.get("grant") == grant:
                print("state=%s" % g.get("state")); print("bound=%s" % g.get("offline_until"))
        if "connectivity" in v: print("connectivity=%s" % (v["connectivity"] or {}).get("state"))
        if "issuance" in v: print("issuance=%s" % v["issuance"])
' "$ENVIRONMENT" "$A24_GRANT")
        known_state=$(fact state <<<"$f")
        [ -n "$known_state" ] && break
        i=$((i + 1)); [ $i -lt 100 ] || { reason="controller_status_grant=not_reported"; return 1; }
        sleep 0.4
    done
    eq status_state "$known_state" within_bound || return 1
    eq connectivity "$(fact connectivity <<<"$f")" connected || return 1
    eq issuance "$(fact issuance <<<"$f")" reconciled || return 1
    known_bound=$(epoch "$(fact bound <<<"$f")")
    [ -n "$known_bound" ] && [ "$known_bound" -le "$expires" ] || { reason="status_bound_past_the_grant=true"; return 1; }
    A24_BOUND=$known_bound
    # The runner's own report: its owner's local request attaches to the same grant and names
    # the same dependency and a bound no later than the grant's.
    runner_ensure a24 job-x-a24-local x-a24-local-1 30s || return 1
    eq runner_grant_is_the_forwarded_grant "$([ "$R_GRANT" = "$A24_GRANT" ] && echo true || echo false)" true || return 1
    eq runner_refresh_dependency "$R_DEPENDENCY" controller || return 1
    A24_ENDPOINT=$R_ENDPOINT
    check_identities a24 "$A24_ENDPOINT" 1 "$CA" || return 1
    obs="refresh_dependency=controller status=within_bound earliest_bound=certificate_valid_before bound_within_grant_deadline=true controller_view=connected_reconciled runner_own_report=same_grant_dependency_controller runner_endpoint_identities=1"
}
s_a24_work_clean_launch() {
    local d=$run/fa f out pid i=0
    mkdir -m 700 "$d" || return 1
    # A DISPOSABLE agent with one per-run key, started here; it stands for nothing of the owner's.
    env -i PATH=/usr/bin:/bin HOME="$d" ssh-keygen -q -t ed25519 -N '' -C hm-m06x-forwarded-fixture -f "$d/key" </dev/null >/dev/null 2>&1 || { reason="ssh_keygen=failed"; return 1; }
    env -i PATH=/usr/bin:/bin HOME="$d" ssh-agent -D -a "$d/agent.sock" </dev/null >/dev/null 2>&1 &
    pid=$!
    echo "$pid" >"$d/agent.pid"
    while [ $i -lt 50 ] && [ ! -S "$d/agent.sock" ]; do sleep 0.1; i=$((i + 1)); done
    env -i PATH=/usr/bin:/bin HOME="$d" SSH_AUTH_SOCK="$d/agent.sock" ssh-add -q "$d/key" </dev/null >/dev/null 2>&1 || { reason="fixture_agent=no_key"; return 1; }
    # A real ssh session from the controller host to the runner host that forwards that agent.
    out=$(ssh -o BatchMode=yes -o ConnectTimeout=20 -o ControlMaster=no -o ControlPath=none -o ForwardAgent="$d/agent.sock" "$host" \
        "bash \"\$HOME/$stage/crosshost-runner.sh\" work \"\$HOME/$stage/hm-m06j-a24\" job-x-a24-local x-a24-work-1" </dev/null 2>/dev/null)
    echo "exit $?: ssh <runnerhost> (a session forwarding the disposable fixture agent) crosshost-runner.sh work <root:a24>" >>"$commands"
    dbg work-a24 <<<"$out"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -f "$d/agent.pid"
    f=$out
    eq session_forwarded_an_agent "$(fact session_agent <<<"$f")" true || return 1
    eq session_agent_keys "$(fact session_agent_keys <<<"$f")" 1 || return 1
    eq session_connection "$(fact session_connection <<<"$f")" true || return 1
    eq work_exit "$(fact exit <<<"$f")" 0 || return 1
    eq work_env_extra "$(fact work_env_extra <<<"$f")" none || return 1
    eq work_shell_is_account_shell "$(fact work_shell_is_account_shell <<<"$f")" true || return 1
    eq work_has_session_marker "$(fact work_has_session_marker <<<"$f")" false || return 1
    eq work_has_ssh_connection "$(fact work_has_ssh_connection <<<"$f")" false || return 1
    eq work_agent_is_session_agent "$(fact work_agent_is_session_agent <<<"$f")" false || return 1
    eq work_agent_under_runner_home "$(fact work_agent_under_runner_home <<<"$f")" true || return 1
    eq work_agent_identities "$(fact work_agent_identities <<<"$f")" 1 || return 1
    eq work_agent_certificates "$(fact work_agent_certificates <<<"$f")" 1 || return 1
    eq work_agent_lists_session_key "$(fact work_agent_lists_session_key <<<"$f")" false || return 1
    eq provenance "$(fact provenance <<<"$f")" controller_dependency || return 1
    eq stderr_names_session_socket "$(fact stderr_names_session_socket <<<"$f")" false || return 1
    obs="launched_by=heimdall_run launcher=real_ssh_session_from_controller_host_with_agent_forwarding forwarded_agent=disposable_fixture_agent environment=clean_allowlist_only shell=account_database work_agent=binding_endpoint work_agent_lists=runner_k_env_certificate_only forwarded_agent_inherited=false forwarded_agent_provenance=controller_dependency controller=running"
}
s_a24_controller_leaves() {
    local c=$run/c-a24 pid kids f i=0 lport
    lport=$(cat "$run/w-a24/lport")
    pid=$(cat "$c/runtime.pid") || { reason="controller_runtime=not_recorded"; return 1; }
    kids=$(children_of "$pid" | tr '\n' ' ')
    [ -n "$kids" ] || { reason="issuer_child=absent"; return 1; }
    controller_stop a24 || { reason="controller_runtime=still_running"; return 1; }
    eq controller_runtime_stop "$STOP_HOW" stopped_by_exact_pid_identity_checked || return 1
    # shellcheck disable=SC2086
    while any_alive $kids; do i=$((i + 1)); [ $i -lt 300 ] || { reason="issuer_child=still_running"; return 1; }; sleep 0.1; done
    echo "$kids" >"$run/w-a24/issuer.pids"
    forward_close a24 || { reason="forward=still_open"; return 1; }
    eq management_forward_stop "$FORWARD_HOW" stopped_by_exact_pid_identity_checked || return 1
    port_in_use "$lport" && { reason="controller_host_port=still_in_use"; return 1; }
    # Part a of the "No silent controller socket" row: how and when the controller was gone.
    echo "$STOP_HOW" >"$run/w-a24/gone.runtime"
    echo "$FORWARD_HOW" >"$run/w-a24/gone.forward"
    date +%s >"$run/w-a24/gone.at"
    # The window starts here: what the fixture management sshd has logged so far.
    f=$(must_runner a24 sshd-log mgmt) || return 1
    fact connections <<<"$f" >"$run/w-a24/window.connections"
    fact accepted <<<"$f" >"$run/w-a24/window.accepted"
    fact lines <<<"$f" >"$run/w-a24/window.lines"
    date +%s >"$run/w-a24/window.start"
    obs="controller_runtime=$STOP_HOW issuer_child=stopped management_forward=$FORWARD_HOW controller_host_listener=none"
}
s_a24_onward_managed() {
    local s gone
    check_identities a24 "$A24_ENDPOINT" 1 "$CA" || return 1
    check_onward a24 "$A24_ENDPOINT" ok || return 1
    # Part b of the "No silent controller socket" row, AT THIS MOMENT (the onward login just
    # succeeded): the runner host's connection table, read right after it.
    date +%s >"$run/w-a24/onward.ok_at"
    s=$(must_runner a24 sockets) || return 1
    printf '%s\n' "$s" >"$run/w-a24/onward.sockets"
    gone=$(cat "$run/w-a24/gone.at" 2>/dev/null)
    case "$gone" in '' | *[!0-9]*) reason="controller_gone_at=unknown"; return 1 ;; esac
    [ "$gone" -le "$(cat "$run/w-a24/onward.ok_at")" ] || { reason="controller_gone_before_onward=false"; return 1; }
    obs="login=ok credential=runner_k_env_certificate signed_by=controller_ca controller=stopped route=closed controller_gone_before_this_login=true"
}
s_a24_no_controller_socket() {
    local f p s lport since n kids k left
    lport=$(cat "$run/w-a24/lport")
    # Keep the window open for a while: a silent reconnect would show in it.
    since=$(cat "$run/w-a24/window.start"); left=$((since + 20 - $(date +%s)))
    [ "$left" -le 0 ] || sleep "$left"
    # The runner host, as the product reports it and as this account can read it.
    check_identities a24 "$A24_ENDPOINT" 1 "$CA" || return 1
    p=$(must_runner a24 processes) || return 1
    eq runtime_parent_is_sshd "$(fact runtime_parent_is_sshd <<<"$p")" false || return 1
    [ "$(fact runtime_has_ssh_auth_sock <<<"$p")" != true ] || { reason="runtime_has_ssh_auth_sock=true"; return 1; }
    s=$(must_runner a24 sockets) || return 1
    eq mgmt_established "$(fact mgmt_established <<<"$s")" 0 || return 1
    eq forwarded_agent_sockets "$(fact unix_listeners_named_agent_elsewhere <<<"$s")" 0 || return 1
    [ "$(fact unix_listeners_under_runner_home <<<"$s")" -ge 1 ] 2>/dev/null || { reason="runner_own_sockets=none"; return 1; }
    f=$(must_runner a24 sshd-log mgmt) || return 1
    n=$(($(fact connections <<<"$f") - $(cat "$run/w-a24/window.connections")))
    eq mgmt_sshd_connections_in_window "$n" 0 || return 1
    local sessions at
    sessions=$(($(fact accepted <<<"$f") - $(cat "$run/w-a24/window.accepted")))
    at=$(cat "$run/w-a24/onward.sockets" 2>/dev/null)
    # The same table again now, at the end of the window, by direction: still nothing opened
    # to the controller host and nothing accepted on the fixture's port.
    eq runner_host_outbound_to_controller_host_now "$(fact outbound_to_controller_host <<<"$s")" 0 || return 1
    eq runner_host_inbound_on_management_port_now "$(fact mgmt_inbound <<<"$s")" 0 || return 1
    eq runner_host_inbound_on_fixture_port_now "$(fact dest_inbound <<<"$s")" 0 || return 1
    # The controller host: nothing of the controller is left, nothing listens or connects.
    [ ! -f "$run/c-a24/runtime.pid" ] && [ ! -f "$run/w-a24/forward.pid" ] || { reason="controller_process=recorded"; return 1; }
    kids=$(cat "$run/w-a24/issuer.pids")
    for k in $kids; do kill -0 "$k" 2>/dev/null && { reason="issuer_child=alive"; return 1; }; done
    port_in_use "$lport" && { reason="controller_host_port=in_use"; return 1; }
    # (The pattern is passed in the environment, so the counting process does not match itself.)
    n=$(HM_XH_PATTERN="$run/c-a24/" ps -A -o command= | HM_XH_PATTERN="$run/c-a24/" awk 'BEGIN { p = ENVIRON["HM_XH_PATTERN"] } index($0, p) { n++ } END { print n + 0 }')
    eq controller_host_processes_of_this_controller "$n" 0 || return 1
    # The row's three parts, in the ruled order (a, b, c); it passes only if all three hold.
    # The rest of what was observed follows them. The other half of the row is the clean-launch
    # exact-set test the case index cites (no SSH_AUTH_SOCK reaches runner work).
    socket_row_obs \
        runtime_stop="$(cat "$run/w-a24/gone.runtime" 2>/dev/null)" forward_stop="$(cat "$run/w-a24/gone.forward" 2>/dev/null)" \
        gone_at="$(cat "$run/w-a24/gone.at" 2>/dev/null)" onward_ok_at="$(cat "$run/w-a24/onward.ok_at" 2>/dev/null)" \
        controller_host_known="$(fact controller_host_known <<<"$at")" at_onward_outbound="$(fact outbound_to_controller_host <<<"$at")" \
        at_onward_mgmt="$(fact mgmt_inbound <<<"$at")" at_onward_fixture="$(fact dest_inbound <<<"$at")" \
        at_onward_inbound="$(fact inbound_from_controller_host <<<"$at")" at_onward_channel="$(fact observation_channel <<<"$at")" \
        window_connections="$n" window_sessions="$sessions" window_s="$(($(date +%s) - since))" \
        fd_readable="$(fact runtime_fd_readable <<<"$s")" fd_reason="$(fact runtime_fd_unreadable_reason <<<"$s")" \
        rest="endpoint=under_runner_home identities=1 identity=runner_k_env_certificate runner_runtime_parent_is_sshd=false runner_started_with_ssh_auth_sock=$(fact runtime_has_ssh_auth_sock <<<"$p") runner_host_forwarded_agent_sockets=0 runner_host_outbound_to_controller_host_at_window_end=0 controller_host_processes=0 controller_host_forward_port=closed" || return 1
}
s_a24_bound() {
    local wait f state conn
    wait=$((A24_BOUND + 3 - $(date +%s)))
    [ "$wait" -le 0 ] || sleep "$wait"
    check_onward a24 "$A24_ENDPOINT" refused || return 1
    f=$(ctl a24 environment status | python3 -I -c '
import json, sys
env, grant = sys.argv[1], sys.argv[2]
try:
    entries = json.load(sys.stdin)["data"]["environments"]
except Exception:
    entries = []
for e in entries:
    rec = e.get("record") or e
    if rec.get("environment") != env and e.get("environment") != env:
        continue
    for v in (e, e.get("remote") or {}):
        for g in v.get("last_known_readiness") or []:
            if g.get("grant") == grant: print("state=%s" % g.get("state"))
        if "connectivity" in v: print("connectivity=%s" % (v["connectivity"] or {}).get("state"))
' "$ENVIRONMENT" "$A24_GRANT")
    state=$(fact state <<<"$f"); conn=$(fact connectivity <<<"$f")
    eq status_state "$state" bound_passed || return 1
    [ "$conn" != connected ] || { reason="connectivity=connected"; return 1; }
    obs="managed_login_at_predicted_bound=refused status=bound_passed controller=stopped"
}

# ---- A07 ----
s_a07_pair() { world_up a07 || return 1; obs=$PAIR_OBS; }
s_a07_issued() {
    forwarded_ensure a07 "$ENVIRONMENT" job-x-a07 x-a07-fwd-1 1h || return 1
    eq code "$(af code)" OK || return 1
    A07_GRANT=$(af data.grant_id)
    runner_ensure a07 job-x-a07-local x-a07-local-1 30s || return 1
    eq runner_grant_is_the_forwarded_grant "$([ "$R_GRANT" = "$A07_GRANT" ] && echo true || echo false)" true || return 1
    A07_ENDPOINT=$R_ENDPOINT
    check_identities a07 "$A07_ENDPOINT" 1 "$CA" || return 1
    check_onward a07 "$A07_ENDPOINT" ok || return 1
    wait_view a07 "$ENVIRONMENT" connectivity.state connected || return 1
    obs="grant=issued onward_login=ok"
}
# The record's view fields live at the entry's top level or under `remote`: read either.
view() { # TAG ENV PATH
    local v
    v=$(status "$1" "$2" a="$3" b="remote.$3")
    if [ "$(fact a <<<"$v")" != none ]; then fact a <<<"$v"; else fact b <<<"$v"; fi
}
wait_view() { # TAG ENV PATH WANT [SECONDS]
    local until=$(($(date +%s) + ${5:-60})) last=""
    while :; do
        last=$(view "$1" "$2" "$3")
        [ "$last" = "$4" ] && return 0
        if [ "$(date +%s)" -ge "$until" ]; then reason="status_$(tr '.' '_' <<<"$3")=$last wanted=$4"; return 1; fi
        sleep 0.4
    done
}
a07_disconnect() {
    forward_close a07 || { reason="forward=still_open"; return 1; }
    controller_stop a07 || { reason="controller_runtime=still_running"; return 1; }
    controller_start a07 || return 1
    wait_view a07 "$ENVIRONMENT" issuance awaiting_resync || return 1
    [ "$(view a07 "$ENVIRONMENT" connectivity.state)" != connected ] || { reason="connectivity=connected"; return 1; }
}
s_a07_disconnected() {
    a07_disconnect || return 1
    obs="connectivity=not_connected issuance=awaiting_resync management_forward=closed"
}
s_a07_revoke_pending() {
    local r
    r=$(ctl a07 access revoke "$A07_GRANT")
    dbg revoke-a07 <<<"$r"
    eq code "$(py field code <<<"$r")" OK || return 1
    eq local_applied "$(py field data.local_applied <<<"$r")" false || return 1
    eq remote_pending_names_the_grant "$([ "$(py field data.remote_pending.0 <<<"$r")" = "$A07_GRANT" ] && echo true || echo false)" true || return 1
    eq pending_target "$(view a07 "$ENVIRONMENT" remote_pending.0.target.kind)" grant_revoke || return 1
    eq pending_count "$(view a07 "$ENVIRONMENT" remote_pending.1.target.kind)" none || return 1
    eq residual_acknowledged "$(view a07 "$ENVIRONMENT" residuals.0.acknowledged)" false || return 1
    [ "$(view a07 "$ENVIRONMENT" residuals.0.statement)" != none ] || { reason="residual_statement=none"; return 1; }
    # Not applied on the runner yet: it still serves the grant.
    check_identities a07 "$A07_ENDPOINT" 1 || return 1
    check_onward a07 "$A07_ENDPOINT" ok || return 1
    obs="local_applied=false remote_pending=1 target=grant_revoke residual=stated acknowledged=false runner_still_serves=true"
}
s_a07_reconnect() {
    local st names
    forward_open a07 || return 1
    forwarded_ensure a07 "$ENVIRONMENT" job-x-a07 x-a07-fwd-1 1h || return 1
    wait_view a07 "$ENVIRONMENT" remote_pending "[]" || return 1
    wait_view a07 "$ENVIRONMENT" residuals.0.acknowledged true || return 1
    st=$(view a07 "$ENVIRONMENT" residuals.0.statement)
    check_identities a07 "$A07_ENDPOINT" 0 || return 1
    check_onward a07 "$A07_ENDPOINT" refused || return 1
    names=false
    case "$st" in *"destination-clock error"*) names=true ;; esac
    obs="remote_pending=0 residual_acknowledged=true residual_names_destination_clock_error=$names runner_endpoint_identities=0 onward_login=refused management_forward=reopened"
}
s_a07_barrier() {
    wait_view a07 "$ENVIRONMENT" issuance reconciled || return 1
    eq connectivity "$(view a07 "$ENVIRONMENT" connectivity.state)" connected || return 1
    obs="while_disconnected=awaiting_resync after_resync=reconciled"
}
s_a07_no_stale_reactivation() {
    forwarded_ensure a07 "$ENVIRONMENT" job-x-a07 x-a07-fwd-1 1h || return 1
    check_identities a07 "$A07_ENDPOINT" 0 || return 1
    case "$(view a07 "$ENVIRONMENT" last_known_readiness)" in *"$A07_GRANT"*) reason="revoked_grant_readiness=present"; return 1 ;; esac
    obs="same_request_again=$(af code) revoked_grant_identities=0 revoked_grant_readiness=none"
}
s_a07_pause_pending() {
    local r
    a07_disconnect || return 1
    r=$(ctl a07 access pause runner-pol)
    dbg pause-a07 <<<"$r"
    eq code "$(py field code <<<"$r")" OK || return 1
    eq pending_target "$(view a07 "$ENVIRONMENT" remote_pending.0.target.kind)" policy_pause || return 1
    eq pending_count "$(view a07 "$ENVIRONMENT" remote_pending.1.target.kind)" none || return 1
    obs="remote_pending=1 target=policy_pause"
}
s_a07_cutoff_pending() {
    local r at f
    at=$(python3 -I -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
    r=$(ctl a07 access cutoff runner-pol --at "$at")
    dbg cutoff-a07 <<<"$r"
    eq code "$(py field code <<<"$r")" OK || return 1
    eq pending_target "$(view a07 "$ENVIRONMENT" remote_pending.1.target.kind)" policy_cutoff || return 1
    eq pending_count "$(view a07 "$ENVIRONMENT" remote_pending.2.target.kind)" none || return 1
    f=$(must_runner a07 policy runner-pol) || return 1
    eq runner_policy_present "$(fact present <<<"$f")" true || return 1
    eq runner_policy_paused_while_disconnected "$(fact paused <<<"$f")" false || return 1
    eq runner_policy_cutoff_while_disconnected "$(fact cutoff <<<"$f")" false || return 1
    obs="remote_pending=2 target=policy_cutoff applied_on_runner_while_disconnected=false"
}
s_a07_uncertain_time() {
    local f
    f=$(must_runner a07 runtime-stop) || return 1
    eq runner_runtime "$(fact runtime <<<"$f")" stopped || return 1
    f=$(must_runner a07 runtime-start-with not_synchronized sshd_config) || return 1
    forward_open a07 || return 1
    sleep 6
    forwarded_ensure a07 "$ENVIRONMENT" job-x-a07-fresh x-a07-fwd-2 30m || return 1
    A07_FRESH=$(af code)
    case "$A07_FRESH" in OK | ACCESS_READY | ACCEPTED) reason="fresh_work_after_pause_and_cutoff=$A07_FRESH"; return 1 ;; esac
    wait_view a07 "$ENVIRONMENT" remote_pending "[]" || return 1
    f=$(must_runner a07 policy runner-pol) || return 1
    eq runner_policy_paused "$(fact paused <<<"$f")" true || return 1
    eq runner_policy_cutoff "$(fact cutoff <<<"$f")" true || return 1
    obs="runner_time=not_synchronized remote_pending=0 policy_paused=applied policy_cutoff=applied"
}
s_a07_fresh_work_refused() {
    forwarded_ensure a07 "$ENVIRONMENT" job-x-a07-fresh-2 x-a07-fwd-3 30m || return 1
    eq second_fresh_request "$(af code)" "$A07_FRESH" || return 1
    case "$(view a07 "$ENVIRONMENT" last_known_readiness)" in none | "[]") ;; *) reason="issued_after_cutoff=true"; return 1 ;; esac
    obs="fresh_work_id=$A07_FRESH issued=nothing"
}

# ---- T06 and A25 share the invitation path ----
# invite_join OWNER_TAG NEW_TAG ROLE WORLD: the invited device shows its key; the owner invites it
# (confirmed here on a terminal); the runner's local owner approves at the runner's terminal;
# the owner collects the bundle; the invited device joins on a terminal. Sets INVITED_CLIENT.
invite_join() {
    local owner=$1 new=$2 role=$3 world=$4 key f ref rid
    f=$(ctl "$new" environment join --show-key)
    dbg "showkey-$new" <<<"$f"
    key=$(py field data.public_key <<<"$f")
    case "$key" in "ssh-ed25519 "*) ;; *) reason="invited_key=none code=$(py field code <<<"$f")"; return 1 ;; esac
    eq invited_key_store "$(py field data.store.test <<<"$f" | grep -c -v '^none$')" 1 || return 1
    f=$(ctl_pty "$owner" --field decision=next.decision_ref --field message=data.error.message -- environment invite "$ENVIRONMENT" --role "$role" --public-key "$key")
    eqr invite_prompted "$(fact prompted <<<"$f")" true "$f" || return 1
    eq invite_code "$(fact code <<<"$f")" APPROVAL_REQUIRED || return 1
    ref=$(fact decision <<<"$f")
    rid=$(fact message <<<"$f" | sed -n 's/.*--request-id \([A-Za-z0-9_-]*\).*/\1/p')
    [ "$ref" != none ] && [ -n "$rid" ] || { reason="invite_pending_reference=none"; return 1; }
    f=$(must_runner "$world" attended client=data.client -- decision approve "$ref") || return 1
    dbg "approve-$new" <<<"$f"
    eqr runner_approval_prompted "$(fact prompted <<<"$f")" true "$f" || return 1
    eqr runner_approval "$(fact code <<<"$f")" OK "$f" || return 1
    # The same command again, with the request ID the pending answer named: the bundle.
    f=$(ctl_pty "$owner" --envelope-out "$run/c-$new/invite.json" -- environment invite "$ENVIRONMENT" --role "$role" --public-key "$key" --request-id "$rid")
    eq invite_created "$(fact code <<<"$f")" OK || return 1
    python3 -I -c 'import json, sys; json.dump(json.load(open(sys.argv[1]))["data"], open(sys.argv[2], "w"))' "$run/c-$new/invite.json" "$run/c-$new/bundle.json" 2>/dev/null || { reason="bundle=unreadable"; return 1; }
    f=$(ctl_pty "$new" --field client=data.client --field role=data.role --field environment=data.environment -- environment join "$run/c-$new/bundle.json")
    eqr join_prompted "$(fact prompted <<<"$f")" true "$f" || return 1
    eqr join_code "$(fact code <<<"$f")" OK "$f" || return 1
    eq joined_role "$(fact role <<<"$f")" "$role" || return 1
    eq joined_environment "$(fact environment <<<"$f")" "$ENVIRONMENT" || return 1
    INVITED_CLIENT=$(fact client <<<"$f")
}

s_t06_pair() { world_up t06 || return 1; obs=$PAIR_OBS; }
s_t06_first_grant() {
    forwarded_ensure t06 "$ENVIRONMENT" job-x-t06-a x-t06-a-1 1h || return 1
    eq code "$(af code)" OK || return 1
    T06_FIRST=$(af data.grant_id)
    runner_ensure t06 job-x-t06-local x-t06-local-1 30s || return 1
    eq runner_grant_is_the_forwarded_grant "$([ "$R_GRANT" = "$T06_FIRST" ] && echo true || echo false)" true || return 1
    T06_FIRST_ENDPOINT=$R_ENDPOINT
    check_identities t06 "$T06_FIRST_ENDPOINT" 1 "$CA" || return 1
    obs="issued_under=first_ca identities=1"
}
s_t06_second_owner() {
    local c=$run/c-t06b
    controller_new t06b || { reason="second_controller_home=not_created"; return 1; }
    CONTROLLERS+=(t06b)
    # The second installation's own fixture state: its profile and its own issuer (another CA).
    driver seed_controller "$c/facts/seed" HM_M06J_HOME="$c/home" HM_M06J_ACCOUNT="$ACCOUNT" HM_M06J_ALIAS="$ALIAS" \
        HM_M06J_MGMT_HOST=127.0.0.1 HM_M06J_MGMT_PORT="$(cat "$run/w-t06/lport")" \
        HM_M06J_MGMT_HOST_KEY="$(awk '{ print $2 " " $3 }' "$run/c-t06/acct/.ssh/known_hosts")" || return 1
    T06_CA2=$(fact ca_fingerprint <"$c/facts/seed")
    fact ca_public_key <"$c/facts/seed" | awk '{ print $1 " " $2 }' >"$run/w-t06/ca2.pub"
    [ "$T06_CA2" != "$CA" ] || { reason="second_ca=first_ca"; return 1; }
    invite_join t06 t06b owner t06 || return 1
    T06_CLIENT2=$INVITED_CLIENT
    obs="invited_by=first_owner_environment_invite approved_by=runner_local_owner_decision_approve_on_terminal joined_with=own_key_environment_join role=owner requests=product_cli second_controller_host=macos"
}
s_t06_first_controller_gone() {
    controller_stop t06 || { reason="first_controller_runtime=still_running"; return 1; }
    obs="first_controller_runtime=stopped"
}
s_t06_narrowing() {
    local r
    controller_start t06b || return 1
    wait_view t06b "$ENVIRONMENT" connectivity.state connected 90 || return 1
    r=$(ctl t06b access revoke "$T06_FIRST")
    dbg revoke-t06b <<<"$r"
    eq code "$(py field code <<<"$r")" OK || return 1
    wait_view t06b "$ENVIRONMENT" remote_pending "[]" || return 1
    wait_view t06b "$ENVIRONMENT" residuals.0.acknowledged true || return 1
    check_identities t06 "$T06_FIRST_ENDPOINT" 0 || return 1
    obs="effect=grant_revoke target=first_controllers_grant applied_on_runner=true acknowledged_to=second_controller"
}
s_t06_untrusted_issuer() {
    forwarded_ensure t06b "$ENVIRONMENT" job-x-t06-b1 x-t06-b-1 30m || return 1
    eq code "$(af code)" CAPABILITY_UNAVAILABLE || return 1
    eq reason "$(af data.error.reason)" issuer_untrusted || return 1
    obs="forwarded_request=CAPABILITY_UNAVAILABLE reason=issuer_untrusted"
}
s_t06_own_grant() {
    local f own
    f=$(must_runner t06 issuer-trust "$(cat "$run/w-t06/ca2.pub")" "$T06_CLIENT2") || return 1
    eqr trust_prompted "$(fact prompted <<<"$f")" true "$f" || return 1
    eq trust_code "$(fact code <<<"$f")" OK || return 1
    forwarded_ensure t06b "$ENVIRONMENT" job-x-t06-b2 x-t06-b-2 30m || return 1
    eq code "$(af code)" OK || return 1
    own=$(af data.grant_id)
    [ "$own" != "$T06_FIRST" ] && [ "$own" != none ] || { reason="own_grant=first_grant_or_none"; return 1; }
    runner_ensure t06 job-x-t06-local-2 x-t06-local-2 30s || return 1
    eq runner_grant_is_the_second_controllers "$([ "$R_GRANT" = "$own" ] && echo true || echo false)" true || return 1
    T06_OWN_ENDPOINT=$R_ENDPOINT
    check_identities t06 "$T06_OWN_ENDPOINT" 1 "$T06_CA2" || return 1
    check_identities t06 "$T06_FIRST_ENDPOINT" 0 || return 1
    obs="trusted_by=runner_local_owner_on_terminal issued_under=second_ca first_controllers_grant_identities=0"
}
s_t06_destination_trust() {
    check_onward t06 "$T06_OWN_ENDPOINT" refused || return 1
    must_runner t06 trust-ca "$(cat "$run/w-t06/ca2.pub")" "$(cat "$run/w-t06/principal")" >/dev/null || return 1
    check_onward t06 "$T06_OWN_ENDPOINT" ok || return 1
    obs="destination_trusting_first_ca_only=refused destination_trusting_second_ca=ok"
}

s_a25_pair() { world_up a25 || return 1; obs=$PAIR_OBS; }
s_a25_sshd_policy_verified() {
    local f
    f=$(must_runner a25 sshd-check sshd_config) || return 1
    dbg sshd-check-a25 <<<"$f"
    eq sshd_t_exit "$(fact sshd_t_exit <<<"$f")" 0 || return 1
    eq allowagentforwarding "$(fact allowagentforwarding <<<"$f")" no || return 1
    eq allowtcpforwarding "$(fact allowtcpforwarding <<<"$f")" no || return 1
    eq acceptenv_all "$(fact acceptenv_all <<<"$f")" false || return 1
    eq forcecommand "$(fact forcecommand <<<"$f")" none || return 1
    eq authorizedkeyscommand "$(fact authorizedkeyscommand <<<"$f")" none || return 1
    obs="sshd_t=host_sshd_binary_over_fixture_config exit=0 agent_forwarding=no tcp_forwarding=no accept_env_all=false force_command=none authorized_keys_command=none"
}
s_a25_limited_after_verification() {
    controller_new a25v || { reason="viewer_home=not_created"; return 1; }
    CONTROLLERS+=(a25v)
    invite_join a25 a25v viewer a25 || return 1
    eq viewer_record_role "$(status a25v "$ENVIRONMENT" r=role q=record.role | grep -v '=none$' | grep -c '=viewer$')" 1 || return 1
    obs="invited_role=viewer runner_approval=OK joined=environment_join_on_terminal viewer_record_role=viewer requests=product_cli viewer_host=macos"
}
s_a25_sshd_policy_unverified() {
    local v w key f ref
    for v in kc fc ae; do
        # Its own runner installation, paired by its own owner controller, whose sshd policy
        # check reads the variant from its first start: no earlier downgrade stands on it.
        w="a25$v"
        world_up "$w" "policy-$v" || return 1
        f=$(must_runner "$w" sshd-check "policy-$v") || return 1
        eq "sshd_t_exit_$v" "$(fact sshd_t_exit <<<"$f")" 0 || return 1
        case "$v" in
        kc) eq "sshd_t_$v" "$(fact authorizedkeyscommand <<<"$f")" set || return 1 ;;
        fc) eq "sshd_t_$v" "$(fact forcecommand <<<"$f")" set || return 1 ;;
        ae) eq "sshd_t_$v" "$(fact acceptenv_all <<<"$f")" true || return 1 ;;
        esac
        controller_new "${w}v" || { reason="invited_home=not_created"; return 1; }
        CONTROLLERS+=("${w}v")
        key=$(ctl "${w}v" environment join --show-key | py field data.public_key)
        case "$key" in "ssh-ed25519 "*) ;; *) reason="invited_key=none"; return 1 ;; esac
        f=$(ctl_pty "$w" --field decision=next.decision_ref -- environment invite "$ENVIRONMENT" --role viewer --public-key "$key")
        eq "invite_code_$v" "$(fact code <<<"$f")" APPROVAL_REQUIRED || return 1
        ref=$(fact decision <<<"$f")
        f=$(must_runner "$w" attended -- decision approve "$ref") || return 1
        dbg "approve-$w" <<<"$f"
        eqr "runner_approval_prompted_$v" "$(fact prompted <<<"$f")" true "$f" || return 1
        eq "limited_invitation_$v" "$(fact code <<<"$f") $(fact reason <<<"$f")" "CAPABILITY_UNAVAILABLE management_sshd_unverified" || return 1
        # The owner's own management still works on that runner (owner-only, not unusable).
        eq "owner_record_$v" "$(status "$w" "$ENVIRONMENT" r=role q=record.role | grep -c '=owner$')" 1 || return 1
        world_down "$w" || { reason="variant_teardown=incomplete"; return 1; }
    done
    obs="authorized_keys_command=management_sshd_unverified force_command=management_sshd_unverified accept_env_all=management_sshd_unverified refused_at=runner_local_approval runner_installations=one_per_variant policy_check=host_sshd_T_over_variant_config owner_pairing_on_each=ok live_sshd_with_variant=not_run"
}

# --- main -------------------------------------------------------------------------------------------

case "${1:-}" in
--selftest) selftest; exit $? ;;
--plan) plan; exit 0 ;;
esac
out=${1:-}
host=${2:-}
[ -n "$out" ] && [ $# -le 2 ] || { echo "usage: run-crosshost.sh <artifact-dir> <ssh-host-alias> | --selftest | --plan (--container is not built: see the unit's DONE)" >&2; exit 2; }
build_only=${HM_BUILD_ONLY:-0}
if [ "$build_only" != 1 ]; then
    m02_valid_alias "$host" || { echo "bad host alias" >&2; exit 2; }
fi
only=${HM_XH_ONLY:-a24 a07 t06 a25}
for j in $only; do case "$j" in a24 | a07 | t06 | a25) ;; *) echo "bad HM_XH_ONLY" >&2; exit 2 ;; esac; done
lifetime=${HM_XH_LIFETIME_S:-240}
case "$lifetime" in '' | *[!0-9]*) echo "bad HM_XH_LIFETIME_S" >&2; exit 2 ;; esac
[ -z "${HM_XH_DEBUG_DIR:-}" ] || [ -d "$HM_XH_DEBUG_DIR" ] || { echo "HM_XH_DEBUG_DIR is not a directory" >&2; exit 2; }
ALIAS=hm-m06x-runner
blocked() { echo "blocked: $*"; exit 3; }

# Inputs first: nothing is created and no host is contacted before they are known.
prebuilt=0
for v in HM_XH_HEIMDALL HM_XH_DRIVER HM_XH_LINUX_HEIMDALL HM_XH_LINUX_DRIVER; do [ -n "${!v:-}" ] && prebuilt=$((prebuilt + 1)); done
case "$prebuilt" in
0) ;;
4) for v in HM_XH_HEIMDALL HM_XH_DRIVER HM_XH_LINUX_HEIMDALL HM_XH_LINUX_DRIVER; do [ -f "${!v}" ] || blocked "$v is not a file"; done ;;
*) for v in HM_XH_HEIMDALL HM_XH_DRIVER HM_XH_LINUX_HEIMDALL HM_XH_LINUX_DRIVER; do [ -n "${!v:-}" ] && [ -f "${!v}" ] || blocked "$v is not a file (give all four prebuilt inputs, or none)"; done ;;
esac
for t in python3 ssh ssh-keygen ssh-agent ssh-add lsof shasum jq; do command -v "$t" >/dev/null 2>&1 || blocked "missing tool: $t"; done
[ "$(uname -s)" = Darwin ] || blocked "the controller of this journey is macOS (the build host)"
scratch_parent=${HM_XH_SCRATCH:-/tmp}
[ -d "$scratch_parent" ] || blocked "HM_XH_SCRATCH is not a directory"
scratch_parent=$(cd "$scratch_parent" && pwd)
# The controller's K_mgmt agent socket is <home>/run/mgmt/<12 hex>/a.sock (and p.sock beside it),
# and macOS holds 103 bytes of a socket path. A longer one fails the bind, which the product
# reports as "the management key agent could not be started" after the bootstrap (the W5
# candidate run under the default $TMPDIR, w5q). Refused before anything is created.
socket_room "$scratch_parent" || blocked "HM_XH_SCRATCH is too long for the controller's sockets ($(socket_longest "$scratch_parent") bytes, the limit is $SOCKET_MAX): give a shorter one"

mkdir -p "$out" || exit 2
out=$(cd "$out" && pwd)
commands=$out/commands.txt
: >"$commands"
: >"$out/build.txt"
unset CARGO_TARGET_DIR

hex=$(m02_random_hex 4)
stage="hm-m06x-$hex"
own_remote_dir "$stage" || { echo "internal: bad staging name" >&2; exit 2; }
run="$scratch_parent/hm-m06x-$hex"
results=""
WORLDS=()
CONTROLLERS=()
CAS=()
remote_created=0
cleanup_ok=1
failed=0
ran=0
journey_failed=0
heimdall=""
driver_bin=""

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local w c pid
    trap - EXIT INT TERM
    for w in ${WORLDS[@]+"${WORLDS[@]}"}; do
        forward_close "$w" || cleanup_ok=0
    done
    for c in ${CONTROLLERS[@]+"${CONTROLLERS[@]}"}; do
        controller_stop "$c" || cleanup_ok=0
    done
    if [ -f "$run/fa/agent.pid" ]; then
        pid=$(cat "$run/fa/agent.pid")
        case "$pid" in '' | *[!0-9]*) ;; *) kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null ;; esac
    fi
    if [ "$remote_created" = 1 ]; then
        for w in ${WORLDS[@]+"${WORLDS[@]}"}; do
            [ "$(runner "$w" cleanup | fact removed)" = yes ] || cleanup_ok=0
        done
        # Only the directory this run created (exact name, never a glob), then checked absent.
        rssh "rm -rf -- \"\$HOME/$stage\" && test ! -e \"\$HOME/$stage\"" </dev/null
        rc=$?
        echo "exit $rc: ssh <runnerhost> rm -rf the run's staging directory, then check it is absent" >>"$commands"
        [ $rc = 0 ] || cleanup_ok=0
    fi
}

finish() {
    local code scans=1 planned_selected=0 j n hits leaks keychain kc
    cleanup
    # The login keychain, by service name only: no generic-password item may exist under any
    # service the product can create (the code's own list, plus this run's CA items).
    local services checked=0
    if services=$(keychain_services "$repo/crates/credential/src/lib.rs" ${CAS[@]+"${CAS[@]}"}); then
        keychain=absent
        while IFS= read -r kc; do
            [ -n "$kc" ] || continue
            checked=$((checked + 1))
            if security find-generic-password -s "$kc" >/dev/null 2>&1; then keychain="present:${kc%%/*}"; cleanup_ok=0; fi
        done <<<"$services"
    else
        keychain=not_checked_service_list_unreadable
        cleanup_ok=0
    fi
    echo "exit 0: security find-generic-password -s <each of $checked service names: crates/credential/src/lib.rs MACOS_KEYCHAIN_SERVICES, and the issuer prefix with each CA fingerprint of this run> (by service name only; attributes and secrets never printed): $keychain" >>"$commands"
    echo "login-keychain-heimdall-items=$keychain" >>"$run/host.txt"
    echo "login-keychain-service-names-checked=$checked" >>"$run/host.txt"
    echo "cleanup=$([ "$cleanup_ok" = 1 ] && echo clean || echo incomplete)" >>"$run/host.txt"
    for j in $only; do n=$(plan | awk -v c="$j" '$2 == c' | wc -l | tr -d ' '); planned_selected=$((planned_selected + n)); done
    plan | cut -d' ' -f1 >"$run/planned"
    # Redaction first, then the scans decide the exit code.
    local user rhome=${RUNNER_HOME:-} ruser=${RUNNER_USER:-}
    user=$(id -un)
    cp "$results" "$run/results.raw"
    m02_redact "$run/results.raw" "$run/results.tsv" --word "$host" "<runnerhost>" "$run" "<run>" "$HOME" "<home>" "$user" "<user>" "$rhome" "<runnerhome>" "$ruser" "<runneruser>"
    m02_redact "$run/host.txt" "$out/host.txt" --word "$host" "<runnerhost>" "$run" "<run>" "$HOME" "<home>" "$user" "<user>" "$rhome" "<runnerhome>" "$ruser" "<runneruser>"
    m02_redact "$commands" "$run/commands.red" --word "$host" "<runnerhost>" "$run" "<run>" "$HOME" "<home>" "$user" "<user>" "$rhome" "<runnerhome>" "$ruser" "<runneruser>"
    cp "$run/commands.red" "$commands"
    m02_redact "$out/build.txt" "$run/build.red" --word "$host" "<runnerhost>" "$run" "<run>" "$HOME" "<home>" "$user" "<user>"
    cp "$run/build.red" "$out/build.txt"
    py log --target "$TARGET" --results "$run/results.tsv" --planned "$run/planned" --exit 0 >"$out/tests.txt"
    hits=$(m02_canary_scan "$out")
    [ "$hits" = 0 ] || scans=0
    leaks=$(m02_leak_scan "$out" "$HOME" "$run" --word "$user" --word "$host" ${rhome:+"$rhome"} ${ruser:+--word "$ruser"}) || scans=0
    echo "leak-scan: $leaks artifact(s) with a home path, user or host name" >>"$out/canary-scan.txt"
    code=$(run_exit "$failed" "$ran" "$planned_selected" "$cleanup_ok" "$scans")
    py log --target "$TARGET" --results "$run/results.tsv" --planned "$run/planned" --exit "$code" >"$out/tests.txt"
    rm -rf -- "$run"
    [ ! -e "$run" ] || code=1
    echo "### $TARGET exit=$code ($((ran - failed)) of $planned_selected selected steps passed; cleanup $([ "$cleanup_ok" = 1 ] && echo clean || echo incomplete); canary $hits; leaks $leaks)"
    exit "$code"
}

# --- build ------------------------------------------------------------------------------------------

mkdir -m 700 "$run" || blocked "the run directory could not be created"
trap 'cleanup; rm -rf -- "$run"; exit 1' INT TERM
results=$run/results.raw0
: >"$results"
: >"$run/host.txt"
if [ "$prebuilt" = 4 ]; then
    heimdall=$HM_XH_HEIMDALL; driver_bin=$HM_XH_DRIVER; linux_heimdall=$HM_XH_LINUX_HEIMDALL; linux_driver=$HM_XH_LINUX_DRIVER
    echo "inputs: prebuilt (HM_XH_*)" >>"$out/build.txt"
else
    command -v zig >/dev/null 2>&1 || { rm -rf -- "$run"; blocked "missing tool: zig (the Linux cross-build)"; }
    m02_write_shims "$(m02_shim_dir "$repo")" || { rm -rf -- "$run"; blocked "the zig shims could not be written"; }
    mkdir "$run/b-host" "$run/b-linux"
    sel=(-p heimdall --test e2e_windows_controller_m06)
    (cd "$repo" && m02_cargo_build host "$run/b-host" "$run/b-host/build.log" build.json "${sel[@]}")
    rc=$?
    m02_record "$commands" "cargo test -p heimdall --test e2e_windows_controller_m06 --no-run --locked (the macOS debug heimdall and the fixture driver)" "$rc"
    [ $rc = 0 ] || { tail -n 20 "$run/b-host/build.log" >&2; cp "$run/b-host/build.log" "$out/build-failed.txt"; rm -rf -- "$run"; exit 1; }
    (cd "$repo" && m02_cargo_build x86_64-unknown-linux-gnu "$run/b-linux" "$run/b-linux/build.log" build.json "${sel[@]}")
    rc=$?
    m02_record "$commands" "cargo test --target x86_64-unknown-linux-gnu --profile native-test -p heimdall --test e2e_windows_controller_m06 --no-run --locked (zig cc, glibc 2.31 floor)" "$rc"
    [ $rc = 0 ] || { tail -n 20 "$run/b-linux/build.log" >&2; cp "$run/b-linux/build.log" "$out/build-failed.txt"; rm -rf -- "$run"; exit 1; }
    pick() { # DIR KIND -> the executable
        if [ "$2" = cli ]; then
            jq -r 'select(.reason == "compiler-artifact" and .profile.test == false and .executable != null and .target.name == "heimdall" and (.target.kind | index("bin"))) | .executable' "$1/build.json" | sort -u | head -1
        else
            jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null and .target.name == "e2e_windows_controller_m06") | .executable' "$1/build.json" | sort -u | head -1
        fi
    }
    heimdall=$(pick "$run/b-host" cli); driver_bin=$(pick "$run/b-host" driver)
    linux_heimdall=$(pick "$run/b-linux" cli); linux_driver=$(pick "$run/b-linux" driver)
    for f in "$heimdall" "$driver_bin" "$linux_heimdall" "$linux_driver"; do [ -n "$f" ] && [ -f "$f" ] || { rm -rf -- "$run"; echo "a built binary is missing" >&2; exit 1; }; done
    { echo "rustc: $(rustc --version)"; echo "zig: $(zig version)"; echo "commit: $(git -C "$repo" rev-parse HEAD) (worktree $(git -C "$repo" status --porcelain | wc -l | tr -d ' ') changed paths)"; } >>"$out/build.txt"
fi
heimdall_sha=$(shasum -a 256 "$heimdall" | cut -d' ' -f1)
linux_heimdall_sha=$(shasum -a 256 "$linux_heimdall" | cut -d' ' -f1)
linux_driver_sha=$(shasum -a 256 "$linux_driver" | cut -d' ' -f1)
{
    echo "heimdall (macOS controller, debug) sha256: $heimdall_sha"
    echo "e2e_windows_controller_m06 (macOS fixture driver) sha256: $(shasum -a 256 "$driver_bin" | cut -d' ' -f1)"
    echo "heimdall (x86_64-unknown-linux-gnu runner, native-test profile: debug assertions on) sha256: $linux_heimdall_sha"
    echo "e2e_windows_controller_m06 (x86_64-unknown-linux-gnu fixture driver) sha256: $linux_driver_sha"
} >>"$out/build.txt"
if [ "$build_only" = 1 ]; then
    rm -rf -- "$run"
    echo "### $TARGET build-only"
    exit 0
fi
# Keep the four binaries for the whole run, whatever a concurrent build does to target/.
mkdir -m 700 "$run/bin"
cp "$heimdall" "$run/bin/heimdall" && cp "$driver_bin" "$run/bin/driver" && cp "$linux_heimdall" "$run/bin/heimdall.linux" && cp "$linux_driver" "$run/bin/driver.linux" || { rm -rf -- "$run"; exit 1; }
heimdall=$run/bin/heimdall; driver_bin=$run/bin/driver

# --- the runner host --------------------------------------------------------------------------------

arch=$(rssh 'uname -m' </dev/null 2>/dev/null)
rc=$?
m02_record "$commands" "ssh <runnerhost> uname -m" "$rc"
if [ $rc != 0 ]; then rm -rf -- "$run"; echo "blocked: the runner host is unreachable"; exit 4; fi
[ "$arch" = x86_64 ] || { rm -rf -- "$run"; blocked "the runner host is $arch, the runner binary is x86_64"; }
avail=$(rssh 'df -Pk "$HOME" | awk "NR == 2 { print int(\$4 / 1048576) }"' </dev/null 2>/dev/null)
m02_record "$commands" "ssh <runnerhost> df (free space in the account's home, GiB: ${avail:-unknown})" "$?"
case "$avail" in '' | *[!0-9]*) rm -rf -- "$run"; blocked "the runner host's free space is unknown" ;; esac
[ "$avail" -ge 5 ] || { rm -rf -- "$run"; blocked "the runner host has ${avail} GiB free (the floor is 4 GiB plus this run)"; }
trap finish EXIT
trap 'exit 1' INT TERM
rssh "mkdir -m 700 -- \"\$HOME/$stage\"" </dev/null
rc=$?
m02_record "$commands" "ssh <runnerhost> mkdir the run's staging directory (plain mkdir: refused when it exists)" "$rc"
[ $rc = 0 ] || { echo "the staging directory could not be created" >&2; exit 1; }
remote_created=1
mkdir "$run/stage"
ln -s "$run/bin/heimdall.linux" "$run/stage/heimdall"
ln -s "$run/bin/driver.linux" "$run/stage/journey-driver"
cp "$here/crosshost-runner.sh" "$here/windows-controller-runner.sh" "$here/crosshost-tool.py" "$run/stage/"
(cd "$run/stage" && tar -chf - .) | rssh "tar -xf - -C \"\$HOME/$stage\" && chmod 700 \"\$HOME/$stage/heimdall\" \"\$HOME/$stage/journey-driver\""
rc=$?
m02_record "$commands" "tar | ssh <runnerhost> tar -x (the runner binary, the fixture driver, the runner scripts)" "$rc"
[ $rc = 0 ] || { echo "the copy failed" >&2; exit 1; }
RUNNER_HOME=$(rssh 'printf %s "$HOME"' </dev/null 2>/dev/null)
RUNNER_USER=$(rssh 'id -un' </dev/null 2>/dev/null)
# The staged binaries' paths, as the runner script's `prepare` wants them.
runner() {
    local world=$1 action=$2 out rc
    shift 2
    out=$(rssh "STAGE=\"\$HOME/$stage\"; bash \"\$STAGE/crosshost-runner.sh\" $action \"\$STAGE/hm-m06j-$world\" $(quote "$@" | sed 's/\\\$STAGE/$STAGE/g')" </dev/null 2>"$run/runner.err")
    rc=$?
    echo "exit $rc: ssh <runnerhost> crosshost-runner.sh $action <root:$world>" >>"$commands"
    [ $rc = 0 ] || keep_debug "$run/runner.err" "runner-$world-$action"
    printf '%s\n' "$out"
    return $rc
}
{
    echo "controller-host=$(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
    echo "controller-ssh=$(ssh -V 2>&1 | head -n 1)"
    echo "controller-k-mgmt-store=fixture-file (HEIMDALL_TEST_MGMT_STORE, per controller home, in the run directory)"
    echo "controller-k-iroh-store=fixture directory (HEIMDALL_TEST_IROH_KEY_STORE, per controller home, in the run directory)"
    echo "management-route=ssh -N -L 127.0.0.1:<port>:127.0.0.1:<port> over the owner's alias (ControlMaster=no, ControlPath=none), to an unprivileged fixture sshd on the runner host's loopback"
    echo "journeys=$only"
    echo "a24-lifetime-s=$lifetime"
    rssh "bash \"\$HOME/$stage/crosshost-runner.sh\" host-facts \"\$HOME/$stage/hm-m06j-facts\"" </dev/null 2>/dev/null | sed 's/^/runner-/'
    echo "runner-free-gib=$avail"
} >>"$run/host.txt"

# --- the journeys -----------------------------------------------------------------------------------

journey() { # CASE: its steps, in the plan's order, then its teardown
    local c=$1 test case name w
    journey_failed=0
    while read -r test case name; do
        [ "$case" = "$c" ] || continue
        step "$test" "$case" "$name" "s_$test"
    done <<EOF
$(plan)
EOF
    for w in ${WORLDS[@]+"${WORLDS[@]}"}; do
        case "$w" in "$c"*) world_down "$w" || cleanup_ok=0 ;; esac
    done
    # The journey's own controllers are stopped now (cleanup stops whatever is left).
    for w in ${CONTROLLERS[@]+"${CONTROLLERS[@]}"}; do
        case "$w" in "$c"*) controller_stop "$w" || cleanup_ok=0 ;; esac
    done
    local keep=()
    for w in ${WORLDS[@]+"${WORLDS[@]}"}; do case "$w" in "$c"*) ;; *) keep+=("$w") ;; esac; done
    WORLDS=(${keep[@]+"${keep[@]}"})
}
for j in a24 a07 t06 a25; do
    if selected "$j"; then journey "$j"; fi
done
exit 0
