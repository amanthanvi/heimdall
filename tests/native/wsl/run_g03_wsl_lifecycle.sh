#!/usr/bin/env bash
# G03 WSL lifecycle and multi-distribution probes (A13 Mode B).
#
# Run in a CONTROLLER WSL2 distribution against a separate, disposable TARGET
# distribution on the same Windows user account. The target is driven through
# documented `wsl.exe -d <target>` commands; helper files are staged in a
# Windows-side scratch directory that both distributions see under /mnt/c.
#
# Usage: run_g03_wsl_lifecycle.sh --target-distro NAME [options]
#   --out DIR                   output directory
#   --probes LIST               multi,restart,idle (default: all)
#   --allow-terminate-target    permit `wsl.exe --terminate <target>` (required for
#                               restart and idle; disrupts anything running there)
#   --idle-wait-seconds N       how long to watch for idle shutdown (default 120)
#
# Probes:
#   multi    G03-wsl-b-multi-distro-exposure: which placements of a Linux endpoint
#            in the target are reachable from the controller distribution and
#            from Windows (private path, abstract namespace, /mnt/wsl, loopback TCP),
#            and whether the controller can simply invoke the target via wsl.exe.
#   restart  G03-wsl-b-distro-restart: endpoint processes and socket files across
#            `wsl.exe --terminate`, stale detection and recovery.
#   idle     G03-wsl-b-idle-timeout: does a detached endpoint keep the target
#            running, or does WSL stop the instance when no session remains.
# The exposure probe's extra listeners are inert banner servers (exposure_listener.py);
# only the private-path proxy speaks the agent protocol, with a disposable key.

# shellcheck disable=SC2016,SC1003  # intentional single-quoted target scripts; Windows separators
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=g03_common.sh
. "$HERE/g03_common.sh"

OUT="" PROBES="all" TARGET="" ALLOW_TERMINATE=0 IDLE_WAIT=120
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --probes) PROBES="$2"; shift 2 ;;
    --target-distro) TARGET="$2"; shift 2 ;;
    --allow-terminate-target) ALLOW_TERMINATE=1; shift ;;
    --idle-wait-seconds) IDLE_WAIT="$2"; shift 2 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

g03_init "$OUT"
G03_PROVIDERS=("linux ssh (controller)=$("$LINUX_SSH" -V 2>&1 | head -1)")
want() { [ "$PROBES" = all ] && return 0; case ",$PROBES," in *",$1,"*) return 0 ;; esac; return 1; }

NOT_WSL="controller WSL2 distribution with interop on a native Windows 11 x86-64 host, plus a second disposable WSL2 target distribution (--target-distro) with python3 and OpenSSH client tools; this run was not inside WSL"
REQ_MULTI=(R-EN-03 R-SE-03 R-RT-03)
REQ_RESTART=(R-EN-03 R-RT-01 R-RT-04 R-RT-07)
REQ_IDLE=(R-EN-03 R-RT-01)

block_all() {
  want multi && g03_blocked wsl-b-multi-distro-exposure "$1" "${REQ_MULTI[@]}"
  want restart && g03_blocked wsl-b-distro-restart "$1" "${REQ_RESTART[@]}"
  want idle && g03_blocked wsl-b-idle-timeout "$1" "${REQ_IDLE[@]}"
  exit 0
}
g03_is_wsl && [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || block_all "$NOT_WSL"
[ -n "$TARGET" ] || block_all "a second disposable WSL2 distribution named with --target-distro"
[ "$TARGET" != "${WSL_DISTRO_NAME:-}" ] || { echo "target must differ from the controller distribution" >&2; exit 2; }
g03_win_init || block_all "powershell.exe reachable through WSL interop"

wslx() { (cd /mnt/c && WSL_UTF8=1 wsl.exe "$@") | tr -d '\000\r'; }
running() { wslx -l --running -q 2>/dev/null | grep -Fxq "$TARGET"; }
G03_PROVIDERS+=("wsl.exe=$(wslx --version 2>/dev/null | head -1)")

# Stage helpers where the target can read them.
SH="$G03_WIN_SCRATCH_U/h"
mkdir -p "$SH"
cp "$HERE"/agent_proto.py "$HERE"/agent_proxy.py "$HERE"/agent_client.py "$HERE"/exposure_listener.py "$SH/"
ID="$(g03_hex 3)"

# Target-side scripts (executed inside the target with `wsl.exe -d TARGET -- bash FILE`).
cat > "$SH/t_start.sh" <<'EOS'
#!/usr/bin/env bash
# args: SHARED_DIR ID MODE(multi|restart|idle)
set -u
S="$1"; ID="$2"; MODE="$3"
unset SSH_AUTH_SOCK
T="/tmp/hg03-$ID"; mkdir -p "$T/ep" "$T/k"; chmod 700 "$T" "$T/ep" "$T/k"
/usr/bin/ssh-keygen -q -t ed25519 -N '' -C hg03-target -f "$T/k/k1"
eval "$(/usr/bin/ssh-agent -a "$T/up.sock" -s)" >/dev/null
SSH_AUTH_SOCK="$T/up.sock" /usr/bin/ssh-add -q "$T/k/k1" 2>/dev/null
start() { setsid nohup "$@" >/dev/null 2>&1 < /dev/null & echo $!; }
PX=$(start python3 "$S/agent_proxy.py" --listen "$T/ep/agent.sock" --upstream-unix "$T/up.sock" --allow-pub "$T/k/k1.pub" --log "$T/proxy.log" --ready-file "$T/proxy.ready")
HOMEDIR="$HOME/.cache/hg03-$ID"; mkdir -p "$HOMEDIR"; chmod 700 "$HOMEDIR"
PX2=""
if [ "$MODE" = restart ]; then
  PX2=$(start python3 "$S/agent_proxy.py" --listen "$HOMEDIR/agent.sock" --upstream-unix "$T/up.sock" --allow-pub "$T/k/k1.pub" --log "$T/proxy2.log" --ready-file "$T/proxy2.ready")
fi
AB="" TCP="" MW=""
if [ "$MODE" = multi ]; then
  AB=$(start python3 "$S/exposure_listener.py" --abstract "hg03-$ID" --seconds 300 --ready-file "$T/ab.ready")
  TCP=$(start python3 "$S/exposure_listener.py" --tcp-port 0 --seconds 300 --ready-file "$T/tcp.ready")
  MW=$(start python3 "$S/exposure_listener.py" --unix "/mnt/wsl/hg03-$ID.sock" --seconds 300 --ready-file "$T/mw.ready")
fi
waitf() { i=0; while [ $i -lt 50 ] && [ ! -s "$1" ]; do sleep 0.1; i=$((i+1)); done; }
waitf "$T/proxy.ready"
if [ "$MODE" = multi ]; then waitf "$T/ab.ready"; waitf "$T/tcp.ready"; waitf "$T/mw.ready"; fi
st() { [ -n "$1" ] && sed -e 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'; }
TCPADDR=$( [ -s "$T/tcp.ready" ] && python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tcp"])' "$T/tcp.ready" )
python3 - "$S/state-$ID.json" <<EOF
import json, sys
json.dump({"tmp": "$T", "home_ep": "$HOMEDIR/agent.sock", "proxy_pid": "$PX", "proxy_start": "$(st "$PX")",
           "proxy2_pid": "$PX2", "proxy2_start": "$(st "$PX2")", "agent_pid": "$SSH_AGENT_PID", "agent_start": "$(st "$SSH_AGENT_PID")",
           "abstract_pid": "$AB", "abstract_start": "$(st "$AB")", "tcp_pid": "$TCP", "tcp_start": "$(st "$TCP")",
           "mnt_wsl_pid": "$MW", "mnt_wsl_start": "$(st "$MW")", "tcp": "$TCPADDR",
           "net_ns": "$(readlink /proc/self/ns/net)", "mnt_ns": "$(readlink /proc/self/ns/mnt)",
           "user": "$(id -un)",
           "listeners_ready": {"abstract": $( [ -s "$T/ab.ready" ] && echo True || echo False ), "tcp": $( [ -s "$T/tcp.ready" ] && echo True || echo False ),
                               "mnt_wsl": $( [ -s "$T/mw.ready" ] && echo True || echo False )}}, open(sys.argv[1], "w"))
EOF
EOS
cat > "$SH/t_stop.sh" <<'EOS'
#!/usr/bin/env bash
# args: STATE_JSON ; stops only recorded pids whose recorded start time is non-empty
# and still matches (a pid without a recorded start time is never signalled; the
# inert listeners also exit by themselves after --seconds 300).
set -u
eval "$(python3 - "$1" <<'EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
safe = lambda v: str(v) if re.fullmatch(r"[0-9]*", str(v)) else ""
for k in ("proxy", "proxy2", "agent", "abstract", "tcp", "mnt_wsl"):
    print("%s_PID=%s %s_ST=%s" % (k.upper(), safe(d.get(k + "_pid", "")), k.upper(), safe(d.get(k + "_start", ""))))
print("TMPD=%s" % d["tmp"])
print("HOMEEP=%s" % d.get("home_ep", ""))
EOF
)"
st() { sed -e 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'; }
stop() { [ -n "$1" ] && [ -n "$2" ] || return 0; if [ "$(st "$1")" = "$2" ]; then kill "$1" 2>/dev/null; fi; }
stop "$PROXY_PID" "$PROXY_ST"; stop "$PROXY2_PID" "$PROXY2_ST"; stop "$AGENT_PID" "$AGENT_ST"
stop "$ABSTRACT_PID" "$ABSTRACT_ST"; stop "$TCP_PID" "$TCP_ST"; stop "$MNT_WSL_PID" "$MNT_WSL_ST"
sleep 1; case "$TMPD" in /tmp/hg03-*) rm -rf "$TMPD" ;; esac
case "$HOMEEP" in "$HOME"/.cache/hg03-*/agent.sock) rm -rf "$(dirname "$HOMEEP")" ;; esac
EOS
cat > "$SH/t_inspect.sh" <<'EOS'
#!/usr/bin/env bash
# args: PID START_TOKEN TMP_SOCKET HOME_SOCKET
s=$(sed -e 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}')
if [ -n "$s" ] && [ "$s" = "$2" ]; then echo proxy_alive=yes; else echo proxy_alive=no; fi
if [ -S "$3" ]; then echo tmp_socket=present; else echo tmp_socket=absent; fi
if [ -S "$4" ]; then echo home_socket=present; else echo home_socket=absent; fi
EOS
cat > "$SH/t_keep.sh" <<'EOS'
#!/usr/bin/env bash
# args: PIDFILE SECONDS ; records "pid start_token", then becomes `sleep` (exec keeps
# the pid and the start time), so t_keepstop.sh can stop exactly this process.
s=$(sed -e 's/^.*) //' "/proc/$$/stat" 2>/dev/null | awk '{print $20}')
printf '%s %s\n' "$$" "$s" > "$1"
exec sleep "$2"
EOS
cat > "$SH/t_keepstop.sh" <<'EOS'
#!/usr/bin/env bash
# args: PIDFILE ; stops the keepalive sleep only if its pid, start token and comm match.
[ -f "$1" ] || { echo keepalive=no-pidfile; exit 0; }
read -r p want < "$1"
case "$p" in ''|*[!0-9]*) echo keepalive=bad-pidfile; exit 0 ;; esac
cur=$(sed -e 's/^.*) //' "/proc/$p/stat" 2>/dev/null | awk '{print $20}')
[ -n "$cur" ] || { echo keepalive=already-exited; exit 0; }
if [ -z "$want" ] || [ "$cur" != "$want" ] || [ "$(cat "/proc/$p/comm" 2>/dev/null)" != sleep ]; then
  echo keepalive=identity-mismatch-not-stopped; exit 0
fi
kill -TERM "$p" 2>/dev/null && echo keepalive=stopped
EOS
chmod +x "$SH/t_start.sh" "$SH/t_stop.sh" "$SH/t_inspect.sh" "$SH/t_keep.sh" "$SH/t_keepstop.sh"
TS="$SH"   # the same /mnt/c path inside the target (default automount root assumed)

tstart() { wslx -d "$TARGET" -- bash "$TS/t_start.sh" "$TS" "$ID" "$1" >/dev/null 2>&1; }
tstop() { wslx -d "$TARGET" -- bash "$TS/t_stop.sh" "$TS/state-$ID.json" >/dev/null 2>&1; }
tget() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$SH/state-$ID.json" "$1"; }
tclient() { wslx -d "$TARGET" -- python3 "$TS/agent_client.py" "$@"; }

KEEP_PID="" KEEP_PIDFILE=""
# Keepalive session in the target (review D6): `exec` makes $! the wsl.exe interop
# process itself rather than a wrapping subshell, and the target-side `sleep` records
# its pid and start token so stop_keepalive can end it inside the target even if
# stopping the Windows-side wsl.exe does not end the session [U].
keepalive() {
  KEEP_PIDFILE="$TS/keepalive-$ID.pid"
  (cd /mnt/c && exec wsl.exe -d "$TARGET" -- bash "$TS/t_keep.sh" "$KEEP_PIDFILE" 900 >/dev/null 2>&1) & KEEP_PID=$!
  g03_own "$KEEP_PID" keepalive; sleep 2
}
stop_keepalive() {  # prints "target=<t_keepstop result> controller=<g03_stop_pid result>"
  local t="keepalive=not-started" w="not-started"
  if [ -n "$KEEP_PIDFILE" ]; then t="$(wslx -d "$TARGET" -- bash "$TS/t_keepstop.sh" "$KEEP_PIDFILE" 2>/dev/null | head -1)"; fi
  if [ -n "$KEEP_PID" ]; then w="$(g03_stop_pid "$KEEP_PID" 2>/dev/null)"; fi
  KEEP_PIDFILE="" KEEP_PID=""
  echo "target=${t:-unknown} controller=${w:-unknown}"
}
trap 'stop_keepalive >/dev/null 2>&1; g03_cleanup' EXIT

# ------------------------------------------------------------------ multi
probe_multi() {
  local c=wsl-b-multi-distro-exposure
  keepalive
  tstart multi
  [ -s "$SH/state-$ID.json" ] || { g03_obs $c error --str "target start script produced no state"; g03_crit $c target_started null; g03_finish $c "${REQ_MULTI[@]}"; return; }
  printf '%s\n' "$SH/state-$ID.json" >> "$(g03_case_file $c evidence)"
  g03_net_mode_obs $c
  local tnm
  tnm="$(wslx -d "$TARGET" -- sh -c 'command -v wslinfo >/dev/null 2>&1 && wslinfo --networking-mode 2>/dev/null | head -1 || echo unavailable' | tr -d ' \t')"
  [ "$tnm" = unavailable ] || tnm="$(g03_net_mode_word "$tnm")"
  g03_obs $c target_networking_mode_wslinfo --str "$tnm"
  local ep tcp
  ep="$(tget tmp)/ep/agent.sock"; tcp="$(tget tcp)"
  g03_run $c target-self-list -- tclient --socket "$ep" list
  g03_crit $c target_endpoint_serves_inside_target "$(grep -q '"reply_type": 12' "$G03_LAST_OUT" && echo true || echo false)"
  g03_crit $c private_path_not_visible_from_controller "$([ ! -e "$ep" ] && echo true || echo false)"
  g03_obs $c same_network_namespace --json "$([ "$(readlink /proc/self/ns/net)" = "$(tget net_ns)" ] && echo true || echo false)"
  g03_obs $c same_mount_namespace --json "$([ "$(readlink /proc/self/ns/mnt)" = "$(tget mnt_ns)" ] && echo true || echo false)"
  g03_run $c controller-abstract -- "$PY" "$HERE/agent_client.py" --abstract "hg03-$ID" banner
  g03_obs $c abstract_namespace_reachable_from_controller --json "$(grep -q 'heimdall-g03-banner' "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c controller-mnt-wsl -- "$PY" "$HERE/agent_client.py" --socket "/mnt/wsl/hg03-$ID.sock" banner
  g03_obs $c mnt_wsl_socket_reachable_from_controller --json "$(grep -q 'heimdall-g03-banner' "$G03_LAST_OUT" && echo true || echo false)"
  if [ -n "$tcp" ]; then
    g03_run $c controller-loopback-tcp -- "$PY" "$HERE/agent_client.py" --tcp "$tcp" banner
    g03_obs $c loopback_tcp_reachable_from_controller --json "$(grep -q 'heimdall-g03-banner' "$G03_LAST_OUT" && echo true || echo false)"
    local port="${tcp##*:}"
    local ps="try { \$c = New-Object Net.Sockets.TcpClient; \$c.Connect('127.0.0.1', $port); \$b = New-Object byte[] 32; \$n = \$c.GetStream().Read(\$b, 0, 32); [Text.Encoding]::ASCII.GetString(\$b, 0, \$n) } catch { 'unreachable' }"
    g03_run $c windows-loopback-tcp -- g03_win powershell.exe -NoProfile -NonInteractive -Command "$ps"
    g03_obs $c loopback_tcp_reachable_from_windows --json "$(grep -q 'heimdall-g03-banner' "$G03_LAST_OUT" && echo true || echo false)"
  fi
  g03_run $c controller-invokes-target-via-wsl-exe -- wslx -d "$TARGET" -u "$(tget user)" -- python3 "$TS/agent_client.py" --socket "$ep" list
  g03_obs $c controller_can_use_target_endpoint_via_wsl_exe --json "$(grep -q '"reply_type": 12' "$G03_LAST_OUT" && echo true || echo false)"
  local unc
  unc="\\\\wsl.localhost\\${TARGET}$(tget tmp | tr '/' '\\')\\ep\\agent.sock"
  g03_run $c windows-unc-visibility -- g03_win powershell.exe -NoProfile -NonInteractive -Command "Test-Path -LiteralPath '$unc'"
  g03_obs $c endpoint_file_visible_to_windows_via_unc --str "$(tr -d '\r\n' < "$G03_LAST_OUT")"
  g03_obs $c target_listeners_ready --json "$("$PY" -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["listeners_ready"]))' "$SH/state-$ID.json")"
  g03_crit $c exposure_matrix_measured true
  tstop
  g03_obs $c keepalive_stop --str "$(stop_keepalive)"
  g03_limit $c "Microsoft's WSL security model states a distribution is not a security boundary from the Windows user or from other distributions of the same user; this probe measures default reachability, not isolation."
  g03_limit $c "Assumes the default /mnt automount root in both distributions."
  g03_limit $c "The loopback rows depend on the WSL networking mode (NAT relays bound ports to Windows via wslrelay; mirrored forwards bind() to Windows; Consomme tracks bound guest ports; wsl-config.md, localhost.md [G03-S15, G03-S16]); interpret loopback_tcp_reachable_from_windows only together with the recorded mode."
  g03_finish $c "${REQ_MULTI[@]}"
}

# ------------------------------------------------------------------ restart
probe_restart() {
  local c=wsl-b-distro-restart i
  [ "$ALLOW_TERMINATE" = 1 ] || { g03_blocked $c "explicit permission to terminate the disposable target distribution (--allow-terminate-target)" "${REQ_RESTART[@]}"; return; }
  keepalive
  tstart restart
  [ -s "$SH/state-$ID.json" ] || { g03_obs $c error --str "target start script produced no state"; g03_crit $c target_started null; g03_finish $c "${REQ_RESTART[@]}"; return; }
  local ep home_ep ppid pst
  ep="$(tget tmp)/ep/agent.sock"; home_ep="$(tget home_ep)"; ppid="$(tget proxy_pid)"; pst="$(tget proxy_start)"
  g03_run $c before-restart-list -- tclient --socket "$ep" list
  g03_crit $c serves_before_restart "$(grep -q '"reply_type": 12' "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c terminate -- wslx --terminate "$TARGET"
  i=0; while [ $i -lt 30 ] && running; do sleep 1; i=$((i + 1)); done
  g03_obs $c seconds_until_not_running --json "$i"
  # After --terminate the target-side sleep is gone; stop_keepalive runs after the
  # restart-and-inspect step below, where a reused pid is rejected by its start token.
  g03_run $c restart-and-inspect -- wslx -d "$TARGET" -- bash "$TS/t_inspect.sh" "$ppid" "$pst" "$ep" "$home_ep"
  g03_obs $c after_restart --file "$G03_LAST_OUT"
  g03_crit $c endpoint_processes_gone_after_terminate "$(grep -q 'proxy_alive=no' "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c client-after-restart -- tclient --socket "$home_ep" list
  g03_obs $c client_against_persistent_path_after_restart --file "$G03_LAST_OUT"
  g03_crit $c stale_endpoint_fails_cleanly "$(grep -q '"connected": false' "$G03_LAST_OUT" && echo true || echo false)"
  g03_obs $c keepalive_stop --str "$(stop_keepalive)"
  g03_limit $c "Recovery of the stale persistent-path endpoint is exercised by wsl-b-stale-socket (agent_proxy --replace-stale) in run_g03_wsl_probes.sh; this probe records what survives a distribution restart."
  tstop
  g03_finish $c "${REQ_RESTART[@]}"
}

# ------------------------------------------------------------------ idle
probe_idle() {
  local c=wsl-b-idle-timeout i=0 stopped_at="" tl
  tl="$G03_OUT/artifacts/$(g03_cid wsl-b-idle-timeout)/timeline.txt"
  [ "$ALLOW_TERMINATE" = 1 ] || { g03_blocked $c "explicit permission to terminate the disposable target distribution (--allow-terminate-target) so the idle baseline starts with no sessions" "${REQ_IDLE[@]}"; return; }
  mkdir -p "$(dirname "$tl")"
  wslx --terminate "$TARGET" >/dev/null 2>&1; sleep 3
  ID="$(g03_hex 3)"
  tstart idle
  while [ $i -lt "$IDLE_WAIT" ]; do
    if running; then echo "t+${i}s running" >> "$tl"; else echo "t+${i}s stopped" >> "$tl"; stopped_at="$i"; break; fi
    sleep 5; i=$((i + 5))
  done
  printf '%s\n' "$tl" >> "$(g03_case_file $c evidence)"
  g03_obs $c stopped_after_seconds --json "${stopped_at:-null}"
  g03_obs $c watched_seconds --json "$IDLE_WAIT"
  g03_obs $c documented_default_instanceIdleTimeout_ms --json 15000
  g03_crit $c timeline_recorded true
  if [ -z "$stopped_at" ]; then tstop; fi
  g03_limit $c "Observation only: whether a detached background endpoint keeps a WSL instance alive decides whether a Mode B helper needs a keepalive or a supervisor outside the distribution."
  g03_finish $c "${REQ_IDLE[@]}"
}

want multi && probe_multi
want restart && probe_restart
want idle && probe_idle
g03_redact_out
g03_canary_scan || exit 9
g03_log "records: $G03_OUT/records"
