# shellcheck shell=bash
# shellcheck disable=SC2034  # globals are consumed by the scripts that source this file
# Shared helpers for the G03 WSL harness. Source this file; do not execute it.
# Harness code, not product code. Portable to bash 3.2 (macOS self-test) and
# bash 5 (WSL distributions). Safety model: README.md.
#
# Invariants:
#   * SSH_AUTH_SOCK is unset at init; every agent use names a fixture socket or
#     a Windows fixture pipe explicitly (IdentityAgent / scoped env).
#   * Linux ssh runs with HOME pointing into scratch, -F <fixture config>,
#     IdentityFile=none and fixture known_hosts, so ~/.ssh is never read.
#   * Only processes started by this harness are stopped, by exact PID plus
#     recorded start time; a PID whose start time was not recorded is never
#     signalled (reported as identity-unverified).
#   * Windows ssh.exe launched from WSL always gets an explicit Windows-side
#     SSH_AUTH_SOCK (the manifest decoy pipe, else a non-existent sentinel pipe)
#     through WSLENV, so it never inherits the system default pipe; callers
#     check the propagation with g03_wslenv_check (cmd.exe) before ssh.exe runs.
#   * PYTHONDONTWRITEBYTECODE=1 (no __pycache__ in the repository).

G03_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
G03_REPO="$(cd "$G03_HERE/../../.." && pwd)"
PY="${PYTHON:-python3}"
LINUX_SSH=/usr/bin/ssh
LINUX_SSH_ADD=/usr/bin/ssh-add
LINUX_SSH_AGENT=/usr/bin/ssh-agent
LINUX_SSH_KEYGEN=/usr/bin/ssh-keygen
G03_OWNED=""          # newline-separated "pid starttime label"
G03_CASE_PREFIX="G03-"
# Canary prefix assembled at run time so repository-wide canary scans do not
# flag this source file itself.
G03_CANARY_PREFIX="HEIMDALL_""CANARY_"

g03_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
g03_epoch() { date +%s; }
g03_hex() { od -An -tx1 -N"${1:-3}" /dev/urandom | tr -d ' \n'; }
g03_log() { printf '[g03 %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

g03_is_wsl() {
  [ -n "${WSL_DISTRO_NAME:-}" ] && return 0
  grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null
}

g03_sha256() { "$PY" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

g03_stat() {  # prints: <octal mode> <uid> <socket|dir|file|other>
  "$PY" - "$1" <<'EOF'
import os, stat, sys
try:
    s = os.lstat(sys.argv[1])
except FileNotFoundError:
    print("missing - -"); sys.exit(0)
kind = "socket" if stat.S_ISSOCK(s.st_mode) else "dir" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other"
print("%o %d %s %d" % (stat.S_IMODE(s.st_mode), s.st_uid, kind, s.st_ino))
EOF
}

g03_proc_start() {  # start-time token for a pid ("" if gone)
  local pid="$1"
  if [ -r "/proc/$pid/stat" ]; then
    sed -e 's/^.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{print $20}'
  else
    ps -o lstart= -p "$pid" 2>/dev/null | tr -s ' ' '_'
  fi
}

g03_own() {  # g03_own PID LABEL
  local st
  st="$(g03_proc_start "$1")"
  G03_OWNED="${G03_OWNED}$1 ${st:-unknown} $2
"
}

g03_verify_owned() {  # g03_verify_owned PID -> prints ok|not-owned|already-exited|identity-unverified-not-stopped|identity-mismatch-not-stopped
  local pid="$1" want line cur
  line="$(printf '%s' "$G03_OWNED" | awk -v p="$pid" '$1==p {print; exit}')"
  if [ -z "$line" ]; then echo "not-owned"; return 1; fi
  want="$(printf '%s' "$line" | awk '{print $2}')"
  cur="$(g03_proc_start "$pid")"
  if [ -z "$cur" ]; then echo "already-exited"; return 1; fi
  if [ "$want" = "unknown" ]; then echo "identity-unverified-not-stopped"; return 1; fi
  if [ "$cur" != "$want" ]; then echo "identity-mismatch-not-stopped"; return 1; fi
  echo ok
}

g03_signal_pid() {  # g03_signal_pid PID SIGNAL: send SIGNAL only to a verified owned pid; prints result
  local v
  v="$(g03_verify_owned "$1")"
  if [ "$v" != ok ]; then echo "$v"; return 1; fi
  kill "-$2" "$1" 2>/dev/null && echo "signalled-$2"
}

g03_stop_pid() {  # stop an owned pid after re-verifying identity; prints result
  local pid="$1" v
  v="$(g03_verify_owned "$pid")"
  case "$v" in
    ok) ;;
    already-exited) echo "$v"; return 0 ;;
    *) echo "$v"; return 1 ;;
  esac
  kill -TERM "$pid" 2>/dev/null
  local i=0
  while [ $i -lt 30 ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
  if kill -0 "$pid" 2>/dev/null; then
    # Re-verify before escalating: the pid could have exited and been reused meanwhile.
    if [ "$(g03_verify_owned "$pid")" = ok ]; then kill -KILL "$pid" 2>/dev/null; echo "killed"; else echo "exited-during-stop"; fi
  else echo "stopped"; fi
  return 0
}

g03_cleanup() {
  local pid
  for pid in $(printf '%s' "$G03_OWNED" | awk '{print $1}'); do
    g03_stop_pid "$pid" >/dev/null 2>&1 || true
  done
  if [ -n "${G03_SCRATCH:-}" ] && [ -d "$G03_SCRATCH" ]; then
    rm -rf "$G03_SCRATCH"
  fi
  if [ -n "${G03_WIN_SCRATCH_U:-}" ] && [ -d "$G03_WIN_SCRATCH_U" ]; then
    rm -rf "$G03_WIN_SCRATCH_U"
  fi
}

g03_init() {  # g03_init [OUT_DIR]
  unset SSH_AUTH_SOCK SSH_AGENT_PID GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT
  # Harness Python modules must not leave __pycache__ in the repository.
  export PYTHONDONTWRITEBYTECODE=1
  G03_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(g03_hex 3)"
  G03_OUT="${1:-$G03_REPO/tests/evidence/artifacts/g03/runs/$G03_RUN_ID}"
  mkdir -p "$G03_OUT/records" "$G03_OUT/artifacts" "$G03_OUT/obs"
  G03_SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/hg03-XXXXXX")"
  chmod 700 "$G03_SCRATCH"
  G03_SPACED="$G03_SCRATCH/probe dir üø"
  G03_HOME="$G03_SCRATCH/home"
  mkdir -p "$G03_SPACED" "$G03_HOME" "$G03_SCRATCH/keys"
  chmod 700 "$G03_HOME" "$G03_SCRATCH/keys"
  : > "$G03_HOME/empty.gitconfig"
  G03_STARTED_AT="$(g03_now)"
  G03_BUILD_COMMIT="$(git -C "$G03_REPO" rev-parse HEAD 2>/dev/null || true)"
  G03_CANARY="${G03_CANARY_PREFIX}G03_$(g03_hex 12)"
  export HEIMDALL_G03_CANARY_ENV="$G03_CANARY"
  trap g03_cleanup EXIT
  g03_write_env
}

g03_write_env() {
  local envf="$G03_OUT/obs/_env.json"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" run_id --str "$G03_RUN_ID"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" kernel --str "$(uname -sr)"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" arch --str "$(uname -m)"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    "$PY" "$G03_HERE/evidence.py" obs-set "$envf" distro --str "$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
  fi
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" wsl_distro_name --str "${WSL_DISTRO_NAME:-<not WSL>}"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" is_wsl --json "$(g03_is_wsl && echo true || echo false)"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" wsl_interop_binfmt_present --json "$([ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && echo true || echo false)"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" linux_ssh --str "$("$LINUX_SSH" -V 2>&1 | head -1)"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" python --str "$("$PY" --version 2>&1)"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" bash --str "$BASH_VERSION"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" xdg_runtime_dir_present --json "$([ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR:-/nonexistent}" ] && echo true || echo false)"
  "$PY" "$G03_HERE/evidence.py" obs-set "$envf" systemd_pid1 --json "$([ "$(ps -o comm= -p 1 2>/dev/null)" = systemd ] && echo true || echo false)"
  local f h
  for f in agent_proxy.py agent_client.py agent_proto.py evidence.py exposure_listener.py argv_fidelity.py g03_common.sh run_g03_wsl_probes.sh run_g03_wsl_lifecycle.sh; do
    [ -f "$G03_HERE/$f" ] || continue
    h="$(g03_sha256 "$G03_HERE/$f")"
    "$PY" "$G03_HERE/evidence.py" obs-set "$envf" "harness_sha256_$f" --str "$h"
  done
}

# ---------------------------------------------------------------- case state
g03_case_file() { printf '%s/obs/%s.%s' "$G03_OUT" "$1" "$2"; }
g03_cid() { printf '%s%s' "$G03_CASE_PREFIX" "$1"; }

g03_obs() {  # g03_obs CASE KEY --json V | --str V | --file P
  local c="$1" k="$2"; shift 2
  "$PY" "$G03_HERE/evidence.py" obs-set "$(g03_case_file "$c" obs.json)" "$k" "$@"
}
g03_obs_get() {  # g03_obs_get CASE dotted.key -> value or empty
  "$PY" -c 'import json,sys
try:
    v = json.load(open(sys.argv[1]))
    for k in sys.argv[2].split("."):
        v = v[k]
    print(v)
except Exception:
    pass' "$(g03_case_file "$1" obs.json)" "$2"
}
g03_crit() {  # g03_crit CASE KEY true|false|null
  "$PY" "$G03_HERE/evidence.py" obs-set "$(g03_case_file "$1" crit.json)" "$2" --json "$3"
}
g03_bool() { if "$@"; then echo true; else echo false; fi; }
g03_glob() {  # g03_glob STRING PATTERN -> true|false (shell glob match; avoids case-in-$() parsing bugs of bash 3.2)
  # shellcheck disable=SC2254
  case "$1" in $2) echo true ;; *) echo false ;; esac
}
g03_limit() { printf '%s\n' "$2" >> "$(g03_case_file "$1" limits)"; }

g03_run() {  # g03_run CASE LABEL -- cmd args...   (stdout/stderr to artifacts; sets G03_RC)
  local c="$1" label="$2"; shift 3
  local dir
  dir="$G03_OUT/artifacts/$(g03_cid "$c")"
  mkdir -p "$dir"
  local safe
  safe="$(printf '%s' "$label" | tr -c 'A-Za-z0-9_.-' '_')"
  "$@" > "$dir/$safe.stdout" 2> "$dir/$safe.stderr"
  G03_RC=$?
  printf '%s\n' "$dir/$safe.stdout" "$dir/$safe.stderr" >> "$(g03_case_file "$c" evidence)"
  printf '%s (exit %s)\n' "$*" "$G03_RC" >> "$(g03_case_file "$c" commands)"
  G03_LAST_OUT="$dir/$safe.stdout"
  G03_LAST_ERR="$dir/$safe.stderr"
  return 0
}

g03_finish() {  # g03_finish CASE REQ [REQ...]   (criteria decide status)
  local c="$1"; shift
  local args=() r line
  # Harness self-test records name no product requirement (tests/evidence/README.md).
  if [ "$G03_CASE_PREFIX" = "G03-" ]; then for r in "$@"; do args+=(--req "$r"); done; fi
  if [ -f "$(g03_case_file "$c" evidence)" ]; then
    while IFS= read -r line; do args+=(--evidence "$line"); done < "$(g03_case_file "$c" evidence)"
  fi
  if [ -f "$(g03_case_file "$c" commands)" ]; then
    while IFS= read -r line; do args+=(--command "$line"); done < "$(g03_case_file "$c" commands)"
  fi
  if [ -f "$(g03_case_file "$c" limits)" ]; then
    while IFS= read -r line; do args+=(--limitation "$line"); done < "$(g03_case_file "$c" limits)"
  fi
  for line in "${G03_PROVIDERS[@]:-}"; do [ -n "$line" ] && args+=(--provider "$line"); done
  if [ "$G03_CASE_PREFIX" != "G03-" ]; then
    args+=(--limitation "Harness self-test outside WSL: NOT G03 evidence and names no product requirement. Exercises the probe proxy/client mechanics on this host only; WSL distribution, interop, Windows and multi-distribution behavior are not exercised.")
  fi
  [ -f "$(g03_case_file "$c" obs.json)" ] || echo '{}' > "$(g03_case_file "$c" obs.json)"
  [ -f "$(g03_case_file "$c" crit.json)" ] || echo '{}' > "$(g03_case_file "$c" crit.json)"
  "$PY" "$G03_HERE/evidence.py" record --out "$G03_OUT/records/g03-${G03_CASE_PREFIX#G03-}${c}.json" \
    --case-id "$(g03_cid "$c")" --obs "$(g03_case_file "$c" obs.json)" --criteria "$(g03_case_file "$c" crit.json)" \
    --env "$G03_OUT/obs/_env.json" --build-commit "$G03_BUILD_COMMIT" --started-at "$G03_STARTED_AT" \
    --repo-root "$G03_REPO" "${args[@]}"
}

g03_blocked() {  # g03_blocked CASE "blocked_on" REQ [REQ...]
  local c="$1" on="$2"; shift 2
  local args=() r line
  if [ "$G03_CASE_PREFIX" = "G03-" ]; then for r in "$@"; do args+=(--req "$r"); done; fi
  if [ -f "$(g03_case_file "$c" limits)" ]; then
    while IFS= read -r line; do args+=(--limitation "$line"); done < "$(g03_case_file "$c" limits)"
  fi
  "$PY" "$G03_HERE/evidence.py" record --out "$G03_OUT/records/g03-${G03_CASE_PREFIX#G03-}${c}.json" \
    --case-id "$(g03_cid "$c")" --status blocked --blocked-on "$on" --env "$G03_OUT/obs/_env.json" \
    --build-commit "$G03_BUILD_COMMIT" --started-at "$G03_STARTED_AT" --repo-root "$G03_REPO" "${args[@]}"
}

g03_redact_out() {  # redact identifying names in everything written under the run directory
  "$PY" "$G03_HERE/evidence.py" redact-tree "$G03_OUT" >/dev/null
}

g03_canary_scan() {  # exit status 0 when clean
  if grep -rl "$G03_CANARY_PREFIX" "$G03_OUT" >/dev/null 2>&1; then
    g03_log "CANARY LEAK: $(grep -rl "$G03_CANARY_PREFIX" "$G03_OUT" | tr '\n' ' ')"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------- Mode B fixtures
g03_b_keys() {  # creates k1,k2 (disposable ed25519) once
  [ -f "$G03_SCRATCH/keys/k1" ] && return 0
  "$LINUX_SSH_KEYGEN" -q -t ed25519 -N '' -C heimdall-g03-k1 -f "$G03_SCRATCH/keys/k1"
  "$LINUX_SSH_KEYGEN" -q -t ed25519 -N '' -C heimdall-g03-k2 -f "$G03_SCRATCH/keys/k2"
  G03_K1_FP="$("$LINUX_SSH_KEYGEN" -lf "$G03_SCRATCH/keys/k1.pub" | awk '{print $2}')"
  G03_K2_FP="$("$LINUX_SSH_KEYGEN" -lf "$G03_SCRATCH/keys/k2.pub" | awk '{print $2}')"
}

g03_b_upstream() {  # starts a fixture ssh-agent holding k1,k2; sets G03_UP_SOCK
  [ -n "${G03_UP_SOCK:-}" ] && [ -S "$G03_UP_SOCK" ] && return 0
  g03_b_keys
  mkdir -p "$G03_SCRATCH/up" && chmod 700 "$G03_SCRATCH/up"
  G03_UP_SOCK="$G03_SCRATCH/up/agent.sock"
  local out pid
  out="$("$LINUX_SSH_AGENT" -a "$G03_UP_SOCK" -s)"
  pid="$(printf '%s' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p')"
  [ -n "$pid" ] && g03_own "$pid" fixture-ssh-agent
  G03_UP_PID="$pid"
  SSH_AUTH_SOCK="$G03_UP_SOCK" "$LINUX_SSH_ADD" -q "$G03_SCRATCH/keys/k1" "$G03_SCRATCH/keys/k2" 2>/dev/null
}

g03_b_epdir() {  # private endpoint directory (prefers XDG_RUNTIME_DIR)
  local base="${XDG_RUNTIME_DIR:-}"
  if [ -z "$base" ] || [ ! -d "$base" ] || [ ${#base} -gt 60 ]; then base="$G03_SCRATCH"; fi
  local d
  d="$base/hg03-$(g03_hex 3)"
  mkdir -p "$d" && chmod 700 "$d"
  printf '%s' "$d"
}

g03_proxy_start() {  # g03_proxy_start NAME SOCKPATH [agent_proxy args...]; sets G03_PX_PID/G03_PX_LOG/G03_PX_RC
  local name="$1" sock="$2"; shift 2
  local log="$G03_SCRATCH/proxy-$name.log" ready="$G03_SCRATCH/proxy-$name.ready"
  rm -f "$ready"
  "$PY" "$G03_HERE/agent_proxy.py" --listen "$sock" --log "$log" --ready-file "$ready" \
    --generation-file "$G03_SCRATCH/proxy-$name.gen" "$@" &
  G03_PX_PID=$!
  g03_own "$G03_PX_PID" "proxy-$name"
  G03_PX_LOG="$log"
  local i=0
  while [ $i -lt 50 ] && [ ! -s "$ready" ] && kill -0 "$G03_PX_PID" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
  if [ -s "$ready" ]; then G03_PX_RC=running; return 0; fi
  wait "$G03_PX_PID" 2>/dev/null
  G03_PX_RC=$?
  return 1
}

g03_log_count() {  # g03_log_count LOGFILE KEY=VALUE [KEY=VALUE...]  -> count of matching JSONL lines
  "$PY" - "$@" <<'EOF'
import json, sys
path, conds = sys.argv[1], [c.split("=", 1) for c in sys.argv[2:]]
n = 0
try:
    for line in open(path, encoding="utf-8"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if all(str(d.get(k)) == v or (v.endswith("*") and str(d.get(k, "")).startswith(v[:-1])) for k, v in conds):
            n += 1
except FileNotFoundError:
    pass
print(n)
EOF
}

# ---------------------------------------------------------------- Windows side (Mode A / relay)
g03_win() {  # run a Windows tool from a Windows working directory (avoids UNC cwd warnings)
  (cd /mnt/c 2>/dev/null || cd /; "$@")
}

g03_win_init() {  # requires interop; sets G03_WIN_SCRATCH_U/_W and plain dir for base options
  local t
  t="$(g03_win powershell.exe -NoProfile -NonInteractive -Command '[IO.Path]::GetTempPath()' 2>/dev/null | tr -d '\r')"
  [ -n "$t" ] || return 1
  G03_WIN_TEMP_U="$(wslpath -u "$t")"
  G03_WIN_SCRATCH_U="$G03_WIN_TEMP_U/hg03-$G03_RUN_ID"
  mkdir -p "$G03_WIN_SCRATCH_U/plain" "$G03_WIN_SCRATCH_U/probe dir üø"
  G03_WIN_PLAIN_W="$(wslpath -w "$G03_WIN_SCRATCH_U/plain")"
  export HEIMDALL_G03_WIN_USER
  HEIMDALL_G03_WIN_USER="$(g03_win cmd.exe /d /c 'echo %USERNAME%' 2>/dev/null | tr -d '\r')"
  return 0
}

g03_manifest_get() {  # g03_manifest_get KEY  (from --win-manifest JSON)
  "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); v=d
for k in sys.argv[2].split("."):
    v = v[int(k)] if isinstance(v, list) else v[k]
print(v)' "$G03_WIN_MANIFEST" "$1"
}

g03_winlog_since() {  # g03_winlog_since EPOCH KEY=VALUE...  -> matching count in the Windows agent log
  g03_winlog_file_since "$G03_WIN_LOG_U" "$@"
}

g03_winlog_file_since() {  # g03_winlog_file_since LOGFILE EPOCH KEY=VALUE...  -> matching count (-1 if no log)
  "$PY" - "$@" <<'EOF'
import json, sys
from datetime import datetime, timezone
path, since, conds = sys.argv[1], float(sys.argv[2]), [c.split("=", 1) for c in sys.argv[3:]]
def ts(s):
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()
n = 0
try:
    for line in open(path, encoding="utf-8-sig"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if ts(d.get("ts", "1970-01-01T00:00:00")) < since:
            continue
        ok = True
        for k, v in conds:
            got = str(d.get(k, ""))
            if v.startswith("~"):
                ok = ok and v[1:].lower() in got.lower()
            else:
                ok = ok and got == v
        n += 1 if ok else 0
except FileNotFoundError:
    print(-1); sys.exit(0)
print(n)
EOF
}

g03_win_relay_count() {  # count live Windows PipeStdioRelay.ps1 processes started at/after EPOCH
  # The command line is filtered inside PowerShell and only a count is printed
  # (no command line is emitted). The match string is split so this counter's
  # own command line does not match itself.
  local since="$1"
  g03_win powershell.exe -NoProfile -NonInteractive -Command \
    "\$t=[DateTimeOffset]::FromUnixTimeSeconds($since).UtcDateTime; \$m='*PipeStdio'+'Relay.ps1*'; @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" -ErrorAction SilentlyContinue | Where-Object { \$_.CommandLine -like \$m -and \$_.CreationDate.ToUniversalTime() -ge \$t }).Count" \
    2>/dev/null | tr -d '\r'
}

g03_win_sock_env() {  # sets WENV: env prefix giving Windows ssh.exe an explicit SSH_AUTH_SOCK via WSLENV
  # $1 = extra WSLENV entries (optional, e.g. HEIMDALL_G03_IA/w). The user's WSLENV is not inherited.
  local sock="${G03_WIN_DECOY_PIPE_PATH:-\\\\.\\pipe\\heimdall-g03-none-$G03_RUN_ID}" extra="${1:-}"
  WENV=(env "SSH_AUTH_SOCK=$sock" "WSLENV=SSH_AUTH_SOCK/w${extra:+:$extra}")
}

g03_net_mode_obs() {  # g03_net_mode_obs CASE: record the WSL networking mode (interop required)
  # Effective mode first from wslinfo inside the distribution (no Windows file read;
  # `wslinfo --networking-mode` is not in the pinned sources [U]). Only when wslinfo is
  # unavailable is the owner's %USERPROFILE%\.wslconfig read, and then only the
  # [wsl2] networkingMode key (wsl-config.md [G03-S15]: none|nat|bridged|mirrored|
  # consomme, formerly called virtioproxy; absent or unknown -> NAT, with a Consomme
  # fallback from WSL 2.3.25). Either
  # value is recorded only if it is one of the known mode words; anything else is
  # recorded as "<unrecognized value, not recorded>". Neither the profile path nor any
  # other .wslconfig content is recorded.
  local c="$1" prof cfgv="" wc w
  if command -v wslinfo >/dev/null 2>&1; then
    w="$(wslinfo --networking-mode 2>/dev/null | head -1 | tr -d ' \r\t')"
    g03_obs "$c" wslinfo_networking_mode --str "$(g03_net_mode_word "$w")"
    g03_obs "$c" wslconfig_networkingMode --str "<not read: wslinfo available>"
    return 0
  fi
  g03_obs "$c" wslinfo_networking_mode --str unavailable
  prof="$(g03_win cmd.exe /d /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
  wc=""; [ -n "$prof" ] && wc="$(wslpath -u "$prof" 2>/dev/null)/.wslconfig"
  if [ -n "$wc" ] && [ -f "$wc" ]; then
    cfgv="$(sed -n '/^[[:space:]]*\[wsl2\]/,/^[[:space:]]*\[/p' "$wc" | grep -i -m1 '^[[:space:]]*networkingMode[[:space:]]*=' | sed 's/^[^=]*=//' | tr -d ' \r\t"')"
    if [ -n "$cfgv" ]; then g03_obs "$c" wslconfig_networkingMode --str "$(g03_net_mode_word "$cfgv")"
    else g03_obs "$c" wslconfig_networkingMode --str "<key absent: documented default nat>"; fi
  else
    g03_obs "$c" wslconfig_networkingMode --str "<no .wslconfig: documented default nat>"
  fi
}

g03_net_mode_word() {  # print $1 lower-cased if it is a known WSL networking-mode word, else a placeholder
  local v; v="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$v" in
    none|nat|bridged|mirrored|virtioproxy|consomme) printf '%s' "$v" ;;
    "") printf '<empty>' ;;
    *) printf '<unrecognized value, not recorded>' ;;
  esac
}

g03_wslenv_check() {  # g03_wslenv_check: verify WENV's SSH_AUTH_SOCK reaches a Win32 process (cmd.exe, no ssh)
  # WSLENV '/w' = "only be included when running Win32 from WSL" (filesystems.md
  # [G03-S15]). If a Win32 process does not see exactly the value WENV sets, ssh.exe
  # would start with an UNSET Windows-side SSH_AUTH_SOCK (= the system default pipe),
  # so callers must not run ssh.exe. Prints ok|mismatch.
  local want seen
  want="${WENV[1]#SSH_AUTH_SOCK=}"
  seen="$("${WENV[@]}" sh -c 'cd /mnt/c && cmd.exe /d /c echo %SSH_AUTH_SOCK%' 2>/dev/null | tr -d '\r\n')"
  if [ -n "$want" ] && [ "$seen" = "$want" ]; then echo ok; else echo mismatch; fi
}

g03_win_proc_count() {  # count Windows processes by image name started at/after EPOCH (names/PIDs only)
  local image="$1" since="$2"
  g03_win powershell.exe -NoProfile -NonInteractive -Command \
    "\$t=[DateTimeOffset]::FromUnixTimeSeconds($since).LocalDateTime; @(Get-Process -Name '$image' -ErrorAction SilentlyContinue | Where-Object { try { \$_.StartTime -ge \$t } catch { \$false } }).Count" \
    2>/dev/null | tr -d '\r'
}
