#!/usr/bin/env bash
# G03 WSL probe harness, in-distribution probes (plan.md §3 G03; spec §8.4,
# §10.3, §10.4; acceptance A12 Mode A and A13 Mode B).
#
# Run INSIDE a real WSL2 distribution on a Windows x86-64 host. Multi-
# distribution exposure, distribution restart and idle-timeout probes need a
# second distribution and live in run_g03_wsl_lifecycle.sh.
#
# Usage: run_g03_wsl_probes.sh [options]
#   --out DIR                 output directory (default tests/evidence/artifacts/g03/runs/<run-id>)
#   --probes LIST             comma list (default: all) of:
#                             env,a-exec,a-io,a-quoting,a-git,a-cert,a-elevation,
#                             b-perms,b-unauthorized,b-relay,b-deletion,b-stale,b-teardown,b-lock
#   --ssh-host H --ssh-port P --ssh-user U --known-hosts FILE
#                             disposable fixture reachable from Windows ssh.exe (Mode A)
#   --win-manifest FILE       manifest written by Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl
#   --git-url URL [--git-push]  disposable fixture repository (Mode A Git)
#   --ca-key FILE --cert-principal P --cert-host H --cert-port P --cert-user U
#                             disposable fixture CA and CA-trusting host (Mode A cert change)
#   --other-linux-user NAME   second Linux account usable via `sudo -n -u NAME` (Mode B perms)
#   --lock-window-minutes N   run the host-lock probe for N minutes (operator locks Windows)
#   --no-uac-observed         operator attests no UAC prompt appeared during the run
#   --selftest-non-wsl        harness self-test outside WSL (Mode B mechanics only;
#                             records are labeled G03-harness-selftest-unix-*)
#
# Default mode never touches ~/.ssh, the owner's agents, or global Git config,
# and never contacts \\.\pipe\openssh-ssh-agent: Windows ssh.exe always gets an
# explicit IdentityAgent for the fixture pipe named in --win-manifest, and an
# explicit Windows-side SSH_AUTH_SOCK (decoy or sentinel) whose WSLENV propagation
# is checked with cmd.exe before the first ssh.exe run.
# Owner state read: the WSL networking mode, from `wslinfo --networking-mode`, or
# when wslinfo is absent from the [wsl2] networkingMode key of the owner's
# %USERPROFILE%\.wslconfig; only a known mode word is recorded (no path, no other
# content).

# SC2016: single-quoted $ in sh -c bodies, ssh_config text and remote commands is intentional.
# SC1003: tr '\\' '/' converts Windows separators.
# shellcheck disable=SC2016,SC1003
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=g03_common.sh
. "$HERE/g03_common.sh"

OUT="" PROBES="all" SSH_HOST="" SSH_PORT="22" SSH_USER="" KNOWN_HOSTS="" G03_WIN_MANIFEST=""
GIT_URL="" GIT_PUSH=0 CA_KEY="" CERT_PRINCIPAL="" CERT_HOST="" CERT_PORT="22" CERT_USER=""
OTHER_USER="" LOCK_MINUTES=0 NO_UAC=0 SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --probes) PROBES="$2"; shift 2 ;;
    --ssh-host) SSH_HOST="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --ssh-user) SSH_USER="$2"; shift 2 ;;
    --known-hosts) KNOWN_HOSTS="$2"; shift 2 ;;
    --win-manifest) G03_WIN_MANIFEST="$2"; shift 2 ;;
    --git-url) GIT_URL="$2"; shift 2 ;;
    --git-push) GIT_PUSH=1; shift ;;
    --ca-key) CA_KEY="$2"; shift 2 ;;
    --cert-principal) CERT_PRINCIPAL="$2"; shift 2 ;;
    --cert-host) CERT_HOST="$2"; shift 2 ;;
    --cert-port) CERT_PORT="$2"; shift 2 ;;
    --cert-user) CERT_USER="$2"; shift 2 ;;
    --other-linux-user) OTHER_USER="$2"; shift 2 ;;
    --lock-window-minutes) LOCK_MINUTES="$2"; shift 2 ;;
    --no-uac-observed) NO_UAC=1; shift ;;
    --selftest-non-wsl) SELFTEST=1; shift ;;
    -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

g03_init "$OUT"
[ "$SELFTEST" = 1 ] && G03_CASE_PREFIX="G03-harness-selftest-unix-"
G03_PROVIDERS=("linux ssh=$("$LINUX_SSH" -V 2>&1 | head -1)")
QUOTING_CASES="$G03_REPO/tests/native/windows/fixtures/quoting-cases.json"

NOT_WSL="WSL2 distribution (Ubuntu 24.04 or Debian 13, x86-64) on a native Windows 11 x86-64 host with WSL interop enabled; this run was not inside WSL"
NO_FIXTURE="disposable SSH fixture reachable from Windows ssh.exe (--ssh-host/--ssh-user/--known-hosts), e.g. tests/fixtures/ssh (M00-T03)"
NO_MANIFEST="Windows-side instrumented agent manifest (--win-manifest from Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl) on the same Windows host"

want() { [ "$PROBES" = all ] && return 0; case ",$PROBES," in *",$1,"*) return 0 ;; esac; return 1; }
in_wsl() { g03_is_wsl; }
mechanics_ok() { in_wsl || [ "$SELFTEST" = 1 ]; }

# ------------------------------------------------------------------ Windows/Mode A setup
SSHEXE="" SSHEXE_BASE=() PIPE="" WIN_READY=0 WIN_AUTH=""
win_setup() {  # prepares ssh.exe base argv against the fixture; returns 1 with WIN_REASON on failure
  [ "$WIN_READY" = 1 ] && return 0
  WIN_REASON=""
  in_wsl || { WIN_REASON="$NOT_WSL"; return 1; }
  [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || { WIN_REASON="WSL interop enabled in the probe distribution ([interop] enabled=true)"; return 1; }
  [ -n "$G03_WIN_MANIFEST" ] && [ -f "$G03_WIN_MANIFEST" ] || { WIN_REASON="$NO_MANIFEST"; return 1; }
  [ -n "$SSH_HOST" ] && [ -n "$SSH_USER" ] && [ -f "$KNOWN_HOSTS" ] || { WIN_REASON="$NO_FIXTURE"; return 1; }
  g03_win_init || { WIN_REASON="powershell.exe reachable through WSL interop"; return 1; }
  SSHEXE="$(command -v ssh.exe || true)"
  [ -n "$SSHEXE" ] || SSHEXE=/mnt/c/Windows/System32/OpenSSH/ssh.exe
  [ -x "$SSHEXE" ] || { WIN_REASON="Windows OpenSSH client (ssh.exe) installed on the Windows host"; return 1; }
  PIPE="$(g03_manifest_get pipe_name)"
  G03_WIN_LOG_U="$(wslpath -u "$(g03_manifest_get log_path)")"
  win_decoy_setup
  # Positive check of WSLENV '/w' propagation before ANY ssh.exe run (review D7): if a
  # Win32 process does not see the decoy/sentinel value, ssh.exe would start with an
  # unset Windows-side SSH_AUTH_SOCK (= the system default pipe), so refuse.
  if [ "$(g03_wslenv_check)" != ok ]; then
    WIN_REASON="WSLENV 'SSH_AUTH_SOCK/w' propagation to a Win32 process (cmd.exe check did not see the value); ssh.exe runs refused so ssh.exe never starts with an unset Windows-side SSH_AUTH_SOCK"
    return 1
  fi
  cp "$KNOWN_HOSTS" "$G03_WIN_SCRATCH_U/plain/known_hosts"
  printf 'Host probe-target\n    HostName %s\n    Port %s\n    User %s\n' "$SSH_HOST" "$SSH_PORT" "$SSH_USER" > "$G03_WIN_SCRATCH_U/plain/ssh_config"
  local kh cfg
  kh="$(wslpath -w "$G03_WIN_SCRATCH_U/plain/known_hosts" | tr '\\' '/')"
  cfg="$(wslpath -w "$G03_WIN_SCRATCH_U/plain/ssh_config")"
  case "$kh" in *" "*) kh="\"$kh\"" ;; esac
  SSHEXE_BASE=(-F "$cfg" -o BatchMode=yes -o IdentityFile=none -o IdentitiesOnly=no -o PreferredAuthentications=publickey
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$kh" -o GlobalKnownHostsFile=none -o UpdateHostKeys=no -o ControlMaster=no
    -o ControlPath=none -o ForwardAgent=no -o ProxyCommand=none -o ConnectTimeout=10)
  G03_PROVIDERS+=("windows ssh.exe=$("${WENV[@]}" "$SSHEXE" -V 2>&1 | tr -d '\r' | head -1)")
  WIN_READY=1
  return 0
}
win_decoy_setup() {  # decoy pipe from the manifest (older manifests: none -> sentinel); sets WENV
  local d
  d="$(g03_manifest_get decoy_pipe_name 2>/dev/null || true)"
  if [ -n "$d" ]; then
    G03_WIN_DECOY_PIPE_PATH="\\\\.\\pipe\\$d"
    G03_WIN_DECOY_LOG_U="$(wslpath -u "$(g03_manifest_get decoy_log_path)")"
  else
    G03_WIN_DECOY_PIPE_PATH="" G03_WIN_DECOY_LOG_U=""
  fi
  g03_win_sock_env
}
win_auth() {  # verifies the manifest key 1 is authorized on the fixture (ssh.exe true)
  [ -n "$WIN_AUTH" ] && { [ "$WIN_AUTH" = yes ]; return; }
  if "${WENV[@]}" "$SSHEXE" "${SSHEXE_BASE[@]}" -o "IdentityAgent=//./pipe/$PIPE" probe-target true </dev/null >/dev/null 2>&1; then
    WIN_AUTH=yes; return 0
  fi
  WIN_AUTH=no; return 1
}
NO_WIN_AUTH="the Windows instrumented agent's key 1 (manifest public_key_dir/probe-key-1.pub) authorized on the disposable fixture account"

# ------------------------------------------------------------------ env
probe_env() {
  local c=wsl-env-inventory
  in_wsl || { g03_blocked $c "$NOT_WSL" R-EN-02 R-EN-03 R-QU-02; return; }
  g03_obs $c interop_binfmt --str "$(head -1 /proc/sys/fs/binfmt_misc/WSLInterop 2>/dev/null || echo absent)"
  g03_obs $c wsl_conf_interop_lines --str "$(sed -n '/^\[interop\]/,/^\[/p' /etc/wsl.conf 2>/dev/null | head -10)"
  g03_obs $c windows_path_appended --json "$(g03_bool sh -c 'echo "$PATH" | grep -q "/mnt/c/"')"
  g03_obs $c wsl_interop_env_present --json "$([ -n "${WSL_INTEROP:-}" ] && echo true || echo false)"
  g03_obs $c run_wsl_entries --str "$(find /run/WSL -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ') entries"
  g03_obs $c mnt_wsl_present --json "$([ -d /mnt/wsl ] && echo true || echo false)"
  g03_obs $c mnt_wsl_fstype --str "$(awk '$2=="/mnt/wsl"{print $3}' /proc/mounts 2>/dev/null | head -1)"
  g03_obs $c net_namespace_id --str "$(readlink /proc/self/ns/net 2>/dev/null)"
  g03_obs $c mnt_namespace_id --str "$(readlink /proc/self/ns/mnt 2>/dev/null)"
  if [ -e /proc/sys/fs/binfmt_misc/WSLInterop ]; then
    g03_run $c wsl-version -- env WSL_UTF8=1 sh -c 'cd /mnt/c && wsl.exe --version'
    g03_obs $c wsl_version --str "$(tr -d '\000\r' < "$G03_LAST_OUT" | head -3)"
    g03_run $c wsl-list -- env WSL_UTF8=1 sh -c 'cd /mnt/c && wsl.exe -l -v'
    g03_obs $c wsl_distributions --str "$(tr -d '\000\r' < "$G03_LAST_OUT")"
    g03_net_mode_obs $c
    g03_obs $c ssh_exe_on_path --str "$(command -v ssh.exe || echo none)"
    if command -v ssh.exe >/dev/null 2>&1; then g03_obs $c ssh_exe_version --str "$(ssh.exe -V 2>&1 | tr -d '\r' | head -1)"; fi
  fi
  g03_obs $c git_version --str "$(git --version 2>/dev/null || echo none)"
  g03_crit $c inventory_collected true
  g03_finish $c R-EN-02 R-EN-03 R-QU-02
}

# ------------------------------------------------------------------ Mode A: executable/endpoint selection
win_counts() {  # win_counts EPOCH -> sets NT (target REQUEST_IDENTITIES) and ND (decoy; -1 if no decoy log)
  NT=$(g03_winlog_since "$1" event=request msg_type=11)
  if [ -n "${G03_WIN_DECOY_LOG_U:-}" ]; then ND=$(g03_winlog_file_since "$G03_WIN_DECOY_LOG_U" "$1" event=request msg_type=11); else ND=-1; fi
}

probe_a_exec() {
  local c=wsl-a-executable-selection t0 val out
  win_setup || { g03_blocked $c "$WIN_REASON" R-EN-02 R-SS-03; return; }
  g03_obs $c ssh_exe_path --str "$SSHEXE"
  g03_obs $c windows_side_SSH_AUTH_SOCK --str "$([ -n "${G03_WIN_DECOY_LOG_U:-}" ] && echo 'manifest decoy pipe (instrumented)' || echo 'non-existent sentinel pipe (manifest has no decoy)')"
  # 1. explicit -o IdentityAgent; decoy in the Windows-side SSH_AUTH_SOCK.
  t0=$(g03_epoch); sleep 1
  g03_run $c identityagent-cli -- "${WENV[@]}" "$SSHEXE" "${SSHEXE_BASE[@]}" -o "IdentityAgent=//./pipe/$PIPE" probe-target true
  local reached=false
  if [ "$G03_RC" -eq 0 ] || grep -q 'Permission denied' "$G03_LAST_ERR"; then reached=true; fi
  sleep 1; win_counts "$t0"
  g03_obs $c identityagent_cli --json "{\"exit\": $G03_RC, \"target_identity_requests\": $NT, \"decoy_identity_requests\": $ND, \"reached_userauth\": $reached}"
  g03_crit $c cli_identityagent_selects_windows_fixture_pipe "$([ "$NT" -ge 1 ] && [ "$ND" -le 0 ] && echo true || echo false)"
  # 2. config IdentityAgent $HEIMDALL_G03_IA propagated with WSLENV; decoy still in SSH_AUTH_SOCK.
  printf 'Host probe-target\n    HostName %s\n    Port %s\n    User %s\n    IdentityAgent $HEIMDALL_G03_IA\n' "$SSH_HOST" "$SSH_PORT" "$SSH_USER" > "$G03_WIN_SCRATCH_U/plain/ssh_config_envform"
  local cfg2; cfg2="$(wslpath -w "$G03_WIN_SCRATCH_U/plain/ssh_config_envform")"
  local base2=("${SSHEXE_BASE[@]}"); base2[1]="$cfg2"
  g03_win_sock_env "HEIMDALL_G03_IA/w"
  t0=$(g03_epoch); sleep 1
  g03_run $c wslenv-envform -- "${WENV[@]}" HEIMDALL_G03_IA="\\\\.\\pipe\\$PIPE" "$SSHEXE" "${base2[@]}" probe-target true
  g03_win_sock_env
  sleep 1; win_counts "$t0"
  g03_obs $c wslenv_env_form --json "{\"exit\": $G03_RC, \"target_identity_requests\": $NT, \"decoy_identity_requests\": $ND}"
  g03_crit $c wslenv_propagates_identityagent_env_form "$([ "$NT" -ge 1 ] && [ "$ND" -le 0 ] && echo true || echo false)"
  # 3. Linux env visibility to a Windows process without a WSLENV entry, measured with
  #    cmd.exe (no ssh, no agent). Control: the same variable listed in WSLENV.
  val="g03-$(g03_hex 4)"
  g03_run $c env-visible-with-wslenv -- env HEIMDALL_G03_IA="$val" WSLENV="HEIMDALL_G03_IA/w" sh -c 'cd /mnt/c && cmd.exe /d /c echo %HEIMDALL_G03_IA%'
  out="$(tr -d '\r\n' < "$G03_LAST_OUT")"
  local ctl=false; [ "$out" = "$val" ] && ctl=true
  g03_run $c env-visible-without-wslenv -- env -u WSLENV HEIMDALL_G03_IA="$val" sh -c 'cd /mnt/c && cmd.exe /d /c echo %HEIMDALL_G03_IA%'
  out="$(tr -d '\r\n' < "$G03_LAST_OUT")"
  g03_obs $c env_visibility --json "{\"control_with_wslenv_visible\": $ctl, \"without_wslenv_output_is_value\": $([ "$out" = "$val" ] && echo true || echo false)}"
  g03_crit $c linux_env_not_visible_without_wslenv "$([ "$out" != "$val" ] && echo true || echo false)"
  [ "$ctl" = true ] || g03_crit $c linux_env_not_visible_without_wslenv null
  # 4. ssh.exe with IdentityAgent $VAR whose variable is absent (observation). Pinned
  #    ssh.c unsets SSH_AUTH_SOCK in that case [S]; whether a shipped build falls back
  #    to \\.\pipe\openssh-ssh-agent is unknown, so this runs only while that pipe name
  #    does not exist (passive enumeration), i.e. no owner agent can be reached.
  local dflt
  dflt="$(g03_win powershell.exe -NoProfile -NonInteractive -Command "@([IO.Directory]::GetFiles('\\\\.\\pipe\\') | Where-Object { \$_ -like '*\\openssh-ssh-agent' }).Count" 2>/dev/null | tr -d '\r')"
  if [ "$dflt" = 0 ]; then
    t0=$(g03_epoch); sleep 1
    g03_run $c unset-var-envform -- "${WENV[@]}" "$SSHEXE" "${base2[@]}" probe-target true
    sleep 1; win_counts "$t0"
    g03_obs $c unset_var_identityagent --json "{\"exit\": $G03_RC, \"target_identity_requests\": $NT, \"decoy_identity_requests\": $ND, \"default_pipe_present\": false}"
  else
    g03_obs $c unset_var_identityagent --str "not run: \\\\.\\pipe\\openssh-ssh-agent exists on this host (count=${dflt:-unknown}); running it could reach the owner's agent"
  fi
  if [ "$reached" != true ]; then
    # The -o run doubles as the control: if it never reached user authentication
    # (e.g. fixture unreachable or host key mismatch) the selection rows are inconclusive.
    g03_crit $c cli_identityagent_selects_windows_fixture_pipe null
    g03_crit $c wslenv_propagates_identityagent_env_form null
  fi
  g03_limit $c "Selection is judged from the Windows instrumented agent logs (target and decoy); authentication success is not required."
  g03_limit $c "ssh.exe always receives the manifest decoy pipe (or a non-existent sentinel) as its Windows-side SSH_AUTH_SOCK through WSLENV; a selection criterion fails if the decoy is contacted."
  g03_finish $c R-EN-02 R-SS-03
}

# ------------------------------------------------------------------ Mode A: process I/O
probe_a_io() {
  local c=wsl-a-process-io t0 cnt
  win_setup || { g03_blocked $c "$WIN_REASON" R-EN-02 R-SS-04; return; }
  win_auth || { g03_blocked $c "$NO_WIN_AUTH" R-EN-02 R-SS-04; return; }
  local A=("${WENV[@]}" "$SSHEXE" "${SSHEXE_BASE[@]}" -o "IdentityAgent=//./pipe/$PIPE" probe-target)
  g03_run $c exit-42 -- "${A[@]}" 'exit 42' </dev/null
  g03_crit $c remote_exit_status_preserved "$([ "$G03_RC" -eq 42 ] && echo true || echo false)"
  g03_run $c stream-separation -- "${A[@]}" 'printf out; printf err >&2' </dev/null
  g03_crit $c stderr_not_on_stdout "$([ "$(cat "$G03_LAST_OUT")" = out ] && echo true || echo false)"
  g03_run $c utf8-output -- "${A[@]}" "printf '\\303\\274\\342\\230\\203\\n'" </dev/null
  local hex; hex="$(od -An -tx1 < "$G03_LAST_OUT" | tr -d ' \n')"
  g03_obs $c utf8_bytes_hex --str "$hex"
  g03_crit $c utf8_output_bytes_exact "$([ "$hex" = c3bce298830a ] && echo true || echo false)"
  head -c 1048576 /dev/urandom > "$G03_SCRATCH/in.bin"
  g03_run $c binary-roundtrip -- sh -c '"$@" cat < "$0" > "$0.out"' "$G03_SCRATCH/in.bin" "${A[@]}"
  local a b; a="$(g03_sha256 "$G03_SCRATCH/in.bin")"; b="$(g03_sha256 "$G03_SCRATCH/in.bin.out" 2>/dev/null || echo missing)"
  g03_obs $c binary_sha256 --json "{\"in\": \"$a\", \"out\": \"$b\"}"
  g03_crit $c binary_roundtrip_exact "$([ "$a" = "$b" ] && echo true || echo false)"
  g03_run $c stdin-eof -- sh -c 'printf abc | "$@" "cat; printf done"' sh "${A[@]}"
  g03_crit $c stdin_eof_propagates "$([ "$(cat "$G03_LAST_OUT")" = abcdone ] && echo true || echo false)"
  t0=$(g03_epoch)
  g03_run $c interrupt-sigint -- timeout -s INT 4 "${A[@]}" 'sleep 30' </dev/null
  g03_obs $c interrupt_exit_code --json "$G03_RC"
  sleep 4; cnt="$(g03_win_proc_count ssh "$t0")"
  g03_obs $c windows_ssh_processes_after_interrupt --str "$cnt"
  g03_crit $c no_orphan_windows_ssh_after_interrupt "$([ "$cnt" = 0 ] && echo true || echo false)"
  local i s e lat=""
  for i in 1 2 3; do s=$(date +%s%N 2>/dev/null || date +%s); "${A[@]}" true </dev/null >/dev/null 2>&1; e=$(date +%s%N 2>/dev/null || date +%s); lat="$lat $(( (e - s) / 1000000 ))"; done
  g03_obs $c ssh_exe_true_wall_ms --str "${lat# }"
  g03_limit $c "Interactive Ctrl-C from a WSL terminal, PTY resize, and console behavior are manual steps not run by this script."
  g03_finish $c R-EN-02 R-SS-04
}

# ------------------------------------------------------------------ Mode A: paths and quoting
probe_a_quoting() {
  local c=wsl-a-path-quoting
  win_setup || { g03_blocked $c "$WIN_REASON" R-EN-02 R-SS-04; return; }
  win_auth || { g03_blocked $c "$NO_WIN_AUTH" R-EN-02 R-SS-04; return; }
  local cfgtext; cfgtext="$(cat "$G03_WIN_SCRATCH_U/plain/ssh_config")"
  printf '%s\n' "$cfgtext" > "$G03_SPACED/linux ssh config"
  local wdir="$G03_WIN_SCRATCH_U/probe dir üø"
  printf '%s\n' "$cfgtext" > "$wdir/ssh config"
  cp "$KNOWN_HOSTS" "$wdir/known_hosts"
  local ia="IdentityAgent=//./pipe/$PIPE"
  local b1=("${SSHEXE_BASE[@]}"); b1[1]="$G03_SPACED/linux ssh config"
  g03_run $c config-linux-path -- "${WENV[@]}" "$SSHEXE" "${b1[@]}" -o "$ia" probe-target true </dev/null
  g03_obs $c config_linux_path_exit --json "$G03_RC"
  b1[1]="$(wslpath -w "$G03_SPACED/linux ssh config")"
  g03_run $c config-unc-wsl-path -- "${WENV[@]}" "$SSHEXE" "${b1[@]}" -o "$ia" probe-target true </dev/null
  g03_obs $c config_unc_wsl_localhost_path_exit --json "$G03_RC"
  b1[1]="$(wslpath -w "$wdir/ssh config")"
  g03_run $c config-windows-spaced-unicode -- "${WENV[@]}" "$SSHEXE" "${b1[@]}" -o "$ia" probe-target true </dev/null
  g03_obs $c config_windows_spaced_unicode_exit --json "$G03_RC"
  g03_crit $c windows_fs_spaced_unicode_config_works "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  local khq; khq="$(wslpath -w "$wdir/known_hosts" | tr '\\' '/')"
  local b2=() i=0
  while [ $i -lt ${#SSHEXE_BASE[@]} ]; do
    case "${SSHEXE_BASE[$i]}" in UserKnownHostsFile=*) b2+=("UserKnownHostsFile=\"$khq\"") ;; *) b2+=("${SSHEXE_BASE[$i]}") ;; esac
    i=$((i + 1))
  done
  g03_run $c known-hosts-embedded-quotes -- "${WENV[@]}" "$SSHEXE" "${b2[@]}" -o "$ia" probe-target true </dev/null
  g03_obs $c known_hosts_spaced_path_with_embedded_quotes_exit --json "$G03_RC"
  local outdir
  outdir="$G03_OUT/artifacts/$(g03_cid $c)/argv"
  "$PY" "$HERE/argv_fidelity.py" --cases "$QUOTING_CASES" --out-dir "$outdir" -- "${WENV[@]}" "$SSHEXE" "${SSHEXE_BASE[@]}" -o "$ia" probe-target > "$G03_SCRATCH/argv.json"
  g03_obs $c remote_argument_fidelity --file "$G03_SCRATCH/argv.json"
  printf '%s\n' "$outdir" >> "$(g03_case_file $c evidence)"
  g03_crit $c argv_exact_all_cases "$("$PY" -c 'import json,sys; print("true" if json.load(open(sys.argv[1]))["all_exact"] else "false")' "$G03_SCRATCH/argv.json")"
  g03_limit $c "Linux-path and \\\\wsl.localhost UNC config rows are observations; WSL interop's argv-to-command-line conversion is undocumented and is what the argv rows measure."
  g03_finish $c R-EN-02 R-SS-04
}

g03_shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# ------------------------------------------------------------------ Mode A: Git
probe_a_git() {
  local c=wsl-a-git t0 n
  win_setup || { g03_blocked $c "$WIN_REASON" R-EN-02 R-SS-03; return; }
  [ -n "$GIT_URL" ] || { g03_blocked $c "disposable fixture Git repository URL (--git-url) reachable from Windows ssh.exe" R-EN-02 R-SS-03; return; }
  win_auth || { g03_blocked $c "$NO_WIN_AUTH" R-EN-02 R-SS-03; return; }
  command -v git >/dev/null || { g03_blocked $c "git installed in the WSL distribution" R-EN-02 R-SS-03; return; }
  local words="" w
  for w in "$SSHEXE" "${SSHEXE_BASE[@]}"; do words="$words $(g03_shq "$w")"; done
  local good bad
  good="${words# } -o $(g03_shq "IdentityAgent=//./pipe/$PIPE")"
  bad="${words# } -o $(g03_shq "IdentityAgent=//./pipe/heimdall-g03-nonexistent-$(g03_hex 3)")"
  # WENV (env SSH_AUTH_SOCK=<decoy> WSLENV=SSH_AUTH_SOCK/w) reaches ssh.exe through git.
  local GENV=("${WENV[@]}" HOME="$G03_HOME" GIT_CONFIG_GLOBAL="$G03_HOME/empty.gitconfig" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0)
  t0=$(g03_epoch); sleep 1
  g03_run $c ls-remote-core-sshCommand -- "${GENV[@]}" git -c "core.sshCommand=$good" ls-remote "$GIT_URL"
  sleep 1; n=$(g03_winlog_since "$t0" event=request msg_type=11)
  g03_obs $c core_sshCommand --json "{\"exit\": $G03_RC, \"windows_agent_identity_requests\": $n}"
  g03_crit $c core_sshCommand_ssh_exe_works "$([ "$G03_RC" -eq 0 ] && [ "$n" -ge 1 ] && echo true || echo false)"
  g03_run $c env-precedence -- "${GENV[@]}" GIT_SSH_COMMAND="$good" git -c "core.sshCommand=$bad" ls-remote "$GIT_URL"
  g03_crit $c GIT_SSH_COMMAND_overrides_core_sshCommand "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  local lclone="$G03_SPACED/clone ü"
  g03_run $c clone-linux-spaced-unicode -- "${GENV[@]}" git -c "core.sshCommand=$good" clone -q "$GIT_URL" "$lclone"
  g03_crit $c clone_into_linux_spaced_unicode_path "$([ "$G03_RC" -eq 0 ] && [ -d "$lclone/.git" ] && echo true || echo false)"
  local wclone="$G03_WIN_SCRATCH_U/probe dir üø/clone ü"
  g03_run $c clone-windows-spaced-unicode -- "${GENV[@]}" git -c "core.sshCommand=$good" clone -q "$GIT_URL" "$wclone"
  g03_crit $c clone_into_windows_spaced_unicode_path "$([ "$G03_RC" -eq 0 ] && [ -d "$wclone/.git" ] && echo true || echo false)"
  if [ "$GIT_PUSH" = 1 ] && [ -d "$lclone/.git" ]; then
    printf 'g03 %s\n' "$G03_RUN_ID" > "$lclone/g03-probe-$G03_RUN_ID.txt"
    "${GENV[@]}" git -C "$lclone" add . >/dev/null 2>&1
    "${GENV[@]}" git -C "$lclone" -c user.name=heimdall-g03 -c user.email=g03@invalid commit -qm "g03 probe $G03_RUN_ID" >/dev/null 2>&1
    g03_run $c push -- "${GENV[@]}" git -C "$lclone" -c "core.sshCommand=$good" push -q origin HEAD
    g03_crit $c push_works "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  else
    g03_limit $c "Push not exercised (needs --git-push and a disposable writable fixture repository)."
  fi
  g03_finish $c R-EN-02 R-SS-03
}

# ------------------------------------------------------------------ Mode A: public certificate file change
probe_a_cert() {
  local c=wsl-a-cert-change
  win_setup || { g03_blocked $c "$WIN_REASON" R-EN-02 R-CR-07; return; }
  [ -n "$CA_KEY" ] && [ -f "$CA_KEY" ] && [ -n "$CERT_PRINCIPAL" ] && [ -n "$CERT_HOST" ] && [ -n "$CERT_USER" ] || {
    g03_blocked $c "disposable fixture user CA private key and a CA-trusting fixture host (--ca-key/--cert-principal/--cert-host/--cert-user), e.g. M00-T03 ca-host1" R-EN-02 R-CR-07; return; }
  local kpub_w kdir="$G03_SCRATCH/cert" wdir="$G03_WIN_SCRATCH_U/plain"
  mkdir -p "$kdir"
  kpub_w="$(g03_manifest_get public_key_dir)\\probe-key-1.pub"
  cp "$(wslpath -u "$kpub_w")" "$kdir/k.pub"
  printf 'Host probe-cert\n    HostName %s\n    Port %s\n    User %s\n' "$CERT_HOST" "$CERT_PORT" "$CERT_USER" > "$wdir/ssh_config_cert"
  local base=("${SSHEXE_BASE[@]}"); base[1]="$(wslpath -w "$wdir/ssh_config_cert")"
  local certw; certw="$(wslpath -w "$wdir/k-cert.pub" | tr '\\' '/')"
  sign_cert() { rm -f "$kdir/k-cert.pub"; "$LINUX_SSH_KEYGEN" -q -s "$CA_KEY" -I heimdall-g03 -n "$1" -V +15m "$kdir/k.pub" && cp "$kdir/k-cert.pub" "$wdir/k-cert.pub"; }
  sign_cert "$CERT_PRINCIPAL"
  g03_run $c cert-good -- "${WENV[@]}" "$SSHEXE" "${base[@]}" -o "IdentityAgent=//./pipe/$PIPE" -o "CertificateFile=$certw" probe-cert true </dev/null
  g03_crit $c cert_with_permitted_principal_accepted "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  sign_cert "heimdall-g03-wrong-$(g03_hex 3)"
  g03_run $c cert-swapped -- "${WENV[@]}" "$SSHEXE" "${base[@]}" -o "IdentityAgent=//./pipe/$PIPE" -o "CertificateFile=$certw" probe-cert true </dev/null
  g03_crit $c swapped_cert_file_takes_effect_and_is_rejected "$([ "$G03_RC" -ne 0 ] && echo true || echo false)"
  sign_cert "$CERT_PRINCIPAL"
  g03_run $c cert-restored -- "${WENV[@]}" "$SSHEXE" "${base[@]}" -o "IdentityAgent=//./pipe/$PIPE" -o "CertificateFile=$certw" probe-cert true </dev/null
  g03_crit $c restored_cert_accepted "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  g03_finish $c R-EN-02 R-CR-07
}

# ------------------------------------------------------------------ Mode A: elevation
probe_a_elevation() {
  local c=wsl-a-elevation
  in_wsl || { g03_blocked $c "$NOT_WSL" R-EN-02 R-DI-02; return; }
  [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || { g03_blocked $c "WSL interop enabled in the probe distribution" R-EN-02 R-DI-02; return; }
  g03_run $c interop-child-elevation -- sh -c 'cd /mnt/c && powershell.exe -NoProfile -NonInteractive -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"'
  local el; el="$(tr -d '\r\n' < "$G03_LAST_OUT")"
  g03_obs $c interop_child_is_admin_token --str "$el"
  g03_run $c interop-child-integrity -- sh -c 'cd /mnt/c && whoami.exe /groups /fo csv'
  g03_obs $c interop_child_integrity_label --str "$(grep -i 'Mandatory Label' "$G03_LAST_OUT" | cut -d, -f1 | tr -d '"\r' | head -1)"
  g03_crit $c interop_child_not_elevated "$([ "$el" = False ] && echo true || echo false)"
  g03_crit $c no_uac_prompt_observed "$([ "$NO_UAC" = 1 ] && echo true || echo null)"
  g03_limit $c "The interop child inherits the token of the Windows process that started the WSL session; launching WSL from an elevated terminal is expected to change this result (inference, see research doc)."
  g03_finish $c R-EN-02 R-DI-02
}

# ------------------------------------------------------------------ Mode B mechanics (fixture upstream)
b_start_default() {  # fixture upstream + filtering proxy allowing k1 only; sets EPDIR/EPSOCK
  g03_b_upstream
  EPDIR="$(g03_b_epdir)"; EPSOCK="$EPDIR/agent.sock"
  g03_proxy_start "$1" "$EPSOCK" --upstream-unix "$G03_UP_SOCK" --allow-pub "$G03_SCRATCH/keys/k1.pub" "${@:2}"
}

probe_b_perms() {
  local c=wsl-b-endpoint-perms st
  mechanics_ok || { g03_blocked $c "$NOT_WSL" R-EN-03 R-RT-03 R-SE-03; return; }
  b_start_default perms
  st="$(g03_stat "$EPDIR")"; g03_obs $c endpoint_dir_stat --str "$st"
  g03_crit $c endpoint_dir_private "$(g03_glob "$st" "700 $(id -u) dir*")"
  st="$(g03_stat "$EPSOCK")"; g03_obs $c endpoint_socket_stat --str "$st"
  g03_crit $c endpoint_socket_owner_only "$(g03_glob "$st" "600 $(id -u) socket*")"
  g03_obs $c endpoint_under_xdg_runtime_dir --json "$(g03_glob "$EPDIR" "${XDG_RUNTIME_DIR:-/nonexistent}/*")"
  g03_run $c same-user-list -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c same_user_sees_only_allowed_key "$(grep -q "$G03_K1_FP" "$G03_LAST_OUT" && ! grep -q "$G03_K2_FP" "$G03_LAST_OUT" && echo true || echo false)"
  if [ -n "$OTHER_USER" ] && sudo -n -u "$OTHER_USER" true 2>/dev/null; then
    g03_run $c other-user-connect -- sudo -n -u "$OTHER_USER" "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" connect
    g03_obs $c other_user_connect --file "$G03_LAST_OUT"
    g03_crit $c other_linux_user_blocked_by_filesystem "$(grep -q '"connected": false' "$G03_LAST_OUT" && echo true || echo false)"
    # Peer-UID check in isolation: a deliberately world-accessible test endpoint.
    local odir
    odir="$G03_SCRATCH/insecure-$(g03_hex 2)"; mkdir -p "$odir"; chmod 755 "$odir"; chmod 711 "$G03_SCRATCH"
    g03_proxy_start insecure "$odir/agent.sock" --upstream-unix "$G03_UP_SOCK" --allow-pub "$G03_SCRATCH/keys/k1.pub" --insecure-mode-for-test
    g03_run $c other-user-vs-uid-check -- sudo -n -u "$OTHER_USER" "$PY" "$HERE/agent_client.py" --socket "$odir/agent.sock" list
    g03_obs $c other_user_vs_peer_uid_check --file "$G03_LAST_OUT"
    g03_crit $c peer_uid_check_rejects_other_user "$([ "$(g03_log_count "$G03_PX_LOG" event=peer_rejected)" -ge 1 ] && echo true || echo false)"
    g03_stop_pid "$G03_PX_PID" >/dev/null; chmod 700 "$G03_SCRATCH"
    if in_wsl && [ -e /proc/sys/fs/binfmt_misc/WSLInterop ]; then
      g03_run $c other-user-assume-owner-via-wsl-exe -- sudo -n -u "$OTHER_USER" sh -c "cd /mnt/c && wsl.exe -d \"\$1\" -u \"\$2\" -- id -un" sh "${WSL_DISTRO_NAME:-}" "$(id -un)"
      g03_obs $c other_linux_user_can_run_as_owner_via_wsl_exe --json "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
      g03_limit $c "Microsoft documents that a WSL distribution is not a security boundary from the Windows user; other_linux_user_can_run_as_owner_via_wsl_exe records whether interop lets another Linux account become the owner."
    fi
  else
    g03_crit $c other_linux_user_blocked_by_filesystem null
    g03_limit $c "Other-Linux-user sub-probes not run: needs --other-linux-user NAME with non-interactive sudo."
  fi
  g03_finish $c R-EN-03 R-RT-03 R-SE-03
}

probe_b_unauthorized() {
  local c=wsl-b-unauthorized-key
  mechanics_ok || { g03_blocked $c "$NOT_WSL" R-EN-03 R-SE-03 R-RT-03; return; }
  b_start_default unauth
  local PXLOG="$G03_PX_LOG" E=(env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME")
  g03_run $c list -- "${E[@]}" "$LINUX_SSH_ADD" -l
  g03_crit $c list_filtered_to_allowed_key "$(grep -q "$G03_K1_FP" "$G03_LAST_OUT" && ! grep -q "$G03_K2_FP" "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c crafted-sign-unauthorized -- "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" sign --pub "$G03_SCRATCH/keys/k2.pub"
  g03_crit $c unauthorized_key_sign_refused "$(grep -q '"reply_type": 5' "$G03_LAST_OUT" && echo true || echo false)"
  printf 'g03 %s\n' "$G03_RUN_ID" > "$G03_SCRATCH/msg.txt"
  g03_run $c sign-allowed -- "${E[@]}" "$LINUX_SSH_KEYGEN" -Y sign -U -f "$G03_SCRATCH/keys/k1.pub" -n heimdall-g03 "$G03_SCRATCH/msg.txt"
  printf 'probe@heimdall %s\n' "$(cut -d' ' -f1,2 < "$G03_SCRATCH/keys/k1.pub")" > "$G03_SCRATCH/allowed_signers"
  g03_run $c verify-allowed -- sh -c '"$0" -Y verify -f "$1" -I probe@heimdall -n heimdall-g03 -s "$2.sig" < "$2"' "$LINUX_SSH_KEYGEN" "$G03_SCRATCH/allowed_signers" "$G03_SCRATCH/msg.txt"
  g03_crit $c allowed_key_signature_verifies "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  g03_run $c add-key -- "${E[@]}" "$LINUX_SSH_ADD" "$G03_SCRATCH/keys/k2"
  g03_crit $c add_identity_refused "$([ "$G03_RC" -ne 0 ] && echo true || echo false)"
  g03_run $c remove-all -- "${E[@]}" "$LINUX_SSH_ADD" -D
  g03_run $c lock -- "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" raw --type 22 --payload-hex 0000000470617373
  g03_crit $c lock_refused "$(grep -q '"reply_type": 5' "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c extension-other -- "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" raw --type 27 --payload-hex 000000117175657279406f70656e7373682e636f6d
  g03_crit $c non_session_bind_extension_refused "$(grep -q '"reply_type": 5' "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c oversize -- "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" oversize
  g03_crit $c oversize_message_closes_connection "$(grep -q '"closed_by_peer": true' "$G03_LAST_OUT" && echo true || echo false)"
  g03_run $c upstream-intact -- env SSH_AUTH_SOCK="$G03_UP_SOCK" "$LINUX_SSH_ADD" -l
  g03_crit $c upstream_keys_unchanged_by_refused_mutations "$([ "$(grep -c 'SHA256:' "$G03_LAST_OUT")" -eq 2 ] && echo true || echo false)"
  g03_obs $c proxy_denials --json "{\"denied_key\": $(g03_log_count "$PXLOG" result=denied_key_not_allowed), \"denied_mutation\": $(g03_log_count "$PXLOG" result=denied_mutation), \"denied_extension\": $(g03_log_count "$PXLOG" result=denied_extension)}"
  cp "$PXLOG" "$G03_OUT/artifacts/$(g03_cid $c)/proxy-log.jsonl"
  g03_limit $c "Filtering is enforced by the probe proxy for callers that use this endpoint; any process able to reach the upstream directly bypasses it (filtered convenience, not isolation)."
  g03_finish $c R-EN-03 R-SE-03 R-RT-03
}

probe_b_deletion() {
  local c=wsl-b-socket-deletion st1 st2 rc
  mechanics_ok || { g03_blocked $c "$NOT_WSL" R-EN-03 R-RT-01 R-RT-04; return; }
  b_start_default delr --recreate
  st1="$(g03_stat "$EPSOCK")"; rm -f "$EPSOCK"; sleep 2; st2="$(g03_stat "$EPSOCK")"
  g03_obs $c with_recreate --json "{\"before\": \"$st1\", \"after\": \"$st2\"}"
  if [ "$(g03_glob "$st2" "600 * socket *")" = true ] && [ "$st1" != "$st2" ]; then g03_crit $c recreated_after_deletion true; else g03_crit $c recreated_after_deletion false; fi
  g03_run $c list-after-recreate -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c serves_after_recreate "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  g03_stop_pid "$G03_PX_PID" >/dev/null
  b_start_default delx
  local pid="$G03_PX_PID"; rm -f "$EPSOCK"; sleep 2
  if kill -0 "$pid" 2>/dev/null; then rc=running; else wait "$pid" 2>/dev/null; rc=$?; fi
  g03_obs $c without_recreate_exit --str "$rc"
  g03_crit $c stops_with_distinct_code_when_deleted "$([ "$rc" = 7 ] && echo true || echo false)"
  g03_run $c client-after-deletion -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c client_fails_cleanly "$([ "$G03_RC" -eq 2 ] && echo true || echo false)"
  g03_finish $c R-EN-03 R-RT-01 R-RT-04
}

probe_b_stale() {
  local c=wsl-b-stale-socket rc pidA
  mechanics_ok || { g03_blocked $c "$NOT_WSL" R-EN-03 R-RT-04; return; }
  b_start_default staleA; pidA="$G03_PX_PID"
  g03_proxy_start staleLive "$EPSOCK" --upstream-unix "$G03_UP_SOCK" --allow-pub "$G03_SCRATCH/keys/k1.pub"
  g03_obs $c second_start_while_live_exit --str "$G03_PX_RC"
  g03_crit $c refuses_to_replace_live_endpoint "$([ "$G03_PX_RC" = 3 ] && echo true || echo false)"
  # Kill, wait and reap inside one stderr-redirected block: bash's notice for a job killed by a
  # signal echoes the job's command line, which must not reach the console transcript.
  local killres
  { killres="$(g03_signal_pid "$pidA" KILL)"; sleep 0.5; wait "$pidA"; } 2>/dev/null
  g03_obs $c sigkill_live_generation --str "$killres"
  g03_obs $c socket_after_sigkill --str "$(g03_stat "$EPSOCK")"
  g03_run $c client-on-stale -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c client_on_stale_socket_fails_cleanly "$([ "$G03_RC" -eq 2 ] && echo true || echo false)"
  g03_proxy_start staleNoReplace "$EPSOCK" --upstream-unix "$G03_UP_SOCK" --allow-pub "$G03_SCRATCH/keys/k1.pub"
  g03_crit $c stale_not_replaced_without_flag "$([ "$G03_PX_RC" = 4 ] && echo true || echo false)"
  g03_proxy_start staleB "$EPSOCK" --upstream-unix "$G03_UP_SOCK" --allow-pub "$G03_SCRATCH/keys/k1.pub" --replace-stale
  local pidB="$G03_PX_PID"
  g03_crit $c stale_replaced_with_flag "$([ "$G03_PX_RC" = running ] && echo true || echo false)"
  # Replacement safety: B's path is deleted and taken over by C; B must not unlink C's socket.
  rm -f "$EPSOCK"
  g03_proxy_start staleC "$EPSOCK" --upstream-unix "$G03_UP_SOCK" --allow-pub "$G03_SCRATCH/keys/k1.pub"
  sleep 1.5
  if kill -0 "$pidB" 2>/dev/null; then g03_stop_pid "$pidB" >/dev/null; rc=stopped-by-harness; else wait "$pidB" 2>/dev/null; rc=$?; fi
  g03_obs $c old_generation_exit --str "$rc"
  g03_run $c list-via-replacement -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c old_generation_did_not_remove_replacement "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  g03_finish $c R-EN-03 R-RT-04
}

probe_b_teardown() {
  local c=wsl-b-teardown-deadline dl rc pid
  mechanics_ok || { g03_blocked $c "$NOT_WSL" R-EN-03 R-RT-04 R-AU-05; return; }
  dl=$(( $(g03_epoch) + 6 ))
  b_start_default tear --deadline "$dl"
  pid="$G03_PX_PID"
  g03_run $c before-deadline -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c serves_before_deadline "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  sleep 8
  g03_run $c after-deadline -- "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" list
  g03_crit $c refuses_after_deadline "$(grep -q '"reply_type": 5' "$G03_LAST_OUT" && echo true || echo false)"
  g03_obs $c stop_result --str "$(g03_stop_pid "$pid")"
  sleep 0.5
  g03_obs $c socket_after_stop --str "$(g03_stat "$EPSOCK")"
  g03_crit $c socket_removed_on_stop "$([ ! -e "$EPSOCK" ] && echo true || echo false)"
  g03_run $c upstream-after-stop -- env SSH_AUTH_SOCK="$G03_UP_SOCK" "$LINUX_SSH_ADD" -l
  g03_crit $c upstream_unaffected_by_teardown "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  g03_finish $c R-EN-03 R-RT-04 R-AU-05
}

# ------------------------------------------------------------------ Mode B: Windows relay (attribution)
probe_b_relay() {
  local c=wsl-b-relay-attribution t0 n cnt live
  in_wsl || { g03_blocked $c "$NOT_WSL" R-EN-03 R-SE-03 R-CR-01; return; }
  [ -e /proc/sys/fs/binfmt_misc/WSLInterop ] || { g03_blocked $c "WSL interop enabled in the probe distribution" R-EN-03 R-SE-03 R-CR-01; return; }
  [ -n "$G03_WIN_MANIFEST" ] && [ -f "$G03_WIN_MANIFEST" ] || { g03_blocked $c "$NO_MANIFEST" R-EN-03 R-SE-03 R-CR-01; return; }
  g03_win_init
  PIPE="$(g03_manifest_get pipe_name)"
  G03_WIN_LOG_U="$(wslpath -u "$(g03_manifest_get log_path)")"
  local relay fp1 fp2 pubdir
  relay="$(g03_manifest_get relay_script)"
  fp1="$(g03_manifest_get keys.0.fingerprint)"
  fp2="$(g03_manifest_get keys.1.fingerprint)"
  pubdir="$(wslpath -u "$(g03_manifest_get public_key_dir)")"
  EPDIR="$(g03_b_epdir)"; EPSOCK="$EPDIR/agent.sock"
  local cmd; cmd="$("$PY" -c 'import json,sys; print(json.dumps(["powershell.exe","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",sys.argv[1],"-PipeName",sys.argv[2]]))' "$relay" "$PIPE")"
  t0=$(g03_epoch); sleep 1
  g03_proxy_start relay "$EPSOCK" --upstream-cmd "$cmd" --upstream-cwd /mnt/c --allow-fp "$fp1"
  g03_run $c list-via-relay -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_ADD" -l
  g03_crit $c relay_lists_allowed_key "$(grep -q "$fp1" "$G03_LAST_OUT" && echo true || echo false)"
  printf 'g03 %s\n' "$G03_RUN_ID" > "$G03_SCRATCH/rmsg.txt"
  g03_run $c sign-via-relay -- env SSH_AUTH_SOCK="$EPSOCK" HOME="$G03_HOME" "$LINUX_SSH_KEYGEN" -Y sign -U -f "$pubdir/probe-key-1.pub" -n heimdall-g03 "$G03_SCRATCH/rmsg.txt"
  printf 'probe@heimdall %s\n' "$(cut -d' ' -f1,2 < "$pubdir/probe-key-1.pub")" > "$G03_SCRATCH/rallowed"
  g03_run $c verify-relay-signature -- sh -c '"$0" -Y verify -f "$1" -I probe@heimdall -n heimdall-g03 -s "$2.sig" < "$2"' "$LINUX_SSH_KEYGEN" "$G03_SCRATCH/rallowed" "$G03_SCRATCH/rmsg.txt"
  g03_crit $c relay_signature_verifies "$([ "$G03_RC" -eq 0 ] && echo true || echo false)"
  # The Windows fixture also refuses key 2 (-AllowedKeyIndexes 1), so a type-5 reply alone
  # cannot show the Linux proxy filtered it: also require that the proxy logged the denial
  # and that no SIGN_REQUEST for key 2 reached the Windows agent.
  local t1 rep5 nk2 pxden
  t1=$(g03_epoch); sleep 1
  g03_run $c crafted-sign-filtered -- "$PY" "$HERE/agent_client.py" --socket "$EPSOCK" sign --pub "$pubdir/probe-key-2.pub"
  rep5=false; grep -q '"reply_type": 5' "$G03_LAST_OUT" && rep5=true
  sleep 1
  nk2=$(g03_winlog_since "$t1" event=request msg_type=13 "key_fp=$fp2")
  pxden=$(g03_log_count "$G03_PX_LOG" result=denied_key_not_allowed)
  g03_obs $c filtered_key --json "{\"reply_type_5\": $rep5, \"windows_sign_requests_for_key2\": $nk2, \"proxy_denials\": $pxden}"
  g03_crit $c relay_proxy_refuses_filtered_key "$([ "$rep5" = true ] && [ "$nk2" -eq 0 ] && [ "$pxden" -ge 1 ] && echo true || echo false)"
  [ "$nk2" -ge 0 ] || g03_crit $c relay_proxy_refuses_filtered_key null
  n=$(g03_winlog_since "$t0" event=connect client_image=powershell)
  g03_obs $c windows_agent_connects_attributed_to_powershell --json "$n"
  g03_obs $c windows_agent_connects_total --json "$(g03_winlog_since "$t0" event=connect)"
  g03_crit $c attribution_observed_as_relay_process "$([ "$n" -ge 1 ] && echo true || echo false)"
  local i s e lat=""
  for i in 1 2 3; do s=$(date +%s%N); env SSH_AUTH_SOCK="$EPSOCK" "$LINUX_SSH_ADD" -l >/dev/null 2>&1; e=$(date +%s%N); lat="$lat $(( (e - s) / 1000000 ))"; done
  g03_obs $c relay_list_wall_ms --str "${lat# }"
  # Relay lifetime, measured while the proxy is STILL running. Control: a client that
  # holds its connection open after one request must show >= 1 live relay; after every
  # client has disconnected the count must drop to 0 (per-connection relays).
  "$PY" - "$EPSOCK" >/dev/null 2>&1 <<'PYEOF' &
import socket, struct, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(struct.pack(">I", 1) + b"\x0b")
s.recv(65536)
time.sleep(12)
s.close()
PYEOF
  local holder=$!
  g03_own "$holder" relay-holder
  sleep 5; live="$(g03_win_relay_count "$t0")"
  wait "$holder" 2>/dev/null
  sleep 7; cnt="$(g03_win_relay_count "$t0")"
  g03_obs $c relay_processes --json "{\"while_connection_held\": \"${live:-unknown}\", \"after_all_clients_disconnected_proxy_running\": \"${cnt:-unknown}\"}"
  g03_crit $c relay_counter_control_sees_held_connection "$([ "${live:-0}" -ge 1 ] 2>/dev/null && echo true || echo false)"
  g03_crit $c relay_processes_exit_with_connections "$([ "${cnt:-99}" = 0 ] && echo true || echo false)"
  if [ "${live:-0}" -lt 1 ] 2>/dev/null || [ -z "$live" ]; then
    g03_crit $c relay_counter_control_sees_held_connection null; g03_crit $c relay_processes_exit_with_connections null
  fi
  g03_stop_pid "$G03_PX_PID" >/dev/null
  sleep 2; g03_obs $c relay_processes_after_proxy_stop --str "$(g03_win_relay_count "$t0")"
  g03_limit $c "The Windows endpoint authenticates the relay (powershell.exe running as the Windows user), not the Linux caller; a provider that authorizes per application would attribute every WSL request to the relay."
  g03_limit $c "Relay processes are counted by Win32_Process command lines containing the relay script name, filtered inside PowerShell (only a count is emitted), started at or after the probe start."
  g03_finish $c R-EN-03 R-SE-03 R-CR-01
}

# ------------------------------------------------------------------ Mode B: host lock (manual window)
probe_b_lock() {
  local c=wsl-b-host-lock
  in_wsl || { g03_blocked $c "$NOT_WSL" R-EN-03 R-QU-02; return; }
  [ "$LOCK_MINUTES" -gt 0 ] 2>/dev/null || { g03_blocked $c "an operator present to lock and unlock the Windows session during --lock-window-minutes N" R-EN-03 R-QU-02; return; }
  b_start_default lock
  local pid="$G03_PX_PID" end rows lu rc
  rows="$G03_OUT/artifacts/$(g03_cid $c)/timeline.jsonl"
  mkdir -p "$(dirname "$rows")"
  end=$(( $(g03_epoch) + LOCK_MINUTES * 60 ))
  g03_log "Host-lock window open for $LOCK_MINUTES min: lock Windows (Win+L) for at least 2 minutes, then unlock."
  while [ "$(g03_epoch)" -lt "$end" ]; do
    env SSH_AUTH_SOCK="$EPSOCK" "$LINUX_SSH_ADD" -l >/dev/null 2>&1; rc=$?
    lu="$(g03_win tasklist.exe /FI "IMAGENAME eq LogonUI.exe" /NH 2>/dev/null | grep -ci logonui)"
    printf '{"ts": "%s", "list_exit": %s, "logonui_running": %s, "proxy_alive": %s}\n' "$(g03_now)" "$rc" "$([ "${lu:-0}" -gt 0 ] && echo true || echo false)" "$(kill -0 "$pid" 2>/dev/null && echo true || echo false)" >> "$rows"
    sleep 20
  done
  printf '%s\n' "$rows" >> "$(g03_case_file $c evidence)"
  g03_crit $c lock_observed_via_logonui "$(grep -q '"logonui_running": true' "$rows" && echo true || echo null)"
  g03_crit $c bridge_process_survived_window "$(kill -0 "$pid" 2>/dev/null && echo true || echo false)"
  env SSH_AUTH_SOCK="$EPSOCK" "$LINUX_SSH_ADD" -l >/dev/null 2>&1; rc=$?
  g03_crit $c request_after_unlock_succeeds "$([ "$rc" -eq 0 ] && echo true || echo false)"
  g03_obs $c requests_failed_while_locked --json "$(grep '"logonui_running": true' "$rows" | grep -vc '"list_exit": 0')"
  g03_limit $c "Lock detection uses LogonUI.exe presence as a heuristic (inference). The upstream here is a Linux fixture agent; provider lock semantics (1Password, Windows agent) need the relay variant and the G04 managed recipe."
  g03_finish $c R-EN-03 R-QU-02
}

# ------------------------------------------------------------------ main
want env && probe_env
want a-exec && probe_a_exec
want a-io && probe_a_io
want a-quoting && probe_a_quoting
want a-git && probe_a_git
want a-cert && probe_a_cert
want a-elevation && probe_a_elevation
want b-perms && probe_b_perms
want b-unauthorized && probe_b_unauthorized
want b-relay && probe_b_relay
want b-deletion && probe_b_deletion
want b-stale && probe_b_stale
want b-teardown && probe_b_teardown
want b-lock && probe_b_lock

# Preserve proxy logs (fingerprints, peer UIDs/PIDs, decisions; no secrets).
mkdir -p "$G03_OUT/artifacts/proxy-logs"
for f in "$G03_SCRATCH"/proxy-*.log; do [ -f "$f" ] && cp "$f" "$G03_OUT/artifacts/proxy-logs/"; done

g03_redact_out
if g03_canary_scan; then
  g03_log "records: $G03_OUT/records"
  exit 0
fi
exit 9
