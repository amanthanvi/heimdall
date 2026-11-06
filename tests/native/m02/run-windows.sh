#!/usr/bin/env bash
# M02-U11 (m02-plan §4): cross-build every workspace test binary, heimdall.exe and
# hm-fixture-hook.exe for x86_64-pc-windows-gnu on the build host, run them natively on
# the owner's Windows 11 PC (non-elevated user, through WSL interop) and save redacted
# output. Generalized from tests/native/m01/run-windows.sh.
#
# Usage: tests/native/m02/run-windows.sh <artifact-dir>
#   HM_SSH_CONFIG  ssh config for the Windows host's WSL (required unless HM_BUILD_ONLY=1)
#   HM_HOST        ssh host alias in that config (required unless HM_BUILD_ONLY=1)
#   HM_TASK        scratch directory name prefix (default: M02-U11); the run uses
#                  <HM_TASK>-<16 random hex digits>
#   HM_ONLY        optional space-separated list of test target names to run (default: all)
#   HM_BUILD_ONLY  1 = cross-build, plan and record the binaries' hashes, then stop (no ssh)
#   HM_TIMEOUT_S   per-binary timeout in seconds (default 1800)
#   HM_LAUNCH_DRIVER 0 = skip the pseudoconsole drivers (default 1: run them)
#
# Scratch (review B01; helpers in tests/native/windows-ipc/scratch-lib.sh): one remote
# step creates ~/hm-m00/<run> (WSL) and %LOCALAPPDATA%\hm-m00\<run> (Windows)
# exclusively; only the exact paths it reports are removed at the end, pass or fail.
# TEMP/TMP point inside the Windows directory.
#
# On the host, in this order:
#   * inherited agent, Git and Heimdall variables are unset; the integrity level, the
#     Windows version, `ssh -V` of the in-box client (System32) and of the PATH-first
#     client, `sshd -V` (the WSL fixture server; the in-box server's presence only),
#     `git --version` (Windows and WSL; scratch HOME, GIT_CONFIG_NOSYSTEM=1), whether
#     Developer Mode is on (read only, B10), the heimdall-hmtest- pipe count,
#     %LOCALAPPDATA%\heimdall existence, and a metadata digest of %USERPROFILE%\.ssh and
#     %USERPROFILE%\.gitconfig (never their names or contents) are recorded;
#   * the fixture sshd starts **in WSL scratch** (non-root, 127.0.0.1 only, per-run host
#     key; G03 §0.1) with its authorized-keys file and log in the Windows scratch. NAT
#     localhost forwarding is checked from Windows first (a TcpClient reads the SSH
#     banner); when it fails on three ports the failure is recorded and the tests run
#     without the HM_FIXTURE_SSHD_* variables. Otherwise HM_FIXTURE_SSHD_{HOST,PORT,
#     HOST_KEY,AUTHORIZED_KEYS,LOG} reach the Windows tests through WSLENV (ADR-0007
#     §12.15 item 6). Whether the WSL account name equals the Windows one is recorded (a
#     non-root sshd authenticates only its own account);
#   * every binary runs through `cmd.exe /d /c` with %SystemRoot%\System32\OpenSSH put
#     first on that process's PATH (the in-box client is the E6 baseline; the PATH-first
#     client is recorded as a candidate, not selected; HM_WINDOWS_SSH=path keeps the
#     inherited PATH), under `timeout` and `nice -n 10` on the WSL side (`nice` there lowers
#     only the interop relay's priority, never the Windows process's, which is unchanged),
#     its real exit code recorded; every binary gets `--show-output` (the `observation` lines of passing tests,
#     the settled ADR-0007 facts); HEIMDALL_E2E_BIN and HM_FIXTURE_HOOK name the copied
#     binaries;
#   * the pseudoconsole drivers of tests/native/windows-launch (Ctrl-C and resize through
#     `heimdall run`, with argvdump.exe cross-built by Go) run with -ExecutionPolicy Bypass
#     for that process only; their report rows become "### windows_launch" test lines;
#   * afterwards: leftover test processes and heimdall-hmtest- pipes are counted (never
#     signalled by name), the sshd is stopped by exact PID, the digests are taken again.
#
# Nothing is elevated; no service, registry value, firewall rule, ssh-agent state or
# ~/.ssh is changed; `\\.\pipe\openssh-ssh-agent` is never opened; no `wsl --shutdown`.
# The Windows DACL, file-ID and Git-name-transition observations of A22 are made by the
# tests in-process; this harness does not read ACLs itself.
#
# No CARGO_TARGET_DIR override (AGENTS.md). Output (redacted: <winuser>, <winhost>,
# <winhome>, <wsluser>, <wslhome>, <wslhost>, S-1-5-21-<redacted>, the build host's
# <home>/<user>): build.txt, host.txt, tests.txt, commands.txt, skipped.txt,
# canary-scan.txt. Exit: nonzero when a binary or a required step fails, or a canary or
# a leak is found. Self-test without any host: tools/validation/native-harness-selftest.sh.

set -euo pipefail

out=${1:?usage: run-windows.sh <artifact-dir>}
build_only=${HM_BUILD_ONLY:-0}
if [ "$build_only" != 1 ]; then
    ssh_config=${HM_SSH_CONFIG:?set HM_SSH_CONFIG to the ssh config for the Windows test host}
    host=${HM_HOST:?set HM_HOST to the host alias in HM_SSH_CONFIG}
fi
triple=x86_64-pc-windows-gnu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/lib.sh"
slib="$repo/tests/native/windows-ipc/scratch-lib.sh"
rlib="$here/remote-lib.sh"
# shellcheck source=tests/native/windows-ipc/scratch-lib.sh
. "$slib"
task=${HM_TASK:-M02-U11}
hm_valid_name "$task" || { echo "bad HM_TASK" >&2; exit 2; }
timeout_s=${HM_TIMEOUT_S:-1800}
case "$timeout_s" in '' | *[!0-9]*) echo "bad HM_TIMEOUT_S" >&2; exit 2 ;; esac
launch=${HM_LAUNCH_DRIVER:-1}
winssh=${HM_WINDOWS_SSH:-inbox}
case "$winssh" in inbox | path) ;; *) echo "bad HM_WINDOWS_SSH (inbox or path)" >&2; exit 2 ;; esac
# Unique per run: concurrent or earlier runs never share a directory.
run="$task-$(m02_random_hex 8)"
hm_valid_name "$run" || { echo "cannot make a run name" >&2; exit 2; }

mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR

# Run a remote script (stdin) after scratch-lib.sh, remote-lib.sh and the given shell
# assignments (built with printf %q, sent on stdin, never on the command line); the
# remaining arguments are the script's.
remote() {
    local prelude=$1
    shift
    { cat "$slib" "$rlib"; printf '%s\n' "$prelude"; cat; } |
        ssh -F "$ssh_config" -o BatchMode=yes "$host" bash -s -- "$@"
}

shim=$(mktemp -d)
commands="$out/commands.txt"
: >"$commands"
# Exact directories the create step reported; only these are ever removed.
wsl_dir=""
win_dir=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    if [ -n "$wsl_dir$win_dir" ]; then
        set +e
        remote "$(printf 'wsl_dir=%q; win_dir=%q' "$wsl_dir" "$win_dir")" "$run" >"$shim/cleanup.txt" 2>&1 <<'REMOTE'
main() {
set -u
run=$1
cd /mnt/c || return 1
# A fixture sshd left by an interrupted session: only the recorded process, matched by
# its start time and scratch configuration path.
[ -n "$wsl_dir" ] && echo "fixture-sshd-at-cleanup=$(hm2_stop_recorded "$wsl_dir/sshd")"
rc=0
hm_scratch_remove "$win_dir" "$run" || rc=1
hm_scratch_remove "$wsl_dir" "$run" || rc=1
[ -z "$win_dir" ] || [ ! -e "$win_dir" ] || rc=1
[ -z "$wsl_dir" ] || [ ! -e "$wsl_dir" ] || rc=1
return "$rc"
}
main "$@" </dev/null
REMOTE
        m02_record "$commands" "remote: remove exactly the run directories (both sides), then check they are absent" "$?"
        sed -n 's/^fixture-sshd-at-cleanup=/fixture sshd at cleanup: /p' "$shim/cleanup.txt" >>"$commands"
    fi
    rm -rf "$shim"
    exit "$rc"
}
trap cleanup EXIT

m02_write_shims "$shim"
cd "$repo"
set +e
m02_cargo_build "$triple" "$shim" "$out/build.txt"
rc=$?
set -e
m02_record "$commands" "cargo test --target $triple --workspace --no-run --locked (zig linker/CC shims)" "$rc"
redact_build_log() { m02_redact "$out/build.txt" "$out/build.txt" "$shim" "<shim>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" "$(id -un)" "<user>"; }
[ "$rc" = 0 ] || { redact_build_log; exit "$rc"; }
m02_artifacts "$shim" || { echo "heimdall.exe or hm-fixture-hook.exe was not built" >&2; redact_build_log; exit 5; }
set +e
m02_plan "$here" windows "$shim" "$out"
rc=$?
set -e
m02_record "$commands" "run plan from case-index.json build_host_paths" "$rc"
[ "$rc" = 0 ] || exit "$rc"
if [ -n "${HM_ONLY:-}" ]; then
    awk -F'\t' -v only=" ${HM_ONLY} " 'index(only, " " $1 " ") { print; next } { print $1 ": not selected (HM_ONLY)" > "/dev/stderr" }' \
        "$shim/run.tsv" >"$shim/run.only" 2>>"$out/skipped.txt"
    mv "$shim/run.only" "$shim/run.tsv"
fi
m02_hashes "$shim" "$out" ".exe"
if [ "$launch" = 1 ]; then
    set +e
    (cd "$repo/tests/native/windows-g02/argvdump" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOFLAGS=-trimpath \
        go build -o "$shim/argvdump.exe" .) >>"$out/build.txt" 2>&1
    rc=$?
    set -e
    m02_record "$commands" "go build argvdump.exe (GOOS=windows GOARCH=amd64, -trimpath) for the pseudoconsole drivers" "$rc"
    [ "$rc" = 0 ] || { redact_build_log; exit "$rc"; }
    echo "argvdump.exe sha256: $(shasum -a 256 "$shim/argvdump.exe" | cut -d' ' -f1)" >>"$out/build.txt"
else
    echo "windows_launch: not run (HM_LAUNCH_DRIVER=0)" >>"$out/skipped.txt"
fi
echo "toolchain: $(rustc --version); zig $(zig version); target $triple" >>"$out/build.txt"
if [ "$build_only" = 1 ]; then
    redact_build_log
    echo "test binaries planned: $(wc -l <"$shim/run.tsv" | tr -d ' '); skipped entries: $(wc -l <"$out/skipped.txt" | tr -d ' ')"
    exit 0
fi

# Create both run directories exclusively; keep the exact paths reported.
set +e
remote "" "$run" >"$shim/created.txt" <<'REMOTE'
main() {
set -u
run=$1
cd /mnt/c || return 1
d=$(hm_scratch_create "$HOME" "$run") || return 1
echo "created-wsl=$d"
w=$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" | tr -d '\r')
[ -n "$w" ] || { echo "LOCALAPPDATA unavailable" >&2; return 1; }
d=$(hm_scratch_create "$(wslpath "$w")" "$run") || return 1
echo "created-win=$d"
mkdir -- "$d/tmp" "$d/sshd" || return 1
}
main "$@" </dev/null
REMOTE
crc=$?
set -e
wsl_dir=$(sed -n 's/^created-wsl=//p' "$shim/created.txt" | head -1)
win_dir=$(sed -n 's/^created-win=//p' "$shim/created.txt" | head -1)
m02_record "$commands" "remote: create the run directories exclusively (run $run)" "$crc"
[ "$crc" = 0 ] && [ -n "$wsl_dir" ] && [ -n "$win_dir" ] || exit 1

m02_stage "$shim" ".exe"
if [ "$launch" = 1 ]; then
    mkdir -p "$shim/stage/launch/windows-launch" "$shim/stage/launch/windows-g02"
    cp "$shim/argvdump.exe" "$shim/stage/argvdump.exe"
    cp "$repo/tests/native/windows-launch/Invoke-WindowsLaunch.ps1" "$shim/stage/launch/windows-launch/"
    cp "$repo/tests/native/windows-g02/G02X1Native.cs" "$repo/tests/native/windows-g02/Send-ConsoleCtrl.ps1" \
        "$shim/stage/launch/windows-g02/"
fi
set +e
tar -C "$shim/stage" -chf - . | gzip -1 |
    ssh -F "$ssh_config" -o BatchMode=yes "$host" "tar -xzf - -C \"\$HOME/hm-m00/$run\""
rc=$?
set -e
m02_record "$commands" "tar stream of $(wc -l <"$shim/run.tsv" | tr -d ' ') test binaries, heimdall.exe and hm-fixture-hook.exe into WSL scratch" "$rc"
[ "$rc" = 0 ] || exit 1
names=$(cut -f1 "$shim/run.tsv" | tr '\n' ' ')

set +e
# shellcheck disable=SC2086  # names are [A-Za-z0-9_-] target names
remote "$(printf 'wsl_dir=%q; win_dir=%q; timeout_s=%q; launch=%q; winssh=%q' "$wsl_dir" "$win_dir" "$timeout_s" "$launch" "$winssh")" \
    $names >"$shim/remote.txt" 2>&1 <<'REMOTE'
W=/mnt/c/Windows/System32
ps1() {
    # One PowerShell command, passed base64/UTF-16LE encoded so no quoting crosses WSL
    # interop; prints its output without carriage returns.
    local enc
    enc=$(printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)
    "$W/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -NonInteractive -EncodedCommand "$enc" 2>/dev/null | tr -d '\r'
}
winline() {
    # A command line for `cmd.exe /d /c`, with the in-box OpenSSH first on PATH
    # (winssh=inbox). Callers pass fixed text and [A-Za-z0-9_:.-] names only.
    if [ "$winssh" = inbox ]; then
        printf '%s' "set PATH=%SystemRoot%\\System32\\OpenSSH;%PATH%&& $1"
    else
        printf '%s' "$1"
    fi
}
test_pipes() {
    ps1 '@([System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*\heimdall-hmtest-*" }).Count'
}
banner() {
    # The first 8 bytes the WSL fixture sshd sends to a Windows TcpClient (NAT localhost
    # forwarding); the port is a number, so the command carries no other input.
    ps1 "\$c = New-Object System.Net.Sockets.TcpClient; \$c.ReceiveTimeout = 5000; try { \$c.Connect('127.0.0.1', $1); \$b = New-Object byte[] 8; \$n = \$c.GetStream().Read(\$b, 0, 8); [Text.Encoding]::ASCII.GetString(\$b, 0, \$n) } catch { 'unreachable' } finally { \$c.Close() }"
}
main() {
set -u
bins=$*
cd /mnt/c || return 1
hm2_sanitize_env
w=$("$W/cmd.exe" /c "echo %LOCALAPPDATA%" | tr -d '\r')
[ -n "$w" ] || { echo "LOCALAPPDATA unavailable"; return 1; }
wroot=$(wslpath "$w")
winprofile=$(wslpath "$("$W/cmd.exe" /c 'echo %USERPROFILE%' | tr -d '\r')")
heimdall_before=$([ -e "$wroot/heimdall" ] && echo present || echo absent)
wl=$win_dir
cp "$wsl_dir/"*.exe "$wl/" || return 1
[ "$launch" = 1 ] && { cp -R "$wsl_dir/launch" "$wl/launch" || return 1; }
cd "$wl" || return 1
TEMP=$(wslpath -w "$wl/tmp"); TMP=$TEMP
HEIMDALL_E2E_BIN=$(wslpath -w "$wl/heimdall.exe")
HM_FIXTURE_HOOK=$(wslpath -w "$wl/hm-fixture-hook.exe")
WSLENV=TEMP/w:TMP/w:HEIMDALL_E2E_BIN/w:HM_FIXTURE_HOOK/w
export TEMP TMP HEIMDALL_E2E_BIN HM_FIXTURE_HOOK WSLENV
echo "integrity=$("$W/whoami.exe" /groups | grep -o 'Medium Mandatory Level\|High Mandatory Level\|System Mandatory Level' | head -1)"
echo "os=$("$W/cmd.exe" /c ver | tr -d '\r' | grep -v '^$')"
echo "ssh-V-inbox=$(hm2_first_line "$W/OpenSSH/ssh.exe" -V)"
echo "ssh-V-path-first=$("$W/cmd.exe" /d /c 'ssh -V' 2>&1 | tr -d '\r' | head -1) (candidate, not selected)"
echo "ssh-V-tests=$("$W/cmd.exe" /d /c "$(winline 'ssh -V')" 2>&1 | tr -d '\r' | head -1) (what the tests resolve, HM_WINDOWS_SSH=$winssh)"
echo "sshd-inbox-server=$([ -e "$W/OpenSSH/sshd.exe" ] && echo present || echo absent) (not started)"
mkdir -p "$wl/tmp/githome"
echo "git-version-windows=$("$W/cmd.exe" /c "set HOME=$(wslpath -w "$wl/tmp/githome")&& set GIT_CONFIG_NOSYSTEM=1&& git --version" 2>&1 | tr -d '\r' | head -1)"
echo "git-version-wsl=$(HOME="$wsl_dir" GIT_CONFIG_NOSYSTEM=1 hm2_first_line git --version)"
dev=$("$W/reg.exe" query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' /v AllowDevelopmentWithoutDevLicense 2>/dev/null | tr -d '\r' | awk '/AllowDevelopmentWithoutDevLicense/ { print $NF }')
case "$dev" in 0x1) dev=on ;; 0x0) dev=off ;; *) dev=unknown ;; esac
echo "developer-mode=$dev (read only)"
echo "localappdata-heimdall-before=$heimdall_before"
echo "test-pipes-before=$(test_pipes)"
echo "owner-ssh-before=$(hm2_owner_digest "$winprofile/.ssh")"
echo "owner-git-before=$(hm2_owner_digest "$winprofile/.gitconfig")"
# The fixture sshd in WSL scratch; its keys file and log in the Windows scratch.
sshd_ok=0
for try in 1 2 3; do
    rm -rf -- "$wsl_dir/sshd"
    if ! hm2_sshd_start "$wsl_dir/sshd" "$wl/sshd/authorized_keys" "$wl/sshd/sshd.log"; then
        echo "fixture-sshd=unavailable: $HM2_SSHD_WHY"
        break
    fi
    trap 'hm2_sshd_stop' EXIT HUP INT TERM
    b=$(banner "$HM2_SSHD_PORT")
    case "$b" in
        SSH-2.0-*) sshd_ok=1; break ;;
    esac
    echo "fixture-sshd-forwarding-try-$try=unreachable from Windows"
    hm2_sshd_stop
done
if [ "$sshd_ok" = 1 ]; then
    echo "fixture-sshd=listening on 127.0.0.1 in WSL scratch (non-root, per-run host key)"
    echo "fixture-sshd-V=$(hm2_first_line "$(hm2_sshd_bin)" -V)"
    echo "fixture-sshd-from-windows=reachable (NAT localhost forwarding, SSH banner read)"
    wu=$("$W/cmd.exe" /c 'echo %USERNAME%' | tr -d '\r')
    if [ "$(printf '%s' "$wu" | tr '[:upper:]' '[:lower:]')" = "$(id -un | tr '[:upper:]' '[:lower:]')" ]; then
        echo "fixture-sshd-account=same name as the Windows user"
    else
        echo "fixture-sshd-account=differs from the Windows user (a non-root sshd authenticates only its own account)"
    fi
    HM_FIXTURE_SSHD_HOST=127.0.0.1
    HM_FIXTURE_SSHD_PORT=$HM2_SSHD_PORT
    HM_FIXTURE_SSHD_HOST_KEY=$HM2_SSHD_HOSTKEY
    HM_FIXTURE_SSHD_AUTHORIZED_KEYS=$(wslpath -w "$wl/sshd/authorized_keys")
    HM_FIXTURE_SSHD_LOG=$(wslpath -w "$wl/sshd/sshd.log")
    WSLENV=$WSLENV:HM_FIXTURE_SSHD_HOST/w:HM_FIXTURE_SSHD_PORT/w:HM_FIXTURE_SSHD_HOST_KEY/w:HM_FIXTURE_SSHD_AUTHORIZED_KEYS/w:HM_FIXTURE_SSHD_LOG/w
    export HM_FIXTURE_SSHD_HOST HM_FIXTURE_SSHD_PORT HM_FIXTURE_SSHD_HOST_KEY \
        HM_FIXTURE_SSHD_AUTHORIZED_KEYS HM_FIXTURE_SSHD_LOG WSLENV
else
    echo "fixture-sshd-harness=failed: the tests run without HM_FIXTURE_SSHD_* (recorded as a harness failure)"
fi
echo "---tests---"
arc=0
for b in $bins; do
    set --
    while IFS="$(printf '\t')" read -r t n; do
        [ "$t" = "$b" ] && set -- "$@" --skip "$n"
    done <"$wsl_dir/skips.tsv"
    [ $# -gt 0 ] && set -- --exact "$@"
    # --show-output keeps the `observation` lines of passing tests (the settled [I]/[U] facts).
    set -- "$@" --show-output
    echo "### $b"
    timeout "$timeout_s" nice -n 10 "$W/cmd.exe" /d /c "$(winline ".\\$b.exe $*")" 2>&1
    brc=$?
    echo "### $b exit=$brc"
    [ "$brc" = 0 ] || arc=$brc
done
if [ "$launch" = 1 ]; then
    echo "### windows_launch"
    timeout 600 "$W/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$(wslpath -w "$wl/launch/windows-launch/Invoke-WindowsLaunch.ps1")" \
        -Heimdall "$(wslpath -w "$wl/heimdall.exe")" -ArgvDump "$(wslpath -w "$wl/argvdump.exe")" \
        -Out "$(wslpath -w "$wl/tmp/windows-launch-report.json")" >"$wsl_dir/launch.out" 2>&1
    lrc=$?
    if [ -f "$wl/tmp/windows-launch-report.json" ] && command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8-sig"))
rows = r.get("rows") or []
rows = rows if isinstance(rows, list) else [rows]
for row in rows:
    print("test %s ... %s" % (row.get("id"), "ok" if row.get("verdict") == "pass" else "FAILED"))
    print("  observed: %s" % json.dumps(row.get("observed"), sort_keys=True))' "$wl/tmp/windows-launch-report.json"
    else
        echo "windows_launch: no report (exit $lrc)"
    fi
    echo "### windows_launch exit=$lrc"
    [ "$lrc" = 0 ] || arc=$lrc
fi
echo "all-tests-exit=$arc"
echo "---after---"
hm2_sshd_stop
trap - EXIT HUP INT TERM
echo "fixture-sshd-stopped=yes"
leftover=0
for b in $bins heimdall hm-fixture-hook argvdump; do
    n=$("$W/tasklist.exe" /NH /FI "IMAGENAME eq $b.exe" | tr -d '\r' | grep -c -i "^$b\.exe" || true)
    leftover=$((leftover + n))
done
echo "leftover-test-processes=$leftover"
echo "test-pipes-after=$(test_pipes)"
echo "localappdata-heimdall-after=$([ -e "$wroot/heimdall" ] && echo present || echo absent)"
echo "owner-ssh-after=$(hm2_owner_digest "$winprofile/.ssh")"
echo "owner-git-after=$(hm2_owner_digest "$winprofile/.gitconfig")"
echo "---redaction---"
echo "winuser=$("$W/cmd.exe" /c 'echo %USERNAME%' | tr -d '\r')"
echo "winhost=$("$W/cmd.exe" /c 'echo %COMPUTERNAME%' | tr -d '\r')"
echo "winhome=$("$W/cmd.exe" /c 'echo %USERPROFILE%' | tr -d '\r')"
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
return "$arc"
}
main "$@" </dev/null
REMOTE
rc=$?
set -e
arc=$(sed -n '/^---redaction---$/q;s/^all-tests-exit=//p' "$shim/remote.txt" | tail -1)
m02_record "$commands" "remote: every test binary and the pseudoconsole drivers as the non-elevated user (overall exit = last failing binary's exit, 0 if all passed)" "$rc"
grep -q '^fixture-sshd=listening' "$shim/remote.txt" && fx=0 || fx=1
m02_record "$commands" "fixture sshd in WSL scratch reachable from Windows (NAT localhost forwarding)" "$fx"

red=$(sed -n '/^---redaction---$/,$p' "$shim/remote.txt")
val() { printf '%s\n' "$red" | sed -n "s/^$1=//p" | head -1; }
winuser=$(val winuser); winhost=$(val winhost); winhome=$(val winhome)
wsluser=$(val wsluser); wslhome=$(val wslhome); wslhost=$(val wslhost)
sed '/^---redaction---$/,$d' "$shim/remote.txt" >"$shim/remote.body"
m02_redact "$shim/remote.body" "$shim/redacted.txt" "$winhome" "<winhome>" "$wslhome" "<wslhome>" "$HOME" "<home>" \
    "$winuser" "<winuser>" "$winhost" "<winhost>" "$host" "<winhost>" "$wsluser" "<wsluser>" \
    "$wslhost" "<wslhost>" "$(id -un)" "<user>"
sed -n '1,/^---tests---$/p' "$shim/redacted.txt" | sed '$d' >"$out/host.txt"
sed -n '/^---after---$/,$p' "$shim/redacted.txt" | sed '1d' >>"$out/host.txt"
sed -n '/^---tests---$/,/^---after---$/p' "$shim/redacted.txt" | sed '1d;$d' >"$out/tests.txt"
redact_build_log

before=$(sed -n 's/^owner-ssh-before=//p;s/^owner-git-before=//p' "$out/host.txt" | tr '\n' ' ')
after=$(sed -n 's/^owner-ssh-after=//p;s/^owner-git-after=//p' "$out/host.txt" | tr '\n' ' ')
same=1
[ -n "$before" ] && [ "$before" = "$after" ] || same=0
m02_record "$commands" "%USERPROFILE%\\.ssh and .gitconfig metadata unchanged by the run" "$([ "$same" = 1 ] && echo 0 || echo 1)"
hits=$(m02_canary_scan "$out")
m02_record "$commands" "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
set +e
leaks=$(m02_leak_scan "$out" "$winhome" "$wslhome" "$HOME" "$winuser" "$winhost" "$host" "$wsluser" "$wslhost" "$(id -un)")
lrc=$?
set -e
m02_record "$commands" "leak scan: saved files still naming a host, a user or a home ($leaks)" "$lrc"
cat "$out/host.txt"
grep -E '^### |^test result' "$out/tests.txt" || true
[ "$hits" = 0 ] && [ "$lrc" = 0 ] && [ "$same" = 1 ] || exit 1
[ "$rc" = 0 ] || exit "$rc"
# Belt and braces: a missing or nonzero overall test exit is a failure too.
[ "${arc:-x}" = 0 ] || exit 1
exit 0
