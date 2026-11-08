#!/usr/bin/env bash
# M02-U11 (m02-plan §4): ordinary ssh without -F in a disposable WSL distribution
# (ADR-0004 §3, P-B08/09/10 pattern; ADR-0007 §9 item 5). From the build host, through
# the owner's own ssh config into the owner's WSL distribution (the controller), then WSL
# interop:
#   1. cross-build the Linux heimdall binary (the same `cargo test --no-run` build as
#      run-linux.sh, so its sha256 matches that run's);
#   2. create the run directories exclusively (~/hm-m00/<run> in the controller and
#      %LOCALAPPDATA%\hm-m00\<run> on Windows; tests/native/windows-ipc/scratch-lib.sh);
#   3. use the pinned image, `ubuntu-24.04.5-wsl-amd64.wsl` (sha256 below, the value G03
#      checked against Ubuntu's signed SHA256SUMS): HM_WSL_ROOTFS names an existing copy on
#      the Windows host, or HM_WSL_DOWNLOAD=1 downloads it over https into the Windows run
#      directory. Any other file, or a digest mismatch, stops the run before an import;
#   4. `wsl --import hm-m02-<random>` into the Windows run directory (a name no
#      registered distribution has), `[boot] systemd=false` and a `wsl --terminate` so no
#      service of the image ever starts, then target-root.sh as root inside it (missing
#      OpenSSH or Git tools stop the run, exit 3, unless HM_WSL_ALLOW_APT=1 installs them
#      from the image's archive with every service blocked first), a non-root user with a
#      disposable home, and the heimdall binary;
#   5. scenario-ordinary-ssh.sh as that user: setup apply writes the user's real
#      ~/.ssh/config, then ordinary `ssh`, `git`, `scp` and `sftp` without -F, then
#      `uninstall`;
#   6. `wsl --terminate` and `wsl --unregister` of that distribution only (never
#      `wsl --shutdown`, never another distribution), and the registered set is compared
#      with the one before (names never printed); the run directories are removed exactly.
# An interrupted run is cleaned up by the EXIT trap: the recorded distribution (its name
# re-checked against the pattern and the before-list) is unregistered, then the
# directories are removed.
#
# Local mode (HM_LOCAL=1; ADR-0007 §12.32 item 15, the WSL counterpart of run-windows-local.ps1):
# the ssh route into the controller no longer exists, so a local agent on the PC runs this
# script INSIDE the controller distribution, e.g.
#   wsl.exe -e bash <clone>/tests/native/m02/run-wsl-distro.sh <artifact-dir>
# Every step above is the same script body, run by a local `bash -s` (same arguments, stdin and
# exit-code handling) instead of through ssh, and the tar stream is a local extraction into the
# same scratch directory; there is no ssh, scp or host alias, and HM_SSH_CONFIG and HM_HOST are
# neither required nor read. Nothing is built: the Linux heimdall binary is cross-built on the
# build host (HM_BUILD_ONLY=1 there prints `prebuilt-heimdall=<path>` and `prebuilt-sha256=<hex>`
# on stdout) and copied to the PC. HM_PREBUILT_HEIMDALL names the copy and HM_PREBUILT_SHA256 is the
# digest the build host recorded; the run refuses before anything is created when either is
# missing or the file is not a regular file (exit 3), when the digest is not 64 hex digits (exit
# 2) or when the file's sha256 differs (exit 1). The verified digest is recorded in build.txt as
# on the build path, and the staged copy is hashed again before it is shipped. Every safety
# property is unchanged: exclusive run directories, the pinned image and its digest before any
# import, the distribution-name pattern, the registered-set comparison, terminate and unregister
# of that distribution only, the EXIT trap, redaction and the canary and leak scans.
#
# Usage: tests/native/m02/run-wsl-distro.sh <artifact-dir>
#   HM_SSH_CONFIG, HM_HOST  as for run-windows.sh (required unless HM_BUILD_ONLY=1 or HM_LOCAL=1)
#   HM_TASK                 scratch directory prefix (default M02-U11-wsl)
#   HM_WSL_ROOTFS           the pinned image already on the Windows host (C:\... or /mnt/c/...)
#   HM_WSL_DOWNLOAD         1 = download the pinned image into the run directory
#   HM_WSL_ALLOW_APT        1 = install missing OpenSSH/Git tools inside the disposable distribution
#   HM_BUILD_ONLY           1 = cross-build and record the binary's hash, then stop (no ssh); prints
#                           prebuilt-heimdall=<path> and prebuilt-sha256=<hex> on stdout
#   HM_LOCAL                1 = local mode (above); not combinable with HM_BUILD_ONLY
#   HM_PREBUILT_HEIMDALL    local mode: the Linux heimdall binary cross-built on the build host
#   HM_PREBUILT_SHA256      local mode: the 64-hex sha256 the build host recorded for it
#
# Nothing is elevated; no Windows service, firewall rule, ssh-agent state or the
# owner's ~/.ssh is touched (the WSL import's own registration is removed by the
# unregister). Output (redacted as run-windows.sh, plus the controller distribution's
# name): build.txt, host.txt, tests.txt, commands.txt, canary-scan.txt. Exit: nonzero
# when a step fails, 3 when an input is missing (the image, tools without
# HM_WSL_ALLOW_APT, or in local mode the prebuilt binary or its digest), or a canary or leak
# is found.

set -euo pipefail

ROOTFS_URL=https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl
ROOTFS_SHA256=bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e

out=${1:?usage: run-wsl-distro.sh <artifact-dir>}
build_only=${HM_BUILD_ONLY:-0}
local_mode=${HM_LOCAL:-0}
case "$local_mode" in 0 | 1) ;; *) echo "bad HM_LOCAL (0 or 1)" >&2; exit 2 ;; esac
if [ "$local_mode" = 1 ] && [ "$build_only" = 1 ]; then
    echo "HM_LOCAL=1 builds nothing: HM_BUILD_ONLY=1 belongs on the build host" >&2
    exit 2
fi
# Local mode never reads HM_SSH_CONFIG or HM_HOST (no ssh); both stay empty.
ssh_config=""
host=""
if [ "$build_only" != 1 ] && [ "$local_mode" != 1 ]; then
    ssh_config=${HM_SSH_CONFIG:?set HM_SSH_CONFIG to the ssh config for the Windows test host}
    host=${HM_HOST:?set HM_HOST to the host alias in HM_SSH_CONFIG}
fi
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/lib.sh"
slib="$repo/tests/native/windows-ipc/scratch-lib.sh"
rlib="$here/remote-lib.sh"
# shellcheck source=tests/native/windows-ipc/scratch-lib.sh
. "$slib"
task=${HM_TASK:-M02-U11-wsl}
hm_valid_name "$task" || { echo "bad HM_TASK" >&2; exit 2; }
rid=$(m02_random_hex 6)
run="$task-$rid"
distro="hm-m02-$rid"
hm_valid_name "$run" || { echo "cannot make a run name" >&2; exit 2; }
rootfs_in=${HM_WSL_ROOTFS:-}
case "$rootfs_in" in *[\"\'\`\$]*) echo "bad HM_WSL_ROOTFS" >&2; exit 2 ;; esac
download=${HM_WSL_DOWNLOAD:-0}
allow_apt=${HM_WSL_ALLOW_APT:-0}
user=hmtest

# Local mode: the prebuilt binary is checked before anything at all is created (no artifact
# directory, no temporary directory, no run directory, no import).
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | cut -d' ' -f1
    else
        shasum -a 256 -- "$1" | cut -d' ' -f1
    fi
}
prebuilt=""
prebuilt_sha=""
if [ "$local_mode" = 1 ]; then
    prebuilt=${HM_PREBUILT_HEIMDALL:-}
    want=$(printf '%s' "${HM_PREBUILT_SHA256:-}" | tr 'A-F' 'a-f')
    [ -n "$prebuilt" ] || { echo "blocked: set HM_PREBUILT_HEIMDALL to the Linux heimdall binary cross-built on the build host" >&2; exit 3; }
    [ -n "$want" ] || { echo "blocked: set HM_PREBUILT_SHA256 to the digest the build host recorded" >&2; exit 3; }
    [ -f "$prebuilt" ] || { echo "blocked: HM_PREBUILT_HEIMDALL is not a regular file" >&2; exit 3; }
    case "$want" in *[!0-9a-f]*) want="" ;; esac
    [ "${#want}" = 64 ] || { echo "bad HM_PREBUILT_SHA256 (64 hex digits)" >&2; exit 2; }
    prebuilt_sha=$(sha256_file "$prebuilt")
    if [ "$prebuilt_sha" != "$want" ]; then
        echo "prebuilt heimdall sha256 mismatch: file $prebuilt_sha, expected $want; nothing created" >&2
        exit 1
    fi
fi

mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR

# One step of the target side: the script body on stdin, run with bash -s and the same
# arguments, through ssh to the controller, or (local mode) by a local bash from $HOME, as
# ssh would start it.
remote() {
    local prelude=$1
    shift
    if [ "$local_mode" = 1 ]; then
        { cat "$slib" "$rlib"; printf '%s\n' "$prelude"; cat; } |
            (cd "$HOME" && bash -s -- "$@")
    else
        { cat "$slib" "$rlib"; printf '%s\n' "$prelude"; cat; } |
            ssh -F "$ssh_config" -o BatchMode=yes "$host" bash -s -- "$@"
    fi
}

shim=$(mktemp -d)
commands="$out/commands.txt"
: >"$commands"
wsl_dir=""
win_dir=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    if [ -n "$wsl_dir$win_dir" ]; then
        set +e
        remote "$(printf 'wsl_dir=%q; win_dir=%q; distro=%q' "$wsl_dir" "$win_dir" "$distro")" "$run" \
            >"$shim/cleanup.txt" 2>&1 <<'REMOTE'
main() {
set -u
run=$1
W=/mnt/c/Windows/System32
cd /mnt/c || return 1
rc=0
# A distribution this run imported and did not unregister: only the recorded name, of
# this run's pattern, and absent from the list taken before the import.
if [ -n "$wsl_dir" ] && [ -f "$wsl_dir/distro-name" ]; then
    d=$(cat "$wsl_dir/distro-name")
    if [ "$d" = "$distro" ] && case "$d" in hm-m02-[0-9a-f]*) true ;; *) false ;; esac &&
        ! grep -qxF -- "$d" "$wsl_dir/before.txt" 2>/dev/null; then
        (cd /mnt/c && "$W/wsl.exe" --terminate "$d") </dev/null >/dev/null 2>&1
        (cd /mnt/c && "$W/wsl.exe" --unregister "$d") </dev/null >/dev/null 2>&1
        echo "cleanup-unregister-exit=$?"
    else
        echo "cleanup-unregister=refused (name does not match this run)"
        rc=1
    fi
fi
hm_scratch_remove "$win_dir" "$run" || rc=1
hm_scratch_remove "$wsl_dir" "$run" || rc=1
[ -z "$win_dir" ] || [ ! -e "$win_dir" ] || rc=1
[ -z "$wsl_dir" ] || [ ! -e "$wsl_dir" ] || rc=1
return "$rc"
}
main "$@" </dev/null
REMOTE
        m02_record "$commands" "remote: unregister a distribution left by an interrupted run (if any), remove exactly the run directories, check they are absent" "$?"
        sed -n 's/^cleanup-unregister/cleanup unregister/p' "$shim/cleanup.txt" >>"$commands"
    fi
    rm -rf "$shim"
    exit "$rc"
}
trap cleanup EXIT

redact_build_log() { m02_redact "$out/build.txt" "$out/build.txt" "$shim" "<shim>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" "$(id -un)" "<user>"; }
if [ "$local_mode" = 1 ]; then
    # Nothing is built here: the binary and its digest came from the build host's run.
    echo "mode=local" >>"$commands"
    m02_record "$commands" "prebuilt heimdall sha256 equals HM_PREBUILT_SHA256 recorded by the build host ($prebuilt_sha)" 0
    cli=$prebuilt
    {
        echo "heimdall (Linux, for the disposable distribution) sha256: $prebuilt_sha"
        echo "prebuilt: cross-built on the build host; sha256 verified here against HM_PREBUILT_SHA256 (mode=local)"
        echo "pinned image: $ROOTFS_URL sha256 $ROOTFS_SHA256"
    } >"$out/build.txt"
else
    m02_write_shims "$shim"
    cd "$repo"
    set +e
    m02_cargo_build x86_64-unknown-linux-gnu "$shim" "$out/build.txt"
    rc=$?
    set -e
    m02_record "$commands" "cargo test --target x86_64-unknown-linux-gnu --workspace --no-run --locked (zig cc linker/CC shims)" "$rc"
    [ "$rc" = 0 ] || { redact_build_log; exit "$rc"; }
    m02_artifacts "$shim" || { echo "the heimdall binary was not built" >&2; redact_build_log; exit 5; }
    cli=$(cat "$shim/cli.txt")
    bin_sha=$(shasum -a 256 "$cli" | cut -d' ' -f1)
    {
        echo "heimdall (Linux, for the disposable distribution) sha256: $bin_sha"
        echo "toolchain: $(rustc --version); zig $(zig version); target x86_64-unknown-linux-gnu (glibc floor 2.31)"
        echo "pinned image: $ROOTFS_URL sha256 $ROOTFS_SHA256"
    } >>"$out/build.txt"
    if [ "$build_only" = 1 ]; then
        redact_build_log
        echo "heimdall binary ready; pinned image $ROOTFS_URL"
        # For the orchestrator, who copies the binary to the PC for HM_LOCAL=1 (stdout only).
        echo "prebuilt-heimdall=$cli"
        echo "prebuilt-sha256=$bin_sha"
        exit 0
    fi
fi

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
mkdir -- "$d/files" "$d/distro" "$d/rootfs" || return 1
}
main "$@" </dev/null
REMOTE
crc=$?
set -e
wsl_dir=$(sed -n 's/^created-wsl=//p' "$shim/created.txt" | head -1)
win_dir=$(sed -n 's/^created-win=//p' "$shim/created.txt" | head -1)
m02_record "$commands" "remote: create the run directories exclusively (run $run)" "$crc"
[ "$crc" = 0 ] && [ -n "$wsl_dir" ] && [ -n "$win_dir" ] || exit 1

mkdir "$shim/stage"
cp "$cli" "$shim/stage/heimdall"
cp "$here/scenario-ordinary-ssh.sh" "$here/remote-lib.sh" "$here/pty-answer.py" "$here/target-root.sh" "$shim/stage/"
if [ "$local_mode" = 1 ]; then
    # The digest checked above is that of the bytes shipped: hash the staged copy again.
    set +e
    [ "$(sha256_file "$shim/stage/heimdall")" = "$prebuilt_sha" ]
    rc=$?
    set -e
    m02_record "$commands" "staged heimdall copy still has the verified sha256" "$rc"
    [ "$rc" = 0 ] || exit 1
    # A local extraction into the same scratch directory the ssh path extracts into.
    set +e
    [ "$wsl_dir" = "$HOME/hm-m00/$run" ] && tar -C "$shim/stage" -cf - . | tar -xf - -C "$wsl_dir"
    rc=$?
    set -e
    m02_record "$commands" "local tar extraction of heimdall and the scenario files into WSL scratch" "$rc"
else
    set +e
    tar -C "$shim/stage" -cf - . | gzip -1 |
        ssh -F "$ssh_config" -o BatchMode=yes "$host" "tar -xzf - -C \"\$HOME/hm-m00/$run\""
    rc=$?
    set -e
    m02_record "$commands" "tar stream of heimdall and the scenario files into WSL scratch" "$rc"
fi
[ "$rc" = 0 ] || exit 1

set +e
remote "$(printf 'wsl_dir=%q; win_dir=%q; distro=%q; user=%q; rootfs_in=%q; download=%q; allow_apt=%q; url=%q; pin=%q' \
    "$wsl_dir" "$win_dir" "$distro" "$user" "$rootfs_in" "$download" "$allow_apt" "$ROOTFS_URL" "$ROOTFS_SHA256")" \
    >"$shim/remote.txt" 2>&1 <<'REMOTE'
W=/mnt/c/Windows/System32
# With pipefail (main), both return wsl.exe's exit code (that of the command it ran).
wslx() { (cd /mnt/c && WSL_UTF8=1 "$W/wsl.exe" "$@") </dev/null | tr -d '\000\r'; }
in_target() { (cd /mnt/c && WSL_UTF8=1 "$W/wsl.exe" -d "$distro" "$@") </dev/null 2>&1 | tr -d '\000\r'; }
main() {
set -u -o pipefail
cd /mnt/c || return 1
hm2_sanitize_env
files=$win_dir/files
cp "$wsl_dir/"heimdall "$wsl_dir/"*.sh "$wsl_dir/"*.py "$files/" || return 1
echo "wsl-version=$(wslx --version | head -1)"
wslx -l -q | sed '/^$/d' | sort >"$wsl_dir/before.txt"
echo "distributions-before=$(grep -c . "$wsl_dir/before.txt")"
if grep -qxF -- "$distro" "$wsl_dir/before.txt"; then
    echo "import=refused: a distribution with this run's name exists"
    return 1
fi
# The pinned image.
img=""
if [ -n "$rootfs_in" ]; then
    case "$rootfs_in" in [A-Za-z]:\\*) img=$(wslpath -u "$rootfs_in") ;; *) img=$rootfs_in ;; esac
    echo "rootfs-source=HM_WSL_ROOTFS"
elif [ "$download" = 1 ]; then
    img=$win_dir/rootfs/ubuntu-24.04.5-wsl-amd64.wsl
    curl -fsSL --proto '=https' --tlsv1.2 -o "$img" "$url"
    echo "rootfs-download-exit=$?"
    echo "rootfs-source=download over https"
else
    echo "blocked=the pinned image (HM_WSL_ROOTFS or HM_WSL_DOWNLOAD=1)"
    return 3
fi
[ -f "$img" ] || { echo "blocked=the pinned image is not a file on the host"; return 3; }
sha=$(sha256sum "$img" | cut -d' ' -f1)
if [ "$sha" != "$pin" ]; then
    echo "rootfs-sha256=mismatch (not the pinned image; nothing imported)"
    return 3
fi
echo "rootfs-sha256=matches the pin"
echo "$distro" >"$wsl_dir/distro-name"
wslx --import "$distro" "$(wslpath -w "$win_dir/distro")" "$(wslpath -w "$img")" --version 2 >/dev/null
echo "import-exit=$?"
wslx -l -q | sed '/^$/d' >"$wsl_dir/now.txt"
grep -qxF -- "$distro" "$wsl_dir/now.txt" || { echo "import=not registered"; return 1; }
echo "### target-facts"
in_target -u root --exec /bin/bash "$files/target-root.sh" "$distro" no-systemd
wslx --terminate "$distro" >/dev/null
echo "terminate-after-no-systemd-exit=$?"
in_target -u root --exec /bin/bash "$files/target-root.sh" "$distro" prepare "$user" "$allow_apt" "$files"
prc=$?
echo "prepare-exit=$prc"
src=0
if [ "$prc" = 0 ]; then
    echo "---tests---"
    in_target -u "$user" --cd "~" --exec /bin/bash "$files/scenario-ordinary-ssh.sh" \
        "/home/$user/hm-m02-scenario" "/home/$user/heimdall"
    src=$?
    echo "---after---"
    echo "scenario-exit=$src"
    in_target -u root --exec /bin/bash "$files/target-root.sh" "$distro" listeners
else
    src=$prc
fi
wslx --terminate "$distro" >/dev/null
echo "terminate-exit=$?"
wslx --unregister "$distro" >/dev/null
urc=$?
echo "unregister-exit=$urc"
wslx -l -q | sed '/^$/d' | sort >"$wsl_dir/after.txt"
if ! grep -qxF -- "$distro" "$wsl_dir/after.txt"; then
    rm -f "$wsl_dir/distro-name"
    echo "distribution-registered-after=no"
fi
echo "distributions-after=$(grep -c . "$wsl_dir/after.txt")"
cmp -s "$wsl_dir/before.txt" "$wsl_dir/after.txt" && echo "registered-set-equal-to-before=yes" || echo "registered-set-equal-to-before=no"
[ -d "$win_dir/distro" ] && echo "distro-dir-entries-after=$(ls -A "$win_dir/distro" | wc -l | tr -d ' ')"
echo "---redaction---"
echo "winuser=$("$W/cmd.exe" /c 'echo %USERNAME%' | tr -d '\r')"
echo "winhost=$("$W/cmd.exe" /c 'echo %COMPUTERNAME%' | tr -d '\r')"
echo "winhome=$("$W/cmd.exe" /c 'echo %USERPROFILE%' | tr -d '\r')"
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
echo "wsldistro=${WSL_DISTRO_NAME:-}"
[ "$urc" = 0 ] || return 1
return "$src"
}
main "$@" </dev/null
REMOTE
rc=$?
set -e
m02_record "$commands" "remote: pinned image, import, prepare, the ordinary-ssh scenario, terminate and unregister the disposable distribution" "$rc"

red=$(sed -n '/^---redaction---$/,$p' "$shim/remote.txt")
val() { printf '%s\n' "$red" | sed -n "s/^$1=//p" | head -1; }
winuser=$(val winuser); winhost=$(val winhost); winhome=$(val winhome)
wsluser=$(val wsluser); wslhome=$(val wslhome); wslhost=$(val wslhost); wsldistro=$(val wsldistro)
sed '/^---redaction---$/,$d' "$shim/remote.txt" >"$shim/remote.body"
m02_redact "$shim/remote.body" "$shim/redacted.txt" "$winhome" "<winhome>" "$wslhome" "<wslhome>" "$HOME" "<home>" \
    "$winuser" "<winuser>" --word "$winhost" "<winhost>" --word "$host" "<winhost>" "$wsluser" "<wsluser>" \
    --word "$wslhost" "<wslhost>" "$wsldistro" "<owner-distro>" "$(id -un)" "<user>"
if grep -q '^---tests---$' "$shim/redacted.txt"; then
    sed -n '1,/^---tests---$/p' "$shim/redacted.txt" | sed '$d' >"$out/host.txt"
    sed -n '/^---after---$/,$p' "$shim/redacted.txt" | sed '1d' >>"$out/host.txt"
    sed -n '/^---tests---$/,/^---after---$/p' "$shim/redacted.txt" | sed '1d;$d' >"$out/tests.txt"
else
    cp "$shim/redacted.txt" "$out/host.txt"
    : >"$out/tests.txt"
fi
if [ "$local_mode" = 1 ]; then
    { echo "mode=local (run inside the WSL controller by an agent on the PC; ADR-0007 §12.32 item 15)"; cat "$out/host.txt"; } >"$shim/host.new"
    cat "$shim/host.new" >"$out/host.txt"
fi
# The scenario's own facts (versions, digests, counts: never a path or a name) join host.txt as
# key=value lines, where the evidence generator reads versions and facts.
sed -n 's/^fact \([A-Za-z0-9_.-]*\)=\(.*\)$/\1=\2/p' "$out/tests.txt" >>"$out/host.txt"
grep -q '^registered-set-equal-to-before=yes$' "$out/host.txt" && eq=0 || eq=1
m02_record "$commands" "registered WSL distributions equal to the set before the import (the disposable one unregistered, no other touched)" "$eq"
redact_build_log
hits=$(m02_canary_scan "$out")
m02_record "$commands" "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
set +e
leaks=$(m02_leak_scan "$out" "$winhome" "$wslhome" "$HOME" "$winuser" --word "$winhost" --word "$host" "$wsluser" --word "$wslhost" "$wsldistro" "$(id -un)")
lrc=$?
set -e
m02_record "$commands" "leak scan: saved files still naming a host, a user, a home or the controller distribution ($leaks)" "$lrc"
cat "$out/host.txt"
grep -E '^### |^test ' "$out/tests.txt" || true
[ "$hits" = 0 ] && [ "$lrc" = 0 ] || exit 1
[ "$rc" = 0 ] || exit "$rc"
[ "$eq" = 0 ] || exit 1
exit 0
