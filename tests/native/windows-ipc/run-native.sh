#!/usr/bin/env bash
# M01-U6w / U6b: cross-build the heimdall-ipc test binaries for x86_64-pc-windows-gnu
# on a macOS/Linux host, run them natively on the owner's Windows PC (non-elevated
# user, through WSL interop) and save redacted output.
#
# Binaries (one per Cargo test target, F09 harness): the lib unit tests (`windows::`
# native pipe tests plus the platform-neutral unit tests), `adversarial_ipc_frames`
# and `adversarial_agent_frames` (platform-neutral, in-memory streams), and
# `integration_ipc_unix` (`#![cfg(unix)]`: on Windows it must report 0 tests; it is
# run to show that).
#
# Usage: tests/native/windows-ipc/run-native.sh <artifact-dir>
#   HM_SSH_CONFIG  ssh config for the Windows host (required unless HM_BUILD_ONLY=1)
#   HM_HOST        ssh host alias in that config (required unless HM_BUILD_ONLY=1)
#   HM_TASK        scratch directory name prefix (default: M01-U6w); the run uses
#                  <HM_TASK>-<16 random hex digits>
#   HM_BUILD_ONLY  1 = cross-build and record the binaries' hashes, then stop (no ssh)
#
# Remote scripts run inside a function with stdin from /dev/null: Windows programs
# started through interop would otherwise consume the rest of the script from stdin.
#
# Linker: zig (`zig cc -target x86_64-windows-gnu`, `zig dlltool` for raw-dylib
# import libraries) through two shims in a mktemp directory that is removed on exit.
# No CARGO_TARGET_DIR override: the workspace ./target is used (AGENTS.md).
#
# Scratch (review B01; helpers in scratch-lib.sh, sent ahead of every remote
# script): ~/hm-m00/<run> (WSL) and %LOCALAPPDATA%\hm-m00\<run> (Windows), where
# <run> = <HM_TASK>-<random>, each created exclusively by one remote step (plain
# mkdir: an existing directory is an error, never reused; a symlinked hm-m00 root
# is refused). The exact paths that step reports as created are kept in memory
# (never written to the evidence) and only those are removed at the end, pass or
# fail. HM_TASK '.', '..' and names outside [A-Za-z0-9][A-Za-z0-9._-]* are
# rejected before anything runs. Nothing is elevated; no service, registry,
# firewall or ssh-agent state is touched. Pipes created by the tests are named
# \\.\pipe\hm-M01-U6w-<pid>-<n>-<kind> and die with the test process.
#
# Exit (review B03): nonzero when the windows:: run or any binary of the full
# run fails (or the canary scan finds a hit); commands.txt records both exits
# and the remote step's own exit.
#
# Self-test without any host: tools/validation/native-harness-selftest.sh.
#
# Output (all redacted: <winuser>, <winhost>, <winhome>, <wsluser>, <wslhome>,
# S-1-5-21-<redacted>): build.txt, windows-tests.txt, all-tests.txt (every binary,
# each followed by its exit code), host.txt, commands.txt (each command with its real
# exit code), canary-scan.txt.

set -euo pipefail

out=${1:?usage: run-native.sh <artifact-dir>}
build_only=${HM_BUILD_ONLY:-0}
if [ "$build_only" != 1 ]; then
    ssh_config=${HM_SSH_CONFIG:?set HM_SSH_CONFIG to the ssh config for the Windows test host}
    host=${HM_HOST:?set HM_HOST to the host alias in HM_SSH_CONFIG}
fi
repo=$(cd "$(dirname "$0")/../../.." && pwd)
lib="$repo/tests/native/windows-ipc/scratch-lib.sh"
# shellcheck source=tests/native/windows-ipc/scratch-lib.sh
. "$lib"
task=${HM_TASK:-M01-U6w}
hm_valid_name "$task" || { echo "bad HM_TASK" >&2; exit 2; }
# Unique per run: concurrent or earlier runs never share a directory.
run="$task-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
hm_valid_name "$run" || { echo "cannot make a run name" >&2; exit 2; }

mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR

# Run a remote script (stdin) after scratch-lib.sh and the given shell
# assignments (built with printf %q, sent on stdin, never on the command line);
# the remaining arguments are the script's.
remote() {
    local prelude=$1
    shift
    { cat "$lib"; printf '%s\n' "$prelude"; cat; } |
        ssh -F "$ssh_config" -o BatchMode=yes "$host" bash -s -- "$@"
}

shim=$(mktemp -d)
# Exact directories the create step reported; only these are ever removed.
wsl_dir=""
win_dir=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    rm -rf "$shim"
    if [ -n "$wsl_dir$win_dir" ]; then
        remote "$(printf 'wsl_dir=%q; win_dir=%q' "$wsl_dir" "$win_dir")" "$run" <<'REMOTE' || true
main() {
set -u
run=$1
cd /mnt/c || return 1
rc=0
hm_scratch_remove "$win_dir" "$run" || rc=1
hm_scratch_remove "$wsl_dir" "$run" || rc=1
return "$rc"
}
main "$@" </dev/null
REMOTE
    fi
}
trap cleanup EXIT

cat >"$shim/zigcc-win.sh" <<'EOF'
#!/usr/bin/env bash
# zig cc as the x86_64-pc-windows-gnu linker (same filtering idea as cargo-zigbuild).
args=()
for a in "$@"; do
  case "$a" in
    -lgcc_eh) args+=("-lunwind") ;;
    -lgcc_s|-lgcc|-l:libpthread.a|-lwindows|-lmsvcrt|-Wl,--disable-auto-image-base|-fno-use-linker-plugin|-nodefaultlibs|-nostartfiles) ;;
    */self-contained/crt2.o|*/self-contained/dllcrt2.o|*rsbegin.o|*rsend.o) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-windows-gnu "${args[@]}"
EOF
printf '#!/usr/bin/env bash\nexec zig dlltool "$@"\n' >"$shim/x86_64-w64-mingw32-dlltool"
chmod +x "$shim/zigcc-win.sh" "$shim/x86_64-w64-mingw32-dlltool"

commands="$out/commands.txt"
: >"$commands"
record() { echo "exit $2: $1" >>"$commands"; }

# Cargo target name : remote executable name. `heimdall_ipc` is the lib unit-test
# binary (kept as heimdall_ipc_tests.exe, the name earlier evidence used).
targets="heimdall_ipc:heimdall_ipc_tests adversarial_ipc_frames:adversarial_ipc_frames adversarial_agent_frames:adversarial_agent_frames integration_ipc_unix:integration_ipc_unix"

# Build log: redact the local home path and user name.
redact_build_log() {
    python3 -I - "$out/build.txt" "$HOME" "$(id -un)" <<'PYREDACT'
import sys
path, home, user = sys.argv[1:4]
text = open(path, encoding="utf-8", errors="replace").read().replace(home, "<home>").replace(user, "<user>")
open(path, "w", encoding="utf-8").write(text)
PYREDACT
}

cd "$repo"
set +e
PATH="$shim:$PATH" CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$shim/zigcc-win.sh" \
    cargo test --target x86_64-pc-windows-gnu -p heimdall-ipc --lib \
    --test adversarial_ipc_frames --test adversarial_agent_frames --test integration_ipc_unix \
    --no-run --locked \
    --message-format=json-render-diagnostics >"$shim/build.json" 2>"$out/build.txt"
rc=$?
set -e
record "cargo test --target x86_64-pc-windows-gnu -p heimdall-ipc --lib --test adversarial_ipc_frames --test adversarial_agent_frames --test integration_ipc_unix --no-run --locked (zig linker shims)" "$rc"
[ "$rc" = 0 ] || exit "$rc"
exe_for() {
    jq -r --arg n "$1" 'select(.reason == "compiler-artifact" and .executable != null and .target.name == $n) | .executable' "$shim/build.json" | tail -1
}
for pair in $targets; do
    exe=$(exe_for "${pair%%:*}")
    [ -f "$exe" ] || { echo "test executable for ${pair%%:*} not found" >&2; exit 1; }
    echo "${pair#*:}.exe sha256: $(shasum -a 256 "$exe" | cut -d' ' -f1)" >>"$out/build.txt"
done
echo "toolchain: $(rustc --version); zig $(zig version)" >>"$out/build.txt"
if [ "$build_only" = 1 ]; then
    redact_build_log
    grep -E 'sha256|^toolchain' "$out/build.txt"
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
mkdir -- "$d/tmp" || return 1
}
main "$@" </dev/null
REMOTE
crc=$?
set -e
wsl_dir=$(sed -n 's/^created-wsl=//p' "$shim/created.txt" | head -1)
win_dir=$(sed -n 's/^created-win=//p' "$shim/created.txt" | head -1)
record "remote: create the run directories exclusively (run $run)" "$crc"
[ "$crc" = 0 ] && [ -n "$wsl_dir" ] && [ -n "$win_dir" ] || exit 1

for pair in $targets; do
    scp -F "$ssh_config" -q "$(exe_for "${pair%%:*}")" "$host:hm-m00/$run/${pair#*:}.exe"
done
record "scp $(echo "$targets" | wc -w | tr -d ' ') test binaries to WSL scratch" 0

set +e
remote "$(printf 'wsl_dir=%q; win_dir=%q' "$wsl_dir" "$win_dir")" >"$shim/remote.txt" 2>&1 <<'REMOTE'
main() {
set -u
cd /mnt/c || return 1
wl=$win_dir
cp "$wsl_dir/"*.exe "$wl/" || return 1
cd "$wl" || return 1
TEMP=$(wslpath -w "$wl/tmp"); TMP=$TEMP; WSLENV=TEMP/w:TMP/w
export TEMP TMP WSLENV
timeout 300 ./heimdall_ipc_tests.exe windows:: --test-threads=1 >windows-tests.txt 2>&1
wrc=$?
echo "windows-tests-exit=$wrc"
: >all-tests.txt
arc=0
for b in heimdall_ipc_tests adversarial_ipc_frames adversarial_agent_frames integration_ipc_unix; do
    echo "### $b" >>all-tests.txt
    timeout 600 "./$b.exe" --test-threads=1 >>all-tests.txt 2>&1
    brc=$?
    echo "### $b exit=$brc" >>all-tests.txt
    echo "all-tests-exit[$b]=$brc"
    [ "$brc" = 0 ] || arc=$brc
done
echo "all-tests-exit=$arc"
leftover=$(/mnt/c/Windows/System32/tasklist.exe /NH | tr -d '\r' | grep -c -E '^(heimdall_ipc_tests|adversarial_ipc_frames|adversarial_agent_frames|integration_ipc_unix)\.exe' || true)
echo "leftover-test-processes=$leftover"
echo "integrity=$(/mnt/c/Windows/System32/whoami.exe /groups | grep -o 'Medium Mandatory Level\|High Mandatory Level\|System Mandatory Level' | head -1)"
echo "os=$(/mnt/c/Windows/System32/cmd.exe /c ver | tr -d '\r' | grep -v '^$')"
echo "---windows-tests---"; cat windows-tests.txt
echo "---all-tests---"; cat all-tests.txt
echo "---redaction---"
echo "winuser=$(/mnt/c/Windows/System32/cmd.exe /c 'echo %USERNAME%' | tr -d '\r')"
echo "winhost=$(/mnt/c/Windows/System32/cmd.exe /c 'echo %COMPUTERNAME%' | tr -d '\r')"
echo "winhome=$(/mnt/c/Windows/System32/cmd.exe /c 'echo %USERPROFILE%' | tr -d '\r')"
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
# Review B03: either run failing fails the step (windows:: first, then the rest).
[ "$wrc" = 0 ] || return "$wrc"
return "$arc"
}
main "$@" </dev/null
REMOTE
rc=$?
set -e
# The two runs' own exits, as the remote script printed them (before any test output).
head_part=$(sed -n '1,/^---windows-tests---$/p' "$shim/remote.txt")
wrc=$(printf '%s\n' "$head_part" | sed -n 's/^windows-tests-exit=//p' | head -1)
arc=$(printf '%s\n' "$head_part" | sed -n 's/^all-tests-exit=//p' | head -1)
record "remote: heimdall_ipc_tests.exe windows:: --test-threads=1 as the non-elevated user (exit of the windows:: run)" "${wrc:-missing}"
record "remote: every test binary --test-threads=1 (last failing binary's exit, 0 if all passed)" "${arc:-missing}"
record "remote: test step (nonzero when either run failed)" "$rc"

# Redact with values read from the host; the values themselves are never written.
red=$(sed -n '/^---redaction---$/,$p' "$shim/remote.txt")
val() { printf '%s\n' "$red" | sed -n "s/^$1=//p" | head -1; }
winuser=$(val winuser); winhost=$(val winhost); winhome=$(val winhome)
wsluser=$(val wsluser); wslhome=$(val wslhome); wslhost=$(val wslhost)
python3 -I - "$shim/remote.txt" "$shim/redacted.txt" "$winhome" "$wslhome" "$winuser" "$winhost" "$wsluser" "$wslhost" <<'PY'
import re, sys
src, dst, winhome, wslhome, winuser, winhost, wsluser, wslhost = sys.argv[1:9]
text = open(src, encoding="utf-8", errors="replace").read()
text = text.split("---redaction---")[0]
def sub(text, value, label):
    if not value:
        return text
    forms = {value, value.replace("\\", "\\\\"), value.replace("\\", "/")}
    for form in sorted(forms, key=len, reverse=True):
        text = re.sub(re.escape(form), label, text, flags=re.IGNORECASE)
    return text
# WSL view of the Windows home (/mnt/c/Users/<user>) before the plain forms.
if len(winhome) > 2 and winhome[1] == ":":
    text = sub(text, "/mnt/" + winhome[0].lower() + winhome[2:].replace("\\", "/"), "<winhome>")
for value, label in ((winhome, "<winhome>"), (wslhome, "<wslhome>"), (winuser, "<winuser>"),
                     (winhost, "<winhost>"), (wsluser, "<wsluser>"), (wslhost, "<wslhost>")):
    text = sub(text, value, label)
text = re.sub(r"S-1-5-21(-\d+){2,4}", "S-1-5-21-<redacted>", text)
open(dst, "w", encoding="utf-8").write(text)
PY
sed -n '1,/^---windows-tests---$/p' "$shim/redacted.txt" | sed '$d' >"$out/host.txt"
sed -n '/^---windows-tests---$/,/^---all-tests---$/p' "$shim/redacted.txt" | sed '1d;$d' >"$out/windows-tests.txt"
sed -n '/^---all-tests---$/,$p' "$shim/redacted.txt" | sed '1d' >"$out/all-tests.txt"
redact_build_log

hits=$(cat "$out"/*.txt | grep -c 'HEIMDALL_CANARY_' || true)
echo "canary-prefix occurrences in saved output: $hits" >"$out/canary-scan.txt"
record "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
cat "$out/host.txt"
grep -E '^test result|^test windows::' "$out/windows-tests.txt" || true
grep -E '^### |^test result' "$out/all-tests.txt" || true
[ "$hits" = 0 ] || exit 1
[ "$rc" = 0 ] || exit "$rc"
# Belt and braces: a missing or nonzero per-run exit is a failure too.
[ "${wrc:-x}" = 0 ] && [ "${arc:-x}" = 0 ] || exit 1
exit 0
