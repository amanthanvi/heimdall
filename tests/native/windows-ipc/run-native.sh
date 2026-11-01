#!/usr/bin/env bash
# M01-U6w: cross-build the heimdall-ipc unit-test binary for x86_64-pc-windows-gnu on a
# macOS/Linux host, run it natively on the owner's Windows PC (non-elevated user,
# through WSL interop) and save redacted output.
#
# Usage: tests/native/windows-ipc/run-native.sh <artifact-dir>
#   HM_SSH_CONFIG  ssh config for the Windows host (required)
#   HM_HOST        ssh host alias in that config (required)
#   HM_TASK        scratch directory name (default: M01-U6w)
#
# Remote scripts run inside a function with stdin from /dev/null: Windows programs
# started through interop would otherwise consume the rest of the script from stdin.
#
# Linker: zig (`zig cc -target x86_64-windows-gnu`, `zig dlltool` for raw-dylib
# import libraries) through two shims in a mktemp directory that is removed on exit.
# No CARGO_TARGET_DIR override: the workspace ./target is used (AGENTS.md).
#
# Scratch: ~/hm-m00/$HM_TASK (WSL) and %LOCALAPPDATA%\hm-m00\$HM_TASK (Windows); both
# are removed at the end, pass or fail. Nothing is elevated; no service, registry,
# firewall or ssh-agent state is touched. Pipes created by the tests are named
# \\.\pipe\hm-M01-U6w-<pid>-<n>-<kind> and die with the test process.
#
# Output (all redacted: <winuser>, <winhost>, <winhome>, <wsluser>, <wslhome>,
# S-1-5-21-<redacted>): build.txt, windows-tests.txt, all-tests.txt, host.txt,
# commands.txt (each command with its real exit code), canary-scan.txt.

set -euo pipefail

out=${1:?usage: run-native.sh <artifact-dir>}
ssh_config=${HM_SSH_CONFIG:?set HM_SSH_CONFIG to the ssh config for the Windows test host}
host=${HM_HOST:?set HM_HOST to the host alias in HM_SSH_CONFIG}
task=${HM_TASK:-M01-U6w}
case "$task" in *[!A-Za-z0-9._-]*|'') echo "bad HM_TASK" >&2; exit 2 ;; esac

repo=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR

shim=$(mktemp -d)
remote_created=0
cleanup() {
    rm -rf "$shim"
    if [ "$remote_created" = 1 ]; then
        ssh -F "$ssh_config" -o BatchMode=yes "$host" bash -s -- "$task" <<'REMOTE' || true
main() {
set -u
task=$1
cd /mnt/c || exit 1
w=$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" | tr -d '\r')
[ -n "$w" ] && wl=$(wslpath "$w")/hm-m00/$task && rm -rf -- "$wl"
rm -rf -- "$HOME/hm-m00/$task"
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

cd "$repo"
set +e
PATH="$shim:$PATH" CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$shim/zigcc-win.sh" \
    cargo test --target x86_64-pc-windows-gnu -p heimdall-ipc --lib --no-run --locked \
    --message-format=json-render-diagnostics >"$shim/build.json" 2>"$out/build.txt"
rc=$?
set -e
record "cargo test --target x86_64-pc-windows-gnu -p heimdall-ipc --lib --no-run --locked (zig linker shims)" "$rc"
[ "$rc" = 0 ] || exit "$rc"
exe=$(jq -r 'select(.reason == "compiler-artifact" and .executable != null and (.target.kind | index("lib"))) | .executable' "$shim/build.json" | tail -1)
[ -f "$exe" ] || { echo "test executable not found" >&2; exit 1; }
echo "test binary sha256: $(shasum -a 256 "$exe" | cut -d' ' -f1)" >>"$out/build.txt"
echo "toolchain: $(rustc --version); zig $(zig version)" >>"$out/build.txt"

remote_created=1
ssh -F "$ssh_config" -o BatchMode=yes "$host" "mkdir -p \"\$HOME/hm-m00/$task\""
scp -F "$ssh_config" -q "$exe" "$host:hm-m00/$task/heimdall_ipc_tests.exe"
record "scp test binary to WSL scratch" 0

set +e
ssh -F "$ssh_config" -o BatchMode=yes "$host" bash -s -- "$task" >"$shim/remote.txt" 2>&1 <<'REMOTE'
main() {
set -u
task=$1
cd /mnt/c || return 1
w=$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" | tr -d '\r')
[ -n "$w" ] || { echo "LOCALAPPDATA unavailable"; return 1; }
wl=$(wslpath "$w")/hm-m00/$task
mkdir -p "$wl/tmp"
cp "$HOME/hm-m00/$task/heimdall_ipc_tests.exe" "$wl/"
cd "$wl" || return 1
TEMP=$(wslpath -w "$wl/tmp"); TMP=$TEMP; WSLENV=TEMP/w:TMP/w
export TEMP TMP WSLENV
timeout 300 ./heimdall_ipc_tests.exe windows:: --test-threads=1 >windows-tests.txt 2>&1
wrc=$?
echo "windows-tests-exit=$wrc"
timeout 600 ./heimdall_ipc_tests.exe --test-threads=1 >all-tests.txt 2>&1
echo "all-tests-exit=$?"
leftover=$(/mnt/c/Windows/System32/tasklist.exe /FI "IMAGENAME eq heimdall_ipc_tests.exe" /NH | tr -d '\r' | grep -c heimdall_ipc_tests)
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
return "$wrc"
}
main "$@" </dev/null
REMOTE
rc=$?
set -e
record "remote: heimdall_ipc_tests.exe windows:: --test-threads=1 as the non-elevated user (exit of the windows:: run)" "$rc"

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
# Build log: redact the local home path and user name.
python3 -I - "$out/build.txt" "$HOME" "$(id -un)" <<'PY'
import sys
path, home, user = sys.argv[1:4]
text = open(path, encoding="utf-8", errors="replace").read().replace(home, "<home>").replace(user, "<user>")
open(path, "w", encoding="utf-8").write(text)
PY

hits=$(cat "$out"/*.txt | grep -c 'HEIMDALL_CANARY_' || true)
echo "canary-prefix occurrences in saved output: $hits" >"$out/canary-scan.txt"
record "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
cat "$out/host.txt"
grep -E '^test result|^test windows::' "$out/windows-tests.txt" || true
[ "$hits" = 0 ] || exit 1
exit "$rc"
