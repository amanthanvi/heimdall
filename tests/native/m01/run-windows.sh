#!/usr/bin/env bash
# M01-U10: cross-build every workspace test binary for x86_64-pc-windows-gnu on a
# macOS/Linux host, run them natively on the owner's Windows 11 PC (non-elevated
# user, through WSL interop) and save redacted output. Extends the pattern of
# tests/native/windows-ipc/run-native.sh (M01-U6w) from heimdall-ipc to the
# workspace.
#
# Usage: tests/native/m01/run-windows.sh <artifact-dir>
#   HM_SSH_CONFIG  ssh config for the Windows host (required unless HM_BUILD_ONLY=1)
#   HM_HOST        ssh host alias in that config (required unless HM_BUILD_ONLY=1)
#   HM_TASK        scratch directory name (default: M01-U10)
#   HM_ONLY        optional space-separated list of test target names to run (default: all)
#   HM_BUILD_ONLY  1 = cross-build and record the binaries' hashes, then stop (no ssh)
#
# Binaries: every test executable `cargo test --workspace --no-run` produces for the
# target, plus the `heimdall.exe` CLI binary (copied next to them; the e2e suite
# finds it through HEIMDALL_E2E_BIN), except (recorded in skipped.txt with the
# reason):
#   * e2e_cli_m01's pseudo-terminal cases are `cfg(unix)` (script(1)); every other
#     e2e case runs natively against heimdall.exe (`service stop` sends
#     Request::Shutdown over the named pipe; ADR-0006 §13.6 item 8).
#   * contracts: reads schemas/ and tests/contracts/golden at the compile-time
#     CARGO_MANIFEST_DIR path (build host); platform-neutral, run on the build host.
#   * integration_runtime::config_schema_export_matches_checked_in_file: same reason.
#
# Linker and C compiler: zig (`zig cc -target x86_64-windows-gnu`, `zig dlltool` for
# raw-dylib import libraries, `zig ar`) through shims in a mktemp directory removed
# on exit. The C compiler shim (bundled SQLite) drops cc-rs's --target= argument.
# No CARGO_TARGET_DIR override: the workspace ./target is used (AGENTS.md); remove
# target/x86_64-pc-windows-gnu afterwards to keep the shared target small.
#
# Scratch: ~/hm-m00/$HM_TASK (WSL) and %LOCALAPPDATA%\hm-m00\$HM_TASK (Windows), with
# TEMP/TMP pointed inside the latter; both are removed at the end, pass or fail.
# Nothing is elevated; no service, registry, firewall, ssh-agent state or ~/.ssh is
# touched; no `wsl --shutdown`. Pipes created by the tests are per-process names
# that die with the test process; runtime pipes carry the `heimdall-hmtest-`
# prefix (counted before and after the run). The script records (existence only)
# whether %LOCALAPPDATA%\heimdall existed before and after the run; every e2e and
# runtime test uses its own temporary HEIMDALL_HOME under the scratch TEMP.
#
# Output (all redacted: <winuser>, <winhost>, <winhome>, <wsluser>, <wslhome>,
# <wslhost>, S-1-5-21-<redacted>, build host <home>/<user>): build.txt (build log,
# sha256 per binary, toolchain), host.txt, tests.txt (every binary followed by its
# exit code), commands.txt (each command with its real exit code), skipped.txt,
# canary-scan.txt.

set -euo pipefail

out=${1:?usage: run-windows.sh <artifact-dir>}
build_only=${HM_BUILD_ONLY:-0}
if [ "$build_only" != 1 ]; then
    ssh_config=${HM_SSH_CONFIG:?set HM_SSH_CONFIG to the ssh config for the Windows test host}
    host=${HM_HOST:?set HM_HOST to the host alias in HM_SSH_CONFIG}
fi
task=${HM_TASK:-M01-U10}
case "$task" in *[!A-Za-z0-9._-]*|'') echo "bad HM_TASK" >&2; exit 2 ;; esac
triple=x86_64-pc-windows-gnu

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
cat >"$shim/zigcc-win-cc.sh" <<'EOF'
#!/usr/bin/env bash
# zig cc as the C compiler for x86_64-pc-windows-gnu (bundled SQLite via cc-rs).
args=()
for a in "$@"; do
  case "$a" in
    --target=*|-m64|-mthreads) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-windows-gnu "${args[@]}"
EOF
printf '#!/usr/bin/env bash\nexec zig dlltool "$@"\n' >"$shim/x86_64-w64-mingw32-dlltool"
printf '#!/usr/bin/env bash\nexec zig ar "$@"\n' >"$shim/zigar.sh"
chmod +x "$shim/zigcc-win.sh" "$shim/zigcc-win-cc.sh" "$shim/x86_64-w64-mingw32-dlltool" "$shim/zigar.sh"

commands="$out/commands.txt"
: >"$commands"
record() { echo "exit $2: $1" >>"$commands"; }

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
CC_x86_64_pc_windows_gnu="$shim/zigcc-win-cc.sh" AR_x86_64_pc_windows_gnu="$shim/zigar.sh" \
    cargo test --target "$triple" --workspace --no-run --locked \
    --message-format=json-render-diagnostics >"$shim/build.json" 2>"$out/build.txt"
rc=$?
set -e
record "cargo test --target $triple --workspace --no-run --locked (zig linker/CC shims)" "$rc"
[ "$rc" = 0 ] || { redact_build_log; exit "$rc"; }

jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null)
       | [(if (.target.kind | index("test")) then .target.name else .target.name + "-unit" end), .executable] | @tsv' \
    "$shim/build.json" | sort -u >"$shim/all.tsv"
cli_exe=$(jq -r 'select(.reason == "compiler-artifact" and .profile.test == false and .executable != null
       and .target.name == "heimdall" and (.target.kind | index("bin"))) | .executable' "$shim/build.json" | sort -u | head -1)
[ -n "$cli_exe" ] && [ -f "$cli_exe" ] || { echo "the heimdall.exe CLI binary was not built" >&2; exit 1; }
only=${HM_ONLY:-}
: >"$shim/run.tsv"
: >"$out/skipped.txt"
while IFS=$'\t' read -r name exe; do
    case "$name" in
        contracts) echo "$name: not run on Windows: it reads schemas/ and tests/contracts/golden at the compile-time CARGO_MANIFEST_DIR path on the build host (platform-neutral; run on the build host)" >>"$out/skipped.txt" ;;
        *)
            if [ -n "$only" ] && ! printf ' %s ' "$only" | grep -q " $name "; then
                echo "$name: not selected (HM_ONLY)" >>"$out/skipped.txt"
            else
                printf '%s\t%s\n' "$name" "$exe" >>"$shim/run.tsv"
            fi ;;
    esac
done <"$shim/all.tsv"
echo "integration_runtime::config_schema_export_matches_checked_in_file: skipped on Windows (reads schemas/configuration at the compile-time CARGO_MANIFEST_DIR path)" >>"$out/skipped.txt"
echo "e2e_cli_m01 pseudo-terminal cases (non_interactive_with_a_pending_decision..., owner_prompt_on_a_pty..., interactive_ensure_on_a_pty..., widening_resume..._on_a_pty, time_confirmation_on_a_pty...): cfg(unix), not compiled for Windows (script(1)); the attendance order and prompt outcomes are covered by heimdall-unit cli::tests on every platform" >>"$out/skipped.txt"

while IFS=$'\t' read -r name exe; do
    echo "$name.exe sha256: $(shasum -a 256 "$exe" | cut -d' ' -f1)" >>"$out/build.txt"
done <"$shim/run.tsv"
echo "heimdall.exe (CLI) sha256: $(shasum -a 256 "$cli_exe" | cut -d' ' -f1)" >>"$out/build.txt"
echo "toolchain: $(rustc --version); zig $(zig version); target $triple" >>"$out/build.txt"
if [ "$build_only" = 1 ]; then
    redact_build_log
    grep -E 'sha256|^toolchain' "$out/build.txt"
    exit 0
fi

remote_created=1
ssh -F "$ssh_config" -o BatchMode=yes "$host" "mkdir -p \"\$HOME/hm-m00/$task\"" </dev/null
while IFS=$'\t' read -r name exe; do
    scp -F "$ssh_config" -q "$exe" "$host:hm-m00/$task/$name.exe"
done <"$shim/run.tsv"
scp -F "$ssh_config" -q "$cli_exe" "$host:hm-m00/$task/heimdall.exe"
record "scp $(wc -l <"$shim/run.tsv" | tr -d ' ') test binaries and heimdall.exe to WSL scratch" 0
names=$(cut -f1 "$shim/run.tsv" | tr '\n' ' ')

set +e
# shellcheck disable=SC2086  # names are [A-Za-z0-9_-] target names
ssh -F "$ssh_config" -o BatchMode=yes "$host" bash -s -- "$task" $names >"$shim/remote.txt" 2>&1 <<'REMOTE'
main() {
set -u
task=$1
shift
cd /mnt/c || return 1
w=$(/mnt/c/Windows/System32/cmd.exe /c "echo %LOCALAPPDATA%" | tr -d '\r')
[ -n "$w" ] || { echo "LOCALAPPDATA unavailable"; return 1; }
wroot=$(wslpath "$w")
heimdall_before=$([ -e "$wroot/heimdall" ] && echo present || echo absent)
wl=$wroot/hm-m00/$task
mkdir -p "$wl/tmp"
cp "$HOME/hm-m00/$task/"*.exe "$wl/"
cd "$wl" || return 1
TEMP=$(wslpath -w "$wl/tmp"); TMP=$TEMP
HEIMDALL_E2E_BIN=$(wslpath -w "$wl/heimdall.exe")
WSLENV=TEMP/w:TMP/w:HEIMDALL_E2E_BIN/w
export TEMP TMP HEIMDALL_E2E_BIN WSLENV
# Count of named pipes whose name starts with heimdall-hmtest- (names only; the
# command is passed base64/UTF-16LE encoded so no quoting crosses WSL interop).
test_pipes() {
    local ps enc
    ps='@([System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*\heimdall-hmtest-*" }).Count'
    enc=$(printf '%s' "$ps" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)
    /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive \
        -EncodedCommand "$enc" 2>/dev/null | tr -d '\r'
}
echo "integrity=$(/mnt/c/Windows/System32/whoami.exe /groups | grep -o 'Medium Mandatory Level\|High Mandatory Level\|System Mandatory Level' | head -1)"
echo "os=$(/mnt/c/Windows/System32/cmd.exe /c ver | tr -d '\r' | grep -v '^$')"
echo "localappdata-heimdall-before=$heimdall_before"
echo "test-pipes-before=$(test_pipes)"
echo "---tests---"
arc=0
for b in "$@"; do
    skip=""
    [ "$b" = integration_runtime ] && skip="--skip config_schema_export_matches_checked_in_file"
    echo "### $b"
    # shellcheck disable=SC2086
    timeout 1200 "./$b.exe" $skip 2>&1
    brc=$?
    echo "### $b exit=$brc"
    [ "$brc" = 0 ] || arc=$brc
done
echo "all-tests-exit=$arc"
leftover=0
for b in "$@" heimdall; do
    n=$(/mnt/c/Windows/System32/tasklist.exe /NH /FI "IMAGENAME eq $b.exe" | tr -d '\r' | grep -c -i "^$b\.exe" || true)
    leftover=$((leftover + n))
done
echo "leftover-test-processes=$leftover"
echo "test-pipes-after=$(test_pipes)"
echo "localappdata-heimdall-after=$([ -e "$wroot/heimdall" ] && echo present || echo absent)"
echo "---redaction---"
echo "winuser=$(/mnt/c/Windows/System32/cmd.exe /c 'echo %USERNAME%' | tr -d '\r')"
echo "winhost=$(/mnt/c/Windows/System32/cmd.exe /c 'echo %COMPUTERNAME%' | tr -d '\r')"
echo "winhome=$(/mnt/c/Windows/System32/cmd.exe /c 'echo %USERPROFILE%' | tr -d '\r')"
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
return "$arc"
}
main "$@" </dev/null
REMOTE
rc=$?
set -e
record "remote: every test binary as the non-elevated user (overall exit = last failing binary's exit, 0 if all passed)" "$rc"

red=$(sed -n '/^---redaction---$/,$p' "$shim/remote.txt")
val() { printf '%s\n' "$red" | sed -n "s/^$1=//p" | head -1; }
winuser=$(val winuser); winhost=$(val winhost); winhome=$(val winhome)
wsluser=$(val wsluser); wslhome=$(val wslhome); wslhost=$(val wslhost)
python3 -I - "$shim/remote.txt" "$shim/redacted.txt" "$winhome" "$wslhome" "$winuser" "$winhost" "$wsluser" "$wslhost" "$host" "$HOME" "$(id -un)" <<'PY'
import re, sys
src, dst, winhome, wslhome, winuser, winhost, wsluser, wslhost, alias, lhome, luser = sys.argv[1:12]
text = open(src, encoding="utf-8", errors="replace").read()
text = text.split("---redaction---")[0]
def sub(text, value, label):
    if not value or len(value) < 2:
        return text
    forms = {value, value.replace("\\", "\\\\"), value.replace("\\", "/")}
    for form in sorted(forms, key=len, reverse=True):
        text = re.sub(re.escape(form), label, text, flags=re.IGNORECASE)
    return text
if len(winhome) > 2 and winhome[1] == ":":
    text = sub(text, "/mnt/" + winhome[0].lower() + winhome[2:].replace("\\", "/"), "<winhome>")
for value, label in ((winhome, "<winhome>"), (wslhome, "<wslhome>"), (lhome, "<home>"), (winuser, "<winuser>"),
                     (winhost, "<winhost>"), (alias, "<winhost>"), (wsluser, "<wsluser>"), (wslhost, "<wslhost>"),
                     (luser, "<user>")):
    text = sub(text, value, label)
text = re.sub(r"S-1-5-21(-\d+){2,4}", "S-1-5-21-<redacted>", text)
open(dst, "w", encoding="utf-8").write(text)
PY
sed -n '1,/^---tests---$/p' "$shim/redacted.txt" | sed '$d' >"$out/host.txt"
sed -n '/^---tests---$/,$p' "$shim/redacted.txt" | sed '1d' >"$out/tests.txt"
redact_build_log

hits=$(cat "$out"/*.txt | grep -c 'HEIMDALL_CANARY_' || true)
echo "canary-prefix occurrences in saved output: $hits" >"$out/canary-scan.txt"
record "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
cat "$out/host.txt"
grep -E '^### |^test result' "$out/tests.txt" || true
[ "$hits" = 0 ] || exit 1
exit "$rc"
