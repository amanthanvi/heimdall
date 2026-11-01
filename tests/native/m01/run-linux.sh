#!/usr/bin/env bash
# M01-U10: cross-build every workspace test binary for x86_64-unknown-linux-gnu on a
# macOS/Linux host, run them natively on one of the owner's Linux x86-64 hosts over
# the owner's own ssh config, and save redacted output.
#
# Usage: tests/native/m01/run-linux.sh <artifact-dir> <ssh-host-alias>
#   HM_BUILD_ONLY  1 = cross-build and record the binaries' hashes, then stop (no ssh)
#
# Steps: `uname -m` on the host first (anything but x86_64 stops with exit 3 and
# host-arch.txt, nothing copied); cross-build with zig (`zig cc -target
# x86_64-linux-gnu.2.31`) as linker and as the C compiler for the bundled SQLite,
# through shims in a mktemp directory removed on exit; copy the binaries to a fresh
# scratch dir ~/hm-m01-u10-<random> on the host; run each with `nice -n 10`, TMPDIR
# inside the scratch dir, a timeout, its real exit code recorded; remove the scratch
# dir, pass or fail. Nothing is installed; no service is touched; no listener other
# than owner-only Unix sockets inside the scratch TMPDIR is created; only processes
# this run started exist (the test binaries and the children they spawn themselves).
#
# e2e_cli_m01 (gap G09) runs on the remote host against the copied `heimdall`
# binary: the suite takes its binary from HEIMDALL_E2E_BIN (set to the copy in the
# scratch dir) and uses util-linux script(1) for its pseudo-terminal cases (the
# host's `script` is recorded in host.txt; without it those cases fail visibly).
#
# Not run on the remote host (recorded in skipped.txt with the reason):
#   * contracts: it reads schemas/ and tests/contracts/golden at the compile-time
#     CARGO_MANIFEST_DIR path (build host); platform-neutral, run on the build host.
#   * integration_runtime::config_schema_export_matches_checked_in_file: same reason.
#
# No CARGO_TARGET_DIR override: the workspace ./target is used (AGENTS.md); the
# cross-built x86_64-unknown-linux-gnu tree can be removed afterwards with
# `rm -rf target/x86_64-unknown-linux-gnu`.
#
# Output (redacted: <linuxhost>, <user>, <home>, and the build host's <home>/<user>):
#   build.txt (build log, sha256 per binary, toolchain), host.txt, tests.txt (every
#   binary's output followed by its exit code), commands.txt (each command with its
#   real exit code), skipped.txt, canary-scan.txt.

set -euo pipefail

out=${1:?usage: run-linux.sh <artifact-dir> <ssh-host-alias>}
build_only=${HM_BUILD_ONLY:-0}
if [ "$build_only" != 1 ]; then
    host=${2:?usage: run-linux.sh <artifact-dir> <ssh-host-alias>}
    case "$host" in *[!A-Za-z0-9._-]*|'') echo "bad host alias" >&2; exit 2 ;; esac
fi
triple=x86_64-unknown-linux-gnu

repo=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR

shim=$(mktemp -d)
scratch=""
cleanup() {
    rm -rf "$shim"
    if [ -n "$scratch" ]; then
        # Only the directory this run created (exact name, never a glob).
        ssh -o BatchMode=yes "$host" "rm -rf -- \"\$HOME/$scratch\"" </dev/null || true
    fi
}
trap cleanup EXIT

commands="$out/commands.txt"
: >"$commands"
record() { echo "exit $2: $1" >>"$commands"; }

# Arch check before anything is built or copied.
if [ "$build_only" != 1 ]; then
    set +e
    arch=$(ssh -o BatchMode=yes -o ConnectTimeout=15 "$host" 'uname -m' </dev/null 2>"$shim/arch.err")
    rc=$?
    set -e
    record "ssh <linuxhost> uname -m" "$rc"
    if [ "$rc" != 0 ]; then
        # The error text may name the host, the user or an address: keep its shape only.
        sed -E -e "s/$(id -un)/<user>/g" -e 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/<addr>/g' \
            -e "s/$host/<linuxhost>/g" "$shim/arch.err" >"$out/host-unreachable.txt"
        cat "$out/host-unreachable.txt" >&2
        exit 4
    fi
    echo "uname -m: $arch" >"$out/host-arch.txt"
    if [ "$arch" != x86_64 ]; then
        echo "host architecture $arch is not x86_64: skipped (binaries are $triple)" >>"$out/host-arch.txt"
        exit 3
    fi
fi

cat >"$shim/zigcc-linux.sh" <<'EOF'
#!/usr/bin/env bash
# zig cc for x86_64-unknown-linux-gnu, glibc 2.31 floor. Drops the triple cc-rs and
# rustc pass (zig has its own -target), keeps everything else.
args=()
for a in "$@"; do
  case "$a" in
    --target=*|-m64) ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc -target x86_64-linux-gnu.2.31 "${args[@]}"
EOF
printf '#!/usr/bin/env bash\nexec zig ar "$@"\n' >"$shim/zigar.sh"
chmod +x "$shim/zigcc-linux.sh" "$shim/zigar.sh"

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
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$shim/zigcc-linux.sh" \
CC_x86_64_unknown_linux_gnu="$shim/zigcc-linux.sh" \
AR_x86_64_unknown_linux_gnu="$shim/zigar.sh" \
    cargo test --target "$triple" --workspace --no-run --locked \
    --message-format=json-render-diagnostics >"$shim/build.json" 2>"$out/build.txt"
rc=$?
set -e
record "cargo test --target $triple --workspace --no-run --locked (zig cc linker/CC shims)" "$rc"
[ "$rc" = 0 ] || { redact_build_log; exit "$rc"; }

# name<TAB>path for every test executable: lib/bin unit tests are "<crate>-unit".
jq -r 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null)
       | [(if (.target.kind | index("test")) then .target.name else .target.name + "-unit" end), .executable] | @tsv' \
    "$shim/build.json" | sort -u >"$shim/all.tsv"
: >"$shim/run.tsv"
: >"$out/skipped.txt"
# The CLI binary the e2e suite drives (HEIMDALL_E2E_BIN on the remote host).
jq -r 'select(.reason == "compiler-artifact" and .profile.test == false and .executable != null
              and .target.name == "heimdall" and (.target.kind | index("bin")))
       | .executable' "$shim/build.json" | sort -u | head -1 >"$shim/cli.txt"
cli_bin=$(cat "$shim/cli.txt")
[ -n "$cli_bin" ] && [ -f "$cli_bin" ] || { echo "heimdall binary not built" >&2; redact_build_log; exit 5; }
while IFS=$'\t' read -r name exe; do
    case "$name" in
        contracts) echo "$name: not run on the remote host: it reads schemas/ and tests/contracts/golden at the compile-time CARGO_MANIFEST_DIR path on the build host (platform-neutral; run on the build host)" >>"$out/skipped.txt" ;;
        *) printf '%s\t%s\n' "$name" "$exe" >>"$shim/run.tsv" ;;
    esac
done <"$shim/all.tsv"
echo "integration_runtime::config_schema_export_matches_checked_in_file: skipped on the remote host (reads schemas/configuration at the compile-time CARGO_MANIFEST_DIR path)" >>"$out/skipped.txt"

while IFS=$'\t' read -r name exe; do
    echo "$name sha256: $(shasum -a 256 "$exe" | cut -d' ' -f1)" >>"$out/build.txt"
done <"$shim/run.tsv"
echo "heimdall (CLI for e2e_cli_m01) sha256: $(shasum -a 256 "$cli_bin" | cut -d' ' -f1)" >>"$out/build.txt"
echo "toolchain: $(rustc --version); zig $(zig version); target $triple (glibc floor 2.31)" >>"$out/build.txt"
if [ "$build_only" = 1 ]; then
    redact_build_log
    grep -E 'sha256|^toolchain' "$out/build.txt"
    exit 0
fi

scratch="hm-m01-u10-$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')"
ssh -o BatchMode=yes "$host" "mkdir -m 700 \"\$HOME/$scratch\" \"\$HOME/$scratch/tmp\"" </dev/null
record "ssh <linuxhost> mkdir scratch ~/hm-m01-u10-<random>" 0
while IFS=$'\t' read -r name exe; do
    scp -q "$exe" "$host:$scratch/$name"
done <"$shim/run.tsv"
scp -q "$cli_bin" "$host:$scratch/heimdall"
record "scp $(wc -l <"$shim/run.tsv" | tr -d ' ') test binaries and the heimdall CLI to the scratch dir" 0
cut -f1 "$shim/run.tsv" | tr '\n' ' ' >"$shim/names.txt"

set +e
# shellcheck disable=SC2046  # names are [A-Za-z0-9_-] target names; ssh joins args anyway
ssh -o BatchMode=yes "$host" bash -s -- "$scratch" $(cat "$shim/names.txt") >"$shim/remote.txt" 2>&1 <<'REMOTE'
main() {
set -u
scratch=$HOME/$1
shift
names="$*"
cd "$scratch" || return 1
export TMPDIR=$scratch/tmp
echo "os=$(uname -srm)"
echo "glibc=$(ldd --version 2>&1 | head -1)"
echo "nproc=$(nproc)"
echo "script=$(command -v script >/dev/null 2>&1 && script --version 2>&1 | head -1 || echo absent)"
chmod 700 ./heimdall
export HEIMDALL_E2E_BIN=$scratch/heimdall
echo "---tests---"
arc=0
for b in $names; do
    chmod 700 "./$b"
    skip=""
    [ "$b" = integration_runtime ] && skip="--skip config_schema_export_matches_checked_in_file"
    echo "### $b"
    # shellcheck disable=SC2086
    timeout 1200 nice -n 10 "./$b" $skip 2>&1
    brc=$?
    echo "### $b exit=$brc"
    [ "$brc" = 0 ] || arc=$brc
done
echo "all-tests-exit=$arc"
leftover=0
for b in $names; do
    # Count only (nothing is signalled): processes still running a binary of this run.
    n=$(pgrep -u "$(id -u)" -f "^\./$b( |\$)" | wc -l)
    leftover=$((leftover + n))
done
echo "leftover-test-processes=$leftover"
echo "---redaction---"
echo "rhost=$(hostname)"
echo "rfqdn=$(hostname -f 2>/dev/null || true)"
echo "ruser=$(id -un)"
echo "rhome=$HOME"
return "$arc"
}
main "$@" </dev/null
REMOTE
rc=$?
set -e
record "remote: every test binary under nice -n 10 (overall exit = last failing binary's exit, 0 if all passed)" "$rc"

red=$(sed -n '/^---redaction---$/,$p' "$shim/remote.txt")
val() { printf '%s\n' "$red" | sed -n "s/^$1=//p" | head -1; }
python3 -I - "$shim/remote.txt" "$shim/redacted.txt" "$(val rhome)" "$(val rfqdn)" "$(val rhost)" "$(val ruser)" "$host" "$HOME" "$(id -un)" <<'PY'
import re, sys
src, dst, rhome, rfqdn, rhost, ruser, alias, lhome, luser = sys.argv[1:10]
text = open(src, encoding="utf-8", errors="replace").read()
text = text.split("---redaction---")[0]
for value, label in ((rhome, "<home>"), (lhome, "<home>"), (rfqdn, "<linuxhost>"), (rhost, "<linuxhost>"),
                     (alias, "<linuxhost>"), (ruser, "<user>"), (luser, "<user>")):
    if value and len(value) > 1:
        text = re.sub(re.escape(value), label, text)
text = re.sub(r"hm-m01-u10-[a-z0-9]{10}", "hm-m01-u10-<random>", text)
open(dst, "w", encoding="utf-8").write(text)
PY
sed -n '1,/^---tests---$/p' "$shim/redacted.txt" | sed '$d' >"$out/host.txt"
cat "$out/host-arch.txt" >>"$out/host.txt"
rm -f "$out/host-arch.txt"
sed -n '/^---tests---$/,$p' "$shim/redacted.txt" | sed '1d' >"$out/tests.txt"
redact_build_log

hits=$(cat "$out"/*.txt | grep -c 'HEIMDALL_CANARY_' || true)
echo "canary-prefix occurrences in saved output: $hits" >"$out/canary-scan.txt"
record "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
cat "$out/host.txt"
grep -E '^### |^test result' "$out/tests.txt" || true
[ "$hits" = 0 ] || exit 1
exit "$rc"
