#!/usr/bin/env bash
# M02-U11 (m02-plan §4): the macOS arm64 row on the build host: tools/validation/check.sh
# (every workspace test, the CLI e2e suites through CARGO_BIN_EXE_heimdall included) with
# the facts the evidence needs recorded around it.
#
# Usage: tests/native/m02/run-macos.sh <artifact-dir>
#   HM_BUILD_ONLY        1 = `cargo test --workspace --no-run` and the binaries' hashes only
#   HM_DOCKER_FALLBACK   0 = never start the Docker fixtures (default 1: only when the
#                        fixture sshd cannot run here)
#
# Steps:
#   1. A scratch directory (mktemp, mode 700), removed exactly at exit, pass or fail.
#   2. Facts: sw_vers, `uname -m`, `ssh -V`, `sshd -V`, `git --version` (scratch HOME,
#      GIT_CONFIG_NOSYSTEM=1), script(1), the file system of TMPDIR (APFS: exchange support
#      is recorded by the tests), and a metadata digest of ~/.ssh and the Git
#      configuration files before and after (never their names or contents).
#   3. Preflight: the fixture sshd (/usr/sbin/sshd as this non-root user, 127.0.0.1 only,
#      per-run host key in scratch; the configuration heimdall-testkit's LoopbackSshd uses)
#      starts and is stopped by exact PID. Only when it cannot start ([U]) are the M00-T03
#      Docker fixtures started (tests/fixtures/ssh/up.sh, every port on 127.0.0.1) and the
#      `fixed` role passed as HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY}; down.sh then has to print
#      CLEANUP CONFIRMED. Limitation: those containers' keys are set at up time, so no
#      HM_FIXTURE_SSHD_AUTHORIZED_KEYS is offered and a test that needs its own keys reports
#      the fixture unavailable.
#   4. check.sh with inherited agent, Git and Heimdall variables unset and TMPDIR inside
#      scratch (the tests start their own LoopbackSshd, disposable ssh-agent with a scratch
#      HOME, script(1) and rustix ptys), its real exit code recorded.
#   5. Redaction (<home>, <user>, <host>), a leak scan and a canary scan over every saved file.
#
#   6. The observation targets of the case index run once more with --show-output
#      (observations.txt): check.sh's own run discards what passing tests print.
#
# No CARGO_TARGET_DIR override (AGENTS.md). Output: check.txt, observations.txt, host.txt,
# build.txt (build only), commands.txt, canary-scan.txt. Exit: check.sh's exit when it
# fails, 1 when a canary, a leak or a changed ~/.ssh or Git configuration is found, else
# the observation pass's exit.

set -euo pipefail

out=${1:?usage: run-macos.sh <artifact-dir>}
build_only=${HM_BUILD_ONLY:-0}
docker_fallback=${HM_DOCKER_FALLBACK:-1}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/lib.sh"
# shellcheck source=tests/native/m02/remote-lib.sh
. "$here/remote-lib.sh"
mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR
commands="$out/commands.txt"
: >"$commands"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/hm-m02-macos.XXXXXX")
scratch=$(cd "$scratch" && pwd -P)
chmod 700 "$scratch"
docker_up=0
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    set +e
    hm2_sshd_stop
    if [ "$docker_up" = 1 ]; then
        bash "$repo/tests/fixtures/ssh/down.sh" >"$scratch/down.txt" 2>&1
        drc=$?
        grep -q '^CLEANUP CONFIRMED$' "$scratch/down.txt" && cc=0 || cc=1
        m02_record "$commands" "tests/fixtures/ssh/down.sh (exit $drc) printed CLEANUP CONFIRMED" "$cc"
        [ "$cc" = 0 ] || rc=1
    fi
    rm -rf -- "$scratch"
    [ ! -e "$scratch" ]
    m02_record "$commands" "remove exactly the run's scratch directory, then check it is absent" "$?"
    exit "$rc"
}
trap cleanup EXIT

cd "$repo"
if [ "$build_only" = 1 ]; then
    set +e
    m02_cargo_build host "$scratch" "$out/build.txt"
    rc=$?
    set -e
    m02_record "$commands" "cargo test --workspace --no-run --locked" "$rc"
    m02_redact "$out/build.txt" "$out/build.txt" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" "$(id -un)" "<user>"
    [ "$rc" = 0 ] || exit "$rc"
    m02_artifacts "$scratch" || { echo "the heimdall or hm-fixture-hook binary was not built" >&2; exit 5; }
    cp "$scratch/all.tsv" "$scratch/run.tsv"
    m02_hashes "$scratch" "$out" ""
    echo "toolchain: $(rustc --version); host $(uname -m)" >>"$out/build.txt"
    echo "test binaries: $(wc -l <"$scratch/run.tsv" | tr -d ' ')"
    exit 0
fi

facts="$scratch/host.raw"
{
    hm2_sanitize_env
    echo "os=$(sw_vers -productName 2>/dev/null || uname -s) $(sw_vers -productVersion 2>/dev/null || uname -r) ($(sw_vers -buildVersion 2>/dev/null || echo -)) $(uname -m)"
    echo "script=$([ -x /usr/bin/script ] && echo /usr/bin/script || echo absent)"
    echo "scratch-fs=$(hm2_fs_type "$scratch")"
    hm2_versions "$scratch"
    echo "owner-ssh-before=$(hm2_owner_digest "$HOME/.ssh")"
    echo "owner-git-before=$(hm2_owner_digest "$HOME/.gitconfig" "${XDG_CONFIG_HOME:-$HOME/.config}/git/config")"
} >"$facts"

if hm2_sshd_start "$scratch/sshd-preflight" "$scratch/sshd-preflight.keys" "$scratch/sshd-preflight.log"; then
    echo "fixture-sshd-preflight=listening on 127.0.0.1 (non-root, per-run host key)" >>"$facts"
    hm2_sshd_stop
    m02_record "$commands" "fixture sshd preflight (non-root, 127.0.0.1) started and stopped by exact PID" 0
else
    echo "fixture-sshd-preflight=unavailable: $HM2_SSHD_WHY" >>"$facts"
    m02_record "$commands" "fixture sshd preflight (non-root, 127.0.0.1): unavailable" 1
    if [ "$docker_fallback" = 1 ]; then
        set +e
        docker_up=1
        bash "$repo/tests/fixtures/ssh/up.sh" >"$scratch/up.txt" 2>&1
        urc=$?
        set -e
        m02_record "$commands" "tests/fixtures/ssh/up.sh (M00-T03 Docker fixtures, 127.0.0.1 only)" "$urc"
        [ "$urc" = 0 ] || exit "$urc"
        port=$(sed -n 's/^PORT_fixed=//p' "$repo/tests/fixtures/ssh/runtime/ports.env" | head -1)
        key=$(awk '{ print $1 " " $2 }' "$repo/tests/fixtures/ssh/runtime/hostkeys/fixed/ssh_host_ed25519_key.pub")
        case "$port" in '' | *[!0-9]*) echo "no fixture port" >&2; exit 1 ;; esac
        export HM_FIXTURE_SSHD_HOST=127.0.0.1 HM_FIXTURE_SSHD_PORT=$port HM_FIXTURE_SSHD_HOST_KEY=$key
        echo "fixture-sshd=Docker fallback (M00-T03 role fixed on 127.0.0.1; no per-test authorized keys)" >>"$facts"
    fi
fi

mkdir -m 700 "$scratch/tmp"
set +e
TMPDIR="$scratch/tmp" bash "$repo/tools/validation/check.sh" >"$scratch/check.raw" 2>&1
rc=$?
set -e
m02_record "$commands" "bash tools/validation/check.sh (TMPDIR in scratch; inherited agent, Git and Heimdall variables unset)" "$rc"

# check.sh's own run discards what passing tests print. The targets whose tests print
# `observation` lines (case-index.json observation_targets: the settled ADR-0007 facts) run
# once more through cargo with --show-output, their output kept as observations.txt.
obs_args=()
for t in $(jq -r '.observation_targets[]' "$here/case-index.json"); do
    case "$t" in *[!A-Za-z0-9_-]* | '') echo "bad observation target" >&2; exit 2 ;; esac
    obs_args+=(--test "$t")
done
[ ${#obs_args[@]} -gt 0 ] || { echo "case-index.json lists no observation_targets" >&2; exit 2; }
set +e
TMPDIR="$scratch/tmp" cargo test --workspace --locked --no-fail-fast "${obs_args[@]}" -- --show-output >"$scratch/obs.raw" 2>&1
orc=$?
set -e
m02_record "$commands" "cargo test --workspace --locked --no-fail-fast <the observation targets> -- --show-output (TMPDIR in scratch)" "$orc"

{
    n=0
    while IFS= read -r p; do
        case "$p" in '' | *[!0-9]*) continue ;; esac
        n=$((n + 1))
    done < <(pgrep -u "$(id -u)" -f "$scratch" 2>/dev/null || true)
    echo "leftover-test-processes=$n"
    echo "owner-ssh-after=$(hm2_owner_digest "$HOME/.ssh")"
    echo "owner-git-after=$(hm2_owner_digest "$HOME/.gitconfig" "${XDG_CONFIG_HOME:-$HOME/.config}/git/config")"
} >>"$facts"
lhost=$(hostname)
lshort=$(hostname -s 2>/dev/null || echo "$lhost")
# A very short host name would also match ordinary words (macOS, crate names).
[ ${#lshort} -ge 5 ] || lshort=$lhost
m02_redact "$facts" "$out/host.txt" "$scratch" "<scratch>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" \
    "$lhost" "<host>" "$lshort" "<host>" "$(id -un)" "<user>"
m02_redact "$scratch/check.raw" "$out/check.txt" "$scratch" "<scratch>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" \
    "$lhost" "<host>" "$lshort" "<host>" "$(id -un)" "<user>"
m02_redact "$scratch/obs.raw" "$out/observations.txt" "$scratch" "<scratch>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" \
    "$lhost" "<host>" "$lshort" "<host>" "$(id -un)" "<user>"

before=$(sed -n 's/^owner-ssh-before=//p;s/^owner-git-before=//p' "$out/host.txt" | tr '\n' ' ')
after=$(sed -n 's/^owner-ssh-after=//p;s/^owner-git-after=//p' "$out/host.txt" | tr '\n' ' ')
same=1
[ -n "$before" ] && [ "$before" = "$after" ] || same=0
m02_record "$commands" "the home .ssh directory and Git configuration metadata unchanged by the run" "$([ "$same" = 1 ] && echo 0 || echo 1)"
hits=$(m02_canary_scan "$out")
m02_record "$commands" "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
set +e
leaks=$(m02_leak_scan "$out" "$HOME" "$lhost" "$(id -un)")
lrc=$?
set -e
m02_record "$commands" "leak scan: saved files still naming the host, the user or the home ($leaks)" "$lrc"
cat "$out/host.txt"
grep -E '^== ' "$out/check.txt" || true
[ "$hits" = 0 ] && [ "$lrc" = 0 ] && [ "$same" = 1 ] || exit 1
[ "$rc" = 0 ] || exit "$rc"
exit "$orc"
