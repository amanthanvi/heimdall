#!/usr/bin/env bash
# M03-U13 (m03-plan §4.1, §4.3): the macOS arm64 row on the build host. The M02 harness
# (tests/native/m02/run-macos.sh: check.sh with every workspace test, the observation pass,
# facts, owner digests, redaction, leak and canary scans; documented there) generalized for
# M03 rather than copied, then the Docker phase M03 adds:
#
#   1. tests/native/m02/run-macos.sh <out>/macos with the M03 case index's observation
#      targets (HM_HARNESS_DIR), its digest now covering the keychain search list too;
#   2. the M00-T03 Docker fixtures (tests/fixtures/ssh/up.sh: enrollable, enrollable2, ca1,
#      ca2 and the rest, every port on 127.0.0.1), owned by this run only after an exclusive
#      lock (tests/fixtures/ssh/runtime.owner.lock, an atomic mkdir) and a clean up.sh: exit 3
#      ("already exist", another run's) leaves everything untouched and the Docker rows
#      blocked; the container and image versions are recorded;
#   3. the Docker rows with HM_DOCKER_TESTS=1 (`#[ignore = "docker: …"]` tests:
#      integration_testkit_m03 docker_* and shell_containers_*, integration_enroll_verify
#      verify_on_account_without_log_access, integration_enroll_registry docker_*), each
#      cargo run's real exit code recorded, output kept (docker.txt);
#   4. tests/fixtures/ssh/down.sh, which must print CLEANUP CONFIRMED, then the lock is
#      released; redaction, leak and canary scans over the Docker artifacts.
#
# Usage: tests/native/m03/run-macos.sh <artifact-root>
#   writes <artifact-root>/macos/{check,observations,host,commands,canary-scan}.txt (the M02
#   harness) and <artifact-root>/macos/{docker,docker-commands,docker-host}.txt.
#   HM_SKIP_DOCKER=1  skip the Docker phase (its rows then stay blocked: "not run").
# Exit: the M02 harness's exit when nonzero; else 1 when a Docker step fails, down.sh does not
# confirm, or a canary or leak is found; 3 when the fixtures belong to another run; else 0.

set -euo pipefail
root=${1:?usage: run-macos.sh <artifact-root>}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/../m02/lib.sh"
mkdir -p "$root/macos"
out=$(cd "$root/macos" && pwd)
unset CARGO_TARGET_DIR

set +e
TMPDIR=/tmp HM_HARNESS_DIR="$here" bash "$here/../m02/run-macos.sh" "$out"
mrc=$?
set -e
[ "$mrc" = 0 ] || exit "$mrc"
[ "${HM_SKIP_DOCKER:-0}" = 1 ] && { echo "docker phase skipped (HM_SKIP_DOCKER=1)"; exit 0; }

commands="$out/docker-commands.txt"
: >"$commands"
scratch=$(mktemp -d /tmp/hm-m03-docker.XXXXXX)
scratch=$(cd "$scratch" && pwd -P)
chmod 700 "$scratch"
owner_lock="$repo/tests/fixtures/ssh/runtime.owner.lock"
lock_held=0
docker_up=0
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    set +e
    if [ "$docker_up" = 1 ]; then
        bash "$repo/tests/fixtures/ssh/down.sh" >"$scratch/down.txt" 2>&1
        drc=$?
        grep -q '^CLEANUP CONFIRMED$' "$scratch/down.txt" && cc=0 || cc=1
        m02_record "$commands" "tests/fixtures/ssh/down.sh (exit $drc) printed CLEANUP CONFIRMED" "$cc"
        [ "$cc" = 0 ] || rc=1
    fi
    if [ "$lock_held" = 1 ]; then
        rmdir -- "$owner_lock"
        m02_record "$commands" "release the Docker fixture ownership lock" "$?"
    fi
    lhost=$(hostname)
    lshort=$(hostname -s 2>/dev/null || echo "$lhost")
    for f in docker docker-host; do
        [ -f "$scratch/$f.raw" ] || continue
        m02_redact "$scratch/$f.raw" "$out/$f.txt" "$scratch" "<scratch>" "$repo" "<repo>" "${TMPDIR:-/tmp}" "<tmp>" \
            "$HOME" "<home>" --word "$lhost" "<host>" --word "$lshort" "<host>" "$(id -un)" "<user>"
    done
    hits=$(find "$out" -name 'docker*.txt' -type f -exec grep -a -o 'HEIMDALL_CANARY_' {} + 2>/dev/null | wc -l | tr -d ' ')
    m02_record "$commands" "canary-prefix scan over the Docker artifacts (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
    [ "$hits" = 0 ] || rc=1
    leaks=$(m02_leak_scan "$out" "$HOME" --word "$lhost" --word "$lshort" "$(id -un)") && lrc=0 || lrc=$?
    m02_record "$commands" "leak scan over macos/ after the Docker phase ($leaks)" "$lrc"
    [ "$lrc" = 0 ] || rc=1
    rm -rf -- "$scratch"
    exit "$rc"
}
trap cleanup EXIT

if ! mkdir -- "$owner_lock" 2>/dev/null; then
    echo "docker=blocked: another run holds the Docker fixture lock; nothing touched" >"$scratch/docker-host.raw"
    m02_record "$commands" "Docker fixture lock held by another run: nothing touched, Docker rows blocked" 3
    exit 3
fi
lock_held=1
{
    echo "docker-server=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
    echo "docker-client=$(docker version --format '{{.Client.Version}}' 2>/dev/null || echo unavailable)"
} >"$scratch/docker-host.raw"
set +e
bash "$repo/tests/fixtures/ssh/up.sh" >"$scratch/up.txt" 2>&1
urc=$?
set -e
m02_record "$commands" "tests/fixtures/ssh/up.sh (M00-T03 Docker fixtures, 127.0.0.1 only)" "$urc"
if [ "$urc" = 3 ]; then
    echo "docker=blocked: the Docker fixtures already exist (another run's); left untouched, no teardown" >>"$scratch/docker-host.raw"
    exit 3
fi
docker_up=1
[ "$urc" = 0 ] || exit 1
# The containers this run started, by label: image digest and OpenSSH version only.
docker ps --filter label=heimdall.fixture=m00-t03 --format '{{.Names}}' 2>/dev/null | sort | while read -r c; do
    case "$c" in '' | *[!A-Za-z0-9._-]*) continue ;; esac
    v=$(docker exec "$c" sh -c 'ssh -V 2>&1; . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"' 2>/dev/null | tr '\n' ' ') || v=unavailable
    echo "docker-container-$c=$v"
done >>"$scratch/docker-host.raw"

run_docker() {
    local what=$1
    shift
    set +e
    (cd "$repo" && TMPDIR="$scratch" HM_DOCKER_TESTS=1 cargo test --locked --no-fail-fast "$@") >>"$scratch/docker.raw" 2>&1
    local rc=$?
    set -e
    m02_record "$commands" "HM_DOCKER_TESTS=1 cargo test $what" "$rc"
}
: >"$scratch/docker.raw"
run_docker "-p heimdall-testkit --features fixtures,managed --test integration_testkit_m03 -- --ignored docker_ shell_containers_ --show-output" \
    -p heimdall-testkit --features fixtures,managed --test integration_testkit_m03 -- --ignored docker_ shell_containers_ --show-output
run_docker "-p heimdall-enroll --test integration_enroll_verify -- --ignored --exact verify_on_account_without_log_access --show-output" \
    -p heimdall-enroll --test integration_enroll_verify -- --ignored --exact verify_on_account_without_log_access --show-output
run_docker "-p heimdall-enroll --test integration_enroll_registry -- --ignored docker_ --show-output" \
    -p heimdall-enroll --test integration_enroll_registry -- --ignored docker_ --show-output
grep -q '^exit [^0]' "$commands" && exit 1
exit 0
