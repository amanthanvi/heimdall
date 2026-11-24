#!/usr/bin/env bash
# M02-U11 (m02-plan §4): cross-build every workspace test binary, the heimdall CLI and
# hm-fixture-hook for x86_64-unknown-linux-gnu on the build host, run them natively on
# one of the owner's Linux x86-64 hosts over the owner's own ssh config, and save
# redacted output. Generalized from tests/native/m01/run-linux.sh.
#
# Usage: tests/native/m02/run-linux.sh <artifact-dir> <ssh-host-alias>
#   HM_BUILD_ONLY  1 = cross-build, plan and record the binaries' hashes, then stop (no ssh)
#   HM_ONLY        optional space-separated list of test target names to run (default: all)
#   HM_TIMEOUT_S   per-binary timeout in seconds (default 1800)
#   ⟨M06 exit⟩ HM_STAGE_MAX_KB optional cap (KiB) on the staged set (the binaries, both CLIs,
#                  hm-fixture-hook and the repository files, links dereferenced): measured with
#                  `du -skL` before the tar stream; over it, exit 7 and nothing is copied
#                  (tests/native/m06/run-linux-batches.sh sets it per batch). Unset: no cap.
#   ⟨M03 wave 6⟩ The milestone's harness (tests/native/m03/run-linux.sh sets these):
#   HM_HARNESS_DIR the directory holding case-index.json and the evidence generator
#                  (default: this directory)
#   HM_EVIDENCE    the generator's file name there (default m02-evidence.py)
#   HM_RUN_PREFIX  the scratch directory prefix, hm-m0<N> (default hm-m02)
#   HM_EXTRA_REMOTE a file of bash defining hm_extra_facts, sent with remote-lib.sh and
#                  run on the host after the version facts (key=value lines only)
#   ⟨M06 W5c⟩ HM_FEATURE_UNIT comma-separated package names (tests/native/m06/run-linux.sh sets
#                  `heimdall-transport-iroh`): with HM_FEATURE, each package's own unit tests are
#                  built with the feature too and run as `<crate>-unit` in place of the
#                  default-feature build's (lib.sh m02_feature_build, M02_FEATURE_UNIT).
#   ⟨M06 W5⟩ HM_FEATURE a Cargo feature (tests/native/m06/run-linux.sh sets `iroh`): after the
#                  workspace build, the test targets whose required-features name it are
#                  built too (lib.sh m02_feature_build) and run with the others. They run
#                  against that build's own heimdall (feature/heimdall in the scratch
#                  directory); every other target keeps the default-feature one. A feature
#                  target that does not build is recorded as `feature-blocked-<target>=<reason>`
#                  in host.txt (the evidence row is blocked on it) and the harness exits 6
#                  when nothing else failed. Unset: nothing changes.
#
# Steps:
#   1. `uname -m` on the host (anything but x86_64 stops with exit 3, nothing copied).
#   2. Cross-build with zig (`zig cc -target x86_64-linux-gnu.2.31`) as linker and as C
#      compiler for the bundled SQLite, through shims in a mktemp directory removed on exit.
#   3. The run plan from case-index.json `build_host_paths`: a test that truly needs the
#      build host is skipped with `--exact --skip` and listed in skipped.txt with its reason
#      (platform-neutral, run on the build host; or a harness gap, which keeps the evidence
#      row in_progress). Tests that read repository files read them through HM_REPO_ROOT
#      (ADR-0007 §12.32 item 3), so they run here.
#   4. A fresh scratch directory ~/hm-m02-<random> (plain mkdir, never reused), created
#      before anything is copied. Only that exact directory is removed at the end, pass or
#      fail, and its absence is checked.
#   5. One tar stream copies the binaries, heimdall (HEIMDALL_E2E_BIN),
#      hm-fixture-hook (HM_FIXTURE_HOOK, also found next to the test binaries) and the
#      repository files the tests read (lib.sh M02_REPO_DIRS) as repo/ (HM_REPO_ROOT).
#   6. On the host: inherited agent, Git and Heimdall variables are unset; `ssh -V`,
#      `sshd -V`, `git --version` (scratch HOME, GIT_CONFIG_NOSYSTEM=1), script(1), the
#      scratch file system type are recorded; a preflight starts the fixture sshd (the
#      same configuration as heimdall-testkit's LoopbackSshd: non-root, 127.0.0.1 only,
#      per-run host key in scratch) and stops it by exact PID; every binary runs with
#      `timeout` and `nice -n 10`, with `--show-output` (the `observation` lines of the tests
#      that settle ADR-0007 facts), TMPDIR inside scratch, its real exit code recorded.
#      The tests start their own LoopbackSshd and disposable ssh-agent (scratch HOME)
#      the same way. A metadata digest of ~/.ssh and the Git configuration files is
#      taken before and after (names and contents never printed): unchanged means
#      nothing wrote there.
#   7. Redaction (<linuxhost> as whole words only, <user>, <home>, the build host's
#      <home>/<user>), a leak scan for those values and a canary scan over every saved
#      artifact.
#
# Nothing is installed or elevated; no service is touched; no listener other than the
# loopback fixture sshd and owner-only Unix sockets inside the scratch TMPDIR is created;
# the host's ~/.ssh, Git configuration and agent are never used. Only processes this
# run started exist (the binaries and their own children); leftovers are counted, never
# signalled by name.
#
# No CARGO_TARGET_DIR override: the workspace ./target is used (AGENTS.md); remove
# target/x86_64-unknown-linux-gnu afterwards to keep it small.
#
# Output (redacted): build.txt (build log, sha256 per binary, toolchain), host.txt,
# tests.txt (every binary's output, then "### <target> exit=N"), commands.txt (each
# command with its real exit code), skipped.txt, canary-scan.txt. Exit: nonzero when a
# binary fails, a required step fails, or a canary or leak is found.

set -euo pipefail

out=${1:?usage: run-linux.sh <artifact-dir> <ssh-host-alias>}
build_only=${HM_BUILD_ONLY:-0}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/lib.sh"
host=""
if [ "$build_only" != 1 ]; then
    host=${2:?usage: run-linux.sh <artifact-dir> <ssh-host-alias>}
    m02_valid_alias "$host" || { echo "bad host alias" >&2; exit 2; }
fi
timeout_s=${HM_TIMEOUT_S:-1800}
stage_max_kb=${HM_STAGE_MAX_KB:-}
case "$stage_max_kb" in *[!0-9]*) echo "bad HM_STAGE_MAX_KB" >&2; exit 2 ;; esac
case "$timeout_s" in '' | *[!0-9]*) echo "bad HM_TIMEOUT_S" >&2; exit 2 ;; esac
triple=x86_64-unknown-linux-gnu
repo=$(cd "$here/../../.." && pwd)
hdir=${HM_HARNESS_DIR:-$here}
M02_EVIDENCE=${HM_EVIDENCE:-m02-evidence.py}
prefix=${HM_RUN_PREFIX:-hm-m02}
case "$prefix" in hm-m0[0-9]) ;; *) echo "bad HM_RUN_PREFIX" >&2; exit 2 ;; esac
extra=${HM_EXTRA_REMOTE:-}
feature=${HM_FEATURE:-}
case "$feature" in *[!a-z0-9-]*) echo "bad HM_FEATURE" >&2; exit 2 ;; esac
feature_unit=${HM_FEATURE_UNIT:-}
case "$feature_unit" in *[!a-z0-9,-]*) echo "bad HM_FEATURE_UNIT" >&2; exit 2 ;; esac
[ -z "$feature_unit" ] || [ -n "$feature" ] || { echo "HM_FEATURE_UNIT needs HM_FEATURE" >&2; exit 2; }
[ -z "$extra" ] || [ -f "$extra" ] || { echo "HM_EXTRA_REMOTE is not a file" >&2; exit 2; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
unset CARGO_TARGET_DIR

shim=$(mktemp -d)
scratch=""
commands="$out/commands.txt"
: >"$commands"
rssh() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$host" "$@"; }
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    if [ -n "$scratch" ]; then
        # Only the directory this run created (exact name, never a glob).
        set +e
        rssh "rm -rf -- \"\$HOME/$scratch\" && test ! -e \"\$HOME/$scratch\"" </dev/null
        m02_record "$commands" "ssh <linuxhost> rm -rf the run's scratch dir, then check it is absent" "$?"
    fi
    rm -rf "$shim"
    exit "$rc"
}
trap cleanup EXIT

if [ "$build_only" != 1 ]; then
    set +e
    arch=$(rssh 'uname -m' </dev/null 2>"$shim/arch.err")
    rc=$?
    set -e
    m02_record "$commands" "ssh <linuxhost> uname -m" "$rc"
    if [ "$rc" != 0 ]; then
        # The error text may name the host, the user or an address: keep its shape only.
        m02_redact "$shim/arch.err" "$out/host-unreachable.txt" --word "$host" "<linuxhost>" "$(id -un)" "<user>" "$HOME" "<home>"
        cat "$out/host-unreachable.txt" >&2
        exit 4
    fi
    echo "uname -m: $arch" >"$shim/host-arch.txt"
    if [ "$arch" != x86_64 ]; then
        echo "host architecture $arch is not x86_64: skipped (binaries are $triple)" >>"$shim/host-arch.txt"
        cp "$shim/host-arch.txt" "$out/host.txt"
        exit 3
    fi
fi

m02_write_shims "$(m02_shim_dir "$repo")"
cd "$repo"
set +e
m02_cargo_build "$triple" "$shim" "$out/build.txt"
rc=$?
set -e
m02_record "$commands" "cargo test --target $triple --profile ${HM_CARGO_PROFILE:-native-test} --workspace --no-run --locked (zig cc linker/CC shims at the stable shim directory)" "$rc"
redact_build_log() { m02_redact "$out/build.txt" "$out/build.txt" "$shim" "<shim>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" "$(id -un)" "<user>"; }
[ "$rc" = 0 ] || { redact_build_log; exit "$rc"; }
m02_artifacts "$shim" || { echo "the heimdall or hm-fixture-hook binary was not built" >&2; redact_build_log; exit 5; }
feature_rc=0
: >"$shim/feature-facts.txt"
if [ -n "$feature" ]; then
    set +e
    M02_FEATURE_UNIT=$feature_unit m02_feature_build "$triple" "$shim" "$out/build.txt" "$feature"
    feature_rc=$?
    set -e
    case "$feature_rc" in
        0) m02_record "$commands" "cargo test --target $triple --profile ${HM_CARGO_PROFILE:-native-test} -p <package> --features $feature --test <each target that requires it> --no-run --locked${feature_unit:+, and --lib for the unit tests of $feature_unit} ($(wc -l <"$shim/feature.tsv" | tr -d ' ') targets built)" 0 ;;
        6) m02_record "$commands" "record the $feature-feature targets that did not build as blocked ($(wc -l <"$shim/feature-blocked.tsv" | tr -d ' '); host.txt feature-blocked-<target> keeps cargo's exit code and first error)" 0 ;;
        *) m02_record "$commands" "list and build the test targets that require feature $feature" "$feature_rc"
           redact_build_log
           exit "$feature_rc" ;;
    esac
    m02_feature_facts "$shim" "$feature" >"$shim/feature-facts.raw"
    m02_redact "$shim/feature-facts.raw" "$shim/feature-facts.txt" "$shim" "<shim>" "${TMPDIR:-/tmp}" "<tmp>" "$HOME" "<home>" "$(id -un)" "<user>"
fi
set +e
m02_plan "$hdir" linux "$shim" "$out"
rc=$?
set -e
m02_record "$commands" "run plan from case-index.json build_host_paths" "$rc"
[ "$rc" = 0 ] || exit "$rc"
if [ -n "${HM_ONLY:-}" ]; then
    awk -F'\t' -v only=" ${HM_ONLY} " 'index(only, " " $1 " ") { print; next } { print $1 ": not selected (HM_ONLY)" > "/dev/stderr" }' \
        "$shim/run.tsv" >"$shim/run.only" 2>>"$out/skipped.txt"
    mv "$shim/run.only" "$shim/run.tsv"
fi
m02_hashes "$shim" "$out" ""
if [ -s "$shim/feature-cli.txt" ]; then
    echo "heimdall ($feature feature; HEIMDALL_E2E_BIN for the targets that require it) sha256: $(shasum -a 256 "$(cat "$shim/feature-cli.txt")" | cut -d' ' -f1)" >>"$out/build.txt"
fi
echo "toolchain: $(rustc --version); zig $(zig version); target $triple (glibc floor 2.31)" >>"$out/build.txt"
if [ "$build_only" = 1 ]; then
    cat "$shim/feature-facts.txt" >>"$out/build.txt"
    redact_build_log
    echo "test binaries planned: $(wc -l <"$shim/run.tsv" | tr -d ' '); skipped entries: $(wc -l <"$out/skipped.txt" | tr -d ' ')"
    [ "$feature_rc" = 0 ] || { cat "$shim/feature-facts.txt"; exit "$feature_rc"; }
    exit 0
fi

# The scratch directory: created exclusively, remembered only after the creation succeeded.
name="$prefix-$(m02_random_hex 6)"
set +e
rssh "mkdir -m 700 -- \"\$HOME/$name\" && mkdir -m 700 -- \"\$HOME/$name/tmp\"" </dev/null
rc=$?
set -e
m02_record "$commands" "ssh <linuxhost> mkdir (exclusive) ~/$prefix-<random> and its tmp" "$rc"
[ "$rc" = 0 ] || exit 1
scratch=$name

m02_stage "$shim" ""
if [ -n "$feature" ]; then
    # The feature targets' names, and that build's own CLI beside the default one.
    cut -f1 "$shim/feature.tsv" >"$shim/stage/feature-targets.txt"
    if [ -s "$shim/feature-cli.txt" ]; then
        mkdir "$shim/stage/feature" && ln -s "$(cat "$shim/feature-cli.txt")" "$shim/stage/feature/heimdall"
    fi
fi
set +e
nrepo=$(m02_stage_repo "$repo" "$shim/stage")
rc=$?
set -e
m02_record "$commands" "stage the repository files the tests read (HM_REPO_ROOT: $nrepo files)" "$rc"
[ "$rc" = 0 ] || exit 1
if [ -n "$stage_max_kb" ]; then
    # ⟨M06 exit⟩ The staged set's size (links dereferenced, as tar -h sends it), checked
    # before anything is copied: over the cap, exit 7 with nothing sent.
    staged_kb=$(du -skL "$shim/stage" | cut -f1)
    if [ "$staged_kb" -gt "$stage_max_kb" ]; then
        m02_record "$commands" "staged set ${staged_kb} KiB, over the HM_STAGE_MAX_KB cap of ${stage_max_kb} KiB: nothing copied" 7
        echo "the staged set is ${staged_kb} KiB, over the HM_STAGE_MAX_KB cap of ${stage_max_kb} KiB" >&2
        exit 7
    fi
    m02_record "$commands" "staged set ${staged_kb} KiB (HM_STAGE_MAX_KB cap ${stage_max_kb} KiB)" 0
fi
set +e
tar -C "$shim/stage" -chf - . | gzip -1 | rssh "tar -xzf - -C \"\$HOME/$scratch\""
rc=$?
set -e
m02_record "$commands" "tar stream of $(wc -l <"$shim/run.tsv" | tr -d ' ') test binaries, heimdall, hm-fixture-hook and the repository files into the scratch dir" "$rc"
[ "$rc" = 0 ] || exit 1
names=$(cut -f1 "$shim/run.tsv" | tr '\n' ' ')

set +e
# shellcheck disable=SC2086  # names are [A-Za-z0-9_-] target names
{ cat "$here/remote-lib.sh"; if [ -n "$extra" ]; then cat "$extra"; else echo 'hm_extra_facts() { :; }'; fi; cat <<'REMOTE'; } | rssh bash -s -- "$scratch" "$timeout_s" $names >"$shim/remote.txt" 2>&1
main() {
set -u
scratch=$HOME/$1
timeout_s=$2
shift 2
bins=$*
cd "$scratch" || return 1
hm2_sanitize_env
export TMPDIR=$scratch/tmp
echo "os=$(uname -srm)"
echo "glibc=$(ldd --version 2>&1 | head -1)"
echo "nproc=$(nproc)"
echo "script=$(command -v script >/dev/null 2>&1 && script --version 2>&1 | head -1 || echo absent)"
echo "scratch-fs=$(hm2_fs_type "$scratch")"
hm2_versions "$scratch"
hm_extra_facts "$scratch"
echo "owner-ssh-before=$(hm2_owner_digest "$HOME/.ssh")"
echo "owner-git-before=$(hm2_owner_digest "$HOME/.gitconfig" "${XDG_CONFIG_HOME:-$HOME/.config}/git/config")"
if hm2_sshd_start "$scratch/sshd-preflight" "$scratch/sshd-preflight.keys" "$scratch/sshd-preflight.log"; then
    echo "fixture-sshd-preflight=listening on 127.0.0.1 (non-root, per-run host key)"
    hm2_sshd_stop
    echo "fixture-sshd-preflight-stopped=yes"
else
    echo "fixture-sshd-preflight=unavailable: $HM2_SSHD_WHY"
fi
chmod 700 ./heimdall ./hm-fixture-hook
export HEIMDALL_E2E_BIN=$scratch/heimdall HM_FIXTURE_HOOK=$scratch/hm-fixture-hook
# ⟨M06 W5⟩ HM_FEATURE: the feature build's own CLI, for the targets feature-targets.txt names.
fbin=""
if [ -f "$scratch/feature/heimdall" ]; then
    chmod 700 "$scratch/feature/heimdall"
    fbin=$scratch/feature/heimdall
fi
# The repository files the tests read (heimdall_testkit::repo; ADR-0007 §12.32 item 3).
[ -d "$scratch/repo" ] || { echo "the repository copy is missing"; return 1; }
export HM_REPO_ROOT=$scratch/repo
echo "---tests---"
arc=0
for b in "$@"; do
    chmod 700 "./$b"
    set --
    while IFS="$(printf '\t')" read -r t n; do
        [ "$t" = "$b" ] && set -- "$@" --skip "$n"
    done <skips.tsv
    [ $# -gt 0 ] && set -- --exact "$@"
    # --show-output keeps the `observation` lines of passing tests (the settled [I]/[U] facts).
    set -- "$@" --show-output
    HEIMDALL_E2E_BIN=$scratch/heimdall
    if [ -n "$fbin" ] && grep -qxF -- "$b" "$scratch/feature-targets.txt" 2>/dev/null; then
        HEIMDALL_E2E_BIN=$fbin
    fi
    echo "### $b"
    timeout "$timeout_s" nice -n 10 "./$b" "$@" 2>&1
    brc=$?
    echo "### $b exit=$brc"
    [ "$brc" = 0 ] || arc=$brc
done
echo "all-tests-exit=$arc"
echo "---after---"
leftover=0
for b in heimdall hm-fixture-hook ${fbin:+feature/heimdall} $bins; do
    # Count only (nothing is signalled): processes still running a binary of this run.
    n=$(pgrep -u "$(id -u)" -f "^$scratch/$b( |\$)|^\./$b( |\$)" 2>/dev/null | wc -l)
    leftover=$((leftover + n))
done
echo "leftover-test-processes=$leftover"
echo "owner-ssh-after=$(hm2_owner_digest "$HOME/.ssh")"
echo "owner-git-after=$(hm2_owner_digest "$HOME/.gitconfig" "${XDG_CONFIG_HOME:-$HOME/.config}/git/config")"
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
m02_record "$commands" "remote: every test binary under timeout $timeout_s and nice -n 10 (overall exit = last failing binary's exit, 0 if all passed)" "$rc"

red=$(sed -n '/^---redaction---$/,$p' "$shim/remote.txt")
val() { printf '%s\n' "$red" | sed -n "s/^$1=//p" | head -1; }
rhome=$(val rhome); rfqdn=$(val rfqdn); rhost=$(val rhost); ruser=$(val ruser)
sed '/^---redaction---$/,$d' "$shim/remote.txt" >"$shim/remote.body"
m02_redact "$shim/remote.body" "$shim/redacted.txt" "$rhome" "<home>" "$HOME" "<home>" --word "$rfqdn" "<linuxhost>" \
    --word "$rhost" "<linuxhost>" --word "$host" "<linuxhost>" "$ruser" "<user>" "$(id -un)" "<user>"
sed -i.bak -E "s/$prefix-[0-9a-f]{12}/$prefix-<random>/g" "$shim/redacted.txt" && rm -f "$shim/redacted.txt.bak"
{
    sed -n '1,/^---tests---$/p' "$shim/redacted.txt" | sed '$d'
    cat "$shim/host-arch.txt"
    cat "$shim/feature-facts.txt"
    sed -n '/^---after---$/,$p' "$shim/redacted.txt" | sed '1d'
} >"$out/host.txt"
sed -n '/^---tests---$/,/^---after---$/p' "$shim/redacted.txt" | sed '1d;$d' >"$out/tests.txt"
redact_build_log

before=$(sed -n 's/^owner-ssh-before=//p' "$out/host.txt")$(sed -n 's/^owner-git-before=//p' "$out/host.txt")
after=$(sed -n 's/^owner-ssh-after=//p' "$out/host.txt")$(sed -n 's/^owner-git-after=//p' "$out/host.txt")
same=1
[ -n "$before" ] && [ "$before" = "$after" ] || same=0
m02_record "$commands" "host ~/.ssh and Git configuration metadata unchanged by the run" "$([ "$same" = 1 ] && echo 0 || echo 1)"
hits=$(m02_canary_scan "$out")
m02_record "$commands" "canary-prefix scan over saved output (count = $hits)" "$([ "$hits" = 0 ] && echo 0 || echo 1)"
set +e
leaks=$(m02_leak_scan "$out" "$rhome" "$HOME" --word "$rfqdn" --word "$rhost" --word "$host" "$ruser" "$(id -un)")
lrc=$?
set -e
m02_record "$commands" "leak scan: saved files still naming the host, user or a home ($leaks)" "$lrc"
cat "$out/host.txt"
grep -E '^### |^test result' "$out/tests.txt" || true
[ "$hits" = 0 ] && [ "$lrc" = 0 ] && [ "$same" = 1 ] || exit 1
[ "$rc" = 0 ] || exit "$rc"
# ⟨M06 W5⟩ 6: everything that ran passed, but a feature target did not build (blocked).
exit "$feature_rc"
