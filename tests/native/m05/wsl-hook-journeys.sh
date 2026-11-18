#!/usr/bin/env bash
# M05-U10 (m05-plan §3, ruling I-19): the shell-hook journeys inside one disposable WSL
# distribution, as its non-root user, against the Linux build cross-built on the build host.
# Run by a distribution manager (the Mode B harness's pattern: one `hm-m05-<8 hex>` distribution
# created and unregistered by exact name); nothing here creates, stops or unregisters a distribution.
#
#   wsl-hook-journeys.sh SCRATCH BINDIR
#
# SCRATCH  a new directory for this run (created here exclusively, mode 700; must not exist; at
#          most 64 bytes long, for the runtime's Unix socket paths). Removed at the end, pass or
#          fail (only the directory this run created), unless HM_KEEP_SCRATCH=1.
# BINDIR   the staged build, laid out as tests/native/m02/run-linux.sh stages it:
#            heimdall                           the Linux binary under test (HEIMDALL_E2E_BIN)
#            hm-fixture-hook                    the fixture hook binary (HM_FIXTURE_HOOK)
#            e2e_cli_m05, e2e_hook_m05,
#            adversarial_prompt_injection_cli   the Linux test binaries
#            repo/                              the repository files the tests read (HM_REPO_ROOT;
#                                               tests/native/m02/lib.sh m02_stage_repo)
#          remote-lib.sh (tests/native/m02) must sit next to this script, or in ../m02/.
#
# What the manager must provide before it runs (root, in this distribution only):
#   * `zsh` installed (`apt-get install -y --no-install-recommends zsh`, as M02's HM_WSL_ALLOW_APT
#     phase does for its packages) so that /bin/zsh exists beside /bin/bash; the step
#     m05_wsl_bash_and_zsh_present fails without both, and then no shell step is trusted;
#   * `openssh-server` (sshd), `openssh-client`, `git` and `script` (util-linux), as M02/M03 need
#     them; the fixture sshd runs as this non-root user on 127.0.0.1 only;
#   * WSL_DISTRO_NAME in this script's environment (WSL sets it); the script refuses to run in a
#     distribution whose name is not hm-m05-<8 hex>.
# It passes: SCRATCH BINDIR, a home that is itself disposable (the distribution is unregistered
# afterwards), and no SSH_AUTH_SOCK, Heimdall or Git variable (hm2_sanitize_env drops them).
#
# Steps, each printed as `test <step> ... ok|FAILED` under `### wsl_hook_m05`
# (case-index.json scenario_targets; m05-evidence.py reads them like cargo tests):
#   m05_wsl_bash_and_zsh_present                       /bin/bash and /bin/zsh exist
#   m05_wsl_hook_never_evaluates_repository_text       e2e_cli_m05 (real bash and zsh on a pty)
#   m05_wsl_hook_creates_no_decision_when_uncovered    e2e_cli_m05
#   m05_wsl_hook_warms_the_default_so_the_first_ordinary_ssh_logs_in   e2e_hook_m05
#   m05_wsl_hook_warm_up_creates_no_decision_when_the_default_does_not_cover   e2e_hook_m05
#   m05_wsl_hook_without_a_runtime_prints_nothing_and_starts_none      e2e_hook_m05
#   m05_wsl_a29_hook_ignores_a_hostile_environment     adversarial_prompt_injection_cli
#   m05_wsl_no_leftover_processes                      no process of this run's binaries is left
# A step that runs a test binary passes only when the binary exits 0 and prints `test <name> ... ok`
# for exactly that test (`--exact`), so a test that is filtered out, ignored or absent never passes.
# The inner `test ...` lines are not repeated here (they would read as results of this target); their
# `observation` lines are kept under a `---- <step> stdout ----` header, and a failing step's last
# lines are kept after `detail`, prefixed so no line reads as a test result.
#
# HM_SCENARIO_ISOLATED=1 (build-host self-test only) skips the distribution-name guard and allows
# HM_SCENARIO_SHELLS (a space-separated list of shell paths to require) in place of /bin/bash and
# /bin/zsh. Everything else is as in the distribution: the tests keep their own isolation (a cleared
# environment, scratch homes, the decoy agent); no owner key, agent, keychain or ~/.ssh is touched.
#
# Output: step lines, `fact <name>=<value>` lines (versions, counts; never a key, an environment
# value or a path outside scratch) and `### wsl_hook_m05 exit=<n>`. Exit: 0 when every step passed,
# 1 otherwise, 2 for a refused start.

# The `[ ... ] && [ ... ]` conditions before `step NAME "$?"` are the step results.
# shellcheck disable=SC2319
set -u
here=$(cd "$(dirname "$0")" && pwd)
if [ -f "$here/remote-lib.sh" ]; then
    # shellcheck source=tests/native/m02/remote-lib.sh
    . "$here/remote-lib.sh"
elif [ -f "$here/../m02/remote-lib.sh" ]; then
    # shellcheck source=tests/native/m02/remote-lib.sh
    . "$here/../m02/remote-lib.sh"
else
    echo "remote-lib.sh is missing (next to this script or in ../m02/)" >&2
    exit 2
fi
S=${1:?usage: wsl-hook-journeys.sh SCRATCH BINDIR}
B=${2:?usage: wsl-hook-journeys.sh SCRATCH BINDIR}
isolated=${HM_SCENARIO_ISOLATED:-0}
shells=${HM_SCENARIO_SHELLS:-"/bin/bash /bin/zsh"}
[ "$isolated" = 1 ] || shells="/bin/bash /bin/zsh"

if [ "$isolated" != 1 ]; then
    case "${WSL_DISTRO_NAME:-}" in
        hm-m05-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
        *) echo "refused: not inside a disposable hm-m05-<8 hex> distribution" >&2; exit 2 ;;
    esac
    # Exactly 8 hex digits after the prefix (the case pattern above fixes the length).
fi
[ "$(id -u)" != 0 ] || { echo "refused: run as the disposable non-root user" >&2; exit 2; }
[ -d "$B" ] || { echo "BINDIR is not a directory" >&2; exit 2; }
mkdir -m 700 -- "$S" 2>/dev/null || { echo "scratch exists or cannot be created" >&2; exit 2; }
S=$(cd "$S" && pwd -P)
created=$S
if [ ${#S} -gt 64 ]; then
    rmdir -- "$S"
    echo "scratch path is too long for Unix socket paths (${#S} > 64 bytes)" >&2
    exit 2
fi

hm2_sanitize_env >/dev/null
mkdir -m 700 "$S/bin" "$S/out" "$S/tmp"
export TMPDIR="$S/tmp"

# Private copies of what runs: the leftover count at the end then names only this run's processes.
missing=""
for f in heimdall hm-fixture-hook e2e_cli_m05 e2e_hook_m05 adversarial_prompt_injection_cli; do
    if [ -f "$B/$f" ]; then
        cp -p -- "$B/$f" "$S/bin/$f" && chmod 700 "$S/bin/$f" || missing="$missing $f"
    else
        missing="$missing $f"
    fi
done
repo=""
[ -d "$B/repo" ] && repo="$B/repo"

cleanup() {
    # Only the directory this run created, by its exact recorded path.
    if [ "${HM_KEEP_SCRATCH:-0}" != 1 ] && [ -n "$created" ] && [ "$created" = "$S" ] && [ -d "$S" ] && [ ! -L "$S" ]; then
        rm -rf -- "$S"
    fi
}
trap cleanup EXIT HUP INT TERM

status=0
echo "### wsl_hook_m05"
step() {
    # step NAME RC: one test line; a nonzero RC fails the scenario.
    if [ "$2" = 0 ]; then
        echo "test $1 ... ok"
    else
        echo "test $1 ... FAILED"
        status=1
    fi
}

have_timeout=0
command -v timeout >/dev/null 2>&1 && have_timeout=1
HM_BIN="$S/bin/heimdall"
export HEIMDALL_E2E_BIN="$HM_BIN" HM_FIXTURE_HOOK="$S/bin/hm-fixture-hook"
[ -n "$repo" ] && export HM_REPO_ROOT="$repo"

# run_test STEP BINARY TEST [needs-shells]: run BINARY --exact TEST --show-output; ok only on exit 0
# and `test TEST ... ok`. A test that enters real shells skips the ones its /bin path lacks, so with
# `needs-shells` the step fails outright unless the shell precondition held.
run_test() {
    local sname=$1 bin=$2 name=$3 need=${4:-} out="$S/out/$1.txt" rc=0 n
    if [ "$need" = needs-shells ] && [ "$ok" != 0 ]; then
        echo "detail $sname: not run: bash and zsh are not both present"
        step "$sname" 1
        return
    fi
    if [ ! -x "$S/bin/$bin" ]; then
        echo "detail $sname: the test binary $bin was not provided"
        step "$sname" 1
        return
    fi
    (
        cd "$S" || exit 1
        if [ "$have_timeout" = 1 ]; then
            timeout "${HM_TEST_TIMEOUT_S:-900}" "$S/bin/$bin" --exact "$name" --show-output
        else
            "$S/bin/$bin" --exact "$name" --show-output
        fi
    ) >"$out" 2>&1 </dev/null || rc=$?
    # The result line of exactly this test (libtest prints the full path of a nested test; ours are top level).
    if [ "$rc" = 0 ] && grep -q "^test $name \.\.\. ok\$" "$out" && grep -q '^test result: ok\. 1 passed; 0 failed' "$out"; then
        n=0
    else
        n=1
    fi
    echo "detail $sname: $bin exit=$rc"
    echo "---- $sname stdout ----"
    grep -E '^[[:space:]]*(m0[35] )?observation' "$out" | head -40
    if [ "$n" != 0 ]; then
        # Prefixed so that no kept line reads as a test result or a header.
        tail -n 40 "$out" | sed 's/^/  | /'
    fi
    step "$sname" "$n"
}

# 1. The shells (zsh is installed in this distribution only, by the manager's root phase).
ok=0
for sh in $shells; do
    [ -x "$sh" ] || ok=1
done
if [ -x /bin/bash ]; then echo "fact shell-bash=$(/bin/bash --version 2>&1 | head -1 | tr -d '\r')"; else echo "fact shell-bash=absent"; fi
if [ -x /bin/zsh ]; then echo "fact shell-zsh=$(/bin/zsh --version 2>&1 | head -1 | tr -d '\r')"; else echo "fact shell-zsh=absent"; fi
[ "$ok" = 0 ]
step m05_wsl_bash_and_zsh_present "$?"
if hm2_sshd_bin >/dev/null; then echo "fact sshd=present"; else echo "fact sshd=absent"; fi
[ -z "$repo" ] && echo "fact repo-root=not provided"
[ -n "$missing" ] && echo "fact missing-binaries=$(echo "$missing" | sed 's/^ //; s/ /,/g')"

# 2-4. The journeys, one test each.
run_test m05_wsl_hook_never_evaluates_repository_text e2e_cli_m05 hook_never_evaluates_repository_text needs-shells
run_test m05_wsl_hook_creates_no_decision_when_uncovered e2e_cli_m05 hook_creates_no_decision_when_uncovered
run_test m05_wsl_hook_warms_the_default_so_the_first_ordinary_ssh_logs_in e2e_hook_m05 hook_warms_the_default_so_the_first_ordinary_ssh_logs_in
run_test m05_wsl_hook_warm_up_creates_no_decision_when_the_default_does_not_cover e2e_hook_m05 hook_warm_up_creates_no_decision_when_the_default_does_not_cover
run_test m05_wsl_hook_without_a_runtime_prints_nothing_and_starts_none e2e_hook_m05 hook_without_a_runtime_prints_nothing_and_starts_none
run_test m05_wsl_a29_hook_ignores_a_hostile_environment adversarial_prompt_injection_cli a29_cli_hook_ignores_a_hostile_environment needs-shells

# 5. Count what is left (never signalled by name): processes still running a binary of this run.
left=0
for b in heimdall hm-fixture-hook e2e_cli_m05 e2e_hook_m05 adversarial_prompt_injection_cli; do
    n=$(pgrep -u "$(id -u)" -f "^$S/bin/$b( |\$)" 2>/dev/null | wc -l | tr -d ' ')
    left=$((left + ${n:-0}))
done
echo "fact leftover-processes=$left"
[ "$left" = 0 ]
step m05_wsl_no_leftover_processes "$?"

trap - EXIT HUP INT TERM
cleanup
echo "### wsl_hook_m05 exit=$status"
exit "$status"
