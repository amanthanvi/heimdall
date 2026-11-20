#!/usr/bin/env bash
# M05-U10: self-test of the M05 evidence harness, run by tools/validation/native-harness-selftest.sh.
# Reaches no host, builds nothing, starts no sshd and no real shell: the M02 scripts the wrappers
# call are stubs that print what they were given, and the "test binaries" of the WSL hook run are
# stub scripts that pass or fail on demand. Everything lives under one mktemp directory, removed on
# exit, pass or fail; the one process a check leaves behind on purpose is stopped by its exact PID.
#
# Checks:
#   m05_generator_*      the generator over synthetic logs (selftest_synthetic.py: a verified row, a
#                        failed test, a missing platform, a blocked row, a platform_only exclusion
#                        and its rationale, the WSL scenario row, HM_SKIP_TARGETS)
#   m05_wrapper_*        run-linux.sh, run-macos.sh, refresh-inventory.sh and run-windows-local.ps1
#                        reach the M02 scripts with the M05 settings (prefix hm-m05, the M05 case
#                        index and generator, no Docker phase, the PowerShell runner's own -SelfTest)
#   m05_wsl_hook_*       tests/native/m05/wsl-hook-journeys.sh in a fake world: the eight steps in
#                        the log format the generator reads and in the case index's names; a failed,
#                        filtered-out, missing or leftover step fails the run; zsh absent fails the
#                        shell steps; a run outside an hm-m05-<8 hex> distribution, onto an existing
#                        scratch directory or a too long path is refused before anything runs; the
#                        scratch directory is removed; the tests get a sanitized environment
# Prints one line per check and `m05-selftest: N passed, M failed`; exit 0 only when every check passed.

# The checks run their predicates through `bash -c` with single-quoted bodies on purpose.
# shellcheck disable=SC2016
set -u
here=$(cd "$(dirname "$0")" && pwd)
# Under /tmp, not the per-user TMPDIR: the scratch paths the WSL script accepts are short (Unix sockets).
T=$(mktemp -d /tmp/hm-m05-st.XXXXXX) || exit 2
T=$(cd "$T" && pwd -P)
trap 'rm -rf "$T"' EXIT
passes=0
fails=0
check() {
    local name=$1
    shift
    if "$@"; then
        echo "ok   $name"
        passes=$((passes + 1))
    else
        echo "FAIL $name"
        fails=$((fails + 1))
    fi
}
skip() { echo "skip $1 ($2)"; }

# --- the generator over synthetic logs ----------------------------------------------------------

PYTHONDONTWRITEBYTECODE=1 python3 -I "$here/selftest_synthetic.py" >"$T/gen.out" 2>&1
gen_rc=$?
gen_n=$(sed -n 's/^Ran \([0-9]*\) tests.*/\1/p' "$T/gen.out" | tail -1)
check "m05_generator_dry_runs_over_synthetic_logs (${gen_n:-0} tests: verified, failed, missing platform, blocked, platform_only, WSL scenario, skip)" \
    bash -c '[ "$1" = 0 ] && grep -q "^OK$" "$2"' _ "$gen_rc" "$T/gen.out"
[ "$gen_rc" = 0 ] || grep -E '^(FAIL|ERROR):' "$T/gen.out" | head -20

# --- the wrappers ----------------------------------------------------------------------------------

W="$T/wrap"
mkdir -p "$W/m02" "$W/m05"
for f in run-linux.sh run-macos.sh refresh-inventory.sh; do cp "$here/$f" "$W/m05/$f"; done
for s in run-linux run-macos refresh-inventory; do
    cat >"$W/m02/$s.sh" <<'EOF'
#!/usr/bin/env bash
# Stub of the M02 script: prints the settings the M05 wrapper gave it.
{
    echo "script=$(basename "$0")"
    echo "args=$*"
    echo "HM_HARNESS_DIR=${HM_HARNESS_DIR:-unset}"
    echo "HM_EVIDENCE=${HM_EVIDENCE:-unset}"
    echo "HM_RUN_PREFIX=${HM_RUN_PREFIX:-unset}"
    echo "HM_EXTRA_REMOTE=${HM_EXTRA_REMOTE:-unset}"
    echo "HM_SKIP_TARGETS=${HM_SKIP_TARGETS:-unset}"
    echo "TMPDIR=${TMPDIR:-unset}"
} >"$HM_ST_OUT"
EOF
done
wrap() {
    # wrap SCRIPT ARGS...: run an M05 wrapper in the stub tree; prints nothing, writes $W/out.
    local s=$1
    shift
    rm -f "$W/out"
    HM_ST_OUT="$W/out" bash "$W/m05/$s" "$@" >"$W/log" 2>&1
}
has() { grep -qxF -- "$1" "$W/out"; }

wrap run-linux.sh "$T/art" devbox-alias
check "m05_wrapper_linux_sets_the_m05_prefix_case_index_and_generator" \
    bash -c 'W=$1; grep -qxF "script=run-linux.sh" "$W/out" && grep -qxF "args=$2 devbox-alias" "$W/out" && grep -qxF "HM_RUN_PREFIX=hm-m05" "$W/out" &&
        grep -qxF "HM_EVIDENCE=m05-evidence.py" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m05" "$W/out" && grep -qxF "HM_EXTRA_REMOTE=unset" "$W/out"' _ "$W" "$T/art"
check "m05_wrapper_prefix_is_one_the_m02_scripts_accept" \
    bash -c 'p=hm-m05; case "$p" in hm-m0[0-9]) ;; *) exit 1 ;; esac; grep -q "hm-m0\[0-9\]" "$1/../m02/run-linux.sh" && grep -q "hm-m0\[0-9\]" "$1/../m02/run-wsl-distro.sh"' _ "$here"

wrap run-macos.sh "$T/art"
check "m05_wrapper_macos_runs_the_m02_harness_with_the_m05_index_and_no_docker_phase" \
    bash -c 'W=$1; grep -qxF "script=run-macos.sh" "$W/out" && grep -qxF "args=$2/macos" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m05" "$W/out" &&
        grep -qxF "TMPDIR=/tmp" "$W/out" && [ -d "$2/macos" ] && ! grep -qE "^[^#]*docker" "$3"' _ "$W" "$T/art" "$here/run-macos.sh"

wrap refresh-inventory.sh
check "m05_wrapper_refresh_inventory_selects_the_m05_generator" \
    bash -c 'W=$1; grep -qxF "script=refresh-inventory.sh" "$W/out" && grep -qxF "HM_EVIDENCE=m05-evidence.py" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m05" "$W/out"' _ "$W"
rm -f "$W/out"
HM_SKIP_TARGETS=a,b HM_ST_OUT="$W/out" bash "$W/m05/refresh-inventory.sh" >/dev/null 2>&1
check "m05_wrapper_refresh_inventory_passes_HM_SKIP_TARGETS_through" has "HM_SKIP_TARGETS=a,b"

check "m05_wrapper_windows_runs_the_m02_runner_with_milestone_m05" \
    bash -c 'grep -q -- "-Milestone m05" "$1/run-windows-local.ps1" && grep -q "ValidateSet(.m02., .m03., .m05.)" "$1/../m02/run-windows-local.ps1"' _ "$here"
if command -v pwsh >/dev/null 2>&1; then
    (cd "$T" && pwsh -NoProfile -File "$here/run-windows-local.ps1" -SelfTest) >"$T/winlocal.log" 2>&1
    wrc=$?
    check "m05_wrapper_windows_runner_selftest_passes_through_the_m05_wrapper" \
        bash -c '[ "$1" = 0 ] && grep -q "^run-windows-local selftest: [1-9][0-9]* passed, 0 failed$" "$2"' _ "$wrc" "$T/winlocal.log"
else
    skip m05_wrapper_windows_runner_selftest_passes_through_the_m05_wrapper "pwsh absent"
fi
if command -v shellcheck >/dev/null 2>&1; then
    check "m05_scripts_pass_shellcheck" shellcheck -x "$here/wsl-hook-journeys.sh" "$here/run-linux.sh" "$here/run-macos.sh" "$here/refresh-inventory.sh" "$here/selftest.sh"
else
    skip m05_scripts_pass_shellcheck "shellcheck absent"
fi

# --- the WSL hook run (wsl-hook-journeys.sh) in a fake world ---------------------------------------

# stage BINDIR: the staged build (stub test binaries, a heimdall stub, hm-fixture-hook, repo/).
stage() {
    local d=$1 b
    mkdir -p "$d/repo"
    echo "fixture" >"$d/repo/Cargo.toml"
    for b in heimdall hm-fixture-hook e2e_cli_m05 e2e_hook_m05 adversarial_prompt_injection_cli; do
        cat >"$d/$b" <<'EOF'
#!/usr/bin/env bash
# Stub test binary: `<bin> --exact NAME --show-output`.
name=${2:-}
if [ -n "${HM_ST_ENVLOG:-}" ]; then
    {
        echo "ssh_auth_sock=${SSH_AUTH_SOCK:-unset}"
        echo "heimdall_home=${HEIMDALL_HOME:-unset}"
        echo "git_dir=${GIT_DIR:-unset}"
        echo "e2e_bin=${HEIMDALL_E2E_BIN:-unset}"
        echo "fixture_hook=${HM_FIXTURE_HOOK:-unset}"
        echo "repo_root=${HM_REPO_ROOT:-unset}"
        echo "tmpdir=${TMPDIR:-unset}"
        echo "cwd=$(pwd -P)"
    } >>"$HM_ST_ENVLOG"
fi
case " ${HM_ST_FAIL:-} " in *" $name "*)
    echo "running 1 test"; echo "test $name ... FAILED"; echo "test result: FAILED. 0 passed; 1 failed"; exit 101 ;;
esac
case " ${HM_ST_FILTERED:-} " in *" $name "*)
    echo "running 0 tests"; echo "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"; exit 0 ;;
esac
echo "running 1 test"
echo "test $name ... ok"
echo
echo "successes:"
echo
echo "---- $name stdout ----"
case "$name" in hook_warms*) echo "m05 observation: hook bash warm-up: the hook took 12 ms (stub)" ;; esac
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
if [ -n "${HM_ST_LEAVE:-}" ] && [ "$name" = "$HM_ST_LEAVE" ]; then
    # A child that keeps this binary's own command line (argv[0] = this path), as a runtime would.
    ( exec -a "$0" sleep 120 ) >/dev/null 2>&1 &
    echo "$!" >"$HM_ST_PIDFILE"
fi
exit 0
EOF
        chmod +x "$d/$b"
    done
}

# journey ID [ENV...]: stage a fresh world ID and run the script in isolated mode with the extra
# environment words; sets $rc and $OUT (the stdout log).
journey() {
    local id=$1
    shift
    J="$T/j-$id"
    mkdir -p "$J"
    stage "$J/bin"
    OUT="$J/out.txt"
    env HM_SCENARIO_ISOLATED=1 HM_SCENARIO_SHELLS="/bin/bash /bin/sh" HM_ST_ENVLOG="$J/env.log" HM_ST_PIDFILE="$J/leftover.pid" \
        SSH_AUTH_SOCK=/nonexistent/agent.sock HEIMDALL_HOME=/nonexistent/hh GIT_DIR=/nonexistent/git \
        "$@" bash "$here/wsl-hook-journeys.sh" "$J/s" "$J/bin" >"$OUT" 2>"$J/err.txt" </dev/null
    rc=$?
}
step_line() { grep -qxF "test $1 ... $2" "$OUT"; }

journey good
check "m05_wsl_hook_all_eight_steps_pass_and_the_run_exits_0" \
    bash -c '[ "$1" = 0 ]' _ "$rc"
check "m05_wsl_hook_every_step_is_a_test_line_and_nothing_else_reads_as_a_result" \
    bash -c 'all=$(grep -c "^test " "$1"); [ "$all" = 8 ] && ! grep -q "FAILED" "$1" && [ "$(head -1 "$1")" = "### wsl_hook_m05" ] && [ "$(tail -1 "$1")" = "### wsl_hook_m05 exit=0" ]' _ "$OUT"
check "m05_wsl_hook_steps_are_exactly_the_case_index_scenario_steps" \
    bash -c 'python3 -I - "$1" "$2" <<PY
import importlib.util, json, sys
out, index = sys.argv[1], sys.argv[2]
sys.argv = ["x"]
spec = importlib.util.spec_from_file_location("m05", "$3/m05-evidence.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
got = m.ev.parse_log(out)
want = json.load(open(index))["scenario_targets"]["wsl_hook_m05"]["steps"]
assert set(got) == {"wsl_hook_m05"}, got
assert got["wsl_hook_m05"] == {k: "ok" for k in want}, (got, list(want))
PY' _ "$OUT" "$here/case-index.json" "$here"
check "m05_wsl_hook_keeps_observation_lines_under_their_step_header" \
    bash -c 'awk "/^---- m05_wsl_hook_warms_the_default_so_the_first_ordinary_ssh_logs_in stdout ----\$/{f=1;next} /^---- /{f=0} f" "$1" | grep -q "^m05 observation: hook bash warm-up"' _ "$OUT"
check "m05_wsl_hook_the_scratch_directory_it_created_is_removed" \
    bash -c '[ ! -e "$1/s" ] && [ -d "$1/bin" ]' _ "$J"
check "m05_wsl_hook_tests_get_a_sanitized_environment_and_private_copies_under_scratch" \
    bash -c 'e=$1/env.log; [ -s "$e" ] && ! grep -qv "^[a-z0-9_]*=" "$e" &&
        ! grep -q "^ssh_auth_sock=/" "$e" && ! grep -q "^heimdall_home=/" "$e" && ! grep -q "^git_dir=/" "$e" &&
        grep -q "^e2e_bin=$1/s/bin/heimdall\$" "$e" && grep -q "^fixture_hook=$1/s/bin/hm-fixture-hook\$" "$e" &&
        grep -q "^repo_root=$1/bin/repo\$" "$e" && grep -q "^tmpdir=$1/s/tmp\$" "$e"' _ "$J"
check "m05_wsl_hook_runs_each_test_exactly_once_by_name" \
    bash -c 'grep -c "^cwd=" "$1/env.log" | grep -qx 6' _ "$J"

journey failing "HM_ST_FAIL=hook_without_a_runtime_prints_nothing_and_starts_none"
check "m05_wsl_hook_a_failing_test_fails_its_step_and_the_run" \
    bash -c '[ "$1" = 1 ]' _ "$rc"
check "m05_wsl_hook_...only_that_step_and_its_tail_is_kept_prefixed" \
    bash -c 'grep -qxF "test m05_wsl_hook_without_a_runtime_prints_nothing_and_starts_none ... FAILED" "$1" && [ "$(grep -c "^test .* \.\.\. FAILED\$" "$1")" = 1 ] &&
        grep -q "^  | test hook_without_a_runtime_prints_nothing_and_starts_none \.\.\. FAILED" "$1" && [ "$(grep -c "^test " "$1")" = 8 ] &&
        [ "$(tail -1 "$1")" = "### wsl_hook_m05 exit=1" ] && [ ! -e "$2/s" ]' _ "$OUT" "$J"

journey filtered "HM_ST_FILTERED=hook_never_evaluates_repository_text"
check "m05_wsl_hook_a_test_that_ran_zero_tests_never_passes" \
    bash -c '[ "$1" = 1 ]' _ "$rc"
check "m05_wsl_hook_...its_step_is_FAILED" step_line m05_wsl_hook_never_evaluates_repository_text FAILED

journey nobinary
rm -f "$J/bin/e2e_hook_m05"
env HM_SCENARIO_ISOLATED=1 HM_SCENARIO_SHELLS="/bin/bash /bin/sh" bash "$here/wsl-hook-journeys.sh" "$J/s2" "$J/bin" >"$OUT" 2>"$J/err.txt" </dev/null
rc=$?
check "m05_wsl_hook_a_test_binary_that_was_not_provided_fails_its_steps_and_is_named" \
    bash -c '[ "$1" = 1 ] && grep -qxF "test m05_wsl_hook_warms_the_default_so_the_first_ordinary_ssh_logs_in ... FAILED" "$2" &&
        grep -qxF "fact missing-binaries=e2e_hook_m05" "$2" && grep -qxF "test m05_wsl_hook_never_evaluates_repository_text ... ok" "$2"' _ "$rc" "$OUT"

journey nozsh "HM_SCENARIO_SHELLS=/bin/bash /nonexistent/zsh"
check "m05_wsl_hook_without_both_shells_the_precondition_and_the_shell_steps_fail" \
    bash -c '[ "$1" = 1 ]' _ "$rc"
check "m05_wsl_hook_...and_no_shell_test_runs_(the_other_journeys_still_do)" \
    bash -c 'grep -qxF "test m05_wsl_bash_and_zsh_present ... FAILED" "$1" && grep -qxF "test m05_wsl_hook_never_evaluates_repository_text ... FAILED" "$1" &&
        grep -qxF "test m05_wsl_a29_hook_ignores_a_hostile_environment ... FAILED" "$1" && grep -qxF "test m05_wsl_hook_creates_no_decision_when_uncovered ... ok" "$1" &&
        [ "$(grep -c "^cwd=" "$2/env.log")" = 4 ]' _ "$OUT" "$J"

journey leftover "HM_ST_LEAVE=hook_warm_up_creates_no_decision_when_the_default_does_not_cover"
leftover_pid=$(cat "$J/leftover.pid" 2>/dev/null || true)
check "m05_wsl_hook_a_process_of_the_run_left_running_fails_the_run_and_is_counted" \
    bash -c '[ "$1" = 1 ] && grep -qxF "test m05_wsl_no_leftover_processes ... FAILED" "$2" && grep -qxF "fact leftover-processes=1" "$2"' _ "$rc" "$OUT"
# Stop what the check left, by exact PID: its own child, identified by its command line first.
if [ -n "$leftover_pid" ]; then
    case "$(ps -o command= -p "$leftover_pid" 2>/dev/null)" in
        "$J/s/bin/e2e_hook_m05 120") kill "$leftover_pid" 2>/dev/null; wait "$leftover_pid" 2>/dev/null ;;
    esac
fi
check "m05_wsl_hook_...the_leftover_was_stopped_by_exact_pid" \
    bash -c '[ -n "$1" ] && ! kill -0 "$1" 2>/dev/null' _ "$leftover_pid"

# Refusals: nothing runs, nothing is created.
bind="$T/j-good/bin"
refused() {
    # refused LABEL ENV... -- SCRATCH: run non-isolated with the given environment.
    local sc=${*: -1}
    local envs=("${@:1:$#-1}")
    env -u HM_SCENARIO_ISOLATED "${envs[@]}" bash "$here/wsl-hook-journeys.sh" "$sc" "$bind" >"$T/ref.out" 2>"$T/ref.err" </dev/null
    rrc=$?
    [ "$rrc" = 2 ] && [ ! -e "$sc" ] && [ ! -s "$T/ref.out" ]
}
for name in "" Ubuntu hm-m05-1234567 hm-m05-123456789 hm-m05-GHIJKLMN hm-m03-0123abcd "hm-m05-0123abcd;x" hm-m05-0123ABCD; do
    check "m05_wsl_hook_refuses_outside_a_disposable_distribution (WSL_DISTRO_NAME='$name')" refused "WSL_DISTRO_NAME=$name" "$T/refused-$$"
done
check "m05_wsl_hook_refuses_an_unset_distribution_name" refused "A_=b" "$T/refused-unset"
mkdir -p "$T/exists"
echo keep >"$T/exists/file"
env HM_SCENARIO_ISOLATED=1 bash "$here/wsl-hook-journeys.sh" "$T/exists" "$bind" >"$T/ref.out" 2>"$T/ref.err" </dev/null
check "m05_wsl_hook_refuses_an_existing_scratch_directory_and_leaves_it_untouched" \
    bash -c '[ "$1" = 2 ] && [ "$(cat "$2/exists/file")" = keep ] && [ "$(ls -A "$2/exists")" = file ]' _ "$?" "$T"
long="$T/$(printf 'x%.0s' $(seq 1 70))"
env HM_SCENARIO_ISOLATED=1 bash "$here/wsl-hook-journeys.sh" "$long" "$bind" >"$T/ref.out" 2>"$T/ref.err" </dev/null
check "m05_wsl_hook_refuses_a_path_too_long_for_unix_socket_paths_and_creates_nothing" \
    bash -c '[ "$1" = 2 ] && [ ! -e "$2" ]' _ "$?" "$long"
# A disposable distribution name of the right shape is accepted (stub binaries, the real /bin shells).
env -u HM_SCENARIO_ISOLATED WSL_DISTRO_NAME=hm-m05-0123abcd bash "$here/wsl-hook-journeys.sh" "$T/accepted" "$bind" >"$T/acc.out" 2>/dev/null </dev/null
check "m05_wsl_hook_accepts_an_hm_m05_distribution_name_of_the_right_shape" \
    bash -c '[ "$1" != 2 ] && [ "$(head -1 "$2")" = "### wsl_hook_m05" ]' _ "$?" "$T/acc.out"
check "m05_wsl_hook_HM_KEEP_SCRATCH_keeps_the_run_directory_only_on_request" \
    bash -c 'env HM_SCENARIO_ISOLATED=1 HM_SCENARIO_SHELLS="/bin/bash /bin/sh" HM_KEEP_SCRATCH=1 bash "$1/wsl-hook-journeys.sh" "$2/kept" "$3" >/dev/null 2>&1 </dev/null; [ -d "$2/kept/out" ] && [ -s "$2/kept/out/m05_wsl_hook_warms_the_default_so_the_first_ordinary_ssh_logs_in.txt" ]' _ "$here" "$T" "$bind"

echo "m05-selftest: $passes passed, $fails failed"
[ "$fails" = 0 ]
