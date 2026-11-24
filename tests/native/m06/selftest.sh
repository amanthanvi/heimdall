#!/usr/bin/env bash
# M06-U7: self-test of the M06 evidence harness, run by tools/validation/native-harness-selftest.sh.
# Reaches no host, builds nothing and starts no sshd: `ssh`, `cargo`, `rustc`, `zig`, `sshd` and the
# other host commands are stubs first on PATH, the "remote host" is a fake home under this run's
# temporary directory, and the "test binaries" are stub scripts. Everything lives under one mktemp
# directory, removed on exit, pass or fail.
#
# Checks:
#   m06_generator_*   the generator over synthetic logs (selftest_synthetic.py: verified rows, a
#                     failed test, a missing platform, a missing test, the owner-input, not-started
#                     and deferred rows, an iroh-feature target a platform could not build, the
#                     m06 observation lines, HM_SKIP_TARGETS)
#   m06_wrapper_*     run-linux.sh, run-macos.sh, refresh-inventory.sh and run-windows-local.ps1
#                     reach the M02 scripts with the M06 settings (prefix hm-m06, the M06 case
#                     index and generator, HM_FEATURE=iroh / -Feature iroh, no Docker phase, the
#                     PowerShell runner's own -SelfTest)
#   m06_feature_*     tests/native/m02/lib.sh m02_feature_targets, m02_feature_build and
#                     m02_feature_facts against a stub cargo: the targets come from the metadata's
#                     required-features, each package is built once with the feature, the
#                     default-feature CLI survives the feature build that overwrites its path, a
#                     failed build is a blocked reason with cargo's exit code and first error and
#                     never a pass, and a feature no target requires is an error
#   m06_linux_*       tests/native/m06/run-linux.sh end to end in the fake world: the iroh targets
#                     are built, staged and run with the rest, against the feature build's own CLI
#                     (every other target keeps the default one); a build failure gives exit 6, a
#                     feature-blocked fact and no result line for the target; a failing iroh test
#                     gives its exit code; HM_ONLY, HM_BUILD_ONLY; the scratch directory is removed
#   m06_macos_*       tests/native/m06/run-macos.sh against a fake repository root (a stub
#                     check.sh): the feature pass after check.sh and the observation pass,
#                     features.txt, the blocked fact and exit 6, a failing iroh test's exit code
# Prints one line per check and `m06-selftest: N passed, M failed`; exit 0 only when every check passed.
# HM_SELFTEST_VERBOSE=1 also prints each harness log (it may contain temporary paths).

# The checks run their predicates through `bash -c` with single-quoted bodies on purpose.
# shellcheck disable=SC2016
set -u
here=$(cd "$(dirname "$0")" && pwd)
m02="$here/../m02"
T=$(mktemp -d /tmp/hm-m06-st.XXXXXX) || exit 2
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
HOST=hm-selftest-no-such-host

# --- the generator over synthetic logs ----------------------------------------------------------

PYTHONDONTWRITEBYTECODE=1 python3 -I "$here/selftest_synthetic.py" >"$T/gen.out" 2>&1
gen_rc=$?
gen_n=$(sed -n 's/^Ran \([0-9]*\) tests.*/\1/p' "$T/gen.out" | tail -1)
check "m06_generator_dry_runs_over_synthetic_logs (${gen_n:-0} tests: verified, failed, missing platform, missing test, owner inputs, iroh blocked, observations, skip)" \
    bash -c '[ "$1" = 0 ] && grep -q "^OK$" "$2"' _ "$gen_rc" "$T/gen.out"
[ "$gen_rc" = 0 ] || grep -E '^(FAIL|ERROR):' "$T/gen.out" | head -20

# --- the wrappers ----------------------------------------------------------------------------------

W="$T/wrap"
mkdir -p "$W/m02" "$W/m06"
for f in run-linux.sh run-macos.sh refresh-inventory.sh; do cp "$here/$f" "$W/m06/$f"; done
for s in run-linux run-macos refresh-inventory; do
    cat >"$W/m02/$s.sh" <<'EOF'
#!/usr/bin/env bash
# Stub of the M02 script: prints the settings the M06 wrapper gave it.
{
    echo "script=$(basename "$0")"
    echo "args=$*"
    echo "HM_HARNESS_DIR=${HM_HARNESS_DIR:-unset}"
    echo "HM_EVIDENCE=${HM_EVIDENCE:-unset}"
    echo "HM_RUN_PREFIX=${HM_RUN_PREFIX:-unset}"
    echo "HM_EXTRA_REMOTE=${HM_EXTRA_REMOTE:-unset}"
    echo "HM_FEATURE=${HM_FEATURE:-unset}"
    echo "HM_SKIP_TARGETS=${HM_SKIP_TARGETS:-unset}"
    echo "TMPDIR=${TMPDIR:-unset}"
} >"$HM_ST_OUT"
EOF
done
wrap() {
    # wrap SCRIPT ARGS...: run an M06 wrapper in the stub tree; prints nothing, writes $W/out.
    local s=$1
    shift
    rm -f "$W/out"
    HM_ST_OUT="$W/out" bash "$W/m06/$s" "$@" >"$W/log" 2>&1
}
has() { grep -qxF -- "$1" "$W/out"; }

wrap run-linux.sh "$T/art" devbox-alias
check "m06_wrapper_linux_sets_the_m06_prefix_case_index_generator_and_the_iroh_feature" \
    bash -c 'W=$1; grep -qxF "script=run-linux.sh" "$W/out" && grep -qxF "args=$2 devbox-alias" "$W/out" && grep -qxF "HM_RUN_PREFIX=hm-m06" "$W/out" &&
        grep -qxF "HM_EVIDENCE=m06-evidence.py" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m06" "$W/out" && grep -qxF "HM_FEATURE=iroh" "$W/out" &&
        grep -qxF "HM_EXTRA_REMOTE=unset" "$W/out"' _ "$W" "$T/art"
check "m06_wrapper_prefix_is_one_the_m02_scripts_accept" \
    bash -c 'p=hm-m06; case "$p" in hm-m0[0-9]) ;; *) exit 1 ;; esac; grep -q "hm-m0\[0-9\]" "$1/run-linux.sh"' _ "$m02"

wrap run-macos.sh "$T/art"
check "m06_wrapper_macos_runs_the_m02_harness_with_the_m06_index_the_iroh_feature_and_no_docker_phase" \
    bash -c 'W=$1; grep -qxF "script=run-macos.sh" "$W/out" && grep -qxF "args=$2/macos" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m06" "$W/out" &&
        grep -qxF "HM_FEATURE=iroh" "$W/out" && grep -qxF "TMPDIR=/tmp" "$W/out" && [ -d "$2/macos" ] && ! grep -qE "^[^#]*docker" "$3"' _ "$W" "$T/art" "$here/run-macos.sh"

wrap refresh-inventory.sh
check "m06_wrapper_refresh_inventory_selects_the_m06_generator_and_the_iroh_feature" \
    bash -c 'W=$1; grep -qxF "script=refresh-inventory.sh" "$W/out" && grep -qxF "HM_EVIDENCE=m06-evidence.py" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m06" "$W/out" &&
        grep -qxF "HM_FEATURE=iroh" "$W/out"' _ "$W"
rm -f "$W/out"
HM_SKIP_TARGETS=a,b HM_ST_OUT="$W/out" bash "$W/m06/refresh-inventory.sh" >/dev/null 2>&1
check "m06_wrapper_refresh_inventory_passes_HM_SKIP_TARGETS_through" has "HM_SKIP_TARGETS=a,b"

check "m06_wrapper_windows_runs_the_m02_runner_with_milestone_m06_and_feature_iroh" \
    bash -c 'grep -q -- "-Milestone m06 -Feature iroh" "$1/run-windows-local.ps1" && grep -q "ValidateSet(.*.m06..*)" "$2/run-windows-local.ps1" &&
        grep -q "\[string\]\$Feature = ..," "$2/run-windows-local.ps1"' _ "$here" "$m02"
if command -v pwsh >/dev/null 2>&1; then
    (cd "$T" && pwsh -NoProfile -File "$here/run-windows-local.ps1" -SelfTest) >"$T/winlocal.log" 2>&1
    wrc=$?
    check "m06_wrapper_windows_runner_selftest_passes_through_the_m06_wrapper (the feature-target and blocked-reason helpers included)" \
        bash -c '[ "$1" = 0 ] && grep -q "^run-windows-local selftest: [1-9][0-9]* passed, 0 failed$" "$2" && grep -q "^ok   F01 " "$2" && grep -q "^ok   F04 " "$2"' _ "$wrc" "$T/winlocal.log"
else
    skip m06_wrapper_windows_runner_selftest_passes_through_the_m06_wrapper "pwsh absent"
fi

# ⟨M06 W5h⟩ The Windows controller journey (run-windows-controller.ps1 and its runner-side script):
# its helpers on synthetic data (step plan, distribution names, facts and envelope parsing, the
# log the generator reads, failure handling, the runner script's refusals).
check "m06_controller_journey_runner_script_parses" bash -n "$here/windows-controller-runner.sh"
if command -v pwsh >/dev/null 2>&1; then
    (cd "$T" && pwsh -NoProfile -NonInteractive -File "$here/run-windows-controller.ps1" -SelfTest) >"$T/journey.log" 2>&1 </dev/null
    journey_rc=$?
    check "m06_controller_journey_selftest_passes ($(tail -n 1 "$T/journey.log"))" \
        bash -c '[ "$1" = 0 ] && tail -n 1 "$2" | grep -Eq "^[1-9][0-9]* passed, 0 failed$"' _ "$journey_rc" "$T/journey.log"
    (cd "$T" && pwsh -NoProfile -NonInteractive -File "$here/run-windows-controller.ps1" -ScratchRoot "$T" -HeimdallExe "$T/absent") >"$T/journey-blocked.log" 2>&1 </dev/null
    check "m06_controller_journey_with_a_missing_input_is_blocked_exit_3_and_creates_nothing" \
        bash -c '[ "$1" = 3 ] && grep -q "^blocked: " "$2" && ! ls -d "$3"/hm-m06j-* >/dev/null 2>&1' _ "$?" "$T/journey-blocked.log" "$T"
else
    skip m06_controller_journey_selftest_passes "pwsh absent"
fi
# ⟨M06 exit⟩ The journey's recorder (record-windows-controller.ps1): its helpers, then a run
# against a stub journey beside a copy of it (the stub fails with trailer exit=1): commands.txt
# is the stub's real exit code in the line import-windows-controller.py reads, build.txt carries
# a sha256 per input, and a non-empty -Out is refused before anything starts.
if command -v pwsh >/dev/null 2>&1; then
    (cd "$T" && pwsh -NoProfile -NonInteractive -File "$here/record-windows-controller.ps1" -SelfTest) >"$T/rwc.log" 2>&1 </dev/null
    check "m06_controller_recorder_selftest_passes ($(tail -n 1 "$T/rwc.log"))" \
        bash -c '[ "$1" = 0 ] && grep -q "^record-windows-controller selftest: [1-9][0-9]* passed, 0 failed$" "$2"' _ "$?" "$T/rwc.log"
    mkdir -p "$T/rwc/bin"
    cp "$here/record-windows-controller.ps1" "$T/rwc/"
    cat >"$T/rwc/run-windows-controller.ps1" <<'PS1'
param([string]$ScratchRoot, [string]$HeimdallExe, [string]$DriverExe, [string]$LinuxHeimdall, [string]$LinuxDriver, [string]$WslDistro, [string]$Out)
[void](New-Item -ItemType Directory -Path $Out -Force)
[System.IO.File]::WriteAllText((Join-Path $Out 'tests.txt'), "### windows-controller-journey`n`nrunning 1 tests`ntest a24_pair ... FAILED`n### windows-controller-journey exit=1`n")
[System.IO.File]::WriteAllText((Join-Path $Out 'host.txt'), "os=stub`nwsl-distro-arg=$WslDistro`n")
exit 1
PS1
    printf 'heimdall' >"$T/rwc/bin/h"
    (cd "$T" && pwsh -NoProfile -NonInteractive -File "$T/rwc/record-windows-controller.ps1" -ScratchRoot "$T" -HeimdallExe "$T/rwc/bin/h" \
        -DriverExe "$T/rwc/bin/absent" -WslDistro Stub -Out "$T/rwc/out") >"$T/rwc-run.log" 2>&1 </dev/null
    check "m06_controller_recorder_writes_the_journeys_real_exit_code_and_the_inputs_sha256" \
        bash -c '[ "$1" = 1 ] && [ "$(cat "$2/commands.txt")" = "exit 1: $3" ] && grep -qx "wsl-distro-arg=Stub" "$2/host.txt" &&
            grep -qx "heimdall.exe sha256: $(shasum -a 256 "$4" | cut -d" " -f1)" "$2/build.txt" && grep -qx "e2e_windows_controller_m06.exe absent" "$2/build.txt" &&
            grep -q "^run-windows-controller.ps1 sha256: [0-9a-f]\{64\}$" "$2/build.txt" && grep -q "^commit=" "$2/build.txt" && ! grep -qF "$5" "$2/build.txt" "$2/commands.txt"' \
        _ "$?" "$T/rwc/out" "$(python3 -I -c 'import importlib.util as u, sys; s = u.spec_from_file_location("i", sys.argv[1]); m = u.module_from_spec(s); s.loader.exec_module(m); print(m.COMMAND)' "$here/import-windows-controller.py")" "$T/rwc/bin/h" "$T"
    (cd "$T" && pwsh -NoProfile -NonInteractive -File "$T/rwc/record-windows-controller.ps1" -Out "$T/rwc/out") >"$T/rwc-again.log" 2>&1 </dev/null
    check "m06_controller_recorder_refuses_a_non_empty_out_before_the_journey_starts (exit 2)" \
        bash -c '[ "$1" = 2 ] && grep -q "^refused: -Out exists and is not empty" "$2" && [ "$(cat "$3/commands.txt")" != "" ] && grep -q "exit 1:" "$3/commands.txt"' _ "$?" "$T/rwc-again.log" "$T/rwc/out"
else
    skip m06_controller_recorder_selftest_passes "pwsh absent"
fi
if command -v shellcheck >/dev/null 2>&1; then
    check "m06_scripts_pass_shellcheck" shellcheck -x "$here/run-linux.sh" "$here/run-macos.sh" "$here/refresh-inventory.sh" "$here/selftest.sh" "$here/run-linux-batches.sh"
else
    skip m06_scripts_pass_shellcheck "shellcheck absent"
fi

# --- the fake world --------------------------------------------------------------------------------

# new_world NAME: a fresh fake remote home ($H), stub bin ($B), stub executables ($X), artifact
# directory ($O), call log ($L) and the stub cargo's inputs.
#   Packages: pkg-rt (iroh_rt requires `iroh`; plain_rt does not) and pkg-cli (iroh_cli requires
#   `iroh` and builds the heimdall binary), and heimdall-transport-iroh, whose unit tests are
#   built only with the feature (HM_FEATURE_UNIT). The workspace build and pkg-cli's feature build both
#   write the heimdall binary to ONE path ($X/heimdall), as cargo does: its content says which
#   build wrote it last.
new_world() {
    S="$T/$1"
    H="$S/home"
    B="$S/bin"
    X="$S/exes"
    O="$S/out"
    L="$S/calls.log"
    mkdir -p "$H" "$B" "$X" "$S/tmp" "$S/feature-json"
    : >"$L"
    extra_env=()
    cat >"$S/metadata.json" <<'EOF'
{"packages":[{"name":"pkg-rt","targets":[{"name":"plain_rt","kind":["test"],"required-features":[]},{"name":"iroh_rt","kind":["test"],"required-features":["iroh"]},{"name":"pkg_rt","kind":["lib"]}]},{"name":"pkg-cli","targets":[{"name":"iroh_cli","kind":["test"],"required-features":["iroh"]},{"name":"heimdall","kind":["bin"]},{"name":"other_feature","kind":["test"],"required-features":["other"]}]},{"name":"heimdall-testkit","targets":[{"name":"heimdall_testkit","kind":["lib"]}]},{"name":"heimdall-transport-iroh","targets":[{"name":"heimdall_transport_iroh","kind":["lib"]}]}]}
EOF
    local t
    for t in plain_rt heimdall_testkit-unit iroh_rt iroh_cli; do exe "$t" pass; done
    printf 'hook stub\n' >"$X/hm-fixture-hook"
    {
        artifact plain_rt test true "$X/plain_rt"
        artifact heimdall_testkit lib true "$X/heimdall_testkit-unit"
        artifact heimdall bin false "$X/heimdall"
        artifact hm-fixture-hook bin false "$X/hm-fixture-hook"
    } >"$S/build.json"
    artifact iroh_rt test true "$X/iroh_rt" >"$S/feature-json/pkg-rt.json"
    {
        artifact iroh_cli test true "$X/iroh_cli"
        artifact heimdall bin false "$X/heimdall"
    } >"$S/feature-json/pkg-cli.json"
    # ⟨M06 W5c⟩ heimdall-transport-iroh's unit tests, as the feature build of that package
    # makes them (the M06 wrappers name the package in HM_FEATURE_UNIT).
    exe heimdall_transport_iroh-unit pass
    artifact heimdall_transport_iroh lib true "$X/heimdall_transport_iroh-unit" >"$S/feature-json/heimdall-transport-iroh.json"
    write_stubs
}

# artifact NAME KIND TEST(true|false) EXE: one cargo compiler-artifact line.
artifact() {
    printf '{"reason":"compiler-artifact","target":{"name":"%s","kind":["%s"]},"profile":{"test":%s},"executable":"%s"}\n' "$1" "$2" "$3" "$4"
}

# exe NAME pass|fail: a stub test binary that says which CLI it was given.
exe() {
    {
        printf '#!/usr/bin/env bash\n'
        printf 'echo "argv: $*" >>"$HM_ST_LOG"\n'
        printf 'echo "running 1 test"\n'
        printf 'echo "env e2e_bin=${HEIMDALL_E2E_BIN#"$PWD"/} content=$(head -1 "$HEIMDALL_E2E_BIN" 2>/dev/null)"\n'
        if [ "$2" = pass ]; then
            printf 'echo "test fixture::a ... ok"\necho "test result: ok. 1 passed; 0 failed"\nexit 0\n'
        else
            printf 'echo "test fixture::a ... FAILED"\necho "test result: FAILED. 0 passed; 1 failed"\nexit 101\n'
        fi
    } >"$X/$1"
    chmod +x "$X/$1"
}

write_stubs() {
    cat >"$B/cargo" <<'EOF'
#!/usr/bin/env bash
# cargo stub: `metadata` prints the fake workspace; `test` writes the heimdall binary's one path as
# the build it stands for would, and prints that build's artifacts (or, without --no-run, runs
# the "tests"). HM_ST_FEATURE_FAIL names packages whose feature build fails.
{ printf 'cargo'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
if [ "${1:-}" = metadata ]; then
    cat "$HM_ST_DIR/metadata.json"
    exit "${HM_ST_METADATA_RC:-0}"
fi
feature="" pkg="" norun=0 prev="" tests=""
for a in "$@"; do
    case "$prev" in --features) feature=$a ;; -p) pkg=$a ;; --test) tests="$tests $a" ;; esac
    [ "$a" = --no-run ] && norun=1
    [ "$a" = -- ] && break
    prev=$a
done
if [ -z "$feature" ]; then
    echo "   Compiling the workspace (selftest stub) in $HOME/hm-selftest-checkout" >&2
    if [ "$norun" = 1 ]; then
        printf 'default-cli\n' >"$HM_ST_EXES/heimdall"
        cat "$HM_ST_DIR/build.json"
    else
        echo "     Running tests/x.rs (target/debug/deps/observed_target-0123abcd)"
        echo "test fixture::observed ... ok"
    fi
    exit 0
fi
case " ${HM_ST_FEATURE_FAIL:-} " in *" $pkg "*)
    echo "   Compiling $pkg with $feature (selftest stub)" >&2
    printf 'error[E0463]: can'"'"'t find crate for `iroh` in %s\twith a tab\n' "$HOME/hm-selftest-checkout" >&2
    echo "error: could not compile \`$pkg\` (selftest)" >&2
    exit 101 ;;
esac
if [ "$norun" = 1 ]; then
    echo "   Compiling $pkg with $feature (selftest stub)" >&2
    [ "$pkg" = pkg-cli ] && printf 'feature-cli\n' >"$HM_ST_EXES/heimdall"
    [ -f "$HM_ST_DIR/feature-json/$pkg.json" ] && cat "$HM_ST_DIR/feature-json/$pkg.json"
    exit 0
fi
failed=0
for t in $tests; do
    echo "     Running tests/x/$t.rs (target/debug/deps/$t-0123abcd)"
    echo "running 1 test"
    case " ${HM_ST_FEATURE_TEST_FAIL:-} " in
        *" $t "*) echo "test fixture::a ... FAILED"; failed=1 ;;
        *) echo "test fixture::a ... ok"; printf '\nsuccesses:\n\n---- fixture::a stdout ----\nm06 observation: %s step: ok in %s\n\n' "$t" "$HOME" ;;
    esac
done
[ "$failed" = 0 ] || exit 101
exit 0
EOF
    cat >"$B/ssh" <<'EOF'
#!/usr/bin/env bash
# ssh stub: never connects; runs the remote command in the fake home.
set -u
{ printf 'ssh'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
if [ "${1:-}" = -V ]; then echo "OpenSSH_9.9p9, selftest stub" >&2; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -F | -o) shift 2 ;; -*) shift ;; *) break ;; esac
done
[ "${1:-}" = "$HM_ST_HOST" ] || { echo "ssh stub: unexpected host" >&2; exit 255; }
shift
env HOME="$HM_ST_HOME" PATH="$HM_ST_BIN:$PATH" bash -c "$*"
EOF
    cat >"$B/sshd" <<'EOF'
#!/usr/bin/env bash
# sshd stub: a version line, and a configuration test that always refuses (no sshd is started).
case " $* " in *" -V "*) echo "OpenSSH_9.9p9 selftest sshd stub" >&2; exit 1 ;; esac
exit 1
EOF
    cat >"$B/uname" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = -m ]; then echo x86_64; else exec /usr/bin/uname "$@"; fi
EOF
    cat >"$B/timeout" <<'EOF'
#!/usr/bin/env bash
shift
exec "$@"
EOF
    cat >"$B/git" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = --version ]; then echo "git version 0.0.0-selftest"; exit 0; fi
exit 1
EOF
    printf '#!/usr/bin/env bash\necho "rustc 0.0.0-selftest"\n' >"$B/rustc"
    printf '#!/usr/bin/env bash\necho "0.0.0-selftest"\n' >"$B/zig"
    printf '#!/usr/bin/env bash\necho 4\n' >"$B/nproc"
    printf '#!/usr/bin/env bash\necho "ldd (selftest) 2.31"\n' >"$B/ldd"
    printf '#!/usr/bin/env bash\necho "script from util-linux (selftest)"\n' >"$B/script"
    printf '#!/usr/bin/env bash\ncase "${1:-}" in -f) echo "fixturehost.example.invalid" ;; *) echo "fixturehost" ;; esac\n' >"$B/hostname"
    chmod +x "$B"/*
}

# harness SCRIPT ARGS...: run an M06 wrapper (and through it the real M02 harness) in the fake
# world; sets $rc. Extra environment goes in the array extra_env (NAME=value words).
extra_env=()
harness() {
    local script=$1
    shift
    env -u HM_HARNESS_DIR -u HM_EVIDENCE -u HM_RUN_PREFIX -u HM_EXTRA_REMOTE -u HM_FEATURE -u HM_ONLY -u HM_BUILD_ONLY \
        -u CARGO_TARGET_DIR -u HM_CARGO_PROFILE HOME="$H" TMPDIR="$S/tmp" PATH="$B:$PATH" \
        HM_ST_LOG="$L" HM_ST_HOST="$HOST" HM_ST_HOME="$H" HM_ST_BIN="$B" HM_ST_DIR="$S" HM_ST_EXES="$X" HM_SHIM_DIR="$S/shims" \
        ${extra_env[@]+"${extra_env[@]}"} \
        bash "$script" "$@" >"$S/harness.log" 2>&1 </dev/null
    rc=$?
    if [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ]; then
        echo "--- $(basename "$script") exit $rc"
        cat "$S/harness.log"
    fi
}
# --- lib.sh: the feature targets and the feature build ----------------------------------------------

# lib CMD...: run lib.sh functions in the fake world, in the work directory $S/work.
lib() {
    mkdir -p "$S/work"
    env HOME="$H" PATH="$B:$PATH" HM_ST_LOG="$L" HM_ST_DIR="$S" HM_ST_EXES="$X" HM_SHIM_DIR="$S/shims" \
        ${extra_env[@]+"${extra_env[@]}"} bash -c '. "$1/lib.sh"; work=$2; shift 2; cd "$work" || exit 97; "$@"' _ "$m02" "$S/work" "$@"
}
# prepare: the state m02_feature_build starts from (the workspace build and m02_artifacts).
prepare() {
    lib bash -c '. "$1/lib.sh"; m02_cargo_build host "$2" "$2/build.log" && m02_artifacts "$2"' _ "$m02" "$S/work" >/dev/null 2>&1
}

new_world lib-targets
lib m02_feature_targets iroh >"$S/targets.out" 2>"$S/targets.err"
check "m06_feature_targets_are_the_test_targets_whose_required_features_name_the_feature_per_package" \
    bash -c '[ "$(cat "$1")" = "$(printf "pkg-cli\tiroh_cli\npkg-rt\tiroh_rt")" ]' _ "$S/targets.out"
: >"$L"
lib m02_feature_targets 'iroh;x' >/dev/null 2>&1
check "m06_feature_targets_refuse_a_bad_feature_name_before_cargo_runs" \
    bash -c '[ "$1" != 0 ] && [ ! -s "$2" ]' _ "$?" "$L"

new_world lib-build
prepare
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_build_returns_0_when_every_feature_target_built" bash -c '[ "$1" = 0 ]' _ "$?"
check "m06_feature_build_runs_one_cargo_build_per_package_with_the_feature_and_its_targets_only" \
    bash -c 'grep -qxF "cargo test -p pkg-cli --features iroh --test iroh_cli --no-run --locked --message-format=json-render-diagnostics" "$1" &&
        grep -qxF "cargo test -p pkg-rt --features iroh --test iroh_rt --no-run --locked --message-format=json-render-diagnostics" "$1" &&
        [ "$(grep -c -- "--features" "$1")" = 2 ] && ! grep -q -e "--target-dir" -e "other_feature" "$1"' _ "$L"
check "m06_feature_build_lists_the_feature_targets_and_merges_them_into_the_run_plan_input" \
    bash -c 'w=$1; [ "$(cut -f1 "$w/feature.tsv" | sort | tr "\n" " ")" = "iroh_cli iroh_rt " ] &&
        [ "$(cut -f1 "$w/all.tsv" | tr "\n" " ")" = "heimdall_testkit-unit iroh_cli iroh_rt plain_rt " ] && [ ! -s "$w/feature-blocked.tsv" ]' _ "$S/work"
check "m06_feature_build_keeps_the_default_feature_cli_although_the_feature_build_overwrote_its_path" \
    bash -c 'w=$1; [ "$(cat "$(cat "$w/cli.txt")")" = default-cli ] && [ "$(cat "$(cat "$w/feature-cli.txt")")" = feature-cli ] &&
        [ "$(cat "$2/heimdall")" = feature-cli ] && [ "$(cat "$w/cli.txt")" != "$(cat "$w/feature-cli.txt")" ]' _ "$S/work" "$X"
lib m02_feature_facts "$S/work" iroh >"$S/facts.out" 2>&1
check "m06_feature_facts_name_the_built_targets_and_the_cli_and_no_blocked_target" \
    bash -c 'grep -qxF "feature-targets=iroh: iroh_cli iroh_rt" "$1" && grep -q "^feature-cli=the iroh-feature heimdall " "$1" && ! grep -q "^feature-blocked-" "$1"' _ "$S/facts.out"

new_world lib-blocked
prepare
extra_env=(HM_ST_FEATURE_FAIL=pkg-rt)
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_build_returns_6_when_a_package_does_not_build_with_the_feature" bash -c '[ "$1" = 6 ]' _ "$?"
check "m06_feature_build_blocks_exactly_that_packages_targets_with_cargos_exit_code_and_first_error" \
    bash -c 'w=$1; [ "$(wc -l <"$w/feature-blocked.tsv" | tr -d " ")" = 1 ] &&
        grep -q "^iroh_rt	the iroh-feature build of pkg-rt failed (cargo exit 101): error\[E0463\]: can.t find crate for .iroh. in .* with a tab$" "$w/feature-blocked.tsv"' _ "$S/work"
check "m06_feature_build_still_builds_the_other_package_and_never_plans_the_blocked_target" \
    bash -c 'w=$1; [ "$(cut -f1 "$w/feature.tsv" | tr "\n" " ")" = "iroh_cli " ] && ! cut -f1 "$w/all.tsv" | grep -qx iroh_rt && cut -f1 "$w/all.tsv" | grep -qx iroh_cli' _ "$S/work"
lib m02_feature_facts "$S/work" iroh >"$S/facts.out" 2>&1
check "m06_feature_facts_carry_one_feature_blocked_line_per_target_that_did_not_build" \
    bash -c '[ "$(grep -c "^feature-blocked-" "$1")" = 1 ] && grep -q "^feature-blocked-iroh_rt=the iroh-feature build of pkg-rt failed (cargo exit 101): error" "$1" && grep -qxF "feature-targets=iroh: iroh_cli" "$1"' _ "$S/facts.out"

new_world lib-noexe
prepare
: >"$S/feature-json/pkg-rt.json"
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_build_blocks_a_target_cargo_reported_no_executable_for (exit 6, never assumed built)" \
    bash -c '[ "$1" = 6 ] && grep -q "^iroh_rt	the iroh-feature build of pkg-rt produced no test executable for it$" "$2/feature-blocked.tsv"' _ "$?" "$S/work"

# ⟨M06 W5c⟩ M02_FEATURE_UNIT: a package's own unit tests, built with the feature.
new_world lib-unit
prepare
exe heimdall_testkit-unit-feature pass
artifact heimdall_testkit lib true "$X/heimdall_testkit-unit-feature" >"$S/feature-json/heimdall-testkit.json"
extra_env=(M02_FEATURE_UNIT=heimdall-testkit)
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_unit_builds_the_named_packages_unit_tests_with_the_feature (one more cargo build, --lib)" \
    bash -c '[ "$1" = 0 ] && grep -qxF "cargo test -p heimdall-testkit --features iroh --lib --no-run --locked --message-format=json-render-diagnostics" "$2" &&
        [ "$(grep -c -- "--features" "$2")" = 3 ]' _ "$?" "$L"
check "m06_feature_unit_replaces_the_default_feature_row_of_the_same_name_in_the_run_plan_input" \
    bash -c 'w=$1; [ "$(awk -F"\t" "\$1 == \"heimdall_testkit-unit\" { print \$2 }" "$w/all.tsv")" = "$2/heimdall_testkit-unit-feature" ] &&
        [ "$(cut -f1 "$w/all.tsv" | tr "\n" " ")" = "heimdall_testkit-unit iroh_cli iroh_rt plain_rt " ] &&
        cut -f1 "$w/feature.tsv" | grep -qx heimdall_testkit-unit && [ ! -s "$w/feature-blocked.tsv" ]' _ "$S/work" "$X"
lib m02_feature_facts "$S/work" iroh >"$S/facts.out" 2>&1
check "m06_feature_unit_is_named_among_the_built_feature_targets" \
    grep -qxF "feature-targets=iroh: iroh_cli iroh_rt heimdall_testkit-unit" "$S/facts.out"

new_world lib-unit-blocked
prepare
extra_env=(M02_FEATURE_UNIT=heimdall-testkit HM_ST_FEATURE_FAIL=heimdall-testkit)
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_unit_that_does_not_build_is_blocked_and_its_default_feature_binary_leaves_the_plan (exit 6)" \
    bash -c 'w=$2; [ "$1" = 6 ] && grep -q "^heimdall_testkit-unit	the iroh-feature build of heimdall-testkit failed (cargo exit 101): error" "$w/feature-blocked.tsv" &&
        ! cut -f1 "$w/all.tsv" | grep -qx heimdall_testkit-unit && [ "$(cut -f1 "$w/all.tsv" | tr "\n" " ")" = "iroh_cli iroh_rt plain_rt " ]' _ "$?" "$S/work"

new_world lib-unit-noexe
prepare
extra_env=(M02_FEATURE_UNIT=heimdall-testkit)
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_unit_with_no_test_executable_is_blocked_never_run_from_the_default_build (exit 6)" \
    bash -c 'w=$2; [ "$1" = 6 ] && grep -q "^heimdall_testkit-unit	the iroh-feature build of heimdall-testkit produced no test executable for it$" "$w/feature-blocked.tsv" &&
        ! cut -f1 "$w/all.tsv" | grep -qx heimdall_testkit-unit' _ "$?" "$S/work"

new_world lib-unit-bad
prepare
extra_env=("M02_FEATURE_UNIT=pkg;x")
: >"$L"
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_unit_refuses_a_bad_package_list (exit 2)" bash -c '[ "$1" = 2 ] && ! grep -q -- "--lib" "$2"' _ "$?" "$L"

check "m06_feature_unit_the_wrappers_and_the_generator_name_the_same_package (linux, inventory, windows; macOS runs it in check.sh)" \
    bash -c 'grep -q "HM_FEATURE=iroh HM_FEATURE_UNIT=heimdall-transport-iroh" "$1/run-linux.sh" && grep -q "HM_FEATURE=iroh HM_FEATURE_UNIT=heimdall-transport-iroh" "$1/refresh-inventory.sh" &&
        grep -q -- "-Feature iroh -FeatureUnit heimdall-transport-iroh" "$1/run-windows-local.ps1" && grep -qxF "FEATURE_UNIT = {\"heimdall-transport-iroh\": \"iroh\"}" "$1/m06-evidence.py" &&
        grep -q "cargo test --locked -p heimdall-transport-iroh --features iroh" "$1/../../../tools/validation/check.sh"' _ "$here"

new_world lib-none
prepare
lib m02_feature_build host "$S/work" "$S/work/log.txt" absent >"$S/fb.out" 2>&1
check "m06_feature_build_refuses_a_feature_no_target_requires (exit 2, nothing built with it)" \
    bash -c '[ "$1" = 2 ] && ! grep -q -- "--features" "$2"' _ "$?" "$L"

new_world lib-skip
prepare
extra_env=("M02_FEATURE_SKIP=iroh_cli,absent_target")
lib m02_feature_build host "$S/work" "$S/work/log.txt" iroh >"$S/fb.out" 2>&1
check "m06_feature_build_leaves_out_only_the_targets_the_inventory_refresh_skips (never set by a run harness)" \
    bash -c '[ "$1" = 0 ] && [ "$(cut -f1 "$2/feature.tsv" | tr "\n" " ")" = "iroh_rt " ] && ! grep -q "pkg-cli" "$3" &&
        ! grep -q "M02_FEATURE_SKIP" "$4/run-linux.sh" "$4/run-macos.sh" && grep -q "M02_FEATURE_SKIP=\${HM_SKIP_TARGETS:-}" "$4/refresh-inventory.sh"' _ "$?" "$S/work" "$L" "$m02"

new_world lib-default
prepare
check "m06_feature_the_workspace_build_is_unchanged_without_a_selection (m05 behaviour)" \
    bash -c 'grep -qxF "cargo test --workspace --no-run --locked --message-format=json-render-diagnostics" "$1" && [ "$(grep -c "^cargo" "$1")" = 1 ] && [ -s "$2/build.json" ]' _ "$L" "$S/work"

# --- run-linux.sh end to end ------------------------------------------------------------------------

new_world linux-pass
harness "$here/run-linux.sh" "$O" "$HOST"
check "m06_linux_a_run_with_the_iroh_targets_built_and_every_binary_passing_exits_0" bash -c '[ "$1" = 0 ]' _ "$rc"
check "m06_linux_the_iroh_targets_ran_with_the_rest_each_with_its_exit_line" \
    bash -c 't=$1; for n in plain_rt heimdall_testkit-unit heimdall_transport_iroh-unit iroh_rt iroh_cli; do grep -qx "### $n exit=0" "$t" || exit 1; done; [ "$(grep -c "^### .* exit=" "$t")" = 5 ]' _ "$O/tests.txt"
check "m06_linux_the_iroh_targets_ran_against_the_feature_builds_own_cli_and_the_others_against_the_default_one" \
    bash -c 'python3 -I - "$1" <<PY
import re, sys
cur, seen = None, {}
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"^### ([A-Za-z0-9_-]+)$", line.strip())
    if m:
        cur = m.group(1)
    m = re.match(r"^env e2e_bin=(\S+) content=(\S+)$", line.strip())
    if m and cur:
        seen[cur] = m.groups()
want = {"plain_rt": ("heimdall", "default-cli"), "heimdall_testkit-unit": ("heimdall", "default-cli"),
        "iroh_rt": ("feature/heimdall", "feature-cli"), "iroh_cli": ("feature/heimdall", "feature-cli"),
        "heimdall_transport_iroh-unit": ("feature/heimdall", "feature-cli")}
sys.exit(0 if seen == want else 1)
PY' _ "$O/tests.txt"
check "m06_linux_host_txt_names_the_feature_targets_and_no_blocked_target" \
    bash -c 'grep -qxF "feature-targets=iroh: iroh_cli iroh_rt heimdall_transport_iroh-unit" "$1" && grep -q "^feature-cli=the iroh-feature heimdall " "$1" && ! grep -q "^feature-blocked-" "$1"' _ "$O/host.txt"
check "m06_linux_the_feature_build_is_recorded_and_both_clis_are_hashed" \
    bash -c 'grep -q "^exit 0: cargo test --target x86_64-unknown-linux-gnu --profile native-test -p <package> --features iroh .*, and --lib for the unit tests of heimdall-transport-iroh (3 targets built)$" "$1" &&
        grep -q "^heimdall (CLI for the e2e suites, HEIMDALL_E2E_BIN) sha256: [0-9a-f]\{64\}$" "$2" && grep -q "^heimdall (iroh feature; .*) sha256: [0-9a-f]\{64\}$" "$2" &&
        [ "$(grep -c "^heimdall (" "$2")" = 2 ] && [ "$(grep "^heimdall (" "$2" | sed "s/.*sha256: //" | sort -u | wc -l | tr -d " ")" = 2 ]' _ "$O/commands.txt" "$O/build.txt"
check "m06_linux_the_scratch_directory_hm_m06_random_was_created_and_removed_and_its_name_is_anonymized" \
    bash -c '[ -d "$1" ] && [ -z "$(ls -A "$1")" ] && grep -q "ssh <linuxhost> mkdir (exclusive) ~/hm-m06-<random>" "$2/commands.txt" &&
        grep -q "^exit 0: ssh <linuxhost> rm -rf the run.s scratch dir, then check it is absent$" "$2/commands.txt" && ! grep -rqE "hm-m06-[0-9a-f]{12}" "$2"' _ "$H" "$O"
check "m06_linux_no_artifact_names_the_home_the_user_or_the_host (the build log's paths are redacted)" \
    bash -c '! grep -rqF -e "$2" -e "$3" "$1" && grep -q "^exit 0: leak scan" "$1/commands.txt" && grep -q "^exit 0: canary-prefix scan" "$1/commands.txt"' _ "$O" "$H" "$HOST"

new_world linux-blocked
extra_env=(HM_ST_FEATURE_FAIL=pkg-rt)
harness "$here/run-linux.sh" "$O" "$HOST"
check "m06_linux_an_iroh_target_that_does_not_build_gives_exit_6_never_0" bash -c '[ "$1" = 6 ]' _ "$rc"
check "m06_linux_the_blocked_target_is_a_host_fact_with_cargos_exit_code_and_first_error_redacted" \
    bash -c 'grep -q "^feature-blocked-iroh_rt=the iroh-feature build of pkg-rt failed (cargo exit 101): error\[E0463\]: can.t find crate for .iroh. in <home>/hm-selftest-checkout with a tab$" "$1" &&
        [ "$(grep -c "^feature-blocked-" "$1")" = 1 ]' _ "$O/host.txt"
check "m06_linux_the_blocked_target_has_no_result_line_and_every_other_target_still_ran" \
    bash -c 't=$1; ! grep -q "^### iroh_rt" "$t" && for n in plain_rt heimdall_testkit-unit iroh_cli; do grep -qx "### $n exit=0" "$t" || exit 1; done' _ "$O/tests.txt"
check "m06_linux_the_blocked_build_is_recorded_as_such_and_the_scratch_directory_is_removed" \
    bash -c 'grep -q "^exit 0: record the iroh-feature targets that did not build as blocked (1; " "$1/commands.txt" && [ -z "$(ls -A "$2")" ]' _ "$O" "$H"

new_world linux-unit-blocked
extra_env=(HM_ST_FEATURE_FAIL=heimdall-transport-iroh)
harness "$here/run-linux.sh" "$O" "$HOST"
check "m06_linux_transport_unit_tests_that_do_not_build_with_the_feature_are_blocked_and_have_no_result_line (exit 6)" \
    bash -c '[ "$1" = 6 ] && grep -q "^feature-blocked-heimdall_transport_iroh-unit=the iroh-feature build of heimdall-transport-iroh failed (cargo exit 101): " "$2/host.txt" &&
        ! grep -q "^### heimdall_transport_iroh-unit" "$2/tests.txt" && grep -qx "### iroh_rt exit=0" "$2/tests.txt"' _ "$rc" "$O"

new_world linux-allblocked
extra_env=(HM_ST_FEATURE_FAIL="pkg-rt pkg-cli")
harness "$here/run-linux.sh" "$O" "$HOST"
check "m06_linux_with_no_iroh_target_built_the_rest_runs_against_the_default_cli_and_the_run_exits_6" \
    bash -c '[ "$1" = 6 ] && [ "$(grep -c "^feature-blocked-" "$2/host.txt")" = 2 ] && grep -qxF "feature-cli=none built (no selected package builds the heimdall binary)" "$2/host.txt" &&
        grep -qx "### plain_rt exit=0" "$2/tests.txt" && grep -q "^env e2e_bin=heimdall content=default-cli$" "$2/tests.txt" && ! grep -q "content=feature-cli" "$2/tests.txt"' _ "$rc" "$O"

new_world linux-fail
exe iroh_cli fail
harness "$here/run-linux.sh" "$O" "$HOST"
check "m06_linux_a_failing_iroh_test_gives_its_exit_code_and_is_never_blocked" \
    bash -c '[ "$1" = 101 ] && grep -qx "### iroh_cli exit=101" "$2/tests.txt" && ! grep -q "^feature-blocked-" "$2/host.txt" && [ -z "$(ls -A "$3")" ]' _ "$rc" "$O" "$H"

new_world linux-only
extra_env=(HM_ONLY="iroh_rt plain_rt")
harness "$here/run-linux.sh" "$O" "$HOST"
check "m06_linux_HM_ONLY_selects_iroh_targets_like_any_other" \
    bash -c '[ "$1" = 0 ] && [ "$(grep -c "^### .* exit=" "$2/tests.txt")" = 2 ] && grep -qx "### iroh_rt exit=0" "$2/tests.txt" && grep -q "^iroh_cli: not selected (HM_ONLY)$" "$2/skipped.txt"' _ "$rc" "$O"

new_world linux-build
extra_env=(HM_BUILD_ONLY=1)
harness "$here/run-linux.sh" "$O"
check "m06_linux_build_only_builds_the_iroh_targets_too_and_reaches_no_host" \
    bash -c '[ "$1" = 0 ] && ! grep -q "^ssh " "$2" && grep -q "^iroh_rt sha256: [0-9a-f]\{64\}$" "$3/build.txt" && grep -qxF "feature-targets=iroh: iroh_cli iroh_rt heimdall_transport_iroh-unit" "$3/build.txt" &&
        grep -q "^heimdall_transport_iroh-unit sha256: [0-9a-f]\{64\}$" "$3/build.txt" && [ -z "$(ls -A "$4")" ]' _ "$rc" "$L" "$O" "$H"
new_world linux-build-blocked
extra_env=(HM_BUILD_ONLY=1 HM_ST_FEATURE_FAIL=pkg-cli)
harness "$here/run-linux.sh" "$O"
check "m06_linux_build_only_reports_a_blocked_iroh_build_with_exit_6" \
    bash -c '[ "$1" = 6 ] && grep -q "^feature-blocked-iroh_cli=the iroh-feature build of pkg-cli failed (cargo exit 101): " "$2/build.txt"' _ "$rc" "$O"

# ⟨M06 exit⟩ run-linux-batches.sh in the fake world: the list read on fd 3, ssh -n for the
# free-space check, the 3 GiB floor, the coverage check against the build-only plan, and
# run-linux.sh's HM_STAGE_MAX_KB cap (exit 7 before anything is copied).
batch_world() {
    new_world "$1"
    cat >"$B/df" <<'DF'
#!/usr/bin/env bash
# df stub: `df -Pk DIR` answers HM_ST_DF_KB KiB available; anything else is the real df.
if [ "${1:-}" = -Pk ]; then
    echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
    echo "stub 99999999 1 ${HM_ST_DF_KB:-9999999} 1% /"
    exit 0
fi
exec /bin/df "$@"
DF
    chmod +x "$B/df"
    printf '# a comment\nb1 plain_rt heimdall_testkit-unit   # trailing comment\n\nb2 iroh_rt iroh_cli heimdall_transport_iroh-unit\n' >"$S/batches.txt"
}
batch_world linux-batches
harness "$here/run-linux-batches.sh" "$O" "$HOST" "$S/batches.txt"
check "m06_batches_run_every_batch_into_its_own_directory_and_exit_0" \
    bash -c '[ "$1" = 0 ] && grep -qx "### plain_rt exit=0" "$2/linux-b1/tests.txt" && grep -qx "### iroh_cli exit=0" "$2/linux-b2/tests.txt" &&
        ! grep -q "^### iroh_rt" "$2/linux-b1/tests.txt" && ! grep -q "^### plain_rt" "$2/linux-b2/tests.txt"' _ "$rc" "$O"
check "m06_batches_record_each_floor_check_and_batch_exit_as_a_commands_log_the_generator_reads" \
    bash -c '[ "$(grep -c "^exit 0: ssh -n <linuxhost> df -Pk \$HOME before batch b[12]: 9999999 KiB free" "$1")" = 2 ] &&
        grep -q "^exit 0: HM_ONLY=<the 2 targets of batch b1> HM_STAGE_MAX_KB=1572864 tests/native/m06/run-linux.sh" "$1" &&
        grep -q "^exit 0: HM_ONLY=<the 3 targets of batch b2> " "$1" && grep -q "^exit 0: staged set [0-9]* KiB (HM_STAGE_MAX_KB cap 1572864 KiB)$" "$2/linux-b1/commands.txt"' _ "$O/linux-batches.txt" "$O"
check "m06_batches_every_free_space_ssh_has_-n_and_no_scratch_directory_is_left" \
    bash -c '[ "$(grep -c "^ssh -n -o BatchMode=yes .* df -Pk" "$1")" = 2 ] && ! grep "df -Pk" "$1" | grep -qv "^ssh -n " && [ -z "$(ls -A "$2")" ]' _ "$L" "$H"
check "m06_batches_print_the_linux_platform_entries_for_the_exit_configuration" \
    bash -c 'grep -qF "\"logs\": [\"linux-b1/tests.txt\", \"linux-b2/tests.txt\"]," "$1" && grep -qF "\"commands_logs\": [\"linux-batches.txt\", \"linux-b1/commands.txt\", \"linux-b2/commands.txt\"]," "$1"' _ "$S/harness.log"

batch_world linux-batches-cover
printf 'b1 plain_rt heimdall_testkit-unit\nb2 iroh_rt iroh_cli\n' >"$S/batches.txt"
harness "$here/run-linux-batches.sh" "$O" "$HOST" "$S/batches.txt"
check "m06_batches_refuse_a_list_that_misses_a_planned_target_before_any_host_is_contacted (exit 2)" \
    bash -c '[ "$1" = 2 ] && grep -q "planned targets in no batch .*heimdall_transport_iroh-unit" "$2" && ! grep -q "^ssh " "$3" && [ ! -e "$4/linux-batches.txt" ]' _ "$rc" "$S/harness.log" "$L" "$O"
printf 'b1 plain_rt heimdall_testkit-unit no_such_target\nb2 iroh_rt iroh_cli heimdall_transport_iroh-unit plain_rt\n' >"$S/batches.txt"
rm -rf "$O"
harness "$here/run-linux-batches.sh" "$O" "$HOST" "$S/batches.txt"
check "m06_batches_refuse_a_target_in_two_batches_or_one_the_build_does_not_plan (exit 2)" \
    bash -c '[ "$1" = 2 ] && grep -q "targets in more than one batch: plain_rt" "$2" && ! grep -q "^ssh " "$3"' _ "$rc" "$S/harness.log" "$L"

batch_world linux-batches-floor
extra_env=(HM_ST_DF_KB=3145727)
harness "$here/run-linux-batches.sh" "$O" "$HOST" "$S/batches.txt"
check "m06_batches_stop_below_the_3_GiB_floor_blocked_with_nothing_staged (exit 3)" \
    bash -c '[ "$1" = 3 ] && grep -q "^exit 3: ssh -n <linuxhost> df -Pk \$HOME before batch b1: 3145727 KiB free, below the 3145728 KiB floor (blocked)$" "$2/linux-batches.txt" &&
        [ ! -e "$2/linux-b1" ] && ! grep -q "mkdir" "$3"' _ "$rc" "$O" "$L"
extra_env=(HM_BATCH_FLOOR_KB=1048576)
rm -rf "$O"
harness "$here/run-linux-batches.sh" "$O" "$HOST" "$S/batches.txt"
check "m06_batches_refuse_a_floor_below_3_GiB (exit 2)" bash -c '[ "$1" = 2 ] && grep -q "below 3 GiB is refused" "$2"' _ "$rc" "$S/harness.log"

batch_world linux-batches-cap
extra_env=(HM_BATCH_STAGE_MAX_KB=1)
harness "$here/run-linux-batches.sh" "$O" "$HOST" "$S/batches.txt"
check "m06_batches_a_staged_set_over_the_cap_is_exit_7_before_the_tar_stream_and_stops_the_run" \
    bash -c '[ "$1" = 7 ] && grep -q "^exit 7: staged set [0-9]* KiB, over the HM_STAGE_MAX_KB cap of 1 KiB: nothing copied$" "$2/linux-b1/commands.txt" &&
        ! grep -q "tar stream" "$2/linux-b1/commands.txt" && [ ! -e "$2/linux-b2" ] && grep -q "^exit 7: HM_ONLY=<the 2 targets of batch b1>" "$2/linux-batches.txt" &&
        [ -z "$(ls -A "$3")" ]' _ "$rc" "$O" "$H"

# --- run-macos.sh against a fake repository root ------------------------------------------------------

# fake_root DIR: the M02 harness files and the M06 wrapper and case index, with a stub check.sh.
fake_root() {
    local r=$1
    mkdir -p "$r/tests/native/m06" "$r/tools/validation"
    cp -R "$m02" "$r/tests/native/m02"
    rm -rf "$r/tests/native/m02/__pycache__"
    cp "$here/run-macos.sh" "$here/case-index.json" "$r/tests/native/m06/"
    cat >"$r/tools/validation/check.sh" <<'EOF'
#!/usr/bin/env bash
# check.sh stub: the shape of the real output; it must not see the harness's milestone settings.
echo "== test: cargo test --workspace --locked"
echo "     Running unittests src/lib.rs (target/debug/deps/heimdall_x-0123abcd)"
echo "test a::b ... ok"
echo "env feature=${HM_FEATURE:-unset} harness_dir=${HM_HARNESS_DIR:-unset}"
echo "== overall: exit 0"
EOF
    chmod +x "$r/tools/validation/check.sh"
}
new_world mac-pass
fake_root "$S/repo"
harness "$S/repo/tests/native/m06/run-macos.sh" "$O"
check "m06_macos_a_run_with_check_sh_the_observation_pass_and_the_iroh_targets_passing_exits_0" bash -c '[ "$1" = 0 ]' _ "$rc"
check "m06_macos_the_iroh_targets_ran_per_package_with_the_feature_and_show_output_after_being_built" \
    bash -c 'L=$1; grep -qxF "cargo test --locked -p pkg-cli --features iroh --test iroh_cli --no-run" "$L" &&
        grep -qxF "cargo test --locked --no-fail-fast -p pkg-cli --features iroh --test iroh_cli -- --show-output" "$L" &&
        grep -qxF "cargo test --locked --no-fail-fast -p pkg-rt --features iroh --test iroh_rt -- --show-output" "$L" && ! grep -q -e "--target-dir" "$L"' _ "$L"
check "m06_macos_features_txt_keeps_their_cargo_output_for_the_generator_with_the_home_redacted" \
    bash -c 'f=$1/macos/features.txt; grep -q "Running tests/x/iroh_rt.rs (target/debug/deps/iroh_rt-0123abcd)" "$f" && grep -q "Running tests/x/iroh_cli.rs" "$f" &&
        grep -qx "m06 observation: iroh_cli step: ok in <home>" "$f" && [ "$(grep -c "^test fixture::a ... ok$" "$f")" = 2 ]' _ "$O"
check "m06_macos_the_feature_passes_are_recorded_with_their_exit_codes_and_the_targets_are_a_host_fact" \
    bash -c 'c=$1/macos/commands.txt; [ "$(grep -c "^exit 0: cargo test --locked --no-fail-fast -p pkg-[a-z]* --features iroh " "$c")" = 2 ] &&
        grep -qxF "feature-targets=iroh: iroh_cli iroh_rt" "$1/macos/host.txt" && ! grep -q "^feature-blocked-" "$1/macos/host.txt"' _ "$O"
check "m06_macos_check_sh_never_inherits_the_milestone_settings" grep -qxF "env feature=unset harness_dir=unset" "$O/macos/check.txt"
check "m06_macos_the_observation_pass_ran_the_case_indexs_observation_targets" \
    bash -c 'grep -q "^cargo test --workspace --locked --no-fail-fast --test e2e_exit_m06 --test e2e_environment_runner_m06 -- --show-output$" "$1" && [ -f "$2/macos/observations.txt" ]' _ "$L" "$O"
check "m06_macos_the_scratch_directory_is_removed_and_recorded" \
    bash -c 'grep -q "^exit 0: remove exactly the run.s scratch directory, then check it is absent$" "$1/macos/commands.txt"' _ "$O"

new_world mac-blocked
fake_root "$S/repo"
extra_env=(HM_ST_FEATURE_FAIL=pkg-rt)
harness "$S/repo/tests/native/m06/run-macos.sh" "$O"
check "m06_macos_an_iroh_package_that_does_not_build_gives_exit_6_and_a_feature_blocked_fact" \
    bash -c '[ "$1" = 6 ] && grep -q "^feature-blocked-iroh_rt=the iroh-feature build of pkg-rt failed (cargo exit 101): error\[E0463\]: can.t find crate for .iroh. in <home>/hm-selftest-checkout with a tab$" "$2/macos/host.txt" &&
        grep -qxF "feature-targets=iroh: iroh_cli" "$2/macos/host.txt"' _ "$rc" "$O"
check "m06_macos_the_blocked_package_was_never_run_and_the_other_one_was" \
    bash -c '! grep -q "^cargo test --locked --no-fail-fast -p pkg-rt " "$1" && grep -q "^cargo test --locked --no-fail-fast -p pkg-cli " "$1" &&
        ! grep -q "iroh_rt" "$2/macos/features.txt" && grep -q "^exit 0: record the iroh-feature targets of pkg-rt that did not build as blocked " "$2/macos/commands.txt"' _ "$L" "$O"

new_world mac-fail
fake_root "$S/repo"
extra_env=(HM_ST_FEATURE_TEST_FAIL=iroh_rt)
harness "$S/repo/tests/native/m06/run-macos.sh" "$O"
check "m06_macos_a_failing_iroh_test_gives_cargos_exit_code_recorded_and_is_never_blocked" \
    bash -c '[ "$1" = 101 ] && grep -q "^exit 101: cargo test --locked --no-fail-fast -p pkg-rt --features iroh " "$2/macos/commands.txt" &&
        grep -q "^test fixture::a ... FAILED$" "$2/macos/features.txt" && ! grep -q "^feature-blocked-" "$2/macos/host.txt"' _ "$rc" "$O"

new_world mac-build
fake_root "$S/repo"
extra_env=(HM_BUILD_ONLY=1)
harness "$S/repo/tests/native/m06/run-macos.sh" "$O"
check "m06_macos_build_only_builds_the_iroh_targets_too_and_runs_nothing" \
    bash -c '[ "$1" = 0 ] && grep -q "^iroh_cli sha256: [0-9a-f]\{64\}$" "$2/macos/build.txt" && grep -qxF "feature-targets=iroh: iroh_cli iroh_rt" "$2/macos/build.txt" &&
        ! grep -q -e "--show-output" "$3" && [ ! -f "$2/macos/check.txt" ]' _ "$rc" "$O" "$L"

# ⟨M06 W5g⟩ The cross-host journey (run-crosshost.sh, its runner-side script and its tool): the
# helpers on synthetic data (the step plan, the key-store guard, the scratch ssh configuration, the
# log the generator reads, the runner script's refusals). No host is contacted and nothing is built.
check "m06_crosshost_scripts_parse" bash -c 'bash -n "$1/run-crosshost.sh" && bash -n "$1/crosshost-runner.sh"' _ "$here"
(cd "$T" && bash "$here/run-crosshost.sh" --selftest) >"$T/crosshost.log" 2>&1 </dev/null
xrc=$?
check "m06_crosshost_selftest_passes ($(tail -n 1 "$T/crosshost.log"))" \
    bash -c '[ "$1" = 0 ] && grep -q "^run-crosshost selftest: [1-9][0-9]* passed, 0 failed$" "$2" && grep -q "^ok   G03 " "$2" && ! grep -q "^FAIL" "$2"' _ "$xrc" "$T/crosshost.log"
check "m06_crosshost_plan_is_the_case_index_scenario_in_order" \
    bash -c 'bash "$1/run-crosshost.sh" --plan | cut -d" " -f1 >"$2/plan.txt" &&
        python3 -I -c "import json, sys; print(chr(10).join(json.load(open(sys.argv[1]))[\"scenario_targets\"][\"crosshost-journey\"][\"steps\"]))" "$1/case-index.json" | cmp -s - "$2/plan.txt"' _ "$here" "$T"
check "m06_crosshost_never_uses_the_owner_agent_for_a_fixture_and_never_a_blanket_kill" \
    bash -c '! grep -nE "pkill|killall|kill -9 -1|ssh-add -D" "$1/run-crosshost.sh" "$1/crosshost-runner.sh" &&
        grep -q -- "-o ControlMaster=no -o ControlPath=none" "$1/run-crosshost.sh" && grep -q "HEIMDALL_TEST_MGMT_STORE=" "$1/run-crosshost.sh" &&
        grep -q "HEIMDALL_TEST_IROH_KEY_STORE=" "$1/run-crosshost.sh" && ! grep -q "tests/evidence" "$1/run-crosshost.sh"' _ "$here"

# ⟨M06 W5 `w5s`, M06-W5-R04⟩ The runner-side scripts start every `heimdall` with the three fixture
# key stores (AGENTS.md "Boundaries"): each environment that names the runner's Heimdall home, the
# runner's own sshd's SetEnv and the seed driver's name all three, in ROOT.
check "m06_runner_scripts_start_heimdall_with_the_three_fixture_key_stores" \
    python3 -I -c '
import re, sys
bad = []
for path in sys.argv[1:]:
    lines = open(path).read().splitlines()
    starts = [i for i, l in enumerate(lines)
              if re.search(r"HEIMDALL_HOME=\"\$home\"|HM_M06J_HOME=\"\$home\"|^SetEnv ", l)]
    if not starts:
        bad.append(path + ": no launch found")
    for i in starts:
        block = " ".join(lines[max(0, i - 1):i + 4])
        for v in ("HEIMDALL_TEST_SECRET_STORE=scratch", "HEIMDALL_TEST_MGMT_STORE=\"$mgmt_store\"",
                  "HEIMDALL_TEST_IROH_KEY_STORE=\"$iroh_store\""):
            if v not in block:
                bad.append("%s:%d: %s missing" % (path, i + 1, v.split("=")[0]))
    text = "\n".join(lines)
    if "mgmt_store=\"fixture-file:$root/" not in text or "iroh_store=$root/" not in text:
        bad.append(path + ": the stores are not in ROOT")
print("\n".join(bad))
sys.exit(1 if bad else 0)
' "$here/windows-controller-runner.sh" "$here/crosshost-runner.sh"

echo "m06-selftest: $passes passed, $fails failed"
[ "$fails" = 0 ]
