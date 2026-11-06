#!/usr/bin/env bash
# Local self-test of the native harnesses: the Windows ones (reviews B01 and B03:
# tests/native/windows-ipc/run-native.sh, tests/native/m01/run-windows.sh and their
# scratch helpers tests/native/windows-ipc/scratch-lib.sh) and the M02 ones
# (tests/native/m02: run-linux.sh, run-macos.sh, run-windows.sh, run-wsl-distro.sh,
# scenario-ordinary-ssh.sh, target-root.sh and their helpers), through
# tests/native/m02/selftest.sh and the evidence generator's Python tests.
#
# Reaches no host and builds nothing: `ssh`, `scp`, `cargo`, `rustc` and `zig`
# are stubs first on PATH (the ssh stub accepts only the fake alias and runs the
# remote script locally with HOME pointed at a fake WSL home and /mnt/c rewritten
# to a fake Windows tree under this run's mktemp directory; scp copies into the
# fake home). The "test binaries" are stub scripts that pass or fail on demand.
# Everything lives under one mktemp directory, removed on exit, pass or fail.
#
# Checks:
#   B01  unique run directories, created exclusively on both sides; an existing
#        directory with the task's name (an earlier or concurrent run) is left
#        untouched; only the directories this run created are removed; HM_TASK
#        '.', '..' and other bad names are rejected before anything runs; a
#        symlinked hm-m00 root (WSL or Windows side) is refused and nothing behind
#        it is written or removed; the helpers refuse to reuse a directory and to
#        remove anything but the exact created path.
#   B03  windows-ipc: the windows:: subset passes but a later suite fails -> the
#        harness exits nonzero, and commands.txt keeps both exits. m01: a failing
#        binary -> nonzero.
#
#   M02  tests/native/m02/selftest.sh (its own checks, listed in that file's header: the
#        helpers, run-linux/macos/windows/wsl-distro with stubs and a fake host tree, the
#        scenario in its isolated mode when a debug heimdall and a sshd exist) and
#        tests/native/m02/test_m02_evidence.py (the evidence generator, platform scans and
#        pty driver); their counts are added to this script's.
#
# Usage: tools/validation/native-harness-selftest.sh [root]
#   root  directory holding tests/native/... (default: this checkout); another
#         root runs the same checks against other copies of the harnesses.
# Exit: 0 when every check passes, 1 otherwise. Prints one line per check only
# (HM_SELFTEST_VERBOSE=1 also prints each harness log, which may contain local
# temporary paths).

set -u
here=$(cd "$(dirname "$0")/../.." && pwd) || exit 2
root=${1:-$here}
root=$(cd "$root" && pwd) || exit 2
T=$(mktemp -d) || exit 2
T=$(cd "$T" && pwd -P)
trap 'rm -rf "$T"' EXIT

HOST=hm-selftest-no-such-host
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

# --- the fake world ----------------------------------------------------------

# new_world NAME: fresh fake WSL home ($H), Windows tree ($W), stub bin ($B),
# stub executables ($X), artifact dir ($O) and call log ($L).
new_world() {
    S="$T/$1"
    H="$S/home"
    W="$S/win"
    B="$S/bin"
    X="$S/exes"
    O="$S/out"
    L="$S/calls.log"
    mkdir -p "$H" "$W/localappdata" "$W/Windows/System32/WindowsPowerShell/v1.0" "$B" "$X"
    : >"$L"
    write_stubs
}

write_stubs() {
    cat >"$B/ssh" <<'EOF'
#!/usr/bin/env bash
# ssh stub: never connects; runs the remote command in the fake host.
set -u
{ printf 'ssh'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
while [ $# -gt 0 ]; do
    case "$1" in -F | -o) shift 2 ;; -*) shift ;; *) break ;; esac
done
[ "${1:-}" = "$HM_ST_HOST" ] || { echo "ssh stub: unexpected host" >&2; exit 255; }
shift
cmd="$*"
case "$cmd" in
    "bash -s"*)
        sed "s#/mnt/c#$HM_ST_WINROOT#g" |
            env HOME="$HM_ST_HOME" PATH="$HM_ST_BIN:$PATH" bash -c "$cmd" ;;
    *) env HOME="$HM_ST_HOME" PATH="$HM_ST_BIN:$PATH" bash -c "$cmd" </dev/null ;;
esac
EOF
    cat >"$B/scp" <<'EOF'
#!/usr/bin/env bash
# scp stub: copies into the fake WSL home.
set -u
{ printf 'scp'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
while [ $# -gt 0 ]; do
    case "$1" in -F | -o) shift 2 ;; -*) shift ;; *) break ;; esac
done
src=$1
dst=${2#"$HM_ST_HOST":}
case "$dst" in /*) ;; *) dst="$HM_ST_HOME/$dst" ;; esac
cp -- "$src" "$dst"
EOF
    cat >"$B/cargo" <<'EOF'
#!/usr/bin/env bash
{ printf 'cargo'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
cat "$HM_ST_BUILD_JSON"
EOF
    printf '#!/usr/bin/env bash\necho "rustc 0.0.0-selftest"\n' >"$B/rustc"
    printf '#!/usr/bin/env bash\necho "0.0.0-selftest"\n' >"$B/zig"
    # GNU base64 -w0 is not portable; the stub PowerShell ignores its argument.
    printf '#!/usr/bin/env bash\ncat >/dev/null\necho AA==\n' >"$B/base64"
    if ! command -v timeout >/dev/null 2>&1; then
        printf '#!/usr/bin/env bash\nshift\nexec "$@"\n' >"$B/timeout"
    fi
    cat >"$B/wslpath" <<'EOF'
#!/usr/bin/env bash
# C:\a\b <-> $HM_ST_WINROOT/a/b
if [ "$1" = -w ]; then
    rest=${2#"$HM_ST_WINROOT"}
    rest=${rest#/}
    printf 'C:\\%s\n' "$(printf '%s' "$rest" | tr / '\\')"
else
    rest=${1#?:}
    rest=${rest#\\}
    printf '%s/%s\n' "$HM_ST_WINROOT" "$(printf '%s' "$rest" | tr '\\' /)"
fi
EOF
    local sys="$W/Windows/System32"
    cat >"$sys/cmd.exe" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *LOCALAPPDATA*) printf 'C:\\localappdata\r\n' ;;
    *USERNAME*) printf 'fixtureuser\r\n' ;;
    *COMPUTERNAME*) printf 'FIXTUREHOST\r\n' ;;
    *USERPROFILE*) printf 'C:\\Users\\fixtureuser\r\n' ;;
    *ver*) printf '\r\nMicrosoft Windows [Version 10.0.0.0]\r\n' ;;
esac
EOF
    printf '#!/usr/bin/env bash\necho "Mandatory Label\\\\Medium Mandatory Level"\n' >"$sys/whoami.exe"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$sys/tasklist.exe"
    printf '#!/usr/bin/env bash\necho 0\n' >"$sys/WindowsPowerShell/v1.0/powershell.exe"
    chmod +x "$B"/* "$sys/cmd.exe" "$sys/whoami.exe" "$sys/tasklist.exe" \
        "$sys/WindowsPowerShell/v1.0/powershell.exe"
}

# exe NAME pass|fail: a stub test binary.
exe() {
    if [ "$2" = pass ]; then
        printf '#!/usr/bin/env bash\necho "running 1 test"\necho "test fixture::case ... ok"\necho "test result: ok. 1 passed; 0 failed"\nexit 0\n' >"$X/$1"
    else
        printf '#!/usr/bin/env bash\necho "running 1 test"\necho "test fixture::case ... FAILED"\necho "test result: FAILED. 0 passed; 1 failed"\nexit 101\n' >"$X/$1"
    fi
    chmod +x "$X/$1"
}

# artifact NAME KIND TEST(true|false): one cargo compiler-artifact line.
artifact() {
    printf '{"reason":"compiler-artifact","target":{"name":"%s","kind":["%s"]},"profile":{"test":%s},"executable":"%s"}\n' \
        "$1" "$2" "$3" "$X/$1"
}

# ipc_build [failing-target]: the windows-ipc harness's four test binaries.
ipc_build() {
    local t
    : >"$S/build.json"
    for t in heimdall_ipc adversarial_ipc_frames adversarial_agent_frames integration_ipc_unix; do
        if [ "$t" = "${1:-}" ]; then exe "$t" fail; else exe "$t" pass; fi
        if [ "$t" = heimdall_ipc ]; then
            artifact "$t" lib true >>"$S/build.json"
        else
            artifact "$t" test true >>"$S/build.json"
        fi
    done
}

# m01_build [failing-target]: a lib unit binary, two test targets, the skipped
# `contracts` target and the CLI.
m01_build() {
    local t
    : >"$S/build.json"
    for t in heimdall_runtime integration_runtime adversarial_agent_frames contracts heimdall; do
        if [ "$t" = "${1:-}" ]; then exe "$t" fail; else exe "$t" pass; fi
    done
    {
        artifact heimdall_runtime lib true
        artifact integration_runtime test true
        artifact adversarial_agent_frames test true
        artifact contracts test true
        artifact heimdall bin false
    } >>"$S/build.json"
}

# harness SCRIPT TASK: run a harness in the fake world; sets $rc.
harness() {
    local script=$1 task=$2
    env HM_SSH_CONFIG=/dev/null HM_HOST="$HOST" HM_TASK="$task" \
        HM_ST_LOG="$L" HM_ST_HOST="$HOST" HM_ST_HOME="$H" HM_ST_WINROOT="$W" \
        HM_ST_BIN="$B" HM_ST_BUILD_JSON="$S/build.json" PATH="$B:$PATH" \
        bash "$root/tests/native/$script" "$O" >"$S/harness.log" 2>&1 </dev/null
    rc=$?
    if [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ]; then
        echo "--- $script ($task) exit $rc"
        cat "$S/harness.log"
    fi
}

# --- predicates --------------------------------------------------------------

is_zero() { [ "$1" = 0 ]; }
is_nonzero() { [ "$1" != 0 ]; }
is_two() { [ "$1" = 2 ]; }
# entries DIR: the sorted entry names (empty if DIR is absent).
# shellcheck disable=SC2012  # fixture names only ([A-Za-z0-9._-])
entries() { [ -d "$1" ] && (cd "$1" && ls -A | sort | tr '\n' ' '); }
entries_are() { [ "$(entries "$1")" = "$2" ]; }
has_file() { [ -f "$1" ]; }
log_empty() { [ ! -s "$L" ]; }
no_scp() { ! grep -q '^scp' "$L"; }
grep_q() { grep -qF -- "$1" "$2" 2>/dev/null; }
run_name() { sed -n 's/.*create the run directories exclusively (run \(.*\))$/\1/p' "$1" | head -1; }
differ() { [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ]; }
starts_with() { case "$1" in "$2"*) return 0 ;; esac; return 1; }
# exit_agrees RC FAILS: a self-test exits 0 exactly when it reports no failure.
exit_agrees() { { [ "$1" = 0 ] && [ "$2" = 0 ]; } || { [ "$1" != 0 ] && [ "$2" != 0 ]; }; }

# --- harness scenarios ---------------------------------------------------------

for spec in windows-ipc/run-native.sh:ipc_build m01/run-windows.sh:m01_build; do
    script=${spec%%:*}
    build=${spec#*:}
    tag=${script%%/*}

    # B01: an existing directory named like the task (an earlier or concurrent
    # run's, with its own files) on both sides is never touched; this run uses
    # its own unique directories and removes exactly those.
    new_world "$tag-existing"
    $build
    mkdir -p "$H/hm-m00/M01-old" "$W/localappdata/hm-m00/M01-old"
    echo keep >"$H/hm-m00/M01-old/other-run.txt"
    echo keep >"$W/localappdata/hm-m00/M01-old/other-run.txt"
    harness "$script" M01-old
    check "B01 $tag: run with all suites passing exits 0" is_zero "$rc"
    check "B01 $tag: another run's WSL files survive" has_file "$H/hm-m00/M01-old/other-run.txt"
    check "B01 $tag: another run's Windows files survive" has_file "$W/localappdata/hm-m00/M01-old/other-run.txt"
    check "B01 $tag: WSL scratch holds no leftover run directory" entries_are "$H/hm-m00" "M01-old "
    check "B01 $tag: Windows scratch holds no leftover run directory" entries_are "$W/localappdata/hm-m00" "M01-old "
    check "B01 $tag: no binaries written into the other run's directory" entries_are "$H/hm-m00/M01-old" "other-run.txt "
    first=$(run_name "$O/commands.txt")
    check "B01 $tag: the run directory is <task>-<random>" starts_with "$first" "M01-old-"
    harness "$script" M01-old
    second=$(run_name "$O/commands.txt")
    check "B01 $tag: two runs use different directories" differ "$first" "$second"

    # B01: '.', '..' and other bad names are rejected before any build or ssh.
    n=0
    for bad in . .. -x 'a/b' ''; do
        n=$((n + 1))
        new_world "$tag-bad-$n"
        $build
        harness "$script" "$bad"
        [ -n "$bad" ] || rc_bad_empty=$rc
        if [ -n "$bad" ]; then
            check "B01 $tag: HM_TASK '$bad' rejected with exit 2" is_two "$rc"
            check "B01 $tag: HM_TASK '$bad' reaches no cargo, ssh or scp" log_empty
        fi
    done
    # An empty HM_TASK means the default task name (the variable is unset-like).
    check "B01 $tag: empty HM_TASK falls back to the default and passes" is_zero "${rc_bad_empty:-1}"

    # B01: a symlinked WSL scratch root is refused; nothing behind it changes.
    new_world "$tag-wsl-link"
    $build
    mkdir -p "$S/elsewhere"
    echo keep >"$S/elsewhere/unrelated.txt"
    ln -s "$S/elsewhere" "$H/hm-m00"
    harness "$script" M01-link
    check "B01 $tag: symlinked WSL root -> nonzero exit" is_nonzero "$rc"
    check "B01 $tag: nothing written or removed behind the WSL symlink" entries_are "$S/elsewhere" "unrelated.txt "
    check "B01 $tag: no Windows run directory created" entries_are "$W/localappdata" ""
    check "B01 $tag: no binaries copied after the refusal" no_scp

    # B01: a symlinked Windows scratch root is refused; the WSL directory this
    # run did create is removed, and nothing behind the symlink changes.
    new_world "$tag-win-link"
    $build
    mkdir -p "$S/elsewhere"
    echo keep >"$S/elsewhere/unrelated.txt"
    ln -s "$S/elsewhere" "$W/localappdata/hm-m00"
    harness "$script" M01-link
    check "B01 $tag: symlinked Windows root -> nonzero exit" is_nonzero "$rc"
    check "B01 $tag: nothing written or removed behind the Windows symlink" entries_are "$S/elsewhere" "unrelated.txt "
    check "B01 $tag: the WSL run directory it created was removed" entries_are "$H/hm-m00" ""
done

# B03: the windows:: subset passes, a later suite fails.
new_world ipc-later-fails
ipc_build adversarial_agent_frames
harness windows-ipc/run-native.sh M01-b03
check "B03 windows-ipc: a failing later suite -> nonzero exit" is_nonzero "$rc"
check "B03 windows-ipc: commands.txt keeps the windows:: exit (0)" \
    grep_q "exit 0: remote: heimdall_ipc_tests.exe windows::" "$O/commands.txt"
check "B03 windows-ipc: commands.txt keeps the full-run exit (101)" \
    grep_q "exit 101: remote: every test binary" "$O/commands.txt"
check "B03 windows-ipc: all-tests.txt shows the failing suite's exit" \
    grep_q "### adversarial_agent_frames exit=101" "$O/all-tests.txt"
check "B03 windows-ipc: run directories removed after the failure" entries_are "$H/hm-m00" ""

# B03: the windows:: subset itself fails.
new_world ipc-first-fails
ipc_build heimdall_ipc
harness windows-ipc/run-native.sh M01-b03
check "B03 windows-ipc: a failing windows:: run -> nonzero exit" is_nonzero "$rc"

# B03 (m01 harness): any failing binary -> nonzero.
new_world m01-fails
m01_build integration_runtime
harness m01/run-windows.sh M01-b03
check "B03 m01: a failing binary -> nonzero exit" is_nonzero "$rc"
check "B03 m01: tests.txt shows the failing binary's exit" \
    grep_q "### integration_runtime exit=101" "$O/tests.txt"

# --- scratch helpers -----------------------------------------------------------

lib="$root/tests/native/windows-ipc/scratch-lib.sh"
if [ -f "$lib" ]; then
    # shellcheck source=tests/native/windows-ipc/scratch-lib.sh
    . "$lib"
    P="$T/lib"
    mkdir -p "$P"
    valid_names() {
        hm_valid_name M01-U6w && hm_valid_name a.b_c-1 &&
            ! hm_valid_name . && ! hm_valid_name .. && ! hm_valid_name '' &&
            ! hm_valid_name -a && ! hm_valid_name .hidden && ! hm_valid_name 'a/b' &&
            ! hm_valid_name 'a b'
    }
    check "B01 lib: name rules (no '.', '..', separators, leading punctuation)" valid_names
    created=$(hm_scratch_create "$P" run-1 2>/dev/null)
    check "B01 lib: create prints the exact new directory" [ "$created" = "$P/hm-m00/run-1" ]
    echo keep >"$P/hm-m00/run-1/f"
    reuse() { ! hm_scratch_create "$P" run-1 >/dev/null 2>&1; }
    check "B01 lib: an existing run directory is never reused" reuse
    check "B01 lib: a refused reuse leaves the directory intact" has_file "$P/hm-m00/run-1/f"
    refuse_dot() { ! hm_scratch_create "$P" .. >/dev/null 2>&1 && ! hm_scratch_create "$P" . >/dev/null 2>&1; }
    check "B01 lib: create refuses '.' and '..'" refuse_dot
    wrong_run() { ! hm_scratch_remove "$P/hm-m00/run-1" run-2 2>/dev/null; }
    check "B01 lib: remove refuses a path that is not this run's" wrong_run
    check "B01 lib: ...and leaves it intact" has_file "$P/hm-m00/run-1/f"
    escaped() { ! hm_scratch_remove "$P/hm-m00/../hm-m00/run-1" run-1 2>/dev/null &&
        ! hm_scratch_remove "hm-m00/run-1" run-1 2>/dev/null; }
    check "B01 lib: remove refuses relative or non-canonical shapes" escaped
    noop() { hm_scratch_remove "" run-1; }
    check "B01 lib: nothing created -> nothing removed" noop
    check "B01 lib: ...and the directory is intact" has_file "$P/hm-m00/run-1/f"
    mkdir -p "$P/real/hm-m00/run-3" "$P/linked"
    echo keep >"$P/real/hm-m00/run-3/f"
    ln -s "$P/real/hm-m00" "$P/linked/hm-m00"
    via_link() { ! hm_scratch_remove "$P/linked/hm-m00/run-3" run-3 2>/dev/null; }
    check "B01 lib: remove refuses a symlinked root" via_link
    check "B01 lib: ...and nothing behind it is removed" has_file "$P/real/hm-m00/run-3/f"
    link_root() { ! hm_scratch_create "$P/linked" run-4 >/dev/null 2>&1; }
    check "B01 lib: create refuses a symlinked root" link_root
    check "B01 lib: ...creating nothing behind it" entries_are "$P/real/hm-m00" "run-3 "
    exact() { hm_scratch_remove "$created" run-1 && [ ! -e "$created" ]; }
    check "B01 lib: remove deletes exactly the created directory" exact
else
    check "B01 lib: tests/native/windows-ipc/scratch-lib.sh exists" false
fi

# --- M02 harnesses -------------------------------------------------------------------------

m02_dir="$root/tests/native/m02"
if [ -f "$m02_dir/selftest.sh" ]; then
    bash "$m02_dir/selftest.sh" "$root" >"$T/m02-selftest.out" 2>&1 </dev/null
    m02_rc=$?
    # Its checks, line by line (a failure names itself), then its totals join ours.
    cat "$T/m02-selftest.out"
    m02_line=$(grep '^m02-selftest: ' "$T/m02-selftest.out" | tail -1)
    m02_pass=$(printf '%s\n' "$m02_line" | sed -n 's/^m02-selftest: \([0-9][0-9]*\) passed.*/\1/p')
    m02_fail=$(printf '%s\n' "$m02_line" | sed -n 's/^m02-selftest: [0-9][0-9]* passed, \([0-9][0-9]*\) failed.*/\1/p')
    if [ -n "$m02_pass" ] && [ -n "$m02_fail" ]; then
        passes=$((passes + m02_pass))
        fails=$((fails + m02_fail))
        check "M02 selftest: its exit code agrees with its totals ($m02_pass passed, $m02_fail failed)" \
            exit_agrees "$m02_rc" "$m02_fail"
    else
        check "M02 selftest: it ran to its summary line" false
    fi
else
    check "M02 selftest: tests/native/m02/selftest.sh exists" false
fi
if [ -f "$m02_dir/test_m02_evidence.py" ]; then
    PYTHONDONTWRITEBYTECODE=1 python3 -I "$m02_dir/test_m02_evidence.py" >"$T/m02-py.out" 2>&1
    py_n=$(sed -n 's/^Ran \([0-9]*\) tests.*/\1/p' "$T/m02-py.out" | tail -1)
    check "M02 evidence generator, platform scan and pty driver unit tests (${py_n:-0} tests)" \
        grep -q '^OK$' "$T/m02-py.out"
    if ! grep -q '^OK$' "$T/m02-py.out"; then
        grep -E '^(FAIL|ERROR):' "$T/m02-py.out" | head -20
    fi
else
    check "M02 evidence tests: tests/native/m02/test_m02_evidence.py exists" false
fi

echo "native-harness-selftest: $passes passed, $fails failed"
[ "$fails" = 0 ]
