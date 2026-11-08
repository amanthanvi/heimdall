#!/usr/bin/env bash
# M02-U11: local self-test of the M02 native harnesses (m02-plan section 4), run by
# tools/validation/native-harness-selftest.sh (check.sh's native-harness-selftest step).
#
# Reaches no host and builds nothing: `ssh`, `cargo`, `rustc`, `zig`, `go`, `sshd`, `git`,
# `timeout`, `nice`, `uname` and, for the Windows side, `cmd.exe`, `powershell.exe`,
# `wsl.exe`, `reg.exe` and the rest are stubs first on PATH. The ssh stub accepts only
# the fake alias and runs the remote script locally with HOME pointed at a fake remote
# home and /mnt/c rewritten to a fake Windows tree; the "test binaries" are stub scripts
# that pass, fail or misbehave on demand. The test targets are the real case index's, so
# the real run plan (build_host_paths, whole targets and single tests) is what is
# exercised. Everything lives under one mktemp directory, removed on exit, pass or fail.
# Real processes started: ssh-keygen, tar, python3, and (scenario checks) ssh-agent and
# a loopback sshd of the account in the temp directory, each stopped by exact PID.
#
# Checks (prefix, what):
#   X   lib.sh and remote-lib.sh helpers: alias rules, redaction (forms, SIDs, addresses),
#       canary and leak scans (never print the value), digests, the fixture sshd's
#       configuration and its exact-PID stop, the environment sanitizing.
#   L   run-linux.sh: build-only reaches no host; the plan skips; a unique ~/hm-m02-<random>
#       scratch created exclusively, only that directory removed (pass or fail); under
#       `nice -n 10` and `timeout`; real exit codes in commands.txt; host facts (ssh -V,
#       sshd -V, git --version); the fixture preflight on 127.0.0.1 only; inherited agent,
#       Git and Heimdall variables unset; an architecture or reachability refusal; a
#       failing binary; canary, leak and ~/.ssh change detection; redaction.
#   M   run-macos.sh against a fake repository root: check.sh and its exit code, the
#       Docker fallback only when the fixture sshd cannot start (CLEANUP CONFIRMED required),
#       scratch removal, build-only.
#   W   run-windows.sh: unique run directories on both sides, other runs' files untouched,
#       bad task names and symlinked roots refused, the in-box OpenSSH first on PATH, the
#       fixture sshd in WSL scratch with HM_FIXTURE_SSHD_* through WSLENV, a forwarding
#       failure recorded, the pseudoconsole driver rows, nothing elevated, no registry
#       write, no service, the owner's profile unchanged, redaction.
#   D   run-wsl-distro.sh: the pinned image only (nothing imported otherwise), one
#       disposable distribution imported, prepared, used and unregistered by exact name;
#       the registered set equal afterwards; no `--shutdown`; an interrupted run's EXIT
#       trap unregisters; an existing distribution of the run's name is never touched.
#       Local mode (HM_LOCAL=1, ADR-0007 §12.32 item 15): no ssh, scp or tar stream to a host;
#       the prebuilt binary and its digest refused before anything is created (missing: exit 3,
#       mismatch: 1, malformed digest: 2); the same safety properties and redaction as the ssh
#       path; HM_BUILD_ONLY=1 prints prebuilt-heimdall=<path> and prebuilt-sha256=<hex>.
#   T   target-root.sh refusals.   S   scenario-ordinary-ssh.sh (see below).
#   P   run-windows-local.ps1 (Windows local mode, ADR-0007 §12.32 item 17) when pwsh is
#       installed: it parses, its -SelfTest passes, its bundle imports through
#       import-windows-bundle.py with nothing unredacted left, and a real run off Windows is
#       refused (exit 2, nothing created); `skip` without pwsh.
# Also (ADR-0007 §12.32 items 3 and 10): the harnesses ship the repository files the tests
# read and set HM_REPO_ROOT (nothing is build-host-only), redact host names as whole words,
# put the macOS scratch under /tmp, and redact the Windows build log before any exit.
# Also in L, M and W: every binary runs with --show-output and what a passing test printed
# (the `observation` lines of the tests that settle ADR-0007 facts) is kept, redacted; the
# macOS run repeats the case index's observation targets through cargo for the same reason.
# Not covered here: refresh-inventory.sh (it cross-builds; run it by hand at the build
# commit) and any real host: that is what the native runs are for.
#
# S (the scenario, run for real in its isolated mode: HM_SCENARIO_ISOLATED=1 keeps the
# account's home out of it): runs when the debug `heimdall` of the checkout's ./target, a
# non-root sshd, ssh-agent and ssh-keygen exist, else the checks print `skip` (a skip is
# neither a pass nor a failure; the distribution is where the scenario really counts).
# HM_SELFTEST_SCENARIO=0 turns it off. A sabotaged `setup apply` must make the clients
# refuse (no default identity), not succeed.
#
# Usage: tests/native/m02/selftest.sh [root]
#   root  directory holding tests/native/m02 (default: this checkout)
# Output: one line per check, then "m02-selftest: N passed, M failed[, K skipped]".
# Exit: 0 when every check passes. HM_SELFTEST_VERBOSE=1 also prints each harness log
# (it may contain temporary paths).

# The `bash -c '...'` check bodies keep their variables for the inner shell on purpose.
# shellcheck disable=SC2016,SC2013,SC2030,SC2031
set -u
here=$(cd "$(dirname "$0")" && pwd) || exit 2
root=${1:-$(cd "$here/../../.." && pwd)}
root=$(cd "$root" && pwd) || exit 2
m02="$root/tests/native/m02"
[ -f "$m02/lib.sh" ] || { echo "FAIL m02 harness files exist under the root"; echo "m02-selftest: 0 passed, 1 failed"; exit 1; }
T=$(mktemp -d) || exit 2
T=$(cd "$T" && pwd -P)
# The scenario's scratch directories live under a short path of their own (Unix socket paths
# are limited to 104 bytes on macOS; the temp directory of a macOS user is already 50).
SCN_BASE=""
cleanup_all() {
    rm -rf "$T"
    [ -z "$SCN_BASE" ] || rm -rf "$SCN_BASE"
}
if [ "${HM_SELFTEST_KEEP:-0}" = 1 ]; then
    echo "m02-selftest: keeping $T (HM_SELFTEST_KEEP=1; remove it yourself)"
else
    trap cleanup_all EXIT
fi

HOST=hm-selftest-no-such-host
passes=0
fails=0
skips=0
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
skip() {
    echo "skip $1"
    skips=$((skips + 1))
}

# --- the case index's targets -------------------------------------------------------------

TARGETS=$(python3 -I - "$m02/case-index.json" <<'PY'
import json, sys
idx = json.load(open(sys.argv[1], encoding="utf-8"))
t = set()
for sec in list(idx["groups"].values()) + list(idx["exit_claims"].values()):
    t.update(sec.get("tests", {}))
t -= set(idx.get("scenario_targets", {}))
t.update(k.split("::")[0] for k in idx.get("build_host_paths", {}))
t.add("extra_target")
print(" ".join(sorted(t)))
PY
)

# The case index's build_host_paths entries (`target` or `target::test`), one per line: the
# run plan skips exactly these off the build host, and the checks below compare against them.
BHP=$(python3 -I - "$m02/case-index.json" <<'PY2'
import json, sys
idx = json.load(open(sys.argv[1], encoding="utf-8"))
print("\n".join(sorted(idx.get("build_host_paths", {}))))
PY2
)

# skipped_exactly PLATFORM FILE: FILE names every build_host_paths entry for PLATFORM
# ("<key>: skipped on PLATFORM" or "<target>: not run on PLATFORM") and no other skip. A
# directory two runs wrote into holds each line once per run, so the names are compared as sets.
skipped_exactly() {
    python3 -I - "$1" "$2" "$BHP" <<'PY2'
import re, sys
platform, path, bhp = sys.argv[1], sys.argv[2], sys.argv[3]
want = sorted(k for k in bhp.splitlines() if k)
try:
    lines = open(path, encoding="utf-8").read().splitlines()
except FileNotFoundError:
    lines = []
got = sorted(m.group(1) for l in lines
             if (m := re.match(r"^(\S+): (?:skipped|not run) on " + re.escape(platform) + r" ", l)))
sys.exit(0 if sorted(set(got)) == want else 1)
PY2
}

# skip_args_exactly LOG: every binary's argv ends with --show-output; a binary with
# build_host_paths single-test entries gets `--exact --skip <test>...` for exactly those
# tests before it, and every other binary gets --show-output alone.
skip_args_exactly() {
    python3 -I - "$1" "$BHP" <<'PY2'
import sys
log, bhp = sys.argv[1], sys.argv[2]
tests = sorted(k.split("::", 1)[1] for k in bhp.splitlines() if "::" in k)
targets = {k.split("::", 1)[0] for k in bhp.splitlines() if "::" in k}
argvs = [l[len("argv: "):].split(" ") for l in open(log, encoding="utf-8").read().splitlines()
         if l.startswith("argv: ")]
skipped = []
with_skip = 0
for a in argvs:
    if a == ["--show-output"]:
        continue
    if len(a) < 4 or a[0] != "--exact" or a[-1] != "--show-output":
        sys.exit(1)
    mid = a[1:-1]
    if len(mid) % 2 or any(mid[i] != "--skip" for i in range(0, len(mid), 2)):
        sys.exit(1)
    skipped += mid[1::2]
    with_skip += 1
sys.exit(0 if argvs and sorted(skipped) == tests and with_skip == len(targets) else 1)
PY2
}

# --- the fake world -----------------------------------------------------------------------

# new_world NAME: fresh fake remote home ($H), Windows tree ($W), stub bin ($B), stub
# executables ($X), artifact dir ($O), call log ($L), temp dir ($S/tmp) and WSL state.
new_world() {
    S="$T/$1"
    H="$S/home"
    W="$S/win"
    B="$S/bin"
    X="$S/exes"
    O="$S/out"
    L="$S/calls.log"
    mkdir -p "$H" "$W/localappdata" "$W/Windows/System32/WindowsPowerShell/v1.0" "$W/Windows/System32/OpenSSH" \
        "$B" "$X" "$S/tmp" "$S/wsl"
    : >"$L"
    : >"$S/wsl/registry"
    write_stubs
    build_json
    extra_env=()
    local_world=0
}

write_stubs() {
    cat >"$B/ssh" <<'EOF'
#!/usr/bin/env bash
# ssh stub: never connects; runs the remote command in the fake host.
set -u
{ printf 'ssh'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
if [ "${1:-}" = -V ]; then echo "OpenSSH_9.9p9, selftest stub" >&2; exit 0; fi
while [ $# -gt 0 ]; do
    case "$1" in -F | -o) shift 2 ;; -*) shift ;; *) break ;; esac
done
[ "${1:-}" = "$HM_ST_HOST" ] || { echo "ssh stub: unexpected host" >&2; exit 255; }
shift
if [ "${HM_ST_UNREACHABLE:-0}" = 1 ]; then
    echo "ssh: connect to host $HM_ST_HOST port 22: Connection timed out" >&2
    exit 255
fi
cmd="$*"
case "$cmd" in
    "bash -s"*)
        sed "s#/mnt/c#$HM_ST_WINROOT#g; s#/etc/os-release#$HM_ST_OSRELEASE#g" |
            env HOME="$HM_ST_HOME" PATH="$HM_ST_BIN:$PATH" WSL_DISTRO_NAME="${HM_ST_CONTROLLER:-}" bash -c "$cmd" ;;
    *) env HOME="$HM_ST_HOME" PATH="$HM_ST_BIN:$PATH" bash -c "$cmd" ;;
esac
EOF
    cat >"$B/cargo" <<'EOF'
#!/usr/bin/env bash
{ printf 'cargo'; printf ' %s' "$@"; echo; echo "cargo-env CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-unset}"; } >>"$HM_ST_LOG"
if [ "${HM_ST_CARGO_FAIL:-0}" = 1 ]; then
    echo "error: could not compile (selftest)" >&2
    exit 101
fi
echo "   Compiling selftest stub" >&2
# What a real build log carries: the build host's paths (redacted before the harness exits).
echo "   Compiling heimdall ($HOME/hm-selftest-checkout/crates/heimdall)" >&2
cat "$HM_ST_BUILD_JSON"
EOF
    printf '#!/usr/bin/env bash\necho "rustc 0.0.0-selftest"\n' >"$B/rustc"
    printf '#!/usr/bin/env bash\necho "0.0.0-selftest"\n' >"$B/zig"
    cat >"$B/go" <<'EOF'
#!/usr/bin/env bash
# go stub: `go build -o OUT .` writes OUT.
{ printf 'go'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
while [ $# -gt 0 ]; do
    if [ "$1" = -o ]; then printf 'stub argvdump\n' >"$2"; exit 0; fi
    shift
done
exit 1
EOF
    cat >"$B/timeout" <<'EOF'
#!/usr/bin/env bash
# timeout stub: logs the limit and the command's base name, then runs it.
n=$1
shift
{ printf 'timeout %s %s\n' "$n" "$(basename "$1")"; } >>"$HM_ST_LOG"
exec "$@"
EOF
    cat >"$B/nice" <<'EOF'
#!/usr/bin/env bash
# nice stub: logs the adjustment and the command's base name, then runs it.
{ printf 'nice %s %s %s\n' "$1" "$2" "$(basename "$3")"; } >>"$HM_ST_LOG"
shift 2
exec "$@"
EOF
    cat >"$B/uname" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = -m ]; then echo "${HM_ST_ARCH:-x86_64}"; else exec /usr/bin/uname "$@"; fi
EOF
    cat >"$B/hostname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in -f) echo "wslfixturehost.example.invalid" ;; *) echo "wslfixturehost" ;; esac
EOF
    printf '#!/usr/bin/env bash\necho 4\n' >"$B/nproc"
    printf '#!/usr/bin/env bash\necho "ldd (selftest) 2.31"\n' >"$B/ldd"
    printf '#!/usr/bin/env bash\necho "script from util-linux (selftest)"\n' >"$B/script"
    cat >"$B/git" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = --version ]; then echo "git version 0.0.0-selftest"; exit 0; fi
exit 1
EOF
    cat >"$B/sshd" <<'EOF'
#!/usr/bin/env bash
# sshd stub: validates (-t), prints a version (-V), or "listens" (-D): it copies its
# configuration for the checks, writes the listening line the harness waits for, records
# its PID and sleeps until it is killed.
{ printf 'sshd'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
mode=run
cfg="" log=""
while [ $# -gt 0 ]; do
    case "$1" in
        -t) mode=test ;;
        -V) mode=version ;;
        -D) ;;
        -f) cfg=$2; shift ;;
        -E) log=$2; shift ;;
    esac
    shift
done
case "$mode" in
    version) echo "OpenSSH_9.9p9 selftest sshd stub" >&2; exit 1 ;;
    test) [ "${HM_ST_SSHD:-ok}" = fail ] && { echo "selftest: sshd refuses this configuration" >&2; exit 1; }; exit 0 ;;
esac
[ "${HM_ST_SSHD:-ok}" = fail ] && exit 1
port=$(sed -n 's/^Port //p' "$cfg")
cp "$cfg" "$HM_ST_SSHD_COPY"
echo "$$" >>"$HM_ST_SSHD_PIDS"
echo "Server listening on 127.0.0.1 port $port." >"$log"
exec sleep 300
EOF
    cat >"$B/sha256sum" <<'EOF'
#!/usr/bin/env bash
exec shasum -a 256 "$@"
EOF
    cat >"$B/curl" <<'EOF'
#!/usr/bin/env bash
# curl stub: only an https download of the pinned image's URL, into -o FILE.
{ printf 'curl'; printf ' %s' "$@"; echo; } >>"$HM_ST_LOG"
out=""
while [ $# -gt 0 ]; do
    [ "$1" = -o ] && out=$2
    shift
done
[ -n "$out" ] && cp "$HM_ST_IMAGE" "$out"
EOF
    # PowerShell is sent a command as `base64(UTF-16LE)`: this base64 stub keeps the
    # plain text instead (NUL bytes dropped), which the PowerShell stub then reads.
    printf '#!/usr/bin/env bash\ntr -d "\\000\\n"\necho\n' >"$B/base64"
    cat >"$B/wslpath" <<'EOF'
#!/usr/bin/env bash
# wslpath stub: C:\a\b <-> $HM_ST_WINROOT/a/b ; -w, -u or (default) -u.
mode=-u
if [ "${1:-}" = -w ] || [ "${1:-}" = -u ]; then mode=$1; shift; fi
if [ "$mode" = -w ]; then
    rest=${1#"$HM_ST_WINROOT"}
    rest=${rest#/}
    printf 'C:\\%s\n' "$(printf '%s' "$rest" | tr / '\\')"
else
    rest=${1#?:}
    rest=${rest#\\}
    printf '%s/%s\n' "$HM_ST_WINROOT" "$(printf '%s' "$rest" | tr '\\' /)"
fi
EOF
    # Forbidden commands: nothing in a harness run may call them.
    for f in sudo doas su ssh-agent ssh-add; do
        printf '#!/usr/bin/env bash\necho "%s $*" >>"$HM_ST_LOG"\nexit 1\n' "$f" >"$B/$f"
    done
    local sys="$W/Windows/System32"
    cat >"$sys/cmd.exe" <<'EOF'
#!/usr/bin/env bash
# cmd.exe stub: environment queries, `ver`, ssh/git version lines, and `.\NAME.exe ARGS`
# (run in the current directory, the whole command line logged first).
echo "cmd.exe $*" >>"$HM_ST_LOG"
line="$*"
case "$line" in
    *"echo %LOCALAPPDATA%"*) printf 'C:\\localappdata\r\n' ;;
    *"echo %USERNAME%"*) printf 'fixtureuser\r\n' ;;
    *"echo %COMPUTERNAME%"*) printf 'FIXTUREHOST\r\n' ;;
    *"echo %USERPROFILE%"*) printf 'C:\\Users\\fixtureuser\r\n' ;;
    *"/c ver"*) printf '\r\nMicrosoft Windows [Version 10.0.0.0]\r\n' ;;
    *"ssh -V"*) printf 'OpenSSH_for_Windows_9.5p2 selftest\r\n' ;;
    *"git --version"*) printf 'git version 2.0.0.windows.1\r\n' ;;
    *'.\'*.exe*)
        rest=${line#*'.\'}
        exe=${rest%%.exe*}
        args=${rest#*.exe}
        # shellcheck disable=SC2086
        exec "./$exe.exe" $args ;;
esac
EOF
    printf '#!/usr/bin/env bash\necho "Mandatory Label\\\\Medium Mandatory Level"\n' >"$sys/whoami.exe"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$sys/tasklist.exe"
    printf '#!/usr/bin/env bash\necho "OpenSSH_for_Windows_9.5p2 selftest"\n' >"$sys/OpenSSH/ssh.exe"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$sys/OpenSSH/sshd.exe"
    cat >"$sys/reg.exe" <<'EOF'
#!/usr/bin/env bash
echo "reg.exe $*" >>"$HM_ST_LOG"
[ "${1:-}" = query ] || exit 1
printf '    AllowDevelopmentWithoutDevLicense    REG_DWORD    0x1\r\n'
EOF
    cat >"$sys/WindowsPowerShell/v1.0/powershell.exe" <<'EOF'
#!/usr/bin/env bash
# PowerShell stub: the banner probe, the pipe count and the pseudoconsole driver.
echo "powershell.exe ${1:-} ${2:-} ${3:-}" >>"$HM_ST_LOG"
all="$*"
case "$all" in
    *TcpClient*)
        if [ "${HM_ST_BANNER:-ok}" = ok ]; then echo "SSH-2.0-selftest"; else echo unreachable; fi ;;
    *GetFiles*) echo "${HM_ST_PIPES:-0}" ;;
    *Invoke-WindowsLaunch.ps1*)
        out=""
        while [ $# -gt 0 ]; do
            [ "$1" = -Out ] && out=$2
            shift
        done
        v=pass
        [ "${HM_ST_LAUNCH:-pass}" = fail ] && v=fail
        out=$(wslpath -u "$out")
        printf '{"rows":[{"id":"ctrlc.event","verdict":"%s","observed":{}},{"id":"ctrlc.keystroke","verdict":"pass","observed":{}},{"id":"ctrlc.break","verdict":"pass","observed":{}},{"id":"resize","verdict":"pass","observed":{}}]}\n' "$v" >"$out"
        [ "$v" = pass ] ;;
    *) echo 0 ;;
esac
EOF
    cat >"$sys/wsl.exe" <<'EOF'
#!/usr/bin/env bash
# wsl.exe stub: a registry file of distributions and the commands run-wsl-distro.sh uses.
echo "wsl $*" >>"$HM_ST_LOG"
reg=$HM_ST_WSLDIR/registry
has() { grep -qxF -- "$1" "$reg"; }
case "${1:-}" in
    --version) echo "WSL version: 0.0.0-selftest" ;;
    -l) cat "$reg" ;;
    --import)
        name=$2
        has "$name" && exit 1
        echo "$name" >>"$reg"
        dest=$(wslpath -u "$3")
        : >"$dest/ext4.vhdx"
        echo "$dest" >"$HM_ST_WSLDIR/dest-$name"
        exit "${HM_ST_IMPORT_RC:-0}" ;;
    --terminate) has "$2" ;;
    --unregister)
        has "$2" || exit 1
        if [ "${HM_ST_UNREGISTER_FAIL:-0}" = once ] && [ ! -e "$HM_ST_WSLDIR/failed-once" ]; then
            : >"$HM_ST_WSLDIR/failed-once"
            exit 1
        fi
        grep -vxF -- "$2" "$reg" >"$reg.new"
        mv "$reg.new" "$reg"
        [ -f "$HM_ST_WSLDIR/dest-$2" ] && rm -f "$(cat "$HM_ST_WSLDIR/dest-$2")/ext4.vhdx"
        ;;
    --shutdown) exit 0 ;;
    -d)
        name=$2
        shift 2
        has "$name" || exit 1
        while [ $# -gt 0 ] && [ "$1" != --exec ]; do shift; done
        shift
        script=$(basename "${2:-}")
        case "$script" in
            target-root.sh)
                case "$4" in
                    no-systemd) echo "wsl-conf-systemd=false" ;;
                    listeners) echo "listeners-loopback=1"; echo "listeners-other=0" ;;
                    prepare)
                        echo "os=Ubuntu 24.04.5 LTS (selftest)"
                        echo "missing-tools=${HM_ST_MISSING:- none}"
                        if [ -n "${HM_ST_MISSING:-}" ] && [ "$6" != 1 ]; then
                            echo "blocked=the pinned image lacks:${HM_ST_MISSING} (selftest)"
                            exit 3
                        fi
                        echo "user=created (non-root, disposable home)"
                        echo "heimdall-installed=yes" ;;
                esac ;;
            scenario-ordinary-ssh.sh)
                echo "### wsl_ordinary_ssh"
                # What a scenario step may print: the local user, host and home and the Windows
                # ones (redacted before anything is saved).
                [ "${HM_ST_DISTRO_LEAK:-0}" = 1 ] && echo "observation leak home=$HOME user=$(id -un) host=$(hostname) winuser=fixtureuser winhost=FIXTUREHOST winhome=C:\\Users\\fixtureuser"
                # An arbitrary scenario line (the controller-distribution-name cases, ADR-0007 §12.44).
                [ -z "${HM_ST_SCEN_LINE:-}" ] || echo "observation ${HM_ST_SCEN_LINE}"
                echo "fact ssh-V=OpenSSH_9.9p9 (exit 0)"
                echo "fact rename-exchange=supported (selftest)"
                for s in a01_setup_apply_writes_the_users_real_ssh_config a01_ordinary_ssh_alias_without_f \
                    a01_ordinary_git_without_f a01_ordinary_scp_without_f a01_ordinary_sftp_without_f \
                    a01_unaffected_alias_effective_config_unchanged a01_provider_agent_accepted_key_is_the_adopted_one \
                    a22_rename_exchange_supported_on_the_home_fs t06_uninstall_restores_user_bytes \
                    t06_uninstall_restores_effective_config; do
                    if [ "${HM_ST_SCENARIO_FAIL:-}" = "$s" ]; then echo "test $s ... FAILED"; else echo "test $s ... ok"; fi
                done
                [ -z "${HM_ST_SCENARIO_FAIL:-}" ] && st=0 || st=1
                echo "### wsl_ordinary_ssh exit=$st"
                exit $st ;;
        esac ;;
esac
EOF
    chmod +x "$B"/* "$sys/cmd.exe" "$sys/whoami.exe" "$sys/tasklist.exe" "$sys/reg.exe" \
        "$sys/WindowsPowerShell/v1.0/powershell.exe" "$sys/wsl.exe" "$sys/OpenSSH/ssh.exe" "$sys/OpenSSH/sshd.exe"
}

# exe NAME MODE: a stub test binary. MODE: pass, fail, env, leak, canary, touch-owner, obs.
exe() {
    {
        printf '#!/usr/bin/env bash\n'
        printf 'echo "argv: $*" >>"$HM_ST_LOG"\n'
        printf 'echo "running 2 tests"\n'
        case "$2" in
            fail) printf 'echo "test fixture::a ... FAILED"\necho "test fixture::b ... ok"\necho "test result: FAILED. 1 passed; 1 failed"\nexit 101\n' ;;
            *)
                case "$2" in
                    env)
                        cat <<'EOS'
echo "env ssh_auth_sock=${SSH_AUTH_SOCK:-unset}"
echo "env git_vars=$(env | grep -c '^GIT_')"
echo "env heimdall_vars=$(env | grep '^HEIMDALL_' | grep -vc '^HEIMDALL_E2E_BIN=')"
echo "env e2e_bin=${HEIMDALL_E2E_BIN:+set}"
echo "env hook=${HM_FIXTURE_HOOK:+set}"
echo "env fixture_host=${HM_FIXTURE_SSHD_HOST:-unset}"
echo "env fixture_port_value_is_numeric=$(printf '%s' "${HM_FIXTURE_SSHD_PORT:-x}" | grep -qE '^[0-9]+$' && echo yes || echo no)"
echo "env fixture_port=${HM_FIXTURE_SSHD_PORT:+set}"
echo "env fixture_key=${HM_FIXTURE_SSHD_HOST_KEY:+set}"
echo "env fixture_keys_file=${HM_FIXTURE_SSHD_AUTHORIZED_KEYS:+set}"
echo "env fixture_log=${HM_FIXTURE_SSHD_LOG:+set}"
echo "env wslenv=${WSLENV:-unset}"
echo "env temp=${TEMP:-unset}"
echo "env tmpdir_inside_cwd=$([ "${TMPDIR:-x}" != "${TMPDIR#"$PWD"/}" ] && echo yes || echo no)"
echo "env cwd_has_scratch_name=$(printf '%s' "$PWD" | grep -qE 'hm-m02-|hm-m00' && echo yes || echo no)"
echo "env repo_root=${HM_REPO_ROOT:+set}"
r=${HM_REPO_ROOT:-/nonexistent}
case "$r" in [A-Za-z]:*) r=$(wslpath -u "$r") ;; esac
echo "env repo_root_inside_cwd=$([ "$r" != "${r#"$PWD"/}" ] && echo yes || echo no)"
echo "env repo_root_has_files=$([ -f "$r/schemas/public-api/envelope.schema.json" ] && [ -f "$r/crates/testkit/src/repo.rs" ] && [ -f "$r/tests/e2e/cli_m02.rs" ] && [ ! -e "$r/tests/evidence" ] && echo yes || echo no)"
EOS
                        ;;
                    leak) printf 'echo "leak home=$HOME user=$(id -un) host=$(hostname) fqdn=$(hostname -f) winuser=fixtureuser winhost=FIXTUREHOST winhome=C:\\\\Users\\\\fixtureuser sid=S-1-5-21-1111111111-2222222222-3333333333-1001 addr=203.0.113.9 loop=127.0.0.1"\n' ;;
                    canary) printf 'echo "HEIMDALL_CANARY_"\n' ;;
                    touch-owner) printf 'mkdir -p "$HOME/.ssh" && : >"$HOME/.ssh/hm-m02-selftest-intruder"\nmkdir -p "$HM_ST_WINROOT/Users/fixtureuser/.ssh" && : >"$HM_ST_WINROOT/Users/fixtureuser/.ssh/hm-m02-selftest-intruder"\n' ;;
                esac
                printf 'echo "test fixture::a ... ok"\necho "test fixture::b ... ok"\n'
                if [ "$2" = obs ]; then
                    # What libtest prints for a passing test under --show-output: the captured
                    # output of the test, under its own header, after the results.
                    cat <<'EOS'
case " $* " in
    *" --show-output "*)
        printf '\nsuccesses:\n\n---- fixture::a stdout ----\nobservation test=a path=%s supported=true\n\nsuccesses:\n    fixture::a\n    fixture::b\n\n' "$HOME" ;;
esac
EOS
                fi
                printf 'echo "test result: ok. 2 passed; 0 failed"\nexit 0\n' ;;
        esac
    } >"$X/$1"
    chmod +x "$X/$1"
}

# build_json: stub executables for every target of the case index (plus the CLI and the
# hook) and the cargo JSON that names them.
build_json() {
    local t base kind
    : >"$S/build.json"
    for t in $TARGETS; do
        exe "$t" pass
        case "$t" in
            *-unit)
                base=${t%-unit}
                kind=lib
                [ "$base" = heimdall ] && kind=bin
                printf '{"reason":"compiler-artifact","target":{"name":"%s","kind":["%s"]},"profile":{"test":true},"executable":"%s"}\n' \
                    "$base" "$kind" "$X/$t" >>"$S/build.json" ;;
            *)
                printf '{"reason":"compiler-artifact","target":{"name":"%s","kind":["test"]},"profile":{"test":true},"executable":"%s"}\n' \
                    "$t" "$X/$t" >>"$S/build.json" ;;
        esac
    done
    printf '#!/usr/bin/env bash\necho "heimdall stub"\n' >"$X/heimdall.bin"
    printf '#!/usr/bin/env bash\necho "hook stub"\n' >"$X/hm-fixture-hook.bin"
    chmod +x "$X/heimdall.bin" "$X/hm-fixture-hook.bin"
    printf '{"reason":"compiler-artifact","target":{"name":"heimdall","kind":["bin"]},"profile":{"test":false},"executable":"%s"}\n' "$X/heimdall.bin" >>"$S/build.json"
    printf '{"reason":"compiler-artifact","target":{"name":"hm-fixture-hook","kind":["bin"]},"profile":{"test":false},"executable":"%s"}\n' "$X/hm-fixture-hook.bin" >>"$S/build.json"
}

# harness ROOT SCRIPT ARGS...: run a harness in the fake world; sets $rc. Extra
# environment goes in the array extra_env (NAME=value words).
extra_env=()
# local_world=1 (set by local_distro_world): the harness runs as HM_LOCAL=1 would on the PC, inside
# the controller distribution: neither HM_SSH_CONFIG nor HM_HOST is in its environment, and the
# controller's name is WSL_DISTRO_NAME.
local_world=0
harness() {
    local r=$1 script=$2
    shift 2
    local unset_env=() ssh_env=(HM_SSH_CONFIG=/dev/null HM_HOST="$HOST")
    if [ "$local_world" = 1 ]; then
        unset_env=(-u HM_SSH_CONFIG -u HM_HOST)
        ssh_env=(WSL_DISTRO_NAME="${HM_ST_CONTROLLER:-}")
    fi
    env ${unset_env[@]+"${unset_env[@]}"} HOME="$H" TMPDIR="$S/tmp" PATH="$B:$PATH" \
        "${ssh_env[@]}" \
        HM_ST_LOG="$L" HM_ST_HOST="$HOST" HM_ST_HOME="$H" HM_ST_WINROOT="$W" HM_ST_BIN="$B" \
        HM_ST_BUILD_JSON="$S/build.json" HM_ST_WSLDIR="$S/wsl" HM_ST_SSHD_COPY="$S/sshd-config.copy" \
        HM_ST_SSHD_PIDS="$S/sshd.pids" HM_ST_IMAGE="$S/image.bin" HM_ST_OSRELEASE="$S/os-release" \
        ${extra_env[@]+"${extra_env[@]}"} \
        bash "$r/tests/native/m02/$script" "$@" >"$S/harness.log" 2>&1 </dev/null
    rc=$?
    if [ "$rc" = 127 ] && [ ! -f "$r/tests/native/m02/$script" ]; then
        echo "FAIL harness $script exists under the root (it could not be started)"
        fails=$((fails + 1))
    fi
    if [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ]; then
        echo "--- $script exit $rc"
        cat "$S/harness.log"
    fi
}

# --- predicates ---------------------------------------------------------------------------

is_zero() { [ "$1" = 0 ]; }
is_nonzero() { [ "$1" != 0 ]; }
is_n() { [ "$1" = "$2" ]; }
has_file() { [ -f "$1" ]; }
no_file() { [ ! -e "$1" ]; }
grep_q() { grep -qF -- "$1" "$2" 2>/dev/null; }
no_grep() { ! grep -qF -- "$1" "$2" 2>/dev/null; }
grep_e() { grep -qE -- "$1" "$2" 2>/dev/null; }
no_grep_e() { ! grep -qE -- "$1" "$2" 2>/dev/null; }
log_has() { grep -qE -- "$1" "$L"; }
log_lacks() { ! grep -qE -- "$1" "$L"; }
log_empty() { [ ! -s "$L" ]; }
count_is() { [ "$(grep -cE -- "$1" "$2" 2>/dev/null)" = "$3" ]; }
# entries DIR: the sorted entry names (empty if DIR is absent).
# shellcheck disable=SC2012  # fixture names only ([A-Za-z0-9._-])
entries() { [ -d "$1" ] && (cd "$1" && ls -A | sort | tr '\n' ' '); }
entries_are() { [ "$(entries "$1")" = "$2" ]; }
starts_with() { case "$1" in "$2"*) return 0 ;; esac; return 1; }
differ() { [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ]; }
# none_of OUT VALUE...: no saved artifact under OUT contains any VALUE (case-insensitive).
none_of() {
    local out=$1 v
    shift
    for v in "$@"; do
        [ -n "$v" ] || continue
        ! grep -r -q -i -F -- "$v" "$out" 2>/dev/null || return 1
    done
    return 0
}
# live_pid FILE: 0 when any PID recorded in FILE is still alive.
live_pid() {
    local p
    [ -f "$1" ] || return 1
    for p in $(cat "$1"); do
        kill -0 "$p" 2>/dev/null && return 0
    done
    return 1
}
dir_tree_is_empty() { [ -d "$1" ] && [ -z "$(ls -A "$1")" ]; }
# run_name FILE: the run directory name a harness recorded in commands.txt.
run_name() { sed -n 's/.*create the run directories exclusively (run \(.*\))$/\1/p' "$1" | head -1; }
owner_digests_equal() {
    local a b
    a=$(sed -n 's/^owner-[a-z]*-before=//p' "$1" | tr '\n' ' ')
    b=$(sed -n 's/^owner-[a-z]*-after=//p' "$1" | tr '\n' ' ')
    [ -n "$a" ] && [ "$a" = "$b" ]
}

REAL_USER=$(id -un)

# =============================================================================================
# X: lib.sh and remote-lib.sh
# =============================================================================================

# shellcheck source=tests/native/m02/lib.sh
. "$m02/lib.sh"
# shellcheck source=tests/native/m02/remote-lib.sh
. "$m02/remote-lib.sh"
X0="$T/xlib"
mkdir -p "$X0"

alias_rules() {
    m02_valid_alias hm-host_1.example && m02_valid_alias a &&
        ! m02_valid_alias '' && ! m02_valid_alias -oProxyCommand=x && ! m02_valid_alias 'a b' &&
        ! m02_valid_alias 'a;b' && ! m02_valid_alias 'a$b' && ! m02_valid_alias 'a/b' && ! m02_valid_alias 'a`b'
}
check "X01 lib: host aliases are [A-Za-z0-9._-] and never an option" alias_rules

hex_a=$(m02_random_hex 8)
hex_b=$(m02_random_hex 8)
check "X02 lib: random hex is lowercase hex of the requested length and differs per call" \
    bash -c '[ "${#1}" = 16 ] && [ "${#2}" = 16 ] && [ "$1" != "$2" ] && case "$1$2" in *[!0-9a-f]*) exit 1 ;; esac' _ "$hex_a" "$hex_b"

m02_record "$X0/commands" "a command" 101
check "X03 lib: a command line carries its real exit code" grep_q "exit 101: a command" "$X0/commands"

printf 'path C:\\Users\\Fix.User\\.ssh and C:\\\\Users\\\\Fix.User and C:/Users/fix.user and /mnt/c/Users/fix.user/x\nhost FixHost user fixuser sid S-1-5-21-1-2-3-1001 ip 203.0.113.9 and 127.0.0.1 and 0.0.0.0 v1.2.3.4.5\nshort a\n' >"$X0/redact.in"
m02_redact "$X0/redact.in" "$X0/redact.out" 'C:\Users\Fix.User' "<winhome>" "FixHost" "<h>" "fixuser" "<u>" "a" "<never>"
check "X04 lib: redaction replaces the Windows home in its backslash, doubled, slash and /mnt forms, any case" \
    bash -c '! grep -qi "fix.user" "$1" && [ "$(grep -o "<winhome>" "$1" | wc -l | tr -d " ")" -ge 4 ]' _ "$X0/redact.out"
check "X05 lib: host and user names are replaced case-insensitively" \
    bash -c '! grep -qi "fixhost" "$1" && ! grep -qi "fixuser" "$1" && grep -q "<h>" "$1" && grep -q "<u>" "$1"' _ "$X0/redact.out"
check "X06 lib: a domain SID and a non-loopback IPv4 address are masked, loopback addresses kept" \
    bash -c 'grep -q "S-1-5-21-<redacted>" "$1" && grep -q "<addr>" "$1" && grep -q "127.0.0.1" "$1" && grep -q "0.0.0.0" "$1" && ! grep -q "203.0.113.9" "$1"' _ "$X0/redact.out"
check "X07 lib: a one-character value is ignored (it would mangle ordinary text)" \
    bash -c 'grep -q "^short a$" "$1"' _ "$X0/redact.out"
printf 'mac on macOS, Mac.local, mac-1 and xmac; heimdall_mac_x\n' >"$X0/word.in"
m02_redact "$X0/word.in" "$X0/word.out" --word "mac" "<host>"
check "X27 lib: a --word host name is replaced only as a whole word, any case, never inside another word" \
    bash -c 'grep -qx "<host> on macOS, <host>.local, <host>-1 and xmac; heimdall_mac_x" "$1"' _ "$X0/word.out"
mkdir -p "$X0/wscan"
printf 'built on macOS\n' >"$X0/wscan/a.txt"
wleak_clean=$(m02_leak_scan "$X0/wscan" --word "mac")
printf 'host mac\n' >"$X0/wscan/b.txt"
wleak_hit=$(m02_leak_scan "$X0/wscan" --word "mac")
wleak_any=$(m02_leak_scan "$X0/wscan" "mac")
check "X28 lib: the leak scan counts a --word value only as a whole word (as it is redacted), any other value anywhere" \
    bash -c '[ "$1" = 0 ] && [ "$2" = 1 ] && [ "$3" = 2 ]' _ "$wleak_clean" "$wleak_hit" "$wleak_any"
mkdir -p "$X0/repo-src/crates/x/src" "$X0/repo-src/crates/x/target" "$X0/repo-src/schemas" "$X0/repo-src/docs/decisions" \
    "$X0/repo-src/docs/other" "$X0/repo-src/tests/e2e" "$X0/repo-src/tests/evidence/a" "$X0/repo-src/tests/contracts/golden" \
    "$X0/repo-src/tests/fixtures/f" "$X0/repo-src/tests/native"
for f in crates/x/src/lib.rs crates/x/target/big schemas/s.json docs/decisions/0007.md docs/other/no.md tests/e2e/t.rs \
    tests/evidence/a/p.rs tests/contracts/golden/g.json tests/fixtures/f/c tests/native/n.sh; do
    echo "$f" >"$X0/repo-src/$f"
done
ln -s "$X0/repo-src/schemas/s.json" "$X0/repo-src/schemas/link.json"
repo_n=$(m02_stage_repo "$X0/repo-src" "$X0/repo-stage")
check "X29 lib: the repository copy for HM_REPO_ROOT holds the listed directories and every tests/*.rs, never build output, evidence, other files or symbolic links" \
    bash -c 'd=$1/repo; [ "$2" = 6 ] && for f in crates/x/src/lib.rs schemas/s.json docs/decisions/0007.md tests/e2e/t.rs tests/contracts/golden/g.json tests/fixtures/f/c; do [ -f "$d/$f" ] || exit 1; done &&
        for f in crates/x/target/big docs/other/no.md tests/evidence tests/native/n.sh schemas/link.json; do [ ! -e "$d/$f" ] || exit 1; done' _ "$X0/repo-stage" "$repo_n"

mkdir -p "$X0/scan"
printf 'clean\n' >"$X0/scan/a.txt"
check "X08 lib: the canary scan counts nothing in clean output and writes canary-scan.txt" \
    bash -c '. "$1"; [ "$(m02_canary_scan "$2")" = 0 ] && grep -q "occurrences in saved output: 0" "$2/canary-scan.txt"' _ "$m02/lib.sh" "$X0/scan"
printf 'x HEIMDALL_CANARY_ x\nHEIMDALL_CANARY_ again\n' >"$X0/scan/b.txt"
check "X09 lib: the canary scan counts every occurrence (and the scan file itself is not scanned)" \
    bash -c '. "$1"; [ "$(m02_canary_scan "$2")" = 2 ] && [ "$(m02_canary_scan "$2")" = 2 ]' _ "$m02/lib.sh" "$X0/scan"
printf 'the secret-home-value is here\n' >"$X0/scan/c.txt"
leak_out=$(m02_leak_scan "$X0/scan" "secret-home-value" "x" "absent-value")
leak_rc=$?
check "X10 lib: the leak scan counts the files naming a value, returns nonzero, and never prints the value" \
    bash -c '[ "$1" = 1 ] && [ "$2" != 0 ] && case "$1" in *secret*) exit 1 ;; esac' _ "$leak_out" "$leak_rc"
leak_out=$(m02_leak_scan "$X0/scan" "absent-value" "q")
check "X11 lib: the leak scan passes (and prints 0) when no value is present" bash -c '[ "$1" = 0 ]' _ "$leak_out"

check "X12 lib: the zig shims map winapi import archives and synchronization to libraries zig ships" \
    bash -c '. "$1"; d=$(mktemp -d); m02_write_shims "$d"; grep -q "lwinapi_synchronization) args+=(\"-lapi-ms-win-core-synch-l1-2-0\")" "$d/zigcc-win.sh" && grep -q "lwinapi_\*) args+=" "$d/zigcc-win.sh" && [ -x "$d/zigcc-linux.sh" ] && [ -x "$d/zigar.sh" ]; rc=$?; rm -rf "$d"; exit $rc' _ "$m02/lib.sh"

# remote-lib.sh
env_probe() {
    (
        for v in $(env | sed -n -E 's/^((GIT|HEIMDALL)_[A-Za-z0-9_]*)=.*/\1/p'); do unset "$v"; done
        export SSH_AUTH_SOCK=/nonexistent/sock SSH_AGENT_PID=1 SSH_ASKPASS=x GIT_DIR=/x GIT_CONFIG_GLOBAL=/y HEIMDALL_HOME=/z HEIMDALL_TEST_ADAPTER=q HM_FIXTURE_SSHD_PORT=9
        hm2_sanitize_env >"$T/sanitize.out"
        out=$(cat "$T/sanitize.out")
        [ -z "${SSH_AUTH_SOCK:-}${SSH_AGENT_PID:-}${SSH_ASKPASS:-}${GIT_DIR:-}${GIT_CONFIG_GLOBAL:-}${HEIMDALL_HOME:-}${HEIMDALL_TEST_ADAPTER:-}${HM_FIXTURE_SSHD_PORT:-}" ] || exit 1
        printf '%s\n' "$out" | grep -q 'inherited-ssh-auth-sock=set' && printf '%s\n' "$out" | grep -q 'inherited-git-variables=2' &&
            printf '%s\n' "$out" | grep -q 'inherited-heimdall-variables=2' && ! printf '%s\n' "$out" | grep -q '/nonexistent'
    )
}
check "X13 remote-lib: sanitizing unsets agent, askpass, Git, Heimdall and fixture variables, reporting counts only" env_probe
# The sanitizing runs in a subshell above; this one proves it does not touch an unrelated variable.
check "X14 remote-lib: an unrelated variable survives sanitizing" \
    bash -c '. "$1"; export HM_SELFTEST_KEEP=1; hm2_sanitize_env >/dev/null; [ "$HM_SELFTEST_KEEP" = 1 ]' _ "$m02/remote-lib.sh"
check "X15 remote-lib: hm2_first_line reports the first line and the exit code, or absent" \
    bash -c '. "$1"; [ "$(hm2_first_line sh -c "echo one; echo two; exit 3")" = "one (exit 3)" ] && [ "$(hm2_first_line hm-m02-no-such-command)" = absent ]' _ "$m02/remote-lib.sh"
mkdir -p "$X0/own/d"
printf 'secret-name\n' >"$X0/own/d/secret-file-name"
d1=$(hm2_owner_digest "$X0/own")
d2=$(hm2_owner_digest "$X0/own")
printf 'more\n' >"$X0/own/d/another"
d3=$(hm2_owner_digest "$X0/own")
d4=$(hm2_owner_digest "$X0/own/absent")
check "X16 remote-lib: the owner digest is stable, changes with an entry, is 'absent' for nothing, and names no file" \
    bash -c '[ "$1" = "$2" ] && [ "$1" != "$3" ] && [ "$4" = absent ] && case "$1$3" in *secret*) exit 1 ;; esac && case "$1" in [0-9]*:*) ;; *) exit 1 ;; esac' _ "$d1" "$d2" "$d3" "$d4"
port=$(hm2_port)
check "X17 remote-lib: fixture ports are 20000-59999" bash -c '[ "$1" -ge 20000 ] && [ "$1" -le 59999 ]' _ "$port"
cfg=$(hm2_sshd_config 24680 /d /d/keys 1)
check "X18 remote-lib: the fixture sshd configuration listens on 127.0.0.1 only, public keys only, no forwarding" \
    bash -c 'c=$1; [ "$(printf "%s\n" "$c" | grep -c "^ListenAddress")" = 1 ] && printf "%s\n" "$c" | grep -qx "ListenAddress 127.0.0.1" &&
        printf "%s\n" "$c" | grep -qx "AuthenticationMethods publickey" && printf "%s\n" "$c" | grep -qx "PasswordAuthentication no" &&
        printf "%s\n" "$c" | grep -qx "PermitRootLogin no" && printf "%s\n" "$c" | grep -qx "AllowTcpForwarding no" &&
        printf "%s\n" "$c" | grep -qx "PerSourcePenalties no" && ! printf "%s\n" "$c" | grep -qE "ListenAddress (0\.0\.0\.0|::)"' _ "$cfg"
check "X19 remote-lib: PerSourcePenalties is left out for servers that do not know it" \
    bash -c '. "$1"; ! hm2_sshd_config 24680 /d /d/keys 0 | grep -q PerSourcePenalties' _ "$m02/remote-lib.sh"

check "X26 remote-lib: the functions survive a caller's set -e (sshd -V exits 1; a killed child reaps as 143)" \
    bash -ec '. "$1"; r=$(hm2_first_line sh -c "exit 1"); [ "$r" = " (exit 1)" ] || exit 9; sleep 30 & HM2_SSHD_PID=$!; hm2_sshd_stop; [ -z "$HM2_SSHD_PID" ]; hm2_sshd_stop' _ "$m02/remote-lib.sh"

# The fixture sshd start and stop, with the stub sshd.
new_world xlib-sshd
sshd_probe() {
    (
        PATH="$B:$PATH" HM_ST_SSHD_COPY="$S/sshd.cfg" HM_ST_SSHD_PIDS="$S/sshd.pids" HM_ST_LOG="$L"
        export PATH HM_ST_SSHD_COPY HM_ST_SSHD_PIDS HM_ST_LOG
        hm2_sshd_start "$S/fx" "$S/fx.keys" "$S/fx.log" || exit 10
        [ -n "$HM2_SSHD_PID" ] && [ -n "$HM2_SSHD_PORT" ] && [ -n "$HM2_SSHD_START" ] || exit 11
        case "$HM2_SSHD_HOSTKEY" in ssh-ed25519\ *) ;; *) exit 12 ;; esac
        [ "$(python3 -I -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$S/fx")" = 0o700 ] || exit 13
        grep -q "^pid=$HM2_SSHD_PID$" "$S/fx/state" || exit 14
        kill -0 "$HM2_SSHD_PID" || exit 15
        pid=$HM2_SSHD_PID
        hm2_sshd_stop
        sleep 0.2
        kill -0 "$pid" 2>/dev/null && exit 16
        [ -z "$HM2_SSHD_PID" ] || exit 17
        exit 0
    )
}
sshd_probe
check "X20 remote-lib: the fixture sshd starts (700 directory, state recorded, ed25519 host key) and is stopped by exact PID" is_zero "$?"
check "X21 remote-lib: the sshd it started listened on 127.0.0.1 only" \
    bash -c 'grep -qx "ListenAddress 127.0.0.1" "$1" && [ "$(grep -c "^ListenAddress" "$1")" = 1 ]' _ "$S/sshd.cfg"
check "X22 remote-lib: no fixture sshd process is left" bash -c 'for p in $(cat "$1"); do kill -0 "$p" 2>/dev/null && exit 1; done; exit 0' _ "$S/sshd.pids"
sshd_refusals() {
    (
        PATH="$B:$PATH" HM_ST_SSHD_COPY="$S/sshd.cfg" HM_ST_SSHD_PIDS="$S/sshd.pids" HM_ST_LOG="$L"
        export PATH HM_ST_SSHD_COPY HM_ST_SSHD_PIDS HM_ST_LOG
        mkdir "$S/exists"
        hm2_sshd_start "$S/exists" "$S/k" "$S/l" && exit 1
        case "$HM2_SSHD_WHY" in *exists*) ;; *) exit 2 ;; esac
        HM_ST_SSHD=fail
        export HM_ST_SSHD
        hm2_sshd_start "$S/fx2" "$S/k2" "$S/l2" && exit 3
        case "$HM2_SSHD_WHY" in *rejected*) ;; *) exit 4 ;; esac
        [ -z "$HM2_SSHD_PID" ] || exit 5
        exit 0
    )
}
sshd_refusals
check "X23 remote-lib: an existing fixture directory is never reused, and a refused configuration starts nothing" is_zero "$?"
check "X24 remote-lib: stop-by-record says none without a record, gone for a dead PID, mismatch otherwise" \
    bash -c '. "$1"; d=$(mktemp -d); [ "$(hm2_stop_recorded "$d")" = none ] || exit 1; printf "pid=999999\nstart=x\nconfig=c\n" >"$d/state"; r=$(hm2_stop_recorded "$d"); rm -rf "$d"; case "$r" in gone|mismatch) exit 0 ;; *) exit 1 ;; esac' _ "$m02/remote-lib.sh"
sleeper_probe() {
    local d p
    d=$(mktemp -d)
    sleep 60 &
    p=$!
    # A live process whose start time or configuration path does not match is never signalled.
    printf 'pid=%s\nstart=not-its-start-time\nconfig=/not/its/config\n' "$p" >"$d/state"
    r=$(hm2_stop_recorded "$d")
    kill -0 "$p" 2>/dev/null && alive=1 || alive=0
    kill "$p" 2>/dev/null
    wait "$p" 2>/dev/null
    rm -rf "$d"
    [ "$alive" = 1 ] && case "$r" in mismatch | gone) true ;; *) false ;; esac
}
check "X25 remote-lib: a recorded PID whose start time and configuration do not match is left alone" sleeper_probe
# A running sshd retitles itself ("sshd: <argv> [listener] ..."), which on Linux makes its whole
# command line one argument: the recorded configuration path must still be found in it (the first
# Windows local run reported "mismatch" and left its sshd running). /proc is Linux only.
retitled_probe() {
    local d p r start
    [ -r /proc/self/stat ] || return 0
    d=$(mktemp -d)
    (exec -a "sshd: /usr/sbin/sshd -D -f $d/sshd_config -E $d/log [listener] 0 of 10-100 startups" sleep 60) &
    p=$!
    sleep 0.3
    start=$(hm2_start_time "$p")
    printf 'pid=%s\nstart=%s\nconfig=%s\n' "$p" "$start" "$d/sshd_config" >"$d/state"
    r=$(hm2_stop_recorded "$d")
    kill "$p" 2>/dev/null
    wait "$p" 2>/dev/null
    rm -rf "$d"
    [ "$r" = stopped ]
}
check "X27 remote-lib: a recorded sshd whose process title holds the whole command line is found and stopped (Linux /proc)" retitled_probe

# =============================================================================================
# L: run-linux.sh
# =============================================================================================

# L-build: HM_BUILD_ONLY reaches no host.
new_world linux-build
extra_env=(HM_BUILD_ONLY=1 CARGO_TARGET_DIR=/nonexistent/hm-selftest-target)
harness "$root" run-linux.sh "$O"
check "L01 linux build-only: exits 0" is_zero "$rc"
check "L02 linux build-only: reaches no host (no ssh, scp or tar to one)" log_lacks '^(ssh|scp) '
check "L03 linux build-only: cargo ran for x86_64-unknown-linux-gnu, locked, without CARGO_TARGET_DIR or --target-dir" \
    bash -c 'grep -q "^cargo test --target x86_64-unknown-linux-gnu --workspace --no-run --locked" "$1" && grep -q "cargo-env CARGO_TARGET_DIR=unset" "$1" && ! grep -q -e "--target-dir" "$1"' _ "$L"
check "L04 linux build-only: build.txt has a sha256 per planned binary, the CLI and the hook, and the toolchain" \
    bash -c 'b=$1; grep -q "^e2e_cli_m02 sha256: [0-9a-f]\{64\}$" "$b" && grep -q "^heimdall (CLI for the e2e suites, HEIMDALL_E2E_BIN) sha256: [0-9a-f]\{64\}$" "$b" &&
        grep -q "^hm-fixture-hook (HM_FIXTURE_HOOK) sha256: [0-9a-f]\{64\}$" "$b" && grep -q "^toolchain: rustc 0.0.0-selftest; zig 0.0.0-selftest; target x86_64-unknown-linux-gnu" "$b"' _ "$O/build.txt"
check "L05 linux build-only: every target is planned (repository files come from HM_REPO_ROOT; ADR-0007 §12.32 item 3)" \
    bash -c 'for t in $2; do [ "$t" = extra_target ] && continue; grep -q "^$t sha256: " "$1" || exit 1; done' _ "$O/build.txt" "$TARGETS"
check "L06 linux build-only: exactly the case index's build_host_paths entries are skipped as build-host-only" \
    skipped_exactly linux "$O/skipped.txt"
check "L07 linux build-only: no scratch, no remote directory, nothing in the fake home" dir_tree_is_empty "$H"
check "L08 linux build-only: the commands record real exit codes" \
    bash -c 'grep -q "^exit 0: cargo test --target x86_64-unknown-linux-gnu" "$1" && grep -q "^exit 0: run plan from case-index.json" "$1"' _ "$O/commands.txt"

# L-full: a passing run.
new_world linux-pass
exe e2e_cli_m02 env
extra_env=(SSH_AUTH_SOCK=/nonexistent/hm-selftest-agent GIT_DIR=/nonexistent HEIMDALL_HOME=/nonexistent HM_FIXTURE_SSHD_PORT=1 HM_ST_CONTROLLER=)
harness "$root" run-linux.sh "$O" "$HOST"
check "L10 linux: a run with every binary passing exits 0" is_zero "$rc"
check "L11 linux: the scratch directory ~/hm-m02-<random> was created and removed, nothing else in the home" dir_tree_is_empty "$H"
check "L12 linux: the removal is recorded with its check that the directory is absent, exit 0" \
    grep_q "exit 0: ssh <linuxhost> rm -rf the run's scratch dir, then check it is absent" "$O/commands.txt"
check "L13 linux: every binary ran and its exit code is kept (### name exit=0)" \
    bash -c 'n=$(grep -c "^### [A-Za-z0-9_-]* exit=0$" "$1"); [ "$n" -ge 25 ] && ! grep -q "exit=[1-9]" "$1"' _ "$O/tests.txt"
check "L14 linux: each binary ran under nice -n 10 and timeout 1800" \
    bash -c 'n=$(grep -c "^nice -n 10 " "$1"); t=$(grep -c "^timeout 1800 " "$1"); [ "$n" -ge 25 ] && [ "$n" = "$t" ]' _ "$L"
check "L15 linux: --exact --skip is given for exactly the build_host_paths tests, to their binaries only" \
    skip_args_exactly "$L"
check "L16 linux: HM_REPO_ROOT names the repository copy inside the scratch, with the schemas, the sources and the tests (no evidence)" \
    bash -c 't=$1; grep -q "^env repo_root=set$" "$t" && grep -q "^env repo_root_inside_cwd=yes$" "$t" && grep -q "^env repo_root_has_files=yes$" "$t" && grep -q "^exit 0: stage the repository files the tests read (HM_REPO_ROOT: [1-9][0-9]* files)$" "$2"' _ "$O/tests.txt" "$O/commands.txt"
check "L17 linux: host.txt records ssh -V, sshd -V and git --version with exit codes" \
    bash -c 'h=$1; grep -q "^ssh-V=OpenSSH_9.9p9, selftest stub (exit 0)$" "$h" && grep -q "^sshd-V=OpenSSH_9.9p9 selftest sshd stub (exit 1)$" "$h" && grep -q "^git-version=git version 0.0.0-selftest (exit 0)$" "$h"' _ "$O/host.txt"
check "L18 linux: the fixture sshd preflight listened on 127.0.0.1 and was stopped" \
    bash -c 'h=$1; grep -q "^fixture-sshd-preflight=listening on 127.0.0.1 (non-root, per-run host key)$" "$h" && grep -q "^fixture-sshd-preflight-stopped=yes$" "$h"' _ "$O/host.txt"
check "L19 linux: that sshd's configuration listened on 127.0.0.1 only" \
    bash -c 'grep -qx "ListenAddress 127.0.0.1" "$1" && [ "$(grep -c "^ListenAddress" "$1")" = 1 ]' _ "$S/sshd-config.copy"
check "L20 linux: no sshd process of the run is left" bash -c 'for p in $(cat "$1"); do kill -0 "$p" 2>/dev/null && exit 1; done; exit 0' _ "$S/sshd.pids"
check "L21 linux: inherited agent, Git and Heimdall variables were unset for the tests" \
    bash -c 't=$1; grep -q "^env ssh_auth_sock=unset$" "$t" && grep -q "^env git_vars=0$" "$t" && grep -q "^env heimdall_vars=0$" "$t" && grep -q "^env fixture_host=unset$" "$t" && grep -q "^env fixture_port=$" "$t"' _ "$O/tests.txt"
check "L22 linux: host.txt reports the inherited counts, never a value" \
    bash -c 'h=$1; grep -q "^inherited-ssh-auth-sock=set (unset for the run)$" "$h" && grep -q "^inherited-git-variables=[1-9][0-9]* " "$h" && ! grep -q "hm-selftest-agent" "$h"' _ "$O/host.txt"
check "L23 linux: HEIMDALL_E2E_BIN and HM_FIXTURE_HOOK are set for the tests, TMPDIR is inside the scratch" \
    bash -c 't=$1; grep -q "^env e2e_bin=set$" "$t" && grep -q "^env hook=set$" "$t" && grep -q "^env tmpdir_inside_cwd=yes$" "$t" && grep -q "^env cwd_has_scratch_name=yes$" "$t"' _ "$O/tests.txt"
check "L24 linux: the owner's ~/.ssh and Git configuration metadata were unchanged (recorded exit 0)" \
    grep_q "exit 0: host ~/.ssh and Git configuration metadata unchanged by the run" "$O/commands.txt"
check "L25 linux: the canary scan and the leak scan are recorded with exit 0" \
    bash -c 'c=$1; grep -q "^exit 0: canary-prefix scan over saved output (count = 0)$" "$c" && grep -q "^exit 0: leak scan: saved files still naming the host, user or a home (0)$" "$c"' _ "$O/commands.txt"
check "L26 linux: nothing was elevated or touched ssh-agent state (no sudo, su, ssh-agent or ssh-add call)" \
    log_lacks '^(sudo|doas|su|ssh-agent|ssh-add) '
check "L27 linux: the scratch directory name is anonymized in the artifacts" \
    bash -c '! grep -rqE "hm-m02-[0-9a-f]{12}" "$1"' _ "$O"

# L-fail: a failing binary.
new_world linux-fail
exe model_setup fail
harness "$root" run-linux.sh "$O" "$HOST"
check "L30 linux: a failing binary -> nonzero exit" is_nonzero "$rc"
check "L31 linux: tests.txt keeps the failing binary's exit (101)" grep_q "### model_setup exit=101" "$O/tests.txt"
check "L32 linux: commands.txt keeps that exit for the remote step" \
    grep_q "exit 101: remote: every test binary under timeout 1800 and nice -n 10" "$O/commands.txt"
check "L33 linux: the scratch directory is removed after a failure" dir_tree_is_empty "$H"
check "L34 linux: the removal after the failure is recorded as exit 0" \
    grep_q "exit 0: ssh <linuxhost> rm -rf the run's scratch dir, then check it is absent" "$O/commands.txt"

# L-arch: not x86_64.
new_world linux-arch
extra_env=(HM_ST_ARCH=aarch64)
harness "$root" run-linux.sh "$O" "$HOST"
check "L40 linux: a host that is not x86_64 -> exit 3 and nothing copied or created" \
    bash -c '[ "$1" = 3 ] && ! grep -qE "^(cargo|zig)" "$2" && [ -z "$(ls -A "$3")" ]' _ "$rc" "$L" "$H"
check "L41 linux: host.txt names the architecture" grep_q "aarch64" "$O/host.txt"

# L-unreachable
new_world linux-unreachable
extra_env=(HM_ST_UNREACHABLE=1)
harness "$root" run-linux.sh "$O" "$HOST"
check "L42 linux: an unreachable host -> exit 4 with the error saved without the host name" \
    bash -c '[ "$1" = 4 ] && [ -f "$2/host-unreachable.txt" ] && ! grep -q "hm-selftest-no-such-host" "$2/host-unreachable.txt"' _ "$rc" "$O"
check "L43 linux: nothing was built or created after the refusal" bash -c '! grep -q "^cargo" "$1" && [ -z "$(ls -A "$2")" ]' _ "$L" "$H"

# L-bad alias
for bad in -oProxyCommand=x 'a b' 'a;b'; do
    new_world linux-bad
    harness "$root" run-linux.sh "$O" "$bad"
    check "L44 linux: alias '$bad' rejected with exit 2 before cargo or ssh" bash -c '[ "$1" = 2 ] && [ ! -s "$2" ]' _ "$rc" "$L"
done

# L-canary, leak, owner-change
new_world linux-canary
exe model_setup canary
harness "$root" run-linux.sh "$O" "$HOST"
check "L50 linux: a canary prefix in a binary's output -> nonzero exit" is_nonzero "$rc"
check "L51 linux: the canary scan result is recorded with exit 1" grep_q "exit 1: canary-prefix scan over saved output" "$O/commands.txt"
check "L52 linux: the scratch directory is removed after a canary finding" dir_tree_is_empty "$H"

new_world linux-leak
exe model_setup leak
harness "$root" run-linux.sh "$O" "$HOST"
check "L53 linux: a binary that prints the home, the user and host names still leaves them out of every artifact" \
    none_of "$O" "$H" "$REAL_USER" "wslfixturehost" "203.0.113.9"
check "L54 linux: they were replaced by labels and the run still passes" \
    bash -c 'grep -q "<home>" "$2" && grep -q "<user>" "$2" && grep -q "<linuxhost>" "$2" && grep -q "<addr>" "$2" && [ "$1" = 0 ]' _ "$rc" "$O/tests.txt"

new_world linux-owner
exe model_setup touch-owner
harness "$root" run-linux.sh "$O" "$HOST"
check "L55 linux: a binary that writes into ~/.ssh -> the unchanged-metadata check fails, exit nonzero" is_nonzero "$rc"
check "L56 linux: that check is recorded with exit 1" grep_q "exit 1: host ~/.ssh and Git configuration metadata unchanged by the run" "$O/commands.txt"

# L-only
new_world linux-only
extra_env=(HM_ONLY="model_setup model_time_does_not_exist")
harness "$root" run-linux.sh "$O" "$HOST"
check "L57 linux: HM_ONLY runs only the named targets, the rest are listed as not selected" \
    bash -c '[ "$1" = 0 ] && [ "$(grep -c "^### [A-Za-z0-9_-]* exit=" "$2")" = 1 ] && grep -q "^### model_setup exit=0" "$2" && grep -q "e2e_cli_m02: not selected (HM_ONLY)" "$3"' _ "$rc" "$O/tests.txt" "$O/skipped.txt"

# L-preflight sshd unavailable
new_world linux-nosshd
extra_env=(HM_ST_SSHD=fail)
harness "$root" run-linux.sh "$O" "$HOST"
check "L58 linux: a fixture sshd that cannot start is recorded as unavailable with its reason, never silently" \
    bash -c 'grep -q "^fixture-sshd-preflight=unavailable: sshd -t rejected the fixture configuration$" "$1"' _ "$O/host.txt"

# L-obs: --show-output reaches every binary, and what a passing test printed is kept (redacted).
new_world linux-obs
exe model_setup obs
harness "$root" run-linux.sh "$O" "$HOST"
check "L60 linux: every binary ran with --show-output" \
    bash -c 'n=$(grep -c "^argv: .*--show-output$" "$1"); [ "$n" -ge 25 ] && [ "$n" = "$(grep -c "^argv: " "$1")" ]' _ "$L"
check "L61 linux: the observation line of a passing test is in tests.txt under its test header, with the home redacted" \
    bash -c 't=$1; grep -q "^---- fixture::a stdout ----$" "$t" && grep -q "^observation test=a path=<home> supported=true$" "$t"' _ "$O/tests.txt"
show_output_last() {
    local n
    n=$(grep -c "^argv: .*--show-output$" "$1")
    [ "$n" -ge 25 ] && [ "$n" = "$(grep -c "^argv: " "$1")" ] && skip_args_exactly "$1"
}
check "L62 linux: --show-output is every binary's last argument, preceded only by the build_host_paths skips" \
    show_output_last "$L"

# L-existing directory with a similar name
new_world linux-existing
mkdir -p "$H/hm-m02-aaaaaaaaaaaa"
echo keep >"$H/hm-m02-aaaaaaaaaaaa/other-run.txt"
harness "$root" run-linux.sh "$O" "$HOST"
check "L59 linux: another run's hm-m02-* directory and its files survive; only this run's is removed" \
    bash -c '[ "$1" = 0 ] && [ -f "$2/hm-m02-aaaaaaaaaaaa/other-run.txt" ] && [ "$(ls -A "$2" | wc -l | tr -d " ")" = 1 ]' _ "$rc" "$H"

# =============================================================================================
# M: run-macos.sh against a fake repository root
# =============================================================================================

make_fake_root() {
    # make_fake_root DIR: a copy of the M02 harness files with a stub check.sh and Docker fixtures.
    local r=$1
    mkdir -p "$r/tests/native" "$r/tools/validation" "$r/tests/fixtures/ssh"
    cp -R "$m02" "$r/tests/native/m02"
    rm -rf "$r/tests/native/m02/__pycache__"
    mkdir -p "$r/tests/native/windows-ipc"
    cp "$root/tests/native/windows-ipc/scratch-lib.sh" "$r/tests/native/windows-ipc/"
    cat >"$r/tools/validation/check.sh" <<'EOF'
#!/usr/bin/env bash
# check.sh stub: the shape of the real output, an exit code on demand, the fixture
# variables and the temp directory it was given.
echo "== test: cargo test --workspace --locked"
echo "     Running unittests src/lib.rs (target/debug/deps/heimdall_x-0123abcd)"
echo "running 1 test"
echo "test a::b ... ok"
echo "env tmpdir_in_scratch=$(printf '%s' "${TMPDIR:-}" | grep -q 'hm-m02-macos\.' && echo yes || echo no)"
echo "check-tmpdir ${TMPDIR:-}" >>"$HM_ST_LOG"
echo "env repo_root=$([ "${HM_REPO_ROOT:-}" = "$(cd "$(dirname "$0")/../.." && pwd)" ] && echo checkout || echo other)"
echo "env ssh_auth_sock=${SSH_AUTH_SOCK:-unset}"
echo "env fixture_port=${HM_FIXTURE_SSHD_PORT:-unset}"
echo "env fixture_host=${HM_FIXTURE_SSHD_HOST:-unset}"
echo "env fixture_key=${HM_FIXTURE_SSHD_HOST_KEY:+set}"
[ "${HM_ST_CHECK:-ok}" = canary ] && echo "HEIMDALL_CANARY_"
[ "${HM_ST_CHECK:-ok}" = leak ] && echo "leak home=$HOME user=$(id -un) host=$(hostname)"
echo "== test: exit ${HM_ST_CHECK_RC:-0}"
echo "== overall: exit ${HM_ST_CHECK_RC:-0}"
exit "${HM_ST_CHECK_RC:-0}"
EOF
    cat >"$r/tests/fixtures/ssh/up.sh" <<'EOF'
#!/usr/bin/env bash
# Docker fixture stub: ports and host key for the `fixed` role.
d=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$d/runtime/hostkeys/fixed"
printf 'PORT_fixed=24242\n' >"$d/runtime/ports.env"
printf 'ssh-ed25519 AAAAselftestkey selftest\n' >"$d/runtime/hostkeys/fixed/ssh_host_ed25519_key.pub"
echo "up (stub)"
exit "${HM_ST_UP_RC:-0}"
EOF
    cat >"$r/tests/fixtures/ssh/down.sh" <<'EOF'
#!/usr/bin/env bash
echo "down (stub)" >>"$HM_ST_LOG"
[ "${HM_ST_DOWN:-ok}" = ok ] && echo "CLEANUP CONFIRMED"
exit 0
EOF
    chmod +x "$r/tools/validation/check.sh" "$r/tests/fixtures/ssh/up.sh" "$r/tests/fixtures/ssh/down.sh"
}

# mac_scratch_gone LOG: the TMPDIR check.sh saw was <scratch>/tmp with <scratch> directly
# under /tmp (the macOS /tmp is /private/tmp), and that scratch no longer exists.
mac_scratch_gone() {
    local t d
    t=$(sed -n 's/^check-tmpdir //p' "$1" | tail -1)
    d=${t%/tmp}
    case "$d" in /tmp/hm-m02-macos.?* | /private/tmp/hm-m02-macos.?*) ;; *) return 1 ;; esac
    case "${d#*/tmp/}" in */*) return 1 ;; esac
    [ ! -e "$d" ]
}

new_world mac-build
make_fake_root "$S/repo"
extra_env=(HM_BUILD_ONLY=1)
harness "$S/repo" run-macos.sh "$O"
check "M01 macos build-only: exits 0, cargo ran for the host, hashes recorded, check.sh and sshd untouched" \
    bash -c '[ "$1" = 0 ] && grep -q "^cargo test --workspace --no-run --locked" "$2" && grep -q "sha256: [0-9a-f]\{64\}$" "$3" && ! grep -q "^sshd" "$2"' _ "$rc" "$L" "$O/build.txt"
check "M02 macos build-only: the scratch directory is removed, recorded with exit 0" \
    bash -c 'grep -q "^exit 0: remove exactly the run.s scratch directory, then check it is absent" "$1" && [ -z "$(ls -A "$2")" ]' _ "$O/commands.txt" "$S/tmp"

new_world mac-pass
make_fake_root "$S/repo"
extra_env=(SSH_AUTH_SOCK=/nonexistent/hm-selftest-agent)
harness "$S/repo" run-macos.sh "$O"
check "M03 macos: a passing check.sh -> exit 0; its real exit code is recorded" \
    bash -c '[ "$1" = 0 ] && grep -q "^exit 0: bash tools/validation/check.sh" "$2"' _ "$rc" "$O/commands.txt"
check "M04 macos: check.sh ran with TMPDIR inside the scratch directory and the inherited agent unset" \
    bash -c 'grep -q "^env tmpdir_in_scratch=yes$" "$1" && grep -q "^env ssh_auth_sock=unset$" "$1"' _ "$O/check.txt"
check "M05 macos: the cargo log lines are kept for the evidence generator" grep_q "Running unittests src/lib.rs (target/debug/deps/heimdall_x-0123abcd)" "$O/check.txt"
check "M06 macos: the sshd preflight ran on 127.0.0.1 (no Docker) and the fixture facts are recorded" \
    bash -c 'grep -q "^fixture-sshd-preflight=listening on 127.0.0.1" "$1" && ! grep -q "^down" "$2" && grep -q "^env fixture_port=unset$" "$3"' _ "$O/host.txt" "$L" "$O/check.txt"
check "M07 macos: host.txt has the OS, script, scratch file system, ssh/sshd/git versions" \
    bash -c 'h=$1; grep -q "^os=" "$h" && grep -q "^script=" "$h" && grep -q "^scratch-fs=" "$h" && grep -q "^ssh-V=" "$h" && grep -q "^sshd-V=" "$h" && grep -q "^git-version=git version 0.0.0-selftest (exit 0)$" "$h"' _ "$O/host.txt"
check "M21 macos: the observation targets of the case index ran once more through cargo with --show-output" \
    bash -c 'grep -qx "cargo test --workspace --locked --no-fail-fast --test integration_doctor --test integration_git_observe --test integration_projection_replace --test integration_sshconf_vs_ssh_g -- --show-output" "$1" && grep -q "^exit 0: cargo test --workspace --locked --no-fail-fast <the observation targets> -- --show-output" "$2" && [ -f "$3" ]' _ "$L" "$O/commands.txt" "$O/observations.txt"
check "M08 macos: the home .ssh and Git metadata unchanged is recorded with exit 0; scans pass" \
    bash -c 'c=$1; grep -q "^exit 0: the home .ssh directory and Git configuration metadata unchanged by the run" "$c" && grep -q "^exit 0: canary-prefix scan" "$c" && grep -q "^exit 0: leak scan" "$c"' _ "$O/commands.txt"
check "M09 macos: the scratch directory is gone and the sshd it started too" \
    bash -c '[ -z "$(ls -A "$1")" ] && { for p in $(cat "$2"); do kill -0 "$p" 2>/dev/null && exit 1; done; exit 0; }' _ "$S/tmp" "$S/sshd.pids"
check "M24 macos: the scratch directory is under /tmp, not the per-user TMPDIR (SUN_LEN), and it is gone after the run" \
    mac_scratch_gone "$L"
check "M25 macos: check.sh ran with HM_REPO_ROOT at the checkout (ADR-0007 §12.32 item 3)" \
    grep_q "env repo_root=checkout" "$O/check.txt"

new_world mac-fail
make_fake_root "$S/repo"
extra_env=(HM_ST_CHECK_RC=1)
harness "$S/repo" run-macos.sh "$O"
check "M10 macos: a failing check.sh -> the harness exits with its code, recorded as exit 1" \
    bash -c '[ "$1" = 1 ] && grep -q "^exit 1: bash tools/validation/check.sh" "$2" && grep -q "== overall: exit 1" "$3"' _ "$rc" "$O/commands.txt" "$O/check.txt"
check "M11 macos: the scratch directory is removed after the failure" mac_scratch_gone "$L"

new_world mac-obs-fail
make_fake_root "$S/repo"
extra_env=(HM_ST_CARGO_FAIL=1)
harness "$S/repo" run-macos.sh "$O"
check "M22 macos: a failing observation pass -> the harness exits with its code (101), recorded; check.sh's own exit was 0" \
    bash -c '[ "$1" = 101 ] && grep -q "^exit 101: cargo test --workspace --locked --no-fail-fast <the observation targets>" "$2" && grep -q "^exit 0: bash tools/validation/check.sh" "$2"' _ "$rc" "$O/commands.txt"
check "M23 macos: the scratch directory is removed after it" mac_scratch_gone "$L"

new_world mac-docker
make_fake_root "$S/repo"
extra_env=(HM_ST_SSHD=fail HM_DOCKER_FALLBACK=1)
harness "$S/repo" run-macos.sh "$O"
check "M12 macos: a fixture sshd that cannot start -> the Docker fixtures are started on 127.0.0.1 and passed as HM_FIXTURE_SSHD_*" \
    bash -c '[ "$1" = 0 ] && grep -q "^env fixture_port=24242$" "$2" && grep -q "^env fixture_host=127.0.0.1$" "$2" && grep -q "^env fixture_key=set$" "$2"' _ "$rc" "$O/check.txt"
check "M13 macos: down.sh ran and its CLEANUP CONFIRMED is recorded" \
    bash -c 'grep -q "^down (stub)" "$1" && grep -q "^exit 0: tests/fixtures/ssh/down.sh (exit 0) printed CLEANUP CONFIRMED" "$2"' _ "$L" "$O/commands.txt"
check "M14 macos: the unavailable sshd and the fixture fallback are recorded" \
    bash -c 'grep -q "^fixture-sshd-preflight=unavailable" "$1" && grep -q "^fixture-sshd=Docker fallback" "$1"' _ "$O/host.txt"

new_world mac-docker-unconfirmed
make_fake_root "$S/repo"
extra_env=(HM_ST_SSHD=fail HM_ST_DOWN=silent HM_DOCKER_FALLBACK=1)
harness "$S/repo" run-macos.sh "$O"
check "M15 macos: a down.sh that does not print CLEANUP CONFIRMED -> nonzero exit, recorded as exit 1" \
    bash -c '[ "$1" != 0 ] && grep -q "^exit 1: tests/fixtures/ssh/down.sh (exit 0) printed CLEANUP CONFIRMED" "$2"' _ "$rc" "$O/commands.txt"

new_world mac-nodocker
make_fake_root "$S/repo"
extra_env=(HM_ST_SSHD=fail HM_DOCKER_FALLBACK=0)
harness "$S/repo" run-macos.sh "$O"
check "M16 macos: HM_DOCKER_FALLBACK=0 never starts the Docker fixtures; the tests see no fixture variables" \
    bash -c '! grep -q "^down" "$1" && grep -q "^env fixture_port=unset$" "$2" && [ ! -e "$3/tests/fixtures/ssh/runtime" ]' _ "$L" "$O/check.txt" "$S/repo"

new_world mac-docker-up-fails
make_fake_root "$S/repo"
extra_env=(HM_ST_SSHD=fail HM_ST_UP_RC=7 HM_DOCKER_FALLBACK=1)
harness "$S/repo" run-macos.sh "$O"
check "M17 macos: up.sh failing stops the run with its exit code, and down.sh still cleans up" \
    bash -c '[ "$1" = 7 ] && grep -q "^down (stub)" "$2" && grep -q "^exit 7: tests/fixtures/ssh/up.sh" "$3"' _ "$rc" "$L" "$O/commands.txt"

new_world mac-docker-already-up
make_fake_root "$S/repo"
mkdir -p "$S/repo/tests/fixtures/ssh/runtime"
: >"$S/repo/tests/fixtures/ssh/runtime/other-run-sentinel"
extra_env=(HM_ST_SSHD=fail HM_ST_UP_RC=3 HM_DOCKER_FALLBACK=1)
harness "$S/repo" run-macos.sh "$O"
check "M17b macos (ADR-0007 §12.33 P01): up.sh refusing pre-existing fixtures (exit 3) -> exit 3, no down.sh, the other run's fixtures untouched, recorded as blocked" \
    bash -c '[ "$1" = 3 ] && ! grep -q "^down" "$2" && [ -e "$3/tests/fixtures/ssh/runtime/other-run-sentinel" ] && grep -q "^blocked: the Docker fixtures already exist" "$4/blocked.txt" && grep -q "already exist (another run.s): left untouched, run blocked" "$4/commands.txt"' _ "$rc" "$L" "$S/repo" "$O"

new_world mac-docker-default-off
make_fake_root "$S/repo"
extra_env=(HM_ST_SSHD=fail)
harness "$S/repo" run-macos.sh "$O"
check "M16b macos (ADR-0007 §12.38 L01): by default a fixture sshd that cannot start never starts Docker; no up.sh, no down.sh, no lock" \
    bash -c '! grep -q "^up (stub)" "$1/up.txt" 2>/dev/null && ! grep -q "^down" "$2" && [ ! -e "$3/tests/fixtures/ssh/runtime" ] && [ ! -e "$3/tests/fixtures/ssh/runtime.owner.lock" ] && grep -q "^env fixture_port=unset$" "$4"' _ "$O" "$L" "$S/repo" "$O/check.txt"

new_world mac-docker-locked
make_fake_root "$S/repo"
mkdir -p "$S/repo/tests/fixtures/ssh/runtime.owner.lock"
mkdir -p "$S/repo/tests/fixtures/ssh/runtime"
: >"$S/repo/tests/fixtures/ssh/runtime/other-run-sentinel"
extra_env=(HM_ST_SSHD=fail HM_DOCKER_FALLBACK=1)
harness "$S/repo" run-macos.sh "$O"
check "M17c macos (ADR-0007 §12.38 L01): a held ownership lock blocks the run (exit 3), runs neither up.sh nor down.sh, and leaves the lock and the other run's fixtures in place" \
    bash -c '[ "$1" = 3 ] && ! grep -q "^down" "$2" && [ -d "$3/tests/fixtures/ssh/runtime.owner.lock" ] && [ -e "$3/tests/fixtures/ssh/runtime/other-run-sentinel" ] && grep -q "^blocked: another run holds the Docker fixture lock" "$4/blocked.txt"' _ "$rc" "$L" "$S/repo" "$O"

new_world mac-docker-lock-released
make_fake_root "$S/repo"
extra_env=(HM_ST_SSHD=fail HM_DOCKER_FALLBACK=1)
harness "$S/repo" run-macos.sh "$O"
check "M17d macos (ADR-0007 §12.38 L01): a run that started the fixtures releases its lock after its teardown" \
    bash -c '[ "$1" = 0 ] && grep -q "^down (stub)" "$2" && [ ! -e "$3/tests/fixtures/ssh/runtime.owner.lock" ] && grep -q "^exit 0: release the Docker fixture ownership lock" "$4/commands.txt"' _ "$rc" "$L" "$S/repo" "$O"

new_world mac-canary
make_fake_root "$S/repo"
extra_env=(HM_ST_CHECK=canary)
harness "$S/repo" run-macos.sh "$O"
check "M18 macos: a canary prefix in check.sh's output -> nonzero exit" is_nonzero "$rc"
new_world mac-leak
make_fake_root "$S/repo"
extra_env=(HM_ST_CHECK=leak)
harness "$S/repo" run-macos.sh "$O"
check "M19 macos: the home, user and host names in check.sh's output are redacted from every artifact" \
    bash -c '[ "$1" = 0 ] && grep -q "<home>" "$2" && grep -q "<user>" "$2" && grep -q "<host>" "$2"' _ "$rc" "$O/check.txt"
check "M20 macos: ...and none of them is left in any artifact" none_of "$O" "$H" "$REAL_USER" "wslfixturehost"

# =============================================================================================
# W: run-windows.sh
# =============================================================================================

# B01 on the M02 harness: an existing directory named like the task is never touched.
new_world win-existing
mkdir -p "$H/hm-m00/M02-old" "$W/localappdata/hm-m00/M02-old"
echo keep >"$H/hm-m00/M02-old/other-run.txt"
echo keep >"$W/localappdata/hm-m00/M02-old/other-run.txt"
exe e2e_cli_m02 env
extra_env=(HM_TASK=M02-old SSH_AUTH_SOCK=/nonexistent/hm-selftest-agent GIT_DIR=/nonexistent)
harness "$root" run-windows.sh "$O"
first=$(run_name "$O/commands.txt")
check "W01 windows: a run with every binary passing exits 0" is_zero "$rc"
check "W02 windows: another run's WSL and Windows files survive and nothing is written into its directories" \
    bash -c '[ -f "$1/hm-m00/M02-old/other-run.txt" ] && [ -f "$2/localappdata/hm-m00/M02-old/other-run.txt" ] && [ "$(ls -A "$1/hm-m00/M02-old")" = other-run.txt ] && [ "$(ls -A "$2/localappdata/hm-m00/M02-old")" = other-run.txt ]' _ "$H" "$W"
check "W03 windows: both run directories were removed (only the pre-existing one is left)" \
    bash -c '[ "$(ls -A "$1/hm-m00")" = M02-old ] && [ "$(ls -A "$2/localappdata/hm-m00")" = M02-old ]' _ "$H" "$W"
check "W04 windows: the run directory is <task>-<random>" starts_with "$first" "M02-old-"
check "W05 windows: the removal of both sides is recorded with exit 0" \
    grep_q "exit 0: remote: remove exactly the run directories (both sides), then check they are absent" "$O/commands.txt"
harness "$root" run-windows.sh "$O"
second=$(run_name "$O/commands.txt")
check "W06 windows: two runs use different directories" differ "$first" "$second"

check "W07 windows: the tests resolve the in-box OpenSSH first: the command line puts System32\\OpenSSH at the front of PATH" \
    bash -c 'grep -q "set PATH=%SystemRoot%\\\\System32\\\\OpenSSH;%PATH%&& \.\\\\e2e_cli_m02\.exe" "$1"' _ "$L"
check "W08 windows: every binary under timeout 1800 and nice -n 10 (the WSL relay's priority only) through cmd.exe /d /c" \
    bash -c 'n=$(grep -c "^nice -n 10 cmd.exe" "$1"); t=$(grep -c "^timeout 1800 nice" "$1"); [ "$n" -ge 25 ] && [ "$n" = "$t" ]' _ "$L"
check "W09 windows: host.txt has the integrity level, Windows version, both ssh -V lines, Git versions, Developer Mode (read only)" \
    bash -c 'h=$1; grep -q "^integrity=Medium Mandatory Level$" "$h" && grep -q "^os=Microsoft Windows" "$h" && grep -q "^ssh-V-inbox=" "$h" && grep -q "^ssh-V-path-first=.*(candidate, not selected)$" "$h" &&
        grep -q "^ssh-V-tests=.* (what the tests resolve, HM_WINDOWS_SSH=inbox)$" "$h" && grep -q "^git-version-windows=git version 2.0.0.windows.1$" "$h" && grep -q "^git-version-wsl=git version 0.0.0-selftest (exit 0)$" "$h" && grep -q "^developer-mode=on (read only)$" "$h"' _ "$O/host.txt"
check "W10 windows: the registry was only queried (no add, delete, import or other write)" \
    bash -c 'grep "^reg.exe" "$1" | grep -qv "^reg.exe query " && exit 1; grep -q "^reg.exe query " "$1"' _ "$L"
check "W11 windows: nothing elevated, no service, no firewall, no agent state, no wsl --shutdown" \
    log_lacks '^(sudo|doas|su|ssh-agent|ssh-add) |^wsl --shutdown'
check "W12 windows: the fixture sshd ran in WSL scratch on 127.0.0.1 only and was reachable from Windows (banner)" \
    bash -c 'h=$1; grep -q "^fixture-sshd=listening on 127.0.0.1 in WSL scratch (non-root, per-run host key)$" "$h" && grep -q "^fixture-sshd-from-windows=reachable" "$h" && grep -qx "ListenAddress 127.0.0.1" "$2" && [ "$(grep -c "^ListenAddress" "$2")" = 1 ]' _ "$O/host.txt" "$S/sshd-config.copy"
check "W13 windows: HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY,AUTHORIZED_KEYS,LOG} reached the tests, through WSLENV" \
    bash -c 't=$1; grep -q "^env fixture_host=127.0.0.1$" "$t" && grep -q "^env fixture_port=set$" "$t" && grep -q "^env fixture_key=set$" "$t" && grep -q "^env fixture_keys_file=set$" "$t" && grep -q "^env fixture_log=set$" "$t" &&
        grep "^env wslenv=" "$t" | grep -q "HM_FIXTURE_SSHD_HOST/w:HM_FIXTURE_SSHD_PORT/w:HM_FIXTURE_SSHD_HOST_KEY/w:HM_FIXTURE_SSHD_AUTHORIZED_KEYS/w:HM_FIXTURE_SSHD_LOG/w" && grep "^env wslenv=" "$t" | grep -q "HEIMDALL_E2E_BIN/w" && grep "^env wslenv=" "$t" | grep -q "HM_FIXTURE_HOOK/w"' _ "$O/tests.txt"
check "W14 windows: TEMP points inside the Windows run directory; inherited agent and Git variables were unset" \
    bash -c 't=$1; grep -q "^env temp=C:.*hm-m00.*tmp$" "$t" && grep -q "^env ssh_auth_sock=unset$" "$t" && grep -q "^env git_vars=0$" "$t" && grep -q "^env e2e_bin=set$" "$t" && grep -q "^env hook=set$" "$t"' _ "$O/tests.txt"
check "W15 windows: the fixture sshd was stopped and no sshd process of the run is left" \
    bash -c 'grep -q "^fixture-sshd-stopped=yes$" "$1" && for p in $(cat "$2"); do kill -0 "$p" 2>/dev/null && exit 1; done; exit 0' _ "$O/host.txt" "$S/sshd.pids"
check "W16 windows: the pseudoconsole driver rows became ### windows_launch test lines with their exit code" \
    bash -c 't=$1; grep -q "^### windows_launch$" "$t" && grep -q "^test ctrlc.event \.\.\. ok$" "$t" && grep -q "^test resize \.\.\. ok$" "$t" && grep -q "^### windows_launch exit=0$" "$t"' _ "$O/tests.txt"
check "W17 windows: the driver was cross-built (go build, trimpath) and its hash recorded" \
    bash -c 'grep -q "^go build -o " "$1" && grep -q "^argvdump.exe sha256: [0-9a-f]\{64\}$" "$2"' _ "$L" "$O/build.txt"
check "W18 windows: the Windows profile .ssh and .gitconfig metadata unchanged is recorded with exit 0" \
    grep_q "unchanged by the run" "$O/commands.txt"
check "W19 windows: test pipes and %LOCALAPPDATA%\\heimdall are counted before and after" \
    bash -c 'h=$1; grep -q "^test-pipes-before=0$" "$h" && grep -q "^test-pipes-after=0$" "$h" && grep -q "^localappdata-heimdall-before=absent$" "$h" && grep -q "^localappdata-heimdall-after=absent$" "$h" && grep -q "^leftover-test-processes=0$" "$h"' _ "$O/host.txt"
w20_repo_root() {
    skipped_exactly windows "$1" &&
        bash -c 't=$1; grep -q "^### e2e_cli_m02 exit=0" "$t" && grep -q "^env repo_root=set$" "$t" && grep -q "^env repo_root_has_files=yes$" "$t" && grep "^env wslenv=" "$t" | grep -q "HM_REPO_ROOT/w"' _ "$2"
}
check "W20 windows: exactly the build_host_paths entries are skipped as build-host-only; HM_REPO_ROOT names the repository copy in the Windows scratch, through WSLENV" \
    w20_repo_root "$O/skipped.txt" "$O/tests.txt"
check "W21 windows: host, user and home names, both WSL and Windows, are absent from every artifact" \
    none_of "$O" "$H" "wslfixturehost" "FIXTUREHOST" "fixtureuser" "$REAL_USER"
check "W22 windows: the owner's Windows profile .ssh was not touched (no file created there)" no_file "$W/Users/fixtureuser/.ssh"

# ADR-0007 §12.32 item 10: an unreachable host ends the run after the build, and the build
# log is redacted all the same; the error is kept without the host name.
new_world win-unreachable
extra_env=(HM_ST_UNREACHABLE=1)
harness "$root" run-windows.sh "$O"
check "W38 windows: an unreachable host -> exit 4, nothing created, the error saved without the host name" \
    bash -c '[ "$1" = 4 ] && [ -f "$2/host-unreachable.txt" ] && ! grep -q "hm-selftest-no-such-host" "$2/host-unreachable.txt" && grep -q "<winhost>" "$2/host-unreachable.txt" && [ -z "$(ls -A "$3/localappdata")" ]' _ "$rc" "$O" "$W"
check "W39 windows: ...and the build log is redacted before that exit (no build-host home or user left)" \
    bash -c 'grep -q "<home>/hm-selftest-checkout" "$1" && ! grep -qF "$2" "$1" && ! grep -qw "$3" "$1"' _ "$O/build.txt" "$H" "$REAL_USER"

new_world win-obs
exe model_setup obs
harness "$root" run-windows.sh "$O"
check "W37 windows: every binary ran with --show-output and a passing test's observation line is kept, redacted" \
    bash -c 'n=$(grep -c "^argv: .*--show-output$" "$1"); [ "$n" -ge 25 ] && [ "$n" = "$(grep -c "^argv: " "$1")" ] && grep -q "^observation test=a path=<wslhome> supported=true$" "$2"' _ "$L" "$O/tests.txt"

# B01: bad task names reach nothing.
n=0
for bad in . .. -x 'a/b'; do
    n=$((n + 1))
    new_world "win-bad-$n"
    extra_env=(HM_TASK="$bad")
    harness "$root" run-windows.sh "$O"
    check "W23 windows: HM_TASK '$bad' rejected with exit 2 before any cargo, ssh or scp" bash -c '[ "$1" = 2 ] && [ ! -s "$2" ]' _ "$rc" "$L"
done

# B01: symlinked roots refused, nothing behind them touched.
new_world win-wsl-link
mkdir -p "$S/elsewhere"
echo keep >"$S/elsewhere/unrelated.txt"
ln -s "$S/elsewhere" "$H/hm-m00"
extra_env=(HM_TASK=M02-link)
harness "$root" run-windows.sh "$O"
check "W24 windows: a symlinked WSL scratch root -> nonzero exit, nothing written or removed behind it, no Windows directory" \
    bash -c '[ "$1" != 0 ] && [ "$(ls -A "$2")" = unrelated.txt ] && [ -z "$(ls -A "$3/localappdata")" ]' _ "$rc" "$S/elsewhere" "$W"
new_world win-win-link
mkdir -p "$S/elsewhere"
echo keep >"$S/elsewhere/unrelated.txt"
ln -s "$S/elsewhere" "$W/localappdata/hm-m00"
extra_env=(HM_TASK=M02-link)
harness "$root" run-windows.sh "$O"
check "W25 windows: a symlinked Windows scratch root -> nonzero exit, the WSL directory it made is removed, nothing behind the link touched" \
    bash -c '[ "$1" != 0 ] && [ "$(ls -A "$2")" = unrelated.txt ] && [ -z "$(ls -A "$3/hm-m00")" ]' _ "$rc" "$S/elsewhere" "$H"

# A failing binary; a forwarding failure; no launch driver; the driver failing; PATH-first ssh.
new_world win-fail
exe model_setup fail
harness "$root" run-windows.sh "$O"
check "W26 windows: a failing binary -> nonzero exit, its exit kept, the run directories removed" \
    bash -c '[ "$1" != 0 ] && grep -q "^### model_setup exit=101" "$2" && grep -q "exit 101: remote: every test binary and the pseudoconsole drivers" "$3" && [ -z "$(ls -A "$4/hm-m00")" ]' _ "$rc" "$O/tests.txt" "$O/commands.txt" "$H"

new_world win-noforward
exe e2e_cli_m02 env
extra_env=(HM_ST_BANNER=unreachable)
harness "$root" run-windows.sh "$O"
check "W27 windows: NAT forwarding failing on three ports is recorded as a harness failure and the tests run without HM_FIXTURE_SSHD_*" \
    bash -c 'h=$1; grep -q "^fixture-sshd-forwarding-try-3=unreachable from Windows$" "$h" && grep -q "^fixture-sshd-harness=failed" "$h" && grep -q "^env fixture_host=unset$" "$2" && grep -q "exit 1: fixture sshd in WSL scratch reachable from Windows" "$3"' _ "$O/host.txt" "$O/tests.txt" "$O/commands.txt"
check "W28 windows: ...every try's sshd was stopped" bash -c 'for p in $(cat "$1"); do kill -0 "$p" 2>/dev/null && exit 1; done; [ "$(wc -l <"$1" | tr -d " ")" = 3 ]' _ "$S/sshd.pids"

new_world win-nolaunch
extra_env=(HM_LAUNCH_DRIVER=0)
harness "$root" run-windows.sh "$O"
check "W29 windows: HM_LAUNCH_DRIVER=0 skips the pseudoconsole drivers and says so" \
    bash -c '[ "$1" = 0 ] && grep -q "^windows_launch: not run (HM_LAUNCH_DRIVER=0)$" "$2" && ! grep -q "^### windows_launch" "$3" && ! grep -q "^go build" "$4"' _ "$rc" "$O/skipped.txt" "$O/tests.txt" "$L"

new_world win-launchfail
extra_env=(HM_ST_LAUNCH=fail)
harness "$root" run-windows.sh "$O"
check "W30 windows: a failing driver row -> nonzero exit and a FAILED line for that row" \
    bash -c '[ "$1" != 0 ] && grep -q "^test ctrlc.event \.\.\. FAILED$" "$2" && grep -q "^### windows_launch exit=1$" "$2"' _ "$rc" "$O/tests.txt"

new_world win-pathssh
extra_env=(HM_WINDOWS_SSH=path)
harness "$root" run-windows.sh "$O"
check "W31 windows: HM_WINDOWS_SSH=path keeps the inherited PATH (no OpenSSH prefix)" \
    bash -c '[ "$1" = 0 ] && ! grep -q "set PATH=%SystemRoot%" "$2" && grep -q "HM_WINDOWS_SSH=path" "$3"' _ "$rc" "$L" "$O/host.txt"
new_world win-badssh
extra_env=(HM_WINDOWS_SSH=other)
harness "$root" run-windows.sh "$O"
check "W32 windows: an unknown HM_WINDOWS_SSH is refused with exit 2" is_n "$rc" 2

new_world win-canary
exe model_setup canary
harness "$root" run-windows.sh "$O"
check "W33 windows: a canary prefix in a binary's output -> nonzero exit, run directories removed" \
    bash -c '[ "$1" != 0 ] && [ -z "$(ls -A "$2/hm-m00")" ] && grep -q "exit 1: canary-prefix scan" "$3"' _ "$rc" "$H" "$O/commands.txt"
new_world win-owner
exe model_setup touch-owner
harness "$root" run-windows.sh "$O"
check "W34 windows: a binary that writes into the Windows profile's .ssh -> the metadata check fails, nonzero exit" \
    bash -c '[ "$1" != 0 ] && grep -q "exit 1: %USERPROFILE%.*unchanged by the run" "$2"' _ "$rc" "$O/commands.txt"

new_world win-build-only
extra_env=(HM_BUILD_ONLY=1)
harness "$root" run-windows.sh "$O"
check "W35 windows build-only: no ssh, builds the driver, plans the targets, hashes with .exe names" \
    bash -c '[ "$1" = 0 ] && ! grep -q "^ssh " "$2" && grep -q "^go build" "$2" && grep -q "^e2e_cli_m02.exe sha256: " "$3" && grep -q "^heimdall.exe (CLI" "$3"' _ "$rc" "$L" "$O/build.txt"

new_world win-cargo-fail
extra_env=(HM_ST_CARGO_FAIL=1)
harness "$root" run-windows.sh "$O"
check "W36 windows: a failed cross-build exits with cargo's code, reaches no host and records it" \
    bash -c '[ "$1" = 101 ] && ! grep -q "^ssh " "$2" && grep -q "^exit 101: cargo test --target x86_64-pc-windows-gnu" "$3"' _ "$rc" "$L" "$O/commands.txt"

# =============================================================================================
# D: run-wsl-distro.sh
# =============================================================================================

PIN=$(sed -n 's/^ROOTFS_SHA256=//p' "$m02/run-wsl-distro.sh")
check "D01 distro: the pinned image digest and URL are the ones G03 checked (ubuntu-24.04.5, 64 hex digits)" \
    bash -c '[ "${#1}" = 64 ] && case "$1" in *[!0-9a-f]*) exit 1 ;; esac && grep -q "^ROOTFS_URL=https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl$" "$2"' _ "$PIN" "$m02/run-wsl-distro.sh"

new_world distro-build
extra_env=(HM_BUILD_ONLY=1)
harness "$root" run-wsl-distro.sh "$O"
check "D02 distro build-only: exit 0, no host reached, the binary's hash and the pinned image recorded" \
    bash -c '[ "$1" = 0 ] && ! grep -q "^ssh \|^wsl " "$2" && grep -q "^heimdall (Linux, for the disposable distribution) sha256: [0-9a-f]\{64\}$" "$3" && grep -q "^pinned image: https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl sha256 " "$3"' _ "$rc" "$L" "$O/build.txt"

# No image given: blocked on the pinned image, nothing imported.
new_world distro-noimage
extra_env=(HM_ST_CONTROLLER=OwnerDistroSelftest)
printf 'OwnerDistroSelftest\n' >"$S/wsl/registry"
harness "$root" run-wsl-distro.sh "$O"
check "D03 distro: no pinned image -> exit 3 (blocked), the input named, nothing imported or unregistered" \
    bash -c '[ "$1" = 3 ] && grep -q "^blocked=the pinned image" "$2" && ! grep -qE "^wsl (--import|--unregister)" "$3"' _ "$rc" "$O/host.txt" "$L"
check "D04 distro: the owner's registered distribution is untouched and the run directories are removed" \
    bash -c '[ "$(cat "$1")" = OwnerDistroSelftest ] && [ -z "$(ls -A "$2/hm-m00")" ] && [ -z "$(ls -A "$3/localappdata/hm-m00")" ]' _ "$S/wsl/registry" "$H" "$W"

# A file that is not the pinned image.
new_world distro-wrongimage
printf 'not the pinned image\n' >"$S/image.bin"
extra_env=(HM_WSL_ROOTFS="$W/localappdata/not-the-pinned-image.wsl")
cp "$S/image.bin" "$W/localappdata/not-the-pinned-image.wsl"
harness "$root" run-wsl-distro.sh "$O"
check "D05 distro: an image with another digest -> exit 3, nothing imported" \
    bash -c '[ "$1" = 3 ] && grep -q "^rootfs-sha256=mismatch" "$2" && ! grep -qE "^wsl (--import|--unregister)" "$3" && [ ! -s "$4" ]' _ "$rc" "$O/host.txt" "$L" "$S/wsl/registry"
check "D06 distro: ...and a download is not attempted when an image path was given" bash -c '! grep -q "^curl" "$1"' _ "$L"

# The full flow, against a copy of the harness whose pin is the stub image's digest.
distro_world() {
    new_world "$1"
    make_fake_root "$S/repo"
    printf 'stub rootfs image\n' >"$S/image.bin"
    cp "$S/image.bin" "$W/localappdata/pinned.wsl"
    local sum
    sum=$(shasum -a 256 "$S/image.bin" | cut -d' ' -f1)
    sed -i.bak "s/^ROOTFS_SHA256=.*/ROOTFS_SHA256=$sum/" "$S/repo/tests/native/m02/run-wsl-distro.sh" && rm -f "$S/repo/tests/native/m02/run-wsl-distro.sh.bak"
    printf 'OwnerDistroSelftest\nOtherOwnerDistro\n' >"$S/wsl/registry"
    cp "$S/wsl/registry" "$S/registry.before"
    extra_env=(HM_WSL_ROOTFS='C:\localappdata\pinned.wsl' HM_ST_CONTROLLER=OwnerDistroSelftest)
}
distro_world distro-pass
harness "$S/repo" run-wsl-distro.sh "$O"
check "D10 distro: the full flow exits 0" is_zero "$rc"
check "D11 distro: the registered set is equal to the set before (the disposable one unregistered, no other touched)" \
    bash -c 'cmp -s "$1" "$2" && grep -q "^registered-set-equal-to-before=yes$" "$3" && grep -q "^distribution-registered-after=no$" "$3"' _ "$S/wsl/registry" "$S/registry.before" "$O/host.txt"
check "D12 distro: exactly one import, one unregister, by one name of the pattern hm-m02-<hex>; every -d targets that name" \
    bash -c 'l=$1; [ "$(grep -c "^wsl --import " "$l")" = 1 ] && [ "$(grep -c "^wsl --unregister " "$l")" = 1 ] &&
        n=$(sed -n "s/^wsl --import \([^ ]*\) .*/\1/p" "$l") && case "$n" in hm-m02-[0-9a-f]*) ;; *) exit 1 ;; esac &&
        [ "$(grep "^wsl --unregister " "$l" | sed "s/^wsl --unregister //")" = "$n" ] &&
        ! grep "^wsl -d " "$l" | grep -qv "^wsl -d $n " && ! grep "^wsl --terminate " "$l" | grep -qv "^wsl --terminate $n$"' _ "$L"
check "D13 distro: wsl --shutdown is never run, and no other distribution is named in any command" \
    bash -c '! grep -q -e "--shutdown" "$1" && ! grep -q "OwnerDistroSelftest\|OtherOwnerDistro" "$1"' _ "$L"
check "D14 distro: the order is import, systemd off + terminate, prepare, scenario, terminate, unregister" \
    bash -c 'l=$1; a=$(grep -n "^wsl --import " "$l" | cut -d: -f1); b=$(grep -n "target-root.sh" "$l" | head -1 | cut -d: -f1); c=$(grep -n "scenario-ordinary-ssh.sh" "$l" | cut -d: -f1); d=$(grep -n "^wsl --unregister " "$l" | cut -d: -f1); [ "$a" -lt "$b" ] && [ "$b" -lt "$c" ] && [ "$c" -lt "$d" ]' _ "$L"
check "D15 distro: the scenario ran as the non-root user and root only for the root-side phases" \
    bash -c 'l=$1; grep "scenario-ordinary-ssh.sh" "$l" | grep -q -- "-u hmtest " && grep "target-root.sh" "$l" | grep -q -- "-u root "' _ "$L"
check "D16 distro: the scenario's step lines are the test lines of ### wsl_ordinary_ssh" \
    bash -c 't=$1; grep -q "^### wsl_ordinary_ssh$" "$t" && [ "$(grep -c "^test .* \.\.\. ok$" "$t")" = 10 ] && grep -q "^### wsl_ordinary_ssh exit=0$" "$t"' _ "$O/tests.txt"
check "D29 distro: the scenario's facts join host.txt as key=value lines (versions and exchange support for the records)" \
    bash -c 'h=$1; grep -q "^ssh-V=OpenSSH_9.9p9 (exit 0)$" "$h" && grep -q "^rename-exchange=supported (selftest)$" "$h"' _ "$O/host.txt"
check "D17 distro: the run directories on both sides and the distribution directory are removed" \
    bash -c '[ -z "$(ls -A "$1/hm-m00")" ] && [ -z "$(ls -A "$2/localappdata/hm-m00")" ] && grep -q "^exit 0: remote: unregister a distribution left by an interrupted run (if any), remove exactly the run directories, check they are absent" "$3"' _ "$H" "$W" "$O/commands.txt"
check "D18 distro: the controller distribution's name, the user, host and home are absent from every artifact" \
    none_of "$O" "OwnerDistroSelftest" "OtherOwnerDistro" "$H" "wslfixturehost" "FIXTUREHOST" "fixtureuser" "$REAL_USER"
check "D19 distro: the listener count after the scenario is recorded and nothing but loopback listened" \
    grep_q "listeners-other=0" "$O/host.txt"
check "D20 distro: no elevation, no sudo, no ssh-agent state from the controller side" log_lacks '^(sudo|doas|su|ssh-agent|ssh-add) '

distro_world distro-scenario-fails
extra_env+=(HM_ST_SCENARIO_FAIL=a01_ordinary_scp_without_f)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D21 distro: a failing scenario step -> nonzero exit, a FAILED line, and the distribution is still unregistered" \
    bash -c '[ "$1" != 0 ] && grep -q "^test a01_ordinary_scp_without_f \.\.\. FAILED$" "$2" && cmp -s "$3" "$4"' _ "$rc" "$O/tests.txt" "$S/wsl/registry" "$S/registry.before"

distro_world distro-missing-tools
extra_env+=(HM_ST_MISSING="sshd git")
harness "$S/repo" run-wsl-distro.sh "$O"
check "D22 distro: missing tools without HM_WSL_ALLOW_APT -> the failure is the run's, the distribution is unregistered, the scenario never ran" \
    bash -c '[ "$1" != 0 ] && grep -q "^prepare-exit=3$" "$2" && ! grep -q "scenario-ordinary-ssh.sh" "$3" && cmp -s "$4" "$5"' _ "$rc" "$O/host.txt" "$L" "$S/wsl/registry" "$S/registry.before"
distro_world distro-allow-apt
extra_env+=(HM_ST_MISSING="sshd git" HM_WSL_ALLOW_APT=1)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D23 distro: HM_WSL_ALLOW_APT=1 is handed to the in-distribution preparation (and only there)" \
    bash -c '[ "$1" = 0 ] && grep "target-root.sh" "$2" | grep -q " prepare hmtest 1 "' _ "$rc" "$L"

distro_world distro-download
extra_env=(HM_WSL_DOWNLOAD=1 HM_ST_CONTROLLER=OwnerDistroSelftest)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D24 distro: HM_WSL_DOWNLOAD=1 downloads over https (TLS 1.2+) into the run directory, and the digest is still checked" \
    bash -c '[ "$1" = 0 ] && grep "^curl " "$2" | grep -q -e "--proto =https" && grep "^curl " "$2" | grep -q -e "--tlsv1.2" && grep -q "^rootfs-sha256=matches the pin$" "$3" && grep -q "^rootfs-source=download over https$" "$3"' _ "$rc" "$L" "$O/host.txt"

# An interrupted run: the first unregister fails; the EXIT trap retries it.
distro_world distro-interrupted
extra_env+=(HM_ST_UNREGISTER_FAIL=once)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D25 distro: an unregister that failed is retried by the EXIT trap; the registered set ends equal to the one before" \
    bash -c '[ "$1" != 0 ] && [ "$(grep -c "^wsl --unregister " "$2")" = 2 ] && cmp -s "$3" "$4" && grep -q "^cleanup unregister-exit=0$" "$5"' _ "$rc" "$L" "$S/wsl/registry" "$S/registry.before" "$O/commands.txt"
check "D26 distro: the directories are removed after the retry" \
    bash -c '[ -z "$(ls -A "$1/hm-m00")" ] && [ -z "$(ls -A "$2/localappdata/hm-m00")" ]' _ "$H" "$W"

# A distribution already registered under the run's name is never imported over or touched.
distro_world distro-same-name
printf '#!/usr/bin/env bash\nfor a in "$@"; do [ "$a" = -N6 ] && { echo " aa bb cc dd ee ff"; exit 0; }; done\nexec /usr/bin/od "$@"\n' >"$B/od"
chmod +x "$B/od"
printf 'OwnerDistroSelftest\nhm-m02-aabbccddeeff\n' >"$S/wsl/registry"
cp "$S/wsl/registry" "$S/registry.before"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D27 distro: a distribution with the run's own name already registered -> the run refuses, imports nothing, unregisters nothing, leaves it registered" \
    bash -c 'grep -q "^import=refused" "$1" && [ "$2" != 0 ] && ! grep -qE "^wsl (--import|--unregister|--terminate)" "$3" && cmp -s "$4" "$5"' _ "$O/host.txt" "$rc" "$L" "$S/wsl/registry" "$S/registry.before"

distro_world distro-badrootfs
extra_env=(HM_WSL_ROOTFS='C:\x"; rm -rf /; echo "')
harness "$S/repo" run-wsl-distro.sh "$O"
check "D28 distro: an image path with shell metacharacters is refused with exit 2 before anything runs" bash -c '[ "$1" = 2 ] && [ ! -s "$2" ]' _ "$rc" "$L"

# --- local mode (HM_LOCAL=1; ADR-0007 §12.32 item 15) ------------------------------------------

# HM_BUILD_ONLY=1 on the build host prints the binary's path and digest for the orchestrator.
new_world distro-build-only-prints
extra_env=(HM_BUILD_ONLY=1)
harness "$root" run-wsl-distro.sh "$O"
D_BIN=$(sed -n 's/^prebuilt-heimdall=//p' "$S/harness.log" | head -1)
D_SUM=$(sed -n 's/^prebuilt-sha256=//p' "$S/harness.log" | head -1)
check "D30 distro build-only: stdout has prebuilt-heimdall=<path> and prebuilt-sha256=<hex> (the file's own digest, the one in build.txt)" \
    bash -c '[ "$1" = 0 ] && [ -f "$2" ] && [ "${#3}" = 64 ] && [ "$(shasum -a 256 "$2" | cut -d" " -f1)" = "$3" ] && grep -q "^heimdall (Linux, for the disposable distribution) sha256: $3$" "$4" && [ "$(grep -c "^prebuilt-" "$5")" = 2 ]' _ "$rc" "$D_BIN" "$D_SUM" "$O/build.txt" "$S/harness.log"
check "D31 distro build-only: ...and the printed lines are not saved in any artifact" no_grep "prebuilt-" "$O/build.txt"

# local_distro_world NAME: the full-flow world as the local agent on the PC sees it: HM_LOCAL=1, no
# HM_SSH_CONFIG or HM_HOST in the environment, a Linux heimdall binary copied from the build host
# ($PB, digest $PBSUM; added to extra_env by each case), and bash, tar and scp stubs that log. A
# `bash -s` reads the script with the fake Windows tree for /mnt/c (the ssh stub does the same);
# every other bash call runs the real one.
local_distro_world() {
    distro_world "$1"
    local_world=1
    mkdir "$S/prebuilt"
    PB="$S/prebuilt/heimdall"
    printf '#!/bin/sh\necho "heimdall prebuilt (selftest)"\n' >"$PB"
    PBSUM=$(shasum -a 256 "$PB" | cut -d' ' -f1)
    cat >"$B/bash" <<'EOF'
#!/bin/bash
if [ "${1:-}" = -s ]; then
    sed "s#/mnt/c#$HM_ST_WINROOT#g; s#/etc/os-release#$HM_ST_OSRELEASE#g" | "$HM_ST_REALBASH" "$@"
    exit $?
fi
exec "$HM_ST_REALBASH" "$@"
EOF
    printf '#!/usr/bin/env bash\necho "tar $*" >>"$HM_ST_LOG"\nexec "$HM_ST_REALTAR" "$@"\n' >"$B/tar"
    printf '#!/usr/bin/env bash\necho "scp $*" >>"$HM_ST_LOG"\nexit 1\n' >"$B/scp"
    chmod +x "$B/bash" "$B/tar" "$B/scp"
    # The controller's name is the harness process's own WSL_DISTRO_NAME in local mode (the extra_env
    # entry follows the harness' own and wins); a case names another controller by appending its own.
    extra_env+=(WSL_DISTRO_NAME=OwnerDistroSelftest HM_LOCAL=1 HM_ST_REALBASH="$(command -v bash)" HM_ST_REALTAR="$(command -v tar)")
}
# nothing_created: a refused local run created no artifact directory, no temporary directory, no run
# directory, called no tool, and left the registered set as it was.
nothing_created() {
    [ ! -e "$O" ] && [ ! -e "$H/hm-m00" ] && [ ! -e "$W/localappdata/hm-m00" ] && [ -z "$(ls -A "$S/tmp")" ] &&
        [ ! -s "$L" ] && cmp -s "$S/wsl/registry" "$S/registry.before"
}

local_distro_world distro-local-pass
extra_env+=(HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="$PBSUM" HM_ST_DISTRO_LEAK=1)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D32 distro local: the full flow exits 0 with neither HM_SSH_CONFIG nor HM_HOST set" is_zero "$rc"
check "D33 distro local: no ssh, no scp and no tar stream to a host; the tar is a local extraction into the run directory; nothing is built" \
    bash -c 'l=$1; ! grep -qE "^(ssh|scp|cargo|go|rustc|zig) " "$l" && ! grep -q "^tar -xzf" "$l" && [ "$(grep -c "^tar -xf - -C $2/hm-m00/" "$l")" = 1 ]' _ "$L" "$H"
check "D34 distro local: one import and one unregister, both of this run's hm-m02-<hex>, every -d and --terminate targets it, no --shutdown, no other distribution named" \
    bash -c 'l=$1; [ "$(grep -c "^wsl --import " "$l")" = 1 ] && [ "$(grep -c "^wsl --unregister " "$l")" = 1 ] &&
        n=$(sed -n "s/^wsl --import \([^ ]*\) .*/\1/p" "$l") && case "$n" in hm-m02-[0-9a-f]*) ;; *) exit 1 ;; esac &&
        [ "$(grep "^wsl --unregister " "$l" | sed "s/^wsl --unregister //")" = "$n" ] &&
        ! grep "^wsl -d " "$l" | grep -qv "^wsl -d $n " && ! grep "^wsl --terminate " "$l" | grep -qv "^wsl --terminate $n$" &&
        ! grep -q -e "--shutdown" "$l" && ! grep -q "OwnerDistroSelftest\|OtherOwnerDistro" "$l"' _ "$L"
check "D35 distro local: the order is import, prepare, scenario (as the non-root user), terminate, unregister; the registered set equals the one before" \
    bash -c 'l=$1; a=$(grep -n "^wsl --import " "$l" | cut -d: -f1); b=$(grep -n "target-root.sh" "$l" | head -1 | cut -d: -f1); c=$(grep -n "scenario-ordinary-ssh.sh" "$l" | cut -d: -f1); d=$(grep -n "^wsl --unregister " "$l" | cut -d: -f1);
        [ "$a" -lt "$b" ] && [ "$b" -lt "$c" ] && [ "$c" -lt "$d" ] && grep "scenario-ordinary-ssh.sh" "$l" | grep -q -- "-u hmtest " &&
        cmp -s "$2" "$3" && grep -q "^registered-set-equal-to-before=yes$" "$4" && grep -q "^distribution-registered-after=no$" "$4" &&
        [ "$(grep -c "^test .* \.\.\. ok$" "$5")" = 10 ]' _ "$L" "$S/wsl/registry" "$S/registry.before" "$O/host.txt" "$O/tests.txt"
check "D36 distro local: the run directories and the distribution directory are removed, recorded with exit 0" \
    bash -c '[ -z "$(ls -A "$1/hm-m00")" ] && [ -z "$(ls -A "$2/localappdata/hm-m00")" ] && grep -q "^exit 0: remote: unregister a distribution left by an interrupted run (if any), remove exactly the run directories, check they are absent" "$3"' _ "$H" "$W" "$O/commands.txt"
check "D37 distro local: build.txt carries the verified sha256 in the build path's line format; commands.txt has mode=local and the prebuilt check as its own exit line" \
    bash -c 'grep -qx "heimdall (Linux, for the disposable distribution) sha256: $1" "$2" && grep -q "^pinned image: " "$2" && grep -qx "mode=local" "$3" && grep -q "^exit 0: prebuilt heimdall sha256 equals HM_PREBUILT_SHA256 recorded by the build host ($1)$" "$3" && grep -q "^exit 0: local tar extraction of heimdall and the scenario files into WSL scratch$" "$3"' _ "$PBSUM" "$O/build.txt" "$O/commands.txt"
check "D38 distro local: host.txt says mode=local (run inside the WSL controller by an agent on the PC; ADR-0007 §12.32 item 15) and keeps the other facts" \
    bash -c 'h=$1; [ "$(head -1 "$h")" = "mode=local (run inside the WSL controller by an agent on the PC; ADR-0007 §12.32 item 15)" ] && grep -q "^wsl-version=" "$h" && grep -q "^distributions-before=2$" "$h" && grep -q "^rootfs-sha256=matches the pin$" "$h" && grep -q "^listeners-other=0$" "$h" && grep -q "^ssh-V=OpenSSH_9.9p9 (exit 0)$" "$h"' _ "$O/host.txt"
check "D39 distro local: the local WSL user, host and home and the Windows user, host and home are redacted as on the ssh path" \
    bash -c 'grep -qx "observation leak home=<wslhome> user=<wsluser> host=<wslhost> winuser=<winuser> winhost=<winhost> winhome=<winhome>" "$1"' _ "$O/tests.txt"
check "D40 distro local: ...none of them nor the controller distribution is in any artifact; the canary and leak scans ran and passed" \
    bash -c '! grep -q "OwnerDistroSelftest\|OtherOwnerDistro" "$1" && grep -q "^exit 0: canary-prefix scan" "$2" && grep -q "^exit 0: leak scan" "$2"' _ "$L" "$O/commands.txt"
check "D41 distro local: ...and no saved file holds the WSL or Windows user, host or home" \
    none_of "$O" "OwnerDistroSelftest" "OtherOwnerDistro" "$H" "wslfixturehost" "FIXTUREHOST" "fixtureuser" "$REAL_USER"
check "D42 distro local: no elevation, no sudo, no ssh-agent state" log_lacks '^(sudo|doas|su|ssh-agent|ssh-add) '

# Refusals happen before anything is created.
base_env=()
local_distro_world distro-local-no-binary
extra_env+=(HM_PREBUILT_SHA256="$PBSUM")
harness "$S/repo" run-wsl-distro.sh "$O"
check "D43 distro local: no HM_PREBUILT_HEIMDALL -> exit 3" is_n "$rc" 3
check "D44 distro local: ...and nothing is created, no tool called" nothing_created
local_distro_world distro-local-no-digest
extra_env+=(HM_PREBUILT_HEIMDALL="$PB")
harness "$S/repo" run-wsl-distro.sh "$O"
check "D45 distro local: no HM_PREBUILT_SHA256 -> exit 3" is_n "$rc" 3
check "D46 distro local: ...and nothing is created, no tool called" nothing_created
local_distro_world distro-local-not-a-file
base_env=("${extra_env[@]}")
extra_env=("${base_env[@]}" HM_PREBUILT_HEIMDALL="$S/prebuilt" HM_PREBUILT_SHA256="$PBSUM")
harness "$S/repo" run-wsl-distro.sh "$O"
rc_dir=$rc
extra_env=("${base_env[@]}" HM_PREBUILT_HEIMDALL="$S/prebuilt/absent" HM_PREBUILT_SHA256="$PBSUM")
harness "$S/repo" run-wsl-distro.sh "$O"
check "D47 distro local: a directory, or a file that is not there -> exit 3" bash -c '[ "$1" = 3 ] && [ "$2" = 3 ]' _ "$rc_dir" "$rc"
check "D48 distro local: ...and nothing is created, no tool called" nothing_created
local_distro_world distro-local-wrong-digest
base_env=("${extra_env[@]}")
extra_env=("${base_env[@]}" HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="$(printf '%064d' 7)")
harness "$S/repo" run-wsl-distro.sh "$O"
check "D49 distro local: a digest that differs from the file's -> exit 1, the file's digest named on stderr" \
    bash -c '[ "$1" = 1 ] && grep -q "sha256 mismatch" "$2" && grep -q "$3" "$2"' _ "$rc" "$S/harness.log" "$PBSUM"
check "D50 distro local: ...and nothing is created or imported" nothing_created
extra_env=("${base_env[@]}" HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="not-a-digest")
harness "$S/repo" run-wsl-distro.sh "$O"
check "D51 distro local: a digest that is not 64 hex digits -> exit 2" is_n "$rc" 2
check "D52 distro local: ...and nothing is created" nothing_created
extra_env=("${base_env[@]}" HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="$PBSUM" HM_BUILD_ONLY=1)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D53 distro local: HM_LOCAL=1 with HM_BUILD_ONLY=1 builds nothing -> exit 2" is_n "$rc" 2
check "D54 distro local: ...and nothing is created" nothing_created

# Cleanup in local mode: a failing scenario step, and an unregister that failed (the EXIT trap).
local_distro_world distro-local-scenario-fails
extra_env+=(HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="$PBSUM" HM_ST_SCENARIO_FAIL=a01_ordinary_scp_without_f)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D55 distro local: a failing scenario step -> nonzero exit, a FAILED line, the distribution unregistered, the directories removed" \
    bash -c '[ "$1" != 0 ] && grep -q "^test a01_ordinary_scp_without_f \.\.\. FAILED$" "$2" && cmp -s "$3" "$4" && [ -z "$(ls -A "$5/hm-m00")" ] && [ -z "$(ls -A "$6/localappdata/hm-m00")" ]' _ "$rc" "$O/tests.txt" "$S/wsl/registry" "$S/registry.before" "$H" "$W"
local_distro_world distro-local-interrupted
extra_env+=(HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="$PBSUM" HM_ST_UNREGISTER_FAIL=once)
harness "$S/repo" run-wsl-distro.sh "$O"
check "D56 distro local: an unregister that failed is retried by the EXIT trap, locally; the set ends equal, the directories are removed, no ssh" \
    bash -c '[ "$1" != 0 ] && [ "$(grep -c "^wsl --unregister " "$2")" = 2 ] && cmp -s "$3" "$4" && grep -q "^cleanup unregister-exit=0$" "$5" && [ -z "$(ls -A "$6/hm-m00")" ] && [ -z "$(ls -A "$7/localappdata/hm-m00")" ] && ! grep -qE "^(ssh|scp) " "$2"' _ "$rc" "$L" "$S/wsl/registry" "$S/registry.before" "$O/commands.txt" "$H" "$W"

# --- the controller distribution's name (ADR-0007 §12.44 item 1) -------------------------------

# controller_world NAME CONTROLLER LINE [local]: the full-flow world (ssh path, or local mode with a
# 4th argument) whose controller distribution is CONTROLLER, with an Ubuntu 24.04 os-release (NAME
# "Ubuntu", ID ubuntu, VERSION_ID "24.04") and LINE as one scenario observation line.
controller_world() {
    if [ "${4:-}" = local ]; then
        local_distro_world "$1"
        extra_env+=(HM_PREBUILT_HEIMDALL="$PB" HM_PREBUILT_SHA256="$PBSUM")
    else
        distro_world "$1"
    fi
    printf 'PRETTY_NAME="Ubuntu 24.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n' >"$S/os-release"
    extra_env+=(HM_ST_CONTROLLER="$2" WSL_DISTRO_NAME="$2" HM_ST_SCEN_LINE="$3")
}
# default_name_ok: the checks every default-name run shares (D57..).
default_name_ok() {
    [ "$1" = 0 ] && [ "$(grep -c "^controller-distro-name=" "$2")" = 1 ] && grep -qx "controller-distro-name=default (os-release)" "$2" &&
        grep -qx "observation client OpenSSH_9.6p1 Ubuntu-3ubuntu13.20" "$3" && grep -q "^os=Ubuntu 24.04.5 LTS" "$2" &&
        grep -q "releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl" "$4" && ! grep -rq "owner-distro" "$5" &&
        grep -q "^exit 0: leak scan" "$6" && grep -q "^exit 0: canary-prefix scan" "$6"
}
local_default_name_ok() { head -1 "$2" | grep -q "^mode=local " && default_name_ok "$@"; }
VERSION_LINE="client OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"

controller_world distro-name-default Ubuntu "$VERSION_LINE"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D57 distro name: a default name (os-release NAME, Ubuntu) is kept: host.txt says default (os-release), a version line stays intact, the leak scan passes with the pinned URL in build.txt, exit 0" \
    default_name_ok "$rc" "$O/host.txt" "$O/tests.txt" "$O/build.txt" "$O" "$O/commands.txt"
check "D58 distro name: ...the controller's name itself is in no host.txt line, and every registered distribution is untouched" \
    bash -c '! grep -qi "^wsldistro" "$1" && cmp -s "$2" "$3"' _ "$O/host.txt" "$S/wsl/registry" "$S/registry.before"

controller_world distro-name-default-nv UBUNTU-24.04 "$VERSION_LINE"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D59 distro name: NAME-VERSION_ID (UBUNTU-24.04, case-insensitively) is also a default name, with the same outcome" \
    default_name_ok "$rc" "$O/host.txt" "$O/tests.txt" "$O/build.txt" "$O" "$O/commands.txt"

controller_world distro-name-default-id ubuntu "$VERSION_LINE"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D60 distro name: os-release ID (ubuntu) is a default name too" \
    default_name_ok "$rc" "$O/host.txt" "$O/tests.txt" "$O/build.txt" "$O" "$O/commands.txt"

controller_world distro-name-default-local Ubuntu "$VERSION_LINE" local
harness "$S/repo" run-wsl-distro.sh "$O"
check "D61 distro name local: the same decision in local mode (default name kept, host.txt says default (os-release), mode=local still first, exit 0)" \
    local_default_name_ok "$rc" "$O/host.txt" "$O/tests.txt" "$O/build.txt" "$O" "$O/commands.txt"

controller_world distro-name-owner ownerbox "name=ownerbox again OWNERBOX"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D62 distro name: an owner-chosen name is redacted wherever it is a whole word in a saved file, and host.txt says owner-chosen (redacted)" \
    bash -c '[ "$1" = 0 ] && grep -qx "controller-distro-name=owner-chosen (redacted)" "$2" && [ "$(grep -c "^controller-distro-name=" "$2")" = 1 ] &&
        grep -qx "observation name=<owner-distro> again <owner-distro>" "$3"' _ "$rc" "$O/host.txt" "$O/tests.txt"
check "D63 distro name: ...the name is absent from every artifact and from the call log, and the leak scan ran and passed" \
    bash -c 'none=1; for f in $(find "$1" -type f); do grep -qi ownerbox "$f" && none=0; done; [ "$none" = 1 ] && ! grep -qi ownerbox "$2" && grep -q "^exit 0: leak scan" "$3"' _ "$O" "$L" "$O/commands.txt"
D_OWNER_OUT="$O"
D_SCAN_DIR="$S/leakcopy"
cp -R "$O" "$D_SCAN_DIR"
printf 'a stray line naming ownerbox\n' >>"$D_SCAN_DIR/tests.txt"
check "D64 distro name: the leak scan finds an owner-chosen name still in an artifact (count 1, exit 1), and passes the redacted set (count 0, exit 0)" \
    bash -c '. "$1"; n=$(m02_leak_scan "$2" --word ownerbox); a=$?; m=$(m02_leak_scan "$3" --word ownerbox); b=$?; [ "$n" = 1 ] && [ "$a" = 1 ] && [ "$m" = 0 ] && [ "$b" = 0 ]' _ "$m02/lib.sh" "$D_SCAN_DIR" "$D_OWNER_OUT"
check "D65 distro name: ...and the harness scans the name as a whole word (a longer word holding it is not a leak)" \
    bash -c '. "$1"; d=$2; printf "myownerbox ownerboxes toolbox\n" >"$d/tests.txt"; n=$(m02_leak_scan "$d" --word ownerbox); a=$?; [ "$n" = 0 ] && [ "$a" = 0 ] && grep -q -- "--word \"\$wsldistro\"" "$3"' _ "$m02/lib.sh" "$D_SCAN_DIR" "$m02/run-wsl-distro.sh"

controller_world distro-name-wholeword box "a=box b=toolbox c=Box. d=boxes e=my_box f=sandbox"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D66 distro name: an owner-chosen name inside another word (box in toolbox) is not redacted there; the standalone name is, and the run exits 0" \
    bash -c '[ "$1" = 0 ] && grep -qx "observation a=<owner-distro> b=toolbox c=<owner-distro>. d=boxes e=my_box f=sandbox" "$2" && grep -qx "controller-distro-name=owner-chosen (redacted)" "$3"' _ "$rc" "$O/tests.txt" "$O/host.txt"

controller_world distro-name-owner-near Ubuntu-22.04 "name=Ubuntu-22.04"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D67 distro name: a name that is no os-release form (Ubuntu-22.04 on a 24.04 controller) is owner-chosen and redacted" \
    bash -c '[ "$1" = 0 ] && grep -qx "controller-distro-name=owner-chosen (redacted)" "$2" && grep -qx "observation name=<owner-distro>" "$3" && ! grep -rqi "ubuntu-22.04" "$4"' _ "$rc" "$O/host.txt" "$O/tests.txt" "$O"

controller_world distro-name-no-osrelease Ubuntu "$VERSION_LINE"
rm -f "$S/os-release"
harness "$S/repo" run-wsl-distro.sh "$O"
check "D68 distro name: with no readable os-release the name is never taken as default: it is owner-chosen and redacted (so the version line is rewritten) and the leak scan, which now sees the public image URL, fails the run closed" \
    bash -c '[ "$1" != 0 ] && grep -qx "controller-distro-name=owner-chosen (redacted)" "$2" && grep -qx "observation client OpenSSH_9.6p1 <owner-distro>-3ubuntu13.20" "$3" && grep -q "^exit 1: leak scan" "$4"' _ "$rc" "$O/host.txt" "$O/tests.txt" "$O/commands.txt"

controller_world distro-name-owner-local ownerbox "name=ownerbox again OWNERBOX" local
harness "$S/repo" run-wsl-distro.sh "$O"
check "D69 distro name local: an owner-chosen name is redacted as a whole word in local mode too, recorded owner-chosen, absent from every artifact, exit 0" \
    bash -c '[ "$1" = 0 ] && grep -qx "controller-distro-name=owner-chosen (redacted)" "$2" && grep -qx "observation name=<owner-distro> again <owner-distro>" "$3" && ! grep -rqi ownerbox "$4"' _ "$rc" "$O/host.txt" "$O/tests.txt" "$O"

# =============================================================================================
# T: target-root.sh refusals (it needs root inside the disposable distribution)
# =============================================================================================

check "T01 target-root: refuses outside the named distribution (WSL_DISTRO_NAME differs), exit 2" \
    bash -c 'out=$(WSL_DISTRO_NAME=other bash "$1" hm-m02-x no-systemd 2>&1 >/dev/null); rc=$?; [ "$rc" = 2 ] && case "$out" in *"not inside the disposable distribution"*) true ;; *) false ;; esac' _ "$m02/target-root.sh"
if [ "$(id -u)" != 0 ]; then
    check "T02 target-root: refuses to run without root even inside the named distribution, exit 2" \
        bash -c 'out=$(WSL_DISTRO_NAME=hm-m02-x bash "$1" hm-m02-x no-systemd 2>&1 >/dev/null); rc=$?; [ "$rc" = 2 ] && case "$out" in *"needs root"*) true ;; *) false ;; esac' _ "$m02/target-root.sh"
else
    skip "T02 target-root: root refusal (the self-test is running as root)"
fi
check "T03 target-root: a missing phase is a usage error and nothing is written" \
    bash -c 'WSL_DISTRO_NAME=x bash "$1" x >/dev/null 2>&1; [ $? -ne 0 ]' _ "$m02/target-root.sh"
check "T04 target-root: services are blocked before any install (policy-rc.d 101, ssh.service and ssh.socket masked)" \
    bash -c 'f=$1; l1=$(grep -n "usr/sbin/policy-rc.d" "$f" | head -1 | cut -d: -f1); l2=$(grep -n "apt-get -q update" "$f" | head -1 | cut -d: -f1); [ "$l1" -lt "$l2" ] && grep -q "exit 101" "$f" && grep -q "ssh.service" "$f" && grep -q "ssh.socket" "$f"' _ "$m02/target-root.sh"
check "T05 target-root: only the image's own archive is used (no add-apt-repository, no PPA, no curl)" \
    bash -c '! grep -qE "add-apt-repository|ppa:|curl|wget|pip install" "$1"' _ "$m02/target-root.sh"

# =============================================================================================
# S: scenario-ordinary-ssh.sh
# =============================================================================================

HM_BIN="$root/target/debug/heimdall"
scenario_ready=1
reason=""
if [ "${HM_SELFTEST_SCENARIO:-1}" = 0 ]; then
    scenario_ready=0
    reason="HM_SELFTEST_SCENARIO=0"
elif [ ! -x "$HM_BIN" ]; then
    scenario_ready=0
    reason="no debug heimdall at target/debug (cargo build -p heimdall)"
else
    for c in ssh ssh-agent ssh-keygen ssh-add sftp scp git python3; do
        command -v "$c" >/dev/null 2>&1 || { scenario_ready=0; reason="$c is missing"; }
    done
    command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || { scenario_ready=0; reason="sshd is missing"; }
    [ "$(id -u)" != 0 ] || { scenario_ready=0; reason="running as root"; }
fi

# The usage and fail-closed paths need no product binary.
new_world scn-usage
printf '#!/usr/bin/env bash\nexit 1\n' >"$X/heimdall-fails"
chmod +x "$X/heimdall-fails"
mkdir "$S/exists"
bash "$m02/scenario-ordinary-ssh.sh" "$S/exists" "$X/heimdall-fails" >"$S/scn.out" 2>"$S/scn.err" </dev/null
rc=$?
check "S01 scenario: an existing scratch directory is refused with exit 2 and left as it was" \
    bash -c '[ "$1" = 2 ] && [ -z "$(ls -A "$2")" ]' _ "$rc" "$S/exists"
bash "$m02/scenario-ordinary-ssh.sh" >"$S/scn.out" 2>"$S/scn.err" </dev/null
check "S02 scenario: missing arguments are a usage error" is_nonzero "$?"
long_dir="$S/$(printf 'x%.0s' $(seq 1 70))"
bash "$m02/scenario-ordinary-ssh.sh" "$long_dir" "$X/heimdall-fails" >"$S/scn.out" 2>"$S/scn.err" </dev/null
check "S03 scenario: a scratch path too long for Unix sockets is refused with exit 2, naming the reason, creating nothing" \
    bash -c '[ "$1" = 2 ] && grep -q "too long for Unix socket paths" "$2" && [ ! -e "$3" ]' _ "$?" "$S/scn.err" "$long_dir"

if [ "$scenario_ready" = 1 ]; then
    SCN_BASE=$(mktemp -d /tmp/hm-m02-st.XXXXXX)
    scn_run() {
        # scn_run NAME BINARY: the scenario in isolated mode; sets scn_rc and $SC (output file).
        local d="$SCN_BASE/$1"
        mkdir "$d"
        SC="$d/out.txt"
        HM_SCENARIO_ISOLATED=1 bash "$m02/scenario-ordinary-ssh.sh" "$d/s" "$2" >"$SC" 2>"$d/err.txt" </dev/null &
        local pid=$!
        # A watchdog for this one process (TERM runs the scenario's own cleanup trap).
        ( sleep 300; kill "$pid" 2>/dev/null ) &
        local wd=$!
        wait "$pid"
        scn_rc=$?
        kill "$wd" 2>/dev/null
        wait "$wd" 2>/dev/null
        SCD=$d
        if [ "${HM_SELFTEST_VERBOSE:-0}" = 1 ]; then
            echo "--- scenario ($1) exit $scn_rc"
            cat "$SC"
        fi
    }
    # A product binary that never applies the projection: `setup apply` reports success and
    # does nothing, everything else is the real binary.
    printf '#!/usr/bin/env bash\ncase " $* " in *" setup apply "*) echo "{\\"code\\":\\"OK\\"}"; exit 0 ;; esac\nexec "%s" "$@"\n' "$HM_BIN" >"$T/heimdall-no-apply"
    chmod +x "$T/heimdall-no-apply"

    # ADR-0007 §12.33 item 2 (P02): a foreign XDG Git configuration whose template and
    # hooksPath hooks would leave a marker; the scenario must neither read nor run it.
    fx="$T/foreign-xdg"
    mkdir -p "$fx/git" "$fx/tpl/hooks" "$fx/hooks"
    printf '#!/bin/sh\n: >"%s"\n' "$fx/hook-ran" >"$fx/tpl/hooks/post-commit"
    cp "$fx/tpl/hooks/post-commit" "$fx/hooks/post-commit"
    chmod +x "$fx/tpl/hooks/post-commit" "$fx/hooks/post-commit"
    printf '[init]\n\ttemplateDir = %s\n[core]\n\thooksPath = %s\n[heimdall]\n\tforeignprobe = read\n' "$fx/tpl" "$fx/hooks" >"$fx/git/config"
    XDG_CONFIG_HOME="$fx" scn_run pass "$HM_BIN"
    check "S17 scenario (ADR-0007 §12.33 P02): an inherited XDG Git configuration is never read and its hooks never run" \
        bash -c '[ ! -e "$1/hook-ran" ]' _ "$fx"
    check "S10 scenario (isolated, real heimdall): exits 0 and ends with its exit line" \
        bash -c '[ "$1" = 0 ] && grep -q "^### wsl_ordinary_ssh exit=0$" "$2"' _ "$scn_rc" "$SC"
    steps=$(python3 -I - "$m02/case-index.json" <<'PY'
import json, sys
print(" ".join(sorted(json.load(open(sys.argv[1], encoding="utf-8"))["scenario_targets"]["wsl_ordinary_ssh"]["steps"])))
PY
)
    ok_steps=$(sed -n 's/^test \(.*\) \.\.\. ok$/\1/p' "$SC" | sort | tr '\n' ' ' | sed 's/ $//')
    check "S11 scenario: the steps that passed are exactly the case index's ten" bash -c '[ "$1" = "$2" ]' _ "$ok_steps" "$steps"
    check "S12 scenario: no step failed and no precondition stopped it" bash -c '! grep -q "FAILED" "$1" && ! grep -q "^setup .* exit=[1-9]" "$1"' _ "$SC"
    check "S13 scenario: the user's configuration bytes after uninstall equal the original, and apply changed them" \
        bash -c 'a=$(sed -n "s/^fact user-config-sha256-before=//p" "$1"); b=$(sed -n "s/^fact user-config-sha256-after-apply=//p" "$1"); c=$(sed -n "s/^fact user-config-sha256-after-uninstall=//p" "$1"); [ -n "$a" ] && [ "$a" != "$b" ] && [ "$a" = "$c" ]' _ "$SC"
    check "S14 scenario: the fixture sshd accepted logins and only the adopted key" \
        bash -c 'n=$(sed -n "s/^fact sshd-accepted-logins=//p" "$1"); [ "$n" -ge 4 ]' _ "$SC"
    check "S15 scenario: nothing but facts and step lines is printed: no home path, key material or environment value" \
        bash -c 'o=$1; ! grep -qE "BEGIN [A-Z ]*PRIVATE|AAAA[A-Za-z0-9+/]{20}|SSH_AUTH_SOCK=|/Users/|/home/" "$o" && ! grep -q "$2" "$o"' _ "$SC" "$HOME"
    check "S16 scenario: it left no process of its own (heimdall copy, agents, sshd) and its facts say so" \
        bash -c 'grep -q "^fact leftover-heimdall-processes=0$" "$1" && [ "$(pgrep -f "$2" | wc -l | tr -d " ")" = 0 ]' _ "$SC" "$SCD"

    scn_run sabotage "$T/heimdall-no-apply"
    check "S20 scenario (apply sabotaged): nonzero exit, the apply step FAILED" \
        bash -c '[ "$1" != 0 ] && grep -q "^test a01_setup_apply_writes_the_users_real_ssh_config \.\.\. FAILED$" "$2"' _ "$scn_rc" "$SC"
    check "S21 scenario (apply sabotaged): the default-identity guard refuses and every ordinary client step FAILED (no unmanaged identity is ever tried)" \
        bash -c 'o=$1; grep -q "^fact default-identity-guard=refused" "$o" && for s in a01_ordinary_ssh_alias_without_f a01_ordinary_git_without_f a01_ordinary_scp_without_f a01_ordinary_sftp_without_f; do grep -q "^test $s \.\.\. FAILED$" "$o" || exit 1; done' _ "$SC"
    check "S22 scenario (apply sabotaged): the sshd accepted no login at all" grep_q "fact sshd-accepted-logins=0" "$SC"
    check "S23 scenario (apply sabotaged): it still stopped everything it started" \
        bash -c 'grep -q "^fact leftover-heimdall-processes=0$" "$1" && [ "$(pgrep -f "$2" | wc -l | tr -d " ")" = 0 ]' _ "$SC" "$SCD"
else
    skip "S10-S23 scenario in isolated mode ($reason)"
fi

# =============================================================================================
# P: run-windows-local.ps1, the Windows local mode (ADR-0007 §12.32 items 15-17), and the
#    build-host import of its bundle (import-windows-bundle.py). No host: the runner's own
#    -SelfTest exercises its redaction, canary masking, results format and bundle writer on
#    synthetic data; its bundle is then imported as the agent's report would be.
# =============================================================================================

if command -v pwsh >/dev/null 2>&1; then
    ps1="$m02/run-windows-local.ps1"
    parse_ps1() {
        HM_ST_PS1="$1" pwsh -NoProfile -NonInteractive -Command \
            '$e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:HM_ST_PS1, [ref]$t, [ref]$e); if ($e.Count) { foreach ($x in $e) { "{0}: {1}" -f $x.Extent.StartLineNumber, $x.Message }; exit 1 }' \
            >"$T/ps-parse.txt" 2>&1
    }
    check "P01 local mode: run-windows-local.ps1 parses under PowerShell 7 with no error" parse_ps1 "$ps1"
    pwsh -NoProfile -NonInteractive -File "$ps1" -SelfTest -Out "$T/ps-bundle" >"$T/ps-selftest.txt" 2>&1
    ps_rc=$?
    check "P02 local mode: its -SelfTest passes (redaction of <winuser>/<winhost>/<winhome>/SIDs, canary masking, results, bundle)" \
        bash -c '[ "$1" = 0 ] && grep -q "^run-windows-local selftest: [1-9][0-9]* passed, 0 failed$" "$2" && ! grep -q "^FAIL" "$2"' _ "$ps_rc" "$T/ps-selftest.txt"
    python3 -I "$m02/import-windows-bundle.py" --bundle "$T/ps-bundle/bundle.b64" --label exit-selftest \
        --artifacts-root "$T/ps-imported" --commit 0000000000000000000000000000000000000000 >"$T/ps-import.txt" 2>&1
    imp_rc=$?
    check "P03 local mode: the bundle imports into <label>/windows/ as the files the generator reads, nothing unredacted left" \
        bash -c 'd=$2/exit-selftest/windows; [ "$1" = 0 ] && for f in tests.txt commands.txt host.txt build.txt skipped.txt canary-scan.txt; do [ -f "$d/$f" ] || exit 1; done &&
            grep -q "^### e2e_cli_m02 exit=0$" "$d/tests.txt" && grep -q "^exit 101: every test binary$" "$d/commands.txt" &&
            ! grep -rqiE "fixtureuser|FIXTUREHOST|wslfixture|HEIMDALL_CANARY_|3333333333|203\.0\.113\.9" "$d"' _ "$imp_rc" "$T/ps-imported"
    mkdir -p "$T/ps-root"
    pwsh -NoProfile -NonInteractive -File "$ps1" -Commit 0000000000000000000000000000000000000000 -ScratchRoot "$T/ps-root" >"$T/ps-real.txt" 2>&1
    real_rc=$?
    if [ "$(uname -s)" != Windows_NT ]; then
        check "P04 local mode: a real run off Windows is refused with exit 2 and creates nothing" \
            bash -c '[ "$1" = 2 ] && [ -z "$(ls -A "$2")" ]' _ "$real_rc" "$T/ps-root"
    fi
else
    skip "P01-P04 local mode: pwsh (PowerShell 7) is not installed here (the importer is still tested by test_m02_evidence.py)"
fi

echo "m02-selftest: $passes passed, $fails failed$([ "$skips" = 0 ] || echo ", $skips skipped")"
[ "$fails" = 0 ]
