#!/usr/bin/env bash
# M02-U11 (m02-plan §4, "run-wsl-distro.sh"; ADR-0007 §9 item 5): ordinary ssh without -F.
#
# Run inside the disposable WSL distribution as its non-root user, whose home is itself
# disposable (the distribution is unregistered afterwards):
#   scenario-ordinary-ssh.sh SCRATCH HEIMDALL
# SCRATCH: a new directory for this run (created here, mode 700; must not exist; at most 64
# bytes long, for the runtime's Unix socket paths).
# HEIMDALL: the Linux heimdall binary under test. remote-lib.sh and pty-answer.py must sit
# next to this script.
#
# Steps, each printed as `test <step> ... ok|FAILED` under `### wsl_ordinary_ssh`
# (case-index.json scenario_targets; m02-evidence.py reads them like cargo tests):
#   1. a disposable key, a disposable provider ssh-agent (HOME in scratch) holding it, an
#      empty decoy agent at SSH_AUTH_SOCK, the fixture sshd (non-root, 127.0.0.1 only,
#      per-run host key; remote-lib.sh), a scratch bare Git repository;
#   2. the user's real ~/.ssh/config starts with one unrelated alias; the fixture host
#      key is put in ~/.ssh/known_hosts (as a first trust would);
#   3. heimdall with no test variable: `identity adopt --from-agent --active-probe agent`,
#      `destination add`, then `setup apply` on a pseudo-terminal with a typed yes
#      (`time confirm` first only when the runtime reports TIME_UNCERTAIN);
#   4. ordinary `ssh <alias> true`, `git ls-remote`/`git clone`, `scp` and `sftp -b`
#      with no -F, no isolation option and no GIT_SSH_COMMAND; the unrelated alias's
#      `ssh -G` output is unchanged; the sshd accepted only the adopted key; whether
#      renameat2(RENAME_EXCHANGE) works on the home's file system, and whether it fills a
#      birth time (statx STATX_BTIME);
#   5. `heimdall uninstall`: ~/.ssh/config is byte-identical to the original and the
#      alias no longer resolves to the managed values;
#   6. everything this script started is stopped by exact PID (its own children), and
#      the runtime by `heimdall service stop`.
#
# HM_SCENARIO_ISOLATED=1 (build-host self-test only) keeps the account's real home out
# of it: HEIMDALL_HOME and HEIMDALL_TEST_SSH_HOME in scratch, every client with
# `-F <scratch config>` and scratch known-hosts files, and a default-identity guard
# (`ssh -G` must name only scratch identities) before any connection. Ordinary ssh
# without -F is shown only in the disposable distribution.
#
# Output: the step lines plus `fact <name>=<value>` lines (versions, digests of the
# disposable config, counts); never a key, an environment value or a path outside
# scratch and the disposable home. Exit: 0 when every step passed.

# The `[ ... ] && [ ... ]` conditions before `step NAME "$?"` are the step results.
# shellcheck disable=SC2319
set -u
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/native/m02/remote-lib.sh
. "$here/remote-lib.sh"
S=${1:?usage: scenario-ordinary-ssh.sh SCRATCH HEIMDALL}
HM=${2:?usage: scenario-ordinary-ssh.sh SCRATCH HEIMDALL}
isolated=${HM_SCENARIO_ISOLATED:-0}
ALIAS=hmalpha
mkdir -m 700 -- "$S" || { echo "scratch exists or cannot be created" >&2; exit 2; }
S=$(cd "$S" && pwd -P)
# Unix socket paths are limited (104 bytes on macOS, 108 on Linux) and the runtime's control
# socket is <home>/run/control.sock: a long scratch path would make the runtime fail to
# start for a reason nobody would guess. Refuse it here, naming the reason.
if [ ${#S} -gt 64 ]; then
    rmdir -- "$S"
    echo "scratch path is too long for Unix socket paths (${#S} > 64 bytes)" >&2
    exit 2
fi
# A private copy of the binary under test: the leftover-process count at the end then
# names only processes this run started, even where other work uses the same binary.
cp -p -- "$HM" "$S/heimdall-under-test" || { echo "cannot copy the binary under test" >&2; exit 2; }
HM=$S/heimdall-under-test
hm2_sanitize_env >/dev/null
export TMPDIR="$S/tmp"
mkdir -m 700 "$TMPDIR"

agent_pid=""
decoy_pid=""
cleanup() {
    "$HM" --json --non-interactive service stop >/dev/null 2>&1 </dev/null
    hm2_sshd_stop
    for p in $agent_pid $decoy_pid; do
        # Our own unreaped children: the PIDs cannot have been reused.
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done
    agent_pid=""
    decoy_pid=""
}
trap cleanup EXIT HUP INT TERM

if [ "$isolated" = 1 ]; then
    H="$S/home"
    mkdir -m 700 "$H" "$H/etc-ssh"
    export HEIMDALL_HOME="$S/hh" HEIMDALL_TEST_SSH_HOME="$H"
else
    H=$HOME
fi
SSHDIR="$H/.ssh"
CFG="$SSHDIR/config"
KH="$SSHDIR/known_hosts"
: >"$S/empty_known_hosts"
# The client options of the isolated self-test; none in the distribution.
ISO=()
if [ "$isolated" = 1 ]; then
    ISO=(-F "$CFG" -o "UserKnownHostsFile=$KH" -o "GlobalKnownHostsFile=$S/empty_known_hosts")
fi

status=0
step() {
    # step NAME RC: one test line; a nonzero RC fails the scenario.
    if [ "$2" = 0 ]; then
        echo "test $1 ... ok"
    else
        echo "test $1 ... FAILED"
        status=1
    fi
}
setup() {
    # setup NAME RC: a precondition line; a failure stops the scenario (no step can pass).
    echo "setup $1 exit=$2"
    if [ "$2" != 0 ]; then
        echo "### wsl_ordinary_ssh exit=1"
        exit 1
    fi
}
sha() { { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1" 2>/dev/null; } | cut -d' ' -f1; }
jget() {
    # jget FILE KEY...: a value from the last JSON envelope line of FILE (empty if absent).
    python3 -I - "$@" <<'PY'
import json, sys
path, keys = sys.argv[1], sys.argv[2:]
env = None
try:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
except OSError:
    lines = []
for line in lines[::-1]:
    line = line.strip()
    if line.startswith("{"):
        try:
            env = json.loads(line)
            break
        except ValueError:
            pass
v = env
for k in keys:
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else v)
PY
}
hmcli() {
    # hmcli OUT ARGS...: heimdall --json --non-interactive ARGS, stdout to OUT.
    local out=$1
    shift
    "$HM" --json --non-interactive "$@" >"$out" 2>"$out.err" </dev/null
}
on_pty() {
    # on_pty OUT ARGS...: heimdall --json ARGS on a pseudo-terminal, typed yes at each prompt.
    local out=$1
    shift
    python3 -I "$here/pty-answer.py" "$out" yes 120 -- "$HM" --json "$@"
}

echo "### wsl_ordinary_ssh"
echo "fact mode=$([ "$isolated" = 1 ] && echo isolated-self-test || echo disposable-home)"
echo "fact ssh-V=$(hm2_first_line ssh -V)"
echo "fact git-version=$(hm2_first_line git --version)"
echo "fact home-fs=$(hm2_fs_type "$H")"

# 1. Disposable key, agents, sshd, repository.
ssh-keygen -q -t ed25519 -N '' -C hm-m02-scenario-k0 -f "$S/k0" </dev/null >/dev/null 2>&1
setup key "$?"
fp=$(ssh-keygen -l -f "$S/k0.pub" | awk '{ print $2 }')
mkdir -m 700 "$S/agent-home" "$S/decoy-home"
HOME="$S/agent-home" ssh-agent -D -a "$S/agent.sock" </dev/null >/dev/null 2>&1 &
agent_pid=$!
HOME="$S/decoy-home" ssh-agent -D -a "$S/decoy.sock" </dev/null >/dev/null 2>&1 &
decoy_pid=$!
i=0
while [ $i -lt 100 ] && { [ ! -S "$S/agent.sock" ] || [ ! -S "$S/decoy.sock" ]; }; do
    sleep 0.1
    i=$((i + 1))
done
SSH_AUTH_SOCK="$S/agent.sock" ssh-add -q "$S/k0" </dev/null >/dev/null 2>&1
setup provider-agent-holds-the-disposable-key "$?"
{ printf 'restrict '; cat "$S/k0.pub"; } >"$S/authorized_keys"
hm2_sshd_start "$S/sshd" "$S/authorized_keys" "$S/sshd.log"
rc=$?
[ "$rc" = 0 ] || echo "fact fixture-sshd=unavailable: $HM2_SSHD_WHY"
setup fixture-sshd-listening-on-127.0.0.1 "$rc"
echo "fact sshd-V=$(hm2_first_line "$(hm2_sshd_bin)" -V)"
port=$HM2_SSHD_PORT
# ADR-0007 §12.33 item 2 (P02): every Git call pins its user configuration to the scratch
# home: HOME and XDG_CONFIG_HOME both inside it (so $HOME/.gitconfig and
# $XDG_CONFIG_HOME/git/config are scratch files), and no system file. An inherited
# XDG_CONFIG_HOME, templateDir, hooksPath, include or credential helper is never read.
git_quiet() { HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 git "$@" </dev/null >/dev/null 2>&1; }
git_quiet init -q --bare "$S/repo.git" &&
    git_quiet init -q "$S/work" &&
    printf 'hm-m02 scenario\n' >"$S/work/README" &&
    git_quiet -C "$S/work" add README &&
    git_quiet -C "$S/work" -c user.name=hm -c user.email=hm@example.invalid commit -q -m scenario &&
    git_quiet -C "$S/work" push -q "$S/repo.git" HEAD:refs/heads/main &&
    git_quiet --git-dir="$S/repo.git" symbolic-ref HEAD refs/heads/main
setup scratch-git-repository "$?"
head -c 65536 /dev/urandom >"$S/payload"

# 2. The user's configuration before Heimdall.
[ -d "$SSHDIR" ] || mkdir -m 700 "$SSHDIR"
cat >"$CFG" <<'EOF'
# disposable user configuration (hm-m02 scenario)
Host unrelated
    HostName unrelated.example.invalid
    Port 2201
EOF
chmod 600 "$CFG"
printf '[127.0.0.1]:%s %s\n' "$port" "$HM2_SSHD_HOSTKEY" >>"$KH"
chmod 600 "$KH"
orig=$(sha "$CFG")
echo "fact user-config-sha256-before=$orig"
ssh ${ISO[@]+"${ISO[@]}"} -G unrelated </dev/null >"$S/unrelated.before" 2>/dev/null
setup ssh-G-unrelated-before "$?"

# 3. Heimdall: adopt, add, apply.
SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
rc=$?
if [ "$(jget "$S/adopt.json" code)" = TIME_UNCERTAIN ]; then
    on_pty "$S/time.txt" time confirm
    echo "fact time-confirmation=needed (exit $?)"
    SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
    rc=$?
else
    echo "fact time-confirmation=not needed"
fi
identity=$(jget "$S/adopt.json" data identity_id)
[ -n "$identity" ] || rc=1
echo "fact identity-adopt-code=$(jget "$S/adopt.json" code)"
setup identity-adopt-from-agent "$rc"
hmcli "$S/dest.json" destination add "$ALIAS" --hostname 127.0.0.1 --port "$port" --account "$(id -un)" --identity "$identity"
rc=$?
echo "fact destination-add-code=$(jget "$S/dest.json" code)"
setup destination-add "$rc"
on_pty "$S/apply.txt" setup apply
rc=$?
echo "fact setup-apply-code=$(jget "$S/apply.txt" code) (exit $rc)"
[ "$(jget "$S/apply.txt" code)" = OK ] || rc=1
after=$(sha "$CFG")
echo "fact user-config-sha256-after-apply=$after"
[ "$rc" = 0 ] && [ "$after" != "$orig" ]
step a01_setup_apply_writes_the_users_real_ssh_config "$?"

# The default-identity guard: every identity and agent the alias names is inside scratch
# or the (disposable) home, and it names at least one identity file. ssh expands `~` to the
# account's home from the account database, never from $HOME or HEIMDALL_TEST_SSH_HOME, so
# that is what the guard expands it to: in the isolated self-test a default identity of the
# build host's account (~/.ssh/id_*) is outside both and refuses.
REALHOME=$(python3 -I -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')
guard() {
    local g
    g=$(ssh ${ISO[@]+"${ISO[@]}"} -G "$ALIAS" </dev/null 2>/dev/null) || return 1
    printf '%s\n' "$g" | awk -v s="$S" -v h="$H" -v real="$REALHOME" '
        $1 == "identityfile" || $1 == "identityagent" || $1 == "certificatefile" {
            v = $2; sub(/^~/, real, v)
            if (v != "none" && index(v, s "/") != 1 && index(v, h "/") != 1) bad = 1
            if ($1 == "identityfile") n++
        }
        END { exit (bad || n == 0) }'
}
guarded=0
if ! guard; then
    guarded=1
    echo "fact default-identity-guard=refused (an identity outside scratch and the home, or none)"
fi

# 4. Ordinary clients, the empty decoy agent at SSH_AUTH_SOCK.
export SSH_AUTH_SOCK="$S/decoy.sock"
run_ok() { [ "$guarded" = 0 ] && "$@" </dev/null >/dev/null 2>"$S/client.err"; }
run_ok ssh ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$ALIAS" true
step a01_ordinary_ssh_alias_without_f "$?"
if [ "$isolated" = 1 ]; then
    export GIT_SSH_COMMAND="ssh -F '$CFG' -o 'UserKnownHostsFile=$KH' -o 'GlobalKnownHostsFile=$S/empty_known_hosts' -o BatchMode=yes"
fi
run_ok env HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 git ls-remote "$ALIAS:$S/repo.git" &&
    run_ok env HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 git clone -q "$ALIAS:$S/repo.git" "$S/clone" &&
    [ "$(cat "$S/clone/README" 2>/dev/null)" = "hm-m02 scenario" ]
step a01_ordinary_git_without_f "$?"
unset GIT_SSH_COMMAND
run_ok scp -q ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$S/payload" "$ALIAS:$S/payload.up" &&
    run_ok scp -q ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$ALIAS:$S/payload.up" "$S/payload.down" &&
    [ "$(sha "$S/payload")" = "$(sha "$S/payload.down")" ]
step a01_ordinary_scp_without_f "$?"
printf 'put %s %s\nget %s %s\n' "$S/payload" "$S/payload.sftp" "$S/payload.sftp" "$S/payload.sftp.down" >"$S/batch"
run_ok sftp -q ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes -b "$S/batch" "$ALIAS" &&
    [ "$(sha "$S/payload")" = "$(sha "$S/payload.sftp.down")" ]
step a01_ordinary_sftp_without_f "$?"
ssh ${ISO[@]+"${ISO[@]}"} -G unrelated </dev/null >"$S/unrelated.after" 2>/dev/null &&
    cmp -s "$S/unrelated.before" "$S/unrelated.after"
step a01_unaffected_alias_effective_config_unchanged "$?"
accepted=$(grep 'Accepted publickey for ' "$S/sshd.log" 2>/dev/null |
    sed -n 's/.*ssh2: [A-Z0-9-]* \(SHA256:[A-Za-z0-9+\/=]*\).*/\1/p' | sort -u)
echo "fact sshd-accepted-logins=$(grep -c 'Accepted publickey for ' "$S/sshd.log" 2>/dev/null)"
[ -n "$accepted" ] && [ "$accepted" = "$fp" ]
step a01_provider_agent_accepted_key_is_the_adopted_one "$?"
python3 -I - "$H" <<'PY'
import ctypes, os, sys
home = sys.argv[1]
a, b = os.path.join(home, ".hm-xchg-a"), os.path.join(home, ".hm-xchg-b")
for p, t in ((a, b"a"), (b, b"b")):
    with open(p, "wb") as f:
        f.write(t)
ok, how = False, "none"
libc = ctypes.CDLL(None, use_errno=True)
if hasattr(libc, "renameat2"):
    # Linux: renameat2(AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE).
    how = "renameat2 RENAME_EXCHANGE"
    ok = libc.renameat2(-100, a.encode(), -100, b.encode(), 2) == 0
elif hasattr(libc, "renamex_np"):
    # macOS (the isolated self-test): renamex_np(a, b, RENAME_SWAP).
    how = "renamex_np RENAME_SWAP"
    ok = libc.renamex_np(a.encode(), b.encode(), 2) == 0
ok = ok and open(a, "rb").read() == b"b"
print("fact rename-exchange=%s (%s)" % ("supported" if ok else "unsupported", how))
os.unlink(a)
os.unlink(b)
sys.exit(0 if ok else 1)
PY
step a22_rename_exchange_supported_on_the_home_fs "$?"
# Audit G-W1 (m02-plan U4 file_identity_birth_recorded_on_target_fs names WSL ext4; ADR-0007
# F25): whether the home's file system fills a birth time. Linux: statx(AT_FDCWD, path, 0,
# STATX_BTIME); the kernel sets STATX_BTIME in stx_mask only when it filled stx_btime. macOS
# (the isolated self-test): st_birthtime. A file system that records none is an ADR-0007 §14
# reopen condition, so the step passes only when the birth time is filled.
python3 -I - "$H" <<'PY'
import ctypes, os, sys, time
home = sys.argv[1]
p = os.path.join(home, ".hm-btime")
with open(p, "wb") as f:
    f.write(b"b")
recorded, how = False, "none"
try:
    if sys.platform.startswith("linux"):
        how = "statx STATX_BTIME"
        libc = ctypes.CDLL(None, use_errno=True)
        if hasattr(libc, "statx"):
            buf = ctypes.create_string_buffer(256)  # struct statx
            if libc.statx(-100, p.encode(), 0, 0x800, buf) == 0:
                mask = int.from_bytes(buf.raw[0:4], "little")
                sec = int.from_bytes(buf.raw[80:88], "little", signed=True)  # stx_btime.tv_sec
                # Filled and plausible: within a day of now (the file was just created).
                recorded = bool(mask & 0x800) and abs(sec - time.time()) < 86400
            else:
                how += " (statx errno %d)" % ctypes.get_errno()
        else:
            how += " (no statx in libc)"
    elif hasattr(os.stat_result, "st_birthtime"):
        how = "st_birthtime"
        recorded = abs(os.stat(p).st_birthtime - time.time()) < 86400
finally:
    os.unlink(p)
print("fact birth-time=%s (%s)" % ("recorded" if recorded else "not-recorded", how))
sys.exit(0 if recorded else 1)
PY
step a22_birth_time_recorded_on_the_home_fs "$?"
unset SSH_AUTH_SOCK

# 5. Uninstall.
hmcli "$S/uninstall.json" uninstall
rc=$?
echo "fact uninstall-code=$(jget "$S/uninstall.json" code) (exit $rc)"
final=$(sha "$CFG")
echo "fact user-config-sha256-after-uninstall=$final"
[ "$rc" = 0 ] && [ "$final" = "$orig" ]
step t06_uninstall_restores_user_bytes "$?"
g=$(ssh ${ISO[@]+"${ISO[@]}"} -G "$ALIAS" </dev/null 2>/dev/null)
printf '%s\n' "$g" | grep -qx "hostname $ALIAS" && ! printf '%s\n' "$g" | grep -qx "port $port"
step t06_uninstall_restores_effective_config "$?"

# 6. Stop what this script started; count what is left (never signalled by name).
cleanup
trap - EXIT HUP INT TERM
left=$(pgrep -u "$(id -u)" -f "^$HM( |\$)" 2>/dev/null | wc -l | tr -d ' ')
echo "fact leftover-heimdall-processes=$left"
[ "$left" = 0 ] || status=1
echo "### wsl_ordinary_ssh exit=$status"
exit "$status"
