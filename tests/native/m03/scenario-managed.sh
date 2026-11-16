#!/usr/bin/env bash
# M03-U13 (m03-plan §4.2 "WSL disposable distribution", §4.3 `run-wsl-distro.sh`): a managed
# credential end to end with the product CLI, ordinary clients without -F.
#
# Run inside the disposable WSL distribution as its non-root user (tests/native/m03/run-wsl-distro.sh),
# after `target-root.sh NAME m03-sshd-start` started the root sshds:
#   scenario-managed.sh SCRATCH HEIMDALL
# SCRATCH: a new directory for this run (created here, mode 700; must not exist; at most 64 bytes,
# for the runtime's Unix socket paths). HEIMDALL: the Linux heimdall debug binary under test.
# remote-lib.sh and pty-answer.py sit next to this script (or in tests/native/m02 of a checkout).
#
# Steps, each `test <step> ... ok|FAILED` between `### wsl_managed_ssh` and
# `### wsl_managed_ssh exit=N` (the case index's scenario_targets), plus `fact <name>=<value>`
# lines (versions, codes, counts and classifications; never a key, a path, a user or a host). The
# managed flow runs under the test configuration (HEIMDALL_TEST_SECRET_STORE=scratch, HEIMDALL_HOME
# in scratch, HEIMDALL_TEST_SSH_HOME = the account's real home) after the fixtures (a disposable
# existing-access key in a disposable ssh-agent, the source provider; an empty decoy agent at
# SSH_AUTH_SOCK for every client), `identity adopt --from-agent`, `destination add` per form, a
# first `setup apply` (the enrollment evaluates the alias's own configuration), the CA (below),
# `profile create` and `time confirm`:
#   m03_wsl_product_store_unavailable_no_plaintext_fallback   (Linux) without a test store `issuer
#       init` ends `issuer_store_unavailable` (exit 4) and writes no backup and no key material;
#   m03_wsl_enroll_account_form_verified   `enroll` (typed yes) of the account form ends `verified`;
#       the registry holds one `cert-authority,principals="hm:<dest>:<account>"` line of this
#       run's CA with its marker, and the existing-access line is untouched;
#   m03_wsl_account_form_registry_is_the_default_path   (WSL) enrolled with no --registry-path
#       (the record says `resolved_by: remote_home`: the remote $HOME/.ssh/authorized_keys), and
#       the root sshd (StrictModes yes, AuthorizedKeysFile .ssh/authorized_keys) logged the
#       verification certificate accepted "found at" the account's ~/.ssh/authorized_keys;
#   m03_wsl_enroll_system_form_verified   `enroll --form system` (typed yes), the CA and principals
#       lines installed as the owner would, `enroll verify` ends `verified`, and the system sshd
#       logged a certificate accepted via its TrustedUserCAKeys file;
#   m03_wsl_setup_apply_projects_the_managed_aliases   `destination prefer … managed`, `setup
#       apply` (typed yes) rewrites the account's configuration (in the distribution its real
#       ~/.ssh/config) so each managed alias names Heimdall's own agent or certificate;
#   m03_wsl_access_ensure_signed_by_the_real_issuer_child   `access ensure` per pair (an owner
#       decision approved with a typed yes when asked) yields a grant, with the runtime's
#       `internal issuer` child running;
#   m03_wsl_ordinary_{ssh,git,scp,sftp}_managed_alias_without_f   the account-form alias, managed,
#       with no -F (isolated: the scratch config), no isolation option, no GIT_SSH_COMMAND;
#   m03_wsl_system_form_ordinary_ssh_by_trusted_user_ca   the system-form alias, managed, ssh;
#   m03_wsl_logins_attributed_to_the_grant_certificate   every login the servers accepted during
#       those clients is a certificate whose key ID names the pair's grant, signed by this run's
#       CA, and none is the existing-access key;
#   m03_wsl_strictmodes_refuses_a_group_writable_registry   (WSL) the same certificate is refused
#       ("bad ownership or modes") while ~/.ssh/authorized_keys is group-writable;
#   m03_wsl_revoke_on_lock_refused_lock_signal_unavailable   (Linux) `access lock-behavior
#       --policy … revoke-on-lock` is refused, `lock_signal_unavailable`;
#   m03_wsl_revoke_then_fresh_login_refused   `access revoke` of each grant, then fresh ordinary
#       logins fail and the servers accept nothing more;
#   m03_wsl_uninstall_lists_the_remote_enrollments   `uninstall` (typed yes) names every enrollment
#       `enroll status` listed (Heimdall removes nothing remote);
#   m03_wsl_uninstall_restores_the_users_config_bytes   ~/.ssh/config is byte-identical to the
#       bytes before the first `setup apply`.
# Everything this script started is stopped by exact PID (its own children) and the runtime by
# `heimdall service stop`; `fact leftover-heimdall-processes=` counts what is left.
#
# The CA: `issuer init` runs first on a pseudo-terminal (the scratch store). On Linux a debug
# build refuses to register a test-configuration store (ADR-0008 §17.25 item 7; U10B-Q5: "a test
# kind is never on the wire"), so it ends at the registration (exit 4, `issuer_store_unavailable`)
# with nothing written; the scenario then provisions the CA as the e2e suites do (`ManagedPair`,
# `e2e_exit_m03`'s World): a fresh K_ca in the scratch store (OpenSSH, encrypted under the store's
# own per-run passphrase, typed into ssh-keygen on a pty, never an argument) and its `active` CA
# record in the stopped runtime's store. `fact ca-provisioning=` says which happened.
#
# HM_SCENARIO_ISOLATED=1 (a Linux or macOS host with no root, before the WSL run): HEIMDALL_HOME and
# HEIMDALL_TEST_SSH_HOME in scratch, every client with `-F <scratch config>` and scratch known-hosts
# files, the default-identity guard before any connection, and two non-root sshds (remote-lib.sh
# `hm2_sshd_start`): the account form with an explicit scratch `--registry-path`, the system form
# with scratch TrustedUserCAKeys and principals files, StrictModes off. The steps that need the
# root sshds or the real home are WSL-only, not printed there, and named by `fact wsl-only-steps=`.
# On macOS the product step is not run either (it would reach the login keychain).
#
# Output: the step lines and facts only. Exit: 0 when every step passed.

# The `[ ... ] && [ ... ]` conditions before `step NAME "$?"` are the step results.
# shellcheck disable=SC2319
set -u
here=$(cd "$(dirname "$0")" && pwd)
# Staged beside this script in the distribution; tests/native/m02 in a checkout (isolated runs).
lib=$here
[ -f "$lib/remote-lib.sh" ] || lib=$(cd "$here/../m02" 2>/dev/null && pwd)
# shellcheck source=tests/native/m02/remote-lib.sh
. "$lib/remote-lib.sh"
S=${1:?usage: scenario-managed.sh SCRATCH HEIMDALL}
HM=${2:?usage: scenario-managed.sh SCRATCH HEIMDALL}
isolated=${HM_SCENARIO_ISOLATED:-0}
T=wsl_managed_ssh
# The root sshds' directory (tests/native/m02/target-root.sh M03_DIR).
ROOT_DIR=/etc/ssh/hm-m03
ACCT_ALIAS=hmacct
SYS_ALIAS=hmsys
ACCT_DEST=wslacct
SYS_DEST=wslsys
PROFILE=wslmanaged
mkdir -m 700 -- "$S" || { echo "scratch exists or cannot be created" >&2; exit 2; }
S=$(cd "$S" && pwd -P)
if [ ${#S} -gt 64 ]; then
    rmdir -- "$S"
    echo "scratch path is too long for Unix socket paths (${#S} > 64 bytes)" >&2
    exit 2
fi
cp -p -- "$HM" "$S/heimdall-under-test" || { echo "cannot copy the binary under test" >&2; exit 2; }
HM=$S/heimdall-under-test
hm2_sanitize_env >/dev/null
export TMPDIR="$S/tmp"
mkdir -m 700 "$TMPDIR"
ACCOUNT=$(id -un)
OS=$(uname -s)

if [ "$isolated" = 1 ]; then
    H="$S/home"
    mkdir -m 700 "$H"
else
    H=$HOME
fi
HH="$S/hh"
HP="$S/hh-product"
SSHDIR="$H/.ssh"
CFG="$SSHDIR/config"
KH="$SSHDIR/known_hosts"
: >"$S/empty_known_hosts"
ISO=()
if [ "$isolated" = 1 ]; then
    ISO=(-F "$CFG" -o "UserKnownHostsFile=$KH" -o "GlobalKnownHostsFile=$S/empty_known_hosts")
fi

agent_pid=""
decoy_pid=""
sys_pid=""
hold_pid=""
cleanup() {
    # The slot holder ends by itself once its sentinel exists (bounded wait).
    [ -n "${S:-}" ] && : >"$S/release-hold" 2>/dev/null
    hmx --json --non-interactive service stop >/dev/null 2>&1 </dev/null
    [ -d "$HP" ] && env HEIMDALL_HOME="$HP" HEIMDALL_TEST_SSH_HOME="$H" "$HM" --json --non-interactive service stop >/dev/null 2>&1 </dev/null
    hm2_sshd_stop
    for p in $agent_pid $decoy_pid $sys_pid $hold_pid; do
        # Our own unreaped children: the PIDs cannot have been reused.
        kill "$p" 2>/dev/null
        wait "$p" 2>/dev/null
    done
    agent_pid=""
    decoy_pid=""
    sys_pid=""
    hold_pid=""
}
trap cleanup EXIT HUP INT TERM

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
    # setup NAME RC: a precondition line; a failure stops the scenario (no later step can pass).
    echo "setup $1 exit=$2"
    if [ "$2" != 0 ]; then
        echo "### $T exit=1"
        exit 1
    fi
}
sha() { { shasum -a 256 "$1" 2>/dev/null || sha256sum "$1" 2>/dev/null; } | cut -d' ' -f1; }
jget() {
    # jget FILE KEY...: a value from the last JSON envelope line of FILE (empty if absent); an
    # integer KEY indexes an array.
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
    if isinstance(v, list) and k.lstrip("-").isdigit():
        v = v[int(k)] if -len(v) <= int(k) < len(v) else None
    else:
        v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else (json.dumps(v) if isinstance(v, (dict, list)) else v))
PY
}
reason() {
    # reason FILE: the envelope's machine reason (data.error.reason, else data.reason).
    local r
    r=$(jget "$1" data error reason)
    [ -n "$r" ] || r=$(jget "$1" data reason)
    echo "$r"
}
# The test configuration every heimdall call of the managed flow runs under.
hmx() { env HEIMDALL_HOME="$HH" HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_SSH_HOME="$H" "$HM" "$@"; }
hmcli() {
    # hmcli OUT ARGS...: heimdall --json --non-interactive ARGS, stdout to OUT.
    local out=$1
    shift
    hmx --json --non-interactive "$@" >"$out" 2>"$out.err" </dev/null
}
on_pty() {
    # on_pty OUT ARGS...: heimdall --json ARGS on a pseudo-terminal, typed yes at each prompt.
    local out=$1
    shift
    python3 -I "$lib/pty-answer.py" "$out" yes 180 -- env HEIMDALL_HOME="$HH" HEIMDALL_TEST_SECRET_STORE=scratch \
        HEIMDALL_TEST_SSH_HOME="$H" "$HM" --json "$@"
}
WSL_ONLY="m03_wsl_account_form_registry_is_the_default_path m03_wsl_strictmodes_refuses_a_group_writable_registry"
wsl_step() {
    # wsl_step NAME RC: a step only the disposable distribution can show (not printed when isolated).
    [ "$isolated" = 1 ] || step "$@"
}

# pty-drive.py TRANSCRIPT TIMEOUT NEEDLE ANSWER [NEEDLE ANSWER ...] -- PROGRAM ARG...: run PROGRAM on
# a fresh pseudo-terminal and type ANSWER once per new occurrence of NEEDLE (non-secret answers
# only; the exit code is the program's, 124 on timeout).
cat >"$S/pty-drive.py" <<'PY'
import os, pty, select, signal, sys, time
a = sys.argv[1:]
sep = a.index("--")
transcript, timeout, pairs, program = a[0], float(a[1]), a[2:sep], a[sep + 1:]
pairs = [(pairs[i].encode(), pairs[i + 1].encode() + b"\n") for i in range(0, len(pairs), 2)]
pid, fd = pty.fork()
if pid == 0:
    try:
        os.execvp(program[0], program)
    finally:
        os._exit(127)
out, seen, status = bytearray(), {}, None
deadline = time.monotonic() + timeout
while status is None:
    r, _, _ = select.select([fd], [], [], 0.05)
    if r:
        try:
            out.extend(os.read(fd, 4096))
        except OSError:
            pass
    for needle, answer in pairs:
        if out.count(needle) > seen.get(needle, 0):
            seen[needle] = out.count(needle)
            time.sleep(0.2)
            os.write(fd, answer)
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        status = st
        while select.select([fd], [], [], 0.1)[0]:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out.extend(chunk)
    elif time.monotonic() >= deadline:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        status = -1
open(transcript, "wb").write(bytes(out))
sys.exit(124 if status == -1 else (os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)))
PY

echo "### $T"
echo "fact mode=$([ "$isolated" = 1 ] && echo isolated-self-test || echo disposable-distribution)"
[ "$isolated" = 1 ] && echo "fact wsl-only-steps=$(echo "$WSL_ONLY" | tr ' ' ',')"
echo "fact os=$OS"
echo "fact ssh-V=$(hm2_first_line ssh -V)"
echo "fact git-version=$(HOME="$S/tmp" GIT_CONFIG_NOSYSTEM=1 hm2_first_line git --version)"
echo "fact heimdall-version=$(hm2_first_line "$HM" --version)"

# 1. Disposable existing-access key, agents, repository.
ssh-keygen -q -t ed25519 -N '' -C hm-m03-scenario-k0 -f "$S/k0" </dev/null >/dev/null 2>&1
setup key "$?"
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
git_quiet() { HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 git "$@" </dev/null >/dev/null 2>&1; }
git_quiet init -q --bare "$S/repo.git" &&
    git_quiet init -q "$S/work" &&
    printf 'hm-m03 scenario\n' >"$S/work/README" &&
    git_quiet -C "$S/work" add README &&
    git_quiet -C "$S/work" -c user.name=hm -c user.email=hm@example.invalid commit -q -m scenario &&
    git_quiet -C "$S/work" push -q "$S/repo.git" HEAD:refs/heads/main &&
    git_quiet --git-dir="$S/repo.git" symbolic-ref HEAD refs/heads/main
setup scratch-git-repository "$?"
head -c 65536 /dev/urandom >"$S/payload"

# 2. The servers, one per enrollment form.
[ -d "$SSHDIR" ] || mkdir -m 700 "$SSHDIR"
if [ "$isolated" = 1 ]; then
    # The account form: the existing access in one file, the explicit scratch registry in another.
    { printf 'restrict '; cat "$S/k0.pub"; } >"$S/existing_keys"
    REGISTRY="$S/reg/authorized_keys"
    EXISTING="$S/existing_keys"
    hm2_sshd_start "$S/sshd-account" "$S/existing_keys" "$S/account.log" 6 "$REGISTRY"
    rc=$?
    [ "$rc" = 0 ] || echo "fact account-sshd=unavailable: $HM2_SSHD_WHY"
    setup account-form-sshd-on-127.0.0.1 "$rc"
    ACCT_PORT=$HM2_SSHD_PORT
    ACCT_HOSTKEY=$HM2_SSHD_HOSTKEY
    ACCT_LOG="$S/account.log"
    acct_pid=$HM2_SSHD_PID
    # The system form: the same fixture configuration plus the system registry's two files.
    mkdir -m 700 "$S/sys"
    CA_FILE="$S/sys/trusted_user_ca_keys"
    PRINC_FILE="$S/sys/principals"
    : >"$CA_FILE"
    : >"$PRINC_FILE"
    eval "orig_$(declare -f hm2_sshd_config)"
    # shellcheck disable=SC2329  # called by hm2_sshd_start
    hm2_sshd_config() {
        orig_hm2_sshd_config "$@"
        echo "TrustedUserCAKeys \"$CA_FILE\""
        echo "AuthorizedPrincipalsFile \"$PRINC_FILE\""
    }
    hm2_sshd_start "$S/sshd-system" "$S/existing_keys" "$S/system.log" 6
    rc=$?
    eval "$(declare -f orig_hm2_sshd_config | sed '1s/^orig_//')"
    [ "$rc" = 0 ] || echo "fact system-sshd=unavailable: $HM2_SSHD_WHY"
    setup system-form-sshd-on-127.0.0.1 "$rc"
    SYS_PORT=$HM2_SSHD_PORT
    SYS_HOSTKEY=$HM2_SSHD_HOSTKEY
    SYS_LOG="$S/system.log"
    sys_pid=$HM2_SSHD_PID
    # hm2_sshd_stop stops the account sshd; the system one is stopped by cleanup's PID list.
    HM2_SSHD_PID=$acct_pid
    REGISTRY_ARGS=(--registry-path "$REGISTRY")
else
    env_file="$ROOT_DIR/sshd.env"
    [ -r "$env_file" ] && grep -q '^system_port=' "$env_file"
    setup root-sshds-started-by-m03-sshd-start "$?"
    rget() { sed -n "s/^$1=//p" "$env_file" | head -1; }
    ACCT_PORT=$(rget account_port)
    ACCT_HOSTKEY=$(rget account_host_key)
    SYS_PORT=$(rget system_port)
    SYS_HOSTKEY=$(rget system_host_key)
    ACCT_LOG="$ROOT_DIR/account.log"
    SYS_LOG="$ROOT_DIR/system.log"
    CA_FILE="$ROOT_DIR/trusted_user_ca_keys"
    PRINC_FILE="$ROOT_DIR/principals/$ACCOUNT"
    for k in strictmodes authorizedkeysfile trustedusercakeys authorizedprincipalsfile; do
        echo "fact root-sshd-account-$k=$(rget "account_$k")"
        echo "fact root-sshd-system-$k=$(rget "system_$k")"
    done
    # The existing access, as the account had it before Heimdall: its default registry path.
    REGISTRY="$SSHDIR/authorized_keys"
    EXISTING=$REGISTRY
    { printf 'restrict '; cat "$S/k0.pub"; } >>"$REGISTRY"
    chmod 600 "$REGISTRY"
    REGISTRY_ARGS=()
    # The CLI's static pass and the runtime read HEIMDALL_TEST_SSH_HOME/etc-ssh as the system
    # directory: the distribution's own system configuration, copied, so they see what ssh sees.
    mkdir -m 700 "$H/etc-ssh"
    [ -f /etc/ssh/ssh_config ] && cp /etc/ssh/ssh_config "$H/etc-ssh/"
    [ -d /etc/ssh/ssh_config.d ] && cp -R /etc/ssh/ssh_config.d "$H/etc-ssh/"
fi
echo "fact sshd-V=$(hm2_first_line "$(hm2_sshd_bin)" -V)"
[ -n "$ACCT_PORT" ] && [ -n "$SYS_PORT" ] && [ -n "$ACCT_HOSTKEY" ] && [ -n "$SYS_HOSTKEY" ]
setup server-ports-and-host-keys "$?"
[ "$isolated" = 1 ] && mkdir -m 700 "$H/etc-ssh"

# 3. The account's configuration before Heimdall.
cat >"$CFG" <<'EOF'
# disposable user configuration (hm-m03 scenario)
Host unrelated
    HostName unrelated.example.invalid
    Port 2201
EOF
chmod 600 "$CFG"
printf '[127.0.0.1]:%s %s\n[127.0.0.1]:%s %s\n' "$ACCT_PORT" "$ACCT_HOSTKEY" "$SYS_PORT" "$SYS_HOSTKEY" >>"$KH"
chmod 600 "$KH"
orig=$(sha "$CFG")
echo "fact user-config-sha256-before=$orig"

# 4. The product without a test store (headless Linux: no Secret Service).
if [ "$OS" = Linux ]; then
    # An unreachable session bus: whatever the host runs, no Secret Service is reached.
    python3 -I "$S/pty-drive.py" "$S/product-init.txt" 120 -- env HEIMDALL_HOME="$HP" HEIMDALL_TEST_SSH_HOME="$H" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$S/no-session-bus" "$HM" --json issuer init --backup-out "$S/product-backup.key"
    rc=$?
    r=$(reason "$S/product-init.txt")
    echo "fact product-issuer-init=exit $rc, $(jget "$S/product-init.txt" code), $r"
    keys=$(grep -rl 'PRIVATE KEY' "$HP" 2>/dev/null | wc -l | tr -d ' ')
    echo "fact product-key-material-files=$keys"
    [ "$rc" = 4 ] && [ "$r" = issuer_store_unavailable ] && [ ! -e "$S/product-backup.key" ] && [ "$keys" = 0 ]
    step m03_wsl_product_store_unavailable_no_plaintext_fallback "$?"
else
    echo "fact product-issuer-init=not run on $OS (it would reach the platform store)"
fi

# 5. The managed flow: catalog, CA, enrollments, projection, activation.
SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
rc=$?
if [ "$(jget "$S/adopt.json" code)" = TIME_UNCERTAIN ]; then
    on_pty "$S/time0.txt" time confirm
    echo "fact time-confirmation-before-adopt=needed (exit $?)"
    SSH_AUTH_SOCK="$S/agent.sock" hmcli "$S/adopt.json" identity adopt --from-agent --active-probe agent
    rc=$?
fi
identity=$(jget "$S/adopt.json" data identity_id)
[ -n "$identity" ] || rc=1
echo "fact identity-adopt=$(jget "$S/adopt.json" code) (exit $rc)"
setup identity-adopt-from-agent "$rc"
hmcli "$S/dest-acct.json" destination add "$ACCT_ALIAS" --id "$ACCT_DEST" --hostname 127.0.0.1 --port "$ACCT_PORT" \
    --account "$ACCOUNT" --identity "$identity"
rc=$?
echo "fact destination-add-account-form=$(jget "$S/dest-acct.json" code) (exit $rc)"
setup destination-add-account-form "$rc"
hmcli "$S/dest-sys.json" destination add "$SYS_ALIAS" --id "$SYS_DEST" --hostname 127.0.0.1 --port "$SYS_PORT" \
    --account "$ACCOUNT" --identity "$identity"
rc=$?
echo "fact destination-add-system-form=$(jget "$S/dest-sys.json" code) (exit $rc)"
setup destination-add-system-form "$rc"

# The existing-access projection first: an enrollment evaluates the alias's own configuration
# (HostName, Port, User, the known host key, the existing access's IdentityAgent; D5 §6.1).
on_pty "$S/apply1.txt" setup apply
rc=$?
echo "fact setup-apply-existing=$(jget "$S/apply1.txt" code) (exit $rc)"
[ "$(jget "$S/apply1.txt" code)" = OK ] || rc=1
setup setup-apply-existing-access "$rc"

# The CA (header): issuer init first, then the e2e suites' provisioning when it cannot register.
python3 -I "$S/pty-drive.py" "$S/init.txt" 180 "Type 'yes' to register this CA: " yes "Type 'written'" written -- \
    env HEIMDALL_HOME="$HH" HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_SSH_HOME="$H" "$HM" --json issuer init \
    --backup-out "$S/ca-backup.key"
rc=$?
echo "fact issuer-init-scratch-store=exit $rc, $(jget "$S/init.txt" code), $(reason "$S/init.txt")"
CA_FP=""
if [ "$rc" = 0 ] && [ "$(jget "$S/init.txt" data cas 0 state)" = active ]; then
    CA_FP=$(jget "$S/init.txt" data cas 0 fingerprint)
    echo "fact ca-provisioning=issuer-init"
else
    hmcli "$S/stop.json" service stop
    python3 -I - "$HH/state" "$S/ca-fp" <<'PY'
import base64, hashlib, json, os, pty, select, sqlite3, sys, time
state, fp_out = sys.argv[1], sys.argv[2]
store = os.path.join(state, "scratch-secret-store")
os.makedirs(store, mode=0o700, exist_ok=True)
os.chmod(store, 0o700)
pf = os.path.join(store, "scratch-store.passphrase")
if not os.path.exists(pf):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fd = os.open(pf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, "".join(alphabet[b & 31] for b in os.urandom(26)).encode())
    os.close(fd)
passphrase = open(pf, "rb").read()
tmp = os.path.join(store, ".seed-ca")
# ssh-keygen on a pseudo-terminal: the store's passphrase typed at its two prompts.
pid, fd = pty.fork()
if pid == 0:
    try:
        os.execvp("ssh-keygen", ["ssh-keygen", "-q", "-t", "ed25519", "-C", "", "-f", tmp])
    finally:
        os._exit(127)
out, typed, deadline = b"", 0, time.monotonic() + 60
while True:
    if select.select([fd], [], [], 0.05)[0]:
        try:
            out += os.read(fd, 1024)
        except OSError:
            pass
    if out.count(b"Enter passphrase") + out.count(b"Enter same passphrase") > typed:
        typed += 1
        time.sleep(0.1)
        os.write(fd, passphrase + b"\n")
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        break
    if time.monotonic() > deadline:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        sys.exit(1)
if not (os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0 and typed == 2):
    sys.exit(1)
kind, b64 = open(tmp + ".pub").read().split()[:2]
digest = hashlib.sha256(base64.b64decode(b64)).digest()
fp = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
item = os.path.join(store, "sha256-" + digest.hex() + ".key")
os.rename(tmp, item)
os.unlink(tmp + ".pub")
os.chmod(item, 0o600)
now = time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())
record = {
    "ca_fingerprint": fp, "public_key": "%s %s" % (kind, b64), "state": "active",
    "store_kind": "linux_secret_service", "backup_sha256": "ab" * 32,
    "backup_created_at": now, "created_at": now, "store_locator": item,
}
db = sqlite3.connect(os.path.join(state, "state.db"), timeout=30)
with db:
    db.execute(
        "INSERT INTO issuers (ca_fingerprint, public_key, state, store_kind, backup_sha256,"
        " backup_created_at, restored_without_log, created_at, retired_at, record_json)"
        " VALUES (?, ?, 'active', 'linux_secret_service', ?, ?, 0, ?, NULL, ?)",
        (fp, record["public_key"], record["backup_sha256"], now, now, json.dumps(record)),
    )
db.close()
open(fp_out, "w").write(fp)
PY
    rc=$?
    [ "$rc" = 0 ] && CA_FP=$(cat "$S/ca-fp")
    echo "fact ca-provisioning=seeded-scratch-store (issuer init cannot register a test store on this platform)"
    setup ca-key-in-the-scratch-store-and-its-active-record "$rc"
fi
# The profile of both pairs (an effectful command: it starts the runtime, whose issuer child loads
# the CA).
hmcli "$S/profile.json" profile create "$PROFILE" --pair "$ACCT_DEST:$ACCOUNT" --pair "$SYS_DEST:$ACCOUNT"
rc=$?
echo "fact profile-create=$(jget "$S/profile.json" code) (exit $rc)"
setup profile-create "$rc"
hmcli "$S/issuer-status.json" issuer status
rc=$?
echo "fact issuer-status=$(jget "$S/issuer-status.json" data state) (exit $rc)"
[ "$rc" = 0 ] && [ "$(jget "$S/issuer-status.json" data state)" = ready ] && [ -n "$CA_FP" ]
setup issuer-ready "$?"
# This boot's time, confirmed after the runtime's last start: the issuer child signs nothing (not
# even a verification certificate) without a same-boot reference.
on_pty "$S/time.txt" time confirm
rc=$?
echo "fact time-confirm=$(jget "$S/time.txt" code) (exit $rc)"
setup time-confirm "$rc"


# The account form: the default registry path in the distribution, an explicit scratch one when
# isolated. The typed yes approves the EnrollAccount decision; the CLI then runs the remote steps
# over the existing access and verifies.
on_pty "$S/enroll-acct.txt" enroll "$ACCT_ALIAS" ${REGISTRY_ARGS[@]+"${REGISTRY_ARGS[@]}"}
rc=$?
acct_state=$(jget "$S/enroll-acct.txt" data state)
echo "fact enroll-account-form=exit $rc, $(jget "$S/enroll-acct.txt" code), state ${acct_state:-none}, $(reason "$S/enroll-acct.txt")"
# The registry's enrollment line: the pair's principal, a CA whose fingerprint is this run's, the marker.
grep "^cert-authority,principals=\"hm:$ACCT_DEST:$ACCOUNT\" ssh-ed25519 [A-Za-z0-9+/=]* heimdall:enr_[0-9a-f]*\$" "$REGISTRY" \
    2>/dev/null | cut -d' ' -f2-3 >"$S/acct-ca.pub"
acct_line=$(grep -c . "$S/acct-ca.pub")
[ "$acct_line" = 1 ] && [ "$(ssh-keygen -l -f "$S/acct-ca.pub" 2>/dev/null | awk '{ print $2 }')" = "$CA_FP" ] || acct_line="0 (no line of this CA)"
existing_kept=$(grep -cF "$(cut -d' ' -f2 "$S/k0.pub")" "$EXISTING" 2>/dev/null)
echo "fact account-registry=enrollment lines $acct_line, existing-access lines $existing_kept"
[ "$rc" = 0 ] && [ "$acct_state" = verified ] && [ "$acct_line" = 1 ] && [ "$existing_kept" = 1 ]
step m03_wsl_enroll_account_form_verified "$?"
acct_ok=$([ "$rc" = 0 ] && [ "$acct_state" = verified ] && echo 1 || echo 0)
# The server accepted the verification certificate through the line in the account's default
# registry path (OpenSSH: `Accepted certificate ID ... found at <file>:<line>`), under StrictModes.
if [ "$isolated" != 1 ]; then
    found=$(grep -c "Accepted certificate ID \".*found at $REGISTRY:[0-9]" "$ACCT_LOG" 2>/dev/null)
    resolved=$(hmcli "$S/enroll-status.json" enroll status; jget "$S/enroll-status.json" data enrollments 0 registry resolved_by)
    echo "fact account-form-registry=resolved by ${resolved:-none}, server certificate acceptances through it $found"
    [ "$acct_ok" = 1 ] && [ -z "${REGISTRY_ARGS[*]:-}" ] && [ "$resolved" = remote_home ] && [ "$found" -ge 1 ] &&
        [ "$(rget account_strictmodes)" = yes ] && [ "$(rget account_authorizedkeysfile)" = .ssh/authorized_keys ]
    wsl_step m03_wsl_account_form_registry_is_the_default_path "$?"
fi

# The system form: the decision, then the lines installed as the owner would (D5 §6.9), then
# `enroll verify`.
on_pty "$S/enroll-sys.txt" enroll "$SYS_ALIAS" --form system
rc=$?
SYS_ENR=$(jget "$S/enroll-sys.txt" data enrollment_id)
echo "fact enroll-system-form=exit $rc, $(jget "$S/enroll-sys.txt" code), state $(jget "$S/enroll-sys.txt" data state)"
ca_line=$(jget "$S/enroll-sys.txt" data instructions 0 | sed -n 's/^add to the TrustedUserCAKeys file: //p')
principal=$(jget "$S/enroll-sys.txt" data instructions 1 | sed -n "s/^add to the account's AuthorizedPrincipalsFile: //p")
[ "$principal" = "hm:$SYS_DEST:$ACCOUNT" ] && [ -n "$ca_line" ] &&
    printf '%s\n' "$ca_line" >>"$CA_FILE" && printf '%s\n' "$principal" >>"$PRINC_FILE"
installed=$?
hmcli "$S/verify-sys.json" enroll verify "$SYS_ENR"
vrc=$?
sys_state=$(jget "$S/verify-sys.json" data state)
echo "fact enroll-verify-system-form=exit $vrc, $(jget "$S/verify-sys.json" code), state ${sys_state:-none}, $(reason "$S/verify-sys.json")"
# OpenSSH's -E log lines end in \r\n: strip the CR before anchoring at the end.
via=$(tr -d '\r' <"$SYS_LOG" 2>/dev/null | grep -c "Accepted certificate ID \".* via $CA_FILE\$")
echo "fact system-form-server-acceptances-via-trusted-user-ca=$via"
[ "$rc" = 0 ] && [ -n "$SYS_ENR" ] && [ "$installed" = 0 ] && [ "$vrc" = 0 ] && [ "$sys_state" = verified ] && [ "$via" -ge 1 ]
step m03_wsl_enroll_system_form_verified "$?"

# The managed definition for each verified pair, applied with a typed yes.
for a in "$ACCT_ALIAS" "$SYS_ALIAS"; do
    hmcli "$S/prefer-$a.json" destination prefer "$a" managed
    rc=$?
    echo "fact destination-prefer-$([ "$a" = "$ACCT_ALIAS" ] && echo account || echo system)-form=$(jget "$S/prefer-$a.json" code) (exit $rc), $(reason "$S/prefer-$a.json")"
done
on_pty "$S/apply2.txt" setup apply
rc=$?
after=$(sha "$CFG")
echo "fact setup-apply-managed=$(jget "$S/apply2.txt" code) (exit $rc)"
echo "fact user-config=$([ "$isolated" = 1 ] && echo scratch || echo "the account's real ~/.ssh/config")"
echo "fact user-config-sha256-after-apply=$after"
# Each managed alias now names Heimdall's own material (inside HEIMDALL_HOME) for its identity.
managed_names() { ssh ${ISO[@]+"${ISO[@]}"} -G "$1" </dev/null 2>/dev/null | awk -v hh="$HH/" '
    ($1 == "identityagent" || $1 == "certificatefile") && index($2, hh) == 1 { n++ } END { print n + 0 }'; }
acct_managed=$(managed_names "$ACCT_ALIAS")
sys_managed=$(managed_names "$SYS_ALIAS")
echo "fact managed-alias-heimdall-entries=account $acct_managed, system $sys_managed"
# The second apply writes only Heimdall's included file (the user config has held the
# Include since the first apply), so only "changed since the original" is asserted here.
[ "$rc" = 0 ] && [ "$(jget "$S/apply2.txt" code)" = OK ] && [ "$after" != "$orig" ] &&
    [ "$sys_managed" -ge 1 ] && { [ "$acct_ok" = 0 ] || [ "$acct_managed" -ge 1 ]; }
step m03_wsl_setup_apply_projects_the_managed_aliases "$?"

# Activation: one ensure per pair, each signed by the runtime's issuer child.
ensure_pair() {
    # ensure_pair TAG DEST: access ensure of (DEST, ACCOUNT). When it needs owner authority, the
    # decision is approved on the pty and the same operation is waited for; OUT then holds its result.
    local out="$S/ensure-$1.json" d op rc
    hmcli "$out" access ensure --profile "$PROFILE" --pair "$2:$ACCOUNT" --work-id "w-$1" --request-id "r-$1"
    rc=$?
    d=$(jget "$out" next decision_ref)
    op=$(jget "$out" next operation_id)
    if [ "$rc" = 3 ] && [ -n "$d" ] && [ -n "$op" ]; then
        on_pty "$S/approve-$1.txt" decision approve "$d"
        rc=$?
        echo "fact ensure-$1-decision=$(jget "$S/approve-$1.txt" data state) (exit $rc), operation $(jget "$S/approve-$1.txt" data operation_state)"
        hmcli "$out" operation wait "$op" --timeout-ms 60000
        rc=$?
    fi
    echo "fact ensure-$1=$(jget "$out" code) (exit $rc), operation $(jget "$out" data state), $(jget "$out" data code)$(reason "$out")"
    return "$rc"
}
grant_of() {
    # grant_of FILE: the grant of an ensure result (the envelope's data, or an operation's result).
    local g
    g=$(jget "$1" data grant_id)
    [ -n "$g" ] || g=$(jget "$1" data result grant_id)
    echo "$g"
}
issuer_children() { pgrep -u "$(id -u)" -f "^$HM internal issuer" 2>/dev/null | wc -l | tr -d ' '; }
ACCT_GRANT=""
if [ "$acct_ok" = 1 ]; then
    ensure_pair acct "$ACCT_DEST" && ACCT_GRANT=$(grant_of "$S/ensure-acct.json")
fi
ensure_pair sys "$SYS_DEST"
rc=$?
SYS_GRANT=$(grant_of "$S/ensure-sys.json")
children=$(issuer_children)
echo "fact issuer-child-processes=$children"
[ "$rc" = 0 ] && [ -n "$SYS_GRANT" ] && [ "$children" -ge 1 ] && { [ "$acct_ok" = 0 ] || [ -n "$ACCT_GRANT" ]; }
step m03_wsl_access_ensure_signed_by_the_real_issuer_child "$?"

# The default-identity guard: every identity, certificate and agent an alias names is inside scratch
# (or the disposable home), and it names at least one. ssh expands `~` to the account database's
# home, never $HOME, which is what the guard expands it to.
REALHOME=$(python3 -I -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')
guard() {
    local g
    g=$(ssh ${ISO[@]+"${ISO[@]}"} -G "$1" </dev/null 2>/dev/null) || return 1
    printf '%s\n' "$g" | awk -v s="$S" -v h="$H" -v real="$REALHOME" '
        $1 == "identityfile" || $1 == "identityagent" || $1 == "certificatefile" {
            v = $2; sub(/^~/, real, v)
            if (v != "none" && index(v, s "/") != 1 && index(v, h "/") != 1) bad = 1
            if ($1 == "identityfile" || $1 == "identityagent") n++
        }
        END { exit (bad || n == 0) }'
}
guarded=0
for a in "$ACCT_ALIAS" "$SYS_ALIAS"; do
    if ! guard "$a"; then
        guarded=1
        echo "fact default-identity-guard=refused for the $([ "$a" = "$ACCT_ALIAS" ] && echo account || echo system)-form alias"
    fi
done

# Ordinary `ssh <alias>` works only while a binding holds the pair's slot (ADR-0008 D10 item 2,
# r3; automatic activation on first use is M05): `heimdall run` (a typed yes for its decision)
# holds both pairs' slots while the clients run, until the sentinel release-hold exists (at most
# 900 s). `run` creates its own grant (worker R's I-5), so attribution and revocation cover every
# grant of this run (inspect grants).
# shellcheck disable=SC2016  # $1 and $i are the inner sh's
on_pty "$S/hold.txt" run --profile "$PROFILE" --work-id w-hold -- \
    /bin/sh -c 'i=0; while [ ! -e "$1" ] && [ $i -lt 900 ]; do sleep 1; i=$((i + 1)); done' _ "$S/release-hold" >/dev/null 2>&1 &
hold_pid=$!
# The slot's certificate as the projection names it (IdentityFile in the
# CertificateAsIdentityFile form of 10.5p1, else CertificateFile).
cert_of() { ssh ${ISO[@]+"${ISO[@]}"} -G "$1" </dev/null 2>/dev/null | awk -v d="$HH/state/managed/" '
    ($1 == "identityfile" || $1 == "certificatefile") && index($2, d) == 1 { print $2; exit }'; }
i=0
while [ $i -lt 600 ] && { [ ! -s "$(cert_of "$ACCT_ALIAS")" ] || [ ! -s "$(cert_of "$SYS_ALIAS")" ]; }; do
    sleep 0.1
    i=$((i + 1))
done
held=$([ -s "$(cert_of "$ACCT_ALIAS")" ] && [ -s "$(cert_of "$SYS_ALIAS")" ] && echo yes || echo no)
echo "fact slots-held-by-heimdall-run=$held"
hmcli "$S/grants.json" inspect grants
GRANTS=$(grep -o 'grant_[0-9a-f]\{32\}' "$S/grants.json" | sort -u | tr '\n' ' ')
echo "fact grants=$(echo "$GRANTS" | wc -w | tr -d ' ')"

# Ordinary clients, no -F (isolated: the scratch config), the empty decoy agent at SSH_AUTH_SOCK.
export SSH_AUTH_SOCK="$S/decoy.sock"
mark_acct=$(wc -l <"$ACCT_LOG" | tr -d ' ')
mark_sys=$(wc -l <"$SYS_LOG" | tr -d ' ')
# Only an alias whose projection names Heimdall's material counts: an existing-access login through
# the same alias proves nothing here (the attribution step below checks each login's certificate).
run_ok() { [ "$guarded" = 0 ] && "$@" </dev/null >/dev/null 2>"$S/client.err"; }
acct_run() { [ "$acct_managed" -ge 1 ] && run_ok "$@"; }
acct_run ssh ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$ACCT_ALIAS" true
step m03_wsl_ordinary_ssh_managed_alias_without_f "$?"
if [ "$isolated" = 1 ]; then
    export GIT_SSH_COMMAND="ssh -F '$CFG' -o 'UserKnownHostsFile=$KH' -o 'GlobalKnownHostsFile=$S/empty_known_hosts' -o BatchMode=yes"
fi
acct_run env HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 git ls-remote "$ACCT_ALIAS:$S/repo.git" &&
    acct_run env HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 git clone -q "$ACCT_ALIAS:$S/repo.git" "$S/clone" &&
    [ "$(cat "$S/clone/README" 2>/dev/null)" = "hm-m03 scenario" ]
step m03_wsl_ordinary_git_managed_alias_without_f "$?"
unset GIT_SSH_COMMAND
acct_run scp -q ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$S/payload" "$ACCT_ALIAS:$S/payload.up" &&
    acct_run scp -q ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$ACCT_ALIAS:$S/payload.up" "$S/payload.down" &&
    [ "$(sha "$S/payload")" = "$(sha "$S/payload.down")" ]
step m03_wsl_ordinary_scp_managed_alias_without_f "$?"
printf 'put %s %s\nget %s %s\n' "$S/payload" "$S/payload.sftp" "$S/payload.sftp" "$S/payload.sftp.down" >"$S/batch"
acct_run sftp -q ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes -b "$S/batch" "$ACCT_ALIAS" &&
    [ "$(sha "$S/payload")" = "$(sha "$S/payload.sftp.down")" ]
step m03_wsl_ordinary_sftp_managed_alias_without_f "$?"
[ "$sys_managed" -ge 1 ] && run_ok ssh ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$SYS_ALIAS" true
step m03_wsl_system_form_ordinary_ssh_by_trusted_user_ca "$?"

# Attribution: every login the servers accepted since the mark is a certificate of this run's
# grant (key ID heimdall:<environment>:<grant>:<n>), signed by this run's CA; none by the
# existing-access key.
attribute() {
    # attribute LOG MARK GRANT: "<accepted logins> <of the grant under the CA> <plain publickey>".
    tail -n +"$(($2 + 1))" "$1" 2>/dev/null | awk -v g="$3" -v ca="$CA_FP" '
        /Accepted publickey for / {
            n++
            gid = ""
            if (match($0, /ID heimdall:[^ ]+/)) { split(substr($0, RSTART + 3, RLENGTH - 3), f, ":"); gid = f[3] }
            if ($0 ~ /-CERT / && gid != "" && index(" " g " ", " " gid " ") && index($0, "CA ") && index($0, ca)) ok++
            else if ($0 !~ /-CERT /) plain++
        }
        END { printf "%d %d %d\n", n, ok, plain }'
}
read -r a_n a_ok a_plain <<<"$(attribute "$ACCT_LOG" "$mark_acct" "${GRANTS:-none}")"
read -r s_n s_ok s_plain <<<"$(attribute "$SYS_LOG" "$mark_sys" "${GRANTS:-none}")"
echo "fact attributed-logins=account form $a_ok of $a_n (plain publickey $a_plain), system form $s_ok of $s_n (plain publickey $s_plain)"
[ "$a_n" -ge 6 ] && [ "$a_ok" = "$a_n" ] && [ "$a_plain" = 0 ] && [ "$s_n" -ge 1 ] && [ "$s_ok" = "$s_n" ] && [ "$s_plain" = 0 ]
step m03_wsl_logins_attributed_to_the_grant_certificate "$?"

# StrictModes on the root sshd: the registry made group-writable refuses the same certificate.
if [ "$isolated" != 1 ]; then
    chmod g+w "$REGISTRY"
    m=$(wc -l <"$ACCT_LOG" | tr -d ' ')
    ssh -o BatchMode=yes "$ACCT_ALIAS" true </dev/null >/dev/null 2>&1
    src=$?
    chmod 600 "$REGISTRY"
    bad=$(tail -n +"$((m + 1))" "$ACCT_LOG" | grep -c "bad ownership or modes")
    echo "fact strictmodes-control=exit $src, refusals logged $bad"
    [ "$src" = 255 ] && [ "$bad" -ge 1 ]
    wsl_step m03_wsl_strictmodes_refuses_a_group_writable_registry "$?"
fi
unset SSH_AUTH_SOCK

# No lock signal on headless Linux: revoke-on-lock is refused, nothing saved.
if [ "$OS" = Linux ]; then
    pol=$(jget "$S/ensure-sys.json" data policy_id)
    hmcli "$S/lock.json" access lock-behavior --policy "${pol:-pol}" revoke-on-lock
    rc=$?
    r=$(reason "$S/lock.json")
    echo "fact lock-behavior-revoke-on-lock=exit $rc, $(jget "$S/lock.json" code), $r"
    [ "$rc" != 0 ] && [ "$r" = lock_signal_unavailable ]
    step m03_wsl_revoke_on_lock_refused_lock_signal_unavailable "$?"
else
    echo "fact lock-behavior-revoke-on-lock=not run on $OS (a lock signal exists there)"
fi

# Revocation: each grant revoked, then a fresh ordinary login refused and nothing accepted after.
export SSH_AUTH_SOCK="$S/decoy.sock"
m_acct=$(wc -l <"$ACCT_LOG" | tr -d ' ')
m_sys=$(wc -l <"$SYS_LOG" | tr -d ' ')
rrc=0
for g in $GRANTS; do
    hmcli "$S/revoke-$g.json" access revoke "$g"
    r=$?
    echo "fact access-revoke=$(jget "$S/revoke-$g.json" code) (exit $r)"
    [ "$r" = 0 ] || rrc=1
done
ssh ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$SYS_ALIAS" true </dev/null >/dev/null 2>&1
s_after=$?
a_after=255
[ -n "$ACCT_GRANT" ] && { ssh ${ISO[@]+"${ISO[@]}"} -o BatchMode=yes "$ACCT_ALIAS" true </dev/null >/dev/null 2>&1; a_after=$?; }
acc=$(( $(tail -n +"$((m_acct + 1))" "$ACCT_LOG" | grep -c 'Accepted publickey for ') + $(tail -n +"$((m_sys + 1))" "$SYS_LOG" | grep -c 'Accepted publickey for ') ))
echo "fact after-revoke=fresh logins exit account $a_after, system $s_after; accepted since $acc"
: >"$S/release-hold"
wait "$hold_pid" 2>/dev/null
echo "fact holder=exit $?"
hold_pid=""
unset SSH_AUTH_SOCK
[ "$rrc" = 0 ] && [ -n "$SYS_GRANT" ] && [ "$s_after" != 0 ] && [ "$a_after" != 0 ] && [ "$acc" = 0 ]
step m03_wsl_revoke_then_fresh_login_refused "$?"

# Uninstall: the remote enrollments are listed (Heimdall removes nothing remote here), and the
# account's configuration is restored byte for byte.
hmcli "$S/enroll-status-final.json" enroll status
ids=$(jget "$S/enroll-status-final.json" data enrollments |
    python3 -I -c 'import json, sys; [print(e.get("enrollment_id", "")) for e in (json.loads(sys.stdin.read() or "[]") or [])]' 2>/dev/null)
on_pty "$S/uninstall.json" uninstall
rc=$?
final=$(sha "$CFG")
known=0
listed=0
for e in $ids; do
    known=$((known + 1))
    grep -qF "$e" "$S/uninstall.json" && listed=$((listed + 1))
done
echo "fact uninstall=$(jget "$S/uninstall.json" code) (exit $rc), enrollments named $listed of $known"
echo "fact user-config-sha256-after-uninstall=$final"
[ "$rc" = 0 ] && [ "$known" -ge 2 ] && [ "$listed" = "$known" ]
step m03_wsl_uninstall_lists_the_remote_enrollments "$?"
[ "$rc" = 0 ] && [ "$final" = "$orig" ]
step m03_wsl_uninstall_restores_the_users_config_bytes "$?"

# Stop what this script started; count what is left (never signalled by name).
cleanup
trap - EXIT HUP INT TERM
left=$(pgrep -u "$(id -u)" -f "^$HM( |\$)" 2>/dev/null | wc -l | tr -d ' ')
echo "fact leftover-heimdall-processes=$left"
[ "$left" = 0 ] || status=1
echo "### $T exit=$status"
exit "$status"
