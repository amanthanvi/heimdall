# shellcheck shell=bash
# The HM2_SSHD_* results are read by the scripts that source this file.
# shellcheck disable=SC2034
# Target-side helpers for the M02 native harnesses (m02-plan §4). run-linux.sh,
# run-windows.sh and run-wsl-distro.sh send this file to the target ahead of every
# remote script (on stdin, with `bash -s`); run-macos.sh and
# tests/native/m02/selftest.sh source it locally. Bash 3.2 compatible. Every function is
# safe in a caller that runs with `set -e` (run-macos.sh does): a command whose nonzero
# exit is data (sshd -V, a reaped signalled child) is guarded with `&&`/`||`.
#
# Rules kept here:
#   * Nothing prints a value of the environment, a home path, a user or host name, a
#     process command line or a key: only versions, counts, classifications and digests.
#   * The fixture sshd runs as the current, non-root user, binds 127.0.0.1 only, uses a
#     per-run host key in the given scratch directory, and is stopped by exact PID: its
#     own unreaped child (`kill` + `wait`), or, from another session, only after its
#     recorded start time and its scratch configuration path both match.
#   * The owner's ~/.ssh and Git configuration are never written: hm2_owner_digest only
#     reads their metadata (lstat), to show they are unchanged after the run.

# hm2_sanitize_env: drop inherited agent, askpass, Git and Heimdall variables, so no
# test can reach the account's agent or configuration by inheritance. Prints what was
# inherited, as set/unset and counts only.
hm2_sanitize_env() {
    local sock=unset n_git=0 n_hm=0 v
    [ -n "${SSH_AUTH_SOCK:-}" ] && sock="set"
    for v in $(env | sed -n 's/^\(GIT_[A-Za-z0-9_]*\)=.*/\1/p'); do
        unset "$v"
        n_git=$((n_git + 1))
    done
    for v in $(env | sed -n 's/^\(HEIMDALL_[A-Za-z0-9_]*\)=.*/\1/p'); do
        unset "$v"
        n_hm=$((n_hm + 1))
    done
    unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY \
        HM_FIXTURE_SSHD_HOST HM_FIXTURE_SSHD_PORT HM_FIXTURE_SSHD_HOST_KEY \
        HM_FIXTURE_SSHD_AUTHORIZED_KEYS HM_FIXTURE_SSHD_LOG HM_FIXTURE_HOOK
    echo "inherited-ssh-auth-sock=$sock (unset for the run)"
    echo "inherited-git-variables=$n_git (unset for the run)"
    echo "inherited-heimdall-variables=$n_hm (unset for the run)"
}

# hm2_first_line CMD...: the first output line of CMD (stdout and stderr), then its exit
# code, as "<line> (exit N)"; "absent" when CMD is not found.
hm2_first_line() {
    local out rc
    command -v "$1" >/dev/null 2>&1 || { echo "absent"; return 0; }
    # `&& rc=0 || rc=$?`: a nonzero exit (sshd -V exits 1) is data here, not an error, even
    # in a caller that runs with `set -e`.
    out=$("$@" 2>&1 </dev/null) && rc=0 || rc=$?
    printf '%s (exit %s)\n' "$(printf '%s\n' "$out" | head -1 | tr -d '\r')" "$rc"
}

# hm2_sshd_bin: the sshd program (PATH first, then the usual sbin directories).
hm2_sshd_bin() {
    local p
    p=$(command -v sshd 2>/dev/null) && { echo "$p"; return 0; }
    for p in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}

# hm2_versions SCRATCH: `ssh -V`, `sshd -V` and `git --version` on this target, each with
# its real exit code. Git runs with a scratch HOME and GIT_CONFIG_NOSYSTEM=1.
hm2_versions() {
    local sshd
    echo "ssh-V=$(hm2_first_line ssh -V)"
    if sshd=$(hm2_sshd_bin); then
        echo "sshd-V=$(hm2_first_line "$sshd" -V)"
    else
        echo "sshd-V=absent"
    fi
    mkdir -p "$1/githome"
    echo "git-version=$(HOME="$1/githome" GIT_CONFIG_NOSYSTEM=1 hm2_first_line git --version)"
}

# hm2_fs_type DIR: the file system type DIR lives on.
hm2_fs_type() {
    local t mp
    t=$(findmnt -n -o FSTYPE -T "$1" 2>/dev/null) && [ -n "$t" ] && { echo "$t"; return 0; }
    t=$(stat -f -c %T "$1" 2>/dev/null) && [ -n "$t" ] && { echo "$t"; return 0; }
    mp=$(df -P "$1" 2>/dev/null | awk 'NR == 2 { print $NF }')
    t=$(mount 2>/dev/null | awk -v mp="$mp" '$0 ~ " on " mp " \\(" { sub(/.*\(/, ""); sub(/,.*/, ""); print; exit }')
    echo "${t:-unknown}"
}

# hm2_owner_digest PATH...: entry count and a digest of the lstat metadata (name, type,
# size, mtime, inode) of every PATH, recursively for a directory. Names are only hashed
# and contents never read; nothing is printed but "<count>:<digest>", or "absent" when
# no PATH exists.
hm2_owner_digest() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3-unavailable"
        return 0
    fi
    python3 -I - "$@" <<'PY'
import hashlib, os, stat, sys
h = hashlib.sha256()
n = 0
def add(path, rel):
    global n
    try:
        st = os.lstat(path)
    except OSError:
        return
    n += 1
    h.update(("%s\0%o\0%d\0%d\0%d\n" % (rel, stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ino)).encode("utf-8", "surrogateescape"))
    if stat.S_ISDIR(st.st_mode):
        try:
            names = sorted(os.listdir(path))
        except OSError:
            h.update(b"unlistable\n")
            return
        for name in names:
            add(os.path.join(path, name), rel + "/" + name)
for i, p in enumerate(sys.argv[1:]):
    add(p, str(i))
print("absent" if n == 0 else "%d:%s" % (n, h.hexdigest()[:24]))
PY
}

# hm2_port: a random port in 20000-59999.
hm2_port() {
    local r
    r=$(od -An -N2 -tu2 /dev/urandom | tr -d ' \n')
    echo $((20000 + r % 40000))
}

# hm2_start_time PID: the process start time (Linux: /proc stat field 22; elsewhere ps).
hm2_start_time() {
    if [ -r "/proc/$1/stat" ]; then
        sed -e 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{ print $20 }'
    else
        ps -o lstart= -p "$1" 2>/dev/null | tr -s ' '
    fi
}

# hm2_sshd_config PORT DIR AUTHKEYS PENALTIES: the fixture configuration (as in
# heimdall-testkit's LoopbackSshd: loopback only, public keys only, restrict).
hm2_sshd_config() {
    cat <<EOF
ListenAddress 127.0.0.1
Port $1
AddressFamily inet
HostKey "$2/host_ed25519"
AuthorizedKeysFile "$3"
PidFile none
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
PermitUserRC no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
UseDNS no
MaxAuthTries 6
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF
    [ "$4" = 1 ] && echo "PerSourcePenalties no"
}

# hm2_sshd_start DIR AUTHKEYS LOG: start the fixture sshd (config and host key in DIR,
# created here with mode 700; authorized keys AUTHKEYS, created empty if absent; log
# LOG). On success sets HM2_SSHD_PID, HM2_SSHD_PORT, HM2_SSHD_HOSTKEY ("<type> <base64>")
# and HM2_SSHD_START, writes DIR/state (pid, start time) and returns 0. Otherwise sets
# HM2_SSHD_WHY (no path, no user) and returns 1.
hm2_sshd_start() {
    local dir=$1 ak=$2 log=$3 sshd attempt port pen i
    HM2_SSHD_PID="" HM2_SSHD_PORT="" HM2_SSHD_HOSTKEY="" HM2_SSHD_START="" HM2_SSHD_WHY=""
    sshd=$(hm2_sshd_bin) || { HM2_SSHD_WHY="sshd is not installed"; return 1; }
    [ "$(id -u)" != 0 ] || { HM2_SSHD_WHY="refusing to run the fixture sshd as root"; return 1; }
    mkdir -m 700 -- "$dir" 2>/dev/null || { HM2_SSHD_WHY="fixture directory exists or cannot be created"; return 1; }
    ssh-keygen -q -t ed25519 -N '' -C hm-m02-fixture-host -f "$dir/host_ed25519" </dev/null >/dev/null 2>&1 ||
        { HM2_SSHD_WHY="ssh-keygen failed"; return 1; }
    [ -e "$ak" ] || : >"$ak"
    chmod 600 "$ak" 2>/dev/null || true
    for attempt in 1 2 3 4 5; do
        port=$(hm2_port)
        pen=1
        hm2_sshd_config "$port" "$dir" "$ak" 1 >"$dir/sshd_config"
        if ! "$sshd" -t -f "$dir/sshd_config" </dev/null >/dev/null 2>&1; then
            # Servers before OpenSSH 9.8 do not know PerSourcePenalties.
            pen=0
            hm2_sshd_config "$port" "$dir" "$ak" 0 >"$dir/sshd_config"
            "$sshd" -t -f "$dir/sshd_config" </dev/null >/dev/null 2>&1 ||
                { HM2_SSHD_WHY="sshd -t rejected the fixture configuration"; return 1; }
        fi
        rm -f -- "$log"
        "$sshd" -D -f "$dir/sshd_config" -E "$log" </dev/null >/dev/null 2>&1 &
        HM2_SSHD_PID=$!
        i=0
        while [ $i -lt 100 ]; do
            if grep -q "Server listening on 127.0.0.1 port $port\." "$log" 2>/dev/null; then
                HM2_SSHD_PORT=$port
                HM2_SSHD_HOSTKEY=$(awk '{ print $1 " " $2 }' "$dir/host_ed25519.pub")
                HM2_SSHD_START=$(hm2_start_time "$HM2_SSHD_PID")
                printf 'pid=%s\nstart=%s\nconfig=%s\npenalties=%s\n' "$HM2_SSHD_PID" "$HM2_SSHD_START" \
                    "$dir/sshd_config" "$pen" >"$dir/state"
                return 0
            fi
            kill -0 "$HM2_SSHD_PID" 2>/dev/null || break
            sleep 0.1
            i=$((i + 1))
        done
        if kill -0 "$HM2_SSHD_PID" 2>/dev/null; then
            # Our own unreaped child: the PID cannot have been reused.
            kill "$HM2_SSHD_PID" 2>/dev/null || true
            wait "$HM2_SSHD_PID" 2>/dev/null || true
            HM2_SSHD_PID=""
            HM2_SSHD_WHY="sshd did not report listening within 10 s"
            return 1
        fi
        wait "$HM2_SSHD_PID" 2>/dev/null || true
        HM2_SSHD_PID=""
        if ! grep -q "Address already in use" "$log" 2>/dev/null; then
            HM2_SSHD_WHY="sshd exited before listening"
            return 1
        fi
        HM2_SSHD_WHY="port taken ($attempt attempts)"
    done
    return 1
}

# hm2_sshd_stop: stop the sshd this shell started (its own unreaped child), wait for it.
hm2_sshd_stop() {
    [ -n "${HM2_SSHD_PID:-}" ] || return 0
    # `|| true`: the reaped child's status is the signal that stopped it (143), which must
    # not end a caller that runs with `set -e`.
    kill "$HM2_SSHD_PID" 2>/dev/null || true
    wait "$HM2_SSHD_PID" 2>/dev/null || true
    HM2_SSHD_PID=""
}

# hm2_stop_recorded DIR: from another session, stop the sshd recorded in DIR/state, only
# when its start time and its configuration path still match (Linux /proc only).
# Prints what it did: none, stopped, gone or mismatch.
hm2_stop_recorded() {
    local pid start cfg now
    [ -f "$1/state" ] || { echo none; return 0; }
    pid=$(sed -n 's/^pid=//p' "$1/state")
    start=$(sed -n 's/^start=//p' "$1/state")
    cfg=$(sed -n 's/^config=//p' "$1/state")
    case "$pid" in '' | *[!0-9]*) echo none; return 0 ;; esac
    [ -r "/proc/$pid/stat" ] || { echo gone; return 0; }
    now=$(hm2_start_time "$pid")
    if [ -n "$start" ] && [ "$now" = "$start" ] && tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -qxF -- "$cfg"; then
        kill "$pid" 2>/dev/null || true
        echo stopped
    else
        echo mismatch
    fi
}
