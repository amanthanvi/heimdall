#!/usr/bin/env bash
# M02-U11: root-side preparation inside the disposable WSL distribution that
# run-wsl-distro.sh imported (ADR-0004 §3: that distribution only). Never run elsewhere:
# it refuses unless WSL_DISTRO_NAME is the name it was given.
#
# Usage (as root, through `wsl.exe -d <name> -u root --exec /bin/bash`):
#   target-root.sh NAME no-systemd
#       write `[boot] systemd=false` into this distribution's /etc/wsl.conf, so after the
#       caller's `wsl --terminate` no service of the image starts at all;
#   target-root.sh NAME prepare USER ALLOW_APT FILES
#       record the image's facts; when ssh, sshd, scp, sftp, ssh-agent, ssh-keygen,
#       ssh-add, git or python3 is missing: stop with exit 3 unless ALLOW_APT=1, else
#       install openssh-server, openssh-sftp-server and git from the image's own archive
#       with every service blocked first (policy-rc.d exit 101, ssh.service and
#       ssh.socket masked); create the non-root USER with a disposable home; install
#       FILES/heimdall as that user's ~/heimdall;
#   target-root.sh NAME listeners
#       count listening TCP sockets, loopback and other, with nothing else printed.
#   ⟨M03 wave 6⟩ target-root.sh NAME m03-sshd-start USER FILES
#       (HM_ROOT_PHASES before tests/native/m03/scenario-managed.sh) two root sshds on
#       127.0.0.1 only, one per enrollment form (ADR-0008 D5), each with its own per-run
#       host key, StrictModes yes, public keys only, AllowUsers USER, LogLevel VERBOSE:
#         * account form: AuthorizedKeysFile .ssh/authorized_keys, the account's default
#           registry path;
#         * system form: TrustedUserCAKeys and AuthorizedPrincipalsFile <dir>/principals/%u,
#           both files owned by USER (the owner's manual install of D5 §6.9 is the
#           scenario's step), and .ssh/authorized_keys for the existing access.
#       Everything lives in M03_DIR (created here; an existing one is refused). USER's
#       locked password ('!', which sshd without PAM treats as a locked account) becomes
#       '*' (no password; password logins are off). The scenario reads M03_DIR/sshd.env
#       (ports, host keys, the effective StrictModes and registry settings) and the two
#       logs (M03_DIR/<form>.log, mode 644). FILES holds remote-lib.sh.
#   ⟨M03 wave 6⟩ target-root.sh NAME m03-sshd-stop USER FILES
#       (the after phase) stop each sshd only when its recorded PID still has the
#       recorded start time and configuration (remote-lib.sh hm2_stop_recorded), report
#       the certificate logins each logged, and remove M03_DIR when both are stopped.
# Output: `key=value` facts only (no user, host or path outside the distribution).

set -u
name=${1:?usage: target-root.sh NAME no-systemd|prepare|listeners|m03-sshd-start|m03-sshd-stop ...}
phase=${2:?usage: target-root.sh NAME no-systemd|prepare|listeners|m03-sshd-start|m03-sshd-stop ...}
# ⟨M03 wave 6⟩ The root sshds' directory (scenario-managed.sh reads the same constant).
M03_DIR=/etc/ssh/hm-m03
[ "${WSL_DISTRO_NAME:-}" = "$name" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "refusing: needs root inside the disposable distribution" >&2; exit 2; }

listeners() {
    local lo=0 other=0 a
    for a in $(ss -ltnH 2>/dev/null | awk '{ print $4 }'); do
        case "$a" in 127.* | '[::1]':* | ::1:*) lo=$((lo + 1)) ;; *) other=$((other + 1)) ;; esac
    done
    echo "listeners-loopback=$lo"
    echo "listeners-other=$other"
}

# ⟨M03 wave 6⟩ m03_sshd_config FORM PORT USER PENALTIES: one root sshd's configuration.
m03_sshd_config() {
    cat <<EOF
ListenAddress 127.0.0.1
Port $2
AddressFamily inet
HostKey $M03_DIR/$1/host_ed25519
PidFile $M03_DIR/$1/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitRootLogin no
AllowUsers $3
PermitUserRC no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
UseDNS no
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF
    if [ "$1" = system ]; then
        echo "TrustedUserCAKeys $M03_DIR/trusted_user_ca_keys"
        echo "AuthorizedPrincipalsFile $M03_DIR/principals/%u"
    fi
    [ "$4" = 1 ] && echo "PerSourcePenalties no"
    return 0
}

# ⟨M03 wave 6⟩ m03_sshd_start FORM USER SSHD: start one root sshd (it daemonizes and
# writes its PID file once its socket is bound), record pid/start/config in
# M03_DIR/FORM/state for hm2_stop_recorded, and append its facts to sshd.env.
m03_sshd_start() {
    local form=$1 user=$2 sshd=$3 d="$M03_DIR/$1" log="$M03_DIR/$1.log" attempt port pen i pid eff
    mkdir -m 700 "$d" || return 1
    ssh-keygen -q -t ed25519 -N '' -C hm-m03-wsl-host -f "$d/host_ed25519" </dev/null >/dev/null 2>&1 || return 1
    for attempt in 1 2 3 4 5; do
        port=$(hm2_port)
        pen=1
        m03_sshd_config "$form" "$port" "$user" 1 >"$d/sshd_config"
        if ! "$sshd" -t -f "$d/sshd_config" </dev/null >/dev/null 2>&1; then
            # OpenSSH before 9.8 (Ubuntu 24.04 has 9.6p1) does not know PerSourcePenalties.
            pen=0
            m03_sshd_config "$form" "$port" "$user" 0 >"$d/sshd_config"
            "$sshd" -t -f "$d/sshd_config" </dev/null >/dev/null 2>&1 ||
                { echo "m03-sshd-$form=refused (sshd -t rejected the configuration)"; return 1; }
        fi
        rm -f -- "$d/sshd.pid"
        install -m 644 /dev/null "$log" || return 1
        "$sshd" -f "$d/sshd_config" -E "$log" </dev/null >/dev/null 2>&1 || true
        i=0
        while [ $i -lt 100 ]; do
            grep -q "Server listening on 127.0.0.1 port $port\." "$log" 2>/dev/null && [ -s "$d/sshd.pid" ] && break
            grep -q "Cannot bind any address" "$log" 2>/dev/null && break
            sleep 0.1
            i=$((i + 1))
        done
        if grep -q "Server listening on 127.0.0.1 port $port\." "$log" 2>/dev/null && [ -s "$d/sshd.pid" ]; then
            pid=$(cat "$d/sshd.pid")
            printf 'pid=%s\nstart=%s\nconfig=%s\npenalties=%s\n' "$pid" "$(hm2_start_time "$pid")" \
                "$d/sshd_config" "$pen" >"$d/state"
            eff=$("$sshd" -T -f "$d/sshd_config" -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null)
            val() { printf '%s\n' "$eff" | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }'; }
            {
                echo "${form}_port=$port"
                echo "${form}_host_key=$(awk '{ print $1 " " $2 }' "$d/host_ed25519.pub")"
                echo "${form}_strictmodes=$(val strictmodes)"
                echo "${form}_authorizedkeysfile=$(val authorizedkeysfile)"
                echo "${form}_trustedusercakeys=$([ "$(val trustedusercakeys)" = "$M03_DIR/trusted_user_ca_keys" ] && echo set || echo none)"
                echo "${form}_authorizedprincipalsfile=$([ "$(val authorizedprincipalsfile)" = "$M03_DIR/principals/%u" ] && echo set || echo none)"
            } >>"$M03_DIR/sshd.env"
            echo "m03-sshd-$form=listening on 127.0.0.1 (attempt $attempt)"
            echo "m03-sshd-$form-effective=strictmodes $(val strictmodes); authorizedkeysfile $(val authorizedkeysfile); usepam $(val usepam); passwordauthentication $(val passwordauthentication); loglevel $(val loglevel)"
            return 0
        fi
        if ! grep -q "Address already in use" "$log" 2>/dev/null; then
            echo "m03-sshd-$form=unavailable (sshd exited or did not report listening within 10 s)"
            return 1
        fi
    done
    echo "m03-sshd-$form=unavailable (port taken, 5 attempts)"
    return 1
}

case "$phase" in
    no-systemd)
        conf=/etc/wsl.conf
        [ -f "$conf" ] || : >"$conf"
        python3 -I - "$conf" <<'PY' || exit 1
import configparser, sys
path = sys.argv[1]
c = configparser.ConfigParser()
c.optionxform = str
c.read(path)
if not c.has_section("boot"):
    c.add_section("boot")
c.set("boot", "systemd", "false")
with open(path, "w") as f:
    c.write(f)
PY
        echo "wsl-conf-systemd=false"
        ;;
    prepare)
        user=${3:?user}
        allow_apt=${4:?allow_apt}
        files=${5:?files}
        case "$user" in '' | *[!a-z0-9_-]* | [!a-z]*) echo "bad user name" >&2; exit 2 ;; esac
        # shellcheck disable=SC1091  # the distribution's own file
        echo "os=$(. /etc/os-release && echo "$PRETTY_NAME")"
        echo "pid1=$(ps -p 1 -o comm= 2>/dev/null)"
        have() { command -v "$1" >/dev/null 2>&1 || [ -x "/usr/sbin/$1" ]; }
        missing=""
        for t in ssh sshd scp sftp ssh-agent ssh-keygen ssh-add git python3; do
            have "$t" || missing="$missing $t"
        done
        [ -x /usr/lib/openssh/sftp-server ] || [ -x /usr/libexec/sftp-server ] || missing="$missing sftp-server"
        echo "missing-tools=${missing:- none}"
        if [ -n "$missing" ]; then
            if [ "$allow_apt" != 1 ]; then
                echo "blocked=the pinned image lacks:$missing (HM_WSL_ALLOW_APT=1 installs them inside this distribution)"
                exit 3
            fi
            printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
            chmod 755 /usr/sbin/policy-rc.d
            mkdir -p /etc/systemd/system
            ln -sf /dev/null /etc/systemd/system/ssh.service
            ln -sf /dev/null /etc/systemd/system/ssh.socket
            DEBIAN_FRONTEND=noninteractive apt-get -q update >/dev/null 2>&1 &&
                DEBIAN_FRONTEND=noninteractive apt-get -q -y install --no-install-recommends \
                    openssh-server openssh-sftp-server git >/dev/null 2>&1
            echo "apt-install-exit=$?"
            missing=""
            for t in ssh sshd scp sftp ssh-agent ssh-keygen ssh-add git python3; do
                have "$t" || missing="$missing $t"
            done
            echo "missing-tools-after-install=${missing:- none}"
            [ -z "$missing" ] || exit 3
        fi
        id -u "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user" || exit 1
        echo "user=created (non-root, disposable home)"
        install -o "$user" -g "$user" -m 755 "$files/heimdall" "/home/$user/heimdall" || exit 1
        echo "heimdall-installed=yes"
        listeners
        ;;
    listeners)
        listeners
        ;;
    m03-sshd-start)
        user=${3:?user}
        files=${4:?files}
        case "$user" in '' | *[!a-z0-9_-]* | [!a-z]*) echo "bad user name" >&2; exit 2 ;; esac
        id -u "$user" >/dev/null 2>&1 || { echo "m03-sshd=refused (the user does not exist)"; exit 1; }
        # shellcheck source=tests/native/m02/remote-lib.sh
        . "$files/remote-lib.sh" || exit 1
        sshd=$(hm2_sshd_bin) || { echo "m03-sshd=unavailable (sshd is not installed)"; exit 3; }
        [ ! -e "$M03_DIR" ] || { echo "m03-sshd=refused (the directory exists)"; exit 1; }
        mkdir -m 755 "$M03_DIR" "$M03_DIR/principals" || exit 1
        : >"$M03_DIR/sshd.env"
        chmod 644 "$M03_DIR/sshd.env"
        # The privilege separation directory (no service of the image created it).
        [ -d /run/sshd ] || mkdir -m 755 /run/sshd || exit 1
        # sshd without PAM refuses an account whose password field is locked ('!').
        case "$(getent shadow "$user" | cut -d: -f2)" in
            '!'*) usermod -p '*' "$user" || exit 1; echo "m03-account-password=locked, set to none (no password login: PasswordAuthentication no)" ;;
            *) echo "m03-account-password=not locked" ;;
        esac
        # The system registry's two files, the owner's to install lines into (D5 §6.9).
        install -o "$user" -g "$user" -m 644 /dev/null "$M03_DIR/trusted_user_ca_keys" || exit 1
        install -o "$user" -g "$user" -m 644 /dev/null "$M03_DIR/principals/$user" || exit 1
        rc=0
        m03_sshd_start account "$user" "$sshd" || rc=1
        [ "$rc" = 0 ] && { m03_sshd_start system "$user" "$sshd" || rc=1; }
        echo "m03-sshd-V=$(hm2_first_line "$sshd" -V)"
        listeners
        exit "$rc"
        ;;
    m03-sshd-stop)
        user=${3:?user}
        files=${4:?files}
        # shellcheck source=tests/native/m02/remote-lib.sh
        . "$files/remote-lib.sh" || exit 1
        [ -d "$M03_DIR" ] || { echo "m03-sshd-stop=none (no directory)"; exit 0; }
        rc=0
        for form in account system; do
            r=$(hm2_stop_recorded "$M03_DIR/$form")
            echo "m03-sshd-$form-stop=$r"
            case "$r" in stopped | none) ;; *) rc=1 ;; esac
            echo "m03-sshd-$form-accepted-certificate-logins=$(grep -c 'Accepted certificate ID ' "$M03_DIR/$form.log" 2>/dev/null)"
            echo "m03-sshd-$form-accepted-publickey-logins=$(grep -c 'Accepted publickey for ' "$M03_DIR/$form.log" 2>/dev/null)"
        done
        if [ "$rc" = 0 ]; then
            rm -rf -- "$M03_DIR"
            echo "m03-sshd-dir-removed=$([ -e "$M03_DIR" ] && echo no || echo yes)"
        fi
        exit "$rc"
        ;;
    *)
        echo "unknown phase" >&2
        exit 2
        ;;
esac
