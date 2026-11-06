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
# Output: `key=value` facts only (no user, host or path outside the distribution).

set -u
name=${1:?usage: target-root.sh NAME no-systemd|prepare|listeners ...}
phase=${2:?usage: target-root.sh NAME no-systemd|prepare|listeners ...}
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
    *)
        echo "unknown phase" >&2
        exit 2
        ;;
esac
