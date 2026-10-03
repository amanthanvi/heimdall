#!/bin/bash
# Runs as root inside the fixture container. Installs per-role material staged by
# up.sh under /fixture (copied with `docker cp` before start), then execs sshd.
set -eu
[ -f /fixture/role.env ] || { echo "fixture: /fixture/role.env missing" >&2; exit 64; }
# shellcheck disable=SC1091
. /fixture/role.env   # ROLE, ACCOUNT, KEYS_MODE (root|account)

id "$ACCOUNT" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$ACCOUNT"
usermod -p '*' "$ACCOUNT"          # not locked ('!'), but no password login possible

install -m 0600 -o root -g root /fixture/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
install -m 0644 -o root -g root /fixture/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
install -m 0644 -o root -g root /fixture/sshd_config /etc/ssh/sshd_config_fixture

case "$KEYS_MODE" in
  root)    # registry is root-owned and read-only to the account (no remote writes)
    install -d -m 0755 -o root -g root /etc/ssh/authorized_keys.d
    install -m 0644 -o root -g root /fixture/authorized_keys "/etc/ssh/authorized_keys.d/$ACCOUNT"
    chown root:root "/home/$ACCOUNT"; chmod 0755 "/home/$ACCOUNT"
    ;;
  account) # account owns and may edit its own registry
    install -d -m 0700 -o "$ACCOUNT" -g "$ACCOUNT" "/home/$ACCOUNT/.ssh"
    install -m 0600 -o "$ACCOUNT" -g "$ACCOUNT" /fixture/authorized_keys "/home/$ACCOUNT/.ssh/authorized_keys"
    ;;
  ca)      # trust the disposable user CA; principals mapped by a root-owned file
    install -m 0644 -o root -g root /fixture/user_ca.pub /etc/ssh/user_ca.pub
    install -d -m 0755 -o root -g root /etc/ssh/principals
    install -m 0644 -o root -g root /fixture/principals "/etc/ssh/principals/$ACCOUNT"
    chown root:root "/home/$ACCOUNT"; chmod 0755 "/home/$ACCOUNT"
    ;;
  *) echo "fixture: bad KEYS_MODE" >&2; exit 64 ;;
esac

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config_fixture -o PidFile=/run/sshd-fixture.pid
