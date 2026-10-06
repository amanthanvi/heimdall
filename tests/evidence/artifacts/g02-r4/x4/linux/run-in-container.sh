#!/bin/bash
# Entry: private session bus, then inner.sh. X4_NO_BUS=1 skips the bus entirely.
export HOME=/home/x4
unset SSH_AUTH_SOCK
mkdir -p "$HOME/.local/share/keyrings"
if [ "${X4_NO_BUS:-0}" = 1 ]; then unset DBUS_SESSION_BUS_ADDRESS; X4_NO_SS=1 exec /bin/bash /opt/x4/inner.sh "$@"; fi
exec dbus-run-session -- /bin/bash /opt/x4/inner.sh "$@"
