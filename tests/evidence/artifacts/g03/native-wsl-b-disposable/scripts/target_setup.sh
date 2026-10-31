#!/bin/bash
# Runs INSIDE the disposable distribution as root: one non-root uid-1000 user as the default
# user (the image's interactive OOBE would create one; it is not run here).
set -u
if ! getent passwd 1000 >/dev/null; then useradd -m -u 1000 -U -s /bin/bash hg03t; echo "useradd exit $?"; fi
if ! grep -q '^\[user\]' /etc/wsl.conf; then printf '\n[user]\ndefault=hg03t\n' >> /etc/wsl.conf; echo "wsl.conf [user] appended exit $?"; fi
