#!/bin/bash
# Runs INSIDE the disposable distribution: how /tmp is mounted, and who cleans it at boot.
echo "pid1=$(ps -o comm= -p 1)"
findmnt -n -o TARGET,FSTYPE /tmp || echo "/tmp: no separate mount (exit $?)"
command -v systemctl >/dev/null && [ "$(ps -o comm= -p 1)" = systemd ] && for u in tmp.mount systemd-tmpfiles-setup.service systemd-tmpfiles-clean.timer; do printf '%s enabled=%s active=%s\n' "$u" "$(systemctl is-enabled "$u" 2>/dev/null)" "$(systemctl is-active "$u" 2>/dev/null)"; done
