#!/bin/bash
# Runs INSIDE the disposable distribution: facts only.
echo "user=$(id -un) uid=$(id -u)"
. /etc/os-release; echo "os=$PRETTY_NAME"
echo "pid1=$(ps -o comm= -p 1)"
command -v systemctl >/dev/null && echo "systemd_state=$(systemctl is-system-running 2>/dev/null)"
for t in python3 ssh-keygen ssh-agent ssh-add setsid nohup awk sed wslinfo; do printf '%s=%s\n' "$t" "$(command -v "$t" || echo MISSING)"; done
echo "python=$(python3 --version 2>&1)"; echo "ssh=$(ssh -V 2>&1)"
echo "net_ns=$(readlink /proc/self/ns/net) mnt_ns=$(readlink /proc/self/ns/mnt)"
echo "uid1000_user=$(getent passwd 1000 | cut -d: -f1)"
echo "--- /etc/wsl.conf"; cat /etc/wsl.conf
