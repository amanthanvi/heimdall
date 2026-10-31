#!/bin/bash
# Runs INSIDE the disposable distribution as root: supplementary no-systemd configuration (r3 only).
sed -i 's/^systemd=true$/systemd=false/' /etc/wsl.conf; echo "sed exit $?"; cat /etc/wsl.conf
