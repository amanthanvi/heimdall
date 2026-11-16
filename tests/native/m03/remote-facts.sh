# shellcheck shell=bash
# M03-U13 (m03-plan §4.3): the extra facts tests/native/m03/run-linux.sh records on the
# Linux host, sent after tests/native/m02/remote-lib.sh (HM_EXTRA_REMOTE) and run after the
# version facts. Read-only; key=value lines only: no path, user, host or environment value.
#   ptrace-scope       /proc/sys/kernel/yama/ptrace_scope (linux_signer_not_ptraceable_by_same_user)
#   memlock-limit      `ulimit -l` (the signer's locked key pages)
#   ntp-synchronized   `timedatectl show -p NTPSynchronized --value`, read-only (Q13 observation)
#   gnome-keyring      whether gnome-keyring is installed (never installed; B11 row stays blocked)
hm_extra_facts() {
    local v
    v=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null) || v=absent
    echo "ptrace-scope=${v:-absent}"
    echo "memlock-limit=$(ulimit -l 2>/dev/null || echo unknown)"
    if command -v timedatectl >/dev/null 2>&1; then
        v=$(timedatectl show -p NTPSynchronized --value 2>/dev/null) || v=unknown
        echo "ntp-synchronized=${v:-unknown}"
    else
        echo "ntp-synchronized=timedatectl-absent"
    fi
    if command -v gnome-keyring-daemon >/dev/null 2>&1; then
        echo "gnome-keyring=installed"
    else
        echo "gnome-keyring=absent"
    fi
}
