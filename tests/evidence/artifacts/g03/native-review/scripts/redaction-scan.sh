#!/bin/bash
# Counts (never prints) occurrences of this host's identifying values in the evidence copy.
T=M00-T04-G03-native-review
E=$HOME/hm-m00/$T/evid
WU=$(cd /mnt/c && /mnt/c/Windows/System32/cmd.exe /d /c 'echo %USERNAME%' | tr -d '\r\n')
WH=$(cd /mnt/c && /mnt/c/Windows/System32/cmd.exe /d /c 'echo %COMPUTERNAME%' | tr -d '\r\n')
LU=$(id -un); LH=$(hostname)
c() { local n; n=$(grep -railF -- "$2" "$E" 2>/dev/null | wc -l); echo "$1 (len ${#2}): files=$n"; }
c windows_user "$WU"; c windows_host "$WH"; c linux_user "$LU"; c linux_hostname "$LH"
c wsl_home "$HOME"; c win_profile_bs "C:\\Users\\$WU"; c win_profile_fs "C:/Users/$WU"; c win_profile_mnt "/mnt/c/Users/$WU"
echo "full canary values: $(grep -raoE 'HEIMDALL_CANARY_[A-Za-z0-9_]{6,}' "$E" | wc -l)"
echo "email-shaped (non-openssh.com): $(grep -raohE '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' "$E" | grep -vc '@openssh\.com$')"
