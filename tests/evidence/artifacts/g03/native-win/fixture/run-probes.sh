#!/bin/bash
# usage: run-probes.sh <pwsh|ps51> <probes-csv> <outdir-rel>
T=M00-T04-G03-native-windows
S=~/hm-m00/$T
W=$(cat $S/winscratch.path)
WW=$(wslpath -w "$W")
P=$(cat $S/fixture/port)
U=$(id -un)
exec $S/wrun.sh "$1" -File launch.ps1 -Target repo/tests/native/windows/Invoke-G03WindowsProbes.ps1 -Probes "$2" -OutDir "$WW\\$3" \
  -SshHost 127.0.0.1 -SshPort "$P" -SshUser "$U" -KnownHostsFile "$WW\\fixture\\known_hosts" \
  -AuthorizeKeyScript "$WW\\authorize.ps1" -GitRemoteUrl "ssh://$U@127.0.0.1:$P/~/hm-m00/$T/fixture/probe.git"
