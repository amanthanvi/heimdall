#!/bin/bash
# Disposable loopback fixture: sshd A (public-key, scratch authorized_keys, scratch bare repo)
# and sshd B (certificate-only: TrustedUserCAKeys = per-run disposable user CA, no authorized_keys).
set -euo pipefail
T=M00-T04-G03-native-wsl
S=$HOME/hm-m00/$T
F=$S/fixture; mkdir -p $F; chmod 700 $F
freeport() { local P; for i in $(seq 1 50); do P=$((40000 + RANDOM % 20000)); ss -ltn "( sport = :$P )" | grep -q LISTEN || { echo $P; return; }; done; return 1; }
PA=$(freeport); PB=$(freeport); [ "$PA" != "$PB" ]
echo $PA > $F/portA; echo $PB > $F/portB
ssh-keygen -q -t ed25519 -N '' -C hm-g03-wsl-fixture-hostkey -f $F/hostkey
ssh-keygen -q -t ed25519 -N '' -C hm-g03-wsl-disposable-user-ca -f $F/user_ca
: > $F/authorized_keys
common() { cat <<CFG
ListenAddress 127.0.0.1
HostKey $F/hostkey
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers $(id -un)
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
PrintMotd no
PrintLastLog no
MaxStartups 50:30:100
LogLevel VERBOSE
CFG
}
{ echo "Port $PA"; echo "PidFile $F/sshdA.pid"; echo "AuthorizedKeysFile $F/authorized_keys"; common; } > $F/sshdA_config
{ echo "Port $PB"; echo "PidFile $F/sshdB.pid"; echo "AuthorizedKeysFile none"; echo "TrustedUserCAKeys $F/user_ca.pub"; common; } > $F/sshdB_config
/usr/sbin/sshd -t -f $F/sshdA_config; /usr/sbin/sshd -t -f $F/sshdB_config
rm -rf $F/probe.git $F/work
git init -q --bare $F/probe.git
git init -q $F/work && cd $F/work && echo probe > README && git add README && git -c user.name=g03 -c user.email=g03@invalid commit -q -m probe && git push -q $F/probe.git HEAD:refs/heads/main && cd $F && rm -rf $F/work
git --git-dir=$F/probe.git symbolic-ref HEAD refs/heads/main
for X in A B; do
  setsid nohup /usr/sbin/sshd -D -f $F/sshd${X}_config -E $F/sshd$X.log < /dev/null > /dev/null 2>&1 &
  echo $! > $F/sshd$X.launcher.pid
done
sleep 1
{ echo "[127.0.0.1]:$PA $(cut -d' ' -f1,2 $F/hostkey.pub)"; echo "[127.0.0.1]:$PB $(cut -d' ' -f1,2 $F/hostkey.pub)"; } > $F/known_hosts
for X in A B; do ps -o pid=,ppid=,lstart=,comm= -p $(cat $F/sshd$X.launcher.pid); done
ss -ltn "( sport = :$PA or sport = :$PB )" | tail -n +2 | awk '{print $1, $4}'
echo portA=$PA portB=$PB
