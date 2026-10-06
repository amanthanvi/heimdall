#!/bin/bash
set -euo pipefail
T=M00-T04-G03-native-windows
S=~/hm-m00/$T
W=$(cat $S/winscratch.path)
F=$S/fixture; mkdir -p $F; chmod 700 $F
# pick a free loopback port
for i in $(seq 1 50); do P=$((40000 + RANDOM % 20000)); ss -ltn "( sport = :$P )" | grep -q LISTEN || break; done
echo $P > $F/port
ssh-keygen -q -t ed25519 -N '' -C hm-g03-fixture-hostkey -f $F/hostkey
: > "$W/fixture/authorized_keys"
cat > $F/sshd_config <<CFG
Port $P
ListenAddress 127.0.0.1
HostKey $F/hostkey
PidFile $F/sshd.pid
AuthorizedKeysFile $W/fixture/authorized_keys
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
/usr/sbin/sshd -t -f $F/sshd_config
# disposable bare repo with one commit
rm -rf $F/probe.git $F/work
git init -q --bare $F/probe.git
git init -q $F/work && cd $F/work && echo probe > README && git add README && git -c user.name=g03 -c user.email=g03@invalid commit -q -m probe && git push -q $F/probe.git HEAD:refs/heads/main && cd $F && rm -rf $F/work
git --git-dir=$F/probe.git symbolic-ref HEAD refs/heads/main
setsid nohup /usr/sbin/sshd -D -f $F/sshd_config -E $F/sshd.log < /dev/null > /dev/null 2>&1 &
echo $! > $F/sshd.launcher.pid
sleep 1
echo "[127.0.0.1]:$P $(cut -d' ' -f1,2 $F/hostkey.pub)" > "$W/fixture/known_hosts"
ps -o pid=,ppid=,lstart=,comm= -p $(cat $F/sshd.launcher.pid)
ss -ltn "( sport = :$P )" | tail -n +2 | awk '{print $1, $4}'
echo port=$P
