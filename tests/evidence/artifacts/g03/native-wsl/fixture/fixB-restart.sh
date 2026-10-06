#!/bin/bash
set -euo pipefail
T=M00-T04-G03-native-wsl
S=$HOME/hm-m00/$T; F=$S/fixture
OLD=$(cat $F/sshdB.launcher.pid)
# exact-PID stop: must be our sshd with our config path
if [ -r /proc/$OLD/cmdline ] && tr '\0' ' ' < /proc/$OLD/cmdline | grep -q -- "-f $F/sshdB_config"; then kill -TERM $OLD; sleep 1; fi
kill -0 $OLD 2>/dev/null && { echo "old sshd B still running"; exit 1; }
EXCL=$(cd /mnt/c && /mnt/c/Windows/System32/netsh.exe int ipv4 show excludedportrange protocol=tcp | tr -d '\r' | awk '/^ +[0-9]/{print $1, $2}')
okport() { local p=$1 a b; while read -r a b; do [ -n "$a" ] && [ "$p" -ge "$a" ] && [ "$p" -le "$b" ] && return 1; done <<< "$EXCL"; ss -ltn "( sport = :$p )" | grep -q LISTEN && return 1; return 0; }
for i in $(seq 1 100); do P=$((40000 + RANDOM % 9000)); okport $P && break; done
PA=$(cat $F/portA); okport_a=$(okport $PA && echo free-or-ok || echo in-use-or-excluded); echo "portA $PA check: $okport_a (in use by sshd A expected)"
sed -i "s/^Port .*/Port $P/" $F/sshdB_config
/usr/sbin/sshd -t -f $F/sshdB_config
echo $P > $F/portB
setsid nohup /usr/sbin/sshd -D -f $F/sshdB_config -E $F/sshdB.log < /dev/null > /dev/null 2>&1 &
echo $! > $F/sshdB.launcher.pid
sleep 1
{ echo "[127.0.0.1]:$PA $(cut -d' ' -f1,2 $F/hostkey.pub)"; echo "[127.0.0.1]:$P $(cut -d' ' -f1,2 $F/hostkey.pub)"; } > $F/known_hosts
ps -o pid=,lstart=,comm= -p $(cat $F/sshdB.launcher.pid)
sleep 4
cd /mnt/c && /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -Command "\$c=New-Object Net.Sockets.TcpClient; try{ \$c.Connect('127.0.0.1',$P); 'portB $P connect ok from Windows' } catch { 'portB $P ' + \$_.Exception.InnerException.Message } finally { \$c.Close() }" | tr -d '\r'
