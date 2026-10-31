#!/bin/sh
# Print the identity and every socket of ONE exact PID (Linux). No command lines, no env.
# Socket fds are matched by inode against this PID's namespace tables (/proc/PID/net/*),
# so other processes' sockets are never listed. Addresses are decoded from hex.
p=$1
[ -d /proc/$p ] || { echo "pid $p: gone"; exit 0; }
exe=$(basename "$(readlink /proc/$p/exe 2>/dev/null)")
ppid=$(awk '/^PPid:/{print $2}' /proc/$p/status 2>/dev/null)
echo "pid $p exe=$exe ppid=$ppid"
inodes=$(ls -l /proc/$p/fd 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p')
n=0; for i in $inodes; do n=$((n+1)); done
echo "  socket_fds=$n"
for i in $inodes; do
  hit=0
  for t in udp udp6 tcp tcp6 raw raw6 udplite udplite6; do
    line=$(awk -v ino="$i" 'NR>1 && $10==ino {print $2, $3, $4}' /proc/$p/net/$t 2>/dev/null)
    if [ -n "$line" ]; then
      hit=1
      set -- $line
      echo "  inode $i: $t local=$(hex2addr "$1" 2>/dev/null || echo "$1") remote=$2 st=$3"
    fi
  done
  if [ $hit = 0 ]; then
    nl=$(awk -v ino="$i" 'NR>1 && $NF==ino {print "proto="$2}' /proc/$p/net/netlink 2>/dev/null)
    [ -n "$nl" ] && { echo "  inode $i: netlink $nl (0=NETLINK_ROUTE)"; hit=1; }
  fi
  if [ $hit = 0 ]; then
    ux=$(awk -v ino="$i" 'NR>1 && $7==ino {print "unix"}' /proc/$p/net/unix 2>/dev/null)
    [ -n "$ux" ] && { echo "  inode $i: unix"; hit=1; }
  fi
  [ $hit = 0 ] && echo "  inode $i: not found in inet/netlink/unix tables"
done
echo "  lsof -i (inet sockets of this pid):"
lsof -nP -a -p "$p" -i 2>/dev/null | awk 'NR>1{print "    "$5,$8,$9,$10}'
echo "  ss -uatpn rows owned by this pid:"
ss -uatpn 2>/dev/null | grep "pid=$p," | awk '{print "    "$1,$2,$5,$6}'
