#!/bin/sh
# Runs inside `docker run --network none` (busybox sh). /x5 holds x5-iroh and x5-gosup.
# 1) one-process selftest; 2) Go supervisor + two helpers, inspecting the exact helper PIDs'
# sockets from /proc while the supervisor holds. Prints interfaces, results, exit codes.
set -u
echo "## interfaces in this network namespace:"; ls /sys/class/net
echo "## uname -m: $(uname -m)"
echo "## selftest"
/x5/x5-iroh selftest --hold-ms 2500 > /tmp/st.out 2> /tmp/st.err &
P=$!; sleep 1.2
echo "selftest sockets (pid $P, /proc/$P/net/udp local_address:port, hex):"
awk 'NR>1{print "  "$2, "st="$4}' /proc/$P/net/udp
echo "  udp6:"; awk 'NR>1{print "  "$2}' /proc/$P/net/udp6
echo "  tcp:";  awk 'NR>1{print "  "$2, "st="$4}' /proc/$P/net/tcp
echo "  socket fds: $(ls -l /proc/$P/fd 2>/dev/null | grep -c socket:)"
wait $P; echo "selftest_exit=$?"; cat /tmp/st.out; sed -E 's/pid [0-9]+/pid <pid>/' /tmp/st.err
echo "## go supervisor"
/x5/x5-gosup -helper /x5/x5-iroh -hold-ms 2500 > /tmp/g.out 2> /tmp/g.err &
G=$!; sleep 1.5
PIDS=$(sed -n 's/.*pid \([0-9]*\), helper A pid \([0-9]*\), helper B pid \([0-9]*\).*/\1 \2 \3/p' /tmp/g.err)
for p in $PIDS; do
  echo "pid $p exe=$(basename "$(readlink /proc/$p/exe)") ppid=$(awk '/^PPid:/{print $2}' /proc/$p/status) socket_fds=$(ls -l /proc/$p/fd 2>/dev/null | grep -c socket:)"
done
echo "UDP sockets in namespace (local_address:port hex; 0100007F = 127.0.0.1):"
awk 'NR>1{print "  "$2}' /proc/net/udp
echo "UDP6:"; awk 'NR>1{print "  "$2}' /proc/net/udp6
wait $G; echo "gosup_exit=$?"; cat /tmp/g.out; sed -E 's/pid [0-9]+/pid <pid>/g' /tmp/g.err
