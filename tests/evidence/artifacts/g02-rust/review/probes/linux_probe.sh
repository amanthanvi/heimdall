#!/bin/sh
# runs inside debian:bookworm-slim, --network none, /dist read-only
B=/dist/linux-arm64/heimdall-proto
echo "uname: $(uname -m)"; echo "ldd: $(ldd $B 2>&1 | head -1)"
show() { grep -E '^(SigBlk|SigIgn|SigCgt)' /proc/self/status | tr '\n' ' '; echo; }
echo "== baseline direct child";  sh -c 'grep -E "^(SigBlk|SigIgn)" /proc/self/status | tr "\n" " "'; echo
echo "== via run (default)"; $B run -- sh -c 'grep -E "^(SigBlk|SigIgn)" /proc/self/status | tr "\n" " "'; echo " rc=$?"
echo "== nohup-like (trap '' HUP INT QUIT TERM) direct"; sh -c "trap '' HUP INT QUIT TERM; exec sh -c 'grep -E \"^SigIgn\" /proc/self/status'"
echo "== nohup-like via run"; sh -c "trap '' HUP INT QUIT TERM; exec $B run -- sh -c 'grep -E \"^SigIgn\" /proc/self/status'"; echo " rc=$?"
echo "== background job in non-interactive sh: direct"; sh -c 'sh -c "grep -E ^SigIgn /proc/self/status" & wait'
echo "== background job in non-interactive sh: via run"; sh -c "$B run -- sh -c 'grep -E ^SigIgn /proc/self/status' & wait"
echo "== zombie check: parent of child while child runs"; $B run -- sh -c 'sleep 0.3; ps -o pid,ppid,stat,comm 2>/dev/null || cat /proc/$PPID/status | grep -E "^(Name|State)"'; echo rc=$?
echo "== no zombies after run, list all processes"; ls /proc | grep -E '^[0-9]+$' | while read p; do s=$(grep -E '^State' /proc/$p/status 2>/dev/null); case "$s" in *Z*) echo "ZOMBIE $p";; esac; done; echo "zombie-scan done"
echo "== /proc/self/exe identity independent of argv0"; (exec -a /bin/evil $B version --json); echo rc=$?
