# Linux container smoke for the §9 alignment (K5, K6, K8, K11). Runs inside
# debian:trixie with --network none; /d = dist/<target> (ro), /f = fixtures (ro).
set -u
B=/d/heimdall-proto
echo "--- command -v bun node: $(command -v bun node || echo none)"
$B version --json; echo "exit=$?"
echo "--- run basics + K5 state"
$B run --meta-file /tmp/m.json -- sh -c 'printf "%s|" "$@"; exit 7' x 'a b' '$HOME' ';*' 'ü'; echo " exit=$?"; cat /tmp/m.json
$B run --meta-file /tmp/m.json -- sh -c 'kill -TERM $$'; echo "exit=$?"; cat /tmp/m.json
$B run --meta-file /tmp/m2.json -- does-not-exist-xyz; echo "exit=$?"; cat /tmp/m2.json
printf '\000\377binary' | $B run -- cat | od -An -tx1
echo "--- env passthrough of a non-UTF-8 value (bytes)"
env "G02_RAW=$(printf 'a\377b')" $B run -- sh -c 'printf %s "$G02_RAW"' | od -An -tx1
echo "--- K8: argv element with invalid UTF-8 (expected stack limitation)"
$B run -- sh -c 'printf %s "$1"' sh "$(printf 'a\377b')" | od -An -tx1
echo "--- K6: child in its own process group (no tty)"
$B run -- sh -c 'read -r _ _ _ _ pg _ < /proc/$$/stat; echo "pid=$$ pgrp=$pg"'
echo "--- K6: explicit kill -INT to proto, no tty: child count"
cat > /tmp/child.sh <<'C'
trap 'echo INT >> /tmp/log' INT
trap 'echo QUIT >> /tmp/log' QUIT
echo ready >> /tmp/log
while [ ! -f /tmp/stop ]; do sleep 0.05; done
exit 3
C
rm -f /tmp/log /tmp/stop
$B run -- sh /tmp/child.sh & P=$!
while ! grep -q ready /tmp/log 2>/dev/null; do sleep 0.05; done
kill -INT $P; kill -QUIT $P; sleep 0.5; touch /tmp/stop; wait $P; echo "proto exit=$?"
echo "INT=$(grep -c INT /tmp/log) QUIT=$(grep -c QUIT /tmp/log)"
echo "--- K6 under a PTY (script(1)): terminal ^C once, then explicit kill -INT to proto once, fg group restored"
rm -f /tmp/log /tmp/stop /tmp/ppid
cat > /tmp/inner.sh <<'C'
/d/heimdall-proto run -- sh /tmp/child.sh &
echo $! > /tmp/ppid
wait $!
echo "proto exit=$?" >> /tmp/log
read -r _ _ _ _ pg _ _ tp _ < /proc/$$/stat
echo "after: shell pgrp=$pg tty_fg=$tp" >> /tmp/log
C
( for i in $(seq 1 100); do grep -q ready /tmp/log 2>/dev/null && break; sleep 0.05; done
  printf '\003'; sleep 1
  kill -INT "$(cat /tmp/ppid)"; sleep 1
  touch /tmp/stop; sleep 1 ) | script -qec "sh /tmp/inner.sh" /dev/null > /tmp/script.out 2>&1
echo "script exit=$?"; cat /tmp/log; echo "INT=$(grep -cx INT /tmp/log)"
echo "--- K11: TUI under script(1) with fresh TMPDIR and hostile OTUI_ASSET_ROOT/OPENTUI_LIBC"
mkdir -p /tmp/fresh /tmp/evil/@opentui/core-linux-arm64 /tmp/evil/@opentui/core-linux-x64
head -c 1000 /dev/zero > /tmp/evil/@opentui/core-linux-arm64/libopentui.so 2>/dev/null
head -c 1000 /dev/zero > /tmp/evil/@opentui/core-linux-x64/libopentui.so 2>/dev/null
( sleep 2; printf 'q' ; sleep 1 ) | TMPDIR=/tmp/fresh OTUI_ASSET_ROOT=/tmp/evil OPENTUI_LIBC=musl script -qec "stty cols 80 rows 10; /d/heimdall-proto tui --file /f/homelab.toml; echo SCRIPT_DONE tui_exit=\$?" /tmp/ts.out >/dev/null 2>&1
echo "script exit=$?"; grep -ao "SCRIPT_DONE.*" /tmp/ts.out
echo "rows containing lab-server: $(grep -c 'lab-server' /tmp/ts.out)"
echo "fresh TMPDIR entries: $(ls -A /tmp/fresh | wc -l)"; ls -la /tmp | grep '\.bun-' || echo "no .bun- extraction in /tmp"
echo "--- K11: sidecar missing -> fail closed"
cp /d/heimdall-proto /tmp/lone
( sleep 2; printf 'q'; sleep 1 ) | TMPDIR=/tmp/fresh script -qec "stty cols 80 rows 10; /tmp/lone tui --file /f/homelab.toml; echo SCRIPT_DONE tui_exit=\$?" /tmp/ts2.out >/dev/null 2>&1
grep -ao "SCRIPT_DONE.*" /tmp/ts2.out; echo "fresh TMPDIR entries: $(ls -A /tmp/fresh | wc -l)"
