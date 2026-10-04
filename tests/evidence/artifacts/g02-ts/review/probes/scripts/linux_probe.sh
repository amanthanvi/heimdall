#!/bin/sh
B=/opt/hm/heimdall-proto
P=/fixtures/homelab.toml
echo "uname: $(uname -sm); glibc: $(ldd --version 2>&1 | head -1)"
echo "== ldd"; ldd $B
mkdir -p /tmp/t; export TMPDIR=/tmp/t HOME=/tmp/h; mkdir -p $HOME; cd /tmp/h
echo "== version"; $B version --json; echo "rc=$?"
echo "== profile spaced"; mkdir -p "/tmp/h/sp ü"; cp $P "/tmp/h/sp ü/prøfile.toml"; $B profile show --file "/tmp/h/sp ü/prøfile.toml" --json | head -c 100; echo " rc=$?"
echo "== K8 argv a\\377b"; $B run -- /bin/sh -c 'printf %s "$1" | od -An -tx1' sh "$(printf 'a\377b')"; echo "rc=$?"
echo "== env bytes"; FOO="$(printf 'a\377b')" $B run -- /bin/sh -c 'printf %s "$FOO" | od -An -tx1'
echo "== nofile soft"; sh -c "ulimit -S -n 256; echo direct \$(sh -c 'ulimit -S -n'); echo proto \$($B run -- sh -c 'ulimit -S -n')"
echo "== SIG_IGN inheritance (SigIgn mask of child)"; sh -c "trap '' HUP INT QUIT; echo direct \$(grep SigIgn /proc/self/status); echo proto \$($B run -- grep SigIgn /proc/self/status)"
echo "== BUN_OPTIONS preload"; echo 'require("fs").writeFileSync("/tmp/h/PRELOAD_RAN","x")' > /tmp/h/evil.js; BUN_OPTIONS="--preload /tmp/h/evil.js" $B version --json >/dev/null; echo "rc=$? ran=$(test -e /tmp/h/PRELOAD_RAN && echo yes || echo no)"
echo "== launch failure"; $B run --meta-file /tmp/h/meta.json -- /nonexistent/x; echo "rc=$?"; cat /tmp/h/meta.json
echo "== new files in TMPDIR: $(ls -A /tmp/t | wc -l); /tmp .bun-*: $(ls -A /tmp | grep -c '^\.bun')"
