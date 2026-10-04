#!/bin/sh
# Re-runs the M00-T05-review-ts probes; each output goes to out/<name>.log with its real exit code.
B=/tmp/hm-review-root/prototypes/ts/dist/darwin-arm64/heimdall-proto
S=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd); O=$S/../out
unset SSH_AUTH_SOCK
mkdir -p /tmp/hm-review-probes/h /tmp/hm-review-probes/agent /tmp/hm-review-probes/envid /tmp/hm-review-probes/otui
cp $S/fdflags.py /tmp/hm-review-probes/fdflags.py
[ -f /tmp/hm-review-probes/envid/evil.js ] || echo 'require("fs").writeFileSync("/tmp/hm-review-probes/envid/PRELOAD_RAN","x"); console.error("PRELOAD_RAN");' > /tmp/hm-review-probes/envid/evil.js
r() { name=$1; shift; date -u +%Y-%m-%dT%H:%M:%SZ > $O/$name.log; "$@" >> $O/$name.log 2>&1; echo "exit=$?" >> $O/$name.log; echo "$name exit=$(tail -1 $O/$name.log)"; }
r io_probe /usr/bin/python3 $S/io_probe.py $B
r pty_fd /usr/bin/python3 $S/pty_fd.py $B
r envprobe sh $S/envprobe.sh
r sigign_rlimit /bin/sh -c "ulimit -S -n 256; echo direct_nofile \$(/bin/sh -c 'ulimit -S -n'); echo proto_nofile \$($B run -- /bin/sh -c 'ulimit -S -n'); trap '' HUP INT QUIT; C='import signal as s; print(\"HUP\",s.getsignal(s.SIGHUP),\"INT\",s.getsignal(s.SIGINT),\"QUIT\",s.getsignal(s.SIGQUIT))'; echo direct: \$(/usr/bin/python3 -c \"\$C\"); echo proto: \$($B run -- /usr/bin/python3 -c \"\$C\")"
r nohup_hup /bin/sh -c "trap '' HUP; /bin/sleep 2 & P=\$!; sleep 0.5; kill -HUP \$P; wait \$P; echo direct_rc=\$?; $B run -- /bin/sleep 2 & P=\$!; sleep 0.5; kill -HUP \$P; wait \$P; echo proto_rc=\$?"
r race_sigterm /usr/bin/python3 $S/race.py $B SIGTERM 1
r race_sigint /usr/bin/python3 $S/race.py $B SIGINT 1
r pipeline_tty_sh_env /usr/bin/python3 $S/pipeline_tty.py $B env
r pipeline_tty_sh_proto /usr/bin/python3 $S/pipeline_tty.py $B proto
r pipeline_tty_bash_i_env /usr/bin/python3 $S/pipeline_tty_jc.py $B env
r pipeline_tty_bash_i_proto /usr/bin/python3 $S/pipeline_tty_jc.py $B proto
r less_bash_i_env /usr/bin/python3 $S/less_jc.py $B env
r less_bash_i_proto /usr/bin/python3 $S/less_jc.py $B proto
r killpg /usr/bin/python3 $S/killpg.py $B
r exitloop sh $S/exitloop.sh $B
r agent_frames /usr/bin/python3 $S/agent_probe.py $B
r envid sh $S/envid.sh
r bun_inspect sh $S/inspect.sh
r otui_env /usr/bin/python3 $S/otui_env.py $B
r tui_selected_colors <repo>/tests/g02/.venv/bin/python $S/sel_colors.py $B xterm-256color
