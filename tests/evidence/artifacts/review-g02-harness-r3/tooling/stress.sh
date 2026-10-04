#!/bin/sh
cd /tmp/r3rev
NEW=run.k6d_shared_mode_explicit_signals,run.k6e_job_control,tui.large_100_filter_latency,run.k6a_inherited_ignore
: > hogs.pids
i=0; while [ $i -lt 18 ]; do yes > /dev/null & echo $! >> hogs.pids; i=$((i+1)); done
echo "hogs started: $(wc -l < hogs.pids) (yes > /dev/null, 18 host CPUs)"
for n in 1 2; do
  ./runhost.sh "stress18-orig-$n" $HOME/GitRepos/heimdall/tests/g02/reference_impl.py "$NEW"
  ./runlinux.sh "stress18-orig-$n" ref "$NEW"
done
for p in $(cat hogs.pids); do
  c=$(ps -o comm= -p "$p" 2>/dev/null); pp=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
  if [ "$c" = yes ] && [ "$pp" = "$$" ]; then kill "$p"; fi
done
sleep 1; echo "hogs left: $(for p in $(cat hogs.pids); do ps -o pid= -p $p; done | wc -l)"
echo STRESS_DONE
