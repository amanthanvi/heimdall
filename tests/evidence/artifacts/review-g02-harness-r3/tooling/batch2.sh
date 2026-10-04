#!/bin/sh
cd /tmp/r3rev
NEW=run.k6d_shared_mode_explicit_signals,run.k6e_job_control,tui.large_100_filter_latency,run.k6a_inherited_ignore
for m in base2 rv_jc2 rv_jc_no_tty_after_fg2 rv_jc_bg_no_cont2 rv_jc_no_selfstop2; do
  ./runhost.sh "mut-$m" "/tmp/r3rev/m/$m/heimdall-proto" "$NEW"
  ./runlinux.sh "mut-$m" "/tmp/r3rev/m/$m" "$NEW"
done
./runhost.sh "runall-rv_jc2" "/tmp/r3rev/m/rv_jc2/heimdall-proto" "run.*"
./runlinux.sh "runall-rv_jc2" "/tmp/r3rev/m/rv_jc2" "run.*"
echo BATCH2_DONE
