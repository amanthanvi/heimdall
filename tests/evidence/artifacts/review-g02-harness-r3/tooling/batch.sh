#!/bin/sh
cd /tmp/r3rev
NEW=run.k6d_shared_mode_explicit_signals,run.k6e_job_control,tui.large_100_filter_latency,run.k6a_inherited_ignore
for m in rv_shared_sigint_only rv_shared_drop_winch rv_shared_drop_pipe_stdin rv_shared_drop_sh_c rv_dedupe_500ms rv_hup_exit_early rv_jc rv_jc_no_tty_after_fg rv_jc_bg_no_cont rv_jc_no_selfstop rv_restop_linux rv_restop_700ms rv_delay_bigresult rv_delay_first_key rv_rows_lag rv_delay_backspace rv_delay_90ms rv_child_sigpipe_ignored; do
  ./runhost.sh "mut-$m" "/tmp/r3rev/m/$m/heimdall-proto" "$NEW"
  ./runlinux.sh "mut-$m" "/tmp/r3rev/m/$m" "$NEW"
done
for m in rv_dedupe_500ms rv_hup_exit_early rv_jc rv_child_sigpipe_ignored; do
  ./runhost.sh "runall-$m" "/tmp/r3rev/m/$m/heimdall-proto" "run.*"
  ./runlinux.sh "runall-$m" "/tmp/r3rev/m/$m" "run.*"
done
for i in 2 3 4 5; do
  ./runhost.sh "flake-orig-$i" $HOME/GitRepos/heimdall/tests/g02/reference_impl.py "$NEW"
  ./runlinux.sh "flake-orig-$i" ref "$NEW"
done
echo BATCH_DONE
