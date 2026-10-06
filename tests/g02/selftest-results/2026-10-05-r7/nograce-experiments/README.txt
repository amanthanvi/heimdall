run_mirror_nograce experiments (M00-T05-harness-r4-fix, harness 2.4.1), darwin-arm64, 2026-10-05.

Question: can a black-box check reliably catch reference mutation run_mirror_nograce (the round-4 harness review's
rv_nograce: a stop-mirroring launcher without the reference's 200 ms grace)?  If yes it would be a required
self-test mutation; if not it is a RACE mutation (selftest.py) and Q18 in the README.

Scripts (stdlib only; temp dirs only; SSH_AUTH_SOCK unset; only processes they started are signalled):
  pty_cycles.py     Ctrl-Z / fg cycles in `bash -i` in a pty; layouts `simple` and `grandkids` (the child is a
                    /bin/sh wrapper that first starts 100 waiting processes in the job's process group, then execs
                    the child); CREAD=1 makes the child block in a terminal read; counts re-stops after `fg`
  killpg_cycles.py  the `grandkids` layout stopped/continued with killpg(SIGTSTP)/killpg(SIGCONT), no shell
  burn.py           runs a command while N busy loops load the CPUs (18 = this host's CPU count)
  make_logged_copy.py  a no-grace copy of reference_impl.py that appends a log line between its "child still
                    stopped" decision and its own stop (shows how a slower decision-to-stop path behaves)
  run_all.sh        the driver; results-darwin-arm64.txt holds its output (repository and temp paths shortened to
                    <repo> and <tmp>), followed by a rerun of the last two steps after make_logged_copy.py was fixed to
                    set the executable bit

Observed (results-darwin-arm64.txt): run_mirror_nograce re-stopped the job after `fg` in 0 of 15 cycles in each of
the six pty variants (simple / grandkids, sleeping / terminal-reading child, idle / 18 burners) and in 0 of 12 killpg
cycles; the reference (grace) in 0 of 15 (idle and loaded) and 0 of 12.  The logged no-grace copy re-stopped in 12 of
12 killpg cycles and 9 of 10 pty cycles in the grandkids layout, 0 of 10 in the simple layout.  Earlier exploratory
runs during this task (console output only, not preserved) saw 1 of 15 for the terminal-reading child in the
grandkids layout, and one harness run of an experimental run.k6e_job_control form with that layout failed the
mutation at its first cycle; harness 2.4.0's stress record (selftest-results/2026-10-04-r6/stress-k6e-nograce-load-
darwin.json) has 2 re-stops in 160 cycles under 20 burners.

Inference (not measured directly): the no-grace launcher re-stops only when the group stop reaches it between its
"child still stopped" decision and its own kill(); the log line widens that window, the real mutation's window is a
few instructions, and a black-box harness cannot force that interleaving.  Not run on Linux.
