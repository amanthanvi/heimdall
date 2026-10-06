Manual observation, round 3c (before the selftest run). Not a red proof (timing-dependent, contract 9.4 Q18).
Build: prototypes/rust source of round 3c with STOP_GRACE temporarily set to 0 ms (source restored and
compared with cmp afterwards), `cargo build --locked --target-dir target/nograce`, debug, darwin-arm64.
Command, run 3 times: HP_PTY_ONLY=k6e python3 tests/pty_tui.py target/nograce/debug/heimdall-proto
Observed exit codes: run 1 = 0, run 2 = 0, run 3 = 1 (k6e-interactive-bash-ctrl-z-fg-bg:
"z-fg #3: stopped after fg: ('T', 'T')", i.e. a stale stop report re-stopped the job right after fg).
The same cases on the 200 ms grace build: 5 of 5 runs exit 0 (manual), plus the selftest steps
k6e-repeat-darwin / k6e-repeat-linux-arm64 (5 runs each, exit 0). The selftest step
observation-zero-grace-darwin re-ran the zero-grace build 5 times and saw 0 failures: the race is rare.
