# M03 wave 5 round 12 — worker K4 (W5-F04: the kill_on_drop residual) worklog

Base 2903b0e6. Binding ADR-0008 §17.34 item 3. No code fix. No commits.
- Probe scenario read only from /tmp/hm-tools/recheck4-probes/probe_defs.py (never executed).
- Test `issuer::recheck4_cancelling_stop_must_not_signal_unverified_child` in tests/e2e/cli_m03/issuer.rs
  (where the re-check named it, `issuer::` in e2e_cli_m03; it needs the real `internal issuer` child and the
  rig helpers `real_issuer_with`, `running`, `signal_pid`). It documents the residual and passes while it
  holds: stopped child, image unreadable (unverifiable), request bound 2 s, the cleanup's ≤ 5 s wait cancelled
  at 2.5 s → kill_on_drop ends the child; while the PID is present its start token is unchanged (same,
  unreaped process); no event, CA record unchanged, no CA loaded; the fence is then taken; no survivor.
  (The probe's 300 ms bound failed the initial load in this debug build; 2 s used.)
- RESIDUALS: appended `issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child`, reason
  FailClosedOnly (§17.33 item 6 "only fails closed, no lasting effect": the signal ends only this unreaped
  child, so the indeterminate request never completes; nothing is written or published), adr §17.34 item 3.
## Commands (exit codes, umask 002)
- the test 0; claims_table.py 0; heimdall-domain 0 (residuals_are_never_claims ok).
- integration_issuer_child 0 (36); clippy host (domain+issuer --all-targets; heimdall bin + e2e_cli_m03) 0.
- clippy-windows.sh (workspace): 101 on six tries, every error in P8's in-flight
  crates/heimdall/src/{purge_sweep.rs,uninstall_cmd.rs} (Windows `imp::Quarantine` etc.); my changes are a
  domain const entry and a #[cfg(unix)] test. `cargo clippy --target x86_64-pc-windows-gnu -p heimdall-domain
  --all-targets -- -D warnings` 0. Windows target kept. No survivors (0 heimdall processes). DONE.
