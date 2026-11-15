# M03 wave 5 round 15 — worker K4 (devbox failures of the two recheck3 real-issuer tests) worklog

Base 40a8d1d4. No commits.
## Requests (devbox coordination with P8)
- K4 devbox use: ONE `HM_ONLY=e2e_cli_m03 run-linux.sh` at a time; K4 marks "IN USE" / "FREE" here.
- devbox: FREE (K4 done: run 2 passed 56/56, 0 leftovers; no ~/hm-m02-* left; local output dirs removed)
- P8 → K4: P8 waits for "FREE", then makes ONE `HM_ONLY=e2e_cli_m03` devbox run (item 4: the
  passphrase test's `Rig::program` skip already in the tree; P8 does not edit issuer.rs further).
  P8 marks "IN USE by P8" / "FREE" on this line when it runs.
## Notes
- Also failing in the same bundle (my file): `issuer::issuer_init_prints_passphrase_only_to_tty` at :1016 on
  Linux: the scan of every file under the rig's tmp finds the literal prompt text in the rig's own program
  copy (`tmp/program/heimdall`, added in round 3). Test defect.
## Diagnosis (devbox run 1, temporary K4-DIAG eprintln in signal_exact, booleans only; removed)
- On Linux every exact-child check of the issuer child: exited=false same_pid=true tok_now=tok_then=tok_eq=true,
  image now=None AND image at spawn=None → `(Some, Some)` arm never matched → never signalled → the SIGSTOPped
  child keeps the admission → ACQUIRE_WAIT (20 s) expires.
- Cause: the issuer child runs `credential::sys::harden_process` (`PR_SET_DUMPABLE` 0) before any key exists, so
  `/proc/<pid>` is owned by root and `/proc/<pid>/exe` is unreadable to this user (ptrace-read check). macOS
  `proc_pidpath` has no such check. Start token (`/proc/<pid>/stat` field 22, world-readable) is fine, stopped too.
- PRODUCT BUG: on Linux no exact-child signal of the issuer child could ever be sent (crash, stop fallback,
  indeterminate cleanup, start_once cleanup): a hung child was never ended, its admission held until it exited.
## Fix
- `signal_exact`: the image is part of the identity only when it was read at spawn; then it must re-read equal
  (unreadable now or different → refuse). Unread at spawn → PID + start token + the client's own unreaped
  handle (no PID reuse possible while unreaped). Not weakened: keeping the child dumpable is not an option (K_ca).
- Tests modelling an unverifiable child now use `image_unreadable_after_start()` (reads at spawn, not after):
  unconfirmed_stop, recheck4 (kill_on_drop residual), residual_leader.
- Unit regressions (client.rs, unix): exact_child_signalled_when_its_image_was_never_readable;
  exact_child_refused_when_a_read_identity_no_longer_matches. Revert (old arm) → 101; restored sha same; 0.
- Converge: crash(), stop(), start_once old-link cleanup, Indeterminate drop, end_child all go through
  signal_exact → all fixed. kill_on_drop unchanged. Owned ssh connections (runtime connections.rs
  `ProcessPin::verify`) are dumpable (execve resets the flag): unaffected.
- §17.33 item 6: FailClosedOnly (a delay/refusal: the admission stayed held, the fence refused; no write, no
  certificate) — fixed anyway as a product bug.
- issuer_init_prints_passphrase_only_to_tty (Linux branch): skip `Rig::program` in the file scan (test defect;
  shown passing on devbox run 1).
## Commands (exit codes, umask 002)
- devbox run 1 (diag) exit 101: 54/56, both recheck3 fail with the diag above; passphrase test passed.
- devbox run 2 (fix) exit 0: e2e_cli_m03 56 passed, 0 failed, 3 ignored; leftovers 0.
- macOS: issuer --lib 0 (24), e2e_cli_m03 issuer:: 0 (24 + 1 ignored), integration_issuer_child 0 (36).
- clippy host (issuer --all-targets; heimdall bin + e2e_cli_m03) 0; linux-xcheck -p heimdall-issuer -p heimdall 0.
- clippy-windows.sh 101 twice: only `read_with_wal` never used in crates/heimdall/src/uninstall_cmd.rs:6290 (P8's
  in-flight file); Windows target kept. target/x86_64-unknown-linux-gnu (36 G) removed after the runs (no harness
  running). Diagnostics removed (0 K4-DIAG). Owner keychain digests unchanged; 0 heimdall processes.
