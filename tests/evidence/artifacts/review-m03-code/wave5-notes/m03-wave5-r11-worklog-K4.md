# M03 wave 5 round 11 — worker K4 (W5-E02: ending indeterminate issuer requests) worklog

Base 06990cc8. Binding ADR-0008 §17.33 item 2. No commits.
Files: crates/issuer/src/client.rs; crates/app/src/operations/issuer_m03.rs (`issuer_request_hold`);
crates/runtime/src/service.rs (client construction → pub `issuer_client_config`);
tests/e2e/cli_m03/issuer.rs (Rig carries the runtime's Operations; 3 tests); tests/integration/issuer_child.rs
(3 tests updated to the new rule).

## Design
- `Inner::exchange_ending` (load, sign) owns its admissions until the reply is consumed: the load gate's
  permit (load) and, for sign, `ClientConfig.request_hold` = `Operations::issuer_request_hold()` →
  `UninstallFence::write_extension()` (an extra counted admission extending the calling task's, e.g. the
  managed pipeline's). Ending without the reply (cancel = `Indeterminate` drop guard; timeout; broken):
  view `crashed`, `end_child` = verify exact child (PID unchanged + start token re-read equal + image
  re-read equal to the one read after hello_ack) → signal only if verified → close stdin → await exit
  ≤ STOP_TIMEOUT (5 s) → release permits. Unconfirmed: a background wait keeps the permits held until
  the exit is observed.
- Unconfirmed reading: the held admission makes `uninstall_fence_acquire` time out (ACQUIRE_WAIT 20 s)
  with the existing refusal `SERVICE_UNAVAILABLE` / `uninstall_in_progress`, message "work being admitted
  did not settle in time, so the uninstall fence was not taken; nothing was changed". No new reason.
- After: `crashed`, restart on demand under the round-10 load gate (a broken link still supervises at once).
- `crash()`, `stop()` and start_once's old-link cleanup now also signal only a re-verified child.
- Converge: unload (only removes a key: a late one fails closed), status (read-only), hello (nothing loaded
  before `load`), shutdown (stop) need no ending; register/retire deletion are CLI store operations, no child
  request; RegisterIssuer approval's reload is a `load` (covered).
- Limit: the sign hold exists only when the caller's admission was taken in a tokio task (task id); the
  runtime's pipeline runs in spawned tasks. Without it the child is still ended, but the caller's admission
  may be released before the exit is confirmed (the test shows the hold is what holds acquisition).

## Commands (exit codes, umask 002)
- recheck3_real_issuer_late_sign_cannot_cross_fence 0; recheck3_real_issuer_cancelled_load_cannot_cross_fence 0;
  recheck3_real_issuer_unconfirmed_stop_keeps_the_admission_held 0 (21 s: the acquisition's bound).
- Reverts (sha same each, rerun 0): `armed: true→false` (no ending on cancel) → both recheck3 101;
  sign hold `.take(0)` → unconfirmed-stop test 101 (acquire Held at once); image check removed → 101
  (unverified child signalled).
- issuer_child: 3 tests updated (cancelled sign/load now end the child; spawn count by distinct PID).
- Full runs (umask 002), all 0: issuer --lib (22), --release --lib (21), integration_issuer_child (36),
  integration_issuer_m03 (22), runtime --lib (62), e2e_cli_m03 issuer:: (22 + 1 ignored pty entry);
  clippy issuer+runtime+app --all-targets and heimdall bin+e2e (first run 101: a needless `&ops` in my
  service.rs line, fixed; an app `items after a test module` from another worker's in-flight file was gone
  on rerun), clippy-windows.sh (Windows target kept), linux-xcheck -p issuer -p runtime -p app.
  Owner keychain digests unchanged; 0 heimdall processes of this user after the runs. Scratch removed. DONE.
