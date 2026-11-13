# P8 worklog (M03 wave 5 round 8, W5-C01; ADR-0008 §17.31 item 1)

## Goal
Uninstall purges only after a confirmed stop, holding the runtime's `InstanceLock`
(`<state>/service.lock`) from before its final inventory + bundle read through the deletion.

## Decisions
- Lock: reuse `heimdall_runtime::instance::InstanceLock::try_acquire` (std `File::try_lock`:
  flock on Unix, LockFileEx on Windows). No runtime change needed; CLI polls it (bounded,
  `LOCK_WAIT`), because a stopping runtime drops its advertisement before its lock.
- The lock file is never deleted: unlinking a held lock lets a start-up create a fresh
  inode at the same path and lock it. Delete db + backups under the lock, then drop it.
- Refusals after the stop: `SERVICE_UNAVAILABLE` (exit 5, retryable), **no reason**
  (no existing reason fits; `uninstall_in_progress` means a held fence). Effect `partial`.
- Final read under the lock: inventory (`same_obligations`) and the bundle check against the
  confirmed inventory (retirements legitimately change CAs after the confirmation).
- Test pause point = a closure parameter of `purge_locked` (production passes a no-op): no
  `HEIMDALL_TEST_*` variable, nothing for the release gate.

## Progress
(see below)
- Implemented in uninstall_cmd.rs: PurgeEnd, purge_after_stop, purge_locked, instance_lock,
  not_purged, after_stop; stop_runtime generic over Session. No runtime change.
- Tests: 4 unit (uninstall_cmd::tests) + 1 e2e (uninstall_doctor). All pass.
- Revert runs: A (drop `!stopped` refusal): unconfirmed_stop exit 101. B (drop lock acquisition):
  excludes_runtime_start 101, refuses_replacement 101, recheck 101. Restored, shasum OK
  (77c03fd1...), reran: 19/19 ok.
- Commands: build ok; clippy host (-p heimdall -p heimdall-runtime --all-targets) 0; clippy-windows
  -p heimdall 0; linux-xcheck 0; e2e_cli_m03 full (umask 002) 0 (64 passed, 3 ignored);
  uninstall_doctor:: 0; e2e_cli_m02 uninstall 0 (8); bin 173 passed x8 runs; runtime instance:: 0.
- Done. Remaining: none.
