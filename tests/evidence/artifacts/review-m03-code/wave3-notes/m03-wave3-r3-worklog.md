# M03 wave 3, round 3: worklog (untracked; integrator + agents)

Base `5ee3e143` (round 2 committed). Orchestrator: §17.20 item 15 rules W3-R2-Q1 (a), Q2, Q3 as taken.

## Integrator
- Item 1 (devbox, umask 002): test anchors owner-only explicitly (`managed_adapter.rs` `owner_only_anchor`,
  `managed_dir.rs` tests `owner_only_tempdir`); the check is unchanged.
  - Revert proof on this host: the HEAD test code under `sh -c 'umask 002; …'` → localenv `--lib` managed_dir
    2 failed (`managed_dir.rs:526`, `:548`), `integration_managed_adapter` 31 failed (the devbox's 33); the fix under
    umask 002 → localenv `--lib` 89 passed, adapter 46 passed.
  - Production audit: `Paths::ensure` (`crates/runtime/src/paths.rs:159`, M01) creates every directory (parents too)
    `DirBuilder::mode(0o700)` and tightens an existing owned too-permissive directory to 0700 through its handle;
    refuses a symlink, non-directory or foreign owner (`PermissionDenied`). `open_root` refuses an anchor loosened
    after `ensure` (`managed_dir_unsafe`).
  - Regression `integration_runtime_m03::umask_anchors::production_anchors_are_owner_only_under_umask_002` (child
    process through `/bin/sh -c 'umask 002 && exec <test binary> --exact umask_anchors::umask_child_entry'`, control
    dir proves 0775): mutation "create with mode 0777" alone → still exit 0 (M01's tightening repairs it: two
    mechanisms); mutation "no tightening" → exit 101 (`runtime_m03.rs:2662`, older/state 0775 ≠ 0700); both →
    exit 101 (`:2635`, config 0775); restored → exit 0, `paths.rs` no diff.
  - Container (ubuntu:24.04, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, amd64 emulated, `--network none`, user hmtest,
    `umask 002`; validation only): `integration_managed_adapter` 46 passed; `integration_runtime_m03 umask_anchors`
    2 passed; `heimdall-localenv --lib` 88 passed, 1 failed `probe::network::tests::a_silent_server_times_out`
    (Unreachable vs Timeout at a 300 ms loopback deadline; also fails under umask 022 in the parallel run; passes
    3/3 alone; M02 code, unchanged since 26f94dc8: emulation load). Image `heimdall-w3r3-u2404:local` removed by
    name; scratch removed.
- Items 2 (W3-C01) and 3 (W3-C02) from the re-check: F7 and F6 resumed.
- check.sh (round 3, after F6/F7) → **exit 0**, every step 0: 2585 passed, 0 failed, 188 ignored, 97 targets;
  native-harness-selftest 316/0. `linux-xcheck.sh --workspace` → 0; `clippy-windows.sh` → 0.
- After check.sh, two `sleep 300` with PPID 1 (08:45:27, 08:45:29): not wave-3 code (the connections fixture now
  uses `exec /bin/sleep 40`); `sleep 300` is spawned and orphaned by design in the wave-1 fence tests
  (`tests/integration/enroll_registry.rs:827-888`) and the M02 harness selftest (`tests/native/m02/selftest.sh:1761`).
  Left to end on their own (bounded at 300 s); confirmed ended afterwards.
- Scan of every changed file: no canary value, home path or private key.

## F6
W3-C02 (re-check; the symlink regressions were masked by the permission check). Base `5ee3e143` + the integrator's
round-3 anchors (`owner_only_anchor`, `owner_only_tempdir`), kept.
- `tests/integration/managed_adapter.rs` `managed_files_never_follow_a_planted_directory`: every planted symlink
  target (the parent `managed` victim, the leaf `managed/h1` victim, the `b/<tag>` and planted `b` cases) is created
  and then set to mode 0700 explicitly, asserted 0700 (an acceptable directory). Each traversal case asserts
  `FilesError::Unsafe(why)` with `why` naming the symlink (never the permission refusal) via `link_refused`; added a
  leaf write case; asserts the victim's entries are unchanged after every leaf, binding and planted-`b` case (nothing
  written into or removed from it). The pre-existing 0777 case stays separate and unchanged.
- `crates/localenv/src/sys/managed_dir.rs` test `symlinks_and_open_directories_are_refused_never_repaired`: the link
  target is `owner_only_tempdir()`, proven acceptable (`open_root` + `child("sub", true)` succeed); `child("link", …)`
  must be refused with the symlink reason; nothing created through the link.
- Windows `managed_dir_windows_refuses_inherited_dacl_and_junction`: the junction victim was created with
  `std::fs::create_dir` (inherited DACL), which `ManagedDir::child`'s DACL check also refuses, so a followed junction
  would be masked. It is now created through `ManagedDir::open_root(..).child("victim", true)` (Heimdall's owner-only
  DACL, verified there), and the refusal must name the reparse point. Inherited-DACL case unchanged. Needs the
  Windows-native run (compiled here only).
- Revert proof (exactly the reviewer's mutation: `ManagedDir::child`'s `fsentry::open_dir_at` replaced by
  `rustix::fs::openat(.., RDONLY | DIRECTORY | CLOEXEC, ..)`, owner/mode checks kept):
  - regression managed_files_never_follow_a_planted_directory: reverted → exit 101 (managed_adapter.rs:4457 "parent write: a planted symlink was followed: Ok(())"); restored → exit 0
  - regression symlinks_and_open_directories_are_refused_never_repaired: reverted → exit 101 (managed_dir.rs:570 "the link was followed: Ok(Some(ManagedDir { .. }))"); restored → exit 0
- `cargo test -p heimdall-adapters --test integration_managed_adapter` → exit 0 (46); under `sh -c 'umask 002; …'` → exit 0 (46)
- `cargo test -p heimdall-localenv --lib` → exit 0 (89); under `sh -c 'umask 002; …'` → exit 0 (89)
- `cargo clippy -p heimdall-adapters -p heimdall-localenv --all-targets -- -D warnings` → exit 0
- `.m03-wave3-xcheck-windows.sh` was absent (no F7 copy): recreated from `tools/validation/clippy-windows.sh`, only
  `cd "$(dirname "$0")"` and `"$@"` for `--workspace --all-targets` changed (diff checked). `bash .m03-wave3-xcheck-windows.sh -p heimdall-adapters -p heimdall-localenv --all-targets` → exit 0
- `bash tools/validation/linux-xcheck.sh -p heimdall-adapters -p heimdall-localenv` → exit 0
- `rustfmt --edition 2024 --check` on F6 files → exit 0
- Windows-native to run: `cargo test -p heimdall-adapters --test integration_managed_adapter` (incl.
  `managed_dir_windows_refuses_inherited_dacl_and_junction`) and the `heimdall-localenv` unit tests.

## F7
- Item 2 (W3-C01), `tests/integration/connections.rs` only (fixture; no product change):
  - Fixture-owned receipts (`Receipt { role, pid, token, image }`, `World::receipts`) for every process the
    world starts or records: its children (`spawn`, `spawn_ordinary`, `foreign_master`, the launcher sh),
    every master a supervisor under test started (`World::start`, `World::track` at the direct
    `start_master` sites), and the loopback server's commands. `World::drop` stops masters and server
    commands from the receipts, merging the store's master rows **only when the store can be read** (a
    failed read no longer empties the set), each by exact identity through `stop_exact` (start token
    before/after `ProcessPin::open`, `ProcessPin::verify` against the receipt's image, SIGKILL); children
    by their handles.
  - Server commands are tracked and self-terminating: `World::remote_sleep` makes `echo $$ > <pidfile>;
    exec /bin/sleep 40` (`REMOTE_SECS`), `collect_remote` reads the pidfile into a receipt **after** the
    image is `/bin/sleep` (bounded; the first audit run caught the pre-exec race: a fast test met the
    shell in the sleep's place and the image check refused it, survivor PID 53717, which self-terminated).
    Every remote `sleep 120`/`sleep 60` became a tracked `spawn_remote_sleep`; the unix_revoke launcher's
    remote command and the `nohup` remote process are tracked too.
  - Audit: after cleanup, each world's drop (when not unwinding) asserts that none of its receipts'
    identities survives (bounded 5 s); `HM_U7_RECEIPTS=<file>` appends every receipt for an external
    exact-PID audit after the whole target.
  - Regression (b) `panic_with_store_failure_leaks_no_process`: a world in a thread starts a master and a
    session through it, arms the store failure, panics; the receipts (master, client, server command)
    are all gone after the join.
  - Revert proofs: (a) server commands not stopped at drop (masters only) → full target exit 101 (28
    passed, 12 failed: 11 "processes this test started or recorded survived it", plus (b)); external
    audit 14 survivors, which self-terminated within ~30 s (audit 0; nothing signalled); restored (cmp).
    (b) master receipts dropped (store rows only) → `--exact unix::panic_with_store_failure_leaks_no_process`
    exit 101 ("survivors: [59435]"); restored (cmp). The leaked master 59435 (PPID 1, `/usr/bin/ssh`,
    started 08:33:02, U7 master args) was re-verified and stopped by exact PID (SIGTERM), gone.
  - Checks: `HM_U7_RECEIPTS=… TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections`
    3 runs exit 0 (40 passed each), each followed by the exact-PID audit (`ps -o pid=,ppid=,comm=` and
    start time vs token, per recorded PID): 70 identities, 0 survivors each. Afterwards: 0 orphaned
    `/usr/bin/ssh` and 0 orphaned `sleep` with PPID 1 (observation only).
- Item 3 (§17.20 item 16), `tests/e2e/deadline_m03.rs` (Windows):
  - `windows_register_while_suspended_under_gate` **kept its name**; its doc now says it tests the
    registration gate (U0b row 26's shared signing-gate acquisition) with a `fake_agent` grant whose gate is
    `retain`ed, not a managed credential.
  - `windows_non_ssh_run_has_no_job_object_by_default`: the fixture child writes
    `is_process_in_job=<bool>` (its `IsProcessInJob(GetCurrentProcess(), NULL)`); when the test itself is
    in no job, it asserts that is `false`. The `ping` grandchild is held by an `ExactStop` guard from the
    moment its PID is read (stopped pass or fail: `ProcessPin::open`, creation time read on the handle,
    image verified on it, signal through the verified handle, bounded wait); the test asserts it is gone.
  - Not run (no Windows here); revert not run.
- Commands: Windows clippy (`.m03-wave3-xcheck-windows.sh` recreated from `tools/validation/clippy-windows.sh`
  with `cd "$(dirname "$0")"` and `"$@"`, then deleted) `-p heimdall -p heimdall-runtime -p heimdall-localenv
  --all-targets` exit 0; host clippy `-p heimdall-runtime -p heimdall --all-targets --locked -D warnings`
  exit 0; `linux-xcheck.sh -p heimdall-runtime` exit 0; `cargo test -p heimdall --test e2e_deadline_m03`
  exit 0 (1 passed); rustfmt `--check` on my three files exit 0.
- Windows-native to run: `e2e_deadline_m03` `windows::windows_register_while_suspended_under_gate`,
  `windows::windows_non_ssh_run_has_no_job_object_by_default` (with `HEIMDALL_E2E_BIN`); devbox:
  `integration_connections` (the remote-command receipts and drop audit on Linux).
