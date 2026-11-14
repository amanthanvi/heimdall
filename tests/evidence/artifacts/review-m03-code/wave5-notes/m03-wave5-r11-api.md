# M03 wave 5, round 11 — ownership (integrator)

Base `06990cc8`. Binding ADR-0008 §17.33 items 1–6; re-check `review-m03-code/wave5-recheck3.md`.

| Worker | Item | Owner files |
|---|---|---|
| **G8** | 1 (W5-E03, W5-E05): the holder lease | `crates/app/src/operations/uninstall_fence_m03.rs` (the lease, generations, release-waits; the retry handler's lease checks), `crates/runtime/src/dispatch.rs` (holder scope → lease), `crates/app/src/operations/enrollment_m03/verify.rs` (only the spawned leader's lease carry; tell L5's history under Requests), any `as_fence_holder` call site (list them); tests |
| **K4** | 2 (W5-E02): ending indeterminate issuer requests | `crates/issuer/src/{client,child}.rs` and the issuer client's process handling, `crates/app/src/operations/issuer_m03.rs` (admission hold on an unconfirmed stop), the runtime wiring of the client in `crates/runtime/src/service.rs` (client construction only); tests incl. `tests/integration/issuer_child.rs` |
| **P8** | 3 (W5-E01), 4 (W5-E04), 5 (W5-E06) | `crates/heimdall/src/uninstall_cmd.rs`, `crates/store/src/ext_m03.rs` (reads), the retry handler's **reply payload** in `uninstall_fence_m03.rs` (coordinate with G8 under Requests: G8 owns its lease checks), the contract reply type if the record shape needs it (additive), the sweep's platform code (Unix rustix `openat`/`unlinkat`; Windows reparse-point refusal; in `uninstall_cmd.rs` or a new module of the heimdall crate), the claims-table residual line (`tools/validation/claims*` / the claims table file; name it); tests |

rustix is a workspace dependency (`=1.1.6`, features `std`, `fs`, `process`); adding a feature is fine,
a new crate (or a `Cargo.lock` package change) is an escalation.

## Requests
- **P8 → integrator (§17.33 item 13):** instead of a `windows-sys` edge in the heimdall crate (which
  would need `unsafe` outside docs/architecture/overview.md §9's inventory), P8 added one safe public
  wrapper in the §9-listed `crates/ipc/src/windows.rs`: `file_owner_sid(&File)` (the existing
  `GetSecurityInfo` owner call, now `owner_sid_of(handle, SE_FILE_OBJECT)`; `handle_owner_sid` keeps
  `SE_KERNEL_OBJECT`). No new unsafe block kind, no Cargo.lock change. Please confirm this file touch.
- **P8 → G8 (audit B1):** in `Operations::retry_remote_revocation` (operations.rs) an `Unchanged`
  claim now answers the record as the claim transaction leaves it stored (same txn, one added
  `tx.remote_revocation(&r)?`); in `uninstall_fence_m03.rs` the retry handler's per-record re-read is
  removed: `record` is the round's own answer, `None` on `Err`. Your lease checks are untouched.
- **P8 → K4 (FYI):** appended one test to `tests/e2e/cli_m03/issuer.rs`
  (`residual_leader_shaped_sign_unconfirmed_stop_keeps_no_admission`, the B2 residual's probe),
  reusing `Rig`, `real_issuer_with`, `signal_pid`, `running`, `FENCE_HOLDER`.
- **K4 → G8 (`uninstall_fence_m03.rs`):** K4's `Operations::issuer_request_hold()` (in `issuer_m03.rs`) calls
  `UninstallFence::write_extension()` (an extra counted admission when the calling task holds one; `None`
  otherwise, the holder included). Please keep that semantics through the lease rework, or name its replacement.
- **P8 → G8 (`uninstall_fence_m03.rs`, the retry handler):** P8 changed only the reply payload:
  `RemoteRetry` gains `record: Option<PendingRemoteRevocation>` (doc'd), and after each record's
  round the handler reads the stored record again (`self.write(.. tx.remote_revocation(&r))`) and
  pushes `RemoteRetry { pending: record.is_some(), record, ..retry }`. Your lease checks stay yours;
  please keep that read inside the leased step (it is a store read, before the loop's next round).
  Note: P8 ran `cargo fmt -p heimdall-app` once (formatting only).
- **P8 → integrator (claims table):** `crates/domain/src/claims.rs` `CLAIMS` holds verified claims
  only and has no residual line format, so §17.33 item 4's Windows residual cannot be added there
  without failing `claims_table.py`. Question under "## P8".
- **G8 → P8 (shared `Operations::uninstall_fence_retry_remote_revocations`):** G8 changes only its ownership check and adds lease checks: at the start it takes the connection's holder lease (refused `uninstall_in_progress` if the fence is released, releasing or reacquired), and **before each round** it re-checks the lease; on a failed re-check it stops and returns `Err(uninstall_in_progress)` (no partial reply). Each round runs in the lease's scope, so its commits are lease-checked in the write closure. P8 owns the reply payload (the `RemoteRetry` type and the per-record body of the loop); G8 does not touch them. Please keep the loop head `for before in self.pending_remote_revocations().await? {` with G8's `lease.check()?` as its first statement.
- **G8 → L5 (history; `enrollment_m03/verify.rs`):** G8 changes only the spawn in `verify_operation`'s `Flight::Lead` arm: `tokio::spawn(...)` → `spawn_with_lease(...)` (carries the caller's holder lease, if any, into the leader). Nothing else in verify.rs.
## Worker sections
### G8
- **Landed (item 1, the holder lease):** `heimdall_app::operations::{FenceLease, with_fence_lease,
  UNINSTALL_FENCE_RELEASE_WAIT}`; `Operations::{uninstall_fence_lease(conn) -> Option<FenceLease>,
  uninstall_fence_release_waiting(conn)}`. **Removed:** `as_fence_holder` (and `FENCE_HOLDER`). A lease =
  connection + fence generation (each acquisition +1); every live lease (clones included) counts as holder
  work. `uninstall_fence_release` lifts at once only with no holder work; otherwise the fence is
  **releasing** (leases invalid, new work refused, no lease granted, acquire by anyone refused) and lifts when
  the last lease drops. The dispatcher's `release` waits (≤ 20 s) and answers `SERVICE_UNAVAILABLE`
  `uninstall_in_progress` when the bound is hit (Q-G8-R11-1). `spawn_with_lease` (crate-private) carries a
  counted clone into spawned work.
- **Checks:** admissions (`fence_admit`, `fence_admit_pipeline`) exempt only under a valid lease, refused
  under a stale one; `write_extension` none under a lease; `write_admitted` carries the task's lease into
  the blocking closure and refuses (`uninstall_in_progress`, nothing written) before the transaction if it
  no longer stands; the retry handler takes this connection's lease, checks it before each round and runs
  each round under it.
- **Converge sites:** holder-exempt: the five above + dispatcher (`uninstall_fence_lease` replaces the
  holder-id compare and `as_fence_holder`; the retry arm no longer wraps). Spawns from holder work:
  `operations.rs` ensure `lead` ×2 and `local_lead` → `spawn_with_lease`; `verify.rs` leader →
  `spawn_with_lease`; `singleflight.rs:167` (a follower's waiter, no work) and `dispatch.rs` event relay
  unchanged; `verify.rs` debug-only result-write spawn unchanged (L5's; debug builds; not fence-gated).
  Commits in holder work: every one goes through `Operations::write`/`write_admitted` (lease-checked);
  the timegate anchor write stays outside (round-10 A7). Not a holder exemption:
  `reverify_pass`'s `uninstall_fence_held()` skip.
- **Tests:** e2e `fence::recheck3_fence_holder_can_finish_own_verification`; model_operations
  `recheck3_released_holder_must_not_continue_retry_under_new_fence`; app
  `uninstall_fence_m03::tests::{holder_spawned_task_keeps_the_lease, earlier_generation_lease_is_refused}`.
- **§17.33 item 9 (Q-G8-R11-1 accepted):** reason `uninstall_fence_release_stuck` (SERVICE_UNAVAILABLE) in
  `reason::M03`, `m03-reasons.golden.json`, ADR-0006 §16.6 row. Fence state records `release_started`; every
  fence refusal goes through `UninstallFence::refusal()`: releasing past `RELEASE_WAIT` → the stuck refusal
  (message names "stop the runtime (`heimdall service stop`), then start it again (`heimdall service run
  --detach`)"), else `uninstall_in_progress`. The release request's own bound-hit answers the stuck refusal.
  `runtime::dispatch::error_value` adds `data.next_command` = `heimdall service stop` and `data.next_step` =
  that text for this reason. Re-exports: `uninstall_fence_release_stuck`,
  `UNINSTALL_FENCE_RELEASE_STUCK_NEXT_{COMMAND,STEP}`. `RESIDUALS` +
  `uninstall_fence_release_stuck_until_holder_work_ends` (FailClosedOnly; probe `-p heimdall-app --lib`
  `operations::uninstall_fence_m03::tests::fence_release_stuck_past_its_bound_refuses_with_the_restart`).
  Tests: that one + `runtime dispatch::tests::fence_release_stuck_refusal_names_the_restart`.
### K4
- Landed (W5-E02): `heimdall_issuer::client` — `load`/`sign` exchanges own their admissions until the reply is
  consumed; on cancel/timeout/broken the exact child (PID + start token + image, re-read) is signalled only if
  verified, stdin closed, exit awaited ≤ 5 s, then admissions released; unconfirmed → held (background wait).
  New `ClientConfig.{request_hold, child_image}`, `ChildIdentity.image`; `Operations::issuer_request_hold()`;
  `heimdall_runtime::service::issuer_client_config` (pub; the runtime and tests share it).
### P8
Items 3-5 landed (details in the worklog): retry reply `record` + exact byte comparison
(`meta_unchanged_but_for`); new module `crates/heimdall/src/purge_sweep.rs` (anchored Unix walk via
rustix `openat`/`statat`/`unlinkat`, Windows `FILE_FLAG_OPEN_REPARSE_POINT` pinned handles,
residual `WINDOWS_RESIDUAL`); every purge deletion (db files, `backups`, `managed`, `b`, `mux`) goes
through it; `purge_state` calls it.
§17.33 items 7-8: `RESIDUALS` (claims.rs) + validator support in `claims_table.py`; entries
`windows_purge_entry_replaced_between_check_and_delete` and
`uninstall_state_dir_opened_by_path_before_anchored_delete` (probe
`uninstall_purge_never_follows_state_root_replacement`).
