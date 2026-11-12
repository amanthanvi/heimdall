# M03 wave 4, round 3 — worklog R3-D (runtime + setup)

Items (ADR-0008 §17.22): 3 (W4-S03), 11 (W4-R09), 13 (R2C-Q2), 14 (R2D-Q1 doc), 16 (R2F-Q1..Q4).

## Decisions
- D3-1 (item 3): `ManagedTeardown` (service.rs) owns everything an end must undo (ops clone, vault,
  registry, late registry, install view, cleanup, issuer, platform lock). Built right after the endpoint
  registry in `ManagedParts::start` (so every later `?` unwinds through its `Drop`), the issuer and lock
  source join it as soon as they exist; `ManagedRuntime` holds it. `Drop` (unless `stop` ran): zeroize,
  **fence + stop the issuer** (`ChildIssuer::stop` spawned on the current tokio runtime; no runtime →
  the last handle's `kill_on_drop`), stop endpoints, shut the lock source, clear `ManagedWiring`, late
  registry, install view, cleanup. `stop(self)` (no `ops` argument now) awaits the issuer stop, runs the
  same `release()`, marks `stopped`.
- D3-2 (item 11): the scenario is one file, `tests/e2e/m02_ensure_golden.rs`, compiled unchanged into
  the base tree and the current tree (API both have): in-process `Operations` + real store, VirtualClock,
  fixture `native_agent` adapter, fixed request. Pinned: `EnsureData` JSON, the dispatcher's wire envelope,
  the raw stored `recovery_intents.record_json`, the request hash. Normalized (CSPRNG-minted by design):
  operation ID, grant ID, binding ID — nothing else. Goldens: `tests/contracts/golden/m02-existing-access-ensure/`.
  Test: `e2e_consumer_m03::existing_access_ensure_bytes_match_base_goldens`.

- D3-3 (item 13, R2C-Q2): the runtime names the endpoint where it answers the bind, not in `drive_bind`:
  `OperationsDispatcher::with_binding_endpoints(Arc<dyn connections::BindingEndpoints>)` (dispatch.rs), wired in
  `Service::run` over the late registry. A `bind` result whose `credential_mechanism` is `managed_certificate` gets
  `consumer.signing_endpoint` = the registry's live endpoint for **that exact** `binding_id`, or none when it is not
  live; every other result is returned untouched. Why not `drive_bind`: the app reaches no runtime registry (no
  port offers a lookup; `ManagedWiring`/`app::ports` are not mine), and a stored copy would go stale. Consequence:
  the stored operation result keeps no endpoint (a replay reads the registry again). No `operations.rs` edit.
  `connect_cmd`: the D8 item 2 flow was already there; `managed_connect_args` split into the pure
  `managed_launch_args` (refuses before launch without a live binding endpoint, `driver_unavailable`), module docs
  updated (the stale "step 3 is never reached").
- D3-4 (item 14): docs only, at `pair_masters_enabled`, `StorePairSource` and `ManagedSectionSpec.control_path`.
- D3-5 (item 16): Q1 `record_managed_projection` takes the committed SSH item's aliases; an `existing` row is
  `applied {g}` when the plan's P renders its alias as existing access (alias ∈ committed aliases, pair ∉
  `managed_pairs`, a rendering intent), else `pending`; rows are only updated, never created. Q2
  `ManagedPairSource::projection_pending` (defaulted `false`; `StorePairSource`: the stored row is `pending`) and
  `plan.rs` `recommit_step`: when P's bytes are already the rendering but a rendered pair's stored preference is
  pending, the plan writes P again (base = target digest, a staged whole-file write, not a file change of the view),
  so the SSH item commits a new generation through the normal journaled path; no source / no rows → no step (M02
  no-op unchanged). Q3 chosen: **return to `pending`** (keep mechanism + issuing CAs) in `RemoveDestination`'s
  transaction; the pair's accounts come from its managed definition and its enrollments under every CA (rows are
  only created for enrolled pairs; enrollments are never deleted); result JSON unchanged. Q4 no code change
  (already counted); regression added. Existing R2-F tests updated for Q1: `h2` is now `existing/applied`;
  `setup_rollback_or_existing_rendering_never_marks_pair_applied` renamed `…_never_marks_managed_applied`
  (the switch-back now records `existing/applied`).

## Progress
- [x] item 3 — [x] item 11 — [x] item 13 — [x] item 14 (docs) — [x] item 16 (Q1 Q2 Q3 Q4) — [x] full suites/clippy/xcheck/fmt

## Commands (exit codes)
### item 11 baseline (W4-R09), base `d6593a7c`
- `S=$(mktemp -d /tmp/r3d-base.XXXXXX); chmod 700 "$S"` → `/tmp/r3d-base.2LiLks`
- `git archive d6593a7c | tar -x -C "$S"` → 0
- `cp tests/e2e/m02_ensure_golden.rs $S/tests/e2e/` (sha256 abfee06b…718af6 at recording) + scratch-only
  `record_base_goldens` test appended to `$S/tests/e2e/consumer_m03.rs` (writes `produce()`'s 4 strings + `\n`).
- `cd $S && HM_R3D_GOLDEN_OUT=$S/out cargo test -p heimdall --test e2e_consumer_m03 record_base_goldens` → 0
  (own `$S/target`, no CARGO_TARGET_DIR).
- rerun into `$S/out2` → 0; `diff -r out out2` → identical.
- `cp $S/out/{result.json,envelope.json,intent.json,request-hash.txt} tests/contracts/golden/m02-existing-access-ensure/`
- current tree: `cargo test -p heimdall --test e2e_consumer_m03 existing_access_ensure_bytes` → 0 (1 passed).
- revert proof: `ResolvedIntent.binding_id` serialized always (`#[serde(default)]`, no skip) → 101
  (`recovery-intent bytes`: `…,"binding_id":null}}`); restored → 0.
### item 3 (W4-S03)
- `cargo test -p heimdall-runtime --test integration_runtime_m03 teardown_r3` → 0 (3 passed:
  `dropped_started_service_stops_issuer_and_releases_vault`, `failed_start_after_issuer_unwinds_and_stops_it`,
  `failed_start_after_managed_start_unwinds_and_stops_issuer`).
- R1 (round 2's drop: no issuer stop, no wiring clear) → 101, all 3 FAILED; restored.
- R2 (guard disarmed until `ManagedRuntime` is built) → 101, only `failed_start_after_issuer_unwinds_and_stops_it` FAILED; restored.
- R3 (drop stops the issuer but does not clear `ManagedWiring`) → 101, `dropped_started_service…` FAILED at the
  vault-released assertion; restored.
- Note: these three reverts restored service.rs from a backup taken at 16:54:47 (final restore 16:55:27); any
  R3-A edit to `mod sources` inside those 40 s would have been overwritten (flagged under Requests). Later
  reverts toggle in place.
### item 13 (R2C-Q2)
- `cargo test -p heimdall-runtime --test integration_runtime_m03 bind_endpoint_r3` → 0 (2 passed:
  `issuer_crash::bind_endpoint_r3::managed_bind_result_names_live_binding_endpoint`,
  `…::existing_access_bind_result_unchanged_by_endpoint_wiring`).
- revert "never fill" (`if false && … MANAGED_CERTIFICATE`) → 101, managed test FAILED; revert "fill every mechanism"
  (`if true || …`) → 101, existing-access test FAILED; restored → 0.
- `cargo test -p heimdall --bin heimdall managed_connect_refuses` → 0
  (`connect_cmd::tests::managed_connect_refuses_without_a_live_binding_endpoint`); revert (no endpoint → `ssh <alias>`)
  → 101; restored → 0.
### item 16 (R2F-Q1..Q4), `cargo test -p heimdall-runtime --test integration_runtime_m03 setup_switch`
- with fixes → 0 (7 passed; new `setup_switch::r2f_r3::{existing_preference_recorded_applied_when_its_rendering_commits,
  unchanged_apply_still_commits_generation_and_preference, removed_destination_preference_returns_to_pending,
  manual_mode_apply_counts_as_applied_with_diagnostic}`).
- Q1 revert (`existing` arm `if false && …`) → 101 (3 FAILED: the Q1 test and the two updated R2-F tests). The first
  attempt hit another worker's transient compile error (`E0382 borrow of moved value: id` in heimdall-app) → invalid, rerun.
- Q2 revert (`None if false && self.projection_pending()?`) → 101 (`unchanged_apply…` FAILED) (first attempt: same
  transient compile error, rerun).
- Q2/M02 revert (recommit unconditionally: `None if true || …`) → 101 (`unchanged_apply…` FAILED at the no-op legs).
- Q3 revert (`if false && removed`) → 101 (`removed_destination…` FAILED).
- Q4 revert (`finish` keeps `managed_pairs` only for `SetupMode::Automatic`) → 101 (`manual_mode_apply…` FAILED).
- restored → 0 (7 passed).
### suites / lint (final)
- `cargo test -p heimdall-runtime --no-fail-fast` → 0 (14 targets incl. model_setup, e2e_setup_dispatch, integration_runtime_m03 51).
- `cargo test -p heimdall --test e2e_consumer_m03 --test e2e_cli_m02 --test e2e_run_m02 --test e2e_managed_m03 --no-fail-fast` → 0
  (7 / 42+1 ignored / 54+1 ignored / 16; the ignored ones pre-exist).
- `cargo test -p heimdall-localenv --no-fail-fast` → 0 (incl. integration_projection*). `cargo test -p heimdall --bin heimdall` → 0 (113).
  `cargo test -p heimdall-app --lib` → 0 (50).
- clippy `-p heimdall-runtime -p heimdall-app -p heimdall-localenv -p heimdall --all-targets -- -D warnings`: first 101 (only
  R3-B `issuer_m03.rs:229` / C2 `managed_store.rs:1476` type_complexity; warn-only run showed no lint in my files); rerun → 0.
- `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: first 101 (same R3-B lint); rerun → 0 (14m41s).
- `rustfmt --edition 2024 --check` on my files (+ runtime_m03.rs, consumer_m03.rs) → 0.
- Final reruns after fmt: `integration_runtime_m03 -- teardown_r3 bind_endpoint_r3 setup_switch` → 0 (12); `e2e_consumer_m03` → 0 (7).
- Scratch removed: `/tmp/r3d-base.2LiLks` (with its 2.2 GB target), `/tmp/r3d-probe`.
