# M03 wave 4, round 2 — integrator worklog

Base: `d74e35cf` (round-1 checkpoint) + uncommitted ADR-0008 §17.21 (orchestrator's; never edited here).
Goal: §17.21 items 1–11; `check.sh` all-zero; xchecks; umask-002; container; revert proofs; report.

## Decisions
- R2-D1. Four parallel workers (A enrollment, B issuer, C managed binding, D runtime) per the
  ownership map in `.m03-wave4-r2-api.md`; phase 2 (E) writes the cross-cutting e2e tests (full flow
  ensure+ssh, a10 ×2, issuer crash) once item 1 is in.

## Progress
- [ ] A  - [ ] B  - [ ] C  - [ ] D  - [ ] E  - [ ] checks  - [ ] archive

## Commands (exit codes)
- Workers A–D returned (reports in conversation; worklogs `-A..-D`).
- I-R2-1. `service.rs` `LateRegistry`: forwards `create_binding_endpoint`/`remove_binding_endpoint` (R2-C
  request) — without it production never creates a binding endpoint.
- I-R2-2. Removed the empty `IssuerProcessState`, `ManagedOpsState.issuer`, `DecideCtx` (R2-B request).
- I-R2-3. R2C-Q1 (ADR-0008 D6 item 7 / D10 item 6 reading, flagged for review): `fresh_pair` keeps a
  `managed_certificate` pair's signer facts (interaction `none`, eligible; only the check time moves);
  `fresh_fallback_refusal` refuses a non-`exclusive` managed pair without consulting its catalog identity;
  `adapters::managed::prepare::pair_integrations` now carries each pair's own D10 item 6 selection and report.
  Regression `operations::tests::managed_pair_commit_eligibility_is_the_signers_and_follows_its_selection`:
  `fresh_pair` guard reverted → exit 101 (operations.rs:12428); fallback guard reverted → exit 0 (the M02
  path also refuses this fixture: the guard is defence in depth, not proven load-bearing); restored → 0.
- I-R2-4. `StoreCleanup::bindings_and_slots` also finds an ended grant's slots through
  `held_slots_of_ended_grants` (a released binding has no grant reference). Regression
  `wave4::released_binding_held_slot_cleared_after_grant_ends`: reverted → 101 (runtime_m03.rs:3675);
  restored → 0.
- `cargo fmt --all`; `cargo build --workspace --tests --locked`: 0, no warnings.
- R2-E returned: the four cross-cutting tests (full flow ensure+ssh, a10 ×2, issuer crash) pass; one product
  defect fixed (`prepare_error`: managed issuer refusal → `CAPABILITY_UNAVAILABLE issuer_unavailable`, D3 item 7),
  revert proof 101/0. Raised R2E-Q1..Q3.
- R2E-Q1 (D5 §6.6 ruled: the projection becomes applied through M02's journaled setup apply) and R2E-Q3 (D3
  item 7 "or the store reason") are owed implementation → worker R2-F. The T3 server restarted while it ran; its
  worklog shows both fixes done with revert proofs (R2E-Q3: 101/0; R2E-Q1: R1/R2/R3 each 101, restored 0) and the
  e2e setup-apply leg through the real setup path. Its final checks had not run: taken over by the integrator
  (no cargo was running). `cargo fmt --all --check`: 0. `Cargo.lock`: only `heimdall`'s array (+ adapters,
  credential; pre-authorized).
- check.sh (round 2) run 1: exit 0, every step 0 — 2735 passed, 0 failed, 188 ignored, 84 targets;
  native-harness-selftest 316/0; canary count 0. Run 2: exit 0, every step 0, same totals.
- `linux-xcheck.sh --workspace`: 0.
- umask 002 (host): `integration_runtime_m03::setup_switch::setup_rollback_or_existing_rendering_never_marks_pair_applied`
  failed (exit 101 under umask 002, 0 under 022): the fixture wrote `~/.ssh/config` 0664, which M02 correctly
  classifies `unmanageable_file` (manual mode; the rollback plans no items). Fixture fix: chmod 0600 explicitly.
  After: 3/3 under both umasks; full umask-002 set (e2e_enroll 62, e2e_managed 16, runtime lib 36, issuer_m03 17,
  runtime_m03 42, operations_m03 37, app lib 50): exit 0.
- Container (ubuntu:24.04 amd64 under Rosetta, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, user hmtest, --network none,
  umask 002; validation only): e2e_managed 16/0, runtime lib 36/0, issuer_m03 17/0, operations_m03 37/0, app lib
  50/0; runtime_m03 40/2 (`wave4::connections_close_routed…`, `wave4::sweep_closes…`: the known
  `/proc/<pid>/exe` = `/run/rosetta/rosetta` artefact, devbox-native needed); e2e_enroll 60/2: both `a10_*`
  asserted 10.x's log wording (`Refusing certificate ID "<id>" …`); 9.6p1 logs the bare `Certificate does not
  contain an authorized principal` (probed). Test fix: a log mark (new `LoopbackSshd::{log_mark,
  log_lines_since}` in testkit) so only this attempt's lines count, either wording accepted, and h2 accepted no
  certificate of the grant. After: e2e_enroll 62/0 in the container, 62/0 on the host. Image removed by name;
  cross dirs pruned.
- check.sh run 3 (testkit insertion misplaced a doc comment): clippy and clippy-windows 101 (`missing_docs`,
  duplicate `#[must_use]`); fixed; run 4 is the final.
