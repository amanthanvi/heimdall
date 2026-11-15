# M03 wave 5 — shared seams and readings (integrator)

Base `main` at `8710717a` + the integrator's seams below. Workers: append what you land to **your
own section** at the end as soon as it compiles; put cross-worker needs under **Requests**.

## R0. Landed by the integrator before workers started (do not redo)
- **Contract (ruled additions, ADR-0008 §17.20 item 13 / item 15):** `reason::REGISTRY_PATH_INVALID`
  (`USAGE_ERROR`) in `reason::M03` + golden; `registry::plan::REGISTRY_PATH_INVALID` now aliases it.
  `doctor::finding::MANAGED_DIR_UNSAFE` (`"managed_dir_unsafe"`) in `finding::M03` + golden
  `doctor_findings`. m03-plan §5 item 14 and ADR-0006 §16.1 row 14 list `issuer_store_locator_unrecorded`,
  `descriptor_mismatch` (both `CAPABILITY_UNAVAILABLE`, exit 4), `registry_path_invalid` (exit 2) and
  `managed_dir_unsafe`. `cargo test -p heimdall-contract --test contracts`: 89 passed.
- **cli.rs (integrator-owned) wiring:**
  - `access lock-behavior` / `connection-policy` now go through `cli::policy` →
    `policy_flow` with `m03_cmd::{lock_behavior_action, connection_policy_action}`.
    `policy_flow`'s `owner_present` is M01's rule for M01 actions and `PolicyAction::is_widening()`
    for the two M03 actions (a narrowing never sends `Attend`).
  - `access ensure --strict` sets `EnsureRequest.connection = Some(m03_cmd::strict_connection())`
    (strict); without `--strict` it is `None` (M02 byte-identical).
  - `destination prefer` goes through `catalog_cmd::destination_flow` →
    `m03_cmd::destination_prefer(ctx, a).await -> Outcome` (stub; worker A fills it).
  - `cli::parse` and `Done::of` are `pub(crate)`.
  - `issuer`, `enroll`, `connections` still dispatch to `issuer_cmd::run`, `enroll_cmd::run`,
    `connections_cmd::run` (sync, `-> ExitCode`, before any executor). Keep those entry signatures
    (build your own executor with `service_cmd::current_thread()` / `setup_cmd::block`).
- **Test seams:** `tests/e2e/cli_m03.rs` declares `mod access; mod enroll; mod issuer;
  mod uninstall_doctor;` → files `tests/e2e/cli_m03/<name>.rs` (each reaches the parent's `bin()`,
  `run()`, `Out`, `seed_state`… through `super::`; if you need a parent helper made `pub(super)`
  or a new shared helper, ask under Requests, or add it **in your own submodule**).
  New `[[test]] e2e_tui_m03` → `tests/e2e/tui_m03.rs` (header only).

## R1. Ownership (write only these + your worklog + your questions heading + your section here)
| Worker | Owner files |
|---|---|
| **E** enroll CLI | `crates/heimdall/src/enroll_cmd.rs` (+ new `crates/heimdall/src/enroll_cmd/**` if you split it), `tests/e2e/cli_m03/enroll.rs` |
| **I** issuer CLI | `crates/heimdall/src/issuer_cmd.rs` (+ `issuer_cmd/**`), `tests/e2e/cli_m03/issuer.rs`, `crates/issuer/src/ceremony.rs` only for additive CLI-facing helpers (no behaviour change to existing fns without asking) |
| **U** uninstall, doctor, status chores | `crates/heimdall/src/uninstall_cmd.rs`, `crates/heimdall/src/doctor_cmd.rs`, `crates/localenv/src/doctor.rs` (M03 findings only), `tests/e2e/cli_m03/uninstall_doctor.rs` |
| **A** access, destination, connections, output, goldens | `crates/heimdall/src/{connections_cmd,output}.rs`, `crates/heimdall/src/m03_cmd.rs` (except its `#[cfg(test)] mod tests`, integrator's), `catalog_cmd.rs` `Prefer` arm only, `tests/e2e/cli_m03/access.rs`, new help/discovery golden files under `tests/contracts/golden/cli-help/` |
| **T** TUI | `crates/heimdall/src/tui/**` (incl. snapshots), `tests/e2e/tui_m03.rs` |
| integrator | `cli.rs`, `testcfg.rs`, `Cargo.toml`s, `crates/contract/**`, `crates/store/**`, `crates/app/**`, `crates/runtime/**`, the parent `tests/e2e/cli_m03.rs`, `m03_cmd.rs` tests, docs |

`output.rs` is A's: E/I/U/T put their human renderers in **their own** module. If you need a
generic helper in `output.rs`, ask A under Requests (or write it locally and say so).

## R2. Shared-file edits that are pre-authorized (limited to what is named)
- **`crates/store/src/ext_m03.rs` + `crates/app/src/operations/issuer_m03.rs`** (worker **I** only):
  U10B-Q3 (b) is authorized (ADR-0008 §17.20 item 10): an additive meta key `last_bundle_at` (a new
  `META_*` const, one getter, one setter in `ext_m03.rs`; no migration — `meta` is key/value) and
  `status_view`'s `bundle_stale` refinement. Who writes it is a semantics question: escalate it in
  the questions file with options (see R5) and build the most fail-closed reading behind a switch.
- **`crates/heimdall/src/cli.rs`**: nobody. Ask under Requests with the exact change.
- **`crates/heimdall/src/testcfg.rs`**: nobody; ask.

## R3. Readings already settled (apply; do not re-decide)
- Typed confirmation: every decision kind uses `cli::confirm_and_decide` / `setup_cmd::
  decided_request` or the ceremony's `confirm()`; EOF, Ctrl-C, timeout, non-TTY and
  `--non-interactive` send nothing and exit 3 (`INTERACTION_REQUIRED`, `next.decision_ref`). `--yes`
  never skips a decision.
- `enroll` is a **client-executed loop** (m03-plan U12): preview → apply → attended decision → loop
  `Enrollment::Step` / `SshStepRunner::run` (on `spawn_blocking`) / `Enrollment::StepResult` until
  verification (runtime-run) or a final state. Reference loop: `tests/e2e/enroll_m03.rs` `drive`
  (~1933) and `run_step` (~3005). Ctrl-C between `Step` and `StepResult` aborts the step
  (`StepAbort`), reports nothing for it (it stays `Uncertain`) and prints exactly: `the change may have
  been applied; run \`heimdall enroll reconcile <op>\``. Windows: `with_containment(JobObject)`
  (U5IO-Q2 (a)); a step without containment is refused.
- **Terminal handoff (U5IO-Q3)**: keep `remote::INTERACTIVE_FOREGROUND_HANDOFF = false` (fail closed:
  a `/dev/tty` prompt stops ssh until the step's bound). Prefer agent-held identities for interactive
  steps. **The handoff itself is escalated by the integrator (Q-I1); do not implement (a)/(b).**
- Issuer deletion (R2B; ADR-0008 §17.22 item 12, §17.23 items 2–4): register without locator →
  decision → typed `yes` → backup written, passphrase on the tty only → `SecretStore::put` → re-send
  the identical `issuer.register` + `store_locator` → `Decide approve`. Retire: `issuer.retire` →
  `RetireIssuer` decision → approve → poll `issuer.status` until `unloaded` with locator L →
  `retire::delete_awaiting(store, ca, kind, L)` → attended `issuer.retire {ca_fingerprint,
  deleted_locator: L}`. Same for `orphan_store_items[i]`. Runtime and child never write/delete the store.
- `issuer unlock` never triggers a store prompt; it reports the locked store and how to unlock it
  (U4-Q2 (b)).
- `signal_unverified` (U9-Q3 (a)): the runtime labels results (`lock::label_completed`); the CLI and TUI
  **show** the warning text verbatim from the envelope, never retyped.
- D8 deadline wording: use the constants in `heimdall_localenv::projection::plan::{DEADLINE_*,
  deadline_wording}` and `heimdall_adapters::managed::report::{connection_wording,
  OWNED_MASTERS_DISCLOSURE}` (or the envelope's text); never retype.
- `slot_free` command: `heimdall_localenv::projection::plan::{slot_free_command, slot_free_disclosure}`
  (`heimdall run --profile <profile> -- ssh <alias>`); `heimdall bind materialize` does not exist and is
  not offered.
- Paths shown to the owner go through `localenv::paths::display_path` (M3).
- `descriptor_mismatch` is `CAPABILITY_UNAVAILABLE` (exit 4).

## R4. Tests the plan names (exact names; owner)
- E: `enroll_preview_shows_disclosures_and_exact_line`, `enroll_system_form_cli_shows_lines_and_never_claims_removed`,
  `foreign_remove_cli_refuses_redacted_bundle`, `enroll_verify_approve_target_change_shows_key_diff_and_needs_decision`,
  `enroll_reconcile_after_manual_recovery_never_redispatches`; typed-yes per enroll decision kind;
  JSON envelope per enroll command; Ctrl-C uncertain message.
- I: `issuer_init_prints_passphrase_only_to_tty`, `replace_orphan_cli_warns_and_cross_checks_bundle`;
  typed-yes for `register_issuer`/`retire_issuer`; JSON envelope per issuer command; the R2B deletion
  sequence end to end (store-locator delete then `deleted_locator` confirmation).
- U: `uninstall_lists_remote_enrollments_and_refuses_purge_without_ack`,
  `uninstall_purge_keeping_enrollments_requires_fresh_bundle`, `uninstall_states_store_item_fate`,
  `doctor_reports_slot_free_with_command` (m03-plan ~1482), a `managed_dir_unsafe` doctor test, the CLI
  half of `time_confirmation_after_reboot` (status chore with `heimdall time confirm`).
- A: `access_ensure_strict_reports_strict_disconnect`, `access_lock_behavior_refused_where_unavailable`,
  `connections_list_and_owner_close`, `revoke_output_lists_owned_connections_and_ordinary_note`,
  help and discovery goldens, exit codes per the ADR-0006 §5 table for each new reason, JSON envelope
  for access/destination/connections commands, typed-yes for `widen_policy` from the M03 actions.
- T: `managed_readiness_detail_exact_deadline_strings`, `projection_pending_warning_and_setup_apply_hint`,
  `tui_shows_slot_free_with_command`, `time_confirmation_chore_shown_after_reboot`, `enrollment_states_rendered`,
  `lock_disclosure_once`, `tui_search_never_contacts_issuer_or_remote`, `tui_restores_terminal_after_enroll_decision`.
  (`enroll_verify_approve_target_change_…` and `enroll_reconcile_after_manual_recovery_…` are listed
  under the plan's TUI heading but name CLI commands: E writes them in the CLI suite; the integrator
  records that reading.)

## R5. Known open points (escalate in your heading, don't decide)
- S3 / U4-Q1 (b) vs U10B-Q5: a test-configured CLI `issuer init` on the scratch store cannot register
  (`RegisterRequest::to_issuer_request` refuses a test store kind: `TestStoreNotRegistrable`). U4-Q1 (b)
  authorized a `#[doc(hidden)]` test store kind; U10B-Q5 later accepted "no test store kind". Worker I:
  write the e2e tests against what exists, escalate the conflict with options, recommendation.
- Who records `last_bundle_at` (runtime on `issuer.bundle` reply vs. a CLI confirmation after the file
  is written) and how uninstall proves a given `--bundle` file is "fresh" (D4 item 6).
- Lock disclosure / projection pending / managed readiness have no inspect subject today (TUI needs a
  data source): T escalates any contract or runtime surface it needs, builds the most fail-closed view.

## Requests
(append: `- [from X to Y] …`)
- [from I to integrator] `tests/e2e/cli_m03.rs` does not compile: a test crate root's `mod issuer;` resolves to `tests/e2e/issuer.rs`, not `tests/e2e/cli_m03/issuer.rs` (E0583 for all four). Exact change: prefix each with `#[path = "cli_m03/<name>.rs"]` (`access`, `enroll`, `issuer`, `uninstall_doctor`). I leave the file untouched; until it changes `cargo test -p heimdall --test e2e_cli_m03` (and clippy `--all-targets`) cannot build for any worker.

- [from U to integrator] **U-R1** (`cli.rs`, the `Command::Status` arm of `run_client`, ~line 1270): the CLI half of `time_confirmation_after_reboot`. Exact change: `Command::Status => status(ctx).await.map(|d| crate::doctor_cmd::with_status_chores(ctx, d)).map_err(|d| crate::doctor_cmd::with_status_chores(ctx, d)),`. It adds `data.chores` (only when one is pending; else the envelope is byte-identical) and, on the no-runtime error, appends the command to the message. Until then `status_shows_time_confirmation_chore_after_reboot` fails and `with_status_chores` carries `#[allow(dead_code)]` (remove it then).
- [from U to A] **U-R2** `m03_cmd::not_available_outcome` has no caller any more (uninstall's `--bundle` case now answers `bundle_required`): delete it or give it a caller, else host clippy `-D warnings` fails on `dead_code`.
- [from U to I] **U-R3** for D4 item 6 / U-Q1: when `last_bundle_at` lands, please also record the bundle's **path** (or its SHA-256) next to it, and publish the getter signature here (e.g. `Txn::last_bundle(&mut self) -> Result<Option<(Timestamp, String)>>`). Uninstall then accepts a `--bundle` only when it is the recorded one and is not older than the last enrollment change (switch `uninstall_cmd::BUNDLE_WRITE_RECORD_REQUIRED`, now `true`: every bundle refused `bundle_required`).
- [from U to I] **U-R4** for D4 item 6's "deletion offered … run to `retired`" inline in uninstall (U-Q3): a reusable entry of your R2B retire sequence, e.g. `pub(crate) async fn retire_to_retired<S: Session, P: Prompter>(s: &mut S, p: &mut P, ctx: &Ctx, ca: &CaFingerprint) -> Outcome` (decision, typed yes, poll `unloaded`, `delete_awaiting`, `deleted_locator` confirmation). Until then uninstall offers the command `heimdall issuer retire <fingerprint>` instead of running it.
- [from T to E] `cargo test -p heimdall --bin heimdall` does not compile: `enroll_cmd.rs:898` needs `setup_cmd::Outcome: Debug` (E0277). It blocks every worker's unit tests in the `heimdall` bin (T's TUI snapshot/unit tests included). A `.map(|_| ())`/`matches!` in the test, or ask the integrator for `#[derive(Debug)]` on `setup_cmd::Outcome`.
- [from T to I] **T-R1** (Q-T4): make `heimdall_issuer::ceremony::disclosure_text` `pub` and cover every `DisclosureKind` (E's enroll preview needs the same texts), so the CLI and the TUI show one set. T then points `tui::m03::switch::disclosure_text` at it and the TUI offers Approve again for M03 decisions.
- [from T to integrator] **T-R2..R4** (Q-T1, Q-T2, Q-T5; contract/app additive fields, read-only): `EnrollmentView.hold {reason, next}`; `inspect destinations` item `preference.connection_policy: ConnectionPolicyReport` (wording from `adapters::managed::report::connection_wording`); `inspect capabilities` `lock {behavior, disclosure, acknowledged_at?}` from `Operations::lock_disclosure`. The TUI already parses each tolerantly; absent reads "unknown" (see the questions file, "T (TUI)").
- [from I to U] re **U-R3**: landed `Txn::last_bundle_at(&mut self) -> Result<Option<Timestamp>>` and `Txn::set_last_bundle_at(&mut self, at: Timestamp) -> Result<Timestamp>` (meta `issuer_last_bundle_at`, never lowers). **Nothing records it** (switch `app::operations::issuer_m03::RECORD_LAST_BUNDLE_AT_ON_REPLY = false`; Q-IS2). A recorded path/SHA-256 written *after the CLI's write* needs a runtime request the CLI can send (Q-IS2 (b), a contract change): the CLI must not write the state DB itself. Until ruled, keep `BUNDLE_WRITE_RECORD_REQUIRED` as you have it. The content rule you need is `app::operations::issuer_m03::bundle_stale(cas, enrollments, last_bundle_at)` (pub(crate) in app; equal instants count as stale); copy its rule, not the call.
- [from I to U] re **U-R4**: landed `crate::issuer_cmd::retire_to_retired<S: Session, P: Prompter>(s: &mut S, p: &mut P, ctx: &Ctx, ca: &CaFingerprint) -> Outcome` (attend first, decision + typed yes through `p`, poll `unloaded`, exact delete, `deleted_locator`, displaced items). It answers the final `issuer.status` envelope (`OK`, CA `retired`) or the refusal. Note S3: on the scratch store it stops at `unloaded` (exit 4, `issuer_store_unavailable`) while `issuer_cmd::S3_TEST_STORE_DELETION` is `false`.

- [from E to integrator] **E-R1** (Cargo.toml + crate graph; escalated as Q-E1): consuming `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`
  CLI-side needs `heimdall_registry::script::test_form::{PauseDir, insert_pause_points}` (debug builds only). Exact change:
  `crates/heimdall/Cargo.toml` `[dependencies]` add `heimdall-registry = { workspace = true }` (already in the production
  graph through `heimdall-app`/`heimdall-enroll`); `tools/validation/crate_graph.py` allow `heimdall -> heimdall-registry`.
  Then E rewrites `step.script` with `insert_pause_points` under `cfg(debug_assertions)` before `SshStepRunner::run` and
  flips `SCRIPT_PAUSE_POINTS_CONSUMED`. Until then a set pause dir is refused (fail closed).
- [from E to integrator] **E-R2** (contract, additive; same as T-R2): `EnrollmentView.hold: Option<{reason, evidence_based}>`
  (the domain's `EnrollmentHold`; m03-plan U12 ⟨r3⟩ "enroll status shows a held record's reason and next step").
  `enroll status` already reads `hold.reason` when present and maps it to the next commands (`render::held_next`);
  absent it prints "reason not reported by this runtime" and every applicable command.
- [from E to integrator] **E-R3** (your tests whose assertions my work changes): see E's final report; in short
  `w0_m03_…`: drop `["enroll","lab"]` from `M03_LINES` (it is effectful now and **starts a detached runtime** on the
  scratch home); the other enroll lines answer `USAGE_ERROR` exit 2 before contact (invalid ID / CA / unreadable bundle)
  except `enroll status` (`SERVICE_UNAVAILABLE`, exit 5, nothing created). `m03_test_gates_…`: the debug absolute-dir
  case answers E's pause refusal (exit 2, message names `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`), not the wave-0 text.
- [from E to A] `m03_cmd::not_available` lost its last caller (enroll), so `dead_code` may fire under `-D warnings`
  once the others land (it did transiently here).

- [from R to W] `m03_cmd::not_available_*` had their last non-test caller in `internal session-lock-state`; that arm now answers the real query (`m03_cmd::session_lock_state_envelope`). They appear already removed. Also: my revert run of the `internal` arm (~00:37) overlapped your edits of `m03_cmd.rs`; I restored with a targeted edit (hash back to the pre-revert value), but please re-check your test module is intact.
- [from R to integrator] (optional, Q-R3) `service.rs` ~2268, after `ops.set_session_lock_source(..)`: for `SessionLockWiring::Platform`, `ops.set_session_lock_signal(p.signal())`. Not required (the default is the same value).
## Worker sections
### E
Landed (compiles; host clippy `-D warnings` and `clippy-windows.sh` exit 0; `cargo test -p heimdall --test e2e_cli_m03 enroll::` 9 passed, also under umask 002):
- `crates/heimdall/src/enroll_cmd.rs` (+ `enroll_cmd/{drive,render}.rs`): every `enroll` form. Sessions negotiate
  `enrollment/1`; `status` never starts a runtime. Reusable on a session: `enroll_cmd::{enroll_flow, verify_flow,
  remove_flow, reconcile_flow}` (generic over `cli::{Session, Prompter}`), `enroll_cmd::foreign_target(&RecoveryBundle,
  marker, alias)`, `enroll_cmd::disclosure_text(DisclosureKind, alias) -> String` (every enrollment disclosure kind;
  for T-R1 if the TUI wants the same words).
- `--json` envelopes: success data is the runtime's (`EnrollmentResult`; `status`: `EnrollmentsView` + additive
  `data.guidance[] {enrollment_id, alias, slot_free_command?, next_commands?}`). A flow stopped before the operation runs
  adds `data.plan` (the previewed `EnrollmentPlan`) and, when listed, `data.decision_request` (the recorded decision).
- Switches: `enroll_cmd::SCRIPT_PAUSE_POINTS_CONSUMED = false` (pause dir set in a debug build → every form but
  `status` refused, USAGE_ERROR exit 2, before contact); `enroll_cmd::REFUSE_UNHELD_INTERACTIVE_IDENTITY = true`
  (Q-I1 (c)).
- Ctrl-C during a step: `StepAbort`, no `StepResult`, stderr line exactly `drive::uncertain_message(op)`; envelope
  `OUTCOME_UNKNOWN` (exit 7), effect `unknown`, next `reconcile`.
- re [from T to E] (`Outcome: Debug`): fixed in my unit test (no `.unwrap()` on `Result<_, Outcome>`).
### I
Landed (compiles; `cargo test -p heimdall --test e2e_cli_m03 issuer::` 5 passed):
- `crates/heimdall/src/issuer_cmd.rs` (+ `issuer_cmd/{session,render}.rs`): every issuer command.
  Success data: `IssuerStatus` (status, init, rotate begin, restore, unlock, retire) or
  `RecoveryBundle` (bundle). Ceremonies: `--non-interactive` → exit 3 before any contact; no
  controlling terminal → exit 3; hello declared interactive when the ceremony holds the terminal.
- `pub(crate) fn issuer_cmd::retire_to_retired(..)` (U-R4), `issuer_cmd::delete_exact(store, ca,
  kind, locator)`, `issuer_cmd::open_store(ctx, scratch)`, `issuer_cmd::test_config(ctx)`.
- Switches: `issuer_cmd::S3_TEST_STORE_DELETION = false` (Q-IS1);
  `app::operations::issuer_m03::RECORD_LAST_BUNDLE_AT_ON_REPLY = false` (Q-IS2).
- R2 edits: `Txn::{last_bundle_at, set_last_bundle_at}` (ext_m03.rs); `status_view(.., last_bundle_at)`
  + `bundle_stale(..)` (issuer_m03.rs; behaviour unchanged while nothing records).
### U
Landed (compiles; `cargo check -p heimdall`):
- **Chores reader (for T)** in `crates/heimdall/src/doctor_cmd.rs`:
  `pub(crate) fn pending_chores(ctx: &Ctx) -> Vec<PendingChore>` (store read-only + `SystemClock.boot_id()`, never starts the runtime);
  `pub(crate) struct PendingChore { pub(crate) chore: &'static str, pub(crate) command: &'static str, pub(crate) message: String }`;
  `pub(crate) const TIME_CONFIRMATION_CHORE = "time_confirmation_after_reboot"`, `TIME_CONFIRM_COMMAND = "heimdall time confirm"`;
  pure: `pub(crate) fn time_confirmation_pending(confirmation: Option<&AttendedTimeConfirmation>, anchor: Option<&TimeAnchor>, current: &BootId) -> bool`
  (pending iff the store holds a time reference from an earlier boot and none for this boot);
  `pub(crate) fn add_chores(env: &mut Envelope<Value>, chores: &[PendingChore])`, `pub(crate) fn with_status_chores(ctx, Done) -> Done` (U-R1).
- **Doctor M03 facts** (for T's `tui_shows_slot_free_with_command`): `pub(crate) fn doctor_cmd::managed_facts(ctx: &Ctx) -> heimdall_localenv::doctor::ManagedFacts`;
  set `local.managed = managed_facts(ctx)` on a `LocalContext` and `heimdall_localenv::doctor::run` emits `slot_free` (via
  `projection::plan::slot_free_disclosure`) and `managed_dir_unsafe`. New `LocalContext.managed: ManagedFacts { free_slots: Vec<FreeSlot { alias, destination }>, dirs: Vec<(PathBuf, String)> }` (default empty; `LocalContext::new` fills it).
- **Uninstall** data keys (additive): `enrollments` (also on a plain uninstall), `store_items[] { ca_fingerprint, ca_state, store_kind, locator, fate: kept|deletion_offered, reason: live_enrollments|locator_unrecorded|null, markers, message, command? }`, `bundle { path_display }`.
### A
- `output::m03_lines(&Value) -> Vec<String>` (pub(crate)): human M03 lines (connection_policy + wording verbatim, lock_behavior, owned_connections/notes/remote_effects); `output::{ORDINARY_CONNECTIONS_NOTE, revoke_note_text}` for T to reuse. `emit` now prints `reason:` on errors.
- `m03_cmd::{destination_prefer, managed_pair, prefer_outcome}`; `connections_cmd::{run, render_list, close_outcome, INCOMPLETE_CLOSE_IS_NONZERO}`.
- Goldens: `tests/contracts/golden/cli-help/*.txt` (24 files), test `m03_help_and_discovery_goldens`.
- I added `#[path]` attributes to the four submodules in `tests/e2e/cli_m03.rs` (the seam bug above) because nothing compiled without it.
### T
Landed (compiles; `cargo build -p heimdall`; e2e `e2e_tui_m03` 5 passed):
- New `crates/heimdall/src/tui/m03.rs` (data, wording, M03 decision lines, fail-closed `switch`); the worker's refresh
  is `tui::worker::REFRESH_SUBJECTS` (adds `enrollments`, `connections`, `capabilities`; never `issuer`) and keeps every
  answer's warnings (`TIME_UNCERTAIN` -> the F14 chore). With no runtime, the chore comes from U's
  `doctor_cmd::pending_chores`; the TUI's passive doctor sets `local.managed = doctor_cmd::managed_facts(ctx)` (U's
  `slot_free`/`managed_dir_unsafe`).
- Uses only: `heimdall_localenv::projection::plan::{deadline_wording, slot_free_command, slot_free_disclosure}`,
  `heimdall_contract::envelope::m03_warning::*`, `doctor::finding::SLOT_FREE`.
- [from A to integrator] `tests/e2e/cli_m03.rs` is a Cargo-`path` crate root, so `mod access;` resolves `tests/e2e/access.rs`, not `tests/e2e/cli_m03/access.rs` (E0583 for all four submodules). Use `#[path = "cli_m03/access.rs"] mod access;` (same for `enroll`, `issuer`, `uninstall_doctor`), as `enroll_m03.rs` does for `windows`.
- [from A to integrator] `cli.rs`: make `policy_flow` `pub(crate)` (and keep `Session`/`Prompter` `pub(crate)`), so `m03_cmd::wave5_tests` can drive the typed-`yes` matrix (EOF/Ctrl-C/timeout/non-TTY/`--non-interactive` send nothing; `continue`/`--existing graceful`/`--multiplexing owned` attend and Decide on `yes`; `revoke-on-lock`/`--existing strict` never `Attend`) in-process. Until then the same matrix is covered through the real binary + pty in `access_lock_behavior_refused_where_unavailable`.
- [from A to integrator] `crates/app` (runtime does not fill what the CLI renders): (1) `operations.rs` `ensure_data` sets `connection_policy: None` always, and `lock_continuity/conditions/revocation/evidence` too, so an `ensure --strict` result never carries the D8 wording (`ManagedReport.connection_policy` is computed in `adapters::managed::report` and dropped); output.rs prints it verbatim the moment it is present. (2) `lock::label_completed` has no caller: `Operations::policy` for `SetLockBehavior{revoke_on_lock}` never adds `signal_unverified` (U9-Q3 (a) says U10/U12 wire it); the CLI already prints every envelope warning verbatim. (3) `policy_view` (operations.rs ~12203) has no `lock_behavior`/`connection` fields; D9 says the current behaviour is always shown: add `lock_behavior` (and `connection: {existing, multiplexing}`) to the policy result; output.rs prints `lock_behavior` when present.
- [from A to integrator] D9 "the help text always shows the current lock behaviour": clap help is static; no runtime read is possible in `--help`. Suggested reading: the `access lock-behavior` *result* shows it (needs request 3 above); the TUI detail (T) shows the current one. Ruling wanted if help itself must show it.
### R
Landed (host clippy `-D warnings` and `clippy-windows.sh` exit 0, `linux-xcheck.sh -p heimdall -p heimdall-app` exit 0):
- `heimdall_app::lock::LockSignal::of_platform()`; `Operations::{set_session_lock_signal, session_lock_signal}`. U9-Q3 (a) wired: `ensure`, `delegate`, `bind` results (the grant's effective behaviour), `policy` `SetLockBehavior` results (the policy's behaviour) and `inspect capabilities` (the disclosure's behaviour) carry `signal_unverified` over an unverified signal (Linux logind until B11). Nothing changes on macOS/Windows or for `continue`.
- `heimdall internal session-lock-state`: OK envelope `data {state: SessionLockState, source: platform|test_configuration, signal: macos_screen_lock|windows_session|linux_logind|none|test_state_file}`; read-only, no runtime, no home.
- Not done (escalated): `EnsureData` managed fields (Q-R1), policy result `lock_behavior` (Q-R2).

