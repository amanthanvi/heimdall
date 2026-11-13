# M03 wave 5, round 3 — questions for the orchestrator

Format: ID, question, evidence (file:line), options, recommendation, what is built and behind which switch.

## Integrator (I)
## U3 (uninstall, inventory, fence)

**Q-U3-1 (fence shape, recorded per §17.27 item 2: built, ADR-0006 §16.6).** Shape chosen:
`Request::UninstallFence(UninstallFenceRequest::{Acquire, Release})`, a new top-level `op` under the
existing `service-control/1` (owner only, any session, synchronous, no operation row).
- *Why not under an existing family:* `Issuer`/`Enrollment` are the families being fenced, and their
  capability gates and owner/attended rules differ; `Shutdown` is the existing service-control request and
  the fence is the same class (an availability action on the runtime, not an authority widening).
- *Options:* (a) as built; (b) `Request::Setup` action (uninstall is a setup operation), rejected: it would
  need `setup/1` and a journaled kind.
- *Recommendation:* (a).

**Q-U3-2 (fence lifetime and scope — authority semantics; escalated, built fail-closed).**
**ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.28 item 1), built in round 3:**
(1) lifetime accepted as built (the acquiring connection; released on finish, refusal or crash; the
20 s wait for in-progress admissions; plain uninstall revalidated too). (2) Scope widened: while held,
every connection other than the holder is refused `SERVICE_UNAVAILABLE`/`uninstall_in_progress` for
every request that can start or advance remote or CA work — new enrollment, CA and issuance admissions,
`Enrollment::Step`, `abandon`, `reconcile`, issuer `retire`/`register`/`unlock`, and approvals. Still
allowed: read-only requests, denials, and `StepResult` for a step dispatched before the fence. The
holder's own requests (incl. the inline retire) are not blocked. (3) Under the fence, any operation with
a dispatched step lacking its result refuses the purge (exit 4; `uninstall_inventory_changed` or a
dedicated additive reason recorded in ADR-0006), lifts the fence, deletes nothing. (4) Regressions: a
second connection's `Step`, `abandon`, `retire` refused; a pre-fence step's `StepResult` accepted; a
dispatched-but-unresolved step blocks the purge; each shown failing with its fix reverted.
- *Built:* the fence is bound to the acquiring control **connection**. The runtime identifies a
  connection by its dispatcher clone (`runtime::dispatch::ConnectionScope`: the control listener clones
  the dispatcher once per accepted connection, `service.rs:1132`, and drops it when the connection ends);
  dropping the holder's scope releases it, so CLI exit, refusal, crash or kill all lift it, and so does a
  runtime stop. No lease or timeout while the connection lives (the uninstall may legitimately wait
  ≤ 120 s at each inline retire prompt).
- *Scope built:* refused while held: enrollment apply/verify/remove (own and foreign)/reconcile;
  issuer register (incl. rotation/restore) and unlock; every certificate reservation
  (`reserve_issuance_with`); approving `enroll_account`, `enroll_system_form`, `remove_enrollment`,
  `approve_target_change`, `register_issuer` decisions; the reverify and re-issue supervisor passes skip.
  **Not** fenced: step/step_result (already-admitted remote work must record its results), abandon,
  denials, `retire_issuer` and every M01/M02 kind (uninstall's own rollback and retirement run under it).
  `acquire` drains admissions already past their check (shared/exclusive lock, ≤ 20 s, else refused
  `uninstall_in_progress` with nothing changed), so the re-read under the fence sees every obligation
  admitted before it.
- *Defence in depth built:* after the runtime stopped and before deleting, the CLI re-reads the store
  read-only once more and refuses the purge (`uninstall_inventory_changed`, effect `partial`: the
  rollback ran) if the outstanding obligations differ from the confirmed ones — covers work admitted
  before the fence that moved afterwards.
- *Options:* (a) as built; (b) a lease the CLI renews (needs a concurrent renewal task during prompts);
  (c) also fence step results (risks losing a remote step's result).
- *Recommendation:* (a). *Switch:* none needed; every refusal deletes nothing.
- *Also applied to the plain uninstall* (no purge): the fence is taken and the inventory revalidated the
  same way when the first read succeeded (a plain uninstall keeps the state, so this is stricter than
  required). Confirm, or limit to `--purge-state`.

**Q-U3-2 implementation note (round 3, after the ruling).** Gate placement: the dispatcher
(`runtime::dispatch::fenced` + the connection scope), which holds the shared admission guard from
the check to the end of the request, so `acquire`'s drain covers every fenced request; the holder's
requests run in `app::operations::as_fence_holder` (a task-local scope). The app keeps only the
checks no request carries: the certificate reservation (`fence_check`, holder scope exempt) and the
two supervisor passes. The earlier app-level request gates were removed (a nested shared lock inside
the dispatcher's guard could stall behind a queued `acquire`). Unresolved-step reason: a dedicated
`uninstall_remote_step_unresolved` (`CAPABILITY_UNAVAILABLE`, exit 4), because the inventory did not
change and the remedy is different (ADR-0006 §16.6). "Dispatched without its result" = the
operation's journal has `outstanding` (step issued, no result) **or** `uncertain` (result lost:
remote effect unknown); checked for `--purge-state` only, and the last pre-delete check compares it too.

**Q-U3-3 (`uninstall_inventory_changed` code).** Registered with `CAPABILITY_UNAVAILABLE` (exit 4),
reasons in ADR-0006 §16.6 row 3. `next.action` stays the code default (`narrow_request`); the command
is carried as `data.next_command: "heimdall uninstall"` (no `NextAction` field holds a command).
Options: (a) as built; (b) a new `next.action` name (contract change). Recommendation: (a).

**Q-U3-4 ("unresolved late_write").** Read as `EnrollmentRecord.late_write.is_some()`: no code path
clears the residual today (`grep late_write crates/app/src` shows only sets), so a passed not-after with no
later absence inspect is still outstanding (tested both). When an absence inspect starts clearing it, the
inventory follows automatically. Recommendation: confirm.
## K3 (ceremonies)
- **K3-Q1 (no ruling needed now; for U13).** Windows: a ceremony read with the console's processed
  input on turns Ctrl-C into `CTRL_C_EVENT`, which ends the process (nothing more is sent: fail closed)
  instead of answering `NotConfirmed`/exit 3. Evidence: `crates/issuer/src/ceremony.rs` Windows
  `read_answer` (unchanged console mode except echo). Options: (a) leave to U13's native harness and
  fix there (turning processed input off makes Ctrl-C a byte that only ends the line at Enter);
  (b) install a console control handler for the read. Recommendation (a). Built: nothing new.
- **K3-Q2 (refusal code for a replaced executable).** `StoreError::ExecutableChanged` (macOS `put`,
  before any write; `crates/issuer/src/sys.rs` `running_code_satisfies`) needs an envelope. Options:
  (a) `SERVICE_UNAVAILABLE` without a reason (exit 5, "run the command again"); (b) a new reason
  `issuer_executable_changed` (contract + golden, integrator). Recommendation (b) eventually, (a) now.
  Built: (a) (`CeremonyError::code`), nothing written either way.
- **K3-Q3 (release signing; for U13/packaging).** A keychain item's access list trusts the writer's
  designated requirement. For an ad-hoc-signed build (debug, or any unsigned release) that is its
  cdhash, so after **any** update the new binary (CLI or `internal issuer` child) cannot read an
  existing K_ca without a prompt, which Heimdall never shows: `issuer_store_locked` until a restore.
  Observed here with the per-rig snapshot reverted (items written by one build, read by another).
  Options: (a) require Developer-ID signing (stable DR: identifier + team) for macOS releases and
  record it as a release obligation; (b) widen the access list (weaker). Recommendation (a).

## D3 (consent, disclosures, rendering)
