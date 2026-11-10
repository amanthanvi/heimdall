# M03 wave 0: questions and readings of agent O (rows 2-4, 9-12, 19, 21, 22, E10)

Each item names the reading built (fail closed) and the options. File:line at the time of writing.

- **O-Q1 (row 3, how the M01 path is recognized).** `IssuanceRequest` (`crates/app/src/operations.rs`,
  struct `IssuanceRequest`) has no CA field, and its three full literals live in files O does not own
  (`tests/model/operations.rs:1996`, `:3238`; `tests/model/revocation.rs:525`). Built: the request is on
  the **M03 path** when it names a CA through the new `Operations::reserve_issuance_naming_ca(req, ca)`
  (`crates/app/src/operations/ca_issuance_m03.rs`) **or** the grant's recorded `GrantOrigin.mechanism` is
  `managed_certificate`; otherwise the M01 path (no CA selected, bounds name none, `enrolled_cas: None`).
  An entry whose bounds name a CA is always checked on the M03 path (publish too).
  Options: (a) as built; (b) later wave adds `IssuanceRequest.ca_fingerprint: Option<CaFingerprint>`
  with the three mechanical literal edits and drops the extra method.
- **O-Q2 (row 2, sub-reasons of the CA refusals).** `OpError::from_issuance_refusal` (A1, `error.rs`)
  maps all three to one `CAPABILITY_UNAVAILABLE` message. Built (wrapper `ca_issuance_m03::refusal_error`,
  `error.rs` untouched): `CaRetiring` → reason `ca_retiring`; `CaNotVerifiedForPair` → `pair_not_enrolled`;
  `UnknownCa` → no reason. Options: other reasons (`enrollment_unverified` for the second), or a reason
  for `UnknownCa`.
- **O-Q3 (row 9, `next` of a pending-projection success).** ADR-0008 §6.6 says the result carries the
  warning `managed_projection_pending` **and** `next: setup_apply`. Built: `next.action = setup_apply`
  with `next.binding_id` kept (it replaces `use_binding`). Option: keep `use_binding` and carry the
  hint only in the warning.
- **O-Q4 (row 9, missing reason).** ADR-0008 D6 item 7 names `interaction_required` as an `unattended`
  refusal reason; it is not in `envelope::reason::M03`. Built: a local constant
  (`pair_mechanism_m03::INTERACTION_REQUIRED`), never produced in wave 0. **Request to the contract
  owner:** add it to `reason::M03` (`CAPABILITY_UNAVAILABLE`) and its golden.
- **O-Q5 (row 11, a mixed `SetConnectionPolicy`).** An action that widens one field and narrows the
  other (e.g. `existing: graceful` + `multiplexing: disabled` from strict/owned_masters) is widening as a
  whole (contract `PolicyAction::is_widening`): nothing applies before the attended decision; the
  approval applies the whole recorded action with `upsert_policy(.., false)` (the generation does not
  move for its narrowing part). Classification is against the current values (as `Cutoff`): a no-op field
  never widens. Options: (a) as built; (b) apply the narrowing part at once and record a decision for the
  widening part only; (c) refuse mixed actions `USAGE_ERROR`.
- **O-Q6 (row 19, "the launch's program is the verified client").** The application cannot resolve paths
  (no `localenv`). Built, fail closed: the row is written only when the launch's `executable` equals, byte
  for byte, the `path` of an `ssh` `ConsumerExecutable` in the grant's stored `PreparedFacts.executables`
  (`bind_connection_m03::verified_client_image`); no stored integration, a symlinked or otherwise
  different path writes nothing. Also: a dedicated row has `generation: 0`; a replayed launch that claims
  its holder registers too (`claim_replayed_launch`); the row closes in the holder pass's release
  transaction (`release_checked`, only for the exact exited holder). A failed exec leaves the launcher
  as the holder, so it is cleared when the pass observes that exit. Escalation: confirm the reading, or
  have the CLI pass a `verified_client: bool` it computed with `localenv` (a contract field).
- **O-Q7 (row 9, D6 item 7 vs M02).** D6 item 7: `unattended` is met only with `managed_certificate`.
  M02's `u0b_unattended_minimum_unknown_is_capability_unavailable` (`tests/model/operations.rs:10822`)
  has a control where an existing-access fake adapter with `lock_continuity: Verified` meets it. Built:
  `select_adapter` unchanged (preserve list); only the refusal gains its reason
  (`lock_continuity_unverified`, or `projection_pending` while a projection is pending). Production M02
  adapters never report `Verified` (`crates/adapters/src/lib.rs:91`), so D6 holds in production. Ruling
  needed if the control should change.
- **O-Q8 (row 9, limits of the per-pair resolution).** (a) "Projection applied" is
  `ProjectionStatus::Applied { .. }`, not compared with the current projection generation. (b) The
  `offline_until` minimum is checked after preparation (`unmet_minimum`), so a pending projection whose
  offline minimum the existing mechanism cannot meet fails with M01's message, not `projection_pending`.
  (c) The reconcile stage's mechanism re-check (`stage_reconcile`, `catalog_pairs`/`catalog_mechanism`)
  still reads the catalog identity only (no managed grant can prepare in wave 0). (d) The pre-admission
  check refuses only the `managed_certificate` resolution (`driver_unavailable`) and `connection: graceful`
  before any record; `pair_not_enrolled` and `mixed_mechanisms` are refused by resolution (a failed
  operation), as M02 does for `mixed_mechanisms`.
- **O-Q9 (row 4, verification facts).** `VerificationEntry` has no attempt number. Built: attempts =
  the operation's `enroll.verify.started` receipts; entries in the attempt = its entries reserved at or
  after the latest of them; at the verification stage = operation `running`, enrollment `verifying` or
  `reverifying`, and ≥ 1 started attempt. Authorization: a presence/absence `enrollment.verify` naming the
  enrollment is authorized; `enrollment.apply` (its `EnrollAccount` basis) and a target change (its
  `ApproveTargetChange`) are unauthorized in wave 0 (`operation_not_verifying`). The plan's pair and CA
  are the enrollment record's. No event is emitted for verification reserve/publish/void (U5 decides).
  Publish/void use an in-memory map of this instance's reservations (`Inner::managed_ops`), so an entry
  reserved before a restart is never published (it stays counted).
- **O-Q10 (row 10, what is recorded).** The merged (strictest) applicable policy's lock behaviour and
  connection policy, narrowed by the request's `connection.existing: strict`, are recorded in the
  creating transaction; a **default** value is recorded as absent, so M01/M02 origins stay byte-identical.
  The store already refuses any later change (`Txn::set_grant_origin` fills only `covered`/`adapter`).
  For an owner-decision grant the approval prompt's own choice (D9 item 2) is U10's.
- **O-Q11 (row 22).** Journaling `SetPreference` under `catalog` needs a `CatalogAction` variant: added
  `CatalogAction::SetPreference { destination, account, mechanism }` and its `from_request` arm to
  `crates/domain/src/catalog.rs` (A1's file; additive, marked `// M03 wave 0 (O)`). Also built: the
  destination must exist (`NOT_FOUND`); `existing` is a narrowing catalog action (no safe-time wait);
  `existing` on a pair with no stored preference changes nothing; `setup apply` does not mark a
  preference `applied` in wave 0 (the managed projection is U10's). Hooks: `Operations::add_issuing_ca(pair,
  ca, e5)` (refused `pair_not_enrolled` unless `ca` is verified for the pair; `e5` sets managed/pending
  only when not already managed+applied) and `Operations::remove_issuing_ca(pair, ca)` (back to
  `existing`/pending when no verified CA remains), in `crates/app/src/catalog.rs`.
- **O-Q12 (row 11, the lock source).** Agent G owns `Inner.narrowing.lock_source` and
  `Operations::set_session_lock_source` (`operations/authorize.rs`); the policy path reads that source (no
  second one). No source (wave 0 runtime) or `unavailable` refuses `revoke_on_lock` with
  `lock_signal_unavailable`. Linux's `signal_unverified` warning is not added (U9).
- **O-Q13 (E10).** Before a remote mutation's `Attempted` receipt: `CAPABILITY_UNAVAILABLE`,
  `driver_unavailable` (the cancel is allowed by the rule but its driver is U10's); after it:
  `remote_step_in_progress`, `next: reconcile`. Both write nothing. A settled or unresolved enrollment
  operation answers as M01 (idempotent, unchanged).
- **O-Q14 (row 12).** `mechanism_refuses` now refuses a degraded grant only when its reason's
  `sign_rule()` is `Refuse` (today exactly `mechanism_unavailable`, so M01 behaviour is identical);
  `credential_reissue_pending` (`NoKey`) is the signer's refusal, never the re-issue's. The rule is the
  public free fn `operations::degraded_refuses_use`.

## Q4, ruled (orchestrator)
Accepted: no `interaction_required` reason in wave 0. Whichever later unit first produces it adds it to the
reason table (`reason::M03`) and the golden (`tests/contracts/golden/m03-reasons.golden.json`).
