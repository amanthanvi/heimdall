# M03 wave 0: questions from agent S (store: migration 0006, ext_m03)

Each names the choice taken (the most fail-closed one) and the options.

## S1, ruled: the partial UNIQUE index versus removing an abandoned line
Original question: once a (pair, CA) had a new open enrollment, the plan's index (excluding only final
states and `abandoned`) refused `abandoned → removing`, so the old line could not be removed.

Ruling (orchestrator): the index exists so each (destination, account, CA) has at most one **live**
enrollment, and a removal in progress is not a live enrollment.
1. The index covers only the enrollment-path states: `planned`, `applying`, `outcome_unknown`,
   `verifying`, `applied_unverified`, `verified`, `reverifying`, `held`. It excludes every removal and
   rollback state (`removing`, `remove_unknown`, `removal_verifying`, `manual_removal_pending`,
   `rollback_pending`, `rollback_unknown`), `abandoned`, and every final state.
2. Cancelling a removal returns the row to its persisted `removal_origin` (ADR-0008 §17.4 item 5). From an
   abandoned origin that is `abandoned` (outside the index). From an enrollment-path origin the row was
   already the pair's one live enrollment, so a second live row cannot normally exist; a cancel that would
   collide fails cleanly (`GenerationConflict`), never silently.

`manual_pending` (the system form's enrollment-path state) is inside the index: the integrator added it as
fail-closed and the orchestrator confirmed it is covered by the ruling.

Applied:
* `0006_managed_credentials.sql` (edited in place; not shipped): `WHERE state IN ('planned', 'applying',
  'outcome_unknown', 'applied_unverified', 'manual_pending', 'verifying', 'verified', 'reverifying',
  'held')`, a positive list, so a future state is outside the index only by an explicit decision.
* `ext_m03` unit test `indexed_states_are_the_enrollment_path`: the list equals the domain's states that
  are not final, not `abandoned` and not a removal or rollback state, and equals the SQL's list.
* `Txn::transition_enrollment`: the domain `transition` decides the target and the CAS writes it. An
  `OwnerCancelsManualRemoval` or `AbsenceVerified` event whose `origin` (and `ca_not_held_seen`) differs
  from the record's persisted `removal_origin` is refused (inner `Err(InvalidTransition)`, nothing
  written). A move onto the enrollment path that collides is a `GenerationConflict`.
* Tests: `removing_abandoned_line_while_new_enrollment_open_is_allowed`,
  `cancelling_that_removal_returns_to_abandoned` (also covers the wrong-origin refusal and a colliding cancel
  back to `verified`), `second_live_enrollment_for_pair_and_ca_still_refused` (every live state blocks,
  every other state does not, and `abandoned → removing → held` beside a live enrollment conflicts).

## S1 follow-up, ruled
1. **Confirmed:** a cancel (or absence result) naming an origin other than the persisted `removal_origin` is
   refused and writes nothing (the fail-closed addition to `transition_enrollment` stays).
2. **Ruled:** `held` reached by a removal is a residual, not a live enrollment. A `held` row whose
   `removal_origin` is set is outside the uniqueness index; a `held` row reached on the enrollment path
   (`removal_origin` unset) stays inside.

Applied (0006 edited in place, unshipped):
* `enrollments.removal_origin_set INTEGER NOT NULL DEFAULT 0 CHECK (removal_origin_set IN (0, 1))`, written
  by every enrollment write (`write_new_enrollment`, `transition_enrollment`) from the same record that
  becomes `record_json`. Every enrollment read selects it with `state` and refuses a row where either
  disagrees with the document (`StoreError::Corrupt`), so the column and the JSON cannot silently diverge.
  No JSON function in the index predicate.
* Predicate: `WHERE state IN (<enrollment path incl. manual_pending>) AND NOT (state = 'held' AND
  removal_origin_set = 1)`. The `ext_m03` unit test also asserts the exclusion clause.
* Tests: `removal_held_residual_outside_index_beside_live_enrollment` (abandoned → removing → held beside a
  live planned enrollment of the same pair and CA: no conflict; the residual can be removed again);
  `second_live_enrollment_for_pair_and_ca_still_refused` updated (the residual is allowed; leaving it onto
  the enrollment path, `held → applied_unverified`, conflicts with nothing written; an enrollment-path
  `held` without a removal origin still blocks a second live row).
* Callers: the residual is outside the index only if the caller sets `removal_origin` in the record it
  passes for the move into removal; without it the `held` is treated as live (fail closed).
* Not tested: the column/document disagreement read (no public way to write a disagreeing row).

## S2. `verified_cas_for_pair` leaves out `reverifying`
Evidence: `EnrollmentRecord::issuable(reverify_from)` counts `reverifying` that started from `verified`, but
the record does not store where a `reverifying` run started, so the store cannot tell.
Built: only `verified` counts (fail closed: a pair being re-verified from `verified` is briefly not issuable
through this read). Options: (a) keep; (b) A1 adds `reverify_from: Option<ReverifyFrom>` (serde default) to
`EnrollmentRecord` and the store counts `reverifying` with `Some(Verified)`.

## S3. `IssuerRecord.store_kind` cannot hold the test store kind
Evidence: `contract::issuer::StoreKind` has no test variant (F23); plan §5 item 2 says test builds
"register it through a test-only path". The `issuers` row's `record_json` is typed with `StoreKind`, so a
`scratch_test` row would not decode.
Built: typed `StoreKind` (U4 decides the test-only path). Options: (a) the scratch store registers a real
`StoreKind` value plus a testkit-side marker; (b) the store gains a `#[doc(hidden)]` store-kind string
column/field for test builds.

## S4. E12 and `open_read_only` on a schema-5 file
Evidence: `Store::open_read_only` refuses any older schema with `OlderSchema` (unchanged behaviour), so a
read-only open never reaches a schema without `enrollments`. `uninstall_cmd.rs:272` (`read_counts`) on an
M02 file that M03 never migrated still fails as it did for schema 4 under M02.
Built: `Txn::open_enrollments` treats a missing `enrollments` table as "none" (tested through
`Store::open_at_schema_version(.., 5)`), and `open_read_only` is unchanged.
Options: (a) keep; (b) a separate read-only open that accepts an older schema (a behaviour change, so the
integrator's call).

## S5. Foreign keys beyond the plan's list
Added: `managed_slots.binding_id → bindings(id)`, `owned_connections.binding_id → bindings(id)`,
`owned_connections.grant_id → grants(id)` (both parents are never deleted; M02's `binding_holders` and
`grant_prepared_facts` do the same). Not added: any `operation_id` FK (operations are purged by retention)
and any `destination_id` FK (destinations can be removed). `foreign_removals` has none (F07). Confirm.

## S6. Not done here, for the owners of these files
* `ext::TableCounts` (uninstall's purge counts, ADR-0007 §12.32 item 7) counts no M03 table (ext.rs is not S's).
* No methods yet for the `session_lock_last` and `windows_environment_pipe_token` meta keys (U9/U2 add them).
* `Txn::seed_enrollment` is a `#[doc(hidden)]` test-support insert in any state (for model tests that need a
  `verified` enrollment); production uses `insert_enrollment` (`planned` only).
