//! Store methods added by the M01 design-fix round (review F02, F04–F08; ADR-0005
//! §3.5/§3.6). Signatures are the contract wave 2 builds against; bodies are
//! M01-U4b (`docs/architecture/m01-plan.md`). Schema: `migrations/0002_*.sql`.
//!
//! Conventions: every method runs inside the caller's [`Txn`]; reads return
//! `Option`/`Vec`; compare-and-swap methods return [`StoreError::GenerationConflict`]
//! on a stale expectation; nothing here purges tombstones, policies, grant
//! anchors, decisions, issuance entries or unresolved operations.
//!
//! Further rules shared by every method here:
//! * inserting a record whose ID already exists is a
//!   [`StoreError::GenerationConflict`] and leaves the stored record unchanged;
//! * updating or completing a record that does not exist is
//!   `StoreError::Sqlite(QueryReturnedNoRows)` (as `Txn::update_operation`);
//! * the store reads no clock: every instant is the caller's.

use std::collections::BTreeSet;

use heimdall_contract::event::Event;
use heimdall_contract::ids::{
    BindingId, CredentialInstanceId, DecisionId, DestinationId, EnvironmentId, GrantId, IdentityId,
    IssuanceId, OperationId, ProfileId, WorkId,
};
use heimdall_contract::request::Verdict;
use heimdall_contract::{GrantState, OperationState, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome};
use heimdall_domain::catalog::{
    DeclarationEndReason, DeclarationState, DestinationRecord, IdentityRecord,
    InteractionDeclaration, PreparedFacts,
};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionRefusal, DecisionState};
use heimdall_domain::environment::EnvironmentRecord;
use heimdall_domain::grant::{AuthorizationSource, DegradedReason, GrantOrigin, GrantReference};
use heimdall_domain::holder::ProcessHolder;
use heimdall_domain::idempotency::IdempotencyRecord;
use heimdall_domain::idempotency::{ExpiredKeyMarker, IdempotencyKey, KeyHash};
use heimdall_domain::issuance::{
    CredentialInstance, CredentialState, IssuanceEntry, IssuanceRefusal, IssuanceState,
};
use heimdall_domain::operation::{
    AdapterIdentity, ApprovalBasis, CoveredBasis, EffectReceipt, FilePhase, ItemPhase, LocalIntent,
    LocalReceipt, OperationKind, OperationRecord, RecoveryIntent, STAGE_SETUP_ITEM, StageReceipt,
};
use heimdall_domain::policy::{AuthorityGeneration, StandingPolicy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::profile::{ProfileDefinition, ProfileSnapshot};
use heimdall_domain::projection::{
    ConsentRecord, ConsentedStates, FileIdentity, ItemCommit, ItemId, ProjectionLocator,
    ProjectionRecord, projection_resource_id,
};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_domain::revocation::{CleanupIntent, PendingRemoteRevocation, Tombstone};
use heimdall_domain::time::{AttendedTimeConfirmation, GrantAnchor, TimeAnchor};
use rusqlite::OptionalExtension as _;

use crate::{Result, StoreError, Txn, codec, operation_states, sql_in_list};

const META_HIGH_WATER: &str = "high_water_mark";
/// Also read and written by the wave-1 `time_anchor`/`set_time_anchor` aliases.
/// Migration 0002 drops the v1 `time_anchor` row (no boot ID) instead of reusing it.
const META_RUNTIME_ANCHOR: &str = "runtime_anchor";
const META_TIME_CONFIRMATION: &str = "time_confirmation";
/// Per-grant last re-validated generation: `grant_validation:<grant id>`.
const META_GRANT_VALIDATION_PREFIX: &str = "grant_validation:";
/// ⟨r2.6⟩ A withdrawal whose completion was reported (ADR-0006 §13.9 item 3):
/// `withdrawal_reported:<tombstoned root grant id>`, value `1`.
const META_WITHDRAWAL_REPORTED_PREFIX: &str = "withdrawal_reported:";
/// ⟨r2.7⟩ Why a `degraded` grant is degraded (ADR-0006 §13.10 item 2):
/// `grant_degraded:<grant id>`, value the reason's wire name. Removed by
/// `update_grant_state` whenever the grant leaves `degraded`.
const META_GRANT_DEGRADED_PREFIX: &str = "grant_degraded:";
/// ⟨r2.7⟩ A revocation whose remote part is still pending (ADR-0006 §13.10 item
/// 3): `remote_revocation:<tombstoned root grant id>`, value the JSON record.
const META_REMOTE_REVOCATION_PREFIX: &str = "remote_revocation:";
/// ⟨r2.16⟩ The last claim sequence assigned to a remote-revocation round (ADR-0006
/// §13.19 item 1): it only increases, and outlives every record (the key does not
/// start with [`META_REMOTE_REVOCATION_PREFIX`]).
const META_REMOTE_CLAIM_SEQ: &str = "remote_revocation_claim_seq";
/// ⟨r2.16⟩ A recoverable cleanup intent (ADR-0006 §13.19 item 2):
/// `cleanup_intent:<grant id>:<operation id>`, value the JSON intent.
const META_CLEANUP_INTENT_PREFIX: &str = "cleanup_intent:";
/// ⟨r2.16⟩ The last version assigned to a cleanup intent (only increases).
const META_CLEANUP_INTENT_VERSION: &str = "cleanup_intent_version";

fn cleanup_intent_key(grant: &GrantId, operation: &OperationId) -> String {
    format!("{META_CLEANUP_INTENT_PREFIX}{grant}:{operation}")
}

/// The meta key of a grant's degradation reason.
pub(crate) fn grant_degradation_key(grant: &GrantId) -> String {
    format!("{META_GRANT_DEGRADED_PREFIX}{grant}")
}

/// A persisted event with its neutral sequence number (review F08: the store keeps
/// sequences; the application builds reader-scoped cursors at delivery).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvent {
    /// Store sequence (monotonic per environment, not contiguous).
    pub seq: u64,
    /// The event; `cursor` is empty in storage.
    pub event: Event,
}

/// Page of stored events with the retention and head boundaries.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEventPage {
    /// Events in sequence order.
    pub events: Vec<StoredEvent>,
    /// Highest sequence in this environment's log at read time.
    pub head_seq: u64,
    /// Highest sequence removed by retention (0 when none); a cursor below it is
    /// expired.
    pub tail_seq: u64,
}

/// Result of completing a decision (CAS on state and generation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionCompletion {
    /// Completed; the record now carries the verdict.
    Completed(DecisionRecord),
    /// Refused (not pending, expired, or stale generation); the record is returned
    /// unchanged or marked `Stale` when the generation moved.
    Refused {
        /// Why (`heimdall_domain::decision::DecisionRefusal` display).
        reason: String,
        /// Record after the attempt.
        record: DecisionRecord,
    },
}

/// ⟨M02⟩ Result of [`Txn::end_interaction_declaration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndOutcome {
    /// Whether a live declaration was ended by this call.
    pub ended: bool,
    /// The row's revision after the call (0 when the identity has no row).
    pub revision: u64,
}

/// ⟨M02⟩ Result of [`Txn::insert_setup_operation`] (m02-plan §5 item 18; frozen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupAdmitted {
    /// The operation, its idempotency record and its intent were inserted.
    Inserted,
    /// Another open or unresolved setup operation of the environment blocks it;
    /// nothing was written. The blockers, oldest first.
    InProgress(Vec<OperationId>),
}

fn missing() -> StoreError {
    StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)
}

fn conflict(what: String) -> StoreError {
    StoreError::GenerationConflict(what)
}

fn parse_grant_id(s: &str) -> Result<GrantId> {
    GrantId::parse(s).map_err(|_| codec::doc_error("stored grant id is malformed"))
}

fn parse_binding_id(s: &str) -> Result<BindingId> {
    BindingId::parse(s).map_err(|_| codec::doc_error("stored binding id is malformed"))
}

/// A recovery intent may only gain facts: the request is immutable, and once the
/// resolved intent exists its pinned authority (profile revision, scope, deadline,
/// policy revision, generation) never changes and an assigned grant, binding or
/// adapter is never reassigned (review F05: a retry never re-resolves).
///
/// ⟨M02⟩ U0b row 16: `local` is add-only as well. `None → Some` is allowed; once
/// set, its variant and every field except `approval` never change, and `approval`
/// goes `None → Some` once and is never replaced. A `local` and a `resolved` on the
/// same intent are refused (also on a first write, [`Txn::set_recovery_intent`]).
fn intent_update_allowed(old: &RecoveryIntent, new: &RecoveryIntent) -> bool {
    if old.request != new.request || (new.local.is_some() && new.resolved.is_some()) {
        return false;
    }
    let local_kept = match (&old.local, &new.local) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => {
            a.without_approval() == b.without_approval() && (!a.has_approval() || a == b)
        }
    };
    if !local_kept {
        return false;
    }
    match (&old.resolved, &new.resolved) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => {
            fn kept<T: PartialEq>(old: &Option<T>, new: &Option<T>) -> bool {
                old.is_none() || old == new
            }
            a.profile == b.profile
                && a.profile_revision == b.profile_revision
                && a.scope == b.scope
                && a.deadline == b.deadline
                && a.policy_revision == b.policy_revision
                && a.generation == b.generation
                && kept(&a.grant, &b.grant)
                && kept(&a.binding, &b.binding)
                && kept(&a.adapter, &b.adapter)
                && kept(&a.approval, &b.approval)
                && kept(&a.covered, &b.covered)
        }
    }
}

impl Txn<'_> {
    // --- R1: time anchors, high-water mark, attended confirmation ----------------

    /// Persisted high-water mark (latest accepted wall time).
    pub fn high_water_mark(&mut self) -> Result<Option<Timestamp>> {
        self.meta(META_HIGH_WATER)?
            .as_deref()
            .map(codec::parse_ts)
            .transpose()
    }

    /// Persist the high-water mark; refuses to lower it (returns the stored value).
    ///
    /// Returns `heimdall_domain::time::next_high_water(stored, accepted)`, which is
    /// what is stored afterwards.
    pub fn raise_high_water_mark(&mut self, accepted: Timestamp) -> Result<Timestamp> {
        let previous = self.high_water_mark()?;
        let next = heimdall_domain::time::next_high_water(previous, accepted);
        if previous != Some(next) {
            self.set_meta(META_HIGH_WATER, &codec::ts(next))?;
        }
        Ok(next)
    }

    /// The runtime's last accepted anchor (replaces the wave-1 `time_anchor`
    /// semantics; the old method keeps returning this record).
    pub fn runtime_anchor(&mut self) -> Result<Option<TimeAnchor>> {
        self.meta(META_RUNTIME_ANCHOR)?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// Persist the runtime anchor.
    pub fn set_runtime_anchor(&mut self, anchor: &TimeAnchor) -> Result<()> {
        self.set_meta(META_RUNTIME_ANCHOR, &codec::doc(anchor)?)
    }

    /// A grant's persisted budget anchor.
    pub fn grant_anchor(&mut self, grant: &GrantId) -> Result<Option<GrantAnchor>> {
        self.one_doc(
            "SELECT record_json FROM grant_anchors WHERE grant_id = ?1",
            [grant.as_str()],
        )
    }

    /// Upsert a grant anchor. Refuses (returns the stored one) when the new anchor
    /// is in the same boot and has a later `budget_end` or `bound` than the stored
    /// one: budgets only shorten within a boot.
    ///
    /// Otherwise (no stored anchor, another boot, or neither field later) the new
    /// anchor replaces the stored one and is returned.
    pub fn set_grant_anchor(&mut self, anchor: &GrantAnchor) -> Result<GrantAnchor> {
        if let Some(stored) = self.grant_anchor(&anchor.grant)?
            && stored.anchor.boot_id == anchor.anchor.boot_id
            && (anchor.budget_end > stored.budget_end || anchor.bound > stored.bound)
        {
            return Ok(stored);
        }
        let budget_end_ns = i64::try_from(anchor.budget_end.as_nanos()).unwrap_or(i64::MAX);
        self.tx.execute(
            "INSERT INTO grant_anchors (grant_id, record_json, boot_id, budget_end_ns, bound)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(grant_id) DO UPDATE SET record_json = excluded.record_json,
                 boot_id = excluded.boot_id, budget_end_ns = excluded.budget_end_ns,
                 bound = excluded.bound",
            rusqlite::params![
                anchor.grant.as_str(),
                codec::doc(anchor)?,
                anchor.anchor.boot_id.0,
                budget_end_ns,
                codec::ts(anchor.bound),
            ],
        )?;
        Ok(anchor.clone())
    }

    /// Attended time confirmation on record for the current boot, if any.
    ///
    /// The store does not know the current boot: it returns the latest stored
    /// confirmation and the caller compares its `boot_id`.
    pub fn time_confirmation(&mut self) -> Result<Option<AttendedTimeConfirmation>> {
        self.meta(META_TIME_CONFIRMATION)?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// Persist an attended confirmation (replaces any earlier one).
    pub fn set_time_confirmation(&mut self, confirmation: &AttendedTimeConfirmation) -> Result<()> {
        self.set_meta(META_TIME_CONFIRMATION, &codec::doc(confirmation)?)
    }

    // --- R2: idempotency settlement and expired-key markers -----------------------

    /// At settlement: set the record's `expires_at = terminal_at + retention`
    /// (pending keys have none). Idempotent.
    ///
    /// The first settlement wins: a record that already has an expiry keeps it. The
    /// operation must be settled (`succeeded`, `failed`, `cancelled`); settling the
    /// key of an open or `outcome_unknown` operation is a
    /// [`StoreError::GenerationConflict`] (pending keys never expire). A missing
    /// record is `Sqlite(QueryReturnedNoRows)`.
    pub fn settle_idempotency(
        &mut self,
        key: &IdempotencyKey,
        expires_at: Timestamp,
    ) -> Result<()> {
        let caller = crate::caller_doc(key)?;
        let row: Option<(String, Option<String>)> = self
            .tx
            .query_row(
                "SELECT operation_id, expires_at FROM idempotency
                 WHERE caller_json = ?1 AND kind = ?2 AND request_id = ?3",
                rusqlite::params![caller, key.kind.as_str(), key.request_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((operation, existing)) = row else {
            return Err(missing());
        };
        if existing.is_some() {
            return Ok(());
        }
        let state: String = self.tx.query_row(
            "SELECT state FROM operations WHERE id = ?1",
            [operation.as_str()],
            |r| r.get(0),
        )?;
        let state: OperationState = codec::enum_parse(&state)?;
        if !state.is_settled() {
            return Err(conflict(format!(
                "operation {operation} is not settled; its idempotency key stays live"
            )));
        }
        self.tx.execute(
            "UPDATE idempotency SET expires_at = ?4
             WHERE caller_json = ?1 AND kind = ?2 AND request_id = ?3 AND expires_at IS NULL",
            rusqlite::params![
                caller,
                key.kind.as_str(),
                key.request_id.as_str(),
                codec::ts(expires_at)
            ],
        )?;
        Ok(())
    }

    /// Marker for a purged key, if within its window.
    ///
    /// The store reads no clock: a marker is returned until
    /// [`Txn::purge_markers_before`] removes it; `classify` compares
    /// `marker_until` with the caller's `now`.
    pub fn expired_key_marker(&mut self, key_hash: &KeyHash) -> Result<Option<ExpiredKeyMarker>> {
        let row: Option<(String, String)> = self
            .tx
            .query_row(
                "SELECT expired_at, marker_until FROM idempotency_markers WHERE key_hash = ?1",
                [key_hash.0.to_hex()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(expired, until)| {
            Ok(ExpiredKeyMarker {
                key_hash: *key_hash,
                expired_at: codec::parse_ts(&expired)?,
                marker_until: codec::parse_ts(&until)?,
            })
        })
        .transpose()
    }

    /// Purge markers whose `marker_until` is at or before `now`.
    pub fn purge_markers_before(&mut self, now: Timestamp) -> Result<u64> {
        let n = self.tx.execute(
            "DELETE FROM idempotency_markers WHERE marker_until <= ?1",
            [codec::ts(now)],
        )?;
        Ok(n as u64)
    }

    // --- R3: decision records ----------------------------------------------------------

    /// Insert a pending decision.
    ///
    /// A record that is not `Pending` or already carries `decided_at` is refused.
    pub fn insert_decision(&mut self, decision: &DecisionRecord) -> Result<()> {
        if decision.state != DecisionState::Pending || decision.decided_at.is_some() {
            return Err(codec::doc_error("a decision is inserted pending"));
        }
        let n = self.tx.execute(
            "INSERT INTO decisions (id, kind_json, generation, created_at, expires_at, state,
                 decided_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                decision.id.as_str(),
                codec::doc(&decision.kind)?,
                codec::int(decision.generation.0)?,
                codec::ts(decision.created_at),
                codec::ts(decision.expires_at),
                codec::enum_str(&decision.state)?,
                codec::doc(decision)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("decision {} exists", decision.id)));
        }
        Ok(())
    }

    /// Load a decision.
    pub fn decision(&mut self, id: &DecisionId) -> Result<Option<DecisionRecord>> {
        self.one_doc(
            "SELECT record_json FROM decisions WHERE id = ?1",
            [id.as_str()],
        )
    }

    fn write_decision(&mut self, record: &DecisionRecord) -> Result<()> {
        let n = self.tx.execute(
            "UPDATE decisions SET state = ?2, decided_at = ?3, record_json = ?4
             WHERE id = ?1 AND state = ?5",
            rusqlite::params![
                record.id.as_str(),
                codec::enum_str(&record.state)?,
                record.decided_at.map(codec::ts),
                codec::doc(record)?,
                codec::enum_str(&DecisionState::Pending)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("decision {} is not pending", record.id)));
        }
        Ok(())
    }

    /// Complete a decision with CAS on `Pending` state and on the current authority
    /// generation (read inside this transaction); consume-once.
    ///
    /// Applies `heimdall_domain::decision::complete`. On success the record moves
    /// to `Approved`/`Denied` with `decided_at = now`. A stale generation marks the
    /// record `Stale` (persisted; `decided_at` stays empty) and is refused; a record
    /// that is not pending or has expired is refused and left unchanged. A missing
    /// decision is `Sqlite(QueryReturnedNoRows)`.
    pub fn complete_decision(
        &mut self,
        id: &DecisionId,
        verdict: Verdict,
        now: Timestamp,
    ) -> Result<DecisionCompletion> {
        let Some(record) = self.decision(id)? else {
            return Err(missing());
        };
        let current = self.authority_generation()?;
        match heimdall_domain::decision::complete(&record, verdict, current, now) {
            Ok(state) => {
                let mut done = record;
                done.state = state;
                done.decided_at = Some(now);
                self.write_decision(&done)?;
                Ok(DecisionCompletion::Completed(done))
            }
            Err(refusal) => {
                let mut after = record;
                if matches!(refusal, DecisionRefusal::StaleGeneration { .. }) {
                    after.state = DecisionState::Stale;
                    self.write_decision(&after)?;
                }
                Ok(DecisionCompletion::Refused {
                    reason: refusal.to_string(),
                    record: after,
                })
            }
        }
    }

    /// Pending decisions (for `inspect decisions` and the TUI).
    ///
    /// Oldest first; includes pending records past `expires_at` (the store reads no
    /// clock; completion refuses them).
    pub fn pending_decisions(&mut self) -> Result<Vec<DecisionRecord>> {
        self.docs(
            "SELECT record_json FROM decisions WHERE state = ?1 ORDER BY created_at, id",
            [codec::enum_str(&DecisionState::Pending)?],
        )
    }

    /// ⟨r2.4⟩ Move a pending `ApproveAuthority` record from the waiting operation
    /// `from` to the waiting operation `to` (ADR-0006 §13.7 item 4: the shared
    /// decision follows its shared grant to the oldest remaining waiter and stays
    /// pending). Compare-and-swap on `Pending` and on the recorded operation; the
    /// ID, delta, generation, creation and expiry are unchanged. Anything else is
    /// a [`StoreError::GenerationConflict`]; a missing decision is
    /// `Sqlite(QueryReturnedNoRows)`. Returns the record after the move.
    pub fn transfer_decision(
        &mut self,
        id: &DecisionId,
        from: &OperationId,
        to: &OperationId,
    ) -> Result<DecisionRecord> {
        let Some(mut record) = self.decision(id)? else {
            return Err(missing());
        };
        if record.state != DecisionState::Pending {
            return Err(conflict(format!("decision {id} is not pending")));
        }
        match &mut record.kind {
            DecisionKind::ApproveAuthority { operation, .. } if operation == from => {
                *operation = to.clone();
            }
            _ => {
                return Err(conflict(format!(
                    "decision {id} does not belong to the expected operation"
                )));
            }
        }
        let n = self.tx.execute(
            "UPDATE decisions SET kind_json = ?2, record_json = ?3 WHERE id = ?1 AND state = ?4",
            rusqlite::params![
                id.as_str(),
                codec::doc(&record.kind)?,
                codec::doc(&record)?,
                codec::enum_str(&DecisionState::Pending)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("decision {id} is not pending")));
        }
        Ok(record)
    }

    /// ⟨r2.4⟩ Withdraw a pending decision without a verdict (ADR-0006 §13.7 items 2
    /// and 4): it moves to [`DecisionState::Withdrawn`], `decided_at` stays empty,
    /// and it can never be completed. Compare-and-swap on `Pending`: any other
    /// state is a [`StoreError::GenerationConflict`] and leaves the record
    /// unchanged; a missing decision is `Sqlite(QueryReturnedNoRows)`. Returns the
    /// record after the change.
    pub fn withdraw_decision(&mut self, id: &DecisionId) -> Result<DecisionRecord> {
        let Some(mut record) = self.decision(id)? else {
            return Err(missing());
        };
        record.state = DecisionState::Withdrawn;
        self.write_decision(&record)?;
        Ok(record)
    }

    // --- R4: bindings, profiles, environments, policy lookup, denial reads ---------

    /// Insert a binding and its grant reference atomically.
    ///
    /// An `Active` binding adds the `(binding, grant)` reference; a binding inserted
    /// already `Released` adds none. The grant must exist (foreign key); a binding
    /// cannot be its own parent.
    pub fn insert_binding(&mut self, binding: &BindingRecord) -> Result<()> {
        if binding.parent.as_ref() == Some(&binding.id) {
            return Err(codec::doc_error("a binding cannot be its own parent"));
        }
        let n = self.tx.execute(
            "INSERT INTO bindings (id, environment, grant_id, work_id, record_json, created_at,
                 released_at, owner_json, profile, profile_revision, scope_json, mechanism,
                 parent, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                binding.id.as_str(),
                binding.environment.as_str(),
                binding.grant.as_str(),
                binding.work_id.as_str(),
                codec::doc(binding)?,
                codec::ts(binding.created_at),
                binding.released_at.map(codec::ts),
                codec::doc(&binding.owner)?,
                binding.profile.as_str(),
                codec::int(binding.profile_revision)?,
                codec::doc(&binding.scope)?,
                binding.mechanism,
                binding.parent.as_ref().map(BindingId::as_str),
                codec::enum_str(&binding.state)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("binding {} exists", binding.id)));
        }
        if binding.state == BindingState::Active {
            self.add_grant_reference(&GrantReference {
                binding: binding.id.clone(),
                grant: binding.grant.clone(),
                acquired_at: binding.created_at,
            })?;
        }
        Ok(())
    }

    /// Load a binding.
    pub fn binding(&mut self, id: &BindingId) -> Result<Option<BindingRecord>> {
        self.one_doc(
            "SELECT record_json FROM bindings WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Bindings for a work ID in an environment (continuing work reuses them).
    ///
    /// Active and released bindings, oldest first; the caller picks.
    pub fn bindings_for_work(
        &mut self,
        environment: &EnvironmentId,
        work_id: &WorkId,
    ) -> Result<Vec<BindingRecord>> {
        self.docs(
            "SELECT record_json FROM bindings WHERE environment = ?1 AND work_id = ?2
             ORDER BY created_at, id",
            [environment.as_str(), work_id.as_str()],
        )
    }

    /// Release a binding: ownership check (`may_act_on`), idempotent, drops the
    /// grant reference and returns the remaining reference count.
    ///
    /// Ownership is checked first, so a foreign caller learns `NotOwner` whether or
    /// not the binding was already released. Release never revokes (ADR-0006 §13.2).
    /// A missing binding is `Sqlite(QueryReturnedNoRows)`.
    pub fn release_binding(
        &mut self,
        id: &BindingId,
        caller: &CallerContext,
        now: Timestamp,
    ) -> Result<ReleaseOutcome> {
        let Some(mut binding) = self.binding(id)? else {
            return Err(missing());
        };
        if !heimdall_domain::binding::may_act_on(&binding, caller) {
            return Ok(ReleaseOutcome::NotOwner);
        }
        if binding.state == BindingState::Released {
            return Ok(ReleaseOutcome::AlreadyReleased);
        }
        binding.state = BindingState::Released;
        binding.released_at = Some(now);
        let n = self.tx.execute(
            "UPDATE bindings SET state = ?2, released_at = ?3, record_json = ?4
             WHERE id = ?1 AND state = ?5",
            rusqlite::params![
                binding.id.as_str(),
                codec::enum_str(&binding.state)?,
                codec::ts(now),
                codec::doc(&binding)?,
                codec::enum_str(&BindingState::Active)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("binding {} is not active", binding.id)));
        }
        let remaining = self.remove_grant_reference(&GrantReference {
            binding: binding.id.clone(),
            grant: binding.grant.clone(),
            acquired_at: binding.created_at,
        })?;
        Ok(ReleaseOutcome::Released {
            remaining_references: remaining,
        })
    }

    /// References currently held on a grant.
    ///
    /// Oldest first.
    pub fn grant_references(&mut self, grant: &GrantId) -> Result<Vec<GrantReference>> {
        let rows: Vec<(String, String, String)> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT binding, grant_id, acquired_at FROM grant_references WHERE grant_id = ?1
                 ORDER BY acquired_at, binding",
            )?;
            let rows =
                stmt.query_map([grant.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(binding, grant, acquired)| {
                Ok(GrantReference {
                    binding: parse_binding_id(&binding)?,
                    grant: parse_grant_id(&grant)?,
                    acquired_at: codec::parse_ts(&acquired)?,
                })
            })
            .collect()
    }

    /// Upsert a profile definition (bumps nothing; the caller sets the revision)
    /// and store its snapshot for that revision.
    ///
    /// Snapshots are insert-only: re-upserting a revision whose snapshot differs
    /// (scope changed without a revision bump) is a
    /// [`StoreError::GenerationConflict`], as is a revision lower than the stored
    /// definition's. Re-upserting identical content is a no-op for the snapshot.
    pub fn upsert_profile(&mut self, profile: &ProfileDefinition) -> Result<()> {
        let snapshot = profile.snapshot();
        if let Some(pinned) = self.profile_snapshot(&profile.id, profile.revision)?
            && pinned != snapshot
        {
            return Err(conflict(format!(
                "profile {} revision {} is pinned with different content",
                profile.id, profile.revision
            )));
        }
        if let Some(current) = self.profile(&profile.id)?
            && current.revision > profile.revision
        {
            return Err(conflict(format!(
                "profile {} revision {} is older than stored {}",
                profile.id, profile.revision, current.revision
            )));
        }
        let revision = codec::int(profile.revision)?;
        self.tx.execute(
            "INSERT INTO profiles (id, revision, record_json, updated_at) VALUES (?1, ?2, ?3, '')
             ON CONFLICT(id) DO UPDATE SET revision = excluded.revision,
                 record_json = excluded.record_json",
            rusqlite::params![profile.id.as_str(), revision, codec::doc(profile)?],
        )?;
        self.tx.execute(
            "INSERT INTO profile_snapshots (profile, revision, record_json) VALUES (?1, ?2, ?3)
             ON CONFLICT(profile, revision) DO NOTHING",
            rusqlite::params![profile.id.as_str(), revision, codec::doc(&snapshot)?],
        )?;
        Ok(())
    }

    /// Current profile definition.
    pub fn profile(&mut self, id: &ProfileId) -> Result<Option<ProfileDefinition>> {
        self.one_doc(
            "SELECT record_json FROM profiles WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// ⟨M02⟩ ADR-0007 §12.22 item 10: remove a profile's current definition; returns
    /// whether one was removed.
    ///
    /// Only the definition goes. Its snapshots are immutable pins (a grant, binding or
    /// operation resolved against a revision keeps reading exactly that revision, and
    /// is never widened or re-resolved by the removal), so they are kept. New work that
    /// names the profile finds no definition and is refused. A later
    /// [`Txn::upsert_profile`] of the same ID must continue after
    /// [`Txn::profile_latest_revision`], so a revision is never reused with other
    /// content.
    pub fn remove_profile(&mut self, id: &ProfileId) -> Result<bool> {
        let n = self
            .tx
            .execute("DELETE FROM profiles WHERE id = ?1", [id.as_str()])?;
        Ok(n > 0)
    }

    /// ⟨M02⟩ The highest revision ever pinned for a profile (its definition or any
    /// snapshot, the definition removed or not); `None` when the profile never existed.
    pub fn profile_latest_revision(&mut self, id: &ProfileId) -> Result<Option<u64>> {
        let pinned: Option<i64> = self.tx.query_row(
            "SELECT MAX(revision) FROM (
                 SELECT revision FROM profiles WHERE id = ?1
                 UNION ALL
                 SELECT revision FROM profile_snapshots WHERE profile = ?1)",
            [id.as_str()],
            |r| r.get(0),
        )?;
        pinned.map(codec::uint).transpose()
    }

    /// Pinned snapshot of a profile at a revision (immutable once written).
    pub fn profile_snapshot(
        &mut self,
        id: &ProfileId,
        revision: u64,
    ) -> Result<Option<ProfileSnapshot>> {
        self.one_doc(
            "SELECT record_json FROM profile_snapshots WHERE profile = ?1 AND revision = ?2",
            rusqlite::params![id.as_str(), codec::int(revision)?],
        )
    }

    /// Upsert an environment record and advance the authority generation in the
    /// same transaction.
    ///
    /// ⟨r2.4⟩ ADR-0006 §13.7 item 5: **every** accepted write moves the generation,
    /// as policy writes do (§13.6 item 5), so a change in enrolled environment
    /// permissions (spec §6.2: they bound the effective set) triggers re-validation
    /// (§13.5 ruling 2) and voids a reservation made before it. A write rolled back
    /// with its transaction moves nothing.
    pub fn upsert_environment(&mut self, environment: &EnvironmentRecord) -> Result<()> {
        self.tx.execute(
            "INSERT INTO environments (id, record_json, updated_at) VALUES (?1, ?2, '')
             ON CONFLICT(id) DO UPDATE SET record_json = excluded.record_json",
            rusqlite::params![environment.id.as_str(), codec::doc(environment)?],
        )?;
        let next = self.authority_generation()?.next();
        self.set_meta(crate::META_AUTHORITY_GENERATION, &next.0.to_string())
    }

    /// Load an environment record.
    pub fn environment(&mut self, id: &EnvironmentId) -> Result<Option<EnvironmentRecord>> {
        self.one_doc(
            "SELECT record_json FROM environments WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Standing policies that name `profile` and include `environment`.
    ///
    /// Ordered by policy ID; pause and cutoff are not filtered (the caller applies
    /// them).
    pub fn policies_for(
        &mut self,
        profile: &ProfileId,
        environment: &EnvironmentId,
    ) -> Result<Vec<StandingPolicy>> {
        let all: Vec<StandingPolicy> =
            self.docs("SELECT record_json FROM policies ORDER BY id", [])?;
        Ok(all
            .into_iter()
            .filter(|p| p.profile == *profile && p.environments.contains(environment))
            .collect())
    }

    /// Tombstone for a grant, if revoked.
    ///
    /// Only a tombstone written for this grant itself; see
    /// [`Txn::denied_ancestor`] for ancestor denial.
    pub fn tombstone(&mut self, grant: &GrantId) -> Result<Option<Tombstone>> {
        self.one_doc(
            "SELECT record_json FROM tombstones WHERE grant_id = ?1",
            [grant.as_str()],
        )
    }

    /// The grant itself or the nearest ancestor that carries a tombstone, if any
    /// (ancestor denial, spec §6.7).
    ///
    /// Walks `grant`, its parent, grandparent, ... and returns the first one with a
    /// tombstone; the walk continues past ancestors without one (whatever their
    /// state) and stops at a grant with no parent or with no grant row. A cycle in
    /// the parent chain is [`StoreError::Corrupt`].
    pub fn denied_ancestor(&mut self, grant: &GrantId) -> Result<Option<GrantId>> {
        let mut current = grant.clone();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current.clone()) {
                return Err(StoreError::Corrupt("grant parent chain has a cycle".into()));
            }
            let tombstoned: bool = self.tx.query_row(
                "SELECT count(*) > 0 FROM tombstones WHERE grant_id = ?1",
                [current.as_str()],
                |r| r.get(0),
            )?;
            if tombstoned {
                return Ok(Some(current));
            }
            let parent: Option<Option<String>> = self
                .tx
                .query_row(
                    "SELECT parent FROM grants WHERE id = ?1",
                    [current.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            match parent.flatten() {
                Some(p) => current = parse_grant_id(&p)?,
                None => return Ok(None),
            }
        }
    }

    /// The authority generation at which `grant` was last re-validated
    /// (ADR-0006 §13.5 ruling 2), if it ever was. The grant's own `generation`
    /// (authorization) is immutable; this record only moves forward.
    pub fn grant_validation(&mut self, grant: &GrantId) -> Result<Option<AuthorityGeneration>> {
        match self.meta(&format!("{META_GRANT_VALIDATION_PREFIX}{grant}"))? {
            None => Ok(None),
            Some(s) => s
                .parse()
                .map(|g| Some(AuthorityGeneration(g)))
                .map_err(|_| StoreError::Corrupt("grant validation is malformed".into())),
        }
    }

    /// Record that `grant` was re-validated at `generation` (the current one, read
    /// in this transaction). Never moves the record backwards; a generation above
    /// the current one is refused as a [`StoreError::GenerationConflict`].
    pub fn record_grant_validation(
        &mut self,
        grant: &GrantId,
        generation: AuthorityGeneration,
    ) -> Result<()> {
        if generation > self.authority_generation()? {
            return Err(conflict(format!(
                "grant {grant} cannot be validated at a future generation"
            )));
        }
        if self.grant(grant)?.is_none() {
            return Err(missing());
        }
        if self
            .grant_validation(grant)?
            .is_some_and(|g| g >= generation)
        {
            return Ok(());
        }
        self.set_meta(
            &format!("{META_GRANT_VALIDATION_PREFIX}{grant}"),
            &generation.0.to_string(),
        )
    }

    // --- ⟨r2.4⟩ ADR-0006 §13.7 items 3 and 4: approval basis and waiting owner ---

    /// Persist the approval basis of an owner-approved grant **with the grant**
    /// (schema version 3, `grants.approval_json`), in the transaction that records
    /// the approval (ADR-0006 §13.7 item 3).
    ///
    /// Operation retention never touches it: it outlives the purge of the approving
    /// operation and its recovery intent. Written once: recording the same basis
    /// again is a no-op; a different basis is a [`StoreError::GenerationConflict`]
    /// and leaves the stored one unchanged. A missing grant is
    /// `Sqlite(QueryReturnedNoRows)`.
    pub fn set_grant_approval(&mut self, grant: &GrantId, basis: &ApprovalBasis) -> Result<()> {
        if let Some(existing) = self.grant_approval(grant)? {
            if existing == *basis {
                return Ok(());
            }
            return Err(conflict(format!(
                "grant {grant} already records its approval basis"
            )));
        }
        let n = self.tx.execute(
            "UPDATE grants SET approval_json = ?2 WHERE id = ?1 AND approval_json IS NULL",
            rusqlite::params![grant.as_str(), codec::doc(basis)?],
        )?;
        if n == 0 {
            return Err(missing());
        }
        Ok(())
    }

    /// The approval basis recorded with `grant`, if it was approved by the owner
    /// (`None` for standing-policy and delegated grants, for a grant approved
    /// before schema version 3 whose operation was already purged, and for a
    /// missing grant).
    pub fn grant_approval(&mut self, grant: &GrantId) -> Result<Option<ApprovalBasis>> {
        let doc: Option<Option<String>> = self
            .tx
            .query_row(
                "SELECT approval_json FROM grants WHERE id = ?1",
                [grant.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        doc.flatten().as_deref().map(codec::parse_doc).transpose()
    }

    /// Move the ownership of a **waiting** owner-decision grant from operation
    /// `from` to operation `to` (ADR-0006 §13.7 item 4: cancelling the request that
    /// created a shared decision hands the shared grant to the oldest remaining
    /// waiter). Compare-and-swap: the grant must be `requested` or
    /// `awaiting_approval` and its source must be `OwnerDecision { from }`;
    /// otherwise [`StoreError::GenerationConflict`] and nothing changes. Only the
    /// source's operation changes; scope, deadline, state and every other field
    /// keep their stored values. A missing grant is `Sqlite(QueryReturnedNoRows)`.
    pub fn transfer_waiting_grant(
        &mut self,
        grant: &GrantId,
        from: &OperationId,
        to: &OperationId,
    ) -> Result<()> {
        let Some(mut stored) = self.grant(grant)? else {
            return Err(missing());
        };
        if !matches!(
            stored.state,
            GrantState::Requested | GrantState::AwaitingApproval
        ) {
            return Err(conflict(format!("grant {grant} is no longer waiting")));
        }
        if !matches!(&stored.source, AuthorizationSource::OwnerDecision { operation_id } if operation_id == from)
        {
            return Err(conflict(format!(
                "grant {grant} is not owned by the expected operation"
            )));
        }
        stored.source = AuthorizationSource::OwnerDecision {
            operation_id: to.clone(),
        };
        self.tx.execute(
            "UPDATE grants SET record_json = ?2 WHERE id = ?1",
            rusqlite::params![grant.as_str(), codec::doc(&stored)?],
        )?;
        Ok(())
    }

    // --- ⟨r2.6⟩ ADR-0006 §13.9 items 2 and 3: grant origin, withdrawal report ---

    /// Persist where `grant`'s authority was resolved **with the grant** (schema
    /// version 4, `grants.origin_json`), in the transaction that creates it
    /// (ADR-0006 §13.9 item 2: re-validation derives its context from the grant's
    /// own record, never from a consumer binding or an operation record).
    ///
    /// Written once: recording the same origin again is a no-op. The only changes
    /// accepted afterwards are add-only: a stored origin without a `covered` basis
    /// may gain one (§13.7 item 2), and ⟨r2.10⟩ one without the preparing
    /// `adapter` may gain it (ADR-0006 §13.13 item 1), every other field
    /// unchanged; once recorded, neither is replaced or cleared. Anything else is a
    /// [`StoreError::GenerationConflict`] and leaves the stored origin unchanged. A
    /// missing grant is `Sqlite(QueryReturnedNoRows)`.
    pub fn set_grant_origin(&mut self, grant: &GrantId, origin: &GrantOrigin) -> Result<()> {
        if self.grant(grant)?.is_none() {
            return Err(missing());
        }
        if let Some(existing) = self.grant_origin(grant)? {
            if existing == *origin {
                return Ok(());
            }
            // The stored origin with only its absent optional fields filled in
            // from the new one must be exactly the new one.
            let mut added = existing.clone();
            if added.covered.is_none() {
                added.covered.clone_from(&origin.covered);
            }
            if added.adapter.is_none() {
                added.adapter.clone_from(&origin.adapter);
            }
            if added != *origin {
                return Err(conflict(format!(
                    "grant {grant} already records its origin"
                )));
            }
        }
        self.tx.execute(
            "UPDATE grants SET origin_json = ?2 WHERE id = ?1",
            rusqlite::params![grant.as_str(), codec::doc(origin)?],
        )?;
        Ok(())
    }

    /// Record, add-only, the covered basis of a waiting owner-decision grant the
    /// saved standing policy came to cover entirely (ADR-0006 §13.7 item 2) in its
    /// origin. `Ok(false)` when the grant records no origin (nothing to add to);
    /// the same basis again is a no-op; another basis is a
    /// [`StoreError::GenerationConflict`].
    pub fn set_grant_covered(&mut self, grant: &GrantId, basis: &CoveredBasis) -> Result<bool> {
        let Some(origin) = self.grant_origin(grant)? else {
            return Ok(false);
        };
        match &origin.covered {
            Some(existing) if existing == basis => Ok(true),
            Some(_) => Err(conflict(format!(
                "grant {grant} already records its covered basis"
            ))),
            None => {
                self.set_grant_origin(
                    grant,
                    &GrantOrigin {
                        covered: Some(basis.clone()),
                        ..origin
                    },
                )?;
                Ok(true)
            }
        }
    }

    /// The origin recorded with `grant` (`None` for a grant that predates schema
    /// version 4 with nothing to backfill from, and for a missing grant).
    pub fn grant_origin(&mut self, grant: &GrantId) -> Result<Option<GrantOrigin>> {
        let doc: Option<Option<String>> = self
            .tx
            .query_row(
                "SELECT origin_json FROM grants WHERE id = ?1",
                [grant.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        doc.flatten().as_deref().map(codec::parse_doc).transpose()
    }

    /// Record that the completion of the withdrawal rooted at `root` (the grant
    /// carrying the `authority_withdrawn` tombstone) was reported (ADR-0006 §13.9
    /// item 3), so an interrupted withdrawal completed again after a restart or in
    /// a later scheduler pass reports it exactly once. `true` when this call
    /// recorded it, `false` when it was already recorded. A root without a
    /// tombstone is `Sqlite(QueryReturnedNoRows)`.
    pub fn record_withdrawal_report(&mut self, root: &GrantId) -> Result<bool> {
        if self.tombstone(root)?.is_none() {
            return Err(missing());
        }
        if self.withdrawal_reported(root)? {
            return Ok(false);
        }
        self.set_meta(&format!("{META_WITHDRAWAL_REPORTED_PREFIX}{root}"), "1")?;
        Ok(true)
    }

    /// Whether the completion of the withdrawal rooted at `root` was reported.
    pub fn withdrawal_reported(&mut self, root: &GrantId) -> Result<bool> {
        Ok(self
            .meta(&format!("{META_WITHDRAWAL_REPORTED_PREFIX}{root}"))?
            .is_some())
    }

    // --- ⟨r2.7⟩ ADR-0006 §13.10 items 2 and 3: degradation and pending remote revocation

    /// Record why `grant` is `degraded` (ADR-0006 §13.10 item 2), in the
    /// transaction that degrades it. The reason exists only while the grant is
    /// `degraded`: [`Txn::update_grant_state`] removes it when the grant leaves that
    /// state. A missing grant is `Sqlite(QueryReturnedNoRows)`; a grant in any other
    /// state is a [`StoreError::GenerationConflict`] and nothing is written.
    pub fn set_grant_degradation(&mut self, grant: &GrantId, reason: DegradedReason) -> Result<()> {
        let Some(g) = self.grant(grant)? else {
            return Err(missing());
        };
        if g.state != GrantState::Degraded {
            return Err(conflict(format!(
                "grant {grant} is not degraded; no degradation reason can be recorded"
            )));
        }
        self.set_meta(&grant_degradation_key(grant), &codec::enum_str(&reason)?)
    }

    /// Why `grant` is `degraded`, if a reason was recorded (never for a grant in
    /// another state).
    pub fn grant_degradation(&mut self, grant: &GrantId) -> Result<Option<DegradedReason>> {
        self.meta(&grant_degradation_key(grant))?
            .map(|s| codec::enum_parse(&s))
            .transpose()
    }

    /// Persist the pending remote part of the revocation rooted at `record.root`
    /// (ADR-0006 §13.10 item 3), replacing an earlier record for that root. The root
    /// must carry a tombstone (`Sqlite(QueryReturnedNoRows)` otherwise) and the
    /// record must name at least one grant (else [`StoreError::GenerationConflict`]:
    /// nothing pending is [`Txn::clear_remote_revocation`]).
    ///
    /// ⟨r2.9⟩ ADR-0006 §13.12 item 2: a record carrying `obligations` must name
    /// exactly their grants in `grants` (else [`StoreError::GenerationConflict`]); a
    /// record without obligations (the pre-§13.12 shape) is accepted as before.
    pub fn set_remote_revocation(&mut self, record: &PendingRemoteRevocation) -> Result<()> {
        if self.tombstone(&record.root)?.is_none() {
            return Err(missing());
        }
        if record.grants.is_empty() {
            return Err(conflict(format!(
                "a pending remote revocation for {} names no grant",
                record.root
            )));
        }
        if !record.obligations.is_empty() {
            let named: BTreeSet<&GrantId> = record.grants.iter().collect();
            let owed: BTreeSet<&GrantId> = record.obligations.iter().map(|o| &o.grant).collect();
            if named != owed {
                return Err(conflict(format!(
                    "the pending remote revocation for {} names other grants than its obligations",
                    record.root
                )));
            }
        }
        self.set_meta(
            &format!("{META_REMOTE_REVOCATION_PREFIX}{}", record.root),
            &codec::doc(record)?,
        )
    }

    /// The pending remote part of the revocation rooted at `root`, if any.
    pub fn remote_revocation(&mut self, root: &GrantId) -> Result<Option<PendingRemoteRevocation>> {
        self.meta(&format!("{META_REMOTE_REVOCATION_PREFIX}{root}"))?
            .map(|s| codec::parse_doc(&s))
            .transpose()
    }

    /// Remove the pending remote record of `root` (nothing pending any more);
    /// idempotent.
    pub fn clear_remote_revocation(&mut self, root: &GrantId) -> Result<()> {
        self.delete_meta(&format!("{META_REMOTE_REVOCATION_PREFIX}{root}"))
    }

    /// Every pending remote revocation record, ordered by root ID.
    pub fn remote_revocations(&mut self) -> Result<Vec<PendingRemoteRevocation>> {
        self.meta_with_prefix(META_REMOTE_REVOCATION_PREFIX)?
            .iter()
            .map(|s| codec::parse_doc(s))
            .collect()
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: the sequence of a new remote-revocation claim:
    /// greater than every sequence assigned before, by any record (one removed since
    /// included), and than `after` (the claiming record's latest, which a record
    /// written before the counter existed derives from its round count). Recorded, so
    /// no sequence is ever assigned twice, even to a record created again for the
    /// same root.
    pub fn next_remote_claim_seq(&mut self, after: u64) -> Result<u64> {
        let last = match self.meta(META_REMOTE_CLAIM_SEQ)? {
            Some(v) => v
                .parse::<u64>()
                .map_err(|_| codec::doc_error("the remote claim sequence is unreadable"))?,
            None => 0,
        };
        let next = last
            .max(after)
            .checked_add(1)
            .ok_or_else(|| codec::doc_error("the remote claim sequence overflowed"))?;
        self.set_meta(META_REMOTE_CLAIM_SEQ, &next.to_string())?;
        Ok(next)
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: persist `intent` for its (grant, operation),
    /// replacing an earlier one, with a fresh `version` (the previous greatest one
    /// assigned plus one, whatever was removed since; `intent.version` is ignored).
    /// Returns the stored intent.
    pub fn record_cleanup_intent(&mut self, intent: &CleanupIntent) -> Result<CleanupIntent> {
        let last = match self.meta(META_CLEANUP_INTENT_VERSION)? {
            Some(v) => v
                .parse::<u64>()
                .map_err(|_| codec::doc_error("the cleanup intent version is unreadable"))?,
            None => 0,
        };
        let stored = CleanupIntent {
            version: last
                .checked_add(1)
                .ok_or_else(|| codec::doc_error("the cleanup intent version overflowed"))?,
            ..intent.clone()
        };
        self.set_meta(META_CLEANUP_INTENT_VERSION, &stored.version.to_string())?;
        self.set_meta(
            &cleanup_intent_key(&stored.grant, &stored.operation),
            &codec::doc(&stored)?,
        )?;
        Ok(stored)
    }

    /// ⟨r2.16⟩ The cleanup intent of (`grant`, `operation`), if any.
    pub fn cleanup_intent(
        &mut self,
        grant: &GrantId,
        operation: &OperationId,
    ) -> Result<Option<CleanupIntent>> {
        self.meta(&cleanup_intent_key(grant, operation))?
            .map(|s| codec::parse_doc(&s))
            .transpose()
    }

    /// ⟨r2.16⟩ Remove the cleanup intent of (`grant`, `operation`); idempotent.
    pub fn clear_cleanup_intent(&mut self, grant: &GrantId, operation: &OperationId) -> Result<()> {
        self.delete_meta(&cleanup_intent_key(grant, operation))
    }

    /// ⟨r2.16⟩ Every cleanup intent, ordered by grant ID, then operation ID.
    pub fn cleanup_intents(&mut self) -> Result<Vec<CleanupIntent>> {
        self.meta_with_prefix(META_CLEANUP_INTENT_PREFIX)?
            .iter()
            .map(|s| codec::parse_doc(s))
            .collect()
    }

    /// ⟨r2.9⟩ ADR-0006 §13.12 item 2: the adapter identities recorded for `grant`
    /// by the recovery intents that pin it (`resolved.grant`, their
    /// `resolved.adapter`) and by those operations' stage receipts (the adapter of
    /// every `Attempted`, `Confirmed` or `Uncertain` effect), each once: the
    /// intents' adapters first (operation order), then the receipts' (operation,
    /// then receipt order). Empty when none is recorded (never prepared, or the
    /// operations were purged with their settled records).
    pub fn grant_adapters(&mut self, grant: &GrantId) -> Result<Vec<AdapterIdentity>> {
        let intents: Vec<RecoveryIntent> = self.docs(
            "SELECT record_json FROM recovery_intents
             WHERE json_valid(record_json)
               AND json_extract(record_json, '$.resolved.grant') = ?1
             ORDER BY operation_id",
            [grant.as_str()],
        )?;
        let receipts: Vec<StageReceipt> = self.docs(
            "SELECT s.record_json FROM stage_receipts s
             JOIN recovery_intents r ON r.operation_id = s.operation_id
             WHERE json_valid(r.record_json)
               AND json_extract(r.record_json, '$.resolved.grant') = ?1
             ORDER BY s.operation_id, s.ordinal",
            [grant.as_str()],
        )?;
        let mut out: Vec<AdapterIdentity> = Vec::new();
        let recorded = intents
            .into_iter()
            .filter_map(|i| i.resolved.and_then(|r| r.adapter))
            .chain(receipts.into_iter().filter_map(|r| match r.effect {
                EffectReceipt::Attempted { adapter, .. }
                | EffectReceipt::Confirmed { adapter, .. }
                | EffectReceipt::Uncertain { adapter, .. } => Some(adapter),
                EffectReceipt::NotAttempted => None,
            }));
        for a in recorded {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        Ok(out)
    }

    /// ⟨r2.11⟩ ADR-0006 §13.14 item 2: whether a stage receipt of an operation whose
    /// recovery intent pins `grant` (`resolved.grant`) records an external effect
    /// (`Attempted`, `Confirmed` or `Uncertain`). `false` when none is recorded
    /// (never attempted, or purged with its settled operation; the grant's origin
    /// `adapter`, written with the first `Attempted` receipt, outlives the purge).
    pub fn grant_has_effect_receipt(&mut self, grant: &GrantId) -> Result<bool> {
        let receipts: Vec<StageReceipt> = self.docs(
            "SELECT s.record_json FROM stage_receipts s
             JOIN recovery_intents r ON r.operation_id = s.operation_id
             WHERE json_valid(r.record_json)
               AND json_extract(r.record_json, '$.resolved.grant') = ?1
             ORDER BY s.operation_id, s.ordinal",
            [grant.as_str()],
        )?;
        Ok(receipts
            .iter()
            .any(|r| !matches!(r.effect, EffectReceipt::NotAttempted)))
    }

    // --- R5: recovery intent and stage receipts ----------------------------------------

    /// Persist the redacted recovery intent (written before any effect).
    ///
    /// The operation must exist (foreign key). An update may only add facts: the
    /// request is immutable; once `resolved` is set it cannot be cleared, its
    /// pinned profile revision, scope, deadline, policy revision and generation
    /// never change, and an assigned grant, binding, adapter, approval basis or
    /// covered basis (⟨r2.4⟩ ADR-0006 §13.7 item 2) is never replaced.
    /// Anything else is a [`StoreError::GenerationConflict`]. Key armor is refused.
    ///
    /// ⟨M02⟩ `local` is add-only too (U0b row 16). An intent carrying both `local`
    /// and `resolved` is a [`StoreError::GenerationConflict`] on every write, the
    /// first included (wave-0 verifier note N4). A `local` intent that fails
    /// `LocalIntent::validate` (content binding, bounds, approval fit) is refused
    /// before anything is written.
    pub fn set_recovery_intent(
        &mut self,
        operation: &OperationId,
        intent: &RecoveryIntent,
    ) -> Result<()> {
        if intent.local.is_some() && intent.resolved.is_some() {
            return Err(conflict(format!(
                "recovery intent of {operation} carries both a local and a resolved intent"
            )));
        }
        if let Some(local) = &intent.local
            && local.validate().is_err()
        {
            return Err(codec::doc_error("the local intent is invalid"));
        }
        if let Some(old) = self.recovery_intent(operation)?
            && !intent_update_allowed(&old, intent)
        {
            return Err(conflict(format!(
                "recovery intent of {operation} may only gain facts"
            )));
        }
        self.tx.execute(
            "INSERT INTO recovery_intents (operation_id, record_json) VALUES (?1, ?2)
             ON CONFLICT(operation_id) DO UPDATE SET record_json = excluded.record_json",
            rusqlite::params![operation.as_str(), codec::doc(intent)?],
        )?;
        Ok(())
    }

    /// Load the recovery intent.
    pub fn recovery_intent(&mut self, operation: &OperationId) -> Result<Option<RecoveryIntent>> {
        self.one_doc(
            "SELECT record_json FROM recovery_intents WHERE operation_id = ?1",
            [operation.as_str()],
        )
    }

    /// Append a stage receipt (receipts are append-only).
    ///
    /// The operation must exist (foreign key); no method updates or deletes a
    /// receipt (they go only with a purged settled operation).
    pub fn append_stage_receipt(
        &mut self,
        operation: &OperationId,
        receipt: &StageReceipt,
    ) -> Result<()> {
        self.tx.execute(
            "INSERT INTO stage_receipts (operation_id, ordinal, record_json)
             SELECT ?1, COALESCE(max(ordinal), 0) + 1, ?2
             FROM stage_receipts WHERE operation_id = ?1",
            rusqlite::params![operation.as_str(), codec::doc(receipt)?],
        )?;
        Ok(())
    }

    /// Receipts in order.
    pub fn stage_receipts(&mut self, operation: &OperationId) -> Result<Vec<StageReceipt>> {
        self.docs(
            "SELECT record_json FROM stage_receipts WHERE operation_id = ?1 ORDER BY ordinal",
            [operation.as_str()],
        )
    }

    // --- R6: issuance substrate ---------------------------------------------------------

    /// Reserve: insert the entry in state `reserved` with its complete bounds. The
    /// caller ran `heimdall_domain::issuance::check` in this transaction.
    ///
    /// An entry that is not `Reserved`, or already carries `settled_at` or a void
    /// reason, is refused.
    pub fn reserve_issuance(&mut self, entry: &IssuanceEntry) -> Result<()> {
        if entry.state != IssuanceState::Reserved
            || entry.settled_at.is_some()
            || entry.void_reason.is_some()
        {
            return Err(codec::doc_error("an issuance entry is inserted reserved"));
        }
        let n = self.tx.execute(
            "INSERT INTO issuance_log (id, grant_id, generation, state, valid_before,
                 reserved_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                entry.id.as_str(),
                entry.grant.as_str(),
                codec::int(entry.generation.0)?,
                codec::enum_str(&entry.state)?,
                codec::ts(entry.bounds.valid_before),
                codec::ts(entry.reserved_at),
                codec::doc(entry)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("issuance {} exists", entry.id)));
        }
        Ok(())
    }

    fn issuance_entry(&mut self, id: &IssuanceId) -> Result<Option<IssuanceEntry>> {
        self.one_doc(
            "SELECT record_json FROM issuance_log WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// CAS `reserved → to` at `now`.
    fn settle_issuance(
        &mut self,
        id: &IssuanceId,
        to: IssuanceState,
        reason: Option<IssuanceRefusal>,
        now: Timestamp,
    ) -> Result<IssuanceEntry> {
        let Some(mut entry) = self.issuance_entry(id)? else {
            return Err(missing());
        };
        if entry.state != IssuanceState::Reserved {
            return Err(conflict(format!(
                "issuance {id} is {:?}, not reserved",
                entry.state
            )));
        }
        entry.state = to;
        entry.settled_at = Some(now);
        entry.void_reason = reason;
        let n = self.tx.execute(
            "UPDATE issuance_log SET state = ?2, record_json = ?3 WHERE id = ?1 AND state = ?4",
            rusqlite::params![
                id.as_str(),
                codec::enum_str(&entry.state)?,
                codec::doc(&entry)?,
                codec::enum_str(&IssuanceState::Reserved)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("issuance {id} is not reserved")));
        }
        Ok(entry)
    }

    /// Publish: CAS `reserved → published` at `now`; a non-reserved entry is a
    /// `GenerationConflict`. The caller re-ran every predicate in this transaction.
    pub fn publish_issuance(&mut self, id: &IssuanceId, now: Timestamp) -> Result<IssuanceEntry> {
        self.settle_issuance(id, IssuanceState::Published, None, now)
    }

    /// Void: CAS `reserved → voided` with the reason.
    pub fn void_issuance(
        &mut self,
        id: &IssuanceId,
        reason: &IssuanceRefusal,
        now: Timestamp,
    ) -> Result<IssuanceEntry> {
        self.settle_issuance(id, IssuanceState::Voided, Some(reason.clone()), now)
    }

    /// Entries for a grant.
    ///
    /// Every state, in reservation order.
    pub fn issuance_entries(&mut self, grant: &GrantId) -> Result<Vec<IssuanceEntry>> {
        self.docs(
            "SELECT record_json FROM issuance_log WHERE grant_id = ?1 ORDER BY reserved_at, id",
            [grant.as_str()],
        )
    }

    /// Residual over several grants: latest `valid_before` among `reserved` and
    /// `published` entries (`heimdall_domain::issuance::residual`).
    pub fn issuance_residual(&mut self, grants: &[GrantId]) -> Result<Option<Timestamp>> {
        let counted = sql_in_list(&[IssuanceState::Reserved, IssuanceState::Published])?;
        let sql = format!(
            "SELECT record_json FROM issuance_log WHERE grant_id = ?1 AND state IN ({counted})"
        );
        let mut entries: Vec<IssuanceEntry> = Vec::new();
        for grant in grants {
            entries.extend(self.docs::<IssuanceEntry>(&sql, [grant.as_str()])?);
        }
        Ok(heimdall_domain::issuance::residual(&entries))
    }

    /// Insert a credential instance.
    pub fn insert_credential_instance(&mut self, instance: &CredentialInstance) -> Result<()> {
        let n = self.tx.execute(
            "INSERT INTO credential_instances (id, grant_id, state, record_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO NOTHING",
            rusqlite::params![
                instance.id.as_str(),
                instance.grant.as_str(),
                codec::enum_str(&instance.state)?,
                codec::doc(instance)?,
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!(
                "credential instance {} exists",
                instance.id
            )));
        }
        Ok(())
    }

    /// Load a credential instance.
    pub fn credential_instance(
        &mut self,
        id: &CredentialInstanceId,
    ) -> Result<Option<CredentialInstance>> {
        self.one_doc(
            "SELECT record_json FROM credential_instances WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Update a credential instance's state and certificate list.
    ///
    /// Only `state` and `certificates` are taken from `instance`; the grant and key
    /// handle keep their stored values. `Destroyed` is absorbing: leaving it is a
    /// [`StoreError::GenerationConflict`]. A missing instance is
    /// `Sqlite(QueryReturnedNoRows)`.
    pub fn update_credential_instance(&mut self, instance: &CredentialInstance) -> Result<()> {
        let Some(mut stored) = self.credential_instance(&instance.id)? else {
            return Err(missing());
        };
        if stored.state == CredentialState::Destroyed
            && instance.state != CredentialState::Destroyed
        {
            return Err(conflict(format!(
                "credential instance {} is destroyed",
                instance.id
            )));
        }
        stored.state = instance.state;
        stored.certificates.clone_from(&instance.certificates);
        self.tx.execute(
            "UPDATE credential_instances SET state = ?2, record_json = ?3 WHERE id = ?1",
            rusqlite::params![
                stored.id.as_str(),
                codec::enum_str(&stored.state)?,
                codec::doc(&stored)?,
            ],
        )?;
        Ok(())
    }

    // --- R7: unresolved operations -------------------------------------------------------

    /// Operations in `outcome_unknown` (restart reconciliation list). Never purged
    /// by retention while unresolved.
    ///
    /// Oldest first.
    pub fn unresolved_operations(&mut self) -> Result<Vec<OperationRecord>> {
        let sql = format!(
            "SELECT record_json FROM operations WHERE state IN ({}) ORDER BY created_at, id",
            sql_in_list(&operation_states(OperationState::is_unresolved))?
        );
        self.docs(&sql, [])
    }

    // --- R8: neutral event sequences -----------------------------------------------------

    /// Read stored events after `after_seq` with their sequences (replaces the
    /// wave-1 cursor-marker convention of `events_after`).
    ///
    /// At most `limit` events of `environment` with `seq > after_seq` matching
    /// `filter`, in sequence order; `cursor` is empty. `head_seq` and `tail_seq` are
    /// unfiltered environment-wide values read in the same transaction.
    pub fn stored_events_after(
        &mut self,
        environment: &EnvironmentId,
        after_seq: u64,
        filter: &heimdall_contract::event::EventFilter,
        limit: u32,
    ) -> Result<StoredEventPage> {
        use rusqlite::types::Value;
        let mut sql =
            String::from("SELECT seq, record_json FROM events WHERE environment = ?1 AND seq > ?2");
        let mut params: Vec<Value> = vec![
            Value::Text(environment.as_str().to_owned()),
            Value::Integer(i64::try_from(after_seq).unwrap_or(i64::MAX)),
        ];
        if let Some(op) = &filter.operation_id {
            params.push(Value::Text(op.as_str().to_owned()));
            sql.push_str(&format!(" AND operation_id = ?{}", params.len()));
        }
        if !filter.types.is_empty() {
            let mut placeholders = Vec::with_capacity(filter.types.len());
            for t in &filter.types {
                params.push(Value::Text(codec::enum_str(t)?));
                placeholders.push(format!("?{}", params.len()));
            }
            sql.push_str(&format!(" AND type IN ({})", placeholders.join(",")));
        }
        params.push(Value::Integer(i64::from(limit)));
        sql.push_str(&format!(" ORDER BY seq LIMIT ?{}", params.len()));

        let mut events = Vec::new();
        {
            let mut stmt = self.tx.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (seq, json) = row?;
                let mut event: Event = codec::parse_doc(&json)?;
                event.cursor = heimdall_contract::event::Cursor(String::new());
                events.push(StoredEvent {
                    seq: codec::uint(seq)?,
                    event,
                });
            }
        }
        Ok(StoredEventPage {
            events,
            head_seq: self.event_head(environment)?,
            tail_seq: self.event_tail(environment)?,
        })
    }

    /// Current authority generation and head sequence read together (consistent
    /// snapshot boundary for subscriptions).
    pub fn snapshot_boundary(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<(AuthorityGeneration, u64)> {
        let generation = self.authority_generation()?;
        let head = self.event_head(environment)?;
        Ok((generation, head))
    }
}

// --- ⟨M02⟩ existing access (m02-plan §5 item 18; U0b rows 16, 20, 23) ----------------
//
// Schema: `migrations/0005_existing_access.sql`. The same conventions as above:
// every method runs inside the caller's transaction (`BEGIN IMMEDIATE`), reads the
// store's own rows only, and reads no clock.

/// Whether `e` is a SQLite constraint violation (an alias or a fingerprint already
/// taken by another row).
fn unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ConstraintViolation)
    )
}

impl Txn<'_> {
    // --- catalog: destinations and identities ----------------------------------------

    /// Create or replace a destination by ID. Its alias is unique: an alias held by
    /// another destination is a [`StoreError::GenerationConflict`] (the catalog
    /// driver reports `alias_collision`). A revision lower than the stored one, or
    /// the stored revision with other content, is a conflict too (a stale writer
    /// never overwrites); the same content at the same revision is a no-op.
    pub fn upsert_destination(&mut self, destination: &DestinationRecord) -> Result<()> {
        if let Some(stored) = self.destination(&destination.id)? {
            if stored.revision > destination.revision
                || (stored.revision == destination.revision && stored != *destination)
            {
                return Err(conflict(format!(
                    "destination {} revision {} is not newer than stored {}",
                    destination.id, destination.revision, stored.revision
                )));
            }
            if stored == *destination {
                return Ok(());
            }
        }
        self.tx
            .execute(
                "INSERT INTO destinations (id, alias, revision, record_json) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET alias = excluded.alias,
                     revision = excluded.revision, record_json = excluded.record_json",
                rusqlite::params![
                    destination.id.as_str(),
                    destination.alias,
                    codec::int(destination.revision)?,
                    codec::doc(destination)?,
                ],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict("the destination alias is taken".to_owned())
                } else {
                    StoreError::Sqlite(e)
                }
            })?;
        Ok(())
    }

    /// Remove a destination; returns whether one was removed.
    pub fn remove_destination(&mut self, id: &DestinationId) -> Result<bool> {
        let n = self
            .tx
            .execute("DELETE FROM destinations WHERE id = ?1", [id.as_str()])?;
        Ok(n > 0)
    }

    /// One destination.
    pub fn destination(&mut self, id: &DestinationId) -> Result<Option<DestinationRecord>> {
        self.one_doc(
            "SELECT record_json FROM destinations WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// The destination holding `alias`, if any.
    pub fn destination_by_alias(&mut self, alias: &str) -> Result<Option<DestinationRecord>> {
        self.one_doc(
            "SELECT record_json FROM destinations WHERE alias = ?1",
            [alias],
        )
    }

    /// Every destination, ordered by alias.
    pub fn destinations(&mut self) -> Result<Vec<DestinationRecord>> {
        self.docs(
            "SELECT record_json FROM destinations ORDER BY alias, id",
            [],
        )
    }

    /// Create or replace an identity by ID. Its fingerprint is unique: a fingerprint
    /// held by another identity is a [`StoreError::GenerationConflict`]. Revisions
    /// as for [`Txn::upsert_destination`]. Key armor in the record is refused.
    pub fn upsert_identity(&mut self, identity: &IdentityRecord) -> Result<()> {
        if let Some(stored) = self.identity(&identity.id)? {
            if stored.revision > identity.revision
                || (stored.revision == identity.revision && stored != *identity)
            {
                return Err(conflict(format!(
                    "identity {} revision {} is not newer than stored {}",
                    identity.id, identity.revision, stored.revision
                )));
            }
            if stored == *identity {
                return Ok(());
            }
        }
        self.tx
            .execute(
                "INSERT INTO identities (id, fingerprint, revision, record_json) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET fingerprint = excluded.fingerprint,
                     revision = excluded.revision, record_json = excluded.record_json",
                rusqlite::params![
                    identity.id.as_str(),
                    identity.fingerprint,
                    codec::int(identity.revision)?,
                    codec::doc(identity)?,
                ],
            )
            .map_err(|e| {
                if unique_violation(&e) {
                    conflict("the identity fingerprint is already adopted".to_owned())
                } else {
                    StoreError::Sqlite(e)
                }
            })?;
        Ok(())
    }

    /// Remove an identity; returns whether one was removed. Its declaration row is
    /// kept (rows are never deleted, so a revision is never reused).
    pub fn remove_identity(&mut self, id: &IdentityId) -> Result<bool> {
        let n = self
            .tx
            .execute("DELETE FROM identities WHERE id = ?1", [id.as_str()])?;
        Ok(n > 0)
    }

    /// One identity.
    pub fn identity(&mut self, id: &IdentityId) -> Result<Option<IdentityRecord>> {
        self.one_doc(
            "SELECT record_json FROM identities WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// The identity with this public-key fingerprint, if adopted.
    pub fn identity_by_fingerprint(&mut self, fingerprint: &str) -> Result<Option<IdentityRecord>> {
        self.one_doc(
            "SELECT record_json FROM identities WHERE fingerprint = ?1",
            [fingerprint],
        )
    }

    /// Every identity, ordered by ID.
    pub fn identities(&mut self) -> Result<Vec<IdentityRecord>> {
        self.docs("SELECT record_json FROM identities ORDER BY id", [])
    }

    // --- interaction declarations (ADR-0007 §7) ----------------------------------------

    /// The declaration row of `identity`, whatever its state (expiry is computed by
    /// the reader, `heimdall_domain::catalog::eligibility`).
    pub fn interaction_declaration(
        &mut self,
        identity: &IdentityId,
    ) -> Result<Option<InteractionDeclaration>> {
        self.one_doc(
            "SELECT record_json FROM interaction_declarations WHERE identity = ?1",
            [identity.as_str()],
        )
    }

    /// ⟨r3⟩ Write `declaration` as the row of `identity`, a compare-and-swap on
    /// `expected_revision` (0 when no row exists yet). The new revision must be
    /// exactly `expected_revision + 1` and the declaration `live`, so revisions grow
    /// by one per write and are never reused. Any mismatch is a
    /// [`StoreError::GenerationConflict`] and writes nothing.
    pub fn put_interaction_declaration(
        &mut self,
        identity: &IdentityId,
        expected_revision: u64,
        declaration: &InteractionDeclaration,
    ) -> Result<()> {
        let stored = self
            .interaction_declaration(identity)?
            .map_or(0, |d| d.revision);
        let next = expected_revision
            .checked_add(1)
            .ok_or_else(|| codec::doc_error("the declaration revision overflowed"))?;
        if stored != expected_revision || declaration.revision != next {
            return Err(conflict(format!(
                "declaration of {identity} is at revision {stored}, not {expected_revision}"
            )));
        }
        if declaration.state != DeclarationState::Live
            || declaration.ended_at.is_some()
            || declaration.end_reason.is_some()
        {
            return Err(codec::doc_error("a declaration is written live"));
        }
        self.tx.execute(
            "INSERT INTO interaction_declarations (identity, revision, record_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(identity) DO UPDATE SET revision = excluded.revision,
                 record_json = excluded.record_json",
            rusqlite::params![
                identity.as_str(),
                codec::int(declaration.revision)?,
                codec::doc(declaration)?
            ],
        )?;
        Ok(())
    }

    /// ⟨r3⟩ End the live declaration of `identity` (`WithdrawDeclaration`, a
    /// recorded lapse). With `expected_revision` it is a compare-and-swap: a row at
    /// another revision (a newer declaration) stays as it is and the result says
    /// `ended: false`. A row that is not live, or no row, is not ended either. An
    /// ended row moves to `withdrawn` (reason `owner_withdrawn`) or `lapsed`
    /// (`listing_missing`, `endpoint_changed`) at the next revision, with `ended_at`.
    pub fn end_interaction_declaration(
        &mut self,
        identity: &IdentityId,
        expected_revision: Option<u64>,
        reason: DeclarationEndReason,
        at: Timestamp,
    ) -> Result<EndOutcome> {
        let Some(mut row) = self.interaction_declaration(identity)? else {
            return Ok(EndOutcome {
                ended: false,
                revision: 0,
            });
        };
        if row.state != DeclarationState::Live
            || expected_revision.is_some_and(|r| r != row.revision)
        {
            return Ok(EndOutcome {
                ended: false,
                revision: row.revision,
            });
        }
        let previous = row.revision;
        row.revision = previous
            .checked_add(1)
            .ok_or_else(|| codec::doc_error("the declaration revision overflowed"))?;
        row.state = match reason {
            DeclarationEndReason::OwnerWithdrawn => DeclarationState::Withdrawn,
            DeclarationEndReason::ListingMissing | DeclarationEndReason::EndpointChanged => {
                DeclarationState::Lapsed
            }
        };
        row.ended_at = Some(at);
        row.end_reason = Some(reason);
        let n = self.tx.execute(
            "UPDATE interaction_declarations SET revision = ?2, record_json = ?3
             WHERE identity = ?1 AND revision = ?4",
            rusqlite::params![
                identity.as_str(),
                codec::int(row.revision)?,
                codec::doc(&row)?,
                codec::int(previous)?
            ],
        )?;
        if n == 0 {
            return Err(conflict(format!("declaration of {identity} moved")));
        }
        Ok(EndOutcome {
            ended: true,
            revision: row.revision,
        })
    }

    // --- binding holders, prepared facts ------------------------------------------------

    /// Record the process holding a launch binding (replacing an earlier holder).
    /// The binding must exist (foreign key).
    pub fn set_binding_holder(
        &mut self,
        binding: &BindingId,
        holder: &ProcessHolder,
    ) -> Result<()> {
        if !heimdall_domain::holder::holder_is_valid(holder) {
            return Err(codec::doc_error(
                "a binding holder needs pid > 0 and a valid start token",
            ));
        }
        self.tx.execute(
            "INSERT INTO binding_holders (binding, holder_json) VALUES (?1, ?2)
             ON CONFLICT(binding) DO UPDATE SET holder_json = excluded.holder_json",
            rusqlite::params![binding.as_str(), codec::doc(holder)?],
        )?;
        Ok(())
    }

    /// The holder of one binding, if recorded.
    pub fn binding_holder(&mut self, binding: &BindingId) -> Result<Option<ProcessHolder>> {
        self.one_doc(
            "SELECT holder_json FROM binding_holders WHERE binding = ?1",
            [binding.as_str()],
        )
    }

    /// Every recorded holder, ordered by binding ID.
    pub fn binding_holders(&mut self) -> Result<Vec<(BindingId, ProcessHolder)>> {
        let rows: Vec<(String, String)> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT binding, holder_json FROM binding_holders ORDER BY binding",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(b, h)| Ok((parse_binding_id(&b)?, codec::parse_doc(&h)?)))
            .collect()
    }

    /// ⟨r2⟩ Record what `prepare` observed for `grant` (history only; replaces an
    /// earlier record). Written in the transaction of the `Confirmed` receipt (U0b
    /// row 6). The grant must exist (foreign key).
    pub fn set_grant_prepared_facts(
        &mut self,
        grant: &GrantId,
        facts: &PreparedFacts,
    ) -> Result<()> {
        self.tx.execute(
            "INSERT INTO grant_prepared_facts (grant_id, record_json) VALUES (?1, ?2)
             ON CONFLICT(grant_id) DO UPDATE SET record_json = excluded.record_json",
            rusqlite::params![grant.as_str(), codec::doc(facts)?],
        )?;
        Ok(())
    }

    /// ⟨r2⟩ The prepared facts of `grant`, if recorded.
    pub fn grant_prepared_facts(&mut self, grant: &GrantId) -> Result<Option<PreparedFacts>> {
        self.one_doc(
            "SELECT record_json FROM grant_prepared_facts WHERE grant_id = ?1",
            [grant.as_str()],
        )
    }

    // --- projection consent, resources and records ------------------------------------

    /// ⟨r2⟩ Merge `consent` into the environment's consent: each item it names
    /// replaces that item's stored states; other items are kept.
    pub fn set_projection_consent(
        &mut self,
        environment: &EnvironmentId,
        consent: &ConsentRecord,
    ) -> Result<()> {
        for (item, states) in &consent.items {
            self.tx.execute(
                "INSERT INTO projection_consent (environment, item, record_json) VALUES (?1, ?2, ?3)
                 ON CONFLICT(environment, item) DO UPDATE SET record_json = excluded.record_json",
                rusqlite::params![environment.as_str(), item.0, codec::doc(states)?],
            )?;
        }
        Ok(())
    }

    /// ⟨r2⟩ The environment's consent (empty when nothing was consented).
    pub fn get_projection_consent(&mut self, environment: &EnvironmentId) -> Result<ConsentRecord> {
        let rows: Vec<(String, String)> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT item, record_json FROM projection_consent WHERE environment = ?1
                 ORDER BY item",
            )?;
            let rows = stmt.query_map([environment.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = ConsentRecord::default();
        for (item, json) in rows {
            let states: ConsentedStates = codec::parse_doc(&json)?;
            out.items.insert(ItemId(item), states);
        }
        Ok(out)
    }

    /// The `config_projection` resources owned by the environment's projection,
    /// ordered by ID.
    pub fn projection_resources(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<Vec<ManagedResource>> {
        let owner = codec::doc(&OwnerRef::Projection {
            environment: environment.clone(),
        })?;
        self.docs(
            "SELECT record_json FROM resources WHERE kind = ?1 AND owner_json = ?2 ORDER BY id",
            rusqlite::params![codec::enum_str(&ResourceKind::ConfigProjection)?, owner],
        )
    }

    /// Insert or update a projection resource, a compare-and-swap by generation and
    /// identity (U0b row 20). The resource must be a `config_projection` owned by a
    /// projection, and its locator a canonical `ProjectionLocator`.
    ///
    /// `expected = None` inserts and fails if the resource exists. `Some((g, id))`
    /// updates only when the stored generation is `g` and the stored locator's file
    /// identity is `id` (birth compared on both sides, never a wildcard), and the
    /// new generation is not lower. Any mismatch is a
    /// [`StoreError::GenerationConflict`] and leaves the row unchanged.
    pub fn put_projection_resource(
        &mut self,
        resource: &ManagedResource,
        expected: Option<(ResourceGeneration, &FileIdentity)>,
    ) -> Result<()> {
        if resource.kind != ResourceKind::ConfigProjection
            || !matches!(resource.owner, OwnerRef::Projection { .. })
        {
            return Err(codec::doc_error(
                "a projection resource is a config_projection owned by a projection",
            ));
        }
        let locator: ProjectionLocator = codec::parse_doc(&resource.locator)?;
        if locator.canonical().ok().as_deref() != Some(resource.locator.as_str()) {
            return Err(codec::doc_error(
                "a projection resource locator is canonical",
            ));
        }
        match expected {
            None => self.upsert_resource(resource, None),
            Some((generation, identity)) => {
                let Some(stored) = self.resource(&resource.id)? else {
                    return Err(conflict(format!("resource {} does not exist", resource.id)));
                };
                let stored_locator: ProjectionLocator = codec::parse_doc(&stored.locator)?;
                if stored.generation != generation || !stored_locator.identity.same_file(identity) {
                    return Err(conflict(format!("resource {}", resource.id)));
                }
                self.upsert_resource(resource, Some(generation))
            }
        }
    }

    /// The environment's projection record, if an item was ever committed.
    pub fn projection_record(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<Option<ProjectionRecord>> {
        self.one_doc(
            "SELECT record_json FROM projection_records WHERE environment = ?1",
            [environment.as_str()],
        )
    }

    /// ⟨r3⟩ Commit one projection item (M2-R01; `StageSink::commit_item`): in the
    /// caller's one transaction, write the item's `config_projection` resources at
    /// the committed generation, the environment's projection record, the consented
    /// states, and the `item.committed` receipt. Any refusal or error writes nothing
    /// (the transaction rolls back).
    ///
    /// Checks: `receipt` is the `setup.item` receipt `item.committed{generation}` of
    /// `commit.item` with a `Confirmed` effect; `operation` exists, is a setup
    /// operation, and belongs to `commit.record.environment`; every resource's role
    /// belongs to the item; the record carries the item at the committed generation;
    /// and the generation is above both the stored record's and each stored
    /// resource's (a compare-and-swap, so a stale writer never wins). Resources of
    /// the item that the commit does not name are left as they are (the setup
    /// driver and the cleaner own them).
    pub fn commit_projection_item(
        &mut self,
        operation: &OperationId,
        commit: &ItemCommit,
        receipt: &StageReceipt,
    ) -> Result<()> {
        let committed = matches!(
            &receipt.local,
            Some(LocalReceipt::Item {
                item,
                phase: ItemPhase::Committed { generation },
            }) if *item == commit.item && *generation == commit.generation
        );
        if !committed
            || receipt.stage != STAGE_SETUP_ITEM
            || !matches!(receipt.effect, EffectReceipt::Confirmed { .. })
        {
            return Err(codec::doc_error(
                "commit_projection_item needs the item's item.committed receipt",
            ));
        }
        let Some(op) = self.operation(operation)? else {
            return Err(missing());
        };
        let environment = commit.record.environment.clone();
        if !op.kind.is_setup() || op.environment != environment {
            return Err(codec::doc_error(
                "a projection item is committed by a setup operation of its environment",
            ));
        }
        if commit
            .resources
            .iter()
            .any(|l| l.role.item() != commit.item)
            || commit
                .record
                .items
                .get(&commit.item)
                .is_none_or(|r| r.generation != commit.generation)
        {
            return Err(codec::doc_error("the commit does not describe its item"));
        }
        if let Some(stored) = self.projection_record(&environment)?
            && stored
                .items
                .get(&commit.item)
                .is_some_and(|r| r.generation >= commit.generation)
        {
            return Err(conflict(format!(
                "projection item of {environment} is already at generation {} or later",
                commit.generation
            )));
        }
        let generation = ResourceGeneration(commit.generation);
        for locator in &commit.resources {
            let id = projection_resource_id(&environment, locator.role, &locator.path);
            let canonical = locator
                .canonical()
                .map_err(|_| codec::doc_error("a projection locator cannot be canonicalized"))?;
            let resource = ManagedResource {
                id: id.clone(),
                kind: ResourceKind::ConfigProjection,
                owner: OwnerRef::Projection {
                    environment: environment.clone(),
                },
                generation,
                desired: ResourceState::Present,
                observed: ResourceState::Present,
                last_operation: Some(operation.clone()),
                locator: canonical,
                updated_at: receipt.recorded_at,
            };
            match self.resource(&id)? {
                None => self.upsert_resource(&resource, None)?,
                Some(stored) if stored.generation < generation => {
                    self.upsert_resource(&resource, Some(stored.generation))?;
                }
                Some(_) => return Err(conflict(format!("resource {id}"))),
            }
        }
        self.tx.execute(
            "INSERT INTO projection_records (environment, record_json) VALUES (?1, ?2)
             ON CONFLICT(environment) DO UPDATE SET record_json = excluded.record_json",
            rusqlite::params![environment.as_str(), codec::doc(&commit.record)?],
        )?;
        self.set_projection_consent(&environment, &commit.consent)?;
        self.append_stage_receipt(operation, receipt)
    }

    // --- setup admission (ADR-0007 §5.7 "One setup operation at a time") ----------------

    /// ⟨r3⟩ The environment's open or unresolved setup operations (`queued`,
    /// `running`, `awaiting_approval`, `outcome_unknown`), oldest first.
    pub fn open_setup_operations(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<Vec<OperationId>> {
        // Kind names carry a dot, so they are bound; state names are plain.
        let sql = format!(
            "SELECT id FROM operations
             WHERE environment = ?1 AND kind IN (?2, ?3, ?4) AND state IN ({})
             ORDER BY created_at, id",
            sql_in_list(&operation_states(|s| !s.is_settled()))?
        );
        let [a, r, p] = OperationKind::SETUP.map(OperationKind::as_str);
        let ids: Vec<String> = {
            let mut stmt = self.tx.prepare_cached(&sql)?;
            let rows = stmt.query_map(rusqlite::params![environment.as_str(), a, r, p], |row| {
                row.get(0)
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        ids.iter()
            .map(|s| {
                OperationId::parse(s)
                    .map_err(|_| codec::doc_error("stored operation id is malformed"))
            })
            .collect()
    }

    /// Whether `operation` is held: in `outcome_unknown`, with its last local
    /// receipt `file.held`. A receipt this build cannot decode never shows a hold.
    fn setup_operation_is_held(&mut self, operation: &OperationId) -> Result<bool> {
        let Some(op) = self.operation(operation)? else {
            return Ok(false);
        };
        if op.state != OperationState::OutcomeUnknown {
            return Ok(false);
        }
        let raw: Vec<String> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT record_json FROM stage_receipts WHERE operation_id = ?1 ORDER BY ordinal",
            )?;
            let rows = stmt.query_map([operation.as_str()], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut last_local = None;
        for json in &raw {
            let Ok(receipt) = codec::parse_doc::<StageReceipt>(json) else {
                return Ok(false);
            };
            if receipt.local.is_some() {
                last_local = receipt.local;
            }
        }
        Ok(matches!(
            last_local,
            Some(LocalReceipt::File {
                phase: FilePhase::Held { .. },
                ..
            })
        ))
    }

    /// ⟨r4⟩ Admit a setup operation (m02-plan §5 item 18; frozen; ADR-0007 §5.7
    /// "Admission is atomic"). Inside the caller's admission transaction, which runs
    /// as `BEGIN IMMEDIATE`: read the environment's open or unresolved setup
    /// operations, then either insert the operation, its idempotency record and its
    /// recovery intent, or write nothing and return the blockers. Two admissions can
    /// therefore never both see an empty set.
    ///
    /// The set must be empty, or exactly `{repair_target}` with that operation held
    /// (`outcome_unknown`, last local receipt `file.held`): the repair of a held
    /// operation by `retry_held`/`keep_held` naming it is the one exception.
    ///
    /// The caller classifies idempotency first (a replay never reaches this). The
    /// record must be a setup operation that is not settled, and the intent must
    /// carry a valid `LocalIntent::Setup` and no `resolved` intent; a `repair_target`
    /// needs a `setup.repair` operation whose intent is a held repair naming that
    /// target. A caller error is refused before the read and writes nothing.
    pub fn insert_setup_operation(
        &mut self,
        op: &OperationRecord,
        idem: &IdempotencyRecord,
        intent: &RecoveryIntent,
        repair_target: Option<&OperationId>,
    ) -> Result<SetupAdmitted> {
        if !op.kind.is_setup() || op.state.is_settled() {
            return Err(codec::doc_error(
                "insert_setup_operation admits an unsettled setup operation",
            ));
        }
        if intent.resolved.is_some() {
            return Err(conflict(format!(
                "recovery intent of {} carries both a local and a resolved intent",
                op.id
            )));
        }
        let Some(LocalIntent::Setup(setup)) = &intent.local else {
            return Err(codec::doc_error(
                "a setup operation's intent is a setup intent",
            ));
        };
        if setup.validate().is_err() {
            return Err(codec::doc_error("the local intent is invalid"));
        }
        if let Some(target) = repair_target {
            let names_target = match &setup.intent {
                heimdall_contract::setup::PreviewIntent::Repair {
                    resolution,
                    operation,
                    ..
                } => resolution.is_held_resolution() && operation.as_ref() == Some(target),
                _ => false,
            };
            if op.kind != OperationKind::SetupRepair || !names_target {
                return Err(codec::doc_error(
                    "a repair target goes only with a held repair that names it",
                ));
            }
        }
        let blockers = self.open_setup_operations(&op.environment)?;
        let admitted = match (blockers.as_slice(), repair_target) {
            ([], _) => true,
            ([only], Some(target)) if only == target => self.setup_operation_is_held(target)?,
            _ => false,
        };
        if !admitted {
            return Ok(SetupAdmitted::InProgress(blockers));
        }
        self.insert_operation(op, idem)?;
        self.set_recovery_intent(&op.id, intent)?;
        Ok(SetupAdmitted::Inserted)
    }
}
