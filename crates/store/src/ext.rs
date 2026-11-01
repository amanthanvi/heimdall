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
    BindingId, CredentialInstanceId, DecisionId, EnvironmentId, GrantId, IssuanceId, OperationId,
    ProfileId, WorkId,
};
use heimdall_contract::request::Verdict;
use heimdall_contract::{GrantState, OperationState, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionRefusal, DecisionState};
use heimdall_domain::environment::EnvironmentRecord;
use heimdall_domain::grant::{AuthorizationSource, DegradedReason, GrantOrigin, GrantReference};
use heimdall_domain::idempotency::{ExpiredKeyMarker, IdempotencyKey, KeyHash};
use heimdall_domain::issuance::{
    CredentialInstance, CredentialState, IssuanceEntry, IssuanceRefusal, IssuanceState,
};
use heimdall_domain::operation::{
    ApprovalBasis, CoveredBasis, OperationRecord, RecoveryIntent, StageReceipt,
};
use heimdall_domain::policy::{AuthorityGeneration, StandingPolicy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::profile::{ProfileDefinition, ProfileSnapshot};
use heimdall_domain::revocation::{PendingRemoteRevocation, Tombstone};
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
fn intent_update_allowed(old: &RecoveryIntent, new: &RecoveryIntent) -> bool {
    if old.request != new.request {
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
    /// Written once: recording the same origin again is a no-op. The only change
    /// accepted afterwards is add-only: a stored origin without a `covered` basis
    /// may gain one (§13.7 item 2), every other field unchanged. Anything else is a
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
            let gains_covered = existing.covered.is_none()
                && origin.covered.is_some()
                && GrantOrigin {
                    covered: None,
                    ..origin.clone()
                } == existing;
            if !gains_covered {
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

    // --- R5: recovery intent and stage receipts ----------------------------------------

    /// Persist the redacted recovery intent (written before any effect).
    ///
    /// The operation must exist (foreign key). An update may only add facts: the
    /// request is immutable; once `resolved` is set it cannot be cleared, its
    /// pinned profile revision, scope, deadline, policy revision and generation
    /// never change, and an assigned grant, binding, adapter, approval basis or
    /// covered basis (⟨r2.4⟩ ADR-0006 §13.7 item 2) is never replaced.
    /// Anything else is a [`StoreError::GenerationConflict`]. Key armor is refused.
    pub fn set_recovery_intent(
        &mut self,
        operation: &OperationId,
        intent: &RecoveryIntent,
    ) -> Result<()> {
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
