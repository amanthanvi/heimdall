//! Heimdall transactional local state (plan §4.1 "Persistence/secrets"; spec §13.3,
//! P08). One implementation: SQLite through `rusqlite` with the bundled engine.
//! `Store::open_in_memory` serves model tests, so no second backend exists
//! (plan §4.1 "two callers" rule; overview §7).
//!
//! Owns: the operation journal, idempotency records, grants and references,
//! tombstones and the authority generation, standing policies, profile and
//! environment records, managed-resource generations, the event log with
//! per-environment sequence numbers, time anchors, and schema migrations.
//!
//! Must not own: private key material or plaintext secrets (references only,
//! spec §13.3), retry loops, authorization decisions, or wire rendering.
//!
//! Durability rules: WAL journal, `synchronous=FULL`, foreign keys on. Every write
//! happens inside [`Store::transaction`]; fault points before and after the commit
//! are exposed through [`FaultHook`] so plan §6.4 interruptions are testable
//! without killing the process. A newer schema than this build understands is
//! refused with [`StoreError::NewerSchema`], never read as empty (spec §13.3).

use std::path::Path;
use std::sync::Arc;

use heimdall_contract::event::{Event, EventFilter};
use heimdall_contract::ids::{EnvironmentId, EventId, GrantId, OperationId, PolicyId, ResourceId};
use heimdall_contract::{OperationState, Timestamp};
use heimdall_domain::grant::{GrantReference, GrantSnapshot};
use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
use heimdall_domain::operation::OperationRecord;
use heimdall_domain::policy::{AuthorityGeneration, StandingPolicy};
use heimdall_domain::resource::{ManagedResource, ResourceGeneration};
use heimdall_domain::revocation::Tombstone;
use heimdall_domain::time::TimeAnchor;

pub mod migrations;

/// Store errors. Mapped to `STATE_UNAVAILABLE` by the application layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// JSON (de)serialization of a stored column.
    #[error("stored document is malformed: {0}")]
    Json(#[from] serde_json::Error),
    /// The on-disk schema is newer than this build understands.
    #[error("state store schema {found} is newer than supported {supported}")]
    NewerSchema {
        /// Found on disk.
        found: u32,
        /// Supported by this build.
        supported: u32,
    },
    /// Integrity check failed; unsafe operations must stop (spec §15.2).
    #[error("state store failed integrity check: {0}")]
    Corrupt(String),
    /// A fault hook requested failure (tests only).
    #[error("injected fault at {0:?}")]
    InjectedFault(FaultPoint),
    /// Optimistic concurrency: the row's generation changed under us.
    #[error("generation conflict on {0}")]
    GenerationConflict(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Durable-write interruption points (plan §6.4 "before and after each durable
/// write").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Before `BEGIN`.
    BeforeTransaction,
    /// After all statements, before `COMMIT`.
    BeforeCommit,
    /// After `COMMIT` returned, before the caller observes success.
    AfterCommit,
    /// Before a migration step.
    BeforeMigration,
    /// After a migration step's commit.
    AfterMigration,
}

/// What an injected fault does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    /// Nothing.
    Continue,
    /// Return [`StoreError::InjectedFault`] (the transaction rolls back if open).
    Fail,
    /// Abort the process immediately (simulates a crash; tests spawn a child).
    Crash,
}

/// Hook consulted at every [`FaultPoint`]. Production uses [`NoFaults`].
pub trait FaultHook: Send + Sync {
    /// Decide what happens at `point`.
    fn at(&self, point: FaultPoint) -> FaultAction;
}

/// Never injects.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFaults;

impl FaultHook for NoFaults {
    fn at(&self, _point: FaultPoint) -> FaultAction {
        FaultAction::Continue
    }
}

/// The local state store.
pub struct Store {
    conn: std::sync::Mutex<rusqlite::Connection>,
    faults: Arc<dyn FaultHook>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// A unit of work. Every method runs inside one SQLite transaction.
pub struct Txn<'a> {
    tx: rusqlite::Transaction<'a>,
}

impl std::fmt::Debug for Txn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Txn").finish_non_exhaustive()
    }
}

/// Page of events with the cursor boundary to continue from.
#[derive(Debug, Clone)]
pub struct EventPage {
    /// Events in sequence order.
    pub events: Vec<Event>,
    /// Highest sequence number in this environment's log (for snapshot cursors).
    pub head_seq: u64,
    /// Lowest sequence still retained (a cursor below it is expired).
    pub tail_seq: u64,
}

impl Store {
    /// Open or create the store at `path`, applying migrations (with a backup of
    /// the file before the first schema change). Refuses a newer schema.
    pub fn open(_path: &Path, _faults: Arc<dyn FaultHook>) -> Result<Self> {
        todo!("M01-T03: open with WAL/synchronous=FULL/foreign_keys, integrity_check, migrate")
    }

    /// In-memory store for tests; same schema and code paths.
    pub fn open_in_memory(_faults: Arc<dyn FaultHook>) -> Result<Self> {
        todo!("M01-T03: open :memory: and migrate")
    }

    /// Run `f` inside one transaction. Fault points fire before the transaction,
    /// before commit and after commit.
    pub fn transaction<R>(&self, f: impl FnOnce(&mut Txn<'_>) -> Result<R>) -> Result<R> {
        let _ = &self.faults;
        let _ = &self.conn;
        let _ = f;
        todo!("M01-T03: BEGIN IMMEDIATE, run f, consult FaultHook, COMMIT")
    }

    /// Schema version on disk.
    pub fn schema_version(&self) -> Result<u32> {
        todo!("M01-T03")
    }
}

impl Txn<'_> {
    // --- operations and idempotency (spec §11.4) ---------------------------------

    /// Insert a new operation and its idempotency record atomically.
    pub fn insert_operation(
        &mut self,
        _op: &OperationRecord,
        _idem: &IdempotencyRecord,
    ) -> Result<()> {
        let _ = &self.tx;
        todo!("M01-T03")
    }

    /// Look up an idempotency record by key.
    pub fn idempotency_record(
        &mut self,
        _key: &IdempotencyKey,
    ) -> Result<Option<IdempotencyRecord>> {
        todo!("M01-T03")
    }

    /// Load an operation.
    pub fn operation(&mut self, _id: &OperationId) -> Result<Option<OperationRecord>> {
        todo!("M01-T03")
    }

    /// Persist a state change; the caller has already validated the transition.
    pub fn update_operation(&mut self, _op: &OperationRecord) -> Result<()> {
        todo!("M01-T03")
    }

    /// Operations not in a terminal state (restart recovery, spec §13.3).
    pub fn open_operations(&mut self) -> Result<Vec<OperationRecord>> {
        todo!("M01-T03")
    }

    /// Purge terminal operations and idempotency records past `before`
    /// (retention contract, ADR-0006 §7.4). Never touches tombstones or policies.
    pub fn purge_operations_before(&mut self, _before: Timestamp) -> Result<u64> {
        todo!("M01-T03")
    }

    // --- grants, references, tombstones, generation (spec §6.3, §6.7) -----------

    /// Insert a grant snapshot.
    pub fn insert_grant(&mut self, _grant: &GrantSnapshot) -> Result<()> {
        todo!("M01-T03")
    }

    /// Load a grant.
    pub fn grant(&mut self, _id: &GrantId) -> Result<Option<GrantSnapshot>> {
        todo!("M01-T03")
    }

    /// Update a grant's state and enforcement; scope and deadline columns are
    /// immutable and the statement must not touch them.
    pub fn update_grant_state(&mut self, _grant: &GrantSnapshot) -> Result<()> {
        todo!("M01-T03")
    }

    /// Grants whose deadline is at or before `now` and that are not terminal.
    pub fn grants_due(&mut self, _now: Timestamp) -> Result<Vec<GrantSnapshot>> {
        todo!("M01-T03")
    }

    /// Descendants of a grant (transitive children).
    pub fn grant_descendants(&mut self, _id: &GrantId) -> Result<Vec<GrantId>> {
        todo!("M01-T03")
    }

    /// Add a consumer reference.
    pub fn add_grant_reference(&mut self, _reference: &GrantReference) -> Result<()> {
        todo!("M01-T03")
    }

    /// Drop a consumer reference; returns remaining references for the grant.
    pub fn remove_grant_reference(&mut self, _reference: &GrantReference) -> Result<u64> {
        todo!("M01-T03")
    }

    /// Persist a tombstone and bump the authority generation in the same transaction.
    pub fn insert_tombstone(&mut self, _tombstone: &Tombstone) -> Result<AuthorityGeneration> {
        todo!("M01-T03")
    }

    /// Current authority generation.
    pub fn authority_generation(&mut self) -> Result<AuthorityGeneration> {
        todo!("M01-T03")
    }

    // --- policies, profiles, environments ------------------------------------------

    /// Upsert a standing policy at a new revision; bumps the authority generation
    /// when the change narrows, pauses or cuts off.
    pub fn upsert_policy(
        &mut self,
        _policy: &StandingPolicy,
        _narrowing: bool,
    ) -> Result<AuthorityGeneration> {
        todo!("M01-T03")
    }

    /// Load a policy.
    pub fn policy(&mut self, _id: &PolicyId) -> Result<Option<StandingPolicy>> {
        todo!("M01-T03")
    }

    /// This runtime's own environment ID (created at first start, never reset by
    /// recovery; R-RT-07).
    pub fn self_environment(&mut self) -> Result<Option<EnvironmentId>> {
        todo!("M01-T03")
    }

    /// Record this runtime's environment ID once.
    pub fn init_self_environment(&mut self, _id: &EnvironmentId) -> Result<()> {
        todo!("M01-T03")
    }

    // --- managed resources (spec §13.5) ------------------------------------------------

    /// Upsert with compare-and-swap on generation.
    pub fn upsert_resource(
        &mut self,
        _resource: &ManagedResource,
        _expected: Option<ResourceGeneration>,
    ) -> Result<()> {
        todo!("M01-T03")
    }

    /// Load a resource.
    pub fn resource(&mut self, _id: &ResourceId) -> Result<Option<ManagedResource>> {
        todo!("M01-T03")
    }

    /// Resources whose desired and observed states differ.
    pub fn resources_needing_reconcile(&mut self) -> Result<Vec<ManagedResource>> {
        todo!("M01-T03")
    }

    // --- events (spec §11.5) -------------------------------------------------------------

    /// Append an event; assigns the next per-environment sequence and the event ID.
    pub fn append_event(&mut self, _event_without_cursor: &Event) -> Result<(EventId, u64)> {
        todo!("M01-T03")
    }

    /// Read events after `after_seq` (bounded by `limit`).
    pub fn events_after(
        &mut self,
        _environment: &EnvironmentId,
        _after_seq: u64,
        _filter: &EventFilter,
        _limit: u32,
    ) -> Result<EventPage> {
        todo!("M01-T03")
    }

    /// Trim the event log to retention; returns the new tail sequence.
    pub fn trim_events(
        &mut self,
        _environment: &EnvironmentId,
        _keep_after: Timestamp,
        _max_rows: u64,
    ) -> Result<u64> {
        todo!("M01-T03")
    }

    // --- time anchors (spec §6.4) ---------------------------------------------------------

    /// Last persisted anchor.
    pub fn time_anchor(&mut self) -> Result<Option<TimeAnchor>> {
        todo!("M01-T03")
    }

    /// Persist the anchor.
    pub fn set_time_anchor(&mut self, _anchor: &TimeAnchor) -> Result<()> {
        todo!("M01-T03")
    }

    /// Count of operations by state (status/inspect).
    pub fn operation_counts(&mut self) -> Result<Vec<(OperationState, u64)>> {
        todo!("M01-T03")
    }
}
