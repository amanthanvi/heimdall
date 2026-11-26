//! Heimdall transactional local state (plan §4.1 "Persistence/secrets"; spec §13.3,
//! P08). One implementation: SQLite through `rusqlite` with the bundled engine.
//! `Store::open_in_memory` serves model tests, so no second backend exists
//! (plan §4.1 "two callers" rule; overview §7).
//!
//! Owns: the operation journal, idempotency records, grants and references,
//! tombstones and the authority generation, standing policies, profile and
//! environment records, managed-resource generations, the event log with
//! per-environment sequence numbers, time anchors, and schema migrations.
//! ⟨M02⟩ Also the destination and identity catalog, interaction declarations,
//! binding holders, prepared facts, projection consent and records, and atomic
//! setup admission (`migrations/0005_existing_access.sql`; m02-plan §5 item 18).
//! ⟨M03⟩ Also registered CAs, enrollments, foreign removals, verification issuance,
//! pair preferences, managed slots and owned connections
//! (`migrations/0006_managed_credentials.sql`; m03-plan §5 item 18; [`ext_m03`]).
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

pub use migrations::SCHEMA_VERSION;

mod codec;
pub mod ext;
pub mod ext_m03;
// ⟨M04⟩ Joint wave 0: the managed-environment set and WSL distribution records.
pub mod ext_m04;
pub mod ext_m05;
// ⟨M06⟩ U1: the runner's role table, invitations and the admission authority generation.
pub mod ext_m06;
// ⟨M06 U5a⟩ A destination's ordered approved routes (ADR-0012 §5.1, §9 item 9).
pub mod ext_routes;
// ⟨M06 U56⟩ The Iroh transport's key references and exposure consents (ADR-0012 §2).
pub mod ext_transport;
// ⟨M06 U3⟩ The runner's grant-to-issuer pins, issuer_trust and time source (ADR-0012 §4).
pub mod ext_runner;
// ⟨M06 U4⟩ Typed narrowing effects: the outbox, acknowledgements and policy revisions (ADR-0012 §7).
pub mod ext_effects;
// ⟨M08 U2b-2⟩ The restore epoch and the replay fence (ADR-0014 H9, §3.6).
pub mod fence;
// ⟨M08 U2b-1⟩ The generation layout (ADR-0014 §3.6, H12): the pointer, the generations and
// the adoption of a flat store, over `heimdall-stategen`.
pub mod layout;
pub mod migrations;

pub use ext::{DecisionCompletion, EndOutcome, SetupAdmitted, StoredEvent, StoredEventPage};
pub use ext_m03::{
    IssuerRecord, LostInstances, ManagedSlot, OpenEnrollmentOperation, OutstandingObligations,
};

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
    /// ⟨M02⟩ A read-only open found an older schema; it is reported, never
    /// upgraded ([`Store::open_read_only`] never migrates).
    #[error("state store schema {found} is older than {supported}; open it read-write to migrate")]
    OlderSchema {
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
    /// ⟨rev7; U0-Q9, review U0-R01⟩ A destination write met another destination's alias
    /// (compared without ASCII case, [`Txn::upsert_destination`]): a typed conflict, so a caller
    /// answers it as `CONFIG_CONFLICT` / `alias_collision`, never as an unavailable store.
    #[error("the destination alias is taken (aliases compare without case)")]
    DestinationAliasTaken,
    /// ⟨M08 U2b-1; ADR-0014 §3.6 adoption step 2⟩ The family was fenced for adoption into the
    /// generation layout ([`layout::ADOPTION_FENCE`]). It is never served again: the store is
    /// the generation `CURRENT` names, or, while the adoption is unfinished, the next start of
    /// the runtime finishes it ([`layout::open_locked`]).
    #[error(
        "this state store was fenced for adoption into the generation layout and is not served; start the runtime to finish the adoption"
    )]
    AdoptionFenced,
    /// ⟨M08 U2b-1; ADR-0014 §3.6⟩ The generation layout's own failure: an I/O error, or a
    /// refusal, of the state directory's pointer, intent or generation directories
    /// ([`layout`]). A corrupt layout is [`StoreError::Corrupt`] (`state_corrupt: <reason>`).
    #[error("state layout: {0}")]
    Layout(heimdall_stategen::StateError),
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

/// A `file:` URI for `path` with `query` (every byte outside the unreserved set and `/`
/// percent-encoded; Windows separators as `/`, a drive path behind `///`).
fn file_uri(path: &Path, query: &str) -> Option<String> {
    let text = path.to_str()?;
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    };
    let mut out = String::from("file://");
    if !text.starts_with('/') {
        out.push('/');
    }
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(char::from(b));
            }
            b':' if cfg!(windows) && i == 1 => out.push(':'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push('?');
    out.push_str(query);
    Some(out)
}

/// The local state store.
pub struct Store {
    conn: std::sync::Mutex<rusqlite::Connection>,
    faults: Arc<dyn FaultHook>,
    /// Opened by [`Store::open_read_only`]: transactions are deferred and the
    /// connection is `query_only`, so every write fails.
    read_only: bool,
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
    /// Sequences are monotonic per environment (never reused, not contiguous:
    /// one store-wide counter feeds every environment).
    pub head_seq: u64,
    /// Retention boundary: the highest sequence removed by [`Txn::trim_events`]
    /// for this environment (0 when nothing was trimmed). A cursor whose
    /// consumed-through sequence is below it is expired (`RESYNC_REQUIRED`); every
    /// event after a cursor at or above it is still retained.
    pub tail_seq: u64,
}

/// Consult `hook` at `point`: continue, fail with [`StoreError::InjectedFault`], or
/// abort the process (child-process crash tests).
pub(crate) fn fire(hook: &dyn FaultHook, point: FaultPoint) -> Result<()> {
    match hook.at(point) {
        FaultAction::Continue => Ok(()),
        FaultAction::Fail => Err(StoreError::InjectedFault(point)),
        FaultAction::Crash => std::process::abort(),
    }
}

/// Tables the current schema must contain; a versioned file missing one is corrupt.
const REQUIRED_TABLES: &[&str] = &[
    "meta",
    "operations",
    "idempotency",
    "policies",
    "profiles",
    "environments",
    "grants",
    "grant_references",
    "bindings",
    "tombstones",
    "resources",
    "events",
    // schema version 2
    "idempotency_markers",
    "decisions",
    "profile_snapshots",
    "grant_anchors",
    "recovery_intents",
    "stage_receipts",
    "issuance_log",
    "credential_instances",
    // schema version 5 (M02 existing access; m02-plan §5 item 18)
    "destinations",
    "identities",
    "interaction_declarations",
    "binding_holders",
    "grant_prepared_facts",
    "projection_consent",
    "projection_records",
    // schema version 6 (M03 managed credentials; m03-plan §5 item 18)
    "issuers",
    "enrollments",
    "foreign_removals",
    "verification_issuance",
    "pair_preferences",
    "managed_slots",
    "owned_connections",
    // schema version 7 (M04 platform realization; ADR-0010 §9 item 1)
    "managed_environments",
    "wsl_distributions",
    // schema version 8 (M05 trusted work; ADR-0011 §10 item 5)
    "workspaces",
    "policy_history",
    "decision_cooldowns",
    "work_stops",
    "slot_references",
    // schema version 9 (M06 remote runners, routes, transport; ADR-0012 §9 item 11)
    "remote_clients",
    "remote_invitations",
    "remote_effect_outbox",
    "remote_effect_acks",
    "remote_policy_revisions",
    "remote_environment_pins",
    "remote_grant_issuers",
    "destination_routes",
    "route_consents",
    "remote_authority_generation",
    "transport_keys",
    // schema version 10 (M06 wave 2: the runner-local widening records; ADR-0012 §3.10)
    "remote_widening",
    // schema version 12 (M06 wave 4: the controller's lift acknowledgements; ADR-0006 §18.8)
    "remote_lift_acks",
    // schema version 14 (revision 7: the request fences; ADR-0014 H9, §3.6)
    "request_fences",
];

/// Columns added to existing tables that the current schema must contain
/// (schema version 3: the approval basis persisted with the grant, ADR-0006 §13.7
/// item 3; schema version 4: the grant's origin, ADR-0006 §13.9 item 2).
/// Schema version 8 adds `bindings.context_json` (ADR-0011 §5.1).
const REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("grants", "approval_json"),
    ("grants", "origin_json"),
    ("grants", "is_live"), // schema version 15 (M08 GRANT-LIVE)
    ("bindings", "context_json"),
    // schema version 13 (M06 wave 5: the widening record's origin; ADR-0006 §18.9 item 8)
    ("remote_widening", "origin"),
    ("remote_widening", "delta_digest"),
    // schema version 14 (revision 7: the restore epoch; ADR-0014 H9, §3.6)
    ("operations", "restore_epoch"),
    ("decisions", "restore_epoch"),
    ("remote_effect_outbox", "restore_epoch"),
    ("idempotency", "request_epoch"),
];

const LIVE_GRANTS_SQL: &str =
    "SELECT record_json FROM grants WHERE is_live = 1 ORDER BY deadline_effective, id";
const GRANTS_DUE_SQL: &str =
    "SELECT record_json FROM grants WHERE is_live = 1 AND deadline_effective <= ?1
     ORDER BY deadline_effective, id";

const META_SELF_ENVIRONMENT: &str = "self_environment_id";
const META_AUTHORITY_GENERATION: &str = "authority_generation";
/// ⟨M03⟩ ADR-0008 D10 item 1: the installation's Windows environment pipe token.
const META_WINDOWS_PIPE_TOKEN: &str = "windows_environment_pipe_token";
/// ⟨rev7⟩ ADR-0014 H9, §3.6 step 1: the current restore epoch. Migration 0014 writes `0`; a
/// restore raises it before its pointer moves (U2b). From schema version 14 on a store without
/// it is damaged ([`StoreError::Corrupt`], `state_corrupt`), never epoch 0 (review U0-R06):
/// [`verify_schema`] refuses it at every open.
const META_RESTORE_EPOCH: &str = "restore_epoch";

/// ⟨rev7; review U0-RC04⟩ The stored restore epoch's only form: canonical decimal (`0`, or a
/// nonzero digit then digits), no sign, no leading zero, no whitespace, within `u64`. Anything
/// else is damage. The reader U2b adds parses through this too, so the open check and the
/// reader cannot disagree.
pub(crate) fn parse_restore_epoch(text: &str) -> Option<u64> {
    let canonical = text == "0"
        || (text
            .as_bytes()
            .first()
            .is_some_and(|b| (b'1'..=b'9').contains(b))
            && text.bytes().all(|b| b.is_ascii_digit()));
    if canonical { text.parse().ok() } else { None }
}

/// A Windows pipe token: 1 to 64 ASCII letters or digits (the credential crate's
/// `pipe_token_ok`, which the store cannot name).
fn pipe_token_valid(token: &str) -> bool {
    !token.is_empty() && token.len() <= 64 && token.bytes().all(|b| b.is_ascii_alphanumeric())
}
/// Per-environment retention boundary: `event_tail:<environment id>`.
const META_EVENT_TAIL_PREFIX: &str = "event_tail:";

/// Prefix of the store-level sequence marker placed in [`Event::cursor`] by
/// [`Txn::events_after`]; see [`event_seq`].
const STORE_SEQ_PREFIX: &str = "store-seq:";

/// Sequence number of an event returned by [`Txn::events_after`].
///
/// The store cannot build reader-scoped cursors (they depend on the authenticated
/// reader, ADR-0006 §8), so it places a store-internal marker in `Event::cursor`;
/// the application must replace it with the reader-scoped opaque cursor before the
/// event leaves the process. Returns `None` for any other cursor form.
#[must_use]
pub fn event_seq(event: &Event) -> Option<u64> {
    event
        .cursor
        .0
        .strip_prefix(STORE_SEQ_PREFIX)
        .and_then(|s| s.parse().ok())
}

impl Store {
    /// Open or create the store at `path`, applying migrations (with a backup of
    /// the file before the first schema change). Refuses a newer schema.
    ///
    /// A file that is not a state database, fails `integrity_check` or
    /// `foreign_key_check`, has schema objects without a version, or misses a
    /// required table is [`StoreError::Corrupt`]; nothing is rewritten in that case
    /// (spec §15.2: corrupt state stops unsafe operations and is never silently
    /// reinitialized). Only a missing or zero-length file is a new installation.
    pub fn open(path: &Path, faults: Arc<dyn FaultHook>) -> Result<Self> {
        Self::open_with_steps(path, faults, migrations::MIGRATIONS, true)
    }

    /// In-memory store for tests; same schema and code paths.
    pub fn open_in_memory(faults: Arc<dyn FaultHook>) -> Result<Self> {
        let mut conn = rusqlite::Connection::open_in_memory().map_err(codec::classify)?;
        configure(&conn, false)?;
        migrations::apply_steps(&mut conn, faults.as_ref(), migrations::MIGRATIONS)?;
        verify_schema(&conn)?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
            faults,
            read_only: false,
        })
    }

    /// ⟨M02⟩ Open an existing store without writing anything (m02-plan §5 item 18;
    /// U0b row 20): doctor and the CLI's pre-launch check read the catalog and the
    /// declarations this way, and never start the runtime.
    ///
    /// It never creates, migrates or repairs. A missing file is an error; a newer
    /// schema is [`StoreError::NewerSchema`]; an older one (including an empty file)
    /// is [`StoreError::OlderSchema`], reported and never upgraded; a damaged file
    /// is [`StoreError::Corrupt`]. The connection is `query_only` and every
    /// transaction is deferred, so a write through it fails.
    pub fn open_read_only(path: &Path, faults: Arc<dyn FaultHook>) -> Result<Self> {
        let conn = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(codec::classify)?;
        Self::read_only_from(conn, faults)
    }

    /// ⟨ADR-0008 §17.36 item 1 (audit E3)⟩ [`Store::open_read_only`] that writes **no**
    /// file of the database family: a URI open with `mode=ro&readonly_shm=1`. SQLite
    /// then opens the `-shm` read-only and never creates, extends or writes it; when it is
    /// empty or stale, SQLite builds the WAL index in heap memory from the `-wal` (result
    /// `SQLITE_READONLY_CANTINIT`, handled inside SQLite's `walBeginShmUnreliable`), so a
    /// WAL-only commit is still read. An **absent** `-shm` (or `-wal`) cannot be opened
    /// read-only: that open fails (`SQLITE_CANTOPEN`), and the caller reads a copy
    /// instead. For the uninstall purge's validating reads of the owner's family only;
    /// every other caller keeps [`Store::open_read_only`].
    ///
    /// # Errors
    /// As [`Store::open_read_only`]; a path that is not UTF-8.
    pub fn open_read_only_no_write(path: &Path, faults: Arc<dyn FaultHook>) -> Result<Self> {
        let Some(uri) = file_uri(path, "mode=ro&readonly_shm=1") else {
            return Err(StoreError::Corrupt(
                "the database path is not UTF-8".to_owned(),
            ));
        };
        let conn = rusqlite::Connection::open_with_flags(
            uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(codec::classify)?;
        Self::read_only_from(conn, faults)
    }

    fn read_only_from(conn: rusqlite::Connection, faults: Arc<dyn FaultHook>) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(codec::classify)?;
        let current = migrations::check_version(&conn, migrations::MIGRATIONS)?;
        if current < SCHEMA_VERSION {
            return Err(StoreError::OlderSchema {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }
        integrity_check(&conn)?;
        conn.pragma_update(None, "query_only", "ON")
            .map_err(codec::classify)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(codec::classify)?;
        conn.pragma_update(None, "trusted_schema", "OFF")
            .map_err(codec::classify)?;
        verify_schema(&conn)?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
            faults,
            read_only: true,
        })
    }

    /// ⟨ADR-0008 §17.36 item 1⟩ Write one self-contained copy of this **read-only**
    /// store's database (its log included) to `out` with `VACUUM INTO`: the uninstall
    /// purge's recovery copy, from the connection its final read validated. `out` must be
    /// an existing empty file (the caller creates it exclusively) or absent. The main
    /// database is opened `SQLITE_OPEN_READONLY`, so nothing can write it; `query_only`
    /// (which also forbids writing the `INTO` file) is lifted for this one statement
    /// only. The copy is in rollback-journal mode, with no log of its own.
    ///
    /// # Errors
    /// Not a read-only store, a path that is not UTF-8, or SQLite.
    pub fn vacuum_into(&self, out: &Path) -> Result<()> {
        if !self.read_only {
            return Err(StoreError::Corrupt(
                "vacuum_into is only for a read-only store".to_owned(),
            ));
        }
        let Some(target) = out.to_str() else {
            return Err(StoreError::Corrupt(
                "the recovery copy's path is not UTF-8".to_owned(),
            ));
        };
        let conn = self
            .conn
            .lock()
            .map_err(|_| StoreError::Corrupt("store connection poisoned".to_owned()))?;
        conn.pragma_update(None, "query_only", "OFF")
            .map_err(codec::classify)?;
        let written = conn
            .execute("VACUUM INTO ?1", [target])
            .map_err(codec::classify);
        conn.pragma_update(None, "query_only", "ON")
            .map_err(codec::classify)?;
        written.map(drop)
    }

    /// Test support (`tests/integration/store.rs`, migration coverage): open or
    /// create the store at `path` migrated only up to `version` (1 ..=
    /// [`SCHEMA_VERSION`]), as a build of that schema would leave it. Never used by
    /// production code.
    #[doc(hidden)]
    pub fn open_at_schema_version(
        path: &Path,
        faults: Arc<dyn FaultHook>,
        version: u32,
    ) -> Result<Self> {
        let n = usize::try_from(version)
            .ok()
            .filter(|n| (1..=migrations::MIGRATIONS.len()).contains(n))
            .ok_or_else(|| codec::doc_error("no such schema version"))?;
        Self::open_with_steps(path, faults, &migrations::MIGRATIONS[..n], false)
    }

    /// ⟨M08 U2b-1⟩ Test support (`tests/adversarial/store_generations.rs`): open the store at
    /// `path` with this build's migrations **and** `ahead` after them, as a build one or more
    /// schema versions newer would leave it (the "newer build" of
    /// `older_build_on_newer_store_refuses_and_touches_nothing`). Never used by production
    /// code.
    #[doc(hidden)]
    pub fn open_ahead_of_this_build(
        path: &Path,
        faults: Arc<dyn FaultHook>,
        ahead: &[migrations::Migration],
    ) -> Result<Self> {
        let mut steps = migrations::MIGRATIONS.to_vec();
        steps.extend_from_slice(ahead);
        Self::open_with_steps(path, faults, &steps, true)
    }

    pub(crate) fn open_with_steps(
        path: &Path,
        faults: Arc<dyn FaultHook>,
        steps: &[migrations::Migration],
        verify_tables: bool,
    ) -> Result<Self> {
        Self::open_family(path, faults, steps, verify_tables, true).map(|(store, _)| store)
    }

    /// ⟨M08 U2b-1⟩ The store of a generation ([`layout::open_locked`]): an existing database,
    /// never created (a missing file is an error, not a new store), migrated in place with
    /// its backup as [`Store::open`] does. Returns the schema version found before any
    /// migration, for the generation's migration notes.
    pub(crate) fn open_generation(path: &Path, faults: Arc<dyn FaultHook>) -> Result<(Self, u32)> {
        Self::open_family(path, faults, migrations::MIGRATIONS, true, false)
    }

    fn open_family(
        path: &Path,
        faults: Arc<dyn FaultHook>,
        steps: &[migrations::Migration],
        verify_tables: bool,
        create: bool,
    ) -> Result<(Self, u32)> {
        let mut flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if create {
            create_owner_only(path)?;
            flags |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut conn =
            rusqlite::Connection::open_with_flags(path, flags).map_err(codec::classify)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(codec::classify)?;
        // Read-only checks first: nothing is written to a newer, foreign or damaged
        // file.
        let current = migrations::check_version(&conn, steps)?;
        integrity_check(&conn)?;
        configure(&conn, true)?;
        if current > 0 && current < migrations::target_version(steps) {
            backup(&conn, path, current)?;
        }
        migrations::apply_steps(&mut conn, faults.as_ref(), steps)?;
        if verify_tables {
            verify_schema(&conn)?;
        }
        Ok((
            Self {
                conn: std::sync::Mutex::new(conn),
                faults,
                read_only: false,
            },
            current,
        ))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        // A panic inside `transaction` drops the open `rusqlite::Transaction`, which
        // rolls back; the connection is consistent, so poisoning carries no state.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run `f` inside one transaction. Fault points fire before the transaction,
    /// before commit and after commit.
    pub fn transaction<R>(&self, f: impl FnOnce(&mut Txn<'_>) -> Result<R>) -> Result<R> {
        fire(self.faults.as_ref(), FaultPoint::BeforeTransaction)?;
        let mut conn = self.lock();
        // `BEGIN IMMEDIATE` takes the write lock at once, so a read and the insert
        // it decides (for example `Txn::insert_setup_operation`) can never
        // interleave with another connection's. A read-only store cannot take that
        // lock and reads in a deferred transaction.
        let behavior = if self.read_only {
            rusqlite::TransactionBehavior::Deferred
        } else {
            rusqlite::TransactionBehavior::Immediate
        };
        let tx = conn
            .transaction_with_behavior(behavior)
            .map_err(codec::classify)?;
        let mut txn = Txn { tx };
        let out = f(&mut txn).map_err(codec::reclassify)?;
        // Dropping `txn` on any early return rolls back.
        fire(self.faults.as_ref(), FaultPoint::BeforeCommit)?;
        txn.tx.commit().map_err(codec::classify)?;
        fire(self.faults.as_ref(), FaultPoint::AfterCommit)?;
        Ok(out)
    }

    /// Schema version on disk.
    pub fn schema_version(&self) -> Result<u32> {
        migrations::user_version(&self.lock())
    }
}

/// Create a missing database file with owner-only permissions before SQLite opens
/// it (WAL and SHM files inherit the database file's mode). Existing files are left
/// untouched.
fn create_owner_only(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(
            Box::new(std::io::Error::new(
                e.kind(),
                "cannot create state database file",
            )),
        ))),
    }
}

/// Durability and safety pragmas.
fn configure(conn: &rusqlite::Connection, file_backed: bool) -> Result<()> {
    if file_backed {
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .map_err(codec::classify)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Corrupt(
                "state database refused write-ahead logging".into(),
            ));
        }
    }
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(codec::classify)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(codec::classify)?;
    conn.pragma_update(None, "trusted_schema", "OFF")
        .map_err(codec::classify)?;
    Ok(())
}

/// `PRAGMA integrity_check` and `PRAGMA foreign_key_check`; any finding is
/// [`StoreError::Corrupt`] (the finding text names pages and tables, never values).
fn integrity_check(conn: &rusqlite::Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA integrity_check")
        .map_err(codec::classify)?;
    let findings: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(codec::classify)?
        .collect::<std::result::Result<_, _>>()
        .map_err(codec::classify)?;
    if findings.len() != 1 || findings[0] != "ok" {
        return Err(StoreError::Corrupt(format!(
            "integrity_check reported {} finding(s)",
            findings.len()
        )));
    }
    let fk_violation = conn
        .prepare("PRAGMA foreign_key_check")
        .and_then(|mut s| s.exists([]))
        .map_err(codec::classify)?;
    if fk_violation {
        return Err(StoreError::Corrupt(
            "foreign_key_check reported violations".into(),
        ));
    }
    Ok(())
}

/// Every table of the current schema exists.
fn verify_schema(conn: &rusqlite::Connection) -> Result<()> {
    use rusqlite::OptionalExtension as _;
    for table in REQUIRED_TABLES {
        let present: bool = conn
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |r| r.get(0),
            )
            .map_err(codec::classify)?;
        if !present {
            return Err(StoreError::Corrupt(format!(
                "required table {table} is missing"
            )));
        }
    }
    // ⟨rev7; review U0-R06⟩ A lost restore epoch must not read as epoch 0.
    let epoch: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_RESTORE_EPOCH],
            |r| r.get(0),
        )
        .optional()
        .map_err(codec::classify)?;
    if epoch.as_deref().and_then(parse_restore_epoch).is_none() {
        return Err(StoreError::Corrupt(
            "the restore epoch is missing or malformed".to_owned(),
        ));
    }
    for (table, column) in REQUIRED_COLUMNS {
        let present: bool = conn
            .query_row(
                "SELECT count(*) > 0 FROM pragma_table_xinfo(?1) WHERE name = ?2",
                [table, column],
                |r| r.get(0),
            )
            .map_err(codec::classify)?;
        if !present {
            return Err(StoreError::Corrupt(format!(
                "required column {table}.{column} is missing"
            )));
        }
    }
    Ok(())
}

/// Consistent copy of the database (`VACUUM INTO`) next to it, named
/// `<file>.v<version>.backup[.<n>]`, owner-only, never overwriting an older backup.
fn backup(
    conn: &rusqlite::Connection,
    path: &Path,
    from_version: u32,
) -> Result<std::path::PathBuf> {
    let io_err = |msg: &'static str| {
        StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(msg),
        )))
    };
    let base = path.as_os_str().to_owned();
    for n in 0u32..1000 {
        let mut name = base.clone();
        name.push(format!(".v{from_version}.backup"));
        if n > 0 {
            name.push(format!(".{n}"));
        }
        let target = std::path::PathBuf::from(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&target) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(io_err("cannot create migration backup file")),
        }
        let Some(target_str) = target.to_str() else {
            let _ = std::fs::remove_file(&target);
            return Err(io_err("backup path is not valid UTF-8"));
        };
        if let Err(e) = conn.execute("VACUUM INTO ?1", [target_str]) {
            let _ = std::fs::remove_file(&target);
            return Err(codec::classify(e));
        }
        tracing::info!(from_version, "state store backed up before migration");
        return Ok(target);
    }
    Err(io_err("too many migration backups present"))
}

/// Every operation state; the store derives its state sets from the contract's
/// predicates (`is_settled`, `is_quiescent`, `is_unresolved`) over this list.
const ALL_OPERATION_STATES: &[OperationState] = &[
    OperationState::Queued,
    OperationState::Running,
    OperationState::AwaitingApproval,
    OperationState::Succeeded,
    OperationState::Failed,
    OperationState::Cancelled,
    OperationState::OutcomeUnknown,
];

/// States matching `pred`, in [`ALL_OPERATION_STATES`] order. Settled states
/// (`OperationState::is_settled`) are the only ones retention may purge and whose
/// idempotency record may get an expiry; `outcome_unknown` is quiescent but
/// unresolved and stays, with its evidence, until reconciled.
pub(crate) fn operation_states(pred: fn(OperationState) -> bool) -> Vec<OperationState> {
    ALL_OPERATION_STATES
        .iter()
        .copied()
        .filter(|s| pred(*s))
        .collect()
}

fn sql_in_list<T: serde::Serialize>(values: &[T]) -> Result<String> {
    let mut out = String::new();
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Enum names are `[a-z_A-Z]` only, so quoting is safe.
        let s = codec::enum_str(v)?;
        if !s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_') {
            return Err(codec::doc_error("unexpected enum name"));
        }
        out.push('\'');
        out.push_str(&s);
        out.push('\'');
    }
    Ok(out)
}

fn caller_doc(key: &IdempotencyKey) -> Result<String> {
    codec::doc(&key.caller)
}

/// Test support: which raw JSON documents [`Txn::raw_documents`] returns.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawDocuments {
    /// `stage_receipts.record_json`, keyed `<operation id>:<ordinal>`.
    StageReceipts,
    /// `recovery_intents.record_json`, keyed by operation ID.
    RecoveryIntents,
    /// `meta.value`, keyed by meta key.
    Meta,
    /// ⟨M03⟩ `issuance_log.record_json`, keyed by issuance ID.
    IssuanceLog,
    /// ⟨M03⟩ `credential_instances.record_json`, keyed by instance ID.
    CredentialInstances,
    /// ⟨M03⟩ `destinations.record_json`, keyed by destination ID.
    Destinations,
    /// ⟨M03⟩ `identities.record_json`, keyed by identity ID.
    Identities,
    /// ⟨M03⟩ `interaction_declarations.record_json`, keyed by identity ID.
    InteractionDeclarations,
    /// ⟨M03⟩ `projection_records.record_json`, keyed by environment ID.
    ProjectionRecords,
    /// ⟨M03⟩ `projection_consent.record_json`, keyed `<environment>:<item>`.
    ProjectionConsent,
    /// ⟨M03⟩ `resources.record_json`, keyed by resource ID.
    Resources,
    /// ⟨M03; ADR-0008 §17.30 item 4⟩ every `enrollments` column (`state`,
    /// `removal_origin_set` and `record_json`, joined by `|`), keyed by enrollment ID.
    Enrollments,
    /// ⟨M03; ADR-0008 §17.30 item 4⟩ `events.record_json`, keyed by sequence number.
    Events,
}

impl Txn<'_> {
    /// Test support (migration coverage): the stored JSON text of a fixed set of
    /// columns, exactly as on disk, in key order. Never used by production code.
    #[doc(hidden)]
    pub fn raw_documents(&mut self, which: RawDocuments) -> Result<Vec<(String, String)>> {
        let sql = match which {
            RawDocuments::StageReceipts => {
                "SELECT operation_id || ':' || ordinal, record_json FROM stage_receipts
                 ORDER BY operation_id, ordinal"
            }
            RawDocuments::RecoveryIntents => {
                "SELECT operation_id, record_json FROM recovery_intents ORDER BY operation_id"
            }
            RawDocuments::Meta => "SELECT key, value FROM meta ORDER BY key",
            RawDocuments::IssuanceLog => "SELECT id, record_json FROM issuance_log ORDER BY id",
            RawDocuments::CredentialInstances => {
                "SELECT id, record_json FROM credential_instances ORDER BY id"
            }
            RawDocuments::Destinations => "SELECT id, record_json FROM destinations ORDER BY id",
            RawDocuments::Identities => "SELECT id, record_json FROM identities ORDER BY id",
            RawDocuments::InteractionDeclarations => {
                "SELECT identity, record_json FROM interaction_declarations ORDER BY identity"
            }
            RawDocuments::ProjectionRecords => {
                "SELECT environment, record_json FROM projection_records ORDER BY environment"
            }
            RawDocuments::ProjectionConsent => {
                "SELECT environment || ':' || item, record_json FROM projection_consent
                 ORDER BY environment, item"
            }
            RawDocuments::Resources => "SELECT id, record_json FROM resources ORDER BY id",
            RawDocuments::Enrollments => {
                "SELECT id, destination_id || '|' || account || '|' || ca_fingerprint || '|' ||
                        form || '|' || marker || '|' || state || '|' ||
                        coalesce(verified_at, '') || '|' || removal_origin_set || '|' ||
                        record_json
                 FROM enrollments ORDER BY id"
            }
            RawDocuments::Events => {
                "SELECT CAST(seq AS TEXT), record_json FROM events ORDER BY seq"
            }
        };
        let mut stmt = self.tx.prepare(sql)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub(crate) fn meta(&self, key: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension as _;
        Ok(self
            .tx
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub(crate) fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    pub(crate) fn delete_meta(&self, key: &str) -> Result<()> {
        self.tx.execute("DELETE FROM meta WHERE key = ?1", [key])?;
        Ok(())
    }

    /// Values of every meta row whose key starts with `prefix`, in key order.
    pub(crate) fn meta_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut stmt = self.tx.prepare_cached(
            "SELECT value FROM meta WHERE substr(key, 1, length(?1)) = ?1 ORDER BY key",
        )?;
        let rows = stmt.query_map([prefix], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn docs<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<T>> {
        let mut stmt = self.tx.prepare_cached(sql)?;
        let rows = stmt.query_map(params, |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(codec::parse_doc(&row?)?);
        }
        Ok(out)
    }

    fn one_doc<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<T>> {
        use rusqlite::OptionalExtension as _;
        let s: Option<String> = self.tx.query_row(sql, params, |r| r.get(0)).optional()?;
        s.as_deref().map(codec::parse_doc).transpose()
    }

    // --- operations and idempotency (spec §11.4) ---------------------------------

    /// Insert a new operation and its idempotency record atomically.
    ///
    /// Both rows are written in this transaction, before any external step
    /// (ADR-0006 §7.3). A second record for the same key is refused by the primary
    /// key; callers classify with [`Txn::idempotency_record`] first.
    pub fn insert_operation(
        &mut self,
        op: &OperationRecord,
        idem: &IdempotencyRecord,
    ) -> Result<()> {
        if idem.operation_id != op.id || idem.key != op.key || idem.request_hash != op.request_hash
        {
            return Err(codec::doc_error(
                "idempotency record does not describe the operation",
            ));
        }
        let record = codec::doc(op)?;
        let result = op.result.as_ref().map(codec::doc).transpose()?;
        let code = op.code.as_ref().map(codec::enum_str).transpose()?;
        let terminal_at = op.state.is_settled().then(|| codec::ts(op.updated_at));
        self.tx.execute(
            "INSERT INTO operations (id, kind, environment, caller_json, request_id,
                 request_hash, effect_class, state, code, effect_status, result_json,
                 record_json, created_at, updated_at, terminal_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                op.id.as_str(),
                op.kind.as_str(),
                op.environment.as_str(),
                caller_doc(&op.key)?,
                op.key.request_id.as_str(),
                op.request_hash.to_hex(),
                codec::enum_str(&op.effect_class)?,
                codec::enum_str(&op.state)?,
                code,
                codec::enum_str(&op.effect_status)?,
                result,
                record,
                codec::ts(op.created_at),
                codec::ts(op.updated_at),
                terminal_at,
            ],
        )?;
        self.tx.execute(
            "INSERT INTO idempotency (caller_json, kind, request_id, request_hash,
                 operation_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                caller_doc(&idem.key)?,
                idem.key.kind.as_str(),
                idem.key.request_id.as_str(),
                idem.request_hash.to_hex(),
                idem.operation_id.as_str(),
                codec::ts(idem.created_at),
                // NULL while the operation is pending (never expires); set at
                // settlement by `settle_idempotency` (migration 0002 relaxes NOT NULL).
                idem.expires_at.map(codec::ts),
            ],
        )?;
        // ⟨M08 U2b-2; ADR-0014 §3.6 steps 2 and 3⟩ The operation ID is minted under the
        // current epoch, and the request was bound to it (a request bound to another epoch is
        // refused before the store is written). Both columns default to 0.
        if let Some(epoch) = self.minted_epoch()? {
            self.tx.execute(
                "UPDATE operations SET restore_epoch = ?2 WHERE id = ?1",
                rusqlite::params![op.id.as_str(), epoch],
            )?;
            self.tx.execute(
                "UPDATE idempotency SET request_epoch = ?4
                 WHERE caller_json = ?1 AND kind = ?2 AND request_id = ?3",
                rusqlite::params![
                    caller_doc(&idem.key)?,
                    idem.key.kind.as_str(),
                    idem.key.request_id.as_str(),
                    epoch
                ],
            )?;
        }
        Ok(())
    }

    /// Look up an idempotency record by key.
    pub fn idempotency_record(
        &mut self,
        key: &IdempotencyKey,
    ) -> Result<Option<IdempotencyRecord>> {
        use rusqlite::OptionalExtension as _;
        let row: Option<(String, String, String, Option<String>)> = self
            .tx
            .query_row(
                "SELECT request_hash, operation_id, created_at, expires_at FROM idempotency
                 WHERE caller_json = ?1 AND kind = ?2 AND request_id = ?3",
                rusqlite::params![caller_doc(key)?, key.kind.as_str(), key.request_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((hash, op, created, expires)) = row else {
            return Ok(None);
        };
        Ok(Some(IdempotencyRecord {
            key: key.clone(),
            request_hash: heimdall_contract::canonical::RequestHash::from_hex(&hash)
                .map_err(|_| codec::doc_error("stored request hash is malformed"))?,
            operation_id: OperationId::parse(&op)
                .map_err(|_| codec::doc_error("stored operation id is malformed"))?,
            created_at: codec::parse_ts(&created)?,
            expires_at: expires.as_deref().map(codec::parse_ts).transpose()?,
        }))
    }

    /// Load an operation.
    pub fn operation(&mut self, id: &OperationId) -> Result<Option<OperationRecord>> {
        self.one_doc(
            "SELECT record_json FROM operations WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Persist a state change; the caller has already validated the transition.
    ///
    /// Identity columns (kind, environment, idempotency key, request hash, effect
    /// class, creation time) are immutable: a record that changes them is refused
    /// with [`StoreError::GenerationConflict`], as is any state change out of a
    /// resolved terminal state (`succeeded`, `failed`, `cancelled`). A missing
    /// operation is `Sqlite(QueryReturnedNoRows)`.
    pub fn update_operation(&mut self, op: &OperationRecord) -> Result<()> {
        let Some(old) = self.operation(&op.id)? else {
            return Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        };
        if old.kind != op.kind
            || old.environment != op.environment
            || old.key != op.key
            || old.request_hash != op.request_hash
            || old.effect_class != op.effect_class
            || old.created_at != op.created_at
        {
            return Err(StoreError::GenerationConflict(format!(
                "operation {} identity is immutable",
                op.id
            )));
        }
        if old.state.is_settled() && old.state != op.state {
            return Err(StoreError::GenerationConflict(format!(
                "operation {} is already terminal",
                op.id
            )));
        }
        let record = codec::doc(op)?;
        let result = op.result.as_ref().map(codec::doc).transpose()?;
        let code = op.code.as_ref().map(codec::enum_str).transpose()?;
        let terminal_at = op.state.is_settled().then(|| codec::ts(op.updated_at));
        self.tx.execute(
            "UPDATE operations SET state = ?2, code = ?3, effect_status = ?4,
                 result_json = ?5, record_json = ?6, updated_at = ?7,
                 terminal_at = COALESCE(terminal_at, ?8)
             WHERE id = ?1",
            rusqlite::params![
                op.id.as_str(),
                codec::enum_str(&op.state)?,
                code,
                codec::enum_str(&op.effect_status)?,
                result,
                record,
                codec::ts(op.updated_at),
                terminal_at,
            ],
        )?;
        Ok(())
    }

    /// Operations that are not quiescent (`!OperationState::is_quiescent`: queued,
    /// running, awaiting approval), oldest first, for restart recovery (spec
    /// §13.3). `outcome_unknown` operations are quiescent and listed by
    /// [`Txn::unresolved_operations`] instead.
    pub fn open_operations(&mut self) -> Result<Vec<OperationRecord>> {
        let sql = format!(
            "SELECT record_json FROM operations WHERE state IN ({}) ORDER BY created_at, id",
            sql_in_list(&operation_states(|s| !s.is_quiescent()))?
        );
        self.docs(&sql, [])
    }

    /// Purge settled operations whose idempotency record expired at or before
    /// `now` (retention contract, ADR-0006 §7.4; review F02, F07).
    ///
    /// Only `succeeded`, `failed` and `cancelled` operations whose record has an
    /// `expires_at` (set by [`Txn::settle_idempotency`]) at or before `now` go.
    /// Each purged key leaves an [`heimdall_domain::idempotency::ExpiredKeyMarker`]
    /// until `marker_until(expires_at)`, so a reuse stays `REQUEST_EXPIRED`. Pending
    /// keys (no expiry), open and `outcome_unknown` operations are never purged.
    /// The idempotency row, recovery intent and stage receipts go with their
    /// settled operation (`ON DELETE CASCADE`); tombstones, policies, decisions,
    /// issuance entries, grant anchors and meta are never touched. Returns the
    /// operations removed.
    pub fn purge_operations_before(&mut self, now: Timestamp) -> Result<u64> {
        let sql = format!(
            "SELECT o.id, o.record_json, i.expires_at
             FROM operations o JOIN idempotency i ON i.operation_id = o.id
             WHERE o.state IN ({}) AND i.expires_at IS NOT NULL AND i.expires_at <= ?1
             ORDER BY o.id",
            sql_in_list(&operation_states(OperationState::is_settled))?
        );
        let due: Vec<(String, String, String)> = {
            let mut stmt = self.tx.prepare(&sql)?;
            let rows =
                stmt.query_map([codec::ts(now)], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut removed = 0u64;
        for (id, record, expires) in due {
            let op: OperationRecord = codec::parse_doc(&record)?;
            let expired_at = codec::parse_ts(&expires)?;
            let key_hash = op
                .key
                .hash()
                .map_err(|_| codec::doc_error("idempotency key cannot be hashed"))?;
            let until = heimdall_domain::idempotency::marker_until(expired_at);
            // A key purged again later (after an earlier marker aged out and the
            // key was reused) keeps the later expiry and window; never shortened.
            self.tx.execute(
                "INSERT INTO idempotency_markers (key_hash, expired_at, marker_until)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key_hash) DO UPDATE SET
                     expired_at = max(expired_at, excluded.expired_at),
                     marker_until = max(marker_until, excluded.marker_until)",
                rusqlite::params![key_hash.0.to_hex(), codec::ts(expired_at), codec::ts(until)],
            )?;
            let n = self
                .tx
                .execute("DELETE FROM operations WHERE id = ?1", [id.as_str()])?;
            removed += n as u64;
        }
        Ok(removed)
    }

    // --- grants, references, tombstones, generation (spec §6.3, §6.7) -----------

    /// Insert a grant snapshot.
    pub fn insert_grant(&mut self, grant: &GrantSnapshot) -> Result<()> {
        if grant.parent.as_ref() == Some(&grant.id) {
            return Err(codec::doc_error("a grant cannot be its own parent"));
        }
        self.tx.execute(
            "INSERT INTO grants (id, environment, parent, state, starts_at,
                 deadline_effective, deadline_json, scope_json, generation, record_json,
                 updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?5)",
            rusqlite::params![
                grant.id.as_str(),
                grant.environment.as_str(),
                grant.parent.as_ref().map(GrantId::as_str),
                codec::enum_str(&grant.state)?,
                codec::ts(grant.starts_at),
                codec::ts(grant.deadline.effective),
                codec::doc(&grant.deadline)?,
                codec::doc(&grant.scope)?,
                codec::int(grant.generation.0)?,
                codec::doc(grant)?,
            ],
        )?;
        Ok(())
    }

    /// Load a grant.
    pub fn grant(&mut self, id: &GrantId) -> Result<Option<GrantSnapshot>> {
        self.one_doc(
            "SELECT record_json FROM grants WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Update a grant's state and enforcement; scope and deadline columns are
    /// immutable and the statement must not touch them.
    ///
    /// Only `state` and `enforcement` are taken from `grant`; every other field
    /// (scope, deadline, start, parent, source, generation, environment) keeps its
    /// stored value even if the caller's copy differs. Terminal grant states are
    /// absorbing: changing one is [`StoreError::GenerationConflict`]. The
    /// `updated_at` column is not maintained (the store reads no clock).
    ///
    /// ⟨r2.7⟩ A degradation reason ([`Txn::set_grant_degradation`]) exists only
    /// while the grant is `degraded`: any other state written here removes it in the
    /// same transaction (ADR-0006 §13.10 item 2).
    pub fn update_grant_state(&mut self, grant: &GrantSnapshot) -> Result<()> {
        let Some(mut stored) = self.grant(&grant.id)? else {
            return Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        };
        if stored.state.is_terminal() && stored.state != grant.state {
            return Err(StoreError::GenerationConflict(format!(
                "grant {} is already terminal",
                grant.id
            )));
        }
        stored.state = grant.state;
        stored.enforcement = grant.enforcement.clone();
        self.tx.execute(
            "UPDATE grants SET state = ?2, record_json = ?3 WHERE id = ?1",
            rusqlite::params![
                grant.id.as_str(),
                codec::enum_str(&stored.state)?,
                codec::doc(&stored)?,
            ],
        )?;
        if stored.state != heimdall_contract::GrantState::Degraded {
            self.delete_meta(&ext::grant_degradation_key(&grant.id))?;
        }
        Ok(())
    }

    /// Nonterminal grants in deadline and ID order, regardless of deadline passage.
    /// This includes pending grants and grants in the process of revocation.
    pub fn live_grants(&mut self) -> Result<Vec<GrantSnapshot>> {
        self.docs(LIVE_GRANTS_SQL, [])
    }

    /// Nonterminal grants whose deadline is at or before `now`, in deadline and ID order.
    pub fn grants_due(&mut self, now: Timestamp) -> Result<Vec<GrantSnapshot>> {
        self.docs(GRANTS_DUE_SQL, [codec::ts(now)])
    }

    /// Descendants of a grant (transitive children).
    pub fn grant_descendants(&mut self, id: &GrantId) -> Result<Vec<GrantId>> {
        let mut stmt = self.tx.prepare_cached(
            "WITH RECURSIVE d(id) AS (
                 SELECT id FROM grants WHERE parent = ?1
                 UNION
                 SELECT g.id FROM grants g JOIN d ON g.parent = d.id
             )
             SELECT id FROM d WHERE id <> ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([id.as_str()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                GrantId::parse(&row?)
                    .map_err(|_| codec::doc_error("stored grant id is malformed"))?,
            );
        }
        Ok(out)
    }

    /// Add a consumer reference. Adding the same `(binding, grant)` twice is a
    /// no-op (references are ownership-aware, not counters).
    pub fn add_grant_reference(&mut self, reference: &GrantReference) -> Result<()> {
        self.tx.execute(
            "INSERT INTO grant_references (binding, grant_id, acquired_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(binding, grant_id) DO NOTHING",
            rusqlite::params![
                reference.binding.as_str(),
                reference.grant.as_str(),
                codec::ts(reference.acquired_at),
            ],
        )?;
        Ok(())
    }

    /// Drop a consumer reference; returns remaining references for the grant.
    pub fn remove_grant_reference(&mut self, reference: &GrantReference) -> Result<u64> {
        self.tx.execute(
            "DELETE FROM grant_references WHERE binding = ?1 AND grant_id = ?2",
            [reference.binding.as_str(), reference.grant.as_str()],
        )?;
        let n: i64 = self.tx.query_row(
            "SELECT count(*) FROM grant_references WHERE grant_id = ?1",
            [reference.grant.as_str()],
            |r| r.get(0),
        )?;
        codec::uint(n)
    }

    /// Persist a tombstone and bump the authority generation in the same transaction.
    ///
    /// The returned generation is authoritative and is what the stored tombstone
    /// records (the caller's `generation` field is overwritten). A second tombstone
    /// for the same grant keeps the first (evidence is never rewritten) but still
    /// bumps the generation.
    pub fn insert_tombstone(&mut self, tombstone: &Tombstone) -> Result<AuthorityGeneration> {
        let next = self.authority_generation()?.next();
        self.set_meta(META_AUTHORITY_GENERATION, &next.0.to_string())?;
        let mut stored = tombstone.clone();
        stored.generation = next;
        self.tx.execute(
            "INSERT INTO tombstones (grant_id, generation, revoked_at, record_json)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(grant_id) DO NOTHING",
            rusqlite::params![
                stored.grant.as_str(),
                codec::int(next.0)?,
                codec::ts(stored.revoked_at),
                codec::doc(&stored)?,
            ],
        )?;
        Ok(next)
    }

    /// Current authority generation.
    pub fn authority_generation(&mut self) -> Result<AuthorityGeneration> {
        match self.meta(META_AUTHORITY_GENERATION)? {
            None => Ok(AuthorityGeneration(0)),
            Some(s) => s
                .parse()
                .map(AuthorityGeneration)
                .map_err(|_| StoreError::Corrupt("authority generation is malformed".into())),
        }
    }

    /// Move the authority generation up by one, in the caller's transaction (every write
    /// that widens or narrows authority does, ADR-0006 §13.7 item 5).
    pub(crate) fn bump_generation(&mut self) -> Result<()> {
        let next = self.authority_generation()?.next();
        self.set_meta(META_AUTHORITY_GENERATION, &next.0.to_string())
    }

    // --- policies, profiles, environments ------------------------------------------

    /// Upsert a standing policy at a new revision and bump the authority
    /// generation in the same transaction.
    ///
    /// The revision must be strictly greater than the stored one, otherwise
    /// [`StoreError::GenerationConflict`] (a stale writer never overwrites a newer
    /// policy). **Every** accepted write moves the generation (ADR-0006 §13.6 item
    /// 5): a new applicable policy, a pause, a cutoff, a narrowing, a widening and
    /// any other revision, so re-validation (§13.5 ruling 2) runs and a
    /// reservation made before the change is voided at publish. `narrowing` is the
    /// caller's classification of the change (`_narrowing`); it no longer selects
    /// whether the generation moves (kept so the signature is unchanged).
    pub fn upsert_policy(
        &mut self,
        policy: &StandingPolicy,
        _narrowing: bool,
    ) -> Result<AuthorityGeneration> {
        let existing = self.policy(&policy.id)?;
        if let Some(old) = &existing
            && old.revision >= policy.revision
        {
            return Err(StoreError::GenerationConflict(format!(
                "policy {} revision {} is not newer than stored {}",
                policy.id, policy.revision.0, old.revision.0
            )));
        }
        let updated_at = match &policy.source {
            heimdall_domain::policy::PolicySource::OwnerDecision { decided_at } => {
                codec::ts(*decided_at)
            }
            heimdall_domain::policy::PolicySource::SetupDefault => String::new(),
        };
        self.tx.execute(
            "INSERT INTO policies (id, revision, record_json, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET revision = excluded.revision,
                 record_json = excluded.record_json, updated_at = excluded.updated_at",
            rusqlite::params![
                policy.id.as_str(),
                codec::int(policy.revision.0)?,
                codec::doc(policy)?,
                updated_at,
            ],
        )?;
        let next = self.authority_generation()?.next();
        self.set_meta(META_AUTHORITY_GENERATION, &next.0.to_string())?;
        Ok(next)
    }

    /// Load a policy.
    pub fn policy(&mut self, id: &PolicyId) -> Result<Option<StandingPolicy>> {
        self.one_doc(
            "SELECT record_json FROM policies WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// This runtime's own environment ID (created at first start, never reset by
    /// recovery; R-RT-07).
    pub fn self_environment(&mut self) -> Result<Option<EnvironmentId>> {
        self.meta(META_SELF_ENVIRONMENT)?
            .map(|s| {
                EnvironmentId::parse(&s)
                    .map_err(|_| StoreError::Corrupt("self environment id is malformed".into()))
            })
            .transpose()
    }

    /// Record this runtime's environment ID once.
    ///
    /// Recording the same ID again is a no-op; a different ID is refused with
    /// [`StoreError::GenerationConflict`] (identity never changes, R-RT-07).
    pub fn init_self_environment(&mut self, id: &EnvironmentId) -> Result<()> {
        match self.self_environment()? {
            Some(existing) if existing == *id => Ok(()),
            Some(_) => Err(StoreError::GenerationConflict(
                "self environment is already initialized".into(),
            )),
            None => {
                self.tx.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                    [META_SELF_ENVIRONMENT, id.as_str()],
                )?;
                Ok(())
            }
        }
    }

    /// ⟨M03⟩ ADR-0008 D10 item 1, §17.21 item 8: this installation's stable Windows
    /// environment pipe token (`meta: windows_environment_pipe_token`), created once
    /// and reused by every runtime start, so P keeps naming the live pipe. `None`
    /// before the first managed start. A stored value that is not 1 to 64 ASCII
    /// letters or digits is [`StoreError::Corrupt`] (never a pipe name).
    pub fn windows_pipe_token(&mut self) -> Result<Option<String>> {
        match self.meta(META_WINDOWS_PIPE_TOKEN)? {
            Some(t) if pipe_token_valid(&t) => Ok(Some(t)),
            Some(_) => Err(StoreError::Corrupt(
                "windows environment pipe token is malformed".into(),
            )),
            None => Ok(None),
        }
    }

    /// ⟨M03⟩ Record the installation's Windows pipe token once (§17.21 item 8).
    /// Recording the same token again is a no-op; a different one is refused with
    /// [`StoreError::GenerationConflict`] (the token is stable: a new one would make
    /// P name a pipe nobody serves). A token that is not 1 to 64 ASCII letters or
    /// digits is refused as malformed.
    pub fn set_windows_pipe_token(&mut self, token: &str) -> Result<()> {
        if !pipe_token_valid(token) {
            return Err(codec::doc_error(
                "a windows pipe token is 1 to 64 ASCII letters or digits",
            ));
        }
        match self.windows_pipe_token()? {
            Some(existing) if existing == token => Ok(()),
            Some(_) => Err(StoreError::GenerationConflict(
                "the windows environment pipe token is already recorded".into(),
            )),
            None => self.set_meta(META_WINDOWS_PIPE_TOKEN, token),
        }
    }

    // --- managed resources (spec §13.5) ------------------------------------------------

    /// Upsert with compare-and-swap on generation.
    ///
    /// `expected = None` inserts and fails if the resource exists; `Some(g)`
    /// updates only when the stored generation equals `g` and the new generation is
    /// not lower than `g`. Any mismatch is [`StoreError::GenerationConflict`] and
    /// leaves the stored row unchanged.
    pub fn upsert_resource(
        &mut self,
        resource: &ManagedResource,
        expected: Option<ResourceGeneration>,
    ) -> Result<()> {
        let conflict = || StoreError::GenerationConflict(format!("resource {}", resource.id));
        let record = codec::doc(resource)?;
        let owner = codec::doc(&resource.owner)?;
        let kind = codec::enum_str(&resource.kind)?;
        let desired = codec::enum_str(&resource.desired)?;
        let observed = codec::enum_str(&resource.observed)?;
        let generation = codec::int(resource.generation.0)?;
        let updated_at = codec::ts(resource.updated_at);
        match expected {
            None => {
                let n = self.tx.execute(
                    "INSERT INTO resources (id, kind, owner_json, generation, desired, observed,
                         locator, record_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(id) DO NOTHING",
                    rusqlite::params![
                        resource.id.as_str(),
                        kind,
                        owner,
                        generation,
                        desired,
                        observed,
                        resource.locator,
                        record,
                        updated_at,
                    ],
                )?;
                if n == 0 {
                    return Err(conflict());
                }
            }
            Some(expected) => {
                if resource.generation < expected {
                    return Err(conflict());
                }
                let n = self.tx.execute(
                    "UPDATE resources SET kind = ?3, owner_json = ?4, generation = ?5,
                         desired = ?6, observed = ?7, locator = ?8, record_json = ?9,
                         updated_at = ?10
                     WHERE id = ?1 AND generation = ?2",
                    rusqlite::params![
                        resource.id.as_str(),
                        codec::int(expected.0)?,
                        kind,
                        owner,
                        generation,
                        desired,
                        observed,
                        resource.locator,
                        record,
                        updated_at,
                    ],
                )?;
                if n == 0 {
                    return Err(conflict());
                }
            }
        }
        Ok(())
    }

    /// Load a resource.
    pub fn resource(&mut self, id: &ResourceId) -> Result<Option<ManagedResource>> {
        self.one_doc(
            "SELECT record_json FROM resources WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Resources whose desired and observed states differ.
    pub fn resources_needing_reconcile(&mut self) -> Result<Vec<ManagedResource>> {
        self.docs(
            "SELECT record_json FROM resources WHERE desired <> observed ORDER BY id",
            [],
        )
    }

    // --- events (spec §11.5) -------------------------------------------------------------

    /// Append an event; assigns the next per-environment sequence and the event ID.
    ///
    /// The caller's `event_id` and `cursor` are ignored: the event ID is 16 random
    /// bytes from SQLite's PRNG (OS-seeded; uniqueness is enforced by the column),
    /// and the sequence comes from one store-wide `AUTOINCREMENT` counter, so it is
    /// strictly increasing within every environment and never reused after trims.
    /// The payload must already be redacted; key armor is refused.
    pub fn append_event(&mut self, event_without_cursor: &Event) -> Result<(EventId, u64)> {
        let bytes: Vec<u8> = self
            .tx
            .query_row("SELECT randomblob(16)", [], |r| r.get(0))?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| codec::doc_error("random event id has the wrong length"))?;
        let event_id = EventId::from_random_bytes(bytes);
        let mut stored = event_without_cursor.clone();
        stored.event_id = event_id.clone();
        stored.cursor = heimdall_contract::event::Cursor(String::new());
        self.tx.execute(
            "INSERT INTO events (event_id, environment, type, operation_id, timestamp, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                event_id.as_str(),
                stored.environment_id.as_str(),
                codec::enum_str(&stored.event_type)?,
                stored.operation_id.as_ref().map(OperationId::as_str),
                codec::ts(stored.timestamp),
                codec::doc(&stored)?,
            ],
        )?;
        let seq = codec::uint(self.tx.last_insert_rowid())?;
        Ok((event_id, seq))
    }

    pub(crate) fn event_tail(&self, environment: &EnvironmentId) -> Result<u64> {
        let key = format!("{META_EVENT_TAIL_PREFIX}{environment}");
        match self.meta(&key)? {
            None => Ok(0),
            Some(s) => s
                .parse()
                .map_err(|_| StoreError::Corrupt("event retention boundary is malformed".into())),
        }
    }

    /// Read events after `after_seq` (bounded by `limit`); the wave-1 form of
    /// [`Txn::stored_events_after`].
    ///
    /// Each returned event carries a store-level marker in `cursor` from which
    /// [`event_seq`] recovers its sequence; the application replaces it with a
    /// reader-scoped cursor. `head_seq`/`tail_seq` are unfiltered environment-wide
    /// values (see [`EventPage`]).
    pub fn events_after(
        &mut self,
        environment: &EnvironmentId,
        after_seq: u64,
        filter: &EventFilter,
        limit: u32,
    ) -> Result<EventPage> {
        let page = self.stored_events_after(environment, after_seq, filter, limit)?;
        Ok(EventPage {
            events: page
                .events
                .into_iter()
                .map(|stored| {
                    let mut event = stored.event;
                    event.cursor = heimdall_contract::event::Cursor(format!(
                        "{STORE_SEQ_PREFIX}{}",
                        stored.seq
                    ));
                    event
                })
                .collect(),
            head_seq: page.head_seq,
            tail_seq: page.tail_seq,
        })
    }

    /// Highest sequence of the environment's log, never below its retention tail.
    pub(crate) fn event_head(&self, environment: &EnvironmentId) -> Result<u64> {
        let tail_seq = self.event_tail(environment)?;
        let max_seq: Option<i64> = self.tx.query_row(
            "SELECT max(seq) FROM events WHERE environment = ?1",
            [environment.as_str()],
            |r| r.get(0),
        )?;
        Ok(max_seq
            .map(codec::uint)
            .transpose()?
            .unwrap_or(0)
            .max(tail_seq))
    }

    /// Trim the event log to retention; returns the new tail sequence.
    ///
    /// Removes a prefix of the environment's log: everything up to the newest
    /// event older than `keep_after`, and further oldest events until at most
    /// `max_rows` remain. The returned value is the retention boundary described on
    /// [`EventPage::tail_seq`]; it never decreases.
    pub fn trim_events(
        &mut self,
        environment: &EnvironmentId,
        keep_after: Timestamp,
        max_rows: u64,
    ) -> Result<u64> {
        let env = environment.as_str();
        let by_age: Option<i64> = self.tx.query_row(
            "SELECT max(seq) FROM events WHERE environment = ?1 AND timestamp < ?2",
            rusqlite::params![env, codec::ts(keep_after)],
            |r| r.get(0),
        )?;
        let total: i64 = self.tx.query_row(
            "SELECT count(*) FROM events WHERE environment = ?1",
            [env],
            |r| r.get(0),
        )?;
        let excess = codec::uint(total)?.saturating_sub(max_rows);
        let by_count: Option<i64> = if excess > 0 {
            Some(self.tx.query_row(
                "SELECT seq FROM events WHERE environment = ?1 ORDER BY seq LIMIT 1 OFFSET ?2",
                rusqlite::params![env, codec::int(excess - 1)?],
                |r| r.get(0),
            )?)
        } else {
            None
        };
        let old_tail = self.event_tail(environment)?;
        let Some(boundary) = by_age.max(by_count) else {
            return Ok(old_tail);
        };
        self.tx.execute(
            "DELETE FROM events WHERE environment = ?1 AND seq <= ?2",
            rusqlite::params![env, boundary],
        )?;
        let new_tail = old_tail.max(codec::uint(boundary)?);
        self.set_meta(
            &format!("{META_EVENT_TAIL_PREFIX}{environment}"),
            &new_tail.to_string(),
        )?;
        Ok(new_tail)
    }

    // --- time anchors (spec §6.4) ---------------------------------------------------------

    /// Alias of [`Txn::runtime_anchor`] (wave-1 name; same stored record).
    pub fn time_anchor(&mut self) -> Result<Option<TimeAnchor>> {
        self.runtime_anchor()
    }

    /// Alias of [`Txn::set_runtime_anchor`] (wave-1 name; same stored record).
    pub fn set_time_anchor(&mut self, anchor: &TimeAnchor) -> Result<()> {
        self.set_runtime_anchor(anchor)
    }

    /// Count of operations by state (status/inspect).
    pub fn operation_counts(&mut self) -> Result<Vec<(OperationState, u64)>> {
        let mut stmt = self.tx.prepare_cached(
            "SELECT state, count(*) FROM operations GROUP BY state ORDER BY state",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (state, n) = row?;
            out.push((codec::enum_parse(&state)?, codec::uint(n)?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod grant_live_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use migrations::Migration;

    const V1: &[Migration] = &[Migration {
        version: 1,
        name: "one",
        sql: "CREATE TABLE t (x INTEGER NOT NULL) STRICT;",
    }];
    const V2: &[Migration] = &[
        V1[0],
        Migration {
            version: 2,
            name: "two",
            sql: "ALTER TABLE t ADD COLUMN y INTEGER;",
        },
    ];
    const V2_BROKEN: &[Migration] = &[
        V1[0],
        Migration {
            version: 2,
            name: "broken",
            sql: "ALTER TABLE t ADD COLUMN y INTEGER; NOT SQL;",
        },
    ];

    /// Every `meta` row, as `(key, value)`.
    fn meta_rows(c: &rusqlite::Connection) -> Vec<(String, String)> {
        let mut st = c
            .prepare("SELECT key, value FROM meta ORDER BY key")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    fn backup_path(db: &Path, suffix: &str) -> std::path::PathBuf {
        let mut s = db.as_os_str().to_owned();
        s.push(suffix);
        std::path::PathBuf::from(s)
    }

    fn row_count(path: &Path) -> (u32, i64) {
        let c = rusqlite::Connection::open(path).unwrap();
        let v = migrations::user_version(&c).unwrap();
        let n = c
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        (v, n)
    }

    #[test]
    fn fresh_file_needs_no_backup_and_pending_step_is_backed_up_first() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        {
            let s = Store::open_with_steps(&db, Arc::new(NoFaults), V1, false).unwrap();
            s.lock()
                .execute("INSERT INTO t (x) VALUES (42)", [])
                .unwrap();
        }
        assert!(!backup_path(&db, ".v0.backup").exists());
        assert!(!backup_path(&db, ".v1.backup").exists());

        // A failing v2 step: backup written, store left at v1 with its data.
        assert!(Store::open_with_steps(&db, Arc::new(NoFaults), V2_BROKEN, false).is_err());
        let b0 = backup_path(&db, ".v1.backup");
        assert_eq!(row_count(&b0), (1, 1));
        assert_eq!(row_count(&db), (1, 1));

        // Retry with a good v2: a second backup, never overwriting the first.
        let s = Store::open_with_steps(&db, Arc::new(NoFaults), V2, false).unwrap();
        assert_eq!(s.schema_version().unwrap(), 2);
        drop(s);
        let b1 = backup_path(&db, ".v1.backup.1");
        assert_eq!(row_count(&b1), (1, 1));
        assert_eq!(row_count(&db), (2, 1));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for p in [&db, &b0, &b1] {
                let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
    }

    struct FailAt(FaultPoint);
    impl FaultHook for FailAt {
        fn at(&self, point: FaultPoint) -> FaultAction {
            if point == self.0 {
                FaultAction::Fail
            } else {
                FaultAction::Continue
            }
        }
    }

    #[test]
    fn migration_fault_points_fire_and_leave_consistent_versions() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let e = Store::open_with_steps(
            &db,
            Arc::new(FailAt(FaultPoint::BeforeMigration)),
            V1,
            false,
        )
        .unwrap_err();
        assert!(matches!(
            e,
            StoreError::InjectedFault(FaultPoint::BeforeMigration)
        ));
        let c = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(migrations::user_version(&c).unwrap(), 0);
        drop(c);
        let e =
            Store::open_with_steps(&db, Arc::new(FailAt(FaultPoint::AfterMigration)), V1, false)
                .unwrap_err();
        assert!(matches!(
            e,
            StoreError::InjectedFault(FaultPoint::AfterMigration)
        ));
        let c = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(migrations::user_version(&c).unwrap(), 1);
    }

    fn raw_counts(s: &Store) -> (i64, i64, Vec<(String, String)>) {
        let c = s.lock();
        let tomb: i64 = c
            .query_row("SELECT count(*) FROM tombstones", [], |r| r.get(0))
            .unwrap();
        let pol: i64 = c
            .query_row("SELECT count(*) FROM policies", [], |r| r.get(0))
            .unwrap();
        let mut stmt = c
            .prepare("SELECT key, value FROM meta ORDER BY key")
            .unwrap();
        let meta = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        (tomb, pol, meta)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 256,
            ..proptest::prelude::ProptestConfig::default()
        })]

        /// plan §6.3 #6 (retention part): for any purge instant, tombstones,
        /// policies and every meta key (self environment, authority generation,
        /// time anchor, event tails) survive; only operation rows can go.
        #[test]
        fn purge_never_touches_tombstones_policies_or_meta(
            purge_offset_s in -86_400i64 * 400..86_400 * 400,
            n_tombstones in 0u8..5,
        ) {
            use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource};
            let s = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
            let t0: Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
            let env = EnvironmentId::from_random_bytes([1; 16]);
            s.transaction(|tx| {
                tx.init_self_environment(&env)?;
                for b in 0..n_tombstones {
                    tx.insert_tombstone(&Tombstone {
                        grant: GrantId::from_random_bytes([b; 16]),
                        cascade: Vec::new(),
                        generation: AuthorityGeneration(0),
                        revoked_at: t0,
                        remote_pending: Vec::new(),
                        cause: heimdall_domain::revocation::RevocationCause::Revoke,
                    })?;
                }
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("personal").unwrap(),
                        revision: PolicyRevision(1),
                        profile: heimdall_contract::ids::ProfileId::parse("default").unwrap(),
                        workspace: None,
                        scope: heimdall_domain::scope::Scope::empty(),
                        environments: std::collections::BTreeSet::new(),
                        max_window: std::time::Duration::from_secs(3600),
                        pause: PauseState::Paused { since: t0 },
                        cutoff_at: Some(t0),
                        source: PolicySource::SetupDefault,
                        // M03 wave 0 (A1): fail closed until U0b
                        lock_behavior: Default::default(),
                        connection: Default::default(),
                        default: false,
                    },
                    true,
                )?;
                tx.set_time_anchor(&TimeAnchor {
                    boot_id: heimdall_domain::time::BootId("boot-a".into()),
                    continuous: std::time::Duration::ZERO,
                    wall: t0,
                })?;
                tx.raise_high_water_mark(t0)?;
                tx.append_event(&Event {
                    schema_version: heimdall_contract::SchemaVersion::current(),
                    event_id: EventId::from_random_bytes([0; 16]),
                    event_type: heimdall_contract::event::EventType::PolicyChanged,
                    environment_id: env.clone(),
                    operation_id: None,
                    resource: None,
                    timestamp: t0,
                    cursor: heimdall_contract::event::Cursor(String::new()),
                    payload: serde_json::Value::Null,
                })?;
                tx.trim_events(&env, t0, 0)?;
                Ok(())
            })
            .unwrap();
            let before = raw_counts(&s);
            let at = t0
                .checked_add(jiff::SignedDuration::from_secs(purge_offset_s))
                .unwrap();
            s.transaction(|tx| tx.purge_operations_before(at)).unwrap();
            proptest::prop_assert_eq!(raw_counts(&s), before);
        }
    }

    #[test]
    fn event_seq_marker_parses_only_store_markers() {
        let mut e = Event {
            schema_version: heimdall_contract::SchemaVersion::current(),
            event_id: EventId::from_random_bytes([1; 16]),
            event_type: heimdall_contract::event::EventType::Decision,
            environment_id: EnvironmentId::from_random_bytes([2; 16]),
            operation_id: None,
            resource: None,
            timestamp: "2026-10-01T00:00:00Z".parse().unwrap(),
            cursor: heimdall_contract::event::Cursor("store-seq:17".into()),
            payload: serde_json::Value::Null,
        };
        assert_eq!(event_seq(&e), Some(17));
        e.cursor = heimdall_contract::event::Cursor("AAEC".into());
        assert_eq!(event_seq(&e), None);
    }

    // --- migration 0001 -> 0002 on a populated v1 database ---------------------------

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn v1_op(n: u8, state: OperationState) -> (OperationRecord, IdempotencyRecord) {
        use heimdall_contract::canonical::RequestHash;
        use heimdall_domain::operation::{EffectClass, OperationKind, RecoveryMetadata};
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        let key = IdempotencyKey {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
                remote_client: None,
            },
            kind: OperationKind::Ensure,
            request_id: heimdall_contract::ids::RequestId::parse(&format!("req-{n}")).unwrap(),
        };
        let created = ts("2026-10-01T00:00:00Z");
        let op = OperationRecord {
            id: OperationId::from_random_bytes([n; 16]),
            kind: OperationKind::Ensure,
            environment: EnvironmentId::from_random_bytes([7; 16]),
            key: key.clone(),
            request_hash: RequestHash([n; 32]),
            effect_class: EffectClass::Local,
            state,
            code: None,
            effect_status: heimdall_contract::envelope::EffectStatus::None,
            result: None,
            created_at: created,
            updated_at: created,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        let idem = IdempotencyRecord {
            key,
            request_hash: op.request_hash,
            operation_id: op.id.clone(),
            created_at: created,
            // v1 required an expiry at insertion.
            expires_at: Some(ts("2026-10-08T00:00:00Z")),
        };
        (op, idem)
    }

    fn v1_grant() -> GrantSnapshot {
        use heimdall_domain::grant::AuthorizationSource;
        use heimdall_domain::policy::PolicyRevision;
        GrantSnapshot {
            id: GrantId::from_random_bytes([4; 16]),
            environment: EnvironmentId::from_random_bytes([7; 16]),
            scope: heimdall_domain::scope::Scope::empty(),
            starts_at: ts("2026-10-01T00:00:00Z"),
            deadline: heimdall_domain::time::Deadline {
                intent: heimdall_contract::request::DeadlineIntent::Duration("2h".into()),
                resolved_at: ts("2026-10-01T00:00:00Z"),
                effective: ts("2026-10-01T02:00:00Z"),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(0),
            state: heimdall_contract::GrantState::Active,
            enforcement: heimdall_domain::evidence::EnforcementEvidence::unknown(),
        }
    }

    /// A v1 database exactly as a v1 build leaves it: only migration 0001 applied,
    /// rows written through the v1 code paths plus raw rows for what v1 had no API
    /// for (a binding, the boot-less `time_anchor` meta document).
    fn populated_v1(db: &Path) -> Vec<(OperationRecord, IdempotencyRecord)> {
        let s = Store::open_with_steps(db, Arc::new(NoFaults), &migrations::MIGRATIONS[..1], false)
            .unwrap();
        assert_eq!(s.schema_version().unwrap(), 1);
        let ops = vec![
            v1_op(1, OperationState::Queued),
            v1_op(2, OperationState::Succeeded),
            v1_op(3, OperationState::OutcomeUnknown),
        ];
        let env = EnvironmentId::from_random_bytes([7; 16]);
        s.transaction(|tx| {
            tx.init_self_environment(&env)?;
            for (op, idem) in &ops {
                tx.insert_operation(op, idem)?;
            }
            tx.insert_grant(&v1_grant())?;
            tx.add_grant_reference(&GrantReference {
                binding: heimdall_contract::ids::BindingId::from_random_bytes([5; 16]),
                grant: v1_grant().id,
                acquired_at: ts("2026-10-01T00:00:00Z"),
            })?;
            tx.insert_tombstone(&Tombstone {
                grant: GrantId::from_random_bytes([6; 16]),
                cascade: Vec::new(),
                generation: AuthorityGeneration(0),
                revoked_at: ts("2026-10-01T00:00:00Z"),
                remote_pending: Vec::new(),
                cause: heimdall_domain::revocation::RevocationCause::Revoke,
            })?;
            for i in 0..3i64 {
                tx.append_event(&Event {
                    schema_version: heimdall_contract::SchemaVersion::current(),
                    event_id: EventId::from_random_bytes([0; 16]),
                    event_type: heimdall_contract::event::EventType::OperationStateChanged,
                    environment_id: env.clone(),
                    operation_id: None,
                    resource: None,
                    timestamp: ts("2026-10-01T00:00:00Z")
                        .checked_add(jiff::SignedDuration::from_secs(i * 60))
                        .unwrap(),
                    cursor: heimdall_contract::event::Cursor(String::new()),
                    payload: serde_json::Value::Null,
                })?;
            }
            tx.trim_events(&env, ts("2026-10-01T00:00:30Z"), 100)?;
            Ok(())
        })
        .unwrap();
        let c = s.lock();
        c.execute(
            "INSERT INTO meta (key, value) VALUES ('time_anchor', ?1)",
            [r#"{"wall":"2026-10-01T00:00:05Z","monotonic":{"secs":1,"nanos":0},"process_generation":7}"#],
        )
        .unwrap();
        c.execute(
            "INSERT INTO bindings (id, environment, grant_id, work_id, record_json, created_at,
                 released_at)
             VALUES ('binding_v1', ?1, ?2, 'w', '{}', '2026-10-01T00:00:00.000000000Z',
                 '2026-10-01T00:30:00.000000000Z')",
            [env.as_str(), v1_grant().id.as_str()],
        )
        .unwrap();
        ops
    }

    fn table_count(c: &rusqlite::Connection, table: &str) -> i64 {
        c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn migration_0002_preserves_a_populated_v1_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let ops = populated_v1(&db);
        let before: Vec<(String, i64)> = {
            let c = rusqlite::Connection::open(&db).unwrap();
            [
                "operations",
                "idempotency",
                "grants",
                "grant_references",
                "bindings",
                "tombstones",
                "events",
            ]
            .iter()
            .map(|t| ((*t).to_owned(), table_count(&c, t)))
            .collect()
        };
        assert!(
            before.iter().all(|(_, n)| *n > 0),
            "fixture populated every table"
        );

        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        // 0001 → … → 0005 in one open (0003: the approval basis column; 0004: the
        // grant origin column; 0005: the M02 tables, which add tables only).
        // M03 wave 0 (S): 0006 (the M03 tables) adds tables only as well.
        // ⟨M04/M05 wave 0⟩ 0007 and 0008 add tables, and 0008 one nullable column.
        // ⟨M06 wave 0⟩ 0009 adds tables only. ⟨M06 wave 2⟩ 0010 adds one table.
        // ⟨M06 wave 3⟩ 0011 adds one table and one defaulted column.
        // ⟨M06 wave 4⟩ 0012 adds one table.
        // ⟨M06 wave 5⟩ 0013 rebuilds `remote_widening` with its origin (rows kept).
        // ⟨rev7⟩ 0014 adds four defaulted columns, one table and two indexes.
        // M08 GRANT-LIVE: 0015 adds the generated live column and replaces the deadline index.
        assert_eq!(migrations::SCHEMA_VERSION, 15);
        assert!(
            backup_path(&db, ".v1.backup").exists(),
            "v1 file backed up first"
        );
        {
            let c = s.lock();
            for (table, n) in &before {
                assert_eq!(table_count(&c, table), *n, "{table} rows preserved");
            }
            let fk_violation = c
                .prepare("PRAGMA foreign_key_check")
                .and_then(|mut st| st.exists([]))
                .unwrap();
            assert!(!fk_violation);
            let expires_notnull: i64 = c
                .query_row(
                    "SELECT \"notnull\" FROM pragma_table_info('idempotency') WHERE name = 'expires_at'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(expires_notnull, 0, "expires_at is nullable after 0002");
            let binding_state: String = c
                .query_row(
                    "SELECT state FROM bindings WHERE id = 'binding_v1'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(binding_state, "released");
        }
        let env = EnvironmentId::from_random_bytes([7; 16]);
        s.transaction(|tx| {
            assert_eq!(tx.self_environment()?, Some(env.clone()));
            assert_eq!(tx.authority_generation()?, AuthorityGeneration(1));
            for (op, idem) in &ops {
                assert_eq!(tx.operation(&op.id)?.as_ref(), Some(op));
                let rec = tx.idempotency_record(&idem.key)?.unwrap();
                assert_eq!(rec.operation_id, op.id);
                // Settled keys keep their v1 expiry; pending and unresolved keys
                // become live (no expiry) under the 0002 protocol.
                let want = op.state.is_settled().then_some(idem.expires_at).flatten();
                assert_eq!(rec.expires_at, want, "{:?}", op.state);
            }
            assert_eq!(tx.grant(&v1_grant().id)?, Some(v1_grant()));
            assert_eq!(
                tx.grant_references(&v1_grant().id)?.len(),
                1,
                "v1 reference readable through the 0002 API"
            );
            let tomb = tx.tombstone(&GrantId::from_random_bytes([6; 16]))?.unwrap();
            assert_eq!(tomb.generation, AuthorityGeneration(1));
            let page = tx.stored_events_after(&env, 0, &EventFilter::default(), 10)?;
            assert_eq!(page.events.len(), 2, "trimmed event stays trimmed");
            assert!(page.tail_seq > 0 && page.head_seq > page.tail_seq);
            // The boot-less v1 anchor is gone; its wall time seeds the high-water mark.
            assert_eq!(tx.runtime_anchor()?, None);
            assert_eq!(tx.time_anchor()?, None);
            assert_eq!(tx.high_water_mark()?, Some(ts("2026-10-01T00:00:05Z")));
            // New tables are usable.
            assert_eq!(tx.unresolved_operations()?.len(), 1);
            assert_eq!(tx.open_operations()?.len(), 1);
            assert!(tx.pending_decisions()?.is_empty());
            Ok(())
        })
        .unwrap();
        drop(s);
        // Reopening at the current version neither migrates nor backs up again.
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        assert!(!backup_path(&db, ".v1.backup.1").exists());
        assert!(!backup_path(&db, ".v2.backup").exists());
    }

    #[test]
    fn failing_0002_step_leaves_the_v1_database_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        populated_v1(&db);
        // Migration 0002 with a statement that fails after the table rebuild.
        let broken: &'static str =
            Box::leak(format!("{}\nNOT SQL;", migrations::MIGRATIONS[1].sql).into_boxed_str());
        let steps: &'static [Migration] = Box::leak(Box::new([
            migrations::MIGRATIONS[0],
            Migration {
                version: 2,
                name: "design_fix_broken",
                sql: broken,
            },
        ]));
        assert!(Store::open_with_steps(&db, Arc::new(NoFaults), steps, true).is_err());
        let c = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(migrations::user_version(&c).unwrap(), 1);
        let expires_notnull: i64 = c
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('idempotency') WHERE name = 'expires_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(expires_notnull, 1, "v1 idempotency table intact");
        assert_eq!(table_count(&c, "idempotency"), 3);
        let markers: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'idempotency_markers'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(markers, 0, "no half-applied 0002 table");
        let anchor: i64 = c
            .query_row(
                "SELECT count(*) FROM meta WHERE key = 'time_anchor'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(anchor, 1, "v1 meta untouched");
        drop(c);
        // The good migration still applies afterwards.
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
    }

    // --- migration 0002 -> 0003 on a populated v2 database (ADR-0006 §13.7 item 3) ---

    fn v2_grant(b: u8, source: heimdall_domain::grant::AuthorizationSource) -> GrantSnapshot {
        GrantSnapshot {
            id: GrantId::from_random_bytes([b; 16]),
            source,
            ..v1_grant()
        }
    }

    fn v2_basis(decision: u8) -> heimdall_domain::operation::ApprovalBasis {
        use heimdall_domain::policy::PolicyRevision;
        heimdall_domain::operation::ApprovalBasis {
            decision: heimdall_contract::ids::DecisionId::from_random_bytes([decision; 16]),
            delta: heimdall_domain::authority::AuthorityDelta {
                added_scope: heimdall_domain::scope::Scope::empty(),
                extra_window: Some(std::time::Duration::from_secs(600)),
                environment_not_covered: false,
            },
            generation: AuthorityGeneration(3),
            policy_revision: Some(PolicyRevision(2)),
        }
    }

    fn v2_intent(
        grant: &GrantId,
        approval: Option<heimdall_domain::operation::ApprovalBasis>,
    ) -> heimdall_domain::operation::RecoveryIntent {
        let g = v1_grant();
        heimdall_domain::operation::RecoveryIntent {
            request: serde_json::json!({"op": "ensure", "request_id": "r"}),
            resolved: Some(heimdall_domain::operation::ResolvedIntent {
                profile: heimdall_contract::ids::ProfileId::parse("dev").unwrap(),
                profile_revision: 1,
                scope: g.scope,
                deadline: g.deadline,
                policy_revision: None,
                generation: AuthorityGeneration(2),
                grant: Some(grant.clone()),
                binding: None,
                adapter: None,
                approval,
                covered: None,
                binding_id: None,
                workspace: None,
            }),
            local: None,
        }
    }

    /// A v2 database as a v2 build leaves it (migrations 0001 and 0002 only): an
    /// owner-approved grant whose basis lives in the recovery intents of its creator
    /// and of a request that joined it, a standing-policy grant, an approved grant
    /// whose operations were already purged, a malformed recovery intent, a pending
    /// decision and a tombstone. Returns (approved, standing, purged) grant IDs.
    fn populated_v2(db: &Path) -> (GrantId, GrantId, GrantId) {
        use heimdall_domain::grant::AuthorizationSource;
        use heimdall_domain::policy::PolicyRevision;
        let s = Store::open_with_steps(db, Arc::new(NoFaults), &migrations::MIGRATIONS[..2], false)
            .unwrap();
        assert_eq!(s.schema_version().unwrap(), 2);
        let creator = v1_op(11, OperationState::Succeeded);
        let joiner = v1_op(12, OperationState::Succeeded);
        let standing_op = v1_op(13, OperationState::Succeeded);
        let malformed_op = v1_op(14, OperationState::Queued);
        let approved = v2_grant(
            21,
            AuthorizationSource::OwnerDecision {
                operation_id: creator.0.id.clone(),
            },
        );
        let standing = v2_grant(
            22,
            AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
        );
        let purged = v2_grant(
            23,
            AuthorizationSource::OwnerDecision {
                operation_id: OperationId::from_random_bytes([99; 16]),
            },
        );
        let env = EnvironmentId::from_random_bytes([7; 16]);
        s.transaction(|tx| {
            tx.init_self_environment(&env)?;
            for (op, idem) in [&creator, &joiner, &standing_op, &malformed_op] {
                tx.insert_operation(op, idem)?;
            }
            for g in [&approved, &standing, &purged] {
                tx.insert_grant(g)?;
            }
            tx.set_recovery_intent(&creator.0.id, &v2_intent(&approved.id, Some(v2_basis(31))))?;
            tx.set_recovery_intent(&joiner.0.id, &v2_intent(&approved.id, Some(v2_basis(31))))?;
            tx.set_recovery_intent(&standing_op.0.id, &v2_intent(&standing.id, None))?;
            tx.insert_decision(&heimdall_domain::decision::DecisionRecord {
                id: heimdall_contract::ids::DecisionId::from_random_bytes([32; 16]),
                kind: heimdall_domain::decision::DecisionKind::ApproveAuthority {
                    operation: malformed_op.0.id.clone(),
                    delta: v2_basis(32).delta,
                },
                generation: AuthorityGeneration(1),
                created_at: ts("2026-10-01T00:00:00Z"),
                expires_at: ts("2026-10-01T00:15:00Z"),
                state: heimdall_domain::decision::DecisionState::Pending,
                decided_at: None,
            })?;
            tx.insert_tombstone(&Tombstone {
                grant: GrantId::from_random_bytes([6; 16]),
                cascade: Vec::new(),
                generation: AuthorityGeneration(0),
                revoked_at: ts("2026-10-01T00:00:00Z"),
                remote_pending: Vec::new(),
                cause: heimdall_domain::revocation::RevocationCause::Revoke,
            })?;
            Ok(())
        })
        .unwrap();
        // Written past the API: a recovery intent that is not JSON at all.
        s.lock()
            .execute(
                "INSERT INTO recovery_intents (operation_id, record_json) VALUES (?1, 'not json')",
                [malformed_op.0.id.as_str()],
            )
            .unwrap();
        (approved.id, standing.id, purged.id)
    }

    #[test]
    fn migration_0003_preserves_a_populated_v2_database_and_backfills_the_basis() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let (approved, standing, purged) = populated_v2(&db);
        let tables = [
            "operations",
            "idempotency",
            "grants",
            "recovery_intents",
            "decisions",
            "tombstones",
            "meta",
        ];
        let before: Vec<(String, i64)> = {
            let c = rusqlite::Connection::open(&db).unwrap();
            tables
                .iter()
                .map(|t| ((*t).to_owned(), table_count(&c, t)))
                .collect()
        };
        // ⟨rev7; review U0-R06⟩ Every pre-existing `meta` row, byte for byte: a later migration
        // may add keys (0014's `restore_epoch`), never change or drop one.
        let meta_before = meta_rows(&rusqlite::Connection::open(&db).unwrap());
        assert!(
            before.iter().all(|(_, n)| *n > 0),
            "fixture populated every table"
        );
        let grants_before: Vec<GrantSnapshot> = {
            let s = Store::open_with_steps(
                &db,
                Arc::new(NoFaults),
                &migrations::MIGRATIONS[..2],
                false,
            )
            .unwrap();
            s.transaction(|tx| {
                let mut out = Vec::new();
                for g in [&approved, &standing, &purged] {
                    out.push(tx.grant(g)?.unwrap());
                }
                Ok(out)
            })
            .unwrap()
        };

        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        assert!(
            backup_path(&db, ".v2.backup").exists(),
            "v2 file backed up first"
        );
        {
            let c = s.lock();
            for (table, n) in &before {
                if table == "meta" {
                    continue;
                }
                assert_eq!(table_count(&c, table), *n, "{table} rows preserved");
            }
            let meta_after = meta_rows(&c);
            for row in &meta_before {
                assert!(meta_after.contains(row), "meta row {} preserved", row.0);
            }
            let fk_violation = c
                .prepare("PRAGMA foreign_key_check")
                .and_then(|mut st| st.exists([]))
                .unwrap();
            assert!(!fk_violation);
        }
        s.transaction(|tx| {
            for g in &grants_before {
                assert_eq!(tx.grant(&g.id)?.as_ref(), Some(g), "grant record unchanged");
            }
            // The basis moved to the grant row; the recovery intents keep theirs.
            assert_eq!(tx.grant_approval(&approved)?, Some(v2_basis(31)));
            assert_eq!(tx.grant_approval(&standing)?, None);
            assert_eq!(
                tx.grant_approval(&purged)?,
                None,
                "no basis left to backfill: re-validated against the policy alone"
            );
            assert_eq!(tx.pending_decisions()?.len(), 1);
            assert_eq!(tx.authority_generation()?, AuthorityGeneration(1));
            // Retention purges the approving operations; the basis stays.
            assert!(tx.purge_operations_before(ts("2026-12-01T00:00:00Z"))? >= 2);
            assert_eq!(tx.grant_approval(&approved)?, Some(v2_basis(31)));
            // Written once afterwards too.
            tx.set_grant_approval(&approved, &v2_basis(31))?;
            assert!(matches!(
                tx.set_grant_approval(&approved, &v2_basis(33)),
                Err(StoreError::GenerationConflict(_))
            ));
            tx.set_grant_approval(&purged, &v2_basis(34))?;
            assert_eq!(tx.grant_approval(&purged)?, Some(v2_basis(34)));
            Ok(())
        })
        .unwrap();
        drop(s);
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        assert!(
            !backup_path(&db, ".v2.backup.1").exists(),
            "no second migration"
        );
    }

    #[test]
    fn failing_0003_step_leaves_the_v2_database_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let (approved, ..) = populated_v2(&db);
        // Migration 0003 with a statement that fails after the column and backfill.
        let broken: &'static str =
            Box::leak(format!("{}\nNOT SQL;", migrations::MIGRATIONS[2].sql).into_boxed_str());
        let steps: &'static [Migration] = Box::leak(Box::new([
            migrations::MIGRATIONS[0],
            migrations::MIGRATIONS[1],
            Migration {
                version: 3,
                name: "grant_approval_broken",
                sql: broken,
            },
        ]));
        assert!(Store::open_with_steps(&db, Arc::new(NoFaults), steps, true).is_err());
        let c = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(migrations::user_version(&c).unwrap(), 2);
        let column: i64 = c
            .query_row(
                "SELECT count(*) FROM pragma_table_info('grants') WHERE name = 'approval_json'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(column, 0, "no half-applied 0003 column");
        assert_eq!(table_count(&c, "grants"), 3);
        drop(c);
        // A current-version file missing the column is refused as corrupt, never used.
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        s.transaction(|tx| {
            assert_eq!(tx.grant_approval(&approved)?, Some(v2_basis(31)));
            Ok(())
        })
        .unwrap();
        drop(s);
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("ALTER TABLE grants DROP COLUMN approval_json;")
            .unwrap();
        drop(c);
        assert!(matches!(
            Store::open(&db, Arc::new(NoFaults)),
            Err(StoreError::Corrupt(_))
        ));
    }

    // --- migration 0003 -> 0004 on a populated v3 database (ADR-0006 §13.9 item 2) ---

    fn v3_origin_intent(
        grant: &GrantId,
        covered: Option<heimdall_domain::operation::CoveredBasis>,
    ) -> heimdall_domain::operation::RecoveryIntent {
        let mut intent = v2_intent(grant, None);
        if let Some(r) = intent.resolved.as_mut() {
            r.profile_revision = 4;
            r.policy_revision = Some(heimdall_domain::policy::PolicyRevision(6));
            r.adapter = Some(heimdall_domain::operation::AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            });
            r.covered = covered;
        }
        intent
    }

    fn v3_binding(b: u8, grant: &GrantId, uid: u32) -> heimdall_domain::binding::BindingRecord {
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        heimdall_domain::binding::BindingRecord {
            id: heimdall_contract::ids::BindingId::from_random_bytes([b; 16]),
            environment: EnvironmentId::from_random_bytes([7; 16]),
            grant: grant.clone(),
            work_id: heimdall_contract::ids::WorkId::parse(&format!("work-{b}")).unwrap(),
            owner: CallerContext {
                principal: PrincipalRef::UnixUser { uid },
                role: ClientRole::LimitedConsumer,
                remote_client: None,
            },
            profile: heimdall_contract::ids::ProfileId::parse("ops").unwrap(),
            profile_revision: 9,
            scope: v1_grant().scope,
            mechanism: "fake_agent".into(),
            parent: None,
            created_at: ts("2026-10-01T00:00:00Z"),
            released_at: None,
            state: heimdall_domain::binding::BindingState::Active,
        }
    }

    /// A v3 database (migrations 0001–0003 only): a grant pinned by an operation's
    /// recovery intent (with a covered basis), a standing-policy grant realized only
    /// by a binding, a delegated child's binding that names the child (never its
    /// parent), a parent with no record to backfill from, and a malformed intent.
    /// Returns (pinned, bound, parent, child) grant IDs.
    fn populated_v3(db: &Path) -> (GrantId, GrantId, GrantId, GrantId) {
        use heimdall_domain::grant::AuthorizationSource;
        use heimdall_domain::policy::PolicyRevision;
        let s = Store::open_with_steps(db, Arc::new(NoFaults), &migrations::MIGRATIONS[..3], false)
            .unwrap();
        assert_eq!(s.schema_version().unwrap(), 3);
        let creator = v1_op(41, OperationState::Succeeded);
        let malformed_op = v1_op(42, OperationState::Queued);
        let pinned = v2_grant(
            51,
            AuthorizationSource::OwnerDecision {
                operation_id: creator.0.id.clone(),
            },
        );
        let bound = v2_grant(
            52,
            AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(3),
            },
        );
        let parent = v2_grant(
            53,
            AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(3),
            },
        );
        let child = GrantSnapshot {
            parent: Some(parent.id.clone()),
            ..v2_grant(
                54,
                AuthorizationSource::Delegation {
                    parent: parent.id.clone(),
                },
            )
        };
        let env = EnvironmentId::from_random_bytes([7; 16]);
        s.transaction(|tx| {
            tx.init_self_environment(&env)?;
            for (op, idem) in [&creator, &malformed_op] {
                tx.insert_operation(op, idem)?;
            }
            for g in [&pinned, &bound, &parent, &child] {
                tx.insert_grant(g)?;
            }
            tx.set_recovery_intent(
                &creator.0.id,
                &v3_origin_intent(
                    &pinned.id,
                    Some(heimdall_domain::operation::CoveredBasis {
                        generation: AuthorityGeneration(5),
                        policy_revision: Some(PolicyRevision(7)),
                    }),
                ),
            )?;
            tx.insert_binding(&v3_binding(61, &bound.id, 777))?;
            // The child's binding (with its reference on the parent) names the child.
            tx.insert_binding(&v3_binding(62, &child.id, 778))?;
            tx.add_grant_reference(&GrantReference {
                binding: heimdall_contract::ids::BindingId::from_random_bytes([62; 16]),
                grant: parent.id.clone(),
                acquired_at: ts("2026-10-01T00:00:00Z"),
            })?;
            Ok(())
        })
        .unwrap();
        s.lock()
            .execute(
                "INSERT INTO recovery_intents (operation_id, record_json) VALUES (?1, 'not json')",
                [malformed_op.0.id.as_str()],
            )
            .unwrap();
        (pinned.id, bound.id, parent.id, child.id)
    }

    #[test]
    fn migration_0004_preserves_a_populated_v3_database_and_backfills_the_origin() {
        use heimdall_domain::grant::GrantOrigin;
        use heimdall_domain::policy::PolicyRevision;
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let (pinned, bound, parent, child) = populated_v3(&db);
        let tables = [
            "operations",
            "grants",
            "grant_references",
            "bindings",
            "recovery_intents",
            "meta",
        ];
        let before: Vec<(String, i64)> = {
            let c = rusqlite::Connection::open(&db).unwrap();
            tables
                .iter()
                .map(|t| ((*t).to_owned(), table_count(&c, t)))
                .collect()
        };
        // ⟨rev7; review U0-R06⟩ Every pre-existing `meta` row, byte for byte: a later migration
        // may add keys (0014's `restore_epoch`), never change or drop one.
        let meta_before = meta_rows(&rusqlite::Connection::open(&db).unwrap());
        let grants_before: Vec<GrantSnapshot> = {
            let s = Store::open_with_steps(
                &db,
                Arc::new(NoFaults),
                &migrations::MIGRATIONS[..3],
                false,
            )
            .unwrap();
            s.transaction(|tx| {
                let mut out = Vec::new();
                for g in [&pinned, &bound, &parent, &child] {
                    out.push(tx.grant(g)?.unwrap());
                }
                Ok(out)
            })
            .unwrap()
        };
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        assert!(
            backup_path(&db, ".v3.backup").exists(),
            "v3 file backed up first"
        );
        {
            let c = s.lock();
            for (table, n) in &before {
                if table == "meta" {
                    continue;
                }
                assert_eq!(table_count(&c, table), *n, "{table} rows preserved");
            }
            let meta_after = meta_rows(&c);
            for row in &meta_before {
                assert!(meta_after.contains(row), "meta row {} preserved", row.0);
            }
        }
        let owner = CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: None,
        };
        s.transaction(|tx| {
            for g in &grants_before {
                assert_eq!(tx.grant(&g.id)?.as_ref(), Some(g), "grant record unchanged");
            }
            let from_intent = GrantOrigin {
                profile: heimdall_contract::ids::ProfileId::parse("dev").unwrap(),
                profile_revision: 4,
                policy_revision: Some(PolicyRevision(6)),
                caller: owner.clone(),
                mechanism: "fake_agent".into(),
                covered: Some(heimdall_domain::operation::CoveredBasis {
                    generation: AuthorityGeneration(5),
                    policy_revision: Some(PolicyRevision(7)),
                }),
                adapter: None,
                // M03 wave 0 (A1): fail closed until U0b
                lock_behavior: None,
                connection: None,
                policy_id: None,
                workspace: None,
            };
            assert_eq!(tx.grant_origin(&pinned)?, Some(from_intent.clone()));
            let from_binding = GrantOrigin {
                profile: heimdall_contract::ids::ProfileId::parse("ops").unwrap(),
                profile_revision: 9,
                policy_revision: Some(PolicyRevision(3)),
                caller: CallerContext {
                    principal: PrincipalRef::UnixUser { uid: 777 },
                    role: ClientRole::LimitedConsumer,
                    remote_client: None,
                },
                mechanism: "fake_agent".into(),
                covered: None,
                adapter: None,
                // M03 wave 0 (A1): fail closed until U0b
                lock_behavior: None,
                connection: None,
                policy_id: None,
                workspace: None,
            };
            assert_eq!(tx.grant_origin(&bound)?, Some(from_binding));
            assert_eq!(
                tx.grant_origin(&parent)?,
                None,
                "a child's binding is never the parent's origin"
            );
            assert_eq!(
                tx.grant_origin(&child)?.map(|o| o.policy_revision),
                Some(None),
                "a delegated grant's binding gives no standing-policy revision"
            );
            // Retention purges the operation; the origin stays with the grant.
            assert!(tx.purge_operations_before(ts("2026-12-01T00:00:00Z"))? >= 1);
            assert_eq!(tx.grant_origin(&pinned)?, Some(from_intent));
            Ok(())
        })
        .unwrap();
        drop(s);
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        assert!(
            !backup_path(&db, ".v3.backup.1").exists(),
            "no second migration"
        );
    }

    #[test]
    fn failing_0004_step_leaves_the_v3_database_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        let (pinned, ..) = populated_v3(&db);
        let broken: &'static str =
            Box::leak(format!("{}\nNOT SQL;", migrations::MIGRATIONS[3].sql).into_boxed_str());
        let steps: &'static [Migration] = Box::leak(Box::new([
            migrations::MIGRATIONS[0],
            migrations::MIGRATIONS[1],
            migrations::MIGRATIONS[2],
            Migration {
                version: 4,
                name: "grant_origin_broken",
                sql: broken,
            },
        ]));
        assert!(Store::open_with_steps(&db, Arc::new(NoFaults), steps, true).is_err());
        let c = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(migrations::user_version(&c).unwrap(), 3);
        let column: i64 = c
            .query_row(
                "SELECT count(*) FROM pragma_table_info('grants') WHERE name = 'origin_json'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(column, 0, "no half-applied 0004 column");
        drop(c);
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.schema_version().unwrap(), migrations::SCHEMA_VERSION);
        s.transaction(|tx| {
            assert!(tx.grant_origin(&pinned)?.is_some());
            Ok(())
        })
        .unwrap();
        drop(s);
        // A v4 file missing the column is refused as corrupt, never used.
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("ALTER TABLE grants DROP COLUMN origin_json;")
            .unwrap();
        drop(c);
        assert!(matches!(
            Store::open(&db, Arc::new(NoFaults)),
            Err(StoreError::Corrupt(_))
        ));
    }

    /// ⟨M03⟩ §17.21 item 8: the Windows environment pipe token is recorded once and
    /// read back unchanged by every later transaction (and a reopened store); a second,
    /// different token is refused; a malformed one is never stored.
    #[test]
    fn windows_pipe_token_recorded_once_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.sqlite3");
        {
            let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
            assert_eq!(s.transaction(|tx| tx.windows_pipe_token()).unwrap(), None);
            s.transaction(|tx| tx.set_windows_pipe_token("abc123DEF"))
                .unwrap();
            s.transaction(|tx| tx.set_windows_pipe_token("abc123DEF"))
                .unwrap();
            assert!(matches!(
                s.transaction(|tx| tx.set_windows_pipe_token("other")),
                Err(StoreError::GenerationConflict(_))
            ));
            for bad in ["", "has-dash", "x".repeat(65).as_str(), "sp ace"] {
                assert!(s.transaction(|tx| tx.set_windows_pipe_token(bad)).is_err());
            }
        }
        let s = Store::open(&db, Arc::new(NoFaults)).unwrap();
        assert_eq!(
            s.transaction(|tx| tx.windows_pipe_token())
                .unwrap()
                .as_deref(),
            Some("abc123DEF")
        );
    }

    /// `read_only_open_never_rolls_back_a_hot_journal` (ADR-0008 §17.36 item 1): with a hot
    /// rollback journal beside a database, a read-only connection
    /// (`SQLITE_OPEN_READONLY`, as [`Store::open_read_only`] opens) fails with
    /// `SQLITE_READONLY_ROLLBACK` and leaves the database's bytes and the journal as they
    /// are; a read-write connection (the control) rolls the journal back and loses the
    /// later change. SQLite's documented behaviour (result code `SQLITE_READONLY_ROLLBACK`,
    /// <https://www.sqlite.org/rescode.html#readonly_rollback>; `pager.c`,
    /// `pagerSharedLock`: a hot journal on a read-only pager is refused rather than
    /// played back).
    #[test]
    fn read_only_open_never_rolls_back_a_hot_journal() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("x.db");
        let journal_of = |p: &Path| {
            let mut j = p.as_os_str().to_owned();
            j.push("-journal");
            std::path::PathBuf::from(j)
        };
        let c = rusqlite::Connection::open(&db).unwrap();
        c.pragma_update(None, "journal_mode", "DELETE").unwrap();
        c.pragma_update(None, "cache_size", 1).unwrap();
        c.execute_batch("CREATE TABLE t (x BLOB); CREATE TABLE marker (y INTEGER);")
            .unwrap();
        for _ in 0..20 {
            c.execute("INSERT INTO t VALUES (zeroblob(8000))", [])
                .unwrap();
        }
        c.execute_batch("BEGIN IMMEDIATE; UPDATE t SET x = randomblob(8000);")
            .unwrap();
        let hot = std::fs::read(journal_of(&db)).unwrap();
        assert_eq!(&hot[..8], &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
        c.execute_batch("ROLLBACK;").unwrap();
        c.execute("INSERT INTO marker VALUES (9)", []).unwrap();
        c.execute("UPDATE t SET x = zeroblob(10)", []).unwrap();
        drop(c);
        std::fs::write(journal_of(&db), &hot).unwrap();
        let bytes = std::fs::read(&db).unwrap();
        // A read-only connection refuses, and changes nothing.
        let ro =
            rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let err = ro
            .query_row("SELECT count(*) FROM marker", [], |r| r.get::<_, i64>(0))
            .unwrap_err();
        assert_eq!(
            err.sqlite_error().map(|e| e.extended_code),
            Some(rusqlite::ffi::SQLITE_READONLY_ROLLBACK),
            "{err}"
        );
        drop(ro);
        assert!(Store::open_read_only(&db, Arc::new(NoFaults)).is_err());
        assert_eq!(
            std::fs::read(&db).unwrap(),
            bytes,
            "the database was written"
        );
        assert_eq!(
            std::fs::read(journal_of(&db)).unwrap(),
            hot,
            "the journal was played"
        );
        // The control: a read-write connection rolls it back and loses the later row.
        let ctl = d.path().join("control.db");
        std::fs::copy(&db, &ctl).unwrap();
        std::fs::copy(journal_of(&db), journal_of(&ctl)).unwrap();
        let rw = rusqlite::Connection::open(&ctl).unwrap();
        let len: i64 = rw
            .query_row("SELECT max(length(x)) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            len, 8000,
            "the read-write control did not replay the journal"
        );
    }

    /// ⟨rev7⟩ U0-Q9: catalog aliases are unique without ASCII case, checked at write. A new
    /// destination, or a rename, into a case-variant of another destination's alias is a
    /// conflict and changes nothing; a write that keeps a destination's own stored alias byte
    /// for byte is not refused, so a legacy case-variant pair (written before revision 7)
    /// stays readable and editable, and is listed once for `doctor`.
    #[test]
    fn catalog_aliases_are_unique_without_case_at_write() {
        use heimdall_contract::ids::{AccountName, DestinationId, IdentityId};
        use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
        let t0 = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        let destination = |n: u8, alias: &str, revision: u64| DestinationRecord {
            id: DestinationId::parse(&format!("dest{n}")).unwrap(),
            alias: alias.into(),
            revision,
            definition: DestinationDefinition::Managed {
                hostname: "example.invalid".into(),
                port: None,
                account: AccountName::parse("git").unwrap(),
                identity: IdentityId::from_random_bytes([n; 16]),
                jump: None,
            },
            label: None,
            updated_at: t0,
        };
        let s = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        s.transaction(|tx| {
            tx.upsert_destination(&destination(1, "Work", 1))?;
            for refused in [destination(2, "work", 1), destination(2, "WORK", 1)] {
                assert!(matches!(
                    tx.upsert_destination(&refused),
                    Err(StoreError::DestinationAliasTaken)
                ));
            }
            tx.upsert_destination(&destination(2, "home", 1))?;
            assert!(
                matches!(
                    tx.upsert_destination(&destination(2, "wORK", 2)),
                    Err(StoreError::DestinationAliasTaken)
                ),
                "a rename into a case-variant is refused"
            );
            // A change of case of the destination's own alias is no collision.
            tx.upsert_destination(&destination(1, "work", 2))?;
            assert_eq!(
                tx.destinations_by_alias_ignoring_case("WORK")?
                    .into_iter()
                    .map(|d| d.alias)
                    .collect::<Vec<_>>(),
                ["work"]
            );
            assert!(tx.destination_alias_case_collisions()?.is_empty());
            Ok(())
        })
        .unwrap();
        // A legacy pair, as an earlier build could store it.
        {
            let c = s.lock();
            let mut legacy = destination(3, "Lab", 1);
            c.execute(
                "INSERT INTO destinations (id, alias, revision, record_json) VALUES (?1, ?2, 1, ?3)",
                rusqlite::params![
                    legacy.id.as_str(),
                    legacy.alias,
                    serde_json::to_string(&legacy).unwrap()
                ],
            )
            .unwrap();
            legacy = destination(4, "lab", 1);
            c.execute(
                "INSERT INTO destinations (id, alias, revision, record_json) VALUES (?1, ?2, 1, ?3)",
                rusqlite::params![
                    legacy.id.as_str(),
                    legacy.alias,
                    serde_json::to_string(&legacy).unwrap()
                ],
            )
            .unwrap();
        }
        s.transaction(|tx| {
            let pairs = tx.destination_alias_case_collisions()?;
            assert_eq!(pairs.len(), 1);
            assert_eq!(
                (pairs[0].0.alias.as_str(), pairs[0].1.alias.as_str()),
                ("Lab", "lab")
            );
            // Each stays editable while it keeps its own alias.
            let mut relabelled = destination(3, "Lab", 2);
            relabelled.label = Some("kept".into());
            tx.upsert_destination(&relabelled)?;
            // Renaming into the other's case-variant is still refused.
            assert!(matches!(
                tx.upsert_destination(&destination(4, "LAB", 2)),
                Err(StoreError::DestinationAliasTaken)
            ));
            Ok(())
        })
        .unwrap();
    }

    /// ⟨rev7; review U0-R06⟩ A store at schema version 14 whose `meta.restore_epoch` row is
    /// lost, malformed or not canonical decimal (U0-RC04) is refused as damaged at every open,
    /// never read as epoch 0 or as another number: a lost row must not reset the restore fence.
    #[test]
    fn a_lost_restore_epoch_is_damage_never_epoch_zero() {
        let dir = tempfile::tempdir().unwrap();
        for (label, damage) in [
            ("deleted", "DELETE FROM meta WHERE key = 'restore_epoch'"),
            (
                "malformed",
                "UPDATE meta SET value = 'x' WHERE key = 'restore_epoch'",
            ),
            (
                "signed",
                "UPDATE meta SET value = '+1' WHERE key = 'restore_epoch'",
            ),
            (
                "leading-zero",
                "UPDATE meta SET value = '007' WHERE key = 'restore_epoch'",
            ),
        ] {
            let db = dir.path().join(format!("{label}.sqlite3"));
            drop(Store::open(&db, Arc::new(NoFaults)).unwrap());
            rusqlite::Connection::open(&db)
                .unwrap()
                .execute_batch(damage)
                .unwrap();
            assert!(
                matches!(
                    Store::open(&db, Arc::new(NoFaults)),
                    Err(StoreError::Corrupt(_))
                ),
                "{label}"
            );
            assert!(
                matches!(
                    Store::open_read_only(&db, Arc::new(NoFaults)),
                    Err(StoreError::Corrupt(_))
                ),
                "{label}, read-only"
            );
        }
    }

    /// ⟨rev7; review U0-RC04⟩ The restore epoch parses as canonical decimal only.
    #[test]
    fn the_restore_epoch_is_canonical_decimal_only() {
        for (text, want) in [
            ("0", Some(0)),
            ("1", Some(1)),
            ("42", Some(42)),
            ("18446744073709551615", Some(u64::MAX)),
        ] {
            assert_eq!(parse_restore_epoch(text), want, "{text:?}");
        }
        for text in [
            "",
            "+1",
            "-1",
            "-0",
            "00",
            "007",
            " 0",
            "0 ",
            "\t1",
            "1\n",
            "1e3",
            "0x1",
            "1_000",
            "١",
            "18446744073709551616",
        ] {
            assert_eq!(parse_restore_epoch(text), None, "{text:?}");
        }
    }
}
