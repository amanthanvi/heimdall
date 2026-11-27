//! ⟨M08 W4 U2b-3b; ADR-0014 §3.6 "The restore rule" and "The restore protocol", deltas H3, H9,
//! H10; ADR-0006 §19.4 and U0-Q8⟩ Restore, reset and repair of the state store.
//!
//! **A restore recovers identity and configuration, and no authority.** It builds a new store
//! generation from one of this installation's own backups and makes it current by the one
//! pointer switch ([`heimdall_stategen::StateDir::publish`], or, from `state_corrupt`,
//! [`heimdall_stategen::StateDir::recover`]). Its steps, in the protocol's order:
//!
//! 1. **Identity binding** ([`inspect_backup`]): the backup must be a Heimdall store that
//!    passes its integrity check, at a schema no newer than this build's, holding an
//!    environment ID (`meta.self_environment_id`; no column was added, as ruled). It must be
//!    the environment the current generation's operation record names. With no trusted
//!    record (`state_corrupt`, or a flat store that was never adopted and cannot be read) the
//!    restore is attended only, the owner is shown the backup's environment ID, and only a
//!    backup under this installation's own backup names is accepted ([`is_own_backup`]).
//! 2. **Exclusion** is the caller's: the runtime's instance lock is held from before anything
//!    is read until after the switch, with the runtime and the issuer stopped (the runtime's
//!    `state_store`).
//! 3. **Staging,** in the new generation's directory: the backup is copied **through SQLite**
//!    (`VACUUM INTO` from a read-only connection; never a copy of the file), checked, migrated
//!    to this build's schema, and then, **in one transaction**: the carry-forward from the
//!    replaced generation when it is readable, the sanitization of ADR-0014 §3.6's table, the
//!    fence records from the request ledger, the raised epoch, and the removal of the page
//!    tokens' key. The `state_restored` event is appended in a second transaction, through the
//!    caller's [`RestoreEvent`] (the application's event publisher, the one writer of events).
//! 4. **Completion:** the staged database is put in rollback-journal mode (checkpointed, no
//!    log), checked and closed; the generation crate then syncs it, writes and syncs the
//!    operation record (`restore`, the backup by its SHA-256, the environment, the epoch) and
//!    syncs the directories.
//! 5. **The switch.**
//! 6. **The report** ([`RestoreOutcome`]).
//!
//! **What the sanitization does** (ADR-0014 §3.6's table), in the staged generation:
//! - every grant that is not terminal is ended (`revoked`, with a tombstone, cause
//!   `authority_withdrawn`) and held as `grant` (`state_restored_authority_ended`); its active
//!   bindings are released. Managed slots and owned connections end with the runtime, which is
//!   stopped; the restarted runtime's own recovery finds their grants ended;
//! - every standing policy is paused, with a cutoff at the restore time (or earlier, when the
//!   replaced generation had one); every active workspace trust record is made stale, so it
//!   needs a new attended trust;
//! - every pending decision, a pending widening record included, is closed as stale;
//! - every operation that was not terminal is closed as stale: `failed`, with the answer
//!   `REQUEST_STALE` / `restored_before_completion`. None resumes;
//! - every paired management client that is not revoked is held as `client`
//!   (`client_quarantined_after_restore`): not admitted until the owner reauthorizes it at this
//!   machine;
//! - every invitation pending or consumed in the backup is held as `invitation`
//!   (`invitation_void_after_restore`);
//! - exposure and admission state is disabled: every K_iroh reference withdrawn (marked
//!   destroyed; the platform item is kept until a `transport disable` removes it), every
//!   exposure consent removed, the serve port, the rotation being announced and the serve
//!   allowlist cleared, and the admission authority generation moved; held as `exposure`
//!   (`exposure_disabled_after_restore`). Enabling again is the same local decision as the first
//!   time. Routes are catalog and are kept;
//! - every paired runner environment is held as `environment` until reconciled. No issuance
//!   happens before the issuer's reconciliation barrier has run in any case: the barrier is
//!   closed for every environment at each runtime start (`heimdall_app::remote_status_barrier`);
//! - the page tokens' key (`meta.page_token_hmac_key`, never in a snapshot) is removed: a
//!   restore never carries it in either direction, and the first page served makes a new one.
//!
//! **The carry-forward** ([`Carried`]): when the replaced generation is readable, it is read
//! first, through SQLite, inside a `BEGIN IMMEDIATE` transaction held until after the switch.
//! That transaction writes nothing and is rolled back; it keeps the one writer that holds no
//! instance lock, the bridge's downgrade write, out of the replaced generation from the read
//! to the switch, so a downgrade it records lands before the read (and is carried) or after
//! the switch (where the bridge's pointer check sends it to its fail-closed marker). It keeps
//! the more restrictive of the two states for every revocation (client tombstones, grant
//! tombstones), retirement (issuers), unpairing (environment pins, and the runner's issuer
//! trust and time source), consumption (invitations), removal (enrollments), cutoff, pause and
//! the runner's downgrade marker, with the runner's own effect ledger and delivered policy
//! revisions; and every terminal operation and idempotency record, expired-key marker,
//! request terminal record and fence record made after the backup, so a retry of a request
//! that completed gets its real recorded answer. Decisions made after the backup are carried
//! closed as stale, under the epoch they were minted in, so their references answer
//! `DECISION_STALE` / `restore_epoch_stale`. The authority generations never go back.
//!
//! **Not established by any test:** durability across power loss (ADR-0014 §3.6
//! "Platforms"). The fault tests stop the process and inject I/O errors; they cut no power.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ClientId, EnvironmentId, GrantId, PolicyId};
use heimdall_contract::lifecycle::{RestoreEpoch, StateRestoredPayload};
use heimdall_contract::{GrantState, OperationState};
use heimdall_domain::decision::{DecisionRecord, DecisionState};
use heimdall_domain::policy::PauseState;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_stategen::{
    Current, Fs, GenerationName, Ledger, LedgerScan, Operation, Plan, PublishError, Startup,
    StateDir, StateError,
};
use rusqlite::OptionalExtension as _;
use rusqlite::types::Value;

use crate::fence::{RequestFence, restored_before_completion};
use crate::layout::DB_FILE;
use crate::{
    META_AUTHORITY_GENERATION, META_RESTORE_EPOCH, META_SELF_ENVIRONMENT, NoFaults, Result, Store,
    StoreError, Txn, codec,
};

/// The schema version that added the hold records (migration 0017).
const HOLDS_SCHEMA_VERSION: u32 = 17;

/// The `meta` key of M07's page-token key (ADR-0013 §6.2; classified "never in the snapshot").
/// A restore removes it from what it stages and never copies it in either direction; a reset's
/// new store has none. It is not this crate's key to define: the name is matched exactly.
const PAGE_TOKEN_KEY: &str = "page_token_hmac_key";

/// The runner's downgrade marker (`crate::ext_runner`), carried forward.
const RUNNER_OWNER_ONLY: &str = "runner_owner_only";
/// The runner's recorded time source (`crate::ext_runner`): removed when the replaced
/// generation no longer records one.
const RUNNER_TIME_SOURCE: &str = "runner_time_source";
/// The runner's issuer-trust prefix (`crate::ext_runner`): an entry the replaced generation no
/// longer records is removed.
const RUNNER_ISSUER_TRUST_PREFIX: &str = "runner_issuer_trust:";

// --- the hold records (migration 0017) ----------------------------------------------------

/// What a restore put on hold (`restore_holds.kind`; migration 0017).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HoldKind {
    /// A paired management client of this runner, quarantined until reauthorized
    /// (`client_quarantined_after_restore`).
    Client,
    /// An invitation pending or consumed in the backup: void (`invitation_void_after_restore`).
    Invitation,
    /// The Iroh transport's exposure and admission state: disabled
    /// (`exposure_disabled_after_restore`).
    Exposure,
    /// A paired runner environment of this controller: held until reconciled.
    Environment,
    /// A grant the restore ended (`state_restored_authority_ended`).
    Grant,
}

impl HoldKind {
    /// The stored form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Invitation => "invitation",
            Self::Exposure => "exposure",
            Self::Environment => "environment",
            Self::Grant => "grant",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::Client,
            Self::Invitation,
            Self::Exposure,
            Self::Environment,
            Self::Grant,
        ]
        .into_iter()
        .find(|k| k.as_str() == text)
    }
}

/// The `ref` of the transport's exposure hold.
pub const EXPOSURE_TRANSPORT: &str = "transport";

/// One hold record (`restore_holds`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreHold {
    /// What is held.
    pub kind: HoldKind,
    /// The item's opaque ID.
    pub reference: String,
    /// The epoch the restore raised to.
    pub epoch: RestoreEpoch,
    /// When.
    pub created_at: Timestamp,
}

impl Txn<'_> {
    /// The hold record of `reference` of `kind`, if any. A store from before migration 0017
    /// holds none.
    ///
    /// # Errors
    /// The store's, or a malformed row.
    pub fn restore_hold(&mut self, kind: HoldKind, reference: &str) -> Result<Option<RestoreHold>> {
        if crate::migrations::user_version(&self.tx)? < HOLDS_SCHEMA_VERSION {
            return Ok(None);
        }
        let row: Option<(i64, String)> = self
            .tx
            .query_row(
                "SELECT epoch, created_at FROM restore_holds WHERE kind = ?1 AND ref = ?2",
                [kind.as_str(), reference],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(epoch, created)| {
            Ok(RestoreHold {
                kind,
                reference: reference.to_owned(),
                epoch: RestoreEpoch(codec::uint(epoch)?),
                created_at: codec::parse_ts(&created)?,
            })
        })
        .transpose()
    }

    /// Every hold record, of `kind` or of every kind, ordered by kind and reference.
    ///
    /// # Errors
    /// The store's, or a malformed row.
    pub fn restore_holds(&mut self, kind: Option<HoldKind>) -> Result<Vec<RestoreHold>> {
        if crate::migrations::user_version(&self.tx)? < HOLDS_SCHEMA_VERSION {
            return Ok(Vec::new());
        }
        let rows: Vec<(String, String, i64, String)> = {
            let mut stmt = self.tx.prepare(
                "SELECT kind, ref, epoch, created_at FROM restore_holds
                 WHERE ?1 IS NULL OR kind = ?1 ORDER BY kind, ref",
            )?;
            let rows = stmt.query_map([kind.map(HoldKind::as_str)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        rows.into_iter()
            .map(|(kind, reference, epoch, created)| {
                Ok(RestoreHold {
                    kind: HoldKind::parse(&kind)
                        .ok_or_else(|| codec::doc_error("a hold record's kind is unknown"))?,
                    reference,
                    epoch: RestoreEpoch(codec::uint(epoch)?),
                    created_at: codec::parse_ts(&created)?,
                })
            })
            .collect()
    }

    /// ⟨ADR-0014 §3.6 step 6⟩ **Reauthorize** a paired management client the restore
    /// quarantined: remove its `client` hold. Only the owner, attended at this machine, calls
    /// this (the runtime's `PairedRunner::reauthorize_client`); it admits the requests the
    /// client mints after a fresh hello and reopens nothing else (its pre-restore request IDs
    /// stay refused by their epoch and their fences, and its decision references stay stale).
    /// Only a client hold is ever removed. Returns whether one was.
    ///
    /// # Errors
    /// The store's.
    pub fn lift_client_hold(&mut self, client: &ClientId) -> Result<bool> {
        if crate::migrations::user_version(&self.tx)? < HOLDS_SCHEMA_VERSION {
            return Ok(false);
        }
        let n = self.tx.execute(
            "DELETE FROM restore_holds WHERE kind = 'client' AND ref = ?1",
            [client.as_str()],
        )?;
        Ok(n > 0)
    }

    fn put_hold(
        &mut self,
        kind: HoldKind,
        reference: &str,
        epoch: RestoreEpoch,
        at: Timestamp,
    ) -> Result<()> {
        self.tx.execute(
            "INSERT INTO restore_holds (kind, ref, epoch, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(kind, ref) DO UPDATE SET epoch = excluded.epoch,
                 created_at = excluded.created_at",
            rusqlite::params![
                kind.as_str(),
                reference,
                codec::int(epoch.0)?,
                codec::ts(at)
            ],
        )?;
        Ok(())
    }
}

// --- refusals, errors and the report --------------------------------------------------------

/// Why a restore, a reset or a repair was refused. Nothing was changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The file is not a Heimdall backup, cannot be read, or fails its integrity check.
    #[error("the file is not a backup of a Heimdall state store: {0}")]
    NotABackup(&'static str),
    /// The backup's schema is newer than this build's (`state_newer_than_build`).
    #[error("the backup's schema {found} is newer than this build's {supported}")]
    NewerThanBuild {
        /// Found in the backup.
        found: u32,
        /// This build's.
        supported: u32,
    },
    /// The backup belongs to another environment. Replacing the identity is a reset.
    #[error("the backup belongs to another environment; replacing the identity is `state reset`")]
    EnvironmentMismatch,
    /// With no trusted record to bind the backup to, only a backup under this installation's
    /// own backup names is accepted.
    #[error(
        "with no readable record of this installation's identity, only a backup under its own backup names is accepted"
    )]
    NotOwnBackup,
    /// The state is in no condition for this: the reason says which.
    #[error("{0}")]
    WrongState(&'static str),
    /// The current state is damaged and the owner has not confirmed the recovery from it.
    #[error("the state is damaged: the attended recovery must be confirmed")]
    RecoveryNotConfirmed,
    /// The current store is newer than this build (`state_newer_than_build`).
    #[error("the state store is newer than this build")]
    StoreNewerThanBuild,
}

/// A restore's, a reset's or a repair's failure.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// Refused before anything was changed.
    #[error("refused: {0}")]
    Refused(Refusal),
    /// The store's or the layout's error. Before the switch the earlier state is untouched;
    /// at or after it, the next start settles it (`heimdall_stategen::StateError`).
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<Refusal> for RestoreError {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

fn layout_err(e: StateError) -> RestoreError {
    match e {
        StateError::Corrupt(reason) => RestoreError::Store(StoreError::Corrupt(format!(
            "state_corrupt: {}",
            reason.code()
        ))),
        StateError::Refused(heimdall_stategen::Refusal::EnvironmentMismatch) => {
            RestoreError::Refused(Refusal::EnvironmentMismatch)
        }
        other => RestoreError::Store(StoreError::Layout(other)),
    }
}

fn publish_err(e: PublishError<RestoreError>) -> RestoreError {
    match e {
        PublishError::State(e) => layout_err(e),
        PublishError::Caller(e) => e,
    }
}

/// What a backup file is ([`inspect_backup`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFacts {
    /// The environment ID the backup records (`meta.self_environment_id`).
    pub environment: EnvironmentId,
    /// Its schema version.
    pub schema_version: u32,
    /// Its restore epoch (0 before migration 0014).
    pub restore_epoch: RestoreEpoch,
    /// Its SHA-256, 64 lower-case hex digits.
    pub sha256: String,
}

/// The `state_restored` event's writer: the application's event publisher, the one writer of
/// events. It is called with the staged store after the sanitizing transaction committed, and
/// before the staged database is closed.
pub trait RestoreEvent {
    /// Append the `state_restored` event with `payload` to `store`, the staged store of
    /// `environment`.
    ///
    /// # Errors
    /// The store's.
    fn append(
        &self,
        store: &Arc<Store>,
        environment: &EnvironmentId,
        payload: &StateRestoredPayload,
        at: Timestamp,
    ) -> Result<()>;
}

/// A restore's report (ADR-0014 §3.6, the protocol's item 6).
#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    /// The new current generation.
    pub current: Current,
    /// The generation it replaced, kept whole under its own name (`None` from a flat store
    /// that was never adopted).
    pub left_behind: Option<GenerationName>,
    /// What it ended, quarantined and voided (the `state_restored` event's payload).
    pub ended: StateRestoredPayload,
    /// Requests fenced from the ledger.
    pub fenced_requests: u64,
    /// Whether the request ledger was read whole (`false`: damaged or unreadable; every
    /// decodable record was fenced all the same).
    pub ledger_readable: bool,
    /// Whether the replaced generation was readable, so its more restrictive states and later
    /// terminal records were carried forward.
    pub carried_forward: bool,
    /// Remote effects pending until acknowledged (the controller's undelivered narrowing
    /// effects in the restored store).
    pub remote_effects_pending: u64,
    /// Remote residue the restore cannot remove (opaque references): pairings and
    /// enrollments the replaced generation recorded and the backup does not.
    pub remote_residue: Vec<String>,
    /// The K_iroh references the restore withdrew: their platform items stay until
    /// `transport disable` removes them.
    pub transport_keys_withdrawn: Vec<String>,
}

/// What to restore, and how ([`restore_locked`]).
pub struct RestoreRequest<'a> {
    /// The backup file the owner named.
    pub backup: &'a Path,
    /// The restore's time.
    pub now: Timestamp,
    /// The owner confirmed the attended recovery from a damaged state (with no trusted record
    /// of the identity). Without it a damaged state refuses
    /// ([`Refusal::RecoveryNotConfirmed`]).
    pub recovery_confirmed: bool,
    /// The event's writer.
    pub event: &'a dyn RestoreEvent,
    /// The operations' retention (ADR-0006 §7.4): an operation the restore closes as stale
    /// keeps its record that long from the restore.
    pub operation_retention: std::time::Duration,
}

/// What [`plan_restore`] found: where the restore stands before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    /// The backup.
    pub backup: BackupFacts,
    /// Whether the current state is damaged (an attended recovery).
    pub recovery: bool,
    /// The environment ID of the current generation's record, when there is a trusted one.
    pub bound_to: Option<String>,
}

// --- the backup -------------------------------------------------------------------------------

/// Read the backup at `path` **without writing anything** and check it (the protocol's item 1):
/// a SQLite database that passes `integrity_check` and `foreign_key_check`, with a Heimdall
/// schema no newer than this build's and the tables of its version, and an environment ID.
///
/// # Errors
/// [`Refusal::NotABackup`] or [`Refusal::NewerThanBuild`]; the store's for an I/O failure.
pub fn inspect_backup(path: &Path) -> std::result::Result<BackupFacts, RestoreError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|_| Refusal::NotABackup("it cannot be read"))?;
    if !meta.file_type().is_file() {
        return Err(Refusal::NotABackup("it is not a regular file").into());
    }
    let conn = open_backup(path)?;
    let version = match crate::migrations::check_version(&conn, crate::migrations::MIGRATIONS) {
        Ok(0) => return Err(Refusal::NotABackup("it holds no Heimdall schema").into()),
        Ok(v) => v,
        Err(StoreError::NewerSchema { found, supported }) => {
            return Err(Refusal::NewerThanBuild { found, supported }.into());
        }
        Err(StoreError::AdoptionFenced) => {
            return Err(Refusal::NotABackup("it is a store fenced for adoption").into());
        }
        Err(_) => return Err(Refusal::NotABackup("its schema version cannot be read").into()),
    };
    crate::integrity_check(&conn)
        .map_err(|_| Refusal::NotABackup("it fails its integrity check"))?;
    let environment: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_SELF_ENVIRONMENT],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Refusal::NotABackup("it has no Heimdall metadata"))?;
    let environment = environment
        .as_deref()
        .and_then(|t| EnvironmentId::parse(t).ok())
        .ok_or(Refusal::NotABackup("it records no environment ID"))?;
    let epoch = if version >= 14 {
        let text: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_RESTORE_EPOCH],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Refusal::NotABackup("its restore epoch cannot be read"))?;
        text.as_deref()
            .and_then(crate::parse_restore_epoch)
            .map(RestoreEpoch)
            .ok_or(Refusal::NotABackup(
                "its restore epoch is missing or malformed",
            ))?
    } else {
        RestoreEpoch(0)
    };
    drop(conn);
    let sha256 = heimdall_stategen::record::sha256_file(path)
        .map_err(|_| Refusal::NotABackup("it cannot be read"))?;
    Ok(BackupFacts {
        environment,
        schema_version: version,
        restore_epoch: epoch,
        sha256,
    })
}

/// A read-only connection to a backup that **writes no file**, not even SQLite's log or index
/// beside it: with no write-ahead log present the file is the whole database and is opened
/// `immutable`; with one, `readonly_shm` reads the log without writing (`Store::
/// open_read_only_quiescent`'s rule). A backup no one can open this way is refused.
fn open_backup(path: &Path) -> std::result::Result<rusqlite::Connection, RestoreError> {
    let refuse = || Refusal::NotABackup("it cannot be opened as a database");
    let conn = open_quiet(path).ok_or_else(refuse)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| refuse())?;
    for (pragma, value) in [("query_only", "ON"), ("trusted_schema", "OFF")] {
        conn.pragma_update(None, pragma, value)
            .map_err(|_| refuse())?;
    }
    Ok(conn)
}

/// A read-only connection to the database at `path` that writes no file of its family
/// (`open_backup`), or `None`.
fn open_quiet(path: &Path) -> Option<rusqlite::Connection> {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let query = if std::fs::symlink_metadata(PathBuf::from(wal)).is_ok() {
        "mode=ro&readonly_shm=1"
    } else {
        "mode=ro&immutable=1"
    };
    let uri = crate::file_uri(path, query)?;
    rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .ok()
}

/// Whether `backup` is under one of this installation's own backup names: a migration backup
/// (`state.db.v<N>.backup`, or with `.<n>` after it) in the state directory `state_dir` itself
/// (a flat store's) or directly in one of its generation directories. Paths are compared after
/// resolving links, and the file itself must not be a link.
#[must_use]
pub fn is_own_backup(state_dir: &Path, backup: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(backup) else {
        return false;
    };
    if !meta.file_type().is_file() {
        return false;
    }
    let (Ok(file), Ok(root)) = (backup.canonicalize(), state_dir.canonicalize()) else {
        return false;
    };
    let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(rest) = name.strip_prefix(&format!("{DB_FILE}.v")) else {
        return false;
    };
    let (version, tail) = rest.split_once('.').unwrap_or((rest, ""));
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    let suffix_ok = match tail.strip_prefix("backup") {
        Some("") => true,
        Some(more) => more.strip_prefix('.').is_some_and(digits),
        None => false,
    };
    if !digits(version) || !suffix_ok {
        return false;
    }
    let Some(parent) = file.parent() else {
        return false;
    };
    parent == root
        || (parent.parent() == Some(&root.join(heimdall_stategen::generations::GENERATIONS))
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(GenerationName::parse)
                .is_some())
}

// --- the plan ---------------------------------------------------------------------------------

/// What the current state is, for a restore or a reset (read only).
enum Standing {
    /// The pointer names a complete generation.
    Serving(Box<Current>),
    /// No pointer: a flat store a build before generations wrote, which cannot be read.
    FlatUnreadable,
    /// No pointer and no flat store, or a flat store that is readable (adopted at the next
    /// start).
    NotAdopted { flat: bool },
    /// The layout is `state_corrupt`; with the record of the generation the pointer names,
    /// when that record can be read.
    Corrupt {
        record: Option<heimdall_stategen::OperationRecord>,
    },
}

fn standing(state_dir: &Path, fs: &dyn Fs) -> std::result::Result<Standing, RestoreError> {
    let state = StateDir::new(fs, state_dir);
    match state.inspect() {
        Ok(Startup::Serving(current)) => Ok(Standing::Serving(Box::new(current))),
        Ok(Startup::Empty | Startup::FirstPublicationPending { .. }) => {
            let flat = state_dir.join(DB_FILE);
            match crate::layout::probe_flat_readable(&flat) {
                Ok(present) => Ok(Standing::NotAdopted { flat: present }),
                Err(StoreError::NewerSchema { .. }) => Err(Refusal::StoreNewerThanBuild.into()),
                Err(_) => Ok(Standing::FlatUnreadable),
            }
        }
        Err(StateError::Corrupt(_)) => {
            // The record of the generation the pointer names, when the pointer and the record
            // can both be read (a generation whose database is missing, for example).
            let record = state
                .pointer()
                .ok()
                .flatten()
                .and_then(|name| read_record(&state, &name));
            Ok(Standing::Corrupt { record })
        }
        Err(e) => Err(layout_err(e)),
    }
}

fn read_record(
    state: &StateDir<&dyn Fs>,
    name: &GenerationName,
) -> Option<heimdall_stategen::OperationRecord> {
    state.record_unchecked(name)
}

/// Check a restore before anything is written (read only): the backup, and where the state
/// stands. The CLI shows the result to the owner and asks for the typed confirmation.
///
/// # Errors
/// The refusals of [`inspect_backup`]; [`Refusal::EnvironmentMismatch`];
/// [`Refusal::NotOwnBackup`]; [`Refusal::WrongState`] for a new installation or a flat store
/// not yet adopted; [`Refusal::StoreNewerThanBuild`].
pub fn plan_restore(
    state_dir: &Path,
    fs: &dyn Fs,
    backup: &Path,
) -> std::result::Result<RestorePlan, RestoreError> {
    let facts = inspect_backup(backup)?;
    let (recovery, bound_to) = match standing(state_dir, fs)? {
        Standing::Serving(current) => (false, Some(current.record.environment_id.clone())),
        Standing::Corrupt { record: Some(r) } => (true, Some(r.environment_id)),
        Standing::Corrupt { record: None } | Standing::FlatUnreadable => (true, None),
        Standing::NotAdopted { flat: true } => {
            return Err(Refusal::WrongState(
                "this installation's store has not been adopted into the generation layout yet: start the runtime once (`heimdall service run`), stop it, then restore",
            )
            .into());
        }
        Standing::NotAdopted { flat: false } => {
            return Err(Refusal::WrongState(
                "there is no state store here to restore into: this is a new installation",
            )
            .into());
        }
    };
    match &bound_to {
        Some(env) if env != facts.environment.as_str() => {
            return Err(Refusal::EnvironmentMismatch.into());
        }
        Some(_) => {}
        None if !is_own_backup(state_dir, backup) => return Err(Refusal::NotOwnBackup.into()),
        None => {}
    }
    Ok(RestorePlan {
        backup: facts,
        recovery,
        bound_to,
    })
}

// --- the carry-forward ------------------------------------------------------------------------

/// The replaced generation, read through SQLite inside a `BEGIN IMMEDIATE` transaction that is
/// held until it is dropped and then rolled back (module docs). It writes nothing.
struct Replaced {
    conn: rusqlite::Connection,
}

impl Replaced {
    /// Open the generation's database at `db` (never created), take its write lock, and check
    /// it. `None` when it cannot be read: everything recovered is then treated as possibly
    /// revoked, which is what the sanitization does.
    fn open(db: &Path) -> Option<Self> {
        let conn = rusqlite::Connection::open_with_flags(
            db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        conn.busy_timeout(std::time::Duration::from_secs(5)).ok()?;
        conn.pragma_update(None, "trusted_schema", "OFF").ok()?;
        conn.execute_batch("BEGIN IMMEDIATE").ok()?;
        let readable = crate::migrations::check_version(&conn, crate::migrations::MIGRATIONS)
            .is_ok_and(|v| v > 0)
            && crate::integrity_check(&conn).is_ok();
        if !readable {
            let _ = conn.execute_batch("ROLLBACK");
            return None;
        }
        Some(Self { conn })
    }

    fn version(&self) -> u32 {
        crate::migrations::user_version(&self.conn).unwrap_or(0)
    }

    fn has_table(&self, table: &str) -> bool {
        self.conn
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false)
    }

    fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }
}

impl Drop for Replaced {
    fn drop(&mut self) {
        let _ = self.conn.execute_batch("ROLLBACK");
    }
}

/// One row, column by column.
type Row = Vec<(String, Value)>;

/// The stored columns of `table` (generated and hidden columns left out), and the primary key's.
fn columns(conn: &rusqlite::Connection, table: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut stmt =
        conn.prepare("SELECT name, pk, hidden FROM pragma_table_xinfo(?1) ORDER BY cid")?;
    let rows = stmt.query_map([table], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut all = Vec::new();
    let mut pk: Vec<(i64, String)> = Vec::new();
    for row in rows {
        let (name, key, hidden) = row?;
        if hidden != 0 {
            continue;
        }
        if key > 0 {
            pk.push((key, name.clone()));
        }
        all.push(name);
    }
    pk.sort();
    Ok((all, pk.into_iter().map(|(_, n)| n).collect()))
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The rows of `table` in the replaced generation matching `filter` (an SQL condition over its
/// columns), restricted to the columns the staged table also has.
fn old_rows(
    old: &Replaced,
    staged: &rusqlite::Connection,
    table: &str,
    filter: &str,
) -> Result<Vec<Row>> {
    if !old.has_table(table) {
        return Ok(Vec::new());
    }
    let (theirs, _) = columns(&old.conn, table)?;
    let (ours, _) = columns(staged, table)?;
    let shared: Vec<String> = theirs.into_iter().filter(|c| ours.contains(c)).collect();
    if shared.is_empty() {
        return Ok(Vec::new());
    }
    let list = shared
        .iter()
        .map(|c| quoted(c))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {list} FROM {} WHERE {filter}", quoted(table));
    let mut stmt = old.conn.prepare(&sql)?;
    let n = shared.len();
    let rows = stmt.query_map([], |r| {
        let mut row = Vec::with_capacity(n);
        for (i, name) in shared.iter().enumerate() {
            row.push((name.clone(), r.get::<_, Value>(i)?));
        }
        Ok(row)
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn value<'a>(row: &'a Row, column: &str) -> Option<&'a Value> {
    row.iter().find(|(c, _)| c == column).map(|(_, v)| v)
}

fn text(row: &Row, column: &str) -> Option<String> {
    match value(row, column) {
        Some(Value::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

/// How [`put_row`] treats a row whose primary key the staged table already holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnKey {
    /// Keep the staged row.
    Keep,
    /// Replace its other columns with the carried ones (an `UPDATE`, never a delete, so
    /// nothing cascades).
    Update,
}

/// Write `row` into the staged `table`. Returns whether a row was written.
fn put_row(tx: &rusqlite::Transaction<'_>, table: &str, row: &Row, on_key: OnKey) -> Result<bool> {
    let names: Vec<&str> = row.iter().map(|(c, _)| c.as_str()).collect();
    let list = names
        .iter()
        .map(|c| quoted(c))
        .collect::<Vec<_>>()
        .join(", ");
    let marks = (1..=names.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = match on_key {
        // Any row that would conflict with one the staged table holds is skipped.
        OnKey::Keep => format!(
            "INSERT OR IGNORE INTO {} ({list}) VALUES ({marks})",
            quoted(table)
        ),
        OnKey::Update => {
            let (_, pk) = columns(tx, table)?;
            let key = pk.iter().map(|c| quoted(c)).collect::<Vec<_>>().join(", ");
            let sets: Vec<String> = names
                .iter()
                .filter(|c| !pk.iter().any(|k| k == *c))
                .map(|c| format!("{} = excluded.{}", quoted(c), quoted(c)))
                .collect();
            if pk.is_empty() || sets.is_empty() {
                format!(
                    "INSERT OR IGNORE INTO {} ({list}) VALUES ({marks})",
                    quoted(table)
                )
            } else {
                format!(
                    "INSERT INTO {} ({list}) VALUES ({marks}) ON CONFLICT({key}) DO UPDATE SET {}",
                    quoted(table),
                    sets.join(", ")
                )
            }
        }
    };
    let params: Vec<&dyn rusqlite::ToSql> =
        row.iter().map(|(_, v)| v as &dyn rusqlite::ToSql).collect();
    Ok(tx.execute(&sql, params.as_slice())? > 0)
}

/// What the carry-forward took from the replaced generation, for the report.
#[derive(Debug, Default)]
struct Carried {
    /// Pairings and enrollments the replaced generation recorded and the backup does not.
    residue: Vec<String>,
}

/// The rank of a CA's state on its way to retirement (ADR-0008 D4 item 3).
fn ca_rank(state: &str) -> u8 {
    match state {
        "pending" => 0,
        "active" => 1,
        "retiring" => 2,
        "unloaded" => 3,
        "deleted" => 4,
        "retired" => 5,
        _ => 0,
    }
}

/// The enrollment states that are a removal under way or final (ADR-0008 D5 §6.2).
const ENROLLMENT_REMOVED: &[&str] = &[
    "rollback_pending",
    "rollback_unknown",
    "removing",
    "remove_unknown",
    "manual_removal_pending",
    "removal_verifying",
    "verification_failed",
    "removed",
    "withdrawn",
    "failed_unwritten",
    "abandoned",
];

fn settled_states_sql() -> Result<String> {
    crate::sql_in_list(&crate::operation_states(OperationState::is_settled))
}

/// The carry-forward (module docs), in the staged store's transaction, before the
/// sanitization.
fn carry_forward(tx: &mut Txn<'_>, old: &Replaced) -> Result<Carried> {
    let mut carried = Carried::default();
    let staged: &rusqlite::Transaction<'_> = &tx.tx;
    // Terminal operations and their idempotency records.
    let settled = settled_states_sql()?;
    let ops = old_rows(old, staged, "operations", &format!("state IN ({settled})"))?;
    let mut carried_ops = BTreeSet::new();
    for row in &ops {
        let Some(id) = text(row, "id") else { continue };
        let staged_state: Option<String> = staged
            .query_row("SELECT state FROM operations WHERE id = ?1", [&id], |r| {
                r.get(0)
            })
            .optional()?;
        let already_settled = staged_state
            .as_deref()
            .is_some_and(|s| settled.contains(&format!("'{s}'")));
        if !already_settled {
            put_row(staged, "operations", row, OnKey::Update)?;
            carried_ops.insert(id);
        }
    }
    for row in old_rows(old, staged, "idempotency", "1")? {
        if text(&row, "operation_id").is_some_and(|op| carried_ops.contains(&op)) {
            put_row(staged, "idempotency", &row, OnKey::Update)?;
        }
    }
    // Expired-key markers, terminal records and fences: the later of each.
    for row in old_rows(old, staged, "idempotency_markers", "1")? {
        if let (Some(hash), Some(expired), Some(until)) = (
            text(&row, "key_hash"),
            text(&row, "expired_at"),
            text(&row, "marker_until"),
        ) {
            staged.execute(
                "INSERT INTO idempotency_markers (key_hash, expired_at, marker_until)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key_hash) DO UPDATE SET
                     expired_at = max(expired_at, excluded.expired_at),
                     marker_until = max(marker_until, excluded.marker_until)",
                [hash, expired, until],
            )?;
        }
    }
    for row in old_rows(old, staged, "request_terminals", "1")? {
        if let (Some(digest), Some(settled_at), Some(trim_after)) = (
            text(&row, "key_digest"),
            text(&row, "settled_at"),
            text(&row, "trim_after"),
        ) {
            staged.execute(
                "INSERT INTO request_terminals (key_digest, settled_at, trim_after, trimmable)
                 VALUES (?1, ?2, ?3, 0)
                 ON CONFLICT(key_digest) DO UPDATE SET
                     settled_at = max(settled_at, excluded.settled_at),
                     trim_after = max(trim_after, excluded.trim_after),
                     trimmable = 0",
                [digest, settled_at, trim_after],
            )?;
        }
    }
    for row in old_rows(old, staged, "request_fences", "1")? {
        put_row(staged, "request_fences", &row, OnKey::Keep)?;
    }
    // Decisions made after the backup: carried closed as stale, under their own epoch.
    for row in old_rows(old, staged, "decisions", "1")? {
        let Some(id) = text(&row, "id") else { continue };
        let known: bool = staged.query_row(
            "SELECT count(*) > 0 FROM decisions WHERE id = ?1",
            [&id],
            |r| r.get(0),
        )?;
        if known {
            continue;
        }
        let Some(doc) = text(&row, "record_json") else {
            continue;
        };
        let Ok(mut record) = codec::parse_doc::<DecisionRecord>(&doc) else {
            continue;
        };
        if record.state == DecisionState::Pending {
            record.state = DecisionState::Stale;
        }
        let mut stale = row.clone();
        for (column, v) in &mut stale {
            match column.as_str() {
                "state" => *v = Value::Text(codec::enum_str(&record.state)?),
                "record_json" => *v = Value::Text(codec::doc(&record)?),
                _ => {}
            }
        }
        put_row(staged, "decisions", &stale, OnKey::Keep)?;
    }
    // Grant tombstones: the replaced generation's revocation record, for a grant the backup
    // knows (the sanitization then ends every grant still live).
    for row in old_rows(old, staged, "tombstones", "1")? {
        let Some(grant) = text(&row, "grant_id") else {
            continue;
        };
        let known: bool = staged.query_row(
            "SELECT count(*) > 0 FROM grants WHERE id = ?1",
            [&grant],
            |r| r.get(0),
        )?;
        if known {
            put_row(staged, "tombstones", &row, OnKey::Keep)?;
        }
    }
    // Client tombstones (the admission authority): revoked there, revoked here.
    for row in old_rows(old, staged, "remote_clients", "state = 'revoked'")? {
        put_row(staged, "remote_clients", &row, OnKey::Update)?;
    }
    // Invitations consumed, expired or revoked there.
    for row in old_rows(old, staged, "remote_invitations", "state <> 'pending'")? {
        let Some(id) = text(&row, "invitation_id") else {
            continue;
        };
        let pending: bool = staged.query_row(
            "SELECT count(*) > 0 FROM remote_invitations WHERE invitation_id = ?1 AND state = 'pending'",
            [&id],
            |r| r.get(0),
        )?;
        if pending {
            put_row(staged, "remote_invitations", &row, OnKey::Update)?;
        }
    }
    // Issuers: the further along retirement.
    for row in old_rows(old, staged, "issuers", "1")? {
        let (Some(ca), Some(theirs)) = (text(&row, "ca_fingerprint"), text(&row, "state")) else {
            continue;
        };
        let ours: Option<String> = staged
            .query_row(
                "SELECT state FROM issuers WHERE ca_fingerprint = ?1",
                [&ca],
                |r| r.get(0),
            )
            .optional()?;
        if ours.is_some_and(|o| ca_rank(&theirs) > ca_rank(&o)) {
            put_row(staged, "issuers", &row, OnKey::Update)?;
        }
    }
    // Enrollments: a removal under way or final there.
    let removed = ENROLLMENT_REMOVED
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");
    for row in old_rows(old, staged, "enrollments", &format!("state IN ({removed})"))? {
        let (Some(id), Some(theirs)) = (text(&row, "id"), text(&row, "state")) else {
            continue;
        };
        let ours: Option<String> = staged
            .query_row("SELECT state FROM enrollments WHERE id = ?1", [&id], |r| {
                r.get(0)
            })
            .optional()?;
        if ours.is_some_and(|o| o != theirs && !ENROLLMENT_REMOVED.contains(&o.as_str())) {
            // A row that would break an index (another open enrollment of the pair) is left
            // as the backup has it: the removal is the remote host's fact, never undone here.
            let _ = put_row(staged, "enrollments", &row, OnKey::Update);
        }
    }
    // Pairings: an environment the replaced generation no longer pins is unpaired.
    if old.has_table("remote_environment_pins") {
        let theirs: BTreeSet<String> = {
            let mut stmt = old
                .conn
                .prepare("SELECT environment_id FROM remote_environment_pins")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let ours: Vec<(EnvironmentId, String)> = tx.remote_environment_pins()?;
        for (environment, _) in ours {
            if !theirs.contains(environment.as_str()) {
                tx.remove_remote_environment_pin(&environment)?;
                tx.forget_delivered_grants(&environment)?;
            }
        }
        let staged_pins: BTreeSet<String> = tx
            .remote_environment_pins()?
            .into_iter()
            .map(|(e, _)| e.as_str().to_owned())
            .collect();
        carried.residue.extend(
            theirs
                .difference(&staged_pins)
                .map(|e| format!("pairing:{e}")),
        );
    }
    // Enrollments the backup does not know: lines on remote hosts this store cannot remove.
    if old.has_table("enrollments") {
        let open: Vec<String> = {
            let mut stmt = old.conn.prepare(&format!(
                "SELECT id FROM enrollments WHERE state NOT IN ({removed}) ORDER BY id"
            ))?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let staged: &rusqlite::Transaction<'_> = &tx.tx;
        for id in open {
            let known: bool = staged.query_row(
                "SELECT count(*) > 0 FROM enrollments WHERE id = ?1",
                [&id],
                |r| r.get(0),
            )?;
            if !known {
                carried.residue.push(format!("enrollment:{id}"));
            }
        }
    }
    let staged: &rusqlite::Transaction<'_> = &tx.tx;
    // The runner's effect ledger and delivered policy revisions (narrowings compose), and the
    // controller's outbox: what was delivered or acknowledged there is a fact here.
    for row in old_rows(old, staged, "remote_effect_acks", "1")? {
        put_row(staged, "remote_effect_acks", &row, OnKey::Keep)?;
    }
    for row in old_rows(old, staged, "remote_policy_revisions", "1")? {
        put_row(staged, "remote_policy_revisions", &row, OnKey::Keep)?;
    }
    for row in old_rows(old, staged, "remote_effect_outbox", "state <> 'pending'")? {
        put_row(staged, "remote_effect_outbox", &row, OnKey::Update)?;
    }
    for row in old_rows(old, staged, "remote_effect_outbox", "state = 'pending'")? {
        put_row(staged, "remote_effect_outbox", &row, OnKey::Keep)?;
    }
    // The runner's downgrade marker, and its runner-local widenings removed since the backup.
    if let Some(marker) = old.meta(RUNNER_OWNER_ONLY)? {
        match codec::parse_doc::<crate::ext_runner::RunnerDowngrade>(&marker) {
            Ok(standing) => {
                tx.carry_runner_downgrade(&standing)?;
            }
            // A row that does not parse reads as "downgraded" everywhere (fail closed): it
            // is kept as it is, unless one stands here already.
            Err(_) => {
                if tx.runner_downgrade().is_ok_and(|d| d.is_none()) {
                    tx.set_meta(RUNNER_OWNER_ONLY, &marker)?;
                }
            }
        }
    }
    if old.meta(RUNNER_TIME_SOURCE)?.is_none() {
        tx.delete_meta(RUNNER_TIME_SOURCE)?;
    }
    let trusted: Vec<String> = {
        let mut stmt = tx
            .tx
            .prepare("SELECT key FROM meta WHERE substr(key, 1, ?2) = ?1")?;
        let rows = stmt.query_map(
            rusqlite::params![
                RUNNER_ISSUER_TRUST_PREFIX,
                i64::try_from(RUNNER_ISSUER_TRUST_PREFIX.len()).unwrap_or(i64::MAX)
            ],
            |r| r.get::<_, String>(0),
        )?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for key in trusted {
        if old.meta(&key)?.is_none() {
            tx.delete_meta(&key)?;
        }
    }
    // The authority generations never go back.
    if let Some(theirs) = old
        .meta(META_AUTHORITY_GENERATION)?
        .and_then(|t| t.parse::<u64>().ok())
    {
        let ours = tx.authority_generation()?.0;
        if theirs > ours {
            tx.set_meta(META_AUTHORITY_GENERATION, &theirs.to_string())?;
        }
    }
    if old.has_table("remote_authority_generation") {
        let theirs: Option<i64> = old
            .conn
            .query_row(
                "SELECT generation FROM remote_authority_generation WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(theirs) = theirs {
            tx.tx.execute(
                "INSERT INTO remote_authority_generation (id, generation, updated_at)
                 VALUES (1, ?1, '1970-01-01T00:00:00Z')
                 ON CONFLICT(id) DO UPDATE SET generation = max(generation, excluded.generation)",
                [theirs],
            )?;
        }
    }
    carried.residue.sort();
    carried.residue.dedup();
    Ok(carried)
}

// --- the sanitization ------------------------------------------------------------------------

/// What the sanitization did ([`sanitize`]).
#[derive(Debug)]
struct Sanitized {
    payload: StateRestoredPayload,
    transport_keys: Vec<String>,
}

/// ADR-0014 §3.6's table, in the staged store (module docs). `cutoffs` are the replaced
/// generation's policy cutoffs, when it was readable.
fn sanitize(
    tx: &mut Txn<'_>,
    epoch: RestoreEpoch,
    now: Timestamp,
    retention: std::time::Duration,
    cutoffs: &OldPolicies,
) -> Result<Sanitized> {
    let mut out = Sanitized {
        payload: StateRestoredPayload {
            restore_epoch: epoch,
            grants_ended: Vec::new(),
            policies_paused: Vec::new(),
            decisions_closed: Vec::new(),
            operations_closed: Vec::new(),
            clients_quarantined: Vec::new(),
            invitations_voided: Vec::new(),
            exposure_disabled: Vec::new(),
        },
        transport_keys: Vec::new(),
    };
    // Grants: ended with a tombstone each; their active bindings released.
    let live: Vec<heimdall_domain::grant::GrantSnapshot> = tx.live_grants()?;
    for mut grant in live {
        tx.insert_tombstone(&Tombstone {
            grant: grant.id.clone(),
            cascade: Vec::new(),
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            revoked_at: now,
            remote_pending: Vec::new(),
            cause: RevocationCause::AuthorityWithdrawn,
        })?;
        grant.state = GrantState::Revoked;
        tx.update_grant_state(&grant)?;
        end_bindings(tx, &grant.id, now)?;
        tx.put_hold(HoldKind::Grant, grant.id.as_str(), epoch, now)?;
        out.payload.grants_ended.push(grant.id);
    }
    // Standing policies: paused, with a cutoff at the restore time or earlier. One the
    // replaced generation no longer has (removed after the backup) stays removed.
    if let Some(theirs) = cutoffs.known() {
        for policy in tx.policies()? {
            if !theirs.contains_key(&policy.id) {
                tx.delete_policy(&policy.id)?;
            }
        }
    }
    for mut policy in tx.policies()? {
        let earlier = cutoffs.cutoff(&policy.id);
        let cutoff = [policy.cutoff_at, earlier, Some(now)]
            .into_iter()
            .flatten()
            .min();
        let paused = match policy.pause {
            PauseState::Paused { since } => PauseState::Paused { since },
            PauseState::Active => PauseState::Paused { since: now },
        };
        if policy.pause != paused || policy.cutoff_at != cutoff {
            policy.pause = paused;
            policy.cutoff_at = cutoff;
            policy.revision = heimdall_domain::policy::PolicyRevision(policy.revision.0 + 1);
            tx.upsert_policy(&policy, true)?;
        }
        out.payload.policies_paused.push(policy.id);
    }
    // Workspace trust: a new attended trust is needed.
    let active: Vec<String> = {
        let mut stmt = tx
            .tx
            .prepare("SELECT id FROM workspaces WHERE state = 'active' ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for id in active {
        let id = heimdall_contract::ids::WorkspaceId::parse(&id)
            .map_err(|_| codec::doc_error("a stored workspace ID is malformed"))?;
        tx.set_workspace_state(
            &id,
            heimdall_domain::workspace::WorkspaceState::Active,
            heimdall_domain::workspace::WorkspaceState::Stale,
        )?;
    }
    // Pending decisions, pending widening records included: closed as stale.
    for record in tx.pending_decisions()? {
        if tx.remote_widening(&record.id)?.is_some() {
            tx.settle_remote_widening(&record.id, DecisionState::Stale, now, None)?;
        } else {
            let mut stale = record.clone();
            stale.state = DecisionState::Stale;
            tx.write_decision(&stale)?;
        }
        out.payload.decisions_closed.push(record.id);
    }
    // Operations that were not terminal: closed as stale. None resumes.
    let mut open = tx.open_operations()?;
    open.extend(tx.unresolved_operations()?);
    open.sort_by(|a, b| a.id.cmp(&b.id));
    open.dedup_by(|a, b| a.id == b.id);
    let answer = restored_before_completion();
    let expires = jiff::SignedDuration::try_from(retention)
        .ok()
        .and_then(|r| now.checked_add(r).ok())
        .unwrap_or(Timestamp::MAX);
    for mut op in open {
        // The answer a retry gets: the fence's, with the effect this operation had reached.
        let mut detail = answer.clone();
        detail.effect_status = op.effect_status;
        op.state = OperationState::Failed;
        op.code = Some(heimdall_contract::Code::RequestStale);
        op.result = Some(serde_json::json!({ "error": detail }));
        op.updated_at = now;
        tx.update_operation(&op)?;
        match tx.settle_idempotency(&op.key, expires) {
            Ok(()) | Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {}
            Err(e) => return Err(e),
        }
        out.payload.operations_closed.push(op.id);
    }
    // Paired management clients: quarantined until reauthorized.
    for client in tx.remote_clients()? {
        if client.state != crate::ext_m06::ClientState::Revoked {
            tx.put_hold(HoldKind::Client, client.client.as_str(), epoch, now)?;
            out.payload.clients_quarantined.push(client.client);
        }
    }
    // Invitations pending or consumed in the backup: void.
    let invitations: Vec<String> = {
        let mut stmt = tx.tx.prepare(
            "SELECT invitation_id FROM remote_invitations
             WHERE state IN ('pending', 'consumed') ORDER BY invitation_id",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for id in invitations {
        tx.put_hold(HoldKind::Invitation, &id, epoch, now)?;
        out.payload.invitations_voided.push(id);
    }
    // Exposure and admission state: disabled.
    let keys = tx.transport_keys()?;
    let mut disabled = false;
    for key in &keys {
        if key.state == crate::ext_transport::TransportKeyState::Active {
            disabled = true;
            out.transport_keys.push(key.endpoint.as_str().to_owned());
        }
        tx.destroy_transport_key(&key.endpoint, now)?;
    }
    let consents = tx.tx.execute("DELETE FROM route_consents", [])?;
    disabled |= consents > 0;
    disabled |= tx.clear_transport_serve_port()?;
    disabled |= tx.clear_transport_rotation()?;
    disabled |= tx.clear_remote_client_endpoints(now)? > 0;
    tx.narrow_remote_admission(now)?;
    if disabled {
        tx.put_hold(HoldKind::Exposure, EXPOSURE_TRANSPORT, epoch, now)?;
        out.payload
            .exposure_disabled
            .push(EXPOSURE_TRANSPORT.to_owned());
    }
    // Paired runner environments: held until reconciled.
    for (environment, _) in tx.remote_environment_pins()? {
        tx.put_hold(HoldKind::Environment, environment.as_str(), epoch, now)?;
    }
    Ok(out)
}

/// Release every active binding of an ended grant and drop its grant reference.
fn end_bindings(tx: &mut Txn<'_>, grant: &GrantId, now: Timestamp) -> Result<()> {
    for id in tx.bindings_of_grant(grant)? {
        let Some(mut binding) = tx.binding(&id)? else {
            continue;
        };
        if binding.state != heimdall_domain::binding::BindingState::Active {
            continue;
        }
        binding.state = heimdall_domain::binding::BindingState::Released;
        binding.released_at = Some(now);
        tx.tx.execute(
            "UPDATE bindings SET state = ?2, released_at = ?3, record_json = ?4 WHERE id = ?1",
            rusqlite::params![
                binding.id.as_str(),
                codec::enum_str(&binding.state)?,
                codec::ts(now),
                codec::doc(&binding)?,
            ],
        )?;
        tx.tx.execute(
            "DELETE FROM grant_references WHERE binding = ?1",
            [binding.id.as_str()],
        )?;
    }
    Ok(())
}

/// The fence records from the request ledger: every decodable entry with no terminal record
/// in the staged generation (after the carry-forward) is fenced, unresolved (ADR-0014 §3.6
/// step 4). Returns how many were written.
fn fence_entries(
    tx: &mut Txn<'_>,
    entries: &[heimdall_stategen::Entry],
    now: Timestamp,
) -> Result<u64> {
    let terminal = tx.terminal_request_digests()?;
    let mut written = 0u64;
    for entry in heimdall_stategen::ledger::unfenced(entries, |e| terminal.contains(&e.digest)) {
        let fence = RequestFence {
            key_digest: entry.digest,
            epoch: RestoreEpoch(entry.epoch),
            answer: restored_before_completion(),
            created_at: now,
            settlement: None,
        };
        if tx.insert_request_fence(&fence)? {
            written += 1;
        }
    }
    Ok(written)
}

/// Set the staged store's epoch.
fn set_epoch(tx: &mut Txn<'_>, epoch: RestoreEpoch) -> Result<()> {
    tx.tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [META_RESTORE_EPOCH, epoch.0.to_string().as_str()],
    )?;
    Ok(())
}

/// Put a connection's database in rollback-journal mode and check it (the staged database is
/// one file before the switch).
fn close_staged(store: &Store) -> Result<()> {
    let conn = store.lock();
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
        .map_err(codec::classify)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(StoreError::Corrupt(
            "the staged database kept its write-ahead log".to_owned(),
        ));
    }
    crate::integrity_check(&conn)
}

// --- the restore ------------------------------------------------------------------------------

/// The ledger's decodable entries, and whether it was read whole.
fn ledger_entries(
    state_dir: &Path,
    fs: &dyn Fs,
) -> (Vec<heimdall_stategen::Entry>, bool, Option<u64>) {
    match Ledger::new(fs, state_dir).scan() {
        Ok(LedgerScan {
            intact,
            damaged_at,
            after,
            ..
        }) => {
            let whole = damaged_at.is_none();
            let all: Vec<_> = intact.into_iter().chain(after).collect();
            let top = all.iter().map(|e| e.epoch).max();
            (all, whole, top)
        }
        Err(_) => (Vec::new(), false, None),
    }
}

/// **Restore** (module docs), under the runtime's instance lock, which the caller holds, with
/// the runtime and the issuer stopped. `fs` makes every file-system call of the layout (in
/// production the runtime's, whose Windows rename is write-through).
///
/// # Errors
/// - [`RestoreError::Refused`] before anything is written: the refusals of [`plan_restore`],
///   and [`Refusal::RecoveryNotConfirmed`] for a damaged state the owner has not confirmed.
/// - [`RestoreError::Store`]: before the switch the earlier generation is untouched and what
///   was staged is removed; at or after it, the next start settles it.
pub fn restore_locked(
    state_dir: &Path,
    fs: &dyn Fs,
    request: &RestoreRequest<'_>,
) -> std::result::Result<RestoreOutcome, RestoreError> {
    let plan = plan_restore(state_dir, fs, request.backup)?;
    if plan.recovery && !request.recovery_confirmed {
        return Err(Refusal::RecoveryNotConfirmed.into());
    }
    let state = StateDir::new(fs, state_dir);
    // The replaced generation (module docs, "The carry-forward"), read and locked first.
    let (replaced, record_epoch, left_behind) = match standing(state_dir, fs)? {
        Standing::Serving(current) => (
            Replaced::open(&current.dir.join(DB_FILE)),
            current.record.restore_epoch,
            Some(current.name.clone()),
        ),
        Standing::Corrupt { record } => (
            None,
            record.as_ref().map_or(0, |r| r.restore_epoch),
            state.pointer().ok().flatten(),
        ),
        Standing::FlatUnreadable | Standing::NotAdopted { .. } => (None, 0, None),
    };
    let old_epoch = replaced
        .as_ref()
        .filter(|r| r.version() >= 14)
        .and_then(|r| r.meta(META_RESTORE_EPOCH).ok().flatten())
        .and_then(|t| crate::parse_restore_epoch(&t))
        .unwrap_or(0);
    let (entries, ledger_readable, ledger_top) = ledger_entries(state_dir, fs);
    let top = [
        plan.backup.restore_epoch.0,
        record_epoch,
        old_epoch,
        ledger_top.unwrap_or(0),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let epoch = RestoreEpoch(
        top.checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("the restore epoch would overflow".to_owned()))?,
    );
    let cutoffs = match &replaced {
        Some(old) => old_cutoffs(old)?,
        None => OldPolicies::default(),
    };
    let generation = GenerationName::fresh()
        .map_err(|_| StoreError::Corrupt("operating system randomness is unavailable".into()))?;
    let layout_plan = Plan {
        name: generation,
        operation: Operation::Restore,
        created_at: request.now,
        backup_sha256: Some(plan.backup.sha256.clone()),
        environment_id: plan.backup.environment.as_str().to_owned(),
        restore_epoch: epoch.0,
    };
    let mut report: Option<(Sanitized, Carried, u64, u64)> = None;
    let populate = |dir: &Path| -> std::result::Result<Vec<String>, RestoreError> {
        let out = dir.join(DB_FILE);
        let Some(target) = out.to_str() else {
            return Err(StoreError::Corrupt("the staged database path is not UTF-8".into()).into());
        };
        crate::create_owner_only(&out)?;
        {
            let source = open_backup(request.backup)?;
            source
                .pragma_update(None, "query_only", "OFF")
                .map_err(codec::classify)?;
            source
                .execute("VACUUM INTO ?1", [target])
                .map_err(codec::classify)?;
        }
        let (store, _) = Store::open_staged_copy(&out)?;
        let store = Arc::new(store);
        let (sanitized, carried, fenced) = store.transaction(|tx| {
            let carried = match &replaced {
                Some(old) => carry_forward(tx, old)?,
                None => Carried::default(),
            };
            let sanitized = sanitize(
                tx,
                epoch,
                request.now,
                request.operation_retention,
                &cutoffs,
            )?;
            let fenced = fence_entries(tx, &entries, request.now)?;
            set_epoch(tx, epoch)?;
            tx.delete_meta(PAGE_TOKEN_KEY)?;
            Ok((sanitized, carried, fenced))
        })?;
        request.event.append(
            &store,
            &plan.backup.environment,
            &sanitized.payload,
            request.now,
        )?;
        let pending = store.transaction(|tx| {
            Ok(tx.tx.query_row(
                "SELECT count(*) FROM remote_effect_outbox WHERE state = 'pending'",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })?;
        close_staged(&store)?;
        let store = Arc::try_unwrap(store)
            .map_err(|_| StoreError::Corrupt("the staged store is still in use".into()))?;
        drop(store);
        report = Some((sanitized, carried, fenced, codec::uint(pending)?));
        Ok(vec![DB_FILE.to_owned()])
    };
    let current = if plan.recovery {
        state.recover(layout_plan, populate)
    } else {
        state.publish(layout_plan, populate)
    }
    .map_err(publish_err)?;
    let carried_forward = replaced.is_some();
    // The replaced generation's lock is released only after the switch.
    drop(replaced);
    let (sanitized, carried, fenced, pending) =
        report.ok_or_else(|| StoreError::Corrupt("the restore staged nothing".to_owned()))?;
    Ok(RestoreOutcome {
        current,
        left_behind,
        ended: sanitized.payload,
        fenced_requests: fenced,
        ledger_readable,
        carried_forward,
        remote_effects_pending: pending,
        remote_residue: carried.residue,
        transport_keys_withdrawn: sanitized.transport_keys,
    })
}

/// The replaced generation's standing policies and their cutoffs, when it was readable.
#[derive(Debug, Default)]
struct OldPolicies(Option<std::collections::BTreeMap<PolicyId, Option<Timestamp>>>);

impl OldPolicies {
    fn known(&self) -> Option<&std::collections::BTreeMap<PolicyId, Option<Timestamp>>> {
        self.0.as_ref()
    }

    fn cutoff(&self, id: &PolicyId) -> Option<Timestamp> {
        self.0.as_ref().and_then(|m| m.get(id).copied().flatten())
    }
}

/// The replaced generation's policy cutoffs.
fn old_cutoffs(old: &Replaced) -> Result<OldPolicies> {
    let mut out = std::collections::BTreeMap::new();
    if !old.has_table("policies") {
        return Ok(OldPolicies(Some(out)));
    }
    let docs: Vec<String> = {
        let mut stmt = old.conn.prepare("SELECT record_json FROM policies")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for doc in docs {
        if let Ok(policy) = codec::parse_doc::<heimdall_domain::policy::StandingPolicy>(&doc) {
            out.insert(policy.id, policy.cutoff_at);
        }
    }
    Ok(OldPolicies(Some(out)))
}

// --- the reset --------------------------------------------------------------------------------

/// What a reset orphans, read before the confirmation (ADR-0014 §3.2 item 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetInventory {
    /// Whether an inventory was readable (from the old store).
    pub readable: bool,
    /// What the reset orphans, as opaque references: remote enrollments (`enrollment:<id>`),
    /// pairings (`pairing:<environment>`), and management lines this runner wrote for its
    /// clients (`management_line:<client>`).
    pub orphaned: Vec<String>,
    /// Whether the current state is damaged (an attended recovery).
    pub recovery: bool,
    /// The generation the reset replaces, when the pointer names one.
    pub replaces: Option<String>,
}

/// The sentence the owner confirms, typed, when no inventory is readable (ADR-0014 §3.2
/// item 10).
pub const NO_INVENTORY_SENTENCE: &str =
    "Heimdall cannot list what this leaves behind on remote hosts";

/// Read what a reset would orphan (read only). The old store is read through SQLite when it
/// can be; a recovery bundle is the owner's file and is not found here.
///
/// # Errors
/// [`Refusal::WrongState`] for a new installation or a flat store not yet adopted;
/// [`Refusal::StoreNewerThanBuild`].
pub fn reset_inventory(
    state_dir: &Path,
    fs: &dyn Fs,
) -> std::result::Result<ResetInventory, RestoreError> {
    let (db, recovery, replaces) = match standing(state_dir, fs)? {
        Standing::Serving(current) => (
            Some(current.dir.join(DB_FILE)),
            false,
            Some(current.name.as_str().to_owned()),
        ),
        Standing::Corrupt { .. } => {
            let state = StateDir::new(fs, state_dir);
            let named = state.pointer().ok().flatten();
            (
                named
                    .as_ref()
                    .map(|n| state.generation_dir(n).join(DB_FILE)),
                true,
                named.map(|n| n.as_str().to_owned()),
            )
        }
        Standing::FlatUnreadable => (None, true, None),
        Standing::NotAdopted { flat: true } => {
            return Err(Refusal::WrongState(
                "this installation's store has not been adopted into the generation layout yet: start the runtime once (`heimdall service run`), stop it, then reset",
            )
            .into());
        }
        Standing::NotAdopted { flat: false } => {
            return Err(Refusal::WrongState(
                "there is no state store here to reset: this is a new installation",
            )
            .into());
        }
    };
    let orphaned = db.as_deref().and_then(read_inventory);
    Ok(ResetInventory {
        readable: orphaned.is_some(),
        orphaned: orphaned.unwrap_or_default(),
        recovery,
        replaces,
    })
}

/// What the old store records on remote hosts, read through SQLite without writing anything
/// (`None`: unreadable).
fn read_inventory(db: &Path) -> Option<Vec<String>> {
    // Read only, writing no file of the old store's family (`open_quiet`).
    let conn = open_quiet(db)?;
    conn.busy_timeout(std::time::Duration::from_secs(5)).ok()?;
    crate::migrations::check_version(&conn, crate::migrations::MIGRATIONS)
        .ok()
        .filter(|v| *v > 0)?;
    crate::integrity_check(&conn).ok()?;
    let removed = ENROLLMENT_REMOVED
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");
    let mut out = Vec::new();
    let mut list = |sql: &str, prefix: &str| -> Option<()> {
        let present: bool = conn
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [sql.split_whitespace().nth(3).unwrap_or_default()],
                |r| r.get(0),
            )
            .ok()?;
        if !present {
            return Some(());
        }
        let mut stmt = conn.prepare(sql).ok()?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).ok()?;
        for row in rows {
            out.push(format!("{prefix}:{}", row.ok()?));
        }
        Some(())
    };
    list(
        &format!("SELECT id FROM enrollments WHERE state NOT IN ({removed}) ORDER BY id"),
        "enrollment",
    )?;
    list(
        "SELECT environment_id FROM remote_environment_pins ORDER BY environment_id",
        "pairing",
    )?;
    list(
        "SELECT client_id FROM remote_clients WHERE state <> 'revoked' ORDER BY client_id",
        "management_line",
    )?;
    Some(out)
}

/// A reset's report.
#[derive(Debug, Clone)]
pub struct ResetOutcome {
    /// The new current generation.
    pub current: Current,
    /// The generation it replaced, kept whole.
    pub left_behind: Option<GenerationName>,
}

/// **Reset** (ADR-0014 §3.6, "Reset is the same switch"): a new, empty store with a new
/// environment ID at epoch 0, and a record saying `reset` and naming the generation it
/// replaced, made current by the switch. Under the runtime's instance lock, which the caller
/// holds, with the runtime and the issuer stopped. The old generation is kept, never deleted
/// or overwritten; the request ledger is left as it is.
///
/// # Errors
/// [`Refusal::RecoveryNotConfirmed`] for a damaged state the owner has not confirmed; the
/// refusals of [`reset_inventory`]; the store's or the layout's.
pub fn reset_locked(
    state_dir: &Path,
    fs: &dyn Fs,
    environment: &EnvironmentId,
    now: Timestamp,
    recovery_confirmed: bool,
) -> std::result::Result<ResetOutcome, RestoreError> {
    let inventory = reset_inventory(state_dir, fs)?;
    if inventory.recovery && !recovery_confirmed {
        return Err(Refusal::RecoveryNotConfirmed.into());
    }
    let state = StateDir::new(fs, state_dir);
    let left_behind = state.pointer().ok().flatten();
    let plan = Plan {
        name: GenerationName::fresh().map_err(|_| {
            StoreError::Corrupt("operating system randomness is unavailable".into())
        })?,
        operation: Operation::Reset,
        created_at: now,
        backup_sha256: None,
        environment_id: environment.as_str().to_owned(),
        restore_epoch: 0,
    };
    let populate = |dir: &Path| -> std::result::Result<Vec<String>, RestoreError> {
        let store = Store::open(&dir.join(DB_FILE), Arc::new(NoFaults))?;
        store.transaction(|tx| tx.init_self_environment(environment))?;
        close_staged(&store)?;
        drop(store);
        Ok(vec![DB_FILE.to_owned()])
    };
    let current = if inventory.recovery {
        state.recover(plan, populate)
    } else {
        state.publish(plan, populate)
    }
    .map_err(publish_err)?;
    Ok(ResetOutcome {
        current,
        left_behind,
    })
}

// --- the repair -------------------------------------------------------------------------------

/// What [`repair_locked`] did (ADR-0006 §19.4, U0-Q8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairOutcome {
    /// Decodable records after the damage, written into the store as fence records (records
    /// with a terminal record in the store are not fenced, as at a restore).
    pub fenced_records: u64,
    /// Undecodable records dropped by the cut.
    pub dropped_records: u64,
    /// The restore epoch after the repair.
    pub restore_epoch: RestoreEpoch,
}

/// Whether the request ledger of `state_dir` is damaged (read only): a repair has something
/// to do.
///
/// # Errors
/// The ledger cannot be read at all (not a regular file, or too long).
pub fn ledger_damage(
    state_dir: &Path,
    fs: &dyn Fs,
) -> std::result::Result<Option<LedgerScan>, RestoreError> {
    let scan = Ledger::new(fs, state_dir).scan().map_err(|_| {
        StoreError::Corrupt("state_corrupt: the request ledger cannot be read".into())
    })?;
    Ok(scan.damaged_at.is_some().then_some(scan))
}

/// **The attended `state repair`** (ADR-0006 §19.4, U0-Q8; ledger scope in 1.0): in this order,
/// carry every decodable record after the damage into the current store as fence records
/// (`REQUEST_STALE` / `restored_before_completion`, unresolved), raise the restore epoch, and
/// cut the ledger at the first damaged record. The fences and the epoch are one transaction,
/// durable before the cut: a stop in between leaves the ledger damaged and the repair is run
/// again (the fences are not written twice). Under the runtime's instance lock, which the
/// caller holds; `store` is the current generation's, opened under that lock.
///
/// **The stated residual:** a request among the dropped (undecodable) records, retried without
/// its epoch, could run again; a retry carrying its old epoch is refused.
///
/// # Errors
/// [`Refusal::WrongState`] when the ledger is not damaged; the store's.
pub fn repair_locked(
    state_dir: &Path,
    fs: &dyn Fs,
    store: &Store,
    now: Timestamp,
) -> std::result::Result<RepairOutcome, RestoreError> {
    let Some(scan) = ledger_damage(state_dir, fs)? else {
        return Err(Refusal::WrongState(
            "the request ledger is not damaged: there is nothing to repair",
        )
        .into());
    };
    let top = scan
        .after
        .iter()
        .chain(&scan.intact)
        .map(|e| e.epoch)
        .max()
        .unwrap_or(0);
    let (fenced, epoch) = store.transaction(|tx| {
        let current = tx.restore_epoch()?.0;
        let epoch =
            RestoreEpoch(current.max(top).checked_add(1).ok_or_else(|| {
                StoreError::Corrupt("the restore epoch would overflow".to_owned())
            })?);
        let fenced = fence_entries(tx, &scan.after, now)?;
        set_epoch(tx, epoch)?;
        Ok((fenced, epoch))
    })?;
    Ledger::new(fs, state_dir)
        .cut(scan.cut_len())
        .map_err(|_| {
            StoreError::Corrupt("state_corrupt: the request ledger could not be cut".into())
        })?;
    Ok(RepairOutcome {
        fenced_records: fenced,
        dropped_records: scan.dropped_records,
        restore_epoch: epoch,
    })
}

/// ⟨ADR-0014 H4⟩ The schema version of the store at `db`, read **without writing any file of
/// its family** (a read-only URI open, `PRAGMA user_version` only): a
/// newer schema is [`StoreError::NewerSchema`], a file that is not a database is
/// [`StoreError::Corrupt`]. `Ok(None)` when it cannot be opened that way (a write-ahead-log
/// family without its index file, as a clean stop leaves it): only an open that may write
/// would tell more. A quick check for the CLI before it starts a runtime; the integrity check
/// is the runtime's start's and the deep read's.
///
/// # Errors
/// As above.
pub fn peek_schema_version(db: &Path) -> Result<Option<u32>> {
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    // With no log the database file is the whole family: an immutable open reads it with no
    // lock and no index file (`Store::open_read_only_quiescent`).
    let query = if std::fs::symlink_metadata(PathBuf::from(wal)).is_ok() {
        "mode=ro&readonly_shm=1"
    } else {
        "mode=ro&immutable=1"
    };
    let Some(uri) = crate::file_uri(db, query) else {
        return Ok(None);
    };
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ) else {
        return Ok(None);
    };
    match crate::migrations::check_version(&conn, crate::migrations::MIGRATIONS) {
        Ok(v) => Ok(Some(v)),
        Err(e @ (StoreError::NewerSchema { .. } | StoreError::Corrupt(_))) => Err(e),
        Err(StoreError::Sqlite(inner)) => match codec::classify(inner) {
            e @ StoreError::Corrupt(_) => Err(e),
            _ => Ok(None),
        },
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
