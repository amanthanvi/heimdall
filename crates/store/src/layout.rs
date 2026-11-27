//! ⟨M08 U2b-1; ADR-0014 §3.6 "Store generations: one durable switch", delta H12⟩ The state
//! directory's layout.
//!
//! * **Generations.** Each store family lives alone in its own directory,
//!   `<state>/generations/<name>/`, beside that generation's sealed operation record. The
//!   pointer `<state>/CURRENT` names the one that is served. The switch, the records, the
//!   staging intent and start-up recovery are `heimdall-stategen`'s ([`StateDir`]); this
//!   module puts the store in them. The instance lock (`service.lock`) and the request ledger
//!   stay in the state directory, outside every generation.
//! * **Start-up trusts only the pointer** ([`open_locked`], under the runtime's instance
//!   lock). It serves the generation `CURRENT` names and never chooses one by name, time or
//!   content. A pointer that is unreadable, or names a missing or record-less generation, is
//!   [`StoreError::Corrupt`] (`state_corrupt: <reason>`). Nothing is then opened or removed,
//!   and nothing falls back to another generation or to the flat family.
//! * **Adoption of today's layout: fence first, then publish.** A store that an earlier build
//!   wrote directly in the state directory (`<state>/state.db`, at any schema version up to
//!   this build's, 14 included, by the U0 ruling) is adopted under the instance lock. Each
//!   step is durable before the next:
//!   1. the intent;
//!   2. the fence: in one SQLite transaction the family's `user_version` becomes
//!      [`ADOPTION_FENCE`], and the version it had is kept in `meta`. Every earlier build
//!      refuses that (`NewerSchema`), and this build answers [`StoreError::AdoptionFenced`];
//!   3. the copy: `VACUUM INTO` the staged generation, then the copy's own version restored
//!      and its fence key removed;
//!   4. the pointer switch;
//!   5. completion.
//!
//!   An interruption before the fence leaves the flat family usable by any build. After the
//!   fence, start-up resumes from the intent. The flat family is never moved, removed or
//!   served again: it is residue.
//! * **Every copy goes through SQLite** (the ruling of 2026-11-22). The adoption copy is
//!   `VACUUM INTO` over a connection that opens the whole family, its write-ahead log
//!   included. The migration backup inside a generation is the existing `VACUUM INTO`.
//!   Nothing copies or reads the main database file alone.
//! * **Migration stays in place.** A generation's store is migrated inside its generation,
//!   one transaction per step, after the existing backup, which is written beside it in the
//!   generation directory. The generation's migration notes record it after the transaction.
//!   A note lost in a crash is rebuilt from the database's schema version at the next start:
//!   every serving start first makes the notes end at the version it found, then notes what it
//!   migrated. The first start of a generation writes its baseline this way (`from == to`).
//! * **Readers** ([`locate`], [`db_path`]) follow the pointer and write nothing.
//!
//! **Not established by any test:** durability across power loss (ADR-0014 §3.6
//! "Platforms"). The fault tests kill the process and inject I/O errors; they cut no power.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::EnvironmentId;
use heimdall_stategen::{
    Current, Fs, GenerationName, MigrationNote, Operation, Plan, PublishError, RealFs, Startup,
    StateDir, StateError,
};
use rusqlite::OptionalExtension as _;

use crate::{FaultHook, META_SELF_ENVIRONMENT, NoFaults, Result, Store, StoreError, codec};

/// The generation crate, for the layout's callers: the file-system trait the runtime
/// implements (its Windows rename is write-through, H15) and the types of [`Current`].
pub use heimdall_stategen as stategen;

/// The database file's name, in a generation directory and in the flat layout of the builds
/// before generations.
pub const DB_FILE: &str = "state.db";

/// The schema version a flat family is fenced to (adoption step 2). It is above every schema
/// version a build will have, and a positive 32-bit value, so a build before generations
/// reads it as a newer schema and refuses the family without touching it.
pub const ADOPTION_FENCE: u32 = 2_000_000_000;

/// The `meta` key that the fence's transaction writes. It keeps the family's schema version
/// from before the fence.
pub(crate) const META_FENCED_FROM: &str = "adoption_fenced_from";

/// Where a reader finds the store ([`locate`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    /// The generation `CURRENT` names, checked against its record.
    Generation {
        /// Its database.
        db: PathBuf,
        /// The generation.
        current: Box<Current>,
    },
    /// There is no pointer: the flat family of a build before generations,
    /// `<state>/state.db`, which may not exist. A family fenced by an unfinished adoption
    /// opens as [`StoreError::AdoptionFenced`].
    Flat(PathBuf),
}

impl Located {
    /// The database's path.
    #[must_use]
    pub fn db(&self) -> &Path {
        match self {
            Self::Generation { db, .. } | Self::Flat(db) => db,
        }
    }

    /// The database's path, owned.
    #[must_use]
    pub fn into_db(self) -> PathBuf {
        match self {
            Self::Generation { db, .. } | Self::Flat(db) => db,
        }
    }
}

/// Where the store of `state_dir` is, following the pointer. It writes and removes nothing,
/// so it needs no lock. What it names is read with the store's read-only opens.
///
/// # Errors
/// [`StoreError::Corrupt`] (`state_corrupt: <reason>`) when the pointer is unreadable or
/// names a missing or record-less generation, or when there is no pointer and generations
/// show there was one. No other generation, and not the flat family, is offered instead.
pub fn locate(state_dir: &Path) -> Result<Located> {
    match StateDir::new(RealFs, state_dir).inspect() {
        Ok(Startup::Serving(current)) => Ok(Located::Generation {
            db: current.dir.join(DB_FILE),
            current: Box::new(current),
        }),
        // No generation was ever published: the flat family, if any, is the store.
        Ok(Startup::Empty | Startup::FirstPublicationPending { .. }) => {
            Ok(Located::Flat(state_dir.join(DB_FILE)))
        }
        Err(e) => Err(layout_error(e)),
    }
}

/// The database of the store in `state_dir`, following the pointer ([`locate`]). Every reader
/// of the state path, and every test that opens the store by path, reaches it this way.
///
/// # Errors
/// As [`locate`].
pub fn db_path(state_dir: &Path) -> Result<PathBuf> {
    locate(state_dir).map(Located::into_db)
}

/// The directory of the generation the pointer names, read from the pointer alone, with no
/// record or file checked; `None` when there is no pointer. It never decides what is served
/// or read ([`locate`] does). The purge uses it to anchor where the store's family lives and
/// goes back to. While a purge holds the family in quarantine, the generation's record lists
/// a file that is not there, and its crash recovery must still find where the family returns.
///
/// # Errors
/// [`StoreError::Corrupt`] (`state_corrupt: <reason>`) for a pointer that is unreadable or
/// malformed.
pub fn pointed_generation(state_dir: &Path) -> Result<Option<PathBuf>> {
    let state = StateDir::new(RealFs, state_dir);
    Ok(state
        .pointer()
        .map_err(layout_error)?
        .map(|name| state.generation_dir(&name)))
}

/// The database path in the generation the pointer names ([`pointed_generation`]); `None`
/// without a readable pointer. **For refusals only:** the runtime uses it to refuse a
/// database log left without its database.
#[must_use]
pub fn pointed_db(state_dir: &Path) -> Option<PathBuf> {
    pointed_generation(state_dir)
        .ok()
        .flatten()
        .map(|dir| dir.join(DB_FILE))
}

/// How start-up reached the store ([`open_locked`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Began {
    /// The generation `CURRENT` names was served.
    Served,
    /// A new installation: an empty store, staged and published as the first generation.
    Installed,
    /// The flat family was adopted, or its interrupted adoption resumed. `schema_version`
    /// is the version the family had before the fence, which the adopted generation starts
    /// from before it is migrated in place.
    Adopted {
        /// The family's schema version before the fence.
        schema_version: u32,
    },
}

/// The store, opened at start-up.
#[derive(Debug)]
pub struct Opened {
    /// The store of the current generation, migrated in place to this build's schema.
    pub store: Store,
    /// Its database.
    pub db: PathBuf,
    /// The generation.
    pub current: Current,
    /// How it was reached.
    pub began: Began,
}

/// Start-up, **under the runtime's instance lock** (the caller holds it): follow the pointer
/// and serve its generation. With no pointer, adopt the flat family when there is one, or
/// install an empty store as the first generation. Then open the generation's store,
/// migrating it in place.
///
/// `fs` makes every file-system call of the layout. In production it is the runtime's
/// platform file system, whose Windows rename is write-through (delta H15). `faults` is the
/// served store's hook; the staging of a new store and the adoption copy use none.
/// `new_environment` mints the environment ID of a new installation, or of a flat family
/// that never recorded one. `now` is the operation record's and the migration notes' time.
///
/// # Errors
/// - [`StoreError::Corrupt`] (`state_corrupt: <reason>`) for a corrupt layout, with nothing
///   opened, removed or chosen instead.
/// - [`StoreError::NewerSchema`], or [`StoreError::Corrupt`], for a newer or damaged store,
///   flat or in its generation. Before an adoption this is decided before its intent is
///   written, so nothing is touched.
/// - [`StoreError::Layout`] for an I/O error of the layout: before the switch the earlier
///   state is untouched; at or after it, the next start settles it.
pub fn open_locked(
    state_dir: &Path,
    fs: &dyn Fs,
    faults: Arc<dyn FaultHook>,
    new_environment: &dyn Fn() -> Option<EnvironmentId>,
    now: Timestamp,
) -> Result<Opened> {
    let state = StateDir::new(fs, state_dir);
    let (current, began) = match state.open().map_err(layout_error)? {
        Startup::Serving(current) => (current, Began::Served),
        Startup::Empty => first_publication(&state, None, new_environment, now)?,
        Startup::FirstPublicationPending { intent, .. } => {
            first_publication(&state, Some(intent.operation), new_environment, now)?
        }
    };
    let db = current.dir.join(DB_FILE);
    // The notes end at the version found **before** any migration, so a kill between a
    // migration's commit and its note leaves the evidence to rebuild it. A store this build
    // refuses (a newer schema, a fence) gets no note: it is not touched.
    let found = generation_version(&db)?;
    note_migration(&state, &current, None, found, now);
    let (store, before) = Store::open_generation(&db, faults)?;
    let after = store.schema_version()?;
    if after != before {
        note_migration(&state, &current, Some(before), after, now);
    }
    Ok(Opened {
        store,
        db,
        current,
        began,
    })
}

/// No generation was ever published: adopt the flat family when there is one, else install.
/// `interrupted` is the operation an earlier start left unfinished (its staged leftover is
/// already gone).
///
/// ⟨M08 W4 U2b-3a; W3-R05⟩ An interrupted install whose home then got a flat family (a build
/// that predates generations created it) is recovered: the flat family is adopted, its
/// adoption's intent replacing the stale install's. Only an **unfenced** family: one fenced
/// for an adoption that no adoption intent explains is refused (`adoption_intent_missing`),
/// and nothing is changed.
fn first_publication(
    state: &StateDir<&dyn Fs>,
    interrupted: Option<Operation>,
    new_environment: &dyn Fn() -> Option<EnvironmentId>,
    now: Timestamp,
) -> Result<(Current, Began)> {
    let flat = state.root().join(DB_FILE);
    let resuming = interrupted == Some(Operation::Adopt);
    match probe_flat(&flat)? {
        Some(probe) => adopt(state, &flat, &probe, resuming, new_environment, now),
        // An adoption intent whose family is gone: removed from outside. Nothing is guessed.
        None if resuming => Err(StoreError::Corrupt(
            "state_corrupt: adoption_source_missing".to_owned(),
        )),
        None => install(state, new_environment, now),
    }
}

/// The flat family as start-up found it (read-only checks only).
#[derive(Debug)]
struct FlatProbe {
    /// Its schema version, from before the fence when it is fenced.
    schema_version: u32,
    /// Whether an adoption already fenced it.
    fenced: bool,
    /// The environment ID it recorded.
    environment: Option<EnvironmentId>,
}

/// The flat family, checked read-only before anything is written: `None` when there is no
/// store there. That is no file, an empty file with no log, or a database with no schema
/// at all, as a build that stopped before its first migration leaves it. A newer schema, a
/// damaged file or an unversioned schema refuses, and nothing is written.
fn probe_flat(flat: &Path) -> Result<Option<FlatProbe>> {
    let meta = match std::fs::symlink_metadata(flat) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error("the flat state database cannot be examined", &e)),
    };
    if !meta.file_type().is_file() {
        return Err(StoreError::Corrupt(
            "the flat state database is not a regular file".to_owned(),
        ));
    }
    if meta.len() == 0 && std::fs::symlink_metadata(with_suffix(flat, "-wal")).is_err() {
        return Ok(None);
    }
    let conn = open_flat(flat)?;
    let version = crate::migrations::user_version(&conn)?;
    let (schema_version, fenced) = if version == ADOPTION_FENCE {
        (fenced_from(&conn)?, true)
    } else {
        match crate::migrations::check_version(&conn, crate::migrations::MIGRATIONS)? {
            0 => return Ok(None),
            found => (found, false),
        }
    };
    crate::integrity_check(&conn)?;
    let environment = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_SELF_ENVIRONMENT],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(codec::classify)?
        .map(|text| {
            EnvironmentId::parse(&text)
                .map_err(|_| StoreError::Corrupt("self environment id is malformed".into()))
        })
        .transpose()?;
    Ok(Some(FlatProbe {
        schema_version,
        fenced,
        environment,
    }))
}

/// Steps 1 to 5 of the adoption, through `heimdall-stategen`'s order.
fn adopt(
    state: &StateDir<&dyn Fs>,
    flat: &Path,
    probe: &FlatProbe,
    resuming: bool,
    new_environment: &dyn Fn() -> Option<EnvironmentId>,
    now: Timestamp,
) -> Result<(Current, Began)> {
    if probe.fenced && !resuming {
        // The fence follows a durable intent. A fenced family with no adoption intent means
        // the intent was removed from outside: nothing is guessed.
        return Err(StoreError::Corrupt(
            "state_corrupt: adoption_intent_missing".to_owned(),
        ));
    }
    let environment = match &probe.environment {
        Some(id) => id.clone(),
        None => new_environment().ok_or_else(randomness_unavailable)?,
    };
    let plan = Plan {
        name: fresh_name()?,
        operation: Operation::Adopt,
        created_at: now,
        backup_sha256: None,
        environment_id: environment.as_str().to_owned(),
        restore_epoch: 0,
    };
    let current = state
        .adopt(
            plan,
            DB_FILE,
            || fence(flat),
            |dir| copy_fenced(flat, dir, &environment),
        )
        .map_err(publish_error)?;
    Ok((
        current,
        Began::Adopted {
            schema_version: probe.schema_version,
        },
    ))
}

/// Adoption step 2: in one SQLite transaction, keep the family's schema version in `meta`
/// and set its `user_version` to [`ADOPTION_FENCE`]. A family already fenced, by the start
/// an interruption stopped, is left as it is.
fn fence(flat: &Path) -> Result<()> {
    let mut conn = open_flat(flat)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(codec::classify)?;
    if crate::migrations::user_version(&tx)? == ADOPTION_FENCE {
        fenced_from(&tx)?;
        // Already fenced: nothing to write (the transaction rolls back unchanged).
        return Ok(());
    }
    let version = crate::migrations::check_version(&tx, crate::migrations::MIGRATIONS)?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [META_FENCED_FROM, version.to_string().as_str()],
    )
    .map_err(codec::classify)?;
    tx.pragma_update(None, "user_version", ADOPTION_FENCE)
        .map_err(codec::classify)?;
    tx.commit().map_err(codec::classify)?;
    tracing::info!(
        from_version = version,
        "the flat state store was fenced for adoption into the generation layout"
    );
    Ok(())
}

/// Adoption step 3: a consistent copy of the fenced family, through SQLite (`VACUUM INTO`
/// over a connection that opens the family with its log), into the staged generation
/// directory `dir`. The copy's schema version is put back and its fence key removed, and
/// the environment ID is recorded if the family never had one. The copy is checked and
/// closed with no log or journal. The flat family itself is only read.
fn copy_fenced(flat: &Path, dir: &Path, environment: &EnvironmentId) -> Result<Vec<String>> {
    let source = open_flat(flat)?;
    if crate::migrations::user_version(&source)? != ADOPTION_FENCE {
        return Err(StoreError::Corrupt(
            "the adoption copy found the flat state store unfenced".to_owned(),
        ));
    }
    let schema_version = fenced_from(&source)?;
    let out = dir.join(DB_FILE);
    let Some(target) = out.to_str() else {
        return Err(StoreError::Corrupt(
            "the staged database path is not UTF-8".to_owned(),
        ));
    };
    crate::create_owner_only(&out)?;
    source
        .execute("VACUUM INTO ?1", [target])
        .map_err(codec::classify)?;
    drop(source);
    let mut copy = rusqlite::Connection::open_with_flags(
        &out,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(codec::classify)?;
    copy.pragma_update(None, "synchronous", "FULL")
        .map_err(codec::classify)?;
    rollback_journal(&copy)?;
    let tx = copy
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(codec::classify)?;
    tx.execute("DELETE FROM meta WHERE key = ?1", [META_FENCED_FROM])
        .map_err(codec::classify)?;
    let recorded: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_SELF_ENVIRONMENT],
            |r| r.get(0),
        )
        .optional()
        .map_err(codec::classify)?;
    match recorded {
        None => {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                [META_SELF_ENVIRONMENT, environment.as_str()],
            )
            .map_err(codec::classify)?;
        }
        Some(text) if text == environment.as_str() => {}
        Some(_) => {
            return Err(StoreError::Corrupt(
                "the adopted store's environment changed during the adoption".to_owned(),
            ));
        }
    }
    tx.pragma_update(None, "user_version", schema_version)
        .map_err(codec::classify)?;
    tx.commit().map_err(codec::classify)?;
    crate::integrity_check(&copy)?;
    drop(copy);
    Ok(vec![DB_FILE.to_owned()])
}

/// A new installation: an empty store at this build's schema, with a new environment ID,
/// staged and published as the first generation.
fn install(
    state: &StateDir<&dyn Fs>,
    new_environment: &dyn Fn() -> Option<EnvironmentId>,
    now: Timestamp,
) -> Result<(Current, Began)> {
    let environment = new_environment().ok_or_else(randomness_unavailable)?;
    let plan = Plan {
        name: fresh_name()?,
        operation: Operation::Install,
        created_at: now,
        backup_sha256: None,
        environment_id: environment.as_str().to_owned(),
        restore_epoch: 0,
    };
    let current = state
        .publish(plan, |dir| new_store(dir, &environment))
        .map_err(publish_error)?;
    Ok((current, Began::Installed))
}

/// The staged store of a new installation, closed with no write-ahead log or journal.
fn new_store(dir: &Path, environment: &EnvironmentId) -> Result<Vec<String>> {
    let store = Store::open(&dir.join(DB_FILE), Arc::new(NoFaults))?;
    store.transaction(|tx| tx.init_self_environment(environment))?;
    {
        let conn = store.lock();
        rollback_journal(&conn)?;
    }
    drop(store);
    Ok(vec![DB_FILE.to_owned()])
}

/// Put a connection's database in rollback-journal mode, which checkpoints and removes a
/// write-ahead log, so that a staged database is one file (ADR-0014 §3.6, "the switch").
fn rollback_journal(conn: &rusqlite::Connection) -> Result<()> {
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
        .map_err(codec::classify)?;
    if mode.eq_ignore_ascii_case("delete") {
        Ok(())
    } else {
        Err(StoreError::Corrupt(
            "the staged database kept its write-ahead log".to_owned(),
        ))
    }
}

/// The schema version of a generation's database, read before it is opened as a store: a
/// newer schema or a fence refuses here, before anything is written. The file is never
/// created.
fn generation_version(db: &Path) -> Result<u32> {
    let conn = rusqlite::Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(codec::classify)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(codec::classify)?;
    crate::migrations::check_version(&conn, crate::migrations::MIGRATIONS)
}

/// Note in the current generation that its store is at `to`. With `from`, it records a
/// migration that just committed. With none, it makes the notes end at `to`: the baseline at
/// a generation's first start (`to → to`), or a migration whose note a crash lost
/// (`last → to`), rebuilt from the database's version. This is completion metadata only. A
/// failure is logged and the next start rebuilds what is missing. It never selects anything.
fn note_migration(
    state: &StateDir<&dyn Fs>,
    current: &Current,
    from: Option<u32>,
    to: u32,
    now: Timestamp,
) {
    let from = match from {
        Some(from) => from,
        None => {
            let Ok(notes) = state.migrations(current) else {
                tracing::warn!("the generation's migration notes cannot be read; none was written");
                return;
            };
            match notes.last().map(|n| n.to) {
                Some(last) if last == to => return,
                Some(last) => last,
                None => to,
            }
        }
    };
    let note = MigrationNote { from, to, at: now };
    if state.note_migration(current, &note).is_err() {
        tracing::warn!("a migration note could not be written; the next start rebuilds it");
    }
}

/// A connection to the flat family that opens the whole family (its log included) and
/// never creates a file.
fn open_flat(flat: &Path) -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_with_flags(
        flat,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(codec::classify)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(codec::classify)?;
    for (pragma, value) in [
        ("synchronous", "FULL"),
        ("foreign_keys", "ON"),
        ("trusted_schema", "OFF"),
    ] {
        conn.pragma_update(None, pragma, value)
            .map_err(codec::classify)?;
    }
    Ok(conn)
}

/// The schema version a fenced family kept ([`META_FENCED_FROM`]): a canonical decimal no
/// higher than this build's. Anything else is damage.
fn fenced_from(conn: &rusqlite::Connection) -> Result<u32> {
    let kept: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_FENCED_FROM],
            |r| r.get(0),
        )
        .optional()
        .map_err(codec::classify)?;
    kept.as_deref()
        .and_then(crate::parse_restore_epoch)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| (1..=crate::SCHEMA_VERSION).contains(v))
        .ok_or_else(|| {
            StoreError::Corrupt("the fenced store's kept schema version is malformed".to_owned())
        })
}

fn fresh_name() -> Result<GenerationName> {
    GenerationName::fresh().map_err(|_| randomness_unavailable())
}

fn randomness_unavailable() -> StoreError {
    StoreError::Corrupt("operating system randomness is unavailable".to_owned())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn io_error(what: &'static str, e: &std::io::Error) -> StoreError {
    StoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
        std::io::Error::new(e.kind(), what),
    )))
}

/// A layout error as a store error: a corrupt layout is `state_corrupt` with its reason.
fn layout_error(e: StateError) -> StoreError {
    match e {
        StateError::Corrupt(reason) => {
            StoreError::Corrupt(format!("state_corrupt: {}", reason.code()))
        }
        other => StoreError::Layout(other),
    }
}

fn publish_error(e: PublishError<StoreError>) -> StoreError {
    match e {
        PublishError::State(e) => layout_error(e),
        PublishError::Caller(e) => e,
    }
}
