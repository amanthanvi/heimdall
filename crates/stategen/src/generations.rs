//! Generation directories, the `CURRENT` pointer switch, the staging intent and start-up
//! recovery (ADR-0014 §3.6, "Store generations: one durable switch").
//!
//! The caller holds the runtime's exclusive instance lock around every call that writes
//! ([`StateDir::open`], [`StateDir::publish`], [`StateDir::adopt`],
//! [`StateDir::note_migration`]). [`StateDir::inspect`] writes nothing.

use std::path::{Path, PathBuf};

use jiff::Timestamp;

use crate::fs::{Fs, Kind, Point};
use crate::record::{self, GenerationName, Intent, IntentState, Operation, OperationRecord};

/// The pointer file: names the generation that is served.
pub const CURRENT: &str = "CURRENT";
/// The temporary pointer, renamed over [`CURRENT`].
pub const CURRENT_TMP: &str = "CURRENT.tmp";
/// The staging intent (for an adoption, the adoption intent).
pub const INTENT: &str = "STAGING-INTENT";
/// The temporary staging intent.
pub const INTENT_TMP: &str = "STAGING-INTENT.tmp";
/// The directory that holds every generation directory.
pub const GENERATIONS: &str = "generations";
/// The operation record inside a generation.
pub const RECORD: &str = "OPERATION";
/// The migration notes inside a generation.
pub const MIGRATIONS: &str = "MIGRATIONS";

const SMALL: u64 = 16 * 1024;
const MIGRATIONS_LIMIT: u64 = 1024 * 1024;

/// Why the state directory is `state_corrupt`. Unsafe operations stop; no other generation
/// is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptReason {
    /// `CURRENT` is there and cannot be read, or is not a regular file.
    PointerUnreadable,
    /// `CURRENT` was read and is not a pointer.
    PointerMalformed,
    /// There is no `CURRENT`, and generations or a finished intent show there was one.
    PointerMissing,
    /// `CURRENT` names a generation directory that is not there.
    GenerationMissing,
    /// The generation `CURRENT` names holds no operation record.
    RecordMissing,
    /// The record cannot be read, is cut, altered, or belongs to another generation.
    RecordDamaged,
    /// A file the record lists is not in the generation.
    FileMissing,
    /// There is no `CURRENT` and the staging intent cannot be read.
    IntentDamaged,
}

impl CorruptReason {
    /// The reason as a code.
    pub fn code(self) -> &'static str {
        match self {
            Self::PointerUnreadable => "pointer_unreadable",
            Self::PointerMalformed => "pointer_malformed",
            Self::PointerMissing => "pointer_missing",
            Self::GenerationMissing => "generation_missing",
            Self::RecordMissing => "record_missing",
            Self::RecordDamaged => "record_damaged",
            Self::FileMissing => "generation_file_missing",
            Self::IntentDamaged => "intent_damaged",
        }
    }
}

/// Why a request was refused before anything was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The state directory is not in the state this operation starts from (an install
    /// with a store present, a restore or reset with none, an adoption after publication).
    WrongState,
    /// [`StateDir::publish`] was asked to adopt; adoption has its own order
    /// ([`StateDir::adopt`]).
    AdoptHasItsOwnOrder,
    /// A restore names another environment. Replacing the identity is reset.
    EnvironmentMismatch,
    /// A restore must raise the restore epoch.
    EpochNotRaised,
    /// A reset must create a new environment ID.
    ResetKeepsIdentity,
    /// An install, an adoption and a reset start at epoch zero.
    EpochNotZero,
    /// A restore names its backup by digest; no other operation has one.
    BackupDigest,
    /// The environment ID is empty, too long or not plain printable ASCII.
    EnvironmentId,
    /// A generation or leftover already has this name.
    NameTaken,
    /// The caller staged no file, a file with a name that is not plain, a name the crate
    /// reserves, or did not report every file in the directory.
    StagedFiles,
    /// The staged directory holds a write-ahead log, a journal or a shared-memory file:
    /// the database was not checkpointed and closed.
    StagedNotClosed,
}

/// An error from this module.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    /// The state directory is `state_corrupt`.
    #[error("state_corrupt: {}", .0.code())]
    Corrupt(CorruptReason),
    /// Refused before any write.
    #[error("refused: {0:?}")]
    Refused(Refusal),
    /// An I/O call failed before the pointer's rename. What was staged has been removed
    /// where that was possible; the earlier state is untouched.
    #[error("i/o error at {point:?}: {kind:?}")]
    Io {
        /// The step.
        point: Point,
        /// The error's kind (no path, no message text).
        kind: std::io::ErrorKind,
    },
    /// An I/O call failed at or after the pointer's rename. Either pointer value is a
    /// complete state; nothing was removed, and the next start-up settles it.
    #[error("i/o error at {point:?} during the switch: {kind:?}; the next start-up settles it")]
    SwitchUnsettled {
        /// The step.
        point: Point,
        /// The error's kind.
        kind: std::io::ErrorKind,
    },
}

/// A failure of an operation that calls the caller's own functions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublishError<E> {
    /// This crate's error.
    #[error(transparent)]
    State(#[from] StateError),
    /// The caller's function failed. What was staged has been removed.
    #[error("the caller's step failed")]
    Caller(E),
}

/// What start-up removed or finished.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovered {
    /// A staged generation that never became current, removed as garbage.
    pub removed_staged: Option<GenerationName>,
    /// A leftover temporary pointer or temporary intent was removed.
    pub removed_temporary: bool,
    /// A pending intent whose generation is current was marked complete.
    pub completed_intent: bool,
    /// The intent could not be read. The pointer is still trusted and nothing was removed.
    pub intent_unreadable: bool,
}

/// The generation that is served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    /// Its name, from the pointer.
    pub name: GenerationName,
    /// Its record.
    pub record: OperationRecord,
    /// Its directory.
    pub dir: PathBuf,
    /// What start-up did on the way.
    pub recovered: Recovered,
}

/// What start-up found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// No pointer, no intent and no generation: a new installation, or a store an earlier
    /// build wrote directly in the state directory (the caller looks for one).
    Empty,
    /// The pointer names a complete generation.
    Serving(Current),
    /// No generation was ever published, and an install or an adoption was interrupted.
    /// Its staged generation is gone; the caller runs the operation again.
    FirstPublicationPending {
        /// The interrupted operation's intent.
        intent: Intent,
        /// What was removed.
        recovered: Recovered,
    },
}

/// What a new generation is to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Its name: free, and never used before ([`GenerationName::fresh`]).
    pub name: GenerationName,
    /// The operation creating it.
    pub operation: Operation,
    /// When.
    pub created_at: Timestamp,
    /// For a restore, the backup's SHA-256 as 64 hex digits.
    pub backup_sha256: Option<String>,
    /// The environment ID of the store being staged.
    pub environment_id: String,
    /// Its restore epoch.
    pub restore_epoch: u64,
}

/// A generation that is not the current one: residue, kept until the owner removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Residue {
    /// The directory's name, as found.
    pub name: String,
    /// Its record, when it has a complete one.
    pub record: Option<OperationRecord>,
}

/// One migration note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationNote {
    /// The schema version before.
    pub from: u32,
    /// The schema version after.
    pub to: u32,
    /// When the migration finished.
    pub at: Timestamp,
}

enum IntentFile {
    None,
    Read(Intent),
    Unreadable,
}

/// A state directory.
#[derive(Debug)]
pub struct StateDir<F> {
    fs: F,
    root: PathBuf,
}

impl<F: Fs> StateDir<F> {
    /// A state directory at `root`, which exists.
    pub fn new(fs: F, root: impl Into<PathBuf>) -> Self {
        Self {
            fs,
            root: root.into(),
        }
    }

    /// The file system.
    pub fn fs(&self) -> &F {
        &self.fs
    }

    /// The state directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A generation's directory.
    pub fn generation_dir(&self, name: &GenerationName) -> PathBuf {
        self.root.join(GENERATIONS).join(name.as_str())
    }

    fn at(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Start-up, under the instance lock: follow the pointer, check the generation it
    /// names, remove a staged leftover and finish a pending intent.
    ///
    /// It never chooses a generation by name, time or content and never falls back to
    /// another one. The only directory it removes is the one a pending intent names, and
    /// only when the pointer does not name it.
    pub fn open(&self) -> Result<Startup, StateError> {
        self.start(true)
    }

    /// The same classification as [`StateDir::open`], writing and removing nothing. For
    /// `status`, `doctor` and the support bundle.
    pub fn inspect(&self) -> Result<Startup, StateError> {
        self.start(false)
    }

    fn start(&self, repair: bool) -> Result<Startup, StateError> {
        let pointer = self.read_pointer()?;
        let intent = self.read_intent();
        let mut recovered = Recovered::default();
        match pointer {
            Some(name) => {
                let record = self.read_record(&name).map_err(StateError::Corrupt)?;
                match intent {
                    IntentFile::Read(i)
                        if i.state == IntentState::Pending && i.generation == name =>
                    {
                        if repair {
                            self.write_intent(&i.completed())?;
                            recovered.completed_intent = true;
                        }
                    }
                    IntentFile::Read(i) if i.state == IntentState::Pending => {
                        if repair {
                            recovered.removed_staged = self.discard_staged(&i.generation)?;
                            self.remove_if_file(INTENT)?;
                        }
                    }
                    IntentFile::Unreadable => recovered.intent_unreadable = true,
                    IntentFile::Read(_) | IntentFile::None => {}
                }
                if repair {
                    recovered.removed_temporary = self.remove_temporaries()?;
                }
                let dir = self.generation_dir(&name);
                Ok(Startup::Serving(Current {
                    name,
                    record,
                    dir,
                    recovered,
                }))
            }
            None => match intent {
                IntentFile::Read(i)
                    if i.state == IntentState::Pending
                        && matches!(i.operation, Operation::Install | Operation::Adopt) =>
                {
                    if repair {
                        recovered.removed_staged = self.discard_staged(&i.generation)?;
                        recovered.removed_temporary = self.remove_temporaries()?;
                    }
                    Ok(Startup::FirstPublicationPending {
                        intent: i,
                        recovered,
                    })
                }
                // A restore or reset in progress, or a finished operation, means a pointer
                // existed. It is gone: nothing is guessed.
                IntentFile::Read(_) => Err(StateError::Corrupt(CorruptReason::PointerMissing)),
                IntentFile::Unreadable => Err(StateError::Corrupt(CorruptReason::IntentDamaged)),
                IntentFile::None => {
                    if !self.generation_names()?.is_empty() {
                        return Err(StateError::Corrupt(CorruptReason::PointerMissing));
                    }
                    if repair {
                        self.remove_temporaries()?;
                    }
                    Ok(Startup::Empty)
                }
            },
        }
    }

    /// Stage a generation and make it current: an install, a restore or a reset.
    ///
    /// `populate` receives the new, empty generation directory. It puts the store there
    /// **through SQLite** (an online backup or `VACUUM INTO`, never a copy of the main
    /// file alone), checkpointed and closed, and returns the names of the files it wrote.
    /// This crate then syncs those files, writes and syncs the operation record, syncs the
    /// directories and switches the pointer.
    ///
    /// On any failure before the pointer's rename the staged generation is removed and the
    /// earlier generation is untouched. No earlier generation is ever renamed, moved,
    /// overwritten or removed.
    pub fn publish<E>(
        &self,
        plan: Plan,
        populate: impl FnOnce(&Path) -> Result<Vec<String>, E>,
    ) -> Result<Current, PublishError<E>> {
        if plan.operation == Operation::Adopt {
            return Err(StateError::Refused(Refusal::AdoptHasItsOwnOrder).into());
        }
        check_plan(&plan)?;
        let from = match (plan.operation, self.open()?) {
            (Operation::Install, Startup::Empty) => None,
            (Operation::Install, Startup::FirstPublicationPending { intent, .. })
                if intent.operation == Operation::Install =>
            {
                None
            }
            (Operation::Restore, Startup::Serving(current)) => {
                if plan.environment_id != current.record.environment_id {
                    return Err(StateError::Refused(Refusal::EnvironmentMismatch).into());
                }
                if plan.restore_epoch <= current.record.restore_epoch {
                    return Err(StateError::Refused(Refusal::EpochNotRaised).into());
                }
                Some(current.name)
            }
            (Operation::Reset, Startup::Serving(current)) => {
                if plan.environment_id == current.record.environment_id {
                    return Err(StateError::Refused(Refusal::ResetKeepsIdentity).into());
                }
                Some(current.name)
            }
            _ => return Err(StateError::Refused(Refusal::WrongState).into()),
        };
        self.require_free(&plan.name)?;
        self.write_intent(&Intent::new(plan.operation, plan.name.clone(), None))
            .inspect_err(|_| self.abandon(None, false))?;
        self.stage_and_switch(plan, from, populate, false)
    }

    /// Adopt a store an earlier build wrote directly in the state directory, in the order
    /// of ADR-0014 §3.6: **intent, fence, copy, publication, completion,** each durable
    /// before the next.
    ///
    /// `fence` sets the flat family's schema version, in one SQLite transaction, to a value
    /// no earlier build accepts. It must be safe to run again: an interrupted adoption is
    /// resumed by calling `adopt` again, which repeats it. `copy` stages a consistent copy
    /// of the fenced family, as `populate` does in [`StateDir::publish`].
    ///
    /// The flat family is never moved, removed or served again by this crate.
    pub fn adopt<E>(
        &self,
        plan: Plan,
        flat_family: &str,
        fence: impl FnOnce() -> Result<(), E>,
        copy: impl FnOnce(&Path) -> Result<Vec<String>, E>,
    ) -> Result<Current, PublishError<E>> {
        if plan.operation != Operation::Adopt || !plain_file_name(flat_family) {
            return Err(StateError::Refused(Refusal::WrongState).into());
        }
        check_plan(&plan)?;
        match self.open()? {
            Startup::Empty => {}
            Startup::FirstPublicationPending { intent, .. }
                if intent.operation == Operation::Adopt => {}
            _ => return Err(StateError::Refused(Refusal::WrongState).into()),
        }
        self.require_free(&plan.name)?;
        // 1. The intent. A failure here leaves the flat family usable by any build.
        self.write_intent(&Intent::new(
            Operation::Adopt,
            plan.name.clone(),
            Some(flat_family.to_owned()),
        ))?;
        // 2. The fence. From here an earlier build refuses the family, so the intent stays
        //    pending whatever happens next: the adoption is resumed, never abandoned.
        fence().map_err(PublishError::Caller)?;
        // 3 to 5. The copy, the publication and the completion.
        self.stage_and_switch(plan, None, copy, true)
    }

    fn stage_and_switch<E>(
        &self,
        plan: Plan,
        from: Option<GenerationName>,
        populate: impl FnOnce(&Path) -> Result<Vec<String>, E>,
        keep_intent: bool,
    ) -> Result<Current, PublishError<E>> {
        let name = plan.name.clone();
        let dir = self.generation_dir(&name);
        let staged = self.stage(plan, from, &dir, populate).and_then(|record| {
            self.write_temp_pointer(&name)?;
            Ok(record)
        });
        let record = match staged {
            Ok(record) => record,
            Err(e) => {
                self.abandon(Some(&name), keep_intent);
                return Err(e);
            }
        };
        // The switch. From here nothing is removed on failure: after a failed rename or a
        // failed directory sync either pointer value may be the durable one, and both are
        // complete states. Start-up settles it.
        let unsettled = |point| {
            move |e: std::io::Error| StateError::SwitchUnsettled {
                point,
                kind: e.kind(),
            }
        };
        self.fs
            .rename_over(
                Point::PointerRename,
                &self.at(CURRENT_TMP),
                &self.at(CURRENT),
            )
            .map_err(unsettled(Point::PointerRename))?;
        self.fs
            .sync_dir(Point::StateDirSync, &self.root)
            .map_err(unsettled(Point::StateDirSync))?;
        // Completion. The switch is done; a failure here is finished by the next start-up.
        let mut recovered = Recovered::default();
        if let IntentFile::Read(intent) = self.read_intent() {
            recovered.completed_intent = self.write_intent(&intent.completed()).is_ok();
        }
        Ok(Current {
            name,
            record,
            dir,
            recovered,
        })
    }

    fn stage<E>(
        &self,
        plan: Plan,
        from: Option<GenerationName>,
        dir: &Path,
        populate: impl FnOnce(&Path) -> Result<Vec<String>, E>,
    ) -> Result<OperationRecord, PublishError<E>> {
        let generations = self.at(GENERATIONS);
        match self
            .fs
            .kind(&generations)
            .map_err(io_at(Point::GenerationCreate))?
        {
            Kind::Dir => {}
            Kind::Missing => {
                self.fs
                    .create_dir(Point::GenerationCreate, &generations)
                    .map_err(io_at(Point::GenerationCreate))?;
                self.fs
                    .sync_dir(Point::GenerationsDirSync, &self.root)
                    .map_err(io_at(Point::GenerationsDirSync))?;
            }
            _ => return Err(StateError::Refused(Refusal::WrongState).into()),
        }
        self.fs
            .create_dir(Point::GenerationCreate, dir)
            .map_err(io_at(Point::GenerationCreate))?;
        let mut files = populate(dir).map_err(PublishError::Caller)?;
        files.sort();
        files.dedup();
        let found = self.fs.list(dir).map_err(io_at(Point::StagedFileSync))?;
        if found
            .iter()
            .any(|f| ["-wal", "-shm", "-journal"].iter().any(|s| f.ends_with(s)))
        {
            return Err(StateError::Refused(Refusal::StagedNotClosed).into());
        }
        let reserved = |f: &String| f == RECORD || f == MIGRATIONS;
        if files.is_empty()
            || files != found
            || files.iter().any(|f| !plain_file_name(f) || reserved(f))
        {
            return Err(StateError::Refused(Refusal::StagedFiles).into());
        }
        for file in &files {
            let path = dir.join(file);
            if self.fs.kind(&path).map_err(io_at(Point::StagedFileSync))? != Kind::File {
                return Err(StateError::Refused(Refusal::StagedFiles).into());
            }
            self.fs
                .sync_file(Point::StagedFileSync, &path)
                .map_err(io_at(Point::StagedFileSync))?;
        }
        let record = OperationRecord {
            schema: record::RECORD_SCHEMA.to_owned(),
            generation: plan.name,
            operation: plan.operation,
            created_at: plan.created_at,
            from_generation: from,
            backup_sha256: plan.backup_sha256,
            environment_id: plan.environment_id,
            restore_epoch: plan.restore_epoch,
            files,
        };
        let record_path = dir.join(RECORD);
        self.fs
            .write_new(Point::RecordWrite, &record_path, &record.encode())
            .map_err(io_at(Point::RecordWrite))?;
        self.fs
            .sync_file(Point::RecordSync, &record_path)
            .map_err(io_at(Point::RecordSync))?;
        self.fs
            .sync_dir(Point::GenerationDirSync, dir)
            .map_err(io_at(Point::GenerationDirSync))?;
        self.fs
            .sync_dir(Point::GenerationsDirSync, &generations)
            .map_err(io_at(Point::GenerationsDirSync))?;
        Ok(record)
    }

    fn write_temp_pointer<E>(&self, name: &GenerationName) -> Result<(), PublishError<E>> {
        let tmp = self.at(CURRENT_TMP);
        self.remove_if_file(CURRENT_TMP)?;
        self.fs
            .write_new(Point::TempPointerWrite, &tmp, &record::encode_pointer(name))
            .map_err(io_at(Point::TempPointerWrite))?;
        self.fs
            .sync_file(Point::TempPointerSync, &tmp)
            .map_err(io_at(Point::TempPointerSync))?;
        Ok(())
    }

    /// Best-effort removal of what a failed operation staged. Never the pointer, never
    /// another generation. Errors are ignored: start-up removes what is left.
    fn abandon(&self, staged: Option<&GenerationName>, keep_intent: bool) {
        if let Some(name) = staged {
            let _ = self.discard_staged(name);
        }
        let _ = self.remove_temporaries();
        if !keep_intent {
            let _ = self.remove_if_file(INTENT);
        }
    }

    /// Note a finished migration in the current generation. Completion metadata only: it
    /// never selects a generation, and it is rebuilt from the database's schema version if
    /// a crash loses it.
    pub fn note_migration(
        &self,
        current: &Current,
        note: &MigrationNote,
    ) -> Result<(), StateError> {
        let line = format!("{} {} {}\n", note.from, note.to, note.at);
        self.fs
            .append_sync(
                Point::MigrationAppend,
                &current.dir.join(MIGRATIONS),
                line.as_bytes(),
            )
            .map_err(plain_io(Point::MigrationAppend))
    }

    /// The migration notes of a generation. A cut last line is ignored.
    pub fn migrations(&self, current: &Current) -> Result<Vec<MigrationNote>, StateError> {
        let path = current.dir.join(MIGRATIONS);
        if self
            .fs
            .kind(&path)
            .map_err(plain_io(Point::MigrationAppend))?
            != Kind::File
        {
            return Ok(Vec::new());
        }
        let bytes = self
            .fs
            .read(&path, MIGRATIONS_LIMIT)
            .map_err(plain_io(Point::MigrationAppend))?;
        let text = String::from_utf8_lossy(&bytes);
        let complete = text.rsplit_once('\n').map_or("", |(lines, _)| lines);
        Ok(complete
            .lines()
            .filter_map(|line| {
                let mut parts = line.split(' ');
                let note = MigrationNote {
                    from: parts.next()?.parse().ok()?,
                    to: parts.next()?.parse().ok()?,
                    at: parts.next()?.parse().ok()?,
                };
                parts.next().is_none().then_some(note)
            })
            .collect())
    }

    /// Every generation directory other than the current one, for the uninstall inventory
    /// and the purge. Reads only.
    pub fn residue(&self) -> Result<Vec<Residue>, StateError> {
        let current = self.read_pointer()?;
        Ok(self
            .generation_names()?
            .into_iter()
            .filter(|name| current.as_ref().is_none_or(|c| c.as_str() != name))
            .map(|name| {
                let record = GenerationName::parse(&name).and_then(|n| self.read_record(&n).ok());
                Residue { name, record }
            })
            .collect())
    }

    fn generation_names(&self) -> Result<Vec<String>, StateError> {
        let dir = self.at(GENERATIONS);
        match self.fs.kind(&dir).map_err(plain_io(Point::Cleanup))? {
            Kind::Missing => Ok(Vec::new()),
            Kind::Dir => self.fs.list(&dir).map_err(plain_io(Point::Cleanup)),
            _ => Err(StateError::Corrupt(CorruptReason::GenerationMissing)),
        }
    }

    fn read_pointer(&self) -> Result<Option<GenerationName>, StateError> {
        let path = self.at(CURRENT);
        let unreadable = StateError::Corrupt(CorruptReason::PointerUnreadable);
        match self.fs.kind(&path) {
            Ok(Kind::Missing) => Ok(None),
            Ok(Kind::File) => {
                let bytes = self.fs.read(&path, SMALL).map_err(|_| unreadable)?;
                record::decode_pointer(&bytes)
                    .map(Some)
                    .ok_or(StateError::Corrupt(CorruptReason::PointerMalformed))
            }
            _ => Err(unreadable),
        }
    }

    fn read_record(&self, name: &GenerationName) -> Result<OperationRecord, CorruptReason> {
        let dir = self.generation_dir(name);
        if !matches!(self.fs.kind(&dir), Ok(Kind::Dir)) {
            return Err(CorruptReason::GenerationMissing);
        }
        let path = dir.join(RECORD);
        match self.fs.kind(&path) {
            Ok(Kind::Missing) => return Err(CorruptReason::RecordMissing),
            Ok(Kind::File) => {}
            _ => return Err(CorruptReason::RecordDamaged),
        }
        let bytes = self
            .fs
            .read(&path, SMALL)
            .map_err(|_| CorruptReason::RecordDamaged)?;
        let record = OperationRecord::decode(&bytes)
            .filter(|r| r.generation == *name)
            .ok_or(CorruptReason::RecordDamaged)?;
        for file in &record.files {
            if !plain_file_name(file) || !matches!(self.fs.kind(&dir.join(file)), Ok(Kind::File)) {
                return Err(CorruptReason::FileMissing);
            }
        }
        Ok(record)
    }

    fn read_intent(&self) -> IntentFile {
        let path = self.at(INTENT);
        match self.fs.kind(&path) {
            Ok(Kind::Missing) => IntentFile::None,
            Ok(Kind::File) => match self
                .fs
                .read(&path, SMALL)
                .ok()
                .and_then(|b| Intent::decode(&b))
            {
                Some(intent) => IntentFile::Read(intent),
                None => IntentFile::Unreadable,
            },
            _ => IntentFile::Unreadable,
        }
    }

    fn write_intent(&self, intent: &Intent) -> Result<(), StateError> {
        let tmp = self.at(INTENT_TMP);
        self.remove_if_file(INTENT_TMP)?;
        self.fs
            .write_new(Point::IntentWrite, &tmp, &intent.encode())
            .map_err(plain_io(Point::IntentWrite))?;
        self.fs
            .sync_file(Point::IntentSync, &tmp)
            .map_err(plain_io(Point::IntentSync))?;
        self.fs
            .rename_over(Point::IntentRename, &tmp, &self.at(INTENT))
            .map_err(plain_io(Point::IntentRename))?;
        self.fs
            .sync_dir(Point::IntentDirSync, &self.root)
            .map_err(plain_io(Point::IntentDirSync))
    }

    fn require_free(&self, name: &GenerationName) -> Result<(), StateError> {
        match self
            .fs
            .kind(&self.generation_dir(name))
            .map_err(plain_io(Point::GenerationCreate))?
        {
            Kind::Missing => Ok(()),
            _ => Err(StateError::Refused(Refusal::NameTaken)),
        }
    }

    /// Remove the generation a pending intent names. The name was free when the intent
    /// was written, so the directory is that operation's and nothing else's.
    fn discard_staged(&self, name: &GenerationName) -> Result<Option<GenerationName>, StateError> {
        let dir = self.generation_dir(name);
        match self.fs.kind(&dir).map_err(plain_io(Point::Cleanup))? {
            Kind::Missing => Ok(None),
            Kind::Dir => {
                self.fs
                    .remove_dir_all(Point::Cleanup, &dir)
                    .map_err(plain_io(Point::Cleanup))?;
                Ok(Some(name.clone()))
            }
            // A link or a file under that name is not removed through and not followed.
            _ => Err(StateError::Corrupt(CorruptReason::GenerationMissing)),
        }
    }

    fn remove_temporaries(&self) -> Result<bool, StateError> {
        Ok(self.remove_if_file(CURRENT_TMP)? | self.remove_if_file(INTENT_TMP)?)
    }

    fn remove_if_file(&self, name: &str) -> Result<bool, StateError> {
        let path = self.at(name);
        match self.fs.kind(&path).map_err(plain_io(Point::Cleanup))? {
            Kind::File => self
                .fs
                .remove_file(Point::Cleanup, &path)
                .map(|()| true)
                .map_err(plain_io(Point::Cleanup)),
            _ => Ok(false),
        }
    }
}

fn plain_io(point: Point) -> impl Fn(std::io::Error) -> StateError {
    move |e| StateError::Io {
        point,
        kind: e.kind(),
    }
}

fn io_at<E>(point: Point) -> impl Fn(std::io::Error) -> PublishError<E> {
    move |e| {
        PublishError::State(StateError::Io {
            point,
            kind: e.kind(),
        })
    }
}

fn check_plan(plan: &Plan) -> Result<(), StateError> {
    let id = &plan.environment_id;
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(StateError::Refused(Refusal::EnvironmentId));
    }
    let digest_ok = match (plan.operation, &plan.backup_sha256) {
        (Operation::Restore, Some(digest)) => record::is_sha256_hex(digest),
        (Operation::Restore, None) => false,
        (_, digest) => digest.is_none(),
    };
    if !digest_ok {
        return Err(StateError::Refused(Refusal::BackupDigest));
    }
    if plan.operation != Operation::Restore && plan.restore_epoch != 0 {
        return Err(StateError::Refused(Refusal::EpochNotZero));
    }
    Ok(())
}

/// A file name with no separator, no leading dot and nothing but letters, digits, `.`,
/// `_` and `-`.
fn plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
