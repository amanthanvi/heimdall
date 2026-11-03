//! The file replacement primitive and the quarantine (m02-plan U4; ADR-0007 §5.3).
//!
//! **Frozen in wave 0** (m02-plan U0): every type and signature in this module that
//! existed in wave 0. Everything marked "Additive (W2-U4a)" below was added in wave 2
//! without changing a frozen signature.
//!
//! The primitive never settles by itself: settlement and restore are separate calls the
//! transaction makes (M2-R01), and every discard goes through the quarantine with the
//! expected identity **and** digest (M2-R02, M2-S02). The only removal is
//! `sys::QuarantineDir::remove_verified`.
//!
//! Steps (ADR-0007 §5.3): open and validate the directory → [`validate`] the base →
//! [`stage`] the materialized bytes at the random staged name → [`recheck`] at the
//! boundary → [`exchange`] (atomic exchange; Windows `ReplaceFileW`; a create is a
//! no-replace rename) → [`post_validate`] → commit (the item) → [`settle`] what was
//! displaced, or [`restore`] and then settle.
//!
//! **Names.** Every name is resolved relative to the [`DirHandle`] (`openat`,
//! `renameat_with`), so a substituted parent path is never followed. The frozen
//! signatures of [`recheck`], [`exchange`], [`post_validate`] and [`restore`] carry no
//! target name, so a handle remembers what it has seen, keyed so that it is never
//! ambiguous: the name each validated base identity was read from ([`validate`]), and
//! each step's target, staged and displaced names ([`observe_step`],
//! [`DirHandle::learn_step`]). A staged or displaced name in the ADR's form
//! (`.<name>.hm-<generation>-<32 hex>`, `.<name>.hm-displaced-<generation>`) also names
//! its target. When these sources disagree, or name nothing, the call refuses and moves
//! nothing. The `*_at`/`*_with` functions take the names explicitly ([`StepNames`]).
//!
//! **Test hooks.** The frozen functions fire no [`ReplaceHook`] point: the transaction
//! fires them around its calls. [`restore_with`], [`settle_with`] and
//! [`Quarantine::remove_verified_with`] fire the three points that lie *inside* a call
//! (`BeforeRestoreExchange` after the pre-restore content check, `AfterSettleMove`
//! between the move and its check, `AfterSettleCheck` between the final check and the
//! removal), for a transaction that wants exactly the windows m02-plan U4 names.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use heimdall_domain::operation::{
    FilePhase, HoldReason, LocalReceipt, PostVerdict, RestoreCause, StageReceipt,
};
use heimdall_domain::projection::{
    Base, ContentState, EffectivePhase, EntryFileType, EntryFingerprint, EntryObs, FileIdentity,
    FileStep, FingerprintContent, ItemState, RecordedRole, RecoveryState, RestoreCtx, Sha256Hex,
    StepContentView, StepFingerprint, StepObservation, StepShape, Target,
};

use super::content::{Materialized, READ_MAX};
use super::{ReplaceHook, ReplacePoint};
pub use crate::sys::IdentitySource;
use crate::sys::QuarantineDir;
use crate::sys::fsentry::{self, EntryMeta, Kind};
use crate::sys::{QUARANTINE_NAME, QuarantineError, RemoveOutcome};

/// Why a directory or file cannot be managed (manual mode, `unmanageable_file`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unmanageable {
    /// A symlink or reparse point where a directory or file must be.
    #[error("symlink or reparse point")]
    Link,
    /// A hard-linked file (link count above 1).
    #[error("hard-linked file")]
    HardLinked,
    /// Owned by another user, or not writable by this one.
    #[error("foreign owner or not writable")]
    ForeignOwner,
    /// The quarantine exists with the wrong owner or mode, or is a mount point.
    #[error("quarantine directory invalid")]
    QuarantineInvalid,
    /// Another I/O failure (the kind only).
    #[error("io: {0}")]
    Io(String),
}

/// The text of an I/O error: its OS code or kind, never a path.
fn io_text(e: &std::io::Error) -> String {
    e.raw_os_error()
        .map_or_else(|| format!("{:?}", e.kind()), |c| format!("os error {c}"))
}

/// What a handle has seen (see the module's "Names").
#[derive(Debug, Default)]
struct Known {
    /// Present bases: identity, name, permission bits.
    validated: Vec<(FileIdentity, String, u32)>,
    /// The name of the last base validated as absent, if the last validation was one.
    last_absent: Option<String>,
    /// Steps: target, staged and displaced names.
    steps: Vec<StepNames>,
}

/// An open, validated directory; every name below is resolved relative to it.
#[derive(Debug)]
pub struct DirHandle {
    path: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    /// Windows: the directory is held open without delete sharing (it cannot be
    /// renamed or removed meanwhile), and names are resolved under its final path.
    #[cfg(windows)]
    pin: std::os::windows::io::OwnedHandle,
    #[cfg(windows)]
    final_path: PathBuf,
    opened: EntryMeta,
    source: IdentitySource,
    known: Mutex<Known>,
}

/// ADR-0007 §5.3 step 1: a directory (no symlink or reparse point), owned by the
/// current user, writable and searchable by it, and (Unix) not writable by group or
/// others.
fn check_dir_meta(meta: &EntryMeta) -> Result<(), Unmanageable> {
    match meta.kind {
        Kind::Directory => {}
        Kind::Symlink => return Err(Unmanageable::Link),
        Kind::Regular | Kind::Other => return Err(Unmanageable::Io("not a directory".into())),
    }
    if !meta.owned {
        return Err(Unmanageable::ForeignOwner);
    }
    if cfg!(unix) && (meta.perm & 0o022 != 0 || meta.perm & 0o700 != 0o700) {
        return Err(Unmanageable::ForeignOwner);
    }
    Ok(())
}

impl DirHandle {
    /// Open and validate `path` (owner, no symlink or reparse point).
    ///
    /// # Errors
    /// [`Unmanageable`].
    pub fn open(path: &Path) -> Result<DirHandle, Unmanageable> {
        Self::open_with(path, IdentitySource::Native)
    }

    /// Additive (W2-U4a): [`DirHandle::open`] with an identity source. Production
    /// uses [`IdentitySource::Native`]; `WithoutBirth` is the test-only source of
    /// m02-plan U4 (Unix identities without a birth time). Quarantines opened from this
    /// handle use the same source.
    ///
    /// Unix: `open(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` and `fstat`. Windows: a
    /// handle with `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS` and no
    /// delete sharing, whose owner SID is the process user's.
    ///
    /// # Errors
    /// [`Unmanageable`].
    pub fn open_with(path: &Path, source: IdentitySource) -> Result<DirHandle, Unmanageable> {
        #[cfg(unix)]
        {
            let fd = match fsentry::open_dir_path(path) {
                Ok(fd) => fd,
                // `O_DIRECTORY|O_NOFOLLOW` on a symlink is `ELOOP` on Linux and
                // `ENOTDIR` on macOS: the entry itself says which it is.
                Err(e) => {
                    let link = fsentry::is_link_error(&e)
                        || std::fs::symlink_metadata(path)
                            .is_ok_and(|m| m.file_type().is_symlink());
                    return Err(if link {
                        Unmanageable::Link
                    } else {
                        Unmanageable::Io(io_text(&e))
                    });
                }
            };
            let opened = fsentry::fstat(&fd, source).map_err(|e| Unmanageable::Io(io_text(&e)))?;
            check_dir_meta(&opened)?;
            Ok(DirHandle {
                path: path.to_path_buf(),
                fd,
                opened,
                source,
                known: Mutex::default(),
            })
        }
        #[cfg(windows)]
        {
            let pin = fsentry::win::open_dir_pinned(path, false)
                .map_err(|e| Unmanageable::Io(io_text(&e)))?;
            let mut opened = fsentry::win::meta(&pin).map_err(|e| Unmanageable::Io(io_text(&e)))?;
            opened.identity = source.apply(opened.identity);
            check_dir_meta(&opened)?;
            let final_path =
                fsentry::win::final_path(&pin).map_err(|e| Unmanageable::Io(io_text(&e)))?;
            Ok(DirHandle {
                path: path.to_path_buf(),
                pin,
                final_path,
                opened,
                source,
                known: Mutex::default(),
            })
        }
    }

    /// The directory's path (display and diagnostics only; never re-resolved).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Additive (W2-U4a): the identity source of this handle.
    #[must_use]
    pub fn source(&self) -> IdentitySource {
        self.source
    }

    /// Additive (W2-U4a): remember `step`'s target, staged and displaced names, so
    /// the frozen [`exchange`], [`post_validate`] and [`restore`] can name its target
    /// (see the module's "Names"). [`observe_step`] calls it; a transaction that calls
    /// [`restore`] without observing first calls it itself. A step whose directory is
    /// not this handle's is ignored.
    pub fn learn_step(&self, step: &FileStep) {
        if let Ok(names) = StepNames::of(step)
            && self.contains(&step.path)
        {
            self.remember_step(names);
        }
    }

    fn dir(&self) -> fsentry::Dir<'_> {
        #[cfg(unix)]
        {
            std::os::fd::AsFd::as_fd(&self.fd)
        }
        #[cfg(windows)]
        {
            &self.final_path
        }
    }

    /// The directory still is what was validated (same identity, owner and mode).
    fn still_valid(&self) -> bool {
        #[cfg(unix)]
        let now = fsentry::fstat(&self.fd, self.source);
        #[cfg(windows)]
        let now = fsentry::win::meta(&self.pin).map(|mut m| {
            m.identity = self.source.apply(m.identity);
            m
        });
        now.is_ok_and(|m| {
            m.identity == self.opened.identity
                && check_dir_meta(&m).is_ok()
                && m.perm == self.opened.perm
        })
    }

    /// Whether `path`'s parent is this handle's directory (component-wise).
    fn contains(&self, path: &str) -> bool {
        Path::new(path)
            .parent()
            .is_some_and(|p| p.components().eq(self.path.components()))
    }

    fn known(&self) -> MutexGuard<'_, Known> {
        self.known.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn remember_validated(&self, name: &str, identity: Option<&FileIdentity>, perm: u32) {
        let mut k = self.known();
        match identity {
            Some(id) => {
                k.validated.retain(|(i, n, _)| i != id && n != name);
                k.validated.push((id.clone(), name.to_owned(), perm));
                k.last_absent = None;
            }
            None => {
                k.validated.retain(|(_, n, _)| n != name);
                k.last_absent = Some(name.to_owned());
            }
        }
    }

    fn remember_step(&self, names: StepNames) {
        let mut k = self.known();
        k.steps.retain(|s| {
            s.target != names.target
                && s.staged != names.staged
                && s.displaced.as_deref() != Some(names.staged.as_str())
        });
        k.steps.push(names);
    }

    fn validated_by_identity(&self, id: &FileIdentity) -> Option<(String, u32)> {
        self.known()
            .validated
            .iter()
            .find(|(i, _, _)| i.same_file(id))
            .map(|(_, n, p)| (n.clone(), *p))
    }

    fn validated_perm(&self, name: &str) -> Option<u32> {
        self.known()
            .validated
            .iter()
            .find(|(_, n, _)| n == name)
            .map(|(_, _, p)| *p)
    }

    fn step_by_aside(&self, aside: &str) -> Option<StepNames> {
        let k = self.known();
        let mut found = k
            .steps
            .iter()
            .filter(|s| s.staged == aside || s.displaced.as_deref() == Some(aside));
        let first = found.next()?.clone();
        found.all(|s| s.target == first.target).then_some(first)
    }

    /// Resolve the target of `aside` (a staged or displaced name), from the base
    /// identity validated through this handle, the step names it has seen, the ADR
    /// name form, and (for a create only) the last base validated as absent. Every
    /// source that names a target must name the same one.
    fn resolve(
        &self,
        aside: &str,
        base: Option<&FileIdentity>,
        create: bool,
    ) -> Result<StepNames, ReplaceError> {
        let mut targets: Vec<String> = Vec::new();
        if let Some(id) = base
            && let Some((name, _)) = self.validated_by_identity(id)
        {
            targets.push(name);
        }
        let learned = self.step_by_aside(aside);
        if let Some(s) = &learned {
            targets.push(s.target.clone());
        }
        let parsed = parse_aside(aside);
        if let Some((t, _)) = &parsed {
            targets.push(t.clone());
        }
        if targets.is_empty()
            && create
            && let Some(last) = self.known().last_absent.clone()
        {
            targets.push(last);
        }
        let Some(target) = targets.first().cloned() else {
            return Err(ReplaceError::Io("target name unknown".into()));
        };
        if targets.iter().any(|t| *t != target) {
            return Err(ReplaceError::Io("target name ambiguous".into()));
        }
        Ok(match learned {
            Some(s) => s,
            None => StepNames {
                // From a staged name: the displaced name is the staged name on Unix
                // and `.<name>.hm-displaced-<generation>` on Windows (ADR-0007 §5.7).
                displaced: parsed.and_then(|(_, generation)| generation).map(|g| {
                    if cfg!(windows) {
                        displaced_name_for(&target, g)
                    } else {
                        aside.to_owned()
                    }
                }),
                target,
                staged: aside.to_owned(),
            },
        })
    }
}

/// ADR-0007 §5.7: a staged name `.<name>.hm-<generation>-<32 lowercase hex>` or a
/// Windows displaced name `.<name>.hm-displaced-<generation>` names its target.
/// Returns the target and, for a staged name, the generation.
fn parse_aside(aside: &str) -> Option<(String, Option<u64>)> {
    let rest = aside.strip_prefix('.')?;
    let (target, suffix) = rest.rsplit_once(".hm-")?;
    if target.is_empty() || !fsentry::is_component(target) {
        return None;
    }
    let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if let Some(generation) = suffix.strip_prefix("displaced-") {
        return is_digits(generation).then(|| (target.to_owned(), None));
    }
    let (generation, random) = suffix.split_once('-')?;
    let hex = random.len() == 32
        && random
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !is_digits(generation) || !hex {
        return None;
    }
    Some((target.to_owned(), generation.parse().ok()))
}

/// The Windows displaced name of `target` (ADR-0007 §5.7).
fn displaced_name_for(target: &str, generation: u64) -> String {
    format!(".{target}.hm-displaced-{generation}")
}

/// Additive (W2-U4a): the names one step uses, relative to its directory (ADR-0007
/// §5.7 `FileStep`): the target (the last component of `FileStep.path`), the staged
/// name and, for a replace, the displaced name (the staged name on Unix,
/// `.<name>.hm-displaced-<generation>` on Windows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepNames {
    /// The path's name (for the `git_lock` step, the lock name).
    pub target: String,
    /// The staged name (K's for the `git_lock` step).
    pub staged: String,
    /// The displaced name, for a replace.
    pub displaced: Option<String>,
}

impl StepNames {
    /// The names of `step`.
    ///
    /// # Errors
    /// [`ReplaceError::Io`] when the path has no single last component, the step has no
    /// staged name, or a name is not a single component.
    pub fn of(step: &FileStep) -> Result<StepNames, ReplaceError> {
        let target = Path::new(&step.path)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ReplaceError::Io("step path has no file name".into()))?
            .to_owned();
        let staged = step
            .staged_name
            .clone()
            .ok_or_else(|| ReplaceError::Io("step has no staged name".into()))?;
        let names = StepNames {
            target,
            staged,
            displaced: step.displaced_name.clone(),
        };
        names.check()?;
        Ok(names)
    }

    fn check(&self) -> Result<(), ReplaceError> {
        let ok = fsentry::is_component(&self.target)
            && fsentry::is_component(&self.staged)
            && self.displaced.as_deref().is_none_or(fsentry::is_component)
            && self.target != self.staged;
        if ok {
            Ok(())
        } else {
            Err(ReplaceError::Io("not a single name".into()))
        }
    }
}

/// Additive (W2-U4a): where the test-only [`ReplaceHook`] fires inside a primitive
/// call (`*_with` functions). [`HookAt::NONE`] fires nothing.
#[derive(Clone, Copy)]
pub struct HookAt<'a> {
    hook: Option<&'a dyn ReplaceHook>,
    step: u16,
}

impl std::fmt::Debug for HookAt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookAt")
            .field("hook", &self.hook.is_some())
            .field("step", &self.step)
            .finish()
    }
}

impl<'a> HookAt<'a> {
    /// No hook.
    pub const NONE: HookAt<'static> = HookAt {
        hook: None,
        step: 0,
    };

    /// `hook` for step `step` (`None` in production).
    #[must_use]
    pub fn new(hook: Option<&'a dyn ReplaceHook>, step: u16) -> Self {
        Self { hook, step }
    }

    fn fire(self, point: ReplacePoint) {
        if let Some(h) = self.hook {
            h.at(point, self.step);
        }
    }
}

/// `<dir>/.hm-quarantine`: created 0700 (Windows: owner-only DACL) and validated on
/// every open (owner, mode exactly 0700, no symlink or reparse point, not a mount
/// point).
#[derive(Debug)]
pub struct Quarantine {
    dir: QuarantineDir,
}

fn quarantine_error(e: QuarantineError) -> Unmanageable {
    match e {
        QuarantineError::Invalid(_) => Unmanageable::QuarantineInvalid,
        QuarantineError::Sys(s) => Unmanageable::Io(s.to_string()),
    }
}

impl Quarantine {
    /// Open (validating) or create the quarantine of `dir`.
    ///
    /// # Errors
    /// [`Unmanageable`].
    pub fn open_or_create(dir: &DirHandle) -> Result<Quarantine, Unmanageable> {
        if !dir.still_valid() {
            return Err(Unmanageable::Io("directory changed".into()));
        }
        #[cfg(unix)]
        let q = QuarantineDir::open_or_create_in(dir.dir(), dir.source);
        #[cfg(windows)]
        let q = QuarantineDir::open_or_create_at(dir.dir(), dir.source);
        q.map(|dir| Quarantine { dir }).map_err(quarantine_error)
    }

    /// Additive (W2-U4a): open and validate the quarantine of `dir` when it exists;
    /// `Ok(None)` when it does not. Creates nothing (observation).
    ///
    /// # Errors
    /// [`Unmanageable`].
    pub fn open_existing(dir: &DirHandle) -> Result<Option<Quarantine>, Unmanageable> {
        #[cfg(unix)]
        let q = QuarantineDir::open_existing_in(dir.dir(), dir.source);
        #[cfg(windows)]
        let q = QuarantineDir::open_existing_at(dir.dir(), dir.source);
        q.map(|d| d.map(|dir| Quarantine { dir }))
            .map_err(quarantine_error)
    }

    /// Re-check identity and digest, then remove `slot`. Called after
    /// `file.settled` is durable.
    ///
    /// # Errors
    /// [`ReplaceError`].
    pub fn remove_verified(
        &self,
        slot: &str,
        expected: &Expected,
    ) -> Result<RemoveVerified, ReplaceError> {
        self.remove_verified_with(slot, expected, HookAt::NONE)
    }

    /// Additive (W2-U4a): [`Quarantine::remove_verified`], firing `AfterSettleCheck`
    /// between the final identity and digest check and the removal.
    ///
    /// # Errors
    /// [`ReplaceError`].
    pub fn remove_verified_with(
        &self,
        slot: &str,
        expected: &Expected,
        hook: HookAt<'_>,
    ) -> Result<RemoveVerified, ReplaceError> {
        let outcome = self
            .dir
            .remove_verified_with(
                slot,
                &expected.identity,
                expected.sha256.as_str(),
                &mut || hook.fire(ReplacePoint::AfterSettleCheck),
            )
            .map_err(|e| ReplaceError::Io(e.to_string()))?;
        Ok(match outcome {
            RemoveOutcome::Removed => RemoveVerified::Removed,
            RemoveOutcome::Missing => RemoveVerified::Missing,
            RemoveOutcome::IdentityMismatch => RemoveVerified::Foreign,
            RemoveOutcome::ContentMismatch => RemoveVerified::Modified,
        })
    }

    /// Remove the quarantine when it is empty; never removes an entry.
    ///
    /// # Errors
    /// [`ReplaceError`].
    pub fn rmdir_if_empty(self) -> Result<bool, ReplaceError> {
        self.dir
            .rmdir_if_empty()
            .map_err(|e| ReplaceError::Io(e.to_string()))
    }

    /// Additive (W2-U4a): what `slot` holds against `expected` (rows F8–F9, R1–R6).
    #[must_use]
    pub fn check_slot(&self, slot: &str, expected: &Expected) -> NameState {
        name_state(self.dir.dir(), slot, self.dir.source(), expected)
    }

    /// Additive (W2-U4a): move the entry in `slot` back to `name` in `dir` with
    /// no-replace (rows F8d, R5). If `name` is occupied again, the entry is kept as
    /// `<name>.hm-conflict-<slot>` beside it; if that is occupied too, it stays in the
    /// slot. Nothing is ever deleted or overwritten.
    ///
    /// # Errors
    /// [`ReplaceError::Io`] on another failure (nothing moved).
    pub fn put_back(
        &self,
        dir: &DirHandle,
        slot: &str,
        name: &str,
    ) -> Result<SettleOutcome, ReplaceError> {
        if !fsentry::is_component(slot) || !fsentry::is_component(name) {
            return Err(ReplaceError::Io("not a single name".into()));
        }
        put_back(dir, self, slot, name)
    }
}

/// Additive (W2-U4a): what a name holds against an expected identity and digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameState {
    /// No entry.
    Absent,
    /// A regular file owned by the user with one link and the expected identity, with
    /// or without the expected content (L/L′, Q/Q′ …).
    Expected(ContentState),
    /// Anything else (X).
    Foreign,
    /// The observation failed (?).
    Unobservable,
}

/// Additive (W2-U4a): what `name` in `dir` holds against `expected` (the cleaner's
/// rows R1–R6 and every other identity-and-digest check by name).
#[must_use]
pub fn check_name(dir: &DirHandle, name: &str, expected: &Expected) -> NameState {
    if !fsentry::is_component(name) || !dir.still_valid() {
        return NameState::Unobservable;
    }
    name_state(dir.dir(), name, dir.source, expected)
}

fn name_state(
    dir: fsentry::Dir<'_>,
    name: &str,
    source: IdentitySource,
    expected: &Expected,
) -> NameState {
    match fsentry::inspect(dir, name, source) {
        Ok(None) => NameState::Absent,
        Err(_) => NameState::Unobservable,
        Ok(Some((meta, file))) => {
            if meta.is_heimdall_shape() && meta.identity.same_file(&expected.identity) {
                NameState::Expected(content_state(file.as_ref(), &expected.sha256))
            } else {
                NameState::Foreign
            }
        }
    }
}

/// `Unchanged` only when the whole content (at most 1 MiB) hashes to `sha256`.
fn content_state(file: Option<&std::fs::File>, sha256: &Sha256Hex) -> ContentState {
    match file.map(fsentry::read_bounded) {
        Some(Ok(Some(bytes))) if Sha256Hex::of(&bytes) == *sha256 => ContentState::Unchanged,
        _ => ContentState::Modified,
    }
}

/// What a verified removal found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveVerified {
    /// Removed.
    Removed,
    /// Already gone (F9b).
    Missing,
    /// Another identity: kept (F9c).
    Foreign,
    /// The content changed after the check: kept (F9a, `settle_conflict{modified}`).
    Modified,
}

/// What a discard requires: identity and content digest (M2-S02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The recorded identity.
    pub identity: FileIdentity,
    /// The expected content digest.
    pub sha256: Sha256Hex,
}

/// The base as validated, with its bytes (the splice input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    /// V's identity, or `None` when the base is absent.
    pub identity: Option<FileIdentity>,
    /// The base digest, when present.
    pub sha256: Option<Sha256Hex>,
    /// The base bytes, when present (at most 1 MiB).
    pub bytes: Option<Vec<u8>>,
}

/// The staged file S.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// S's identity.
    pub identity: FileIdentity,
    /// Its random name.
    pub name: String,
}

/// An exchange that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchanged {
    /// Where the displaced entry now is (`None` for a create).
    pub displaced_name: Option<String>,
}

/// The mode of a staged file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// 0600 / owner-only DACL.
    OwnerReadWrite,
    /// 0644 for public files (key `.pub` files), owner-writable.
    PublicRead,
}

impl Mode {
    fn perm(self) -> u32 {
        match self {
            Mode::OwnerReadWrite => 0o600,
            Mode::PublicRead => 0o644,
        }
    }
}

/// Why a step stops before its exchange (nothing active changed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplaceRefusal {
    /// The path no longer holds the planned base (`user_config_changed`,
    /// `managed_file_edited`).
    #[error("base changed")]
    BaseChanged,
    /// The path is not manageable.
    #[error("unmanageable: {0}")]
    Unmanageable(Unmanageable),
    /// The filesystem has no atomic exchange: manual mode.
    #[error("atomic exchange unsupported")]
    AtomicExchangeUnsupported,
}

/// A failure inside a step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplaceError {
    /// A refusal.
    #[error("refused: {0}")]
    Refused(ReplaceRefusal),
    /// The name to create exists (no-replace).
    #[error("name exists")]
    Exists,
    /// Another I/O failure (the kind only).
    #[error("io: {0}")]
    Io(String),
}

/// The result of post-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostValidation {
    /// The path is S and the displaced entry is V.
    Valid,
    /// The displaced entry is not V.
    Mismatch {
        /// What was found at the displaced name.
        observed: Option<FileIdentity>,
    },
}

/// The result of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// D is back at the path and S is aside.
    Restored,
    /// Nothing was moved (`active_entry_modified`, `third_writer` …).
    Held(HoldReason, StepObservation),
}

/// The result of a settlement move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// Moved into the slot with the expected identity and digest; the caller writes
    /// `file.settled`, then removes.
    Settled,
    /// Moved, but its content changed: kept in the quarantine.
    Modified {
        /// The slot.
        slot: String,
    },
    /// Nothing at the source (`settle_conflict{missing}`).
    Missing,
    /// A foreign entry was moved and put back.
    ForeignPutBack {
        /// Where it is.
        path: String,
    },
    /// A foreign entry was kept under a conflict name.
    ForeignKept {
        /// Where it is.
        path: String,
    },
}

/// The recorded identities and digests of a step (S, V, D, Q), from its receipts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StepRecord {
    /// S (K for the `git_lock` step) with the target digest.
    pub staged: Option<Expected>,
    /// V with the base digest.
    pub validated: Option<Expected>,
    /// D, the identity `post_validated{mismatch}` recorded.
    pub displaced_mismatch: Option<FileIdentity>,
    /// Q, from the open `file.settling`.
    pub settling: Option<Expected>,
}

impl StepRecord {
    /// Additive (W2-U4a): the record of step `index` (`step` is its `FileStep`) from
    /// the operation's receipts: S from the last `file.staged` with the target digest
    /// (the holder digest for the `git_lock` step), V from the last
    /// `file.validated{base}` with the base digest, D from the last
    /// `post_validated{mismatch}`, Q from the last `file.settling`. `held` receipts and
    /// other steps' receipts are ignored.
    #[must_use]
    pub fn from_receipts(index: u16, step: &FileStep, receipts: &[StageReceipt]) -> StepRecord {
        let target_sha = match (&step.target, step.content.view()) {
            (Target::Present { sha256 }, _) => Some(sha256.clone()),
            (Target::Absent, StepContentView::LockHolder { bytes }) => Some(Sha256Hex::of(bytes)),
            (Target::Absent, _) => None,
        };
        let base_sha = match &step.base {
            Base::Present { sha256 } => Some(sha256.clone()),
            Base::Absent => None,
        };
        let mut rec = StepRecord::default();
        for phase in step_phases(index, receipts) {
            match phase {
                FilePhase::Staged { identity } => {
                    rec.staged = target_sha.clone().map(|sha256| Expected {
                        identity: identity.clone(),
                        sha256,
                    });
                }
                FilePhase::Validated { base: Some(v) } => {
                    rec.validated = base_sha.clone().map(|sha256| Expected {
                        identity: v.clone(),
                        sha256,
                    });
                }
                FilePhase::PostValidated {
                    verdict: PostVerdict::Mismatch,
                    observed,
                } => rec.displaced_mismatch.clone_from(observed),
                FilePhase::Settling {
                    expected,
                    expected_sha256,
                    ..
                } => {
                    rec.settling = Some(Expected {
                        identity: expected.clone(),
                        sha256: expected_sha256.clone(),
                    });
                }
                _ => {}
            }
        }
        rec
    }
}

fn step_phases(index: u16, receipts: &[StageReceipt]) -> impl Iterator<Item = &FilePhase> {
    receipts.iter().filter_map(move |r| match &r.local {
        Some(LocalReceipt::File { step, phase }) if *step == index => Some(phase),
        _ => None,
    })
}

/// Additive (W2-U4a): what a step's `file.settling` recorded: the source name, the
/// slot and the expected entry (Q).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlingAt {
    /// The source name (the path's name for a create restore and K's release).
    pub name: String,
    /// The quarantine slot.
    pub slot: String,
    /// Q: the expected identity and digest.
    pub expected: Expected,
}

impl SettlingAt {
    /// The last `file.settling` of step `index`, if any.
    #[must_use]
    pub fn from_receipts(index: u16, receipts: &[StageReceipt]) -> Option<SettlingAt> {
        step_phases(index, receipts)
            .filter_map(|p| match p {
                FilePhase::Settling {
                    name,
                    expected,
                    expected_sha256,
                    slot,
                    ..
                } => Some(SettlingAt {
                    name: name.clone(),
                    slot: slot.clone(),
                    expected: Expected {
                        identity: expected.clone(),
                        sha256: expected_sha256.clone(),
                    },
                }),
                _ => None,
            })
            .last()
    }

    fn from_state(state: &RecoveryState) -> Option<SettlingAt> {
        match &state.phase {
            Some(EffectivePhase::Settling {
                name,
                expected,
                expected_sha256,
                slot,
                ..
            }) => Some(SettlingAt {
                name: name.clone(),
                slot: slot.clone(),
                expected: Expected {
                    identity: expected.clone(),
                    sha256: expected_sha256.clone(),
                },
            }),
            _ => None,
        }
    }
}

// --- step 2: validate --------------------------------------------------------------

/// ADR-0007 §5.3 step 2's file rules: a regular file (no symlink or reparse point),
/// owned by the current user, one link, and (Unix) owner-readable and -writable with
/// no group or other write bit.
fn check_file_meta(meta: &EntryMeta) -> Result<(), Unmanageable> {
    match meta.kind {
        Kind::Regular => {}
        Kind::Symlink => return Err(Unmanageable::Link),
        Kind::Directory | Kind::Other => {
            return Err(Unmanageable::Io("not a regular file".into()));
        }
    }
    if !meta.owned {
        return Err(Unmanageable::ForeignOwner);
    }
    if meta.nlink != 1 {
        return Err(Unmanageable::HardLinked);
    }
    if cfg!(unix) && (meta.perm & 0o022 != 0 || meta.perm & 0o600 != 0o600) {
        return Err(Unmanageable::ForeignOwner);
    }
    Ok(())
}

fn unmanageable(e: &std::io::Error) -> ReplaceRefusal {
    ReplaceRefusal::Unmanageable(Unmanageable::Io(io_text(e)))
}

/// Validate the base at `name`.
///
/// `Base::Absent`: `lstat` must report no entry (else [`ReplaceRefusal::BaseChanged`]).
/// `Base::Present`: the entry is opened without following it (Unix
/// `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`), must pass the file rules (else
/// [`ReplaceRefusal::Unmanageable`], manual mode), and its content (at most 1 MiB) must
/// hash to the base digest (else [`ReplaceRefusal::BaseChanged`]). Records V's identity
/// (with the birth time where the filesystem records one) and the name it was read
/// from in the handle. Nothing is written.
///
/// # Errors
/// [`ReplaceRefusal`].
pub fn validate(dir: &DirHandle, name: &str, base: &Base) -> Result<Validated, ReplaceRefusal> {
    if !fsentry::is_component(name) {
        return Err(ReplaceRefusal::Unmanageable(Unmanageable::Io(
            "not a single name".into(),
        )));
    }
    if !dir.still_valid() {
        return Err(ReplaceRefusal::Unmanageable(Unmanageable::Io(
            "directory changed".into(),
        )));
    }
    match base {
        Base::Absent => match fsentry::lstat(dir.dir(), name, dir.source) {
            Ok(None) => {
                dir.remember_validated(name, None, 0);
                Ok(Validated {
                    identity: None,
                    sha256: None,
                    bytes: None,
                })
            }
            Ok(Some(_)) => Err(ReplaceRefusal::BaseChanged),
            Err(e) => Err(unmanageable(&e)),
        },
        Base::Present { sha256 } => {
            let (meta, file) = match fsentry::inspect(dir.dir(), name, dir.source) {
                Ok(None) => return Err(ReplaceRefusal::BaseChanged),
                Ok(Some(found)) => found,
                Err(e) => return Err(unmanageable(&e)),
            };
            check_file_meta(&meta).map_err(ReplaceRefusal::Unmanageable)?;
            let Some(file) = file else {
                return Err(ReplaceRefusal::BaseChanged);
            };
            let bytes = match fsentry::read_bounded(&file) {
                Ok(Some(b)) => b,
                Ok(None) => return Err(ReplaceRefusal::BaseChanged),
                Err(e) => return Err(unmanageable(&e)),
            };
            if Sha256Hex::of(&bytes) != *sha256 {
                return Err(ReplaceRefusal::BaseChanged);
            }
            dir.remember_validated(name, Some(&meta.identity), meta.perm);
            Ok(Validated {
                identity: Some(meta.identity),
                sha256: Some(sha256.clone()),
                bytes: Some(bytes),
            })
        }
    }
}

// --- step 3: stage -----------------------------------------------------------------

/// Create S exclusively at `staged_name` with `bytes`, fsync'd.
///
/// Unix: `openat(O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC)`, then `fchmod` to the
/// original's permission bits when `staged_name` names a target this handle validated
/// as present (ADR-0007 §5.3 step 3; `& 0o755`), else to `mode` (0600 or 0644), so the
/// umask cannot narrow it. Windows: `CREATE_NEW` with an owner-only DACL. Then the
/// bytes are written and `fsync`'d, and S's identity is read from the open file. A
/// name that exists is [`ReplaceError::Exists`]; nothing is ever removed, so a write
/// that fails half-way leaves the partial file at its random name for recovery (rows
/// F0x, F1).
///
/// # Errors
/// [`ReplaceError`].
pub fn stage(
    dir: &DirHandle,
    staged_name: &str,
    bytes: &Materialized,
    mode: Mode,
) -> Result<Staged, ReplaceError> {
    use std::io::Write as _;
    if !fsentry::is_component(staged_name) {
        return Err(ReplaceError::Io("not a single name".into()));
    }
    if !dir.still_valid() {
        return Err(ReplaceError::Refused(ReplaceRefusal::Unmanageable(
            Unmanageable::Io("directory changed".into()),
        )));
    }
    if bytes.bytes.len() > READ_MAX || Sha256Hex::of(&bytes.bytes) != bytes.sha256 {
        return Err(ReplaceError::Io(
            "materialized bytes do not match their digest".into(),
        ));
    }
    let target = dir
        .step_by_aside(staged_name)
        .map(|s| s.target)
        .or_else(|| parse_aside(staged_name).map(|(t, _)| t));
    let perm = target
        .as_deref()
        .and_then(|t| dir.validated_perm(t))
        .map_or(mode.perm(), |p| (p & 0o755) | 0o600);
    let mut file = match fsentry::create_new(dir.dir(), staged_name, perm) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ReplaceError::Exists);
        }
        Err(e) => return Err(ReplaceError::Io(io_text(&e))),
    };
    file.write_all(&bytes.bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| ReplaceError::Io(io_text(&e)))?;
    #[cfg(unix)]
    let meta = fsentry::fstat(&file, dir.source);
    #[cfg(windows)]
    let meta = fsentry::win::meta(&file).map(|mut m| {
        m.identity = dir.source.apply(m.identity);
        m
    });
    let meta = meta.map_err(|e| ReplaceError::Io(io_text(&e)))?;
    Ok(Staged {
        identity: meta.identity,
        name: staged_name.to_owned(),
    })
}

// --- step 4: recheck ---------------------------------------------------------------

/// Re-check the base at the boundary (step 4).
///
/// A present base is found by its identity among the bases validated through `dir`
/// and re-checked by [`recheck_at`]. For an absent base, the name last validated as
/// absent through `dir` must still be absent; the create itself is a no-replace rename
/// that refuses an existing name, which is the atomic form of this check.
///
/// # Errors
/// [`ReplaceRefusal`].
pub fn recheck(dir: &DirHandle, validated: &Validated) -> Result<(), ReplaceRefusal> {
    let name = match &validated.identity {
        Some(id) => match dir.validated_by_identity(id) {
            Some((name, _)) => name,
            None => {
                return Err(ReplaceRefusal::Unmanageable(Unmanageable::Io(
                    "base not validated through this handle".into(),
                )));
            }
        },
        None => match dir.known().last_absent.clone() {
            Some(name) => name,
            None => return Ok(()),
        },
    };
    recheck_at(dir, &name, validated)
}

/// Additive (W2-U4a): [`recheck`] of the named entry. The entry must still be V
/// (same identity, type, owner, link count and mode) with the base digest, or still be
/// absent; anything else is [`ReplaceRefusal::BaseChanged`]. This narrows the race
/// window; it does not close it (ADR-0007 §5.3 step 4).
///
/// # Errors
/// [`ReplaceRefusal`].
pub fn recheck_at(
    dir: &DirHandle,
    name: &str,
    validated: &Validated,
) -> Result<(), ReplaceRefusal> {
    if !fsentry::is_component(name) || !dir.still_valid() {
        return Err(ReplaceRefusal::Unmanageable(Unmanageable::Io(
            "directory changed".into(),
        )));
    }
    let Some(id) = &validated.identity else {
        return match fsentry::lstat(dir.dir(), name, dir.source) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(ReplaceRefusal::BaseChanged),
            Err(e) => Err(unmanageable(&e)),
        };
    };
    let Some(sha256) = &validated.sha256 else {
        return Err(ReplaceRefusal::BaseChanged);
    };
    let (meta, file) = match fsentry::inspect(dir.dir(), name, dir.source) {
        Ok(Some((meta, Some(file)))) => (meta, file),
        Ok(_) => return Err(ReplaceRefusal::BaseChanged),
        Err(e) => return Err(unmanageable(&e)),
    };
    let perm_same = dir
        .validated_by_identity(id)
        .is_none_or(|(_, perm)| perm == meta.perm);
    if !meta.identity.same_file(id) || check_file_meta(&meta).is_err() || !perm_same {
        return Err(ReplaceRefusal::BaseChanged);
    }
    if content_state(Some(&file), sha256) != ContentState::Unchanged {
        return Err(ReplaceRefusal::BaseChanged);
    }
    Ok(())
}

// --- step 5: exchange --------------------------------------------------------------

/// Exchange S with the path (or create it with no-replace when `validated` is
/// `None`).
///
/// The target is resolved from what `dir` has seen (see the module's "Names"); an
/// unknown or ambiguous target is [`ReplaceError::Io`] and nothing moves. Then
/// [`exchange_at`].
///
/// # Errors
/// [`ReplaceError`].
pub fn exchange(
    dir: &DirHandle,
    staged: &Staged,
    validated: Option<&Validated>,
) -> Result<Exchanged, ReplaceError> {
    let base = validated.and_then(|v| v.identity.as_ref());
    let names = dir.resolve(&staged.name, base, base.is_none())?;
    exchange_at(dir, &names, staged, validated)
}

/// Additive (W2-U4a): [`exchange`] with explicit names.
///
/// S must still be at its staged name (identity, regular, owned, one link), else
/// [`ReplaceError::Io`] and nothing moves. A replace (`validated` with an identity):
/// Unix atomic exchange of the staged name and the target (`renameat_with`
/// `RENAME_EXCHANGE`/`RENAME_SWAP`; D lands at the staged name); Windows
/// `ReplaceFileW(target, staged, backup = displaced)`, with the displaced name
/// required to be free first. A create: a no-replace rename of the staged name onto the
/// target; an existing target is [`ReplaceError::Exists`]. A filesystem without the
/// exchange (`EINVAL`, `ENOTSUP`, `ENOSYS`) is
/// [`ReplaceRefusal::AtomicExchangeUnsupported`] (manual mode); a target that vanished
/// before a replace is [`ReplaceRefusal::BaseChanged`]. There is no plain-rename
/// fallback.
///
/// # Errors
/// [`ReplaceError`].
pub fn exchange_at(
    dir: &DirHandle,
    names: &StepNames,
    staged: &Staged,
    validated: Option<&Validated>,
) -> Result<Exchanged, ReplaceError> {
    names.check()?;
    if names.staged != staged.name {
        return Err(ReplaceError::Io(
            "staged name differs from the step's".into(),
        ));
    }
    if !dir.still_valid() {
        return Err(ReplaceError::Refused(ReplaceRefusal::Unmanageable(
            Unmanageable::Io("directory changed".into()),
        )));
    }
    match fsentry::lstat(dir.dir(), &staged.name, dir.source) {
        Ok(Some(m)) if m.is_heimdall_shape() && m.identity.same_file(&staged.identity) => {}
        Ok(_) => return Err(ReplaceError::Io("staged entry changed".into())),
        Err(e) => return Err(ReplaceError::Io(io_text(&e))),
    }
    let replace = validated.is_some_and(|v| v.identity.is_some());
    let map = |e: std::io::Error| -> ReplaceError {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            ReplaceError::Exists
        } else if e.kind() == std::io::ErrorKind::NotFound && replace {
            ReplaceError::Refused(ReplaceRefusal::BaseChanged)
        } else if fsentry::is_unsupported(&e) {
            ReplaceError::Refused(ReplaceRefusal::AtomicExchangeUnsupported)
        } else {
            ReplaceError::Io(io_text(&e))
        }
    };
    let displaced_name = if replace {
        #[cfg(unix)]
        {
            fsentry::exchange(dir.dir(), &staged.name, &names.target).map_err(map)?;
            Some(staged.name.clone())
        }
        #[cfg(windows)]
        {
            let displaced = names
                .displaced
                .clone()
                .ok_or_else(|| ReplaceError::Io("displaced name unknown".into()))?;
            match fsentry::lstat(dir.dir(), &displaced, dir.source) {
                Ok(None) => {}
                Ok(Some(_)) => return Err(ReplaceError::Exists),
                Err(e) => return Err(ReplaceError::Io(io_text(&e))),
            }
            fsentry::replace(dir.dir(), &names.target, &staged.name, &displaced).map_err(map)?;
            Some(displaced)
        }
    } else {
        fsentry::rename_noreplace(dir.dir(), &staged.name, dir.dir(), &names.target)
            .map_err(map)?;
        None
    };
    dir.remember_step(names.clone());
    Ok(Exchanged { displaced_name })
}

// --- step 6: post-validate ---------------------------------------------------------

/// Check that the path is S and the displaced entry is V.
///
/// [`PostValidation::Mismatch`] with `observed: None` when the target is unknown, the
/// path does not hold S, or nothing readable is at the displaced name (the table then
/// decides from an observation: F3b, F3c, C6a); with `observed: Some(identity)` when the
/// path is S and the displaced entry is another identity, or V with other content.
#[must_use]
pub fn post_validate(
    dir: &DirHandle,
    exchanged: &Exchanged,
    validated: &Validated,
    staged: &Staged,
) -> PostValidation {
    match dir.resolve(
        &staged.name,
        validated.identity.as_ref(),
        validated.identity.is_none(),
    ) {
        Ok(names) => post_validate_at(dir, &names, exchanged, validated, staged),
        Err(_) => PostValidation::Mismatch { observed: None },
    }
}

/// Additive (W2-U4a): [`post_validate`] with explicit names.
#[must_use]
pub fn post_validate_at(
    dir: &DirHandle,
    names: &StepNames,
    exchanged: &Exchanged,
    validated: &Validated,
    staged: &Staged,
) -> PostValidation {
    let none = PostValidation::Mismatch { observed: None };
    if names.check().is_err() || !dir.still_valid() {
        return none;
    }
    let path_is_s = matches!(
        fsentry::lstat(dir.dir(), &names.target, dir.source),
        Ok(Some(m)) if m.is_heimdall_shape() && m.identity.same_file(&staged.identity)
    );
    if !path_is_s {
        return none;
    }
    let (Some(v), Some(base_sha)) = (&validated.identity, &validated.sha256) else {
        return if validated.identity.is_none() {
            PostValidation::Valid
        } else {
            none
        };
    };
    let Some(displaced) = exchanged.displaced_name.as_deref() else {
        return none;
    };
    if !fsentry::is_component(displaced) {
        return none;
    }
    match fsentry::inspect(dir.dir(), displaced, dir.source) {
        Ok(Some((meta, file))) => {
            let ok = meta.is_heimdall_shape()
                && meta.identity.same_file(v)
                && content_state(file.as_ref(), base_sha) == ContentState::Unchanged;
            if ok {
                PostValidation::Valid
            } else {
                PostValidation::Mismatch {
                    observed: Some(meta.identity),
                }
            }
        }
        Ok(None) | Err(_) => none,
    }
}

// --- step 7: restore ---------------------------------------------------------------

/// Additive (W2-U4a): why [`restore_with`] stopped without an outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestoreFailure<E> {
    /// The caller's callback (writing `file.restore_started`) failed: nothing moved.
    #[error("before the restore exchange")]
    BeforeExchange(E),
    /// The restore exchange itself failed (the kind only). An exchange is atomic, so
    /// nothing moved; the caller re-observes.
    #[error("io: {0}")]
    Io(String),
}

/// Exchange back: first check that the path holds S with the target digest
/// (`at_path`), else hold and move nothing (QR13).
///
/// The target (and on Windows the staged name) is resolved from what `dir` has seen
/// (see the module's "Names"). An unknown target is `Held(Unmatched)`; a failed
/// exchange is `Held(Unobservable)`. Then [`restore_with`] with no callback.
#[must_use]
pub fn restore(
    dir: &DirHandle,
    exchanged: &Exchanged,
    at_path: &Expected,
    aside: FileIdentity,
) -> RestoreOutcome {
    let unknown = || {
        RestoreOutcome::Held(
            HoldReason::Unmatched,
            restore_observation(EntryObs::Unobservable, EntryObs::Unobservable),
        )
    };
    let Some(displaced) = exchanged.displaced_name.as_deref() else {
        return unknown();
    };
    let Ok(mut names) = dir.resolve(displaced, Some(&aside), false) else {
        return unknown();
    };
    // Windows restores S to its own staged name, which only the step's names give
    // (the displaced name is `.<name>.hm-displaced-<generation>`).
    if cfg!(windows) && names.staged == displaced {
        return unknown();
    }
    names.displaced = Some(displaced.to_owned());
    match restore_with(dir, &names, at_path, &aside, HookAt::NONE, || {
        Ok::<(), std::convert::Infallible>(())
    }) {
        Ok(outcome) => outcome,
        Err(_) => RestoreOutcome::Held(
            HoldReason::Unobservable,
            restore_observation(EntryObs::Unobservable, EntryObs::Unobservable),
        ),
    }
}

/// Additive (W2-U4a): the restore of ADR-0007 §5.3 step 7 with the receipt written
/// where the ADR puts it.
///
/// 1. **Before anything moves:** the path must hold S (`at_path.identity`) with the
///    target digest, and the displaced name D (`aside`, by identity alone, whatever it
///    is). S with other content is
///    `Held(ActiveEntryModified)` (QR13, row F5a); anything else is
///    `Held(ThirdWriter)` (row F5d). Nothing moves.
/// 2. `before_exchange` runs (the transaction writes `file.restore_started`); an error
///    is [`RestoreFailure::BeforeExchange`] and nothing moves.
/// 3. `BeforeRestoreExchange` fires, then the restore exchange: Unix the atomic
///    exchange of the displaced name and the path; Windows
///    `ReplaceFileW(path, displaced, backup = staged)`, with the staged name required to
///    be free.
/// 4. Both identities are verified: D at the path and S at the staged name gives
///    `Restored`. Anything else (a writer raced the exchange) is `Held(ThirdWriter)`;
///    the caller writes no `file.restored` and recovery recognizes what happened
///    (rows F5b, F5c).
///
/// # Errors
/// [`RestoreFailure`].
pub fn restore_with<E>(
    dir: &DirHandle,
    names: &StepNames,
    at_path: &Expected,
    aside: &FileIdentity,
    hook: HookAt<'_>,
    before_exchange: impl FnOnce() -> Result<(), E>,
) -> Result<RestoreOutcome, RestoreFailure<E>> {
    let Some(displaced) = names.displaced.as_deref() else {
        return Ok(RestoreOutcome::Held(
            HoldReason::Unmatched,
            restore_observation(EntryObs::Unobservable, EntryObs::Unobservable),
        ));
    };
    if names.check().is_err() || !fsentry::is_component(displaced) || !dir.still_valid() {
        return Ok(RestoreOutcome::Held(
            HoldReason::Unobservable,
            restore_observation(EntryObs::Unobservable, EntryObs::Unobservable),
        ));
    }
    let (path, aside_obs) = restore_symbols(dir, names, displaced, at_path, aside);
    let d = EntryObs::Recorded {
        which: RecordedRole::D,
        content: ContentState::Unchanged,
    };
    let s_unchanged = EntryObs::Recorded {
        which: RecordedRole::S,
        content: ContentState::Unchanged,
    };
    let s_modified = EntryObs::Recorded {
        which: RecordedRole::S,
        content: ContentState::Modified,
    };
    if aside_obs != d || (path != s_unchanged && path != s_modified) {
        return Ok(RestoreOutcome::Held(
            HoldReason::ThirdWriter,
            restore_observation(path, aside_obs),
        ));
    }
    if path == s_modified {
        return Ok(RestoreOutcome::Held(
            HoldReason::ActiveEntryModified,
            restore_observation(path, aside_obs),
        ));
    }
    #[cfg(windows)]
    match fsentry::lstat(dir.dir(), &names.staged, dir.source) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Ok(RestoreOutcome::Held(
                HoldReason::ThirdWriter,
                restore_observation(path, aside_obs),
            ));
        }
        Err(e) => return Err(RestoreFailure::Io(io_text(&e))),
    }
    before_exchange().map_err(RestoreFailure::BeforeExchange)?;
    hook.fire(ReplacePoint::BeforeRestoreExchange);
    #[cfg(unix)]
    let moved = fsentry::exchange(dir.dir(), displaced, &names.target);
    #[cfg(windows)]
    let moved = fsentry::replace(dir.dir(), &names.target, displaced, &names.staged);
    moved.map_err(|e| RestoreFailure::Io(io_text(&e)))?;
    #[cfg(unix)]
    let s_at = displaced;
    #[cfg(windows)]
    let s_at = names.staged.as_str();
    let has = |name: &str, id: &FileIdentity, shape: bool| {
        matches!(
            fsentry::lstat(dir.dir(), name, dir.source),
            Ok(Some(m)) if (!shape || m.is_heimdall_shape()) && m.identity.same_file(id)
        )
    };
    if has(&names.target, aside, false) && has(s_at, &at_path.identity, true) {
        Ok(RestoreOutcome::Restored)
    } else {
        let (path, aside_obs) = restore_symbols(dir, names, displaced, at_path, aside);
        Ok(RestoreOutcome::Held(
            HoldReason::ThirdWriter,
            restore_observation(path, aside_obs),
        ))
    }
}

/// The path against S (with the target digest) and the displaced name against D.
fn restore_symbols(
    dir: &DirHandle,
    names: &StepNames,
    displaced: &str,
    at_path: &Expected,
    aside: &FileIdentity,
) -> (EntryObs, EntryObs) {
    let path = match fsentry::inspect(dir.dir(), &names.target, dir.source) {
        Ok(None) => EntryObs::Absent,
        Err(_) => EntryObs::Unobservable,
        Ok(Some((meta, file))) => {
            if meta.is_heimdall_shape() && meta.identity.same_file(&at_path.identity) {
                EntryObs::Recorded {
                    which: RecordedRole::S,
                    content: content_state(file.as_ref(), &at_path.sha256),
                }
            } else {
                EntryObs::Foreign
            }
        }
    };
    // D is matched by identity alone: it goes back to the path whatever it holds (a
    // symlink a writer substituted included; ADR-0007 §5.3 step 7).
    let aside_obs = match fsentry::lstat(dir.dir(), displaced, dir.source) {
        Ok(None) => EntryObs::Absent,
        Err(_) => EntryObs::Unobservable,
        Ok(Some(meta)) => {
            if meta.identity.same_file(aside) {
                EntryObs::Recorded {
                    which: RecordedRole::D,
                    content: ContentState::Unchanged,
                }
            } else {
                EntryObs::Foreign
            }
        }
    };
    (path, aside_obs)
}

/// The observation a `Held` restore reports. `restore` has no recovery state, so the
/// observation is normalized against the state a due restore after a recorded
/// mismatch has (which admits D at the aside name).
fn restore_observation(path: EntryObs, aside: EntryObs) -> StepObservation {
    let state = RecoveryState {
        phase: Some(EffectivePhase::RestoreStarted {
            cause: RestoreCause::FileMismatch,
        }),
        restore: RestoreCtx::Started(RestoreCause::FileMismatch),
        settlement: None,
        item: ItemState::Open,
        release_due: false,
    };
    normalized(path, aside, EntryObs::Absent, &state, StepShape::Replace)
}

/// `StepObservation::normalize`, falling back to an all-unobservable observation (which
/// recovery holds as `unobservable`) when the observed combination is rejected.
fn normalized(
    path: EntryObs,
    aside: EntryObs,
    slot: EntryObs,
    state: &RecoveryState,
    shape: StepShape,
) -> StepObservation {
    let slot_unobservable = if state.settlement.is_some() {
        EntryObs::Unobservable
    } else {
        EntryObs::Absent
    };
    let empty = RecoveryState {
        phase: None,
        restore: RestoreCtx::NotDue,
        settlement: None,
        item: ItemState::Open,
        release_due: false,
    };
    StepObservation::normalize(path, aside, slot, state, shape)
        .or_else(|_| {
            StepObservation::normalize(
                EntryObs::Unobservable,
                EntryObs::Unobservable,
                slot_unobservable,
                state,
                shape,
            )
        })
        .or_else(|_| {
            StepObservation::normalize(
                EntryObs::Unobservable,
                EntryObs::Unobservable,
                EntryObs::Absent,
                &empty,
                shape,
            )
        })
        .unwrap_or_else(|e| {
            // ADR-0007 §5.7: every `?` is a valid observation (decided `Hold` before
            // any row), so the normalizer must accept an all-unobservable observation
            // of the empty state. Reaching this is a defect of the normalizer.
            panic!("StepObservation::normalize rejected an all-unobservable observation: {e}")
        })
}

// --- step 8: settle ----------------------------------------------------------------

/// Move `source_name` into `slot` with no-replace, then verify identity and digest.
/// Returns before removal; the caller writes `file.settled` between the two.
///
/// [`settle_with`] with no hook; a failure before anything moved (an I/O error, or a
/// slot that is already occupied) is reported as `ForeignPutBack` at the source name:
/// the entry was left where it is and nothing was deleted.
#[must_use]
pub fn settle(
    dir: &DirHandle,
    quarantine: &Quarantine,
    source_name: &str,
    expected: &Expected,
    slot: &str,
) -> SettleOutcome {
    settle_with(dir, quarantine, source_name, expected, slot, HookAt::NONE).unwrap_or_else(|_| {
        SettleOutcome::ForeignPutBack {
            path: source_name.to_owned(),
        }
    })
}

/// Additive (W2-U4a): the settlement move of ADR-0007 §5.3 step 8.2–8.5, firing
/// `AfterSettleMove` between the move and its check.
///
/// 1. The source must hold the expected identity (a regular file owned by the user,
///    one link); no entry is `Missing`, anything else is `ForeignPutBack` at the
///    source name and is **not moved** (row F8e).
/// 2. A no-replace rename into the slot (`ENOENT` → `Missing`; an occupied slot →
///    [`ReplaceError::Exists`], nothing moved; row F8d is the caller's).
/// 3. The moved entry is checked: the expected identity and digest → `Settled`; the
///    expected identity with other content, or content that cannot be read within
///    1 MiB → `Modified` (kept in the quarantine); another identity (a writer took the
///    source name between steps 1 and 2) → put back with no-replace, or kept as
///    `<source>.hm-conflict-<slot>` (`ForeignPutBack`/`ForeignKept`).
///
/// # Errors
/// [`ReplaceError`] when nothing was moved.
pub fn settle_with(
    dir: &DirHandle,
    quarantine: &Quarantine,
    source_name: &str,
    expected: &Expected,
    slot: &str,
    hook: HookAt<'_>,
) -> Result<SettleOutcome, ReplaceError> {
    if !fsentry::is_component(source_name) || !fsentry::is_component(slot) {
        return Err(ReplaceError::Io("not a single name".into()));
    }
    if !dir.still_valid() {
        return Err(ReplaceError::Io("directory changed".into()));
    }
    match fsentry::lstat(dir.dir(), source_name, dir.source) {
        Ok(None) => return Ok(SettleOutcome::Missing),
        Ok(Some(m)) if m.is_heimdall_shape() && m.identity.same_file(&expected.identity) => {}
        Ok(Some(_)) => {
            return Ok(SettleOutcome::ForeignPutBack {
                path: source_name.to_owned(),
            });
        }
        Err(e) => return Err(ReplaceError::Io(io_text(&e))),
    }
    let q = quarantine.dir.dir();
    match fsentry::rename_noreplace(dir.dir(), source_name, q, slot) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SettleOutcome::Missing),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ReplaceError::Exists);
        }
        Err(e) => return Err(ReplaceError::Io(io_text(&e))),
    }
    hook.fire(ReplacePoint::AfterSettleMove);
    match fsentry::inspect(q, slot, quarantine.dir.source()) {
        Ok(Some((meta, file))) => {
            if meta.is_heimdall_shape() && meta.identity.same_file(&expected.identity) {
                if content_state(file.as_ref(), &expected.sha256) == ContentState::Unchanged {
                    Ok(SettleOutcome::Settled)
                } else {
                    Ok(SettleOutcome::Modified {
                        slot: slot.to_owned(),
                    })
                }
            } else {
                put_back(dir, quarantine, slot, source_name)
            }
        }
        // Moved, then gone from the private quarantine (ADR-0007 §5.9 item 4).
        Ok(None) => Ok(SettleOutcome::Missing),
        Err(_) => Ok(SettleOutcome::Modified {
            slot: slot.to_owned(),
        }),
    }
}

fn put_back(
    dir: &DirHandle,
    quarantine: &Quarantine,
    slot: &str,
    name: &str,
) -> Result<SettleOutcome, ReplaceError> {
    let q = quarantine.dir.dir();
    match fsentry::rename_noreplace(q, slot, dir.dir(), name) {
        Ok(()) => {
            return Ok(SettleOutcome::ForeignPutBack {
                path: name.to_owned(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SettleOutcome::Missing),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(ReplaceError::Io(io_text(&e))),
    }
    let conflict = format!("{name}.hm-conflict-{slot}");
    if fsentry::is_component(&conflict) {
        match fsentry::rename_noreplace(q, slot, dir.dir(), &conflict) {
            Ok(()) => return Ok(SettleOutcome::ForeignKept { path: conflict }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SettleOutcome::Missing);
            }
            Err(e) => return Err(ReplaceError::Io(io_text(&e))),
        }
    }
    Ok(SettleOutcome::ForeignKept {
        path: format!("{QUARANTINE_NAME}/{slot}"),
    })
}

/// Additive (W2-U4a): a no-replace rename of `from` onto `to` inside `dir` (Linux
/// `RENAME_NOREPLACE`, macOS `RENAME_EXCL`, Windows `MoveFileExW` without
/// `MOVEFILE_REPLACE_EXISTING`): `projection::git::claim_lock`'s rename. An existing
/// `to` is [`ReplaceError::Exists`]; nothing is ever replaced.
///
/// # Errors
/// [`ReplaceError`].
pub fn rename_noreplace(dir: &DirHandle, from: &str, to: &str) -> Result<(), ReplaceError> {
    if !fsentry::is_component(from) || !fsentry::is_component(to) || from == to {
        return Err(ReplaceError::Io("not a single name".into()));
    }
    if !dir.still_valid() {
        return Err(ReplaceError::Io("directory changed".into()));
    }
    fsentry::rename_noreplace(dir.dir(), from, dir.dir(), to).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            ReplaceError::Exists
        } else if fsentry::is_unsupported(&e) {
            ReplaceError::Refused(ReplaceRefusal::AtomicExchangeUnsupported)
        } else {
            ReplaceError::Io(io_text(&e))
        }
    })
}

// --- observation (reconcile and held previews) ---------------------------------------

/// Which names a step's observation looks at: the path, and the aside name(s) (one
/// on Unix, where the displaced name is the staged name; both on Windows).
fn aside_names(step: &FileStep) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for n in [&step.staged_name, &step.displaced_name]
        .into_iter()
        .flatten()
    {
        if !names.contains(n) {
            names.push(n.clone());
        }
    }
    if cfg!(unix) {
        names.truncate(1);
    }
    names
}

/// The ADR-0007 §5.7 classifier for one name: rule 1 (not Heimdall's shape → X),
/// then rule 2's role precedence (Q only at the settlement's source and slot, S, D
/// only when distinct from S and V, V only with a present base), each with its content
/// part.
struct Classifier<'a> {
    step: &'a FileStep,
    record: &'a StepRecord,
    settling: Option<&'a SettlingAt>,
}

impl Classifier<'_> {
    fn classify(
        &self,
        found: std::io::Result<Option<(EntryMeta, Option<std::fs::File>)>>,
        q_eligible: bool,
    ) -> EntryObs {
        let (meta, file) = match found {
            Ok(None) => return EntryObs::Absent,
            Err(_) => return EntryObs::Unobservable,
            Ok(Some(found)) => found,
        };
        if !meta.is_heimdall_shape() {
            return EntryObs::Foreign;
        }
        let id = &meta.identity;
        let recorded = |which, expected: &Expected| EntryObs::Recorded {
            which,
            content: content_state(file.as_ref(), &expected.sha256),
        };
        if q_eligible
            && let Some(q) = self.settling
            && id.same_file(&q.expected.identity)
        {
            return recorded(RecordedRole::Q, &q.expected);
        }
        if let Some(s) = &self.record.staged
            && id.same_file(&s.identity)
        {
            return recorded(RecordedRole::S, s);
        }
        if let Some(d) = &self.record.displaced_mismatch
            && id.same_file(d)
            && self
                .record
                .validated
                .as_ref()
                .is_none_or(|v| !v.identity.same_file(d))
        {
            return EntryObs::Recorded {
                which: RecordedRole::D,
                content: ContentState::Unchanged,
            };
        }
        if matches!(self.step.base, Base::Present { .. })
            && let Some(v) = &self.record.validated
            && id.same_file(&v.identity)
        {
            return recorded(RecordedRole::V, v);
        }
        EntryObs::Foreign
    }
}

/// Observe a step's path, aside and slot for recovery (`reconcile` only).
///
/// [`observe_step_at`] with the settlement taken from the state (an open
/// `file.settling`); once `file.settled` is the effective phase, the slot is found in
/// the quarantine by Q's recorded identity. Pass the exact settlement with
/// [`observe_step_at`] (from [`SettlingAt::from_receipts`]) when it is known.
#[must_use]
pub fn observe_step(
    dir: &DirHandle,
    step: &FileStep,
    record: &StepRecord,
    state: &RecoveryState,
) -> StepObservation {
    let settling = if state.settlement.is_some() {
        SettlingAt::from_state(state).or_else(|| find_slot(dir, record))
    } else {
        None
    };
    observe_step_at(dir, step, record, state, settling.as_ref())
}

/// The slot holding Q's identity, when the quarantine has exactly one such entry. A
/// quarantine that no longer validates gives a settlement whose slot cannot be named,
/// which [`observe_step_at`] observes as `?`.
fn find_slot(dir: &DirHandle, record: &StepRecord) -> Option<SettlingAt> {
    let q = record.settling.as_ref()?;
    let at = |slot: String| SettlingAt {
        name: String::new(),
        slot,
        expected: q.clone(),
    };
    match Quarantine::open_existing(dir) {
        Ok(None) => None,
        Ok(Some(quarantine)) => {
            fsentry::find_by_identity(quarantine.dir.dir(), &q.identity, dir.source).map(at)
        }
        Err(_) => Some(at(String::new())),
    }
}

/// Additive (W2-U4a): [`observe_step`] with the step's settlement given explicitly.
///
/// Each name gets one symbol of ADR-0007 §5.7 (∅, S/S′, V/V′, D, Q/Q′, X, ?), and the
/// result is built by `StepObservation::normalize`. A directory that no longer
/// validates, or is not the step's, makes every name `?`. On Unix, when K's recorded
/// identity has no birth time, every entry at the `git_lock` step's path (the lock
/// name) is X (ADR-0007 §5.6, QR15). On Windows both aside names are observed, and
/// both holding an entry is X. Moves nothing; it records the step's names in `dir`
/// ([`DirHandle::learn_step`]).
#[must_use]
pub fn observe_step_at(
    dir: &DirHandle,
    step: &FileStep,
    record: &StepRecord,
    state: &RecoveryState,
    settling: Option<&SettlingAt>,
) -> StepObservation {
    let shape = StepShape::of(step);
    let unobservable = || {
        normalized(
            EntryObs::Unobservable,
            EntryObs::Unobservable,
            if settling.is_some() {
                EntryObs::Unobservable
            } else {
                EntryObs::Absent
            },
            state,
            shape,
        )
    };
    let Some(target) = Path::new(&step.path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| fsentry::is_component(n))
    else {
        return unobservable();
    };
    if !dir.contains(&step.path) || !dir.still_valid() {
        return unobservable();
    }
    dir.learn_step(step);
    let c = Classifier {
        step,
        record,
        settling,
    };
    let q_at = |name: &str| settling.is_some_and(|s| s.name == name);
    let lock_blind = cfg!(unix)
        && shape == StepShape::GitLock
        && record
            .staged
            .as_ref()
            .is_some_and(|k| matches!(k.identity, FileIdentity::Unix { birth: None, .. }));
    let path = if lock_blind {
        match fsentry::lstat(dir.dir(), target, dir.source) {
            Ok(None) => EntryObs::Absent,
            Ok(Some(_)) => EntryObs::Foreign,
            Err(_) => EntryObs::Unobservable,
        }
    } else {
        c.classify(
            fsentry::inspect(dir.dir(), target, dir.source),
            q_at(target),
        )
    };
    let mut asides = aside_names(step)
        .into_iter()
        .filter(|n| fsentry::is_component(n))
        .map(|n| c.classify(fsentry::inspect(dir.dir(), &n, dir.source), q_at(&n)))
        .filter(|o| *o != EntryObs::Absent)
        .collect::<Vec<_>>();
    let aside = match asides.len() {
        0 => EntryObs::Absent,
        1 => asides.pop().unwrap_or(EntryObs::Absent),
        _ if asides.contains(&EntryObs::Unobservable) => EntryObs::Unobservable,
        _ => EntryObs::Foreign,
    };
    let slot = match settling {
        None => EntryObs::Absent,
        Some(s) if !fsentry::is_component(&s.slot) => EntryObs::Unobservable,
        Some(s) => match Quarantine::open_existing(dir) {
            Ok(None) => EntryObs::Absent,
            Err(_) => EntryObs::Unobservable,
            Ok(Some(q)) => c.classify(fsentry::inspect(q.dir.dir(), &s.slot, q.dir.source()), true),
        },
    };
    normalized(path, aside, slot, state, shape)
}

/// Fingerprint a held step's names (`observe_held` only; M2-T03).
///
/// [`observe_fingerprint_at`] with the slot of an open `file.settling` from the
/// state.
#[must_use]
pub fn observe_fingerprint(
    dir: &DirHandle,
    step: &FileStep,
    state: &RecoveryState,
) -> StepFingerprint {
    let settling = SettlingAt::from_state(state);
    observe_fingerprint_at(dir, step, settling.as_ref())
}

/// Additive (W2-U4a): [`observe_fingerprint`] with the slot given explicitly.
///
/// The path, the aside name (Unix: the staged name; Windows: the staged and the
/// displaced name), and the slot when one is named. Each is `Absent`, `Unobservable`
/// or `Present` with identity, type, owner, link count, length, change time and the
/// SHA-256 of the content, or `Unreadable` when it cannot be read within 1 MiB.
/// Digests and metadata only; moves nothing.
#[must_use]
pub fn observe_fingerprint_at(
    dir: &DirHandle,
    step: &FileStep,
    settling: Option<&SettlingAt>,
) -> StepFingerprint {
    let valid = dir.contains(&step.path) && dir.still_valid();
    let at = |name: &str| {
        if valid && fsentry::is_component(name) {
            fingerprint(fsentry::inspect(dir.dir(), name, dir.source))
        } else {
            EntryFingerprint::Unobservable
        }
    };
    let path = Path::new(&step.path)
        .file_name()
        .and_then(|n| n.to_str())
        .map_or(EntryFingerprint::Unobservable, at);
    let aside = aside_names(step).iter().map(|n| at(n)).collect();
    let slot = settling.map(|s| {
        if !valid || !fsentry::is_component(&s.slot) {
            return EntryFingerprint::Unobservable;
        }
        match Quarantine::open_existing(dir) {
            Ok(None) => EntryFingerprint::Absent,
            Err(_) => EntryFingerprint::Unobservable,
            Ok(Some(q)) => fingerprint(fsentry::inspect(q.dir.dir(), &s.slot, q.dir.source())),
        }
    });
    StepFingerprint { path, aside, slot }
}

fn fingerprint(
    found: std::io::Result<Option<(EntryMeta, Option<std::fs::File>)>>,
) -> EntryFingerprint {
    match found {
        Ok(None) => EntryFingerprint::Absent,
        Err(_) => EntryFingerprint::Unobservable,
        Ok(Some((meta, file))) => {
            let content = match file.as_ref().map(fsentry::read_bounded) {
                Some(Ok(Some(bytes))) => FingerprintContent::Sha256 {
                    sha256: Sha256Hex::of(&bytes),
                },
                _ => FingerprintContent::Unreadable,
            };
            EntryFingerprint::Present {
                identity: meta.identity,
                file_type: match meta.kind {
                    Kind::Regular => EntryFileType::Regular,
                    Kind::Directory => EntryFileType::Directory,
                    Kind::Symlink => EntryFileType::Symlink,
                    Kind::Other => EntryFileType::Other,
                },
                owned_by_user: meta.owned,
                link_count: meta.nlink,
                len: meta.len,
                changed_ns: meta.changed_ns,
                content,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn adr_aside_names_name_their_target() {
        let hex = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_aside(&format!(".config.hm-3-{hex}")),
            Some(("config".to_owned(), Some(3)))
        );
        assert_eq!(
            parse_aside(".config.hm-displaced-3"),
            Some(("config".to_owned(), None))
        );
        assert_eq!(
            parse_aside(&format!(".a.hm-b.hm-12-{hex}")),
            Some(("a.hm-b".to_owned(), Some(12)))
        );
        for bad in [
            "config",
            ".config.hm-3-XYZ",
            ".config.hm-x-0123456789abcdef0123456789abcdef",
            ".config.hm-3-0123456789ABCDEF0123456789ABCDEF",
            "..hm-3-0123456789abcdef0123456789abcdef",
            ".config.hm-displaced-",
            ".config.hm-displaced-x",
        ] {
            assert_eq!(parse_aside(bad), None, "{bad}");
        }
        assert_eq!(displaced_name_for("config", 4), ".config.hm-displaced-4");
    }

    #[test]
    fn modes_map_to_their_permission_bits() {
        assert_eq!(Mode::OwnerReadWrite.perm(), 0o600);
        assert_eq!(Mode::PublicRead.perm(), 0o644);
    }
}
