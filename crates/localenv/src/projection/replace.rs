//! The file replacement primitive and the quarantine (m02-plan U4; ADR-0007 §5.3).
//!
//! **Frozen in wave 0** (m02-plan U0): every type and signature in this module.
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

use std::path::{Path, PathBuf};

use heimdall_domain::operation::HoldReason;
use heimdall_domain::projection::{
    Base, FileIdentity, FileStep, RecoveryState, Sha256Hex, StepFingerprint, StepObservation,
};

use super::content::Materialized;
use crate::sys::QuarantineDir;

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

/// An open, validated directory; every name below is resolved relative to it.
#[derive(Debug)]
pub struct DirHandle {
    path: PathBuf,
}

impl DirHandle {
    /// Open and validate `path` (owner, no symlink or reparse point).
    ///
    /// # Errors
    /// [`Unmanageable`].
    pub fn open(path: &Path) -> Result<DirHandle, Unmanageable> {
        let _ = path;
        todo!("M02-U4 replace::DirHandle::open")
    }

    /// The directory's path (display and diagnostics only; never re-resolved).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// `<dir>/.hm-quarantine`: created 0700 (Windows: owner-only DACL) and validated on
/// every open (owner, mode exactly 0700, no symlink or reparse point, not a mount
/// point).
#[derive(Debug)]
pub struct Quarantine {
    dir: QuarantineDir,
}

impl Quarantine {
    /// Open (validating) or create the quarantine of `dir`.
    ///
    /// # Errors
    /// [`Unmanageable`].
    pub fn open_or_create(dir: &DirHandle) -> Result<Quarantine, Unmanageable> {
        let _ = dir;
        todo!("M02-U4 replace::Quarantine::open_or_create")
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
        let _ = (&self.dir, slot, expected);
        todo!("M02-U4 replace::Quarantine::remove_verified")
    }

    /// Remove the quarantine when it is empty; never removes an entry.
    ///
    /// # Errors
    /// [`ReplaceError`].
    pub fn rmdir_if_empty(self) -> Result<bool, ReplaceError> {
        todo!("M02-U4 replace::Quarantine::rmdir_if_empty")
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

/// Validate the base at `name`.
///
/// # Errors
/// [`ReplaceRefusal`].
pub fn validate(dir: &DirHandle, name: &str, base: &Base) -> Result<Validated, ReplaceRefusal> {
    let _ = (dir, name, base);
    todo!("M02-U4 replace::validate")
}

/// Create S exclusively at `staged_name` with `bytes`, fsync'd.
///
/// # Errors
/// [`ReplaceError`].
pub fn stage(
    dir: &DirHandle,
    staged_name: &str,
    bytes: &Materialized,
    mode: Mode,
) -> Result<Staged, ReplaceError> {
    let _ = (dir, staged_name, bytes, mode);
    todo!("M02-U4 replace::stage")
}

/// Re-check the base at the boundary (step 4).
///
/// # Errors
/// [`ReplaceRefusal`].
pub fn recheck(dir: &DirHandle, validated: &Validated) -> Result<(), ReplaceRefusal> {
    let _ = (dir, validated);
    todo!("M02-U4 replace::recheck")
}

/// Exchange S with the path (or create it with no-replace when `validated` is
/// `None`).
///
/// # Errors
/// [`ReplaceError`].
pub fn exchange(
    dir: &DirHandle,
    staged: &Staged,
    validated: Option<&Validated>,
) -> Result<Exchanged, ReplaceError> {
    let _ = (dir, staged, validated);
    todo!("M02-U4 replace::exchange")
}

/// Check that the path is S and the displaced entry is V.
#[must_use]
pub fn post_validate(
    dir: &DirHandle,
    exchanged: &Exchanged,
    validated: &Validated,
    staged: &Staged,
) -> PostValidation {
    let _ = (dir, exchanged, validated, staged);
    todo!("M02-U4 replace::post_validate")
}

/// Exchange back: first check that the path holds S with the target digest
/// (`at_path`), else hold and move nothing (QR13).
#[must_use]
pub fn restore(
    dir: &DirHandle,
    exchanged: &Exchanged,
    at_path: &Expected,
    aside: FileIdentity,
) -> RestoreOutcome {
    let _ = (dir, exchanged, at_path, aside);
    todo!("M02-U4 replace::restore")
}

/// Move `source_name` into `slot` with no-replace, then verify identity and digest.
/// Returns before removal; the caller writes `file.settled` between the two.
#[must_use]
pub fn settle(
    dir: &DirHandle,
    quarantine: &Quarantine,
    source_name: &str,
    expected: &Expected,
    slot: &str,
) -> SettleOutcome {
    let _ = (dir, quarantine, source_name, expected, slot);
    todo!("M02-U4 replace::settle")
}

/// Observe a step's path, aside and slot for recovery (`reconcile` only).
#[must_use]
pub fn observe_step(
    dir: &DirHandle,
    step: &FileStep,
    record: &StepRecord,
    state: &RecoveryState,
) -> StepObservation {
    let _ = (dir, step, record, state);
    todo!("M02-U4 replace::observe_step")
}

/// Fingerprint a held step's names (`observe_held` only; M2-T03).
#[must_use]
pub fn observe_fingerprint(
    dir: &DirHandle,
    step: &FileStep,
    state: &RecoveryState,
) -> StepFingerprint {
    let _ = (dir, step, state);
    todo!("M02-U4 replace::observe_fingerprint")
}
