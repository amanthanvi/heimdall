//! Execution and recovery of a setup intent (m02-plan U4; ADR-0007 §5.3–§5.7).
//!
//! Every staged byte comes from `content::materialize` over the intent's content and
//! the bytes validated in the same run. Each receipt is appended through the sink
//! before the next step; each item is committed through `StageSink::commit_item`
//! before anything of it is settled. `reconcile` runs `observe_step`, `decide` and
//! the action until every step is final or held, and never calls `apply`.
//!
//! **Structure.** One engine serves both entry points. `apply` first checks every
//! precondition of every file (§5.4 step 3: the intent's content binding, the bases,
//! the directories) and writes nothing when one fails. It then runs each item's steps
//! forward through the §5.3 primitive (stage, validate, exchange, post-validate) in
//! plan order. From the commit step's post-validation on, and after any failure, the
//! item is driven by the same loop `reconcile` runs: build each step's
//! `RecoveryState` from the receipts, observe its names, `decide`, act, and repeat
//! until the item is finished or held. So the live path and recovery write the same
//! receipts and pass through the same table (§5.7 "The live path writes the same
//! receipts and, after any failure, continues through the same decide").
//!
//! * Recording decisions (a lost `exchanged`, a post-validation, a recognized
//!   restore, a restore or settlement in progress, a settlement conflict) are carried
//!   out whatever the item state, because the receipts already decide them. A held
//!   step moves nothing, but the item's other steps still finish what their own rows
//!   decide (the commit step's restore is never blocked by an edited inactive file);
//!   once nothing else progresses, a held step holds the item (TH).
//! * The item rows (`decide_item`) choose between resuming forward and aborting (T0),
//!   run the transaction check (T1), and finish the item (T2, T3, T4). T0 resumes the
//!   Git item only under a lock the receipts prove (K1 or K2), never after K3 or K4.
//! * K's release (ADR-0007 §12.17 item 3). It is due when the receipts make it due
//!   (`RecoveryState::build`: every other Git step final by its receipts), or when the
//!   item rows decide the item's abort or restore and every other Git step reached its
//!   end in the current observation (settled, nothing to settle, never staged, or an
//!   exchanged inactive step handed to the cleaner). No receipt records that
//!   hand-over, so it is computed every round from the durable receipts and a fresh
//!   observation, and a restart computes it again; K is always released last.
//! * K in the run that claimed it (ADR-0007 §12.20 item 1). Within a run whose own
//!   `claim_lock` succeeded, the lock name is classified by K's identity and holder
//!   digest, the check [`Run::lock_held_by_k`] makes before B_git's exchange (§5.6:
//!   within one run, identity and holder digest are checked at each step). So the run
//!   keeps the lock by K2 and releases K, with or without a birth time. A restart, which
//!   did not claim K, keeps the recovery classifier: on Unix without a birth time every
//!   entry at the lock name is X there (QR15), and K4 leaves it for the owner.
//! * Rows F0x and K0x are the classifier's (`replace::observe_step_at`, §12.17 item
//!   2): an unrecorded entry of Heimdall's shape at a step's own staged name, before
//!   any receipt of the step, is its S by digest.
//! * The Git item follows the SSH commit point: it runs only when the intent's SSH
//!   item applied (or the intent has none). B_git's staged bytes must parse
//!   (`git config --file <N_s> --no-includes --list`, a local query) before its
//!   exchange; a failure aborts before the commit point (§5.6 step 3,
//!   `unmanageable_file`), and so does a check that cannot run (§12.19 item 8, §12.20
//!   item 2(a): `verified_client_unavailable`).
//! * Outcome reasons (ADR-0007 §12.20 item 2(b)). An abort the live path stops itself
//!   keeps the reason of its stop. An abort that recovery decides carries the reason
//!   its §5.7 row names ([`Run::abort_reason`]): `concurrent_writer` for F1a, F2g, C3,
//!   C4 and K3; the base's (`user_config_changed` or `managed_file_edited`) for F2e,
//!   F2j and a T0 precondition; `git_config_locked` for K0 and K1 with a foreign lock,
//!   and for K4 (escalated reading). The reason is durable: `item.finished` records
//!   it, and a restart reports the recorded one.
//! * K before B_git's commit point (§12.18 item 4, X04). Immediately before B_git's
//!   exchange, on fresh apply and on a restart's resume alike, the lock name must hold
//!   K: the identity the lock step's `file.staged` recorded, with the holder digest.
//!   Otherwise B_git is never exchanged, nothing is written to the global Git file,
//!   and the item aborts (`git_config_locked`) while the lock step's own rows (K3, K4)
//!   record what the lock name holds, exactly as recovery does.
//! * A create's restore moves its active file (§12.18 item 2, X02). Right before it
//!   writes `file.restore_started` and again right before the settlement move, the path
//!   must hold S with the target digest; an edit since the observation is held
//!   (`active_entry_modified`, C7a, F8a) and the edited file stays at its path.
//! * An item with no step to write (a rollback whose B is already gone) has its check
//!   and `item.committed` as its commit point.
//! * After a rollback's item committed, an edited managed file is renamed, with
//!   no-replace, to `<name>.hm-conflict-<generation>` instead of being left for the
//!   cleaner (§5.5).
//!
//! **Steps that write nothing.** A step whose target is absent is the cleaner's
//! (§5.8) and is skipped. A user-file step whose target equals its base is a
//! *check-only* step: the update's commit point never writes the user file, but its
//! transaction check re-reads it (identity, base digest, B intact and first; §5.4
//! "Update"). It is never staged and has no receipts.
//!
//! **Item commit.** `ItemCommit.record` carries the item's [`ItemRecord`] with the
//! generation, the locators of the files this intent wrote (identity and target
//! digest) and, for `ssh`, the aliases rendered into P. The writer knows neither the
//! environment, the operation nor the commit time: those fields are placeholders that
//! the sink completes from its operation (escalated by W2-U4c; the store refuses a
//! record whose environment is not the operation's, so a sink that forgets fails
//! closed).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use heimdall_app::ports::{
    HeldStep, ItemOutcome, ProjectionReceipt, ProjectionReconcile, ReconcileError, StageSink,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::{
    EffectReceipt, FilePhase, HoldReason, ItemFinish, ItemPhase, LocalReceipt, ObservedEntry,
    ObservedName, ObservedNameRole, PostVerdict, PreservedEntry, RestoreCause, SettleConflictFound,
    SettleSource, SettledDisposition, StageReceipt,
};
use heimdall_domain::projection::{
    Base, ConsentRecord, ContentState, EffectivePhase, EntryFingerprint, EntryObs, FileIdentity,
    FileRole, FileStep, ItemCommit, ItemRecord, ItemState, ProjectionLocator, ProjectionRecord,
    RecordedRole, RecoveryState, RestoreCtx, SetupIntent, Sha256Hex, StepContentView,
    StepFingerprint, StepObservation, StepShape, Target,
};

use super::content::{self, ContentError};
use super::git::claim_lock;
use super::recovery::{
    self, AbortStep, ForwardStep, ItemDecision, ItemReceipts, RestoreStep, SettleStep,
    StepDecision, StepState,
};
use super::replace::{
    self, DirHandle, Expected, HookAt, Mode, NameState, PostValidation, Quarantine, RemoveVerified,
    ReplaceError, ReplaceRefusal, RestoreFailure, RestoreOutcome, SettleOutcome, SettlingAt,
    Staged, StepNames, StepRecord,
};
use super::{ProjectionConfig, ReplacePoint};
use crate::clients::ClientKind;
use crate::local_query::LocalQueries;
use crate::sys::IdentitySource;
use crate::sys::fsentry::{self, EntryMeta, Kind};

/// Iterations of one item's recovery loop before it is reported held (`unmatched`).
/// Every iteration performs at most one action; a correct item needs a few per step.
const MAX_ITERATIONS: usize = 4096;

/// `file.held` receipts per step (ADR-0007 §5.7 "Receipts").
const MAX_HELD_RECEIPTS: usize = 16;

/// Execute `intent`.
///
/// # Errors
/// [`ReconcileError`].
pub fn apply(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    sink: &mut dyn StageSink,
) -> Result<ProjectionReceipt, ReconcileError> {
    intent
        .validate()
        .map_err(|e| ReconcileError::IntentInvalid(e.to_string()))?;
    let mut run = Run::new(config, intent, Some(sink), Vec::new())?;
    let items = run.apply_all()?;
    run.tidy();
    Ok(ProjectionReceipt { items })
}

/// Recover `intent` from `receipts`.
///
/// # Errors
/// [`ReconcileError`].
pub fn reconcile(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
    sink: &mut dyn StageSink,
) -> Result<ProjectionReconcile, ReconcileError> {
    intent
        .validate()
        .map_err(|e| ReconcileError::IntentInvalid(e.to_string()))?;
    let mut run = Run::new(config, intent, Some(sink), receipts.to_vec())?;
    run.content_check()?;
    let items = run.reconcile_all()?;
    run.tidy();
    Ok(ProjectionReconcile { items })
}

/// The held steps of `intent` (passive: nothing is moved or written).
pub(super) fn held_steps(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
) -> Result<Vec<HeldStep>, ReconcileError> {
    intent
        .validate()
        .map_err(|e| ReconcileError::IntentInvalid(e.to_string()))?;
    let mut run = Run::new(config, intent, None, receipts.to_vec())?;
    let mut out = Vec::new();
    for item in items_of(intent) {
        out.extend(run.held_of(item));
    }
    Ok(out)
}

// --- the original's snapshot (ADR-0007 §5.5, §12.35 item 2) -------------------------------

/// The snapshot name of the user's SSH configuration
/// (`<state>/backups/ssh_config.<UTC timestamp>.orig`; ADR-0007 §5.5).
pub const SSH_SNAPSHOT_NAME: &str = "ssh_config";

/// The snapshot name of the global Git file
/// (`<state>/backups/gitconfig.<UTC timestamp>.orig`; ADR-0007 §5.5, §12.32 item 2).
pub const GIT_SNAPSHOT_NAME: &str = "gitconfig";

/// What [`snapshot_original`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Snapshot {
    /// The original's bytes were copied to this new file.
    Written(PathBuf),
    /// A valid snapshot of this name was taken before an earlier first edit; it is never
    /// replaced, and nothing was written.
    Exists(PathBuf),
    /// The file does not exist: there is no original to copy.
    Absent,
    /// The file's bytes are not the ones the plan was computed from; nothing was
    /// written (the plan's own base check refuses the edit).
    Changed,
}

/// ⟨M02⟩ ADR-0007 §5.5 "Snapshots" (§12.30 item 7): before the first edit of a user
/// file, copy its original bytes to `<backups>/<name>.<UTC timestamp>.orig`, so the owner
/// can recover it by hand. Heimdall never restores a snapshot automatically, and only
/// `uninstall --purge-state` deletes one.
///
/// * `backups` is opened without following a link (§12.35 item 2) and must be a
///   directory owned by the current user that group and others cannot write (Unix; on
///   Windows it inherits the state directory's ACL). A symbolic link, a non-directory, a
///   foreign owner or a group- or other-writable directory refuses, and nothing is
///   read from or written to it.
/// * The first edit is the one with no `<name>.*.orig` in `backups` yet. An existing
///   snapshot is kept as it is ([`Snapshot::Exists`]) and nothing is written, but it
///   counts only as a *valid* one: a regular file of the current user with one link and
///   mode exactly 0600 (a protected owner-only DACL on Windows), opened without following
///   a link. Every entry of that name must be valid; any other (a directory, a link, a
///   file with another mode, owner or link count) refuses the copy with an error that
///   names the entry, so a lookalike can never stand in for the original.
/// * `file` is read without following a link (an absent file has no original,
///   [`Snapshot::Absent`]) and must be a regular file of at most 1 MiB. With `expected`
///   (the plan's base digest, lowercase hex), bytes with another digest write nothing
///   ([`Snapshot::Changed`]).
/// * `backups` is created when missing (0700 on Unix). The copy is created new and
///   owner-only relative to the directory that was validated (0600 on Unix; a protected
///   owner-only DACL on Windows), synced, and moved into place by a no-replace rename
///   from a dot-named staging file, so a reader never sees a partial snapshot and no
///   entry is ever replaced. Nothing is ever removed: a staging file a failed or raced
///   copy leaves behind stays (production code unlinks nothing outside the quarantine)
///   and, being dot-named, is never taken for a snapshot.
/// * The timestamp is the UTC second of `now` as `YYYYMMDDTHHMMSSZ` (no `:`, which
///   Windows names cannot hold).
///
/// # Errors
/// Any I/O failure (the caller then submits nothing), an over-long file, a file that is
/// not regular, an unsafe `backups`, or an entry of `backups` that is named like a
/// snapshot and is not a valid one. The messages name an entry by its name only.
pub fn snapshot_original(
    file: &Path,
    backups: &Path,
    name: &str,
    expected: Option<&str>,
    now: Timestamp,
) -> std::io::Result<Snapshot> {
    use std::io::Write as _;
    let mut dir = match SnapshotDir::open(backups) {
        Ok(dir) => {
            dir.require_private()?;
            Some(dir)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if let Some(dir) = &dir
        && let Some(existing) = existing_snapshot(dir, backups, name)?
    {
        return Ok(Snapshot::Exists(existing));
    }
    let Some(bytes) = read_original(file)? else {
        return Ok(Snapshot::Absent);
    };
    if expected.is_some_and(|d| Sha256Hex::of(&bytes).as_str() != d) {
        return Ok(Snapshot::Changed);
    }
    let dir = match dir.take() {
        Some(dir) => dir,
        None => {
            let dir = SnapshotDir::create(backups)?;
            // A first edit that raced this one may have created the directory and copied.
            if let Some(existing) = existing_snapshot(&dir, backups, name)? {
                return Ok(Snapshot::Exists(existing));
            }
            dir
        }
    };
    let stamp = snapshot_stamp(now);
    let target = format!("{name}.{stamp}.orig");
    let staging = format!(".{name}.{stamp}.orig.tmp");
    // Unix 0600 with `O_EXCL|O_NOFOLLOW`; Windows a protected owner-only DACL (§5.5).
    let mut out = fsentry::create_new(dir.dir(), &staging, 0o600)?;
    out.write_all(&bytes)?;
    out.sync_all()?;
    drop(out);
    match fsentry::rename_noreplace(dir.dir(), &staging, dir.dir(), &target) {
        Ok(()) => Ok(Snapshot::Written(backups.join(&target))),
        // Another first edit's copy landed under this very name meanwhile: it is kept,
        // if it is a valid one.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            existing_snapshot(&dir, backups, name)?
                .map(Snapshot::Exists)
                .ok_or(e)
        }
        Err(e) => Err(e),
    }
}

/// A refusal of the snapshot; `what` names an entry by its name only, never a path.
fn snapshot_refusal(what: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, what.into())
}

/// A directory opened without following a link, whose names are resolved relative to
/// it (the way `replace::DirHandle` resolves them): the backups directory, and the
/// directory of the file to copy.
struct SnapshotDir {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    /// Windows: held open without delete sharing, so it cannot be renamed or removed
    /// meanwhile; names are resolved under its final path.
    #[cfg(windows)]
    _pin: std::os::windows::io::OwnedHandle,
    #[cfg(windows)]
    final_path: PathBuf,
    meta: EntryMeta,
}

impl SnapshotDir {
    /// Open `path` as a directory without following a link (Unix
    /// `O_DIRECTORY|O_NOFOLLOW`; Windows `FILE_FLAG_OPEN_REPARSE_POINT`), whatever its
    /// owner and mode. A missing directory is `NotFound`.
    fn open(path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let fd = match fsentry::open_dir_path(path) {
                Ok(fd) => fd,
                // `O_DIRECTORY|O_NOFOLLOW` on a link is `ELOOP` on Linux and `ENOTDIR` on
                // macOS: the entry itself says which it is.
                Err(e) => {
                    return Err(match std::fs::symlink_metadata(path) {
                        Ok(m) if m.file_type().is_symlink() => {
                            snapshot_refusal("a symbolic link where a directory must be")
                        }
                        Ok(m) if !m.file_type().is_dir() => {
                            snapshot_refusal("a file where a directory must be")
                        }
                        _ => e,
                    });
                }
            };
            let meta = fsentry::fstat(&fd, IdentitySource::Native)?;
            Ok(Self { fd, meta })
        }
        #[cfg(windows)]
        {
            let pin = fsentry::win::open_dir_pinned(path, false)?;
            let meta = fsentry::win::meta(&pin)?;
            match meta.kind {
                Kind::Directory => {}
                Kind::Symlink => {
                    return Err(snapshot_refusal(
                        "a symbolic link or reparse point where a directory must be",
                    ));
                }
                Kind::Regular | Kind::Other => {
                    return Err(snapshot_refusal("a file where a directory must be"));
                }
            }
            let final_path = fsentry::win::final_path(&pin)?;
            Ok(Self {
                _pin: pin,
                final_path,
                meta,
            })
        }
    }

    /// Create the missing backups directory (0700 on Unix; on Windows the protected
    /// owner-only DACL, as the quarantine gets, ADR-0007 §12.48 item 2), then open and
    /// check it like an existing one, so a directory that a racing creator made first is
    /// held to the same rules.
    fn create(path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(false);
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        // An existing name is not an error here either; `open` checks what it is.
        #[cfg(windows)]
        fsentry::win::create_owner_only_dir(path)?;
        let dir = Self::open(path)?;
        dir.require_private()?;
        Ok(dir)
    }

    /// What names resolve against.
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

    /// The rules of the backups directory (§12.35 item 2): owned by the current user
    /// and, on Unix, usable by its owner and writable by neither group nor others.
    fn require_private(&self) -> std::io::Result<()> {
        if let Some(problem) = private_directory_problem(&self.meta) {
            return Err(snapshot_refusal(format!(
                "the backups directory is {problem}"
            )));
        }
        Ok(())
    }

    /// The names in the directory that look like a snapshot of `name`
    /// (`<name>.*.orig`; a name that is not UTF-8 is matched by its lossy form), sorted.
    fn snapshot_names(&self, name: &str) -> std::io::Result<Vec<std::ffi::OsString>> {
        let prefix = format!("{name}.");
        let looks_like_one = |n: &std::ffi::OsStr| {
            let text = n.to_string_lossy();
            text.starts_with(&prefix) && text.ends_with(".orig")
        };
        let mut found = Vec::new();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            for entry in rustix::fs::Dir::read_from(&self.fd)? {
                let n = std::ffi::OsString::from_vec(entry?.file_name().to_bytes().to_vec());
                if looks_like_one(&n) {
                    found.push(n);
                }
            }
        }
        #[cfg(windows)]
        {
            for entry in std::fs::read_dir(&self.final_path)? {
                let n = entry?.file_name();
                if looks_like_one(&n) {
                    found.push(n);
                }
            }
        }
        found.sort();
        Ok(found)
    }
}

/// Why `meta` is no backups directory, or `None` when it is one (§12.35 item 2).
fn private_directory_problem(meta: &EntryMeta) -> Option<&'static str> {
    if meta.kind != Kind::Directory {
        Some("not a directory")
    } else if !meta.owned {
        Some("owned by another user")
    } else if cfg!(unix) && meta.perm & 0o022 != 0 {
        Some("writable by group or others")
    } else if cfg!(unix) && meta.perm & 0o700 != 0o700 {
        Some("not usable by its owner")
    } else {
        None
    }
}

/// Whether `meta` is a valid snapshot (§12.35 item 2): a regular file of the current
/// user with one link and, on Unix, mode exactly 0600.
fn is_valid_snapshot(meta: &EntryMeta) -> bool {
    meta.kind == Kind::Regular
        && meta.owned
        && meta.nlink == 1
        && (!cfg!(unix) || meta.perm == 0o600)
}

/// The first valid `<name>.*.orig` in `dir` (sorted), if any; no entry of that name
/// is not a valid snapshot. A name that vanishes meanwhile is no entry.
///
/// # Errors
/// An entry of that name that is not a valid snapshot, named, or an I/O failure.
fn existing_snapshot(
    dir: &SnapshotDir,
    backups: &Path,
    name: &str,
) -> std::io::Result<Option<PathBuf>> {
    let mut first = None;
    for entry in dir.snapshot_names(name)? {
        let invalid = |why: &str| {
            snapshot_refusal(format!(
                "the backups directory holds {entry:?}, which is not a valid snapshot ({why})"
            ))
        };
        let Some(text) = entry.to_str() else {
            return Err(invalid("its name is not valid text"));
        };
        let found = fsentry::inspect(dir.dir(), text, IdentitySource::Native)
            .map_err(|e| invalid(&format!("it cannot be inspected: {:?}", e.kind())))?;
        let Some((meta, handle)) = found else {
            continue;
        };
        if !is_valid_snapshot(&meta) {
            return Err(invalid(
                "a snapshot is a regular file of the current user with one link and mode 0600",
            ));
        }
        #[cfg(windows)]
        {
            let owner_only = handle.is_some_and(|f| {
                fsentry::win::dacl_is_owner_only(&std::os::windows::io::OwnedHandle::from(f))
                    .unwrap_or(false)
            });
            if !owner_only {
                return Err(invalid("a snapshot has a protected owner-only ACL"));
            }
        }
        #[cfg(not(windows))]
        drop(handle);
        first.get_or_insert(entry);
    }
    Ok(first.map(|n| backups.join(n)))
}

/// The original's bytes, read without following a link; `None` when the file is absent.
///
/// # Errors
/// A file that is not regular (a link included), one longer than 1 MiB, or an I/O
/// failure.
fn read_original(file: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let (Some(parent), Some(leaf)) = (file.parent(), file.file_name().and_then(|n| n.to_str()))
    else {
        return Err(snapshot_refusal("the file to snapshot has no directory"));
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let dir = match SnapshotDir::open(parent) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some((meta, handle)) = fsentry::inspect(dir.dir(), leaf, IdentitySource::Native)? else {
        return Ok(None);
    };
    let (Kind::Regular, Some(handle)) = (meta.kind, handle) else {
        return Err(snapshot_refusal(
            "the file to snapshot is not a regular file",
        ));
    };
    fsentry::read_bounded(&handle)?
        .map(Some)
        .ok_or_else(|| snapshot_refusal("the file to snapshot exceeds the read bound"))
}

/// `now`'s UTC second as `YYYYMMDDTHHMMSSZ`.
fn snapshot_stamp(now: Timestamp) -> String {
    let text = now.to_string();
    let second: String = text
        .chars()
        .take(19)
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .collect();
    format!("{second}Z")
}

// --- step classification -------------------------------------------------------------

/// Where a step's file lives: its directory and its name in it.
pub(super) fn split(path: &str) -> Option<(PathBuf, String)> {
    let p = Path::new(path);
    let name = p.file_name()?.to_str()?.to_owned();
    let parent = p.parent()?.to_path_buf();
    if parent.as_os_str().is_empty() {
        return None;
    }
    Some((parent, name))
}

/// A user-file or global-Git-file step whose target equals its base (the preview
/// builds it as a splice that removes and re-inserts the recorded block): the
/// update's transaction check reads it, nothing writes it.
pub(super) fn is_check_only(step: &FileStep) -> bool {
    matches!(step.role, FileRole::UserSsh | FileRole::GitInclude)
        && matches!(
            (&step.base, &step.target),
            (Base::Present { sha256: b }, Target::Present { sha256: t }) if b == t
        )
        && matches!(step.content.view(), StepContentView::Splice { .. })
}

/// A step the writer stages and exchanges (not the cleaner's, not check-only).
pub(super) fn is_writing(step: &FileStep) -> bool {
    StepShape::of(step) != StepShape::Removal && !is_check_only(step)
}

/// The digest S must have: the target, or K's holder line.
pub(super) fn staged_sha(step: &FileStep) -> Option<Sha256Hex> {
    match (&step.target, step.content.view()) {
        (Target::Present { sha256 }, _) => Some(sha256.clone()),
        (Target::Absent, StepContentView::LockHolder { bytes }) => Some(Sha256Hex::of(bytes)),
        _ => None,
    }
}

fn base_sha(step: &FileStep) -> Option<Sha256Hex> {
    match &step.base {
        Base::Present { sha256 } => Some(sha256.clone()),
        Base::Absent => None,
    }
}

fn mode_of(step: &FileStep) -> Mode {
    if step.role == FileRole::Key {
        Mode::PublicRead
    } else {
        Mode::OwnerReadWrite
    }
}

/// The conflict a changed base of `step` means (§5.3 step 2).
fn changed_kind(step: &FileStep) -> ConflictKind {
    match step.role {
        FileRole::UserSsh | FileRole::GitInclude => ConflictKind::UserConfigChanged,
        _ => ConflictKind::ManagedFileEdited,
    }
}

/// The items of `intent`, in the order of their first step.
pub(super) fn items_of(intent: &SetupIntent) -> Vec<ProjectionItem> {
    let mut out: Vec<ProjectionItem> = Vec::new();
    for s in &intent.files {
        let item = s.role.item();
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn step_index(i: usize) -> u16 {
    u16::try_from(i).unwrap_or(u16::MAX)
}

fn phase_kind(local: &LocalReceipt) -> &'static str {
    match local {
        LocalReceipt::File { phase, .. } => match phase {
            FilePhase::Staged { .. } => "staged",
            FilePhase::Validated { .. } => "validated",
            FilePhase::Exchanged => "exchanged",
            FilePhase::PostValidated { .. } => "post_validated",
            FilePhase::RestoreStarted { .. } => "restore_started",
            FilePhase::Restored => "restored",
            FilePhase::Held { .. } => "held",
            FilePhase::Settling { .. } => "settling",
            FilePhase::Settled { .. } => "settled",
            FilePhase::SettleConflict { .. } => "settle_conflict",
        },
        LocalReceipt::Item { phase, .. } => match phase {
            ItemPhase::Committed { .. } => "committed",
            ItemPhase::RollingBack { .. } => "rolling_back",
            ItemPhase::Finished { .. } => "finished",
        },
    }
}

fn stage_receipt(local: LocalReceipt) -> StageReceipt {
    StageReceipt {
        stage: local.stage().to_owned(),
        recorded_at: Timestamp::now(),
        // The sink fixes the durable effect by phase; the writer's copy only carries
        // the local payload, which is all recovery reads.
        effect: EffectReceipt::NotAttempted,
        local: Some(local),
    }
}

/// 128 random bits as 32 lowercase hex characters.
pub(super) fn random_hex() -> Result<String, ReconcileError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| ReconcileError::Unavailable("no random source".to_owned()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn intent_invalid(e: &ContentError) -> ReconcileError {
    ReconcileError::IntentInvalid(e.to_string())
}

fn default_state() -> RecoveryState {
    RecoveryState {
        phase: None,
        restore: RestoreCtx::NotDue,
        settlement: None,
        item: ItemState::Open,
        release_due: false,
    }
}

/// Some observation for a step whose names could not be classified (a contradictory
/// history, an unopenable directory): every name unobservable, as normalization
/// allows.
fn unobservable(state: &RecoveryState, shape: StepShape) -> StepObservation {
    let u = EntryObs::Unobservable;
    let a = EntryObs::Absent;
    for (p, s, q) in [(u, u, u), (u, u, a), (a, a, a)] {
        if let Ok(o) = StepObservation::normalize(p, s, q, state, shape) {
            return o;
        }
        if let Ok(o) = StepObservation::normalize(p, s, q, &default_state(), shape) {
            return o;
        }
    }
    // `normalize(∅, ∅, ∅)` of a fresh create step has no impossible combination
    // (ADR-0007 §5.7 "Normalization" item 3); a normalizer that refuses it is a
    // recovery defect, and nothing may be decided without an observation.
    match StepObservation::normalize(a, a, a, &default_state(), StepShape::Create) {
        Ok(o) => o,
        Err(e) => panic!("StepObservation::normalize refused a fresh all-absent step: {e}"),
    }
}

/// Outcome of one forward step.
enum Flow {
    /// The step reached post-validation (or K holds the lock).
    Continue,
    /// The step stopped before anything active changed, or the engine must decide;
    /// the item's reason.
    Stop(ConflictKind),
}

/// ADR-0007 §12.19 item 8, §12.20 item 2(a): when B_git's parse check cannot run
/// (local queries disabled, no verified Git client, or the client cannot be started),
/// the Git item aborts before its commit point with reason
/// `verified_client_unavailable`, not `unmanageable_file` (a check that ran and
/// refused the bytes).
const PARSE_CHECK_UNAVAILABLE: ConflictKind = ConflictKind::VerifiedClientUnavailable;

/// What B_git's parse check established (ADR-0007 §5.6 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseCheck {
    /// `git config --file <N_s> --no-includes --list` exited 0 within its bound.
    Parses,
    /// It ran and did not: a refusal, a non-zero exit or a timeout.
    Refused,
    /// It could not run (§12.19 item 8).
    Unavailable,
}

/// Where a forward step resumes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum From {
    /// Nothing written yet.
    Fresh,
    /// `file.staged` is the effective phase.
    Staged,
    /// `file.validated` is the effective phase.
    Validated,
}

/// One step's recovery view.
struct View {
    step: u16,
    state: Option<RecoveryState>,
    obs: StepObservation,
    dec: StepDecision,
}

/// Whether an action changed anything.
enum Progress {
    Acted,
    Held(HoldReason),
}

// --- the run ----------------------------------------------------------------------------

struct Run<'a> {
    config: &'a ProjectionConfig,
    intent: &'a SetupIntent,
    sink: Option<&'a mut dyn StageSink>,
    log: Vec<StageReceipt>,
    dirs: HashMap<PathBuf, Rc<DirHandle>>,
    quarantines: HashMap<PathBuf, Rc<Quarantine>>,
    reasons: BTreeMap<ProjectionItem, ConflictKind>,
    outcomes: BTreeMap<ProjectionItem, ItemOutcome>,
    /// ADR-0007 §12.20 item 1: this run's own `claim_lock` succeeded, so the lock name
    /// is classified by K's identity and holder digest ([`Run::k_in_this_run`]). A
    /// restart starts `false` and keeps the recovery classifier until it claims K
    /// itself.
    claimed_k: bool,
}

impl<'a> Run<'a> {
    fn new(
        config: &'a ProjectionConfig,
        intent: &'a SetupIntent,
        sink: Option<&'a mut dyn StageSink>,
        log: Vec<StageReceipt>,
    ) -> Result<Self, ReconcileError> {
        // Every local receipt must name a step of this intent; anything else cannot
        // be placed, and nothing is inferred from it (§5 item 17a).
        for r in &log {
            match &r.local {
                Some(LocalReceipt::File { step, .. })
                    if usize::from(*step) >= intent.files.len() =>
                {
                    return Err(ReconcileError::UnreadableReceipt(format!(
                        "receipt names step {step}, which the intent does not have"
                    )));
                }
                Some(local) if r.stage != local.stage() => {
                    return Err(ReconcileError::UnreadableReceipt(
                        "receipt stage does not match its payload".to_owned(),
                    ));
                }
                _ => {}
            }
        }
        Ok(Self {
            config,
            intent,
            sink,
            log,
            dirs: HashMap::new(),
            quarantines: HashMap::new(),
            reasons: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            claimed_k: false,
        })
    }

    fn step(&self, i: u16) -> &'a FileStep {
        &self.intent.files[usize::from(i)]
    }

    fn steps_of(&self, item: ProjectionItem) -> Vec<u16> {
        self.intent
            .files
            .iter()
            .enumerate()
            .filter(|(_, s)| s.role.item() == item && is_writing(s))
            .map(|(i, _)| step_index(i))
            .collect()
    }

    fn commit_step(&self, item: ProjectionItem) -> Option<u16> {
        self.intent
            .files
            .iter()
            .enumerate()
            .find(|(_, s)| s.role.item() == item && s.commit)
            .map(|(i, _)| step_index(i))
    }

    // --- receipts ------------------------------------------------------------------

    fn file_phases(&self, i: u16) -> impl Iterator<Item = &FilePhase> {
        self.log.iter().filter_map(move |r| match &r.local {
            Some(LocalReceipt::File { step, phase }) if *step == i => Some(phase),
            _ => None,
        })
    }

    fn item_phases(&self, item: ProjectionItem) -> impl Iterator<Item = &ItemPhase> {
        self.log.iter().filter_map(move |r| match &r.local {
            Some(LocalReceipt::Item { item: it, phase }) if *it == item => Some(phase),
            _ => None,
        })
    }

    fn staged_identity(&self, i: u16) -> Option<FileIdentity> {
        self.file_phases(i)
            .filter_map(|p| match p {
                FilePhase::Staged { identity } => Some(identity.clone()),
                _ => None,
            })
            .last()
    }

    fn validated_base(&self, i: u16) -> Option<FileIdentity> {
        self.file_phases(i)
            .filter_map(|p| match p {
                FilePhase::Validated { base } => base.clone(),
                _ => None,
            })
            .last()
    }

    fn mismatch_identity(&self, i: u16) -> Option<FileIdentity> {
        self.file_phases(i)
            .filter_map(|p| match p {
                FilePhase::PostValidated {
                    verdict: PostVerdict::Mismatch,
                    observed,
                } => observed.clone(),
                _ => None,
            })
            .last()
    }

    fn was_exchanged(&self, i: u16) -> bool {
        self.file_phases(i)
            .any(|p| matches!(p, FilePhase::Exchanged))
    }

    /// The last `file.settling` of step `i`: source, name, expected entry, slot.
    fn settling(&self, i: u16) -> Option<(SettleSource, String, Expected, String)> {
        self.file_phases(i)
            .filter_map(|p| match p {
                FilePhase::Settling {
                    source,
                    name,
                    expected,
                    expected_sha256,
                    slot,
                } => Some((
                    *source,
                    name.clone(),
                    Expected {
                        identity: expected.clone(),
                        sha256: expected_sha256.clone(),
                    },
                    slot.clone(),
                )),
                _ => None,
            })
            .last()
    }

    fn held_count(&self, i: u16) -> (usize, Option<&Vec<ObservedName>>, Option<HoldReason>) {
        let mut n = 0;
        let mut last = None;
        let mut reason = None;
        for p in self.file_phases(i) {
            if let FilePhase::Held {
                reason: r,
                observed,
            } = p
            {
                n += 1;
                last = Some(observed);
                reason = Some(*r);
            }
        }
        (n, last, reason)
    }

    fn item_receipts(&self, item: ProjectionItem) -> ItemReceipts {
        let mut rx = ItemReceipts::default();
        for p in self.item_phases(item) {
            match p {
                ItemPhase::Committed { .. } => rx.committed = true,
                ItemPhase::RollingBack { reason } => rx.rolling_back = Some(*reason),
                ItemPhase::Finished { .. } => rx.finished = true,
            }
        }
        rx
    }

    fn finished(&self, item: ProjectionItem) -> Option<ItemFinish> {
        self.item_phases(item)
            .filter_map(|p| match p {
                ItemPhase::Finished { outcome, .. } => Some(*outcome),
                _ => None,
            })
            .last()
    }

    /// The reason `item.finished` recorded (ADR-0007 §12.20 item 2(b)), if any.
    fn finished_reason(&self, item: ProjectionItem) -> Option<ConflictKind> {
        self.item_phases(item)
            .filter_map(|p| match p {
                ItemPhase::Finished { reason, .. } => Some(*reason),
                _ => None,
            })
            .last()
            .flatten()
    }

    fn committed_generation(&self, item: ProjectionItem) -> Option<u64> {
        self.item_phases(item)
            .filter_map(|p| match p {
                ItemPhase::Committed { generation } => Some(*generation),
                _ => None,
            })
            .last()
    }

    /// The recorded identities and digests of step `i`.
    fn record(&self, i: u16) -> StepRecord {
        StepRecord::from_receipts(i, self.step(i), &self.log)
    }

    /// A hook handle for the points that fire inside a primitive call.
    fn hook_at(&self, i: u16) -> HookAt<'a> {
        HookAt::new(self.config.hook.as_deref(), i)
    }

    /// Append one receipt durably, then remember it.
    fn append(&mut self, hook_step: u16, local: LocalReceipt) -> Result<(), ReconcileError> {
        self.config
            .fire(ReplacePoint::BeforeReceipt(phase_kind(&local)), hook_step);
        let Some(sink) = self.sink.as_deref_mut() else {
            return Err(ReconcileError::Unavailable(
                "a passive observation cannot write".to_owned(),
            ));
        };
        sink.append(&local)?;
        self.log.push(stage_receipt(local));
        Ok(())
    }

    fn append_file(&mut self, i: u16, phase: FilePhase) -> Result<(), ReconcileError> {
        self.append(i, LocalReceipt::File { step: i, phase })
    }

    fn append_item(
        &mut self,
        item: ProjectionItem,
        phase: ItemPhase,
    ) -> Result<(), ReconcileError> {
        let hook_step = self.commit_step(item).unwrap_or(0);
        self.append(hook_step, LocalReceipt::Item { item, phase })
    }

    // --- directories ---------------------------------------------------------------

    /// The validated handle of `parent`; `Ok(None)` when it does not exist.
    fn dir(&mut self, parent: &Path) -> Result<Option<Rc<DirHandle>>, ReplaceRefusal> {
        if let Some(d) = self.dirs.get(parent) {
            return Ok(Some(Rc::clone(d)));
        }
        match std::fs::symlink_metadata(parent) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => {}
        }
        let d = Rc::new(
            DirHandle::open_with(parent, self.config.test.identity)
                .map_err(ReplaceRefusal::Unmanageable)?,
        );
        self.dirs.insert(parent.to_path_buf(), Rc::clone(&d));
        Ok(Some(d))
    }

    /// The handle of `parent`, creating it when it is missing for a file of `role`
    /// ([`create_missing_dir`]). Only a step that creates its file gets here with a
    /// missing directory.
    fn ensure_dir(
        &mut self,
        parent: &Path,
        role: FileRole,
    ) -> Result<Rc<DirHandle>, ReplaceRefusal> {
        if let Some(d) = self.dir(parent)? {
            return Ok(d);
        }
        create_missing_dir(parent, DirOwner::of(role))
            .map_err(|e| ReplaceRefusal::Unmanageable(replace::Unmanageable::Io(e)))?;
        self.dir(parent)?.ok_or_else(|| {
            ReplaceRefusal::Unmanageable(replace::Unmanageable::Io("directory vanished".into()))
        })
    }

    fn quarantine(&mut self, parent: &Path) -> Result<Rc<Quarantine>, ReconcileError> {
        if let Some(q) = self.quarantines.get(parent) {
            return Ok(Rc::clone(q));
        }
        let dir = self
            .dir(parent)
            .map_err(|e| ReconcileError::Unavailable(e.to_string()))?
            .ok_or_else(|| ReconcileError::Unavailable("directory missing".to_owned()))?;
        let q = Rc::new(
            Quarantine::open_or_create(&dir)
                .map_err(|e| ReconcileError::Unavailable(e.to_string()))?,
        );
        self.quarantines.insert(parent.to_path_buf(), Rc::clone(&q));
        Ok(q)
    }

    /// Remove every quarantine this run opened that is empty (`rmdir` never removes an
    /// entry).
    fn tidy(&mut self) {
        self.dirs.clear();
        for (_, q) in std::mem::take(&mut self.quarantines) {
            if let Ok(q) = Rc::try_unwrap(q) {
                let _ = q.rmdir_if_empty();
            }
        }
    }

    // --- preconditions ----------------------------------------------------------------

    /// §5.4 step 3 for step `i`: the directory, the base and the content binding.
    /// `Err` only for content that fails its binding (`IntentInvalid`).
    fn precheck(&mut self, i: u16) -> Result<Result<(), ConflictKind>, ReconcileError> {
        let step = self.step(i);
        if StepShape::of(step) == StepShape::Removal {
            return Ok(Ok(()));
        }
        if step.role == FileRole::GitLock {
            content::materialize(step, None).map_err(|e| intent_invalid(&e))?;
            return Ok(Ok(()));
        }
        let Some((parent, name)) = split(&step.path) else {
            return Err(ReconcileError::IntentInvalid(
                "a step path has no directory".to_owned(),
            ));
        };
        let dir = match self.dir(&parent) {
            Err(_) => return Ok(Err(ConflictKind::UnmanageableFile)),
            Ok(None) => {
                if step.base != Base::Absent {
                    return Ok(Err(changed_kind(step)));
                }
                content::materialize(step, None).map_err(|e| intent_invalid(&e))?;
                return Ok(Ok(()));
            }
            Ok(Some(d)) => d,
        };
        let validated = match replace::validate(&dir, &name, &step.base) {
            Ok(v) => v,
            Err(ReplaceRefusal::BaseChanged) => return Ok(Err(changed_kind(step))),
            Err(_) => return Ok(Err(ConflictKind::UnmanageableFile)),
        };
        match content::materialize(step, validated.bytes.as_deref()) {
            Ok(_) => Ok(Ok(())),
            Err(ContentError::BaseMismatch) => Ok(Err(changed_kind(step))),
            Err(e) => Err(intent_invalid(&e)),
        }
    }

    /// `reconcile`'s content check: every step whose base is still at its path must
    /// materialize, so a tampered intent is refused before any write.
    fn content_check(&mut self) -> Result<(), ReconcileError> {
        for i in 0..self.intent.files.len() {
            let i = step_index(i);
            let step = self.step(i);
            if !is_writing(step) && !is_check_only(step) {
                continue;
            }
            if self.was_exchanged(i) {
                continue;
            }
            // Conflicts are the table's business; only a binding failure stops here.
            let _conflict_is_the_tables = self.precheck(i)?;
        }
        Ok(())
    }

    // --- the original's snapshot (ADR-0007 §5.5) ------------------------------------

    /// ⟨M02⟩ ADR-0007 §5.5, §12.32 item 2: before the first edit of a user file (the
    /// user's SSH configuration, the global Git file), its original bytes are copied to
    /// `<state_dir>/backups/<name>.<UTC timestamp>.orig` ([`snapshot_original`]). A step
    /// that creates its file, a step that only checks it and a configuration without a
    /// state directory have nothing to copy. The copy is of the bytes the plan was
    /// computed from, so the stale-base refusal is a precondition of the edit: a file
    /// that is gone or holds other bytes refuses with the base's conflict
    /// (`user_config_changed`), and a copy that cannot be made with `unmanageable_file`;
    /// either way the step is not staged. The copy cannot be made when `backups` is not
    /// a private directory or holds an entry named like a snapshot that is not a valid
    /// one (§12.35 item 2); [`snapshot_original`] names that entry in its error, which
    /// the item outcome (a [`ConflictKind`] only) cannot carry.
    fn snapshot_before_edit(&self, step: &FileStep) -> Result<(), ConflictKind> {
        let name = match step.role {
            FileRole::UserSsh => SSH_SNAPSHOT_NAME,
            FileRole::GitInclude => GIT_SNAPSHOT_NAME,
            _ => return Ok(()),
        };
        let Some(backups) = self.config.backups_dir() else {
            return Ok(());
        };
        let Some(base) = base_sha(step).filter(|_| is_writing(step)) else {
            return Ok(());
        };
        match snapshot_original(
            Path::new(&step.path),
            &backups,
            name,
            Some(base.as_str()),
            Timestamp::now(),
        ) {
            Ok(Snapshot::Written(_) | Snapshot::Exists(_)) => Ok(()),
            Ok(Snapshot::Changed | Snapshot::Absent) => Err(changed_kind(step)),
            Err(_) => Err(ConflictKind::UnmanageableFile),
        }
    }

    // --- apply ------------------------------------------------------------------------

    fn apply_all(&mut self) -> Result<Vec<ItemOutcome>, ReconcileError> {
        let items = items_of(self.intent);
        // §5.4 step 3: every precondition of every file before the first commit point;
        // any failure writes nothing (no file; only the items' `not_applied`, so a
        // restart settles instead of resuming).
        let mut refusal = None;
        for i in 0..self.intent.files.len() {
            if let Err(kind) = self.precheck(step_index(i))? {
                refusal.get_or_insert(kind);
            }
        }
        if let Some(kind) = refusal {
            let mut out = Vec::new();
            for item in items {
                self.reasons.insert(item, kind);
                self.append_item(
                    item,
                    ItemPhase::Finished {
                        outcome: ItemFinish::NotApplied,
                        reason: Some(kind),
                    },
                )?;
                out.push(ItemOutcome::NotApplied {
                    item,
                    reason: Some(kind),
                });
            }
            return Ok(out);
        }
        let mut out = Vec::new();
        for item in items {
            let outcome = if self.blocked_by_ssh(item) {
                self.append_item(
                    item,
                    ItemPhase::Finished {
                        outcome: ItemFinish::NotApplied,
                        reason: None,
                    },
                )?;
                ItemOutcome::NotApplied { item, reason: None }
            } else {
                self.apply_item(item)?
            };
            self.outcomes.insert(item, outcome.clone());
            out.push(outcome);
        }
        Ok(out)
    }

    /// The Git item follows the SSH commit point (§5.4 "Git item"): it runs only when
    /// the intent's SSH item applied.
    fn blocked_by_ssh(&self, item: ProjectionItem) -> bool {
        item == ProjectionItem::Git
            && self
                .intent
                .files
                .iter()
                .any(|s| s.role.item() == ProjectionItem::Ssh)
            && !matches!(
                self.outcomes.get(&ProjectionItem::Ssh),
                Some(ItemOutcome::Applied { .. })
            )
    }

    fn apply_item(&mut self, item: ProjectionItem) -> Result<ItemOutcome, ReconcileError> {
        // ADR-0007 §5.5, §12.32 item 2: the item's user files are copied before any of
        // its steps writes, so a snapshot that cannot be made leaves the item unwritten.
        for i in self.steps_of(item) {
            if let Err(kind) = self.snapshot_before_edit(self.step(i)) {
                self.reasons.entry(item).or_insert(kind);
                return self.drive(item, false);
            }
        }
        for i in self.steps_of(item) {
            match self.forward_step(i, From::Fresh)? {
                Flow::Continue => {}
                Flow::Stop(kind) => {
                    self.reasons.entry(item).or_insert(kind);
                    break;
                }
            }
        }
        self.drive(item, false)
    }

    /// Run step `i` forward from `from` through post-validation (§5.3 steps 2–6).
    fn forward_step(&mut self, i: u16, from: From) -> Result<Flow, ReconcileError> {
        let step = self.step(i);
        if step.role == FileRole::GitLock {
            return self.forward_lock(i, from);
        }
        let (parent, name) = split(&step.path)
            .ok_or_else(|| ReconcileError::IntentInvalid("a step path has no directory".into()))?;
        let names =
            StepNames::of(step).map_err(|e| ReconcileError::IntentInvalid(e.to_string()))?;
        let staged_name = names.staged.clone();
        let dir = match if from == From::Fresh && step.base == Base::Absent {
            self.ensure_dir(&parent, step.role)
        } else {
            self.dir(&parent)
                .and_then(|d| d.ok_or(ReplaceRefusal::BaseChanged))
        } {
            Ok(d) => d,
            Err(ReplaceRefusal::BaseChanged) => return Ok(Flow::Stop(changed_kind(step))),
            Err(_) => return Ok(Flow::Stop(ConflictKind::UnmanageableFile)),
        };
        dir.learn_step(step);
        // Step 2: validate the base.
        let validated = match replace::validate(&dir, &name, &step.base) {
            Ok(v) => v,
            Err(r) => return Ok(Flow::Stop(refusal_kind(step, &r))),
        };
        self.config.fire(ReplacePoint::AfterValidate, i);
        let bytes = match content::materialize(step, validated.bytes.as_deref()) {
            Ok(m) => m,
            Err(ContentError::BaseMismatch) => return Ok(Flow::Stop(changed_kind(step))),
            Err(e) => return Err(intent_invalid(&e)),
        };
        // ADR-0007 §5.5, §12.32 item 2: whatever started this step (an apply, or the
        // resume of a restart that never got to it), a user file's original is copied
        // before its first edit; an existing snapshot is kept.
        if from == From::Fresh
            && let Err(kind) = self.snapshot_before_edit(step)
        {
            return Ok(Flow::Stop(kind));
        }
        // Step 3: stage (or keep the recorded S).
        let staged = if from == From::Fresh {
            let s = match replace::stage(&dir, &staged_name, &bytes, mode_of(step)) {
                Ok(s) => s,
                Err(ReplaceError::Exists) => return Ok(Flow::Stop(ConflictKind::ConcurrentWriter)),
                Err(ReplaceError::Refused(r)) => return Ok(Flow::Stop(refusal_kind(step, &r))),
                Err(_) => return Ok(Flow::Stop(ConflictKind::UnmanageableFile)),
            };
            self.config.fire(ReplacePoint::AfterStage, i);
            self.append_file(
                i,
                FilePhase::Staged {
                    identity: s.identity.clone(),
                },
            )?;
            s
        } else {
            let Some(identity) = self.staged_identity(i) else {
                return Ok(Flow::Stop(ConflictKind::ConcurrentWriter));
            };
            Staged {
                identity,
                name: staged_name,
            }
        };
        // Step 4: recheck at the boundary, then `file.validated`.
        if let Err(r) = replace::recheck_at(&dir, &names.target, &validated) {
            return Ok(Flow::Stop(refusal_kind(step, &r)));
        }
        // §5.6 step 3 (row 4 of the replace and create tables): B_git's new bytes
        // must parse before its exchange; a failure aborts before the commit point. A
        // check that cannot run aborts too, with its own reason (§12.19 item 8).
        if step.role == FileRole::GitInclude {
            match self.git_parse_check(&parent, &names.staged) {
                ParseCheck::Parses => {}
                ParseCheck::Refused => return Ok(Flow::Stop(ConflictKind::UnmanageableFile)),
                ParseCheck::Unavailable => return Ok(Flow::Stop(PARSE_CHECK_UNAVAILABLE)),
            }
        }
        if from != From::Validated {
            self.append_file(
                i,
                FilePhase::Validated {
                    base: validated.identity.clone(),
                },
            )?;
        }
        // Immediately before the commit point, the item's other files are revalidated
        // (§5.4: P still S_P, the key files their staged identities; the update's user
        // file intact).
        if step.commit
            && let Err(kind) = self.transaction_check(step.role.item())?
        {
            return Ok(Flow::Stop(kind));
        }
        // Step 5: the exchange (a no-replace create for an absent base).
        self.config.fire(ReplacePoint::BeforeExchange, i);
        // ADR-0007 §12.18 item 4 (X04): B_git is exchanged only while K holds Git's
        // lock. Fresh apply and a restart's resume both get here; otherwise the item
        // aborts before its commit point, and the lock step's own rows (K3, K4, K2 for
        // a K′) settle what the lock name holds, exactly as recovery does.
        if step.role == FileRole::GitInclude && !self.lock_held_by_k() {
            return Ok(Flow::Stop(ConflictKind::GitConfigLocked));
        }
        let present = step.base != Base::Absent;
        let exchanged =
            match replace::exchange_at(&dir, &names, &staged, present.then_some(&validated)) {
                Ok(x) => x,
                Err(ReplaceError::Exists) => return Ok(Flow::Stop(ConflictKind::ConcurrentWriter)),
                Err(ReplaceError::Refused(r)) => return Ok(Flow::Stop(refusal_kind(step, &r))),
                // Whether an I/O failure exchanged is for the table to establish.
                Err(_) => return Ok(Flow::Stop(ConflictKind::ConcurrentWriter)),
            };
        self.config.fire(ReplacePoint::AfterExchange, i);
        self.append_file(i, FilePhase::Exchanged)?;
        // Step 6: post-validate.
        let verdict = replace::post_validate_at(&dir, &names, &exchanged, &validated, &staged);
        let flow = match verdict {
            PostValidation::Valid => {
                self.append_file(
                    i,
                    FilePhase::PostValidated {
                        verdict: PostVerdict::Valid,
                        observed: None,
                    },
                )?;
                Flow::Continue
            }
            PostValidation::Mismatch {
                observed: Some(observed),
            } => {
                self.append_file(
                    i,
                    FilePhase::PostValidated {
                        verdict: PostVerdict::Mismatch,
                        observed: Some(observed),
                    },
                )?;
                Flow::Stop(ConflictKind::ConcurrentWriter)
            }
            // Nothing at the displaced name, or the path is not S: the table decides
            // (F3b, F3c, C6a hold).
            PostValidation::Mismatch { observed: None } => {
                Flow::Stop(ConflictKind::ConcurrentWriter)
            }
        };
        self.config.fire(ReplacePoint::AfterPostValidate, i);
        Ok(flow)
    }

    /// ADR-0007 §5.6 step 3: `git config --file <N_s> --no-includes --list` exits 0
    /// for B_git's staged bytes. Fail closed: only [`ParseCheck::Parses`] lets B_git
    /// reach its exchange. With local queries off, no verified (selected) Git client in
    /// the inventory, or a client that cannot be started, the check cannot run
    /// ([`ParseCheck::Unavailable`], §12.19 item 8); a check that ran and did not exit
    /// 0 in its bound is [`ParseCheck::Refused`].
    fn git_parse_check(&self, parent: &Path, staged: &str) -> ParseCheck {
        if self.config.queries != LocalQueries::Enabled {
            return ParseCheck::Unavailable;
        }
        let Some(git) = self.config.clients.selected(ClientKind::Git) else {
            return ParseCheck::Unavailable;
        };
        match super::git::parse_check(&git.path, &parent.join(staged), &self.config.env) {
            super::git::ParseCheck::Parses => ParseCheck::Parses,
            super::git::ParseCheck::Refused => ParseCheck::Refused,
            super::git::ParseCheck::CannotRun => ParseCheck::Unavailable,
        }
    }

    /// ADR-0007 §12.18 item 4 (X04): whether the lock name holds K, by the identity the
    /// `git_lock` step's `file.staged` recorded and K's holder digest. This is the live
    /// path's check (§5.6 "Within one run … K's identity and holder digest are checked
    /// at each step"), so it holds without a birth time too: within one run K's
    /// identity cannot be reused while K exists, and a lock re-created on a freed inode
    /// lacks K's random line. `false` when anything is missing (fail closed).
    fn lock_held_by_k(&mut self) -> bool {
        let Some(k) = self
            .intent
            .files
            .iter()
            .position(|s| s.role == FileRole::GitLock)
            .map(step_index)
        else {
            return false;
        };
        let step = self.step(k);
        let (Some(identity), Some(sha256), Some((parent, name))) =
            (self.staged_identity(k), staged_sha(step), split(&step.path))
        else {
            return false;
        };
        let Ok(Some(dir)) = self.dir(&parent) else {
            return false;
        };
        replace::check_name(&dir, &name, &Expected { identity, sha256 })
            == NameState::Expected(ContentState::Unchanged)
    }

    /// The `git_lock` step: stage K, record it, then claim the lock (§5.6 steps 1–2).
    fn forward_lock(&mut self, i: u16, from: From) -> Result<Flow, ReconcileError> {
        let step = self.step(i);
        let (parent, lock_name) = split(&step.path)
            .ok_or_else(|| ReconcileError::IntentInvalid("a step path has no directory".into()))?;
        let staged_name = step
            .staged_name
            .clone()
            .ok_or_else(|| ReconcileError::IntentInvalid("a step has no staged name".into()))?;
        let dir = match self.ensure_dir(&parent, FileRole::GitLock) {
            Ok(d) => d,
            Err(_) => return Ok(Flow::Stop(ConflictKind::UnmanageableFile)),
        };
        let holder = if from == From::Fresh {
            let bytes = content::materialize(step, None).map_err(|e| intent_invalid(&e))?;
            let s = match replace::stage(&dir, &staged_name, &bytes, Mode::OwnerReadWrite) {
                Ok(s) => s,
                Err(_) => return Ok(Flow::Stop(ConflictKind::GitConfigLocked)),
            };
            self.config.fire(ReplacePoint::AfterStage, i);
            self.append_file(
                i,
                FilePhase::Staged {
                    identity: s.identity.clone(),
                },
            )?;
            s
        } else {
            let Some(identity) = self.staged_identity(i) else {
                return Ok(Flow::Stop(ConflictKind::GitConfigLocked));
            };
            Staged {
                identity,
                name: staged_name,
            }
        };
        self.config.fire(ReplacePoint::BeforeLockClaim, i);
        match claim_lock(&dir, &holder, &lock_name) {
            Ok(_) => {
                // ADR-0007 §12.20 item 1: from here on this run classifies the lock
                // name by K's identity and holder digest.
                self.claimed_k = true;
                self.config.fire(ReplacePoint::AfterLockClaim, i);
                Ok(Flow::Continue)
            }
            Err(_) => Ok(Flow::Stop(ConflictKind::GitConfigLocked)),
        }
    }

    // --- the transaction check (§5.4) -------------------------------------------------

    /// The item's transaction check: every other exchanged step of the item still has
    /// S with the target digest at its path, and every check-only step still holds its
    /// base (for the user file: exactly one Heimdall block, intact and first).
    fn transaction_check(
        &mut self,
        item: ProjectionItem,
    ) -> Result<Result<(), ConflictKind>, ReconcileError> {
        for (idx, step) in self.intent.files.iter().enumerate() {
            let i = step_index(idx);
            if step.role.item() != item || step.commit || step.role == FileRole::GitLock {
                continue;
            }
            if is_check_only(step) {
                if let Err(kind) = self.check_only_holds(step) {
                    return Ok(Err(kind));
                }
                continue;
            }
            if !is_writing(step) || !self.was_exchanged(i) {
                continue;
            }
            let Ok(state) = RecoveryState::build(i, &self.log, &self.intent.files) else {
                return Ok(Err(ConflictKind::ManagedFileEdited));
            };
            let obs = self.observe(i, &state);
            if obs.path()
                != (EntryObs::Recorded {
                    which: RecordedRole::S,
                    content: ContentState::Unchanged,
                })
            {
                return Ok(Err(ConflictKind::ManagedFileEdited));
            }
        }
        Ok(Ok(()))
    }

    fn check_only_holds(&mut self, step: &FileStep) -> Result<(), ConflictKind> {
        let (parent, name) = split(&step.path).ok_or(ConflictKind::UserConfigChanged)?;
        let dir = self
            .dir(&parent)
            .ok()
            .flatten()
            .ok_or(ConflictKind::UserConfigChanged)?;
        let validated =
            replace::validate(&dir, &name, &step.base).map_err(|r| refusal_kind(step, &r))?;
        let bytes = validated.bytes.unwrap_or_default();
        let intact_first = match step.role {
            FileRole::UserSsh => {
                let blocks = heimdall_sshconf::edit::find_blocks(&bytes);
                blocks.len() == 1
                    && blocks[0].intact
                    && blocks[0].position
                        == heimdall_sshconf::edit::BlockPosition::BeforeFirstSection
            }
            FileRole::GitInclude => {
                let blocks = heimdall_sshconf::gitedit::find_blocks(&bytes);
                blocks.len() == 1 && blocks[0].intact
            }
            _ => true,
        };
        if intact_first {
            Ok(())
        } else {
            Err(ConflictKind::UserConfigChanged)
        }
    }

    /// Commit the item: `item.committed` with its resources, record and consent in one
    /// store transaction (M2-R01).
    fn commit(&mut self, item: ProjectionItem) -> Result<(), ReconcileError> {
        let generation = self.intent.generation;
        let mut resources = Vec::new();
        for (idx, step) in self.intent.files.iter().enumerate() {
            let i = step_index(idx);
            if step.role.item() != item
                || !matches!(
                    step.role,
                    FileRole::ManagedSsh | FileRole::Key | FileRole::GitManaged
                )
                || !is_writing(step)
            {
                continue;
            }
            let (Some(identity), Target::Present { sha256 }) =
                (self.staged_identity(i), &step.target)
            else {
                continue;
            };
            resources.push(ProjectionLocator {
                role: step.role,
                path: step.path.clone(),
                identity,
                sha256: sha256.clone(),
            });
        }
        let aliases = if item == ProjectionItem::Ssh {
            self.intent
                .files
                .iter()
                .find(|s| s.role == FileRole::ManagedSsh)
                .map(|s| match s.content.view() {
                    StepContentView::Whole { bytes } => managed_aliases(bytes),
                    _ => Vec::new(),
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // ADR-0007 §12.37 item 3: the file B_git was written into, when this intent wrote
        // it. An update of P_git alone has no such step; the sink keeps the path the
        // previous generation recorded.
        let include_file = (item == ProjectionItem::Git)
            .then(|| {
                self.intent
                    .files
                    .iter()
                    .find(|s| s.role == FileRole::GitInclude && is_writing(s))
                    .map(|s| s.path.clone())
            })
            .flatten();
        // The consented states the plan computed (ADR-0007 §5.2), under the decision
        // that approved this intent; the plan carries a placeholder decision.
        let approved = self.intent.approval.as_ref().map(|a| a.decision.clone());
        let consent = ConsentRecord {
            items: self
                .intent
                .consent
                .items
                .iter()
                .filter(|(id, _)| (item == ProjectionItem::Git) == (id.0 == "git"))
                .map(|(k, v)| {
                    let mut v = v.clone();
                    if let Some(decision) = &approved {
                        v.decision = decision.clone();
                    }
                    (k.clone(), v)
                })
                .collect(),
        };
        let now = Timestamp::now();
        let record = ProjectionRecord {
            // Placeholders: the sink fills the environment, operation and time.
            environment: EnvironmentId::from_random_bytes([0; 16]),
            items: [(
                item,
                ItemRecord {
                    generation,
                    files: resources.clone(),
                    aliases,
                    include_file,
                    operation: OperationId::from_random_bytes([0; 16]),
                    committed_at: now,
                },
            )]
            .into_iter()
            .collect(),
        };
        let hook_step = self.commit_step(item).unwrap_or(0);
        self.config
            .fire(ReplacePoint::BeforeReceipt("committed"), hook_step);
        let Some(sink) = self.sink.as_deref_mut() else {
            return Err(ReconcileError::Unavailable(
                "a passive observation cannot write".to_owned(),
            ));
        };
        sink.commit_item(ItemCommit {
            item,
            generation,
            resources,
            record,
            consent,
        })?;
        self.log.push(stage_receipt(LocalReceipt::Item {
            item,
            phase: ItemPhase::Committed { generation },
        }));
        Ok(())
    }

    // --- observation -----------------------------------------------------------------

    fn observe(&mut self, i: u16, state: &RecoveryState) -> StepObservation {
        let step = self.step(i);
        let shape = StepShape::of(step);
        let Some((parent, _)) = split(&step.path) else {
            return unobservable(state, shape);
        };
        match self.dir(&parent) {
            Ok(Some(dir)) => {
                let record = self.record(i);
                let settling = SettlingAt::from_receipts(i, &self.log);
                let obs = replace::observe_step_at(&dir, step, &record, state, settling.as_ref());
                if self.claimed_k && step.role == FileRole::GitLock {
                    self.k_in_this_run(&dir, i, state, obs, settling.as_ref())
                } else {
                    obs
                }
            }
            Ok(None) => StepObservation::normalize(
                EntryObs::Absent,
                EntryObs::Absent,
                EntryObs::Absent,
                state,
                shape,
            )
            .unwrap_or_else(|_| unobservable(state, shape)),
            Err(_) => unobservable(state, shape),
        }
    }

    /// ADR-0007 §12.20 item 1: the `git_lock` step's observation in the run that
    /// claimed K. The lock name is K when it holds K's recorded identity with the
    /// holder digest, exactly as [`Run::lock_held_by_k`] checks before B_git's exchange
    /// (§5.6: within one run, identity and holder digest are checked at each step;
    /// K's identity cannot be reused while K exists, and a lock re-created on a freed
    /// inode lacks K's random line). It is `Q` while K's release from the lock is open
    /// (the settlement's source), `S` otherwise. Anything else keeps the recovery
    /// classification `obs` (an `S′`, a foreign entry, nothing), so this only ever adds
    /// the provable K that the classifier cannot see without a birth time (QR15); with
    /// a birth time, or on Windows, both agree.
    fn k_in_this_run(
        &self,
        dir: &DirHandle,
        i: u16,
        state: &RecoveryState,
        obs: StepObservation,
        settling: Option<&SettlingAt>,
    ) -> StepObservation {
        let step = self.step(i);
        let (Some(identity), Some(sha256), Some((_, lock))) =
            (self.staged_identity(i), staged_sha(step), split(&step.path))
        else {
            return obs;
        };
        let k = Expected { identity, sha256 };
        let (which, expected) = match settling {
            Some(s) if s.name == lock => (RecordedRole::Q, &s.expected),
            _ => (RecordedRole::S, &k),
        };
        if replace::check_name(dir, &lock, expected) != NameState::Expected(ContentState::Unchanged)
        {
            return obs;
        }
        StepObservation::normalize(
            EntryObs::Recorded {
                which,
                content: ContentState::Unchanged,
            },
            obs.aside(),
            obs.slot(),
            state,
            StepShape::GitLock,
        )
        .unwrap_or(obs)
    }

    fn fingerprint(&mut self, i: u16, state: &RecoveryState) -> StepFingerprint {
        let step = self.step(i);
        let unobs = || StepFingerprint {
            path: EntryFingerprint::Unobservable,
            aside: vec![EntryFingerprint::Unobservable],
            slot: None,
        };
        let Some((parent, _)) = split(&step.path) else {
            return unobs();
        };
        match self.dir(&parent) {
            Ok(Some(dir)) => {
                let _ = state;
                let settling = SettlingAt::from_receipts(i, &self.log);
                replace::observe_fingerprint_at(&dir, step, settling.as_ref())
            }
            Ok(None) => StepFingerprint {
                path: EntryFingerprint::Absent,
                aside: vec![EntryFingerprint::Absent],
                slot: None,
            },
            Err(_) => unobs(),
        }
    }

    fn view(&mut self, i: u16) -> View {
        let step = self.step(i);
        let shape = StepShape::of(step);
        match RecoveryState::build(i, &self.log, &self.intent.files) {
            Ok(state) => {
                let obs = self.observe(i, &state);
                let dec = recovery::decide(shape, &state, &obs);
                View {
                    step: i,
                    state: Some(state),
                    obs,
                    dec,
                }
            }
            Err(_) => View {
                step: i,
                obs: unobservable(&default_state(), shape),
                state: None,
                dec: StepDecision::Hold(HoldReason::ContradictoryReceipts),
            },
        }
    }

    /// The item rows' class of one step (ADR-0007 §12.17 item 4, in
    /// `recovery::StepState`'s order): held by its own row with that row's reason;
    /// for the commit step, never exchanged, then its own file-level restore
    /// (`restore_started{file_mismatch}` through `restored` and the settlement after
    /// it); then final, the T1 classes, or open.
    fn step_state(&self, v: &View, commit_at_t1: bool) -> StepState {
        if let StepDecision::Hold(reason) = v.dec {
            return StepState::Held(reason);
        }
        let Some(state) = &v.state else {
            return StepState::Held(HoldReason::ContradictoryReceipts);
        };
        let step = self.step(v.step);
        let exchanged = self.was_exchanged(v.step)
            || (matches!(state.phase, Some(EffectivePhase::Validated { .. }))
                && matches!(
                    v.dec,
                    StepDecision::Forward(ForwardStep::RecordExchanged)
                        | StepDecision::Restore(RestoreStep::RecordMismatch)
                ));
        if step.commit && !exchanged {
            return StepState::CommitNeverExchanged;
        }
        if step.commit
            && matches!(
                state.restore,
                RestoreCtx::Started(RestoreCause::FileMismatch)
                    | RestoreCtx::Done(RestoreCause::FileMismatch)
            )
        {
            return StepState::CommitRestored;
        }
        if v.dec == StepDecision::Settle(SettleStep::Done) {
            return StepState::Final;
        }
        if commit_at_t1
            && exchanged
            && state.item == ItemState::Open
            && state.restore == RestoreCtx::NotDue
        {
            let path_s = matches!(
                v.obs.path(),
                EntryObs::Recorded {
                    which: RecordedRole::S,
                    ..
                }
            );
            let aside_v = StepShape::of(step) != StepShape::Replace
                || matches!(
                    v.obs.aside(),
                    EntryObs::Recorded {
                        which: RecordedRole::V,
                        ..
                    }
                );
            return if path_s && aside_v {
                StepState::ExchangedConsistent
            } else {
                StepState::ExchangedInconsistent
            };
        }
        StepState::Open
    }

    /// Whether the item's commit step is at `post_validated{valid}` (row T1).
    fn commit_at_t1(&self, views: &[View]) -> bool {
        views.iter().any(|v| {
            self.step(v.step).commit
                && v.state.as_ref().is_some_and(|s| {
                    s.item == ItemState::Open
                        && s.restore == RestoreCtx::NotDue
                        && matches!(
                            s.phase,
                            Some(EffectivePhase::PostValidated {
                                verdict: PostVerdict::Valid,
                                ..
                            })
                        )
                })
        })
    }

    // --- the engine --------------------------------------------------------------------

    fn reconcile_all(&mut self) -> Result<Vec<ItemOutcome>, ReconcileError> {
        let mut out = Vec::new();
        for item in items_of(self.intent) {
            let resume = !self.blocked_by_ssh(item);
            let outcome = self.drive(item, resume)?;
            self.outcomes.insert(item, outcome.clone());
            out.push(outcome);
        }
        Ok(out)
    }

    /// Observe, decide and act on `item` until it is finished or held.
    fn drive(
        &mut self,
        item: ProjectionItem,
        mut resume_allowed: bool,
    ) -> Result<ItemOutcome, ReconcileError> {
        let mut abort_decided = false;
        for _ in 0..MAX_ITERATIONS {
            if let Some(finish) = self.finished(item) {
                return Ok(self.outcome_of(item, finish));
            }
            let steps = self.steps_of(item);
            let views: Vec<View> = steps.iter().map(|&i| self.view(i)).collect();
            // Decisions the receipts and entries already settle, in plan order. A held
            // step moves nothing (its decision is not one of these); the item's other
            // steps still finish what their own rows decide (a restore already due, a
            // settlement in flight), so the behaviour-bearing restore is never blocked
            // by an edited inactive file.
            if let Some(v) = views.iter().find(|v| self.is_recording(v)) {
                let step = v.step;
                match self.act(v)? {
                    Progress::Acted => continue,
                    Progress::Held(reason) => {
                        // Record what the names hold now, not before the action.
                        let views: Vec<View> = steps.iter().map(|&i| self.view(i)).collect();
                        return self.hold(item, &views, Some((step, reason)));
                    }
                }
            }
            // TH: once nothing else progresses, a held step holds the item.
            if views.iter().any(|v| matches!(v.dec, StepDecision::Hold(_))) {
                return self.hold(item, &views, None);
            }
            let at_t1 = self.commit_at_t1(&views);
            let states: Vec<StepState> = views.iter().map(|v| self.step_state(v, at_t1)).collect();
            let rx = self.item_receipts(item);
            // An item with no step to write (a rollback whose B is already gone, so
            // only its files for the cleaner remain) exchanges nothing: its transaction
            // check and `item.committed` are its commit point. The item rows have no row
            // for an item without steps.
            let decision = if views.is_empty() && !rx.committed && rx.rolling_back.is_none() {
                ItemDecision::TransactionCheck
            } else {
                recovery::decide_item(&states, &rx)
            };
            match decision {
                ItemDecision::Hold(reason) => {
                    let held: Vec<u16> = views
                        .iter()
                        .zip(&states)
                        .filter(|(_, s)| {
                            matches!(s, StepState::ExchangedInconsistent | StepState::Held(_))
                        })
                        .map(|(v, _)| v.step)
                        .collect();
                    let target = held
                        .first()
                        .copied()
                        .or_else(|| self.commit_step(item))
                        .or_else(|| steps.first().copied());
                    return self.hold(item, &views, target.map(|s| (s, reason)));
                }
                ItemDecision::Settle => {
                    let finish = self.finished(item).unwrap_or(ItemFinish::NotApplied);
                    return Ok(self.outcome_of(item, finish));
                }
                ItemDecision::TransactionCheck => {
                    if let Some(c) = self.commit_step(item) {
                        self.config.fire(ReplacePoint::BeforeCommit, c);
                    }
                    match self.transaction_check(item)? {
                        Ok(()) => self.commit(item)?,
                        Err(kind) => {
                            self.reasons.insert(item, kind);
                            self.append_item(item, ItemPhase::RollingBack { reason: kind })?;
                        }
                    }
                }
                ItemDecision::ResumeOrAbort => {
                    if resume_allowed && self.can_resume(item, &views)? {
                        match self.resume_one(&views)? {
                            Some(Flow::Continue) => continue,
                            Some(Flow::Stop(kind)) => {
                                self.reasons.entry(item).or_insert(kind);
                                resume_allowed = false;
                                continue;
                            }
                            // Nothing left to resume (an abort's settlement already
                            // completed): the item aborts.
                            None => {}
                        }
                    }
                    resume_allowed = false;
                    // ADR-0007 §12.20 item 2(b): the abort's reason is read in the round
                    // that decides it, before its own actions change any phase. A stop
                    // of the live path (or of a resume) already set it and is kept.
                    if !abort_decided {
                        abort_decided = true;
                        if let Some(kind) = self.abort_reason(item, &views)? {
                            self.reasons.entry(item).or_insert(kind);
                        }
                    }
                    // T0 abort: settle Heimdall's own unexchanged staged entries, then
                    // release K last, then finish `not_applied`.
                    if self.abort_one(&views)? || self.release_k(&views, true)? {
                        continue;
                    }
                    if let Some(outcome) =
                        self.finish_at_end(item, &views, ItemFinish::NotApplied)?
                    {
                        return Ok(outcome);
                    }
                }
                ItemDecision::FinishForward | ItemDecision::FinishRestore => {
                    // T2 releases K when the receipts make it due (its K2 release is a
                    // recording decision above; a K1 due by receipts settles from the
                    // staged name here). T3 also releases it once every other step
                    // reached its end in this observation (§12.17 item 3).
                    let restore = !rx.committed;
                    if self.release_k(&views, restore)? {
                        continue;
                    }
                    if rx.committed && views.iter().all(|v| self.at_end(v)) {
                        self.keep_edited_managed(item);
                    }
                    let outcome = if rx.committed {
                        ItemFinish::Applied
                    } else {
                        ItemFinish::Restored
                    };
                    if let Some(outcome) = self.finish_at_end(item, &views, outcome)? {
                        return Ok(outcome);
                    }
                }
            }
        }
        let views: Vec<View> = self.steps_of(item).iter().map(|&i| self.view(i)).collect();
        let target = views.first().map(|v| (v.step, HoldReason::Unmatched));
        self.hold(item, &views, target)
    }

    /// Decisions that only record or continue what the receipts already decide.
    fn is_recording(&self, v: &View) -> bool {
        match v.dec {
            StepDecision::Forward(
                ForwardStep::RecordStaged
                | ForwardStep::RecordExchanged
                | ForwardStep::PostValidate
                | ForwardStep::NothingDisplaced,
            )
            | StepDecision::Restore(_) => true,
            StepDecision::Settle(SettleStep::Done) => false,
            StepDecision::Settle(_) => true,
            _ => false,
        }
    }

    fn can_resume(&mut self, item: ProjectionItem, views: &[View]) -> Result<bool, ReconcileError> {
        if self.blocked_by_ssh(item) {
            return Ok(false);
        }
        for v in views {
            let lock = self.step(v.step).role == FileRole::GitLock;
            let ok = match v.dec {
                StepDecision::Forward(
                    ForwardStep::Stage | ForwardStep::Revalidate | ForwardStep::ClaimLock,
                ) => self.precheck(v.step)?.is_ok(),
                StepDecision::Forward(ForwardStep::KeepLock | ForwardStep::TransactionCheck) => {
                    true
                }
                // T0 resumes the Git item only under a lock Heimdall can prove it holds
                // (K1 whose claim succeeds, or K2); a final lock step (K3, K4 recorded)
                // aborts the item.
                StepDecision::Settle(SettleStep::Done) => !lock,
                _ => false,
            };
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// ADR-0007 §12.20 item 2(b): the reason of an abort that recovery decides, in plan
    /// order: the first step whose own row names one ([`Run::row_reason`]), or whose
    /// T0 precondition (§5.4 step 3, [`Run::precheck`]) fails where its row would
    /// resume. `None` for a Git item that waits for the SSH commit point (it never
    /// ran, and the live path reports none either), and when no row names a reason
    /// (F0z, F2k, C4b, K0z, an `S′` that cannot be continued).
    fn abort_reason(
        &mut self,
        item: ProjectionItem,
        views: &[View],
    ) -> Result<Option<ConflictKind>, ReconcileError> {
        if self.blocked_by_ssh(item) {
            return Ok(None);
        }
        for v in views {
            if let Some(kind) = self.row_reason(v) {
                return Ok(Some(kind));
            }
            if matches!(
                v.dec,
                StepDecision::Forward(
                    ForwardStep::Stage | ForwardStep::Revalidate | ForwardStep::ClaimLock
                )
            ) && let Err(kind) = self.precheck(v.step)?
            {
                return Ok(Some(kind));
            }
        }
        Ok(None)
    }

    /// The conflict reason the ADR-0007 §5.7 row of `v` names for an abort (§12.20
    /// item 2(b)), for a step of an open item with no restore in its context (the rows
    /// before the exchange run under T0):
    ///
    /// * `concurrent_writer`: F1a (`staged`, the aside ∅ or X), F2g (`validated`, path
    ///   V or V′, aside ∅), C3 (`validated`, path X, aside S or S′), C4 (`validated`,
    ///   path and aside ∅) and K3;
    /// * the base's conflict (`user_config_changed` for the user file and the global
    ///   Git file, `managed_file_edited` otherwise): F2e (path X) and F2j (path ∅), each
    ///   with the aside S or S′, and F2a with a V′ at the path, which T0's revalidation
    ///   refuses (a T0 precondition);
    /// * `git_config_locked`: K0 (nothing staged, an entry at the lock) and K1 (K
    ///   staged, a foreign lock: the claim fails), and K4.
    ///
    /// K3 and K4 are recording rows, so when the item aborts they are already on record:
    /// they are read from K's receipts ([`Run::lock_conflict_reason`]).
    fn row_reason(&self, v: &View) -> Option<ConflictKind> {
        let state = v.state.as_ref()?;
        if state.item != ItemState::Open || state.restore != RestoreCtx::NotDue {
            return None;
        }
        let step = self.step(v.step);
        let (p, a) = (v.obs.path(), v.obs.aside());
        let absent = |e: EntryObs| e == EntryObs::Absent;
        let foreign = |e: EntryObs| e == EntryObs::Foreign;
        let is = |e: EntryObs, role: RecordedRole| matches!(e, EntryObs::Recorded { which, .. } if which == role);
        let cw = ConflictKind::ConcurrentWriter;
        let locked = ConflictKind::GitConfigLocked;
        match (StepShape::of(step), &state.phase) {
            (StepShape::Replace | StepShape::Create, Some(EffectivePhase::Staged { .. })) => {
                (absent(a) || foreign(a)).then_some(cw) // F1a
            }
            (StepShape::Replace, Some(EffectivePhase::Validated { .. })) => {
                let v_modified = p
                    == EntryObs::Recorded {
                        which: RecordedRole::V,
                        content: ContentState::Modified,
                    };
                if is(p, RecordedRole::V) && absent(a) {
                    Some(cw) // F2g
                } else if (foreign(p) || absent(p) || v_modified) && is(a, RecordedRole::S) {
                    Some(changed_kind(step)) // F2e, F2j; F2a with V′ (T0 precondition)
                } else {
                    None
                }
            }
            (StepShape::Create, Some(EffectivePhase::Validated { .. })) => {
                ((foreign(p) && is(a, RecordedRole::S)) || (absent(p) && absent(a))).then_some(cw) // C3, C4
            }
            (StepShape::GitLock, None) => (foreign(p) && absent(a)).then_some(locked), // K0
            (StepShape::GitLock, Some(EffectivePhase::Staged { .. })) => {
                (foreign(p) && is(a, RecordedRole::S)).then_some(locked) // K1
            }
            (StepShape::GitLock, Some(EffectivePhase::SettleConflict { .. })) => {
                self.lock_conflict_reason(v.step)
            }
            _ => None,
        }
    }

    /// K3 or K4 as recorded: K's `file.settle_conflict` directly after its
    /// `file.staged`, with no settlement between them (a conflict of K's release
    /// follows a `file.settling`). `{missing}` (K gone) and `{foreign}` naming K's
    /// staged name (an X there, ADR-0007 §12.20 item 4) are K3, `concurrent_writer`;
    /// `{foreign}` naming the lock name is K4, `git_config_locked` (the lock is held,
    /// not provably by Heimdall).
    fn lock_conflict_reason(&self, i: u16) -> Option<ConflictKind> {
        let (_, lock) = split(&self.step(i).path)?;
        let mut phases = self
            .file_phases(i)
            .filter(|p| !matches!(p, FilePhase::Held { .. }));
        let (Some(FilePhase::Staged { .. }), Some(FilePhase::SettleConflict { found, kept }), None) =
            (phases.next(), phases.next(), phases.next())
        else {
            return None;
        };
        match found {
            SettleConflictFound::Foreign if kept.iter().any(|k| k.name == lock) => {
                Some(ConflictKind::GitConfigLocked) // K4
            }
            SettleConflictFound::Missing | SettleConflictFound::Foreign => {
                Some(ConflictKind::ConcurrentWriter) // K3
            }
            SettleConflictFound::Modified => None,
        }
    }

    /// T0 resume: continue the first step that is not yet forward-complete.
    fn resume_one(&mut self, views: &[View]) -> Result<Option<Flow>, ReconcileError> {
        for v in views {
            let from = match (&v.dec, v.state.as_ref().and_then(|s| s.phase.as_ref())) {
                (StepDecision::Forward(ForwardStep::Stage), _) => From::Fresh,
                (
                    StepDecision::Forward(ForwardStep::Revalidate | ForwardStep::ClaimLock),
                    Some(EffectivePhase::Validated { .. }),
                ) => From::Validated,
                (StepDecision::Forward(ForwardStep::Revalidate | ForwardStep::ClaimLock), _) => {
                    From::Staged
                }
                _ => continue,
            };
            return self.forward_step(v.step, from).map(Some);
        }
        Ok(None)
    }

    /// T0 abort, first part: settle Heimdall's own unexchanged staged entries (never
    /// K's: [`Run::release_k`] releases it last). Returns whether it acted.
    fn abort_one(&mut self, views: &[View]) -> Result<bool, ReconcileError> {
        for v in views {
            if self.step(v.step).role != FileRole::GitLock
                && matches!(
                    v.dec,
                    StepDecision::Abort(AbortStep::SettleStaged)
                        | StepDecision::Forward(ForwardStep::Revalidate)
                )
                && !self.was_exchanged(v.step)
                && self.settle_staged(v.step)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Settle step `i`'s own unexchanged S (K before its claim) from its staged name.
    fn settle_staged(&mut self, i: u16) -> Result<bool, ReconcileError> {
        let step = self.step(i);
        let (Some(identity), Some(sha256), Some(name)) = (
            self.staged_identity(i),
            staged_sha(step),
            step.staged_name.clone(),
        ) else {
            return Ok(false);
        };
        let progress =
            self.begin_settlement(i, SettleSource::Staged, name, Expected { identity, sha256 })?;
        Ok(matches!(progress, Progress::Acted))
    }

    /// Release K when it is due (ADR-0007 §12.17 item 3). No receipt records a
    /// hand-over, so this is computed every round from the durable receipts and this
    /// round's observation, and a restart computes it again: K's release is due when
    /// `RecoveryState::build` says so (every other Git step final by its receipts),
    /// or, with `ending` (the item rows decided the item's abort or its restore), when
    /// every other step of the item reached its end in `views`
    /// ([`Run::at_end`]). K's own row then decides with the release due: K1 settles K
    /// from its staged name, K2 settles it from the lock. Returns whether it acted.
    fn release_k(&mut self, views: &[View], ending: bool) -> Result<bool, ReconcileError> {
        let Some(k) = views
            .iter()
            .find(|v| self.step(v.step).role == FileRole::GitLock)
        else {
            return Ok(false);
        };
        let Some(state) = k.state.as_ref() else {
            return Ok(false);
        };
        let others_ended = views
            .iter()
            .filter(|v| v.step != k.step)
            .all(|v| self.at_end(v));
        if !(state.release_due || (ending && others_ended)) {
            return Ok(false);
        }
        let mut due = state.clone();
        due.release_due = true;
        let dec = recovery::decide(StepShape::GitLock, &due, &k.obs);
        match dec {
            StepDecision::Abort(AbortStep::SettleStaged) => self.settle_staged(k.step),
            StepDecision::Settle(SettleStep::Begin) => {
                let view = View {
                    step: k.step,
                    state: Some(due),
                    obs: k.obs,
                    dec,
                };
                Ok(matches!(self.act(&view)?, Progress::Acted))
            }
            _ => Ok(false),
        }
    }

    /// Whether step `v` reached its end for the item (ADR-0007 §5.7 "The recovery
    /// state", `release_due`): its rows have nothing left to do (settled,
    /// `settle_conflict`, a create's `restored`), nothing to settle, never staged, or,
    /// for an exchanged step other than the commit step that waits for the item, handed
    /// to the cleaner (an abort, or the commit step's own file-level restore).
    fn at_end(&self, v: &View) -> bool {
        match v.dec {
            StepDecision::Settle(SettleStep::Done)
            | StepDecision::Abort(AbortStep::NothingToSettle) => true,
            StepDecision::Forward(ForwardStep::Stage) => {
                v.state.as_ref().is_some_and(|s| s.phase.is_none())
            }
            StepDecision::Forward(ForwardStep::TransactionCheck) => !self.step(v.step).commit,
            _ => false,
        }
    }

    /// ADR-0007 §5.5: once a rollback's item committed (B is out of the user file), a
    /// managed file (P, P_git) whose content is no longer the recorded one is not left
    /// for the cleaner: it is renamed, with no-replace, to
    /// `<name>.hm-conflict-<generation>` (the rollback's generation, which the plan
    /// fixed), so the owner's edit survives and the next adoption does not displace
    /// it. The removal step's base is the recorded digest (the preview sets it from the
    /// projection record). A file with that content is the cleaner's (§5.8); a missing
    /// file, an entry that is not Heimdall's shape (a symlink, a hard link, another
    /// owner) and an occupied conflict name are left where they are. Nothing is
    /// deleted, and a restart repeats this without effect.
    fn keep_edited_managed(&mut self, item: ProjectionItem) {
        if !matches!(self.intent.intent, PreviewIntent::Rollback { .. }) {
            return;
        }
        let generation = self.intent.generation;
        for step in &self.intent.files {
            if step.role.item() != item
                || !matches!(step.role, FileRole::ManagedSsh | FileRole::GitManaged)
                || StepShape::of(step) != StepShape::Removal
                || std::fs::symlink_metadata(&step.path).is_err()
            {
                continue;
            }
            let Some((parent, name)) = split(&step.path) else {
                continue;
            };
            let Ok(Some(dir)) = self.dir(&parent) else {
                continue;
            };
            if replace::validate(&dir, &name, &step.base) == Err(ReplaceRefusal::BaseChanged) {
                let conflict = format!("{name}.hm-conflict-{generation}");
                // `Exists` (the name is taken) or a vanished file: left as it is.
                let _kept_in_place = replace::rename_noreplace(&dir, &name, &conflict);
            }
        }
    }

    /// Write `item.finished{outcome}` once every step reached its end; otherwise
    /// nothing a row moves is left, yet the item is not at its end: no row lists the
    /// combination, and the item is held (`unmatched`). The receipt records the
    /// outcome's reason (ADR-0007 §12.20 item 2(b)), which a restart reports.
    fn finish_at_end(
        &mut self,
        item: ProjectionItem,
        views: &[View],
        outcome: ItemFinish,
    ) -> Result<Option<ItemOutcome>, ReconcileError> {
        if let Some(v) = views.iter().find(|v| !self.at_end(v)) {
            let target = Some((v.step, HoldReason::Unmatched));
            return self.hold(item, views, target).map(Some);
        }
        let reason = match outcome {
            ItemFinish::NotApplied => self.reasons.get(&item).copied(),
            ItemFinish::Restored => self.restored_reason(item),
            ItemFinish::Applied | ItemFinish::ConflictPreserved => None,
        };
        self.append_item(item, ItemPhase::Finished { outcome, reason })?;
        Ok(None)
    }

    /// Carry out one step decision.
    fn act(&mut self, v: &View) -> Result<Progress, ReconcileError> {
        let i = v.step;
        let step = self.step(i);
        let state = v.state.clone().unwrap_or_else(default_state);
        match v.dec {
            StepDecision::Forward(ForwardStep::RecordStaged) => {
                let fp = self.fingerprint(i, &state);
                let identity = fp.aside.iter().find_map(|e| match e {
                    EntryFingerprint::Present { identity, .. } => Some(identity.clone()),
                    _ => None,
                });
                let Some(identity) = identity else {
                    return Ok(Progress::Held(HoldReason::Unobservable));
                };
                self.append_file(i, FilePhase::Staged { identity })?;
            }
            StepDecision::Forward(ForwardStep::RecordExchanged) => {
                self.append_file(i, FilePhase::Exchanged)?;
            }
            StepDecision::Forward(ForwardStep::PostValidate) => {
                self.append_file(
                    i,
                    FilePhase::PostValidated {
                        verdict: PostVerdict::Valid,
                        observed: None,
                    },
                )?;
            }
            StepDecision::Forward(ForwardStep::NothingDisplaced) => {
                self.append_file(
                    i,
                    FilePhase::Settled {
                        disposition: SettledDisposition::NothingDisplaced,
                    },
                )?;
            }
            StepDecision::Restore(RestoreStep::RecordMismatch) => {
                if matches!(state.phase, Some(EffectivePhase::Validated { .. })) {
                    self.append_file(i, FilePhase::Exchanged)?;
                }
                let fp = self.fingerprint(i, &state);
                let observed = fp.aside.iter().find_map(|e| match e {
                    EntryFingerprint::Present { identity, .. } => Some(identity.clone()),
                    _ => None,
                });
                self.append_file(
                    i,
                    FilePhase::PostValidated {
                        verdict: PostVerdict::Mismatch,
                        observed,
                    },
                )?;
            }
            StepDecision::Restore(RestoreStep::Exchange) => {
                return self.restore_exchange(i, &state);
            }
            StepDecision::Restore(RestoreStep::RecognizeRestored) => {
                self.append_file(i, FilePhase::Restored)?;
            }
            StepDecision::Restore(RestoreStep::CreateRollback) => {
                let cause = restore_cause(&state);
                self.config.fire(ReplacePoint::BeforeRestoreCheck, i);
                let (Some(identity), Some(sha256), Some((parent, name))) =
                    (self.staged_identity(i), staged_sha(step), split(&step.path))
                else {
                    return Ok(Progress::Held(HoldReason::Unmatched));
                };
                let expected = Expected { identity, sha256 };
                // ADR-0007 §12.18 item 2 (X02), §5.3 step 7, rows C7–C7b: before anything
                // is written or moved, the path must still hold S with the target
                // digest. An edit since the observation is held here (C7a), and the
                // edited file stays at its path; nothing else of S is C7b.
                if let Some(reason) = self.active_path_changed(&parent, &name, &expected) {
                    return Ok(Progress::Held(reason));
                }
                if !matches!(state.phase, Some(EffectivePhase::RestoreStarted { .. })) {
                    self.append_file(i, FilePhase::RestoreStarted { cause })?;
                }
                return self.begin_settlement(i, SettleSource::Path, name, expected);
            }
            StepDecision::Settle(SettleStep::Begin) => {
                let Some((source, name, expected)) = self.settle_source(i, &state, &v.obs) else {
                    return Ok(Progress::Held(HoldReason::Unmatched));
                };
                if step.role == FileRole::GitLock && source == SettleSource::Path {
                    self.config.fire(ReplacePoint::BeforeLockRelease, i);
                }
                return self.begin_settlement(i, source, name, expected);
            }
            StepDecision::Settle(SettleStep::Move) => return self.settle_move(i),
            StepDecision::Settle(SettleStep::RecordSettled) => {
                self.append_file(
                    i,
                    FilePhase::Settled {
                        disposition: SettledDisposition::Quarantined,
                    },
                )?;
                self.remove_slot(i)?;
            }
            StepDecision::Settle(SettleStep::Remove) => self.remove_slot(i)?,
            StepDecision::Settle(SettleStep::PutBackForeign) => self.put_back(i)?,
            StepDecision::Settle(SettleStep::RecordConflict) => {
                let (found, kept) = self.conflict_found(i, &state, &v.obs);
                self.append_file(i, FilePhase::SettleConflict { found, kept })?;
            }
            StepDecision::Settle(SettleStep::Done) => {}
            StepDecision::Hold(reason) => return Ok(Progress::Held(reason)),
            StepDecision::Forward(_) | StepDecision::Abort(_) => {}
        }
        Ok(Progress::Acted)
    }

    /// F5: check that the path holds S with the target digest, write
    /// `file.restore_started` unless it is the effective phase, exchange back, verify
    /// both identities, write `file.restored` (ADR-0007 §5.3 step 7).
    fn restore_exchange(
        &mut self,
        i: u16,
        state: &RecoveryState,
    ) -> Result<Progress, ReconcileError> {
        let step = self.step(i);
        let cause = restore_cause(state);
        let (Some(s), Some(sha256), Some(d)) = (
            self.staged_identity(i),
            staged_sha(step),
            self.mismatch_identity(i).or_else(|| self.validated_base(i)),
        ) else {
            return Ok(Progress::Held(HoldReason::Unmatched));
        };
        let (Some((parent, _)), Ok(names)) = (split(&step.path), StepNames::of(step)) else {
            return Ok(Progress::Held(HoldReason::Unobservable));
        };
        let Ok(Some(dir)) = self.dir(&parent) else {
            return Ok(Progress::Held(HoldReason::Unobservable));
        };
        self.config.fire(ReplacePoint::BeforeRestoreCheck, i);
        let started = matches!(state.phase, Some(EffectivePhase::RestoreStarted { .. }));
        let hook = self.hook_at(i);
        let outcome = replace::restore_with(
            &dir,
            &names,
            &Expected {
                identity: s,
                sha256,
            },
            &d,
            hook,
            || {
                if started {
                    Ok(())
                } else {
                    self.append_file(i, FilePhase::RestoreStarted { cause })
                }
            },
        );
        match outcome {
            Ok(RestoreOutcome::Restored) => {
                self.config.fire(ReplacePoint::AfterRestoreExchange, i);
                self.append_file(i, FilePhase::Restored)?;
                Ok(Progress::Acted)
            }
            // Nothing moved, or a writer raced the exchange: the next observation
            // decides (F5a, F5b, F5c, F5d).
            Ok(RestoreOutcome::Held(reason, _)) => {
                if self.was_restore_started(i) {
                    Ok(Progress::Acted)
                } else {
                    Ok(Progress::Held(reason))
                }
            }
            Err(RestoreFailure::BeforeExchange(e)) => Err(e),
            Err(RestoreFailure::Io(_)) => Ok(Progress::Held(HoldReason::Unobservable)),
        }
    }

    fn was_restore_started(&self, i: u16) -> bool {
        self.file_phases(i)
            .any(|p| matches!(p, FilePhase::RestoreStarted { .. }))
    }

    /// What a `Settle(Begin)` moves (§5.3 step 8): K from the lock or its staged name,
    /// D after a commit, S after a restore or an abort.
    fn settle_source(
        &self,
        i: u16,
        state: &RecoveryState,
        obs: &StepObservation,
    ) -> Option<(SettleSource, String, Expected)> {
        let step = self.step(i);
        let s_expected = || {
            Some(Expected {
                identity: self.staged_identity(i)?,
                sha256: staged_sha(step)?,
            })
        };
        if step.role == FileRole::GitLock {
            let at_lock = matches!(
                obs.path(),
                EntryObs::Recorded {
                    which: RecordedRole::S,
                    ..
                }
            );
            return if at_lock {
                Some((SettleSource::Path, split(&step.path)?.1, s_expected()?))
            } else {
                Some((
                    SettleSource::Staged,
                    step.staged_name.clone()?,
                    s_expected()?,
                ))
            };
        }
        match state.phase {
            Some(EffectivePhase::Restored) => Some((
                SettleSource::Staged,
                step.staged_name.clone()?,
                s_expected()?,
            )),
            Some(EffectivePhase::PostValidated { .. }) if state.item == ItemState::Committed => {
                Some((
                    SettleSource::Displaced,
                    step.displaced_name.clone()?,
                    Expected {
                        identity: self.validated_base(i)?,
                        sha256: base_sha(step)?,
                    },
                ))
            }
            _ => Some((
                SettleSource::Staged,
                step.staged_name.clone()?,
                s_expected()?,
            )),
        }
    }

    fn conflict_found(
        &mut self,
        i: u16,
        state: &RecoveryState,
        obs: &StepObservation,
    ) -> (SettleConflictFound, Vec<PreservedEntry>) {
        let fp = self.fingerprint(i, state);
        let identity_of = |e: &EntryFingerprint| match e {
            EntryFingerprint::Present { identity, .. } => Some(identity.clone()),
            _ => None,
        };
        let slot_name = self.settling(i).map(|(_, _, _, slot)| slot);
        let step = self.step(i);
        match obs.slot() {
            EntryObs::Recorded {
                content: ContentState::Modified,
                ..
            } => {
                return (
                    SettleConflictFound::Modified,
                    slot_name
                        .map(|name| {
                            vec![PreservedEntry {
                                name,
                                identity: fp.slot.as_ref().and_then(identity_of),
                            }]
                        })
                        .unwrap_or_default(),
                );
            }
            EntryObs::Foreign => {
                return (
                    SettleConflictFound::Foreign,
                    slot_name
                        .map(|name| {
                            vec![PreservedEntry {
                                name,
                                identity: fp.slot.as_ref().and_then(identity_of),
                            }]
                        })
                        .unwrap_or_default(),
                );
            }
            _ => {}
        }
        let path_name = split(&step.path).map(|(_, n)| n);
        if obs.path() == EntryObs::Foreign
            && (step.role == FileRole::GitLock
                || matches!(self.settling(i), Some((SettleSource::Path, ..))))
        {
            return (
                SettleConflictFound::Foreign,
                path_name
                    .map(|name| {
                        vec![PreservedEntry {
                            name,
                            identity: identity_of(&fp.path),
                        }]
                    })
                    .unwrap_or_default(),
            );
        }
        if obs.aside() == EntryObs::Foreign {
            let aside_name = match self.settling(i) {
                Some((_, name, ..)) => Some(name),
                None => step
                    .displaced_name
                    .clone()
                    .or_else(|| step.staged_name.clone()),
            };
            return (
                SettleConflictFound::Foreign,
                aside_name
                    .map(|name| {
                        vec![PreservedEntry {
                            name,
                            identity: fp.aside.iter().find_map(identity_of),
                        }]
                    })
                    .unwrap_or_default(),
            );
        }
        (SettleConflictFound::Missing, Vec::new())
    }

    /// Write `file.settling` with a fresh slot, then move.
    fn begin_settlement(
        &mut self,
        i: u16,
        source: SettleSource,
        name: String,
        expected: Expected,
    ) -> Result<Progress, ReconcileError> {
        let slot = random_hex()?;
        self.append_file(
            i,
            FilePhase::Settling {
                source,
                name,
                expected: expected.identity,
                expected_sha256: expected.sha256,
                slot,
            },
        )?;
        self.settle_move(i)
    }

    /// F8a: move the recorded source into its slot and check it (§5.3 step 8.2–8.3).
    ///
    /// ADR-0007 §12.18 item 2 (X02): a create's restore settles its **active** path
    /// entry, so immediately before that move the path must still hold S with the
    /// target digest, as row F8a requires. An S′ there (an edit since `file.settling`
    /// or since the last observation) is not moved: it stays at its path and the next
    /// observation holds it (`active_entry_modified`). Any other entry is left to
    /// `settle_with`, which moves only the recorded identity (F8c, F8e). K's release
    /// from the lock name is not a create's restore: a K′ there is moved and kept in
    /// the quarantine (F8a, §5.3 step 8.4).
    fn settle_move(&mut self, i: u16) -> Result<Progress, ReconcileError> {
        let step = self.step(i);
        let Some((source, name, expected, slot)) = self.settling(i) else {
            return Ok(Progress::Acted);
        };
        let Some((parent, _)) = split(&step.path) else {
            return Ok(Progress::Acted);
        };
        let dir = self
            .dir(&parent)
            .map_err(|e| ReconcileError::Unavailable(e.to_string()))?
            .ok_or_else(|| ReconcileError::Unavailable("directory missing".to_owned()))?;
        let quarantine = self.quarantine(&parent)?;
        self.config.fire(ReplacePoint::BeforeSettleMove, i);
        if source == SettleSource::Path
            && StepShape::of(step) == StepShape::Create
            && replace::check_name(&dir, &name, &expected)
                == NameState::Expected(ContentState::Modified)
        {
            // `file.settling` is on record: the next observation decides (F8a holds
            // an S′ at the path with `active_entry_modified`).
            return Ok(Progress::Acted);
        }
        let outcome =
            replace::settle_with(&dir, &quarantine, &name, &expected, &slot, self.hook_at(i))
                .map_err(|e| ReconcileError::Unavailable(e.to_string()))?;
        self.settled_outcome(i, outcome, &expected)?;
        Ok(Progress::Acted)
    }

    /// ADR-0007 §12.18 item 2 (X02): what a create's restore finds at its path right
    /// before it writes or moves anything. `None` when the path holds S with the
    /// target digest (row C7); otherwise the hold reason of C7a (S′:
    /// `active_entry_modified`), C7b (no entry, or another one:
    /// `active_entry_replaced`), or `unobservable`.
    fn active_path_changed(
        &mut self,
        parent: &Path,
        name: &str,
        expected: &Expected,
    ) -> Option<HoldReason> {
        let Ok(Some(dir)) = self.dir(parent) else {
            return Some(HoldReason::Unobservable);
        };
        match replace::check_name(&dir, name, expected) {
            NameState::Expected(ContentState::Unchanged) => None,
            NameState::Expected(ContentState::Modified) => Some(HoldReason::ActiveEntryModified),
            NameState::Absent | NameState::Foreign => Some(HoldReason::ActiveEntryReplaced),
            NameState::Unobservable => Some(HoldReason::Unobservable),
        }
    }

    fn settled_outcome(
        &mut self,
        i: u16,
        outcome: SettleOutcome,
        expected: &Expected,
    ) -> Result<(), ReconcileError> {
        match outcome {
            SettleOutcome::Settled => {
                self.append_file(
                    i,
                    FilePhase::Settled {
                        disposition: SettledDisposition::Quarantined,
                    },
                )?;
                self.remove_slot(i)?;
            }
            SettleOutcome::Modified { slot } => {
                self.append_file(
                    i,
                    FilePhase::SettleConflict {
                        found: SettleConflictFound::Modified,
                        kept: vec![PreservedEntry {
                            name: slot,
                            identity: Some(expected.identity.clone()),
                        }],
                    },
                )?;
            }
            SettleOutcome::Missing => {
                self.append_file(
                    i,
                    FilePhase::SettleConflict {
                        found: SettleConflictFound::Missing,
                        kept: Vec::new(),
                    },
                )?;
            }
            SettleOutcome::ForeignPutBack { path } | SettleOutcome::ForeignKept { path } => {
                self.append_file(
                    i,
                    FilePhase::SettleConflict {
                        found: SettleConflictFound::Foreign,
                        kept: vec![PreservedEntry {
                            name: path,
                            identity: None,
                        }],
                    },
                )?;
            }
        }
        Ok(())
    }

    /// F9: remove the settled entry from its slot, re-checking identity and digest.
    fn remove_slot(&mut self, i: u16) -> Result<(), ReconcileError> {
        let step = self.step(i);
        let Some((_, _, expected, slot)) = self.settling(i) else {
            return Ok(());
        };
        let Some((parent, _)) = split(&step.path) else {
            return Ok(());
        };
        let quarantine = self.quarantine(&parent)?;
        self.config.fire(ReplacePoint::BeforeQuarantineRemove, i);
        let found = match quarantine.remove_verified_with(&slot, &expected, self.hook_at(i)) {
            Ok(RemoveVerified::Removed | RemoveVerified::Missing) => return Ok(()),
            Ok(RemoveVerified::Modified) => SettleConflictFound::Modified,
            Ok(RemoveVerified::Foreign) => SettleConflictFound::Foreign,
            Err(e) => return Err(ReconcileError::Unavailable(e.to_string())),
        };
        self.append_file(
            i,
            FilePhase::SettleConflict {
                found,
                kept: vec![PreservedEntry {
                    name: slot,
                    identity: None,
                }],
            },
        )
    }

    /// F8d: a foreign entry is in the slot: move it back to the source name with
    /// no-replace, or keep it under a conflict name; nothing is deleted.
    fn put_back(&mut self, i: u16) -> Result<(), ReconcileError> {
        let step = self.step(i);
        let (Some((_, name, expected, slot)), Some((parent, _))) =
            (self.settling(i), split(&step.path))
        else {
            return Ok(());
        };
        let dir = self
            .dir(&parent)
            .map_err(|e| ReconcileError::Unavailable(e.to_string()))?
            .ok_or_else(|| ReconcileError::Unavailable("directory missing".to_owned()))?;
        let quarantine = self.quarantine(&parent)?;
        let outcome = quarantine
            .put_back(&dir, &slot, &name)
            .map_err(|e| ReconcileError::Unavailable(e.to_string()))?;
        let kept = match outcome {
            SettleOutcome::ForeignPutBack { path } | SettleOutcome::ForeignKept { path } => path,
            _ => slot,
        };
        let _ = expected;
        self.append_file(
            i,
            FilePhase::SettleConflict {
                found: SettleConflictFound::Foreign,
                kept: vec![PreservedEntry {
                    name: kept,
                    identity: None,
                }],
            },
        )
    }

    // --- holds and outcomes ----------------------------------------------------------

    /// Outcome H for `item`: write `file.held` for each held step whose observation
    /// changed, and report the held steps. Moves nothing.
    fn hold(
        &mut self,
        item: ProjectionItem,
        views: &[View],
        extra: Option<(u16, HoldReason)>,
    ) -> Result<ItemOutcome, ReconcileError> {
        let mut held: Vec<(u16, HoldReason)> = views
            .iter()
            .filter_map(|v| match v.dec {
                StepDecision::Hold(r) => Some((v.step, r)),
                _ => None,
            })
            .collect();
        if let Some((s, r)) = extra
            && !held.iter().any(|(h, _)| *h == s)
        {
            held.push((s, r));
        }
        let mut steps = Vec::new();
        for (i, reason) in held {
            let Some(v) = views.iter().find(|v| v.step == i) else {
                continue;
            };
            let state = v.state.clone().unwrap_or_else(default_state);
            let fingerprint = self.fingerprint(i, &state);
            let observed = observed_names(&v.obs, &fingerprint);
            let (count, last, last_reason) = self.held_count(i);
            let changed = last != Some(&observed) || last_reason != Some(reason);
            if self.sink.is_some() && changed && count < MAX_HELD_RECEIPTS {
                self.append_file(
                    i,
                    FilePhase::Held {
                        reason,
                        observed: observed.clone(),
                    },
                )?;
            }
            let step = self.step(i);
            steps.push(HeldStep {
                step: i,
                role: step.role,
                path_display: step.path.clone(),
                reason,
                observed: v.obs,
                fingerprint,
            });
        }
        Ok(ItemOutcome::Held { item, steps })
    }

    /// The item's outcome. A reason recorded in `item.finished` is reported as it is,
    /// so a restart reports what the run that finished the item did (ADR-0007 §12.20
    /// item 2(b)); a receipt without one (stored before the field existed, or with no
    /// reason) falls back to this run's reason, or for a restore to the reason its
    /// receipts give.
    fn outcome_of(&self, item: ProjectionItem, finish: ItemFinish) -> ItemOutcome {
        let recorded = self.finished_reason(item);
        match finish {
            ItemFinish::Applied => ItemOutcome::Applied {
                item,
                generation: self
                    .committed_generation(item)
                    .unwrap_or(self.intent.generation),
            },
            ItemFinish::NotApplied => ItemOutcome::NotApplied {
                item,
                reason: recorded.or_else(|| self.reasons.get(&item).copied()),
            },
            ItemFinish::Restored => ItemOutcome::Restored {
                item,
                reason: recorded.or_else(|| self.restored_reason(item)),
            },
            ItemFinish::ConflictPreserved => ItemOutcome::ConflictPreserved { item },
        }
    }

    /// Why the item was restored: the transaction check's (`item.rolling_back`), this
    /// run's, or a recorded mismatch (`concurrent_writer`).
    fn restored_reason(&self, item: ProjectionItem) -> Option<ConflictKind> {
        let rolled = self.item_phases(item).find_map(|p| match p {
            ItemPhase::RollingBack { reason } => Some(*reason),
            _ => None,
        });
        let mismatch = self.steps_of(item).iter().any(|&i| {
            self.file_phases(i).any(|p| {
                matches!(
                    p,
                    FilePhase::PostValidated {
                        verdict: PostVerdict::Mismatch,
                        ..
                    }
                )
            })
        });
        rolled
            .or_else(|| self.reasons.get(&item).copied())
            .or(mismatch.then_some(ConflictKind::ConcurrentWriter))
    }

    /// `observe_held` for one item: the steps a restart would hold, observed
    /// passively.
    fn held_of(&mut self, item: ProjectionItem) -> Vec<HeldStep> {
        if self.finished(item).is_some() {
            return Vec::new();
        }
        let views: Vec<View> = self.steps_of(item).iter().map(|&i| self.view(i)).collect();
        let mut held: Vec<(u16, HoldReason)> = views
            .iter()
            .filter_map(|v| match v.dec {
                StepDecision::Hold(r) => Some((v.step, r)),
                _ => None,
            })
            .collect();
        if held.is_empty() {
            let at_t1 = self.commit_at_t1(&views);
            let states: Vec<StepState> = views.iter().map(|v| self.step_state(v, at_t1)).collect();
            if let ItemDecision::Hold(r) = recovery::decide_item(&states, &self.item_receipts(item))
            {
                let target = views
                    .iter()
                    .zip(&states)
                    .find(|(_, s)| matches!(s, StepState::ExchangedInconsistent))
                    .map(|(v, _)| v.step)
                    .or_else(|| self.commit_step(item));
                if let Some(t) = target {
                    held.push((t, r));
                }
            }
        }
        let mut out = Vec::new();
        for (i, reason) in held {
            let Some(v) = views.iter().find(|v| v.step == i) else {
                continue;
            };
            let state = v.state.clone().unwrap_or_else(default_state);
            let step = self.step(i);
            out.push(HeldStep {
                step: i,
                role: step.role,
                path_display: step.path.clone(),
                reason,
                observed: v.obs,
                fingerprint: self.fingerprint(i, &state),
            });
        }
        out
    }
}

fn restore_cause(state: &RecoveryState) -> RestoreCause {
    match state.restore {
        RestoreCtx::Due(c) | RestoreCtx::Started(c) | RestoreCtx::Done(c) => c,
        RestoreCtx::NotDue => RestoreCause::TransactionCheck,
    }
}

fn refusal_kind(step: &FileStep, r: &ReplaceRefusal) -> ConflictKind {
    match r {
        ReplaceRefusal::BaseChanged => changed_kind(step),
        _ => ConflictKind::UnmanageableFile,
    }
}

/// The identity-only record of what each name held (`file.held`; never content).
fn observed_names(obs: &StepObservation, fp: &StepFingerprint) -> Vec<ObservedName> {
    let identity = |e: Option<&EntryFingerprint>| match e {
        Some(EntryFingerprint::Present { identity, .. }) => Some(identity.clone()),
        _ => None,
    };
    let entry = |o: EntryObs, f: Option<&EntryFingerprint>| match o {
        EntryObs::Absent => ObservedEntry::Absent,
        EntryObs::Recorded { which, content } => ObservedEntry::Recorded { which, content },
        EntryObs::Foreign => ObservedEntry::Foreign {
            identity: identity(f),
        },
        EntryObs::Unobservable => ObservedEntry::Unobservable,
    };
    vec![
        ObservedName {
            name: ObservedNameRole::Path,
            entry: entry(obs.path(), Some(&fp.path)),
        },
        ObservedName {
            name: ObservedNameRole::Aside,
            entry: entry(
                obs.aside(),
                fp.aside
                    .iter()
                    .find(|e| matches!(e, EntryFingerprint::Present { .. })),
            ),
        },
        ObservedName {
            name: ObservedNameRole::Slot,
            entry: entry(obs.slot(), fp.slot.as_ref()),
        },
    ]
}

/// The `Host` names P renders (`Host <alias>` lines of Heimdall's own output).
pub(super) fn managed_aliases(p: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(p) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| l.strip_prefix("Host "))
        .map(|a| a.trim().to_owned())
        .filter(|a| !a.is_empty())
        .collect()
}

/// Whose directory a missing parent is, which decides its access when Heimdall creates
/// it (ADR-0007 §12.48 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirOwner {
    /// Heimdall's own: P's, the key files' and P_git's directories, under its
    /// configuration directory. Owner-only.
    Heimdall,
    /// The user's: `~/.ssh` (the user file) and the global Git file's directory (B_git
    /// and its lock). Windows: user, SYSTEM and Administrators (Win32-OpenSSH's rule).
    User,
}

impl DirOwner {
    fn of(role: FileRole) -> Self {
        match role {
            FileRole::UserSsh | FileRole::GitInclude | FileRole::GitLock => Self::User,
            FileRole::ManagedSsh | FileRole::Key | FileRole::GitManaged => Self::Heimdall,
        }
    }
}

/// Create `dir` and any missing parent. Unix: mode 0700 for every directory created,
/// whoever's it is. Windows: every created level gets its owner's protected DACL, set at
/// creation rather than inherited ([`DirOwner`]): owner-only for Heimdall's, as the
/// quarantine (`create_owner_only_dir`), and user, SYSTEM and Administrators for the
/// user's (`create_user_dir`). An existing level is left as it is. Creating a directory
/// removes nothing.
fn create_missing_dir(dir: &Path, owner: DirOwner) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let _ = owner;
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(dir).map_err(|e| format!("{:?}", e.kind()))
    }
    #[cfg(windows)]
    {
        let mut missing = Vec::new();
        let mut level = Some(dir);
        while let Some(d) = level {
            if std::fs::symlink_metadata(d).is_ok() {
                break;
            }
            missing.push(d);
            level = d.parent();
        }
        for d in missing.into_iter().rev() {
            match owner {
                DirOwner::Heimdall => fsentry::win::create_owner_only_dir(d),
                DirOwner::User => fsentry::win::create_user_dir(d),
            }
            .map_err(|e| format!("{:?}", e.kind()))?;
        }
        Ok(())
    }
}

/// The snapshot rules of ADR-0007 §12.35 item 2 that a fixture cannot build without
/// privileges (another owner), and the ones it can, on the metadata alone.
#[cfg(test)]
mod snapshot_rules {
    use super::{EntryMeta, Kind, is_valid_snapshot, private_directory_problem};
    use heimdall_domain::projection::FileIdentity;

    fn meta(kind: Kind, owned: bool, nlink: u64, perm: u32) -> EntryMeta {
        EntryMeta {
            identity: FileIdentity::Unix {
                dev: 1,
                ino: 1,
                birth: None,
            },
            kind,
            owned,
            nlink,
            len: 0,
            perm,
            changed_ns: 0,
        }
    }

    #[test]
    fn a_snapshot_is_a_regular_owned_single_link_file_of_mode_0600() {
        assert!(is_valid_snapshot(&meta(Kind::Regular, true, 1, 0o600)));
        for (label, m) in [
            ("a foreign owner", meta(Kind::Regular, false, 1, 0o600)),
            ("a directory", meta(Kind::Directory, true, 1, 0o600)),
            ("a link", meta(Kind::Symlink, true, 1, 0o600)),
            ("a FIFO or device", meta(Kind::Other, true, 1, 0o600)),
            ("a second link", meta(Kind::Regular, true, 2, 0o600)),
        ] {
            assert!(!is_valid_snapshot(&m), "{label}");
        }
    }

    /// Unix permission bits (Windows has an owner-only ACL check instead).
    #[cfg(unix)]
    #[test]
    fn a_snapshot_has_exactly_mode_0600() {
        for mode in [0o644, 0o640, 0o660, 0o666, 0o400, 0o700, 0o4600, 0o1600] {
            assert!(
                !is_valid_snapshot(&meta(Kind::Regular, true, 1, mode)),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn the_backups_directory_is_an_owned_directory() {
        assert_eq!(
            private_directory_problem(&meta(Kind::Directory, true, 2, 0o700)),
            None
        );
        for (label, m) in [
            ("a foreign owner", meta(Kind::Directory, false, 2, 0o700)),
            ("a regular file", meta(Kind::Regular, true, 1, 0o700)),
            ("a link", meta(Kind::Symlink, true, 1, 0o700)),
        ] {
            assert!(private_directory_problem(&m).is_some(), "{label}");
        }
    }

    /// Unix permission bits: group and others may read but not write.
    #[cfg(unix)]
    #[test]
    fn the_backups_directory_is_not_writable_by_group_or_others() {
        for ok in [0o700, 0o750, 0o755] {
            assert_eq!(
                private_directory_problem(&meta(Kind::Directory, true, 2, ok)),
                None,
                "{ok:o}"
            );
        }
        for bad in [0o770, 0o707, 0o777, 0o720, 0o702, 0o500, 0o000] {
            assert!(
                private_directory_problem(&meta(Kind::Directory, true, 2, bad)).is_some(),
                "{bad:o}"
            );
        }
    }
}
