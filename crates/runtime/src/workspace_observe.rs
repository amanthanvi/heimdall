//! Workspace observation by the runtime (M05 U4; ADR-0011 §2.2–§2.3, §3.2–§3.3; m05-plan U4).
//! Owner: the M05 track.
//!
//! * [`RealFs`]: `heimdall_project::FsView` over the real filesystem. Every method is one
//!   observation and none follows a last-component symbolic link except
//!   [`FsView::canonicalize`] (the platform's own canonicalization).
//! * [`RealWorkspaceProbe`]: the application's `ports::WorkspaceProbe`:
//!   `heimdall_project::observe_workspace` + `match_workspace`, mapped to a
//!   `ProbedWorkspace`. The runtime sets it on its `Operations` once
//!   (`Operations::set_workspace_probe`, in `service.rs`).
//!
//! **Reading the manifest** (ADR-0011 §2.2 "Reading"). The file is opened **without
//! following** a last-component symlink and **without blocking** on a FIFO (Unix:
//! `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`; Windows:
//! `FILE_FLAG_OPEN_REPARSE_POINT`), the opened handle's own metadata must say "regular
//! file" (Unix `fstat`; Windows `GetFileInformationByHandle`, a reparse point refused),
//! and at most `max + 1` bytes are read once from that same handle (`max + 1` detects
//! `TooLarge`). The bytes returned are the bytes the project crate hashes and parses, so
//! a concurrent writer can never make an observation's digest describe other bytes than
//! the ones parsed. A cheap `lstat` before the open refuses an entry that is plainly not a
//! regular file without opening it at all (no side effect of opening a device); the
//! handle check after the open is the authoritative one.
//!
//! **Identity** (ADR-0011 §2.3). Unix: `st_dev`, `st_ino` and, where the filesystem
//! records it, the birth time (so a directory re-created at the same path with a reused
//! inode number is still another identity). Windows: the volume serial number and the
//! 128-bit file ID of a handle opened on the entry itself
//! (`heimdall_localenv::sys::handle_identity`, the existing helper); a filesystem that
//! cannot report one has no stable identity (`None`, R6: refused, never approximated).
//!
//! The probe does file I/O only; the application calls it outside any store
//! transaction and re-checks what it relied on in its writing transaction.

use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use heimdall_app::ports::{ProbeError, ProbedManifest, ProbedWorkspace, WorkspaceProbe};
use heimdall_contract::ids::EnvironmentId;
use heimdall_domain::projection::FileIdentity;
use heimdall_domain::workspace::WorkspaceRecord;
use heimdall_project::{
    FsKind, FsView, GitObservation, ParsedManifest, ReadOutcome, match_workspace, observe_workspace,
};

/// [`FsView`] over the real filesystem (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

fn kind_of(t: std::fs::FileType) -> FsKind {
    if t.is_symlink() {
        FsKind::Symlink
    } else if t.is_dir() {
        FsKind::Dir
    } else if t.is_file() {
        FsKind::File
    } else {
        FsKind::Other
    }
}

impl FsView for RealFs {
    fn kind(&self, path: &Path) -> io::Result<Option<FsKind>> {
        match std::fs::symlink_metadata(path) {
            Ok(m) => Ok(Some(kind_of(m.file_type()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    fn identity(&self, path: &Path) -> io::Result<Option<FileIdentity>> {
        sys::identity(path)
    }

    fn read_regular_nofollow(&self, path: &Path, max: usize) -> io::Result<ReadOutcome> {
        // A cheap first look: an entry that is plainly not a regular file is refused
        // without being opened (no side effect of opening a device or a FIFO).
        match std::fs::symlink_metadata(path) {
            Ok(m) if !m.file_type().is_file() => return Ok(ReadOutcome::NotRegular),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
        let Some(file) = sys::open_regular_nofollow(path)? else {
            return Ok(ReadOutcome::NotRegular);
        };
        let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
        let mut bytes = Vec::new();
        (&file).take(limit).read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Ok(ReadOutcome::TooLarge);
        }
        Ok(ReadOutcome::Bytes(bytes))
    }
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;

    use heimdall_domain::projection::FileIdentity;

    /// Birth time in nanoseconds since the epoch, when the filesystem records one (a
    /// filesystem that reports none, or zero, has none: the identity is then
    /// device and inode only).
    fn birth_of(m: &std::fs::Metadata) -> Option<i128> {
        let t = m.created().ok()?;
        let ns = match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i128::try_from(d.as_nanos()).ok()?,
            Err(e) => -i128::try_from(e.duration().as_nanos()).ok()?,
        };
        (ns > 0).then_some(ns)
    }

    pub(super) fn identity(path: &Path) -> io::Result<Option<FileIdentity>> {
        let m = std::fs::symlink_metadata(path)?;
        Ok(Some(FileIdentity::Unix {
            dev: m.dev(),
            ino: m.ino(),
            birth: birth_of(&m),
        }))
    }

    /// Open `path` read-only without following a last-component symlink and without
    /// blocking on a FIFO; `None` when the opened entry (by `fstat` on the handle) is
    /// not a regular file, or the last component is a symlink.
    pub(super) fn open_regular_nofollow(path: &Path) -> io::Result<Option<std::fs::File>> {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => f,
            // A symlink on the last component: ELOOP (Linux, macOS), EMLINK (FreeBSD).
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::EMLINK)) => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if !file.metadata()?.file_type().is_file() {
            return Ok(None);
        }
        Ok(Some(file))
    }
}

#[cfg(windows)]
mod sys {
    use std::io;
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;

    use heimdall_domain::projection::FileIdentity;

    /// `FILE_FLAG_BACKUP_SEMANTICS`: needed to open a directory handle.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// `FILE_FLAG_OPEN_REPARSE_POINT`: open the reparse point itself, never its target.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    /// `FILE_READ_ATTRIBUTES`.
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    /// `GENERIC_READ`.
    const GENERIC_READ: u32 = 0x8000_0000;
    /// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`: observing never blocks
    /// another writer.
    const FILE_SHARE_ALL: u32 = 0x7;

    fn open_nofollow(path: &Path, access: u32) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub(super) fn identity(path: &Path) -> io::Result<Option<FileIdentity>> {
        let f = open_nofollow(path, FILE_READ_ATTRIBUTES)?;
        // A filesystem that cannot report a file ID has no stable identity (R6).
        Ok(heimdall_localenv::sys::handle_identity(&f).ok())
    }

    /// Open `path` for reading on the entry itself (a reparse point is never
    /// followed); `None` when the handle's own information says reparse point, or
    /// anything but a regular file.
    pub(super) fn open_regular_nofollow(path: &Path) -> io::Result<Option<std::fs::File>> {
        let f = open_nofollow(path, GENERIC_READ)?;
        let m = f.metadata()?;
        if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !m.file_type().is_file() {
            return Ok(None);
        }
        Ok(Some(f))
    }
}

#[cfg(not(any(unix, windows)))]
mod sys {
    use std::io;
    use std::path::Path;

    use heimdall_domain::projection::FileIdentity;

    pub(super) fn identity(_path: &Path) -> io::Result<Option<FileIdentity>> {
        Ok(None)
    }

    pub(super) fn open_regular_nofollow(_path: &Path) -> io::Result<Option<std::fs::File>> {
        Ok(None)
    }
}

/// The application's view of a validated manifest: request data only, the label already
/// stripped of control characters (ADR-0011 I5).
fn probed_manifest(p: &ParsedManifest) -> ProbedManifest {
    ProbedManifest {
        access_digest: p.access_digest.clone(),
        profile: p.manifest.access.profile.clone(),
        pairs: p
            .pairs
            .iter()
            .map(|pair| format!("{}:{}", pair.destination, pair.account))
            .collect(),
        environments: p.environments.clone(),
        capabilities: p
            .capabilities
            .iter()
            .filter_map(|c| match serde_json::to_value(c) {
                Ok(serde_json::Value::String(s)) => Some(s),
                _ => None,
            })
            .collect(),
        background_work: p.background_work,
        project_label: p.label_for_display(),
    }
}

/// Observe `cwd` in `environment`'s path namespace through `fs` and match it against
/// `records` (the probe's body, over any [`FsView`]).
///
/// # Errors
/// [`ProbeError::Manifest`] for a refused manifest (`manifest_invalid` for one that is
/// not a regular file, or `manifest_invalid` / `manifest_authority_key` from the
/// parser); [`ProbeError::Io`] for an unusable working directory or a filesystem error.
pub fn probe_with(
    fs: &dyn FsView,
    environment: &EnvironmentId,
    cwd: &str,
    records: &[WorkspaceRecord],
) -> Result<ProbedWorkspace, ProbeError> {
    let obs = match observe_workspace(fs, environment, cwd) {
        Ok(Some(obs)) => obs,
        Ok(None) => {
            return Ok(ProbedWorkspace {
                root: None,
                root_identity: None,
                git_common_identity: None,
                matched: None,
                manifest: None,
            });
        }
        Err(e) => {
            return Err(match e.manifest_reason() {
                Some(reason) => ProbeError::Manifest { reason },
                None => ProbeError::Io,
            });
        }
    };
    let manifest = match &obs.manifest {
        None => None,
        Some(Err(e)) => return Err(ProbeError::Manifest { reason: e.reason() }),
        Some(Ok(parsed)) => Some(probed_manifest(parsed)),
    };
    let git_common_identity = match &obs.git {
        Some(GitObservation::Checkout { common_identity }) => common_identity.clone(),
        Some(GitObservation::LinkedWorktree {
            common_identity,
            verified: true,
            ..
        }) => common_identity.clone(),
        _ => None,
    };
    let matched = match_workspace(&obs, records);
    Ok(ProbedWorkspace {
        root: Some(obs.root),
        root_identity: obs.root_identity,
        git_common_identity,
        matched: Some(matched),
        manifest,
    })
}

/// The runtime's `WorkspaceProbe`: [`probe_with`] over [`RealFs`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RealWorkspaceProbe;

impl WorkspaceProbe for RealWorkspaceProbe {
    fn probe(
        &self,
        environment: &EnvironmentId,
        cwd: &str,
        records: &[WorkspaceRecord],
    ) -> Result<ProbedWorkspace, ProbeError> {
        probe_with(&RealFs, environment, cwd, records)
    }
}
