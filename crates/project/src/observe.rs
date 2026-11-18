//! Workspace discovery and observation over the [`FsView`] seam (ADR-0011 §2.2 Discovery,
//! §2.3, §10 item 7).
//!
//! The runtime implements [`FsView`] over the real filesystem (no-follow opens, native file
//! identities); the tests implement it in memory. This module holds the walk and every
//! decision, so there is one implementation of each.
//!
//! **Discovery.** Canonicalize the working directory, then walk up. The first directory
//! holding `.heimdall.toml` (any kind of entry) or `.git` (any kind of entry; a directory or
//! a file in practice) is the root. The walk never goes past a `.git`, so a submodule or a
//! nested repository is its own workspace, and it never descends, so trust is not
//! recursive (spec §5.3). The filesystem root with neither is personal context (`None`).
//!
//! **Reading.** The manifest is read exactly once, through
//! [`FsView::read_regular_nofollow`]; the bytes hashed are the bytes parsed.
//!
//! **Linked worktrees** are verified by resolving paths and comparing identities, never by
//! looking at the text of a `gitdir` line (ruling §10 item 7): see [`verify_linked_worktree`].

use std::io;
use std::path::{Path, PathBuf};

use heimdall_contract::envelope::reason::MANIFEST_INVALID;
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::project::MAX_MANIFEST_BYTES;
use heimdall_domain::projection::FileIdentity;

use crate::manifest::{InvalidReason, ManifestError, ParsedManifest, parse_manifest};

/// The manifest's file name.
pub const MANIFEST_NAME: &str = ".heimdall.toml";
/// Git's marker entry.
const GIT_NAME: &str = ".git";
/// The most bytes read from a `.git` pointer file or a worktree back-link file.
const MAX_GIT_POINTER_BYTES: usize = 4096;

/// What a directory entry is (an `lstat`: the entry itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A symbolic link (never followed by `kind`).
    Symlink,
    /// A FIFO, device, socket or anything else.
    Other,
}

/// The result of a bounded no-follow read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    /// The whole file (at most `max` bytes).
    Bytes(Vec<u8>),
    /// Not a regular file (a symlink on the last component, a FIFO, a device, a directory).
    NotRegular,
    /// More than `max` bytes.
    TooLarge,
}

/// The filesystem as this crate sees it. Implemented by the runtime (real filesystem) and by
/// tests (in memory). Every method is a single observation; none may follow a symlink on the
/// last component except [`FsView::canonicalize`].
pub trait FsView {
    /// `lstat`: the entry itself, never following a last-component symlink. `Ok(None)` is
    /// absent.
    fn kind(&self, path: &Path) -> io::Result<Option<FsKind>>;
    /// Resolve every symlink and `..`; an error when the path is absent.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    /// The file identity of the entry (no-follow). `Ok(None)`: this filesystem has no stable
    /// identity.
    fn identity(&self, path: &Path) -> io::Result<Option<FileIdentity>>;
    /// Open without following a last-component symlink; refuse anything but a regular file
    /// ([`ReadOutcome::NotRegular`]); read at most `max` bytes once, from that same handle
    /// ([`ReadOutcome::TooLarge`] beyond).
    fn read_regular_nofollow(&self, path: &Path, max: usize) -> io::Result<ReadOutcome>;
}

/// What was observed about Git at the root (descriptive; only identities decide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitObservation {
    /// `root/.git` is a directory: this root is a checkout and `.git` is its common
    /// directory.
    Checkout {
        /// The `.git` directory's identity (`None`: the filesystem has none).
        common_identity: Option<FileIdentity>,
    },
    /// `root/.git` is a file (a linked worktree or a submodule).
    LinkedWorktree {
        /// The common directory's canonical path. `Some` only when `verified`.
        common: Option<String>,
        /// The common directory's identity. `Some` only when `verified` and the filesystem
        /// has one.
        common_identity: Option<FileIdentity>,
        /// Whether the whole chain checked out: the pointer resolves to `<common>/worktrees/<n>`
        /// and that entry's back-link names this root's `.git` file (path and identity). Any
        /// malformed, missing or mismatching step is `false`, not an error.
        verified: bool,
    },
}

/// What discovery found at a workspace root.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceObservation {
    /// The environment whose path namespace `root` is in.
    pub environment: EnvironmentId,
    /// The canonical root path.
    pub root: String,
    /// The root directory's identity; `None` is kept as `None` (R6: never approximated).
    pub root_identity: Option<FileIdentity>,
    /// Git, when the root has a `.git` directory or file.
    pub git: Option<GitObservation>,
    /// The manifest read from the root, when there is one: the parse result of exactly the
    /// bytes read.
    pub manifest: Option<Result<ParsedManifest, ManifestError>>,
}

/// Why observation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObserveError {
    /// The working directory is empty, contains NUL, or is not a directory.
    #[error("the working directory is not a usable directory path")]
    BadCwd,
    /// A filesystem error (only the kind is kept: messages may name repository paths).
    #[error("filesystem error ({0:?})")]
    Io(io::ErrorKind),
    /// The canonical root is not valid UTF-8, so it cannot be recorded.
    #[error("the workspace root is not valid UTF-8")]
    RootNotUtf8,
    /// `.heimdall.toml` is a symlink, FIFO, device or directory.
    #[error("the manifest is not a regular file")]
    ManifestNotRegular,
}

impl ObserveError {
    /// The stable reason when this failure is about the manifest (`manifest_invalid`).
    #[must_use]
    pub fn manifest_reason(&self) -> Option<&'static str> {
        matches!(self, Self::ManifestNotRegular).then_some(MANIFEST_INVALID)
    }
}

fn io_err(e: &io::Error) -> ObserveError {
    ObserveError::Io(e.kind())
}

/// Discover and observe the workspace containing `cwd` in `environment`'s path namespace.
/// `Ok(None)` is personal context (no manifest and no `.git` between `cwd` and the
/// filesystem root).
pub fn observe_workspace(
    fs: &dyn FsView,
    environment: &EnvironmentId,
    cwd: &str,
) -> Result<Option<WorkspaceObservation>, ObserveError> {
    if cwd.is_empty() || cwd.contains('\0') {
        return Err(ObserveError::BadCwd);
    }
    let start = fs.canonicalize(Path::new(cwd)).map_err(|e| io_err(&e))?;
    if fs.kind(&start).map_err(|e| io_err(&e))? != Some(FsKind::Dir) {
        return Err(ObserveError::BadCwd);
    }

    let mut dir: &Path = &start;
    let (root, has_manifest, git_kind) = loop {
        let manifest = fs
            .kind(&dir.join(MANIFEST_NAME))
            .map_err(|e| io_err(&e))?
            .is_some();
        let git = fs.kind(&dir.join(GIT_NAME)).map_err(|e| io_err(&e))?;
        if manifest || git.is_some() {
            break (dir, manifest, git);
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => return Ok(None),
        }
    };

    let root_str = root.to_str().ok_or(ObserveError::RootNotUtf8)?.to_owned();
    let root_identity = fs.identity(root).map_err(|e| io_err(&e))?;

    let manifest = if has_manifest {
        match fs
            .read_regular_nofollow(&root.join(MANIFEST_NAME), MAX_MANIFEST_BYTES)
            .map_err(|e| io_err(&e))?
        {
            ReadOutcome::Bytes(bytes) => Some(parse_manifest(&bytes)),
            ReadOutcome::TooLarge => Some(Err(ManifestError::Invalid(InvalidReason::TooLarge))),
            ReadOutcome::NotRegular => return Err(ObserveError::ManifestNotRegular),
        }
    } else {
        None
    };

    let git = match git_kind {
        Some(FsKind::Dir) => Some(GitObservation::Checkout {
            common_identity: fs.identity(&root.join(GIT_NAME)).map_err(|e| io_err(&e))?,
        }),
        Some(FsKind::File) => Some(match verify_linked_worktree(fs, root) {
            Some((common, common_identity)) => GitObservation::LinkedWorktree {
                common: Some(common),
                common_identity,
                verified: true,
            },
            None => GitObservation::LinkedWorktree {
                common: None,
                common_identity: None,
                verified: false,
            },
        }),
        // A `.git` that is a symlink or something else still ends the walk (never cross a
        // `.git` boundary) but carries no Git observation.
        _ => None,
    };

    Ok(Some(WorkspaceObservation {
        environment: environment.clone(),
        root: root_str,
        root_identity,
        git,
        manifest,
    }))
}

/// Resolve a pointer's text against `base` when it is relative.
fn resolve(base: &Path, text: &str) -> PathBuf {
    let path = Path::new(text);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Read a one-line pointer file (bounded, no-follow) and return its path text, without the
/// trailing newline. `prefix` is stripped when given (`gitdir: `).
fn read_pointer(fs: &dyn FsView, file: &Path, prefix: Option<&str>) -> Option<String> {
    let ReadOutcome::Bytes(bytes) = fs.read_regular_nofollow(file, MAX_GIT_POINTER_BYTES).ok()?
    else {
        return None;
    };
    let text = String::from_utf8(bytes).ok()?;
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if line.contains(['\n', '\r', '\0']) {
        return None;
    }
    let path = match prefix {
        Some(p) => line.strip_prefix(p)?,
        None => line,
    };
    (!path.is_empty()).then(|| path.to_owned())
}

/// Verify that `root/.git` (a file) names a linked worktree of a common directory whose
/// back-link names this very file. Returns the common directory's canonical path and
/// identity on success, `None` on any malformed, missing or mismatching step.
///
/// 1. `root/.git` holds one `gitdir: <path>` line; a relative path is resolved against the
///    root; the result is **canonicalized** (this resolves `..` and symlinks, so no text
///    prefix of the line is ever trusted);
/// 2. that entry is a directory whose parent directory is named `worktrees`; the common
///    directory is the parent's parent (a submodule's `.git/modules/<n>` fails here);
/// 3. `<entry>/gitdir` (bounded, no-follow) holds the worktree's `.git` path; resolved
///    (relative against the entry) and canonicalized, it must equal the canonical path of
///    this root's `.git` file **and** have the same file identity (a copied worktree's
///    back-link still names the original).
fn verify_linked_worktree(fs: &dyn FsView, root: &Path) -> Option<(String, Option<FileIdentity>)> {
    let dot_git = root.join(GIT_NAME);
    let pointer = read_pointer(fs, &dot_git, Some("gitdir: "))?;
    let entry = fs.canonicalize(&resolve(root, &pointer)).ok()?;
    if fs.kind(&entry).ok()? != Some(FsKind::Dir) {
        return None;
    }
    let worktrees = entry.parent()?;
    if worktrees.file_name()? != "worktrees" {
        return None;
    }
    let common = worktrees.parent()?;
    if fs.kind(common).ok()? != Some(FsKind::Dir) {
        return None;
    }

    let backlink_text = read_pointer(fs, &entry.join("gitdir"), None)?;
    let backlink = fs.canonicalize(&resolve(&entry, &backlink_text)).ok()?;
    let own = fs.canonicalize(&dot_git).ok()?;
    if backlink != own {
        return None;
    }
    let backlink_identity = fs.identity(&backlink).ok()??;
    let own_identity = fs.identity(&dot_git).ok()??;
    if !backlink_identity.same_file(&own_identity) {
        return None;
    }

    let common_identity = fs.identity(common).ok()?;
    Some((common.to_str()?.to_owned(), common_identity))
}
