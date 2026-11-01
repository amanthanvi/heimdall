//! The include loader and the read-only source port (m02-plan U1; ADR-0007 F3, F6,
//! F19).
//!
//! [`ConfigSource`] is the only way this crate reads anything. It has no method that
//! runs a command, and none is ever added: the `Match exec` tests use a fake that would
//! panic if asked (m02-plan U2). The real implementation is
//! `heimdall_localenv::fs::BoundedSource` (U3).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::limits::Limits;
use crate::parse::{ConfigFile, SourceId};

/// Bytes read from one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBytes {
    /// The canonical path the bytes came from (the cache key).
    pub canonical: PathBuf,
    /// The file's bytes, at most `Limits::file_bytes`.
    pub bytes: Vec<u8>,
}

/// Why a source could not be read. Recorded as `IncludeUnreadable` or
/// `BoundExceeded`; never treated as an empty file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// No such file.
    #[error("not found")]
    NotFound,
    /// Not a regular file (a FIFO, a device, a directory).
    #[error("not a regular file")]
    NotRegular,
    /// Permission denied.
    #[error("permission denied")]
    PermissionDenied,
    /// Larger than the bound, or a glob with more results than the bound.
    #[error("bound exceeded")]
    BoundExceeded,
    /// Another I/O failure (redacted kind only).
    #[error("read failed: {0}")]
    Io(String),
}

/// Read-only access to configuration files and the facts OpenSSH expands.
pub trait ConfigSource {
    /// Read one file, following symlinks as OpenSSH does, regular files only.
    ///
    /// # Errors
    /// [`SourceError`].
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError>;
    /// Expand one `Include` pattern; results in bytewise order.
    ///
    /// # Errors
    /// [`SourceError`].
    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError>;
    /// The account's home directory (from the account database, never `$HOME`;
    /// ADR-0007 F19).
    fn account_home(&self) -> &Path;
    /// The user configuration directory (`~/.ssh`).
    fn user_dir(&self) -> &Path;
    /// The system configuration directory (`/etc/ssh`, `%PROGRAMDATA%\ssh`).
    fn system_dir(&self) -> &Path;
    /// An environment variable, for `${VAR}` expansion (F7). `None` when unset.
    fn env(&self, name: &str) -> Option<String>;
}

/// The user and system configuration files an evaluation starts from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roots {
    /// The user file (`~/.ssh/config`, or `-F`), when present.
    pub user: Option<PathBuf>,
    /// The system file, when read (a `-F` file drops it, F6).
    pub system: Option<PathBuf>,
}

/// Why an include could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IncludeError {
    /// The source refused the read.
    #[error("include unreadable: {0}")]
    Unreadable(SourceError),
    /// A bound of [`Limits`] was exceeded.
    #[error("include bound exceeded")]
    BoundExceeded,
    /// The file includes itself, directly or not.
    #[error("include cycle")]
    Cycle,
    /// The file parsed with an error.
    #[error("include did not parse: {0}")]
    Parse(crate::parse::ParseError),
}

/// A cache of parsed files keyed by canonical path, shared by every evaluation of one
/// configuration tree.
#[derive(Debug, Clone, Default)]
pub struct ConfigSet {
    files: BTreeMap<PathBuf, ConfigFile>,
    next: u32,
}

impl ConfigSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of files loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether nothing is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// A loaded file by canonical path.
    #[must_use]
    pub fn get(&self, canonical: &Path) -> Option<&ConfigFile> {
        self.files.get(canonical)
    }

    /// The next unused [`SourceId`] (each loaded file gets one).
    pub fn next_source_id(&mut self) -> SourceId {
        let id = SourceId(self.next);
        self.next = self.next.saturating_add(1);
        id
    }

    /// Load and parse `path` through `source`, or return the cached copy.
    ///
    /// # Errors
    /// [`IncludeError`].
    pub fn load(
        &mut self,
        source: &dyn ConfigSource,
        path: &Path,
        limits: &Limits,
    ) -> Result<&ConfigFile, IncludeError> {
        let _ = (source, path, limits);
        todo!("M02-U1 include::ConfigSet::load")
    }
}
