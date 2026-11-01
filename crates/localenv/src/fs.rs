//! The real-filesystem configuration source (m02-plan U3).
//!
//! Non-blocking open, then `fstat`: regular files only (a FIFO include never blocks,
//! `a21_fifo_include_does_not_block`); symlinks followed as OpenSSH does; the bounds of
//! `heimdall_sshconf::limits::Limits`.

use std::path::{Path, PathBuf};

use heimdall_sshconf::include::{ConfigSource, SourceBytes, SourceError};
use heimdall_sshconf::limits::Limits;

use crate::env::Env;
use crate::paths::SshPaths;

/// Bounded, read-only access to the real configuration tree.
#[derive(Debug, Clone)]
pub struct BoundedSource {
    paths: SshPaths,
    env: Env,
    limits: Limits,
}

impl BoundedSource {
    /// A source over `paths`, expanding `${VAR}` from `env`.
    #[must_use]
    pub fn new(paths: SshPaths, env: Env, limits: Limits) -> Self {
        Self { paths, env, limits }
    }

    /// The bounds in force.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

impl ConfigSource for BoundedSource {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        let _ = path;
        todo!("M02-U3 fs::BoundedSource::read")
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        let _ = pattern;
        todo!("M02-U3 fs::BoundedSource::glob")
    }

    fn account_home(&self) -> &Path {
        &self.paths.account_home
    }

    fn user_dir(&self) -> &Path {
        &self.paths.user_dir
    }

    fn system_dir(&self) -> &Path {
        &self.paths.system_dir
    }

    fn env(&self, name: &str) -> Option<String> {
        self.env
            .get(name)
            .and_then(|v| v.to_str())
            .map(str::to_owned)
    }
}
