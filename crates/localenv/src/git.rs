//! Git observation (m02-plan U3; ADR-0007 §5.6, §8, F22).
//!
//! A configuration value never leaves these functions: they return scope, origin, a
//! value digest and a classification. Queries run with `--includes`, and the include
//! graph of the system file and both global files is walked with
//! `heimdall_sshconf::gitedit::scan` (bounded: 1 MiB per file, 64 files, depth 10).

use std::path::{Path, PathBuf};

use heimdall_contract::doctor::{GitSshSelection, GitValueObservation};
use heimdall_contract::setup::{GitFileResolution, GitGlobalFileKind};

use crate::clients::ClientInventory;
use crate::env::Env;
use crate::local_query::LocalQueries;

/// Bytes read per Git configuration file during the include walk.
pub const GIT_WALK_FILE_BYTES: usize = 1 << 20;
/// Files read by one include walk.
pub const GIT_WALK_FILES: usize = 64;
/// Include depth of one walk.
pub const GIT_WALK_DEPTH: usize = 10;

/// The global file B_git goes into, under the first-read rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalFileResolution {
    /// The file.
    pub path: PathBuf,
    /// Which of the two global files.
    pub file: GitGlobalFileKind,
    /// How it was chosen.
    pub rule: GitFileResolution,
}

/// Git's default SSH program on this platform, when nothing overrides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultGitSsh {
    /// `ssh` from `PATH`.
    PathSsh,
    /// Git for Windows' bundled MSYS ssh.
    BundledMsys(PathBuf),
    /// Not established (no Git, or local queries off).
    Undetermined,
}

/// What the global Git configuration says about `core.sshCommand`, by digest only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitGlobalObservation {
    /// The global file B_git would go into (`None` when `GIT_CONFIG_GLOBAL`
    /// redirects it: manual mode, `git_global_redirected`).
    pub file: Option<GlobalFileResolution>,
    /// Every `core.sshCommand` occurrence in the system and global scopes, includes
    /// and conditional includes counted.
    pub values: Vec<GitValueObservation>,
    /// The overriding variables that are set (`GIT_SSH_COMMAND`, `GIT_SSH`,
    /// `GIT_CONFIG_GLOBAL` …); names only.
    pub env_overrides: Vec<&'static str>,
    /// Git's default SSH program.
    pub default_ssh: DefaultGitSsh,
    /// Files the walk could not read (display form); the item is then
    /// `not_applicable` (`git_config_unreadable`).
    pub unreadable: Vec<String>,
}

/// Observe the system and global Git configuration.
#[must_use]
pub fn observe_global(
    env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
) -> GitGlobalObservation {
    let _ = (env, clients, queries);
    todo!("M02-U3 git::observe_global")
}

/// Resolve Git's effective SSH selection in the child's working directory with the
/// child's environment (ADR-0007 §8). The value is classified in memory and dropped.
#[must_use]
pub fn resolve_run_selection(
    cwd: &Path,
    child_env: &Env,
    clients: &ClientInventory,
    queries: LocalQueries,
) -> GitSshSelection {
    let _ = (cwd, child_env, clients, queries);
    todo!("M02-U3 git::resolve_run_selection")
}
