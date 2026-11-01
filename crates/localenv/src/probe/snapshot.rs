//! Configuration-tree snapshots around a level (m02-plan U3; M2-S04).
//!
//! [`take`] runs once with the static pass and once after the level. A snapshot holds
//! every `Include`'s expansion result and every reached file's display path and
//! digest, so a new glob member is detected. `config_tree_changed` is
//! `!compare(..).is_empty()`; `false` means only that the two snapshots are equal (a
//! change reverted in between is not detected).

use heimdall_contract::doctor::ConfigTreeDifference;
use heimdall_sshconf::eval::Query;
use heimdall_sshconf::include::{ConfigSource, Roots};
use heimdall_sshconf::limits::Limits;

/// How one `Include` expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeExpansion {
    /// The glob's matches, in order (display form).
    Matches(Vec<String>),
    /// The resolved path of a literal include (display form).
    Resolved(String),
    /// Why it could not resolve (a stable reason).
    Unresolved(String),
}

/// One reached file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachedFile {
    /// Display path.
    pub path_display: String,
    /// SHA-256, or `None` when unreadable.
    pub sha256: Option<String>,
}

/// The tree as one walk saw it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TreeSnapshot {
    /// Every include, in walk order, with its expansion.
    pub includes: Vec<(String, IncludeExpansion)>,
    /// Every reached file.
    pub files: Vec<ReachedFile>,
}

/// Walk the tree for `query` and record it.
#[must_use]
pub fn take(
    source: &dyn ConfigSource,
    roots: &Roots,
    query: &Query,
    limits: &Limits,
) -> TreeSnapshot {
    let _ = (source, roots, query, limits);
    todo!("M02-U3 probe::snapshot::take")
}

/// The differences between two snapshots (at most 256 reported).
#[must_use]
pub fn compare(before: &TreeSnapshot, after: &TreeSnapshot) -> Vec<ConfigTreeDifference> {
    let _ = (before, after);
    todo!("M02-U3 probe::snapshot::compare")
}
