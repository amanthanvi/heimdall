//! Local queries: bounded runs of a local tool for a version or a lookup (m02-plan U3,
//! Q4). Each is bounded at 2 s, runs with stdin null and no shell, and never modifies
//! the environment. `--no-local-exec` turns them off (`LocalQueries::Disabled`).

use std::path::Path;
use std::time::Duration;

use heimdall_sshconf::eval::OpenSshVersion;

/// The bound on one local query.
pub const LOCAL_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether local queries may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalQueries {
    /// Allowed (the default; listed in the report).
    Enabled,
    /// Off (`--no-local-exec`).
    Disabled,
}

/// A local query that did not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LocalQueryError {
    /// Local queries are disabled.
    #[error("local queries disabled")]
    Disabled,
    /// The tool did not answer within the bound.
    #[error("local query timed out")]
    Timeout,
    /// The tool could not be started.
    #[error("local query could not start")]
    Spawn,
    /// The output was not understood.
    #[error("local query output not understood")]
    Unparsed,
}

/// Run `<client> -V` and parse its version.
///
/// # Errors
/// [`LocalQueryError`].
pub fn run_version(client: &Path) -> Result<OpenSshVersion, LocalQueryError> {
    let _ = client;
    todo!("M02-U3 local_query::run_version")
}
