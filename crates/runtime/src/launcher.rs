//! On-demand service start from a client (spec §13.1 "On-demand service startup
//! must be single-instance and must not create a new broad agent on every
//! invocation"; overview §4.2).
//!
//! 1. Read and validate `instance.json`; try to connect to the control endpoint.
//! 2. If absent or dead: take a short-lived `start.lock` (same `File::try_lock`
//!    mechanism) so concurrent clients start at most one service; spawn
//!    `heimdall service run --detach` (same executable path as this process,
//!    resolved once, never from `PATH`), stdio detached, no shell.
//! 3. Wait with bounded backoff for the advertisement; give up with
//!    `SERVICE_UNAVAILABLE` after `start_timeout`.
//!
//! Pure inspection commands never trigger a start (spec §13.1).

use std::path::Path;
use std::time::Duration;

/// Launcher tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LauncherConfig {
    /// Total time to wait for a started service to advertise.
    pub start_timeout: Duration,
    /// First poll interval (doubles, capped at 500 ms).
    pub initial_poll: Duration,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        Self {
            start_timeout: Duration::from_secs(10),
            initial_poll: Duration::from_millis(25),
        }
    }
}

/// Outcome of `ensure_running`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// An instance was already serving.
    AlreadyRunning,
    /// This call started it.
    StartedNow,
}

/// Launcher errors (mapped to `SERVICE_UNAVAILABLE`).
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// Could not spawn.
    #[error("could not start the runtime: {0}")]
    Spawn(std::io::Error),
    /// Started but never advertised.
    #[error("runtime did not become ready within the timeout")]
    Timeout,
    /// Paths unavailable.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
}

/// Ensure a service is running for `paths`, starting one if allowed.
pub async fn ensure_running(
    _paths: &Path,
    _allow_start: bool,
    _config: LauncherConfig,
) -> Result<Started, LaunchError> {
    todo!("M01-T05")
}
