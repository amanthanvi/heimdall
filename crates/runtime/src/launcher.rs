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
//!
//! **Single child.** Only the holder of `start.lock` spawns, and it re-validates
//! the advertisement after taking the lock, so a client that lost the race to an
//! already-started service never spawns a second one. Clients that cannot take
//! the lock wait for the advertisement (or for the lock to free up) within the
//! same timeout. Even if two services were spawned, the instance lock lets only
//! one run (the other exits with `AlreadyRunning`).
//!
//! The spawn step is injectable ([`ensure_running_with`]) so tests can count
//! children and start a test-owned service process; [`ensure_running`] spawns this
//! executable.

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use crate::instance::InstanceInfo;

/// File name of the start lock inside the runtime directory.
pub const START_LOCK_FILE: &str = "start.lock";

/// Arguments the launcher passes to its own executable.
pub const SERVICE_ARGS: [&str; 3] = ["service", "run", "--detach"];

/// Upper bound of the poll interval.
const MAX_POLL: Duration = Duration::from_millis(500);

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
    /// No runtime is serving and the caller did not allow a start (pure
    /// inspection, spec §13.1).
    #[error("no runtime is running")]
    NotRunning,
    /// The advertisement is not a private file owned by this user (planted or
    /// tampered): it is neither trusted nor replaced, and nothing is started.
    #[error("runtime advertisement is not trusted: {0}")]
    Insecure(std::io::Error),
    /// The start lock could not be opened.
    #[error("start lock unavailable: {0}")]
    Io(std::io::Error),
}

/// Ensure a service is running for the runtime directory `paths`
/// (`Paths::runtime_dir`, which holds `instance.json`, the endpoints and
/// `start.lock`), starting one if allowed by spawning this executable with
/// [`SERVICE_ARGS`].
pub async fn ensure_running(
    paths: &Path,
    allow_start: bool,
    config: LauncherConfig,
) -> Result<Started, LaunchError> {
    let exe = std::env::current_exe().map_err(LaunchError::Spawn)?;
    let spawn = move || {
        let args: Vec<&OsStr> = SERVICE_ARGS.iter().map(OsStr::new).collect();
        spawn_detached(&exe, &args).map(drop)
    };
    ensure_running_with(paths, allow_start, config, &spawn).await
}

/// [`ensure_running`] with an injected spawn step (called at most once per call,
/// only while holding `start.lock`).
pub async fn ensure_running_with(
    runtime_dir: &Path,
    allow_start: bool,
    config: LauncherConfig,
    spawn: &(dyn Fn() -> std::io::Result<()> + Send + Sync),
) -> Result<Started, LaunchError> {
    if serving(runtime_dir)? {
        return Ok(Started::AlreadyRunning);
    }
    if !allow_start {
        return Err(LaunchError::NotRunning);
    }
    let deadline = tokio::time::Instant::now() + config.start_timeout;
    let mut poll = config.initial_poll.max(Duration::from_millis(1));
    let lock_path = runtime_dir.join(START_LOCK_FILE);
    loop {
        if let Some(_guard) = try_start_lock(&lock_path)? {
            // Re-check under the lock: another client may have finished starting.
            if serving(runtime_dir)? {
                return Ok(Started::AlreadyRunning);
            }
            spawn().map_err(LaunchError::Spawn)?;
            // Hold the lock until the advertisement appears (or the timeout).
            loop {
                if serving(runtime_dir)? {
                    return Ok(Started::StartedNow);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(LaunchError::Timeout);
                }
                tokio::time::sleep(poll).await;
                poll = (poll * 2).min(MAX_POLL);
            }
        }
        // Another client is starting the runtime: wait for it.
        if serving(runtime_dir)? {
            return Ok(Started::AlreadyRunning);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(LaunchError::Timeout);
        }
        tokio::time::sleep(poll).await;
        poll = (poll * 2).min(MAX_POLL);
    }
}

/// Spawn `program args…` detached from this client: no shell, no `PATH` lookup
/// (callers pass an absolute path), stdio closed, its own process group (Unix) /
/// detached console and new process group (Windows), so a terminal interrupt
/// aimed at the client does not reach the service. The returned child is never
/// killed by dropping it.
///
/// **Descriptors** (ADR-0006 §13.8 item 7): the child receives exactly its three
/// standard descriptors, all null. **Unix:** the spawn sets 0-2 to `/dev/null`
/// and, before it, every descriptor above 2 of this process is marked
/// close-on-exec ([`crate::platform::disinherit_descriptors_above_stdio`]), so
/// one this client inherited without the flag (a caller's pipe) never reaches
/// the long-lived runtime; this process keeps using its descriptors. The runtime
/// also closes every descriptor above 2 at start-up
/// ([`crate::platform::close_inherited_descriptors`]).
///
/// **Windows** (ADR-0006 §13.6 item 8): `DETACHED_PROCESS` (no console and no
/// console window) and `CREATE_NEW_PROCESS_GROUP` (Ctrl-C/Ctrl-Break aimed at the
/// client's group never reaches the service). Handle inheritance: the standard
/// library creates every handle it opens non-inheritable and makes only the
/// three `NUL` stdio handles it passes inheritable for the spawn, but
/// `CreateProcess` also passes any handle the client **inherited** as
/// inheritable, i.e. its own stdio; so the client first clears the inherit flag
/// on its standard handles ([`crate::platform::disinherit_standard_handles`]).
/// The client's files, locks and pipe handles (opened without inheritance) are
/// never passed on. Residual: a non-standard handle the client itself inherited
/// as inheritable from its own parent would still pass on; restricting the list
/// (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) is not reachable through the stable
/// standard library (`CommandExt::raw_attribute` is unstable).
pub fn spawn_detached(program: &Path, args: &[&OsStr]) -> std::io::Result<std::process::Child> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
        // Only the three null standard descriptors reach the child (see below).
        crate::platform::disinherit_descriptors_above_stdio();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
        // Only the NUL stdio handles may be inherited (see below).
        crate::platform::disinherit_standard_handles();
    }
    cmd.spawn()
}

/// Whether a validated advertisement exists (pid alive with its start time,
/// endpoints ours and accepting). A planted or insecure record is an error.
fn serving(runtime_dir: &Path) -> Result<bool, LaunchError> {
    match InstanceInfo::read_valid(runtime_dir) {
        Ok(found) => Ok(found.is_some()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(LaunchError::Insecure(e)),
        // Any other read problem: treat as not serving (the start path then meets
        // the instance lock, which is authoritative).
        Err(_) => Ok(false),
    }
}

/// Take `start.lock` without blocking; `None` when another client holds it.
fn try_start_lock(path: &Path) -> Result<Option<std::fs::File>, LaunchError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(LaunchError::Io)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(LaunchError::Io(e)),
    }
}
