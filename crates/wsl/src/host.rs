//! [`WslHost`]: the `DistributionHost` port's implementation (ADR-0010 §2, §3; design U3 §6).
//!
//! On Windows it reads Lxss, asks `wsl.exe --list --running --quiet` which distributions run,
//! and starts one helper per request through `wsl.exe`. On every other host `discover` answers
//! `wsl_unavailable`. A test constructor ([`WslHost::with_direct_helper`]) starts the helper
//! binary directly, with an injected environment, so the macOS and Linux tests drive the real
//! channel.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use heimdall_app::ports::{
    AdapterError, DiscoveredDistribution, DistributionHost, DistributionStart, DistributionTarget,
    ProjectionWriter, ResourceCleaner, RunningState,
};
use heimdall_contract::environment::DistributionGuid;
use heimdall_localenv::sys::spawn::{ListedSpawn, spawn_listed};

use crate::client::{
    DistributionCleaner, DistributionWriter, HelperLauncher, SessionError, Transport,
};
use crate::spawn;

/// `Unavailable` text: WSL is absent on this host.
pub const WSL_UNAVAILABLE: &str = "wsl_unavailable";
/// `Unavailable` text: the distribution is stopped and the caller may not start it.
pub const DISTRIBUTION_NOT_RUNNING: &str = "wsl_distribution_not_running";

type Discovery = dyn Fn() -> Result<Vec<DiscoveredDistribution>, AdapterError> + Send + Sync;

/// The WSL host.
#[derive(Clone)]
pub struct WslHost {
    launcher: Arc<dyn HelperLauncher>,
    discovery: Arc<Discovery>,
    ssh_exe_windows: String,
}

impl std::fmt::Debug for WslHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WslHost").finish_non_exhaustive()
    }
}

impl WslHost {
    /// The host of this platform: on Windows, Lxss and `wsl.exe` with the helper beside
    /// `heimdall.exe` (or at `helper_override`, the test configuration's
    /// `HEIMDALL_WSL_HELPER`); elsewhere, a host with no WSL.
    #[must_use]
    pub fn platform(helper_override: Option<PathBuf>) -> WslHost {
        #[cfg(windows)]
        {
            let system_root = std::env::var("SystemRoot").ok();
            let helper = helper_override.or_else(|| {
                std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(spawn::helper_windows_path))
            });
            WslHost {
                launcher: Arc::new(WslExeLauncher::new(
                    spawn::wsl_exe_path(system_root.as_deref()),
                    helper.unwrap_or_else(|| PathBuf::from(spawn::HELPER_FILE)),
                )),
                discovery: Arc::new(discover_lxss),
                ssh_exe_windows: spawn::ssh_exe_windows(system_root.as_deref()),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = helper_override;
            WslHost::unavailable()
        }
    }

    /// A host with no WSL: `discover` answers `wsl_unavailable`, nothing runs, and no helper
    /// can be started.
    #[must_use]
    pub fn unavailable() -> WslHost {
        WslHost {
            launcher: Arc::new(NoLauncher),
            discovery: Arc::new(|| Err(AdapterError::Unavailable(WSL_UNAVAILABLE.to_owned()))),
            ssh_exe_windows: spawn::SSH_EXE_DEFAULT.to_owned(),
        }
    }

    /// A host over an arbitrary launcher and discovery (the runtime's tests).
    #[must_use]
    pub fn new(
        launcher: Arc<dyn HelperLauncher>,
        discovery: Arc<Discovery>,
        ssh_exe_windows: String,
    ) -> WslHost {
        WslHost {
            launcher,
            discovery,
            ssh_exe_windows,
        }
    }

    /// **Test constructor.** A host whose helper is `direct`'s binary, started directly (no
    /// `wsl.exe`), with the distributions it lists and the running state it reports.
    #[must_use]
    pub fn with_direct_helper(
        direct: Arc<DirectLauncher>,
        distributions: Vec<DiscoveredDistribution>,
    ) -> WslHost {
        WslHost {
            launcher: direct,
            discovery: Arc::new(move || Ok(distributions.clone())),
            ssh_exe_windows: spawn::SSH_EXE_DEFAULT.to_owned(),
        }
    }

    fn preflight(
        &self,
        target: &DistributionTarget,
        start: DistributionStart,
    ) -> Result<(), AdapterError> {
        if start == DistributionStart::Forbidden
            && self.launcher.running(&target.name) != RunningState::Running
        {
            return Err(AdapterError::Unavailable(
                DISTRIBUTION_NOT_RUNNING.to_owned(),
            ));
        }
        Ok(())
    }
}

impl DistributionHost for WslHost {
    fn discover(&self) -> Result<Vec<DiscoveredDistribution>, AdapterError> {
        (self.discovery)()
    }

    fn running(&self, guid: &DistributionGuid) -> RunningState {
        let Ok(list) = self.discover() else {
            return RunningState::Unknown;
        };
        match list.iter().find(|d| &d.guid == guid) {
            Some(d) => self.launcher.running(&d.name),
            None => RunningState::NotRunning,
        }
    }

    fn writer(
        &self,
        target: &DistributionTarget,
        start: DistributionStart,
    ) -> Result<Arc<dyn ProjectionWriter>, AdapterError> {
        self.preflight(target, start)?;
        Ok(Arc::new(DistributionWriter::new(
            Arc::clone(&self.launcher),
            target.clone(),
            start,
            self.ssh_exe_windows.clone(),
        )))
    }

    fn cleaner(
        &self,
        target: &DistributionTarget,
        start: DistributionStart,
    ) -> Result<Arc<dyn ResourceCleaner>, AdapterError> {
        self.preflight(target, start)?;
        Ok(Arc::new(DistributionCleaner::new(
            Arc::clone(&self.launcher),
            target.clone(),
            start,
            self.ssh_exe_windows.clone(),
        )))
    }
}

/// The launcher of a host with no WSL.
struct NoLauncher;

impl HelperLauncher for NoLauncher {
    fn running(&self, _name: &str) -> RunningState {
        RunningState::Unknown
    }
    fn launch(&self, _target: &DistributionTarget) -> Result<Transport, SessionError> {
        Err(SessionError::HelperUnavailable(WSL_UNAVAILABLE.to_owned()))
    }
}

/// Lxss through the registry read (Windows).
#[cfg(windows)]
fn discover_lxss() -> Result<Vec<DiscoveredDistribution>, AdapterError> {
    use crate::discover::{LxssValues, discover_from};
    let entries = heimdall_localenv::sys::lxss::read_entries()
        .map_err(|_| AdapterError::Unavailable(WSL_UNAVAILABLE.to_owned()))?;
    let values: Vec<(String, LxssValues)> = entries
        .into_iter()
        .map(|e| {
            (
                e.subkey,
                LxssValues {
                    name: e.name,
                    version: e.version,
                    default_uid: e.default_uid,
                    state: e.state,
                },
            )
        })
        .collect();
    let found = discover_from(values.iter().map(|(k, v)| (k.as_str(), v)));
    Ok(found
        .distributions
        .iter()
        .map(DiscoveredDistribution::from)
        .collect())
}

// --- the Windows launcher --------------------------------------------------------------------

/// Resolves the Linux-visible path of a Windows path inside `target`'s distribution.
pub type PathResolver =
    dyn Fn(&DistributionTarget, &str) -> Result<String, SessionError> + Send + Sync;

/// Starts the helper through
/// `wsl.exe -d <name> -u <account> --exec <linux helper path> internal wsl-helper` with the
/// filtered environment and the explicit handle list.
pub struct WslExeLauncher {
    wsl_exe: PathBuf,
    helper_windows: PathBuf,
    resolver: Box<PathResolver>,
}

/// The parent's variables, for the environment filter.
fn parent_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

impl WslExeLauncher {
    /// A launcher over `wsl.exe` and the helper's Windows path, resolving the Linux path with
    /// `wsl.exe … wslpath -u` (10 s).
    #[must_use]
    pub fn new(wsl_exe: PathBuf, helper_windows: PathBuf) -> Self {
        let exe = wsl_exe.clone();
        Self {
            wsl_exe,
            helper_windows,
            resolver: Box::new(move |target, windows_path| {
                let args = spawn::wslpath_args(&target.name, &target.account, windows_path)
                    .ok_or_else(|| {
                        SessionError::HelperUnavailable("not a plain argument".to_owned())
                    })?;
                let cmd = spawn::wsl_command(&exe, &args, &parent_env);
                let done = spawn::run_bounded(&cmd, spawn::WSLPATH_TIMEOUT)
                    .map_err(|e| SessionError::HelperUnavailable(format!("wslpath: {e}")))?;
                if done.status != 0 {
                    return Err(SessionError::HelperUnavailable("wslpath failed".to_owned()));
                }
                spawn::parse_wslpath_output(&done.stdout)
                    .ok_or_else(|| SessionError::HelperUnavailable("no Linux path".to_owned()))
            }),
        }
    }

    /// The same launcher with another path resolver (the client-level tests).
    #[must_use]
    pub fn with_resolver(mut self, resolver: Box<PathResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// The Linux-visible helper path for `target`: resolved, absolute, never a raw Windows
    /// path (design §4).
    ///
    /// # Errors
    /// [`SessionError::HelperUnavailable`] when the resolver fails or answers an empty or
    /// non-absolute path.
    pub fn linux_helper_path(&self, target: &DistributionTarget) -> Result<String, SessionError> {
        let windows = self.helper_windows.to_str().ok_or_else(|| {
            SessionError::HelperUnavailable("the helper path is not text".to_owned())
        })?;
        let linux = (self.resolver)(target, windows)?;
        if linux.starts_with('/') && !linux.contains(['\0', '\n', '\r']) {
            Ok(linux)
        } else {
            Err(SessionError::HelperUnavailable(
                "no Linux-visible helper path".to_owned(),
            ))
        }
    }
}

impl HelperLauncher for WslExeLauncher {
    fn running(&self, name: &str) -> RunningState {
        spawn::list_running(&self.wsl_exe, &parent_env).state_of(name)
    }

    fn launch(&self, target: &DistributionTarget) -> Result<Transport, SessionError> {
        let linux = self.linux_helper_path(target)?;
        let args = spawn::helper_args(&target.name, &target.account, &linux)
            .ok_or_else(|| SessionError::HelperUnavailable("not a plain argument".to_owned()))?;
        let cmd = spawn::wsl_command(&self.wsl_exe, &args, &parent_env);
        let child = spawn_listed(
            &cmd,
            &ListedSpawn {
                env_clear: true,
                creation_flags: 0x0800_0000,
                ..ListedSpawn::piped()
            },
        )
        .map_err(|_| SessionError::HelperUnavailable("wsl.exe could not start".to_owned()))?;
        Transport::from_listed(child)
    }
}

// --- the test launcher -------------------------------------------------------------------------

/// **Test constructor's launcher.** Starts a helper binary directly (no `wsl.exe`), with an
/// explicit argument list and environment, and reports a settable running state. It counts the
/// helpers it started, so a test can show a stopped distribution started nothing.
pub struct DirectLauncher {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    running: Mutex<RunningState>,
    spawned: AtomicUsize,
    last_pid: Mutex<Option<u32>>,
}

impl DirectLauncher {
    /// A launcher for `program args…` with exactly `env` as its environment.
    #[must_use]
    pub fn new(program: PathBuf, args: Vec<OsString>, env: Vec<(OsString, OsString)>) -> Arc<Self> {
        Arc::new(Self {
            program,
            args,
            env,
            running: Mutex::new(RunningState::Running),
            spawned: AtomicUsize::new(0),
            last_pid: Mutex::new(None),
        })
    }

    /// What `running` answers from now on.
    pub fn set_running(&self, state: RunningState) {
        *self.running.lock().unwrap_or_else(PoisonError::into_inner) = state;
    }

    /// How many helpers were started.
    #[must_use]
    pub fn spawned(&self) -> usize {
        self.spawned.load(Ordering::SeqCst)
    }

    /// The process ID of the helper started last (tests kill it by exact PID).
    #[must_use]
    pub fn last_pid(&self) -> Option<u32> {
        *self.last_pid.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl HelperLauncher for DirectLauncher {
    fn running(&self, _name: &str) -> RunningState {
        *self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn launch(&self, _target: &DistributionTarget) -> Result<Transport, SessionError> {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        let child = spawn_listed(
            &cmd,
            &ListedSpawn {
                env_clear: true,
                ..ListedSpawn::piped()
            },
        )
        .map_err(|_| SessionError::HelperUnavailable("the helper could not start".to_owned()))?;
        self.spawned.fetch_add(1, Ordering::SeqCst);
        *self.last_pid.lock().unwrap_or_else(PoisonError::into_inner) = Some(child.id());
        Transport::from_listed(child)
    }
}
