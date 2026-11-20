//! Login start of the per-user runtime (M04 U1; ADR-0010 §1 items 1, 2 and 7, §6;
//! m04-plan U1).
//!
//! **The entry, by host** (§6 item 1): a Windows `HKCU\Software\Microsoft\Windows\
//! CurrentVersion\Run` value ([`windows`]), a macOS LaunchAgent bootstrapped into
//! `gui/<uid>` ([`macos`]), a Linux systemd user unit enabled with `systemctl --user`
//! ([`linux`]). All three run `service run --login`, which exits 0 without side effects
//! when another instance holds the runtime lock. A host without a user manager has **no
//! entry** and the runtime is `on_demand` ([`LoginKind::None`]); lingering is never
//! enabled.
//!
//! **Ownership.** An entry is an owned resource (`ResourceKind::LoginEntry`) compared by
//! exact data ([`render`]): data that re-renders byte for byte is Heimdall's and may be
//! replaced or removed; anything else at Heimdall's own name is a conflict
//! ([`LoginError::Conflict`], reason `login_entry_conflict`) and is never touched. A
//! foreign entry of any other name is never read as ours.
//!
//! **Roots are injected.** Every host takes its root (the registry subkey, the
//! LaunchAgents directory, the unit directory) and its activation (the system command
//! runner, or none) as data, so tests use scratch roots and never the account's. The
//! system hosts are built by [`system_host`]: with no scratch root it uses the real
//! locations and the real activation, with one it writes only there and runs nothing.
//!
//! **Written only by the attended setup step** (`login_entry`: preview, apply, rollback
//! through the M02 setup flow, or `service autostart enable`), removed by `service
//! autostart disable` and by uninstall. Nothing in this module is reached from runtime
//! start-up.

use std::io;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub mod port;
pub mod render;

#[cfg(unix)]
pub mod linux;
#[cfg(unix)]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub use render::LoginCommand;

/// The kind of login entry a host supports (`inspect capabilities` `login_start.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoginKind {
    /// The Windows Run value.
    RunValue,
    /// The macOS LaunchAgent.
    LaunchAgent,
    /// The Linux systemd user unit.
    SystemdUser,
    /// No user manager: no entry, the runtime starts on demand.
    None,
}

impl LoginKind {
    /// The wire word (`run_value`, `launch_agent`, `systemd_user`, `none`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LoginKind::RunValue => "run_value",
            LoginKind::LaunchAgent => "launch_agent",
            LoginKind::SystemdUser => "systemd_user",
            LoginKind::None => "none",
        }
    }
}

/// What is at Heimdall's entry name now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryState {
    /// Nothing.
    Absent,
    /// Heimdall's own entry: exact data, with the command it names.
    Owned(LoginCommand),
    /// Something else is at the name: other data, another type, a hand edit.
    Foreign,
}

/// What an install did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// A new entry.
    Created,
    /// Heimdall's own entry, with another command, replaced.
    Updated,
    /// Heimdall's own entry, already exact: nothing was written.
    Unchanged,
}

/// What a removal did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// Heimdall's own entry was removed.
    Removed,
    /// There was none.
    Absent,
}

/// Why a login-entry operation did not happen.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// A non-owned entry is at Heimdall's own name (`login_entry_conflict`); untouched.
    #[error("another entry is at Heimdall's login entry name; it was left untouched")]
    Conflict,
    /// This host has no user manager (`LoginKind::None`).
    #[error("this host has no user session manager; the runtime starts on demand")]
    NoUserManager,
    /// The command cannot be rendered.
    #[error("{0}")]
    Render(#[from] render::RenderError),
    /// A file or registry operation failed.
    #[error("the login entry could not be written: {0}")]
    Io(#[from] io::Error),
    /// The activation command (`launchctl`, `systemctl`) failed.
    #[error("the login entry could not be activated: {0}")]
    Activation(String),
}

/// One kind of login entry at one root.
pub trait LoginHost: Send + Sync + std::fmt::Debug {
    /// The kind of entry.
    fn kind(&self) -> LoginKind;

    /// Where the entry lives, for display (a path, or `HKCU\...\Run\<name>`).
    fn location(&self) -> String;

    /// The exact data an install of `command` writes (what a preview shows).
    ///
    /// # Errors
    /// The command cannot be rendered.
    fn render(&self, command: &LoginCommand) -> Result<String, LoginError>;

    /// What is at the entry's name. Read-only.
    ///
    /// # Errors
    /// The location cannot be read.
    fn observe(&self) -> Result<EntryState, LoginError>;

    /// Write and activate the entry. A [`EntryState::Foreign`] entry is a
    /// [`LoginError::Conflict`] and is not touched; an owned one is replaced or left.
    ///
    /// # Errors
    /// See [`LoginError`]; nothing is left half-installed (a failed activation removes
    /// what this call created).
    fn install(&self, command: &LoginCommand) -> Result<InstallOutcome, LoginError>;

    /// Deactivate and remove Heimdall's own entry. A foreign entry is left alone and
    /// reported as [`LoginError::Conflict`].
    ///
    /// # Errors
    /// See [`LoginError`].
    fn remove(&self) -> Result<RemoveOutcome, LoginError>;
}

/// The host of a platform without a user manager (`LoginKind::None`).
#[derive(Debug)]
pub struct NoLoginHost;

impl LoginHost for NoLoginHost {
    fn kind(&self) -> LoginKind {
        LoginKind::None
    }
    fn location(&self) -> String {
        "none".to_owned()
    }
    fn render(&self, _command: &LoginCommand) -> Result<String, LoginError> {
        Err(LoginError::NoUserManager)
    }
    fn observe(&self) -> Result<EntryState, LoginError> {
        Ok(EntryState::Absent)
    }
    fn install(&self, _command: &LoginCommand) -> Result<InstallOutcome, LoginError> {
        Err(LoginError::NoUserManager)
    }
    fn remove(&self) -> Result<RemoveOutcome, LoginError> {
        Ok(RemoveOutcome::Absent)
    }
}

/// The stable per-installation token that names the entry: 16 lowercase hex characters of
/// the SHA-256 of the state directory's path (domain-separated). Stable across restarts
/// and independent of the state database, so `service autostart` and uninstall find the
/// same entry with no runtime running; two Heimdall homes on one machine get two names.
#[must_use]
pub fn installation_token(state_dir: &Path) -> String {
    let mut input = b"heimdall login entry v1\0".to_vec();
    input.extend_from_slice(state_dir.to_string_lossy().as_bytes());
    let digest = heimdall_domain::projection::Sha256Hex::of(&input);
    digest.as_str()[..16].to_owned()
}

/// A command that runs the current executable: its absolute path (not canonicalized, so
/// no `\\?\` form on Windows).
///
/// # Errors
/// The executable's path is unknown, or cannot be rendered into an entry.
pub fn current_exe_command() -> Result<LoginCommand, LoginError> {
    let exe = std::env::current_exe()?;
    Ok(LoginCommand::new(&exe)?)
}

/// A bounded command runner: the activation commands of the Unix hosts.
pub trait CommandRunner: Send + Sync + std::fmt::Debug {
    /// Run `program` with `args`; `Ok(true)` when it exited 0. The standard streams are
    /// closed, and a run that outlasts `timeout` is killed and is an error.
    ///
    /// # Errors
    /// The program could not be started, or timed out.
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<bool>;
}

/// [`CommandRunner`] over `std::process::Command`, with a closed standard input and
/// discarded output.
#[derive(Debug, Default)]
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<bool> {
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status.success());
            }
            if std::time::Instant::now() >= deadline {
                // The exact child this call started.
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the activation command timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Time allowed to an activation command.
pub const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(20);

/// The system login host: the real locations and activation (`scratch_root = None`), or a
/// scratch root with no activation. On Windows the root is a registry subkey path under
/// `HKCU`; elsewhere a directory (LaunchAgents or the systemd user directory).
#[must_use]
pub fn system_host(token: &str, scratch_root: Option<&Path>) -> Arc<dyn LoginHost> {
    #[cfg(windows)]
    {
        let subkey = match scratch_root {
            Some(root) => root.to_string_lossy().into_owned(),
            None => windows::RUN_SUBKEY.to_owned(),
        };
        Arc::new(windows::RunValueHost::new(&subkey, token))
    }
    #[cfg(target_os = "macos")]
    {
        let (dir, activation) = match scratch_root {
            Some(root) => (Some(root.to_owned()), None),
            None => (
                macos::launch_agents_dir(),
                Some(Arc::new(ProcessRunner) as Arc<dyn CommandRunner>),
            ),
        };
        match dir {
            Some(dir) => Arc::new(macos::LaunchAgentHost::new(
                &dir,
                &render::launch_agent_label(token),
                heimdall_ipc::unix::current_uid(),
                activation,
            )),
            None => Arc::new(NoLoginHost),
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = token;
        match scratch_root {
            Some(root) => Arc::new(linux::SystemdUserHost::new(root, None)),
            None => {
                let runner: Arc<dyn CommandRunner> = Arc::new(ProcessRunner);
                match linux::user_unit_dir() {
                    Some(dir) if linux::user_manager_available(runner.as_ref()) => {
                        Arc::new(linux::SystemdUserHost::new(&dir, Some(runner)))
                    }
                    _ => Arc::new(NoLoginHost),
                }
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (token, scratch_root);
        Arc::new(NoLoginHost)
    }
}

/// Write `bytes` to `path` only if nothing is there: the data goes to a sibling file,
/// which is hard-linked into place (an existing entry fails the link, so a file that
/// appeared since the caller looked is never overwritten). Unix only.
#[cfg(unix)]
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = sibling_temp(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let linked = written.and_then(|()| std::fs::hard_link(&tmp, path));
    let _ = std::fs::remove_file(&tmp);
    linked
}

/// Replace `path` (Heimdall's own, already read) with `bytes`: a sibling file renamed
/// over it. Unix only.
#[cfg(unix)]
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = sibling_temp(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let renamed = written.and_then(|()| std::fs::rename(&tmp, path));
    if renamed.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    renamed
}

#[cfg(unix)]
fn sibling_temp(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.hm-tmp-{}", std::process::id()))
}

/// Read a login-entry file: at most 64 KiB (anything larger is not Heimdall's), `None`
/// when absent. Not UTF-8 reads as a foreign file.
#[cfg(unix)]
pub(crate) fn read_entry_file(path: &Path) -> io::Result<Option<Result<String, ()>>> {
    use std::io::Read as _;
    // A symlink (or anything but a regular file) at the name is not Heimdall's entry:
    // judged from the path itself, never through the link.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => return Ok(Some(Err(()))),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !file.metadata()?.is_file() {
        return Ok(Some(Err(())));
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Ok(Some(Err(())));
    }
    Ok(Some(String::from_utf8(bytes).map_err(|_| ())))
}
