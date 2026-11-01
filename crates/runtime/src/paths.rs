//! Per-user directories (spec §13.3 "Separate configuration, public/materialized
//! data, transactional runtime state, secrets, and logs"; ADR-0006 §2.1 runtime
//! directory).
//!
//! Layout:
//!
//! | Directory | `HEIMDALL_HOME` set | Unix default (XDG) | Windows default |
//! |---|---|---|---|
//! | config  | `$HEIMDALL_HOME/config` | `$XDG_CONFIG_HOME/heimdall` (`~/.config/heimdall`) | `%LOCALAPPDATA%\heimdall\config` |
//! | state   | `$HEIMDALL_HOME/state`  | `$XDG_STATE_HOME/heimdall` (`~/.local/state/heimdall`) | `%LOCALAPPDATA%\heimdall\state` |
//! | runtime | `$HEIMDALL_HOME/run`    | `$XDG_RUNTIME_DIR/heimdall` when set, else `<state>/run` | `%LOCALAPPDATA%\heimdall\run` |
//! | log     | `$HEIMDALL_HOME/log`    | `<state>/log` | `%LOCALAPPDATA%\heimdall\log` |
//!
//! XDG is used on every Unix including macOS, so the managed include path matches
//! spec §10.1 (etcetera's XDG rules: a relative `XDG_*` value is ignored). On
//! Windows everything lives under the local (non-roaming) application-data folder
//! (Known Folders through etcetera), so the state database is never placed in a
//! roaming profile.
//!
//! `HEIMDALL_HOME` exists for fixtures and tests. It must be an absolute path; an
//! empty or relative value is refused rather than silently falling back to the
//! real per-user directories (a test harness bug must not touch the owner's state).
//!
//! **Owner-only (Unix).** Every directory is created `0700`. An existing directory
//! must be a real directory (not a symlink) owned by the process uid, checked by
//! `fstat` on an opened handle and compared with the `lstat` of the path; group or
//! other permission bits on such a directory are removed through the handle
//! (`fchmod`), never through the path. A directory owned by another user, or a
//! symlink at a leaf, is refused. Parents (`~/.config`, `$XDG_RUNTIME_DIR`) are not
//! modified. **Windows:** directories are created under `%LOCALAPPDATA%`, which
//! inherits the per-user ACL; explicit DACL hardening is M04 work (native
//! evidence).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::config::ConfigError;

/// Environment variable that relocates every directory under one root.
pub const HOME_ENV: &str = "HEIMDALL_HOME";

/// Application directory name under the platform base directories.
const APP: &str = "heimdall";

/// Resolved directories. Never a cloud-sync folder for the state database
/// (spec §13.3); setup refuses known sync roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `config.toml` and the managed OpenSSH include live here.
    pub config_dir: PathBuf,
    /// State database, backups, instance lock.
    pub state_dir: PathBuf,
    /// Endpoints (sockets) and instance info; `XDG_RUNTIME_DIR` when available.
    pub runtime_dir: PathBuf,
    /// Logs (redacted, bounded).
    pub log_dir: PathBuf,
}

impl Paths {
    /// Discover platform defaults, honouring `HEIMDALL_HOME` for fixtures and tests,
    /// and create every directory owner-only (module docs).
    pub fn discover() -> Result<Self, ConfigError> {
        Self::discover_from(&|name| std::env::var_os(name))
    }

    /// [`discover`](Self::discover) with an injected environment lookup (tests
    /// cannot set process environment variables without `unsafe`).
    #[doc(hidden)]
    pub fn discover_from(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let paths = Self::resolve(env)?;
        paths.ensure()?;
        Ok(paths)
    }

    /// Resolve without touching the filesystem.
    #[doc(hidden)]
    pub fn resolve(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        if let Some(home) = env(HOME_ENV) {
            let home = PathBuf::from(home);
            if home.as_os_str().is_empty() || !home.is_absolute() {
                return Err(ConfigError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HEIMDALL_HOME must be an absolute path",
                )));
            }
            return Ok(Self::under(&home));
        }
        Self::platform_defaults(env)
    }

    /// Every directory under one root (the `HEIMDALL_HOME` layout). Does not create
    /// anything; call [`ensure`](Self::ensure).
    #[must_use]
    pub fn under(home: &Path) -> Self {
        Self {
            config_dir: home.join("config"),
            state_dir: home.join("state"),
            runtime_dir: home.join("run"),
            log_dir: home.join("log"),
        }
    }

    /// Create (if missing) and verify every directory owner-only (module docs).
    pub fn ensure(&self) -> Result<(), ConfigError> {
        for dir in [
            &self.config_dir,
            &self.state_dir,
            &self.runtime_dir,
            &self.log_dir,
        ] {
            ensure_owner_only_dir(dir)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn platform_defaults(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let home = etcetera::home_dir().map_err(|_| ConfigError::NoHome)?;
        if !home.is_absolute() {
            return Err(ConfigError::NoHome);
        }
        // XDG Base Directory rule: only absolute values count.
        let xdg = |name: &str| env(name).map(PathBuf::from).filter(|p| p.is_absolute());
        let config_base = xdg("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let state_base = xdg("XDG_STATE_HOME").unwrap_or_else(|| home.join(".local").join("state"));
        let state_dir = state_base.join(APP);
        let runtime_dir = xdg("XDG_RUNTIME_DIR")
            .map(|r| r.join(APP))
            .unwrap_or_else(|| state_dir.join("run"));
        Ok(Self {
            config_dir: config_base.join(APP),
            log_dir: state_dir.join("log"),
            runtime_dir,
            state_dir,
        })
    }

    #[cfg(windows)]
    fn platform_defaults(_env: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        use etcetera::BaseStrategy;
        let strategy = etcetera::choose_base_strategy().map_err(|_| ConfigError::NoHome)?;
        // `cache_dir` is %LOCALAPPDATA% (Known Folder) for the Windows strategy:
        // local, never roaming.
        let local = strategy.cache_dir();
        if !local.is_absolute() {
            return Err(ConfigError::NoHome);
        }
        Ok(Self::under(&local.join(APP)))
    }

    #[cfg(not(any(unix, windows)))]
    fn platform_defaults(_env: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        Err(ConfigError::NoHome)
    }
}

/// Create `dir` owner-only or verify an existing one (module docs).
#[cfg(unix)]
fn ensure_owner_only_dir(dir: &Path) -> Result<(), ConfigError> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    use heimdall_ipc::unix::{DirProblem, PathFacts, check_private_dir, current_uid};

    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Parents get 0700 too when we create them (umask may only remove bits).
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        Err(e) => return Err(e.into()),
    }
    let uid = current_uid();
    let lmeta = std::fs::symlink_metadata(dir)?;
    let handle = std::fs::File::open(dir)?;
    let fmeta = handle.metadata()?;
    if (lmeta.dev(), lmeta.ino()) != (fmeta.dev(), fmeta.ino()) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "a heimdall directory changed while it was being checked",
        )
        .into());
    }
    for facts in [PathFacts::of(&lmeta), PathFacts::of(&fmeta)] {
        match check_private_dir(&facts, uid) {
            Ok(()) => {}
            // Ours and a real directory: tighten through the handle (fchmod), so
            // a swapped path can never redirect the change.
            Err(DirProblem::TooPermissive) => {
                handle.set_permissions(std::fs::Permissions::from_mode(0o700))?;
            }
            Err(problem) => {
                return Err(Error::new(ErrorKind::PermissionDenied, problem.to_string()).into());
            }
        }
    }
    let after = handle.metadata()?;
    check_private_dir(&PathFacts::of(&after), uid)
        .map_err(|p| Error::new(ErrorKind::PermissionDenied, p.to_string()))?;
    Ok(())
}

/// Windows: create under `%LOCALAPPDATA%` (per-user inherited ACL) and require a
/// real directory, not a reparse point.
#[cfg(not(unix))]
fn ensure_owner_only_dir(dir: &Path) -> Result<(), ConfigError> {
    use std::io::{Error, ErrorKind};
    std::fs::create_dir_all(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "a heimdall directory path is not a real directory",
        )
        .into());
    }
    Ok(())
}
