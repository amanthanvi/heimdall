//! Where OpenSSH reads its configuration (m02-plan U3; ADR-0007 F19).
//!
//! OpenSSH takes the account home from the account database, never from `$HOME`
//! (F19), so `SshPaths` resolves it through `sys::account_home()`. Tests redirect it
//! only through the env-gated test configuration.
//!
//! **`[I]` settled on macOS 10.3p1 by `integration_doctor::home_resolution_matches_ssh_g`:**
//! the `%d` token and the defaults follow the account database (F19), but an
//! `Include` path's `~` (and a relative `Include`, which OpenSSH rewrites to
//! `~/.ssh/<path>`) is expanded by `glob(3)` with `GLOB_TILDE`, which consults `$HOME`
//! first. Under a `$HOME` other than the account's, those includes resolve under
//! `$HOME`; the doctor reports `home_mismatch` for that case.
//!
//! ADR-0007 §12.17 item 9: `crate::fs::BoundedSource` therefore reports the account
//! home as the include home only when the runtime's `HOME` is unset or names the
//! account home (`crate::fs::include_home_for`); otherwise such an `Include` is
//! undetermined (reason `environment_reference`), and B's own target is always an
//! absolute path, so B loads P whatever `$HOME` is.

use std::path::{Path, PathBuf};

/// The SSH configuration locations for this account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPaths {
    /// The account home (Unix `getpwuid_r`; Windows the profile folder).
    pub account_home: PathBuf,
    /// `~/.ssh/config`.
    pub user_config: PathBuf,
    /// `~/.ssh`.
    pub user_dir: PathBuf,
    /// `/etc/ssh/ssh_config` or `%PROGRAMDATA%\ssh\ssh_config`.
    pub system_config: PathBuf,
    /// `/etc/ssh` or `%PROGRAMDATA%\ssh`.
    pub system_dir: PathBuf,
}

/// The account home could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("account home unavailable: {0}")]
pub struct HomeUnavailable(pub String);

impl SshPaths {
    /// Resolve the paths for the current account: the home from the account database
    /// (F19), the user directory `~/.ssh`, and the system directory (`/etc/ssh`; on
    /// Windows `%PROGRAMDATA%\ssh`, the Win32-OpenSSH location).
    ///
    /// # Errors
    /// [`HomeUnavailable`].
    pub fn resolve() -> Result<Self, HomeUnavailable> {
        let account_home =
            crate::sys::account_home().map_err(|e| HomeUnavailable(e.to_string()))?;
        let user_dir = account_home.join(".ssh");
        let system_dir = system_dir();
        Ok(Self {
            user_config: user_dir.join("config"),
            user_dir,
            system_config: system_dir.join("ssh_config"),
            system_dir,
            account_home,
        })
    }

    /// Paths under a scratch home, for the env-gated test configuration only (never
    /// compiled into a release build's request paths).
    #[must_use]
    pub fn with_test_override(account_home: PathBuf, system_dir: PathBuf) -> Self {
        let user_dir = account_home.join(".ssh");
        Self {
            user_config: user_dir.join("config"),
            user_dir,
            system_config: system_dir.join("ssh_config"),
            system_dir,
            account_home,
        }
    }

    /// `path` for display: `~` for the account home (ADR-0007 §6 "Paths are shown with
    /// `~` for the home directory").
    #[must_use]
    pub fn display(&self, path: &Path) -> String {
        display_path(&self.account_home, path)
    }
}

/// `path` with a leading `home` shown as `~` (lossy UTF-8), with `/` separators on every
/// platform, as every other display does (ADR-0007 §12.26 item 7, §12.43 item 1): on
/// Windows `\` is a separator and is shown as `/`; on Unix it is a file-name character
/// and is kept.
#[must_use]
pub fn display_path(home: &Path, path: &Path) -> String {
    let text = |p: &Path| {
        let s = p.to_string_lossy();
        if cfg!(windows) {
            s.replace('\\', "/")
        } else {
            s.into_owned()
        }
    };
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) => format!("~/{}", text(rest)),
        Err(_) => text(path),
    }
}

#[cfg(windows)]
fn system_dir() -> PathBuf {
    // Win32-OpenSSH reads `__PROGRAMDATA__\ssh` (G03-S08). `ProgramData` is a
    // machine-wide value set by Windows, not the user's home.
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("ssh")
}

#[cfg(not(windows))]
fn system_dir() -> PathBuf {
    PathBuf::from("/etc/ssh")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_uses_the_account_home_and_its_ssh_directory() {
        let p = SshPaths::resolve().unwrap();
        assert_eq!(p.account_home, crate::sys::account_home().unwrap());
        assert_eq!(p.user_dir, p.account_home.join(".ssh"));
        assert_eq!(p.user_config, p.user_dir.join("config"));
        assert_eq!(p.system_config, p.system_dir.join("ssh_config"));
        assert!(p.system_dir.is_absolute());
    }

    #[test]
    fn display_shows_the_home_as_tilde_only_at_a_component_boundary() {
        let home = PathBuf::from("/scratch/home");
        assert_eq!(display_path(&home, &home), "~");
        assert_eq!(
            display_path(&home, &home.join(".ssh").join("config")),
            "~/.ssh/config"
        );
        assert_eq!(
            display_path(&home, Path::new("/scratch/homework/x")),
            "/scratch/homework/x"
        );
    }
}
