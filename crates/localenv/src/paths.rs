//! Where OpenSSH reads its configuration (m02-plan U3; ADR-0007 F19).
//!
//! OpenSSH takes the account home from the account database, never from `$HOME`
//! (F19), so `SshPaths` resolves it through `sys::account_home()`. Tests redirect it
//! only through the env-gated test configuration.

use std::path::PathBuf;

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
    /// Resolve the paths for the current account.
    ///
    /// # Errors
    /// [`HomeUnavailable`].
    pub fn resolve() -> Result<Self, HomeUnavailable> {
        todo!("M02-U3 paths::SshPaths::resolve")
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
}
