//! The environment snapshot and platform tag shared by discovery, Git resolution and
//! the process contract (m02-plan U3, U8). Complete in the skeleton: plain data.
//!
//! Discovery reads the environment only through an [`Env`] taken once, so a test can
//! pass a scratch environment and production code never re-reads a variable that
//! changed in between. Nothing here modifies the process environment.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

/// A snapshot of environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Env {
    vars: BTreeMap<OsString, OsString>,
}

impl Env {
    /// The current process environment.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            vars: std::env::vars_os().collect(),
        }
    }

    /// An environment holding exactly `vars` (tests, child environments).
    #[must_use]
    pub fn from_vars<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            vars: vars
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// A variable's value, or `None` when unset. Names compare exactly; Windows
    /// callers normalize case before building the snapshot.
    #[must_use]
    pub fn get(&self, name: impl AsRef<OsStr>) -> Option<&OsStr> {
        self.vars.get(name.as_ref()).map(OsString::as_os_str)
    }

    /// Every variable, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.as_os_str(), v.as_os_str()))
    }
}

/// The platform whose rules apply (paths, clients, agents, launch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Linux, WSL included.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
    /// Another Unix.
    OtherUnix,
}

impl Platform {
    /// The platform this build runs on.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::OtherUnix
        }
    }

    /// Whether Windows rules apply.
    #[must_use]
    pub const fn is_windows(self) -> bool {
        matches!(self, Platform::Windows)
    }
}

#[cfg(test)]
mod tests {
    use super::{Env, Platform};

    #[test]
    fn env_snapshot_reads_only_its_own_vars() {
        let env = Env::from_vars([("HM_W0_A", "1"), ("HM_W0_B", "two")]);
        assert_eq!(env.get("HM_W0_A").and_then(|v| v.to_str()), Some("1"));
        assert_eq!(env.get("HM_W0_B").and_then(|v| v.to_str()), Some("two"));
        assert_eq!(env.get("HM_W0_C"), None);
        assert_eq!(env.iter().count(), 2);
    }

    #[test]
    fn platform_matches_the_build_target() {
        let p = Platform::current();
        assert_eq!(p.is_windows(), cfg!(windows));
        if cfg!(target_os = "macos") {
            assert_eq!(p, Platform::MacOs);
        }
        if cfg!(target_os = "linux") {
            assert_eq!(p, Platform::Linux);
        }
    }
}
