//! The environment a launched child gets (m02-plan U8; ADR-0007 §8).
//!
//! * `SSH_AUTH_SOCK` only when every pair of the binding uses one endpoint;
//! * on Windows, `core.sshCommand=<verified client>` through `GIT_CONFIG_COUNT` only
//!   when Git's selection is the bundled MSYS default, appended after the caller's
//!   entries (a malformed caller count injects nothing);
//! * never overrides a user's `GIT_SSH_COMMAND`, `GIT_SSH` or a `core.sshCommand` at
//!   any scope: those are reported as `ConsumerOverride`s.

use std::ffi::OsString;

use heimdall_contract::doctor::GitSshSelection;
use heimdall_contract::request::{ConsumerIntegration, ConsumerOverride};
use heimdall_localenv::env::{Env, Platform};

/// What is added to the caller's environment, and what stays in force instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvDelta {
    /// Variables set (names and values; nonsecret: socket paths and Git's command
    /// configuration).
    pub set: Vec<(OsString, OsString)>,
    /// Settings another source keeps in force (names only, never values).
    pub overrides: Vec<ConsumerOverride>,
}

impl EnvDelta {
    /// The delta for `integration` over the caller's `env` and Git `selection`.
    #[must_use]
    pub fn from_integration(
        integration: &ConsumerIntegration,
        env: &Env,
        selection: &GitSshSelection,
        platform: Platform,
    ) -> EnvDelta {
        let _ = (integration, env, selection, platform);
        todo!("M02-U8 env::EnvDelta::from_integration")
    }
}
