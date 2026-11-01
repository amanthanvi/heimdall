//! Passive agent endpoint detection (m02-plan U3; ADR-0007 §7).
//!
//! Detection opens nothing: it reads `SSH_AUTH_SOCK`, the `IdentityAgent` references
//! in the configuration, and, on Windows, lists `\\.\pipe\` with `std::fs::read_dir`.
//! No 1Password path is hardcoded: the pinned vendor excerpts are not available
//! (docs/sources/excerpts/notes.md, "G03-S12"), so 1Password is recognized only through
//! those two references (ADR-0007 §7; m02-plan U0).

use std::path::PathBuf;

use heimdall_contract::provider::ProviderKind;

use crate::env::{Env, Platform};
use crate::paths::SshPaths;

/// Where an agent listens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointLocator {
    /// A Unix socket.
    UnixSocket(PathBuf),
    /// A Windows named pipe (`\\.\pipe\<name>`).
    NamedPipe(String),
}

/// Whether the endpoint was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presence {
    /// The socket or pipe exists.
    Present,
    /// It does not.
    Absent,
    /// It exists but is owned by another user (`agent_endpoint_foreign_owner`).
    ForeignOwner,
    /// It could not be checked.
    Unknown,
}

/// What pointed at the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EndpointSource {
    /// `SSH_AUTH_SOCK`.
    SshAuthSock,
    /// An `IdentityAgent` directive.
    IdentityAgent(heimdall_contract::doctor::ConfigProvenance),
    /// The Windows system pipe `openssh-ssh-agent`.
    WindowsSystemPipe,
}

/// One detected agent endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEndpoint {
    /// Which provider it is believed to be.
    pub provider: ProviderKind,
    /// Where it listens.
    pub locator: EndpointLocator,
    /// Whether it was seen.
    pub presence: Presence,
    /// What pointed at it.
    pub source: EndpointSource,
}

/// Detect agent endpoints passively.
#[must_use]
pub fn detect_agents(env: &Env, paths: &SshPaths, platform: Platform) -> Vec<AgentEndpoint> {
    let _ = (env, paths, platform);
    todo!("M02-U3 agents::detect_agents")
}
