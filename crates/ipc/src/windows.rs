//! Windows endpoints: owner-only named pipes with client SID check (ADR-0006 §2.1;
//! g03 §3.1 N2; prototypes/rust/REPORT.md §16 lessons).
//!
//! Server: `tokio::net::windows::named_pipe::ServerOptions` with
//! `reject_remote_clients(true)`, `first_pipe_instance(true)` on the first
//! instance, and a `SECURITY_ATTRIBUTES` whose DACL is
//! `D:P(A;;GA;;;<owner SID>)` (protected, owner-only; further instances rely on the
//! DACL withholding `FILE_CREATE_PIPE_INSTANCE`). Names are
//! `\\.\pipe\heimdall-<unpredictable token>-<kind>` and carry no labels.
//!
//! Per connection the server impersonates at identification level
//! (`ImpersonateNamedPipeClient`), reads `TokenUser` from the thread token, reverts,
//! and requires the SID to equal the owner's. `GetNamedPipeClientProcessId` is
//! metadata only.
//!
//! Client: `ClientOptions::security_qos_flags(SECURITY_IDENTIFICATION |
//! SECURITY_SQOS_PRESENT)` so a rogue server cannot impersonate the client beyond
//! identification. Before opening, the path is classified: it must normalize
//! (`GetFullPathNameW`) into the `\\.\pipe\` or `\\?\pipe\` namespace, and the opened
//! handle must report `FILE_TYPE_PIPE`; anything else is refused without a data open
//! (REPORT.md §16 "classify the path before opening it").
//!
//! This is the crate's only `unsafe` boundary: the raw security-attributes pointer
//! passed to `create_with_security_attributes_raw`, the SDDL conversion, and the
//! impersonation/token calls. Each call is wrapped in a safe function with
//! documented invariants; no unsafe escapes this module.

#![allow(unsafe_code)]

use std::path::Path;

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};

use crate::endpoint::{EndpointKind, PeerIdentity, PeerRejected};

/// A named-pipe endpoint that creates a fresh instance per accepted client.
#[derive(Debug)]
pub struct Listener {
    kind: EndpointKind,
    name: String,
    owner_sid: String,
}

impl Listener {
    /// Create the first instance (fails if the name exists) with the owner-only DACL.
    pub fn bind(_name: &str, _kind: EndpointKind, _owner_sid: &str) -> std::io::Result<Self> {
        todo!("M01-T04 (Windows host required for verification)")
    }

    /// Wait for a client, verify its SID, and pre-create the next instance.
    pub async fn accept(&self) -> std::io::Result<(NamedPipeServer, PeerIdentity)> {
        let _ = (&self.kind, &self.name, &self.owner_sid);
        todo!("M01-T04")
    }

    /// Endpoint kind.
    #[must_use]
    pub fn kind(&self) -> EndpointKind {
        self.kind
    }
}

/// Read the connected client's user SID at identification level.
pub fn client_sid(_server: &NamedPipeServer) -> Result<String, PeerRejected> {
    todo!(
        "M01-T04: ImpersonateNamedPipeClient, OpenThreadToken, GetTokenInformation(TokenUser), RevertToSelf"
    )
}

/// Classify a candidate endpoint path before opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// Normalizes into the pipe namespace.
    PipeNamespace,
    /// Anything else (file, device, directory): refuse.
    NotPipe,
}

/// Normalize and classify (`GetFullPathNameW` then prefix check).
#[must_use]
pub fn classify_path(_path: &Path) -> PathClass {
    todo!("M01-T04")
}

/// Connect with `SECURITY_IDENTIFICATION` after classification and a
/// `FILE_TYPE_PIPE` handle check.
pub async fn connect(_path: &Path) -> std::io::Result<NamedPipeClient> {
    todo!("M01-T04")
}

/// The current process's user SID string.
pub fn current_user_sid() -> std::io::Result<String> {
    todo!("M01-T04")
}
