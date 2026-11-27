//! Heimdall local IPC (plan §4.1 "Environment/consumer adapters: OS IPC"; spec
//! §13.2; ADR-0006 §2).
//!
//! Three endpoints with distinct paths and protocols ([`EndpointKind`]):
//!
//! * **Control** (`control.sock` / `\\.\pipe\heimdall-<id>-control`): length-prefixed
//!   JSON ([`frame`]), hello negotiation ([`session`]), the six primitives and
//!   event subscriptions.
//! * **Signing** (`signing.sock` / `\\.\pipe\heimdall-<id>-signing`): the SSH agent
//!   wire protocol, bounded and allow-listed ([`signing`]). It performs only
//!   already-authorized credential operations and never carries management.
//! * **Issuer** (`issuer.sock` / `\\.\pipe\heimdall-<id>-issuer`): issuance requests
//!   from the runtime's own supervisor only, same owner-only transport and frame
//!   limit as control (ADR-0006 §2.1 rev2; the protocol arrives in M03). Never
//!   exposed to bindings, containers or forwarded endpoints.
//!
//! ⟨M02⟩ [`agent_client`] is the client side of the explicit `agent` probe: one
//! bounded `SSH_AGENTC_REQUEST_IDENTITIES` to an existing agent (m02-plan U6).
//!
//! Peer authentication is the OS principal: Unix `getpeereid`/`SO_PEERCRED`
//! (through tokio's `UnixStream::peer_cred`), Windows client SID via
//! impersonation at identification level ([`windows`]). PID, image path and
//! caller-supplied names are metadata (spec §4.2, §13.2).
//!
//! `unsafe` is denied crate-wide; the single exception is [`windows`], which wraps
//! `CreateNamedPipeW` security attributes, the client-token query, the client-side
//! server-owner query and ⟨M07 S2-07⟩ the server-process query
//! (`GetNamedPipeServerProcessId`, the process token's user). Its inventory is in
//! docs/architecture/overview.md §9 and docs/security/unsafe-inventory.md.
//!
//! ⟨M07 S2-07; ADR-0013 §8⟩ A production client connect returns a
//! [`VerifiedConnection`]: the stream, after every check of the platform passed before
//! any byte was sent, and the server's process ID read from that connection (Linux
//! `SO_PEERCRED`, macOS `LOCAL_PEEREPID` through tokio's `peer_cred`, Windows
//! `GetNamedPipeServerProcessId`). A PID the platform does not report is a refusal,
//! never skipped.
//!
//! Test targets hosted by this crate (real Cargo `[[test]]` targets, sources under
//! the repository `tests/` tree): `integration_ipc_unix` (Unix only),
//! `adversarial_ipc_frames`, `adversarial_agent_frames`, `adversarial_agent_client_frames`
//! and ⟨M03⟩ `integration_ipc_signing_m03` (U0b row 1: the signing session and the
//! capacity-then-release order). Items they need that are not part of the supported
//! API are `#[doc(hidden)] pub`.

pub mod agent_client;
pub mod endpoint;
pub mod frame;
pub mod session;
pub mod signing;

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

pub use endpoint::{EndpointKind, EndpointPaths, PeerIdentity, PeerRejected};
pub use frame::{FrameError, decode_frame, encode_frame};

/// ⟨M07 S2-07; ADR-0013 §8⟩ A client connection whose server passed every check of the
/// platform before any byte was sent, with the server's process ID read from the verified
/// connection itself (never from an advertisement). Built only by this crate's connects
/// (`unix::connect_verified`, `windows::connect_with_owner_verified`).
#[derive(Debug)]
pub struct VerifiedConnection<S> {
    stream: S,
    server_pid: u32,
}

impl<S> VerifiedConnection<S> {
    /// A connection whose checks passed; `server_pid` is non-zero.
    pub(crate) fn new(stream: S, server_pid: u32) -> Self {
        Self { stream, server_pid }
    }

    /// The server's process ID, as the OS reports it for this connection (Linux
    /// `SO_PEERCRED`, macOS `LOCAL_PEEREPID`, Windows `GetNamedPipeServerProcessId`).
    #[must_use]
    pub fn server_pid(&self) -> u32 {
        self.server_pid
    }

    /// The stream, dropping the PID.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// The stream and the server's process ID.
    #[must_use]
    pub fn into_parts(self) -> (S, u32) {
        (self.stream, self.server_pid)
    }
}
