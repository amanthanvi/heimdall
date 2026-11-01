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
//! `CreateNamedPipeW` security attributes, the client-token query and the
//! client-side server-owner query. Its inventory is in docs/architecture/overview.md
//! §9.
//!
//! Test targets hosted by this crate (real Cargo `[[test]]` targets, sources under
//! the repository `tests/` tree): `integration_ipc_unix` (Unix only),
//! `adversarial_ipc_frames`, `adversarial_agent_frames`. Items they need that are
//! not part of the supported API are `#[doc(hidden)] pub`.

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
