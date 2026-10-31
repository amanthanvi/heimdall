//! Heimdall local IPC (plan §4.1 "Environment/consumer adapters: OS IPC"; spec
//! §13.2; ADR-0006 §2).
//!
//! Two endpoints with distinct paths, permissions and protocols:
//!
//! * **Control** (`control.sock` / `\\.\pipe\heimdall-<id>-control`): length-prefixed
//!   JSON ([`frame`]), hello negotiation ([`session`]), the six primitives and
//!   event subscriptions.
//! * **Signing** (`signing.sock` / `\\.\pipe\heimdall-<id>-signing`): the SSH agent
//!   wire protocol, bounded and allow-listed ([`signing`]). It performs only
//!   already-authorized credential operations and never carries management.
//!
//! Peer authentication is the OS principal: Unix `getpeereid`/`SO_PEERCRED`
//! (through tokio's `UnixStream::peer_cred`), Windows client SID via
//! impersonation at identification level ([`windows`]). PID, image path and
//! caller-supplied names are metadata (spec §4.2, §13.2).
//!
//! `unsafe` is denied crate-wide; the single exception is [`windows`], which wraps
//! `CreateNamedPipeW` security attributes and the client-token query. Its inventory
//! is in docs/architecture/overview.md §9.

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
