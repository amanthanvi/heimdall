//! Unix endpoints: owner-only socket directory, peer credentials (ADR-0006 §2.1).
//!
//! * Runtime dir: `$XDG_RUNTIME_DIR/heimdall/` when set, else a per-user directory
//!   under the state dir; created `0700`, owned by the runtime's uid; both checked
//!   (`fstat` after open, not a path race) before any bind.
//! * Socket: `0600` (umask `077` around bind), unlinked only when it is ours and
//!   dead (connect → `ECONNREFUSED`), never by glob.
//! * Peer check: `UnixStream::peer_cred()` (tokio; `getpeereid` on macOS,
//!   `SO_PEERCRED` on Linux) must report the runtime's uid.
//! * Client side: the socket's parent directory must be `0700` and owned by the
//!   client's uid before connecting (stale-socket and squatting defence; a
//!   same-user attacker is out of scope, spec §14.1).

use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

use crate::endpoint::{EndpointKind, PeerIdentity, PeerRejected};

/// A bound, owner-only listener.
#[derive(Debug)]
pub struct Listener {
    kind: EndpointKind,
    inner: UnixListener,
}

impl Listener {
    /// Create the directory if needed, verify ownership and mode, remove a dead
    /// socket of ours, bind with umask `077`.
    pub fn bind(_path: &Path, _kind: EndpointKind) -> std::io::Result<Self> {
        todo!("M01-T04")
    }

    /// Accept one connection and read its peer credentials.
    pub async fn accept(&self) -> std::io::Result<(UnixStream, PeerIdentity)> {
        let (stream, _) = self.inner.accept().await?;
        let cred = stream.peer_cred()?;
        let peer = PeerIdentity::Unix {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
        };
        Ok((stream, peer))
    }

    /// Endpoint kind.
    #[must_use]
    pub fn kind(&self) -> EndpointKind {
        self.kind
    }
}

/// Connect as a client after verifying the directory is ours and private.
pub async fn connect(_path: &Path) -> Result<UnixStream, ConnectError> {
    todo!("M01-T04")
}

/// Client-side connect failure.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// No runtime listening (on-demand start may follow).
    #[error("no runtime is listening")]
    NotRunning,
    /// Directory or socket ownership/mode is wrong.
    #[error("endpoint location is not owner-only")]
    Insecure,
    /// Peer verification failed.
    #[error("peer rejected: {0}")]
    Peer(#[from] PeerRejected),
    /// Other I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The runtime's own uid.
#[must_use]
pub fn current_uid() -> u32 {
    // `std::os::unix::fs::MetadataExt::uid` on a file we own is the safe route
    // without `libc`; M01-T04 decides between this and `rustix::process::getuid`.
    todo!("M01-T04")
}
