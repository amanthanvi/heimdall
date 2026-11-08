//! Unix endpoints: owner-only socket directory, peer credentials (ADR-0006 §2.1).
//!
//! * Runtime dir: `$XDG_RUNTIME_DIR/heimdall/` when set, else a per-user directory
//!   under the state dir; created `0700`, owned by the runtime's uid; both checked
//!   (`fstat` after open, compared with the `lstat` of the path so a symlink or a
//!   swapped directory is refused) before any bind.
//! * Socket: `0600`. **Umask equivalent, as implemented** (ADR-0006 §2.1 rev2,
//!   wave-1 E13): the baseline's "bound under umask `077`" is met by the pair
//!   (a) the runtime directory verified `0700` and owned by the runtime uid through
//!   `fstat` on an opened handle (above), then (b) `chmod 0600` of the socket
//!   immediately after `bind`, re-checked by `lstat` (socket, our uid, no
//!   group/other bits; otherwise the socket is unlinked and `bind` fails), all
//!   before the first `accept`. The workspace has no `libc`/`rustix` and denies
//!   `unsafe`, so the process umask itself is never changed (it is process-wide
//!   and would race other threads). Between `bind` and `chmod` the socket is
//!   unreachable for other users because its directory is `0700` and ours: the
//!   directory, not the socket mode, is the barrier (macOS ignores socket modes
//!   for `connect` anyway). The peer check on every accepted connection is the
//!   authentication.
//! * Stale socket: unlinked only when it is a socket, owned by our uid, and dead
//!   (`connect` → `ECONNREFUSED`); never by glob. A live socket, a foreign-owned
//!   socket, or any non-socket file at the path is left in place and `bind` fails.
//! * Peer check: `UnixStream::peer_cred()` (tokio; `getpeereid` on macOS,
//!   `SO_PEERCRED` on Linux) must report the runtime's uid.
//! * Client side: the socket's parent directory must be `0700` (no group/other
//!   bits) and owned by the client's uid, and the socket must be ours, before
//!   connecting; after connecting the server's peer credentials must be ours too
//!   (stale-socket and squatting defence; a same-user attacker is out of scope,
//!   spec §14.1).
//! * The same rules serve the control and signing endpoints; the kind only selects
//!   the file name and the frame limit. ⟨M03⟩ The issuer kind is reserved and never
//!   bound ([`IssuerEndpointReserved`]; ADR-0008 Q1).
//! * Server identity: [`crate::session::ControlConnection::with_server_identity`]
//!   is kept (decision recorded with E13): the runtime (M01-U8) sets the
//!   environment ID and server `PeerInfo` once per listener.
//!
//! The injected-`stat` rules ([`PathFacts`], [`classify_existing`],
//! [`check_private_dir`], [`check_own_socket`]) are `#[doc(hidden)] pub` for the
//! `integration_ipc_unix` test target; they are not a supported API.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tokio::net::{UnixListener, UnixStream};

use crate::endpoint::{EndpointKind, ExpectedOwner, PeerIdentity, PeerRejected, verify_peer};

/// ⟨M03⟩ The typed refusal of `Listener::bind` for `EndpointKind::Issuer`, which is
/// reserved and never bound (ADR-0008 Q1; wave-0 verify E7). Carried inside the
/// returned `io::Error` (`ErrorKind::Unsupported`); recover it with
/// `io::Error::get_ref` and `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerEndpointReserved;

impl std::fmt::Display for IssuerEndpointReserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the issuer endpoint kind is reserved and is never bound")
    }
}

impl std::error::Error for IssuerEndpointReserved {}

impl From<IssuerEndpointReserved> for std::io::Error {
    fn from(e: IssuerEndpointReserved) -> Self {
        std::io::Error::new(std::io::ErrorKind::Unsupported, e)
    }
}

/// A bound, owner-only listener. Dropping it unlinks its socket if the path still
/// names the socket this listener created (same device and inode).
#[derive(Debug)]
pub struct Listener {
    kind: EndpointKind,
    inner: UnixListener,
    path: PathBuf,
    /// `(st_dev, st_ino)` of the socket this listener bound.
    bound: (u64, u64),
}

impl Listener {
    /// Create the directory if needed, verify ownership and mode, remove a dead
    /// socket of ours, bind, and restrict the socket to `0600`.
    ///
    /// Must be called inside a tokio runtime with I/O enabled.
    ///
    /// ⟨M03⟩ `EndpointKind::Issuer` is reserved and never bound (ADR-0008 Q1: the
    /// issuer child speaks over its stdio, never over a listener; wave-0 verify E7):
    /// it is refused with [`IssuerEndpointReserved`] (`ErrorKind::Unsupported`)
    /// before anything is created, checked or removed.
    pub fn bind(path: &Path, kind: EndpointKind) -> std::io::Result<Self> {
        if kind == EndpointKind::Issuer {
            return Err(IssuerEndpointReserved.into());
        }
        let uid = current_uid();
        let dir = parent_dir(path)?;
        ensure_private_dir(dir, uid)?;

        let existing = match fs::symlink_metadata(path) {
            Ok(meta) => Some(PathFacts::of(&meta)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        match classify_existing(existing, uid, || {
            std::os::unix::net::UnixStream::connect(path).map(drop)
        }) {
            Existing::Absent => {}
            Existing::DeadOurs => match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            },
            Existing::LiveOurs => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a live endpoint is already listening at this path",
                ));
            }
            Existing::ForeignOwner => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the existing endpoint belongs to another user; left in place",
                ));
            }
            Existing::NotASocket => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a non-socket file occupies the endpoint path; left in place",
                ));
            }
        }

        let inner = UnixListener::bind(path)?;
        let finish = || -> io::Result<(u64, u64)> {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            let meta = fs::symlink_metadata(path)?;
            let facts = PathFacts::of(&meta);
            if facts.kind != FileKind::Socket || facts.uid != uid || facts.mode & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "bound socket is not owner-only",
                ));
            }
            Ok((meta.dev(), meta.ino()))
        };
        match finish() {
            Ok(bound) => Ok(Self {
                kind,
                inner,
                path: path.to_path_buf(),
                bound,
            }),
            Err(e) => {
                drop(inner);
                let _ = fs::remove_file(path);
                Err(e)
            }
        }
    }

    /// Accept one connection and read its peer credentials. A peer that has
    /// already gone (for example another instance's liveness probe, which
    /// connects and closes) is skipped rather than reported as an error.
    pub async fn accept(&self) -> std::io::Result<(UnixStream, PeerIdentity)> {
        loop {
            let (stream, _) = self.inner.accept().await?;
            let cred = match stream.peer_cred() {
                Ok(cred) => cred,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotConnected | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            };
            let peer = PeerIdentity::Unix {
                uid: cred.uid(),
                gid: cred.gid(),
                pid: cred.pid(),
            };
            return Ok((stream, peer));
        }
    }

    /// Endpoint kind.
    #[must_use]
    pub fn kind(&self) -> EndpointKind {
        self.kind
    }

    /// Socket path this listener bound.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.bound
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Connect as a client after verifying the directory is ours and private, then
/// verify the server's peer credentials are ours too.
pub async fn connect(path: &Path) -> Result<UnixStream, ConnectError> {
    let uid = current_uid();
    let dir = parent_dir(path)?;
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            check_private_dir(&PathFacts::of(&meta), uid).map_err(|_| ConnectError::Insecure)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ConnectError::NotRunning),
        Err(e) => return Err(ConnectError::Io(e)),
    }
    match fs::symlink_metadata(path) {
        Ok(meta) => check_own_socket(&PathFacts::of(&meta), uid)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ConnectError::NotRunning),
        Err(e) => return Err(ConnectError::Io(e)),
    }
    let stream = UnixStream::connect(path)
        .await
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ConnectError::NotRunning,
            _ => ConnectError::Io(e),
        })?;
    let cred = stream.peer_cred().map_err(|_| PeerRejected::Unavailable)?;
    verify_peer(
        &PeerIdentity::Unix {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
        },
        &ExpectedOwner::Uid(uid),
    )?;
    Ok(stream)
}

/// Client-side connect failure.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// No runtime is listening (on-demand start may follow).
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

/// The runtime's own (effective) uid.
///
/// Obtained without `libc`/`unsafe`: the peer credentials of a freshly created
/// socket pair are the calling process's effective uid (`getpeereid` /
/// `SO_PEERCRED`), the same value a peer check on an accepted connection compares
/// against. Computed once on a dedicated thread (so it works inside or outside a
/// tokio runtime) and cached. If the probe fails the function returns `u32::MAX`
/// (`(uid_t)-1`, never a real user), so every ownership and peer check fails
/// closed.
#[must_use]
pub fn current_uid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(|| match probe_euid() {
        Ok(uid) => uid,
        Err(e) => {
            tracing::error!(error = %e, "could not determine the process uid; refusing all peers");
            u32::MAX
        }
    })
}

fn probe_euid() -> io::Result<u32> {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        rt.block_on(async {
            let (a, _b) = UnixStream::pair()?;
            Ok(a.peer_cred()?.uid())
        })
    })
    .join()
    .map_err(|_| io::Error::other("uid probe thread panicked"))?
}

fn parent_dir(path: &Path) -> io::Result<&Path> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "endpoint path must name a file inside a runtime directory",
            )
        })
}

/// Create `dir` (mode `0700`) if missing, then verify it is a real directory,
/// owned by `uid`, with no group/other permission bits. The check uses `fstat`
/// on an opened handle and requires it to be the same object the path names
/// without following symlinks.
fn ensure_private_dir(dir: &Path, uid: u32) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            // The umask may have removed owner bits; the leaf is ours and new.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e),
    }
    let lmeta = fs::symlink_metadata(dir)?;
    let handle = fs::File::open(dir)?;
    let fmeta = handle.metadata()?;
    if (lmeta.dev(), lmeta.ino()) != (fmeta.dev(), fmeta.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory changed while it was being checked",
        ));
    }
    check_private_dir(&PathFacts::of(&lmeta), uid)
        .and_then(|()| check_private_dir(&PathFacts::of(&fmeta), uid))
        .map_err(|p| io::Error::new(io::ErrorKind::PermissionDenied, p.to_string()))
}

/// File kind as far as the endpoint checks care.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A real directory.
    Dir,
    /// A Unix socket.
    Socket,
    /// A symbolic link (never followed).
    Symlink,
    /// Anything else.
    Other,
}

/// The `stat` fields the endpoint checks use. Separate from `fs::Metadata` so the
/// foreign-owner branches can be tested with injected values (changing a file's
/// owner needs root).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathFacts {
    /// File kind (`lstat`, symlinks not followed).
    pub kind: FileKind,
    /// Owner uid.
    pub uid: u32,
    /// Permission bits (`& 0o7777`).
    pub mode: u32,
}

impl PathFacts {
    /// Facts from `lstat`/`fstat` metadata.
    #[must_use]
    pub fn of(meta: &fs::Metadata) -> Self {
        let ft = meta.file_type();
        let kind = if ft.is_symlink() {
            FileKind::Symlink
        } else if ft.is_dir() {
            FileKind::Dir
        } else if ft.is_socket() {
            FileKind::Socket
        } else {
            FileKind::Other
        };
        Self {
            kind,
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
        }
    }
}

/// Why a runtime directory is not acceptable.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DirProblem {
    /// Not a real directory.
    #[error("runtime directory path is not a directory (or is a symlink)")]
    NotADirectory,
    /// Owned by another uid.
    #[error("runtime directory is owned by another user")]
    WrongOwner,
    /// Group or other permission bits set.
    #[error("runtime directory grants group or other access")]
    TooPermissive,
}

/// Pure directory rule: a real directory, ours, no group/other bits.
#[doc(hidden)]
pub fn check_private_dir(f: &PathFacts, uid: u32) -> Result<(), DirProblem> {
    if f.kind != FileKind::Dir {
        return Err(DirProblem::NotADirectory);
    }
    if f.uid != uid {
        return Err(DirProblem::WrongOwner);
    }
    if f.mode & 0o077 != 0 {
        return Err(DirProblem::TooPermissive);
    }
    Ok(())
}

/// Pure client rule for the socket file itself.
#[doc(hidden)]
pub fn check_own_socket(f: &PathFacts, uid: u32) -> Result<(), ConnectError> {
    if f.kind == FileKind::Socket && f.uid == uid && f.mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(ConnectError::Insecure)
    }
}

/// What occupies an endpoint path before `bind`.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Nothing there.
    Absent,
    /// Our socket, nobody listening: safe to unlink.
    DeadOurs,
    /// Our socket with a live listener (or an undetermined probe): leave it.
    LiveOurs,
    /// A socket owned by another uid: never probed, never unlinked.
    ForeignOwner,
    /// A regular file, directory, symlink or device: never unlinked.
    NotASocket,
}

/// Pure stale-socket rule. `probe` connects to the path; it is called only for a
/// socket we own.
#[doc(hidden)]
pub fn classify_existing(
    facts: Option<PathFacts>,
    uid: u32,
    probe: impl FnOnce() -> io::Result<()>,
) -> Existing {
    let Some(f) = facts else {
        return Existing::Absent;
    };
    if f.kind != FileKind::Socket {
        return Existing::NotASocket;
    }
    if f.uid != uid {
        return Existing::ForeignOwner;
    }
    match probe() {
        // Refused: nobody listens. NotFound: it vanished between lstat and probe.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Existing::DeadOurs
        }
        // Ok (someone answered) or any other error: do not delete what we cannot
        // prove dead.
        _ => Existing::LiveOurs,
    }
}
