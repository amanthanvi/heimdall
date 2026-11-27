//! The per-session K_mgmt agent (ADR-0012 §3.4, §5.2): an owner-only endpoint that serves one
//! [`MgmtSigner`] for the lifetime of one management session, named by the isolated
//! configuration's `IdentityAgent`. Same-user peers only (the transport's peer credentials,
//! checked again here by [`peer_admitted`]); stopped and removed when the session ends
//! ([`SessionAgent::stop`], or on drop).
//!
//! * **Unix:** a socket inside the session's own owner-only directory
//!   ([`SessionAgent::start`]). ⟨M06 W5 `w5r`⟩ That directory is an [`AgentDir`]: short,
//!   random, created exclusively under `/tmp` (on Linux an owner-only `$XDG_RUNTIME_DIR`),
//!   never under the Heimdall home, so the home's length cannot push the socket past
//!   `sun_path`. A start failure is classed by [`AgentFailure`] for the opener's reason.
//!   Windows is unchanged by this: a pipe name is not a path and has no such limit.
//!   ⟨M08 W4 SEC-3b, S2-06⟩ Bounded as the pipe agent is: at most
//!   [`MAX_SESSION_CONNECTIONS`] connections at once (a client beyond it is closed without an
//!   answer), each one the accept task's own, so stopping ends every one before the signer
//!   is dropped.
//! * **Windows** (ADR-0012 §2.6, the 2026-11-22 paragraph): a named pipe for the in-box
//!   OpenSSH ([`SessionAgent::start_pipe`]).
//!   - **Name:** `\\.\pipe\heimdall-<32 hex>` ([`session_pipe_name`]): the prefix and a
//!     token from the OS CSPRNG, nothing else (no user, host, environment or key material).
//!   - **Creation:** `heimdall_ipc::windows::Listener`: a protected owner-only DACL, remote
//!     clients rejected, and the first-instance flag, so a name another process already
//!     holds is refused instead of joined.
//!   - **Clients:** the listener returns only clients whose token user is this process's
//!     user; [`peer_admitted`] checks the SID it reports once more before anything is
//!     served.
//!   - **Bounds:** the agent-protocol server's (`heimdall_ipc::signing`): frames of at most
//!     `MAX_SIGNING_FRAME_BYTES`, the idle timeout, the listener's first-write bound, and at
//!     most [`MAX_SESSION_CONNECTIONS`] connections at once.
//!   - **Scope:** [`MgmtSigner`]'s: the identity list is K_mgmt alone, a signature is given
//!     only for a user-authentication request for the session's runner account and pinned
//!     host; every other request type answers `SSH_AGENT_FAILURE`. Nothing is forwarded,
//!     no key can be added, and nothing about the key or a request is written anywhere.
//!   - **Lifetime:** one management session. Stopping (or dropping) the agent ends every
//!     connection, closes every pipe instance and drops the signer, whose key bytes are
//!     zeroized on drop.
//!   - A pipe name is not a file: no path is opened, so there is no reparse point to follow.

use std::io;
use std::path::{Path, PathBuf};
#[cfg(any(unix, windows))]
use std::sync::Arc;

#[cfg(any(unix, windows))]
use heimdall_contract::provider::{EndpointKind as ProviderEndpointKind, EndpointRef};
#[cfg(any(unix, windows))]
use heimdall_ipc::endpoint::EndpointKind;
use heimdall_ipc::endpoint::PeerIdentity;
#[cfg(any(unix, windows))]
use heimdall_ipc::signing::{Signer, serve};
use tokio_util::sync::CancellationToken;

use super::MgmtSigner;

/// Win32 `ERROR_ACCESS_DENIED`: what a first pipe instance at a taken name is answered.
#[cfg(windows)]
const ERROR_ACCESS_DENIED: i32 = 5;

/// The prefix of a session agent's pipe name (the M04 pipe prefix).
pub const SESSION_PIPE_PREFIX: &str = r"\\.\pipe\heimdall-";

/// The random bytes in a session agent's pipe name (written as lowercase hex).
pub const SESSION_PIPE_TOKEN_BYTES: usize = 16;

/// Connections one session agent serves at once, on Windows and ⟨M08 W4 SEC-3b, S2-06⟩ on
/// Unix. One `ssh` authentication uses one; the rest are refused by closing them.
pub const MAX_SESSION_CONNECTIONS: usize = 8;

/// A new session-agent pipe name: [`SESSION_PIPE_PREFIX`] and
/// [`SESSION_PIPE_TOKEN_BYTES`] bytes from the OS CSPRNG as lowercase hex.
///
/// # Errors
/// The operating system's randomness is unavailable.
pub fn session_pipe_name() -> io::Result<String> {
    use std::fmt::Write as _;
    let mut token = [0u8; SESSION_PIPE_TOKEN_BYTES];
    crate::vault::SystemRng::fill(&mut token)
        .map_err(|_| io::Error::other("operating system randomness unavailable"))?;
    let mut name = String::from(SESSION_PIPE_PREFIX);
    for byte in token {
        let _ = write!(name, "{byte:02x}");
    }
    Ok(name)
}

/// Whether `name` has exactly the form [`session_pipe_name`] makes: the prefix, then the
/// token's lowercase hex digits, and nothing else.
#[must_use]
pub fn is_session_pipe_name(name: &str) -> bool {
    name.strip_prefix(SESSION_PIPE_PREFIX).is_some_and(|token| {
        token.len() == SESSION_PIPE_TOKEN_BYTES * 2
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Whose clients a session agent serves: the user that started it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentOwner {
    /// A Unix user ID.
    Uid(u32),
    /// A Windows user SID string (`S-1-…`).
    Sid(String),
}

/// Whether the agent serves `peer`: only a peer the transport identified as `owner`. A
/// peer of the other platform's kind, another user, or an empty SID is refused.
#[must_use]
pub fn peer_admitted(peer: &PeerIdentity, owner: &AgentOwner) -> bool {
    match (peer, owner) {
        (PeerIdentity::Unix { uid, .. }, AgentOwner::Uid(own)) => uid == own,
        (PeerIdentity::Windows { sid, .. }, AgentOwner::Sid(own)) => {
            !own.is_empty() && sid.eq_ignore_ascii_case(own)
        }
        _ => false,
    }
}

/// A running per-session agent.
#[derive(Debug)]
pub struct SessionAgent {
    path: PathBuf,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Tests only: whether the signer (and so the key) is still alive anywhere.
    #[cfg(test)]
    signer: std::sync::Weak<MgmtSigner>,
}

impl SessionAgent {
    /// Bind an owner-only socket at `path` (its directory is created owner-only when
    /// missing; a live or foreign socket there is refused) and serve `signer` to peers of
    /// this user until stopped. Must be called inside a tokio runtime.
    ///
    /// # Errors
    /// [`AgentPathTooLong`] (nothing created) for a path past
    /// `heimdall_ipc::unix::SOCKET_PATH_MAX`; otherwise the bind's I/O error.
    #[cfg(unix)]
    pub fn start(path: &Path, signer: MgmtSigner) -> io::Result<SessionAgent> {
        let bytes = path.as_os_str().len();
        let limit = heimdall_ipc::unix::SOCKET_PATH_MAX;
        if bytes > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                AgentPathTooLong { bytes, limit },
            ));
        }
        let listener = heimdall_ipc::unix::Listener::bind(path, EndpointKind::Signing)?;
        let stop = CancellationToken::new();
        let signer = Arc::new(signer);
        #[cfg(test)]
        let weak = Arc::downgrade(&signer);
        let signer: Arc<dyn Signer> = signer;
        let endpoint = EndpointRef {
            kind: ProviderEndpointKind::UnixSocket,
            locator: path.to_string_lossy().into_owned(),
        };
        let owner = AgentOwner::Uid(heimdall_ipc::unix::current_uid());
        let token = stop.clone();
        // ⟨M08 W4 SEC-3b, S2-06⟩ As the pipe agent: the served connections are this task's
        // own (a `JoinSet`, reaped as they end), at most [`MAX_SESSION_CONNECTIONS`] at once
        // (a client beyond it is closed without an answer), and all of them end before the
        // listener closes and the signer is dropped.
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = token.cancelled() => break,
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        if !peer_admitted(&peer, &owner)
                            || connections.len() >= MAX_SESSION_CONNECTIONS
                        {
                            drop(stream);
                            continue;
                        }
                        let signer = signer.clone();
                        let endpoint = endpoint.clone();
                        let token = token.clone();
                        connections.spawn(async move {
                            let _ = serve(stream, peer, endpoint, signer, token).await;
                        });
                    }
                }
            }
            connections.shutdown().await;
            drop(listener);
            drop(signer);
        });
        Ok(SessionAgent {
            path: path.to_path_buf(),
            stop,
            task: Some(task),
            #[cfg(test)]
            signer: weak,
        })
    }

    /// Not available on this platform (module docs: Windows uses
    /// [`SessionAgent::start_pipe`]).
    ///
    /// # Errors
    /// Always `Unsupported`.
    #[cfg(not(unix))]
    pub fn start(path: &Path, signer: MgmtSigner) -> io::Result<SessionAgent> {
        let _ = (path, signer);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the management key agent has no socket form on this platform",
        ))
    }

    /// ⟨M06 W5; ADR-0012 §2.6⟩ Create a named pipe under a new [`session_pipe_name`] and
    /// serve `signer` on it to clients of this user until stopped (module docs). Must be
    /// called inside a tokio runtime.
    ///
    /// # Errors
    /// The user's SID or the randomness could not be read, or the pipe could not be
    /// created (a name that already exists is refused, never joined).
    #[cfg(windows)]
    pub fn start_pipe(signer: MgmtSigner) -> io::Result<SessionAgent> {
        Self::start_pipe_from(signer, session_pipe_name)
    }

    /// ⟨M06 W5 `w5t`, ruling 2026-11-23⟩ [`SessionAgent::start_pipe`] under names from
    /// `next_name`: a name another process already holds is skipped for a fresh one, at most
    /// [`AGENT_DIR_ATTEMPTS`] names in all, as an agent directory's is; what holds it is
    /// never joined or touched. After that the start is "in use"
    /// ([`AgentFailure::AddressInUse`]). Every other failure is returned at once.
    #[cfg(windows)]
    fn start_pipe_from(
        signer: MgmtSigner,
        mut next_name: impl FnMut() -> io::Result<String>,
    ) -> io::Result<SessionAgent> {
        let owner = heimdall_ipc::windows::current_user_sid()?;
        let mut attempt = 1;
        let (name, listener) = loop {
            let name = next_name()?;
            match Self::bind_pipe(&name) {
                Ok(listener) => break (name, listener),
                Err(e)
                    if attempt < AGENT_DIR_ATTEMPTS
                        && AgentFailure::of(&e) == AgentFailure::AddressInUse =>
                {
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        };
        Ok(Self::serve_pipe(
            &name,
            listener,
            signer,
            AgentOwner::Sid(owner),
        ))
    }

    /// [`SessionAgent::start_pipe`] at `name`, serving only `owner` (always this user
    /// outside tests; the tests name another SID to see the refusal).
    #[cfg(all(windows, test))]
    fn start_pipe_named(
        name: &str,
        signer: MgmtSigner,
        owner: AgentOwner,
    ) -> io::Result<SessionAgent> {
        let listener = Self::bind_pipe(name)?;
        Ok(Self::serve_pipe(name, listener, signer, owner))
    }

    /// The pipe's first instance at `name`, refused when the name is not a session agent's
    /// or another process already holds it.
    #[cfg(windows)]
    fn bind_pipe(name: &str) -> io::Result<heimdall_ipc::windows::Listener> {
        if !is_session_pipe_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a session agent pipe name",
            ));
        }
        // The pipe's DACL always names this process's own user, whatever the owner served.
        let sid = heimdall_ipc::windows::current_user_sid()?;
        // ⟨M06 W5 `w5t`, ruling 2026-11-23⟩ With the first-instance flag, `CreateNamedPipe`
        // answers `ERROR_ACCESS_DENIED` when the name already exists (under any owner): on
        // this call that means "in use", never a denied directory. Any other error keeps its
        // own kind.
        heimdall_ipc::windows::Listener::bind(name, EndpointKind::Signing, &sid).map_err(|e| {
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another process holds this pipe name",
                )
            } else {
                e
            }
        })
    }

    /// Serve `signer` to `owner` on `listener` (bound at `name`).
    #[cfg(windows)]
    fn serve_pipe(
        name: &str,
        listener: heimdall_ipc::windows::Listener,
        signer: MgmtSigner,
        owner: AgentOwner,
    ) -> SessionAgent {
        let stop = CancellationToken::new();
        let signer = Arc::new(signer);
        #[cfg(test)]
        let weak = Arc::downgrade(&signer);
        let signer: Arc<dyn Signer> = signer;
        let endpoint = EndpointRef {
            kind: ProviderEndpointKind::NamedPipe,
            locator: name.to_owned(),
        };
        let token = stop.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = token.cancelled() => break,
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => {
                        // A listener that cannot keep an instance waiting ends the agent:
                        // the session then fails to authenticate, which is the closed side.
                        let Ok((stream, peer)) = accepted else { break };
                        if !peer_admitted(&peer, &owner)
                            || connections.len() >= MAX_SESSION_CONNECTIONS
                        {
                            drop(stream);
                            continue;
                        }
                        let signer = signer.clone();
                        let endpoint = endpoint.clone();
                        let token = token.clone();
                        connections.spawn(async move {
                            let _ = serve(stream, peer, endpoint, signer, token).await;
                        });
                    }
                }
            }
            // Every connection ended and reaped, every instance closed, then the key.
            connections.shutdown().await;
            drop(listener);
            drop(signer);
        });
        SessionAgent {
            path: PathBuf::from(name),
            stop,
            task: Some(task),
            #[cfg(test)]
            signer: weak,
        }
    }

    /// The socket path, or on Windows the pipe name (`\\.\pipe\heimdall-<token>`): the
    /// `IdentityAgent` the configuration names.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stop serving and wait until the listener is closed: the socket is unlinked; on
    /// Windows every connection has ended, every pipe instance is closed and the signer is
    /// dropped.
    pub async fn stop(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for SessionAgent {
    fn drop(&mut self) {
        self.stop.cancel();
        // Windows: the accept task owns every connection, so ending it here closes the
        // pipe and drops the signer even if the task is never polled again. (The Unix
        // task unlinks its socket when it sees the cancellation.)
        #[cfg(windows)]
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// ⟨M06 W5 `w5r`⟩ Why a session agent could not start, as the opener reports it (the
/// reasons `mgmt_agent_*`, ADR-0006 §18.9). Read from the start's I/O error by
/// [`AgentFailure::of`]; never from a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentFailure {
    /// The socket path would exceed the platform's limit ([`AgentPathTooLong`]).
    PathTooLong,
    /// The operating system denied creating the directory, socket or pipe, or what is
    /// there is not owner-only.
    PermissionDenied,
    /// The name is already taken (a file, directory, link, live socket or pipe instance);
    /// what is there is left untouched.
    AddressInUse,
    /// Any other failure (randomness, the user's identity, other I/O).
    Other,
}

impl AgentFailure {
    /// The class of a [`SessionAgent`] or [`AgentDir`] start error.
    #[must_use]
    pub fn of(e: &io::Error) -> AgentFailure {
        if e.get_ref()
            .is_some_and(|inner| inner.is::<AgentPathTooLong>())
            || e.kind() == io::ErrorKind::InvalidFilename
        {
            return AgentFailure::PathTooLong;
        }
        match e.kind() {
            io::ErrorKind::PermissionDenied => AgentFailure::PermissionDenied,
            io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists => AgentFailure::AddressInUse,
            _ => AgentFailure::Other,
        }
    }
}

/// ⟨M06 W5 `w5r`⟩ The refusal of an agent directory whose socket path would not fit the
/// platform's `sun_path`: refused before anything is created. Carried inside an
/// `io::Error` (`InvalidInput`); [`AgentFailure::of`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the session agent's socket path would be {bytes} bytes; this platform allows {limit}")]
pub struct AgentPathTooLong {
    /// The length the socket path would have.
    pub bytes: usize,
    /// The platform's limit.
    pub limit: usize,
}

/// ⟨M06 W5 `w5r`⟩ The name prefix of a session agent's directory; the rest is a random
/// 16-hex endpoint tag (`crate::endpoints::EndpointTag`), never derived from anything.
pub const AGENT_DIR_PREFIX: &str = "heimdall-mgmt-";

/// The session agent's socket in its [`AgentDir`].
pub const AGENT_SOCKET: &str = "a.sock";

/// The confirming probes' disposable agent's socket in the same [`AgentDir`].
pub const PROBE_SOCKET: &str = "p.sock";

/// The only names an [`AgentDir`] ever holds, and so the only ones its removal (or the
/// sweep of a crash's leftover) removes.
#[cfg(unix)]
const AGENT_DIR_FILES: [&str; 2] = [AGENT_SOCKET, PROBE_SOCKET];

/// ⟨M06 W5 `w5t`⟩ How many fresh random names [`AgentDir::create_fresh`] tries before a
/// taken name is reported (`mgmt_agent_address_in_use`).
pub const AGENT_DIR_ATTEMPTS: usize = 3;

/// How long a leftover agent directory must have been unchanged before
/// [`sweep_stale_agent_dirs`] removes it: a session that is creating its directory or
/// binding its socket at that moment changed it just now, so it is never mistaken for a
/// crash's leftover.
pub const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// ⟨M06 W5 `w5r`; ADR-0012 §3.4⟩ A management session's short, owner-only agent
/// directory, `<base>/heimdall-mgmt-<16 hex>/` ([`agent_dir_base`]): the session agent's
/// socket ([`AGENT_SOCKET`]) and the probes' ([`PROBE_SOCKET`]) live here, not under the
/// Heimdall home, so a long home path can never push a socket past `sun_path`.
///
/// The OpenSSH agent's precedent (a random `0700` directory under `/tmp`), built on the
/// binding endpoints' rules (`crate::endpoints`): a random tag from the OS CSPRNG, the
/// directory created **exclusively** and checked by `heimdall_ipc::unix`
/// (`create_private_dir_exclusive`: real directory, ours, `0700`, `lstat` = `fstat`), the
/// socket bound by `heimdall_ipc::unix::Listener` inside it. Anything already at the name
/// is refused, never reused, followed or removed. Dropping it removes only its own sockets
/// and then the directory if it is empty and still the one it created.
#[cfg(unix)]
#[derive(Debug)]
pub struct AgentDir {
    path: PathBuf,
    identity: (u64, u64),
}

#[cfg(unix)]
impl AgentDir {
    /// Sweep a crash's leftovers under [`agent_dir_base`] ([`sweep_stale_agent_dirs`]),
    /// then create a new agent directory there under a fresh random tag
    /// ([`AgentDir::create_fresh`]).
    ///
    /// # Errors
    /// [`AgentDir::create_fresh`]'s.
    pub fn create() -> io::Result<AgentDir> {
        let base = agent_dir_base(std::env::var_os("XDG_RUNTIME_DIR"));
        sweep_stale_agent_dirs(&base, STALE_AFTER);
        Self::create_fresh(&base, || {
            crate::endpoints::EndpointTag::generate()
                .map(|tag| tag.as_str().to_owned())
                .map_err(|_| io::Error::other("operating system randomness unavailable"))
        })
    }

    /// ⟨M06 W5 `w5t`⟩ [`AgentDir::create_in`] under a tag from `next_tag`; a name that is
    /// already taken ([`AgentFailure::AddressInUse`]: what is there is left untouched) is
    /// skipped for a fresh tag, at most [`AGENT_DIR_ATTEMPTS`] times in all. Every other
    /// failure is returned at once: a fresh name cannot fix it.
    ///
    /// # Errors
    /// The last attempt's [`AgentDir::create_in`] error, or `next_tag`'s.
    pub fn create_fresh(
        base: &Path,
        mut next_tag: impl FnMut() -> io::Result<String>,
    ) -> io::Result<AgentDir> {
        let mut attempt = 1;
        loop {
            match Self::create_in(base, &next_tag()?) {
                Err(e)
                    if attempt < AGENT_DIR_ATTEMPTS
                        && AgentFailure::of(&e) == AgentFailure::AddressInUse =>
                {
                    attempt += 1;
                }
                done => return done,
            }
        }
    }

    /// Create `<base>/heimdall-mgmt-<tag>/` exclusively.
    ///
    /// # Errors
    /// [`AgentPathTooLong`] (before anything is created) when the socket path would
    /// exceed `heimdall_ipc::unix::SOCKET_PATH_MAX`; `InvalidInput` for a tag that is not
    /// 16 lowercase hex characters; `AlreadyExists` when anything is at the name;
    /// `PermissionDenied` when the base refuses it or the result is not owner-only.
    pub fn create_in(base: &Path, tag: &str) -> io::Result<AgentDir> {
        if crate::endpoints::EndpointTag::parse(tag).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an endpoint tag",
            ));
        }
        let path = base.join(format!("{AGENT_DIR_PREFIX}{tag}"));
        let bytes = path.join(AGENT_SOCKET).as_os_str().len();
        let limit = heimdall_ipc::unix::SOCKET_PATH_MAX;
        if bytes > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                AgentPathTooLong { bytes, limit },
            ));
        }
        let identity = heimdall_ipc::unix::create_private_dir_exclusive(&path)?;
        Ok(AgentDir { path, identity })
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path of `name` ([`AGENT_SOCKET`] or [`PROBE_SOCKET`]) in it.
    #[must_use]
    pub fn socket(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

#[cfg(unix)]
impl Drop for AgentDir {
    fn drop(&mut self) {
        remove_agent_dir(&self.path, self.identity);
    }
}

/// ⟨M06 W5 `w5r`⟩ Where agent directories are made: on Linux `$XDG_RUNTIME_DIR` when it
/// is set, absolute and an owner-only directory of this user (checked without following a
/// link); everywhere else, and when it is not, `/tmp`.
#[cfg(unix)]
#[must_use]
pub fn agent_dir_base(xdg_runtime_dir: Option<std::ffi::OsString>) -> PathBuf {
    if cfg!(any(target_os = "linux", target_os = "android"))
        && let Some(dir) = xdg_runtime_dir.map(PathBuf::from)
        && dir.is_absolute()
        && std::fs::symlink_metadata(&dir).is_ok_and(|m| {
            heimdall_ipc::unix::check_private_dir(
                &heimdall_ipc::unix::PathFacts::of(&m),
                heimdall_ipc::unix::current_uid(),
            )
            .is_ok()
        })
    {
        return dir;
    }
    PathBuf::from("/tmp")
}

/// ⟨M06 W5 `w5r`⟩ Remove the agent directories under `base` a crashed session left: only
/// an entry named exactly `heimdall-mgmt-<16 hex>` that is a real directory (never a
/// link), owned by this user, mode exactly `0700`, unchanged for `stale_after`, holding
/// nothing but [`AGENT_SOCKET`] and [`PROBE_SOCKET`], each a socket of this user that no
/// one listens on (`heimdall_ipc::unix::classify_existing`: dead). Anything else is left
/// as it is. Best effort: an error skips the entry.
#[cfg(unix)]
pub fn sweep_stale_agent_dirs(base: &Path, stale_after: std::time::Duration) {
    use heimdall_ipc::unix::{Existing, FileKind, PathFacts, classify_existing, current_uid};
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    let uid = current_uid();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(tag) = name.to_str().and_then(|n| n.strip_prefix(AGENT_DIR_PREFIX)) else {
            continue;
        };
        if crate::endpoints::EndpointTag::parse(tag).is_none() {
            continue;
        }
        let dir = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        let old = meta
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= stale_after);
        if !old || meta.permissions().mode() & 0o7777 != 0o700 {
            continue;
        }
        let Ok(identity) = heimdall_ipc::unix::verify_private_dir(&dir, uid) else {
            continue;
        };
        let Ok(inside) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut dead = true;
        for file in inside {
            let Ok(file) = file else {
                dead = false;
                break;
            };
            let known = file
                .file_name()
                .to_str()
                .is_some_and(|n| AGENT_DIR_FILES.contains(&n));
            let path = file.path();
            let facts = std::fs::symlink_metadata(&path)
                .ok()
                .map(|m| PathFacts::of(&m));
            let is_dead = facts.is_some_and(|f| f.kind == FileKind::Socket)
                && classify_existing(facts, uid, || {
                    std::os::unix::net::UnixStream::connect(&path).map(drop)
                }) == Existing::DeadOurs;
            if !known || !is_dead {
                dead = false;
                break;
            }
        }
        if dead {
            remove_agent_dir(&dir, identity);
        }
    }
}

/// Remove `dir`'s own sockets ([`AGENT_DIR_FILES`], each only if it is a socket of this
/// user, never followed), then `dir` itself if it is empty, a real owner-only directory
/// of this user and still the object `identity` names. Never recursive.
#[cfg(unix)]
fn remove_agent_dir(dir: &Path, identity: (u64, u64)) {
    use heimdall_ipc::unix::{FileKind, PathFacts, current_uid};
    let uid = current_uid();
    match heimdall_ipc::unix::verify_private_dir(dir, uid) {
        Ok(found) if found == identity => {}
        _ => return,
    }
    for name in AGENT_DIR_FILES {
        let path = dir.join(name);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| {
            let f = PathFacts::of(&m);
            f.kind == FileKind::Socket && f.uid == uid
        }) {
            let _ = std::fs::remove_file(&path);
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// What the tests of both platforms send and read: agent frames and a user-authentication
/// request to sign.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod wire {
    use ssh_encoding::Encode as _;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

    /// `SSH_AGENT_FAILURE`.
    pub(super) const FAILURE: u8 = 5;
    /// `SSH_AGENTC_REQUEST_IDENTITIES`.
    pub(super) const REQUEST_IDENTITIES: u8 = 11;
    /// `SSH_AGENT_IDENTITIES_ANSWER`.
    pub(super) const IDENTITIES_ANSWER: u8 = 12;
    /// `SSH_AGENTC_SIGN_REQUEST`.
    pub(super) const SIGN_REQUEST: u8 = 13;
    /// `SSH_AGENT_SIGN_RESPONSE`.
    pub(super) const SIGN_RESPONSE: u8 = 14;

    /// The data of a `publickey` user-authentication request for `user` with `key_blob`.
    pub(super) fn userauth(user: &str, key_blob: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        [7u8; 32].as_slice().encode(&mut out).unwrap();
        out.push(50);
        user.encode(&mut out).unwrap();
        "ssh-connection".encode(&mut out).unwrap();
        "publickey".encode(&mut out).unwrap();
        out.push(1);
        "ssh-ed25519".encode(&mut out).unwrap();
        key_blob.encode(&mut out).unwrap();
        out
    }

    /// A sign request's payload: type, key blob, data, flags.
    pub(super) fn sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut out = vec![SIGN_REQUEST];
        key_blob.encode(&mut out).unwrap();
        data.encode(&mut out).unwrap();
        out.extend_from_slice(&flags.to_be_bytes());
        out
    }

    /// Send one frame and read one answer: `None` when the peer closed instead.
    pub(super) async fn exchange<S>(stream: &mut S, payload: &[u8]) -> Option<Vec<u8>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let len = u32::try_from(payload.len()).unwrap();
        stream.write_all(&len.to_be_bytes()).await.ok()?;
        stream.write_all(payload).await.ok()?;
        read_answer(stream).await
    }

    /// Read one answer frame: `None` when the peer closed (or broke the pipe) instead.
    pub(super) async fn read_answer<S>(stream: &mut S) -> Option<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await.ok()?;
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).await.ok()?;
        Some(body)
    }

    /// The key blobs an identities answer lists.
    pub(super) fn listed(answer: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(answer[0], IDENTITIES_ANSWER);
        let count = u32::from_be_bytes(answer[1..5].try_into().unwrap());
        let mut at = 5;
        let mut blobs = Vec::new();
        for _ in 0..count {
            let mut field = || {
                let n = u32::from_be_bytes(answer[at..at + 4].try_into().unwrap()) as usize;
                let bytes = answer[at + 4..at + 4 + n].to_vec();
                at += 4 + n;
                bytes
            };
            blobs.push(field());
            let _comment = field();
        }
        assert_eq!(at, answer.len(), "nothing after the listed identities");
        blobs
    }

    /// Every request the agent protocol and its OpenSSH extensions define other than list
    /// and sign, as well-formed as a payload needs to be to reach the dispatcher, with its
    /// name. The agent must answer each with `SSH_AGENT_FAILURE`.
    pub(super) fn out_of_scope_requests(key_blob: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut requests: Vec<(String, Vec<u8>)> = Vec::new();
        // Every type byte but the two served ones, as a bare request.
        for kind in 0..=u8::MAX {
            if kind != REQUEST_IDENTITIES && kind != SIGN_REQUEST {
                requests.push((format!("bare type {kind}"), vec![kind]));
            }
        }
        // The key-changing and locking requests with a body.
        for (name, kind) in [
            ("add identity", 17u8),
            ("remove identity", 18),
            ("remove all identities", 19),
            ("add smartcard key", 20),
            ("remove smartcard key", 21),
            ("lock", 22),
            ("unlock", 23),
            ("add identity constrained", 25),
            ("add smartcard key constrained", 26),
        ] {
            let mut payload = vec![kind];
            "ssh-ed25519".encode(&mut payload).unwrap();
            key_blob.encode(&mut payload).unwrap();
            requests.push((name.to_owned(), payload));
        }
        // Extensions, the session bind among them (OpenSSH continues without one).
        for name in [
            "session-bind@openssh.com",
            "query",
            "forward@example.invalid",
        ] {
            let mut payload = vec![27u8];
            name.encode(&mut payload).unwrap();
            key_blob.encode(&mut payload).unwrap();
            requests.push((format!("extension {name}"), payload));
        }
        // A list request with trailing bytes is not a list request.
        requests.push(("list with a body".to_owned(), vec![REQUEST_IDENTITIES, 0]));
        requests
    }
}

/// Platform-neutral: the pipe name's form, the peer check, and the protocol scope and
/// framing bounds of exactly what the agent serves ([`MgmtSigner`] behind
/// `heimdall_ipc::signing::serve`), over an in-memory stream.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES;
    use heimdall_contract::provider::{EndpointKind as ProviderEndpointKind, EndpointRef};
    use heimdall_ipc::signing::{IDLE_TIMEOUT_MS, Signer, serve};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    use super::super::MgmtKey;
    use super::wire::{
        FAILURE, REQUEST_IDENTITIES, SIGN_RESPONSE, exchange, listed, out_of_scope_requests,
        read_answer, sign_request, userauth,
    };
    use super::*;

    const ACCOUNT: &str = "runner";

    /// One served connection over an in-memory stream, as the agent serves a pipe client.
    fn served() -> (
        DuplexStream,
        Vec<u8>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let key = MgmtKey::generate().unwrap();
        let blob = key.public().unwrap().blob;
        let signer: Arc<dyn Signer> =
            Arc::new(MgmtSigner::new(key, [ACCOUNT.to_owned()], []).unwrap());
        let (client, server) = tokio::io::duplex(MAX_SIGNING_FRAME_BYTES + 64);
        let peer = PeerIdentity::Windows {
            sid: "S-1-5-21-1-2-3-1001".into(),
            pid: None,
        };
        let endpoint = EndpointRef {
            kind: ProviderEndpointKind::NamedPipe,
            locator: format!("{SESSION_PIPE_PREFIX}{}", "0".repeat(32)),
        };
        let task = tokio::spawn(serve(
            server,
            peer,
            endpoint,
            signer,
            CancellationToken::new(),
        ));
        (client, blob, task)
    }

    #[test]
    fn session_pipe_names_carry_only_the_prefix_and_a_random_token() {
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            let name = session_pipe_name().unwrap();
            assert!(is_session_pipe_name(&name), "{name}");
            assert_eq!(
                name.len(),
                SESSION_PIPE_PREFIX.len() + 2 * SESSION_PIPE_TOKEN_BYTES
            );
            assert!(seen.insert(name), "a token repeated");
        }
        assert_eq!(SESSION_PIPE_PREFIX, r"\\.\pipe\heimdall-");
        let token = "0123456789abcdef0123456789abcdef";
        assert!(is_session_pipe_name(&format!(
            "{SESSION_PIPE_PREFIX}{token}"
        )));
        for bad in [
            String::new(),
            SESSION_PIPE_PREFIX.to_owned(),
            format!("{SESSION_PIPE_PREFIX}{}", &token[1..]),
            format!("{SESSION_PIPE_PREFIX}{token}0"),
            format!("{SESSION_PIPE_PREFIX}{token}-signing"),
            format!("{SESSION_PIPE_PREFIX}{}", token.to_uppercase()),
            format!("{SESSION_PIPE_PREFIX}alice-{}", &token[6..]),
            format!("{SESSION_PIPE_PREFIX}{}\\x", &token[2..]),
            format!("//./pipe/heimdall-{token}"),
            format!(r"\\.\pipe\other-{token}"),
            format!(r"\\server\pipe\heimdall-{token}"),
            format!(r"C:\pipe\heimdall-{token}"),
        ] {
            assert!(!is_session_pipe_name(&bad), "{bad}");
        }
    }

    #[test]
    fn peer_check_admits_only_the_owner() {
        let sid = "S-1-5-21-1-2-3-1001";
        let windows = |sid: &str| PeerIdentity::Windows {
            sid: sid.to_owned(),
            pid: Some(4),
        };
        let unix = |uid: u32| PeerIdentity::Unix {
            uid,
            gid: 0,
            pid: None,
        };
        let owner = AgentOwner::Sid(sid.to_owned());
        assert!(peer_admitted(&windows(sid), &owner));
        assert!(peer_admitted(&windows(&sid.to_lowercase()), &owner));
        for other in [
            "S-1-5-21-1-2-3-1002",
            "S-1-5-18",
            "S-1-5-7",
            "S-1-1-0",
            "S-1-5-21-1-2-3-100",
            "S-1-5-21-1-2-3-10011",
            "",
        ] {
            assert!(!peer_admitted(&windows(other), &owner), "{other}");
        }
        assert!(!peer_admitted(&unix(0), &owner));
        assert!(!peer_admitted(
            &windows(""),
            &AgentOwner::Sid(String::new())
        ));
        assert!(peer_admitted(&unix(501), &AgentOwner::Uid(501)));
        assert!(!peer_admitted(&unix(0), &AgentOwner::Uid(501)));
        assert!(!peer_admitted(&unix(502), &AgentOwner::Uid(501)));
        assert!(!peer_admitted(&windows(sid), &AgentOwner::Uid(501)));
    }

    /// The scope (ADR-0012 §2.6): list answers K_mgmt alone; sign answers only the bound
    /// purpose; every other request answers `SSH_AGENT_FAILURE` and changes nothing.
    #[tokio::test]
    async fn agent_scope_is_list_and_purpose_bound_sign_for_k_mgmt_only() {
        let (mut client, blob, _task) = served();
        let list = exchange(&mut client, &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob.clone()]);

        let good = sign_request(&blob, &userauth(ACCOUNT, &blob), 0);
        let signed = exchange(&mut client, &good).await.unwrap();
        assert_eq!(signed[0], SIGN_RESPONSE);

        let other = MgmtKey::generate().unwrap().public().unwrap().blob;
        for (why, request) in [
            (
                "another account",
                sign_request(&blob, &userauth("root", &blob), 0),
            ),
            (
                "another key in the request",
                sign_request(&blob, &userauth(ACCOUNT, &other), 0),
            ),
            (
                "another key asked of the agent",
                sign_request(&other, &userauth(ACCOUNT, &other), 0),
            ),
            (
                "a signature flag",
                sign_request(&blob, &userauth(ACCOUNT, &blob), 2),
            ),
            (
                "data that is not a user-authentication request",
                sign_request(&blob, b"SSHSIG\0\0\0\x03git", 0),
            ),
            ("an empty sign request", vec![wire::SIGN_REQUEST]),
        ] {
            let answer = exchange(&mut client, &request).await.unwrap();
            assert_eq!(answer, vec![FAILURE], "{why}");
        }

        let requests = out_of_scope_requests(&blob);
        assert!(requests.len() > 254);
        for (name, request) in requests {
            let answer = exchange(&mut client, &request).await;
            assert_eq!(answer, Some(vec![FAILURE]), "{name}");
        }

        // Nothing was added, removed or locked: the list and the signature are as before.
        let list = exchange(&mut client, &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob.clone()]);
        assert_eq!(
            exchange(&mut client, &good).await.unwrap()[0],
            SIGN_RESPONSE
        );
    }

    /// Frames are bounded from their header: a declared length of zero or above the limit
    /// closes the connection with no answer, before any body is read; the largest allowed
    /// frame is read and answered.
    #[tokio::test]
    async fn frames_are_bounded_and_violations_close_without_an_answer() {
        for declared in [
            0u32,
            u32::try_from(MAX_SIGNING_FRAME_BYTES).unwrap() + 1,
            u32::MAX,
        ] {
            let (mut client, _blob, task) = served();
            client.write_all(&declared.to_be_bytes()).await.unwrap();
            assert_eq!(read_answer(&mut client).await, None, "{declared}");
            let end = task.await.unwrap();
            assert_eq!(
                end.unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{declared}"
            );
        }
        // The largest frame: read whole, then refused as a request (an unknown type).
        let (mut client, _blob, _task) = served();
        let mut largest = vec![0u8; MAX_SIGNING_FRAME_BYTES];
        largest[0] = 200;
        assert_eq!(exchange(&mut client, &largest).await, Some(vec![FAILURE]));
        // A frame cut short by the client's close is a violation, not a request.
        let (mut client, _blob, task) = served();
        client.write_all(&[0, 0, 0, 9, 13, 0]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    /// Reads are bounded in time: a client that sends part of a frame and then nothing is
    /// closed at the idle bound with no answer.
    #[tokio::test(start_paused = true)]
    async fn a_silent_client_is_closed_at_the_idle_bound() {
        let (mut client, _blob, task) = served();
        client.write_all(&[0, 0, 0, 9, 13]).await.unwrap();
        let started = tokio::time::Instant::now();
        assert_eq!(read_answer(&mut client).await, None);
        let waited = started.elapsed();
        assert!(task.await.unwrap().is_ok());
        assert_eq!(waited.as_millis(), u128::from(IDLE_TIMEOUT_MS));
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod unix_tests {
    use super::super::MgmtKey;
    use super::*;

    /// The agent lists exactly K_mgmt to a same-user client and is gone after `stop`.
    #[tokio::test]
    async fn serves_k_mgmt_then_unlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("agent.sock");
        let key = MgmtKey::generate().unwrap();
        let blob = key.public().unwrap().blob;
        let agent = SessionAgent::start(&path, MgmtSigner::new(key, ["u".to_owned()], []).unwrap())
            .unwrap();
        assert!(agent.signer.upgrade().is_some());
        let mut client = tokio::net::UnixStream::connect(agent.path()).await.unwrap();
        let answer = wire::exchange(&mut client, &[wire::REQUEST_IDENTITIES])
            .await
            .unwrap();
        assert_eq!(wire::listed(&answer), vec![blob]);
        drop(client);
        agent.stop().await;
        assert!(!path.exists(), "the socket is unlinked");
    }

    /// ⟨M08 W4 SEC-3b, S2-06⟩ The Unix agent's connections are bounded as the Windows
    /// pipe agent's are: beyond [`MAX_SESSION_CONNECTIONS`] connections held open at once,
    /// a client is closed without an answer, and a served one keeps working. `stop` ends
    /// every served connection (they are the agent's tasks, not detached ones) before it
    /// returns, and only then is the signer, so the key, dropped.
    #[tokio::test]
    async fn unix_connections_beyond_the_bound_are_closed_and_stop_ends_every_one() {
        let settle = std::time::Duration::from_secs(5);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("agent.sock");
        let key = MgmtKey::generate().unwrap();
        let blob = key.public().unwrap().blob;
        let agent = SessionAgent::start(&path, MgmtSigner::new(key, ["u".to_owned()], []).unwrap())
            .unwrap();
        let mut open = Vec::new();
        for _ in 0..MAX_SESSION_CONNECTIONS {
            let mut client = tokio::net::UnixStream::connect(agent.path()).await.unwrap();
            let list = wire::exchange(&mut client, &[wire::REQUEST_IDENTITIES])
                .await
                .unwrap();
            assert_eq!(wire::listed(&list), vec![blob.clone()]);
            open.push(client);
        }
        let mut extra = tokio::net::UnixStream::connect(agent.path()).await.unwrap();
        let answer = tokio::time::timeout(
            settle,
            wire::exchange(&mut extra, &[wire::REQUEST_IDENTITIES]),
        )
        .await
        .unwrap();
        assert_eq!(answer, None, "a connection beyond the bound was served");
        let list = wire::exchange(&mut open[0], &[wire::REQUEST_IDENTITIES])
            .await
            .unwrap();
        assert_eq!(wire::listed(&list), vec![blob]);
        // Stopping ends every served connection and then drops the signer.
        let weak = agent.signer.clone();
        tokio::time::timeout(settle, agent.stop()).await.unwrap();
        assert!(
            weak.upgrade().is_none(),
            "the signer outlived the agent's stop"
        );
        for client in &mut open {
            let answer =
                tokio::time::timeout(settle, wire::exchange(client, &[wire::REQUEST_IDENTITIES]))
                    .await
                    .unwrap();
            assert_eq!(
                answer, None,
                "a served connection outlived the agent's stop"
            );
        }
    }

    use std::os::unix::fs::PermissionsExt as _;

    const TAG: &str = "0123456789abcdef";

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn signer() -> MgmtSigner {
        MgmtSigner::new(MgmtKey::generate().unwrap(), ["u".to_owned()], []).unwrap()
    }

    /// ⟨M06 W5 `w5r`⟩ The session's agent directory: short, owner-only, under the base
    /// (`/tmp` or an owner-only `$XDG_RUNTIME_DIR`); the agent serves in it, and after the
    /// session (the agent and the directory dropped) nothing is left.
    #[tokio::test]
    async fn the_agent_directory_is_short_owner_only_and_gone_after_the_session() {
        let dir = AgentDir::create().unwrap();
        let base = agent_dir_base(std::env::var_os("XDG_RUNTIME_DIR"));
        assert_eq!(dir.path().parent(), Some(base.as_path()));
        let name = dir.path().file_name().unwrap().to_str().unwrap().to_owned();
        assert!(name.starts_with(AGENT_DIR_PREFIX), "{name}");
        assert_eq!(mode(dir.path()), 0o700);
        let socket = dir.socket(AGENT_SOCKET);
        assert!(socket.as_os_str().len() <= heimdall_ipc::unix::SOCKET_PATH_MAX);
        let agent = SessionAgent::start(&socket, signer()).unwrap();
        tokio::net::UnixStream::connect(&socket).await.unwrap();
        let probe = tokio::net::UnixListener::bind(dir.socket(PROBE_SOCKET)).unwrap();
        let path = dir.path().to_path_buf();
        // As the session's drop does: the agent and the probe listener dropped (their
        // sockets may still be there), then the directory.
        drop(probe);
        drop(agent);
        drop(dir);
        assert!(
            std::fs::symlink_metadata(&path).is_err(),
            "the directory is gone"
        );
    }

    /// ⟨M06 W5 `w5r`⟩ A directory or a link already at the name is refused as "in use",
    /// never reused, followed or removed: what was there is unchanged.
    #[test]
    fn what_is_already_at_the_agent_directory_name_is_refused_and_left() {
        let base = tempfile::tempdir().unwrap();
        let at = base.path().join(format!("{AGENT_DIR_PREFIX}{TAG}"));
        // An owner-only directory of this user (a squatter's, or a collision).
        std::fs::create_dir(&at).unwrap();
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(at.join("kept"), b"x").unwrap();
        let e = AgentDir::create_in(base.path(), TAG).unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::AddressInUse, "{e}");
        assert!(at.join("kept").exists());
        std::fs::remove_dir_all(&at).unwrap();
        // A link to another directory.
        let target = base.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &at).unwrap();
        let e = AgentDir::create_in(base.path(), TAG).unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::AddressInUse, "{e}");
        assert!(
            std::fs::symlink_metadata(&at)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        // A tag that is not one is refused before anything.
        let e = AgentDir::create_in(base.path(), "../x").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    /// ⟨M06 W5 `w5t`⟩ A taken name is skipped for a fresh one and left untouched; after
    /// `AGENT_DIR_ATTEMPTS` taken names the start is "in use"; a failure a fresh name
    /// cannot fix (the path's length) is not retried.
    #[test]
    fn an_occupied_agent_directory_name_is_skipped_for_a_fresh_one() {
        let base = tempfile::tempdir().unwrap();
        let taken = |tag: &str| {
            let at = base.path().join(format!("{AGENT_DIR_PREFIX}{tag}"));
            std::fs::create_dir(&at).unwrap();
            std::fs::write(at.join("kept"), b"x").unwrap();
            at
        };
        let first = taken(TAG);
        let tags = ["0123456789abcdef", "fedcba9876543210"];
        let mut drawn = 0;
        let dir = AgentDir::create_fresh(base.path(), || {
            drawn += 1;
            Ok(tags[drawn - 1].to_owned())
        })
        .unwrap();
        assert_eq!(drawn, 2);
        assert_eq!(
            dir.path().file_name().unwrap().to_str().unwrap(),
            format!("{AGENT_DIR_PREFIX}fedcba9876543210")
        );
        assert!(first.join("kept").exists(), "the taken name was touched");
        drop(dir);
        // Every name taken: "in use" after exactly the bound, each left as it was.
        let all = ["1111111111111111", "2222222222222222", "3333333333333333"];
        let kept: Vec<_> = all.iter().map(|t| taken(t)).collect();
        let mut drawn = 0;
        let e = AgentDir::create_fresh(base.path(), || {
            drawn += 1;
            Ok(all[drawn - 1].to_owned())
        })
        .unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::AddressInUse, "{e}");
        assert_eq!(drawn, AGENT_DIR_ATTEMPTS);
        assert!(kept.iter().all(|k| k.join("kept").exists()));
        // A base too long for the socket: refused at the first name.
        let long = base
            .path()
            .join("x".repeat(heimdall_ipc::unix::SOCKET_PATH_MAX));
        let mut drawn = 0;
        let e = AgentDir::create_fresh(&long, || {
            drawn += 1;
            Ok(TAG.to_owned())
        })
        .unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::PathTooLong, "{e}");
        assert_eq!(drawn, 1);
    }

    /// ⟨M06 W5 `w5r`⟩ A base whose socket path would pass the platform's limit is refused
    /// "path too long" before anything is created.
    #[tokio::test]
    async fn a_socket_path_past_the_platform_limit_is_refused_before_anything_is_created() {
        let root = tempfile::tempdir().unwrap();
        let long = root
            .path()
            .join("d".repeat(heimdall_ipc::unix::SOCKET_PATH_MAX));
        let e = AgentDir::create_in(&long, TAG).unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::PathTooLong, "{e}");
        assert!(!long.exists());
        let fits = AgentDir::create_in(root.path(), TAG).unwrap();
        // The agent itself refuses a socket path past the limit the same way.
        let past = fits
            .path()
            .join("s".repeat(heimdall_ipc::unix::SOCKET_PATH_MAX));
        let e = SessionAgent::start(&past, signer()).unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::PathTooLong, "{e}");
        drop(fits);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    /// ⟨M06 W5 `w5r`⟩ A base this user may not write is "permission denied".
    #[test]
    fn a_base_this_user_cannot_write_is_permission_denied() {
        // Root is not stopped by a 0500 directory: there the case cannot be caused.
        if heimdall_ipc::unix::current_uid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let e = AgentDir::create_in(root.path(), TAG).unwrap_err();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(AgentFailure::of(&e), AgentFailure::PermissionDenied, "{e}");
    }

    /// ⟨M06 W5 `w5r`⟩ A live agent already at the socket is "address in use".
    #[tokio::test]
    async fn a_live_agent_at_the_socket_is_address_in_use() {
        let base = tempfile::tempdir().unwrap();
        let dir = AgentDir::create_in(base.path(), TAG).unwrap();
        let first = SessionAgent::start(&dir.socket(AGENT_SOCKET), signer()).unwrap();
        let e = SessionAgent::start(&dir.socket(AGENT_SOCKET), signer()).unwrap_err();
        assert_eq!(AgentFailure::of(&e), AgentFailure::AddressInUse, "{e}");
        first.stop().await;
    }

    /// ⟨M06 W5 `w5r`⟩ The sweep removes only a crash's leftover: the expected name, a real
    /// `0700` directory of this user, unchanged long enough, holding only dead sockets of
    /// its own names. Every other case is left as it is.
    #[test]
    fn the_sweep_removes_only_a_crashed_sessions_own_directory() {
        let base = tempfile::tempdir().unwrap();
        let make = |tag: &str| {
            let d = base.path().join(format!("{AGENT_DIR_PREFIX}{tag}"));
            std::fs::create_dir(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        };
        let dead_socket = |p: &Path| drop(std::os::unix::net::UnixListener::bind(p).unwrap());
        let crashed = make("00000000000000a1");
        dead_socket(&crashed.join(AGENT_SOCKET));
        dead_socket(&crashed.join(PROBE_SOCKET));
        let empty = make("00000000000000a2");
        let live = make("00000000000000a3");
        let _listening = std::os::unix::net::UnixListener::bind(live.join(AGENT_SOCKET)).unwrap();
        let other = make("00000000000000a4");
        dead_socket(&other.join(AGENT_SOCKET));
        std::fs::write(other.join("notes"), b"x").unwrap();
        let open = make("00000000000000a5");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unnamed = base.path().join(format!("{AGENT_DIR_PREFIX}xyz"));
        std::fs::create_dir(&unnamed).unwrap();
        std::fs::set_permissions(&unnamed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = make("target-dir-00000");
        dead_socket(&target.join(AGENT_SOCKET));
        let link = base
            .path()
            .join(format!("{AGENT_DIR_PREFIX}00000000000000a6"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let plain = base
            .path()
            .join(format!("{AGENT_DIR_PREFIX}00000000000000a7"));
        std::fs::write(&plain, b"x").unwrap();

        // Too recent: nothing is touched.
        sweep_stale_agent_dirs(base.path(), std::time::Duration::from_secs(3600));
        assert!(crashed.join(AGENT_SOCKET).exists() && empty.exists());

        sweep_stale_agent_dirs(base.path(), std::time::Duration::ZERO);
        assert!(!crashed.exists(), "the crash's leftover is removed");
        assert!(!empty.exists(), "an empty leftover is removed");
        assert!(live.join(AGENT_SOCKET).exists(), "a live agent is kept");
        assert!(other.join("notes").exists() && other.join(AGENT_SOCKET).exists());
        assert!(open.exists(), "not 0700: kept");
        assert!(unnamed.exists(), "not the expected name: kept");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(target.join(AGENT_SOCKET).exists(), "never followed");
        assert!(plain.exists(), "not a directory: kept");
    }
}

/// ⟨M06 W5; ADR-0012 §2.6⟩ The named-pipe agent on Windows. Each test asserts on its own
/// and writes what it observed to the uncaptured standard error (`observed: …`), so the
/// native run's log shows the values, not only the verdicts.
#[cfg(all(test, windows))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod windows_tests {
    use std::os::windows::io::AsRawHandle as _;
    use std::time::Duration;

    use heimdall_ipc::windows::{ServerOwner, connect_with_owner, current_user_sid};
    use tokio::net::windows::named_pipe::{NamedPipeClient, ServerOptions};

    use super::super::MgmtKey;
    use super::wire::{
        FAILURE, REQUEST_IDENTITIES, SIGN_RESPONSE, exchange, listed, out_of_scope_requests,
        sign_request, userauth,
    };
    use super::*;

    const ACCOUNT: &str = "runner";
    /// LocalSystem: a well-known SID that is never this test's user.
    const OTHER_SID: &str = "S-1-5-18";
    /// How long a test waits for something the agent does on its own task.
    const SETTLE: Duration = Duration::from_secs(5);

    fn observed(test: &str, what: &str) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "observed: mgmt pipe agent: {test}: {what}"
        );
    }

    /// One assertion group that ran and held: a stable line on the test's captured
    /// standard output (`m06 observation: mgmt-pipe-agent <group>: <result>`), printed only
    /// after the group's assertions passed.
    #[allow(clippy::print_stdout)] // the marker is the test's evidence line
    fn held(group: &str, result: &str) {
        println!("m06 observation: mgmt-pipe-agent {group}: {result}");
    }

    fn new_signer() -> (MgmtSigner, Vec<u8>) {
        let key = MgmtKey::generate().unwrap();
        let blob = key.public().unwrap().blob;
        (
            MgmtSigner::new(key, [ACCOUNT.to_owned()], []).unwrap(),
            blob,
        )
    }

    /// Connect as the in-box client's side would, requiring the pipe's owner to be this
    /// user.
    async fn client(agent: &SessionAgent) -> io::Result<NamedPipeClient> {
        connect_with_owner(agent.path(), ServerOwner::CurrentUser).await
    }

    /// Wait until `name` no longer answers: `Ok` with the error kind seen.
    async fn gone(name: &Path) -> Result<io::ErrorKind, &'static str> {
        let deadline = tokio::time::Instant::now() + SETTLE;
        loop {
            match heimdall_ipc::windows::connect(name).await {
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(e.kind()),
                _ if tokio::time::Instant::now() >= deadline => {
                    return Err("the pipe name still answers");
                }
                _ => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    }

    /// The pipe: named by the prefix and a random token only, owned by this user, with
    /// the protected DACL that grants this user and nobody else.
    #[tokio::test]
    async fn pipe_has_a_token_only_name_and_an_owner_only_dacl() {
        let test = "pipe_has_a_token_only_name_and_an_owner_only_dacl";
        let sid = current_user_sid().unwrap();
        let (signer, blob) = new_signer();
        let agent = SessionAgent::start_pipe(signer).unwrap();
        let name = agent.path().to_str().unwrap().to_owned();
        observed(
            test,
            &format!("name length {} (prefix + 32 hex)", name.len()),
        );
        assert!(is_session_pipe_name(&name));
        for part in [sid.as_str(), ACCOUNT] {
            assert!(!name.contains(part), "the name carries {part}");
        }
        held("pipe-name", "prefix_and_random_token_only");
        // The owner check passes for this user (and is what refuses a squatter's pipe).
        let mut pipe = client(&agent).await.unwrap();
        let dacl = crate::sys::windows::pipe_handle_dacl_sddl(pipe.as_raw_handle()).unwrap();
        observed(
            test,
            &format!(
                "dacl is owner-only: {}",
                dacl == format!("D:P(A;;FA;;;{sid})")
            ),
        );
        assert_eq!(dacl, format!("D:P(A;;FA;;;{sid})"));
        assert!(
            connect_with_owner(agent.path(), ServerOwner::Sid(OTHER_SID.to_owned()))
                .await
                .is_err(),
            "the pipe's owner is not another principal"
        );
        held("pipe-dacl", "protected_owner_only owner=this_user");
        let list = exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob]);
        observed(test, "a same-user client is served the one identity");
        held("same-user-client", "served_the_one_identity");
        // A second agent has another name.
        let (second, _) = new_signer();
        let second = SessionAgent::start_pipe(second).unwrap();
        assert_ne!(second.path(), agent.path());
        held("pipe-name-per-session", "distinct");
        second.stop().await;
        agent.stop().await;
    }

    /// The client's SID is checked on connect: a client that is not the agent's owner is
    /// disconnected without an answer. The pipe's DACL lets this user in (it must, for the
    /// test to reach the check), and the agent is told its owner is another principal.
    #[tokio::test]
    async fn a_client_with_another_sid_is_refused_without_an_answer() {
        let test = "a_client_with_another_sid_is_refused_without_an_answer";
        let (signer, _blob) = new_signer();
        let name = session_pipe_name().unwrap();
        let agent =
            SessionAgent::start_pipe_named(&name, signer, AgentOwner::Sid(OTHER_SID.to_owned()))
                .unwrap();
        let mut pipe = heimdall_ipc::windows::connect(agent.path()).await.unwrap();
        let answer = tokio::time::timeout(SETTLE, exchange(&mut pipe, &[REQUEST_IDENTITIES]))
            .await
            .expect("the refused client was left waiting");
        observed(
            test,
            &format!("answer to a client of another SID: {answer:?}"),
        );
        assert_eq!(answer, None, "a client of another SID was answered");
        // Still refused on a second connection, and the agent is still up for its owner's
        // side of the comparison: the same pipe serves this user when it is the owner.
        let mut again = heimdall_ipc::windows::connect(agent.path()).await.unwrap();
        let answer = tokio::time::timeout(SETTLE, exchange(&mut again, &[REQUEST_IDENTITIES]))
            .await
            .unwrap();
        assert_eq!(answer, None);
        held("wrong-sid", "disconnected_without_an_answer");
        agent.stop().await;
        // Control: with this user as the owner, the same steps are answered.
        let (signer, blob) = new_signer();
        let agent = SessionAgent::start_pipe(signer).unwrap();
        let mut pipe = client(&agent).await.unwrap();
        let list = exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob]);
        held("wrong-sid-control", "owner_answered");
        agent.stop().await;
    }

    /// ⟨M06 W5 `w5t`, ruling 2026-11-23⟩ Squatted names are skipped for fresh ones and left
    /// alone; three squatted names in a row are "in use" (`AddrInUse`), not "denied".
    #[tokio::test]
    async fn squatted_pipe_names_are_skipped_then_reported_in_use() {
        let squat = |name: &str| {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create(name)
                .unwrap()
        };
        let names: Vec<String> = (0..3).map(|_| session_pipe_name().unwrap()).collect();
        let squatters: Vec<_> = names.iter().map(|n| squat(n)).collect();
        let mut drawn = 0;
        let (signer, _blob) = new_signer();
        let Err(e) = SessionAgent::start_pipe_from(signer, || {
            drawn += 1;
            Ok(names[drawn - 1].clone())
        }) else {
            panic!("a squatted name was joined");
        };
        observed(
            "squatted_pipe_names_are_skipped_then_reported_in_use",
            &format!("three squatted names: {:?}", e.kind()),
        );
        assert_eq!(drawn, AGENT_DIR_ATTEMPTS);
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(AgentFailure::of(&e), AgentFailure::AddressInUse);
        // Two squatted, the third free: started under the third, the squatters untouched.
        let free = session_pipe_name().unwrap();
        let sequence = [names[0].clone(), names[1].clone(), free.clone()];
        let mut drawn = 0;
        let (signer, _blob) = new_signer();
        let agent = SessionAgent::start_pipe_from(signer, || {
            drawn += 1;
            Ok(sequence[drawn - 1].clone())
        })
        .unwrap();
        assert_eq!(drawn, 3);
        assert_eq!(agent.path(), Path::new(&free));
        held("squatted-names", "skipped_then_in_use");
        agent.stop().await;
        drop(squatters);
    }

    /// A name that already exists is refused (the first-instance flag), never joined: the
    /// agent does not serve on a pipe another process created.
    #[tokio::test]
    async fn a_squatted_name_is_refused() {
        let test = "a_squatted_name_is_refused";
        let name = session_pipe_name().unwrap();
        let squatter = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let (signer, _blob) = new_signer();
        let refused = SessionAgent::start_pipe_named(
            &name,
            signer,
            AgentOwner::Sid(current_user_sid().unwrap()),
        );
        let kind = refused.as_ref().err().map(io::Error::kind);
        observed(test, &format!("start on an existing name: {kind:?}"));
        assert!(refused.is_err(), "the agent joined an existing pipe name");
        held("squatted-name", "refused");
        drop(squatter);
        // Names of another form are refused before any pipe is created.
        for bad in [
            format!("{name}-signing"),
            r"\\.\pipe\heimdall-alice".to_owned(),
            r"\\.\pipe\other".to_owned(),
        ] {
            let (signer, _blob) = new_signer();
            let refused = SessionAgent::start_pipe_named(
                &bad,
                signer,
                AgentOwner::Sid(current_user_sid().unwrap()),
            );
            assert_eq!(
                refused.err().map(|e| e.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }
        // Control: the freed name can be created.
        let (signer, _blob) = new_signer();
        let agent = SessionAgent::start_pipe_named(
            &name,
            signer,
            AgentOwner::Sid(current_user_sid().unwrap()),
        )
        .unwrap();
        held("name-form", "other_forms_refused_before_any_pipe");
        held("squatted-name-control", "free_name_created");
        agent.stop().await;
    }

    /// The session's lifetime: after `stop` the pipe name is gone, the open connection is
    /// closed and the signer (with the key) is dropped; the same after a plain drop.
    #[tokio::test]
    async fn teardown_closes_the_pipe_and_drops_the_key() {
        let test = "teardown_closes_the_pipe_and_drops_the_key";
        // stop().
        let (signer, blob) = new_signer();
        let agent = SessionAgent::start_pipe(signer).unwrap();
        let name = agent.path().to_path_buf();
        let alive = agent.signer.clone();
        let mut pipe = client(&agent).await.unwrap();
        let list = exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob]);
        assert!(alive.upgrade().is_some());
        agent.stop().await;
        let after_stop = alive.upgrade().is_none();
        observed(test, &format!("after stop: signer dropped: {after_stop}"));
        assert!(after_stop, "the signer outlived stop()");
        let answer = tokio::time::timeout(SETTLE, exchange(&mut pipe, &[REQUEST_IDENTITIES]))
            .await
            .unwrap();
        observed(
            test,
            &format!("after stop: the open connection answers: {answer:?}"),
        );
        assert_eq!(answer, None, "a connection outlived the agent");
        let kind = gone(&name).await;
        observed(
            test,
            &format!("after stop: connecting to the name: {kind:?}"),
        );
        assert_eq!(kind, Ok(io::ErrorKind::NotFound));
        held(
            "teardown-stop",
            "signer_dropped connection_closed pipe_name_gone",
        );

        // drop, with a connection open.
        let (signer, _blob) = new_signer();
        let agent = SessionAgent::start_pipe(signer).unwrap();
        let name = agent.path().to_path_buf();
        let alive = agent.signer.clone();
        let mut pipe = client(&agent).await.unwrap();
        assert!(exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.is_some());
        drop(agent);
        let kind = gone(&name).await;
        observed(
            test,
            &format!("after drop: connecting to the name: {kind:?}"),
        );
        assert_eq!(kind, Ok(io::ErrorKind::NotFound));
        let deadline = tokio::time::Instant::now() + SETTLE;
        while alive.upgrade().is_some() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let after_drop = alive.upgrade().is_none();
        observed(test, &format!("after drop: signer dropped: {after_drop}"));
        assert!(after_drop, "the signer outlived the dropped agent");
        let answer = tokio::time::timeout(SETTLE, exchange(&mut pipe, &[REQUEST_IDENTITIES]))
            .await
            .unwrap();
        assert_eq!(answer, None, "a connection outlived the dropped agent");
        held(
            "teardown-drop",
            "signer_dropped connection_closed pipe_name_gone",
        );
    }

    /// The scope over the real pipe: list is K_mgmt alone, sign only the bound purpose,
    /// every other request `SSH_AGENT_FAILURE`, and nothing changes.
    #[tokio::test]
    async fn sign_scope_over_the_pipe_is_k_mgmt_and_its_purpose_only() {
        let test = "sign_scope_over_the_pipe_is_k_mgmt_and_its_purpose_only";
        let (signer, blob) = new_signer();
        let agent = SessionAgent::start_pipe(signer).unwrap();
        let mut pipe = client(&agent).await.unwrap();
        let list = exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.unwrap();
        observed(test, &format!("identities listed: {}", listed(&list).len()));
        assert_eq!(listed(&list), vec![blob.clone()]);
        let good = sign_request(&blob, &userauth(ACCOUNT, &blob), 0);
        let signed = exchange(&mut pipe, &good).await.unwrap();
        observed(
            test,
            &format!("bound sign request answered with type {}", signed[0]),
        );
        assert_eq!(signed[0], SIGN_RESPONSE);
        let other = MgmtKey::generate().unwrap().public().unwrap().blob;
        let mut refused = 0usize;
        for (why, request) in [
            (
                "another account",
                sign_request(&blob, &userauth("root", &blob), 0),
            ),
            (
                "another key",
                sign_request(&other, &userauth(ACCOUNT, &other), 0),
            ),
            (
                "a signature flag",
                sign_request(&blob, &userauth(ACCOUNT, &blob), 2),
            ),
            (
                "not a user-authentication request",
                sign_request(&blob, b"SSHSIG\0\0\0\x03git", 0),
            ),
        ] {
            let answer = exchange(&mut pipe, &request).await;
            assert_eq!(answer, Some(vec![FAILURE]), "{why}");
            refused += 1;
        }
        observed(
            test,
            &format!("sign requests outside the purpose refused: {refused}"),
        );
        let requests = out_of_scope_requests(&blob);
        let total = requests.len();
        for (name, request) in requests {
            let answer = exchange(&mut pipe, &request).await;
            assert_eq!(answer, Some(vec![FAILURE]), "{name}");
        }
        observed(
            test,
            &format!("other request types refused: {total} of {total}"),
        );
        let list = exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob]);
        assert_eq!(exchange(&mut pipe, &good).await.unwrap()[0], SIGN_RESPONSE);
        held(
            "sign-scope",
            "list=k_mgmt_only bound_sign=signed other_sign=refused other_requests=refused unchanged_after=true",
        );
        agent.stop().await;
    }

    /// Connections are bounded: beyond [`MAX_SESSION_CONNECTIONS`] a client is closed
    /// without an answer, and a served one keeps working.
    #[tokio::test]
    async fn connections_beyond_the_bound_are_closed() {
        let test = "connections_beyond_the_bound_are_closed";
        let (signer, blob) = new_signer();
        let agent = SessionAgent::start_pipe(signer).unwrap();
        let mut open = Vec::new();
        for _ in 0..MAX_SESSION_CONNECTIONS {
            let mut pipe = client(&agent).await.unwrap();
            let list = exchange(&mut pipe, &[REQUEST_IDENTITIES]).await.unwrap();
            assert_eq!(listed(&list), vec![blob.clone()]);
            open.push(pipe);
        }
        let mut extra = client(&agent).await.unwrap();
        let answer = tokio::time::timeout(SETTLE, exchange(&mut extra, &[REQUEST_IDENTITIES]))
            .await
            .unwrap();
        observed(
            test,
            &format!(
                "connection {} answered: {answer:?}",
                MAX_SESSION_CONNECTIONS + 1
            ),
        );
        assert_eq!(answer, None, "a connection beyond the bound was served");
        let list = exchange(&mut open[0], &[REQUEST_IDENTITIES]).await.unwrap();
        assert_eq!(listed(&list), vec![blob]);
        held(
            "connection-bound",
            "refused_beyond_the_bound served_one_unaffected",
        );
        agent.stop().await;
    }
}
