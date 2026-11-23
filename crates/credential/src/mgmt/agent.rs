//! The per-session K_mgmt agent (ADR-0012 §3.4, §5.2): an owner-only endpoint that serves one
//! [`MgmtSigner`] for the lifetime of one management session, named by the isolated
//! configuration's `IdentityAgent`. Same-user peers only (the transport's peer credentials,
//! checked again here by [`peer_admitted`]); stopped and removed when the session ends
//! ([`SessionAgent::stop`], or on drop).
//!
//! * **Unix:** a socket inside the session's own owner-only directory
//!   ([`SessionAgent::start`]).
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

/// The prefix of a session agent's pipe name (the M04 pipe prefix).
pub const SESSION_PIPE_PREFIX: &str = r"\\.\pipe\heimdall-";

/// The random bytes in a session agent's pipe name (written as lowercase hex).
pub const SESSION_PIPE_TOKEN_BYTES: usize = 16;

/// Connections one session agent serves at once. One `ssh` authentication uses one; the
/// rest are refused by closing them.
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
    /// The bind's I/O error.
    #[cfg(unix)]
    pub fn start(path: &Path, signer: MgmtSigner) -> io::Result<SessionAgent> {
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
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = token.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        if !peer_admitted(&peer, &owner) {
                            continue;
                        }
                        let signer = signer.clone();
                        let endpoint = endpoint.clone();
                        let token = token.clone();
                        tokio::spawn(async move {
                            let _ = serve(stream, peer, endpoint, signer, token).await;
                        });
                    }
                }
            }
            drop(listener);
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
        let owner = heimdall_ipc::windows::current_user_sid()?;
        Self::start_pipe_named(&session_pipe_name()?, signer, AgentOwner::Sid(owner))
    }

    /// [`SessionAgent::start_pipe`] at `name`, serving only `owner` (always this user
    /// outside tests; the tests name another SID to see the refusal).
    #[cfg(windows)]
    fn start_pipe_named(
        name: &str,
        signer: MgmtSigner,
        owner: AgentOwner,
    ) -> io::Result<SessionAgent> {
        if !is_session_pipe_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a session agent pipe name",
            ));
        }
        // The pipe's DACL always names this process's own user, whatever `owner` is.
        let sid = heimdall_ipc::windows::current_user_sid()?;
        let listener = heimdall_ipc::windows::Listener::bind(name, EndpointKind::Signing, &sid)?;
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
        Ok(SessionAgent {
            path: PathBuf::from(name),
            stop,
            task: Some(task),
            #[cfg(test)]
            signer: weak,
        })
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
