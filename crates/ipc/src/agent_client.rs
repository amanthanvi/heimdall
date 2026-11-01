//! The bounded agent-protocol client of the explicit `agent` probe (m02-plan U6;
//! ADR-0007 §6 "The probe ladder", §7).
//!
//! It sends exactly one message, `SSH_AGENTC_REQUEST_IDENTITIES` (11), and reads exactly
//! one reply. It never signs, adds, removes, locks or unlocks a key, and never sends an
//! extension: the request bytes are the constant [`REQUEST_IDENTITIES_FRAME`], and no
//! other write exists in this module.
//!
//! **Bounds** ([`ClientBounds`], never above the hard maximums): the whole call,
//! connect included, ends after 2 s; a reply whose declared length exceeds 256 KiB is
//! refused from its 4-byte header, before any body buffer exists; a reply declaring
//! more than 1024 identities is refused before any identity is parsed. Comments are
//! skipped as bytes and never decoded, kept or echoed.
//!
//! **Peer checks.** Unix: the socket's peer UID (`getpeereid` / `SO_PEERCRED`) must
//! equal ours, checked before the request is written. Windows: the pipe path must
//! normalize into the pipe namespace, the open uses `SECURITY_IDENTIFICATION`, the
//! handle must be `FILE_TYPE_PIPE`, and the pipe's owner must be the current user, or
//! LocalSystem for the system `openssh-ssh-agent` pipe only (all through
//! [`crate::windows::connect_with_owner`]). The observed owner is returned
//! ([`ServerPrincipal`]).
//!
//! **Parsing.** The frame and the identities answer's outer grammar (`uint32 count`,
//! then `string key_blob, string comment` per identity) are read by a bounded reader
//! that checks every declared length against the bytes present; each key blob is
//! decoded by `ssh-key` (an established implementation; spec §7.2), and its
//! fingerprint is `ssh-key`'s SHA-256 fingerprint of the plain public key (for a
//! certificate, of the key it certifies, as OpenSSH lists it). A blob `ssh-key`
//! cannot decode, a trailing byte, or any other deviation refuses the whole reply:
//! nothing is concluded from a reply that is not exactly well formed.
//!
//! **Drop contract** (m02-plan §5 item 15; M2-T06). [`list_identities`] spawns no task
//! and makes no blocking call. Dropping its future at any await point drops the
//! connection, so the agent sees the socket close and nothing further is sent.
//!
//! The Unix peer check against a socket owned by another account needs a second
//! account; its native test is blocked where none exists (m02-plan U6 adversarial
//! list). The decision itself is [`check_peer_uid`].

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use ssh_encoding::{Decode, Reader as _};
use ssh_key::public::KeyData;
use ssh_key::{Certificate, HashAlg};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `SSH_AGENTC_REQUEST_IDENTITIES`.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENT_FAILURE`.
pub const SSH_AGENT_FAILURE: u8 = 5;

/// The only bytes this client ever writes: one framed `SSH_AGENTC_REQUEST_IDENTITIES`.
pub const REQUEST_IDENTITIES_FRAME: [u8; 5] = [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];

/// Hard maximum of the whole call (m02-plan U6: 2 s).
pub const MAX_TIMEOUT: Duration = Duration::from_secs(2);
/// Hard maximum of a reply's declared length (m02-plan U6: 256 KiB).
pub const MAX_REPLY_BYTES: usize = 256 * 1024;
/// Hard maximum of the identities one reply may declare (m02-plan U6: 1024).
pub const MAX_IDENTITIES: usize = 1024;

/// Longest key algorithm name accepted in a key blob (OpenSSH names are well under).
const MAX_ALGORITHM_NAME: usize = 128;

/// The Windows LocalSystem SID, the documented owner of the system agent's pipe.
#[cfg(windows)]
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// The Windows OpenSSH agent service's pipe name (ADR-0007 F13, F18).
pub const WINDOWS_SYSTEM_AGENT_PIPE: &str = "openssh-ssh-agent";

/// Where an agent listens. Mirrors `heimdall_localenv::agents::EndpointLocator`, which
/// `heimdall-ipc` cannot name (the dependency points the other way).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AgentLocator {
    /// A Unix-domain socket path.
    UnixSocket(PathBuf),
    /// A Windows named pipe: a bare name, `\\.\pipe\<name>` or `//./pipe/<name>`.
    NamedPipe(String),
}

/// Bounds of one listing. Every field is narrowed to its hard maximum
/// ([`ClientBounds::clamped`]); a caller can tighten a bound, never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientBounds {
    /// Whole-call timeout, connect included.
    pub timeout: Duration,
    /// Largest reply accepted, in bytes (the declared frame length).
    pub max_reply_bytes: usize,
    /// Most identities one reply may declare.
    pub max_identities: usize,
}

impl Default for ClientBounds {
    /// The hard maximums: 2 s, 256 KiB, 1024 identities.
    fn default() -> Self {
        Self {
            timeout: MAX_TIMEOUT,
            max_reply_bytes: MAX_REPLY_BYTES,
            max_identities: MAX_IDENTITIES,
        }
    }
}

impl ClientBounds {
    /// These bounds, each narrowed to its hard maximum.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            timeout: self.timeout.min(MAX_TIMEOUT),
            max_reply_bytes: self.max_reply_bytes.min(MAX_REPLY_BYTES),
            max_identities: self.max_identities.min(MAX_IDENTITIES),
        }
    }
}

/// One identity an agent listed. Public material only; the comment is discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    /// The key blob's algorithm name (`ssh-ed25519`, `sk-ssh-ed25519@openssh.com`,
    /// `ssh-ed25519-cert-v01@openssh.com` …).
    pub key_type: String,
    /// SHA-256 fingerprint of the plain public key (`SHA256:…`), as `ssh-add -l`
    /// shows it.
    pub fingerprint: String,
    /// The public key blob exactly as listed.
    pub public_blob: Vec<u8>,
}

/// Who owns the endpoint that answered, as observed by the peer check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerPrincipal {
    /// The current user (Unix peer UID, or the Windows pipe owner SID).
    CurrentUser,
    /// Windows LocalSystem, accepted only for the `openssh-ssh-agent` pipe.
    LocalSystem,
}

/// What one listing returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentListing {
    /// The identities, in the agent's order.
    pub identities: Vec<AgentIdentity>,
    /// The endpoint's observed owner.
    pub server: ServerPrincipal,
}

/// Why a listing failed. Nonsecret and bounded: no reply byte, comment or key
/// material is ever part of it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AgentClientError {
    /// The endpoint does not exist.
    #[error("agent endpoint absent")]
    NotFound,
    /// The endpoint is not usable as an agent endpoint (not a socket, outside the
    /// pipe namespace, not a pipe handle, nothing accepting connections).
    #[error("agent endpoint refused: {0}")]
    Refused(&'static str),
    /// The endpoint is owned by another principal; nothing was written.
    #[error("agent endpoint owned by another principal")]
    ForeignPeer,
    /// The call did not complete within its bound.
    #[error("agent did not answer within the bound")]
    Timeout,
    /// The reply declared more bytes than the bound.
    #[error("agent reply of {declared} bytes exceeds the bound")]
    ReplyTooLarge {
        /// The declared length.
        declared: usize,
    },
    /// The reply declared more identities than the bound.
    #[error("agent reply declares {declared} identities, above the bound")]
    TooManyIdentities {
        /// The declared count.
        declared: usize,
    },
    /// The connection ended inside the reply, or before any reply.
    #[error("agent reply truncated")]
    Truncated,
    /// The reply is another message type than an identities answer or a failure.
    #[error("agent replied with message type {0}")]
    UnexpectedMessage(u8),
    /// The agent answered `SSH_AGENT_FAILURE`.
    #[error("agent refused to list identities")]
    AgentFailure,
    /// The reply is not well formed.
    #[error("agent reply malformed: {0}")]
    Malformed(&'static str),
    /// Any other I/O failure.
    #[error("agent I/O failed: {0:?}")]
    Io(io::ErrorKind),
}

impl AgentClientError {
    fn from_io(e: &io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::UnexpectedEof => AgentClientError::Truncated,
            kind => AgentClientError::Io(kind),
        }
    }

    fn from_connect(e: &io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => AgentClientError::NotFound,
            io::ErrorKind::PermissionDenied => AgentClientError::ForeignPeer,
            io::ErrorKind::ConnectionRefused => {
                AgentClientError::Refused("nothing accepts connections at the endpoint")
            }
            io::ErrorKind::InvalidInput => {
                AgentClientError::Refused("the endpoint is not an agent socket or pipe")
            }
            kind => AgentClientError::Io(kind),
        }
    }
}

/// List the identities the agent at `locator` holds: one connection, one
/// `SSH_AGENTC_REQUEST_IDENTITIES`, one reply, all within `bounds` (narrowed to the
/// hard maximums).
///
/// # Errors
/// [`AgentClientError`]; the connection is closed in every case.
pub async fn list_identities(
    locator: &AgentLocator,
    bounds: &ClientBounds,
) -> Result<AgentListing, AgentClientError> {
    let bounds = bounds.clamped();
    match tokio::time::timeout(bounds.timeout, connect_and_list(locator, &bounds)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(AgentClientError::Timeout),
    }
}

#[cfg(unix)]
async fn connect_and_list(
    locator: &AgentLocator,
    bounds: &ClientBounds,
) -> Result<AgentListing, AgentClientError> {
    use std::os::unix::fs::FileTypeExt;
    let AgentLocator::UnixSocket(path) = locator else {
        return Err(AgentClientError::Refused(
            "a named pipe is not reachable on this platform",
        ));
    };
    // One `stat` (a local, non-blocking-in-practice syscall made inline, so no task
    // outlives a dropped future): anything but a socket is refused unconnected.
    match std::fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(AgentClientError::NotFound),
        Ok(meta) if !meta.file_type().is_socket() => {
            return Err(AgentClientError::Refused(
                "the endpoint is not an agent socket or pipe",
            ));
        }
        _ => {}
    }
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| AgentClientError::from_connect(&e))?;
    let peer = stream
        .peer_cred()
        .map_err(|e| AgentClientError::Io(e.kind()))?;
    check_peer_uid(peer.uid(), crate::unix::current_uid())?;
    let identities = exchange(&mut stream, bounds).await?;
    Ok(AgentListing {
        identities,
        server: ServerPrincipal::CurrentUser,
    })
}

#[cfg(windows)]
async fn connect_and_list(
    locator: &AgentLocator,
    bounds: &ClientBounds,
) -> Result<AgentListing, AgentClientError> {
    use crate::windows::{ServerOwner, connect_with_owner};
    let AgentLocator::NamedPipe(name) = locator else {
        return Err(AgentClientError::Refused(
            "a Unix socket is not reachable on this platform",
        ));
    };
    let Some(pipe) = pipe_path(name) else {
        return Err(AgentClientError::Refused("the pipe name is not acceptable"));
    };
    let path = std::path::Path::new(&pipe);
    let (mut client, server) = match connect_with_owner(path, ServerOwner::CurrentUser).await {
        Ok(client) => (client, ServerPrincipal::CurrentUser),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && is_windows_system_agent(name) => {
            let client = connect_with_owner(path, ServerOwner::Sid(LOCAL_SYSTEM_SID.to_owned()))
                .await
                .map_err(|e| AgentClientError::from_connect(&e))?;
            (client, ServerPrincipal::LocalSystem)
        }
        Err(e) => return Err(AgentClientError::from_connect(&e)),
    };
    let identities = exchange(&mut client, bounds).await?;
    Ok(AgentListing { identities, server })
}

#[cfg(not(any(unix, windows)))]
async fn connect_and_list(
    _locator: &AgentLocator,
    _bounds: &ClientBounds,
) -> Result<AgentListing, AgentClientError> {
    Err(AgentClientError::Refused(
        "no agent transport on this platform",
    ))
}

/// The Unix peer check: the agent's UID must be ours.
///
/// # Errors
/// [`AgentClientError::ForeignPeer`] when it is not.
pub fn check_peer_uid(peer: u32, ours: u32) -> Result<(), AgentClientError> {
    if peer == ours {
        Ok(())
    } else {
        Err(AgentClientError::ForeignPeer)
    }
}

/// The `\\.\pipe\<name>` path of a pipe locator given as a bare name,
/// `\\.\pipe\<name>` or `//./pipe/<name>` (prefixes compared case-insensitively).
/// `None` for an empty name or one holding a separator, a NUL or a control character.
#[must_use]
pub fn pipe_path(locator: &str) -> Option<String> {
    let name = pipe_name(locator)?;
    Some(format!(r"\\.\pipe\{name}"))
}

/// The bare pipe name of a pipe locator ([`pipe_path`]'s rules).
#[must_use]
pub fn pipe_name(locator: &str) -> Option<&str> {
    let mut name = locator;
    for prefix in [r"\\.\pipe\", "//./pipe/", r"\\?\pipe\"] {
        if locator.len() >= prefix.len()
            && locator.is_char_boundary(prefix.len())
            && locator[..prefix.len()].eq_ignore_ascii_case(prefix)
        {
            name = &locator[prefix.len()..];
            break;
        }
    }
    let acceptable = !name.is_empty()
        && name.len() <= 256
        && !name
            .chars()
            .any(|c| c == '\\' || c == '/' || c.is_control());
    acceptable.then_some(name)
}

/// Whether a pipe locator names the Windows system agent pipe (`openssh-ssh-agent`).
#[must_use]
pub fn is_windows_system_agent(locator: &str) -> bool {
    pipe_name(locator).is_some_and(|n| n.eq_ignore_ascii_case(WINDOWS_SYSTEM_AGENT_PIPE))
}

/// The protocol exchange over an already peer-checked stream: write the one request,
/// read one bounded reply, parse it. Public for the `adversarial_agent_client_frames`
/// test target only; not a supported API (it performs no peer check and no timeout).
///
/// # Errors
/// [`AgentClientError`].
#[doc(hidden)]
pub async fn exchange<S>(
    stream: &mut S,
    bounds: &ClientBounds,
) -> Result<Vec<AgentIdentity>, AgentClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bounds = bounds.clamped();
    stream
        .write_all(&REQUEST_IDENTITIES_FRAME)
        .await
        .map_err(|e| AgentClientError::from_io(&e))?;
    stream
        .flush()
        .await
        .map_err(|e| AgentClientError::from_io(&e))?;
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| AgentClientError::from_io(&e))?;
    let declared = usize::try_from(u32::from_be_bytes(header)).map_err(|_| {
        AgentClientError::ReplyTooLarge {
            declared: usize::MAX,
        }
    })?;
    if declared == 0 {
        return Err(AgentClientError::Malformed("zero-length reply"));
    }
    if declared > bounds.max_reply_bytes {
        return Err(AgentClientError::ReplyTooLarge { declared });
    }
    let mut body = vec![0u8; declared];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| AgentClientError::from_io(&e))?;
    parse_reply(&body, bounds.max_identities)
}

/// Parse one reply body (after the 4-byte length): an identities answer, or the
/// agent's failure. Pure. Public for the test targets only; not a supported API.
///
/// # Errors
/// [`AgentClientError`]: `AgentFailure`, `UnexpectedMessage`, `TooManyIdentities`
/// (checked before any identity is parsed) or `Malformed`.
#[doc(hidden)]
pub fn parse_reply(
    body: &[u8],
    max_identities: usize,
) -> Result<Vec<AgentIdentity>, AgentClientError> {
    let max_identities = max_identities.min(MAX_IDENTITIES);
    let Some((&message, rest)) = body.split_first() else {
        return Err(AgentClientError::Malformed("empty reply"));
    };
    match message {
        SSH_AGENT_IDENTITIES_ANSWER => {}
        SSH_AGENT_FAILURE if rest.is_empty() => return Err(AgentClientError::AgentFailure),
        SSH_AGENT_FAILURE => return Err(AgentClientError::Malformed("failure with a payload")),
        other => return Err(AgentClientError::UnexpectedMessage(other)),
    }
    let mut fields = Fields(rest);
    let declared = fields
        .u32()
        .ok_or(AgentClientError::Malformed("identity count truncated"))?;
    let declared = usize::try_from(declared).map_err(|_| AgentClientError::TooManyIdentities {
        declared: usize::MAX,
    })?;
    if declared > max_identities {
        return Err(AgentClientError::TooManyIdentities { declared });
    }
    // Every identity needs at least two length prefixes.
    if declared.saturating_mul(8) > fields.0.len() {
        return Err(AgentClientError::Malformed(
            "identity count exceeds the reply",
        ));
    }
    let mut identities = Vec::with_capacity(declared);
    for _ in 0..declared {
        let blob = fields
            .string()
            .ok_or(AgentClientError::Malformed("key blob truncated"))?;
        // The comment is skipped as bytes: never decoded, kept or echoed.
        fields
            .string()
            .ok_or(AgentClientError::Malformed("comment truncated"))?;
        identities.push(identity_of_blob(blob)?);
    }
    if !fields.0.is_empty() {
        return Err(AgentClientError::Malformed(
            "trailing bytes after the identities",
        ));
    }
    Ok(identities)
}

/// The identity a public key blob describes: its algorithm name and the SHA-256
/// fingerprint of the plain public key, both from `ssh-key`. A certificate's
/// fingerprint is that of the key it certifies (as `ssh-add -l` shows it).
///
/// # Errors
/// [`AgentClientError::Malformed`] when `ssh-key` cannot decode the blob exactly.
pub fn identity_of_blob(blob: &[u8]) -> Result<AgentIdentity, AgentClientError> {
    let key_type = Fields(blob)
        .string()
        .and_then(|name| std::str::from_utf8(name).ok())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= MAX_ALGORITHM_NAME
                && name.bytes().all(|b| b.is_ascii_graphic())
        })
        .ok_or(AgentClientError::Malformed("key algorithm name"))?
        .to_owned();
    let mut reader: &[u8] = blob;
    let fingerprint = if key_type.ends_with("-cert-v01@openssh.com") {
        let cert = Certificate::decode(&mut reader)
            .map_err(|_| AgentClientError::Malformed("certificate blob"))?;
        cert.public_key().fingerprint(HashAlg::Sha256)
    } else {
        KeyData::decode(&mut reader)
            .map_err(|_| AgentClientError::Malformed("public key blob"))?
            .fingerprint(HashAlg::Sha256)
    };
    if !reader.is_finished() {
        return Err(AgentClientError::Malformed("trailing bytes in a key blob"));
    }
    Ok(AgentIdentity {
        key_type,
        fingerprint: fingerprint.to_string(),
        public_blob: blob.to_vec(),
    })
}

/// Zero-copy reader for the draft-miller grammar: every declared length is checked
/// against the bytes present before slicing.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        if len > self.0.len() {
            return None;
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ssh_encoding::Encode;
    use ssh_key::public::Ed25519PublicKey;

    fn blob(seed: u8) -> Vec<u8> {
        let key = KeyData::Ed25519(Ed25519PublicKey([seed; 32]));
        let mut out = Vec::new();
        key.encode(&mut out).unwrap();
        out
    }

    fn answer(blobs: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        body.extend_from_slice(&u32::try_from(blobs.len()).unwrap().to_be_bytes());
        for b in blobs {
            body.extend_from_slice(&u32::try_from(b.len()).unwrap().to_be_bytes());
            body.extend_from_slice(b);
            body.extend_from_slice(&3u32.to_be_bytes());
            body.extend_from_slice(b"c\xff\x00");
        }
        body
    }

    #[test]
    fn request_frame_is_exactly_request_identities() {
        assert_eq!(REQUEST_IDENTITIES_FRAME, [0, 0, 0, 1, 11]);
    }

    #[test]
    fn bounds_never_widen() {
        let wide = ClientBounds {
            timeout: Duration::from_secs(60),
            max_reply_bytes: usize::MAX,
            max_identities: usize::MAX,
        };
        assert_eq!(wide.clamped(), ClientBounds::default());
        let narrow = ClientBounds {
            timeout: Duration::from_millis(5),
            max_reply_bytes: 9,
            max_identities: 1,
        };
        assert_eq!(narrow.clamped(), narrow);
    }

    #[test]
    fn fingerprint_matches_ssh_key_and_comment_is_discarded() {
        let b = blob(7);
        let ids = parse_reply(&answer(std::slice::from_ref(&b)), MAX_IDENTITIES).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].key_type, "ssh-ed25519");
        let expected = KeyData::Ed25519(Ed25519PublicKey([7; 32]))
            .fingerprint(HashAlg::Sha256)
            .to_string();
        assert_eq!(ids[0].fingerprint, expected);
        assert!(ids[0].fingerprint.starts_with("SHA256:"));
        assert_eq!(ids[0].public_blob, b);
    }

    #[test]
    fn failure_and_wrong_type_are_distinct() {
        assert_eq!(parse_reply(&[5], 10), Err(AgentClientError::AgentFailure));
        assert_eq!(
            parse_reply(&[14, 0], 10),
            Err(AgentClientError::UnexpectedMessage(14))
        );
        assert!(matches!(
            parse_reply(&[5, 0], 10),
            Err(AgentClientError::Malformed(_))
        ));
    }

    #[test]
    fn count_bound_is_checked_before_parsing() {
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        body.extend_from_slice(&1025u32.to_be_bytes());
        assert_eq!(
            parse_reply(&body, MAX_IDENTITIES),
            Err(AgentClientError::TooManyIdentities { declared: 1025 })
        );
    }

    #[test]
    fn peer_uid_must_be_ours() {
        assert_eq!(check_peer_uid(501, 501), Ok(()));
        assert_eq!(check_peer_uid(0, 501), Err(AgentClientError::ForeignPeer));
    }

    #[test]
    fn pipe_locators_normalize() {
        assert_eq!(
            pipe_path("openssh-ssh-agent").as_deref(),
            Some(r"\\.\pipe\openssh-ssh-agent")
        );
        assert_eq!(
            pipe_path(r"\\.\PIPE\agent x").as_deref(),
            Some(r"\\.\pipe\agent x")
        );
        assert_eq!(pipe_path("//./pipe/a").as_deref(), Some(r"\\.\pipe\a"));
        assert_eq!(pipe_path(""), None);
        assert_eq!(pipe_path(r"\\.\pipe\"), None);
        assert_eq!(pipe_path(r"a\b"), None);
        assert_eq!(pipe_path("a\u{0}b"), None);
        assert!(is_windows_system_agent(r"\\.\pipe\OpenSSH-SSH-Agent"));
        assert!(!is_windows_system_agent("openssh-ssh-agent-2"));
    }
}
