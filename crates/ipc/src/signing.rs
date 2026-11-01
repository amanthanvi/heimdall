//! Bounded SSH-agent-protocol framer for the signing endpoint (spec §13.2, §7.2
//! "established libraries, not guessed parsing"; ADR-0006 §2.6).
//!
//! The signing endpoint performs only already-authorized credential operations.
//! M01 ships the framer and the allow-list; the real signer (keys, certificates,
//! grant/pause/cutoff checks per signature) arrives in M03. Until then the
//! endpoint answers `SSH_AGENT_IDENTITIES_ANSWER` with zero keys and
//! `SSH_AGENT_FAILURE` to everything else, which already exercises the boundary.
//!
//! The `ssh_agent_lib` listener helpers are not used (no `agent` feature): they
//! cannot apply our DACL/peer checks. M01 never parses key material: the type
//! byte is classified ([`classify`]) and a sign request is split into its three
//! draft-miller fields (`string key_blob, string data, uint32 flags`) by a
//! zero-copy reader that checks every declared length against the bytes present
//! before slicing and refuses trailing bytes. Key blobs stay opaque until M03.
//! Answers are encoded with the same grammar; the tests decode them with
//! `ssh_agent_lib::proto::Response` to check interoperability.
//!
//! Connection rules (each violation closes the connection without a reply):
//! a declared frame length of zero or above `MAX_SIGNING_FRAME_BYTES` (checked
//! from the 4-byte header, before the body buffer exists), EOF inside a frame,
//! and no complete frame within `IDLE_TIMEOUT_MS`. A well-framed message that is
//! not allowed, malformed, or refused by the signer gets `SSH_AGENT_FAILURE` and
//! the connection stays usable. Answers never exceed the frame limit or list
//! more than `MAX_IDENTITIES`. Per-endpoint concurrency
//! (`MAX_SIGNING_CONNECTIONS`) is enforced by the accept loop that calls
//! [`serve`].

use std::io;
use std::time::Duration;

use heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum identities ever listed.
pub const MAX_IDENTITIES: usize = 64;
/// Idle timeout for a signing connection (milliseconds).
pub const IDLE_TIMEOUT_MS: u64 = 30_000;

/// Agent message types the signing endpoint accepts (RFC draft-miller-ssh-agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedRequest {
    /// `SSH_AGENTC_REQUEST_IDENTITIES` (11).
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST` (13).
    SignRequest,
    /// `SSH_AGENTC_EXTENSION` (27) with `session-bind@openssh.com` only (spec S03).
    SessionBind,
}

/// Why a request is refused before any signer logic runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigningRefusal {
    /// Frame exceeds the limit.
    #[error("agent frame of {0} bytes exceeds limit")]
    Oversize(usize),
    /// Malformed message.
    #[error("malformed agent message")]
    Malformed,
    /// Add/remove/lock/unlock/smartcard or an unknown extension: refused.
    #[error("agent message type {0} is not permitted on the signing endpoint")]
    NotPermitted(u8),
}

/// Classify a raw agent message (after the 4-byte length prefix) into an allowed
/// request or a refusal. Pure; does not parse key material.
pub fn classify(payload: &[u8]) -> Result<AllowedRequest, SigningRefusal> {
    if payload.len() > MAX_SIGNING_FRAME_BYTES {
        return Err(SigningRefusal::Oversize(payload.len()));
    }
    let Some(&ty) = payload.first() else {
        return Err(SigningRefusal::Malformed);
    };
    match ty {
        11 => Ok(AllowedRequest::RequestIdentities),
        13 => Ok(AllowedRequest::SignRequest),
        27 => {
            // string extension-name follows the type byte.
            if payload.len() < 5 {
                return Err(SigningRefusal::Malformed);
            }
            let n = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
            let name = payload.get(5..5 + n).ok_or(SigningRefusal::Malformed)?;
            if name == b"session-bind@openssh.com" {
                Ok(AllowedRequest::SessionBind)
            } else {
                Err(SigningRefusal::NotPermitted(ty))
            }
        }
        other => Err(SigningRefusal::NotPermitted(other)),
    }
}

/// `SSH_AGENT_FAILURE` (5) as a complete frame.
#[must_use]
pub fn failure_frame() -> [u8; 5] {
    [0, 0, 0, 1, 5]
}

/// `SSH_AGENT_IDENTITIES_ANSWER` (12) with zero keys as a complete frame.
#[must_use]
pub fn empty_identities_frame() -> [u8; 9] {
    [0, 0, 0, 5, 12, 0, 0, 0, 0]
}

/// What the signer behind the endpoint must implement (M03). Every call receives
/// the authenticated peer and must recheck grant state, deadline, pause, cutoff and
/// generation before signing (spec §6.1, R-SE-07).
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Identities visible to this binding (public blobs and comments only).
    async fn identities(&self) -> Vec<(Vec<u8>, String)>;
    /// Sign `data` with the key identified by `key_blob` if authorized now.
    async fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>>;
}

/// A signer with no identities that refuses every signature: the M01 endpoint
/// behaviour (empty identity list, `SSH_AGENT_FAILURE` otherwise).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoIdentities;

#[async_trait::async_trait]
impl Signer for NoIdentities {
    async fn identities(&self) -> Vec<(Vec<u8>, String)> {
        Vec::new()
    }

    async fn sign(&self, _key_blob: &[u8], _data: &[u8], _flags: u32) -> Option<Vec<u8>> {
        None
    }
}

/// Serve one signing connection with the bounded framer.
///
/// Returns `Ok(())` when the peer closes between frames, the connection is idle
/// for `IDLE_TIMEOUT_MS`, or `shutdown` fires; returns an `InvalidData` /
/// `UnexpectedEof` error for a framing violation. The connection is closed in
/// every case.
pub async fn serve<S>(
    stream: S,
    signer: std::sync::Arc<dyn Signer>,
    shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    serve_with_idle(
        stream,
        signer,
        shutdown,
        Duration::from_millis(IDLE_TIMEOUT_MS),
    )
    .await
}

/// [`serve`] with an explicit idle timeout (tests use short ones).
pub(crate) async fn serve_with_idle<S>(
    mut stream: S,
    signer: std::sync::Arc<dyn Signer>,
    shutdown: tokio_util::sync::CancellationToken,
    idle: Duration,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    loop {
        let read = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            r = tokio::time::timeout(idle, read_agent_frame(&mut stream)) => r,
        };
        let payload = match read {
            Err(_idle) => return Ok(()),
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(payload))) => payload,
            Ok(Err(e)) => return Err(e),
        };
        let reply = answer(&payload, signer.as_ref()).await;
        let write = async {
            stream.write_all(&reply).await?;
            stream.flush().await
        };
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            r = tokio::time::timeout(idle, write) => match r {
                Ok(r) => r?,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "agent peer did not read the answer in time",
                    ));
                }
            },
        }
    }
}

fn violation(kind: io::ErrorKind, msg: &'static str) -> io::Error {
    io::Error::new(kind, msg)
}

/// Read one agent frame body. `Ok(None)` is a clean EOF before any header byte.
/// The declared length is checked before the body buffer is allocated.
pub(crate) async fn read_agent_frame<S>(stream: &mut S) -> io::Result<Option<Vec<u8>>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            violation(io::ErrorKind::UnexpectedEof, "agent frame header truncated")
        } else {
            e
        }
    })?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(violation(
            io::ErrorKind::InvalidData,
            "zero-length agent frame",
        ));
    }
    if len > MAX_SIGNING_FRAME_BYTES {
        return Err(violation(
            io::ErrorKind::InvalidData,
            "agent frame exceeds the signing frame limit",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            violation(io::ErrorKind::UnexpectedEof, "agent frame body truncated")
        } else {
            e
        }
    })?;
    Ok(Some(body))
}

/// Zero-copy reader for the draft-miller grammar.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > self.0.len() {
            return None;
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(s)
    }
}

/// A parsed `SSH_AGENTC_SIGN_REQUEST` body (after the type byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignFields<'a> {
    pub(crate) key_blob: &'a [u8],
    pub(crate) data: &'a [u8],
    pub(crate) flags: u32,
}

/// Split a sign request body; `None` on any overrun, short field or trailing
/// byte.
pub(crate) fn parse_sign_request(body: &[u8]) -> Option<SignFields<'_>> {
    let mut f = Fields(body);
    let key_blob = f.string()?;
    let data = f.string()?;
    let flags = f.u32()?;
    if !f.0.is_empty() {
        return None;
    }
    Some(SignFields {
        key_blob,
        data,
        flags,
    })
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(s.len()).ok()?.to_be_bytes());
    out.extend_from_slice(s);
    Some(())
}

fn frame(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() || body.len() > MAX_SIGNING_FRAME_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&u32::try_from(body.len()).ok()?.to_be_bytes());
    out.extend_from_slice(body);
    Some(out)
}

/// `SSH_AGENT_IDENTITIES_ANSWER` listing at most [`MAX_IDENTITIES`] identities, in
/// the signer's order, stopping before the frame limit would be exceeded.
pub(crate) fn identities_frame(identities: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut body = vec![12u8, 0, 0, 0, 0];
    let mut count: u32 = 0;
    for (blob, comment) in identities.iter().take(MAX_IDENTITIES) {
        let need = 8 + blob.len() + comment.len();
        if body.len() + need > MAX_SIGNING_FRAME_BYTES {
            break;
        }
        if put_string(&mut body, blob).is_none()
            || put_string(&mut body, comment.as_bytes()).is_none()
        {
            break;
        }
        count += 1;
    }
    body[1..5].copy_from_slice(&count.to_be_bytes());
    frame(&body).unwrap_or_else(|| empty_identities_frame().to_vec())
}

/// `SSH_AGENT_SIGN_RESPONSE` (14) or `None` if it would exceed the frame limit.
pub(crate) fn sign_response_frame(signature: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(5 + signature.len());
    body.push(14);
    put_string(&mut body, signature)?;
    frame(&body)
}

/// The complete answer frame for one well-framed agent message.
pub(crate) async fn answer(payload: &[u8], signer: &dyn Signer) -> Vec<u8> {
    let failure = || failure_frame().to_vec();
    match classify(payload) {
        Ok(AllowedRequest::RequestIdentities) if payload.len() == 1 => {
            identities_frame(&signer.identities().await)
        }
        Ok(AllowedRequest::SignRequest) => {
            let Some(req) = payload.get(1..).and_then(parse_sign_request) else {
                return failure();
            };
            match signer.sign(req.key_blob, req.data, req.flags).await {
                Some(sig) => sign_response_frame(&sig).unwrap_or_else(failure),
                None => failure(),
            }
        }
        // session-bind is verified by the M03 signer; until then: failure.
        Ok(AllowedRequest::SessionBind | AllowedRequest::RequestIdentities) | Err(_) => failure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_is_exact() {
        assert_eq!(classify(&[11]), Ok(AllowedRequest::RequestIdentities));
        assert_eq!(classify(&[13, 0]), Ok(AllowedRequest::SignRequest));
        for t in [17u8, 18, 19, 20, 21, 22, 23, 9, 25, 26] {
            assert_eq!(
                classify(&[t]),
                Err(SigningRefusal::NotPermitted(t)),
                "type {t}"
            );
        }
        let mut ext = vec![27, 0, 0, 0, 24];
        ext.extend_from_slice(b"session-bind@openssh.com");
        assert_eq!(classify(&ext), Ok(AllowedRequest::SessionBind));
        let mut other = vec![27, 0, 0, 0, 5];
        other.extend_from_slice(b"query");
        assert_eq!(classify(&other), Err(SigningRefusal::NotPermitted(27)));
        assert_eq!(
            classify(&[27, 0, 0, 0, 9, b'x']),
            Err(SigningRefusal::Malformed)
        );
        assert_eq!(classify(&[]), Err(SigningRefusal::Malformed));
    }

    #[test]
    fn canned_frames_are_well_formed() {
        assert_eq!(&failure_frame()[..4], &1u32.to_be_bytes());
        assert_eq!(&empty_identities_frame()[..4], &5u32.to_be_bytes());
    }
}

#[cfg(test)]
#[path = "../../../tests/adversarial/agent_frames.rs"]
mod agent_frames;
