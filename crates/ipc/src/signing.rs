//! Bounded SSH-agent-protocol framer for the signing endpoint (spec §13.2, §7.2
//! "established libraries, not guessed parsing"; ADR-0006 §2.6).
//!
//! The signing endpoint performs only already-authorized credential operations.
//! M01 ships the framer and the allow-list; the real signer (keys, certificates,
//! grant/pause/cutoff checks per signature) arrives in M03. Until then the
//! endpoint answers `SSH_AGENT_IDENTITIES_ANSWER` with zero keys and
//! `SSH_AGENT_FAILURE` to everything else, which already exercises the boundary.
//!
//! Message types are parsed with `ssh_agent_lib::proto` (no `agent` feature: its
//! listener helpers are not used because they cannot apply our DACL/peer checks).
//! Limits: frame ≤ `MAX_SIGNING_FRAME_BYTES`, ≤ `MAX_IDENTITIES`, idle timeout,
//! bounded concurrency.

use heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES;

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

/// Serve one signing connection with the bounded framer.
pub async fn serve<S>(
    _stream: S,
    _signer: std::sync::Arc<dyn Signer>,
    _shutdown: tokio_util::sync::CancellationToken,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    todo!("M01-T04: read length-prefixed agent frames, classify, answer; M03 wires the real signer")
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
