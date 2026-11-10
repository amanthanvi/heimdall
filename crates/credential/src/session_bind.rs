//! `session-bind@openssh.com` (ADR-0008 D2 item 5; m03-plan U1 `session_bind`; wave-0
//! B2-Q4).
//!
//! The extension's contents (after the name; OpenSSH PROTOCOL.agent) are
//! `string hostkey, string session_identifier, string signature, bool is_forwarding`.
//! `ipc` splits them structurally only ([`SessionBindRecord::parse`]: lengths, a
//! boolean of 0 or 1, no trailing bytes); this module does the real work:
//!
//! * [`parse`]: that structural split, then each field decoded into
//!   `ssh-agent-lib`'s [`SessionBind`] with `ssh-encoding`, each completely (no bytes
//!   left inside a field), the session identifier 1 to 128 bytes (ssh-agent's
//!   `AGENT_MAX_SID_LEN`), and the host key an Ed25519, ECDSA (NIST P-256, P-384,
//!   P-521) or RSA key;
//! * [`verify`]: the host key's signature over the session identifier, with `ssh-key`
//!   (through [`SessionBind::verify_signature`]), after checking that the signature
//!   algorithm is the key's (`ssh-ed25519`; `ecdsa-sha2-<same curve>`; `rsa-sha2-256`
//!   or `rsa-sha2-512` for RSA, never SHA-1, which `ssh-key` cannot even decode);
//! * [`accept`]: both, giving the record the signer stores in
//!   `SigningSession::bind`.
//!
//! What the signer does with the result is U2's (D2 item 5): a failed verification
//! makes the connection refuse every later sign; `is_forwarding` refuses every sign
//! unless the grant has the `agent-forwarding` capability; once bound, a sign request
//! must match the bound session ([`crate::purpose::check_bound`]); no bind is
//! `session_bind: absent`. No destination-restriction claim is made from it.

use heimdall_ipc::signing::SessionBindRecord;
use ssh_encoding::Decode;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};

pub use ssh_agent_lib::proto::extension::SessionBind;

/// The longest session identifier accepted (ssh-agent's `AGENT_MAX_SID_LEN`; the
/// purpose parser's bound).
pub use crate::purpose::MAX_SESSION_ID_BYTES;

/// Why a `session-bind@openssh.com` request is refused (nonsecret codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum SessionBindError {
    /// A field is missing, a declared length runs past the end, the boolean is not 0
    /// or 1, a field does not decode completely, or bytes trail.
    #[error("the session-bind request is malformed")]
    Malformed,
    /// The session identifier is empty or longer than [`MAX_SESSION_ID_BYTES`].
    #[error("the session identifier length is invalid")]
    SessionIdLength,
    /// The host key is not Ed25519, ECDSA or RSA.
    #[error("the host key type is not supported")]
    UnsupportedHostKey,
    /// The host's signature over the session identifier does not verify.
    #[error("the host signature does not verify")]
    BadSignature,
}

impl SessionBindError {
    /// The stable, nonsecret code of this refusal.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            SessionBindError::Malformed => "malformed",
            SessionBindError::SessionIdLength => "session_id_length",
            SessionBindError::UnsupportedHostKey => "unsupported_host_key",
            SessionBindError::BadSignature => "bad_signature",
        }
    }
}

/// Decode `bytes` completely as `T`.
fn decode_all<T: Decode>(bytes: &[u8]) -> Option<T> {
    let mut reader = bytes;
    let value = T::decode(&mut reader).ok()?;
    reader.is_empty().then_some(value)
}

/// Parse the extension contents (the bytes after the extension name).
///
/// # Errors
/// [`SessionBindError::Malformed`], [`SessionBindError::SessionIdLength`],
/// [`SessionBindError::UnsupportedHostKey`]; never panics, whatever the input.
pub fn parse(payload: &[u8]) -> Result<SessionBind, SessionBindError> {
    let record = SessionBindRecord::parse(payload).ok_or(SessionBindError::Malformed)?;
    typed(&record)
}

fn typed(record: &SessionBindRecord) -> Result<SessionBind, SessionBindError> {
    if record.session_id.is_empty() || record.session_id.len() > MAX_SESSION_ID_BYTES {
        return Err(SessionBindError::SessionIdLength);
    }
    let host_key: KeyData = decode_all(&record.host_key).ok_or(SessionBindError::Malformed)?;
    if !matches!(
        host_key,
        KeyData::Ed25519(_) | KeyData::Ecdsa(_) | KeyData::Rsa(_)
    ) {
        return Err(SessionBindError::UnsupportedHostKey);
    }
    let signature: Signature = decode_all(&record.signature).ok_or(SessionBindError::Malformed)?;
    Ok(SessionBind {
        host_key,
        session_id: record.session_id.clone(),
        signature,
        is_forwarding: record.is_forwarding,
    })
}

/// Whether the signature algorithm is one the host key may use.
fn algorithm_fits(key: &KeyData, signature: &Algorithm) -> bool {
    match (key, signature) {
        (KeyData::Ed25519(_), Algorithm::Ed25519) => true,
        (KeyData::Ecdsa(k), Algorithm::Ecdsa { curve }) => k.curve() == *curve,
        (
            KeyData::Rsa(_),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256 | HashAlg::Sha512),
            },
        ) => true,
        _ => false,
    }
}

/// Whether the host key's signature over the session identifier verifies (ADR-0008 D2
/// item 5): Ed25519, ECDSA and RSA (SHA-2) host keys, the algorithm matching the key.
#[must_use]
pub fn verify(bind: &SessionBind) -> bool {
    if !matches!(
        bind.host_key,
        KeyData::Ed25519(_) | KeyData::Ecdsa(_) | KeyData::Rsa(_)
    ) || bind.session_id.is_empty()
        || bind.session_id.len() > MAX_SESSION_ID_BYTES
    {
        return false;
    }
    algorithm_fits(&bind.host_key, &bind.signature.algorithm()) && bind.verify_signature().is_ok()
}

/// [`parse`] and [`verify`] together: the verified bind and the record the signer
/// stores in `SigningSession::bind`.
///
/// # Errors
/// As [`parse`], and [`SessionBindError::BadSignature`].
pub fn accept(payload: &[u8]) -> Result<(SessionBind, SessionBindRecord), SessionBindError> {
    let record = SessionBindRecord::parse(payload).ok_or(SessionBindError::Malformed)?;
    let bind = typed(&record)?;
    if !verify(&bind) {
        return Err(SessionBindError::BadSignature);
    }
    Ok((bind, record))
}
