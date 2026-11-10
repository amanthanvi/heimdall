//! Signature purpose checking (ADR-0008 D2 item 4, F17; spec §7.2; m03-plan U1
//! `purpose`).
//!
//! The data a managed key is asked to sign must be an SSH user-authentication request
//! (RFC 4252 §7, and OpenSSH's `publickey-hostbound-v00@openssh.com`), read with the
//! established `ssh-encoding` reader, and nothing else:
//!
//! ```text
//! string  session_id            (1 to 128 bytes, ssh-agent's AGENT_MAX_SID_LEN)
//! byte    SSH_MSG_USERAUTH_REQUEST (50)
//! string  user                  (UTF-8)
//! string  "ssh-connection"
//! string  "publickey" | "publickey-hostbound-v00@openssh.com"
//! boolean TRUE                  (exactly 1: FALSE is a query and is never signed)
//! string  algorithm
//! string  key_blob
//! string  server_host_key       (host-bound method only)
//! (no trailing bytes)
//! ```
//!
//! [`parse_userauth`] checks that grammar and refuses everything else ([`PurposeRefusal`]):
//! `SSHSIG` (Git and file signing), arbitrary data, other SSH messages, truncated input
//! and declared lengths past the end (checked before any slice is taken, so nothing
//! panics and nothing large is allocated), trailing bytes, and anything over
//! [`MAX_USERAUTH_BYTES`].
//!
//! [`check`] then binds the request to the grant: the `key_blob` must be **one of the
//! grant's certificates**, byte for byte, never the plain K_env key (F17); the
//! `algorithm` must be that certificate's; the flags must be the ones Ed25519 permits
//! (none: an RSA SHA-2 flag on an Ed25519 key is refused); and `user` must be the
//! account of **the pair whose principal that certificate names** (F17), not merely any
//! pair of the grant. [`check_bound`] adds the session-bind rule of D2 item 5 for a
//! connection that has a bind record.

use heimdall_domain::issuance::principal_for;
use heimdall_domain::scope::AccessPair;
use heimdall_ipc::signing::SessionBindRecord;
use ssh_encoding::Decode;
use ssh_key::PublicKey;
use ssh_key::certificate::Certificate;

/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 §5).
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// The only service a managed key authenticates for.
pub const SERVICE_CONNECTION: &str = "ssh-connection";
/// RFC 4252 §7 public-key method.
pub const METHOD_PUBLICKEY: &str = "publickey";
/// OpenSSH's host-bound public-key method (PROTOCOL, OpenSSH 8.9+).
pub const METHOD_PUBLICKEY_HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";
/// The `SSHSIG` magic preamble (OpenSSH PROTOCOL.sshsig): Git commit and file signing.
pub const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
/// The longest session identifier accepted (ssh-agent's `AGENT_MAX_SID_LEN`).
pub const MAX_SESSION_ID_BYTES: usize = 128;
/// The largest userauth request accepted. A real one is a few kilobytes at most (a
/// certificate plus, for the host-bound method, a host key); the signing frame bound is
/// 256 KiB.
pub const MAX_USERAUTH_BYTES: usize = 32 * 1024;

/// The authentication method of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAuthMethod {
    /// `publickey`.
    Publickey,
    /// `publickey-hostbound-v00@openssh.com`, with the server host key blob the client
    /// binds the signature to.
    PublickeyHostbound {
        /// The server host key (SSH wire encoding).
        server_host_key: Vec<u8>,
    },
}

/// A parsed SSH user-authentication request (none of it is secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAuthRequest {
    /// The session identifier (exchange hash).
    pub session_id: Vec<u8>,
    /// The remote account the client authenticates as.
    pub user: String,
    /// The method.
    pub method: UserAuthMethod,
    /// The public-key algorithm name.
    pub algorithm: String,
    /// The presented public key or certificate (SSH wire encoding).
    pub key_blob: Vec<u8>,
}

/// Why a signing request is refused for its purpose. Each variant is a nonsecret audit
/// code ([`PurposeRefusal::code`]); none is sent to the client (it gets
/// `SSH_AGENT_FAILURE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PurposeRefusal {
    /// More than [`MAX_USERAUTH_BYTES`].
    #[error("the data to sign is too large")]
    Oversize,
    /// An `SSHSIG` signing request (Git, files).
    #[error("SSHSIG signing is refused")]
    Sshsig,
    /// A field is missing, or a declared length runs past the end.
    #[error("the data to sign is truncated or malformed")]
    Malformed,
    /// The session identifier is empty or longer than [`MAX_SESSION_ID_BYTES`].
    #[error("the session identifier length is invalid")]
    SessionIdLength,
    /// Not `SSH_MSG_USERAUTH_REQUEST`.
    #[error("the data to sign is not a user-authentication request")]
    NotUserAuth,
    /// A text field is not UTF-8.
    #[error("a text field is not UTF-8")]
    NotUtf8,
    /// The service is not `ssh-connection`.
    #[error("the service is not ssh-connection")]
    WrongService,
    /// The method is not `publickey` or `publickey-hostbound-v00@openssh.com`.
    #[error("the authentication method is not public-key")]
    UnsupportedMethod,
    /// The "signature follows" boolean is not exactly TRUE (1).
    #[error("the request is not a signed public-key request")]
    NotSigned,
    /// An empty key blob or host key.
    #[error("an empty key in the request")]
    EmptyKey,
    /// Bytes after the last field.
    #[error("trailing bytes after the request")]
    TrailingBytes,
    /// The key blob is the grant's plain key: every managed authentication presents a
    /// certificate (F17).
    #[error("the plain key is refused; a certificate is required")]
    PlainKeyRefused,
    /// The key blob is not one of the grant's certificates.
    #[error("the key is not one of this grant's certificates")]
    KeyNotInGrant,
    /// The algorithm is not the presented certificate's.
    #[error("the algorithm does not match the key")]
    AlgorithmMismatch,
    /// Signature flags Ed25519 does not permit (any flag).
    #[error("signature flags not permitted for this key")]
    FlagsNotPermitted,
    /// The user is not the account of the pair the certificate names (F17).
    #[error("the user is not the account of the certificate's pair")]
    WrongUser,
    /// The session identifier is not the one the connection was bound to (D2 item 5).
    #[error("the session identifier differs from the bound session")]
    SessionMismatch,
    /// The host-bound request names another host key than the bound one (D2 item 5).
    #[error("the server host key differs from the bound host key")]
    HostKeyMismatch,
}

impl PurposeRefusal {
    /// The stable, nonsecret code of this refusal.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            PurposeRefusal::Oversize => "oversize",
            PurposeRefusal::Sshsig => "sshsig",
            PurposeRefusal::Malformed => "malformed",
            PurposeRefusal::SessionIdLength => "session_id_length",
            PurposeRefusal::NotUserAuth => "not_userauth",
            PurposeRefusal::NotUtf8 => "not_utf8",
            PurposeRefusal::WrongService => "wrong_service",
            PurposeRefusal::UnsupportedMethod => "unsupported_method",
            PurposeRefusal::NotSigned => "not_signed",
            PurposeRefusal::EmptyKey => "empty_key",
            PurposeRefusal::TrailingBytes => "trailing_bytes",
            PurposeRefusal::PlainKeyRefused => "plain_key_refused",
            PurposeRefusal::KeyNotInGrant => "key_not_in_grant",
            PurposeRefusal::AlgorithmMismatch => "algorithm_mismatch",
            PurposeRefusal::FlagsNotPermitted => "flags_not_permitted",
            PurposeRefusal::WrongUser => "wrong_user",
            PurposeRefusal::SessionMismatch => "session_mismatch",
            PurposeRefusal::HostKeyMismatch => "host_key_mismatch",
        }
    }
}

/// A zero-copy reader over the request: lengths are decoded with `ssh-encoding`, and
/// each declared length is checked against the bytes present before any slice.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn byte(&mut self) -> Result<u8, PurposeRefusal> {
        u8::decode(&mut self.0).map_err(|_| PurposeRefusal::Malformed)
    }

    fn string(&mut self) -> Result<&'a [u8], PurposeRefusal> {
        let len = usize::decode(&mut self.0).map_err(|_| PurposeRefusal::Malformed)?;
        if len > self.0.len() {
            return Err(PurposeRefusal::Malformed);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn text(&mut self) -> Result<&'a str, PurposeRefusal> {
        std::str::from_utf8(self.string()?).map_err(|_| PurposeRefusal::NotUtf8)
    }
}

/// Parse the data of a signing request as an SSH user-authentication request
/// (ADR-0008 D2 item 4; the module docs give the grammar).
///
/// # Errors
/// The first [`PurposeRefusal`] that applies; never panics, whatever the input.
pub fn parse_userauth(data: &[u8]) -> Result<UserAuthRequest, PurposeRefusal> {
    if data.len() > MAX_USERAUTH_BYTES {
        return Err(PurposeRefusal::Oversize);
    }
    if data.starts_with(SSHSIG_MAGIC) {
        return Err(PurposeRefusal::Sshsig);
    }
    let mut f = Fields(data);
    let session_id = f.string()?;
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_BYTES {
        return Err(PurposeRefusal::SessionIdLength);
    }
    if f.byte()? != SSH_MSG_USERAUTH_REQUEST {
        return Err(PurposeRefusal::NotUserAuth);
    }
    let user = f.text()?;
    if f.text()? != SERVICE_CONNECTION {
        return Err(PurposeRefusal::WrongService);
    }
    let method = f.text()?;
    let hostbound = match method {
        METHOD_PUBLICKEY => false,
        METHOD_PUBLICKEY_HOSTBOUND => true,
        _ => return Err(PurposeRefusal::UnsupportedMethod),
    };
    if f.byte()? != 1 {
        return Err(PurposeRefusal::NotSigned);
    }
    let algorithm = f.text()?;
    let key_blob = f.string()?;
    if key_blob.is_empty() {
        return Err(PurposeRefusal::EmptyKey);
    }
    let method = if hostbound {
        let server_host_key = f.string()?;
        if server_host_key.is_empty() {
            return Err(PurposeRefusal::EmptyKey);
        }
        UserAuthMethod::PublickeyHostbound {
            server_host_key: server_host_key.to_vec(),
        }
    } else {
        UserAuthMethod::Publickey
    };
    if !f.0.is_empty() {
        return Err(PurposeRefusal::TrailingBytes);
    }
    Ok(UserAuthRequest {
        session_id: session_id.to_vec(),
        user: user.to_owned(),
        method,
        algorithm: algorithm.to_owned(),
        key_blob: key_blob.to_vec(),
    })
}

/// The pair a checked request authenticates for: the pair whose principal the
/// presented certificate names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRef {
    /// The pair.
    pub pair: AccessPair,
    /// The presented certificate's serial (for the audit event).
    pub serial: u64,
}

/// Why a certificate cannot join a [`GrantCertificates`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum GrantCertificateError {
    /// The certificate's subject is not the grant's key.
    #[error("the certificate subject is not the grant's key")]
    SubjectNotGrantKey,
    /// The certificate does not name exactly the pair's principal.
    #[error("the certificate does not name exactly the pair's principal")]
    PrincipalNotPair,
    /// The pair already has a certificate in the set.
    #[error("the pair already has a certificate")]
    DuplicatePair,
    /// The certificate or key could not be encoded.
    #[error("the certificate could not be encoded")]
    Encoding,
}

/// One installed certificate of a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantCertificate {
    pair: AccessPair,
    blob: Vec<u8>,
    algorithm: String,
    serial: u64,
}

/// The certificates a grant's key presents, one per pair (ADR-0008 D2 items 4 and 6),
/// and the grant's plain key, which [`check`] always refuses. Built by the signer at
/// install, after [`crate::cert::validate_installed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantCertificates {
    plain_key: Vec<u8>,
    certs: Vec<GrantCertificate>,
}

impl GrantCertificates {
    /// An empty set for the grant's key (K_env, or K_verify for a verification).
    ///
    /// # Errors
    /// [`GrantCertificateError::Encoding`].
    pub fn new(grant_key: &PublicKey) -> Result<GrantCertificates, GrantCertificateError> {
        Ok(GrantCertificates {
            plain_key: grant_key
                .to_bytes()
                .map_err(|_| GrantCertificateError::Encoding)?,
            certs: Vec::new(),
        })
    }

    /// Add `pair`'s certificate. Its subject must be the grant's key and its only
    /// principal `principal_for(pair)`; one certificate per pair.
    ///
    /// # Errors
    /// [`GrantCertificateError`].
    pub fn add(
        &mut self,
        pair: AccessPair,
        cert: &Certificate,
    ) -> Result<(), GrantCertificateError> {
        let subject = PublicKey::from(cert.public_key().clone())
            .to_bytes()
            .map_err(|_| GrantCertificateError::Encoding)?;
        if subject != self.plain_key {
            return Err(GrantCertificateError::SubjectNotGrantKey);
        }
        if cert.valid_principals() != [principal_for(&pair)] {
            return Err(GrantCertificateError::PrincipalNotPair);
        }
        if self.certs.iter().any(|c| c.pair == pair) {
            return Err(GrantCertificateError::DuplicatePair);
        }
        self.certs.push(GrantCertificate {
            pair,
            blob: cert
                .to_bytes()
                .map_err(|_| GrantCertificateError::Encoding)?,
            algorithm: cert.algorithm().to_certificate_type(),
            serial: cert.serial(),
        });
        Ok(())
    }

    /// Remove `pair`'s certificate (when it is dropped). Returns whether one was there.
    pub fn remove(&mut self, pair: &AccessPair) -> bool {
        let before = self.certs.len();
        self.certs.retain(|c| &c.pair != pair);
        self.certs.len() != before
    }

    /// The certificate blobs, in install order (what the endpoint lists).
    pub fn blobs(&self) -> impl Iterator<Item = &[u8]> {
        self.certs.iter().map(|c| c.blob.as_slice())
    }

    /// The grant's plain key blob (never listed for authentication purposes, never
    /// signed for).
    #[must_use]
    pub fn plain_key(&self) -> &[u8] {
        &self.plain_key
    }

    /// The number of certificates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Whether the set has no certificate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }
}

/// Signature flags Ed25519 permits: none (`SSH_AGENT_RSA_SHA2_256` = 2 and
/// `SSH_AGENT_RSA_SHA2_512` = 4 are RSA-only).
pub const ED25519_PERMITTED_FLAGS: u32 = 0;

/// Bind a parsed request to the grant (ADR-0008 D2 item 4; F17).
///
/// # Errors
/// [`PurposeRefusal::PlainKeyRefused`] for the grant's plain key;
/// [`PurposeRefusal::KeyNotInGrant`] for any other key that is not one of the grant's
/// certificates; [`PurposeRefusal::AlgorithmMismatch`]; [`PurposeRefusal::FlagsNotPermitted`]
/// for any flag; [`PurposeRefusal::WrongUser`] unless `user` is the account of the
/// pair the presented certificate names.
pub fn check(
    request: &UserAuthRequest,
    grant_certs: &GrantCertificates,
    flags: u32,
) -> Result<PairRef, PurposeRefusal> {
    if request.key_blob == grant_certs.plain_key {
        return Err(PurposeRefusal::PlainKeyRefused);
    }
    let Some(cert) = grant_certs
        .certs
        .iter()
        .find(|c| c.blob == request.key_blob)
    else {
        return Err(PurposeRefusal::KeyNotInGrant);
    };
    if request.algorithm != cert.algorithm {
        return Err(PurposeRefusal::AlgorithmMismatch);
    }
    if flags != ED25519_PERMITTED_FLAGS {
        return Err(PurposeRefusal::FlagsNotPermitted);
    }
    if request.user != cert.pair.account.as_str() {
        return Err(PurposeRefusal::WrongUser);
    }
    Ok(PairRef {
        pair: cert.pair.clone(),
        serial: cert.serial,
    })
}

/// The session-bind rule of ADR-0008 D2 item 5, for a connection with an accepted
/// bind record: the request's `session_id` must equal the bound one, and a host-bound
/// request's `server_host_key` must equal the bound host key. A connection without a
/// record skips this (`session_bind: absent`).
///
/// # Errors
/// [`PurposeRefusal::SessionMismatch`]; [`PurposeRefusal::HostKeyMismatch`].
pub fn check_bound(
    request: &UserAuthRequest,
    bind: &SessionBindRecord,
) -> Result<(), PurposeRefusal> {
    if request.session_id != bind.session_id {
        return Err(PurposeRefusal::SessionMismatch);
    }
    if let UserAuthMethod::PublickeyHostbound { server_host_key } = &request.method
        && *server_host_key != bind.host_key
    {
        return Err(PurposeRefusal::HostKeyMismatch);
    }
    Ok(())
}
