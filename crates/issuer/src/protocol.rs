//! The issuer wire protocol `heimdall-issuer/1` (ADR-0008 D3 item 3, D4 item 3;
//! m03-plan §5 item 20). **Frozen in wave 0** (m03-plan U0): the message enums, the
//! framing and its 64 KiB limit, and the wire form of the [`IssuerRefusal`] variants
//! (the variant set itself is `heimdall_app::ports::IssuerRefusal`, re-exported here,
//! as are the `sign` reservation types [`IssuanceRef`] and [`IssuanceTable`]). It is
//! internal, not a public schema; the golden
//! `tests/contracts/golden/issuer-protocol.json` fixes the message set.
//!
//! **Framing.** A frame is a `u32` big-endian length followed by exactly that many
//! bytes: one UTF-8 JSON object of at most [`MAX_FRAME_BYTES`]. The length is checked
//! before anything is allocated ([`body_len`], [`split_frame`]). Every message carries
//! its kind in the field `t`.
//!
//! | Runtime → issuer ([`Request`]) | Issuer → runtime ([`Response`]) |
//! |---|---|
//! | `hello {protocol, nonce}` | `hello_ack {nonce, pid}` |
//! | `load` | `loaded {cas}` or `store_unavailable {reason}` |
//! | `sign {request_id, reservation, subject_public_key}` | `signed {request_id, certificate}` or `refused {request_id, reason}` |
//! | `status` | `status {cas, signed_total, refused_total}` |
//! | `unload {ca_fingerprint}` (retirement; sent only once the CA is `retiring` in the store) | `unloaded {ca_fingerprint}` (after zeroization) |
//! | `shutdown` | (the issuer exits) |
//!
//! A `sign` request carries **no bounds**: the issuer reads them from the store
//! (ADR-0008 D3 item 4).

pub use heimdall_app::ports::{IssuanceRef, IssuanceTable, IssuerRefusal};
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::CaState;
use heimdall_domain::issuance::IssuanceRefusal;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::store::StoreAvailability;

/// The protocol name the `hello` carries.
pub const PROTOCOL: &str = "heimdall-issuer/1";

/// The largest frame body (the JSON object), in bytes. The 4-byte length prefix is
/// not counted.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// The length prefix's size.
pub const HEADER_BYTES: usize = 4;

/// The number of lowercase hex characters of a `nonce` or `request_id` (128 bits).
pub const TOKEN_HEX_CHARS: usize = 32;

/// One CA the issuer holds, as `loaded` and `status` report it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadedCa {
    /// Fingerprint.
    pub fingerprint: CaFingerprint,
    /// Its state (`active` or `pending`; ADR-0008 D4 item 3).
    pub state: CaState,
}

/// A runtime → issuer message. The field-less messages are empty struct variants so
/// that an unknown field is refused for every kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Request {
    /// The first message: the protocol and a fresh nonce the reply echoes.
    Hello {
        /// Exactly [`PROTOCOL`].
        protocol: String,
        /// 32 lowercase hex.
        nonce: String,
    },
    /// Read the CA keys from the store.
    Load {},
    /// Sign the reserved entry for `subject_public_key`.
    Sign {
        /// 32 lowercase hex; the reply echoes it.
        request_id: String,
        /// The reserved entry (`{"table":"grant"|"verification","id":"iss_…"}`).
        reservation: IssuanceRef,
        /// The subject's OpenSSH public key line (`ssh-ed25519 AAAA…`).
        subject_public_key: String,
    },
    /// Report the loaded CAs and counters.
    Status {},
    /// Zeroize and drop the CA (retirement; ADR-0008 D4 item 3).
    Unload {
        /// The CA.
        ca_fingerprint: CaFingerprint,
    },
    /// Zeroize everything and exit.
    Shutdown {},
}

/// An issuer → runtime message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Response {
    /// The reply to `hello`.
    HelloAck {
        /// The `hello`'s nonce.
        nonce: String,
        /// The issuer's process ID.
        pid: u32,
    },
    /// The CAs loaded.
    Loaded {
        /// CAs.
        cas: Vec<LoadedCa>,
    },
    /// The store is not available; no CA is in memory.
    StoreUnavailable {
        /// Why (never `available`).
        reason: StoreAvailability,
    },
    /// The certificate for a `sign`.
    Signed {
        /// The `sign`'s request ID.
        request_id: String,
        /// The OpenSSH certificate line (`ssh-ed25519-cert-v01@openssh.com AAAA…`).
        certificate: String,
    },
    /// A refused `sign`.
    Refused {
        /// The `sign`'s request ID.
        request_id: String,
        /// Why (the one-string wire form of [`refusal_to_wire`]).
        #[serde(with = "wire_refusal")]
        reason: IssuerRefusal,
    },
    /// The reply to `status`.
    Status {
        /// CAs.
        cas: Vec<LoadedCa>,
        /// Certificates signed since start.
        signed_total: u64,
        /// Requests refused since start.
        refused_total: u64,
    },
    /// The reply to `unload`, after zeroization.
    Unloaded {
        /// The CA.
        ca_fingerprint: CaFingerprint,
    },
}

// --- IssuerRefusal on the wire ------------------------------------------------------
//
// The variant set is `heimdall_app::ports::IssuerRefusal` (frozen with the ports, m03-plan
// §5 items 19–20): the `IssuanceRefusal` and `VerificationRefusal` sets plus the issuer's
// own six. Its wire form is one string, frozen here:
// * the issuer's own reasons are their snake_case names (`entry_stale`);
// * a predicate refusal is prefixed with its set, `issuance.<reason>` or
//   `verification.<reason>` (the two sets share names such as `wrong_principal`);
// * `issuance.grant_not_issuable.<grant_state>` carries the grant state.
// The predicate reasons are the domain enums' own serde names, so they cannot drift.

/// The issuer's own refusals with their wire names.
const OWN_REFUSALS: [(&str, IssuerRefusal); 6] = [
    ("entry_not_reserved", IssuerRefusal::EntryNotReserved),
    ("entry_stale", IssuerRefusal::EntryStale),
    ("subject_mismatch", IssuerRefusal::SubjectMismatch),
    ("ceiling_exceeded", IssuerRefusal::CeilingExceeded),
    ("ca_not_loaded", IssuerRefusal::CaNotLoaded),
    ("rate_limited", IssuerRefusal::RateLimited),
];

const ISSUANCE_PREFIX: &str = "issuance.";
const VERIFICATION_PREFIX: &str = "verification.";
const GRANT_NOT_ISSUABLE: &str = "grant_not_issuable";

/// The `reason` name of a domain refusal (its serde tag value).
fn reason_name<T: Serialize>(refusal: &T) -> Option<String> {
    match serde_json::to_value(refusal).ok()? {
        serde_json::Value::Object(map) => match map.get("reason")? {
            serde_json::Value::String(s) if map.len() == 1 && is_word(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// A domain refusal from its `reason` name.
fn from_reason_name<T: for<'de> Deserialize<'de>>(name: &str) -> Option<T> {
    let mut map = serde_json::Map::new();
    map.insert("reason".into(), serde_json::Value::String(name.to_owned()));
    serde_json::from_value(serde_json::Value::Object(map)).ok()
}

/// A snake_case word (the only shape a reason name may have on the wire).
fn is_word(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// The wire string of `refusal`, or `None` for a variant without one (a refusal
/// without a wire name is never sent: encoding fails closed).
#[must_use]
pub fn refusal_to_wire(refusal: &IssuerRefusal) -> Option<String> {
    match refusal {
        IssuerRefusal::Issuance(IssuanceRefusal::GrantNotIssuable(state)) => {
            match serde_json::to_value(state).ok()? {
                serde_json::Value::String(s) if is_word(&s) => {
                    Some(format!("{ISSUANCE_PREFIX}{GRANT_NOT_ISSUABLE}.{s}"))
                }
                _ => None,
            }
        }
        IssuerRefusal::Issuance(r) => reason_name(r).map(|n| format!("{ISSUANCE_PREFIX}{n}")),
        IssuerRefusal::Verification(r) => {
            reason_name(r).map(|n| format!("{VERIFICATION_PREFIX}{n}"))
        }
        own => OWN_REFUSALS
            .iter()
            .find(|(_, r)| r == own)
            .map(|(name, _)| (*name).to_owned()),
    }
}

/// The refusal named by `wire`, if it is one.
#[must_use]
pub fn refusal_from_wire(wire: &str) -> Option<IssuerRefusal> {
    if let Some(rest) = wire.strip_prefix(ISSUANCE_PREFIX) {
        if let Some(state) = rest
            .strip_prefix(GRANT_NOT_ISSUABLE)
            .and_then(|s| s.strip_prefix('.'))
        {
            if !is_word(state) {
                return None;
            }
            let state = serde_json::from_value(serde_json::Value::String(state.into())).ok()?;
            return Some(IssuerRefusal::Issuance(IssuanceRefusal::GrantNotIssuable(
                state,
            )));
        }
        if !is_word(rest) || rest == GRANT_NOT_ISSUABLE {
            return None;
        }
        return from_reason_name(rest).map(IssuerRefusal::Issuance);
    }
    if let Some(rest) = wire.strip_prefix(VERIFICATION_PREFIX) {
        if !is_word(rest) {
            return None;
        }
        return from_reason_name(rest).map(IssuerRefusal::Verification);
    }
    OWN_REFUSALS
        .iter()
        .find(|(name, _)| *name == wire)
        .map(|(_, r)| r.clone())
}

/// Whether the runtime may void, re-validate, re-reserve and ask again: only a
/// generation move between reserve and sign (ADR-0008 D3 item 4; ADR-0006 §13.6 item
/// 11). Every other refusal ends the attempt.
#[must_use]
pub fn is_generation_only(refusal: &IssuerRefusal) -> bool {
    matches!(
        refusal,
        IssuerRefusal::Issuance(IssuanceRefusal::StaleGeneration | IssuanceRefusal::StaleAncestor)
    )
}

/// `#[serde(with)]` for an [`IssuerRefusal`] field: the one-string wire form.
mod wire_refusal {
    use super::{Deserialize, Deserializer, IssuerRefusal, Serializer};

    pub(super) fn serialize<S: Serializer>(
        refusal: &IssuerRefusal,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match super::refusal_to_wire(refusal) {
            Some(wire) => serializer.serialize_str(&wire),
            None => Err(serde::ser::Error::custom(
                "issuer refusal without a wire name",
            )),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IssuerRefusal, D::Error> {
        let wire = String::deserialize(deserializer)?;
        super::refusal_from_wire(&wire)
            .ok_or_else(|| serde::de::Error::custom("unknown issuer refusal"))
    }
}

/// A frame that cannot be encoded or decoded. Messages never carry frame content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The declared or encoded body exceeds [`MAX_FRAME_BYTES`].
    #[error("frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit")]
    TooLarge {
        /// The declared or encoded length.
        len: usize,
    },
    /// A zero-length body.
    #[error("empty frame")]
    Empty,
    /// The body is not UTF-8.
    #[error("frame is not UTF-8")]
    NotUtf8,
    /// The body is not one JSON object of a known message.
    #[error("frame is not a valid heimdall-issuer/1 message")]
    Malformed,
    /// A field violates the protocol (protocol name, token shape, reason).
    #[error("frame violates the heimdall-issuer/1 protocol: {0}")]
    Invalid(&'static str),
}

/// Whether `s` is 32 lowercase hex characters.
fn is_token(s: &str) -> bool {
    s.len() == TOKEN_HEX_CHARS && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `s` is one non-empty line of printable ASCII (a key or certificate line).
fn is_key_line(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

impl Request {
    /// Check the protocol rules serde cannot express.
    ///
    /// # Errors
    /// [`FrameError::Invalid`] naming the rule.
    pub fn validate(&self) -> Result<(), FrameError> {
        match self {
            Request::Hello { protocol, nonce } => {
                if protocol != PROTOCOL {
                    return Err(FrameError::Invalid("protocol"));
                }
                if !is_token(nonce) {
                    return Err(FrameError::Invalid("nonce"));
                }
            }
            Request::Sign {
                request_id,
                subject_public_key,
                ..
            } => {
                if !is_token(request_id) {
                    return Err(FrameError::Invalid("request_id"));
                }
                if !is_key_line(subject_public_key) {
                    return Err(FrameError::Invalid("subject_public_key"));
                }
            }
            Request::Load {}
            | Request::Status {}
            | Request::Unload { .. }
            | Request::Shutdown {} => {}
        }
        Ok(())
    }

    /// Encode as one frame (length prefix and body).
    ///
    /// # Errors
    /// A message that fails [`Request::validate`], or a body over the limit.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.validate()?;
        encode_body(self)
    }

    /// Decode one frame body.
    ///
    /// # Errors
    /// Not UTF-8, not one known message, or a protocol violation.
    pub fn decode(body: &[u8]) -> Result<Request, FrameError> {
        let message: Request = decode_body(body)?;
        message.validate()?;
        Ok(message)
    }
}

impl Response {
    /// Check the protocol rules serde cannot express.
    ///
    /// # Errors
    /// [`FrameError::Invalid`] naming the rule.
    pub fn validate(&self) -> Result<(), FrameError> {
        match self {
            Response::HelloAck { nonce, .. } => {
                if !is_token(nonce) {
                    return Err(FrameError::Invalid("nonce"));
                }
            }
            Response::StoreUnavailable { reason } => {
                if *reason == StoreAvailability::Available {
                    return Err(FrameError::Invalid("reason"));
                }
            }
            Response::Signed {
                request_id,
                certificate,
            } => {
                if !is_token(request_id) {
                    return Err(FrameError::Invalid("request_id"));
                }
                if !is_key_line(certificate) {
                    return Err(FrameError::Invalid("certificate"));
                }
            }
            Response::Refused { request_id, .. } => {
                if !is_token(request_id) {
                    return Err(FrameError::Invalid("request_id"));
                }
            }
            Response::Loaded { .. } | Response::Status { .. } | Response::Unloaded { .. } => {}
        }
        Ok(())
    }

    /// Encode as one frame (length prefix and body).
    ///
    /// # Errors
    /// A message that fails [`Response::validate`], or a body over the limit.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.validate()?;
        encode_body(self)
    }

    /// Decode one frame body.
    ///
    /// # Errors
    /// Not UTF-8, not one known message, or a protocol violation.
    pub fn decode(body: &[u8]) -> Result<Response, FrameError> {
        let message: Response = decode_body(body)?;
        message.validate()?;
        Ok(message)
    }
}

fn encode_body<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(message).map_err(|_| FrameError::Malformed)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len: body.len() });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge { len: body.len() })?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn decode_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, FrameError> {
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len: body.len() });
    }
    let text = std::str::from_utf8(body).map_err(|_| FrameError::NotUtf8)?;
    serde_json::from_str(text).map_err(|_| FrameError::Malformed)
}

/// The body length a header declares, checked against [`MAX_FRAME_BYTES`] before any
/// allocation.
///
/// # Errors
/// [`FrameError::Empty`] for zero, [`FrameError::TooLarge`] over the limit.
pub fn body_len(header: [u8; HEADER_BYTES]) -> Result<usize, FrameError> {
    let len = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| FrameError::TooLarge { len: usize::MAX })?;
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len });
    }
    Ok(len)
}

/// Split the first complete frame off `buf`: `Ok(Some((body, consumed)))`, or
/// `Ok(None)` when more bytes are needed. The header is checked first, so an
/// oversized declaration fails before its body arrives.
///
/// # Errors
/// As [`body_len`].
pub fn split_frame(buf: &[u8]) -> Result<Option<(&[u8], usize)>, FrameError> {
    let Some(header) = buf.first_chunk::<HEADER_BYTES>() else {
        return Ok(None);
    };
    let len = body_len(*header)?;
    let end = HEADER_BYTES + len;
    Ok(buf.get(HEADER_BYTES..end).map(|body| (body, end)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::GrantState;
    use heimdall_contract::ids::IssuanceId;
    use heimdall_domain::verification::VerificationRefusal;

    fn token(c: char) -> String {
        std::iter::repeat_n(c, TOKEN_HEX_CHARS).collect()
    }

    fn fingerprint(c: char) -> CaFingerprint {
        CaFingerprint::parse(&format!(
            "SHA256:{}",
            std::iter::repeat_n(c, 43).collect::<String>()
        ))
        .unwrap()
    }

    fn issuance_id() -> IssuanceId {
        IssuanceId::from_random_bytes([0x11; 16])
    }

    /// Every issuance refusal, through an exhaustive match: a new variant fails to
    /// compile here until the golden is extended.
    fn all_issuance_refusals() -> Vec<IssuanceRefusal> {
        let all = vec![
            IssuanceRefusal::GrantNotIssuable(GrantState::Revoked),
            IssuanceRefusal::StaleGeneration,
            IssuanceRefusal::Tombstoned,
            IssuanceRefusal::PairOutsideSnapshot,
            IssuanceRefusal::ChildExceedsParent,
            IssuanceRefusal::BoundTooLate,
            IssuanceRefusal::BoundPassed,
            IssuanceRefusal::PausedActivation,
            IssuanceRefusal::CutoffPassed,
            IssuanceRefusal::UnknownSubjectKey,
            IssuanceRefusal::CriticalOption,
            IssuanceRefusal::TimeUncertain,
            IssuanceRefusal::BudgetExpired,
            IssuanceRefusal::WrongPrincipal,
            IssuanceRefusal::UnpermittedExtension,
            IssuanceRefusal::StalePolicyRevision,
            IssuanceRefusal::AncestorMissing,
            IssuanceRefusal::AncestorDenied,
            IssuanceRefusal::StaleAncestor,
            IssuanceRefusal::MechanismUnavailable,
            IssuanceRefusal::UnknownCa,
            IssuanceRefusal::CaNotVerifiedForPair,
            IssuanceRefusal::CaRetiring,
        ];
        for r in &all {
            match r {
                IssuanceRefusal::GrantNotIssuable(_)
                | IssuanceRefusal::StaleGeneration
                | IssuanceRefusal::Tombstoned
                | IssuanceRefusal::PairOutsideSnapshot
                | IssuanceRefusal::ChildExceedsParent
                | IssuanceRefusal::BoundTooLate
                | IssuanceRefusal::BoundPassed
                | IssuanceRefusal::PausedActivation
                | IssuanceRefusal::CutoffPassed
                | IssuanceRefusal::UnknownSubjectKey
                | IssuanceRefusal::CriticalOption
                | IssuanceRefusal::TimeUncertain
                | IssuanceRefusal::BudgetExpired
                | IssuanceRefusal::WrongPrincipal
                | IssuanceRefusal::UnpermittedExtension
                | IssuanceRefusal::StalePolicyRevision
                | IssuanceRefusal::AncestorMissing
                | IssuanceRefusal::AncestorDenied
                | IssuanceRefusal::StaleAncestor
                | IssuanceRefusal::MechanismUnavailable
                | IssuanceRefusal::UnknownCa
                | IssuanceRefusal::CaNotVerifiedForPair
                | IssuanceRefusal::CaRetiring => {}
            }
        }
        all
    }

    /// Every verification refusal (the type is `#[non_exhaustive]`, so the count is
    /// pinned by the golden instead).
    fn all_verification_refusals() -> Vec<VerificationRefusal> {
        vec![
            VerificationRefusal::OperationNotVerifying,
            VerificationRefusal::PairMismatch,
            VerificationRefusal::CaMismatch,
            VerificationRefusal::WrongPrincipal,
            VerificationRefusal::ExtensionsPresent,
            VerificationRefusal::ValidityTooLong,
            VerificationRefusal::UnknownSubjectKey,
            VerificationRefusal::TimeUncertain,
            VerificationRefusal::TooManyEntries,
        ]
    }

    fn all_refusals() -> Vec<IssuerRefusal> {
        let mut all: Vec<IssuerRefusal> = all_issuance_refusals()
            .into_iter()
            .map(IssuerRefusal::Issuance)
            .collect();
        all.extend(
            all_verification_refusals()
                .into_iter()
                .map(IssuerRefusal::Verification),
        );
        all.extend(OWN_REFUSALS.iter().map(|(_, r)| r.clone()));
        all
    }

    fn sample_requests() -> Vec<Request> {
        vec![
            Request::Hello {
                protocol: PROTOCOL.into(),
                nonce: token('a'),
            },
            Request::Load {},
            Request::Sign {
                request_id: token('b'),
                reservation: IssuanceRef {
                    table: IssuanceTable::Grant,
                    id: issuance_id(),
                },
                subject_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into(),
            },
            Request::Sign {
                request_id: token('c'),
                reservation: IssuanceRef {
                    table: IssuanceTable::Verification,
                    id: issuance_id(),
                },
                subject_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB".into(),
            },
            Request::Status {},
            Request::Unload {
                ca_fingerprint: fingerprint('C'),
            },
            Request::Shutdown {},
        ]
    }

    fn sample_responses() -> Vec<Response> {
        let cas = vec![
            LoadedCa {
                fingerprint: fingerprint('A'),
                state: CaState::Active,
            },
            LoadedCa {
                fingerprint: fingerprint('P'),
                state: CaState::Pending,
            },
        ];
        vec![
            Response::HelloAck {
                nonce: token('a'),
                pid: 4242,
            },
            Response::Loaded { cas: cas.clone() },
            Response::StoreUnavailable {
                reason: StoreAvailability::Locked,
            },
            Response::Signed {
                request_id: token('b'),
                certificate: "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQ".into(),
            },
            Response::Refused {
                request_id: token('c'),
                reason: IssuerRefusal::EntryStale,
            },
            Response::Status {
                cas,
                signed_total: 7,
                refused_total: 1,
            },
            Response::Unloaded {
                ca_fingerprint: fingerprint('C'),
            },
        ]
    }

    fn wire(frame: &[u8]) -> String {
        let (body, used) = split_frame(frame).unwrap().unwrap();
        assert_eq!(used, frame.len());
        String::from_utf8(body.to_vec()).unwrap()
    }

    /// The golden document: the protocol constants, every message kind's exact wire
    /// form, and every refusal's wire string.
    fn golden_document() -> String {
        let requests: Vec<String> = sample_requests()
            .iter()
            .map(|m| wire(&m.encode().unwrap()))
            .collect();
        let responses: Vec<String> = sample_responses()
            .iter()
            .map(|m| wire(&m.encode().unwrap()))
            .collect();
        let refusals: Vec<String> = all_refusals()
            .iter()
            .map(|r| refusal_to_wire(r).unwrap())
            .collect();
        let doc = serde_json::json!({
            "protocol": PROTOCOL,
            "framing": "u32 big-endian body length, then one UTF-8 JSON object",
            "max_frame_bytes": MAX_FRAME_BYTES,
            "requests": requests,
            "responses": responses,
            "refusals": refusals,
            "store_unavailable_reasons": StoreAvailability::ALL
                .iter()
                .filter(|a| **a != StoreAvailability::Available)
                .map(|a| a.as_str())
                .collect::<Vec<_>>(),
        });
        let mut text = serde_json::to_string_pretty(&doc).unwrap();
        text.push('\n');
        text
    }

    /// `tests/contracts/golden/issuer-protocol.json` (read at a compile-time
    /// repository path; `HM_REPO_ROOT` overrides it on native harness hosts).
    #[test]
    fn issuer_protocol_golden_is_byte_stable() {
        let path = heimdall_testkit::repo::repo_path("tests/contracts/golden/issuer-protocol.json");
        let golden = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            golden,
            golden_document(),
            "the heimdall-issuer/1 golden moved"
        );
    }

    #[test]
    fn every_message_round_trips_through_a_frame() {
        for m in sample_requests() {
            let frame = m.encode().unwrap();
            let (body, _) = split_frame(&frame).unwrap().unwrap();
            assert_eq!(Request::decode(body).unwrap(), m);
        }
        for m in sample_responses() {
            let frame = m.encode().unwrap();
            let (body, _) = split_frame(&frame).unwrap().unwrap();
            assert_eq!(Response::decode(body).unwrap(), m);
        }
    }

    #[test]
    fn every_refusal_round_trips_and_wire_names_are_unique() {
        let all = all_refusals();
        let mut seen = std::collections::BTreeSet::new();
        for r in &all {
            let w = refusal_to_wire(r).unwrap();
            assert!(seen.insert(w.clone()), "duplicate wire name {w}");
            assert_eq!(refusal_from_wire(&w).as_ref(), Some(r), "{w}");
        }
        for bad in [
            "",
            "issuance.",
            "issuance.grant_not_issuable",
            "issuance.grant_not_issuable.nope",
            "issuance.entry_stale",
            "verification.stale_generation",
            "Entry_stale",
            "issuance.stale generation",
        ] {
            assert_eq!(refusal_from_wire(bad), None, "{bad:?}");
        }
        assert!(is_generation_only(&IssuerRefusal::Issuance(
            IssuanceRefusal::StaleGeneration
        )));
        assert!(is_generation_only(&IssuerRefusal::Issuance(
            IssuanceRefusal::StaleAncestor
        )));
        assert!(!is_generation_only(&IssuerRefusal::Issuance(
            IssuanceRefusal::Tombstoned
        )));
        assert!(!is_generation_only(&IssuerRefusal::EntryStale));
    }

    #[test]
    fn frame_bounds_are_checked_before_allocation() {
        assert_eq!(MAX_FRAME_BYTES, 65_536);
        let max = u32::try_from(MAX_FRAME_BYTES).unwrap();
        assert_eq!(body_len(max.to_be_bytes()), Ok(MAX_FRAME_BYTES));
        assert_eq!(
            body_len((max + 1).to_be_bytes()),
            Err(FrameError::TooLarge {
                len: MAX_FRAME_BYTES + 1
            })
        );
        assert_eq!(
            body_len(u32::MAX.to_be_bytes()).unwrap_err(),
            FrameError::TooLarge {
                len: u32::MAX as usize
            }
        );
        assert_eq!(body_len([0; 4]), Err(FrameError::Empty));
        // An oversized declaration fails with only the header present.
        assert!(split_frame(&(max + 1).to_be_bytes()).is_err());
        // Incomplete input asks for more.
        assert_eq!(split_frame(&[0, 0]), Ok(None));
        assert_eq!(split_frame(&[0, 0, 0, 5, b'{']), Ok(None));
    }

    #[test]
    fn oversized_message_is_not_encoded() {
        let m = Request::Sign {
            request_id: token('d'),
            reservation: IssuanceRef {
                table: IssuanceTable::Grant,
                id: issuance_id(),
            },
            subject_public_key: "A".repeat(MAX_FRAME_BYTES),
        };
        assert!(matches!(m.encode(), Err(FrameError::TooLarge { .. })));
    }

    #[test]
    fn hostile_bodies_are_refused() {
        let bad: [&[u8]; 9] = [
            b"",
            b"\xff\xfe",
            b"[]",
            b"{}",
            br#"{"t":"nope"}"#,
            br#"{"t":"load","extra":1}"#,
            br#"{"t":"load"} {"t":"load"}"#,
            br#"{"t":"hello","protocol":"heimdall-issuer/2","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            br#"{"t":"hello","protocol":"heimdall-issuer/1","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        ];
        for body in bad {
            assert!(
                Request::decode(body).is_err(),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
        assert!(Response::decode(br#"{"t":"store_unavailable","reason":"available"}"#).is_err());
        assert!(
            Response::decode(
                br#"{"t":"refused","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reason":"bogus"}"#
            )
            .is_err()
        );
        assert!(
            Request::decode(
                br#"{"t":"sign","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reservation":{"table":"grant","id":"iss_x"},"subject_public_key":"k\nx"}"#
            )
            .is_err()
        );
    }
}
