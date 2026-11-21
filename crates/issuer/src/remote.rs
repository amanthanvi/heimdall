//! ⟨M06 U3⟩ The paired-environment request path (ADR-0012 §4.2; ADR-0005 §4.2): what a
//! controller's issuer accepts from a remote runner before it reserves, and what it hands back
//! for installation.
//!
//! **The order** (ADR-0012 §4.2): the runner admits the grant locally (a covering standing
//! policy, or a decision confirmed runner-locally), generates K_env in its signer's memory and
//! returns K_env.pub bound to the grant and its generation ([`PreparedRemoteGrant`], the data
//! of `runner.prepare_remote_grant`); the issuer runs ADR-0005 §3.5's reserve, sign and
//! publish; the runner installs (`runner.install_certificate`, [`install_request`]) under §3.5
//! step 4.
//!
//! **What the issuer trusts** (ADR-0005 §3.5: "the issuer trusts none of the request's
//! claims"): [`verify_prepared`] holds the runner's answer against what the controller itself
//! asked and pinned, and refuses ([`RemoteRefusal`]) unless
//! * the environment is the pinned runner the request went to, and the grant and generation
//!   are the ones asked for;
//! * the subject is one Ed25519 OpenSSH public key whose fingerprint is the one stated (the
//!   key the reservation's subject must equal: the only key "this environment's signer
//!   registered for this grant", refusal 5);
//! * every pair is inside the principal ceiling, and the bound has not passed;
//! * the grant is not pinned to another controller or CA (ADR-0012 §4.2 "pinned to its
//!   issuer"; §8 item 3: issuance and renewal come only from the issuing controller).
//!
//! It never widens anything: the reserve transaction still runs every §3.5 predicate against
//! the controller's own store, and the runner re-checks everything at install.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CaFingerprint, ClientId, EnvironmentId, GrantId};
use heimdall_contract::remote::{MAX_CERTIFICATE_BYTES, RunnerRequest};
use heimdall_contract::request::AccessPairRef;
use heimdall_domain::issuance::principal_for;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, PublicKey};

use crate::check::principal_within_ceiling;

/// The issuer a runner grant is pinned to (ADR-0012 §4.2), as the runner reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedIssuer {
    /// The controller (the paired client whose session installed the first certificate).
    pub controller: ClientId,
    /// The CA that signed it.
    pub ca_fingerprint: CaFingerprint,
}

/// The data of a successful `runner.prepare_remote_grant` (ADR-0012 §4.2 step 2): K_env.pub
/// bound to the grant and its generation, with the grant's pairs and bound as the runner holds
/// them. Public text only: no private key, no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedRemoteGrant {
    /// The runner's environment.
    pub environment: EnvironmentId,
    /// The grant.
    pub grant: GrantId,
    /// The grant's authority generation the key is bound to.
    pub grant_generation: u64,
    /// K_env.pub: one OpenSSH public key line (`ssh-ed25519 AAAA…`), no comment.
    pub public_key: String,
    /// Its SHA-256 fingerprint (`SHA256:…`).
    pub key_fingerprint: String,
    /// The grant's pairs (one certificate each).
    pub pairs: Vec<AccessPairRef>,
    /// `min(D, cutoff, parent deadline)` as the runner holds it: no certificate may outlive it.
    pub bound: Timestamp,
    /// The grant's issuer pin, when a certificate was already installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_issuer: Option<PinnedIssuer>,
}

/// What the controller asked and pinned, against which a runner's answer is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExpectation {
    /// The pinned runner environment the request went to.
    pub environment: EnvironmentId,
    /// The grant asked for.
    pub grant: GrantId,
    /// The generation asked for.
    pub grant_generation: u64,
    /// This controller's paired client on that runner.
    pub controller: ClientId,
    /// The CA this controller's issuer would sign with.
    pub ca_fingerprint: CaFingerprint,
}

/// A verified request: what the reservation is made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIssuanceRequest {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// The grant.
    pub grant: GrantId,
    /// Its generation.
    pub grant_generation: u64,
    /// K_env.pub, the reservation's subject (the `sign` request's `subject_public_key`).
    pub subject_public_key: String,
    /// Its fingerprint (the reservation's `subject_fingerprint`).
    pub subject_fingerprint: String,
    /// The pairs, one reservation each.
    pub pairs: Vec<AccessPairRef>,
    /// No reservation's `valid_before` may be later.
    pub bound: Timestamp,
}

/// Why a runner's prepared answer is refused (nothing is reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteRefusal {
    /// Another environment answered (`environment_identity_mismatch`).
    #[error("the answer names another environment")]
    EnvironmentMismatch,
    /// Another grant, or another generation, than the one asked for.
    #[error("the answer names another grant or generation")]
    GrantMismatch,
    /// The subject is not one Ed25519 OpenSSH public key line.
    #[error("the subject is not one Ed25519 public key")]
    SubjectMalformed,
    /// The subject's fingerprint is not the stated one.
    #[error("the subject's fingerprint is not the stated one")]
    SubjectFingerprintMismatch,
    /// No pair, a duplicate pair, or a pair outside the principal ceiling.
    #[error("the pairs are empty, repeated or outside the principal ceiling")]
    Pairs,
    /// The bound has passed.
    #[error("the grant's bound has passed")]
    BoundPassed,
    /// The grant is pinned to another controller or CA (`issuer_untrusted`).
    #[error("the grant is pinned to another issuer")]
    PinnedElsewhere,
    /// The certificate is not one line of at most the contract's size, or not an OpenSSH
    /// certificate.
    #[error("the certificate is not one OpenSSH certificate line within the size limit")]
    CertificateMalformed,
    /// A host certificate (or any type but user).
    #[error("the certificate is not a user certificate")]
    NotUserCertificate,
    /// The CA signature does not verify.
    #[error("the certificate signature does not verify")]
    BadSignature,
}

impl RemoteRefusal {
    /// The contract reason a refusal is reported with, where ADR-0012 §9 item 7 names one
    /// (`CAPABILITY_UNAVAILABLE`); `None` for a malformed or mismatched answer, which is a
    /// protocol fault of the runner and carries no reason.
    #[must_use]
    pub fn reason(self) -> Option<&'static str> {
        use heimdall_contract::envelope::reason;
        match self {
            Self::EnvironmentMismatch => Some(reason::ENVIRONMENT_IDENTITY_MISMATCH),
            Self::PinnedElsewhere => Some(reason::ISSUER_UNTRUSTED),
            Self::GrantMismatch
            | Self::SubjectMalformed
            | Self::SubjectFingerprintMismatch
            | Self::Pairs
            | Self::BoundPassed
            | Self::CertificateMalformed
            | Self::NotUserCertificate
            | Self::BadSignature => None,
        }
    }
}

/// The SHA-256 fingerprint of one Ed25519 OpenSSH public key line, or `None` for anything
/// else (another algorithm, a comment-only line, several lines).
#[must_use]
pub fn ed25519_fingerprint(line: &str) -> Option<String> {
    if line.contains(['\n', '\r', '\0']) || line.len() > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let key = PublicKey::from_openssh(line).ok()?;
    (key.algorithm() == Algorithm::Ed25519).then(|| key.fingerprint(HashAlg::Sha256).to_string())
}

/// The SHA-256 fingerprint of one OpenSSH public key line of any algorithm (a CA key), or
/// `None` for anything else.
#[must_use]
pub fn public_key_fingerprint(line: &str) -> Option<String> {
    if line.contains(['\n', '\r', '\0']) || line.len() > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let key = PublicKey::from_openssh(line).ok()?;
    Some(key.fingerprint(HashAlg::Sha256).to_string())
}

/// What a runner reads from a certificate before it judges installing it (ADR-0005 §3.5 step
/// 4): public facts only. [`read_certificate`] has already refused a malformed line, a type
/// other than user and a signature that does not verify under the certificate's own CA key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFacts {
    /// The subject key's fingerprint (must be the grant's K_env).
    pub subject_fingerprint: String,
    /// The signing CA's fingerprint (must be in `issuer_trust`).
    pub ca_fingerprint: CaFingerprint,
    /// The principals, in order.
    pub principals: Vec<String>,
    /// Whether any critical option is present.
    pub critical_option: bool,
    /// The extension names.
    pub extensions: std::collections::BTreeSet<String>,
    /// Whether any extension carries data (every profile extension is a flag).
    pub extension_data: bool,
    /// The serial.
    pub serial: u64,
    /// The key ID.
    pub key_id: String,
    /// `valid_after`.
    pub valid_after: Timestamp,
    /// `valid_before`.
    pub valid_before: Timestamp,
}

/// Read one OpenSSH user certificate line (module docs; [`CertificateFacts`]).
///
/// # Errors
///
/// [`RemoteRefusal::CertificateMalformed`] for anything but one certificate line within the
/// contract's size limit (or validity instants outside the representable range),
/// [`RemoteRefusal::NotUserCertificate`], [`RemoteRefusal::BadSignature`].
pub fn read_certificate(line: &str) -> Result<CertificateFacts, RemoteRefusal> {
    if line.is_empty() || line.len() > MAX_CERTIFICATE_BYTES || line.contains(['\n', '\r', '\0']) {
        return Err(RemoteRefusal::CertificateMalformed);
    }
    let cert = ssh_key::Certificate::from_openssh(line)
        .map_err(|_| RemoteRefusal::CertificateMalformed)?;
    if cert.cert_type() != ssh_key::certificate::CertType::User {
        return Err(RemoteRefusal::NotUserCertificate);
    }
    if cert.verify_signature().is_err() {
        return Err(RemoteRefusal::BadSignature);
    }
    let ca_fingerprint = CaFingerprint::parse(
        &cert
            .signature_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
    )
    .map_err(|_| RemoteRefusal::CertificateMalformed)?;
    let instant = |secs: u64| {
        i64::try_from(secs)
            .ok()
            .and_then(|s| Timestamp::from_second(s).ok())
            .ok_or(RemoteRefusal::CertificateMalformed)
    };
    Ok(CertificateFacts {
        subject_fingerprint: cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
        ca_fingerprint,
        principals: cert.valid_principals().to_vec(),
        critical_option: !cert.critical_options().is_empty(),
        extensions: cert.extensions().keys().cloned().collect(),
        extension_data: cert.extensions().values().any(|v| !v.is_empty()),
        serial: cert.serial(),
        key_id: cert.key_id().to_owned(),
        valid_after: instant(cert.valid_after())?,
        valid_before: instant(cert.valid_before())?,
    })
}

/// Hold a runner's `prepare_remote_grant` answer against what this controller asked and
/// pinned (module docs). `now` is the controller's accepted time.
///
/// # Errors
///
/// The first [`RemoteRefusal`] that applies, in the order of the module docs.
pub fn verify_prepared(
    expected: &RemoteExpectation,
    prepared: &PreparedRemoteGrant,
    now: Timestamp,
) -> Result<RemoteIssuanceRequest, RemoteRefusal> {
    if prepared.environment != expected.environment {
        return Err(RemoteRefusal::EnvironmentMismatch);
    }
    if prepared.grant != expected.grant || prepared.grant_generation != expected.grant_generation {
        return Err(RemoteRefusal::GrantMismatch);
    }
    let fingerprint =
        ed25519_fingerprint(&prepared.public_key).ok_or(RemoteRefusal::SubjectMalformed)?;
    if fingerprint != prepared.key_fingerprint {
        return Err(RemoteRefusal::SubjectFingerprintMismatch);
    }
    let mut seen = std::collections::BTreeSet::new();
    if prepared.pairs.is_empty()
        || !prepared
            .pairs
            .iter()
            .all(|p| seen.insert(p) && principal_within_ceiling(&principal_for(p)))
    {
        return Err(RemoteRefusal::Pairs);
    }
    if now >= prepared.bound {
        return Err(RemoteRefusal::BoundPassed);
    }
    if let Some(pin) = &prepared.pinned_issuer
        && (pin.controller != expected.controller || pin.ca_fingerprint != expected.ca_fingerprint)
    {
        return Err(RemoteRefusal::PinnedElsewhere);
    }
    Ok(RemoteIssuanceRequest {
        environment: prepared.environment.clone(),
        grant: prepared.grant.clone(),
        grant_generation: prepared.grant_generation,
        subject_public_key: prepared.public_key.clone(),
        subject_fingerprint: fingerprint,
        pairs: prepared.pairs.clone(),
        bound: prepared.bound,
    })
}

/// The `runner.install_certificate` request for one **published** certificate of `request`
/// (ADR-0012 §4.2 step 4). Only a published certificate is ever released (ADR-0005 §3.5 step
/// 3); the caller hands this nothing else.
///
/// # Errors
///
/// [`RemoteRefusal::CertificateMalformed`] for anything but one line within the contract's
/// size limit.
pub fn install_request(
    request: &RemoteIssuanceRequest,
    certificate: &str,
) -> Result<RunnerRequest, RemoteRefusal> {
    if certificate.is_empty()
        || certificate.len() > MAX_CERTIFICATE_BYTES
        || certificate.contains(['\n', '\r', '\0'])
    {
        return Err(RemoteRefusal::CertificateMalformed);
    }
    Ok(RunnerRequest::InstallCertificate {
        grant: request.grant.clone(),
        grant_generation: request.grant_generation,
        certificate: certificate.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::ids::{AccountName, DestinationId};
    use ssh_key::PrivateKey;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn key(seed: u8) -> (String, String) {
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        let private = PrivateKey::new(KeypairData::Ed25519(pair), "").unwrap();
        let public = private.public_key().to_openssh().unwrap();
        let fp = private
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        (public, fp)
    }

    fn ca(c: char) -> CaFingerprint {
        CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
    }

    fn pair(d: &str) -> AccessPairRef {
        AccessPairRef {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn expected() -> RemoteExpectation {
        RemoteExpectation {
            environment: EnvironmentId::from_random_bytes([1; 16]),
            grant: GrantId::from_random_bytes([2; 16]),
            grant_generation: 7,
            controller: ClientId::from_random_bytes([3; 16]),
            ca_fingerprint: ca('A'),
        }
    }

    fn prepared() -> PreparedRemoteGrant {
        let (public_key, key_fingerprint) = key(5);
        PreparedRemoteGrant {
            environment: expected().environment,
            grant: expected().grant,
            grant_generation: 7,
            public_key,
            key_fingerprint,
            pairs: vec![pair("h1"), pair("h2")],
            bound: t("2026-11-21T12:00:00Z"),
            pinned_issuer: None,
        }
    }

    const NOW: &str = "2026-11-21T09:00:00Z";

    #[test]
    fn a_runner_answer_is_held_against_the_request_and_the_pin() {
        let ok = verify_prepared(&expected(), &prepared(), t(NOW)).unwrap();
        assert_eq!(ok.subject_fingerprint, prepared().key_fingerprint);
        assert_eq!(ok.pairs.len(), 2);

        let refused =
            |p: PreparedRemoteGrant| verify_prepared(&expected(), &p, t(NOW)).unwrap_err();
        let mut p = prepared();
        p.environment = EnvironmentId::from_random_bytes([9; 16]);
        assert_eq!(refused(p), RemoteRefusal::EnvironmentMismatch);
        let mut p = prepared();
        p.grant_generation = 8;
        assert_eq!(refused(p), RemoteRefusal::GrantMismatch);
        let mut p = prepared();
        p.key_fingerprint = key(6).1;
        assert_eq!(refused(p), RemoteRefusal::SubjectFingerprintMismatch);
        let mut p = prepared();
        p.public_key = format!("{}\n{}", p.public_key, p.public_key);
        assert_eq!(refused(p), RemoteRefusal::SubjectMalformed);
        let mut p = prepared();
        p.pairs.push(pair("h1"));
        assert_eq!(refused(p), RemoteRefusal::Pairs);
        let mut p = prepared();
        p.pairs.clear();
        assert_eq!(refused(p), RemoteRefusal::Pairs);
        let mut p = prepared();
        p.bound = t(NOW);
        assert_eq!(refused(p), RemoteRefusal::BoundPassed);
        // A grant pinned to another controller, or to another CA, is not this issuer's.
        let mut p = prepared();
        p.pinned_issuer = Some(PinnedIssuer {
            controller: ClientId::from_random_bytes([4; 16]),
            ca_fingerprint: ca('A'),
        });
        assert_eq!(refused(p), RemoteRefusal::PinnedElsewhere);
        let mut p = prepared();
        p.pinned_issuer = Some(PinnedIssuer {
            controller: expected().controller,
            ca_fingerprint: ca('B'),
        });
        assert_eq!(refused(p), RemoteRefusal::PinnedElsewhere);
        assert_eq!(
            RemoteRefusal::PinnedElsewhere.reason(),
            Some(heimdall_contract::envelope::reason::ISSUER_UNTRUSTED)
        );
        // Pinned to this controller and CA: a renewal is accepted.
        let mut p = prepared();
        p.pinned_issuer = Some(PinnedIssuer {
            controller: expected().controller,
            ca_fingerprint: ca('A'),
        });
        assert!(verify_prepared(&expected(), &p, t(NOW)).is_ok());
    }

    #[test]
    fn only_one_certificate_line_is_released_for_installation() {
        let ok = verify_prepared(&expected(), &prepared(), t(NOW)).unwrap();
        let line = "ssh-ed25519-cert-v01@openssh.com AAAA";
        match install_request(&ok, line).unwrap() {
            RunnerRequest::InstallCertificate {
                grant,
                grant_generation,
                certificate,
            } => {
                assert_eq!(grant, expected().grant);
                assert_eq!(grant_generation, 7);
                assert_eq!(certificate, line);
            }
            other => panic!("{other:?}"),
        }
        for bad in ["", "a\nb", &"a".repeat(MAX_CERTIFICATE_BYTES + 1)] {
            assert_eq!(
                install_request(&ok, bad).unwrap_err(),
                RemoteRefusal::CertificateMalformed
            );
        }
        // Not Ed25519, or not a key at all.
        assert_eq!(ed25519_fingerprint("ssh-rsa AAAA"), None);
    }
}
