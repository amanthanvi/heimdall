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
    /// ⟨M06 W3; ADR-0006 §18.7 item 12⟩ The runner's standing policy the grant was admitted
    /// under, so the controller's barrier can refuse a paused or cut-off scope before it
    /// reserves. Omitted when the grant has none (a decision confirmed runner-locally). The
    /// runner's install check stays authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<heimdall_contract::ids::PolicyId>,
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
    /// ⟨M06 W3⟩ The runner's policy the grant was admitted under, as the runner stated it
    /// (the barrier's earlier refusal only; never an authority input).
    pub policy: Option<heimdall_contract::ids::PolicyId>,
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
        policy: prepared.policy.clone(),
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

// --- ⟨M06 W3⟩ the `remote` reservation kind (ADR-0005 §3.5 "Remote reservations") ---------

/// Whether ADR-0012's role table lets `role` issue for a runner's grants (condition 1): the
/// role must hold the permission the table gives the two issuance forms
/// (`runner.prepare_remote_grant`, `runner.install_certificate`), as
/// [`heimdall_remote::roles::classify`] states it. Owner in today's table; nothing here names
/// a role.
#[must_use]
pub fn role_may_issue(role: heimdall_contract::remote::Role, grant: &GrantId) -> bool {
    use heimdall_contract::request::Request;
    use heimdall_remote::roles::{Effect, NoConsents, classify};
    let forms = [
        RunnerRequest::PrepareRemoteGrant {
            grant: grant.clone(),
            grant_generation: 0,
        },
        RunnerRequest::InstallCertificate {
            grant: grant.clone(),
            grant_generation: 0,
            certificate: String::new(),
        },
    ];
    forms.into_iter().all(|form| {
        let class = classify(&Request::Runner(form), &NoConsents);
        class.effect != Effect::Unclassified && role.permissions().contains(&class.permission)
    })
}

/// Why a reservation of kind `remote` is not admitted (ADR-0005 §3.5 "Remote reservations";
/// the condition each variant belongs to is in its doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteReservationRefusal {
    /// This store holds the grant itself: it is a local grant, never a remote reservation.
    #[error("the grant is a local grant")]
    LocalGrant,
    /// Condition 1: no record of a paired runner environment the entry names.
    #[error("no record of the runner environment")]
    NoRunnerRecord,
    /// Condition 1: this controller's role there may not issue (the role table).
    #[error("this controller's role on the runner may not issue")]
    RoleMayNotIssue,
    /// Condition 2: the barrier is not open on the report the reservation rests on (another
    /// report was read since, a session attempt failed, or the outbox is not drained).
    #[error("the reconciliation barrier is not open for the runner")]
    BarrierClosed,
    /// Condition 3: no verified prepare answer is recorded for the grant.
    #[error("no key binding from the runner's prepare answer")]
    NoKeyBinding,
    /// Condition 3: the entry's subject, generation or pair is not the one the answer bound.
    #[error("the entry does not match the runner's key binding")]
    KeyBindingMismatch,
    /// Condition 4: the entry's CA is not the one the grant is pinned to, or it is not an
    /// active CA of this controller.
    #[error("the grant is not pinned to this controller's active CA")]
    CaNotPinned,
    /// Condition 5: the key ID does not name the runner's environment and the grant.
    #[error("the key ID does not name the runner's environment")]
    KeyId,
    /// Condition 6: no record of a grant this controller delivered to that runner.
    #[error("no record of a grant delivered to the runner")]
    NotDelivered,
    /// Condition 6: the principal is not one of the delivered pairs' (as narrowed by the
    /// runner's answer).
    #[error("the principal was not delivered")]
    PrincipalNotDelivered,
    /// Condition 6: an extension the delivered grant does not carry, or one no certificate
    /// may carry.
    #[error("an extension was not delivered")]
    ExtensionNotDelivered,
    /// Conditions 6 and 7: `valid_before` is past the grant's expiry, the effective cutoff
    /// or the runner's reported latest possible credential expiry, or the validity is
    /// longer than the delivered grant's window.
    #[error("the validity exceeds the delivered grant's bound")]
    ValidityTooLate,
    /// Condition 7: the bound has passed, or the validity is empty.
    #[error("the bound has passed")]
    BoundPassed,
    /// The grant is tombstoned in this ledger (a revoked grant is never issued for again).
    #[error("the grant is revoked")]
    GrantRevoked,
}

/// Everything a `remote` reservation is judged against, read in one snapshot of this
/// controller's own store ([`crate::check::assess_remote_reservation`] assembles it).
#[derive(Debug, Clone, Copy)]
pub struct RemoteReservationView<'a> {
    /// The reserved entry.
    pub entry: &'a heimdall_domain::issuance::IssuanceEntry,
    /// The SHA-256 fingerprint of the `sign` request's subject key, when it is one key line.
    pub subject_fingerprint: Option<&'a str>,
    /// Whether this store holds a grant of the entry's ID (then it is not a runner's).
    pub local_grant: bool,
    /// This controller's record of the runner environment the key ID names.
    pub pin: Option<&'a heimdall_contract::controller_record::RemoteEnvironmentPin>,
    /// This controller's record of the grant it delivered there.
    pub delivered: Option<&'a heimdall_store::ext_effects::DeliveredGrant>,
    /// What this controller last saw of the runner.
    pub contact: &'a heimdall_store::ext_effects::RemoteContact,
    /// Whether this controller's outbox for the runner has an unacknowledged effect.
    pub outbox_pending: bool,
    /// Whether the grant is tombstoned in this ledger.
    pub tombstoned: bool,
    /// Whether the entry's CA is registered `active` in this store.
    pub ca_active: bool,
    /// The issuer's accepted time.
    pub now: Timestamp,
}

/// The environment a `heimdall:<environment>:<id>:<serial>` key ID names.
#[must_use]
pub fn key_id_environment(key_id: &str) -> Option<EnvironmentId> {
    let mut parts = key_id.split(':');
    match (parts.next(), parts.next()) {
        (Some("heimdall"), Some(env)) => EnvironmentId::parse(env).ok(),
        _ => None,
    }
}

/// ADR-0005 §3.5 "Remote reservations": admit a reservation of kind `remote` only when
/// conditions 1–7 all hold in `view`. Pure: it reads nothing and trusts nothing of the
/// `sign` request but the subject's fingerprint, which must equal the bound key's.
///
/// # Errors
///
/// The first [`RemoteReservationRefusal`] that applies, in the amendment's order.
pub fn admit_remote_reservation(
    view: &RemoteReservationView<'_>,
) -> Result<(), RemoteReservationRefusal> {
    use RemoteReservationRefusal as R;
    let entry = view.entry;
    let bounds = &entry.bounds;
    if view.local_grant {
        return Err(R::LocalGrant);
    }
    // 1. The environment, and this controller's role there.
    let pin = view.pin.ok_or(R::NoRunnerRecord)?;
    if !role_may_issue(pin.role, &entry.grant) {
        return Err(R::RoleMayNotIssue);
    }
    if view.tombstoned {
        return Err(R::GrantRevoked);
    }
    // 6 (the record itself): nothing is signed for a grant this controller did not deliver.
    let delivered = view
        .delivered
        .filter(|d| d.environment == pin.environment && d.grant == entry.grant)
        .ok_or(R::NotDelivered)?;
    // 3. The key binding of the verified prepare answer.
    let binding = delivered.prepared.as_ref().ok_or(R::NoKeyBinding)?;
    // 2. The barrier: the outbox drained, and the reservation rests on the report on record.
    let report_current = view
        .contact
        .last_report
        .as_ref()
        .is_some_and(|r| r.at == binding.report_at);
    if view.outbox_pending || view.contact.last_failure.is_some() || !report_current {
        return Err(R::BarrierClosed);
    }
    if binding.grant_generation != entry.generation.0
        || binding.key_fingerprint != bounds.subject_fingerprint
        || view.subject_fingerprint != Some(bounds.subject_fingerprint.as_str())
        || !binding.pairs.contains(&entry.pair)
    {
        return Err(R::KeyBindingMismatch);
    }
    // 4. The CA.
    if bounds.ca_fingerprint.as_ref() != Some(&binding.ca_fingerprint) || !view.ca_active {
        return Err(R::CaNotPinned);
    }
    // 5. The key ID names the runner's environment (and the grant).
    if !crate::check::key_id_within_ceiling(
        &bounds.key_id,
        pin.environment.as_str(),
        entry.grant.as_str(),
    ) {
        return Err(R::KeyId);
    }
    // 6. The content: this controller's record, narrowed by the runner's answer.
    if !delivered.pairs.contains(&entry.pair)
        || bounds.principal != principal_for(&entry.pair)
        || !principal_within_ceiling(&bounds.principal)
    {
        return Err(R::PrincipalNotDelivered);
    }
    if !bounds.extensions.is_subset(&delivered.extensions)
        || !crate::check::extensions_within_ceiling(bounds.extensions.iter())
    {
        return Err(R::ExtensionNotDelivered);
    }
    // 7. The validity bound.
    if bounds.valid_before <= bounds.valid_after || view.now >= bounds.valid_before {
        return Err(R::BoundPassed);
    }
    let bound = [Some(binding.runner_bound), binding.cutoff]
        .into_iter()
        .flatten()
        .fold(delivered.expires_at, Timestamp::min);
    let window =
        std::time::Duration::try_from(delivered.expires_at.duration_since(delivered.delivered_at))
            .unwrap_or(std::time::Duration::ZERO);
    if bounds.valid_before > bound || !crate::check::validity_within_ceiling(bounds, window) {
        return Err(R::ValidityTooLate);
    }
    Ok(())
}

/// This controller's issuer as remote issuance uses it
/// (`heimdall_app::remote_status_driver::RemoteIssuer`): [`verify_prepared`], and a `sign` of
/// kind `remote` through the issuer child, which admits the reservation only under
/// [`admit_remote_reservation`].
pub struct ChildRemoteIssuer {
    store: std::sync::Arc<heimdall_store::Store>,
    issuer: std::sync::Arc<dyn heimdall_app::ports::IssuerPort>,
}

impl std::fmt::Debug for ChildRemoteIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildRemoteIssuer").finish_non_exhaustive()
    }
}

impl ChildRemoteIssuer {
    /// The issuer over this controller's `store` (its CA registry) and its issuer child.
    #[must_use]
    pub fn new(
        store: std::sync::Arc<heimdall_store::Store>,
        issuer: std::sync::Arc<dyn heimdall_app::ports::IssuerPort>,
    ) -> Self {
        Self { store, issuer }
    }
}

fn refused(message: impl Into<String>) -> heimdall_app::OpError {
    heimdall_app::OpError::new(
        heimdall_contract::code::Code::CapabilityUnavailable,
        message,
    )
    .with_effect(heimdall_contract::envelope::EffectStatus::None)
}

#[async_trait::async_trait]
impl heimdall_app::remote_status_driver::RemoteIssuer for ChildRemoteIssuer {
    /// The one `active` CA registered in this store. No CA, or more than one active (the
    /// store's rotation keeps one), refuses: nothing is signed with a guessed key.
    fn ca(&self) -> Result<CaFingerprint, heimdall_app::OpError> {
        use heimdall_contract::envelope::reason;
        let unavailable = || {
            refused("this controller has no active issuer CA")
                .with_reason(reason::ISSUER_UNAVAILABLE)
        };
        // ⟨ADR-0005 §3.5 condition 9⟩ Exactly one active CA: remote issuance pauses while a
        // rotation holds two.
        let rotating = || {
            refused(
                "this controller has more than one active issuer CA: remote issuance pauses \
                 during a CA rotation",
            )
            .with_reason(reason::ISSUER_UNAVAILABLE)
        };
        let active: Vec<CaFingerprint> = self
            .store
            .transaction(|tx| tx.issuers())
            .map_err(|_| unavailable())?
            .into_iter()
            .filter(|i| i.state == heimdall_contract::issuer::CaState::Active)
            .map(|i| i.ca_fingerprint)
            .collect();
        match active.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(unavailable()),
            _ => Err(rotating()),
        }
    }

    fn verify(
        &self,
        ask: &heimdall_app::remote_status_driver::RemoteAsk,
        answer: serde_json::Value,
        now: Timestamp,
    ) -> Result<heimdall_app::remote_status_driver::RemoteSubject, heimdall_app::OpError> {
        let prepared: PreparedRemoteGrant = serde_json::from_value(answer)
            .map_err(|_| refused("the runner's prepare answer is not well formed"))?;
        let expected = RemoteExpectation {
            environment: ask.environment.clone(),
            grant: ask.grant.clone(),
            grant_generation: ask.grant_generation,
            controller: ask.controller.clone(),
            ca_fingerprint: ask.ca_fingerprint.clone(),
        };
        let request = verify_prepared(&expected, &prepared, now).map_err(|r| {
            let e = refused(r.to_string());
            match r.reason() {
                Some(reason) => e.with_reason(reason),
                None => e,
            }
        })?;
        Ok(heimdall_app::remote_status_driver::RemoteSubject {
            subject_public_key: request.subject_public_key,
            subject_fingerprint: request.subject_fingerprint,
            pairs: request.pairs,
            bound: request.bound,
            policy: request.policy,
        })
    }

    async fn sign(
        &self,
        entry: &heimdall_domain::issuance::IssuanceEntry,
        subject: &str,
    ) -> Result<String, heimdall_app::OpError> {
        use heimdall_app::ports::{IssuanceRef, IssuanceTable, IssuerError};
        use heimdall_contract::code::Code;
        use heimdall_contract::envelope::reason;
        let reference = IssuanceRef {
            table: IssuanceTable::Remote,
            id: entry.id.clone(),
        };
        self.issuer
            .sign(reference, subject)
            .await
            .map_err(|e| match e {
                // ⟨M06 W3 grant-path⟩ The wire names the nearest existing reason only; the
                // condition that refuses is read from this same store and named in the text.
                IssuerError::Refused(r) => {
                    match crate::check::explain_remote_refusal(
                        &self.store,
                        &entry.id,
                        subject,
                        entry.reserved_at,
                    ) {
                        Some(condition) => refused(format!(
                            "the issuer refused the remote reservation ({r}): {condition}"
                        )),
                        None => refused(format!("the issuer refused the remote reservation: {r}")),
                    }
                }
                IssuerError::Unavailable(why) => heimdall_app::OpError::new(
                    Code::CapabilityUnavailable,
                    "this controller's issuer is not available",
                )
                .with_reason(if why.is_empty() {
                    reason::ISSUER_UNAVAILABLE
                } else {
                    &why
                }),
                IssuerError::Timeout => heimdall_app::OpError::new(
                    Code::ServiceUnavailable,
                    "the issuer did not answer in time",
                ),
                _ => heimdall_app::OpError::new(
                    Code::InternalError,
                    "the issuer's answer was not understood",
                ),
            })
    }
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
            policy: None,
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
