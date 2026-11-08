//! ⟨M03⟩ Production verification: the verification issuance entries, their
//! predicate, and the trace classification (ADR-0008 D5 §6.5; m03-plan §5 item 16;
//! U0b row 4).
//!
//! Verification certificates have no grant, so they live in their own issuance
//! table with their own predicate, [`check`], applied identically at reserve and at
//! publish (as `issuance::check` is). [`classify`] is the D5 §6.5 classification
//! table; its body is U5's, and until then it returns an inconclusive verdict,
//! never a pass.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::EnrollmentForm;
use heimdall_contract::ids::{CaFingerprint, IssuanceId, OperationId};
use serde::{Deserialize, Serialize};

use crate::issuance::{CertificateBounds, IssuanceState, principal_for};
use crate::operation::OperationKind;
use crate::scope::AccessPair;
use crate::time::TimeStatus;

/// At most this many entries per verification attempt (ADR-0008 D5 §6.5 item 2).
pub const MAX_ENTRIES_PER_ATTEMPT: u32 = 4;
/// At most this many attempts per operation (`verification_attempts`).
pub const MAX_ATTEMPTS_PER_OPERATION: u32 = 3;
/// `valid_after` is backdated by this much (ADR-0005 §3.4, D5 §6.5 item 2).
pub const BACKDATE: Duration = Duration::from_secs(60);
/// The negative principal's prefix; 32 lowercase hex characters follow.
pub const NEGATIVE_PRINCIPAL_PREFIX: &str = "hm:verify-negative:";

/// Which of the two verification certificates an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationPurpose {
    /// Principal `hm:<destination-id>:<account>`; must be accepted (also the
    /// system form's absence check, which must be refused).
    Positive,
    /// Principal `hm:verify-negative:<32 hex nonce>`; must be refused.
    Negative,
}

/// Why a verification entry is refused (ADR-0008 D5 §6.5 item 2; m03-plan §5 item
/// 16). Applied at reserve and at publish; at publish a refusal voids the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationRefusal {
    /// The operation is not an approved `enrollment.apply` or an `enrollment.verify`
    /// at its verification stage.
    #[error("the operation is not verifying")]
    OperationNotVerifying,
    /// The entry's pair is not the plan's.
    #[error("the entry's pair is not the plan's")]
    PairMismatch,
    /// The entry's CA is absent or not the plan's.
    #[error("the entry's CA is not the plan's")]
    CaMismatch,
    /// The principal is not exactly the positive or negative form.
    #[error("the principal is not the verification principal")]
    WrongPrincipal,
    /// Extensions were requested (`ssh -T` needs none: `clear`).
    #[error("verification certificates carry no extensions")]
    ExtensionsPresent,
    /// The validity window exceeds `valid_after = now − 60 s`, `valid_before ≤ now +
    /// max_validity`.
    #[error("the validity is too long")]
    ValidityTooLong,
    /// The subject is not K_verify registered by this operation's endpoint.
    #[error("the subject key is not this operation's verification key")]
    UnknownSubjectKey,
    /// Time is not `Safe`.
    #[error("time is uncertain")]
    TimeUncertain,
    /// More than 4 entries in the attempt, or more than 3 attempts.
    #[error("too many verification entries")]
    TooManyEntries,
}

/// One verification issuance entry (ADR-0008 D5 §6.5 item 2). Entries count toward
/// the per-pair residual until their `valid_before` (D7 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationEntry {
    /// ID.
    pub id: IssuanceId,
    /// The verifying operation.
    pub operation: OperationId,
    /// The pair.
    pub pair: AccessPair,
    /// Positive or negative.
    pub purpose: VerificationPurpose,
    /// Bounds (`ca_fingerprint` is `Some`).
    pub bounds: CertificateBounds,
    /// State.
    pub state: IssuanceState,
    /// Reserved at.
    pub reserved_at: Timestamp,
    /// Published or voided at.
    pub settled_at: Option<Timestamp>,
    /// Why voided, when voided.
    pub void_reason: Option<VerificationRefusal>,
}

/// The operation facts the predicate needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingOperation {
    /// The operation's kind.
    pub kind: OperationKind,
    /// Its authorization is in place: an `enrollment.apply`'s approval basis, or a
    /// target-change `enrollment.verify`'s `ApproveTargetChange`. A presence or
    /// absence `enrollment.verify` needs no decision (`true`).
    pub authorized: bool,
    /// The operation is at its verification stage (E4, or the re-verification
    /// stage).
    pub at_verification_stage: bool,
}

/// Everything [`check`] looks at; built inside the reserve or publish transaction.
#[derive(Debug, Clone)]
pub struct VerificationCheck<'a> {
    /// The operation.
    pub operation: VerifyingOperation,
    /// The entry's pair.
    pub entry_pair: &'a AccessPair,
    /// The plan's pair.
    pub plan_pair: &'a AccessPair,
    /// The plan's CA.
    pub plan_ca: &'a CaFingerprint,
    /// Positive or negative.
    pub purpose: VerificationPurpose,
    /// The requested bounds.
    pub bounds: &'a CertificateBounds,
    /// The subject is K_verify, registered by this operation's endpoint.
    pub subject_registered: bool,
    /// The time gate.
    pub time: TimeStatus,
    /// Now (the gate's wall time).
    pub now: Timestamp,
    /// `verification_max_validity` (300 s).
    pub max_validity: Duration,
    /// Entries of this attempt, this one included.
    pub entries_in_attempt: u32,
    /// Attempts of this operation, this one included.
    pub attempts: u32,
}

fn is_negative_principal(p: &str) -> bool {
    p.strip_prefix(NEGATIVE_PRINCIPAL_PREFIX)
        .is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn plus(t: Timestamp, d: Duration) -> Option<Timestamp> {
    let d = jiff::SignedDuration::try_from(d).ok()?;
    t.checked_add(d).ok()
}

fn minus(t: Timestamp, d: Duration) -> Option<Timestamp> {
    let d = jiff::SignedDuration::try_from(d).ok()?;
    t.checked_sub(d).ok()
}

/// ADR-0008 D5 §6.5 item 2, in order; the first failing predicate is returned:
/// 1. the operation is verifying (`OperationNotVerifying`);
/// 2. the entry's pair is the plan's (`PairMismatch`) and its CA the plan's
///    (`CaMismatch`);
/// 3. the principal is exactly `hm:<destination-id>:<account>` (positive) or
///    `hm:verify-negative:<32 lowercase hex>` (negative) (`WrongPrincipal`);
/// 4. no extensions (`ExtensionsPresent`);
/// 5. validity: `valid_after < valid_before`, `valid_after ≤ now`, `valid_before ≤
///    now + max_validity`, and the window at most `max_validity + 60 s`
///    (`ValidityTooLong`; an overflow refuses);
/// 6. the subject is registered K_verify (`UnknownSubjectKey`);
/// 7. time `Safe` (`TimeUncertain`);
/// 8. at most 4 entries per attempt and 3 attempts (`TooManyEntries`).
pub fn check(input: &VerificationCheck<'_>) -> Result<(), VerificationRefusal> {
    use VerificationRefusal as R;
    let op = input.operation;
    let verifying_kind = matches!(
        op.kind,
        OperationKind::EnrollmentApply | OperationKind::EnrollmentVerify
    );
    if !(verifying_kind && op.authorized && op.at_verification_stage) {
        return Err(R::OperationNotVerifying);
    }
    if input.entry_pair != input.plan_pair {
        return Err(R::PairMismatch);
    }
    if input.bounds.ca_fingerprint.as_ref() != Some(input.plan_ca) {
        return Err(R::CaMismatch);
    }
    let principal_ok = match input.purpose {
        VerificationPurpose::Positive => input.bounds.principal == principal_for(input.plan_pair),
        VerificationPurpose::Negative => is_negative_principal(&input.bounds.principal),
    };
    if !principal_ok {
        return Err(R::WrongPrincipal);
    }
    if !input.bounds.extensions.is_empty() {
        return Err(R::ExtensionsPresent);
    }
    let b = input.bounds;
    let latest_before = plus(input.now, input.max_validity).ok_or(R::ValidityTooLong)?;
    let window = input
        .max_validity
        .checked_add(BACKDATE)
        .ok_or(R::ValidityTooLong)?;
    let earliest_after = minus(b.valid_before, window).ok_or(R::ValidityTooLong)?;
    if b.valid_after >= b.valid_before
        || b.valid_after > input.now
        || b.valid_before > latest_before
        || b.valid_after < earliest_after
    {
        return Err(R::ValidityTooLong);
    }
    if !input.subject_registered {
        return Err(R::UnknownSubjectKey);
    }
    if input.time != TimeStatus::Safe {
        return Err(R::TimeUncertain);
    }
    if input.entries_in_attempt > MAX_ENTRIES_PER_ATTEMPT
        || input.attempts > MAX_ATTEMPTS_PER_OPERATION
    {
        return Err(R::TooManyEntries);
    }
    Ok(())
}

/// The events the Verifier extracts from one attempt's `-v` trace (ADR-0008 D5 §6.5
/// item 5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvents {
    /// The remote software version line.
    pub server_version: Option<String>,
    /// The approved host key matched under the generated `HostKeyAlias`.
    pub host_key_matched: bool,
    /// The certificate under test was offered.
    pub offered_certificate: bool,
    /// The server accepted the offered key or certificate.
    pub accepted: bool,
    /// After the offer, "Authentications that can continue" with `publickey` and no
    /// acceptance.
    pub not_accepted: bool,
    /// The run ended with a public-key authentication failure.
    pub publickey_failure_final: bool,
}

/// One verification attempt's observable result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptResult {
    /// The client's exit status (`None`: killed or not started).
    pub exit_status: Option<i32>,
    /// Signatures the verification endpoint recorded for K_verify.
    pub signatures: u32,
    /// Trace events.
    pub trace: TraceEvents,
    /// The `HM1 now=` reading (remote epoch seconds), positive attempt only.
    pub remote_now: Option<i64>,
}

/// Which column of the classification table applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationPhase {
    /// The initial verification (`verifying`).
    Initial,
    /// A later verification (`reverifying`).
    Reverify,
}

/// Why a verification is inconclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InconclusiveReason {
    /// A transport failure (refused, reset, timeout, `MaxStartups`): never a refusal.
    Transport,
    /// The client's trace family or version is unrecorded.
    UnrecordedClientFamily,
    /// A refusal a destination clock skew could explain (`destination_clock_skew`).
    DestinationClockSkew,
    /// A foreign system-form absence check: this device holds no key of the CA
    /// (`ca_not_held`, Q28).
    CaNotHeld,
    /// Anything the table does not classify (and wave 0's [`classify`]).
    Unclassified,
}

impl InconclusiveReason {
    /// Every reason.
    pub const ALL: [InconclusiveReason; 5] = [
        InconclusiveReason::Transport,
        InconclusiveReason::UnrecordedClientFamily,
        InconclusiveReason::DestinationClockSkew,
        InconclusiveReason::CaNotHeld,
        InconclusiveReason::Unclassified,
    ];
}

/// The outcome of a verification run (ADR-0008 D5 §6.5 classification table). The
/// enrollment state machine maps it to the next state per form and phase
/// (`crate::enrollment::transition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationVerdict {
    /// Positive passed and negative refused with full evidence.
    Passed,
    /// The negative was accepted, or a signature was recorded for it.
    PrincipalsNotEnforced,
    /// The positive was refused with refusal evidence (`verification_failed`).
    PositiveRefused,
    /// The host key did not match (`HOST_TRUST_CHANGED`; no rollback).
    HostKeyMismatch,
    /// Anything else.
    Inconclusive {
        /// Why.
        reason: InconclusiveReason,
    },
}

impl VerificationVerdict {
    /// Every verdict (each inconclusive reason once).
    #[must_use]
    pub fn all() -> Vec<VerificationVerdict> {
        let mut out = vec![
            VerificationVerdict::Passed,
            VerificationVerdict::PrincipalsNotEnforced,
            VerificationVerdict::PositiveRefused,
            VerificationVerdict::HostKeyMismatch,
        ];
        out.extend(
            InconclusiveReason::ALL
                .into_iter()
                .map(|reason| VerificationVerdict::Inconclusive { reason }),
        );
        out
    }

    /// Whether this is an inconclusive verdict.
    #[must_use]
    pub fn is_inconclusive(self) -> bool {
        matches!(self, VerificationVerdict::Inconclusive { .. })
    }
}

/// ADR-0008 D5 §6.5 classification: the positive and negative attempts' results to
/// a verdict, per phase and form. **Signature only in wave 0**: U5 writes the
/// table. Until then every input is `inconclusive` (`unclassified`), never a pass,
/// so nothing can be recorded `verified` through it.
#[must_use]
pub fn classify(
    positive: &AttemptResult,
    negative: &AttemptResult,
    phase: VerificationPhase,
    form: EnrollmentForm,
) -> VerificationVerdict {
    let _ = (positive, negative, phase, form);
    VerificationVerdict::Inconclusive {
        reason: InconclusiveReason::Unclassified,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use heimdall_contract::ids::{AccountName, DestinationId};

    use super::*;
    use crate::time::TimeUncertainty;

    fn t(secs: i64) -> Timestamp {
        "2026-11-10T14:00:00Z"
            .parse::<Timestamp>()
            .unwrap()
            .checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    }

    fn pair(d: &str) -> AccessPair {
        AccessPair {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn ca(c: char) -> CaFingerprint {
        CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
    }

    #[test]
    fn one_refusal_per_predicate() {
        let p = pair("web");
        let other = pair("db");
        let a = ca('a');
        let bounds = CertificateBounds {
            serial: 1,
            key_id: "k".into(),
            principal: principal_for(&p),
            valid_after: t(-60),
            valid_before: t(300),
            extensions: BTreeSet::new(),
            subject_fingerprint: "fp".into(),
            ca_fingerprint: Some(a.clone()),
        };
        let base = || VerificationCheck {
            operation: VerifyingOperation {
                kind: OperationKind::EnrollmentApply,
                authorized: true,
                at_verification_stage: true,
            },
            entry_pair: &p,
            plan_pair: &p,
            plan_ca: &a,
            purpose: VerificationPurpose::Positive,
            bounds: &bounds,
            subject_registered: true,
            time: TimeStatus::Safe,
            now: t(0),
            max_validity: Duration::from_secs(300),
            entries_in_attempt: 1,
            attempts: 1,
        };
        assert_eq!(check(&base()), Ok(()));
        use VerificationRefusal as R;
        let mut c = base();
        c.operation.kind = OperationKind::Ensure;
        assert_eq!(check(&c), Err(R::OperationNotVerifying));
        let mut c = base();
        c.entry_pair = &other;
        assert_eq!(check(&c), Err(R::PairMismatch));
        let b2 = ca('b');
        let mut c = base();
        c.plan_ca = &b2;
        assert_eq!(check(&c), Err(R::CaMismatch));
        let mut c = base();
        c.purpose = VerificationPurpose::Negative;
        assert_eq!(check(&c), Err(R::WrongPrincipal));
        let mut ext = bounds.clone();
        ext.extensions.insert("permit-pty".into());
        let mut c = base();
        c.bounds = &ext;
        assert_eq!(check(&c), Err(R::ExtensionsPresent));
        let mut long = bounds.clone();
        long.valid_before = t(301);
        let mut c = base();
        c.bounds = &long;
        assert_eq!(check(&c), Err(R::ValidityTooLong));
        let mut c = base();
        c.subject_registered = false;
        assert_eq!(check(&c), Err(R::UnknownSubjectKey));
        let mut c = base();
        c.time = TimeStatus::Uncertain(TimeUncertainty::ContinuousWentBackwards);
        assert_eq!(check(&c), Err(R::TimeUncertain));
        let mut c = base();
        c.entries_in_attempt = 5;
        assert_eq!(check(&c), Err(R::TooManyEntries));
        let mut neg = bounds.clone();
        neg.principal = format!("{NEGATIVE_PRINCIPAL_PREFIX}{}", "0f".repeat(16));
        let mut c = base();
        c.purpose = VerificationPurpose::Negative;
        c.bounds = &neg;
        assert_eq!(check(&c), Ok(()));
    }

    #[test]
    fn wave0_classify_never_passes() {
        let pass = AttemptResult {
            exit_status: Some(0),
            signatures: 1,
            trace: TraceEvents {
                server_version: Some("OpenSSH_10.0".into()),
                host_key_matched: true,
                offered_certificate: true,
                accepted: true,
                ..TraceEvents::default()
            },
            remote_now: Some(1),
        };
        let v = classify(
            &pass,
            &AttemptResult::default(),
            VerificationPhase::Initial,
            EnrollmentForm::Account,
        );
        assert!(v.is_inconclusive());
    }
}
