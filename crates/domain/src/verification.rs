//! ⟨M03⟩ Production verification: the verification issuance entries, their
//! predicate, and the trace classification (ADR-0008 D5 §6.5; m03-plan §5 item 16;
//! U0b row 4).
//!
//! Verification certificates have no grant, so they live in their own issuance
//! table with their own predicate, [`check`], applied identically at reserve and at
//! publish (as `issuance::check` is). [`classify`] is the D5 §6.5 classification
//! table (ADR-0008 §17.17 item 14, U5IO-Q4: U5's body, moved here in wave 4).

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
    /// ⟨M03 wave 4, §17.17 item 14 (U5IO-Q4)⟩ The trace showed a host-key verification
    /// failure (`HOST_TRUST_CHANGED`; never a refusal, never rolled back).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_key_failure: bool,
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

/// A known offset of the destination clock (ADR-0008 D5 §6.5 "The skew rule"): the
/// remote clock minus local time, with its uncertainty (1 s plus the round trip).
/// The initial verification takes it from the operation's E2 `inspect` reading, a
/// re-verification from the enrollment's last fresh `ClockMeasurement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KnownOffset {
    /// Remote minus local, in milliseconds (negative: the destination lags).
    pub remote_minus_local_ms: i64,
    /// The uncertainty, in milliseconds.
    pub uncertainty_ms: u64,
}

impl KnownOffset {
    /// Whether the interval reaches a lag of `lag_ms` or a lead of `lead_ms` (the
    /// `verification_skew_lag` and `verification_skew_lead`: 60 s and 300 s).
    #[must_use]
    pub fn beyond(&self, lag_ms: u64, lead_ms: u64) -> bool {
        let o = i128::from(self.remote_minus_local_ms);
        let u = i128::from(self.uncertainty_ms);
        u - o >= i128::from(lag_ms) || o + u >= i128::from(lead_ms)
    }
}

/// What [`classify`] needs beside the two attempts (ADR-0008 §17.17 item 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassifyContext {
    /// The client's trace family or version is unrecorded: no attempt ran
    /// (`VerificationOutcome::unrecorded`).
    pub unrecorded: bool,
    /// The known clock offset, if any.
    pub offset: Option<KnownOffset>,
    /// `verification_skew_lag` in milliseconds (60 000).
    pub skew_lag_ms: u64,
    /// `verification_skew_lead` in milliseconds (300 000).
    pub skew_lead_ms: u64,
}

impl ClassifyContext {
    /// No offset known, the recorded client, the default allowances (60 s, 300 s).
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            unrecorded: false,
            offset: None,
            skew_lag_ms: 60_000,
            skew_lead_ms: 300_000,
        }
    }
}

fn positive_passed(a: &AttemptResult) -> bool {
    let t = &a.trace;
    a.exit_status == Some(0)
        && t.server_version.is_some()
        && t.host_key_matched
        && t.offered_certificate
        && t.accepted
        && a.signatures == 1
        && a.remote_now.is_some()
}

fn refused(a: &AttemptResult) -> bool {
    let t = &a.trace;
    a.exit_status.is_some_and(|c| c != 0)
        && t.server_version.is_some()
        && t.host_key_matched
        && t.offered_certificate
        && t.not_accepted
        && !t.accepted
        && t.publickey_failure_final
        && a.signatures == 0
}

fn accepted_or_signed(a: &AttemptResult) -> bool {
    a.exit_status == Some(0) || a.trace.accepted || a.signatures > 0
}

/// ADR-0008 D5 §6.5 classification (§17.17 item 14, U5IO-Q4: the body proposed as
/// `heimdall_enroll::verify::classify_evidence`), in order:
///
/// 1. an unrecorded client: inconclusive, `unrecorded_client_family`;
/// 2. a host-key failure in either attempt: `host_key_mismatch`;
/// 3. positive passed (exit 0, server version, host key matched, certificate offered
///    and accepted, **exactly one** signature, the `HM1 now=` reading) and the negative
///    refused (exit ≠ 0, server version, host key matched, offered, not accepted, a
///    final public-key failure, **zero** signatures): `passed`; positive passed and the
///    negative accepted or signed: `principals_not_enforced`; positive passed
///    otherwise: inconclusive (`transport`: a transport failure is never a refusal);
/// 4. positive refused with full refusal evidence: inconclusive
///    `destination_clock_skew` when the known offset is beyond the allowance, else
///    `positive_refused`;
/// 5. anything else: inconclusive (`transport`).
///
/// The verdict does not depend on the phase or the form; the state each verdict leads
/// to does (`crate::enrollment::transition`).
#[must_use]
pub fn classify(
    positive: &AttemptResult,
    negative: &AttemptResult,
    phase: VerificationPhase,
    form: EnrollmentForm,
    context: &ClassifyContext,
) -> VerificationVerdict {
    let _ = (phase, form);
    let inconclusive = |reason| VerificationVerdict::Inconclusive { reason };
    if context.unrecorded {
        return inconclusive(InconclusiveReason::UnrecordedClientFamily);
    }
    if positive.trace.host_key_failure || negative.trace.host_key_failure {
        return VerificationVerdict::HostKeyMismatch;
    }
    if positive_passed(positive) {
        if refused(negative) {
            return VerificationVerdict::Passed;
        }
        if accepted_or_signed(negative) {
            return VerificationVerdict::PrincipalsNotEnforced;
        }
        return inconclusive(InconclusiveReason::Transport);
    }
    if refused(positive) {
        if context
            .offset
            .is_some_and(|o| o.beyond(context.skew_lag_ms, context.skew_lead_ms))
        {
            return inconclusive(InconclusiveReason::DestinationClockSkew);
        }
        return VerificationVerdict::PositiveRefused;
    }
    inconclusive(InconclusiveReason::Transport)
}

/// ADR-0008 D5 §6.9 the system form's **absence** check: the positive certificate
/// must be **refused** with the full refusal evidence. `Passed` means the absence is
/// verified; anything else is not (an accepted positive, a host-key failure, or any
/// inconclusive result returns the record to `manual_removal_pending`).
#[must_use]
pub fn absence_verified(positive: &AttemptResult, context: &ClassifyContext) -> bool {
    !context.unrecorded && !positive.trace.host_key_failure && refused(positive)
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

    fn passed_positive() -> AttemptResult {
        AttemptResult {
            exit_status: Some(0),
            signatures: 1,
            trace: TraceEvents {
                server_version: Some("OpenSSH_10.0".into()),
                host_key_matched: true,
                offered_certificate: true,
                accepted: true,
                ..TraceEvents::default()
            },
            remote_now: Some(1_800_000_000),
        }
    }

    fn refused_attempt() -> AttemptResult {
        AttemptResult {
            exit_status: Some(255),
            signatures: 0,
            trace: TraceEvents {
                server_version: Some("OpenSSH_10.0".into()),
                host_key_matched: true,
                offered_certificate: true,
                not_accepted: true,
                publickey_failure_final: true,
                ..TraceEvents::default()
            },
            remote_now: None,
        }
    }

    fn go(p: &AttemptResult, n: &AttemptResult, c: &ClassifyContext) -> VerificationVerdict {
        classify(p, n, VerificationPhase::Initial, EnrollmentForm::Account, c)
    }

    /// ADR-0008 §17.17 item 14: the D5 §6.5 table (U5IO-Q4's body).
    #[test]
    fn classify_follows_the_d5_table() {
        use InconclusiveReason as I;
        use VerificationVerdict as V;
        let c = ClassifyContext::recorded();
        let (p, n) = (passed_positive(), refused_attempt());
        assert_eq!(go(&p, &n, &c), V::Passed);
        // A positive with two signatures, or without the clock reading, never passes.
        let mut two = p.clone();
        two.signatures = 2;
        assert_eq!(
            go(&two, &n, &c),
            V::Inconclusive {
                reason: I::Transport
            }
        );
        let mut no_now = p.clone();
        no_now.remote_now = None;
        assert_eq!(
            go(&no_now, &n, &c),
            V::Inconclusive {
                reason: I::Transport
            }
        );
        // The negative accepted or signed: principals not enforced.
        let mut signed = n.clone();
        signed.signatures = 1;
        assert_eq!(go(&p, &signed, &c), V::PrincipalsNotEnforced);
        assert_eq!(go(&p, &p, &c), V::PrincipalsNotEnforced);
        // A transport failure of the negative is never a refusal.
        assert_eq!(
            go(&p, &AttemptResult::default(), &c),
            V::Inconclusive {
                reason: I::Transport
            }
        );
        // The positive refused.
        assert_eq!(go(&n, &n, &c), V::PositiveRefused);
        // ... while the destination's clock is skewed beyond the allowance.
        let skewed = ClassifyContext {
            offset: Some(KnownOffset {
                remote_minus_local_ms: -120_000,
                uncertainty_ms: 1_000,
            }),
            ..c
        };
        assert_eq!(
            go(&n, &n, &skewed),
            V::Inconclusive {
                reason: I::DestinationClockSkew
            }
        );
        // A host-key failure in either attempt.
        let mut hk = n.clone();
        hk.trace.host_key_failure = true;
        assert_eq!(go(&p, &hk, &c), V::HostKeyMismatch);
        // An unrecorded client.
        let unrecorded = ClassifyContext {
            unrecorded: true,
            ..c
        };
        assert_eq!(
            go(&p, &n, &unrecorded),
            V::Inconclusive {
                reason: I::UnrecordedClientFamily
            }
        );
        // Absence: only a full refusal.
        assert!(absence_verified(&n, &c));
        assert!(!absence_verified(&p, &c));
        assert!(!absence_verified(&AttemptResult::default(), &c));
        assert!(!absence_verified(&hk, &c));
    }

    #[test]
    fn known_offset_beyond_the_allowance() {
        let o = |m: i64, u: u64| KnownOffset {
            remote_minus_local_ms: m,
            uncertainty_ms: u,
        };
        assert!(!o(0, 1_000).beyond(60_000, 300_000));
        assert!(o(-59_500, 1_000).beyond(60_000, 300_000));
        assert!(o(299_500, 1_000).beyond(60_000, 300_000));
        assert!(!o(298_000, 1_000).beyond(60_000, 300_000));
    }
}
