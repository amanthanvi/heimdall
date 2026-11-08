//! ⟨M03⟩ The enrollment record, its 20-state machine, foreign removal records,
//! pair preferences, and the inputs of the enrollment plan (ADR-0008 D5 §6.2, D4
//! item 5; m03-plan §5 item 16; frozen in wave 0).
//!
//! [`transition`] is exactly the ADR-0008 D5 §6.2 table (revision 2's 20 states)
//! with every revision-3..6 transition and the binding rulings §17.4 item 5, §17.7
//! items 4–5, §17.10 item 2 and §17.12 item 2. Events carry the record facts the
//! table depends on (form, foreign or own), and every context the table names
//! (approval validity, hold kind, removal origin, whether a `ca_not_held` result
//! exists), so the whole table is data: [`EnrollmentState::ALL`] ×
//! [`EnrollmentEvent::all`] enumerates every pair.
//!
//! The wire-visible enums (`EnrollmentState`, `EnrollmentForm`, `VerifyMode`, the
//! registry and target types) live in `heimdall_contract::enrollment` and are
//! re-exported here.

use std::collections::BTreeSet;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DestinationId, EnrollmentId, ForeignRemovalId, IdentityId,
    OperationId,
};
use heimdall_contract::provider::EndpointRef;
use serde::{Deserialize, Serialize};

use crate::catalog::{DestinationRecord, IdentityRecord};
use crate::verification::VerificationVerdict;

pub use heimdall_contract::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentState, ForeignRemovalTarget,
    NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, RemovalPurpose, VerifyMode,
};
pub use heimdall_contract::managed::{ClockMeasurement, PreferredMechanism};

// --- the record --------------------------------------------------------------------

/// Why a record is `held` (ADR-0008 D5 §6.2 `held` row; `hold.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HoldReason {
    /// The negative verification was accepted (evidence-based).
    PrincipalsNotEnforced,
    /// The positive verification was refused with refusal evidence
    /// (evidence-based).
    PositiveRefused,
    /// The host key changed (`review_host_trust`; needs `ApproveTargetChange`).
    HostKeyChanged,
    /// A stale lock's holder could not be proven gone (manual recovery).
    LockHolderUnresolved,
    /// Our marker line differs, or appears more than once.
    RegistryLineDamaged,
    /// The registry changed during removal three times.
    RegistryChanged,
    /// The registry cannot be rewritten safely (manual instructions).
    RegistryNotRewritable,
    /// The post-write check after an append failed.
    PostWriteCheckFailed,
}

/// `EnrollmentRecord.hold` (ADR-0008 D5 §6.2): why, and whether the hold rests on
/// verification evidence (only such a hold may be re-verified by the owner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnrollmentHold {
    /// Why.
    pub reason: HoldReason,
    /// The hold rests on verification evidence (`principals_not_enforced`, positive
    /// refused, or verification failed after the approval lapsed).
    pub evidence_based: bool,
}

/// The kind of a hold, as the `held` row's exits need it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HoldKind {
    /// An evidence-based hold: the owner may re-verify.
    EvidenceBased,
    /// A host-key change: `ApproveTargetChange` re-approves the target.
    HostKeyChanged,
    /// `lock_holder_unresolved`: the manual-recovery reconcile classifies.
    LockHolderUnresolved,
    /// Any other hold.
    Other,
}

impl HoldKind {
    /// Every kind.
    pub const ALL: [HoldKind; 4] = [
        HoldKind::EvidenceBased,
        HoldKind::HostKeyChanged,
        HoldKind::LockHolderUnresolved,
        HoldKind::Other,
    ];
}

impl EnrollmentHold {
    /// The hold's kind.
    #[must_use]
    pub fn kind(&self) -> HoldKind {
        match self.reason {
            HoldReason::HostKeyChanged => HoldKind::HostKeyChanged,
            HoldReason::LockHolderUnresolved => HoldKind::LockHolderUnresolved,
            _ if self.evidence_based => HoldKind::EvidenceBased,
            _ => HoldKind::Other,
        }
    }
}

/// The concrete existing access approved with the plan (ADR-0008 D5 §6.2, §6.3;
/// §17.4 item 4): never `SSH_AUTH_SOCK`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExistingAccessRecord {
    /// The adopted identity.
    pub identity: IdentityId,
    /// The concrete agent endpoint, when the identity is agent-held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<EndpointRef>,
    /// The public key file pinned with `IdentityFile`, when one is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_file: Option<String>,
}

/// Verification evidence (ADR-0008 D5 §6.2, §6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentEvidence {
    /// Client version line.
    pub client: String,
    /// Server version line.
    pub server: String,
    /// The verifying operation.
    pub operation: OperationId,
    /// When verified.
    pub verified_at: Timestamp,
    /// Fresh until (at most 90 days; invalidated earlier by D5 §6.5's rules).
    pub fresh_until: Timestamp,
    /// The destination clock measurement; `None` is `unmeasured`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<ClockMeasurement>,
}

/// `EnrollmentRecord.removal_origin` (ADR-0008 D5 §6.2; §17.4 item 5): the state
/// and evidence a manual removal began from, persisted so that a cancel returns
/// there. Once a `ca_not_held` result exists it is pinned (§17.10 item 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalOrigin {
    /// The state the removal began from: `verified`, `held`, `abandoned`,
    /// `manual_pending`, or `planned` (foreign records only).
    pub state: EnrollmentState,
    /// The verification evidence of a `verified` origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EnrollmentEvidence>,
    /// The hold of a `held` origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold: Option<EnrollmentHold>,
    /// A `ca_not_held` absence result exists (foreign system form, Q28).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ca_not_held_seen: bool,
}

/// `EnrollmentRecord.late_write` (ADR-0008 D5 §6.7; §17.4 item 2): an uncertain
/// append left for `withdrawn` or `abandoned` may still land until an inspect
/// after `not_after_remote` shows absence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LateWrite {
    /// The uncertain step's token.
    pub step_token: String,
    /// Its remote not-after (epoch seconds).
    pub not_after_remote: i64,
}

/// The enrollment record (ADR-0008 D5 §6.2; frozen in wave 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    /// ID.
    pub id: EnrollmentId,
    /// Destination.
    pub destination: DestinationId,
    /// Account.
    pub account: AccountName,
    /// CA.
    pub ca_fingerprint: CaFingerprint,
    /// Form.
    pub form: EnrollmentForm,
    /// `heimdall:<enrollment-id>` ([`marker_for`]); the add's idempotency key.
    pub marker: String,
    /// The registry (display).
    pub registry: RegistryRef,
    /// The canonical registry (what the bundle and foreign removal carry).
    pub registry_canonical: RegistryCanonical,
    /// The full line's SHA-256 (hex).
    pub line_sha256: String,
    /// The approved target.
    pub target: ApprovedTarget,
    /// The approved existing access.
    pub existing_access: ExistingAccessRecord,
    /// Why held, while `held`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold: Option<EnrollmentHold>,
    /// Where a manual removal began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_origin: Option<RemovalOrigin>,
    /// The `late_write` residual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub late_write: Option<LateWrite>,
    /// State.
    pub state: EnrollmentState,
    /// When verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<Timestamp>,
    /// Verification evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EnrollmentEvidence>,
    /// Created.
    pub created_at: Timestamp,
    /// Updated.
    pub updated_at: Timestamp,
}

/// The marker of an enrollment: `heimdall:<enrollment-id>`.
#[must_use]
pub fn marker_for(id: &EnrollmentId) -> String {
    format!("heimdall:{}", id.as_str())
}

impl EnrollmentRecord {
    /// The facts [`transition`] needs about this (own) record.
    #[must_use]
    pub fn facts(&self) -> RecordFacts {
        RecordFacts {
            form: self.form,
            foreign: false,
        }
    }

    /// The removal purpose of a `rollback_*` or `remove*` state.
    #[must_use]
    pub fn removal_purpose(&self) -> Option<RemovalPurpose> {
        removal_purpose(self.state)
    }

    /// Whether this record adds its CA to the pair's issuable set (ADR-0008 D5
    /// §6.2): `verified`, or `reverifying` that started from `verified`.
    #[must_use]
    pub fn issuable(&self, reverify_from: Option<ReverifyFrom>) -> bool {
        match self.state {
            EnrollmentState::Verified => true,
            EnrollmentState::Reverifying => reverify_from == Some(ReverifyFrom::Verified),
            _ => false,
        }
    }
}

/// The removal purpose of a state: `rollback` for `rollback_pending` and
/// `rollback_unknown`, `explicit_removal` for `removing` and `remove_unknown`.
#[must_use]
pub fn removal_purpose(state: EnrollmentState) -> Option<RemovalPurpose> {
    match state {
        EnrollmentState::RollbackPending | EnrollmentState::RollbackUnknown => {
            Some(RemovalPurpose::Rollback)
        }
        EnrollmentState::Removing | EnrollmentState::RemoveUnknown => {
            Some(RemovalPurpose::ExplicitRemoval)
        }
        _ => None,
    }
}

// --- pair preference (§5 item 4b; F05) -------------------------------------------------

/// Whether the projection that renders a pair's preference is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProjectionStatus {
    /// Not yet applied (`setup apply` pending).
    Pending,
    /// Applied at this projection generation.
    Applied {
        /// The projection generation.
        generation: u64,
    },
}

/// A pair's stored preference (m03-plan §5 item 4b; F05). E5 and removal maintain
/// `issuing_cas`; `mechanism` changes only per ADR-0008 D5 §6.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairPreference {
    /// Destination.
    pub destination: DestinationId,
    /// Account.
    pub account: AccountName,
    /// Preferred mechanism.
    pub mechanism: PreferredMechanism,
    /// The projection that renders it.
    pub projection: ProjectionStatus,
    /// The CAs with a verified enrollment for the pair.
    #[serde(default)]
    pub issuing_cas: BTreeSet<CaFingerprint>,
}

// --- foreign removal (ADR-0008 D4 item 5) --------------------------------------------

/// The removal subset of [`EnrollmentState`] a foreign record may be in (ADR-0008 D4
/// item 5; §17.7 item 4): `planned`, `removing`, `remove_unknown`, `removed`,
/// `held`, `abandoned`, `withdrawn`, and for the system form
/// `manual_removal_pending` and `removal_verifying`.
pub const FOREIGN_SUBSET: [EnrollmentState; 9] = [
    EnrollmentState::Planned,
    EnrollmentState::Removing,
    EnrollmentState::RemoveUnknown,
    EnrollmentState::Removed,
    EnrollmentState::Held,
    EnrollmentState::Abandoned,
    EnrollmentState::Withdrawn,
    EnrollmentState::ManualRemovalPending,
    EnrollmentState::RemovalVerifying,
];

/// A foreign removal (ADR-0008 D4 item 5): its own table, no foreign key to the
/// issuers, keyed by the target's marker. `state` is the removal subset of
/// [`EnrollmentState`], checked by [`foreign_transition`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignRemovalRecord {
    /// ID (minted here).
    pub id: ForeignRemovalId,
    /// The full public removal descriptor.
    pub target: ForeignRemovalTarget,
    /// State (in [`FOREIGN_SUBSET`]).
    pub state: EnrollmentState,
    /// The `enrollment.remove` operation.
    pub operation: OperationId,
    /// Created.
    pub created_at: Timestamp,
    /// Where a manual (system-form) removal began: `planned` or `held`, pinned once
    /// a `ca_not_held` result exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_origin: Option<RemovalOrigin>,
}

impl ForeignRemovalRecord {
    /// The facts [`transition`] needs about this foreign record.
    #[must_use]
    pub fn facts(&self) -> RecordFacts {
        RecordFacts {
            form: self.target.form,
            foreign: true,
        }
    }
}

// --- target evaluation and the catalog view (moved below `app`, §0.6) -------------

/// A host key the evaluator found for the target (m03-plan U5; M10).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RawHostKey {
    /// Key type (`ssh-ed25519`).
    pub key_type: String,
    /// Base64 key blob.
    pub key_b64: String,
    /// `SHA256:…` fingerprint.
    pub fingerprint: String,
    /// Where it was found (display only).
    pub origin_display: String,
    /// Marked `@revoked`.
    pub revoked: bool,
}

impl RawHostKey {
    /// The approved form of this key.
    #[must_use]
    pub fn approved(&self) -> ApprovedHostKey {
        ApprovedHostKey {
            algorithm: self.key_type.clone(),
            key: self.key_b64.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// The route's proxy, as evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProxyRoute {
    /// Direct.
    None,
    /// `ProxyJump`.
    Jump,
    /// `ProxyCommand`.
    Command,
}

/// Whether the static evaluation determined the route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Determinism {
    /// Determined.
    Determined,
    /// Not determinable statically.
    Undetermined {
        /// Why.
        reason: String,
    },
}

/// `app::ports::TargetEvaluator::evaluate`'s result (m03-plan U5): the passive,
/// static evaluation of an alias. Only a `determined`, direct route with exactly
/// one non-revoked host key can become an [`ApprovedTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetEvaluation {
    /// `HostName`.
    pub hostname: String,
    /// `Port`.
    pub port: u16,
    /// `User`.
    pub user: String,
    /// Proxy.
    pub proxy: ProxyRoute,
    /// Determinism.
    pub determinism: Determinism,
    /// Host keys found.
    pub host_keys: Vec<RawHostKey>,
}

/// The catalog facts the enrollment plan (`heimdall_registry::plan::build`) reads,
/// moved below `app` (§0.6): the destination, its identity, and every endpoint that
/// belongs to Heimdall (an existing-access endpoint that resolves to one is
/// refused, §17.4 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogView {
    /// The destination record.
    pub destination: DestinationRecord,
    /// Its managed definition's identity, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityRecord>,
    /// Heimdall's endpoints and the runtime directory prefix.
    #[serde(default)]
    pub heimdall_endpoints: Vec<String>,
}

// --- the transition table (ADR-0008 D5 §6.2) -----------------------------------------

/// The record facts the table depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordFacts {
    /// The record's form.
    pub form: EnrollmentForm,
    /// A foreign removal record (D4 item 5) rather than one of this installation's
    /// enrollments.
    pub foreign: bool,
}

impl RecordFacts {
    /// Every combination.
    pub const ALL: [RecordFacts; 4] = [
        RecordFacts {
            form: EnrollmentForm::Account,
            foreign: false,
        },
        RecordFacts {
            form: EnrollmentForm::System,
            foreign: false,
        },
        RecordFacts {
            form: EnrollmentForm::Account,
            foreign: true,
        },
        RecordFacts {
            form: EnrollmentForm::System,
            foreign: true,
        },
    ];
}

/// Which state a `reverifying` run started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReverifyFrom {
    /// From `verified` (owner or supervisor).
    Verified,
    /// From `held` (owner re-verify of an evidence-based hold, or an approved target
    /// change).
    Held,
}

/// Which remote step a `lock_holder_unresolved` hold interrupted, as the
/// manual-recovery reconcile needs it (ADR-0008 §17.15 X-Q3): the removal keeps
/// its purpose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryPurpose {
    /// An append (`outcome_unknown`); the default.
    #[default]
    Append,
    /// A failed initial verification's rollback (`rollback_*`).
    Rollback,
    /// An explicit removal (`remove*`), own or foreign.
    Removal,
}

impl RecoveryPurpose {
    /// Every purpose.
    pub const ALL: [RecoveryPurpose; 3] = [
        RecoveryPurpose::Append,
        RecoveryPurpose::Rollback,
        RecoveryPurpose::Removal,
    ];

    /// Whether this is the default (`append`).
    #[must_use]
    pub fn is_append(&self) -> bool {
        *self == RecoveryPurpose::Append
    }
}

/// An event of the enrollment table (ADR-0008 D5 §6.2; each variant names its row).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentEventKind {
    // `planned`
    /// `EnrollAccount` approved (own, account form): `planned → applying`.
    EnrollAccountApproved,
    /// `EnrollSystemForm` approved (own, system form): `planned → manual_pending`.
    EnrollSystemFormApproved,
    /// The decision was denied, cancelled or stale: `planned → withdrawn`, nothing
    /// written.
    DecisionWithdrawn,
    /// `RemoveEnrollment` approved (account form): `planned → removing` (foreign
    /// admission), and `held`, `applied_unverified`, `verified`, `abandoned` →
    /// `removing`.
    RemoveEnrollmentApproved,
    /// The owner's typed confirmation of a system-form manual removal: `planned →
    /// manual_removal_pending` (foreign admission, origin `planned`), and `held`,
    /// `verified`, `abandoned` → `manual_removal_pending` (origin that state).
    ManualRemovalConfirmed,

    // `applying`
    /// The append was confirmed, or `already_present` with the exact line.
    AppendConfirmed,
    /// The append's (or bootstrap's) result was lost or timed out.
    AppendOutcomeLost,
    /// Refused before any write (not manageable, provider locked, host trust, route
    /// changed, not-after passed, parent absent, endpoint changed).
    RefusedBeforeWrite,
    /// The post-write check failed: `applying → held`.
    PostWriteCheckFailed,
    /// `busy` (bounded retries): stays `applying`.
    StepBusy,
    /// A confirmed bootstrap: stays `applying`.
    BootstrapConfirmed,

    // reconcile (`outcome_unknown`, `rollback_unknown`, `remove_unknown`)
    /// Reconcile found the step applied: exactly one exact line (append), or the
    /// marker absent (removal or rollback).
    ReconcileApplied,
    /// Reconcile authorizes a redispatch: for an append the marker is absent, the
    /// old holder proven gone, the approval valid and the session attended; for a
    /// removal the marker is present and the old holder proven gone.
    ReconcileRedispatch,
    /// Reconcile found a damaged line or two marker lines: `outcome_unknown`,
    /// and (§17.15 X-Q2: §6.7's table applies to a removal step) `rollback_unknown`
    /// and `remove_unknown` → `held`, the record's `removal_origin` kept.
    ReconcileDamaged,
    /// The marker is absent after fencing and the approval lapsed (`approval_lapsed`):
    /// `outcome_unknown → withdrawn`, keeping the `late_write` residual.
    ReconcileApprovalLapsed,
    /// Unreachable, or the old holder may still be alive: the state stays.
    ReconcileUnresolved,
    /// `lock_holder_unresolved` after `holder_termination_attempts`, or a removal
    /// held by it: → `held`.
    HolderUnresolved,
    /// The owner abandons the enrollment (`pending_until_line_removed`).
    OwnerAbandon,

    // `held`
    /// The owner re-verifies a held record (`enroll verify`): only an
    /// evidence-based hold may (`held → reverifying`).
    OwnerReverify {
        /// The hold's kind.
        hold: HoldKind,
    },
    /// `ApproveTargetChange` approved: only for a host-key hold (`held →
    /// reverifying`, with the proposed target on the operation).
    TargetChangeApproved {
        /// The hold's kind.
        hold: HoldKind,
    },
    /// The manual-recovery reconcile (`--after-manual-recovery`) of a
    /// `lock_holder_unresolved` hold found one exact line (never a redispatch;
    /// account form only, §17.15 X-Q1): an append's → `applied_unverified`; a
    /// removal's or rollback's → stays `held`, `removal_origin` kept (§17.15
    /// X-Q3).
    ManualRecoveryLinePresent {
        /// The hold's kind.
        hold: HoldKind,
        /// Which step the hold interrupted (omitted on the wire for `append`).
        #[serde(default, skip_serializing_if = "RecoveryPurpose::is_append")]
        purpose: RecoveryPurpose,
    },
    /// The manual-recovery reconcile found no line (account form only): an
    /// append's → `withdrawn`; a removal's → `removed`; a rollback's →
    /// `verification_failed` (the removal keeps its purpose, §17.15 X-Q3).
    ManualRecoveryLineAbsent {
        /// The hold's kind.
        hold: HoldKind,
        /// Which step the hold interrupted (omitted on the wire for `append`).
        #[serde(default, skip_serializing_if = "RecoveryPurpose::is_append")]
        purpose: RecoveryPurpose,
    },

    // `applied_unverified`, `manual_pending`
    /// The initial verification starts (`applied_unverified → verifying`: through
    /// reconcile while the approval is valid, through `enroll verify` after).
    StartVerification,
    /// The owner confirms the system-form lines applied (`manual_pending →
    /// verifying`).
    OwnerConfirmsApplied,
    /// The owner cancels a system-form enrollment: `manual_pending →
    /// manual_removal_pending`, origin `manual_pending` (the lines may be
    /// installed).
    OwnerCancelsManualEnrollment,

    // `verifying`, `verified`, `reverifying`
    /// The initial verification's result.
    VerificationResult {
        /// The verdict.
        verdict: VerificationVerdict,
        /// The `enrollment.apply` approval is still valid.
        approval_valid: bool,
    },
    /// A later verification starts (`verified → reverifying`).
    StartReverification,
    /// A later verification's result.
    ReverificationResult {
        /// Where it started.
        from: ReverifyFrom,
        /// The verdict.
        verdict: VerificationVerdict,
    },

    // removal steps (`rollback_pending`, `removing`)
    /// The removal step removed the line.
    RemovalConfirmed,
    /// The removal step's result was lost.
    RemovalOutcomeLost,
    /// The removal needs the owner (`registry_changed` three times, not rewritable):
    /// → `held`.
    RemovalHeld,

    // `manual_removal_pending`, `removal_verifying`
    /// The owner confirms the lines removed (`manual_removal_pending →
    /// removal_verifying`).
    OwnerConfirmsRemoved,
    /// The owner cancels a manual removal: back to its origin with its evidence
    /// restored. For a foreign record after a `ca_not_held` result it stays in
    /// `manual_removal_pending`, or returns to `held` for a held origin; never
    /// `planned` or `withdrawn` (§17.10 item 2).
    OwnerCancelsManualRemoval {
        /// `removal_origin.state`.
        origin: EnrollmentState,
        /// `removal_origin.ca_not_held_seen`.
        ca_not_held_seen: bool,
    },
    /// The absence check passed: `removed`, or `withdrawn` when the origin was
    /// `manual_pending`. Never for a foreign record (Q28).
    AbsenceVerified {
        /// `removal_origin.state`.
        origin: EnrollmentState,
    },
    /// The absence check found the trust still accepted, or was inconclusive
    /// (`ca_not_held` included): back to `manual_removal_pending`, origin kept.
    AbsenceNotVerified,
}

impl EnrollmentEventKind {
    /// Every event kind, each payload over its whole (finite) domain.
    #[must_use]
    pub fn all() -> Vec<EnrollmentEventKind> {
        use EnrollmentEventKind as K;
        let mut out = vec![
            K::EnrollAccountApproved,
            K::EnrollSystemFormApproved,
            K::DecisionWithdrawn,
            K::RemoveEnrollmentApproved,
            K::ManualRemovalConfirmed,
            K::AppendConfirmed,
            K::AppendOutcomeLost,
            K::RefusedBeforeWrite,
            K::PostWriteCheckFailed,
            K::StepBusy,
            K::BootstrapConfirmed,
            K::ReconcileApplied,
            K::ReconcileRedispatch,
            K::ReconcileDamaged,
            K::ReconcileApprovalLapsed,
            K::ReconcileUnresolved,
            K::HolderUnresolved,
            K::OwnerAbandon,
            K::StartVerification,
            K::OwnerConfirmsApplied,
            K::OwnerCancelsManualEnrollment,
            K::StartReverification,
            K::RemovalConfirmed,
            K::RemovalOutcomeLost,
            K::RemovalHeld,
            K::OwnerConfirmsRemoved,
            K::AbsenceNotVerified,
        ];
        for hold in HoldKind::ALL {
            out.extend([K::OwnerReverify { hold }, K::TargetChangeApproved { hold }]);
            for purpose in RecoveryPurpose::ALL {
                out.extend([
                    K::ManualRecoveryLinePresent { hold, purpose },
                    K::ManualRecoveryLineAbsent { hold, purpose },
                ]);
            }
        }
        for verdict in VerificationVerdict::all() {
            for approval_valid in [false, true] {
                out.push(K::VerificationResult {
                    verdict,
                    approval_valid,
                });
            }
            for from in [ReverifyFrom::Verified, ReverifyFrom::Held] {
                out.push(K::ReverificationResult { from, verdict });
            }
        }
        for origin in EnrollmentState::ALL {
            out.push(K::AbsenceVerified { origin });
            for ca_not_held_seen in [false, true] {
                out.push(K::OwnerCancelsManualRemoval {
                    origin,
                    ca_not_held_seen,
                });
            }
        }
        out
    }
}

/// An event applied to a record: the record's facts and the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnrollmentEvent {
    /// The record's facts.
    pub record: RecordFacts,
    /// The event.
    pub kind: EnrollmentEventKind,
}

impl EnrollmentEvent {
    /// Every event: [`RecordFacts::ALL`] × [`EnrollmentEventKind::all`].
    #[must_use]
    pub fn all() -> Vec<EnrollmentEvent> {
        let kinds = EnrollmentEventKind::all();
        RecordFacts::ALL
            .into_iter()
            .flat_map(|record| {
                kinds
                    .iter()
                    .map(move |&kind| EnrollmentEvent { record, kind })
            })
            .collect()
    }
}

/// A transition the table does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("enrollment transition {event:?} is not allowed from {from:?}")]
pub struct InvalidTransition {
    /// The current state.
    pub from: EnrollmentState,
    /// The refused event.
    pub event: EnrollmentEvent,
}

/// Which forms a state admits (the table's "Form" column).
fn form_admits(state: EnrollmentState, form: EnrollmentForm) -> bool {
    use EnrollmentState as S;
    match state {
        S::Applying
        | S::OutcomeUnknown
        | S::AppliedUnverified
        | S::RollbackPending
        | S::RollbackUnknown
        | S::Removing
        | S::RemoveUnknown => form == EnrollmentForm::Account,
        S::ManualPending | S::ManualRemovalPending | S::RemovalVerifying => {
            form == EnrollmentForm::System
        }
        S::Planned
        | S::Held
        | S::Verifying
        | S::Verified
        | S::Reverifying
        | S::VerificationFailed
        | S::Removed
        | S::Withdrawn
        | S::FailedUnwritten
        | S::Abandoned => matches!(form, EnrollmentForm::Account | EnrollmentForm::System),
        // A state this build does not know admits nothing.
        _ => false,
    }
}

/// Whether `state` is in the foreign removal subset.
#[must_use]
pub fn in_foreign_subset(state: EnrollmentState) -> bool {
    FOREIGN_SUBSET.contains(&state)
}

/// The cancel of a manual removal (ADR-0008 D5 §6.2 `manual_removal_pending` row;
/// §17.4 item 5, §17.10 item 2, §17.12 item 2).
fn cancel_target(
    foreign: bool,
    origin: EnrollmentState,
    ca_not_held_seen: bool,
) -> Option<EnrollmentState> {
    use EnrollmentState as S;
    if foreign {
        match (origin, ca_not_held_seen) {
            // Before any absence check: back to the origin (§17.12 item 2). A foreign
            // record's subset holds `abandoned`, so an abandoned origin returns there
            // (§17.4 item 5: the persisted origin), keeping its residual.
            (S::Planned | S::Held | S::Abandoned, false) => Some(origin),
            // After `ca_not_held`: never `planned` or `withdrawn` (§17.10 item 2); a
            // known, unresolved residual stays in manual removal unless a held record
            // began it.
            (S::Planned | S::Abandoned, true) => Some(S::ManualRemovalPending),
            (S::Held, true) => Some(S::Held),
            _ => None,
        }
    } else {
        match (origin, ca_not_held_seen) {
            (S::Verified | S::Held | S::Abandoned | S::ManualPending, false) => Some(origin),
            _ => None,
        }
    }
}

/// The table's target for `(state, event)`, before the form and subset checks.
fn target(
    state: EnrollmentState,
    facts: RecordFacts,
    kind: EnrollmentEventKind,
) -> Option<EnrollmentState> {
    use EnrollmentEventKind as K;
    use EnrollmentState as S;
    use VerificationVerdict as V;
    let foreign = facts.foreign;
    let account = facts.form == EnrollmentForm::Account;
    let system = facts.form == EnrollmentForm::System;
    Some(match (state, kind) {
        // planned
        (S::Planned, K::EnrollAccountApproved) if !foreign => S::Applying,
        (S::Planned, K::EnrollSystemFormApproved) if !foreign => S::ManualPending,
        (S::Planned, K::DecisionWithdrawn) => S::Withdrawn,
        (S::Planned, K::RemoveEnrollmentApproved) if foreign => S::Removing,
        (S::Planned, K::ManualRemovalConfirmed) if foreign => S::ManualRemovalPending,

        // applying
        (S::Applying, K::AppendConfirmed) => S::AppliedUnverified,
        (S::Applying, K::AppendOutcomeLost) => S::OutcomeUnknown,
        (S::Applying, K::RefusedBeforeWrite) => S::FailedUnwritten,
        (S::Applying, K::PostWriteCheckFailed) => S::Held,
        (S::Applying, K::StepBusy | K::BootstrapConfirmed) => S::Applying,

        // outcome_unknown
        (S::OutcomeUnknown, K::ReconcileApplied) => S::AppliedUnverified,
        (S::OutcomeUnknown, K::ReconcileRedispatch) => S::Applying,
        (S::OutcomeUnknown, K::ReconcileDamaged | K::HolderUnresolved) => S::Held,
        (S::OutcomeUnknown, K::ReconcileApprovalLapsed) => S::Withdrawn,
        (S::OutcomeUnknown, K::OwnerAbandon) => S::Abandoned,
        (S::OutcomeUnknown, K::ReconcileUnresolved) => S::OutcomeUnknown,

        // held
        (S::Held, K::RemoveEnrollmentApproved) => S::Removing,
        (S::Held, K::ManualRemovalConfirmed) => S::ManualRemovalPending,
        (S::Held, K::OwnerAbandon) => S::Abandoned,
        (
            S::Held,
            K::OwnerReverify {
                hold: HoldKind::EvidenceBased,
            },
        ) if !foreign => S::Reverifying,
        (
            S::Held,
            K::TargetChangeApproved {
                hold: HoldKind::HostKeyChanged,
            },
        ) if !foreign => S::Reverifying,
        // Manual recovery (§6.7 `--after-manual-recovery`): account form only
        // (§17.15 X-Q1); a removal keeps its purpose (§17.15 X-Q3). A foreign record
        // only ever removes.
        (
            S::Held,
            K::ManualRecoveryLinePresent {
                hold: HoldKind::LockHolderUnresolved,
                purpose,
            },
        ) if account => match purpose {
            RecoveryPurpose::Append if !foreign => S::AppliedUnverified,
            RecoveryPurpose::Rollback if !foreign => S::Held,
            RecoveryPurpose::Removal => S::Held,
            _ => return None,
        },
        (
            S::Held,
            K::ManualRecoveryLineAbsent {
                hold: HoldKind::LockHolderUnresolved,
                purpose,
            },
        ) if account => match purpose {
            RecoveryPurpose::Append if !foreign => S::Withdrawn,
            RecoveryPurpose::Rollback if !foreign => S::VerificationFailed,
            RecoveryPurpose::Removal => S::Removed,
            _ => return None,
        },

        // applied_unverified
        (S::AppliedUnverified, K::StartVerification) => S::Verifying,
        (S::AppliedUnverified, K::RemoveEnrollmentApproved) => S::Removing,
        (S::AppliedUnverified, K::OwnerAbandon) => S::Abandoned,

        // manual_pending
        (S::ManualPending, K::OwnerConfirmsApplied) => S::Verifying,
        (S::ManualPending, K::OwnerCancelsManualEnrollment) => S::ManualRemovalPending,
        (S::ManualPending, K::OwnerAbandon) => S::Abandoned,

        // verifying (the initial verification; form-dependent targets)
        (
            S::Verifying,
            K::VerificationResult {
                verdict,
                approval_valid,
            },
        ) => match verdict {
            V::Passed => S::Verified,
            V::HostKeyMismatch => S::Held,
            V::PrincipalsNotEnforced | V::PositiveRefused if account => {
                if approval_valid {
                    S::RollbackPending
                } else {
                    S::Held
                }
            }
            V::PrincipalsNotEnforced if system => S::Held,
            V::PositiveRefused if system => S::ManualPending,
            V::Inconclusive { .. } if account => S::AppliedUnverified,
            V::Inconclusive { .. } if system => S::ManualPending,
            _ => return None,
        },

        // verified
        (S::Verified, K::StartReverification) => S::Reverifying,
        (S::Verified, K::RemoveEnrollmentApproved) => S::Removing,
        (S::Verified, K::ManualRemovalConfirmed) => S::ManualRemovalPending,

        // reverifying (never removes anything)
        (S::Reverifying, K::ReverificationResult { from, verdict }) => match (from, verdict) {
            (_, V::Passed) => S::Verified,
            (_, V::PrincipalsNotEnforced | V::PositiveRefused | V::HostKeyMismatch) => S::Held,
            (ReverifyFrom::Verified, V::Inconclusive { .. }) => S::Verified,
            (ReverifyFrom::Held, V::Inconclusive { .. }) => S::Held,
        },

        // rollback_pending
        (S::RollbackPending, K::RemovalConfirmed) => S::VerificationFailed,
        (S::RollbackPending, K::RemovalOutcomeLost) => S::RollbackUnknown,
        (S::RollbackPending, K::RemovalHeld | K::HolderUnresolved) => S::Held,
        (S::RollbackPending, K::OwnerAbandon) => S::Abandoned,

        // rollback_unknown (keeps the rollback purpose)
        (S::RollbackUnknown, K::ReconcileApplied) => S::VerificationFailed,
        (S::RollbackUnknown, K::ReconcileRedispatch) => S::RollbackPending,
        (S::RollbackUnknown, K::ReconcileDamaged | K::HolderUnresolved) => S::Held,
        (S::RollbackUnknown, K::OwnerAbandon) => S::Abandoned,
        (S::RollbackUnknown, K::ReconcileUnresolved) => S::RollbackUnknown,

        // removing
        (S::Removing, K::RemovalConfirmed) => S::Removed,
        (S::Removing, K::RemovalOutcomeLost) => S::RemoveUnknown,
        (S::Removing, K::RemovalHeld | K::HolderUnresolved) => S::Held,

        // remove_unknown (keeps the explicit removal purpose)
        (S::RemoveUnknown, K::ReconcileApplied) => S::Removed,
        (S::RemoveUnknown, K::ReconcileRedispatch) => S::Removing,
        (S::RemoveUnknown, K::ReconcileDamaged | K::HolderUnresolved) => S::Held,
        (S::RemoveUnknown, K::OwnerAbandon) => S::Abandoned,
        (S::RemoveUnknown, K::ReconcileUnresolved) => S::RemoveUnknown,

        // manual_removal_pending
        (S::ManualRemovalPending, K::OwnerConfirmsRemoved) => S::RemovalVerifying,
        (
            S::ManualRemovalPending,
            K::OwnerCancelsManualRemoval {
                origin,
                ca_not_held_seen,
            },
        ) => cancel_target(foreign, origin, ca_not_held_seen)?,
        // §17.10 item 2: a foreign record may be abandoned, keeping
        // `pending_until_line_removed`.
        (S::ManualRemovalPending, K::OwnerAbandon) if foreign => S::Abandoned,

        // removal_verifying
        (S::RemovalVerifying, K::AbsenceVerified { origin }) if !foreign => match origin {
            S::ManualPending => S::Withdrawn,
            S::Verified | S::Held | S::Abandoned => S::Removed,
            _ => return None,
        },
        (S::RemovalVerifying, K::AbsenceNotVerified) => S::ManualRemovalPending,

        // abandoned
        (S::Abandoned, K::RemoveEnrollmentApproved) => S::Removing,
        (S::Abandoned, K::ManualRemovalConfirmed) => S::ManualRemovalPending,

        // final states, and everything else
        _ => return None,
    })
}

/// ADR-0008 D5 §6.2: the next state of a record in `state` on `event`, or
/// [`InvalidTransition`]. Exactly the table, with the revision-3..6 transitions and
/// the binding rulings:
/// * the `verifying` targets depend on the form (and, for a failure, on whether the
///   approval is still valid; §17.4 item 5);
/// * `rollback_unknown` keeps the rollback purpose and `remove_unknown` the
///   explicit removal's; `→ abandoned` from every uncertain state;
/// * ⟨§17.15⟩ a damaged line found by reconcile moves `outcome_unknown`,
///   `rollback_unknown` and `remove_unknown` to `held` (X-Q2); manual recovery is
///   account form only (X-Q1), and a removal's keeps its purpose: line absent →
///   `removed` (a rollback's → `verification_failed`), present → stays `held`
///   (X-Q3); an append's is unchanged (`applied_unverified` / `withdrawn`);
/// * `held` exits only by the hold's kind (evidence-based re-verify, an approved
///   target change, manual recovery of `lock_holder_unresolved`), by removal, or by
///   abandoning;
/// * the foreign admission `planned → removing` (approved `RemoveEnrollment`) and
///   `planned → manual_removal_pending` (typed confirmation); a foreign record never
///   leaves [`FOREIGN_SUBSET`], never passes an absence check (Q28), may be
///   abandoned from `manual_removal_pending`, and after `ca_not_held` a cancel never
///   reaches `planned` or `withdrawn` (§17.10 item 2, §17.12 item 2);
/// * both states must admit the record's form (account-only and system-only states).
pub fn transition(
    state: EnrollmentState,
    event: EnrollmentEvent,
) -> Result<EnrollmentState, InvalidTransition> {
    let invalid = InvalidTransition { from: state, event };
    let facts = event.record;
    if facts.foreign && !in_foreign_subset(state) {
        return Err(invalid);
    }
    if !form_admits(state, facts.form) {
        return Err(invalid);
    }
    let next = target(state, facts, event.kind).ok_or(invalid)?;
    if facts.foreign && !in_foreign_subset(next) {
        return Err(invalid);
    }
    if !form_admits(next, facts.form) {
        return Err(invalid);
    }
    Ok(next)
}

/// [`transition`] for a foreign removal record: the record's own facts, so the
/// removal subset is always enforced (ADR-0008 D4 item 5).
pub fn foreign_transition(
    record: &ForeignRemovalRecord,
    kind: EnrollmentEventKind,
) -> Result<EnrollmentState, InvalidTransition> {
    transition(
        record.state,
        EnrollmentEvent {
            record: record.facts(),
            kind,
        },
    )
}

/// ADR-0008 D5 §6.2 `reverifying` row, §6.5 item 3, §17.7 item 5: the outcome of a
/// target-change verification (a `reverifying` record that started from a
/// `host_key_changed` hold). A pass replaces the approved target with `proposed`
/// **in the same transition** as the move to `verified` (and clears the hold); a
/// failure or an inconclusive result leaves the approved target unchanged and the
/// record `held`, reason unchanged. The caller sets `updated_at` and the evidence.
pub fn target_change_outcome(
    record: &EnrollmentRecord,
    proposed: &ApprovedTarget,
    verdict: VerificationVerdict,
) -> Result<EnrollmentRecord, InvalidTransition> {
    let event = EnrollmentEvent {
        record: record.facts(),
        kind: EnrollmentEventKind::ReverificationResult {
            from: ReverifyFrom::Held,
            verdict,
        },
    };
    if record.hold.map(|h| h.kind()) != Some(HoldKind::HostKeyChanged) {
        return Err(InvalidTransition {
            from: record.state,
            event,
        });
    }
    let next = transition(record.state, event)?;
    let mut out = record.clone();
    out.state = next;
    if next == EnrollmentState::Verified {
        out.target = proposed.clone();
        out.hold = None;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::verification::InconclusiveReason;

    const ACCOUNT: RecordFacts = RecordFacts {
        form: EnrollmentForm::Account,
        foreign: false,
    };
    const SYSTEM: RecordFacts = RecordFacts {
        form: EnrollmentForm::System,
        foreign: false,
    };
    const F_ACCOUNT: RecordFacts = RecordFacts {
        form: EnrollmentForm::Account,
        foreign: true,
    };
    const F_SYSTEM: RecordFacts = RecordFacts {
        form: EnrollmentForm::System,
        foreign: true,
    };

    fn go(
        record: RecordFacts,
        state: EnrollmentState,
        kind: EnrollmentEventKind,
    ) -> Option<EnrollmentState> {
        transition(state, EnrollmentEvent { record, kind }).ok()
    }

    #[test]
    fn finals_have_no_exit_and_every_target_admits_the_form() {
        for event in EnrollmentEvent::all() {
            for state in EnrollmentState::ALL {
                let r = transition(state, event);
                if state.is_final() {
                    assert!(r.is_err(), "{state:?} {event:?}");
                }
                if let Ok(next) = r {
                    assert!(form_admits(next, event.record.form));
                    if event.record.foreign {
                        assert!(in_foreign_subset(next));
                    }
                }
            }
        }
    }

    #[test]
    fn account_happy_path_and_form_dependent_verifying() {
        use EnrollmentEventKind as K;
        use EnrollmentState as S;
        let s = go(ACCOUNT, S::Planned, K::EnrollAccountApproved).unwrap();
        let s = go(ACCOUNT, s, K::AppendConfirmed).unwrap();
        let s = go(ACCOUNT, s, K::StartVerification).unwrap();
        let pass = K::VerificationResult {
            verdict: VerificationVerdict::Passed,
            approval_valid: true,
        };
        assert_eq!(go(ACCOUNT, s, pass), Some(S::Verified));
        let refused = |approval_valid| K::VerificationResult {
            verdict: VerificationVerdict::PositiveRefused,
            approval_valid,
        };
        assert_eq!(go(ACCOUNT, s, refused(true)), Some(S::RollbackPending));
        assert_eq!(go(ACCOUNT, s, refused(false)), Some(S::Held));
        assert_eq!(go(SYSTEM, s, refused(true)), Some(S::ManualPending));
        let inconclusive = K::VerificationResult {
            verdict: VerificationVerdict::Inconclusive {
                reason: InconclusiveReason::Transport,
            },
            approval_valid: true,
        };
        assert_eq!(go(ACCOUNT, s, inconclusive), Some(S::AppliedUnverified));
        assert_eq!(go(SYSTEM, s, inconclusive), Some(S::ManualPending));
        assert_eq!(go(SYSTEM, S::Planned, K::EnrollAccountApproved), None);
    }

    #[test]
    fn foreign_system_cancel_after_ca_not_held_never_planned_or_withdrawn() {
        use EnrollmentEventKind as K;
        use EnrollmentState as S;
        let s = go(F_SYSTEM, S::Planned, K::ManualRemovalConfirmed).unwrap();
        assert_eq!(s, S::ManualRemovalPending);
        let s = go(F_SYSTEM, s, K::OwnerConfirmsRemoved).unwrap();
        assert_eq!(
            go(F_SYSTEM, s, K::AbsenceVerified { origin: S::Planned }),
            None
        );
        let s = go(F_SYSTEM, s, K::AbsenceNotVerified).unwrap();
        assert_eq!(s, S::ManualRemovalPending);
        let cancel = |origin, seen| K::OwnerCancelsManualRemoval {
            origin,
            ca_not_held_seen: seen,
        };
        assert_eq!(go(F_SYSTEM, s, cancel(S::Planned, true)), Some(s));
        assert_eq!(go(F_SYSTEM, s, cancel(S::Held, true)), Some(S::Held));
        assert_eq!(go(F_SYSTEM, s, cancel(S::Planned, false)), Some(S::Planned));
        assert_eq!(go(F_SYSTEM, s, K::OwnerAbandon), Some(S::Abandoned));
        assert_eq!(go(SYSTEM, s, K::OwnerAbandon), None);
        assert_eq!(
            go(F_ACCOUNT, S::Planned, K::RemoveEnrollmentApproved),
            Some(S::Removing)
        );
        assert_eq!(go(ACCOUNT, S::Planned, K::RemoveEnrollmentApproved), None);
        assert_eq!(
            go(F_ACCOUNT, S::Removing, K::RemovalOutcomeLost),
            Some(S::RemoveUnknown)
        );
        assert_eq!(
            go(F_ACCOUNT, S::RemoveUnknown, K::ReconcileApplied),
            Some(S::Removed)
        );
    }

    #[test]
    fn held_exits_follow_the_hold_kind() {
        use EnrollmentEventKind as K;
        use EnrollmentState as S;
        for hold in HoldKind::ALL {
            assert_eq!(
                go(ACCOUNT, S::Held, K::OwnerReverify { hold }).is_some(),
                hold == HoldKind::EvidenceBased
            );
            assert_eq!(
                go(ACCOUNT, S::Held, K::TargetChangeApproved { hold }).is_some(),
                hold == HoldKind::HostKeyChanged
            );
        }
    }
}
