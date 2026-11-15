//! ⟨M03⟩ `Request::Enrollment` and the enrollment data types (ADR-0006 revision 4;
//! m03-plan §5 item 3; ADR-0008 D5).
//!
//! Wire-visible enrollment types live here; `heimdall-domain::enrollment` re-exports
//! them and owns the semantics (the state table, `transition`). Every enum is
//! `#[non_exhaustive]` and `snake_case`. Nothing here carries a private key, a
//! passphrase or a secret.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{
    AccountName, CaFingerprint, DestinationId, EnrollmentId, GrantId, IdentityId, OperationId,
    RequestId,
};
use crate::managed::{ClockMeasurement, DestinationClock, ResidualStatus};
use crate::request::{InteractionMode, WaitMode};
use crate::setup::PlanDigest;

/// The enrollment record's state (ADR-0008 D5 §6.2; revision 2's 20 states). The
/// allowed transitions are `heimdall_domain::enrollment::transition`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentState {
    /// Operation admitted, awaiting the owner decision.
    Planned,
    /// The approved operation is running; nothing remote is known written.
    Applying,
    /// The append may or may not have applied.
    OutcomeUnknown,
    /// Our marker or trust is present but wrong, or a check needs the owner.
    Held,
    /// The exact line is present; no verification has passed yet.
    AppliedUnverified,
    /// System form: waiting for the owner to apply the sshd lines.
    ManualPending,
    /// The initial verification is running.
    Verifying,
    /// Positive passed and negative refused with full evidence.
    Verified,
    /// A later verification is running; never removes anything.
    Reverifying,
    /// The initial verification failed; removing our line under the decision.
    RollbackPending,
    /// The rollback's removal may or may not have applied (rollback purpose).
    RollbackUnknown,
    /// An explicit owner-decided removal is running.
    Removing,
    /// The explicit removal may or may not have applied (removal purpose).
    RemoveUnknown,
    /// System form: the owner is to remove the sshd lines.
    ManualRemovalPending,
    /// System form: the absence check runs.
    RemovalVerifying,
    /// Final: the rollback removed our line.
    VerificationFailed,
    /// Final: removed (system form: absence verified).
    Removed,
    /// Final: nothing of ours remains as last observed.
    Withdrawn,
    /// Final: refused before any write.
    FailedUnwritten,
    /// The owner gave the account up; trust may remain (`pending_until_line_removed`).
    Abandoned,
}

impl EnrollmentState {
    /// Every state, in the ADR-0008 D5 §6.2 table's order.
    pub const ALL: [EnrollmentState; 20] = [
        EnrollmentState::Planned,
        EnrollmentState::Applying,
        EnrollmentState::OutcomeUnknown,
        EnrollmentState::Held,
        EnrollmentState::AppliedUnverified,
        EnrollmentState::ManualPending,
        EnrollmentState::Verifying,
        EnrollmentState::Verified,
        EnrollmentState::Reverifying,
        EnrollmentState::RollbackPending,
        EnrollmentState::RollbackUnknown,
        EnrollmentState::Removing,
        EnrollmentState::RemoveUnknown,
        EnrollmentState::ManualRemovalPending,
        EnrollmentState::RemovalVerifying,
        EnrollmentState::VerificationFailed,
        EnrollmentState::Removed,
        EnrollmentState::Withdrawn,
        EnrollmentState::FailedUnwritten,
        EnrollmentState::Abandoned,
    ];

    /// The final states (no transition leaves them): `verification_failed`,
    /// `removed`, `withdrawn`, `failed_unwritten`. `abandoned` is not final.
    #[must_use]
    pub fn is_final(self) -> bool {
        matches!(
            self,
            EnrollmentState::VerificationFailed
                | EnrollmentState::Removed
                | EnrollmentState::Withdrawn
                | EnrollmentState::FailedUnwritten
        )
    }

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollmentState::Planned => "planned",
            EnrollmentState::Applying => "applying",
            EnrollmentState::OutcomeUnknown => "outcome_unknown",
            EnrollmentState::Held => "held",
            EnrollmentState::AppliedUnverified => "applied_unverified",
            EnrollmentState::ManualPending => "manual_pending",
            EnrollmentState::Verifying => "verifying",
            EnrollmentState::Verified => "verified",
            EnrollmentState::Reverifying => "reverifying",
            EnrollmentState::RollbackPending => "rollback_pending",
            EnrollmentState::RollbackUnknown => "rollback_unknown",
            EnrollmentState::Removing => "removing",
            EnrollmentState::RemoveUnknown => "remove_unknown",
            EnrollmentState::ManualRemovalPending => "manual_removal_pending",
            EnrollmentState::RemovalVerifying => "removal_verifying",
            EnrollmentState::VerificationFailed => "verification_failed",
            EnrollmentState::Removed => "removed",
            EnrollmentState::Withdrawn => "withdrawn",
            EnrollmentState::FailedUnwritten => "failed_unwritten",
            EnrollmentState::Abandoned => "abandoned",
        }
    }
}

/// The trust form (ADR-0008 D5 §6.1, §6.9).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentForm {
    /// A `cert-authority` line in the account's registry (the default).
    #[default]
    Account,
    /// `TrustedUserCAKeys` plus `AuthorizedPrincipalsFile`, applied by the owner.
    System,
}

/// What an `enrollment.verify` checks (ADR-0008 D5 §6.5, §6.9).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerifyMode {
    /// Presence: re-verification, or the system form's first verification.
    #[default]
    Presence,
    /// The system form's absence check.
    Absence,
    /// A held host-key change, approved through `ApproveTargetChange`; the
    /// operation carries the proposed target.
    TargetChange,
}

/// How a registry path was resolved (ADR-0008 D5 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RegistryResolvedBy {
    /// Given explicitly (`--registry-path`).
    Explicit,
    /// `$HOME/.ssh/authorized_keys` on the remote.
    RemoteHome,
}

/// A registry for people: its display path (always `/` separators; never parsed
/// back) and how it was resolved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RegistryRef {
    /// Display form only.
    pub path_display: String,
    /// Resolution.
    pub resolved_by: RegistryResolvedBy,
}

/// The canonical registry the bundle and foreign removal carry: the validated path
/// (absent for `remote_home`), never a display form (ADR-0008 D4 item 5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RegistryCanonical {
    /// The validated path, when explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Resolution.
    pub resolved_by: RegistryResolvedBy,
}

/// What to enroll (§5 item 3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentSpec {
    /// The managed destination.
    pub destination: DestinationId,
    /// Default: the managed definition's account; any other value is `USAGE_ERROR`
    /// (`account_override_refused`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountName>,
    /// Form (default `account`).
    #[serde(default)]
    pub form: EnrollmentForm,
    /// Registry path (ADR-0008 D5 §6.1 rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<String>,
    /// CA; default the newest active CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<CaFingerprint>,
}

/// The full public removal descriptor of an enrollment from a recovery bundle
/// (ADR-0008 D4 item 5; §17.1 item 11). The decision and the request hash cover
/// every field.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ForeignRemovalTarget {
    /// This device's managed alias for the host.
    pub local_alias: String,
    /// The bundle's destination ID: a label only (IDs are per installation).
    pub bundle_destination_id: String,
    /// Required (a redacted bundle is refused, `bundle_redacted`); must equal the
    /// alias's evaluated `HostName` byte for byte (`bundle_host_mismatch`).
    pub bundle_hostname: String,
    /// Must equal the evaluated `Port`.
    pub bundle_port: u16,
    /// Account.
    pub account: AccountName,
    /// `heimdall:enr_…`.
    pub marker: String,
    /// The CA's OpenSSH public key.
    pub ca_public_key: String,
    /// The full line's SHA-256 (hex); rebuilt and checked before connecting.
    pub line_sha256: String,
    /// The canonical registry.
    pub registry: RegistryCanonical,
    /// Form; `system` gets manual instructions only.
    pub form: EnrollmentForm,
}

/// What an `enrollment.remove` removes, tagged `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemovalTarget {
    /// One of this installation's enrollments.
    Enrollment {
        /// The enrollment.
        enrollment_id: EnrollmentId,
    },
    /// A foreign enrollment from a recovery bundle.
    Foreign(ForeignRemovalTarget),
}

/// `Request::Enrollment`, tagged `action` (capability `enrollment/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentRequest {
    /// Read-only, local, contacts nothing. kind `enrollment.preview`; data
    /// [`EnrollmentPlan`].
    Preview {
        /// What to enroll.
        spec: EnrollmentSpec,
    },
    /// Journaled `enrollment.apply`, effect class `remote_mutation`; needs
    /// `EnrollAccount` (or `EnrollSystemForm`).
    Apply {
        /// What to enroll.
        spec: EnrollmentSpec,
        /// The previewed plan's digest.
        plan_digest: PlanDigest,
        /// Idempotency request ID.
        request_id: RequestId,
        /// Interaction mode.
        #[serde(default)]
        interaction: InteractionMode,
        /// Wait mode.
        #[serde(default)]
        wait: WaitMode,
    },
    /// Journaled `enrollment.verify`, effect class `local`; never removes anything.
    Verify {
        /// The enrollment.
        enrollment_id: EnrollmentId,
        /// Idempotency request ID.
        request_id: RequestId,
        /// Mode (default presence).
        #[serde(default)]
        mode: VerifyMode,
        /// Wait mode.
        #[serde(default)]
        wait: WaitMode,
    },
    /// Journaled `enrollment.remove`, effect class `remote_mutation`; needs
    /// `RemoveEnrollment` (system form: a typed confirmation).
    Remove {
        /// What to remove.
        target: RemovalTarget,
        /// Idempotency request ID.
        request_id: RequestId,
        /// Interaction mode.
        #[serde(default)]
        interaction: InteractionMode,
        /// Wait mode.
        #[serde(default)]
        wait: WaitMode,
    },
    /// Synchronous: drives an unresolved `enrollment.apply`/`remove` (ADR-0008 D5
    /// §6.7). Owner role only; a redispatch of an append needs an attended session.
    Reconcile {
        /// The operation.
        operation_id: OperationId,
        /// Interaction mode.
        #[serde(default)]
        interaction: InteractionMode,
        /// After the owner removed a lock by hand: classify only, never redispatch.
        #[serde(default)]
        after_manual_recovery: bool,
    },
    /// Synchronous, owner channel: record abandonment (residual
    /// `pending_until_line_removed`).
    Abandon {
        /// The enrollment.
        enrollment_id: EnrollmentId,
    },
    /// Synchronous, owner role only: the next client-executed step (ADR-0008 D5
    /// §6.3). kind `enrollment.step`.
    Step {
        /// The operation.
        operation_id: OperationId,
    },
    /// Synchronous, owner role only: the CLI's result for the outstanding step.
    /// kind `enrollment.step_result`.
    StepResult {
        /// The operation.
        operation_id: OperationId,
        /// The step's token (32 hex).
        step_token: String,
        /// The client's exit status.
        exit_status: i32,
        /// At most 512 KiB of HM1 lines.
        stdout: String,
        /// At most 4 KiB, redacted, diagnostics only.
        stderr_excerpt: String,
    },
}

impl EnrollmentRequest {
    /// The request kind (`enrollment.<action>`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            EnrollmentRequest::Preview { .. } => "enrollment.preview",
            EnrollmentRequest::Apply { .. } => "enrollment.apply",
            EnrollmentRequest::Verify { .. } => "enrollment.verify",
            EnrollmentRequest::Remove { .. } => "enrollment.remove",
            EnrollmentRequest::Reconcile { .. } => "enrollment.reconcile",
            EnrollmentRequest::Abandon { .. } => "enrollment.abandon",
            EnrollmentRequest::Step { .. } => "enrollment.step",
            EnrollmentRequest::StepResult { .. } => "enrollment.step_result",
        }
    }
}

/// A client-executed remote stage (ADR-0008 D5 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteStage {
    /// Read-only inspection.
    Inspect,
    /// Create the registry's directory (0700) when absent.
    Bootstrap,
    /// Append the line under the lock.
    Append,
    /// Remove the line (compare-then-rename) under the lock.
    Remove,
    /// Prove a stale lock's holder gone (optionally terminating it).
    Fence,
}

/// One `-o Key=Value` option of a remote step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshOption {
    /// The option name (`HostName`, `StrictHostKeyChecking`, …).
    pub key: String,
    /// Its value, a validated literal.
    pub value: String,
}

/// The target pins, in order: `HostName`, `Port`, `User`, `ProxyCommand=none`,
/// `ProxyJump=none`, `CanonicalizeHostname=no`.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct TargetPins(pub Vec<SshOption>);

/// The host-trust pins, in order (ADR-0008 §17.4 item 1): `UserKnownHostsFile`
/// (generated, one line), `GlobalKnownHostsFile` (empty), `KnownHostsCommand=none`,
/// `VerifyHostKeyDNS=no`, `HostKeyAlgorithms=<approved key's>`, `HostKeyAlias`,
/// `StrictHostKeyChecking=yes`, `CheckHostIP=no`, `UpdateHostKeys=no`,
/// `NoHostAuthenticationForLocalhost=no`, and `GSSAPIKeyExchange=no` where the
/// client knows it (Q23).
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct TrustPins(pub Vec<SshOption>);

/// The existing-access pins, in order (ADR-0008 §17.1 item 4, §17.4 item 4):
/// `IdentityAgent=<approved concrete endpoint>` (never `SSH_AUTH_SOCK`),
/// `IdentityFile`, `IdentitiesOnly=yes`, `CertificateFile=none`,
/// `ControlMaster=no`, `ControlPath=none`.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct AccessPins(pub Vec<SshOption>);

/// The narrowing pins, in order: `BatchMode`, `ForwardAgent=no`,
/// `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `RequestTTY=no`,
/// `ForkAfterAuthentication=no`.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct NarrowingPins(pub Vec<SshOption>);

/// Every `-o` of ADR-0008 D5 §6.3, rendered in this order: target, host trust,
/// existing access, narrowing.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct StepPins {
    /// Target pins.
    pub target: TargetPins,
    /// Host-trust pins.
    pub host_trust: TrustPins,
    /// Existing-access pins.
    pub existing_access: AccessPins,
    /// Narrowing pins.
    pub narrowing: NarrowingPins,
}

/// What the CLI must run for one step (no secret; the script contains only
/// validated literals; ADR-0008 D5 §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteStep {
    /// Stage.
    pub stage: RemoteStage,
    /// The step token (32 hex).
    pub step_token: String,
    /// The verified client's absolute path.
    pub client: String,
    /// The pins.
    pub pins: StepPins,
    /// The managed alias.
    pub alias: String,
    /// `printf 'HM1 ready\n'; exec /bin/sh -s`.
    pub remote_command: String,
    /// Written to ssh's stdin only after `HM1 ready` is read.
    pub script: String,
    /// Step timeout.
    pub timeout_ms: u64,
    /// Hard deadline on the runtime's continuous clock, from issue.
    pub hard_deadline_ms: u64,
    /// Remote epoch seconds; mutating stages only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_remote: Option<i64>,
}

/// The approved host key (ADR-0008 D5 §6.1): the only trust source of every step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApprovedHostKey {
    /// Key algorithm (`ssh-ed25519`).
    pub algorithm: String,
    /// Base64 key blob.
    pub key: String,
    /// `SHA256:…` fingerprint.
    pub fingerprint: String,
}

/// The only proxy an approved target may have in M03: none (routes are direct).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NoProxy {
    /// No proxy.
    #[default]
    None,
}

/// The approved target (ADR-0008 D5 §6.1; §17.1 item 2): what every remote step and
/// verification pins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApprovedTarget {
    /// `HostName`.
    pub hostname: String,
    /// `Port`.
    pub port: u16,
    /// `User`.
    pub user: AccountName,
    /// Proxy (none).
    #[serde(default)]
    pub proxy: NoProxy,
    /// The approved host key.
    pub host_key: ApprovedHostKey,
}

/// Where the existing-access endpoint came from (§17.6 item 3, Q24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EndpointSource {
    /// The catalog identity record names it.
    CatalogRecord,
    /// The alias's own `IdentityAgent`, P's managed block excluded.
    AliasIdentityAgent,
}

/// The existing-access invocation shown and approved with the plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExistingAccessPlan {
    /// The adopted identity.
    pub identity_id: IdentityId,
    /// Its mechanism (`native_agent`, `onepassword`).
    pub mechanism: String,
    /// The concrete endpoint (never `SSH_AUTH_SOCK`).
    pub endpoint: String,
    /// Where the endpoint came from.
    pub endpoint_source: EndpointSource,
    /// The `-o` arguments, in order.
    pub invocation: Vec<String>,
}

/// The conditional bootstrap step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[non_exhaustive]
pub enum BootstrapPlan {
    /// Create the registry's directory with mode 0700 when it is absent.
    #[serde(rename = "create_registry_dir_0700_if_absent")]
    CreateRegistryDir0700IfAbsent,
}

/// The verification the plan runs (ADR-0008 D5 §6.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VerificationPlan {
    /// `hm:<destination-id>:<account>`.
    pub positive_principal: String,
    /// Whether a negative attempt runs.
    pub negative: bool,
    /// Certificate validity ceiling.
    pub max_validity_seconds: u64,
}

/// The rollback procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RollbackPlan {
    /// Compare-then-rename by marker (ADR-0008 D5 §6.8).
    CompareThenRenameByMarker,
}

/// A disclosure shown with a plan or an issuer decision (ADR-0008 D4 item 1, D5).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisclosureKind {
    /// Configuration commands run as in ordinary use (ADR-0007 D5).
    ConfigCommandsRunAsOrdinaryUse,
    /// Every account that trusts the CA is reachable with it.
    CaTrustBlastRadius,
    /// The removal window (early removal and the residual).
    RemoveWindow,
    /// Lock continuity, shown once and conditionally (R-UX-03).
    LockContinuityOnce,
    /// Reconcile may stop this enrollment's own stale script.
    ReconcileMayStopOwnStaleScript,
    /// Ordinary `ssh <alias>` works only while a binding holds the slot.
    OrdinarySshNeedsHeldSlot,
    /// The issuer is a same-user process (ADR-0008 D4 item 1).
    SameUserIssuerBoundary,
    /// The backup instructions (ADR-0008 D4 item 1).
    BackupInstructions,
    /// A key-only restore: every residual is unknown; rotation is recommended
    /// (ADR-0008 D4 item 4).
    RestoredWithoutLogResidualsUnknown,
}

/// The enrollment plan: the preview data, the decision's summary, and the hash
/// input through `plan_digest` (§5 item 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentPlan {
    /// The digest over every other field.
    pub plan_digest: PlanDigest,
    /// Destination.
    pub destination_id: DestinationId,
    /// The managed alias.
    pub alias: String,
    /// Account.
    pub account: AccountName,
    /// Form.
    pub form: EnrollmentForm,
    /// Registry (display).
    pub registry: RegistryRef,
    /// The exact line.
    pub line: String,
    /// The line's SHA-256 (hex).
    pub line_sha256: String,
    /// CA.
    pub ca_fingerprint: CaFingerprint,
    /// The existing-access invocation.
    pub existing_access: ExistingAccessPlan,
    /// The host-trust pins as `Key=Value`.
    pub host_trust: Vec<String>,
    /// The approved target.
    pub approved_target: ApprovedTarget,
    /// The conditional bootstrap step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<BootstrapPlan>,
    /// The verification.
    pub verification: VerificationPlan,
    /// The rollback procedure.
    pub rollback: RollbackPlan,
    /// Disclosures.
    pub disclosures: Vec<DisclosureKind>,
}

/// Verification evidence in a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentEvidenceView {
    /// Client version line.
    pub client: String,
    /// Server version line.
    pub server: String,
    /// The verifying operation.
    pub operation_id: OperationId,
    /// The clock measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<ClockMeasurement>,
}

/// What the owner should do next after an enrollment operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentNext {
    /// After a pass: apply the projection.
    SetupApply,
    /// A held host key: `enroll verify --approve-target-change` or `enroll remove`.
    ReviewHostTrust,
    /// `outcome_unknown`: `enroll reconcile`.
    Reconcile,
    /// `registry_not_rewritable` or `lock_holder_unresolved`: manual instructions.
    ManualRegistryEdit,
}

/// A note kind in an enrollment result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnrollmentNoteKind {
    /// Ordinary `ssh <alias>` needs a held slot.
    OrdinarySshNeedsHeldSlot,
    /// An uncertain append may still land (the `late_write` residual).
    PossibleLateWrite,
}

/// A note in an enrollment result, with the command it names, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentNote {
    /// The note.
    pub kind: EnrollmentNoteKind,
    /// The command that addresses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// The `apply`, `verify` and `remove` operation result (§5 item 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentResult {
    /// Enrollment.
    pub enrollment_id: EnrollmentId,
    /// Its state.
    pub state: EnrollmentState,
    /// When verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<Timestamp>,
    /// Verification evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EnrollmentEvidenceView>,
    /// Next step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<EnrollmentNext>,
    /// Commands for `next` (`review_host_trust`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    /// Manual instructions (`manual_registry_edit`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instructions: Vec<String>,
    /// Notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<EnrollmentNote>,
}

/// Why a record is in a removal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemovalPurpose {
    /// A failed initial verification's rollback (`rollback_*`).
    Rollback,
    /// An explicit owner-decided removal (`remove*`).
    ExplicitRemoval,
}

/// The approved target in a view: host, port, user and host-key fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TargetSummary {
    /// `HostName`.
    pub hostname: String,
    /// `Port`.
    pub port: u16,
    /// `User`.
    pub user: AccountName,
    /// The host key's fingerprint.
    pub host_key_fingerprint: String,
}

/// One enrollment record in `inspect enrollments` (§5 item 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentView {
    /// Enrollment.
    pub enrollment_id: EnrollmentId,
    /// Destination.
    pub destination_id: DestinationId,
    /// Account.
    pub account: AccountName,
    /// Form.
    pub form: EnrollmentForm,
    /// CA.
    pub ca_fingerprint: CaFingerprint,
    /// Marker.
    pub marker: String,
    /// State.
    pub state: EnrollmentState,
    /// Registry (display).
    pub registry: RegistryRef,
    /// When verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<Timestamp>,
    /// Evidence fresh until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_fresh_until: Option<Timestamp>,
    /// Per-pair residual (ADR-0008 D7 item 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_residual_until: Option<Timestamp>,
    /// The pair's clock.
    #[serde(default)]
    pub destination_clock: DestinationClock,
    /// The residual status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_status: Option<ResidualStatus>,
    /// The approved target.
    pub approved_target: TargetSummary,
    /// Removal purpose for `rollback_*` and `remove*` states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_purpose: Option<RemovalPurpose>,
    /// Live grants under this enrollment's CA for the pair.
    #[serde(default)]
    pub live_grants: Vec<GrantId>,
    /// The open operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_operation_id: Option<OperationId>,
    /// The `late_write` residual exists.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub possible_late_write: bool,
    /// ⟨ADR-0008 §17.25 item 4⟩ A `held` record's reason and next step, computed by
    /// the app from the record's `hold`, so `enroll status` and the TUI show the
    /// same commands. Additive: omitted when absent (every record that is not
    /// `held`, and a runtime that predates it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold: Option<EnrollmentHoldView>,
}

/// ⟨ADR-0008 §17.25 item 4⟩ `EnrollmentView.hold`: why a record is `held`, and the
/// owner's next step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentHoldView {
    /// The record's `hold.reason`: the `snake_case` wire name of
    /// `heimdall_domain::enrollment::HoldReason` (`principals_not_enforced`,
    /// `positive_refused`, `host_key_changed`, `lock_holder_unresolved`,
    /// `registry_line_damaged`, `registry_changed`, `registry_not_rewritable`,
    /// `post_write_check_failed`). A string, as `data.error.reason` is: readers
    /// tolerate unknown values.
    pub reason: String,
    /// The owner's next step: the commands (or manual instruction) that leave the
    /// hold, in the order shown. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<String>,
}

/// `inspect enrollments` data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentsView {
    /// One entry per record.
    pub enrollments: Vec<EnrollmentView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn state_wire_names_equal_as_str() {
        for s in EnrollmentState::ALL {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.as_str())
            );
        }
        let finals: Vec<_> = EnrollmentState::ALL
            .into_iter()
            .filter(|s| s.is_final())
            .collect();
        assert_eq!(finals.len(), 4);
    }

    #[test]
    fn removal_target_wire_forms() {
        let t: RemovalTarget = serde_json::from_value(serde_json::json!({
            "kind": "enrollment", "enrollment_id": "enr_00112233445566778899aabbccddeeff"
        }))
        .unwrap();
        assert!(matches!(t, RemovalTarget::Enrollment { .. }));
        assert_eq!(
            serde_json::to_value(BootstrapPlan::CreateRegistryDir0700IfAbsent).unwrap(),
            serde_json::json!("create_registry_dir_0700_if_absent")
        );
    }
}
