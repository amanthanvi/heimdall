//! ⟨M06 U4⟩ Store methods for typed narrowing effects and resynchronization (ADR-0012 §7;
//! ADR-0006 §18 item 11, §18.5 readings 9 and 16; m06-plan U4). Schema:
//! `migrations/0009_remote.sql`'s `remote_effect_outbox`, `remote_effect_acks` and
//! `remote_policy_revisions`, and one `meta` key prefix; ⟨W4⟩ `migrations/0012_remote_lift_acks.sql`'s
//! `remote_lift_acks`.
//!
//! Conventions (as [`crate::ext_m06`]): every method runs inside the caller's [`Txn`]; reads
//! return `Option`/`Vec`; the store reads no clock (every instant is the caller's).
//!
//! * **The effect key** ([`EffectKey`], ADR-0012 §7.2): the authenticated producing controller
//!   (the session's client on the runner, never a request field), the effect ID it minted, the
//!   typed target and the target's generation. The three tables' primary keys are its columns
//!   ([`target_kind`], [`target_ref`], `EffectTarget::generation`).
//! * **The controller's outbox** (`remote_effect_outbox`): one row per effect this controller
//!   produced for a runner, `pending` until the runner's acknowledgement is recorded
//!   ([`Txn::acknowledge_remote_effect`]). A row is never deleted by an acknowledgement and an
//!   acknowledged row never goes back to `pending`.
//! * **The runner's acknowledgements** (`remote_effect_acks`): written only once the durable
//!   record the effect names exists ([`Txn::record_remote_effect_ack`] checks it in the same
//!   transaction: the grant's tombstone, or the policy revision row), so a redelivery returns
//!   the recorded acknowledgement.
//! * **The runner's policy revisions** (`remote_policy_revisions`): one row per
//!   `(scope, producer, revision)`, ordered by `runner_seq` (the runner's apply order). Two
//!   controllers' equal revision numbers for one scope are two rows; nothing here replaces a
//!   row, so no pause or cutoff disappears while it is in force. A cutoff row keeps the owner's
//!   instant; a redelivery of the same key with an earlier instant only shortens it.
//!   ⟨M08 W4 SEC-3b, R2⟩ An in-force row also stands for its producer's later effects of the
//!   same scope and kind (coalesced: [`RevisionOutcome::Coalesced`], acknowledged against the
//!   row's `runner_seq`, which is never assigned again after a prune).
//! * ⟨M08 W4 SEC-3b; ADR-0006 §7.4 and ADR-0012 §7.4 as amended 2026-11-27⟩ **The runner's
//!   history is bounded** (the section "bounding the runner's authority history" below): what
//!   has no authority effect is capped ([`BARE_TOMBSTONES_PER_PRODUCER`],
//!   [`BARE_TOMBSTONES_TOTAL`], [`UNMATCHED_REVISIONS_PER_PRODUCER`]), and the retention pass,
//!   on safe time only, prunes tombstones, lifted revisions and acknowledgements on their
//!   conditions ([`Txn::prune_runner_history`]). A revision in force is never pruned.
//! * ⟨M06 W4; ADR-0012 §7.4 ⟨2026-11-21⟩, M06-W3-R02⟩ **The controller's lift
//!   acknowledgements** (`remote_lift_acks`): one row per pause or cutoff effect of the
//!   outbox whose lift the owner confirmed on this controller
//!   ([`Txn::acknowledge_remote_lift`]). Written only for an outbox row the runner
//!   acknowledged; never updated; removed with the environment's outbox rows. A row alone
//!   reopens nothing (the issuer's barrier also needs the runner's report to show the lift).
//! * **Contact observations** (`meta`, `remote_contact:<environment>`): what the controller
//!   last saw of a runner (connectivity, ADR-0012 §7.1). An observation, never authority.
//!
//! * ⟨M06 W3⟩ **Delivered grants** (`meta`, `remote_delivered_grant:<environment>:<grant>`;
//!   ADR-0005 §3.5 "Remote reservations"): this controller's own record of a grant it
//!   delivered to a runner ([`DeliveredGrant`]): its pairs, extensions and expiry, and, once the
//!   runner's prepare answer was verified, the key binding a reservation rests on
//!   ([`PreparedBinding`]). The issuer child reads it; a remote reservation's certificate
//!   content comes from it, never from the runner.
//!
//! The rows are authority-bearing (`Rows` in [`crate::ext_m03::TABLE_RECOVERY`]), and so are
//! the delivered grants (in the snapshot); the contact observation is local and discarded.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CaFingerprint, ClientId, EffectId, EnvironmentId, GrantId, PolicyId};
use heimdall_contract::managed::ComponentResidual;
use heimdall_contract::remote::EffectTarget;
use heimdall_contract::request::AccessPairRef;
use heimdall_contract::trust::PolicyTarget;
use heimdall_domain::policy::StandingPolicy;
use heimdall_domain::revocation::Tombstone;
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};

use crate::{Result, StoreError, Txn, codec};

/// ⟨M06 U4⟩ The meta key prefix of the controller's contact observations (one per runner
/// environment; module docs).
pub const META_REMOTE_CONTACT: &str = "remote_contact:";

/// ⟨M06 W3⟩ The meta key prefix of the controller's delivered-grant records (one per runner
/// environment and grant; module docs).
pub const META_REMOTE_DELIVERED_GRANT: &str = "remote_delivered_grant:";

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(what.into())
}

/// The `target_kind` column of a typed target; `None` for a target this build does not know
/// (fail closed: nothing is written for it).
#[must_use]
pub fn target_kind(target: &EffectTarget) -> Option<&'static str> {
    match target {
        EffectTarget::GrantRevoke { .. } => Some("grant_revoke"),
        EffectTarget::PolicyPause { .. } => Some("policy_pause"),
        EffectTarget::PolicyCutoff { .. } => Some("policy_cutoff"),
        _ => None,
    }
}

/// The canonical key of a policy scope (`remote_policy_revisions.scope_key`): `policy:<id>`,
/// `profile:<id>`, `workspace:<id>` or `all`. `None` for a scope this build does not know.
#[must_use]
pub fn scope_key(scope: &PolicyTarget) -> Option<String> {
    match scope {
        PolicyTarget::Policy { policy_id } => Some(format!("policy:{policy_id}")),
        PolicyTarget::Profile { profile } => Some(format!("profile:{profile}")),
        PolicyTarget::Workspace { workspace } => Some(format!("workspace:{workspace}")),
        PolicyTarget::All => Some("all".to_owned()),
        _ => None,
    }
}

/// The scope key of one policy (a pause's scope).
#[must_use]
pub fn policy_scope_key(policy: &PolicyId) -> String {
    format!("policy:{policy}")
}

/// The `target_ref` column of a typed target: the grant ID, or the policy scope's key.
/// `None` for a target this build does not know.
#[must_use]
pub fn target_ref(target: &EffectTarget) -> Option<String> {
    match target {
        EffectTarget::GrantRevoke { grant, .. } => Some(grant.as_str().to_owned()),
        EffectTarget::PolicyPause { policy, .. } => Some(policy_scope_key(policy)),
        EffectTarget::PolicyCutoff { scope, .. } => scope_key(scope),
        _ => None,
    }
}

/// A typed effect's key (module docs; ADR-0012 §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectKey {
    /// The producing controller: its authenticated client on the runner.
    pub producer: ClientId,
    /// The effect ID the producer minted.
    pub effect: EffectId,
    /// The typed target, carrying its generation.
    pub target: EffectTarget,
}

impl EffectKey {
    /// The key's three target columns; an unknown target is refused (nothing is written).
    fn columns(&self) -> Result<(&'static str, String, i64)> {
        let (Some(kind), Some(reference)) = (target_kind(&self.target), target_ref(&self.target))
        else {
            return Err(codec::doc_error(
                "an effect target this build does not know",
            ));
        };
        Ok((kind, reference, codec::int(self.target.generation())?))
    }
}

/// What the runner durably recorded for an effect, with its enforcement state (ADR-0012
/// §7.2 "acknowledged with its enforcement state").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppliedRecord {
    /// A durable grant tombstone.
    GrantTombstone {
        /// The tombstoned grant.
        grant: GrantId,
        /// Whether the runner held a grant of that ID (`false`: the tombstone alone denies
        /// any later use of the ID).
        known: bool,
        /// The descendants the tombstone covers.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        cascade: Vec<GrantId>,
        /// K_env of the grant (and of each descendant) is zeroized.
        key_destroyed: bool,
        /// The runner's owned dedicated sessions and masters for the grant.
        owned_dedicated_sessions: ComponentResidual,
        /// The runner's owned admissions for the grant.
        owned_admissions: ComponentResidual,
    },
    /// A durable policy revision.
    PolicyRevision {
        /// The scope's canonical key.
        scope_key: String,
        /// The runner-side apply order.
        runner_seq: u64,
        /// The runner's policies the effect applied to (empty: no policy of that scope
        /// exists on the runner; the revision row is still durable).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        policies: Vec<PolicyId>,
        /// A cutoff: the instant the row keeps (the owner's, or an earlier redelivered one).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cutoff_at: Option<Timestamp>,
        /// A cutoff: whether its instant had passed, or may have passed under uncertain
        /// time, when the runner applied it (it then took effect at the durable apply).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        fired: bool,
    },
}

/// The runner's acknowledgement of one effect (`remote_effect_acks.ack_json`, and the
/// controller's `remote_effect_outbox.ack_json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectAck {
    /// The effect.
    #[serde(flatten)]
    pub key: EffectKey,
    /// When the runner applied it (the runner's clock).
    pub applied_at: Timestamp,
    /// The durable record and its enforcement state.
    pub record: AppliedRecord,
}

/// A policy revision's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRevisionKind {
    /// Running grants continue; new activations are refused.
    Pause,
    /// Also ends every affected grant like expiry at its instant.
    Cutoff,
}

/// One `remote_policy_revisions` row (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRevisionRecord {
    /// The scope's canonical key ([`scope_key`]).
    pub scope_key: String,
    /// The scope.
    pub scope: PolicyTarget,
    /// The producing controller.
    pub producer: ClientId,
    /// The producer's revision number for this scope.
    pub revision: u64,
    /// The runner-side apply order (unique on the runner).
    pub runner_seq: u64,
    /// Pause or cutoff.
    pub kind: PolicyRevisionKind,
    /// The effect that delivered it.
    pub effect: EffectId,
    /// When the runner received it (the runner's clock).
    pub received_at: Timestamp,
    /// A cutoff's instant: the owner's `at`, shortened only by a redelivery of the same key
    /// with an earlier instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff_at: Option<Timestamp>,
    /// ⟨M06 W3; ADR-0012 §7.4 ⟨2026-11-21⟩⟩ A cutoff that fired **before the owner's instant
    /// because the runner's time was uncertain**: the instant applied to the runner's
    /// policies then (earlier than `cutoff_at`). Sticky: once set it is never cleared, and a
    /// later certain reading does not un-fire the cutoff (only a runner-local attended action
    /// lifts it). Omitted when the cutoff did not fire early.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fired_uncertain_at: Option<Timestamp>,
    /// ⟨M06 W5; ADR-0006 §18.9 item 4⟩ Whether this delivered effect is **still in force**
    /// on the runner. `true` from the apply on; cleared, and then never set again, only by
    /// an approved runner-local decision that names it ([`Txn::lift_remote_policy_revision`]).
    /// Removing or narrowing a policy, and the report, never clear it (M06-W5-RC01).
    /// Omitted when `true`, so a row or a report written before the field existed reads as
    /// in force (fail closed).
    #[serde(default = "in_force_default", skip_serializing_if = "is_in_force")]
    pub in_force: bool,
}

fn in_force_default() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_in_force(in_force: &bool) -> bool {
    *in_force
}

/// What [`Txn::record_remote_policy_revision`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionOutcome {
    /// A new row, at the next `runner_seq`.
    Recorded(PolicyRevisionRecord),
    /// The row existed and is unchanged.
    Existing(PolicyRevisionRecord),
    /// The row existed; the redelivered cutoff was earlier and shortened it, or it fired
    /// early under uncertain time and that is now recorded.
    Shortened(PolicyRevisionRecord),
    /// ⟨M08 W4 SEC-3b, R2⟩ No row of this identity: the producer's in-force row of the same
    /// scope and kind is its durable record (coalesced per `(producer, scope_key, kind)`;
    /// [`Txn::record_remote_policy_revision`]). A cutoff earlier than that row's shortened it.
    Coalesced(PolicyRevisionRecord),
}

impl RevisionOutcome {
    /// The row as stored now.
    #[must_use]
    pub fn record(&self) -> &PolicyRevisionRecord {
        match self {
            RevisionOutcome::Recorded(r)
            | RevisionOutcome::Existing(r)
            | RevisionOutcome::Shortened(r)
            | RevisionOutcome::Coalesced(r) => r,
        }
    }
}

/// An outbox row's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    /// Not yet acknowledged by the runner.
    Pending,
    /// The runner's acknowledgement is recorded.
    Acknowledged,
}

/// One `remote_effect_outbox` row (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEffect {
    /// The runner environment the effect is for.
    pub environment: EnvironmentId,
    /// The effect's key (the producer is this controller's client on that runner).
    #[serde(flatten)]
    pub key: EffectKey,
    /// Its state.
    pub state: OutboxState,
    /// When this controller produced it.
    pub created_at: Timestamp,
    /// When the acknowledgement was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<Timestamp>,
    /// The runner's acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<EffectAck>,
    /// ⟨M08 W4 SEC-3b, R2⟩ When a complete authority report of the runner first showed this
    /// delivered pause or cutoff lifted ([`Txn::note_remote_lift_seen`]). Kept once set: the
    /// runner may prune its lifted row afterwards (ADR-0012 §7.4 as amended 2026-11-27), and
    /// the issuer's barrier then counts this instead (`lift_shown`). Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lift_seen_at: Option<Timestamp>,
}

/// What the controller last saw of a runner (module docs). An observation only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteContact {
    /// When a management session to the runner last completed its hello.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    /// The last failed attempt after that, with its stable reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<ContactFailure>,
    /// The certificates the runner last reported installed, and when (the last-known
    /// readiness, which the controller computes forward).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_report: Option<ObservedReport>,
    /// ⟨M06 W5⟩ The grants of the runner's last report that wait for their issuer and that
    /// a standing policy held here refused **for their deadline** ([`RefusedPending`]).
    /// Replaced whole at every hosted pass; omitted when empty, so every earlier record
    /// decodes unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_pending: Vec<RefusedPending>,
    /// ⟨M06 W3⟩ The management session the controller's runtime holds to the runner now, as
    /// that runtime last wrote it ([`Txn::note_remote_session`]). It says nothing once that
    /// runtime is gone: a reader counts it only while the same runtime instance still runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted: Option<HostedSession>,
}

/// ⟨M06 W3⟩ The controller runtime's open, resynchronized management session to a runner
/// (an observation for `environment status`; the issuer's barrier is process state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSession {
    /// The runtime instance that holds it (its process ID and start time, as
    /// `instance.json` states them).
    pub instance: String,
    /// When the reconnect order completed over it.
    pub since: Timestamp,
}

/// ⟨M06 W3; ADR-0005 §3.5 "Remote reservations" condition 3⟩ What the runner's verified
/// prepare answer bound, recorded with the reservation that rests on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedBinding {
    /// The grant's generation the key is bound to.
    pub grant_generation: u64,
    /// K_env's SHA-256 fingerprint.
    pub key_fingerprint: String,
    /// The CA of this controller the grant is pinned to (condition 4).
    pub ca_fingerprint: CaFingerprint,
    /// The pairs the runner's answer named (it can only narrow the delivered ones).
    pub pairs: std::collections::BTreeSet<AccessPairRef>,
    /// The runner's policy the grant rests on, when it stated one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyId>,
    /// The runner's reported latest possible credential expiry (condition 7).
    pub runner_bound: Timestamp,
    /// The effective cutoff the barrier read from the runner's report, when one is ahead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff: Option<Timestamp>,
    /// When the authority report the barrier was opened on was read (condition 2).
    pub report_at: Timestamp,
    /// When the answer was verified.
    pub prepared_at: Timestamp,
}

/// ⟨M06 W5; m06-plan §2 item 3 "As built and ruled in W5"⟩ A runner-originated pending
/// grant this controller did not record under its standing policy because the grant's
/// deadline is later than that policy allows. Nothing is clamped: the grant stays pending
/// until its owner asks for a deadline inside the limit, or the policy's owner moves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedPending {
    /// The grant, as the runner names it.
    pub grant: GrantId,
    /// When this controller first refused it for this limit.
    pub at: Timestamp,
    /// The limit exceeded: `deadline_exceeds_policy_max_lifetime` or
    /// `deadline_exceeds_policy_cutoff`.
    pub limit: String,
    /// The sentence for the owner: the policy, the limit's instant and the deadline asked.
    pub detail: String,
}

/// ⟨M06 W3⟩ Why the last remote issuance for a delivered grant did not complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceFailure {
    /// When.
    pub at: Timestamp,
    /// A stable code or reason string.
    pub reason: String,
}

/// ⟨M06 W3; ADR-0005 §3.5 "Remote reservations" condition 6⟩ This controller's record of a
/// grant it delivered to a runner: the only source of a remote certificate's principals,
/// extensions and validity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveredGrant {
    /// The runner.
    pub environment: EnvironmentId,
    /// The grant, as the runner names it.
    pub grant: GrantId,
    /// The pairs delivered (one principal each).
    pub pairs: std::collections::BTreeSet<AccessPairRef>,
    /// The certificate extensions delivered.
    pub extensions: std::collections::BTreeSet<String>,
    /// The grant's expiry: no certificate is valid past it.
    pub expires_at: Timestamp,
    /// When it was recorded.
    pub delivered_at: Timestamp,
    /// The key binding of the latest verified prepare answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared: Option<PreparedBinding>,
    /// The last issuance failure since the last success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<IssuanceFailure>,
    /// ⟨M06 W5; ADR-0005 §3.5 condition 8 (b)⟩ The standing policy held on this controller
    /// the record was written from, when its source is (b). Issuance for the grant then
    /// also needs that policy to still authorize it. `None` for a forwarded `ensure`
    /// (source (a)); omitted when `None`, so every earlier record decodes unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<heimdall_contract::ids::PolicyId>,
}

/// What the runner's last authority report showed installed (an observation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedReport {
    /// When this controller read it.
    pub at: Timestamp,
    /// The certificates installed then.
    pub certificates: Vec<ReportedCertificate>,
    /// ⟨M06 W3⟩ The delivered cutoffs it showed fired early because the runner's time was
    /// uncertain ([`PolicyRevisionRecord::fired_uncertain_at`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoffs_fired_early: Vec<PolicyRevisionRecord>,
    /// ⟨M06 W3⟩ The runner's standing policies it listed, so the owner's local `policy
    /// pause` or `policy cutoff` naming one of them can be sent to that runner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyId>,
    /// ⟨M06 W4 `w4d`⟩ Those policies as the report stated them (paused, cutoff), so
    /// `environment resume-issuance` can tell the owner whether that report showed a
    /// delivered pause or cutoff lifted. An observation: the issuer's barrier judges on
    /// the report of its own open session, never on this. `None` in a record written
    /// before this field existed (not known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing: Option<Vec<ReportedPolicy>>,
    /// ⟨M06 W5; ADR-0006 §18.9 item 4⟩ The delivered pauses and cutoffs as the report
    /// stated them, each with whether it is still in force: what `environment
    /// resume-issuance` tells the owner about a lift. An observation, as `standing` is.
    /// `None` in a record written before this field existed (not known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revisions: Option<Vec<PolicyRevisionRecord>>,
}

/// A failed attempt to reach a runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactFailure {
    /// When.
    pub at: Timestamp,
    /// A stable reason string (a contract reason where one exists).
    pub reason: String,
}

/// One tombstone of the runner's authority report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedTombstone {
    /// The tombstoned grant.
    pub grant: GrantId,
    /// The descendants it covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cascade: Vec<GrantId>,
    /// The runner's authority generation after it.
    pub generation: u64,
    /// When the runner applied it.
    pub revoked_at: Timestamp,
}

/// One of the runner's standing policies in its authority report: its local revision (the
/// generation) and its blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedPolicy {
    /// The policy.
    pub policy: PolicyId,
    /// The runner's own revision of it.
    pub revision: u64,
    /// Whether it is paused.
    pub paused: bool,
    /// Its cutoff, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff_at: Option<Timestamp>,
}

/// One installed certificate of the runner's authority report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedCertificate {
    /// The grant.
    pub grant: GrantId,
    /// The grant generation it was installed under.
    pub grant_generation: u64,
    /// The pair.
    pub pair: AccessPairRef,
    /// The certificate's serial.
    pub serial: u64,
    /// Its `valid_before`.
    pub valid_before: Timestamp,
    /// The controller that issued it.
    pub issuer: ClientId,
}

/// The runner's authority report (ADR-0012 §7.4 step 3): tombstones, policy revisions with
/// their generations, and installed certificates. The store fills everything but the
/// installed certificates, which live in the runner's memory with K_env.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityReport {
    /// The runner's environment.
    pub environment: EnvironmentId,
    /// The runner's authority generation at the report.
    pub authority_generation: u64,
    /// Every grant tombstone.
    pub tombstones: Vec<ReportedTombstone>,
    /// Every delivered policy revision, in the runner's apply order.
    pub policy_revisions: Vec<PolicyRevisionRecord>,
    /// The runner's standing policies as they are now.
    pub policies: Vec<ReportedPolicy>,
    /// The certificates installed now.
    #[serde(default)]
    pub certificates: Vec<ReportedCertificate>,
    /// Whether a qualifying time sample bounds the runner's clock in this boot (ADR-0012
    /// §4.4). The store cannot know: the runner runtime sets it.
    #[serde(default)]
    pub time_bounded: bool,
    /// ⟨M06 W4; ADR-0005 §3.5 condition 8 (b)⟩ The grants the runner admitted that wait
    /// for their issuer. The store cannot know which wait (K_env lives in the runner's
    /// memory): the runner runtime fills it. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_grants: Vec<ReportedPendingGrant>,
}

/// ⟨M06 W4⟩ One grant of the runner's authority report that waits for its issuer: what
/// the runner admitted, so a controller-held standing policy that names the runner can be
/// held against it (ADR-0005 §3.5 condition 8 (b)). It only describes; the controller
/// issues for it only when its own records authorize every pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedPendingGrant {
    /// The grant.
    pub grant: GrantId,
    /// The profile it was admitted for.
    pub profile: heimdall_contract::ids::ProfileId,
    /// Its destination/account pairs.
    pub pairs: std::collections::BTreeSet<AccessPairRef>,
    /// Its deadline on the runner.
    pub expires_at: Timestamp,
}

fn contact_key(environment: &EnvironmentId) -> String {
    format!("{META_REMOTE_CONTACT}{environment}")
}

fn delivered_prefix(environment: &EnvironmentId) -> String {
    format!("{META_REMOTE_DELIVERED_GRANT}{environment}:")
}

fn delivered_key(environment: &EnvironmentId, grant: &GrantId) -> String {
    format!("{}{grant}", delivered_prefix(environment))
}

impl Txn<'_> {
    // --- the controller's outbox ------------------------------------------------------------

    /// ⟨M06 U4⟩ Put one effect in the outbox, `pending` (module docs). `false` when a row with
    /// that key exists (nothing written: a key is never reused for another effect).
    pub fn enqueue_remote_effect(
        &mut self,
        environment: &EnvironmentId,
        key: &EffectKey,
        now: Timestamp,
    ) -> Result<bool> {
        let (kind, reference, generation) = key.columns()?;
        let n = self.tx.execute(
            "INSERT INTO remote_effect_outbox (environment, producer, effect_id, target_kind,
                 target_ref, target_generation, target_json, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(producer, effect_id, target_kind, target_ref, target_generation)
             DO NOTHING",
            rusqlite::params![
                environment.as_str(),
                key.producer.as_str(),
                key.effect.as_str(),
                kind,
                reference,
                generation,
                codec::doc(&key.target)?,
                codec::enum_str(&OutboxState::Pending)?,
                codec::ts(now),
            ],
        )?;
        // ⟨M08 U2b-2; ADR-0014 §3.6 steps 2 and 7⟩ The effect is minted under the current
        // epoch (the column defaults to 0).
        if n > 0
            && let Some(epoch) = self.minted_epoch()?
        {
            self.tx.execute(
                "UPDATE remote_effect_outbox SET restore_epoch = ?6
                 WHERE producer = ?1 AND effect_id = ?2 AND target_kind = ?3 AND target_ref = ?4
                     AND target_generation = ?5",
                rusqlite::params![
                    key.producer.as_str(),
                    key.effect.as_str(),
                    kind,
                    reference,
                    generation,
                    epoch
                ],
            )?;
        }
        Ok(n > 0)
    }

    /// ⟨M06 U4⟩ The outbox rows for `environment` (every environment when `None`), in the
    /// order they were produced; only the pending ones when `pending_only`.
    pub fn remote_effect_outbox(
        &mut self,
        environment: Option<&EnvironmentId>,
        pending_only: bool,
    ) -> Result<Vec<OutboxEffect>> {
        let mut stmt = self.tx.prepare(
            "SELECT environment, producer, effect_id, target_json, state, created_at,
                    acknowledged_at, ack_json, lift_seen_at
             FROM remote_effect_outbox ORDER BY created_at, rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                (
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ),
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let ((env, producer, effect, target), state, created, acked, ack, seen) = row?;
            let state: OutboxState = codec::enum_parse(&state)?;
            if pending_only && state != OutboxState::Pending {
                continue;
            }
            let env = EnvironmentId::parse(&env)
                .map_err(|_| corrupt("an outbox row names a malformed environment"))?;
            if environment.is_some_and(|e| *e != env) {
                continue;
            }
            out.push(OutboxEffect {
                environment: env,
                key: EffectKey {
                    producer: ClientId::parse(&producer)
                        .map_err(|_| corrupt("an outbox row names a malformed producer"))?,
                    effect: EffectId::parse(&effect)
                        .map_err(|_| corrupt("an outbox row names a malformed effect"))?,
                    target: codec::parse_doc(&target)?,
                },
                state,
                created_at: codec::parse_ts(&created)?,
                acknowledged_at: acked.as_deref().map(codec::parse_ts).transpose()?,
                ack: ack.as_deref().map(codec::parse_doc).transpose()?,
                lift_seen_at: seen.as_deref().map(codec::parse_ts).transpose()?,
            });
        }
        Ok(out)
    }

    /// ⟨M08 W4 SEC-3b, R2⟩ A complete authority report of `environment`'s runner showed the
    /// delivered pause or cutoff `key` (an acknowledged row of this controller's outbox)
    /// lifted at `at`: record it once (module docs of [`OutboxEffect::lift_seen_at`]). Whether
    /// it was recorded now; `false`, nothing written, for a row that is not an acknowledged
    /// pause or cutoff of `environment`, or one already recorded.
    pub fn note_remote_lift_seen(
        &mut self,
        environment: &EnvironmentId,
        key: &EffectKey,
        at: Timestamp,
    ) -> Result<bool> {
        if !matches!(
            key.target,
            EffectTarget::PolicyPause { .. } | EffectTarget::PolicyCutoff { .. }
        ) {
            return Ok(false);
        }
        let (kind, reference, generation) = key.columns()?;
        let n = self.tx.execute(
            "UPDATE remote_effect_outbox SET lift_seen_at = ?8
             WHERE environment = ?1 AND producer = ?2 AND effect_id = ?3 AND target_kind = ?4
               AND target_ref = ?5 AND target_generation = ?6 AND state = ?7
               AND lift_seen_at IS NULL",
            rusqlite::params![
                environment.as_str(),
                key.producer.as_str(),
                key.effect.as_str(),
                kind,
                reference,
                generation,
                codec::enum_str(&OutboxState::Acknowledged)?,
                codec::ts(at),
            ],
        )?;
        Ok(n > 0)
    }

    /// ⟨M06 U4⟩ Record the runner's acknowledgement of an outbox effect: `pending →
    /// acknowledged` (compare-and-set). `false` when there is no pending row with that key
    /// (unknown, or already acknowledged: the first acknowledgement is kept). The
    /// acknowledgement must name the same key.
    pub fn acknowledge_remote_effect(&mut self, ack: &EffectAck, now: Timestamp) -> Result<bool> {
        let (kind, reference, generation) = ack.key.columns()?;
        let n = self.tx.execute(
            "UPDATE remote_effect_outbox SET state = ?6, acknowledged_at = ?7, ack_json = ?8
             WHERE producer = ?1 AND effect_id = ?2 AND target_kind = ?3 AND target_ref = ?4
               AND target_generation = ?5 AND state = ?9",
            rusqlite::params![
                ack.key.producer.as_str(),
                ack.key.effect.as_str(),
                kind,
                reference,
                generation,
                codec::enum_str(&OutboxState::Acknowledged)?,
                codec::ts(now),
                codec::doc(ack)?,
                codec::enum_str(&OutboxState::Pending)?,
            ],
        )?;
        Ok(n > 0)
    }

    /// ⟨M06 U4⟩ Drop every outbox row of `environment` (the controller removed the
    /// environment), ⟨W4⟩ and its lift acknowledgements with them; the number of outbox rows
    /// removed.
    pub fn forget_remote_effect_outbox(&mut self, environment: &EnvironmentId) -> Result<usize> {
        self.tx.execute(
            "DELETE FROM remote_lift_acks WHERE environment = ?1",
            [environment.as_str()],
        )?;
        Ok(self.tx.execute(
            "DELETE FROM remote_effect_outbox WHERE environment = ?1",
            [environment.as_str()],
        )?)
    }

    // --- the controller's lift acknowledgements ----------------------------------------------

    /// ⟨M06 W4⟩ Record that the owner confirmed, on this controller, that the delivered
    /// pause or cutoff `key` was lifted at the runner `environment` (module docs). Written
    /// only when the outbox holds that effect for that environment, acknowledged by the
    /// runner, and it is a pause or a cutoff. `false`, nothing written, otherwise, or when
    /// the row exists (the first acknowledgement is kept).
    pub fn acknowledge_remote_lift(
        &mut self,
        environment: &EnvironmentId,
        key: &EffectKey,
        now: Timestamp,
    ) -> Result<bool> {
        if !matches!(
            key.target,
            EffectTarget::PolicyPause { .. } | EffectTarget::PolicyCutoff { .. }
        ) {
            return Ok(false);
        }
        let (kind, reference, generation) = key.columns()?;
        let delivered: i64 = self.tx.query_row(
            "SELECT count(*) FROM remote_effect_outbox
             WHERE environment = ?1 AND producer = ?2 AND effect_id = ?3 AND target_kind = ?4
               AND target_ref = ?5 AND target_generation = ?6 AND state = ?7",
            rusqlite::params![
                environment.as_str(),
                key.producer.as_str(),
                key.effect.as_str(),
                kind,
                reference,
                generation,
                codec::enum_str(&OutboxState::Acknowledged)?,
            ],
            |r| r.get(0),
        )?;
        if delivered == 0 {
            return Ok(false);
        }
        let n = self.tx.execute(
            "INSERT INTO remote_lift_acks (environment, producer, effect_id, target_kind,
                 target_ref, target_generation, acknowledged_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(producer, effect_id, target_kind, target_ref, target_generation)
             DO NOTHING",
            rusqlite::params![
                environment.as_str(),
                key.producer.as_str(),
                key.effect.as_str(),
                kind,
                reference,
                generation,
                codec::ts(now),
            ],
        )?;
        Ok(n > 0)
    }

    /// ⟨M06 W4⟩ When the owner acknowledged the lift of the delivered effect `key` on this
    /// controller, if they did.
    pub fn remote_lift_ack(&mut self, key: &EffectKey) -> Result<Option<Timestamp>> {
        let (kind, reference, generation) = key.columns()?;
        let at: Option<String> = self
            .tx
            .query_row(
                "SELECT acknowledged_at FROM remote_lift_acks
                 WHERE producer = ?1 AND effect_id = ?2 AND target_kind = ?3
                   AND target_ref = ?4 AND target_generation = ?5",
                rusqlite::params![
                    key.producer.as_str(),
                    key.effect.as_str(),
                    kind,
                    reference,
                    generation
                ],
                |r| r.get(0),
            )
            .optional()?;
        at.as_deref().map(codec::parse_ts).transpose()
    }

    // --- the runner's acknowledgements ------------------------------------------------------

    /// ⟨M06 U4⟩ The recorded acknowledgement of `key`, if any (a redelivery's answer).
    pub fn remote_effect_ack(&mut self, key: &EffectKey) -> Result<Option<EffectAck>> {
        let (kind, reference, generation) = key.columns()?;
        let json: Option<String> = self
            .tx
            .query_row(
                "SELECT ack_json FROM remote_effect_acks
                 WHERE producer = ?1 AND effect_id = ?2 AND target_kind = ?3
                   AND target_ref = ?4 AND target_generation = ?5",
                rusqlite::params![
                    key.producer.as_str(),
                    key.effect.as_str(),
                    kind,
                    reference,
                    generation
                ],
                |r| r.get(0),
            )
            .optional()?;
        json.as_deref().map(codec::parse_doc).transpose()
    }

    /// ⟨M06 U4⟩ Record the acknowledgement of an effect, **only once the durable record it
    /// names exists**, checked here in the same transaction: the grant's tombstone for a
    /// `grant_revoke`, the `(scope, producer, revision)` row for a pause or cutoff. Without
    /// that record nothing is written ([`codec::doc_error`]). A second acknowledgement of one
    /// key replaces the first only in its enforcement state (the key and the record it names
    /// are the same): the caller re-applies idempotently and reports what holds now.
    pub fn record_remote_effect_ack(&mut self, ack: &EffectAck) -> Result<()> {
        let (kind, reference, generation) = ack.key.columns()?;
        let durable = match &ack.key.target {
            // ⟨M08 W4 SEC-3b, R1⟩ Or the grant's `revoked` row, once the retention pass pruned
            // its known tombstone: terminal and absorbing, and `denied_ancestor` denies by it,
            // so a late redelivery converges on it.
            EffectTarget::GrantRevoke { grant, .. } => {
                self.tombstone(grant)?.is_some()
                    || self
                        .grant(grant)?
                        .is_some_and(|g| g.state == heimdall_contract::GrantState::Revoked)
            }
            EffectTarget::PolicyPause { .. } | EffectTarget::PolicyCutoff { .. } => {
                match self.remote_policy_revision(
                    &reference,
                    &ack.key.producer,
                    ack.key.target.generation(),
                )? {
                    Some(r) => r.effect == ack.key.effect,
                    // ⟨M08 W4 SEC-3b, R2⟩ Coalesced: the row the acknowledgement names (its
                    // `runner_seq`), of the same producer, scope and kind.
                    None => match &ack.record {
                        AppliedRecord::PolicyRevision { runner_seq, .. } => self
                            .remote_policy_revision_at(*runner_seq)?
                            .is_some_and(|r| {
                                r.producer == ack.key.producer
                                    && r.scope_key == reference
                                    && Some(r.kind) == revision_kind(&ack.key.target)
                            }),
                        AppliedRecord::GrantTombstone { .. } => false,
                    },
                }
            }
            _ => false,
        };
        if !durable {
            return Err(codec::doc_error(
                "an effect is acknowledged only after its durable record exists",
            ));
        }
        self.tx.execute(
            "INSERT INTO remote_effect_acks (producer, effect_id, target_kind, target_ref,
                 target_generation, applied_at, ack_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(producer, effect_id, target_kind, target_ref, target_generation)
             DO UPDATE SET ack_json = excluded.ack_json",
            rusqlite::params![
                ack.key.producer.as_str(),
                ack.key.effect.as_str(),
                kind,
                reference,
                generation,
                codec::ts(ack.applied_at),
                codec::doc(ack)?,
            ],
        )?;
        Ok(())
    }

    // --- the runner's policy revisions ------------------------------------------------------

    /// ⟨M06 U4⟩ One policy revision row by its producer-scoped identity.
    pub fn remote_policy_revision(
        &mut self,
        scope_key: &str,
        producer: &ClientId,
        revision: u64,
    ) -> Result<Option<PolicyRevisionRecord>> {
        self.one_doc(
            "SELECT record_json FROM remote_policy_revisions
             WHERE scope_key = ?1 AND producer = ?2 AND revision = ?3",
            rusqlite::params![scope_key, producer.as_str(), codec::int(revision)?],
        )
    }

    /// ⟨M06 U4⟩ Every policy revision row, in the runner's apply order (`runner_seq`).
    pub fn remote_policy_revisions(&mut self) -> Result<Vec<PolicyRevisionRecord>> {
        self.docs(
            "SELECT record_json FROM remote_policy_revisions ORDER BY runner_seq",
            [],
        )
    }

    /// ⟨M06 U4⟩ Record a delivered pause or cutoff as a durable policy revision (module
    /// docs). `row.runner_seq` is assigned here (the next in the runner's order) for a new
    /// row. An existing `(scope, producer, revision)` row is kept: it must be the same kind,
    /// and a cutoff redelivered with an earlier instant shortens the stored instant (never
    /// the reverse). A row of another kind under the same identity is refused, nothing
    /// written.
    pub fn record_remote_policy_revision(
        &mut self,
        row: &PolicyRevisionRecord,
    ) -> Result<RevisionOutcome> {
        if scope_key(&row.scope).as_deref() != Some(row.scope_key.as_str())
            || (row.kind == PolicyRevisionKind::Cutoff) != row.cutoff_at.is_some()
            || (row.fired_uncertain_at.is_some() && row.cutoff_at.is_none())
        {
            return Err(codec::doc_error("a policy revision row is inconsistent"));
        }
        if let Some(mut stored) =
            self.remote_policy_revision(&row.scope_key, &row.producer, row.revision)?
        {
            if stored.kind != row.kind {
                return Err(codec::doc_error(
                    "a policy revision identity names one kind of effect",
                ));
            }
            // Only ever narrower: an earlier owner's instant shortens, and an early fire
            // under uncertain time is kept (the earliest one) once recorded.
            let cutoff_at = match (stored.cutoff_at, row.cutoff_at) {
                (Some(old), Some(new)) => Some(old.min(new)),
                (old, _) => old,
            };
            let fired_uncertain_at = match (stored.fired_uncertain_at, row.fired_uncertain_at) {
                (Some(old), Some(new)) => Some(old.min(new)),
                (old, new) => old.or(new),
            };
            return match (cutoff_at, fired_uncertain_at) {
                (c, f) if c != stored.cutoff_at || f != stored.fired_uncertain_at => {
                    stored.cutoff_at = c;
                    stored.fired_uncertain_at = f;
                    self.tx.execute(
                        "UPDATE remote_policy_revisions SET record_json = ?4
                         WHERE scope_key = ?1 AND producer = ?2 AND revision = ?3",
                        rusqlite::params![
                            stored.scope_key,
                            stored.producer.as_str(),
                            codec::int(stored.revision)?,
                            codec::doc(&stored)?,
                        ],
                    )?;
                    Ok(RevisionOutcome::Shortened(stored))
                }
                _ => Ok(RevisionOutcome::Existing(stored)),
            };
        }
        // ⟨M08 W4 SEC-3b, R2; ADR-0012 §7.4 as amended 2026-11-27⟩ Coalesced per `(producer,
        // scope_key, kind)`: the producer's in-force row of the same scope and kind is this
        // effect's durable record too, so no second row is written. Only ever narrower: a
        // cutoff earlier than the row's shortens it, and an early fire is kept.
        if let Some(mut existing) =
            self.in_force_remote_revision(&row.producer, &row.scope_key, row.kind)?
        {
            let cutoff_at = match (existing.cutoff_at, row.cutoff_at) {
                (Some(old), Some(new)) => Some(old.min(new)),
                (old, _) => old,
            };
            let fired_uncertain_at = match (existing.fired_uncertain_at, row.fired_uncertain_at) {
                (Some(old), Some(new)) => Some(old.min(new)),
                (old, new) => old.or(new),
            };
            if cutoff_at != existing.cutoff_at || fired_uncertain_at != existing.fired_uncertain_at
            {
                existing.cutoff_at = cutoff_at;
                existing.fired_uncertain_at = fired_uncertain_at;
                self.tx.execute(
                    "UPDATE remote_policy_revisions SET record_json = ?4
                     WHERE scope_key = ?1 AND producer = ?2 AND revision = ?3",
                    rusqlite::params![
                        existing.scope_key,
                        existing.producer.as_str(),
                        codec::int(existing.revision)?,
                        codec::doc(&existing)?,
                    ],
                )?;
            }
            return Ok(RevisionOutcome::Coalesced(existing));
        }
        // ⟨M08 W4 SEC-3b⟩ The runner's order never reuses a number: the highest ever assigned
        // is kept apart from the rows, which the retention pass may prune.
        let last: i64 = self.tx.query_row(
            "SELECT COALESCE(max(runner_seq), 0) FROM remote_policy_revisions",
            [],
            |r| r.get(0),
        )?;
        let kept = self
            .meta(META_REMOTE_POLICY_SEQ)?
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| corrupt("the policy revision order is malformed"))
            })
            .transpose()?
            .unwrap_or(0);
        let mut stored = row.clone();
        stored.runner_seq = codec::uint(last)?.max(kept).saturating_add(1);
        self.set_meta(META_REMOTE_POLICY_SEQ, &stored.runner_seq.to_string())?;
        // A delivered effect is in force from its apply on, whatever the caller's row says.
        stored.in_force = true;
        self.tx.execute(
            "INSERT INTO remote_policy_revisions (scope_key, producer, revision, runner_seq,
                 kind, effect_id, received_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                stored.scope_key,
                stored.producer.as_str(),
                codec::int(stored.revision)?,
                codec::int(stored.runner_seq)?,
                codec::enum_str(&stored.kind)?,
                stored.effect.as_str(),
                codec::ts(stored.received_at),
                codec::doc(&stored)?,
            ],
        )?;
        Ok(RevisionOutcome::Recorded(stored))
    }

    /// ⟨M06 W5 `w5s`, M06-W5-R01; ADR-0012 §7.4 ⟨2026-11-22⟩ "The in-force flag"⟩ The
    /// delivered effects still in force that changing the standing policies to `after`
    /// releases: of the policies the runner's acknowledgement says each applied to, at least
    /// one still exists in `after` and none that exists there is blocked (paused, for a
    /// pause; carrying a cutoff, for a cutoff), while that is not already so today. Reads
    /// only; it clears nothing. A caller that lets an attended owner widen a policy names
    /// these in the approval and binds them to it, and only that approval clears them
    /// ([`Self::lift_remote_policy_revision`]).
    ///
    /// ⟨M06 W5 `w5w`, M06-W5-RC01⟩ Nothing else clears the flag: not the report, not a
    /// removal, not a narrowing. An effect the policies already leave unblocked today (one
    /// whose other policies were removed, say) is not named here and stays in force until
    /// the local owner lifts it by its exact scope. Fail closed: a row with no recorded
    /// acknowledgement, one that applied to no policy, and one whose policies are all gone
    /// in `after` are never named.
    pub fn lifted_if(&mut self, after: &[StandingPolicy]) -> Result<Vec<PolicyRevisionRecord>> {
        let now = self.policies()?;
        let already: Vec<(String, ClientId, u64)> = self
            .judged_lifted(&now)?
            .into_iter()
            .map(|r| (r.scope_key, r.producer, r.revision))
            .collect();
        Ok(self
            .judged_lifted(after)?
            .into_iter()
            .filter(|r| {
                !already
                    .iter()
                    .any(|(k, c, n)| *k == r.scope_key && *c == r.producer && *n == r.revision)
            })
            .collect())
    }

    /// The rows in force that the rule of [`Self::lifted_if`] judges unblocked under the
    /// standing policies `policies`. Reads only.
    fn judged_lifted(&mut self, policies: &[StandingPolicy]) -> Result<Vec<PolicyRevisionRecord>> {
        let mut out = Vec::new();
        for row in self.remote_policy_revisions()? {
            if !row.in_force {
                continue;
            }
            let kind = match row.kind {
                PolicyRevisionKind::Pause => "policy_pause",
                PolicyRevisionKind::Cutoff => "policy_cutoff",
            };
            let ack: Option<EffectAck> = self.one_doc(
                "SELECT ack_json FROM remote_effect_acks
                 WHERE producer = ?1 AND effect_id = ?2 AND target_kind = ?3
                   AND target_ref = ?4 AND target_generation = ?5",
                rusqlite::params![
                    row.producer.as_str(),
                    row.effect.as_str(),
                    kind,
                    row.scope_key,
                    codec::int(row.revision)?,
                ],
            )?;
            let Some(AppliedRecord::PolicyRevision {
                policies: applied, ..
            }) = ack.map(|a| a.record)
            else {
                continue;
            };
            let mut left = policies
                .iter()
                .filter(|p| applied.contains(&p.id))
                .peekable();
            if left.peek().is_none() {
                continue;
            }
            let blocked = left.any(|p| match row.kind {
                PolicyRevisionKind::Pause => {
                    matches!(p.pause, heimdall_domain::policy::PauseState::Paused { .. })
                }
                PolicyRevisionKind::Cutoff => p.cutoff_at.is_some(),
            });
            if !blocked {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// ⟨M06 W5 `w5m` L1⟩ The runner's own owner lifted, by an attended decision that named
    /// it, the one delivered effect `(scope_key, producer, revision)`: clear its flag.
    /// Whether it was in force (and so cleared now); a row that does not exist or was
    /// already lifted is `false` and nothing is written. The caller holds the owner's
    /// decision; nothing here checks it.
    pub fn lift_remote_policy_revision(
        &mut self,
        scope_key: &str,
        producer: &ClientId,
        revision: u64,
    ) -> Result<bool> {
        let Some(mut row) = self.remote_policy_revision(scope_key, producer, revision)? else {
            return Ok(false);
        };
        if !row.in_force {
            return Ok(false);
        }
        row.in_force = false;
        self.tx.execute(
            "UPDATE remote_policy_revisions SET record_json = ?4
             WHERE scope_key = ?1 AND producer = ?2 AND revision = ?3",
            rusqlite::params![
                row.scope_key,
                row.producer.as_str(),
                codec::int(row.revision)?,
                codec::doc(&row)?,
            ],
        )?;
        Ok(true)
    }

    // --- the runner's authority report ------------------------------------------------------

    /// ⟨M06 U4⟩ Every grant tombstone, in the order applied (the authority report).
    pub fn tombstones(&mut self) -> Result<Vec<Tombstone>> {
        self.docs(
            "SELECT record_json FROM tombstones ORDER BY generation, grant_id",
            [],
        )
    }

    /// ⟨M06 U4⟩ The store's part of the runner's authority report (ADR-0012 §7.4 step 3):
    /// tombstones, delivered policy revisions and the standing policies as they are now. The
    /// caller adds the installed certificates. `None` on a store with no environment of its
    /// own. ⟨W5⟩ Each row states whether it is in force. ⟨M06 W5 `w5w`, M06-W5-RC01⟩ The
    /// report only reads that flag: it never clears one (only an approved lift that names
    /// the effect does, [`Self::lift_remote_policy_revision`]).
    pub fn authority_report(&mut self) -> Result<Option<AuthorityReport>> {
        let Some(environment) = self.self_environment()? else {
            return Ok(None);
        };
        let tombstones = self
            .tombstones()?
            .into_iter()
            .map(|t| ReportedTombstone {
                grant: t.grant,
                cascade: t.cascade,
                generation: t.generation.0,
                revoked_at: t.revoked_at,
            })
            .collect();
        let policies = self
            .policies()?
            .into_iter()
            .map(|p| ReportedPolicy {
                policy: p.id,
                revision: p.revision.0,
                paused: matches!(p.pause, heimdall_domain::policy::PauseState::Paused { .. }),
                cutoff_at: p.cutoff_at,
            })
            .collect();
        Ok(Some(AuthorityReport {
            environment,
            authority_generation: self.authority_generation()?.0,
            tombstones,
            policy_revisions: self.remote_policy_revisions()?,
            policies,
            certificates: Vec::new(),
            time_bounded: false,
            pending_grants: Vec::new(),
        }))
    }

    // --- the controller's contact observations ----------------------------------------------

    /// ⟨M06 U4⟩ What this controller last saw of `environment` (module docs).
    pub fn remote_contact(&mut self, environment: &EnvironmentId) -> Result<RemoteContact> {
        Ok(self
            .meta(&contact_key(environment))?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()?
            .unwrap_or_default())
    }

    /// ⟨M06 U4⟩ A management session to `environment` completed its hello at `at`: the last
    /// failure is cleared. `last_seen_at` never moves backwards.
    pub fn note_remote_seen(&mut self, environment: &EnvironmentId, at: Timestamp) -> Result<()> {
        let mut c = self.remote_contact(environment)?;
        c.last_seen_at = Some(c.last_seen_at.map_or(at, |old| old.max(at)));
        c.last_failure = None;
        self.set_meta(&contact_key(environment), &codec::doc(&c)?)
    }

    /// ⟨M06 U4⟩ An attempt to reach `environment` failed at `at` for `reason`.
    pub fn note_remote_failure(
        &mut self,
        environment: &EnvironmentId,
        at: Timestamp,
        reason: &str,
    ) -> Result<()> {
        let mut c = self.remote_contact(environment)?;
        c.last_failure = Some(ContactFailure {
            at,
            reason: reason.to_owned(),
        });
        self.set_meta(&contact_key(environment), &codec::doc(&c)?)
    }

    /// ⟨M06 U4⟩ This controller read `environment`'s authority report at `at`: keep what it
    /// showed installed (the last-known readiness).
    pub fn note_remote_report(
        &mut self,
        environment: &EnvironmentId,
        at: Timestamp,
        report: &AuthorityReport,
    ) -> Result<()> {
        let mut c = self.remote_contact(environment)?;
        c.last_report = Some(ObservedReport {
            at,
            certificates: report.certificates.clone(),
            cutoffs_fired_early: report
                .policy_revisions
                .iter()
                .filter(|r| r.fired_uncertain_at.is_some())
                .cloned()
                .collect(),
            policies: report.policies.iter().map(|p| p.policy.clone()).collect(),
            standing: Some(report.policies.clone()),
            revisions: Some(report.policy_revisions.clone()),
        });
        self.set_meta(&contact_key(environment), &codec::doc(&c)?)
    }

    /// ⟨M06 W5⟩ The pending grants of `environment` refused for their deadline at this
    /// pass (the whole list; an entry already recorded for the same grant and limit keeps
    /// its first instant). Nothing is written when nothing changes.
    pub fn set_refused_pending(
        &mut self,
        environment: &EnvironmentId,
        mut refused: Vec<RefusedPending>,
    ) -> Result<()> {
        let mut c = self.remote_contact(environment)?;
        for r in &mut refused {
            if let Some(old) = c
                .refused_pending
                .iter()
                .find(|o| o.grant == r.grant && o.limit == r.limit)
            {
                r.at = old.at;
            }
        }
        if c.refused_pending == refused {
            return Ok(());
        }
        c.refused_pending = refused;
        self.set_meta(&contact_key(environment), &codec::doc(&c)?)
    }

    /// ⟨M06 U4⟩ Forget the observation of `environment` (the environment was removed).
    pub fn forget_remote_contact(&mut self, environment: &EnvironmentId) -> Result<()> {
        self.delete_meta(&contact_key(environment))
    }

    /// ⟨M06 W3⟩ The controller runtime `session` holds (or, `None`, no longer holds) a
    /// resynchronized management session to `environment`.
    pub fn note_remote_session(
        &mut self,
        environment: &EnvironmentId,
        session: Option<HostedSession>,
    ) -> Result<()> {
        let mut c = self.remote_contact(environment)?;
        if c.hosted == session {
            return Ok(());
        }
        c.hosted = session;
        self.set_meta(&contact_key(environment), &codec::doc(&c)?)
    }

    // --- the controller's delivered grants --------------------------------------------------

    /// ⟨M06 W3⟩ This controller's record of `grant` on the runner `environment`, if it
    /// delivered one (module docs).
    pub fn delivered_grant(
        &mut self,
        environment: &EnvironmentId,
        grant: &GrantId,
    ) -> Result<Option<DeliveredGrant>> {
        self.meta(&delivered_key(environment, grant))?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// ⟨M06 W3⟩ Every grant this controller delivered to `environment` (`None`: to any
    /// runner), by environment and grant.
    pub fn delivered_grants(
        &mut self,
        environment: Option<&EnvironmentId>,
    ) -> Result<Vec<DeliveredGrant>> {
        let prefix = match environment {
            Some(e) => delivered_prefix(e),
            None => META_REMOTE_DELIVERED_GRANT.to_owned(),
        };
        self.meta_with_prefix(&prefix)?
            .iter()
            .map(|v| codec::parse_doc(v))
            .collect()
    }

    /// ⟨M06 W3⟩ Write `record` (insert or replace: the caller read it in this transaction).
    pub fn put_delivered_grant(&mut self, record: &DeliveredGrant) -> Result<()> {
        self.set_meta(
            &delivered_key(&record.environment, &record.grant),
            &codec::doc(record)?,
        )
    }

    /// ⟨M06 W3⟩ Forget every grant delivered to `environment` (the environment was removed);
    /// the number forgotten.
    pub fn forget_delivered_grants(&mut self, environment: &EnvironmentId) -> Result<usize> {
        let records = self.delivered_grants(Some(environment))?;
        for r in &records {
            self.delete_meta(&delivered_key(&r.environment, &r.grant))?;
        }
        Ok(records.len())
    }
}

// --- ⟨M08 W4 SEC-3b⟩ bounding the runner's authority history ---------------------------------
//
// ADR-0006 §7.4 and ADR-0012 §7.4 as amended 2026-11-27, on the orchestrator's ruling of
// 2026-11-26 (R1 to R3 and the override). Pruning runs only in the retention pass, on time the
// time gate accepted (`heimdall_app::Operations::tick`), and only on a runner. The caps hold
// only what has no authority effect on this runner: a narrowing that has one is never refused.

/// ⟨M08 W4 SEC-3b, R1⟩ The most bare delivered tombstones (a delivered `grant_revoke` naming a
/// grant this runner does not hold: [`Txn::record_bare_tombstone`]) one producing controller
/// may have at once. Past it a new one is refused `BACKPRESSURE`: it has no authority effect
/// here, and the effect stays in that controller's outbox, so its barrier stays closed.
pub const BARE_TOMBSTONES_PER_PRODUCER: usize = 256;

/// ⟨M08 W4 SEC-3b, R1⟩ The most bare delivered tombstones of every producer together.
pub const BARE_TOMBSTONES_TOTAL: usize = 1024;

/// ⟨M08 W4 SEC-3b, R2⟩ The most in-force delivered policy revisions of one producer whose
/// scope matches nothing on this runner ([`Txn::remote_scope_matches`]). Past it a new one is
/// refused `BACKPRESSURE`; a revision whose scope matches a runner object is never refused.
pub const UNMATCHED_REVISIONS_PER_PRODUCER: usize = 256;

/// ⟨M08 W4 SEC-3b, R1⟩ The longest window any grant may have, for a bare tombstone's
/// lifetime (`revoked_at` + this + `retention.operations`). The contract states no absolute
/// maximum for a grant's window (`session.max_window` has no upper bound, and a runner's own
/// configured window is not used, by ruling), so this is the design's 30-day fallback.
pub const GRANT_WINDOW_FALLBACK: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// ⟨M08 W4 SEC-3b⟩ The meta key of the runner's policy-revision order: the highest
/// `runner_seq` ever assigned, so a pruned row's number is never assigned again.
pub const META_REMOTE_POLICY_SEQ: &str = "remote_policy_seq";

/// ⟨M08 W4 SEC-3b, R1⟩ The condition (on alias `t`) of a **bare delivered tombstone**: no grant
/// row for its ID, and an explicit revoke (a delivered `grant_revoke`'s cause; a missing cause
/// reads `revoke`). Another installation's tombstones (a controller's `authority_withdrawn` ones
/// for its runners' grants) are never counted or pruned as these.
const BARE_DELIVERED: &str = "NOT EXISTS (SELECT 1 FROM grants g WHERE g.id = t.grant_id) \
     AND COALESCE(json_extract(t.record_json, '$.cause'), 'revoke') = 'revoke'";

/// The SQL condition (on `record_json`) of a revision row that is in force (the flag is omitted
/// when true, so a missing one reads in force: fail closed).
const IN_FORCE: &str = "COALESCE(json_extract(record_json, '$.in_force'), 1) <> 0";

/// The revision kind a pause or cutoff target delivers.
fn revision_kind(target: &EffectTarget) -> Option<PolicyRevisionKind> {
    match target {
        EffectTarget::PolicyPause { .. } => Some(PolicyRevisionKind::Pause),
        EffectTarget::PolicyCutoff { .. } => Some(PolicyRevisionKind::Cutoff),
        _ => None,
    }
}

/// What [`Txn::record_bare_tombstone`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareTombstone {
    /// A new bare tombstone, attributed to the producer.
    Recorded(Tombstone),
    /// The grant was already tombstoned: that tombstone stands, nothing written.
    Existing(Tombstone),
    /// The runner holds a grant of that ID: not bare (the caller revokes it), nothing written.
    Held,
    /// A cap was reached ([`BARE_TOMBSTONES_PER_PRODUCER`], [`BARE_TOMBSTONES_TOTAL`]): nothing
    /// written.
    Capped,
}

/// What one retention pass over the runner's authority history removed
/// ([`Txn::prune_runner_history`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryPruned {
    /// Known-grant tombstones (R1).
    pub known_tombstones: usize,
    /// Bare delivered tombstones (R1).
    pub bare_tombstones: usize,
    /// Lifted policy revisions (R2).
    pub policy_revisions: usize,
    /// Effect acknowledgements (R3).
    pub effect_acks: usize,
}

/// `at` moved back by `span` (the Unix epoch when it would go before it).
fn before(at: Timestamp, span: std::time::Duration) -> Timestamp {
    jiff::SignedDuration::try_from(span)
        .ok()
        .and_then(|d| at.checked_sub(d).ok())
        .unwrap_or(Timestamp::UNIX_EPOCH)
}

/// `at` moved forward by `span` (the far future when it would overflow).
fn after(at: Timestamp, span: std::time::Duration) -> Timestamp {
    jiff::SignedDuration::try_from(span)
        .ok()
        .and_then(|d| at.checked_add(d).ok())
        .unwrap_or(Timestamp::MAX)
}

impl Txn<'_> {
    /// ⟨M08 W4 SEC-3b⟩ The revision row with the runner's order number `runner_seq`.
    pub fn remote_policy_revision_at(
        &mut self,
        runner_seq: u64,
    ) -> Result<Option<PolicyRevisionRecord>> {
        self.one_doc(
            "SELECT record_json FROM remote_policy_revisions WHERE runner_seq = ?1",
            rusqlite::params![codec::int(runner_seq)?],
        )
    }

    /// ⟨M08 W4 SEC-3b, R2⟩ The producer's in-force revision row of `scope_key` and `kind`, if
    /// any (the first in the runner's order: coalescing keeps one).
    pub fn in_force_remote_revision(
        &mut self,
        producer: &ClientId,
        scope_key: &str,
        kind: PolicyRevisionKind,
    ) -> Result<Option<PolicyRevisionRecord>> {
        self.one_doc(
            &format!(
                "SELECT record_json FROM remote_policy_revisions
                 WHERE producer = ?1 AND scope_key = ?2 AND kind = ?3 AND {IN_FORCE}
                 ORDER BY runner_seq LIMIT 1"
            ),
            rusqlite::params![producer.as_str(), scope_key, codec::enum_str(&kind)?],
        )
    }

    /// ⟨M08 W4 SEC-3b, R1⟩ The bare delivered tombstones of `producer`, and of every producer.
    pub fn bare_tombstone_counts(&mut self, producer: &ClientId) -> Result<(usize, usize)> {
        let mine: i64 = self.tx.query_row(
            &format!(
                "SELECT count(*) FROM tombstones t WHERE t.producer = ?1 AND {BARE_DELIVERED}"
            ),
            [producer.as_str()],
            |r| r.get(0),
        )?;
        let all: i64 = self.tx.query_row(
            &format!("SELECT count(*) FROM tombstones t WHERE {BARE_DELIVERED}"),
            [],
            |r| r.get(0),
        )?;
        Ok((
            usize::try_from(mine).unwrap_or(usize::MAX),
            usize::try_from(all).unwrap_or(usize::MAX),
        ))
    }

    /// ⟨M08 W4 SEC-3b, R1⟩ Record the tombstone a delivered `grant_revoke` of `producer` names,
    /// for a grant this runner does not hold (a bare tombstone), in this transaction: one
    /// already there stands ([`BareTombstone::Existing`], always accepted: nothing grows); a
    /// grant this runner holds is not bare ([`BareTombstone::Held`]: the caller revokes it, and
    /// that is never capped); otherwise the caps are checked and the tombstone is written with
    /// its producer, or nothing is ([`BareTombstone::Capped`]).
    pub fn record_bare_tombstone(
        &mut self,
        tombstone: &Tombstone,
        producer: &ClientId,
    ) -> Result<BareTombstone> {
        if let Some(t) = self.tombstone(&tombstone.grant)? {
            return Ok(BareTombstone::Existing(t));
        }
        if self.grant(&tombstone.grant)?.is_some() {
            return Ok(BareTombstone::Held);
        }
        let (mine, all) = self.bare_tombstone_counts(producer)?;
        if mine >= BARE_TOMBSTONES_PER_PRODUCER || all >= BARE_TOMBSTONES_TOTAL {
            return Ok(BareTombstone::Capped);
        }
        self.insert_tombstone(tombstone)?;
        self.tx.execute(
            "UPDATE tombstones SET producer = ?2 WHERE grant_id = ?1",
            rusqlite::params![tombstone.grant.as_str(), producer.as_str()],
        )?;
        self.tombstone(&tombstone.grant)?
            .map(BareTombstone::Recorded)
            .ok_or_else(|| corrupt("a tombstone just written is missing"))
    }

    /// ⟨M08 W4 SEC-3b, R2⟩ Whether a delivered pause's or cutoff's `scope` matches a runner
    /// object, as the runner applies it: a policy of that ID, a policy of that profile or
    /// workspace, and `all` always (one coalesced row per producer, never refused). A scope
    /// this build does not know matches nothing.
    pub fn remote_scope_matches(&mut self, scope: &PolicyTarget) -> Result<bool> {
        Ok(match scope {
            PolicyTarget::Policy { policy_id } => self.policy(policy_id)?.is_some(),
            PolicyTarget::Profile { profile } => {
                self.policies()?.iter().any(|p| p.profile == *profile)
            }
            PolicyTarget::Workspace { workspace } => self
                .policies()?
                .iter()
                .any(|p| p.workspace.as_ref() == Some(workspace)),
            PolicyTarget::All => true,
            _ => false,
        })
    }

    /// ⟨M08 W4 SEC-3b, R2⟩ The producer's in-force revision rows whose scope matches nothing on
    /// this runner now ([`UNMATCHED_REVISIONS_PER_PRODUCER`] caps them).
    pub fn unmatched_in_force_revisions(&mut self, producer: &ClientId) -> Result<usize> {
        let rows: Vec<PolicyRevisionRecord> = self.docs(
            &format!(
                "SELECT record_json FROM remote_policy_revisions WHERE producer = ?1 AND {IN_FORCE}"
            ),
            [producer.as_str()],
        )?;
        let mut unmatched = 0usize;
        for row in rows {
            if !self.remote_scope_matches(&row.scope)? {
                unmatched += 1;
            }
        }
        Ok(unmatched)
    }

    /// ⟨M08 W4 SEC-3b, R2⟩ Whether recording `row` would add a new in-force row whose scope
    /// matches nothing here while `producer` is at [`UNMATCHED_REVISIONS_PER_PRODUCER`]: the
    /// only case a delivered pause or cutoff is refused (`BACKPRESSURE`). A redelivery of an
    /// existing identity, one coalesced into an in-force row, and one whose scope matches a
    /// runner object never are.
    pub fn unmatched_revision_capped(&mut self, row: &PolicyRevisionRecord) -> Result<bool> {
        if self
            .remote_policy_revision(&row.scope_key, &row.producer, row.revision)?
            .is_some()
            || self
                .in_force_remote_revision(&row.producer, &row.scope_key, row.kind)?
                .is_some()
            || self.remote_scope_matches(&row.scope)?
        {
            return Ok(false);
        }
        Ok(self.unmatched_in_force_revisions(&row.producer)? >= UNMATCHED_REVISIONS_PER_PRODUCER)
    }

    /// ⟨M08 W4 SEC-3b, R2⟩ The producing controller `producer` went on, in the session it was
    /// served a complete authority report in, after that report showed its revisions `shown`
    /// (`(scope_key, revision)`) lifted: the runner's evidence that the controller recorded
    /// each lift (`remote_effect_outbox.lift_seen_at`). Each row still lifted gets its
    /// confirmation once, at `at`. The number confirmed now.
    pub fn confirm_remote_lifts(
        &mut self,
        producer: &ClientId,
        shown: &[(String, u64)],
        at: Timestamp,
    ) -> Result<usize> {
        let mut n = 0usize;
        for (scope_key, revision) in shown {
            n += self.tx.execute(
                &format!(
                    "UPDATE remote_policy_revisions SET lift_confirmed_at = ?4
                     WHERE producer = ?1 AND scope_key = ?2 AND revision = ?3
                       AND lift_confirmed_at IS NULL AND NOT ({IN_FORCE})"
                ),
                rusqlite::params![
                    producer.as_str(),
                    scope_key,
                    codec::int(*revision)?,
                    codec::ts(at)
                ],
            )?;
        }
        Ok(n)
    }

    /// ⟨M08 W4 SEC-3b; R1 to R3⟩ One retention pass over the runner's authority history, at
    /// `now`, the time the caller's time gate accepted (never under `TIME_UNCERTAIN`), with
    /// `retention` = `retention.operations`. `live`: the grants the runner's memory still holds
    /// a key or a certificate for; `None` when it cannot say, and then no known-grant tombstone
    /// is pruned. Only a runner's store is pruned (a store whose own environment is not a remote
    /// runner is left as it is).
    ///
    /// * **R1, a known-grant tombstone** goes only when its grant's row is `revoked` or
    ///   `expired` (both terminal), `now` ≥ the latest deadline
    ///   of the grant and every descendant plus `retention`, every descendant is terminal, and
    ///   nothing live remains for any of them: no key or certificate (`live`), no unreleased
    ///   binding, grant reference, held slot, slot reference or owned connection. The
    ///   controller's issuance log is another store's and is never touched.
    /// * **R1, a bare delivered tombstone** goes at `revoked_at` + [`GRANT_WINDOW_FALLBACK`] +
    ///   `retention`.
    /// * **R2, a policy revision in force is never pruned.** A lifted one first gets its
    ///   `lifted_at` (this pass's time), then goes `retention` after its lift was confirmed by
    ///   its producer ([`Self::confirm_remote_lifts`]), or after its producer was revoked
    ///   (the later of the lift and the revocation).
    /// * **R3, acknowledgements:** a `grant_revoke`'s goes `retention` after it was applied, or
    ///   once its producer is revoked, or once the grant has no tombstone; a pause's or
    ///   cutoff's never while the row it names is in force, and goes with that row, or
    ///   `retention` after it was applied once the row is lifted.
    pub fn prune_runner_history(
        &mut self,
        now: Timestamp,
        retention: std::time::Duration,
        live: Option<&std::collections::BTreeSet<GrantId>>,
    ) -> Result<HistoryPruned> {
        use heimdall_domain::environment::EnvironmentKind;
        let runner = match self.self_environment()? {
            Some(id) => self
                .environment(&id)?
                .is_some_and(|e| e.kind == EnvironmentKind::RemoteRunner),
            None => false,
        };
        if !runner {
            return Ok(HistoryPruned::default());
        }
        let mut pruned = HistoryPruned::default();
        let horizon = before(now, retention);
        // R1: bare delivered tombstones.
        let bare_horizon = before(horizon, GRANT_WINDOW_FALLBACK);
        pruned.bare_tombstones = self.tx.execute(
            &format!("DELETE FROM tombstones AS t WHERE {BARE_DELIVERED} AND t.revoked_at <= ?1"),
            [codec::ts(bare_horizon)],
        )?;
        // R1: known-grant tombstones.
        if let Some(live) = live {
            use heimdall_contract::GrantState;
            let known: Vec<String> = {
                let mut stmt = self.tx.prepare(
                    "SELECT t.grant_id FROM tombstones t
                     JOIN grants g ON g.id = t.grant_id
                     WHERE g.state IN (?1, ?2) ORDER BY t.generation",
                )?;
                let rows = stmt.query_map(
                    [
                        codec::enum_str(&GrantState::Revoked)?,
                        codec::enum_str(&GrantState::Expired)?,
                    ],
                    |r| r.get::<_, String>(0),
                )?;
                rows.collect::<std::result::Result<_, _>>()?
            };
            for id in known {
                let grant = GrantId::parse(&id)
                    .map_err(|_| corrupt("a tombstone names a malformed grant"))?;
                if self.known_tombstone_prunable(&grant, now, retention, live)? {
                    pruned.known_tombstones += self
                        .tx
                        .execute("DELETE FROM tombstones WHERE grant_id = ?1", [id.as_str()])?;
                }
            }
        }
        // R2: lifted revisions get their lift's time, then go once confirmed or orphaned.
        self.tx.execute(
            &format!(
                "UPDATE remote_policy_revisions SET lifted_at = ?1
                 WHERE lifted_at IS NULL AND NOT ({IN_FORCE})"
            ),
            [codec::ts(now)],
        )?;
        let lifted: Vec<(String, String, i64, Option<String>, String)> = {
            let mut stmt = self.tx.prepare(&format!(
                "SELECT scope_key, producer, revision, lift_confirmed_at, lifted_at
                 FROM remote_policy_revisions WHERE NOT ({IN_FORCE}) AND lifted_at IS NOT NULL"
            ))?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (scope_key, producer, revision, confirmed, lifted_at) in lifted {
            let lifted_at = codec::parse_ts(&lifted_at)?;
            let producer_id = ClientId::parse(&producer)
                .map_err(|_| corrupt("a policy revision names a malformed producer"))?;
            let due = match self.revoked_since(&producer_id)? {
                // Revoked (or gone): it can never confirm; the later of the two instants.
                Some(revoked_at) => lifted_at.max(revoked_at) <= horizon,
                None => match confirmed {
                    Some(c) => codec::parse_ts(&c)? <= horizon,
                    None => false,
                },
            };
            if due {
                pruned.policy_revisions += self.tx.execute(
                    "DELETE FROM remote_policy_revisions
                     WHERE scope_key = ?1 AND producer = ?2 AND revision = ?3",
                    rusqlite::params![scope_key, producer, revision],
                )?;
            }
        }
        // R3: acknowledgements.
        pruned.effect_acks = self.prune_effect_acks(horizon)?;
        Ok(pruned)
    }

    /// When `client` was revoked on this runner (its record's last change), or the Unix epoch
    /// when there is no record of it; `None` while it is not revoked.
    fn revoked_since(&mut self, client: &ClientId) -> Result<Option<Timestamp>> {
        Ok(match self.remote_client(client)? {
            None => Some(Timestamp::UNIX_EPOCH),
            Some(c) if c.state == crate::ext_m06::ClientState::Revoked => Some(c.updated_at),
            Some(_) => None,
        })
    }

    /// R1's conditions for one known-grant tombstone (doc of [`Self::prune_runner_history`]).
    fn known_tombstone_prunable(
        &mut self,
        grant: &GrantId,
        now: Timestamp,
        retention: std::time::Duration,
        live: &std::collections::BTreeSet<GrantId>,
    ) -> Result<bool> {
        let Some(root) = self.grant(grant)? else {
            return Ok(false);
        };
        use heimdall_contract::GrantState;
        if !matches!(root.state, GrantState::Revoked | GrantState::Expired) {
            return Ok(false);
        }
        let mut family = vec![root.clone()];
        let mut ids: std::collections::BTreeSet<GrantId> =
            self.grant_descendants(grant)?.into_iter().collect();
        if let Some(t) = self.tombstone(grant)? {
            ids.extend(t.cascade);
        }
        for id in &ids {
            match self.grant(id)? {
                Some(g) if g.state.is_terminal() => family.push(g),
                // A descendant that is still live, or one this store cannot read: kept.
                _ => return Ok(false),
            }
        }
        let latest = family
            .iter()
            .map(|g| g.deadline.effective)
            .max()
            .unwrap_or(root.deadline.effective);
        if now < after(latest, retention) {
            return Ok(false);
        }
        for g in &family {
            if live.contains(&g.id) || self.grant_residue(&g.id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether anything of `grant` is still live in the store: an unreleased binding, a grant
    /// reference, a slot held for one of its bindings, a slot reference, or an owned
    /// connection that is not closed.
    fn grant_residue(&mut self, grant: &GrantId) -> Result<bool> {
        let n: i64 = self.tx.query_row(
            "SELECT
                 (SELECT count(*) FROM bindings WHERE grant_id = ?1 AND released_at IS NULL)
               + (SELECT count(*) FROM grant_references WHERE grant_id = ?1)
               + (SELECT count(*) FROM managed_slots s JOIN bindings b ON b.id = s.binding_id
                  WHERE b.grant_id = ?1 AND s.state <> 'free')
               + (SELECT count(*) FROM slot_references r JOIN bindings b ON b.id = r.binding_id
                  WHERE b.grant_id = ?1)
               + (SELECT count(*) FROM owned_connections WHERE grant_id = ?1 AND state <> 'closed')",
            [grant.as_str()],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// R3 (doc of [`Self::prune_runner_history`]); `horizon` is `now` − retention.
    fn prune_effect_acks(&mut self, horizon: Timestamp) -> Result<usize> {
        let rows: Vec<(String, String, String, String, i64, String, String)> = {
            let mut stmt = self.tx.prepare(
                "SELECT producer, effect_id, target_kind, target_ref, target_generation,
                        applied_at, ack_json
                 FROM remote_effect_acks",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut n = 0usize;
        for (producer, effect, kind, reference, generation, applied_at, ack_json) in rows {
            let applied_due = codec::parse_ts(&applied_at)? <= horizon;
            let ack: EffectAck = codec::parse_doc(&ack_json)?;
            let due = match &ack.record {
                AppliedRecord::GrantTombstone { grant, .. } => {
                    applied_due
                        || self.revoked_since(&ack.key.producer)?.is_some()
                        || self.tombstone(grant)?.is_none()
                }
                AppliedRecord::PolicyRevision { runner_seq, .. } => {
                    // The row the acknowledgement names: its own, else the one it was
                    // coalesced into.
                    let row = match self.remote_policy_revision(
                        &reference,
                        &ack.key.producer,
                        ack.key.target.generation(),
                    )? {
                        Some(r) if r.effect == ack.key.effect => Some(r),
                        _ => self.remote_policy_revision_at(*runner_seq)?,
                    };
                    match row {
                        None => true,
                        Some(r) if r.in_force => false,
                        Some(_) => applied_due,
                    }
                }
            };
            if due {
                n += self.tx.execute(
                    "DELETE FROM remote_effect_acks
                     WHERE producer = ?1 AND effect_id = ?2 AND target_kind = ?3
                       AND target_ref = ?4 AND target_generation = ?5",
                    rusqlite::params![producer, effect, kind, reference, generation],
                )?;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use heimdall_domain::policy::AuthorityGeneration;
    use heimdall_domain::revocation::RevocationCause;

    use super::*;
    use crate::{NoFaults, Store};

    fn store() -> Store {
        Store::open_in_memory(Arc::new(NoFaults)).unwrap()
    }

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn client(b: u8) -> ClientId {
        ClientId::from_random_bytes([b; 16])
    }

    fn effect(b: u8) -> EffectId {
        EffectId::from_random_bytes([b; 16])
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([3; 16])
    }

    fn grant() -> GrantId {
        GrantId::from_random_bytes([9; 16])
    }

    fn revoke_key(producer: u8, e: u8) -> EffectKey {
        EffectKey {
            producer: client(producer),
            effect: effect(e),
            target: EffectTarget::GrantRevoke {
                grant: grant(),
                grant_generation: 4,
            },
        }
    }

    fn cutoff_row(producer: u8, e: u8, revision: u64, at: &str) -> PolicyRevisionRecord {
        PolicyRevisionRecord {
            scope_key: "all".into(),
            scope: PolicyTarget::All,
            producer: client(producer),
            revision,
            runner_seq: 0,
            kind: PolicyRevisionKind::Cutoff,
            effect: effect(e),
            received_at: t("2026-11-21T09:00:00Z"),
            cutoff_at: Some(t(at)),
            fired_uncertain_at: None,
            in_force: true,
        }
    }

    fn tombstone_ack(key: &EffectKey) -> EffectAck {
        EffectAck {
            key: key.clone(),
            applied_at: t("2026-11-21T09:00:01Z"),
            record: AppliedRecord::GrantTombstone {
                grant: grant(),
                known: true,
                cascade: Vec::new(),
                key_destroyed: true,
                owned_dedicated_sessions: ComponentResidual::Closed,
                owned_admissions: ComponentResidual::Closed,
            },
        }
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 4⟩ The authority report states, per delivered pause or
    /// cutoff, whether it is still in force, and only the runner's own owner clears that:
    /// a policy the effect was applied to that is no longer blocked. A runner with no
    /// standing policy keeps reporting it in force; so does a row with no acknowledgement,
    /// and one whose policies are gone. A policy added later does not lift it. Once
    /// cleared it stays cleared; a redelivery of the same key does not set it again.
    #[test]
    fn the_report_says_which_delivered_effects_are_still_in_force() {
        use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
        let at = t("2026-11-21T09:00:00Z");
        // Each write is the policy's next revision.
        let revision = std::cell::Cell::new(0u64);
        let policy = |id: &str, paused: bool, cutoff: bool| StandingPolicy {
            id: PolicyId::parse(id).unwrap(),
            revision: {
                revision.set(revision.get() + 1);
                PolicyRevision(revision.get())
            },
            profile: heimdall_contract::ids::ProfileId::parse("default").unwrap(),
            workspace: None,
            scope: heimdall_domain::scope::Scope::empty(),
            environments: std::collections::BTreeSet::new(),
            max_window: std::time::Duration::from_secs(3600),
            pause: if paused {
                PauseState::Paused { since: at }
            } else {
                PauseState::Active
            },
            cutoff_at: cutoff.then_some(at),
            source: PolicySource::SetupDefault,
            lock_behavior: Default::default(),
            connection: Default::default(),
            default: false,
        };
        // Deliver a cutoff of every policy (`n`), acknowledged as applied to `applied`.
        let deliver = |tx: &mut Txn<'_>, n: u8, applied: &[&str]| -> Result<()> {
            let row = cutoff_row(1, n, u64::from(n), "2026-11-21T09:00:00Z");
            tx.record_remote_policy_revision(&row)?;
            tx.record_remote_effect_ack(&EffectAck {
                key: EffectKey {
                    producer: client(1),
                    effect: effect(n),
                    target: EffectTarget::PolicyCutoff {
                        scope: PolicyTarget::All,
                        at,
                        revision: u64::from(n),
                    },
                },
                applied_at: at,
                record: AppliedRecord::PolicyRevision {
                    scope_key: "all".into(),
                    runner_seq: u64::from(n),
                    policies: applied
                        .iter()
                        .map(|p| PolicyId::parse(p).unwrap())
                        .collect(),
                    cutoff_at: Some(at),
                    fired: true,
                },
            })
        };
        let in_force = |tx: &mut Txn<'_>| -> Result<Vec<bool>> {
            Ok(tx
                .authority_report()?
                .unwrap()
                .policy_revisions
                .iter()
                .map(|r| r.in_force)
                .collect())
        };

        // A runner with no standing policy: nothing its owner could have lifted.
        let s = store();
        s.transaction(|tx| {
            tx.init_self_environment(&env())?;
            deliver(tx, 1, &[])?;
            assert_eq!(in_force(tx)?, vec![true]);
            // A policy added to the scope later is not a lift of the delivered effect.
            tx.upsert_policy(&policy("later", false, false), false)?;
            assert_eq!(in_force(tx)?, vec![true]);
            // A row whose acknowledgement was never recorded stays in force (another
            // producer's row: ⟨M08 W4 SEC-3b, R2⟩ the same producer's next delivery of the same
            // scope and kind, while its first is in force, is coalesced into that row).
            tx.record_remote_policy_revision(&cutoff_row(2, 2, 2, "2026-11-21T09:00:00Z"))?;
            assert_eq!(in_force(tx)?, vec![true, true]);
            let coalesced =
                tx.record_remote_policy_revision(&cutoff_row(1, 4, 4, "2026-11-21T09:00:00Z"))?;
            assert!(matches!(coalesced, RevisionOutcome::Coalesced(ref r) if r.runner_seq == 1));
            assert_eq!(in_force(tx)?, vec![true, true]);
            Ok(())
        })
        .unwrap();

        // ⟨M06-W5-RC01⟩ A runner with policies: the report never clears the flag. What the
        // standing policies would release is only named ([`Txn::lifted_if`]); only an
        // approved lift that names the effect clears it.
        let s = store();
        s.transaction(|tx| {
            tx.init_self_environment(&env())?;
            tx.upsert_policy(&policy("a", false, true), true)?;
            tx.upsert_policy(&policy("b", false, true), true)?;
            deliver(tx, 1, &["a", "b"])?;
            assert_eq!(in_force(tx)?, vec![true]);
            let b_cleared = [policy("a", false, true), policy("b", false, false)];
            let both_cleared = [policy("a", false, false), policy("b", false, false)];
            // Clearing one of the two releases nothing; clearing both names the effect.
            assert!(tx.lifted_if(&b_cleared)?.is_empty());
            assert_eq!(tx.lifted_if(&both_cleared)?.len(), 1);
            // The runner's owner cleared one of the two: still in force.
            tx.upsert_policy(&policy("a", false, false), false)?;
            assert_eq!(in_force(tx)?, vec![true]);
            // A pause is not a cutoff: resuming or pausing changes nothing here.
            tx.upsert_policy(&policy("a", true, false), true)?;
            assert_eq!(in_force(tx)?, vec![true]);
            // Both cleared with no lift naming the effect: still in force (the report reads,
            // it never clears). Already released today, so no later change names it either.
            tx.upsert_policy(&policy("b", false, false), false)?;
            assert_eq!(in_force(tx)?, vec![true]);
            assert!(tx.lifted_if(&both_cleared)?.is_empty());
            // One of them removed (a narrowing): still in force.
            tx.delete_policy(&PolicyId::parse("a").unwrap())?;
            assert_eq!(in_force(tx)?, vec![true]);
            assert!(tx.remote_policy_revisions()?[0].in_force);
            // The approved lift that names it clears it, in the report and in the store.
            let row = tx.remote_policy_revisions()?[0].clone();
            assert!(tx.lift_remote_policy_revision(&row.scope_key, &row.producer, row.revision)?);
            assert_eq!(in_force(tx)?, vec![false]);
            assert!(!tx.remote_policy_revisions()?[0].in_force);
            // A second lift of the same row writes nothing.
            assert!(!tx.lift_remote_policy_revision(
                &row.scope_key,
                &row.producer,
                row.revision
            )?);
            // Sticky: a later local cutoff is the runner's own, not the delivered effect.
            tx.upsert_policy(&policy("b", false, true), true)?;
            assert_eq!(in_force(tx)?, vec![false]);
            // A redelivery of the same key keeps the row as it is.
            let again =
                tx.record_remote_policy_revision(&cutoff_row(1, 1, 1, "2026-11-21T09:00:00Z"))?;
            assert!(matches!(again, RevisionOutcome::Existing(r) if !r.in_force));
            // A new effect is in force from its apply on, whatever the caller's row says.
            let mut lifted_row = cutoff_row(1, 3, 3, "2026-11-21T09:00:00Z");
            lifted_row.in_force = false;
            let stored = tx.record_remote_policy_revision(&lifted_row)?;
            assert!(stored.record().in_force);
            Ok(())
        })
        .unwrap();

        // Every policy the effect applied to is gone: it stays in force, and nothing names it.
        let s = store();
        s.transaction(|tx| {
            tx.init_self_environment(&env())?;
            tx.upsert_policy(&policy("a", false, true), true)?;
            deliver(tx, 1, &["a"])?;
            tx.delete_policy(&PolicyId::parse("a").unwrap())?;
            assert_eq!(in_force(tx)?, vec![true]);
            assert!(tx.lifted_if(&[])?.is_empty());
            Ok(())
        })
        .unwrap();

        // The wire form: omitted while in force, so an earlier row or report reads in force.
        let row = cutoff_row(1, 1, 1, "2026-11-21T09:00:00Z");
        let json = serde_json::to_value(&row).unwrap();
        assert!(json.get("in_force").is_none(), "{json}");
        assert!(
            serde_json::from_value::<PolicyRevisionRecord>(json)
                .unwrap()
                .in_force
        );
        let lifted = PolicyRevisionRecord {
            in_force: false,
            ..row
        };
        let json = serde_json::to_value(&lifted).unwrap();
        assert_eq!(json["in_force"], false, "{json}");
        assert_eq!(
            serde_json::from_value::<PolicyRevisionRecord>(json).unwrap(),
            lifted
        );
    }

    /// The outbox keeps one row per key, lists pending rows in production order, and an
    /// acknowledgement settles a row once.
    #[test]
    fn the_outbox_is_keyed_and_an_acknowledgement_settles_a_row_once() {
        let s = store();
        let now = t("2026-11-21T09:00:00Z");
        let a = revoke_key(1, 1);
        let b = EffectKey {
            effect: effect(2),
            ..a.clone()
        };
        s.transaction(|tx| {
            assert!(tx.enqueue_remote_effect(&env(), &a, now)?);
            assert!(!tx.enqueue_remote_effect(&env(), &a, now)?, "same key");
            assert!(tx.enqueue_remote_effect(&env(), &b, t("2026-11-21T09:00:05Z"))?);
            let pending = tx.remote_effect_outbox(Some(&env()), true)?;
            assert_eq!(
                pending.iter().map(|e| &e.key).collect::<Vec<_>>(),
                vec![&a, &b]
            );
            let other = EnvironmentId::from_random_bytes([4; 16]);
            assert!(tx.remote_effect_outbox(Some(&other), false)?.is_empty());

            let ack = tombstone_ack(&a);
            assert!(tx.acknowledge_remote_effect(&ack, t("2026-11-21T09:01:00Z"))?);
            assert!(
                !tx.acknowledge_remote_effect(&ack, t("2026-11-21T09:02:00Z"))?,
                "the first acknowledgement is kept"
            );
            let all = tx.remote_effect_outbox(None, false)?;
            assert_eq!(all.len(), 2);
            assert_eq!(all[0].state, OutboxState::Acknowledged);
            assert_eq!(all[0].acknowledged_at, Some(t("2026-11-21T09:01:00Z")));
            assert_eq!(all[0].ack.as_ref(), Some(&ack));
            assert_eq!(tx.remote_effect_outbox(None, true)?.len(), 1);
            // An acknowledgement of an unknown key settles nothing.
            assert!(!tx.acknowledge_remote_effect(&tombstone_ack(&revoke_key(2, 1)), now)?);
            assert_eq!(tx.forget_remote_effect_outbox(&env())?, 2);
            Ok(())
        })
        .unwrap();
    }

    /// ⟨M06 W4⟩ A lift acknowledgement is written only for a pause or cutoff of the outbox
    /// that the runner acknowledged, once, and goes with the environment's outbox rows.
    #[test]
    fn a_lift_acknowledgement_needs_a_delivered_pause_or_cutoff() {
        let s = store();
        let now = t("2026-11-21T09:00:00Z");
        let cutoff = EffectKey {
            producer: client(1),
            effect: effect(1),
            target: EffectTarget::PolicyCutoff {
                scope: PolicyTarget::All,
                at: t("2026-11-21T10:00:00Z"),
                revision: 1,
            },
        };
        let ack = EffectAck {
            key: cutoff.clone(),
            applied_at: now,
            record: AppliedRecord::PolicyRevision {
                scope_key: "all".into(),
                runner_seq: 1,
                policies: Vec::new(),
                cutoff_at: Some(t("2026-11-21T10:00:00Z")),
                fired: false,
            },
        };
        s.transaction(|tx| {
            // Not in the outbox; then pending: nothing is written.
            assert!(!tx.acknowledge_remote_lift(&env(), &cutoff, now)?);
            assert!(tx.enqueue_remote_effect(&env(), &cutoff, now)?);
            assert!(!tx.acknowledge_remote_lift(&env(), &cutoff, now)?);
            assert!(tx.acknowledge_remote_effect(&ack, now)?);
            // Another environment's name for the same key: nothing.
            let other = EnvironmentId::from_random_bytes([4; 16]);
            assert!(!tx.acknowledge_remote_lift(&other, &cutoff, now)?);
            assert_eq!(tx.remote_lift_ack(&cutoff)?, None);
            // Delivered: recorded once, the first instant kept.
            assert!(tx.acknowledge_remote_lift(&env(), &cutoff, now)?);
            assert!(!tx.acknowledge_remote_lift(&env(), &cutoff, t("2026-11-21T09:05:00Z"))?);
            assert_eq!(tx.remote_lift_ack(&cutoff)?, Some(now));
            // A revoke is never lifted.
            let revoke = revoke_key(1, 2);
            assert!(tx.enqueue_remote_effect(&env(), &revoke, now)?);
            assert!(tx.acknowledge_remote_effect(&tombstone_ack(&revoke), now)?);
            assert!(!tx.acknowledge_remote_lift(&env(), &revoke, now)?);
            // Forgetting the environment forgets its acknowledgements.
            assert_eq!(tx.forget_remote_effect_outbox(&env())?, 2);
            assert_eq!(tx.remote_lift_ack(&cutoff)?, None);
            Ok(())
        })
        .unwrap();
    }

    /// An acknowledgement is written only after the durable record it names exists.
    #[test]
    fn an_acknowledgement_needs_its_durable_record() {
        let s = store();
        let key = revoke_key(1, 1);
        let refused = s.transaction(|tx| tx.record_remote_effect_ack(&tombstone_ack(&key)));
        assert!(refused.is_err(), "no tombstone yet");
        s.transaction(|tx| {
            assert_eq!(tx.remote_effect_ack(&key)?, None);
            tx.insert_tombstone(&Tombstone {
                grant: grant(),
                cascade: Vec::new(),
                generation: AuthorityGeneration(0),
                revoked_at: t("2026-11-21T09:00:00Z"),
                remote_pending: Vec::new(),
                cause: RevocationCause::Revoke,
            })?;
            tx.record_remote_effect_ack(&tombstone_ack(&key))?;
            assert_eq!(tx.remote_effect_ack(&key)?, Some(tombstone_ack(&key)));
            // Another producer's effect on the same grant is another key.
            assert_eq!(tx.remote_effect_ack(&revoke_key(2, 1))?, None);
            assert_eq!(tx.tombstones()?.len(), 1);
            Ok(())
        })
        .unwrap();

        // A policy effect: the revision row first.
        let cutoff = EffectKey {
            producer: client(1),
            effect: effect(7),
            target: EffectTarget::PolicyCutoff {
                scope: PolicyTarget::All,
                at: t("2026-11-21T12:00:00Z"),
                revision: 3,
            },
        };
        let ack = EffectAck {
            key: cutoff.clone(),
            applied_at: t("2026-11-21T09:00:01Z"),
            record: AppliedRecord::PolicyRevision {
                scope_key: "all".into(),
                runner_seq: 1,
                policies: Vec::new(),
                cutoff_at: Some(t("2026-11-21T12:00:00Z")),
                fired: false,
            },
        };
        assert!(
            s.transaction(|tx| tx.record_remote_effect_ack(&ack))
                .is_err()
        );
        s.transaction(|tx| {
            tx.record_remote_policy_revision(&cutoff_row(1, 7, 3, "2026-11-21T12:00:00Z"))?;
            tx.record_remote_effect_ack(&ack)?;
            assert_eq!(tx.remote_effect_ack(&cutoff)?, Some(ack.clone()));
            Ok(())
        })
        .unwrap();
    }

    /// Producer-scoped identity: two controllers' equal revision numbers for one scope are two
    /// rows in the runner's order; a redelivery keeps the row; an earlier redelivered cutoff
    /// shortens it and a later one does not move it.
    #[test]
    fn policy_revisions_are_producer_scoped_ordered_and_only_shorten() {
        let s = store();
        s.transaction(|tx| {
            let a =
                tx.record_remote_policy_revision(&cutoff_row(1, 1, 5, "2026-11-21T12:00:00Z"))?;
            let b =
                tx.record_remote_policy_revision(&cutoff_row(2, 2, 5, "2026-11-21T13:00:00Z"))?;
            assert!(matches!(a, RevisionOutcome::Recorded(_)));
            assert_eq!(a.record().runner_seq, 1);
            assert_eq!(b.record().runner_seq, 2);
            // Redelivered unchanged.
            let again =
                tx.record_remote_policy_revision(&cutoff_row(1, 1, 5, "2026-11-21T12:00:00Z"))?;
            assert_eq!(again, RevisionOutcome::Existing(a.record().clone()));
            // Later: not moved. Earlier: shortened.
            let later =
                tx.record_remote_policy_revision(&cutoff_row(1, 1, 5, "2026-11-21T15:00:00Z"))?;
            assert_eq!(later.record().cutoff_at, Some(t("2026-11-21T12:00:00Z")));
            let earlier =
                tx.record_remote_policy_revision(&cutoff_row(1, 1, 5, "2026-11-21T10:00:00Z"))?;
            assert!(matches!(earlier, RevisionOutcome::Shortened(_)));
            let rows = tx.remote_policy_revisions()?;
            assert_eq!(rows.len(), 2, "both producers' rows are durable");
            assert_eq!(rows[0].cutoff_at, Some(t("2026-11-21T10:00:00Z")));
            assert_eq!(rows[0].runner_seq, 1, "the order is kept");
            assert_eq!(rows[1].producer, client(2));
            // The same identity as a pause is refused.
            let mut pause = cutoff_row(1, 1, 5, "2026-11-21T10:00:00Z");
            pause.kind = PolicyRevisionKind::Pause;
            pause.cutoff_at = None;
            assert!(tx.record_remote_policy_revision(&pause).is_err());
            Ok(())
        })
        .unwrap();
    }

    /// The contact observation: the last-seen instant never moves back, and a later success
    /// clears the failure.
    #[test]
    fn contact_observations_keep_the_latest_seen_instant() {
        let s = store();
        s.transaction(|tx| {
            assert_eq!(tx.remote_contact(&env())?, RemoteContact::default());
            tx.note_remote_seen(&env(), t("2026-11-21T09:00:00Z"))?;
            tx.note_remote_failure(&env(), t("2026-11-21T09:05:00Z"), "timeout")?;
            let c = tx.remote_contact(&env())?;
            assert_eq!(c.last_seen_at, Some(t("2026-11-21T09:00:00Z")));
            assert_eq!(
                c.last_failure.as_ref().map(|f| f.reason.as_str()),
                Some("timeout")
            );
            tx.note_remote_seen(&env(), t("2026-11-21T08:00:00Z"))?;
            let c = tx.remote_contact(&env())?;
            assert_eq!(c.last_seen_at, Some(t("2026-11-21T09:00:00Z")));
            assert_eq!(c.last_failure, None);
            tx.forget_remote_contact(&env())?;
            assert_eq!(tx.remote_contact(&env())?, RemoteContact::default());
            Ok(())
        })
        .unwrap();
    }

    /// The store's part of the authority report.
    #[test]
    fn the_authority_report_lists_tombstones_and_revisions() {
        let s = store();
        s.transaction(|tx| {
            assert_eq!(tx.authority_report()?, None, "no environment of its own");
            tx.init_self_environment(&env())?;
            tx.insert_tombstone(&Tombstone {
                grant: grant(),
                cascade: Vec::new(),
                generation: AuthorityGeneration(0),
                revoked_at: t("2026-11-21T09:00:00Z"),
                remote_pending: Vec::new(),
                cause: RevocationCause::Revoke,
            })?;
            tx.record_remote_policy_revision(&cutoff_row(1, 1, 5, "2026-11-21T12:00:00Z"))?;
            let r = tx.authority_report()?.unwrap();
            assert_eq!(r.environment, env());
            assert_eq!(r.authority_generation, 1);
            assert_eq!(r.tombstones.len(), 1);
            assert_eq!(r.tombstones[0].generation, 1);
            assert_eq!(r.policy_revisions.len(), 1);
            assert!(r.certificates.is_empty());
            Ok(())
        })
        .unwrap();
    }
}
