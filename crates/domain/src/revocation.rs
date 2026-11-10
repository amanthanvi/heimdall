//! Revocation tombstones and results (spec §6.7; R-AU-04; plan §6.3 property 3).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DestinationId, GrantId, OperationId};
use serde::{Deserialize, Serialize};

use crate::operation::AdapterIdentity;
use crate::policy::AuthorityGeneration;

/// ⟨M03⟩ Wire-visible residual types (contract) re-exported here (ADR-0008 D7 item 3).
pub use heimdall_contract::managed::{ClockMeasurement, DestinationClock, ResidualStatus};

/// A remote effect that is not yet acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEffect {
    /// Destination concerned.
    pub destination: DestinationId,
    /// Grant concerned.
    pub grant: GrantId,
    /// Latest instant an already-issued credential may still be accepted there.
    pub latest_possible_credential_expiry: Option<Timestamp>,
}

/// Why a grant was revoked (ADR-0006 §13.8 item 4). Additive: a record written
/// before the field existed reads as [`RevocationCause::Revoke`], the only cause
/// there was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevocationCause {
    /// An explicit `revoke` (the owner, or a caller holding a binding on the grant).
    #[default]
    Revoke,
    /// Re-validation found the grant's authority withdrawn: a revoke on its chain,
    /// a narrowing outside its approval, or a removed environment permission.
    AuthorityWithdrawn,
    /// ⟨M03⟩ A `revoke_on_lock` grant revoked by a session lock (ADR-0008 D9; U0b
    /// row 25).
    SessionLocked,
}

/// Persisted before local success is acknowledged. Invalidates approval races,
/// renewals and retries against the previous generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Revoked grant.
    pub grant: GrantId,
    /// Descendants revoked by cascade.
    pub cascade: Vec<GrantId>,
    /// Generation after this revocation.
    pub generation: AuthorityGeneration,
    /// When applied locally.
    pub revoked_at: Timestamp,
    /// Remote effects still pending.
    pub remote_pending: Vec<RemoteEffect>,
    /// ⟨r2.5⟩ Why (ADR-0006 §13.8 item 4); `revoke` when absent from the record.
    #[serde(default)]
    pub cause: RevocationCause,
}

/// ⟨r2.7⟩ The remote part of a revocation that local denial left pending (spec
/// §6.7, §12.3; ADR-0006 §13.10 item 3), persisted per tombstoned root
/// (`heimdall_store::Txn::{set_remote_revocation, remote_revocation,
/// clear_remote_revocation, remote_revocations}`).
///
/// The record is the explicit evidence that keeps a `revoking` grant visibly
/// pending. Repeated adapter `revoke()` rounds for it follow the supervisor's
/// bounded, jittered backoff; `attempts` counts every round that called an adapter
/// (the first local denial included) and survives a restart, so the cap is never
/// reset by one. Once `stopped`, nothing calls the adapters for it again and
/// nothing is reported again until an explicit `revoke` covering the root (which
/// re-arms the schedule) or a round that finds nothing pending (which clears it).
///
/// ⟨r2.9⟩ ADR-0006 §13.12:
/// * **T01.** A round is *claimed* before any adapter is called, in its own
///   committed transaction: `attempts` is incremented and `claimed_at` recorded.
///   The completion clears `claimed_at`. A claimed round that never completed (a
///   crash, a failed completion commit) still counts, so no sequence of failures
///   yields more adapter calls than the cap.
/// * **T02.** `obligations` holds every unresolved remote obligation per
///   responsible adapter. A round asks only that adapter, and only its
///   confirmation clears the obligation; `grants` is the set of grants that still
///   have one. A record written before the field existed has `grants` alone and is
///   read with each grant's responsible adapter from its recovery intent and
///   receipts (`heimdall_store::Txn::grant_adapters`).
///
/// ⟨r2.10⟩ ADR-0006 §13.13:
/// * **Item 2.** Every pending answer of a responsible adapter is an obligation,
///   whatever the grant's state (a grant that ended before activation, e.g.
///   `preparing → revoked`, included): a call for a grant that is not `revoking` is
///   recorded as an obligation in the round's claim, before the call, and only its
///   adapter's confirmation clears it.
/// * **Item 3.** Attempts and the cap are counted per obligation
///   ([`RemoteObligation::attempts`], [`RemoteObligation::stopped`]); one adapter's
///   rounds never consume another's attempts. `attempts` here counts the rounds
///   claimed for the record as a whole (the schedule's round count). `stopped` is
///   set only when every obligation has reached its cap ([`Self::capped`]).
///
/// ⟨r2.14⟩ ADR-0006 §13.17: a credential effect applied for a covered grant after
/// its obligation stopped (or with no obligation for the applying adapter) re-arms
/// that obligation, or adds one, and clears `stopped`. `rearmed_effects` records
/// the effects that did so, which bounds the re-arms.
///
/// ⟨r2.15⟩ ADR-0006 §13.18:
/// * **Item 2.** A credential effect left to an obligation is recorded on it
///   ([`RemoteObligation::effect_round`]); only a round claimed after it clears it.
/// * **Item 3.** `cap` is the per-obligation cap of rounds in force when the record
///   was created or last re-armed. Recovery and the supervisor judge the record by
///   [`Self::round_cap`]: that cap, or the configured one when lower.
/// * **Item 4.** `rearmed_effects` is keyed by (grant, adapter, effect token,
///   recorded state).
///
/// ⟨r2.16⟩ ADR-0006 §13.19 item 1: every claim is identified by
/// [`Self::claim_seq`], which is persisted, increases with every claim and is never
/// reset (an explicit revoke's re-arm resets `attempts` only). `claimed_at` is
/// informational. A recorded effect stores the sequence current when it was recorded
/// ([`RemoteObligation::effect_seq`]), and only a completion whose claim is still the
/// current one and was made after it clears the obligation
/// ([`RemoteObligation::cleared_by_claim`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRemoteRevocation {
    /// The grant carrying the tombstone.
    pub root: GrantId,
    /// The root and the descendants its tombstone covers whose remote effect is
    /// still unresolved: exactly the grants named by `obligations` (when present).
    pub grants: Vec<GrantId>,
    /// Adapter `revoke()` rounds claimed so far for the record as a whole (a round
    /// that called no adapter, because no responsible adapter was configured or
    /// every served obligation was capped, is not counted). ⟨r2.10⟩ The cap applies
    /// per obligation ([`RemoteObligation::attempts`]); this count drives the
    /// supervisor's back-off. ⟨r2.16⟩ It no longer identifies a claim: an explicit
    /// revoke's re-arm restarts it ([`Self::claim_seq`] does, ADR-0006 §13.19 item 1).
    pub attempts: u32,
    /// When the last claimed round ran (or the record was created).
    pub last_attempt_at: Timestamp,
    /// The capped retries are exhausted: no further round until an explicit owner
    /// action or a new completion signal. ⟨r2.10⟩ Set only when every obligation
    /// left has reached its own cap. ⟨r2.14⟩ A credential effect applied late for a
    /// covered grant clears it too (ADR-0006 §13.17).
    pub stopped: bool,
    /// ⟨r2.9⟩ The unresolved obligations, one per grant and responsible adapter
    /// (ADR-0006 §13.12 item 2). Empty in a record written before §13.12 (read as
    /// described above); omitted from the record when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<RemoteObligation>,
    /// ⟨r2.9⟩ The instant of a claimed round whose completion has not been recorded
    /// (ADR-0006 §13.12 item 1); `None` once it completed. Omitted when absent.
    /// ⟨r2.16⟩ Informational: the claim is identified by [`Self::claim_seq`]
    /// (ADR-0006 §13.19 item 1); this only tells whether one is still open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<Timestamp>,
    /// ⟨r2.14⟩ ADR-0006 §13.17 item 4: the credential effects that already re-armed
    /// (or added) an obligation of this record, so replaying one never re-arms
    /// again. Kept while the record exists, also after the obligation it re-armed
    /// cleared. Omitted when empty, so a record written before the field reads
    /// unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rearmed_effects: Vec<RearmedEffect>,
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the per-obligation cap of rounds in force when
    /// the record was created or last re-armed. Absent in a record written before
    /// the field existed, which is judged by [`DEFAULT_ROUND_CAP`]
    /// ([`Self::round_cap`]). Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<u32>,
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: the sequence number of the record's latest
    /// claim (`0` before the first). Every claim raises it; nothing resets it. A
    /// claim's sequence comes from a store counter shared by every record
    /// (`heimdall_store::Txn::next_remote_claim_seq`), so it is never assigned twice,
    /// not even to a record created again for the same root after the previous one
    /// was removed. Absent in a record written before the field existed, which is read
    /// with a derived starting sequence ([`Self::migrate_claim_seq`]). Omitted when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_seq: Option<u64>,
}

/// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the cap of rounds that a record written before
/// [`PendingRemoteRevocation::cap`] existed is judged by. It equals the default
/// back-off's `max_attempts` (`heimdall_app::reconcile::Backoff::default()`), the cap
/// such a record was written under in production.
pub const DEFAULT_ROUND_CAP: u32 = 8;

/// ⟨r2.14⟩ ADR-0006 §13.17 item 4: one credential effect that re-armed (or added) an
/// obligation of a pending remote record, keyed by its effect token from the stage
/// receipts.
///
/// An effect counts once in each of the two states its receipts can record: possibly
/// applied (an `Attempted` or `Uncertain` receipt and no confirmation yet; for
/// example an operation cancelled while its preparation was still in flight) and
/// confirmed applied (a `Confirmed` receipt after it). The second state can arrive
/// after rounds that the first state re-armed have already been called, so it
/// re-arms once more. Each state re-arms at most once. An empty token stands for an
/// effect whose receipts are no longer on record.
///
/// ⟨r2.15⟩ ADR-0006 §13.18 item 4: the key also names the grant and the adapter the
/// effect re-armed an obligation for, so one grant's (or one adapter's) re-arm never
/// bounds another's effect. An entry written before those fields existed names
/// neither and matches no effect (it bounds nothing). An empty or unknown token is
/// never recorded and never bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RearmedEffect {
    /// ⟨r2.15⟩ The grant the effect was applied for. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantId>,
    /// ⟨r2.15⟩ The applying adapter whose obligation the effect re-armed or added.
    /// Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterIdentity>,
    /// The effect token of the attempt (`PrepareRequest.effect_token`).
    pub effect_token: String,
    /// `true` once a `Confirmed` receipt followed the attempt.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub confirmed: bool,
}

/// ⟨r2.9⟩ One unresolved remote obligation of a pending revocation (ADR-0006
/// §13.12 item 2): the remote effect of `grant` that `adapter` must confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteObligation {
    /// The grant concerned.
    pub grant: GrantId,
    /// The responsible adapter, from the grant's recovery intent and stage receipts.
    /// When those are gone (purged with their settled operation) it is the grant's
    /// recorded origin mechanism with an empty `instance` (any configured instance
    /// of that mechanism is responsible), and with no origin either both fields are
    /// empty (every configured adapter is responsible). Never another mechanism.
    pub adapter: AdapterIdentity,
    /// Why it is still pending, when not simply unconfirmed. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RemotePendingReason>,
    /// ⟨r2.10⟩ ADR-0006 §13.13 item 3: the rounds claimed that owed this obligation
    /// a call to its responsible adapter. Absent in a record written before the
    /// field existed: it is then read as the record's own `attempts`
    /// ([`PendingRemoteRevocation::obligation_attempts`]), conservatively, as the
    /// rounds of that record were already used. Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    /// ⟨r2.10⟩ This obligation reached its cap without a confirmation: no round
    /// calls its adapter again until an explicit owner action re-arms the record,
    /// or ⟨r2.14⟩ a credential effect its adapter applied late for the grant
    /// re-arms this obligation (ADR-0006 §13.17). Omitted when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stopped: bool,
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 2: the record's claimed-round count
    /// ([`PendingRemoteRevocation::attempts`]) when a credential effect for this grant
    /// was last left to this obligation: by a cleanup that skipped because it was
    /// live, or that re-armed or added it. A confirmation means "revoked as of the
    /// call", so only a round claimed after the effect (a greater count, and still
    /// the record's current claim) clears the obligation
    /// ([`Self::cleared_by_round`]). An explicit revoke that restarts the record's
    /// count sets it to `0`. Absent when no effect was recorded; omitted then.
    ///
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: superseded by [`Self::effect_seq`]. Read only
    /// from a record written before it; [`PendingRemoteRevocation::migrate_claim_seq`]
    /// turns it into an `effect_seq`, conservatively, and clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_round: Option<u32>,
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: the record's
    /// [`PendingRemoteRevocation::claim_seq`] when a credential effect for this grant
    /// was last left to this obligation (a cleanup that skipped because it was live,
    /// or that re-armed or added it). Only a completion whose claim is still the
    /// record's current one and has a greater sequence clears the obligation
    /// ([`Self::cleared_by_claim`]). Absent when no effect was recorded; omitted then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_seq: Option<u64>,
    /// ⟨M03⟩ What settles the obligation (ADR-0008 D7 item 3; U0b row 6). Absent
    /// (an M01/M02 record) reads as [`ObligationKind::NeedsRemoteAction`]; omitted
    /// when it is that, so such records re-encode unchanged.
    #[serde(
        default,
        skip_serializing_if = "ObligationKind::is_needs_remote_action"
    )]
    pub kind: ObligationKind,
}

/// ⟨M03⟩ What settles a remote obligation (ADR-0008 D7 item 3; §17.1 item 10).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ObligationKind {
    /// An adapter must confirm a remote action (M01/M02; the cap and backoff of
    /// ADR-0006 §13.12–§13.19 apply). The default.
    #[default]
    NeedsRemoteAction,
    /// Settled by the issued certificates' expiry, with no adapter call and no
    /// attempt counted (managed certificates; B1 has no remote revocation action).
    BoundedByExpiry {
        /// The latest `valid_before` of a reserved or published entry.
        latest_valid_before: Timestamp,
        /// The pair's destination clock measurement (or `unmeasured`). A
        /// measurement older than the verification freshness is recorded as
        /// `unmeasured` by whoever builds the obligation (ADR-0008 D5 §6.5 item 4).
        clock: DestinationClock,
        /// The last computed status ([`residual_step`]).
        status: ResidualStatus,
    },
}

impl ObligationKind {
    /// Whether this is the default kind.
    #[must_use]
    pub fn is_needs_remote_action(&self) -> bool {
        matches!(self, ObligationKind::NeedsRemoteAction)
    }
}

/// ⟨M03⟩ The drift allowance of ADR-0008 §17.1 item 10, in parts per million of the
/// measurement's age (`residual_drift_ppm`).
pub const RESIDUAL_DRIFT_PPM: u64 = 100;

/// ⟨M03⟩ ADR-0008 D7 item 3: the instant a measured residual completes when
/// evaluated at `now`: `latest_valid_before + behind_upper + rtt + 100 ppm × (now −
/// measured_at)` (the drift rounded up to the millisecond; a negative age counts as
/// zero). `None` on overflow (callers then treat the bound as not passed).
#[must_use]
pub fn measured_completion_bound(
    latest_valid_before: Timestamp,
    clock: &ClockMeasurement,
    now: Timestamp,
) -> Option<Timestamp> {
    let age_ms = now.duration_since(clock.measured_at).as_millis().max(0);
    let age_ms = u64::try_from(age_ms).ok()?;
    let drift_ms = age_ms.checked_mul(RESIDUAL_DRIFT_PPM)?.div_ceil(1_000_000);
    let total = clock
        .behind_upper_ms
        .checked_add(clock.rtt_ms)?
        .checked_add(drift_ms)?;
    let total = i64::try_from(total).ok()?;
    latest_valid_before
        .checked_add(jiff::SignedDuration::from_millis(total))
        .ok()
}

/// ⟨M03⟩ ADR-0008 D7 item 3 (§17.1 item 10; U0b row 6): the next status of a remote
/// obligation, computed by the supervisor's revocation pass with no adapter call.
///
/// `safe_now` is the domain's stand-in for the application's `SafeNow`: `Some(wall)`
/// only when the time gate is `Safe` (that wall time), `None` when time is
/// uncertain. **Nothing moves on uncertain time** (fail closed).
///
/// * `needs_remote_action`: not time-driven (adapter rounds settle it): always
///   `pending_until`.
/// * `bounded_by_expiry`, measured clock: `bounded_complete` once
///   [`measured_completion_bound`] has passed on safe time.
/// * `bounded_by_expiry`, unmeasured: `nominally_expired` once
///   `latest_valid_before` has passed on safe time. It never becomes
///   `bounded_complete` (it is never shown as cleared).
/// * `bounded_complete`, `nominally_expired` and `unbounded_unknown` never change.
#[must_use]
pub fn residual_step(obligation: &RemoteObligation, safe_now: Option<Timestamp>) -> ResidualStatus {
    let ObligationKind::BoundedByExpiry {
        latest_valid_before,
        clock,
        status,
    } = &obligation.kind
    else {
        return ResidualStatus::PendingUntil;
    };
    if *status != ResidualStatus::PendingUntil {
        return *status;
    }
    let Some(now) = safe_now else {
        return ResidualStatus::PendingUntil;
    };
    match clock {
        DestinationClock::Measured(m) => {
            match measured_completion_bound(*latest_valid_before, m, now) {
                Some(bound) if now >= bound => ResidualStatus::BoundedComplete,
                _ => ResidualStatus::PendingUntil,
            }
        }
        DestinationClock::Unmeasured => {
            if now >= *latest_valid_before {
                ResidualStatus::NominallyExpired
            } else {
                ResidualStatus::PendingUntil
            }
        }
        // A clock form this build does not know never completes anything.
        _ => ResidualStatus::PendingUntil,
    }
}

impl PendingRemoteRevocation {
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the cap of rounds this record is judged by:
    /// its own [`Self::cap`] ([`DEFAULT_ROUND_CAP`] for a record written before the
    /// field), or `configured` when that is lower (fail closed). Pass `u32::MAX` when
    /// no cap is configured.
    #[must_use]
    pub fn round_cap(&self, configured: u32) -> u32 {
        self.cap.unwrap_or(DEFAULT_ROUND_CAP).min(configured)
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: the sequence number of the record's latest
    /// claim: [`Self::claim_seq`], or for a record written before it, the record's
    /// claimed-round count (`attempts`), the starting sequence such a record is read
    /// with.
    #[must_use]
    pub fn current_claim_seq(&self) -> u64 {
        self.claim_seq.unwrap_or(u64::from(self.attempts))
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: read a record written before
    /// [`Self::claim_seq`] existed in the current form, once, when it is loaded.
    ///
    /// * Its sequence starts at its claimed-round count ([`Self::current_claim_seq`]).
    ///   A claim it carries came from a process that is gone, so no completion can
    ///   name it, and every claim from now on gets a greater sequence.
    /// * An effect it records ([`RemoteObligation::effect_round`]) becomes an
    ///   [`RemoteObligation::effect_seq`] at that starting sequence: conservatively,
    ///   as recorded at the latest claim, so only a claim made after this load clears
    ///   it. The round is cleared.
    ///
    /// A record in the current form is unchanged.
    pub fn migrate_claim_seq(&mut self) {
        let seq = self.current_claim_seq();
        self.claim_seq = Some(seq);
        for o in &mut self.obligations {
            if o.effect_round.take().is_some() && o.effect_seq.is_none() {
                o.effect_seq = Some(seq);
            }
        }
    }

    /// ⟨r2.10⟩ ADR-0006 §13.13 item 3: the attempts counted for `obligation`: its
    /// own count, or for an obligation recorded before per-obligation counts
    /// existed, the record's `attempts` (conservative: every earlier round of the
    /// record counts against it).
    #[must_use]
    pub fn obligation_attempts(&self, obligation: &RemoteObligation) -> u32 {
        obligation.attempts.unwrap_or(self.attempts)
    }

    /// ⟨r2.10⟩ ADR-0006 §13.13 item 3: whether `obligation` reached its cap of
    /// `max_attempts` rounds (or was stopped there).
    #[must_use]
    pub fn obligation_capped(&self, obligation: &RemoteObligation, max_attempts: u32) -> bool {
        obligation.stopped || self.obligation_attempts(obligation) >= max_attempts
    }

    /// ⟨r2.10⟩ ADR-0006 §13.13 item 3: whether every obligation left reached its
    /// cap, so no round can call any adapter for this record any more. A record
    /// written before obligations existed (grant list only) is judged on its own
    /// `attempts`.
    #[must_use]
    pub fn capped(&self, max_attempts: u32) -> bool {
        if self.obligations.is_empty() {
            return self.attempts >= max_attempts;
        }
        self.obligations
            .iter()
            .all(|o| self.obligation_capped(o, max_attempts))
    }
}

/// ⟨r2.16⟩ ADR-0006 §13.19 item 2: a recoverable **cleanup intent**. A credential
/// effect was applied (or may have been) for `grant` by the attempt of `operation`,
/// and the transaction that settled the operation could not leave the revocation
/// call to a covering obligation: the call must be made later (the immediate call
/// for a grant no record covers, or a bounded call, §13.18 item 4), or the attempt
/// may still be in flight, so an obligation that owns the call now could be cleared
/// by a call made before the effect lands.
///
/// It is written in that settling transaction and persisted per (grant, operation)
/// (`heimdall_store::Txn::{record_cleanup_intent, cleanup_intent,
/// clear_cleanup_intent, cleanup_intents}`). Restart recovery and every supervisor
/// pass process it, whatever the operation's state, and it is removed only once a
/// call was made after the effect or a covering obligation owns the call. It names
/// the effect itself (its adapter, token and recorded state), so it outlives the
/// operation's receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupIntent {
    /// The grant the effect was applied for.
    pub grant: GrantId,
    /// The operation whose attempt applied it (whose receipts record it).
    pub operation: OperationId,
    /// The adapter the attempt asked; `None` when no attempt is on record (the
    /// grant's responsible adapters apply it). Omitted when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterIdentity>,
    /// The attempt's effect token (`PrepareRequest.effect_token`); empty when unknown.
    /// Omitted when empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub effect_token: String,
    /// `true` once a `Confirmed` receipt followed the attempt. Omitted when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub confirmed: bool,
    /// The attempt had no answer yet when the intent was written (its last receipt
    /// is `Attempted`): its preparation may still be in flight. While this process
    /// still runs that preparation, only its own return path processes the intent.
    /// Omitted when `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_flight: bool,
    /// Identifies this write: assigned by the store from a counter that only
    /// increases, so a processor removes the intent only if it is still the one it
    /// processed.
    pub version: u64,
    /// When it was written.
    pub recorded_at: Timestamp,
}

/// ⟨r2.9⟩ Why a remote obligation is still pending (ADR-0006 §13.12 item 2). Wire
/// form snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemotePendingReason {
    /// The responsible adapter is not configured in this runtime: the last round
    /// could not ask it (and consumed no attempt).
    AdapterUnavailable,
}

impl RemoteObligation {
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1 (replaces the §13.18 item 2 round rule): whether
    /// a confirmation from the completion of a claim clears this obligation.
    /// `current` is that claim's [`PendingRemoteRevocation::claim_seq`] when it is
    /// still the record's current claim, and `None` when it was superseded. Only a
    /// current claim clears, and only one made after the obligation's recorded
    /// effect ([`Self::effect_seq`]): a confirmation means "revoked as of the call".
    /// A superseded completion never clears an obligation.
    #[must_use]
    pub fn cleared_by_claim(&self, current: Option<u64>) -> bool {
        current.is_some_and(|n| self.effect_seq.is_none_or(|effect| n > effect))
    }

    /// Whether a configured adapter with identity `configured` is responsible for
    /// this obligation: the recorded identity exactly, or, for an obligation whose
    /// instance (or whole identity) could not be recorded, any instance of its
    /// mechanism (or any adapter).
    #[must_use]
    pub fn served_by(&self, configured: &AdapterIdentity) -> bool {
        if self.adapter.instance.is_empty() {
            self.adapter.mechanism.is_empty() || self.adapter.mechanism == configured.mechanism
        } else {
            &self.adapter == configured
        }
    }
}

/// Whether an action authorized at `authorized_generation` may still proceed
/// against the current generation. Stale callbacks fail closed.
#[must_use]
pub fn generation_still_valid(
    authorized_generation: AuthorityGeneration,
    current: AuthorityGeneration,
) -> bool {
    authorized_generation == current
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_record_without_a_cause_reads_as_an_explicit_revoke() {
        let old = serde_json::json!({
            "grant": GrantId::from_random_bytes([1; 16]),
            "cascade": [],
            "generation": 3,
            "revoked_at": "2026-10-02T09:00:00Z",
            "remote_pending": [],
        });
        let t: Tombstone = serde_json::from_value(old).unwrap();
        assert_eq!(t.cause, RevocationCause::Revoke);
        let withdrawn = Tombstone {
            cause: RevocationCause::AuthorityWithdrawn,
            ..t
        };
        let v = serde_json::to_value(&withdrawn).unwrap();
        assert_eq!(v["cause"], "authority_withdrawn");
        assert_eq!(serde_json::from_value::<Tombstone>(v).unwrap(), withdrawn);
    }

    /// ⟨r2.9⟩ ADR-0006 §13.12: a pending record written before obligations and
    /// claims existed reads with neither; the new fields round-trip and are omitted
    /// when empty; the reason's wire form is snake_case.
    #[test]
    fn a_pending_record_without_obligations_reads_unchanged() {
        let g = GrantId::from_random_bytes([2; 16]);
        let old = serde_json::json!({
            "root": g,
            "grants": [g],
            "attempts": 3,
            "last_attempt_at": "2026-10-02T09:00:00Z",
            "stopped": false,
        });
        let r: PendingRemoteRevocation = serde_json::from_value(old.clone()).unwrap();
        assert!(r.obligations.is_empty());
        assert_eq!(r.claimed_at, None);
        assert_eq!(r.attempts, 3);
        assert_eq!(serde_json::to_value(&r).unwrap(), old, "omitted when empty");
        let adapter = AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        };
        let with = PendingRemoteRevocation {
            obligations: vec![RemoteObligation {
                grant: g.clone(),
                adapter: adapter.clone(),
                reason: Some(RemotePendingReason::AdapterUnavailable),
                attempts: None,
                stopped: false,
                effect_round: None,
                effect_seq: None,
                kind: Default::default(),
            }],
            claimed_at: Some("2026-10-02T09:00:01Z".parse().unwrap()),
            ..r
        };
        assert!(with.rearmed_effects.is_empty());
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["obligations"][0]["reason"], "adapter_unavailable");
        assert_eq!(v["obligations"][0]["adapter"]["instance"], "fixture-1");
        assert_eq!(v["claimed_at"], "2026-10-02T09:00:01Z");
        assert!(v.get("rearmed_effects").is_none(), "omitted when empty");
        assert_eq!(
            serde_json::from_value::<PendingRemoteRevocation>(v).unwrap(),
            with
        );
    }

    /// ⟨r2.9⟩ Only the recorded adapter serves an obligation; an obligation recorded
    /// by mechanism only is served by any instance of that mechanism, never by
    /// another mechanism.
    #[test]
    fn only_the_responsible_adapter_serves_an_obligation() {
        let id = |m: &str, i: &str| AdapterIdentity {
            mechanism: m.into(),
            instance: i.into(),
        };
        let o = |a: AdapterIdentity| RemoteObligation {
            grant: GrantId::from_random_bytes([3; 16]),
            adapter: a,
            reason: None,
            attempts: None,
            stopped: false,
            effect_round: None,
            effect_seq: None,
            kind: Default::default(),
        };
        let exact = o(id("fake_agent", "fixture-1"));
        assert!(exact.served_by(&id("fake_agent", "fixture-1")));
        assert!(!exact.served_by(&id("fake_agent", "fixture-9")));
        assert!(!exact.served_by(&id("fake_other", "fixture-1")));
        let by_mechanism = o(id("fake_agent", ""));
        assert!(by_mechanism.served_by(&id("fake_agent", "fixture-9")));
        assert!(!by_mechanism.served_by(&id("fake_other", "fixture-1")));
        assert!(o(id("", "")).served_by(&id("fake_other", "x")));
    }

    /// ⟨r2.10⟩ ADR-0006 §13.13 item 3: an obligation without its own count (a
    /// record written before per-obligation counts) reads the record's count
    /// conservatively; the new fields round-trip and are omitted when unset; the
    /// record is capped only when every obligation reached its cap.
    #[test]
    fn obligation_attempts_map_a_record_count_conservatively_and_cap_per_obligation() {
        let g = GrantId::from_random_bytes([4; 16]);
        let a = AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        };
        let b = AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-2".into(),
        };
        let legacy = serde_json::json!({
            "root": g,
            "grants": [g],
            "attempts": 3,
            "last_attempt_at": "2026-10-02T09:00:00Z",
            "stopped": false,
            "obligations": [{"grant": g, "adapter": a}],
        });
        let r: PendingRemoteRevocation = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(r.obligations[0].attempts, None);
        assert!(!r.obligations[0].stopped);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            legacy,
            "omitted when unset"
        );
        assert_eq!(
            r.obligation_attempts(&r.obligations[0]),
            3,
            "the record's count"
        );
        assert!(r.capped(3));
        assert!(!r.capped(4));
        let two = PendingRemoteRevocation {
            obligations: vec![
                RemoteObligation {
                    grant: g.clone(),
                    adapter: a,
                    reason: Some(RemotePendingReason::AdapterUnavailable),
                    attempts: Some(0),
                    stopped: false,
                    effect_round: None,
                    effect_seq: None,
                    kind: Default::default(),
                },
                RemoteObligation {
                    grant: g.clone(),
                    adapter: b,
                    reason: None,
                    attempts: Some(3),
                    stopped: true,
                    effect_round: None,
                    effect_seq: None,
                    kind: Default::default(),
                },
            ],
            ..r
        };
        let v = serde_json::to_value(&two).unwrap();
        assert_eq!(v["obligations"][0]["attempts"], 0);
        assert!(v["obligations"][0].get("stopped").is_none());
        assert_eq!(v["obligations"][1]["attempts"], 3);
        assert_eq!(v["obligations"][1]["stopped"], true);
        assert_eq!(
            serde_json::from_value::<PendingRemoteRevocation>(v).unwrap(),
            two
        );
        assert!(!two.capped(3), "the waiting obligation has its full cap");
        assert!(
            two.obligation_capped(&two.obligations[1], 99),
            "stopped stays stopped"
        );
        assert!(!two.obligation_capped(&two.obligations[0], 1));
    }

    /// ⟨r2.14⟩ ADR-0006 §13.17 item 4: the effects that re-armed a record round-trip
    /// (a possibly applied one without `confirmed`, a confirmed one with it); a
    /// record without the field reads with none.
    #[test]
    fn rearmed_effects_round_trip_and_default_to_none() {
        let g = GrantId::from_random_bytes([5; 16]);
        let old = serde_json::json!({
            "root": g,
            "grants": [g],
            "attempts": 1,
            "last_attempt_at": "2026-10-02T09:00:00Z",
            "stopped": true,
        });
        let r: PendingRemoteRevocation = serde_json::from_value(old).unwrap();
        assert!(r.rearmed_effects.is_empty());
        let with = PendingRemoteRevocation {
            rearmed_effects: vec![
                RearmedEffect {
                    grant: None,
                    adapter: None,
                    effect_token: "eff_01".into(),
                    confirmed: false,
                },
                RearmedEffect {
                    grant: None,
                    adapter: None,
                    effect_token: "eff_01".into(),
                    confirmed: true,
                },
            ],
            ..r
        };
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(
            v["rearmed_effects"],
            serde_json::json!([
                {"effect_token": "eff_01"},
                {"effect_token": "eff_01", "confirmed": true},
            ])
        );
        assert_eq!(
            serde_json::from_value::<PendingRemoteRevocation>(v).unwrap(),
            with
        );
    }

    /// ⟨r2.15⟩ ADR-0006 §13.18: a record written at 8d17ace9 (no cap, no effect
    /// round, re-armed effects keyed by token and state alone) reads unchanged with
    /// none of the new fields, and serializes back to the same form; the new fields
    /// round-trip and are omitted when absent.
    #[test]
    fn r1318_a_record_without_the_new_fields_reads_unchanged() {
        let g = GrantId::from_random_bytes([6; 16]);
        let adapter = AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        };
        let old = serde_json::json!({
            "root": g,
            "grants": [g],
            "attempts": 2,
            "last_attempt_at": "2026-10-02T09:00:00Z",
            "stopped": false,
            "obligations": [{"grant": g, "adapter": adapter, "attempts": 2}],
            "rearmed_effects": [{"effect_token": "eff_01", "confirmed": true}],
        });
        let r: PendingRemoteRevocation = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(r.cap, None);
        assert_eq!(r.obligations[0].effect_round, None);
        assert_eq!(r.rearmed_effects[0].grant, None);
        assert_eq!(r.rearmed_effects[0].adapter, None);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            old,
            "omitted when absent"
        );
        let mut with = r;
        with.cap = Some(3);
        with.obligations[0].effect_round = Some(2);
        with.rearmed_effects[0].grant = Some(g.clone());
        with.rearmed_effects[0].adapter = Some(adapter.clone());
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["cap"], 3);
        assert_eq!(v["obligations"][0]["effect_round"], 2);
        assert_eq!(v["rearmed_effects"][0]["grant"], serde_json::json!(g));
        assert_eq!(v["rearmed_effects"][0]["adapter"]["instance"], "fixture-1");
        assert_eq!(
            serde_json::from_value::<PendingRemoteRevocation>(v).unwrap(),
            with
        );
    }

    /// ⟨r2.15⟩ ADR-0006 §13.18 item 3: a record is judged by its own cap, or by the
    /// configured cap when that is lower; a record without one by the default cap.
    #[test]
    fn r1318_a_record_is_judged_by_the_lower_of_its_cap_and_the_configured_one() {
        let g = GrantId::from_random_bytes([7; 16]);
        let mut r: PendingRemoteRevocation = serde_json::from_value(serde_json::json!({
            "root": g,
            "grants": [g],
            "attempts": 0,
            "last_attempt_at": "2026-10-02T09:00:00Z",
            "stopped": false,
        }))
        .unwrap();
        assert_eq!(
            r.round_cap(u32::MAX),
            DEFAULT_ROUND_CAP,
            "no cap: the default"
        );
        assert_eq!(r.round_cap(3), 3);
        assert_eq!(r.round_cap(20), DEFAULT_ROUND_CAP);
        r.cap = Some(3);
        assert_eq!(r.round_cap(u32::MAX), 3, "none configured: its own");
        assert_eq!(r.round_cap(8), 3, "its own when lower");
        assert_eq!(r.round_cap(2), 2, "the configured one when lower");
    }

    /// ⟨r2.15⟩ ADR-0006 §13.18 item 2, ⟨r2.16⟩ as amended by §13.19 item 1 (claims
    /// identified by their sequence, not their round count): with no effect recorded
    /// any current confirming claim clears an obligation; with one, only a current
    /// claim made after it. A superseded claim clears nothing.
    #[test]
    fn r1318_only_a_round_claimed_after_the_effect_clears_it() {
        let mut o = RemoteObligation {
            grant: GrantId::from_random_bytes([8; 16]),
            adapter: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            },
            reason: None,
            attempts: Some(2),
            stopped: false,
            effect_round: None,
            effect_seq: None,
            kind: Default::default(),
        };
        assert!(o.cleared_by_claim(Some(1)));
        assert!(
            !o.cleared_by_claim(None),
            "a superseded claim clears nothing"
        );
        o.effect_seq = Some(2);
        assert!(!o.cleared_by_claim(Some(1)), "claimed before the effect");
        assert!(
            !o.cleared_by_claim(Some(2)),
            "in flight when the effect landed"
        );
        assert!(o.cleared_by_claim(Some(3)), "claimed after it");
        assert!(
            !o.cleared_by_claim(None),
            "a superseded claim: order unknown"
        );
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: a record written before claim sequences
    /// existed is read with its claimed-round count as its sequence, and an effect it
    /// recorded by round becomes an effect at that sequence (conservatively: only a
    /// claim made from now on clears it). A record in the current form is unchanged;
    /// the new fields round-trip and are omitted when absent.
    #[test]
    fn r1319_a_record_without_claim_seq_reads_with_a_derived_sequence() {
        let g = GrantId::from_random_bytes([9; 16]);
        let adapter = AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        };
        let old = serde_json::json!({
            "root": g,
            "grants": [g],
            "attempts": 3,
            "last_attempt_at": "2026-10-02T09:00:00Z",
            "stopped": false,
            "claimed_at": "2026-10-02T09:00:01Z",
            "obligations": [
                {"grant": g, "adapter": adapter, "attempts": 3, "effect_round": 1},
                {"grant": g, "adapter": {"mechanism": "fake_other", "instance": "2"},
                 "attempts": 3},
            ],
        });
        let mut r: PendingRemoteRevocation = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(r.claim_seq, None);
        assert_eq!(r.obligations[0].effect_seq, None);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            old,
            "omitted when absent"
        );
        assert_eq!(r.current_claim_seq(), 3, "the derived starting sequence");
        r.migrate_claim_seq();
        assert_eq!(r.claim_seq, Some(3));
        assert_eq!(r.obligations[0].effect_round, None, "the round is cleared");
        assert_eq!(
            r.obligations[0].effect_seq,
            Some(3),
            "conservatively at the latest claim"
        );
        assert_eq!(r.obligations[1].effect_seq, None, "no effect, none made up");
        assert!(!r.obligations[0].cleared_by_claim(Some(3)));
        assert!(r.obligations[0].cleared_by_claim(Some(4)));
        let current = r.clone();
        r.migrate_claim_seq();
        assert_eq!(r, current, "a record in the current form is unchanged");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["claim_seq"], 3);
        assert_eq!(v["obligations"][0]["effect_seq"], 3);
        assert!(v["obligations"][0].get("effect_round").is_none());
        assert_eq!(
            serde_json::from_value::<PendingRemoteRevocation>(v).unwrap(),
            r
        );
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: a cleanup intent round-trips; its optional
    /// parts are omitted when absent.
    #[test]
    fn r1319_a_cleanup_intent_round_trips() {
        let intent = CleanupIntent {
            grant: GrantId::from_random_bytes([10; 16]),
            operation: OperationId::from_random_bytes([11; 16]),
            adapter: None,
            effect_token: String::new(),
            confirmed: false,
            in_flight: false,
            version: 7,
            recorded_at: "2026-10-02T09:00:00Z".parse().unwrap(),
        };
        let v = serde_json::to_value(&intent).unwrap();
        for absent in ["adapter", "effect_token", "confirmed", "in_flight"] {
            assert!(v.get(absent).is_none(), "{absent} omitted");
        }
        assert_eq!(serde_json::from_value::<CleanupIntent>(v).unwrap(), intent);
        let full = CleanupIntent {
            adapter: Some(AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            }),
            effect_token: "eff_01".into(),
            confirmed: true,
            in_flight: true,
            ..intent
        };
        let v = serde_json::to_value(&full).unwrap();
        assert_eq!(v["effect_token"], "eff_01");
        assert_eq!(v["in_flight"], true);
        assert_eq!(serde_json::from_value::<CleanupIntent>(v).unwrap(), full);
    }

    #[test]
    fn stale_generation_fails_closed() {
        let g1 = AuthorityGeneration(1);
        assert!(generation_still_valid(g1, g1));
        assert!(!generation_still_valid(g1, g1.next()));
    }
}
