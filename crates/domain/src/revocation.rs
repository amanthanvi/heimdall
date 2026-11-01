//! Revocation tombstones and results (spec §6.7; R-AU-04; plan §6.3 property 3).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DestinationId, GrantId};
use serde::{Deserialize, Serialize};

use crate::operation::AdapterIdentity;
use crate::policy::AuthorityGeneration;

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
    /// supervisor's back-off and identifies a claim.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_round: Option<u32>,
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
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 2: whether a confirmation from a round whose
    /// claim counted `round` (the record's claimed-round count it set) clears this
    /// obligation. With no effect recorded, any confirming round does. With one,
    /// only a round claimed after it does. `None` stands for a round that is no
    /// longer the record's current claim (an explicit revoke restarted the count
    /// since), whose order against the effect is unknown: it clears only an
    /// obligation with no effect recorded.
    #[must_use]
    pub fn cleared_by_round(&self, round: Option<u32>) -> bool {
        match self.effect_round {
            None => true,
            Some(effect) => round.is_some_and(|n| n > effect),
        }
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
                },
                RemoteObligation {
                    grant: g.clone(),
                    adapter: b,
                    reason: None,
                    attempts: Some(3),
                    stopped: true,
                    effect_round: None,
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

    /// ⟨r2.15⟩ ADR-0006 §13.18 item 2: with no effect recorded any confirming round
    /// clears an obligation; with one, only a current round claimed after it.
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
        };
        assert!(o.cleared_by_round(Some(1)));
        assert!(o.cleared_by_round(None), "nothing to order against");
        o.effect_round = Some(2);
        assert!(!o.cleared_by_round(Some(1)), "claimed before the effect");
        assert!(
            !o.cleared_by_round(Some(2)),
            "in flight when the effect landed"
        );
        assert!(o.cleared_by_round(Some(3)), "claimed after it");
        assert!(
            !o.cleared_by_round(None),
            "a superseded claim: order unknown"
        );
        o.effect_round = Some(0);
        assert!(
            o.cleared_by_round(Some(1)),
            "after an explicit revoke's restart"
        );
    }

    #[test]
    fn stale_generation_fails_closed() {
        let g1 = AuthorityGeneration(1);
        assert!(generation_still_valid(g1, g1));
        assert!(!generation_still_valid(g1, g1.next()));
    }
}
