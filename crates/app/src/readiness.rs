//! ⟨M06 U3⟩ A runner binding's readiness (ADR-0012 §4.5, §7.3; ADR-0005 §3.6 "Runner
//! deadline", §7.2's runner shape; ADR-0006 §18.5 reading 14). Pure: the caller reads the
//! store, the runner's time state and the lifetime probe, and this module computes the fields.
//!
//! * **`offline_until`** is the **earliest** of the runner's derived continuous-clock anchor
//!   (projected onto the runner's wall clock), the grant's deadline, the inherited or parent
//!   deadline, the cutoff and the installed certificates' earliest `valid_before`. No new cap
//!   (ADR-0012 §12 Q9). Without a qualifying time sample in this boot there is no derived
//!   anchor: time is uncertain ([`RunnerTime::Uncertain`]) and the bound is the credential's
//!   own (ADR-0005 §3.6: "new authentication stays bounded only by the server's
//!   `valid_before`").
//! * **`refresh_dependency`** is the controller's issuer (K_env lives only in the runner's
//!   memory: a restart needs a re-issue; ADR-0005 §3.7). The contract's value for it is
//!   `controller`.
//! * **Conditions:** the runner's lifetime, its time bound and the process not restarting.
//! * **Residuals** (ADR-0012 §7.3), per component: new authentication until the counted
//!   issuance history's `latest_possible_credential_expiry` **plus** the destination clock's
//!   error, `unmeasured` when no measurement exists, so the residual is never a bare deadline
//!   ([`residual_end`]); owned dedicated sessions and owned admissions closed on an applied
//!   revoke; other live sessions `unknown` (the G09 table); detached remote processes not
//!   ended. A runner without the counted history (it sees only what it installed) reports the
//!   expiry `unknown`.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::managed::{
    AuthenticationResidual, ComponentResidual, DestinationClock, ReadinessCondition,
    RefreshCondition, RefreshTrigger, RevocationResiduals,
};
use heimdall_contract::remote::RunnerLifetime;
use heimdall_contract::request::{EnsureData, RefreshDependency};
use heimdall_domain::time::{GrantAnchor, TimeAnchor};

/// Everything a runner binding's readiness is computed from.
#[derive(Debug, Clone)]
pub struct RunnerReadinessInput<'a> {
    /// The runner's observation now.
    pub now: &'a TimeAnchor,
    /// The grant's immutable deadline (D).
    pub deadline: Timestamp,
    /// The inherited or parent deadline (the earliest ancestor's), if any.
    pub parent_deadline: Option<Timestamp>,
    /// The effective cutoff, if any.
    pub cutoff: Option<Timestamp>,
    /// The grant's runner anchor (its budget shortened by every qualifying time sample).
    pub anchor: Option<&'a GrantAnchor>,
    /// Whether a qualifying time sample bounds the runner's offset in this boot (ADR-0012
    /// §4.4).
    pub time_bounded: bool,
    /// The earliest `valid_before` among the grant's installed certificates.
    pub certificate_valid_before: Option<Timestamp>,
    /// The weakest destination clock of the grant's pairs.
    pub destination_clock: DestinationClock,
    /// The latest `valid_before` of the grant's counted issuance history (reserved and
    /// published entries), when that history is known; `None` reads `unknown`.
    pub counted_expiry: Option<Timestamp>,
    /// The runner runtime's lifetime.
    pub lifetime: RunnerLifetime,
}

/// Whether the runner's time is bounded (ADR-0012 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerTime {
    /// A qualifying sample bounds the offset; the derived anchor applies.
    Bounded,
    /// No qualifying sample in this boot (`TIME_UNCERTAIN`): no owned-connection deadline
    /// admission; new authentication is bounded by `valid_before` only.
    Uncertain,
}

/// Which bound `offline_until` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfflineBound {
    /// The runner's derived continuous-clock anchor.
    Anchor,
    /// The grant's deadline.
    Deadline,
    /// The inherited or parent deadline.
    ParentDeadline,
    /// The cutoff.
    Cutoff,
    /// The certificates' `valid_before`.
    CertificateValidBefore,
}

/// A runner binding's readiness fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerReadiness {
    /// Usable with no controller or issuer contact until.
    pub offline_until: Timestamp,
    /// Which bound that is.
    pub bound_by: OfflineBound,
    /// Credentials usable without refresh until (the same instant on a runner).
    pub usable_until: Timestamp,
    /// The time state behind it.
    pub time: RunnerTime,
    /// What ongoing readiness depends on: the controller's issuer.
    pub refresh_dependency: RefreshDependency,
    /// When a refresh is needed: only after a signer restart, from the controller.
    pub refresh_condition: RefreshCondition,
    /// The conditions it depends on, sorted.
    pub conditions: Vec<ReadinessCondition>,
    /// The runner's lifetime (reported in the environment view).
    pub lifetime: RunnerLifetime,
    /// The per-component residuals.
    pub residuals: RevocationResiduals,
}

/// The runner's derived anchor on its own wall clock: `now.wall + (budget_end −
/// now.continuous)`, or `None` when the anchor belongs to another boot (void, ADR-0005 §3.6).
#[must_use]
pub fn anchor_end(anchor: &GrantAnchor, now: &TimeAnchor) -> Option<Timestamp> {
    if anchor.anchor.boot_id != now.boot_id {
        return None;
    }
    let left = anchor.budget_end.saturating_sub(now.continuous);
    let left = jiff::SignedDuration::try_from(left).unwrap_or(jiff::SignedDuration::MAX);
    Some(now.wall.checked_add(left).unwrap_or(Timestamp::MAX))
}

/// The new-authentication residual (ADR-0012 §7.3): the counted history's expiry with the
/// destination clock's error, always stated.
#[must_use]
pub fn authentication_residual(
    counted_expiry: Option<Timestamp>,
    destination_clock: DestinationClock,
) -> AuthenticationResidual {
    AuthenticationResidual {
        latest_possible_credential_expiry: counted_expiry,
        destination_clock_error: destination_clock,
    }
}

/// When new authentication may last be accepted, as the residual states it. Never a bare
/// deadline: an unmeasured clock error is part of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualEnd {
    /// No counted history: unknown.
    Unknown,
    /// Until `valid_before` plus the measured lag bound: at most this instant.
    AtMost(Timestamp),
    /// Until `valid_before` plus an **unmeasured** destination-clock error: no finite bound in
    /// Heimdall's evidence.
    PlusUnmeasuredClockError(Timestamp),
}

/// [`ResidualEnd`] of a residual.
#[must_use]
pub fn residual_end(residual: &AuthenticationResidual) -> ResidualEnd {
    let Some(expiry) = residual.latest_possible_credential_expiry else {
        return ResidualEnd::Unknown;
    };
    match residual.destination_clock_error {
        DestinationClock::Measured(m) => {
            let lag = jiff::SignedDuration::try_from(Duration::from_millis(m.behind_upper_ms))
                .unwrap_or(jiff::SignedDuration::MAX);
            ResidualEnd::AtMost(expiry.checked_add(lag).unwrap_or(Timestamp::MAX))
        }
        _ => ResidualEnd::PlusUnmeasuredClockError(expiry),
    }
}

/// A runner binding's residuals (module docs).
#[must_use]
pub fn runner_residuals(
    counted_expiry: Option<Timestamp>,
    destination_clock: DestinationClock,
) -> RevocationResiduals {
    RevocationResiduals {
        new_authentication: Some(authentication_residual(counted_expiry, destination_clock)),
        owned_dedicated_sessions: Some(ComponentResidual::Closed),
        owned_admissions: Some(ComponentResidual::Closed),
        other_live_sessions: Some(ComponentResidual::Unknown),
        detached_remote_processes: Some(ComponentResidual::NotEnded),
    }
}

/// The conditions a runner binding's readiness depends on (ADR-0012 §4.5), sorted.
pub const RUNNER_CONDITIONS: [ReadinessCondition; 3] = [
    ReadinessCondition::RunnerLifetime,
    ReadinessCondition::RunnerTimeBounded,
    ReadinessCondition::RunnerProcessNotRestarted,
];

/// A runner binding's readiness (module docs).
#[must_use]
pub fn runner_readiness(input: &RunnerReadinessInput<'_>) -> RunnerReadiness {
    let anchor = input
        .anchor
        .filter(|_| input.time_bounded)
        .and_then(|a| anchor_end(a, input.now));
    let time = if anchor.is_some() {
        RunnerTime::Bounded
    } else {
        RunnerTime::Uncertain
    };
    let candidates = [
        (anchor, OfflineBound::Anchor),
        (Some(input.deadline), OfflineBound::Deadline),
        (input.parent_deadline, OfflineBound::ParentDeadline),
        (input.cutoff, OfflineBound::Cutoff),
        (
            input.certificate_valid_before,
            OfflineBound::CertificateValidBefore,
        ),
    ];
    // The earliest; on a tie, prefer `Cutoff` over `Anchor` (an anchor shortened to a
    // cutoff reports the cutoff), and `Anchor` before the other absolute bounds.
    let (offline_until, bound_by) = candidates
        .iter()
        .filter_map(|(t, b)| t.map(|t| (t, *b)))
        .fold((input.deadline, OfflineBound::Deadline), |best, c| {
            let tie_wins = c.0 == best.0
                && (c.1 == OfflineBound::Cutoff
                    || (c.1 == OfflineBound::Anchor && best.1 != OfflineBound::Cutoff));
            if c.0 < best.0 || tie_wins { c } else { best }
        });
    let mut conditions = RUNNER_CONDITIONS.to_vec();
    conditions.sort();
    RunnerReadiness {
        offline_until,
        bound_by,
        usable_until: offline_until,
        time,
        refresh_dependency: RefreshDependency::Controller,
        refresh_condition: RefreshCondition {
            needed_only_after: RefreshTrigger::SignerRestart,
            source: RefreshDependency::Controller,
        },
        conditions,
        lifetime: input.lifetime,
        residuals: runner_residuals(input.counted_expiry, input.destination_clock),
    }
}

/// Attach a runner binding's readiness to its `ensure` result (ADR-0006 §18.5 reading 14):
/// `usable_until` and `offline_until` only ever move earlier, the refresh dependency and
/// condition become the controller's, the runner conditions are added (sorted, once each),
/// and the residuals are attached.
pub fn attach_runner_readiness(data: &mut EnsureData, readiness: &RunnerReadiness) {
    data.usable_until = data.usable_until.min(readiness.usable_until);
    data.offline_until = data.offline_until.min(readiness.offline_until);
    data.refresh_dependency = readiness.refresh_dependency;
    data.refresh_condition = Some(readiness.refresh_condition);
    for c in &readiness.conditions {
        if !data.conditions.contains(c) {
            data.conditions.push(*c);
        }
    }
    data.conditions.sort();
    data.residuals = Some(readiness.residuals.clone());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::ids::GrantId;
    use heimdall_contract::managed::ClockMeasurement;
    use heimdall_domain::time::BootId;

    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn now() -> TimeAnchor {
        TimeAnchor {
            boot_id: BootId("boot-a".into()),
            continuous: Duration::from_secs(1_000),
            wall: t("2026-11-21T09:00:00Z"),
        }
    }

    /// A runner anchor whose budget ends `left` after `now()`.
    fn anchor(left: Duration, boot: &str) -> GrantAnchor {
        GrantAnchor {
            grant: GrantId::from_random_bytes([1; 16]),
            anchor: TimeAnchor {
                boot_id: BootId(boot.into()),
                continuous: Duration::from_secs(900),
                wall: t("2026-11-21T08:58:20Z"),
            },
            bound: t("2026-11-21T12:00:00Z"),
            budget_end: Duration::from_secs(1_000) + left,
        }
    }

    fn input<'a>(now: &'a TimeAnchor, a: Option<&'a GrantAnchor>) -> RunnerReadinessInput<'a> {
        RunnerReadinessInput {
            now,
            deadline: t("2026-11-21T12:00:00Z"),
            parent_deadline: Some(t("2026-11-21T11:00:00Z")),
            cutoff: Some(t("2026-11-21T10:30:00Z")),
            anchor: a,
            time_bounded: true,
            certificate_valid_before: Some(t("2026-11-21T10:00:00Z")),
            destination_clock: DestinationClock::Unmeasured,
            counted_expiry: Some(t("2026-11-21T10:00:00Z")),
            lifetime: RunnerLifetime::SessionScope,
        }
    }

    /// The unit row of m06-plan U3: `offline_until` is the earliest of the anchor, the
    /// parent deadline, the cutoff and `valid_before` (each made the earliest in turn).
    #[test]
    fn offline_until_is_the_earliest_of_anchor_parent_cutoff_and_valid_before() {
        let n = now();
        // The anchor ends 30 minutes from now: earliest of all.
        let a = anchor(Duration::from_secs(1_800), "boot-a");
        let r = runner_readiness(&input(&n, Some(&a)));
        assert_eq!(r.offline_until, t("2026-11-21T09:30:00Z"));
        assert_eq!(r.bound_by, OfflineBound::Anchor);
        assert_eq!(r.usable_until, r.offline_until);
        assert_eq!(r.time, RunnerTime::Bounded);

        // A long anchor: valid_before (10:00) is the earliest.
        let long = anchor(Duration::from_secs(36_000), "boot-a");
        let r = runner_readiness(&input(&n, Some(&long)));
        assert_eq!(
            (r.offline_until, r.bound_by),
            (
                t("2026-11-21T10:00:00Z"),
                OfflineBound::CertificateValidBefore
            )
        );

        // Without a certificate: the cutoff (10:30).
        let mut i = input(&n, Some(&long));
        i.certificate_valid_before = None;
        let r = runner_readiness(&i);
        assert_eq!(
            (r.offline_until, r.bound_by),
            (t("2026-11-21T10:30:00Z"), OfflineBound::Cutoff)
        );

        // Without a cutoff: the parent deadline (11:00).
        i.cutoff = None;
        let r = runner_readiness(&i);
        assert_eq!(
            (r.offline_until, r.bound_by),
            (t("2026-11-21T11:00:00Z"), OfflineBound::ParentDeadline)
        );

        // Without a parent: the grant's deadline.
        i.parent_deadline = None;
        let r = runner_readiness(&i);
        assert_eq!(
            (r.offline_until, r.bound_by),
            (t("2026-11-21T12:00:00Z"), OfflineBound::Deadline)
        );
    }

    /// No qualifying sample, or an anchor of another boot: time is uncertain and the derived
    /// anchor does not count; the bound is the credential's own.
    #[test]
    fn without_a_bounded_offset_the_anchor_does_not_count() {
        let n = now();
        let a = anchor(Duration::from_secs(60), "boot-a");
        let mut i = input(&n, Some(&a));
        i.time_bounded = false;
        let r = runner_readiness(&i);
        assert_eq!(r.time, RunnerTime::Uncertain);
        assert_eq!(r.bound_by, OfflineBound::CertificateValidBefore);
        let other_boot = anchor(Duration::from_secs(60), "boot-b");
        let r = runner_readiness(&input(&n, Some(&other_boot)));
        assert_eq!(r.time, RunnerTime::Uncertain);
        assert_eq!(anchor_end(&other_boot, &n), None);
        // The conditions are reported either way.
        assert_eq!(r.conditions, RUNNER_CONDITIONS.to_vec());
        assert_eq!(r.refresh_dependency, RefreshDependency::Controller);
    }

    /// The revision-6.2 attachment: absent on every existing result (byte-identical), and on a
    /// runner binding the readiness only moves earlier, the residuals ride on the wire and
    /// round-trip.
    #[test]
    fn the_residuals_attach_to_ensure_data_and_round_trip() {
        let existing = r#"{"binding_id":"binding_01010101010101010101010101010101","environment_id":"env_07070707070707070707070707070707","profile_revision":1,"grant_id":"grant_02020202020202020202020202020202","expires_at":"2026-11-21T12:00:00Z","usable_until":"2026-11-21T12:00:00Z","offline_until":"2026-11-21T12:00:00Z","refresh_dependency":"local_issuer","credential_mechanism":"managed_certificate","enforcement":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"shared_os_user","existing_connections":"unknown","revocation":"unknown"},"consumer":{},"credential_availability":"unknown"}"#;
        let mut data: EnsureData = serde_json::from_str(existing).unwrap();
        assert_eq!(data.residuals, None);
        assert_eq!(serde_json::to_string(&data).unwrap(), existing);
        let n = now();
        let a = anchor(Duration::from_secs(1_800), "boot-a");
        let r = runner_readiness(&input(&n, Some(&a)));
        attach_runner_readiness(&mut data, &r);
        assert_eq!(data.offline_until, t("2026-11-21T09:30:00Z"));
        assert_eq!(data.usable_until, t("2026-11-21T09:30:00Z"));
        assert_eq!(data.refresh_dependency, RefreshDependency::Controller);
        assert_eq!(data.conditions, RUNNER_CONDITIONS.to_vec());
        let wire = serde_json::to_value(&data).unwrap();
        assert_eq!(
            wire["residuals"]["new_authentication"]["destination_clock_error"],
            "unmeasured"
        );
        let back: EnsureData = serde_json::from_value(wire).unwrap();
        assert_eq!(back, data);
        // Attaching never moves a bound later.
        let mut later = runner_readiness(&input(&n, None));
        later.offline_until = t("2026-11-21T13:00:00Z");
        later.usable_until = later.offline_until;
        attach_runner_readiness(&mut data, &later);
        assert_eq!(data.offline_until, t("2026-11-21T09:30:00Z"));
    }

    /// The unit row of m06-plan U3: the authentication residual carries
    /// `destination_clock_error: unmeasured` when no measurement exists, and is never a bare
    /// deadline (on the wire and in its meaning).
    #[test]
    fn the_authentication_residual_is_never_a_bare_deadline() {
        let n = now();
        let r = runner_readiness(&input(&n, None));
        let auth = r.residuals.new_authentication.clone().unwrap();
        assert_eq!(auth.destination_clock_error, DestinationClock::Unmeasured);
        let wire = serde_json::to_value(&r.residuals).unwrap();
        assert_eq!(
            wire["new_authentication"],
            serde_json::json!({
                "latest_possible_credential_expiry": "2026-11-21T10:00:00Z",
                "destination_clock_error": "unmeasured"
            })
        );
        assert_eq!(wire["owned_dedicated_sessions"], "closed");
        assert_eq!(wire["owned_admissions"], "closed");
        assert_eq!(wire["other_live_sessions"], "unknown");
        assert_eq!(wire["detached_remote_processes"], "not_ended");
        assert_eq!(
            residual_end(&auth),
            ResidualEnd::PlusUnmeasuredClockError(t("2026-11-21T10:00:00Z"))
        );
        // Measured: the bound includes the lag.
        let measured = authentication_residual(
            Some(t("2026-11-21T10:00:00Z")),
            DestinationClock::Measured(ClockMeasurement {
                behind_upper_ms: 2_000,
                rtt_ms: 40,
                measured_at: t("2026-11-21T08:00:00Z"),
            }),
        );
        assert_eq!(
            residual_end(&measured),
            ResidualEnd::AtMost(t("2026-11-21T10:00:02Z"))
        );
        // No counted history: unknown, and the clock error is still stated.
        let unknown = authentication_residual(None, DestinationClock::Unmeasured);
        assert_eq!(residual_end(&unknown), ResidualEnd::Unknown);
        assert_eq!(
            serde_json::to_value(&unknown).unwrap(),
            serde_json::json!({"destination_clock_error": "unmeasured"})
        );
    }

    /// ⟨M08 W4 SEC-5, item 7.1⟩ When a grant's anchor was shortened to a cutoff and the
    /// anchor's remaining budget equals the cutoff instant (tie), `bound_by` is
    /// `OfflineBound::Cutoff`, not `OfflineBound::Anchor`.
    #[test]
    fn cutoff_wins_tie_against_anchor_shortened_to_it() {
        let n = now();
        let cutoff = n.wall;
        let shortened_anchor = GrantAnchor {
            grant: GrantId::from_random_bytes([1; 16]),
            anchor: TimeAnchor {
                boot_id: BootId("boot-a".into()),
                continuous: Duration::from_secs(900),
                wall: t("2026-11-21T08:58:20Z"),
            },
            bound: cutoff,
            budget_end: n.continuous,
        };
        let mut i = input(&n, Some(&shortened_anchor));
        i.cutoff = Some(cutoff);
        let r = runner_readiness(&i);
        assert_eq!(r.offline_until, cutoff);
        assert_eq!(
            r.bound_by,
            OfflineBound::Cutoff,
            "an anchor shortened to a cutoff must report OfflineBound::Cutoff on tie"
        );
    }
}
