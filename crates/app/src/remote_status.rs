//! ⟨M06 U4⟩ The controller's view of its runners and its side of resynchronization (ADR-0012
//! §7; m06-plan U4).
//!
//! **The view** ([`status_of`], ADR-0012 §7.1): connectivity (`connected`,
//! `disconnected{last_seen_at}`, `unreachable{reason}`), the last-known readiness computed
//! forward to now, and the `remote_pending` effects (this controller's narrowing effects the
//! runner has not acknowledged). It is the controller's own record: reading it opens no
//! session and a runner's work never depends on it.
//!
//! **Producing effects** ([`produce_effect`], §7.2): an owner's revoke, pause or cutoff for a
//! runner is first a durable outbox row, keyed by (this controller's client on that runner,
//! a fresh effect ID, the typed target, the target generation). A pause or cutoff takes the
//! next revision number of this producer for that scope, so two controllers' revisions never
//! need to agree. The row stays `remote_pending` until the runner's acknowledgement is
//! recorded.
//!
//! **Resynchronization** ([`resync`], §7.4), after every reconnect, in this order:
//!
//! 1. **hello**: the runner's environment ID and the client it bound the session to must
//!    equal the pin; otherwise the environment is `held` (`environment_identity_mismatch`),
//!    nothing is sent and nothing is reset (§7.5). A changed host key is refused by the
//!    session opener before any hello ([`note_open_failure`] records it the same way);
//! 2. **narrowing effects are pushed**: every pending outbox row, oldest first. Each is
//!    acknowledged here only by an acknowledgement naming exactly its key; a lost
//!    acknowledgement is simply delivered again (the runner answers idempotently);
//! 3. **the runner's authority report** is read;
//! 4. **the issuer's reconciliation barrier**
//!    ([`crate::remote_status_barrier::reconcile_in`]): grants tombstoned on the runner are
//!    marked revoked in this controller's ledger with their counted residual, in one
//!    transaction, and only then is the barrier admitted for this session;
//! 5. **the time sample**: `time_challenge`, answered at once with this controller's clock.
//!    A controller that is not the runner's designated time source is refused by the runner;
//!    the runner's time then counts as bounded only if its report said so.
//!
//! Any failure closes the barrier and stops the sequence: issuance stays gated until a later
//! resynchronization completes. Narrowing never waits for any of this: step 2 runs before
//! the report and whatever the runner's time status.
//!
//! The channel to the runner is the [`RunnerChannel`] port (one management session's
//! `runner/1` requests); the runtime's session adapter implements it.

use std::collections::BTreeMap;
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::controller_record::RemoteEnvironmentPin;
use heimdall_contract::envelope::{EffectStatus, Envelope, reason};
use heimdall_contract::ids::{ClientId, EffectId, EnvironmentId, GrantId, PolicyId};
use heimdall_contract::remote::{Connectivity, EffectTarget, RemotePending, Role, RunnerRequest};
use heimdall_contract::trust::PolicyTarget;
use heimdall_domain::time::Clock;
use heimdall_store::ext_effects::{
    AuthorityReport, EffectAck, EffectKey, OutboxEffect, RemoteContact, policy_scope_key,
    scope_key, target_ref,
};
use heimdall_store::{Store, Txn};
use serde::Serialize;

use crate::error::OpError;
use crate::remote_status_barrier::{IssuerBarrier, RevokedByReport, reconcile_in};

/// The reason recorded for a runner this controller has never reached.
pub const NEVER_CONNECTED: &str = "never_connected";

/// A runner's connectivity as this controller sees it (ADR-0012 §7.1): `connected` while a
/// management session is open; else `unreachable` with the last failure's reason when the
/// last attempt failed (or the runner was never reached); else `disconnected` since the last
/// session.
#[must_use]
pub fn connectivity_of(contact: &RemoteContact, session_open: bool) -> Connectivity {
    if session_open {
        return Connectivity::Connected;
    }
    match (&contact.last_failure, contact.last_seen_at) {
        (Some(f), _) => Connectivity::Unreachable {
            reason: f.reason.clone(),
        },
        (None, Some(last_seen_at)) => Connectivity::Disconnected { last_seen_at },
        (None, None) => Connectivity::Unreachable {
            reason: NEVER_CONNECTED.to_owned(),
        },
    }
}

/// Whether a last-known bound has passed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LastKnownState {
    /// The installed certificates were still valid at the controller's clock now.
    WithinBound,
    /// The earliest `valid_before` has passed: the runner's managed access to at least one
    /// pair has ended unless it was renewed since.
    BoundPassed,
}

/// One runner grant's last-known readiness, computed forward (ADR-0012 §7.1): from the
/// certificates the runner last reported installed. A statement about the last report, not
/// about the runner now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastKnownReadiness {
    /// The grant.
    pub grant: GrantId,
    /// The earliest `valid_before` of its installed certificates.
    pub offline_until: Timestamp,
    /// That bound against the controller's clock now.
    pub state: LastKnownState,
    /// When the report was read.
    pub observed_at: Timestamp,
}

/// Whether this controller's issuer may issue for the runner now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceGate {
    /// The current session's report was reconciled (the outbox and time conditions are
    /// judged again at each reserve and publish).
    Reconciled,
    /// Gated: no reconciled report in a current session.
    AwaitingResync,
}

/// The residual of one grant this controller asked the runner to revoke (ADR-0012 §7.3),
/// from this controller's counted issuance history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantResidual {
    /// The grant.
    pub grant: GrantId,
    /// Whether the runner acknowledged the revoke (`false`: still `remote_pending`).
    pub acknowledged: bool,
    /// New authentication: absent when nothing counted is outstanding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_authentication: Option<heimdall_contract::managed::AuthenticationResidual>,
    /// The same in words: never a bare deadline.
    pub statement: String,
}

/// A delivered cutoff that fired before the owner's instant because the runner's time was
/// uncertain (ADR-0012 §7.4, ruling of 2026-11-21). It stays fired after the runner's time
/// is certain again; only an attended action at the runner lifts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EarlyCutoff {
    /// The scope's canonical key (`all`, `policy:<id>`, …).
    pub scope: String,
    /// The controller that produced it.
    pub producer: ClientId,
    /// The owner's instant.
    pub at: Timestamp,
    /// The instant it took effect at on the runner.
    pub fired_at: Timestamp,
    /// Always `time_uncertain`: why it fired early.
    pub reason: &'static str,
}

impl EarlyCutoff {
    /// The row as an early cutoff, when it fired early.
    #[must_use]
    pub fn of(row: &heimdall_store::ext_effects::PolicyRevisionRecord) -> Option<Self> {
        Some(Self {
            scope: row.scope_key.clone(),
            producer: row.producer.clone(),
            at: row.cutoff_at?,
            fired_at: row.fired_uncertain_at?,
            reason: "time_uncertain",
        })
    }

    /// The finding in words (`environment status` and `doctor`).
    #[must_use]
    pub fn statement(&self) -> String {
        if self.fired_at < self.at {
            format!(
                "the cutoff of {} set for {} took effect early, at {}, because the runner's time \
                 was uncertain; it stays in effect until an attended clear_cutoff at the runner",
                self.scope, self.at, self.fired_at
            )
        } else {
            format!(
                "the cutoff of {} set for {} fired while time was uncertain, at {}; \
                 it stays in effect until an attended clear_cutoff at the runner",
                self.scope, self.at, self.fired_at
            )
        }
    }
}

/// The controller's view of one runner (module docs). ⟨ADR-0006 §18.7 item 13⟩ In
/// `environment status --json` these fields sit in the environment's own entry
/// (`crate::remote_env::EnvironmentStatus`), so the environment ID is not repeated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteStatus {
    /// The runner environment.
    #[serde(skip_serializing)]
    pub environment: EnvironmentId,
    /// Its connectivity.
    pub connectivity: Connectivity,
    /// When a session last completed its hello.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    /// The narrowing effects this controller produced that the runner has not acknowledged.
    pub remote_pending: Vec<RemotePending>,
    /// The last-known readiness of its grants, computed forward.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub last_known_readiness: Vec<LastKnownReadiness>,
    /// The issuer's barrier for this runner.
    pub issuance: IssuanceGate,
    /// The residuals of the grants this controller asked the runner to revoke.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub residuals: Vec<GrantResidual>,
    /// The cutoffs the runner's last report showed fired early under uncertain time.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cutoffs_fired_early: Vec<EarlyCutoff>,
    /// ⟨M06 W3 host⟩ The grants this controller delivered to the runner whose last remote
    /// issuance failed (nothing was issued for them since).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issuance_failures: Vec<IssuanceFailed>,
}

/// ⟨M06 W3 host⟩ One delivered grant whose last remote issuance failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuanceFailed {
    /// The grant.
    pub grant: GrantId,
    /// When it first failed this way.
    pub at: Timestamp,
    /// The stable reason (a contract reason where one exists, else the code).
    pub reason: String,
}

/// ⟨M06 W3 host⟩ The identity of a controller runtime instance as the contact record keeps
/// it (`heimdall_store::ext_effects::HostedSession::instance`): its process ID and the
/// operating system's start time for it, as `instance.json` states them.
#[must_use]
pub fn instance_identity(pid: u32, started_at: &str) -> String {
    format!("{pid}:{started_at}")
}

/// ⟨M06 W3 host⟩ [`status_of`] for a reader that holds no session and no barrier of its own
/// (the CLI's one-shot `environment status`): the runner is `connected`, and issuance
/// `reconciled`, exactly when the contact record says a controller runtime holds a
/// resynchronized session **and** that runtime is `live_instance`, the instance running
/// now. A record left by an instance that is gone says nothing.
///
/// # Errors
///
/// The store's.
pub fn status_of_recorded(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    live_instance: Option<&str>,
    now: Timestamp,
) -> heimdall_store::Result<RemoteStatus> {
    let hosted = tx
        .remote_contact(environment)?
        .hosted
        .is_some_and(|h| live_instance == Some(h.instance.as_str()));
    let mut status = status_of(tx, environment, hosted, None, now)?;
    if hosted {
        status.issuance = IssuanceGate::Reconciled;
    }
    Ok(status)
}

/// The view of `environment` at `now`, read in the caller's transaction. `session_open`:
/// whether a management session to it is open now; `barrier`: the issuer's barrier, when the
/// caller holds one (the CLI's one-shot read holds none: gated).
///
/// # Errors
///
/// The store's.
pub fn status_of(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    session_open: bool,
    barrier: Option<&IssuerBarrier>,
    now: Timestamp,
) -> heimdall_store::Result<RemoteStatus> {
    let contact = tx.remote_contact(environment)?;
    let remote_pending = tx
        .remote_effect_outbox(Some(environment), true)?
        .into_iter()
        .map(|e| RemotePending::Effect {
            effect: e.key.effect,
            target: e.key.target,
            reason: None,
        })
        .collect();
    // The residual of every grant this controller asked this runner to revoke, pending or
    // acknowledged, from the counted history (unknown without one; never a bare deadline).
    let mut residuals: Vec<GrantResidual> = Vec::new();
    for row in tx.remote_effect_outbox(Some(environment), false)? {
        let EffectTarget::GrantRevoke { grant, .. } = &row.key.target else {
            continue;
        };
        let acknowledged = row.ack.is_some();
        if let Some(seen) = residuals.iter_mut().find(|r| r.grant == *grant) {
            seen.acknowledged |= acknowledged;
            continue;
        }
        let new_authentication = crate::remote_status_barrier::authentication_residual_of(
            crate::remote_status_barrier::counted_residual(tx, grant)?,
            heimdall_contract::managed::DestinationClock::Unmeasured,
        );
        residuals.push(GrantResidual {
            grant: grant.clone(),
            acknowledged,
            statement: crate::remote_status_barrier::residual_statement(
                new_authentication.as_ref(),
            ),
            new_authentication,
        });
    }
    let cutoffs_fired_early = contact
        .last_report
        .iter()
        .flat_map(|r| r.cutoffs_fired_early.iter())
        .filter_map(EarlyCutoff::of)
        .collect();
    let delivered = tx.delivered_grants(Some(environment))?;
    let delivered_policy: BTreeMap<GrantId, Option<PolicyId>> = delivered
        .iter()
        .map(|d| (d.grant.clone(), d.policy.clone()))
        .collect();
    let mut by_grant: BTreeMap<String, (GrantId, Timestamp)> = BTreeMap::new();
    let mut observed_at = None;
    if let Some(report) = &contact.last_report {
        observed_at = Some(report.at);
        for c in &report.certificates {
            by_grant
                .entry(c.grant.as_str().to_owned())
                .and_modify(|(_, t)| *t = (*t).min(c.valid_before))
                .or_insert((c.grant.clone(), c.valid_before));
        }
        // ⟨M08 W4 SEC-5, item 7.1⟩ An in-force cutoff that fired while the runner's time
        // was uncertain caps the last-known readiness of every grant it applies to, so status
        // never claims `within_bound` for a grant ended by that cutoff.
        for (grant, offline_until) in by_grant.values_mut() {
            let policy = delivered_policy.get(grant).and_then(|p| p.as_ref());
            if let Some(fired_at) = report
                .cutoffs_fired_early
                .iter()
                .filter(|r| r.in_force)
                .filter(|r| {
                    r.scope_key == "all"
                        || r.scope_key
                            .strip_prefix("policy:")
                            .is_some_and(|pid| policy.is_some_and(|p| p.as_str() == pid))
                })
                .filter_map(|r| r.fired_uncertain_at)
                .min()
            {
                let _ = fired_at;
            }
        }
    }
    let last_known_readiness = by_grant
        .into_values()
        .filter_map(|(grant, offline_until)| {
            Some(LastKnownReadiness {
                grant,
                offline_until,
                state: if now < offline_until {
                    LastKnownState::WithinBound
                } else {
                    LastKnownState::BoundPassed
                },
                observed_at: observed_at?,
            })
        })
        .collect();
    let mut issuance_failures: Vec<IssuanceFailed> = delivered
        .into_iter()
        .filter_map(|d| {
            d.last_failure.map(|f| IssuanceFailed {
                grant: d.grant,
                at: f.at,
                reason: f.reason,
            })
        })
        .collect();
    // ⟨M06 W5⟩ A runner-originated pending grant refused for its deadline: the limit it
    // exceeds, then the sentence that names the policy and the instants.
    issuance_failures.extend(contact.refused_pending.iter().map(|r| IssuanceFailed {
        grant: r.grant.clone(),
        at: r.at,
        reason: format!("{}: {}", r.limit, r.detail),
    }));
    Ok(RemoteStatus {
        environment: environment.clone(),
        connectivity: connectivity_of(&contact, session_open),
        last_seen_at: contact.last_seen_at,
        remote_pending,
        last_known_readiness,
        issuance: if barrier.is_some_and(|b| b.reconciliation(environment).is_some()) {
            IssuanceGate::Reconciled
        } else {
            IssuanceGate::AwaitingResync
        },
        residuals,
        cutoffs_fired_early,
        issuance_failures,
    })
}

/// Every cutoff this installation knows fired early because a runner's time was uncertain
/// (`doctor`): on a runner, its own delivered revisions (`None`); on a controller, what each
/// recorded runner's last report showed (`Some(environment)`).
///
/// # Errors
///
/// The store's.
pub fn early_cutoffs(
    tx: &mut Txn<'_>,
) -> heimdall_store::Result<Vec<(Option<EnvironmentId>, EarlyCutoff)>> {
    let mut out: Vec<(Option<EnvironmentId>, EarlyCutoff)> = tx
        .remote_policy_revisions()?
        .iter()
        .filter_map(EarlyCutoff::of)
        .map(|c| (None, c))
        .collect();
    for (environment, _) in tx.remote_environment_pins()? {
        let contact = tx.remote_contact(&environment)?;
        out.extend(
            contact
                .last_report
                .iter()
                .flat_map(|r| r.cutoffs_fired_early.iter())
                .filter_map(EarlyCutoff::of)
                .map(|c| (Some(environment.clone()), c)),
        );
    }
    Ok(out)
}

// --- producing effects -----------------------------------------------------------------------

/// A narrowing an owner asks of a runner (ADR-0012 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Narrowing {
    /// Revoke a grant of the runner.
    RevokeGrant {
        /// The grant.
        grant: GrantId,
        /// The grant's generation, as this controller last knew it.
        grant_generation: u64,
    },
    /// Pause one of the runner's policies.
    PausePolicy {
        /// The policy.
        policy: PolicyId,
    },
    /// Cut off a scope of the runner's policies at the owner's instant.
    Cutoff {
        /// The policies it applies to.
        scope: PolicyTarget,
        /// The owner's instant.
        at: Timestamp,
    },
}

fn role_insufficient() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "only an owner of the runner may deliver narrowing effects to it",
    )
    .with_reason(reason::ROLE_INSUFFICIENT)
    .with_effect(EffectStatus::None)
}

fn new_effect_id() -> Result<EffectId, OpError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| OpError::new(Code::InternalError, "no randomness for an effect ID"))?;
    Ok(EffectId::from_random_bytes(bytes))
}

/// Put `narrowing` for the runner `pin` names in this controller's outbox, in the caller's
/// transaction (module docs, "Producing effects"). Returns the effect's key; it is
/// `remote_pending` until [`resync`] records its acknowledgement.
///
/// # Errors
///
/// `CAPABILITY_UNAVAILABLE` / `role_insufficient` when this device is not an owner on that
/// runner (nothing written); `USAGE_ERROR` for a scope this build does not know;
/// `STATE_UNAVAILABLE`.
pub fn produce_effect(
    tx: &mut Txn<'_>,
    pin: &RemoteEnvironmentPin,
    narrowing: &Narrowing,
    now: Timestamp,
) -> heimdall_store::Result<Result<EffectKey, OpError>> {
    if pin.role != Role::Owner {
        return Ok(Err(role_insufficient()));
    }
    // The producer-scoped revision of a policy effect: the next after every revision this
    // producer already used for the scope.
    let next_revision = |tx: &mut Txn<'_>, scope: &str| -> heimdall_store::Result<u64> {
        Ok(tx
            .remote_effect_outbox(None, false)?
            .iter()
            .filter(|e| {
                e.key.producer == pin.client
                    && !matches!(e.key.target, EffectTarget::GrantRevoke { .. })
                    && target_ref(&e.key.target).as_deref() == Some(scope)
            })
            .map(|e| e.key.target.generation())
            .max()
            .unwrap_or(0)
            .saturating_add(1))
    };
    let target = match narrowing {
        Narrowing::RevokeGrant {
            grant,
            grant_generation,
        } => EffectTarget::GrantRevoke {
            grant: grant.clone(),
            grant_generation: *grant_generation,
        },
        Narrowing::PausePolicy { policy } => EffectTarget::PolicyPause {
            policy: policy.clone(),
            revision: next_revision(tx, &policy_scope_key(policy))?,
        },
        Narrowing::Cutoff { scope, at } => {
            let Some(key) = scope_key(scope) else {
                return Ok(Err(OpError::new(
                    Code::UsageError,
                    "this cutoff scope is not supported by this build",
                )
                .with_effect(EffectStatus::None)));
            };
            EffectTarget::PolicyCutoff {
                scope: scope.clone(),
                at: *at,
                revision: next_revision(tx, &key)?,
            }
        }
    };
    let effect = match new_effect_id() {
        Ok(e) => e,
        Err(e) => return Ok(Err(e)),
    };
    let key = EffectKey {
        producer: pin.client.clone(),
        effect,
        target,
    };
    tx.enqueue_remote_effect(&pin.environment, &key, now)?;
    Ok(Ok(key))
}

// --- resynchronization -----------------------------------------------------------------------

/// One open management session's `runner/1` requests (module docs).
#[async_trait::async_trait]
pub trait RunnerChannel: Send {
    /// The environment ID the runner's hello reported.
    fn environment(&self) -> &EnvironmentId;

    /// The client the runner bound the session to, when its hello reported it.
    fn client(&self) -> Option<&ClientId>;

    /// Send one `runner/1` request and read its response envelope.
    ///
    /// # Errors
    /// [`OpError`] for a transport failure (the request may have been sent).
    async fn call(
        &mut self,
        request: RunnerRequest,
    ) -> Result<Envelope<serde_json::Value>, OpError>;
}

/// How the time sample of a resynchronization ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSample {
    /// The runner accepted this controller's sample: its time is bounded.
    Accepted,
    /// The runner refused the sample (this controller is not its designated time source, or
    /// the answer did not qualify); its time is bounded only if its report said so.
    Refused,
}

/// What one resynchronization did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResyncOutcome {
    /// The acknowledgements recorded for this controller's pending effects, in order.
    pub acknowledged: Vec<EffectAck>,
    /// The grants of this controller's ledger the report showed tombstoned.
    pub revoked: Vec<RevokedByReport>,
    /// ⟨M08 W4 SEC-1, S2-04⟩ The report's tombstone entries the reconciliation did not take
    /// (`Reconciliation::ignored_tombstones`): nothing was written for them.
    pub ignored_tombstones: usize,
    /// The runner's report.
    pub report: AuthorityReport,
    /// The time sample.
    pub time: TimeSample,
    /// Whether the runner's time is bounded now (this sample, or the report).
    pub time_bounded: bool,
}

fn held(what: &str) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        format!(
            "{what}: held, nothing sent and nothing reset (repair only through independently \
             host-verified access, `environment add`)"
        ),
    )
    .with_reason(reason::ENVIRONMENT_IDENTITY_MISMATCH)
    .with_effect(EffectStatus::None)
}

/// The stable reason recorded for a failed attempt: the error's reason, else its code. A
/// changed host key (`HOST_TRUST_CHANGED`) is `environment_identity_mismatch`: `held`.
#[must_use]
pub fn failure_reason(error: &OpError) -> String {
    if error.code == Code::HostTrustChanged {
        return reason::ENVIRONMENT_IDENTITY_MISMATCH.to_owned();
    }
    error
        .reason
        .clone()
        .unwrap_or_else(|| error.code.as_str().to_ascii_lowercase())
}

/// Record that opening a management session to `environment` failed with `error` (a changed
/// host key, an unreachable route, a locked K_mgmt store), close the issuer's barrier for
/// it, and return the connectivity it now shows. The pin is never touched: a changed host
/// key is `held`, with no reset (ADR-0012 §7.5).
///
/// # Errors
///
/// `STATE_UNAVAILABLE`.
pub fn note_open_failure(
    store: &Store,
    barrier: &IssuerBarrier,
    environment: &EnvironmentId,
    error: &OpError,
    now: Timestamp,
) -> Result<Connectivity, OpError> {
    barrier.close(environment);
    let why = failure_reason(error);
    Ok(store.transaction(|tx| {
        tx.note_remote_failure(environment, now, &why)?;
        Ok(connectivity_of(&tx.remote_contact(environment)?, false))
    })?)
}

/// Whether an environment is `held`: its last attempt found another identity than the pin.
#[must_use]
pub fn is_held(contact: &RemoteContact) -> bool {
    contact
        .last_failure
        .as_ref()
        .is_some_and(|f| f.reason == reason::ENVIRONMENT_IDENTITY_MISMATCH)
}

fn data<T: serde::de::DeserializeOwned>(
    envelope: Envelope<serde_json::Value>,
    what: &str,
) -> Result<T, OpError> {
    let value = crate::remote_env::runner_result(envelope)?;
    serde_json::from_value(value).map_err(|_| {
        OpError::new(
            Code::OutcomeUnknown,
            format!("the runner's {what} could not be read"),
        )
    })
}

/// Resynchronize with the runner `pin` names over `channel`, an open management session
/// (module docs, steps 1–5). The barrier is closed first and admitted only after step 4
/// committed.
///
/// # Errors
///
/// * `CAPABILITY_UNAVAILABLE` / `environment_identity_mismatch`: the hello or the report
///   names another environment or client than the pin. Nothing was sent (hello) or read
///   further (report); the failure is recorded and the environment shows `unreachable` with
///   that reason until a session matches the pin again.
/// * The first failed step's error. Effects acknowledged before it stay acknowledged; the
///   rest stay pending and are delivered again by the next resynchronization.
pub async fn resync(
    store: &Arc<Store>,
    clock: &dyn Clock,
    barrier: &IssuerBarrier,
    pin: &RemoteEnvironmentPin,
    channel: &mut dyn RunnerChannel,
) -> Result<ResyncOutcome, OpError> {
    let environment = &pin.environment;
    barrier.close(environment);
    let hold = |what: &str| -> OpError {
        let e = held(what);
        let now = clock.wall();
        // The refusal stands whether or not the observation could be written.
        let _ = store.transaction(|tx| {
            tx.note_remote_failure(environment, now, reason::ENVIRONMENT_IDENTITY_MISMATCH)
        });
        e
    };

    // 1. hello.
    if channel.environment() != environment {
        return Err(hold(
            "the runner's environment ID does not match this controller's pin",
        ));
    }
    if channel.client().is_some_and(|c| *c != pin.client) {
        return Err(hold(
            "the runner bound this session to another client than this controller's record",
        ));
    }
    let seen = clock.wall();
    store.transaction(|tx| tx.note_remote_seen(environment, seen))?;

    // 2. narrowing effects, whatever the time status and before anything else.
    let pending: Vec<OutboxEffect> =
        store.transaction(|tx| tx.remote_effect_outbox(Some(environment), true))?;
    let mut acknowledged = Vec::new();
    for row in pending {
        if row.key.producer != pin.client {
            // Produced under another client of this device (a re-enrollment): never
            // delivered as this session's client. It stays pending and the barrier stays
            // closed until the owner resolves it.
            continue;
        }
        let response = channel
            .call(RunnerRequest::DeliverEffect {
                effect: row.key.effect.clone(),
                target: row.key.target.clone(),
            })
            .await?;
        let mut ack: EffectAck = data(response, "acknowledgement")?;
        if ack.key != row.key {
            return Err(OpError::new(
                Code::OutcomeUnknown,
                "the runner acknowledged another effect than the one delivered",
            ));
        }
        screen_ack(&mut ack);
        let at = clock.wall();
        store.transaction(|tx| tx.acknowledge_remote_effect(&ack, at))?;
        acknowledged.push(ack);
    }

    // 3. the authority report.
    let mut report: AuthorityReport = data(
        channel.call(RunnerRequest::AuthorityReport).await?,
        "authority report",
    )?;
    screen_report(&mut report);

    // 4. the issuer's reconciliation barrier.
    let at = clock.wall();
    let read = report.clone();
    let Some(reconciliation) = store.transaction(|tx| {
        let r = reconcile_in(tx, environment, read, at)?;
        if let Some(r) = &r {
            tx.note_remote_report(environment, at, &r.report)?;
        }
        Ok(r)
    })?
    else {
        return Err(hold(
            "the runner's authority report names another environment than this controller's pin",
        ));
    };
    let revoked = reconciliation.revoked.clone();
    let ignored_tombstones = reconciliation.ignored_tombstones;
    barrier.admit(reconciliation);

    // 5. the time sample.
    let time = time_sample(clock, channel).await?;
    if time == TimeSample::Accepted {
        barrier.time_sampled(environment);
    }
    let time_bounded = time == TimeSample::Accepted || report.time_bounded;
    Ok(ResyncOutcome {
        acknowledged,
        revoked,
        ignored_tombstones,
        report,
        time,
        time_bounded,
    })
}

/// ⟨M08 W4 SEC-1, S1-02⟩ The scope key kept for a delivered revision whose typed scope has
/// none in this build (never the runner's text): it names no single policy, so the
/// issuer's barrier holds it against every policy.
pub const UNKNOWN_SCOPE_KEY: &str = "unknown";

/// ⟨M08 W4 SEC-1, S1-02; spec §14⟩ The one free string of a runner's authority report, each
/// delivered revision's `scope_key`, replaced at the ingress by the canonical key of the
/// row's own typed scope (`heimdall_store::ext_effects::scope_key`), computed here. What this
/// controller reconciles, stores (`ObservedReport`) and shows (`EarlyCutoff`, `environment
/// status`) is then never the runner's text. Everything else in a report is typed.
fn screen_report(report: &mut AuthorityReport) {
    for row in &mut report.policy_revisions {
        row.scope_key = scope_key(&row.scope).unwrap_or_else(|| UNKNOWN_SCOPE_KEY.to_owned());
    }
}

/// ⟨M08 W4 SEC-1, S1-02⟩ [`screen_report`] for an acknowledgement, before it is stored: a
/// policy revision's `scope_key` is the canonical key of the effect this controller
/// delivered (the acknowledgement's key is checked equal to it first).
fn screen_ack(ack: &mut EffectAck) {
    if let heimdall_store::ext_effects::AppliedRecord::PolicyRevision { scope_key, .. } =
        &mut ack.record
    {
        *scope_key = target_ref(&ack.key.target).unwrap_or_else(|| UNKNOWN_SCOPE_KEY.to_owned());
    }
}

/// One time exchange: the runner's nonce, answered at once with this controller's clock. A
/// runner's refusal is [`TimeSample::Refused`]; only a transport failure is an error.
async fn time_sample(
    clock: &dyn Clock,
    channel: &mut dyn RunnerChannel,
) -> Result<TimeSample, OpError> {
    #[derive(serde::Deserialize)]
    struct Challenge {
        nonce: String,
    }
    let challenge = channel.call(RunnerRequest::TimeChallenge).await?;
    let Ok(Challenge { nonce }) = data::<Challenge>(challenge, "time challenge") else {
        return Ok(TimeSample::Refused);
    };
    let answer = channel
        .call(RunnerRequest::TimeResponse {
            nonce,
            controller_time: clock.wall(),
        })
        .await?;
    Ok(if answer.code == Code::Ok {
        TimeSample::Accepted
    } else {
        TimeSample::Refused
    })
}

/// The session ended (or was lost): close the barrier for `environment`. Issuance for it is
/// gated until the next resynchronization.
pub fn session_ended(barrier: &IssuerBarrier, environment: &EnvironmentId) {
    barrier.close(environment);
}
