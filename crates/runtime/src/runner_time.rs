//! ⟨M06 U3⟩ The runner's designated time source (ADR-0012 §4.4; ADR-0005 §3.6 "Runner
//! deadline"; m06-plan U3).
//!
//! * **Who may answer.** Only the one `owner` client the owner designated runner-locally as
//!   this runner's time source ([`designate_time_source`], a widening confirmed by an attended
//!   session local to the runner; the store's `runner_time_source`). The client's row is reread
//!   for every challenge and answer: a client no longer active, or no longer `owner`, counts
//!   for nothing.
//! * **Fresh and session-bound.** [`RunnerTime::challenge`] draws a 128-bit nonce from the OS
//!   CSPRNG, bound to the asking session ([`TimeSession`]: the client and its connection) and
//!   to the runner's continuous clock reading `t₁` in this boot. An answer
//!   ([`RunnerTime::respond`]) counts only on the same session, once (a replay finds no
//!   nonce), in the same boot, and when `t₂ − t₁` is within the RTT bound
//!   ([`RunnerTimePolicy::rtt_bound`]; G09 sets the value, [`DEFAULT_RTT_BOUND`] meanwhile).
//! * **Never extends.** A qualifying answer `(t₁, T_c, t₂)` only moves anchors **earlier**: each
//!   pinned runner grant's anchor in this boot becomes the earliest of its budget and `t₂ +
//!   (bound − (T_c + (t₂ − t₁)))` (`heimdall_app::readiness_runner::shorten_runner_anchor`; the
//!   store refuses a longer budget). It never moves a bound or a deadline.
//! * **Never `confirm_time`.** No answer writes the runtime anchor, the high-water mark or an
//!   attended time confirmation: the local time gate's verdict is untouched.
//! * **Without a qualifying sample** in this boot the runner's time is uncertain
//!   ([`RunnerTime::bounded`] false): installation answers `TIME_UNCERTAIN` and readiness
//!   reports no derived anchor.
//!
//! Samples are process state: a restart (which also loses every K_env) needs a fresh exchange,
//! like a reboot (fail closed; the re-issue that follows needs the controller anyway).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use heimdall_app::OpError;
use heimdall_app::readiness_runner::{TimeExchange, runner_bound, shorten_runner_anchor};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::ClientId;
use heimdall_contract::remote::Role;
use heimdall_domain::time::{BootId, Clock};
use heimdall_store::ext_m06::ClientState;
use heimdall_store::ext_runner::TimeSourceDesignation;
use heimdall_store::{Store, Txn};
use serde::{Deserialize, Serialize};

/// The RTT bound used until G09 sets one (ADR-0012 §4.4 "only within the RTT bound G09 sets").
pub const DEFAULT_RTT_BOUND: Duration = Duration::from_secs(2);

/// The most challenges outstanding at once; a new one evicts the oldest.
pub const MAX_OUTSTANDING_CHALLENGES: usize = 16;

/// The nonce's length in lowercase hex characters (128 bits).
pub const NONCE_HEX_CHARS: usize = 32;

/// The runner's time-sample policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerTimePolicy {
    /// The largest `t₂ − t₁` an answer may take and still count.
    pub rtt_bound: Duration,
}

impl Default for RunnerTimePolicy {
    fn default() -> Self {
        Self {
            rtt_bound: DEFAULT_RTT_BOUND,
        }
    }
}

/// The session a challenge is bound to: the paired client and its connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TimeSession {
    /// The paired client (from the role table, never a request field).
    pub client: ClientId,
    /// The connection's serial, unique among the runtime's live connections.
    pub connection: u64,
}

/// The data of `runner.time_challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeChallengeData {
    /// The fresh nonce to echo in `runner.time_response`.
    pub nonce: String,
    /// How long, in milliseconds, an answer can still count.
    pub rtt_bound_ms: u64,
}

/// The data of an accepted `runner.time_response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSampleAccepted {
    /// `t₂ − t₁`, in milliseconds.
    pub rtt_ms: u64,
    /// How many grant anchors moved earlier.
    pub anchors_shortened: u32,
}

/// Why a challenge or an answer does not count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum TimeRefusal {
    /// The client is not this runner's designated time source (or none is designated).
    #[error("the client is not this runner's designated time source")]
    NotDesignated,
    /// The designated client is no longer an active owner.
    #[error("the designated time source is no longer an active owner client")]
    NotActiveOwner,
    /// No outstanding challenge on this session has that nonce (never issued, already
    /// answered, issued on another session, or evicted).
    #[error("the answer matches no outstanding challenge of this session")]
    UnknownNonce,
    /// The answer took longer than the RTT bound.
    #[error("the answer arrived outside the RTT bound")]
    RttExceeded,
    /// The challenge belongs to another boot.
    #[error("the challenge belongs to another boot")]
    OtherBoot,
    /// The OS CSPRNG failed: no nonce.
    #[error("the system random number generator is unavailable")]
    Randomness,
    /// The state store failed.
    #[error("the state store is unavailable")]
    State,
}

impl TimeRefusal {
    /// The envelope error: an answer that does not qualify leaves time uncertain
    /// (`TIME_UNCERTAIN`, ADR-0005 §3.6 "a replayed or unauthenticated answer"); a client that
    /// is not the designated owner is refused `role_insufficient`.
    #[must_use]
    pub fn to_error(self) -> OpError {
        let e = match self {
            Self::NotDesignated | Self::NotActiveOwner => {
                OpError::new(Code::CapabilityUnavailable, self.to_string())
                    .with_reason(reason::ROLE_INSUFFICIENT)
            }
            Self::UnknownNonce | Self::RttExceeded | Self::OtherBoot => {
                OpError::new(Code::TimeUncertain, format!("time uncertain: {self}"))
            }
            Self::Randomness => OpError::new(Code::ServiceUnavailable, self.to_string()),
            Self::State => OpError::new(Code::StateUnavailable, self.to_string()),
        };
        e.with_resource("clock", None)
    }
}

/// One qualifying sample: the exchange and the client that answered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifyingSample {
    /// The designated client that answered.
    pub client: ClientId,
    /// The exchange.
    pub exchange: TimeExchange,
}

#[derive(Debug, Clone)]
struct Challenge {
    session: TimeSession,
    designation: TimeSourceDesignation,
    boot_id: BootId,
    t1: Duration,
    seq: u64,
}

#[derive(Debug)]
struct CommittedSample {
    designation: TimeSourceDesignation,
    sample: QualifyingSample,
}

#[derive(Debug, Default)]
struct State {
    outstanding: HashMap<String, Challenge>,
    seq: u64,
    latest: Option<CommittedSample>,
}

/// The runner's time-sample state (module docs). One per runner runtime.
pub struct RunnerTime {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    policy: RunnerTimePolicy,
    // Serializes a source change with the commit and publication of a response. Never
    // acquired from a store transaction. Readers need only the store and `state`.
    updates: Mutex<()>,
    state: Mutex<State>,
}

impl std::fmt::Debug for RunnerTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerTime")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Whether `client` is an active `owner` in the role table (reread now).
fn active_owner(tx: &mut Txn<'_>, client: &ClientId) -> heimdall_store::Result<bool> {
    Ok(tx
        .remote_client(client)?
        .is_some_and(|r| r.state == ClientState::Active && r.role == Role::Owner))
}

/// The designated time source, checked: `client` is designated and still an active owner.
fn check_designated(
    tx: &mut Txn<'_>,
    client: &ClientId,
) -> Result<TimeSourceDesignation, TimeRefusal> {
    let designation = tx
        .time_source()
        .map_err(|_| TimeRefusal::State)?
        .filter(|d| &d.client == client)
        .ok_or(TimeRefusal::NotDesignated)?;
    if !active_owner(tx, client).map_err(|_| TimeRefusal::State)? {
        return Err(TimeRefusal::NotActiveOwner);
    }
    Ok(designation)
}

/// Designate `client` as this runner's time source (module docs). The caller is an attended
/// session **local to the runner** that confirmed it (ADR-0012 §3.10; a paired session never
/// reaches this). Refused unless `client` is an active `owner`.
///
/// # Errors
///
/// [`TimeRefusal::NotActiveOwner`], or [`TimeRefusal::State`].
pub fn designate_time_source(
    tx: &mut Txn<'_>,
    client: &ClientId,
    now: Timestamp,
) -> Result<(), TimeRefusal> {
    if !active_owner(tx, client).map_err(|_| TimeRefusal::State)? {
        return Err(TimeRefusal::NotActiveOwner);
    }
    tx.designate_time_source(&TimeSourceDesignation {
        client: client.clone(),
        designated_at: now,
    })
    .map_err(|_| TimeRefusal::State)
}

fn fresh_nonce() -> Result<String, TimeRefusal> {
    let mut bytes = [0u8; NONCE_HEX_CHARS / 2];
    heimdall_credential::vault::SystemRng::fill(&mut bytes).map_err(|_| TimeRefusal::Randomness)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl RunnerTime {
    /// New state over the runner's store and clock.
    #[must_use]
    pub fn new(store: Arc<Store>, clock: Arc<dyn Clock>, policy: RunnerTimePolicy) -> Self {
        Self {
            store,
            clock,
            policy,
            updates: Mutex::new(()),
            state: Mutex::new(State::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> RunnerTimePolicy {
        self.policy
    }

    /// Apply a designation change and invalidate samples and challenges from the old one.
    pub(crate) fn change_source<T, E>(&self, apply: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let _update = self.updates.lock().unwrap_or_else(PoisonError::into_inner);
        {
            let mut state = self.lock();
            state.latest = None;
            state.outstanding.clear();
        }
        apply()
    }

    /// ⟨M08 W4 SEC-3a, S2-02⟩ Forget the cached sample when it came from `client` (called on
    /// revocation of `client`).
    pub(crate) fn invalidate_client(&self, client: &ClientId) {
        let _update = self.updates.lock().unwrap_or_else(PoisonError::into_inner);
        let mut s = self.lock();
        if s.latest
            .as_ref()
            .is_some_and(|l| &l.sample.client == client)
        {
            s.latest = None;
        }
        s.outstanding.retain(|_, c| &c.session.client != client);
    }

    pub(super) fn issue_challenge(
        &self,
        session: &TimeSession,
    ) -> Result<TimeChallengeData, TimeRefusal> {
        let _update = self.updates.lock().unwrap_or_else(PoisonError::into_inner);
        self.store
            .transaction(|tx| Ok(self.challenge(tx, session)))
            .map_err(|_| TimeRefusal::State)?
    }

    /// `runner.time_challenge` (module docs): a fresh nonce bound to `session` and to `t₁` now.
    /// Only the designated time source is answered.
    ///
    /// # Errors
    ///
    /// [`TimeRefusal::NotDesignated`], [`TimeRefusal::NotActiveOwner`],
    /// [`TimeRefusal::Randomness`], [`TimeRefusal::State`].
    pub fn challenge(
        &self,
        tx: &mut Txn<'_>,
        session: &TimeSession,
    ) -> Result<TimeChallengeData, TimeRefusal> {
        let designation = check_designated(tx, &session.client)?;
        let nonce = fresh_nonce()?;
        let now = self.clock.observe();
        let mut s = self.lock();
        let bound = self.policy.rtt_bound;
        // Challenges that can no longer qualify are dropped; then the oldest beyond the cap.
        s.outstanding.retain(|_, c| {
            c.boot_id == now.boot_id && now.continuous.saturating_sub(c.t1) <= bound
        });
        while s.outstanding.len() >= MAX_OUTSTANDING_CHALLENGES {
            let Some(oldest) = s
                .outstanding
                .iter()
                .min_by_key(|(_, c)| c.seq)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            s.outstanding.remove(&oldest);
        }
        s.seq = s.seq.wrapping_add(1);
        let seq = s.seq;
        s.outstanding.insert(
            nonce.clone(),
            Challenge {
                session: session.clone(),
                designation,
                boot_id: now.boot_id,
                t1: now.continuous,
                seq,
            },
        );
        Ok(TimeChallengeData {
            nonce,
            rtt_bound_ms: millis(bound),
        })
    }

    /// `runner.time_response` (module docs): count `controller_time` for `nonce` on `session`
    /// and move every pinned runner grant's anchor earlier, in one store transaction. The nonce
    /// is consumed whatever the verdict (a second answer finds nothing).
    ///
    /// ⟨M08 W4 SEC-3a, S3-05⟩ The in-memory `latest` sample is updated only **after** the
    /// SQLite transaction commits: a failed commit rolls back anchor changes and leaves
    /// `latest` untouched.
    ///
    /// # Errors
    ///
    /// The [`TimeRefusal`] that applies; nothing is written or kept then.
    pub fn respond(
        &self,
        session: &TimeSession,
        nonce: &str,
        controller_time: Timestamp,
    ) -> Result<TimeSampleAccepted, TimeRefusal> {
        // The arrival time t₂ is read first, then the nonce consumed: whatever follows, the
        // answer is judged by when it arrived.
        let arrival = self.clock.observe();
        let _update = self.updates.lock().unwrap_or_else(PoisonError::into_inner);
        let challenge = {
            let mut s = self.lock();
            match s.outstanding.get(nonce) {
                Some(c) if c.session == *session => s.outstanding.remove(nonce),
                _ => None,
            }
        };
        let Some(challenge) = challenge else {
            return Err(TimeRefusal::UnknownNonce);
        };
        let (exchange, rtt, shortened) = self
            .store
            .transaction(|tx| {
                match check_designated(tx, &session.client) {
                    Ok(designation) if designation == challenge.designation => {}
                    Ok(_) => return Ok(Err(TimeRefusal::NotDesignated)),
                    Err(refusal) => return Ok(Err(refusal)),
                }
                if challenge.boot_id != arrival.boot_id {
                    return Ok(Err(TimeRefusal::OtherBoot));
                }
                let rtt = arrival.continuous.saturating_sub(challenge.t1);
                if arrival.continuous < challenge.t1 || rtt > self.policy.rtt_bound {
                    return Ok(Err(TimeRefusal::RttExceeded));
                }
                let exchange = TimeExchange {
                    boot_id: arrival.boot_id.clone(),
                    t1: challenge.t1,
                    t2: arrival.continuous,
                    controller_time,
                };
                // Propagate store errors out of the transaction closure so SQLite rolls back.
                let shortened = self.apply(tx, &exchange)?;
                Ok(Ok((exchange, rtt, shortened)))
            })
            .map_err(|_| TimeRefusal::State)??;
        // Commit succeeded: keep the sample in memory only now.
        self.lock().latest = Some(CommittedSample {
            designation: challenge.designation,
            sample: QualifyingSample {
                client: session.client.clone(),
                exchange,
            },
        });
        Ok(TimeSampleAccepted {
            rtt_ms: millis(rtt),
            anchors_shortened: shortened,
        })
    }

    /// Move every pinned, still-issuable runner grant's anchor earlier from `exchange`.
    fn apply(&self, tx: &mut Txn<'_>, exchange: &TimeExchange) -> heimdall_store::Result<u32> {
        let now = self.clock.observe();
        let mut shortened = 0u32;
        for pin in tx.remote_grant_issuers()? {
            let Some(grant) = tx.grant(&pin.grant)? else {
                continue;
            };
            if !grant.state.permits_issuance() {
                continue;
            }
            let before = tx.grant_anchor(&grant.id)?;
            let bound = runner_bound(tx, &grant)?.bound;
            let after = shorten_runner_anchor(tx, &grant.id, bound, exchange, &now, false)?;
            if after.is_some() && after != before {
                shortened = shortened.saturating_add(1);
            }
        }
        Ok(shortened)
    }

    /// ⟨M08 W4 SEC-3a, S2-02⟩ The latest qualifying sample of **this** boot, verified inside
    /// `tx` to still belong to the currently designated active owner time source. Fails closed
    /// (`None`) on any designation change, revocation, boot mismatch, or store error.
    #[must_use]
    pub(super) fn sample_in(&self, tx: &mut Txn<'_>) -> Option<QualifyingSample> {
        let boot = self.clock.boot_id();
        let state = self.lock();
        let latest = state
            .latest
            .as_ref()
            .filter(|s| s.sample.exchange.boot_id == boot)?;
        let designation = check_designated(tx, &latest.sample.client).ok()?;
        (designation == latest.designation).then(|| latest.sample.clone())
    }

    /// ⟨M08 W4 SEC-3a, S2-02⟩ The latest qualifying sample of **this** boot whose client is
    /// still the currently designated active owner time source, failing closed on any mismatch
    /// or store error.
    #[must_use]
    pub fn sample(&self) -> Option<QualifyingSample> {
        self.store
            .transaction(|tx| Ok(self.sample_in(tx)))
            .ok()
            .flatten()
    }

    /// Whether a qualifying sample bounds the runner's offset in this boot.
    #[must_use]
    pub fn bounded(&self) -> bool {
        self.sample().is_some()
    }

    /// Drop every outstanding challenge of `session` (the session ended).
    pub fn forget_session(&self, session: &TimeSession) {
        self.lock().outstanding.retain(|_, c| c.session != *session);
    }
}
