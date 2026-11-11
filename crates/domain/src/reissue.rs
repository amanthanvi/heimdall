//! ⟨M03⟩ The re-issue rule (ADR-0005 §3.7 "Recovery rule" rules 1–5; ADR-0008 D6
//! item 4): when a lost K_env may be replaced by a new key certified for the same
//! grant. Pure: it reads only its arguments.
//!
//! ⟨wave 4, round 2⟩ ADR-0008 §17.21 item 6 (U10C-Q5 amended): the **one**
//! implementation, here in the domain so both callers reach it without a new crate
//! edge: the managed adapter (`heimdall_adapters::managed::reissue` re-exports this
//! module; `ManagedCertificateAdapter::reissue_from`) and the application's
//! `managed_reissue_pass`, which reads the facts in one store transaction and asks
//! [`eligible`]. No second copy of the rule exists.
//!
//! A re-issue never runs for an expired, revoked or released grant, a grant past a
//! cutoff, a `revoke_on_lock` grant (it ends instead, rule 5), while time is not
//! accepted (the grant stays `degraded`, `credential_reissue_pending`), or for a grant
//! read from anything but the store (rule 4: never from a PID, socket or other process
//! file). It never extends anything: the same pairs and the same D ([`same_grant`]).

use heimdall_contract::Timestamp;
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::{GrantState, ids::GrantId};

use crate::grant::{GrantOrigin, GrantSnapshot};
use crate::time::{Admission, TimeStatus};

/// The mechanism name of a managed grant (`GrantOrigin.mechanism`; the same string as
/// `heimdall_app::operations::MANAGED_CERTIFICATE`, asserted by the runtime's tests).
pub const MANAGED_CERTIFICATE: &str = "managed_certificate";

/// Where the grant snapshot handed to [`eligible`] was read from (rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSource {
    /// The transactional store, with its generation and tombstones.
    Store,
    /// Anything else: a PID file, a socket, a process file, a cached value.
    ProcessFile,
}

/// The store facts [`eligible`] needs beside the snapshot (read in the same store
/// transaction as the snapshot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreRead {
    /// Where the snapshot came from.
    pub source: GrantSource,
    /// A tombstone exists on the grant or an ancestor.
    pub tombstoned: bool,
    /// The covering policy's cutoff, if one is set.
    pub cutoff_at: Option<Timestamp>,
    /// The safe wall time of the assessment.
    pub now: Timestamp,
}

/// Why a re-issue is refused (ADR-0005 §3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReissueRefusal {
    /// Rule 4: the grant was not read from the store.
    NotFromStore,
    /// Rule 1: the grant is not in a state a re-issue may continue (expired,
    /// revoked, released, revoking, or any terminal or not-yet-active state).
    GrantEnded(GrantState),
    /// Rule 1: a tombstone on the grant or an ancestor.
    Tombstoned,
    /// Rule 1: the admission deadline passed.
    DeadlinePassed,
    /// Rule 1: a cutoff covering the grant has passed.
    CutoffPassed,
    /// Rule 3: time is not accepted (`TIME_UNCERTAIN`, or the grant's anchor is of
    /// another boot): the grant stays `degraded` until it is.
    TimeNotAccepted,
    /// Rule 5: the owner chose lock-revokes; the grant ends instead.
    RevokeOnLock,
    /// Rule 2: the pairs differ from the grant's.
    ScopeChanged,
    /// Rule 2: the deadline differs from the grant's.
    DeadlineChanged,
    /// Another grant than the stored one, or not a managed grant.
    NotThisGrant,
}

impl ReissueRefusal {
    /// The nonsecret code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            ReissueRefusal::NotFromStore => "grant_not_from_store",
            ReissueRefusal::GrantEnded(_) => "grant_ended",
            ReissueRefusal::Tombstoned => "tombstoned",
            ReissueRefusal::DeadlinePassed => "deadline_passed",
            ReissueRefusal::CutoffPassed => "cutoff_passed",
            ReissueRefusal::TimeNotAccepted => "time_not_accepted",
            ReissueRefusal::RevokeOnLock => "lock_revokes_chosen",
            ReissueRefusal::ScopeChanged => "scope_changed",
            ReissueRefusal::DeadlineChanged => "deadline_changed",
            ReissueRefusal::NotThisGrant => "not_this_grant",
        }
    }
}

impl std::fmt::Display for ReissueRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "re-issue refused: {}", self.code())
    }
}

impl std::error::Error for ReissueRefusal {}

/// The states a re-issue may continue from: the grant is live and degraded or
/// active (`preparing` is the activation itself, not a re-issue).
fn continuing(state: GrantState) -> bool {
    matches!(state, GrantState::Active | GrantState::Degraded)
}

/// ADR-0005 §3.7 rules 1, 3, 4 and 5 for `grant` (rule 2 is [`same_grant`]).
/// `lock_behavior` is the behaviour in force now; the grant's origin's, recorded at
/// creation, wins when it is `revoke_on_lock` (either one refuses).
///
/// # Errors
/// [`ReissueRefusal`], the first rule that fails, in rule order 4, 1, 5, 3.
pub fn eligible(
    grant: &GrantSnapshot,
    origin: &GrantOrigin,
    time: &TimeStatus,
    admission: &Admission,
    lock_behavior: LockBehavior,
    read: &StoreRead,
) -> Result<(), ReissueRefusal> {
    if read.source != GrantSource::Store {
        return Err(ReissueRefusal::NotFromStore);
    }
    if origin.mechanism != MANAGED_CERTIFICATE {
        return Err(ReissueRefusal::NotThisGrant);
    }
    if !continuing(grant.state) {
        return Err(ReissueRefusal::GrantEnded(grant.state));
    }
    if read.tombstoned {
        return Err(ReissueRefusal::Tombstoned);
    }
    if read.now >= grant.deadline.effective || *admission == Admission::Expired {
        return Err(ReissueRefusal::DeadlinePassed);
    }
    if read.cutoff_at.is_some_and(|c| read.now >= c) {
        return Err(ReissueRefusal::CutoffPassed);
    }
    if lock_behavior == LockBehavior::RevokeOnLock
        || origin.lock_behavior == Some(LockBehavior::RevokeOnLock)
    {
        return Err(ReissueRefusal::RevokeOnLock);
    }
    if *time != TimeStatus::Safe || *admission == Admission::NeedsAnchor {
        return Err(ReissueRefusal::TimeNotAccepted);
    }
    Ok(())
}

/// What a re-issue certifies: exactly the stored grant's pairs, up to exactly its
/// deadline (rule 2). Nothing in it can be wider than the stored grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReissuePlan {
    /// The grant.
    pub grant: GrantId,
    /// The stored grant's pairs.
    pub pairs: Vec<crate::scope::AccessPair>,
    /// The stored grant's effective deadline: every certificate's `valid_before` is
    /// at most this.
    pub valid_before: Timestamp,
}

/// Rule 2: `requested` must be the stored grant, with the same pairs and the same
/// deadline; the plan is built from `stored` only, so it never widens or extends it.
///
/// # Errors
/// [`ReissueRefusal::NotThisGrant`], [`ReissueRefusal::ScopeChanged`],
/// [`ReissueRefusal::DeadlineChanged`].
pub fn same_grant(
    stored: &GrantSnapshot,
    requested: &GrantSnapshot,
) -> Result<ReissuePlan, ReissueRefusal> {
    if stored.id != requested.id {
        return Err(ReissueRefusal::NotThisGrant);
    }
    if stored.scope.pairs != requested.scope.pairs {
        return Err(ReissueRefusal::ScopeChanged);
    }
    if stored.deadline.effective != requested.deadline.effective {
        return Err(ReissueRefusal::DeadlineChanged);
    }
    Ok(ReissuePlan {
        grant: stored.id.clone(),
        pairs: stored.scope.pairs.iter().cloned().collect(),
        valid_before: stored.deadline.effective,
    })
}
