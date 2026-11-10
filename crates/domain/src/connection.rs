//! ⟨M03⟩ Connection policies: the effective policy and the closing table
//! (ADR-0008 D8 items 1–3; m03-plan §5 items 5–6).
//!
//! The policy types are wire-visible (policy actions, `ensure` requests and
//! reports carry them), so they live in `heimdall_contract::managed` and are
//! re-exported here. This module owns the two pure rules every layer shares: the
//! effective (strictest) policy of a grant, and which owned connections an end
//! event closes.

use heimdall_contract::managed::ConnectionRequest;

pub use heimdall_contract::managed::{
    CloseReason, ConnectionKind, ConnectionPolicy, ExistingConnectionsMode, MultiplexingMode,
};

use crate::policy::strictest_connection_policy;

/// ADR-0008 D8 item 1: a grant's effective connection policy is the strictest of
/// the value recorded in its `GrantOrigin` at activation, every current applicable
/// policy, and the request. A request may only narrow `existing` (a `graceful`
/// request is refused by the application before this point; here it narrows
/// nothing). An empty input is the default policy.
#[must_use]
pub fn effective_connection_policy(
    origin: Option<ConnectionPolicy>,
    policies: &[ConnectionPolicy],
    request: Option<&ConnectionRequest>,
) -> ConnectionPolicy {
    let mut out = origin.unwrap_or_default();
    for p in policies {
        out = strictest_connection_policy(out, *p);
    }
    if let Some(ConnectionRequest {
        existing: Some(ExistingConnectionsMode::Strict),
    }) = request
    {
        out.existing = ExistingConnectionsMode::Strict;
    }
    out
}

/// An event that may end owned connections (ADR-0008 D8 item 2 table, item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionEnd {
    /// The admission deadline passed.
    AdmissionDeadline,
    /// A cutoff passed.
    Cutoff,
    /// The grant was revoked.
    Revocation,
    /// `revoke_on_lock` after a session lock.
    SessionLocked,
    /// The last reference was released.
    Release,
    /// Time became uncertain.
    TimeUncertain,
}

impl ConnectionEnd {
    /// Every event.
    pub const ALL: [ConnectionEnd; 6] = [
        ConnectionEnd::AdmissionDeadline,
        ConnectionEnd::Cutoff,
        ConnectionEnd::Revocation,
        ConnectionEnd::SessionLocked,
        ConnectionEnd::Release,
        ConnectionEnd::TimeUncertain,
    ];

    /// The wire close reason.
    #[must_use]
    pub fn reason(self) -> CloseReason {
        match self {
            ConnectionEnd::AdmissionDeadline => CloseReason::AdmissionDeadline,
            ConnectionEnd::Cutoff => CloseReason::Cutoff,
            ConnectionEnd::Revocation => CloseReason::Revocation,
            ConnectionEnd::SessionLocked => CloseReason::SessionLocked,
            ConnectionEnd::Release => CloseReason::Release,
            ConnectionEnd::TimeUncertain => CloseReason::TimeUncertain,
        }
    }
}

/// ADR-0008 D8 item 2's table for an owned **dedicated** connection: revocation and
/// `revoke_on_lock` close it under both policies; the deadline, a cutoff, release
/// and `TIME_UNCERTAIN` close it only under `strict` (`graceful` keeps it). A mode
/// this build does not know closes (fail closed).
#[must_use]
pub fn dedicated_closes(event: ConnectionEnd, existing: ExistingConnectionsMode) -> bool {
    match event {
        ConnectionEnd::Revocation | ConnectionEnd::SessionLocked => true,
        ConnectionEnd::AdmissionDeadline
        | ConnectionEnd::Cutoff
        | ConnectionEnd::Release
        | ConnectionEnd::TimeUncertain => existing != ExistingConnectionsMode::Graceful,
    }
}

/// ADR-0008 D8 item 3: an owned **master** is closed at every end event under both
/// policies (sessions shared through it end at the deadline even under `graceful`).
#[must_use]
pub fn master_closes(event: ConnectionEnd) -> bool {
    let _ = event;
    true
}

/// Whether an end event closes an owned connection of `kind` under `existing`.
#[must_use]
pub fn closes(
    kind: ConnectionKind,
    event: ConnectionEnd,
    existing: ExistingConnectionsMode,
) -> bool {
    match kind {
        ConnectionKind::Master => master_closes(event),
        ConnectionKind::Dedicated => dedicated_closes(event, existing),
        // A kind this build does not know is closed (fail closed).
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_table() {
        use ExistingConnectionsMode::{Graceful, Strict};
        for e in ConnectionEnd::ALL {
            assert!(dedicated_closes(e, Strict), "{e:?}");
            assert!(master_closes(e));
            let graceful_closes =
                matches!(e, ConnectionEnd::Revocation | ConnectionEnd::SessionLocked);
            assert_eq!(dedicated_closes(e, Graceful), graceful_closes, "{e:?}");
        }
    }

    #[test]
    fn effective_policy_is_strictest() {
        let strict = ConnectionRequest {
            existing: Some(ExistingConnectionsMode::Strict),
        };
        let p = effective_connection_policy(None, &[], Some(&strict));
        assert_eq!(p.existing, ExistingConnectionsMode::Strict);
        let masters = ConnectionPolicy {
            existing: ExistingConnectionsMode::Graceful,
            multiplexing: MultiplexingMode::OwnedMasters,
        };
        let p = effective_connection_policy(Some(masters), &[ConnectionPolicy::default()], None);
        assert_eq!(p.multiplexing, MultiplexingMode::Disabled);
        assert_eq!(
            effective_connection_policy(Some(masters), &[masters], None),
            masters
        );
    }
}
