//! ⟨M03⟩ U0b row 26 (G): the Windows owned-connection registration (ADR-0008 D8 item 2;
//! §17.4 item 8, §17.13 item 1).
//!
//! [`Operations::register_owned_connection`] resolves the binding to its grant, checks
//! the pending mark (in memory, before any grant check), takes the grant's gate
//! **shared** within `signing_gate_wait`, and in one transaction, bounded by
//! `connection_registration_txn_max`, re-checks the grant (not ended, no tombstone on
//! it or an ancestor, deadline not passed, `Safe` time, current generation) and writes
//! the `owned_connections` row. Any failure is `ConnError::RegistrationRefused` with a
//! fixed nonsecret reason, and the launcher kills the still-suspended child. A narrowing
//! takes the gate exclusively before its commit, so each registration is ordered with
//! each revocation. A grant with no gate (no credential instance) is ordered by the
//! store alone: its narrowing reads, re-checks and commits in one transaction.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, ConnectionId, GrantId};
use heimdall_domain::managed::{ConnectionKind, OwnedConnection, OwnedConnectionState};
use heimdall_domain::time::{self as dtime, Admission};

use super::{Operations, ancestry, bound_of, grant_context, revalidate_chain};
use crate::managed::GateError;
use crate::ports::ConnError;

/// The refusal reasons (fixed nonsecret words; `connection_registration_refused`).
pub(super) mod refused {
    /// The grant or an ancestor is marked `narrowing_pending`.
    pub const NARROWING_PENDING: &str = "narrowing_pending";
    /// The binding is unknown, released, of another environment, or held by no launcher.
    pub const BINDING_UNKNOWN: &str = "binding_unknown";
    /// The grant has ended (or is not usable).
    pub const GRANT_ENDED: &str = "grant_ended";
    /// A tombstone on the grant or an ancestor.
    pub const TOMBSTONED: &str = "tombstoned";
    /// The deadline (or the continuous budget) passed.
    pub const DEADLINE_PASSED: &str = "deadline_passed";
    /// Time is not `Safe`.
    pub const TIME_UNCERTAIN: &str = "time_uncertain";
    /// The generation moved and re-validation did not restore it.
    pub const STALE_GENERATION: &str = "stale_generation";
    /// The gate was not obtained within `signing_gate_wait`.
    pub const GATE_TIMEOUT: &str = "gate_timeout";
    /// The transaction exceeded `connection_registration_txn_max`.
    pub const TXN_TIMEOUT: &str = "registration_txn_timeout";
}

fn refuse(reason: &str) -> ConnError {
    ConnError::RegistrationRefused(reason.to_owned())
}

fn new_connection_id() -> Result<ConnectionId, ConnError> {
    let a = crate::ids::random_u64().map_err(|_| ConnError::Unavailable("randomness".into()))?;
    let b = crate::ids::random_u64().map_err(|_| ConnError::Unavailable("randomness".into()))?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    Ok(ConnectionId::from_random_bytes(bytes))
}

impl Operations {
    /// ⟨M03⟩ U0b row 26: register the still-suspended contained `ssh.exe` of `binding`
    /// (`pid`, its `created_at` creation time, its verified `image`) as an owned
    /// dedicated connection.
    ///
    /// # Errors
    /// `ConnError::RegistrationRefused(reason)` (see the module documentation);
    /// `ConnError::Unavailable` when the store cannot be read.
    pub async fn register_owned_connection(
        &self,
        binding: &BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &str,
    ) -> Result<OwnedConnection, ConnError> {
        let limits = *self.limits();
        let env = self.environment().clone();
        let b = binding.clone();
        let found = self
            .write(move |tx, _| {
                let Some(rec) = tx.binding(&b)? else {
                    return Ok(None);
                };
                if rec.environment != env || rec.released_at.is_some() {
                    return Ok(None);
                }
                // ⟨M03 wave 3⟩ ADR-0008 §17.20 item 14 (U7-Q4); m03-plan §5 item 4a: only a
                // launch binding its launcher holds registers a dedicated connection (the
                // store refuses the row otherwise).
                if tx.binding_holder(&b)?.is_none() {
                    return Ok(None);
                }
                let chain: Vec<GrantId> = match tx.grant(&rec.grant)? {
                    Some(g) => ancestry(tx, &g)?.into_iter().map(|a| a.id).collect(),
                    None => Vec::new(),
                };
                Ok(Some((rec.grant, chain)))
            })
            .await
            .map_err(|_| ConnError::Unavailable("store".into()))?;
        let Some((grant, ancestors)) = found else {
            return Err(refuse(refused::BINDING_UNKNOWN));
        };
        // The pending mark first, before any check of the grant.
        let gates = self.signing_gates();
        if gates.is_pending_with(&grant, &ancestors) {
            return Err(refuse(refused::NARROWING_PENDING));
        }
        let shared = match gates.admit_shared(&grant, limits.signing_gate_wait).await {
            Ok(s) => Some(s),
            Err(GateError::NoGate) => None,
            Err(GateError::Pending) => return Err(refuse(refused::NARROWING_PENDING)),
            Err(_) => return Err(refuse(refused::GATE_TIMEOUT)),
        };
        let id = new_connection_id()?;
        let env = self.environment().clone();
        let adapters = self.adapter_infos();
        let gate = self.inner.timegate.in_txn();
        let (b, image) = (binding.clone(), image.to_owned());
        let started = std::time::Instant::now();
        let max = limits.connection_registration_txn_max;
        let done = self
            .write(move |tx, _| {
                let Some(g) = tx.grant(&grant)? else {
                    return Ok(Err(refused::GRANT_ENDED));
                };
                if tx.denied_ancestor(&grant)?.is_some() {
                    return Ok(Err(refused::TOMBSTONED));
                }
                if !g.state.permits_use() {
                    return Ok(Err(refused::GRANT_ENDED));
                }
                let Ok(safe) = gate.check(tx)? else {
                    return Ok(Err(refused::TIME_UNCERTAIN));
                };
                let ctx = grant_context(tx, &g)?;
                let bound = bound_of(tx, &env, &g, ctx.profile.as_ref())?;
                if dtime::is_expired(safe.wall(), bound)
                    || gate.admission(tx, &grant, &safe)? != Admission::Open
                {
                    return Ok(Err(refused::DEADLINE_PASSED));
                }
                if revalidate_chain(tx, &env, &adapters, &g, safe.wall())?.is_err() {
                    return Ok(Err(refused::STALE_GENERATION));
                }
                if started.elapsed() > max {
                    return Ok(Err(refused::TXN_TIMEOUT));
                }
                let connection = OwnedConnection {
                    id,
                    kind: ConnectionKind::Dedicated,
                    binding: b,
                    grant: grant.clone(),
                    pid,
                    start_token: created_at.to_string(),
                    image,
                    control_path: None,
                    generation: tx.authority_generation()?.0,
                    state: OwnedConnectionState::Up,
                    started_at: safe.wall(),
                };
                tx.insert_owned_connection(&connection)?;
                Ok(Ok(connection))
            })
            .await
            .map_err(|_| ConnError::Unavailable("store".into()))?;
        drop(shared);
        done.map_err(refuse)
    }
}
