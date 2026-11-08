//! ⟨M03⟩ U0b row 19 (ADR-0008 D8 item 2; §17.1 item 8, §17.4 item 8): the owned
//! **dedicated** connection of a Unix launch, a record separate from the binding's
//! holder.
//!
//! **At bind.** On Unix, `run` and `connect` `exec` the client, so the connection
//! process is the holder process. When a launch binding names a holder and its
//! program is **provably** the verified client, the `dedicated` `owned_connections`
//! row is written in the launch's own transaction (the one that claims the holder),
//! with the holder's PID and start token and the **expected image** (the verified
//! client's path), before the launcher execs. "Provably the verified client" is read
//! from the grant's stored integration (`PreparedFacts.executables`): the launch's
//! executable must equal, byte for byte, the path of an `ssh` consumer executable
//! there. Anything else (no stored integration, another program, a path that differs
//! by a symlink or a case) writes no row: the application cannot resolve paths
//! without `localenv`, so it takes the fail-closed reading (questions file O, Q6).
//!
//! **Windows** never writes the row from the holder: there the launcher spawns the
//! client, and the row comes from `Connections::Register` (U0b row 26).
//!
//! **Cleared** on an observed exit of that exact holder process (PID and start
//! token), in the holder pass's release transaction. A failed exec leaves the
//! launcher (`heimdall`) running as the holder until it exits, which the pass then
//! observes, so a failed exec clears the row the same way.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, ConnectionId, OperationId};
use heimdall_contract::request::{BindForm, ConsumerKind, Request};
use heimdall_domain::binding::BindingRecord;
use heimdall_domain::catalog::PreparedFacts;
use heimdall_domain::holder::ProcessHolder;
use heimdall_domain::managed::{ConnectionKind, OwnedConnection, OwnedConnectionState};
use heimdall_store::Txn;

/// The verified client's path when `executable` is it (module docs): an `ssh`
/// consumer executable of the grant's stored integration with exactly that path.
#[must_use]
pub fn verified_client_image(prepared: Option<&PreparedFacts>, executable: &str) -> Option<String> {
    prepared?
        .executables
        .iter()
        .find(|e| e.consumer == ConsumerKind::Ssh && e.path == executable)
        .map(|e| e.path.clone())
}

/// ⟨M03⟩ U0b row 19: whether a launch registers its own `dedicated` owned connection
/// at bind: only on Unix (`windows` false), only with a holder, and only when the
/// program is the verified client (`image` is [`verified_client_image`]'s answer).
#[must_use]
pub fn dedicated_at_bind(
    windows: bool,
    holder: Option<&ProcessHolder>,
    image: Option<&str>,
) -> bool {
    !windows && holder.is_some() && image.is_some()
}

fn new_connection_id() -> Result<ConnectionId, crate::ids::RandomnessUnavailable> {
    let a = crate::ids::random_u64()?;
    let b = crate::ids::random_u64()?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    Ok(ConnectionId::from_random_bytes(bytes))
}

/// The launch executable of a stored `bind` request, if it is a launch.
pub(super) fn stored_launch_executable(
    tx: &mut Txn<'_>,
    operation: &OperationId,
) -> heimdall_store::Result<Option<String>> {
    Ok(tx
        .recovery_intent(operation)?
        .and_then(|i| serde_json::from_value::<Request>(i.request).ok())
        .and_then(|r| match r {
            Request::Bind(b) => match b.form {
                BindForm::Launch(l) => Some(l.executable),
                BindForm::Materialize => None,
            },
            _ => None,
        }))
}

/// In the launch's transaction, with `holder` just claimed for `binding`: write the
/// `dedicated` row when [`dedicated_at_bind`] says so (module docs). Idempotent: a row
/// already `up` for the same binding, PID and start token is kept.
pub(super) fn register_at_bind(
    tx: &mut Txn<'_>,
    binding: &BindingRecord,
    executable: &str,
    holder: Option<&ProcessHolder>,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let prepared = tx.grant_prepared_facts(&binding.grant)?;
    let image = verified_client_image(prepared.as_ref(), executable);
    let (Some(holder), Some(image)) = (holder, image) else {
        return Ok(());
    };
    if !dedicated_at_bind(cfg!(windows), Some(holder), Some(&image)) {
        return Ok(());
    }
    let present = tx
        .owned_connections_for_binding(&binding.id)?
        .iter()
        .any(|c| {
            c.kind == ConnectionKind::Dedicated
                && c.state == OwnedConnectionState::Up
                && c.pid == holder.pid
                && c.start_token == holder.started_at
        });
    if present {
        return Ok(());
    }
    let id = new_connection_id()
        .map_err(|_| heimdall_store::StoreError::Corrupt("randomness unavailable".into()))?;
    tx.insert_owned_connection(&OwnedConnection {
        id,
        kind: ConnectionKind::Dedicated,
        binding: binding.id.clone(),
        grant: binding.grant.clone(),
        pid: holder.pid,
        start_token: holder.started_at.clone(),
        image,
        control_path: None,
        generation: 0,
        state: OwnedConnectionState::Up,
        started_at: now,
    })
}

/// In the holder pass's release transaction: `holder` was observed exited, so every
/// `dedicated` row of `binding` naming exactly that process moves to `closed`.
pub(super) fn close_on_exit(
    tx: &mut Txn<'_>,
    binding: &BindingId,
    holder: &ProcessHolder,
) -> heimdall_store::Result<()> {
    for c in tx.owned_connections_for_binding(binding)? {
        if c.kind == ConnectionKind::Dedicated
            && c.state != OwnedConnectionState::Closed
            && c.pid == holder.pid
            && c.start_token == holder.started_at
        {
            tx.close_owned_connection(&c.id, c.generation, OwnedConnectionState::Closed)?;
        }
    }
    Ok(())
}
