//! ⟨M06 W3⟩ The serve allowlist's durable source (ADR-0012 §2.3 item 1 as amended
//! 2026-11-21; ADR-0006 §18.7 items 1–4; m06-plan W3 ruling 4).
//!
//! [`StorePeerEndpoints`] implements U56's [`PeerEndpoints`] port over the runner's
//! `remote_client_endpoints` table (`heimdall_store::Txn::remote_client_endpoints`): every
//! **active**, non-tombstoned paired client's own Iroh endpoint ID, which that client sent
//! over its K_mgmt session in `join` or in its rotation form, and only when its consumed
//! invitation admitted Iroh (`iroh_admission`, confirmed runner-locally with the
//! invitation). The owner never types an endpoint ID. A client's revocation deletes its row
//! in the tombstone's transaction, and a replacement moves the admission authority
//! generation in its transaction, so the serve child's lease is renewed against the new
//! allowlist (`crate::supervise_transport`).
//!
//! The port reads inside the supervisor's authority transaction; any store error is a lost
//! authority (`transport_authority_lost`), never an empty allowlist that hides a failure.

use heimdall_contract::ids::{ClientId, IrohEndpointId};
use heimdall_store::Txn;

use crate::supervise_transport::PeerEndpoints;

/// The runner's recorded client endpoints (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct StorePeerEndpoints;

impl PeerEndpoints for StorePeerEndpoints {
    fn enrolled(
        &self,
        tx: &mut Txn<'_>,
    ) -> heimdall_store::Result<Vec<(ClientId, IrohEndpointId)>> {
        tx.remote_client_endpoints()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::{EnvironmentId, InvitationId, KeyFingerprint};
    use heimdall_contract::remote::Role;
    use heimdall_domain::time::BootId;
    use heimdall_store::ext_m06::{
        AppliedLine, ClientState, InvitationState, JoinRecord, RemoteClientRecord,
        RemoteInvitationRecord, RevocationCause,
    };
    use heimdall_store::{NoFaults, Store};

    use super::*;

    fn at() -> Timestamp {
        "2026-11-21T12:00:00Z".parse().unwrap()
    }

    fn joined(store: &Store, n: u8) -> ClientId {
        let client = ClientId::from_random_bytes([n; 16]);
        let invitation = InvitationId::from_random_bytes([n; 16]);
        let fp = KeyFingerprint::parse(&format!(
            "SHA256:{}",
            char::from(b'A' + n).to_string().repeat(43)
        ))
        .unwrap();
        let record = RemoteClientRecord {
            client: client.clone(),
            role: Role::Requester,
            key_fingerprint: fp.clone(),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Pending,
            invitation: Some(invitation.clone()),
            revoked_generation: None,
            revocation: None,
            created_at: at(),
            updated_at: at(),
            line: AppliedLine::Absent,
        };
        let inv = RemoteInvitationRecord {
            invitation: invitation.clone(),
            client: client.clone(),
            role: Role::Requester,
            key_fingerprint: fp,
            generation: 0,
            created_wall: at(),
            created_boot_id: BootId("b".into()),
            created_elapsed: Duration::from_secs(1),
            expires_wall: "2026-11-21T12:15:00Z".parse().unwrap(),
            elapsed_bound: Duration::from_secs(900),
            probe_nonce: "00".repeat(16),
            state: InvitationState::Pending,
            consumed_at: None,
            join: None,
            iroh_admission: true,
        };
        store
            .transaction(|tx| {
                tx.insert_remote_invitation(&record, &inv, at())?;
                tx.activate_remote_client(&JoinRecord {
                    environment: EnvironmentId::from_random_bytes([9; 16]),
                    invitation,
                    client: client.clone(),
                    role: Role::Requester,
                    generation: 0,
                    joined_at: at(),
                })
                .map(drop)
            })
            .unwrap();
        client
    }

    /// The port lists exactly the active clients' recorded endpoints; a revoked client's
    /// endpoint is gone from it.
    #[test]
    fn the_port_lists_active_clients_endpoints_only() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let a = joined(&store, 1);
        let b = joined(&store, 2);
        let ea = IrohEndpointId::parse(&"a".repeat(64)).unwrap();
        let eb = IrohEndpointId::parse(&"b".repeat(64)).unwrap();
        store
            .transaction(|tx| {
                tx.set_remote_client_endpoint(&a, &ea, at())?;
                tx.set_remote_client_endpoint(&b, &eb, at()).map(drop)
            })
            .unwrap();
        let listed = store
            .transaction(|tx| StorePeerEndpoints.enrolled(tx))
            .unwrap();
        let mut want = vec![(a.clone(), ea), (b.clone(), eb.clone())];
        want.sort();
        assert_eq!(listed, want);
        store
            .transaction(|tx| tx.revoke_remote_client(&a, RevocationCause::Revoked, at()))
            .unwrap();
        assert_eq!(
            store
                .transaction(|tx| StorePeerEndpoints.enrolled(tx))
                .unwrap(),
            vec![(b, eb)]
        );
    }
}
