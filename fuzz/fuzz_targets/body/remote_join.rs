//! Boundary 13 (ADR-0014 §2.1), M06's invitation state: a paired client's request frame,
//! decoded as the runtime decodes a relayed frame (`heimdall_ipc::session::parse_frame`),
//! its join, activation-probe and rotation fields taken by the public
//! `heimdall_remote::invitations::{JoinRequest, ProbeRequest, RotateRequest}::from_request`,
//! and the join decided by the public `decide_join` against one pending invitation.
//!
//! The invariants (ADR-0012 §3.9): an activation names exactly the invitation's own
//! environment, invitation, role and generation, for its own client; the same request never
//! activates under an expired reading (expiry never extends) or from another session's
//! client.
//!
//! Shared by the fuzz target `remote_join` and the seed test
//! `tests/adversarial/m08_fuzz_seeds.rs`.

use std::time::Duration;

use heimdall_contract::ids::{ClientId, EnvironmentId, InvitationId, KeyFingerprint};
use heimdall_contract::ipc::ClientMessage;
use heimdall_contract::remote::Role;
use heimdall_domain::time::{BootId, TimeAnchor};
use heimdall_ipc::session::parse_frame;
use heimdall_remote::invitations::{
    JoinContext, JoinDecision, JoinRequest, ProbeRequest, RotateRequest, TimeReading, decide_join,
};
use heimdall_store::ext_m06::{
    AppliedLine, ClientState, InvitationState, RemoteClientRecord, RemoteInvitationRecord,
};

/// The runner the fixture invitation belongs to.
pub fn runner() -> EnvironmentId {
    EnvironmentId::from_random_bytes([5; 16])
}

/// The pending fixture invitation: created 10:00:00Z in boot `b1` at 1000 s, live for 900 s.
pub fn invitation() -> Option<RemoteInvitationRecord> {
    Some(RemoteInvitationRecord {
        invitation: InvitationId::from_random_bytes([1; 16]),
        client: ClientId::from_random_bytes([1; 16]),
        role: Role::Owner,
        key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "C".repeat(43))).ok()?,
        generation: 1,
        created_wall: "2026-11-20T10:00:00Z".parse().ok()?,
        created_boot_id: BootId("b1".into()),
        created_elapsed: Duration::from_secs(1000),
        expires_wall: "2026-11-20T10:15:00Z".parse().ok()?,
        elapsed_bound: Duration::from_secs(900),
        probe_nonce: "00".repeat(16),
        state: InvitationState::Pending,
        consumed_at: None,
        join: None,
        iroh_admission: false,
    })
}

fn client_of(i: &RemoteInvitationRecord) -> RemoteClientRecord {
    RemoteClientRecord {
        client: i.client.clone(),
        role: i.role,
        key_fingerprint: i.key_fingerprint.clone(),
        public_key: "ssh-ed25519 AAAA".into(),
        state: ClientState::Pending,
        invitation: Some(i.invitation.clone()),
        revoked_generation: None,
        revocation: None,
        created_at: i.created_wall,
        updated_at: i.created_wall,
        line: AppliedLine::Absent,
    }
}

fn reading(wall: &str, continuous: u64) -> Option<TimeReading> {
    Some(TimeReading::safe(&TimeAnchor {
        boot_id: BootId("b1".into()),
        continuous: Duration::from_secs(continuous),
        wall: wall.parse().ok()?,
    }))
}

/// Decode `data` and decide its join under a live reading; `None` when it is not a join
/// request. Panics (a finding) when an invariant of the module docs breaks.
pub fn run(data: &[u8]) -> Option<JoinDecision> {
    let Ok(ClientMessage::Request { request, .. }) = parse_frame::<ClientMessage>(data) else {
        return None;
    };
    let _ = ProbeRequest::from_request(&request);
    let _ = RotateRequest::from_request(&request);
    let join = JoinRequest::from_request(&request)?;
    let inv = invitation()?;
    let client = client_of(&inv);
    let runner = runner();
    let live = reading("2026-11-20T10:05:00Z", 1300)?;
    let expired = reading("2026-11-20T10:15:00Z", 1900)?;
    let decide = |session: &ClientId, now: &TimeReading| {
        decide_join(
            Some(&inv),
            Some(&client),
            session,
            Some(&inv.key_fingerprint),
            &join,
            JoinContext {
                runner: &runner,
                now,
                generation: inv.generation,
                recorded_endpoint: None,
                endpoint_taken: false,
            },
        )
    };
    let decided = decide(&inv.client, &live);
    if let JoinDecision::Activate(record) = &decided {
        assert!(
            join.environment == runner
                && join.invitation == inv.invitation
                && join.role == inv.role
                && join.generation == inv.generation
                && record.client == inv.client
                && record.invitation == inv.invitation,
            "an activation outside the invitation's own binding"
        );
    }
    assert!(
        !matches!(decide(&inv.client, &expired), JoinDecision::Activate(_)),
        "a join activated under an expired reading"
    );
    let other = ClientId::from_random_bytes([2; 16]);
    assert!(
        !matches!(decide(&other, &live), JoinDecision::Activate(_)),
        "a join activated for another session's client"
    );
    Some(decided)
}
