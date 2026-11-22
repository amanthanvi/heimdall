//! ⟨M06 U4, U4b⟩ Resynchronization over a management session, the paired dispatch path, and
//! the second controller (m06-plan U4 "adapter", U4b; ADR-0012 §7.4–§7.5, §8; M06-T06).
//!
//! The runner is its real store, operations, runner runtime and sync service; a controller is
//! its real outbox, resynchronization and issuer barrier over its own store
//! (`runner_sync_fixture_m06`). Disposable state only.
//!
//! **Adapter rows (A07's runner rows):**
//! * a reconnect with uncertain time on the runner still applies tombstones and policy
//!   revisions, and issuance stays gated;
//! * the issuing controller reconnects after the other controller revoked its grant: its
//!   issuer marks the grant revoked and counts the residual before any reserve;
//! * a changed host key, a substituted environment ID or client gives `held`, with nothing
//!   sent and nothing reset;
//! * the paired dispatch path: `runner.deliver_effect` and `runner.authority_report` reach
//!   the sync service through `PairedRunner::runner_request`.
//!
//! **T06 (the second controller):** wrong role, invitation replay, route substitution, an
//! untrusted issuer, renewal without an issuer.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "runner_fixture_m06.rs"]
mod fixture;
#[path = "runner_sync_fixture_m06.rs"]
mod sync_fixture;

use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use heimdall_app::OpError;
use heimdall_app::context::Caller;
use heimdall_app::remote_env_second::{IssuerStanding, issuer_standing, narrow};
use heimdall_app::remote_status::{
    IssuanceGate, Narrowing, TimeSample, is_held, note_open_failure,
};
use heimdall_app::remote_status_barrier::{
    BarrierRefusal, CountedResidual, authentication_residual_of, counted_residual,
    residual_statement,
};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{EnvironmentId, GrantId, KeyFingerprint};
use heimdall_contract::managed::DestinationClock;
use heimdall_contract::remote::{
    Connectivity, EffectTarget, ManagementPolicy, Role, RunnerRequest,
};
use heimdall_contract::trust::PolicyTarget;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::issuance::IssuanceState;
use heimdall_domain::policy::PauseState;
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::Clock;
use heimdall_remote::invitations::{Invitations, JoinRequest, NewInvitation, TimeReading};
use heimdall_remote::line::{PublicKeyText, ServeCommand};
use heimdall_remote::testing::MemoryLines;
use heimdall_runtime::paired::{PairedRunner, RunnerOptions};
use heimdall_runtime::runner::RunnerRuntime;
use heimdall_runtime::runner::issuance::IssuanceFailure;
use heimdall_store::ext_effects::{AppliedRecord, AuthorityReport, EffectAck};
use heimdall_store::ext_m06::ClientState;
use sync_fixture::*;

const MINUTE: Duration = Duration::from_secs(60);

fn revoke_of(r: &Rig) -> Narrowing {
    Narrowing::RevokeGrant {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    }
}

/// Prepare the fixture grant for controller A, take a good sample, install one certificate
/// for `h1` valid for an hour. Returns its `valid_before`.
fn issue_from_a(r: &Rig) -> Timestamp {
    let w = &r.w;
    w.trust(&w.ca_a, &controller_a());
    let g = w.generation();
    let prepared = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, g)
        .unwrap();
    w.good_sample();
    let valid_before = Timestamp::from_second(plus(w.clock.wall(), HOUR).as_second()).unwrap();
    let cert = w.sign(&w.ca_a, &prepared, &pair("h1"), valid_before);
    w.runner
        .issuance()
        .install(&controller_a(), &w.grant, g, &cert)
        .unwrap();
    valid_before
}

fn reason_of(e: &OpError) -> Option<&str> {
    e.reason.as_deref()
}

// --- adapter rows ----------------------------------------------------------------------------

/// The runner's time is uncertain at the reconnect. Narrowing does not wait for it: the
/// revoke, the pause and the cutoff are all applied and acknowledged, in the order they were
/// produced and before the report. Issuance stays gated: the runner's time is not bounded.
#[tokio::test]
async fn reconnect_with_uncertain_time_still_applies_tombstones_and_policy_revisions() {
    let r = rig().await;
    let b = controller(&r, &controller_b(), Role::Owner);
    let at = plus(b.now(), 6 * HOUR);
    let keys = [
        b.produce(&revoke_of(&r)).unwrap(),
        b.produce(&Narrowing::PausePolicy {
            policy: policy_id(),
        })
        .unwrap(),
        b.produce(&Narrowing::Cutoff {
            scope: PolicyTarget::All,
            at,
        })
        .unwrap(),
    ];
    assert_eq!(b.pending(), 3);

    r.make_time_uncertain().await;
    let mut s = r.session(&controller_b());
    let out = b.resync(&mut s).await.unwrap();

    // All three, in order, each acknowledged under its own key.
    assert_eq!(
        out.acknowledged.iter().map(|a| &a.key).collect::<Vec<_>>(),
        keys.iter().collect::<Vec<_>>()
    );
    assert_eq!(b.pending(), 0);
    // The tombstone and both revisions are durable on the runner.
    let (tombstone, rows) =
        r.w.store
            .transaction(|tx| Ok((tx.tombstone(&r.w.grant)?, tx.remote_policy_revisions()?)))
            .unwrap();
    assert!(tombstone.is_some());
    assert_eq!(rows.len(), 2);
    assert_ne!(r.grant_state(), GrantState::Active);
    let p = r.policy();
    assert!(matches!(p.pause, PauseState::Paused { .. }));
    // Uncertain and unbounded: the future cutoff fires at once, never later than the wall
    // clock read; its row keeps the owner's instant.
    assert!(matches!(
        out.acknowledged[2].record,
        AppliedRecord::PolicyRevision { fired: true, .. }
    ));
    assert!(p.cutoff_at.is_some_and(|c| c <= r.w.clock.wall()));
    assert_eq!(rows[1].cutoff_at, Some(at));
    // The report came after the effects and shows them.
    assert_eq!(out.report.tombstones.len(), 1);
    assert_eq!(out.report.policy_revisions.len(), 2);
    assert!(!out.report.time_bounded);
    // No sample from a controller that is not the time source, no bound: gated.
    assert_eq!(out.time, TimeSample::Refused);
    assert!(!out.time_bounded);
    let other = GrantId::from_random_bytes([0x33; 16]);
    assert_eq!(
        b.reserve(&other, None, plus(b.now(), HOUR)),
        Err(BarrierRefusal::TimeUnbounded)
    );
    assert_eq!(
        BarrierRefusal::TimeUnbounded.to_error().code,
        Code::TimeUncertain
    );
}

/// Controller A issued for the grant; controller B revokes it while A is away. When A
/// reconnects, before it can reserve anything: the barrier is closed until the report is
/// read; reading it marks the grant revoked in A's ledger and counts its certificates in the
/// residual (reserved and published, until their `valid_before`); a reservation made before
/// is voided at publish; and no new one is admitted.
#[tokio::test]
async fn the_issuing_controller_reconnects_after_the_other_revoked_its_grant() {
    let r = rig().await;
    let valid_before = issue_from_a(&r);
    let a = controller(&r, &controller_a(), Role::Owner);
    // A's counted history: the installed certificate (published) and a renewal it had
    // reserved, valid half an hour longer.
    let published = a.reserved_earlier(&r.w.grant, valid_before, true);
    let renewal_until = plus(valid_before, 30 * MINUTE);
    let reserved = a.reserved_earlier(&r.w.grant, renewal_until, false);

    // B revokes; A is not connected.
    let b = controller(&r, &controller_b(), Role::Owner);
    b.produce(&revoke_of(&r)).unwrap();
    let mut sb = r.session(&controller_b());
    let out_b = b.resync(&mut sb).await.unwrap();
    assert_eq!(out_b.acknowledged.len(), 1);
    // B holds no counted history for the grant: it reports the residual unknown.
    let unknown = b
        .store
        .transaction(|tx| counted_residual(tx, &r.w.grant))
        .unwrap();
    assert_eq!(unknown, CountedResidual::Unknown);
    assert!(out_b.revoked.is_empty(), "not B's ledger");
    let residual = authentication_residual_of(unknown, DestinationClock::Unmeasured);
    assert!(residual_statement(residual.as_ref()).starts_with("unknown"));

    // A, before its reconnect: gated.
    assert_eq!(a.status(false).issuance, IssuanceGate::AwaitingResync);
    assert_eq!(
        a.reserve(&r.w.grant, None, renewal_until),
        Err(BarrierRefusal::NotReconciled)
    );
    assert_eq!(
        a.publish(&reserved, None),
        Err(BarrierRefusal::NotReconciled)
    );
    assert_eq!(
        a.entry_state(&reserved),
        IssuanceState::Reserved,
        "a transient refusal keeps the reservation counted"
    );

    // A reconnects and reads the report.
    let mut sa = r.session(&controller_a());
    let out = a.resync(&mut sa).await.unwrap();
    assert_eq!(out.revoked.len(), 1);
    let revoked = &out.revoked[0];
    assert_eq!(revoked.grant, r.w.grant);
    assert!(revoked.marked_now, "the ledger's tombstone is written now");
    // The residual: the latest counted `valid_before`, the reserved renewal included.
    assert_eq!(revoked.residual, CountedResidual::Until(renewal_until));
    assert!(
        a.store
            .transaction(|tx| tx.tombstone(&r.w.grant))
            .unwrap()
            .is_some()
    );
    // Stated with the destination clock's error, never a bare deadline.
    let unmeasured = authentication_residual_of(revoked.residual, DestinationClock::Unmeasured);
    assert_eq!(
        unmeasured
            .as_ref()
            .unwrap()
            .latest_possible_credential_expiry,
        Some(renewal_until)
    );
    assert!(
        residual_statement(unmeasured.as_ref())
            .contains("plus an unmeasured destination-clock error")
    );

    // Nothing new, and the earlier reservation is voided at publish (then no longer counted).
    assert_eq!(out.time, TimeSample::Accepted);
    assert_eq!(
        a.reserve(&r.w.grant, None, renewal_until),
        Err(BarrierRefusal::GrantRevoked)
    );
    assert_eq!(
        a.publish(&reserved, None),
        Err(BarrierRefusal::GrantRevoked)
    );
    assert_eq!(a.entry_state(&reserved), IssuanceState::Voided);
    assert_eq!(a.entry_state(&published), IssuanceState::Published);
    assert_eq!(
        a.store
            .transaction(|tx| counted_residual(tx, &r.w.grant))
            .unwrap(),
        CountedResidual::Until(valid_before),
        "the published certificate counts until its valid_before"
    );
    // The runner dropped the key and the certificate at the revoke.
    assert!(out.report.certificates.is_empty());
    // A second report changes nothing in the ledger.
    let mut again = r.session(&controller_a());
    let out = a.resync(&mut again).await.unwrap();
    assert!(!out.revoked[0].marked_now);
}

/// `held`: a changed host key (refused by the session opener), an environment ID or a client
/// that does not match the pin. Nothing is sent, the pin and the outbox are untouched, the
/// barrier is closed, and only a session that matches the pin again clears it.
#[tokio::test]
async fn a_changed_host_key_gives_held_with_no_reset() {
    let r = rig().await;
    let a = controller(&r, &controller_a(), Role::Owner);
    let pin_before = a.pin.clone();
    // A good first contact.
    let mut s = r.session(&controller_a());
    a.resync(&mut s).await.unwrap();
    assert_eq!(a.status(true).connectivity, Connectivity::Connected);
    assert_eq!(a.status(true).issuance, IssuanceGate::Reconciled);
    let key = a.produce(&revoke_of(&r)).unwrap();

    // The host key changed: the opener refuses before any hello.
    r.w.clock.advance(MINUTE);
    let refused = OpError::new(Code::HostTrustChanged, "the host key is not the pinned key");
    let seen =
        note_open_failure(&a.store, &a.barrier, &a.pin.environment, &refused, a.now()).unwrap();
    assert_eq!(
        seen,
        Connectivity::Unreachable {
            reason: reason::ENVIRONMENT_IDENTITY_MISMATCH.into()
        }
    );
    let contact = a
        .store
        .transaction(|tx| tx.remote_contact(&a.pin.environment))
        .unwrap();
    assert!(is_held(&contact));
    assert!(
        contact.last_seen_at.is_some(),
        "the last good contact is kept"
    );
    assert_eq!(a.status(false).issuance, IssuanceGate::AwaitingResync);
    assert_eq!(a.pending(), 1, "the effect waits");

    // A session that answers with another environment ID, then one bound to another client:
    // held, and not one request is sent.
    let mut substituted = r.session(&controller_a());
    substituted.environment = EnvironmentId::from_random_bytes([0x66; 16]);
    let e = a.resync(&mut substituted).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(reason_of(&e), Some(reason::ENVIRONMENT_IDENTITY_MISMATCH));
    assert_eq!(substituted.sent(), 0);
    let mut other_client = r.session(&controller_a());
    other_client.reported_client = Some(controller_b());
    let e = a.resync(&mut other_client).await.unwrap_err();
    assert_eq!(reason_of(&e), Some(reason::ENVIRONMENT_IDENTITY_MISMATCH));
    assert_eq!(other_client.sent(), 0);

    // No reset: the pin is what it was, the effect is still pending, the runner has not
    // received it, and issuance is gated.
    assert_eq!(a.pin, pin_before);
    assert_eq!(a.pending(), 1);
    assert!(
        r.w.store
            .transaction(|tx| tx.remote_effect_ack(&key))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        a.reserve(&r.w.grant, None, plus(a.now(), HOUR)),
        Err(BarrierRefusal::NotReconciled)
    );
    assert!(matches!(
        a.status(false).connectivity,
        Connectivity::Unreachable { reason } if reason == reason::ENVIRONMENT_IDENTITY_MISMATCH
    ));

    // The pinned identity again: the hold clears and the effect is delivered.
    let mut good = r.session(&controller_a());
    let out = a.resync(&mut good).await.unwrap();
    assert_eq!(out.acknowledged.len(), 1);
    assert_eq!(a.status(true).connectivity, Connectivity::Connected);
    drop(good);
    heimdall_app::remote_status::session_ended(&a.barrier, &a.pin.environment);
    assert!(matches!(
        a.status(false).connectivity,
        Connectivity::Disconnected { .. }
    ));
    assert_eq!(a.status(false).issuance, IssuanceGate::AwaitingResync);
}

/// The dispatch path: a paired owner's `runner.deliver_effect` and `runner.authority_report`
/// are served through `PairedRunner::runner_request` (after the role table and the
/// pre-dispatch rules, which `integration_remote_runtime_m06` covers), and a redelivery
/// answers the recorded acknowledgement.
#[tokio::test]
async fn paired_runner_requests_reach_the_sync_service() {
    let r = rig().await;
    let runtime = Arc::new(RunnerRuntime::new(
        r.w.store.clone(),
        r.w.clock.clone(),
        Arc::new(heimdall_credential::vault::KeyVault::new()),
        heimdall_runtime::runner::time::RunnerTimePolicy::default(),
        heimdall_contract::remote::RunnerLifetime::Unknown,
    ));
    let paired = PairedRunner::new(
        r.w.store.clone(),
        r.ops.clone(),
        r.w.clock.clone(),
        RunnerOptions::default(),
    )
    .with_runtime(runtime);
    let caller = Rig::caller(&controller_b());
    let request = RunnerRequest::DeliverEffect {
        effect: effect(4),
        target: EffectTarget::GrantRevoke {
            grant: r.w.grant.clone(),
            grant_generation: r.w.generation(),
        },
    };
    let first = paired.runner_request(&caller, 3, request.clone()).await;
    assert_eq!(first.code, Code::Ok, "{first:?}");
    let ack: EffectAck = serde_json::from_value(first.data.clone()).unwrap();
    assert_eq!(ack.key.producer, controller_b(), "the session's client");
    assert!(
        r.w.store
            .transaction(|tx| tx.tombstone(&r.w.grant))
            .unwrap()
            .is_some()
    );
    let again = paired.runner_request(&caller, 3, request).await;
    assert_eq!(
        again.data, first.data,
        "a redelivery answers the same acknowledgement"
    );

    let report = paired
        .runner_request(&caller, 3, RunnerRequest::AuthorityReport)
        .await;
    assert_eq!(report.code, Code::Ok);
    let report: AuthorityReport = serde_json::from_value(report.data).unwrap();
    assert_eq!(report.environment, r.w.env);
    assert_eq!(report.tombstones.len(), 1);

    // A local caller (no paired client) is not a producer.
    let local = Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 1000 },
        role: ClientRole::Owner,
        remote_client: None,
    });
    let refused = paired
        .runner_request(&local, 3, RunnerRequest::AuthorityReport)
        .await;
    assert_eq!(refused.code, Code::CapabilityUnavailable);
}

// --- T06: the second controller --------------------------------------------------------------

/// T06 "wrong role": only an owner delivers narrowing effects or reads the authority report.
/// A limited client is refused on the runner with nothing recorded; a controller whose pin is
/// not an owner's produces nothing and has no issuer standing.
#[tokio::test]
async fn t06_wrong_role_delivers_nothing() {
    let r = rig().await;
    // A requester client in the runner's role table, enrolled by invitation.
    let requester = enroll(&r, Role::Requester, 7);
    let target = EffectTarget::GrantRevoke {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    };
    for caller in [
        // Its own, limited, session.
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 1000 },
            role: ClientRole::LimitedConsumer,
            remote_client: Some(requester.clone()),
        }),
        // A session that claims the owner role for a client the table does not give it to.
        Rig::caller(&requester),
        // A client the role table does not know.
        Rig::caller(&client(0x77)),
    ] {
        let e = r
            .sync
            .deliver(r.w.runner.as_ref(), &caller, &effect(1), &target)
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable, "{caller:?}");
        assert_eq!(reason_of(&e), Some(reason::ROLE_INSUFFICIENT));
        let e = r
            .sync
            .authority_report(r.w.runner.as_ref(), &caller)
            .await
            .unwrap_err();
        assert_eq!(reason_of(&e), Some(reason::ROLE_INSUFFICIENT));
    }
    assert_eq!(r.grant_state(), GrantState::Active);
    assert!(
        r.w.store
            .transaction(|tx| tx.tombstones())
            .unwrap()
            .is_empty()
    );

    // The controller side: a device that is a requester on that runner.
    let limited = controller(&r, &requester, Role::Requester);
    let now = limited.now();
    let e = limited
        .store
        .transaction(|tx| narrow(tx, &limited.pin, &revoke_of(&r), now))
        .unwrap()
        .unwrap_err();
    assert_eq!(reason_of(&e), Some(reason::ROLE_INSUFFICIENT));
    assert_eq!(limited.pending(), 0);
    let ca = r.w.ca_b.fingerprint().unwrap();
    let e = issuer_standing(&limited.pin, Some(&ca), None).unwrap_err();
    assert_eq!(reason_of(&e), Some(reason::ROLE_INSUFFICIENT));
}

/// Standard base64 (padded), enough for a fixture key blob.
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A disposable Ed25519 public key (fixed bytes; public text only, never a private key).
fn key(n: u8) -> (String, KeyFingerprint) {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    let mut k = [0x5au8; 32];
    k[0] = n;
    blob.extend_from_slice(&k);
    let text = format!("ssh-ed25519 {}", b64(&blob));
    let fp = PublicKeyText::parse(&text).unwrap().fingerprint();
    (text, fp)
}

/// Enroll a client with `role` and fixture key `n` by invitation and join (the runner's
/// sshd policy counted as verified, so a limited role may enroll).
fn enroll(r: &Rig, role: Role, n: u8) -> heimdall_contract::ids::ClientId {
    let lines = MemoryLines::default_pair();
    let command = ServeCommand::new("/opt/heimdall/bin/heimdall", "/srv/runner/heimdall").unwrap();
    let serial = heimdall_remote::invitations::LineSerial::default();
    let invitations = Invitations {
        store: &r.w.store,
        lines: &lines,
        environment: &r.w.env,
        command: &command,
        clock: r.w.clock.as_ref(),
        serial: &serial,
    };
    let now = TimeReading::safe(&r.w.clock.observe());
    let (public_key, fingerprint) = key(n);
    let invited = invitations
        .invite(
            &NewInvitation {
                role,
                public_key: &public_key,
                key_fingerprint: &fingerprint,
                lifetime: 10 * MINUTE,
                iroh_admission: false,
            },
            ManagementPolicy::Verified,
            &now,
        )
        .unwrap();
    let client = invited.client.client.clone();
    invitations
        .join(
            &client,
            &JoinRequest {
                environment: r.w.env.clone(),
                invitation: invited.invitation.invitation.clone(),
                role,
                generation: invited.invitation.generation,
                iroh_endpoint: None,
                probe: None,
            },
            &now,
        )
        .unwrap();
    client
}

/// T06 "invitation replay": a second owner is enrolled by invitation with its own key. The
/// invitation is consumed once: the joining device's retry reads the recorded result, and
/// any other session presenting it (another client, or the same invitation at another
/// generation) enrolls nobody.
#[tokio::test]
async fn t06_a_second_owner_joins_once_and_the_invitation_cannot_be_replayed() {
    let r = rig().await;
    let lines = MemoryLines::default_pair();
    let command = ServeCommand::new("/opt/heimdall/bin/heimdall", "/srv/runner/heimdall").unwrap();
    let serial = heimdall_remote::invitations::LineSerial::default();
    let invitations = Invitations {
        store: &r.w.store,
        lines: &lines,
        environment: &r.w.env,
        command: &command,
        clock: r.w.clock.as_ref(),
        serial: &serial,
    };
    let now = || TimeReading::safe(&r.w.clock.observe());
    let (second_key, second_fp) = key(2);
    let invited = invitations
        .invite(
            &NewInvitation {
                role: Role::Owner,
                public_key: &second_key,
                key_fingerprint: &second_fp,
                lifetime: 10 * MINUTE,
                iroh_admission: false,
            },
            ManagementPolicy::OwnerOnly,
            &now(),
        )
        .unwrap();
    let second = invited.client.client.clone();
    assert_eq!(invited.client.state, ClientState::Pending);
    let request = JoinRequest {
        environment: r.w.env.clone(),
        invitation: invited.invitation.invitation.clone(),
        role: Role::Owner,
        generation: invited.invitation.generation,
        iroh_endpoint: None,
        probe: None,
    };

    // Before the join, the pending client is no producer.
    let target = EffectTarget::PolicyPause {
        policy: policy_id(),
        revision: 1,
    };
    let e = r.deliver(&second, &effect(1), &target).await.unwrap_err();
    assert_eq!(reason_of(&e), Some(reason::ROLE_INSUFFICIENT));

    // Another client presents the invitation first: refused, and it stays consumable.
    assert!(invitations.join(&controller_b(), &request, &now()).is_err());
    let joined = invitations.join(&second, &request, &now()).unwrap();
    assert!(!joined.replayed);
    let row =
        r.w.store
            .transaction(|tx| tx.remote_client(&second))
            .unwrap()
            .unwrap();
    assert_eq!((row.state, row.role), (ClientState::Active, Role::Owner));
    assert_eq!(row.key_fingerprint, second_fp, "its own K_mgmt");

    // Replays: the device's own retry reads the recorded result; anyone else, or a changed
    // generation, enrolls nobody.
    let clients_before =
        r.w.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .len();
    let retry = invitations.join(&second, &request, &now()).unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.join, joined.join);
    assert!(invitations.join(&controller_b(), &request, &now()).is_err());
    assert!(invitations.join(&client(0x99), &request, &now()).is_err());
    let mut other_generation = request.clone();
    other_generation.generation += 1;
    assert!(
        invitations
            .join(&second, &other_generation, &now())
            .is_err()
    );
    assert_eq!(
        r.w.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .len(),
        clients_before
    );

    // The second owner now delivers any typed narrowing effect, for a grant it did not issue.
    let ack = r.deliver(&second, &effect(1), &target).await.unwrap();
    assert_eq!(ack.key.producer, second);
    assert!(matches!(r.policy().pause, PauseState::Paused { .. }));
}

/// T06 "route substitution": the second controller's session lands on something that is not
/// the pinned runner (another environment ID), or is bound to another client. It is held:
/// its narrowing effect is not sent there, and nothing is reset.
#[tokio::test]
async fn t06_route_substitution_is_held() {
    let r = rig().await;
    let b = controller(&r, &controller_b(), Role::Owner);
    let now = b.now();
    b.store
        .transaction(|tx| narrow(tx, &b.pin, &revoke_of(&r), now))
        .unwrap()
        .unwrap();
    let mut substituted = r.session(&controller_b());
    substituted.environment = EnvironmentId::from_random_bytes([0xee; 16]);
    let e = b.resync(&mut substituted).await.unwrap_err();
    assert_eq!(reason_of(&e), Some(reason::ENVIRONMENT_IDENTITY_MISMATCH));
    assert_eq!(
        substituted.sent(),
        0,
        "nothing reaches the substituted endpoint"
    );
    assert_eq!(b.pending(), 1);
    assert_eq!(r.grant_state(), GrantState::Active);
    let contact = b
        .store
        .transaction(|tx| tx.remote_contact(&b.pin.environment))
        .unwrap();
    assert!(is_held(&contact));
    assert_eq!(
        contact.last_seen_at, None,
        "a substituted endpoint is not a contact"
    );

    // The pinned runner: delivered, from B's own client.
    let mut good = r.session(&controller_b());
    let out = b.resync(&mut good).await.unwrap();
    assert_eq!(out.acknowledged[0].key.producer, controller_b());
    assert_ne!(r.grant_state(), GrantState::Active);
}

/// A second grant on the runner (as a runner-local confirmation would create it), under the
/// same policy.
fn second_grant(r: &Rig) -> GrantId {
    let id = GrantId::from_random_bytes([0x62; 16]);
    let first = r.w.grant.clone();
    r.w.store
        .transaction(|tx| {
            let mut g = tx.grant(&first)?.unwrap();
            let origin = tx.grant_origin(&first)?.unwrap();
            g.id = id.clone();
            g.generation = tx.authority_generation()?;
            tx.insert_grant(&g)?;
            tx.set_grant_origin(&id, &origin)
        })
        .unwrap();
    id
}

/// T06 "an untrusted issuer": the second controller's CA is not in the runner's
/// `issuer_trust`, so the runner prepares nothing for it. After the runner-local trust
/// change it can issue for a **separate** grant, which is then pinned to it; the first
/// controller's grant stays pinned to the first controller, and neither issues for the
/// other's.
#[tokio::test]
async fn t06_an_untrusted_issuer_is_refused_until_trusted_runner_locally() {
    let r = rig().await;
    let w = &r.w;
    issue_from_a(&r);
    let separate = second_grant(&r);
    let g = w.generation();

    // B's CA is not trusted: nothing is prepared for B, on either grant.
    for grant in [&separate, &w.grant] {
        let e = w
            .runner
            .issuance()
            .prepare(&controller_b(), grant, g)
            .unwrap_err();
        let e = e.to_error();
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(reason_of(&e), Some(reason::ISSUER_UNTRUSTED));
    }
    assert!(w.runner.issuance().keys().public_key(&separate).is_none());

    // The runner-local `issuer_trust` change (`heimdall remote issuer-trust add`, attended).
    w.trust(&w.ca_b, &controller_b());
    let prepared = w
        .runner
        .issuance()
        .prepare(&controller_b(), &separate, g)
        .unwrap();
    let key_b = w.runner.issuance().keys().public_key(&separate).unwrap().1;
    let valid_before = Timestamp::from_second(plus(w.clock.wall(), HOUR).as_second()).unwrap();
    // A certificate from A's CA for B's grant is not B's to install.
    let wrong_ca = w.sign_with(
        &w.ca_a,
        &key_b,
        &prepared,
        &pair("h1"),
        valid_before,
        &["permit-pty"],
        None,
    );
    assert!(matches!(
        w.runner
            .issuance()
            .install(&controller_b(), &separate, g, &wrong_ca),
        Err(IssuanceFailure::IssuerUntrusted | IssuanceFailure::Refused(_))
    ));
    let cert = w.sign_with(
        &w.ca_b,
        &key_b,
        &prepared,
        &pair("h1"),
        valid_before,
        &["permit-pty"],
        None,
    );
    w.runner
        .issuance()
        .install(&controller_b(), &separate, g, &cert)
        .unwrap();

    // Each grant is pinned to its own issuer; neither controller is served the other's.
    let pins = w.store.transaction(|tx| tx.remote_grant_issuers()).unwrap();
    let pin_of = |grant: &GrantId| pins.iter().find(|p| p.grant == *grant).unwrap();
    assert_eq!(pin_of(&separate).issuer_client, controller_b());
    assert_eq!(pin_of(&w.grant).issuer_client, controller_a());
    for (controller, grant) in [(controller_b(), &w.grant), (controller_a(), &separate)] {
        let e = w
            .runner
            .issuance()
            .prepare(&controller, grant, w.generation())
            .unwrap_err()
            .to_error();
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(reason_of(&e), Some(reason::ISSUER_UNTRUSTED));
    }

    // The controller's own view of its standing.
    let b = controller(&r, &controller_b(), Role::Owner);
    let ca_a = w.ca_a.fingerprint().unwrap();
    let ca_b = w.ca_b.fingerprint().unwrap();
    assert_eq!(
        issuer_standing(&b.pin, Some(&ca_b), Some((&controller_b(), &ca_b))).unwrap(),
        IssuerStanding::Pinned
    );
    assert_eq!(
        issuer_standing(&b.pin, Some(&ca_b), None).unwrap(),
        IssuerStanding::Unpinned
    );
    let e = issuer_standing(&b.pin, Some(&ca_b), Some((&controller_a(), &ca_a))).unwrap_err();
    assert_eq!(reason_of(&e), Some(reason::ISSUER_UNTRUSTED));
    // The report tells each controller who issued what.
    let mut s = r.session(&controller_b());
    let out = b.resync(&mut s).await.unwrap();
    let issuers: Vec<_> = out
        .report
        .certificates
        .iter()
        .map(|c| (c.grant.clone(), c.issuer.clone()))
        .collect();
    assert!(issuers.contains(&(separate.clone(), controller_b())));
    assert!(issuers.contains(&(w.grant.clone(), controller_a())));
}

/// T06 "renewal without an issuer": the first controller is gone. The second controller can
/// still deliver any narrowing effect, but it cannot renew the first controller's grant: the
/// runner serves a pinned grant only to its issuer, and a controller with no issuer of its
/// own has nothing to renew with (`CAPABILITY_UNAVAILABLE`). The grant runs to its bound.
#[tokio::test]
async fn t06_renewal_without_an_issuer_is_capability_unavailable() {
    let r = rig().await;
    let w = &r.w;
    let valid_before = issue_from_a(&r);
    // The first controller leaves for good; the second has no issuer of its own.
    let b = controller(&r, &controller_b(), Role::Owner);
    let e = issuer_standing(
        &b.pin,
        None,
        Some((&controller_a(), &w.ca_a.fingerprint().unwrap())),
    )
    .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.effect_status,
        heimdall_contract::envelope::EffectStatus::None
    );
    // Even with a trusted CA of its own, the pinned grant is not its to renew.
    w.trust(&w.ca_b, &controller_b());
    let renewal = w
        .runner
        .issuance()
        .prepare(&controller_b(), &w.grant, w.generation())
        .unwrap_err()
        .to_error();
    assert_eq!(renewal.code, Code::CapabilityUnavailable);
    // And the first controller's own key and certificate are untouched by the attempt.
    let certs = w.runner.issuance().keys().certificates(&w.grant);
    assert_eq!(certs[&pair("h1")].valid_before, valid_before);

    // The grant runs to its bound: the report shows the certificate until then, and the
    // second controller's last-known readiness computes it forward.
    let mut s = r.session(&controller_b());
    let out = b.resync(&mut s).await.unwrap();
    assert_eq!(out.report.certificates.len(), 1);
    assert_eq!(out.report.certificates[0].issuer, controller_a());
    let status = b.status(true);
    assert_eq!(status.last_known_readiness[0].offline_until, valid_before);
    assert_eq!(
        serde_json::to_value(status.last_known_readiness[0].state).unwrap(),
        "within_bound"
    );
    w.clock.advance(2 * HOUR);
    let later = b.status(false);
    assert_eq!(
        serde_json::to_value(later.last_known_readiness[0].state).unwrap(),
        "bound_passed"
    );
    // B has no counted history for A's grant: its residual is unknown, never a guess.
    assert_eq!(
        b.store
            .transaction(|tx| counted_residual(tx, &w.grant))
            .unwrap(),
        CountedResidual::Unknown
    );

    // Narrowing needs no issuer: the second controller can still cut everything off.
    let now = b.now();
    b.store
        .transaction(|tx| {
            narrow(
                tx,
                &b.pin,
                &Narrowing::Cutoff {
                    scope: PolicyTarget::All,
                    at: now,
                },
                now,
            )
        })
        .unwrap()
        .unwrap();
    let mut s = r.session(&controller_b());
    let out = b.resync(&mut s).await.unwrap();
    assert_eq!(out.acknowledged.len(), 1);
    assert_eq!(r.policy().cutoff_at, Some(now));
}
