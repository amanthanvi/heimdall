//! ⟨M06 U4⟩ Typed narrowing effects and resynchronization, as a model over the real parts
//! (m06-plan U4 "model"; ADR-0012 §7.2–§7.4; ADR-0006 §18.5 readings 9 and 16; A07's runner
//! rows).
//!
//! The runner is its real store, operations, runner runtime and sync service
//! (`runner_sync_fixture_m06`); a controller is its real outbox, resynchronization and issuer
//! barrier over a store of its own. Only the wire between them is in process.
//!
//! * two controllers' effects interleave in every order with no collision: the same scope,
//!   the same numeric revision and even the same effect ID from different producers are two
//!   durable rows, each replayed to its own acknowledgement;
//! * a lost acknowledgement converges: the effect is delivered again and applied once;
//! * a stale issuance cannot reactivate a tombstoned grant, on the runner or in the issuer's
//!   ledger;
//! * a pause preserves running grants and blocks new issuance for the policy;
//! * a cutoff delivered while disconnected refuses a fresh work ID after the reconnect;
//! * a future cutoff delivered early, late, and replayed under uncertain time (the original
//!   bound, the reconciliation gate and the expiry treatment).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "../integration/runner_fixture_m06.rs"]
mod fixture;
#[path = "../integration/runner_sync_fixture_m06.rs"]
mod sync_fixture;

use std::time::Duration;

use fixture::*;
use heimdall_app::context::Caller;
use heimdall_app::remote_status::{IssuanceGate, Narrowing, TimeSample};
use heimdall_app::remote_status_barrier::{BarrierRefusal, CountedResidual};
use heimdall_contract::code::Code;
use heimdall_contract::ids::{RequestId, WorkId};
use heimdall_contract::remote::{Connectivity, EffectTarget, RemotePending, Role};
use heimdall_contract::request::{EnsureRequest, InteractionMode, RequiredCapabilities, WaitMode};
use heimdall_contract::trust::PolicyTarget;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::issuance::{IssuanceRefusal, IssuanceState};
use heimdall_domain::policy::PauseState;
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::Clock;
use heimdall_runtime::runner::issuance::IssuanceFailure;
use heimdall_store::ext_effects::{AppliedRecord, EffectKey, PolicyRevisionKind};
use sync_fixture::*;

const MINUTE: Duration = Duration::from_secs(60);

fn cutoff_all(at: Timestamp, revision: u64) -> EffectTarget {
    EffectTarget::PolicyCutoff {
        scope: PolicyTarget::All,
        at,
        revision,
    }
}

fn pause(revision: u64) -> EffectTarget {
    EffectTarget::PolicyPause {
        policy: policy_id(),
        revision,
    }
}

fn revoke(r: &Rig) -> EffectTarget {
    EffectTarget::GrantRevoke {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    }
}

fn fired(record: &AppliedRecord) -> bool {
    matches!(record, AppliedRecord::PolicyRevision { fired: true, .. })
}

/// The runner's local owner.
fn local_owner() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 1000 },
        role: ClientRole::Owner,
        remote_client: None,
    })
}

/// A fresh piece of work on the runner: a new work ID and a new request ID for `h1`.
async fn fresh_work(r: &Rig, n: u32) -> Code {
    let request = EnsureRequest {
        profile: Some(profile()),
        profile_revision: None,
        scope: [pair("h1")].into_iter().collect(),
        environment: None,
        work_id: WorkId::parse(&format!("fresh-work-{n}")).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(&format!("fresh-request-{n}")).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 5_000 },
        connection: None,
        context: None,
        covered_only: false,
        pair_issuers: Vec::new(),
    };
    match r.ops.ensure(&local_owner(), request).await {
        Ok(done) => done.code,
        Err(e) => e.code,
    }
}

/// Prepare the fixture grant for controller A, take a good time sample and install one
/// certificate for `h1` valid for an hour. Returns its `valid_before`.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    A,
    B,
    ReplayA,
    ReplayB,
}

/// Every order of the four steps with each replay after its first delivery.
fn interleavings() -> Vec<Vec<Step>> {
    fn go(left: &mut Vec<Step>, cur: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
        if left.is_empty() {
            out.push(cur.clone());
            return;
        }
        for i in 0..left.len() {
            let s = left.remove(i);
            let allowed = match s {
                Step::ReplayA => cur.contains(&Step::A),
                Step::ReplayB => cur.contains(&Step::B),
                _ => true,
            };
            if allowed {
                cur.push(s);
                go(left, cur, out);
                cur.pop();
            }
            left.insert(i, s);
        }
    }
    let mut out = Vec::new();
    go(
        &mut vec![Step::A, Step::B, Step::ReplayA, Step::ReplayB],
        &mut Vec::new(),
        &mut out,
    );
    out
}

/// Two controllers deliver a cutoff of the **same scope** with the **same numeric revision**
/// and the **same effect ID**, and a pause of the same policy with the same revision, in
/// every order with replays: nothing collides. Both producers' rows are durable in the
/// runner's own order, each replay answers its own first acknowledgement, and the narrowing
/// effects compose (the earlier cutoff holds; the pause holds).
#[tokio::test]
async fn two_controllers_effects_interleave_with_no_collision() {
    let orders = interleavings();
    assert_eq!(orders.len(), 6);
    for order in orders {
        let r = rig().await;
        let at_a = plus(r.w.clock.wall(), 2 * HOUR);
        let at_b = plus(r.w.clock.wall(), HOUR);
        let mut first: std::collections::HashMap<&str, Vec<_>> = Default::default();
        let mut arrival = Vec::new();
        for step in &order {
            r.w.clock.advance(Duration::from_secs(1));
            let (who, name, at) = match step {
                Step::A | Step::ReplayA => (controller_a(), "a", at_a),
                Step::B | Step::ReplayB => (controller_b(), "b", at_b),
            };
            // Same effect IDs, same scope, same revision numbers from both producers.
            let cut = r
                .deliver(&who, &effect(1), &cutoff_all(at, 1))
                .await
                .unwrap();
            let pau = r.deliver(&who, &effect(2), &pause(1)).await.unwrap();
            assert_eq!(cut.key.producer, who, "{order:?}");
            match step {
                Step::A | Step::B => {
                    arrival.push(who.clone());
                    first.insert(name, vec![cut, pau]);
                }
                Step::ReplayA | Step::ReplayB => {
                    // A replay answers the acknowledgement as first recorded.
                    assert_eq!(first[name], vec![cut, pau], "{order:?} {step:?}");
                }
            }
        }
        let rows =
            r.w.store
                .transaction(|tx| tx.remote_policy_revisions())
                .unwrap();
        assert_eq!(rows.len(), 4, "{order:?}: two producers x (cutoff, pause)");
        for who in [controller_a(), controller_b()] {
            let mine: Vec<_> = rows.iter().filter(|x| x.producer == who).collect();
            assert_eq!(mine.len(), 2, "{order:?}");
            assert!(mine.iter().all(|x| x.revision == 1));
            assert!(mine.iter().any(|x| x.kind == PolicyRevisionKind::Cutoff));
            assert!(mine.iter().any(|x| x.kind == PolicyRevisionKind::Pause));
        }
        // The runner's order: strictly increasing, the first arrival first, and no replay
        // took a sequence number.
        let seqs: Vec<u64> = rows.iter().map(|x| x.runner_seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4], "{order:?}");
        assert_eq!(rows[0].producer, arrival[0], "{order:?}");
        assert_eq!(rows[2].producer, arrival[1], "{order:?}");
        // Each row keeps its own producer's instant.
        for x in rows.iter().filter(|x| x.kind == PolicyRevisionKind::Cutoff) {
            let want = if x.producer == controller_a() {
                at_a
            } else {
                at_b
            };
            assert_eq!(x.cutoff_at, Some(want), "{order:?}");
        }
        // Composition: the earlier cutoff and the pause both hold on the policy.
        let p = r.policy();
        assert_eq!(p.cutoff_at, Some(at_b), "{order:?}: min(existing, at)");
        assert!(matches!(p.pause, PauseState::Paused { .. }), "{order:?}");
        // Both producers' acknowledgements exist under their own keys.
        for who in [controller_a(), controller_b()] {
            let at = if who == controller_a() { at_a } else { at_b };
            let key = EffectKey {
                producer: who,
                effect: effect(1),
                target: cutoff_all(at, 1),
            };
            assert!(
                r.w.store
                    .transaction(|tx| tx.remote_effect_ack(&key))
                    .unwrap()
                    .is_some(),
                "{order:?}"
            );
        }
    }
}

/// The reply to a delivered revoke is lost. The effect stays pending on the controller and
/// the barrier stays closed; the next resynchronization delivers it again, the runner
/// answers the same acknowledgement without applying anything twice, and a third
/// resynchronization has nothing left to deliver.
#[tokio::test]
async fn a_lost_acknowledgement_converges_idempotently() {
    let r = rig().await;
    issue_from_a(&r);
    let a = controller(&r, &controller_a(), Role::Owner);
    let key = a
        .produce(&Narrowing::RevokeGrant {
            grant: r.w.grant.clone(),
            grant_generation: r.w.generation(),
        })
        .unwrap();
    assert_eq!(a.pending(), 1);

    let mut lost = r.session(&controller_a());
    lost.lose_reply_of = Some(0);
    let e = a.resync(&mut lost).await.unwrap_err();
    assert_eq!(e.code, Code::OutcomeUnknown);
    assert_eq!(lost.sent(), 1, "the sequence stops at the lost reply");
    // The runner applied it: tombstone, acknowledgement, K_env gone.
    let (tombstones, runner_ack) =
        r.w.store
            .transaction(|tx| Ok((tx.tombstones()?, tx.remote_effect_ack(&key)?)))
            .unwrap();
    assert_eq!(tombstones.len(), 1);
    let runner_ack = runner_ack.expect("recorded on the runner");
    assert!(
        r.w.runner
            .issuance()
            .keys()
            .public_key(&r.w.grant)
            .is_none()
    );
    // The controller does not know: still pending, still gated.
    assert_eq!(a.pending(), 1);
    let status = a.status(false);
    assert!(matches!(
        status.remote_pending.as_slice(),
        [RemotePending::Effect { effect, .. }] if *effect == key.effect
    ));
    assert_eq!(status.issuance, IssuanceGate::AwaitingResync);
    assert_eq!(
        a.reserve(&r.w.grant, None, plus(a.now(), HOUR)),
        Err(BarrierRefusal::NotReconciled)
    );

    let generation = r.w.generation();
    let mut again = r.session(&controller_a());
    let out = a.resync(&mut again).await.unwrap();
    assert_eq!(out.acknowledged, vec![runner_ack.clone()]);
    assert_eq!(a.pending(), 0);
    let (tombstones, ack_now) =
        r.w.store
            .transaction(|tx| Ok((tx.tombstones()?, tx.remote_effect_ack(&key)?)))
            .unwrap();
    assert_eq!(tombstones.len(), 1, "applied once");
    assert_eq!(ack_now, Some(runner_ack));
    assert_eq!(
        r.w.generation(),
        generation,
        "the redelivery moved no authority"
    );

    let mut third = r.session(&controller_a());
    let out = a.resync(&mut third).await.unwrap();
    assert!(out.acknowledged.is_empty(), "nothing left to deliver");
    assert!(a.status(true).remote_pending.is_empty());
}

/// Controller B revokes a grant A issued for. A's certificate signed before the revoke is
/// refused at install, a new prepare is refused, and after A's resynchronization its ledger
/// holds the tombstone: no reserve, and a reservation made before is voided at publish.
#[tokio::test]
async fn a_stale_issuance_cannot_reactivate_a_tombstoned_grant() {
    let r = rig().await;
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
    // A's ledger: the entry it reserved for that certificate, before any revoke.
    let a = controller(&r, &controller_a(), Role::Owner);
    let stale = a.reserved_earlier(&w.grant, valid_before, false);

    // B's revoke arrives first.
    let ack = r
        .deliver(&controller_b(), &effect(9), &revoke(&r))
        .await
        .unwrap();
    assert!(matches!(
        ack.record,
        AppliedRecord::GrantTombstone {
            known: true,
            key_destroyed: true,
            ..
        }
    ));
    assert!(w.runner.issuance().keys().public_key(&w.grant).is_none());

    // The stale certificate, and a fresh prepare at any generation: refused.
    let e = w
        .runner
        .issuance()
        .install(&controller_a(), &w.grant, g, &cert)
        .unwrap_err();
    assert!(
        matches!(
            e,
            IssuanceFailure::NoKey
                | IssuanceFailure::Refused(
                    IssuanceRefusal::Tombstoned
                        | IssuanceRefusal::StaleGeneration
                        | IssuanceRefusal::GrantNotIssuable(_)
                )
        ),
        "{e:?}"
    );
    for generation in [g, w.generation()] {
        assert!(
            w.runner
                .issuance()
                .prepare(&controller_a(), &w.grant, generation)
                .is_err(),
            "a tombstoned grant is never prepared again"
        );
    }
    assert!(w.runner.issuance().keys().certificates(&w.grant).is_empty());

    // A reconnects: its ledger marks the grant revoked and counts the reserved entry.
    let mut s = r.session(&controller_a());
    let out = a.resync(&mut s).await.unwrap();
    assert_eq!(out.revoked.len(), 1);
    assert_eq!(out.revoked[0].grant, w.grant);
    assert!(out.revoked[0].marked_now);
    assert_eq!(
        out.revoked[0].residual,
        CountedResidual::Until(valid_before)
    );
    assert_eq!(out.time, TimeSample::Accepted);
    assert_eq!(
        a.reserve(&w.grant, None, valid_before),
        Err(BarrierRefusal::GrantRevoked)
    );
    assert_eq!(a.publish(&stale, None), Err(BarrierRefusal::GrantRevoked));
    assert_eq!(a.entry_state(&stale), IssuanceState::Voided);
}

/// A pause is not a tombstone: the running grant, its K_env and its installed certificate
/// stay, while the policy refuses new activations and the issuer's barrier refuses new
/// issuance under it.
#[tokio::test]
async fn a_pause_preserves_running_grants() {
    let r = rig().await;
    let valid_before = issue_from_a(&r);
    let control = fresh_work(&r, 0).await;
    assert_ne!(control, Code::PolicyPaused, "not paused yet: {control:?}");

    let ack = r
        .deliver(&controller_b(), &effect(1), &pause(1))
        .await
        .unwrap();
    assert!(matches!(
        &ack.record,
        AppliedRecord::PolicyRevision { policies, cutoff_at: None, .. } if *policies == vec![policy_id()]
    ));
    assert!(matches!(r.policy().pause, PauseState::Paused { .. }));

    // The running grant continues: active, its key and its certificate still installed.
    assert_eq!(r.grant_state(), GrantState::Active);
    assert!(
        r.w.runner
            .issuance()
            .keys()
            .public_key(&r.w.grant)
            .is_some()
    );
    let certs = r.w.runner.issuance().keys().certificates(&r.w.grant);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[&pair("h1")].valid_before, valid_before);
    assert!(
        r.w.store
            .transaction(|tx| tx.tombstone(&r.w.grant))
            .unwrap()
            .is_none(),
        "a pause is not a tombstone"
    );

    // New activations are refused, with a fresh work ID too.
    assert_eq!(fresh_work(&r, 1).await, Code::PolicyPaused);

    // The issuer's barrier, after its report: no new issuance under the paused policy, and
    // the report still lists the running certificate.
    let a = controller(&r, &controller_a(), Role::Owner);
    let mut s = r.session(&controller_a());
    let out = a.resync(&mut s).await.unwrap();
    assert_eq!(out.report.certificates.len(), 1);
    assert_eq!(out.report.certificates[0].issuer, controller_a());
    assert!(out.revoked.is_empty());
    assert_eq!(
        a.reserve(&r.w.grant, Some(&policy_id()), valid_before),
        Err(BarrierRefusal::PolicyPaused)
    );
    let status = a.status(true);
    assert_eq!(status.last_known_readiness.len(), 1);
    assert_eq!(status.last_known_readiness[0].offline_until, valid_before);
}

/// The owner cuts off every policy while the runner is disconnected. The effect waits in the
/// outbox (`remote_pending`); at the reconnect it is pushed before anything else, and a
/// fresh work ID is refused afterwards, as is new issuance behind the barrier.
#[tokio::test]
async fn a_cutoff_delivered_while_disconnected_refuses_a_fresh_work_id_after_reconnect() {
    let r = rig().await;
    issue_from_a(&r);
    let b = controller(&r, &controller_b(), Role::Owner);
    let at = plus(b.now(), 10 * MINUTE);
    let key = b
        .produce(&Narrowing::Cutoff {
            scope: PolicyTarget::All,
            at,
        })
        .unwrap();
    let status = b.status(false);
    assert_eq!(
        status.connectivity,
        Connectivity::Unreachable {
            reason: "never_connected".into()
        }
    );
    assert_eq!(status.remote_pending.len(), 1);

    // Disconnected past the owner's instant: the runner has not heard of the cutoff.
    r.w.clock.advance(30 * MINUTE);
    assert_eq!(r.policy().cutoff_at, None);
    let before = fresh_work(&r, 1).await;
    assert_ne!(before, Code::PolicyCutoff, "not cut off yet: {before:?}");

    // Reconnect: the effect is the first request of the session.
    let mut s = r.session(&controller_b());
    let out = b.resync(&mut s).await.unwrap();
    assert_eq!(out.acknowledged.len(), 1);
    assert_eq!(out.acknowledged[0].key, key);
    assert!(
        fired(&out.acknowledged[0].record),
        "the instant had passed: it applied at the durable apply"
    );
    assert_eq!(
        r.policy().cutoff_at,
        Some(at),
        "the owner's instant is kept"
    );
    assert!(b.status(true).remote_pending.is_empty());
    assert_eq!(b.status(true).connectivity, Connectivity::Connected);

    // A fresh work ID and a fresh request ID do not pass the reconciled cutoff.
    assert_eq!(fresh_work(&r, 2).await, Code::PolicyCutoff);
    // The grant under it ended like expiry: no tombstone, and not active.
    assert_ne!(r.grant_state(), GrantState::Active);
    assert!(
        r.w.store
            .transaction(|tx| tx.tombstone(&r.w.grant))
            .unwrap()
            .is_none(),
        "a cutoff is not a revocation"
    );

    // The issuing controller reconnects: its barrier refuses the scope.
    let a = controller(&r, &controller_a(), Role::Owner);
    let mut s = r.session(&controller_a());
    a.resync(&mut s).await.unwrap();
    assert_eq!(
        a.reserve(&r.w.grant, Some(&policy_id()), plus(a.now(), HOUR)),
        Err(BarrierRefusal::PolicyCutoff)
    );
    assert_eq!(
        a.reserve(&r.w.grant, None, plus(a.now(), HOUR)),
        Err(BarrierRefusal::PolicyCutoff),
        "a cutoff of every policy applies whatever the grant's policy"
    );
}

/// A future cutoff, delivered early with trusted time: kept with the owner's instant, the
/// grant keeps running, and the issuer's barrier bounds new certificates by it. Replayed
/// once time is uncertain and unbounded, it fires at once; the row still shows the original
/// bound. When the instant passes, the grant ends like expiry.
#[tokio::test]
async fn a_future_cutoff_delivered_early_then_replayed_under_uncertainty() {
    let r = rig().await;
    issue_from_a(&r);
    let at = plus(r.w.clock.wall(), HOUR);
    let target = cutoff_all(at, 1);

    // Early.
    let early = r
        .deliver(&controller_a(), &effect(1), &target)
        .await
        .unwrap();
    assert!(!fired(&early.record));
    assert_eq!(r.policy().cutoff_at, Some(at));
    assert_eq!(r.grant_state(), GrantState::Active, "nothing ends early");
    assert!(
        r.w.runner
            .issuance()
            .keys()
            .public_key(&r.w.grant)
            .is_some()
    );

    // The reconciliation gate: the barrier admits issuance only up to the cutoff.
    let a = controller(&r, &controller_a(), Role::Owner);
    let mut s = r.session(&controller_a());
    a.resync(&mut s).await.unwrap();
    assert_eq!(
        a.reserve(&r.w.grant, Some(&policy_id()), plus(at, MINUTE)),
        Err(BarrierRefusal::PolicyCutoff),
        "no certificate valid past the cutoff"
    );
    assert!(
        a.reserve(&r.w.grant, Some(&policy_id()), at).is_ok(),
        "up to the cutoff is permitted"
    );

    // A later cutoff from the same producer never moves it later (only shortens).
    let later = r
        .deliver(&controller_a(), &effect(2), &cutoff_all(plus(at, HOUR), 2))
        .await
        .unwrap();
    assert!(!fired(&later.record));
    assert_eq!(r.policy().cutoff_at, Some(at), "min(existing, at)");

    // Time becomes uncertain; the runner's last sample is of this boot, so now is bounded
    // above and the bound is still before `at`: a replay does not fire.
    r.make_time_uncertain().await;
    let bounded = r
        .deliver(&controller_a(), &effect(1), &target)
        .await
        .unwrap();
    assert!(!fired(&bounded.record), "at cannot have passed yet");
    assert_eq!(r.policy().cutoff_at, Some(at));

    // The bound reaches `at` (the continuous clock ran on; the wall clock is still wrong):
    // a replay fires at once, never later than the wall clock read.
    r.w.clock.advance_continuous_only(HOUR);
    let wall = r.w.clock.wall();
    assert!(wall < at, "the wall clock alone would not fire it");
    let replay = r
        .deliver(&controller_a(), &effect(1), &target)
        .await
        .unwrap();
    assert!(fired(&replay.record), "at may have passed");
    assert_eq!(replay.applied_at, early.applied_at, "first applied then");
    assert_eq!(r.policy().cutoff_at, Some(wall), "fires now, never later");
    let rows =
        r.w.store
            .transaction(|tx| tx.remote_policy_revisions())
            .unwrap();
    // ⟨M08 W4 SEC-3b, R2⟩ The later cutoff of the same producer and scope, delivered while the
    // first is in force, was coalesced into its row: one row, the later effect acknowledged
    // against it.
    assert_eq!(rows.len(), 1);
    assert!(matches!(
        later.record,
        heimdall_store::ext_effects::AppliedRecord::PolicyRevision { runner_seq: 1, .. }
    ));
    assert_eq!(
        rows[0].cutoff_at,
        Some(at),
        "the row keeps the original bound"
    );
    assert_eq!(rows[0].runner_seq, 1);
    // Once fired, a further replay still reports fired.
    let again = r
        .deliver(&controller_a(), &effect(1), &target)
        .await
        .unwrap();
    assert!(fired(&again.record));
    assert_eq!(
        fresh_work(&r, 3).await,
        Code::TimeUncertain,
        "and nothing new starts"
    );
}

/// A cutoff delivered late (its instant already passed, trusted time) applies at the durable
/// apply with the owner's instant; one delivered under uncertain, unbounded time fires at
/// once. Both end the grant like expiry and refuse fresh work.
#[tokio::test]
async fn a_cutoff_delivered_late_applies_at_the_durable_apply() {
    // Late, trusted time.
    let r = rig().await;
    issue_from_a(&r);
    let at =
        r.w.clock
            .wall()
            .checked_sub(jiff::SignedDuration::from_mins(5))
            .unwrap();
    let late = r
        .deliver(&controller_b(), &effect(1), &cutoff_all(at, 1))
        .await
        .unwrap();
    assert!(fired(&late.record));
    assert_eq!(r.policy().cutoff_at, Some(at), "the owner's instant");
    assert_eq!(
        r.grant_state(),
        GrantState::Expired,
        "ended at the apply, like expiry"
    );
    assert!(
        r.w.runner
            .issuance()
            .keys()
            .public_key(&r.w.grant)
            .is_none(),
        "no key of an ended grant stays in memory"
    );
    assert_eq!(fresh_work(&r, 1).await, Code::PolicyCutoff);

    // Uncertain and unbounded (no time sample at all): a future instant fires at once.
    let r = rig().await;
    r.make_time_uncertain().await;
    let wall = r.w.clock.wall();
    let at = plus(wall, 3 * HOUR);
    let ack = r
        .deliver(&controller_b(), &effect(1), &cutoff_all(at, 1))
        .await
        .unwrap();
    assert!(fired(&ack.record), "at may have passed: no bound on now");
    assert_eq!(r.policy().cutoff_at, Some(wall));
    let rows =
        r.w.store
            .transaction(|tx| tx.remote_policy_revisions())
            .unwrap();
    assert_eq!(rows[0].cutoff_at, Some(at), "the original bound is kept");
}
