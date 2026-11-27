//! ⟨M08 W4 SEC-3b⟩ The runner's authority history is bounded, and so is its report (S2-05;
//! ADR-0006 §7.4 and ADR-0012 §7.4 as amended 2026-11-27 on the orchestrator's ruling of
//! 2026-11-26, R1 to R5 and the override).
//!
//! The runner is its real store, operations (the retention pass is `Operations::tick`), runner
//! runtime and sync service; a controller is its real outbox, resynchronization and issuer
//! barrier over its own store (`runner_sync_fixture_m06`). Every case reads the history through
//! the store's own readers and drives it through the runner's own paths (a delivered effect, the
//! retention pass, a widening submission, the authority report), so each runs against the
//! production code before the change too, where it fails.
//!
//! * **The override:** at every cap, an effective revoke (a grant the runner holds) and an
//!   effective cutoff (a scope that matches a runner policy) still land.
//! * **R1:** bare revokes are capped per producer and in total; a known tombstone is pruned
//!   only on safe time, after its grant's deadline and the retention, with its row `revoked`
//!   (which still denies); a bare one after the fallback window and the retention; a late
//!   redelivery to a `revoked` row converges.
//! * **R2:** in-force revisions are never pruned and are coalesced per producer, scope and
//!   kind; unmatched scopes are capped; a lifted row goes after its producer confirmed the
//!   lift (or was revoked) and the retention; the controller keeps the lift shown after the
//!   prune; a runner restored from before the lift blocks again.
//! * **R3:** acknowledgements go with their history, never while a pause or cutoff is in force.
//! * **R4:** pending paired widening records are capped; the retention pass lapses them and
//!   purges settled ones into 30-day markers (`REQUEST_EXPIRED`); `OUTCOME_UNKNOWN` stays.
//! * **R5:** a report over its budget is refused whole, the controller's barrier stays closed
//!   with nothing written, and it reopens once pruning brings the report under the budget; the
//!   report at the supported envelope's maximum is within the budget.
//! * **The history-growth workload** (`authority_history_growth`, ignored here; run by
//!   `tools/benchmarks/m08/run-soak.sh --authority-history-growth`) and its short form.
//!
//! Disposable state only: in-memory stores (a temporary file for the workload's sizes),
//! fixture IDs, public fixture key text.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "runner_fixture_m06.rs"]
mod fixture;
#[path = "runner_sync_fixture_m06.rs"]
mod sync_fixture;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use heimdall_app::operations::Limits;
use heimdall_app::remote_status::Narrowing;
use heimdall_app::remote_status_barrier::BarrierRefusal;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{ClientId, EffectId, GrantId, PolicyId};
use heimdall_contract::remote::{EffectTarget, Role, RunnerRequest};
use heimdall_contract::request::Request;
use heimdall_contract::trust::PolicyTarget;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::decision::DecisionState;
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::time::Clock;
use heimdall_remote::widening::{StoreWidening, Submitted, submit};
use heimdall_store::ext_effects::{
    AuthorityReport, EffectKey, PolicyRevisionKind, PolicyRevisionRecord, ReportedCertificate,
    ReportedPendingGrant, ReportedPolicy, ReportedTombstone,
};
use heimdall_store::ext_m06::RevocationCause as ClientRevocation;
use sync_fixture::*;

const DAY: Duration = Duration::from_secs(24 * 3600);
/// The runner's `retention.operations` in these cases (the default, `Limits::default()`).
const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// The report's budget (`heimdall_contract::page::PAGE_BUDGET_BYTES`).
const BUDGET: usize = 768 << 10;
/// The caps of the ruling of 2026-11-26.
const BARE_PER_PRODUCER: usize = 256;
const BARE_TOTAL: usize = 1024;
const UNMATCHED_PER_PRODUCER: usize = 256;
const WIDENING_PER_CLIENT: usize = 32;
const WIDENING_TOTAL: usize = 128;

/// A distinct 16-byte tag for `n`.
fn tag(kind: u8, n: u32) -> [u8; 16] {
    let mut b = [kind; 16];
    b[..4].copy_from_slice(&n.to_be_bytes());
    b
}

fn eff(kind: u8, n: u32) -> EffectId {
    EffectId::from_random_bytes(tag(kind, n))
}

/// A grant ID this runner does not hold.
fn unknown_grant(n: u32) -> GrantId {
    GrantId::from_random_bytes(tag(0xee, n))
}

fn revoke(grant: &GrantId) -> EffectTarget {
    EffectTarget::GrantRevoke {
        grant: grant.clone(),
        grant_generation: 1,
    }
}

fn pause(policy: &str, revision: u64) -> EffectTarget {
    EffectTarget::PolicyPause {
        policy: PolicyId::parse(policy).unwrap(),
        revision,
    }
}

fn cutoff(scope: PolicyTarget, at: Timestamp, revision: u64) -> EffectTarget {
    EffectTarget::PolicyCutoff {
        scope,
        at,
        revision,
    }
}

fn pol_scope() -> PolicyTarget {
    PolicyTarget::Policy {
        policy_id: policy_id(),
    }
}

fn tombstones(r: &Rig) -> Vec<Tombstone> {
    r.w.store.transaction(|tx| tx.tombstones()).unwrap()
}

fn revisions(r: &Rig) -> Vec<PolicyRevisionRecord> {
    r.w.store
        .transaction(|tx| tx.remote_policy_revisions())
        .unwrap()
}

fn ack_of(r: &Rig, key: &EffectKey) -> bool {
    r.w.store
        .transaction(|tx| tx.remote_effect_ack(key))
        .unwrap()
        .is_some()
}

fn key(c: &ClientId, e: &EffectId, target: &EffectTarget) -> EffectKey {
    EffectKey {
        producer: c.clone(),
        effect: e.clone(),
        target: target.clone(),
    }
}

/// Add an active grant `id` to the runner, a copy of the fixture grant with `deadline`.
fn add_grant(r: &Rig, id: &GrantId, deadline: Timestamp) {
    let template = r.w.grant.clone();
    let id = id.clone();
    r.w.store
        .transaction(|tx| {
            let mut g = tx.grant(&template)?.unwrap();
            g.id = id;
            g.state = GrantState::Active;
            g.starts_at = r.w.clock.wall();
            g.deadline.effective = deadline;
            g.generation = tx.authority_generation()?;
            tx.insert_grant(&g)
        })
        .unwrap();
}

async fn tick(r: &Rig) {
    r.ops.tick().await.unwrap();
}

/// Where a binding would be realized: nothing is created.
struct NoFiles;

impl heimdall_runtime::runner::adapter::RunnerMaterializer for NoFiles {
    fn materialize(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        _grant: &GrantId,
    ) -> Result<heimdall_contract::provider::EndpointRef, heimdall_app::ports::AdapterError> {
        Ok(serde_json::from_value(serde_json::json!({
            "kind": "unix_socket",
            "locator": format!("/fixture/{}.sock", binding.as_str()),
        }))
        .expect("an endpoint reference"))
    }

    fn clear(&self, _grant: &GrantId) -> Result<(), heimdall_app::ports::AdapterError> {
        Ok(())
    }
}

/// The sync fixture's rig as a runner runtime wires it: the runner's managed adapter (which
/// completes a revocation, so a revoked grant's row ends `revoked`) and the runner's signer
/// as the operations' runner grants (the retention pass reads its live keys).
async fn managed_rig_with(w: World, limits: Limits) -> Rig {
    use heimdall_app::ensure::NoStageHook;
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    w.store
        .transaction(|tx| {
            let mut e = tx.environment(&w.env)?.unwrap();
            e.permissions = heimdall_domain::environment::EnvironmentPermissions {
                automatic_activation: true,
                managed_signing: true,
                issuer_access: true,
            };
            tx.upsert_environment(&e)
        })
        .unwrap();
    let adapter =
        Arc::new(heimdall_runtime::runner::adapter::RunnerManagedAdapter::new(w.store.clone()));
    adapter.bind(w.runner.clone(), Arc::new(NoFiles));
    let time_sync = heimdall_testkit::ScriptedTimeSync::new(SyncStatus::Synchronized);
    let ops = heimdall_app::Operations::start(heimdall_app::OperationsConfig {
        store: w.store.clone(),
        clock: w.clock.clone(),
        time_sync: time_sync.clone(),
        time_policy: TimePolicy::default(),
        environment: w.env.clone(),
        adapters: vec![adapter],
        stage_hook: Arc::new(NoStageHook),
        limits,
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap();
    ops.set_runner_grants(w.runner.clone());
    let sync =
        heimdall_remote::sync::RunnerSync::new(w.store.clone(), ops.clone(), w.clock.clone());
    Rig {
        w,
        ops,
        sync,
        time_sync,
    }
}

async fn managed_rig() -> Rig {
    managed_rig_with(world(), Limits::default()).await
}

/// The runner's owner lifts `producer`'s delivered revision of `pol` at `revision` (an attended
/// decision at the runner: the policy resumed, or its cutoff cleared, and the effect's flag
/// cleared).
fn lift_at_runner(r: &Rig, producer: &ClientId, revision: u64) {
    r.w.store
        .transaction(|tx| {
            let mut p = tx.policy(&policy_id())?.unwrap();
            p.pause = heimdall_domain::policy::PauseState::Active;
            p.cutoff_at = None;
            p.revision = heimdall_domain::policy::PolicyRevision(p.revision.0 + 1);
            tx.upsert_policy(&p, false)?;
            tx.lift_remote_policy_revision("policy:pol", producer, revision)
                .map(drop)
        })
        .unwrap();
}

/// The runner's report as a paired owner controller's session is served it.
async fn report(r: &Rig, c: &ClientId) -> Result<AuthorityReport, (Code, Option<String>)> {
    let served =
        r.w.runner
            .serve_sync(
                &r.sync,
                &Rig::caller(c),
                41,
                &RunnerRequest::AuthorityReport,
            )
            .await;
    match served {
        Ok(done) => Ok(serde_json::from_value(done.data).unwrap()),
        Err(e) => Err((e.code, e.reason)),
    }
}

fn report_bytes(report: &AuthorityReport) -> usize {
    serde_json::to_vec(report).unwrap().len()
}

// --- the override and the caps (R1, R2) ---------------------------------------------------

/// ⟨R1; the override⟩ A producer's revokes of grant IDs the runner does not hold are capped at
/// 256, and every producer's together at 1,024: past either cap the delivery is refused
/// `BACKPRESSURE` and nothing is recorded. A redelivery of one already recorded is answered as
/// before (nothing grows). At both caps, a revoke of a grant the runner holds and a cutoff of
/// its policy still land.
#[tokio::test]
async fn bare_revokes_are_capped_and_effective_narrowings_still_land() {
    let r = managed_rig().await;
    let a = controller_a();
    for n in 0..BARE_PER_PRODUCER as u32 {
        let target = revoke(&unknown_grant(n));
        r.deliver(&a, &eff(1, n), &target).await.unwrap();
    }
    let over = r
        .deliver(
            &a,
            &eff(1, 9999),
            &revoke(&unknown_grant(BARE_PER_PRODUCER as u32)),
        )
        .await;
    let before = tombstones(&r).len();
    assert_eq!(
        over.as_ref().map_err(|e| e.code.clone()).err(),
        Some(Code::Backpressure),
        "the producer's bare revoke past its cap: {over:?}"
    );
    assert_eq!(
        before, BARE_PER_PRODUCER,
        "nothing was recorded past the cap"
    );
    // A redelivery of a recorded one: answered, nothing grows.
    r.deliver(&a, &eff(1, 0), &revoke(&unknown_grant(0)))
        .await
        .unwrap();
    assert_eq!(tombstones(&r).len(), BARE_PER_PRODUCER);
    // The total: unattributed bare tombstones fill it (as older ones of other producers do).
    let now = r.w.clock.wall();
    r.w.store
        .transaction(|tx| {
            for n in 0..(BARE_TOTAL - BARE_PER_PRODUCER) as u32 {
                tx.insert_tombstone(&Tombstone {
                    grant: unknown_grant(100_000 + n),
                    cascade: Vec::new(),
                    generation: AuthorityGeneration(0),
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })?;
            }
            Ok(())
        })
        .unwrap();
    let b = controller_b();
    let over_total = r
        .deliver(&b, &eff(2, 0), &revoke(&unknown_grant(200_000)))
        .await;
    assert_eq!(
        over_total.as_ref().map_err(|e| e.code.clone()).err(),
        Some(Code::Backpressure),
        "a bare revoke past the total cap: {over_total:?}"
    );
    // The override: at both caps, the held grant's revoke and a cutoff of `pol` land.
    let cut = cutoff(pol_scope(), plus(t0(), HOUR), 1);
    r.deliver(&b, &eff(2, 1), &cut).await.unwrap();
    let held = revoke(&r.w.grant);
    let ack = r.deliver(&b, &eff(2, 2), &held).await.unwrap();
    assert!(matches!(
        ack.record,
        heimdall_store::ext_effects::AppliedRecord::GrantTombstone { known: true, .. }
    ));
    assert_eq!(r.grant_state(), GrantState::Revoked);
    assert_eq!(r.policy().cutoff_at, Some(plus(t0(), HOUR)));
}

/// ⟨R2; the override⟩ Delivered pauses and cutoffs are coalesced per producer, scope and kind
/// while in force: one row, a cutoff's instant only shortening. A producer's in-force rows
/// whose scope matches nothing on the runner are capped at 256 (`BACKPRESSURE` past it, nothing
/// recorded); at the cap, a pause and a cutoff of the runner's policy, and a cutoff of
/// everything, still land.
#[tokio::test]
async fn revisions_are_coalesced_and_unmatched_scopes_capped() {
    let r = managed_rig().await;
    let a = controller_a();
    // 50 pauses of the runner's policy, then 50 cutoffs of it with later and earlier instants.
    for n in 1..=50u32 {
        r.deliver(&a, &eff(3, n), &pause("pol", u64::from(n)))
            .await
            .unwrap();
    }
    for n in 51..=100u32 {
        let at = plus(t0(), Duration::from_secs(3600 + u64::from(n % 7) * 60));
        r.deliver(&a, &eff(3, n), &cutoff(pol_scope(), at, u64::from(n)))
            .await
            .unwrap();
    }
    let rows = revisions(&r);
    let mine = |kind: PolicyRevisionKind| {
        rows.iter()
            .filter(|row| row.producer == a && row.scope_key == "policy:pol" && row.kind == kind)
            .count()
    };
    assert_eq!(
        mine(PolicyRevisionKind::Pause),
        1,
        "pauses coalesced: {}",
        rows.len()
    );
    assert_eq!(
        mine(PolicyRevisionKind::Cutoff),
        1,
        "cutoffs coalesced: {}",
        rows.len()
    );
    let cut = rows
        .iter()
        .find(|row| row.kind == PolicyRevisionKind::Cutoff)
        .unwrap();
    assert_eq!(
        cut.cutoff_at,
        Some(plus(t0(), HOUR)),
        "the earliest instant stands"
    );
    // Unmatched scopes: 256 distinct policies the runner does not have.
    for n in 0..UNMATCHED_PER_PRODUCER as u32 {
        r.deliver(&a, &eff(4, n), &pause(&format!("ghost{n}"), 1))
            .await
            .unwrap();
    }
    let over = r.deliver(&a, &eff(4, 9999), &pause("ghost-over", 1)).await;
    assert_eq!(
        over.as_ref().map_err(|e| e.code.clone()).err(),
        Some(Code::Backpressure),
        "an unmatched revision past its cap: {over:?}"
    );
    assert!(
        !revisions(&r)
            .iter()
            .any(|row| row.scope_key == "policy:ghost-over")
    );
    // A redelivered (coalesced) unmatched one is answered.
    r.deliver(&a, &eff(4, 10_000), &pause("ghost0", 2))
        .await
        .unwrap();
    // The override at the cap.
    r.deliver(&a, &eff(5, 1), &pause("pol", 200)).await.unwrap();
    r.deliver(&a, &eff(5, 2), &cutoff(pol_scope(), plus(t0(), HOUR), 201))
        .await
        .unwrap();
    r.deliver(
        &a,
        &eff(5, 3),
        &cutoff(PolicyTarget::All, plus(t0(), HOUR), 1),
    )
    .await
    .unwrap();
    assert!(matches!(
        r.policy().pause,
        heimdall_domain::policy::PauseState::Paused { .. }
    ));
}

/// ⟨R4; the override⟩ Pending paired widening records are capped: 32 per client and 128 in
/// total (`BACKPRESSURE` past either, nothing recorded). At the caps an effective revoke and an
/// effective cutoff still land.
#[tokio::test]
async fn pending_widening_records_are_capped_and_effective_narrowings_still_land() {
    let r = managed_rig().await;
    let records = StoreWidening::new(r.w.store.clone());
    let now = r.w.clock.wall();
    let generation = AuthorityGeneration(r.w.generation());
    for c in 0..4u8 {
        let client = client(0x40 + c);
        for n in 0..WIDENING_PER_CLIENT as u32 {
            let (done, _) = submit(&records, &client, &invite(c, n), generation, now).unwrap();
            assert!(matches!(done, Submitted::Created(_)));
        }
        let over = submit(&records, &client, &invite(c, 999), generation, now);
        assert_eq!(
            over.as_ref().map_err(|e| e.code()).err(),
            Some(Code::Backpressure),
            "client {c}: a pending record past the client's cap"
        );
    }
    let fifth = submit(&records, &client(0x50), &invite(9, 0), generation, now);
    assert_eq!(
        fifth.as_ref().map_err(|e| e.code()).err(),
        Some(Code::Backpressure),
        "a pending record past the total cap"
    );
    let pending =
        r.w.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .len();
    assert_eq!(pending, WIDENING_TOTAL);
    // The override at the caps.
    let b = controller_b();
    r.deliver(&b, &eff(6, 1), &cutoff(pol_scope(), plus(t0(), HOUR), 1))
        .await
        .unwrap();
    r.deliver(&b, &eff(6, 2), &revoke(&r.w.grant))
        .await
        .unwrap();
    assert_eq!(r.grant_state(), GrantState::Revoked);
}

/// An `invite` widening request with a distinct key, as a paired client submits it.
fn invite(c: u8, n: u32) -> Request {
    let (public_key, fingerprint) = fixture_key();
    serde_json::from_value(serde_json::json!({
        "op": "remote_environment",
        "action": "invite",
        "environment": heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16]),
        "role": "viewer",
        "key_fingerprint": fingerprint,
        "public_key": public_key,
        "request_id": format!("rq-{c}-{n}"),
    }))
    .unwrap()
}

/// A public fixture key and its fingerprint (no private half exists anywhere).
fn fixture_key() -> (String, String) {
    let key = heimdall_remote::line::PublicKeyText::parse(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGcGmKqKxFp+T5LGPkjZcXFDhK/0rNu2tsr3sH5e3Ygq",
    )
    .unwrap();
    (key.openssh(), key.fingerprint().as_str().to_owned())
}

// --- R1: tombstones -----------------------------------------------------------------------

/// ⟨R1⟩ The retention pass ends tombstones on their conditions, on safe time only. A known
/// tombstone goes once its grant's deadline and the retention have passed and nothing of it is
/// live; its `revoked` row still denies (`denied_ancestor`), and a late redelivery of its revoke
/// converges on that row. A bare one goes at its revoke plus the 30-day fallback window plus the
/// retention. Under uncertain time nothing is pruned.
#[tokio::test]
async fn tombstones_are_pruned_on_safe_time_only_and_their_rows_still_deny() {
    let r = managed_rig().await;
    let a = controller_a();
    let held = revoke(&r.w.grant);
    r.deliver(&a, &eff(7, 1), &held).await.unwrap();
    let bare = revoke(&unknown_grant(1));
    r.deliver(&a, &eff(7, 2), &bare).await.unwrap();
    assert_eq!(tombstones(&r).len(), 2);
    // Past the grant's deadline and the retention, but under uncertain time: nothing.
    r.w.clock.advance(2 * HOUR + RETENTION + DAY);
    r.make_time_uncertain().await;
    tick(&r).await;
    assert_eq!(tombstones(&r).len(), 2, "pruned under uncertain time");
    // Safe again (the wall back where the continuous clock has it): the known tombstone
    // goes; the bare one stays (30 days + retention).
    r.w.clock.set_wall(plus(r.w.clock.wall(), HOUR));
    assert!(
        r.ops.timegate().check().await.is_ok(),
        "time is not safe again"
    );
    tick(&r).await;
    let left: Vec<GrantId> = tombstones(&r).into_iter().map(|t| t.grant).collect();
    assert_eq!(
        left,
        vec![unknown_grant(1)],
        "the known tombstone was not pruned"
    );
    let denied =
        r.w.store
            .transaction(|tx| tx.denied_ancestor(&r.w.grant))
            .unwrap();
    assert_eq!(
        denied,
        Some(r.w.grant.clone()),
        "its revoked row still denies"
    );
    // A late redelivery of the revoke (its acknowledgement lost, its request past retention):
    // it converges.
    let again = r.deliver(&a, &eff(7, 1), &held).await;
    assert!(
        again.is_ok(),
        "the late redelivery did not converge: {again:?}"
    );
    assert!(ack_of(&r, &key(&a, &eff(7, 1), &held)));
    // Past the bare tombstone's window.
    r.w.clock.advance(30 * DAY);
    tick(&r).await;
    assert!(
        tombstones(&r).is_empty(),
        "the bare tombstone was not pruned"
    );
}

// --- R2 and R3: revisions and acknowledgements ---------------------------------------------

/// ⟨R2, R3⟩ A delivered pause is never pruned while in force, nor its acknowledgement. Lifted
/// at the runner, it is kept until its producer confirmed the lift (a complete report, then the
/// session going on), then pruned after the retention; the controller still shows the lift
/// (with its owner's acknowledgement, issuance is not held by it). A runner restored from
/// before the lift, reporting it in force, blocks again. A revoked producer's lifted row goes
/// without a confirmation.
#[tokio::test]
async fn lifted_revisions_go_after_confirmation_and_in_force_ones_never() {
    let r = managed_rig().await;
    r.w.designate(&controller_a());
    let a = controller_a();
    let c = controller(&r, &a, Role::Owner);
    let paused = c
        .produce(&Narrowing::PausePolicy {
            policy: policy_id(),
        })
        .unwrap();
    c.resync(&mut r.session(&a)).await.unwrap();
    assert_eq!(c.pending(), 0);
    // In force: kept, with its acknowledgement, past any retention.
    r.w.clock.advance(RETENTION + DAY);
    tick(&r).await;
    assert_eq!(revisions(&r).len(), 1);
    assert!(ack_of(&r, &paused));
    // The runner's owner lifts it (an attended decision at the runner).
    lift_at_runner(&r, &a, 1);
    // The controller's owner acknowledges the lift.
    let env = r.w.env.clone();
    let now = c.now();
    c.store
        .transaction(|tx| tx.acknowledge_remote_lift(&env, &paused, now))
        .unwrap();
    // Not confirmed yet: kept.
    r.w.clock.advance(RETENTION + DAY);
    tick(&r).await;
    assert_eq!(
        revisions(&r).len(),
        1,
        "a lifted row went before its confirmation"
    );
    // The controller resynchronizes: its report shows the lift; its session goes on.
    let mut session = r.session(&a);
    session.connection = 8;
    c.resync(&mut session).await.unwrap();
    r.w.clock.advance(RETENTION + DAY);
    tick(&r).await;
    assert!(
        revisions(&r).is_empty(),
        "the confirmed lifted row was not pruned"
    );
    assert!(!ack_of(&r, &paused), "its acknowledgement was not pruned");
    // The controller, reading the report without the row, still shows the lift.
    let mut session = r.session(&a);
    session.connection = 9;
    c.resync(&mut session).await.unwrap();
    let grant = GrantId::from_random_bytes([0x71; 16]);
    let now = c.now();
    let verdict = c
        .store
        .transaction(|tx| c.barrier.permit(tx, &env, &grant, Some(&policy_id()), now))
        .unwrap();
    assert!(
        !matches!(verdict, Err(BarrierRefusal::PolicyPaused)),
        "the pruned row re-blocked the controller: {verdict:?}"
    );
    // A runner restored from before the lift: the row in force again. Blocked again.
    let restored = PolicyRevisionRecord {
        scope_key: "policy:pol".into(),
        scope: pol_scope(),
        producer: a.clone(),
        revision: 1,
        runner_seq: 0,
        kind: PolicyRevisionKind::Pause,
        effect: paused.effect.clone(),
        received_at: t0(),
        cutoff_at: None,
        fired_uncertain_at: None,
        in_force: true,
    };
    r.w.store
        .transaction(|tx| tx.record_remote_policy_revision(&restored))
        .unwrap();
    let mut session = r.session(&a);
    session.connection = 10;
    c.resync(&mut session).await.unwrap();
    let now = c.now();
    let verdict = c
        .store
        .transaction(|tx| c.barrier.permit(tx, &env, &grant, Some(&policy_id()), now))
        .unwrap();
    assert_eq!(
        verdict,
        Err(BarrierRefusal::PolicyPaused),
        "a restored in-force row blocks"
    );
    // A revoked producer's lifted row goes without a confirmation.
    let b = controller_b();
    let cut = cutoff(pol_scope(), plus(c.now(), HOUR), 1);
    r.deliver(&b, &eff(8, 1), &cut).await.unwrap();
    lift_at_runner(&r, &b, 1);
    let at = r.w.clock.wall();
    r.w.store
        .transaction(|tx| {
            tx.revoke_remote_client(&b, ClientRevocation::Revoked, at)
                .map(drop)
        })
        .unwrap();
    // The pass that first finds it lifted records when; the retention runs from there.
    tick(&r).await;
    assert!(revisions(&r).iter().any(|row| row.producer == b));
    r.w.clock.advance(RETENTION + DAY);
    tick(&r).await;
    assert!(
        !revisions(&r).iter().any(|row| row.producer == b),
        "a revoked producer's lifted row was not pruned"
    );
    assert!(!ack_of(&r, &key(&b, &eff(8, 1), &cut)));
}

/// ⟨R3⟩ A `grant_revoke`'s acknowledgement goes after the retention (its tombstone stays for
/// its own window); a pause's never while it is in force.
#[tokio::test]
async fn acknowledgements_go_with_their_history_never_while_in_force() {
    let r = managed_rig().await;
    let a = controller_a();
    let bare = revoke(&unknown_grant(3));
    r.deliver(&a, &eff(9, 1), &bare).await.unwrap();
    let paused = pause("pol", 1);
    r.deliver(&a, &eff(9, 2), &paused).await.unwrap();
    r.w.clock.advance(RETENTION + DAY);
    tick(&r).await;
    assert!(
        !ack_of(&r, &key(&a, &eff(9, 1), &bare)),
        "the revoke's acknowledgement stayed"
    );
    assert_eq!(
        tombstones(&r).len(),
        1,
        "the bare tombstone keeps its own window"
    );
    assert!(
        ack_of(&r, &key(&a, &eff(9, 2), &paused)),
        "an in-force pause's acknowledgement was pruned"
    );
}

// --- R4: widening records ------------------------------------------------------------------

/// ⟨R4⟩ The retention pass settles a pending paired record past its deadline `expired`, then,
/// after the retention, purges every settled record into a 30-day marker: a replay of its key
/// is `REQUEST_EXPIRED`. An approved record with no result (`OUTCOME_UNKNOWN`) is never purged.
#[tokio::test]
async fn widening_records_lapse_and_are_purged_into_markers() {
    let r = managed_rig().await;
    let records = StoreWidening::new(r.w.store.clone());
    let now = r.w.clock.wall();
    let generation = AuthorityGeneration(r.w.generation());
    let client = client(0x44);
    let mut ids = Vec::new();
    for n in 0..3u32 {
        let (done, _) = submit(&records, &client, &invite(1, n), generation, now).unwrap();
        let Submitted::Created(id) = done else {
            panic!("created")
        };
        ids.push(id);
    }
    // One approved, its result never recorded: OUTCOME_UNKNOWN.
    r.w.store
        .transaction(|tx| {
            tx.settle_remote_widening(&ids[2], DecisionState::Approved, now, None)
                .map(drop)
        })
        .unwrap();
    // Past the deadline: the pass lapses the pending ones.
    r.w.clock.advance(Duration::from_secs(20 * 60));
    tick(&r).await;
    let state = |id| {
        r.w.store
            .transaction(|tx| tx.decision(id))
            .unwrap()
            .map(|d| d.state)
    };
    assert_eq!(
        state(&ids[0]),
        Some(DecisionState::Expired),
        "not lapsed by the pass"
    );
    // Past the retention: purged, with a marker; OUTCOME_UNKNOWN stays.
    r.w.clock.advance(RETENTION + DAY);
    tick(&r).await;
    assert_eq!(state(&ids[0]), None, "a settled record was not purged");
    assert_eq!(state(&ids[2]), Some(DecisionState::Approved));
    let now = r.w.clock.wall();
    let replay = submit(&records, &client, &invite(1, 0), generation, now);
    assert_eq!(
        replay.as_ref().map_err(|e| e.code()).err(),
        Some(Code::RequestExpired),
        "a purged key's replay: {replay:?}"
    );
    // After the marker window the key is free again.
    r.w.clock.advance(31 * DAY);
    tick(&r).await;
    let now = r.w.clock.wall();
    assert!(submit(&records, &client, &invite(1, 0), generation, now).is_ok());
}

// --- R5: the report ---------------------------------------------------------------------------

/// ⟨R5⟩ A report over its budget is refused whole (`USAGE_ERROR` / `response_too_large`): the
/// controller's barrier stays closed and its reconciliation writes nothing (no tombstone, no
/// generation move, no observed report). Once the retention pass prunes the history under the
/// budget, the next resynchronization reopens it.
#[tokio::test]
async fn an_over_budget_report_keeps_the_barrier_closed_and_reopens_after_pruning() {
    let r = managed_rig().await;
    let a = controller_a();
    // Bare tombstones of 128-character grant IDs: past the budget.
    let now = r.w.clock.wall();
    r.w.store
        .transaction(|tx| {
            for n in 0..4_500u32 {
                let id = format!("grant_{n:0>122}");
                tx.insert_tombstone(&Tombstone {
                    grant: GrantId::parse(&id).unwrap(),
                    cascade: Vec::new(),
                    generation: AuthorityGeneration(0),
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })?;
            }
            Ok(())
        })
        .unwrap();
    let served = report(&r, &a).await;
    assert_eq!(
        served.as_ref().err().cloned(),
        Some((
            Code::UsageError,
            Some(reason::RESPONSE_TOO_LARGE.to_owned())
        )),
        "an over-budget report was served ({} bytes)",
        served.as_ref().map(report_bytes).unwrap_or_default()
    );
    let c = controller(&r, &a, Role::Owner);
    let env = r.w.env.clone();
    let before = c
        .store
        .transaction(|tx| Ok((tx.tombstones()?.len(), tx.authority_generation()?)))
        .unwrap();
    let refused = c.resync(&mut r.session(&a)).await;
    assert_eq!(
        refused
            .as_ref()
            .err()
            .and_then(|e| e.reason.clone())
            .as_deref(),
        Some(reason::RESPONSE_TOO_LARGE)
    );
    assert!(
        c.barrier.reconciliation(&env).is_none(),
        "the barrier opened"
    );
    let after = c
        .store
        .transaction(|tx| Ok((tx.tombstones()?.len(), tx.authority_generation()?)))
        .unwrap();
    assert_eq!(before, after, "the refused report wrote authority");
    assert!(
        c.store
            .transaction(|tx| tx.remote_contact(&env))
            .unwrap()
            .last_report
            .is_none(),
        "the refused report was recorded as observed"
    );
    // What `environment status` and `doctor` say once the controller's host records the
    // failure (`ControllerHost::lost`: the error's reason).
    let why = heimdall_app::remote_status::failure_reason(refused.as_ref().err().unwrap());
    let now = c.now();
    c.store
        .transaction(|tx| tx.note_remote_failure(&env, now, &why))
        .unwrap();
    let contact = c.store.transaction(|tx| tx.remote_contact(&env)).unwrap();
    let (statement, next) = heimdall_app::remote_status::report_over_limit(&contact).unwrap();
    assert_eq!(
        statement,
        "the runner's authority report is over its size limit; remote issuance stays closed \
         until history ages out (retention)"
    );
    assert!(
        next.contains("heimdall environment revoke-client"),
        "{next}"
    );
    // `doctor` lists every recorded runner (the controller's record of this one, as `add`
    // writes it).
    let pin = c.pin.clone();
    c.store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                &pin.environment,
                &pin.destination,
                &pin.route.runner.account,
                &pin.key_fingerprint,
                &serde_json::to_string(&pin).unwrap(),
                pin.pinned_at,
            )
        })
        .unwrap();
    let listed = c
        .store
        .transaction(heimdall_app::remote_status::reports_over_limit)
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, env);
    // The history ages out; the barrier reopens at the next resynchronization.
    r.w.clock.advance(30 * DAY + RETENTION + DAY);
    tick(&r).await;
    let served = report(&r, &a).await.unwrap();
    assert!(report_bytes(&served) <= BUDGET);
    c.resync(&mut r.session(&a)).await.unwrap();
    assert!(
        c.barrier.reconciliation(&env).is_some(),
        "the barrier did not reopen"
    );
    assert!(
        heimdall_app::remote_status::report_over_limit(
            &c.store.transaction(|tx| tx.remote_contact(&env)).unwrap()
        )
        .is_none(),
        "the statement stays after the reopening"
    );
}

/// ⟨R5⟩ **The envelope's worst case** (`docs/user/limitations.md`, "Remote authority
/// report"): the report at the supported envelope's maximum, every identifier and free field at
/// its longest (128 characters where a peer or the owner chooses it), every number at its
/// largest, is within the 768 KiB budget. The envelope, under the caps and the pruning:
/// 1,024 bare tombstones (the cap); 500 known tombstones (grants revoked within their window
/// plus the retention), each with 2 descendants; 400 delivered revision rows of every paired
/// controller together (in force, coalesced per producer, scope and kind, and lifted ones
/// awaiting their confirmation and the retention; one compromised owner at its 256-row cap of
/// unmatched scopes fits); 64 runner policies; 96 installed certificates; 16 grants waiting for
/// their issuer, of 8 pairs each.
#[test]
fn the_report_at_the_envelopes_maximum_is_within_the_budget() {
    let report = envelope_report();
    let bytes = report_bytes(&report);
    #[allow(clippy::print_stdout)] // the measured size is the proof's evidence line
    {
        println!(
            "envelope report: {bytes} bytes (budget {BUDGET}); tombstones {}, revisions {}, \
             policies {}, certificates {}, pending grants {}",
            report.tombstones.len(),
            report.policy_revisions.len(),
            report.policies.len(),
            report.certificates.len(),
            report.pending_grants.len()
        );
    }
    assert!(bytes <= BUDGET, "{bytes} > {BUDGET}");
}

/// The envelope's limits (doc of [`the_report_at_the_envelopes_maximum_is_within_the_budget`]).
const ENVELOPE_BARE: usize = 1024;
const ENVELOPE_KNOWN: usize = 500;
const ENVELOPE_DESCENDANTS: usize = 2;
const ENVELOPE_REVISIONS: usize = 400;
const ENVELOPE_LIFTED: usize = 50;
const ENVELOPE_POLICIES: usize = 64;
const ENVELOPE_CERTIFICATES: usize = 96;
const ENVELOPE_PENDING: usize = 16;
const ENVELOPE_PAIRS: usize = 8;

/// The envelope's report (doc of [`the_report_at_the_envelopes_maximum_is_within_the_budget`]).
fn envelope_report() -> AuthorityReport {
    let long = |prefix: &str, n: usize| {
        let body = format!("{n:0>width$}", width = 128 - prefix.len() - 1);
        format!("{prefix}_{body}")
    };
    let token = |n: usize| format!("{n:0>128}");
    let ts: Timestamp = "2026-11-27T09:00:00.123456789Z".parse().unwrap();
    let owners: Vec<ClientId> = (0..8u8)
        .map(|n| ClientId::from_random_bytes([n; 16]))
        .collect();
    let mut tombstones = Vec::new();
    for n in 0..ENVELOPE_BARE {
        tombstones.push(ReportedTombstone {
            grant: GrantId::parse(&long("grant", n)).unwrap(),
            cascade: Vec::new(),
            generation: u64::MAX,
            revoked_at: ts,
        });
    }
    for n in 0..ENVELOPE_KNOWN {
        tombstones.push(ReportedTombstone {
            grant: GrantId::from_random_bytes(tag(1, n as u32)),
            cascade: (0..ENVELOPE_DESCENDANTS)
                .map(|k| GrantId::from_random_bytes(tag(2 + k as u8, n as u32)))
                .collect(),
            generation: u64::MAX,
            revoked_at: ts,
        });
    }
    let revisions = (0..ENVELOPE_REVISIONS)
        .map(|n| {
            let kind = if n % 2 == 0 {
                PolicyRevisionKind::Pause
            } else {
                PolicyRevisionKind::Cutoff
            };
            let policy = PolicyId::parse(&token(n)).unwrap();
            PolicyRevisionRecord {
                scope_key: format!("policy:{policy}"),
                scope: PolicyTarget::Policy { policy_id: policy },
                producer: owners[n % owners.len()].clone(),
                revision: u64::MAX,
                runner_seq: u64::MAX,
                kind,
                effect: EffectId::parse(&long("eff", n)).unwrap(),
                received_at: ts,
                cutoff_at: Some(ts),
                fired_uncertain_at: Some(ts),
                in_force: n >= ENVELOPE_LIFTED,
            }
        })
        .map(|mut r| {
            if r.kind == PolicyRevisionKind::Pause {
                r.cutoff_at = None;
                r.fired_uncertain_at = None;
            }
            r
        })
        .collect();
    let policies = (0..ENVELOPE_POLICIES)
        .map(|n| ReportedPolicy {
            policy: PolicyId::parse(&token(10_000 + n)).unwrap(),
            revision: u64::MAX,
            paused: true,
            cutoff_at: Some(ts),
        })
        .collect();
    let pair = |n: usize| heimdall_contract::request::AccessPairRef {
        destination: heimdall_contract::ids::DestinationId::parse(&token(n)).unwrap(),
        account: heimdall_contract::ids::AccountName::parse(&token(n)).unwrap(),
    };
    let certificates = (0..ENVELOPE_CERTIFICATES)
        .map(|n| ReportedCertificate {
            grant: GrantId::from_random_bytes(tag(8, n as u32)),
            grant_generation: u64::MAX,
            pair: pair(n),
            serial: u64::MAX,
            valid_before: ts,
            issuer: owners[n % owners.len()].clone(),
        })
        .collect();
    let pending_grants = (0..ENVELOPE_PENDING)
        .map(|n| ReportedPendingGrant {
            grant: GrantId::from_random_bytes(tag(9, n as u32)),
            profile: heimdall_contract::ids::ProfileId::parse(&token(20_000 + n)).unwrap(),
            pairs: (0..ENVELOPE_PAIRS)
                .map(|k| pair(30_000 + n * ENVELOPE_PAIRS + k))
                .collect::<BTreeSet<_>>(),
            expires_at: ts,
        })
        .collect();
    AuthorityReport {
        environment: heimdall_contract::ids::EnvironmentId::from_random_bytes([9; 16]),
        authority_generation: u64::MAX,
        tombstones,
        policy_revisions: revisions,
        policies,
        certificates,
        time_bounded: true,
        pending_grants,
    }
}

// --- the history-growth workload -------------------------------------------------------------

/// What one day of the workload measured.
#[derive(Debug, Clone, Copy)]
struct Day {
    tombstones: usize,
    revisions: usize,
    decisions: usize,
    report_bytes: usize,
    store_bytes: u64,
    resync_us: u128,
}

/// ⟨R1–R5⟩ The history-growth workload (`run-soak.sh --authority-history-growth`, beside
/// GRANT-LIVE's grant-history workload), without the design's paging parts. Each simulated day:
/// a grant is admitted and revoked by a delivered effect (a known tombstone), `bare_per_day`
/// revokes of grant IDs the runner never held (past the producer's cap of 256 they are refused,
/// as a compromised controller's flood is), a pause of the runner's policy that the runner's
/// owner lifts and both owners acknowledge, widening requests that lapse, the controller's
/// resynchronization (its report frame measured), then the retention pass. `retention` is
/// `retention.operations` (scaled down). It passes when every report frame is within the
/// budget and, after one retention cycle plus the 30-day fallback window, the history's row
/// counts and the database's size (with its log) stay flat and resynchronization does not slow
/// down.
async fn history_growth(days: u32, bare_per_day: u32, retention: Duration) -> Vec<Day> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runner.sqlite");
    let store =
        Arc::new(heimdall_store::Store::open(&path, Arc::new(heimdall_store::NoFaults)).unwrap());
    let limits = Limits {
        operation_retention: retention,
        ..Limits::default()
    };
    let r = managed_rig_with(world_in(store), limits).await;
    r.w.designate(&controller_a());
    let a = controller_a();
    let c = controller(&r, &a, Role::Owner);
    let env = r.w.env.clone();
    let records = StoreWidening::new(r.w.store.clone());
    let mut out = Vec::new();
    for day in 0..days {
        // A grant admitted, then revoked by a delivered effect.
        let grant = GrantId::from_random_bytes(tag(0x77, day));
        add_grant(&r, &grant, plus(r.w.clock.wall(), 2 * HOUR));
        r.deliver(&a, &eff(0x10, day), &revoke(&grant))
            .await
            .unwrap();
        // Revokes of grant IDs the runner never held: a flood past the producer's cap, whose
        // excess is refused `BACKPRESSURE` (nothing recorded).
        for n in 0..bare_per_day {
            let target = revoke(&unknown_grant(day * 1000 + n));
            match r.deliver(&a, &eff(0x11, day * 1000 + n), &target).await {
                Ok(_) => {}
                Err(e) => assert_eq!(e.code, Code::Backpressure, "day {day}: {e:?}"),
            }
        }
        // A pause the runner's owner lifts and the controller's owner acknowledges.
        let paused = c
            .produce(&Narrowing::PausePolicy {
                policy: policy_id(),
            })
            .unwrap();
        let mut session = r.session(&a);
        session.connection = u64::from(day) * 2 + 100;
        c.resync(&mut session).await.unwrap();
        lift_at_runner(&r, &a, paused.target.generation());
        let now = c.now();
        c.store
            .transaction(|tx| tx.acknowledge_remote_lift(&env, &paused, now))
            .unwrap();
        // Widening requests that lapse.
        let generation = AuthorityGeneration(r.w.generation());
        for n in 0..4u32 {
            let _ = submit(
                &records,
                &client(0x60),
                &invite(2, day * 10 + n),
                generation,
                now,
            );
        }
        // The resynchronization the day ends with (it confirms yesterday's lifts too).
        let started = std::time::Instant::now();
        let mut session = r.session(&a);
        session.connection = u64::from(day) * 2 + 101;
        let outcome = c.resync(&mut session).await.unwrap();
        let resync_us = started.elapsed().as_micros();
        let report_bytes = report_bytes(&outcome.report);
        assert!(
            report_bytes <= BUDGET,
            "day {day}: a {report_bytes}-byte report frame"
        );
        r.w.clock.advance(DAY);
        tick(&r).await;
        let (tombstones, revisions, decisions) =
            r.w.store
                .transaction(|tx| {
                    Ok((
                        tx.tombstones()?.len(),
                        tx.remote_policy_revisions()?.len(),
                        tx.pending_decisions()?.len(),
                    ))
                })
                .unwrap();
        let size = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let mut wal = path.clone().into_os_string();
        wal.push("-wal");
        let store_bytes = size(&path) + size(std::path::Path::new(&wal));
        out.push(Day {
            tombstones,
            revisions,
            decisions,
            report_bytes,
            store_bytes,
            resync_us,
        });
    }
    out
}

/// The workload's verdict (doc of [`history_growth`]): from day `settled` on, no count passes
/// the highest it reached before (plus 2, a day's known tombstone and lifted row in flight), the
/// database (with its log) stays within 1.25× its size that day, and the median
/// resynchronization within 3× (plus 2 ms) the median of the days before.
fn assert_flat(days: &[Day], settled: usize) {
    let base = days[settled];
    let high = |f: fn(&Day) -> usize| days[..settled].iter().map(f).max().unwrap_or(0);
    let (tombstones, revisions, decisions) = (
        high(|d| d.tombstones),
        high(|d| d.revisions),
        high(|d| d.decisions),
    );
    for (n, d) in days.iter().enumerate().skip(settled) {
        assert!(
            d.tombstones <= tombstones + 2,
            "day {n}: tombstones grew: {days:?}"
        );
        assert!(
            d.revisions <= revisions + 2,
            "day {n}: revisions grew: {days:?}"
        );
        assert!(
            d.decisions <= decisions.max(4),
            "day {n}: decisions grew: {days:?}"
        );
        assert!(
            d.store_bytes * 4 <= base.store_bytes * 5,
            "day {n}: the database grew: {days:?}"
        );
    }
    let median = |s: &[Day]| {
        let mut v: Vec<u128> = s.iter().map(|d| d.resync_us).collect();
        v.sort_unstable();
        v[v.len() / 2]
    };
    let early = median(&days[1..settled]);
    let late = median(&days[settled..]);
    assert!(
        late <= early * 3 + 2000,
        "resynchronization slowed down: {early} µs then {late} µs"
    );
}

/// ⟨R1–R5⟩ The history-growth workload's short form, in every test run: 50 days at a 1-day
/// retention (the floor), 20 bare revokes a day (the cap is reached on day 13). Flat from day
/// 40 on (the cap, the 30-day fallback window, 1 retention day and a margin).
#[tokio::test]
async fn authority_history_stays_flat_across_retention_cycles() {
    let days = history_growth(50, 20, DAY).await;
    assert_flat(&days, 40);
}

/// ⟨R1–R5⟩ The history-growth workload's full form: 120 days at a 1-day retention, 100 bare
/// revokes a day (12,000 delivered, over 12,800 events in all, most of the bare ones refused
/// at the cap); one JSON line per day.
#[tokio::test]
#[ignore = "run with tools/benchmarks/m08/run-soak.sh --authority-history-growth"]
#[allow(clippy::print_stdout)] // one JSON sample per simulated day
async fn authority_history_growth() {
    let days = history_growth(120, 100, DAY).await;
    for (n, d) in days.iter().enumerate() {
        println!(
            "{}",
            serde_json::json!({
                "workload": "authority_history_growth",
                "day": n,
                "tombstones": d.tombstones,
                "policy_revisions": d.revisions,
                "pending_decisions": d.decisions,
                "report_bytes": d.report_bytes,
                "store_and_wal_bytes": d.store_bytes,
                "resync_us": d.resync_us,
            })
        );
    }
    assert_flat(&days, 40);
}
