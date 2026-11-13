//! ⟨M03 wave 4, round 5 (Y-S); W4-C02⟩ ADR-0008 §17.22 item 7 and §17.23 item 1 for a
//! **follower**, live: through the real `Operations`, managed adapter, driver,
//! `ManagedEffectsImpl`, signer table and `EndpointRegistry` of [`super::Live`], with the
//! evidence comparison's inputs fed as the runtime feeds them ([`super::LiveFeed`]).
//!
//! A coalesced or decision-joined follower skips preparation; its managed scope claim
//! is recomputed at its own commit from evidence read then (the grant's pairs, the
//! current client and target evaluation, the installed certificate's CA). A leader's
//! historical result never satisfies a follower's present minimum.
//!
//! The evidence change is made by a [`StageHook`] **after the leader's `Commit`** and
//! before the follower's: it changes only the external evidence feed (the verifying
//! client), never a store fact or an application check.
//!
//! Every key and the CA are generated per run in scratch directories; nothing of the
//! owner's is read, contacted or changed.

use super::*;
use heimdall_contract::request::DestinationScopeEnforcement as Scope_;

/// The verifying client after the change: the evidence names `OpenSSH_10.5p1`.
const CHANGED_CLIENT: &str = "OpenSSH_10.6p1, LibreSSL 3.3.6";

/// Changes the verifying client to [`CHANGED_CLIENT`] right after the first `Commit`
/// stage durably completed (the leader's), once, while armed.
struct ClientChangeAfterCommit {
    feed: Arc<LiveFeed>,
    armed: AtomicBool,
    fired: AtomicBool,
}

impl ClientChangeAfterCommit {
    fn new(feed: &Arc<LiveFeed>, armed: bool) -> Arc<Self> {
        Arc::new(Self {
            feed: feed.clone(),
            armed: AtomicBool::new(armed),
            fired: AtomicBool::new(false),
        })
    }
}

impl StageHook for ClientChangeAfterCommit {
    fn before(&self, _stage: EnsureStage) -> Result<(), Code> {
        Ok(())
    }
    fn after(&self, stage: EnsureStage) -> Result<(), Code> {
        if stage == EnsureStage::Commit && self.armed.swap(false, Ordering::SeqCst) {
            *self.feed.client.lock().unwrap() = Some(CHANGED_CLIENT.to_owned());
            self.fired.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

fn scope_minimum() -> RequiredCapabilities {
    RequiredCapabilities {
        destination_scope_at_least: Some(Scope_::VerifiedServerPrincipals),
        ..RequiredCapabilities::default()
    }
}

/// A managed `ensure` over [`pairs`] (one work) with `required` and an optional
/// absolute deadline.
async fn ensure_req(
    ops: &Operations,
    request: &str,
    required: RequiredCapabilities,
    until: Option<heimdall_contract::request::DeadlineIntent>,
) -> Result<heimdall_app::error::Completed<EnsureData>, heimdall_app::OpError> {
    ops.ensure(
        &caller(),
        EnsureRequest {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: None,
            scope: pairs().into_iter().collect(),
            environment: None,
            // One work: equivalent requests join one decision.
            work_id: WorkId::parse("w-c02").unwrap(),
            until,
            required_capabilities: required,
            request_id: RequestId::parse(request).unwrap(),
            interaction: InteractionMode::Interactive,
            wait: WaitMode::Sync { timeout_ms: 30_000 },
            connection: None,
        },
    )
    .await
}

/// The reviewer's scenario: two equivalent three-hour managed ensures (beyond the
/// standing policy's two-hour window: one owner decision) with distinct request IDs and
/// `required`, joined on one decision; approved; then each result. Returns the owner's
/// result, the joined follower's, and the follower's operation.
async fn decision_joined(
    p: &Process,
    tag: &str,
    required: &RequiredCapabilities,
) -> (
    Result<EnsureData, heimdall_app::OpError>,
    Result<EnsureData, heimdall_app::OpError>,
    OperationId,
) {
    use heimdall_app::context::Attendance;
    use heimdall_contract::ids::DecisionId;
    use heimdall_contract::request::{DeadlineIntent, DecideRequest, Verdict};
    let until = DeadlineIntent::Absolute(
        Timestamp::from_second(t0().as_second() + 3 * 3600)
            .unwrap()
            .to_string(),
    );
    let (r1, r2) = (format!("r-{tag}-1"), format!("r-{tag}-2"));
    let a = ensure_req(&p.ops, &r1, required.clone(), Some(until.clone()))
        .await
        .unwrap_err();
    let b = ensure_req(&p.ops, &r2, required.clone(), Some(until.clone()))
        .await
        .unwrap_err();
    assert_eq!(a.code, Code::InteractionRequired, "{}", a.message);
    let decision = |e: &heimdall_app::OpError| {
        DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
    };
    assert_eq!(decision(&a), decision(&b), "one decision record, joined");
    assert_ne!(a.operation_id, b.operation_id);
    let attended = Caller {
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
        ..caller()
    };
    p.ops
        .decide(
            &attended,
            DecideRequest {
                decision_id: decision(&a),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message));
    let ra = ensure_req(&p.ops, &r1, required.clone(), Some(until.clone()))
        .await
        .map(|c| c.data);
    let rb = ensure_req(&p.ops, &r2, required.clone(), Some(until))
        .await
        .map(|c| c.data);
    (ra, rb, b.operation_id.clone().unwrap())
}

/// Two equivalent managed ensures with distinct request IDs and `required`, coalesced in
/// flight: the leader is held in its preparation until the follower resolved and joined
/// it. Returns the leader's result, the follower's, and the follower's operation.
async fn coalesced(
    w: &Live,
    p: &Process,
    hold: &Arc<Hold>,
    tag: &str,
    required: &RequiredCapabilities,
) -> (
    Result<EnsureData, heimdall_app::OpError>,
    Result<EnsureData, heimdall_app::OpError>,
    OperationId,
) {
    hold.armed.store(true, Ordering::SeqCst);
    let (ops, req, r1) = (p.ops.clone(), required.clone(), format!("r-{tag}-lead"));
    let leader = tokio::spawn(async move { ensure_req(&ops, &r1, req, None).await });
    hold.reached.notified().await;
    let (ops, req, r2) = (p.ops.clone(), required.clone(), format!("r-{tag}-follow"));
    let r2_key = r2.clone();
    let follower = tokio::spawn(async move { ensure_req(&ops, &r2, req, None).await });
    // The follower resolves, then joins the leader's flight at `Coalesce`.
    let mut joined = false;
    for _ in 0..500 {
        let resolved = w
            .store
            .transaction(|tx| {
                for o in tx.open_operations()? {
                    let rs = tx.stage_receipts(&o.id)?;
                    if rs.iter().any(|r| r.stage == "resolve_mechanism")
                        && !rs.iter().any(|r| r.stage == "reconcile")
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .unwrap();
        if resolved {
            joined = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(joined, "the follower resolved while the leader prepares");
    tokio::time::sleep(Duration::from_millis(300)).await;
    hold.release.notify_one();
    let lead = leader.await.unwrap().map(|c| c.data);
    let follow = follower.await.unwrap().map(|c| c.data);
    let follow_op = w
        .store
        .transaction(|tx| {
            let key = heimdall_domain::idempotency::IdempotencyKey {
                caller: caller().context.clone(),
                kind: heimdall_domain::operation::OperationKind::Ensure,
                request_id: RequestId::parse(&r2_key).unwrap(),
            };
            Ok(tx.idempotency_record(&key)?.unwrap().operation_id)
        })
        .unwrap();
    (lead, follow, follow_op)
}

/// The follower operation `op` prepared nothing (its last `Reconcile` is
/// `NotAttempted`): it is a follower.
fn prepared_nothing(w: &Live, op: &OperationId) -> bool {
    w.store
        .transaction(|tx| tx.stage_receipts(op))
        .unwrap()
        .into_iter()
        .rev()
        .find(|r| r.stage == "reconcile")
        .is_some_and(|r| r.effect == heimdall_domain::operation::EffectReceipt::NotAttempted)
}

/// A follower refused at its commit for its own, invalidated evidence: refused
/// `CAPABILITY_UNAVAILABLE` (the scope minimum not met), nothing activated for it, its
/// binding not committed, its endpoint and files gone, its intent processed; the
/// leader stands (its binding, its endpoint, the shared K_env, its scope as reported).
fn assert_follower_refused(
    w: &Live,
    p: &Process,
    tag: &str,
    lead: &EnsureData,
    follow: Result<EnsureData, heimdall_app::OpError>,
    follow_op: &OperationId,
) {
    let e = match follow {
        Ok(d) => panic!(
            "{tag}: the follower accepted invalidated evidence: scope={:?}, same_grant={}",
            d.enforcement.destination_scope,
            d.grant_id == lead.grant_id
        ),
        Err(e) => e,
    };
    assert_eq!(e.code, Code::CapabilityUnavailable, "{tag}: {}", e.message);
    assert!(
        e.message.contains("destination-scope"),
        "{tag}: the scope minimum: {}",
        e.message
    );
    assert_eq!(
        e.effect_status,
        heimdall_contract::EffectStatus::None,
        "{tag}"
    );
    assert!(prepared_nothing(w, follow_op), "{tag}: a follower");
    let minted = w.minted_binding(follow_op);
    assert!(
        w.store
            .transaction(|tx| tx.binding(&minted))
            .unwrap()
            .is_none(),
        "{tag}: no binding committed for the refused follower"
    );
    assert!(
        p.registry.binding_endpoint(&minted).is_none(),
        "{tag}: the refused follower's endpoint was removed"
    );
    assert!(w.binding_dirs(&minted).is_empty(), "{tag}: and its files");
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intents())
            .unwrap()
            .is_empty(),
        "{tag}: its intent was processed"
    );
    // The leader stands.
    assert_eq!(
        lead.enforcement.destination_scope,
        Scope_::VerifiedServerPrincipals,
        "{tag}: the leader's own claim (its evidence held at its commit)"
    );
    let (lb, lg) = w
        .store
        .transaction(|tx| {
            Ok((
                tx.binding(&lead.binding_id)?.map(|b| b.state),
                tx.grant(&lead.grant_id)?.map(|g| g.state),
            ))
        })
        .unwrap();
    assert_eq!(
        lb,
        Some(heimdall_domain::binding::BindingState::Active),
        "{tag}"
    );
    assert_eq!(lg, Some(GrantState::Active), "{tag}");
    assert!(
        p.registry.binding_endpoint(&lead.binding_id).is_some(),
        "{tag}: the leader's endpoint runs"
    );
    assert_eq!(p.table.vault().len(), 1, "{tag}: the shared K_env is kept");
}

/// The control: with the leader's grant revoked (so nothing is reused), a **fresh
/// preparation** requiring the scope at the changed client is refused too, by the
/// evidence comparison (its driver ran: `managed.prepared`).
async fn assert_fresh_preparation_refused(w: &Live, p: &Process, lead: &EnsureData, tag: &str) {
    p.ops
        .revoke(
            &caller(),
            RevokeRequest {
                grant_id: lead.grant_id.clone(),
                request_id: RequestId::parse(&format!("rv-{tag}")).unwrap(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{tag}: revoke: {} {}", e.code, e.message));
    let e = ensure_req(&p.ops, &format!("r-{tag}-fresh"), scope_minimum(), None)
        .await
        .expect_err("a fresh preparation at the changed client is refused");
    assert_eq!(e.code, Code::CapabilityUnavailable, "{tag}: {}", e.message);
    let op = e.operation_id.clone().expect("an operation");
    let stages: Vec<String> = w
        .store
        .transaction(|tx| tx.stage_receipts(&op))
        .unwrap()
        .into_iter()
        .map(|r| r.stage)
        .collect();
    assert!(
        stages.iter().any(|s| s == "managed.prepared"),
        "{tag}: the preparation ran, the comparison refused: {stages:?}"
    );
}

/// W4-C02, the reviewer's scenario: fresh valid evidence for both pairs at the
/// evidence's client (`OpenSSH_10.5p1`); two distinct request IDs requiring
/// `destination_scope_at_least: verified_server_principals` join one owner decision;
/// approved. After the leader's commit the verifying client changes to
/// `OpenSSH_10.6p1`. The follower's own evidence no longer holds: it is refused
/// (`CAPABILITY_UNAVAILABLE`, the minimum not met) and its binding cleaned up; the
/// leader stands; a fresh preparation at the changed client is refused too.
#[tokio::test]
async fn decision_joined_follower_refused_when_evidence_changes_after_leader_commit() {
    let w = Live::new();
    w.feed.evidence_holds(&pairs());
    let hook = ClientChangeAfterCommit::new(&w.feed, true);
    let p = w.process(hook.clone()).await;
    let (ra, rb, joined) = decision_joined(&p, "c02-joined", &scope_minimum()).await;
    let ra = ra.unwrap_or_else(|e| panic!("owner: {} {}", e.code, e.message));
    assert!(hook.fired.load(Ordering::SeqCst), "the client changed");
    assert_follower_refused(&w, &p, "joined", &ra, rb, &joined);
    assert_fresh_preparation_refused(&w, &p, &ra, "c02-joined").await;
    p.shutdown.cancel();
}

/// W4-C02, the coalesced (in-flight) variant: two distinct request IDs requiring the
/// scope coalesce while the leader prepares; the client changes after the leader's
/// commit; the follower is refused, the leader stands, and a fresh preparation at the
/// changed client is refused too.
#[tokio::test]
async fn coalesced_follower_refused_when_evidence_changes_after_leader_commit() {
    let w = Live::new();
    w.feed.evidence_holds(&pairs());
    let hook = ClientChangeAfterCommit::new(&w.feed, true);
    let hold = Arc::new(Hold::default());
    let p = w
        .process_opts(
            hook.clone(),
            Opts {
                hold: hold.clone(),
                ..Opts::default()
            },
        )
        .await;
    let (lead, follow, follow_op) = coalesced(&w, &p, &hold, "c02-coal", &scope_minimum()).await;
    let lead = lead.unwrap_or_else(|e| panic!("leader: {} {}", e.code, e.message));
    assert!(hook.fired.load(Ordering::SeqCst), "the client changed");
    assert_follower_refused(&w, &p, "coalesced", &lead, follow, &follow_op);
    assert_fresh_preparation_refused(&w, &p, &lead, "c02-coal").await;
    p.shutdown.cancel();
}

/// W4-C02: a follower **without** a scope minimum still commits after the change, on
/// the leader's grant with its own binding, and reports its own claim:
/// `destination_scope: unknown` (the leader keeps reporting what held at its commit).
#[tokio::test]
async fn follower_without_minimum_commits_reporting_unknown_after_the_change() {
    let w = Live::new();
    w.feed.evidence_holds(&pairs());
    let hook = ClientChangeAfterCommit::new(&w.feed, true);
    let p = w.process(hook.clone()).await;
    let (ra, rb, joined) = decision_joined(&p, "c02-plain", &RequiredCapabilities::default()).await;
    let ra = ra.unwrap_or_else(|e| panic!("owner: {} {}", e.code, e.message));
    let rb = rb.unwrap_or_else(|e| panic!("joined: {} {}", e.code, e.message));
    assert!(hook.fired.load(Ordering::SeqCst), "the client changed");
    assert!(prepared_nothing(&w, &joined), "a follower");
    assert_eq!(rb.grant_id, ra.grant_id, "on the leader's grant");
    assert_ne!(rb.binding_id, ra.binding_id, "its own binding");
    assert_eq!(
        ra.enforcement.destination_scope,
        Scope_::VerifiedServerPrincipals
    );
    assert_eq!(
        rb.enforcement.destination_scope,
        Scope_::Unknown,
        "the follower's own claim at its commit"
    );
    assert!(p.registry.binding_endpoint(&rb.binding_id).is_some());
    p.shutdown.cancel();
}

/// W4-C02, no false refusal: while the follower's evidence still holds (nothing
/// changed), a decision-joined and a coalesced follower requiring the scope each meet
/// it, on the leader's grant with their own binding.
#[tokio::test]
async fn follower_with_valid_evidence_meets_the_minimum() {
    let w = Live::new();
    w.feed.evidence_holds(&pairs());
    let hold = Arc::new(Hold::default());
    let p = w
        .process_opts(
            ClientChangeAfterCommit::new(&w.feed, false),
            Opts {
                hold: hold.clone(),
                ..Opts::default()
            },
        )
        .await;
    let (ra, rb, joined) = decision_joined(&p, "c02-ok", &scope_minimum()).await;
    let ra = ra.unwrap_or_else(|e| panic!("owner: {} {}", e.code, e.message));
    let rb = rb.unwrap_or_else(|e| panic!("joined: {} {}", e.code, e.message));
    assert!(prepared_nothing(&w, &joined), "a follower");
    assert_eq!(rb.grant_id, ra.grant_id);
    assert_ne!(rb.binding_id, ra.binding_id);
    for d in [&ra, &rb] {
        assert_eq!(
            d.enforcement.destination_scope,
            Scope_::VerifiedServerPrincipals
        );
    }
    p.ops
        .revoke(
            &caller(),
            RevokeRequest {
                grant_id: ra.grant_id.clone(),
                request_id: RequestId::parse("rv-c02-ok").unwrap(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("revoke: {} {}", e.code, e.message));
    let (lead, follow, follow_op) = coalesced(&w, &p, &hold, "c02-ok-coal", &scope_minimum()).await;
    let lead = lead.unwrap_or_else(|e| panic!("leader: {} {}", e.code, e.message));
    let follow = follow.unwrap_or_else(|e| panic!("follower: {} {}", e.code, e.message));
    assert!(prepared_nothing(&w, &follow_op), "a follower");
    assert_eq!(follow.grant_id, lead.grant_id);
    assert_ne!(follow.binding_id, lead.binding_id);
    for d in [&lead, &follow] {
        assert_eq!(
            d.enforcement.destination_scope,
            Scope_::VerifiedServerPrincipals
        );
    }
    p.shutdown.cancel();
}
