//! ⟨M03 wave 4, round 3b (X-M)⟩ ADR-0008 §17.23 items 1 and 5, live: through the real
//! `Operations`, managed adapter, driver, `ManagedEffectsImpl`, signer table and
//! `EndpointRegistry` of [`super::Live`], with the managed read sources fed as the
//! runtime feeds them ([`super::LiveFeed`]: the alias observation of `Observing`, the
//! evidence comparison's target evaluation and client of `LateEvidenceFeed`).
//!
//! * Item 1 (R3A-Q2): the managed descriptor advertises
//!   `destination_scope: verified_server_principals`; each pair's evidence comparison
//!   in `prepare_from` decides whether a request gets it.
//! * Item 5 (R3C1-Q1): each pair's `identity_selection` is its alias's D10 item 6
//!   classification, on every managed path including a delegation; an `exclusive`
//!   alias delegates non-interactively, an `undetermined` one is refused.
//!
//! Every key and the CA are generated per run in scratch directories; nothing of the
//! owner's is read, contacted or changed.

use super::*;
use heimdall_contract::request::{DelegateRequest, DestinationScopeEnforcement as Scope_};

/// Revoke `grant`, so the next `ensure` of the same scope prepares a grant of its own
/// (an active equivalent grant would be reused, its stored facts reported).
async fn revoke(p: &Process, grant: &GrantId, tag: &str) {
    p.ops
        .revoke(
            &caller(),
            RevokeRequest {
                grant_id: grant.clone(),
                request_id: RequestId::parse(&format!("rv-{tag}")).unwrap(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("revoke {tag}: {} {}", e.code, e.message));
}

fn scope_minimum() -> RequiredCapabilities {
    RequiredCapabilities {
        destination_scope_at_least: Some(Scope_::VerifiedServerPrincipals),
        ..RequiredCapabilities::default()
    }
}

/// The stage names `op` recorded (which pipeline steps ran).
fn stage_names(w: &Live, op: &OperationId) -> Vec<String> {
    w.store
        .transaction(|tx| tx.stage_receipts(op))
        .unwrap()
        .into_iter()
        .map(|r| r.stage)
        .collect()
}

/// The resolution's refusal of a minimum no configured mechanism advertises
/// (`pair_mechanism_m03::no_mechanism`).
const RESOLUTION_REFUSAL: &str = "no configured credential mechanism meets the requested minimums";

/// An `ensure` over [`pairs`] requiring `verified_server_principals` is refused **by
/// the per-pair evidence comparison**, not at resolution: `CAPABILITY_UNAVAILABLE`, the
/// managed driver ran (`managed.prepared`: resolution let the minimum through) and its
/// key was destroyed, nothing was committed; without the minimum the same request is
/// `ACCESS_READY` reporting `destination_scope: unknown`.
async fn assert_refused_at_the_comparison(w: &Live, p: &Process, tag: &str) {
    let e = w
        .ensure(p, &format!("{tag}-min"), scope_minimum())
        .await
        .expect_err("the minimum must be refused");
    assert_eq!(e.code, Code::CapabilityUnavailable, "{tag}: {}", e.message);
    assert_ne!(
        e.message, RESOLUTION_REFUSAL,
        "{tag}: refused at resolution only"
    );
    let op = e.operation_id.clone().expect("an operation");
    let stages = stage_names(w, &op);
    assert!(
        stages.iter().any(|s| s == "managed.prepared"),
        "{tag}: the preparation ran, the comparison refused: {stages:?}"
    );
    let grant = w.grant_of(&op);
    assert_eq!(w.live_instances(&grant), 0, "{tag}: its K_env destroyed");
    let minted = w.minted_binding(&op);
    assert!(
        w.store
            .transaction(|tx| tx.binding(&minted))
            .unwrap()
            .is_none(),
        "{tag}: nothing committed"
    );
    let plain = w
        .ensure(p, &format!("{tag}-plain"), RequiredCapabilities::default())
        .await
        .unwrap_or_else(|e| panic!("{tag}: {} {}", e.code, e.message));
    assert_eq!(
        plain.enforcement.destination_scope,
        Scope_::Unknown,
        "{tag}"
    );
    revoke(p, &plain.grant_id, tag).await;
}

/// §17.23 item 1 (R3A-Q2), through the real managed `ensure` pipeline: the managed
/// descriptor advertises `destination_scope: verified_server_principals` as achievable,
/// so a `destination_scope_at_least: verified_server_principals` minimum passes
/// resolution and each pair's evidence comparison (§17.22 item 7) decides. With fresh,
/// valid evidence (the aliases evaluate to the approved targets, the verifying client
/// is the evidence's, the certificate is issued under the evidence's CA) the minimum
/// **is met** and the result reports the scope. With the evidence invalidated, by a
/// host-key change, a route change, a client change or a certificate issued under
/// another CA than the evidence's, it is refused at the comparison
/// (`minimum_not_met`), never at resolution only; restoring the evaluation restores
/// the claim (the records never changed).
#[tokio::test]
async fn scope_minimum_met_with_valid_evidence_refused_at_the_comparison_when_invalidated() {
    let w = Live::new();
    w.feed.evidence_holds(&pairs());
    let p = w.process(Arc::new(NoStageHook)).await;
    let records = || {
        w.store
            .transaction(|tx| {
                let mut out = Vec::new();
                for pr in pairs() {
                    out.extend(tx.enrollments_for_pair(&pr)?);
                }
                Ok(out)
            })
            .unwrap()
    };
    let before = records();
    let met = |tag: &'static str| {
        let (w, p) = (&w, &p);
        async move {
            let ok = w
                .ensure(p, tag, scope_minimum())
                .await
                .unwrap_or_else(|e| panic!("{tag}: the minimum is met: {} {}", e.code, e.message));
            assert_eq!(
                ok.enforcement.destination_scope,
                Scope_::VerifiedServerPrincipals,
                "{tag}"
            );
            revoke(p, &ok.grant_id, tag).await;
        }
    };
    met("scp-ok").await;
    let h1 = pairs()[0].clone();
    let alias = h1.destination.as_str().to_owned();
    let approved = LiveFeed::approved(&h1);
    // 1. A host-key change (the alias evaluates to another key for the same route).
    let mut other_key = approved.clone();
    other_key.host_keys[0].key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIotherhost".into();
    w.feed
        .targets
        .lock()
        .unwrap()
        .insert(alias.clone(), other_key);
    assert_refused_at_the_comparison(&w, &p, "scp-hk").await;
    w.feed.evidence_holds(&pairs());
    met("scp-ok2").await;
    // 2. A route change.
    let mut moved = approved.clone();
    moved.port = 2222;
    w.feed.targets.lock().unwrap().insert(alias.clone(), moved);
    assert_refused_at_the_comparison(&w, &p, "scp-rt").await;
    w.feed.evidence_holds(&pairs());
    met("scp-ok3").await;
    // 3. A client change.
    *w.feed.client.lock().unwrap() = Some("OpenSSH_10.6p1, LibreSSL 3.3.6".to_owned());
    assert_refused_at_the_comparison(&w, &p, "scp-cl").await;
    w.feed.evidence_holds(&pairs());
    met("scp-ok4").await;
    assert_eq!(records(), before, "nothing written to the enrollments");
    // 4. Another CA: the pair's certificates are now issued under a second CA verified
    // for the pairs without evidence of its own; the first CA's evidence is not this
    // certificate's.
    let ca2 = w.add_ca();
    w.store
        .transaction(|tx| {
            for (i, pr) in pairs().iter().enumerate() {
                let mut r = enrollment(0x40 + u8::try_from(i).unwrap(), &ca2, pr);
                r.evidence = None;
                tx.seed_enrollment(&r)?;
                tx.set_pair_preference(
                    &heimdall_domain::enrollment::PairPreference {
                        destination: pr.destination.clone(),
                        account: pr.account.clone(),
                        mechanism: PreferredMechanism::ManagedCertificate,
                        projection: ProjectionStatus::Applied { generation: 1 },
                        issuing_cas: [ca2.clone()].into_iter().collect(),
                    },
                    t0(),
                )?;
            }
            Ok(())
        })
        .unwrap();
    assert_refused_at_the_comparison(&w, &p, "scp-ca").await;
    let plain = w
        .ensure(&p, "scp-ca-under", RequiredCapabilities::default())
        .await
        .unwrap_or_else(|e| panic!("{} {}", e.code, e.message));
    let entries = w
        .store
        .transaction(|tx| tx.issuance_entries(&plain.grant_id))
        .unwrap();
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|e| e.bounds.ca_fingerprint.as_ref() == Some(&ca2)),
        "issued under the second CA: {entries:?}"
    );
    revoke(&p, &plain.grant_id, "scp-ca-under").await;
    let open = w.store.transaction(|tx| tx.open_operations()).unwrap();
    assert!(open.is_empty(), "nothing left open");
    p.shutdown.cancel();
}

/// A non-interactive child delegation of `parent` over `scope` (a delegation is never
/// interactive: `WorkSpec::from_request`).
async fn delegate(
    p: &Process,
    parent: &BindingId,
    scope: &[AccessPair],
    tag: &str,
) -> Result<EnsureData, heimdall_app::OpError> {
    p.ops
        .delegate(
            &caller(),
            DelegateRequest {
                parent_binding_id: parent.clone(),
                scope: scope.iter().cloned().collect(),
                until: None,
                work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
                request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
        .map(|c| c.data)
}

/// §17.23 item 5 (R3C1-Q1; §17.21 item 11): each pair's `identity_selection` is its
/// managed alias's D10 item 6 classification, fed per pair through the managed read
/// sources on the delegation path too. With both aliases observed `exclusive`, a
/// **non-interactive managed `delegate` succeeds**: the child is `ACCESS_READY`, each
/// of its pairs reports `exclusive`, its own binding is materialized (its endpoint
/// named in its result and running), and its binding references the parent's grant.
#[tokio::test]
async fn exclusive_alias_delegates_non_interactively() {
    let w = Live::new();
    for pr in pairs() {
        w.feed
            .observe(pr.destination.as_str(), IdentitySelection::Exclusive);
    }
    let p = w.process(Arc::new(NoStageHook)).await;
    let parent = w
        .ensure(&p, "dlg-parent", RequiredCapabilities::default())
        .await
        .unwrap_or_else(|e| panic!("parent: {} {}", e.code, e.message));
    assert!(
        parent
            .consumer
            .pairs
            .iter()
            .all(|pi| pi.identity_selection == IdentitySelection::Exclusive),
        "the parent's pairs carry the classification: {:?}",
        parent.consumer.pairs
    );
    let child = delegate(&p, &parent.binding_id, &pairs(), "dlg-child")
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason));
    assert_ne!(child.binding_id, parent.binding_id);
    assert!(!child.consumer.pairs.is_empty());
    assert!(
        child
            .consumer
            .pairs
            .iter()
            .all(|pi| pi.identity_selection == IdentitySelection::Exclusive),
        "the child's pairs carry the classification: {:?}",
        child.consumer.pairs
    );
    let (endpoint, _) = p
        .registry
        .binding_endpoint(&child.binding_id)
        .expect("the child's binding endpoint runs");
    assert_eq!(
        child.consumer.signing_endpoint.as_deref(),
        Some(endpoint.locator.as_str())
    );
    let parent_refs = w
        .store
        .transaction(|tx| tx.grant_references(&parent.grant_id))
        .unwrap();
    assert!(
        parent_refs.iter().any(|r| r.binding == child.binding_id),
        "the child's binding references the parent's grant: {parent_refs:?}"
    );
    p.shutdown.cancel();
}

/// §17.23 item 5: the classification is per pair. With one alias `exclusive` and the
/// other `undetermined` (observed so, or not observed at all), a non-interactive
/// delegation over the `exclusive` pair alone succeeds, while one that includes the
/// `undetermined` pair is still refused at its commit, `INTERACTION_REQUIRED`
/// (`fallback_identity_interaction`), with no child binding committed.
#[tokio::test]
async fn undetermined_alias_delegation_refused_interaction_required() {
    for observed in [true, false] {
        let w = Live::new();
        let [h1, h2] = <[AccessPair; 2]>::try_from(pairs()).unwrap();
        w.feed
            .observe(h1.destination.as_str(), IdentitySelection::Exclusive);
        if observed {
            w.feed
                .observe(h2.destination.as_str(), IdentitySelection::Undetermined);
        }
        let p = w.process(Arc::new(NoStageHook)).await;
        let parent = w
            .ensure(&p, "und-parent", RequiredCapabilities::default())
            .await
            .unwrap_or_else(|e| panic!("parent: {} {}", e.code, e.message));
        let e = delegate(&p, &parent.binding_id, &pairs(), "und-both")
            .await
            .expect_err("an undetermined alias is refused non-interactively");
        assert_eq!(
            e.code,
            Code::InteractionRequired,
            "{observed}: {}",
            e.message
        );
        assert_eq!(
            e.reason.as_deref(),
            Some(heimdall_contract::envelope::reason::FALLBACK_IDENTITY_INTERACTION),
            "{observed}"
        );
        let op = e.operation_id.clone().expect("the operation");
        let minted = w.minted_binding(&op);
        assert!(
            w.store
                .transaction(|tx| tx.binding(&minted))
                .unwrap()
                .is_none(),
            "{observed}: no child binding committed"
        );
        let one = delegate(&p, &parent.binding_id, std::slice::from_ref(&h1), "und-one")
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{observed}: the exclusive pair alone: {} {}",
                    e.code, e.message
                )
            });
        assert_eq!(one.consumer.pairs.len(), 1);
        assert_eq!(
            one.consumer.pairs[0].identity_selection,
            IdentitySelection::Exclusive
        );
        p.shutdown.cancel();
    }
}
