//! ⟨M03 wave 4, round 3 (R3-C1)⟩ ADR-0008 §17.22 items 4, 9 and 10, live: the
//! production expiry and release paths through the real `Operations`, managed
//! adapter, [`StoreCleanup`], `ManagedEffectsImpl`, signer table, vault and
//! `EndpointRegistry` of [`super::Live`], and the supervisor's ended-grant pass
//! (`Supervisor::ended_slot_pass`) over the same store. Every key is generated per
//! run in a scratch directory; nothing of the owner's is touched.

use super::*;
use crate::supervisor::{FixedJitter, ManagedConnections, Supervisor, SupervisorConfig};
use heimdall_app::ports::{
    SignatureAuthority, SignatureRequestFacts, SignatureSubject, SignerEndpoint,
};
use heimdall_contract::request::ReleaseRequest;
use std::os::unix::fs::PermissionsExt as _;

/// The supervisor of process `p` with the M03 passes and the production end cleanup
/// ([`StoreCleanup`] over `p`'s effects; no connection supervisor in it, as in
/// `Live::process_with`'s adapter).
fn supervisor(w: &Live, p: &Process) -> Supervisor {
    struct NoEndpoints;
    impl crate::connections::BindingEndpoints for NoEndpoints {
        fn endpoint(&self, _: &BindingId) -> Option<EndpointRef> {
            None
        }
    }
    let config = crate::connections::ConnectionConfig::new(
        w.run_dir(),
        std::path::PathBuf::from("/nonexistent/fixture-ssh"),
        Arc::new(NoEndpoints),
        Arc::new(FixedJitter(1.0)),
    );
    let connections = Arc::new(crate::connections::ConnectionSupervisor::new(
        w.store.clone(),
        Some(p.ops.clone()),
        config,
    ));
    let clock: Arc<dyn heimdall_domain::time::Clock> = w.clock.clone();
    Supervisor::new(p.ops.clone(), SupervisorConfig::default())
        .with_state(w.store.clone(), clock)
        .with_connections(Arc::new(ManagedConnections::new(
            connections,
            w.store.clone(),
            p.ops.clone(),
        )))
        .with_end_cleanup(Arc::new(StoreCleanup::new(
            StoreSources::new(w.store.clone(), env()),
            p.effects.clone(),
            None,
        )))
}

fn grant_state(w: &Live, g: &GrantId) -> GrantState {
    w.store
        .transaction(|tx| tx.grant(g))
        .unwrap()
        .expect("the grant")
        .state
}

/// `(instances, of which destroyed)` of `grant`.
fn instances(w: &Live, g: &GrantId) -> (usize, usize) {
    let all = w
        .store
        .transaction(|tx| tx.credential_instances_for_grant(g))
        .unwrap();
    let destroyed = all
        .iter()
        .filter(|i| i.state == CredentialState::Destroyed)
        .count();
    (all.len(), destroyed)
}

fn owed(w: &Live) -> Vec<GrantId> {
    w.store
        .transaction(|tx| tx.managed_cleanup_owed(&env()))
        .unwrap()
}

fn slot_files_present(p: &Process, pr: &AccessPair) -> bool {
    let paths = files::slot_paths(&p.effects.slot_root().data_dir, pr).unwrap();
    paths.key_pub.exists() || paths.cert_pub.exists()
}

fn set_mode(dir: &std::path::Path, mode: u32) {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The binding's live endpoint locator (it lists the grant's certificates).
async fn endpoint_of(p: &Process, binding: &BindingId) -> String {
    let (endpoint, _) = p
        .registry
        .binding_endpoint(binding)
        .expect("the binding endpoint");
    assert!(listed(&endpoint.locator).await.unwrap() >= 1);
    endpoint.locator
}

/// §17.22 item 4's postcondition: the vault holds no key for the grant, every
/// instance is `destroyed`, the gate is gone, the binding endpoint is gone and the
/// binding files are removed; nothing is owed any more.
async fn assert_expiry_cleaned(
    w: &Live,
    p: &Process,
    grant: &GrantId,
    binding: &BindingId,
    locator: &str,
) {
    assert_eq!(grant_state(w, grant), GrantState::Expired);
    assert_eq!(p.table.vault().len(), 0, "the vault holds no key");
    assert!(p.table.public_key(grant).is_none());
    let (all, destroyed) = instances(w, grant);
    assert!(all >= 1, "the grant had an instance");
    assert_eq!(destroyed, all, "every instance is destroyed");
    assert!(!p.ops.signing_gates().contains(grant), "the gate is gone");
    assert!(
        p.registry.binding_endpoint(binding).is_none(),
        "no binding endpoint"
    );
    assert!(gone(locator).await, "the endpoint stopped answering");
    assert!(w.binding_dirs(binding).is_empty(), "no binding file");
    assert!(owed(w).is_empty(), "nothing owed");
}

/// §17.22 item 4 (W4-R01), at use and **without a held slot**: an ensure-only
/// binding; past the deadline a launch bind finds the expiry at use
/// (`CREDENTIAL_EXPIRED`); the same call's cleanup destroys K_env, moves the
/// instance to `destroyed`, releases the gate and removes the endpoint and files.
#[tokio::test]
async fn expiry_at_use_without_held_slot_destroys_key_instance_gate_endpoint_files() {
    let w = Live::new();
    let p = w.process(Arc::new(NoStageHook)).await;
    let data = w
        .ensure(&p, "exp-use", RequiredCapabilities::default())
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    let locator = endpoint_of(&p, &data.binding_id).await;
    assert_eq!(p.table.vault().len(), 1);
    assert!(p.ops.signing_gates().contains(&data.grant_id));
    assert_eq!(w.binding_dirs(&data.binding_id).len(), 1);
    for pr in pairs() {
        assert_eq!(
            slot_of(&w, &pr),
            SlotState::Free { generation: 0 },
            "no slot"
        );
    }
    w.clock.advance(3 * HOUR);
    let e = launch_bind(&p, &data.binding_id, "exp-use", None)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired, "{}", e.message);
    assert_expiry_cleaned(&w, &p, &data.grant_id, &data.binding_id, &locator).await;
}

/// §17.22 item 4 (W4-R01), by the scheduler and **with a held slot**: the tick
/// expires the grant and its cleanup leaves no key, a `destroyed` instance, no gate,
/// no endpoint, no binding file, and the slot freed with its files and listing gone.
#[tokio::test]
async fn expiry_by_scheduler_with_held_slot_destroys_key_instance_gate_endpoint_files() {
    let w = Live::new();
    let p = w.process(Arc::new(NoStageHook)).await;
    let data = w
        .ensure(&p, "exp-tick", RequiredCapabilities::default())
        .await
        .unwrap();
    let locator = endpoint_of(&p, &data.binding_id).await;
    launch_bind(&p, &data.binding_id, "exp-tick", None)
        .await
        .unwrap_or_else(|e| panic!("bind: {} {}", e.code, e.message));
    for pr in pairs() {
        assert!(matches!(slot_of(&w, &pr), SlotState::Held { .. }));
        assert!(slot_files_present(&p, &pr));
    }
    w.clock.advance(3 * HOUR);
    p.ops.tick().await.unwrap();
    assert_expiry_cleaned(&w, &p, &data.grant_id, &data.binding_id, &locator).await;
    for pr in pairs() {
        assert_eq!(slot_of(&w, &pr), SlotState::Free { generation: 1 });
        assert!(!slot_files_present(&p, &pr), "no slot file");
    }
    assert!(
        p.table.list(&SignerEndpoint::Environment).is_empty(),
        "nothing listed on the environment endpoint"
    );
}

/// §17.22 item 4 (W4-R01), durable: the expiry commits, its cleanup fails (the
/// binding files cannot be removed), and the process dies. The obligation is the
/// undestroyed instance row (`managed_cleanup_owed`); after the restart (the
/// instance `lost`) the supervisor's ended-grant pass completes it: instance
/// `destroyed`, files and slots gone, nothing owed.
#[tokio::test]
async fn expiry_cleanup_obligation_survives_failure_and_restart() {
    let w = Live::new();
    let p = w.process(Arc::new(NoStageHook)).await;
    let data = w
        .ensure(&p, "exp-crash", RequiredCapabilities::default())
        .await
        .unwrap();
    launch_bind(&p, &data.binding_id, "exp-crash", None)
        .await
        .unwrap();
    let dirs = w.binding_dirs(&data.binding_id);
    assert_eq!(dirs.len(), 1);
    set_mode(&dirs[0].0, 0o500);
    w.clock.advance(3 * HOUR);
    p.ops.tick().await.unwrap();
    assert_eq!(grant_state(&w, &data.grant_id), GrantState::Expired);
    assert_eq!(p.table.vault().len(), 0, "K_env destroyed at once");
    let (all, destroyed) = instances(&w, &data.grant_id);
    assert!(
        destroyed < all,
        "the cleanup did not complete: the instance is owed"
    );
    assert_eq!(owed(&w), vec![data.grant_id.clone()]);
    assert_eq!(w.binding_dirs(&data.binding_id).len(), 1);
    // The crash: nothing of `p` runs again.
    p.shutdown.cancel();
    drop(p);
    set_mode(&dirs[0].0, 0o700);
    let q = w.process(Arc::new(NoStageHook)).await;
    assert_eq!(
        owed(&w),
        vec![data.grant_id.clone()],
        "still owed after the restart"
    );
    let cleaned = supervisor(&w, &q).ended_slot_pass().await.unwrap();
    assert_eq!(cleaned, vec![data.grant_id.clone()]);
    let (all, destroyed) = instances(&w, &data.grant_id);
    assert_eq!(destroyed, all, "every instance destroyed");
    assert!(
        w.binding_dirs(&data.binding_id).is_empty(),
        "no binding file"
    );
    for pr in pairs() {
        assert_eq!(slot_of(&w, &pr), SlotState::Free { generation: 1 });
        assert!(!slot_files_present(&q, &pr));
    }
    assert!(!q.ops.signing_gates().contains(&data.grant_id));
    assert!(owed(&w).is_empty());
    assert!(
        supervisor(&w, &q)
            .ended_slot_pass()
            .await
            .unwrap()
            .is_empty()
    );
}

/// A parent ensure holding both slots, and ⟨X-M, ADR-0008 §17.23 item 5⟩ a **real child
/// delegation** of it that keeps the parent's grant live when the parent binding is
/// released: the child's commit adds its binding's reference on the parent's grant
/// (§17.22 item 10's "a child delegation keeps the grant live"). A delegation is
/// never interactive, so the managed aliases are observed `exclusive` (D10 item 6, fed
/// through the managed read sources as the runtime feeds them). Returns the parent and
/// the child.
async fn parent_with_child_delegation(
    w: &Live,
    p: &Process,
    tag: &str,
) -> (EnsureData, EnsureData) {
    for pr in pairs() {
        w.feed.observe(
            pr.destination.as_str(),
            heimdall_contract::provider::IdentitySelection::Exclusive,
        );
    }
    let parent = w
        .ensure(p, tag, RequiredCapabilities::default())
        .await
        .unwrap();
    launch_bind(p, &parent.binding_id, tag, None)
        .await
        .unwrap_or_else(|e| panic!("bind: {} {}", e.code, e.message));
    let child = p
        .ops
        .delegate(
            &caller(),
            heimdall_contract::request::DelegateRequest {
                parent_binding_id: parent.binding_id.clone(),
                scope: pairs().into_iter().collect(),
                until: None,
                work_id: WorkId::parse(&format!("w-{tag}-child")).unwrap(),
                request_id: RequestId::parse(&format!("r-{tag}-child")).unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason))
        .data;
    assert_ne!(child.grant_id, parent.grant_id, "the child's own grant");
    let refs = w
        .store
        .transaction(|tx| tx.grant_references(&parent.grant_id))
        .unwrap();
    assert_eq!(
        refs.len(),
        2,
        "two references on the parent's grant: {refs:?}"
    );
    assert!(
        refs.iter().any(|r| r.binding == child.binding_id),
        "the child's binding is one of them"
    );
    (parent, child)
}

async fn release(p: &Process, binding: &BindingId) -> serde_json::Value {
    p.ops
        .release(
            &caller(),
            ReleaseRequest {
                binding_id: binding.clone(),
            },
        )
        .await
        .unwrap()
        .data
}

/// The grant still signs for its remaining reference: a fresh admission of its
/// K_env on that binding's endpoint, and the key still in the signer.
async fn still_signs(p: &Process, grant: &GrantId, binding: &BindingId) {
    let key = p.table.public_key(grant).expect("K_env kept");
    let facts = SignatureRequestFacts {
        endpoint: SignerEndpoint::Binding(binding.clone()),
        subject: SignatureSubject::Grant(grant.clone()),
        pair: pairs()[0].clone(),
        key_fingerprint: key.fingerprint.clone(),
    };
    let permit = p.ops.admit(&facts).await;
    assert!(permit.is_ok(), "the grant signs: {:?}", permit.err());
}

/// §17.22 item 10 (W4-R08; D10 item 2): the parent binding holding the slots is
/// released while ⟨§17.23 item 5⟩ a real child delegation keeps the grant live. Its
/// slots move to `clearing` in the release, its endpoint goes at once, the
/// ended-binding pass removes the slot files and frees them; another binding's
/// `BindForm::Launch` claim then succeeds. K_env is not destroyed (not the last
/// reference): the grant keeps its key, instance and gate, and the child still signs.
#[tokio::test]
async fn released_slot_holder_frees_its_slots_while_grant_stays_live() {
    let w = Live::new();
    let p = w.process(Arc::new(NoStageHook)).await;
    let (parent, child) = parent_with_child_delegation(&w, &p, "rel").await;
    let second = child.binding_id.clone();
    still_signs(&p, &child.grant_id, &second).await;
    let locator = endpoint_of(&p, &parent.binding_id).await;
    let out = release(&p, &parent.binding_id).await;
    assert_eq!(out["grant_state"], "active", "{out}");
    for pr in pairs() {
        assert_eq!(
            slot_of(&w, &pr),
            SlotState::Clearing { generation: 1 },
            "held(b, g) → clearing at the release"
        );
    }
    assert!(p.registry.binding_endpoint(&parent.binding_id).is_none());
    assert!(
        gone(&locator).await,
        "the released binding's endpoint is gone"
    );
    assert_eq!(owed(&w), vec![parent.grant_id.clone()]);
    let cleaned = supervisor(&w, &p).ended_slot_pass().await.unwrap();
    assert_eq!(cleaned, vec![parent.grant_id.clone()]);
    for pr in pairs() {
        assert_eq!(slot_of(&w, &pr), SlotState::Free { generation: 1 });
        assert!(!slot_files_present(&p, &pr));
    }
    assert!(w.binding_dirs(&parent.binding_id).is_empty());
    assert!(owed(&w).is_empty());
    // Another binding claims the slots.
    let other = w
        .ensure(&p, "rel-other", RequiredCapabilities::default())
        .await
        .unwrap();
    launch_bind(&p, &other.binding_id, "rel-other", None)
        .await
        .unwrap_or_else(|e| panic!("the other binding's claim: {} {}", e.code, e.message));
    for pr in pairs() {
        assert_eq!(
            slot_of(&w, &pr),
            SlotState::Held {
                binding: other.binding_id.clone(),
                generation: 2
            }
        );
    }
    // The grant lives on with its key and still signs for the other reference.
    assert_eq!(grant_state(&w, &parent.grant_id), GrantState::Active);
    assert!(p.table.public_key(&parent.grant_id).is_some(), "K_env kept");
    assert_eq!(w.live_instances(&parent.grant_id), 1);
    assert!(p.ops.signing_gates().contains(&parent.grant_id));
    assert_eq!(grant_state(&w, &child.grant_id), GrantState::Active);
    still_signs(&p, &child.grant_id, &second).await;
}

/// §17.22 item 9 (W4-R07): an error after the slot's files are removed (the
/// released binding's files cannot be removed) leaves the slot `clearing`, so the
/// obligation stays discoverable; the next pass retries it until clean.
#[tokio::test]
async fn unfinished_cleanup_after_slot_files_removed_is_retried_until_clean() {
    let w = Live::new();
    let p = w.process(Arc::new(NoStageHook)).await;
    let (parent, _child) = parent_with_child_delegation(&w, &p, "retry").await;
    let dirs = w.binding_dirs(&parent.binding_id);
    assert_eq!(dirs.len(), 1);
    set_mode(&dirs[0].0, 0o500);
    release(&p, &parent.binding_id).await;
    let sup = supervisor(&w, &p);
    let cleaned = sup.ended_slot_pass().await.unwrap();
    assert!(cleaned.is_empty(), "the cleanup is incomplete: {cleaned:?}");
    for pr in pairs() {
        assert!(
            !slot_files_present(&p, &pr),
            "the slot's files were removed"
        );
        assert_eq!(
            slot_of(&w, &pr),
            SlotState::Clearing { generation: 1 },
            "not freed while the binding's files remain"
        );
    }
    assert_eq!(w.binding_dirs(&parent.binding_id).len(), 1);
    assert_eq!(
        owed(&w),
        vec![parent.grant_id.clone()],
        "still discoverable"
    );
    // Still failing: retried, still owed.
    assert!(sup.ended_slot_pass().await.unwrap().is_empty());
    assert_eq!(owed(&w), vec![parent.grant_id.clone()]);
    // The error clears: the next pass completes it.
    set_mode(&dirs[0].0, 0o700);
    let cleaned = sup.ended_slot_pass().await.unwrap();
    assert_eq!(cleaned, vec![parent.grant_id.clone()]);
    assert!(
        w.binding_dirs(&parent.binding_id).is_empty(),
        "no binding file"
    );
    for pr in pairs() {
        assert_eq!(slot_of(&w, &pr), SlotState::Free { generation: 1 });
    }
    assert!(owed(&w).is_empty());
}
