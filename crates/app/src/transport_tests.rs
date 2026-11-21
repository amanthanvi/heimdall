//! ⟨M06 U56⟩ `transport enable|disable|adopt_roost` over fixture ports and an in-memory
//! store (m06-plan U56 "unit" rows; mechanism evidence: no platform store, no serve child).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use heimdall_contract::ids::{AccountName, IdentityId};
use heimdall_domain::catalog::DestinationRecord;
use heimdall_store::NoFaults;

use super::*;

#[derive(Default)]
struct Calls {
    created: usize,
    destroyed: Vec<IrohEndpointId>,
    started: usize,
    narrowed: usize,
    stopped: usize,
    cleared: usize,
}

struct Fakes {
    calls: Arc<Mutex<Calls>>,
    store_refusal: Option<&'static str>,
    next: Mutex<u8>,
}

impl Fakes {
    fn new() -> Self {
        Self {
            calls: Arc::default(),
            store_refusal: None,
            next: Mutex::new(b'a'),
        }
    }
}

fn endpoint(c: u8) -> IrohEndpointId {
    IrohEndpointId::parse(&char::from(c).to_string().repeat(64)).unwrap()
}

impl TransportKeys for Fakes {
    fn create(&self) -> Result<NewTransportKey, KeyStoreRefusal> {
        if let Some(detail) = self.store_refusal {
            return Err(KeyStoreRefusal { detail });
        }
        let mut next = self.next.lock().unwrap();
        let e = endpoint(*next);
        *next += 1;
        self.calls.lock().unwrap().created += 1;
        Ok(NewTransportKey {
            endpoint: e.clone(),
            store_kind: "fixture_test".into(),
            store_ref: format!("heimdall-iroh/fixture_test/{}", e.as_str()),
        })
    }

    fn destroy(&self, key: &TransportKeyRecord) -> Result<(), KeyStoreRefusal> {
        self.calls
            .lock()
            .unwrap()
            .destroyed
            .push(key.endpoint.clone());
        Ok(())
    }
}

#[async_trait]
impl ServeControl for Fakes {
    fn check_policy(&self, policy: &ExposurePolicy) -> Result<(), &'static str> {
        if matches!(policy.infrastructure, InfrastructureProfile::N0Public) {
            // The transport refuses n0-public (outside V1).
            return Err(reason::TRANSPORT_UNAVAILABLE);
        }
        Ok(())
    }

    async fn start(&self) -> Result<(), OpError> {
        self.calls.lock().unwrap().started += 1;
        Ok(())
    }

    async fn apply_narrowing(&self) -> AdmissionReport {
        self.calls.lock().unwrap().narrowed += 1;
        AdmissionReport::Applied
    }

    async fn stop(&self) -> AdmissionReport {
        self.calls.lock().unwrap().stopped += 1;
        AdmissionReport::Applied
    }
}

impl PeerEnrollments for Fakes {
    fn clear(&self) -> Result<usize, OpError> {
        self.calls.lock().unwrap().cleared += 1;
        Ok(2)
    }
}

fn ops<'a>(store: &'a Store, f: &'a Fakes) -> TransportOps<'a> {
    TransportOps {
        store,
        keys: f,
        serve: f,
        peers: f,
    }
}

fn now() -> Timestamp {
    "2026-11-21T12:00:00Z".parse().unwrap()
}

fn store() -> Store {
    Store::open_in_memory(Arc::new(NoFaults)).unwrap()
}

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn relays(urls: &[&str]) -> ExposurePolicy {
    ExposurePolicy {
        bind: BindScope::Loopback,
        infrastructure: InfrastructureProfile::Custom {
            relays: urls.iter().map(|u| (*u).to_owned()).collect(),
        },
        direct_fallback: false,
    }
}

fn admission_generation(store: &Store) -> u64 {
    store
        .transaction(|tx| tx.remote_authority_generation())
        .unwrap()
}

/// m06-plan U56 unit row: an unattended (or remote, not yet decided) request for serving,
/// a new relay set, a broader bind, direct fallback, public infrastructure or a roost
/// adoption is refused `exposure_unconsented` when executed without its decision, and
/// nothing is generated or recorded.
#[test]
fn widening_without_its_decision_is_exposure_unconsented_and_records_nothing() {
    let wildcard = ExposurePolicy {
        bind: BindScope::Wildcard,
        ..ExposurePolicy::default()
    };
    let interface = ExposurePolicy {
        bind: BindScope::Interface {
            address: "192.0.2.10".into(),
        },
        ..ExposurePolicy::default()
    };
    let fallback = ExposurePolicy {
        direct_fallback: true,
        ..ExposurePolicy::default()
    };
    let public = ExposurePolicy {
        infrastructure: InfrastructureProfile::N0Public,
        ..ExposurePolicy::default()
    };
    let cases: Vec<(bool, ExposurePolicy)> = vec![
        (true, ExposurePolicy::default()),
        (false, relays(&["https://relay.example.invalid"])),
        (false, wildcard),
        (false, interface),
        (false, fallback),
    ];
    let store = store();
    let f = Fakes::new();
    for (serve, policy) in cases {
        let delta = ops(&store, &f).enable_delta(serve, Some(&policy)).unwrap();
        assert!(widens(&delta), "{policy:?}");
        let err =
            run(ops(&store, &f).enable(serve, Some(policy.clone()), None, now())).unwrap_err();
        assert_eq!(
            err.reason.as_deref(),
            Some("exposure_unconsented"),
            "{policy:?}"
        );
        assert_eq!(err.effect_status, EffectStatus::None);
    }
    // Public infrastructure widens too; this build also cannot apply it (outside V1).
    let delta = ops(&store, &f).enable_delta(false, Some(&public)).unwrap();
    assert!(widens(&delta) && delta.public_infrastructure_added);
    let roost = endpoint(b'e');
    let err = run(ops(&store, &f).adopt_roost(
        &DestinationId::parse("lab").unwrap(),
        &roost,
        None,
        None,
        now(),
    ))
    .unwrap_err();
    assert_eq!(err.reason.as_deref(), Some("exposure_unconsented"));
    let calls = f.calls.lock().unwrap();
    assert_eq!(calls.created, 0, "no key generated");
    assert_eq!(calls.started, 0);
    assert!(
        store
            .transaction(|tx| tx.transport_keys())
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .transaction(|tx| tx.all_route_consents())
            .unwrap()
            .is_empty()
    );
}

/// The decision binds the exact delta: one approved for another delta executes nothing.
#[test]
fn a_decision_for_another_delta_does_not_execute() {
    let store = store();
    let f = Fakes::new();
    let o = ops(&store, &f);
    let approved_for = o
        .enable_delta(false, Some(&relays(&["https://a.example.invalid"])))
        .unwrap();
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([1; 16]),
        delta: approved_for,
    };
    let err = run(o.enable(
        false,
        Some(relays(&[
            "https://a.example.invalid",
            "https://b.example.invalid",
        ])),
        Some(&approved),
        now(),
    ))
    .unwrap_err();
    assert_eq!(err.reason.as_deref(), Some("exposure_unconsented"));
    assert_eq!(f.calls.lock().unwrap().created, 0);
}

/// The minimal, non-serving enable needs no decision and records only a reference; with
/// no verified store it is refused `transport_key_store_unavailable` and records nothing
/// (direct and bastion routes are untouched: nothing here reads them).
#[test]
fn minimal_enable_records_a_reference_and_no_store_refuses() {
    let store = store();
    let mut f = Fakes::new();
    f.store_refusal = Some("unsupported");
    let err = run(ops(&store, &f).enable(false, None, None, now())).unwrap_err();
    assert_eq!(
        err.reason.as_deref(),
        Some("transport_key_store_unavailable")
    );
    assert_eq!(err.code, Code::CapabilityUnavailable);
    assert!(
        store
            .transaction(|tx| tx.transport_keys())
            .unwrap()
            .is_empty()
    );

    let f = Fakes::new();
    let done = run(ops(&store, &f).enable(false, None, None, now())).unwrap();
    assert!(!done.serve && done.consent.is_none() && !done.already_enabled);
    let key = store
        .transaction(|tx| tx.active_transport_key())
        .unwrap()
        .unwrap();
    assert_eq!(key.endpoint, done.endpoint);
    assert_eq!(key.store_kind, "fixture_test");
    assert_eq!(f.calls.lock().unwrap().started, 0);
    // The same configuration again: the same result, no second key.
    let again = run(ops(&store, &f).enable(false, None, None, now())).unwrap();
    assert!(again.already_enabled);
    assert_eq!(again.endpoint, done.endpoint);
    assert_eq!(f.calls.lock().unwrap().created, 1);
    // Another configuration: refused (disable first), nothing changes.
    let err = run(ops(&store, &f).enable(true, None, None, now())).unwrap_err();
    assert_eq!(err.code, Code::ConfigConflict);
    assert_eq!(admission_generation(&store), 0);
}

fn destination(id: &str) -> DestinationRecord {
    DestinationRecord {
        id: DestinationId::parse(id).unwrap(),
        alias: format!("a-{id}"),
        revision: 1,
        definition: DestinationDefinition::Managed {
            hostname: "192.0.2.20".into(),
            port: None,
            account: AccountName::parse("deploy").unwrap(),
            identity: IdentityId::from_random_bytes([3; 16]),
            jump: None,
        },
        label: None,
        updated_at: now(),
    }
}

/// Serving with its decision records the consent and starts the child; adopting a roost
/// with its decision appends the route (the one-element route made explicit) and records
/// its consent; `disable` then withdraws the key and moves the admission generation in the
/// same commit, removes the routes naming this endpoint and every consent, clears the
/// allowlist, stops the child and destroys the item: no key, route, allowlist entry or
/// consent is left, and the roost route (another endpoint) stays.
#[test]
fn serve_adopt_then_disable_leaves_no_key_route_allowlist_entry_or_consent() {
    let store = store();
    let f = Fakes::new();
    let o = ops(&store, &f);
    let delta = o.enable_delta(true, None).unwrap();
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([4; 16]),
        delta,
    };
    let served = run(o.enable(true, None, Some(&approved), now())).unwrap();
    assert!(served.serve && served.consent.is_some());
    assert_eq!(f.calls.lock().unwrap().started, 1);
    let state = store.transaction(endpoint_state).unwrap();
    assert!(state.serve);
    assert_eq!(state.consents.len(), 1);

    // A destination with a route naming this endpoint, and a roost adopted on another.
    let lab = destination("lab");
    let self_route = DestinationRoute {
        id: RouteId::from_random_bytes([7; 16]),
        route: RouteSpec::Iroh {
            endpoint: served.endpoint.clone(),
            direct_addresses: vec!["127.0.0.1:4433".into()],
            external_roost: false,
        },
        exposure: None,
        consents: Vec::new(),
        identification_timeout_ms: None,
    };
    store
        .transaction(|tx| {
            tx.upsert_destination(&lab)?;
            let mut list = heimdall_domain::routes::approved_routes(&lab, None);
            list.push(self_route.clone());
            tx.put_destination_routes(&lab.id, &list, now())
        })
        .unwrap();
    let roost = endpoint(b'e');
    let roost_delta = TransportOps::adopt_delta(&roost, None);
    let adopted = run(o.adopt_roost(
        &lab.id,
        &roost,
        None,
        Some(&ApprovedWidening {
            decision: DecisionId::from_random_bytes([5; 16]),
            delta: roost_delta,
        }),
        now(),
    ))
    .unwrap();
    assert_eq!(adopted.disclosure, ROOST_DISCLOSURE);
    let routes = store
        .transaction(|tx| tx.destination_routes(&lab.id))
        .unwrap();
    assert_eq!(routes.len(), 3, "implicit, self, roost");
    assert!(matches!(
        &routes[2].route,
        RouteSpec::Iroh { external_roost: true, endpoint, .. } if *endpoint == roost
    ));
    // Adopting the same roost again is refused.
    let err = run(o.adopt_roost(
        &lab.id,
        &roost,
        None,
        Some(&ApprovedWidening {
            decision: DecisionId::from_random_bytes([6; 16]),
            delta: TransportOps::adopt_delta(&roost, None),
        }),
        now(),
    ))
    .unwrap_err();
    assert_eq!(err.code, Code::ConfigConflict);

    let before = admission_generation(&store);
    let done = run(o.disable(now())).unwrap();
    assert_eq!(done.endpoints, vec![served.endpoint.clone()]);
    assert_eq!(done.routes_removed, vec![self_route.id.clone()]);
    assert_eq!(done.consents_removed, 1, "the serving consent");
    assert_eq!(done.allowlist_entries_removed, 2);
    assert_eq!(done.admission, AdmissionReport::Applied);
    assert!(done.keys_pending.is_empty());
    assert!(
        admission_generation(&store) > before,
        "the narrowing bumped"
    );
    let calls = f.calls.lock().unwrap();
    assert_eq!(calls.stopped, 1);
    assert_eq!(calls.cleared, 1);
    assert_eq!(calls.destroyed, vec![served.endpoint.clone()]);
    drop(calls);
    assert!(
        store
            .transaction(|tx| tx.transport_keys())
            .unwrap()
            .is_empty()
    );
    let left = store
        .transaction(|tx| tx.destination_routes(&lab.id))
        .unwrap();
    assert_eq!(left.len(), 2, "the implicit and the roost route stay");
    assert!(left.iter().all(|r| r.id != self_route.id));
    assert!(
        store
            .transaction(|tx| tx.route_consents(None))
            .unwrap()
            .is_empty()
    );
    let state = store.transaction(endpoint_state).unwrap();
    assert!(state.key.is_none() && !state.serve);
    // Disable again: nothing to withdraw, nothing moves.
    let g = admission_generation(&store);
    let again = run(o.disable(now())).unwrap();
    assert!(again.endpoints.is_empty() && again.routes_removed.is_empty());
    assert_eq!(admission_generation(&store), g);
}

/// The delta names each added relay, the bind before and after and the other changes;
/// narrowing or an equal policy never widens.
#[test]
fn deltas_name_the_exact_change_and_narrowing_never_widens() {
    let before = relays(&["https://a.example.invalid"]);
    let after = ExposurePolicy {
        bind: BindScope::Wildcard,
        infrastructure: InfrastructureProfile::Custom {
            relays: vec![
                "https://a.example.invalid".into(),
                "https://b.example.invalid".into(),
            ],
        },
        direct_fallback: true,
    };
    let d = exposure_delta(None, &before, false, &after, false, None);
    assert_eq!(d.relays_added, vec!["https://b.example.invalid".to_owned()]);
    assert_eq!(d.bind_before, BindScope::Loopback);
    assert_eq!(d.bind_after, BindScope::Wildcard);
    assert!(d.direct_fallback_added && widens(&d));
    let back = exposure_delta(None, &after, true, &before, false, None);
    assert!(!widens(&back), "narrowing needs no consent");
    let same = exposure_delta(None, &before, true, &before, true, None);
    assert!(!widens(&same));
    let none_to_loopback = exposure_delta(
        None,
        &ExposurePolicy {
            bind: BindScope::None,
            ..ExposurePolicy::default()
        },
        false,
        &ExposurePolicy::default(),
        false,
        None,
    );
    assert!(!widens(&none_to_loopback));
    let loopback_interface = ExposurePolicy {
        bind: BindScope::Interface {
            address: "127.0.0.1".into(),
        },
        ..ExposurePolicy::default()
    };
    assert!(!widens(&exposure_delta(
        None,
        &ExposurePolicy::default(),
        false,
        &loopback_interface,
        false,
        None
    )));
}

/// K_iroh rotation (ADR-0012 §2.4 item 4): a new endpoint ID, the old reference withdrawn
/// with the admission generation moved in the same commit, the serve child narrowed
/// (replaced), the old item destroyed, the consent and exposure kept; with nothing
/// enabled it is refused.
#[test]
fn rotation_gives_a_new_endpoint_and_narrows_admission() {
    let store = store();
    let f = Fakes::new();
    let o = ops(&store, &f);
    let err = run(o.rotate(now())).unwrap_err();
    assert_eq!(err.reason.as_deref(), Some("transport_unavailable"));
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([8; 16]),
        delta: o.enable_delta(true, None).unwrap(),
    };
    let first = run(o.enable(true, None, Some(&approved), now())).unwrap();
    let before = admission_generation(&store);
    let rotated = run(o.rotate(now())).unwrap();
    assert_ne!(rotated.endpoint, first.endpoint);
    assert_eq!(rotated.previous, first.endpoint);
    assert!(rotated.previous_destroyed);
    assert_eq!(rotated.admission, AdmissionReport::Applied);
    assert_eq!(admission_generation(&store), before + 1);
    let state = store.transaction(endpoint_state).unwrap();
    assert_eq!(state.key.unwrap().endpoint, rotated.endpoint);
    assert!(state.serve, "the consent carries over");
    assert_eq!(
        store.transaction(|tx| tx.transport_keys()).unwrap().len(),
        1,
        "the withdrawn row is deleted once its item is gone"
    );
    let calls = f.calls.lock().unwrap();
    assert_eq!(calls.narrowed, 1);
    assert_eq!(calls.destroyed, vec![first.endpoint.clone()]);
}
