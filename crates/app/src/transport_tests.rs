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
    fn clear(&self, _tx: &mut Txn<'_>, _now: Timestamp) -> heimdall_store::Result<usize> {
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
        ..ExposurePolicy::default()
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
    // ⟨M06 W5⟩ A non-default sshd port on an adoption is refused before any consent is
    // read (a dialer has no target), even with a decision bound to that very request.
    let other = endpoint(b'f');
    let with_port = ExposurePolicy {
        sshd_port: 2222,
        ..ExposurePolicy::default()
    };
    for approved in [
        None,
        Some(ApprovedWidening {
            decision: DecisionId::from_random_bytes([7; 16]),
            delta: TransportOps::adopt_delta(&other, Some(&with_port)),
        }),
    ] {
        let err = run(o.adopt_roost(
            &lab.id,
            &other,
            Some(with_port.clone()),
            approved.as_ref(),
            now(),
        ))
        .unwrap_err();
        assert_eq!(err.code, Code::UsageError);
        assert_eq!(err.message, SSHD_PORT_NOT_FOR_A_DIALER);
        assert_eq!(err.effect_status, EffectStatus::None);
    }
    assert_eq!(
        store
            .transaction(|tx| tx.destination_routes(&lab.id))
            .unwrap()
            .len(),
        3,
        "nothing was adopted"
    );
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
        ..ExposurePolicy::default()
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
    let err = run(o.rotate(None, now())).unwrap_err();
    assert_eq!(err.reason.as_deref(), Some("transport_unavailable"));
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([8; 16]),
        delta: o.enable_delta(true, None).unwrap(),
    };
    let first = run(o.enable(true, None, Some(&approved), now())).unwrap();
    let before = admission_generation(&store);
    let rotated = run(o.rotate(None, now())).unwrap();
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
    assert!(rotated.runners.is_empty() && rotated.pending.is_empty() && !rotated.resumed);
    assert_eq!(
        store.transaction(|tx| tx.transport_rotation()).unwrap(),
        None,
        "nothing was left to announce"
    );
    let calls = f.calls.lock().unwrap();
    assert_eq!(calls.narrowed, 1);
    assert_eq!(calls.destroyed, vec![first.endpoint.clone()]);
}

/// A scripted management channel: the runners in `failing` refuse; every call is logged.
#[derive(Default)]
struct Announcer {
    failing: Mutex<Vec<EnvironmentId>>,
    told: Mutex<Vec<(EnvironmentId, IrohEndpointId)>>,
}

#[async_trait]
impl EndpointAnnouncer for Announcer {
    async fn announce(
        &self,
        environment: &EnvironmentId,
        endpoint: &IrohEndpointId,
    ) -> Result<(), OpError> {
        self.told
            .lock()
            .unwrap()
            .push((environment.clone(), endpoint.clone()));
        if self.failing.lock().unwrap().contains(environment) {
            return Err(
                OpError::new(Code::ServiceUnavailable, "the runner cannot be reached")
                    .with_effect(EffectStatus::None),
            );
        }
        Ok(())
    }
}

fn runner(n: u8) -> EnvironmentId {
    EnvironmentId::from_random_bytes([n; 16])
}

fn record_runner(store: &Store, environment: &EnvironmentId) {
    store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                environment,
                &DestinationId::parse("lab").unwrap(),
                &AccountName::parse("runner").unwrap(),
                &heimdall_contract::ids::KeyFingerprint::parse(&format!(
                    "SHA256:{}",
                    "A".repeat(43)
                ))
                .unwrap(),
                r#"{"v":1}"#,
                now(),
            )
        })
        .unwrap();
}

fn enabled(store: &Store, f: &Fakes) -> IrohEndpointId {
    let o = ops(store, f);
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([8; 16]),
        delta: o.enable_delta(true, None).unwrap(),
    };
    run(o.enable(true, None, Some(&approved), now()))
        .unwrap()
        .endpoint
}

/// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ `transport.rotate` is retry-safe. A runner that fails
/// stays recorded as pending and is named in the result; the old key survives (its item is
/// not destroyed and its withdrawn row stays) while anyone is pending. A re-run mints no
/// further key, tells only the pending runner, and once it acknowledges the old key is
/// destroyed and the record forgotten. A third run is then a fresh rotation.
#[test]
fn a_failed_runner_stays_pending_and_a_rerun_finishes_without_a_new_key() {
    let store = store();
    let f = Fakes::new();
    let old = enabled(&store, &f);
    let (a, b) = (runner(0xa1), runner(0xb2));
    record_runner(&store, &a);
    record_runner(&store, &b);
    let channel = Announcer::default();
    channel.failing.lock().unwrap().push(b.clone());
    let o = ops(&store, &f);
    let generation = admission_generation(&store);

    let first = run(o.rotate(Some(&channel), now())).unwrap();
    assert_eq!(first.previous, old);
    assert!(!first.resumed);
    assert_eq!(first.pending, vec![b.clone()], "the failed runner is named");
    assert!(!first.previous_destroyed, "the old key survives");
    assert_eq!(first.runners.len(), 2);
    assert_eq!(first.runners[0].outcome, AnnouncementOutcome::Acknowledged);
    assert!(matches!(
        &first.runners[1].outcome,
        AnnouncementOutcome::Pending {
            code: Code::ServiceUnavailable,
            ..
        }
    ));
    assert_eq!(
        f.calls.lock().unwrap().created,
        2,
        "enable's key and the new one"
    );
    assert!(f.calls.lock().unwrap().destroyed.is_empty());
    assert_eq!(admission_generation(&store), generation + 1);
    let keys = store.transaction(|tx| tx.transport_keys()).unwrap();
    assert_eq!(
        keys.len(),
        2,
        "the withdrawn row stays while a runner is pending"
    );
    let record = store
        .transaction(|tx| tx.transport_rotation())
        .unwrap()
        .unwrap();
    assert_eq!(
        (&record.endpoint, &record.previous, &record.pending),
        (&first.endpoint, &old, &vec![b.clone()])
    );

    // Re-run while the runner still fails: nothing minted, only the pending runner told.
    let again = run(o.rotate(Some(&channel), now())).unwrap();
    assert!(again.resumed);
    assert_eq!(again.endpoint, first.endpoint, "no further key");
    assert_eq!(again.pending, vec![b.clone()]);
    assert_eq!(again.runners.len(), 1);
    assert_eq!(f.calls.lock().unwrap().created, 2);
    assert!(f.calls.lock().unwrap().destroyed.is_empty());
    assert_eq!(
        admission_generation(&store),
        generation + 1,
        "a re-run narrows nothing further"
    );

    // The runner comes back: the re-run finishes it and only then destroys the old key.
    channel.failing.lock().unwrap().clear();
    let done = run(o.rotate(Some(&channel), now())).unwrap();
    assert!(done.resumed && done.pending.is_empty() && done.previous_destroyed);
    assert_eq!(done.endpoint, first.endpoint);
    assert_eq!(f.calls.lock().unwrap().created, 2, "still no further key");
    assert_eq!(f.calls.lock().unwrap().destroyed, vec![old.clone()]);
    assert_eq!(
        store.transaction(|tx| tx.transport_keys()).unwrap().len(),
        1
    );
    assert_eq!(
        store.transaction(|tx| tx.transport_rotation()).unwrap(),
        None
    );
    let told = channel.told.lock().unwrap().clone();
    assert_eq!(
        told,
        vec![
            (a.clone(), first.endpoint.clone()),
            (b.clone(), first.endpoint.clone()),
            (b.clone(), first.endpoint.clone()),
            (b.clone(), first.endpoint.clone()),
        ],
        "an acknowledged runner is never told again"
    );
    drop(told);

    // Nothing pending any more: the next run is a fresh rotation.
    let fresh = run(o.rotate(Some(&channel), now())).unwrap();
    assert!(!fresh.resumed);
    assert_ne!(fresh.endpoint, first.endpoint);
    assert_eq!(fresh.previous, first.endpoint);
    assert!(fresh.previous_destroyed);
}

/// ⟨rev6.3⟩ A pending runner that is forgotten (its record removed) no longer holds the old
/// key; with runners to tell and no management channel nothing is rotated at all; and
/// `disable` ends a rotation still being announced, destroying both keys.
#[test]
fn forgotten_runners_release_the_old_key_and_no_channel_rotates_nothing() {
    let store = store();
    let f = Fakes::new();
    let old = enabled(&store, &f);
    let a = runner(0xa1);
    record_runner(&store, &a);
    let o = ops(&store, &f);
    // No management channel: refused before any key is minted.
    let err = run(o.rotate(None, now())).unwrap_err();
    assert_eq!(err.reason.as_deref(), Some(reason::DRIVER_UNAVAILABLE));
    assert_eq!(f.calls.lock().unwrap().created, 1);
    assert_eq!(
        store.transaction(|tx| tx.transport_rotation()).unwrap(),
        None
    );
    assert_eq!(
        store
            .transaction(endpoint_state)
            .unwrap()
            .key
            .unwrap()
            .endpoint,
        old
    );
    let channel = Announcer::default();
    channel.failing.lock().unwrap().push(a.clone());
    let first = run(o.rotate(Some(&channel), now())).unwrap();
    assert_eq!(first.pending, vec![a.clone()]);
    assert!(f.calls.lock().unwrap().destroyed.is_empty());
    // The owner removes the environment: the runner is forgotten.
    store
        .transaction(|tx| tx.remove_remote_environment_pin(&a))
        .unwrap();
    let done = run(o.rotate(None, now())).unwrap();
    assert!(done.resumed && done.pending.is_empty() && done.previous_destroyed);
    assert_eq!(done.runners[0].outcome, AnnouncementOutcome::Forgotten);
    assert_eq!(f.calls.lock().unwrap().destroyed, vec![old.clone()]);
    assert_eq!(
        channel.told.lock().unwrap().len(),
        1,
        "a forgotten runner is not told"
    );

    // A rotation still being announced, then `disable`: no key and no record is left.
    record_runner(&store, &a);
    let second = run(o.rotate(Some(&channel), now())).unwrap();
    assert_eq!(second.pending, vec![a]);
    run(o.disable(now())).unwrap();
    assert_eq!(
        store.transaction(|tx| tx.transport_rotation()).unwrap(),
        None
    );
    assert!(
        store
            .transaction(|tx| tx.transport_keys())
            .unwrap()
            .is_empty()
    );
    let destroyed = f.calls.lock().unwrap().destroyed.clone();
    assert!(destroyed.contains(&second.endpoint) && destroyed.contains(&second.previous));
}

/// ⟨M06 W5; ADR-0006 §18.9 item 1; ADR-0012 §2.3 item 2⟩ The serve policy's sshd port:
/// `0` is refused and so is a port without `serve` (nothing recorded, no key made); the
/// default is 22; a named port is bound to the decision's exact delta (a decision for
/// another port does not execute), is recorded with the serve consent in the one enabling
/// transaction, and is what the endpoint's durable state reads back; the same request again
/// is the same result and another port is another configuration (`disable` first).
#[test]
fn the_sshd_port_is_validated_recorded_with_the_serve_consent_and_changed_only_through_disable() {
    let store = store();
    let f = Fakes::new();
    let o = ops(&store, &f);
    let with_port = |sshd_port: u16| ExposurePolicy {
        sshd_port,
        ..ExposurePolicy::default()
    };
    let approve = |policy: &ExposurePolicy, n: u8| ApprovedWidening {
        decision: DecisionId::from_random_bytes([n; 16]),
        delta: o.enable_delta(true, Some(policy)).unwrap(),
    };

    // Validation: nothing is recorded and no key is made.
    let zero = with_port(0);
    let e = run(o.enable(true, Some(zero.clone()), Some(&approve(&zero, 1)), now())).unwrap_err();
    assert_eq!(e.code, Code::UsageError);
    let unserved = run(o.enable(false, Some(with_port(2222)), None, now())).unwrap_err();
    assert_eq!(unserved.code, Code::UsageError);
    assert_eq!(f.calls.lock().unwrap().created, 0);
    assert!(store.transaction(endpoint_state).unwrap().key.is_none());

    // A decision for port 22 does not approve port 2222.
    let named = with_port(2222);
    let for_default = approve(&ExposurePolicy::default(), 2);
    let e = run(o.enable(true, Some(named.clone()), Some(&for_default), now())).unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::EXPOSURE_UNCONSENTED));
    assert_eq!(f.calls.lock().unwrap().created, 0);

    // The named port, approved: recorded, and read back from durable state.
    let approved = approve(&named, 3);
    let enabled = run(o.enable(true, Some(named.clone()), Some(&approved), now())).unwrap();
    assert_eq!(enabled.exposure.sshd_port, 2222);
    let state = store.transaction(endpoint_state).unwrap();
    assert!(state.serve);
    assert_eq!(state.policy.sshd_port, 2222);
    assert_eq!(
        serde_json::to_value(&enabled).unwrap()["exposure"]["sshd_port"],
        2222
    );

    // The same request again: the same result. Another port: disable first.
    let again = run(o.enable(true, Some(named.clone()), None, now())).unwrap();
    assert!(again.already_enabled);
    for other in [ExposurePolicy::default(), with_port(2223)] {
        let e =
            run(o.enable(true, Some(other.clone()), Some(&approve(&other, 4)), now())).unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict);
    }
    assert_eq!(
        store.transaction(endpoint_state).unwrap().policy.sshd_port,
        2222
    );

    // Disable, then enable with the default: 22, and the field is omitted.
    run(o.disable(now())).unwrap();
    let default = ExposurePolicy::default();
    let approved = approve(&default, 5);
    let enabled = run(o.enable(true, None, Some(&approved), now())).unwrap();
    assert_eq!(enabled.exposure.sshd_port, 22);
    assert!(
        serde_json::to_value(&enabled).unwrap()["exposure"]
            .get("sshd_port")
            .is_none()
    );
    assert_eq!(
        store.transaction(endpoint_state).unwrap().policy.sshd_port,
        22
    );
}

/// ⟨rev7; ruling R-A; D20⟩ `transport enable`'s interface bind address is recorded in its one
/// spelling: the delta a decision is bound to names it so, the approval of that delta executes
/// a request in another spelling of the same address, and the endpoint's policy reads it so. A
/// zone on a global address, an interface-name zone or garbage is `USAGE_ERROR` with
/// `fix_request`, over 64 bytes `item_too_large`, before any key or record. `adopt_roost` over
/// a route bound (9 relays; a 9th route) is `item_too_large` and records nothing.
#[test]
fn interface_binds_are_canonical_and_transport_bounds_refuse() {
    let store = store();
    let f = Fakes::new();
    let o = ops(&store, &f);
    let given = ExposurePolicy {
        bind: BindScope::Interface {
            address: "2001:0DB8:0000::0001".into(),
        },
        ..ExposurePolicy::default()
    };
    let canonical = BindScope::Interface {
        address: "2001:db8::1".into(),
    };
    let request = TransportRequest::Enable {
        serve: false,
        exposure: Some(given.clone()),
        request_id: heimdall_contract::ids::RequestId::parse("r-bind").unwrap(),
    };
    let delta = o.delta_of(&request).unwrap().unwrap();
    assert_eq!(delta.bind_after, canonical);
    for (address, reason, what) in [
        (
            "fe80::1%2",
            None,
            "a link-local zone (no zoned bind in 1.0)",
        ),
        ("2001:db8::1%2", None, "a zone on a global address"),
        ("fe80::1%eth0", None, "an interface-name zone"),
        ("garbage", None, "garbage"),
        (
            "fe80::1%000000000000000000000000000000000000000000000000000000000002",
            Some(reason::ITEM_TOO_LARGE),
            "over 64 bytes",
        ),
    ] {
        let bad = ExposurePolicy {
            bind: BindScope::Interface {
                address: address.into(),
            },
            ..ExposurePolicy::default()
        };
        let e = o.enable_delta(false, Some(&bad)).unwrap_err();
        assert_eq!(
            (e.code, e.reason.as_deref()),
            (Code::UsageError, reason),
            "{what}"
        );
        assert_eq!(e.next.action, "fix_request", "{what}");
        let e = run(o.enable(false, Some(bad), None, now())).unwrap_err();
        assert_eq!(
            (e.code, e.reason.as_deref()),
            (Code::UsageError, reason),
            "{what}"
        );
    }
    assert_eq!(f.calls.lock().unwrap().created, 0, "no key for a refusal");
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([5; 16]),
        delta,
    };
    let enabled = run(o.enable(false, Some(given), Some(&approved), now())).unwrap();
    assert_eq!(enabled.exposure.bind, canonical);
    assert_eq!(
        store.transaction(endpoint_state).unwrap().policy.bind,
        canonical
    );

    // adopt_roost: a dialer policy with 9 relays, then a destination already at 8 routes.
    let lab = destination("lab");
    store.transaction(|tx| tx.upsert_destination(&lab)).unwrap();
    let nine: Vec<String> = (0..9)
        .map(|i| format!("https://relay{i}.example.invalid/"))
        .collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    let roost = endpoint(b'd');
    let policy = relays(&nine);
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([6; 16]),
        delta: TransportOps::adopt_delta(&roost, Some(&policy)),
    };
    let e = run(o.adopt_roost(&lab.id, &roost, Some(policy), Some(&approved), now())).unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ITEM_TOO_LARGE), "{e:?}");
    assert!(e.message.starts_with("relays"), "{}", e.message);
    let mut full = heimdall_domain::routes::approved_routes(&lab, None);
    for i in 1..heimdall_contract::bounds::MAX_ROUTES_PER_DESTINATION {
        full.push(DestinationRoute {
            id: RouteId::from_random_bytes([u8::try_from(i).unwrap(); 16]),
            route: RouteSpec::Direct {
                host: format!("10.9.0.{i}"),
                port: None,
            },
            exposure: None,
            consents: Vec::new(),
            identification_timeout_ms: None,
        });
    }
    store
        .transaction(|tx| tx.put_destination_routes(&lab.id, &full, now()))
        .unwrap();
    let approved = ApprovedWidening {
        decision: DecisionId::from_random_bytes([7; 16]),
        delta: TransportOps::adopt_delta(&roost, None),
    };
    let e = run(o.adopt_roost(&lab.id, &roost, None, Some(&approved), now())).unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ITEM_TOO_LARGE), "{e:?}");
    assert!(e.message.starts_with("routes"), "{}", e.message);
    let e = o.adopt_checked(&lab.id, &roost, None).unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ITEM_TOO_LARGE));
    assert_eq!(
        store
            .transaction(|tx| tx.destination_routes(&lab.id))
            .unwrap(),
        full,
        "nothing was written"
    );
}
