//! ⟨rev7⟩ m07-plan U3-3a (ADR-0013 §11 D1, §12 PC2): the `inspect` arms that build a typed
//! view answer exactly the document the hand-built JSON they replace answered. Each test
//! keeps a copy of the replaced builder (`legacy_*`) and compares whole documents, over a
//! real in-memory store and a real `Operations`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ClientId, DecisionId, DeviceId, EffectId, EnvironmentId, PolicyId};
use heimdall_contract::request::{InspectRequest, InspectSubject};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::{BootId, SyncStatus, TimePolicy};
use heimdall_domain::workspace::{DecisionBasis, DeliveredLift};
use heimdall_store::{Store, Txn};
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};
use serde_json::{Value, json};

use crate::context::Caller;
use crate::ensure::NoStageHook;
use crate::events::decision_kind_name;
use crate::operations::{
    Limits, Operations, OperationsConfig, code_row_view, decision_scope, decision_view, stop_m05,
};

fn t0() -> Timestamp {
    "2026-11-25T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([9; 16])
}

fn store() -> Arc<Store> {
    let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })
        })
        .unwrap();
    store
}

async fn ops_on(store: Arc<Store>) -> Operations {
    Operations::start(OperationsConfig {
        store,
        clock: VirtualClock::at(t0()),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: Vec::new(),
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: Duration::from_secs(3600),
        projection: None,
    })
    .await
    .unwrap()
}

fn caller(role: ClientRole, client: Option<u8>) -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role,
        remote_client: client.map(|b| ClientId::from_random_bytes([b; 16])),
    })
}

fn owner() -> Caller {
    caller(ClientRole::Owner, None)
}

fn viewer() -> Caller {
    caller(ClientRole::LimitedConsumer, Some(2))
}

async fn whole(ops: &Operations, who: &Caller, subject: InspectSubject) -> Value {
    let done = ops
        .inspect(
            who,
            InspectRequest {
                subject,
                preview: None,
                cwd: None,
                redact: false,
                select: None,
                page: None,
            },
        )
        .await
        .unwrap();
    done.data
}

/// The code table rows are `schema::code_table`'s, row for row.
#[test]
fn code_rows_match_the_code_table() {
    let rows: Vec<_> = heimdall_contract::Code::all()
        .iter()
        .map(code_row_view)
        .collect();
    assert_eq!(
        serde_json::to_value(rows).unwrap(),
        heimdall_contract::schema::code_table()["codes"]
    );
}

/// `inspect capabilities`: the typed view is the replaced `json!` document, its `lock` and
/// `login_start` included (no adapter: continuity not verified; no login port: `none`).
#[tokio::test]
async fn capabilities_view_is_the_hand_built_document() {
    use heimdall_contract::ipc::capability as c;
    let ops = ops_on(store()).await;
    let got = whole(&ops, &owner(), InspectSubject::Capabilities).await;
    let disclosure = ops
        .lock_disclosure(false, ops.session_lock_signal())
        .await
        .unwrap();
    // The replaced builder: the arm's `json!`, then `add_capabilities_lock` and
    // `add_capabilities_login`.
    let mut legacy = json!({
        "capabilities": [
            c::OPERATIONS_V1, c::EVENTS_V1, c::OWNER_POLICY_V1, c::SCHEMA_DISCOVERY_V1,
            c::SERVICE_CONTROL_V1, c::SETUP_V1, c::ISSUER_V1, c::ENROLLMENT_V1,
            c::MANAGED_CREDENTIALS_V1, c::CONNECTIONS_V1, c::ENVIRONMENTS_V1,
            c::TRUSTED_WORK_V1, c::PAGES_V1,
        ],
        "schemas": heimdall_contract::schema::public_schemas()
            .iter()
            .map(|s| s.name)
            .collect::<Vec<_>>(),
        "codes": heimdall_contract::schema::code_table()["codes"].clone(),
        "schema_version": heimdall_contract::SchemaVersion::current(),
    });
    let mut lock = json!({
        "behavior": disclosure.behavior,
        "disclosure": disclosure.text,
    });
    if let Some(at) = disclosure.acknowledged_at {
        lock["acknowledged_at"] = json!(at);
    }
    legacy["lock"] = lock;
    legacy["login_start"] = serde_json::to_value(heimdall_contract::environment::LoginStartView {
        kind: heimdall_contract::environment::LoginStartKind::None,
        installed: false,
    })
    .unwrap();
    assert_eq!(got, legacy);
    // An acknowledged disclosure carries `acknowledged_at`, as before.
    ops.acknowledge_lock_disclosure().await.unwrap();
    let got = whole(&ops, &owner(), InspectSubject::Capabilities).await;
    let at = ops
        .lock_disclosure(false, ops.session_lock_signal())
        .await
        .unwrap()
        .acknowledged_at
        .unwrap();
    legacy["lock"]["acknowledged_at"] = json!(at);
    assert_eq!(got, legacy);
}

fn record(id: u8, kind: DecisionKind, expires_at: &str) -> DecisionRecord {
    DecisionRecord {
        id: DecisionId::from_random_bytes([id; 16]),
        kind,
        generation: AuthorityGeneration(0),
        created_at: "2026-11-25T08:00:00Z".parse().unwrap(),
        expires_at: expires_at.parse().unwrap(),
        state: DecisionState::Pending,
        decided_at: None,
    }
}

/// The replaced `decision_view` and the arm's insertions, over the same record and store.
fn legacy_decision(tx: &mut Txn<'_>, d: &DecisionRecord, now: Timestamp) -> Value {
    // `request` is built by the same code before and after (persisted content, D9).
    let request = serde_json::to_value(decision_view(d, now)).unwrap()["request"].clone();
    let mut view = json!({
        "decision_id": d.id,
        "kind": decision_kind_name(&d.kind),
        "state": d.state,
        "created_at": d.created_at,
        "expires_at": d.expires_at,
        "expired": now >= d.expires_at,
        "request": request,
    });
    let Value::Object(map) = &mut view else {
        unreachable!()
    };
    if let Some(policies) = stop_m05::listed_policies(tx, d).unwrap() {
        map.insert("policies".to_owned(), json!(policies));
    }
    if let Some(lifted) = stop_m05::lifted_effects(tx, d).unwrap() {
        map.insert("lifted_effects".to_owned(), json!(lifted));
    }
    if let Some(scope) = decision_scope(tx, d).unwrap() {
        map.insert("scope".to_owned(), json!(scope));
    }
    view
}

/// `inspect decisions`: the typed list is the replaced document for records of several
/// kinds, a past-deadline one, a targeted widening listing no policies (`policies: []`), one
/// listing a policy and lifting a delivered effect (`lifted_effects`), and a projection;
/// another role reads `{"decisions": []}`.
#[tokio::test]
async fn decisions_view_is_the_hand_built_document() {
    use heimdall_contract::request::PolicyAction;
    use heimdall_domain::projection::{ProjectionSummary, SummaryIntent};
    let store = store();
    let pol = PolicyId::parse("pol-views").unwrap();
    let records = vec![
        record(
            1,
            DecisionKind::ConfirmTime {
                boot_id: BootId("boot-1".to_owned()),
                observed_wall: t0(),
            },
            "2026-11-25T10:00:00Z",
        ),
        // Past its deadline at the read: `expired: true`.
        record(
            2,
            DecisionKind::ConfirmTime {
                boot_id: BootId("boot-2".to_owned()),
                observed_wall: t0(),
            },
            "2026-11-25T08:30:00Z",
        ),
        record(
            3,
            DecisionKind::WidenPolicy {
                action: PolicyAction::Pause {
                    policy_id: None,
                    target: None,
                },
            },
            "2026-11-25T10:00:00Z",
        ),
        record(
            4,
            DecisionKind::WidenPolicy {
                action: PolicyAction::Resume {
                    policy_id: None,
                    target: None,
                },
            },
            "2026-11-25T10:00:00Z",
        ),
        record(
            5,
            DecisionKind::ApplyProjection {
                operation: heimdall_contract::ids::OperationId::from_random_bytes([5; 16]),
                plan_digest: heimdall_contract::setup::PlanDigest::from_sha256([6; 32]),
                summary: ProjectionSummary {
                    intent: SummaryIntent::Apply,
                    added_aliases: Vec::new(),
                    changed_aliases: Vec::new(),
                    removed_aliases: Vec::new(),
                    files: Vec::new(),
                    git: true,
                    restore: Vec::new(),
                    diff_text: "+Host web\n".to_owned(),
                },
            },
            "2026-11-25T10:00:00Z",
        ),
    ];
    {
        let records = records.clone();
        let pol = pol.clone();
        store
            .transaction(move |tx| {
                for r in &records {
                    tx.insert_decision(r)?;
                }
                tx.put_decision_basis(
                    &records[2].id,
                    &DecisionBasis::Targeted {
                        policies: BTreeMap::new(),
                        lifts: Vec::new(),
                    },
                )?;
                tx.put_decision_basis(
                    &records[3].id,
                    &DecisionBasis::Targeted {
                        policies: BTreeMap::from([(pol.clone(), PolicyRevision(4))]),
                        lifts: vec![DeliveredLift {
                            scope_key: "all".to_owned(),
                            kind: "pause".to_owned(),
                            controller: ClientId::from_random_bytes([7; 16]),
                            revision: 2,
                            effect: EffectId::from_random_bytes([8; 16]),
                            delivered_at: "2026-11-25T07:00:00Z".parse().unwrap(),
                        }],
                    },
                )?;
                Ok(())
            })
            .unwrap();
    }
    let ops = ops_on(Arc::clone(&store)).await;
    let got = whole(&ops, &owner(), InspectSubject::Decisions).await;
    let now = t0();
    let legacy = store
        .transaction(|tx| {
            let mut out = Vec::new();
            for d in tx.pending_decisions()? {
                out.push(legacy_decision(tx, &d, now));
            }
            Ok(json!({ "decisions": out }))
        })
        .unwrap();
    assert_eq!(got, legacy);
    // The fixture reaches every inserted key.
    let items = got["decisions"].as_array().unwrap();
    assert_eq!(items.len(), records.len());
    assert!(items.iter().any(|d| d["expired"] == true));
    assert!(items.iter().any(|d| d["policies"] == json!([])));
    assert!(
        items
            .iter()
            .any(|d| d["policies"][0]["policy_id"] == json!(pol)
                && d["lifted_effects"][0]["kind"] == "pause")
    );
    assert!(items.iter().all(|d| d.get("reason").is_none()));
    assert_eq!(
        whole(&ops, &viewer(), InspectSubject::Decisions).await,
        json!({ "decisions": [] })
    );
}

/// A lapsed local widening's `reason` (set on the typed view) is the key the replaced
/// builder inserted.
#[test]
fn decision_reason_is_the_inserted_key() {
    let d = record(
        9,
        DecisionKind::ConfirmTime {
            boot_id: BootId("boot-9".to_owned()),
            observed_wall: t0(),
        },
        "2026-11-25T10:00:00Z",
    );
    let mut legacy = serde_json::to_value(decision_view(&d, t0())).unwrap();
    legacy.as_object_mut().unwrap().insert(
        "reason".to_owned(),
        json!(heimdall_contract::envelope::reason::APPROVAL_LAPSED),
    );
    let mut view = decision_view(&d, t0());
    view.reason = Some(heimdall_contract::envelope::reason::APPROVAL_LAPSED.to_owned());
    assert_eq!(serde_json::to_value(view).unwrap(), legacy);
}

/// The subjects typed elsewhere (`WithPreview<T>`): another role's empty answers are the
/// replaced literals, byte for byte.
#[tokio::test]
async fn with_preview_subjects_for_another_role_are_the_hand_built_literals() {
    let ops = ops_on(store()).await;
    for (subject, legacy) in [
        (InspectSubject::Enrollments, json!({ "enrollments": [] })),
        (InspectSubject::Connections, json!({ "connections": [] })),
        (InspectSubject::Policies, json!({ "items": [] })),
    ] {
        assert_eq!(whole(&ops, &viewer(), subject).await, legacy, "{subject:?}");
    }
}

// --- U3-3b: `inspect profiles` and `inspect destinations` (D9, PC3) -----------------------

/// A fake D8 wording source: one fixed report for every alias and policy.
struct FixedWording;

impl crate::operations::ConnectionWording for FixedWording {
    fn report(
        &self,
        _alias: &str,
        policy: &heimdall_contract::managed::ConnectionPolicy,
    ) -> Option<heimdall_contract::managed::ConnectionPolicyReport> {
        Some(heimdall_contract::managed::ConnectionPolicyReport {
            existing: policy.existing,
            multiplexing: policy.multiplexing,
            wording: "fixture wording".to_owned(),
        })
    }
}

/// The replaced `destination_view` (M02's catalog fields, M03's `preference`, M04's `jump`),
/// with `null` for an unset `label` and a managed destination's unset `port`.
fn legacy_destination(
    d: &heimdall_domain::catalog::DestinationRecord,
    preference: Option<&heimdall_domain::enrollment::PairPreference>,
) -> Value {
    use heimdall_domain::catalog::DestinationDefinition;
    let mut view = json!({
        "destination_id": d.id,
        "alias": d.alias,
        "revision": d.revision,
        "label": d.label,
        "updated_at": d.updated_at,
    });
    let map = view.as_object_mut().unwrap();
    match &d.definition {
        DestinationDefinition::Managed {
            hostname,
            port,
            account,
            identity,
            jump,
        } => {
            map.insert("definition".to_owned(), json!("managed"));
            map.insert("hostname".to_owned(), json!(hostname));
            map.insert("port".to_owned(), json!(port));
            map.insert("account".to_owned(), json!(account));
            map.insert("identity_id".to_owned(), json!(identity));
            if let Some(jump) = jump {
                map.insert("jump".to_owned(), json!(jump));
            }
            if let Some(p) = preference {
                map.insert(
                    "preference".to_owned(),
                    json!({"mechanism": p.mechanism, "projection": p.projection}),
                );
            }
        }
        DestinationDefinition::Observed => {
            map.insert("definition".to_owned(), json!("observed"));
        }
    }
    view
}

/// `doc` less its top-level keys `keys` that are `null` (the PC3 rows), checking each is.
fn without_nulls(mut doc: Value, keys: &[&str]) -> Value {
    let map = doc.as_object_mut().unwrap();
    for k in keys {
        if map.get(*k).is_some_and(Value::is_null) {
            map.remove(*k);
        }
    }
    doc
}

fn select_page_items(
    subject: InspectSubject,
    select: Option<heimdall_contract::page::Select>,
    page: Option<heimdall_contract::page::PageRequest>,
) -> InspectRequest {
    InspectRequest {
        subject,
        preview: None,
        cwd: None,
        redact: false,
        select,
        page,
    }
}

/// The whole read, a one-page read and a selection of every ID answer the same items.
async fn same_items_in_select_and_page(
    ops: &Operations,
    subject: InspectSubject,
    whole_items: &[Value],
    id: &str,
) {
    let page = ops
        .inspect(
            &owner(),
            select_page_items(
                subject,
                None,
                Some(heimdall_contract::page::PageRequest {
                    limit: None,
                    token: None,
                }),
            ),
        )
        .await
        .unwrap()
        .data;
    assert_eq!(
        page["items"].as_array().unwrap(),
        whole_items,
        "{subject:?}"
    );
    let ids: Vec<String> = whole_items
        .iter()
        .map(|i| i[id].as_str().unwrap().to_owned())
        .collect();
    let selected = ops
        .inspect(
            &owner(),
            select_page_items(
                subject,
                Some(heimdall_contract::page::Select {
                    ids,
                    aliases: Vec::new(),
                }),
                None,
            ),
        )
        .await
        .unwrap()
        .data;
    let mut got = selected["items"].as_array().unwrap().clone();
    got.sort_by(|a, b| a[id].as_str().cmp(&b[id].as_str()));
    assert_eq!(got, whole_items, "{subject:?}");
}

/// `inspect profiles`: a profile without a label has no `label` key (it was `null`); one
/// with a label, and every other key, are the replaced document's. The same items in a page
/// and a selection; another role reads `{"items": []}`.
#[tokio::test]
async fn profiles_view_omits_only_an_unset_label() {
    use heimdall_contract::ids::{AccountName, DestinationId, ProfileId};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{AccessPair, Capability, Scope};
    let store = store();
    let pair = |d: &str| AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    };
    let profiles = vec![
        ProfileDefinition {
            id: ProfileId::parse("dev").unwrap(),
            revision: 2,
            scope: Scope {
                pairs: [pair("web"), pair("git")].into_iter().collect(),
                capabilities: [Capability::GitSigning, Capability::SshAuthentication]
                    .into_iter()
                    .collect(),
            },
            label: None,
        },
        ProfileDefinition {
            id: ProfileId::parse("ops").unwrap(),
            revision: 1,
            scope: Scope::default(),
            label: Some("signing".to_owned()),
        },
    ];
    {
        let p = profiles.clone();
        store
            .transaction(move |tx| p.iter().try_for_each(|p| tx.upsert_profile(p)))
            .unwrap();
    }
    let ops = ops_on(store).await;
    let got = whole(&ops, &owner(), InspectSubject::Profiles).await;
    // The replaced arm's `json!`, less the PC3 row.
    let legacy: Vec<Value> = profiles
        .iter()
        .map(|p| {
            json!({
                "profile_id": p.id,
                "revision": p.revision,
                "label": p.label,
                "pairs": p.scope.pairs,
                "capabilities": p.scope.capabilities,
            })
        })
        .collect();
    let want: Vec<Value> = legacy
        .iter()
        .cloned()
        .map(|d| without_nulls(d, &["label"]))
        .collect();
    assert_eq!(got, json!({ "items": want }));
    let items = got["items"].as_array().unwrap();
    assert!(items[0].get("label").is_none(), "{got}");
    assert_eq!(items[1], legacy[1], "a set label is unchanged");
    same_items_in_select_and_page(&ops, InspectSubject::Profiles, items, "profile_id").await;
    assert_eq!(
        whole(&ops, &viewer(), InspectSubject::Profiles).await,
        json!({ "items": [] })
    );
}

/// `inspect destinations`: an unset `label`, and a managed destination's unset `port`, are
/// omitted keys (they were `null`); a set label and port, `jump`, `preference` (with the
/// wired wording's `connection_policy`) and an observed destination's keys are the replaced
/// document's. No `route_health`/`host_pin_defeated` here: the dispatcher adds them (D11).
/// The same items in a page and a selection; another role reads `{"items": []}`.
#[tokio::test]
async fn destinations_view_omits_only_an_unset_label_and_port() {
    use heimdall_contract::ids::{AccountName, DestinationId, IdentityId, ProfileId};
    use heimdall_contract::managed::{
        ConnectionPolicy, ExistingConnectionsMode, MultiplexingMode, PreferredMechanism,
    };
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
    use heimdall_domain::enrollment::{PairPreference, ProjectionStatus};
    use heimdall_domain::policy::{PauseState, PolicySource, StandingPolicy};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{AccessPair, Capability, Scope};
    let store = store();
    let deploy = AccountName::parse("deploy").unwrap();
    let identity = IdentityId::from_random_bytes([4; 16]);
    let managed =
        |id: &str, port: Option<u16>, label: Option<&str>, jump: Option<&str>| DestinationRecord {
            id: DestinationId::parse(id).unwrap(),
            alias: format!("alias-{id}"),
            revision: 3,
            definition: DestinationDefinition::Managed {
                hostname: format!("{id}.example.invalid"),
                port,
                account: deploy.clone(),
                identity: identity.clone(),
                jump: jump.map(|j| DestinationId::parse(j).unwrap()),
            },
            label: label.map(str::to_owned),
            updated_at: t0(),
        };
    let destinations = vec![
        // Managed, no label, no port, a pending preference.
        managed("dst-a", None, None, None),
        // Managed, a label, a port and a jump, an applied managed preference in a policy.
        managed("dst-b", Some(2222), Some("web tier"), Some("dst-a")),
        // Observed, no label.
        DestinationRecord {
            id: DestinationId::parse("dst-c").unwrap(),
            alias: "alias-dst-c".to_owned(),
            revision: 1,
            definition: DestinationDefinition::Observed,
            label: None,
            updated_at: t0(),
        },
        // Observed, a label.
        DestinationRecord {
            id: DestinationId::parse("dst-d").unwrap(),
            alias: "alias-dst-d".to_owned(),
            revision: 1,
            definition: DestinationDefinition::Observed,
            label: Some("seen".to_owned()),
            updated_at: t0(),
        },
    ];
    let pair = |d: &str| AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: deploy.clone(),
    };
    let preferences = [
        PairPreference {
            destination: pair("dst-a").destination,
            account: deploy.clone(),
            mechanism: PreferredMechanism::Existing,
            projection: ProjectionStatus::Pending,
            issuing_cas: std::collections::BTreeSet::new(),
        },
        PairPreference {
            destination: pair("dst-b").destination,
            account: deploy.clone(),
            mechanism: PreferredMechanism::ManagedCertificate,
            projection: ProjectionStatus::Applied { generation: 4 },
            issuing_cas: std::collections::BTreeSet::new(),
        },
    ];
    let scope = Scope {
        pairs: [pair("dst-b")].into_iter().collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    };
    let policy = ConnectionPolicy {
        existing: ExistingConnectionsMode::Strict,
        multiplexing: MultiplexingMode::Disabled,
    };
    {
        let (d, prefs, scope) = (destinations.clone(), preferences.clone(), scope.clone());
        store
            .transaction(move |tx| {
                for d in &d {
                    tx.upsert_destination(d)?;
                }
                for p in &prefs {
                    tx.set_pair_preference(p, t0())?;
                }
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse("dev").unwrap(),
                    revision: 1,
                    scope: scope.clone(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("pol").unwrap(),
                        revision: PolicyRevision(1),
                        profile: ProfileId::parse("dev").unwrap(),
                        workspace: None,
                        scope,
                        environments: [env_id()].into_iter().collect(),
                        max_window: Duration::from_secs(3600),
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: Default::default(),
                        connection: policy,
                        default: false,
                    },
                    false,
                )
            })
            .unwrap();
    }
    let ops = ops_on(store).await;
    ops.set_connection_wording(Arc::new(FixedWording));
    let got = whole(&ops, &owner(), InspectSubject::Destinations).await;
    // The replaced builder, then `add_connection_policies` (dst-b: covered, managed).
    let mut legacy: Vec<Value> = destinations
        .iter()
        .map(|d| {
            let p = preferences.iter().find(|p| p.destination == d.id);
            legacy_destination(d, p)
        })
        .collect();
    legacy[1]["preference"]["connection_policy"] = json!({
        "existing": "strict",
        "multiplexing": "disabled",
        "wording": "fixture wording",
    });
    assert!(legacy[0]["label"].is_null() && legacy[0]["port"].is_null());
    let want: Vec<Value> = legacy
        .iter()
        .cloned()
        .map(|d| without_nulls(d, &["label", "port"]))
        .collect();
    assert_eq!(got, json!({ "items": want }));
    let items = got["items"].as_array().unwrap();
    assert!(items[0].get("label").is_none() && items[0].get("port").is_none());
    assert!(items[2].get("label").is_none() && items[2].get("port").is_none());
    assert_eq!(
        items[1], legacy[1],
        "set label, port, jump and preference: unchanged"
    );
    assert_eq!(
        items[3], legacy[3],
        "an observed destination's label: unchanged"
    );
    for i in items {
        assert!(i.get("route_health").is_none() && i.get("host_pin_defeated").is_none());
    }
    same_items_in_select_and_page(&ops, InspectSubject::Destinations, items, "destination_id")
        .await;
    assert_eq!(
        whole(&ops, &viewer(), InspectSubject::Destinations).await,
        json!({ "items": [] })
    );
}
