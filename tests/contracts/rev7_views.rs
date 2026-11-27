//! ⟨rev7⟩ ADR-0013 revision 7, unit U0: the typed read views (D1) and their omitted-versus-
//! `null` forms (D9), against today's documents.
//!
//! For each view, documents of **today's** shape (from a golden, an example or a test
//! assertion where one exists, otherwise from the builder, cited at each document) must:
//! read into the view; validate against its `view_schemas()` schema; tolerate an unknown
//! key; and re-serialize dropping exactly the fields the inventory
//! (`tests/contracts/golden/views-null-inventory.md`) marks as PC3 changes, each `null`
//! today, and nothing else. The revision-7 form then round-trips exactly and validates.
//! The revision-7 fields declared but not emitted yet read and round-trip too.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use heimdall_contract::schema::public_schemas;
use heimdall_contract::views::access::{
    BindingListView, DecisionKindName, DecisionListView, GrantListView,
};
use heimdall_contract::views::catalog::{
    DestinationListView, IdentityListView, PairProjectionStatus, ProfileListView,
    ProjectionListView,
};
use heimdall_contract::views::environment::{
    EnvironmentListView, EnvironmentStatusView, GrantResidual,
};
use heimdall_contract::views::operations::{OperationListView, OperationView};
use heimdall_contract::views::status::{CapabilitiesView, ServiceStatusView, StatusView};
use heimdall_contract::views::stream::{StreamLine, SubscriptionHeadView};
use heimdall_contract::views::{PreviewView, view_schemas};

use crate::jsonschema_lite::validate;
use crate::{assert_clean, repo_root};

const INVENTORY: &str = "tests/contracts/golden/views-null-inventory.md";

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|e| panic!("{path} unreadable: {}", e.kind()));
    assert_clean(path, &text);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn view_schema(name: &str) -> Value {
    let doc = view_schemas()
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no view schema {name}"));
    serde_json::to_value(&doc.schema).unwrap()
}

/// Remove the value at JSON pointer `ptr` from `v`, returning it.
fn remove(v: &mut Value, ptr: &str) -> Value {
    let (parent, key) = ptr.rsplit_once('/').unwrap();
    let holder = v
        .pointer_mut(parent)
        .unwrap_or_else(|| panic!("{ptr}: no parent"));
    holder
        .as_object_mut()
        .unwrap_or_else(|| panic!("{ptr}: parent is not an object"))
        .remove(key)
        .unwrap_or_else(|| panic!("{ptr}: absent"))
}

/// `doc`, of today's shape, against view `T` and its schema `name`. `pc3` lists the JSON
/// pointers of the fields the inventory marks as PC3 changes: each is `null` today and is
/// the only thing re-serialization drops. Returns the typed view.
fn today<T: Serialize + DeserializeOwned>(what: &str, name: &str, doc: &Value, pc3: &[&str]) -> T {
    let text = doc.to_string();
    assert_clean(what, &text);
    let schema = view_schema(name);
    if let Err(e) = validate(&schema, doc) {
        panic!("{what}: today's document against {name}: {e:?}");
    }
    let typed: T = serde_json::from_value(doc.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
    let mut rev7 = doc.clone();
    for ptr in pc3 {
        let gone = remove(&mut rev7, ptr);
        assert!(
            gone.is_null(),
            "{what}: PC3 field {ptr} is {gone}, not null, today"
        );
    }
    let out = serde_json::to_value(&typed).unwrap();
    assert_eq!(
        out, rev7,
        "{what}: re-serialization drops exactly the PC3 fields"
    );
    if let Err(e) = validate(&schema, &out) {
        panic!("{what}: revision-7 form against {name}: {e:?}");
    }
    let again: T = serde_json::from_value(out.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&again).unwrap(),
        out,
        "{what}: revision-7 round trip"
    );
    // Unknown non-critical keys are tolerated (ADR-0006 §9).
    if let Value::Object(map) = doc {
        let mut extra = map.clone();
        extra.insert("x_rev8_field".to_owned(), json!({"any": [1, "two"]}));
        serde_json::from_value::<T>(Value::Object(extra))
            .unwrap_or_else(|e| panic!("{what}: an unknown key is refused: {e}"));
    }
    typed
}

/// A revision-7 document (declared fields included) reads and round-trips exactly.
fn exact<T: Serialize + DeserializeOwned>(what: &str, name: &str, doc: &Value) -> T {
    today(what, name, doc, &[])
}

#[test]
fn view_schemas_are_objects_unique_and_disjoint_from_the_public_ones() {
    let views = view_schemas();
    let mut names: Vec<&str> = views.iter().map(|s| s.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), views.len(), "view schema names are unique");
    let public: Vec<&str> = public_schemas().iter().map(|s| s.name).collect();
    for s in &views {
        assert!(
            !public.contains(&s.name),
            "{} is already a public schema",
            s.name
        );
        let v = serde_json::to_value(&s.schema).unwrap();
        assert!(v.is_object(), "{} is not an object schema", s.name);
        assert_clean(s.name, &v.to_string());
    }
    for name in [
        "inspect-capabilities",
        "inspect-profiles",
        "inspect-destinations",
        "inspect-bindings",
        "inspect-grants",
        "inspect-operations",
        "inspect-decisions",
        "inspect-identities",
        "inspect-projections",
        "status",
        "service-status",
        "operation",
        "subscription-head",
        "stream-line",
        "environment-status",
        "grant-residual",
    ] {
        assert!(names.contains(&name), "no view schema {name}");
    }
}

/// Every view schema has its table in the inventory, and the inventory names no other.
#[test]
fn every_view_has_its_inventory_table() {
    let text = std::fs::read_to_string(repo_root().join(INVENTORY)).unwrap();
    assert_clean(INVENTORY, &text);
    let tables: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("## `"))
        .filter_map(|l| l.split('`').next())
        .collect();
    let mut want: Vec<&str> = view_schemas().iter().map(|s| s.name).collect();
    let mut got = tables.clone();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, want, "inventory tables and view schemas");
}

// --- inspect capabilities ----------------------------------------------------------------

/// Builder: `crates/app/src/operations.rs` `inspect` (`InspectSubject::Capabilities`), with
/// `add_capabilities_lock` (`operations/lock_connection_m03.rs`) and
/// `add_capabilities_login` (`operations/login_entry_m04.rs`). The repository's only
/// example, `schemas/examples/envelope.success.read.json`, predates `codes` and
/// `schema_version` and does not read as today's data.
#[test]
fn inspect_capabilities_today() {
    use heimdall_contract::ipc::capability;
    let schemas: Vec<&str> = public_schemas().iter().map(|s| s.name).collect();
    let doc = json!({
        "capabilities": [
            capability::OPERATIONS_V1, capability::EVENTS_V1, capability::OWNER_POLICY_V1,
            capability::SCHEMA_DISCOVERY_V1, capability::SERVICE_CONTROL_V1,
            capability::SETUP_V1, capability::ISSUER_V1, capability::ENROLLMENT_V1,
            capability::MANAGED_CREDENTIALS_V1, capability::CONNECTIONS_V1,
            capability::ENVIRONMENTS_V1, capability::TRUSTED_WORK_V1,
            capability::REQUEST_EPOCH_V1,
        ],
        "schemas": schemas,
        "codes": heimdall_contract::schema::code_table()["codes"].clone(),
        "schema_version": "1",
        "lock": {
            "behavior": "continue",
            "disclosure": "Locking this desktop does not end managed access.",
            "acknowledged_at": "2026-11-20T09:00:00Z"
        },
        "login_start": {"kind": "launch_agent", "installed": false}
    });
    let v: CapabilitiesView = today("inspect capabilities", "inspect-capabilities", &doc, &[]);
    assert_eq!(v.codes.len(), heimdall_contract::code::Code::all().len());
    // The lock disclosure unreadable: the key is absent, as today.
    let mut bare = doc.clone();
    remove(&mut bare, "/lock");
    remove(&mut bare, "/login_start");
    today::<CapabilitiesView>(
        "capabilities without lock",
        "inspect-capabilities",
        &bare,
        &[],
    );
}

// --- inspect environments ----------------------------------------------------------------

/// Builder: `operations.rs` `inspect` (`InspectSubject::Environments`): M01's keys for
/// every role; the owner's `items` are `schemas/examples/inspect.environments.json`'s.
#[test]
fn inspect_environments_today() {
    let items = load("schemas/examples/inspect.environments.json")["items"].clone();
    let owner = json!({
        "environment_id": "env_01010101010101010101010101010101",
        "enrolled": true,
        "environments": [{
            "id": "env_01010101010101010101010101010101",
            "device": "dev_02020202020202020202020202020202",
            "kind": "native_session",
            "label": null,
            "permissions": {
                "automatic_activation": false,
                "managed_signing": true,
                "issuer_access": true
            }
        }],
        "items": items
    });
    let v: EnvironmentListView = today(
        "inspect environments (owner)",
        "inspect-environments.full",
        &owner,
        &["/environments/0/label"],
    );
    assert_eq!(v.items.as_ref().map(Vec::len), Some(3));
    // Another role: M01's keys alone (also the runner's view in `environment status`).
    let other = json!({
        "environment_id": "env_01010101010101010101010101010101",
        "enrolled": false,
        "environments": []
    });
    let v: EnvironmentListView = today(
        "inspect environments (viewer)",
        "inspect-environments.full",
        &other,
        &[],
    );
    assert!(v.items.is_none());
}

// --- catalog subjects --------------------------------------------------------------------

/// Builder: `operations.rs` `inspect` (`InspectSubject::Profiles`). The TUI's tolerant
/// reader test (`crates/heimdall/src/tui/data.rs` `catalog_listings_parse_tolerantly`)
/// shows a partial item.
#[test]
fn inspect_profiles_today() {
    let doc = json!({"items": [
        {
            "profile_id": "dev",
            "revision": 2,
            "label": null,
            "pairs": [{"destination": "web", "account": "deploy"}],
            "capabilities": ["ssh-authentication"]
        },
        {
            "profile_id": "release",
            "revision": 1,
            "label": "signing",
            "pairs": [
                {"destination": "git", "account": "git"},
                {"destination": "web", "account": "deploy"}
            ],
            "capabilities": ["ssh-authentication", "git-signing"]
        }
    ]});
    today::<ProfileListView>(
        "inspect profiles",
        "inspect-profiles",
        &doc,
        &["/items/0/label"],
    );
    today::<ProfileListView>(
        "inspect profiles (not owner)",
        "inspect-profiles",
        &json!({"items": []}),
        &[],
    );
}

/// Builder: `operations.rs` `destination_view` and `destinations_view` (with
/// `add_connection_policies`), then `crates/runtime/src/dispatch.rs` `add_route_health`.
#[test]
fn inspect_destinations_today() {
    let doc = json!({"items": [
        {
            "destination_id": "git",
            "alias": "git",
            "revision": 3,
            "label": null,
            "updated_at": "2026-11-20T09:00:00Z",
            "definition": "managed",
            "hostname": "git.example.test",
            "port": null,
            "account": "git",
            "identity_id": "idn_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
        },
        {
            "destination_id": "lab",
            "alias": "lab",
            "revision": 1,
            "label": null,
            "updated_at": "2026-11-20T09:00:00Z",
            "definition": "observed"
        },
        {
            "destination_id": "web",
            "alias": "web",
            "revision": 5,
            "label": "web tier",
            "updated_at": "2026-11-21T09:00:00Z",
            "definition": "managed",
            "hostname": "192.0.2.10",
            "port": 2222,
            "account": "deploy",
            "identity_id": "idn_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "jump": "bastion",
            "preference": {
                "mechanism": "managed_certificate",
                "projection": {"state": "applied", "generation": 4},
                "connection_policy": {
                    "existing": "strict",
                    "multiplexing": "disabled",
                    "wording": "Dedicated connections close at the deadline."
                }
            },
            "route_health": {
                "result": {
                    "kind": "failed_over",
                    "destination": "web",
                    "account": "deploy",
                    "attempts": [
                        {"route": "route_0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                         "failure": "timeout", "duration_ms": 5000},
                        {"route": "route_0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "duration_ms": 120}
                    ],
                    "final_route": "route_0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
                },
                "reported_at": "2026-11-22T10:00:00Z"
            },
            "host_pin_defeated": {
                "setting": "userknownhostsfile",
                "reported_at": "2026-11-22T10:00:00Z"
            }
        }
    ]});
    let v: DestinationListView = today(
        "inspect destinations",
        "inspect-destinations",
        &doc,
        &["/items/0/label", "/items/0/port", "/items/1/label"],
    );
    let web = &v.items[2];
    assert_eq!(
        web.preference.as_ref().map(|p| p.projection),
        Some(PairProjectionStatus::Applied { generation: 4 })
    );
    assert!(web.route_health.is_some() && web.host_pin_defeated.is_some());
}

/// Builder: `operations.rs` `identity_view`; the key set is
/// `tests/model/operations.rs` `FRESH_KEYS`' identity part.
#[test]
fn inspect_identities_today() {
    let endpoint = json!({"kind": "unix_socket", "locator": "/run/user/1000/agent.sock"});
    let doc = json!({"identities": [
        {
            "identity_id": "idn_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "revision": 2,
            "fingerprint": "SHA256:uXq3mT1n0rWbG5cVxZ2yA7kL9pQeJ4sHdF8oN6iRtC0",
            "key_type": "ssh-ed25519",
            "mechanism": "native_agent",
            "endpoint": endpoint,
            "label": null,
            "interaction": "none",
            "interaction_basis": "declared",
            "declared_at": "2026-11-20T09:00:00Z",
            "declaration": {"revision": 3, "endpoint": endpoint, "expires_at": "2026-12-20T09:00:00Z"},
            "noninteractive": {"eligible": true},
            "eligibility_checked_at": "2026-11-22T10:00:00Z"
        },
        {
            "identity_id": "idn_0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
            "revision": 1,
            "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "key_type": "ssh-ed25519",
            "mechanism": "native_agent",
            "endpoint": null,
            "label": "file key",
            "interaction": "unknown",
            "interaction_basis": "inferred",
            "declared_at": null,
            "declaration": null,
            "noninteractive": {"eligible": false, "reason": "interaction_unknown"},
            "eligibility_checked_at": "2026-11-22T10:00:00Z"
        }
    ]});
    today::<IdentityListView>(
        "inspect identities",
        "inspect-identities",
        &doc,
        &[
            "/identities/0/label",
            "/identities/1/endpoint",
            "/identities/1/declared_at",
            "/identities/1/declaration",
        ],
    );
}

/// Builder: `operations.rs` `inspect` (`InspectSubject::Projections`): the domain
/// `ManagedResource` and `ProjectionRecord` as serialized today. The TUI's tolerant reader
/// test reads `record.items.ssh.generation`.
#[test]
fn inspect_projections_today() {
    let doc = json!({
        "projections": [
            {
                "id": "res_0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
                "kind": "config_projection",
                "owner": {"kind": "projection", "environment": "env_01010101010101010101010101010101"},
                "generation": 3,
                "desired": "present",
                "observed": "present",
                "last_operation": "op_00112233445566778899aabbccddeeff",
                "locator": "{\"path\":\"/home/u/.ssh/heimdall/config\",\"role\":\"managed_ssh\"}",
                "updated_at": "2026-11-20T09:00:00Z"
            },
            {
                "id": "res_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
                "kind": "config_projection",
                "owner": {"kind": "projection", "environment": "env_01010101010101010101010101010101"},
                "generation": 1,
                "desired": "absent",
                "observed": "unknown",
                "last_operation": null,
                "locator": "{\"path\":\"/home/u/.ssh/heimdall/k.pub\",\"role\":\"key\"}",
                "updated_at": "2026-11-20T09:00:00Z"
            }
        ],
        "record": {
            "environment": "env_01010101010101010101010101010101",
            "items": {
                "ssh": {
                    "generation": 3,
                    "files": [{
                        "role": "managed_ssh",
                        "path": "/home/u/.ssh/heimdall/config",
                        "identity": {"platform": "unix", "dev": 1, "ino": 2},
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                    }],
                    "aliases": ["web"],
                    "operation": "op_00112233445566778899aabbccddeeff",
                    "committed_at": "2026-11-20T09:00:00Z"
                },
                "git": {
                    "generation": 1,
                    "files": [],
                    "aliases": [],
                    "include_file": "/home/u/.gitconfig",
                    "operation": "op_00112233445566778899aabbccddeeff",
                    "committed_at": "2026-11-20T09:00:00Z"
                }
            }
        }
    });
    today::<ProjectionListView>(
        "inspect projections",
        "inspect-projections",
        &doc,
        &["/projections/1/last_operation"],
    );
    // Nothing committed yet, and any other role (`operations.rs`: `"record": null`).
    let v: ProjectionListView = today(
        "inspect projections (none)",
        "inspect-projections",
        &json!({"projections": [], "record": null}),
        &["/record"],
    );
    assert!(v.record.is_none());
}

// --- access subjects ---------------------------------------------------------------------

/// Builder: `operations.rs` `inspect` (`InspectSubject::Grants`); the remote keys as
/// `tests/model/operations.rs` asserts them (`remote_retries.attempts`, `.stopped`,
/// `cleanup_pending`).
#[test]
fn inspect_grants_today() {
    let scope = json!({
        "pairs": [{"destination": "web", "account": "deploy"}],
        "capabilities": ["ssh-authentication"]
    });
    let doc = json!({"grants": [
        {
            "grant_id": "grant_10101010101010101010101010101010",
            "state": "active",
            "expires_at": "2026-11-22T18:00:00Z",
            "parent": null,
            "scope": scope
        },
        {
            "grant_id": "grant_20202020202020202020202020202020",
            "state": "revoked",
            "expires_at": "2026-11-22T18:00:00Z",
            "parent": "grant_10101010101010101010101010101010",
            "scope": scope,
            "remote_pending": true,
            "remote_pending_reasons": ["adapter_unavailable"],
            "remote_retries": {
                "attempts": 8,
                "last_attempt_at": "2026-11-22T11:00:00Z",
                "stopped": true
            },
            "cleanup_pending": true
        },
        {
            "grant_id": "grant_30303030303030303030303030303030",
            "state": "degraded",
            "expires_at": "2026-11-22T18:00:00Z",
            "parent": null,
            "scope": scope,
            "degraded_reason": "issuer_unavailable"
        }
    ]});
    today::<GrantListView>(
        "inspect grants",
        "inspect-grants",
        &doc,
        &["/grants/0/parent", "/grants/2/parent"],
    );
}

/// Builder: `operations.rs` `inspect` (`InspectSubject::Bindings`).
#[test]
fn inspect_bindings_today() {
    let doc = json!({"bindings": [{
        "binding_id": "binding_40404040404040404040404040404040",
        "grant_id": "grant_10101010101010101010101010101010",
        "work_id": "build-42",
        "profile": "dev",
        "profile_revision": 2,
        "state": "active",
        "created_at": "2026-11-22T10:00:00Z"
    }]});
    today::<BindingListView>("inspect bindings", "inspect-bindings", &doc, &[]);
}

/// Every view `tests/contracts/golden/rev6-5-decisions.golden.json` holds (`views`,
/// `lift_views`); plus, from `operations.rs` `decision_view` and `lapse_local_widening`,
/// an `approve_authority` record and a lapsed local widening.
#[test]
fn inspect_decisions_today() {
    let golden = load("tests/contracts/golden/rev6-5-decisions.golden.json");
    let mut decisions: Vec<Value> = golden["views"]
        .as_array()
        .unwrap()
        .iter()
        .chain(golden["lift_views"].as_array().unwrap())
        .map(|v| v["json"].clone())
        .collect();
    assert_eq!(decisions.len(), 4);
    decisions.push(json!({
        "decision_id": "dec_50505050505050505050505050505050",
        "kind": "approve_authority",
        "state": "pending",
        "created_at": "2026-11-22T10:00:00Z",
        "expires_at": "2026-11-22T10:10:00Z",
        "expired": false,
        "request": {
            "operation_id": "op_00112233445566778899aabbccddeeff",
            "delta": {
                "added_scope": {
                    "pairs": [{"destination": "web", "account": "deploy"}],
                    "capabilities": []
                },
                "extra_window": null,
                "environment_not_covered": false
            }
        }
    }));
    let mut lapsed = decisions[1].clone();
    lapsed["state"] = json!("expired");
    lapsed["expired"] = json!(true);
    lapsed["reason"] = json!("approval_lapsed");
    decisions.push(lapsed);
    // A recorded request's `null` (here `delta.extra_window`) is persisted content: kept.
    let v: DecisionListView = today(
        "inspect decisions",
        "inspect-decisions",
        &json!({"decisions": decisions}),
        &[],
    );
    assert_eq!(v.decisions[0].kind, DecisionKindName::RemoteWidening);
    assert_eq!(v.decisions[3].policies.as_ref().map(Vec::len), Some(1));
    assert_eq!(v.decisions[2].policies.as_ref().map(Vec::len), Some(0));
    assert_eq!(v.decisions[2].lifted_effects.len(), 1);
}

// --- operations ----------------------------------------------------------------------------

fn running_ensure() -> Value {
    json!({
        "operation_id": "op_60606060606060606060606060606060",
        "kind": "ensure",
        "state": "running",
        "code": null,
        "effect_status": "none",
        "created_at": "2026-11-22T10:00:00Z",
        "updated_at": "2026-11-22T10:00:01Z",
        "cancellation": {"requested_at": "2026-11-22T10:00:02Z", "may_have_external_effect": false},
        "result": null
    })
}

fn held_setup() -> Value {
    json!({
        "operation_id": "op_70707070707070707070707070707070",
        "kind": "setup.apply",
        "state": "outcome_unknown",
        "code": "OUTCOME_UNKNOWN",
        "effect_status": "unknown",
        "created_at": "2026-11-22T09:00:00Z",
        "updated_at": "2026-11-22T09:00:05Z",
        "cancellation": null,
        "result": {"error": {"code": "OUTCOME_UNKNOWN", "reason": "projection_held"}}
    })
}

/// Builder: `operations.rs` `operation_view` and `observed_view` (`observe` operation).
/// No full-shape golden exists; `tests/e2e/cli_m01.rs` asserts the envelope's `state`.
#[test]
fn operation_today() {
    today::<OperationView>(
        "operation (running)",
        "operation",
        &running_ensure(),
        &["/code", "/result"],
    );
    today::<OperationView>(
        "operation (held)",
        "operation",
        &held_setup(),
        &["/cancellation"],
    );
    // `observe` withholds a foreign binding's unreadable result as `null` today.
    let mut withheld = running_ensure();
    withheld["state"] = json!("succeeded");
    withheld["code"] = json!("ACCESS_READY");
    withheld["effect_status"] = json!("applied");
    withheld["cancellation"] = Value::Null;
    today::<OperationView>(
        "operation (withheld result)",
        "operation",
        &withheld,
        &["/cancellation", "/result"],
    );
}

/// Builder: `operations.rs` `inspect` (`InspectSubject::Operations`).
#[test]
fn inspect_operations_today() {
    let doc = json!({
        "operations": [running_ensure(), held_setup()],
        "counts": [
            {"state": "outcome_unknown", "count": 1},
            {"state": "running", "count": 1},
            {"state": "succeeded", "count": 7}
        ]
    });
    today::<OperationListView>(
        "inspect operations",
        "inspect-operations",
        &doc,
        &[
            "/operations/0/code",
            "/operations/0/result",
            "/operations/1/cancellation",
        ],
    );
}

/// `inspect --preview` adds `preview` to the subject's data (`operations.rs` `preview`).
#[test]
fn inspect_preview_today() {
    let snapshot = json!({
        "profile": "dev",
        "profile_revision": 2,
        "requested": {
            "pairs": [{"destination": "web", "account": "deploy"}],
            "capabilities": ["ssh-authentication"]
        },
        "deadline": "2026-11-22T18:00:00Z",
        "mechanism": null
    });
    let doc = json!({
        "bindings": [],
        "preview": {
            "outcome": "approval_required",
            "snapshot": snapshot,
            "covered": null,
            "delta": {
                "added_scope": {
                    "pairs": [{"destination": "web", "account": "deploy"}],
                    "capabilities": ["ssh-authentication"]
                },
                "extra_window": null,
                "environment_not_covered": false
            }
        }
    });
    let v: BindingListView = today(
        "inspect bindings --preview",
        "inspect-bindings",
        &doc,
        &["/preview/snapshot/mechanism", "/preview/covered"],
    );
    assert!(matches!(
        v.preview,
        Some(PreviewView::ApprovalRequired { .. })
    ));
    let denied = json!({"grants": [], "preview": {
        "outcome": "denied", "code": "POLICY_PAUSED", "message": "the policy is paused"
    }});
    today::<GrantListView>("inspect grants --preview", "inspect-grants", &denied, &[]);
}

// --- status ----------------------------------------------------------------------------------

/// `tests/e2e/cli_m07.rs` (`prior_shape`, "JSON status retains its existing shape"):
/// `crates/heimdall/src/cli.rs` `status`; the chores from `doctor_cmd.rs` `add_chores`.
#[test]
fn status_today() {
    let doc = json!({
        "running": true,
        "environment_id": "env_01010101010101010101010101010101",
        "operation_counts": [{"state": "succeeded", "count": 3}],
        "open_operations": 0,
        "pending_decisions": 2
    });
    today::<StatusView>("status", "status", &doc, &[]);
    let mut chores = doc.clone();
    chores["chores"] = json!([{
        "chore": "time_confirmation_after_reboot",
        "command": "heimdall time confirm",
        "message": "confirm the time after the reboot"
    }]);
    today::<StatusView>("status with a chore", "status", &chores, &[]);
}

/// Builder: `crates/heimdall/src/service_cmd.rs` `status` and `time_sync_observation`. No
/// golden exists; `tests/native/m08/lifecycle/journey.sh` reads `data.pid` and
/// `data.environment_id`.
#[test]
fn service_status_today() {
    let doc = json!({
        "running": true,
        "pid": 4242,
        "version": "0.7.0",
        "environment_id": "env_01010101010101010101010101010101",
        "capabilities": ["events/1", "operations/1", "schema-discovery/1"],
        "principal": {"kind": "os_user_unix", "uid": 1000},
        "time_sync_observation": {
            "interface": "ntp_adjtime",
            "reading": "synchronized",
            "used_by_time_gate": false,
            "max_error_us": 1200,
            "sta_unsync": false
        }
    });
    today::<ServiceStatusView>("service status", "service-status", &doc, &[]);
    let mut windows = doc.clone();
    windows["principal"] = json!({"kind": "os_user_windows", "sid": "S-1-5-21-0-0-0-1001"});
    windows["time_sync_observation"] =
        json!({"interface": "none", "reading": "no_interface", "used_by_time_gate": false});
    today::<ServiceStatusView>("service status (windows)", "service-status", &windows, &[]);
    // Revision 7 (D12), declared: the endpoint and the protocol from the verified hello.
    let mut rev7 = doc;
    rev7["control_endpoint"] = json!("/run/user/1000/heimdall/control.sock");
    rev7["protocol"] = json!(1);
    let v: ServiceStatusView = exact("service status (revision 7)", "service-status", &rev7);
    assert_eq!(v.protocol, Some(1));
}

// --- the event stream ----------------------------------------------------------------------

/// `crates/heimdall/src/cli.rs` `operation events --follow`'s head (`tests/e2e/cli_m01.rs`
/// asserts `data.cursor`, and `data.snapshot` `null` on a resume); a cursorless start's
/// snapshot as `crates/app/src/events.rs` `snapshot_data` builds it (⟨PC1⟩ the typed
/// `event-snapshot`: sections follow the filter, `code` omitted before it is terminal, no
/// `boundary_seq`).
#[test]
fn subscription_head_today() {
    let resume = json!({"subscription": 7, "cursor": "AQEBAAAAAAAB", "snapshot": null});
    today::<SubscriptionHeadView>(
        "head (resume)",
        "subscription-head",
        &resume,
        &["/snapshot"],
    );
    let fresh = json!({
        "subscription": 8,
        "cursor": "AQEBAAAAAAAC",
        "snapshot": {
            "data": {
                "environment_id": "env_01010101010101010101010101010101",
                "authority_generation": 4,
                "operations": [{
                    "operation_id": "op_60606060606060606060606060606060",
                    "kind": "ensure",
                    "state": "running",
                    "effect_status": "none",
                    "updated_at": "2026-11-22T10:00:01Z"
                }],
                "pending_decisions": []
            },
            "cursor": "AQEBAAAAAAAC",
            "taken_at": "2026-11-22T10:00:02Z"
        }
    });
    // ⟨PC1⟩ The snapshot's own `data` is the typed `event-snapshot`, exactly.
    exact::<SubscriptionHeadView>("head (snapshot)", "subscription-head", &fresh);
    // Revision 7 (D6), declared: the exact backlog count and the restart reason.
    let rev7 = json!({"subscription": 9, "cursor": "AQEBAAAAAAAD", "backlog": 3});
    exact::<SubscriptionHeadView>("head (revision 7 backlog)", "subscription-head", &rev7);
    let mut restarted = fresh;
    restarted["resync_reason"] = json!("backlog_too_long");
    exact::<SubscriptionHeadView>("head (revision 7 restart)", "subscription-head", &restarted);
}

/// The lines after the head: `schemas/examples/event.operation-state-changed.json`; a
/// stream-ending `resync_required` (`crates/ipc/src/session.rs`, ADR-0006 §8 r2.1); and
/// the terminal error envelope (`schemas/examples/envelope.error.unavailable.json`).
#[test]
fn stream_lines_today() {
    let event = load("schemas/examples/event.operation-state-changed.json");
    let line: StreamLine = today("event line", "stream-line", &event, &[]);
    assert!(matches!(line, StreamLine::Event(_)));
    let mut ended = event.clone();
    ended["type"] = json!("resync_required");
    ended.as_object_mut().unwrap().remove("operation_id");
    ended.as_object_mut().unwrap().remove("resource");
    ended["payload"] = json!({"reason": "event_too_large", "subscription_ended": true});
    let line: StreamLine = today("ending event line", "stream-line", &ended, &[]);
    assert!(matches!(line, StreamLine::Event(_)));
    let error = load("schemas/examples/envelope.error.unavailable.json");
    let line: StreamLine = today("terminal error line", "stream-line", &error, &[]);
    assert!(matches!(line, StreamLine::Error(_)));
}

// --- environment status ----------------------------------------------------------------------

/// The pin as `tests/contracts/golden/rev6-requests.golden.json` records it
/// (`controller_record put_environment`).
fn pin_record() -> Value {
    load("tests/contracts/golden/rev6-requests.golden.json")["no_capability_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["json"]["action"] == "put_environment")
        .map(|r| r["json"]["record"].clone())
        .unwrap()
}

fn pending_residual() -> Value {
    json!({
        "grant": "grant_10101010101010101010101010101010",
        "acknowledged": false,
        "new_authentication": {
            "latest_possible_credential_expiry": "2026-11-22T18:00:00Z",
            "destination_clock_error": "unmeasured"
        },
        "statement": "until 2026-11-22T18:00:00Z (valid_before) plus an unmeasured \
                      destination-clock error"
    })
}

/// Builder: `crates/heimdall/src/m06_cmd.rs` (`EnvironmentCommand::Status`), from
/// `crates/app/src/remote_env.rs` `StatusReport` and `crates/app/src/remote_status.rs`
/// `status_of`; the keys `tests/e2e/exit_m06/a07.rs` reads (`issuance`, `remote_pending`,
/// `residuals[0].statement`).
#[test]
fn environment_status_today() {
    let mut remote = pin_record();
    let fields = json!({
        "connectivity": {"state": "disconnected", "last_seen_at": "2026-11-22T09:00:00Z"},
        "last_seen_at": "2026-11-22T09:00:00Z",
        "remote_pending": [{
            "kind": "effect",
            "effect": "eff_e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
            "target": {"kind": "grant_revoke", "grant": "grant_10101010101010101010101010101010", "grant_generation": 1}
        }],
        "last_known_readiness": [{
            "grant": "grant_10101010101010101010101010101010",
            "offline_until": "2026-11-22T18:00:00Z",
            "state": "within_bound",
            "observed_at": "2026-11-22T09:00:00Z"
        }],
        "issuance": "awaiting_resync",
        "residuals": [pending_residual()],
        "cutoffs_fired_early": [{
            "scope": "all",
            "producer": "cl_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "at": "2026-11-22T12:00:00Z",
            "fired_at": "2026-11-22T11:58:00Z",
            "reason": "time_uncertain"
        }],
        "issuance_failures": [{
            "grant": "grant_20202020202020202020202020202020",
            "at": "2026-11-22T09:30:00Z",
            "reason": "issuer_unavailable"
        }]
    });
    remote
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    // A record whose state cannot be read: the record's keys alone.
    let mut bare = pin_record();
    bare["environment"] = json!("env_fedcba9876543210fedcba9876543210");
    bare.as_object_mut().unwrap().remove("label");
    let doc = json!({"management": "available", "environments": [remote, bare]});
    let v: EnvironmentStatusView = today("environment status", "environment-status", &doc, &[]);
    assert!(v.environments[0].remote.is_some() && v.environments[1].remote.is_none());
    // A limited role's record named on the command line: the runner's own view.
    let mut limited = pin_record();
    limited["role"] = json!("viewer");
    limited["connectivity"] = json!({"state": "connected"});
    limited["remote_pending"] = json!([]);
    limited["issuance"] = json!("reconciled");
    limited["runner_view"] = json!({"read": true, "view": {
        "environment_id": "env_0123456789abcdef0123456789abcdef",
        "enrolled": true,
        "environments": []
    }});
    let doc = json!({"management": "available", "environments": [limited.clone()]});
    today::<EnvironmentStatusView>(
        "environment status (viewer)",
        "environment-status",
        &doc,
        &[],
    );
    limited["runner_view"] = json!({
        "read": false, "code": "SERVICE_UNAVAILABLE", "message": "the runner is not reachable",
        "reason": "ssh_connection_refused"
    });
    let doc = json!({"management": "mgmt_key_store_locked", "environments": [limited.clone()]});
    today::<EnvironmentStatusView>(
        "environment status (unread)",
        "environment-status",
        &doc,
        &[],
    );
    // Revision 7 (ADR-0013 §6.4), declared: the full count beside the first 16 entries.
    limited.as_object_mut().unwrap().remove("runner_view");
    limited["remote_pending_count"] = json!(0);
    let doc = json!({"management": "available", "environments": [limited]});
    let v: EnvironmentStatusView = exact(
        "environment status (revision 7)",
        "environment-status",
        &doc,
    );
    assert_eq!(
        v.environments[0]
            .remote
            .as_ref()
            .and_then(|r| r.remote_pending_count),
        Some(0)
    );
}

/// `crates/app/src/remote_status.rs` `GrantResidual` and
/// `remote_status_barrier::residual_statement`; `tests/e2e/exit_m06/a07.rs` reads
/// `grant`, `acknowledged` and `statement`.
#[test]
fn grant_residual_today() {
    today::<GrantResidual>("grant residual", "grant-residual", &pending_residual(), &[]);
    let measured = json!({
        "grant": "grant_10101010101010101010101010101010",
        "acknowledged": true,
        "new_authentication": {
            "latest_possible_credential_expiry": "2026-11-22T18:00:00Z",
            "destination_clock_error": {"measured": {
                "behind_upper_ms": 40, "rtt_ms": 12, "measured_at": "2026-11-22T09:00:00Z"
            }}
        },
        "statement": "until 2026-11-22T18:00:00.04Z (valid_before plus the measured \
                      destination-clock error)"
    });
    today::<GrantResidual>(
        "grant residual (measured)",
        "grant-residual",
        &measured,
        &[],
    );
    let none = json!({
        "grant": "grant_10101010101010101010101010101010",
        "acknowledged": true,
        "statement": "no issued credential is outstanding"
    });
    today::<GrantResidual>("grant residual (none)", "grant-residual", &none, &[]);
}

/// The revision-7 binding field, declared: `request_id`, shown only to its own caller.
#[test]
fn rev7_binding_request_id_reads_and_round_trips() {
    let doc = json!({"bindings": [{
        "binding_id": "binding_40404040404040404040404040404040",
        "grant_id": "grant_10101010101010101010101010101010",
        "work_id": "build-42",
        "profile": "dev",
        "profile_revision": 2,
        "state": "released",
        "created_at": "2026-11-22T10:00:00Z",
        "request_id": "req-0001"
    }]});
    let v: BindingListView = exact("inspect bindings (revision 7)", "inspect-bindings", &doc);
    assert_eq!(
        v.bindings[0].request_id.as_ref().map(|r| r.as_str()),
        Some("req-0001")
    );
}

/// ⟨U3-3a; PC2⟩ The subjects typed elsewhere are built as `WithPreview<T>` with no preview
/// (a preview is added after, untyped, as before: `PreviewView` drops its `null`s, a PC3
/// change). That document is `T`'s, byte for byte, for every published example of each
/// subject, and it reads and validates as the subject's `WithPreview` schema.
#[test]
fn with_preview_without_a_preview_is_the_view_byte_for_byte() {
    use heimdall_contract::enrollment::EnrollmentsView;
    use heimdall_contract::issuer::IssuerStatus;
    use heimdall_contract::managed::ConnectionsView;
    use heimdall_contract::trust::{PoliciesView, WorkspaceView};
    use heimdall_contract::views::WithPreview;

    fn same_literal<T: Serialize + Default>(want: &Value) {
        let got = serde_json::to_value(WithPreview {
            view: T::default(),
            preview: None,
        })
        .unwrap();
        assert_eq!(&got, want);
    }
    fn same<T: Serialize + DeserializeOwned + Clone>(example: &str, name: &str) {
        let doc = load(example);
        let view: T = serde_json::from_value(doc.clone()).unwrap_or_else(|e| panic!("{e}"));
        let bare = serde_json::to_string(&view).unwrap();
        let typed = serde_json::to_string(&WithPreview {
            view: view.clone(),
            preview: None,
        })
        .unwrap();
        // Byte for byte once both are read back as `Value`s (the runtime answers a
        // `Value`, whose maps are ordered by key).
        let bare: Value = serde_json::from_str(&bare).unwrap();
        let typed: Value = serde_json::from_str(&typed).unwrap();
        assert_eq!(typed, bare, "{example}");
        assert_eq!(
            serde_json::to_vec(&typed).unwrap(),
            serde_json::to_vec(&bare).unwrap(),
            "{example}"
        );
        exact::<WithPreview<T>>(example, name, &bare);
    }
    same::<EnrollmentsView>(
        "schemas/examples/inspect.enrollments.json",
        "inspect-enrollments",
    );
    same::<ConnectionsView>(
        "schemas/examples/inspect.connections.json",
        "inspect-connections",
    );
    same::<IssuerStatus>("schemas/examples/inspect.issuer.json", "inspect-issuer");
    same::<IssuerStatus>(
        "schemas/examples/inspect.issuer.awaiting-deletion.json",
        "inspect-issuer",
    );
    same::<PoliciesView>(
        "schemas/examples/inspect.policies.json",
        "inspect-policies.full",
    );
    same::<PoliciesView>(
        "schemas/examples/inspect.policies.default-profile.json",
        "inspect-policies.full",
    );
    same::<WorkspaceView>(
        "schemas/examples/inspect.workspace.json",
        "inspect-workspace.full",
    );
    same::<WorkspaceView>(
        "schemas/examples/inspect.workspace.proposal.json",
        "inspect-workspace.full",
    );
    // Another role's literals.
    same_literal::<EnrollmentsView>(&json!({"enrollments": []}));
    same_literal::<ConnectionsView>(&json!({"connections": []}));
    same_literal::<PoliciesView>(&json!({"items": []}));
}
