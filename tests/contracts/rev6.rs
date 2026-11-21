//! ADR-0006 revision 6 contract deltas (M06 wave 0; ADR-0006 §18, ADR-0012 §9).
//!
//! Expected values are transcribed from ADR-0012 §9 and §18.1, never from the code under
//! test:
//! * `rev6_reason_golden`: the M06 reasons and their codes (`golden/rev6-reasons.golden.json`)
//!   against `envelope::reason::M06`, both ways; every one `CAPABILITY_UNAVAILABLE` except
//!   revision 6.3's `local_owner_required` (`INTERACTION_REQUIRED`); no
//!   reason string reused across M02–M06 (`route_dependency_out_of_scope` stays M04's); the
//!   pending reason has no code and is not an error reason; the code table is unchanged;
//! * `rev6_request_forms`: one request of every revision-6 form
//!   (`golden/rev6-requests.golden.json`) decodes, re-encodes byte-identically, validates
//!   against the generated request schema, tolerates an unknown field, and has the golden's
//!   kind, admission and capability; there is no `RemoteDecide` and no lease or suspend
//!   message;
//! * `rev6_capabilities_declared_and_roles`: the four capabilities, their declared list, the
//!   role sets (the offer itself is pinned in `heimdall-ipc`:
//!   `the_revision_6_capabilities_are_declared_not_offered`);
//! * `rev6_earlier_forms_unchanged`: every pre-revision-6 request example decodes and
//!   re-encodes byte-identically and needs no revision-6 capability;
//! * `rev6_additive_documents`: the hello fields, the environment view's remote fields, the
//!   event types and payloads, the route and residual types: each omitted when absent, each
//!   round-tripping and validating where a public schema carries it.
//!
//! The idempotency, cursor and visibility rules are proven where they are computed:
//! `heimdall_domain::idempotency::tests::remote_client_namespaces_the_key_and_none_keeps_the_old_encoding`,
//! `heimdall_app::events::tests::remote_client_scopes_cursors_and_visibility` and
//! `heimdall_domain::binding::tests::foreign_limited_caller_may_not_act`.

use std::collections::BTreeSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::environment::{EnvironmentKindView, EnvironmentsView};
use heimdall_contract::event::EventType;
use heimdall_contract::ipc::{ClientMessage, ServerMessage, capability};
use heimdall_contract::managed::{ReadinessCondition, RevocationResiduals};
use heimdall_contract::remote::{
    ClientEventPayload, DeviceEventPayload, EnvironmentEventPayload, RemoteEffectEventPayload, Role,
};
use heimdall_contract::request::{Admission, Request};
use heimdall_contract::route::{DestinationRoutes, RouteHealthPayload};
use heimdall_contract::schema::public_schemas;

use crate::jsonschema_lite::validate;
use crate::{assert_clean, repo_root};

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|e| panic!("{path} unreadable: {}", e.kind()));
    assert_clean(path, &text);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn schema(name: &str) -> Value {
    let doc = public_schemas()
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no public schema {name}"));
    serde_json::to_value(&doc.schema).unwrap()
}

/// `T` round-trips `v` exactly; with a schema name, `v` validates against it.
fn exact<T: Serialize + DeserializeOwned>(what: &str, v: &Value, schema_name: Option<&str>) -> T {
    let typed: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(
        &serde_json::to_value(&typed).unwrap(),
        v,
        "{what}: exact round trip"
    );
    if let Some(name) = schema_name
        && let Err(e) = validate(&schema(name), v)
    {
        panic!("{what} against {name}: {e:?}");
    }
    typed
}

#[test]
fn rev6_reason_golden() {
    let golden = load("tests/contracts/golden/rev6-reasons.golden.json");
    let want: BTreeSet<(String, String)> = golden["m06"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["reason"].as_str().unwrap().to_owned(),
                r["code"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(want.len(), golden["m06"].as_array().unwrap().len());
    let got: BTreeSet<(String, String)> = reason::M06
        .iter()
        .map(|(r, c)| ((*r).to_owned(), c.as_str().to_owned()))
        .collect();
    assert_eq!(got.len(), reason::M06.len(), "duplicate rows in code");
    assert_eq!(got, want, "M06 reasons and codes");
    assert_eq!(
        got.len(),
        26,
        "revision 6.2 added mgmt_key_store_unavailable; revision 6.3 added \
         local_owner_required and resync_pending"
    );
    for (r, c) in &got {
        // Revision 6.3 (ADR-0006 §18.7): `local_owner_required` is the one M06 reason under
        // `INTERACTION_REQUIRED`; every other is `CAPABILITY_UNAVAILABLE`.
        let code = if r == reason::LOCAL_OWNER_REQUIRED {
            "INTERACTION_REQUIRED"
        } else {
            "CAPABILITY_UNAVAILABLE"
        };
        assert_eq!(c, code, "{r}");
        assert!(
            r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{r}"
        );
    }
    // The reused reason is M04's, with the code ADR-0012 §9 item 7 lists, and is not
    // repeated in the M06 list.
    let reused = &golden["reused"][0];
    assert_eq!(reused["reason"], reason::ROUTE_DEPENDENCY_OUT_OF_SCOPE);
    assert!(reason::M04.contains(&(
        reason::ROUTE_DEPENDENCY_OUT_OF_SCOPE,
        Code::CapabilityUnavailable
    )));
    // Each reason string is used once across M02–M06.
    let names = |list: &[(&str, Code)]| -> BTreeSet<String> {
        list.iter().map(|(r, _)| (*r).to_owned()).collect()
    };
    let mut earlier: BTreeSet<String> = reason::ALL.iter().map(|s| (*s).to_owned()).collect();
    for list in [reason::M03, reason::M03_REV5, reason::M04, reason::M05] {
        earlier.extend(names(list));
    }
    let m06 = names(reason::M06);
    assert!(
        earlier.is_disjoint(&m06),
        "a reason reused: {:?}",
        earlier.intersection(&m06).collect::<Vec<_>>()
    );
    // The pending reason: in its own list, not an error reason.
    let pending: BTreeSet<String> = serde_json::from_value(golden["m06_pending"].clone()).unwrap();
    let in_code: BTreeSet<String> = reason::M06_PENDING
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(in_code, pending);
    assert_eq!(reason::IROH_ADMISSION_CLOSING, "iroh_admission_closing");
    assert!(pending.is_disjoint(&m06) && pending.is_disjoint(&earlier));
    assert_eq!(Code::all().len(), 30, "the code table is unchanged");
}

/// The revision-6 ops whose every form needs a revision-6 capability (the golden's
/// `requests`). Revision 6.3 (ADR-0006 §18.7) adds `runner_local`; its other new op,
/// `controller_record`, needs no capability and is the golden's `no_capability_requests`.
const REVISION_6_OPS: [&str; 6] = [
    "remote_environment",
    "device",
    "route",
    "transport",
    "runner",
    "runner_local",
];

#[test]
fn rev6_request_forms() {
    let golden = load("tests/contracts/golden/rev6-requests.golden.json");
    let rows = golden["requests"].as_array().unwrap();
    let request_schema = schema("request");
    let mut ops_actions = BTreeSet::new();
    for row in rows {
        let what = row["what"].as_str().unwrap();
        let v = &row["json"];
        let r: Request = exact(what, v, Some("request"));
        assert!(r.is_revision_6(), "{what}");
        assert_eq!(r.kind(), row["kind"].as_str().unwrap(), "{what}");
        let admission = match r.admission() {
            Admission::Journaled(_) => "journaled",
            Admission::Synchronous => "synchronous",
            Admission::ReadOnly => "read_only",
        };
        assert_eq!(admission, row["admission"].as_str().unwrap(), "{what}");
        let capability = r.required_capability().expect("a revision-6 capability");
        assert_eq!(capability, row["capability"].as_str().unwrap(), "{what}");
        assert!(
            capability::REVISION_6_DECLARED.contains(&capability),
            "{what}"
        );
        assert!(!r.requires_attended_session(), "{what}");
        assert!(!r.is_widening_policy_action(), "{what}");
        // Unknown fields are tolerated (ADR-0006 §9) and not re-emitted.
        let mut extra = v.clone();
        extra["later"] = json!(1);
        let back: Request = serde_json::from_value(extra).unwrap();
        assert_eq!(back, r, "{what}");
        ops_actions.insert((
            v["op"].as_str().unwrap().to_owned(),
            v["action"].as_str().unwrap().to_owned(),
        ));
    }
    // Every revision-6 op and action in the generated schema is in the golden.
    let doc = &request_schema;
    let mut from_schema = BTreeSet::new();
    for alt in doc["oneOf"].as_array().unwrap() {
        let op = alt["properties"]["op"]["const"].as_str().unwrap();
        if !REVISION_6_OPS.contains(&op) {
            continue;
        }
        let def = alt["$ref"]
            .as_str()
            .and_then(|r| doc.pointer(r.trim_start_matches('#')))
            .unwrap();
        for a in def["oneOf"].as_array().unwrap() {
            let action = a["properties"]["action"]["const"].as_str().unwrap();
            from_schema.insert((op.to_owned(), action.to_owned()));
        }
    }
    assert_eq!(ops_actions, from_schema, "the golden covers every form");
    // 21 forms at revision 6; revision 6.1 (M06 wave 1) adds `remote_environment.activation_probe`;
    // revision 6.3 (M06 wave 3) adds `remote_environment.rotate_endpoint`,
    // `remote_environment.runner_policy_recheck`, `transport.rotate` and the six
    // `runner_local` forms.
    assert_eq!(from_schema.len(), 31);
    // Revision 6.3's `controller_record` forms (ADR-0006 §18.7 item 6): revision-6 forms
    // that need no capability beyond `operations/1`, so they are not in `requests`. Every
    // other assertion of the loop above holds for them.
    let mut record_actions = BTreeSet::new();
    for row in golden["no_capability_requests"].as_array().unwrap() {
        let what = row["what"].as_str().unwrap();
        let v = &row["json"];
        let r: Request = exact(what, v, Some("request"));
        assert!(r.is_revision_6(), "{what}");
        assert_eq!(r.kind(), row["kind"].as_str().unwrap(), "{what}");
        assert_eq!(r.admission(), Admission::Synchronous, "{what}");
        assert_eq!(row["admission"], "synchronous", "{what}");
        assert_eq!(r.required_capability(), None, "{what}");
        assert!(row["capability"].is_null(), "{what}");
        assert!(!r.requires_attended_session(), "{what}");
        assert!(!r.is_widening_policy_action(), "{what}");
        let mut extra = v.clone();
        extra["later"] = json!(1);
        let back: Request = serde_json::from_value(extra).unwrap();
        assert_eq!(back, r, "{what}");
        assert_eq!(v["op"], "controller_record", "{what}");
        record_actions.insert(v["action"].as_str().unwrap().to_owned());
    }
    let record_def = doc["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|alt| alt["properties"]["op"]["const"] == "controller_record")
        .and_then(|alt| alt["$ref"].as_str())
        .and_then(|r| doc.pointer(r.trim_start_matches('#')))
        .unwrap();
    let record_schema: BTreeSet<String> = record_def["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            a["properties"]["action"]["const"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        record_actions, record_schema,
        "every controller_record form"
    );
    assert_eq!(record_schema.len(), 2);
    // No RemoteDecide (ADR-0012 §3.10) and no serve-child lease or suspend message (§2.3):
    // no op or action of the whole request schema names one.
    let mut every_name = BTreeSet::new();
    for alt in doc["oneOf"].as_array().unwrap() {
        let op = alt["properties"]["op"]["const"].as_str().unwrap();
        every_name.insert(op.to_owned());
        if let Some(def) = alt["$ref"]
            .as_str()
            .and_then(|r| doc.pointer(r.trim_start_matches('#')))
            && let Some(alts) = def["oneOf"].as_array()
        {
            for a in alts {
                if let Some(action) = a["properties"]["action"]["const"].as_str() {
                    every_name.insert(action.to_owned());
                }
            }
        }
    }
    for name in &every_name {
        for absent in ["decide_remote", "remote_decide", "lease", "suspend"] {
            assert!(
                !name.contains(absent) || name == "release",
                "`{name}` in the request schema"
            );
        }
    }
    assert!(
        every_name.contains("decide"),
        "the local decide is unchanged"
    );
    // A request field never names a caller: no revision-6 form carries `remote_client`, a
    // principal or a producer (the producer of an effect is the session's client).
    for alt in doc["oneOf"].as_array().unwrap() {
        let op = alt["properties"]["op"]["const"].as_str().unwrap();
        if !REVISION_6_OPS.contains(&op) {
            continue;
        }
        let def = alt["$ref"]
            .as_str()
            .and_then(|r| doc.pointer(r.trim_start_matches('#')))
            .unwrap();
        let def_text = serde_json::to_string(def).unwrap();
        for absent in ["\"remote_client\"", "\"principal\"", "\"producer\""] {
            assert!(!def_text.contains(absent), "{op}: {absent}");
        }
    }
    // A form missing a required field is refused (an effect's target carries its
    // generation; a widening form its request ID).
    for bad in [
        json!({"op": "runner", "action": "deliver_effect", "effect": "eff_01",
               "target": {"kind": "policy_pause", "policy": "p"}}),
        json!({"op": "remote_environment", "action": "invite",
               "environment": "env_0123456789abcdef0123456789abcdef", "role": "viewer",
               "key_fingerprint": "SHA256:uXq3mT1n0rWbG5cVxZ2yA7kL9pQeJ4sHdF8oN6iRtC0"}),
        json!({"op": "remote_environment", "action": "invite",
               "environment": "env_0123456789abcdef0123456789abcdef", "role": "admin",
               "key_fingerprint": "SHA256:uXq3mT1n0rWbG5cVxZ2yA7kL9pQeJ4sHdF8oN6iRtC0",
               "request_id": "r"}),
        json!({"op": "transport", "action": "adopt_roost", "destination": "d",
               "endpoint": "not-hex", "request_id": "r"}),
        json!({"op": "runner", "action": "remote_decide"}),
    ] {
        assert!(
            serde_json::from_value::<Request>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn rev6_capabilities_declared_and_roles() {
    assert_eq!(capability::REMOTE_CONTROL_V1, "remote-control/1");
    assert_eq!(capability::RUNNER_V1, "runner/1");
    assert_eq!(capability::ROUTES_V1, "routes/1");
    assert_eq!(capability::TRANSPORT_IROH_V1, "transport-iroh/1");
    assert_eq!(
        capability::REVISION_6_DECLARED,
        [
            capability::REMOTE_CONTROL_V1,
            capability::RUNNER_V1,
            capability::ROUTES_V1,
            capability::TRANSPORT_IROH_V1
        ]
    );
    let all: BTreeSet<&str> = capability::ALL.iter().copied().collect();
    assert_eq!(all.len(), capability::ALL.len(), "no duplicate name");
    for c in capability::REVISION_6_DECLARED
        .iter()
        .chain(&capability::REVISION_5_DECLARED)
        .chain(&capability::M03_DECLARED)
    {
        assert!(all.contains(c), "{c}");
    }
    // ADR-0012 §3.8: owner holds everything; requester `view` + `request`; viewer `view`.
    assert_eq!(Role::Owner.capabilities(), capability::ALL.as_slice());
    let requester: BTreeSet<&str> = Role::Requester.capabilities().iter().copied().collect();
    let viewer: BTreeSet<&str> = Role::Viewer.capabilities().iter().copied().collect();
    assert!(viewer.is_subset(&requester) && requester.is_subset(&all));
    for owner_only in [
        capability::OWNER_POLICY_V1,
        capability::SERVICE_CONTROL_V1,
        capability::SETUP_V1,
        capability::ISSUER_V1,
        capability::ENROLLMENT_V1,
        capability::CONNECTIONS_V1,
        capability::ENVIRONMENTS_V1,
    ]
    .iter()
    .chain(&capability::REVISION_6_DECLARED)
    {
        assert!(!requester.contains(owner_only), "{owner_only}");
    }
    assert!(viewer.contains(capability::OPERATIONS_V1));
    assert!(!viewer.contains(capability::MANAGED_CREDENTIALS_V1));
}

#[test]
fn rev6_earlier_forms_unchanged() {
    let dir = repo_root().join("schemas/examples");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if !name.starts_with("request.") {
            continue;
        }
        let v = load(&format!("schemas/examples/{name}"));
        let r: Request =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(serde_json::to_value(&r).unwrap(), v, "{name}");
        assert!(!r.is_revision_6(), "{name}");
        assert!(
            !matches!(r.required_capability(), Some(c) if capability::REVISION_6_DECLARED.contains(&c)),
            "{name}: an earlier form needs a revision-6 capability"
        );
        checked += 1;
    }
    assert!(checked >= 50, "only {checked} request examples");
}

#[test]
fn rev6_additive_documents() {
    // The hello examples are unchanged (no `remote_client`, no `role`), and each new field
    // round-trips and validates when present.
    let hello = load("schemas/examples/ipc.client-message.hello.json");
    let _: ClientMessage = exact("client hello", &hello, Some("ipc.client-message"));
    assert!(hello.get("remote_client").is_none());
    let mut with_client = hello.clone();
    with_client["remote_client"] = json!("cl_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1");
    let ClientMessage::Hello(h) = exact::<ClientMessage>(
        "client hello with remote_client",
        &with_client,
        Some("ipc.client-message"),
    ) else {
        panic!("a hello");
    };
    assert!(h.remote_client.is_some());
    with_client["remote_client"] = json!("inv_a1");
    assert!(serde_json::from_value::<ClientMessage>(with_client).is_err());
    let server = load("schemas/examples/ipc.server-message.hello.json");
    let _: ServerMessage = exact("server hello", &server, Some("ipc.server-message"));
    assert!(server.get("role").is_none());
    let mut with_role = server.clone();
    with_role["role"] = json!("viewer");
    let _: ServerMessage = exact(
        "server hello with role",
        &with_role,
        Some("ipc.server-message"),
    );

    // The environment view: the M04 example is unchanged; a remote runner with every
    // revision-6 field round-trips and validates.
    let m04: EnvironmentsView = exact(
        "inspect environments (M04)",
        &load("schemas/examples/inspect.environments.json"),
        Some("inspect-environments"),
    );
    assert!(m04.items.iter().all(|v| v.connectivity.is_none()));
    let remote = json!({"items": [{
        "environment_id": "env_0123456789abcdef0123456789abcdef",
        "kind": "remote_runner",
        "label": "lab",
        "state": "active",
        "realization": {"kind": "remote_runner", "destination": "lab-runner", "account": "runner"},
        "connectivity": {"state": "disconnected", "last_seen_at": "2026-11-20T11:00:00Z"},
        "last_seen_at": "2026-11-20T11:00:00Z",
        "runner_lifetime": "session_scope",
        "remote_pending": [
            {"kind": "effect", "effect": "eff_d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
             "target": {"kind": "grant_revoke", "grant": "grant_00112233445566778899aabbccddeeff",
                        "grant_generation": 2}},
            {"kind": "client_revocation", "client": "cl_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
             "reason": "iroh_admission_closing"}
        ],
        "pinned_host_key": "SHA256:uXq3mT1n0rWbG5cVxZ2yA7kL9pQeJ4sHdF8oN6iRtC0",
        "management_policy": "owner_only"
    }]});
    let view: EnvironmentsView = exact("remote runner view", &remote, Some("inspect-environments"));
    assert_eq!(view.items[0].kind, EnvironmentKindView::RemoteRunner);
    for (value, policy) in [("verified", true), ("owner_only", true), ("open", false)] {
        let mut v = remote.clone();
        v["items"][0]["management_policy"] = json!(value);
        assert_eq!(
            serde_json::from_value::<EnvironmentsView>(v).is_ok(),
            policy,
            "{value}"
        );
    }

    // The event types, as ADR-0012 §9 item 8's families: `environment`, `client`, `device`,
    // `remote_effect`, `route` (each payload's `kind` is the name after the dot).
    for (t, wire) in [
        (EventType::Environment, "environment"),
        (EventType::Client, "client"),
        (EventType::Device, "device"),
        (EventType::RemoteEffect, "remote_effect"),
        (EventType::Route, "route"),
    ] {
        assert_eq!(serde_json::to_value(t).unwrap(), json!(wire));
    }
    let _: EnvironmentEventPayload = exact(
        "environment.connectivity_changed",
        &json!({"kind": "connectivity_changed",
                "environment": "env_0123456789abcdef0123456789abcdef",
                "connectivity": {"state": "unreachable", "reason": "transport_unavailable"}}),
        None,
    );
    for kind in ["enrolled", "revoked"] {
        let _: ClientEventPayload = exact(
            "client.*",
            &json!({"kind": kind, "environment": "env_0123456789abcdef0123456789abcdef",
                    "client": "cl_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "role": "requester"}),
            None,
        );
    }
    let _: DeviceEventPayload = exact(
        "device.retired",
        &json!({"kind": "retired", "revoked_on": ["env_0123456789abcdef0123456789abcdef"]}),
        None,
    );
    for kind in ["pending", "acknowledged"] {
        let _: RemoteEffectEventPayload = exact(
            "remote_effect.*",
            &json!({"kind": kind, "environment": "env_0123456789abcdef0123456789abcdef",
                    "producer": "cl_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
                    "effect": "eff_d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
                    "target": {"kind": "policy_cutoff", "scope": {"kind": "all"}, "at": "2026-11-21T18:00:00Z", "revision": 8}}),
            None,
        );
    }
    let health: RouteHealthPayload = exact(
        "route.failed_over",
        &json!({"kind": "failed_over", "destination": "lab-runner", "account": "deploy",
                "attempts": [
                    {"route": "route_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "failure": "identification_timeout"},
                    {"route": "route_e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"}
                ],
                "final_route": "route_e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"}),
        None,
    );
    assert_eq!(health.attempts.len(), 2);
    for class in [
        "refused",
        "timeout",
        "identification_timeout",
        "admission_refused",
        "terminal_after_forwarding",
    ] {
        let v = json!({"route": "route_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "failure": class});
        assert!(
            serde_json::from_value::<heimdall_contract::route::RouteAttempt>(v).is_ok(),
            "{class}"
        );
    }
    let none_used: RouteHealthPayload = exact(
        "route.health with no route used",
        &json!({"kind": "health", "destination": "lab-runner", "account": "deploy",
                "attempts": [{"route": "route_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", "failure": "refused"}]}),
        None,
    );
    assert!(none_used.final_route.is_none());

    // Routes and destinations (types only): the three route kinds, exposure policies,
    // consent references and host keys.
    let routes: DestinationRoutes = exact(
        "destination routes",
        &json!({"destination": "lab-runner",
                "routes": [
                    {"id": "route_c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
                     "route": {"kind": "direct", "host": "192.0.2.10"}},
                    {"id": "route_e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
                     "route": {"kind": "jump", "via": "bastion"}},
                    {"id": "route_f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
                     "route": {"kind": "iroh",
                               "endpoint": "58ff2b14ee18ef79cb690dd8ce9a9e8e8d8ce8fde772c88070ceaa99c6447058",
                               "external_roost": true},
                     "exposure": {"bind": {"kind": "loopback"},
                                  "infrastructure": {"kind": "n0_public"},
                                  "direct_fallback": true},
                     "consents": ["cns_0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"],
                     "identification_timeout_ms": 15000}
                ],
                "host_keys": [{"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture",
                               "fingerprint": "SHA256:uXq3mT1n0rWbG5cVxZ2yA7kL9pQeJ4sHdF8oN6iRtC0"}]}),
        None,
    );
    assert_eq!(routes.routes.len(), 3);

    // Readiness: the runner conditions and the per-component residuals, each omitted when
    // absent; an unmeasured destination clock is written out, never dropped.
    for (c, wire) in [
        (ReadinessCondition::RunnerLifetime, "runner_lifetime"),
        (ReadinessCondition::RunnerTimeBounded, "runner_time_bounded"),
        (
            ReadinessCondition::RunnerProcessNotRestarted,
            "runner_process_not_restarted",
        ),
    ] {
        assert_eq!(serde_json::to_value(c).unwrap(), json!(wire));
    }
    let r: RevocationResiduals = exact(
        "residuals",
        &json!({"new_authentication": {
                    "latest_possible_credential_expiry": "2026-11-20T14:00:00Z",
                    "destination_clock_error": "unmeasured"},
                "owned_dedicated_sessions": "closed",
                "owned_admissions": "closed",
                "other_live_sessions": "unknown",
                "detached_remote_processes": "not_ended"}),
        None,
    );
    assert!(r.new_authentication.is_some());
    let measured: RevocationResiduals = exact(
        "residuals, measured clock, unknown history",
        &json!({"new_authentication": {"destination_clock_error": {"measured": {
                    "behind_upper_ms": 1500, "rtt_ms": 40,
                    "measured_at": "2026-11-20T12:00:00Z"}}}}),
        None,
    );
    assert!(
        measured
            .new_authentication
            .unwrap()
            .latest_possible_credential_expiry
            .is_none(),
        "absent history reads unknown, never a bare deadline"
    );
    assert_eq!(
        serde_json::to_value(RevocationResiduals::default()).unwrap(),
        json!({})
    );
    assert!(
        serde_json::from_value::<RevocationResiduals>(
            json!({"new_authentication": {"latest_possible_credential_expiry": "2026-11-20T14:00:00Z"}})
        )
        .is_err(),
        "the destination-clock error is required"
    );
}
