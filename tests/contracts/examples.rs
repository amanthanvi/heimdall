//! Example payload fixtures under `schemas/examples/` (plan section 4.5: example
//! success / pending / error payloads).
//!
//! The manifest below is explicit on purpose: other units may add their own files
//! to the directory (the CLI unit records observed outputs there) without affecting
//! these checks, and a file listed here that disappears fails loudly.

use serde_json::{Map, Value, json};

use crate::code::Code;
use crate::envelope::{EffectStatus, Envelope, ErrorData};
use crate::event::{Event, Snapshot};
use crate::exit::ExitCode;
use crate::ipc::{ClientHello, ClientMessage, ServerMessage};
use crate::request::{EnsureData, Request, RevokeData};
use crate::schema::public_schemas;
use crate::state::OperationState;
use crate::version::SchemaVersion;

use super::jsonschema_lite::validate;
use super::{assert_clean, repo_root};

#[derive(Clone, Copy, Debug)]
enum Kind {
    Envelope,
    EnvelopeError,
    EnvelopeEnsure,
    EnvelopeRevoke,
    Event,
    Snapshot,
    Request,
    ClientMessage,
    ServerMessage,
}

impl Kind {
    fn schema_name(self) -> &'static str {
        match self {
            Kind::Envelope => "envelope",
            Kind::EnvelopeError => "envelope.error",
            Kind::EnvelopeEnsure => "envelope.ensure",
            Kind::EnvelopeRevoke => "envelope.revoke",
            Kind::Event => "event",
            Kind::Snapshot => "snapshot",
            Kind::Request => "request",
            Kind::ClientMessage => "ipc.client-message",
            Kind::ServerMessage => "ipc.server-message",
        }
    }

    /// Deserialize into the typed model and serialize back.
    fn round_trip(self, v: &Value) -> Value {
        fn go<T: serde::Serialize + serde::de::DeserializeOwned>(v: &Value) -> Value {
            let typed: T = serde_json::from_value(v.clone()).unwrap();
            serde_json::to_value(&typed).unwrap()
        }
        match self {
            Kind::Envelope => go::<Envelope<Value>>(v),
            Kind::EnvelopeError => go::<Envelope<ErrorData>>(v),
            Kind::EnvelopeEnsure => go::<Envelope<EnsureData>>(v),
            Kind::EnvelopeRevoke => go::<Envelope<RevokeData>>(v),
            Kind::Event => go::<Event>(v),
            Kind::Snapshot => go::<Snapshot<Value>>(v),
            Kind::Request => go::<Request>(v),
            Kind::ClientMessage => go::<ClientMessage>(v),
            Kind::ServerMessage => go::<ServerMessage>(v),
        }
    }
}

/// (file, kind)
const EXAMPLES: &[(&str, Kind)] = &[
    ("envelope.success.ensure.json", Kind::EnvelopeEnsure),
    ("envelope.success.revoke.json", Kind::EnvelopeRevoke),
    ("envelope.success.read.json", Kind::Envelope),
    ("envelope.pending.accepted.json", Kind::Envelope),
    ("envelope.pending.approval.json", Kind::EnvelopeError),
    ("envelope.error.internal.json", Kind::EnvelopeError),
    ("envelope.error.usage.json", Kind::EnvelopeError),
    ("envelope.error.interaction.json", Kind::EnvelopeError),
    ("envelope.error.denied.json", Kind::EnvelopeError),
    ("envelope.error.cancelled.json", Kind::EnvelopeError),
    ("envelope.error.unavailable.json", Kind::EnvelopeError),
    ("envelope.error.conflict.json", Kind::EnvelopeError),
    ("envelope.error.resync.json", Kind::EnvelopeError),
    ("envelope.error.outcome-unknown.json", Kind::EnvelopeError),
    ("event.operation-state-changed.json", Kind::Event),
    ("snapshot.operations.json", Kind::Snapshot),
    ("request.ensure.json", Kind::Request),
    ("request.revoke.json", Kind::Request),
    ("request.policy-cutoff.json", Kind::Request),
    ("request.observe-events.json", Kind::Request),
    ("ipc.client-message.hello.json", Kind::ClientMessage),
    ("ipc.client-message.request.json", Kind::ClientMessage),
    ("ipc.client-message.subscribe.json", Kind::ClientMessage),
    ("ipc.server-message.hello.json", Kind::ServerMessage),
    ("ipc.server-message.reject.json", Kind::ServerMessage),
    ("ipc.server-message.response.json", Kind::ServerMessage),
    ("ipc.server-message.goodbye.json", Kind::ServerMessage),
];

fn load(file: &str) -> (String, Value) {
    let path = repo_root().join("schemas/examples").join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("example {file} unreadable: {}", e.kind()));
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
    (text, value)
}

fn schema_doc(kind: Kind) -> Value {
    let named = public_schemas()
        .into_iter()
        .find(|s| s.name == kind.schema_name())
        .unwrap();
    serde_json::to_value(&named.schema).unwrap()
}

fn checked_in_schema(kind: Kind) -> Value {
    let path = repo_root()
        .join("schemas/public-api")
        .join(format!("{}.schema.json", kind.schema_name()));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn all_strings_are_clean(label: &str, v: &Value) {
    match v {
        Value::String(s) => {
            assert!(
                !s.chars().any(char::is_control),
                "{label}: control character in a string"
            );
            assert_clean(label, s);
        }
        Value::Array(items) => items.iter().for_each(|i| all_strings_are_clean(label, i)),
        Value::Object(map) => map.values().for_each(|i| all_strings_are_clean(label, i)),
        _ => {}
    }
}

#[test]
fn every_example_round_trips_exactly_through_the_typed_model() {
    for (file, kind) in EXAMPLES {
        let (text, value) = load(file);
        assert_clean(file, &text);
        all_strings_are_clean(file, &value);
        let back = kind.round_trip(&value);
        assert_eq!(back, value, "{file}: typed round trip changed the document");
    }
}

#[test]
fn every_example_validates_against_generated_and_checked_in_schemas() {
    for (file, kind) in EXAMPLES {
        let (_, value) = load(file);
        for (which, schema) in [
            ("generated", schema_doc(*kind)),
            ("checked-in", checked_in_schema(*kind)),
        ] {
            if let Err(errors) = validate(&schema, &value) {
                panic!("{file} vs {which} {}: {errors:#?}", kind.schema_name());
            }
        }
    }
}

#[test]
fn schema_validator_is_not_vacuous_for_the_examples() {
    // Mutating a required or enumerated field must invalidate an example, otherwise
    // the schema checks above prove nothing.
    let (_, ok) = load("envelope.success.ensure.json");
    let schema = schema_doc(Kind::EnvelopeEnsure);
    assert!(validate(&schema, &ok).is_ok());
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for key in ["schema_version", "state", "code", "data"] {
        let mut v = ok.clone();
        v.as_object_mut().unwrap().remove(key);
        cases.push((key, v));
    }
    for (field, bad) in [
        ("code", json!("NOT_A_CODE")),
        ("state", json!("exploded")),
        ("warnings", json!("none")),
        ("operation_id", json!(7)),
    ] {
        let mut v = ok.clone();
        v[field] = bad;
        cases.push((field, v));
    }
    let mut v = ok.clone();
    v["data"]["enforcement"]["revocation"] = json!("telepathy");
    cases.push(("enforcement.revocation", v));
    let mut v = ok.clone();
    v["data"]["profile_revision"] = json!(-1);
    cases.push(("profile_revision", v));
    for (what, bad) in cases {
        assert!(
            validate(&schema, &bad).is_err(),
            "mutation of {what} accepted"
        );
    }
    let (_, request) = load("request.ensure.json");
    let mut bad = request.clone();
    bad["op"] = json!("teleport");
    assert!(validate(&schema_doc(Kind::Request), &bad).is_err());
    let (_, hello) = load("ipc.client-message.hello.json");
    let mut bad = hello.clone();
    bad["type"] = json!("nope");
    assert!(validate(&schema_doc(Kind::ClientMessage), &bad).is_err());
}

/// Insert `key` into every object of `v`.
fn inject(v: &mut Value, key: &str) {
    match v {
        Value::Object(map) => {
            map.values_mut().for_each(|c| inject(c, key));
            map.insert(key.to_owned(), json!({"future": [1, {"deep": true}]}));
        }
        Value::Array(items) => items.iter_mut().for_each(|c| inject(c, key)),
        _ => {}
    }
}

fn strip(v: &mut Value, key: &str) {
    match v {
        Value::Object(map) => {
            map.remove(key);
            map.values_mut().for_each(|c| strip(c, key));
        }
        Value::Array(items) => items.iter_mut().for_each(|c| strip(c, key)),
        _ => {}
    }
}

#[test]
fn unknown_fields_are_tolerated_at_every_nesting_level() {
    // ADR-0006 section 9: readers tolerate unknown non-critical fields.
    const KEY: &str = "x_future_field";
    for (file, kind) in EXAMPLES {
        let (_, original) = load(file);
        let mut extended = original.clone();
        inject(&mut extended, KEY);
        let mut back = kind.round_trip(&extended);
        strip(&mut back, KEY);
        assert_eq!(back, original, "{file}: unknown fields changed known ones");
    }
}

#[test]
fn unsupported_schema_major_is_rejected_explicitly() {
    assert!(SchemaVersion("1".to_owned()).is_supported());
    for bad in [
        "0", "2", "10", "11", "1.0", "1.1", "01", " 1", "1 ", "v1", "", "\u{ff11}",
    ] {
        assert!(
            !SchemaVersion(bad.to_owned()).is_supported(),
            "major {bad:?} must be unsupported"
        );
    }
    assert!(SchemaVersion::current().is_supported());
    assert_eq!(SchemaVersion::default(), SchemaVersion::current());

    // A document carrying another major still parses structurally (the reader can
    // report what it refused) and carries the unsupported version for the caller to
    // reject with SCHEMA_UNSUPPORTED; it is never read as empty or as version 1.
    for (file, kind) in EXAMPLES {
        let (_, mut v) = load(file);
        let Some(obj) = v.as_object_mut() else {
            continue;
        };
        if !obj.contains_key("schema_version") {
            continue;
        }
        obj.insert("schema_version".into(), json!("2"));
        let back = kind.round_trip(&v);
        assert_eq!(back["schema_version"], json!("2"), "{file}");
        match kind {
            Kind::Envelope | Kind::EnvelopeError | Kind::EnvelopeEnsure | Kind::EnvelopeRevoke => {
                let env: Envelope<Value> = serde_json::from_value(v).unwrap();
                assert!(!env.schema_version.is_supported(), "{file}");
            }
            Kind::Event => {
                let ev: Event = serde_json::from_value(v).unwrap();
                assert!(!ev.schema_version.is_supported(), "{file}");
            }
            _ => {}
        }
    }

    // Hello frames carry the schema major the client expects.
    let (_, mut hello) = load("ipc.client-message.hello.json");
    hello["schema_version"] = json!("2");
    let ClientMessage::Hello(ClientHello { schema_version, .. }) =
        serde_json::from_value(hello).unwrap()
    else {
        panic!("not a hello");
    };
    assert!(!schema_version.is_supported());
}

#[test]
fn missing_schema_version_is_not_defaulted() {
    // A document without a major must not be read as the current one.
    let (_, mut v) = load("envelope.success.read.json");
    v.as_object_mut().unwrap().remove("schema_version");
    assert!(serde_json::from_value::<Envelope<Value>>(v).is_err());
    let (_, mut ev) = load("event.operation-state-changed.json");
    ev.as_object_mut().unwrap().remove("schema_version");
    assert!(serde_json::from_value::<Event>(ev).is_err());
}

fn envelope_of(file: &str) -> Envelope<Value> {
    let (_, v) = load(file);
    serde_json::from_value(v).unwrap()
}

#[test]
fn error_examples_cover_every_exit_class_and_agree_with_the_code_table() {
    // (file, expected exit class)
    let table: &[(&str, ExitCode)] = &[
        ("envelope.error.internal.json", ExitCode::Internal),
        ("envelope.error.usage.json", ExitCode::Usage),
        (
            "envelope.error.interaction.json",
            ExitCode::InteractionRequired,
        ),
        (
            "envelope.pending.approval.json",
            ExitCode::InteractionRequired,
        ),
        ("envelope.error.denied.json", ExitCode::Denied),
        ("envelope.error.cancelled.json", ExitCode::Denied),
        ("envelope.error.unavailable.json", ExitCode::Unavailable),
        ("envelope.error.conflict.json", ExitCode::Conflict),
        ("envelope.error.resync.json", ExitCode::Conflict),
        (
            "envelope.error.outcome-unknown.json",
            ExitCode::OutcomeUnknown,
        ),
    ];
    let mut classes = std::collections::BTreeSet::new();
    for (file, class) in table {
        let (_, v) = load(file);
        let env: Envelope<ErrorData> = serde_json::from_value(v).unwrap();
        let err = &env.data.error;
        assert_eq!(env.code, err.code, "{file}: envelope and error code differ");
        assert_eq!(env.code.exit_code(), *class, "{file}: exit class");
        assert_eq!(err.retryable, env.code.retryable(), "{file}: retryable");
        assert_eq!(
            err.effect_status,
            env.code.default_effect_status(),
            "{file}: effect"
        );
        assert_eq!(
            err.next.action,
            env.code.default_next_action(),
            "{file}: next"
        );
        assert_eq!(env.next.as_ref(), Some(&err.next), "{file}: envelope next");
        assert!(!env.code.is_success(), "{file}");
        classes.insert(class.as_i32());
    }
    assert_eq!(
        classes.into_iter().collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7],
        "every non-success exit class has an example"
    );
}

#[test]
fn state_matches_code_in_the_examples() {
    // overview section 7: state derives from the code.
    let outcome = envelope_of("envelope.error.outcome-unknown.json");
    assert_eq!(outcome.state, OperationState::OutcomeUnknown);
    assert_eq!(outcome.code, Code::OutcomeUnknown);
    let unknown: Envelope<ErrorData> =
        serde_json::from_value(load("envelope.error.outcome-unknown.json").1).unwrap();
    assert_eq!(unknown.data.error.effect_status, EffectStatus::Unknown);
    assert!(
        !unknown.data.error.retryable,
        "OUTCOME_UNKNOWN is never retryable"
    );

    let cancelled = envelope_of("envelope.error.cancelled.json");
    assert_eq!(cancelled.state, OperationState::Cancelled);

    let approval = envelope_of("envelope.pending.approval.json");
    assert_eq!(approval.state, OperationState::AwaitingApproval);
    assert_eq!(approval.code, Code::ApprovalRequired);
    let next = approval.next.unwrap();
    assert_eq!(next.action, "observe");
    assert!(next.decision_ref.is_some() && next.operation_id.is_some());

    let accepted = envelope_of("envelope.pending.accepted.json");
    assert_eq!(accepted.state, OperationState::Queued);
    assert_eq!(accepted.code, Code::Accepted);
    assert!(accepted.code.is_success());
    let next = accepted.next.unwrap();
    assert_eq!(next.action, "observe");
    assert_eq!(next.operation_id, accepted.operation_id);

    let ready = envelope_of("envelope.success.ensure.json");
    assert_eq!(ready.state, OperationState::Succeeded);
    assert_eq!(ready.code, Code::AccessReady);
    assert_eq!(ready.next.unwrap().action, "use_binding");

    // Pure reads carry no operation_id (ADR-0006 section 3).
    assert!(
        envelope_of("envelope.success.read.json")
            .operation_id
            .is_none()
    );
    assert!(
        envelope_of("envelope.error.usage.json")
            .operation_id
            .is_none()
    );
}

#[test]
fn success_examples_carry_no_private_material_fields() {
    // Names that would indicate a secret in a result payload (spec section 11.2).
    const FORBIDDEN: &[&str] = &[
        "private_key",
        "passphrase",
        "password",
        "secret",
        "token",
        "approval_secret",
    ];
    fn walk(v: &Value, file: &str) {
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    assert!(
                        !FORBIDDEN.iter().any(|f| k.to_ascii_lowercase().contains(f)),
                        "{file}: suspicious field name {k}"
                    );
                    walk(child, file);
                }
            }
            Value::Array(items) => items.iter().for_each(|i| walk(i, file)),
            _ => {}
        }
    }
    for (file, _) in EXAMPLES {
        walk(&load(file).1, file);
    }
}

#[test]
fn emitted_documents_always_materialize_next_and_warnings() {
    // ADR-0006 section 3: `warnings` is always an array, `next` always present
    // (null when nothing is expected). The generated schema leaves both optional on
    // input (serde defaults); this pins the emitted form.
    let ok = serde_json::to_value(Envelope::ok(json!({}))).unwrap();
    let obj: &Map<String, Value> = ok.as_object().unwrap();
    assert!(obj["next"].is_null());
    assert_eq!(obj["warnings"], json!([]));
    assert!(!obj.contains_key("operation_id"), "omitted, not null");
}
