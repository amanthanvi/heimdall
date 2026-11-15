//! Example payload fixtures under `schemas/examples/` (plan section 4.5: example
//! success / pending / error payloads).
//!
//! The manifest below is explicit on purpose: other units may add their own files
//! to the directory (the CLI unit records observed outputs there) without affecting
//! these checks, and a file listed here that disappears fails loudly.
//!
//! ⟨M03⟩ The ADR-0006 revision 4 examples (m03-plan U0) are listed too. Their keys,
//! fingerprints, hosts and paths are synthetic placeholders, never real key material
//! (AGENTS.md). A bare `EnsureData` or `RevokeData` validates against the `data`
//! definition of its envelope schema; the `inspect enrollments` and `inspect
//! connections` views have no public schema file, so they validate against the schema
//! generated from their type only.

use serde_json::{Map, Value, json};

use heimdall_contract::code::Code;
use heimdall_contract::doctor::DoctorReport;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData};
use heimdall_contract::event::{Event, Snapshot};
use heimdall_contract::exit::ExitCode;
use heimdall_contract::ids::DecisionId;
use heimdall_contract::ipc::{ClientHello, ClientMessage, ServerMessage};
use heimdall_contract::request::{
    ConfirmTimeRequest, DecideRequest, EnsureData, InteractionMode, Request, RevokeData, Verdict,
};
use heimdall_contract::run_record::RunRecord;
use heimdall_contract::schema::public_schemas;
use heimdall_contract::setup::{SetupPlan, SetupResult};
use heimdall_contract::state::OperationState;
use heimdall_contract::version::SchemaVersion;

use crate::jsonschema_lite::validate;
use crate::{assert_clean, repo_root};

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
    DoctorReport,
    RunRecord,
    SetupPlan,
    SetupResult,
    // ⟨M03⟩
    EnsureData,
    RevokeData,
    EnrollmentPlan,
    EnrollmentResult,
    IssuerStatus,
    EnrollmentsView,
    ConnectionsView,
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
            Kind::DoctorReport => "doctor-report",
            Kind::RunRecord => "run-record",
            Kind::SetupPlan => "setup-plan",
            Kind::SetupResult => "setup-result",
            Kind::EnsureData => "envelope.ensure",
            Kind::RevokeData => "envelope.revoke",
            Kind::EnrollmentPlan => "enrollment-plan",
            Kind::EnrollmentResult => "enrollment-result",
            Kind::IssuerStatus => "issuer-status",
            Kind::EnrollmentsView => "inspect enrollments (no schema file)",
            Kind::ConnectionsView => "inspect connections (no schema file)",
        }
    }

    /// ⟨M03⟩ The `$defs` entry of the envelope schema a bare payload validates
    /// against, when the example is a payload rather than a whole document.
    fn payload_def(self) -> Option<&'static str> {
        match self {
            Kind::EnsureData => Some("EnsureData"),
            Kind::RevokeData => Some("RevokeData"),
            _ => None,
        }
    }

    /// ⟨M03⟩ Kinds with no public schema: the schema generated from the type.
    fn generated_only(self) -> Option<Value> {
        let schema = match self {
            Kind::EnrollmentsView => {
                schemars::schema_for!(heimdall_contract::enrollment::EnrollmentsView)
            }
            Kind::ConnectionsView => {
                schemars::schema_for!(heimdall_contract::managed::ConnectionsView)
            }
            _ => return None,
        };
        Some(serde_json::to_value(&schema).unwrap())
    }

    /// Deserialize into the typed model and serialize back.
    fn round_trip(self, v: &Value) -> Value {
        fn go<T: serde::Serialize + serde::de::DeserializeOwned>(v: &Value) -> Value {
            let typed: T = serde_json::from_value(v.clone())
                .unwrap_or_else(|e| panic!("{}: {e}", std::any::type_name::<T>()));
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
            Kind::DoctorReport => go::<DoctorReport>(v),
            Kind::RunRecord => go::<RunRecord>(v),
            Kind::SetupPlan => go::<SetupPlan>(v),
            Kind::SetupResult => go::<SetupResult>(v),
            Kind::EnsureData => go::<EnsureData>(v),
            Kind::RevokeData => go::<RevokeData>(v),
            Kind::EnrollmentPlan => go::<heimdall_contract::enrollment::EnrollmentPlan>(v),
            Kind::EnrollmentResult => go::<heimdall_contract::enrollment::EnrollmentResult>(v),
            Kind::IssuerStatus => go::<heimdall_contract::issuer::IssuerStatus>(v),
            Kind::EnrollmentsView => go::<heimdall_contract::enrollment::EnrollmentsView>(v),
            Kind::ConnectionsView => go::<heimdall_contract::managed::ConnectionsView>(v),
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
    ("envelope.error.decision-stale.json", Kind::EnvelopeError),
    ("event.operation-state-changed.json", Kind::Event),
    ("snapshot.operations.json", Kind::Snapshot),
    ("request.ensure.json", Kind::Request),
    ("request.revoke.json", Kind::Request),
    ("request.policy-cutoff.json", Kind::Request),
    ("request.observe-events.json", Kind::Request),
    ("request.decide.json", Kind::Request),
    ("request.confirm-time.json", Kind::Request),
    ("ipc.client-message.hello.json", Kind::ClientMessage),
    ("ipc.client-message.request.json", Kind::ClientMessage),
    ("ipc.client-message.subscribe.json", Kind::ClientMessage),
    ("ipc.client-message.attend.json", Kind::ClientMessage),
    ("ipc.server-message.hello.json", Kind::ServerMessage),
    ("ipc.server-message.reject.json", Kind::ServerMessage),
    ("ipc.server-message.response.json", Kind::ServerMessage),
    ("ipc.server-message.subscribed.json", Kind::ServerMessage),
    ("ipc.server-message.goodbye.json", Kind::ServerMessage),
    // ADR-0006 revision 3 (m02-plan section 5; U0 "the new examples").
    ("request.setup.preview-apply.json", Kind::Request),
    ("request.setup.preview-rollback.json", Kind::Request),
    ("request.setup.preview-repair.json", Kind::Request),
    ("request.setup.apply.json", Kind::Request),
    ("request.setup.rollback.json", Kind::Request),
    ("request.setup.repair.json", Kind::Request),
    ("request.catalog.upsert-destination.json", Kind::Request),
    (
        "request.catalog.upsert-destination-observed.json",
        Kind::Request,
    ),
    ("request.catalog.remove-destination.json", Kind::Request),
    ("request.catalog.adopt-identity.json", Kind::Request),
    (
        "request.catalog.adopt-identity-onepassword.json",
        Kind::Request,
    ),
    ("request.catalog.remove-identity.json", Kind::Request),
    ("request.catalog.upsert-profile.json", Kind::Request),
    ("request.catalog.remove-profile.json", Kind::Request),
    ("request.catalog.declare-interaction.json", Kind::Request),
    ("request.catalog.withdraw-declaration.json", Kind::Request),
    ("request.bind-launch.json", Kind::Request),
    ("doctor-report.json", Kind::DoctorReport),
    ("run-record.prelaunch-failed.json", Kind::RunRecord),
    ("run-record.launching.json", Kind::RunRecord),
    ("run-record.spawned.json", Kind::RunRecord),
    ("run-record.exited.json", Kind::RunRecord),
    ("setup-plan.apply.json", Kind::SetupPlan),
    ("setup-plan.rollback-manual.json", Kind::SetupPlan),
    ("setup-result.held.json", Kind::SetupResult),
    (
        "envelope.success.ensure-existing-access.json",
        Kind::EnvelopeEnsure,
    ),
    ("envelope.error.projection-held.json", Kind::EnvelopeError),
    ("envelope.error.launch-failed.json", Kind::EnvelopeError),
    (
        "envelope.error.driver-unavailable.json",
        Kind::EnvelopeError,
    ),
    ("envelope.error.provider-locked.json", Kind::EnvelopeError),
    // ADR-0006 revision 4 (m03-plan section 5; U0 "the new examples round-trip").
    ("request.issuer.status.json", Kind::Request),
    ("request.issuer.register.json", Kind::Request),
    ("request.issuer.register-rotation.json", Kind::Request),
    ("request.issuer.unlock.json", Kind::Request),
    ("request.issuer.retire.json", Kind::Request),
    // ⟨ADR-0008 §17.22 item 12⟩ The store-item report, the restore's compare-and-swap,
    // the owner-present CLI's deletion confirmation.
    ("request.issuer.register-report.json", Kind::Request),
    ("request.issuer.register-restore.json", Kind::Request),
    ("request.issuer.retire-confirm.json", Kind::Request),
    ("request.issuer.bundle.json", Kind::Request),
    // ⟨ADR-0008 §17.25 item 8⟩ The CLI's written-bundle confirmation.
    ("request.issuer.bundle-written.json", Kind::Request),
    ("request.enrollment.preview.json", Kind::Request),
    ("request.enrollment.apply.json", Kind::Request),
    ("request.enrollment.verify.json", Kind::Request),
    ("request.enrollment.remove.json", Kind::Request),
    ("request.enrollment.remove-foreign.json", Kind::Request),
    ("request.enrollment.reconcile.json", Kind::Request),
    ("request.enrollment.abandon.json", Kind::Request),
    ("request.enrollment.step.json", Kind::Request),
    ("request.enrollment.step-result.json", Kind::Request),
    ("enrollment-plan.json", Kind::EnrollmentPlan),
    ("enrollment-result.json", Kind::EnrollmentResult),
    ("ensure-data.managed.json", Kind::EnsureData),
    ("revoke-data.managed.json", Kind::RevokeData),
    ("inspect.enrollments.json", Kind::EnrollmentsView),
    ("inspect.issuer.json", Kind::IssuerStatus),
    ("inspect.issuer.awaiting-deletion.json", Kind::IssuerStatus),
    ("inspect.connections.json", Kind::ConnectionsView),
];

fn load(file: &str) -> (String, Value) {
    let path = repo_root().join("schemas/examples").join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("example {file} unreadable: {}", e.kind()));
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
    (text, value)
}

/// A payload kind's schema: the envelope document's `$defs` with a root `$ref` to the
/// payload's definition.
fn payload_schema(kind: Kind, envelope: Value) -> Value {
    match kind.payload_def() {
        Some(def) => json!({
            "$defs": envelope["$defs"].clone(),
            "$ref": format!("#/$defs/{def}"),
        }),
        None => envelope,
    }
}

fn schema_doc(kind: Kind) -> Value {
    if let Some(generated) = kind.generated_only() {
        return generated;
    }
    let named = public_schemas()
        .into_iter()
        .find(|s| s.name == kind.schema_name())
        .unwrap();
    payload_schema(kind, serde_json::to_value(&named.schema).unwrap())
}

/// `None` only for the M03 kinds without a public schema file.
fn checked_in_schema(kind: Kind) -> Option<Value> {
    if kind.generated_only().is_some() {
        return None;
    }
    let path = repo_root()
        .join("schemas/public-api")
        .join(format!("{}.schema.json", kind.schema_name()));
    Some(payload_schema(
        kind,
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(),
    ))
}

/// Strings carry no control character, except the line feeds and tabs of a rendered
/// diff (`FileChange.diff`, m02-plan section 5 item 2), which is multi-line file text
/// by design. ESC and every other control character stay refused there too.
fn all_strings_are_clean(label: &str, v: &Value) {
    fn walk(label: &str, key: Option<&str>, v: &Value) {
        match v {
            Value::String(s) => {
                // ⟨M03⟩ `StepResult.stdout` is HM1 lines (m03-plan section 5 item 3).
                let multiline = matches!(key, Some("diff" | "stdout"));
                assert!(
                    !s.chars()
                        .any(|c| c.is_control() && !(multiline && matches!(c, '\n' | '\t'))),
                    "{label}: control character in a string"
                );
                assert_clean(label, s);
            }
            Value::Array(items) => items.iter().for_each(|i| walk(label, key, i)),
            Value::Object(map) => map.iter().for_each(|(k, i)| walk(label, Some(k), i)),
            _ => {}
        }
    }
    walk(label, None, v);
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
            ("generated", Some(schema_doc(*kind))),
            ("checked-in", checked_in_schema(*kind)),
        ] {
            let Some(schema) = schema else {
                continue;
            };
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
    let mut refused = Vec::new();
    for (file, kind) in EXAMPLES {
        let (_, original) = load(file);
        let mut extended = original.clone();
        inject(&mut extended, KEY);
        // Every file is tried, so a failure names all the examples it affects.
        let Ok(mut back) = std::panic::catch_unwind(|| kind.round_trip(&extended)) else {
            refused.push(*file);
            continue;
        };
        strip(&mut back, KEY);
        assert_eq!(back, original, "{file}: unknown fields changed known ones");
    }
    assert!(
        refused.is_empty(),
        "an unknown field at some nesting level is refused in: {refused:?}"
    );
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
        ("envelope.error.decision-stale.json", ExitCode::Conflict),
        (
            "envelope.error.outcome-unknown.json",
            ExitCode::OutcomeUnknown,
        ),
        // ADR-0006 revision 3.
        (
            "envelope.error.projection-held.json",
            ExitCode::OutcomeUnknown,
        ),
        ("envelope.error.launch-failed.json", ExitCode::LaunchFailed),
        ("envelope.error.driver-unavailable.json", ExitCode::Denied),
        (
            "envelope.error.provider-locked.json",
            ExitCode::InteractionRequired,
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
        vec![1, 2, 3, 4, 5, 6, 7, 127],
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
        let (_, mut v) = load(file);
        // ⟨M03⟩ `step_token` is the step's correlation nonce (32 hex), returned in the
        // `RemoteStep` the CLI runs; m03-plan section 5 item 3 names it and states the
        // step carries no secret. Only that exact field is exempt.
        if *file == "request.enrollment.step-result.json" {
            assert!(v.as_object_mut().unwrap().remove("step_token").is_some());
        }
        walk(&v, file);
    }
}

#[test]
fn emitted_documents_always_materialize_next_and_warnings() {
    // ADR-0006 section 3: `warnings` is always an array, `next` always present
    // (null when nothing is expected). The generated schema lists both as required
    // (wave-1 E5, `schema_export::envelope_schemas_require_warnings_and_next`); a
    // lenient reader still defaults them. This pins the emitted form.
    let ok = serde_json::to_value(Envelope::ok(json!({}))).unwrap();
    let obj: &Map<String, Value> = ok.as_object().unwrap();
    assert!(obj["next"].is_null());
    assert_eq!(obj["warnings"], json!([]));
    assert!(!obj.contains_key("operation_id"), "omitted, not null");
}

#[test]
fn decision_stale_example_matches_its_table_row() {
    let env: Envelope<ErrorData> =
        serde_json::from_value(load("envelope.error.decision-stale.json").1).unwrap();
    assert_eq!(env.code, Code::DecisionStale);
    assert_eq!(env.state, OperationState::Failed);
    assert_eq!(env.code.exit_code().as_i32(), 6);
    let err = &env.data.error;
    assert_eq!(err.effect_status, EffectStatus::None);
    assert!(!err.retryable);
    assert_eq!(err.next.action, "fix_request");
    let resource = err.resource.as_ref().unwrap();
    assert_eq!(resource.kind, "decision");
    assert!(DecisionId::parse(resource.id.as_deref().unwrap()).is_ok());
}

#[test]
fn decide_and_confirm_time_examples_are_attended_only_requests() {
    // ADR-0006 section 3.1: both are served on attended sessions only.
    let decide: Request = serde_json::from_value(load("request.decide.json").1).unwrap();
    let Request::Decide(DecideRequest {
        decision_id,
        verdict,
    }) = &decide
    else {
        panic!("not a decide request: {decide:?}");
    };
    assert_eq!(decision_id.as_str(), "dec_00112233445566778899aabbccddeeff");
    assert_eq!(*verdict, Verdict::Approve);
    assert_eq!(decide.kind(), "decide");
    assert!(decide.requires_attended_session());
    assert!(decide.is_effectful());

    let confirm: Request = serde_json::from_value(load("request.confirm-time.json").1).unwrap();
    let Request::ConfirmTime(ConfirmTimeRequest { observed_wall }) = &confirm else {
        panic!("not a confirm_time request: {confirm:?}");
    };
    assert_eq!(
        *observed_wall,
        "2026-10-31T12:00:05Z"
            .parse::<heimdall_contract::Timestamp>()
            .unwrap()
    );
    assert_eq!(confirm.kind(), "confirm_time");
    assert!(confirm.requires_attended_session());

    // Unattended requests stay unattended; only the widening policy actions join.
    for file in [
        "request.ensure.json",
        "request.revoke.json",
        "request.policy-cutoff.json",
    ] {
        let r: Request = serde_json::from_value(load(file).1).unwrap();
        assert!(!r.requires_attended_session(), "{file}");
    }
    // A decision ID of another kind is refused at the boundary.
    let mut bad = load("request.decide.json").1;
    bad["decision_id"] = json!("op_00112233445566778899aabbccddeeff");
    assert!(serde_json::from_value::<Request>(bad).is_err());
    let mut bad = load("request.decide.json").1;
    bad["verdict"] = json!("maybe");
    assert!(serde_json::from_value::<Request>(bad).is_err());
}

#[test]
fn client_hello_interaction_defaults_to_non_interactive() {
    let (_, hello) = load("ipc.client-message.hello.json");
    let ClientMessage::Hello(declared) = serde_json::from_value(hello.clone()).unwrap() else {
        panic!("not a hello");
    };
    assert_eq!(declared.interaction, InteractionMode::Interactive);

    // An older client that omits the field is non-interactive, never attended.
    let mut legacy = hello;
    legacy.as_object_mut().unwrap().remove("interaction");
    let ClientMessage::Hello(omitted) = serde_json::from_value(legacy).unwrap() else {
        panic!("not a hello");
    };
    assert_eq!(omitted.interaction, InteractionMode::NonInteractive);
    assert_eq!(
        ClientHello {
            interaction: InteractionMode::Interactive,
            ..omitted.clone()
        },
        declared
    );
    let schema = schema_doc(Kind::ClientMessage);
    let mut written = serde_json::to_value(ClientMessage::Hello(omitted)).unwrap();
    assert_eq!(written["interaction"], json!("non_interactive"));
    assert!(validate(&schema, &written).is_ok());
    written["interaction"] = json!("attended");
    assert!(
        validate(&schema, &written).is_err(),
        "unknown interaction mode"
    );
}

#[test]
fn attend_and_subscribed_examples_parse_to_the_documented_shapes() {
    let ClientMessage::Attend { seq } =
        serde_json::from_value(load("ipc.client-message.attend.json").1).unwrap()
    else {
        panic!("not an attend frame");
    };
    assert_eq!(seq, 3);

    let (_, subscribed) = load("ipc.server-message.subscribed.json");
    let ServerMessage::Subscribed {
        in_reply_to,
        subscription,
        cursor,
        snapshot,
    } = serde_json::from_value(subscribed.clone()).unwrap()
    else {
        panic!("not a subscribed frame");
    };
    assert_eq!((in_reply_to, subscription), (2, 1));
    let snapshot: Snapshot<Value> = snapshot.expect("snapshot present");
    // With a snapshot, the stream continues after the snapshot's own boundary.
    assert_eq!(snapshot.cursor, cursor);
    // Without one (the client resumed from its cursor) the field is omitted.
    let mut resumed = subscribed;
    resumed.as_object_mut().unwrap().remove("snapshot");
    let back = Kind::ServerMessage.round_trip(&resumed);
    assert_eq!(back, resumed);
    assert!(back.get("snapshot").is_none(), "omitted, not null");
    assert!(validate(&schema_doc(Kind::ServerMessage), &resumed).is_ok());
}
