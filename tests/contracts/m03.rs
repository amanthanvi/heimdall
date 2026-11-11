//! ADR-0006 revision 4 contract deltas (m03-plan revision 6, section 5; U0 "Tests").
//!
//! Every expected value is transcribed from `docs/architecture/m03-plan.md` and
//! ADR-0008 (rulings win), never from the code under test:
//! * `contract_code_table_unchanged_30_rows`: M03 adds reasons, never codes;
//! * `contract_reason_golden`: every section 5 item 14 reason with its code
//!   (`golden/m03-reasons.golden.json`) against `envelope::reason::M03`, both ways,
//!   plus the warnings and doctor findings under the table;
//! * `public_schema_has_no_scratch_store_kind` (F23);
//! * the additive-field decodes: `revoke_data_timestamps_golden`,
//!   `revoke_data_without_timestamps_decodes`, `ensure_data_without_m03_fields_decodes`,
//!   `enforcement_without_m03_fields_decodes_unknown`;
//! * the managed `ensure` example's values (section 5 item 8, an empty claim table), the
//!   capability names (item 15), the request classes and the policy widening rule.
//!
//! The new `schemas/examples/` files round-trip and validate in `examples.rs`. Every
//! key, fingerprint and host there is a synthetic placeholder, never a real key.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use heimdall_contract::code::Code;
use heimdall_contract::doctor::finding;
use heimdall_contract::envelope::{m03_warning, reason};
use heimdall_contract::ids::{CaFingerprint, EnrollmentId};
use heimdall_contract::ipc::capability;
use heimdall_contract::managed::{
    DestinationClock, ExistingConnectionsMode, IdentitySelectionEnforcement, IssuerIsolation,
    LockBehavior, LockContinuityReport, MultiplexingMode, NewSigningExpiry, OwnedMultiplexing,
    RemoteProcesses, RemoteRevocation, RevokeNote, UnmanagedConnections,
};
use heimdall_contract::request::{
    EnsureData, EnsureRequest, InspectSubject, NewAuthenticationExpiry, PolicyAction, Request,
    RevokeData,
};
use heimdall_contract::schema::public_schemas;

use crate::{assert_clean, repo_root};

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|e| panic!("{path} unreadable: {}", e.kind()));
    assert_clean(path, &text);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn code_named(name: &str) -> &'static Code {
    Code::all()
        .iter()
        .find(|c| c.as_str() == name)
        .unwrap_or_else(|| panic!("no code {name}"))
}

/// m03-plan section 5: "The code table stays at 30 rows"; new reasons only.
#[test]
fn contract_code_table_unchanged_30_rows() {
    assert_eq!(Code::all().len(), 30);
    let golden = load("tests/contracts/golden/code-table.golden.json");
    let rows = golden["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 30);
    let golden_names: BTreeSet<&str> = rows.iter().map(|r| r["code"].as_str().unwrap()).collect();
    let code_names: BTreeSet<&str> = Code::all().iter().map(Code::as_str).collect();
    assert_eq!(golden_names, code_names);
    // Every M03 reason uses one of the existing codes.
    for (r, c) in reason::M03 {
        assert!(code_names.contains(c.as_str()), "{r} uses an unknown code");
    }
}

/// m03-plan section 5 item 14: every new stable sub-reason with its code, both ways;
/// `driver_unavailable` exists already (M02) and stays in `reason::ALL`, which is
/// otherwise unchanged; the warnings and doctor findings under the table.
#[test]
fn contract_reason_golden() {
    let golden = load("tests/contracts/golden/m03-reasons.golden.json");
    let pairs = |key: &str| -> BTreeSet<(String, String)> {
        golden[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["reason"].as_str().unwrap().to_owned(),
                    r["code"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };
    let new = pairs("new");
    let existing = pairs("existing");
    assert_eq!(
        new.len(),
        golden["new"].as_array().unwrap().len(),
        "duplicate golden rows"
    );
    let code: BTreeSet<(String, String)> = reason::M03
        .iter()
        .map(|(r, c)| ((*r).to_owned(), c.as_str().to_owned()))
        .collect();
    assert_eq!(code.len(), reason::M03.len(), "duplicate reason::M03 rows");
    let missing: Vec<_> = new.difference(&code).collect();
    let extra: Vec<_> = code.difference(&new).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "reason::M03 vs plan §5 item 14: missing {missing:?}, not in the plan {extra:?}"
    );
    // A reason names one code.
    let names: BTreeSet<&str> = reason::M03.iter().map(|(r, _)| *r).collect();
    assert_eq!(
        names.len(),
        reason::M03.len(),
        "a reason listed with two codes"
    );
    for (r, c) in &existing {
        code_named(c);
        assert!(reason::ALL.contains(&r.as_str()), "{r} exists (M02)");
        assert!(!names.contains(r.as_str()), "{r} is not repeated in M03");
    }
    for r in &names {
        assert!(
            !reason::ALL.contains(r),
            "{r}: reason::ALL stays M02's list"
        );
        assert!(
            r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "{r} is not snake_case"
        );
    }
    for (_, c) in &new {
        code_named(c);
    }
    let set =
        |key: &str| -> BTreeSet<String> { serde_json::from_value(golden[key].clone()).unwrap() };
    let warnings: BTreeSet<String> = m03_warning::ALL.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(warnings, set("warnings"), "M03 warnings");
    let findings: BTreeSet<String> = finding::M03.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(findings, set("doctor_findings"), "M03 doctor findings");
}

/// m03-plan section 5 item 2 (F23): no test store kind in any public schema; the
/// public `StoreKind` is exactly the four platform stores.
#[test]
fn public_schema_has_no_scratch_store_kind() {
    for s in public_schemas() {
        let text = serde_json::to_string(&s.schema).unwrap();
        assert!(
            !text.contains("scratch"),
            "{}: scratch in the schema",
            s.name
        );
        let path = repo_root()
            .join("schemas/public-api")
            .join(format!("{}.schema.json", s.name));
        let checked = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} unreadable: {}", s.name, e.kind()));
        assert!(!checked.contains("scratch"), "{}: checked-in", s.name);
    }
    let status = public_schemas()
        .into_iter()
        .find(|s| s.name == "issuer-status")
        .expect("issuer-status schema (§5 item 23)");
    let doc = serde_json::to_value(&status.schema).unwrap();
    let kinds: BTreeSet<String> = doc["$defs"]["StoreKind"]["oneOf"]
        .as_array()
        .expect("StoreKind alternatives")
        .iter()
        .map(|alt| alt["const"].as_str().unwrap().to_owned())
        .collect();
    let want: BTreeSet<String> = [
        "macos_login_keychain",
        "macos_data_protection_keychain",
        "windows_dpapi",
        "linux_secret_service",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert_eq!(kinds, want);
    for name in [
        "enrollment-plan",
        "enrollment-result",
        "issuer-status",
        "recovery-bundle",
    ] {
        assert!(
            public_schemas().iter().any(|s| s.name == name),
            "{name} schema (§5 item 23)"
        );
    }
}

/// m03-plan section 5 item 9 (⟨r5⟩; §17.10 item 3): the frozen golden carries
/// `requested_at` and `committed_at`, round-trips exactly, and reports the managed
/// facts (remote effects with their status, owned connections, the fixed note).
#[test]
fn revoke_data_timestamps_golden() {
    let v = load("schemas/examples/revoke-data.managed.json");
    let data: RevokeData = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(serde_json::to_value(&data).unwrap(), v, "round trip");
    let requested = data.requested_at.expect("requested_at");
    let committed = data.committed_at.expect("committed_at");
    assert!(committed >= requested, "committed after requested");
    assert_eq!(v["requested_at"], json!("2026-11-10T15:00:00Z"));
    assert_eq!(v["committed_at"], json!("2026-11-10T15:00:00.214Z"));
    assert!(
        data.notes
            .contains(&RevokeNote::OrdinaryConnectionsNotClosed),
        "always present for a managed revoke (F15)"
    );
    assert!(!data.remote_effects.is_empty() && !data.owned_connections.is_empty());
    let effect = &data.remote_effects[0];
    assert!(matches!(
        effect.destination_clock,
        DestinationClock::Measured(_)
    ));
    assert!(effect.until.is_some(), "the completion bound when measured");
}

/// m03-plan U0 ⟨r5⟩: an M01/M02 `RevokeData` without the timestamps still decodes,
/// and re-encodes unchanged.
#[test]
fn revoke_data_without_timestamps_decodes() {
    let env = load("schemas/examples/envelope.success.revoke.json");
    let data: RevokeData = serde_json::from_value(env["data"].clone()).unwrap();
    assert_eq!(data.requested_at, None);
    assert_eq!(data.committed_at, None);
    assert!(data.remote_effects.is_empty() && data.owned_connections.is_empty());
    assert!(data.notes.is_empty());
    assert_eq!(serde_json::to_value(&data).unwrap(), env["data"]);
}

/// m03-plan U0: an M02 `EnsureData` reads `lock_continuity: not_verified`, empty
/// `conditions`, absent `revocation`, and re-encodes unchanged.
#[test]
fn ensure_data_without_m03_fields_decodes() {
    for file in [
        "schemas/examples/envelope.success.ensure.json",
        "schemas/examples/envelope.success.ensure-existing-access.json",
    ] {
        let env = load(file);
        let data: EnsureData = serde_json::from_value(env["data"].clone()).unwrap();
        assert_eq!(
            data.lock_continuity(),
            LockContinuityReport::NotVerified,
            "{file}"
        );
        assert!(data.conditions.is_empty(), "{file}");
        assert!(data.revocation.is_none(), "{file}");
        assert!(data.refresh_condition.is_none(), "{file}");
        assert!(data.evidence.is_empty(), "{file}");
        assert!(data.connection_policy.is_none(), "{file}");
        assert_eq!(
            serde_json::to_value(&data).unwrap(),
            env["data"],
            "{file}: re-encodes unchanged"
        );
    }
}

/// m03-plan section 5 item 8: each new `Enforcement` field reads `unknown` when absent,
/// and an M01/M02 enforcement block re-encodes unchanged.
#[test]
fn enforcement_without_m03_fields_decodes_unknown() {
    let env = load("schemas/examples/envelope.success.ensure.json");
    let data: EnsureData = serde_json::from_value(env["data"].clone()).unwrap();
    let e = &data.enforcement;
    assert_eq!(
        e.identity_selection(),
        IdentitySelectionEnforcement::Unknown
    );
    assert_eq!(e.new_signing_expiry(), NewSigningExpiry::Unknown);
    assert_eq!(e.owned_multiplexing(), OwnedMultiplexing::Unknown);
    assert_eq!(e.remote_processes(), RemoteProcesses::Unknown);
    assert_eq!(e.unmanaged_connections(), UnmanagedConnections::Unknown);
    assert_eq!(e.issuer_isolation(), IssuerIsolation::Unknown);
    assert_eq!(
        serde_json::to_value(e).unwrap(),
        env["data"]["enforcement"],
        "an M02 enforcement block re-encodes unchanged"
    );
    // `ExistingConnectionsPolicy` gains `not_controlled` (D8 item 2).
    let mut v = env["data"]["enforcement"].clone();
    v["existing_connections"] = json!("not_controlled");
    let back: heimdall_contract::request::Enforcement = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), v);
}

/// m03-plan section 5 item 8: the managed `ensure` example, with the values an empty
/// claim table gives: the claim-gated fields stay `unknown`; `destination_scope` and
/// `identity_selection` are runtime evidence; the limitations are reported from the
/// start; `latest_possible_credential_expiry` and `destination_clock` are computed.
#[test]
fn ensure_data_managed_example_matches_plan() {
    let v = load("schemas/examples/ensure-data.managed.json");
    let data: EnsureData = serde_json::from_value(v.clone()).unwrap();
    let e = &data.enforcement;
    // Claim-gated (ADR-0008 D12; F11): unknown with an empty claim table.
    assert_eq!(e.new_signing_expiry(), NewSigningExpiry::Unknown);
    assert_eq!(
        e.new_authentication_expiry,
        NewAuthenticationExpiry::Unknown
    );
    assert_eq!(v["enforcement"]["existing_connections"], json!("unknown"));
    assert_eq!(v["enforcement"]["revocation"], json!("unknown"));
    let revocation = data.revocation.as_ref().expect("revocation semantics");
    assert_eq!(revocation.remote, RemoteRevocation::Unknown);
    // Runtime evidence.
    assert_eq!(
        v["enforcement"]["destination_scope"],
        json!("verified_server_principals")
    );
    assert_eq!(
        e.identity_selection(),
        IdentitySelectionEnforcement::ClientConfigurationAndSigner
    );
    // Limitations and the binding's own configuration.
    assert_eq!(e.owned_multiplexing(), OwnedMultiplexing::Disabled);
    assert_eq!(e.remote_processes(), RemoteProcesses::NotTerminated);
    assert_eq!(
        e.unmanaged_connections(),
        UnmanagedConnections::NotControlled
    );
    assert_eq!(e.issuer_isolation(), IssuerIsolation::SameUserProcess);
    assert_eq!(
        v["enforcement"]["workload_isolation"],
        json!("shared_os_user")
    );
    // Computed facts, not claims.
    assert!(revocation.latest_possible_credential_expiry.is_some());
    assert!(matches!(
        revocation.destination_clock,
        DestinationClock::Measured(_)
    ));
    assert_eq!(data.lock_continuity(), LockContinuityReport::NotVerified);
    assert_eq!(v["refresh_dependency"], json!("local_issuer"));
    assert_eq!(v["credential_availability"], json!("through_deadline"));
    // A Windows result: no `issuer_store_unlocked_at_start` (macOS only, F03).
    assert_eq!(
        v["conditions"],
        json!(["signer_running", "time_confirmation_after_reboot"])
    );
    // ADR-0008 §17.20 items 14 and 15 (U6-Q6, W3-R2-Q1): the consumer integration of a
    // managed binding names the **binding** endpoint (D10 item 4) as the locator the
    // product emits and `connect` parses, `\\.\pipe\heimdall-<token>-b<tag>` with a
    // 16-hex tag, never the environment endpoint (`…-signing`) or P's rendered spelling.
    let endpoint = v["consumer"]["signing_endpoint"]
        .as_str()
        .expect("signing endpoint");
    let (token, tag) = endpoint
        .strip_prefix(r"\\.\pipe\heimdall-")
        .and_then(|rest| rest.rsplit_once("-b"))
        .expect("the binding endpoint form");
    assert!(!token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric()));
    assert!(tag.len() == 16 && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert!(!endpoint.ends_with("-signing"));
}

/// m03-plan section 5 item 15: the four capability names, declared (offered only in
/// phase 2, which `heimdall_ipc::session` tests).
#[test]
fn m03_capabilities_declared() {
    assert_eq!(capability::ISSUER_V1, "issuer/1");
    assert_eq!(capability::ENROLLMENT_V1, "enrollment/1");
    assert_eq!(capability::MANAGED_CREDENTIALS_V1, "managed-credentials/1");
    assert_eq!(capability::CONNECTIONS_V1, "connections/1");
    let declared: BTreeSet<&str> = capability::M03_DECLARED.iter().copied().collect();
    assert_eq!(declared.len(), 4);
    for c in [
        capability::OPERATIONS_V1,
        capability::EVENTS_V1,
        capability::OWNER_POLICY_V1,
        capability::SCHEMA_DISCOVERY_V1,
        capability::SERVICE_CONTROL_V1,
        capability::SETUP_V1,
    ] {
        assert!(!declared.contains(c), "{c} is not an M03 capability");
    }
}

/// m03-plan section 5 items 2, 3, 4a: each new request needs its capability;
/// `issuer.unlock` is attended-only, the others are not.
#[test]
fn m03_requests_need_their_capability_and_unlock_is_attended() {
    let cases = [
        (
            "schemas/examples/request.issuer.status.json",
            "issuer/1",
            false,
        ),
        (
            "schemas/examples/request.issuer.register.json",
            "issuer/1",
            false,
        ),
        (
            "schemas/examples/request.issuer.unlock.json",
            "issuer/1",
            true,
        ),
        (
            "schemas/examples/request.issuer.retire.json",
            "issuer/1",
            false,
        ),
        (
            "schemas/examples/request.issuer.bundle.json",
            "issuer/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.preview.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.apply.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.verify.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.remove.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.reconcile.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.abandon.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.step.json",
            "enrollment/1",
            false,
        ),
        (
            "schemas/examples/request.enrollment.step-result.json",
            "enrollment/1",
            false,
        ),
    ];
    for (file, cap, attended) in cases {
        let r: Request = serde_json::from_value(load(file)).unwrap();
        assert_eq!(r.required_capability(), Some(cap), "{file}");
        assert_eq!(r.requires_attended_session(), attended, "{file}");
    }
    for v in [
        json!({"op": "connections", "action": "close",
               "connection_id": "conn_00112233445566778899aabbccddeeff"}),
        json!({"op": "connections", "action": "register",
               "binding_id": "binding_0123456789abcdef0123456789abcdef", "pid": 4242,
               "created_at": "2026-11-10T14:05:00Z",
               "image": "C:\\Windows\\System32\\OpenSSH\\ssh.exe"}),
    ] {
        let r: Request = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert_eq!(r.required_capability(), Some("connections/1"), "{v}");
        assert!(!r.requires_attended_session(), "{v}");
    }
}

/// m03-plan section 5 items 6 and 11 (U0b row 11): `SetLockBehavior{continue}`,
/// `SetConnectionPolicy{existing: graceful}` and `{multiplexing: owned_masters}` are
/// widening; the others are narrowing.
#[test]
fn policy_lock_and_connection_widening_classification() {
    let p = || heimdall_contract::ids::PolicyId::parse("default").unwrap();
    let cases = [
        (
            PolicyAction::SetLockBehavior {
                policy_id: p(),
                behavior: LockBehavior::Continue,
            },
            true,
        ),
        (
            PolicyAction::SetLockBehavior {
                policy_id: p(),
                behavior: LockBehavior::RevokeOnLock,
            },
            false,
        ),
        (
            PolicyAction::SetConnectionPolicy {
                policy_id: p(),
                existing: Some(ExistingConnectionsMode::Graceful),
                multiplexing: None,
            },
            true,
        ),
        (
            PolicyAction::SetConnectionPolicy {
                policy_id: p(),
                existing: Some(ExistingConnectionsMode::Strict),
                multiplexing: None,
            },
            false,
        ),
        (
            PolicyAction::SetConnectionPolicy {
                policy_id: p(),
                existing: None,
                multiplexing: Some(MultiplexingMode::OwnedMasters),
            },
            true,
        ),
        (
            PolicyAction::SetConnectionPolicy {
                policy_id: p(),
                existing: None,
                multiplexing: Some(MultiplexingMode::Disabled),
            },
            false,
        ),
        (
            PolicyAction::SetConnectionPolicy {
                policy_id: p(),
                existing: Some(ExistingConnectionsMode::Strict),
                multiplexing: Some(MultiplexingMode::OwnedMasters),
            },
            true,
        ),
    ];
    for (action, widening) in cases {
        assert_eq!(action.is_widening(), widening, "{action:?}");
        let r = Request::Policy(action);
        assert!(!r.requires_attended_session(), "{r:?}");
        assert_eq!(r.kind(), "policy");
    }
    // Wire forms (§5 item 6).
    let v = serde_json::to_value(PolicyAction::SetLockBehavior {
        policy_id: p(),
        behavior: LockBehavior::RevokeOnLock,
    })
    .unwrap();
    assert_eq!(v["behavior"], json!("revoke_on_lock"));
}

/// m03-plan section 5 items 1, 4, 5 and 13: ID forms, the inspect subjects, the
/// `ensure` connection field (omitted when absent, so an M02 request is unchanged),
/// the event types and the credential lifecycle values.
#[test]
fn m03_wire_forms_and_m02_requests_unchanged() {
    let e = EnrollmentId::from_random_bytes([0xab; 16]);
    assert!(e.as_str().starts_with("enr_"), "§5 item 1");
    assert!(CaFingerprint::parse(&format!("SHA256:{}", "Q".repeat(43))).is_ok());
    assert!(CaFingerprint::parse(&format!("SHA256:{}", "Q".repeat(42))).is_err());
    for (s, name) in [
        (InspectSubject::Enrollments, "enrollments"),
        (InspectSubject::Issuer, "issuer"),
        (InspectSubject::Connections, "connections"),
    ] {
        assert_eq!(serde_json::to_value(s).unwrap(), json!(name));
    }
    let m02 = load("schemas/examples/request.ensure.json");
    let r: EnsureRequest = serde_json::from_value(m02.clone()).unwrap();
    assert!(r.connection.is_none());
    let back = serde_json::to_value(Request::Ensure(r)).unwrap();
    assert!(back.get("connection").is_none(), "omitted when absent");
    assert_eq!(back, m02, "an M02 ensure request re-encodes unchanged");
    let mut strict = m02.clone();
    strict["connection"] = json!({"existing": "strict"});
    let r: Request = serde_json::from_value(strict.clone()).unwrap();
    assert_eq!(serde_json::to_value(r).unwrap(), strict);
    for (t, name) in [
        (
            heimdall_contract::event::EventType::Enrollment,
            "enrollment",
        ),
        (
            heimdall_contract::event::EventType::Connection,
            "connection",
        ),
        (
            heimdall_contract::event::EventType::SessionLock,
            "session_lock",
        ),
    ] {
        assert_eq!(serde_json::to_value(t).unwrap(), json!(name));
    }
    for v in [
        "reserved",
        "published",
        "voided",
        "installed",
        "destroyed",
        "lost",
        "reissued",
    ] {
        let e: heimdall_contract::managed::CredentialLifecycleEvent =
            serde_json::from_value(json!(v)).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert_eq!(serde_json::to_value(e).unwrap(), json!(v));
    }
}
