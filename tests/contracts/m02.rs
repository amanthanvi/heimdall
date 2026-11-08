//! ADR-0006 revision 3 contract deltas (m02-plan section 5; U0 "Tests").
//!
//! * `journaled_operation_kinds_match_their_request_kind`: the contract half of the
//!   journaled-kind mapping (`golden/journaled-kinds.golden.json`, shared with the
//!   domain half that checks `OperationKind::as_str`), with completeness taken from
//!   the generated request schema, so a variant missing here fails;
//! * `bind_launch_without_argv` (Q8) and the launch-binding rules;
//! * `run_record_classify_golden`: every row of ADR-0007 section 8's reader table,
//!   checked against the ADR text, plus a property over arbitrary record sequences;
//! * the new error reasons, capabilities, inspect subjects and additive fields.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use serde_json::{Value, json};

use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{
    EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, reason,
};
use heimdall_contract::ids::IdentityId;
use heimdall_contract::ipc::capability;
use heimdall_contract::provider::{
    CredentialAvailability, InteractionKind, ProviderInteractionRef, ProviderKind,
    noninteractive_reason,
};
use heimdall_contract::request::{
    Admission, BindForm, EnsureData, InspectSubject, LaunchBinding, LaunchBindingError,
    ProcessHolder, Request, RequiredCapabilities,
};
use heimdall_contract::run_record::{LaunchClassification, RunPlatform, RunRecord, classify};
use heimdall_contract::schema::public_schemas;
use heimdall_contract::setup::{
    ConflictKind, PreviewIntent, PreviewIntentError, RepairResolution, SetupRequest, manual_reason,
};
use heimdall_contract::version::SchemaVersion;

use crate::{assert_clean, proptest_config, repo_root};

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|e| panic!("{path} unreadable: {}", e.kind()));
    assert_clean(path, &text);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn request(v: Value) -> Request {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"))
}

fn schema(name: &str) -> Value {
    serde_json::to_value(
        public_schemas()
            .into_iter()
            .find(|s| s.name == name)
            .unwrap()
            .schema,
    )
    .unwrap()
}

/// Every `(op, action)` the generated request schema admits; `action` is `None`
/// for ops without an action tag, and for `policy` (one admission class whatever
/// its action).
fn schema_ops_and_actions() -> BTreeSet<(String, Option<String>)> {
    let doc = schema("request");
    let mut out = BTreeSet::new();
    for alt in doc["oneOf"].as_array().unwrap() {
        let op = alt["properties"]["op"]["const"]
            .as_str()
            .unwrap()
            .to_owned();
        let actions: Vec<String> = alt["$ref"]
            .as_str()
            .and_then(|r| doc.pointer(r.trim_start_matches('#')))
            .and_then(|def| def["oneOf"].as_array())
            .map(|alts| {
                alts.iter()
                    .filter_map(|a| a["properties"]["action"]["const"].as_str())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if actions.is_empty() || op == "policy" {
            out.insert((op, None));
        } else {
            for a in actions {
                out.insert((op.clone(), Some(a)));
            }
        }
    }
    out
}

/// One request of every variant and every setup and catalog action.
fn one_of_every_request() -> Vec<Request> {
    let mut out: Vec<Request> = [
        "schemas/examples/request.ensure.json",
        "schemas/examples/request.revoke.json",
        "schemas/examples/request.policy-cutoff.json",
        "schemas/examples/request.observe-events.json",
        "schemas/examples/request.decide.json",
        "schemas/examples/request.confirm-time.json",
        "schemas/examples/request.shutdown.json",
        "schemas/examples/request.bind-launch.json",
        "schemas/examples/request.setup.preview-apply.json",
        "schemas/examples/request.setup.apply.json",
        "schemas/examples/request.setup.rollback.json",
        "schemas/examples/request.setup.repair.json",
        "schemas/examples/request.catalog.upsert-destination.json",
        "schemas/examples/request.catalog.remove-destination.json",
        "schemas/examples/request.catalog.adopt-identity.json",
        "schemas/examples/request.catalog.remove-identity.json",
        "schemas/examples/request.catalog.upsert-profile.json",
        "schemas/examples/request.catalog.remove-profile.json",
        "schemas/examples/request.catalog.declare-interaction.json",
        "schemas/examples/request.catalog.withdraw-declaration.json",
        // ⟨M03⟩ m03-plan U0: the new requests (section 5 items 2 and 3).
        "schemas/examples/request.issuer.status.json",
        "schemas/examples/request.issuer.register.json",
        "schemas/examples/request.issuer.unlock.json",
        "schemas/examples/request.issuer.retire.json",
        "schemas/examples/request.issuer.bundle.json",
        "schemas/examples/request.enrollment.preview.json",
        "schemas/examples/request.enrollment.apply.json",
        "schemas/examples/request.enrollment.verify.json",
        "schemas/examples/request.enrollment.remove.json",
        "schemas/examples/request.enrollment.reconcile.json",
        "schemas/examples/request.enrollment.abandon.json",
        "schemas/examples/request.enrollment.step.json",
        "schemas/examples/request.enrollment.step-result.json",
    ]
    .iter()
    .map(|p| request(load(p)))
    .collect();
    out.extend([
        request(json!({"op": "inspect", "subject": "identities"})),
        request(json!({
            "op": "delegate",
            "parent_binding_id": "binding_0123456789abcdef0123456789abcdef",
            "scope": [{"destination": "dest-1", "account": "deploy"}],
            "work_id": "work-43",
            "request_id": "req-0401"
        })),
        request(json!({"op": "cancel", "operation_id": "op_00112233445566778899aabbccddeeff"})),
        request(json!({"op": "release", "binding_id": "binding_0123456789abcdef0123456789abcdef"})),
        // ⟨M03⟩ section 5 items 4a (ADR-0008 D8 item 2 adds `image`) and 4b.
        request(json!({
            "op": "connections", "action": "close",
            "connection_id": "conn_00112233445566778899aabbccddeeff"
        })),
        request(json!({
            "op": "connections", "action": "register",
            "binding_id": "binding_0123456789abcdef0123456789abcdef", "pid": 4242,
            "created_at": "2026-11-10T14:05:00Z",
            "image": "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
        })),
        request(json!({
            "op": "catalog", "action": "set_preference", "destination": "dest-lab",
            "account": "deploy", "mechanism": "managed_certificate", "request_id": "req-0209"
        })),
    ]);
    out
}

fn op_and_action(r: &Request) -> (String, Option<String>) {
    let v = serde_json::to_value(r).unwrap();
    let op = v["op"].as_str().unwrap().to_owned();
    let action = if op == "policy" {
        None
    } else {
        v["action"].as_str().map(str::to_owned)
    };
    (op, action)
}

/// m02-plan U0 (rescoped in r3; E5 reading): for each journaled kind a request
/// satisfies `is_effectful()` and its admission names `kind()`; the effectful but
/// not journaled requests and the read-only ones are listed explicitly; no
/// `kind()` returns the reserved `probe`. The variant list is complete because it
/// covers every `op` and setup/catalog `action` of the generated schema, and
/// `Request::admission` matches every variant without a wildcard inside the
/// contract crate. The domain half (OperationKind::as_str and its serde form equal
/// the golden's names; Cancel, Release and Policy declared and never constructed)
/// reads the same golden file.
#[test]
fn journaled_operation_kinds_match_their_request_kind() {
    let golden = load("tests/contracts/golden/journaled-kinds.golden.json");
    let journaled: BTreeMap<String, String> =
        serde_json::from_value(golden["journaled"].clone()).unwrap();
    let journaled_kinds: BTreeSet<&str> = journaled.values().map(String::as_str).collect();
    let set = |k: &str| -> BTreeSet<String> {
        serde_json::from_value::<BTreeSet<String>>(golden[k].clone()).unwrap()
    };
    let synchronous = set("synchronous");
    let read_only = set("read_only");
    let reserved: BTreeMap<String, String> =
        serde_json::from_value(golden["reserved"].clone()).unwrap();

    let requests = one_of_every_request();
    let covered: BTreeSet<(String, Option<String>)> = requests.iter().map(op_and_action).collect();
    let from_schema = schema_ops_and_actions();
    assert_eq!(
        covered, from_schema,
        "the samples must cover every request variant and setup/catalog action"
    );

    let mut seen_journaled = BTreeSet::new();
    for r in &requests {
        let kind = r.kind();
        assert!(
            !reserved.values().any(|p| p == kind),
            "{kind}: reserved kind returned by Request::kind"
        );
        match r.admission() {
            Admission::Journaled(k) => {
                assert_eq!(k, kind, "journaled name equals Request::kind");
                assert!(r.is_effectful(), "{kind}");
                assert!(journaled_kinds.contains(k), "{k} not in the golden mapping");
                seen_journaled.insert(k);
            }
            Admission::Synchronous => {
                assert!(r.is_effectful(), "{kind}");
                assert!(synchronous.contains(kind), "{kind} not listed synchronous");
            }
            Admission::ReadOnly => {
                assert!(!r.is_effectful(), "{kind}");
                assert!(read_only.contains(kind), "{kind} not listed read-only");
            }
        }
    }
    assert_eq!(
        seen_journaled, journaled_kinds,
        "every journaled kind has a request"
    );
    // The three classes are disjoint, and the never-constructed kinds are exactly
    // the synchronous requests that have an OperationKind.
    assert!(synchronous.is_disjoint(&read_only));
    for k in &synchronous {
        assert!(!journaled_kinds.contains(k.as_str()), "{k}");
    }
    let never: BTreeMap<String, String> =
        serde_json::from_value(golden["declared_never_constructed"].clone()).unwrap();
    for k in never.values() {
        assert!(synchronous.contains(k), "{k}");
    }
    assert_eq!(reserved.get("Probe").map(String::as_str), Some("probe"));

    // ⟨M03⟩ m03-plan U0: `Request::admission` still matches every variant without a
    // wildcard (a new variant does not compile until it is classified).
    let source = std::fs::read_to_string(repo_root().join("crates/contract/src/request.rs"))
        .unwrap_or_else(|e| panic!("request.rs unreadable: {}", e.kind()));
    let body = source
        .split("pub fn admission(&self) -> Admission {")
        .nth(1)
        .expect("Request::admission present")
        .split("\n    }\n")
        .next()
        .unwrap();
    assert!(
        body.contains("Request::Enrollment("),
        "the helper is the whole match"
    );
    assert!(
        !body.lines().any(|l| l.trim_start().starts_with("_ =>")),
        "Request::admission has a wildcard arm"
    );
}

/// m02-plan section 5 item 4: Setup and Catalog need `setup/1`, are dispatched on
/// any session (not attended-only), and `Setup(Preview)` is the only read-only one.
#[test]
fn setup_and_catalog_need_setup_1_and_preview_is_read_only() {
    for r in one_of_every_request() {
        let (op, _) = op_and_action(&r);
        match op.as_str() {
            "setup" | "catalog" => {
                assert_eq!(r.required_capability(), Some(capability::SETUP_V1), "{op}");
                assert!(!r.requires_attended_session(), "{op}");
                assert!(!r.is_widening_policy_action(), "{op}");
                let preview = matches!(r, Request::Setup(SetupRequest::Preview { .. }));
                assert_eq!(r.is_effectful(), !preview, "{}", r.kind());
            }
            "shutdown" => {
                assert_eq!(
                    r.required_capability(),
                    Some(capability::SERVICE_CONTROL_V1)
                );
            }
            // ⟨M03⟩ m03-plan section 5 items 2, 3, 4a: their own capabilities (the
            // M03 test `m03_requests_need_their_capability_and_unlock_is_attended`).
            "issuer" => assert_eq!(r.required_capability(), Some(capability::ISSUER_V1)),
            "enrollment" => {
                assert_eq!(r.required_capability(), Some(capability::ENROLLMENT_V1));
            }
            "connections" => {
                assert_eq!(r.required_capability(), Some(capability::CONNECTIONS_V1));
            }
            _ => assert_eq!(r.required_capability(), None, "{op}"),
        }
    }
    let kinds: BTreeSet<&str> = [
        "schemas/examples/request.setup.preview-apply.json",
        "schemas/examples/request.setup.apply.json",
        "schemas/examples/request.setup.rollback.json",
        "schemas/examples/request.setup.repair.json",
        "schemas/examples/request.catalog.upsert-profile.json",
    ]
    .iter()
    .map(|p| request(load(p)).kind())
    .collect();
    assert_eq!(
        kinds,
        [
            "catalog",
            "setup.apply",
            "setup.preview",
            "setup.repair",
            "setup.rollback"
        ]
        .into_iter()
        .collect()
    );
}

/// Q8 (m02-plan section 5 item 5): `BindForm::Launch` carries the resolved
/// executable and the holder, never `argv`.
#[test]
fn bind_launch_without_argv() {
    let v = load("schemas/examples/request.bind-launch.json");
    let r = request(v.clone());
    let Request::Bind(bind) = &r else {
        panic!("a bind request");
    };
    let BindForm::Launch(launch) = &bind.form else {
        panic!("a launch form");
    };
    assert_eq!(launch.executable, "/usr/bin/ssh");
    assert_eq!(
        launch.holder,
        Some(ProcessHolder {
            pid: 4242,
            started_at: "1761912000.123456".to_owned()
        })
    );
    assert_eq!(serde_json::to_value(&r).unwrap(), v);
    assert!(v["form"].get("argv").is_none());

    // The old wire form no longer decodes (no executable), and an `argv` sent
    // beside an executable is never carried or re-emitted.
    let old = json!({"op": "bind", "binding_id": "binding_0123456789abcdef0123456789abcdef",
        "form": {"form": "launch", "argv": ["ssh", "host"]}, "request_id": "r"});
    assert!(serde_json::from_value::<Request>(old).is_err());
    let mixed = json!({"op": "bind", "binding_id": "binding_0123456789abcdef0123456789abcdef",
        "form": {"form": "launch", "executable": "/usr/bin/ssh", "argv": ["ssh", "host"]},
        "request_id": "r"});
    let back = serde_json::to_value(request(mixed)).unwrap();
    assert!(back["form"].get("argv").is_none());
    assert!(!back.to_string().contains("host\""));
    // Without a holder the field is omitted, not null.
    let bare = BindForm::Launch(LaunchBinding {
        executable: "/usr/bin/ssh".to_owned(),
        holder: None,
    });
    assert_eq!(
        serde_json::to_value(&bare).unwrap(),
        json!({"form": "launch", "executable": "/usr/bin/ssh"})
    );
    // The generated schema has no `argv` property anywhere (prose may name it).
    let text = serde_json::to_string(&schema("request")).unwrap();
    assert!(!text.contains("\"argv\""), "argv left the contract");
    assert!(text.contains("LaunchBinding") && text.contains("ProcessHolder"));
}

/// m02-plan section 5 item 5 validation (U0b row 3 calls it).
#[test]
fn launch_binding_rules() {
    let abs = if cfg!(windows) {
        r"C:\Windows\System32\OpenSSH\ssh.exe"
    } else {
        "/usr/bin/ssh"
    };
    let holder = |pid: u32, t: &str| {
        Some(ProcessHolder {
            pid,
            started_at: t.to_owned(),
        })
    };
    let lb = |exe: &str, h: Option<ProcessHolder>| LaunchBinding {
        executable: exe.to_owned(),
        holder: h,
    };
    assert_eq!(lb(abs, None).validate(), Ok(()));
    assert_eq!(lb(abs, holder(1, "a")).validate(), Ok(()));
    assert_eq!(lb(abs, holder(1, &"9".repeat(64))).validate(), Ok(()));
    assert_eq!(lb(abs, holder(u32::MAX, "A.b_c:d-1")).validate(), Ok(()));
    // Executable: 1 to 4096 bytes, no NUL, absolute.
    let long = format!("{abs}{}", "x".repeat(4096 - abs.len()));
    assert_eq!(long.len(), 4096);
    assert_eq!(lb(&long, None).validate(), Ok(()));
    assert_eq!(
        lb(&format!("{long}x"), None).validate(),
        Err(LaunchBindingError::ExecutableLength)
    );
    assert_eq!(
        lb("", None).validate(),
        Err(LaunchBindingError::ExecutableLength)
    );
    assert_eq!(
        lb(&format!("{abs}\0x"), None).validate(),
        Err(LaunchBindingError::ExecutableLength)
    );
    for rel in ["ssh", "./ssh", "bin/ssh"] {
        assert_eq!(
            lb(rel, None).validate(),
            Err(LaunchBindingError::ExecutableNotAbsolute),
            "{rel}"
        );
    }
    // Holder: pid > 0; started_at 1 to 64 bytes of [A-Za-z0-9._:-].
    assert_eq!(
        lb(abs, holder(0, "a")).validate(),
        Err(LaunchBindingError::HolderPid)
    );
    for bad in ["", " ", "a b", "a/b", "a\u{1b}b", "é", &"9".repeat(65)] {
        assert_eq!(
            lb(abs, holder(1, bad)).validate(),
            Err(LaunchBindingError::HolderStartedAt),
            "{bad:?}"
        );
    }
}

/// ADR-0007 section 8 reader table, parsed from the decision record.
fn adr_reader_rows() -> Vec<String> {
    let text = std::fs::read_to_string(
        repo_root().join("docs/decisions/0007-existing-access-integration.md"),
    )
    .unwrap();
    let section = text
        .split("**Reader classification**")
        .nth(1)
        .expect("ADR-0007 section 8 reader table present");
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in section.lines() {
        let t = line.trim();
        if !t.starts_with('|') {
            if in_table {
                break;
            }
            continue;
        }
        in_table = true;
        let first = t.trim_matches('|').split('|').next().unwrap().trim();
        if first == "Records, in order" || first.starts_with("---") {
            continue;
        }
        rows.push(first.to_owned());
    }
    rows
}

fn platform(s: &str) -> RunPlatform {
    match s {
        "unix" => RunPlatform::Unix,
        "windows" => RunPlatform::Windows,
        other => panic!("platform {other}"),
    }
}

/// m02-plan U0 `run_record_classify_golden`: every row of ADR-0007 section 8's
/// reader table (taken from the ADR text) has a golden case, and every golden case
/// classifies as recorded.
#[test]
fn run_record_classify_golden() {
    let golden = load("tests/contracts/golden/run-record-classify.golden.json");
    let cases = golden["cases"].as_array().unwrap();
    let adr = adr_reader_rows();
    assert_eq!(
        adr.len(),
        6,
        "ADR-0007 section 8 reader table rows: {adr:?}"
    );
    let covered: BTreeSet<&str> = cases.iter().filter_map(|c| c["adr_row"].as_str()).collect();
    let adr_set: BTreeSet<&str> = adr.iter().map(String::as_str).collect();
    assert_eq!(covered, adr_set, "golden rows vs ADR rows");
    for (i, case) in cases.iter().enumerate() {
        let records: Vec<RunRecord> = serde_json::from_value(case["records"].clone())
            .unwrap_or_else(|e| panic!("case {i}: {e}"));
        // Records round-trip exactly (NDJSON lines are re-readable).
        for (r, v) in records.iter().zip(case["records"].as_array().unwrap()) {
            let mut written = serde_json::to_value(r).unwrap();
            if let Some(o) = written.as_object_mut()
                && o.get("consumer_overrides") == Some(&json!([]))
                && v.get("consumer_overrides").is_none()
            {
                o.remove("consumer_overrides");
            }
            assert_eq!(&written, v, "case {i}: record round trip");
        }
        let got = classify(&records, platform(case["platform"].as_str().unwrap()));
        assert_eq!(
            serde_json::to_value(&got).unwrap(),
            case["expect"],
            "case {i} ({}): {:?}",
            case["adr_row"].as_str().unwrap_or("fail-closed"),
            case.get("note")
        );
        let back: LaunchClassification = serde_json::from_value(case["expect"].clone()).unwrap();
        assert_eq!(back, got, "case {i}: classification wire form");
    }
}

fn arb_record() -> impl Strategy<Value = RunRecord> {
    let version = prop_oneof![
        8 => Just(SchemaVersion::current()),
        1 => Just(SchemaVersion("2".to_owned())),
    ];
    (version, 0u8..4, 0u32..3, any::<i64>()).prop_map(
        |(schema_version, which, n, code)| match which {
            0 => RunRecord::PrelaunchFailed {
                schema_version,
                code: Code::LaunchFailed,
                exit_code: 127,
                reason: None,
                operation_id: None,
                binding_id: None,
            },
            1 => RunRecord::Launching {
                schema_version,
                attempt: n,
                executable: "/usr/bin/ssh".to_owned(),
                operation_id: None,
                binding_id: None,
                pid: 1,
                consumer_overrides: Vec::new(),
            },
            2 => RunRecord::Spawned {
                schema_version,
                pid: 2,
            },
            _ => RunRecord::Exited {
                schema_version,
                exit_code: code,
            },
        },
    )
}

proptest! {
    #![proptest_config(proptest_config())]

    /// The reader never claims a launch without positive evidence (Windows
    /// `launching` then `spawned`), never on Unix, and never claims "not launched"
    /// once an attempt was written unless the attempt was answered by
    /// `prelaunch_failed`. An unsupported major is always indeterminate.
    #[test]
    fn classify_never_claims_more_than_the_records_show(
        records in prop::collection::vec(arb_record(), 0..6),
        windows in any::<bool>(),
    ) {
        let p = if windows { RunPlatform::Windows } else { RunPlatform::Unix };
        let got = classify(&records, p);
        let unsupported = records.iter().any(|r| !r.schema_version().is_supported());
        if unsupported {
            prop_assert_eq!(&got, &LaunchClassification::Indeterminate);
        }
        match &got {
            LaunchClassification::Launched { exit_code } => {
                prop_assert!(windows);
                prop_assert!(records.len() == 2 || records.len() == 3);
                let launching_first = matches!(
                    records[0],
                    RunRecord::Launching { attempt: 1, .. }
                );
                let spawned_second = matches!(records[1], RunRecord::Spawned { .. });
                prop_assert!(launching_first);
                prop_assert!(spawned_second);
                prop_assert_eq!(exit_code.is_some(), records.len() == 3);
            }
            LaunchClassification::NotLaunched { .. } => {
                let attempted = records.iter().any(|r| !matches!(r, RunRecord::PrelaunchFailed { .. }));
                if attempted {
                    prop_assert_eq!(records.len(), 2);
                    let answered = matches!(
                        (&records[0], &records[1]),
                        (RunRecord::Launching { attempt: 1, .. }, RunRecord::PrelaunchFailed { .. })
                    );
                    prop_assert!(answered);
                }
            }
            LaunchClassification::Indeterminate => {
                prop_assert!(!records.is_empty());
            }
            _ => prop_assert!(false, "unknown classification"),
        }
    }
}

/// m02-plan section 5 item 14 (E3 reading: `ErrorDetail.reason`, wire
/// `data.error.reason`). The values are stable snake_case tokens; the conflict
/// kinds and manual reasons are reasons with the same spelling.
#[test]
fn error_reasons_are_stable_snake_case_and_complete() {
    let token = |s: &str| {
        !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    };
    let mut all: BTreeSet<String> = BTreeSet::new();
    for r in reason::ALL {
        assert!(token(r), "{r}");
        assert!(all.insert((*r).to_owned()), "duplicate {r}");
    }
    let conflicts = [
        ConflictKind::UserConfigChanged,
        ConflictKind::ManagedFileEdited,
        ConflictKind::MarkerEdited,
        ConflictKind::MarkerDuplicated,
        ConflictKind::IncludeConditional,
        ConflictKind::UnmanageableFile,
        ConflictKind::AliasCollision,
        ConflictKind::ConcurrentWriter,
        ConflictKind::GitConfigLocked,
        ConflictKind::ProjectionHeld,
        // ADR-0007 §12.20 item 2(a).
        ConflictKind::VerifiedClientUnavailable,
    ];
    for c in conflicts {
        let wire = serde_json::to_value(c).unwrap();
        let wire = wire.as_str().unwrap().to_owned();
        assert!(token(&wire), "{wire}");
        all.insert(wire);
    }
    for m in manual_reason::ALL {
        assert!(token(m), "{m}");
        all.insert((*m).to_owned());
    }
    // m02-plan section 5 item 14, transcribed.
    let item_14: BTreeSet<String> = [
        "user_config_changed",
        "managed_file_edited",
        "marker_edited",
        "marker_duplicated",
        "include_conditional",
        "unmanageable_file",
        "alias_collision",
        "concurrent_writer",
        "git_config_locked",
        "projection_held",
        "atomic_exchange_unsupported",
        "unsupported_encoding",
        "git_global_redirected",
        "not_found",
        "current_directory",
        "refused_batch_path",
        "refused_argument",
        "not_executable",
        "exec_error",
        "refused_path",
        "meta_unavailable",
        "endpoint_absent",
        "identity_not_listed",
        "provider_interaction",
        "interaction_unknown",
        "mixed_mechanisms",
        "config_commands_not_authorized",
        "git_ssh_command_present",
        "driver_unavailable",
        "fallback_identity_interaction",
        "config_not_fully_readable",
        "git_config_unreadable",
        "setup_in_progress",
        "projection_too_large",
        // ADR-0007 §12.32 item 5: a preview whose full diff exceeds `MAX_DIFF_BYTES`.
        "plan_too_large",
        // ADR-0007 §12.17 item 11 (the Git item's reasons) and §12.19 item 9 (the
        // manual reasons a `manual_mode` repair and a globbed P path give).
        "git_default_not_bundled_msys",
        "verified_client_unavailable",
        "include_target_glob",
        // ADR-0007 §12.25 item 4 and §12.26 item 3(a): the launch binding's holder
        // and the released binding.
        "binding_in_use",
        "binding_released",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(all, item_14);
    for r in noninteractive_reason::ALL {
        assert!(all.contains(*r), "{r}");
    }

    // Omitted when absent, so every M01 error envelope is unchanged; carried
    // through a round trip when present.
    let mut detail = ErrorDetail {
        code: Code::CapabilityUnavailable,
        effect_status: EffectStatus::None,
        retryable: false,
        resource: None,
        next: NextAction::for_code(Code::CapabilityUnavailable),
        message: "m".to_owned(),
        reason: None,
        entries: Vec::new(),
    };
    let v = serde_json::to_value(Envelope::failed(None, detail.clone())).unwrap();
    assert!(v["data"]["error"].get("reason").is_none());
    assert!(v["data"].get("setup").is_none());
    detail.reason = Some(reason::DRIVER_UNAVAILABLE.to_owned());
    let env = Envelope::failed(None, detail);
    let v = serde_json::to_value(&env).unwrap();
    assert_eq!(v["data"]["error"]["reason"], "driver_unavailable");
    let back: Envelope<ErrorData> = serde_json::from_value(v).unwrap();
    assert_eq!(back, env);
}

/// m02-plan section 5 items 1, 6, 7, 10, 15: identifiers, the additive fields and
/// their defaults, the provider interaction rule and the new inspect subjects.
#[test]
fn m02_additive_fields_and_defaults() {
    // IdentityId: prefixed `idn`.
    let id = IdentityId::from_random_bytes([0x5a; 16]);
    assert!(id.as_str().starts_with("idn_"));
    assert_eq!(IdentityId::PREFIX, "idn");
    assert!(IdentityId::parse("op_00112233445566778899aabbccddeeff").is_err());

    // `unattended`: default false, omitted when false (M01 hashes unchanged),
    // written when true.
    let rc: RequiredCapabilities = serde_json::from_value(json!({})).unwrap();
    assert!(!rc.unattended);
    assert_eq!(serde_json::to_value(&rc).unwrap(), json!({}));
    let rc = RequiredCapabilities {
        unattended: true,
        ..RequiredCapabilities::default()
    };
    assert_eq!(
        serde_json::to_value(&rc).unwrap(),
        json!({"unattended": true})
    );
    let ensure = load("schemas/examples/request.ensure.json");
    assert!(ensure["required_capabilities"].get("unattended").is_none());

    // EnsureData: an M01 document without the new fields reads as `unknown` and
    // no provider; the M02 example carries both.
    let m02 = load("schemas/examples/envelope.success.ensure-existing-access.json");
    let mut m01_data = m02["data"].clone();
    let obj = m01_data.as_object_mut().unwrap();
    obj.remove("credential_availability");
    obj.remove("provider");
    obj["consumer"] = json!({});
    let data: EnsureData = serde_json::from_value(m01_data).unwrap();
    assert_eq!(
        data.credential_availability,
        CredentialAvailability::Unknown
    );
    assert!(data.provider.is_none());
    assert!(data.consumer.pairs.is_empty() && data.consumer.executables.is_empty());
    let written = serde_json::to_value(&data).unwrap();
    assert_eq!(written["credential_availability"], "unknown");
    assert_eq!(written["consumer"], json!({}), "empty lists are omitted");
    let full: EnsureData = serde_json::from_value(m02["data"].clone()).unwrap();
    assert_eq!(full.consumer.pairs.len(), 1);
    assert_eq!(full.consumer.pairs[0].interaction, InteractionKind::None);
    assert!(full.consumer.pairs[0].noninteractive.eligible);

    // NextAction.provider_interaction: omitted when absent; never with decision_ref.
    let n = NextAction::for_code(Code::ProviderLocked);
    assert!(
        serde_json::to_value(&n)
            .unwrap()
            .get("provider_interaction")
            .is_none()
    );
    let with = NextAction {
        provider_interaction: Some(ProviderInteractionRef {
            provider: ProviderKind::OnePassword,
            kind: InteractionKind::ProviderUnlock,
        }),
        ..n
    };
    assert!(with.is_well_formed());
    let both = NextAction {
        decision_ref: Some("dec_00112233445566778899aabbccddeeff".to_owned()),
        ..with.clone()
    };
    assert!(!both.is_well_formed());
    for file in [
        "schemas/examples/envelope.error.provider-locked.json",
        "schemas/examples/envelope.error.projection-held.json",
        "schemas/examples/envelope.pending.approval.json",
    ] {
        let env: Envelope<ErrorData> = serde_json::from_value(load(file)).unwrap();
        assert!(env.data.error.next.is_well_formed(), "{file}");
    }
    let locked: Envelope<ErrorData> =
        serde_json::from_value(load("schemas/examples/envelope.error.provider-locked.json"))
            .unwrap();
    assert_eq!(locked.data.error.next, with);

    // Inspect subjects.
    for (subject, wire) in [
        (InspectSubject::Identities, "identities"),
        (InspectSubject::Projections, "projections"),
    ] {
        assert_eq!(serde_json::to_value(subject).unwrap(), json!(wire));
    }

    // The held envelope carries the setup result in `data.setup`.
    let held: Envelope<ErrorData> =
        serde_json::from_value(load("schemas/examples/envelope.error.projection-held.json"))
            .unwrap();
    assert_eq!(held.code, Code::OutcomeUnknown);
    assert_eq!(
        held.data.error.reason.as_deref(),
        Some(reason::PROJECTION_HELD)
    );
    assert!(held.data.setup.is_some());
}

/// m02-plan section 5 item 2: the repair rules the wire types cannot express.
#[test]
fn preview_intent_repair_rules() {
    let op = Some(heimdall_contract::ids::OperationId::from_random_bytes(
        [1; 16],
    ));
    let repair = |conflict, resolution, operation| PreviewIntent::Repair {
        conflict,
        resolution,
        operation,
    };
    use ConflictKind as C;
    use RepairResolution as R;
    assert_eq!(
        repair(C::ProjectionHeld, R::RetryHeld, op.clone()).validate(),
        Ok(())
    );
    assert_eq!(
        repair(C::ProjectionHeld, R::KeepHeld, op.clone()).validate(),
        Ok(())
    );
    assert_eq!(
        repair(C::MarkerDuplicated, R::RemoveDuplicateMarkers, None).validate(),
        Ok(())
    );
    assert_eq!(
        repair(C::ProjectionHeld, R::RetryHeld, None).validate(),
        Err(PreviewIntentError::OperationRequired)
    );
    assert_eq!(
        repair(C::MarkerEdited, R::Rerender, op.clone()).validate(),
        Err(PreviewIntentError::OperationNotAllowed)
    );
    assert_eq!(
        repair(C::MarkerEdited, R::KeepHeld, op.clone()).validate(),
        Err(PreviewIntentError::HeldResolutionMismatch)
    );
    assert_eq!(
        repair(C::ProjectionHeld, R::Rerender, None).validate(),
        Err(PreviewIntentError::HeldResolutionMismatch)
    );
    let ex = request(load("schemas/examples/request.setup.preview-repair.json"));
    let Request::Setup(SetupRequest::Preview { intent }) = ex else {
        panic!("a preview");
    };
    assert_eq!(intent.validate(), Ok(()));
}

/// Catalog boundary checks run on every example.
#[test]
fn catalog_examples_pass_the_boundary_checks() {
    for file in [
        "schemas/examples/request.catalog.upsert-destination.json",
        "schemas/examples/request.catalog.upsert-destination-observed.json",
        "schemas/examples/request.catalog.adopt-identity.json",
        "schemas/examples/request.catalog.adopt-identity-onepassword.json",
        "schemas/examples/request.catalog.upsert-profile.json",
        "schemas/examples/request.catalog.withdraw-declaration.json",
    ] {
        let Request::Catalog(c) = request(load(file)) else {
            panic!("{file}: a catalog request");
        };
        assert_eq!(c.validate(), Ok(()), "{file}");
        assert_eq!(
            serde_json::to_value(&c).unwrap()["action"],
            c.action(),
            "{file}"
        );
        assert!(matches!(
            c,
            CatalogRequest::UpsertDestination { .. }
                | CatalogRequest::AdoptIdentity { .. }
                | CatalogRequest::UpsertProfile { .. }
                | CatalogRequest::WithdrawDeclaration { .. }
        ));
    }
}

/// The new schemas reject what the typed model rejects, so the example checks in
/// `examples` are not vacuous for them.
#[test]
fn m02_schemas_are_not_vacuous() {
    use crate::jsonschema_lite::validate;
    let cases: &[(&str, &str, &[&str], Value)] = &[
        (
            "request",
            "schemas/examples/request.setup.apply.json",
            &["plan_digest"],
            json!(null),
        ),
        (
            "request",
            "schemas/examples/request.catalog.declare-interaction.json",
            &["interaction"],
            json!("provider_approval"),
        ),
        (
            "request",
            "schemas/examples/request.setup.preview-repair.json",
            &["intent", "resolution"],
            json!("retry_maybe"),
        ),
        (
            "request",
            "schemas/examples/request.bind-launch.json",
            &["form", "executable"],
            json!(null),
        ),
        (
            "doctor-report",
            "schemas/examples/doctor-report.json",
            &["levels_performed"],
            json!(["telepathy"]),
        ),
        (
            "run-record",
            "schemas/examples/run-record.launching.json",
            &["type"],
            json!("launched"),
        ),
        (
            "setup-plan",
            "schemas/examples/setup-plan.apply.json",
            &["mode"],
            json!("eventually"),
        ),
        (
            "setup-result",
            "schemas/examples/setup-result.held.json",
            &["generation"],
            json!(-1),
        ),
    ];
    for (name, file, path, bad) in cases {
        let doc = schema(name);
        let ok = load(file);
        assert!(validate(&doc, &ok).is_ok(), "{file}");
        let mut v = ok.clone();
        let mut at = &mut v;
        for key in &path[..path.len() - 1] {
            at = &mut at[*key];
        }
        let last = path[path.len() - 1];
        if bad.is_null() {
            at.as_object_mut().unwrap().remove(last);
        } else {
            at[last] = bad.clone();
        }
        assert!(
            validate(&doc, &v).is_err(),
            "{file}: mutation of {path:?} accepted"
        );
        assert!(
            match *name {
                "request" => serde_json::from_value::<Request>(v).is_err(),
                "doctor-report" =>
                    serde_json::from_value::<heimdall_contract::doctor::DoctorReport>(v).is_err(),
                "run-record" => serde_json::from_value::<RunRecord>(v).is_err(),
                "setup-plan" =>
                    serde_json::from_value::<heimdall_contract::setup::SetupPlan>(v).is_err(),
                _ => serde_json::from_value::<heimdall_contract::setup::SetupResult>(v).is_err(),
            },
            "{file}: the typed model accepted the mutation of {path:?}"
        );
    }
}
