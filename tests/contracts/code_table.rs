//! Golden tests for the stable code table (ADR-0006 section 5; spec section 11.6).
//!
//! Two independent sources are compared with `contract::Code`:
//! * `golden/code-table.golden.json`: a mechanical transcription of the ADR table;
//! * the ADR markdown itself, parsed here, which also proves the golden file has
//!   not drifted from the decision record.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction};
use heimdall_contract::exit::ExitCode;

use crate::{assert_clean, repo_root};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    code: String,
    exit: i64,
    retryable: bool,
    effect: String,
    next: String,
}

fn golden_rows() -> Vec<Row> {
    let path = repo_root().join("tests/contracts/golden/code-table.golden.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| Row {
            code: r["code"].as_str().unwrap().to_owned(),
            exit: r["exit"].as_i64().unwrap(),
            retryable: r["retryable"].as_bool().unwrap(),
            effect: r["effect"].as_str().unwrap().to_owned(),
            next: r["next"].as_str().unwrap().to_owned(),
        })
        .collect()
}

/// Parse the table in ADR-0006 section 5 directly from the decision record.
fn adr_rows() -> Vec<Row> {
    let path = repo_root().join("docs/decisions/0006-public-contract-baseline.md");
    let text = std::fs::read_to_string(path).unwrap();
    let section = text
        .split("## 5. Stable code table")
        .nth(1)
        .expect("ADR section 5 present")
        .split("Placement decisions")
        .next()
        .unwrap();
    let mut rows = Vec::new();
    for line in section.lines() {
        let cells: Vec<&str> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() < 5 || cells[0] == "Code" {
            continue;
        }
        if !cells[0].chars().all(|c| c.is_ascii_uppercase() || c == '_') || cells[0].is_empty() {
            continue;
        }
        // "0 (async only, else 5)" -> 0: the ACCEPTED override is a CLI rule.
        let exit: i64 = cells[1].split_whitespace().next().unwrap().parse().unwrap();
        rows.push(Row {
            code: cells[0].to_owned(),
            exit,
            retryable: cells[2] == "yes",
            effect: cells[3].to_owned(),
            next: cells[4].to_owned(),
        });
    }
    rows
}

fn effect_name(e: EffectStatus) -> &'static str {
    match e {
        EffectStatus::None => "none",
        EffectStatus::Applied => "applied",
        EffectStatus::Partial => "partial",
        EffectStatus::Unknown => "unknown",
    }
}

#[test]
fn golden_file_matches_the_adr_table() {
    let adr = adr_rows();
    assert_eq!(adr.len(), 29, "ADR section 5 row count");
    assert_eq!(golden_rows(), adr);
}

#[test]
fn every_code_matches_its_golden_row() {
    let golden = golden_rows();
    let codes = Code::all();
    assert_eq!(codes.len(), golden.len(), "Code::all() vs ADR rows");
    for (code, row) in codes.iter().zip(&golden) {
        assert_eq!(code.as_str(), row.code, "table order");
        assert_eq!(
            i64::from(code.exit_code().as_i32()),
            row.exit,
            "{code}: exit"
        );
        assert_eq!(code.retryable(), row.retryable, "{code}: retryable");
        assert_eq!(
            effect_name(code.default_effect_status()),
            row.effect,
            "{code}: default effect"
        );
        assert_eq!(code.default_next_action(), row.next, "{code}: next");
    }
}

#[test]
fn code_set_has_no_duplicates_and_covers_the_spec_list() {
    let names: BTreeSet<&str> = Code::all().iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), Code::all().len());
    for required in [
        "APPROVAL_REQUIRED",
        "CAPABILITY_UNAVAILABLE",
        "PROVIDER_LOCKED",
        "INTERACTION_REQUIRED",
        "HOST_TRUST_CHANGED",
        "DESTINATION_UNREACHABLE",
        "CREDENTIAL_EXPIRED",
        "POLICY_PAUSED",
        "POLICY_CUTOFF",
        "REQUEST_CONFLICT",
        "CONFIG_CONFLICT",
        "OUTCOME_UNKNOWN",
        "UNSUPPORTED_CLIENT",
        "TIME_UNCERTAIN",
    ] {
        assert!(
            names.contains(required),
            "spec section 11.6 code {required}"
        );
    }
}

#[test]
fn adr_13_1_rulings_hold() {
    // Orchestrator rulings 2026-10-31, item 3.
    assert_eq!(Code::CapabilityUnavailable.exit_code(), ExitCode::Denied);
    assert_eq!(Code::NotFound.exit_code(), ExitCode::Usage);
    // ACCEPTED is exit 0 in the table; the "async only, else 5" rule is the CLI's
    // (`output::exit_code_for`) and is covered by the CLI unit.
    assert_eq!(Code::Accepted.exit_code(), ExitCode::Success);
}

#[test]
fn exit_numbers_are_the_documented_wire_numbers() {
    let expected = [
        (ExitCode::Success, 0),
        (ExitCode::Internal, 1),
        (ExitCode::Usage, 2),
        (ExitCode::InteractionRequired, 3),
        (ExitCode::Denied, 4),
        (ExitCode::Unavailable, 5),
        (ExitCode::Conflict, 6),
        (ExitCode::OutcomeUnknown, 7),
    ];
    for (code, n) in expected {
        assert_eq!(code.as_i32(), n);
    }
}

/// The error envelope built from a code's defaults carries exactly the golden row.
#[test]
fn error_envelope_golden_json_for_every_code() {
    for (code, row) in Code::all().iter().zip(golden_rows()) {
        if code.is_success() {
            continue;
        }
        let detail = ErrorDetail {
            code: code.clone(),
            effect_status: code.default_effect_status(),
            retryable: code.retryable(),
            resource: None,
            next: NextAction::for_code(code.clone()),
            message: "m".to_owned(),
        };
        let env = Envelope::failed(None, detail);
        let v = serde_json::to_value(&env).unwrap();
        assert_clean("error envelope", &v.to_string());
        assert_eq!(v["code"], json!(row.code));
        let err = &v["data"]["error"];
        assert_eq!(err["code"], json!(row.code));
        assert_eq!(err["effect_status"], json!(row.effect));
        assert_eq!(err["retryable"], json!(row.retryable));
        assert_eq!(err["next"]["action"], json!(row.next));
        // Omitted vs null: the envelope always materializes `next` and `warnings`.
        assert!(v.get("next").is_some_and(Value::is_null));
        assert_eq!(v["warnings"], json!([]));
        let back: Envelope<ErrorData> = serde_json::from_value(v).unwrap();
        assert_eq!(back, env);
    }
}

#[test]
fn code_spelling_is_exact_on_the_wire() {
    for bad in [
        "\"ok\"",
        "\"Access_Ready\"",
        "\"ACCESS-READY\"",
        "\"\"",
        "7",
    ] {
        assert!(serde_json::from_str::<Code>(bad).is_err(), "{bad}");
    }
}

#[test]
fn retryable_never_applies_to_uncertain_or_refused_outcomes() {
    // spec section 11.6: retryable never authorizes replaying a remote mutation.
    for code in Code::all() {
        if code.default_effect_status() == EffectStatus::Unknown {
            assert!(!code.retryable(), "{code}");
        }
        if matches!(
            code.exit_code(),
            ExitCode::Denied | ExitCode::Conflict | ExitCode::OutcomeUnknown
        ) {
            assert!(!code.retryable(), "{code}");
        }
    }
}

#[test]
fn decision_stale_row_is_in_table_order() {
    // ADR-0006 section 5 revision 2: after RESYNC_REQUIRED, before OUTCOME_UNKNOWN.
    let names: Vec<&str> = Code::all().iter().map(Code::as_str).collect();
    let at = names.iter().position(|n| *n == "DECISION_STALE").unwrap();
    assert_eq!(names[at - 1], "RESYNC_REQUIRED");
    assert_eq!(names[at + 1], "OUTCOME_UNKNOWN");
    assert_eq!(Code::DecisionStale.exit_code(), ExitCode::Conflict);
    assert_eq!(Code::DecisionStale.exit_code().as_i32(), 6);
    assert!(!Code::DecisionStale.retryable());
    assert_eq!(
        Code::DecisionStale.default_effect_status(),
        EffectStatus::None
    );
    assert_eq!(Code::DecisionStale.default_next_action(), "fix_request");
}

/// ADR-0006 section 9 / wave-1 E4: a code added by a newer peer is read as
/// `Code::Unknown`, never as success, exits 1, reports an unknown effect, and is
/// written back unchanged.
#[test]
fn unknown_code_reads_as_an_error_with_exit_one_and_round_trips() {
    let longest = "Z".repeat(64);
    for wire in ["FUTURE_THING", "A", "X_9", longest.as_str()] {
        let json = format!("\"{wire}\"");
        let code: Code = serde_json::from_str(&json).unwrap();
        assert_eq!(code, Code::Unknown(wire.to_owned()), "{wire}");
        assert!(!Code::all().contains(&code), "{wire}: not a table row");
        assert!(!code.is_success(), "{wire}");
        assert_eq!(code.exit_code(), ExitCode::Internal, "{wire}");
        assert_eq!(code.exit_code().as_i32(), 1, "{wire}");
        assert_eq!(
            code.default_effect_status(),
            EffectStatus::Unknown,
            "{wire}"
        );
        assert!(!code.retryable(), "{wire}");
        assert_eq!(code.as_str(), wire);
        assert_eq!(serde_json::to_string(&code).unwrap(), json, "{wire}");
        let again: Code = serde_json::from_str(&serde_json::to_string(&code).unwrap()).unwrap();
        assert_eq!(again, code, "{wire}: round trip");
    }
    // Known spellings never fall back to Unknown.
    for known in Code::all() {
        let back: Code = serde_json::from_str(&format!("\"{}\"", known.as_str())).unwrap();
        assert_eq!(&back, known);
        assert!(!matches!(back, Code::Unknown(_)));
    }
    // The fallback stays bounded: overlong or non-token strings are refused.
    assert!(serde_json::from_str::<Code>(&format!("\"{}\"", "Z".repeat(65))).is_err());
    assert!(serde_json::from_str::<Code>("\"FUTURE THING\"").is_err());
    assert!(serde_json::from_str::<Code>("\"FUTURE\\u001bX\"").is_err());
}

/// An envelope from a newer peer carrying an unknown code still parses; its code
/// classifies as a non-success exit-1 error and the document round-trips.
#[test]
fn envelope_with_an_unknown_code_parses_and_is_not_success() {
    let text = r#"{"schema_version":"1","operation_id":"op_00112233445566778899aabbccddeeff","state":"failed","code":"FUTURE_THING","data":{"error":{"code":"FUTURE_THING","effect_status":"unknown","retryable":false,"next":{"action":"report"},"message":"m"}},"warnings":[],"next":null}"#;
    let v: Value = serde_json::from_str(text).unwrap();
    let env: Envelope<ErrorData> = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(env.code, Code::Unknown("FUTURE_THING".to_owned()));
    assert_eq!(env.data.error.code, env.code);
    assert!(!env.code.is_success());
    assert_eq!(env.code.exit_code(), ExitCode::Internal);
    assert_eq!(serde_json::to_value(&env).unwrap(), v);
}
