//! Golden tests for the stable code table (ADR-0006 section 5; spec section 11.6).
//!
//! Two independent sources are compared with `contract::Code`:
//! * `golden/code-table.golden.json`: a mechanical transcription of the ADR table;
//! * the ADR markdown itself, parsed here, which also proves the golden file has
//!   not drifted from the decision record.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::code::Code;
use crate::envelope::{EffectStatus, Envelope, ErrorDetail, NextAction};
use crate::exit::ExitCode;

use super::{assert_clean, repo_root};

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
    assert_eq!(adr.len(), 28, "ADR section 5 row count");
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
            code: *code,
            effect_status: code.default_effect_status(),
            retryable: code.retryable(),
            resource: None,
            next: NextAction::for_code(*code),
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
        let back: Envelope<crate::envelope::ErrorData> = serde_json::from_value(v).unwrap();
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
