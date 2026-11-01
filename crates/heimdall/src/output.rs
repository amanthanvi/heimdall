//! Envelope rendering and exit-code mapping (spec §11.2, §11.6; ADR-0006 §6).
//!
//! `--json`: exactly one envelope on stdout, newline-terminated, no ANSI (event
//! streams: one JSON value per line). Human mode: a short summary on stdout;
//! error messages, next actions, warnings and prompts on stderr. Every human
//! string passes through [`sanitize_for_terminal`] (spec §11.2, §14.3).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use heimdall_contract::envelope::{Envelope, ErrorData};
use heimdall_contract::{Code, ExitCode, OperationState};

/// Exit code for an envelope as a non-child command (ADR-0006 §6). `ACCEPTED`
/// exits 0 only when the caller selected asynchronous behaviour; otherwise a
/// pending result after a synchronous wait is reported as `Unavailable` (5) with
/// the operation to observe. A code this reader does not know
/// (`Code::Unknown`) is never success: exit 1 (ADR-0006 §5, §9).
#[must_use]
pub fn exit_code_for(code: Code, caller_chose_async: bool) -> ExitCode {
    match code {
        Code::Accepted if !caller_chose_async => ExitCode::Unavailable,
        other => other.exit_code(),
    }
}

/// Exit code for a bounded wait on an operation (`operation wait`). The read
/// itself succeeded, so the exit reflects the awaited operation:
///
/// * still active (`queued`, `running`, `awaiting_approval`): the same "pending
///   after a synchronous bounded wait" as `ACCEPTED` without `--async` (exit 5);
/// * `outcome_unknown`: exit 7;
/// * settled: the exit class of the operation's recorded code (`succeeded`
///   without a recorded code is 0).
///
/// A failed read (`NOT_FOUND`, transport errors) keeps its own code.
#[must_use]
pub fn exit_code_after_wait(
    read_code: Code,
    state: OperationState,
    operation_code: Option<Code>,
) -> ExitCode {
    if !read_code.is_success() {
        return exit_code_for(read_code, false);
    }
    if !state.is_quiescent() {
        return ExitCode::Unavailable;
    }
    if state.is_unresolved() {
        return ExitCode::OutcomeUnknown;
    }
    match operation_code {
        Some(code) => exit_code_for(code, false),
        None if state == OperationState::Succeeded => ExitCode::Success,
        // A settled failure without a recorded code is never reported as success.
        None => ExitCode::Internal,
    }
}

/// Strip C0/C1 control characters and ESC sequences from a human string before
/// printing (defence against terminal-injection via labels; spec §11.2, §14.3).
#[must_use]
pub fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC [ ... final byte (0x40..=0x7E) is a CSI sequence; ESC x is a
            // two-character escape. Drop both whole.
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if !c.is_control() || c == '\n' || c == '\t' {
            out.push(c);
        }
    }
    out
}

/// Convert an error envelope to the generic value form.
#[must_use]
pub fn error_value(env: Envelope<ErrorData>) -> Envelope<serde_json::Value> {
    env.map(|d| serde_json::to_value(d).unwrap_or(serde_json::Value::Null))
}

/// Print an envelope in the selected mode.
pub fn emit<T: serde::Serialize>(envelope: &Envelope<T>, json: bool) {
    if json {
        match serde_json::to_string(envelope) {
            Ok(s) => println!("{s}"),
            Err(_) => eprintln!("internal: envelope serialization failed"),
        }
        return;
    }
    let Ok(value) = serde_json::to_value(envelope) else {
        eprintln!("internal: envelope serialization failed");
        return;
    };
    let field =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
    let mut head = format!(
        "{} ({})",
        envelope.code.as_str(),
        field(&value, "state").unwrap_or_default()
    );
    if let Some(op) = field(&value, "operation_id") {
        head.push_str(" operation ");
        head.push_str(&op);
    }
    println!("{}", sanitize_for_terminal(&head));
    let data = value
        .get("data")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(error) = data.get("error") {
        if let Some(msg) = field(error, "message") {
            eprintln!("error: {}", sanitize_for_terminal(&msg));
        }
        if let Some(effect) = field(error, "effect_status") {
            eprintln!("effect: {}", sanitize_for_terminal(&effect));
        }
    } else if !data.is_null()
        && let Ok(text) = serde_json::to_string_pretty(&data)
    {
        println!("{}", sanitize_for_terminal(&text));
    }
    if let Some(next) = value.get("next").filter(|n| !n.is_null()) {
        let mut line = format!("next: {}", field(next, "action").unwrap_or_default());
        for k in ["operation_id", "binding_id", "decision_ref", "cursor"] {
            if let Some(v) = field(next, k) {
                line.push_str(&format!(" {k}={v}"));
            }
        }
        if let Some(ms) = next
            .get("retry_after_ms")
            .and_then(serde_json::Value::as_u64)
        {
            line.push_str(&format!(" retry_after_ms={ms}"));
        }
        eprintln!("{}", sanitize_for_terminal(&line));
    }
    for w in &envelope.warnings {
        eprintln!(
            "warning: {} {}",
            sanitize_for_terminal(&w.code),
            sanitize_for_terminal(&w.message)
        );
    }
}

/// Print one line of an event stream: the JSON value (NDJSON) or a short human
/// line.
pub fn emit_line(value: &serde_json::Value, human: &str, json: bool) {
    if json {
        match serde_json::to_string(value) {
            Ok(s) => println!("{s}"),
            Err(_) => eprintln!("internal: event serialization failed"),
        }
    } else {
        println!("{}", sanitize_for_terminal(human));
    }
}

/// A diagnostic line on stderr (sanitized).
pub fn diagnostic(text: &str) {
    eprintln!("{}", sanitize_for_terminal(text));
}

/// Prompt text on stderr without a trailing newline (sanitized).
pub fn prompt(text: &str) {
    use std::io::Write as _;
    eprint!("{}", sanitize_for_terminal(text));
    let _ = std::io::stderr().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_without_async_is_not_success() {
        assert_eq!(exit_code_for(Code::Accepted, true), ExitCode::Success);
        assert_eq!(exit_code_for(Code::Accepted, false), ExitCode::Unavailable);
        assert_eq!(exit_code_for(Code::PolicyCutoff, false), ExitCode::Denied);
    }

    #[test]
    fn unknown_code_is_never_success_and_exits_one() {
        let unknown = Code::parse("FUTURE_CODE_FROM_A_NEWER_PEER");
        assert!(matches!(unknown, Code::Unknown(_)));
        assert_eq!(exit_code_for(unknown.clone(), false), ExitCode::Internal);
        assert_eq!(exit_code_for(unknown, true), ExitCode::Internal);
        // Parsed from a wire envelope, too.
        let env: Envelope<serde_json::Value> = serde_json::from_str(
            r#"{"schema_version":"1","state":"succeeded","code":"FUTURE_CODE","data":{}}"#,
        )
        .unwrap_or_else(|_| panic!("envelope parses"));
        assert_eq!(exit_code_for(env.code, false).as_i32(), 1);
    }

    #[test]
    fn every_known_code_maps_to_its_table_exit_class() {
        for code in Code::all() {
            let expected = code.exit_code();
            if *code == Code::Accepted {
                assert_eq!(exit_code_for(code.clone(), false), ExitCode::Unavailable);
            } else {
                assert_eq!(exit_code_for(code.clone(), false), expected);
            }
            assert_eq!(exit_code_for(code.clone(), true), expected);
        }
    }

    #[test]
    fn a_wait_reports_the_awaited_operation() {
        let w = exit_code_after_wait;
        assert_eq!(
            w(Code::Ok, OperationState::Running, None),
            ExitCode::Unavailable
        );
        assert_eq!(
            w(Code::Ok, OperationState::AwaitingApproval, None),
            ExitCode::Unavailable
        );
        assert_eq!(
            w(Code::Ok, OperationState::Succeeded, Some(Code::AccessReady)),
            ExitCode::Success
        );
        assert_eq!(
            w(Code::Ok, OperationState::Succeeded, None),
            ExitCode::Success
        );
        assert_eq!(
            w(Code::Ok, OperationState::OutcomeUnknown, None),
            ExitCode::OutcomeUnknown
        );
        assert_eq!(
            w(Code::Ok, OperationState::Failed, Some(Code::PolicyPaused)),
            ExitCode::Denied
        );
        assert_eq!(
            w(Code::Ok, OperationState::Failed, None),
            ExitCode::Internal
        );
        assert_eq!(
            w(Code::NotFound, OperationState::Failed, None),
            ExitCode::Usage
        );
    }

    #[test]
    fn sanitizer_drops_escapes() {
        assert_eq!(sanitize_for_terminal("ok\u{1b}[31mred\u{7}"), "okred");
    }
}
