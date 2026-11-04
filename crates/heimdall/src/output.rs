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

// ---- ⟨M02⟩ m02-plan U9: human renderings of the setup, doctor, catalog and
// uninstall results. `--json` prints the envelope only ([`emit`]); human mode prints
// [`emit_rendered`]'s text on stdout and the error, next action and warnings on
// stderr, as M01 does. Every string passes through [`sanitize_for_terminal`].

/// The heading every rendering of a probe's `executed_config_commands` uses (ADR-0007
/// §6, M2-S04): the list is what the static pass found before the run, never complete.
pub const INVENTORY_HEADING: &str = heimdall_localenv::doctor::INVENTORY_WORDING;

/// The warning code that carries [`INVENTORY_HEADING`] in a `--json` doctor envelope
/// whenever a level ran the real configuration tree (U9; ADR-0007 §6).
pub const INVENTORY_WARNING: &str = "config_commands_inventory";

/// Print `envelope` in the selected mode, with `human` as the human rendering of its
/// data (M02 commands). `--json`: exactly the envelope ([`emit`]). Human: a head line
/// and `human` on stdout; the error, next action and warnings on stderr.
pub fn emit_rendered(envelope: &Envelope<serde_json::Value>, json: bool, human: &str) {
    if json {
        emit(envelope, true);
        return;
    }
    let mut head = envelope.code.as_str().to_owned();
    if let Some(op) = &envelope.operation_id {
        head.push_str(" operation ");
        head.push_str(op.as_str());
    }
    println!("{}", sanitize_for_terminal(&head));
    if !human.trim().is_empty() {
        println!("{}", sanitize_for_terminal(human.trim_end()));
    }
    let field =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
    if let Some(error) = envelope.data.get("error") {
        if let Some(msg) = field(error, "message") {
            eprintln!("error: {}", sanitize_for_terminal(&msg));
        }
        if let Some(reason) = field(error, "reason") {
            eprintln!("reason: {}", sanitize_for_terminal(&reason));
        }
        if let Some(effect) = field(error, "effect_status") {
            eprintln!("effect: {}", sanitize_for_terminal(&effect));
        }
    }
    if let Some(next) = &envelope.next {
        let mut line = format!("next: {}", next.action);
        if let Some(v) = &next.operation_id {
            line.push_str(&format!(" operation_id={v}"));
        }
        if let Some(v) = &next.decision_ref {
            line.push_str(&format!(" decision_ref={v}"));
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

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v.get(k).and_then(serde_json::Value::as_str).unwrap_or("")
}

fn list<'a>(v: &'a serde_json::Value, k: &str) -> &'a [serde_json::Value] {
    v.get(k)
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// One behaviour column (`before`, `after`, `restore`) of a plan's alias: its digest
/// prefix and each relevant directive with its certainty.
fn behaviour_column(v: &serde_json::Value) -> String {
    let digest = s(v, "digest");
    let mut out = format!("digest {}", digest.get(..12).unwrap_or(digest));
    for d in list(v, "directives") {
        let values: Vec<&str> = list(d, "values")
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        let certainty = s(d, "certainty");
        out.push_str(&format!(
            "; {} {} ({certainty})",
            s(d, "directive"),
            if values.is_empty() {
                "-".to_owned()
            } else {
                values.join(" | ")
            },
        ));
    }
    out
}

/// A setup plan (`SetupPlan` wire form) for the owner: the mode and its reasons, every
/// file with its diff, every affected alias with its before, after and **restore**
/// columns, the consent need and the findings (ADR-0007 §5.1, §5.2).
#[must_use]
pub fn render_plan(plan: &serde_json::Value) -> String {
    let mut out = String::new();
    let intent = plan.get("intent").cloned().unwrap_or_default();
    out.push_str(&format!(
        "Setup plan: {} ({} mode), plan digest {}\n",
        s(&intent, "kind"),
        s(plan, "mode"),
        s(plan, "plan_digest")
    ));
    let reasons: Vec<&str> = list(plan, "manual_reasons")
        .iter()
        .filter_map(|r| r.as_str())
        .collect();
    if !reasons.is_empty() {
        out.push_str(&format!(
            "Manual mode: Heimdall will not edit your file ({}); add the include block yourself.\n",
            reasons.join(", ")
        ));
    }
    let files = list(plan, "files");
    if files.is_empty() {
        out.push_str("Files: none change.\n");
    }
    for f in files {
        out.push_str(&format!(
            "File {} ({}): {} -> {}\n",
            s(f, "path_display"),
            s(f, "role"),
            f.get("before_sha256")
                .and_then(|x| x.as_str())
                .map_or("absent", |d| d.get(..12).unwrap_or(d)),
            f.get("after_sha256")
                .and_then(|x| x.as_str())
                .map_or("absent", |d| d.get(..12).unwrap_or(d)),
        ));
        let diff = s(f, "diff");
        if !diff.is_empty() {
            for line in diff.lines() {
                out.push_str(&format!("    {line}\n"));
            }
        }
    }
    if let Some(git) = plan.get("git").filter(|g| !g.is_null()) {
        out.push_str(&format!(
            "Git include: {}{}\n",
            s(git, "applicability"),
            git.get("reason")
                .and_then(|r| r.as_str())
                .map_or(String::new(), |r| format!(" ({r})")),
        ));
    }
    for a in list(plan, "aliases") {
        out.push_str(&format!("Alias {} ({}):\n", s(a, "alias"), s(a, "kind")));
        out.push_str(&format!(
            "    before:  {}\n",
            behaviour_column(a.get("before").unwrap_or(&serde_json::Value::Null))
        ));
        out.push_str(&format!(
            "    after:   {}\n",
            behaviour_column(a.get("after").unwrap_or(&serde_json::Value::Null))
        ));
        match a.get("restore").filter(|r| !r.is_null()) {
            Some(r) => out.push_str(&format!("    restore: {}\n", behaviour_column(r))),
            None => out.push_str("    restore: (not recorded for this plan)\n"),
        }
        if let Some(sel) = a.get("identity_selection").filter(|x| !x.is_null()) {
            out.push_str(&format!(
                "    identity selection: {} (IdentitiesOnly {})\n",
                s(sel, "selection"),
                s(sel, "identities_only")
            ));
        }
    }
    let consent = plan.get("consent").cloned().unwrap_or_default();
    if consent
        .get("decision_required")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        let why: Vec<String> = list(&consent, "reasons")
            .iter()
            .map(|r| format!("{} ({})", s(r, "item"), s(r, "kind")))
            .collect();
        out.push_str(&format!("Needs your decision: {}\n", why.join(", ")));
    } else {
        out.push_str("Needs no new decision: every affected state is one you consented to.\n");
    }
    for f in list(plan, "findings") {
        out.push_str(&format!(
            "Finding {} ({}): {}\n",
            s(f, "code"),
            s(f, "severity"),
            s(f, "message")
        ));
    }
    out
}

/// A setup result (`SetupResult` wire form): each item's outcome and files, and what
/// remains for the owner.
#[must_use]
pub fn render_setup_result(result: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(g) = result.get("generation").and_then(serde_json::Value::as_u64) {
        out.push_str(&format!("Generation {g}\n"));
    }
    for item in list(result, "items") {
        out.push_str(&format!(
            "Item {}: {}\n",
            s(item, "item"),
            s(item, "outcome")
        ));
        for f in list(item, "files") {
            out.push_str(&format!(
                "    {} ({}): {}\n",
                s(f, "path_display"),
                s(f, "role"),
                s(f, "state")
            ));
        }
    }
    let remaining = list(result, "remaining");
    if !remaining.is_empty() {
        out.push_str("Remaining for you:\n");
        for r in remaining {
            out.push_str(&format!("    {} {}\n", s(r, "kind"), s(r, "path_display")));
        }
    }
    out
}

/// The two repair commands of a held setup operation, one sentence each (m02-plan U9;
/// ADR-0007 §5.7 "Repair path").
#[must_use]
pub fn held_repair_commands(operation: &str) -> String {
    format!(
        "heimdall setup repair --operation {operation} retry\n    Runs the held operation's recovery again, after you put the file it names back; it continues exactly the recorded plan.\n\
         heimdall setup repair --operation {operation} keep\n    Closes the operation keeping every file as it is now; nothing is moved, and what stays in place is listed.\n"
    )
}

/// A doctor report (`DoctorReport` wire form) for the owner. Every probe that ran the
/// real configuration tree lists its `executed_config_commands` under
/// [`INVENTORY_HEADING`] (never called complete), and its `config_tree_differences`
/// when `config_tree_changed` is `true` (ADR-0007 §6).
#[must_use]
pub fn render_doctor(report: &serde_json::Value) -> String {
    let mut out = String::new();
    let levels = |k: &str| -> String {
        let v: Vec<&str> = list(report, k).iter().filter_map(|x| x.as_str()).collect();
        if v.is_empty() {
            "none".to_owned()
        } else {
            v.join(", ")
        }
    };
    out.push_str(&format!(
        "Levels performed: {}\n",
        levels("levels_performed")
    ));
    out.push_str(&format!("Levels declined: {}\n", levels("levels_declined")));
    for c in list(report, "clients") {
        out.push_str(&format!(
            "Client {} {} {}{}\n",
            s(c, "consumer"),
            s(c, "path_display"),
            c.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("version unknown"),
            if c.get("selected").and_then(serde_json::Value::as_bool) == Some(true) {
                " (selected)"
            } else {
                ""
            }
        ));
    }
    if let Some(p) = report.get("projection").filter(|p| !p.is_null()) {
        out.push_str(&format!(
            "Projection: {}{}\n",
            s(p, "state"),
            p.get("conflict")
                .and_then(|c| c.as_str())
                .map_or(String::new(), |c| format!(" (conflict {c})"))
        ));
    }
    for a in list(report, "aliases") {
        let sel = a
            .get("identity_selection")
            .filter(|x| !x.is_null())
            .map_or(String::new(), |sel| {
                format!(", identity selection {}", s(sel, "selection"))
            });
        out.push_str(&format!(
            "Alias {} ({}){sel}\n",
            s(a, "alias"),
            s(a, "definition")
        ));
    }
    for f in list(report, "findings") {
        let at = f
            .get("provenance")
            .filter(|p| !p.is_null())
            .map_or(String::new(), |p| {
                format!(
                    " at {}:{}",
                    s(p, "path_display"),
                    p.get("line")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                )
            });
        out.push_str(&format!(
            "Finding {} ({}){at}: {}\n",
            s(f, "code"),
            s(f, "severity"),
            s(f, "message")
        ));
    }
    for p in list(report, "probes") {
        out.push_str(&format!(
            "Probe {} {}: {}",
            s(p, "level"),
            s(p, "target"),
            s(p, "outcome")
        ));
        if let Some(r) = p.get("decline_reason").and_then(|r| r.as_str()) {
            out.push_str(&format!(" ({r})"));
        }
        let auth: Vec<&str> = list(p, "authorization")
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        if !auth.is_empty() {
            out.push_str(&format!(", authorized by {}", auth.join(", ")));
        }
        out.push('\n');
        if let Some(changed) = p
            .get("config_tree_changed")
            .and_then(serde_json::Value::as_bool)
        {
            out.push_str(&format!("    {INVENTORY_HEADING}:\n"));
            let found = list(p, "executed_config_commands");
            if found.is_empty() {
                out.push_str("        (none found before the run)\n");
            }
            for c in found {
                out.push_str(&format!(
                    "        {}:{}\n",
                    s(c, "path_display"),
                    c.get("line")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                ));
            }
            if changed {
                out.push_str("    the configuration tree differed after the run:\n");
                for d in list(p, "config_tree_differences") {
                    out.push_str(&format!(
                        "        {} {}\n",
                        s(d, "change"),
                        s(d, "path_display")
                    ));
                }
            }
        }
    }
    out
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
