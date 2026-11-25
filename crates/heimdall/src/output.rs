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

/// Whether `c` can reorder or hide the text around it: a Unicode format character
/// (general category Cf: the bidirectional marks, embeddings, overrides and isolates
/// U+200E–U+200F, U+202A–U+202E and U+2066–U+2069, the zero-width and invisible
/// characters, the soft hyphen, the Arabic and other prepended number signs, the
/// interlinear annotation and tag characters), or the line and paragraph separators
/// U+2028 and U+2029. ⟨M05⟩ Review M05-W3-R03: the one character class of inert data text,
/// for the CLI's [`quoted_field`] and the TUI's `tui::m05::{safe, quoted}`.
#[must_use]
pub(crate) fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// ⟨M05⟩ Review M05-W3-R03: a human **data** field (a path, a repository label: text the
/// file system or a repository chose) as one inert quoted token, so it can neither start a
/// line of its own nor reorder the text around it. Between double quotes, `"` and `\` are
/// escaped and every line break and control character is written as its escape (`\n`,
/// `\r`, `\t`, `\u2028`, `\u2029`, `\u00XX`), as in JSON; a bidirectional or invisible
/// formatting character ([`is_invisible_format`]) is removed, and a note then says so.
/// Heimdall's own prose and layout never pass through it; `--json` output is data and is
/// unchanged.
#[must_use]
pub(crate) fn quoted_field(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    let mut removed = false;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c if is_invisible_format(c) => removed = true,
            c => out.push(c),
        }
    }
    out.push('"');
    if removed {
        out.push_str(" (invisible formatting characters removed)");
    }
    out
}

/// ⟨M05⟩ Review M05-W3-RC01: a JSON value pretty-printed for a **human** reader, inert. The
/// text is `serde_json`'s pretty form with every bidirectional or invisible formatting
/// character ([`is_invisible_format`]) written as its JSON escape (`\u202e`; a character
/// beyond U+FFFF as its surrogate pair), so it can neither reorder nor hide the text around
/// it, and the printed JSON still denotes exactly the same value (such characters only ever
/// appear inside JSON strings). Plain text is byte-identical to `to_string_pretty`. For the
/// recorded request a confirmation prompt shows and every human JSON dump; `--json` output
/// is data and never passes through it.
#[must_use]
pub(crate) fn human_json(v: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let text = serde_json::to_string_pretty(v).unwrap_or_default();
    if !text.chars().any(is_invisible_format) {
        return text;
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if is_invisible_format(c) {
            let mut units = [0_u16; 2];
            for u in c.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{u:04x}");
            }
        } else {
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
    if let Some(summary) = value["data"][HUMAN_STATUS].as_str() {
        println!("{}", sanitize_for_terminal(summary));
        if let Some(message) = value["data"]["error"]["message"].as_str() {
            diagnostic(message);
        }
        for warning in &envelope.warnings {
            diagnostic(&warning.message);
        }
        return;
    }
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
        // ⟨M03⟩ The stable reason (`lock_signal_unavailable`, `pair_not_enrolled`, …)
        // is part of what the owner acts on; `emit_rendered` prints it the same way.
        if let Some(reason) = field(error, "reason") {
            eprintln!("reason: {}", sanitize_for_terminal(&reason));
        }
        if let Some(line) = item_bound_line(error) {
            eprintln!("{}", sanitize_for_terminal(&line));
        }
        if let Some(effect) = field(error, "effect_status") {
            eprintln!("effect: {}", sanitize_for_terminal(&effect));
        }
    } else if !data.is_null() {
        let text = human_json(&data);
        println!("{}", sanitize_for_terminal(&text));
        for line in m03_lines(&data) {
            println!("{}", sanitize_for_terminal(&line));
        }
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

/// ⟨rev7; D20, PC11⟩ An `item_too_large` refusal's typed detail in plain words: the field,
/// its bound and the item, never the refused value (`too large: pairs may hold at most 200
/// entries (profile work)`). `None` for a detail without one.
pub(crate) fn item_bound_line(error: &serde_json::Value) -> Option<String> {
    let field = error.get("field")?.as_str()?;
    let bound = error.get("bound")?.as_u64()?;
    let mut line = match error.get("unit")?.as_str()? {
        "entries" => format!("too large: {field} may hold at most {bound} entries"),
        "bytes" => format!("too large: {field} may be at most {bound} bytes"),
        _ => format!("too large: {field} is over its bound of {bound}"),
    };
    if let Some(r) = error.get("resource") {
        let kind = r.get("kind").and_then(serde_json::Value::as_str);
        let id = r.get("id").and_then(serde_json::Value::as_str);
        match (kind, id) {
            (Some(kind), Some(id)) => line.push_str(&format!(" ({kind} {id})")),
            (Some(kind), None) => line.push_str(&format!(" ({kind})")),
            _ => {}
        }
    }
    Some(line)
}

/// Private to the top-level status handler and populated only for human output.
pub(crate) const HUMAN_STATUS: &str = "__human_status";
pub(crate) const STATUS_LISTINGS: &str = "__status_listings";

pub(crate) fn render_status(
    data: &serde_json::Value,
    chores: &[crate::doctor_cmd::PendingChore],
) -> String {
    let open = data["open_operations"].as_u64().unwrap_or_default();
    let waiting = data["pending_decisions"].as_u64().unwrap_or_default();
    let mut status = if data["running"] == true {
        let listings = &data[STATUS_LISTINGS];
        let access = status_access(listings, s(data, "environment_id"));
        let lock = &listings["capabilities"]["lock"];
        let setting = match s(lock, "behavior") {
            "continue" => "saved personal setting \"continue\"",
            "revoke_on_lock" => "saved personal setting \"revoke on lock\"",
            "" => "saved setting not reported by the runtime",
            _ => "saved setting not recognized",
        };
        let disclosure = lock["disclosure"]
            .as_str()
            .filter(|text| !text.trim().is_empty())
            .unwrap_or("The runtime sent no disclosure. Whether work keeps going at a lock is unverified here.");
        format!(
            "Heimdall is running on this machine.\n\
             Activity: {open} open, {waiting} waiting for your approval.\n\
             {access}\n\
             Desktop lock: {setting}.\n\
             {disclosure}\n\
             Pause automatic access with `heimdall access pause --profile <profile>` or stop work with `heimdall access stop --work <work-id>`."
        )
    } else {
        "Heimdall status is unavailable.".to_owned()
    };
    for chore in chores {
        let message = if chore.chore == crate::doctor_cmd::TIME_CONFIRMATION_CHORE {
            "Confirm this machine's clock with `heimdall time confirm` so Heimdall can prepare new access."
        } else {
            &chore.message
        };
        if !message.is_empty() {
            status.push('\n');
            status.push_str(message);
        }
    }
    status
}

fn status_access(listings: &serde_json::Value, own: &str) -> String {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;

    use heimdall_contract::environment::{EnvironmentsView, RealizationView};
    use heimdall_contract::trust::PoliciesView;
    use serde::Deserialize as _;

    let environments = EnvironmentsView::deserialize(&listings["environments"]).ok();
    let policies = PoliciesView::deserialize(&listings["policies"]).ok();
    let now = heimdall_contract::Timestamp::now();
    let active = listings["bindings"]["bindings"]
        .as_array()
        .zip(listings["grants"]["grants"].as_array())
        .map(|(bindings, grants)| {
            let current: BTreeMap<_, _> = grants
                .iter()
                .filter(|g| {
                    heimdall_contract::Timestamp::deserialize(&g["expires_at"])
                        .is_ok_and(|at| at > now)
                })
                .map(|g| (s(g, "grant_id"), s(g, "state")))
                .collect();
            let mut ready = 0;
            let mut limited = 0;
            for binding in bindings.iter().filter(|b| b["state"] == "active") {
                match current.get(s(binding, "grant_id")).copied() {
                    Some("active") => ready += 1,
                    Some("degraded") => limited += 1,
                    _ => {}
                }
            }
            (ready, limited)
        });
    let mut access = String::new();
    if let Some(environments) = environments.filter(|e| !e.items.is_empty()) {
        for env in &environments.items {
            let name = match (&env.label, &env.realization) {
                (Some(label), _) => quoted_field(label),
                (None, RealizationView::Wsl { name, .. }) => format!("WSL {}", quoted_field(name)),
                (None, RealizationView::Container { label, .. }) => {
                    format!("container {}", quoted_field(label))
                }
                (None, _) if env.environment_id.as_str() == own => "this computer".to_owned(),
                (None, _) => "a native session".to_owned(),
            };
            let Some(policies) = &policies else {
                let _ = writeln!(access, "Access for {name}: not available.");
                continue;
            };
            let mut scopes = BTreeMap::new();
            scopes.insert(None, (BTreeSet::new(), BTreeSet::new()));
            for policy in policies
                .items
                .iter()
                .filter(|p| p.environments.contains(&env.environment_id))
            {
                let scope = policy.workspace_id.as_ref().map(|id| id.as_str());
                let (automatic, paused) = scopes.entry(scope).or_default();
                let profiles = if policy.paused_since.is_some()
                    || policy.cutoff_at.is_some_and(|at| at <= now)
                {
                    paused
                } else {
                    automatic
                };
                profiles.insert(policy.profile.as_str());
            }
            for (project, (automatic, paused)) in scopes {
                if let Some(project) = project {
                    let _ = write!(
                        access,
                        "Project {} access on {name}: ",
                        quoted_field(project)
                    );
                } else {
                    let _ = write!(access, "Personal access on {name}: ");
                }
                if automatic.is_empty() {
                    access.push_str("none configured for automatic use");
                } else {
                    let automatic = automatic.iter().copied().collect::<Vec<_>>().join(", ");
                    let _ = write!(access, "{automatic} configured for automatic use");
                }
                let paused: Vec<_> = paused.difference(&automatic).copied().collect();
                if !paused.is_empty() {
                    let _ = write!(access, " (paused: {})", paused.join(", "));
                }
                access.push_str(".\n");
            }
        }
        // The current listings expose active work without the environment that holds it.
        if environments.items.len() == 1 && environments.items[0].environment_id.as_str() == own {
            let _ = write!(
                access,
                "Active work on this computer: {}.",
                active_work(active)
            );
        } else {
            let _ = write!(
                access,
                "Active work across environments: {}.",
                active_work(active)
            );
            if active.is_some_and(|(ready, limited)| ready + limited > 0) {
                access.push_str(" Work by environment is not available from this runtime.");
            }
        }
    } else {
        let _ = write!(
            access,
            "Access by environment: not available.\nActive work: {}.",
            active_work(active)
        );
    }
    access
}

fn active_work(count: Option<(usize, usize)>) -> String {
    use std::fmt::Write as _;

    match count {
        None => "not available".to_owned(),
        Some((0, 0)) => "no sessions have access".to_owned(),
        Some((ready, limited)) => {
            let mut summary = match ready {
                0 => String::new(),
                1 => "1 session has access".to_owned(),
                n => format!("{n} sessions have access"),
            };
            if limited > 0 {
                if ready > 0 {
                    summary.push_str(", ");
                }
                let noun = if limited == 1 { "session" } else { "sessions" };
                let _ = write!(summary, "{limited} {noun} with limited access");
            }
            summary
        }
    }
}

/// Explain a slow synchronous server request.
pub(crate) async fn explain_wait<T>(
    human: bool,
    what: &str,
    operation: Option<&heimdall_contract::ids::OperationId>,
    wait: impl std::future::Future<Output = T>,
) -> T {
    explain_slow_wait(human, wait, || {
        let here = operation.map_or_else(String::new, |id| format!(" (operation {id})"));
        let next = operation.map_or_else(
            || "Find the ID with `heimdall inspect operations`, then run `heimdall operation show <id>`.".to_owned(),
            |id| format!("Check with `heimdall operation show {id}`."),
        );
        format!("Waiting for {what}{here}. Ctrl-C stops waiting but does not cancel the request. {next}")
    })
    .await
}

/// Report a slow wait once and keep driving the same future.
pub(crate) async fn explain_slow_wait<T>(
    human: bool,
    wait: impl std::future::Future<Output = T>,
    notice: impl FnOnce() -> String,
) -> T {
    if !human {
        return wait.await;
    }
    tokio::pin!(wait);
    tokio::select! {
        biased;
        answer = &mut wait => return answer,
        () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
    }
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        sanitize_for_terminal(&notice())
    );
    wait.await
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
    // ⟨M03⟩ `destination show|list`: each managed pair's connection policy, in the
    // runtime's own words (ADR-0008 §17.25 item 19; D9 item 1).
    for line in destination_lines(&envelope.data) {
        println!("{}", sanitize_for_terminal(&line));
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
        if let Some(line) = item_bound_line(error) {
            eprintln!("{}", sanitize_for_terminal(&line));
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

/// How a plan's diff line says that one of Heimdall's own files (P, P_git, a key file) is
/// removed (ADR-0007 §12.34 item 7): the file's name, its number of lines and the SHA-256
/// of the removed content, instead of the content. `None` when `line` is not that
/// summary line (a diff line, or a path heading).
#[must_use]
pub(crate) fn own_removal_text(line: &str) -> Option<String> {
    let r = heimdall_localenv::projection::plan::OwnRemoval::parse(line)?;
    Some(format!(
        "removes Heimdall's own file {}: {} line{}, sha256 {}",
        r.name,
        r.lines,
        if r.lines == 1 { "" } else { "s" },
        r.sha256
    ))
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
                // ADR-0007 §12.34 item 7: the removal of one of Heimdall's own files is a
                // summary line, said as such; everything else is the diff, whole.
                let line = own_removal_text(line).unwrap_or_else(|| line.to_owned());
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

// ---- ⟨M03⟩ wave 5 (U12): the human rendering of the M03 access results. `--json`
// prints the envelope only ([`emit`]); human mode adds these lines to the data it
// already prints. Nothing here decides anything: every sentence the runtime wrote
// (the deadline wording, a warning such as `signal_unverified`) is shown verbatim.

/// The revoke note code `ordinary_connections_not_closed` (`RevokeNote`, F15).
pub(crate) const ORDINARY_CONNECTIONS_NOT_CLOSED: &str = "ordinary_connections_not_closed";

/// What the fixed revoke note `ordinary_connections_not_closed` says (ADR-0008 D7
/// item 2 step 6): connections that ordinary `ssh` opened through the managed
/// configuration, and any unmanaged connection, are not closed. The contract carries
/// the code only, so this text is the CLI's (and the TUI's) one rendering of it.
pub(crate) const ORDINARY_CONNECTIONS_NOTE: &str = "Connections that ordinary ssh opened through Heimdall's configuration, and connections Heimdall did not start, are not closed.";

/// The text of a revoke note code; a code this build does not know is shown as is.
#[must_use]
pub(crate) fn revoke_note_text(code: &str) -> String {
    if code == ORDINARY_CONNECTIONS_NOT_CLOSED {
        ORDINARY_CONNECTIONS_NOTE.to_owned()
    } else {
        code.to_owned()
    }
}

/// One owned connection of a revoke's cascade, for people (F15).
fn owned_connection_line(c: &serde_json::Value) -> String {
    let state = s(c, "state");
    let meaning = match state {
        "closed" => "",
        "closing" => " (being closed)",
        "unverified" => {
            " (not signalled: its process could not be verified, so it is treated as unmanaged)"
        }
        _ => "",
    };
    format!("  {} ({}): {state}{meaning}", s(c, "id"), s(c, "kind"))
}

/// The mechanism name of a managed-certificate binding and preference (D1).
const MANAGED_CERTIFICATE: &str = "managed_certificate";

/// What a managed result or pair shows when the runtime reports no connection policy
/// (after a restart, an attached binding; ADR-0008 §17.25 item 18): never a guess.
pub(crate) const CONNECTION_POLICY_UNKNOWN: &str =
    "Connection policy: unknown (the runtime reports none for this result).";

/// The lines of a `ConnectionPolicyReport` (`{existing, multiplexing, wording}`): the
/// policy, then the runtime's own D8 wording, verbatim.
fn connection_policy_lines(cp: &serde_json::Value, head: &str) -> Vec<String> {
    let mut out = vec![format!(
        "{head}existing {}, multiplexing {}.",
        s(cp, "existing"),
        s(cp, "multiplexing")
    )];
    let wording = s(cp, "wording");
    if !wording.is_empty() {
        out.push(wording.to_owned());
    }
    out
}

/// ⟨§17.25 item 19⟩ The connection-policy lines of `destination show` (one destination
/// object) or `destination list` / `inspect destinations` (the runtime's `items[]`,
/// `Operations::destinations_view`; ⟨§17.27 item 9⟩ and the older `destinations[]`): for each
/// destination whose `preference` names the managed mechanism, the policy and the
/// runtime's wording (`preference.connection_policy`) verbatim, or that it is unknown.
/// A destination without a managed preference (every M02 listing) gives no line.
#[must_use]
pub(crate) fn destination_lines(data: &serde_json::Value) -> Vec<String> {
    let one = |d: &serde_json::Value| -> Vec<String> {
        let Some(p) = d.get("preference").filter(|p| p.is_object()) else {
            return Vec::new();
        };
        let name = match (s(d, "alias"), s(d, "destination_id")) {
            ("", id) => id.to_owned(),
            (alias, _) => alias.to_owned(),
        };
        match p.get("connection_policy").filter(|c| c.is_object()) {
            Some(cp) => connection_policy_lines(cp, &format!("{name}: connection policy: ")),
            None if s(p, "mechanism") == MANAGED_CERTIFICATE => vec![format!(
                "{name}: connection policy unknown (the runtime reports none for this pair)."
            )],
            None => Vec::new(),
        }
    };
    if let Some(items) = data
        .get("items")
        .or_else(|| data.get("destinations"))
        .and_then(serde_json::Value::as_array)
    {
        return items.iter().flat_map(one).collect();
    }
    if data.get("destination_id").is_some() {
        return one(data);
    }
    Vec::new()
}

/// The M03 lines of a success result's data, after the data itself (human mode):
///
/// * `connection_policy` (an `ensure` result): the policy in force and the runtime's
///   own deadline wording, verbatim; a managed result without it says it is unknown;
/// * `lock_behavior` and `connection` (the `access lock-behavior` and
///   `connection-policy` results, §17.25 item 22): this policy's stored values;
/// * a revoke result's `owned_connections` (how many closed, how many remain, each
///   with its state), its `remote_effects` residuals and its fixed `notes`;
/// * `inspect destinations`: [`destination_lines`].
///
/// Data without those keys (every M01 and M02 result) gives no lines.
#[must_use]
pub(crate) fn m03_lines(data: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(cp) = data.get("connection_policy").filter(|c| c.is_object()) {
        out.extend(connection_policy_lines(cp, "Connection policy: "));
    } else if s(data, "credential_mechanism") == MANAGED_CERTIFICATE {
        out.push(CONNECTION_POLICY_UNKNOWN.to_owned());
    }
    if let Some(b) = data
        .get("lock_behavior")
        .and_then(serde_json::Value::as_str)
    {
        out.push(format!("Lock behaviour: {b}."));
    }
    if let Some(c) = data.get("connection").filter(|c| c.is_object()) {
        out.push(format!(
            "Connections: existing {}, multiplexing {}.",
            s(c, "existing"),
            s(c, "multiplexing")
        ));
    }
    out.extend(destination_lines(data));
    let connections = list(data, "owned_connections");
    let notes = list(data, "notes");
    if !connections.is_empty() || !notes.is_empty() {
        let closed = connections
            .iter()
            .filter(|c| s(c, "state") == "closed")
            .count();
        let remaining = connections.len() - closed;
        out.push(format!(
            "Owned connections: {closed} closed, {remaining} remaining."
        ));
        out.extend(connections.iter().map(owned_connection_line));
    }
    for r in list(data, "remote_effects") {
        out.push(format!(
            "Remote residual: {}/{} until {} ({}).",
            s(r, "destination"),
            s(r, "account"),
            s(r, "latest_valid_before"),
            s(r, "status")
        ));
    }
    for n in notes.iter().filter_map(serde_json::Value::as_str) {
        out.push(format!("Note: {}", revoke_note_text(n)));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const UNVERIFIED_LOCK: &str = "Approved work is designed to keep working while your screen or password manager is locked, until the end time you approve. On this computer that has not been verified yet.";

    fn status_data() -> serde_json::Value {
        let mut data = serde_json::json!({
            "running": true,
            "environment_id": "env_lab",
            "operation_counts": {"awaiting_approval": 1},
            "open_operations": 3,
            "pending_decisions": 1,
        });
        data[STATUS_LISTINGS] = serde_json::json!({
            "environments": {"items": [{
                "environment_id": "env_lab",
                "kind": "native_session",
                "state": "active",
                "realization": {"kind": "native"}
            }]},
            "policies": {"items": [
                {"policy_id": "pol-on", "revision": 1, "profile": "lab", "environments": ["env_lab"]},
                {"policy_id": "pol-off", "revision": 1, "profile": "ops", "environments": ["env_lab"],
                 "cutoff_at": "2000-01-01T00:00:00Z"},
            ]},
            "bindings": {"bindings": [
                {"grant_id": "ready", "state": "active"},
                {"grant_id": "ready", "state": "released"},
                {"grant_id": "expired", "state": "active"}
            ]},
            "grants": {"grants": [
                {"grant_id": "ready", "state": "active", "expires_at": "2099-01-01T00:00:00Z"},
                {"grant_id": "expired", "state": "active", "expires_at": "2000-01-01T00:00:00Z"}
            ]},
            "capabilities": {"lock": {"behavior": "continue", "disclosure": UNVERIFIED_LOCK}},
        });
        data
    }

    #[test]
    fn status_uses_everyday_vocabulary() {
        let shown = render_status(&status_data(), &[]).to_ascii_lowercase();
        for private in [
            "grant",
            "lease",
            "certificate",
            "issuer",
            "generation",
            "epoch",
            "principal",
            "awaiting_approval",
            "open_operations",
            "native_session",
            "revoke_on_lock",
        ] {
            assert!(
                !shown
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|word| word == private),
                "{shown}"
            );
        }
        assert!(shown.contains("this machine"));
        assert!(shown.contains("activity: 3 open, 1 waiting"));
        assert!(shown.contains(
            "personal access on this computer: lab configured for automatic use (paused: ops)"
        ));
        let chore = crate::doctor_cmd::PendingChore {
            chore: crate::doctor_cmd::TIME_CONFIRMATION_CHORE,
            command: crate::doctor_cmd::TIME_CONFIRM_COMMAND,
            message: "technical time warning".to_owned(),
        };
        let offline = render_status(&serde_json::Value::Null, &[chore]);
        assert!(offline.contains("Heimdall status is unavailable."));
        assert!(offline.contains("Confirm this machine's clock with `heimdall time confirm`"));
    }

    #[test]
    fn status_answers_the_three_questions() {
        let mut data = status_data();
        let shown = render_status(&data, &[]);
        assert!(shown.contains(
            "Personal access on this computer: lab configured for automatic use (paused: ops)."
        ));
        assert!(shown.contains("Active work on this computer: 1 session has access."));
        assert!(shown.contains(&format!(
            "Desktop lock: saved personal setting \"continue\".\n{UNVERIFIED_LOCK}\n"
        )));
        assert!(shown.contains("heimdall access pause --profile"));
        assert!(shown.contains("heimdall access stop --work"));

        let listings = &mut data[STATUS_LISTINGS];
        listings["environments"]["items"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "environment_id": "env_other", "kind": "native_session", "label": "Other machine",
                "state": "active", "realization": {"kind": "native"}
            }));
        listings["policies"]["items"][0]["environments"]
            .as_array_mut()
            .unwrap()
            .push("env_other".into());
        listings["capabilities"]["lock"]["behavior"] = "revoke_on_lock".into();
        let disclosure = format!(
            "{UNVERIFIED_LOCK} Work under your saved policy \"pol-off\" ends when you lock the screen (revoke on lock)."
        );
        listings["capabilities"]["lock"]["disclosure"] = disclosure.as_str().into();
        let shown = render_status(&data, &[]);
        assert!(
            shown.contains(
                "Personal access on \"Other machine\": lab configured for automatic use."
            )
        );
        assert!(shown.contains("Active work across environments: 1 session has access."));
        assert!(shown.contains("Work by environment is not available from this runtime."));
        assert!(shown.contains(&format!(
            "Desktop lock: saved personal setting \"revoke on lock\".\n{disclosure}\n"
        )));

        data[STATUS_LISTINGS]["grants"]["grants"][0]["state"] = "degraded".into();
        let shown = render_status(&data, &[]);
        assert!(shown.contains("Active work across environments: 1 session with limited access."));

        let mut paused = status_data();
        paused[STATUS_LISTINGS]["policies"]["items"][0]["paused_since"] =
            "2000-01-01T00:00:00Z".into();
        paused[STATUS_LISTINGS]["bindings"]["bindings"] = serde_json::json!([]);
        let shown = render_status(&paused, &[]);
        assert!(
            shown.contains("Personal access on this computer: none configured for automatic use (paused: lab, ops).")
        );
        assert!(shown.contains("Active work on this computer: no sessions have access."));

        data[STATUS_LISTINGS] = serde_json::Value::Null;
        let shown = render_status(&data, &[]);
        assert!(shown.contains("Access by environment: not available."));
        assert!(shown.contains("Active work: not available."));
        assert!(shown.contains("Desktop lock: saved setting not reported by the runtime."));
        assert!(shown.contains("Whether work keeps going at a lock is unverified here."));
    }

    #[test]
    fn status_scopes_project_policies_separately_from_personal_policies() {
        let mut data = status_data();
        let items = data[STATUS_LISTINGS]["policies"]["items"]
            .as_array_mut()
            .unwrap();
        items[0]["paused_since"] = "2000-01-01T00:00:00Z".into();
        items.push(serde_json::json!({
            "policy_id": "pol-project", "revision": 1, "profile": "lab",
            "environments": ["env_lab"], "workspace_id": "ws_project"
        }));
        let shown = render_status(&data, &[]);
        let project =
            "Project \"ws_project\" access on this computer: lab configured for automatic use.";
        assert!(shown.contains(project));
        assert!(shown.contains(
            "Personal access on this computer: none configured for automatic use (paused: lab, ops)."
        ));

        data[STATUS_LISTINGS]["policies"]["items"]
            .as_array_mut()
            .unwrap()
            .drain(..2);
        let shown = render_status(&data, &[]);
        assert!(shown.contains(project));
        assert!(
            shown.contains("Personal access on this computer: none configured for automatic use.")
        );
    }

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

    /// ADR-0007 §12.34 item 7: a plan that removes files of Heimdall's own shows each as
    /// a removal with its name, line count and SHA-256 (not the raw writer line, not the
    /// content); the owner's file is its diff, whole.
    #[test]
    fn a_plan_shows_a_removed_file_of_heimdalls_own_as_a_removal() {
        let sha = "ab".repeat(32);
        let plan = serde_json::json!({
            "intent": {"kind": "rollback"},
            "mode": "automatic",
            "plan_digest": "plan_x",
            "files": [
                {
                    "role": "user_ssh",
                    "path_display": "~/.ssh/config",
                    "before_sha256": "11".repeat(32),
                    "after_sha256": "22".repeat(32),
                    "diff": "-# >>> heimdall managed include\n-Include ~/.config/heimdall/ssh_config\n",
                },
                {
                    "role": "managed_ssh",
                    "path_display": "~/.config/heimdall/ssh_config",
                    "before_sha256": sha,
                    "diff": format!("~ removed ssh_config: 1234 lines, sha256 {sha}\n"),
                },
                {
                    "role": "key_file",
                    "path_display": "~/.config/heimdall/keys/k.pub",
                    "before_sha256": sha,
                    "diff": format!("~ removed k.pub: 1 line, sha256 {sha}\n"),
                },
            ],
        });
        let text = render_plan(&plan);
        for line in [
            "    -# >>> heimdall managed include\n".to_owned(),
            "    -Include ~/.config/heimdall/ssh_config\n".to_owned(),
            format!("    removes Heimdall's own file ssh_config: 1234 lines, sha256 {sha}\n"),
            format!("    removes Heimdall's own file k.pub: 1 line, sha256 {sha}\n"),
        ] {
            assert!(text.contains(&line), "{line:?} is missing from\n{text}");
        }
        assert!(!text.contains("~ removed"), "{text}");
        // A line that merely looks like it is a diff line like any other.
        assert!(own_removal_text("-~ removed x: 1 line, sha256 00").is_none());
        assert!(own_removal_text("~ removed x: 1 line, sha256 short").is_none());
    }

    /// ⟨rev7; D20, PC11⟩ The human rendering of an `item_too_large` refusal names the field
    /// and the bound in plain words, from the typed detail; another error has no such line.
    #[test]
    fn an_item_too_large_refusal_names_the_field_and_the_bound() {
        let e = heimdall_app::OpError::new(Code::UsageError, "m")
            .with_reason(heimdall_contract::envelope::reason::ITEM_TOO_LARGE)
            .with_item_bound(
                "pairs",
                200,
                heimdall_contract::envelope::BoundUnit::Entries,
            )
            .with_resource("profile", Some("work".to_owned()));
        let v = serde_json::to_value(e.detail()).unwrap();
        assert_eq!(
            item_bound_line(&v).as_deref(),
            Some("too large: pairs may hold at most 200 entries (profile work)")
        );
        let e = heimdall_app::OpError::new(Code::UsageError, "m").with_item_bound(
            "label",
            256,
            heimdall_contract::envelope::BoundUnit::Bytes,
        );
        let v = serde_json::to_value(e.detail()).unwrap();
        assert_eq!(
            item_bound_line(&v).as_deref(),
            Some("too large: label may be at most 256 bytes")
        );
        let v = serde_json::to_value(heimdall_app::OpError::new(Code::UsageError, "m").detail())
            .unwrap();
        assert_eq!(item_bound_line(&v), None);
    }

    #[test]
    fn sanitizer_drops_escapes() {
        assert_eq!(sanitize_for_terminal("ok\u{1b}[31mred\u{7}"), "okred");
    }

    /// ⟨M05⟩ Review M05-W3-R03: a data field is one quoted token on one line: line breaks
    /// and controls are escapes, quotes and backslashes are escaped, every bidirectional and
    /// invisible formatting character is removed (and a note says so), and what is left is
    /// unchanged by the terminal sanitizer. Plain text is just quoted, as JSON quotes it.
    #[test]
    fn human_json_is_inert_and_denotes_the_same_value() {
        // ⟨M05⟩ Review M05-W3-RC01.
        let plain = serde_json::json!({"cwd": "/w/r", "label": "naïve ☃ 日本", "n": 1});
        assert_eq!(
            human_json(&plain),
            serde_json::to_string_pretty(&plain).unwrap(),
            "plain text is byte-identical to the pretty form"
        );
        let hostile = serde_json::json!({
            "cwd": "/w/r\nX\u{202e}cba\u{2066}",
            "tag": "a\u{e0041}b\u{200d}c",
        });
        let text = human_json(&hostile);
        assert!(!text.chars().any(is_invisible_format), "{text}");
        assert!(
            text.contains("\\u202e") && text.contains("\\u2066"),
            "{text}"
        );
        assert!(
            text.contains("\\udb40\\udc41"),
            "a tag character as its surrogate pair: {text}"
        );
        assert_eq!(
            text.lines().count(),
            4,
            "a line break in a string stays escaped: {text}"
        );
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back, hostile, "the printed JSON denotes the same value");
        assert_eq!(
            sanitize_for_terminal(&text),
            text,
            "nothing left for the sanitizer"
        );
    }

    #[test]
    fn a_data_field_is_one_inert_quoted_token() {
        let hostile = "/w/r\nOWNER-LINE\u{202e}cba\r\t\u{2028}\u{2029}\u{1b}[31m\u{85}\"\\\u{200b}\u{2066}x\u{2069}\u{e0041}\u{ad}";
        let shown = quoted_field(hostile);
        assert_eq!(
            shown,
            r#""/w/r\nOWNER-LINEcba\r\t\u2028\u2029\u001b[31m\u0085\"\\x" (invisible formatting characters removed)"#
        );
        assert_eq!(
            sanitize_for_terminal(&shown),
            shown,
            "nothing left to strip"
        );
        assert!(!shown.contains('\n') && !shown.chars().any(is_invisible_format));
        for plain in ["/home/me/project", "x\n$(touch y)", "naïve ☃ 日本"] {
            assert_eq!(
                quoted_field(plain),
                serde_json::Value::String(plain.to_owned()).to_string(),
                "{plain:?}"
            );
        }
        for c in [
            '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{feff}', '\u{061c}',
        ] {
            assert!(is_invisible_format(c), "{:04x}", u32::from(c));
        }
        for c in ['a', ' ', 'é', '\u{05d0}', '\u{0627}', '\u{2603}'] {
            assert!(!is_invisible_format(c), "{:04x}", u32::from(c));
        }
    }

    // ---- ⟨M03⟩ wave 5 (U12): the access renderings ---------------------------------------

    use heimdall_contract::managed::{
        ConnectionKind, ConnectionPolicyReport, ExistingConnectionsMode, MultiplexingMode,
        OwnedConnectionReport, OwnedConnectionReportState, RevokeNote,
    };
    use heimdall_contract::provider::IdentitySelection;
    use heimdall_contract::request::RevokeData;

    fn conn(
        id: &str,
        kind: ConnectionKind,
        state: OwnedConnectionReportState,
    ) -> OwnedConnectionReport {
        OwnedConnectionReport {
            id: heimdall_contract::ids::ConnectionId::parse(id).unwrap(),
            kind,
            state,
        }
    }

    /// `access ensure --strict`: the policy the runtime reports is shown with the D8
    /// strict wording **as the runtime wrote it** (the `localenv` constants, never
    /// retyped here), for each selection form; a graceful result shows the graceful
    /// wording, never the strict one.
    #[test]
    fn access_ensure_strict_reports_strict_disconnect() {
        use heimdall_localenv::projection::plan::{
            DEADLINE_STRICT_EXCLUSIVE, DEADLINE_STRICT_NOT_EXCLUSIVE, deadline_wording,
        };
        for (selection, constant) in [
            (IdentitySelection::Exclusive, DEADLINE_STRICT_EXCLUSIVE),
            (
                IdentitySelection::NotExclusive,
                DEADLINE_STRICT_NOT_EXCLUSIVE,
            ),
            (
                IdentitySelection::Undetermined,
                DEADLINE_STRICT_NOT_EXCLUSIVE,
            ),
        ] {
            let wording = deadline_wording(selection, ExistingConnectionsMode::Strict);
            assert_eq!(wording, constant, "{selection:?}");
            let report = ConnectionPolicyReport {
                existing: ExistingConnectionsMode::Strict,
                multiplexing: MultiplexingMode::Disabled,
                wording: wording.to_owned(),
            };
            let data = serde_json::json!({ "connection_policy": report });
            let lines = m03_lines(&data);
            assert_eq!(
                lines,
                vec![
                    "Connection policy: existing strict, multiplexing disabled.".to_owned(),
                    constant.to_owned()
                ],
                "{selection:?}"
            );
        }
        let graceful = ConnectionPolicyReport {
            existing: ExistingConnectionsMode::Graceful,
            multiplexing: MultiplexingMode::OwnedMasters,
            wording: deadline_wording(
                IdentitySelection::Exclusive,
                ExistingConnectionsMode::Graceful,
            )
            .to_owned(),
        };
        let lines = m03_lines(&serde_json::json!({ "connection_policy": graceful }));
        assert!(lines[0].contains("existing graceful"), "{lines:?}");
        assert!(!lines.join("\n").contains(DEADLINE_STRICT_EXCLUSIVE));
        // A result without the field (M01/M02, or a runtime that does not report it)
        // says nothing about connections: never a claim.
        assert!(m03_lines(&serde_json::json!({ "binding_id": "bind_x" })).is_empty());
        assert!(m03_lines(&serde_json::json!({ "connection_policy": null })).is_empty());
    }

    /// F15: a revoke result lists each owned connection with its state, how many are
    /// closed and how many remain, and always carries the ordinary-`ssh` note; an
    /// unverified connection is said to be unsignalled.
    #[test]
    fn revoke_output_lists_owned_connections_and_ordinary_note() {
        use OwnedConnectionReportState as S;
        let revoke = RevokeData {
            local_applied: true,
            remote_pending: Vec::new(),
            latest_possible_credential_expiry: None,
            remote_effects: Vec::new(),
            owned_connections: vec![
                conn(
                    "conn_00000000000000000000000000000001",
                    ConnectionKind::Dedicated,
                    S::Closed,
                ),
                conn(
                    "conn_00000000000000000000000000000002",
                    ConnectionKind::Master,
                    S::Closing,
                ),
                conn(
                    "conn_00000000000000000000000000000003",
                    ConnectionKind::Dedicated,
                    S::Unverified,
                ),
            ],
            notes: vec![RevokeNote::OrdinaryConnectionsNotClosed],
            requested_at: None,
            committed_at: None,
        };
        let data = serde_json::to_value(&revoke).unwrap();
        let lines = m03_lines(&data);
        assert_eq!(lines[0], "Owned connections: 1 closed, 2 remaining.");
        assert!(lines[1].contains("conn_00000000000000000000000000000001 (dedicated): closed"));
        assert!(lines[2].contains("conn_00000000000000000000000000000002 (master): closing"));
        assert!(
            lines[3].contains("(dedicated): unverified") && lines[3].contains("not signalled"),
            "{}",
            lines[3]
        );
        assert_eq!(
            lines.last().unwrap(),
            &format!("Note: {ORDINARY_CONNECTIONS_NOTE}")
        );
        assert!(ORDINARY_CONNECTIONS_NOTE.contains("ordinary ssh"));
        // The note code the text is keyed by is the contract's (never a typo).
        assert_eq!(
            serde_json::to_value(RevokeNote::OrdinaryConnectionsNotClosed).unwrap(),
            serde_json::json!(ORDINARY_CONNECTIONS_NOT_CLOSED)
        );
        // No owned connection (a managed revoke before any connect) still carries the
        // note; an existing-access revoke (no M03 keys) prints nothing extra.
        let none = RevokeData {
            owned_connections: Vec::new(),
            ..revoke
        };
        let lines = m03_lines(&serde_json::to_value(&none).unwrap());
        assert_eq!(lines[0], "Owned connections: 0 closed, 0 remaining.");
        assert!(lines.iter().any(|l| l.starts_with("Note: ")));
        let m02 = RevokeData {
            notes: Vec::new(),
            ..none
        };
        assert!(m03_lines(&serde_json::to_value(&m02).unwrap()).is_empty());
        // An unknown future note is shown by its code, not dropped.
        assert_eq!(revoke_note_text("future_note"), "future_note");
    }

    /// ⟨§17.25 item 22⟩ The `access lock-behavior` and `connection-policy` results carry
    /// this policy's `lock_behavior` and `connection {existing, multiplexing}` (the keys
    /// R2's `policy_view` emits); both are shown, from the contract's own serde forms. An
    /// M01 policy result (the five keys) shows nothing extra.
    #[test]
    fn a_policy_result_shows_the_lock_behaviour_when_it_carries_one() {
        use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
        let data = serde_json::json!({
            "policy_id": "pol",
            "revision": 3,
            "paused": false,
            "cutoff_at": null,
            "changed": true,
            "lock_behavior": LockBehavior::RevokeOnLock,
            "connection": ConnectionPolicy {
                existing: ExistingConnectionsMode::Strict,
                multiplexing: MultiplexingMode::OwnedMasters,
            },
        });
        assert_eq!(
            m03_lines(&data),
            vec![
                "Lock behaviour: revoke_on_lock.".to_owned(),
                "Connections: existing strict, multiplexing owned_masters.".to_owned(),
            ]
        );
        let m01 = serde_json::json!({
            "policy_id": "pol", "revision": 3, "paused": true, "cutoff_at": null, "changed": true,
        });
        assert!(m03_lines(&m01).is_empty());
    }

    /// ⟨§17.25 items 18 and 19⟩ `destination show|list` shows a managed pair's
    /// `preference.connection_policy` wording verbatim, and "unknown" for a managed
    /// preference the runtime reports no policy for; an existing-access preference and
    /// an M02 destination show nothing. A managed `ensure` result without
    /// `connection_policy` (after a restart) says it is unknown, never a claim.
    #[test]
    fn destination_listing_shows_the_runtimes_connection_policy_wording() {
        use heimdall_localenv::projection::plan::DEADLINE_STRICT_NOT_EXCLUSIVE;
        let report = ConnectionPolicyReport {
            existing: ExistingConnectionsMode::Strict,
            multiplexing: MultiplexingMode::Disabled,
            wording: DEADLINE_STRICT_NOT_EXCLUSIVE.to_owned(),
        };
        let managed = serde_json::json!({
            "destination_id": "h2", "alias": "lab2",
            "preference": {"mechanism": "managed_certificate", "projection": "pending",
                           "connection_policy": report},
        });
        let unknown = serde_json::json!({
            "destination_id": "h3", "alias": "lab3",
            "preference": {"mechanism": "managed_certificate", "projection": "pending"},
        });
        let existing = serde_json::json!({
            "destination_id": "h4", "alias": "lab4",
            "preference": {"mechanism": "existing", "projection": "current"},
        });
        let m02 = serde_json::json!({"destination_id": "h5", "alias": "lab5"});
        let shown = vec![
            "lab2: connection policy: existing strict, multiplexing disabled.".to_owned(),
            DEADLINE_STRICT_NOT_EXCLUSIVE.to_owned(),
        ];
        assert_eq!(destination_lines(&managed), shown);
        let list = serde_json::json!({"destinations": [managed, unknown, existing, m02.clone()]});
        let lines = destination_lines(&list);
        assert_eq!(lines[..2], shown[..]);
        assert_eq!(
            lines[2],
            "lab3: connection policy unknown (the runtime reports none for this pair)."
        );
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(destination_lines(&m02).is_empty());
        assert!(destination_lines(&serde_json::json!({"destinations": []})).is_empty());
        // `inspect destinations` (through `emit`) shows the same lines.
        assert_eq!(m03_lines(&list), lines);
        // A managed ensure result without the field.
        let restarted = serde_json::json!({
            "binding_id": "bind_x", "credential_mechanism": "managed_certificate",
        });
        assert_eq!(
            m03_lines(&restarted),
            vec![CONNECTION_POLICY_UNKNOWN.to_owned()]
        );
    }

    /// ⟨ADR-0008 §17.27 item 9; W5-R06⟩ `destination list` and `inspect destinations`
    /// render the runtime's real list shape, `{"items": [...]}`
    /// (`Operations::destinations_view`). The items below are a real `inspect
    /// destinations` answer, captured from the CLI-started runtime of
    /// `e2e_cli_m03 access::access_ensure_strict_reports_strict_disconnect` (lab2: a
    /// managed pair in a saved policy, its policy computed) and of `access::
    /// destination_prefer_resolves_alias_and_journals_the_preference` (lab1: a managed
    /// preference in no saved policy, whose policy cannot be computed, so "unknown";
    /// seen: observed); those tests assert the same lines from the live answer.
    #[test]
    fn destination_list_renders_the_runtimes_items_shape() {
        let data: serde_json::Value = serde_json::from_str(
            r#"{"items": [
            {"account":"deploy","alias":"lab2","definition":"managed","destination_id":"h2",
             "hostname":"127.0.0.1","identity_id":"idn_99524804984d960a168fe75318215824",
             "label":null,"port":null,
             "preference":{"connection_policy":{"existing":"graceful","multiplexing":"disabled",
                 "wording":"New connections stop at the deadline; existing sessions may stay connected."},
                 "mechanism":"managed_certificate","projection":{"generation":1,"state":"applied"}},
             "revision":1,"updated_at":"2026-11-13T09:26:30.495429Z"},
            {"account":"deploy","alias":"lab1","definition":"managed","destination_id":"dst-lab1",
             "hostname":"lab1.example.invalid","identity_id":"idn_81549ea3ed849236f3ca5f6b607d3572",
             "label":null,"port":null,
             "preference":{"mechanism":"managed_certificate","projection":{"state":"pending"}},
             "revision":1,"updated_at":"2026-11-13T09:26:30.495416Z"},
            {"alias":"seen","definition":"observed","destination_id":"seen","label":null,
             "revision":1,"updated_at":"2026-11-13T09:26:30.503668Z"}
            ]}"#,
        )
        .unwrap();
        let expected = vec![
            "lab2: connection policy: existing graceful, multiplexing disabled.".to_owned(),
            "New connections stop at the deadline; existing sessions may stay connected."
                .to_owned(),
            "lab1: connection policy unknown (the runtime reports none for this pair).".to_owned(),
        ];
        assert_eq!(destination_lines(&data), expected);
        // `inspect destinations` (through `emit`) shows the same lines.
        assert_eq!(m03_lines(&data), expected);
        // The older `destinations` spelling still reads.
        let older = serde_json::json!({ "destinations": data["items"].clone() });
        assert_eq!(destination_lines(&older), expected);
        assert!(destination_lines(&serde_json::json!({"items": []})).is_empty());
    }
}
