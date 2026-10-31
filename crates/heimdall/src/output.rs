//! Envelope rendering and exit-code mapping (spec §11.2, §11.6; ADR-0006 §6).
//!
//! `--json`: exactly one envelope on stdout, newline-terminated, no ANSI. Human
//! mode: a short text summary on stdout, details on stderr. Machine strings never
//! carry terminal escape sequences (spec §11.2).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

/// Exit code for an envelope as a non-child command (ADR-0006 §6). `ACCEPTED`
/// exits 0 only when the caller selected asynchronous behaviour; otherwise a
/// pending result after a synchronous wait is reported as `Unavailable` (5) with
/// the operation to observe.
#[must_use]
pub fn exit_code_for(code: Code, caller_chose_async: bool) -> ExitCode {
    match code {
        Code::Accepted if !caller_chose_async => ExitCode::Unavailable,
        other => other.exit_code(),
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

/// Print an envelope in the selected mode.
pub fn emit<T: serde::Serialize>(envelope: &Envelope<T>, json: bool) {
    if json {
        match serde_json::to_string(envelope) {
            Ok(s) => println!("{s}"),
            Err(_) => eprintln!("internal: envelope serialization failed"),
        }
    } else {
        println!(
            "{} ({:?})",
            sanitize_for_terminal(envelope.code.as_str()),
            envelope.state
        );
    }
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
    fn sanitizer_drops_escapes() {
        assert_eq!(sanitize_for_terminal("ok\u{1b}[31mred\u{7}"), "okred");
    }
}
