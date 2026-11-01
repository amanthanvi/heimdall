//! The owner confirmation prompt (ADR-0006 §3.1 ⟨r2.1⟩ N04, binding on this CLI).
//!
//! Only `y` or `yes` (case-insensitive, surrounding whitespace ignored) confirms;
//! the default is **No**. End of input, Ctrl-C, the prompt timeout, a read error
//! or any other answer is a refusal, and the caller then sends nothing. The prompt
//! is written to stderr (stdout carries only the envelope); the answer is read
//! from stdin, which the caller has already checked is a terminal.
//!
//! Disclosure: the runtime cannot verify that a client prompted. A program
//! running as the same OS user can open an interactive session and send `Attend`
//! and `Decide` itself; this prompt is the owner workflow conforming clients
//! follow, not a server-enforced boundary.

use std::time::Duration;

/// How long the prompt waits for an answer before refusing.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// The outcome of one prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `y` / `yes`.
    Yes,
    /// Any other line (including an empty one: default No).
    No,
    /// End of input.
    Eof,
    /// Ctrl-C.
    Interrupted,
    /// No answer within [`PROMPT_TIMEOUT`].
    TimedOut,
    /// stdin could not be read.
    Unreadable,
}

impl Answer {
    /// Short reason for the "not confirmed" message.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Answer::Yes => "confirmed",
            Answer::No => "answered no",
            Answer::Eof => "end of input",
            Answer::Interrupted => "interrupted",
            Answer::TimedOut => "no answer in time",
            Answer::Unreadable => "input unreadable",
        }
    }
}

/// Classify one line read from the terminal (`None` = end of input).
#[must_use]
pub fn classify(line: Option<&str>) -> Answer {
    match line {
        None => Answer::Eof,
        Some(l) => {
            let t = l.trim().to_ascii_lowercase();
            if t == "y" || t == "yes" {
                Answer::Yes
            } else {
                Answer::No
            }
        }
    }
}

/// Show `text`, then ask for a typed `yes` (default No).
pub async fn ask(text: &str) -> Answer {
    crate::output::prompt(text);
    crate::output::prompt("Type 'yes' to confirm [y/N]: ");
    let (tx, rx) = tokio::sync::oneshot::channel();
    // A blocking read on its own thread; if the prompt ends another way the
    // thread is abandoned (the process exits soon after).
    let spawned = std::thread::Builder::new()
        .name("heimdall-prompt".into())
        .spawn(move || {
            let mut line = String::new();
            let r = std::io::stdin().read_line(&mut line).map(|n| (n, line));
            let _ = tx.send(r);
        });
    if spawned.is_err() {
        return Answer::Unreadable;
    }
    let answer = tokio::select! {
        r = rx => match r {
            Ok(Ok((0, _))) => Answer::Eof,
            Ok(Ok((_, line))) => classify(Some(&line)),
            _ => Answer::Unreadable,
        },
        _ = tokio::signal::ctrl_c() => Answer::Interrupted,
        () = tokio::time::sleep(PROMPT_TIMEOUT) => Answer::TimedOut,
    };
    if answer != Answer::Yes {
        crate::output::diagnostic("");
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_y_or_yes_confirms_and_the_default_is_no() {
        for yes in ["y", "Y", "yes", "YES", " Yes \n", "\tyEs\r\n"] {
            assert_eq!(classify(Some(yes)), Answer::Yes, "{yes:?}");
        }
        for no in [
            "", "\n", "n", "no", "yess", "ye", "y e s", "sure", "1", "true",
        ] {
            assert_eq!(classify(Some(no)), Answer::No, "{no:?}");
        }
        assert_eq!(classify(None), Answer::Eof);
    }
}
