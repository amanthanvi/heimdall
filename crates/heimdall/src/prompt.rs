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

/// Show `text`, then ask for a typed `yes` (default No), reading one line of stdin
/// within [`PROMPT_TIMEOUT`].
pub async fn ask(text: &str) -> Answer {
    ask_within(text, read_stdin_line, PROMPT_TIMEOUT).await
}

/// One line of stdin: `(bytes read, line)`; 0 bytes is end of input.
fn read_stdin_line() -> std::io::Result<(usize, String)> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map(|n| (n, line))
}

/// [`ask`] with its line reader and its bound: `read` runs on its own thread and
/// answers `(bytes read, line)`; no answer within `timeout` is [`Answer::TimedOut`]
/// (the caller then sends nothing). The unit tests give a reader that never answers
/// and a short bound, so the timeout case needs no 120 s wait and no variable.
pub(crate) async fn ask_within<R>(text: &str, read: R, timeout: Duration) -> Answer
where
    R: FnOnce() -> std::io::Result<(usize, String)> + Send + 'static,
{
    crate::output::prompt(text);
    crate::output::prompt("Type 'yes' to confirm [y/N]: ");
    let (tx, rx) = tokio::sync::oneshot::channel();
    // A blocking read on its own thread; if the prompt ends another way the
    // thread is abandoned (the process exits soon after).
    let spawned = std::thread::Builder::new()
        .name("heimdall-prompt".into())
        .spawn(move || {
            let _ = tx.send(read());
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
        () = tokio::time::sleep(timeout) => Answer::TimedOut,
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

    /// A reader that never answers: blocked until the test drops its sender.
    fn never_answers() -> (
        std::sync::mpsc::Sender<()>,
        impl FnOnce() -> std::io::Result<(usize, String)> + Send + 'static,
    ) {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        (tx, move || {
            let _ = rx.recv();
            Err(std::io::Error::other("released"))
        })
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    /// No answer within the bound is `TimedOut` (the 120 s bound, shortened), never a
    /// confirmation; an answer within it is classified as usual.
    #[test]
    fn no_answer_in_time_is_timed_out() {
        let (release, read) = never_answers();
        let started = std::time::Instant::now();
        let a = block_on(ask_within("t", read, Duration::from_millis(50)));
        assert_eq!(a, Answer::TimedOut);
        assert_eq!(a.reason(), "no answer in time");
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(release);
        let yes = || Ok((4, "yes\n".to_owned()));
        assert_eq!(
            block_on(ask_within("t", yes, Duration::from_secs(30))),
            Answer::Yes
        );
        assert_eq!(PROMPT_TIMEOUT, Duration::from_secs(120));
    }
}
