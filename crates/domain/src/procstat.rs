//! ⟨M03⟩ The shared `/proc/<pid>/stat` parser (ADR-0008 D5 §6.3; §17.13 item 2;
//! U0b row 28; frozen in wave 0).
//!
//! `comm` (field 2) is the executable name in parentheses and may contain spaces,
//! `(`, `)` and newlines, so a whitespace field count over the whole line is wrong.
//! The rule, shared with the enrollment scripts' `awk` text: take the whole text,
//! find the **last** `)`, split the suffix after it on ASCII whitespace, and read
//! token 1 (the state, field 3), token 3 (the process group, field 5) and token 20
//! (the start time in clock ticks, field 22). At least 20 tokens are required, and
//! each value is validated.

/// The fields of `/proc/<pid>/stat` the runtime uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcStat {
    /// The state letter (field 3). Kept so the runtime can apply its own rule
    /// (`process_start_time` rejects `Z` and `X`).
    pub state: char,
    /// The process group (field 5), ≥ 1.
    pub process_group: u32,
    /// The start time after boot, in clock ticks (field 22).
    pub start_time: u64,
}

/// Why a `/proc/<pid>/stat` text is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProcStatError {
    /// No `)` in the text.
    #[error("no closing parenthesis")]
    NoCloseParen,
    /// Fewer than 20 tokens after the last `)`.
    #[error("{found} fields after the command name, 20 needed")]
    TooFewFields {
        /// Tokens found.
        found: usize,
    },
    /// Token 1 is not a single ASCII letter.
    #[error("the state is not a single letter")]
    BadState,
    /// Token 3 is not a decimal number ≥ 1 that fits a PID.
    #[error("the process group is not a positive decimal")]
    BadProcessGroup,
    /// Token 20 is not a decimal number.
    #[error("the start time is not a decimal")]
    BadStartTime,
}

fn decimal(token: &[u8]) -> Option<u64> {
    if token.is_empty() || !token.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(token).ok()?.parse().ok()
}

/// The validated state letter and the suffix tokens after the **last** `)`.
fn suffix_tokens(text: &[u8]) -> Result<(char, Vec<&[u8]>), ProcStatError> {
    let close = text
        .iter()
        .rposition(|&b| b == b')')
        .ok_or(ProcStatError::NoCloseParen)?;
    let suffix = text.get(close + 1..).unwrap_or_default();
    let tokens: Vec<&[u8]> = suffix
        .split(u8::is_ascii_whitespace)
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 20 {
        return Err(ProcStatError::TooFewFields {
            found: tokens.len(),
        });
    }
    let state = match tokens[0] {
        [c] if c.is_ascii_alphabetic() => char::from(*c),
        _ => return Err(ProcStatError::BadState),
    };
    Ok((state, tokens))
}

/// Parse a whole `/proc/<pid>/stat` text (`&str` or bytes; `comm` may be any
/// bytes). See the module documentation for the rule.
pub fn parse(text: impl AsRef<[u8]>) -> Result<ProcStat, ProcStatError> {
    let (state, tokens) = suffix_tokens(text.as_ref())?;
    let process_group = decimal(tokens[2])
        .and_then(|g| u32::try_from(g).ok())
        .filter(|&g| g >= 1)
        .ok_or(ProcStatError::BadProcessGroup)?;
    let start_time = decimal(tokens[19]).ok_or(ProcStatError::BadStartTime)?;
    Ok(ProcStat {
        state,
        process_group,
        start_time,
    })
}

/// The state letter and the start time (field 22) of a whole `/proc/<pid>/stat`
/// text, by the same rule as [`parse`] but **without** the process-group check
/// (U0b row 28; wave-0 verify E9, reading (a)). For `runtime::platform::
/// process_start_time`, whose semantics must not change: `/proc` shows group 0 for a
/// kernel thread, and such a process still has a start time. The enrollment
/// scripts and the owned-connection check, which need the group, use [`parse`].
pub fn parse_start_time(text: impl AsRef<[u8]>) -> Result<(char, u64), ProcStatError> {
    let (state, tokens) = suffix_tokens(text.as_ref())?;
    let start_time = decimal(tokens[19]).ok_or(ProcStatError::BadStartTime)?;
    Ok((state, start_time))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn line(comm: &str, state: &str, pgrp: &str, start: &str) -> String {
        // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt
        // cmajflt utime stime cutime cstime priority nice threads itrealvalue starttime …
        format!(
            "4242 ({comm}) {state} 1 {pgrp} 4242 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 200 18446744073709551615\n"
        )
    }

    #[test]
    fn comm_with_spaces_parentheses_and_newline() {
        for comm in ["sh", "a b", "x) (y", "evil) R 1 9 9", "new\nline", ")"] {
            let p = parse(line(comm, "S", "77", "123456")).unwrap();
            assert_eq!(
                p,
                ProcStat {
                    state: 'S',
                    process_group: 77,
                    start_time: 123456
                },
                "{comm:?}"
            );
        }
        assert_eq!(parse(line("z", "Z", "1", "0")).unwrap().state, 'Z');
    }

    #[test]
    fn start_time_entry_ignores_only_the_group() {
        let zero = line("a b", "S", "0", "77");
        assert_eq!(parse(&zero), Err(ProcStatError::BadProcessGroup));
        assert_eq!(parse_start_time(&zero), Ok(('S', 77)));
        let ok = line("x", "R", "5", "9");
        assert_eq!(parse_start_time(&ok), Ok(('R', 9)));
        assert_eq!(
            parse_start_time(line("x", "R", "5", "nine")),
            Err(ProcStatError::BadStartTime)
        );
        assert_eq!(
            parse_start_time("no paren"),
            Err(ProcStatError::NoCloseParen)
        );
    }

    #[test]
    fn malformed_is_rejected() {
        assert_eq!(parse("4242 sh S 1 2"), Err(ProcStatError::NoCloseParen));
        assert!(matches!(
            parse("4242 (sh) S 1 77 4242"),
            Err(ProcStatError::TooFewFields { found: 4 })
        ));
        assert_eq!(
            parse(line("sh", "SS", "77", "1")),
            Err(ProcStatError::BadState)
        );
        assert_eq!(
            parse(line("sh", "1", "77", "1")),
            Err(ProcStatError::BadState)
        );
        for bad in ["0", "-1", "+7", "x", "99999999999"] {
            assert_eq!(
                parse(line("sh", "S", bad, "1")),
                Err(ProcStatError::BadProcessGroup),
                "{bad}"
            );
        }
        for bad in ["-1", "1.5", "abc"] {
            assert_eq!(
                parse(line("sh", "S", "7", bad)),
                Err(ProcStatError::BadStartTime),
                "{bad}"
            );
        }
        let bytes = b"1 (\xff\xfe) S 1 9 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55 0";
        assert_eq!(parse(&bytes[..]).unwrap().start_time, 55);
    }
}
