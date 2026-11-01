//! Argument splitting (m02-plan U1; OpenSSH ≥ 8.7 `argv_split` rules [G03-S04]).
//!
//! One line is split the way OpenSSH's `process_config_line` does it:
//!
//! 1. Trailing whitespace and form feeds (`" \t\r\n\f"`) are stripped, never the
//!    line's first byte (OpenSSH's loop stops at index 1).
//! 2. The keyword is the first run of bytes that are not `" \t\r\n"`, `"` or `=`
//!    (OpenSSH's `strdelim`). A line that is empty or whitespace only is blank; a
//!    keyword starting with `#` makes the line a comment.
//! 3. The keyword is separated from its arguments by whitespace, by exactly one `=`,
//!    or by one `=` surrounded by whitespace. A second `=` is kept as argument text
//!    (OpenSSH skips one `=` only).
//! 4. Nothing after the keyword (`Host`, `Host =`) is refused: OpenSSH reports "no
//!    argument after keyword" before it even looks the keyword up, so `IgnoreUnknown`
//!    cannot cover it ([`LexError::MalformedKeyword`]).
//! 5. The rest is split by `argv_split` with comments on [G03-S02 misc.c]: tokens are
//!    separated by spaces and tabs only; a `#` at the **start** of a token ends the
//!    line (`a#b` is one argument, `a #b` is `a`); `"` and `'` quote (each closes
//!    only itself); `\` followed by `'`, `"`, `\`, or (outside quotes) a space yields
//!    that character, and any other `\` is kept as is; an unterminated quote is
//!    refused ([`LexError::UnterminatedQuote`]).
//!
//! **Deliberate fail-closed differences.** OpenSSH's `strdelim` also accepts a quoted
//! keyword (`"Host" a`), a quote inside or right after the keyword, and an `=` before
//! the keyword (`=Host a`), and it silently skips a line whose keyword quote is not
//! closed. No configuration needs those forms; this lexer refuses each with
//! [`LexError::MalformedKeyword`] instead of guessing what a given client does, so an
//! evaluator reports the line instead of trusting it.
//!
//! [`LexError::InvalidEscape`] is never produced: OpenSSH ≥ 8.7 keeps an unrecognised
//! escape rather than refusing it.

/// A line whose arguments cannot be split. The line's directive is then invalid; the
/// error never echoes the line's text (it may carry a secret pasted by mistake).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LexError {
    /// A single or double quote is not closed on the line.
    #[error("unterminated quote")]
    UnterminatedQuote,
    /// A backslash escape OpenSSH refuses.
    #[error("invalid escape")]
    InvalidEscape,
    /// The keyword is missing or is not followed by whitespace or `=`.
    #[error("malformed keyword")]
    MalformedKeyword,
}

/// Whitespace for the keyword (`strdelim`'s `WHITESPACE`).
const KEYWORD_SPACE: &[u8] = b" \t\r\n";
/// Trailing bytes OpenSSH strips (`WHITESPACE "\f"`).
const TRAILING_SPACE: &[u8] = b" \t\r\n\x0c";

/// One line, split into bytes (the parser converts and checks UTF-8 afterwards).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Split {
    /// Empty or whitespace only.
    Blank,
    /// The keyword starts with `#`.
    Comment,
    /// A keyword and its arguments, quotes and escapes removed.
    Directive {
        /// The keyword as written.
        keyword: Vec<u8>,
        /// The arguments, in order.
        args: Vec<Vec<u8>>,
    },
}

/// Split one physical line (without its `\n`) into bytes. Total: never panics.
pub(crate) fn split_line(line: &[u8]) -> Result<Split, LexError> {
    let mut end = line.len();
    while end > 1
        && line
            .get(end - 1)
            .is_some_and(|b| TRAILING_SPACE.contains(b))
    {
        end -= 1;
    }
    let line = line.get(..end).unwrap_or_default();

    let mut i = skip(line, 0, KEYWORD_SPACE);
    let Some(&first) = line.get(i) else {
        return Ok(Split::Blank);
    };
    match first {
        b'#' => return Ok(Split::Comment),
        b'=' | b'"' => return Err(LexError::MalformedKeyword),
        _ => {}
    }
    let start = i;
    while line
        .get(i)
        .is_some_and(|b| !KEYWORD_SPACE.contains(b) && *b != b'"' && *b != b'=')
    {
        i += 1;
    }
    let keyword = line.get(start..i).unwrap_or_default().to_vec();

    match line.get(i) {
        Some(b'"') => return Err(LexError::MalformedKeyword),
        Some(b'=') => i = skip(line, i + 1, KEYWORD_SPACE),
        _ => {
            i = skip(line, i, KEYWORD_SPACE);
            if line.get(i) == Some(&b'=') {
                i = skip(line, i + 1, KEYWORD_SPACE);
            }
        }
    }
    let rest = line.get(i..).unwrap_or_default();
    if rest.is_empty() {
        return Err(LexError::MalformedKeyword);
    }
    let args = argv_split(rest)?;
    Ok(Split::Directive { keyword, args })
}

fn skip(line: &[u8], mut i: usize, set: &[u8]) -> usize {
    while line.get(i).is_some_and(|b| set.contains(b)) {
        i += 1;
    }
    i
}

/// OpenSSH's `argv_split(s, …, terminate_on_comment = 1)`, over bytes.
fn argv_split(s: &[u8]) -> Result<Vec<Vec<u8>>, LexError> {
    let mut args = Vec::new();
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if c == b' ' || c == b'\t' {
            i += 1;
            continue;
        }
        if c == b'#' {
            break;
        }
        let mut quote = 0u8;
        let mut arg = Vec::new();
        while let Some(&c) = s.get(i) {
            if c == b'\\' {
                match s.get(i + 1) {
                    Some(&n)
                        if n == b'\'' || n == b'"' || n == b'\\' || (quote == 0 && n == b' ') =>
                    {
                        arg.push(n);
                        i += 2;
                    }
                    _ => {
                        arg.push(b'\\');
                        i += 1;
                    }
                }
                continue;
            }
            if quote == 0 && (c == b' ' || c == b'\t') {
                break;
            }
            if quote == 0 && (c == b'"' || c == b'\'') {
                quote = c;
            } else if quote != 0 && c == quote {
                quote = 0;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        if quote != 0 {
            return Err(LexError::UnterminatedQuote);
        }
        args.push(arg);
    }
    Ok(args)
}

/// Split one logical line into its keyword and arguments, following OpenSSH ≥ 8.7:
/// quotes, backslashes, an optional `=` after the keyword, and `#` outside quotes
/// starting a comment. The first element is the keyword as written.
///
/// A blank or comment line gives an empty vector. The rules, and the forms refused
/// on purpose, are in the module documentation.
///
/// # Errors
/// [`LexError`] for a line OpenSSH would refuse.
pub fn split_args(line: &str) -> Result<Vec<String>, LexError> {
    match split_line(line.as_bytes())? {
        Split::Blank | Split::Comment => Ok(Vec::new()),
        Split::Directive { keyword, args } => Ok(std::iter::once(keyword)
            .chain(args)
            // Valid UTF-8 split only at ASCII bytes, with only ASCII bytes removed, is
            // valid UTF-8: the lossy conversion never replaces anything here.
            .map(|piece| String::from_utf8_lossy(&piece).into_owned())
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(line: &str) -> Vec<String> {
        split_args(line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
    }

    #[test]
    fn keyword_and_simple_arguments() {
        assert_eq!(ok("Host a b"), ["Host", "a", "b"]);
        assert_eq!(
            ok("  \tHostName   example.test  "),
            ["HostName", "example.test"]
        );
    }

    #[test]
    fn single_equals_after_the_keyword() {
        assert_eq!(ok("Port=22"), ["Port", "22"]);
        assert_eq!(ok("Port = 22"), ["Port", "22"]);
        assert_eq!(ok("Port =22"), ["Port", "22"]);
        assert_eq!(ok("Port= 22"), ["Port", "22"]);
        // Only one `=` is skipped; a second one is argument text.
        assert_eq!(ok("Port==22"), ["Port", "=22"]);
        assert_eq!(ok("Port = = 22"), ["Port", "=", "22"]);
        // `=` inside an argument is data.
        assert_eq!(ok("SetEnv A=B"), ["SetEnv", "A=B"]);
    }

    #[test]
    fn hash_starts_a_comment_only_at_a_token_start() {
        assert_eq!(ok("HostName a#b"), ["HostName", "a#b"]);
        assert_eq!(ok("HostName a #b c"), ["HostName", "a"]);
        assert_eq!(ok("HostName \"a #b\" c"), ["HostName", "a #b", "c"]);
        assert_eq!(ok("Host #only a comment"), ["Host"]);
        assert!(ok("# Host a").is_empty());
        assert!(ok("   #Host a").is_empty());
    }

    #[test]
    fn missing_argument_is_refused() {
        assert_eq!(split_args("Host"), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("Host   "), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("Host ="), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("Host#x"), Err(LexError::MalformedKeyword));
    }

    #[test]
    fn quoted_or_equals_first_keyword_is_refused() {
        assert_eq!(split_args("\"Host\" a"), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("Ho\"st\" a"), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("=Host a"), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("  = Host a"), Err(LexError::MalformedKeyword));
        assert_eq!(split_args("Host\"a\""), Err(LexError::MalformedKeyword));
    }

    #[test]
    fn blank_lines() {
        assert!(ok("").is_empty());
        assert!(ok(" \t ").is_empty());
        assert!(ok("\r").is_empty());
        // A lone form feed is not whitespace for the keyword, and the first byte is
        // never stripped, so OpenSSH sees a keyword without arguments.
        assert_eq!(split_args("\u{c}"), Err(LexError::MalformedKeyword));
        assert_eq!(ok("Host a\u{c}"), ["Host", "a"]);
    }
}
