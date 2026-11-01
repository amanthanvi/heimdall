//! Argument splitting (m02-plan U1; OpenSSH ≥ 8.7 `argv_split` rules [G03-S04]).

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

/// Split one logical line into its keyword and arguments, following OpenSSH ≥ 8.7:
/// quotes, backslashes, an optional `=` after the keyword, and `#` outside quotes
/// starting a comment. The first element is the keyword as written.
///
/// # Errors
/// [`LexError`] for a line OpenSSH would refuse.
pub fn split_args(line: &str) -> Result<Vec<String>, LexError> {
    let _ = line;
    todo!("M02-U1 lex::split_args")
}
