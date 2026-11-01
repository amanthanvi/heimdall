//! The configuration file AST (m02-plan U1). Fixed by U0: U2 builds on these types.

use crate::directive::Keyword;
use crate::limits::Limits;

/// Identifies one loaded file inside a [`crate::include::ConfigSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub u32);

/// Where a directive was read: file and 1-based line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    /// The file.
    pub source: SourceId,
    /// 1-based line number.
    pub line: u32,
}

/// One directive line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    /// The keyword; [`Keyword::Unreadable`] for a line that is not UTF-8.
    pub keyword: Keyword,
    /// The arguments after the keyword, split by [`crate::lex::split_args`].
    pub args: Vec<String>,
    /// Where it was read.
    pub span: Span,
}

/// One physical line of a configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Empty or whitespace only.
    Blank(Span),
    /// A `#` comment.
    Comment(Span),
    /// A directive.
    Directive(Directive),
    /// A line [`crate::lex::split_args`] refused; recorded, never guessed.
    Invalid {
        /// Where.
        span: Span,
        /// Why.
        error: crate::lex::LexError,
    },
}

/// A parsed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    /// Its identity in the set.
    pub source: SourceId,
    /// Every line, in order.
    pub lines: Vec<Line>,
    /// Whether the bytes began with a UTF-8 byte-order mark.
    pub had_bom: bool,
    /// Whether any line ended with CRLF.
    pub crlf: bool,
}

/// A file the parser refuses as a whole.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Larger than `Limits::file_bytes`.
    #[error("configuration file exceeds the size bound")]
    FileTooLarge,
    /// A line longer than `Limits::line_bytes`.
    #[error("line {line} exceeds the line bound")]
    LineTooLong {
        /// 1-based line number.
        line: u32,
    },
    /// A NUL byte.
    #[error("line {line} contains a NUL byte")]
    NulByte {
        /// 1-based line number.
        line: u32,
    },
}

/// Parse one file's bytes. Never panics on arbitrary input (U1's proptest). A line
/// that is not UTF-8 becomes a directive with [`Keyword::Unreadable`].
///
/// # Errors
/// [`ParseError`] when a bound is exceeded or a NUL byte is present.
pub fn parse_file(
    source: SourceId,
    bytes: &[u8],
    limits: &Limits,
) -> Result<ConfigFile, ParseError> {
    let _ = (source, bytes, limits);
    todo!("M02-U1 parse::parse_file")
}
