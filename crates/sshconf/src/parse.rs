//! The configuration file AST (m02-plan U1). Fixed by U0: U2 builds on these types.

use crate::directive::Keyword;
use crate::lex::Split;
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
    /// For `ProxyCommand`, `LocalCommand`, `RemoteCommand` and `KnownHostsCommand`
    /// ([`crate::directive::keeps_raw`]): the rest of the line after the keyword and
    /// its separator, as OpenSSH's `readconf` keeps it and hands it to a shell, with
    /// quotes, escapes and a trailing comment included. `None` for every other
    /// keyword (ADR-0007 §12.15 item 2).
    pub raw: Option<String>,
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

/// The UTF-8 byte-order mark.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Parse one file's bytes. Never panics on arbitrary input (U1's proptest). A line
/// that is not UTF-8 becomes a directive with [`Keyword::Unreadable`].
///
/// The model (m02-plan U1):
///
/// * the whole file is refused ([`ParseError`]) when it is larger than
///   `Limits::file_bytes`, when a line is longer than `Limits::line_bytes` (counted
///   without its `\n` or `\r\n`), or when it holds a NUL byte (C string handling in
///   OpenSSH would silently drop the rest of that line). The first offending line is
///   reported; nothing is truncated;
/// * lines end at `\n`, as with OpenSSH's `getline`; a last line without `\n` is still
///   a line, and line numbers are 1-based;
/// * a leading UTF-8 BOM is removed before line 1 is split and recorded in
///   [`ConfigFile::had_bom`]. Upstream OpenSSH does not skip a BOM (its first keyword
///   would be unknown), so whether a client accepts such a file is the client's
///   observed behaviour (ADR-0007 §4, `bom_and_crlf_acceptance`): an evaluator must
///   consult `had_bom`;
/// * a `\r` before `\n` is trailing whitespace to OpenSSH, so it is dropped and
///   recorded in [`ConfigFile::crlf`];
/// * each line is split by the [`crate::lex`] rules over its bytes. The keyword and
///   every argument must be UTF-8, or the directive is [`Keyword::Unreadable`] with no
///   arguments (never a guess). Bytes after a comment start never matter, so a
///   comment, including a trailing one, may hold any bytes, except on the four command
///   keywords ([`crate::directive::keeps_raw`]): their raw text includes a trailing
///   comment and is the command ssh hands to a shell, so a line whose raw text is not
///   UTF-8 is unreadable too;
/// * a line the lexer refuses is [`Line::Invalid`].
///
/// # Errors
/// [`ParseError`] when a bound is exceeded or a NUL byte is present.
pub fn parse_file(
    source: SourceId,
    bytes: &[u8],
    limits: &Limits,
) -> Result<ConfigFile, ParseError> {
    if bytes.len() > limits.file_bytes {
        return Err(ParseError::FileTooLarge);
    }
    let (had_bom, body) = match bytes.strip_prefix(BOM) {
        Some(rest) => (true, rest),
        None => (false, bytes),
    };

    let mut lines = Vec::new();
    let mut crlf = false;
    let mut count: usize = 0;
    let mut rest = body;
    while !rest.is_empty() {
        let (raw, terminated) = match rest.iter().position(|&b| b == b'\n') {
            Some(at) => {
                let (line, tail) = rest.split_at(at);
                rest = tail.get(1..).unwrap_or_default();
                (line, true)
            }
            None => {
                let line = rest;
                rest = &[];
                (line, false)
            }
        };
        count += 1;
        let line = u32::try_from(count).unwrap_or(u32::MAX);
        let content = match raw.strip_suffix(b"\r") {
            Some(content) if terminated => {
                crlf = true;
                content
            }
            _ => raw,
        };
        if content.len() > limits.line_bytes {
            return Err(ParseError::LineTooLong { line });
        }
        if content.contains(&0) {
            return Err(ParseError::NulByte { line });
        }
        lines.push(classify(Span { source, line }, content));
    }

    Ok(ConfigFile {
        source,
        lines,
        had_bom,
        crlf,
    })
}

/// A directive that is not UTF-8: nothing is guessed about it.
fn unreadable(span: Span) -> Directive {
    Directive {
        keyword: Keyword::Unreadable,
        args: Vec::new(),
        raw: None,
        span,
    }
}

fn classify(span: Span, content: &[u8]) -> Line {
    match crate::lex::split_line(content) {
        Err(error) => Line::Invalid { span, error },
        Ok(Split::Blank) => Line::Blank(span),
        Ok(Split::Comment) => Line::Comment(span),
        Ok(Split::Directive { keyword, args, raw }) => {
            let keyword = String::from_utf8(keyword);
            let args: Result<Vec<String>, _> = args.into_iter().map(String::from_utf8).collect();
            let directive = match (keyword, args) {
                (Ok(keyword), Ok(args)) => {
                    let keyword = crate::directive::keyword(&keyword);
                    let keeps_raw =
                        matches!(&keyword, Keyword::Known(k) if crate::directive::keeps_raw(*k));
                    if keeps_raw {
                        match String::from_utf8(raw) {
                            Ok(raw) => Directive {
                                keyword,
                                args,
                                raw: Some(raw),
                                span,
                            },
                            Err(_) => unreadable(span),
                        }
                    } else {
                        Directive {
                            keyword,
                            args,
                            raw: None,
                            span,
                        }
                    }
                }
                _ => unreadable(span),
            };
            Line::Directive(directive)
        }
    }
}
