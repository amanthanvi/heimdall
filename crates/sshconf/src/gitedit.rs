//! The Git configuration text editor and scanner (m02-plan U2; ADR-0007 §5.6).
//!
//! The same block contract as [`crate::edit`], for Git configuration text: the block
//! goes before the first section header, after leading `#`/`;` comments, blank lines
//! and a BOM. [`scan`] reports includes and keys by span and **never returns a
//! configuration value** (M2-R08).
//!
//! The only text [`scan`] returns besides section and key names is an include's path,
//! which the caller needs to walk the include graph. Every other value, such as a
//! `core.sshCommand`, is parsed only to find where it ends (quotes, escapes, comments
//! and `\` line continuations) and is then dropped.

use std::ops::Range;

use crate::edit::{
    EditRefusal, Flavor, FoundBlock, IncludeBlock, InsertPlan, find_blocks_in, plan_insert_in,
    plan_remove_in,
};
use crate::render::MarkerId;

/// A location in Git configuration text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitSpan {
    /// 1-based line.
    pub line: u32,
    /// Byte range of the line.
    pub range: Range<usize>,
}

/// An `[include]` or `[includeIf "…"]` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitInclude {
    /// The path as written.
    pub path: String,
    /// Whether it is behind `includeIf` (never evaluated here).
    pub conditional: bool,
    /// Where.
    pub span: GitSpan,
}

/// A key and its section; never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitKey {
    /// Section name, lowercased.
    pub section: String,
    /// Subsection, as written.
    pub subsection: Option<String>,
    /// Key name, lowercased.
    pub key: String,
    /// Where.
    pub span: GitSpan,
}

/// What a Git configuration text contains, without values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GitScan {
    /// Include paths.
    pub includes: Vec<GitInclude>,
    /// Keys.
    pub keys: Vec<GitKey>,
}

/// Every Heimdall block in Git configuration text.
#[must_use]
pub fn find_blocks(bytes: &[u8]) -> Vec<FoundBlock> {
    find_blocks_in(bytes, Flavor::Git)
}

/// Plan inserting `block` before the first section header.
///
/// # Errors
/// [`EditRefusal`], as [`crate::edit::plan_insert`].
pub fn plan_insert_top(
    existing: Option<&[u8]>,
    block: &IncludeBlock,
) -> Result<InsertPlan, EditRefusal> {
    plan_insert_in(existing, block, Flavor::Git)
}

/// Plan removing the block `marker`, which must equal `expected_block` exactly.
///
/// # Errors
/// [`EditRefusal`], as [`crate::edit::plan_remove`].
pub fn plan_remove(
    bytes: &[u8],
    marker: &MarkerId,
    expected_block: &[u8],
) -> Result<Vec<u8>, EditRefusal> {
    plan_remove_in(bytes, marker, expected_block, Flavor::Git)
}

/// Scan for includes and keys; values are never returned.
///
/// * A key is reported with its lowercased section, its subsection (as written for
///   `[section "sub"]`, lowercased for the old `[section.sub]` form) and its
///   lowercased name. A key after a malformed header, or before any header, is not
///   reported (Git refuses such a file).
/// * `path` under `[include]` and under `[includeIf "<condition>"]` is also reported
///   as an include (`conditional` for `includeIf`). The condition is never evaluated.
///   A path value that cannot be parsed (an unterminated quote, a missing value) is
///   reported with an empty path, which the caller cannot resolve, so the include
///   graph counts as unreadable (fail closed).
#[must_use]
pub fn scan(bytes: &[u8]) -> GitScan {
    let mut out = GitScan::default();
    let mut section: Option<(String, Option<String>)> = None;
    let mut pos = if bytes.starts_with(b"\xEF\xBB\xBF") {
        3
    } else {
        0
    };
    let mut line: u32 = 1;
    while pos < bytes.len() {
        let start = pos;
        let start_line = line;
        let mut cur = Cursor { bytes, pos, line };
        cur.skip_blank();
        match cur.peek() {
            None => {
                pos = cur.pos;
                line = cur.line;
                continue;
            }
            Some(b'\n') => {
                cur.next_line();
            }
            Some(b'#' | b';') => cur.skip_to_next_line(),
            Some(b'[') => {
                section = cur.header();
                // A key may follow the header on the same line.
                cur.skip_blank();
                match cur.peek() {
                    Some(c) if c.is_ascii_alphabetic() => {
                        cur.key(&section, start, start_line, &mut out);
                    }
                    _ => cur.skip_to_next_line(),
                }
            }
            Some(c) if c.is_ascii_alphabetic() => {
                cur.key(&section, start, start_line, &mut out);
            }
            Some(_) => cur.skip_to_next_line(),
        }
        pos = cur.pos;
        line = cur.line;
    }
    out
}

/// A position in the text.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: u32,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Skip spaces, tabs and `\r` (a `\r\n` line end then shows as `\n`).
    fn skip_blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r')) {
            self.pos += 1;
        }
    }

    fn next_line(&mut self) {
        // At a `\n`.
        self.pos += 1;
        self.line = self.line.saturating_add(1);
    }

    fn skip_to_next_line(&mut self) {
        while let Some(c) = self.peek() {
            self.pos += 1;
            if c == b'\n' {
                self.line = self.line.saturating_add(1);
                return;
            }
        }
    }

    /// Parse `[name]`, `[name "sub"]` or `[name.sub]`; `None` when malformed. Leaves
    /// the cursor after `]` (or at the line end when malformed).
    fn header(&mut self) -> Option<(String, Option<String>)> {
        self.pos += 1; // '['
        let name_start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'-' || c == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let name = std::str::from_utf8(&self.bytes[name_start..self.pos]).ok()?;
        if name.is_empty() {
            self.skip_to_line_end();
            return None;
        }
        match self.peek() {
            Some(b']') => {
                self.pos += 1;
                let name = name.to_ascii_lowercase();
                Some(match name.split_once('.') {
                    Some((s, sub)) => (s.to_owned(), Some(sub.to_owned())),
                    None => (name, None),
                })
            }
            Some(b' ' | b'\t') => {
                while matches!(self.peek(), Some(b' ' | b'\t')) {
                    self.pos += 1;
                }
                if self.peek() != Some(b'"') || name.contains('.') {
                    self.skip_to_line_end();
                    return None;
                }
                self.pos += 1;
                let mut sub = Vec::new();
                loop {
                    match self.peek() {
                        Some(b'\\') => {
                            self.pos += 1;
                            match self.peek() {
                                Some(c) if c != b'\n' => {
                                    sub.push(c);
                                    self.pos += 1;
                                }
                                _ => {
                                    self.skip_to_line_end();
                                    return None;
                                }
                            }
                        }
                        Some(b'"') => {
                            self.pos += 1;
                            break;
                        }
                        Some(b'\n') | None => return None,
                        Some(c) => {
                            sub.push(c);
                            self.pos += 1;
                        }
                    }
                }
                if self.peek() != Some(b']') {
                    self.skip_to_line_end();
                    return None;
                }
                self.pos += 1;
                let sub = String::from_utf8(sub).ok()?;
                Some((name.to_ascii_lowercase(), Some(sub)))
            }
            _ => {
                self.skip_to_line_end();
                None
            }
        }
    }

    fn skip_to_line_end(&mut self) {
        while let Some(c) = self.peek() {
            if c == b'\n' {
                return;
            }
            self.pos += 1;
        }
    }

    /// Parse one key line (with continuations) and record it.
    fn key(
        &mut self,
        section: &Option<(String, Option<String>)>,
        start: usize,
        start_line: u32,
        out: &mut GitScan,
    ) {
        let name_start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let name = String::from_utf8_lossy(&self.bytes[name_start..self.pos]).to_ascii_lowercase();
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
        let value = match self.peek() {
            Some(b'=') => {
                self.pos += 1;
                self.value()
            }
            Some(b'#' | b';' | b'\n' | b'\r') | None => {
                self.skip_to_line_end();
                None // a boolean key: no value
            }
            Some(_) => {
                // Not a key line Git accepts.
                self.skip_to_line_end();
                if self.peek() == Some(b'\n') {
                    self.next_line();
                }
                return;
            }
        };
        // The cursor is at the line end; the span stops before `\r\n`/`\n`.
        let mut end = self.pos.min(self.bytes.len());
        if end > start && self.bytes[end - 1] == b'\r' {
            end -= 1;
        }
        let span = GitSpan {
            line: start_line,
            range: start..end.max(start),
        };
        if self.peek() == Some(b'\n') {
            self.next_line();
        }
        let Some((sec, sub)) = section else {
            return;
        };
        if name == "path" {
            let conditional = match (sec.as_str(), sub) {
                ("include", None) => Some(false),
                ("includeif", Some(_)) => Some(true),
                _ => None,
            };
            if let Some(conditional) = conditional {
                out.includes.push(GitInclude {
                    path: value.unwrap_or_default(),
                    conditional,
                    span: span.clone(),
                });
            }
        }
        out.keys.push(GitKey {
            section: sec.clone(),
            subsection: sub.clone(),
            key: name,
            span,
        });
    }

    /// Parse a value after `=`, following Git's rules: leading whitespace skipped,
    /// `"` toggles quoting, `\` escapes (`\n`, `\t`, `\b`, `\\`, `\"`) and continues the
    /// line before a newline, `#`/`;` outside quotes start a comment, and trailing
    /// whitespace outside quotes is dropped. Leaves the cursor at the line end.
    /// `None` for a malformed value (unterminated quote or a bad escape).
    fn value(&mut self) -> Option<String> {
        let mut out: Vec<u8> = Vec::new();
        let mut pending_space = 0usize;
        let mut quoted = false;
        let mut started = false;
        let mut ok = true;
        while let Some(c) = self.peek() {
            match c {
                b'\n' => {
                    if quoted {
                        ok = false;
                    }
                    break;
                }
                b'\r' if self.bytes.get(self.pos + 1) == Some(&b'\n') => {
                    self.pos += 1;
                }
                b' ' | b'\t' if !quoted => {
                    if started {
                        pending_space += 1;
                    }
                    self.pos += 1;
                }
                b'#' | b';' if !quoted => {
                    self.skip_to_line_end();
                    break;
                }
                b'"' => {
                    self.flush_space(&mut out, &mut pending_space);
                    quoted = !quoted;
                    started = true;
                    self.pos += 1;
                }
                b'\\' => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'\n') => {
                            self.next_line();
                        }
                        Some(b'\r') if self.bytes.get(self.pos + 1) == Some(&b'\n') => {
                            self.pos += 1;
                            self.next_line();
                        }
                        Some(e) => {
                            let mapped = match e {
                                b'n' => Some(b'\n'),
                                b't' => Some(b'\t'),
                                b'b' => Some(8),
                                b'\\' => Some(b'\\'),
                                b'"' => Some(b'"'),
                                _ => None,
                            };
                            self.flush_space(&mut out, &mut pending_space);
                            started = true;
                            match mapped {
                                Some(m) => out.push(m),
                                None => ok = false,
                            }
                            self.pos += 1;
                        }
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                _ => {
                    self.flush_space(&mut out, &mut pending_space);
                    started = true;
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
        if quoted {
            ok = false;
        }
        if ok {
            String::from_utf8(out).ok()
        } else {
            None
        }
    }

    fn flush_space(&self, out: &mut Vec<u8>, pending: &mut usize) {
        out.extend(std::iter::repeat_n(b' ', *pending));
        *pending = 0;
    }
}
