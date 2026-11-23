//! The user-file block editor (m02-plan U2; ADR-0007 §2, §4).
//!
//! `plan_remove(plan_insert(x)) == x` byte for byte for every `x`, including CRLF, a
//! BOM, no trailing newline, an empty file and a missing file. Bytes outside the block
//! are never changed.
//!
//! The editor reads lines as bytes. It needs no parse of the user's file: a line is
//! blank, a `#` comment, or a directive, and a directive is a section line when its
//! keyword is `Host` or `Match` (case-insensitive, ended by whitespace or `=`). A line
//! that is not UTF-8 is a directive, so it is never left above the block.
//!
//! **Placement** (ADR-0007 §3). B goes before the first directive line. Only the BOM,
//! leading blank lines and leading comments stay above it. When the file has no
//! directive, B goes after the last complete line, so an unterminated final line
//! (a comment without a newline) ends up below B and is never joined to it. B always
//! starts at a line start and ends with a newline, so removing it restores the file.
//!
//! The same core edits Git configuration text ([`crate::gitedit`]); only the line
//! classes and the block body differ.

use std::collections::HashMap;
use std::ops::Range;

use crate::parse::{SourceId, Span};
use crate::render::{BEGIN_PREFIX, BEGIN_SUFFIX, END_PREFIX, MarkerId, Newline};

/// Where a found block sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockPosition {
    /// Before the first `Host`/`Match` line and before any top-level directive that
    /// would precede it: effective for every host.
    BeforeFirstSection,
    /// Inside a section: conditional, reported `include_conditional`.
    ///
    /// The span is the last section line above the block or, when there is none, the
    /// first directive above it (a top-level directive above B wins over P's values,
    /// F1, so B is no longer placed as ADR-0007 §3 requires). Its `source` is
    /// `SourceId(0)`, the edited text itself, and its line is 1-based.
    Conditional(Span),
}

/// A Heimdall block found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundBlock {
    /// Its marker.
    pub marker: MarkerId,
    /// Its byte range, markers included.
    pub range: Range<usize>,
    /// Whether its content is exactly what Heimdall rendered.
    pub intact: bool,
    /// Where it sits.
    pub position: BlockPosition,
}

/// A block to insert (from `render::render_include_block`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeBlock {
    /// Its marker.
    pub marker: MarkerId,
    /// The rendered bytes, line endings matching the target file.
    pub bytes: Vec<u8>,
}

/// The planned insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertPlan {
    /// The whole file after insertion.
    pub bytes: Vec<u8>,
    /// Where the block starts.
    pub offset: usize,
    /// The file's line ending.
    pub newline: Newline,
    /// Whether the file had a BOM (kept).
    pub had_bom: bool,
}

/// Why an edit is refused. Each maps to a `ConflictKind` or a manual reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EditRefusal {
    /// More than one block with this marker (`marker_duplicated`).
    #[error("duplicate marker")]
    DuplicateMarker,
    /// The block's content was edited (`marker_edited`), with the edited lines.
    #[error("marker block edited")]
    MarkerEdited {
        /// 1-based lines that differ.
        lines: Vec<u32>,
    },
    /// The block is inside a section (`include_conditional`).
    #[error("marker block is conditional")]
    Conditional,
    /// No block with this marker.
    #[error("marker not found")]
    MarkerMissing,
    /// An encoding the client is not known to accept (`unsupported_encoding`).
    #[error("unsupported encoding")]
    UnsupportedEncoding,
}

/// Every Heimdall block in `bytes`.
#[must_use]
pub fn find_blocks(bytes: &[u8]) -> Vec<FoundBlock> {
    find_blocks_in(bytes, Flavor::Ssh)
}

/// Plan inserting `block` before the first section line or top-level directive of
/// `existing` (`None`: the file does not exist).
///
/// # Errors
/// [`EditRefusal`]:
/// * `DuplicateMarker` when `existing` already holds a Heimdall block (any marker:
///   two blocks would include P twice);
/// * `UnsupportedEncoding` for a UTF-16 or UTF-32 byte-order mark, or when the
///   block's line ending is not the file's (detected from its first line ending);
/// * `MarkerEdited` when `block` is not one intact block for `block.marker`.
pub fn plan_insert(
    existing: Option<&[u8]>,
    block: &IncludeBlock,
) -> Result<InsertPlan, EditRefusal> {
    plan_insert_in(existing, block, Flavor::Ssh)
}

/// Plan removing the block `marker`, which must equal `expected_block` exactly.
/// Removal does not depend on where the block sits: a block moved into a section is
/// still removed when its bytes are the recorded ones.
///
/// # Errors
/// [`EditRefusal`]: `MarkerMissing`, `DuplicateMarker`, or `MarkerEdited` with the
/// file lines that differ from `expected_block`.
pub fn plan_remove(
    bytes: &[u8],
    marker: &MarkerId,
    expected_block: &[u8],
) -> Result<Vec<u8>, EditRefusal> {
    plan_remove_in(bytes, marker, expected_block, Flavor::Ssh)
}

/// The line ending of `bytes`, from its first line ending; `None` when it has none.
#[must_use]
pub fn detect_newline(bytes: &[u8]) -> Option<Newline> {
    let i = bytes.iter().position(|&b| b == b'\n')?;
    Some(if i > 0 && bytes[i - 1] == b'\r' {
        Newline::CrLf
    } else {
        Newline::Lf
    })
}

// --- the shared core ------------------------------------------------------------------

/// Which configuration language the text is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    /// OpenSSH client configuration.
    Ssh,
    /// Git configuration.
    Git,
}

/// The UTF-8 byte-order mark.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// One physical line.
#[derive(Debug, Clone, Copy)]
struct LineRef {
    /// First byte.
    start: usize,
    /// End of the content (before `\r\n` or `\n`).
    content_end: usize,
    /// After the line ending.
    end: usize,
    /// The line ending, `None` for an unterminated last line.
    newline: Option<Newline>,
}

/// What a line is, for placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineClass {
    Blank,
    Comment,
    /// `Host`/`Match` (OpenSSH) or a `[section]` header (Git).
    Section,
    /// Any other directive or key line.
    Directive,
}

fn body_start(bytes: &[u8]) -> usize {
    if bytes.starts_with(BOM) { BOM.len() } else { 0 }
}

fn split_lines(bytes: &[u8]) -> Vec<LineRef> {
    let mut out = Vec::new();
    let mut start = body_start(bytes);
    while start < bytes.len() {
        match bytes[start..].iter().position(|&b| b == b'\n') {
            Some(rel) => {
                let nl = start + rel;
                let (content_end, newline) = if nl > start && bytes[nl - 1] == b'\r' {
                    (nl - 1, Newline::CrLf)
                } else {
                    (nl, Newline::Lf)
                };
                out.push(LineRef {
                    start,
                    content_end,
                    end: nl + 1,
                    newline: Some(newline),
                });
                start = nl + 1;
            }
            None => {
                out.push(LineRef {
                    start,
                    content_end: bytes.len(),
                    end: bytes.len(),
                    newline: None,
                });
                start = bytes.len();
            }
        }
    }
    out
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &b[start..end.max(start)]
}

fn classify(content: &[u8], flavor: Flavor) -> LineClass {
    let t = trim_ascii(content);
    if t.is_empty() {
        return LineClass::Blank;
    }
    match flavor {
        Flavor::Ssh => {
            if t[0] == b'#' {
                return LineClass::Comment;
            }
            let kw_end = t
                .iter()
                .position(|c| c.is_ascii_whitespace() || *c == b'=')
                .unwrap_or(t.len());
            let kw = &t[..kw_end];
            if kw.eq_ignore_ascii_case(b"host") || kw.eq_ignore_ascii_case(b"match") {
                LineClass::Section
            } else {
                LineClass::Directive
            }
        }
        Flavor::Git => match t[0] {
            b'#' | b';' => LineClass::Comment,
            b'[' => LineClass::Section,
            _ => LineClass::Directive,
        },
    }
}

/// The marker id of a begin line (leading whitespace tolerated, so an indented marker
/// is still found, and then reported not intact).
fn begin_marker(content: &[u8]) -> Option<MarkerId> {
    let t = std::str::from_utf8(trim_ascii(content)).ok()?;
    let rest = t.strip_prefix(BEGIN_PREFIX)?;
    let close = rest.find(')')?;
    MarkerId::parse(&rest[..close]).ok()
}

/// The id text of an end marker line: what lies between `END_PREFIX` and the final
/// `)` of the line with surrounding whitespace trimmed. The line ends the block of
/// `marker` exactly when this is `marker.as_str()`.
fn end_marker_id(content: &[u8]) -> Option<&str> {
    std::str::from_utf8(trim_ascii(content))
        .ok()?
        .strip_prefix(END_PREFIX)?
        .strip_suffix(')')
}

/// Every end marker line of a file, by id, read in one pass, so that finding each
/// begin marker's end never rescans the lines below it (M08-W2-F1: an unterminated
/// begin marker used to read, and build an end-marker `String` for, every later line).
struct EndLines<'a> {
    /// Each id's end lines in ascending order, and how many of them lie at or above
    /// the begin line of the last lookup for that id.
    by_id: HashMap<&'a str, (Vec<usize>, usize)>,
}

impl<'a> EndLines<'a> {
    fn new(bytes: &'a [u8], lines: &[LineRef]) -> Self {
        let mut by_id: HashMap<&'a str, (Vec<usize>, usize)> = HashMap::new();
        for (j, l) in lines.iter().enumerate() {
            if let Some(id) = end_marker_id(&bytes[l.start..l.content_end]) {
                by_id.entry(id).or_default().0.push(j);
            }
        }
        Self { by_id }
    }

    /// The first end line of `marker` below line `begin`. `begin` never decreases from
    /// one call to the next, so the lines passed over are never needed again.
    fn first_below(&mut self, marker: &MarkerId, begin: usize) -> Option<usize> {
        let (at, passed) = self.by_id.get_mut(marker.as_str())?;
        *passed += at[*passed..].iter().take_while(|&&j| j <= begin).count();
        at.get(*passed).copied()
    }
}

fn line_text(bytes: &[u8], l: &LineRef) -> Option<String> {
    std::str::from_utf8(&bytes[l.start..l.content_end])
        .ok()
        .map(str::to_owned)
}

/// A quoted path body: non-empty, no raw `"`, no control character.
fn quoted_body_ok(body: &str, git: bool) -> bool {
    if body.is_empty() || body.chars().any(char::is_control) {
        return false;
    }
    if !git {
        return !body.contains('"');
    }
    // Git: `\` escapes the next character; an unescaped `"` ends the value early.
    let mut escaped = false;
    for c in body.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return false;
        }
    }
    !escaped
}

fn intact(bytes: &[u8], lines: &[LineRef], marker: &MarkerId, flavor: Flavor) -> bool {
    let want = match flavor {
        Flavor::Ssh => 3,
        Flavor::Git => 4,
    };
    if lines.len() != want {
        return false;
    }
    let Some(nl) = lines[0].newline else {
        return false;
    };
    if lines.iter().any(|l| l.newline != Some(nl)) {
        return false;
    }
    let Some(texts) = lines
        .iter()
        .map(|l| line_text(bytes, l))
        .collect::<Option<Vec<String>>>()
    else {
        return false;
    };
    if texts[0] != format!("{BEGIN_PREFIX}{}{BEGIN_SUFFIX}", marker.as_str())
        || texts[want - 1] != format!("{END_PREFIX}{})", marker.as_str())
    {
        return false;
    }
    match flavor {
        Flavor::Ssh => texts[1]
            .strip_prefix("Include \"")
            .and_then(|r| r.strip_suffix('"'))
            .is_some_and(|body| quoted_body_ok(body, false)),
        Flavor::Git => {
            texts[1] == "[include]"
                && texts[2]
                    .strip_prefix("\tpath = \"")
                    .and_then(|r| r.strip_suffix('"'))
                    .is_some_and(|body| quoted_body_ok(body, true))
        }
    }
}

fn line_no(i: usize) -> u32 {
    u32::try_from(i + 1).unwrap_or(u32::MAX)
}

/// The lines above a begin marker, classified once each as the scan moves down, so
/// that each block's position does not reclassify every line above it (M08-W2-F1).
/// Every line counts, those inside earlier blocks included.
#[derive(Default)]
struct LinesAbove {
    /// How many lines, from the first, are classified.
    seen: usize,
    /// The last section line among them.
    last_section: Option<usize>,
    /// The first directive line among them.
    first_directive: Option<usize>,
}

impl LinesAbove {
    /// Where a block that begins at line `begin` sits. `begin` never decreases from
    /// one call to the next.
    fn position(
        &mut self,
        bytes: &[u8],
        lines: &[LineRef],
        begin: usize,
        flavor: Flavor,
    ) -> BlockPosition {
        for (i, l) in lines[..begin].iter().enumerate().skip(self.seen) {
            match classify(&bytes[l.start..l.content_end], flavor) {
                LineClass::Section => self.last_section = Some(i),
                LineClass::Directive => {
                    self.first_directive.get_or_insert(i);
                }
                LineClass::Blank | LineClass::Comment => {}
            }
        }
        self.seen = self.seen.max(begin);
        match self.last_section.or(self.first_directive) {
            None => BlockPosition::BeforeFirstSection,
            Some(i) => BlockPosition::Conditional(Span {
                source: SourceId(0),
                line: line_no(i),
            }),
        }
    }
}

/// A block with its first line index (for edited-line reporting).
struct Located {
    found: FoundBlock,
    first_line: usize,
}

/// Every block, in file order. A begin marker's block ends at the first later end
/// marker for its id; begin markers inside it are not blocks. Linear in the length of
/// `bytes`: each line is split, tested as a begin and an end marker and classified at
/// most once.
fn locate(bytes: &[u8], flavor: Flavor) -> Vec<Located> {
    let lines = split_lines(bytes);
    let mut ends = EndLines::new(bytes, &lines);
    let mut above = LinesAbove::default();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        let Some(marker) = begin_marker(&bytes[l.start..l.content_end]) else {
            i += 1;
            continue;
        };
        let end = ends.first_below(&marker, i);
        let position = above.position(bytes, &lines, i, flavor);
        let (range, ok, next) = match end {
            Some(j) => (
                l.start..lines[j].end,
                intact(bytes, &lines[i..=j], &marker, flavor),
                j + 1,
            ),
            // An unterminated begin marker is reported as a block that is not intact,
            // so an insert refuses and a remove reports the edit (fail closed).
            None => (l.start..l.end, false, i + 1),
        };
        out.push(Located {
            found: FoundBlock {
                marker,
                range,
                intact: ok,
                position,
            },
            first_line: i,
        });
        i = next;
    }
    out
}

pub(crate) fn find_blocks_in(bytes: &[u8], flavor: Flavor) -> Vec<FoundBlock> {
    locate(bytes, flavor).into_iter().map(|l| l.found).collect()
}

fn utf16_or_32_bom(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\xFF\xFE")
        || bytes.starts_with(b"\xFE\xFF")
        || bytes.starts_with(b"\x00\x00\xFE\xFF")
}

pub(crate) fn plan_insert_in(
    existing: Option<&[u8]>,
    block: &IncludeBlock,
    flavor: Flavor,
) -> Result<InsertPlan, EditRefusal> {
    // The block itself must be exactly one intact block for its marker, ending with a
    // newline, so that it starts and ends on line boundaries.
    let own = find_blocks_in(&block.bytes, flavor);
    let well_formed = own.len() == 1
        && own[0].intact
        && own[0].marker == block.marker
        && own[0].range == (0..block.bytes.len())
        && !block.bytes.starts_with(BOM);
    if !well_formed {
        return Err(EditRefusal::MarkerEdited { lines: Vec::new() });
    }
    let block_nl = detect_newline(&block.bytes).unwrap_or(Newline::Lf);
    let Some(x) = existing else {
        return Ok(InsertPlan {
            bytes: block.bytes.clone(),
            offset: 0,
            newline: block_nl,
            had_bom: false,
        });
    };
    if utf16_or_32_bom(x) {
        return Err(EditRefusal::UnsupportedEncoding);
    }
    if !find_blocks_in(x, flavor).is_empty() {
        return Err(EditRefusal::DuplicateMarker);
    }
    let had_bom = x.starts_with(BOM);
    if let Some(file_nl) = detect_newline(x)
        && file_nl != block_nl
    {
        return Err(EditRefusal::UnsupportedEncoding);
    }
    let lines = split_lines(x);
    let first_directive = lines.iter().find(|l| {
        matches!(
            classify(&x[l.start..l.content_end], flavor),
            LineClass::Section | LineClass::Directive
        )
    });
    let offset = match first_directive {
        Some(l) => l.start,
        // No directive: after the last complete line, before an unterminated one.
        None => lines
            .iter()
            .rev()
            .find(|l| l.newline.is_some())
            .map_or(body_start(x), |l| l.end),
    };
    let mut bytes = Vec::with_capacity(x.len() + block.bytes.len());
    bytes.extend_from_slice(&x[..offset]);
    bytes.extend_from_slice(&block.bytes);
    bytes.extend_from_slice(&x[offset..]);
    Ok(InsertPlan {
        bytes,
        offset,
        newline: detect_newline(x).unwrap_or(block_nl),
        had_bom,
    })
}

pub(crate) fn plan_remove_in(
    bytes: &[u8],
    marker: &MarkerId,
    expected_block: &[u8],
    flavor: Flavor,
) -> Result<Vec<u8>, EditRefusal> {
    let mut matching: Vec<Located> = locate(bytes, flavor)
        .into_iter()
        .filter(|l| &l.found.marker == marker)
        .collect();
    let located = match matching.len() {
        0 => return Err(EditRefusal::MarkerMissing),
        1 => matching.remove(0),
        _ => return Err(EditRefusal::DuplicateMarker),
    };
    let range = located.found.range.clone();
    let actual = &bytes[range.clone()];
    if actual != expected_block {
        let a: Vec<&[u8]> = actual.split_inclusive(|&b| b == b'\n').collect();
        let e: Vec<&[u8]> = expected_block.split_inclusive(|&b| b == b'\n').collect();
        let lines = (0..a.len().max(e.len()))
            .filter(|&k| a.get(k) != e.get(k))
            .map(|k| line_no(located.first_line + k))
            .collect();
        return Err(EditRefusal::MarkerEdited { lines });
    }
    let mut out = Vec::with_capacity(bytes.len() - actual.len());
    out.extend_from_slice(&bytes[..range.start]);
    out.extend_from_slice(&bytes[range.end..]);
    Ok(out)
}
