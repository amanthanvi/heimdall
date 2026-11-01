//! The user-file block editor (m02-plan U2; ADR-0007 §2, §4).
//!
//! `plan_remove(plan_insert(x)) == x` byte for byte for every `x`, including CRLF, a
//! BOM, no trailing newline, an empty file and a missing file. Bytes outside the block
//! are never changed.

use std::ops::Range;

use crate::parse::Span;
use crate::render::{MarkerId, Newline};

/// Where a found block sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockPosition {
    /// Before the first `Host`/`Match` line and before any top-level directive that
    /// would precede it: effective for every host.
    BeforeFirstSection,
    /// Inside a section: conditional, reported `include_conditional`.
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
    let _ = bytes;
    todo!("M02-U2 edit::find_blocks")
}

/// Plan inserting `block` before the first section line or top-level directive of
/// `existing` (`None`: the file does not exist).
///
/// # Errors
/// [`EditRefusal`].
pub fn plan_insert(
    existing: Option<&[u8]>,
    block: &IncludeBlock,
) -> Result<InsertPlan, EditRefusal> {
    let _ = (existing, block);
    todo!("M02-U2 edit::plan_insert")
}

/// Plan removing the block `marker`, which must equal `expected_block` exactly.
///
/// # Errors
/// [`EditRefusal`].
pub fn plan_remove(
    bytes: &[u8],
    marker: &MarkerId,
    expected_block: &[u8],
) -> Result<Vec<u8>, EditRefusal> {
    let _ = (bytes, marker, expected_block);
    todo!("M02-U2 edit::plan_remove")
}
