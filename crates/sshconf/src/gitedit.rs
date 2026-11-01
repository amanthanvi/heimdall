//! The Git configuration text editor and scanner (m02-plan U2; ADR-0007 §5.6).
//!
//! The same block contract as [`crate::edit`], for Git configuration text: the block
//! goes before the first section header, after leading `#`/`;` comments, blank lines
//! and a BOM. [`scan`] reports includes and keys by span and **never returns a
//! configuration value** (M2-R08).

use std::ops::Range;

use crate::edit::{EditRefusal, FoundBlock, IncludeBlock, InsertPlan};
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
    let _ = bytes;
    todo!("M02-U2 gitedit::find_blocks")
}

/// Plan inserting `block` before the first section header.
///
/// # Errors
/// [`EditRefusal`].
pub fn plan_insert_top(
    existing: Option<&[u8]>,
    block: &IncludeBlock,
) -> Result<InsertPlan, EditRefusal> {
    let _ = (existing, block);
    todo!("M02-U2 gitedit::plan_insert_top")
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
    todo!("M02-U2 gitedit::plan_remove")
}

/// Scan for includes and keys; values are never returned.
#[must_use]
pub fn scan(bytes: &[u8]) -> GitScan {
    let _ = bytes;
    todo!("M02-U2 gitedit::scan")
}
