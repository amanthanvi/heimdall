//! Heimdall's trusted-work project logic (M05 U1; ADR-0011 §2.2–§2.4, §10 items 2, 7, 9).
//!
//! * [`manifest`]: the bounded, closed-schema `.heimdall.toml` parser, its authority-key
//!   rejection at any depth, and the access digest (§2.2).
//! * [`observe`]: workspace discovery and observation over the [`observe::FsView`] seam,
//!   including the linked-worktree back-link verification (§2.3, §10 item 7).
//! * [`matching`]: [`match_workspace`], the §2.3 table (property P11).
//! * [`portable`]: the portable bundle, emitted and parsed (§2.4 I4).
//!
//! **Pure.** Production edges are `heimdall-contract` and `heimdall-domain` only, with no
//! process, network, file or terminal I/O of its own: every file access goes through
//! [`observe::FsView`], which the runtime implements over the real filesystem and the tests
//! implement in memory. The crate-graph step refuses any other workspace edge
//! (`tools/validation/crate_graph.py`); `heimdall-app` depends on this crate, never the
//! reverse.
//!
//! **Hostile input.** Every parser here treats its bytes as attacker-controlled (a cloned
//! repository's manifest, an imported bundle): nothing panics, nothing is unbounded, and no
//! error message echoes repository text except an authority key name sanitized to token
//! characters.

pub mod manifest;
pub mod matching;
pub mod observe;
pub mod portable;

pub use manifest::{
    MANIFEST_AUTHORITY_KEYS, ManifestError, ParsedManifest, access_digest, parse_manifest,
};
pub use matching::match_workspace;
pub use observe::{
    FsKind, FsView, GitObservation, ObserveError, ReadOutcome, WorkspaceObservation,
    observe_workspace,
};
pub use portable::{BundleError, BundleInput, emit_bundle, parse_bundle};

/// Lower-case ASCII and map `-` to `_`: the key normalization `heimdall_runtime::config`
/// applies to its `FORBIDDEN_KEYS` (`normalized`), mirrored here because this crate cannot
/// depend on the runtime.
pub(crate) fn normalized_key(key: &str) -> String {
    key.to_ascii_lowercase().replace('-', "_")
}

/// A key name safe to put in an error: token characters only (`[A-Za-z0-9._:-]`, every
/// other character replaced by `_`) and at most 64 bytes.
pub(crate) fn sanitized_key(key: &str) -> String {
    key.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
