//! Contract golden tests and schema consistency (M01-T06 part 1, unit U1).
//!
//! This directory is compiled as a `#[cfg(test)]` module tree of `heimdall-contract`
//! (see the one-line `#[path]` hook at the end of `crates/contract/src/schema.rs`),
//! so the tests use the crate's public types exactly as an external caller would,
//! without a new dependency edge or Cargo target.
//!
//! * `code_table`: every `Code` row (exit, retryable, effect, next) against ADR-0006
//!   section 5, by two independent sources (a mechanical transcription of the ADR
//!   table in `golden/code-table.golden.json`, and a parse of the ADR file itself).
//! * `examples`: `schemas/examples/*.json` envelope/event/request/IPC fixtures parse,
//!   round-trip byte-for-byte as JSON values, validate against the generated schemas,
//!   tolerate unknown fields, and are rejected on an unsupported major.
//! * `canonical_props`: canonical-JSON and request-hash properties (proptest).
//! * `ids`: identifier parser bounds (A29 "parsers bounded").
//! * `schema_export`: export determinism and agreement of `schemas/public-api/`.
//! * `limits`: ADR-0006 section 2 limits and version constants.
//!
//! Property tests run 256 cases with a fixed default seed so a failure reproduces;
//! set `PROPTEST_RNG_SEED=<u64>` to explore other seeds. Failing cases persist to
//! `tests/contracts/proptest-regressions/contract.txt` (committed).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod canonical_props;
mod code_table;
mod examples;
mod ids;
mod jsonschema_lite;
mod limits;
mod schema_export;

use std::path::PathBuf;

use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

/// Repository root (two levels above the crate manifest).
pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Property-test configuration shared by every property in this tree.
pub(crate) fn proptest_config() -> ProptestConfig {
    let mut config = ProptestConfig {
        cases: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "../../tests/contracts/proptest-regressions/contract.txt",
        ))),
        ..ProptestConfig::default()
    };
    // `ProptestConfig::default()` honours PROPTEST_RNG_SEED; otherwise pin a seed so
    // CI runs are reproducible.
    if matches!(config.rng_seed, RngSeed::Random) {
        config.rng_seed = RngSeed::Fixed(0x4845_494D_4441_4C4C);
    }
    config
}

/// Fail if text a test produced or consumed carries material that must never appear
/// in a public contract artifact (ADR-0004 section 4; AGENTS.md canary rule).
pub(crate) fn assert_clean(label: &str, text: &str) {
    assert!(
        !text.contains("HEIMDALL_CANARY_"),
        "{label}: canary value present"
    );
    assert!(
        !text.contains("PRIVATE KEY"),
        "{label}: private-key block present"
    );
    assert!(
        !text.chars().any(|c| c == '\u{1b}'),
        "{label}: terminal escape present"
    );
}
