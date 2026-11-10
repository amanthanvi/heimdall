//! Contract golden tests and schema consistency (M01-T06 part 1, unit U1).
//!
//! This directory is the `contracts` Cargo test target of `heimdall-contract`
//! (`[[test]]` in `crates/contract/Cargo.toml`; run with
//! `cargo test -p heimdall-contract --test contracts`). It links the crate like any
//! external caller and uses only its public API.
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
//! * `m02`: ADR-0006 revision 3 deltas (m02-plan section 5): the journaled-kind
//!   mapping, `bind(launch)` without `argv`, the `run` record reader against
//!   ADR-0007 section 8, error reasons and the additive fields.
//! * `m03`: ADR-0006 revision 4 deltas (m03-plan section 5): the code table still 30
//!   rows, the section 5 item 14 reason golden, no scratch store kind in the public
//!   schemas, the M03 additive fields and their M01/M02 decodes, capabilities and
//!   the policy widening rule (the journaled-kind mapping stays in `m02`).
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
mod m02;
mod m03;
mod schema_export;

use std::path::PathBuf;

use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

/// Repository root: `HM_REPO_ROOT` when a native harness sets it, else the compile-time
/// root (ADR-0007 §12.32 item 3).
pub fn repo_root() -> PathBuf {
    heimdall_testkit::repo::repo_root()
}

/// Property-test configuration shared by every property in this tree.
pub fn proptest_config() -> ProptestConfig {
    // `Direct` paths are relative to the working directory, which Cargo sets to the
    // package root (`crates/contract`) when it runs a test target.
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
pub fn assert_clean(label: &str, text: &str) {
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
