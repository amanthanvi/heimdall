//! Heimdall public wire contract (G08 baseline, ADR-0006; "baseline, not frozen").
//!
//! This crate defines what crosses a process boundary: the common envelope
//! (spec §11.2), the stable code table and CLI exit codes (spec §11.6), operation
//! and grant state enums (spec §11.4, §6.3), events and cursors (spec §11.5), the
//! request/response types of the six primitives (docs/contracts/primitives-draft.md),
//! the local IPC message set and its hard limits (spec §13.2), canonical JSON for
//! request hashing (spec §11.4) and the JSON Schema generator (plan §4.5).
//! ADR-0006 revision 3 (M02; m02-plan §5) adds the setup and catalog requests
//! (`setup`, `catalog`), provider and identity-selection types (`provider`), the
//! doctor report (`doctor`) and the `run` side-channel records (`run_record`).
//! ⟨M03⟩ ADR-0006 revision 4 (m03-plan §5) adds the issuer and enrollment requests
//! (`issuer`, `enrollment`) and the managed-credential reports, connection control
//! and lock behaviour (`managed`).
//!
//! It owns no semantics: state *transitions*, authority resolution and hashing
//! *inputs* live in `heimdall-domain`. Nothing here performs I/O. Dependencies are
//! limited to serialization, schema generation, time types and SHA-256.
//!
//! Compatibility rules readers of this crate must keep (ADR-0006 §9):
//! unknown non-critical fields are tolerated; an unsupported major
//! `schema_version` is rejected explicitly; omitted, `null`, and `unknown` are
//! distinct; timestamps are RFC 3339 with an explicit offset; IDs are opaque.

pub mod canonical;
pub mod catalog;
pub mod code;
pub mod doctor;
pub mod enrollment;
pub mod envelope;
pub mod event;
pub mod exit;
pub mod ids;
pub mod ipc;
pub mod issuer;
pub mod managed;
pub mod provider;
pub mod request;
pub mod run_record;
pub mod schema;
pub mod setup;
pub mod state;
pub mod version;

pub use code::Code;
pub use envelope::{EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, Warning};
pub use exit::ExitCode;
pub use state::{GrantState, OperationState};
pub use version::{PROTOCOL_VERSION, SCHEMA_VERSION, SchemaVersion};

/// RFC 3339 instant with explicit offset on the wire; stored as UTC (spec §6.2).
pub type Timestamp = jiff::Timestamp;
