//! Heimdall G02 prototype (Rust + Ratatui). Disposable gate evidence, not production code.
//!
//! Domain-ish operations live in this library so the CLI (`src/cli.rs`) and the
//! TUI (`src/tui.rs`) share exactly the same code paths:
//!
//! - [`envelope`]: result envelope, semantic codes, exit-code mapping (contract §1)
//! - [`profile`]: bounded profile loading and validation (contract §2)
//! - [`agent`]: SSH-agent identity probe and bounded frame parser (contract §3)
//! - [`runner`]: shell-free child launch, signal forwarding, status mapping (contract §4)
//! - [`list_model`]: terminal-independent list/filter/selection state machine (contract §5)
//! - [`text`]: shared sanitizing helpers for machine strings
//! - [`sigdisp`] (Unix): startup signal mask and inherited-disposition query
//! - [`keys`]: terminal input byte decoder for the TUI (no terminal queries)
//!
//! `unsafe` is denied crate-wide; the single exception is the query-only
//! `sigaction(sig, NULL, &old)` in `sigdisp::inherited_ignored` (round 2, K6a).
#![deny(unsafe_code)]

pub mod agent;
pub mod envelope;
pub mod keys;
pub mod list_model;
pub mod profile;
pub mod runner;
#[cfg(unix)]
pub mod sigdisp;
pub mod text;

/// Prototype version reported by `version --json` (contract §6).
pub const VERSION: &str = "0.0.0-g02";
/// Candidate identifier (contract §6).
pub const CANDIDATE: &str = "rust";
/// TUI framework name.
pub const TUI_FRAMEWORK: &str = "ratatui";
/// Pinned TUI framework version, extracted from Cargo.lock at build time by build.rs.
pub const TUI_FRAMEWORK_VERSION: &str = env!("HEIMDALL_PROTO_RATATUI_VERSION");
/// Crossterm backend version, extracted from Cargo.lock at build time by build.rs.
pub const CROSSTERM_VERSION: &str = env!("HEIMDALL_PROTO_CROSSTERM_VERSION");
/// `rustc --version` of the compiler that built this binary (captured by build.rs).
pub const RUSTC_VERSION: &str = env!("HEIMDALL_PROTO_RUSTC_VERSION");
