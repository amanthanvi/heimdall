//! Heimdall per-user runtime (spec §13.1, P01; plan §4.1 "Runtime/reconciler").
//!
//! `heimdall service run` hosts: the state store, the application operations, the
//! control and signing endpoints, the supervisor (one owner per resource, bounded
//! recovery), the deadline scheduler (persisted absolute deadlines), the time
//! guard (anchors, rollback detection), and the single-instance lock. On-demand
//! start from a client never creates a second instance or a broad agent (spec
//! §13.1).
//!
//! Executor: tokio **current-thread** runtime; blocking work (SQLite, signing,
//! process launch) runs on `spawn_blocking`. Rationale in overview §5.
//!
//! Must not own: authority semantics (domain), operation logic (app), wire
//! formats (contract/ipc), terminal rendering.

pub mod config;
pub mod instance;
pub mod launcher;
pub mod service;
pub mod supervisor;
pub mod telemetry;

pub use config::{Config, Paths};
pub use instance::InstanceLock;
pub use service::Service;
