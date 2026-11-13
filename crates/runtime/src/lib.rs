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
// ⟨M03⟩ m03-plan U7 (ADR-0008 D8): owned masters, owned dedicated connections, policies.
pub mod connections;
pub mod dispatch;
pub mod instance;
pub mod launcher;
// ⟨M03⟩ wave 4 (U10): the managed adapter's store-backed sources (ADR-0008 §17.20 "For
// U10": `ManagedSourceRead`, `GrantScopes`, `SlotStore`, the production `InstallView`).
pub mod managed_store;
pub mod paths;
pub mod platform;
pub mod service;
// ⟨M03⟩ U9: the session-lock sources (ADR-0008 D9 item 3; m03-plan U9).
pub mod session_lock;
pub mod supervisor;
pub mod telemetry;

/// Serializes this crate's unit tests that spawn a child with those that assert a
/// lock's release. A spawned child holds duplicates of the test process's descriptors
/// until its `exec` closes them, so a `service.lock` dropped by one test can still be
/// held, briefly, by a child another test is spawning (observed: the instance-lock
/// test failed in 8 of 30 runs alongside the holder-liveness test, and in 0 of 30
/// without it).
#[cfg(test)]
pub(crate) fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub use config::{Config, Paths};
pub use instance::InstanceLock;
pub use service::Service;
