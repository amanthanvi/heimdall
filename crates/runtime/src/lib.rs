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

// ⟨M04⟩ U1 (ADR-0010 §1, §6): login autostart, one file per platform.
pub mod autostart;
pub mod config;
// ⟨M03⟩ m03-plan U7 (ADR-0008 D8): owned masters, owned dedicated connections, policies.
pub mod connections;
// ⟨M06 W3 host⟩ The controller's sync and issuance driver, hosted in the runtime.
pub mod controller_host;
// ⟨M05⟩ U5 (ADR-0011 §3): personal default and ordinary-`ssh` activation.
pub mod default_activation;
pub mod dispatch;
pub mod instance;
pub mod launcher;
// ⟨M06 W5⟩ Local widening decisions, on every installation (ADR-0006 §18.9 item 8).
pub mod local_widening;
// ⟨M03⟩ wave 4 (U10): the managed adapter's store-backed sources (ADR-0008 §17.20 "For
// U10": `ManagedSourceRead`, `GrantScopes`, `SlotStore`, the production `InstallView`).
pub mod managed_store;
// ⟨M06⟩ W2 (ADR-0012 §3.6–§3.11): the runner runtime's paired sessions.
pub mod paired;
// ⟨M06⟩ W3 (ADR-0012 §2.3 item 1): the serve allowlist's source, paired clients' endpoints.
pub mod paired_endpoints;
// ⟨M06⟩ W2: the runner's production authorized_keys writer (ADR-0012 §3.5).
pub mod paired_lines;
pub mod paths;
pub mod platform;
// ⟨M06 U3⟩ (ADR-0012 §4): the runner runtime's issuance, time source, readiness, clean
// launch and lifetime.
pub mod runner;
pub mod service;
// ⟨M05⟩ U6 (ADR-0011 §5): managed-slot handover.
pub mod slot_handover;
// ⟨M03⟩ U9: the session-lock sources (ADR-0008 D9 item 3; m03-plan U9).
pub mod session_lock;
pub mod supervisor;
// ⟨M06 U56⟩ (ADR-0012 §2.3-§2.4, §5.5): the Iroh serve child's supervision and admission
// authority, the K_iroh adapters and the route helper's Iroh leg.
pub mod supervise_transport;
pub mod telemetry;
// ⟨M05⟩ U4 (ADR-0011 §2.2–§2.3, §3.2–§3.3): workspace observation.
pub mod workspace_observe;
// ⟨M04 U3b⟩ The WSL wiring (the namespace-routing projection cleaner).
pub mod wsl_bridge;
pub mod wsl_wiring;

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
