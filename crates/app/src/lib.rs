//! Heimdall application operations (plan §4.1 "Application operations" and the
//! core of "Runtime/reconciler"; spec §13.1 "versioned application operations").
//!
//! One implementation of the six primitives shared by the CLI, the TUI and the
//! IPC server. Authorization is evaluated here on the authenticated
//! [`heimdall_domain::principal::CallerContext`], never on request fields. The
//! ensure pipeline (plan §4.2) is explicit and interruptible between stages.
//!
//! Owns: orchestration, authorization checks, idempotency handling, single-flight
//! for equivalent work, the reconciler planning core, event publication, and the
//! adapter ports (traits) that credential/environment adapters implement.
//!
//! Must not own: shell-string construction, per-frontend retry loops, transport
//! framing, terminal rendering, or storage SQL.

pub mod catalog;
pub mod context;
// ⟨M03⟩ wave 4 (U10): the enrollment stage driver's public surface (ADR-0008 D5).
pub mod enrollment;
pub mod ensure;
// ⟨M04⟩ Joint wave 0: the managed-environment set (ADR-0010 §9 item 1).
pub mod environments;
pub mod error;
pub mod events;
// ⟨M02⟩ U8: launch-binding holder release (`Operations::release_exited_holders`).
pub mod holders;
pub mod ids;
// ⟨M03⟩ wave 4 (U10): the issuer request handling and lifecycle port (ADR-0008 D3, D4).
pub mod issuer;
// ⟨M03⟩ U3: the read-only issuance check (body U3's; fail closed in wave 0).
pub mod issuance_ro;
// ⟨M03⟩ U9: the effective lock behaviour (ADR-0008 D9; §17.15 item 12).
pub mod lock;
// ⟨M03⟩ U0b rows 21 and 24: the signing gates, pending marks, permits and the
// managed effect driver's entry point.
pub mod managed;
pub mod operations;
// ⟨M05⟩ Joint wave 0: policy resolution by context (ADR-0011 §10 item 1).
pub mod policy_context;
pub mod ports;
pub mod reconcile;
// ⟨M06 U5a⟩ The route helper's core (`route connect`, direct and jump legs), failover and the
// `ssh -G` pin verification (ADR-0012 §5.2–§5.5).
pub mod routes;
pub mod setup;
pub mod singleflight;
pub mod timegate;

pub use context::{Attendance, Caller};
pub use error::{OpError, OpResult};
pub use operations::{Operations, OperationsConfig, SetupAdmission};
pub use timegate::{SafeNow, TimeGate};

/// ⟨M03 E9⟩ ADR-0008 §17.43 (ruling I-24): a non-interactive child, one whose standard
/// streams are all redirected or null, never gets a console window. `no_window!(command)`
/// is `command` (a `std::process::Command` or a `tokio::process::Command`), on Windows with
/// `CREATE_NO_WINDOW` set: a console program started by a parent with no console (the
/// runtime runs `DETACHED_PROCESS`) otherwise gets a new console, which Windows hands off to
/// the default terminal (a window or tab on the user's desktop), and the child's start waits
/// on that hand-off. Elsewhere it is `command` itself. Never for a launch that shares the
/// user's terminal (`connect`, `run`, an interactive enrollment step).
#[cfg(windows)]
#[macro_export]
macro_rules! no_window {
    ($command:expr) => {{
        #[allow(unused_imports)]
        use ::std::os::windows::process::CommandExt as _;
        let mut command = $command;
        // CREATE_NO_WINDOW.
        command.creation_flags(0x0800_0000);
        command
    }};
}

/// ⟨M03 E9⟩ [`no_window!`] elsewhere: the command itself.
#[cfg(not(windows))]
#[macro_export]
macro_rules! no_window {
    ($command:expr) => {
        $command
    };
}
