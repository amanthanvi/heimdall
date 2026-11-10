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
pub mod ensure;
pub mod error;
pub mod events;
// ⟨M02⟩ U8: launch-binding holder release (`Operations::release_exited_holders`).
pub mod holders;
pub mod ids;
// ⟨M03⟩ U3: the read-only issuance check (body U3's; fail closed in wave 0).
pub mod issuance_ro;
// ⟨M03⟩ U9: the effective lock behaviour (ADR-0008 D9; §17.15 item 12).
pub mod lock;
// ⟨M03⟩ U0b rows 21 and 24: the signing gates, pending marks, permits and the
// managed effect driver's entry point.
pub mod managed;
pub mod operations;
pub mod ports;
pub mod reconcile;
pub mod setup;
pub mod singleflight;
pub mod timegate;

pub use context::{Attendance, Caller};
pub use error::{OpError, OpResult};
pub use operations::{Operations, OperationsConfig, SetupAdmission};
pub use timegate::{SafeNow, TimeGate};
