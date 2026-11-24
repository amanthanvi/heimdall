//! ⟨rev7⟩ Discovery and status reads: `inspect capabilities`, `heimdall status --json` and
//! `heimdall service status --json` (ADR-0013 §11 D1, D9, D12; §8 "Discovery").

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::PreviewView;
use super::operations::OperationCountView;
use crate::Timestamp;
use crate::code::Code;
use crate::envelope::EffectStatus;
use crate::environment::LoginStartView;
use crate::ids::EnvironmentId;
use crate::ipc::PrincipalInfo;
use crate::managed::LockBehavior;
use crate::version::SchemaVersion;

// --- inspect capabilities ----------------------------------------------------------------

/// `inspect capabilities` data: capability and schema discovery (R-AP-08).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesView {
    /// The capability names this runtime's `inspect` lists.
    pub capabilities: Vec<String>,
    /// The names of the public schemas.
    pub schemas: Vec<String>,
    /// The stable code table.
    pub codes: Vec<CodeRowView>,
    /// The schema major the runtime emits.
    pub schema_version: SchemaVersion,
    /// ⟨M03⟩ The current lock behaviour and its disclosure. Omitted when the disclosure
    /// cannot be read (the reader shows "unknown").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<CapabilitiesLockView>,
    /// ⟨M04⟩ The host's login entry. Omitted only when it cannot be observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_start: Option<LoginStartView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// One row of the stable code table (`crate::schema::code_table`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CodeRowView {
    /// The code.
    pub code: Code,
    /// Its CLI exit code.
    pub exit_code: i32,
    /// Whether it is retryable.
    pub retryable: bool,
    /// Its default effect status.
    pub default_effect_status: EffectStatus,
    /// Its default next action's name.
    pub default_next_action: String,
    /// Whether it is a success code.
    pub success: bool,
}

/// ⟨M03⟩ The current lock behaviour (ADR-0008 D9 item 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitiesLockView {
    /// The strictest behaviour over the floor and the applicable policies.
    pub behavior: LockBehavior,
    /// The disclosure's text.
    pub disclosure: String,
    /// When the owner acknowledged the disclosure. Omitted when never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<Timestamp>,
}

// --- status ------------------------------------------------------------------------------

/// `heimdall status --json` data (a running runtime; with none, the answer is a
/// `SERVICE_UNAVAILABLE` error envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusView {
    /// Always true in a success.
    pub running: bool,
    /// The runtime's environment (from its hello).
    pub environment_id: EnvironmentId,
    /// `inspect operations`' `counts`: every stored operation counted by state.
    pub operation_counts: Vec<OperationCountView>,
    /// How many open and unresolved operations the caller may see.
    pub open_operations: u64,
    /// How many decision records `inspect decisions` lists, expired ones included.
    pub pending_decisions: u64,
    /// ⟨M03⟩ The pending chores. Omitted when none is pending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chores: Vec<ChoreView>,
}

/// ⟨M03⟩ A pending chore the status answer names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChoreView {
    /// The chore (`time_confirmation_after_reboot`).
    pub chore: String,
    /// The command that does it (`heimdall time confirm`).
    pub command: String,
    /// What it is for.
    pub message: String,
}

// --- service status ----------------------------------------------------------------------

/// `heimdall service status --json` data. Today it combines the runtime advertisement
/// (`pid`, `version`) with the verified hello (`environment_id`, `capabilities`,
/// `principal`). From revision 7 (D12; ADR-0013 §8 "Discovery") every field comes from,
/// or is checked against, the verified connection: `control_endpoint` is the endpoint
/// connected to; `environment_id`, `protocol`, `capabilities`, `principal` and `version`
/// come from the hello; `pid` is the verified peer's and must equal the advertisement's.
/// No runtime is `SERVICE_UNAVAILABLE`/`runtime_not_running`; a mismatch is
/// `SERVICE_UNAVAILABLE`/`endpoint_untrusted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceStatusView {
    /// Always true in a success.
    pub running: bool,
    /// The runtime's process ID (today: the advertisement's; revision 7: the verified
    /// peer's, equal to the advertisement's).
    pub pid: u32,
    /// The runtime's build version (today: the advertisement's; revision 7: the hello's
    /// `server.version`).
    pub version: String,
    /// The runtime's environment (from its hello).
    pub environment_id: EnvironmentId,
    /// The capabilities in effect on the session (from its hello).
    pub capabilities: BTreeSet<String>,
    /// How the runtime authenticated this client (from its hello).
    pub principal: PrincipalInfo,
    /// ⟨M04⟩ The host's read-only time-synchronization observation, a diagnostic only.
    pub time_sync_observation: TimeSyncObservationView,
    /// **Revision 7, not emitted yet** (D12): the control endpoint connected to and
    /// verified. Omitted until emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_endpoint: Option<String>,
    /// **Revision 7, not emitted yet** (D12): the protocol version in effect (from the
    /// hello). Omitted until emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u16>,
}

/// ⟨M04⟩ The host's read-only synchronization observation (ADR-0010 §9 item 6). The time
/// gate never reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimeSyncObservationView {
    /// The interface read: `adjtimex`, `ntp_adjtime` or `none`.
    pub interface: String,
    /// What it reported.
    pub reading: TimeSyncReading,
    /// Always false: the time gate does not use it.
    pub used_by_time_gate: bool,
    /// The kernel's maximum error estimate, in microseconds. Present exactly for
    /// `synchronized` and `not_synchronized`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_error_us: Option<i64>,
    /// Whether `STA_UNSYNC` was set (ignored by the rule). Present exactly for
    /// `synchronized` and `not_synchronized`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sta_unsync: Option<bool>,
    /// What went wrong. Present exactly for `unavailable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
}

/// A time-synchronization reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TimeSyncReading {
    /// The rule reads "synchronized".
    Synchronized,
    /// The rule reads "not synchronized".
    NotSynchronized,
    /// The interface failed or returned a value no rule can read.
    Unavailable,
    /// This platform has no documented read-only interface.
    NoInterface,
}
