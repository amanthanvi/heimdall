//! Supervisor, deadline scheduler and time guard (spec §13.5, §6.4, §11.5 "one
//! supervisor owns retries for a resource"; R-RT-01, R-RT-06; overview §4.3;
//! ADR-0005 §3.6).
//!
//! * One task per owned resource; retries use `heimdall_app::reconcile::Backoff`
//!   and stop when authority ends (a watchdog never resurrects paused access).
//! * The deadline scheduler sleeps until the earliest persisted absolute deadline
//!   or budget end, re-reads on wake/restart, and calls `Operations::tick`. Sleep
//!   does not suspend deadlines: on wake it re-evaluates immediately against the
//!   continuous clock.
//! * The time guard runs the **shared** gate (`Operations::timegate`) every
//!   `anchor_interval` and after any wake; the gate persists the anchor and the
//!   high-water mark on `Safe`. There is no separate supervisor-private flag
//!   (review F01): every admission, signature and issuance consults the same gate.

use std::time::Duration;

use heimdall_app::Operations;
use heimdall_domain::time::{TimePolicy, TimeStatus};
use tokio_util::sync::CancellationToken;

/// Supervisor tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// How often to run the time guard while idle.
    pub anchor_interval: Duration,
    /// Maximum sleep between scheduler wake-ups even with no deadline (bounded
    /// polling, not a tight loop; spec §15.1 idle budgets).
    pub max_idle_sleep: Duration,
    /// Time policy in force (informational; the gate inside `Operations` holds the
    /// authoritative copy).
    pub time_policy: TimePolicy,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            anchor_interval: Duration::from_secs(60),
            max_idle_sleep: Duration::from_secs(300),
            time_policy: TimePolicy::default(),
        }
    }
}

/// Runs the resource owners, the deadline scheduler and the time guard.
pub struct Supervisor {
    operations: Operations,
    config: SupervisorConfig,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// New supervisor over the shared operations (clock, sync and gate live there).
    #[must_use]
    pub fn new(operations: Operations, config: SupervisorConfig) -> Self {
        Self { operations, config }
    }

    /// Run all loops until cancelled.
    pub async fn run(self, _shutdown: CancellationToken) {
        let _ = (&self.operations, self.config);
        todo!("M01-U8: select over scheduler, time guard, resource owners, shutdown")
    }

    /// One scheduler pass (exposed for virtual-clock tests): expire due grants by
    /// wall bound or continuous budget, return the next wake instant.
    pub async fn scheduler_pass(
        &self,
    ) -> Result<Option<heimdall_contract::Timestamp>, heimdall_app::OpError> {
        todo!("M01-U8: Operations::tick + next due")
    }

    /// One time-guard pass (exposed for tests): run the shared gate (persists on
    /// `Safe`) and return its status.
    pub async fn time_guard_pass(&self) -> Result<TimeStatus, heimdall_app::OpError> {
        todo!("M01-U8: Operations::timegate().check()/peek()")
    }
}
