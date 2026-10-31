//! Supervisor, deadline scheduler and time guard (spec §13.5, §6.4, §11.5 "one
//! supervisor owns retries for a resource"; R-RT-01, R-RT-06; overview §4.3).
//!
//! * One task per owned resource; retries use `heimdall_app::reconcile::Backoff`
//!   and stop when authority ends (a watchdog never resurrects paused access).
//! * The deadline scheduler sleeps until the earliest persisted absolute deadline
//!   using the injected clock, re-reads on wake/restart, and calls
//!   `Operations::tick`. Sleep does not suspend deadlines: on wake it re-evaluates
//!   immediately.
//! * The time guard persists a `TimeAnchor` every `anchor_interval` and after any
//!   wake, runs `assess_time`, and flips issuance off on `Uncertain`.

use std::sync::Arc;
use std::time::Duration;

use heimdall_app::Operations;
use heimdall_domain::time::{Clock, TimePolicy, TimeStatus};
use tokio_util::sync::CancellationToken;

/// Supervisor tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// How often to persist a time anchor while idle.
    pub anchor_interval: Duration,
    /// Maximum sleep between scheduler wake-ups even with no deadline (bounded
    /// polling, not a tight loop; spec §15.1 idle budgets).
    pub max_idle_sleep: Duration,
    /// Time policy.
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
    clock: Arc<dyn Clock>,
    config: SupervisorConfig,
    issuance_enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// New supervisor.
    #[must_use]
    pub fn new(operations: Operations, clock: Arc<dyn Clock>, config: SupervisorConfig) -> Self {
        Self {
            operations,
            clock,
            config,
            issuance_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Whether issuance is currently permitted by the time guard.
    #[must_use]
    pub fn issuance_enabled(&self) -> bool {
        self.issuance_enabled
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Run all loops until cancelled.
    pub async fn run(self, _shutdown: CancellationToken) {
        let _ = (
            &self.operations,
            &self.clock,
            self.config,
            &self.issuance_enabled,
        );
        todo!("M01-T05: select over scheduler, time guard, resource owners, shutdown")
    }

    /// One scheduler pass (exposed for virtual-clock tests): expire due grants,
    /// return the next wake instant.
    pub async fn scheduler_pass(
        &self,
    ) -> Result<Option<heimdall_contract::Timestamp>, heimdall_app::OpError> {
        todo!("M01-T05")
    }

    /// One time-guard pass (exposed for tests): persist anchor, assess, update flag.
    pub async fn time_guard_pass(&self) -> Result<TimeStatus, heimdall_app::OpError> {
        todo!("M01-T05")
    }
}
