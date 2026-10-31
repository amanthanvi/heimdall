//! The six primitives as one shared implementation (spec §11.7 "the same
//! application operations used by CLI and TUI"; R-UX-05, R-AP-07).

use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::request::{
    BindRequest, CancelRequest, DelegateRequest, EnsureData, EnsureRequest, InspectRequest,
    ObserveRequest, PolicyAction, ReleaseRequest, RevokeData, RevokeRequest,
};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::time::{Clock, TimePolicy};
use heimdall_store::Store;

use crate::error::OpResult;
use crate::events::EventPublisher;
use crate::ports::{CredentialAdapter, DecisionChannel};
use crate::singleflight::SingleFlight;

/// Bounds the application enforces regardless of caller (spec §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrent operations in `running`.
    pub max_running_operations: usize,
    /// Maximum concurrent adapter prepare/probe calls.
    pub max_concurrent_adapter_calls: usize,
    /// Maximum events returned by one `observe` page.
    pub max_event_page: u32,
    /// Maximum bounded wait a caller may request.
    pub max_wait: Duration,
    /// Retention of terminal operations and idempotency records.
    pub operation_retention: Duration,
    /// Retention of the event log.
    pub event_retention: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_running_operations: 32,
            max_concurrent_adapter_calls: 4,
            max_event_page: 500,
            max_wait: Duration::from_secs(300),
            operation_retention: heimdall_domain::idempotency::DEFAULT_RETENTION,
            event_retention: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// Construction parameters.
pub struct OperationsConfig {
    /// State store.
    pub store: Arc<Store>,
    /// Clock (system or virtual).
    pub clock: Arc<dyn Clock>,
    /// Time plausibility policy.
    pub time_policy: TimePolicy,
    /// This runtime's environment.
    pub environment: EnvironmentId,
    /// Credential adapters by mechanism name.
    pub adapters: Vec<Arc<dyn CredentialAdapter>>,
    /// Owner decision channel.
    pub decisions: Arc<dyn DecisionChannel>,
    /// Limits.
    pub limits: Limits,
    /// Default maximum window for new work (spec P04).
    pub default_window: Duration,
}

impl std::fmt::Debug for OperationsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationsConfig")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// The application operations. Cheap to clone (`Arc` inside); one instance per
/// runtime.
#[derive(Clone)]
pub struct Operations {
    inner: Arc<Inner>,
}

struct Inner {
    config: OperationsConfig,
    publisher: EventPublisher,
    singleflight: SingleFlight<crate::ensure::EquivalenceKey, crate::ensure::EnsureHandle>,
}

impl std::fmt::Debug for Operations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operations")
            .field("environment", &self.inner.config.environment)
            .finish_non_exhaustive()
    }
}

impl Operations {
    /// Build. Performs restart recovery of open operations (spec §13.3, R-RT-07)
    /// before returning: open operations are re-driven or marked according to
    /// their last durable stage; no deadline is reset, no pause revived.
    pub async fn start(config: OperationsConfig) -> Result<Self, crate::OpError> {
        let publisher = EventPublisher::new(config.store.clone(), config.environment.clone());
        let inner = Inner {
            config,
            publisher,
            singleflight: SingleFlight::new(),
        };
        let ops = Self {
            inner: Arc::new(inner),
        };
        ops.recover_after_restart().await?;
        Ok(ops)
    }

    /// Limits in effect.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.inner.config.limits
    }

    /// Event publisher (used by the IPC server for subscriptions).
    #[must_use]
    pub fn events(&self) -> &EventPublisher {
        &self.inner.publisher
    }

    /// This runtime's environment ID.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.inner.config.environment
    }

    /// Restart recovery (M01-T05). Pure reads plus state-machine transitions;
    /// never re-executes a remote mutation (R-RT-05).
    async fn recover_after_restart(&self) -> Result<(), crate::OpError> {
        let _ = &self.inner.singleflight;
        todo!("M01-T05: re-drive open operations from their last durable stage")
    }

    /// `inspect` (read-only, passive; spec §10.2).
    pub async fn inspect(
        &self,
        _caller: &CallerContext,
        _req: InspectRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-T06: snapshot with provenance; preview = resolve_authority without effects")
    }

    /// `ensure` (plan §4.2 pipeline; `crate::ensure`).
    pub async fn ensure(
        &self,
        _caller: &CallerContext,
        _req: EnsureRequest,
    ) -> OpResult<EnsureData> {
        todo!("M01-T05/T06: idempotency, single-flight, pipeline stages, recheck, commit")
    }

    /// `bind` (materialize only in M01; launch is the CLI's job after ensure).
    pub async fn bind(&self, _caller: &CallerContext, _req: BindRequest) -> OpResult<EnsureData> {
        todo!("M01-T06: attach reference, return pinned integration")
    }

    /// `delegate` (spec §6.7, §8.7).
    pub async fn delegate(
        &self,
        _caller: &CallerContext,
        _req: DelegateRequest,
    ) -> OpResult<EnsureData> {
        todo!("M01-T05: child scope ⊆ parent, deadline ≤ parent, cascade registration")
    }

    /// `observe` (spec §11.5; timeout ≠ cancel).
    pub async fn observe(
        &self,
        _caller: &CallerContext,
        _req: ObserveRequest,
    ) -> OpResult<serde_json::Value> {
        todo!(
            "M01-T06: get/wait; events page or snapshot with cursor; RESYNC_REQUIRED on expired/foreign cursor"
        )
    }

    /// `cancel` (explicit, idempotent; reports possible external effect).
    pub async fn cancel(
        &self,
        _caller: &CallerContext,
        _req: CancelRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-T05")
    }

    /// `release` (drops a reference; never revokes a shared grant; spec §6.3).
    pub async fn release(
        &self,
        _caller: &CallerContext,
        _req: ReleaseRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-T05")
    }

    /// `revoke` (tombstone before acknowledgment; cascade; spec §6.7).
    pub async fn revoke(
        &self,
        _caller: &CallerContext,
        _req: RevokeRequest,
    ) -> OpResult<RevokeData> {
        todo!("M01-T05")
    }

    /// Owner-channel policy actions (pause/resume/cutoff/clear; spec §6.1).
    pub async fn policy(
        &self,
        _caller: &CallerContext,
        _req: PolicyAction,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-T05: owner role required; bump generation on pause/cutoff")
    }

    /// Deadline tick: expire due grants, close owned resources (M01-T05 supervisor
    /// calls this at persisted absolute deadlines and after wake/restart).
    pub async fn tick(&self) -> Result<(), crate::OpError> {
        todo!("M01-T05: grants_due -> DeadlineReached transitions; resource desired=Absent")
    }
}
