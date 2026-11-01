//! The six primitives as one shared implementation (spec §11.7 "the same
//! application operations used by CLI and TUI"; R-UX-05, R-AP-07), plus the
//! attended-session actions (ADR-0006 §3.1): `attend`, `decide`, `confirm_time`.

use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::request::{
    BindRequest, CancelRequest, ConfirmTimeRequest, DecideRequest, DelegateRequest, EnsureData,
    EnsureRequest, InspectRequest, ObserveRequest, PolicyAction, ReleaseRequest, RevokeData,
    RevokeRequest,
};
use heimdall_domain::time::{Clock, TimePolicy, TimeSync};
use heimdall_store::Store;

use crate::context::{Attendance, Caller};
use crate::ensure::StageHook;
use crate::error::OpResult;
use crate::events::EventPublisher;
use crate::ports::CredentialAdapter;
use crate::singleflight::SingleFlight;
use crate::timegate::TimeGate;

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
    /// Retention of settled operations and idempotency records after settlement
    /// (never below `MIN_RETENTION`; unresolved operations are never purged).
    pub operation_retention: Duration,
    /// Retention of the event log.
    pub event_retention: Duration,
    /// Lifetime of a pending decision record.
    pub decision_lifetime: Duration,
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
            decision_lifetime: heimdall_domain::decision::DEFAULT_DECISION_LIFETIME,
        }
    }
}

/// Construction parameters.
pub struct OperationsConfig {
    /// State store.
    pub store: Arc<Store>,
    /// Clock (system or virtual).
    pub clock: Arc<dyn Clock>,
    /// Platform synchronization report (stub returning `Unknown` until evidenced).
    pub time_sync: Arc<dyn TimeSync>,
    /// Time plausibility policy.
    pub time_policy: TimePolicy,
    /// This runtime's environment.
    pub environment: EnvironmentId,
    /// Credential adapters by mechanism name.
    pub adapters: Vec<Arc<dyn CredentialAdapter>>,
    /// Pipeline fault-injection hook; production passes `NoStageHook`
    /// (plan §6.4; review F09).
    pub stage_hook: Arc<dyn StageHook>,
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
    timegate: TimeGate,
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
    /// Build. Performs restart recovery before returning (spec §13.3, R-RT-07;
    /// review F05/F07): active operations are re-driven from their last stage
    /// receipt; unresolved (`outcome_unknown`) ones are listed for reconciliation
    /// through the recorded adapter identity and effect token; no deadline is
    /// reset, no pause revived, no effect replayed from a hash or stage marker.
    pub async fn start(config: OperationsConfig) -> Result<Self, crate::OpError> {
        let publisher = EventPublisher::new(config.store.clone(), config.environment.clone());
        let timegate = TimeGate::new(
            config.store.clone(),
            config.clock.clone(),
            config.time_sync.clone(),
            config.time_policy,
        );
        let inner = Inner {
            config,
            publisher,
            timegate,
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

    /// The shared time gate (used by the signer and issuer as well).
    #[must_use]
    pub fn timegate(&self) -> &TimeGate {
        &self.inner.timegate
    }

    /// This runtime's environment ID.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.inner.config.environment
    }

    /// Stage hook in force (production: no-op).
    #[must_use]
    pub fn stage_hook(&self) -> &Arc<dyn StageHook> {
        &self.inner.config.stage_hook
    }

    /// Restart recovery (M01-U5). Pure reads plus state-machine transitions;
    /// never re-executes a remote mutation (R-RT-05).
    async fn recover_after_restart(&self) -> Result<(), crate::OpError> {
        let _ = &self.inner.singleflight;
        todo!("M01-U5: re-drive open operations from receipts; list unresolved for reconcile")
    }

    /// Promote a session to attended. Only sessions that declared `interactive`
    /// may attend (ADR-0006 §3.1); others get `INTERACTION_REQUIRED`. Returns the
    /// attendance the session now has.
    pub async fn attend(&self, _caller: &Caller) -> OpResult<Attendance> {
        todo!("M01-U5: may_attend() => Attended(since = now); else INTERACTION_REQUIRED")
    }

    /// `inspect` (read-only, passive; spec §10.2).
    pub async fn inspect(
        &self,
        _caller: &Caller,
        _req: InspectRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-U5/U9: snapshot with provenance; preview = resolve_authority without effects")
    }

    /// `ensure` (plan §4.2 pipeline; `crate::ensure`).
    pub async fn ensure(&self, _caller: &Caller, _req: EnsureRequest) -> OpResult<EnsureData> {
        todo!(
            "M01-U5: idempotency, recovery intent, single-flight, stages+receipts, time gate, recheck, commit"
        )
    }

    /// `bind` (materialize only in M01; launch is the CLI's job after ensure).
    /// Authorized by binding ownership or owner role.
    pub async fn bind(&self, _caller: &Caller, _req: BindRequest) -> OpResult<EnsureData> {
        todo!("M01-U5")
    }

    /// `delegate` (spec §6.7, §8.7). Authorized by parent-binding ownership.
    pub async fn delegate(&self, _caller: &Caller, _req: DelegateRequest) -> OpResult<EnsureData> {
        todo!("M01-U5: child scope ⊆ parent, deadline ≤ parent, cascade registration")
    }

    /// `observe` (spec §11.5; timeout ≠ cancel).
    pub async fn observe(
        &self,
        _caller: &Caller,
        _req: ObserveRequest,
    ) -> OpResult<serde_json::Value> {
        todo!(
            "M01-U5/U9: get/wait; events page or snapshot with cursor; RESYNC_REQUIRED on expired/foreign cursor"
        )
    }

    /// `cancel` (explicit, idempotent; reports possible external effect).
    pub async fn cancel(
        &self,
        _caller: &Caller,
        _req: CancelRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-U5")
    }

    /// `release` (drops a reference; idempotent; never revokes a shared grant;
    /// spec §6.3). Authorized by binding ownership or owner role.
    pub async fn release(
        &self,
        _caller: &Caller,
        _req: ReleaseRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-U5: Txn::release_binding → ReleaseOutcome")
    }

    /// `revoke` (tombstone before acknowledgment; cascade; residual from the
    /// issuance log; spec §6.7).
    pub async fn revoke(&self, _caller: &Caller, _req: RevokeRequest) -> OpResult<RevokeData> {
        todo!("M01-U5")
    }

    /// Owner-channel policy actions (spec §6.1). `pause`/`cutoff` narrow and are
    /// accepted from any owner-role caller; `resume`/`clear_cutoff` widen and need
    /// an attended session: on an unattended one a `WidenPolicy` decision record is
    /// created and `INTERACTION_REQUIRED` returned with its `decision_ref`.
    pub async fn policy(
        &self,
        _caller: &Caller,
        _req: PolicyAction,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-U5: owner role; narrowing bumps generation; widening needs attendance")
    }

    /// Complete a server-issued decision on an attended session (consume-once;
    /// stale generation ⇒ `DECISION_STALE`). Approval applies exactly the recorded
    /// delta and resumes the waiting operation.
    pub async fn decide(
        &self,
        _caller: &Caller,
        _req: DecideRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-U5: attendance check; Txn::complete_decision; apply kind")
    }

    /// Attended confirmation of the current time (ADR-0005 §3.6). Creates and
    /// consumes a `ConfirmTime` decision in one step on an attended session and
    /// records the confirmation through the time gate. Never moves deadlines.
    pub async fn confirm_time(
        &self,
        _caller: &Caller,
        _req: ConfirmTimeRequest,
    ) -> OpResult<serde_json::Value> {
        todo!("M01-U5: attendance check; TimeGate::confirm_attended")
    }

    /// Deadline tick: expire due grants (wall bound or continuous budget), close
    /// owned resources, trim retention (M01-U8 supervisor calls this at persisted
    /// deadlines and after wake/restart).
    pub async fn tick(&self) -> Result<(), crate::OpError> {
        todo!(
            "M01-U5: grants_due + admission per grant anchor → DeadlineReached; resource desired=Absent"
        )
    }
}
