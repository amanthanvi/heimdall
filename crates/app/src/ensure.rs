//! The ensure-access pipeline (plan §4.2), explicit and interruptible between
//! stages. Each stage journals its completion so restart recovery resumes from the
//! last durable stage without re-running an external step.

use heimdall_contract::ids::{EnvironmentId, OperationId, ProfileId};
use heimdall_domain::scope::Scope;
use serde::{Deserialize, Serialize};

/// Pipeline stages in order (plan §4.2 steps 1–8). The stage name is persisted in
/// `RecoveryMetadata::last_stage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnsureStage {
    /// 1. Authenticate caller/context; parse bounded input; resolve environment.
    Authenticate,
    /// 2. Load policy revision, pause/cutoff, profile snapshot, parent scope.
    LoadAuthority,
    /// 3. Resolve mechanism and required guarantees; classify added authority.
    ResolveMechanism,
    /// 4. Return/coalesce approval, or create/retrieve the idempotent operation.
    Coalesce,
    /// 5. Reconcile owned credential, endpoint, consumer config, route resources.
    Reconcile,
    /// 6. Only authorized probes; record evidence freshness and limits.
    Probe,
    /// 7. Recheck policy generation/deadline before admitting access.
    Recheck,
    /// 8. Commit active binding; persist scheduling; publish bounded events.
    Commit,
}

impl EnsureStage {
    /// Stages in order.
    pub const ALL: [EnsureStage; 8] = [
        EnsureStage::Authenticate,
        EnsureStage::LoadAuthority,
        EnsureStage::ResolveMechanism,
        EnsureStage::Coalesce,
        EnsureStage::Reconcile,
        EnsureStage::Probe,
        EnsureStage::Recheck,
        EnsureStage::Commit,
    ];

    /// Stable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnsureStage::Authenticate => "authenticate",
            EnsureStage::LoadAuthority => "load_authority",
            EnsureStage::ResolveMechanism => "resolve_mechanism",
            EnsureStage::Coalesce => "coalesce",
            EnsureStage::Reconcile => "reconcile",
            EnsureStage::Probe => "probe",
            EnsureStage::Recheck => "recheck",
            EnsureStage::Commit => "commit",
        }
    }

    /// Whether re-entering after an interruption at this stage may have left an
    /// external effect (only `Reconcile` with a remote-mutating adapter can).
    #[must_use]
    pub fn may_have_external_effect(self) -> bool {
        matches!(self, EnsureStage::Reconcile)
    }
}

/// Equivalent work is single-flight (spec §8.2): same environment, same profile
/// snapshot scope, same mechanism class, same deadline instant. Different
/// callers get separate references to the result; unrelated scopes are never
/// merged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EquivalenceKey {
    /// Environment.
    pub environment: EnvironmentId,
    /// Profile.
    pub profile: ProfileId,
    /// Profile revision.
    pub profile_revision: u64,
    /// Resolved scope.
    pub scope: Scope,
    /// Mechanism name.
    pub mechanism: String,
    /// Effective deadline (RFC 3339 UTC).
    pub deadline: String,
}

/// Handle to an in-flight or completed ensure shared across coalesced callers.
#[derive(Debug, Clone)]
pub struct EnsureHandle {
    /// Operation performing the work.
    pub operation_id: OperationId,
}

/// Fault-injection points inside the pipeline (plan §6.4), consulted by the
/// application between stages. Production wiring uses a no-op.
pub trait StageHook: Send + Sync {
    /// Called before `stage` starts; returning `Err` aborts the stage with the
    /// given code (tests simulate interruptions and adapter failures here).
    fn before(&self, stage: EnsureStage) -> Result<(), heimdall_contract::Code>;
    /// Called after `stage` durably completed.
    fn after(&self, stage: EnsureStage) -> Result<(), heimdall_contract::Code>;
}

/// No-op hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStageHook;

impl StageHook for NoStageHook {
    fn before(&self, _stage: EnsureStage) -> Result<(), heimdall_contract::Code> {
        Ok(())
    }
    fn after(&self, _stage: EnsureStage) -> Result<(), heimdall_contract::Code> {
        Ok(())
    }
}
