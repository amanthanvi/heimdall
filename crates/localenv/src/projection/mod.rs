//! The projection file transaction (m02-plan U4; ADR-0007 §5).
//!
//! [`LocalProjection`] implements the app port `ProjectionWriter`. Its only state is
//! its configuration ([`ProjectionConfig`]: paths and test hooks). It has no field
//! that caches a plan, a spec or bytes, so a fresh instance in a fresh process
//! executes or recovers any intent (stateless contract, frozen; M2-S05).
//!
//! * [`replace`]: the replacement primitive and the quarantine (frozen);
//! * [`content`]: the materializer (frozen);
//! * [`recovery`]: the total recovery function (frozen);
//! * [`git`]: the Git item under Git's lock, held by K;
//! * [`plan`], [`apply`], [`observe`]: the port's preview, execution and passive
//!   observation;
//! * [`cleaner`]: the `ResourceCleaner` for projection resources.

use std::sync::Arc;

use heimdall_app::ports::{
    HeldStep, PreviewError, ProjectionReceipt, ProjectionReconcile, ProjectionWriter,
    ReconcileError, StageSink,
};
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::setup::PreviewIntent;
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent};

use crate::env::Platform;
use crate::paths::SshPaths;

pub mod apply;
pub mod cleaner;
pub mod content;
pub mod git;
pub mod observe;
pub mod plan;
pub mod recovery;
pub mod replace;

/// The test-only points of the file transaction (env-gated through the test
/// configuration; never compiled into a release build's request paths). Mirrors the
/// M01 `CleanupHook`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplacePoint {
    /// After `stage`.
    AfterStage,
    /// After `validate`.
    AfterValidate,
    /// Before the exchange.
    BeforeExchange,
    /// After the exchange.
    AfterExchange,
    /// After post-validation.
    AfterPostValidate,
    /// Before the item commit.
    BeforeCommit,
    /// After the pre-restore content check, before the restore exchange.
    BeforeRestoreExchange,
    /// After the restore exchange.
    AfterRestoreExchange,
    /// Before a settlement move.
    BeforeSettleMove,
    /// After a settlement move.
    AfterSettleMove,
    /// Before the removal from the quarantine.
    BeforeQuarantineRemove,
    /// Before a receipt of this phase kind (`staged`, `exchanged`, …).
    BeforeReceipt(&'static str),
    /// Before K claims Git's lock.
    BeforeLockClaim,
    /// After K claimed Git's lock.
    AfterLockClaim,
    /// Before the pre-restore content check.
    BeforeRestoreCheck,
    /// After a settlement's identity and digest check.
    AfterSettleCheck,
    /// Before K's `file.settling` (its release).
    BeforeLockRelease,
}

/// A test-only hook run at a [`ReplacePoint`]: a racing writer, or a process abort.
pub trait ReplaceHook: Send + Sync {
    /// Called at `point` for step `step` of the intent.
    fn at(&self, point: ReplacePoint, step: u16);
}

/// The writer's configuration: its only state.
#[derive(Clone)]
pub struct ProjectionConfig {
    /// SSH configuration locations.
    pub paths: SshPaths,
    /// Platform rules.
    pub platform: Platform,
    /// Test-only hook (`None` in production).
    pub hook: Option<Arc<dyn ReplaceHook>>,
}

impl std::fmt::Debug for ProjectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionConfig")
            .field("platform", &self.platform)
            .field("hook", &self.hook.is_some())
            .finish_non_exhaustive()
    }
}

/// The local projection writer.
#[derive(Debug, Clone)]
pub struct LocalProjection {
    config: ProjectionConfig,
}

impl LocalProjection {
    /// A writer over `config`.
    #[must_use]
    pub fn new(config: ProjectionConfig) -> Self {
        Self { config }
    }

    /// Its configuration.
    #[must_use]
    pub fn config(&self) -> &ProjectionConfig {
        &self.config
    }
}

impl ProjectionWriter for LocalProjection {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        plan::preview(&self.config, spec, intent)
    }

    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        apply::apply(&self.config, intent, sink)
    }

    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
        apply::reconcile(&self.config, intent, receipts, sink)
    }

    fn observe(&self, record: &ProjectionRecord, aliases: &[String]) -> Vec<AliasObservation> {
        observe::observe(&self.config, record, aliases)
    }

    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<HeldStep>, ReconcileError> {
        observe::observe_held(&self.config, intent, receipts)
    }
}
