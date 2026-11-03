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

use std::path::PathBuf;
use std::sync::Arc;

use heimdall_app::ports::{
    HeldStep, PreviewError, ProjectionReceipt, ProjectionReconcile, ProjectionWriter,
    ReconcileError, StageSink,
};
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::ids::IdentityId;
use heimdall_contract::setup::PreviewIntent;
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent};

use crate::clients::ClientInventory;
use crate::env::{Env, Platform};
use crate::local_query::LocalQueries;
use crate::paths::SshPaths;
use crate::sys::IdentitySource;

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
    /// Called at `point` for step `step` of the intent. The cleaner calls it with
    /// [`CLEANER_STEP`].
    fn at(&self, point: ReplacePoint, step: u16);
}

/// The `step` the cleaner passes to [`ReplaceHook::at`] (it has no intent step).
pub const CLEANER_STEP: u16 = u16::MAX;

/// Where the preview finds the OpenSSH public key of an adopted identity (the
/// catalog's `IdentityRecord.public_key`). Used by `preview` only: `apply` and
/// `reconcile` read every byte from the intent (stateless contract).
pub trait PublicKeySource: Send + Sync {
    /// The one-line public key of `identity`, when known.
    fn public_key(&self, identity: &IdentityId) -> Option<String>;
}

/// Test-only switches of the writer (the defaults in production).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProjectionTestConfig {
    /// Offer the Git item whatever Git's default SSH is. ADR-0007 §5.6 makes the item
    /// applicable only where Git's default is its bundled MSYS client (Windows); the
    /// Unix harness sets this so the Git transaction runs in `check.sh`.
    pub git_item_any_default: bool,
    /// The identity source of every directory handle the writer opens: `Native` in
    /// production; `WithoutBirth` is m02-plan U4's test-only source (Unix identities
    /// without a birth time, ADR-0007 F25, QR15).
    pub identity: IdentitySource,
}

/// The writer's configuration: its only state.
///
/// Besides the SSH paths and the test hook, the preview needs Heimdall's own
/// configuration directory (P is `<config_dir>/ssh_config`, key files live under
/// `<config_dir>/keys/`, P_git is `<config_dir>/gitconfig`; ADR-0007 §2, §5.6), the
/// environment snapshot and client inventory for the Git item, and the public keys of
/// adopted identities. `apply` and `reconcile` use only `hook` and `platform`: every
/// path and byte they touch comes from the intent.
#[derive(Clone)]
pub struct ProjectionConfig {
    /// SSH configuration locations.
    pub paths: SshPaths,
    /// Platform rules.
    pub platform: Platform,
    /// Test-only hook (`None` in production).
    pub hook: Option<Arc<dyn ReplaceHook>>,
    /// Heimdall's configuration directory (M01 `Paths`).
    pub config_dir: PathBuf,
    /// The environment snapshot (Git's global-file resolution and queries).
    pub env: Env,
    /// The client inventory (BOM/CRLF acceptance, the verified `ssh` and `git`).
    pub clients: ClientInventory,
    /// Whether local queries may run (the Git item's observation).
    pub queries: LocalQueries,
    /// Public keys of adopted identities (preview only).
    pub keys: Option<Arc<dyn PublicKeySource>>,
    /// Test-only switches.
    pub test: ProjectionTestConfig,
}

impl ProjectionConfig {
    /// A configuration with no hook, an empty environment and inventory, local queries
    /// off and no key source.
    #[must_use]
    pub fn new(paths: SshPaths, platform: Platform, config_dir: PathBuf) -> Self {
        Self {
            paths,
            platform,
            hook: None,
            config_dir,
            env: Env::default(),
            clients: ClientInventory::default(),
            queries: LocalQueries::Disabled,
            keys: None,
            test: ProjectionTestConfig::default(),
        }
    }

    /// P's path.
    #[must_use]
    pub fn managed_ssh_path(&self) -> PathBuf {
        self.config_dir.join("ssh_config")
    }

    /// P_git's path.
    #[must_use]
    pub fn managed_git_path(&self) -> PathBuf {
        self.config_dir.join("gitconfig")
    }

    /// Run the test hook, when one is configured.
    pub(crate) fn fire(&self, point: ReplacePoint, step: u16) {
        if let Some(hook) = &self.hook {
            hook.at(point, step);
        }
    }
}

impl std::fmt::Debug for ProjectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionConfig")
            .field("platform", &self.platform)
            .field("hook", &self.hook.is_some())
            .field("keys", &self.keys.is_some())
            .field("queries", &self.queries)
            .field("test", &self.test)
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
