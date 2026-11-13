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
//!   observation (the writer also takes the §5.5 snapshot of an original user file
//!   before its first edit: [`apply::snapshot_original`]);
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

/// ⟨M03⟩ What P renders for a pair whose preference is `managed_certificate` (ADR-0008
/// D10 item 1; m03-plan U8): the **environment** endpoint and the slot's files, plus
/// the slot's stable mux path once owned masters are enabled and applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSectionSpec {
    /// The environment endpoint: a Unix socket path (`<runtime_dir>/signing.sock`), or
    /// the stable Windows pipe `\\.\pipe\heimdall-<installation token>-signing`
    /// (reading R6), which P writes `//./pipe/…`.
    pub environment_endpoint: heimdall_contract::provider::EndpointRef,
    /// The slot's public key file ([`content::managed_slot_paths`]).
    pub key_pub: PathBuf,
    /// The slot's certificate file ([`content::managed_slot_paths`]).
    pub cert_pub: PathBuf,
    /// `None`: `ControlPath none`. `Some`: the slot's stable mux path
    /// ([`content::managed_mux_path`]), only once owned masters are enabled and applied
    /// (ADR-0008 D8 item 3). ⟨§17.22 item 14⟩ Enabled is a **pair-level rendering rule**:
    /// every current standing policy covering the pair has `owned_masters` (no applicable
    /// policy: disabled); each master's own grant policy is still checked when it starts
    /// (the runtime's `pair_masters_enabled`).
    pub control_path: Option<PathBuf>,
}

/// ⟨M03⟩ Which pairs prefer `managed_certificate`, and what their sections render
/// (preview only, like [`PublicKeySource`]). The runtime implements it over the store's
/// `pair_preferences` and the endpoint names (U10's wiring); without a source every
/// alias is existing access, exactly as in M02.
pub trait ManagedPairSource: Send + Sync {
    /// The managed section of `alias`'s pair when its preference is
    /// `managed_certificate` (whatever its projection status: the apply is what renders
    /// it), `Ok(None)` for existing access.
    ///
    /// # Errors
    /// The preference or the endpoint cannot be read: the preview is refused
    /// (`PreviewError::Unavailable`), never rendered as existing access.
    fn managed_section(
        &self,
        alias: &heimdall_domain::projection::ManagedAliasSpec,
    ) -> Result<Option<ManagedSectionSpec>, String>;

    /// ⟨ADR-0008 §17.22 item 16 (R2F-Q2)⟩ Whether `alias`'s pair has a **stored**
    /// preference (either mechanism) whose projection is still `pending`. An apply whose
    /// rendering of P is unchanged then still writes and commits P (same bytes, a new
    /// generation), so the SSH item's commit records the preference metadata: a toggle
    /// back to an already-rendered configuration does not stay `pending`. A pair without
    /// a stored preference (every M02 pair) is never pending, so an M02 apply that changes
    /// nothing still plans nothing. The default (a source that stores no preferences):
    /// `false`.
    ///
    /// # Errors
    /// The preference cannot be read: the preview is refused.
    fn projection_pending(
        &self,
        alias: &heimdall_domain::projection::ManagedAliasSpec,
    ) -> Result<bool, String> {
        let _ = alias;
        Ok(false)
    }
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
    /// ⟨M03⟩ The managed sections' identity form, overriding
    /// `heimdall_sshconf::render::ManagedIdentityForm::select` (`None` in production;
    /// the INT-Q10 observation tests render each form).
    pub managed_identity_form: Option<heimdall_sshconf::render::ManagedIdentityForm>,
    /// The bound on each local query of the Git item's observation, overriding
    /// `local_query::LOCAL_QUERY_TIMEOUT` (`None` in production; M03 wave 5 r4 F1: the
    /// slow-Git regression runs it at the earlier 2 s and at the constant).
    pub local_query_timeout: Option<std::time::Duration>,
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
    /// Heimdall's state directory (M01 `Paths`). The writer copies an original user
    /// file to `<state_dir>/backups` before its first edit of it (ADR-0007 §5.5,
    /// §12.32 item 2: the snapshot is the writer's, so every caller is covered). `None`
    /// takes no snapshot: a configuration of the file transaction's own tests. Every
    /// wiring of a real runtime sets it ([`ProjectionConfig::with_state_dir`]).
    pub state_dir: Option<PathBuf>,
    /// The environment snapshot (Git's global-file resolution and queries).
    pub env: Env,
    /// The client inventory (BOM/CRLF acceptance, the verified `ssh` and `git`).
    pub clients: ClientInventory,
    /// Whether local queries may run (the Git item's observation).
    pub queries: LocalQueries,
    /// Public keys of adopted identities (preview only).
    pub keys: Option<Arc<dyn PublicKeySource>>,
    /// ⟨M03⟩ The pairs that prefer `managed_certificate` and their sections (preview
    /// only; `None`: every alias is existing access, as in M02).
    pub managed: Option<Arc<dyn ManagedPairSource>>,
    /// Test-only switches.
    pub test: ProjectionTestConfig,
    /// Test-only diagnostics (`None` in production): called with every Git observation
    /// a preview plans from, so a test that sees two digests differ can name what the
    /// observation could not read (its `unreadable` entries, never a value).
    pub git_observed: Option<GitObserved>,
}

/// A test's view of the Git observations a preview plans from
/// ([`ProjectionConfig::git_observed`]).
pub type GitObserved = Arc<dyn Fn(&crate::git::GitGlobalObservation) + Send + Sync>;

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
            state_dir: None,
            env: Env::default(),
            clients: ClientInventory::default(),
            queries: LocalQueries::Disabled,
            keys: None,
            managed: None,
            test: ProjectionTestConfig::default(),
            git_observed: None,
        }
    }

    /// This configuration with Heimdall's state directory, where the original files'
    /// snapshots go (`<state_dir>/backups`; ADR-0007 §12.32 item 2).
    #[must_use]
    pub fn with_state_dir(mut self, state_dir: PathBuf) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    /// The directory of the original files' snapshots (`<state_dir>/backups`), when a
    /// state directory is configured.
    #[must_use]
    pub fn backups_dir(&self) -> Option<PathBuf> {
        self.state_dir.as_ref().map(|d| d.join("backups"))
    }

    /// P's path.
    #[must_use]
    pub fn managed_ssh_path(&self) -> PathBuf {
        self.config_dir.join("ssh_config")
    }

    /// P_git's path.
    #[must_use]
    pub fn managed_git_path(&self) -> PathBuf {
        self.config_dir.join(crate::git::MANAGED_GIT_FILE)
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
            .field("snapshots", &self.state_dir.is_some())
            .field("hook", &self.hook.is_some())
            .field("keys", &self.keys.is_some())
            .field("managed", &self.managed.is_some())
            .field("queries", &self.queries)
            .field("test", &self.test)
            .field("git_observed", &self.git_observed.is_some())
            .finish_non_exhaustive()
    }
}

/// The local projection writer.
#[derive(Debug, Clone)]
pub struct LocalProjection {
    config: ProjectionConfig,
}

/// ⟨M03⟩ ADR-0007 §12.34 item 6 (deferred to M03 hardening, §13; m02-exit §7): a
/// writer of the owner's files built without a state directory, which could not copy an
/// original user file before its first edit (§5.5, §12.32 item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a writing projection configuration needs a state directory (the original's snapshot)")]
pub struct StateDirMissing;

impl LocalProjection {
    /// A writer over `config`, as M02 builds it. A configuration without `state_dir`
    /// takes no snapshot: that is the file transaction's own tests' configuration, which
    /// the M02 suites keep using unchanged. **Every writer a runtime wires is built with
    /// [`LocalProjection::writing`]** (U8-Q1).
    #[must_use]
    pub fn new(config: ProjectionConfig) -> Self {
        Self { config }
    }

    /// ⟨M03⟩ The writer a runtime wires (ADR-0007 §12.34 item 6): refused without a
    /// state directory, so no edit of the owner's files can ever run without the
    /// original's snapshot. The source guard (`integration_projection_state_dir_guard`)
    /// keeps checking the constructors; this is the refusal behind it.
    ///
    /// # Errors
    /// [`StateDirMissing`] when `config.state_dir` is `None`.
    pub fn writing(config: ProjectionConfig) -> Result<Self, StateDirMissing> {
        if config.state_dir.is_none() {
            return Err(StateDirMissing);
        }
        Ok(Self { config })
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
