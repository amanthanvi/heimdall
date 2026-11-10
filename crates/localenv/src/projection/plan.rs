//! The read-only preview (m02-plan U4; ADR-0007 §5.1).
//!
//! The plan carries each step's `StepContent`, built through `Rendered`; staged
//! names are random and fixed in the plan. A plan beyond the content bounds is
//! refused (`PreviewError::TooLarge`, `projection_too_large`). The diffs are whole: the
//! preview never cuts one (ADR-0007 §12.32 item 5); the application refuses a plan whose
//! full diff exceeds `MAX_DIFF_BYTES` (`plan_too_large`). The one exception is the removal
//! of a file of Heimdall's own (P, P_git, a key file), which the diff shows as a single
//! summary line ([`OwnRemoval`]: name, line count, SHA-256; ADR-0007 §12.34 item 7), so
//! that a rollback is never refused for the size of a file the owner already approved.
//! Changes to the files the owner owns are always whole.
//!
//! **Reproducible digests** (ADR-0007 §12.18 item 3). The marker of a block a plan
//! inserts (B, B_git) is derived from the proposed generation, the target file's role
//! and the canonical digest of the plan inputs (the spec and the base of every file
//! the preview read), never drawn. Staged names, displaced names and K's holder line
//! are random but are not part of the plan digest. So two previews of unchanged inputs
//! give the same plan digest, and §5.4 step 1's recomputation reproduces an approved
//! preview; any change of input changes it.
//!
//! **What the preview builds** (ADR-0007 §5.4, §5.5, §5.6):
//!
//! * `apply`, first adoption (no block in the user file): the key files and P
//!   (inactive), then the user-file splice that inserts B (the commit step; a create
//!   when the user file is absent);
//! * `apply`, update (one intact block, first): the changed key files and P (the
//!   commit step), then a *check-only* user step whose target equals its base (a
//!   splice that removes and re-inserts the recorded block), so the transaction check
//!   re-reads the user file and nothing writes it; an unchanged projection plans no
//!   file;
//! * `apply` with the Git item: P_git, then the lock holder K and the B_git splice
//!   (the Git commit step) at the top of the first-read global file. B_git is looked for
//!   first where the Git item's record says it was written (ADR-0007 §12.39 item 3), so
//!   that an XDG file created after the apply does not hide it; only P_git changes when
//!   B_git is there already;
//! * `rollback`: the splice that removes B (the commit step), then P and the key files
//!   as target-absent steps for the cleaner, each with its recorded digest as base (a
//!   P whose content is no longer that is kept as `ssh_config.hm-conflict-<gen>` once
//!   the rollback committed, §5.5); for Git, K, the B_git removal and P_git. The Git
//!   selection a rollback changes is Heimdall's value to the user's when a user value
//!   sits before B_git in Git's read order (ADR-0007 §12.39 item 4), which needs a
//!   decision;
//! * `repair rerender`: as `apply` over the recorded items;
//! * `repair remove_duplicate_markers`: keep the first block that is Heimdall's exact B
//!   before the first section, remove one other exact B (one splice per intent);
//! * `repair move_include_to_top`: insert a fresh B at the top (one splice per intent);
//!   the conditional block left behind is removed by `remove_duplicate_markers`;
//! * `repair manual_mode`: P and the key files only, with the exact block shown.
//!
//! B names P by its **absolute** path, never `~`, so it loads P whatever `$HOME` is
//! (ADR-0007 §12.17 item 9). A P path no literal Include can name (a glob
//! metacharacter, §12.16 item 3) is manual mode before any edit.
//!
//! A file that fails the §5.3 step-1/2 checks (a symlink or reparse point, a hard
//! link, a foreign owner, a quarantine that does not validate), and a user file with a
//! BOM or CRLF on a client not known to accept it (`ClientInventory::accepts_encoding`),
//! make the plan manual: no user-file step, the reason listed, P (or the last key
//! file) committed. Conflicts (a duplicate or edited marker, a conditional block) are
//! findings, and the plan then changes no file.
//!
//! **Consent** (ADR-0007 §5.2, §12.17 item 8). The affected items are the aliases whose
//! rendered section in effect changes (every alias P renders, for a rollback or a block
//! repair) and Git's SSH selection when B_git is added or removed. For each, the
//! behaviour now, after the plan and on restore is evaluated statically (U2's
//! evaluator over the planned bytes; nothing executes) and classified by
//! `sshconf::consent` against the stored consent, which counts only for an item the
//! projection record still manages. A plan that needs no decision gets none and records
//! no consent; otherwise `ProjectionPlan.consent` holds the managed and restore states
//! (with a placeholder decision that `apply` replaces by the intent's approval), and
//! the summary carries the restore column. The behaviour digests are part of the plan
//! digest.
//!
//! **Wave 3b (W3b-consent; ADR-0007 §12.21, §12.22 items 2 and 8).**
//!
//! * *Manual mode still classifies consent* (V01). Whether the user file may be edited
//!   and whether it activates P are separate facts. A manual plan reads the user
//!   configuration through the read-only source, takes the affected aliases from
//!   every P change and lets the evaluation say whether P is in effect; a
//!   configuration it cannot read makes every affected state undetermined.
//! * *Every invocation profile* (V02). Each state is the alias's behaviour under
//!   `Shell`, `Exec(None)` and `Subsystem("sftp")`, digested with tag
//!   `heimdall.behavior.v3`, determined only when every profile is.
//! * *An empty item record is no item*, for SSH and Git alike: a rerender plans Git
//!   only for a live Git record, and stored consent counts only for a live one.
//! * *A managed alias without a key file* is refused (`PreviewError::Unavailable`),
//!   and `include_target_glob` is listed as its own manual reason, besides
//!   `unmanageable_file`.
//!
//! **Wave 3c (W3c-run; ADR-0007 §12.24 item 6).** A first adoption always needs a
//! decision, manual mode included: an alias the plan adds to P that no live record
//! consents to gets `new_state` even when its evaluated states are equal (a manual plan
//! whose configuration does not include P yet), because the owner's own Include then
//! activates P without another Heimdall decision.
//!
//! **Wave 3d (W3d-select; ADR-0007 §12.25 item 2, §12.26 item 5).**
//!
//! * *A changed managed alias always needs a decision, in manual mode too*, P active or
//!   not: a manual plan whose alias section in P changes gets `new_state` when the
//!   classification gave it none (P not yet included evaluates the same state before
//!   and after, and the owner's own Include later activates the change without another
//!   decision).
//! * *The local account* for `%u` and `Match localuser` is the account database's,
//!   never `USER` or `USERNAME`; when it cannot be established, a state whose
//!   configuration reads it is undetermined.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use heimdall_app::ports::PreviewError;
use heimdall_contract::Code;
use heimdall_contract::doctor::{
    Finding, FindingSeverity, GitScope, GitSshClassification, GitSshSelection, GitSshSource,
    finding,
};
use heimdall_contract::envelope::{NextAction, ResourceRef};
use heimdall_contract::ids::DecisionId;
use heimdall_contract::provider::{EndpointKind, ProbeLevel};
use heimdall_contract::setup::{
    AliasKind, AliasPreview, BehaviorSummary, ConflictKind, ConsentNeed, ConsentReason,
    ConsentReasonKind, FileChange, GitApplicability, GitConfigChange, GitGlobalFile, PlanDigest,
    PreviewIntent, ProjectionFileRole, ProjectionItem, RepairResolution, SetupMode, SetupPlan,
    manual_reason,
};
use heimdall_domain::projection::{
    Base, BehaviorState, ConsentRecord, ConsentedStates, FileRole, FileStep, ItemId, ItemRecord,
    ItemRestore, ManagedAliasSpec, ProjectionPlan, ProjectionSpec, ProjectionSummary, Rendered,
    Sha256Hex, StepContent, StepContentView, SummaryIntent, Target, bounds,
};
use heimdall_sshconf::consent;
use heimdall_sshconf::edit::{self, BlockPosition, EditRefusal, FoundBlock, IncludeBlock};
use heimdall_sshconf::eval::{Invocation, OpenSshVersion, Query};
use heimdall_sshconf::gitedit;
use heimdall_sshconf::include::{ConfigSet, ConfigSource, Roots, SourceBytes, SourceError};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::relevant::consent_behavior_state;
use heimdall_sshconf::render::{
    self, AliasName, HostName, ManagedAlias, ManagedIdentityForm, MarkerId, Newline, PathStyle,
    RenderPath, Section,
};
use sha2::{Digest as _, Sha256};

use super::apply::random_hex;
use super::git::{GlobalFileCheck, check_global_file, lock_holder};
use super::replace::{self, DirHandle, Quarantine, ReplaceRefusal};
use super::{ManagedSectionSpec, ProjectionConfig};
use crate::clients::ClientKind;
use crate::fs::BoundedSource;
use crate::git::{DefaultGitSsh, observe_global, observe_global_for, origin_of, winning_origin};
use crate::materialize::{PublicKeyLine, public_key_bytes};

/// Bytes read of one file the preview inspects (the §5.3 bound).
const READ_MAX: usize = 1 << 20;

/// The quarantine directory's name (ADR-0007 §5.3).
const QUARANTINE: &str = ".hm-quarantine";

/// Build the plan for `intent` over `spec`, reading the files as they are.
///
/// # Errors
/// [`PreviewError`].
pub fn preview(
    config: &ProjectionConfig,
    spec: &ProjectionSpec,
    intent: &PreviewIntent,
) -> Result<ProjectionPlan, PreviewError> {
    intent
        .validate()
        .map_err(|e| PreviewError::Unavailable(e.to_string()))?;
    let generation = spec
        .record
        .as_ref()
        .and_then(|r| r.items.values().map(|i| i.generation).max())
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| PreviewError::Unavailable("generation overflow".to_owned()))?;
    let mut b = Builder::new(config, spec, generation);
    match intent {
        PreviewIntent::Apply { include_git } => {
            b.plan_ssh_apply()?;
            if *include_git {
                b.plan_git_apply()?;
            }
        }
        PreviewIntent::Rollback {
            keep_key_files,
            items,
        } => {
            if items.contains(&ProjectionItem::Ssh) {
                b.plan_ssh_rollback(*keep_key_files)?;
            }
            if items.contains(&ProjectionItem::Git) {
                b.plan_git_rollback()?;
            }
        }
        PreviewIntent::Repair {
            resolution: RepairResolution::Rerender,
            ..
        } => {
            b.plan_ssh_apply()?;
            // Only a Git item the record still manages is re-rendered: a rolled-back
            // item is an empty record, which is no item (ADR-0007 §12.22 item 2).
            if live_item(spec, ProjectionItem::Git).is_some() {
                b.plan_git_apply()?;
            }
        }
        PreviewIntent::Repair {
            resolution: RepairResolution::RemoveDuplicateMarkers,
            ..
        } => b.plan_remove_duplicate()?,
        PreviewIntent::Repair {
            resolution: RepairResolution::MoveIncludeToTop,
            ..
        } => b.plan_move_to_top()?,
        PreviewIntent::Repair {
            resolution: RepairResolution::ManualMode,
            conflict,
            ..
        } => {
            b.manual_for = Some(*conflict);
            b.plan_ssh_apply()?;
        }
        // `retry_held` and `keep_held` are built by the setup driver from
        // `observe_held` (ADR-0007 §5.7 "Repair path"), not rendered here.
        PreviewIntent::Repair { resolution, .. } => {
            return Err(PreviewError::Unavailable(format!(
                "repair {resolution:?} is not previewed by this writer"
            )));
        }
        _ => {
            return Err(PreviewError::Unavailable(
                "unknown preview intent".to_owned(),
            ));
        }
    }
    b.finish(intent.clone())
}

struct Builder<'a> {
    config: &'a ProjectionConfig,
    spec: &'a ProjectionSpec,
    generation: u64,
    style: PathStyle,
    steps: Vec<FileStep>,
    changes: Vec<FileChange>,
    manual: Vec<String>,
    findings: Vec<Finding>,
    git: Option<GitConfigChange>,
    added: Vec<String>,
    removed: Vec<String>,
    /// ADR-0007 §5.2 inputs: the user file as read, and its planned bytes when the
    /// plan changes it.
    user_now: Option<Vec<u8>>,
    user_after: Option<Vec<u8>>,
    /// P as it is and as planned (`None`: unchanged).
    p_now: Option<Vec<u8>>,
    p_after: Option<Vec<u8>>,
    /// A rollback or a block repair: every alias P renders is affected.
    ssh_all_affected: bool,
    /// A block repair: the aliases stay managed (P is unchanged).
    ssh_repair: bool,
    /// The SSH plan is manual: it writes P and the key files and never plans the user
    /// file. Whether the user configuration activates P is a separate fact, which the
    /// evaluation establishes, so every P change is affected (ADR-0007 §12.21 item 1).
    ssh_manual: bool,
    /// The read-only source could not read the user configuration for a manual plan:
    /// whether it activates P is unknown, so every affected state is undetermined
    /// (ADR-0007 §12.21 item 1).
    user_unreadable: bool,
    /// The `manual_mode` repair, with the conflict it resolves.
    manual_for: Option<ConflictKind>,
    /// ADR-0007 §12.25 item 2 (T02): the local account for `%u` and `Match localuser`,
    /// from the account database (`doctor::local_account`); `None` when it cannot be
    /// established, so a state whose configuration reads it is undetermined.
    account: Option<String>,
    /// The Git selection now and after the plan, when the plan changes it.
    git_selection: Option<(GitSshSelection, GitSshSelection)>,
    /// ADR-0007 §12.18 item 3: every file the preview read so far, with the base it
    /// found (absent, or the digest of its bytes). A derived marker binds them.
    reads: BTreeMap<(FileRole, PathBuf), Base>,
}

impl<'a> Builder<'a> {
    fn new(config: &'a ProjectionConfig, spec: &'a ProjectionSpec, generation: u64) -> Self {
        Self {
            config,
            spec,
            generation,
            style: if config.platform.is_windows() {
                PathStyle::Windows
            } else {
                PathStyle::Unix
            },
            steps: Vec::new(),
            changes: Vec::new(),
            manual: Vec::new(),
            findings: Vec::new(),
            git: None,
            added: Vec::new(),
            removed: Vec::new(),
            user_now: None,
            user_after: None,
            p_now: None,
            p_after: None,
            ssh_all_affected: false,
            ssh_repair: false,
            ssh_manual: false,
            user_unreadable: false,
            manual_for: None,
            account: crate::doctor::local_account(),
            git_selection: None,
            reads: BTreeMap::new(),
        }
    }

    // --- plan inputs (ADR-0007 §12.18 item 3) ---------------------------------------------

    /// Read `path` ([`read_file`]) and note its base as a plan input.
    fn read(&mut self, role: FileRole, path: &Path) -> Result<Option<Vec<u8>>, PreviewError> {
        let bytes = read_file(path)?;
        self.note(role, path, bytes.as_deref());
        Ok(bytes)
    }

    /// Note that the plan read `path` (in `role`) and found `bytes` (`None`: absent).
    fn note(&mut self, role: FileRole, path: &Path, bytes: Option<&[u8]>) {
        let base = bytes.map_or(Base::Absent, |b| Base::Present {
            sha256: Sha256Hex::of(b),
        });
        self.reads.insert((role, path.to_path_buf()), base);
    }

    /// The marker of a block this plan inserts into the file of `role` (ADR-0007
    /// §12.18 item 3, X03). It is derived, never drawn, so the same inputs give the
    /// same block, target digest and plan digest, and §5.4 step 1's recomputation
    /// reproduces an approved preview:
    ///
    /// 1. the canonical digest of the plan inputs: SHA-256 over the canonical JSON of
    ///    the spec and of the base of every file the preview has read (role, path, and
    ///    absent or its digest);
    /// 2. SHA-256 over the length-prefixed fields `heimdall.marker.v1`, the proposed
    ///    generation (decimal), the role's wire name and that digest (hex); its first
    ///    **64** bits are the marker (ADR-0007 §12.20 item 3, which amends §12.18 item
    ///    3's 128 bits), rendered in §2's frozen form `hm-<16 hex>` that `MarkerId`
    ///    enforces.
    ///
    /// Markers are not secrets; a user's copy of a block, or two equal markers, is the
    /// duplicate-marker case (`marker_duplicated`).
    fn derived_marker(&self, role: FileRole) -> Result<MarkerId, PreviewError> {
        let unavailable = |what: &str| PreviewError::Unavailable(format!("marker: {what}"));
        let spec = serde_json::to_value(self.spec).map_err(|_| unavailable("spec"))?;
        let reads: Vec<serde_json::Value> = self
            .reads
            .iter()
            .map(|((r, path), base)| serde_json::json!([r, path.to_string_lossy(), base]))
            .collect();
        let inputs = serde_json::json!({
            "heimdall_marker_inputs": 1,
            "spec": spec,
            "reads": reads,
        });
        let canonical = heimdall_contract::canonical::canonical_json(&inputs)
            .map_err(|_| unavailable("inputs not canonical"))?;
        let inputs = Sha256Hex::of(&canonical);
        let generation = self.generation.to_string();
        let mut h = Sha256::new();
        for field in [
            b"heimdall.marker.v1".as_slice(),
            generation.as_bytes(),
            role.as_str().as_bytes(),
            inputs.as_str().as_bytes(),
        ] {
            h.update((field.len() as u64).to_be_bytes());
            h.update(field);
        }
        let digest = h.finalize();
        let derived = digest.get(..8).ok_or_else(|| unavailable("digest"))?;
        let hex: String = derived.iter().map(|b| format!("{b:02x}")).collect();
        MarkerId::parse(&format!("hm-{hex}")).map_err(|e| unavailable(&e.to_string()))
    }

    // --- the SSH item -------------------------------------------------------------------

    fn plan_ssh_apply(&mut self) -> Result<(), PreviewError> {
        let p_path = self.config.managed_ssh_path();
        if self.spec.aliases.len() > bounds::KEY_FILES_MAX {
            return Err(PreviewError::TooLarge);
        }
        // ⟨M03⟩ ADR-0008 D10 item 1: which aliases' pairs prefer `managed_certificate`
        // (none without a source: every alias is existing access, as in M02).
        let managed = self.managed_sections()?;
        // ADR-0007 §12.22 item 8: an existing-access alias always names its key file. An
        // empty path is refused, never rendered as an empty `IdentityFile` (the runtime's
        // writer fills it from the catalog before a preview). A managed-certificate
        // alias renders the slot's files instead.
        if self
            .spec
            .aliases
            .iter()
            .zip(&managed)
            .any(|(a, m)| m.is_none() && a.key_file.is_empty())
        {
            return Err(PreviewError::Unavailable(
                "a managed alias has no key file".to_owned(),
            ));
        }
        if self.managed_edited(FileRole::ManagedSsh, &p_path)? {
            self.conflict(ConflictKind::ManagedFileEdited, None);
            return Ok(());
        }
        let changes_before = self.changes.len();
        let mut sections = Vec::new();
        let mut key_steps: Vec<FileStep> = Vec::new();
        let mut disclosures = Vec::new();
        for (a, m) in self.spec.aliases.iter().zip(&managed) {
            if let Some(m) = m {
                sections.push(self.managed_certificate(a, m)?);
                disclosures.push(slot_free_disclosure(&a.alias, &a.destination));
                continue;
            }
            sections.push(Section::ExistingAccess(self.managed_alias(a)?));
            let key = self.key_bytes(a)?;
            if key.bytes().len() > bounds::KEY_FILE_MAX {
                return Err(PreviewError::TooLarge);
            }
            if key_steps.iter().any(|s| s.path == a.key_file) {
                continue;
            }
            if let Some(step) = self.whole_step(FileRole::Key, Path::new(&a.key_file), key)? {
                key_steps.push(step);
            }
        }
        let p = render::rendered_sections(&sections, self.style, self.identity_form())
            .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))?;
        if p.bytes().len() > bounds::MANAGED_SSH_MAX {
            return Err(PreviewError::TooLarge);
        }
        // ⟨M03⟩ ADR-0008 D10 item 2, §17.4 item 12: the preview of a managed alias says
        // that ordinary `ssh <alias>` needs a held slot, and names the command.
        self.findings.extend(disclosures);
        self.p_now = self.read(FileRole::ManagedSsh, &p_path)?;
        self.p_after = Some(p.bytes().to_vec());
        let p_step = self.whole_step(FileRole::ManagedSsh, &p_path, p)?;
        // ADR-0007 §5.3 item 9, §12.48 item 3: a directory this item writes into (P's,
        // a key file's) whose quarantine does not validate makes the item manual at
        // preview, and nothing is planned: a settlement there would fail only after the
        // commit. The plan writes nothing, so it changes nothing and needs no decision.
        let blocked: Vec<PathBuf> = key_steps
            .iter()
            .chain(p_step.iter())
            .filter_map(|s| Path::new(&s.path).parent().map(Path::to_path_buf))
            .fold(Vec::new(), |mut dirs, d| {
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
                dirs
            })
            .into_iter()
            .filter(|d| quarantine_invalid(d))
            .collect();
        if !blocked.is_empty() {
            self.changes.truncate(changes_before);
            self.p_after = None;
            self.manual(manual_reason::UNMANAGEABLE_FILE);
            for dir in &blocked {
                let message = format!(
                    "{} holds a {QUARANTINE} that Heimdall cannot validate; nothing is written there",
                    self.display(dir)
                );
                self.findings.push(Finding {
                    code: manual_reason::UNMANAGEABLE_FILE.to_owned(),
                    severity: FindingSeverity::Problem,
                    subject: ResourceRef {
                        kind: "projection".to_owned(),
                        id: None,
                    },
                    level: ProbeLevel::Static,
                    provenance: None,
                    message,
                    next: NextAction::for_code(Code::ConfigConflict),
                    reason: None,
                });
            }
            return Ok(());
        }
        self.added = self.spec.aliases.iter().map(|a| a.alias.clone()).collect();

        let user = self.config.paths.user_config.clone();
        if let Some(conflict) = self.manual_for {
            // The `manual_mode` repair: P and the key files as an apply renders them;
            // the user file is never planned, and the plan shows the exact block the
            // owner keeps at its top (ADR-0007 §5.3 step 9, §5.5).
            self.manual(&manual_for_conflict(conflict));
            self.manual_block_finding(&user, &p_path)?;
            self.manual_consent(&user);
            self.steps.extend(manual_steps(key_steps, p_step));
            return Ok(());
        }
        let Some(user_bytes) = self.inspect_user_file(&user)? else {
            // Manual mode: P and the key files only; the owner inserts B. Whether the
            // user configuration activates P is still evaluated (§12.21 item 1).
            self.manual_consent(&user);
            self.steps.extend(manual_steps(key_steps, p_step));
            return Ok(());
        };
        self.user_now.clone_from(&user_bytes);
        let blocks = edit::find_blocks(user_bytes.as_deref().unwrap_or_default());
        match blocks.as_slice() {
            [] => {
                self.plan_first_adoption(&user, user_bytes.as_deref(), &p_path, key_steps, p_step)?
            }
            [only] if only.intact && only.position == BlockPosition::BeforeFirstSection => {
                // Update: P is the commit step; the user file is only checked.
                let mut writing = key_steps;
                writing.extend(p_step);
                if writing.is_empty() {
                    return Ok(());
                }
                let commit = writing
                    .iter()
                    .rposition(|s| s.role == FileRole::ManagedSsh)
                    .unwrap_or(writing.len() - 1);
                writing[commit].commit = true;
                let bytes = user_bytes.unwrap_or_default();
                let check = self.check_step(&user, &bytes, only, &p_path)?;
                self.steps.extend(writing);
                self.steps.push(check);
            }
            [only] if !only.intact => self.conflict(ConflictKind::MarkerEdited, None),
            [only] => {
                let line = match &only.position {
                    BlockPosition::Conditional(span) => Some(vec![span.line]),
                    BlockPosition::BeforeFirstSection => None,
                };
                self.conflict(ConflictKind::IncludeConditional, line.as_deref());
            }
            _ => self.conflict(ConflictKind::MarkerDuplicated, None),
        }
        Ok(())
    }

    fn plan_first_adoption(
        &mut self,
        user: &Path,
        user_bytes: Option<&[u8]>,
        p_path: &Path,
        key_steps: Vec<FileStep>,
        p_step: Option<FileStep>,
    ) -> Result<(), PreviewError> {
        let newline = user_bytes
            .and_then(edit::detect_newline)
            .unwrap_or(Newline::Lf);
        let marker = self.derived_marker(FileRole::UserSsh)?;
        let block = match self.include_block(&marker, p_path, newline)? {
            Ok(block) => block,
            Err(reason) => {
                self.manual_unmanageable(reason);
                self.ssh_manual = true;
                self.steps.extend(manual_steps(key_steps, p_step));
                return Ok(());
            }
        };
        let plan = edit::plan_insert(
            user_bytes,
            &IncludeBlock {
                marker,
                bytes: block.bytes().to_vec(),
            },
        );
        match plan {
            Ok(plan) => {
                if !self.accepts_encoding(plan.had_bom, plan.newline == Newline::CrLf) {
                    self.manual(manual_reason::UNSUPPORTED_ENCODING);
                    self.ssh_manual = true;
                    self.steps.extend(manual_steps(key_steps, p_step));
                    return Ok(());
                }
                let offset = u64::try_from(plan.offset).map_err(|_| PreviewError::TooLarge)?;
                self.user_after = Some(plan.bytes.clone());
                let step = self.splice_step(
                    FileRole::UserSsh,
                    user,
                    user_bytes,
                    &plan.bytes,
                    block.into_splice(offset, 0, None),
                    true,
                )?;
                self.steps.extend(key_steps);
                self.steps.extend(p_step);
                self.steps.push(step);
            }
            Err(EditRefusal::UnsupportedEncoding) => {
                self.manual(manual_reason::UNSUPPORTED_ENCODING);
                self.ssh_manual = true;
                self.steps.extend(manual_steps(key_steps, p_step));
            }
            Err(EditRefusal::DuplicateMarker) => {
                self.conflict(ConflictKind::MarkerDuplicated, None)
            }
            Err(EditRefusal::MarkerEdited { lines }) => {
                self.conflict(ConflictKind::MarkerEdited, Some(&lines));
            }
            Err(_) => self.conflict(ConflictKind::MarkerEdited, None),
        }
        Ok(())
    }

    fn plan_ssh_rollback(&mut self, keep_key_files: bool) -> Result<(), PreviewError> {
        let user = self.config.paths.user_config.clone();
        let p_path = self.config.managed_ssh_path();
        let Some(user_bytes) = self.inspect_user_file(&user)? else {
            return Ok(());
        };
        let bytes = user_bytes.unwrap_or_default();
        let blocks = edit::find_blocks(&bytes);
        let mut steps = Vec::new();
        match blocks.as_slice() {
            [] => {}
            [only] => {
                let newline = block_newline(&bytes, only);
                let expected = match self.include_block(&only.marker, &p_path, newline)? {
                    Ok(block) => block.bytes().to_vec(),
                    // No B Heimdall renders can name this P, so the block is not one.
                    Err(_) => {
                        self.conflict(ConflictKind::MarkerEdited, None);
                        return Ok(());
                    }
                };
                match edit::plan_remove(&bytes, &only.marker, &expected) {
                    Ok(after) => steps.push({
                        self.user_now = Some(bytes.clone());
                        self.user_after = Some(after.clone());
                        self.p_now = read_file(&p_path)?;
                        self.ssh_all_affected = true;
                        self.removal_splice(FileRole::UserSsh, &user, &bytes, &after, only)?
                    }),
                    Err(EditRefusal::MarkerEdited { lines }) => {
                        self.conflict(ConflictKind::MarkerEdited, Some(&lines));
                        return Ok(());
                    }
                    Err(_) => {
                        self.conflict(ConflictKind::MarkerEdited, None);
                        return Ok(());
                    }
                }
            }
            _ => {
                self.conflict(ConflictKind::MarkerDuplicated, None);
                return Ok(());
            }
        }
        // P and the key files go to the cleaner (target absent).
        if let Some(step) = self.removal_step(FileRole::ManagedSsh, &p_path)? {
            steps.push(step);
        }
        let record = live_item(self.spec, ProjectionItem::Ssh);
        if !keep_key_files {
            let keys: Vec<String> = record
                .map(|r| {
                    r.files
                        .iter()
                        .filter(|l| l.role == FileRole::Key)
                        .map(|l| l.path.clone())
                        .collect()
                })
                .unwrap_or_default();
            for k in keys {
                if let Some(step) = self.removal_step(FileRole::Key, Path::new(&k))? {
                    steps.push(step);
                }
            }
        }
        self.removed = record.map(|r| r.aliases.clone()).unwrap_or_default();
        self.steps.extend(steps);
        Ok(())
    }

    // --- block repairs (ADR-0007 §5.5) ----------------------------------------------------

    /// The user file for a block repair, with its blocks. `None`: manual mode or no
    /// user file (nothing to repair).
    fn repair_input(&mut self) -> Result<Option<(PathBuf, Vec<u8>)>, PreviewError> {
        let user = self.config.paths.user_config.clone();
        let Some(Some(bytes)) = self.inspect_user_file(&user)? else {
            return Ok(None);
        };
        Ok(Some((user, bytes)))
    }

    /// Whether `block` is exactly the B Heimdall renders for its marker and P (the only
    /// block a repair may remove or move; anything else is `marker_edited`).
    fn is_heimdalls(&self, bytes: &[u8], block: &FoundBlock) -> Result<bool, PreviewError> {
        let p_path = self.config.managed_ssh_path();
        let newline = block_newline(bytes, block);
        Ok(match self.include_block(&block.marker, &p_path, newline)? {
            Ok(rendered) => bytes.get(block.range.clone()) == Some(rendered.bytes()),
            Err(_) => false,
        })
    }

    /// Note the repair's inputs for §5.2: every managed alias is affected, and stays
    /// managed.
    fn repair_consent(&mut self, before: &[u8], after: &[u8]) -> Result<(), PreviewError> {
        self.user_now = Some(before.to_vec());
        self.user_after = Some(after.to_vec());
        self.p_now = read_file(&self.config.managed_ssh_path())?;
        self.ssh_all_affected = true;
        self.ssh_repair = true;
        Ok(())
    }

    /// `remove_duplicate_markers` (`marker_duplicated`): keep the first block that is
    /// Heimdall's exact B before the first section, and remove one other block that is
    /// also Heimdall's exact B (for its own marker), by one splice. An intent has one
    /// step per file, so a file with more duplicates needs the repair again; the plan
    /// says so. Nothing else is removed: an edited block is `marker_edited` with its
    /// lines, and without a block to keep the plan changes nothing.
    fn plan_remove_duplicate(&mut self) -> Result<(), PreviewError> {
        let Some((user, bytes)) = self.repair_input()? else {
            return Ok(());
        };
        let blocks = edit::find_blocks(&bytes);
        if blocks.len() < 2 {
            return Ok(());
        }
        let mut keep = None;
        for (i, b) in blocks.iter().enumerate() {
            if b.position == BlockPosition::BeforeFirstSection && self.is_heimdalls(&bytes, b)? {
                keep = Some(i);
                break;
            }
        }
        let Some(keep) = keep else {
            self.conflict(ConflictKind::MarkerDuplicated, None);
            return Ok(());
        };
        let Some((_, dup)) = blocks.iter().enumerate().find(|(i, _)| *i != keep) else {
            return Ok(());
        };
        if !self.is_heimdalls(&bytes, dup)? {
            let line = line_of(&bytes, dup.range.start);
            self.conflict(ConflictKind::MarkerEdited, Some(&[line]));
            return Ok(());
        }
        let mut after = bytes.clone();
        after.drain(dup.range.clone());
        self.repair_consent(&bytes, &after)?;
        let step = self.removal_splice(FileRole::UserSsh, &user, &bytes, &after, dup)?;
        self.steps.push(step);
        if blocks.len() > 2 {
            self.conflict(ConflictKind::MarkerDuplicated, None);
        }
        Ok(())
    }

    /// `move_include_to_top` (`include_conditional`): the one block, Heimdall's exact
    /// B, sits below a section or a top-level directive. Moving it is two edits of the
    /// user file, and an intent has one step per file, so this repair inserts a fresh
    /// B at the top (one splice, before the first directive, as a first adoption
    /// places it) and leaves the conditional block, now redundant, for a following
    /// `remove_duplicate_markers`, which keeps the top block. P is in effect for every
    /// host from this repair on, and at no point is it out of effect. The plan reports
    /// the remaining duplicate.
    fn plan_move_to_top(&mut self) -> Result<(), PreviewError> {
        let Some((user, bytes)) = self.repair_input()? else {
            return Ok(());
        };
        let blocks = edit::find_blocks(&bytes);
        let [only] = blocks.as_slice() else {
            if blocks.len() > 1 {
                self.conflict(ConflictKind::MarkerDuplicated, None);
            }
            return Ok(());
        };
        if only.position == BlockPosition::BeforeFirstSection {
            return Ok(());
        }
        if !self.is_heimdalls(&bytes, only)? {
            let line = line_of(&bytes, only.range.start);
            self.conflict(ConflictKind::MarkerEdited, Some(&[line]));
            return Ok(());
        }
        let p_path = self.config.managed_ssh_path();
        let newline = block_newline(&bytes, only);
        self.read(FileRole::ManagedSsh, &p_path)?;
        let marker = self.derived_marker(FileRole::UserSsh)?;
        let block = match self.include_block(&marker, &p_path, newline)? {
            Ok(block) => block,
            Err(reason) => {
                self.manual_unmanageable(reason);
                return Ok(());
            }
        };
        let mut without = bytes.clone();
        without.drain(only.range.clone());
        let plan = match edit::plan_insert(
            Some(&without),
            &IncludeBlock {
                marker,
                bytes: block.bytes().to_vec(),
            },
        ) {
            Ok(plan) => plan,
            Err(EditRefusal::UnsupportedEncoding) => {
                self.manual(manual_reason::UNSUPPORTED_ENCODING);
                return Ok(());
            }
            Err(_) => {
                self.conflict(ConflictKind::MarkerEdited, None);
                return Ok(());
            }
        };
        // The conditional block lies below the first directive, so the top offset is
        // the same in the file that still holds it.
        if plan.offset > only.range.start
            || !self.accepts_encoding(plan.had_bom, plan.newline == Newline::CrLf)
        {
            self.manual(manual_reason::UNSUPPORTED_ENCODING);
            return Ok(());
        }
        let mut after = bytes.clone();
        after.splice(plan.offset..plan.offset, block.bytes().iter().copied());
        let offset = u64::try_from(plan.offset).map_err(|_| PreviewError::TooLarge)?;
        self.repair_consent(&bytes, &after)?;
        let step = self.splice_step(
            FileRole::UserSsh,
            &user,
            Some(&bytes),
            &after,
            block.into_splice(offset, 0, None),
            true,
        )?;
        self.steps.push(step);
        self.conflict(ConflictKind::MarkerDuplicated, None);
        Ok(())
    }

    /// The exact block the owner keeps at the top of the user file in manual mode, as
    /// a finding (ADR-0007 §5.3 step 9: Heimdall prints the block and changes
    /// nothing there).
    fn manual_block_finding(&mut self, user: &Path, p_path: &Path) -> Result<(), PreviewError> {
        let newline = self
            .read(FileRole::UserSsh, user)?
            .as_deref()
            .and_then(edit::detect_newline)
            .unwrap_or(Newline::Lf);
        let marker = self.derived_marker(FileRole::UserSsh)?;
        let message = match self.include_block(&marker, p_path, newline)? {
            Ok(block) => format!(
                "keep exactly these lines at the top of {}:\n{}",
                self.display(user),
                String::from_utf8_lossy(block.bytes())
            ),
            Err(reason) => {
                self.manual_unmanageable(reason);
                return Ok(());
            }
        };
        self.findings.push(Finding {
            code: "manual_mode".to_owned(),
            severity: FindingSeverity::Info,
            subject: ResourceRef {
                kind: "projection".to_owned(),
                id: None,
            },
            level: ProbeLevel::Static,
            provenance: None,
            message,
            next: NextAction::for_code(Code::ConfigConflict),
            reason: self.manual_for.map(manual_for_conflict),
        });
        Ok(())
    }

    /// Read the user file and decide whether it can be edited automatically.
    /// `Ok(None)`: manual mode (the reason is recorded). `Ok(Some(None))`: absent.
    /// What it found is noted as a plan input.
    fn inspect_user_file(&mut self, user: &Path) -> Result<Option<Option<Vec<u8>>>, PreviewError> {
        let found = self.inspect_user_file_bytes(user)?;
        if let Some(bytes) = &found {
            self.note(FileRole::UserSsh, user, bytes.as_deref());
        }
        Ok(found)
    }

    fn inspect_user_file_bytes(
        &mut self,
        user: &Path,
    ) -> Result<Option<Option<Vec<u8>>>, PreviewError> {
        let (Some(parent), Some(name)) = (user.parent(), user.file_name().and_then(|n| n.to_str()))
        else {
            self.manual(manual_reason::UNMANAGEABLE_FILE);
            return Ok(None);
        };
        if matches!(std::fs::symlink_metadata(parent), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(Some(None));
        }
        let Ok(dir) = DirHandle::open(parent) else {
            self.manual(manual_reason::UNMANAGEABLE_FILE);
            return Ok(None);
        };
        // The directory still is the one validated, and an existing quarantine must
        // validate; a preview never creates one (W6X-R04, ADR-0007 §12.51 item 4).
        if Quarantine::validate_existing(&dir).is_err() {
            self.manual(manual_reason::UNMANAGEABLE_FILE);
            return Ok(None);
        }
        match std::fs::symlink_metadata(user) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Some(None)),
            Err(_) => {
                self.manual(manual_reason::UNMANAGEABLE_FILE);
                return Ok(None);
            }
            Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
                self.manual(manual_reason::UNMANAGEABLE_FILE);
                return Ok(None);
            }
            Ok(_) => {}
        }
        let Ok(bytes) = read_file(user).map(Option::unwrap_or_default) else {
            self.manual(manual_reason::UNMANAGEABLE_FILE);
            return Ok(None);
        };
        let base = Base::Present {
            sha256: Sha256Hex::of(&bytes),
        };
        match replace::validate(&dir, name, &base) {
            Ok(_) => Ok(Some(Some(bytes))),
            Err(ReplaceRefusal::BaseChanged) => Err(PreviewError::Unavailable(
                "the user file changed while it was read".to_owned(),
            )),
            Err(_) => {
                self.manual(manual_reason::UNMANAGEABLE_FILE);
                Ok(None)
            }
        }
    }

    /// ADR-0007 §12.21 item 1 (V01): whether the user file may be edited, and whether
    /// it activates P, are separate facts. A manual plan does not plan the user file,
    /// but it reads the user configuration through the read-only source, as ssh reads
    /// it (a symlink followed) and exactly as for an editable file, and takes the
    /// affected aliases from every P change. The evaluation then establishes whether
    /// P is in effect. A configuration the source cannot read (an unreadable symlink
    /// target, a directory, a bound exceeded) leaves that unknown: every affected
    /// state is undetermined, so a decision is required. An absent one activates
    /// nothing.
    fn manual_consent(&mut self, user: &Path) {
        self.ssh_manual = true;
        let source = BoundedSource::new(
            self.config.paths.clone(),
            self.config.env.clone(),
            Limits::default(),
        );
        match source.read(user) {
            Ok(found) => self.user_now = Some(found.bytes),
            Err(SourceError::NotFound) => self.user_now = None,
            Err(_) => {
                self.user_now = None;
                self.user_unreadable = true;
            }
        }
    }

    /// Whether the selected client loads the user file with B effective given its
    /// BOM and line endings (ADR-0007 §4 "Encodings"; U3's observation table). A file
    /// with neither is always accepted.
    fn accepts_encoding(&self, bom: bool, crlf: bool) -> bool {
        if !bom && !crlf {
            return true;
        }
        self.config
            .clients
            .selected(ClientKind::Ssh)
            .is_some_and(|c| self.config.clients.accepts_encoding(c, bom, crlf))
    }

    /// The recorded digest of the file at `path` in `role`, when its item's record
    /// names it (an empty record names nothing, ADR-0007 §12.22 item 2).
    fn recorded(&self, role: FileRole, path: &Path) -> Option<Sha256Hex> {
        let item = live_item(self.spec, role.item())?;
        item.files
            .iter()
            .find(|l| l.role == role && Path::new(&l.path) == path)
            .map(|l| l.sha256.clone())
    }

    /// A managed file that no longer holds what the record says Heimdall wrote was
    /// edited: it is never overwritten (`managed_file_edited`, finding
    /// `projection_edited`).
    fn managed_edited(&self, role: FileRole, path: &Path) -> Result<bool, PreviewError> {
        let Some(recorded) = self.recorded(role, path) else {
            return Ok(false);
        };
        Ok(read_file(path)?.is_some_and(|b| Sha256Hex::of(&b) != recorded))
    }

    // --- the Git item -------------------------------------------------------------------

    fn plan_git_apply(&mut self) -> Result<(), PreviewError> {
        let undetermined = GitSshSelection {
            source: GitSshSource::Default,
            scope: None,
            classification: GitSshClassification::Undetermined,
        };
        if self.config.env.get("GIT_CONFIG_GLOBAL").is_some() {
            self.git = Some(not_applicable(
                manual_reason::GIT_GLOBAL_REDIRECTED,
                undetermined,
            ));
            return Ok(());
        }
        // ADR-0007 §12.34 item 8 (1): Heimdall's own P_git, which B_git includes once the
        // item is applied, is not a user's `core.sshCommand`. The observation splits it
        // out; it is judged below, once the global file's blocks are known.
        let p_git_path = self.config.managed_git_path();
        let obs = observe_global_for(
            &self.config.env,
            &self.config.clients,
            self.config.queries,
            &p_git_path,
        );
        let before = GitSshSelection {
            source: GitSshSource::Default,
            scope: None,
            classification: match obs.default_ssh {
                DefaultGitSsh::BundledMsys(_) => GitSshClassification::BundledMsys,
                DefaultGitSsh::PathSsh => GitSshClassification::Other,
                DefaultGitSsh::Undetermined => GitSshClassification::Undetermined,
            },
        };
        if !obs.unreadable.is_empty() {
            self.git = Some(not_applicable(finding::GIT_CONFIG_UNREADABLE, before));
            return Ok(());
        }
        if !obs.values.is_empty() {
            let mut change = not_applicable(finding::GIT_SSH_COMMAND_PRESENT, before);
            change.previous_values = obs.values.clone();
            self.git = Some(change);
            return Ok(());
        }
        let msys = matches!(obs.default_ssh, DefaultGitSsh::BundledMsys(_));
        if !msys && !self.config.test.git_item_any_default {
            self.git = Some(not_applicable("git_default_not_bundled_msys", before));
            return Ok(());
        }
        let Some(file) = obs.file.clone() else {
            self.git = Some(not_applicable(manual_reason::GIT_GLOBAL_REDIRECTED, before));
            return Ok(());
        };
        let Some(client) = self.config.clients.selected(ClientKind::Ssh) else {
            self.git = Some(not_applicable("verified_client_unavailable", before));
            return Ok(());
        };
        // ADR-0007 §12.39 item 3 (the twin of the rollback's §12.37 item 3): B_git is looked
        // for where it was written, which is the file the Git item's record names, not
        // necessarily Git's first-read file now. After B_git went into `~/.gitconfig`
        // because no XDG file existed, an XDG file created later is the first-read file
        // while B_git stays where it is; looking only in the first-read file found no
        // block, took P_git's value (reached through the block that was not found) for a
        // user's, and reported `git_ssh_command_present` for Heimdall's own value.
        let (global, global_bytes) = match self.locate_b_git(&file.path)? {
            BGitSearch::At(path, bytes) => (path, Some(bytes)),
            // No file holds a block and the first-read file does not exist: it is created.
            BGitSearch::Nothing => (file.path.clone(), None),
            BGitSearch::Ambiguous => {
                self.manual_b_git_duplicated();
                self.git = Some(not_applicable(manual_reason::MARKER_DUPLICATED, before));
                return Ok(());
            }
        };
        self.note(FileRole::GitInclude, &global, global_bytes.as_deref());
        let blocks = gitedit::find_blocks(global_bytes.as_deref().unwrap_or_default());
        // ADR-0007 §12.34 item 8 (1): P_git's one value is Heimdall's own only when it
        // is reached through B_git, which is then the global file's one block, intact
        // and naming P_git. Anything else (no block, an edited or a duplicated one, one
        // that names another file) leaves a `core.sshCommand` in a file Heimdall did
        // not link in: a present value, as before (fail closed).
        if !obs.own_values.is_empty()
            && !self.names_include(&blocks, global_bytes.as_deref(), &p_git_path)?
        {
            let mut change = not_applicable(finding::GIT_SSH_COMMAND_PRESENT, before);
            change.previous_values = obs.values.iter().chain(&obs.own_values).cloned().collect();
            self.git = Some(change);
            return Ok(());
        }
        // A managed file that no longer holds what the record says Heimdall wrote was
        // edited: it is never overwritten (`managed_file_edited`), as for P (§5.8). The
        // update arm below is reachable only now that Heimdall's own value no longer
        // blocks the item.
        if self.managed_edited(FileRole::GitManaged, &p_git_path)? {
            self.conflict(ConflictKind::ManagedFileEdited, None);
            return Ok(());
        }
        // ADR-0007 §5.3 item 9, §5.6: a global file the writer will not touch (its
        // directory or the file fails a step-1 or step-2 check) is manual mode for the
        // Git item, decided here as the SSH user file is, not at apply, where the
        // refusal would sink the SSH item too (§12.32 item 13). Only a plan that
        // writes the global file needs it: an update of P_git alone does not.
        if blocks.is_empty() {
            match check_global_file(&global, global_bytes.as_deref()) {
                GlobalFileCheck::Manageable => {}
                GlobalFileCheck::Unmanageable => {
                    let mut change = not_applicable(manual_reason::UNMANAGEABLE_FILE, before);
                    change.global_file = Some(GitGlobalFile {
                        path_display: self.display(&global),
                        file: file.file,
                        resolution: file.rule,
                    });
                    self.git = Some(change);
                    return Ok(());
                }
                GlobalFileCheck::Changed => {
                    return Err(PreviewError::Unavailable(
                        "the global Git file changed while it was read".to_owned(),
                    ));
                }
            }
        }
        let client_path = self.absolute_path(&client.path)?;
        let p_git = render::rendered_git_managed(&client_path)
            .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))?;
        if p_git.bytes().len() > bounds::GIT_MANAGED_MAX {
            return Err(PreviewError::TooLarge);
        }
        let p_git_step = self.whole_step(FileRole::GitManaged, &p_git_path, p_git)?;
        let mut steps: Vec<FileStep> = Vec::new();
        let mut include_change = None;
        match blocks.as_slice() {
            [] => {
                let target = self.absolute_path(&p_git_path)?;
                let newline = global_bytes
                    .as_deref()
                    .and_then(edit::detect_newline)
                    .unwrap_or(Newline::Lf);
                let marker = self.derived_marker(FileRole::GitInclude)?;
                let block = render::rendered_git_include_block(&marker, &target, newline)
                    .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))?;
                let plan = gitedit::plan_insert_top(
                    global_bytes.as_deref(),
                    &IncludeBlock {
                        marker,
                        bytes: block.bytes().to_vec(),
                    },
                )
                .map_err(|e| PreviewError::Unavailable(format!("git edit: {e}")))?;
                let offset = u64::try_from(plan.offset).map_err(|_| PreviewError::TooLarge)?;
                let include = self.splice_step(
                    FileRole::GitInclude,
                    &global,
                    global_bytes.as_deref(),
                    &plan.bytes,
                    block.into_splice(offset, 0, None),
                    true,
                )?;
                include_change = self.changes.last().cloned();
                steps.extend(p_git_step);
                steps.push(self.lock_step(&global)?);
                steps.push(include);
            }
            [only] if only.intact => {
                // Update: only P_git changes, and it is then the Git commit step.
                if let Some(mut s) = p_git_step {
                    s.commit = true;
                    steps.push(s);
                }
            }
            _ => {
                self.conflict(ConflictKind::MarkerEdited, None);
                return Ok(());
            }
        }
        let managed_change = self
            .changes
            .iter()
            .find(|c| c.role == ProjectionFileRole::GitManaged)
            .cloned();
        self.steps.extend(steps);
        let after = GitSshSelection {
            source: GitSshSource::Config,
            scope: Some(GitScope::Global),
            classification: GitSshClassification::VerifiedClient,
        };
        if include_change.is_some() {
            self.git_selection = Some((before.clone(), after.clone()));
        }
        self.git = Some(GitConfigChange {
            applicability: GitApplicability::Applicable,
            reason: None,
            global_file: Some(GitGlobalFile {
                path_display: self.display(&global),
                file: file.file,
                resolution: file.rule,
            }),
            previous_values: Vec::new(),
            include_block: include_change,
            managed_file: managed_change,
            effective_before: before,
            effective_after: after,
        });
        Ok(())
    }

    fn plan_git_rollback(&mut self) -> Result<(), PreviewError> {
        let p_git_path = self.config.managed_git_path();
        let obs = observe_global(&self.config.env, &self.config.clients, self.config.queries);
        // §5.2 for the Git item: with B_git in effect the selection is P_git's value;
        // after the rollback it is a user value, when one remains, or Git's default.
        // P_git's own value, by its origin as the observation shows origins (the
        // canonical path, `~` for Git's home): `origin_of`, the one definition.
        let p_git_origin = origin_of(&self.config.env, &p_git_path);
        let user_value = obs
            .values
            .iter()
            .find(|v| v.origin_display.is_none() || v.origin_display != p_git_origin);
        let default = GitSshSelection {
            source: GitSshSource::Default,
            scope: None,
            classification: match obs.default_ssh {
                DefaultGitSsh::BundledMsys(_) => GitSshClassification::BundledMsys,
                DefaultGitSsh::PathSsh => GitSshClassification::Other,
                DefaultGitSsh::Undetermined => GitSshClassification::Undetermined,
            },
        };
        let heimdall = GitSshSelection {
            source: GitSshSource::Config,
            scope: Some(GitScope::Global),
            classification: GitSshClassification::VerifiedClient,
        };
        // ADR-0007 §12.42 item 2 (R02): an observation that could not read the whole
        // include graph, or could not establish Git's global file, cannot say what
        // the rollback leaves in effect, whether or not it found a user value: the
        // selection after the rollback is undetermined, which needs a decision (§5.2).
        let incomplete = !obs.unreadable.is_empty() || obs.file.is_none();
        let undetermined = GitSshSelection {
            source: GitSshSource::Default,
            scope: None,
            classification: GitSshClassification::Undetermined,
        };
        let selection = match user_value {
            _ if incomplete => (heimdall, undetermined),
            Some(v) => {
                let user = GitSshSelection {
                    source: GitSshSource::Config,
                    scope: Some(v.scope),
                    classification: GitSshClassification::Other,
                };
                // ADR-0007 §12.39 item 4. A user value that comes after B_git in Git's read
                // order already wins, so removing B_git changes nothing (§5.6 "Rollback").
                // One that comes before it (an XDG file created after the apply while B_git
                // is in `~/.gitconfig`, or the system file) loses to Heimdall's value, and
                // the rollback exposes it: the effective value changes from Heimdall's to
                // the user's, a change the owner has not consented to (§5.2). Who wins is
                // established as the doctor does, `git config --show-origin` (the last
                // occurrence): `winning_origin`. When that cannot be established (local
                // queries off, or the query failed) the reading that needs a decision is
                // taken: Heimdall's value is the effective one.
                let user_wins =
                    winning_origin(&self.config.env, &self.config.clients, self.config.queries)
                        .is_some_and(|won| Some(&won) != p_git_origin.as_ref());
                if user_wins {
                    (user.clone(), user)
                } else {
                    (heimdall, user)
                }
            }
            None => (heimdall, default),
        };
        // ADR-0007 §12.37 item 3: B_git is removed from the file its own step wrote, which
        // the Git item's record names. Git's first-read file is not that file once an XDG
        // file has been created after the apply (B_git stays in `~/.gitconfig`), and a
        // rollback that looked only at the first-read file would remove P_git and leave
        // B_git behind, including a file that no longer exists.
        let (global, bytes) = match self.recorded_include_file() {
            // A file that is gone holds no block: P_git alone is removed.
            Some(path) => {
                let bytes = read_file(&path)?.unwrap_or_default();
                (path, bytes)
            }
            None => match self.search_b_git(obs.file.as_ref().map(|f| f.path.as_path()))? {
                BGitSearch::At(path, bytes) => (path, bytes),
                BGitSearch::Nothing => return Ok(()),
                BGitSearch::Ambiguous => {
                    self.manual_b_git_duplicated();
                    return Ok(());
                }
            },
        };
        let blocks = gitedit::find_blocks(&bytes);
        // ADR-0007 §5.3 item 9, §12.34 item 8 (2): the writer refuses a global file, or
        // the directory holding it, that fails a step-1 or step-2 check, and refuses the
        // whole operation before its first commit point, the SSH item's rollback with it.
        // A rollback that edits the global file is therefore checked here, as the apply
        // is, with the writer's own check: otherwise the owner approves a rollback that
        // the apply then refuses. A file Heimdall will not touch is manual mode for the
        // Git item, as the SSH user file is on a rollback: nothing is planned for the
        // item (B_git stays, and P_git with it), and the owner removes the block by hand.
        if !blocks.is_empty() {
            match check_global_file(&global, Some(&bytes)) {
                GlobalFileCheck::Manageable => {}
                GlobalFileCheck::Unmanageable => {
                    self.manual_unmanageable_git(&global);
                    return Ok(());
                }
                GlobalFileCheck::Changed => {
                    return Err(PreviewError::Unavailable(
                        "the global Git file changed while it was read".to_owned(),
                    ));
                }
            }
        }
        let mut steps = Vec::new();
        match blocks.as_slice() {
            [] => {}
            [only] => {
                let target = self.absolute_path(&p_git_path)?;
                let newline = block_newline(&bytes, only);
                let expected = render::render_git_include_block(&only.marker, &target, newline)
                    .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))?;
                match gitedit::plan_remove(&bytes, &only.marker, &expected) {
                    Ok(after) => {
                        self.git_selection = Some(selection);
                        steps.push(self.lock_step(&global)?);
                        steps.push(self.removal_splice(
                            FileRole::GitInclude,
                            &global,
                            &bytes,
                            &after,
                            only,
                        )?);
                    }
                    Err(EditRefusal::MarkerEdited { lines }) => {
                        self.conflict(ConflictKind::MarkerEdited, Some(&lines));
                        return Ok(());
                    }
                    Err(_) => {
                        self.conflict(ConflictKind::MarkerEdited, None);
                        return Ok(());
                    }
                }
            }
            _ => {
                self.conflict(ConflictKind::MarkerDuplicated, None);
                return Ok(());
            }
        }
        if let Some(step) = self.removal_step(FileRole::GitManaged, &p_git_path)? {
            steps.push(step);
        }
        self.steps.extend(steps);
        Ok(())
    }

    /// Whether `blocks` of the global file `bytes` are B_git as Heimdall renders it for
    /// `p_git_path`: exactly one block, and its bytes are what [`render::render_git_include_block`]
    /// gives for its own marker, P_git's absolute path and its own line ending. A block
    /// that is edited, duplicated, absent or names another file is not
    /// ([`crate::git::holds_include`], which the doctor shares).
    fn names_include(
        &self,
        blocks: &[FoundBlock],
        bytes: Option<&[u8]>,
        p_git_path: &Path,
    ) -> Result<bool, PreviewError> {
        let ([_], Some(bytes)) = (blocks, bytes) else {
            return Ok(false);
        };
        let target = self.absolute_path(p_git_path)?;
        crate::git::holds_include(bytes, &target)
            .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))
    }

    /// A rollback over a global Git file the writer will not touch (`unmanageable_file`,
    /// ADR-0007 §12.34 item 8 (2)): manual mode, and a `problem` finding so that a plan
    /// that changes nothing is refused before admission, not approved and then refused.
    fn manual_unmanageable_git(&mut self, global: &Path) {
        let message = format!(
            "{} cannot be edited by Heimdall; remove its include block by hand",
            self.display(global)
        );
        self.manual_git(manual_reason::UNMANAGEABLE_FILE, message);
    }

    /// A Git rollback that is manual mode for `reason` (one of [`manual_reason`]): nothing
    /// is planned for the item, and a `problem` finding says why.
    fn manual_git(&mut self, reason: &str, message: String) {
        self.manual(reason);
        self.findings.push(Finding {
            code: reason.to_owned(),
            severity: FindingSeverity::Problem,
            subject: ResourceRef {
                kind: "projection".to_owned(),
                id: None,
            },
            level: ProbeLevel::Static,
            provenance: None,
            message,
            next: NextAction::for_code(Code::ConfigConflict),
            reason: Some(reason.to_owned()),
        });
    }

    /// The absolute path of the file the Git item's record says B_git was written into
    /// (`ItemRecord::include_file`, ADR-0007 §12.37 item 3, §12.39 item 1). `None` for a
    /// record that names none (written before the record carried it, or an item the
    /// record does not manage) and for a path that is not absolute.
    fn recorded_include_file(&self) -> Option<PathBuf> {
        live_item(self.spec, ProjectionItem::Git)
            .and_then(|r| r.include_file.as_deref())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    }

    /// ADR-0007 §12.39 item 3: where B_git is for a Git apply or re-render, the twin of the
    /// rollback's lookup. The file the record names is used when it still holds a block.
    /// Otherwise (the record names none, or the file it names is gone or holds no block,
    /// for example because the owner moved the block) both global files are searched as
    /// [`Self::search_b_git`] does, so that a block the owner moved to the other global
    /// file is found and a second one is never inserted beside it. `resolved` is the
    /// first-read file; with no block anywhere B_git goes there
    /// ([`BGitSearch::At`] when it exists, [`BGitSearch::Nothing`] when it is to be
    /// created).
    fn locate_b_git(&self, resolved: &Path) -> Result<BGitSearch, PreviewError> {
        if let Some(path) = self.recorded_include_file()
            && let Some(bytes) = read_file(&path)?
            && !gitedit::find_blocks(&bytes).is_empty()
        {
            return Ok(BGitSearch::At(path, bytes));
        }
        self.search_b_git(Some(resolved))
    }

    /// Manual mode for a Git item whose Heimdall block cannot be told apart from another
    /// (`marker_duplicated`, ADR-0007 §12.37 item 3): more than one block in the global
    /// Git files, in one file or in two.
    fn manual_b_git_duplicated(&mut self) {
        self.manual_git(
            manual_reason::MARKER_DUPLICATED,
            "Heimdall's include block is in more than one place in the global Git files; \
             remove the blocks by hand"
                .to_owned(),
        );
    }

    /// ADR-0007 §12.37 item 3: where B_git is for a record that names no file (one
    /// written before the record carried it). Both global files are read,
    /// `$XDG_CONFIG_HOME/git/config` and `$HOME/.gitconfig` as the environment gives
    /// them. Exactly one block in all of them names the file; a block that is edited is
    /// still found there, so the removal refuses it as before (`marker_edited`). No block
    /// anywhere leaves the file Git's first-read rule resolves (`resolved`), as before:
    /// there is nothing to remove from it and P_git alone is. More than one block, in one
    /// file or two, cannot be told apart and is manual mode. `resolved` is `None` when
    /// `GIT_CONFIG_GLOBAL` redirects the global file or Git's home is unknown: nothing is
    /// planned, as before.
    fn search_b_git(&self, resolved: Option<&Path>) -> Result<BGitSearch, PreviewError> {
        let Some(resolved) = resolved else {
            return Ok(BGitSearch::Nothing);
        };
        let files = crate::git::global_files(&self.config.env);
        let mut holding: Vec<(PathBuf, Vec<u8>, usize)> = Vec::new();
        for path in files.xdg.into_iter().chain(files.home) {
            if let Some(bytes) = read_file(&path)? {
                let blocks = gitedit::find_blocks(&bytes).len();
                if blocks > 0 {
                    holding.push((path, bytes, blocks));
                }
            }
        }
        Ok(match holding.len() {
            0 => match read_file(resolved)? {
                Some(bytes) => BGitSearch::At(resolved.to_path_buf(), bytes),
                None => BGitSearch::Nothing,
            },
            1 if holding[0].2 == 1 => {
                let (path, bytes, _) = holding.remove(0);
                BGitSearch::At(path, bytes)
            }
            _ => BGitSearch::Ambiguous,
        })
    }

    /// The `git_lock` step for `global` (ADR-0007 §5.7 "The `git_lock` step").
    fn lock_step(&self, global: &Path) -> Result<FileStep, PreviewError> {
        let mut lock = global.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let name = file_name(&lock)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| PreviewError::Unavailable("no random source".to_owned()))?;
        Ok(FileStep {
            role: FileRole::GitLock,
            path: path_string(&lock)?,
            base: Base::Absent,
            target: Target::Absent,
            content: lock_holder(self.generation, nonce).into_lock_holder(),
            commit: false,
            staged_name: Some(self.staged_name(&name)?),
            displaced_name: None,
        })
    }

    fn absolute_path(&self, path: &Path) -> Result<RenderPath, PreviewError> {
        match self.style {
            PathStyle::Windows => RenderPath::windows(path),
            PathStyle::Unix => RenderPath::unix(path),
        }
        .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))
    }

    /// B for `marker` naming P at `p_path` (ADR-0007 §12.17 item 9): the target is
    /// always absolute, never `~`, so B loads P whatever `$HOME` is. `Ok(Err(reason))`
    /// when no literal Include can name P (`include_target_glob`: OpenSSH globs inside
    /// a quoted Include argument, §12.16 item 3), which is manual mode before any edit.
    fn include_block(
        &self,
        marker: &MarkerId,
        p_path: &Path,
        newline: Newline,
    ) -> Result<Result<Rendered, &'static str>, PreviewError> {
        let refused = |e: render::RenderError| PreviewError::Unavailable(format!("render: {e}"));
        let target = RenderPath::absolute(p_path, self.style).map_err(refused)?;
        let block = render::rendered_include_block(marker, &target, newline);
        match block {
            Ok(block) => Ok(Ok(block)),
            Err(render::RenderError::Unmanageable(reason)) => Ok(Err(reason)),
            Err(e) => Err(refused(e)),
        }
    }

    /// Manual mode because a file cannot be managed (`unmanageable_file`), with the
    /// reason as a finding (`unmanageable{<reason>}`, for example
    /// `include_target_glob`). A reason the contract lists as a manual reason
    /// (`include_target_glob`, ADR-0007 §12.19 item 9, §12.22 item 8) is also listed
    /// as its own manual reason, besides `unmanageable_file`.
    fn manual_unmanageable(&mut self, reason: &str) {
        self.manual(manual_reason::UNMANAGEABLE_FILE);
        if manual_reason::ALL.contains(&reason) {
            self.manual(reason);
        }
        self.findings.push(Finding {
            code: manual_reason::UNMANAGEABLE_FILE.to_owned(),
            severity: FindingSeverity::Problem,
            subject: ResourceRef {
                kind: "projection".to_owned(),
                id: None,
            },
            level: ProbeLevel::Static,
            provenance: None,
            message: "the include block cannot be written for this path; add it by hand".to_owned(),
            next: NextAction::for_code(Code::ConfigConflict),
            reason: Some(reason.to_owned()),
        });
    }

    // --- steps ------------------------------------------------------------------------

    fn managed_alias(&self, a: &ManagedAliasSpec) -> Result<ManagedAlias, PreviewError> {
        let refused = |e: render::RenderError| PreviewError::Unavailable(format!("render: {e}"));
        let identity_agent = match &a.endpoint {
            None => None,
            Some(ep) => Some(match ep.kind {
                EndpointKind::NamedPipe => RenderPath::pipe(&ep.locator).map_err(refused)?,
                _ => self.render_path(Path::new(&ep.locator))?,
            }),
        };
        Ok(ManagedAlias {
            alias: AliasName::parse(&a.alias).map_err(refused)?,
            hostname: HostName::parse(&a.hostname).map_err(refused)?,
            port: a.port.filter(|p| *p != 22),
            user: a.account.as_str().to_owned(),
            identity_agent,
            identity_files: vec![self.render_path(Path::new(&a.key_file))?],
            identities_only: true,
        })
    }

    /// ⟨M03⟩ Each alias's managed section, in spec order (`None`: existing access).
    fn managed_sections(&self) -> Result<Vec<Option<ManagedSectionSpec>>, PreviewError> {
        let Some(source) = self.config.managed.as_ref() else {
            return Ok(vec![None; self.spec.aliases.len()]);
        };
        self.spec
            .aliases
            .iter()
            .map(|a| {
                source
                    .managed_section(a)
                    .map_err(|e| PreviewError::Unavailable(format!("managed pair: {e}")))
            })
            .collect()
    }

    /// ⟨M03⟩ The identity form of the managed sections: the one selector
    /// (`ManagedIdentityForm::select`, reading R4) for the selected `ssh` client, unless
    /// a test configuration names one.
    fn identity_form(&self) -> ManagedIdentityForm {
        self.config.test.managed_identity_form.unwrap_or_else(|| {
            ManagedIdentityForm::select(
                self.config
                    .clients
                    .selected(ClientKind::Ssh)
                    .and_then(|c| c.version),
            )
        })
    }

    /// ⟨M03⟩ ADR-0008 D10 item 1: a managed-certificate section, with ADR-0007 §4's
    /// value rules (paths `~/…` under the home, a Windows pipe `//./pipe/…`).
    fn managed_certificate(
        &self,
        a: &ManagedAliasSpec,
        m: &ManagedSectionSpec,
    ) -> Result<Section, PreviewError> {
        let refused = |e: render::RenderError| PreviewError::Unavailable(format!("render: {e}"));
        let endpoint = match m.environment_endpoint.kind {
            EndpointKind::NamedPipe => {
                RenderPath::pipe(&m.environment_endpoint.locator).map_err(refused)?
            }
            _ => self.render_path(Path::new(&m.environment_endpoint.locator))?,
        };
        Ok(Section::ManagedCertificate {
            alias: AliasName::parse(&a.alias).map_err(refused)?,
            hostname: HostName::parse(&a.hostname).map_err(refused)?,
            port: a.port.filter(|p| *p != 22),
            user: a.account.as_str().to_owned(),
            endpoint,
            key_pub: self.render_path(&m.key_pub)?,
            cert: self.render_path(&m.cert_pub)?,
            control_path: match &m.control_path {
                None => None,
                Some(p) => Some(self.render_path(p)?),
            },
        })
    }

    fn key_bytes(&self, a: &ManagedAliasSpec) -> Result<Rendered, PreviewError> {
        let line = self
            .config
            .keys
            .as_ref()
            .and_then(|k| k.public_key(&a.identity))
            .ok_or_else(|| {
                PreviewError::Unavailable("an adopted identity's public key is unknown".to_owned())
            })?;
        let key = PublicKeyLine::parse(&line)
            .map_err(|e| PreviewError::Unavailable(format!("public key: {e}")))?;
        Ok(public_key_bytes(&key))
    }

    fn render_path(&self, path: &Path) -> Result<RenderPath, PreviewError> {
        RenderPath::home_relative(path, &self.config.paths.account_home, self.style)
            .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))
    }

    fn staged_name(&self, name: &str) -> Result<String, PreviewError> {
        let random =
            random_hex().map_err(|_| PreviewError::Unavailable("no random source".to_owned()))?;
        let staged = format!(".{name}.hm-{}-{random}", self.generation);
        if staged.len() > bounds::NAME_MAX {
            return Err(PreviewError::Unavailable("file name too long".to_owned()));
        }
        Ok(staged)
    }

    /// Unix: the staged name (the exchange leaves D there); Windows:
    /// `.<name>.hm-displaced-<generation>` (ADR-0007 §5.7).
    fn displaced_name(&self, name: &str, staged: &str) -> String {
        if self.config.platform.is_windows() {
            format!(".{name}.hm-displaced-{}", self.generation)
        } else {
            staged.to_owned()
        }
    }

    /// A whole-file step, or `None` when the file already holds exactly these bytes.
    fn whole_step(
        &mut self,
        role: FileRole,
        path: &Path,
        rendered: Rendered,
    ) -> Result<Option<FileStep>, PreviewError> {
        let current = self.read(role, path)?;
        let target = rendered.sha256();
        if current.as_deref().map(Sha256Hex::of).as_ref() == Some(&target) {
            return Ok(None);
        }
        let name = file_name(path)?;
        let staged = self.staged_name(&name)?;
        let base = current.as_deref().map_or(Base::Absent, |b| Base::Present {
            sha256: Sha256Hex::of(b),
        });
        let displaced =
            matches!(base, Base::Present { .. }).then(|| self.displaced_name(&name, &staged));
        self.change(role, path, current.as_deref(), Some(rendered.bytes()));
        Ok(Some(FileStep {
            role,
            path: path_string(path)?,
            base,
            target: Target::Present { sha256: target },
            content: rendered.into_whole(),
            commit: false,
            staged_name: Some(staged),
            displaced_name: displaced,
        }))
    }

    fn splice_step(
        &mut self,
        role: FileRole,
        path: &Path,
        before: Option<&[u8]>,
        after: &[u8],
        content: StepContent,
        commit: bool,
    ) -> Result<FileStep, PreviewError> {
        let name = file_name(path)?;
        let staged = self.staged_name(&name)?;
        let base = before.map_or(Base::Absent, |b| Base::Present {
            sha256: Sha256Hex::of(b),
        });
        let displaced =
            matches!(base, Base::Present { .. }).then(|| self.displaced_name(&name, &staged));
        self.change(role, path, before, Some(after));
        Ok(FileStep {
            role,
            path: path_string(path)?,
            base,
            target: Target::Present {
                sha256: Sha256Hex::of(after),
            },
            content,
            commit,
            staged_name: Some(staged),
            displaced_name: displaced,
        })
    }

    /// The splice that removes `block` from `before`, giving `after`.
    fn removal_splice(
        &mut self,
        role: FileRole,
        path: &Path,
        before: &[u8],
        after: &[u8],
        block: &FoundBlock,
    ) -> Result<FileStep, PreviewError> {
        let removed = before
            .get(block.range.clone())
            .ok_or_else(|| PreviewError::Unavailable("block range".to_owned()))?;
        let offset = u64::try_from(block.range.start).map_err(|_| PreviewError::TooLarge)?;
        let len = u64::try_from(removed.len()).map_err(|_| PreviewError::TooLarge)?;
        let content = StepContent::remove_range(offset, len, Sha256Hex::of(removed));
        self.splice_step(role, path, Some(before), after, content, true)
    }

    /// The update's check-only user step: a splice that removes the recorded block
    /// and inserts it again, so its target equals its base and it writes nothing.
    fn check_step(
        &mut self,
        user: &Path,
        bytes: &[u8],
        block: &FoundBlock,
        p_path: &Path,
    ) -> Result<FileStep, PreviewError> {
        let newline = block_newline(bytes, block);
        let Ok(rendered) = self.include_block(&block.marker, p_path, newline)? else {
            return Err(PreviewError::Unavailable(
                "the include block does not name this P".to_owned(),
            ));
        };
        let removed = bytes
            .get(block.range.clone())
            .ok_or_else(|| PreviewError::Unavailable("block range".to_owned()))?;
        if rendered.bytes() != removed {
            // The block points elsewhere (P moved): a conflict, not an update.
            return Err(PreviewError::Unavailable(
                "the include block does not name this P".to_owned(),
            ));
        }
        let offset = u64::try_from(block.range.start).map_err(|_| PreviewError::TooLarge)?;
        let len = u64::try_from(removed.len()).map_err(|_| PreviewError::TooLarge)?;
        let content = rendered.into_splice(offset, len, Some(Sha256Hex::of(removed)));
        let name = file_name(user)?;
        let staged = self.staged_name(&name)?;
        let sha = Sha256Hex::of(bytes);
        Ok(FileStep {
            role: FileRole::UserSsh,
            path: path_string(user)?,
            base: Base::Present {
                sha256: sha.clone(),
            },
            target: Target::Present { sha256: sha },
            content,
            commit: false,
            displaced_name: Some(self.displaced_name(&name, &staged)),
            staged_name: Some(staged),
        })
    }

    /// A target-absent step for the cleaner, or `None` when the file is absent.
    fn removal_step(
        &mut self,
        role: FileRole,
        path: &Path,
    ) -> Result<Option<FileStep>, PreviewError> {
        let Some(current) = read_file(path)? else {
            return Ok(None);
        };
        self.change(role, path, Some(&current), None);
        // The base is the recorded digest, what the cleaner may remove (§5.8). A managed
        // file whose content is no longer that is kept as `<name>.hm-conflict-<gen>`
        // once the rollback committed (§5.5; `apply::keep_edited_managed`).
        let current_sha = Sha256Hex::of(&current);
        let recorded = self.recorded(role, path);
        if matches!(role, FileRole::ManagedSsh | FileRole::GitManaged)
            && recorded.as_ref().is_some_and(|r| *r != current_sha)
        {
            let name = file_name(path)?;
            self.findings.push(Finding {
                code: finding::PROJECTION_EDITED.to_owned(),
                severity: FindingSeverity::Problem,
                subject: ResourceRef {
                    kind: "projection".to_owned(),
                    id: None,
                },
                level: ProbeLevel::Static,
                provenance: None,
                message: format!(
                    "{} was edited after Heimdall wrote it; the rollback keeps it as {name}.hm-conflict-{}",
                    self.display(path),
                    self.generation
                ),
                next: NextAction::for_code(Code::ConfigConflict),
                reason: Some(conflict_reason(ConflictKind::ManagedFileEdited).to_owned()),
            });
        }
        Ok(Some(FileStep {
            role,
            path: path_string(path)?,
            base: Base::Present {
                sha256: recorded.unwrap_or(current_sha),
            },
            target: Target::Absent,
            content: StepContent::absent(),
            commit: false,
            staged_name: None,
            displaced_name: None,
        }))
    }

    fn change(&mut self, role: FileRole, path: &Path, before: Option<&[u8]>, after: Option<&[u8]>) {
        let role = match role {
            FileRole::UserSsh => ProjectionFileRole::UserSsh,
            FileRole::ManagedSsh => ProjectionFileRole::ManagedSsh,
            FileRole::Key => ProjectionFileRole::KeyFile,
            FileRole::GitInclude => ProjectionFileRole::GitInclude,
            FileRole::GitManaged => ProjectionFileRole::GitManaged,
            FileRole::GitLock => return,
        };
        // ADR-0007 §12.34 item 7: the removal of one of Heimdall's own files (P, P_git, a
        // key file) is one summary line; every other change shows its diff whole.
        let diff = match (before, after) {
            (Some(removed), None) if is_own_file(role) => {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                OwnRemoval::of(name, removed).to_string()
            }
            _ => line_diff(before.unwrap_or_default(), after.unwrap_or_default()),
        };
        self.changes.push(FileChange {
            role,
            path_display: self.display(path),
            before_sha256: before.map(|b| Sha256Hex::of(b).to_string()),
            after_sha256: after.map(|b| Sha256Hex::of(b).to_string()),
            diff,
        });
    }

    fn display(&self, path: &Path) -> String {
        let home = &self.config.paths.account_home;
        let shown = match path.strip_prefix(home) {
            Ok(rest) if !home.as_os_str().is_empty() => format!("~/{}", rest.display()),
            _ => path.display().to_string(),
        };
        shown.replace('\\', "/")
    }

    fn manual(&mut self, reason: &str) {
        if !self.manual.iter().any(|r| r == reason) {
            self.manual.push(reason.to_owned());
        }
    }

    fn conflict(&mut self, kind: ConflictKind, lines: Option<&[u32]>) {
        let code = match kind {
            ConflictKind::MarkerEdited => finding::MARKER_EDITED,
            ConflictKind::IncludeConditional => finding::INCLUDE_CONDITIONAL,
            ConflictKind::ManagedFileEdited => finding::PROJECTION_EDITED,
            _ => "marker_duplicated",
        };
        let lines = lines
            .map(|l| l.iter().map(u32::to_string).collect::<Vec<_>>().join(", "))
            .filter(|s| !s.is_empty());
        let message = match &lines {
            Some(l) => format!("the Heimdall block needs attention (lines {l})"),
            None => "the Heimdall block needs attention".to_owned(),
        };
        self.findings.push(Finding {
            code: code.to_owned(),
            severity: FindingSeverity::Problem,
            subject: ResourceRef {
                kind: "projection".to_owned(),
                id: None,
            },
            level: ProbeLevel::Static,
            provenance: None,
            message,
            next: NextAction::for_code(Code::ConfigConflict),
            reason: Some(conflict_reason(kind).to_owned()),
        });
    }

    // --- consent (ADR-0007 §5.2) -------------------------------------------------------

    /// The aliases the plan affects: those whose rendered section in effect changes
    /// (added, changed or removed), or, for a rollback, every alias P renders. For a
    /// plan that edits the user file, P is in effect only through a Heimdall block in
    /// it. A manual plan does not edit it, and whether the user configuration
    /// activates P is the evaluation's to establish, so every P change is affected
    /// (ADR-0007 §12.21 item 1).
    fn affected_aliases(&self) -> (BTreeMap<String, Vec<u8>>, BTreeMap<String, Vec<u8>>) {
        if self.ssh_manual {
            let now = self.p_now.as_deref().map(sections).unwrap_or_default();
            let after = self
                .p_after
                .as_deref()
                .map_or_else(|| now.clone(), sections);
            return (now, after);
        }
        let has_block = |u: Option<&[u8]>| u.is_some_and(|u| !edit::find_blocks(u).is_empty());
        let now = if has_block(self.user_now.as_deref()) {
            self.p_now.as_deref().map(sections).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        if self.ssh_all_affected {
            let after = if self.ssh_repair {
                now.clone()
            } else {
                BTreeMap::new()
            };
            return (now, after);
        }
        let after_user = self.user_after.as_deref().or(self.user_now.as_deref());
        let after = match &self.p_after {
            Some(p) if has_block(after_user) => sections(p),
            Some(_) => BTreeMap::new(),
            None => now.clone(),
        };
        (now, after)
    }

    /// ADR-0007 §5.2 through `sshconf::consent`: each affected item's behaviour now,
    /// after the plan and on restore (its section removed now: the user file without
    /// its blocks and P absent), statically and with nothing executed, against the
    /// stored consent. Each state covers every invocation profile (§12.21 item 2,
    /// [`Builder::behavior`]). A consented state counts only for an item the
    /// projection record still manages, never for an empty record (§12.22 item 2), so
    /// a first adoption, or an alias added again after a rollback, always needs a
    /// decision: such an alias has a reason even when its states are equal, manual
    /// mode included (§12.24 item 6, [`always_needs_decision`]). So does an alias whose
    /// section a manual plan changes, P active or not (§12.26 item 5). When a manual
    /// plan could not read the user configuration, every alias state is undetermined
    /// (§12.21 item 1).
    fn consent(&self) -> Decided {
        let (now, after) = self.affected_aliases();
        let affected: Vec<String> = now
            .keys()
            .chain(after.keys())
            .filter(|n| self.ssh_all_affected || now.get(*n) != after.get(*n))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let managed = |item: ProjectionItem| live_item(self.spec, item);
        let consented = |id: &ItemId| {
            self.spec
                .consent
                .items
                .get(id)
                .map(|c| consent::ConsentedStates {
                    managed: c.managed.clone(),
                    restore: c.restore.clone(),
                })
        };
        let mut out = Decided::default();
        let mut items = Vec::new();
        let mut kept: Vec<(ItemId, BehaviorState, BehaviorState)> = Vec::new();
        // Aliases that always need a decision: those the plan adds that no live record
        // consents to (§12.24 item 6), and those whose section a manual plan changes
        // (§12.26 item 5).
        let mut always: BTreeSet<String> = BTreeSet::new();
        if !affected.is_empty() {
            let paths = &self.config.paths;
            let source =
                BoundedSource::new(paths.clone(), self.config.env.clone(), Limits::default());
            let user = paths.user_config.clone();
            let mut planned = BTreeMap::new();
            if let Some(b) = &self.user_after {
                planned.insert(user.clone(), Some(b.clone()));
            }
            if let Some(b) = &self.p_after {
                planned.insert(self.config.managed_ssh_path(), Some(b.clone()));
            }
            let mut restored = BTreeMap::new();
            if let Some(b) = self.user_after.as_ref().or(self.user_now.as_ref()) {
                restored.insert(user, Some(without_blocks(b)));
            }
            // Its section removed: also when the user configuration names P another
            // way (a hand-written Include, in manual mode).
            restored.insert(self.config.managed_ssh_path(), None);
            let after_source = Overlay {
                inner: &source,
                files: &planned,
            };
            let restore_source = Overlay {
                inner: &source,
                files: &restored,
            };
            let ssh = managed(ProjectionItem::Ssh);
            // Activation unknown (§12.21 item 1): no state of an alias is determined.
            let known = |s: BehaviorState| BehaviorState {
                determined: s.determined && !self.user_unreadable,
                ..s
            };
            for name in &affected {
                let id = ItemId::alias(name);
                let current = known(self.behavior(&source, name));
                let after_state = known(self.behavior(&after_source, name));
                let restore = known(self.behavior(&restore_source, name));
                out.digest_view.push(serde_json::json!([
                    id.0,
                    current.digest,
                    current.determined,
                    after_state.digest,
                    after_state.determined,
                    restore.digest,
                    restore.determined,
                ]));
                if after.contains_key(name) {
                    out.restore.push(ItemRestore {
                        item: id.clone(),
                        digest: restore.digest.clone(),
                    });
                    out.aliases
                        .push(alias_preview(name, &current, &after_state, &restore));
                    kept.push((id.clone(), after_state.clone(), restore.clone()));
                    if now.contains_key(name) {
                        out.changed.push(name.clone());
                        // §12.26 item 5: P active or not, the owner's own Include
                        // activates a manual plan's change without another decision.
                        if self.ssh_manual && now.get(name) != after.get(name) {
                            always.insert(name.clone());
                        }
                    } else {
                        out.added.push(name.clone());
                    }
                } else {
                    out.removed.push(name.clone());
                }
                let consented_states = ssh
                    .filter(|r| r.aliases.contains(name))
                    .and_then(|_| consented(&id));
                if consented_states.is_none() && after.contains_key(name) && !now.contains_key(name)
                {
                    always.insert(name.clone());
                }
                items.push(consent::ConsentItem {
                    item: consent::ConsentItemId(name.clone()),
                    current,
                    after: after_state,
                    consented: consented_states,
                });
            }
        }
        if let Some((before, after_selection)) = &self.git_selection {
            let id = ItemId::git_selection();
            let current = selection_state(before);
            let after_state = selection_state(after_selection);
            out.digest_view.push(serde_json::json!([
                id.0,
                current.digest,
                current.determined,
                after_state.digest,
                after_state.determined,
            ]));
            if !self.git_selection_is_rollback() {
                kept.push((id.clone(), after_state.clone(), current.clone()));
            }
            items.push(consent::ConsentItem {
                item: consent::ConsentItemId(id.0.clone()),
                current,
                after: after_state,
                consented: managed(ProjectionItem::Git).and_then(|_| consented(&id)),
            });
        }
        out.need = always_needs_decision(consent::classify(&items), &items, &always);
        // Placeholder decision: `apply` records the intent's approval in its place.
        let decision = DecisionId::from_random_bytes([0; 16]);
        for (id, managed_state, restore) in kept {
            out.record.items.insert(
                id,
                ConsentedStates {
                    managed: managed_state,
                    restore,
                    decision: decision.clone(),
                },
            );
        }
        out
    }

    /// Whether the planned Git selection change is a rollback (nothing is consented
    /// to for an item that the plan removes).
    fn git_selection_is_rollback(&self) -> bool {
        self.steps.iter().any(|s| {
            s.role == FileRole::GitInclude
                && matches!(s.content.view(), StepContentView::Splice { remove_len, .. } if remove_len > 0)
        })
    }

    /// One alias's consent behaviour state under `source`, evaluated statically (U2's
    /// evaluator; nothing executes) under every invocation profile, `Shell`,
    /// `Exec(None)` and `Subsystem("sftp")`: the `heimdall.behavior.v3` digest over the
    /// ordered per-profile digests, determined only when every profile is (ADR-0007
    /// §12.21 item 2, `relevant::consent_behavior_state`).
    fn behavior(&self, source: &dyn ConfigSource, alias: &str) -> BehaviorState {
        let paths = &self.config.paths;
        let mut roots = Roots::new(
            Some(paths.user_config.clone()),
            Some(paths.system_config.clone()),
        );
        roots.managed = Some(self.config.managed_ssh_path());
        // ADR-0007 §12.25 item 2 (T02): the account database, never the environment
        // (`Builder::account`). §12.28 item 3: without it, only the conditions that
        // read the account are undetermined, so a state they reach is not determined.
        let query = Query {
            host: alias.to_owned(),
            user: None,
            local_user: self.account.clone(),
            client_version: self
                .config
                .clients
                .selected(ClientKind::Ssh)
                .and_then(|c| c.version)
                .unwrap_or(OpenSshVersion::MINIMUM),
            // Replaced by each profile in turn.
            invocation: Invocation::Shell,
        };
        let mut set = ConfigSet::new();
        consent_behavior_state(&mut set, source, &roots, &query, &Limits::default())
    }

    // --- the plan ---------------------------------------------------------------------

    fn finish(self, intent: PreviewIntent) -> Result<ProjectionPlan, PreviewError> {
        let total: usize = self.steps.iter().map(|s| s.content.stored_len()).sum();
        let keys = self
            .steps
            .iter()
            .filter(|s| s.role == FileRole::Key)
            .count();
        if total > bounds::INTENT_CONTENT_MAX || keys > bounds::KEY_FILES_MAX {
            return Err(PreviewError::TooLarge);
        }
        let mode = if self.manual.is_empty() {
            SetupMode::Automatic
        } else {
            SetupMode::Manual
        };
        let writes = !self.steps.is_empty();
        let git_applicable = self
            .git
            .as_ref()
            .is_some_and(|g| g.applicability == GitApplicability::Applicable);
        // ADR-0007 §5.2: the decision follows the behaviour of the affected items, not
        // the files written (§12.17 item 8).
        let decided = if writes {
            self.consent()
        } else {
            Decided::default()
        };
        let consent = ConsentNeed {
            decision_required: decided.need.required,
            reasons: decided
                .need
                .reasons
                .iter()
                .map(|r| ConsentReason {
                    item: r.item.0.clone(),
                    kind: match r.kind {
                        consent::ConsentReasonKind::NewState => ConsentReasonKind::NewState,
                        consent::ConsentReasonKind::ExposesInherited => {
                            ConsentReasonKind::ExposesInherited
                        }
                        consent::ConsentReasonKind::UndeterminedState => {
                            ConsentReasonKind::UndeterminedState
                        }
                        consent::ConsentReasonKind::GitSelectionChanged => {
                            ConsentReasonKind::GitSelectionChanged
                        }
                    },
                })
                .collect(),
        };
        let plan_digest = plan_digest(
            &intent,
            self.generation,
            mode,
            &self.manual,
            &self.steps,
            self.git.as_ref(),
            Reported {
                findings: &self.findings,
                behavior: &decided.digest_view,
            },
        )?;
        let diff_text = full_diff(&self.changes);
        let rollback = matches!(intent, PreviewIntent::Rollback { .. });
        let summary = decided.need.required.then(|| ProjectionSummary {
            intent: match intent {
                PreviewIntent::Rollback { .. } => SummaryIntent::Rollback,
                PreviewIntent::Repair { .. } => SummaryIntent::Repair,
                _ => SummaryIntent::Apply,
            },
            added_aliases: if rollback {
                Vec::new()
            } else {
                decided.added.clone()
            },
            changed_aliases: decided.changed.clone(),
            removed_aliases: if rollback {
                self.removed.clone()
            } else {
                decided.removed.clone()
            },
            files: self
                .changes
                .iter()
                .map(|c| c.path_display.clone())
                .collect(),
            git: git_applicable || self.steps.iter().any(|s| s.role == FileRole::GitInclude),
            restore: decided.restore.clone(),
            diff_text,
        });
        let view = SetupPlan {
            plan_digest,
            intent,
            mode,
            manual_reasons: self.manual,
            files: self.changes,
            git: self.git,
            // ADR-0007 §5.1, §12.30 item 7: the restore column comes from the preview
            // itself, for every alias an apply adds or changes (a first adoption's
            // aliases, each with its restore state); a rollback lists none.
            aliases: if rollback {
                Vec::new()
            } else {
                decided.aliases.clone()
            },
            consent,
            unaffected_names_checked: 0,
            findings: self.findings,
        };
        Ok(ProjectionPlan {
            view,
            generation: self.generation,
            consent: if decided.need.required {
                decided.record
            } else {
                ConsentRecord::default()
            },
            files: self.steps,
            summary,
        })
    }
}

/// What the plan reports that its digest binds besides its steps: the findings and
/// the §5.2 behaviour digests.
struct Reported<'a> {
    findings: &'a [Finding],
    behavior: &'a [serde_json::Value],
}

/// ADR-0007 §5.2's result for a plan.
#[derive(Default)]
struct Decided {
    need: consent::ConsentNeed,
    /// The consented states `item.committed` records (when a decision is required).
    record: ConsentRecord,
    /// The restore column.
    restore: Vec<ItemRestore>,
    /// ⟨M02⟩ ADR-0007 §12.30 item 7: each alias the plan adds or changes, with its
    /// before, after and restore states (`SetupPlan.aliases`).
    aliases: Vec<AliasPreview>,
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    /// The behaviour digests the plan digest binds.
    digest_view: Vec<serde_json::Value>,
}

/// A configuration source that reads the planned bytes of the files a plan changes
/// (`Some`), or no file (`None`), and every other file as it is.
struct Overlay<'a> {
    inner: &'a BoundedSource,
    files: &'a BTreeMap<PathBuf, Option<Vec<u8>>>,
}

impl ConfigSource for Overlay<'_> {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        match self.files.get(path) {
            Some(Some(bytes)) => Ok(SourceBytes {
                canonical: path.to_path_buf(),
                bytes: bytes.clone(),
            }),
            Some(None) => Err(SourceError::NotFound),
            None => self.inner.read(path),
        }
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        let mut found = match self.inner.glob(pattern) {
            Ok(found) => found,
            Err(SourceError::NotFound) => Vec::new(),
            Err(e) => return Err(e),
        };
        found.retain(|p| !matches!(self.files.get(p), Some(None)));
        if matches!(self.files.get(pattern), Some(Some(_))) && !found.iter().any(|p| p == pattern) {
            found.push(pattern.to_path_buf());
        }
        Ok(found)
    }

    fn account_home(&self) -> &Path {
        self.inner.account_home()
    }

    fn user_dir(&self) -> &Path {
        self.inner.user_dir()
    }

    fn system_dir(&self) -> &Path {
        self.inner.system_dir()
    }

    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }

    fn include_home(&self) -> Option<&Path> {
        self.inner.include_home()
    }
}

/// Each `Host <name>` section of Heimdall's rendered P, by name, without the blank
/// lines that separate sections.
/// ⟨M03⟩ The command that holds a managed alias's slot, as the `slot_free` disclosure
/// names it (ADR-0008 D10 item 2: `heimdall run …`; `heimdall bind materialize` is
/// U12's and is not offered until it exists).
#[must_use]
pub fn slot_free_command(alias: &str) -> String {
    format!("heimdall run --profile <profile> -- ssh {alias}")
}

/// ⟨M03⟩ The `slot_free` disclosure of a managed alias (ADR-0008 D10 item 2, §17.4 item
/// 12): ordinary `ssh <alias>` works only while a binding holds the alias's slot, with
/// the command that holds one ([`slot_free_command`]). The `ApplyProjection` preview
/// lists it for every managed alias it renders; the doctor reports the same finding for
/// an alias whose slot is free.
#[must_use]
pub fn slot_free_disclosure(
    alias: &str,
    destination: &heimdall_contract::ids::DestinationId,
) -> Finding {
    Finding {
        code: heimdall_contract::doctor::finding::SLOT_FREE.to_owned(),
        severity: FindingSeverity::Info,
        subject: ResourceRef {
            kind: "destination".to_owned(),
            id: Some(destination.to_string()),
        },
        level: ProbeLevel::Static,
        provenance: None,
        message: format!(
            "ordinary `ssh {alias}` works only while a binding holds this alias's managed \
             slot; `{}` holds one while it runs (automatic activation is not available)",
            slot_free_command(alias)
        ),
        next: NextAction {
            action: "none".to_owned(),
            ..NextAction::default()
        },
        reason: None,
    }
}

/// ⟨M03⟩ ADR-0008 D8 item 6 (F15): the graceful text for an `exclusive` selection
/// (spec §6.6).
pub const DEADLINE_GRACEFUL_EXCLUSIVE: &str =
    "New connections stop at the deadline; existing sessions may stay connected.";
/// ⟨M03⟩ ADR-0008 D8 item 6: the graceful text for a `not_exclusive` or `undetermined`
/// selection.
pub const DEADLINE_GRACEFUL_NOT_EXCLUSIVE: &str = "New connections through Heimdall's key stop \
     at the deadline. Your other configured identities for this host are not controlled; \
     existing sessions may stay connected.";
/// ⟨M03⟩ ADR-0008 D8 item 2's table: the `strict` text for an `exclusive` selection.
pub const DEADLINE_STRICT_EXCLUSIVE: &str =
    "Connections Heimdall started are closed at the deadline.";
/// ⟨M03⟩ The `strict` text for a `not_exclusive` or `undetermined` selection: D8 item
/// 6's identity sentence with the `strict` table text (U8's composition; U8-Q4).
pub const DEADLINE_STRICT_NOT_EXCLUSIVE: &str = "New connections through Heimdall's key stop \
     at the deadline. Your other configured identities for this host are not controlled. \
     Connections Heimdall started are closed at the deadline.";

/// ⟨M03⟩ ADR-0008 D8 item 6 (F15): the deadline wording of a managed alias, which
/// follows its identity selection (D10 item 6) and the effective `existing` mode. Only
/// `exclusive` gets the unqualified text; `not_exclusive` and `undetermined` name the
/// identities Heimdall does not control. `connect` and `run` notices use it.
#[must_use]
pub fn deadline_wording(
    selection: heimdall_contract::provider::IdentitySelection,
    existing: heimdall_contract::managed::ExistingConnectionsMode,
) -> &'static str {
    use heimdall_contract::managed::ExistingConnectionsMode;
    use heimdall_contract::provider::IdentitySelection;
    let exclusive = selection == IdentitySelection::Exclusive;
    match (existing, exclusive) {
        (ExistingConnectionsMode::Strict, true) => DEADLINE_STRICT_EXCLUSIVE,
        (ExistingConnectionsMode::Strict, false) => DEADLINE_STRICT_NOT_EXCLUSIVE,
        (_, true) => DEADLINE_GRACEFUL_EXCLUSIVE,
        (_, false) => DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
    }
}

fn sections(p: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in p.split_inclusive(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"Host ") {
            let name = String::from_utf8_lossy(rest).trim().to_owned();
            out.insert(name.clone(), line.to_vec());
            current = Some(name);
        } else if let Some(name) = &current
            && !line.iter().all(u8::is_ascii_whitespace)
            && let Some(section) = out.get_mut(name)
        {
            section.extend_from_slice(line);
        }
    }
    out
}

/// ⟨M02⟩ ADR-0007 §12.30 item 7: one managed alias of a plan, with its behaviour now,
/// after the plan and on restore (its section removed now: §5.1's restore column), each
/// as its behaviour digest. The directives are not listed (the digests are what the plan
/// digest and the consent bind), so for a first adoption the restore state is the
/// alias's state without Heimdall's section, with no directive of its own.
fn alias_preview(
    alias: &str,
    current: &BehaviorState,
    after: &BehaviorState,
    restore: &BehaviorState,
) -> AliasPreview {
    let summary = |s: &BehaviorState| BehaviorSummary {
        digest: s.digest.as_str().to_owned(),
        directives: Vec::new(),
    };
    AliasPreview {
        alias: alias.to_owned(),
        kind: AliasKind::Managed,
        before: summary(current),
        after: summary(after),
        restore: Some(summary(restore)),
        changes: Vec::new(),
        inherited: Vec::new(),
        identity_selection: None,
    }
}

/// `bytes` with every Heimdall block removed (the restore column's user file).
fn without_blocks(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let mut blocks = edit::find_blocks(bytes);
    blocks.sort_by_key(|b| std::cmp::Reverse(b.range.start));
    for b in blocks {
        if b.range.end <= out.len() {
            out.drain(b.range);
        }
    }
    out
}

/// ADR-0007 §5.2 ("first adoption, and any new or changed managed alias, always need a
/// decision"), manual mode included (§12.24 item 6, §12.26 item 5): an alias the plan
/// adds to P that no live record consents to, and an alias whose section a manual plan
/// changes, always have a reason, `new_state` when the classification gave them none. A
/// manual plan whose configuration does not activate P yet evaluates the same state
/// before and after (and, for a change, a state the first decision consented to), but
/// the owner's own Include then activates P without another Heimdall decision. `always`
/// names those aliases; each reason keeps the item order of `items`.
fn always_needs_decision(
    classified: consent::ConsentNeed,
    items: &[consent::ConsentItem],
    always: &BTreeSet<String>,
) -> consent::ConsentNeed {
    let mut reasons = Vec::with_capacity(items.len());
    for item in items {
        if let Some(r) = classified.reasons.iter().find(|r| r.item == item.item) {
            reasons.push(r.clone());
        } else if always.contains(&item.item.0) {
            reasons.push(consent::ConsentReason {
                item: item.item.clone(),
                kind: consent::ConsentReasonKind::NewState,
            });
        }
    }
    consent::ConsentNeed {
        required: !reasons.is_empty(),
        reasons,
    }
}

/// The record of `item` when the projection record still manages it (ADR-0007 §12.22
/// item 2). A rollback commits an **empty** `ItemRecord` (no files, no aliases) at its
/// generation, so the generation stays monotonic; such a record is no item, for the
/// SSH item and for Git alike: its files and consent are not read, and re-adoption
/// needs a decision. Only the next generation still counts it ([`preview`]).
fn live_item(spec: &ProjectionSpec, item: ProjectionItem) -> Option<&ItemRecord> {
    spec.record
        .as_ref()
        .and_then(|r| r.items.get(&item))
        .filter(|r| !(r.files.is_empty() && r.aliases.is_empty()))
}

/// Git's SSH selection as a behaviour state: the digest of its canonical form,
/// determined unless its classification is undetermined.
fn selection_state(selection: &GitSshSelection) -> BehaviorState {
    let canonical = serde_json::to_value(selection)
        .ok()
        .and_then(|v| heimdall_contract::canonical::canonical_json(&v).ok())
        .unwrap_or_default();
    BehaviorState {
        digest: Sha256Hex::of(&canonical),
        determined: selection.classification != GitSshClassification::Undetermined,
    }
}

/// Whether the existing directory `dir` holds a quarantine that does not validate
/// (ADR-0007 §5.3 "Enforcement"; a preview never creates one). A missing directory, or
/// one without a quarantine, is not; a directory that cannot be opened is left to the
/// writer's own checks.
fn quarantine_invalid(dir: &Path) -> bool {
    // `validate_existing` rechecks the directory, validates and never creates, so a
    // quarantine removed after any earlier look is not recreated by the preview
    // (W6X-R04, ADR-0007 §12.51 item 4).
    DirHandle::open(dir).is_ok_and(|handle| Quarantine::validate_existing(&handle).is_err())
}

/// The steps of a manual-mode SSH plan: the key files and P, with P (or, when P is
/// unchanged, the last key file) as the item's commit step, so `apply` commits the
/// record the doctor verifies the owner's block against. The user file is never
/// planned.
fn manual_steps(key_steps: Vec<FileStep>, p_step: Option<FileStep>) -> Vec<FileStep> {
    let mut steps = key_steps;
    steps.extend(p_step);
    if let Some(last) = steps.last_mut() {
        last.commit = true;
    }
    steps
}

fn not_applicable(reason: &str, before: GitSshSelection) -> GitConfigChange {
    GitConfigChange {
        applicability: GitApplicability::NotApplicable,
        reason: Some(reason.to_owned()),
        global_file: None,
        previous_values: Vec::new(),
        include_block: None,
        managed_file: None,
        effective_after: before.clone(),
        effective_before: before,
    }
}

/// The manual reason of a `manual_mode` repair: `unmanageable_file` for that conflict,
/// otherwise the conflict's own wire name (`marker_edited`, `include_conditional`, …).
fn manual_for_conflict(kind: ConflictKind) -> String {
    if kind == ConflictKind::UnmanageableFile {
        return manual_reason::UNMANAGEABLE_FILE.to_owned();
    }
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| conflict_reason(kind).to_owned())
}

fn conflict_reason(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::MarkerEdited => "marker_edited",
        ConflictKind::IncludeConditional => "include_conditional",
        ConflictKind::MarkerDuplicated => "marker_duplicated",
        ConflictKind::ManagedFileEdited => "managed_file_edited",
        _ => "config_conflict",
    }
}

/// SHA-256 over the canonical plan (ADR-0007 §5.1). Staged and displaced names and
/// the lock holder's bytes are fixed at admission and are not part of it; every
/// target digest is, so an approval covers every byte the writer will stage.
fn plan_digest(
    intent: &PreviewIntent,
    generation: u64,
    mode: SetupMode,
    manual: &[String],
    steps: &[FileStep],
    git: Option<&GitConfigChange>,
    bound: Reported<'_>,
) -> Result<PlanDigest, PreviewError> {
    let Reported { findings, behavior } = bound;
    let steps: Vec<serde_json::Value> = steps
        .iter()
        .map(|s| {
            let content = match s.content.view() {
                StepContentView::Whole { .. } => serde_json::json!({ "kind": "whole" }),
                StepContentView::Splice {
                    offset,
                    remove_len,
                    removed_sha256,
                    insert,
                } => serde_json::json!({
                    "kind": "splice",
                    "offset": offset,
                    "remove_len": remove_len,
                    "removed_sha256": removed_sha256,
                    "insert_sha256": Sha256Hex::of(insert),
                }),
                StepContentView::Absent => serde_json::json!({ "kind": "absent" }),
                StepContentView::LockHolder { .. } => serde_json::json!({ "kind": "lock_holder" }),
            };
            serde_json::json!({
                "role": s.role,
                "path": s.path,
                "base": s.base,
                "target": s.target,
                "commit": s.commit,
                "content": content,
            })
        })
        .collect();
    let codes: Vec<(&str, Option<&str>)> = findings
        .iter()
        .map(|f| (f.code.as_str(), f.reason.as_deref()))
        .collect();
    let value = serde_json::json!({
        "heimdall_plan": 1,
        "intent": intent,
        "generation": generation,
        "mode": mode,
        "manual_reasons": manual,
        "steps": steps,
        "git": git,
        "findings": codes,
        "behavior": behavior,
    });
    let canonical = heimdall_contract::canonical::canonical_json(&value)
        .map_err(|_| PreviewError::Unavailable("plan not canonical".to_owned()))?;
    Ok(PlanDigest::from_sha256(Sha256::digest(&canonical).into()))
}

/// The 1-based line of byte `offset`.
fn line_of(bytes: &[u8], offset: usize) -> u32 {
    let n = bytes
        .get(..offset)
        .map_or(0, |b| b.iter().filter(|c| **c == b'\n').count());
    u32::try_from(n + 1).unwrap_or(u32::MAX)
}

/// What [`Builder::search_b_git`] found.
enum BGitSearch {
    /// The global file to remove B_git from, with its bytes.
    At(PathBuf, Vec<u8>),
    /// No global file can be resolved: nothing is planned.
    Nothing,
    /// More than one block: manual mode.
    Ambiguous,
}

/// The line ending of the found block (from its first line).
fn block_newline(bytes: &[u8], block: &FoundBlock) -> Newline {
    bytes
        .get(block.range.clone())
        .and_then(edit::detect_newline)
        .unwrap_or(Newline::Lf)
}

fn file_name(path: &Path) -> Result<String, PreviewError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
        .ok_or_else(|| PreviewError::Unavailable("a file path has no name".to_owned()))
}

fn path_string(path: &Path) -> Result<String, PreviewError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| PreviewError::Unavailable("a path is not UTF-8".to_owned()))
}

/// The file's bytes, `None` when it does not exist. Bounded; a read failure is a
/// preview failure (nothing is planned over a file that cannot be read).
fn read_file(path: &Path) -> Result<Option<Vec<u8>>, PreviewError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PreviewError::Unavailable(format!("{:?}", e.kind()))),
        Ok(_) => {}
    }
    crate::fs::read_bounded(path, READ_MAX)
        .map(|s| Some(s.bytes))
        .map_err(|e| PreviewError::Unavailable(format!("read: {e:?}")))
}

/// A line diff: removed lines with `-`, added lines with `+`, the common prefix and
/// suffix omitted. Display only. It is never cut: a diff beyond
/// [`heimdall_contract::setup::MAX_DIFF_BYTES`] makes the application refuse the plan
/// (`plan_too_large`, ADR-0007 §12.32 item 5), so no client is shown part of a diff. (The
/// removal of a file of Heimdall's own is not a line diff: [`OwnRemoval`].)
fn line_diff(before: &[u8], after: &[u8]) -> String {
    let b: Vec<&[u8]> = before.split_inclusive(|c| *c == b'\n').collect();
    let a: Vec<&[u8]> = after.split_inclusive(|c| *c == b'\n').collect();
    let prefix = b.iter().zip(&a).take_while(|(x, y)| x == y).count();
    let suffix = b[prefix..]
        .iter()
        .rev()
        .zip(a[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let mut out = String::new();
    for (sign, lines) in [
        ('-', &b[prefix..b.len() - suffix]),
        ('+', &a[prefix..a.len() - suffix]),
    ] {
        for l in lines {
            out.push(sign);
            out.push_str(&String::from_utf8_lossy(l));
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

/// Every change's diff under its path header, whole (ADR-0007 §12.32 item 5): the decision
/// summary's `diff_text`. The application refuses a plan whose text exceeds
/// [`ProjectionSummary::MAX_DIFF_TEXT`] before it is shown or journaled; the summary lines
/// of removed files of Heimdall's own ([`OwnRemoval`]) are not counted (§12.34 item 7).
fn full_diff(changes: &[FileChange]) -> String {
    let mut out = String::new();
    for c in changes {
        out.push_str(FILE_HEADER_PREFIX);
        out.push_str(&c.path_display);
        out.push('\n');
        out.push_str(&c.diff);
    }
    out
}

/// What starts a file's heading line in the decision summary's text ([`full_diff`]).
const FILE_HEADER_PREFIX: &str = "--- ";

/// Whether `role` is a file of Heimdall's own (P, a key file, P_git), as against the
/// files the owner owns (the user SSH configuration, the global Git file).
#[must_use]
pub fn is_own_file(role: ProjectionFileRole) -> bool {
    matches!(
        role,
        ProjectionFileRole::ManagedSsh
            | ProjectionFileRole::KeyFile
            | ProjectionFileRole::GitManaged
    )
}

/// ADR-0007 §12.34 item 7: the diff of a plan that **removes** one of Heimdall's own files
/// (P, P_git, a key file) is this one line, not the removed content, so a rollback or an
/// uninstall is never refused for the size of a file whose content the owner was shown in
/// full when they approved it. Files the owner owns are always shown in full.
///
/// The line is `~ removed <name>: <lines> lines, sha256 <hex>`: the file's name, its
/// number of lines and the SHA-256 of the removed content. Clients render it as the
/// removal of a file of Heimdall's own ([`OwnRemoval::parse`] reads it back); every line of
/// a real diff starts with `-` or `+`, so the mark cannot be mistaken for content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnRemoval {
    /// The file's name (no directory).
    pub name: String,
    /// How many lines the removed content has.
    pub lines: usize,
    /// SHA-256 of the removed content, lowercase hex.
    pub sha256: String,
}

impl OwnRemoval {
    /// What starts the line.
    pub const MARK: &'static str = "~ removed ";

    /// The summary of removing `name`, whose content is `content`.
    #[must_use]
    pub fn of(name: &str, content: &[u8]) -> Self {
        let breaks = content.iter().filter(|b| **b == b'\n').count();
        let unterminated = usize::from(content.last().is_some_and(|b| *b != b'\n'));
        Self {
            // The name is a file name of Heimdall's own; a control character is never in
            // one, but nothing here can start a second line.
            name: name
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
            lines: breaks + unterminated,
            sha256: Sha256Hex::of(content).to_string(),
        }
    }

    /// The summary [`OwnRemoval`]'s `Display` wrote as `line` (without its newline), if it
    /// is one.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let rest = line.strip_prefix(Self::MARK)?;
        let (name, tail) = rest.rsplit_once(": ")?;
        let (count, sha256) = tail.split_once(", sha256 ")?;
        let lines = count
            .strip_suffix(" lines")
            .or_else(|| count.strip_suffix(" line"))?
            .parse()
            .ok()?;
        let digest = sha256.len() == 64
            && sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        digest.then(|| Self {
            name: name.to_owned(),
            lines,
            sha256: sha256.to_owned(),
        })
    }
}

impl std::fmt::Display for OwnRemoval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unit = if self.lines == 1 { "line" } else { "lines" };
        writeln!(
            f,
            "{}{}: {} {unit}, sha256 {}",
            Self::MARK,
            self.name,
            self.lines,
            self.sha256
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::ids::EnvironmentId;

    use super::*;
    use crate::env::Platform;
    use crate::paths::SshPaths;

    fn world() -> (ProjectionConfig, ProjectionSpec) {
        let paths = SshPaths::with_test_override(
            PathBuf::from("/scratch/home"),
            PathBuf::from("/scratch/etc-ssh"),
        );
        let config = ProjectionConfig::new(
            paths,
            Platform::current(),
            PathBuf::from("/scratch/home/.config/heimdall"),
        );
        let spec = ProjectionSpec {
            environment: EnvironmentId::from_random_bytes([3; 16]),
            aliases: Vec::new(),
            record: None,
            consent: ConsentRecord::default(),
        };
        (config, spec)
    }

    /// ADR-0007 §12.25 item 2 (T02): with the local account not established, an
    /// alias's consent state is undetermined when its configuration reads the account
    /// (`Match localuser`), in any profile, and determined otherwise; with the
    /// account known, the same configuration is determined.
    #[test]
    fn an_unknown_local_account_makes_a_state_that_reads_it_undetermined() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let paths = SshPaths::with_test_override(home.clone(), dir.path().join("etc-ssh"));
        let config = ProjectionConfig::new(
            paths.clone(),
            Platform::current(),
            dir.path().join("config"),
        );
        let (_, spec) = world();
        let source = BoundedSource::new(paths, crate::env::Env::default(), Limits::default());
        let state = |text: &str, account: Option<&str>| {
            std::fs::write(home.join(".ssh").join("config"), text).unwrap();
            let mut b = Builder::new(&config, &spec, 1);
            b.account = account.map(str::to_owned);
            b.behavior(&source, "work")
        };
        let reads = "Match localuser hm-fixture-account\n  ForwardAgent yes\n";
        let exec_only = "Match sessiontype exec\nInclude ~/%u.conf\n";
        assert!(!state(reads, None).determined);
        assert!(
            !state(exec_only, None).determined,
            "an exec-only Include of %u"
        );
        assert!(state(reads, Some("hm-fixture-account")).determined);
        assert!(state("Host work\n  ForwardAgent yes\n", None).determined);
    }

    /// The recipe of ADR-0007 §12.18 item 3 as amended by §12.20 item 3, restated
    /// independently: the plan-input digest, then SHA-256 over the length-prefixed
    /// fields, of which the marker is the first 64 bits in §2's form `hm-<16 hex>`.
    fn recipe(
        spec: &ProjectionSpec,
        reads: &[(FileRole, &str, Base)],
        generation: u64,
        role: FileRole,
    ) -> String {
        let reads: Vec<serde_json::Value> = reads
            .iter()
            .map(|(r, path, base)| serde_json::json!([r, path, base]))
            .collect();
        let inputs = serde_json::json!({
            "heimdall_marker_inputs": 1,
            "spec": serde_json::to_value(spec).unwrap(),
            "reads": reads,
        });
        let inputs = Sha256Hex::of(&heimdall_contract::canonical::canonical_json(&inputs).unwrap());
        let generation = generation.to_string();
        let mut h = Sha256::new();
        for field in [
            b"heimdall.marker.v1".as_slice(),
            generation.as_bytes(),
            role.as_str().as_bytes(),
            inputs.as_str().as_bytes(),
        ] {
            h.update((field.len() as u64).to_be_bytes());
            h.update(field);
        }
        let digest = h.finalize();
        let first_64: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        format!("hm-{first_64}")
    }

    /// ADR-0007 §12.20 item 3: the derived marker is the first 64 bits of the derived
    /// digest, rendered as `hm-<16 hex>` (§2), for the SSH and the Git block; the same
    /// inputs give the same marker, and another generation, role or read gives another.
    #[test]
    fn derived_marker_is_the_first_64_bits_as_rendered() {
        let (config, spec) = world();
        let user = (
            FileRole::UserSsh,
            "/scratch/home/.ssh/config",
            Base::Present {
                sha256: Sha256Hex::of(b"Host personal\n"),
            },
        );
        for role in [FileRole::UserSsh, FileRole::GitInclude] {
            let mut b = Builder::new(&config, &spec, 7);
            b.note(user.0, Path::new(user.1), Some(b"Host personal\n"));
            let marker = b.derived_marker(role).unwrap();
            let want = recipe(&spec, std::slice::from_ref(&user), 7, role);
            assert_eq!(marker.as_str(), want, "{role:?}");
            assert_eq!(marker.as_str().len(), "hm-".len() + 16, "64 bits, 16 hex");
            assert_eq!(b.derived_marker(role).unwrap(), marker, "reproducible");
            let mut other_generation = Builder::new(&config, &spec, 8);
            other_generation.note(user.0, Path::new(user.1), Some(b"Host personal\n"));
            assert_ne!(other_generation.derived_marker(role).unwrap(), marker);
            let mut other_read = Builder::new(&config, &spec, 7);
            other_read.note(user.0, Path::new(user.1), Some(b"Host other\n"));
            assert_ne!(other_read.derived_marker(role).unwrap(), marker);
        }
        let mut b = Builder::new(&config, &spec, 7);
        b.note(user.0, Path::new(user.1), Some(b"Host personal\n"));
        assert_ne!(
            b.derived_marker(FileRole::UserSsh).unwrap(),
            b.derived_marker(FileRole::GitInclude).unwrap(),
            "the role is an input"
        );
    }

    /// ADR-0007 §12.22 item 2: stored consent for Git's selection counts only while the
    /// record still manages the Git item. An empty Git record (a rolled-back item) is
    /// no item, so a selection change needs a decision again; a live record lets the
    /// same consent count.
    #[test]
    fn empty_git_record_is_absent_for_consent() {
        use heimdall_contract::ids::OperationId;
        use heimdall_domain::projection::{FileIdentity, ProjectionLocator, ProjectionRecord};
        let (config, mut spec) = world();
        let before = GitSshSelection {
            source: GitSshSource::Default,
            scope: None,
            classification: GitSshClassification::BundledMsys,
        };
        let after = GitSshSelection {
            source: GitSshSource::Config,
            scope: Some(GitScope::Global),
            classification: GitSshClassification::VerifiedClient,
        };
        spec.consent.items.insert(
            ItemId::git_selection(),
            ConsentedStates {
                managed: selection_state(&after),
                restore: selection_state(&before),
                decision: DecisionId::from_random_bytes([1; 16]),
            },
        );
        let record = |files: Vec<ProjectionLocator>| ProjectionRecord {
            environment: EnvironmentId::from_random_bytes([3; 16]),
            items: [(
                ProjectionItem::Git,
                ItemRecord {
                    generation: 3,
                    files,
                    aliases: Vec::new(),
                    include_file: None,
                    operation: OperationId::from_random_bytes([2; 16]),
                    committed_at: heimdall_contract::Timestamp::now(),
                },
            )]
            .into_iter()
            .collect(),
        };
        let need = |spec: &ProjectionSpec| {
            let mut b = Builder::new(&config, spec, 4);
            b.git_selection = Some((before.clone(), after.clone()));
            b.consent().need
        };
        spec.record = Some(record(vec![ProjectionLocator {
            role: FileRole::GitManaged,
            path: "/scratch/home/.config/heimdall/gitconfig".to_owned(),
            identity: FileIdentity::Unix {
                dev: 1,
                ino: 2,
                birth: None,
            },
            sha256: Sha256Hex::of(b"[core]\n"),
        }]));
        assert!(
            !need(&spec).required,
            "a live Git record: the consent counts"
        );
        spec.record = Some(record(Vec::new()));
        let n = need(&spec);
        assert!(n.required, "an empty Git record is no item");
        assert_eq!(
            n.reasons[0].kind,
            consent::ConsentReasonKind::GitSelectionChanged
        );
        assert!(live_item(&spec, ProjectionItem::Git).is_none());
    }
}

/// ADR-0007 §12.34 item 7: the summary line of a removed file of Heimdall's own.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod own_removal {
    use super::*;

    #[test]
    fn counts_lines_and_reads_back_what_it_wrote() {
        for (content, lines) in [
            (&b""[..], 0),
            (b"\n", 1),
            (b"x", 1),
            (b"a\nb\n", 2),
            (b"a\nb", 2),
            (b"a\n\nb\n", 3),
        ] {
            let r = OwnRemoval::of("ssh_config", content);
            assert_eq!(r.lines, lines, "{content:?}");
            assert_eq!(r.sha256, Sha256Hex::of(content).to_string());
            let text = r.to_string();
            assert!(text.starts_with("~ removed ssh_config: "), "{text}");
            assert!(
                text.ends_with('\n') && text.matches('\n').count() == 1,
                "{text:?}"
            );
            assert_eq!(OwnRemoval::parse(text.trim_end_matches('\n')), Some(r));
        }
        let one = OwnRemoval::of("k.pub", b"ssh-ed25519 AAAA\n").to_string();
        assert!(one.contains(": 1 line, sha256 "), "{one}");
    }

    #[test]
    fn a_name_never_starts_a_second_line_and_may_hold_a_colon() {
        let r = OwnRemoval::of("a\nb\u{1b}c", b"x");
        assert_eq!(r.name, "a?b?c");
        let colon = OwnRemoval::of("odd: name", b"x\n");
        assert_eq!(OwnRemoval::parse(colon.to_string().trim_end()), Some(colon));
    }

    #[test]
    fn only_the_exact_line_parses() {
        let ok = format!("~ removed p: 3 lines, sha256 {}", "0f".repeat(32));
        assert!(OwnRemoval::parse(&ok).is_some());
        for bad in [
            format!("-~ removed p: 3 lines, sha256 {}", "0f".repeat(32)),
            format!("+~ removed p: 3 lines, sha256 {}", "0f".repeat(32)),
            format!("~ removed p: x lines, sha256 {}", "0f".repeat(32)),
            format!("~ removed p: 3 rows, sha256 {}", "0f".repeat(32)),
            format!("~ removed p: 3 lines, sha256 {}", "0F".repeat(32)),
            format!("~ removed p: 3 lines, sha256 {}", "0f".repeat(31)),
            "~ removed p: 3 lines".to_owned(),
            "~ removed p".to_owned(),
            "--- ~/p".to_owned(),
        ] {
            assert_eq!(OwnRemoval::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn only_heimdalls_own_roles_are_own_files() {
        use ProjectionFileRole as R;
        for (role, own) in [
            (R::ManagedSsh, true),
            (R::KeyFile, true),
            (R::GitManaged, true),
            (R::UserSsh, false),
            (R::GitInclude, false),
        ] {
            assert_eq!(is_own_file(role), own, "{role:?}");
        }
    }
}
