//! The read-only preview (m02-plan U4; ADR-0007 §5.1).
//!
//! The plan carries each step's `StepContent`, built through `Rendered`; staged
//! names are random and fixed in the plan. A plan beyond the content bounds is
//! refused (`PreviewError::TooLarge`, `projection_too_large`).
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
//!   (the Git commit step) at the top of the first-read global file;
//! * `rollback`: the splice that removes B (the commit step), then P and the key files
//!   as target-absent steps for the cleaner; for Git, K, the B_git removal and P_git;
//! * `repair rerender`: as `apply` over the recorded items.
//!
//! A file that fails the §5.3 step-1/2 checks (a symlink or reparse point, a hard
//! link, a foreign owner, a quarantine that does not validate), and a user file with a
//! BOM or CRLF on a client not known to accept it, make the plan manual: no user-file
//! step, the reason listed. Conflicts (a duplicate or edited marker, a conditional
//! block) are findings, and the plan then changes no file.
//!
//! **Consent** (fail-closed reading, escalated by W2-U4c): every plan that changes a
//! file needs an owner decision; only a plan with no file change needs none. The
//! per-item behaviour comparison of §5.2 that would waive some decisions is not
//! computed here, so `consent` (the consented states recorded at commit) is empty and
//! the plan's alias list is empty.

use std::path::{Path, PathBuf};

use heimdall_app::ports::PreviewError;
use heimdall_contract::Code;
use heimdall_contract::doctor::{
    Finding, FindingSeverity, GitScope, GitSshClassification, GitSshSelection, GitSshSource,
    finding,
};
use heimdall_contract::envelope::{NextAction, ResourceRef};
use heimdall_contract::provider::{EndpointKind, ProbeLevel};
use heimdall_contract::setup::{
    ConflictKind, ConsentNeed, ConsentReason, ConsentReasonKind, FileChange, GitApplicability,
    GitConfigChange, GitGlobalFile, PlanDigest, PreviewIntent, ProjectionFileRole, ProjectionItem,
    RepairResolution, SetupMode, SetupPlan, manual_reason,
};
use heimdall_domain::projection::{
    Base, ConsentRecord, FileRole, FileStep, ManagedAliasSpec, ProjectionPlan, ProjectionSpec,
    ProjectionSummary, Rendered, Sha256Hex, StepContent, StepContentView, SummaryIntent, Target,
    bounds,
};
use heimdall_sshconf::edit::{self, BlockPosition, EditRefusal, FoundBlock, IncludeBlock};
use heimdall_sshconf::gitedit;
use heimdall_sshconf::render::{
    self, AliasName, HostName, ManagedAlias, MarkerId, Newline, PathStyle, RenderPath,
};
use sha2::{Digest as _, Sha256};

use super::ProjectionConfig;
use super::apply::random_hex;
use super::git::lock_holder;
use super::replace::{self, DirHandle, Quarantine, ReplaceRefusal};
use crate::clients::ClientKind;
use crate::git::{DefaultGitSsh, observe_global};
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
            let has_git = spec
                .record
                .as_ref()
                .is_some_and(|r| r.items.contains_key(&ProjectionItem::Git));
            if has_git {
                b.plan_git_apply()?;
            }
        }
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
        }
    }

    // --- the SSH item -------------------------------------------------------------------

    fn plan_ssh_apply(&mut self) -> Result<(), PreviewError> {
        let p_path = self.config.managed_ssh_path();
        if self.spec.aliases.len() > bounds::KEY_FILES_MAX {
            return Err(PreviewError::TooLarge);
        }
        if self.managed_edited(FileRole::ManagedSsh, &p_path)? {
            self.conflict(ConflictKind::ManagedFileEdited, None);
            return Ok(());
        }
        let mut aliases = Vec::new();
        let mut key_steps: Vec<FileStep> = Vec::new();
        for a in &self.spec.aliases {
            aliases.push(self.managed_alias(a)?);
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
        let p = render::rendered_managed(&aliases, self.style)
            .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))?;
        if p.bytes().len() > bounds::MANAGED_SSH_MAX {
            return Err(PreviewError::TooLarge);
        }
        let p_step = self.whole_step(FileRole::ManagedSsh, &p_path, p)?;
        self.added = self.spec.aliases.iter().map(|a| a.alias.clone()).collect();

        let user = self.config.paths.user_config.clone();
        let Some(user_bytes) = self.inspect_user_file(&user)? else {
            // Manual mode: P and the key files only; the owner inserts B.
            self.steps.extend(key_steps);
            self.steps.extend(p_step);
            return Ok(());
        };
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
        let p_render = self.render_path(p_path)?;
        let newline = user_bytes
            .and_then(edit::detect_newline)
            .unwrap_or(Newline::Lf);
        let marker = new_marker()?;
        let block = render::rendered_include_block(&marker, &p_render, newline);
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
                    self.steps.extend(key_steps);
                    self.steps.extend(p_step);
                    return Ok(());
                }
                let offset = u64::try_from(plan.offset).map_err(|_| PreviewError::TooLarge)?;
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
                self.steps.extend(key_steps);
                self.steps.extend(p_step);
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
                let p_render = self.render_path(&p_path)?;
                let expected = render::render_include_block(&only.marker, &p_render, newline);
                match edit::plan_remove(&bytes, &only.marker, &expected) {
                    Ok(after) => steps.push(self.removal_splice(
                        FileRole::UserSsh,
                        &user,
                        &bytes,
                        &after,
                        only,
                    )?),
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
        let record = self
            .spec
            .record
            .as_ref()
            .and_then(|r| r.items.get(&ProjectionItem::Ssh));
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

    /// Read the user file and decide whether it can be edited automatically.
    /// `Ok(None)`: manual mode (the reason is recorded). `Ok(Some(None))`: absent.
    fn inspect_user_file(&mut self, user: &Path) -> Result<Option<Option<Vec<u8>>>, PreviewError> {
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
        // An existing quarantine must validate (it is never created by a preview).
        if std::fs::symlink_metadata(parent.join(QUARANTINE)).is_ok()
            && Quarantine::open_or_create(&dir).is_err()
        {
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

    /// The recorded P of the SSH item, when its record names one.
    fn recorded(&self, role: FileRole, path: &Path) -> Option<Sha256Hex> {
        let record = self.spec.record.as_ref()?;
        let item = record.items.get(&role.item())?;
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
        let obs = observe_global(&self.config.env, &self.config.clients, self.config.queries);
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
        let client_path = self.absolute_path(&client.path)?;
        let p_git = render::rendered_git_managed(&client_path)
            .map_err(|e| PreviewError::Unavailable(format!("render: {e}")))?;
        if p_git.bytes().len() > bounds::GIT_MANAGED_MAX {
            return Err(PreviewError::TooLarge);
        }
        let p_git_path = self.config.managed_git_path();
        let p_git_step = self.whole_step(FileRole::GitManaged, &p_git_path, p_git)?;
        let global = file.path.clone();
        let global_bytes = read_file(&global)?;
        let blocks = gitedit::find_blocks(global_bytes.as_deref().unwrap_or_default());
        let mut steps: Vec<FileStep> = Vec::new();
        let mut include_change = None;
        match blocks.as_slice() {
            [] => {
                let target = self.absolute_path(&p_git_path)?;
                let newline = global_bytes
                    .as_deref()
                    .and_then(edit::detect_newline)
                    .unwrap_or(Newline::Lf);
                let marker = new_marker()?;
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
            effective_after: GitSshSelection {
                source: GitSshSource::Config,
                scope: Some(GitScope::Global),
                classification: GitSshClassification::VerifiedClient,
            },
        });
        Ok(())
    }

    fn plan_git_rollback(&mut self) -> Result<(), PreviewError> {
        let p_git_path = self.config.managed_git_path();
        let obs = observe_global(&self.config.env, &self.config.clients, self.config.queries);
        let Some(file) = obs.file else {
            return Ok(());
        };
        let global = file.path;
        let Some(bytes) = read_file(&global)? else {
            return Ok(());
        };
        let blocks = gitedit::find_blocks(&bytes);
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
        let current = read_file(path)?;
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
        let p_render = self.render_path(p_path)?;
        let newline = block_newline(bytes, block);
        let rendered = render::rendered_include_block(&block.marker, &p_render, newline);
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
        Ok(Some(FileStep {
            role,
            path: path_string(path)?,
            base: Base::Present {
                sha256: Sha256Hex::of(&current),
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
        self.changes.push(FileChange {
            role,
            path_display: self.display(path),
            before_sha256: before.map(|b| Sha256Hex::of(b).to_string()),
            after_sha256: after.map(|b| Sha256Hex::of(b).to_string()),
            diff: line_diff(before.unwrap_or_default(), after.unwrap_or_default()),
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
        let consent = ConsentNeed {
            decision_required: writes,
            reasons: if writes {
                self.added
                    .iter()
                    .chain(&self.removed)
                    .map(|a| ConsentReason {
                        item: a.clone(),
                        kind: ConsentReasonKind::NewState,
                    })
                    .chain(git_applicable.then(|| ConsentReason {
                        item: "git".to_owned(),
                        kind: ConsentReasonKind::GitSelectionChanged,
                    }))
                    .collect()
            } else {
                Vec::new()
            },
        };
        let plan_digest = plan_digest(
            &intent,
            self.generation,
            mode,
            &self.manual,
            &self.steps,
            self.git.as_ref(),
            &self.findings,
        )?;
        let diff_text = bounded_diff(&self.changes);
        let rollback = matches!(intent, PreviewIntent::Rollback { .. });
        let summary = writes.then(|| ProjectionSummary {
            intent: match intent {
                PreviewIntent::Rollback { .. } => SummaryIntent::Rollback,
                PreviewIntent::Repair { .. } => SummaryIntent::Repair,
                _ => SummaryIntent::Apply,
            },
            added_aliases: if rollback {
                Vec::new()
            } else {
                self.added.clone()
            },
            changed_aliases: Vec::new(),
            removed_aliases: self.removed.clone(),
            files: self
                .changes
                .iter()
                .map(|c| c.path_display.clone())
                .collect(),
            git: git_applicable || self.steps.iter().any(|s| s.role == FileRole::GitInclude),
            restore: Vec::new(),
            diff_text,
        });
        let view = SetupPlan {
            plan_digest,
            intent,
            mode,
            manual_reasons: self.manual,
            files: self.changes,
            git: self.git,
            aliases: Vec::new(),
            consent,
            unaffected_names_checked: 0,
            findings: self.findings,
        };
        Ok(ProjectionPlan {
            view,
            generation: self.generation,
            consent: ConsentRecord::default(),
            files: self.steps,
            summary,
        })
    }
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
    findings: &[Finding],
) -> Result<PlanDigest, PreviewError> {
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
    });
    let canonical = heimdall_contract::canonical::canonical_json(&value)
        .map_err(|_| PreviewError::Unavailable("plan not canonical".to_owned()))?;
    Ok(PlanDigest::from_sha256(Sha256::digest(&canonical).into()))
}

fn new_marker() -> Result<MarkerId, PreviewError> {
    let hex = random_hex().map_err(|_| PreviewError::Unavailable("no random source".to_owned()))?;
    MarkerId::parse(&format!("hm-{}", &hex[..16]))
        .map_err(|e| PreviewError::Unavailable(format!("marker: {e}")))
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
/// suffix omitted. Display only.
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
    truncate(out, heimdall_contract::setup::MAX_DIFF_BYTES)
}

fn bounded_diff(changes: &[FileChange]) -> String {
    let mut out = String::new();
    for c in changes {
        out.push_str("--- ");
        out.push_str(&c.path_display);
        out.push('\n');
        out.push_str(&c.diff);
    }
    truncate(out, ProjectionSummary::MAX_DIFF_TEXT)
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}
