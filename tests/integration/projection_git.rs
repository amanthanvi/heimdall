//! W2-U4c: the Git item of the projection transaction (m02-plan U4 "Tests (Git,
//! M2-D10)"; ADR-0007 §5.6, rows K0–K4).
//!
//! Every test runs with a scratch `HOME` (`heimdall_testkit::home::ScratchHome`), a
//! scratch system Git file named by `GIT_CONFIG_SYSTEM`, `XDG_CONFIG_HOME` inside the
//! scratch home and `GIT_CONFIG_GLOBAL` unset, and every `git` process the tests run
//! gets exactly that environment (`env_clear`). The account's own Git configuration
//! is never read or written.
//!
//! ADR-0007 §5.6 offers the Git item only where Git's default SSH is its bundled MSYS
//! client (Windows). On this Unix harness the writer's test configuration sets
//! `git_item_any_default`, so the Git transaction itself runs here; the applicability
//! rule is asserted separately (`git_item_not_offered_without_bundled_msys_default`).
//!
//! **Crashes** are in-process (the test hook panics; a fresh writer restarts from the
//! durable receipts), as in `integration_projection`.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt as _;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once, PoisonError};

use heimdall_app::ports::{
    ItemOutcome, ProjectionReceipt, ProjectionWriter, ReconcileError, SinkError, StageSink,
};
use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, IdentityId, OperationId};
use heimdall_contract::setup::{ConflictKind, GitApplicability, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::{
    AdapterIdentity, EffectReceipt, FilePhase, HoldReason, ItemFinish, ItemPhase, LocalReceipt,
    SettleConflictFound, StageReceipt,
};
use heimdall_domain::projection::{
    FileRole, FileStep, ItemCommit, ManagedAliasSpec, ProjectionPlan, ProjectionRecord,
    ProjectionSpec, SetupIntent, Sha256Hex, StepContentView, Target,
};
use heimdall_localenv::clients::{ClientCandidate, ClientInventory, ClientKind, ClientSource};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::{
    LocalProjection, ProjectionConfig, PublicKeySource, ReplaceHook, ReplacePoint,
};
use heimdall_localenv::sys::IdentitySource;
use heimdall_testkit::home::{ScratchHome, find_program};

// --- fixtures (the compact harness of integration_projection) ------------------------

struct Crash;

fn quiet_crashes() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.payload().is::<Crash>() {
                previous(info);
            }
        }));
    });
}

type Action = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
enum Act {
    Crash,
    Run(Action),
}

struct Rule {
    point: ReplacePoint,
    step: Option<u16>,
    act: Act,
    left: usize,
}

#[derive(Default)]
struct Hook {
    rules: Mutex<Vec<Rule>>,
    seen: Mutex<Vec<(ReplacePoint, u16)>>,
}

impl Hook {
    fn new() -> Arc<Hook> {
        Arc::new(Hook::default())
    }

    fn crash(self: &Arc<Self>, point: ReplacePoint, step: Option<u16>) -> Arc<Self> {
        self.push(point, step, Act::Crash, 1);
        Arc::clone(self)
    }

    fn run(
        self: &Arc<Self>,
        point: ReplacePoint,
        step: Option<u16>,
        f: impl Fn() + Send + Sync + 'static,
    ) -> Arc<Self> {
        self.push(point, step, Act::Run(Arc::new(f)), 1);
        Arc::clone(self)
    }

    fn every(self: &Arc<Self>, f: impl Fn(ReplacePoint, u16) + Send + Sync + 'static) -> Arc<Self> {
        let f = Arc::new(f);
        for point in ALL_POINTS {
            let g = Arc::clone(&f);
            let p = *point;
            // A rule per point that fires every time, with the point's step.
            self.rules
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Rule {
                    point: p,
                    step: None,
                    act: Act::Run(Arc::new(move || g(p, u16::MAX))),
                    left: usize::MAX,
                });
        }
        Arc::clone(self)
    }

    fn push(&self, point: ReplacePoint, step: Option<u16>, act: Act, times: usize) {
        self.rules
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Rule {
                point,
                step,
                act,
                left: times,
            });
    }

    fn seen(&self) -> Vec<(ReplacePoint, u16)> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

const ALL_POINTS: &[ReplacePoint] = &[
    ReplacePoint::AfterStage,
    ReplacePoint::AfterValidate,
    ReplacePoint::BeforeExchange,
    ReplacePoint::AfterExchange,
    ReplacePoint::AfterPostValidate,
    ReplacePoint::BeforeCommit,
    ReplacePoint::BeforeRestoreExchange,
    ReplacePoint::AfterRestoreExchange,
    ReplacePoint::BeforeSettleMove,
    ReplacePoint::AfterSettleMove,
    ReplacePoint::BeforeQuarantineRemove,
    ReplacePoint::BeforeLockClaim,
    ReplacePoint::AfterLockClaim,
    ReplacePoint::BeforeRestoreCheck,
    ReplacePoint::AfterSettleCheck,
    ReplacePoint::BeforeLockRelease,
];

impl ReplaceHook for Hook {
    fn at(&self, point: ReplacePoint, step: u16) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((point, step));
        let acts: Vec<Act> = {
            let mut rules = self.rules.lock().unwrap_or_else(PoisonError::into_inner);
            rules
                .iter_mut()
                .filter(|r| r.point == point && r.step.is_none_or(|s| s == step) && r.left > 0)
                .map(|r| {
                    r.left = r.left.saturating_sub(1);
                    r.act.clone()
                })
                .collect()
        };
        for act in acts {
            match act {
                Act::Crash => std::panic::panic_any(Crash),
                Act::Run(f) => f(),
            }
        }
    }
}

#[derive(Default)]
struct KeyBook(Mutex<BTreeMap<String, String>>);

impl PublicKeySource for KeyBook {
    fn public_key(&self, identity: &IdentityId) -> Option<String> {
        self.0.lock().unwrap().get(identity.as_str()).cloned()
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A synthetic `ssh-ed25519` public key over 32 random bytes (no private key exists).
fn synthetic_public_key() -> String {
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend(random::<32>());
    format!("ssh-ed25519 {}", b64(&blob))
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<StageReceipt>>>);

fn durable(local: &LocalReceipt) -> StageReceipt {
    let adapter = AdapterIdentity {
        mechanism: "config_projection".into(),
        instance: "scratch".into(),
    };
    StageReceipt {
        stage: local.stage().to_owned(),
        recorded_at: heimdall_contract::Timestamp::now(),
        effect: if local.effect_is_confirmed() {
            EffectReceipt::Confirmed {
                adapter,
                credential_ref: "projection".into(),
            }
        } else {
            EffectReceipt::Attempted {
                adapter,
                effect_token: "eff_scratch".into(),
            }
        },
        local: Some(local.clone()),
    }
}

impl StageSink for Sink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(durable(receipt));
        Ok(())
    }

    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError> {
        self.append(&LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        })
    }
}

impl Sink {
    fn receipts(&self) -> Vec<StageReceipt> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn kinds(&self) -> Vec<String> {
        self.receipts()
            .iter()
            .filter_map(|r| r.local.as_ref())
            .map(kind_of)
            .collect()
    }

    fn file_phases(&self, step: u16) -> Vec<FilePhase> {
        self.receipts()
            .into_iter()
            .filter_map(|r| match r.local {
                Some(LocalReceipt::File { step: s, phase }) if s == step => Some(phase),
                _ => None,
            })
            .collect()
    }
}

fn kind_of(local: &LocalReceipt) -> String {
    match local {
        LocalReceipt::File { step, phase } => {
            let k = match phase {
                FilePhase::Staged { .. } => "staged",
                FilePhase::Validated { .. } => "validated",
                FilePhase::Exchanged => "exchanged",
                FilePhase::PostValidated { .. } => "post_validated",
                FilePhase::RestoreStarted { .. } => "restore_started",
                FilePhase::Restored => "restored",
                FilePhase::Held { .. } => "held",
                FilePhase::Settling { .. } => "settling",
                FilePhase::Settled { .. } => "settled",
                FilePhase::SettleConflict { .. } => "settle_conflict",
            };
            format!("{step}:{k}")
        }
        LocalReceipt::Item { item, phase } => {
            let i = if *item == ProjectionItem::Ssh {
                "ssh"
            } else {
                "git"
            };
            let k = match phase {
                ItemPhase::Committed { .. } => "committed",
                ItemPhase::RollingBack { .. } => "rolling_back",
                ItemPhase::Finished {
                    outcome: ItemFinish::Applied,
                } => "finished_applied",
                ItemPhase::Finished {
                    outcome: ItemFinish::NotApplied,
                } => "finished_not_applied",
                ItemPhase::Finished {
                    outcome: ItemFinish::Restored,
                } => "finished_restored",
                ItemPhase::Finished { .. } => "finished_other",
            };
            format!("{i}:{k}")
        }
    }
}

/// The scratch world of one Git test.
struct Fx {
    home: ScratchHome,
    keys: Arc<KeyBook>,
    env: EnvironmentId,
    git: PathBuf,
    system: PathBuf,
}

impl Fx {
    fn new() -> Fx {
        quiet_crashes();
        let home = ScratchHome::new();
        std::fs::create_dir(home.root.join("etc-ssh")).unwrap();
        let system = home.root.join("gitconfig-system");
        std::fs::write(&system, b"").unwrap();
        std::fs::write(home.ssh_dir.join("config"), b"Host personal\n    User me\n").unwrap();
        Fx {
            home,
            keys: Arc::default(),
            env: EnvironmentId::from_random_bytes(random()),
            git: find_program("git").expect("git is installed on the harness"),
            system,
        }
    }

    fn home_dir(&self) -> &Path {
        &self.home.git_home
    }

    fn global(&self) -> PathBuf {
        self.home_dir().join(".gitconfig")
    }

    fn xdg_dir(&self) -> PathBuf {
        self.home_dir().join(".config")
    }

    fn lock(&self) -> PathBuf {
        self.home_dir().join(".gitconfig.lock")
    }

    fn p_git(&self) -> PathBuf {
        self.home.config_dir.join("gitconfig")
    }

    /// The environment every Git query and process of the test gets.
    fn git_env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("HOME", self.home_dir().to_str().unwrap().to_owned()),
            (
                "XDG_CONFIG_HOME",
                self.xdg_dir().to_str().unwrap().to_owned(),
            ),
            (
                "GIT_CONFIG_SYSTEM",
                self.system.to_str().unwrap().to_owned(),
            ),
        ]
    }

    fn config(&self) -> ProjectionConfig {
        let paths = SshPaths::with_test_override(
            self.home_dir().to_path_buf(),
            self.home.root.join("etc-ssh"),
        );
        let mut c = ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone());
        let keys: Arc<dyn PublicKeySource> = self.keys.clone();
        c.keys = Some(keys);
        c.env = Env::from_vars(self.git_env());
        c.queries = LocalQueries::Enabled;
        c.clients = ClientInventory {
            candidates: vec![
                ClientCandidate {
                    kind: ClientKind::Git,
                    path: self.git.clone(),
                    source: ClientSource::Path,
                    version: None,
                    sha256: None,
                    selected: true,
                },
                ClientCandidate {
                    kind: ClientKind::Ssh,
                    path: PathBuf::from("/usr/bin/ssh"),
                    source: ClientSource::Path,
                    version: None,
                    sha256: None,
                    selected: true,
                },
            ],
        };
        c.test.git_item_any_default = true;
        c
    }

    fn hooked(&self, hook: &Arc<Hook>) -> ProjectionConfig {
        let mut c = self.config();
        let h: Arc<dyn ReplaceHook> = hook.clone();
        c.hook = Some(h);
        c
    }

    fn writer(&self) -> LocalProjection {
        LocalProjection::new(self.config())
    }

    fn alias(&self, name: &str) -> ManagedAliasSpec {
        let identity = IdentityId::from_random_bytes(random());
        self.keys
            .0
            .lock()
            .unwrap()
            .insert(identity.as_str().to_owned(), synthetic_public_key());
        ManagedAliasSpec {
            alias: name.to_owned(),
            destination: DestinationId::parse(&format!("dst-{name}")).unwrap(),
            hostname: format!("{name}.example.invalid"),
            port: None,
            account: AccountName::parse("fixture").unwrap(),
            identity,
            endpoint: None,
            key_file: self
                .home
                .config_dir
                .join("keys")
                .join(format!("{name}.pub"))
                .to_str()
                .unwrap()
                .to_owned(),
        }
    }

    fn spec(&self, record: Option<ProjectionRecord>) -> ProjectionSpec {
        ProjectionSpec {
            environment: self.env.clone(),
            aliases: vec![self.alias("work")],
            record,
            consent: heimdall_domain::projection::ConsentRecord::default(),
        }
    }

    fn plan(&self) -> ProjectionPlan {
        self.writer()
            .preview(
                &self.spec(None),
                &PreviewIntent::Apply { include_git: true },
            )
            .unwrap()
    }

    /// Run `git` with the scratch environment only.
    fn git(&self, args: &[&str]) -> std::process::Output {
        let mut c = std::process::Command::new(&self.git);
        c.env_clear().current_dir(&self.home.root).args(args);
        for (k, v) in self.git_env() {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    fn effective_ssh_command(&self) -> Option<String> {
        let o = self.git(&["config", "--includes", "--get", "core.sshCommand"]);
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim_end().to_owned())
    }

    fn tree(&self) -> BTreeMap<String, (u64, Vec<u8>)> {
        let mut out = BTreeMap::new();
        for dir in [self.home_dir().to_path_buf(), self.home.config_dir.clone()] {
            walk(&dir, &dir.file_name().unwrap().to_string_lossy(), &mut out);
        }
        out
    }
}

fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, (u64, Vec<u8>)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let e = e.unwrap();
        let name = format!("{prefix}/{}", e.file_name().to_string_lossy());
        if name.contains("/.ssh/") || name.ends_with("/.ssh") {
            continue;
        }
        let m = std::fs::symlink_metadata(e.path()).unwrap();
        if m.is_dir() {
            walk(&e.path(), &name, out);
        } else {
            out.insert(name, (m.ino(), std::fs::read(e.path()).unwrap_or_default()));
        }
    }
}

fn leftovers(fx: &Fx) -> Vec<String> {
    fx.tree()
        .keys()
        .filter(|k| (k.contains(".hm-") && !k.ends_with(".hm-quarantine")) || k.ends_with(".lock"))
        .cloned()
        .collect()
}

fn step_of(intent: &SetupIntent, role: FileRole) -> u16 {
    u16::try_from(intent.files.iter().position(|s| s.role == role).unwrap()).unwrap()
}

fn step_ref(intent: &SetupIntent, role: FileRole) -> &FileStep {
    intent.files.iter().find(|s| s.role == role).unwrap()
}

fn apply_or_crash(
    config: ProjectionConfig,
    intent: &SetupIntent,
    sink: &Sink,
) -> Option<Result<ProjectionReceipt, ReconcileError>> {
    let mut s = sink.clone();
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        LocalProjection::new(config).apply(intent, &mut s)
    })) {
        Ok(r) => Some(r),
        Err(p) if p.is::<Crash>() => None,
        Err(p) => std::panic::resume_unwind(p),
    }
}

fn restart_with(config: ProjectionConfig, intent: &SetupIntent, sink: &Sink) -> Vec<ItemOutcome> {
    let mut s = sink.clone();
    LocalProjection::new(config)
        .reconcile(intent, &sink.receipts(), &mut s)
        .unwrap()
        .items
}

fn git_outcome(items: &[ItemOutcome]) -> ItemOutcome {
    items
        .iter()
        .find(|o| {
            matches!(
                o,
                ItemOutcome::Applied {
                    item: ProjectionItem::Git,
                    ..
                } | ItemOutcome::NotApplied {
                    item: ProjectionItem::Git,
                    ..
                } | ItemOutcome::Restored {
                    item: ProjectionItem::Git,
                    ..
                } | ItemOutcome::Held {
                    item: ProjectionItem::Git,
                    ..
                } | ItemOutcome::ConflictPreserved {
                    item: ProjectionItem::Git
                }
            )
        })
        .cloned()
        .unwrap()
}

fn holder_bytes(intent: &SetupIntent) -> Vec<u8> {
    match step_ref(intent, FileRole::GitLock).content.view() {
        StepContentView::LockHolder { bytes } => bytes.to_vec(),
        _ => unreachable!(),
    }
}

fn target_bytes_digest(step: &FileStep) -> Sha256Hex {
    match &step.target {
        Target::Present { sha256 } => sha256.clone(),
        Target::Absent => unreachable!(),
    }
}

fn applied_git(items: &[ItemOutcome]) -> bool {
    matches!(git_outcome(items), ItemOutcome::Applied { .. })
}

fn write_lock(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension("lock-tmp");
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

// --- applicability ------------------------------------------------------------------------

#[test]
fn git_item_not_offered_without_bundled_msys_default() {
    let fx = Fx::new();
    let mut c = fx.config();
    c.test.git_item_any_default = false;
    let plan = LocalProjection::new(c)
        .preview(&fx.spec(None), &PreviewIntent::Apply { include_git: true })
        .unwrap();
    let git = plan.view.git.unwrap();
    assert_eq!(git.applicability, GitApplicability::NotApplicable);
    assert!(
        plan.files
            .iter()
            .all(|s| s.role.item() != ProjectionItem::Git)
    );
}

#[test]
fn git_existing_core_sshcommand_in_system_or_global_makes_item_not_applicable() {
    for (scope_file, values) in [("system", 1), ("system", 3), ("global", 1), ("global", 2)] {
        let fx = Fx::new();
        let file = if scope_file == "system" {
            fx.system.clone()
        } else {
            fx.global()
        };
        let mut text = String::from("[core]\n");
        for i in 0..values {
            text.push_str(&format!("\tsshCommand = ssh-{i}\n"));
        }
        std::fs::write(&file, text).unwrap();
        let tree = fx.tree();
        let plan = fx.plan();
        let git = plan.view.git.clone().unwrap();
        assert_eq!(
            git.applicability,
            GitApplicability::NotApplicable,
            "{scope_file} {values}"
        );
        assert_eq!(git.reason.as_deref(), Some("git_ssh_command_present"));
        let count: u32 = git.previous_values.iter().map(|v| v.count).sum();
        assert!(
            count >= values,
            "{scope_file} {values}: {:?}",
            git.previous_values
        );
        assert!(
            plan.files
                .iter()
                .all(|s| s.role.item() != ProjectionItem::Git)
        );
        assert_eq!(fx.tree(), tree, "a preview writes nothing");
    }
}

// --- apply, rollback, the lock ------------------------------------------------------------

#[test]
fn git_include_applied_under_lock_and_rollback_restores_bytes() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let before = std::fs::read(fx.global()).unwrap();
    let plan = fx.plan();
    assert_eq!(
        plan.view.git.as_ref().unwrap().applicability,
        GitApplicability::Applicable
    );
    let intent = plan.intent();
    let roles: Vec<FileRole> = intent
        .files
        .iter()
        .filter(|s| s.role.item() == ProjectionItem::Git)
        .map(|s| s.role)
        .collect();
    assert_eq!(
        roles,
        vec![
            FileRole::GitManaged,
            FileRole::GitLock,
            FileRole::GitInclude
        ]
    );
    let sink = Sink::default();
    let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    assert!(applied_git(&r.items), "{r:?} {:?}", sink.kinds());
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/usr/bin/ssh'")
    );
    assert!(!fx.lock().exists(), "the lock is released");
    assert!(leftovers(&fx).is_empty(), "{:?}", leftovers(&fx));
    // Roll the Git item back: B_git leaves the global file byte for byte.
    let record = record_of(&fx, &intent, &sink);
    let rb = fx
        .writer()
        .preview(
            &fx.spec(Some(record)),
            &PreviewIntent::Rollback {
                keep_key_files: true,
                items: [ProjectionItem::Git].into_iter().collect(),
            },
        )
        .unwrap()
        .intent();
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert_eq!(std::fs::read(fx.global()).unwrap(), before);
    assert_eq!(fx.effective_ssh_command(), None);
    assert!(leftovers(&fx).is_empty(), "{:?}", leftovers(&fx));
}

fn record_of(fx: &Fx, intent: &SetupIntent, sink: &Sink) -> ProjectionRecord {
    let mut items = BTreeMap::new();
    for item in [ProjectionItem::Ssh, ProjectionItem::Git] {
        let mut files = Vec::new();
        for (i, s) in intent.files.iter().enumerate() {
            if s.role.item() != item
                || !matches!(
                    s.role,
                    FileRole::ManagedSsh | FileRole::Key | FileRole::GitManaged
                )
            {
                continue;
            }
            let identity =
                sink.file_phases(u16::try_from(i).unwrap())
                    .iter()
                    .find_map(|p| match p {
                        FilePhase::Staged { identity } => Some(identity.clone()),
                        _ => None,
                    });
            if let Some(identity) = identity {
                files.push(heimdall_domain::projection::ProjectionLocator {
                    role: s.role,
                    path: s.path.clone(),
                    identity,
                    sha256: target_bytes_digest(s),
                });
            }
        }
        items.insert(
            item,
            heimdall_domain::projection::ItemRecord {
                generation: intent.generation,
                files,
                aliases: Vec::new(),
                operation: OperationId::from_random_bytes([3; 16]),
                committed_at: heimdall_contract::Timestamp::now(),
            },
        );
    }
    ProjectionRecord {
        environment: fx.env.clone(),
        items,
    }
}

#[test]
fn git_lock_held_by_git_is_git_config_locked_nothing_written() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let intent = fx.plan().intent();
    let before = std::fs::read(fx.global()).unwrap();
    write_lock(&fx.lock(), b"[user]\n\tname = Git is writing\n");
    let lock = std::fs::symlink_metadata(fx.lock()).unwrap().ino();
    let sink = Sink::default();
    let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    assert_eq!(
        git_outcome(&r.items),
        ItemOutcome::NotApplied {
            item: ProjectionItem::Git,
            reason: Some(ConflictKind::GitConfigLocked)
        },
        "{:?}",
        sink.kinds()
    );
    assert_eq!(
        std::fs::read(fx.global()).unwrap(),
        before,
        "global file untouched"
    );
    assert_eq!(
        std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
        lock,
        "lock untouched"
    );
    let k = step_of(&intent, FileRole::GitLock);
    assert!(
        sink.kinds().contains(&format!("{k}:settled")),
        "K settled: {:?}",
        sink.kinds()
    );
    let b = step_of(&intent, FileRole::GitInclude);
    assert!(sink.file_phases(b).is_empty(), "B_git never staged");
}

#[test]
fn git_writer_during_heimdall_lock_fails_cleanly_nothing_lost() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let intent = fx.plan().intent();
    let k = step_of(&intent, FileRole::GitLock);
    let failed: Arc<Mutex<Option<bool>>> = Arc::default();
    let f = Arc::clone(&failed);
    let env = fx.git_env();
    let git = fx.git.clone();
    let root = fx.home.root.clone();
    let hook = Hook::new().run(ReplacePoint::AfterLockClaim, Some(k), move || {
        let mut c = std::process::Command::new(&git);
        c.env_clear().current_dir(&root);
        for (key, v) in &env {
            c.env(key, v);
        }
        let o = c
            .args([
                "config",
                "--global",
                "user.email",
                "scratch@example.invalid",
            ])
            .output()
            .unwrap();
        *f.lock().unwrap() = Some(!o.status.success());
    });
    let r = apply_or_crash(fx.hooked(&hook), &intent, &Sink::default())
        .unwrap()
        .unwrap();
    assert!(applied_git(&r.items));
    assert_eq!(*failed.lock().unwrap(), Some(true), "Git's own lock error");
    // Re-run afterwards: both edits are present.
    assert!(
        fx.git(&[
            "config",
            "--global",
            "user.email",
            "scratch@example.invalid"
        ])
        .status
        .success()
    );
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/usr/bin/ssh'")
    );
    let email = fx.git(&["config", "--global", "--get", "user.email"]);
    assert_eq!(
        String::from_utf8_lossy(&email.stdout).trim(),
        "scratch@example.invalid"
    );
}

#[test]
fn git_editor_write_after_final_check_is_restored() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let intent = fx.plan().intent();
    let b = step_of(&intent, FileRole::GitInclude);
    let global = fx.global();
    let hook = Hook::new().run(ReplacePoint::BeforeExchange, Some(b), move || {
        let tmp = global.with_extension("editor");
        std::fs::write(&tmp, b"[user]\n\tname = Editor\n").unwrap();
        std::fs::rename(&tmp, &global).unwrap();
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        git_outcome(&r.items),
        ItemOutcome::Restored {
            item: ProjectionItem::Git,
            reason: Some(ConflictKind::ConcurrentWriter)
        },
        "{:?}",
        sink.kinds()
    );
    assert_eq!(
        std::fs::read(fx.global()).unwrap(),
        b"[user]\n\tname = Editor\n"
    );
    assert!(!fx.lock().exists(), "K released last");
}

#[test]
fn git_crash_with_lock_holding_staged_or_displaced_reconciles() {
    for (point, role) in [
        (ReplacePoint::BeforeLockClaim, FileRole::GitLock),
        (ReplacePoint::AfterLockClaim, FileRole::GitLock),
        (ReplacePoint::BeforeExchange, FileRole::GitInclude),
    ] {
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let intent = fx.plan().intent();
        let hook = Hook::new().crash(point, Some(step_of(&intent, role)));
        let sink = Sink::default();
        assert!(
            apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none(),
            "{point:?}"
        );
        let out = restart_with(fx.config(), &intent, &sink);
        assert!(applied_git(&out), "{point:?} {out:?} {:?}", sink.kinds());
        assert_eq!(
            fx.effective_ssh_command().as_deref(),
            Some("'/usr/bin/ssh'")
        );
        assert!(leftovers(&fx).is_empty(), "{point:?} {:?}", leftovers(&fx));
    }
}

/// Every transition of ADR-0007 §5.6's replace, create and restore tables, crashed
/// before and after its receipt, with and without a Unix birth time (the test-only
/// identity source). After restart: the expected outcome, the global file's bytes,
/// and no lock, N_s, N_d or N_k left, except that without a birth time a K at the
/// lock is X and is left in place (K4).
#[test]
fn git_name_transitions_crash_at_every_point_reconciles() {
    let points = |k: u16, b: u16, p: u16| -> Vec<(ReplacePoint, u16)> {
        vec![
            (ReplacePoint::AfterStage, k),
            (ReplacePoint::BeforeReceipt("staged"), k),
            (ReplacePoint::BeforeLockClaim, k),
            (ReplacePoint::AfterLockClaim, k),
            (ReplacePoint::AfterStage, b),
            (ReplacePoint::BeforeReceipt("staged"), b),
            (ReplacePoint::BeforeReceipt("validated"), b),
            (ReplacePoint::BeforeExchange, b),
            (ReplacePoint::AfterExchange, b),
            (ReplacePoint::BeforeReceipt("exchanged"), b),
            (ReplacePoint::BeforeReceipt("post_validated"), b),
            (ReplacePoint::BeforeCommit, b),
            (ReplacePoint::BeforeReceipt("committed"), b),
            (ReplacePoint::BeforeReceipt("settling"), b),
            (ReplacePoint::AfterSettleMove, b),
            (ReplacePoint::BeforeQuarantineRemove, b),
            (ReplacePoint::BeforeLockRelease, k),
            (ReplacePoint::BeforeReceipt("settling"), k),
            (ReplacePoint::AfterSettleMove, k),
            (ReplacePoint::BeforeQuarantineRemove, k),
            (ReplacePoint::BeforeReceipt("finished"), b),
            (ReplacePoint::BeforeReceipt("staged"), p),
        ]
    };
    let mut vectors = 0;
    for create in [false, true] {
        for birth in [true, false] {
            for restore in [false, true] {
                let probe = Fx::new();
                if !create {
                    std::fs::write(probe.global(), b"[user]\n\tname = Scratch\n").unwrap();
                } else {
                    std::fs::remove_file(probe.global()).unwrap();
                }
                let probe_intent = probe.plan().intent();
                let k = step_of(&probe_intent, FileRole::GitLock);
                let b = step_of(&probe_intent, FileRole::GitInclude);
                let p = step_of(&probe_intent, FileRole::GitManaged);
                for (point, step) in points(k, b, p) {
                    let fx = Fx::new();
                    if create {
                        std::fs::remove_file(fx.global()).unwrap();
                    } else {
                        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
                    }
                    let before = std::fs::read(fx.global()).ok();
                    let intent = fx.plan().intent();
                    let mut hook = Hook::new();
                    if restore {
                        // The Git item's check fails: P_git is edited after B_git's
                        // post-validation, so the item rolls back (restore table).
                        let pg = fx.p_git();
                        hook = hook.run(ReplacePoint::AfterPostValidate, Some(b), move || {
                            let mut t = std::fs::read(&pg).unwrap();
                            t.extend_from_slice(b"# edited\n");
                            std::fs::write(&pg, t).unwrap();
                        });
                    }
                    let hook = hook.crash(point, Some(step));
                    let mut config = fx.hooked(&hook);
                    let mut fresh = fx.config();
                    if !birth {
                        config.test.identity = IdentitySource::WithoutBirth;
                        fresh.test.identity = IdentitySource::WithoutBirth;
                    }
                    let sink = Sink::default();
                    let first = apply_or_crash(config, &intent, &sink);
                    // The edit happens only when the crash comes after B_git's
                    // post-validation; earlier crashes restart without it.
                    let restore =
                        restore && hook.seen().contains(&(ReplacePoint::AfterPostValidate, b));
                    let out = match first {
                        None => restart_with(fresh, &intent, &sink),
                        Some(r) => r.unwrap().items,
                    };
                    let git = git_outcome(&out);
                    let label = format!(
                        "create={create} birth={birth} restore={restore} {point:?}@{step}: {git:?} {:?}",
                        sink.kinds()
                    );
                    let b_exchanged = sink.kinds().contains(&format!("{b}:exchanged"));
                    let lock_left = fx.lock().exists();
                    match &git {
                        ItemOutcome::Applied { .. } => {
                            assert!(!restore, "{label}");
                            assert_eq!(
                                Sha256Hex::of(&std::fs::read(fx.global()).unwrap()),
                                target_bytes_digest(step_ref(&intent, FileRole::GitInclude)),
                                "{label}"
                            );
                        }
                        ItemOutcome::Restored { .. } => {
                            assert_eq!(std::fs::read(fx.global()).ok(), before, "{label}");
                        }
                        ItemOutcome::NotApplied { .. } => {
                            assert!(
                                !b_exchanged,
                                "not_applied only before B_git's exchange: {label}"
                            );
                            assert_eq!(std::fs::read(fx.global()).ok(), before, "{label}");
                        }
                        ItemOutcome::Held { steps, .. } => {
                            // Only C7a/F5a for an edited P_git (an inactive file) may hold.
                            assert!(restore, "{label}");
                            assert!(
                                steps
                                    .iter()
                                    .all(|s| s.reason == HoldReason::ActiveEntryModified),
                                "{label}"
                            );
                        }
                        other => panic!("{label}: {other:?}"),
                    }
                    if matches!(git, ItemOutcome::Held { .. }) {
                        // A held Git item keeps K at the lock (its release is due only
                        // once every other step is final); nothing else is asserted.
                    } else if birth {
                        assert!(!lock_left, "{label}");
                    } else if lock_left {
                        // K4: the lock is never moved or removed without a birth time.
                        let bytes = std::fs::read(fx.lock()).unwrap();
                        assert_eq!(bytes, holder_bytes(&intent), "{label}");
                        assert!(
                            sink.file_phases(k).iter().any(|ph| matches!(
                                ph,
                                FilePhase::SettleConflict {
                                    found: SettleConflictFound::Foreign,
                                    ..
                                }
                            )),
                            "{label}"
                        );
                    }
                    let names: Vec<String> = leftovers(&fx)
                        .into_iter()
                        .filter(|n| !n.ends_with(".gitconfig.lock"))
                        .collect();
                    if !matches!(git, ItemOutcome::Held { .. }) {
                        assert!(names.is_empty(), "{label}: {names:?}");
                    }
                    vectors += 1;
                }
            }
        }
    }
    assert!(vectors >= 8 * 22, "{vectors}");
}

#[test]
fn git_lock_occupied_by_holder_until_settlement() {
    for create in [false, true] {
        let fx = Fx::new();
        if create {
            std::fs::remove_file(fx.global()).unwrap();
        } else {
            std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        }
        let intent = fx.plan().intent();
        let holder = holder_bytes(&intent);
        let lock = fx.lock();
        let held = Arc::new(Mutex::new((false, 0usize, Vec::<String>::new())));
        let h = Arc::clone(&held);
        let env = fx.git_env();
        let git = fx.git.clone();
        let root = fx.home.root.clone();
        let hook = Hook::new().every(move |point, _| {
            let mut st = h.lock().unwrap();
            if point == ReplacePoint::AfterLockClaim {
                st.0 = true;
            }
            if point == ReplacePoint::BeforeLockRelease {
                st.0 = false;
            }
            if !st.0 {
                return;
            }
            st.1 += 1;
            if std::fs::read(&lock).ok().as_deref() != Some(holder.as_slice()) {
                st.2.push(format!("{point:?}: lock not K"));
            }
            let mut c = std::process::Command::new(&git);
            c.env_clear().current_dir(&root);
            for (key, v) in &env {
                c.env(key, v);
            }
            let o = c
                .args(["config", "--global", "user.x", "y"])
                .output()
                .unwrap();
            if o.status.success() {
                st.2.push(format!("{point:?}: git wrote under Heimdall's lock"));
            }
        });
        let r = apply_or_crash(fx.hooked(&hook), &intent, &Sink::default())
            .unwrap()
            .unwrap();
        assert!(applied_git(&r.items));
        let st = held.lock().unwrap();
        assert!(st.1 >= 5, "points between claim and release: {}", st.1);
        assert!(st.2.is_empty(), "{:?}", st.2);
        assert_eq!(
            Sha256Hex::of(&std::fs::read(fx.global()).unwrap()),
            target_bytes_digest(step_ref(&intent, FileRole::GitInclude))
        );
        assert!(leftovers(&fx).is_empty(), "{:?}", leftovers(&fx));
    }
}

#[test]
fn git_foreign_lock_with_exact_target_bytes_is_never_claimed_or_removed() {
    // Each variant runs with the planned target's bytes, and again with K's line.
    for use_holder_bytes in [false, true] {
        let foreign = |fx: &Fx, intent: &SetupIntent| -> Vec<u8> {
            if use_holder_bytes {
                holder_bytes(intent)
            } else {
                let _ = fx;
                let b = step_ref(intent, FileRole::GitInclude);
                let mut bytes = std::fs::read(&b.path).unwrap_or_default();
                if let StepContentView::Splice { offset, insert, .. } = b.content.view() {
                    let at = usize::try_from(offset).unwrap();
                    bytes.splice(at..at, insert.iter().copied());
                }
                assert_eq!(Sha256Hex::of(&bytes), target_bytes_digest(b));
                bytes
            }
        };
        // 1. Present before the claim.
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let intent = fx.plan().intent();
        let before = std::fs::read(fx.global()).unwrap();
        write_lock(&fx.lock(), &foreign(&fx, &intent));
        let lock = (
            std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
            std::fs::read(fx.lock()).unwrap(),
        );
        let sink = Sink::default();
        let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
        assert!(matches!(
            git_outcome(&r.items),
            ItemOutcome::NotApplied { .. }
        ));
        assert_eq!(std::fs::read(fx.global()).unwrap(), before);
        assert_eq!(
            (
                std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
                std::fs::read(fx.lock()).unwrap()
            ),
            lock
        );
        assert!(
            sink.file_phases(step_of(&intent, FileRole::GitInclude))
                .is_empty()
        );

        // 2. A crash at BeforeLockClaim; the lock is created while the runtime is down
        //    (K1: the claim fails, K settled from its staged name, the lock left).
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let intent = fx.plan().intent();
        let k = step_of(&intent, FileRole::GitLock);
        let hook = Hook::new().crash(ReplacePoint::BeforeLockClaim, Some(k));
        let sink = Sink::default();
        assert!(apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none());
        write_lock(&fx.lock(), &foreign(&fx, &intent));
        let lock = (
            std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
            std::fs::read(fx.lock()).unwrap(),
        );
        let out = restart_with(fx.config(), &intent, &sink);
        assert!(
            matches!(git_outcome(&out), ItemOutcome::NotApplied { .. }),
            "{out:?}"
        );
        assert_eq!(
            (
                std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
                std::fs::read(fx.lock()).unwrap()
            ),
            lock
        );
        let staged = step_ref(&intent, FileRole::GitLock)
            .staged_name
            .clone()
            .unwrap();
        assert!(
            !fx.home_dir().join(staged).exists(),
            "K settled from its staged name"
        );

        // 3. A crash at AfterLockClaim; the owner removes Heimdall's lock (as Git's error
        //    suggests) and a foreign lock with the same bytes appears (K4: left).
        // 4. The same without a birth time: even Heimdall's own lock is foreign.
        for birth in [true, false] {
            let fx = Fx::new();
            std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
            let intent = fx.plan().intent();
            let k = step_of(&intent, FileRole::GitLock);
            let hook = Hook::new().crash(ReplacePoint::AfterLockClaim, Some(k));
            let mut config = fx.hooked(&hook);
            let mut fresh = fx.config();
            if !birth {
                config.test.identity = IdentitySource::WithoutBirth;
                fresh.test.identity = IdentitySource::WithoutBirth;
            }
            let sink = Sink::default();
            assert!(apply_or_crash(config, &intent, &sink).is_none());
            if birth {
                std::fs::remove_file(fx.lock()).unwrap();
                write_lock(&fx.lock(), &foreign(&fx, &intent));
            }
            let lock = (
                std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
                std::fs::read(fx.lock()).unwrap(),
            );
            let out = restart_with(fresh, &intent, &sink);
            assert!(
                !applied_git(&out),
                "never claimed under a foreign lock: {out:?} {:?}",
                sink.kinds()
            );
            assert_eq!(
                (
                    std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
                    std::fs::read(fx.lock()).unwrap()
                ),
                lock,
                "birth={birth}: the lock is never moved or removed"
            );
            assert!(
                sink.file_phases(k).iter().any(|ph| matches!(
                    ph,
                    FilePhase::SettleConflict {
                        found: SettleConflictFound::Foreign,
                        ..
                    }
                )),
                "{:?}",
                sink.kinds()
            );
        }
    }
}

mod lock_claim_order {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x5534_4347_4954_4c4b);
        }
        c
    }

    fn points() -> &'static Vec<(ReplacePoint, u16)> {
        static P: std::sync::OnceLock<Vec<(ReplacePoint, u16)>> = std::sync::OnceLock::new();
        P.get_or_init(|| {
            let fx = Fx::new();
            let intent = fx.plan().intent();
            let hook = Hook::new();
            apply_or_crash(fx.hooked(&hook), &intent, &Sink::default())
                .unwrap()
                .unwrap();
            let mut seen = hook.seen();
            seen.dedup();
            seen
        })
    }

    proptest! {
        #![proptest_config(config())]

        /// In every run, K's `file.staged` is durable before the lock name exists, and
        /// B_git's S is never at the lock name; nothing reaches the lock name except
        /// the claim.
        #[test]
        fn git_lock_claimed_only_after_staged_receipt(pick in 0usize..10_000, existing in any::<bool>()) {
            let fx = Fx::new();
            if !existing {
                std::fs::remove_file(fx.global()).unwrap();
            }
            let intent = fx.plan().intent();
            let k = step_of(&intent, FileRole::GitLock);
            let b = step_of(&intent, FileRole::GitInclude);
            let (point, step) = points()[pick % points().len()];
            let sink = Sink::default();
            let violations: Arc<Mutex<Vec<String>>> = Arc::default();
            let (v, s, lock, holder) = (
                Arc::clone(&violations),
                sink.clone(),
                fx.lock(),
                holder_bytes(&intent),
            );
            let hook = Hook::new()
                .every(move |pt, _| {
                    if !lock.exists() {
                        return;
                    }
                    let staged_k = s.file_phases(k).iter().any(|p| matches!(p, FilePhase::Staged { .. }));
                    if !staged_k {
                        v.lock().unwrap().push(format!("{pt:?}: lock exists before K's file.staged"));
                    }
                    if std::fs::read(&lock).ok().as_deref() != Some(holder.as_slice()) {
                        v.lock().unwrap().push(format!("{pt:?}: something other than K at the lock"));
                    }
                })
                .crash(point, Some(step));
            let first = apply_or_crash(fx.hooked(&hook), &intent, &sink);
            if first.is_none() {
                let _ = restart_with(fx.config(), &intent, &sink);
            }
            prop_assert!(violations.lock().unwrap().is_empty(), "{:?}", violations.lock().unwrap());
            let _ = b;
            prop_assert!(!fx.lock().exists(), "{point:?}@{step}: {:?}", sink.kinds());
        }
    }
}

// --- user values -------------------------------------------------------------------------

fn apply_git(fx: &Fx) -> (SetupIntent, Sink) {
    let intent = fx.plan().intent();
    let sink = Sink::default();
    let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    assert!(applied_git(&r.items), "{r:?} {:?}", sink.kinds());
    (intent, sink)
}

fn rollback_git(fx: &Fx, intent: &SetupIntent, sink: &Sink) -> ProjectionPlan {
    fx.writer()
        .preview(
            &fx.spec(Some(record_of(fx, intent, sink))),
            &PreviewIntent::Rollback {
                keep_key_files: true,
                items: [ProjectionItem::Git].into_iter().collect(),
            },
        )
        .unwrap()
}

#[test]
fn git_rollback_after_user_added_value_keeps_user_value() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (intent, sink) = apply_git(&fx);
    assert!(
        fx.git(&["config", "--global", "core.sshCommand", "ssh -v"])
            .status
            .success()
    );
    let rb = rollback_git(&fx, &intent, &sink).intent();
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert_eq!(fx.effective_ssh_command().as_deref(), Some("ssh -v"));
    let text = std::fs::read_to_string(fx.global()).unwrap();
    assert!(!text.contains("heimdall managed include"));
    assert!(text.contains("name = Scratch"));
}

#[test]
fn git_rollback_after_edit_inside_block_is_marker_edited() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (intent, sink) = apply_git(&fx);
    let text = std::fs::read_to_string(fx.global()).unwrap();
    std::fs::write(fx.global(), text.replacen("\tpath = ", "\tpath =  ", 1)).unwrap();
    let plan = rollback_git(&fx, &intent, &sink);
    assert!(plan.files.iter().all(|s| s.role != FileRole::GitInclude));
    assert_eq!(plan.view.findings.len(), 1);
    assert_eq!(plan.view.findings[0].code, "marker_edited");
}

#[test]
fn git_user_set_after_include_wins() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let _ = apply_git(&fx);
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/usr/bin/ssh'")
    );
    assert!(
        fx.git(&["config", "--global", "core.sshCommand", "ssh -4"])
            .status
            .success()
    );
    assert_eq!(fx.effective_ssh_command().as_deref(), Some("ssh -4"));
}

#[test]
fn git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win()
 {
    let fx = Fx::new();
    let xdg = fx.xdg_dir().join("git").join("config");
    std::fs::create_dir_all(xdg.parent().unwrap()).unwrap();
    std::fs::write(&xdg, b"[user]\n\tname = Xdg\n").unwrap();
    std::fs::write(fx.global(), b"[user]\n\temail = scratch@example.invalid\n").unwrap();
    let (intent, _sink) = apply_git(&fx);
    assert_eq!(
        Path::new(&step_ref(&intent, FileRole::GitInclude).path),
        xdg,
        "B_git in the first-read file"
    );
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/usr/bin/ssh'")
    );
    // A `git config --global` value (written to ~/.gitconfig) wins.
    assert!(
        fx.git(&["config", "--global", "core.sshCommand", "ssh -6"])
            .status
            .success()
    );
    let o = fx.git(&[
        "config",
        "--includes",
        "--show-origin",
        "--get",
        "core.sshCommand",
    ]);
    let shown = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(shown.trim_end().ends_with("ssh -6"), "{shown}");
    // So does a manual value in the XDG file below B_git.
    assert!(
        fx.git(&["config", "--global", "--unset", "core.sshCommand"])
            .status
            .success()
    );
    let mut t = std::fs::read_to_string(&xdg).unwrap();
    t.push_str("[core]\n\tsshCommand = ssh -x\n");
    std::fs::write(&xdg, t).unwrap();
    let o = fx.git(&[
        "config",
        "--includes",
        "--show-origin",
        "--get",
        "core.sshCommand",
    ]);
    let shown = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(shown.trim_end().ends_with("ssh -x"), "{shown}");
}

/// Only `~/.gitconfig` existed at apply; the owner then creates the XDG file with a
/// value. Git reads the XDG file first, so Heimdall's include (in `~/.gitconfig`) wins,
/// as disclosed. The doctor finding `git_user_value_shadowed` is U3's/U5's and is not
/// asserted here.
#[test]
fn git_xdg_created_after_apply_shadowed_value_reported() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (intent, _sink) = apply_git(&fx);
    assert_eq!(
        Path::new(&step_ref(&intent, FileRole::GitInclude).path),
        fx.global()
    );
    let xdg = fx.xdg_dir().join("git").join("config");
    std::fs::create_dir_all(xdg.parent().unwrap()).unwrap();
    std::fs::write(&xdg, b"[core]\n\tsshCommand = ssh -q\n").unwrap();
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/usr/bin/ssh'")
    );
}
