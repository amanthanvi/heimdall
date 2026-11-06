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
use heimdall_contract::doctor::{DoctorReport, Finding, FindingSeverity, finding};
use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, IdentityId, OperationId};
use heimdall_contract::setup::{ConflictKind, GitApplicability, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::{
    AdapterIdentity, EffectReceipt, FilePhase, HoldReason, ItemFinish, ItemPhase, LocalReceipt,
    SettleConflictFound, SettleSource, SettledDisposition, StageReceipt,
};
use heimdall_domain::projection::{
    Base, FileRole, FileStep, ItemCommit, ManagedAliasSpec, ProjectionPlan, ProjectionRecord,
    ProjectionSpec, SetupIntent, Sha256Hex, StepContentView, Target,
};
use heimdall_localenv::clients::{
    ClientCandidate, ClientInventory, ClientKind, ClientSource, ClientsConfig,
};
use heimdall_localenv::doctor::{DoctorRequest, LocalContext};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::{
    LocalProjection, ProjectionConfig, PublicKeySource, ReplaceHook, ReplacePoint,
};
use heimdall_localenv::sys::IdentitySource;
use heimdall_sshconf::limits::Limits;
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

/// The receipts the writer appended, and the item commits it handed to the sink (what
/// the application's sink merges into the projection record).
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<StageReceipt>>>, Arc<Mutex<Vec<ItemCommit>>>);

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
        let receipt = LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        };
        self.1
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(commit);
        self.append(&receipt)
    }
}

impl Sink {
    /// The item commits, in order.
    fn commits(&self) -> Vec<ItemCommit> {
        self.1
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The file the writer last recorded B_git in (`ItemRecord::include_file`): the
    /// newest Git commit that names one, as the application's sink keeps the previous
    /// generation's path across an update that names none.
    fn recorded_include_file(&self) -> Option<String> {
        self.commits()
            .iter()
            .rev()
            .filter(|c| c.item == ProjectionItem::Git)
            .find_map(|c| {
                c.record
                    .items
                    .get(&ProjectionItem::Git)?
                    .include_file
                    .clone()
            })
    }

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
                    ..
                } => "finished_applied",
                ItemPhase::Finished {
                    outcome: ItemFinish::NotApplied,
                    ..
                } => "finished_not_applied",
                ItemPhase::Finished {
                    outcome: ItemFinish::Restored,
                    ..
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

    /// The passive doctor over this scratch world (ADR-0007 §12.37): the same scratch
    /// `HOME`, `XDG_CONFIG_HOME` and `GIT_CONFIG_SYSTEM`, this scratch Git, Heimdall's
    /// configuration directory as the writer uses it. No alias is evaluated.
    fn doctor(&self, queries: LocalQueries) -> DoctorReport {
        let path = std::env::join_paths([
            self.git.parent().unwrap(),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .unwrap();
        let mut vars: Vec<(std::ffi::OsString, std::ffi::OsString)> = vec![("PATH".into(), path)];
        vars.extend(
            self.git_env()
                .into_iter()
                .map(|(k, v)| (k.into(), v.into())),
        );
        let mut ctx = LocalContext::new(
            SshPaths::with_test_override(
                self.home_dir().to_path_buf(),
                self.home.root.join("etc-ssh"),
            ),
            Env::from_vars(vars),
            Platform::current(),
            ClientsConfig {
                git: Some(self.git.clone()),
                ..ClientsConfig::default()
            },
            Limits::default(),
        );
        ctx.managed_file = Some(self.config().managed_ssh_path());
        let mut request = DoctorRequest::passive();
        request.local_queries = queries;
        request.aliases = Some(Vec::new());
        heimdall_localenv::doctor::run(&ctx, &request)
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

/// ADR-0007 §12.18 item 3 (review X03), for the Git block: B_git's marker is derived
/// like B's, so two previews of an unchanged first adoption with the Git item give the
/// same plan digest and the same B_git (for an existing and an absent global file), and
/// changing any one input changes the digest.
#[test]
fn git_first_adoption_previews_reproduce_their_plan_digest() {
    for global_present in [true, false] {
        let fx = Fx::new();
        if global_present {
            std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        }
        let spec = fx.spec(None);
        let intent = PreviewIntent::Apply { include_git: true };
        let preview = |spec: &ProjectionSpec| fx.writer().preview(spec, &intent).unwrap();
        let (a, b) = (preview(&spec), preview(&spec));
        let label = format!("global_present={global_present}");
        let (ai, bi) = (a.intent(), b.intent());
        let include = step_ref(&ai, FileRole::GitInclude);
        assert!(include.commit, "{label}: B_git is inserted");
        assert_eq!(a.view.plan_digest, b.view.plan_digest, "{label}");
        assert_eq!(
            include.target,
            step_ref(&bi, FileRole::GitInclude).target,
            "{label}: the same B_git"
        );
        let base = a.view.plan_digest.clone();
        let mut other = spec.clone();
        other.environment = EnvironmentId::from_random_bytes(random());
        let changed = preview(&other);
        assert_ne!(changed.view.plan_digest, base, "{label}: the spec");
        assert_ne!(
            step_ref(&changed.intent(), FileRole::GitInclude).target,
            include.target,
            "{label}: the spec changes B_git's marker"
        );
        let before = std::fs::read(fx.global()).ok();
        std::fs::write(fx.global(), b"[user]\n\tname = Another\n").unwrap();
        assert_ne!(
            preview(&spec).view.plan_digest,
            base,
            "{label}: the global file"
        );
        match before {
            Some(bytes) => std::fs::write(fx.global(), bytes).unwrap(),
            None => std::fs::remove_file(fx.global()).unwrap(),
        }
        std::fs::create_dir_all(fx.home.config_dir.clone()).unwrap();
        std::fs::write(fx.p_git(), b"# stray\n").unwrap();
        assert_ne!(preview(&spec).view.plan_digest, base, "{label}: P_git");
        std::fs::remove_file(fx.p_git()).unwrap();
        assert_eq!(preview(&spec).view.plan_digest, base, "{label}: restored");
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
                // What the writer's own commit recorded (ADR-0007 §12.37 item 3), not
                // what the test knows: the sink merges it into the stored record.
                include_file: (item == ProjectionItem::Git)
                    .then(|| sink.recorded_include_file())
                    .flatten(),
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

/// ADR-0007 §12.17 item 3. In an abort or a restore no receipt records the hand-over
/// of the Git item's other steps (B_git's S settled, P_git left to the cleaner), so K's
/// release is computed every round from the durable receipts and a fresh observation.
/// A crash after the hand-over and before K's release releases K at restart; a crash
/// inside the hand-over never releases K before it completes. Two ways to end: an abort
/// (the global file changes after B_git is staged, so B_git's recheck fails and its S
/// is settled) and B_git's own file-level restore (an editor replaces the global file
/// right before the exchange).
#[test]
fn git_release_of_k_after_hand_over_happens_at_restart_never_earlier() {
    let mut vectors = 0;
    for restore in [false, true] {
        let probe = Fx::new();
        std::fs::write(probe.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let probe_intent = probe.plan().intent();
        let k = step_of(&probe_intent, FileRole::GitLock);
        let b = step_of(&probe_intent, FileRole::GitInclude);
        for (point, step) in [
            // After the hand-over, before K's release.
            (ReplacePoint::BeforeLockRelease, k),
            (ReplacePoint::BeforeReceipt("settling"), k),
            // Inside the hand-over: B_git's S is being settled.
            (ReplacePoint::BeforeReceipt("settling"), b),
            (ReplacePoint::AfterSettleMove, b),
            (ReplacePoint::BeforeReceipt("settled"), b),
            (ReplacePoint::BeforeQuarantineRemove, b),
        ] {
            let fx = Fx::new();
            std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
            let intent = fx.plan().intent();
            let global = fx.global();
            let hook = if restore {
                Hook::new().run(ReplacePoint::BeforeExchange, Some(b), move || {
                    let tmp = global.with_extension("editor");
                    std::fs::write(&tmp, b"[user]\n\tname = Editor\n").unwrap();
                    std::fs::rename(&tmp, &global).unwrap();
                })
            } else {
                Hook::new().run(ReplacePoint::AfterStage, Some(b), move || {
                    let mut t = std::fs::read(&global).unwrap();
                    t.extend_from_slice(b"[core]\n\tbare = false\n");
                    std::fs::write(&global, t).unwrap();
                })
            };
            let hook = hook.crash(point, Some(step));
            let sink = Sink::default();
            let label = format!("restore={restore} {point:?}@{step}");
            assert!(
                apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none(),
                "{label}: {:?}",
                sink.kinds()
            );
            assert_eq!(
                std::fs::read(fx.lock()).unwrap(),
                holder_bytes(&intent),
                "{label}: K still holds the lock after the crash"
            );
            // The restart checks, at K's release, that the hand-over is complete.
            let staged_b = fx.global().with_file_name(
                step_ref(&intent, FileRole::GitInclude)
                    .staged_name
                    .clone()
                    .unwrap(),
            );
            let early = Arc::new(Mutex::new(Vec::<String>::new()));
            let (e, s2) = (Arc::clone(&early), sink.clone());
            let watch = Hook::new().run(ReplacePoint::BeforeLockRelease, Some(k), move || {
                if staged_b.exists() {
                    e.lock()
                        .unwrap()
                        .push("B_git's S is still at its staged name".into());
                }
                if !s2.kinds().contains(&format!("{b}:settled")) {
                    e.lock().unwrap().push("no durable B_git settled".into());
                }
            });
            let out = restart_with(fx.hooked(&watch), &intent, &sink);
            let git = git_outcome(&out);
            let kinds = sink.kinds();
            if restore {
                assert!(
                    matches!(git, ItemOutcome::Restored { .. }),
                    "{label}: {git:?} {kinds:?}"
                );
            } else {
                assert!(
                    matches!(git, ItemOutcome::NotApplied { .. }),
                    "{label}: {git:?} {kinds:?}"
                );
            }
            assert!(
                early.lock().unwrap().is_empty(),
                "{label}: {:?}",
                early.lock().unwrap()
            );
            assert!(!fx.lock().exists(), "{label}: K released at restart");
            let pos = |k: &str| kinds.iter().rposition(|x| x == k);
            assert!(
                pos(&format!("{k}:settling")) > pos(&format!("{b}:settled")),
                "{label}: K released last {kinds:?}"
            );
            assert_eq!(
                kinds.last().map(String::as_str),
                Some(if restore {
                    "git:finished_restored"
                } else {
                    "git:finished_not_applied"
                }),
                "{label}"
            );
            assert!(leftovers(&fx).is_empty(), "{label}: {:?}", leftovers(&fx));
            vectors += 1;
        }
    }
    assert_eq!(vectors, 12);
}

/// ADR-0007 §12.17 item 8, §5.6 step 3: `git config --file <N_s> --no-includes
/// --list` runs before B_git's exchange, and a failure aborts before the commit point.
/// Right after B_git's S is staged, another writer leaves bytes there that Git refuses
/// to parse (an unclosed section header). The real Git refuses them, so the item
/// aborts (`not_applied`, `unmanageable_file`): B_git is never exchanged, the global
/// file is unchanged, the written-into S stays in the quarantine as a conflict artifact
/// (it is not Heimdall's content any more), and K is released last.
#[test]
fn git_parse_check_failure_aborts_before_the_commit_point() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let before = std::fs::read(fx.global()).unwrap();
    let intent = fx.plan().intent();
    let b = step_of(&intent, FileRole::GitInclude);
    let staged = fx.global().with_file_name(
        step_ref(&intent, FileRole::GitInclude)
            .staged_name
            .clone()
            .unwrap(),
    );
    let s = staged.clone();
    let hook = Hook::new().run(ReplacePoint::AfterStage, Some(b), move || {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&s)
            .unwrap();
        std::io::Write::write_all(&mut f, b"[core\n\tbroken = \n").unwrap();
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    let kinds = sink.kinds();
    assert_eq!(
        git_outcome(&r.items),
        ItemOutcome::NotApplied {
            item: ProjectionItem::Git,
            reason: Some(ConflictKind::UnmanageableFile)
        },
        "{kinds:?}"
    );
    assert!(!kinds.contains(&format!("{b}:validated")), "{kinds:?}");
    assert!(!kinds.contains(&format!("{b}:exchanged")), "{kinds:?}");
    assert_eq!(std::fs::read(fx.global()).unwrap(), before);
    assert!(!fx.lock().exists(), "K released");
    assert!(!staged.exists());
    assert!(
        sink.file_phases(b).iter().any(|p| matches!(
            p,
            FilePhase::SettleConflict {
                found: SettleConflictFound::Modified,
                ..
            }
        )),
        "{kinds:?}"
    );
    // The same intent with the bytes untouched passes the check and applies.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let r = fx
        .writer()
        .apply(&fx.plan().intent(), &mut Sink::default())
        .unwrap();
    assert!(applied_git(&r.items), "{r:?}");
}

/// ADR-0007 §12.19 item 8, §12.20 item 2(a): when B_git's parse check cannot run
/// (local queries disabled, no verified Git client in the inventory, or a selected
/// client that cannot be started), the Git item aborts before its commit point with
/// reason `verified_client_unavailable` (`ConflictKind::VerifiedClientUnavailable`),
/// never `unmanageable_file` (that is a check that ran and refused the bytes,
/// `git_parse_check_failure_aborts_before_the_commit_point`). B_git is never exchanged,
/// the global file is unchanged, K is released and nothing is left behind; the SSH
/// item applies. The reason is recorded in `item.finished` (§12.20 item 2(b)), so a
/// restart from the receipts reports the same reason and writes nothing.
#[test]
fn git_parse_check_that_cannot_run_aborts_as_verified_client_unavailable() {
    for case in ["queries_disabled", "no_git_client", "client_cannot_start"] {
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let before = std::fs::read(fx.global()).unwrap();
        let intent = fx.plan().intent();
        let b = step_of(&intent, FileRole::GitInclude);
        let mut config = fx.config();
        match case {
            "queries_disabled" => config.queries = LocalQueries::Disabled,
            "no_git_client" => config
                .clients
                .candidates
                .retain(|c| c.kind != ClientKind::Git),
            _ => {
                for c in &mut config.clients.candidates {
                    if c.kind == ClientKind::Git {
                        c.path = fx.home.root.join("no-such-git");
                    }
                }
            }
        }
        let sink = Sink::default();
        let r = LocalProjection::new(config)
            .apply(&intent, &mut sink.clone())
            .unwrap();
        let kinds = sink.kinds();
        let git = git_outcome(&r.items);
        let ItemOutcome::NotApplied { reason, .. } = &git else {
            panic!("{case}: {git:?} {kinds:?}");
        };
        assert_eq!(
            *reason,
            Some(ConflictKind::VerifiedClientUnavailable),
            "{case}"
        );
        assert!(applied_ssh(&r.items), "{case}: {r:?}");
        assert!(
            !kinds.contains(&format!("{b}:validated")),
            "{case}: {kinds:?}"
        );
        assert!(
            !kinds.contains(&format!("{b}:exchanged")),
            "{case}: {kinds:?}"
        );
        assert_eq!(std::fs::read(fx.global()).unwrap(), before, "{case}");
        assert!(!fx.lock().exists(), "{case}: K released");
        assert!(leftovers(&fx).is_empty(), "{case}: {:?}", leftovers(&fx));
        assert_eq!(
            kinds.last().map(String::as_str),
            Some("git:finished_not_applied"),
            "{case}"
        );
        assert_eq!(
            finished_reason(&sink, ProjectionItem::Git),
            Some(ConflictKind::VerifiedClientUnavailable),
            "{case}: item.finished records the reason"
        );
        let written = sink.receipts().len();
        let again = restart_with(fx.config(), &intent, &sink);
        assert_eq!(again, r.items, "{case}: a restart reports the same reason");
        assert_eq!(sink.receipts().len(), written, "{case}: and writes nothing");
    }
}

/// The reason the item's `item.finished` recorded (ADR-0007 §12.20 item 2(b)).
fn finished_reason(sink: &Sink, item: ProjectionItem) -> Option<ConflictKind> {
    sink.receipts()
        .iter()
        .filter_map(|r| match &r.local {
            Some(LocalReceipt::Item {
                item: i,
                phase: ItemPhase::Finished { reason, .. },
            }) if *i == item => Some(*reason),
            _ => None,
        })
        .next_back()
        .flatten()
}

fn applied_ssh(items: &[ItemOutcome]) -> bool {
    items.iter().any(|o| {
        matches!(
            o,
            ItemOutcome::Applied {
                item: ProjectionItem::Ssh,
                ..
            }
        )
    })
}

/// ADR-0007 §12.17 item 6, for the Git item: the Git item's check fails because
/// P_git, still inactive, was edited in place after B_git's post-validation. B_git is
/// restored, the edited P_git is held (C7a), and the held Git item keeps K at the lock
/// (its release is due only once every other step reached its end, and a held step
/// never does): the lock still holds K's line, a concurrent `git config --global`
/// still fails, and a restart releases nothing.
#[test]
fn git_check_failure_with_edited_p_git_is_held_and_keeps_k() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let before = std::fs::read(fx.global()).unwrap();
    let intent = fx.plan().intent();
    let b = step_of(&intent, FileRole::GitInclude);
    let pg = step_of(&intent, FileRole::GitManaged);
    let path = fx.p_git();
    let hook = Hook::new().run(ReplacePoint::AfterPostValidate, Some(b), move || {
        let mut t = std::fs::read(&path).unwrap();
        t.extend_from_slice(b"# the owner's edit\n");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, &t).unwrap();
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    let kinds = sink.kinds();
    let ItemOutcome::Held { steps, .. } = git_outcome(&r.items) else {
        panic!("{:?} {kinds:?}", r.items);
    };
    assert_eq!(
        steps.iter().map(|s| (s.step, s.reason)).collect::<Vec<_>>(),
        vec![(pg, HoldReason::ActiveEntryModified)],
        "{kinds:?}"
    );
    assert!(kinds.contains(&format!("{b}:restored")), "{kinds:?}");
    assert_eq!(
        std::fs::read(fx.global()).unwrap(),
        before,
        "B_git restored"
    );
    assert_eq!(
        std::fs::read(fx.lock()).unwrap(),
        holder_bytes(&intent),
        "K keeps the lock: {kinds:?}"
    );
    let k = step_of(&intent, FileRole::GitLock);
    assert!(!kinds.contains(&format!("{k}:settling")), "{kinds:?}");
    let o = fx.git(&["config", "--global", "user.x", "y"]);
    assert!(!o.status.success(), "Git's lock error while K is held");
    let tree = fx.tree();
    let again = restart_with(fx.config(), &intent, &sink);
    assert!(
        matches!(git_outcome(&again), ItemOutcome::Held { .. }),
        "{again:?}"
    );
    assert_eq!(fx.tree(), tree, "a restart moves nothing");
}

/// Every transition of ADR-0007 §5.6's replace, create and restore tables, crashed
/// before and after its receipt, with and without a Unix birth time (the test-only
/// identity source). After restart: the expected outcome, the global file's bytes,
/// and no lock, N_s, N_d or N_k left, except that without a birth time a K that the
/// crash left at the lock is X to the restart, which did not claim it, and is left in
/// place (K4). A run that claimed K releases it (ADR-0007 §12.20 item 1): the first run
/// when it is not crashed, and a restart that resumes from before the claim.
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
                    // K is at the lock when the first run crashed after its claim and
                    // before K's move into the quarantine.
                    let k_at_lock_at_crash = first.is_none()
                        && hook.seen().contains(&(ReplacePoint::AfterLockClaim, k))
                        && !hook.seen().contains(&(ReplacePoint::AfterSettleMove, k));
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
                    } else {
                        assert_eq!(lock_left, k_at_lock_at_crash, "{label}");
                    }
                    if !birth && lock_left && !matches!(git, ItemOutcome::Held { .. }) {
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

/// ADR-0007 §12.11 item 1, with and without a Unix birth time (§12.20 item 1: the run
/// that claimed K keeps it by K's identity and holder digest, then releases it).
#[test]
fn git_lock_occupied_by_holder_until_settlement() {
    for (create, birth) in [(false, true), (true, true), (false, false), (true, false)] {
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
        let mut config = fx.hooked(&hook);
        if !birth {
            config.test.identity = IdentitySource::WithoutBirth;
        }
        let r = apply_or_crash(config, &intent, &Sink::default())
            .unwrap()
            .unwrap();
        assert!(applied_git(&r.items), "create={create} birth={birth}");
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

/// ADR-0007 §12.18 item 4 (review X04). Right after K claims Git's lock
/// (`AfterLockClaim`), or right before B_git's exchange, another process replaces K
/// with its own lock, or K is removed. Before B_git's exchange the live path observes
/// the lock name and requires K's recorded identity and holder digest there; otherwise
/// B_git is never exchanged, nothing is written to the global Git file, and the Git
/// item aborts (`not_applied`) while K's own rows record what the lock name holds: K4
/// (`settle_conflict{foreign}`, the foreign lock left untouched) or K3
/// (`settle_conflict{missing}`). Both on fresh apply and on a restart that resumes
/// from a crash before the claim. The controls: with nothing disturbed the item
/// applies, with and without a birth time (the live check is K's identity and holder
/// digest within one run, §5.6).
#[test]
fn git_lock_lost_before_b_git_exchange_aborts_and_writes_nothing() {
    let mut vectors = 0;
    for restart in [false, true] {
        for at_claim in [true, false] {
            for foreign in [true, false] {
                let fx = Fx::new();
                std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
                let before = std::fs::read(fx.global()).unwrap();
                let intent = fx.plan().intent();
                let k = step_of(&intent, FileRole::GitLock);
                let b = step_of(&intent, FileRole::GitInclude);
                let (point, step) = if at_claim {
                    (ReplacePoint::AfterLockClaim, k)
                } else {
                    (ReplacePoint::BeforeExchange, b)
                };
                let lock = fx.lock();
                let disturb = move || {
                    if foreign {
                        write_lock(&lock, b"[user]\n\tname = Another writer\n");
                    } else {
                        std::fs::remove_file(&lock).unwrap();
                    }
                };
                let label = format!("restart={restart} {point:?}@{step} foreign={foreign}");
                let sink = Sink::default();
                let watch = Hook::new().run(point, Some(step), disturb);
                let out = if restart {
                    let crash = Hook::new().crash(ReplacePoint::BeforeLockClaim, Some(k));
                    assert!(
                        apply_or_crash(fx.hooked(&crash), &intent, &sink).is_none(),
                        "{label}"
                    );
                    restart_with(fx.hooked(&watch), &intent, &sink)
                } else {
                    apply_or_crash(fx.hooked(&watch), &intent, &sink)
                        .unwrap()
                        .unwrap()
                        .items
                };
                let kinds = sink.kinds();
                assert!(watch.seen().contains(&(point, step)), "{label}: {kinds:?}");
                let git = git_outcome(&out);
                let ItemOutcome::NotApplied { reason, .. } = &git else {
                    panic!("{label}: {git:?} {kinds:?}");
                };
                // ADR-0007 §12.20 item 2(b): B_git's own check (the X04 abort) reports
                // `git_config_locked`. A restart that observes the lost lock at its next
                // round aborts by K's rows, with their reasons: K4 (a foreign lock)
                // `git_config_locked`, K3 (K gone) `concurrent_writer`.
                let want = if restart && at_claim && !foreign {
                    ConflictKind::ConcurrentWriter
                } else {
                    ConflictKind::GitConfigLocked
                };
                assert_eq!(*reason, Some(want), "{label}");
                assert_eq!(
                    finished_reason(&sink, ProjectionItem::Git),
                    Some(want),
                    "{label}: recorded"
                );
                let written = sink.receipts().len();
                assert_eq!(
                    restart_with(fx.config(), &intent, &sink),
                    out,
                    "{label}: a restart reports the same outcomes and reasons"
                );
                assert_eq!(sink.receipts().len(), written, "{label}");
                assert!(
                    !kinds.contains(&format!("{b}:exchanged")),
                    "{label}: {kinds:?}"
                );
                assert_eq!(
                    std::fs::read(fx.global()).unwrap(),
                    before,
                    "{label}: nothing written to the global Git file"
                );
                assert!(
                    out.iter().any(|o| matches!(
                        o,
                        ItemOutcome::Applied {
                            item: ProjectionItem::Ssh,
                            ..
                        }
                    )),
                    "{label}: {out:?}"
                );
                let found = sink.file_phases(k).into_iter().find_map(|p| match p {
                    FilePhase::SettleConflict { found, .. } => Some(found),
                    _ => None,
                });
                if foreign {
                    assert_eq!(found, Some(SettleConflictFound::Foreign), "{label}");
                    assert_eq!(
                        std::fs::read(fx.lock()).unwrap(),
                        b"[user]\n\tname = Another writer\n",
                        "{label}: the foreign lock is never moved or removed"
                    );
                } else {
                    assert_eq!(found, Some(SettleConflictFound::Missing), "{label}");
                    assert!(!fx.lock().exists(), "{label}");
                }
                assert_eq!(
                    kinds.last().map(String::as_str),
                    Some("git:finished_not_applied"),
                    "{label}"
                );
                let names: Vec<String> = leftovers(&fx)
                    .into_iter()
                    .filter(|n| !n.ends_with(".gitconfig.lock"))
                    .collect();
                assert!(names.is_empty(), "{label}: {names:?}");
                vectors += 1;
            }
        }
    }
    assert_eq!(vectors, 8);
    // Controls: undisturbed, the live check passes with and without a birth time, so
    // B_git is exchanged and the item applies, and K is released either way (ADR-0007
    // §12.20 item 1: the run that claimed K classifies the lock name by K's identity
    // and holder digest, `git_apply_releases_k_with_and_without_birth_time`).
    for birth in [true, false] {
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let intent = fx.plan().intent();
        let mut config = fx.config();
        if !birth {
            config.test.identity = IdentitySource::WithoutBirth;
        }
        let sink = Sink::default();
        let r = LocalProjection::new(config)
            .apply(&intent, &mut sink.clone())
            .unwrap();
        assert!(
            applied_git(&r.items),
            "birth={birth}: {r:?} {:?}",
            sink.kinds()
        );
        assert_eq!(
            Sha256Hex::of(&std::fs::read(fx.global()).unwrap()),
            target_bytes_digest(step_ref(&intent, FileRole::GitInclude)),
            "birth={birth}"
        );
        assert!(!fx.lock().exists(), "birth={birth}: K released");
    }
}

/// ADR-0007 §12.20 item 1 (blocks the M02 exit). Within the run that claimed K, K's
/// release classifies the lock name by K's identity and holder digest, as the check
/// before B_git's exchange does (§5.6), so a successful Git apply releases K with and
/// without a birth time (the test-only identity source with `birth: None`), for an
/// existing and for an absent global file: K's receipts are exactly `staged`,
/// `settling{path}` naming the lock name and `settled{quarantined}`, with no
/// `settle_conflict`; K is released after B_git's settlement and before
/// `item.finished{applied}`; nothing is left; and Git can write its global file again
/// (a lock left behind would make every later Git configuration write fail).
#[test]
fn git_apply_releases_k_with_and_without_birth_time() {
    for create in [false, true] {
        for birth in [true, false] {
            let fx = Fx::new();
            if create {
                std::fs::remove_file(fx.global()).unwrap();
            } else {
                std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
            }
            let intent = fx.plan().intent();
            let k = step_of(&intent, FileRole::GitLock);
            let b = step_of(&intent, FileRole::GitInclude);
            let mut config = fx.config();
            if !birth {
                config.test.identity = IdentitySource::WithoutBirth;
            }
            let sink = Sink::default();
            let r = LocalProjection::new(config)
                .apply(&intent, &mut sink.clone())
                .unwrap();
            let kinds = sink.kinds();
            let label = format!("create={create} birth={birth}: {kinds:?}");
            assert!(applied_git(&r.items), "{label}: {r:?}");
            assert_eq!(
                Sha256Hex::of(&std::fs::read(fx.global()).unwrap()),
                target_bytes_digest(step_ref(&intent, FileRole::GitInclude)),
                "{label}"
            );
            assert!(!fx.lock().exists(), "{label}: K released");
            let phases = sink.file_phases(k);
            assert!(
                matches!(
                    phases.as_slice(),
                    [
                        FilePhase::Staged { .. },
                        FilePhase::Settling {
                            source: SettleSource::Path,
                            name,
                            ..
                        },
                        FilePhase::Settled {
                            disposition: SettledDisposition::Quarantined
                        },
                    ] if name == ".gitconfig.lock"
                ),
                "{label}: {phases:?}"
            );
            let pos = |s: &str| kinds.iter().position(|x| x == s);
            assert!(
                pos(&format!("{k}:settling")) > pos(&format!("{b}:settled")),
                "{label}: K released last"
            );
            assert_eq!(
                kinds.last().map(String::as_str),
                Some("git:finished_applied"),
                "{label}"
            );
            assert!(leftovers(&fx).is_empty(), "{label}: {:?}", leftovers(&fx));
            let o = fx.git(&["config", "--global", "user.x", "y"]);
            assert!(o.status.success(), "{label}: Git's lock is free again");
        }
    }
}

/// ADR-0007 §12.20 item 1, the restart case: a restart did not claim K, so it keeps
/// the recovery classifier. Without a birth time every entry at the lock name is X
/// there (QR15): after a crash that leaves K at the lock (right after the claim,
/// before B_git's commit, right before K's release), the restart records K4
/// (`settle_conflict{foreign}` naming the lock) and leaves the lock with K's identity
/// and bytes for the owner to remove; K's release is never attempted. With a birth
/// time the same restart proves K and releases it. A restart that claims K itself (a
/// crash before the claim) is a run that claimed K: it releases K without a birth time
/// too. The SSH item applies in every case.
#[test]
fn git_restart_keeps_the_recovery_classifier_for_k() {
    let probe = Fx::new();
    std::fs::write(probe.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let probe_intent = probe.plan().intent();
    let k = step_of(&probe_intent, FileRole::GitLock);
    let b = step_of(&probe_intent, FileRole::GitInclude);
    let mut vectors = 0;
    for birth in [true, false] {
        for (point, step, claimed) in [
            (ReplacePoint::BeforeLockClaim, k, false),
            (ReplacePoint::AfterLockClaim, k, true),
            (ReplacePoint::BeforeCommit, b, true),
            (ReplacePoint::BeforeLockRelease, k, true),
        ] {
            let fx = Fx::new();
            std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
            let before = std::fs::read(fx.global()).unwrap();
            let intent = fx.plan().intent();
            let hook = Hook::new().crash(point, Some(step));
            let mut config = fx.hooked(&hook);
            let mut fresh = fx.config();
            if !birth {
                config.test.identity = IdentitySource::WithoutBirth;
                fresh.test.identity = IdentitySource::WithoutBirth;
            }
            let sink = Sink::default();
            let label = format!("birth={birth} {point:?}@{step}");
            assert!(
                apply_or_crash(config, &intent, &sink).is_none(),
                "{label}: {:?}",
                sink.kinds()
            );
            assert_eq!(fx.lock().exists(), claimed, "{label}: K at the lock");
            let lock = claimed.then(|| {
                (
                    std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
                    std::fs::read(fx.lock()).unwrap(),
                )
            });
            let out = restart_with(fresh, &intent, &sink);
            let kinds = sink.kinds();
            let label = format!("{label}: {kinds:?}");
            assert!(applied_ssh(&out), "{label}: {out:?}");
            let k_phases = sink.file_phases(k);
            let k4 = k_phases.iter().any(|p| {
                matches!(
                    p,
                    FilePhase::SettleConflict {
                        found: SettleConflictFound::Foreign,
                        kept,
                    } if kept.iter().any(|e| e.name == ".gitconfig.lock")
                )
            });
            if claimed && !birth {
                // K4 by the recovery classifier: the lock is never moved or removed.
                assert!(k4, "{label}");
                assert!(
                    !k_phases
                        .iter()
                        .any(|p| matches!(p, FilePhase::Settling { .. })),
                    "{label}: no release is attempted"
                );
                assert_eq!(
                    lock.as_ref().map(|(_, bytes)| bytes.clone()),
                    Some(holder_bytes(&intent)),
                    "{label}"
                );
                assert_eq!(
                    Some((
                        std::fs::symlink_metadata(fx.lock()).unwrap().ino(),
                        std::fs::read(fx.lock()).unwrap(),
                    )),
                    lock,
                    "{label}: K left with its identity and bytes"
                );
                let git = git_outcome(&out);
                if point == ReplacePoint::AfterLockClaim {
                    // B_git was never exchanged: the item aborts by K4's row.
                    assert_eq!(
                        git,
                        ItemOutcome::NotApplied {
                            item: ProjectionItem::Git,
                            reason: Some(ConflictKind::GitConfigLocked)
                        },
                        "{label}"
                    );
                    assert_eq!(std::fs::read(fx.global()).unwrap(), before, "{label}");
                } else {
                    // B_git committed (or commits at T1): applied, the lock left.
                    assert!(applied_git(&out), "{label}: {git:?}");
                }
            } else {
                assert!(!k4, "{label}");
                assert!(applied_git(&out), "{label}: {out:?}");
                assert!(!fx.lock().exists(), "{label}: K released at restart");
                assert!(leftovers(&fx).is_empty(), "{label}: {:?}", leftovers(&fx));
            }
            vectors += 1;
        }
    }
    assert_eq!(vectors, 8);
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
    let plan = fx.plan();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(
        git.applicability,
        GitApplicability::Applicable,
        "the Git item is not offered: {:?}",
        git.reason
    );
    let intent = plan.intent();
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

/// ADR-0007 §5.2 for the Git item (§12.17 item 8): applying B_git changes Git's SSH
/// selection (`git_selection_changed`), and the plan records the selection the owner
/// approves and the one a rollback restores. Rolling back to exactly that restore state
/// needs no decision; so does a rollback after the user set a value of their own, which
/// already wins, so the selection does not change.
#[test]
fn git_consent_apply_decided_rollback_to_consented_state_waived() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let plan = fx.plan();
    let git_reasons: Vec<ConsentReasonKind> = plan
        .view
        .consent
        .reasons
        .iter()
        .filter(|r| r.item == "git")
        .map(|r| r.kind)
        .collect();
    assert_eq!(git_reasons, vec![ConsentReasonKind::GitSelectionChanged]);
    let git = plan.consent.items[&ItemId::git_selection()].clone();
    assert!(git.managed.determined && git.restore.determined);
    let intent = plan.intent();
    let sink = Sink::default();
    let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    let mut spec = fx.spec(Some(record_of(&fx, &intent, &sink)));
    spec.consent = plan.consent.clone();
    let rollback = PreviewIntent::Rollback {
        keep_key_files: true,
        items: [ProjectionItem::Git].into_iter().collect(),
    };
    let rb = fx.writer().preview(&spec, &rollback).unwrap();
    assert!(rb.files.iter().any(|s| s.role == FileRole::GitInclude));
    assert!(!rb.view.consent.decision_required, "{:?}", rb.view.consent);
    // Without the stored consent the same rollback is a change the owner decides.
    let mut bare = spec.clone();
    bare.consent = heimdall_domain::projection::ConsentRecord::default();
    let rb = fx.writer().preview(&bare, &rollback).unwrap();
    assert!(rb.view.consent.decision_required);
    // A value the user set later already wins: the rollback changes no selection.
    let o = fx.git(&["config", "--global", "core.sshCommand", "ssh -v"]);
    assert!(o.status.success());
    let rb = fx.writer().preview(&bare, &rollback).unwrap();
    assert!(rb.files.iter().any(|s| s.role == FileRole::GitInclude));
    assert!(!rb.view.consent.decision_required, "{:?}", rb.view.consent);
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

/// `create_dir_all` that gives every directory it creates mode 0700 whatever the process
/// umask. The writer refuses a directory that group or others can write to
/// (ADR-0007 §5.3 step 1), and a session umask of 0002 (user-private groups, the
/// devbox's default) makes a plain `create_dir_all` produce 0775 directories. A fixture
/// that must produce a directory the writer accepts creates it this way (§12.32 item
/// 13: the test failed on the devbox for this reason and no other).
fn create_owner_only_dir_all(path: &Path) {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .unwrap();
    let mode = std::fs::metadata(path).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o700, "the fixture directory is owner-only");
}

/// `std::fs::set_permissions` with an exact mode.
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Write a file the writer accepts (mode 0600) whatever the process umask: a plain
/// `std::fs::write` of a new file is 0664 under a umask of 0002, which the writer
/// refuses (ADR-0007 §5.3 step 2).
fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    chmod(path, 0o600);
}

#[test]
fn git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win()
 {
    let fx = Fx::new();
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[user]\n\tname = Xdg\n");
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

/// ADR-0007 §5.3 item 9, §5.6, §12.32 item 13. The writer refuses a global Git file, or
/// the directory holding it, that fails a step-1 or step-2 check (a group or other write
/// bit, a link, a second hard link), and refuses the whole operation before the first
/// commit point, the SSH item with it. The preview must therefore not offer the Git item
/// over such a file: the Git item is `not_applicable` with `unmanageable_file`, names the
/// file, plans nothing for Git, and the SSH item still applies.
///
/// This is what the devbox showed. Its session umask is 0002, so the `~/.config/git`
/// the test made with `create_dir_all` was 0775: the preview said "applicable" and the
/// apply refused both items. Git 2.43 was not involved, so each case here also runs
/// under whatever umask the harness has.
#[test]
fn git_global_file_or_directory_the_writer_would_refuse_is_not_applicable_and_ssh_still_applies() {
    type Setup = fn(&Fx);
    let cases: [(&str, Setup); 6] = [
        ("xdg directory group-writable", |fx| {
            let xdg = fx.xdg_dir().join("git").join("config");
            create_owner_only_dir_all(xdg.parent().unwrap());
            write_private(&xdg, b"[user]\n\tname = Xdg\n");
            chmod(xdg.parent().unwrap(), 0o775);
        }),
        ("xdg directory writable by others", |fx| {
            let xdg = fx.xdg_dir().join("git").join("config");
            create_owner_only_dir_all(xdg.parent().unwrap());
            write_private(&xdg, b"[user]\n\tname = Xdg\n");
            chmod(xdg.parent().unwrap(), 0o707);
        }),
        ("home directory group-writable", |fx| {
            chmod(fx.home_dir(), 0o775);
        }),
        ("global file group-writable", |fx| {
            chmod(&fx.global(), 0o664);
        }),
        ("global file a symlink", |fx| {
            let real = fx.home_dir().join("dotfiles-gitconfig");
            std::fs::rename(fx.global(), &real).unwrap();
            std::os::unix::fs::symlink(&real, fx.global()).unwrap();
        }),
        ("global file hard-linked", |fx| {
            std::fs::hard_link(fx.global(), fx.home_dir().join("gitconfig-second-link")).unwrap();
        }),
    ];
    for (label, setup) in cases {
        let fx = Fx::new();
        setup(&fx);
        let tree = fx.tree();
        let plan = fx.plan();
        let git = plan.view.git.clone().unwrap();
        assert_eq!(
            git.applicability,
            GitApplicability::NotApplicable,
            "{label}"
        );
        assert_eq!(git.reason.as_deref(), Some("unmanageable_file"), "{label}");
        assert!(
            git.global_file.is_some(),
            "{label}: the plan names the file that cannot be managed"
        );
        assert!(
            git.include_block.is_none() && git.managed_file.is_none(),
            "{label}: nothing is planned for Git"
        );
        assert!(
            plan.files
                .iter()
                .all(|s| s.role.item() != ProjectionItem::Git),
            "{label}: no Git step"
        );
        assert_eq!(fx.tree(), tree, "{label}: a preview writes nothing");

        // The SSH item is not sunk by the Git item's file.
        let intent = plan.intent();
        let sink = Sink::default();
        let receipt = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
        assert!(
            receipt.items.iter().any(|o| matches!(
                o,
                ItemOutcome::Applied {
                    item: ProjectionItem::Ssh,
                    ..
                }
            )),
            "{label}: {receipt:?} {:?}",
            sink.kinds()
        );
        assert!(
            receipt.items.iter().all(|o| !matches!(
                o,
                ItemOutcome::Applied {
                    item: ProjectionItem::Git,
                    ..
                } | ItemOutcome::NotApplied {
                    item: ProjectionItem::Git,
                    ..
                }
            )),
            "{label}: the Git item is not part of the operation: {receipt:?}"
        );
        assert!(!fx.p_git().exists(), "{label}: P_git was not written");
        assert!(!fx.lock().exists(), "{label}: Git's lock was not taken");
        let global = std::fs::read_to_string(fx.global()).unwrap_or_default();
        assert!(
            !global.contains("heimdall managed include"),
            "{label}: no include block"
        );
    }
}

/// The control for the case above: the same fixtures with owner-only directories and
/// files are offered, applied and rolled back by the Git item, so the refusal is the
/// mode and the link, not the fixture.
#[test]
fn git_global_file_in_an_owner_only_directory_is_applicable_under_any_umask() {
    let fx = Fx::new();
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[user]\n\tname = Xdg\n");
    let plan = fx.plan();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(git.applicability, GitApplicability::Applicable);
    assert_eq!(git.reason, None);
    let (intent, _sink) = apply_git(&fx);
    assert_eq!(
        Path::new(&step_ref(&intent, FileRole::GitInclude).path),
        xdg
    );
}

fn findings<'a>(report: &'a DoctorReport, code: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.code == code).collect()
}

/// Only `~/.gitconfig` existed at apply; the owner then creates the XDG file with a
/// value. Git reads the XDG file first, so Heimdall's include (in `~/.gitconfig`) wins,
/// as disclosed (ADR-0007 §5.6 "Residual, disclosed"; §12.37 item 2). The doctor, run
/// over the same scratch world, reports `git_user_value_shadowed` with both origins and
/// both value digests, and never a value. The user's value stays a present value with
/// its origin, and Heimdall's own is not listed. When the user's value wins instead (B_git
/// in the XDG file, the user's value in `~/.gitconfig`, which Git reads later), the
/// finding is not emitted.
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
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[core]\n\tsshCommand = ssh -q\n");
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/usr/bin/ssh'")
    );

    let report = fx.doctor(LocalQueries::Enabled);
    let shadowed = findings(&report, finding::GIT_USER_VALUE_SHADOWED);
    assert_eq!(shadowed.len(), 1, "{:?}", report.findings);
    let message = &shadowed[0].message;
    let env = Env::from_vars(fx.git_env());
    let own_origin = heimdall_localenv::git::origin_of(&env, &fx.p_git()).unwrap();
    let user_origin = heimdall_localenv::git::origin_of(&env, &xdg).unwrap();
    for needed in [
        own_origin.clone(),
        user_origin.clone(),
        heimdall_localenv::git::value_digest("'/usr/bin/ssh'"),
        heimdall_localenv::git::value_digest("ssh -q"),
    ] {
        assert!(message.contains(&needed), "{needed}: {message}");
    }
    for never in ["ssh -q", "/usr/bin/ssh"] {
        assert!(!message.contains(never), "{never}: {message}");
    }
    assert_eq!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
        1,
        "the user's value is a present value: {:?}",
        report.findings
    );
    let git = report.git.expect("git is installed on the harness");
    assert_eq!(git.values.len(), 1, "{:?}", git.values);
    assert_eq!(
        git.values[0].origin_display.as_deref(),
        Some(user_origin.as_str())
    );
    assert_ne!(
        Some(own_origin.as_str()),
        git.values[0].origin_display.as_deref()
    );

    // The other order: B_git went into the XDG file (it existed at apply), and the
    // user's value is later set in `~/.gitconfig`, which Git reads after it. The user's
    // value wins, so nothing is shadowed (and it is still reported as present).
    let fx = Fx::new();
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[user]\n\tname = Xdg\n");
    let (intent, _sink) = apply_git(&fx);
    assert_eq!(
        Path::new(&step_ref(&intent, FileRole::GitInclude).path),
        xdg
    );
    std::fs::write(fx.global(), b"[core]\n\tsshCommand = ssh -v\n").unwrap();
    assert_eq!(fx.effective_ssh_command().as_deref(), Some("ssh -v"));
    let report = fx.doctor(LocalQueries::Enabled);
    assert!(
        findings(&report, finding::GIT_USER_VALUE_SHADOWED).is_empty(),
        "{:?}",
        report.findings
    );
    assert_eq!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
        1,
        "{:?}",
        report.findings
    );
}

// --- Heimdall's own value after the apply; the rollback's manageability check --------------
//
// ADR-0007 §12.34 item 8 (M02 wave 5d). Every test here runs in the `Fx` scratch world
// above: scratch `HOME`, `XDG_CONFIG_HOME` and `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_GLOBAL`
// unset, every `git` process on `env_clear`.

impl Fx {
    /// A writer whose verified `ssh` client is at `client` (the path P_git renders).
    fn writer_with_client(&self, client: &str) -> LocalProjection {
        let mut c = self.config();
        for candidate in &mut c.clients.candidates {
            if candidate.kind == ClientKind::Ssh {
                candidate.path = PathBuf::from(client);
            }
        }
        LocalProjection::new(c)
    }
}

const GIT_APPLY: PreviewIntent = PreviewIntent::Apply { include_git: true };

/// Apply the Git item (and SSH) once. Returns the spec it applied, the intent and the
/// receipts: `again(&spec, …)` is the spec of a later preview that has the record.
fn applied_once(fx: &Fx) -> (ProjectionSpec, SetupIntent, Sink) {
    let spec = fx.spec(None);
    let plan = fx.writer().preview(&spec, &GIT_APPLY).unwrap();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(
        git.applicability,
        GitApplicability::Applicable,
        "the Git item is not offered: {:?}",
        git.reason
    );
    let intent = plan.intent();
    let sink = Sink::default();
    let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    assert!(applied_git(&r.items), "{r:?} {:?}", sink.kinds());
    (spec, intent, sink)
}

fn again(fx: &Fx, spec: &ProjectionSpec, intent: &SetupIntent, sink: &Sink) -> ProjectionSpec {
    let mut next = spec.clone();
    next.record = Some(record_of(fx, intent, sink));
    next
}

fn git_steps(plan: &ProjectionPlan) -> Vec<FileRole> {
    plan.files
        .iter()
        .filter(|s| s.role.item() == ProjectionItem::Git)
        .map(|s| s.role)
        .collect()
}

/// After the Git item is applied, B_git includes P_git, which holds Heimdall's own
/// `core.sshCommand`. A preview that took that for a user's value reported
/// `git_ssh_command_present`, so no update or re-render could ever be planned. Here the
/// item stays applicable: unchanged, there is nothing to write; with a changed verified
/// client path an update of P_git alone (the Git commit step, no lock, B_git not
/// touched) is planned, applies, and Git then selects the new client; with an alias
/// changed the Git item is still offered and SSH is updated.
#[test]
fn git_reapply_after_apply_plans_an_update_instead_of_git_ssh_command_present() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (spec, intent, sink) = applied_once(&fx);
    let global_after_apply = std::fs::read(fx.global()).unwrap();
    let p_git_before = std::fs::read(fx.p_git()).unwrap();
    let spec = again(&fx, &spec, &intent, &sink);

    // Unchanged inputs: applicable, nothing to write.
    let plan = fx.writer().preview(&spec, &GIT_APPLY).unwrap();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(git.applicability, GitApplicability::Applicable, "{git:?}");
    assert_eq!(git.reason, None);
    assert!(git.previous_values.is_empty());
    assert!(plan.files.is_empty(), "{:?}", plan.files);

    // An alias changed: the Git item is still offered and plans nothing for Git (P_git
    // renders only the client path); SSH is updated.
    let mut renamed = spec.clone();
    renamed.aliases[0].hostname = "elsewhere.example.invalid".to_owned();
    let plan = fx.writer().preview(&renamed, &GIT_APPLY).unwrap();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(git.applicability, GitApplicability::Applicable, "{git:?}");
    assert_eq!(git.reason, None);
    assert!(git_steps(&plan).is_empty(), "{:?}", git_steps(&plan));
    assert!(
        plan.files.iter().any(|s| s.role == FileRole::ManagedSsh),
        "the alias change is an SSH update"
    );

    // The verified client moved: P_git alone is updated, as the Git commit step.
    let moved = "/opt/heimdall-fixture/bin/ssh";
    let writer = fx.writer_with_client(moved);
    let plan = writer.preview(&spec, &GIT_APPLY).unwrap();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(git.applicability, GitApplicability::Applicable, "{git:?}");
    assert_eq!(git.reason, None);
    assert!(git.include_block.is_none(), "B_git is not planned again");
    assert!(git.managed_file.is_some(), "P_git's change is shown");
    assert_eq!(git_steps(&plan), vec![FileRole::GitManaged]);
    let update = step_ref(&plan.intent(), FileRole::GitManaged).clone();
    assert!(update.commit, "P_git is the Git item's commit step");
    assert_eq!(
        update.base,
        Base::Present {
            sha256: Sha256Hex::of(&p_git_before)
        },
        "the update replaces the P_git that was written"
    );
    let update_intent = plan.intent();
    let sink2 = Sink::default();
    let r = writer.apply(&update_intent, &mut sink2.clone()).unwrap();
    assert!(applied_git(&r.items), "{r:?} {:?}", sink2.kinds());
    assert_eq!(
        fx.effective_ssh_command().as_deref(),
        Some("'/opt/heimdall-fixture/bin/ssh'"),
        "Git now selects the moved client"
    );
    assert_ne!(std::fs::read(fx.p_git()).unwrap(), p_git_before);
    assert_eq!(
        std::fs::read(fx.global()).unwrap(),
        global_after_apply,
        "an update does not touch the global file"
    );
    assert!(!fx.lock().exists(), "no lock was taken");
    assert!(leftovers(&fx).is_empty(), "{:?}", leftovers(&fx));
}

/// The control for the above: a `core.sshCommand` that is not Heimdall's own P_git, added
/// after the apply, still makes the item `not_applicable` (`git_ssh_command_present`),
/// and the plan lists that value, not Heimdall's. Both placements the owner can use are
/// covered: after B_git in the same global file (what `git config --global` writes), and
/// in an XDG file created after the apply, which Git reads first, so Heimdall's include
/// wins over it (the `git_user_value_shadowed` residual: the value is still observed).
#[test]
fn git_user_value_added_after_apply_still_makes_the_item_not_applicable() {
    type Setup = fn(&Fx);
    let cases: [(&str, Setup, &str, &str); 2] = [
        (
            "after B_git in the global file",
            |fx| {
                assert!(
                    fx.git(&["config", "--global", "core.sshCommand", "ssh -v"])
                        .status
                        .success()
                );
            },
            "ssh -v",
            ".gitconfig",
        ),
        (
            "XDG file created after the apply",
            |fx| {
                let xdg = fx.xdg_dir().join("git").join("config");
                create_owner_only_dir_all(xdg.parent().unwrap());
                write_private(&xdg, b"[core]\n\tsshCommand = ssh -q\n");
            },
            "ssh -q",
            "git/config",
        ),
    ];
    for (label, add, value, file) in cases {
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let (spec, intent, sink) = applied_once(&fx);
        add(&fx);
        let tree = fx.tree();
        let spec = again(&fx, &spec, &intent, &sink);
        // Even with a client change, which would otherwise be an update.
        let plan = fx
            .writer_with_client("/opt/heimdall-fixture/bin/ssh")
            .preview(&spec, &GIT_APPLY)
            .unwrap();
        let git = plan.view.git.clone().unwrap();
        assert_eq!(
            git.applicability,
            GitApplicability::NotApplicable,
            "{label}: {git:?}"
        );
        assert_eq!(
            git.reason.as_deref(),
            Some("git_ssh_command_present"),
            "{label}"
        );
        assert!(
            git_steps(&plan).is_empty(),
            "{label}: {:?}",
            git_steps(&plan)
        );
        assert_eq!(
            git.previous_values.len(),
            1,
            "{label}: {:?}",
            git.previous_values
        );
        let v = &git.previous_values[0];
        assert_eq!(
            v.value_sha256,
            heimdall_localenv::git::value_digest(value),
            "{label}"
        );
        let origin = v.origin_display.as_deref().unwrap();
        assert!(origin.ends_with(file), "{label}: {origin}");
        assert_ne!(
            Some(origin),
            heimdall_localenv::git::origin_of(&Env::from_vars(fx.git_env()), &fx.p_git())
                .as_deref(),
            "{label}: Heimdall's own value is not listed"
        );
        assert_eq!(fx.tree(), tree, "{label}: a preview writes nothing");
    }
}

/// P_git is Heimdall's own only while it holds what Heimdall wrote, and only when B_git
/// links it in. Otherwise the update arm would overwrite the owner's file, or a
/// `core.sshCommand` that Heimdall did not link in would pass for Heimdall's.
#[test]
fn git_p_git_edited_or_not_linked_by_b_git_is_never_taken_for_heimdalls_own() {
    // An edited P_git (one key, another value) is Heimdall's file but not what it wrote:
    // never overwritten (`managed_file_edited`, as for P).
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (spec, intent, sink) = applied_once(&fx);
    let spec = again(&fx, &spec, &intent, &sink);
    std::fs::write(fx.p_git(), b"[core]\n\tsshCommand = edited\n").unwrap();
    let edited = std::fs::read(fx.p_git()).unwrap();
    let plan = fx
        .writer_with_client("/opt/heimdall-fixture/bin/ssh")
        .preview(&spec, &GIT_APPLY)
        .unwrap();
    assert!(git_steps(&plan).is_empty(), "{:?}", git_steps(&plan));
    assert!(
        plan.view
            .findings
            .iter()
            .any(|f| f.reason.as_deref() == Some("managed_file_edited")),
        "{:?}",
        plan.view.findings
    );
    assert_eq!(
        std::fs::read(fx.p_git()).unwrap(),
        edited,
        "a preview writes nothing"
    );

    // A second key in P_git is a value Heimdall did not write.
    std::fs::write(
        fx.p_git(),
        b"[core]\n\tsshCommand = one\n\tsshCommand = two\n",
    )
    .unwrap();
    let plan = fx.writer().preview(&spec, &GIT_APPLY).unwrap();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(git.applicability, GitApplicability::NotApplicable);
    assert_eq!(git.reason.as_deref(), Some("git_ssh_command_present"));
    assert!(git_steps(&plan).is_empty());

    // B_git edited: P_git is no longer linked by Heimdall's block, so its value is a
    // present value (the edit is the owner's to resolve; nothing is overwritten).
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (spec, intent, sink) = applied_once(&fx);
    let spec = again(&fx, &spec, &intent, &sink);
    let text = std::fs::read_to_string(fx.global()).unwrap();
    std::fs::write(fx.global(), text.replacen("\tpath = ", "\tpath =  ", 1)).unwrap();
    let plan = fx.writer().preview(&spec, &GIT_APPLY).unwrap();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(
        git.applicability,
        GitApplicability::NotApplicable,
        "{git:?}"
    );
    assert_eq!(git.reason.as_deref(), Some("git_ssh_command_present"));
    assert!(git_steps(&plan).is_empty());

    // The owner's own include of P_git, with no Heimdall block: not B_git, so its value
    // is present, and the owner's file at that path is not overwritten.
    let fx = Fx::new();
    std::fs::create_dir_all(fx.home.config_dir.clone()).unwrap();
    std::fs::write(fx.p_git(), b"[core]\n\tsshCommand = theirs\n").unwrap();
    std::fs::write(
        fx.global(),
        format!("[include]\n\tpath = \"{}\"\n", fx.p_git().display()),
    )
    .unwrap();
    let plan = fx.plan();
    let git = plan.view.git.clone().unwrap();
    assert_eq!(
        git.applicability,
        GitApplicability::NotApplicable,
        "{git:?}"
    );
    assert_eq!(git.reason.as_deref(), Some("git_ssh_command_present"));
    assert!(git_steps(&plan).is_empty());
    assert_eq!(
        std::fs::read(fx.p_git()).unwrap(),
        b"[core]\n\tsshCommand = theirs\n"
    );
}

/// ADR-0007 §5.3 item 9, §12.34 item 8 (2). The writer refuses a global Git file, or its
/// directory, that fails a step-1 or step-2 check, and refuses the whole operation
/// before its first commit point. The apply's preview already says so
/// (`unmanageable_file`); the rollback's preview must too, or the owner approves a
/// rollback that the apply then refuses. A Git-only rollback plans nothing and says why
/// (a `problem` finding with the reason, which the setup driver refuses before
/// admission); with SSH in the same rollback, SSH is still rolled back and the Git item
/// is left whole, B_git and P_git together.
#[test]
fn git_rollback_over_a_global_file_the_writer_would_refuse_plans_nothing_for_git() {
    type Setup = fn(&Fx);
    let cases: [(&str, Setup); 4] = [
        ("global file group-writable", |fx| {
            chmod(&fx.global(), 0o664)
        }),
        ("global file writable by others", |fx| {
            chmod(&fx.global(), 0o606)
        }),
        ("home directory group-writable", |fx| {
            chmod(fx.home_dir(), 0o775)
        }),
        ("global file hard-linked", |fx| {
            std::fs::hard_link(fx.global(), fx.home_dir().join("gitconfig-second-link")).unwrap();
        }),
    ];
    for (label, mutate) in cases {
        let fx = Fx::new();
        std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
        let (spec, intent, sink) = applied_once(&fx);
        let spec = again(&fx, &spec, &intent, &sink);
        let git_only = PreviewIntent::Rollback {
            keep_key_files: true,
            items: [ProjectionItem::Git].into_iter().collect(),
        };
        let both = PreviewIntent::Rollback {
            keep_key_files: true,
            items: [ProjectionItem::Ssh, ProjectionItem::Git]
                .into_iter()
                .collect(),
        };
        // The control: the file as the writer accepts it is rolled back by a plan that
        // edits it.
        let plan = fx.writer().preview(&spec, &git_only).unwrap();
        assert!(
            git_steps(&plan).contains(&FileRole::GitInclude),
            "{label}: the control plans B_git's removal"
        );
        assert!(plan.view.manual_reasons.is_empty(), "{label}");

        mutate(&fx);
        let tree = fx.tree();
        let plan = fx.writer().preview(&spec, &git_only).unwrap();
        assert!(plan.files.is_empty(), "{label}: {:?}", plan.files);
        assert_eq!(
            plan.view.manual_reasons,
            vec!["unmanageable_file".to_owned()],
            "{label}"
        );
        let problems: Vec<_> = plan
            .view
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Problem)
            .collect();
        assert_eq!(problems.len(), 1, "{label}: {:?}", plan.view.findings);
        assert_eq!(
            problems[0].reason.as_deref(),
            Some("unmanageable_file"),
            "{label}"
        );
        assert_eq!(fx.tree(), tree, "{label}: a preview writes nothing");

        // With SSH in the same rollback, SSH goes and the Git item is left whole.
        let plan = fx.writer().preview(&spec, &both).unwrap();
        assert!(
            git_steps(&plan).is_empty(),
            "{label}: {:?}",
            git_steps(&plan)
        );
        assert!(
            plan.files.iter().any(|s| s.role == FileRole::UserSsh),
            "{label}: SSH is rolled back"
        );
        let rb = plan.intent();
        let receipt = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
        assert!(applied_ssh(&receipt.items), "{label}: {receipt:?}");
        assert!(
            std::fs::read_to_string(fx.global())
                .unwrap()
                .contains("heimdall managed include"),
            "{label}: B_git stays"
        );
        assert!(fx.p_git().exists(), "{label}: P_git stays with B_git");
        assert!(!fx.lock().exists(), "{label}: Git's lock was not taken");
        assert!(leftovers(&fx).is_empty(), "{label}: {:?}", leftovers(&fx));
    }
}

// --- ADR-0007 §12.35 item 2 (N02): the Git file's snapshot follows the same rules ---------

/// The names in `dir` that start with `prefix`, sorted.
fn snapshot_names(dir: &Path, prefix: &str) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(prefix))
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// `gitconfig.<timestamp>.orig` is held to the rules of `ssh_config.<timestamp>.orig`
/// (§5.5, §12.35 item 2). An entry of that name that is a directory or a symlink, or a
/// file that is not exactly 0600, refuses the Git item before its first edit
/// (`unmanageable_file`): the global Git file, P_git and Git's lock are untouched, while
/// the SSH item, which has a valid snapshot of its own, applies. A valid existing
/// snapshot is accepted, kept byte for byte, and no second copy is made.
#[test]
fn the_git_snapshot_follows_the_same_rules_as_the_ssh_one() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let original: &[u8] = b"[user]\n\tname = Scratch\n";
    let apply_with_state = |fx: &Fx, prepare: &dyn Fn(&Path)| {
        write_private(&fx.global(), original);
        let backups = fx.home.state_dir.join("backups");
        create_owner_only_dir_all(&backups);
        prepare(&backups);
        let writer = LocalProjection::new(fx.config().with_state_dir(fx.home.state_dir.clone()));
        let plan = writer.preview(&fx.spec(None), &GIT_APPLY).unwrap();
        let git = plan.view.git.clone().unwrap();
        assert_eq!(git.applicability, GitApplicability::Applicable);
        let sink = Sink::default();
        let r = writer.apply(&plan.intent(), &mut sink.clone()).unwrap();
        (backups, r.items)
    };

    type Prepare = fn(&Path);
    let invalid: &[(&str, Prepare)] = &[
        ("a directory", |b| {
            std::fs::create_dir(b.join("gitconfig.fake.orig")).unwrap();
        }),
        ("a symlink to a regular file", |b| {
            let real = b.parent().unwrap().join("real");
            write_private(&real, b"a bystander\n");
            symlink(&real, b.join("gitconfig.fake.orig")).unwrap();
        }),
        ("a file with mode 0644", |b| {
            write_private(&b.join("gitconfig.fake.orig"), b"x\n");
            chmod(&b.join("gitconfig.fake.orig"), 0o644);
        }),
        ("a file with mode 0400", |b| {
            write_private(&b.join("gitconfig.fake.orig"), b"x\n");
            chmod(&b.join("gitconfig.fake.orig"), 0o400);
        }),
    ];
    for (label, prepare) in invalid {
        let fx = Fx::new();
        let (backups, items) = apply_with_state(&fx, prepare);
        assert_eq!(
            git_outcome(&items),
            ItemOutcome::NotApplied {
                item: ProjectionItem::Git,
                reason: Some(ConflictKind::UnmanageableFile)
            },
            "{label}: {items:?}"
        );
        assert!(
            applied_ssh(&items),
            "{label}: SSH has its own snapshot: {items:?}"
        );
        assert_eq!(
            std::fs::read(fx.global()).unwrap(),
            original,
            "{label}: the global Git file is untouched"
        );
        assert!(!fx.p_git().exists(), "{label}");
        assert!(!fx.lock().exists(), "{label}: Git's lock was not taken");
        assert_eq!(
            snapshot_names(&backups, "gitconfig."),
            ["gitconfig.fake.orig"],
            "{label}: no gitconfig snapshot was made beside the invalid entry"
        );
        assert_eq!(snapshot_names(&backups, "ssh_config.").len(), 1, "{label}");
        assert!(leftovers(&fx).is_empty(), "{label}: {:?}", leftovers(&fx));
    }

    // A valid existing snapshot is accepted and no second copy is made.
    let fx = Fx::new();
    let (backups, items) = apply_with_state(&fx, &|b| {
        let seed = b.join("gitconfig.20200102T030405Z.orig");
        write_private(&seed, b"an earlier original\n");
    });
    assert!(applied_git(&items), "{items:?}");
    assert_eq!(
        snapshot_names(&backups, "gitconfig."),
        ["gitconfig.20200102T030405Z.orig"]
    );
    let seed = backups.join("gitconfig.20200102T030405Z.orig");
    assert_eq!(std::fs::read(&seed).unwrap(), b"an earlier original\n");
    assert_eq!(
        std::fs::metadata(&seed).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_ne!(
        std::fs::read(fx.global()).unwrap(),
        original,
        "the item edited the global Git file"
    );
}

// --- the doctor and Heimdall's own value; a rollback finds B_git where it was written --------
//
// ADR-0007 §12.37 items 1 to 3 (M02 wave 5f). Same `Fx` scratch world as above.

/// After a real Git apply, the doctor takes the value reached once through B_git for
/// Heimdall's own: it is the projection's Git selection and never
/// `git_ssh_command_present`. A user value is still reported with its origin, and a B_git
/// that has been edited no longer vouches for P_git's value (fail closed).
#[test]
fn git_doctor_after_apply_reports_no_present_value_for_heimdalls_own() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    // Before the apply there is no value at all.
    let report = fx.doctor(LocalQueries::Enabled);
    assert!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).is_empty(),
        "{:?}",
        report.findings
    );
    let (_intent, _sink) = apply_git(&fx);
    let tree = fx.tree();

    let report = fx.doctor(LocalQueries::Enabled);
    assert!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).is_empty(),
        "Heimdall's own value is not a present value: {:?}",
        report.findings
    );
    assert!(findings(&report, finding::GIT_USER_VALUE_SHADOWED).is_empty());
    let git = report.git.expect("git is installed on the harness");
    assert!(git.values.is_empty(), "{:?}", git.values);
    assert_eq!(
        git.selection.source,
        heimdall_contract::doctor::GitSshSource::Config
    );
    assert_eq!(
        git.selection.scope,
        Some(heimdall_contract::doctor::GitScope::Global)
    );
    assert_eq!(fx.tree(), tree, "the doctor changes nothing");

    // A user value elsewhere is reported, with its origin.
    assert!(
        fx.git(&["config", "--global", "core.sshCommand", "ssh -v"])
            .status
            .success()
    );
    let report = fx.doctor(LocalQueries::Enabled);
    assert_eq!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
        1,
        "{:?}",
        report.findings
    );
    let git = report.git.unwrap();
    assert_eq!(git.values.len(), 1, "{:?}", git.values);
    assert_eq!(
        git.values[0].value_sha256,
        heimdall_localenv::git::value_digest("ssh -v")
    );
    assert!(
        git.values[0]
            .origin_display
            .as_deref()
            .is_some_and(|o| o.ends_with(".gitconfig")),
        "{:?}",
        git.values
    );

    // B_git edited: P_git is no longer linked by Heimdall's block, so its value is
    // reported like any other.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let _ = apply_git(&fx);
    let text = std::fs::read_to_string(fx.global()).unwrap();
    std::fs::write(fx.global(), text.replacen("\tpath = ", "\tpath =  ", 1)).unwrap();
    let report = fx.doctor(LocalQueries::Enabled);
    assert_eq!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
        1,
        "{:?}",
        report.findings
    );
}

/// The writer records the file it wrote B_git into on the Git item's record
/// (`ItemRecord::include_file`), for the first-read file Git resolved at apply: the
/// existing `~/.gitconfig`, the XDG file when it exists. An update of P_git alone writes
/// no B_git and names none (the application's sink keeps the previous generation's), and
/// the SSH item never names one.
#[test]
fn git_apply_records_the_file_b_git_was_written_into() {
    // ~/.gitconfig only.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (spec, intent, sink) = applied_once(&fx);
    assert_eq!(
        sink.recorded_include_file().as_deref(),
        Some(fx.global().to_str().unwrap())
    );
    let ssh = sink
        .commits()
        .into_iter()
        .find(|c| c.item == ProjectionItem::Ssh)
        .unwrap();
    assert_eq!(ssh.record.items[&ProjectionItem::Ssh].include_file, None);

    // An update of P_git alone: the commit names no file.
    let spec = again(&fx, &spec, &intent, &sink);
    let writer = fx.writer_with_client("/opt/heimdall-fixture/bin/ssh");
    let plan = writer.preview(&spec, &GIT_APPLY).unwrap();
    assert_eq!(git_steps(&plan), vec![FileRole::GitManaged]);
    let update = Sink::default();
    let r = writer.apply(&plan.intent(), &mut update.clone()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    let commit = update
        .commits()
        .into_iter()
        .find(|c| c.item == ProjectionItem::Git)
        .unwrap();
    assert_eq!(commit.record.items[&ProjectionItem::Git].include_file, None);

    // The XDG file exists at apply: B_git goes there, and that is the recorded file.
    let fx = Fx::new();
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[user]\n\tname = Xdg\n");
    let (_spec, _intent, sink) = applied_once(&fx);
    assert_eq!(
        sink.recorded_include_file().as_deref(),
        Some(xdg.to_str().unwrap())
    );
}

/// Whether the intent plans P_git's removal: a Git step with an absent target, which the
/// cleaner (not the writer's apply) carries out.
fn removes_p_git(intent: &SetupIntent) -> bool {
    intent
        .files
        .iter()
        .any(|s| s.role == FileRole::GitManaged && matches!(s.target, Target::Absent))
}

/// ADR-0007 §12.37 item 3, the regression. B_git went into `~/.gitconfig` because no XDG
/// file existed. The owner then created the XDG file, which Git reads first, so it is now
/// the first-read file. The rollback removes B_git from the file its step wrote (the
/// record names it): `~/.gitconfig` is byte for byte what it was before the apply, P_git
/// is removed, and the XDG file is not touched. Reading only the first-read file removed
/// P_git and left B_git behind in `~/.gitconfig`.
#[test]
fn git_rollback_finds_b_git_in_the_file_its_step_wrote_after_an_xdg_file_appears() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let original = std::fs::read(fx.global()).unwrap();
    let (intent, sink) = apply_git(&fx);
    assert_ne!(std::fs::read(fx.global()).unwrap(), original);
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[user]\n\tname = Xdg\n");
    let xdg_bytes = std::fs::read(&xdg).unwrap();

    let plan = rollback_git(&fx, &intent, &sink);
    let rb = plan.intent();
    assert_eq!(
        Path::new(&step_ref(&rb, FileRole::GitInclude).path),
        fx.global(),
        "the removal is planned where B_git was written"
    );
    assert!(removes_p_git(&rb), "P_git's removal is planned");
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert_eq!(std::fs::read(fx.global()).unwrap(), original);
    assert_eq!(std::fs::read(&xdg).unwrap(), xdg_bytes);
    assert_eq!(fx.effective_ssh_command(), None);
    assert!(!fx.lock().exists());
    assert!(leftovers(&fx).is_empty(), "{:?}", leftovers(&fx));
}

/// The record names the file, so the record decides, whatever else is in the global
/// files: a second Heimdall block in the other global file (a copy the owner made) does
/// not make the rollback ambiguous, and it is not touched. A record that names a file
/// that no longer exists leaves nothing to remove from it: P_git alone is removed.
#[test]
fn git_rollback_trusts_the_recorded_file_over_what_else_the_global_files_hold() {
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let original = std::fs::read(fx.global()).unwrap();
    let (intent, sink) = apply_git(&fx);
    let with_block = std::fs::read(fx.global()).unwrap();
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, &with_block);
    let copy = std::fs::read(&xdg).unwrap();

    let plan = rollback_git(&fx, &intent, &sink);
    assert!(plan.view.manual_reasons.is_empty(), "{:?}", plan.view);
    let rb = plan.intent();
    assert_eq!(
        Path::new(&step_ref(&rb, FileRole::GitInclude).path),
        fx.global()
    );
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert_eq!(std::fs::read(fx.global()).unwrap(), original);
    assert_eq!(
        std::fs::read(&xdg).unwrap(),
        copy,
        "the other file is not touched"
    );

    // The recorded file is gone: nothing to remove from it, and P_git alone is.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (intent, sink) = apply_git(&fx);
    std::fs::remove_file(fx.global()).unwrap();
    let plan = rollback_git(&fx, &intent, &sink);
    assert_eq!(
        git_steps(&plan),
        vec![FileRole::GitManaged],
        "no B_git step"
    );
    assert!(removes_p_git(&plan.intent()));
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert!(!fx.global().exists(), "the owner's file is not recreated");
}

/// A record written before it named the file: both global files are searched. Exactly one
/// Heimdall block names the file, and the removal is planned there, with the XDG file
/// created after the apply left alone. More than one block, in the two files, cannot be
/// told apart: manual mode, nothing planned for the Git item (B_git and P_git stay), a
/// `problem` finding that says why, and nothing written. No block at all leaves only
/// P_git to remove.
#[test]
fn git_rollback_without_a_recorded_file_searches_both_global_files() {
    use heimdall_contract::setup::SetupMode;
    let without_file = |fx: &Fx, intent: &SetupIntent, sink: &Sink| -> ProjectionSpec {
        let mut record = record_of(fx, intent, sink);
        record
            .items
            .get_mut(&ProjectionItem::Git)
            .unwrap()
            .include_file = None;
        fx.spec(Some(record))
    };
    let git_only = PreviewIntent::Rollback {
        keep_key_files: true,
        items: [ProjectionItem::Git].into_iter().collect(),
    };

    // Exactly one block (in ~/.gitconfig; the XDG file appeared later without one).
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let original = std::fs::read(fx.global()).unwrap();
    let (intent, sink) = apply_git(&fx);
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, b"[user]\n\tname = Xdg\n");
    let spec = without_file(&fx, &intent, &sink);
    assert_eq!(
        spec.record.as_ref().unwrap().items[&ProjectionItem::Git].include_file,
        None
    );
    let plan = fx.writer().preview(&spec, &git_only).unwrap();
    assert!(plan.view.manual_reasons.is_empty(), "{:?}", plan.view);
    let rb = plan.intent();
    assert_eq!(
        Path::new(&step_ref(&rb, FileRole::GitInclude).path),
        fx.global()
    );
    assert!(removes_p_git(&rb));
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert_eq!(std::fs::read(fx.global()).unwrap(), original);

    // Two blocks, one in each global file: manual mode.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (intent, sink) = apply_git(&fx);
    let xdg = fx.xdg_dir().join("git").join("config");
    create_owner_only_dir_all(xdg.parent().unwrap());
    write_private(&xdg, &std::fs::read(fx.global()).unwrap());
    let spec = without_file(&fx, &intent, &sink);
    let tree = fx.tree();
    let plan = fx.writer().preview(&spec, &git_only).unwrap();
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert_eq!(plan.view.manual_reasons, ["marker_duplicated"]);
    assert!(plan.files.is_empty(), "{:?}", plan.files);
    assert!(
        plan.view
            .findings
            .iter()
            .any(|f| f.code == "marker_duplicated"
                && f.severity == FindingSeverity::Problem
                && f.reason.as_deref() == Some("marker_duplicated")),
        "{:?}",
        plan.view.findings
    );
    assert_eq!(fx.tree(), tree, "a preview writes nothing");

    // Two blocks in the one file: also not told apart.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let (intent, sink) = apply_git(&fx);
    let once = std::fs::read(fx.global()).unwrap();
    let mut twice = once.clone();
    twice.extend_from_slice(&once);
    std::fs::write(fx.global(), twice).unwrap();
    let plan = fx
        .writer()
        .preview(&without_file(&fx, &intent, &sink), &git_only)
        .unwrap();
    assert_eq!(plan.view.manual_reasons, ["marker_duplicated"]);
    assert!(plan.files.is_empty(), "{:?}", plan.files);

    // No block anywhere (the owner removed it): P_git alone is removed.
    let fx = Fx::new();
    std::fs::write(fx.global(), b"[user]\n\tname = Scratch\n").unwrap();
    let original = std::fs::read(fx.global()).unwrap();
    let (intent, sink) = apply_git(&fx);
    std::fs::write(fx.global(), &original).unwrap();
    let plan = fx
        .writer()
        .preview(&without_file(&fx, &intent, &sink), &git_only)
        .unwrap();
    assert!(plan.view.manual_reasons.is_empty(), "{:?}", plan.view);
    assert_eq!(git_steps(&plan), vec![FileRole::GitManaged]);
    assert!(removes_p_git(&plan.intent()));
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(applied_git(&r.items), "{r:?}");
    assert_eq!(std::fs::read(fx.global()).unwrap(), original);
}
