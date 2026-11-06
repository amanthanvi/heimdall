//! W2-U4c: the projection file transaction (m02-plan U4, the A22 transaction half;
//! ADR-0007 §5.3–§5.8).
//!
//! Every test runs in a `heimdall_testkit::home::ScratchHome` (a scratch home, a
//! scratch `~/.ssh`, Heimdall's scratch configuration directory) and touches nothing
//! outside it: the writer is configured with `SshPaths::with_test_override`, and the
//! public keys it materializes are synthetic, generated per run (no private key exists
//! anywhere). No test runs a client against these files and no test reads the
//! account's real `~/.ssh`.
//!
//! **Crashes.** A "crash" is an in-process crash: the test `ReplaceHook` panics with
//! the [`Crash`] payload at a point, the writer unwinds (all of its in-memory state is
//! dropped), and the test restarts with a fresh `LocalProjection` over the receipts the
//! sink made durable. The writer keeps no state between calls (M2-S05), so this is
//! what a process restart sees; it is not an operating-system process abort, and the
//! evidence records label it so (an in-process unwind). The store-backed variant uses
//! the store's own `FaultHook` (`heimdall_testkit::ScriptedFaults`). One test,
//! `a22_first_adoption_commit_point_crash_as_a_process_abort_reconciles`, is a real
//! **process abort**: a child process calls `std::process::abort` at the hook and dies
//! by SIGABRT, and a fresh child process reconciles (ADR-0007 §12.17 item 8).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once, PoisonError};

use heimdall_app::ports::{
    ItemOutcome, ProjectionReceipt, ProjectionWriter, ReconcileError, ResourceCleaner, SinkError,
    StageSink,
};
use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, IdentityId, OperationId};
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem, SetupMode};
use heimdall_domain::operation::{
    AdapterIdentity, EffectReceipt, FilePhase, HoldReason, ItemFinish, ItemPhase, LocalReceipt,
    PostVerdict, SettleConflictFound, StageReceipt,
};
use heimdall_domain::projection::{
    FileRole, FileStep, ItemCommit, ProjectionLocator, ProjectionPlan, ProjectionRecord,
    ProjectionSpec, SetupIntent, Sha256Hex, Target,
};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_localenv::env::Platform;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::cleaner::ProjectionCleaner;
use heimdall_localenv::projection::{
    LocalProjection, ProjectionConfig, PublicKeySource, ReplaceHook, ReplacePoint,
};
use heimdall_testkit::home::ScratchHome;

// --- fixtures ---------------------------------------------------------------------------

/// The panic payload of an injected crash.
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

/// A scripted `ReplaceHook`: each rule fires at its point (and step) a number of
/// times; every point reached is recorded.
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

impl ReplaceHook for Hook {
    fn at(&self, point: ReplacePoint, step: u16) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((point, step));
        let act = {
            let mut rules = self.rules.lock().unwrap_or_else(PoisonError::into_inner);
            rules
                .iter_mut()
                .find(|r| r.point == point && r.step.is_none_or(|s| s == step) && r.left > 0)
                .map(|r| {
                    r.left -= 1;
                    r.act.clone()
                })
        };
        match act {
            Some(Act::Crash) => std::panic::panic_any(Crash),
            Some(Act::Run(f)) => f(),
            None => {}
        }
    }
}

/// Synthetic public keys by identity (preview only).
#[derive(Default)]
struct KeyBook(Mutex<BTreeMap<String, String>>);

impl PublicKeySource for KeyBook {
    fn public_key(&self, identity: &IdentityId) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(identity.as_str())
            .cloned()
    }
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

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

/// A synthetic `ssh-ed25519` public key line: a valid wire blob over 32 random bytes,
/// generated per run. It has no private key.
fn synthetic_public_key() -> String {
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend(random::<32>());
    format!("ssh-ed25519 {}", b64(&blob))
}

/// The scratch world of one test.
struct Fx {
    home: ScratchHome,
    keys: Arc<KeyBook>,
    env: EnvironmentId,
    /// The selected `ssh` client's version, when the fixture names one (otherwise
    /// unknown: the strictest reading, ADR-0007 §12.32 item 11).
    client: Option<heimdall_sshconf::eval::OpenSshVersion>,
}

impl Fx {
    fn new() -> Fx {
        quiet_crashes();
        let home = ScratchHome::new();
        std::fs::create_dir(home.root.join("etc-ssh")).unwrap();
        Fx {
            home,
            keys: Arc::default(),
            env: EnvironmentId::from_random_bytes(random()),
            client: None,
        }
    }

    fn user(&self) -> &Path {
        &self.home.user_config
    }

    fn ssh_dir(&self) -> &Path {
        &self.home.ssh_dir
    }

    fn p(&self) -> PathBuf {
        self.home.config_dir.join("ssh_config")
    }

    fn config(&self) -> ProjectionConfig {
        let paths = SshPaths::with_test_override(
            self.home.git_home.clone(),
            self.home.root.join("etc-ssh"),
        );
        // ADR-0007 §12.32 item 2: the snapshot is the writer's, so every writer of these
        // tests takes it, into the scratch state directory.
        let mut c = ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone())
            .with_state_dir(self.home.state_dir.clone());
        let keys: Arc<dyn PublicKeySource> = self.keys.clone();
        c.keys = Some(keys);
        if let Some(version) = self.client {
            use heimdall_localenv::clients::{
                ClientCandidate, ClientInventory, ClientKind, ClientSource,
            };
            c.clients = ClientInventory {
                candidates: vec![ClientCandidate {
                    kind: ClientKind::Ssh,
                    path: self.home.root.join("bin").join("ssh"),
                    source: ClientSource::Path,
                    version: Some(version),
                    sha256: None,
                    selected: true,
                }],
            };
        }
        c
    }

    /// A fixture whose selected `ssh` is an observed client that evaluates `Match
    /// sessiontype` (OpenSSH 10.5p1, ADR-0007 §12.32 item 11).
    fn with_sessiontype_client() -> Fx {
        Fx {
            client: Some(heimdall_sshconf::eval::OpenSshVersion {
                major: 10,
                minor: 5,
                portable: Some(1),
            }),
            ..Fx::new()
        }
    }

    fn hooked(&self, hook: &Arc<Hook>) -> ProjectionConfig {
        let mut c = self.config();
        let h: Arc<dyn ReplaceHook> = hook.clone();
        c.hook = Some(h);
        c
    }

    /// `<state>/backups`.
    fn backups(&self) -> PathBuf {
        self.home.state_dir.join("backups")
    }

    /// The snapshots named `name.<timestamp>.orig` in the backups directory, sorted.
    fn snapshots(&self, name: &str) -> Vec<PathBuf> {
        let prefix = format!("{name}.");
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.backups())
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        found
    }

    fn writer(&self) -> LocalProjection {
        LocalProjection::new(self.config())
    }

    fn alias(&self, name: &str) -> heimdall_domain::projection::ManagedAliasSpec {
        let identity = IdentityId::from_random_bytes(random());
        let key = synthetic_public_key();
        self.keys
            .0
            .lock()
            .unwrap()
            .insert(identity.as_str().to_owned(), key);
        heimdall_domain::projection::ManagedAliasSpec {
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

    fn spec(&self, names: &[&str], record: Option<ProjectionRecord>) -> ProjectionSpec {
        ProjectionSpec {
            environment: self.env.clone(),
            aliases: names.iter().map(|n| self.alias(n)).collect(),
            record,
            consent: heimdall_domain::projection::ConsentRecord::default(),
        }
    }

    fn preview(&self, spec: &ProjectionSpec, intent: &PreviewIntent) -> ProjectionPlan {
        self.writer().preview(spec, intent).unwrap()
    }

    fn apply_intent() -> PreviewIntent {
        PreviewIntent::Apply { include_git: false }
    }

    fn rollback_intent() -> PreviewIntent {
        PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        }
    }

    /// Preview and apply the projection of `names`; returns the intent and the sink.
    fn adopt(&self, names: &[&str]) -> (SetupIntent, Sink) {
        let plan = self.preview(&self.spec(names, None), &Fx::apply_intent());
        let intent = plan.intent();
        let sink = Sink::default();
        let r = self.writer().apply(&intent, &mut sink.clone()).unwrap();
        assert_eq!(
            r.items,
            vec![ItemOutcome::Applied {
                item: ProjectionItem::Ssh,
                generation: 1
            }]
        );
        (intent, sink)
    }

    /// A ready generation-1 projection and the spec of an update to generation 2
    /// that adds `extra`.
    fn update_plan(&self, names: &[&str], extra: &str) -> (SetupIntent, Sink, SetupIntent) {
        let (first, sink) = self.adopt(names);
        let mut spec = self.spec(&[], Some(sink.record(&self.env)));
        spec.aliases = first_aliases(&first, self, names);
        spec.aliases.push(self.alias(extra));
        let plan = self.preview(&spec, &Fx::apply_intent());
        (first, sink, plan.intent())
    }

    fn tree(&self) -> BTreeMap<String, Entry> {
        let mut out = BTreeMap::new();
        walk(self.ssh_dir(), "ssh", &mut out);
        walk(&self.home.config_dir, "config", &mut out);
        out
    }

    fn cleaner(&self) -> ProjectionCleaner {
        ProjectionCleaner::new(self.config())
    }
}

/// The aliases of the first plan, with the same identities and key files (their keys
/// are already in the key book).
fn first_aliases(
    first: &SetupIntent,
    fx: &Fx,
    names: &[&str],
) -> Vec<heimdall_domain::projection::ManagedAliasSpec> {
    let _ = first;
    let book = fx.keys.0.lock().unwrap();
    let mut out = Vec::new();
    for n in names {
        let key_file = fx
            .home
            .config_dir
            .join("keys")
            .join(format!("{n}.pub"))
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = std::fs::read_to_string(&key_file).unwrap();
        let identity = book
            .iter()
            .find(|(_, k)| bytes.starts_with(k.as_str()))
            .map(|(id, _)| IdentityId::parse(id).unwrap())
            .unwrap();
        out.push(heimdall_domain::projection::ManagedAliasSpec {
            alias: (*n).to_owned(),
            destination: DestinationId::parse(&format!("dst-{n}")).unwrap(),
            hostname: format!("{n}.example.invalid"),
            port: None,
            account: AccountName::parse("fixture").unwrap(),
            identity,
            endpoint: None,
            key_file,
        });
    }
    out
}

/// One entry of a scratch tree: identity (inode) and content.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    ino: u64,
    kind: char,
    bytes: Vec<u8>,
}

fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Entry>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let e = e.unwrap();
        let name = format!("{prefix}/{}", e.file_name().to_string_lossy());
        let m = std::fs::symlink_metadata(e.path()).unwrap();
        if m.is_dir() {
            out.insert(
                name.clone(),
                Entry {
                    ino: m.ino(),
                    kind: 'd',
                    bytes: Vec::new(),
                },
            );
            walk(&e.path(), &name, out);
        } else if m.file_type().is_symlink() {
            let t = std::fs::read_link(e.path()).unwrap();
            out.insert(
                name,
                Entry {
                    ino: m.ino(),
                    kind: 'l',
                    bytes: t.to_string_lossy().as_bytes().to_vec(),
                },
            );
        } else {
            out.insert(
                name,
                Entry {
                    ino: m.ino(),
                    kind: 'f',
                    bytes: std::fs::read(e.path()).unwrap_or_default(),
                },
            );
        }
    }
}

/// Every name in the tree that is a Heimdall leftover: staged or displaced names,
/// quarantine entries, conflict names, a lock.
fn leftovers(tree: &BTreeMap<String, Entry>) -> Vec<String> {
    tree.keys()
        .filter(|k| {
            k.contains(".hm-") && !k.ends_with(".hm-quarantine") || k.contains("hm-conflict")
        })
        .cloned()
        .collect()
}

/// A test `StageSink`: receipts and commits in memory, with injected failures.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<SinkLog>>);

#[derive(Default)]
struct SinkLog {
    receipts: Vec<StageReceipt>,
    commits: Vec<ItemCommit>,
    fail_commit: bool,
}

fn adapter() -> AdapterIdentity {
    AdapterIdentity {
        mechanism: "config_projection".into(),
        instance: "scratch".into(),
    }
}

fn durable(local: &LocalReceipt) -> StageReceipt {
    StageReceipt {
        stage: local.stage().to_owned(),
        recorded_at: heimdall_contract::Timestamp::now(),
        effect: if local.effect_is_confirmed() {
            EffectReceipt::Confirmed {
                adapter: adapter(),
                credential_ref: "projection".into(),
            }
        } else {
            EffectReceipt::Attempted {
                adapter: adapter(),
                effect_token: "eff_scratch".into(),
            }
        },
        local: Some(local.clone()),
    }
}

impl StageSink for Sink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        let mut l = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        l.receipts.push(durable(receipt));
        Ok(())
    }

    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError> {
        let mut l = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if l.fail_commit {
            return Err(SinkError("injected commit failure".into()));
        }
        l.receipts.push(durable(&LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        }));
        l.commits.push(commit);
        Ok(())
    }
}

impl Sink {
    fn receipts(&self) -> Vec<StageReceipt> {
        self.0.lock().unwrap().receipts.clone()
    }

    fn commits(&self) -> Vec<ItemCommit> {
        self.0.lock().unwrap().commits.clone()
    }

    /// `step:kind` and `item:kind` for every receipt, in order.
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

    /// The record the sink would have committed for the environment.
    fn record(&self, env: &EnvironmentId) -> ProjectionRecord {
        let mut items = BTreeMap::new();
        for c in self.commits() {
            let mut r = c.record.items.get(&c.item).cloned().unwrap();
            r.operation = OperationId::from_random_bytes([7; 16]);
            items.insert(c.item, r);
        }
        ProjectionRecord {
            environment: env.clone(),
            items,
        }
    }
}

fn kind_of(local: &LocalReceipt) -> String {
    match local {
        LocalReceipt::File { step, phase } => {
            let k = match phase {
                FilePhase::Staged { .. } => "staged",
                FilePhase::Validated { .. } => "validated",
                FilePhase::Exchanged => "exchanged",
                FilePhase::PostValidated {
                    verdict: PostVerdict::Valid,
                    ..
                } => "post_validated",
                FilePhase::PostValidated { .. } => "post_validated_mismatch",
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
            let i = match item {
                ProjectionItem::Ssh => "ssh",
                _ => "git",
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

fn step_of(intent: &SetupIntent, role: FileRole) -> u16 {
    u16::try_from(intent.files.iter().position(|s| s.role == role).unwrap()).unwrap()
}

fn step_ref(intent: &SetupIntent, role: FileRole) -> &FileStep {
    intent.files.iter().find(|s| s.role == role).unwrap()
}

/// Apply under `config`; `None` when the hook crashed the writer.
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

/// Reconcile under `config` from the sink's durable receipts; `None` on a crash.
fn reconcile_or_crash(
    config: ProjectionConfig,
    intent: &SetupIntent,
    sink: &Sink,
) -> Option<Result<Vec<ItemOutcome>, ReconcileError>> {
    let mut s = sink.clone();
    let receipts = sink.receipts();
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        LocalProjection::new(config).reconcile(intent, &receipts, &mut s)
    })) {
        Ok(r) => Some(r.map(|r| r.items)),
        Err(p) if p.is::<Crash>() => None,
        Err(p) => std::panic::resume_unwind(p),
    }
}

/// Restart with a fresh writer and no hook.
fn restart(fx: &Fx, intent: &SetupIntent, sink: &Sink) -> Vec<ItemOutcome> {
    reconcile_or_crash(fx.config(), intent, sink)
        .expect("no hook, no crash")
        .unwrap()
}

fn held_reasons(o: &ItemOutcome) -> Vec<HoldReason> {
    match o {
        ItemOutcome::Held { steps, .. } => steps.iter().map(|s| s.reason).collect(),
        _ => Vec::new(),
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Replace `path` by a new file (another identity) through a rename, as an editor
/// that saves by rename does.
fn rename_replace(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension("editor-tmp");
    write_mode(&tmp, bytes, 0o600);
    std::fs::rename(&tmp, path).unwrap();
}

/// Rewrite `path` in place (same identity).
fn write_in_place(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

const USER_TEXT: &str =
    "# my settings\n\nHost personal\n    HostName personal.example.invalid\n    User me\n";

// --- A22: apply, rollback, render -------------------------------------------------------

#[test]
fn a22_apply_then_rollback_restores_user_bytes_exactly() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let before = std::fs::read(fx.user()).unwrap();
    let (intent, sink) = fx.adopt(&["work", "lab"]);
    let after = std::fs::read(fx.user()).unwrap();
    assert_ne!(after, before, "B was inserted");
    assert!(String::from_utf8_lossy(&after).contains("# >>> heimdall managed include"));
    assert!(fx.p().exists(), "P written");
    assert_eq!(intent.generation, 1);
    let kinds = sink.kinds();
    let u = step_of(&intent, FileRole::UserSsh);
    let committed = kinds.iter().position(|k| k == "ssh:committed").unwrap();
    let settling = kinds
        .iter()
        .position(|k| *k == format!("{u}:settling"))
        .unwrap();
    assert!(committed < settling, "{kinds:?}");
    assert_eq!(
        kinds.last().map(String::as_str),
        Some("ssh:finished_applied"),
        "{kinds:?}"
    );
    // Roll back: B leaves the user file, P and the key files go to the cleaner.
    let record = sink.record(&fx.env);
    let plan = fx.preview(&fx.spec(&[], Some(record.clone())), &Fx::rollback_intent());
    let rollback = plan.intent();
    let rsink = Sink::default();
    let r = fx.writer().apply(&rollback, &mut rsink.clone()).unwrap();
    assert!(matches!(
        r.items.as_slice(),
        [ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            ..
        }]
    ));
    assert_eq!(std::fs::read(fx.user()).unwrap(), before, "byte-for-byte");
    // The cleaner removes P and the key files of generation 1.
    let cleaner = fx.cleaner();
    for l in &record.items[&ProjectionItem::Ssh].files {
        block_on(cleaner.delete(&resource(&fx.env, l, 1))).unwrap();
        assert!(!Path::new(&l.path).exists(), "{} removed", l.path);
    }
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
    assert!(!fx.ssh_dir().join(".hm-quarantine").exists());
}

#[test]
fn a22_render_is_deterministic_and_reapply_is_noop() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    let tree = fx.tree();
    // The same catalog previews to no file change: nothing to apply, no decision.
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.aliases = first_aliases(&first, &fx, &["work"]);
    let plan = fx.preview(&spec, &Fx::apply_intent());
    assert!(plan.files.is_empty(), "{:?}", plan.files);
    assert!(!plan.view.consent.decision_required);
    let again = fx.preview(&spec, &Fx::apply_intent());
    assert_eq!(
        again.view.plan_digest, plan.view.plan_digest,
        "deterministic"
    );
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(r.items.is_empty());
    assert_eq!(fx.tree(), tree, "re-apply changed nothing");
    // P renders identically from the same input.
    let p = step_ref(&first, FileRole::ManagedSsh);
    assert_eq!(
        Sha256Hex::of(&std::fs::read(fx.p()).unwrap()),
        match &p.target {
            Target::Present { sha256 } => sha256.clone(),
            Target::Absent => unreachable!(),
        }
    );
}

/// ADR-0007 §12.18 item 3 (review X03). A first adoption's marker is derived from the
/// proposed generation, the role and the plan inputs, never drawn: two previews of an
/// unchanged first adoption give the same plan digest (§5.4 step 1 recomputes it), for
/// an existing and for an absent user file, and changing any one input changes it.
#[test]
fn a22_first_adoption_previews_reproduce_their_plan_digest() {
    for user_present in [true, false] {
        let fx = Fx::new();
        if user_present {
            std::fs::write(fx.user(), USER_TEXT).unwrap();
        } else {
            std::fs::remove_file(fx.user()).unwrap();
        }
        let spec = fx.spec(&["work", "lab"], None);
        let digest = |spec: &ProjectionSpec| fx.preview(spec, &Fx::apply_intent()).view.plan_digest;
        let a = fx.preview(&spec, &Fx::apply_intent());
        let b = fx.preview(&spec, &Fx::apply_intent());
        let (ai, bi) = (a.intent(), b.intent());
        let user = step_ref(&ai, FileRole::UserSsh).clone();
        assert!(user.commit, "a first adoption inserts B");
        assert_eq!(
            a.view.plan_digest, b.view.plan_digest,
            "user_present={user_present}: unchanged inputs, same digest"
        );
        assert_eq!(
            user.target,
            step_ref(&bi, FileRole::UserSsh).target,
            "the same block"
        );
        let base = a.view.plan_digest.clone();
        let label = format!("user_present={user_present}");
        // The spec alone (its environment changes nothing else in the plan).
        let mut other = spec.clone();
        other.environment = EnvironmentId::from_random_bytes(random());
        assert_ne!(digest(&other), base, "{label}: environment");
        // An alias of the spec.
        let mut other = spec.clone();
        other.aliases[0].hostname = "elsewhere.example.invalid".to_owned();
        assert_ne!(digest(&other), base, "{label}: alias");
        // The proposed generation (a record of an earlier generation).
        let mut other = spec.clone();
        other.record = Some(ProjectionRecord {
            environment: fx.env.clone(),
            items: [(
                ProjectionItem::Ssh,
                heimdall_domain::projection::ItemRecord {
                    generation: 4,
                    files: Vec::new(),
                    aliases: Vec::new(),
                    operation: OperationId::from_random_bytes([7; 16]),
                    committed_at: heimdall_contract::Timestamp::now(),
                },
            )]
            .into_iter()
            .collect(),
        });
        let later = fx.preview(&other, &Fx::apply_intent());
        assert_eq!(later.generation, 5);
        assert_ne!(later.view.plan_digest, base, "{label}: generation");
        assert_eq!(
            digest(&other),
            later.view.plan_digest,
            "{label}: reproducible at another generation too"
        );
        assert_eq!(
            digest(&spec),
            base,
            "{label}: the original inputs still agree"
        );
        // The base of each file the plan reads: the user file, P, a key file.
        let user_before = std::fs::read(fx.user()).ok();
        std::fs::write(fx.user(), format!("{USER_TEXT}Host more\n")).unwrap();
        assert_ne!(digest(&spec), base, "{label}: the user file");
        match &user_before {
            Some(b) => std::fs::write(fx.user(), b).unwrap(),
            None => std::fs::remove_file(fx.user()).unwrap(),
        }
        assert_eq!(digest(&spec), base, "{label}: restored inputs");
        std::fs::create_dir_all(fx.home.config_dir.clone()).unwrap();
        write_mode(&fx.p(), b"# stray\n", 0o600);
        assert_ne!(digest(&spec), base, "{label}: P");
        std::fs::remove_file(fx.p()).unwrap();
        let key = PathBuf::from(&spec.aliases[1].key_file);
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        write_mode(&key, b"ssh-ed25519 AAAA stray\n", 0o644);
        assert_ne!(digest(&spec), base, "{label}: a key file");
        std::fs::remove_file(&key).unwrap();
        assert_eq!(digest(&spec), base, "{label}: restored inputs");
    }
}

#[test]
fn a22_missing_user_config_created_0600_and_ssh_dir_0700() {
    let fx = Fx::new();
    std::fs::remove_file(fx.user()).unwrap();
    std::fs::remove_file(fx.ssh_dir().join("known_hosts")).unwrap();
    std::fs::remove_dir(fx.ssh_dir()).unwrap();
    let (intent, _sink) = fx.adopt(&["work"]);
    let user = step_ref(&intent, FileRole::UserSsh);
    assert_eq!(user.base, heimdall_domain::projection::Base::Absent);
    let dir = std::fs::metadata(fx.ssh_dir()).unwrap();
    assert_eq!(dir.permissions().mode() & 0o777, 0o700);
    let file = std::fs::metadata(fx.user()).unwrap();
    assert_eq!(file.permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(fx.user()).unwrap();
    assert!(text.starts_with("# >>> heimdall managed include"));
    assert!(leftovers(&fx.tree()).is_empty());
}

#[test]
fn a22_user_edit_between_preview_and_apply_conflicts_user_config_changed() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    let edited = format!("{USER_TEXT}Host later\n    User me\n");
    std::fs::write(fx.user(), &edited).unwrap();
    let tree = fx.tree();
    let sink = Sink::default();
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut sink.clone())
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }]
    );
    assert_eq!(fx.tree(), tree, "nothing written");
    assert_eq!(sink.kinds(), vec!["ssh:finished_not_applied"]);
}

#[test]
fn a22_update_never_writes_user_file() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink1, update) = fx.update_plan(&["work"], "lab");
    let _ = sink1;
    let before = std::fs::symlink_metadata(fx.user()).unwrap();
    let bytes = std::fs::read(fx.user()).unwrap();
    let user = step_ref(&update, FileRole::UserSsh);
    assert!(!user.commit, "the update's user step is check-only");
    assert!(step_ref(&update, FileRole::ManagedSsh).commit);
    let sink = Sink::default();
    let r = fx.writer().apply(&update, &mut sink.clone()).unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }]
    );
    let after = std::fs::symlink_metadata(fx.user()).unwrap();
    assert_eq!((after.ino(), after.dev()), (before.ino(), before.dev()));
    assert_eq!(std::fs::read(fx.user()).unwrap(), bytes);
    let user_step = step_of(&update, FileRole::UserSsh);
    assert!(
        sink.file_phases(user_step).is_empty(),
        "no receipt for the user file"
    );
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .contains("Host lab")
    );
    assert!(leftovers(&fx.tree()).is_empty());
}

// --- races after the final comparison (M2-D03) ------------------------------------------

#[test]
fn a22_race_rename_replace_after_final_check_is_restored() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    let intent = plan.intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let user = fx.user().to_path_buf();
    let writer_bytes = b"Host racer\n    User racer\n".to_vec();
    let wb = writer_bytes.clone();
    let hook = Hook::new().run(ReplacePoint::BeforeExchange, Some(u), move || {
        rename_replace(&user, &wb);
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Restored {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::ConcurrentWriter)
        }],
        "{:?}",
        sink.kinds()
    );
    assert_eq!(
        std::fs::read(fx.user()).unwrap(),
        writer_bytes,
        "writer's bytes active"
    );
    let staged = step_ref(&intent, FileRole::UserSsh)
        .staged_name
        .clone()
        .unwrap();
    assert!(
        !fx.ssh_dir().join(staged).exists(),
        "Heimdall's staged file is gone"
    );
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

#[test]
fn a22_race_in_place_write_after_final_check_is_restored() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let user = fx.user().to_path_buf();
    let original = std::fs::symlink_metadata(&user).unwrap().ino();
    let written = format!("{USER_TEXT}Host inplace\n    User me\n");
    let w = written.clone();
    let hook = Hook::new().run(ReplacePoint::BeforeExchange, Some(u), move || {
        write_in_place(&user, w.as_bytes());
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Restored {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::ConcurrentWriter)
        }],
        "{:?}",
        sink.kinds()
    );
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), written);
    assert_eq!(
        std::fs::symlink_metadata(fx.user()).unwrap().ino(),
        original
    );
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

/// ADR-0007 §12.17 item 5 (m02-plan U4, amended): normalization rule 1 (§5.7) makes an
/// entry that is not a regular file X whatever its identity, so the displaced symlink
/// is not a D that F5 may move back. F5d holds the operation (`third_writer`) and
/// nothing moves: the symlink is preserved intact, its target is untouched, and
/// nothing is deleted. Revision 5 named this test `…_is_restored`.
#[test]
fn a22_race_symlink_substitution_at_boundary_is_held() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let target = fx.home.root.join("elsewhere.conf");
    std::fs::write(&target, b"Host elsewhere\n").unwrap();
    let user = fx.user().to_path_buf();
    let t = target.clone();
    let hook = Hook::new().run(ReplacePoint::BeforeExchange, Some(u), move || {
        let link = user.with_extension("link-tmp");
        std::os::unix::fs::symlink(&t, &link).unwrap();
        std::fs::rename(&link, &user).unwrap();
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        held_reasons(&r.items[0]),
        vec![HoldReason::ThirdWriter],
        "{:?}",
        sink.kinds()
    );
    let staged = step_ref(&intent, FileRole::UserSsh)
        .staged_name
        .clone()
        .unwrap();
    let aside = fx.ssh_dir().join(&staged);
    let m = std::fs::symlink_metadata(&aside).unwrap();
    assert!(
        m.file_type().is_symlink(),
        "the symlink is preserved, intact"
    );
    assert_eq!(std::fs::read_link(&aside).unwrap(), target);
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"Host elsewhere\n",
        "target untouched"
    );
    assert!(
        !sink
            .kinds()
            .iter()
            .any(|k| k.ends_with(":settling") || k.ends_with(":restored"))
    );
    let tree = fx.tree();
    let again = restart(&fx, &intent, &sink);
    assert_eq!(held_reasons(&again[0]), vec![HoldReason::ThirdWriter]);
    assert_eq!(fx.tree(), tree, "a restart moves nothing");
}

#[test]
fn a22_race_third_writer_during_restore_preserves_both() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let user = fx.user().to_path_buf();
    let second = b"Host second\n".to_vec();
    let third = b"Host third\n".to_vec();
    let (u1, u2, s2, s3) = (user.clone(), user.clone(), second.clone(), third.clone());
    let backup = fx.ssh_dir().join("config.bak");
    let b = backup.clone();
    let hook = Hook::new()
        .run(ReplacePoint::BeforeExchange, Some(u), move || {
            rename_replace(&u1, &s2);
        })
        .run(ReplacePoint::BeforeRestoreCheck, Some(u), move || {
            // An editor keeps a backup of what it found (Heimdall's S) and saves anew.
            std::fs::rename(&u2, &b).unwrap();
            write_mode(&u2, &s3, 0o600);
        });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        held_reasons(&r.items[0]),
        vec![HoldReason::ThirdWriter],
        "{:?}",
        sink.kinds()
    );
    let tree = fx.tree();
    // All three entries exist with their bytes; nothing was moved or renamed.
    assert_eq!(std::fs::read(&user).unwrap(), third);
    let staged = step_ref(&intent, FileRole::UserSsh)
        .staged_name
        .clone()
        .unwrap();
    assert_eq!(std::fs::read(fx.ssh_dir().join(&staged)).unwrap(), second);
    let s_bytes = std::fs::read(&backup).unwrap();
    assert!(String::from_utf8_lossy(&s_bytes).contains("# >>> heimdall managed include"));
    assert!(!tree.keys().any(|k| k.contains("hm-conflict")));
    assert!(
        !sink
            .kinds()
            .iter()
            .any(|k| k.ends_with(":restored") || k.ends_with(":settling"))
    );
    // A restart with nothing changed holds again, moves nothing, writes no new held.
    let held_before = sink.kinds().iter().filter(|k| k.ends_with(":held")).count();
    let again = restart(&fx, &intent, &sink);
    assert_eq!(held_reasons(&again[0]), vec![HoldReason::ThirdWriter]);
    assert_eq!(fx.tree(), tree);
    assert_eq!(
        sink.kinds().iter().filter(|k| k.ends_with(":held")).count(),
        held_before
    );
}

// --- commit points (M2-D02) ---------------------------------------------------------------

/// Locators of the inactive files a not-applied item left, built from its receipts
/// (what the setup driver hands to the cleanup executor).
fn inactive_locators(intent: &SetupIntent, sink: &Sink) -> Vec<ProjectionLocator> {
    let mut out = Vec::new();
    for (i, step) in intent.files.iter().enumerate() {
        let i = u16::try_from(i).unwrap();
        if !matches!(step.role, FileRole::ManagedSsh | FileRole::Key) {
            continue;
        }
        let phases = sink.file_phases(i);
        if !phases.iter().any(|p| matches!(p, FilePhase::Exchanged)) {
            continue;
        }
        let identity = phases
            .iter()
            .find_map(|p| match p {
                FilePhase::Staged { identity } => Some(identity.clone()),
                _ => None,
            })
            .unwrap();
        let Target::Present { sha256 } = &step.target else {
            continue;
        };
        out.push(ProjectionLocator {
            role: step.role,
            path: step.path.clone(),
            identity,
            sha256: sha256.clone(),
        });
    }
    out
}

#[test]
fn a22_first_adoption_failure_before_commit_leaves_only_inactive_files_then_cleaned() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work", "lab"], None), &Fx::apply_intent())
        .intent();
    let p = step_of(&intent, FileRole::ManagedSsh);
    let user = fx.user().to_path_buf();
    let hook = Hook::new().run(ReplacePoint::AfterPostValidate, Some(p), move || {
        let mut t = std::fs::read_to_string(&user).unwrap();
        t.push_str("Host meanwhile\n");
        write_in_place(&user, t.as_bytes());
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }],
        "{:?}",
        sink.kinds()
    );
    let text = std::fs::read_to_string(fx.user()).unwrap();
    assert!(
        !text.contains("heimdall managed include"),
        "the user file has no B"
    );
    assert!(text.ends_with("Host meanwhile\n"));
    let u = step_of(&intent, FileRole::UserSsh);
    assert!(!sink.kinds().contains(&format!("{u}:exchanged")));
    assert!(sink.commits().is_empty());
    // Only inactive files remain; the cleaner removes them by identity and digest.
    let inactive = inactive_locators(&intent, &sink);
    assert_eq!(inactive.len(), 3, "P and two key files");
    for l in &inactive {
        assert!(Path::new(&l.path).exists());
        block_on(fx.cleaner().delete(&resource(&fx.env, l, 1))).unwrap();
        assert!(!Path::new(&l.path).exists(), "{}", l.path);
    }
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

#[test]
fn a22_first_adoption_crash_after_p_before_b_reconciles_forward_or_cleans() {
    // Process-crash variant (in-process unwind): B's S exists, its `file.staged` was
    // never made durable (F0x), so the restart records it and resumes forward.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let hook = Hook::new().crash(ReplacePoint::BeforeReceipt("staged"), Some(u));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none());
    let staged = step_ref(&intent, FileRole::UserSsh)
        .staged_name
        .clone()
        .unwrap();
    assert!(fx.ssh_dir().join(&staged).exists());
    let out = restart(&fx, &intent, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 1
        }],
        "{:?}",
        sink.kinds()
    );
    assert!(
        std::fs::read_to_string(fx.user())
            .unwrap()
            .contains("heimdall managed include")
    );
    assert!(leftovers(&fx.tree()).is_empty());

    // The "cleans" variant: the user file changed while the runtime was down, so the
    // resume's precondition fails, S is settled, the item is not applied, and the
    // inactive files go to the cleaner.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let hook = Hook::new().crash(ReplacePoint::BeforeReceipt("staged"), Some(u));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none());
    std::fs::write(fx.user(), format!("{USER_TEXT}Host down\n")).unwrap();
    let out = restart(&fx, &intent, &sink);
    // A T0 precondition failed: the abort carries its reason (ADR-0007 §12.20 item 2).
    assert_eq!(
        out,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }],
        "{:?}",
        sink.kinds()
    );
    assert!(
        !std::fs::read_to_string(fx.user())
            .unwrap()
            .contains("heimdall managed")
    );
    for l in inactive_locators(&intent, &sink) {
        block_on(fx.cleaner().delete(&resource(&fx.env, &l, 1))).unwrap();
    }
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

#[test]
fn a22_first_adoption_crash_after_p_before_b_reconciles_through_the_store_fault_hook() {
    use heimdall_store::{FaultAction, FaultPoint};
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    // Count the receipts a clean run writes before B's `file.staged`.
    let before_b = 4 * usize::from(u);
    // Transaction 1 admits the operation; the next `before_b` append receipts; the
    // one after that (B's `file.staged`) fails in the store.
    let mut script = vec![(FaultPoint::BeforeCommit, FaultAction::Continue); 1 + before_b];
    script.push((FaultPoint::BeforeCommit, FaultAction::Fail));
    let faults = heimdall_testkit::ScriptedFaults::new(script);
    let store = Arc::new(heimdall_store::Store::open_in_memory(faults).unwrap());
    let mut sink = StoreSink::admit(&store, &fx.env, &intent);
    let e = fx.writer().apply(&intent, &mut sink).unwrap_err();
    assert!(matches!(e, ReconcileError::Sink(_)), "{e:?}");
    let durable = sink.receipts();
    assert_eq!(durable.len(), before_b, "B's file.staged did not commit");
    let staged = step_ref(&intent, FileRole::UserSsh)
        .staged_name
        .clone()
        .unwrap();
    assert!(fx.ssh_dir().join(&staged).exists(), "S was created");
    // A fresh writer reconciles from the store's receipts: F0x, then T0 forward.
    let r = fx.writer().reconcile(&intent, &durable, &mut sink).unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 1
        }]
    );
    let kinds: Vec<String> = sink
        .receipts()
        .iter()
        .filter_map(|r| r.local.as_ref())
        .map(kind_of)
        .collect();
    assert!(kinds.contains(&"ssh:committed".to_owned()), "{kinds:?}");
    assert!(leftovers(&fx.tree()).is_empty());
}

/// ADR-0007 §12.20 item 2(b): when recovery itself decides an abort, the outcome
/// carries the reason the §5.7 row names, and the reason is durable. A first
/// adoption's first run crashes on the user step before B's exchange (after its
/// `file.staged`, or after its `file.validated`), and the scratch tree changes while
/// the runtime is down. The restart aborts by the row and reports the row's reason;
/// its `item.finished{not_applied}` records that reason on the wire; and a second
/// restart reads it there (T4), reports the same outcome and writes nothing. The
/// user file is never written by Heimdall:
/// * F1a (B's S removed after `staged`) and F2g (after `validated`):
///   `concurrent_writer`;
/// * F2e (the user file replaced by rename), F2j (removed) and F2a with a V′ (edited
///   in place, which T0's revalidation refuses): `user_config_changed`;
/// * with no user file, C3 (another writer creates one) and C4 (S removed):
///   `concurrent_writer`.
#[test]
fn recovery_decided_abort_reason_is_recorded_and_survives_restart() {
    use ConflictKind::{ConcurrentWriter as Cw, UserConfigChanged as Changed};
    type Change = fn(&Path, &Path);
    let validated = ReplacePoint::BeforeExchange;
    let staged = ReplacePoint::BeforeReceipt("validated");
    let cases: [(&str, bool, ReplacePoint, Change, ConflictKind); 7] = [
        (
            "F1a",
            true,
            staged,
            |_, s| std::fs::remove_file(s).unwrap(),
            Cw,
        ),
        (
            "F2g",
            true,
            validated,
            |_, s| std::fs::remove_file(s).unwrap(),
            Cw,
        ),
        (
            "F2e",
            true,
            validated,
            |u, _| rename_replace(u, b"Host other\n"),
            Changed,
        ),
        (
            "F2j",
            true,
            validated,
            |u, _| std::fs::remove_file(u).unwrap(),
            Changed,
        ),
        (
            "F2a",
            true,
            validated,
            |u, _| write_in_place(u, b"Host edited\n"),
            Changed,
        ),
        (
            "C3",
            false,
            validated,
            |u, _| write_mode(u, b"Host theirs\n", 0o600),
            Cw,
        ),
        (
            "C4",
            false,
            validated,
            |_, s| std::fs::remove_file(s).unwrap(),
            Cw,
        ),
    ];
    for (row, user_present, point, change, want) in cases {
        let fx = Fx::new();
        if user_present {
            std::fs::write(fx.user(), USER_TEXT).unwrap();
        } else {
            std::fs::remove_file(fx.user()).unwrap();
        }
        let intent = fx
            .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
            .intent();
        let u = step_of(&intent, FileRole::UserSsh);
        let hook = Hook::new().crash(point, Some(u));
        let sink = Sink::default();
        assert!(
            apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none(),
            "{row}"
        );
        let s = fx.ssh_dir().join(
            step_ref(&intent, FileRole::UserSsh)
                .staged_name
                .clone()
                .unwrap(),
        );
        assert!(s.exists(), "{row}: B's S at its staged name");
        change(fx.user(), &s);
        let user_now = std::fs::read(fx.user()).ok();
        let want_out = vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(want),
        }];
        let out = restart(&fx, &intent, &sink);
        assert_eq!(out, want_out, "{row}: {:?}", sink.kinds());
        let last = sink.receipts().last().and_then(|r| r.local.clone());
        assert_eq!(
            last,
            Some(LocalReceipt::Item {
                item: ProjectionItem::Ssh,
                phase: ItemPhase::Finished {
                    outcome: ItemFinish::NotApplied,
                    reason: Some(want),
                },
            }),
            "{row}: item.finished records the reason"
        );
        let wire = serde_json::to_value(last.unwrap()).unwrap();
        assert_eq!(
            wire["phase"]["reason"],
            serde_json::to_value(want).unwrap(),
            "{row}: on the wire"
        );
        assert_eq!(
            std::fs::read(fx.user()).ok(),
            user_now,
            "{row}: the user file is not written"
        );
        let written = sink.receipts().len();
        assert_eq!(
            restart(&fx, &intent, &sink),
            want_out,
            "{row}: a second restart reports the recorded reason"
        );
        assert_eq!(sink.receipts().len(), written, "{row}: and writes nothing");
    }
}

#[test]
fn a22_first_adoption_crash_after_b_exchange_before_validation_reconciles() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let hook = Hook::new().crash(ReplacePoint::AfterExchange, Some(u));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none());
    assert_eq!(
        sink.kinds().last().map(String::as_str),
        Some(format!("{u}:validated").as_str())
    );
    let out = restart(&fx, &intent, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 1
        }],
        "{:?}",
        sink.kinds()
    );
    let k = sink.kinds();
    let pos = |s: &str| k.iter().position(|x| x == s).unwrap();
    assert!(pos(&format!("{u}:exchanged")) < pos(&format!("{u}:post_validated")));
    assert!(pos(&format!("{u}:post_validated")) < pos("ssh:committed"));
    assert!(leftovers(&fx.tree()).is_empty());
}

#[test]
fn a22_update_user_edit_after_p_exchange_restores_generation_n() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let gen_n = std::fs::read(fx.p()).unwrap();
    let gen_n_ino = std::fs::symlink_metadata(fx.p()).unwrap().ino();
    let user = fx.user().to_path_buf();
    let edit = |path: &Path| {
        let mut t = std::fs::read_to_string(path).unwrap();
        t.push_str("Host edited\n    User me\n");
        write_in_place(path, t.as_bytes());
    };
    let hook = Hook::new().run(ReplacePoint::AfterExchange, Some(p), move || edit(&user));
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Restored {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }],
        "{:?}",
        sink.kinds()
    );
    assert_eq!(std::fs::read(fx.p()).unwrap(), gen_n, "generation N back");
    assert_eq!(std::fs::symlink_metadata(fx.p()).unwrap().ino(), gen_n_ino);
    assert!(
        std::fs::read_to_string(fx.user())
            .unwrap()
            .ends_with("Host edited\n    User me\n")
    );
    assert!(sink.commits().is_empty());
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

/// ADR-0007 §12.17 item 6: §5.7 governs a failed first-adoption check (§5.4's
/// `CONFIG_CONFLICT` with effect `none` is superseded). P, still inactive, is edited in
/// place after its exchange and before the user file's transaction check, so the
/// check fails (`managed_file_edited`). The user file is restored (F5), the unchanged
/// key files are rolled back (C7), the edited P is held (C7a,
/// `active_entry_modified`), and the item is held: the operation is `OUTCOME_UNKNOWN`
/// with the held repair options (`observe_held` lists P), not `restored`. A restart
/// moves nothing.
#[test]
fn a22_first_adoption_check_failure_with_edited_inactive_p_is_held() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let user_ino = std::fs::symlink_metadata(fx.user()).unwrap().ino();
    let intent = fx
        .preview(&fx.spec(&["work", "lab"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let p = step_of(&intent, FileRole::ManagedSsh);
    let hook = Hook::new().run(
        ReplacePoint::AfterPostValidate,
        Some(u),
        appender(&fx.p(), "# the owner's edit\n"),
    );
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    let kinds = sink.kinds();
    let [ItemOutcome::Held { steps, .. }] = r.items.as_slice() else {
        panic!("{:?} {kinds:?}", r.items);
    };
    assert_eq!(
        steps.iter().map(|s| (s.step, s.reason)).collect::<Vec<_>>(),
        vec![(p, HoldReason::ActiveEntryModified)],
        "{kinds:?}"
    );
    assert!(
        sink.receipts().iter().any(|r| matches!(
            r.local,
            Some(LocalReceipt::Item {
                phase: ItemPhase::RollingBack {
                    reason: ConflictKind::ManagedFileEdited
                },
                ..
            })
        )),
        "{kinds:?}"
    );
    // The user file is restored, byte for byte and by identity.
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), USER_TEXT);
    assert_eq!(
        std::fs::symlink_metadata(fx.user()).unwrap().ino(),
        user_ino
    );
    assert!(kinds.contains(&format!("{u}:restored")), "{kinds:?}");
    // The unchanged key files are rolled back; the edited P stays, with the edit.
    for (i, s) in intent.files.iter().enumerate() {
        if s.role == FileRole::Key {
            assert!(!Path::new(&s.path).exists(), "{} rolled back", s.path);
            assert!(kinds.contains(&format!("{i}:restored")), "{kinds:?}");
        }
    }
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .ends_with("# the owner's edit\n")
    );
    assert!(
        !kinds
            .iter()
            .any(|k| k == "ssh:committed" || k.starts_with("ssh:finished"))
    );
    assert!(sink.commits().is_empty());
    // The repair options are built from the held steps.
    let held = fx.writer().observe_held(&intent, &sink.receipts()).unwrap();
    assert_eq!(
        held.iter().map(|h| (h.step, h.reason)).collect::<Vec<_>>(),
        vec![(p, HoldReason::ActiveEntryModified)]
    );
    let tree = fx.tree();
    let again = restart(&fx, &intent, &sink);
    assert_eq!(
        held_reasons(&again[0]),
        vec![HoldReason::ActiveEntryModified]
    );
    assert_eq!(fx.tree(), tree, "a restart moves nothing");
}

#[test]
fn a22_update_crash_after_p_exchange_reconciles() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let hook = Hook::new().crash(ReplacePoint::AfterExchange, Some(p));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
    let out = restart(&fx, &update, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }],
        "{:?}",
        sink.kinds()
    );
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .contains("Host lab")
    );
    assert!(leftovers(&fx.tree()).is_empty());
}

#[test]
fn a22_update_user_edit_after_p_post_validation_restores_generation_n() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let gen_n = std::fs::read(fx.p()).unwrap();
    let gen_n_ino = std::fs::symlink_metadata(fx.p()).unwrap().ino();
    let user = fx.user().to_path_buf();
    let hook = Hook::new().run(ReplacePoint::AfterPostValidate, Some(p), move || {
        let mut t = std::fs::read_to_string(&user).unwrap();
        t.push_str("Host edited\n");
        write_in_place(&user, t.as_bytes());
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Restored {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }]
    );
    assert_eq!(std::fs::read(fx.p()).unwrap(), gen_n);
    assert_eq!(std::fs::symlink_metadata(fx.p()).unwrap().ino(), gen_n_ino);
    assert!(
        std::fs::read_to_string(fx.user())
            .unwrap()
            .ends_with("Host edited\n")
    );
    assert!(!sink.kinds().contains(&"ssh:committed".to_owned()));
}

#[test]
fn a22_update_crash_between_post_validation_and_commit_reconciles() {
    for edit_while_down in [false, true] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let gen_n = std::fs::read(fx.p()).unwrap();
        let hook = Hook::new().crash(ReplacePoint::BeforeCommit, Some(p));
        let sink = Sink::default();
        assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
        if edit_while_down {
            let mut t = std::fs::read_to_string(fx.user()).unwrap();
            t.push_str("Host down\n");
            std::fs::write(fx.user(), t).unwrap();
        }
        let out = restart(&fx, &update, &sink);
        if edit_while_down {
            assert_eq!(
                out,
                vec![ItemOutcome::Restored {
                    item: ProjectionItem::Ssh,
                    reason: Some(ConflictKind::UserConfigChanged)
                }],
                "{:?}",
                sink.kinds()
            );
            assert_eq!(std::fs::read(fx.p()).unwrap(), gen_n);
        } else {
            assert_eq!(
                out,
                vec![ItemOutcome::Applied {
                    item: ProjectionItem::Ssh,
                    generation: 2
                }],
                "{:?}",
                sink.kinds()
            );
            assert!(
                std::fs::read_to_string(fx.p())
                    .unwrap()
                    .contains("Host lab")
            );
        }
        assert!(
            leftovers(&fx.tree()).is_empty(),
            "{:?}",
            leftovers(&fx.tree())
        );
    }
}

#[test]
fn a22_update_crash_after_commit_before_settlement_settles_never_restores() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let hook = Hook::new().crash(ReplacePoint::BeforeSettleMove, Some(p));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
    assert!(sink.kinds().contains(&"ssh:committed".to_owned()));
    let out = restart(&fx, &update, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }]
    );
    assert!(
        !sink.kinds().iter().any(|k| k.contains("restore")),
        "{:?}",
        sink.kinds()
    );
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .contains("Host lab")
    );
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
    assert!(
        !fx.home.config_dir.join(".hm-quarantine").exists(),
        "emptied and removed"
    );
}

#[test]
fn a22_update_user_edit_after_commit_is_reported_not_restored() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let user = fx.user().to_path_buf();
    let hook = Hook::new().run(ReplacePoint::BeforeSettleMove, Some(p), move || {
        let mut t = std::fs::read_to_string(&user).unwrap();
        t.push_str("Host later\n");
        write_in_place(&user, t.as_bytes());
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }]
    );
    assert!(
        std::fs::read_to_string(fx.user())
            .unwrap()
            .ends_with("Host later\n")
    );
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .contains("Host lab")
    );
    assert!(leftovers(&fx.tree()).is_empty());
}

// --- the recovery table through crashes (ADR-0007 §5.7) ---------------------------------

/// Edit the user file in place (appending a line) from a hook.
fn appender(path: &Path, line: &str) -> impl Fn() + Send + Sync + 'static {
    let path = path.to_path_buf();
    let line = line.to_owned();
    move || {
        let mut t = std::fs::read_to_string(&path).unwrap();
        t.push_str(&line);
        write_in_place(&path, t.as_bytes());
    }
}

fn count(kinds: &[String], k: &str) -> usize {
    kinds.iter().filter(|x| *x == k).count()
}

#[test]
fn a22_crash_before_restore_exchange_restores() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let gen_n = std::fs::read(fx.p()).unwrap();
    let hook = Hook::new()
        .run(
            ReplacePoint::AfterPostValidate,
            Some(p),
            appender(fx.user(), "Host x\n"),
        )
        .crash(ReplacePoint::BeforeRestoreExchange, Some(p));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
    assert_eq!(
        sink.kinds().last().unwrap(),
        &format!("{p}:restore_started")
    );
    let out = restart(&fx, &update, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Restored {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }],
        "{:?}",
        sink.kinds()
    );
    let k = sink.kinds();
    assert_eq!(count(&k, &format!("{p}:restore_started")), 1, "{k:?}");
    assert_eq!(count(&k, &format!("{p}:restored")), 1);
    assert_eq!(std::fs::read(fx.p()).unwrap(), gen_n);
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

#[test]
fn a22_crash_after_restore_exchange_before_receipt_is_recognized_as_restored() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let gen_n = std::fs::read(fx.p()).unwrap();
    let gen_n_ino = std::fs::symlink_metadata(fx.p()).unwrap().ino();
    let hook = Hook::new()
        .run(
            ReplacePoint::AfterPostValidate,
            Some(p),
            appender(fx.user(), "Host x\n"),
        )
        .crash(ReplacePoint::AfterRestoreExchange, Some(p));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
    // The exchange happened; its receipt did not.
    assert_eq!(std::fs::symlink_metadata(fx.p()).unwrap().ino(), gen_n_ino);
    assert!(!sink.kinds().contains(&format!("{p}:restored")));
    let restart_hook = Hook::new();
    let out = reconcile_or_crash(fx.hooked(&restart_hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        out,
        vec![ItemOutcome::Restored {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }],
        "{:?}",
        sink.kinds()
    );
    // Recognized (F5b), never exchanged again; S then settled.
    assert!(
        !restart_hook
            .seen()
            .iter()
            .any(|(pt, _)| *pt == ReplacePoint::BeforeRestoreExchange)
    );
    let k = sink.kinds();
    assert_eq!(count(&k, &format!("{p}:restored")), 1, "{k:?}");
    assert!(k.contains(&format!("{p}:settled")));
    assert_eq!(std::fs::read(fx.p()).unwrap(), gen_n);
    assert!(leftovers(&fx.tree()).is_empty());
}

#[test]
fn a22_crash_before_each_settlement_receipt_completes_settlement() {
    for point in [
        ReplacePoint::BeforeReceipt("settling"),
        ReplacePoint::AfterSettleMove,
        ReplacePoint::BeforeQuarantineRemove,
    ] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let displaced = step_ref(&update, FileRole::ManagedSsh)
            .displaced_name
            .clone()
            .unwrap();
        let hook = Hook::new().crash(point, Some(p));
        let sink = Sink::default();
        assert!(
            apply_or_crash(fx.hooked(&hook), &update, &sink).is_none(),
            "{point:?}"
        );
        let out = restart(&fx, &update, &sink);
        assert_eq!(
            out,
            vec![ItemOutcome::Applied {
                item: ProjectionItem::Ssh,
                generation: 2
            }],
            "{point:?} {:?}",
            sink.kinds()
        );
        assert!(
            !fx.home.config_dir.join(&displaced).exists(),
            "{point:?}: D gone"
        );
        assert!(
            !fx.home.config_dir.join(".hm-quarantine").exists(),
            "{point:?}: quarantine empty and removed"
        );
        assert!(leftovers(&fx.tree()).is_empty(), "{point:?}");
    }
}

#[test]
fn a22_displaced_entry_removed_by_another_writer_is_conflict_never_settled() {
    // Before `file.post_validated`: H (displaced_missing), nothing moved, S active.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let displaced = fx.home.config_dir.join(
        step_ref(&update, FileRole::ManagedSsh)
            .displaced_name
            .clone()
            .unwrap(),
    );
    let d = displaced.clone();
    let hook = Hook::new().run(ReplacePoint::AfterExchange, Some(p), move || {
        std::fs::remove_file(&d).unwrap();
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        held_reasons(&r.items[0]),
        vec![HoldReason::DisplacedMissing],
        "{:?}",
        sink.kinds()
    );
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .contains("Host lab"),
        "S active"
    );
    assert!(
        !sink
            .kinds()
            .iter()
            .any(|k| k.ends_with(":settled") || k.ends_with(":settling"))
    );

    // After `item.committed`, before the settle move: settle_conflict{missing}, applied.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let displaced = fx.home.config_dir.join(
        step_ref(&update, FileRole::ManagedSsh)
            .displaced_name
            .clone()
            .unwrap(),
    );
    let hook = Hook::new().run(ReplacePoint::BeforeSettleMove, Some(p), move || {
        std::fs::remove_file(&displaced).unwrap();
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }]
    );
    let phases = sink.file_phases(p);
    assert!(phases.iter().any(|ph| matches!(
        ph,
        FilePhase::SettleConflict {
            found: SettleConflictFound::Missing,
            ..
        }
    )));
    assert!(
        !phases
            .iter()
            .any(|ph| matches!(ph, FilePhase::Settled { .. }))
    );
}

#[test]
fn a22_replacement_onto_displaced_name_during_settlement_survives() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let displaced = fx.home.config_dir.join(
        step_ref(&update, FileRole::ManagedSsh)
            .displaced_name
            .clone()
            .unwrap(),
    );
    let d = displaced.clone();
    let hook = Hook::new().run(ReplacePoint::BeforeSettleMove, Some(p), move || {
        rename_replace(&d, b"another writer's file\n");
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }]
    );
    assert_eq!(
        std::fs::read(&displaced).unwrap(),
        b"another writer's file\n",
        "intact"
    );
    let phases = sink.file_phases(p);
    assert!(phases.iter().any(|ph| matches!(
        ph,
        FilePhase::SettleConflict {
            found: SettleConflictFound::Foreign,
            ..
        }
    )));
    assert!(
        !phases
            .iter()
            .any(|ph| matches!(ph, FilePhase::Settled { .. }))
    );
}

#[test]
fn a22_exchanged_with_displaced_missing_is_held() {
    for after_receipt in [false, true] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let displaced = fx.home.config_dir.join(
            step_ref(&update, FileRole::ManagedSsh)
                .displaced_name
                .clone()
                .unwrap(),
        );
        let sink = Sink::default();
        if after_receipt {
            // F3b: `file.exchanged` is on record when D vanishes.
            let d = displaced.clone();
            let hook = Hook::new().run(
                ReplacePoint::BeforeReceipt("post_validated"),
                Some(p),
                move || {
                    std::fs::remove_file(&d).unwrap();
                },
            );
            let _ = apply_or_crash(fx.hooked(&hook), &update, &sink)
                .unwrap()
                .unwrap();
        } else {
            // F2d: a crash before `file.exchanged`, and D removed while down.
            let hook = Hook::new().crash(ReplacePoint::AfterExchange, Some(p));
            assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
            std::fs::remove_file(&displaced).unwrap();
        }
        let tree = fx.tree();
        let out = restart(&fx, &update, &sink);
        assert_eq!(
            held_reasons(&out[0]),
            vec![HoldReason::DisplacedMissing],
            "after_receipt={after_receipt} {:?}",
            sink.kinds()
        );
        assert_eq!(fx.tree(), tree, "nothing moved");
        assert!(
            std::fs::read_to_string(fx.p())
                .unwrap()
                .contains("Host lab"),
            "S active"
        );
    }
}

#[test]
fn a22_displaced_missing_or_replaced_after_valid_post_validation_is_held() {
    for replaced in [false, true] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let displaced = fx.home.config_dir.join(
            step_ref(&update, FileRole::ManagedSsh)
                .displaced_name
                .clone()
                .unwrap(),
        );
        let hook = Hook::new().crash(ReplacePoint::BeforeCommit, Some(p));
        let sink = Sink::default();
        assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
        if replaced {
            rename_replace(&displaced, b"foreign\n");
        } else {
            std::fs::remove_file(&displaced).unwrap();
        }
        let user = std::fs::read(fx.user()).unwrap();
        let tree = fx.tree();
        let out = restart(&fx, &update, &sink);
        let want = if replaced {
            HoldReason::DisplacedReplaced
        } else {
            HoldReason::DisplacedMissing
        };
        assert_eq!(held_reasons(&out[0]), vec![want], "{:?}", sink.kinds());
        assert!(
            !sink
                .kinds()
                .iter()
                .any(|k| k == "ssh:committed" || k == "ssh:rolling_back")
        );
        assert_eq!(std::fs::read(fx.user()).unwrap(), user);
        assert_eq!(fx.tree(), tree);
        if replaced {
            assert_eq!(std::fs::read(&displaced).unwrap(), b"foreign\n");
        }
    }
}

#[test]
fn a22_foreign_active_entry_after_create_is_held_nothing_moved() {
    let fx = Fx::new();
    std::fs::remove_file(fx.user()).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let user = fx.user().to_path_buf();
    let hook = Hook::new().run(ReplacePoint::AfterPostValidate, Some(u), move || {
        // An editor saves by rename, keeping B in the saved bytes.
        let mut t = std::fs::read_to_string(&user).unwrap();
        t.push_str("Host mine\n");
        rename_replace(&user, t.as_bytes());
    });
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    assert_eq!(
        held_reasons(&r.items[0]),
        vec![HoldReason::ActiveEntryReplaced],
        "{:?}",
        sink.kinds()
    );
    assert!(
        std::fs::read_to_string(fx.user())
            .unwrap()
            .ends_with("Host mine\n")
    );
    assert!(fx.p().exists(), "P stays");
    assert!(sink.commits().is_empty(), "nothing reaches the cleaner");
}

#[test]
fn a22_first_adoption_crash_after_create_exchanged_before_post_validation_reconciles() {
    for replaced_while_down in [false, true] {
        let fx = Fx::new();
        std::fs::remove_file(fx.user()).unwrap();
        let intent = fx
            .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
            .intent();
        let u = step_of(&intent, FileRole::UserSsh);
        let hook = Hook::new().crash(ReplacePoint::BeforeReceipt("post_validated"), Some(u));
        let sink = Sink::default();
        assert!(apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none());
        if replaced_while_down {
            let t = std::fs::read(fx.user()).unwrap();
            rename_replace(fx.user(), &t);
        }
        let out = restart(&fx, &intent, &sink);
        if replaced_while_down {
            assert_eq!(held_reasons(&out[0]), vec![HoldReason::ActiveEntryReplaced]);
            assert!(fx.p().exists());
            assert!(sink.commits().is_empty());
        } else {
            assert_eq!(
                out,
                vec![ItemOutcome::Applied {
                    item: ProjectionItem::Ssh,
                    generation: 1
                }],
                "{:?}",
                sink.kinds()
            );
        }
    }
}

/// The ADR's T3 restores every exchanged step (§5.7, C7), and C7a holds an inactive P
/// edited after its create, so a first adoption whose transaction check failed on an
/// edited P ends with P held while the user file (the commit step) is restored. The
/// crash falls after the user step's `file.restore_started`, before `file.settling`.
#[test]
fn a22_create_undo_crash_after_restore_started_before_settling_reconciles() {
    for edited_while_down in [false, true] {
        let fx = Fx::new();
        std::fs::remove_file(fx.user()).unwrap();
        let intent = fx
            .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
            .intent();
        let u = step_of(&intent, FileRole::UserSsh);
        let p = fx.p();
        let hook = Hook::new()
            .run(
                ReplacePoint::AfterPostValidate,
                Some(u),
                appender(&p, "# edited\n"),
            )
            .crash(ReplacePoint::BeforeReceipt("settling"), Some(u));
        let sink = Sink::default();
        assert!(
            apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none(),
            "{:?}",
            sink.kinds()
        );
        assert!(
            sink.kinds().contains(&format!("{u}:restore_started")),
            "{:?}",
            sink.kinds()
        );
        if edited_while_down {
            appender(fx.user(), "Host mine\n")();
        }
        let out = restart(&fx, &intent, &sink);
        let k = sink.kinds();
        if edited_while_down {
            // C7a: the edited created file stays active.
            assert!(
                held_reasons(&out[0]).contains(&HoldReason::ActiveEntryModified),
                "{k:?}"
            );
            assert!(
                std::fs::read_to_string(fx.user())
                    .unwrap()
                    .ends_with("Host mine\n")
            );
            assert!(!k.contains(&format!("{u}:restored")));
        } else {
            // C7, F8a: S settled through the quarantine, then `file.restored`.
            assert!(!fx.user().exists(), "{k:?}");
            let pos = |s: &str| k.iter().position(|x| x == s).unwrap();
            assert!(
                pos(&format!("{u}:settled")) < pos(&format!("{u}:restored")),
                "{k:?}"
            );
            // P, edited after its create, is held, never removed.
            assert!(
                held_reasons(&out[0]).contains(&HoldReason::ActiveEntryModified),
                "{out:?}"
            );
            assert!(
                std::fs::read_to_string(fx.p())
                    .unwrap()
                    .ends_with("# edited\n")
            );
        }
    }
}

/// ADR-0007 §12.18 item 2 (review X02), the reviewer's scenario. A first adoption
/// creates the absent user file; the transaction check fails (P, still inactive, is
/// edited after the user step's post-validation), so the created user file is rolled
/// back. An editor appends a host to it at `BeforeRestoreCheck`. The rollback re-checks
/// the path's identity and target digest before writing or moving anything: the edited
/// file stays at its path, the step holds with `active_entry_modified` (C7a), nothing of
/// it enters the quarantine, and a restart moves nothing.
#[test]
fn a22_create_rollback_never_moves_an_edit_made_at_restore_check() {
    let fx = Fx::new();
    std::fs::remove_file(fx.user()).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let user = fx.user().to_path_buf();
    let hook = Hook::new()
        .run(
            ReplacePoint::AfterPostValidate,
            Some(u),
            appender(&fx.p(), "# the owner's edit of P\n"),
        )
        .run(
            ReplacePoint::BeforeRestoreCheck,
            Some(u),
            appender(&user, "Host mine\n"),
        );
    let sink = Sink::default();
    let r = apply_or_crash(fx.hooked(&hook), &intent, &sink)
        .unwrap()
        .unwrap();
    let kinds = sink.kinds();
    assert!(
        hook.seen().contains(&(ReplacePoint::BeforeRestoreCheck, u)),
        "{kinds:?}"
    );
    let [ItemOutcome::Held { steps, .. }] = r.items.as_slice() else {
        panic!("{:?} {kinds:?}", r.items);
    };
    assert!(
        steps
            .iter()
            .any(|s| s.step == u && s.reason == HoldReason::ActiveEntryModified),
        "{steps:?} {kinds:?}"
    );
    let text = std::fs::read_to_string(&user).expect("the edited user file stays at its path");
    assert!(text.ends_with("Host mine\n"), "{text}");
    assert!(text.contains("# >>> heimdall managed include"));
    for k in ["settling", "settled", "settle_conflict", "restored"] {
        assert!(!kinds.contains(&format!("{u}:{k}")), "{k}: {kinds:?}");
    }
    assert!(
        !kinds.iter().any(|k| k.starts_with("ssh:finished")),
        "{kinds:?}"
    );
    let quarantined: Vec<String> = fx
        .tree()
        .into_iter()
        .filter(|(name, e)| {
            name.starts_with("ssh/.hm-quarantine/") && e.bytes.ends_with(b"Host mine\n")
        })
        .map(|(name, _)| name)
        .collect();
    assert!(quarantined.is_empty(), "{quarantined:?}");
    let tree = fx.tree();
    let again = restart(&fx, &intent, &sink);
    assert!(
        held_reasons(&again[0]).contains(&HoldReason::ActiveEntryModified),
        "{again:?}"
    );
    assert_eq!(fx.tree(), tree, "a restart moves nothing");
}

/// ADR-0007 §12.18 item 2 (review X02), for a continued path-source settlement. The
/// same rollback of a created user file crashes after its `file.settling{path}` and
/// before the move. At restart the path still holds S unchanged (row F8a: move), and an
/// editor appends to it at `BeforeSettleMove`, right before the move. The settlement
/// re-checks identity and target digest before moving: the edited file stays at its
/// path and the step holds with `active_entry_modified`, never kept in the quarantine.
#[test]
fn a22_continued_create_settlement_never_moves_an_edit_made_before_the_move() {
    let fx = Fx::new();
    std::fs::remove_file(fx.user()).unwrap();
    let intent = fx
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .intent();
    let u = step_of(&intent, FileRole::UserSsh);
    let user = fx.user().to_path_buf();
    let hook = Hook::new()
        .run(
            ReplacePoint::AfterPostValidate,
            Some(u),
            appender(&fx.p(), "# the owner's edit of P\n"),
        )
        .crash(ReplacePoint::BeforeSettleMove, Some(u));
    let sink = Sink::default();
    assert!(
        apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none(),
        "{:?}",
        sink.kinds()
    );
    let kinds = sink.kinds();
    assert_eq!(
        kinds.last().map(String::as_str),
        Some(format!("{u}:settling").as_str()),
        "{kinds:?}"
    );
    assert!(user.exists(), "the crash fell before the move");
    let restart_hook = Hook::new().run(
        ReplacePoint::BeforeSettleMove,
        Some(u),
        appender(&user, "Host mine\n"),
    );
    let out = reconcile_or_crash(fx.hooked(&restart_hook), &intent, &sink)
        .unwrap()
        .unwrap();
    let kinds = sink.kinds();
    assert!(
        restart_hook
            .seen()
            .contains(&(ReplacePoint::BeforeSettleMove, u)),
        "{kinds:?}"
    );
    let ItemOutcome::Held { steps, .. } = &out[0] else {
        panic!("{out:?} {kinds:?}");
    };
    assert!(
        steps
            .iter()
            .any(|s| s.step == u && s.reason == HoldReason::ActiveEntryModified),
        "{steps:?} {kinds:?}"
    );
    let text = std::fs::read_to_string(&user).expect("the edited user file stays at its path");
    assert!(text.ends_with("Host mine\n"), "{text}");
    for k in ["settled", "settle_conflict", "restored"] {
        assert!(!kinds.contains(&format!("{u}:{k}")), "{k}: {kinds:?}");
    }
    let tree = fx.tree();
    let again = restart(&fx, &intent, &sink);
    assert!(
        held_reasons(&again[0]).contains(&HoldReason::ActiveEntryModified),
        "{again:?}"
    );
    assert_eq!(fx.tree(), tree, "a restart moves nothing");
}

#[test]
fn held_step_moves_nothing_and_reobserves_at_restart() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let displaced = fx.home.config_dir.join(
        step_ref(&update, FileRole::ManagedSsh)
            .displaced_name
            .clone()
            .unwrap(),
    );
    let hook = Hook::new().crash(ReplacePoint::BeforeCommit, Some(p));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
    let parked = fx.home.root.join("parked");
    std::fs::rename(&displaced, &parked).unwrap();
    let tree = fx.tree();
    for _ in 0..3 {
        let out = restart(&fx, &update, &sink);
        assert_eq!(
            held_reasons(&out[0]),
            vec![HoldReason::DisplacedMissing],
            "{out:?}"
        );
        assert_eq!(fx.tree(), tree);
    }
    assert_eq!(
        count(&sink.kinds(), &format!("{p}:held")),
        1,
        "one held receipt"
    );
    // The owner moves D back; the next restart continues by F4 and T1.
    std::fs::rename(&parked, &displaced).unwrap();
    let out = restart(&fx, &update, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 2
        }],
        "{:?}",
        sink.kinds()
    );
    assert!(leftovers(&fx.tree()).is_empty());
}

// --- consent: decisions by effect (ADR-0007 §5.2; §12.17 item 8) ------------------------

/// The consent the sink's commits recorded (what the store keeps per item).
fn consent_of(sink: &Sink) -> heimdall_domain::projection::ConsentRecord {
    let mut out = heimdall_domain::projection::ConsentRecord::default();
    for c in sink.commits() {
        out.items.extend(c.consent.items);
    }
    out
}

fn reasons(plan: &ProjectionPlan) -> Vec<(String, heimdall_contract::setup::ConsentReasonKind)> {
    plan.view
        .consent
        .reasons
        .iter()
        .map(|r| (r.item.clone(), r.kind))
        .collect()
}

#[test]
fn consent_first_adoption_needs_a_decision_and_records_the_consented_states() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["work", "lab"], None), &Fx::apply_intent());
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![
            ("lab".to_owned(), ConsentReasonKind::NewState),
            ("work".to_owned(), ConsentReasonKind::NewState)
        ]
    );
    // The plan records, per alias, the approved managed state and the restore state
    // the decision shows; the restore column is in the summary.
    let work = &plan.consent.items[&ItemId::alias("work")];
    assert!(work.managed.determined && work.restore.determined);
    assert_ne!(work.managed.digest, work.restore.digest);
    let summary = plan.summary.as_ref().unwrap();
    assert_eq!(
        summary.added_aliases,
        vec!["lab".to_owned(), "work".to_owned()]
    );
    assert!(
        summary
            .restore
            .iter()
            .any(|r| r.item == ItemId::alias("work") && r.digest == work.restore.digest)
    );
    // `apply` records them under the approving decision.
    let mut intent = plan.intent();
    let decision = heimdall_contract::ids::DecisionId::from_random_bytes(random());
    intent.approval = Some(heimdall_domain::projection::ProjectionApproval {
        decision: decision.clone(),
        plan_digest: intent.plan_digest.clone(),
    });
    let sink = Sink::default();
    fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    let recorded = consent_of(&sink);
    assert_eq!(recorded.items[&ItemId::alias("work")].decision, decision);
    assert_eq!(recorded.items[&ItemId::alias("work")].managed, work.managed);
}

/// A plan that changes files but no alias's rendered section (a new public key in the
/// same key file) affects no item, so §5.2 needs no decision, and the plan records no
/// consent.
#[test]
fn consent_plan_affecting_no_item_needs_no_decision() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(&sink);
    spec.aliases = first_aliases(&first, &fx, &["work"]);
    // Another key for the same alias: only the key file's bytes change.
    let id = &spec.aliases[0].identity;
    fx.keys
        .0
        .lock()
        .unwrap()
        .insert(id.as_str().to_owned(), synthetic_public_key());
    let plan = fx.preview(&spec, &Fx::apply_intent());
    assert!(
        plan.files.iter().any(|s| s.role == FileRole::Key),
        "{:?}",
        plan.files
    );
    assert!(!plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert!(plan.consent.items.is_empty());
    assert!(plan.summary.is_none());
}

/// A rollback that yields exactly the restore state the owner was shown needs no
/// decision; one that would expose a value the user's configuration gained after the
/// decision needs one (`exposes_inherited`).
#[test]
fn consent_rollback_to_the_consented_restore_state_is_waived_else_decided() {
    use heimdall_contract::setup::ConsentReasonKind;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(&sink);
    assert!(!spec.consent.items.is_empty());
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.files.iter().any(|s| s.role == FileRole::UserSsh));
    assert!(!plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert!(plan.consent.items.is_empty());
    // The user later adds a wildcard HostName below B: P's value wins now, but the
    // rollback would expose it.
    let mut text = std::fs::read_to_string(fx.user()).unwrap();
    text.push_str("Host *\n    HostName exposed.example.invalid\n");
    std::fs::write(fx.user(), &text).unwrap();
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::ExposesInherited)]
    );
    // Without stored consent the same rollback needs a decision too.
    let mut bare = spec.clone();
    bare.consent = heimdall_domain::projection::ConsentRecord::default();
    assert!(
        fx.preview(&bare, &Fx::rollback_intent())
            .view
            .consent
            .decision_required
    );
}

/// An affected item whose state is undetermined (a `Match exec` that may set a relevant
/// directive) needs an attended decision whatever the digests say (§5.2, M2-R03).
#[test]
fn consent_undetermined_state_always_needs_a_decision() {
    use heimdall_contract::setup::ConsentReasonKind;
    let fx = Fx::new();
    let text =
        format!("{USER_TEXT}Match exec \"test -n x\"\n    ProxyJump bastion.example.invalid\n");
    std::fs::write(fx.user(), &text).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(&sink);
    let recorded = &spec.consent.items[&heimdall_domain::projection::ItemId::alias("work")];
    assert!(!recorded.managed.determined);
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::UndeterminedState)]
    );
}

// --- W3b-consent: manual mode classifies consent (ADR-0007 §12.21 item 1, V01) ----------

/// Replace the user file by a symlink to a regular file holding `bytes`; returns the
/// target. A symlinked user file is never edited (manual mode), but ssh reads it.
fn symlink_user_config(fx: &Fx, bytes: &[u8]) -> PathBuf {
    let real = fx.home.root.join("real-config");
    std::fs::write(&real, bytes).unwrap();
    std::fs::remove_file(fx.user()).unwrap();
    std::os::unix::fs::symlink(&real, fx.user()).unwrap();
    real
}

/// The spec of an update of `names` over the adoption `first`, with the record and the
/// consent the adoption committed.
fn update_spec(fx: &Fx, first: &SetupIntent, sink: &Sink, names: &[&str]) -> ProjectionSpec {
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(sink);
    spec.aliases = first_aliases(first, fx, names);
    spec
}

/// V01 reviewer reproducer (wave-2b/2c review; ADR-0007 §12.21 item 1): `work` adopted,
/// the user configuration then replaced by a symlink to the same bytes (B included),
/// then `work`'s HostName changed. The plan is manual (a symlink is never edited) and
/// writes P, and B still activates P, so the change needs a decision. Before the fix
/// the manual plan read no user bytes, classified no alias and needed none.
#[test]
fn v01_manual_mode_active_b_in_symlinked_user_config_changed_alias_needs_decision() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    let with_b = std::fs::read(fx.user()).unwrap();
    let real = symlink_user_config(&fx, &with_b);
    // Nothing changed: P is not rewritten and no alias is affected.
    let same = fx.preview(
        &update_spec(&fx, &first, &sink, &["work"]),
        &Fx::apply_intent(),
    );
    assert_eq!(same.view.mode, SetupMode::Manual);
    assert!(same.files.is_empty(), "{:?}", same.files);
    assert!(!same.view.consent.decision_required);
    // The reviewer's change.
    let mut spec = update_spec(&fx, &first, &sink, &["work"]);
    spec.aliases[0].hostname = "moved.example.invalid".to_owned();
    let plan = fx.preview(&spec, &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert_eq!(
        plan.view.manual_reasons,
        vec!["unmanageable_file".to_owned()]
    );
    assert!(
        plan.files
            .iter()
            .any(|s| s.role == FileRole::ManagedSsh && s.commit)
    );
    assert!(plan.files.iter().all(|s| s.role != FileRole::UserSsh));
    assert!(plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::ExposesInherited)]
    );
    let work = &plan.consent.items[&ItemId::alias("work")];
    assert!(work.managed.determined && work.restore.determined);
    assert_eq!(
        plan.summary.as_ref().unwrap().changed_aliases,
        vec!["work".to_owned()]
    );
    // The preview read through the symlink and wrote nothing.
    assert_eq!(std::fs::read(&real).unwrap(), with_b);
    assert!(
        std::fs::symlink_metadata(fx.user())
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// V01, the other manual branch (the `manual_mode` repair): the user file is never
/// planned, but its B activates P, so a changed alias needs a decision all the same.
#[test]
fn v01_manual_mode_repair_with_active_b_and_changed_alias_needs_decision() {
    use heimdall_contract::setup::{ConsentReasonKind, RepairResolution};
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    let user_before = std::fs::read(fx.user()).unwrap();
    let mut spec = update_spec(&fx, &first, &sink, &["work"]);
    spec.aliases[0].hostname = "moved.example.invalid".to_owned();
    let plan = fx.preview(
        &spec,
        &repair(ConflictKind::UnmanageableFile, RepairResolution::ManualMode),
    );
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.files.iter().all(|s| s.role != FileRole::UserSsh));
    assert!(plan.files.iter().any(|s| s.role == FileRole::ManagedSsh));
    assert!(plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::ExposesInherited)]
    );
    assert_eq!(std::fs::read(fx.user()).unwrap(), user_before);
}

/// V01: a user configuration the read-only source cannot read leaves P's activation
/// unknown, so every affected state is undetermined and a decision is required
/// (`undetermined_state`). The symlink's target is a directory (never a configuration
/// file, for any account), and, when this account cannot read it, a mode-000 file
/// holding B.
#[test]
fn v01_manual_mode_unreadable_symlink_target_makes_affected_states_undetermined() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    let dir = fx.home.root.join("config-dir");
    std::fs::create_dir(&dir).unwrap();
    std::fs::remove_file(fx.user()).unwrap();
    std::os::unix::fs::symlink(&dir, fx.user()).unwrap();
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.files.iter().any(|s| s.role == FileRole::ManagedSsh));
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::UndeterminedState)]
    );
    let work = &plan.consent.items[&ItemId::alias("work")];
    assert!(!work.managed.determined && !work.restore.determined);

    // An active B behind a target this account cannot read.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    let with_b = std::fs::read(fx.user()).unwrap();
    let real = symlink_user_config(&fx, &with_b);
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o000)).unwrap();
    // As the other unreadable-file tests here, this runs as an ordinary account.
    let readable = std::fs::read(&real).is_ok();
    let mut spec = update_spec(&fx, &first, &sink, &["work"]);
    spec.aliases[0].hostname = "moved.example.invalid".to_owned();
    let plan = fx.preview(&spec, &Fx::apply_intent());
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !readable,
        "precondition: this account cannot read a mode-000 file"
    );
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::UndeterminedState)]
    );
    assert_eq!(std::fs::read(&real).unwrap(), with_b);
}

/// ADR-0007 §12.24 item 6 (the W3b-consent reading "a manual first adoption whose
/// configuration does not activate P needs no decision" is rejected): a first adoption
/// always needs a decision, manual mode included (§5.2). Under a symlinked
/// configuration without B the alias's evaluated states are determined and equal (P is
/// not in effect yet), but the owner's own Include then activates P without another
/// Heimdall decision, so the plan needs one (`new_state`), shows the alias as added
/// and records the consented states for `apply`. Re-adoption over an empty record (a
/// rolled-back item) in manual mode needs one too. Controls: the same configuration
/// with B, or with the owner's own Include of P, needs one as before.
#[test]
fn manual_first_adoption_without_b_still_needs_a_decision() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    symlink_user_config(&fx, USER_TEXT.as_bytes());
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.files.iter().any(|s| s.role == FileRole::ManagedSsh));
    assert!(plan.files.iter().any(|s| s.role == FileRole::Key));
    assert!(plan.files.iter().all(|s| s.role != FileRole::UserSsh));
    assert!(plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::NewState)]
    );
    let work = &plan.consent.items[&ItemId::alias("work")];
    assert!(work.managed.determined && work.restore.determined);
    assert_eq!(
        work.managed.digest, work.restore.digest,
        "P is not in effect yet: the evaluated states are equal"
    );
    assert_eq!(
        plan.summary.as_ref().unwrap().added_aliases,
        vec!["work".to_owned()]
    );
    // Re-adoption over an empty SSH record (a rolled-back item), still manual: the
    // leftover consent does not count, and the decision is needed again.
    let mut items = BTreeMap::new();
    items.insert(ProjectionItem::Ssh, empty_record(2));
    let again = ProjectionSpec {
        environment: fx.env.clone(),
        aliases: fx.spec(&["work"], None).aliases,
        record: Some(ProjectionRecord {
            environment: fx.env.clone(),
            items,
        }),
        consent: plan.consent.clone(),
    };
    let plan = fx.preview(&again, &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::NewState)]
    );
    // The same configuration with B (written by the owner, as manual mode asks) makes
    // the adoption need a decision.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let probe = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    let with_b = probe
        .files
        .iter()
        .find(|s| s.role == FileRole::UserSsh)
        .map(|s| match s.content.view() {
            heimdall_domain::projection::StepContentView::Splice { offset, insert, .. } => {
                let mut b = USER_TEXT.as_bytes().to_vec();
                let at = usize::try_from(offset).unwrap();
                b.splice(at..at, insert.iter().copied());
                b
            }
            other => panic!("{other:?}"),
        })
        .unwrap();
    symlink_user_config(&fx, &with_b);
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.view.consent.decision_required, "{:?}", reasons(&plan));
    // So does the owner's own Include of P without Heimdall's markers: activation is
    // the evaluation's to establish, not the presence of a block.
    let fx = Fx::new();
    let own = format!("Include \"{}\"\n{USER_TEXT}", fx.p().to_str().unwrap());
    symlink_user_config(&fx, own.as_bytes());
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert_eq!(
        reasons(&plan),
        vec![(
            "work".to_owned(),
            heimdall_contract::setup::ConsentReasonKind::NewState
        )]
    );
}

/// ADR-0007 §12.26 item 5: a changed managed alias always needs a decision, in manual
/// mode too, P active or not. `work` is adopted in manual mode under a symlinked user
/// configuration without B: P is not in effect, so the consented managed state is the
/// user-only state. Its HostName then changes: the plan is manual, P's section changes,
/// and every evaluated state (current, after, consented) is still the same user-only
/// state, so the classification alone needs nothing; the owner's own Include would then
/// activate the change without another decision. The plan needs one (`new_state`) and
/// lists the alias as changed. Control: the unchanged spec affects nothing.
#[test]
fn manual_changed_alias_with_inactive_p_still_needs_a_decision() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    symlink_user_config(&fx, USER_TEXT.as_bytes());
    let (first, sink) = fx.adopt(&["work"]);
    let consented = consent_of(&sink);
    let recorded = &consented.items[&ItemId::alias("work")];
    assert!(recorded.managed.determined);
    assert_eq!(
        recorded.managed.digest, recorded.restore.digest,
        "P is not in effect: the consented state is the user-only state"
    );
    let same = fx.preview(
        &update_spec(&fx, &first, &sink, &["work"]),
        &Fx::apply_intent(),
    );
    assert_eq!(same.view.mode, SetupMode::Manual);
    assert!(!same.view.consent.decision_required, "{:?}", reasons(&same));

    let mut spec = update_spec(&fx, &first, &sink, &["work"]);
    spec.aliases[0].hostname = "moved.example.invalid".to_owned();
    let plan = fx.preview(&spec, &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert!(plan.files.iter().any(|s| s.role == FileRole::ManagedSsh));
    assert!(plan.files.iter().all(|s| s.role != FileRole::UserSsh));
    let work = &plan.consent.items[&ItemId::alias("work")];
    assert_eq!(
        work.managed.digest, recorded.managed.digest,
        "the after state is the consented one"
    );
    assert!(plan.view.consent.decision_required, "{:?}", reasons(&plan));
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::NewState)]
    );
    assert_eq!(
        plan.summary.as_ref().unwrap().changed_aliases,
        vec!["work".to_owned()]
    );
}

// --- W3d-select: the local account from the account database (ADR-0007 §12.25 item 2) ---

/// The account database's name for this test's account (never printed).
fn os_account() -> String {
    heimdall_localenv::doctor::local_account().expect("the account database names this account")
}

/// A projection configuration whose environment snapshot has `USER` (and `USERNAME`)
/// set to `user`, or neither.
fn config_with_user(fx: &Fx, user: Option<&str>) -> ProjectionConfig {
    let mut c = fx.config();
    let mut vars: Vec<(&str, String)> = vec![("HOME", fx.home.git_home.display().to_string())];
    if let Some(u) = user {
        vars.push(("USER", u.to_owned()));
        vars.push(("USERNAME", u.to_owned()));
    }
    c.env = heimdall_localenv::env::Env::from_vars(vars);
    c
}

/// ADR-0007 §12.25 item 2 (T02), projection observe (the runtime's readiness and the
/// CLI's pre-launch check): `Match localuser` reads the account database. A fallback
/// behind `Match localuser <the OS account>` makes `work`'s selection not exclusive
/// with `USER` unset and with `USER` naming another account; a rule for that other
/// name never applies, so the selection stays exclusive while `USER` names it.
#[test]
fn observe_reads_localuser_from_the_account_database() {
    use heimdall_contract::provider::IdentitySelection;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let record = sink.record(&fx.env);
    let base = std::fs::read_to_string(fx.user()).unwrap();
    let k2 = fx.home.root.join("k2.pub");
    std::fs::write(&k2, format!("{}\n", synthetic_public_key())).unwrap();
    let rule = |name: &str| {
        format!(
            "{base}Match localuser {name}\n    IdentityFile \"{}\"\n",
            k2.display()
        )
    };
    let other = "hm-fixture-other-account";
    let selection = |config: &ProjectionConfig| {
        heimdall_localenv::projection::observe::observe(config, &record, &["work".to_owned()])[0]
            .identity_selection
            .clone()
            .expect("a managed alias's selection")
            .selection
    };
    assert_eq!(
        selection(&config_with_user(&fx, None)),
        IdentitySelection::Exclusive,
        "control: the base configuration"
    );
    std::fs::write(fx.user(), rule(&os_account())).unwrap();
    for user in [None, Some(other)] {
        assert_eq!(
            selection(&config_with_user(&fx, user)),
            IdentitySelection::NotExclusive,
            "USER {}",
            if user.is_some() {
                "names another account"
            } else {
                "unset"
            }
        );
    }
    std::fs::write(fx.user(), rule(other)).unwrap();
    assert_eq!(
        selection(&config_with_user(&fx, Some(other))),
        IdentitySelection::Exclusive
    );
}

/// ADR-0007 §12.28 item 3 (replacing §12.25 item 2's whole-configuration reading):
/// when the local account cannot be established (`observe_as` with `None`), only the
/// conditions that read it are undetermined. A `Match localuser` that guards nothing the
/// selection reads leaves `work` exclusive with every directive as before; one that
/// guards an `IdentityFile` leaves that entry, and so the selection, undetermined while
/// `HostName`, `User` and `IdentitiesOnly` stay determined. With the account named, a
/// rule for another name never applies.
#[test]
fn observe_with_the_account_unknown_leaves_only_what_reads_it_undetermined() {
    use heimdall_contract::doctor::DirectiveCertainty;
    use heimdall_contract::provider::{Certainty, IdentitiesOnly, IdentitySelection};
    use heimdall_sshconf::eval::Invocation;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let record = sink.record(&fx.env);
    let base = std::fs::read_to_string(fx.user()).unwrap();
    let k2 = fx.home.root.join("k2.pub");
    std::fs::write(&k2, format!("{}\n", synthetic_public_key())).unwrap();
    let observe = |account: Option<&str>| {
        heimdall_localenv::projection::observe::observe_as(
            &fx.config(),
            &record,
            &["work".to_owned()],
            &Invocation::Shell,
            account.map(str::to_owned),
        )
        .remove(0)
    };
    let certainty = |o: &heimdall_contract::doctor::AliasObservation, name: &str| {
        o.behavior
            .iter()
            .find(|d| d.directive == name)
            .map(|d| d.certainty)
            .unwrap()
    };
    let before = observe(None);
    assert_eq!(
        before.identity_selection.as_ref().unwrap().selection,
        IdentitySelection::Exclusive,
        "unaffected"
    );
    // A rule that guards nothing the selection reads: unaffected.
    std::fs::write(
        fx.user(),
        format!("{base}Match localuser hm-fixture-nobody\n    ForwardAgent yes\n"),
    )
    .unwrap();
    let unknown = observe(None);
    assert_eq!(
        unknown.identity_selection.as_ref().unwrap().selection,
        IdentitySelection::Exclusive,
        "only the affected conditions are undetermined"
    );
    assert_eq!(unknown.behavior, before.behavior);
    // A rule that guards an `IdentityFile`: that entry is undetermined, nothing else.
    std::fs::write(
        fx.user(),
        format!(
            "{base}Match localuser hm-fixture-nobody\n    IdentityFile \"{}\"\n",
            k2.display()
        ),
    )
    .unwrap();
    let unknown = observe(None);
    let report = unknown.identity_selection.clone().unwrap();
    assert_eq!(report.selection, IdentitySelection::Undetermined);
    assert_eq!(report.identities_only, IdentitiesOnly::DeterminedYes);
    let k2_entries: Vec<_> = report
        .entries
        .iter()
        .filter(|e| e.source == heimdall_contract::provider::IdentityEntrySource::User)
        .collect();
    assert_eq!(k2_entries.len(), 1, "{report:?}");
    assert_eq!(k2_entries[0].certainty, Certainty::Undetermined);
    for name in ["HostName", "User", "IdentitiesOnly"] {
        assert_eq!(
            certainty(&unknown, name),
            DirectiveCertainty::Determined,
            "{name}"
        );
    }
    assert_eq!(
        certainty(&unknown, "IdentityFile"),
        DirectiveCertainty::Undetermined
    );
    let named = observe(Some("hm-fixture-account"));
    assert_eq!(
        named.identity_selection.unwrap().selection,
        IdentitySelection::Exclusive
    );
}

/// ADR-0007 §12.28 item 5: the projection observation the runtime's no-interaction
/// readiness reads (`ProjectionWriter::observe`, `observe::observe`) covers `Shell`,
/// `Exec(None)` and `Subsystem("sftp")`. An `IdentityFile` behind `Match sessiontype
/// exec` (exec-only) or `Match sessiontype subsystem` (subsystem-only) leaves the shell
/// alone exclusive, but the observation `observe` answers is not exclusive and lists
/// the entry, so readiness must clear it. An `IdentityAgent` behind either makes that
/// directive undetermined. The base configuration stays exclusive and determined.
#[test]
fn observe_combines_every_invocation_profile_for_readiness() {
    use heimdall_app::ports::ProjectionWriter as _;
    use heimdall_contract::doctor::DirectiveCertainty;
    use heimdall_contract::provider::{IdentityEntrySource, IdentitySelection};
    use heimdall_sshconf::eval::Invocation;
    let fx = Fx::with_sessiontype_client();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let record = sink.record(&fx.env);
    let base = std::fs::read_to_string(fx.user()).unwrap();
    let k2 = fx.home.root.join("k2.pub");
    std::fs::write(&k2, format!("{}\n", synthetic_public_key())).unwrap();
    let writer = LocalProjection::new(fx.config());
    let combined = || writer.observe(&record, &["work".to_owned()]).remove(0);
    let shell = || {
        heimdall_localenv::projection::observe::observe_under(
            &fx.config(),
            &record,
            &["work".to_owned()],
            &Invocation::Shell,
        )
        .remove(0)
    };
    let control = combined();
    assert_eq!(
        control.identity_selection.as_ref().unwrap().selection,
        IdentitySelection::Exclusive
    );
    assert_eq!(control.behavior, shell().behavior, "alike in every profile");
    for criterion in ["exec", "subsystem"] {
        std::fs::write(
            fx.user(),
            format!(
                "{base}Match sessiontype {criterion}\n    IdentityFile \"{}\"\n",
                k2.display()
            ),
        )
        .unwrap();
        assert_eq!(
            shell().identity_selection.unwrap().selection,
            IdentitySelection::Exclusive,
            "{criterion}: the shell alone is exclusive"
        );
        let all = combined();
        let report = all.identity_selection.clone().unwrap();
        assert_ne!(
            report.selection,
            IdentitySelection::Exclusive,
            "{criterion}"
        );
        let user: Vec<_> = report
            .entries
            .iter()
            .filter(|e| e.source == IdentityEntrySource::User)
            .collect();
        assert_eq!(user.len(), 1, "{criterion}: {report:?}");
        let line = u32::try_from(base.lines().count() + 2).unwrap();
        assert_eq!(user[0].provenance.as_ref().unwrap().line, line);
        assert_eq!(
            user[0].provenance.as_ref().unwrap().path_display,
            "~/.ssh/config"
        );
        assert!(user[0].cleared.is_none(), "readiness clears it itself");
        let file = all
            .behavior
            .iter()
            .find(|d| d.directive == "IdentityFile")
            .unwrap();
        assert_eq!(
            file.certainty,
            DirectiveCertainty::Undetermined,
            "{criterion}"
        );
        // An `IdentityAgent` override behind the criterion, before Heimdall's block.
        std::fs::write(
            fx.user(),
            format!(
                "Match sessiontype {criterion}\n    IdentityAgent \"{}\"\nMatch all\n{base}",
                fx.home.root.join("other-agent.sock").display()
            ),
        )
        .unwrap();
        let agent = combined()
            .behavior
            .into_iter()
            .find(|d| d.directive == "IdentityAgent")
            .unwrap();
        // The shell leaves it unset, the other profile sets it: undetermined.
        assert_eq!(
            agent.certainty,
            DirectiveCertainty::Undetermined,
            "{criterion}"
        );
        assert_eq!(agent.values.len(), 1, "{criterion}: {agent:?}");
        assert!(agent.values[0].ends_with("other-agent.sock"), "{agent:?}");
    }
}

/// ADR-0007 §12.25 item 2 (T02), preview (consent): a `ForwardAgent yes` behind `Match
/// localuser <the OS account>` is part of `work`'s consented state with `USER` naming
/// another account (its digest differs from the state without the rule), and one
/// behind `Match localuser <that other name>` is not (the digest is the rule-less one).
#[test]
fn preview_consent_reads_localuser_from_the_account_database() {
    use heimdall_domain::projection::ItemId;
    let other = "hm-fixture-other-account";
    let fx = Fx::new();
    let spec = fx.spec(&["work"], None);
    let state = |extra: &str| {
        std::fs::write(fx.user(), format!("{USER_TEXT}{extra}")).unwrap();
        let plan = LocalProjection::new(config_with_user(&fx, Some(other)))
            .preview(&spec, &Fx::apply_intent())
            .unwrap();
        plan.consent.items[&ItemId::alias("work")].managed.clone()
    };
    let none = state("");
    let account = state(&format!(
        "Match localuser {}\n    ForwardAgent yes\n",
        os_account()
    ));
    let named = state(&format!("Match localuser {other}\n    ForwardAgent yes\n"));
    assert!(none.determined && account.determined && named.determined);
    assert_ne!(account.digest, none.digest, "the account's rule applies");
    assert_eq!(named.digest, none.digest, "the USER name's rule does not");
}

// --- W3b-consent: every invocation profile (ADR-0007 §12.21 item 2, V02) ---------------

/// The spec of a rollback after `sink`'s adoption, with its consent.
fn rollback_spec(fx: &Fx, sink: &Sink) -> ProjectionSpec {
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(sink);
    spec
}

/// V02 reviewer reproducer 1, through the writer: a `Match sessiontype exec` HostName
/// changed after the adoption. The rollback would expose another destination to remote
/// commands and Git over SSH, so it needs a decision; unchanged, it is still waived.
#[test]
fn v02_rollback_after_exec_only_hostname_change_needs_decision() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::with_sessiontype_client();
    let text = format!("{USER_TEXT}Match sessiontype exec\n    HostName exec-a.example.invalid\n");
    std::fs::write(fx.user(), &text).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let spec = rollback_spec(&fx, &sink);
    let recorded = &spec.consent.items[&ItemId::alias("work")];
    assert!(recorded.managed.determined && recorded.restore.determined);
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.files.iter().any(|s| s.role == FileRole::UserSsh));
    assert!(!plan.view.consent.decision_required, "{:?}", reasons(&plan));
    let now = std::fs::read_to_string(fx.user())
        .unwrap()
        .replace("exec-a.example.invalid", "exec-b.example.invalid");
    std::fs::write(fx.user(), now).unwrap();
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::ExposesInherited)]
    );
}

/// V02 reviewer reproducer 2, through the writer: an environment-dependent
/// `IdentityAgent` behind `Match sessiontype subsystem` added after the adoption. The
/// restore state is undetermined for SFTP, so the rollback needs a decision.
#[test]
fn v02_rollback_after_subsystem_only_environment_agent_needs_decision() {
    use heimdall_contract::setup::ConsentReasonKind;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let spec = rollback_spec(&fx, &sink);
    assert!(
        !fx.preview(&spec, &Fx::rollback_intent())
            .view
            .consent
            .decision_required
    );
    let mut text = std::fs::read_to_string(fx.user()).unwrap();
    text.push_str("Match sessiontype subsystem\n    IdentityAgent ${HM_FIXTURE_AGENT}\n");
    std::fs::write(fx.user(), &text).unwrap();
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::UndeterminedState)]
    );
}

/// ADR-0007 §12.21 item 2 through the writer: `Match command` is unknown under
/// `Exec(None)`, so a `ProxyJump` behind it (P sets none) leaves the alias's recorded
/// states undetermined, and a rollback needs a decision.
#[test]
fn v02_match_command_unknown_under_exec_leaves_the_states_undetermined() {
    use heimdall_contract::setup::ConsentReasonKind;
    use heimdall_domain::projection::ItemId;
    let fx = Fx::new();
    let text =
        format!("{USER_TEXT}Match command \"git-*\"\n    ProxyJump bastion.example.invalid\n");
    std::fs::write(fx.user(), &text).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    let spec = rollback_spec(&fx, &sink);
    let recorded = &spec.consent.items[&ItemId::alias("work")];
    assert!(!recorded.managed.determined && !recorded.restore.determined);
    let plan = fx.preview(&spec, &Fx::rollback_intent());
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::UndeterminedState)]
    );
}

// --- W3b-consent: empty records and key files (ADR-0007 §12.22 items 2 and 8) -----------

/// An empty item record (no files, no aliases), as a rollback commits it.
fn empty_record(generation: u64) -> heimdall_domain::projection::ItemRecord {
    heimdall_domain::projection::ItemRecord {
        generation,
        files: Vec::new(),
        aliases: Vec::new(),
        operation: OperationId::from_random_bytes([7; 16]),
        committed_at: heimdall_contract::Timestamp::now(),
    }
}

/// ADR-0007 §12.22 item 2: a rolled-back item is an empty record at its generation. The
/// preview treats it as absent, Git included: a rerender plans no Git item for an
/// empty Git record, stored consent does not count for an empty SSH record (re-adoption
/// needs a decision), and the next generation still counts both.
#[test]
fn empty_item_records_are_absent_git_included() {
    use heimdall_contract::setup::{ConsentReasonKind, RepairResolution};
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    // The consent a first adoption of `work` would record.
    let first = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    assert!(!first.consent.items.is_empty());
    let aliases = fx.spec(&["work"], None).aliases;
    let spec_with = |ssh: heimdall_domain::projection::ItemRecord, with_git: bool| {
        let mut items = BTreeMap::new();
        items.insert(ProjectionItem::Ssh, ssh);
        if with_git {
            items.insert(ProjectionItem::Git, empty_record(3));
        }
        ProjectionSpec {
            environment: fx.env.clone(),
            aliases: aliases.clone(),
            record: Some(ProjectionRecord {
                environment: fx.env.clone(),
                items,
            }),
            consent: first.consent.clone(),
        }
    };
    // Rerender over an empty Git record: no Git item is planned.
    let rerender = repair(ConflictKind::ManagedFileEdited, RepairResolution::Rerender);
    let plan = fx.preview(&spec_with(empty_record(2), true), &rerender);
    assert!(plan.view.git.is_none(), "{:?}", plan.view.git);
    assert_eq!(plan.generation, 4, "empty records keep the generation");
    // Re-adoption over an empty SSH record: the leftover consent does not count.
    let plan = fx.preview(&spec_with(empty_record(2), false), &Fx::apply_intent());
    assert_eq!(plan.generation, 3);
    assert!(plan.view.consent.decision_required);
    assert_eq!(
        reasons(&plan),
        vec![("work".to_owned(), ConsentReasonKind::NewState)]
    );
    // Control: a live record naming `work` lets the same consent count.
    let mut live = empty_record(2);
    live.aliases = vec!["work".to_owned()];
    let plan = fx.preview(&spec_with(live, false), &Fx::apply_intent());
    assert!(!plan.view.consent.decision_required, "{:?}", reasons(&plan));
}

/// ADR-0007 §12.22 item 8: a managed alias with an empty `key_file` is refused as
/// `PreviewError::Unavailable`, never rendered as an empty `IdentityFile`; nothing is
/// written.
#[test]
fn empty_key_file_is_refused_unavailable() {
    use heimdall_app::ports::PreviewError;
    use heimdall_contract::setup::RepairResolution;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let tree = fx.tree();
    let mut spec = fx.spec(&["work", "lab"], None);
    spec.aliases[1].key_file = String::new();
    for intent in [
        Fx::apply_intent(),
        repair(ConflictKind::ManagedFileEdited, RepairResolution::Rerender),
        repair(ConflictKind::UnmanageableFile, RepairResolution::ManualMode),
    ] {
        match fx.writer().preview(&spec, &intent) {
            Err(PreviewError::Unavailable(message)) => {
                assert_eq!(message, "a managed alias has no key file", "{intent:?}");
            }
            other => panic!("{intent:?}: {other:?}"),
        }
    }
    assert_eq!(fx.tree(), tree, "a refused preview writes nothing");
}

// --- markers, manual mode, encodings ----------------------------------------------------

fn findings(plan: &ProjectionPlan) -> Vec<(String, Option<String>)> {
    plan.view
        .findings
        .iter()
        .map(|f| (f.code.clone(), f.reason.clone()))
        .collect()
}

fn rollback_plan(fx: &Fx, sink: &Sink) -> ProjectionPlan {
    fx.preview(
        &fx.spec(&[], Some(sink.record(&fx.env))),
        &Fx::rollback_intent(),
    )
}

#[test]
fn a22_edit_of_managed_file_is_never_overwritten() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    // The owner edits P. A new preview refuses to overwrite it.
    appender(&fx.p(), "# mine\n")();
    let edited = std::fs::read(fx.p()).unwrap();
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.aliases = first_aliases(&first, &fx, &["work"]);
    spec.aliases.push(fx.alias("lab"));
    let plan = fx.preview(&spec, &Fx::apply_intent());
    assert!(plan.files.is_empty());
    assert_eq!(
        findings(&plan),
        vec![(
            "projection_edited".to_owned(),
            Some("managed_file_edited".to_owned())
        )]
    );
    // An approved intent whose P was edited between preview and apply writes nothing.
    std::fs::write(fx.p(), std::fs::read(fx.p()).unwrap()).unwrap();
    let fx2 = Fx::new();
    std::fs::write(fx2.user(), USER_TEXT).unwrap();
    let (_f2, _s2, update) = fx2.update_plan(&["work"], "lab");
    appender(&fx2.p(), "# mine\n")();
    let p_bytes = std::fs::read(fx2.p()).unwrap();
    let r = fx2.writer().apply(&update, &mut Sink::default()).unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::ManagedFileEdited)
        }]
    );
    assert_eq!(
        std::fs::read(fx2.p()).unwrap(),
        p_bytes,
        "never overwritten"
    );
    // At rollback (§5.5, §12.17 item 8), B is removed and the edited P is not removed:
    // it is renamed, with no-replace, to `ssh_config.hm-conflict-<gen>` and reported.
    let rb_plan = rollback_plan(&fx, &sink);
    assert!(
        findings(&rb_plan).contains(&(
            "projection_edited".to_owned(),
            Some("managed_file_edited".to_owned())
        )),
        "{:?}",
        findings(&rb_plan)
    );
    let rb = rb_plan.intent();
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(matches!(r.items[0], ItemOutcome::Applied { .. }), "{r:?}");
    assert!(!fx.p().exists(), "P is no longer at its name");
    let kept = fx
        .home
        .config_dir
        .join(format!("ssh_config.hm-conflict-{}", rb.generation));
    assert_eq!(std::fs::read(&kept).unwrap(), edited, "the edit survives");
    let locator = sink.record(&fx.env).items[&ProjectionItem::Ssh]
        .files
        .iter()
        .find(|l| l.role == FileRole::ManagedSsh)
        .cloned()
        .unwrap();
    // The cleaner then finds P absent (R3) and removes nothing.
    block_on(fx.cleaner().delete(&resource(&fx.env, &locator, 1))).unwrap();
    assert_eq!(std::fs::read(&kept).unwrap(), edited);
    assert!(!String::from_utf8_lossy(&std::fs::read(fx.user()).unwrap()).contains("heimdall"));
}

/// §5.5's rename, the other cases: an edit made between the rollback's preview and its
/// apply is kept the same way; an occupied conflict name leaves the edited P where it
/// is (no-replace), with the occupant intact; an unedited P is the cleaner's.
#[test]
fn a22_rollback_keeps_edited_p_under_conflict_name_never_over_another() {
    for case in ["edited_after_preview", "name_occupied", "unedited"] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, sink) = fx.adopt(&["work"]);
        let original = std::fs::read(fx.p()).unwrap();
        let rb = rollback_plan(&fx, &sink).intent();
        let kept = fx
            .home
            .config_dir
            .join(format!("ssh_config.hm-conflict-{}", rb.generation));
        if case != "unedited" {
            appender(&fx.p(), "# mine\n")();
        }
        if case == "name_occupied" {
            std::fs::write(&kept, b"another file\n").unwrap();
        }
        let p_bytes = std::fs::read(fx.p()).unwrap();
        let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
        assert!(
            matches!(r.items[0], ItemOutcome::Applied { .. }),
            "{case}: {r:?}"
        );
        match case {
            "edited_after_preview" => {
                assert!(!fx.p().exists(), "{case}");
                assert_eq!(std::fs::read(&kept).unwrap(), p_bytes, "{case}");
            }
            "name_occupied" => {
                assert_eq!(std::fs::read(fx.p()).unwrap(), p_bytes, "{case}: P stays");
                assert_eq!(std::fs::read(&kept).unwrap(), b"another file\n", "{case}");
            }
            _ => {
                assert_eq!(std::fs::read(fx.p()).unwrap(), original, "{case}");
                assert!(!kept.exists(), "{case}");
                let locator = sink.record(&fx.env).items[&ProjectionItem::Ssh]
                    .files
                    .iter()
                    .find(|l| l.role == FileRole::ManagedSsh)
                    .cloned()
                    .unwrap();
                block_on(fx.cleaner().delete(&resource(&fx.env, &locator, 1))).unwrap();
                assert!(!fx.p().exists(), "{case}: the cleaner removed P");
            }
        }
    }
}

/// A rollback whose user file no longer has B (the owner removed it by hand) plans
/// only the files for the cleaner. Its item exchanges nothing; its check and
/// `item.committed` are its commit point, and it ends `applied`, never held.
#[test]
fn a22_rollback_without_block_commits_and_hands_files_to_the_cleaner() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, sink) = fx.adopt(&["work"]);
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let rb = rollback_plan(&fx, &sink).intent();
    assert!(rb.files.iter().all(|s| s.role != FileRole::UserSsh));
    let rsink = Sink::default();
    let r = fx.writer().apply(&rb, &mut rsink.clone()).unwrap();
    assert!(
        matches!(r.items[0], ItemOutcome::Applied { .. }),
        "{r:?} {:?}",
        rsink.kinds()
    );
    assert_eq!(rsink.kinds(), vec!["ssh:committed", "ssh:finished_applied"]);
}

#[test]
fn a22_edit_inside_marker_block_refuses_removal_and_names_lines() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_intent, sink) = fx.adopt(&["work"]);
    let text = std::fs::read_to_string(fx.user()).unwrap();
    let edited = text.replacen("Include \"", "Include  \"", 1);
    std::fs::write(fx.user(), &edited).unwrap();
    let plan = rollback_plan(&fx, &sink);
    assert!(
        plan.files.iter().all(|s| s.role != FileRole::UserSsh),
        "no removal"
    );
    assert_eq!(plan.view.findings.len(), 1);
    let f = &plan.view.findings[0];
    assert_eq!(f.code, "marker_edited");
    let include_line = edited
        .lines()
        .position(|l| l.starts_with("Include"))
        .unwrap()
        + 1;
    assert!(
        f.message.contains(&format!("lines {include_line}")),
        "{}",
        f.message
    );
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), edited);
}

#[test]
fn a22_newer_user_edits_elsewhere_survive_rollback() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_intent, sink) = fx.adopt(&["work"]);
    let mut text = std::fs::read_to_string(fx.user()).unwrap();
    text.push_str("Host newer\n    User me\n");
    let text = text.replacen("# my settings", "# my settings (edited)", 1);
    std::fs::write(fx.user(), &text).unwrap();
    let rb = rollback_plan(&fx, &sink).intent();
    let r = fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    assert!(matches!(r.items[0], ItemOutcome::Applied { .. }), "{r:?}");
    let expected = format!("{USER_TEXT}Host newer\n    User me\n").replacen(
        "# my settings",
        "# my settings (edited)",
        1,
    );
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), expected);
}

#[test]
fn a22_marker_moved_into_host_section_reported_conditional() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (first, sink) = fx.adopt(&["work"]);
    let text = std::fs::read_to_string(fx.user()).unwrap();
    let start = text.find("# >>> heimdall").unwrap();
    let end = text.find("# <<< heimdall").unwrap();
    let end = end + text[end..].find('\n').unwrap() + 1;
    let block = &text[start..end];
    let moved = format!("{}{}", text.replace(block, ""), block);
    std::fs::write(fx.user(), &moved).unwrap();
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.aliases = first_aliases(&first, &fx, &["work"]);
    spec.aliases.push(fx.alias("lab"));
    let plan = fx.preview(&spec, &Fx::apply_intent());
    assert!(plan.files.is_empty());
    assert_eq!(
        findings(&plan),
        vec![(
            "include_conditional".to_owned(),
            Some("include_conditional".to_owned())
        )]
    );
    assert!(plan.view.findings[0].message.contains("lines"));
}

#[test]
fn a22_duplicate_marker_refused() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_intent, sink) = fx.adopt(&["work"]);
    let text = std::fs::read_to_string(fx.user()).unwrap();
    let start = text.find("# >>> heimdall").unwrap();
    let end = text.find("# <<< heimdall").unwrap();
    let end = end + text[end..].find('\n').unwrap() + 1;
    let doubled = format!("{}{}", &text[start..end], text);
    std::fs::write(fx.user(), &doubled).unwrap();
    let plan = rollback_plan(&fx, &sink);
    assert!(plan.files.is_empty());
    assert_eq!(
        findings(&plan),
        vec![(
            "marker_duplicated".to_owned(),
            Some("marker_duplicated".to_owned())
        )]
    );
    let fresh = fx.preview(&fx.spec(&["lab"], None), &Fx::apply_intent());
    assert!(fresh.files.iter().all(|s| s.role != FileRole::UserSsh));
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), doubled);
}

fn repair(
    conflict: ConflictKind,
    resolution: heimdall_contract::setup::RepairResolution,
) -> PreviewIntent {
    PreviewIntent::Repair {
        conflict,
        resolution,
        operation: None,
    }
}

/// `remove_duplicate_markers` (ADR-0007 §5.5; §12.17 item 8): the first block that is
/// Heimdall's exact B before the first section stays, one other exact B is removed by
/// one splice, and nothing else changes. Removing a redundant include changes no
/// alias's behaviour, so §5.2 needs no decision. An edited duplicate is never removed.
#[test]
fn a22_repair_remove_duplicate_markers_keeps_one_block() {
    use heimdall_contract::setup::RepairResolution;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_intent, sink) = fx.adopt(&["work"]);
    let adopted = std::fs::read_to_string(fx.user()).unwrap();
    let start = adopted.find("# >>> heimdall").unwrap();
    let end = adopted.find("# <<< heimdall").unwrap();
    let end = end + adopted[end..].find('\n').unwrap() + 1;
    let block = adopted[start..end].to_owned();
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(&sink);
    let intent = repair(
        ConflictKind::MarkerDuplicated,
        RepairResolution::RemoveDuplicateMarkers,
    );
    // An edited duplicate is not Heimdall's: no removal, its line named.
    let edited = format!("{adopted}{}", block.replace("Include \"", "Include  \""));
    std::fs::write(fx.user(), &edited).unwrap();
    let plan = fx.preview(&spec, &intent);
    assert!(plan.files.is_empty());
    assert_eq!(findings(&plan)[0].0, "marker_edited");
    // An exact duplicate is removed.
    let doubled = format!("{block}{adopted}");
    std::fs::write(fx.user(), &doubled).unwrap();
    let plan = fx.preview(&spec, &intent);
    assert_eq!(
        plan.files
            .iter()
            .map(|s| (s.role, s.commit))
            .collect::<Vec<_>>(),
        vec![(FileRole::UserSsh, true)]
    );
    assert!(!plan.view.consent.decision_required, "{:?}", reasons(&plan));
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(matches!(r.items[0], ItemOutcome::Applied { .. }), "{r:?}");
    // The first exact block at the top stays; the user's lines are untouched.
    assert_eq!(
        std::fs::read_to_string(fx.user()).unwrap(),
        format!("{block}{USER_TEXT}")
    );
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

/// `move_include_to_top` (ADR-0007 §5.5; §12.17 item 8): a move is two edits of the
/// user file and an intent has one step per file, so the repair inserts a fresh B at
/// the top and reports the conditional block left behind, which
/// `remove_duplicate_markers` then removes. P is never out of effect. Reaching the
/// managed state the owner consented to needs no new decision.
#[test]
fn a22_repair_move_include_to_top_then_remove_the_conditional_block() {
    use heimdall_contract::setup::RepairResolution;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_intent, sink) = fx.adopt(&["work"]);
    let adopted = std::fs::read_to_string(fx.user()).unwrap();
    let start = adopted.find("# >>> heimdall").unwrap();
    let end = adopted.find("# <<< heimdall").unwrap();
    let end = end + adopted[end..].find('\n').unwrap() + 1;
    let block = &adopted[start..end];
    let moved = format!("{}{}", adopted.replace(block, ""), block);
    std::fs::write(fx.user(), &moved).unwrap();
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.consent = consent_of(&sink);
    let plan = fx.preview(
        &spec,
        &repair(
            ConflictKind::IncludeConditional,
            RepairResolution::MoveIncludeToTop,
        ),
    );
    assert_eq!(
        plan.files
            .iter()
            .map(|s| (s.role, s.commit))
            .collect::<Vec<_>>(),
        vec![(FileRole::UserSsh, true)]
    );
    assert!(
        findings(&plan)
            .iter()
            .any(|(c, _)| c == "marker_duplicated")
    );
    assert!(!plan.view.consent.decision_required, "{:?}", reasons(&plan));
    // Without the stored consent, P coming into effect for `work` is a new state.
    let mut bare = spec.clone();
    bare.consent = heimdall_domain::projection::ConsentRecord::default();
    assert!(
        fx.preview(
            &bare,
            &repair(
                ConflictKind::IncludeConditional,
                RepairResolution::MoveIncludeToTop
            )
        )
        .view
        .consent
        .decision_required
    );
    fx.writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    let text = std::fs::read(fx.user()).unwrap();
    let blocks = heimdall_sshconf::edit::find_blocks(&text);
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        blocks[0].position,
        heimdall_sshconf::edit::BlockPosition::BeforeFirstSection
    );
    let plan = fx.preview(
        &spec,
        &repair(
            ConflictKind::MarkerDuplicated,
            RepairResolution::RemoveDuplicateMarkers,
        ),
    );
    fx.writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    let text = std::fs::read(fx.user()).unwrap();
    let blocks = heimdall_sshconf::edit::find_blocks(&text);
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].intact);
    assert_eq!(
        blocks[0].position,
        heimdall_sshconf::edit::BlockPosition::BeforeFirstSection
    );
    assert!(
        String::from_utf8_lossy(&text)
            .ends_with("Host personal\n    HostName personal.example.invalid\n    User me\n")
    );
}

/// `manual_mode` (ADR-0007 §5.3 step 9, §5.5; §12.17 item 8): P and the key files are
/// written and committed as an apply renders them, the user file is never planned or
/// touched, and the plan shows the exact block (B naming P by its absolute path).
#[test]
fn a22_repair_manual_mode_writes_p_never_the_user_file() {
    use heimdall_contract::setup::RepairResolution;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let ino = std::fs::symlink_metadata(fx.user()).unwrap().ino();
    let plan = fx.preview(
        &fx.spec(&["work"], None),
        &repair(ConflictKind::UnmanageableFile, RepairResolution::ManualMode),
    );
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert_eq!(
        plan.view.manual_reasons,
        vec!["unmanageable_file".to_owned()]
    );
    assert!(plan.files.iter().all(|s| s.role != FileRole::UserSsh));
    let shown = plan
        .view
        .findings
        .iter()
        .find(|f| f.code == "manual_mode")
        .unwrap();
    let p = fx.p();
    assert!(
        shown
            .message
            .contains(&format!("Include \"{}\"", p.to_str().unwrap())),
        "{}",
        shown.message
    );
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(matches!(r.items[0], ItemOutcome::Applied { .. }), "{r:?}");
    assert!(p.exists());
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), USER_TEXT);
    assert_eq!(std::fs::symlink_metadata(fx.user()).unwrap().ino(), ino);
}

fn assert_manual(fx: &Fx, reason: &str) {
    let tree = fx.tree();
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    assert_eq!(plan.view.mode, SetupMode::Manual);
    assert_eq!(plan.view.manual_reasons, vec![reason.to_owned()]);
    assert!(plan.files.iter().all(|s| s.role != FileRole::UserSsh));
    assert_eq!(fx.tree(), tree, "a preview writes nothing");
    let user_before = std::fs::symlink_metadata(fx.user())
        .ok()
        .map(|m| (m.ino(), m.mode()));
    let bytes_before = std::fs::read(fx.user()).ok();
    // Manual mode writes P and the key files, and commits them (P is the commit step),
    // so the doctor can verify the owner's block against the record.
    let sink = Sink::default();
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut sink.clone())
        .unwrap();
    assert!(
        matches!(r.items.as_slice(), [ItemOutcome::Applied { .. }]),
        "{r:?} {:?}",
        sink.kinds()
    );
    assert!(fx.p().exists());
    let user_after = std::fs::symlink_metadata(fx.user())
        .ok()
        .map(|m| (m.ino(), m.mode()));
    assert_eq!(user_after, user_before, "the user file is unchanged");
    assert_eq!(std::fs::read(fx.user()).ok(), bytes_before);
}

/// ADR-0007 §12.17 item 9 (caller side): B's target is P's absolute path, never `~`,
/// also when P lies under the account home, so B loads P whatever `$HOME` is. The
/// rollback finds and removes exactly that block.
#[test]
fn a22_include_block_names_p_by_absolute_path() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let mut config = fx.config();
    config.config_dir = fx.home.git_home.join(".config").join("heimdall");
    let p = config.managed_ssh_path();
    let writer = LocalProjection::new(config);
    let plan = writer
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .unwrap();
    let sink = Sink::default();
    let r = writer.apply(&plan.intent(), &mut sink.clone()).unwrap();
    assert!(matches!(r.items[0], ItemOutcome::Applied { .. }), "{r:?}");
    let text = std::fs::read_to_string(fx.user()).unwrap();
    let p_text = p.to_str().unwrap();
    assert!(p_text.starts_with('/'));
    assert!(text.contains(&format!("Include \"{p_text}\"\n")), "{text}");
    assert!(!text.contains("Include \"~"), "{text}");
    let rb = writer
        .preview(
            &fx.spec(&[], Some(sink.record(&fx.env))),
            &Fx::rollback_intent(),
        )
        .unwrap();
    assert!(rb.files.iter().any(|s| s.role == FileRole::UserSsh));
    writer.apply(&rb.intent(), &mut Sink::default()).unwrap();
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), USER_TEXT);
}

/// ADR-0007 §12.16 item 3 and §12.17 item 9: OpenSSH globs inside a quoted Include
/// argument, so a P path holding `*`, `?`, `[` or `]` cannot be named literally. The
/// plan is manual before any edit (`unmanageable_file`, with the finding reason
/// `include_target_glob`): no user-file step, P and the key files written and
/// committed, the user file untouched. ADR-0007 §12.22 item 8: the writer lists
/// `include_target_glob` as its own manual reason, besides `unmanageable_file`.
#[test]
fn a22_include_target_with_glob_metacharacter_is_manual_mode() {
    for dir in ["cfg[x]", "cfg*", "cfg?"] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let mut config = fx.config();
        config.config_dir = fx.home.root.join(dir);
        let writer = LocalProjection::new(config.clone());
        let plan = writer
            .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
            .unwrap();
        assert_eq!(plan.view.mode, SetupMode::Manual, "{dir}");
        assert_eq!(
            plan.view.manual_reasons,
            vec![
                "unmanageable_file".to_owned(),
                "include_target_glob".to_owned()
            ],
            "{dir}"
        );
        assert!(
            findings(&plan).contains(&(
                "unmanageable_file".to_owned(),
                Some("include_target_glob".to_owned())
            )),
            "{dir}: {:?}",
            findings(&plan)
        );
        assert!(
            plan.files.iter().all(|s| s.role != FileRole::UserSsh),
            "{dir}"
        );
        let ino = std::fs::symlink_metadata(fx.user()).unwrap().ino();
        let r = writer.apply(&plan.intent(), &mut Sink::default()).unwrap();
        assert!(
            matches!(r.items[0], ItemOutcome::Applied { .. }),
            "{dir}: {r:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fx.user()).unwrap(),
            USER_TEXT,
            "{dir}"
        );
        assert_eq!(std::fs::symlink_metadata(fx.user()).unwrap().ino(), ino);
        assert!(config.managed_ssh_path().exists(), "{dir}: P written");
    }
}

#[test]
fn a22_symlinked_user_config_is_manual_mode() {
    let fx = Fx::new();
    let real = fx.home.root.join("real-config");
    std::fs::write(&real, USER_TEXT).unwrap();
    std::fs::remove_file(fx.user()).unwrap();
    std::os::unix::fs::symlink(&real, fx.user()).unwrap();
    assert_manual(&fx, "unmanageable_file");
    assert_eq!(std::fs::read_to_string(&real).unwrap(), USER_TEXT);
}

#[test]
fn a22_hardlinked_user_config_is_manual_mode() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    std::fs::hard_link(fx.user(), fx.home.root.join("second-name")).unwrap();
    assert_manual(&fx, "unmanageable_file");
}

/// A file owned by another account cannot be made without privileges in a scratch
/// test; "not writable by this account alone" is covered by group/other write bits on
/// the file and on its directory (§5.3 steps 1–2), each manual mode.
#[test]
fn a22_foreign_owner_or_unwritable_is_manual_mode() {
    let fx = Fx::new();
    write_mode(fx.user(), USER_TEXT.as_bytes(), 0o666);
    assert_manual(&fx, "unmanageable_file");

    let fx = Fx::new();
    write_mode(fx.user(), USER_TEXT.as_bytes(), 0o600);
    std::fs::set_permissions(fx.ssh_dir(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_manual(&fx, "unmanageable_file");
    std::fs::set_permissions(fx.ssh_dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn accepting_client(fx: &Fx) -> ProjectionConfig {
    use heimdall_localenv::clients::{ClientCandidate, ClientInventory, ClientKind, ClientSource};
    let mut c = fx.config();
    c.clients = ClientInventory {
        candidates: vec![ClientCandidate {
            kind: ClientKind::Ssh,
            path: fx.home.root.join("bin").join("ssh"),
            source: ClientSource::Path,
            version: Some(heimdall_sshconf::eval::OpenSshVersion {
                major: 10,
                minor: 3,
                portable: Some(1),
            }),
            sha256: None,
            selected: true,
        }],
    };
    c
}

/// CRLF line endings and no trailing newline round-trip byte for byte on a client the
/// U3 observation table says accepts CRLF (macOS 10.3p1). A BOM is accepted by no
/// observed client on this platform, so a BOM file is manual mode (next test).
#[test]
#[cfg(target_os = "macos")]
fn a22_crlf_bom_no_trailing_newline_preserved() {
    let fx = Fx::new();
    let text = "# mine\r\nHost personal\r\n    User me";
    std::fs::write(fx.user(), text).unwrap();
    let writer = LocalProjection::new(accepting_client(&fx));
    let plan = writer
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .unwrap();
    assert_eq!(
        plan.view.mode,
        SetupMode::Automatic,
        "{:?}",
        plan.view.manual_reasons
    );
    let sink = Sink::default();
    writer.apply(&plan.intent(), &mut sink.clone()).unwrap();
    let after = std::fs::read_to_string(fx.user()).unwrap();
    assert!(after.contains("heimdall managed include (id hm-"));
    assert!(after.contains(");\u{20}remove with `heimdall setup rollback`\r\nInclude"));
    assert!(after.ends_with("    User me"), "no trailing newline added");
    let rb = writer
        .preview(
            &fx.spec(&[], Some(sink.record(&fx.env))),
            &Fx::rollback_intent(),
        )
        .unwrap();
    writer.apply(&rb.intent(), &mut Sink::default()).unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.user()).unwrap(),
        text,
        "byte for byte"
    );
}

#[test]
fn a22_bom_or_crlf_on_unaccepting_client_is_manual_mode_unchanged() {
    // No client is known to accept either (an unknown client means `false`).
    let fx = Fx::new();
    std::fs::write(fx.user(), "\u{feff}Host personal\n").unwrap();
    assert_manual(&fx, "unsupported_encoding");
    let fx = Fx::new();
    std::fs::write(fx.user(), "Host personal\r\n").unwrap();
    assert_manual(&fx, "unsupported_encoding");
    // A BOM on the observed client that does not accept a BOM.
    let fx = Fx::new();
    std::fs::write(fx.user(), "\u{feff}Host personal\r\n").unwrap();
    let plan = LocalProjection::new(accepting_client(&fx))
        .preview(&fx.spec(&["work"], None), &Fx::apply_intent())
        .unwrap();
    assert_eq!(
        plan.view.manual_reasons,
        vec!["unsupported_encoding".to_owned()]
    );
}

// --- durable writer content (M2-S05) -----------------------------------------------------

/// A JSON round trip of the intent, as the store keeps it.
fn round_trip(intent: &SetupIntent) -> SetupIntent {
    let json = serde_json::to_string(intent).unwrap();
    let back: SetupIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, intent);
    back.validate().unwrap();
    back
}

#[test]
fn intent_content_bound_to_digests_or_refused() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    let good = round_trip(&plan.intent());
    let tamper = |f: &dyn Fn(&mut serde_json::Value)| -> SetupIntent {
        let mut v = serde_json::to_value(&good).unwrap();
        f(&mut v);
        serde_json::from_value(v).unwrap()
    };
    let p = usize::from(step_of(&good, FileRole::ManagedSsh));
    let u = usize::from(step_of(&good, FileRole::UserSsh));
    let whole_changed = tamper(&|v| {
        v["files"][p]["content"]["bytes_b64"] = serde_json::json!("SG9zdCBldmlsCg==");
    });
    let offset_moved = tamper(&|v| {
        v["files"][u]["content"]["offset"] = serde_json::json!(1);
    });
    let user_bytes = std::fs::read(fx.user()).unwrap();
    let wrong_removed = {
        // A removal splice whose removed digest is wrong: the rollback shape.
        let mut i = good.clone();
        let step = i
            .files
            .iter_mut()
            .find(|s| s.role == FileRole::UserSsh)
            .unwrap();
        step.content = heimdall_domain::projection::StepContent::remove_range(
            0,
            3,
            Sha256Hex::of(b"not these bytes"),
        );
        step.target = Target::Present {
            sha256: Sha256Hex::of(&user_bytes[3..]),
        };
        i
    };
    let tree = fx.tree();
    for bad in [whole_changed, offset_moved, wrong_removed] {
        let e = fx.writer().apply(&bad, &mut Sink::default()).unwrap_err();
        assert!(matches!(e, ReconcileError::IntentInvalid(_)), "{e:?}");
        let e = fx
            .writer()
            .reconcile(&bad, &[], &mut Sink::default())
            .unwrap_err();
        assert!(matches!(e, ReconcileError::IntentInvalid(_)), "{e:?}");
        assert_eq!(fx.tree(), tree, "nothing written");
    }
}

#[test]
fn splice_applies_only_to_validated_base() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
    // Same length, other bytes: the splice offset would still fit.
    std::fs::write(fx.user(), USER_TEXT.replace("personal", "PERSONAL")).unwrap();
    let sink = Sink::default();
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut sink.clone())
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }]
    );
    assert!(
        !std::fs::read_to_string(fx.user())
            .unwrap()
            .contains("heimdall")
    );
}

#[test]
fn intent_content_nonsecret_and_bounded() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    // Private-key canaries in the scratch home: never read into an intent.
    let canary = format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nHEIMDALL_CANARY_U4C_{}\n-----END OPENSSH PRIVATE KEY-----\n",
        b64(&random::<12>())
    );
    write_mode(&fx.ssh_dir().join("id_ed25519"), canary.as_bytes(), 0o600);
    let plan = fx.preview(&fx.spec(&["work", "lab"], None), &Fx::apply_intent());
    let json = serde_json::to_string(&plan.intent()).unwrap();
    heimdall_testkit::assert_no_canary(&json);
    for s in &plan.files {
        let bytes: Vec<u8> = match s.content.view() {
            heimdall_domain::projection::StepContentView::Whole { bytes }
            | heimdall_domain::projection::StepContentView::LockHolder { bytes } => bytes.to_vec(),
            heimdall_domain::projection::StepContentView::Splice { insert, .. } => insert.to_vec(),
            heimdall_domain::projection::StepContentView::Absent => Vec::new(),
        };
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("PRIVATE KEY"));
        heimdall_testkit::assert_no_canary(&text);
    }
    // 257 key files are refused at preview.
    let names: Vec<String> = (0..257).map(|i| format!("a{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let e = fx
        .writer()
        .preview(&fx.spec(&refs, None), &Fx::apply_intent())
        .unwrap_err();
    assert_eq!(e, heimdall_app::ports::PreviewError::TooLarge);
}

#[test]
fn a22_recovery_before_remaining_file_staged_uses_intent_bytes() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["work", "lab"], None), &Fx::apply_intent());
    let intent = round_trip(&plan.intent());
    let first_key = u16::try_from(
        intent
            .files
            .iter()
            .position(|s| s.role == FileRole::Key)
            .unwrap(),
    )
    .unwrap();
    let hook = Hook::new().crash(ReplacePoint::AfterStage, Some(first_key));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &intent, &sink).is_none());
    // The catalog changes after the crash (an alias renamed). Recovery never renders:
    // it stages the remaining files from the intent.
    let renamed = fx.preview(&fx.spec(&["work2", "lab"], None), &Fx::apply_intent());
    assert_ne!(renamed.view.plan_digest, plan.view.plan_digest);
    let out = restart(&fx, &intent, &sink);
    assert_eq!(
        out,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 1
        }],
        "{:?}",
        sink.kinds()
    );
    for s in &intent.files {
        let Target::Present { sha256 } = &s.target else {
            continue;
        };
        assert_eq!(
            &Sha256Hex::of(&std::fs::read(&s.path).unwrap()),
            sha256,
            "{}",
            s.path
        );
    }
    assert!(!std::fs::read_to_string(fx.p()).unwrap().contains("work2"));
}

// --- content-checked discard (M2-S02) -------------------------------------------------------

#[test]
fn a22_in_place_edit_after_forward_exchange_then_rollback_is_held_never_restored_over() {
    for crash in [false, true] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let gen_n_ino = {
            let displaced = step_ref(&update, FileRole::ManagedSsh)
                .displaced_name
                .clone()
                .unwrap();
            (displaced, std::fs::symlink_metadata(fx.p()).unwrap().ino())
        };
        let p_path = fx.p();
        let hook = Hook::new().run(
            ReplacePoint::AfterPostValidate,
            Some(p),
            appender(fx.user(), "Host edited\n"),
        );
        // The editor rewrites the active P in place (identity S, content S′): in the
        // live variant just before the pre-restore check, in the crash variant while
        // the runtime is down after a crash at that point.
        let hook = if crash {
            hook.crash(ReplacePoint::BeforeRestoreCheck, Some(p))
        } else {
            hook.run(
                ReplacePoint::BeforeRestoreCheck,
                Some(p),
                appender(&p_path, "# editor\n"),
            )
        };
        let sink = Sink::default();
        let r = apply_or_crash(fx.hooked(&hook), &update, &sink);
        let out = if crash {
            assert!(r.is_none());
            appender(&fx.p(), "# editor\n")();
            restart(&fx, &update, &sink)
        } else {
            r.unwrap().unwrap().items
        };
        assert_eq!(
            held_reasons(&out[0]),
            vec![HoldReason::ActiveEntryModified],
            "{:?}",
            sink.kinds()
        );
        assert!(
            std::fs::read_to_string(fx.p())
                .unwrap()
                .ends_with("# editor\n"),
            "editor's bytes active"
        );
        let displaced = fx.home.config_dir.join(&gen_n_ino.0);
        assert_eq!(
            std::fs::symlink_metadata(&displaced).unwrap().ino(),
            gen_n_ino.1,
            "old P aside"
        );
        assert!(
            !sink.file_phases(p).iter().any(|ph| matches!(
                ph,
                FilePhase::Settled { .. } | FilePhase::Restored | FilePhase::Settling { .. }
            )),
            "nothing of P moved: {:?}",
            sink.kinds()
        );
    }
}

#[test]
fn a22_in_place_edit_racing_restore_is_kept_in_quarantine_never_deleted() {
    for crash in [false, true] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let p_path = fx.p();
        let editor = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&editor);
        let mut hook = Hook::new()
            .run(
                ReplacePoint::AfterPostValidate,
                Some(p),
                appender(fx.user(), "Host edited\n"),
            )
            .run(ReplacePoint::BeforeRestoreExchange, Some(p), move || {
                appender(&p_path, "# racing editor\n")();
                *e.lock().unwrap() = std::fs::read(&p_path).unwrap();
            });
        if crash {
            hook = hook.crash(ReplacePoint::AfterRestoreExchange, Some(p));
        }
        let sink = Sink::default();
        let r = apply_or_crash(fx.hooked(&hook), &update, &sink);
        let out = if crash {
            assert!(r.is_none());
            restart(&fx, &update, &sink)
        } else {
            r.unwrap().unwrap().items
        };
        assert!(
            matches!(
                out.as_slice(),
                [ItemOutcome::Restored {
                    item: ProjectionItem::Ssh,
                    ..
                }]
            ),
            "{out:?} {:?}",
            sink.kinds()
        );
        let phases = sink.file_phases(p);
        let kept = phases
            .iter()
            .find_map(|ph| match ph {
                FilePhase::SettleConflict {
                    found: SettleConflictFound::Modified,
                    kept,
                } => Some(kept.clone()),
                _ => None,
            })
            .expect("settle_conflict{modified}");
        let slot = fx
            .home
            .config_dir
            .join(".hm-quarantine")
            .join(&kept[0].name);
        assert_eq!(
            std::fs::read(&slot).unwrap(),
            *editor.lock().unwrap(),
            "editor's bytes kept"
        );
    }
}

#[test]
fn a22_displaced_written_through_open_descriptor_before_settlement_is_kept() {
    use std::io::Write as _;
    for residual in [false, true] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
        let p = step_of(&update, FileRole::ManagedSsh);
        let p_path = fx.p();
        let fd: Arc<Mutex<Option<std::fs::File>>> = Arc::default();
        let (f1, f2) = (Arc::clone(&fd), Arc::clone(&fd));
        let write_point = if residual {
            ReplacePoint::AfterSettleCheck
        } else {
            ReplacePoint::BeforeSettleMove
        };
        let hook = Hook::new()
            .run(ReplacePoint::BeforeExchange, Some(p), move || {
                *f1.lock().unwrap() = Some(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&p_path)
                        .unwrap(),
                );
            })
            .run(write_point, Some(p), move || {
                let mut g = f2.lock().unwrap();
                let f = g.as_mut().unwrap();
                f.write_all(b"# written through an old descriptor\n")
                    .unwrap();
                f.sync_all().unwrap();
            });
        let sink = Sink::default();
        let r = apply_or_crash(fx.hooked(&hook), &update, &sink)
            .unwrap()
            .unwrap();
        assert_eq!(
            r.items,
            vec![ItemOutcome::Applied {
                item: ProjectionItem::Ssh,
                generation: 2
            }]
        );
        let phases = sink.file_phases(p);
        let modified = phases.iter().any(|ph| {
            matches!(
                ph,
                FilePhase::SettleConflict {
                    found: SettleConflictFound::Modified,
                    ..
                }
            )
        });
        let q = fx.home.config_dir.join(".hm-quarantine");
        let kept: Vec<Vec<u8>> = std::fs::read_dir(&q)
            .map(|rd| {
                rd.map(|e| std::fs::read(e.unwrap().path()).unwrap())
                    .collect()
            })
            .unwrap_or_default();
        if residual {
            // ADR-0007 §5.9 item 1 residual, observed: the write between the final
            // check and the removal. Recorded as observed; no evidence claims it kept.
            let survived = kept
                .iter()
                .any(|b| String::from_utf8_lossy(b).contains("old descriptor"));
            #[allow(clippy::print_stderr)] // the residual is recorded as observed, not asserted
            {
                eprintln!(
                    "residual write at AfterSettleCheck: modified={modified} kept={survived}"
                );
            }
        } else {
            assert!(modified, "{:?}", sink.kinds());
            assert!(
                kept.iter()
                    .any(|b| String::from_utf8_lossy(b).contains("old descriptor"))
            );
        }
    }
}

// --- cleanup (ADR-0007 §5.8) -------------------------------------------------------------

fn p_locator(sink: &Sink, env: &EnvironmentId) -> ProjectionLocator {
    sink.record(env).items[&ProjectionItem::Ssh]
        .files
        .iter()
        .find(|l| l.role == FileRole::ManagedSsh)
        .cloned()
        .unwrap()
}

#[test]
fn a22_cleanup_entry_modified_after_quarantine_move_is_kept() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_i, sink) = fx.adopt(&["work"]);
    let l = p_locator(&sink, &fx.env);
    let slot = heimdall_localenv::projection::cleaner::slot_name(&l, 1).unwrap();
    let in_slot = fx.home.config_dir.join(".hm-quarantine").join(&slot);
    let s2 = in_slot.clone();
    let hook = Hook::new().run(ReplacePoint::AfterSettleMove, None, move || {
        appender(&s2, "# written in the slot\n")();
    });
    let cleaner = ProjectionCleaner::new(fx.hooked(&hook));
    block_on(cleaner.delete(&resource(&fx.env, &l, 1))).unwrap();
    assert!(
        String::from_utf8_lossy(&std::fs::read(&in_slot).unwrap())
            .ends_with("# written in the slot\n")
    );
    // Written before the move: left in place (R1a).
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_i, sink) = fx.adopt(&["work"]);
    let l = p_locator(&sink, &fx.env);
    appender(&fx.p(), "# mine\n")();
    block_on(fx.cleaner().delete(&resource(&fx.env, &l, 1))).unwrap();
    assert!(
        std::fs::read_to_string(fx.p())
            .unwrap()
            .ends_with("# mine\n")
    );
}

#[test]
fn a22_stale_cleanup_generation_n_cannot_delete_n_plus_1() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, s1, update) = fx.update_plan(&["work"], "lab");
    let gen1 = p_locator(&s1, &fx.env);
    let s2 = Sink::default();
    fx.writer().apply(&update, &mut s2.clone()).unwrap();
    let gen2 = std::fs::read(fx.p()).unwrap();
    // The cleanup of generation 1 reaches the deletion boundary after generation 2.
    block_on(fx.cleaner().delete(&resource(&fx.env, &gen1, 1))).unwrap();
    assert_eq!(std::fs::read(fx.p()).unwrap(), gen2, "generation 2 intact");
}

#[test]
fn a22_same_bytes_new_identity_is_not_deleted_by_cleanup() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_i, sink) = fx.adopt(&["work"]);
    let l = p_locator(&sink, &fx.env);
    let bytes = std::fs::read(fx.p()).unwrap();
    rename_replace(&fx.p(), &bytes);
    block_on(fx.cleaner().delete(&resource(&fx.env, &l, 1))).unwrap();
    assert_eq!(
        std::fs::read(fx.p()).unwrap(),
        bytes,
        "same bytes, new identity: kept"
    );
}

#[test]
fn a22_cleanup_target_swapped_at_deletion_is_moved_back() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_i, sink) = fx.adopt(&["work"]);
    let l = p_locator(&sink, &fx.env);
    let p = fx.p();
    let hook = Hook::new().run(ReplacePoint::BeforeSettleMove, None, move || {
        rename_replace(&p, b"swapped in\n");
    });
    block_on(ProjectionCleaner::new(fx.hooked(&hook)).delete(&resource(&fx.env, &l, 1))).unwrap();
    assert_eq!(std::fs::read(fx.p()).unwrap(), b"swapped in\n");
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
}

#[test]
fn a22_cleanup_crash_after_quarantine_move_completes_on_retry() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_i, sink) = fx.adopt(&["work"]);
    let l = p_locator(&sink, &fx.env);
    let hook = Hook::new().crash(ReplacePoint::AfterSettleMove, None);
    let cleaner = ProjectionCleaner::new(fx.hooked(&hook));
    let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        block_on(cleaner.delete(&resource(&fx.env, &l, 1)))
    }));
    assert!(crashed.is_err());
    assert!(!fx.p().exists(), "moved into the slot");
    block_on(fx.cleaner().delete(&resource(&fx.env, &l, 1))).unwrap();
    assert!(
        leftovers(&fx.tree()).is_empty(),
        "{:?}",
        leftovers(&fx.tree())
    );
    assert!(!fx.home.config_dir.join(".hm-quarantine").exists());
}

#[test]
fn a22_foreign_entry_in_quarantine_slot_is_put_back_never_deleted() {
    // R5: the cleaner's slot holds a foreign entry and the path is empty.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_i, sink) = fx.adopt(&["work"]);
    let l = p_locator(&sink, &fx.env);
    let slot = heimdall_localenv::projection::cleaner::slot_name(&l, 1).unwrap();
    let q = fx.home.config_dir.join(".hm-quarantine");
    std::fs::create_dir(&q).unwrap();
    std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::rename(fx.p(), fx.home.root.join("moved-away")).unwrap();
    write_mode(&q.join(&slot), b"foreign\n", 0o600);
    block_on(fx.cleaner().delete(&resource(&fx.env, &l, 1))).unwrap();
    assert_eq!(
        std::fs::read(fx.p()).unwrap(),
        b"foreign\n",
        "moved back, never deleted"
    );

    // F8d: a setup settlement finds a foreign entry in its slot.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_first, _s1, update) = fx.update_plan(&["work"], "lab");
    let p = step_of(&update, FileRole::ManagedSsh);
    let hook = Hook::new().crash(ReplacePoint::BeforeSettleMove, Some(p));
    let sink = Sink::default();
    assert!(apply_or_crash(fx.hooked(&hook), &update, &sink).is_none());
    let slot = sink
        .file_phases(p)
        .iter()
        .find_map(|ph| match ph {
            FilePhase::Settling { slot, .. } => Some(slot.clone()),
            _ => None,
        })
        .unwrap();
    let displaced = fx.home.config_dir.join(
        step_ref(&update, FileRole::ManagedSsh)
            .displaced_name
            .clone()
            .unwrap(),
    );
    let q = fx.home.config_dir.join(".hm-quarantine");
    std::fs::create_dir_all(&q).unwrap();
    std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::rename(&displaced, fx.home.root.join("old-p")).unwrap();
    write_mode(&q.join(&slot), b"foreign\n", 0o600);
    let out = restart(&fx, &update, &sink);
    assert!(
        matches!(out[0], ItemOutcome::Applied { .. }),
        "{out:?} {:?}",
        sink.kinds()
    );
    assert_eq!(std::fs::read(&displaced).unwrap(), b"foreign\n", "put back");
    assert!(sink.file_phases(p).iter().any(|ph| matches!(
        ph,
        FilePhase::SettleConflict {
            found: SettleConflictFound::Foreign,
            ..
        }
    )));
}

// --- settlement order (M2-R01), property over crash points ------------------------------

mod settlement_order {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

    /// 256 cases, a fixed seed unless `PROPTEST_RNG_SEED` is set (which reproduces a
    /// run), failures persisted beside this file (m02-plan §0).
    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x5534_4353_4554_544c);
        }
        c
    }

    /// Every hook point (with its step) a clean update reaches, from one reference run.
    fn points() -> &'static Vec<(ReplacePoint, u16)> {
        static POINTS: std::sync::OnceLock<Vec<(ReplacePoint, u16)>> = std::sync::OnceLock::new();
        POINTS.get_or_init(|| {
            let fx = Fx::new();
            std::fs::write(fx.user(), USER_TEXT).unwrap();
            let (_f, _s, update) = fx.update_plan(&["work"], "lab");
            let hook = Hook::new();
            apply_or_crash(fx.hooked(&hook), &update, &Sink::default())
                .unwrap()
                .unwrap();
            let mut seen = hook.seen();
            seen.dedup();
            seen
        })
    }

    /// No `file.settling` of a commit step's displaced entry comes before its item's
    /// `item.committed`, and none at all once the item rolls back.
    fn check_order(intent: &SetupIntent, sink: &Sink) -> Result<(), TestCaseError> {
        let mut committed = false;
        let mut rolling_back = false;
        for r in sink.receipts() {
            match r.local {
                Some(LocalReceipt::Item {
                    phase: ItemPhase::Committed { .. },
                    ..
                }) => committed = true,
                Some(LocalReceipt::Item {
                    phase: ItemPhase::RollingBack { .. },
                    ..
                }) => rolling_back = true,
                Some(LocalReceipt::File {
                    step,
                    phase:
                        FilePhase::Settling {
                            source: heimdall_domain::operation::SettleSource::Displaced,
                            ..
                        },
                }) if intent.files[usize::from(step)].commit => {
                    prop_assert!(
                        committed,
                        "settling before item.committed: {:?}",
                        sink.kinds()
                    );
                    prop_assert!(
                        !rolling_back,
                        "settling D after rolling_back: {:?}",
                        sink.kinds()
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn a22_settlement_never_precedes_item_committed(
            pick in 0usize..10_000,
            edit_user in any::<bool>(),
        ) {
            let fx = Fx::new();
            std::fs::write(fx.user(), USER_TEXT).unwrap();
            let (_f, _s, update) = fx.update_plan(&["work"], "lab");
            let p = step_of(&update, FileRole::ManagedSsh);
            let (point, step) = points()[pick % points().len()];
            let mut hook = Hook::new();
            if edit_user {
                hook = hook.run(ReplacePoint::AfterPostValidate, Some(p), appender(fx.user(), "Host x\n"));
            }
            let hook = hook.crash(point, Some(step));
            let sink = Sink::default();
            let first = apply_or_crash(fx.hooked(&hook), &update, &sink);
            check_order(&update, &sink)?;
            if first.is_none() {
                let out = restart(&fx, &update, &sink);
                prop_assert!(!matches!(out[0], ItemOutcome::Held { .. }), "{out:?} {:?}", sink.kinds());
            }
            check_order(&update, &sink)?;
            prop_assert!(sink.kinds().last().is_some_and(|k| k.starts_with("ssh:finished")));
        }
    }
}

// --- production code removes only inside the quarantine ---------------------------------

/// The source text with every `#[cfg(test)]` / `#[cfg(all(test, …))]` item and every
/// comment removed.
fn production_text(src: &str) -> String {
    let mut out = String::new();
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        if t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(all(test") {
            // Skip the attributed item: up to its matching closing brace.
            let mut depth = 0i32;
            let mut opened = false;
            for l in lines.by_ref() {
                for c in l.chars() {
                    match c {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if opened && depth <= 0 {
                    break;
                }
                if !opened && l.trim_end().ends_with(';') {
                    break;
                }
            }
            continue;
        }
        let code = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        out.push_str(code);
        out.push('\n');
    }
    out
}

/// The byte ranges of `impl QuarantineDir` blocks in `text`.
fn quarantine_impls(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find("impl QuarantineDir") {
        let start = from + i;
        let open = start + text[start..].find('{').unwrap();
        let mut depth = 0;
        let mut end = open;
        for (j, c) in text[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + j;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(start..end);
        from = end;
    }
    out
}

#[test]
fn production_code_never_unlinks_outside_quarantine() {
    const REMOVALS: &[&str] = &[
        "unlinkat",
        "remove_file",
        "remove_dir_all",
        "DeleteFileW",
        "FileDispositionInfoEx",
    ];
    // This crate's sources, through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
    let src = heimdall_testkit::repo::repo_path("crates/localenv/src");
    let mut files = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let path = e.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "rs") {
                files.push(path);
            }
        }
    }
    assert!(files.len() > 10, "the crate's sources were found");
    let mut allowed_hits = 0;
    for f in files {
        let text = production_text(&std::fs::read_to_string(&f).unwrap());
        let rel = f
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let impls = if rel == "sys/quarantine.rs" {
            quarantine_impls(&text)
        } else {
            Vec::new()
        };
        for needle in REMOVALS {
            let mut from = 0;
            while let Some(i) = text[from..].find(needle) {
                let at = from + i;
                assert!(
                    impls.iter().any(|r| r.contains(&at)),
                    "{rel}: `{needle}` outside sys::QuarantineDir"
                );
                allowed_hits += 1;
                from = at + needle.len();
            }
        }
    }
    assert!(allowed_hits > 0, "the quarantine's own removal was found");
}

#[test]
fn private_key_files_never_opened() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    // Private key files the owner keeps beside the public ones, unreadable (mode 000):
    // adoption needs only the public keys.
    for name in ["id_ed25519", "id_ecdsa"] {
        write_mode(
            &fx.ssh_dir().join(name),
            b"HEIMDALL_CANARY_U4C_PRIVATE\n",
            0o000,
        );
        write_mode(
            &fx.ssh_dir().join(format!("{name}.pub")),
            synthetic_public_key().as_bytes(),
            0o644,
        );
    }
    let (intent, _sink) = fx.adopt(&["work"]);
    let json = serde_json::to_string(&intent).unwrap();
    heimdall_testkit::assert_no_canary(&json);
    for name in ["id_ed25519", "id_ecdsa"] {
        let m = std::fs::metadata(fx.ssh_dir().join(name)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0, "untouched");
    }
    let key = step_ref(&intent, FileRole::Key);
    let written = std::fs::read_to_string(&key.path).unwrap();
    assert!(written.starts_with("ssh-ed25519 "));
    assert!(!written.contains("PRIVATE"));
}

// --- a fresh writer in a fresh process (M2-S05) -------------------------------------------

/// A `StageSink` over a JSON-lines file, so receipts survive the child process.
struct FileSink(PathBuf);

impl FileSink {
    fn read(path: &Path) -> Vec<StageReceipt> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn push(&self, r: &StageReceipt) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(r).unwrap()).unwrap();
        f.sync_all().unwrap();
    }
}

impl StageSink for FileSink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        self.push(&durable(receipt));
        Ok(())
    }

    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError> {
        self.push(&durable(&LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        }));
        Ok(())
    }
}

/// A `ProjectionWriter` that counts `preview` calls.
struct Counting {
    inner: LocalProjection,
    previews: std::sync::atomic::AtomicUsize,
}

impl ProjectionWriter for Counting {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, heimdall_app::ports::PreviewError> {
        self.previews
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.preview(spec, intent)
    }
    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        self.inner.apply(intent, sink)
    }
    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<heimdall_app::ports::ProjectionReconcile, ReconcileError> {
        self.inner.reconcile(intent, receipts, sink)
    }
    fn observe(
        &self,
        record: &ProjectionRecord,
        aliases: &[String],
    ) -> Vec<heimdall_contract::doctor::AliasObservation> {
        self.inner.observe(record, aliases)
    }
    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<heimdall_app::ports::HeldStep>, ReconcileError> {
        self.inner.observe_held(intent, receipts)
    }
}

const CHILD: &str = "HM_U4C_CHILD_DIR";

/// A hook that ends the process with `std::process::abort` (SIGABRT) at one point of
/// one step: a real process crash, with no unwinding and no destructor run.
struct AbortAt(ReplacePoint, u16);

impl ReplaceHook for AbortAt {
    fn at(&self, point: ReplacePoint, step: u16) {
        if point == self.0 && step == self.1 {
            std::process::abort();
        }
    }
}

/// Run `mode` (`apply`, `reconcile`, `crash_exchanged:<step>`) in a child process: this
/// test binary, re-executed for `child_process_writer_entry` only, with the scratch
/// directory in the environment. Returns the child's exit status.
fn run_child(fx: &Fx, dir: &Path, mode: &str) -> std::process::ExitStatus {
    std::fs::write(dir.join("mode"), mode).unwrap();
    std::fs::write(dir.join("root"), fx.home.root.to_str().unwrap()).unwrap();
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_process_writer_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
}

/// The child half of the fresh-writer tests. Without the variable it does nothing (it
/// is not a test of its own; the parent tests below assert what it did).
#[test]
fn child_process_writer_entry() {
    let Some(dir) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    quiet_crashes();
    let mode = std::fs::read_to_string(dir.join("mode")).unwrap();
    let root = PathBuf::from(std::fs::read_to_string(dir.join("root")).unwrap());
    let intent: SetupIntent =
        serde_json::from_str(&std::fs::read_to_string(dir.join("intent.json")).unwrap()).unwrap();
    intent.validate().unwrap();
    let paths = SshPaths::with_test_override(root.join("home"), root.join("etc-ssh"));
    let mut config = ProjectionConfig::new(paths, Platform::current(), root.join("config"));
    if let Some(step) = mode.strip_prefix("crash_exchanged:") {
        let step: u16 = step.trim().parse().unwrap();
        let hook = Hook::new().crash(ReplacePoint::BeforeReceipt("exchanged"), Some(step));
        let h: Arc<dyn ReplaceHook> = hook;
        config.hook = Some(h);
    }
    if let Some(rest) = mode.strip_prefix("abort:") {
        let (kind, step) = rest.trim().split_once(':').unwrap();
        let point = match kind {
            "staged" => ReplacePoint::BeforeReceipt("staged"),
            "commit" => ReplacePoint::BeforeCommit,
            other => panic!("unknown abort point {other}"),
        };
        let h: Arc<dyn ReplaceHook> = Arc::new(AbortAt(point, step.parse().unwrap()));
        config.hook = Some(h);
    }
    let writer = Counting {
        inner: LocalProjection::new(config),
        previews: std::sync::atomic::AtomicUsize::new(0),
    };
    let receipts = dir.join("receipts.jsonl");
    let mut sink = FileSink(receipts.clone());
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if mode.starts_with("reconcile") {
            let rx = FileSink::read(&receipts);
            writer.reconcile(&intent, &rx, &mut sink).map(|r| r.items)
        } else {
            writer.apply(&intent, &mut sink).map(|r| r.items)
        }
    }));
    let text = match outcome {
        Ok(Ok(items)) => format!("{items:?}"),
        Ok(Err(e)) => format!("error {e:?}"),
        Err(_) => "crashed".to_owned(),
    };
    let previews = writer.previews.load(std::sync::atomic::Ordering::SeqCst);
    std::fs::write(
        dir.join("outcome"),
        format!("{text}\npreviews={previews}\n"),
    )
    .unwrap();
}

fn child_outcome(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("outcome")).unwrap()
}

#[test]
fn fresh_writer_executes_intent_without_preview() {
    // First adoption, update, rollback: each planned by one writer, executed by a fresh
    // writer in a child process after the store's JSON round trip.
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let mut record = None;
    let mut first: Option<SetupIntent> = None;
    for (n, step) in ["adopt", "update", "rollback"].iter().enumerate() {
        let plan = match *step {
            "adopt" => fx.preview(&fx.spec(&["work", "lab"], None), &Fx::apply_intent()),
            "update" => {
                let mut spec = fx.spec(&[], record.clone());
                spec.aliases = first_aliases(first.as_ref().unwrap(), &fx, &["work", "lab"]);
                spec.aliases.push(fx.alias("ops"));
                fx.preview(&spec, &Fx::apply_intent())
            }
            _ => fx.preview(&fx.spec(&[], record.clone()), &Fx::rollback_intent()),
        };
        let intent = round_trip(&plan.intent());
        let dir = fx.home.scratch().subdir("child").unwrap();
        std::fs::write(
            dir.join("intent.json"),
            serde_json::to_string(&intent).unwrap(),
        )
        .unwrap();
        let status = run_child(&fx, &dir, "apply");
        assert!(status.success(), "{step}: {status:?}");
        let out = child_outcome(&dir);
        assert!(out.starts_with("[Applied"), "{step}: {out}");
        assert!(out.contains("previews=0"), "{step}: {out}");
        for s in &intent.files {
            if let Target::Present { sha256 } = &s.target {
                assert_eq!(
                    &Sha256Hex::of(&std::fs::read(&s.path).unwrap()),
                    sha256,
                    "{step} {}",
                    s.path
                );
            }
        }
        // The parent's record of what the child committed (identities from receipts).
        let rx = FileSink::read(&dir.join("receipts.jsonl"));
        let mut files = record
            .as_ref()
            .and_then(|r: &ProjectionRecord| r.items.get(&ProjectionItem::Ssh))
            .map(|r| r.files.clone())
            .unwrap_or_default();
        for (i, s) in intent.files.iter().enumerate() {
            let staged = rx.iter().find_map(|r| match &r.local {
                Some(LocalReceipt::File {
                    step,
                    phase: FilePhase::Staged { identity },
                }) if usize::from(*step) == i => Some(identity.clone()),
                _ => None,
            });
            files.retain(|l| l.path != s.path);
            if let (
                Some(identity),
                Target::Present { sha256 },
                FileRole::ManagedSsh | FileRole::Key,
            ) = (staged, &s.target, s.role)
            {
                files.push(ProjectionLocator {
                    role: s.role,
                    path: s.path.clone(),
                    identity,
                    sha256: sha256.clone(),
                });
            }
        }
        record = Some(ProjectionRecord {
            environment: fx.env.clone(),
            items: [(
                ProjectionItem::Ssh,
                heimdall_domain::projection::ItemRecord {
                    generation: u64::try_from(n + 1).unwrap(),
                    files,
                    aliases: Vec::new(),
                    operation: OperationId::from_random_bytes([1; 16]),
                    committed_at: heimdall_contract::Timestamp::now(),
                },
            )]
            .into_iter()
            .collect(),
        });
        if first.is_none() {
            first = Some(intent);
        }
    }
    assert_eq!(
        std::fs::read_to_string(fx.user()).unwrap(),
        USER_TEXT,
        "rolled back exactly"
    );
}

#[test]
fn fresh_writer_creates_absent_ssh_config() {
    for crash in [false, true] {
        let fx = Fx::new();
        std::fs::remove_file(fx.user()).unwrap();
        let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
        let intent = round_trip(&plan.intent());
        let u = step_of(&intent, FileRole::UserSsh);
        let dir = fx.home.scratch().subdir("child").unwrap();
        std::fs::write(
            dir.join("intent.json"),
            serde_json::to_string(&intent).unwrap(),
        )
        .unwrap();
        if crash {
            assert!(run_child(&fx, &dir, &format!("crash_exchanged:{u}")).success());
            assert!(child_outcome(&dir).starts_with("crashed"));
            // A third fresh process recovers through C2.
            assert!(run_child(&fx, &dir, "reconcile").success());
        } else {
            assert!(run_child(&fx, &dir, "apply").success());
        }
        let out = child_outcome(&dir);
        assert!(out.starts_with("[Applied"), "{out}");
        assert!(out.contains("previews=0"));
        let user = step_ref(&intent, FileRole::UserSsh);
        let Target::Present { sha256 } = &user.target else {
            unreachable!()
        };
        assert_eq!(&Sha256Hex::of(&std::fs::read(fx.user()).unwrap()), sha256);
        let mode = std::fs::metadata(fx.user()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        if crash {
            let rx = FileSink::read(&dir.join("receipts.jsonl"));
            let kinds: Vec<String> = rx
                .iter()
                .filter_map(|r| r.local.as_ref())
                .map(kind_of)
                .collect();
            assert_eq!(
                count(&kinds, &format!("{u}:exchanged")),
                1,
                "C2 recorded it: {kinds:?}"
            );
        }
    }
}

/// ADR-0007 §12.17 item 8: the commit-point crash runs once as a real process abort,
/// besides the in-process unwinds of the other crash tests (which stay labelled as
/// unwinds). The child process running `apply` calls `std::process::abort` at the
/// hook, so it dies by SIGABRT with nothing unwound; a second, fresh child process
/// reconciles from the durable receipts. Two points of the first adoption: after P and
/// before B's `file.staged` (row F0x, the commit step's S unrecorded), and at the
/// commit point after B's post-validation, before `item.committed` (row T1).
#[test]
fn a22_first_adoption_commit_point_crash_as_a_process_abort_reconciles() {
    use std::os::unix::process::ExitStatusExt as _;
    for kind in ["staged", "commit"] {
        let fx = Fx::new();
        std::fs::write(fx.user(), USER_TEXT).unwrap();
        let plan = fx.preview(&fx.spec(&["work"], None), &Fx::apply_intent());
        let intent = round_trip(&plan.intent());
        let u = step_of(&intent, FileRole::UserSsh);
        let dir = fx.home.scratch().subdir("child").unwrap();
        std::fs::write(
            dir.join("intent.json"),
            serde_json::to_string(&intent).unwrap(),
        )
        .unwrap();
        let status = run_child(&fx, &dir, &format!("abort:{kind}:{u}"));
        assert_eq!(
            status.signal(),
            Some(6),
            "{kind}: a process abort (SIGABRT)"
        );
        assert!(
            !dir.join("outcome").exists(),
            "{kind}: the child died at the hook"
        );
        let rx = FileSink::read(&dir.join("receipts.jsonl"));
        let kinds: Vec<String> = rx
            .iter()
            .filter_map(|r| r.local.as_ref())
            .map(kind_of)
            .collect();
        assert!(
            !kinds.contains(&"ssh:committed".to_owned()),
            "{kind}: {kinds:?}"
        );
        assert!(run_child(&fx, &dir, "reconcile").success(), "{kind}");
        let out = child_outcome(&dir);
        assert!(out.starts_with("[Applied"), "{kind}: {out}");
        assert!(out.contains("previews=0"), "{kind}: {out}");
        let Target::Present { sha256 } = &step_ref(&intent, FileRole::UserSsh).target else {
            unreachable!()
        };
        assert_eq!(&Sha256Hex::of(&std::fs::read(fx.user()).unwrap()), sha256);
        assert!(
            leftovers(&fx.tree()).is_empty(),
            "{kind}: {:?}",
            leftovers(&fx.tree())
        );
    }
}

// --- the generated domain on the filesystem (ADR-0007 §5.7 properties) ------------------

mod generated {
    use super::*;
    use heimdall_domain::operation::{PostVerdict, RestoreCause, SettleSource, SettledDisposition};
    use heimdall_domain::projection::{Base, FileIdentity, StepContent};
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            // Three shapes are drawn uniformly: about 256 cases each.
            cases: 768,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x5534_4347_454e_4f42);
        }
        c
    }

    /// The step shape a cell builds (ADR-0007 §12.17 item 8: the generated domain
    /// covers the `git_lock` and removal shapes too).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Shape {
        /// The user-file step (a replace, or a create with `create`).
        User,
        /// The `git_lock` step K, with B_git after it at its start.
        GitLock,
        /// The cleaner's removal of a locator (rows R1–R6).
        Removal,
    }

    /// Where a recorded entity is placed, and whether its content changed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum At {
        Nowhere,
        Path,
        Aside,
        Slot,
    }

    /// What fills a name no recorded entity holds.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Filler {
        Empty,
        File,
        HardLink,
        Symlink,
        Dir,
        Fifo,
    }

    /// A receipt history: phases written in order for the single step, with the item
    /// receipts interleaved.
    #[derive(Debug, Clone, Copy)]
    enum H {
        None,
        Staged,
        Validated,
        Exchanged,
        PostValid,
        Committed,
        CommittedSettling,
        CommittedSettled,
        Mismatch,
        MismatchRestoreStarted,
        MismatchRestored,
        MismatchRestoredSettling,
        RollingBack,
        RollingBackRestoreStarted,
        RollingBackRestored,
        AbortSettling,
        AbortSettled,
    }

    const HISTORIES: &[H] = &[
        H::None,
        H::Staged,
        H::Validated,
        H::Exchanged,
        H::PostValid,
        H::Committed,
        H::CommittedSettling,
        H::CommittedSettled,
        H::Mismatch,
        H::MismatchRestoreStarted,
        H::MismatchRestored,
        H::MismatchRestoredSettling,
        H::RollingBack,
        H::RollingBackRestoreStarted,
        H::RollingBackRestored,
        H::AbortSettling,
        H::AbortSettled,
    ];

    #[derive(Debug, Clone)]
    struct Cell {
        shape: Shape,
        create: bool,
        history: H,
        s: (At, bool),
        v: (At, bool),
        d: At,
        fill: [Filler; 3],
        unobservable: bool,
        crash_after: usize,
    }

    fn cell() -> impl Strategy<Value = Cell> {
        let at = prop_oneof![
            Just(At::Nowhere),
            Just(At::Path),
            Just(At::Aside),
            Just(At::Slot)
        ];
        let filler = prop_oneof![
            Just(Filler::Empty),
            Just(Filler::Empty),
            Just(Filler::File),
            Just(Filler::HardLink),
            Just(Filler::Symlink),
            Just(Filler::Dir),
            Just(Filler::Fifo),
        ];
        let shape = prop_oneof![
            Just(Shape::User),
            Just(Shape::GitLock),
            Just(Shape::Removal)
        ];
        (
            shape,
            any::<bool>(),
            0..HISTORIES.len(),
            (at.clone(), any::<bool>()),
            (at.clone(), any::<bool>()),
            at,
            [filler.clone(), filler.clone(), filler],
            prop::bool::weighted(0.05),
            0usize..12,
        )
            .prop_map(
                |(shape, create, h, s, v, d, fill, unobservable, crash_after)| Cell {
                    shape,
                    create,
                    history: HISTORIES[h],
                    s,
                    v,
                    d,
                    fill,
                    unobservable,
                    crash_after,
                },
            )
    }

    const BASE: &[u8] = b"Host personal\n    User me\n";

    struct Built {
        _dir: tempfile::TempDir,
        root: PathBuf,
        intent: SetupIntent,
        receipts: Vec<StageReceipt>,
        /// The intent's commit step.
        commit: u16,
        /// For the removal shape: the locator and generation the cleaner removes.
        locator: Option<(ProjectionLocator, u64)>,
    }

    fn identity_of(path: &Path) -> FileIdentity {
        let m = std::fs::symlink_metadata(path).unwrap();
        FileIdentity::Unix {
            dev: m.dev(),
            ino: m.ino(),
            birth: birth_of(path),
        }
    }

    #[cfg(target_os = "macos")]
    fn birth_of(path: &Path) -> Option<i128> {
        let m = std::fs::symlink_metadata(path).ok()?;
        let t = m.created().ok()?;
        let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
        i128::try_from(d.as_nanos()).ok()
    }

    #[cfg(not(target_os = "macos"))]
    fn birth_of(path: &Path) -> Option<i128> {
        let m = std::fs::symlink_metadata(path).ok()?;
        let t = m.created().ok()?;
        let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
        i128::try_from(d.as_nanos()).ok()
    }

    fn file(path: &Path, bytes: &[u8]) {
        write_mode(path, bytes, 0o600);
    }

    /// Build the cell's entries and receipts. `None` when the placement is not a
    /// buildable observation (normalization would reject it: one identity at two
    /// names is impossible by construction here, so only shape rules remain).
    fn build(c: &Cell) -> Option<Built> {
        match c.shape {
            Shape::User => build_user(c),
            Shape::GitLock => build_lock(c),
            Shape::Removal => build_removal(c),
        }
    }

    /// Fill each of `names` that no recorded entity holds with the cell's filler.
    fn fill_names(c: &Cell, tmp: &Path, q: &Path, names: &[(At, PathBuf)], used: &[At]) {
        for (i, (at, path)) in names.iter().enumerate() {
            if used.contains(at) {
                continue;
            }
            if *at == At::Slot && c.fill[i] != Filler::Empty && !q.exists() {
                std::fs::create_dir(q).unwrap();
                std::fs::set_permissions(q, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            match c.fill[i] {
                Filler::Empty => {}
                Filler::File => file(path, b"foreign\n"),
                Filler::HardLink => {
                    let other = tmp.join(format!("link-src-{i}"));
                    file(&other, b"foreign linked\n");
                    std::fs::hard_link(&other, path).unwrap();
                }
                Filler::Symlink => std::os::unix::fs::symlink("/scratch/elsewhere", path).unwrap(),
                Filler::Dir => std::fs::create_dir(path).unwrap(),
                Filler::Fifo => {
                    let ok = std::process::Command::new("mkfifo")
                        .arg(path)
                        .status()
                        .unwrap();
                    assert!(ok.success());
                }
            }
        }
    }

    /// Put `bytes` at `at` (one of `names`), or nowhere (created outside the scratch
    /// directory, so its identity is recorded but no name holds it); in place-modified
    /// when `modified`. `false` when the name is already taken.
    /// A cell's scratch directory, its quarantine and its names.
    struct Names<'a> {
        tmp: &'a Path,
        q: &'a Path,
        at: &'a [(At, PathBuf)],
    }

    fn place_at(
        n: &Names<'_>,
        label: &str,
        at: At,
        bytes: &[u8],
        modified: bool,
        used: &mut Vec<At>,
    ) -> Option<FileIdentity> {
        let (tmp, q, names) = (n.tmp, n.q, n.at);
        let Some((_, path)) = names.iter().find(|(a, _)| *a == at) else {
            let elsewhere = tmp.join(label);
            file(&elsewhere, bytes);
            return Some(identity_of(&elsewhere));
        };
        if used.contains(&at) {
            return None;
        }
        used.push(at);
        if at == At::Slot && !q.exists() {
            std::fs::create_dir(q).unwrap();
            std::fs::set_permissions(q, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        file(path, bytes);
        let id = identity_of(path);
        if modified {
            write_in_place(path, b"modified in place\n");
        }
        Some(id)
    }

    /// The `git_lock` step K (rows K0–K4 and its settlement), with B_git after it at
    /// its start (no receipt, nothing at its names). The path is the lock name, the
    /// aside K's random staged name. Histories: none, `staged`, a settlement from the
    /// staged name or from the lock (open, or `settled`), and `settle_conflict`.
    fn build_lock(c: &Cell) -> Option<Built> {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("git");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let q = root.join(".hm-quarantine");
        let holder = heimdall_domain::projection::lock_holder_line(1, [7; 16]);
        let k_staged = format!(".config.lock.hm-1-{}", "ef".repeat(16));
        let marker = heimdall_sshconf::render::MarkerId::parse("hm-0123456789abcdef").unwrap();
        let p_git =
            heimdall_sshconf::render::RenderPath::unix(Path::new("/scratch/gitconfig")).unwrap();
        let block = heimdall_sshconf::render::rendered_git_include_block(
            &marker,
            &p_git,
            heimdall_sshconf::render::Newline::Lf,
        )
        .unwrap();
        let k = FileStep {
            role: FileRole::GitLock,
            path: root.join("config.lock").to_str().unwrap().to_owned(),
            base: Base::Absent,
            target: Target::Absent,
            content: heimdall_domain::projection::Rendered::from_renderer(holder.clone())
                .into_lock_holder(),
            commit: false,
            staged_name: Some(k_staged.clone()),
            displaced_name: None,
        };
        let b = FileStep {
            role: FileRole::GitInclude,
            path: root.join("config").to_str().unwrap().to_owned(),
            base: Base::Absent,
            target: Target::Present {
                sha256: Sha256Hex::of(block.bytes()),
            },
            content: block.into_splice(0, 0, None),
            commit: true,
            staged_name: Some(format!(".config.hm-1-{}", "cd".repeat(16))),
            displaced_name: None,
        };
        let intent = SetupIntent {
            plan_digest: heimdall_contract::setup::PlanDigest::from_sha256([9; 32]),
            intent: PreviewIntent::Apply { include_git: true },
            generation: 1,
            approval: None,
            consent: heimdall_domain::projection::ConsentRecord::default(),
            files: vec![k, b],
        };
        intent.validate().unwrap();
        let slot = "cd".repeat(16);
        let names = [
            (At::Path, root.join("config.lock")),
            (At::Aside, root.join(&k_staged)),
            (At::Slot, q.join(&slot)),
        ];
        let mut used = Vec::new();
        let k_id = place_at(
            &Names {
                tmp: tmp.path(),
                q: &q,
                at: &names,
            },
            "K",
            c.s.0,
            &holder,
            c.s.1,
            &mut used,
        )?;
        place_at(
            &Names {
                tmp: tmp.path(),
                q: &q,
                at: &names,
            },
            "D",
            c.d,
            b"another writer\n",
            false,
            &mut used,
        )?;
        fill_names(c, tmp.path(), &q, &names, &used);
        let file_r = |phase: FilePhase| LocalReceipt::File { step: 0, phase };
        let settling = |source: SettleSource, name: &str| {
            file_r(FilePhase::Settling {
                source,
                name: name.to_owned(),
                expected: k_id.clone(),
                expected_sha256: Sha256Hex::of(&holder),
                slot: slot.clone(),
            })
        };
        let staged = file_r(FilePhase::Staged {
            identity: k_id.clone(),
        });
        let settled = file_r(FilePhase::Settled {
            disposition: SettledDisposition::Quarantined,
        });
        let r: Vec<LocalReceipt> = match (c.history as usize) % 7 {
            0 => vec![],
            1 => vec![staged],
            2 => vec![staged, settling(SettleSource::Staged, &k_staged)],
            3 => vec![staged, settling(SettleSource::Staged, &k_staged), settled],
            4 => vec![staged, settling(SettleSource::Path, "config.lock")],
            5 => vec![staged, settling(SettleSource::Path, "config.lock"), settled],
            _ => vec![
                staged,
                file_r(FilePhase::SettleConflict {
                    found: SettleConflictFound::Foreign,
                    kept: Vec::new(),
                }),
            ],
        };
        Some(Built {
            _dir: tmp,
            root,
            intent,
            receipts: r.iter().map(durable).collect(),
            commit: 1,
            locator: None,
        })
    }

    /// The cleaner's removal of P's locator L at generation 1 (rows R1–R6): L at the
    /// path, in the locator's slot or nowhere, with its content or modified, and
    /// foreign entries at the free names. The cleaner writes no receipt.
    fn build_removal(c: &Cell) -> Option<Built> {
        if c.s.0 == At::Aside || c.d == At::Aside {
            return None;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cfg");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let q = root.join(".hm-quarantine");
        let bytes = b"# managed\nHost work\n".to_vec();
        // L's identity first: the slot name is derived from the locator.
        let staging = tmp.path().join("l");
        file(&staging, &bytes);
        let locator = ProjectionLocator {
            role: FileRole::ManagedSsh,
            path: root.join("ssh_config").to_str().unwrap().to_owned(),
            identity: identity_of(&staging),
            sha256: Sha256Hex::of(&bytes),
        };
        let slot = heimdall_localenv::projection::cleaner::slot_name(&locator, 1).unwrap();
        let names = [
            (At::Path, root.join("ssh_config")),
            (At::Aside, tmp.path().join("no-aside")),
            (At::Slot, q.join(&slot)),
        ];
        let mut used = vec![At::Aside];
        if let Some((_, path)) = names.iter().find(|(a, _)| *a == c.s.0) {
            used.push(c.s.0);
            if c.s.0 == At::Slot {
                std::fs::create_dir(&q).unwrap();
                std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            std::fs::rename(&staging, path).unwrap();
            if c.s.1 {
                write_in_place(path, b"modified in place\n");
            }
        }
        place_at(
            &Names {
                tmp: tmp.path(),
                q: &q,
                at: &names,
            },
            "D",
            c.d,
            b"another writer\n",
            false,
            &mut used,
        )?;
        fill_names(c, tmp.path(), &q, &names, &used);
        let intent = SetupIntent {
            plan_digest: heimdall_contract::setup::PlanDigest::from_sha256([9; 32]),
            intent: PreviewIntent::Rollback {
                keep_key_files: true,
                items: [ProjectionItem::Ssh].into_iter().collect(),
            },
            generation: 2,
            approval: None,
            consent: heimdall_domain::projection::ConsentRecord::default(),
            files: vec![FileStep {
                role: FileRole::ManagedSsh,
                path: locator.path.clone(),
                base: Base::Present {
                    sha256: locator.sha256.clone(),
                },
                target: Target::Absent,
                content: StepContent::absent(),
                commit: false,
                staged_name: None,
                displaced_name: None,
            }],
        };
        intent.validate().unwrap();
        Some(Built {
            _dir: tmp,
            root,
            intent,
            receipts: Vec::new(),
            commit: 0,
            locator: Some((locator, 1)),
        })
    }

    /// The user-file step (a replace, or a create).
    fn build_user(c: &Cell) -> Option<Built> {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ssh");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let q = root.join(".hm-quarantine");
        let marker = heimdall_sshconf::render::MarkerId::parse("hm-0123456789abcdef").unwrap();
        let target_path =
            heimdall_sshconf::render::RenderPath::unix(Path::new("/scratch/p")).unwrap();
        let block = heimdall_sshconf::render::rendered_include_block(
            &marker,
            &target_path,
            heimdall_sshconf::render::Newline::Lf,
        )
        .unwrap();
        let mut target = block.bytes().to_vec();
        if !c.create {
            target.extend_from_slice(BASE);
        }
        let staged = format!(".config.hm-1-{}", "ab".repeat(16));
        let step = FileStep {
            role: FileRole::UserSsh,
            path: root.join("config").to_str().unwrap().to_owned(),
            base: if c.create {
                Base::Absent
            } else {
                Base::Present {
                    sha256: Sha256Hex::of(BASE),
                }
            },
            target: Target::Present {
                sha256: Sha256Hex::of(&target),
            },
            content: block.into_splice(0, 0, None),
            commit: true,
            staged_name: Some(staged.clone()),
            displaced_name: (!c.create).then(|| staged.clone()),
        };
        let intent = SetupIntent {
            plan_digest: heimdall_contract::setup::PlanDigest::from_sha256([9; 32]),
            intent: PreviewIntent::Apply { include_git: false },
            generation: 1,
            approval: None,
            consent: heimdall_domain::projection::ConsentRecord::default(),
            files: vec![step],
        };
        intent.validate().unwrap();
        let slot = "cd".repeat(16);
        let name_of = |at: At| match at {
            At::Path => Some(root.join("config")),
            At::Aside => Some(root.join(&staged)),
            At::Slot => Some(q.join(&slot)),
            At::Nowhere => None,
        };
        // Entities: S (target bytes), V (base bytes, replace only), D (another file).
        let mut ids: BTreeMap<&str, FileIdentity> = BTreeMap::new();
        let mut used: Vec<At> = Vec::new();
        let place = |label: &'static str,
                     at: At,
                     bytes: &[u8],
                     modified: bool,
                     used: &mut Vec<At>,
                     ids: &mut BTreeMap<&str, FileIdentity>| {
            let Some(path) = name_of(at) else {
                // Recorded but nowhere: create it elsewhere for its identity, then drop
                // it, so the receipts name an entity that is gone.
                let elsewhere = tmp.path().join(label);
                file(&elsewhere, bytes);
                ids.insert(label, identity_of(&elsewhere));
                return true;
            };
            if used.contains(&at) {
                return false;
            }
            used.push(at);
            if at == At::Slot && !q.exists() {
                std::fs::create_dir(&q).unwrap();
                std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            file(&path, bytes);
            ids.insert(label, identity_of(&path));
            if modified {
                write_in_place(&path, b"modified in place\n");
            }
            true
        };
        if !place("S", c.s.0, &target, c.s.1, &mut used, &mut ids) {
            return None;
        }
        if !c.create && !place("V", c.v.0, BASE, c.v.1, &mut used, &mut ids) {
            return None;
        }
        if !place("D", c.d, b"another writer\n", false, &mut used, &mut ids) {
            return None;
        }
        // Fillers at names nothing recorded holds.
        for (i, at) in [At::Path, At::Aside, At::Slot].into_iter().enumerate() {
            if used.contains(&at) {
                continue;
            }
            let path = name_of(at).unwrap();
            if at == At::Slot && c.fill[i] != Filler::Empty && !q.exists() {
                std::fs::create_dir(&q).unwrap();
                std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            match c.fill[i] {
                Filler::Empty => {}
                Filler::File => file(&path, b"foreign\n"),
                Filler::HardLink => {
                    let other = tmp.path().join(format!("link-src-{i}"));
                    file(&other, b"foreign linked\n");
                    std::fs::hard_link(&other, &path).unwrap();
                }
                Filler::Symlink => std::os::unix::fs::symlink("/scratch/elsewhere", &path).unwrap(),
                Filler::Dir => std::fs::create_dir(&path).unwrap(),
                Filler::Fifo => {
                    let ok = std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap();
                    assert!(ok.success());
                }
            }
        }
        // Receipts.
        let s_id = ids.get("S").cloned().unwrap();
        let v_id = ids.get("V").cloned();
        let d_id = ids.get("D").cloned().unwrap();
        let mut r: Vec<LocalReceipt> = Vec::new();
        let file_r = |phase: FilePhase| LocalReceipt::File { step: 0, phase };
        let item_r = |phase: ItemPhase| LocalReceipt::Item {
            item: ProjectionItem::Ssh,
            phase,
        };
        let h = c.history;
        let reach = |n: u8| -> bool {
            let level = match h {
                H::None => 0,
                H::Staged => 1,
                H::Validated | H::AbortSettling | H::AbortSettled => 2,
                H::Exchanged => 3,
                _ => 4,
            };
            level >= n
        };
        if reach(1) {
            r.push(file_r(FilePhase::Staged {
                identity: s_id.clone(),
            }));
        }
        if reach(2) {
            r.push(file_r(FilePhase::Validated { base: v_id.clone() }));
        }
        if reach(3) {
            r.push(file_r(FilePhase::Exchanged));
        }
        let mismatch = matches!(
            h,
            H::Mismatch
                | H::MismatchRestoreStarted
                | H::MismatchRestored
                | H::MismatchRestoredSettling
        );
        if reach(4) {
            r.push(file_r(if mismatch {
                FilePhase::PostValidated {
                    verdict: PostVerdict::Mismatch,
                    observed: Some(d_id.clone()),
                }
            } else {
                FilePhase::PostValidated {
                    verdict: PostVerdict::Valid,
                    observed: None,
                }
            }));
        }
        let settling = |source: SettleSource, name: &str, id: &FileIdentity, sha: Sha256Hex| {
            file_r(FilePhase::Settling {
                source,
                name: name.to_owned(),
                expected: id.clone(),
                expected_sha256: sha,
                slot: slot.clone(),
            })
        };
        let tsha = Sha256Hex::of(&target);
        match h {
            H::Committed | H::CommittedSettling | H::CommittedSettled => {
                r.push(item_r(ItemPhase::Committed { generation: 1 }));
                if !matches!(h, H::Committed) {
                    if c.create {
                        r.push(file_r(FilePhase::Settled {
                            disposition: SettledDisposition::NothingDisplaced,
                        }));
                    } else {
                        let v = v_id.clone()?;
                        r.push(settling(
                            SettleSource::Displaced,
                            &staged,
                            &v,
                            Sha256Hex::of(BASE),
                        ));
                        if matches!(h, H::CommittedSettled) {
                            r.push(file_r(FilePhase::Settled {
                                disposition: SettledDisposition::Quarantined,
                            }));
                        }
                    }
                }
            }
            H::MismatchRestoreStarted | H::MismatchRestored | H::MismatchRestoredSettling => {
                if c.create {
                    return None;
                }
                r.push(file_r(FilePhase::RestoreStarted {
                    cause: RestoreCause::FileMismatch,
                }));
                if !matches!(h, H::MismatchRestoreStarted) {
                    r.push(file_r(FilePhase::Restored));
                }
                if matches!(h, H::MismatchRestoredSettling) {
                    r.push(settling(SettleSource::Staged, &staged, &s_id, tsha.clone()));
                }
            }
            H::Mismatch if c.create => return None,
            H::RollingBack | H::RollingBackRestoreStarted | H::RollingBackRestored => {
                r.push(item_r(ItemPhase::RollingBack {
                    reason: ConflictKind::ManagedFileEdited,
                }));
                if !matches!(h, H::RollingBack) {
                    r.push(file_r(FilePhase::RestoreStarted {
                        cause: RestoreCause::TransactionCheck,
                    }));
                }
                if matches!(h, H::RollingBackRestored) {
                    if c.create {
                        r.push(settling(SettleSource::Path, "config", &s_id, tsha.clone()));
                        r.push(file_r(FilePhase::Settled {
                            disposition: SettledDisposition::Quarantined,
                        }));
                    }
                    r.push(file_r(FilePhase::Restored));
                }
            }
            H::AbortSettling | H::AbortSettled => {
                r.push(settling(SettleSource::Staged, &staged, &s_id, tsha.clone()));
                if matches!(h, H::AbortSettled) {
                    r.push(file_r(FilePhase::Settled {
                        disposition: SettledDisposition::Quarantined,
                    }));
                }
            }
            _ => {}
        }
        Some(Built {
            _dir: tmp,
            root,
            intent,
            receipts: r.iter().map(durable).collect(),
            commit: 0,
            locator: None,
        })
    }

    /// Every regular entry under `root` (the quarantine included): identity → bytes.
    /// Foreign non-regular entries are recorded by name and kind.
    /// Regular entries by identity, and foreign non-regular entries by kind.
    type Inventory = (BTreeMap<(u64, u64), Vec<u8>>, BTreeMap<String, char>);

    fn inventory(root: &Path) -> Inventory {
        let mut files = BTreeMap::new();
        let mut others = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd {
                let e = e.unwrap();
                let m = std::fs::symlink_metadata(e.path()).unwrap();
                let ft = m.file_type();
                if ft.is_dir() {
                    if e.file_name() == ".hm-quarantine" {
                        stack.push(e.path());
                    } else {
                        others.insert(format!("d::{}", m.ino()), 'd');
                    }
                } else if ft.is_file() {
                    files.insert((m.dev(), m.ino()), std::fs::read(e.path()).unwrap());
                } else {
                    let kind = if ft.is_symlink() { 'l' } else { 'p' };
                    // Foreign entries move only back or to a conflict name (put_back,
                    // keep_as_conflict): compared by kind and link target, not name.
                    let target = std::fs::read_link(e.path())
                        .map(|t| t.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let key = format!("{kind}:{target}:{}", m.ino());
                    others.insert(key, kind);
                }
            }
        }
        (files, others)
    }

    /// Entries a durable `file.settled` (or the settlement it closes) allows removing:
    /// the identity and digest a `file.settling` recorded, followed by `file.settled`.
    fn removable(receipts: &[StageReceipt]) -> Vec<((u64, u64), Sha256Hex)> {
        let mut out = Vec::new();
        let mut open: Option<((u64, u64), Sha256Hex)> = None;
        for r in receipts {
            match &r.local {
                Some(LocalReceipt::File {
                    phase:
                        FilePhase::Settling {
                            expected: FileIdentity::Unix { dev, ino, .. },
                            expected_sha256,
                            ..
                        },
                    ..
                }) => open = Some(((*dev, *ino), expected_sha256.clone())),
                Some(LocalReceipt::File {
                    phase: FilePhase::Settled { .. },
                    ..
                }) => out.extend(open.take()),
                _ => {}
            }
        }
        out
    }

    fn run(
        built: &Built,
        sink: &Sink,
        crash_after: Option<usize>,
    ) -> Option<Result<Vec<ItemOutcome>, ReconcileError>> {
        let paths = SshPaths::with_test_override(built.root.clone(), built.root.clone());
        let mut config = ProjectionConfig::new(paths, Platform::current(), built.root.clone());
        if let Some(n) = crash_after {
            let count = Arc::new(Mutex::new(0usize));
            struct Counter(Arc<Mutex<usize>>, usize);
            impl ReplaceHook for Counter {
                fn at(&self, _: ReplacePoint, _: u16) {
                    let mut c = self.0.lock().unwrap_or_else(PoisonError::into_inner);
                    *c += 1;
                    if *c > self.1 {
                        std::panic::panic_any(Crash);
                    }
                }
            }
            let h: Arc<dyn ReplaceHook> = Arc::new(Counter(count, n));
            config.hook = Some(h);
        }
        if let Some((locator, generation)) = &built.locator {
            // The removal shape is the cleaner's: it writes no receipt, and its result
            // is `Ok` (absent, or left with a finding) or a retryable error (R6, `?`).
            return match std::panic::catch_unwind(AssertUnwindSafe(|| {
                heimdall_localenv::projection::cleaner::delete_locator(
                    &config,
                    locator,
                    *generation,
                )
            })) {
                Ok(_) => Some(Ok(Vec::new())),
                Err(p) if p.is::<Crash>() => None,
                Err(p) => std::panic::resume_unwind(p),
            };
        }
        reconcile_or_crash(config, &built.intent, sink)
    }

    fn check(
        built: &Built,
        before: &Inventory,
        sink: &Sink,
        outcome: &[ItemOutcome],
    ) -> Result<(), TestCaseError> {
        let after = inventory(&built.root);
        let mut allowed = removable(&sink.receipts());
        // The cleaner's ownership rule: the locator's identity and digest.
        if let Some((
            ProjectionLocator {
                identity: FileIdentity::Unix { dev, ino, .. },
                sha256,
                ..
            },
            _,
        )) = &built.locator
        {
            allowed.push(((*dev, *ino), sha256.clone()));
        }
        // 2, 3: no loss; foreign and modified content preserved.
        for (id, bytes) in &before.0 {
            match after.0.get(id) {
                Some(b) => prop_assert_eq!(b, bytes, "entry {:?} changed", id),
                None => prop_assert!(
                    allowed
                        .iter()
                        .any(|(i, sha)| i == id && Sha256Hex::of(bytes) == *sha),
                    "entry {:?} removed without a durable settled: {:?}",
                    id,
                    sink.kinds()
                ),
            }
        }
        for (name, kind) in &before.1 {
            prop_assert_eq!(after.1.get(name), Some(kind), "foreign {} moved", name);
        }
        // 7: outcomes match receipts.
        let kinds = sink.kinds();
        let commit = built.commit;
        match outcome {
            [ItemOutcome::Applied { .. }] => prop_assert!(
                kinds.contains(&"ssh:committed".to_owned())
                    || kinds.contains(&"git:committed".to_owned())
            ),
            [ItemOutcome::NotApplied { .. }] => {
                prop_assert!(
                    !kinds.contains(&format!("{commit}:exchanged")),
                    "{:?}",
                    kinds
                );
            }
            [ItemOutcome::Restored { .. }] => {
                prop_assert!(kinds.contains(&format!("{commit}:restored")), "{:?}", kinds);
            }
            _ => {}
        }
        if built.locator.is_some() {
            prop_assert!(
                kinds.is_empty(),
                "the cleaner writes no receipt: {:?}",
                kinds
            );
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(config())]

        /// ADR-0007 §5.7's properties over concrete effects, on the filesystem:
        /// totality, no loss, foreign and modified content preserved, H inert, outcomes
        /// matching receipts, idempotence; with a crash injected after the k-th write.
        #[test]
        fn recovery_generated_observations_preserve_every_entry(c in cell()) {
            quiet_crashes();
            let Some(built) = build(&c) else {
                return Ok(());
            };
            let before = inventory(&built.root);
            if c.unobservable {
                std::fs::set_permissions(&built.root, std::fs::Permissions::from_mode(0o000)).unwrap();
            }
            let sink = Sink(Arc::new(Mutex::new(SinkLog {
                receipts: built.receipts.clone(),
                ..SinkLog::default()
            })));
            // 1: totality (no panic but the injected crash, no error but H).
            let first = run(&built, &sink, Some(c.crash_after));
            if let Some(r) = &first {
                prop_assert!(r.is_ok(), "{:?}", r);
            }
            let outcome = run(&built, &sink, None).expect("no hook").unwrap_or_default();
            if c.unobservable {
                // 6 and 8 in the same (unobservable) world: nothing more is written.
                let n = sink.receipts().len();
                let again = run(&built, &sink, None).expect("no hook").unwrap_or_default();
                prop_assert!(
                    built.locator.is_some() || matches!(again.as_slice(), [ItemOutcome::Held { .. }]),
                    "{:?}",
                    again
                );
                prop_assert_eq!(sink.receipts().len(), n, "{:?}", sink.kinds());
                std::fs::set_permissions(&built.root, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            check(&built, &before, &sink, &outcome)?;
            if c.unobservable {
                // Making the directory observable again is a change of the world; its
                // idempotence was checked above, under the same mode.
                return Ok(());
            }
            // 8: idempotence: a second reconcile moves nothing and writes nothing more
            // for an unchanged H.
            let settled = inventory(&built.root);
            let n = sink.receipts().len();
            let again = run(&built, &sink, None).expect("no hook").unwrap_or_default();
            // 6 and 8: H is inert, and a finished item stays as it is.
            prop_assert_eq!(&inventory(&built.root).0, &settled.0, "{:?}", sink.kinds());
            if let [ItemOutcome::Held { .. }] = again.as_slice() {
                prop_assert_eq!(sink.receipts().len(), n, "{:?}", sink.kinds());
            }
            let _ = StepContent::absent();
        }
    }
}

// --- passive observation ------------------------------------------------------------------

#[test]
fn observe_reevaluates_aliases_statically_against_the_record() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let (_intent, sink) = fx.adopt(&["work"]);
    let tree = fx.tree();
    let record = sink.record(&fx.env);
    let seen = fx
        .writer()
        .observe(&record, &["work".to_owned(), "personal".to_owned()]);
    assert_eq!(seen.len(), 2);
    let value = |i: usize, d: &str| {
        seen[i]
            .behavior
            .iter()
            .find(|o| o.directive == d)
            .map(|o| (o.values.clone(), o.certainty))
            .unwrap()
    };
    use heimdall_contract::doctor::{AliasDefinition, DirectiveCertainty};
    assert_eq!(seen[0].definition, AliasDefinition::Managed);
    assert_eq!(
        value(0, "HostName"),
        (
            vec!["work.example.invalid".to_owned()],
            DirectiveCertainty::Determined
        )
    );
    assert!(seen[0].identity_selection.is_some());
    assert_eq!(seen[1].definition, AliasDefinition::UserOnly);
    assert_eq!(
        value(1, "HostName"),
        (
            vec!["personal.example.invalid".to_owned()],
            DirectiveCertainty::Determined
        )
    );
    assert_eq!(fx.tree(), tree, "observation writes nothing");
}

// --- helpers: resources and async ---------------------------------------------------------

fn resource(env: &EnvironmentId, l: &ProjectionLocator, generation: u64) -> ManagedResource {
    ManagedResource {
        id: heimdall_domain::projection::projection_resource_id(env, l.role, &l.path),
        kind: ResourceKind::ConfigProjection,
        owner: OwnerRef::Projection {
            environment: env.clone(),
        },
        generation: ResourceGeneration(generation),
        desired: ResourceState::Absent,
        observed: ResourceState::Present,
        last_operation: None,
        locator: l.canonical().unwrap(),
        updated_at: heimdall_contract::Timestamp::now(),
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

/// A `StageSink` over the real store (U5's sink in miniature): each receipt in its own
/// transaction, the commit through `Txn::commit_projection_item` with the record's
/// environment, operation and time filled in.
struct StoreSink {
    store: Arc<heimdall_store::Store>,
    op: OperationId,
    env: EnvironmentId,
}

impl StoreSink {
    fn admit(
        store: &Arc<heimdall_store::Store>,
        env: &EnvironmentId,
        intent: &SetupIntent,
    ) -> Self {
        use heimdall_contract::EffectStatus;
        use heimdall_contract::canonical::RequestHash;
        use heimdall_contract::ids::RequestId;
        use heimdall_contract::state::OperationState;
        use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
        use heimdall_domain::operation::{
            EffectClass, LocalIntent, OperationKind, OperationRecord, RecoveryIntent,
            RecoveryMetadata,
        };
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        let op = OperationId::from_random_bytes(random());
        let key = IdempotencyKey {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            },
            kind: OperationKind::SetupApply,
            request_id: RequestId::parse("setup-scratch").unwrap(),
        };
        let now = heimdall_contract::Timestamp::now();
        let record = OperationRecord {
            id: op.clone(),
            kind: OperationKind::SetupApply,
            environment: env.clone(),
            key: key.clone(),
            request_hash: RequestHash(random()),
            effect_class: EffectClass::LocalResources,
            state: OperationState::Running,
            code: None,
            effect_status: EffectStatus::None,
            result: None,
            created_at: now,
            updated_at: now,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        let idem = IdempotencyRecord {
            key,
            request_hash: record.request_hash,
            operation_id: op.clone(),
            created_at: now,
            expires_at: None,
        };
        let recovery = RecoveryIntent {
            request: serde_json::json!({"action": "setup.apply", "request_id": "setup-scratch"}),
            resolved: None,
            local: Some(LocalIntent::Setup(intent.clone())),
        };
        store
            .transaction(|tx| tx.insert_setup_operation(&record, &idem, &recovery, None))
            .unwrap();
        StoreSink {
            store: Arc::clone(store),
            op,
            env: env.clone(),
        }
    }

    fn receipts(&self) -> Vec<StageReceipt> {
        self.store
            .transaction(|tx| tx.stage_receipts(&self.op))
            .unwrap()
    }
}

impl StageSink for StoreSink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        let r = durable(receipt);
        self.store
            .transaction(|tx| tx.append_stage_receipt(&self.op, &r))
            .map_err(|e| SinkError(e.to_string()))
    }

    fn commit_item(&mut self, mut commit: ItemCommit) -> Result<(), SinkError> {
        let now = heimdall_contract::Timestamp::now();
        commit.record.environment = self.env.clone();
        for r in commit.record.items.values_mut() {
            r.operation = self.op.clone();
            r.committed_at = now;
        }
        let receipt = durable(&LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        });
        self.store
            .transaction(|tx| tx.commit_projection_item(&self.op, &commit, &receipt))
            .map_err(|e| SinkError(e.to_string()))
    }
}

// --- ADR-0007 §12.30 item 7: the restore column and the original's snapshot ---------------

/// ADR-0007 §5.1, §12.30 item 7: a first adoption's `SetupPlan` carries its aliases, each
/// managed, with its before, after and restore states; the restore state is the alias's
/// behaviour with its section removed now (for a first adoption, its state without
/// Heimdall's section: the same digest as before) and lists no directive. The plan
/// digest does not change with the listing (two previews agree). A rollback lists none.
#[test]
fn first_adoption_plan_carries_its_aliases_with_their_restore_state() {
    let fx = Fx::new();
    std::fs::write(fx.user(), "Host other\n    User fixture\n").unwrap();
    let spec = fx.spec(&["alpha", "beta"], None);
    let plan = fx.preview(&spec, &Fx::apply_intent());
    let names: Vec<&str> = plan.view.aliases.iter().map(|a| a.alias.as_str()).collect();
    assert_eq!(names, ["alpha", "beta"], "{:?}", plan.view.aliases);
    for a in &plan.view.aliases {
        assert_eq!(a.kind, heimdall_contract::setup::AliasKind::Managed);
        let restore = a.restore.as_ref().expect("the restore column");
        assert!(restore.directives.is_empty(), "{restore:?}");
        assert_eq!(restore.digest.len(), 64, "{restore:?}");
        assert_eq!(
            restore.digest, a.before.digest,
            "nothing of its own on restore"
        );
        assert_ne!(a.after.digest, a.before.digest, "the plan adds it");
    }
    // The summary's restore column and the view's agree.
    let summary = plan
        .summary
        .as_ref()
        .expect("a first adoption needs a decision");
    for r in &summary.restore {
        let name = r.item.0.trim_start_matches("alias:");
        let a = plan.view.aliases.iter().find(|a| a.alias == name).unwrap();
        assert_eq!(a.restore.as_ref().unwrap().digest, r.digest.as_str());
    }
    assert_eq!(
        fx.preview(&spec, &Fx::apply_intent()).view.plan_digest,
        plan.view.plan_digest
    );
    // After the adoption, a rollback's plan lists no alias.
    let (_, sink) = fx.adopt(&["alpha"]);
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.aliases = Vec::new();
    let rollback = fx.preview(&spec, &Fx::rollback_intent());
    assert!(
        rollback.view.aliases.is_empty(),
        "{:?}",
        rollback.view.aliases
    );
}

// --- ADR-0007 §5.5, §12.32 item 2: the snapshot is the writer's -------------------------

/// The writer itself copies the original user file to
/// `<state>/backups/ssh_config.<UTC timestamp>.orig` (0600, in a 0700 directory, the
/// original bytes) before its first edit of it, with no CLI in the path: an apply takes it;
/// a preview takes none; an update that only checks the user file takes none; a rollback,
/// which edits the file again, keeps the first copy and adds none.
#[test]
fn the_writer_snapshots_the_original_user_file_before_its_first_edit() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha"], None), &Fx::apply_intent());
    assert!(!fx.backups().exists(), "a preview takes no snapshot");
    let sink = Sink::default();
    let intent = plan.intent();
    let r = fx.writer().apply(&intent, &mut sink.clone()).unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::Applied {
            item: ProjectionItem::Ssh,
            generation: 1
        }]
    );
    let taken = fx.snapshots("ssh_config");
    assert_eq!(taken.len(), 1, "{taken:?}");
    let name = taken[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.ends_with("Z.orig") && name.len() == "ssh_config.20261103T090807Z.orig".len(),
        "{name}"
    );
    assert_eq!(std::fs::read(&taken[0]).unwrap(), USER_TEXT.as_bytes());
    assert_eq!(
        std::fs::metadata(&taken[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(fx.backups())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_ne!(
        std::fs::read(fx.user()).unwrap(),
        USER_TEXT.as_bytes(),
        "the apply edited the file after the copy"
    );
    assert_eq!(
        std::fs::read_dir(fx.backups()).unwrap().count(),
        1,
        "no staging file is left behind"
    );
    // An update leaves the user file to the transaction check: no snapshot is added.
    let mut spec = fx.spec(&[], Some(sink.record(&fx.env)));
    spec.aliases = first_aliases(&intent, &fx, &["alpha"]);
    spec.aliases.push(fx.alias("beta"));
    let update = fx.preview(&spec, &Fx::apply_intent()).intent();
    fx.writer().apply(&update, &mut sink.clone()).unwrap();
    assert_eq!(fx.snapshots("ssh_config"), taken);
    // A rollback edits the user file again; the first original is kept.
    let record = sink.record(&fx.env);
    let rollback = fx
        .preview(&fx.spec(&[], Some(record)), &Fx::rollback_intent())
        .intent();
    fx.writer().apply(&rollback, &mut Sink::default()).unwrap();
    assert_eq!(std::fs::read(fx.user()).unwrap(), USER_TEXT.as_bytes());
    assert_eq!(fx.snapshots("ssh_config"), taken, "no second snapshot");
    assert_eq!(std::fs::read(&taken[0]).unwrap(), USER_TEXT.as_bytes());
}

/// A user file the apply creates has no original, and a configuration without a state
/// directory takes no snapshot: no backups directory appears in either case.
#[test]
fn a_created_user_file_or_a_missing_state_dir_takes_no_snapshot() {
    let fx = Fx::new();
    std::fs::remove_file(fx.user()).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha"], None), &Fx::apply_intent());
    fx.writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(fx.user().exists(), "the apply created the user file");
    assert!(!fx.backups().exists(), "nothing to copy");

    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha"], None), &Fx::apply_intent());
    let mut config = fx.config();
    config.state_dir = None;
    let r = LocalProjection::new(config)
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert!(matches!(r.items.as_slice(), [ItemOutcome::Applied { .. }]));
    assert!(!fx.backups().exists(), "no state directory, no snapshot");
}

/// The stale-base refusal is a precondition of the edit: a user file that changed after
/// the preview refuses the apply (`user_config_changed`) before anything is written, and
/// no snapshot of bytes the plan was not computed from is taken.
#[test]
fn a_stale_user_file_refuses_the_apply_and_takes_no_snapshot() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha"], None), &Fx::apply_intent());
    let changed = format!("{USER_TEXT}Host later\n    User changed\n");
    std::fs::write(fx.user(), &changed).unwrap();
    let before = fx.tree();
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UserConfigChanged)
        }]
    );
    assert!(!fx.backups().exists(), "no snapshot of a stale base");
    assert_eq!(fx.tree(), before, "nothing was written");
    assert_eq!(std::fs::read_to_string(fx.user()).unwrap(), changed);
}

/// No edit without its original copied: when the copy cannot be made (the backups path
/// holds a file), the item is not applied (`unmanageable_file`) before any of its steps
/// writes: P, the key files and the user file are as they were.
#[test]
fn a_snapshot_that_cannot_be_made_leaves_the_item_unwritten() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha", "beta"], None), &Fx::apply_intent());
    std::fs::write(fx.backups(), b"not a directory").unwrap();
    let before = fx.tree();
    let sink = Sink::default();
    let r = fx
        .writer()
        .apply(&plan.intent(), &mut sink.clone())
        .unwrap();
    assert_eq!(
        r.items,
        vec![ItemOutcome::NotApplied {
            item: ProjectionItem::Ssh,
            reason: Some(ConflictKind::UnmanageableFile)
        }]
    );
    assert_eq!(fx.tree(), before, "nothing was written");
    assert!(!fx.p().exists());
    assert_eq!(std::fs::read(fx.user()).unwrap(), USER_TEXT.as_bytes());
    assert!(
        sink.file_phases(0).is_empty(),
        "no step was staged: {:?}",
        sink.kinds()
    );
}

/// A restart that resumes an operation whose user-file step was never reached still
/// takes the snapshot before that step's first edit (an operation admitted by a writer
/// that took none, or a crash before the copy): the resume path is covered like the
/// first apply, which is what a held repair's retry runs.
#[test]
fn a_resumed_operation_snapshots_before_the_user_file_step() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha"], None), &Fx::apply_intent());
    let intent = plan.intent();
    let p_step = step_of(&intent, FileRole::ManagedSsh);
    // The first run has no state directory (so it copies nothing) and crashes after P's
    // staging, before the user file's step.
    let hook = Hook::new().crash(ReplacePoint::AfterStage, Some(p_step));
    let mut first = fx.hooked(&hook);
    first.state_dir = None;
    let sink = Sink::default();
    assert!(apply_or_crash(first, &intent, &sink).is_none());
    assert!(!fx.backups().exists());
    assert_eq!(std::fs::read(fx.user()).unwrap(), USER_TEXT.as_bytes());
    // The restart (with the state directory) completes the item and copied the original
    // first.
    let out = restart(&fx, &intent, &sink);
    assert!(
        matches!(out.as_slice(), [ItemOutcome::Applied { .. }]),
        "{out:?}"
    );
    let taken = fx.snapshots("ssh_config");
    assert_eq!(taken.len(), 1, "{taken:?}");
    assert_eq!(std::fs::read(&taken[0]).unwrap(), USER_TEXT.as_bytes());
    assert_ne!(std::fs::read(fx.user()).unwrap(), USER_TEXT.as_bytes());
}

/// The copy is of the bytes the plan was computed from: when the user file changes
/// between the writer's base check and the copy, and no snapshot exists yet (a resume),
/// the edit is refused as a changed base (`user_config_changed`), nothing is copied, and
/// the other writer's bytes are never overwritten.
#[test]
fn a_user_file_that_changes_before_the_copy_is_not_snapshotted_or_edited() {
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let plan = fx.preview(&fx.spec(&["alpha"], None), &Fx::apply_intent());
    let intent = plan.intent();
    let p_step = step_of(&intent, FileRole::ManagedSsh);
    let user_step = step_of(&intent, FileRole::UserSsh);
    let mut first = fx.hooked(&Hook::new().crash(ReplacePoint::AfterStage, Some(p_step)));
    first.state_dir = None;
    let sink = Sink::default();
    assert!(apply_or_crash(first, &intent, &sink).is_none());
    // The restart reaches the user file's step; another writer edits the file just after
    // the base check and before the copy.
    let other = format!("{USER_TEXT}Host raced\n    User other\n");
    let path = fx.user().to_path_buf();
    let racing = other.clone();
    let hook = Hook::new().run(ReplacePoint::AfterValidate, Some(user_step), move || {
        std::fs::write(&path, &racing).unwrap();
    });
    let out = reconcile_or_crash(fx.hooked(&hook), &intent, &sink)
        .expect("no crash")
        .unwrap();
    let reason = match out.as_slice() {
        [ItemOutcome::NotApplied { reason, .. } | ItemOutcome::Restored { reason, .. }] => *reason,
        other => panic!("{other:?}"),
    };
    assert_eq!(reason, Some(ConflictKind::UserConfigChanged), "{out:?}");
    assert!(fx.snapshots("ssh_config").is_empty(), "nothing was copied");
    assert_eq!(
        std::fs::read_to_string(fx.user()).unwrap(),
        other,
        "the other writer's bytes are kept"
    );
}

/// The global Git file is snapshotted the same way, to `gitconfig.<timestamp>.orig`,
/// before the Git item's first edit of it (ADR-0007 §5.5, §12.32 item 2). The copy is taken
/// when the item starts, so it exists whether or not the item then applies on this host's
/// Git (the item's own outcome is `projection_git`'s concern).
#[test]
fn the_writer_snapshots_the_global_git_file_before_its_first_edit() {
    use heimdall_localenv::clients::{ClientCandidate, ClientInventory, ClientKind, ClientSource};
    use heimdall_localenv::env::Env;
    use heimdall_localenv::local_query::LocalQueries;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let git = heimdall_testkit::home::find_program("git").expect("git is installed");
    let system = fx.home.root.join("gitconfig-system");
    std::fs::write(&system, b"").unwrap();
    let global = fx.home.git_home.join(".gitconfig");
    let original: &[u8] = b"[user]\n\tname = Scratch\n";
    std::fs::write(&global, original).unwrap();
    let mut config = fx.config();
    config.env = Env::from_vars([
        ("HOME", fx.home.git_home.display().to_string()),
        (
            "XDG_CONFIG_HOME",
            fx.home.git_home.join(".config").display().to_string(),
        ),
        ("GIT_CONFIG_SYSTEM", system.display().to_string()),
    ]);
    config.queries = LocalQueries::Enabled;
    let candidate = |kind, path| ClientCandidate {
        kind,
        path,
        source: ClientSource::Path,
        version: None,
        sha256: None,
        selected: true,
    };
    config.clients = ClientInventory {
        candidates: vec![
            candidate(ClientKind::Git, git),
            candidate(ClientKind::Ssh, PathBuf::from("/usr/bin/ssh")),
        ],
    };
    config.test.git_item_any_default = true;
    let writer = LocalProjection::new(config);
    let intent = PreviewIntent::Apply { include_git: true };
    let plan = writer.preview(&fx.spec(&["alpha"], None), &intent).unwrap();
    assert!(
        plan.files.iter().any(|s| s.role == FileRole::GitInclude),
        "the plan edits the global Git file"
    );
    assert!(!fx.backups().exists(), "a preview takes no snapshot");
    writer.apply(&plan.intent(), &mut Sink::default()).unwrap();
    let ssh = fx.snapshots("ssh_config");
    let taken = fx.snapshots("gitconfig");
    assert_eq!((ssh.len(), taken.len()), (1, 1), "{ssh:?} {taken:?}");
    assert_eq!(std::fs::read(&taken[0]).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&taken[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read(&ssh[0]).unwrap(), USER_TEXT.as_bytes());
}

/// ADR-0007 §12.32 item 5: the real writer never cuts a diff. A plan of 250 aliases with
/// long host names has a P diff beyond `MAX_DIFF_BYTES` by itself and a total far beyond
/// it; the preview carries each diff whole (every added line of P is there, and the
/// summary text ends with the last file's last line), so the application can refuse the
/// plan instead of showing part of it.
#[test]
fn the_preview_never_cuts_a_diff() {
    use heimdall_contract::setup::MAX_DIFF_BYTES;
    let fx = Fx::new();
    std::fs::write(fx.user(), USER_TEXT).unwrap();
    let names: Vec<String> = (0..250).map(|i| format!("host{i:03}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut spec = fx.spec(&refs, None);
    for a in &mut spec.aliases {
        let label = "a".repeat(60);
        a.hostname = format!("{label}.{label}.{label}.{}.example.invalid", a.alias);
    }
    let plan = fx.preview(&spec, &Fx::apply_intent());
    let p = plan
        .view
        .files
        .iter()
        .find(|f| f.role == heimdall_contract::setup::ProjectionFileRole::ManagedSsh)
        .unwrap();
    assert!(
        p.diff.len() > MAX_DIFF_BYTES,
        "P's diff alone is {} bytes",
        p.diff.len()
    );
    for n in &names {
        assert!(
            p.diff.contains(&format!("+Host {n}\n")),
            "{n} is in P's diff"
        );
    }
    assert!(p.diff.ends_with('\n'));
    let summary = plan
        .summary
        .as_ref()
        .expect("a first adoption needs a decision");
    assert!(
        summary.diff_text.len() > MAX_DIFF_BYTES,
        "not cut to the bound"
    );
    assert!(!summary.within_bounds());
    let last = plan.view.files.last().unwrap();
    assert!(
        summary.diff_text.ends_with(&last.diff),
        "the last file is whole"
    );
    let shown: usize = plan.view.files.iter().map(|f| f.diff.len()).sum();
    assert!(
        summary.diff_text.len() >= shown,
        "the summary holds every file's diff"
    );
}

/// ADR-0007 §5.5 "Snapshots" (§12.30 item 7): `snapshot_original` copies the original
/// bytes once, owner-only, as `<name>.<YYYYMMDDTHHMMSSZ>.orig` in a 0700 `backups`
/// directory it creates; a later call keeps that snapshot and writes nothing; an absent
/// file has no original; bytes that are not the plan's base are not copied; a link is
/// never followed. Nothing is removed (no staging file is left behind).
#[test]
fn snapshot_original_copies_the_original_once_owner_only() {
    use heimdall_localenv::projection::apply::{Snapshot, snapshot_original};
    let fx = Fx::new();
    let backups = fx.home.state_dir.join("backups");
    let now: heimdall_contract::Timestamp = "2026-11-03T09:08:07.654Z".parse().unwrap();
    // No file: nothing to copy, nothing created (the scratch home creates it empty).
    std::fs::remove_file(fx.user()).unwrap();
    assert_eq!(
        snapshot_original(fx.user(), &backups, "ssh_config", None, now).unwrap(),
        Snapshot::Absent
    );
    assert!(!backups.exists());
    let original = b"Host other\n    User fixture\n";
    std::fs::write(fx.user(), original).unwrap();
    // Not the plan's base: nothing written.
    assert_eq!(
        snapshot_original(
            fx.user(),
            &backups,
            "ssh_config",
            Some(&"00".repeat(32)),
            now
        )
        .unwrap(),
        Snapshot::Changed
    );
    let base = Sha256Hex::of(original);
    let first =
        snapshot_original(fx.user(), &backups, "ssh_config", Some(base.as_str()), now).unwrap();
    let expected = backups.join("ssh_config.20261103T090807Z.orig");
    assert_eq!(first, Snapshot::Written(expected.clone()));
    assert_eq!(std::fs::read(&expected).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&expected).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&backups).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // A later edit is never snapshotted again: the first original is kept.
    std::fs::write(fx.user(), b"Host other\n    User changed\n").unwrap();
    let later: heimdall_contract::Timestamp = "2026-11-04T00:00:00Z".parse().unwrap();
    assert_eq!(
        snapshot_original(fx.user(), &backups, "ssh_config", None, later).unwrap(),
        Snapshot::Exists(expected.clone())
    );
    assert_eq!(std::fs::read(&expected).unwrap(), original);
    let names: Vec<String> = std::fs::read_dir(&backups)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["ssh_config.20261103T090807Z.orig"], "{names:?}");
    // A link is never followed.
    let other = fx.home.state_dir.join("other-backups");
    let link = fx.ssh_dir().join("linked-config");
    std::os::unix::fs::symlink(fx.user(), &link).unwrap();
    assert!(snapshot_original(&link, &other, "ssh_config", None, now).is_err());
    assert!(!other.exists());
}
