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
//! evidence records label it so. The store-backed variant uses the store's own
//! `FaultHook` (`heimdall_testkit::ScriptedFaults`).
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
        let mut c = ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone());
        let keys: Arc<dyn PublicKeySource> = self.keys.clone();
        c.keys = Some(keys);
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

/// m02-plan U4 names this case "is restored" (revision 2). ADR-0007 revision 5's
/// normalization (§5.7 rule 1) makes an entry that is not a regular file X whatever its
/// identity, so the displaced symlink is not a D that F5 may move back: the restore is
/// held (`third_writer`, F5d) and nothing moves. The test asserts the binding table:
/// the symlink is preserved intact, its target is untouched, and nothing is deleted.
/// The name/expectation mismatch is escalated.
#[test]
fn a22_race_symlink_substitution_at_boundary_is_restored() {
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
    assert!(
        matches!(
            out.as_slice(),
            [ItemOutcome::NotApplied {
                item: ProjectionItem::Ssh,
                ..
            }]
        ),
        "{out:?} {:?}",
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
    // At rollback, B is removed and the edited P is left to the owner (R1a): the
    // cleaner removes nothing whose content changed.
    let rb = rollback_plan(&fx, &sink).intent();
    fx.writer().apply(&rb, &mut Sink::default()).unwrap();
    let locator = sink.record(&fx.env).items[&ProjectionItem::Ssh]
        .files
        .iter()
        .find(|l| l.role == FileRole::ManagedSsh)
        .cloned()
        .unwrap();
    block_on(fx.cleaner().delete(&resource(&fx.env, &locator, 1))).unwrap();
    assert_eq!(std::fs::read(fx.p()).unwrap(), edited, "edited P kept");
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
    fx.writer()
        .apply(&plan.intent(), &mut Sink::default())
        .unwrap();
    let user_after = std::fs::symlink_metadata(fx.user())
        .ok()
        .map(|m| (m.ino(), m.mode()));
    assert_eq!(user_after, user_before, "the user file is unchanged");
    assert_eq!(std::fs::read(fx.user()).ok(), bytes_before);
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
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
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

// --- the generated domain on the filesystem (ADR-0007 §5.7 properties) ------------------

mod generated {
    use super::*;
    use heimdall_domain::operation::{PostVerdict, RestoreCause, SettleSource, SettledDisposition};
    use heimdall_domain::projection::{Base, FileIdentity, StepContent};
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
            c.rng_seed = RngSeed::Fixed(0x5534_4347_454e_4f42);
        }
        c
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
        (
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
                |(create, h, s, v, d, fill, unobservable, crash_after)| Cell {
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
        );
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
        reconcile_or_crash(config, &built.intent, sink)
    }

    fn check(
        built: &Built,
        before: &Inventory,
        sink: &Sink,
        outcome: &[ItemOutcome],
    ) -> Result<(), TestCaseError> {
        let after = inventory(&built.root);
        let allowed = removable(&sink.receipts());
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
        match outcome {
            [ItemOutcome::Applied { .. }] => {
                prop_assert!(kinds.contains(&"ssh:committed".to_owned()))
            }
            [ItemOutcome::NotApplied { .. }] => {
                prop_assert!(!kinds.contains(&"0:exchanged".to_owned()), "{:?}", kinds);
            }
            [ItemOutcome::Restored { .. }] => {
                prop_assert!(kinds.contains(&"0:restored".to_owned()), "{:?}", kinds);
            }
            _ => {}
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
                prop_assert!(matches!(again.as_slice(), [ItemOutcome::Held { .. }]), "{:?}", again);
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
