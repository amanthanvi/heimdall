//! ⟨M04 U3a⟩ The projection transaction across the `heimdall-wsl/1` channel, with the **real
//! `heimdall` binary** as the in-distribution helper over pipes (ADR-0010 §3 items 3–4, §9
//! item 2; review finding M04-D02, design U3 §3.3 and §5).
//!
//! The helper runs `heimdall internal wsl-helper` as a local child with the test
//! configuration (`HEIMDALL_TEST_WSL_*`: an injected identity and home, a stand-in `ssh.exe`,
//! and an env-gated crash point inside the helper's file transaction). The Windows side is
//! [`DistributionWriter`] over [`DirectLauncher`], and its caller's [`StageSink`] is a **durable
//! test sink**: each receipt is on disk (fsync'd) before the call returns, and so before the
//! helper is acknowledged.
//!
//! A lost channel at any point is exactly a crash of the native writer at the same point
//! (design §3.3), so the scenarios reuse M02's
//! `a22_first_adoption_crash_after_b_exchange_before_validation_reconciles` shape for the Git
//! item: the item is exchanged, the channel is lost, and a **fresh helper** reconciles from the
//! persisted receipts, never a second `apply` (R-RT-05).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_app::ports::{
    DiscoveredDistribution, DistributionHost, DistributionStart, DistributionTarget, ItemOutcome,
    ProjectionWriter, ReconcileError, SinkError, StageSink,
};
use heimdall_contract::environment::DistributionGuid;
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_contract::setup::{GitApplicability, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::{AdapterIdentity, EffectReceipt, LocalReceipt, StageReceipt};
use heimdall_domain::projection::{
    ConsentRecord, ItemCommit, ProjectionLocator, ProjectionRecord, ProjectionSpec, SetupIntent,
};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_wsl::{DirectLauncher, WslHost};

/// The helper binary: the real `heimdall` (`HEIMDALL_E2E_BIN` names it where the harness runs a
/// cross-built test binary on another host).
fn helper_bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

const GUID: &str = "0b1c2d3e-1111-4222-8333-abcdef012345";

// --- the scratch world the helper runs in ---------------------------------------------------

struct World {
    home: ScratchHome,
    git: PathBuf,
    system: PathBuf,
    ssh_exe: PathBuf,
    target: DistributionTarget,
}

impl World {
    fn new() -> World {
        let home = ScratchHome::new();
        let system = home.root.join("gitconfig-system");
        std::fs::write(&system, b"").unwrap();
        // The stand-in for the Windows in-box `ssh.exe` at its distribution-visible path.
        let bin = home.root.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let ssh_exe = bin.join("ssh.exe");
        std::fs::write(&ssh_exe, b"#!/bin/sh\necho OpenSSH_for_Windows_9.5p2 >&2\n").unwrap();
        std::fs::set_permissions(
            &ssh_exe,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(home.ssh_dir.join("config"), b"Host personal\n    User me\n").unwrap();
        World {
            git: find_program("git").expect("git is installed on the harness"),
            target: DistributionTarget {
                guid: DistributionGuid::parse(GUID).unwrap(),
                name: "Ubuntu".to_owned(),
                account: "alice".to_owned(),
                namespace: EnvironmentId::from_random_bytes([0x44; 16]),
            },
            home,
            system,
            ssh_exe,
        }
    }

    fn account_home(&self) -> &Path {
        &self.home.git_home
    }

    fn global(&self) -> PathBuf {
        self.account_home().join(".gitconfig")
    }

    fn heimdall_config(&self) -> PathBuf {
        self.account_home().join(".config").join("heimdall")
    }

    fn p_git(&self) -> PathBuf {
        self.heimdall_config().join("gitconfig")
    }

    fn ssh_config(&self) -> PathBuf {
        self.home.ssh_dir.join("config")
    }

    /// The helper's whole environment: nothing else is inherited.
    fn helper_env(&self, crash: Option<&str>) -> Vec<(OsString, OsString)> {
        let path = std::env::join_paths([
            self.git.parent().unwrap(),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .unwrap();
        let home = self.account_home();
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), path),
            ("HOME".into(), home.into()),
            ("XDG_CONFIG_HOME".into(), home.join(".config").into()),
            (
                "XDG_STATE_HOME".into(),
                home.join(".local").join("state").into(),
            ),
            ("GIT_CONFIG_SYSTEM".into(), self.system.clone().into()),
            (
                "HEIMDALL_TEST_WSL_HELPER_ID".into(),
                "1000:alice:Ubuntu".into(),
            ),
            ("HEIMDALL_TEST_WSL_HOME".into(), home.into()),
            (
                "HEIMDALL_TEST_WSL_SSH_EXE".into(),
                self.ssh_exe.clone().into(),
            ),
        ];
        if let Some(point) = crash {
            env.push(("HEIMDALL_TEST_WSL_CRASH".into(), point.into()));
        }
        env
    }

    /// A host whose helper is the real binary. Each call is one fresh launcher: a fresh helper
    /// per request.
    fn host(&self, crash: Option<&str>) -> (WslHost, Arc<DirectLauncher>) {
        let launcher = DirectLauncher::new(
            PathBuf::from(helper_bin()),
            vec!["internal".into(), "wsl-helper".into()],
            self.helper_env(crash),
        );
        let host = WslHost::with_direct_helper(
            launcher.clone(),
            vec![DiscoveredDistribution {
                guid: self.target.guid.clone(),
                name: self.target.name.clone(),
                version: 2,
                default_uid: Some(1000),
            }],
        );
        (host, launcher)
    }

    fn writer(&self, crash: Option<&str>) -> (Arc<dyn ProjectionWriter>, Arc<DirectLauncher>) {
        let (host, launcher) = self.host(crash);
        let writer = host
            .writer(&self.target, DistributionStart::Forbidden)
            .unwrap();
        (writer, launcher)
    }

    fn spec(&self, record: Option<ProjectionRecord>) -> ProjectionSpec {
        ProjectionSpec {
            environment: self.target.namespace.clone(),
            aliases: Vec::new(),
            record,
            consent: ConsentRecord::default(),
        }
    }

    fn apply_intent(&self) -> PreviewIntent {
        PreviewIntent::Apply {
            include_git: false,
            items: [ProjectionItem::DistributionGit].into_iter().collect(),
            distribution: Some(self.target.guid.clone()),
        }
    }

    fn rollback_intent(&self) -> PreviewIntent {
        PreviewIntent::Rollback {
            keep_key_files: true,
            items: [ProjectionItem::DistributionGit].into_iter().collect(),
            distribution: Some(self.target.guid.clone()),
        }
    }

    /// `git config --includes --get core.sshCommand` with the helper's own scratch environment.
    fn effective_ssh_command(&self) -> Option<String> {
        let mut c = std::process::Command::new(&self.git);
        c.env_clear().current_dir(&self.home.root).args([
            "config",
            "--includes",
            "--get",
            "core.sshCommand",
        ]);
        for (k, v) in self.helper_env(None).iter().take(5) {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim_end().to_owned())
    }

    /// Every file under the account's home, with its bytes (the SSH and Git files).
    fn tree(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                if p.is_dir() {
                    walk(&p, root, out);
                } else if let Ok(bytes) = std::fs::read(&p) {
                    out.insert(rel, bytes);
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.account_home(), self.account_home(), &mut out);
        out
    }
}

// --- the durable test sink --------------------------------------------------------------------

/// What the sink does to the channel, once, at a named receipt.
enum Fault {
    None,
    /// Persist the receipt, then kill the helper by exact PID and wait until it is dead, and
    /// only then return: the helper's `append` never gets its acknowledgment (lost after the
    /// receipt is durable, before the ack).
    KillAfterDurable {
        kind: &'static str,
        launcher: Arc<DirectLauncher>,
    },
    /// Refuse the call (the store failed): nothing is persisted, `sink_failed` is sent.
    Refuse {
        kind: &'static str,
    },
}

struct DurableSink {
    dir: PathBuf,
    fault: Fault,
    fired: bool,
}

impl DurableSink {
    fn new(dir: &Path, fault: Fault) -> DurableSink {
        DurableSink {
            dir: dir.to_path_buf(),
            fault,
            fired: false,
        }
    }

    fn persist(&self, file: &str, line: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(file))
            .unwrap();
        writeln!(f, "{line}").unwrap();
        f.sync_all().unwrap();
    }

    fn receipts(dir: &Path) -> Vec<StageReceipt> {
        std::fs::read_to_string(dir.join("receipts.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn commits(dir: &Path) -> Vec<ItemCommit> {
        std::fs::read_to_string(dir.join("commits.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn kinds(dir: &Path) -> Vec<String> {
        DurableSink::receipts(dir)
            .iter()
            .map(|r| kind(r.local.as_ref().unwrap()))
            .collect()
    }

    fn hit(&mut self, local: &LocalReceipt) -> Result<bool, SinkError> {
        let k = kind(local);
        match &self.fault {
            Fault::Refuse { kind } if !self.fired && *kind == k => {
                self.fired = true;
                Err(SinkError("the store refused".to_owned()))
            }
            Fault::KillAfterDurable { kind, .. } if !self.fired && *kind == k => {
                self.fired = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn kill_helper(&self) {
        let Fault::KillAfterDurable { launcher, .. } = &self.fault else {
            return;
        };
        let pid = launcher.last_pid().expect("a helper is running");
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap(),
            rustix::process::Signal::KILL,
        )
        .unwrap();
        // Wait until it is dead (a zombie until the session reaps it), so the acknowledgment
        // the session writes next can never reach a live helper.
        let start = Instant::now();
        while !heimdall_localenv::sys::exited_unreaped(pid).unwrap_or(true) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the helper did not die"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn kind(local: &LocalReceipt) -> String {
    let v = serde_json::to_value(local).unwrap();
    let subject = if v["scope"] == "file" {
        v["step"].to_string()
    } else {
        v["item"].as_str().unwrap().to_owned()
    };
    format!("{subject}:{}", v["phase"]["kind"].as_str().unwrap())
}

fn stage_receipt(local: &LocalReceipt) -> StageReceipt {
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

impl StageSink for DurableSink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        if self.hit(receipt)? {
            self.persist(
                "receipts.jsonl",
                &serde_json::to_string(&stage_receipt(receipt)).unwrap(),
            );
            self.kill_helper();
            return Ok(());
        }
        self.persist(
            "receipts.jsonl",
            &serde_json::to_string(&stage_receipt(receipt)).unwrap(),
        );
        Ok(())
    }

    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError> {
        let receipt = LocalReceipt::Item {
            item: commit.item,
            phase: heimdall_domain::operation::ItemPhase::Committed {
                generation: commit.generation,
            },
        };
        // The store writes the commit and its `item.committed` receipt in one transaction.
        self.persist("commits.jsonl", &serde_json::to_string(&commit).unwrap());
        self.append(&receipt)
    }
}

fn applied_git(items: &[ItemOutcome]) -> bool {
    matches!(
        items,
        [ItemOutcome::Applied {
            item: ProjectionItem::Git,
            generation: 1
        }]
    )
}

fn resource_of(world: &World, locator: &ProjectionLocator, generation: u64) -> ManagedResource {
    ManagedResource {
        id: heimdall_domain::projection::projection_resource_id(
            &world.target.namespace,
            locator.role,
            &locator.path,
        ),
        kind: ResourceKind::ConfigProjection,
        owner: OwnerRef::Projection {
            environment: world.target.namespace.clone(),
        },
        generation: ResourceGeneration(generation),
        desired: ResourceState::Absent,
        observed: ResourceState::Present,
        last_operation: Some(OperationId::from_random_bytes([9; 16])),
        locator: locator.canonical().unwrap(),
        updated_at: heimdall_contract::Timestamp::now(),
    }
}

/// Preview the distribution's Git item through the helper.
fn preview_apply(world: &World) -> SetupIntent {
    let (writer, _) = world.writer(None);
    let plan = writer
        .preview(&world.spec(None), &world.apply_intent())
        .unwrap_or_else(|e| panic!("preview over the channel: {e}"));
    assert_eq!(
        plan.view.git.as_ref().map(|g| g.applicability),
        Some(GitApplicability::Applicable),
        "{:?}",
        plan.view.git.as_ref().and_then(|g| g.reason.clone())
    );
    plan.intent()
}

/// After a committed item: a user edit made later is kept through the rollback, and only the
/// recorded generation's files go. Returns nothing; asserts.
fn rollback_after_a_later_user_edit(world: &World, dir: &Path, intent: &SetupIntent) {
    let commits = DurableSink::commits(dir);
    assert_eq!(commits.len(), 1, "one durable commit");
    let record = commits[0].record.clone();
    assert_eq!(record.environment, world.target.namespace);

    // The owner edits the global Git file after the commit, and leaves an unrelated file in
    // Heimdall's configuration directory.
    let mut text = std::fs::read_to_string(world.global()).unwrap();
    text.push_str("[user]\n\tname = Edited Later\n");
    std::fs::write(world.global(), &text).unwrap();
    let decoy = world.heimdall_config().join("keep.txt");
    std::fs::write(&decoy, b"not Heimdall's\n").unwrap();
    let ssh_before = std::fs::read(world.ssh_config()).unwrap();

    let (writer, _) = world.writer(None);
    let rollback = writer
        .preview(&world.spec(Some(record.clone())), &world.rollback_intent())
        .unwrap_or_else(|e| panic!("rollback preview over the channel: {e}"))
        .intent();
    assert!(
        rollback
            .files
            .iter()
            .all(|s| s.role.item() == ProjectionItem::Git)
    );
    let rb_dir = dir.join("rollback");
    std::fs::create_dir(&rb_dir).unwrap();
    let r = writer
        .apply(&rollback, &mut DurableSink::new(&rb_dir, Fault::None))
        .unwrap();
    assert!(
        matches!(
            r.items.as_slice(),
            [ItemOutcome::Applied {
                item: ProjectionItem::Git,
                ..
            }]
        ),
        "{r:?}"
    );

    // B_git is gone; the later edit is kept; Git's SSH selection is the user's again.
    let after = std::fs::read_to_string(world.global()).unwrap();
    assert!(
        after.contains("name = Edited Later"),
        "the later user edit is kept"
    );
    assert!(
        !after.contains("heimdall"),
        "the include block is gone: {after:?}"
    );
    assert_eq!(world.effective_ssh_command(), None);
    assert!(!world.home.git_home.join(".gitconfig.lock").exists());

    // P_git is the cleaner's: the recorded generation's file is removed through the helper,
    // the unrelated file is not, and `~/.ssh` was never touched.
    let locator = record.items[&ProjectionItem::Git]
        .files
        .iter()
        .find(|l| l.path.ends_with("gitconfig"))
        .expect("P_git is a recorded file")
        .clone();
    assert!(world.p_git().exists());
    let (host, _) = world.host(None);
    let cleaner = host
        .cleaner(&world.target, DistributionStart::Forbidden)
        .unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(cleaner.delete(&resource_of(world, &locator, intent.generation)))
        .unwrap();
    assert!(
        !world.p_git().exists(),
        "the recorded generation's file is removed"
    );
    assert_eq!(std::fs::read(&decoy).unwrap(), b"not Heimdall's\n");
    assert_eq!(std::fs::read(world.ssh_config()).unwrap(), ssh_before);
    assert!(
        !world.tree().keys().any(|k| k.contains(".hm-")),
        "no quarantine or staging leftovers: {:?}",
        world.tree().keys().collect::<Vec<_>>()
    );
}

/// The scenario's common tail: a fresh helper reconciles from the persisted receipts.
fn reconcile_with_a_fresh_helper(
    world: &World,
    dir: &Path,
    intent: &SetupIntent,
) -> Vec<ItemOutcome> {
    let receipts = DurableSink::receipts(dir);
    let (writer, launcher) = world.writer(None);
    let mut sink = DurableSink::new(dir, Fault::None);
    let out = writer
        .reconcile(intent, &receipts, &mut sink)
        .unwrap_or_else(|e| panic!("reconcile over a fresh helper: {e}"));
    assert_eq!(launcher.spawned(), 1, "one fresh helper, one request");
    out.items
}

/// The D02 proof (ADR-0010 §9 item 2; M04-D02): one projection fault scenario (M02's crash
/// after the exchange, before the next receipt) run over the real helper channel and
/// interrupted twice, restarted through a fresh helper and reconciled from the durable
/// receipts, with a later user edit preserved and only the recorded generation removed.
///
/// (a) The helper dies after the exchange, before its `exchanged` receipt is sent: the step
///     happened and no receipt exists (native: a crash after a step, before its receipt).
/// (b) The receipt is durable on Windows and the helper is killed before the acknowledgment
///     arrives: its `append` fails and the writer stops (row T1); Windows has the receipt.
/// (c) The store refuses a call: no acknowledgment, the writer stops, nothing is lost.
#[test]
fn d02_lost_reply_then_reconcile_over_real_helper_channel() {
    for scenario in ["a", "b", "c"] {
        let world = World::new();
        let ssh_before = std::fs::read(world.ssh_config()).unwrap();
        let intent = preview_apply(&world);
        let commit_step = intent
            .files
            .iter()
            .position(|s| s.commit)
            .expect("the Git item has a commit step");
        let user_before = std::fs::read(world.global()).unwrap();

        let dir = world.home.root.join(format!("durable-{scenario}"));
        std::fs::create_dir(&dir).unwrap();
        let exchanged = format!("{commit_step}:exchanged");
        let (writer, launcher, mut sink) = match scenario {
            "a" => {
                let crash = format!("after_exchange:{commit_step}");
                let (w, l) = world.writer(Some(&crash));
                (w, l, DurableSink::new(&dir, Fault::None))
            }
            "b" => {
                let (w, l) = world.writer(None);
                let kill = Fault::KillAfterDurable {
                    kind: Box::leak(exchanged.clone().into_boxed_str()),
                    launcher: l.clone(),
                };
                (w, l, DurableSink::new(&dir, kill))
            }
            _ => {
                let (w, l) = world.writer(None);
                let refuse = Fault::Refuse {
                    kind: Box::leak(exchanged.clone().into_boxed_str()),
                };
                (w, l, DurableSink::new(&dir, refuse))
            }
        };

        // The apply is lost mid-transaction.
        let err = writer.apply(&intent, &mut sink).unwrap_err();
        assert_eq!(launcher.spawned(), 1);
        let kinds = DurableSink::kinds(&dir);
        match scenario {
            "a" => {
                assert_eq!(
                    err,
                    ReconcileError::Unavailable("wsl_helper_unavailable".to_owned())
                );
                assert_eq!(
                    kinds.last().map(String::as_str),
                    Some(format!("{commit_step}:validated").as_str()),
                    "(a) the exchange happened and no receipt for it exists: {kinds:?}"
                );
            }
            "b" => {
                assert_eq!(
                    err,
                    ReconcileError::Unavailable("wsl_helper_unavailable".to_owned())
                );
                assert_eq!(
                    kinds.last().map(String::as_str),
                    Some(exchanged.as_str()),
                    "(b) the receipt is durable on Windows: {kinds:?}"
                );
            }
            _ => {
                assert!(matches!(err, ReconcileError::Sink(_)), "{err:?}");
                assert_eq!(
                    kinds.last().map(String::as_str),
                    Some(format!("{commit_step}:validated").as_str()),
                    "(c) the refused call persisted nothing: {kinds:?}"
                );
            }
        }
        assert!(DurableSink::commits(&dir).is_empty(), "no item commit yet");
        // The exchange happened: B_git is in the owner's file already, but nothing is committed.
        assert_ne!(
            std::fs::read(world.global()).unwrap(),
            user_before,
            "{scenario}: the item was exchanged before the channel was lost"
        );

        // A fresh helper, the persisted receipts, and never a second `apply`.
        let items = reconcile_with_a_fresh_helper(&world, &dir, &intent);
        assert!(applied_git(&items), "{scenario}: {items:?}");
        let k = DurableSink::kinds(&dir);
        let pos = |s: &str| {
            k.iter()
                .position(|x| x == s)
                .unwrap_or_else(|| panic!("{scenario}: {s} in {k:?}"))
        };
        assert!(pos(&exchanged) < pos(&format!("{commit_step}:post_validated")));
        assert!(pos(&format!("{commit_step}:post_validated")) < pos("git:committed"));
        assert_eq!(
            k.iter().filter(|x| x.as_str() == exchanged).count(),
            1,
            "{scenario}: the exchange receipt exists once: {k:?}"
        );
        assert_eq!(
            DurableSink::commits(&dir).len(),
            1,
            "one commit, recorded once"
        );
        assert_eq!(
            world.effective_ssh_command().as_deref(),
            Some(format!("'{}'", world.ssh_exe.display()).as_str()),
            "Git runs the distribution-visible in-box ssh.exe"
        );
        assert!(!world.home.git_home.join(".gitconfig.lock").exists());

        // A second reconcile recovers nothing new and writes nothing.
        let written = DurableSink::receipts(&dir).len();
        let again = reconcile_with_a_fresh_helper(&world, &dir, &intent);
        assert!(applied_git(&again), "{again:?}");
        assert_eq!(DurableSink::receipts(&dir).len(), written);

        // Mode A never touches the distribution's Linux SSH configuration or key files.
        assert_eq!(std::fs::read(world.ssh_config()).unwrap(), ssh_before);
        assert!(!world.heimdall_config().join("ssh_config").exists());
        assert!(!world.heimdall_config().join("keys").exists());

        rollback_after_a_later_user_edit(&world, &dir, &intent);
    }
}

/// One helper per (distribution, account): while a helper holds the instance lock a second
/// one answers `busy` to its first file request, and the session continues without having
/// touched a file.
#[test]
fn a_second_helper_for_the_same_account_answers_busy() {
    let world = World::new();
    let (first, first_launcher) = world.writer(None);
    let (second, _) = world.writer(None);
    // The first session holds the lock for as long as it is open: open one and keep it
    // by previewing through a session we do not close.
    let transport = {
        use heimdall_wsl::HelperLauncher as _;
        first_launcher.launch(&world.target).unwrap()
    };
    let mut held = heimdall_wsl::HelperSession::open(
        transport,
        &heimdall_wsl::client::Expected {
            name: "Ubuntu".to_owned(),
            account: "alice".to_owned(),
            uid: Some(1000),
        },
    )
    .unwrap();
    let ctx = heimdall_wsl::proto::DistContext {
        guid: world.target.guid.clone(),
        namespace: world.target.namespace.clone(),
        ssh_exe_windows: "C:\\Windows\\System32\\OpenSSH\\ssh.exe".to_owned(),
        items: [ProjectionItem::DistributionGit].into_iter().collect(),
    };
    held.preview(&world.spec(None), &world.apply_intent(), &ctx)
        .expect("the first helper holds the lock and serves");
    let err = second
        .preview(&world.spec(None), &world.apply_intent())
        .unwrap_err();
    assert_eq!(
        err,
        heimdall_app::ports::PreviewError::Unavailable("wsl_helper_busy".to_owned())
    );
    drop(first);
    held.close();
    // Released with the first helper: the second account helper now serves.
    let (third, _) = world.writer(None);
    third
        .preview(&world.spec(None), &world.apply_intent())
        .expect("the lock went with the first helper");
}

// --- ⟨M04 U3b⟩ the same boundary through the setup driver and the store ---------------------

/// ⟨M04 U3b; ruling §9 item 2 (M04-D02)⟩ The proof through the product's own machinery, not a
/// test sink: Mode A enabled with `wsl_request`, the `distribution_git` item previewed and
/// applied through `Operations::setup` (the decision approved), the store's own `StageSink`
/// durable on the Windows side. The helper dies after the exchange of the commit step, before
/// its receipt is sent; the runtime "restarts" (a new `Operations` over the same store, whose
/// restart recovery cannot reach the distribution before the host is wired), and the host's
/// wiring drives the operation again: a **reconcile** through a fresh helper (never a second
/// `apply`) that settles it applied. Then the owner edits the distribution's Git file, a
/// rollback through the same driver removes Heimdall's block and keeps the edit, and the
/// cleaner routes the recorded generation's P_git to the distribution's helper, which removes
/// it and only it. The native session's files are untouched throughout.
mod driver {
    use super::*;
    use heimdall_app::ensure::NoStageHook;
    use heimdall_app::operations::Limits;
    use heimdall_app::ports::ResourceCleaner;
    use heimdall_app::{Attendance, Caller, OpError, Operations, OperationsConfig};
    use heimdall_contract::environment::EnvironmentRequest;
    use heimdall_contract::ids::{DecisionId, RequestId};
    use heimdall_contract::request::{DecideRequest, InteractionMode, Verdict};
    use heimdall_contract::setup::{SetupPlan, SetupRequest};
    use heimdall_contract::{Code, OperationState, Timestamp};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_localenv::env::Platform;
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::ProjectionConfig;
    use heimdall_localenv::projection::cleaner::ProjectionCleaner;
    use heimdall_runtime::service::wire_projection;
    use heimdall_runtime::wsl_wiring::NamespaceCleaner;
    use heimdall_store::{NoFaults, Store};
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

    fn t0() -> Timestamp {
        "2026-11-18T09:00:00Z".parse().unwrap()
    }

    fn own() -> EnvironmentId {
        EnvironmentId::from_random_bytes([0x5e; 16])
    }

    fn attended() -> Caller {
        Caller {
            context: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
                remote_client: None,
            },
            attendance: Attendance::Attended { since: t0() },
            interaction: InteractionMode::Interactive,
        }
    }

    /// The native session's side: its own scratch home, the store, the clock.
    struct Native {
        home: ScratchHome,
        store: Arc<Store>,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
        config: ProjectionConfig,
    }

    impl Native {
        fn new() -> Native {
            let home = ScratchHome::new();
            std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
            std::fs::write(&home.user_config, b"Host native\n    User me\n").unwrap();
            let store = Arc::new(
                Store::open(&home.state_dir.join("state.db"), Arc::new(NoFaults)).unwrap(),
            );
            let paths =
                SshPaths::with_test_override(home.git_home.clone(), home.root.join("etc-ssh"));
            let mut config =
                ProjectionConfig::new(paths, Platform::current(), home.config_dir.clone())
                    .with_state_dir(home.state_dir.clone());
            config.env = heimdall_localenv::env::Env::from_vars([
                ("HOME", home.git_home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ]);
            Native {
                home,
                store,
                clock: VirtualClock::at(t0()),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                config,
            }
        }

        async fn operations(&self) -> Operations {
            let writer = wire_projection(self.store.clone(), self.config.clone()).writer;
            Operations::start(OperationsConfig {
                store: self.store.clone(),
                clock: self.clock.clone(),
                time_sync: self.sync.clone(),
                time_policy: TimePolicy::default(),
                environment: own(),
                adapters: Vec::new(),
                stage_hook: Arc::new(NoStageHook),
                limits: Limits::default(),
                default_window: Duration::from_secs(12 * 3600),
                projection: Some(writer),
            })
            .await
            .unwrap()
        }

        fn tree(&self) -> BTreeMap<String, Vec<u8>> {
            let mut out = BTreeMap::new();
            for dir in [&self.home.ssh_dir, &self.home.git_home] {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for e in entries.flatten() {
                        if let Ok(bytes) = std::fs::read(e.path()) {
                            out.insert(e.path().display().to_string(), bytes);
                        }
                    }
                }
            }
            out
        }
    }

    /// Preview `intent` through the driver, submit it, approve a decision when one is asked
    /// for; the operation and the effect's (or the decision's) answer.
    async fn effect(
        ops: &Operations,
        intent: PreviewIntent,
        request: &str,
    ) -> (OperationId, Result<(), OpError>) {
        let plan: SetupPlan = serde_json::from_value(
            ops.setup(
                &attended(),
                SetupRequest::Preview {
                    intent: intent.clone(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("preview: {} {}", e.code, e.message))
            .data,
        )
        .unwrap();
        let req = match intent {
            PreviewIntent::Rollback { .. } => SetupRequest::Rollback {
                plan_digest: plan.plan_digest.clone(),
                request_id: RequestId::parse(request).unwrap(),
            },
            _ => SetupRequest::Apply {
                plan_digest: plan.plan_digest.clone(),
                request_id: RequestId::parse(request).unwrap(),
            },
        };
        match ops.setup(&attended(), req).await {
            Ok(c) => (c.operation_id.unwrap(), Ok(())),
            Err(e) if e.code == Code::ApprovalRequired => {
                let op = e.operation_id.clone().unwrap();
                let decision = e.next.decision_ref.clone().unwrap();
                let r = ops
                    .decide(
                        &attended(),
                        DecideRequest {
                            decision_id: DecisionId::parse(&decision).unwrap(),
                            verdict: Verdict::Approve,
                        },
                    )
                    .await
                    .map(drop);
                (op, r)
            }
            Err(e) => (e.operation_id.clone().unwrap(), Err(e)),
        }
    }

    fn op_state(store: &Store, op: &OperationId) -> OperationState {
        store
            .transaction(|tx| tx.operation(op))
            .unwrap()
            .unwrap()
            .state
    }

    #[tokio::test]
    async fn d02_distribution_git_through_the_setup_driver_restart_and_cleanup() {
        let world = World::new();
        let native = Native::new();
        let native_before = native.tree();
        let ssh_before = std::fs::read(world.ssh_config()).unwrap();
        let user_before = std::fs::read(world.global()).unwrap();
        let commit_step = preview_apply(&world)
            .files
            .iter()
            .position(|s| s.commit)
            .expect("the Git item has a commit step");

        // Process 1: Mode A enabled; the apply's helper dies after the commit step's
        // exchange, before that receipt is sent.
        let ops = native.operations().await;
        let (host, crashing) = world.host(Some(&format!("after_exchange:{commit_step}")));
        crashing.set_running(heimdall_app::ports::RunningState::Running);
        ops.set_distribution_host(Arc::new(host));
        let enabled = ops
            .wsl_request(
                &attended(),
                EnvironmentRequest::WslEnable {
                    distribution_guid: world.target.guid.clone(),
                    account: world.target.account.clone(),
                    mode_a: true,
                    mode_b: false,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("wsl enable: {} {}", e.code, e.message));
        let namespace: EnvironmentId =
            serde_json::from_value(enabled.data["environment"]["environment_id"].clone()).unwrap();
        assert_ne!(
            namespace,
            own(),
            "a distribution has its own projection namespace"
        );
        // Reading I-6: the owner's `inspect environments` lists it under that namespace, in
        // Mode A, its state from the host's running listing.
        let listed = ops
            .inspect(
                &attended(),
                heimdall_contract::request::InspectRequest {
                    subject: heimdall_contract::request::InspectSubject::Environments,
                    preview: None,
                    cwd: None,
                    redact: false,
                    select: None,
                    page: None,
                },
            )
            .await
            .unwrap()
            .data;
        let row = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["environment_id"] == serde_json::json!(namespace))
            .unwrap_or_else(|| panic!("the Mode A row: {listed}"))
            .clone();
        assert_eq!(row["kind"], "wsl_distribution");
        assert_eq!(row["state"], "active");
        assert_eq!(row["realization"]["modes"], serde_json::json!(["a"]));
        let (op, _) = effect(&ops, world.apply_intent(), "req_wsl_apply_1").await;
        assert!(
            op_state(&native.store, &op).is_unresolved(),
            "the lost channel leaves the operation for reconcile: {:?}",
            op_state(&native.store, &op)
        );
        drop(ops);

        // Process 2: restart recovery runs before the host is wired (it cannot reach the
        // distribution); wiring the host drives the operation again: one reconcile, through a
        // fresh helper, no second apply.
        let ops = native.operations().await;
        let (host, fresh) = world.host(None);
        fresh.set_running(heimdall_app::ports::RunningState::Running);
        let host = Arc::new(host);
        ops.set_distribution_host(host.clone());
        ops.redrive_distribution_setups(None, false).await;
        let after = native
            .store
            .transaction(|tx| tx.operation(&op))
            .unwrap()
            .unwrap();
        assert_eq!(
            after.state,
            OperationState::Succeeded,
            "{:?} spawned={} result={:?}",
            after.code,
            fresh.spawned(),
            after.result
        );
        assert_eq!(fresh.spawned(), 1, "one fresh helper reconciled it");
        let record = native
            .store
            .transaction(|tx| tx.projection_record(&namespace))
            .unwrap()
            .expect("the distribution's record, keyed by its namespace");
        assert_eq!(
            record.items.get(&ProjectionItem::Git).map(|i| i.generation),
            Some(1)
        );
        assert!(
            native
                .store
                .transaction(|tx| tx.projection_record(&own()))
                .unwrap()
                .is_none(),
            "the native session's record is untouched"
        );
        assert_eq!(
            world
                .effective_ssh_command()
                .as_deref()
                .map(|c| c.trim_matches('\'')),
            Some(world.ssh_exe.to_str().unwrap()),
            "the distribution's Git uses the in-box ssh.exe (P_git quotes the path)"
        );
        assert_eq!(std::fs::read(world.ssh_config()).unwrap(), ssh_before);

        // The owner edits the distribution's Git file later; a rollback through the driver
        // removes Heimdall's block and keeps the edit.
        let mut text = std::fs::read_to_string(world.global()).unwrap();
        text.push_str("[user]\n\tname = later-edit\n");
        std::fs::write(world.global(), &text).unwrap();
        let unrelated = world.heimdall_config().join("unrelated");
        std::fs::write(&unrelated, b"not heimdall's").unwrap();
        let (rolled, r) = effect(&ops, world.rollback_intent(), "req_wsl_rollback_1").await;
        r.unwrap_or_else(|e| panic!("rollback: {} {}", e.code, e.message));
        assert_eq!(op_state(&native.store, &rolled), OperationState::Succeeded);
        let after = std::fs::read_to_string(world.global()).unwrap();
        assert!(after.contains("name = later-edit"), "{after}");
        assert_eq!(world.effective_ssh_command(), None, "{after}");
        let user_after = std::fs::read(world.global()).unwrap();
        assert_ne!(user_after, user_before, "the later edit stays");

        // The cleaner routes the recorded generation's files to the distribution's helper.
        let absent: Vec<ManagedResource> = native
            .store
            .transaction(|tx| tx.projection_resources(&namespace))
            .unwrap()
            .into_iter()
            .filter(|r| r.desired == ResourceState::Absent)
            .collect();
        assert!(
            !absent.is_empty(),
            "the rollback hands P_git to the cleaner"
        );
        let native_cleaner: Arc<dyn ResourceCleaner> =
            Arc::new(ProjectionCleaner::new(native.config.clone()));
        let cleaner = NamespaceCleaner::new(
            native_cleaner,
            own(),
            native.store.clone(),
            Some(host as Arc<dyn DistributionHost>),
        );
        for r in &absent {
            cleaner
                .delete(r)
                .await
                .unwrap_or_else(|e| panic!("clean {}: {e}", r.locator));
        }
        assert!(
            !world.p_git().exists(),
            "P_git of the recorded generation is gone"
        );
        assert!(unrelated.exists(), "an unrelated file beside it stays");
        assert_eq!(
            native.tree(),
            native_before,
            "the native session is untouched"
        );
    }
}

// --- Mode B: the stream relay with the real helper (ADR-0010 §3 items 4-6, 8, 11-12; U4a) ----

/// A `Bridge` over [`DirectLauncher`] with the real helper binary, serving each stream with a
/// test signer (one Ed25519 key) through `serve_with_limits`; the Linux-side clients are the
/// real `ssh-add` and `ssh-keygen -Y sign` with `SSH_AUTH_SOCK` set to the binding's socket.
/// A client of another uid cannot be arranged here: it is the native row's (the helper's
/// `SO_PEERCRED` check).
mod bridge_relay {
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_ipc::PeerIdentity;
    use heimdall_ipc::signing::{
        ServeLimits, SignOutcome, Signer, SigningSession, serve_with_limits,
    };
    use heimdall_testkit::agent::FixtureKey;
    use heimdall_wsl::{Bridge, BridgePublic, StreamHandler, realized_paths};
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// One key; counts what reached it.
    struct RelaySigner {
        key: FixtureKey,
        listings: AtomicUsize,
        signs: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Signer for RelaySigner {
        async fn identities(&self, _session: &SigningSession) -> Vec<(Vec<u8>, String)> {
            self.listings.fetch_add(1, Ordering::SeqCst);
            vec![(self.key.public_blob(), self.key.comment().to_owned())]
        }

        async fn sign(
            &self,
            _session: &SigningSession,
            key_blob: &[u8],
            data: &[u8],
            _flags: u32,
        ) -> SignOutcome {
            self.signs.fetch_add(1, Ordering::SeqCst);
            if key_blob != self.key.public_blob() {
                return SignOutcome::failure();
            }
            match self.key.sign(data) {
                // The fixture models a grant with no signing gate.
                Some(sig) => SignOutcome::ungated_signature(&sig),
                None => SignOutcome::failure(),
            }
        }
    }

    /// Serves the tags that start with `b`; counts the streams it was given.
    struct Relay {
        rt: tokio::runtime::Handle,
        signer: Arc<RelaySigner>,
        served: AtomicUsize,
    }

    impl StreamHandler for Relay {
        fn serve(&self, tag: &str, stream: tokio::io::DuplexStream) -> bool {
            if !tag.starts_with('b') {
                return false;
            }
            self.served.fetch_add(1, Ordering::SeqCst);
            let signer = Arc::clone(&self.signer);
            self.rt.spawn(async move {
                let _ = serve_with_limits(
                    stream,
                    PeerIdentity::Unix {
                        uid: 0,
                        gid: 0,
                        pid: None,
                    },
                    EndpointRef {
                        kind: EndpointKind::UnixSocket,
                        locator: "bridge".to_owned(),
                    },
                    signer,
                    CancellationToken::new(),
                    ServeLimits::default(),
                )
                .await;
            });
            true
        }
    }

    struct Rig {
        world: World,
        runtime: tempfile::TempDir,
        relay: Arc<Relay>,
        stop: CancellationToken,
    }

    impl Rig {
        fn new() -> Rig {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let handle = rt.handle().clone();
            let stop = CancellationToken::new();
            let waiter = stop.clone();
            std::thread::spawn(move || rt.block_on(waiter.cancelled()));
            // A short path: the endpoint's socket path must fit `sun_path` on macOS.
            let runtime = tempfile::Builder::new()
                .prefix("hmr")
                .tempdir_in("/tmp")
                .unwrap();
            // An XDG runtime directory is the user's alone (0700), whatever the umask made the
            // temporary directory: Mode B refuses a run base another principal could replace
            // (M04-W2-R01).
            std::fs::set_permissions(
                runtime.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            // The comment is not a canary: `ssh-add -l` prints it.
            let key = FixtureKey::generate().with_comment("relay-test-key");
            Rig {
                world: World::new(),
                runtime,
                relay: Arc::new(Relay {
                    rt: handle,
                    signer: Arc::new(RelaySigner {
                        key,
                        listings: AtomicUsize::new(0),
                        signs: AtomicUsize::new(0),
                    }),
                    served: AtomicUsize::new(0),
                }),
                stop,
            }
        }

        fn launcher(&self) -> Arc<DirectLauncher> {
            let mut env = self.world.helper_env(None);
            env.push(("XDG_RUNTIME_DIR".into(), self.runtime.path().into()));
            DirectLauncher::new(
                PathBuf::from(helper_bin()),
                vec!["internal".into(), "wsl-helper".into()],
                env,
            )
        }

        fn start(&self) -> Bridge {
            Bridge::start(
                self.launcher(),
                &self.world.target,
                DistributionStart::Forbidden,
                self.relay.clone(),
            )
            .unwrap_or_else(|e| panic!("bridge start: {e}"))
        }

        fn realize(&self, bridge: &Bridge, tag: &str, generation: u64) -> heimdall_wsl::Realized {
            let paths = realized_paths(bridge.run_dir(), tag);
            bridge
                .realize(
                    tag,
                    generation,
                    BridgePublic {
                        files: vec![(
                            "id.pub".to_owned(),
                            self.relay.signer.key.public_line_without_comment(),
                        )],
                        ssh_config: format!(
                            "Host *\n  IdentityAgent {}\n  IdentitiesOnly yes\n",
                            paths.socket
                        ),
                        known_hosts: String::new(),
                    },
                    heimdall_contract::Timestamp::now()
                        .checked_add(Duration::from_secs(3600))
                        .unwrap(),
                )
                .unwrap_or_else(|e| panic!("realize {tag}: {e}"))
        }

        /// A Linux client program with the binding's socket as its agent.
        fn client(&self, program: &str, socket: &str) -> Command {
            let mut c = Command::new(find_program(program).expect("OpenSSH client tools"));
            c.env_clear()
                .env("SSH_AUTH_SOCK", socket)
                .env("HOME", self.world.account_home())
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&self.world.home.root)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            c
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            self.stop.cancel();
        }
    }

    /// Run a client to its end within 30 s.
    fn run(cmd: &mut Command) -> std::process::Output {
        let mut child = cmd.spawn().unwrap();
        let start = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("a client did not finish within 30 s");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn connect(socket: &str) -> UnixStream {
        let s = UnixStream::connect(socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s
    }

    /// What a raw client reads next: one whole agent frame, or `None` at the end of the stream.
    fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
        let mut head = [0u8; 4];
        s.read_exact(&mut head).ok()?;
        let mut body = vec![0u8; u32::from_be_bytes(head) as usize];
        s.read_exact(&mut body).ok()?;
        Some(body)
    }

    /// `bridge_relays_listing_and_signing_with_peer_and_classify_checks`: through a real helper
    /// process, `ssh-add -l` lists the binding's one key and `ssh-keygen -Y sign -U` gets a
    /// signature that verifies; a message `classify` refuses (add, remove, lock, another
    /// extension) is answered `SSH_AGENT_FAILURE` on Linux, never reaches the handler (which
    /// counts the streams and the signer's calls), and leaves the connection usable; a frame above
    /// 256 KiB closes the connection; the 65th connection of a binding is closed at once; the
    /// directory is 0700 and the socket 0600; and the runtime ending the session (EOF) makes the
    /// helper remove every endpoint and exit.
    #[test]
    fn bridge_relays_listing_and_signing_with_peer_and_classify_checks() {
        let rig = Rig::new();
        let bridge = rig.start();
        let run_dir = bridge.run_dir().to_owned();
        assert_eq!(Path::new(&run_dir), rig.runtime.path().join("heimdall"));
        let b1 = rig.realize(&bridge, "b1", 1);
        let dir = Path::new(&run_dir).join("b/b1");
        assert_eq!(b1.socket, dir.join("agent.sock").to_str().unwrap());
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join("agent.sock")), 0o600);
        }
        assert!(dir.join("ssh_config").exists() && dir.join("id.pub").exists());

        // The 65th connection of a binding is closed at once (nothing else is connected yet).
        let mut idle: Vec<UnixStream> = (0..64)
            .map(|_| {
                let s = UnixStream::connect(&b1.socket).unwrap();
                s.set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                s
            })
            .collect();
        let mut over = connect(&b1.socket);
        let mut byte = [0u8; 1];
        assert_eq!(
            over.read(&mut byte).unwrap(),
            0,
            "the 65th connection ends at once"
        );
        for s in &mut idle {
            let e = s.read(&mut byte).unwrap_err();
            assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "the first 64 stay open and idle: {e:?}"
            );
        }
        idle.clear();
        drop(over);

        // The Linux clients.
        let listed = run_ok(rig.client("ssh-add", &b1.socket).arg("-l"));
        let key = &rig.relay.signer.key;
        assert!(listed.contains(&key.fingerprint()), "{listed}");
        assert_eq!(
            listed.lines().count(),
            1,
            "only the binding's key: {listed}"
        );
        assert!(listed.contains("relay-test-key"), "{listed}");

        let msg = rig.world.home.root.join("msg.txt");
        std::fs::write(&msg, b"the bytes to sign").unwrap();
        let pubfile = rig.world.home.root.join("key.pub");
        key.write_public(&pubfile).unwrap();
        let signed = run(rig
            .client("ssh-keygen", &b1.socket)
            .args(["-Y", "sign", "-U", "-n", "heimdall-test", "-f"])
            .arg(&pubfile)
            .arg(&msg));
        assert!(
            signed.status.success(),
            "ssh-keygen -Y sign: {}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let sig = rig.world.home.root.join("msg.txt.sig");
        assert!(
            std::fs::read_to_string(&sig)
                .unwrap()
                .starts_with("-----BEGIN SSH SIGNATURE-----")
        );
        let mut verify = rig.client("ssh-keygen", &b1.socket);
        verify
            .args(["-Y", "check-novalidate", "-n", "heimdall-test", "-s"])
            .arg(&sig)
            .stdin(Stdio::piped());
        let mut child = verify.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"the bytes to sign")
            .unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
        assert_eq!(rig.relay.signer.signs.load(Ordering::SeqCst), 1);

        // The real `ssh-add` adding a key is refused (it exits non-zero).
        let private = rig.world.home.root.join("id_fixture");
        key.write_private(&private).unwrap();
        let before = (
            rig.relay.served.load(Ordering::SeqCst),
            rig.relay.signer.listings.load(Ordering::SeqCst),
            rig.relay.signer.signs.load(Ordering::SeqCst),
        );
        let added = run(rig.client("ssh-add", &b1.socket).arg(&private));
        assert!(!added.status.success(), "an add-identity is refused");

        // Raw messages: each refused one is answered here and never counted by the handler.
        let mut raw = connect(&b1.socket);
        let handler_saw = || {
            (
                rig.relay.served.load(Ordering::SeqCst),
                rig.relay.signer.listings.load(Ordering::SeqCst),
                rig.relay.signer.signs.load(Ordering::SeqCst),
            )
        };
        let after_add = handler_saw();
        for body in [
            &[17u8, 0, 0, 0, 0][..],                 // SSH_AGENTC_ADD_IDENTITY
            &[18, 0, 0, 0, 0][..],                   // SSH_AGENTC_REMOVE_IDENTITY
            &[19][..],                               // SSH_AGENTC_REMOVE_ALL_IDENTITIES
            &[22, 0, 0, 0, 0][..],                   // SSH_AGENTC_LOCK
            &[27, 0, 0, 0, 3, b'x', b'@', b'y'][..], // an extension that is not session-bind
            &[0xff][..],                             // a type nobody defines
        ] {
            raw.write_all(&frame(body)).unwrap();
            assert_eq!(
                read_frame(&mut raw).as_deref(),
                Some(&[5u8][..]),
                "{body:?}"
            );
        }
        assert_eq!(handler_saw(), after_add, "nothing refused reached Windows");
        assert_eq!(
            after_add, before,
            "not even a stream was opened for the refused add"
        );
        // The same connection still serves an allowed request, which does reach the signer.
        raw.write_all(&frame(&[11])).unwrap();
        let answer = read_frame(&mut raw).expect("an identities answer");
        assert_eq!(answer[0], 12);
        assert_eq!(handler_saw().1, before.1 + 1);
        drop(raw);

        // A frame above 256 KiB closes the connection with no reply.
        let mut big = connect(&b1.socket);
        big.write_all(&u32::try_from((256 << 10) + 1).unwrap().to_be_bytes())
            .unwrap();
        assert!(read_frame(&mut big).is_none());

        // EOF from Windows: the helper removes every endpoint and exits.
        assert!(bridge.alive());
        drop(bridge);
        assert!(!dir.exists(), "the endpoint directory is gone");
        assert!(
            UnixStream::connect(&b1.socket).is_err(),
            "nothing listens any more"
        );
    }

    fn run_ok(cmd: &mut Command) -> String {
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// A helper killed by its exact PID leaves a dead socket (and its files) behind; the next
    /// helper of the account removes that directory by the stale-socket rule when it first
    /// realizes, and serves its own endpoint.
    #[test]
    fn bridge_restart_after_a_killed_helper_removes_the_stale_endpoint() {
        let rig = Rig::new();
        let first = rig.start();
        let run_dir = first.run_dir().to_owned();
        let old = rig.realize(&first, "b1", 1);
        assert!(Path::new(&old.socket).exists());
        let status = Command::new("kill")
            .args(["-KILL", &first.helper_pid().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let start = Instant::now();
        while first.alive() {
            assert!(start.elapsed() < Duration::from_secs(10), "the helper died");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            Path::new(&old.socket).exists(),
            "a killed helper leaves its socket"
        );
        assert!(
            UnixStream::connect(&old.socket).is_err(),
            "and nobody listens"
        );

        let second = rig.start();
        assert_eq!(second.run_dir(), run_dir);
        let fresh = rig.realize(&second, "b2", 1);
        assert!(
            !Path::new(&old.socket).exists() && !Path::new(&run_dir).join("b/b1").exists(),
            "the stale directory was removed"
        );
        let listed = run_ok(rig.client("ssh-add", &fresh.socket).arg("-l"));
        assert!(
            listed.contains(&rig.relay.signer.key.fingerprint()),
            "{listed}"
        );
        assert_eq!(second.realized().unwrap(), vec![("b2".to_owned(), 1)]);
        drop(first);
    }
}
