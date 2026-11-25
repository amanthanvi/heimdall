//! M04 U1 (m04-plan U1; ADR-0010 §1 item 2, §6 item 1): the login entries against scratch
//! roots.
//!
//! * `<platform>::login_entry_install_remove_round_trip`: each host's own mechanism, written
//!   to a scratch root and removed again. Windows: an injected scratch key under
//!   `HKCU\Software\HeimdallTest\<unique>` (never the real Run key), read back with `reg
//!   query`, deleted at the end. macOS: a plist in a scratch directory bootstrapped into the
//!   real `gui/<uid>` domain under a unique label and **always** booted out (the one allowed
//!   exception, m04-plan §0; nothing is written under `~/Library`). Linux: a scratch unit
//!   directory, file only (nothing is installed in the owner's account; the real
//!   `systemctl` row is `linux_login_entry_starts_runtime_at_next_login`). Each leaves a
//!   foreign entry of a similar name alone.
//! * `the_login_entry_setup_item_*`: the setup item through the real `Operations` over a
//!   scratch port (every platform): the plan, the attended-only effect, a stale plan, a
//!   conflict, the items it is not mixed with, the owned-resource record, and `inspect
//!   capabilities` → `login_start`.
//!
//! Disposable fixtures only: never the account's Run key, LaunchAgents or systemd units.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::{Limits, login_resource_id};
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::request::{InspectRequest, InspectSubject, InteractionMode};
use heimdall_contract::setup::{PlanDigest, PreviewIntent, ProjectionItem, SetupRequest};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::resource::ResourceState;
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_runtime::autostart::port::HostLoginPort;
use heimdall_store::Store;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

fn unique(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("hmtest-{tag}-{}-{nanos:x}", std::process::id())
}

// =================================================================================
// The round trip, per platform
// =================================================================================

#[cfg(target_os = "macos")]
mod macos {
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;

    use heimdall_runtime::autostart::macos::LaunchAgentHost;
    use heimdall_runtime::autostart::render::{self, LoginCommand};
    use heimdall_runtime::autostart::{
        EntryState, InstallOutcome, LoginHost, ProcessRunner, RemoveOutcome,
    };

    /// Boots the unique label out of `gui/<uid>` when dropped, so a failing assertion
    /// never leaves a job loaded in the owner's launchd session.
    struct BootOut {
        domain_target: String,
    }

    impl Drop for BootOut {
        fn drop(&mut self) {
            let _ = Command::new("/bin/launchctl")
                .args(["bootout", &self.domain_target])
                .output();
        }
    }

    fn loaded(target: &str) -> bool {
        Command::new("/bin/launchctl")
            .args(["print", target])
            .output()
            .unwrap()
            .status
            .success()
    }

    #[test]
    fn login_entry_install_remove_round_trip() {
        let uid = heimdall_ipc::unix::current_uid();
        let label = format!("io.github.amanthanvi.heimdall.{}", super::unique("mac"));
        let target = format!("gui/{uid}/{label}");
        let dir = tempfile::tempdir().unwrap();
        let _boot_out = BootOut {
            domain_target: target.clone(),
        };
        // The job runs `true service run --login` once at load and exits 0; nothing of
        // Heimdall starts.
        let command = LoginCommand::new(Path::new("/usr/bin/true")).unwrap();
        let host = LaunchAgentHost::new(dir.path(), &label, uid, Some(Arc::new(ProcessRunner)));
        let plist = dir.path().join(format!("{label}.plist"));
        let foreign = dir.path().join(format!("{label}-other.plist"));
        std::fs::write(&foreign, "<plist><dict/></plist>").unwrap();

        assert_eq!(host.observe().unwrap(), EntryState::Absent);
        assert!(!loaded(&target));
        assert_eq!(host.install(&command).unwrap(), InstallOutcome::Created);
        assert_eq!(
            std::fs::read_to_string(&plist).unwrap(),
            render::launch_agent_plist(&label, &command),
            "the plist is exactly the rendering"
        );
        assert!(loaded(&target), "bootstrapped into gui/{uid}");
        assert_eq!(host.observe().unwrap(), EntryState::Owned(command.clone()));

        assert_eq!(host.remove().unwrap(), RemoveOutcome::Removed);
        assert!(!plist.exists());
        assert!(!loaded(&target), "booted out");
        assert_eq!(
            std::fs::read_to_string(&foreign).unwrap(),
            "<plist><dict/></plist>",
            "an entry of a similar name is untouched"
        );
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Absent);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;

    use heimdall_runtime::autostart::linux::SystemdUserHost;
    use heimdall_runtime::autostart::render::{self, LoginCommand};
    use heimdall_runtime::autostart::{EntryState, InstallOutcome, LoginHost, RemoveOutcome};

    #[test]
    fn login_entry_install_remove_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let unit_dir = dir.path().join("systemd").join("user");
        std::fs::create_dir_all(&unit_dir).unwrap();
        let foreign = unit_dir.join("heimdall-other.service");
        std::fs::write(&foreign, "[Service]\nExecStart=/bin/true\n").unwrap();
        let host = SystemdUserHost::new(&unit_dir, None);
        let command = LoginCommand::new(Path::new("/opt/heimdall/bin/heimdall")).unwrap();
        assert_eq!(host.observe().unwrap(), EntryState::Absent);
        assert_eq!(host.install(&command).unwrap(), InstallOutcome::Created);
        assert_eq!(
            std::fs::read_to_string(unit_dir.join("heimdall.service")).unwrap(),
            render::systemd_unit(&command)
        );
        assert_eq!(host.observe().unwrap(), EntryState::Owned(command.clone()));
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Removed);
        assert!(!unit_dir.join("heimdall.service").exists());
        assert_eq!(
            std::fs::read_to_string(&foreign).unwrap(),
            "[Service]\nExecStart=/bin/true\n",
            "an entry of a similar name is untouched"
        );
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;
    use std::process::Command;

    use heimdall_runtime::autostart::render::{self, LoginCommand};
    use heimdall_runtime::autostart::windows::{RunValueHost, delete_scratch_key};
    use heimdall_runtime::autostart::{EntryState, InstallOutcome, LoginHost, RemoveOutcome};

    /// Deletes the scratch key when dropped (the key is under `HKCU\Software\HeimdallTest\`).
    struct Scratch(String);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = Command::new("reg")
                .args(["delete", &format!(r"HKCU\{}", self.0), "/f"])
                .output();
            let _ = delete_scratch_key(&self.0);
        }
    }

    /// `reg query` of one value: its text, or `None` when it does not exist.
    fn query(key: &str, name: &str) -> Option<String> {
        let out = Command::new("reg")
            .args(["query", &format!(r"HKCU\{key}"), "/v", name])
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn login_entry_install_remove_round_trip() {
        let subkey = format!(r"Software\HeimdallTest\{}", super::unique("win"));
        let _scratch = Scratch(subkey.clone());
        let host = RunValueHost::new(&subkey, "hmtest");
        let command =
            LoginCommand::new(Path::new(r"C:\Program Files\Heimdall\heimdall.exe")).unwrap();
        // A foreign value of a similar name, written by another tool.
        let added = Command::new("reg")
            .args([
                "add",
                &format!(r"HKCU\{subkey}"),
                "/v",
                "Heimdall-hmtestx",
                "/t",
                "REG_SZ",
                "/d",
                "foreign",
                "/f",
            ])
            .output()
            .unwrap();
        assert!(added.status.success());

        assert_eq!(host.observe().unwrap(), EntryState::Absent);
        assert_eq!(host.install(&command).unwrap(), InstallOutcome::Created);
        let text = query(&subkey, "Heimdall-hmtest").expect("the value exists");
        assert!(text.contains("REG_SZ"), "{text}");
        assert!(text.contains(&render::run_value_data(&command)), "{text}");
        assert_eq!(host.observe().unwrap(), EntryState::Owned(command.clone()));

        assert_eq!(host.remove().unwrap(), RemoveOutcome::Removed);
        assert!(query(&subkey, "Heimdall-hmtest").is_none());
        assert!(
            query(&subkey, "Heimdall-hmtestx").is_some_and(|t| t.contains("foreign")),
            "an entry of a similar name is untouched"
        );
        assert_eq!(host.remove().unwrap(), RemoveOutcome::Absent);
    }
}

// =================================================================================
// The setup item through the real Operations
// =================================================================================

/// A scratch root for the host's own mechanism, removed when dropped.
struct Root {
    path: std::path::PathBuf,
    _dir: Option<tempfile::TempDir>,
}

impl Root {
    fn new() -> Self {
        if cfg!(windows) {
            Self {
                path: std::path::PathBuf::from(format!(
                    r"Software\HeimdallTest\{}",
                    unique("setup")
                )),
                _dir: None,
            }
        } else {
            let dir = tempfile::tempdir().unwrap();
            Self {
                path: dir.path().to_owned(),
                _dir: Some(dir),
            }
        }
    }
}

#[cfg(windows)]
impl Drop for Root {
    fn drop(&mut self) {
        let key = self.path.to_string_lossy().into_owned();
        let _ = std::process::Command::new("reg")
            .args(["delete", &format!(r"HKCU\{key}"), "/f"])
            .output();
        let _ = heimdall_runtime::autostart::windows::delete_scratch_key(&key);
    }
}

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn owner() -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
        remote_client: None,
    }
}

fn unattended() -> Caller {
    Caller::unattended(owner())
}

fn attended() -> Caller {
    Caller {
        context: owner(),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn entry_intent(rollback: bool) -> PreviewIntent {
    let items = [ProjectionItem::LoginEntry].into_iter().collect();
    if rollback {
        PreviewIntent::Rollback {
            keep_key_files: false,
            items,
            distribution: None,
        }
    } else {
        PreviewIntent::Apply {
            include_git: false,
            items,
            distribution: None,
        }
    }
}

fn digest(data: &serde_json::Value) -> PlanDigest {
    PlanDigest::parse(data["plan_digest"].as_str().unwrap()).unwrap()
}

fn rid(n: u8) -> heimdall_contract::ids::RequestId {
    heimdall_contract::ids::RequestId::parse(&format!("req-login-{n}")).unwrap()
}

/// The entry's kind on this host, as `inspect capabilities` words it.
const KIND: &str = if cfg!(windows) {
    "run_value"
} else if cfg!(target_os = "macos") {
    "launch_agent"
} else {
    "systemd_user"
};

/// Write a foreign entry at Heimdall's name for `state_dir` in `root` (a plist or unit
/// file; a registry value through `reg add`).
fn write_foreign(root: &Root, token: &str) -> String {
    #[cfg(windows)]
    {
        let name = format!("Heimdall-{token}");
        let added = std::process::Command::new("reg")
            .args([
                "add",
                &format!(r"HKCU\{}", root.path.display()),
                "/v",
                &name,
                "/t",
                "REG_SZ",
                "/d",
                "C:\\other\\tool.exe --flag",
                "/f",
            ])
            .output()
            .unwrap();
        assert!(added.status.success());
        name
    }
    #[cfg(not(windows))]
    {
        let file = if cfg!(target_os = "macos") {
            format!("io.github.amanthanvi.heimdall.{token}.plist")
        } else {
            "heimdall.service".to_owned()
        };
        std::fs::write(root.path.join(&file), "foreign data\n").unwrap();
        file
    }
}

fn foreign_is_intact(root: &Root, name: &str) -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("reg")
            .args([
                "query",
                &format!(r"HKCU\{}", root.path.display()),
                "/v",
                name,
            ])
            .output()
            .unwrap()
            .status
            .success()
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string(root.path.join(name)).is_ok_and(|t| t == "foreign data\n")
    }
}

#[tokio::test]
async fn the_login_entry_setup_item_previews_applies_rolls_back_and_refuses() {
    let root = Root::new();
    let state_dir = std::path::PathBuf::from(if cfg!(windows) {
        r"C:\hm-test\state"
    } else {
        "/hm-test/state"
    });
    let env = EnvironmentId::from_random_bytes([7; 16]);
    let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
    let ops = Operations::start(OperationsConfig {
        store: store.clone(),
        clock: VirtualClock::at(t0()),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env.clone(),
        adapters: Vec::new(),
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: Duration::from_secs(12 * 3600),
        projection: None,
    })
    .await
    .unwrap();
    let setup = |c: &Caller, r: SetupRequest| {
        let ops = ops.clone();
        let c = c.clone();
        async move { ops.setup(&c, r).await }
    };
    let capabilities = || {
        let ops = ops.clone();
        async move {
            ops.inspect(
                &unattended(),
                InspectRequest {
                    subject: InspectSubject::Capabilities,
                    preview: None,
                    cwd: None,
                    redact: false,
                    select: None,
                    page: None,
                },
            )
            .await
            .unwrap()
            .data
        }
    };
    let preview = |intent: PreviewIntent| setup(&unattended(), SetupRequest::Preview { intent });

    // Not wired: `login_start` reads none, and the item is unavailable (nothing planned).
    assert_eq!(
        capabilities().await["login_start"],
        serde_json::json!({"kind": "none", "installed": false})
    );
    let e = preview(entry_intent(false)).await.unwrap_err();
    assert_eq!(
        (e.code, e.reason.as_deref()),
        (
            Code::CapabilityUnavailable,
            Some(reason::DRIVER_UNAVAILABLE)
        )
    );

    let port = HostLoginPort::system(&state_dir, Some(&root.path));
    let token = heimdall_runtime::autostart::installation_token(&state_dir);
    ops.set_login_entry(Arc::new(port));
    assert_eq!(
        capabilities().await["login_start"],
        serde_json::json!({"kind": KIND, "installed": false})
    );
    assert!(
        capabilities().await["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "environments/1")
    );

    // The plan: no file, no consent, one finding naming the kind, the location and the exact
    // data. Previewing writes nothing.
    let plan = preview(entry_intent(false)).await.unwrap().data;
    assert_eq!(plan["consent"]["decision_required"], false);
    assert_eq!(plan["files"], serde_json::json!([]));
    let message = plan["findings"][0]["message"].as_str().unwrap();
    assert!(
        message.contains(KIND) && message.contains("service run --login"),
        "{message}"
    );
    assert_eq!(capabilities().await["login_start"]["installed"], false);

    // Attended only: an unattended session is refused, nothing is written.
    let e = setup(
        &unattended(),
        SetupRequest::Apply {
            plan_digest: digest(&plan),
            request_id: rid(1),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    assert_eq!(capabilities().await["login_start"]["installed"], false);

    // A plan is stale once the entry changed since it was shown.
    let direct = HostLoginPort::system(&state_dir, Some(&root.path));
    use heimdall_app::ports::LoginEntryPort as _;
    direct.install().unwrap();
    let e = setup(
        &attended(),
        SetupRequest::Apply {
            plan_digest: digest(&plan),
            request_id: rid(2),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{}", e.message);
    assert!(e.message.contains("stale"), "{}", e.message);
    direct.remove().unwrap();

    // Apply, attended: written, recorded as an owned resource, visible in `login_start`.
    let plan = preview(entry_intent(false)).await.unwrap().data;
    let applied = setup(
        &attended(),
        SetupRequest::Apply {
            plan_digest: digest(&plan),
            request_id: rid(3),
        },
    )
    .await
    .unwrap()
    .data;
    assert_eq!(applied["login_entry"]["effect"], "created");
    assert_eq!(applied["items"][0]["item"], "login_entry");
    assert_eq!(capabilities().await["login_start"]["installed"], true);
    let location = applied["login_entry"]["location"]
        .as_str()
        .unwrap()
        .to_owned();
    let record = store
        .transaction(|tx| tx.resource(&login_resource_id(&env, &location)))
        .unwrap()
        .expect("the owned resource record");
    assert_eq!(record.desired, ResourceState::Present);
    assert_eq!(
        record.kind,
        heimdall_domain::resource::ResourceKind::LoginEntry
    );

    // The same plan again is a no-op by exact data (the plan is stale: state changed).
    let again = preview(entry_intent(false)).await.unwrap().data;
    let second = setup(
        &attended(),
        SetupRequest::Apply {
            plan_digest: digest(&again),
            request_id: rid(4),
        },
    )
    .await
    .unwrap()
    .data;
    assert_eq!(second["login_entry"]["effect"], "unchanged");

    // Rollback removes it, by exact data.
    let plan = preview(entry_intent(true)).await.unwrap().data;
    let removed = setup(
        &attended(),
        SetupRequest::Rollback {
            plan_digest: digest(&plan),
            request_id: rid(5),
        },
    )
    .await
    .unwrap()
    .data;
    assert_eq!(removed["login_entry"]["effect"], "removed");
    assert_eq!(capabilities().await["login_start"]["installed"], false);
    let record = store
        .transaction(|tx| tx.resource(&login_resource_id(&env, &location)))
        .unwrap()
        .unwrap();
    assert_eq!(record.desired, ResourceState::Absent);
    assert_eq!(record.generation.0, 3, "created, unchanged, removed");

    // A foreign entry at Heimdall's name: the plan says conflict, the apply and the rollback
    // are refused `login_entry_conflict`, and it is never touched.
    let name = write_foreign(&root, &token);
    for rollback in [false, true] {
        let plan = preview(entry_intent(rollback)).await.unwrap().data;
        assert_eq!(plan["findings"][0]["severity"], "problem");
        assert_eq!(plan["findings"][0]["reason"], "login_entry_conflict");
        let request = if rollback {
            SetupRequest::Rollback {
                plan_digest: digest(&plan),
                request_id: rid(6 + u8::from(rollback)),
            }
        } else {
            SetupRequest::Apply {
                plan_digest: digest(&plan),
                request_id: rid(6),
            }
        };
        let e = setup(&attended(), request).await.unwrap_err();
        assert_eq!(
            (e.code, e.reason.as_deref()),
            (Code::ConfigConflict, Some(reason::LOGIN_ENTRY_CONFLICT)),
            "rollback={rollback}"
        );
        assert!(foreign_is_intact(&root, &name), "rollback={rollback}");
    }

    // The login entry is its own step: mixed with another item it is a usage error, and the
    // distribution items stay refused.
    let mixed = PreviewIntent::Apply {
        include_git: true,
        items: [ProjectionItem::LoginEntry].into_iter().collect(),
        distribution: None,
    };
    assert_eq!(preview(mixed).await.unwrap_err().code, Code::UsageError);
    let both = PreviewIntent::Rollback {
        keep_key_files: false,
        items: [ProjectionItem::LoginEntry, ProjectionItem::Ssh]
            .into_iter()
            .collect(),
        distribution: None,
    };
    assert_eq!(preview(both).await.unwrap_err().code, Code::UsageError);
    let distribution = PreviewIntent::Apply {
        include_git: false,
        items: [ProjectionItem::LoginEntry, ProjectionItem::DistributionGit]
            .into_iter()
            .collect(),
        distribution: None,
    };
    let e = preview(distribution).await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::DRIVER_UNAVAILABLE));
}
