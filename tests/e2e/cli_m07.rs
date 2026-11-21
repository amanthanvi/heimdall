//! Standalone CLI access and stop through a disposable OpenSSH installation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::{Attendance, Caller, OpError, Operations};
use heimdall_contract::catalog::{
    CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
    IdentitySourceSpec, IdentitySpec, ProfileSpec,
};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, IdentityId, ProfileId, RequestId,
};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{
    AccessPairRef, DecideRequest, InteractionMode, PolicyAction, Verdict,
};
use heimdall_contract::setup::{PreviewIntent, SetupPlan, SetupRequest};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::ProjectionConfig;
use heimdall_runtime::config::{Config, Paths};
use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

const TIMEOUT: Duration = Duration::from_secs(30);

fn account(sshd: &LoopbackSshd) -> AccountName {
    if let Some(account) = sshd.account() {
        return AccountName::parse(account).unwrap();
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .env_clear()
            .output()
            .unwrap();
        assert!(out.status.success());
        AccountName::parse(std::str::from_utf8(&out.stdout).unwrap().trim()).unwrap()
    }
    #[cfg(windows)]
    panic!("the fixture server did not report its account");
}

fn owner(root: &Path) -> Caller {
    #[cfg(unix)]
    let principal = {
        use std::os::unix::fs::MetadataExt as _;
        PrincipalRef::UnixUser {
            uid: std::fs::metadata(root).unwrap().uid(),
        }
    };
    #[cfg(windows)]
    let principal: PrincipalRef = {
        assert!(root.is_dir());
        heimdall_testkit::win::current_principal().unwrap()
    };
    Caller {
        context: CallerContext {
            principal,
            role: ClientRole::Owner,
        },
        attendance: Attendance::Attended {
            since: heimdall_contract::Timestamp::now(),
        },
        interaction: InteractionMode::Interactive,
    }
}

async fn approve(ops: &Operations, caller: &Caller, pending: OpError) {
    let id = pending.next.decision_ref.expect("pending owner decision");
    ops.decide(
        caller,
        DecideRequest {
            decision_id: DecisionId::parse(&id).unwrap(),
            verdict: Verdict::Approve,
        },
    )
    .await
    .unwrap();
}

async fn seed(
    ops: &Operations,
    caller: &Caller,
    sshd: &LoopbackSshd,
    key: &FixtureKey,
    agent: &FakeAgent,
) {
    let rid = |value| RequestId::parse(value).unwrap();
    let endpoint = EndpointRef {
        kind: if cfg!(windows) {
            EndpointKind::NamedPipe
        } else {
            EndpointKind::UnixSocket
        },
        locator: agent.endpoint().locator().to_str().unwrap().to_owned(),
    };
    let adopted = ops
        .catalog(
            caller,
            CatalogRequest::AdoptIdentity {
                identity: IdentitySpec {
                    source: IdentitySourceSpec::NativeAgent { endpoint },
                    public_key: key.public_line_without_comment(),
                    label: None,
                },
                request_id: rid("adopt-m07"),
            },
        )
        .await
        .unwrap();
    let identity = IdentityId::parse(adopted.data["identity_id"].as_str().unwrap()).unwrap();
    let destination = DestinationId::parse("dst-lab").unwrap();
    let account = account(sshd);
    ops.catalog(
        caller,
        CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: destination.clone(),
                alias: "lab".into(),
                definition: DestinationDefinitionSpec::Managed {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: account.clone(),
                    identity: identity.clone(),
                    jump: None,
                },
                label: None,
            },
            request_id: rid("destination-m07"),
        },
    )
    .await
    .unwrap();
    let profile = ProfileId::parse("lab-access").unwrap();
    ops.catalog(
        caller,
        CatalogRequest::UpsertProfile {
            profile: ProfileSpec {
                id: profile.clone(),
                pairs: [AccessPairRef {
                    destination,
                    account,
                }]
                .into_iter()
                .collect(),
                label: None,
            },
            request_id: rid("profile-m07"),
        },
    )
    .await
    .unwrap();
    let preview = ops
        .setup(
            caller,
            SetupRequest::Preview {
                intent: PreviewIntent::Apply {
                    include_git: false,
                    items: Default::default(),
                    distribution: None,
                },
            },
        )
        .await
        .unwrap();
    let plan: SetupPlan = serde_json::from_value(preview.data).unwrap();
    let apply = SetupRequest::Apply {
        plan_digest: plan.plan_digest,
        request_id: rid("apply-m07"),
    };
    if let Err(pending) = ops.setup(caller, apply.clone()).await {
        approve(ops, caller, pending).await;
        ops.setup(caller, apply).await.unwrap();
    }
    let declare = CatalogRequest::DeclareInteraction {
        identity,
        interaction: DeclaredInteraction::None,
        request_id: rid("declare-m07"),
    };
    approve(
        ops,
        caller,
        ops.catalog(caller, declare.clone()).await.unwrap_err(),
    )
    .await;
    ops.catalog(caller, declare).await.unwrap();
    approve(
        ops,
        caller,
        ops.policy(
            caller,
            PolicyAction::Create {
                profile,
                environments: [ops.environment().clone()].into_iter().collect(),
                max_window: None,
                default: false,
            },
        )
        .await
        .unwrap_err(),
    )
    .await;
}

fn cli(home: &ScratchHome, heimdall_home: &Path, args: &[&str]) -> Command {
    // A native run copies the binary elsewhere and names it (`HEIMDALL_E2E_BIN`), as the
    // other e2e suites do.
    let bin = std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned());
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("HEIMDALL_HOME", heimdall_home)
        .env("HEIMDALL_TEST_SSH_HOME", &home.git_home)
        .env("HOME", home.root.join("cli-home"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", home.git_home.join(".gitconfig"))
        .env("LANG", "C")
        .env("TERM", "dumb")
        .current_dir(&home.root)
        .args(["--json", "--non-interactive"])
        .args(args)
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    #[cfg(windows)]
    {
        let windows = std::env::var_os("SystemRoot").expect("SystemRoot");
        let system = PathBuf::from(&windows).join("System32");
        cmd.env(
            "PATH",
            std::env::join_paths([system.clone(), system.join("OpenSSH")]).unwrap(),
        )
        .env("SystemRoot", windows)
        .env("USERPROFILE", home.root.join("cli-home"))
        .env("TEMP", &home.root)
        .env("TMP", &home.root);
    }
    cmd
}

#[tokio::test(flavor = "current_thread")]
async fn cli_standalone_access_and_stop() {
    let home = ScratchHome::new();
    std::fs::create_dir(home.git_home.join("etc-ssh")).unwrap();
    std::fs::create_dir(home.root.join("cli-home")).unwrap();
    let root = home.root.join("heimdall");
    let key = FixtureKey::generate().with_comment("m07-fixture");
    let agent = FakeAgent::start(
        Endpoint::in_scratch(home.scratch(), "access").unwrap(),
        FakeAgentConfig {
            keys: vec![key.clone()],
            mode: AgentMode::Normal,
        },
    );
    let sshd = LoopbackSshd::start(
        home.scratch(),
        SshdConfig {
            authorized: vec![key.public().clone()],
            ..SshdConfig::default()
        },
    )
    .unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();

    let paths = Paths::under(&root);
    let mut projection = ProjectionConfig::new(
        SshPaths::with_test_override(home.git_home.clone(), home.git_home.join("etc-ssh")),
        Platform::current(),
        paths.config_dir.clone(),
    )
    .with_state_dir(paths.state_dir.clone());
    projection.env = Env::from_vars([("HOME", home.git_home.display().to_string())]);
    let mut options = ServiceOptions::with_clock(
        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
        heimdall_testkit::ScriptedTimeSync::new(heimdall_domain::time::SyncStatus::Synchronized),
    );
    options.projection = ProjectionWiring::Config(Box::new(projection));
    options.existing_access = true;
    let shutdown = CancellationToken::new();
    let service = Service::start_with(paths, Config::default(), options, shutdown.clone())
        .await
        .unwrap();
    seed(service.operations(), &owner(&root), &sshd, &key, &agent).await;
    let serving = tokio::spawn(service.run());

    // The runtime prepares the adopted agent identity. The direct SSH probe pins
    // the same fixture key in scratch and disables all agent fallback.
    let identity = home.root.join("login-key");
    key.write_private(&identity).unwrap();
    let global: PathBuf = if cfg!(windows) {
        home.global_known_hosts.clone()
    } else {
        "/dev/null".into()
    };
    let run = || {
        let mut cmd = cli(
            &home,
            &root,
            &[
                "run",
                "--profile",
                "lab-access",
                "--work-id",
                "lab-job",
                "--request-id",
                "lab-run",
                "--",
            ],
        );
        cmd.arg(find_program("ssh").expect("ssh client"))
            .arg("-F")
            .arg(&home.user_config)
            .args([
                "-oIdentityFile=none",
                "-oIdentitiesOnly=yes",
                "-oIdentityAgent=none",
                "-oCertificateFile=none",
                "-oControlMaster=no",
                "-oControlPath=none",
                "-oBatchMode=yes",
                "-oStrictHostKeyChecking=yes",
            ])
            .arg(format!(
                "-oUserKnownHostsFile={}",
                home.known_hosts.display()
            ))
            .arg(format!("-oGlobalKnownHostsFile={}", global.display()))
            .arg("-i")
            .arg(&identity)
            .args(["lab", "printf 'fixture login\\n'; cat"]);
        cmd
    };
    let mut running = run()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut login = String::new();
    let mut stdout = BufReader::new(running.stdout.take().unwrap());
    tokio::time::timeout(TIMEOUT, stdout.read_line(&mut login))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(login.trim_end(), "fixture login");
    let during = tokio::time::timeout(
        TIMEOUT,
        cli(&home, &root, &["inspect", "bindings"]).output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(during.status.success());
    let bindings: Value = serde_json::from_slice(&during.stdout).unwrap();
    assert!(
        bindings["data"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|binding| { binding["work_id"] == "lab-job" && binding["state"] == "active" })
    );

    let stopped = tokio::time::timeout(
        TIMEOUT,
        cli(&home, &root, &["access", "stop", "--work", "lab-job"]).output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(stopped.status.success());
    let answer: Value = serde_json::from_slice(&stopped.stdout).unwrap();
    assert_eq!(answer["data"]["local_applied"], true);

    let refused = tokio::time::timeout(TIMEOUT, run().stdin(Stdio::null()).output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    let refusal: Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(refusal["code"], "CREDENTIAL_EXPIRED");
    assert_eq!(refusal["data"]["error"]["reason"], "work_stopped");
    let accepted = sshd.accepted_log();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].fingerprint, key.fingerprint());

    drop(running.stdin.take());
    let first = tokio::time::timeout(TIMEOUT, running.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(first.status.success());
    for out in [&first, &during, &stopped, &refused] {
        for bytes in [&out.stdout, &out.stderr] {
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(bytes));
        }
    }
    shutdown.cancel();
    tokio::time::timeout(TIMEOUT, serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
