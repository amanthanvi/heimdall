//! Standalone CLI access and stop through a disposable OpenSSH installation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
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
#[cfg(unix)]
use heimdall_testkit::home::find_program;
use heimdall_testkit::home::{ScratchHome, ssh_option_path};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

const TIMEOUT: Duration = Duration::from_secs(30);

fn account(sshd: &LoopbackSshd, _home: &ScratchHome) -> AccountName {
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
        verify(_home, &out, out.status.success(), "fixture account lookup");
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
            remote_client: None,
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
    home: &ScratchHome,
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
    let account = account(sshd, home);
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

fn unused_fixture_stores(root: &Path) -> [PathBuf; 2] {
    let stores = [root.join("mgmt-store"), root.join("iroh-key-store")];
    for store in &stores {
        assert!(
            store
                .symlink_metadata()
                .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound),
            "unexpected fixture store"
        );
    }
    stores
}

fn cli(home: &ScratchHome, heimdall_home: &Path, args: &[&str]) -> Command {
    let account = home.root.join("cli-home");
    let [mgmt, iroh] = unused_fixture_stores(&home.root);
    for path in [&account, &home.git_home, heimdall_home, &mgmt, &iroh] {
        assert!(home.scratch().contains_lexically(path));
    }
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
        .env("HOME", account)
        .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
        .env(
            "HEIMDALL_TEST_MGMT_STORE",
            format!("fixture-file:{}", mgmt.to_str().unwrap()),
        )
        .env("HEIMDALL_TEST_IROH_KEY_STORE", iroh)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", home.git_home.join(".gitconfig"))
        .env("LANG", "C")
        .env("TERM", "dumb")
        .current_dir(&home.root)
        .arg("--non-interactive")
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
            std::env::join_paths([system.join("OpenSSH"), system, PathBuf::from(&windows)])
                .unwrap(),
        )
        .env("SystemRoot", windows)
        // In-box OpenSSH requires ProgramData even with an isolated -F.
        .env("ProgramData", home.root.join("cli-home"))
        .env("USERPROFILE", home.root.join("cli-home"))
        .env("TEMP", &home.root)
        .env("TMP", &home.root);
    }
    cmd
}

fn cli_scratch() -> ScratchHome {
    let home = ScratchHome::new();
    std::fs::create_dir(home.git_home.join("etc-ssh")).unwrap();
    std::fs::create_dir(home.root.join("cli-home")).unwrap();
    home
}

async fn cli_output(home: &ScratchHome, mut command: Command) -> Output {
    command.stdin(Stdio::null());
    let (child, log) = ChildLog::start(home, command);
    log.finish(home, child).await
}

fn check_output(out: &Output) {
    for bytes in [&out.stdout, &out.stderr] {
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(bytes));
    }
}

fn excerpt(bytes: &[u8], root: &Path) -> String {
    let mut names: Vec<_> = [
        "USER",
        "USERNAME",
        "LOGNAME",
        "HOSTNAME",
        "COMPUTERNAME",
        "HM_FIXTURE_SSHD_USER",
    ]
    .into_iter()
    .filter_map(|name| std::env::var(name).ok())
    .collect();
    names.sort_unstable_by_key(|name| std::cmp::Reverse(name.len()));
    redact_diagnostic(bytes, root, names.iter().map(String::as_str))
}

fn redact_diagnostic<'a>(
    bytes: &[u8],
    root: &Path,
    names: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    heimdall_testkit::assert_no_canary(&text);
    let root = root.to_string_lossy();
    for path in [
        root.to_string(),
        root.replace('\\', "/"),
        root.replace('\\', "\\\\"),
    ] {
        redact_value(&mut text, &path, "<scratch>");
    }
    // The shared excerpt sanitizer handles exact-case home paths. Also recognize
    // Windows home segments in mixed case and in JSON diagnostics.
    for marker in [r"\\users\\", r"\users\", "/users/"] {
        for (at, _) in text.to_ascii_lowercase().rmatch_indices(marker) {
            let start = at + marker.len();
            let account = &text[start..];
            let len = account
                .find(['/', '\\', '\'', '"', '\r', '\n'])
                .unwrap_or(account.len());
            if len != 0 {
                text.replace_range(start..start + len, "~");
            }
        }
    }
    for name in names {
        redact_value(&mut text, name, "<redacted>");
    }
    heimdall_enroll::remote::redact_excerpt(text.as_bytes(), 4096)
}

fn redact_value(text: &mut String, value: &str, replacement: &str) {
    if value.is_empty() {
        return;
    }
    let mut ranges = Vec::new();
    let mut end = 0;
    for (start, _) in text.char_indices() {
        if start < end {
            continue;
        }
        let mut rest = text[start..].chars();
        if value.chars().all(|expected| {
            rest.next()
                .is_some_and(|actual| actual.to_uppercase().eq(expected.to_uppercase()))
        }) {
            end = text.len() - rest.as_str().len();
            ranges.push(start..end);
        }
    }
    for range in ranges.into_iter().rev() {
        text.replace_range(range, replacement);
    }
}

#[test]
fn diagnostic_redacts_mixed_case_windows_identifiers() {
    let stderr = br#"Failed: C:\uSeRs\ExampleUser\ScRaTcH\raw
{"path":"c:\\USerS\\EXAMPLEUSER\\sCrAtCh\\escaped"}
Path: c:/users/exampleuser/SCRATCH/forward
Other: c:\uSeRs\OtherFixture\file c:\\uSeRs\\OtherFixture\\file c:/uSeRs/OtherFixture/file
Account: eXaMpLeUsEr; Machine: example-pc
"#;
    let redacted = redact_diagnostic(
        stderr,
        Path::new(r"C:\Users\ExampleUser\scratch"),
        ["ExampleUser", "EXAMPLE-PC"],
    );
    assert_eq!(redacted.matches("<scratch>").count(), 3, "{redacted}");
    assert!(
        redacted.contains("Account: <redacted>; Machine: <redacted>"),
        "{redacted}"
    );
    for value in ["exampleuser", "example-pc", "otherfixture"] {
        assert!(!redacted.to_ascii_lowercase().contains(value), "{redacted}");
    }
}

#[track_caller]
fn verify(home: &ScratchHome, out: &Output, passed: bool, expected: &str) {
    assert!(
        passed,
        "{expected}; exit {}\nstdout tail: {:?}\nstderr tail: {:?}",
        out.status,
        excerpt(&out.stdout, &home.root),
        excerpt(&out.stderr, &home.root)
    );
}

fn json(home: &ScratchHome, out: &Output, bytes: &[u8]) -> Value {
    let decoded = serde_json::from_slice(bytes);
    verify(home, out, decoded.is_ok(), "expected a JSON envelope");
    decoded.unwrap()
}

// The parent can inspect both streams while the child is still running.
struct ChildLog {
    stdout: tempfile::NamedTempFile,
    stderr: tempfile::NamedTempFile,
}

impl ChildLog {
    fn start(home: &ScratchHome, mut command: Command) -> (Child, Self) {
        let stdout = tempfile::NamedTempFile::new_in(&home.root).unwrap();
        let stderr = tempfile::NamedTempFile::new_in(&home.root).unwrap();
        let child = command
            .stdout(stdout.reopen().unwrap())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .unwrap();
        (child, Self { stdout, stderr })
    }

    fn output(&self, status: std::process::ExitStatus) -> Output {
        let out = Output {
            status,
            stdout: std::fs::read(self.stdout.path()).unwrap(),
            stderr: std::fs::read(self.stderr.path()).unwrap(),
        };
        check_output(&out);
        out
    }

    fn fail(&self, home: &ScratchHome, child: &mut Child, what: &str) -> ! {
        let status = child.try_wait().unwrap();
        panic!(
            "{what}; exit {status:?}\nstdout tail: {:?}\nstderr tail: {:?}",
            excerpt(&std::fs::read(self.stdout.path()).unwrap(), &home.root),
            excerpt(&std::fs::read(self.stderr.path()).unwrap(), &home.root),
        );
    }

    async fn finish(&self, home: &ScratchHome, mut child: Child) -> Output {
        let status = tokio::time::timeout(TIMEOUT, child.wait())
            .await
            .unwrap_or_else(|_| self.fail(home, &mut child, "child did not exit"))
            .unwrap();
        unused_fixture_stores(&home.root);
        self.output(status)
    }

    async fn wait_for(
        &self,
        home: &ScratchHome,
        child: &mut Child,
        stream: &tempfile::NamedTempFile,
        what: &str,
        found: impl Fn(&str) -> bool,
    ) {
        use std::io::Read as _;
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let mut prefix = Vec::new();
            stream
                .reopen()
                .unwrap()
                .take(64 * 1024)
                .read_to_end(&mut prefix)
                .unwrap();
            let text = String::from_utf8_lossy(&prefix);
            heimdall_testkit::assert_no_canary(&text);
            if found(&text) {
                return;
            }
            if child.try_wait().unwrap().is_some() || tokio::time::Instant::now() >= deadline {
                self.fail(home, child, what);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

async fn test_runtime(home: &ScratchHome, root: &Path, delay_ms: &str) -> (Child, ChildLog) {
    let mut command = cli(home, root, &["service", "run"]);
    command
        .env("HEIMDALL_TEST_ADAPTER", "prepare")
        .env("HEIMDALL_TEST_SLOW_PREPARE_MS", delay_ms)
        .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
        .stdin(Stdio::null());
    let (mut child, log) = ChildLog::start(home, command);
    let ready = tokio::time::timeout(TIMEOUT, async {
        loop {
            let status = cli_output(home, cli(home, root, &["--json", "status"])).await;
            if status.status.success() {
                break;
            }
            if child.try_wait().unwrap().is_some() {
                log.fail(home, &mut child, "fixture runtime exited during startup");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if ready.is_err() {
        log.fail(home, &mut child, "fixture runtime did not start");
    }
    (child, log)
}

async fn stop_test_runtime(home: &ScratchHome, root: &Path, (child, log): (Child, ChildLog)) {
    let stop = cli_output(home, cli(home, root, &["--json", "service", "stop"])).await;
    verify(home, &stop, stop.status.success(), "service stop");
    let stopped = log.finish(home, child).await;
    verify(
        home,
        &stopped,
        stopped.status.success(),
        "runtime exited cleanly",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn status_counts_only_live_approvals_in_human_output() {
    use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
    use heimdall_domain::time::BootId;
    use heimdall_store::{NoFaults, Store};

    let home = cli_scratch();
    let root = home.root.join("heimdall");
    let offline = cli_output(&home, cli(&home, &root, &["status"])).await;
    verify(
        &home,
        &offline,
        offline.status.code() == Some(5)
            && String::from_utf8_lossy(&offline.stdout).contains("Heimdall status is unavailable."),
        "offline status is unavailable",
    );
    assert!(!root.exists(), "status started the runtime");

    let paths = Paths::under(&root);
    paths.ensure().unwrap();
    let db = heimdall_store::layout::db_path(&paths.state_dir).unwrap();
    Store::open(&db, Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| {
            let created_at = "1999-01-01T00:00:00Z".parse().unwrap();
            let generation = tx.authority_generation()?;
            for (id, expiry) in [(1, "2000-01-01T00:00:00Z"), (2, "2099-01-01T00:00:00Z")] {
                tx.insert_decision(&DecisionRecord {
                    id: DecisionId::from_random_bytes([id; 16]),
                    kind: DecisionKind::ConfirmTime {
                        boot_id: BootId("fixture".into()),
                        observed_wall: created_at,
                    },
                    generation,
                    created_at,
                    expires_at: expiry.parse().unwrap(),
                    state: DecisionState::Pending,
                    decided_at: None,
                })?;
            }
            Ok(())
        })
        .unwrap();
    let serving = test_runtime(&home, &root, "0").await;
    let inspect = async |subject| {
        let out = cli_output(&home, cli(&home, &root, &["--json", "inspect", subject])).await;
        verify(&home, &out, out.status.success(), "inspect succeeded");
        (json(&home, &out, &out.stdout), out)
    };
    let (env, _) = inspect("environments").await;
    let (operations, operation_output) = inspect("operations").await;
    let (decisions, decision_output) = inspect("decisions").await;
    let pending = decisions["data"]["decisions"].as_array();
    verify(
        &home,
        &decision_output,
        pending.is_some_and(|pending| {
            pending.len() == 2
                && pending.iter().all(|d| d["state"] == "pending")
                && pending.iter().any(|d| d["expired"] == true)
                && pending.iter().any(|d| d["expired"] == false)
        }),
        "inspect shows both pending decisions, only one of which expired",
    );
    let open_operations = operations["data"]["operations"].as_array();
    verify(
        &home,
        &operation_output,
        open_operations.is_some(),
        "inspect lists operations",
    );
    let human = cli_output(&home, cli(&home, &root, &["status"])).await;
    let (capabilities, capabilities_output) = inspect("capabilities").await;
    let disclosure = capabilities["data"]["lock"]["disclosure"].as_str();
    verify(
        &home,
        &capabilities_output,
        disclosure.is_some_and(|text| text.contains("has not been verified yet")),
        "the fixture runtime reports unverified lock continuity",
    );
    verify(
        &home,
        &human,
        human.status.success()
            && String::from_utf8_lossy(&human.stdout).contains("1 waiting for your approval."),
        "only one approval is live",
    );
    let shown = String::from_utf8_lossy(&human.stdout);
    verify(
        &home,
        &human,
        shown.contains(&format!(
            "Desktop lock: saved personal setting \"continue\".\n{}\n",
            disclosure.unwrap()
        )),
        "status shows the saved setting with the runtime's verbatim lock disclosure",
    );
    let prior_shape = heimdall_contract::Envelope::ok(serde_json::json!({
        "running": true,
        "environment_id": env["data"]["environment_id"],
        "operation_counts": operations["data"]["counts"],
        "open_operations": open_operations.unwrap().len(),
        "pending_decisions": pending.unwrap().len(),
    }));
    let status = cli_output(&home, cli(&home, &root, &["--json", "status"])).await;
    verify(
        &home,
        &status,
        status.status.success()
            && status.stderr.is_empty()
            && status.stdout
                == format!("{}\n", serde_json::to_string(&prior_shape).unwrap()).as_bytes(),
        "JSON status retains its existing shape",
    );
    stop_test_runtime(&home, &root, serving).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cli_sync_wait_explains_itself() {
    const NOTICE: &str = "Ctrl-C stops waiting but does not cancel the request.";
    let home = cli_scratch();
    let root = home.root.join("heimdall");
    let serving = test_runtime(&home, &root, "3000").await;
    let accepted = cli_output(
        &home,
        cli(
            &home,
            &root,
            &[
                "--json",
                "access",
                "ensure",
                "--profile",
                "dev",
                "--work-id",
                "wait-known",
                "--request-id",
                "wait-known",
                "--pair",
                "h1:deploy",
                "--async",
            ],
        ),
    )
    .await;
    verify(
        &home,
        &accepted,
        accepted.status.success(),
        "async ensure succeeded",
    );
    let started = json(&home, &accepted, &accepted.stdout);
    verify(
        &home,
        &accepted,
        started["code"] == "ACCEPTED",
        "async ensure was accepted",
    );
    let id = started["operation_id"].as_str();
    verify(
        &home,
        &accepted,
        id.is_some(),
        "async ensure returned an operation ID",
    );
    let id = id.unwrap();
    let (human, machine) = tokio::join!(
        cli_output(&home, cli(&home, &root, &["operation", "wait", id])),
        cli_output(
            &home,
            cli(&home, &root, &["--json", "operation", "wait", id])
        ),
    );
    verify(
        &home,
        &human,
        human.status.success(),
        "human wait succeeded",
    );
    verify(
        &home,
        &machine,
        machine.status.success() && machine.stderr.is_empty(),
        "machine wait succeeded silently",
    );
    let stderr = String::from_utf8_lossy(&human.stderr);
    verify(
        &home,
        &human,
        stderr.matches(NOTICE).count() == 1
            && stderr.contains(&format!(
                "Waiting for the operation to finish (operation {id})."
            ))
            && stderr.contains(&format!("heimdall operation show {id}")),
        "human wait explained once what it was waiting for",
    );
    let fast = cli_output(&home, cli(&home, &root, &["operation", "wait", id])).await;
    verify(
        &home,
        &fast,
        fast.status.success() && !String::from_utf8_lossy(&fast.stderr).contains(NOTICE),
        "completed operation does not print the wait notice",
    );

    let start = tokio::time::Instant::now();
    let mut cmd = cli(
        &home,
        &root,
        &[
            "access",
            "ensure",
            "--profile",
            "dev",
            "--work-id",
            "wait-initial",
            "--request-id",
            "wait-initial",
            "--pair",
            "h2:deploy",
        ],
    );
    cmd.stdin(Stdio::null());
    let (mut ensure, log) = ChildLog::start(&home, cmd);
    log.wait_for(
        &home,
        &mut ensure,
        &log.stderr,
        "expected the initial ensure wait notice",
        |text| text.split_once('\n').is_some(),
    )
    .await;
    if start.elapsed() < Duration::from_secs(1) || ensure.try_wait().unwrap().is_some() {
        log.fail(&home, &mut ensure, "notice must appear during the wait");
    }
    let out = log.finish(&home, ensure).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let first = stderr.lines().next().unwrap_or_default();
    verify(
        &home,
        &out,
        out.status.success()
            && stderr.matches(NOTICE).count() == 1
            && first.contains("Waiting for access to be ready.")
            && first.contains(NOTICE)
            && first.contains("heimdall operation show <id>"),
        "initial ensure explains its wait once",
    );
    stop_test_runtime(&home, &root, serving).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn enrollment_wait_explains_an_interrupted_step() {
    use std::os::unix::fs::PermissionsExt as _;

    use heimdall_app::enrollment::StepAnswer;
    use heimdall_contract::enrollment::{
        EnrollmentRequest, NarrowingPins, RemoteStage, RemoteStep, SshOption, StepPins,
    };
    use heimdall_contract::ipc::{
        ClientMessage, MAX_CONTROL_FRAME_BYTES, PeerInfo, PrincipalInfo, ServerMessage,
    };
    use heimdall_contract::request::Request;
    use heimdall_contract::{Code, Envelope, OperationState};
    use heimdall_ipc::unix::{Listener, current_uid};
    use heimdall_ipc::{EndpointKind, EndpointPaths, encode_frame};
    use heimdall_runtime::instance::InstanceInfo;
    use heimdall_testkit::registry::{PauseHooks, hook};
    use rustix::process::{Pid, Signal, kill_process};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    async fn receive(stream: &mut UnixStream) -> Option<ClientMessage> {
        let len = match stream.read_u32().await {
            Ok(len) => len as usize,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(error) => panic!("fixture control read failed: {}", error.kind()),
        };
        assert!(len <= MAX_CONTROL_FRAME_BYTES);
        let mut frame = vec![0; len];
        stream.read_exact(&mut frame).await.unwrap();
        Some(heimdall_ipc::session::parse_frame(&frame).unwrap())
    }

    const OP: &str = "op_enroll-interrupt";
    let home = cli_scratch();
    let root = home.root.join("heimdall");
    let paths = Paths::under(&root);
    paths.ensure().unwrap();
    let endpoints = EndpointPaths::for_runtime(&paths.runtime_dir, "");
    let control = Listener::bind(&endpoints.control, EndpointKind::Control).unwrap();
    let _signing = Listener::bind(&endpoints.signing, EndpointKind::Signing).unwrap();
    InstanceInfo {
        pid: std::process::id(),
        started_at: InstanceInfo::current_started_at().unwrap(),
        version: "0.0.0".into(),
        control_endpoint: endpoints.control.to_str().unwrap().into(),
        signing_endpoint: endpoints.signing.to_str().unwrap().into(),
    }
    .write(&paths.runtime_dir)
    .unwrap();

    // Reuse M03's pause point with a local stand-in for SSH. The real CLI receives
    // the ready line, sends the script and starts waiting without opening a connection.
    let hooks = PauseHooks::new(home.scratch()).unwrap();
    hooks.arm(hook::BEFORE_WRITE).unwrap();
    let shim = home.root.join("step-client");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\n{}\n",
            heimdall_enroll::remote::STEP_REMOTE_COMMAND
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let step = StepAnswer::Step {
        step: Box::new(RemoteStep {
            stage: RemoteStage::Append,
            step_token: "1".repeat(32),
            client: shim.to_str().unwrap().to_owned(),
            pins: StepPins {
                narrowing: NarrowingPins(vec![SshOption {
                    key: "BatchMode".into(),
                    value: "yes".into(),
                }]),
                ..StepPins::default()
            },
            alias: "fixture".into(),
            remote_command: heimdall_enroll::remote::STEP_REMOTE_COMMAND.into(),
            script: hooks.snippet(hook::BEFORE_WRITE) + "\n",
            timeout_ms: 15000,
            hard_deadline_ms: 15000,
            not_after_remote: None,
        }),
    };

    let mut cmd = cli(&home, &root, &["enroll", "reconcile", OP]);
    cmd.stdin(Stdio::null());
    let (mut child, log) = ChildLog::start(&home, cmd);
    let (mut wire, hello) = tokio::time::timeout(TIMEOUT, async {
        loop {
            let (mut wire, _) = control.accept().await.unwrap();
            // The launcher first checks socket liveness without sending a hello.
            if let Some(ClientMessage::Hello(hello)) = receive(&mut wire).await {
                break (wire, hello);
            }
        }
    })
    .await
    .unwrap();
    let hello = heimdall_ipc::session::negotiate(
        &hello,
        PrincipalInfo::OsUserUnix { uid: current_uid() },
        heimdall_contract::ids::EnvironmentId::parse("env_fixture").unwrap(),
        PeerInfo {
            name: "fixture-runtime".into(),
            version: "0.0.0".into(),
        },
    )
    .unwrap();
    wire.write_all(&encode_frame(&ServerMessage::Hello(hello), MAX_CONTROL_FRAME_BYTES).unwrap())
        .await
        .unwrap();
    let mut accepted = Envelope::ok(serde_json::json!({"next": "step"}));
    accepted.code = Code::Accepted;
    accepted.state = OperationState::Running;
    accepted.operation_id = Some(heimdall_contract::ids::OperationId::parse(OP).unwrap());
    for envelope in [accepted, Envelope::ok(serde_json::to_value(step).unwrap())] {
        let message = tokio::time::timeout(TIMEOUT, receive(&mut wire))
            .await
            .unwrap();
        let Some(ClientMessage::Request {
            seq,
            request: Request::Enrollment(request),
        }) = message
        else {
            panic!("expected an enrollment request");
        };
        match request {
            EnrollmentRequest::Reconcile { operation_id, .. }
                if envelope.code == Code::Accepted =>
            {
                assert_eq!(operation_id.as_str(), OP);
            }
            EnrollmentRequest::Step { operation_id } if envelope.code == Code::Ok => {
                assert_eq!(operation_id.as_str(), OP);
            }
            _ => panic!("unexpected enrollment request"),
        }
        let reply = ServerMessage::Response {
            in_reply_to: seq,
            envelope,
        };
        wire.write_all(&encode_frame(&reply, MAX_CONTROL_FRAME_BYTES).unwrap())
            .await
            .unwrap();
    }

    const NOTICE: &str = "Ctrl-C interrupts the step.";
    log.wait_for(
        &home,
        &mut child,
        &log.stderr,
        "enrollment wait notice",
        |text| text.contains("Waiting for the enrollment steps to finish"),
    )
    .await;
    let reached = hooks
        .wait_at_for(hook::BEFORE_WRITE, Duration::from_secs(3))
        .unwrap();
    assert!(reached.pid.is_some());
    assert!(child.try_wait().unwrap().is_none());
    kill_process(
        Pid::from_raw(child.id().unwrap().try_into().unwrap()).unwrap(),
        Signal::INT,
    )
    .unwrap();
    let out = log.finish(&home, child).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    verify(
        &home,
        &out,
        out.status.code() == Some(7)
            && stderr.matches(NOTICE).count() == 1
            && stderr.contains(&format!(
                "You may need to check its outcome with `heimdall enroll reconcile {OP}`."
            ))
            && stderr.contains(&format!(
                "the change may have been applied; run `heimdall enroll reconcile {OP}`"
            ))
            && !stderr.contains("does not cancel the request"),
        "interrupt describes its uncertain enrollment outcome",
    );
    assert!(
        tokio::time::timeout(TIMEOUT, receive(&mut wire))
            .await
            .unwrap()
            .is_none(),
        "interrupted step sent a result"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cli_standalone_access_and_stop() {
    let home = cli_scratch();
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
    seed(
        service.operations(),
        &owner(&root),
        &sshd,
        &home,
        &key,
        &agent,
    )
    .await;
    let serving = tokio::spawn(service.run());

    // The runtime prepares the adopted agent identity. The direct SSH probe pins
    // the same fixture key in scratch and disables all agent fallback.
    let identity = home.root.join("login-key");
    key.write_private(&identity).unwrap();
    #[cfg(windows)]
    heimdall_testkit::win::set_owner_only(&identity).unwrap();
    let global: PathBuf = if cfg!(windows) {
        // Windows has no /dev/null. Use the fixture's empty global host file.
        home.global_known_hosts.clone()
    } else {
        "/dev/null".into()
    };
    let run = || {
        let mut cmd = cli(
            &home,
            &root,
            &[
                "--json",
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
        #[cfg(windows)]
        let ssh = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32/OpenSSH/ssh.exe");
        #[cfg(unix)]
        let ssh = find_program("ssh").expect("ssh client");
        cmd.arg(ssh)
            .arg("-T")
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
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                ssh_option_path(&home.known_hosts)
            ))
            .arg("-o")
            .arg(format!("GlobalKnownHostsFile={}", ssh_option_path(&global)))
            .arg("-i")
            .arg(&identity)
            .args(["lab", "echo fixture-login; cat"]);
        cmd
    };
    let mut cmd = run();
    cmd.stdin(Stdio::piped());
    let (mut running, log) = ChildLog::start(&home, cmd);
    log.wait_for(
        &home,
        &mut running,
        &log.stdout,
        "fixture SSH login marker missing",
        |text| {
            text.split_inclusive('\n')
                .any(|line| matches!(line, "fixture-login\n" | "fixture-login\r\n"))
        },
    )
    .await;
    if running.try_wait().unwrap().is_some() {
        log.fail(&home, &mut running, "fixture SSH login did not stay open");
    }
    let during = cli_output(&home, cli(&home, &root, &["--json", "inspect", "bindings"])).await;
    verify(
        &home,
        &during,
        during.status.success(),
        "inspect bindings succeeded",
    );
    let bindings = json(&home, &during, &during.stdout);
    verify(
        &home,
        &during,
        bindings["data"]["bindings"]
            .as_array()
            .is_some_and(|bindings| {
                bindings
                    .iter()
                    .any(|binding| binding["work_id"] == "lab-job" && binding["state"] == "active")
            }),
        "the fixture login has an active binding",
    );
    let status = cli_output(&home, cli(&home, &root, &["status"])).await;
    verify(&home, &status, status.status.success(), "status succeeded");
    let shown = String::from_utf8_lossy(&status.stdout);
    for expected in [
        "Personal access on this computer: lab-access configured for automatic use.",
        "Active work on this computer: 1 session has access.",
        "Desktop lock: saved personal setting \"continue\".",
        "Approved work is designed to keep working while your screen or password manager is locked",
        "heimdall access pause --profile <profile>",
        "heimdall access stop --work <work-id>",
    ] {
        verify(&home, &status, shown.contains(expected), expected);
    }

    let stopped = cli_output(
        &home,
        cli(
            &home,
            &root,
            &["--json", "access", "stop", "--work", "lab-job"],
        ),
    )
    .await;
    verify(
        &home,
        &stopped,
        stopped.status.success(),
        "access stop succeeded",
    );
    let answer = json(&home, &stopped, &stopped.stdout);
    verify(
        &home,
        &stopped,
        answer["data"]["local_applied"] == true,
        "stop was applied locally",
    );

    let refused = cli_output(&home, run()).await;
    verify(
        &home,
        &refused,
        refused.status.code() == Some(4) && refused.stdout.is_empty(),
        "retry was refused without running SSH",
    );
    let refusal = json(&home, &refused, &refused.stderr);
    verify(
        &home,
        &refused,
        refusal["code"] == "CREDENTIAL_EXPIRED"
            && refusal["data"]["error"]["reason"] == "work_stopped",
        "retry was refused because the work stopped",
    );

    drop(running.stdin.take());
    let first = log.finish(&home, running).await;
    verify(
        &home,
        &first,
        first.status.success(),
        "existing SSH session exited cleanly",
    );
    let accepted = sshd.accepted_log();
    verify(
        &home,
        &first,
        accepted.len() == 1 && accepted[0].fingerprint == key.fingerprint(),
        "fixture sshd accepted exactly one login with the generated key",
    );
    shutdown.cancel();
    tokio::time::timeout(TIMEOUT, serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
