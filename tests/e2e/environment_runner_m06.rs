//! ⟨M06 W2 wiring⟩ A controller's management session to a real runner, end to end (m06-plan
//! U2/U3 wiring; ADR-0012 §3.3, §3.5, §3.6, §5.2):
//!
//! 1. **The runner side, through the real binary.** `heimdall --home <runner home> remote
//!    init --owner-client <cid> --owner-key <K_mgmt.pub>` on a pseudo-terminal, confirmed
//!    with a typed `yes` (the runner-local confirmation): the runner marker and the owner
//!    client are written, and the management line is answered. A retried bootstrap of the
//!    same key under another client ID answers the first client (`created: false`). Then
//!    `heimdall service run --runner` serves the runner home.
//! 2. **The management line.** ⟨W2 fixes⟩ The runner runtime's own writer
//!    (`heimdall_runtime::paired_lines`) reconciles the owner's line into the runner
//!    account's `~/.ssh/authorized_keys` (the scratch `HEIMDALL_TEST_SSH_HOME`) at start:
//!    exactly the line `remote init` rendered, `restrict,command="exec \"<heimdall>\" remote
//!    serve --client <cid> --home \"<home>\"" <K_mgmt.pub> heimdall-mgmt:<cid>`. The fixture
//!    sshd's `AuthorizedKeysFile` resolves to that file.
//! 3. **The controller side.** The isolated `-F` configuration (`heimdall_sshconf::mgmt`),
//!    the per-session K_mgmt agent (`heimdall_credential::mgmt::SessionAgent`), the
//!    management `ssh` (`heimdall_app::remote_env::ssh::spawn_management`) and the IPC client
//!    over its standard streams requiring `remote-control/1`. The runner's hello reports its
//!    environment ID, the `owner` role and ⟨rev6.2⟩ the bound client; an `inspect
//!    environments` over the paired session answers the runner's own `remote_runner`
//!    environment ("status"); a `Decide` the paired session sends is refused before dispatch.
//!    A key the runner never enrolled is refused at authentication.
//!
//! 4. ⟨W2 fixes⟩ **Invite, runner-local approval, activation probe, join.** The owner's
//!    session submits an `invite` for a second K_mgmt: `APPROVAL_REQUIRED` with the runner's
//!    decision reference; an attended session local to the runner approves it (the
//!    invitation and its pending line, with `expiry-time`, are written); the owner's replay
//!    returns the recorded result. The new key's first session negotiates only
//!    `remote-control/1`, echoes the probe's nonce and joins; its line is rewritten without
//!    `expiry-time`; its next session is an ordinary owner session. Revoking it removes the
//!    line, and the key is refused at authentication.
//!
//! Not covered here (and why): the controller CLI's `environment add` needs a verified M03 enrollment in
//! the controller catalog and a terminal, so the controller half is driven at the library
//! level with the same adapters the CLI wires.
//!
//! **Isolation.** The runner processes get a cleared environment with a scratch `HOME`,
//! `HEIMDALL_HOME` and `HEIMDALL_TEST_SSH_HOME`; the fixture sshd is unprivileged on
//! 127.0.0.1 with per-run host keys; the controller's `ssh` reads only the rendered scratch
//! `-F` file (strict pin, no agent but the named session agent, `IdentitiesOnly`,
//! `CertificateFile none`, no multiplexing), with `SSH_AUTH_SOCK` removed. Keys are generated
//! per run. Only the runtime this test started is stopped (`service stop` on its scratch
//! home, then the child is waited for). Where no sshd can start the case reports `blocked`.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::ids::ClientId;
use heimdall_contract::ipc::{PeerInfo, capability};
use heimdall_contract::remote::Role;
use heimdall_contract::request::{
    DecideRequest, InspectRequest, InspectSubject, InteractionMode, Request, Verdict,
};
use heimdall_credential::mgmt::{MgmtKey, MgmtSigner, SessionAgent};
use heimdall_ipc::session::ControlClient;
use heimdall_sshconf::mgmt::{
    HopIdentity, MgmtHop, MgmtTarget, PinnedKey, render_mgmt_config, render_mgmt_pin_file,
};
use heimdall_sshconf::render::{HostName, PathStyle, RenderPath};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::{Scratch, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use serde_json::Value;

fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// The runner installation: its Heimdall home and account home.
struct Runner {
    home: PathBuf,
    account: PathBuf,
    runtime: Option<Child>,
}

impl Runner {
    fn new(scratch: &Scratch) -> Runner {
        Runner {
            home: scratch.subdir("rh").unwrap(),
            account: scratch.subdir("ra").unwrap(),
            runtime: None,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(bin());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.account)
            .env("HEIMDALL_HOME", &self.home)
            .env("HEIMDALL_TEST_SSH_HOME", &self.account)
            .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
            .arg("--home")
            .arg(&self.home);
        cmd
    }

    /// `heimdall remote init …` on a pseudo-terminal (`script(1)`), answering `answer` to the
    /// confirmation; the transcript.
    fn remote_init(&self, client: &ClientId, key: &str, answer: &str) -> String {
        let mut argv = vec![
            bin(),
            "--json".to_owned(),
            "--home".to_owned(),
            self.home.to_string_lossy().into_owned(),
            "remote".to_owned(),
            "init".to_owned(),
            "--owner-client".to_owned(),
            client.as_str().to_owned(),
            "--owner-key".to_owned(),
            key.to_owned(),
        ];
        let mut cmd = Command::new("script");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.account)
            .env("HEIMDALL_TEST_SSH_HOME", &self.account);
        if cfg!(target_os = "linux") {
            let quoted: Vec<String> = argv
                .drain(..)
                .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
                .collect();
            cmd.args(["-q", "-e", "-c", &quoted.join(" "), "/dev/null"]);
        } else {
            cmd.args(["-q", "/dev/null"]).args(&argv);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("blocked: script(1) is needed for the runner-local confirmation");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut stdout = child.stdout.take().unwrap();
        let sink = seen.clone();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let text = || String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        let start = Instant::now();
        while !text().contains("Type yes to continue") {
            assert!(
                child.try_wait().unwrap().is_none(),
                "remote init exited before asking: {}",
                text()
            );
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "no prompt: {}",
                text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        {
            use std::io::Write as _;
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(answer.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
            stdin.flush().unwrap();
        }
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "remote init did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(child.stdin.take());
        reader.join().unwrap();
        let out = text();
        assert_no_canary(&out);
        assert!(!out.contains("panicked"), "{out}");
        out
    }

    /// Start `service run --runner` and wait until it serves.
    fn start(&mut self) {
        let child = self
            .command()
            .args(["service", "run", "--runner"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.runtime = Some(child);
        let start = Instant::now();
        loop {
            let status = self
                .command()
                .args(["--json", "service", "status"])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            if status.status.success() {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "the runner runtime did not start"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            let _ = self
                .command()
                .args(["--json", "service", "stop"])
                .stdin(Stdio::null())
                .output();
            let start = Instant::now();
            while child.try_wait().ok().flatten().is_none()
                && start.elapsed() < Duration::from_secs(30)
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            // Only this test's own child, by its handle, if it is still running.
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// The last JSON object in a transcript (the envelope).
fn envelope(transcript: &str) -> Value {
    transcript
        .lines()
        .rev()
        .find_map(|l| {
            let l = l.trim();
            l.find('{')
                .and_then(|i| serde_json::from_str::<Value>(&l[i..]).ok())
        })
        .unwrap_or_else(|| panic!("no envelope: {transcript}"))
}

fn rpath(p: &Path) -> RenderPath {
    RenderPath::absolute(p, PathStyle::Unix).unwrap()
}

/// `<type> <base64>` of the fixture's known-hosts line.
fn host_key(sshd: &LoopbackSshd) -> String {
    let mut words = sshd.host_key_line.split_ascii_whitespace().skip(1);
    format!("{} {}", words.next().unwrap(), words.next().unwrap())
}

/// A management session through the isolated configuration and K_mgmt's session agent.
struct Session {
    client: MgmtClient,
    _child: tokio::process::Child,
    agent: SessionAgent,
}

async fn open_session(
    dir: &Path,
    sshd: &LoopbackSshd,
    account: &str,
    key: MgmtKey,
    environment_name: &str,
) -> Result<Session, String> {
    let public = key.public().unwrap();
    let signer =
        MgmtSigner::with_host_key_lines(key, [account.to_owned()], &[host_key(sshd)]).unwrap();
    let agent = SessionAgent::start(&dir.join("a.sock"), signer).unwrap();
    match connect(dir, sshd, account, &public.openssh_line, environment_name).await {
        Ok((client, child)) => Ok(Session {
            client,
            _child: child,
            agent,
        }),
        Err(e) => {
            agent.stop().await;
            Err(e)
        }
    }
}

type MgmtClient =
    ControlClient<tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>>;

/// A management connection through the isolated configuration, with the session agent at
/// `dir/a.sock` already serving the key whose public line is `public_line`.
async fn connect(
    dir: &Path,
    sshd: &LoopbackSshd,
    account: &str,
    public_line: &str,
    environment_name: &str,
) -> Result<(MgmtClient, tokio::process::Child), String> {
    let pin = host_key(sshd);
    let pub_file = dir.join("k_mgmt.pub");
    std::fs::write(&pub_file, format!("{public_line}\n")).unwrap();
    let target = MgmtTarget {
        environment: environment_name.to_owned(),
        hop: MgmtHop {
            hostname: HostName::parse(&sshd.host).unwrap(),
            port: Some(sshd.port),
            user: account.to_owned(),
            pins: vec![PinnedKey::parse(&pin).unwrap()],
            identity: HopIdentity::new(rpath(&dir.join("a.sock")), rpath(&pub_file)).unwrap(),
        },
        jump: None,
    };
    let pins = dir.join("known_hosts");
    std::fs::write(&pins, render_mgmt_pin_file(&target).unwrap()).unwrap();
    let config = dir.join("mgmt.conf");
    std::fs::write(
        &config,
        render_mgmt_config(&target, &rpath(&pins), PathStyle::Unix).unwrap(),
    )
    .unwrap();
    let args: Vec<std::ffi::OsString> = vec![
        "-F".into(),
        config.into_os_string(),
        "-T".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "CertificateFile=none".into(),
        "--".into(),
        target.alias().into(),
    ];
    let child = heimdall_app::remote_env::ssh::spawn_management(
        &find_program("ssh").expect("an OpenSSH client"),
        &args,
    )
    .map_err(|e| e.message)?;
    let heimdall_app::remote_env::ssh::ManagementChild {
        child,
        stdin,
        stdout,
        stderr,
    } = child;
    let required: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
    let handshake = tokio::time::timeout(
        Duration::from_secs(30),
        ControlClient::handshake(
            tokio::io::join(stdout, stdin),
            PeerInfo {
                name: "heimdall-cli".into(),
                version: "test".into(),
            },
            required,
            InteractionMode::NonInteractive,
        ),
    )
    .await;
    match handshake {
        Ok(Ok(client)) => Ok((client, child)),
        other => {
            let kept = String::from_utf8_lossy(&stderr.lock().unwrap()).into_owned();
            assert_no_canary(&kept);
            Err(format!(
                "handshake failed ({}): {kept}",
                match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "timeout".into(),
                }
            ))
        }
    }
}

#[tokio::test]
async fn a_controller_reaches_a_real_runner_through_its_management_line() {
    let scratch = Scratch::new().unwrap();
    let mut runner = Runner::new(&scratch);
    let key = MgmtKey::generate().unwrap();
    let public = key.public().unwrap();
    let key_text = public
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let client = ClientId::from_random_bytes([0x5a; 16]);

    // 1. The runner-local bootstrap enrollment, confirmed on the runner's terminal.
    let refused = runner.remote_init(&client, &key_text, "no");
    assert_eq!(
        envelope(&refused)["code"],
        "INTERACTION_REQUIRED",
        "{refused}"
    );
    let first = envelope(&runner.remote_init(&client, &key_text, "yes"));
    assert_eq!(first["code"], "OK", "{first}");
    let environment = first["data"]["environment"].as_str().unwrap().to_owned();
    assert_eq!(first["data"]["client"], client.as_str());
    assert_eq!(first["data"]["created"], true);
    assert_eq!(
        first["data"]["key_fingerprint"],
        public.fingerprint.as_str()
    );
    let line = first["data"]["management_line"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(line.starts_with("restrict,command=\"exec \\\""), "{line}");
    assert!(line.contains(&format!("remote serve --client {}", client.as_str())));
    assert!(line.ends_with(&format!(" heimdall-mgmt:{}", client.as_str())));
    // A retried bootstrap of the same key, under a new client ID: the first client stands.
    let retry =
        envelope(&runner.remote_init(&ClientId::from_random_bytes([0x6b; 16]), &key_text, "yes"));
    assert_eq!(retry["code"], "OK", "{retry}");
    assert_eq!(retry["data"]["created"], false);
    assert_eq!(retry["data"]["client"], client.as_str());
    assert_eq!(retry["data"]["environment"], environment.as_str());
    // ⟨W2 fixes⟩ The runner account's own `~/.ssh` (owner-only): the runtime's line writer
    // reconciles the owner's line there at start.
    let ssh_dir = runner.account.join(".ssh");
    std::fs::create_dir(&ssh_dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let keys_file = ssh_dir.join("authorized_keys");
    runner.start();
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "the runtime wrote exactly the rendered owner line"
    );

    // 2. The fixture sshd reads the runner account's authorized_keys (its registry resolves
    //    to that file).
    let sshd = match LoopbackSshd::start(
        &scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            ..SshdConfig::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            #[allow(clippy::print_stderr)] // the blocked row's reason
            {
                eprintln!("m06 controller->runner: blocked (no fixture sshd: {e})");
            }
            return;
        }
    };
    let account = sshd
        .login_account()
        .or_else(current_account)
        .expect("the fixture account");
    let Some(registry) = sshd.registry_path().map(Path::to_path_buf) else {
        #[allow(clippy::print_stderr)] // the blocked row's reason
        {
            eprintln!("m06 controller->runner: blocked (the fixture sshd has no local registry)");
        }
        return;
    };
    std::fs::remove_file(&registry).unwrap();
    std::os::unix::fs::symlink(&keys_file, &registry).unwrap();

    // 3. The controller's management session.
    let dir = scratch.subdir("c").unwrap();
    let mut session = open_session(&dir, &sshd, &account, key, &environment)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let hello = session.client.server().clone();
    assert_eq!(hello.environment_id.as_str(), environment);
    assert_eq!(hello.role, Some(Role::Owner));
    assert_eq!(
        hello.remote_client.as_ref(),
        Some(&client),
        "rev6.2: the bound client"
    );
    assert!(hello.capabilities.contains(capability::REMOTE_CONTROL_V1));

    // "Status": the runner's own environment, read over the paired session.
    let inspected = session
        .client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Environments,
            preview: None,
            cwd: None,
            redact: false,
        }))
        .await
        .unwrap();
    let text = serde_json::to_string(&inspected).unwrap();
    assert_no_canary(&text);
    assert_eq!(inspected.code.as_str(), "OK", "{text}");
    assert!(text.contains(&environment), "{text}");
    assert!(text.contains("remote_runner"), "{text}");

    // A paired session never decides (ADR-0012 §3.10): refused before dispatch.
    let decided = session
        .client
        .request(Request::Decide(DecideRequest {
            decision_id: heimdall_contract::ids::DecisionId::from_random_bytes([1; 16]),
            verdict: Verdict::Approve,
        }))
        .await
        .unwrap();
    assert_eq!(decided.code.as_str(), "INTERACTION_REQUIRED", "{decided:?}");

    // 4. ⟨W2 fixes⟩ Invite a second K_mgmt (role owner: this runner's sshd policy is not
    //    verified, so limited roles are refused), approve it at the runner, activate it.
    let second = MgmtKey::generate().unwrap();
    let second_public = second.public().unwrap();
    let second_text = second_public
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let invite: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "invite", "environment": environment,
        "role": "owner", "key_fingerprint": second_public.fingerprint,
        "public_key": second_text, "request_id": "e2e-invite-1",
    }))
    .unwrap();
    let pending = session.client.request(invite.clone()).await.unwrap();
    assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
    let decision = pending.next.unwrap().decision_ref.unwrap();
    // The runner-local confirmation: an attended session on the runner's own endpoint.
    let info = heimdall_runtime::instance::InstanceInfo::read_valid(
        &heimdall_runtime::Paths::under(&runner.home).runtime_dir,
    )
    .unwrap()
    .expect("the runner runtime's advertisement");
    let stream = heimdall_ipc::unix::connect(Path::new(&info.control_endpoint))
        .await
        .unwrap();
    let mut at_runner = ControlClient::handshake(
        stream,
        PeerInfo {
            name: "heimdall-cli".into(),
            version: "test".into(),
        },
        BTreeSet::new(),
        InteractionMode::Interactive,
    )
    .await
    .unwrap();
    assert_eq!(at_runner.attend().await.unwrap().code.as_str(), "OK");
    let approved = at_runner
        .request(Request::Decide(DecideRequest {
            decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
            verdict: Verdict::Approve,
        }))
        .await
        .unwrap();
    assert_eq!(approved.code.as_str(), "OK", "{approved:?}");
    let invited: ClientId = serde_json::from_value(approved.data["client"].clone()).unwrap();
    let nonce = approved.data["probe_nonce"].as_str().unwrap().to_owned();
    let pending_line = std::fs::read_to_string(&keys_file).unwrap();
    assert!(pending_line.contains(&format!("heimdall-mgmt:{}", invited.as_str())));
    assert!(pending_line.contains("expiry-time="), "{pending_line}");
    assert!(
        pending_line.starts_with(&format!("{line}\n")),
        "the owner's line kept"
    );
    // The owner's replay returns the recorded terminal result.
    let replayed = session.client.request(invite).await.unwrap();
    assert_eq!(replayed.data, approved.data);
    // The new key's first session: pending, so only the probe and join.
    let joining = scratch.subdir("j").unwrap();
    let signer =
        MgmtSigner::with_host_key_lines(second, [account.clone()], &[host_key(&sshd)]).unwrap();
    let agent = SessionAgent::start(&joining.join("a.sock"), signer).unwrap();
    let (mut first_session, child) = connect(
        &joining,
        &sshd,
        &account,
        &second_public.openssh_line,
        &environment,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let caps: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
    assert_eq!(first_session.server().capabilities, caps);
    assert_eq!(
        first_session.server().remote_client.as_ref(),
        Some(&invited)
    );
    let probe: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "activation_probe",
        "environment": environment, "nonce": nonce,
    }))
    .unwrap();
    let echoed = first_session.request(probe).await.unwrap();
    assert_eq!(echoed.code.as_str(), "OK", "{echoed:?}");
    assert_eq!(echoed.data["client"], invited.as_str());
    let join: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "join", "environment": environment,
        "invitation": approved.data["invitation"], "role": "owner",
        "generation": approved.data["generation"],
    }))
    .unwrap();
    let joined = first_session.request(join).await.unwrap();
    assert_eq!(joined.code.as_str(), "OK", "{joined:?}");
    drop(first_session);
    drop(child);
    let active_text = std::fs::read_to_string(&keys_file).unwrap();
    let active: Vec<&str> = active_text
        .lines()
        .filter(|l| l.ends_with(&format!(" heimdall-mgmt:{}", invited.as_str())))
        .collect();
    assert_eq!(active.len(), 1, "{active_text}");
    assert!(
        !active[0].contains("expiry-time="),
        "rewritten without expiry-time"
    );
    // Its next session is an ordinary owner session.
    let (mut ordinary, child) = connect(
        &joining,
        &sshd,
        &account,
        &second_public.openssh_line,
        &environment,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ordinary.server().role, Some(Role::Owner));
    assert!(
        ordinary
            .server()
            .capabilities
            .contains(capability::OPERATIONS_V1)
    );
    let status = ordinary
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Environments,
            preview: None,
            cwd: None,
            redact: false,
        }))
        .await
        .unwrap();
    assert_eq!(status.code.as_str(), "OK", "{status:?}");
    drop(ordinary);
    drop(child);
    // Revoking it removes its line; the key is then refused at authentication.
    let revoke: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "revoke_client", "environment": environment,
        "client": invited,
    }))
    .unwrap();
    let revoked = session.client.request(revoke).await.unwrap();
    assert_eq!(revoked.code.as_str(), "OK", "{revoked:?}");
    assert_eq!(revoked.data["line_removed"], true);
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n")
    );
    let after = connect(
        &joining,
        &sshd,
        &account,
        &second_public.openssh_line,
        &environment,
    )
    .await;
    assert!(after.is_err(), "a revoked key opened a session");
    agent.stop().await;
    drop(at_runner);
    drop(session.client);
    session.agent.stop().await;

    // A key the runner never enrolled is refused at authentication.
    let other = scratch.subdir("o").unwrap();
    let refused = open_session(
        &other,
        &sshd,
        &account,
        MgmtKey::generate().unwrap(),
        &environment,
    )
    .await;
    let Err(why) = refused else {
        panic!("an unenrolled key opened a management session");
    };
    assert!(
        why.contains("Permission denied") || why.contains("handshake failed"),
        "{why}"
    );
}
