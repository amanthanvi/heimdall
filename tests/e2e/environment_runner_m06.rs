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

/// [`Runner::remote_init`]'s answer for a case that must be refused before it is asked.
const NEVER_ASKED: &str = "<never asked>";

/// The runner installation: its Heimdall home and account home.
struct Runner {
    home: PathBuf,
    account: PathBuf,
    runtime: Option<Child>,
    /// ⟨M06 W3⟩ `HEIMDALL_TEST_RUNNER_SSHD_CONFIG` for the runtime, when the case has one.
    sshd_config: Option<PathBuf>,
}

impl Runner {
    fn new(scratch: &Scratch) -> Runner {
        Runner {
            home: scratch.subdir("rh").unwrap(),
            account: scratch.subdir("ra").unwrap(),
            runtime: None,
            sshd_config: None,
        }
    }

    /// A second, separate runner installation under `scratch` (`tag` names its directories).
    fn named(scratch: &Scratch, tag: &str) -> Runner {
        Runner {
            home: scratch.subdir(&format!("{tag}h")).unwrap(),
            account: scratch.subdir(&format!("{tag}a")).unwrap(),
            runtime: None,
            sshd_config: None,
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
        if let Some(config) = &self.sshd_config {
            cmd.env("HEIMDALL_TEST_RUNNER_SSHD_CONFIG", config);
        }
        cmd
    }

    /// `heimdall remote init …` on a pseudo-terminal (`script(1)`), answering `answer` to the
    /// confirmation; the transcript.
    fn remote_init(&self, client: &ClientId, key: &str, answer: &str) -> String {
        self.remote_init_with(client, key, answer, &[])
    }

    /// [`Self::remote_init`] with more arguments (`--iroh-endpoint <id>`).
    fn remote_init_with(
        &self,
        client: &ClientId,
        key: &str,
        answer: &str,
        extra: &[&str],
    ) -> String {
        let mut args = vec![
            "remote".to_owned(),
            "init".to_owned(),
            "--owner-client".to_owned(),
            client.as_str().to_owned(),
            "--owner-key".to_owned(),
            key.to_owned(),
        ];
        args.extend(extra.iter().map(|a| (*a).to_owned()));
        self.on_terminal(&args, answer)
    }

    /// `heimdall --json --home <home> <args…>` on a pseudo-terminal (`script(1)`), answering
    /// `answer` to its typed confirmation; the transcript.
    fn on_terminal(&self, args: &[String], answer: &str) -> String {
        let mut argv = vec![
            bin(),
            "--json".to_owned(),
            "--home".to_owned(),
            self.home.to_string_lossy().into_owned(),
        ];
        argv.extend(args.iter().cloned());
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
        // `NEVER_ASKED`: the case expects a refusal before the confirmation.
        let mut asked = true;
        while !text().contains("Type yes to continue") {
            if child.try_wait().unwrap().is_some() {
                assert_eq!(
                    answer,
                    NEVER_ASKED,
                    "remote init exited before asking: {}",
                    text()
                );
                asked = false;
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "no prompt: {}",
                text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        if asked {
            use std::io::Write as _;
            assert_ne!(answer, NEVER_ASKED, "asked: {}", text());
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
            .stderr(std::fs::File::create(self.account.join("runtime.stderr")).unwrap())
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
                "the runner runtime did not start: {}",
                std::fs::read_to_string(self.account.join("runtime.stderr")).unwrap_or_default()
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
    connect_offering(dir, sshd, account, public_line, environment_name, false).await
}

/// [`connect`], also offering `runner/1` when `offer_runner` (as the CLI's session opener
/// does: offered, not required; the runner negotiates it for an owner session only).
async fn connect_offering(
    dir: &Path,
    sshd: &LoopbackSshd,
    account: &str,
    public_line: &str,
    environment_name: &str,
    offer_runner: bool,
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
    let mut capabilities = heimdall_ipc::session::server_capabilities();
    capabilities.extend(required.iter().cloned());
    if offer_runner {
        capabilities.insert(capability::RUNNER_V1.to_owned());
    }
    let handshake = tokio::time::timeout(
        Duration::from_secs(30),
        ControlClient::handshake_hello(
            tokio::io::join(stdout, stdin),
            heimdall_contract::ipc::ClientHello {
                protocol: heimdall_contract::PROTOCOL_VERSION,
                schema_version: heimdall_contract::SchemaVersion::current(),
                client: PeerInfo {
                    name: "heimdall-cli".into(),
                    version: "test".into(),
                },
                capabilities,
                required,
                interaction: InteractionMode::NonInteractive,
                remote_client: None,
            },
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
    assert!(
        !runner.account.join(".ssh").exists(),
        "declined: nothing created"
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
    // ⟨M06-W2-R02⟩ The account had no `~/.ssh`: the declined run created nothing; the
    // confirmed one created it owner-only (the scratch `HEIMDALL_TEST_SSH_HOME`) and wrote
    // the owner's line there.
    let ssh_dir = runner.account.join(".ssh");
    let keys_file = ssh_dir.join("authorized_keys");
    assert_eq!(first["data"]["line_written"], true, "{first}");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&ssh_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
        // The shared module's exclusive create: owner-only.
        let mode = std::fs::metadata(&keys_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n")
    );
    // A retried bootstrap of the same key, under a new client ID: the first client stands,
    // and ⟨M06-W2-R02⟩ `remote init` itself writes the owner's line now (no runtime runs).
    let retry =
        envelope(&runner.remote_init(&ClientId::from_random_bytes([0x6b; 16]), &key_text, "yes"));
    assert_eq!(retry["code"], "OK", "{retry}");
    assert_eq!(retry["data"]["created"], false);
    assert_eq!(retry["data"]["client"], client.as_str());
    assert_eq!(retry["data"]["environment"], environment.as_str());
    assert_eq!(retry["data"]["line_written"], true, "{retry}");
    assert!(
        retry["data"]["iroh_admission"].is_null(),
        "no token, no admission"
    );
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "remote init wrote exactly the rendered owner line"
    );
    runner.start();
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "the runtime's reconciler leaves the line as it is"
    );
    // ⟨M06-W2-R02; ADR-0006 §18.7 item 8⟩ The repair while the runtime runs (it holds the
    // instance lock): the same confirmation, through the attended runner-local form. With
    // the controller's endpoint ID it adds the owner's Iroh admission and first endpoint; a
    // second repair with another endpoint never replaces it. (Two RFC 8032 test-vector
    // public keys: valid endpoint IDs for the Iroh library's own parser too.)
    let (ep_a, ep_b) = (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    // Anything but an endpoint ID is refused before the confirmation is asked.
    let refused = runner
        .command()
        .args([
            "--json",
            "remote",
            "init",
            "--owner-client",
            client.as_str(),
        ])
        .args([
            "--owner-key",
            &key_text,
            "--iroh-endpoint",
            "not-an-endpoint",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let refused = envelope(&String::from_utf8_lossy(&refused.stdout));
    assert_eq!(refused["code"], "USAGE_ERROR", "{refused}");
    let declined =
        envelope(&runner.remote_init_with(&client, &key_text, "no", &["--iroh-endpoint", ep_a]));
    assert_eq!(declined["code"], "INTERACTION_REQUIRED", "{declined}");
    let transcript = runner.remote_init_with(&client, &key_text, "yes", &["--iroh-endpoint", ep_a]);
    assert!(
        transcript.contains(ep_a) && transcript.contains(public.fingerprint.as_str()),
        "the confirmation shows the endpoint ID next to the key's fingerprint: {transcript}"
    );
    let repaired = envelope(&transcript);
    assert_eq!(repaired["code"], "OK", "{repaired}");
    assert_eq!(repaired["data"]["created"], false);
    assert_eq!(repaired["data"]["client"], client.as_str());
    assert_eq!(repaired["data"]["line_written"], true, "{repaired}");
    assert_eq!(repaired["data"]["management_line"], line.as_str());
    assert_eq!(repaired["data"]["iroh_admission"]["endpoint"], "recorded");
    let again =
        envelope(&runner.remote_init_with(&client, &key_text, "yes", &["--iroh-endpoint", ep_b]));
    assert_eq!(again["code"], "OK", "{again}");
    assert_eq!(
        again["data"]["iroh_admission"]["endpoint"], "kept",
        "{again}"
    );
    assert_eq!(again["data"]["iroh_admission"]["kept_endpoint"], ep_a);
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "the repairs left exactly the owner's line"
    );

    // 2. The fixture sshd reads the runner account's authorized_keys (its registry resolves
    //    to that file).
    let sshd = match LoopbackSshd::start(
        &scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            // ⟨ADR-0006 §18.7 items 16–17⟩ The daemon itself allows agent forwarding, so
            // it is the runner's line (`restrict`) that refuses it to a management key,
            // and a line without that restriction really forwards (the last step).
            agent_forwarding: true,
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
    // ⟨ADR-0006 §18.7 item 16; ADR-0012 §3.2⟩ The four confirming probes with the enrolled
    // key, on the real connection: this sshd refuses the line's key a PTY, a `-W` forward
    // and agent forwarding (a disposable agent, never the one holding the key), and does
    // not deliver the `SetEnv` variable. The join reports exactly that.
    let ssh = find_program("ssh").expect("an OpenSSH client");
    let alias = format!("hm-env-{environment}");
    let disposable =
        heimdall_app::remote_env::ssh::DisposableAgent::start(&joining.join("p.sock")).unwrap();
    let observed = heimdall_app::remote_env::ssh::run_probes(
        &ssh,
        &joining.join("mgmt.conf"),
        &alias,
        &disposable,
    )
    .await;
    drop(disposable);
    assert_eq!(
        observed,
        Some(heimdall_contract::remote::ProbeObservation {
            pty_refused: true,
            forward_refused: true,
            agent_forward_refused: true,
            setenv_canary_delivered: false,
        })
    );
    assert_eq!(
        recorded_downgrade(&runner.home),
        None,
        "restricted sessions record nothing"
    );
    let join: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "join", "environment": environment,
        "invitation": approved.data["invitation"], "role": "owner",
        "generation": approved.data["generation"], "probe": observed,
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

    // ⟨ADR-0006 §18.7 items 16–17; ADR-0012 §3.2 "Limits"⟩ A session that is NOT restricted
    // as the runner's line says. The fixture stands in for an sshd whose real connections
    // get another policy: two more keys reach the same forced command through lines that
    // also grant a PTY, or agent forwarding (written by the test; the runner never writes
    // such a line). Asked for neither, such a session works. Asked by the probes:
    // * sshd allocates the PTY, the bridge finds `SSH_TTY` and refuses the session, and the
    //   probe reads that refusal: `pty_refused: false`; the runner is recorded owner-only;
    // * sshd forwards the disposable agent, the bridge finds `SSH_AUTH_SOCK` and refuses:
    //   `agent_forward_refused: false`.
    assert_eq!(recorded_downgrade(&runner.home), None);
    let options = line
        .split_once(" ssh-ed25519 ")
        .map(|(options, _)| options.to_owned())
        .unwrap();
    let mut unrestricted = Vec::new();
    for (tag, grant) in [
        ("pty", "restrict,pty,"),
        ("agt", "restrict,agent-forwarding,"),
    ] {
        let extra = MgmtKey::generate().unwrap();
        let extra_public = extra.public().unwrap();
        let extra_text = extra_public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let mut keys = std::fs::read_to_string(&keys_file).unwrap();
        keys.push_str(&format!(
            "{} {extra_text} fixture-{tag}\n",
            options.replacen("restrict,", grant, 1)
        ));
        std::fs::write(&keys_file, keys).unwrap();
        let dir = scratch.subdir(tag).unwrap();
        let session = open_session(&dir, &sshd, &account, extra, &environment)
            .await
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
        assert_eq!(
            session.client.server().remote_client.as_ref(),
            Some(&client)
        );
        let disposable =
            heimdall_app::remote_env::ssh::DisposableAgent::start(&dir.join("p.sock")).unwrap();
        let observed = heimdall_app::remote_env::ssh::run_probes(
            &ssh,
            &dir.join("mgmt.conf"),
            &alias,
            &disposable,
        )
        .await
        .unwrap_or_else(|| panic!("{tag}: a probe was inconclusive"));
        drop(disposable);
        unrestricted.push(observed);
        assert!(
            recorded_downgrade(&runner.home).is_some(),
            "{tag}: the bridge recorded it"
        );
        drop(session.client);
        session.agent.stop().await;
    }
    let restricted = heimdall_contract::remote::ProbeObservation {
        pty_refused: true,
        forward_refused: true,
        agent_forward_refused: true,
        setenv_canary_delivered: false,
    };
    assert_eq!(
        unrestricted,
        [
            heimdall_contract::remote::ProbeObservation {
                pty_refused: false,
                ..restricted
            },
            heimdall_contract::remote::ProbeObservation {
                agent_forward_refused: false,
                ..restricted
            },
        ]
    );
    // The first cause stands (a row of the running runner's own database, written by the
    // bridge's own connection; §18.7 item 18).
    assert_eq!(
        recorded_downgrade(&runner.home).as_deref(),
        Some("session_pty")
    );
}

/// ⟨ADR-0006 §18.7 item 17; ADR-0012 §3.2 "Limits"⟩ The bridge checks its own session at
/// start, through the real binary (the forced command, started directly with a cleared
/// environment, so nothing of the test's own session reaches it):
///
/// * neither variable: the session is served (here the remote side closes at once: exit 0),
///   and nothing is recorded;
/// * **`SSH_TTY`** set (sshd allocated a PTY), on one runner, and **`SSH_AUTH_SOCK`** set
///   (sshd forwarded an agent), on another: the session is refused before any frame is read
///   (one `Goodbye`, `CAPABILITY_UNAVAILABLE`, a failing exit), the runner's owner-only
///   record names the cause, and `doctor` reports `runner_sshd_policy_unverifiable`;
/// * the `SetEnv` probe's variable alone: refused, and nothing recorded (the prober's `join`
///   reports it).
#[test]
fn the_bridge_refuses_a_session_with_a_terminal_or_a_forwarded_agent() {
    let scratch = Scratch::new().unwrap();
    let key = MgmtKey::generate().unwrap().public().unwrap();
    let key_text = key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let owner = ClientId::from_random_bytes([0x33; 16]);
    let cases = [
        (
            "t",
            "SSH_TTY",
            "/dev/ttys999",
            Some("session_pty"),
            "allocated a terminal",
        ),
        (
            "a",
            "SSH_AUTH_SOCK",
            "/nonexistent/hm-fixture/agent.sock",
            Some("session_agent_forwarded"),
            "forwarded an agent",
        ),
        (
            "e",
            "HEIMDALL_SETENV_PROBE",
            "1",
            None,
            "delivered a client variable",
        ),
    ];
    for (tag, variable, value, recorded, said) in cases {
        let runner = Runner::named(&scratch, tag);
        let init = envelope(&runner.remote_init(&owner, &key_text, "yes"));
        assert_eq!(init["code"], "OK", "{tag}: {init}");
        // ⟨§18.7 item 18⟩ The downgrade is a row of the runner's state database.
        let record = || recorded_downgrade(&runner.home);
        let bridge = |set: Option<(&str, &str)>| {
            let mut cmd = Command::new(bin());
            cmd.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &runner.account)
                .args(["remote", "serve", "--client", owner.as_str(), "--home"])
                .arg(&runner.home)
                .stdin(Stdio::null());
            if let Some((name, value)) = set {
                cmd.env(name, value);
            }
            cmd.output().unwrap()
        };
        let served = bridge(None);
        assert!(served.status.success(), "{tag}: {served:?}");
        assert!(served.stdout.is_empty() && record().is_none(), "{tag}");

        let refused = bridge(Some((variable, value)));
        let out = String::from_utf8_lossy(&refused.stdout).into_owned();
        let err = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert_no_canary(&out);
        assert_no_canary(&err);
        assert!(!refused.status.success(), "{tag}: {refused:?}");
        // One frame: a four-byte length, then the goodbye.
        let goodbye: Value = serde_json::from_slice(&refused.stdout[4..]).unwrap();
        assert_eq!(goodbye["type"], "goodbye", "{tag}: {goodbye}");
        assert_eq!(
            goodbye["code"], "CAPABILITY_UNAVAILABLE",
            "{tag}: {goodbye}"
        );
        assert!(
            goodbye["message"].as_str().unwrap().contains(said),
            "{goodbye}"
        );
        assert!(err.contains(said) && !err.contains(value), "{tag}: {err}");

        let doctor = runner
            .command()
            .args(["--json", "doctor"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&doctor.stdout).into_owned();
        assert_no_canary(&report);
        let report = envelope(&report);
        let finding = report["data"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["code"] == "runner_sshd_policy_unverifiable");
        match recorded {
            Some(token) => {
                assert_eq!(record().as_deref(), Some(token), "{tag}");
                assert!(
                    !heimdall_runtime::Paths::under(&runner.home)
                        .state_dir
                        .join("runner-owner-only")
                        .exists(),
                    "{tag}: no marker file"
                );
                let finding = finding.unwrap_or_else(|| panic!("{tag}: no finding: {report}"));
                assert_eq!(finding["severity"], "problem", "{finding}");
                assert!(
                    finding["message"].as_str().unwrap().contains(said),
                    "{finding}"
                );
            }
            None => {
                assert!(
                    record().is_none(),
                    "{tag}: a probe variable records nothing"
                );
                assert!(finding.is_none(), "{tag}: {report}");
            }
        }
    }
}

/// ⟨ADR-0006 §18.7 item 18⟩ The cause token of the owner-only downgrade recorded in the
/// state database of the runner home `home` (read-only; `None` without the row).
fn recorded_downgrade(home: &Path) -> Option<String> {
    let db = heimdall_runtime::Paths::under(home)
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
        .unwrap()
        .transaction(|tx| tx.runner_downgrade())
        .unwrap()
        .map(|d| d.cause)
}

// --- ⟨M06 W3 `driver`⟩ the controller's sync and issuance driver over a real session --------

/// ⟨M06 W3 `driver`; ADR-0012 §4.2, §7.4; ADR-0006 §18.7 items 11–13⟩ The controller's
/// driver (`heimdall_app::remote_status_driver`) against a real runner runtime, over the
/// fixture sshd and the runner's management line:
///
/// 1. **Pair.** `remote init --issuer-ca` on the runner's terminal enrolls the owner, trusts
///    its CA and designates it time source. The runner holds one grant under a standing
///    policy (seeded in its store before the runtime starts: admission is the runner's).
/// 2. **Reconnect and issue.** The owner session negotiates `runner/1`; the driver runs the
///    reconnect order, the barrier opens, and the grant is issued remotely: prepare on the
///    runner, reserve and publish in the controller's ledger, install on the runner.
/// 3. **Disconnect, revoke while disconnected.** The owner's local revoke of the runner's
///    grant is an outbox row: `remote_pending`, issuance gated, the residual stated.
/// 4. **Reconnect.** The effect is delivered before the report and acknowledged with its
///    enforcement state; the report shows the tombstone; the barrier opens; the view shows
///    it; the revoked grant is never issued for again.
///
/// The controller half is driven at the library level with the adapters the CLI wires (as
/// in the case above). ⟨M06 W3 host⟩ The issuer is the **production** one: the real
/// `heimdall internal issuer` child over the controller's own state database, signing a
/// reservation of kind `remote` (ADR-0005 §3.5 "Remote reservations") with a per-run K_ca
/// held in a scratch secret store (`HEIMDALL_TEST_SECRET_STORE=scratch`; no platform key
/// store is touched). The certificate's content is the controller's record of the grant it
/// delivered; the runner's answer only narrows it.
mod driver_e2e {
    use std::sync::Arc;

    use heimdall_app::OpError;
    use heimdall_app::remote_env::{ManagementCall, ManagementSession, SessionHello};
    use heimdall_app::remote_status::{IssuanceGate, status_of};
    use heimdall_app::remote_status_barrier::CountedResidual;
    use heimdall_app::remote_status_driver::{
        ControllerSync, RemoteIssueInput, SessionChannel, deliver_runner_grant, narrow_runner_grant,
    };
    use heimdall_contract::controller_record::{
        ManagementHop, ManagementRoute, RemoteEnvironmentPin,
    };
    use heimdall_contract::envelope::{Envelope, reason};
    use heimdall_contract::ids::{
        AccountName, DestinationId, EnvironmentId, GrantId, PolicyId, ProfileId,
    };
    use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
    use heimdall_contract::remote::Connectivity;
    use heimdall_contract::request::{
        AccessPairRef, DeadlineIntent, DestinationScopeEnforcement, Enforcement,
        ExistingConnectionsPolicy, NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
    };
    use heimdall_contract::{Code, GrantState, Timestamp};
    use heimdall_credential::cert::SecretCaKey;
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantSnapshot};
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{Capability, Scope};
    use heimdall_domain::time::{Clock, Deadline};
    use heimdall_issuer::client::{ChildCommand, ChildIssuer, ClientConfig};
    use heimdall_issuer::remote::ChildRemoteIssuer;
    use heimdall_issuer::store::SecretStore as _;
    use heimdall_store::ext_effects::AppliedRecord;
    use heimdall_store::{NoFaults, Store};

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn plus(t: Timestamp, d: Duration) -> Timestamp {
        Timestamp::from_second(t.as_second() + i64::try_from(d.as_secs()).unwrap()).unwrap()
    }

    fn pair() -> AccessPairRef {
        AccessPairRef {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn scope() -> Scope {
        Scope {
            pairs: [pair()].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        }
    }

    /// The runner's state database (written by `remote init`).
    fn state_db(home: &Path) -> PathBuf {
        fn find(dir: &Path) -> Option<PathBuf> {
            for entry in std::fs::read_dir(dir).ok()?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(found) = find(&path) {
                        return Some(found);
                    }
                } else if path.file_name().is_some_and(|n| n == "state.db") {
                    return Some(path);
                }
            }
            None
        }
        find(home).expect("the runner's state database")
    }

    /// Admission is the runner's: one grant under a standing policy of the runner, written
    /// to its store while no runtime runs (as a covering policy's activation leaves it).
    fn seed_runner_grant(home: &Path, now: Timestamp) -> (EnvironmentId, GrantId) {
        let store = Store::open(&state_db(home), Arc::new(NoFaults)).unwrap();
        let grant = GrantId::from_random_bytes([0x71; 16]);
        let profile = ProfileId::parse("runner-profile").unwrap();
        let env = store
            .transaction(|tx| {
                let env = tx.self_environment()?.expect("a runner environment");
                let mut e = tx.environment(&env)?.unwrap();
                e.permissions = heimdall_domain::environment::EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                };
                tx.upsert_environment(&e)?;
                tx.upsert_profile(&ProfileDefinition {
                    id: profile.clone(),
                    revision: 1,
                    scope: scope(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("runner-pol").unwrap(),
                        revision: PolicyRevision(1),
                        profile: profile.clone(),
                        workspace: None,
                        scope: scope(),
                        environments: [env.clone()].into_iter().collect(),
                        max_window: 4 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: LockBehavior::Continue,
                        connection: ConnectionPolicy::default(),
                        default: false,
                    },
                    false,
                )?;
                tx.upsert_destination(&DestinationRecord {
                    id: DestinationId::parse("h1").unwrap(),
                    alias: "h1".into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: now,
                })?;
                let generation = tx.authority_generation()?;
                tx.insert_grant(&GrantSnapshot {
                    id: grant.clone(),
                    environment: env.clone(),
                    scope: scope(),
                    starts_at: now,
                    deadline: Deadline {
                        intent: DeadlineIntent::Duration("2h".into()),
                        resolved_at: now,
                        effective: plus(now, 2 * HOUR),
                    },
                    parent: None,
                    source: AuthorizationSource::StandingPolicy {
                        revision: PolicyRevision(1),
                    },
                    generation,
                    state: GrantState::Active,
                    enforcement: EnforcementEvidence {
                        report: Enforcement {
                            destination_scope: DestinationScopeEnforcement::ClientRouting,
                            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                            workload_isolation: WorkloadIsolation::SharedOsUser,
                            existing_connections:
                                ExistingConnectionsPolicy::GracefulDedicatedConnections,
                            revocation: RevocationStatus::LocalApplied,
                            identity_selection: None,
                            new_signing_expiry: None,
                            owned_multiplexing: None,
                            remote_processes: None,
                            unmanaged_connections: None,
                            issuer_isolation: None,
                            ordinary_aliases: None,
                            owner_functions: None,
                        },
                        evidence: Vec::new(),
                    },
                })?;
                tx.set_grant_origin(
                    &grant,
                    &GrantOrigin {
                        profile,
                        profile_revision: 1,
                        policy_revision: Some(PolicyRevision(1)),
                        caller: CallerContext {
                            principal: PrincipalRef::UnixUser { uid: 1000 },
                            role: ClientRole::Owner,
                            remote_client: None,
                        },
                        mechanism: "managed_certificate".into(),
                        covered: None,
                        adapter: None,
                        lock_behavior: None,
                        connection: None,
                        workspace: None,
                        policy_id: None,
                    },
                )?;
                Ok(env)
            })
            .unwrap();
        (env, grant)
    }

    /// The scratch secret store's directory inside a state directory (the CLI's
    /// `SCRATCH_STORE_DIR`, selected by `HEIMDALL_TEST_SECRET_STORE=scratch`).
    const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

    /// The controller's production issuer over `home`: K_ca registered `active` in `store`
    /// and held in the scratch secret store, the runtime's time anchor persisted, and the
    /// real `heimdall internal issuer` child started and ready.
    async fn production_issuer(
        home: &Path,
        account: &Path,
        store: &Arc<Store>,
        clock: &Arc<dyn Clock>,
        ca: SecretCaKey,
    ) -> ChildIssuer {
        let paths = heimdall_runtime::Paths::under(home);
        let fingerprint = ca.fingerprint().unwrap();
        let scratch = paths.state_dir.join(SCRATCH_STORE_DIR);
        std::fs::create_dir_all(&scratch).unwrap();
        heimdall_testkit::scratch_store::ScratchSecretStore::new(scratch)
            .put(&fingerprint, &ca)
            .unwrap();
        let now = clock.wall();
        store
            .transaction(|tx| {
                tx.insert_issuer(&heimdall_store::IssuerRecord {
                    ca_fingerprint: fingerprint.clone(),
                    public_key: ca.public_openssh().unwrap(),
                    state: heimdall_contract::issuer::CaState::Active,
                    store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })
            })
            .unwrap();
        drop(ca);
        // The same-boot anchor the issuer child's read-only time assessment needs (the
        // runtime persists it at start).
        heimdall_app::timegate::TimeGate::new(
            store.clone(),
            clock.clone(),
            heimdall_testkit::ScriptedTimeSync::new(
                heimdall_domain::time::SyncStatus::Synchronized,
            ),
            heimdall_domain::time::TimePolicy::default(),
        )
        .check()
        .await
        .unwrap();
        let env = |k: &str, v: &std::ffi::OsStr| (k.into(), v.to_owned());
        let issuer = ChildIssuer::new(ClientConfig::new(
            ChildCommand {
                program: bin().into(),
                args: vec![
                    "--home".into(),
                    home.as_os_str().to_owned(),
                    "internal".into(),
                    "issuer".into(),
                ],
                env: vec![
                    env("HOME", account.as_os_str()),
                    env("HEIMDALL_HOME", home.as_os_str()),
                    env("HEIMDALL_TEST_SSH_HOME", account.as_os_str()),
                    env("HEIMDALL_TEST_SECRET_STORE", "scratch".as_ref()),
                ],
            },
            Arc::new(heimdall_runtime::platform::process_start_time),
        ));
        issuer.start().await.unwrap_or_else(|e| panic!("{e}"));
        let start = Instant::now();
        while issuer.state() != heimdall_contract::issuer::IssuerState::Ready {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "the issuer child did not become ready: {:?}",
                issuer.state()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        issuer
    }

    /// A real management session as the driver's port.
    struct DriverSession {
        inner: Session,
        hello: SessionHello,
    }

    #[async_trait::async_trait]
    impl ManagementSession for DriverSession {
        fn hello(&self) -> &SessionHello {
            &self.hello
        }

        fn runner_negotiated(&self) -> bool {
            self.inner
                .client
                .server()
                .capabilities
                .contains(capability::RUNNER_V1)
        }

        async fn call(&mut self, call: ManagementCall) -> Result<Envelope<Value>, OpError> {
            self.inner
                .client
                .request(call.into_request())
                .await
                .map_err(|_| OpError::new(Code::OutcomeUnknown, "the management session ended"))
        }
    }

    async fn open(
        dir: &Path,
        sshd: &LoopbackSshd,
        account: &str,
        key: &MgmtKey,
        environment: &str,
    ) -> DriverSession {
        let key = MgmtKey::from_store_bytes(&key.to_store_bytes()).unwrap();
        let public = key.public().unwrap();
        let signer =
            MgmtSigner::with_host_key_lines(key, [account.to_owned()], &[host_key(sshd)]).unwrap();
        let agent = SessionAgent::start(&dir.join("a.sock"), signer).unwrap();
        let (client, child) =
            connect_offering(dir, sshd, account, &public.openssh_line, environment, true)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        let hello = SessionHello {
            environment: client.server().environment_id.clone(),
            role: client.server().role,
            client: client.server().remote_client.clone(),
        };
        DriverSession {
            inner: Session {
                client,
                _child: child,
                agent,
            },
            hello,
        }
    }

    async fn close(session: DriverSession) {
        let DriverSession { inner, .. } = session;
        let Session {
            client,
            _child: mut child,
            agent,
        } = inner;
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
        agent.stop().await;
    }

    #[tokio::test]
    async fn the_driver_issues_revokes_while_disconnected_and_resynchronizes() {
        let scratch = Scratch::new().unwrap();
        let mut runner = Runner::new(&scratch);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let client = ClientId::from_random_bytes([0x5c; 16]);
        let ca = SecretCaKey::generate().unwrap();
        let ca_line = ca.public_openssh().unwrap();

        // 1. Pair: the runner-local bootstrap, with the controller's CA (issuer_trust and
        // the time-source designation, confirmed on the runner's terminal).
        let first = envelope(&runner.remote_init_with(
            &client,
            &key_text,
            "yes",
            &["--issuer-ca", ca_line.trim()],
        ));
        assert_eq!(first["code"], "OK", "{first}");
        let clock: Arc<dyn Clock> = Arc::new(heimdall_runtime::platform::SystemClock);
        let seeded_at = clock.wall();
        let (environment, grant) = seed_runner_grant(&runner.home, seeded_at);
        assert_eq!(first["data"]["environment"], environment.as_str());
        runner.start();

        // The fixture sshd reads the runner account's authorized_keys, as in the case above.
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
                    eprintln!("m06 driver e2e: blocked (no fixture sshd: {e})");
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
                eprintln!("m06 driver e2e: blocked (the fixture sshd has no local registry)");
            }
            return;
        };
        std::fs::remove_file(&registry).unwrap();
        std::os::unix::fs::symlink(runner.account.join(".ssh/authorized_keys"), &registry).unwrap();

        // The controller: its own store (where a controller home keeps it, so its issuer
        // child reads the same database), its pin of the runner, and the driver.
        let controller_home = scratch.subdir("ch").unwrap();
        let controller_account = scratch.subdir("ca").unwrap();
        let controller_paths = heimdall_runtime::Paths::under(&controller_home);
        controller_paths.ensure().unwrap();
        let store = Arc::new(
            Store::open(
                &controller_paths
                    .state_dir
                    .join(heimdall_runtime::service::STATE_DB_FILE),
                Arc::new(NoFaults),
            )
            .unwrap(),
        );
        let pin = RemoteEnvironmentPin {
            environment: environment.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: AccountName::parse(&account).unwrap(),
                    host_keys: vec![host_key(&sshd)],
                },
                jump: None,
            },
            client: client.clone(),
            role: Role::Owner,
            key_fingerprint: public.fingerprint.clone(),
            label: None,
            pinned_at: clock.wall(),
        };
        store
            .transaction(|tx| {
                tx.init_self_environment(&EnvironmentId::from_random_bytes([0x2c; 16]))?;
                tx.put_remote_environment_pin(
                    &pin.environment,
                    &pin.destination,
                    &pin.route.runner.account,
                    &pin.key_fingerprint,
                    &serde_json::to_string(&pin).unwrap(),
                    pin.pinned_at,
                )
            })
            .unwrap();
        let driver = ControllerSync::new(store.clone(), clock.clone());
        let ca_fingerprint = ca.fingerprint().unwrap();
        let child =
            production_issuer(&controller_home, &controller_account, &store, &clock, ca).await;
        let issuer = ChildRemoteIssuer::new(store.clone(), Arc::new(child.clone()));
        // Nothing is issued for a grant this controller holds no record of delivering; the
        // record is the certificate's content (pairs, extensions, expiry).
        let delivered_until = plus(seeded_at, 2 * HOUR);
        store
            .transaction(|tx| {
                deliver_runner_grant(
                    tx,
                    &pin,
                    &grant,
                    &[pair()].into(),
                    &["permit-pty".to_owned()].into(),
                    delivered_until,
                    clock.wall(),
                )
            })
            .unwrap()
            .unwrap();
        let view = |open: bool| {
            store
                .transaction(|tx| {
                    status_of(tx, &environment, open, Some(driver.barrier()), clock.wall())
                })
                .unwrap()
        };
        let never = view(false);
        assert!(matches!(
            never.connectivity,
            Connectivity::Unreachable { .. }
        ));
        assert_eq!(never.issuance, IssuanceGate::AwaitingResync);

        // 2. Reconnect: the owner session has runner/1; the reconnect order opens the barrier.
        let dir = scratch.subdir("cs1").unwrap();
        let mut session = open(&dir, &sshd, &account, &key, environment.as_str()).await;
        assert!(
            session.runner_negotiated(),
            "an owner session negotiates runner/1"
        );
        let first_sync = driver.on_session(&pin, &mut session).await.unwrap();
        assert!(first_sync.acknowledged.is_empty());
        assert!(
            first_sync.time_bounded,
            "the designated time source's sample was accepted"
        );
        assert!(first_sync.report.tombstones.is_empty());
        let connected = view(true);
        assert_eq!(connected.connectivity, Connectivity::Connected);
        assert_eq!(connected.issuance, IssuanceGate::Reconciled);

        // Issue remotely: prepare (runner), reserve and publish (this ledger), install (runner).
        let issued = {
            let mut channel = SessionChannel::new(&mut session).unwrap();
            driver
                .issue(
                    &pin,
                    &mut channel,
                    &issuer,
                    &RemoteIssueInput {
                        grant: grant.clone(),
                        grant_generation: first_sync.report.authority_generation,
                        lifetime: Duration::from_secs(30 * 60),
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
        };
        assert_eq!(issued.certificates.len(), 1);
        let valid_before = issued.certificates[0].valid_before;
        // The ledger entry was signed by the production issuer child as a reservation of
        // kind `remote`: published, under this controller's CA, with exactly the delivered
        // content (one principal, the delivered extension), inside the delivered expiry,
        // and whole seconds (a certificate carries no fraction: the runner's report below
        // states the same instant).
        let entry = store
            .transaction(|tx| tx.issuance_entry(&issued.certificates[0].issuance))
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.state,
            heimdall_domain::issuance::IssuanceState::Published
        );
        assert_eq!(entry.bounds.ca_fingerprint.as_ref(), Some(&ca_fingerprint));
        assert_eq!(
            entry.bounds.principal,
            heimdall_domain::issuance::principal_for(&pair())
        );
        assert_eq!(
            entry.bounds.extensions,
            ["permit-pty".to_owned()].into_iter().collect()
        );
        assert!(valid_before <= delivered_until);
        assert_eq!(valid_before.subsec_nanosecond(), 0);
        assert!(entry.bounds.key_id.contains(environment.as_str()));
        // The runner reports the certificate installed, issued by this controller.
        let after_issue = driver.on_session(&pin, &mut session).await.unwrap();
        assert_eq!(after_issue.report.certificates.len(), 1);
        assert_eq!(after_issue.report.certificates[0].grant, grant);
        assert_eq!(after_issue.report.certificates[0].issuer, client);
        assert_eq!(
            after_issue.report.certificates[0].valid_before,
            valid_before
        );

        // 3. Disconnect; the owner's local revoke of the runner's grant while disconnected.
        close(session).await;
        driver.session_closed(&environment);
        let narrowed = store
            .transaction(|tx| narrow_runner_grant(tx, &grant, clock.wall()))
            .unwrap()
            .expect("the ledger ties the grant to the runner")
            .unwrap();
        assert!(narrowed.produced);
        assert_eq!(narrowed.environment, environment);
        assert_eq!(
            narrowed.residual,
            Some(CountedResidual::Until(valid_before))
        );
        let away = view(false);
        assert!(matches!(
            away.connectivity,
            Connectivity::Disconnected { .. }
        ));
        assert_eq!(away.remote_pending.len(), 1);
        assert_eq!(away.issuance, IssuanceGate::AwaitingResync);
        assert_eq!(away.residuals.len(), 1);
        assert!(!away.residuals[0].acknowledged);
        assert!(away.last_known_readiness.iter().any(|r| r.grant == grant));

        // 4. Reconnect: delivered before the report, acknowledged with its enforcement
        // state; the report shows the tombstone; the barrier opens; the view shows it.
        let dir = scratch.subdir("cs2").unwrap();
        let mut session = open(&dir, &sshd, &account, &key, environment.as_str()).await;
        let resynced = driver.on_session(&pin, &mut session).await.unwrap();
        assert_eq!(resynced.acknowledged.len(), 1);
        assert_eq!(resynced.acknowledged[0].key, narrowed.key);
        assert!(matches!(
            &resynced.acknowledged[0].record,
            AppliedRecord::GrantTombstone {
                grant: g,
                known: true,
                key_destroyed: true,
                ..
            } if *g == grant
        ));
        assert!(resynced.report.tombstones.iter().any(|t| t.grant == grant));
        assert!(
            resynced.report.certificates.is_empty(),
            "K_env and its certificate are gone"
        );
        assert!(
            resynced
                .revoked
                .iter()
                .any(|r| r.grant == grant && r.residual == CountedResidual::Until(valid_before))
        );
        let back = view(true);
        assert_eq!(back.connectivity, Connectivity::Connected);
        assert!(back.remote_pending.is_empty());
        assert_eq!(back.issuance, IssuanceGate::Reconciled);
        assert!(back.residuals[0].acknowledged);
        assert!(
            back.residuals[0]
                .statement
                .contains("plus an unmeasured destination-clock error"),
            "{}",
            back.residuals[0].statement
        );
        // `environment status --json`: the remote fields sit in the environment's entry.
        let entry = serde_json::to_value(heimdall_app::remote_env::EnvironmentStatus {
            record: pin.clone(),
            remote: Some(back),
        })
        .unwrap();
        assert_eq!(entry["environment"], environment.as_str());
        assert_eq!(entry["connectivity"]["state"], "connected");
        assert_eq!(entry["issuance"], "reconciled");
        assert_eq!(entry["residuals"][0]["acknowledged"], true);

        // A revoked grant is never issued for again: refused by the barrier, nothing sent.
        let e = {
            let mut channel = SessionChannel::new(&mut session).unwrap();
            driver
                .issue(
                    &pin,
                    &mut channel,
                    &issuer,
                    &RemoteIssueInput {
                        grant: grant.clone(),
                        grant_generation: resynced.report.authority_generation,
                        lifetime: Duration::from_secs(60),
                    },
                )
                .await
                .unwrap_err()
        };
        assert_eq!(e.code, Code::CredentialExpired, "{e:?}");
        assert_ne!(e.reason.as_deref(), Some(reason::RESYNC_PENDING));
        close(session).await;
        driver.session_closed(&environment);
        assert_eq!(view(false).issuance, IssuanceGate::AwaitingResync);
        child.stop().await;
        drop(sshd);
    }

    /// A controller installation whose **runtime** hosts the driver (`service run`): its
    /// home, its account home, and the fixture file its K_mgmt lives in.
    struct ControllerRuntime {
        home: PathBuf,
        account: PathBuf,
        mgmt: PathBuf,
        runtime: Option<Child>,
    }

    impl ControllerRuntime {
        fn command(&self) -> Command {
            let mut cmd = Command::new(bin());
            cmd.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.account)
                .env("HEIMDALL_HOME", &self.home)
                .env("HEIMDALL_TEST_SSH_HOME", &self.account)
                .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
                .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
                .env(
                    "HEIMDALL_TEST_MGMT_STORE",
                    format!("fixture-file:{}", self.mgmt.display()),
                )
                .arg("--home")
                .arg(&self.home)
                .stdin(Stdio::null());
            cmd
        }

        fn json(&self, args: &[&str]) -> Value {
            let out = self.command().arg("--json").args(args).output().unwrap();
            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
                panic!(
                    "{args:?}: {} {}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )
            })
        }

        fn start(&mut self) {
            let child = self
                .command()
                .args(["service", "run"])
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(self.account.join("runtime.stderr")).unwrap())
                .spawn()
                .unwrap();
            self.runtime = Some(child);
            let start = Instant::now();
            while !self
                .command()
                .args(["--json", "service", "status"])
                .output()
                .unwrap()
                .status
                .success()
            {
                assert!(
                    start.elapsed() < Duration::from_secs(60),
                    "the controller runtime did not start: {}",
                    self.stderr()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        fn stderr(&self) -> String {
            std::fs::read_to_string(self.account.join("runtime.stderr")).unwrap_or_default()
        }

        /// Stop the runtime this test started (`service stop`, then its own child is
        /// waited for), leaving the installation for a later [`Self::start`].
        fn runtime_stop(&mut self) {
            if let Some(mut child) = self.runtime.take() {
                let _ = self.command().args(["service", "stop"]).output();
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(30) {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        /// This controller's entry for `environment` in `environment status --json`.
        fn status(&self, environment: &EnvironmentId) -> Value {
            let report = self.json(&["environment", "status"]);
            report["data"]["environments"]
                .as_array()
                .and_then(|all| {
                    all.iter()
                        .find(|e| e["environment"] == environment.as_str())
                        .cloned()
                })
                .unwrap_or_else(|| panic!("no entry for the runner: {report}"))
        }

        /// Poll `environment status` until `done` holds for the runner's entry.
        fn wait_for(
            &self,
            environment: &EnvironmentId,
            what: &str,
            done: impl Fn(&Value) -> bool,
        ) -> Value {
            let start = Instant::now();
            loop {
                let entry = self.status(environment);
                if done(&entry) {
                    return entry;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(90),
                    "{what}: {entry}\n{}",
                    self.stderr()
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    impl Drop for ControllerRuntime {
        fn drop(&mut self) {
            // Only the runtime this test started, through its own handle.
            if let Some(mut child) = self.runtime.take() {
                let _ = self.command().args(["service", "stop"]).output();
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(10) {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// ⟨M06 W3 host⟩ Remote issuance in the product: the controller's **runtime** hosts the
    /// driver. A real `heimdall service run` on the controller (scratch home, K_mgmt in a
    /// fixture file store, K_ca in the scratch secret store) reconnects to the recorded
    /// runner over its management line, runs the reconnect order, and issues for the grant
    /// this controller delivered: its own issuer child signs the `remote` reservation and
    /// the runner installs the certificate. `environment status` (a one-shot CLI read)
    /// reports it: connected, issuance open, the grant's last-known readiness. The owner's
    /// local `revoke` of the runner's grant then answers `OK` with `local_applied: false`
    /// and the grant `remote_pending`, the hosted driver delivers it at once, and the status
    /// shows the revoke applied on the runner.
    #[tokio::test]
    async fn the_controllers_runtime_hosts_the_driver_and_reports_through_environment_status() {
        let scratch = Scratch::new().unwrap();
        let mut runner = Runner::new(&scratch);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let client = ClientId::from_random_bytes([0x5d; 16]);
        let ca = SecretCaKey::generate().unwrap();
        let ca_line = ca.public_openssh().unwrap();
        let first = envelope(&runner.remote_init_with(
            &client,
            &key_text,
            "yes",
            &["--issuer-ca", ca_line.trim()],
        ));
        assert_eq!(first["code"], "OK", "{first}");
        let clock: Arc<dyn Clock> = Arc::new(heimdall_runtime::platform::SystemClock);
        let seeded_at = clock.wall();
        let (environment, grant) = seed_runner_grant(&runner.home, seeded_at);
        runner.start();
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
                    eprintln!("m06 hosted driver e2e: blocked (no fixture sshd: {e})");
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
                eprintln!(
                    "m06 hosted driver e2e: blocked (the fixture sshd has no local registry)"
                );
            }
            return;
        };
        std::fs::remove_file(&registry).unwrap();
        std::os::unix::fs::symlink(runner.account.join(".ssh/authorized_keys"), &registry).unwrap();

        // The controller installation, written while no runtime runs: its K_mgmt (fixture
        // file store), its CA (registered; the key in the scratch secret store), its record
        // of the runner and of the grant it delivered there.
        let mut controller = ControllerRuntime {
            home: scratch.subdir("ch").unwrap(),
            account: scratch.subdir("ca").unwrap(),
            mgmt: scratch.subdir("cm").unwrap().join("k_mgmt.fixture"),
            runtime: None,
        };
        {
            use heimdall_credential::mgmt::MgmtKeyStore as _;
            heimdall_credential::mgmt::fixture::FixtureMgmtStore::file(controller.mgmt.clone())
                .put(&key)
                .unwrap();
        }
        let paths = heimdall_runtime::Paths::under(&controller.home);
        paths.ensure().unwrap();
        let pin = RemoteEnvironmentPin {
            environment: environment.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: AccountName::parse(&account).unwrap(),
                    host_keys: vec![host_key(&sshd)],
                },
                jump: None,
            },
            client: client.clone(),
            role: Role::Owner,
            key_fingerprint: public.fingerprint.clone(),
            label: None,
            pinned_at: seeded_at,
        };
        {
            let store = Store::open(
                &paths
                    .state_dir
                    .join(heimdall_runtime::service::STATE_DB_FILE),
                Arc::new(NoFaults),
            )
            .unwrap();
            let fingerprint = ca.fingerprint().unwrap();
            let secrets = paths.state_dir.join(SCRATCH_STORE_DIR);
            std::fs::create_dir_all(&secrets).unwrap();
            heimdall_testkit::scratch_store::ScratchSecretStore::new(secrets)
                .put(&fingerprint, &ca)
                .unwrap();
            store
                .transaction(|tx| {
                    tx.init_self_environment(&EnvironmentId::from_random_bytes([0x2d; 16]))?;
                    tx.insert_issuer(&heimdall_store::IssuerRecord {
                        ca_fingerprint: fingerprint.clone(),
                        public_key: ca.public_openssh().unwrap(),
                        state: heimdall_contract::issuer::CaState::Active,
                        store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
                        backup_sha256: "ab".repeat(32),
                        backup_created_at: seeded_at,
                        restored_without_log: false,
                        created_at: seeded_at,
                        retired_at: None,
                    })?;
                    tx.put_remote_environment_pin(
                        &pin.environment,
                        &pin.destination,
                        &pin.route.runner.account,
                        &pin.key_fingerprint,
                        &serde_json::to_string(&pin).unwrap(),
                        pin.pinned_at,
                    )?;
                    Ok(deliver_runner_grant(
                        tx,
                        &pin,
                        &grant,
                        &[pair()].into(),
                        &["permit-pty".to_owned()].into(),
                        plus(seeded_at, 2 * HOUR),
                        seeded_at,
                    )?
                    .map(drop))
                })
                .unwrap()
                .unwrap();
        }
        drop(ca);

        // Before any runtime: never reached, issuance gated.
        let never = controller.status(&environment);
        assert_eq!(never["connectivity"]["state"], "unreachable", "{never}");
        assert_eq!(never["issuance"], "awaiting_resync");

        controller.start();
        // The hosted driver reconnected, resynchronized and issued; the status shows it.
        let ready = controller.wait_for(&environment, "the hosted driver did not issue", |e| {
            e["last_known_readiness"]
                .as_array()
                .is_some_and(|r| r.iter().any(|g| g["grant"] == grant.as_str()))
        });
        assert_eq!(ready["connectivity"]["state"], "connected", "{ready}");
        assert_eq!(ready["issuance"], "reconciled");
        assert!(ready.get("issuance_failures").is_none(), "{ready}");
        assert_eq!(ready["last_known_readiness"][0]["state"], "within_bound");
        // The runner holds exactly one certificate, issued by this controller.
        let readiness = &ready["last_known_readiness"][0];
        let until: Timestamp = readiness["offline_until"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            until,
            plus(seeded_at, 2 * HOUR),
            "valid to the delivered bound"
        );

        // The owner's local revoke of the runner's grant.
        let revoked = controller.json(&["access", "revoke", grant.as_str()]);
        assert_eq!(revoked["code"], "OK", "{revoked}");
        assert_eq!(revoked["data"]["local_applied"], false);
        assert_eq!(revoked["data"]["remote_pending"][0], grant.as_str());
        let applied = controller.wait_for(&environment, "the revoke was not delivered", |e| {
            e["residuals"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x["acknowledged"] == true))
        });
        assert!(applied["remote_pending"].as_array().unwrap().is_empty());
        assert_eq!(applied["residuals"][0]["grant"], grant.as_str());
        // The certificate is gone from the runner's next report, and nothing is issued for
        // the revoked grant again.
        let gone = controller.wait_for(
            &environment,
            "the runner still reports the certificate",
            |e| e.get("last_known_readiness").is_none(),
        );
        assert!(gone.get("issuance_failures").is_none(), "{gone}");
        drop(controller);
        drop(sshd);
    }

    // --- ⟨M06 W4 grant-e2e⟩ the journey with real binaries -----------------------------------

    /// The runner's catalog as its owner set it up, written while no runtime runs: the
    /// permissions of its own environment, one profile with one pair, the standing policy
    /// that admits work for it, and the destination. **No grant**: the grant comes from the
    /// controller's forwarded `ensure`.
    fn seed_runner_catalog(home: &Path, now: Timestamp, pair: &AccessPairRef) -> EnvironmentId {
        let store = Store::open(&state_db(home), Arc::new(NoFaults)).unwrap();
        let profile = ProfileId::parse("runner-profile").unwrap();
        let scope = Scope {
            pairs: [pair.clone()].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        };
        store
            .transaction(|tx| {
                let env = tx.self_environment()?.expect("a runner environment");
                let mut e = tx.environment(&env)?.unwrap();
                e.permissions = heimdall_domain::environment::EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                };
                tx.upsert_environment(&e)?;
                tx.upsert_profile(&ProfileDefinition {
                    id: profile.clone(),
                    revision: 1,
                    scope: scope.clone(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("runner-pol").unwrap(),
                        revision: PolicyRevision(1),
                        profile: profile.clone(),
                        workspace: None,
                        scope: scope.clone(),
                        environments: [env.clone()].into_iter().collect(),
                        max_window: 4 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: LockBehavior::Continue,
                        connection: ConnectionPolicy::default(),
                        default: false,
                    },
                    false,
                )?;
                tx.upsert_destination(&DestinationRecord {
                    id: pair.destination.clone(),
                    alias: pair.destination.as_str().to_owned(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: now,
                })?;
                Ok(env)
            })
            .unwrap()
    }

    /// The identities an agent endpoint lists (`ssh-add -L`), one line each. An endpoint
    /// that is gone, or lists nothing, gives none.
    fn listed_identities(endpoint: &str) -> Vec<String> {
        let out = Command::new(find_program("ssh-add").expect("ssh-add"))
            .arg("-L")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("SSH_AUTH_SOCK", endpoint)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-") || l.starts_with("sk-"))
            .map(str::to_owned)
            .collect()
    }

    /// One onward login from the runner to the fixture destination through a binding's
    /// endpoint, with the fixture isolation options: no configuration but an empty scratch
    /// file, the binding's certificate as the only identity, the binding's endpoint as the
    /// only agent, the destination's per-run host key pinned, no multiplexing. `(succeeded,
    /// output)`.
    fn onward_login(
        dir: &Path,
        destination: &LoopbackSshd,
        account: &str,
        endpoint: &str,
        certificate_line: &str,
    ) -> (bool, String) {
        std::fs::create_dir_all(dir).unwrap();
        let config = dir.join("ssh_config");
        std::fs::write(&config, "").unwrap();
        let known = dir.join("known_hosts");
        std::fs::write(&known, format!("{}\n", destination.host_key_line)).unwrap();
        let identity = dir.join("id-cert.pub");
        std::fs::write(&identity, format!("{certificate_line}\n")).unwrap();
        let out = Command::new(find_program("ssh").expect("an OpenSSH client"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", dir)
            .arg("-F")
            .arg(&config)
            .args(["-T", "-o", "BatchMode=yes"])
            .args(["-o", &format!("IdentityFile={}", identity.display())])
            .args(["-o", "IdentitiesOnly=yes"])
            .args(["-o", &format!("IdentityAgent={endpoint}")])
            .args(["-o", "CertificateFile=none"])
            .args(["-o", &format!("UserKnownHostsFile={}", known.display())])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .args(["-o", "StrictHostKeyChecking=yes"])
            .args(["-o", "ControlMaster=no", "-o", "ControlPath=none"])
            .args(["-o", "PreferredAuthentications=publickey"])
            .args(["-o", "ConnectTimeout=20"])
            .args(["-p", &destination.port.to_string()])
            .arg(format!("{account}@{}", destination.host))
            .arg("echo hm-onward")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_no_canary(&text);
        (out.status.success() && text.contains("hm-onward"), text)
    }

    /// ⟨M06 W4 `grant-e2e`; m06-plan §2 "What W3 carries" items 1 and 4; ADR-0012 §4 item 2
    /// ⟨2026-11-21⟩, §7; ADR-0005 §3.5 "Remote reservations"; spec A24's core⟩ **The journey,
    /// with real binaries on both sides.**
    ///
    /// 1. On the controller: `heimdall access ensure --environment <runner>` names no pair.
    ///    The controller's runtime resolves the scope from its own copy of the profile,
    ///    forwards the request (each pair naming the CA it will issue from), and records
    ///    what it asked. The runner admits the grant under its own standing policy, resolves
    ///    the pair to a managed certificate under its `issuer_trust` for that controller, and
    ///    waits. The controller's production issuer child signs the `remote` reservation; the
    ///    runner installs the certificate and its waiting `ensure` settles. The local caller
    ///    gets the runner's result, or the pending state and then `operation wait`.
    /// 2. On the runner: a local `access ensure` covered by that live grant attaches to it
    ///    (a new binding on the same grant). Its endpoint lists exactly one identity: the
    ///    certificate of the runner's K_env for that grant, signed by the controller's CA.
    /// 3. **The controller is stopped.** An onward `ssh` from the runner through that
    ///    endpoint to a fixture destination that trusts the CA succeeds.
    /// 4. The controller comes back while the runner cannot be reached; the owner's
    ///    `access revoke` answers `remote_pending`, and the runner still serves the grant.
    ///    Once the runner is reachable again the revoke is applied: acknowledged in
    ///    `environment status`, the endpoint lists nothing, and an onward login fails.
    #[tokio::test]
    async fn a_forwarded_ensure_reaches_onward_ssh_from_the_runner_with_the_controller_stopped() {
        let scratch = Scratch::new().unwrap();
        let destination_scratch = Scratch::new().unwrap();
        let mut runner = Runner::new(&scratch);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let client = ClientId::from_random_bytes([0x5e; 16]);
        let ca = SecretCaKey::generate().unwrap();
        let ca_line = ca.public_openssh().unwrap();
        let ca_fingerprint = ca.fingerprint().unwrap();
        let first = envelope(&runner.remote_init_with(
            &client,
            &key_text,
            "yes",
            &["--issuer-ca", ca_line.trim()],
        ));
        assert_eq!(first["code"], "OK", "{first}");
        let clock: Arc<dyn Clock> = Arc::new(heimdall_runtime::platform::SystemClock);
        let seeded_at = clock.wall();

        // The management sshd (the runner account's authorized_keys) and the destination
        // (it trusts the controller's CA for the pair's principal, as its administrator set).
        let blocked = |why: &str| {
            #[allow(clippy::print_stderr)] // the blocked row's reason
            {
                eprintln!("m06 grant e2e: blocked ({why})");
            }
        };
        let sshd = match LoopbackSshd::start(
            &scratch,
            SshdConfig {
                registry_seed: Some(Vec::new()),
                ..SshdConfig::default()
            },
        ) {
            Ok(s) => s,
            Err(e) => return blocked(&format!("no fixture sshd: {e}")),
        };
        let Some(account) = sshd.login_account().or_else(current_account) else {
            return blocked("the fixture account is unknown");
        };
        let Some(registry) = sshd.registry_path().map(Path::to_path_buf) else {
            return blocked("the fixture sshd has no local registry");
        };
        let pair = AccessPairRef {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse(&account).unwrap(),
        };
        let principal = heimdall_domain::issuance::principal_for(&pair);
        let ca_keys = destination_scratch
            .subdir("ca-keys")
            .unwrap()
            .join("trusted_user_ca_keys");
        std::fs::write(&ca_keys, b"").unwrap();
        let destination = match LoopbackSshd::start(
            &destination_scratch,
            SshdConfig {
                trusted_user_ca_keys: Some(ca_keys),
                authorized_principals: Some(
                    [(account.clone(), vec![principal.clone()])]
                        .into_iter()
                        .collect(),
                ),
                ..SshdConfig::default()
            },
        ) {
            Ok(s) => s,
            Err(e) => return blocked(&format!("no fixture destination sshd: {e}")),
        };
        destination.trust_user_ca(ca_line.trim()).unwrap();
        // The management sshd reads the runner account's authorized_keys through its
        // registry path; an empty file there makes the runner unreachable for new sessions.
        let runner_keys = runner.account.join(".ssh/authorized_keys");
        let reachable = |on: bool| {
            let _ = std::fs::remove_file(&registry);
            if on {
                std::os::unix::fs::symlink(&runner_keys, &registry).unwrap();
            } else {
                std::fs::write(&registry, b"").unwrap();
            }
        };
        reachable(true);

        let environment = seed_runner_catalog(&runner.home, seeded_at, &pair);
        assert_eq!(first["data"]["environment"], environment.as_str());
        runner.start();

        // The controller installation: K_mgmt, its CA, its record of the runner, and its
        // own copy of the profile (the forwarded scope is resolved from it).
        let mut controller = ControllerRuntime {
            home: scratch.subdir("ch").unwrap(),
            account: scratch.subdir("ca").unwrap(),
            mgmt: scratch.subdir("cm").unwrap().join("k_mgmt.fixture"),
            runtime: None,
        };
        {
            use heimdall_credential::mgmt::MgmtKeyStore as _;
            heimdall_credential::mgmt::fixture::FixtureMgmtStore::file(controller.mgmt.clone())
                .put(&key)
                .unwrap();
        }
        let paths = heimdall_runtime::Paths::under(&controller.home);
        paths.ensure().unwrap();
        let pin = RemoteEnvironmentPin {
            environment: environment.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: AccountName::parse(&account).unwrap(),
                    host_keys: vec![host_key(&sshd)],
                },
                jump: None,
            },
            client: client.clone(),
            role: Role::Owner,
            key_fingerprint: public.fingerprint.clone(),
            label: None,
            pinned_at: seeded_at,
        };
        {
            let store = Store::open(
                &paths
                    .state_dir
                    .join(heimdall_runtime::service::STATE_DB_FILE),
                Arc::new(NoFaults),
            )
            .unwrap();
            let secrets = paths.state_dir.join(SCRATCH_STORE_DIR);
            std::fs::create_dir_all(&secrets).unwrap();
            heimdall_testkit::scratch_store::ScratchSecretStore::new(secrets)
                .put(&ca_fingerprint, &ca)
                .unwrap();
            store
                .transaction(|tx| {
                    tx.init_self_environment(&EnvironmentId::from_random_bytes([0x2e; 16]))?;
                    tx.insert_issuer(&heimdall_store::IssuerRecord {
                        ca_fingerprint: ca_fingerprint.clone(),
                        public_key: ca.public_openssh().unwrap(),
                        state: heimdall_contract::issuer::CaState::Active,
                        store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
                        backup_sha256: "ab".repeat(32),
                        backup_created_at: seeded_at,
                        restored_without_log: false,
                        created_at: seeded_at,
                        retired_at: None,
                    })?;
                    tx.upsert_profile(&ProfileDefinition {
                        id: ProfileId::parse("runner-profile").unwrap(),
                        revision: 1,
                        scope: Scope {
                            pairs: [pair.clone()].into_iter().collect(),
                            capabilities: [Capability::SshAuthentication].into_iter().collect(),
                        },
                        label: None,
                    })?;
                    tx.put_remote_environment_pin(
                        &pin.environment,
                        &pin.destination,
                        &pin.route.runner.account,
                        &pin.key_fingerprint,
                        &serde_json::to_string(&pin).unwrap(),
                        pin.pinned_at,
                    )
                })
                .unwrap();
        }
        drop(ca);
        controller.start();

        // 1. The owner's `ensure --environment <runner>`, naming no pair.
        let forward = [
            "access",
            "ensure",
            "--profile",
            "runner-profile",
            "--environment",
            environment.as_str(),
            "--work-id",
            "job-1",
            "--for",
            "1h",
            "--request-id",
            "fwd-1",
        ];
        let mut answer = controller.json(&forward);
        if answer["code"] == "ACCEPTED" {
            // The pending state: no reason, the refresh dependency, the grant pending; the
            // operation it names is driven by `operation wait`.
            let data = &answer["data"];
            assert!(data["error"].get("reason").is_none(), "{answer}");
            assert_eq!(data["refresh_dependency"], "controller", "{answer}");
            assert_eq!(
                data["remote_pending"][0], data["error"]["resource"]["id"],
                "{answer}"
            );
            let operation = answer["operation_id"]
                .as_str()
                .unwrap_or_else(|| panic!("the pending answer names no operation: {answer}"))
                .to_owned();
            answer = controller.json(&["operation", "wait", &operation, "--timeout-ms", "60000"]);
        }
        assert_eq!(
            answer["code"],
            "OK",
            "{answer}\n{}\n{}\n{}",
            controller.stderr(),
            std::fs::read_to_string(runner.account.join("runtime.stderr")).unwrap_or_default(),
            controller.status(&environment)
        );
        let ready = answer["data"].clone();
        let grant = GrantId::parse(ready["grant_id"].as_str().unwrap()).unwrap();
        assert_eq!(ready["environment_id"], environment.as_str());
        assert_eq!(ready["credential_mechanism"], "managed_certificate");
        assert_eq!(ready["refresh_dependency"], "controller");
        // The same request again reads the same grant and reserves nothing more.
        let again = controller.json(&forward);
        assert_eq!(again["code"], "OK", "{again}");
        assert_eq!(again["data"]["grant_id"], grant.as_str());
        let status = controller.wait_for(&environment, "the grant is not reported", |e| {
            e["last_known_readiness"]
                .as_array()
                .is_some_and(|r| r.iter().any(|g| g["grant"] == grant.as_str()))
        });
        assert_eq!(status["connectivity"]["state"], "connected", "{status}");
        assert!(status.get("issuance_failures").is_none(), "{status}");

        // 2. On the runner: a local `ensure` covered by the live grant attaches to it.
        let local = runner
            .command()
            .args([
                "--json",
                "access",
                "ensure",
                "--profile",
                "runner-profile",
                "--pair",
                &format!("h1:{account}"),
                "--work-id",
                "job-local",
                "--for",
                "30m",
                "--request-id",
                "local-1",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let local: Value = serde_json::from_slice(&local.stdout).unwrap_or_else(|_| {
            panic!(
                "{} {}",
                String::from_utf8_lossy(&local.stdout),
                String::from_utf8_lossy(&local.stderr)
            )
        });
        assert!(
            matches!(local["code"].as_str(), Some("OK" | "ACCESS_READY")),
            "{local}"
        );
        assert_eq!(local["data"]["grant_id"], grant.as_str(), "the same grant");
        assert_ne!(local["data"]["binding_id"], ready["binding_id"], "{local}");
        assert_eq!(local["data"]["refresh_dependency"], "controller");
        let endpoint = local["data"]["consumer"]["signing_endpoint"]
            .as_str()
            .unwrap_or_else(|| panic!("the binding names no endpoint: {local}"))
            .to_owned();
        // The endpoint lists exactly the runner's K_env certificate for that grant.
        let listed = listed_identities(&endpoint);
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert!(listed[0].starts_with("ssh-ed25519-cert-v01@openssh.com "));
        let facts =
            heimdall_issuer::remote::read_certificate(&listed[0]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(facts.ca_fingerprint, ca_fingerprint);
        assert_eq!(facts.principals, vec![principal.clone()]);
        assert!(
            facts.key_id.contains(environment.as_str()),
            "{}",
            facts.key_id
        );
        assert!(facts.key_id.contains(grant.as_str()), "{}", facts.key_id);
        assert_ne!(
            facts.subject_fingerprint,
            public.fingerprint.as_str(),
            "never K_mgmt"
        );
        // The binding the forwarded request created lists the same single identity.
        let forwarded_endpoint = ready["consumer"]["signing_endpoint"].as_str().unwrap();
        assert_eq!(listed_identities(forwarded_endpoint), listed);

        // 3. The controller is stopped; the runner goes on.
        controller.runtime_stop();
        let dir = scratch.subdir("onward").unwrap();
        let mark = destination.log_mark();
        let (ok, out) = onward_login(&dir, &destination, &account, &endpoint, &listed[0]);
        assert!(
            ok,
            "onward ssh with the controller stopped: {out}\n{}",
            std::fs::read_to_string(runner.account.join("runtime.stderr")).unwrap_or_default()
        );
        let accepted = destination.accepted_certificates();
        assert!(
            accepted.iter().any(|c| c.key_id == facts.key_id
                && c.serial == facts.serial
                && c.ca_fingerprint == ca_fingerprint.as_str()),
            "{accepted:?} {:?}",
            destination.log_lines_since(mark, "Accepted")
        );

        // 4. The controller is back, the runner unreachable: the revoke is pending.
        reachable(false);
        controller.start();
        let away = controller.wait_for(&environment, "the runner is still reachable", |e| {
            e["connectivity"]["state"] != "connected"
        });
        assert_eq!(away["issuance"], "awaiting_resync", "{away}");
        let revoked = controller.json(&["access", "revoke", grant.as_str()]);
        assert_eq!(revoked["code"], "OK", "{revoked}");
        assert_eq!(revoked["data"]["local_applied"], false);
        assert_eq!(revoked["data"]["remote_pending"][0], grant.as_str());
        let pending = controller.status(&environment);
        assert_eq!(
            pending["remote_pending"].as_array().unwrap().len(),
            1,
            "{pending}"
        );
        // Not applied yet: the runner still serves the grant.
        assert_eq!(listed_identities(&endpoint), listed);
        let (ok, out) = onward_login(&dir, &destination, &account, &endpoint, &listed[0]);
        assert!(ok, "the revoke is only pending: {out}");

        // Reachable again: an owner-awaited pass (the same forwarded request) reconnects
        // at once; the reconnect order delivers the revoke before anything else.
        reachable(true);
        let _ = controller.json(&forward);
        let applied = controller.wait_for(&environment, "the revoke was not applied", |e| {
            e["residuals"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x["acknowledged"] == true))
        });
        assert!(
            applied["remote_pending"].as_array().unwrap().is_empty(),
            "{applied}"
        );
        assert_eq!(applied["residuals"][0]["grant"], grant.as_str());
        assert!(
            listed_identities(&endpoint).is_empty(),
            "nothing after the revoke"
        );
        let (ok, out) = onward_login(&dir, &destination, &account, &endpoint, &listed[0]);
        assert!(!ok, "no onward login after the revoke: {out}");
        drop(controller);
        drop(destination);
        drop(sshd);
    }
}

/// A local session on a runner runtime's own control endpoint, attended.
async fn attend_at(runner: &Runner) -> ControlClient<tokio::net::UnixStream> {
    let info = heimdall_runtime::instance::InstanceInfo::read_valid(
        &heimdall_runtime::Paths::under(&runner.home).runtime_dir,
    )
    .unwrap()
    .expect("the runner runtime's advertisement");
    let stream = heimdall_ipc::unix::connect(Path::new(&info.control_endpoint))
        .await
        .unwrap();
    let mut client = ControlClient::handshake(
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
    assert_eq!(client.attend().await.unwrap().code.as_str(), "OK");
    client
}

/// ⟨M06 W3; ADR-0012 §3.2; ADR-0006 §18.7 "Also ruled"⟩ The runner's effective sshd policy
/// reaches the runner through `service run --runner`, over a fixture configuration
/// (`HEIMDALL_TEST_RUNNER_SSHD_CONFIG`: the real `sshd -T`, nothing listens):
///
/// * a **verified non-default** policy (one keys file instead of sshd's default pair):
///   limited roles are available, so a `viewer` invitation approved at the runner is
///   created and its pending line is written to that one file;
/// * an **unverifiable** one (an `AuthorizedKeysCommand`): the runner is owner-only, so the
///   same approved invitation is refused `management_sshd_unverified` and no line is written.
///
/// The owner's paired session is the bridge itself (`heimdall remote serve --client <cid>
/// --home <home>`, the forced command, started directly with a cleared environment): no
/// daemon is needed for this row. Where the host has no `/usr/sbin/sshd` the case reports
/// `blocked`.
#[tokio::test]
async fn the_runners_sshd_policy_reaches_the_runner_and_gates_limited_roles() {
    const SSHD: &str = "/usr/sbin/sshd";
    if !Path::new(SSHD).exists() {
        #[allow(clippy::print_stderr)] // the blocked row's reason
        {
            eprintln!("m06 runner sshd policy: blocked ({SSHD} is absent on this host)");
        }
        return;
    }
    const RESTRICTED: &str = "AuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\n\
                              PermitUserEnvironment no\nAcceptEnv LANG LC_*\n\
                              AuthenticationMethods any\nPubkeyAuthentication yes\n";
    let verified = format!("AuthorizedKeysFile .ssh/authorized_keys\n{RESTRICTED}");
    let unverifiable = verified.replace(
        "AuthorizedKeysCommand none",
        "AuthorizedKeysCommand /usr/bin/false\nAuthorizedKeysCommandUser nobody",
    );
    let scratch = Scratch::new().unwrap();
    for (tag, config, limited) in [("v", verified, true), ("u", unverifiable, false)] {
        let mut runner = Runner::named(&scratch, tag);
        let config_path = scratch.path().join(format!("sshd_config_{tag}"));
        std::fs::write(&config_path, config).unwrap();
        runner.sshd_config = Some(config_path);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let owner = ClientId::from_random_bytes([0x71; 16]);
        let init = envelope(&runner.remote_init(&owner, &key_text, "yes"));
        assert_eq!(init["code"], "OK", "{tag}: {init}");
        let environment = init["data"]["environment"].as_str().unwrap().to_owned();
        let keys_file = runner.account.join(".ssh").join("authorized_keys");
        let owner_line = std::fs::read_to_string(&keys_file).unwrap();
        runner.start();

        // The owner's paired session: the bridge over its own standard streams.
        let mut bridge = tokio::process::Command::new(bin());
        bridge
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &runner.account)
            .args(["remote", "serve", "--client", owner.as_str(), "--home"])
            .arg(&runner.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut bridge = bridge.spawn().unwrap();
        let streams = tokio::io::join(bridge.stdout.take().unwrap(), bridge.stdin.take().unwrap());
        let required: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
        let mut paired = tokio::time::timeout(
            Duration::from_secs(30),
            ControlClient::handshake(
                streams,
                PeerInfo {
                    name: "heimdall-cli".into(),
                    version: "test".into(),
                },
                required,
                InteractionMode::NonInteractive,
            ),
        )
        .await
        .expect("the bridge's hello")
        .unwrap_or_else(|e| panic!("{tag}: {e}"));
        assert_eq!(paired.server().role, Some(Role::Owner));
        assert_eq!(paired.server().remote_client.as_ref(), Some(&owner));

        // A viewer's invitation: submitted by the paired owner, approved at the runner.
        let invited_key = MgmtKey::generate().unwrap().public().unwrap();
        let invited_text = invited_key
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let invite: Request = serde_json::from_value(serde_json::json!({
            "op": "remote_environment", "action": "invite", "environment": environment,
            "role": "viewer", "key_fingerprint": invited_key.fingerprint,
            "public_key": invited_text, "request_id": format!("e2e-policy-{tag}"),
        }))
        .unwrap();
        let pending = paired.request(invite).await.unwrap();
        assert_eq!(
            pending.code.as_str(),
            "APPROVAL_REQUIRED",
            "{tag}: {pending:?}"
        );
        let decision = pending.next.unwrap().decision_ref.unwrap();
        let mut at_runner = attend_at(&runner).await;
        let decided = at_runner
            .request(Request::Decide(DecideRequest {
                decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
                verdict: Verdict::Approve,
            }))
            .await
            .unwrap();
        let text = serde_json::to_string(&decided).unwrap();
        assert_no_canary(&text);
        let now = std::fs::read_to_string(&keys_file).unwrap();
        if limited {
            assert_eq!(decided.code.as_str(), "OK", "{text}");
            assert_eq!(decided.data["role"], "viewer", "{text}");
            let invited = decided.data["client"].as_str().unwrap();
            assert!(now.starts_with(&owner_line), "the owner's line kept: {now}");
            assert!(
                now.contains(&format!("heimdall-mgmt:{invited}")) && now.contains("expiry-time="),
                "the pending line is in the verified policy's one file: {now}"
            );
            assert!(
                !runner
                    .account
                    .join(".ssh")
                    .join("authorized_keys2")
                    .exists(),
                "the verified list names one file"
            );
            // ⟨ADR-0006 §18.7 item 17⟩ A management session in which sshd allocated a PTY:
            // its bridge refuses it, and this running runner is owner-only from then on
            // (no restart): the next limited invitation is refused at its approval.
            let unrestricted = std::process::Command::new(bin())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &runner.account)
                .env("SSH_TTY", "/dev/ttys999")
                .args(["remote", "serve", "--client", owner.as_str(), "--home"])
                .arg(&runner.home)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(!unrestricted.status.success(), "{unrestricted:?}");
            let late_key = MgmtKey::generate().unwrap().public().unwrap();
            let late_text = late_key
                .openssh_line
                .rsplit_once(' ')
                .map(|(k, _)| k.to_owned())
                .unwrap();
            let late: Request = serde_json::from_value(serde_json::json!({
                "op": "remote_environment", "action": "invite", "environment": environment,
                "role": "viewer", "key_fingerprint": late_key.fingerprint,
                "public_key": late_text, "request_id": "e2e-policy-late",
            }))
            .unwrap();
            let pending = paired.request(late).await.unwrap();
            assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
            let decision = pending.next.unwrap().decision_ref.unwrap();
            let refused = at_runner
                .request(Request::Decide(DecideRequest {
                    decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
                    verdict: Verdict::Approve,
                }))
                .await
                .unwrap();
            assert_eq!(
                refused.data["error"]["reason"], "management_sshd_unverified",
                "{refused:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&keys_file).unwrap(),
                now,
                "no line was written for it"
            );

            // ⟨ADR-0006 §18.7 items 18–19⟩ Lifting it, on this running runner. The lift
            // needs a terminal: without one nothing is asked or changed.
            assert_eq!(
                recorded_downgrade(&runner.home).as_deref(),
                Some("session_pty")
            );
            let unattended = runner
                .command()
                .args(["--json", "remote", "policy", "recheck"])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let refused = envelope(&String::from_utf8_lossy(&unattended.stdout));
            assert_eq!(refused["code"], "INTERACTION_REQUIRED", "{refused}");
            // With a terminal but no evidence: refused before anything is asked.
            let no_evidence = envelope(&runner.on_terminal(
                &[
                    "remote".to_owned(),
                    "policy".to_owned(),
                    "recheck".to_owned(),
                ],
                NEVER_ASKED,
            ));
            assert_eq!(
                no_evidence["code"], "CAPABILITY_UNAVAILABLE",
                "{no_evidence}"
            );
            assert_eq!(
                no_evidence["data"]["error"]["reason"], "management_sshd_unverified",
                "{no_evidence}"
            );
            // The owner's controller reports its probes over its management session; the
            // runner runs the real `sshd -T` over the fixture configuration again and
            // records the evidence. Nothing is lifted by it.
            let recheck: Request = serde_json::from_value(serde_json::json!({
                "op": "remote_environment", "action": "runner_policy_recheck",
                "environment": environment,
                "probe": {
                    "pty_refused": true, "forward_refused": true,
                    "agent_forward_refused": true, "setenv_canary_delivered": false,
                },
            }))
            .unwrap();
            let recorded = paired.request(recheck).await.unwrap();
            assert_eq!(recorded.code.as_str(), "OK", "{recorded:?}");
            assert_eq!(recorded.data["recorded"], true, "{recorded:?}");
            assert_eq!(recorded.data["controller"], owner.as_str());
            assert!(recorded_downgrade(&runner.home).is_some());
            // The owner at the runner's terminal: shown the evidence, typed `yes`, lifted
            // through the running runtime's attended local form.
            let transcript = runner.on_terminal(
                &[
                    "remote".to_owned(),
                    "policy".to_owned(),
                    "recheck".to_owned(),
                ],
                "yes",
            );
            assert!(
                transcript.contains(owner.as_str())
                    && transcript.contains("sshd allocated a terminal"),
                "the evidence is shown: {transcript}"
            );
            let lifted = envelope(&transcript);
            assert_eq!(lifted["code"], "OK", "{lifted}");
            assert_eq!(lifted["data"]["lifted"], true, "{lifted}");
            assert_eq!(recorded_downgrade(&runner.home), None);
            // Limited roles are admitted again, with no restart.
            let again_key = MgmtKey::generate().unwrap().public().unwrap();
            let again_text = again_key
                .openssh_line
                .rsplit_once(' ')
                .map(|(k, _)| k.to_owned())
                .unwrap();
            let again: Request = serde_json::from_value(serde_json::json!({
                "op": "remote_environment", "action": "invite", "environment": environment,
                "role": "viewer", "key_fingerprint": again_key.fingerprint,
                "public_key": again_text, "request_id": "e2e-policy-again",
            }))
            .unwrap();
            let pending = paired.request(again).await.unwrap();
            assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
            let decision = pending.next.unwrap().decision_ref.unwrap();
            let approved = at_runner
                .request(Request::Decide(DecideRequest {
                    decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
                    verdict: Verdict::Approve,
                }))
                .await
                .unwrap();
            assert_eq!(approved.code.as_str(), "OK", "{approved:?}");
        } else {
            assert_eq!(decided.code.as_str(), "CAPABILITY_UNAVAILABLE", "{text}");
            assert_eq!(
                decided.data["error"]["reason"], "management_sshd_unverified",
                "{text}"
            );
            assert_eq!(now, owner_line, "owner-only: no line was written");
        }
        drop(at_runner);
        drop(paired);
        let _ = bridge.kill().await;
        // Nothing of the check is left in the runner's state directory.
        let left: Vec<_> =
            std::fs::read_dir(heimdall_runtime::Paths::under(&runner.home).state_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| n.to_string_lossy().starts_with("hm-sshd-policy-"))
                .collect();
        assert!(left.is_empty(), "{tag}: {left:?}");
    }
}

/// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ `remote init` and what is not its to change,
/// through the real binary on a pseudo-terminal:
///
/// * the account's `~/.ssh` is a **symbolic link**: refused (`CONFIG_CONFLICT`, effect
///   `none`) before the confirmation is asked; no state, nothing behind the link;
/// * a **first** `remote init` while a runtime that is not a runner's holds the home:
///   `driver_unavailable`, and the message says to stop the local runtime first;
/// * a **group-writable home**: the enrollment succeeds, the answer says what sshd's
///   `StrictModes` would refuse (`strict_modes`), the mode is left as it was, and `doctor`
///   reports the same finding.
#[tokio::test]
async fn remote_init_refuses_and_reports_what_it_never_changes() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new().unwrap();
    let key = MgmtKey::generate().unwrap().public().unwrap();
    let key_text = key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let client = ClientId::from_random_bytes([0x33; 16]);

    // A symbolic link at ~/.ssh.
    let linked = Runner::named(&scratch, "l");
    let elsewhere = scratch.subdir("elsewhere").unwrap();
    std::os::unix::fs::symlink(&elsewhere, linked.account.join(".ssh")).unwrap();
    let transcript = linked.remote_init(&client, &key_text, NEVER_ASKED);
    let refused = envelope(&transcript);
    assert_eq!(refused["code"], "CONFIG_CONFLICT", "{transcript}");
    assert_eq!(refused["data"]["error"]["effect_status"], "none");
    let message = refused["data"]["error"]["message"].as_str().unwrap();
    assert!(message.contains("is a symbolic link"), "{message}");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    assert!(
        !heimdall_runtime::Paths::under(&linked.home)
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE)
            .exists(),
        "no state was written"
    );

    // A first `remote init` under a runtime that is not a runner's.
    let mut plain = Runner::named(&scratch, "p");
    plain.start();
    let transcript = plain.remote_init(&client, &key_text, NEVER_ASKED);
    let refused = envelope(&transcript);
    assert_eq!(refused["code"], "CAPABILITY_UNAVAILABLE", "{transcript}");
    assert_eq!(refused["data"]["error"]["reason"], "driver_unavailable");
    assert_eq!(refused["data"]["error"]["effect_status"], "none");
    let message = refused["data"]["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("stop the local runtime first")
            && message.contains("`heimdall service stop`"),
        "{message}"
    );
    assert!(!plain.account.join(".ssh").exists(), "nothing was created");
    drop(plain);

    // A home sshd's StrictModes would refuse: said, and left as it is.
    let loose = Runner::named(&scratch, "g");
    std::fs::set_permissions(&loose.account, std::fs::Permissions::from_mode(0o775)).unwrap();
    let transcript = loose.remote_init(&client, &key_text, "yes");
    let done = envelope(&transcript);
    assert_eq!(done["code"], "OK", "{transcript}");
    assert_eq!(done["data"]["line_written"], true, "{done}");
    assert_eq!(
        done["data"]["strict_modes"],
        serde_json::json!([{ "path": "home", "problem": "group_or_other_writable" }]),
        "{done}"
    );
    let mode = std::fs::metadata(&loose.account)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o775, "the home's mode is not changed");
    let doctor = loose
        .command()
        .args(["--json", "doctor"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&doctor.stdout).into_owned();
    assert_no_canary(&report);
    let report = envelope(&report);
    let findings = report["data"]["findings"].as_array().unwrap();
    let finding = findings
        .iter()
        .find(|f| f["code"] == "runner_ssh_strict_modes")
        .unwrap_or_else(|| panic!("no StrictModes finding: {report}"));
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("the home directory is writable by group or others"),
        "{finding}"
    );
    let mode = std::fs::metadata(&loose.account)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o775, "doctor changes nothing");
}
