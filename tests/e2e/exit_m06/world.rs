//! ⟨M06 W5 U7⟩ The shared world of the M06 real-binary journeys: the runner and controller
//! installations (scratch homes, the real `heimdall` binary, `service run [--runner]`), the
//! management session over a fixture sshd, the grant journey's two installations with the
//! production issuer, and the fixture `ssh` and `ssh-add` calls.
//!
//! **Moved here unchanged from `environment_runner_m06.rs`** (W2–W5), which now includes
//! this file, so the exit suite (`exit_m06.rs`) and that suite share one copy (as
//! `exit_m05` shares `exit_m03/`'s world). Additions for the exit suite are marked ⟨U7⟩.
//!
//! **Isolation** is stated in `environment_runner_m06.rs`'s header and holds here: every
//! process gets a cleared environment with scratch `HOME`, `HEIMDALL_HOME` and
//! `HEIMDALL_TEST_SSH_HOME`; every fixture sshd is unprivileged on 127.0.0.1 with per-run
//! host keys; every fixture `ssh` reads only a scratch `-F` file with the fixture option
//! set and no `SSH_AUTH_SOCK`; only processes these helpers started are stopped, through
//! their own handles.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::controller_record::{ManagementHop, ManagementRoute, RemoteEnvironmentPin};
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, GrantId, PolicyId, ProfileId,
};
use heimdall_contract::ipc::{PeerInfo, capability};
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::remote::Role;
use heimdall_contract::request::{AccessPairRef, InteractionMode};
use heimdall_credential::cert::SecretCaKey;
use heimdall_credential::mgmt::{MgmtKey, MgmtSigner, SessionAgent};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{Capability, Scope};
use heimdall_domain::time::Clock;
use heimdall_ipc::session::ControlClient;
use heimdall_issuer::store::SecretStore as _;
use heimdall_sshconf::mgmt::{
    HopIdentity, MgmtHop, MgmtTarget, PinnedKey, render_mgmt_config, render_mgmt_pin_file,
};
use heimdall_sshconf::render::{HostName, PathStyle, RenderPath};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::{Scratch, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use serde_json::Value;

pub(crate) fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// [`Runner::remote_init`]'s answer for a case that must be refused before it is asked.
pub(crate) const NEVER_ASKED: &str = "<never asked>";

/// The runner installation: its Heimdall home and account home.
pub(crate) struct Runner {
    pub(crate) home: PathBuf,
    pub(crate) account: PathBuf,
    pub(crate) runtime: Option<Child>,
    /// ⟨M06 W3⟩ `HEIMDALL_TEST_RUNNER_SSHD_CONFIG` for the runtime, when the case has one.
    pub(crate) sshd_config: Option<PathBuf>,
    /// ⟨U7⟩ `HEIMDALL_TEST_TIME_SYNC` for this runner's processes (`synchronized` unless a
    /// journey restarts the runner with uncertain time).
    pub(crate) time_sync: &'static str,
    /// ⟨W5⟩ `HEIMDALL_TEST_IROH_KEY_STORE` for this installation's processes: the debug
    /// build's fixture K_iroh store (kind `fixture_store`; mechanism evidence only). `None`:
    /// the variable is not set and no K_iroh is ever created.
    pub(crate) iroh_store: Option<PathBuf>,
}

impl Runner {
    pub(crate) fn new(scratch: &Scratch) -> Runner {
        Runner {
            home: scratch.subdir("rh").unwrap(),
            account: scratch.subdir("ra").unwrap(),
            runtime: None,
            sshd_config: None,
            time_sync: "synchronized",
            iroh_store: None,
        }
    }

    /// A second, separate runner installation under `scratch` (`tag` names its directories).
    pub(crate) fn named(scratch: &Scratch, tag: &str) -> Runner {
        Runner {
            home: scratch.subdir(&format!("{tag}h")).unwrap(),
            account: scratch.subdir(&format!("{tag}a")).unwrap(),
            runtime: None,
            sshd_config: None,
            time_sync: "synchronized",
            iroh_store: None,
        }
    }

    pub(crate) fn command(&self) -> Command {
        let mut cmd = Command::new(bin());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.account)
            .env("HEIMDALL_HOME", &self.home)
            .env("HEIMDALL_TEST_SSH_HOME", &self.account)
            .env("HEIMDALL_TEST_TIME_SYNC", self.time_sync)
            .arg("--home")
            .arg(&self.home);
        if let Some(config) = &self.sshd_config {
            cmd.env("HEIMDALL_TEST_RUNNER_SSHD_CONFIG", config);
        }
        self.fixture_stores(&mut cmd);
        cmd
    }

    /// ⟨M06 exit c11⟩ The fixture key stores of every `heimdall` this installation starts
    /// (AGENTS.md), so none can reach the account's own: the scratch secret store, a K_mgmt
    /// fixture file beside the home (`<home>-mgmt-store`, created only if a K_mgmt is ever
    /// written, which a runner never does), and K_iroh: the installation's fixture store
    /// when it has one ([`Self::with_iroh_fixture_store`]), otherwise a scratch path that
    /// does not exist (`<home>-no-iroh-store`), which the debug build's store refuses for
    /// every operation (`Unavailable(Missing)`), so no K_iroh is ever created, as before.
    fn fixture_stores(&self, cmd: &mut Command) {
        let beside = |suffix: &str| {
            let mut name = self.home.file_name().unwrap().to_os_string();
            name.push(suffix);
            self.home.with_file_name(name)
        };
        cmd.env("HEIMDALL_TEST_SECRET_STORE", "scratch")
            .env(
                "HEIMDALL_TEST_MGMT_STORE",
                format!("fixture-file:{}", beside("-mgmt-store").display()),
            )
            .env(
                "HEIMDALL_TEST_IROH_KEY_STORE",
                self.iroh_store
                    .clone()
                    .unwrap_or_else(|| beside("-no-iroh-store")),
            );
    }

    /// ⟨W5⟩ Give this installation a fixture K_iroh store: a new owner-only directory
    /// `name` under `scratch`. Takes effect for the processes started afterwards.
    pub(crate) fn with_iroh_fixture_store(&mut self, scratch: &Scratch, name: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch.subdir(name).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        self.iroh_store = Some(dir);
    }

    /// `heimdall remote init …` on a pseudo-terminal (`script(1)`), answering `answer` to the
    /// confirmation; the transcript.
    pub(crate) fn remote_init(&self, client: &ClientId, key: &str, answer: &str) -> String {
        self.remote_init_with(client, key, answer, &[])
    }

    /// [`Self::remote_init`] with more arguments (`--iroh-endpoint <id>`).
    pub(crate) fn remote_init_with(
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
    pub(crate) fn on_terminal(&self, args: &[String], answer: &str) -> String {
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
            .env("HEIMDALL_HOME", &self.home)
            .env("HEIMDALL_TEST_SSH_HOME", &self.account);
        self.fixture_stores(&mut cmd);
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

    /// ⟨M06 W5k⟩ `heimdall --home <home> <args…>` on a pseudo-terminal (`script(1)`) whose
    /// prompts are answered in order: each `(prompt, answer)` waits until the transcript
    /// shows `prompt` after the previous answer, then types `answer`. A command that exits
    /// before a prompt appears ends the dialog there (the caller reads the transcript). The
    /// environment is [`Self::on_terminal`]'s. Returns the transcript.
    pub(crate) fn on_terminal_dialog(&self, args: &[String], steps: &[(&str, &str)]) -> String {
        use std::io::Write as _;
        let mut argv = vec![
            bin(),
            "--home".to_owned(),
            self.home.to_string_lossy().into_owned(),
        ];
        argv.extend(args.iter().cloned());
        let mut cmd = Command::new("script");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.account)
            .env("HEIMDALL_HOME", &self.home)
            .env("HEIMDALL_TEST_SSH_HOME", &self.account);
        self.fixture_stores(&mut cmd);
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
        let mut from = 0;
        'dialog: for (prompt, answer) in steps {
            let start = Instant::now();
            loop {
                let now = text();
                if let Some(at) = now.get(from..).and_then(|rest| rest.find(prompt)) {
                    from += at + prompt.len();
                    break;
                }
                if child.try_wait().unwrap().is_some() {
                    break 'dialog;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(60),
                    "no prompt {prompt:?}: {now}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(answer.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
            stdin.flush().unwrap();
        }
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(90),
                "the command did not exit: {}",
                text()
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
    pub(crate) fn start(&mut self) {
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

impl Runner {
    /// ⟨U7⟩ Stop the runtime this installation started (`service stop` on its own scratch
    /// home, then its own child is waited for), leaving it for a later [`Self::start`].
    pub(crate) fn runtime_stop(&mut self) {
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
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
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
pub(crate) fn envelope(transcript: &str) -> Value {
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

pub(crate) fn rpath(p: &Path) -> RenderPath {
    RenderPath::absolute(p, PathStyle::Unix).unwrap()
}

/// `<type> <base64>` of the fixture's known-hosts line.
pub(crate) fn host_key(sshd: &LoopbackSshd) -> String {
    let mut words = sshd.host_key_line.split_ascii_whitespace().skip(1);
    format!("{} {}", words.next().unwrap(), words.next().unwrap())
}

/// A management session through the isolated configuration and K_mgmt's session agent.
pub(crate) struct Session {
    pub(crate) client: MgmtClient,
    pub(crate) _child: tokio::process::Child,
    pub(crate) agent: SessionAgent,
}

pub(crate) async fn open_session(
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

pub(crate) type MgmtClient =
    ControlClient<tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>>;

/// A management connection through the isolated configuration, with the session agent at
/// `dir/a.sock` already serving the key whose public line is `public_line`.
pub(crate) async fn connect(
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
pub(crate) async fn connect_offering(
    dir: &Path,
    sshd: &LoopbackSshd,
    account: &str,
    public_line: &str,
    environment_name: &str,
    offer_runner: bool,
) -> Result<(MgmtClient, tokio::process::Child), String> {
    connect_with(
        dir,
        sshd,
        &host_key(sshd),
        account,
        public_line,
        environment_name,
        client_hello(offer_runner),
    )
    .await
}

/// ⟨U7⟩ The hello the CLI's session opener sends for an owner record (⟨w5e⟩ a limited
/// record's requires nothing: `heimdall_app::remote_env::SessionCapabilities`): this build's
/// protocol and schema, `remote-control/1` required, `runner/1` offered when `offer_runner`.
pub(crate) fn client_hello(offer_runner: bool) -> heimdall_contract::ipc::ClientHello {
    let required: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
    let mut capabilities = heimdall_ipc::session::server_capabilities();
    capabilities.extend(required.iter().cloned());
    if offer_runner {
        capabilities.insert(capability::RUNNER_V1.to_owned());
    }
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
    }
}

/// ⟨U7⟩ [`connect_offering`] with the pinned host key and the client hello given (the
/// body is `connect_offering`'s, unchanged): `pin` is the `<type> <base64>` the isolated
/// configuration pins for the runner hop, whatever key `sshd` presents.
pub(crate) async fn connect_with(
    dir: &Path,
    sshd: &LoopbackSshd,
    pin: &str,
    account: &str,
    public_line: &str,
    environment_name: &str,
    hello: heimdall_contract::ipc::ClientHello,
) -> Result<(MgmtClient, tokio::process::Child), String> {
    let pin = pin.to_owned();
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
        heimdall_localenv::sys::openssh_env::fill_openssh_environment,
    )
    .map_err(|e| e.message)?;
    let heimdall_app::remote_env::ssh::ManagementChild {
        child,
        stdin,
        stdout,
        stderr,
    } = child;
    let handshake = tokio::time::timeout(
        Duration::from_secs(30),
        ControlClient::handshake_hello(tokio::io::join(stdout, stdin), hello),
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

/// ⟨ADR-0006 §18.7 item 18⟩ The cause token of the owner-only downgrade recorded in the
/// state database of the runner home `home` (read-only; `None` without the row).
pub(crate) fn recorded_downgrade(home: &Path) -> Option<String> {
    let db = heimdall_runtime::Paths::under(home)
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
        .unwrap()
        .transaction(|tx| tx.runner_downgrade())
        .unwrap()
        .map(|d| d.cause)
}

/// A local session on a runner runtime's own control endpoint, attended.
pub(crate) async fn attend_at(runner: &Runner) -> ControlClient<tokio::net::UnixStream> {
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

pub(crate) const HOUR: Duration = Duration::from_secs(3600);

pub(crate) fn plus(t: Timestamp, d: Duration) -> Timestamp {
    Timestamp::from_second(t.as_second() + i64::try_from(d.as_secs()).unwrap()).unwrap()
}

/// The runner's state database (written by `remote init`).
pub(crate) fn state_db(home: &Path) -> PathBuf {
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

/// The scratch secret store's directory inside a state directory (the CLI's
/// `SCRATCH_STORE_DIR`, selected by `HEIMDALL_TEST_SECRET_STORE=scratch`).
pub(crate) const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

/// A controller installation whose **runtime** hosts the driver (`service run`): its
/// home, its account home, and the fixture file its K_mgmt lives in.
pub(crate) struct ControllerRuntime {
    pub(crate) home: PathBuf,
    pub(crate) account: PathBuf,
    pub(crate) mgmt: PathBuf,
    pub(crate) runtime: Option<Child>,
}

impl ControllerRuntime {
    pub(crate) fn command(&self) -> Command {
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

    pub(crate) fn json(&self, args: &[&str]) -> Value {
        let out = self.command().arg("--json").args(args).output().unwrap();
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            panic!(
                "{args:?}: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        })
    }

    pub(crate) fn start(&mut self) {
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

    pub(crate) fn stderr(&self) -> String {
        std::fs::read_to_string(self.account.join("runtime.stderr")).unwrap_or_default()
    }

    /// Stop the runtime this test started (`service stop`, then its own child is
    /// waited for), leaving the installation for a later [`Self::start`].
    pub(crate) fn runtime_stop(&mut self) {
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
    pub(crate) fn status(&self, environment: &EnvironmentId) -> Value {
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
    pub(crate) fn wait_for(
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

/// The runner's catalog as its owner set it up, written while no runtime runs: the
/// permissions of its own environment, one profile with one pair, the standing policy
/// that admits work for it, and the destination. **No grant**: the grant comes from the
/// controller's forwarded `ensure`.
pub(crate) fn seed_runner_catalog_with(
    home: &Path,
    now: Timestamp,
    pairs: &[AccessPairRef],
    window: Duration,
) -> EnvironmentId {
    let store = Store::open(&state_db(home), Arc::new(NoFaults)).unwrap();
    let profile = ProfileId::parse("runner-profile").unwrap();
    let scope = Scope {
        pairs: pairs.iter().cloned().collect(),
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
                    max_window: window,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                    default: false,
                },
                false,
            )?;
            let destinations: BTreeSet<&DestinationId> =
                pairs.iter().map(|p| &p.destination).collect();
            for destination in destinations {
                tx.upsert_destination(&DestinationRecord {
                    id: destination.clone(),
                    alias: destination.as_str().to_owned(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: now,
                })?;
            }
            Ok(env)
        })
        .unwrap()
}

/// The identities an agent endpoint lists (`ssh-add -L`), one line each. An endpoint
/// that is gone, or lists nothing, gives none.
pub(crate) fn listed_identities(endpoint: &str) -> Vec<String> {
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
pub(crate) fn onward_login(
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

/// The two installations of the grant journeys, running: a runner (`service run
/// --runner`, its own standing policy for `runner-profile`, the controller's CA in its
/// `issuer_trust`), the management sshd, a fixture destination that trusts the CA for
/// the pair's principal, and a controller (`service run`: K_mgmt in a fixture file
/// store, K_ca in the scratch secret store, its record of the runner, its own copy of
/// the profile holding [`Journey::pair`] only). Fields drop in order: the runtimes
/// first, the scratch directories last.
pub(crate) struct Journey {
    pub(crate) controller: ControllerRuntime,
    pub(crate) runner: Runner,
    pub(crate) destination: LoopbackSshd,
    pub(crate) _sshd: LoopbackSshd,
    /// ⟨U7⟩ The controller's client on the runner, and its K_mgmt (the fixture key the
    /// controller's file store holds), for a journey that opens its own session.
    pub(crate) client: ClientId,
    pub(crate) mgmt_key: MgmtKey,
    pub(crate) environment: EnvironmentId,
    pub(crate) account: String,
    /// `h1:<account>`: the one pair of the controller's copy of the profile.
    pub(crate) pair: AccessPairRef,
    pub(crate) principal: String,
    pub(crate) ca_fingerprint: heimdall_contract::ids::CaFingerprint,
    pub(crate) mgmt_fingerprint: String,
    pub(crate) registry: PathBuf,
    pub(crate) runner_keys: PathBuf,
    pub(crate) scratch: Scratch,
    pub(crate) _destination_scratch: Scratch,
}

impl Journey {
    /// The management sshd reads the runner account's authorized_keys through its
    /// registry path; an empty file there makes the runner unreachable for new sessions.
    pub(crate) fn reachable(&self, on: bool) {
        let _ = std::fs::remove_file(&self.registry);
        if on {
            std::os::unix::fs::symlink(&self.runner_keys, &self.registry).unwrap();
        } else {
            std::fs::write(&self.registry, b"").unwrap();
        }
    }
}

/// ⟨U7⟩ A controller installation written while no runtime runs (the block [`journey`]
/// had inline, unchanged): K_mgmt `key` in a fixture file store, its record of the runner
/// `environment` behind the management `sshd` as the owner client `client`, its own copy
/// of `runner-profile` holding `pair`, and, with `ca`, its issuer (the CA registered
/// `active`, the key in the scratch secret store). `tag` names its directories under
/// `scratch`; `seed` its own environment ID. Not started.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install_controller(
    scratch: &Scratch,
    tag: &str,
    seed: u8,
    key: &MgmtKey,
    client: &ClientId,
    ca: Option<&SecretCaKey>,
    environment: &EnvironmentId,
    sshd: &LoopbackSshd,
    account: &str,
    pair: &AccessPairRef,
) -> ControllerRuntime {
    let controller = ControllerRuntime {
        home: scratch.subdir(&format!("{tag}h")).unwrap(),
        account: scratch.subdir(&format!("{tag}a")).unwrap(),
        mgmt: scratch
            .subdir(&format!("{tag}m"))
            .unwrap()
            .join("k_mgmt.fixture"),
        runtime: None,
    };
    {
        use heimdall_credential::mgmt::MgmtKeyStore as _;
        heimdall_credential::mgmt::fixture::FixtureMgmtStore::file(controller.mgmt.clone())
            .put(key)
            .unwrap();
    }
    let paths = heimdall_runtime::Paths::under(&controller.home);
    paths.ensure().unwrap();
    let seeded_at = heimdall_runtime::platform::SystemClock.wall();
    let pin = RemoteEnvironmentPin {
        environment: environment.clone(),
        destination: DestinationId::parse("runner1").unwrap(),
        route: ManagementRoute {
            runner: ManagementHop {
                hostname: sshd.host.clone(),
                port: Some(sshd.port),
                account: AccountName::parse(account).unwrap(),
                host_keys: vec![host_key(sshd)],
            },
            jump: None,
        },
        client: client.clone(),
        role: Role::Owner,
        key_fingerprint: key.public().unwrap().fingerprint.clone(),
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
        store
            .transaction(|tx| {
                tx.init_self_environment(&EnvironmentId::from_random_bytes([seed; 16]))?;
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
    if let Some(ca) = ca {
        install_issuer(&controller, ca);
    }
    controller
}

/// ⟨M06 W5 `w5n`⟩ A second controller **device** with nothing written yet: its
/// directories and the path of its fixture K_mgmt store. Its key is made by the product
/// (`environment join --show-key`) and its record of the runner by the product's `join`;
/// [`seed_controller_profile`] then gives it the profile its requests name.
pub(crate) fn empty_controller(scratch: &Scratch, tag: &str) -> ControllerRuntime {
    ControllerRuntime {
        home: scratch.subdir(&format!("{tag}h")).unwrap(),
        account: scratch.subdir(&format!("{tag}a")).unwrap(),
        mgmt: scratch
            .subdir(&format!("{tag}m"))
            .unwrap()
            .join("k_mgmt.fixture"),
        runtime: None,
    }
}

/// ⟨M06 W5 `w5n`⟩ The catalog part of [`install_controller`] and nothing else, for a
/// device whose K_mgmt and record of the runner the product wrote: its own copy of
/// `runner-profile` holding `pair` (no product command gives a controller a profile for a
/// runner's pair). Written while no runtime runs. **No record of the runner is written
/// here**: `environment join` wrote it.
pub(crate) fn seed_controller_profile(controller: &ControllerRuntime, pair: &AccessPairRef) {
    assert!(
        controller.runtime.is_none(),
        "written while no runtime runs"
    );
    let paths = heimdall_runtime::Paths::under(&controller.home);
    paths.ensure().unwrap();
    let store = Store::open(
        &paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE),
        Arc::new(NoFaults),
    )
    .unwrap();
    store
        .transaction(|tx| {
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("runner-profile").unwrap(),
                revision: 1,
                scope: Scope {
                    pairs: [pair.clone()].into_iter().collect(),
                    capabilities: [Capability::SshAuthentication].into_iter().collect(),
                },
                label: None,
            })
        })
        .unwrap();
}

/// ⟨U7⟩ Give the stopped controller installation `controller` its issuer: `ca` registered
/// `active` in its state database, the key in its scratch secret store.
pub(crate) fn install_issuer(controller: &ControllerRuntime, ca: &SecretCaKey) {
    assert!(
        controller.runtime.is_none(),
        "written while no runtime runs"
    );
    let paths = heimdall_runtime::Paths::under(&controller.home);
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
        .put(&fingerprint, ca)
        .unwrap();
    let now = heimdall_runtime::platform::SystemClock.wall();
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
}

/// [`Journey`], started. The runner's profile and standing policy hold `h1:<account>`
/// and `more_runner_pairs(account)`, with `runner_window` as the policy's maximum
/// window. `None`: blocked (no fixture sshd), with the reason on stderr.
pub(crate) fn journey(
    more_runner_pairs: impl Fn(&str) -> Vec<AccessPairRef>,
    runner_window: Duration,
) -> Option<Journey> {
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
    let blocked = |why: &str| -> Option<Journey> {
        #[allow(clippy::print_stderr)] // the blocked row's reason
        {
            eprintln!("m06 grant e2e: blocked ({why})");
        }
        None
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
    std::os::unix::fs::symlink(&runner_keys, &registry)
        .or_else(|_| {
            std::fs::remove_file(&registry)?;
            std::os::unix::fs::symlink(&runner_keys, &registry)
        })
        .unwrap();

    let mut runner_pairs = vec![pair.clone()];
    runner_pairs.extend(more_runner_pairs(&account));
    let environment =
        seed_runner_catalog_with(&runner.home, seeded_at, &runner_pairs, runner_window);
    assert_eq!(first["data"]["environment"], environment.as_str());
    runner.start();

    // The controller installation: K_mgmt, its CA, its record of the runner, and its
    // own copy of the profile (the forwarded scope is resolved from it).
    let mut controller = install_controller(
        &scratch,
        "c",
        0x2e,
        &key,
        &client,
        Some(&ca),
        &environment,
        &sshd,
        &account,
        &pair,
    );
    drop(ca);
    controller.start();
    Some(Journey {
        controller,
        runner,
        destination,
        _sshd: sshd,
        client,
        mgmt_key: key,
        environment,
        account,
        pair,
        principal,
        ca_fingerprint,
        mgmt_fingerprint: public.fingerprint.as_str().to_owned(),
        registry,
        runner_keys,
        scratch,
        _destination_scratch: destination_scratch,
    })
}

/// `heimdall --json --home <home> <args…>` on a pseudo-terminal, in exactly `env`.
/// `answer` is typed at the `[y/N]` confirmation, which must then be asked; `None`: the
/// command is expected to ask nothing. The exit code and the envelope.
pub(crate) fn on_terminal(
    home: &Path,
    env: &[(&str, String)],
    args: &[&str],
    answer: Option<&str>,
) -> (i32, Value) {
    on_terminal_at(home, env, args, "[y/N]:", answer)
}

/// ⟨W5 `w5m`⟩ [`on_terminal`] for a command whose confirmation ends with `prompt` (the M06
/// confirmations end `Type yes to continue:`).
pub(crate) fn on_terminal_at(
    home: &Path,
    env: &[(&str, String)],
    args: &[&str],
    prompt: &str,
    answer: Option<&str>,
) -> (i32, Value) {
    let mut cmd = heimdall_testkit::console::TerminalCommand::new(bin())
        .arg("--json")
        .arg("--home")
        .arg(home)
        .args(args)
        .size(400, 50)
        .env("PATH", "/usr/bin:/bin");
    for (k, v) in env {
        cmd = cmd.env(k, v);
    }
    let mut t = cmd
        .spawn()
        .expect("blocked: script(1) is needed for the attended cases");
    if let Some(answer) = answer {
        if let Err(e) = t.expect(prompt, Duration::from_secs(60)) {
            panic!("{args:?}: no prompt: {e}");
        }
        std::thread::sleep(Duration::from_millis(300));
        t.send(format!("{answer}\r").as_bytes()).unwrap();
    }
    let code = t.wait(Duration::from_secs(120));
    let text = t.text();
    assert_no_canary(&text);
    assert!(!text.contains("panicked"), "{args:?}: {text}");
    let code = code.unwrap_or_else(|| panic!("{args:?}: did not exit: {text}"));
    (code, envelope(&text))
}

impl ControllerRuntime {
    /// [`on_terminal`] as this controller's owner.
    pub(crate) fn attended(&self, args: &[&str], answer: Option<&str>) -> (i32, Value) {
        self.attended_at(args, "[y/N]:", answer)
    }

    /// ⟨W5 `w5m`⟩ [`Self::attended`] for a confirmation that ends with `prompt`.
    pub(crate) fn attended_at(
        &self,
        args: &[&str],
        prompt: &str,
        answer: Option<&str>,
    ) -> (i32, Value) {
        let path = |p: &Path| p.to_string_lossy().into_owned();
        on_terminal_at(
            &self.home,
            &[
                ("HOME", path(&self.account)),
                ("HEIMDALL_HOME", path(&self.home)),
                ("HEIMDALL_TEST_SSH_HOME", path(&self.account)),
                ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
                ("HEIMDALL_TEST_SECRET_STORE", "scratch".to_owned()),
                (
                    "HEIMDALL_TEST_MGMT_STORE",
                    format!("fixture-file:{}", self.mgmt.display()),
                ),
            ],
            args,
            prompt,
            answer,
        )
    }
}

/// [`on_terminal`] as the runner's local owner.
pub(crate) fn runner_attended(runner: &Runner, args: &[&str]) -> (i32, Value) {
    let path = |p: &Path| p.to_string_lossy().into_owned();
    on_terminal(
        &runner.home,
        &[
            ("HOME", path(&runner.account)),
            ("HEIMDALL_HOME", path(&runner.home)),
            ("HEIMDALL_TEST_SSH_HOME", path(&runner.account)),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
        ],
        args,
        None,
    )
}

/// The grant a pending `ACCEPTED` answer names.
pub(crate) fn pending_grant(answer: &Value) -> GrantId {
    assert_eq!(answer["code"], "ACCEPTED", "{answer}");
    assert_eq!(
        answer["data"]["refresh_dependency"], "controller",
        "{answer}"
    );
    GrantId::parse(
        answer["data"]["remote_pending"][0]
            .as_str()
            .unwrap_or_else(|| panic!("the pending answer names no grant: {answer}")),
    )
    .unwrap()
}
