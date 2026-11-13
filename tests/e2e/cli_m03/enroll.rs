//! M03 wave 5 (U12): `e2e_cli_m03` submodule `enroll` (owner: worker E, see
//! `.m03-wave5-api.md` R1). The `heimdall enroll` commands through the **real binary**
//! against an **in-process runtime** (`Service::start_with`, as `cli_m02.rs` runs it),
//! whose enrollment ports are wired with test fakes after start
//! (`Operations::set_managed_wiring`, `set_enrollment_host`).
//!
//! **Fixtures** (m03-plan §0.2; ADR-0008 D13), all disposable, in one scratch tree per
//! test: U11's `LoopbackSshd` (loopback only, a per-run host key, its
//! `AuthorizedKeysFile` the explicit registry), a `FakeAgent` holding a per-run
//! existing-access key, U11's `TestCa` (its public line is the CA the plan names), the
//! catalog seeded in the runtime's own store. The step client is a `/bin/sh` wrapper
//! around the system `ssh` that adds only `-F <scratch config>` and the scratch
//! environment (the owner's `~/.ssh`, agent and keys are never read), counts its step
//! runs, and can be told to hang from its n-th step (the Ctrl-C case). The issuer
//! fake reports `ready` and signs nothing; the verification endpoints refuse to start
//! (no test here needs a verification to pass).
//!
//! **Platforms.** `foreign_remove_cli_refuses_redacted_bundle` needs no runtime and runs
//! everywhere. Everything else is `#[cfg(unix)]`: the step client wrapper is a `/bin/sh`
//! script and the typed-`yes` cases need a Unix pty (Windows: the pseudoconsole driver
//! and the harness fixture sshd, U13's native rows; not run here).
//!
//! Directories the tests create are made owner-only explicitly (the devbox's umask is
//! 002). Every byte the binary prints is scanned for canaries.

use std::ffi::OsString;
use std::path::Path;

use heimdall_testkit::assert_no_canary;

use super::{Out, bin};

/// `heimdall <args>` with exactly `env`, stdin closed.
fn cli_env(env: &[(OsString, OsString)], cwd: &Path, args: &[&str]) -> Out {
    let mut cmd = std::process::Command::new(bin());
    cmd.args(args)
        .env_clear()
        .current_dir(cwd)
        .stdin(std::process::Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn heimdall");
    let out = Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    };
    assert_no_canary(&out.stdout);
    assert_no_canary(&out.stderr);
    assert!(!out.stderr.contains("panicked"), "{args:?}: {out:?}");
    out
}

/// `--json` printed exactly one envelope: one stdout line, an object with the
/// envelope's fields.
fn one_envelope(out: &Out) -> serde_json::Value {
    let lines: Vec<&str> = out
        .stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 1, "exactly one envelope on stdout: {out:?}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    for k in [
        "schema_version",
        "state",
        "code",
        "data",
        "warnings",
        "next",
    ] {
        assert!(v.get(k).is_some(), "{k} in the envelope: {v}");
    }
    v
}

#[cfg(unix)]
fn owner_only_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(windows)]
fn owner_only_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    heimdall_testkit::win::set_owner_only(path).unwrap();
}

/// A recovery bundle with one enrollment of `marker`, redacted or with its host
/// removed (both are refused `bundle_redacted`).
fn redacted_bundle(marker: &str, redacted_flag: bool) -> serde_json::Value {
    serde_json::json!({
        "schema": heimdall_contract::issuer::RECOVERY_BUNDLE_SCHEMA,
        "created_at": "2026-11-01T00:00:00Z",
        "redacted": redacted_flag,
        "cas": [],
        "enrollments": [{
            "marker": marker,
            "destination_id": "dst_lab",
            "alias": "lab",
            "account": "deploy",
            "registry": {"resolved_by": "remote_home"},
            "registry_path_display": "$HOME/.ssh/authorized_keys",
            "form": "account",
            "state": "verified",
            "ca_fingerprint": format!("SHA256:{}", "A".repeat(43)),
            "ca_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture",
            "line_sha256": "ab".repeat(32),
        }],
        "instructions": [],
    })
}

/// m03-plan U12 ⟨r2⟩ (ADR-0008 D4 item 5): `enroll remove --from-bundle` refuses a
/// redacted bundle (the flag, or an entry without host name and port) with
/// `bundle_redacted` (`CAPABILITY_UNAVAILABLE`, exit 4), effect `none`, before any
/// runtime contact (the Heimdall home is never created). Human mode names the reason.
#[test]
fn foreign_remove_cli_refuses_redacted_bundle() {
    let scratch = tempfile::tempdir().unwrap();
    let dir = scratch.path().join("files");
    owner_only_dir(&dir);
    let account = scratch.path().join("account");
    owner_only_dir(&account);
    let marker = "heimdall:enr_00112233445566778899aabbccddeeff";
    for (i, flag) in [true, false].into_iter().enumerate() {
        let file = dir.join(format!("bundle-{i}.json"));
        std::fs::write(&file, redacted_bundle(marker, flag).to_string()).unwrap();
        // The home sits under a regular file, so no runtime can ever be started there:
        // a regression that contacts the runtime fails `SERVICE_UNAVAILABLE` (exit 5)
        // and leaves no process behind.
        let blocker = scratch.path().join(format!("blocker-{i}"));
        std::fs::write(&blocker, b"").unwrap();
        let home = blocker.join("home");
        let mut env: Vec<(OsString, OsString)> = vec![
            ("HEIMDALL_HOME".into(), home.clone().into_os_string()),
            ("HOME".into(), account.clone().into_os_string()),
        ];
        if cfg!(unix) {
            env.push(("PATH".into(), "/usr/bin:/bin".into()));
        } else {
            for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
                if let Some(v) = std::env::var_os(k) {
                    env.push((k.into(), v));
                }
            }
        }
        let f = file.to_string_lossy().into_owned();
        let argv = [
            "enroll",
            "remove",
            "--from-bundle",
            &f,
            "--marker",
            marker,
            "--alias",
            "lab",
        ];
        let mut json = vec!["--json", "--non-interactive"];
        json.extend_from_slice(&argv);
        let out = cli_env(&env, scratch.path(), &json);
        assert_eq!(out.code, 4, "{out:?}");
        let v = one_envelope(&out);
        assert_eq!(v["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
        assert_eq!(v["data"]["error"]["reason"], "bundle_redacted", "{out:?}");
        assert_eq!(v["data"]["error"]["effect_status"], "none", "{out:?}");
        assert!(!home.exists(), "no runtime contact");

        let mut human = vec!["--non-interactive"];
        human.extend_from_slice(&argv);
        let out = cli_env(&env, scratch.path(), &human);
        assert_eq!(out.code, 4, "{out:?}");
        assert!(out.stderr.contains("reason: bundle_redacted"), "{out:?}");
        assert!(out.stderr.contains("redacted"), "{out:?}");
        assert!(!home.exists());
    }
}

// =====================================================================================
// The world: an in-process runtime with the enrollment ports wired, and its fixtures
// =====================================================================================

#[cfg(unix)]
pub(super) mod world {
    use std::ffi::OsString;
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use heimdall_app::Operations;
    use heimdall_app::enrollment::{
        AgentReading, EnrollmentHost, GeneratedPaths, HostError, TrustPaths, effective_config_args,
    };
    use heimdall_app::managed::ManagedWiring;
    use heimdall_app::ports::{
        AdapterError, IssuanceRef, IssuerError, IssuerPort, IssuerStatusSnapshot, TargetEvaluator,
        VerificationEndpoints, VerificationSession,
    };
    use heimdall_contract::Timestamp;
    use heimdall_contract::enrollment::{
        ApprovedTarget, EnrollmentForm, EnrollmentPlan, EnrollmentState, NoProxy,
        RegistryCanonical, RegistryRef, RegistryResolvedBy, RemoteStep,
    };
    use heimdall_contract::ids::{
        AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId, OperationId,
    };
    use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_domain::catalog::{
        DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
        InteractionProfile,
    };
    use heimdall_domain::enrollment::{
        Determinism, EnrollmentHold, EnrollmentRecord, ExistingAccessRecord, HoldReason, LateWrite,
        ProxyRoute, RawHostKey, TargetEvaluation, marker_for,
    };
    use heimdall_runtime::config::{Config, Paths};
    use heimdall_runtime::service::{ManagedOptions, Service, ServiceOptions, SessionLockWiring};
    use heimdall_store::{IssuerRecord, Store};
    use heimdall_testkit::agent::{
        AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey, blob_fingerprint,
    };
    use heimdall_testkit::ca::TestCa;
    use heimdall_testkit::home::{ScratchHome, find_program};
    use heimdall_testkit::registry::PauseHooks;
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
    use tokio_util::sync::CancellationToken;

    use super::{Out, cli_env, owner_only_dir};

    type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    pub const ALIAS: &str = "hm-e2e";
    pub const DESTINATION: &str = "dst_e2e";

    pub fn rand16() -> [u8; 16] {
        let hex = heimdall_testkit::agent::random_hex(16);
        let mut b = [0u8; 16];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        b
    }

    fn write_mode(path: &Path, text: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::remove_file(path);
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn b64decode(s: &str) -> Vec<u8> {
        let val = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => u32::from(c - b'A'),
                b'a'..=b'z' => u32::from(c - b'a') + 26,
                b'0'..=b'9' => u32::from(c - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("not base64"),
            }
        };
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0);
        for c in s.trim_end_matches('=').bytes() {
            acc = (acc << 6) | val(c);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(u8::try_from((acc >> bits) & 0xff).unwrap());
            }
        }
        out
    }

    /// A raw host key from `(type, base64)`.
    pub fn raw_key(key_type: &str, b64: &str) -> RawHostKey {
        RawHostKey {
            key_type: key_type.to_owned(),
            key_b64: b64.to_owned(),
            fingerprint: blob_fingerprint(&b64decode(b64)).unwrap(),
            origin_display: "known_hosts".to_owned(),
            revoked: false,
        }
    }

    // --- the ports ---------------------------------------------------------------------

    /// The target evaluator: the sshd's route and host key (changeable).
    pub struct TestTarget(pub Mutex<TargetEvaluation>);

    impl TargetEvaluator for TestTarget {
        fn evaluate(&self, _alias: &str) -> TargetEvaluation {
            self.0.lock().unwrap().clone()
        }
    }

    /// The host port over a scratch runtime directory; the client is the wrapper.
    pub struct TestHost {
        runtime: PathBuf,
        client: PathBuf,
        version: String,
        agent_path: String,
    }

    impl EnrollmentHost for TestHost {
        fn client(&self) -> Option<String> {
            Some(self.client.display().to_string())
        }

        fn client_version(&self) -> Option<String> {
            Some(self.version.clone())
        }

        fn paths(&self, tag: &str) -> Option<GeneratedPaths> {
            let dir = self.runtime.join("e").join(tag);
            Some(GeneratedPaths {
                trust: TrustPaths {
                    tag: tag.to_owned(),
                    user_known_hosts: dir.join("known_hosts").display().to_string(),
                    global_known_hosts: dir.join("global_known_hosts").display().to_string(),
                },
                identity_file: dir.join("identity.pub").display().to_string(),
            })
        }

        fn write_files(
            &self,
            tag: &str,
            known_hosts_line: &str,
            identity_public: Option<&str>,
        ) -> Result<GeneratedPaths, HostError> {
            let paths = self.paths(tag).unwrap();
            owner_only_dir(&self.runtime.join("e"));
            owner_only_dir(&self.runtime.join("e").join(tag));
            write_mode(
                Path::new(&paths.trust.user_known_hosts),
                known_hosts_line.as_bytes(),
                0o600,
            );
            write_mode(Path::new(&paths.trust.global_known_hosts), b"", 0o600);
            if let Some(p) = identity_public {
                write_mode(
                    Path::new(&paths.identity_file),
                    format!("{}\n", p.trim()).as_bytes(),
                    0o600,
                );
            }
            Ok(paths)
        }

        fn identity_agent(&self, _alias: &str) -> AgentReading {
            AgentReading::Unset
        }

        fn endpoint_valid(&self, endpoint: &str) -> bool {
            endpoint == self.agent_path && Path::new(endpoint).exists()
        }

        fn heimdall_endpoints(&self) -> Vec<String> {
            vec![self.runtime.display().to_string()]
        }

        fn effective_config(&self, step: &RemoteStep) -> Result<String, HostError> {
            // The wrapper passes `-G` straight to the system ssh (not counted).
            let out = std::process::Command::new(&self.client)
                .args(effective_config_args(step))
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|_| HostError("ssh -G".into()))?;
            if !out.status.success() {
                return Err(HostError("ssh -G failed".into()));
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
    }

    /// The issuer: `ready`, never signs (no test here verifies).
    pub struct TestIssuer;

    impl IssuerPort for TestIssuer {
        fn status(&self) -> IssuerStatusSnapshot {
            IssuerStatusSnapshot {
                status: IssuerStatus {
                    state: IssuerState::Ready,
                    reason: None,
                    cas: Vec::new(),
                    orphan_store_items: Vec::new(),
                    issuer_isolation: Default::default(),
                    bundle_stale: false,
                },
            }
        }

        fn sign<'a, 'b, 'c>(
            &'a self,
            _entry: IssuanceRef,
            _subject: &'b str,
        ) -> BoxFut<'c, Result<String, IssuerError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move {
                Err(IssuerError::Protocol(
                    "the test issuer signs nothing".into(),
                ))
            })
        }

        fn unload<'a, 'b, 'c>(
            &'a self,
            _ca: &'b CaFingerprint,
        ) -> BoxFut<'c, Result<(), IssuerError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move { Ok(()) })
        }
    }

    /// The verification endpoints: never created (a verification ends inconclusive).
    pub struct NoEndpoints;

    impl VerificationEndpoints for NoEndpoints {
        fn create<'a, 'b, 'c, 'd>(
            &'a self,
            _operation: &'b OperationId,
            _plan: &'c EnrollmentPlan,
        ) -> BoxFut<'d, Result<Box<dyn VerificationSession>, AdapterError>>
        where
            'a: 'd,
            'b: 'd,
            'c: 'd,
            Self: 'd,
        {
            Box::pin(async move {
                Err(AdapterError::Unavailable(
                    "no verification endpoint in this test".into(),
                ))
            })
        }
    }

    // --- the world ---------------------------------------------------------------------

    struct Running {
        ops: Operations,
        handle: tokio::runtime::Handle,
        store: Arc<Store>,
        token: CancellationToken,
        thread: std::thread::JoinHandle<()>,
    }

    pub struct World {
        pub home: ScratchHome,
        service: Option<Running>,
        pub sshd: LoopbackSshd,
        agent: FakeAgent,
        pub target: Arc<TestTarget>,
        pub ca: TestCa,
        pub destination: DestinationId,
        pub account: AccountName,
        pub identity: IdentityId,
        pub registry: PathBuf,
        pub registry_remote: String,
        agent_locator: String,
        /// The wrapper's control directory: `count` (step runs), `hang-at` (hang from
        /// this step run on).
        pub ctl: PathBuf,
    }

    impl World {
        pub fn new() -> World {
            World::build(false).0
        }

        /// ⟨§17.25 item 3⟩ A world whose runtime is started with a script pause
        /// directory (`ManagedOptions::script_pause_dir`, as the test configuration's
        /// `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` sets it), and the hooks over that directory.
        pub fn with_pause() -> (World, PauseHooks) {
            let (w, hooks) = World::build(true);
            (w, hooks.unwrap())
        }

        fn build(pause: bool) -> (World, Option<PauseHooks>) {
            let home = ScratchHome::new();
            let existing_key = FixtureKey::generate();
            let account_name = current_account().expect("the local account");
            let ca = TestCa::generate(home.scratch()).unwrap();
            let sshd = LoopbackSshd::start(
                home.scratch(),
                SshdConfig {
                    authorized: vec![existing_key.public().clone()],
                    registry_seed: Some(Vec::new()),
                    ..SshdConfig::default()
                },
            )
            .unwrap_or_else(|e| panic!("{e}"));
            let registry = sshd
                .registry_path()
                .expect("a local registry")
                .to_path_buf();
            let registry_remote = sshd
                .registry_remote_path()
                .expect("a registry path")
                .to_owned();
            let agent = FakeAgent::start(
                Endpoint::in_scratch(home.scratch(), "existing").unwrap(),
                FakeAgentConfig {
                    keys: vec![existing_key.clone()],
                    mode: AgentMode::Normal,
                },
            );
            let agent_locator = agent.endpoint().locator().to_string_lossy().into_owned();
            home.write_user_config(&format!(
                "Host {ALIAS}\n  HostName 127.0.0.1\n  Port {}\n  User {account_name}\n",
                sshd.port
            ))
            .unwrap();
            let ctl = home.scratch().subdir("ctl").unwrap();
            owner_only_dir(&ctl);
            let system_ssh = find_program("ssh").expect("an ssh client");
            let bin = home.scratch().subdir("bin").unwrap();
            owner_only_dir(&bin);
            let client = bin.join("ssh");
            // `-G` (the host's effective-configuration check) goes straight through; a
            // step run is counted, and from `hang-at` on it never prints the ready line
            // (it sleeps in the step's own process group, which the runner kills).
            write_mode(
                &client,
                format!(
                    "#!/bin/sh\nHOME='{home}'; export HOME\nSSH_AUTH_SOCK='{decoy}'; export SSH_AUTH_SOCK\n\
                     unset SSH_ASKPASS SSH_ASKPASS_REQUIRE SSH_AGENT_PID DISPLAY\n\
                     for a in \"$@\"; do [ \"$a\" = -G ] && exec '{ssh}' -F '{cfg}' \"$@\"; done\n\
                     n=$(cat '{ctl}/count' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{ctl}/count'\n\
                     if [ -f '{ctl}/hang-at' ] && [ $n -ge $(cat '{ctl}/hang-at') ]; then echo $$ > '{ctl}/hang-pid'; exec /bin/sleep 60; fi\n\
                     exec '{ssh}' -F '{cfg}' \"$@\"\n",
                    home = home.git_home.display(),
                    decoy = home.decoy_agent().endpoint().locator().to_string_lossy(),
                    ssh = system_ssh.display(),
                    cfg = home.user_config.display(),
                    ctl = ctl.display(),
                )
                .as_bytes(),
                0o700,
            );
            let version_out = std::process::Command::new(&system_ssh)
                .arg("-V")
                .output()
                .unwrap();
            let version = String::from_utf8_lossy(&version_out.stderr)
                .trim()
                .to_owned();
            let runtime = home.scratch().subdir("rt").unwrap();
            owner_only_dir(&runtime);

            let (kt, kb) = host_key_of(&sshd.host_key_line);
            let target = Arc::new(TestTarget(Mutex::new(TargetEvaluation {
                hostname: "127.0.0.1".to_owned(),
                port: sshd.port,
                user: account_name.clone(),
                proxy: ProxyRoute::None,
                determinism: Determinism::Determined,
                host_keys: vec![raw_key(&kt, &kb)],
            })));
            let host = Arc::new(TestHost {
                runtime,
                client,
                version,
                agent_path: agent_locator.clone(),
            });
            let mut w = World {
                service: None,
                sshd,
                agent,
                target,
                ca,
                destination: DestinationId::parse(DESTINATION).unwrap(),
                account: AccountName::parse(&account_name).unwrap(),
                identity: IdentityId::from_random_bytes(rand16()),
                registry,
                registry_remote,
                agent_locator,
                ctl,
                home,
            };
            let hooks = pause.then(|| {
                let h = PauseHooks::new(w.home.scratch()).unwrap();
                owner_only_dir(&h.dir());
                h
            });
            w.start(host, &existing_key, hooks.as_ref().map(PauseHooks::dir));
            (w, hooks)
        }

        fn start(&mut self, host: Arc<TestHost>, existing: &FixtureKey, pause: Option<PathBuf>) {
            let root = self.home.root.clone();
            let token = CancellationToken::new();
            let service_token = token.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let handle = rt.handle().clone();
                rt.block_on(async move {
                    let clock =
                        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap());
                    let mut o = ServiceOptions::with_clock(
                        clock,
                        heimdall_testkit::ScriptedTimeSync::new(
                            heimdall_domain::time::SyncStatus::Synchronized,
                        ),
                    );
                    // The runtime's own test configuration carries the pause directory
                    // (its managed wiring is then replaced by this world's fakes below).
                    if let Some(dir) = pause {
                        o.managed = Some(ManagedOptions {
                            session_lock: SessionLockWiring::None,
                            script_pause_dir: Some(dir),
                            ..ManagedOptions::default()
                        });
                    }
                    let service = Service::start_with(
                        Paths::under(&root),
                        Config::default(),
                        o,
                        service_token,
                    )
                    .await
                    .unwrap();
                    let _ = tx.send((
                        handle,
                        service.operations().clone(),
                        Arc::clone(service.store()),
                    ));
                    let _ = service.run().await;
                });
            });
            let (handle, ops, store) = rx.recv().expect("the service started");
            let now = Timestamp::now();
            let identity = self.identity.clone();
            let (destination, account, port) = (
                self.destination.clone(),
                self.account.clone(),
                self.sshd.port,
            );
            let (ca_fp, ca_line) = (
                self.ca.fingerprint().clone(),
                self.ca.public_line().to_owned(),
            );
            let endpoint = agent_ref(&self.agent_locator);
            store
                .transaction(|tx| {
                    tx.upsert_identity(&IdentityRecord {
                        id: identity.clone(),
                        revision: 1,
                        source: IdentitySource::NativeAgent {
                            endpoint: endpoint.clone(),
                        },
                        public_key: existing.public_line_without_comment(),
                        fingerprint: existing.fingerprint(),
                        interaction: InteractionProfile {
                            interaction: heimdall_contract::provider::InteractionKind::None,
                            basis: heimdall_contract::provider::EvidenceBasis::Observed,
                        },
                        label: None,
                        adopted_at: now,
                        updated_at: now,
                    })?;
                    tx.upsert_destination(&DestinationRecord {
                        id: destination.clone(),
                        alias: ALIAS.to_owned(),
                        revision: 1,
                        definition: DestinationDefinition::Managed {
                            hostname: "127.0.0.1".to_owned(),
                            port: Some(port),
                            account: account.clone(),
                            identity: identity.clone(),
                        },
                        label: None,
                        updated_at: now,
                    })?;
                    tx.insert_issuer(&IssuerRecord {
                        ca_fingerprint: ca_fp.clone(),
                        public_key: ca_line.clone(),
                        state: CaState::Active,
                        store_kind: StoreKind::LinuxSecretService,
                        backup_sha256: "00".repeat(32),
                        backup_created_at: now,
                        restored_without_log: false,
                        created_at: now,
                        retired_at: None,
                    })
                })
                .unwrap();
            ops.set_managed_wiring(ManagedWiring {
                issuer: Some(Arc::new(TestIssuer) as Arc<dyn IssuerPort>),
                verification_endpoints: Some(
                    Arc::new(NoEndpoints) as Arc<dyn VerificationEndpoints>
                ),
                verification_runner: Some(Arc::new(heimdall_enroll::verify::Verifier::new())),
                target: Some(self.target.clone() as Arc<dyn TargetEvaluator>),
                ..ManagedWiring::default()
            });
            ops.set_enrollment_host(host as Arc<dyn EnrollmentHost>);
            self.service = Some(Running {
                ops,
                handle,
                store,
                token,
                thread,
            });
        }

        /// Deny every pending decision in process (an attended owner), so the next case
        /// starts from a settled record.
        pub fn deny_pending(&self) {
            use heimdall_contract::ids::DecisionId;
            use heimdall_contract::request::{DecideRequest, InteractionMode, Verdict};
            use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
            use std::os::unix::fs::MetadataExt as _;
            let s = self.service.as_ref().unwrap();
            let uid = std::fs::metadata(&self.home.root).unwrap().uid();
            for (id, _) in self.pending() {
                let ops = s.ops.clone();
                let caller = heimdall_app::Caller {
                    context: CallerContext {
                        principal: PrincipalRef::UnixUser { uid },
                        role: ClientRole::Owner,
                    },
                    attendance: heimdall_app::Attendance::Attended {
                        since: Timestamp::now(),
                    },
                    interaction: InteractionMode::Interactive,
                };
                let (tx, rx) = std::sync::mpsc::channel();
                s.handle.spawn(async move {
                    let r = ops
                        .decide(
                            &caller,
                            DecideRequest {
                                decision_id: DecisionId::parse(&id).unwrap(),
                                verdict: Verdict::Deny,
                            },
                        )
                        .await
                        .map(|_| ());
                    let _ = tx.send(r);
                });
                rx.recv().unwrap().unwrap_or_else(|e| panic!("deny: {e:?}"));
            }
            assert!(self.pending().is_empty());
        }

        pub fn tx<T>(
            &self,
            f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<T>,
        ) -> T {
            self.service.as_ref().unwrap().store.transaction(f).unwrap()
        }

        /// ⟨§17.27 item 4⟩ Save (or revise) the standing policy `id` of profile
        /// `<id>-profile` over this world's pair, with `lock` behaviour, a maximum window
        /// and an optional cutoff: the saved limits the runtime's conditional lock text
        /// (`inspect capabilities` `lock.disclosure`) states.
        pub fn save_policy(
            &self,
            id: &str,
            revision: u64,
            lock: heimdall_contract::managed::LockBehavior,
            max_window: std::time::Duration,
            cutoff: Option<Timestamp>,
        ) {
            use heimdall_contract::ids::{PolicyId, ProfileId};
            use heimdall_domain::policy::{
                PauseState, PolicyRevision, PolicySource, StandingPolicy,
            };
            use heimdall_domain::profile::ProfileDefinition;
            use heimdall_domain::scope::{AccessPair, Capability, Scope};
            let scope = Scope {
                pairs: [AccessPair {
                    destination: self.destination.clone(),
                    account: self.account.clone(),
                }]
                .into_iter()
                .collect(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            };
            let profile = ProfileId::parse(&format!("{id}-profile")).unwrap();
            let env = self
                .tx(|tx| tx.self_environment())
                .expect("the runtime's environment");
            let policy = StandingPolicy {
                id: PolicyId::parse(id).unwrap(),
                revision: PolicyRevision(revision),
                profile: profile.clone(),
                workspace: None,
                scope: scope.clone(),
                environments: [env].into_iter().collect(),
                max_window,
                pause: PauseState::Active,
                cutoff_at: cutoff,
                source: PolicySource::SetupDefault,
                lock_behavior: lock,
                connection: Default::default(),
            };
            self.tx(|tx| {
                tx.upsert_profile(&ProfileDefinition {
                    id: profile.clone(),
                    revision: 1,
                    scope: scope.clone(),
                    label: None,
                })?;
                tx.upsert_policy(&policy, false).map(|_| ())
            });
        }

        /// The once-only lock acknowledgement, if recorded.
        pub fn lock_ack(&self) -> Option<Timestamp> {
            self.tx(|tx| tx.lock_disclosure_ack())
        }

        /// The runtime's conditional lock text (`inspect capabilities` `lock.disclosure`).
        pub fn lock_text(&self) -> String {
            let out = self.cli(&["--json", "inspect", "capabilities"]);
            assert_eq!(out.code, 0, "{out:?}");
            let v: serde_json::Value = serde_json::from_str(out.stdout.trim()).unwrap();
            v["data"]["lock"]["disclosure"]
                .as_str()
                .unwrap_or_else(|| panic!("no lock disclosure: {v}"))
                .to_owned()
        }

        /// The environment every heimdall process of this world gets.
        pub fn env(&self) -> Vec<(OsString, OsString)> {
            vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), self.home.git_home.clone().into_os_string()),
                (
                    "HEIMDALL_HOME".into(),
                    self.home.root.clone().into_os_string(),
                ),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                (
                    "SSH_AUTH_SOCK".into(),
                    self.home.decoy_agent().endpoint().locator(),
                ),
            ]
        }

        /// `heimdall <args>`, stdin closed.
        pub fn cli(&self, args: &[&str]) -> Out {
            assert!(
                self.home.root.join("run/instance.json").exists(),
                "the in-process runtime serves"
            );
            cli_env(&self.env(), &self.home.root, args)
        }

        /// The registry's marker lines.
        pub fn marker_lines(&self) -> usize {
            std::fs::read_to_string(&self.registry)
                .unwrap_or_default()
                .lines()
                .filter(|l| l.contains("heimdall:enr_"))
                .count()
        }

        /// The wrapper's step runs so far.
        pub fn step_runs(&self) -> usize {
            std::fs::read_to_string(self.ctl.join("count"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        }

        /// From the `n`-th step run on, the client hangs before its ready line.
        pub fn hang_at(&self, n: usize) {
            std::fs::write(self.ctl.join("hang-at"), n.to_string()).unwrap();
        }

        /// The pending decisions, as `(id, kind)`.
        pub fn pending(&self) -> Vec<(String, String)> {
            self.tx(|tx| tx.pending_decisions())
                .into_iter()
                .map(|d| {
                    let kind = serde_json::to_value(&d.kind).unwrap()["kind"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned();
                    (d.id.to_string(), kind)
                })
                .collect()
        }

        pub fn record(&self, id: &EnrollmentId) -> EnrollmentRecord {
            self.tx(|tx| tx.enrollment(id)).unwrap()
        }

        /// The approved target the sshd serves now.
        pub fn served_target(&self) -> ApprovedTarget {
            let (kt, kb) = host_key_of(&self.sshd.host_key_line);
            ApprovedTarget {
                hostname: "127.0.0.1".to_owned(),
                port: self.sshd.port,
                user: self.account.clone(),
                proxy: NoProxy::None,
                host_key: raw_key(&kt, &kb).approved(),
            }
        }

        /// The served target with another (fixture) host key: the key the record
        /// approved before the host key changed.
        pub fn old_target(&self) -> (ApprovedTarget, String) {
            let old = FixtureKey::generate();
            let line = old.public_line_without_comment();
            let (kt, kb) = host_key_of(&format!("x {line}"));
            (
                ApprovedTarget {
                    host_key: raw_key(&kt, &kb).approved(),
                    ..self.served_target()
                },
                kb,
            )
        }

        /// Register another active CA (its records may live beside the first CA's: one
        /// live record per (pair, CA)).
        pub fn add_ca(&self) -> TestCa {
            let ca = TestCa::generate(self.home.scratch()).unwrap();
            let now = Timestamp::now();
            let (fp, line) = (ca.fingerprint().clone(), ca.public_line().to_owned());
            self.tx(|tx| {
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: line.clone(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "11".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })
            });
            ca
        }

        /// A record seeded in `state` under the first CA.
        pub fn seed(
            &self,
            state: EnrollmentState,
            form: EnrollmentForm,
            target: ApprovedTarget,
            hold: Option<HoldReason>,
            late_write: bool,
        ) -> EnrollmentRecord {
            self.seed_under(&self.ca, state, form, target, hold, late_write)
        }

        /// A record seeded in `state` under `ca`.
        pub fn seed_under(
            &self,
            ca: &TestCa,
            state: EnrollmentState,
            form: EnrollmentForm,
            target: ApprovedTarget,
            hold: Option<HoldReason>,
            late_write: bool,
        ) -> EnrollmentRecord {
            let id = EnrollmentId::from_random_bytes(rand16());
            let marker = marker_for(&id);
            let line = format!(
                "cert-authority,principals=\"hm:{}:{}\" {} {marker}",
                self.destination.as_str(),
                self.account.as_str(),
                ca.public_line()
            );
            let now = Timestamp::now();
            let record = EnrollmentRecord {
                id,
                destination: self.destination.clone(),
                account: self.account.clone(),
                ca_fingerprint: ca.fingerprint().clone(),
                form,
                marker,
                registry: RegistryRef {
                    path_display: self.registry_remote.clone(),
                    resolved_by: RegistryResolvedBy::Explicit,
                },
                registry_canonical: RegistryCanonical {
                    path: Some(self.registry_remote.clone()),
                    resolved_by: RegistryResolvedBy::Explicit,
                },
                line_sha256: heimdall_domain::projection::Sha256Hex::of(line.as_bytes())
                    .as_str()
                    .to_owned(),
                target,
                existing_access: ExistingAccessRecord {
                    identity: self.identity.clone(),
                    endpoint: Some(agent_ref(&self.agent_locator)),
                    public_key_file: None,
                },
                hold: hold.map(|reason| EnrollmentHold {
                    reason,
                    evidence_based: false,
                }),
                removal_origin: None,
                late_write: late_write.then(|| LateWrite {
                    step_token: "ab".repeat(16),
                    not_after_remote: now.as_second() + 3600,
                }),
                state,
                verified_at: (state == EnrollmentState::Verified).then_some(now),
                evidence: None,
                created_at: now,
                updated_at: now,
            };
            self.tx(|tx| tx.seed_enrollment(&record));
            record
        }

        /// ⟨model setup⟩ An `enrollment.apply` left as the third unproven fence leaves it
        /// (D5 §6.7): the record `held` (`lock_holder_unresolved`), the operation running
        /// with the uncertain append (never run: no marker line) in its journal.
        pub fn forge_lock_holder_unresolved(&self) -> (EnrollmentRecord, OperationId) {
            use heimdall_app::enrollment::{ApprovalFact, Journal, StepPurpose, UncertainStep};
            use heimdall_contract::canonical::RequestHash;
            use heimdall_contract::ids::{DecisionId, RequestId};
            use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
            use heimdall_domain::operation::{
                AdapterIdentity, EffectClass, EffectReceipt, OperationKind, OperationRecord,
                RecoveryMetadata, StageReceipt,
            };
            use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
            let record = self.seed(
                EnrollmentState::Held,
                EnrollmentForm::Account,
                self.served_target(),
                Some(HoldReason::LockHolderUnresolved),
                false,
            );
            let id = OperationId::from_random_bytes(rand16());
            let now = Timestamp::now();
            let past = now.as_second() - 3600;
            let journal = Journal {
                enrollment: Some(record.id.clone()),
                approval: Some(ApprovalFact {
                    decision: DecisionId::from_random_bytes(rand16()),
                    at: now,
                }),
                uncertain: Some(UncertainStep {
                    stage: heimdall_contract::enrollment::RemoteStage::Append,
                    token: "cd".repeat(16),
                    not_after_remote: Some(past),
                    purpose: StepPurpose::Append,
                    hard_deadline_ms: 0,
                    hard_deadline_wall: Timestamp::from_second(past).unwrap(),
                    boot_id: "boot-forged".to_owned(),
                }),
                fence_attempts: 3,
                tag: Some(heimdall_app::enrollment::tag_of(&record.id)),
                ..Journal::default()
            };
            use std::os::unix::fs::MetadataExt as _;
            let key = IdempotencyKey {
                caller: CallerContext {
                    principal: PrincipalRef::UnixUser {
                        uid: std::fs::metadata(&self.home.root).unwrap().uid(),
                    },
                    role: ClientRole::Owner,
                },
                kind: OperationKind::EnrollmentApply,
                request_id: RequestId::parse(&format!(
                    "forged_{}",
                    heimdall_testkit::agent::random_hex(8)
                ))
                .unwrap(),
            };
            let environment = self
                .tx(|tx| tx.self_environment())
                .expect("the runtime's environment");
            let op = OperationRecord {
                id: id.clone(),
                kind: OperationKind::EnrollmentApply,
                environment,
                key: key.clone(),
                request_hash: RequestHash(rand16().repeat(2).try_into().unwrap()),
                effect_class: EffectClass::RemoteMutation,
                state: heimdall_contract::OperationState::Running,
                code: None,
                effect_status: heimdall_contract::envelope::EffectStatus::Unknown,
                result: None,
                created_at: now,
                updated_at: now,
                cancellation: None,
                recovery: RecoveryMetadata::default(),
            };
            let receipt = StageReceipt {
                stage: "enroll.journal".into(),
                recorded_at: now,
                effect: EffectReceipt::Confirmed {
                    adapter: AdapterIdentity {
                        mechanism: "enrollment".into(),
                        instance: "journal".into(),
                    },
                    credential_ref: serde_json::to_string(&journal).unwrap(),
                },
                local: None,
            };
            self.tx(|tx| {
                tx.insert_operation(
                    &op,
                    &IdempotencyRecord {
                        key: key.clone(),
                        request_hash: op.request_hash,
                        operation_id: id.clone(),
                        created_at: now,
                        expires_at: None,
                    },
                )?;
                tx.append_stage_receipt(&id, &receipt)
            });
            (record, id)
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            if let Some(s) = self.service.take() {
                s.token.cancel();
                let _ = s.thread.join();
            }
            self.agent.stop();
        }
    }

    /// `(type, base64)` of a known-hosts (or `<x> <type> <b64>`) line.
    pub fn host_key_of(line: &str) -> (String, String) {
        let mut f = line.split_whitespace().skip(1);
        (f.next().unwrap().to_owned(), f.next().unwrap().to_owned())
    }

    pub fn agent_ref(locator: &str) -> EndpointRef {
        EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: locator.to_owned(),
        }
    }
}

// =====================================================================================
// The owner's terminal: a pty whose session leader runs heimdall
// =====================================================================================

/// The typed-`yes` cases (as `cli_m02.rs`'s `terminal`): the test binary re-executes
/// itself in child mode as the session leader of a new session whose controlling
/// terminal is the pty's slave, then execs heimdall, so its stdin is a TTY.
#[cfg(unix)]
mod terminal {
    use std::ffi::{OsStr, OsString};
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::bin;

    const SLAVE: &str = "HM_W5E_PTY_SLAVE";
    const ARGS: &str = "HM_W5E_PTY_ARGS";
    /// ⟨§17.27 item 3⟩ When set, the child's stdout is this file instead of the terminal
    /// (stdin and stderr stay the pty), so a `--json` case reads its envelope apart from
    /// the prompt and the consent text.
    const STDOUT: &str = "HM_W5E_PTY_STDOUT";

    /// Child-mode entry of the pty cases; does nothing in a normal run.
    #[test]
    #[ignore = "child-mode entry of the enroll pty tests, started by them"]
    fn pty_child() {
        let (Some(slave), Some(args)) = (std::env::var_os(SLAVE), std::env::var(ARGS).ok()) else {
            return;
        };
        rustix::process::setsid().unwrap();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave)
            .unwrap();
        rustix::process::ioctl_tiocsctty(&tty).unwrap();
        rustix::stdio::dup2_stdin(&tty).unwrap();
        match std::env::var_os(STDOUT) {
            Some(file) => {
                let out = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(file)
                    .unwrap();
                rustix::stdio::dup2_stdout(&out).unwrap();
            }
            None => rustix::stdio::dup2_stdout(&tty).unwrap(),
        }
        rustix::stdio::dup2_stderr(&tty).unwrap();
        drop(tty);
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        heimdall_testkit::term::default_terminal_signals_for_exec().unwrap();
        let err = Command::new(bin())
            .args(args)
            .env_remove("HEIMDALL_E2E_BIN")
            .env_remove(STDOUT)
            .exec();
        panic!("exec failed: {err}");
    }

    /// A pseudo-terminal holding its slave for its life; its output drained into a
    /// transcript.
    pub struct Pty {
        master: OwnedFd,
        slave_fd: Option<OwnedFd>,
        slave: PathBuf,
        output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.slave_fd = None;
        }
    }

    impl Pty {
        pub fn open() -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let slave = PathBuf::from(OsStr::from_bytes(name.as_bytes()));
            let slave_fd = rustix::fs::open(
                &slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::termios::tcsetwinsize(
                &slave_fd,
                rustix::termios::Winsize {
                    ws_row: 24,
                    ws_col: 200,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                },
            )
            .unwrap();
            let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = master.try_clone().unwrap();
            let sink = std::sync::Arc::clone(&output);
            let done = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(reader);
                let mut buf = [0u8; 4096];
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            Pty {
                master,
                slave_fd: Some(slave_fd),
                slave,
                output,
                stop,
            }
        }

        pub fn write(&self, bytes: &[u8]) {
            use std::io::Write as _;
            let mut f = std::fs::File::from(self.master.try_clone().unwrap());
            f.write_all(bytes).unwrap();
        }

        /// `heimdall <args>` on this terminal with exactly `env`, in `cwd`.
        pub fn start(&self, env: &[(OsString, OsString)], cwd: &Path, args: &[&str]) -> Child {
            self.start_with(env, cwd, args, None)
        }

        /// ⟨§17.27 item 3⟩ [`Pty::start`] with the child's stdout written to `stdout` (a
        /// new file), its stdin and stderr the terminal.
        pub fn start_split(
            &self,
            env: &[(OsString, OsString)],
            cwd: &Path,
            args: &[&str],
            stdout: &Path,
        ) -> Child {
            self.start_with(env, cwd, args, Some(stdout))
        }

        fn start_with(
            &self,
            env: &[(OsString, OsString)],
            cwd: &Path,
            args: &[&str],
            stdout: Option<&Path>,
        ) -> Child {
            let json = serde_json::to_string(&args).unwrap();
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "enroll::terminal::pty_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .current_dir(cwd);
            for (k, v) in env {
                cmd.env(k, v);
            }
            if let Some(file) = stdout {
                cmd.env(STDOUT, file);
            }
            cmd.env(SLAVE, &self.slave)
                .env(ARGS, &json)
                .env("HEIMDALL_E2E_BIN", bin())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        }

        pub fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        /// Wait until the transcript contains `needle` (the child still running).
        pub fn wait_for(&self, needle: &str, child: &mut Child) {
            let deadline = Instant::now() + Duration::from_secs(90);
            while !self.transcript().contains(needle) {
                if child.try_wait().unwrap().is_some() {
                    std::thread::sleep(Duration::from_millis(150));
                    assert!(
                        self.transcript().contains(needle),
                        "the child exited before {needle:?}: {}",
                        self.transcript()
                    );
                    return;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("no {needle:?} on the terminal: {}", self.transcript());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// Wait for the child's exit; its code and the transcript (canary-scanned).
        pub fn finish(&self, child: &mut Child) -> (Option<i32>, String) {
            let deadline = Instant::now() + Duration::from_secs(120);
            let code = loop {
                if let Some(s) = child.try_wait().unwrap() {
                    break s.code();
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the pty child did not exit in time: {}", self.transcript());
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            std::thread::sleep(Duration::from_millis(150));
            let t = self.transcript();
            heimdall_testkit::assert_no_canary(&t);
            assert!(!t.contains("panicked"), "{t}");
            (code, t)
        }
    }

    /// ⟨§17.27 item 3⟩ `heimdall <args>` (a `--json` line) on a fresh pty whose stdout is
    /// a file: at the first `[y/N]` prompt, the terminal so far (what the owner saw before
    /// answering), then `answer` typed; the exit code, the whole terminal transcript, and
    /// stdout alone.
    pub fn answer_split(
        env: &[(OsString, OsString)],
        cwd: &Path,
        args: &[&str],
        answer: &[u8],
    ) -> (Option<i32>, String, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("stdout");
        let pty = Pty::open();
        let mut child = pty.start_split(env, cwd, args, &file);
        pty.wait_for("[y/N]", &mut child);
        let before = pty.transcript();
        pty.write(answer);
        let (code, t) = pty.finish(&mut child);
        let stdout = std::fs::read_to_string(&file).unwrap_or_default();
        heimdall_testkit::assert_no_canary(&stdout);
        (code, before, t, stdout)
    }

    /// `heimdall <args>` on a fresh pty: at the first `[y/N]` prompt, type `answer`
    /// (raw bytes: `yes\n`, `no\n`, `\x04` for end of input, `\x03` for Ctrl-C).
    pub fn answer(
        env: &[(OsString, OsString)],
        cwd: &Path,
        args: &[&str],
        answer: &[u8],
    ) -> (Option<i32>, String) {
        let pty = Pty::open();
        let mut child = pty.start(env, cwd, args);
        pty.wait_for("[y/N]", &mut child);
        pty.write(answer);
        pty.finish(&mut child)
    }
}

// =====================================================================================
// The cases
// =====================================================================================

#[cfg(unix)]
use heimdall_contract::enrollment::{EnrollmentForm, EnrollmentState};
#[cfg(unix)]
use heimdall_domain::enrollment::HoldReason;
#[cfg(unix)]
use world::{ALIAS, DESTINATION, World, host_key_of};

/// The exit status the CLI gives an envelope code (ADR-0006 §6; `ACCEPTED` without
/// `--async` is 5).
#[cfg(unix)]
fn exit_of(v: &serde_json::Value) -> i32 {
    let code: heimdall_contract::Code = serde_json::from_value(v["code"].clone()).unwrap();
    if code == heimdall_contract::Code::Accepted {
        5
    } else {
        code.exit_code() as i32
    }
}

/// stdout and stderr together (human mode prints the preview and prompts on stderr).
#[cfg(unix)]
fn both(out: &Out) -> String {
    format!("{}\n{}", out.stdout, out.stderr)
}

/// The pending decisions of `kind`.
#[cfg(unix)]
fn pending_of(w: &World, kind: &str) -> Vec<String> {
    w.pending()
        .into_iter()
        .filter(|(_, k)| k == kind)
        .map(|(id, _)| id)
        .collect()
}

/// The operation an exit transcript names (`operation op_…`).
#[cfg(unix)]
fn operation_in(text: &str) -> String {
    let i = text.find("op_").expect("an operation ID");
    text[i..i + 35].to_owned()
}

/// m03-plan U12 (ADR-0008 D5 §6.1): `enroll <destination>` shows the preview in full
/// before anything is applied: the exact line to be written, every disclosure (with the
/// `slot_free` command), the approved target, the existing-access invocation and the
/// bootstrap; then `Apply` waits on the `EnrollAccount` decision, which
/// `--non-interactive` never gives (exit 3, `next.decision_ref`, nothing written).
/// `--json` prints one envelope carrying the plan and the recorded decision request.
#[cfg(unix)]
#[test]
fn enroll_preview_shows_disclosures_and_exact_line() {
    let w = World::new();
    let reg = w.registry_remote.clone();
    let out = w.cli(&[
        "--non-interactive",
        "enroll",
        ALIAS,
        "--registry-path",
        &reg,
    ]);
    assert_eq!(out.code, 3, "{out:?}");
    let text = both(&out);
    let prefix = format!(
        "cert-authority,principals=\"hm:{DESTINATION}:{}\" {} heimdall:enr_",
        w.account,
        w.ca.public_line()
    );
    assert!(text.contains("exact line to be written:"), "{text}");
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("the exact line {prefix}…: {text}"));
    assert_eq!(line.len(), prefix.len() + 32, "{line}");
    for kind in [
        "config_commands_run_as_ordinary_use",
        "ca_trust_blast_radius",
        "remove_window",
        "lock_continuity_once",
        "reconcile_may_stop_own_stale_script",
        "ordinary_ssh_needs_held_slot",
    ] {
        assert!(text.contains(&format!("* {kind}: ")), "{kind}: {text}");
    }
    assert!(
        text.contains("`heimdall run --profile <profile> -- ssh hm-e2e` holds one"),
        "the slot_free command: {text}"
    );
    assert!(
        text.contains(&format!("registry: {reg} (explicit)")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "approved target: 127.0.0.1:{} user {}, no proxy, host key",
            w.sshd.port, w.account
        )),
        "{text}"
    );
    assert!(
        text.contains("every remote step runs: ssh -o IdentityAgent="),
        "{text}"
    );
    assert!(
        text.contains("bootstrap: if the registry's directory is absent"),
        "{text}"
    );
    assert_eq!(w.marker_lines(), 0, "nothing was written");
    let pending = pending_of(&w, "enroll_account");
    assert_eq!(pending.len(), 1, "{:?}", w.pending());
    assert!(
        out.stderr.contains(&format!("decision_ref={}", pending[0])),
        "{out:?}"
    );
    w.deny_pending();

    let out = w.cli(&[
        "--json",
        "--non-interactive",
        "enroll",
        ALIAS,
        "--registry-path",
        &reg,
    ]);
    assert_eq!(out.code, 3, "{out:?}");
    let v = one_envelope(&out);
    assert_eq!(v["code"], "INTERACTION_REQUIRED", "{v}");
    let decision = v["next"]["decision_ref"].as_str().unwrap();
    assert_eq!(pending_of(&w, "enroll_account"), vec![decision.to_owned()]);
    let plan = &v["data"]["plan"];
    assert!(plan["line"].as_str().unwrap().starts_with(&prefix), "{v}");
    assert_eq!(plan["disclosures"].as_array().unwrap().len(), 6, "{v}");
    assert_eq!(
        v["data"]["decision_request"]["kind"], "enroll_account",
        "{v}"
    );
    assert_eq!(
        v["data"]["decision_request"]["plan_digest"], plan["plan_digest"],
        "{v}"
    );
    assert_eq!(w.marker_lines(), 0);
}

/// m03-plan U12 ⟨r2⟩ (ADR-0008 D5 §6.9): `--form system` shows the lines the owner
/// installs (the CA line, the principals line, the `sshd_config` directives) and never
/// an "exact line to be written"; `enroll remove` of a system-form enrollment needs a
/// typed confirmation (none without a terminal), changes nothing remote, shows the lines
/// to delete and says it is NOT removed; the absence check that cannot conclude leaves it
/// not removed. The CLI never claims "removed" without a passing absence check.
#[cfg(unix)]
#[test]
fn enroll_system_form_cli_shows_lines_and_never_claims_removed() {
    let w = World::new();
    let principal = format!("hm:{DESTINATION}:{}", w.account);
    let out = w.cli(&["--non-interactive", "enroll", ALIAS, "--form", "system"]);
    assert_eq!(out.code, 3, "{out:?}");
    let text = both(&out);
    assert!(
        text.contains(&format!(
            "TrustedUserCAKeys file line: {}",
            w.ca.public_line()
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "AuthorizedPrincipalsFile line for {}: {principal}",
            w.account
        )),
        "{text}"
    );
    assert!(text.contains("sshd_config: TrustedUserCAKeys"), "{text}");
    assert!(
        text.contains("sshd_config: AuthorizedPrincipalsFile"),
        "{text}"
    );
    assert!(
        text.contains("Heimdall writes nothing on the destination"),
        "{text}"
    );
    assert!(!text.contains("exact line to be written"), "{text}");
    assert_eq!(
        pending_of(&w, "enroll_system_form").len(),
        1,
        "{:?}",
        w.pending()
    );
    w.deny_pending();

    // The manual removal of a verified system-form enrollment.
    let r = w.seed(
        EnrollmentState::Verified,
        EnrollmentForm::System,
        w.served_target(),
        None,
        false,
    );
    let id = r.id.to_string();
    for flags in [&["--non-interactive"][..], &[]] {
        let mut argv = flags.to_vec();
        argv.extend(["enroll", "remove", id.as_str()]);
        let out = w.cli(&argv);
        assert_eq!(out.code, 3, "{argv:?}: {out:?}");
        assert!(out.stderr.contains("not confirmed"), "{out:?}");
        assert_eq!(
            w.record(&r.id).state,
            EnrollmentState::Verified,
            "nothing was sent"
        );
    }
    let (code, t) = terminal::answer(&w.env(), &w.home.root, &["enroll", "remove", &id], b"yes\n");
    assert_eq!(code, Some(0), "{t}");
    assert_eq!(w.record(&r.id).state, EnrollmentState::ManualRemovalPending);
    assert!(
        t.contains("Heimdall changes nothing on the destination"),
        "{t}"
    );
    assert!(
        t.contains(&format!(
            "enrollment {id}: manual_removal_pending: NOT removed"
        )),
        "{t}"
    );
    assert!(
        t.contains(&format!(
            "delete the TrustedUserCAKeys line: {}",
            w.ca.public_line()
        )),
        "{t}"
    );
    assert!(t.contains(&principal), "{t}");
    assert!(
        t.contains(&format!("heimdall enroll verify {id} --absence")),
        "{t}"
    );
    assert!(!t.contains("absence verified"), "{t}");

    // The absence check cannot conclude here (no verification endpoint): not removed.
    for json in [true, false] {
        let mut argv = vec!["--non-interactive"];
        if json {
            argv.insert(0, "--json");
        }
        argv.extend(["enroll", "verify", id.as_str(), "--absence"]);
        let out = w.cli(&argv);
        assert_ne!(out.code, 0, "{out:?}");
        assert!(!both(&out).contains("absence verified"), "{out:?}");
        if json {
            let v = one_envelope(&out);
            assert_ne!(v["data"]["state"], "removed", "{v}");
            assert_eq!(out.code, exit_of(&v), "{v}");
        }
        assert_eq!(w.record(&r.id).state, EnrollmentState::ManualRemovalPending);
    }
}

/// m03-plan U12 ⟨r3⟩ (ADR-0008 D5 §6.2 `held` row, §6.5 item 3, §17.7 item 5): on a
/// record held for a host-key change, `enroll verify --approve-target-change` shows the
/// new key as a diff against the approved one and needs the `ApproveTargetChange`
/// decision: without a terminal, or answered "no", nothing is sent (the decision stays
/// pending, the approved target unchanged). Answered "yes", the decision is approved and
/// the target-change verification runs; it cannot pass here, so the approved key stays.
#[cfg(unix)]
#[test]
fn enroll_verify_approve_target_change_shows_key_diff_and_needs_decision() {
    let w = World::new();
    let (old, old_b64) = w.old_target();
    let (_, new_b64) = host_key_of(&w.sshd.host_key_line);
    let r = w.seed(
        EnrollmentState::Held,
        EnrollmentForm::Account,
        old.clone(),
        Some(HoldReason::HostKeyChanged),
        false,
    );
    let id = r.id.to_string();
    let out = w.cli(&[
        "--non-interactive",
        "enroll",
        "verify",
        &id,
        "--approve-target-change",
    ]);
    assert_eq!(out.code, 3, "{out:?}");
    let text = both(&out);
    assert!(
        text.contains(&format!("- ssh-ed25519 {old_b64} ")),
        "{text}"
    );
    assert!(text.contains("(approved)"), "{text}");
    assert!(text.contains(&format!(" {new_b64} ")), "{text}");
    assert!(text.contains("(now presented)"), "{text}");
    assert_eq!(pending_of(&w, "approve_target_change").len(), 1);
    assert_eq!(
        w.record(&r.id).target,
        old,
        "the approved target is unchanged"
    );
    w.deny_pending();

    let out = w.cli(&[
        "--json",
        "--non-interactive",
        "enroll",
        "verify",
        &id,
        "--approve-target-change",
    ]);
    assert_eq!(out.code, 3, "{out:?}");
    let v = one_envelope(&out);
    assert_eq!(
        v["data"]["decision_request"]["kind"], "approve_target_change",
        "{v}"
    );
    assert_eq!(
        v["data"]["decision_request"]["approved"]["host_key"]["key"],
        old_b64.as_str()
    );
    assert_eq!(
        v["data"]["decision_request"]["proposed"]["host_key"]["key"],
        new_b64.as_str()
    );
    w.deny_pending();

    let (code, t) = terminal::answer(
        &w.env(),
        &w.home.root,
        &["enroll", "verify", &id, "--approve-target-change"],
        b"no\n",
    );
    assert_eq!(code, Some(3), "{t}");
    let prompt_at = t.find("[y/N]").unwrap();
    let diff_at = t
        .find(&format!("- ssh-ed25519 {old_b64}"))
        .expect("the diff");
    assert!(
        diff_at < prompt_at,
        "the diff is shown before the prompt: {t}"
    );
    assert!(t.contains("not confirmed (answered no)"), "{t}");
    assert_eq!(
        pending_of(&w, "approve_target_change").len(),
        1,
        "nothing was sent"
    );
    w.deny_pending();

    let (code, t) = terminal::answer(
        &w.env(),
        &w.home.root,
        &["enroll", "verify", &id, "--approve-target-change"],
        b"yes\n",
    );
    assert!(code.is_some(), "{t}");
    assert!(
        pending_of(&w, "approve_target_change").is_empty(),
        "the decision was sent: {t}"
    );
    let after = w.record(&r.id);
    assert_eq!(after.target, old, "replaced only on a pass: {t}");
    assert_eq!(after.state, EnrollmentState::Held, "{t}");
}

/// m03-plan U12 ⟨r3⟩ (ADR-0008 D5 §6.7): after `lock_holder_unresolved`, `enroll
/// reconcile <op> --after-manual-recovery` re-inspects and classifies through the real
/// step runner, and never redispatches: exactly one step (an inspect) runs, no line is
/// written, and no marker line means `withdrawn` with the `late_write` residual. The
/// held state is model setup (the third unproven fence's outcome; the fence itself is
/// `e2e_enroll_m03`'s `fence_unproven_never_unlocks_and_counts_attempt`).
#[cfg(unix)]
#[test]
fn enroll_reconcile_after_manual_recovery_never_redispatches() {
    let w = World::new();
    let (r, op) = w.forge_lock_holder_unresolved();
    let opid = op.to_string();
    let out = w.cli(&[
        "--json",
        "--non-interactive",
        "enroll",
        "reconcile",
        &opid,
        "--after-manual-recovery",
    ]);
    let v = one_envelope(&out);
    assert_eq!(out.code, exit_of(&v), "{out:?}");
    assert!(out.stderr.contains("step inspect"), "{out:?}");
    for stage in ["append", "bootstrap", "remove", "fence"] {
        assert!(
            !out.stderr.contains(&format!("step {stage}")),
            "{stage}: {out:?}"
        );
    }
    assert_eq!(w.step_runs(), 1, "one inspect, nothing else: {out:?}");
    assert_eq!(w.marker_lines(), 0, "never a redispatch");
    let after = w.record(&r.id);
    assert_eq!(after.state, EnrollmentState::Withdrawn, "{out:?}");
    assert!(
        after.late_write.is_some(),
        "the late_write residual: {out:?}"
    );
    assert_eq!(v["data"]["state"], "withdrawn", "{v}");
    assert!(
        v["data"]["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["kind"] == "possible_late_write"),
        "{v}"
    );
}

/// m03-plan U12 (ADR-0006 §3.1; R3): every enroll decision kind (`enroll_account`,
/// `enroll_system_form`, `remove_enrollment`, `approve_target_change`) needs the typed
/// `yes`: a non-TTY stdin, `--non-interactive`, "no", end of input and Ctrl-C at the
/// prompt each send nothing (exit 3, the decision still pending). (The 120 s prompt
/// timeout is `prompt::ask`'s, not exercised here.)
#[cfg(unix)]
#[test]
fn enroll_decision_kinds_need_typed_yes() {
    let w = World::new();
    let reg = w.registry_remote.clone();
    let ca1 = w.ca.fingerprint().to_string();
    let (ca2, ca3) = (w.add_ca(), w.add_ca());
    let verified = w.seed_under(
        &ca2,
        EnrollmentState::Verified,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        false,
    );
    let (old, _) = w.old_target();
    let held = w.seed_under(
        &ca3,
        EnrollmentState::Held,
        EnrollmentForm::Account,
        old,
        Some(HoldReason::HostKeyChanged),
        false,
    );
    let (v_id, h_id) = (verified.id.to_string(), held.id.to_string());
    let kinds: Vec<(&str, Vec<&str>)> = vec![
        (
            "enroll_account",
            vec!["enroll", ALIAS, "--registry-path", &reg, "--ca", &ca1],
        ),
        (
            "enroll_system_form",
            vec!["enroll", ALIAS, "--form", "system", "--ca", &ca1],
        ),
        ("remove_enrollment", vec!["enroll", "remove", &v_id]),
        (
            "approve_target_change",
            vec!["enroll", "verify", &h_id, "--approve-target-change"],
        ),
    ];
    for (kind, argv) in &kinds {
        // No terminal: stdin closed, with and without --non-interactive.
        for flags in [&["--non-interactive"][..], &[]] {
            let mut a = flags.to_vec();
            a.extend(argv.iter().copied());
            let out = w.cli(&a);
            assert_eq!(out.code, 3, "{kind} {a:?}: {out:?}");
            assert_eq!(
                pending_of(&w, kind).len(),
                1,
                "{kind} {a:?}: nothing was sent"
            );
            w.deny_pending();
        }
        // The terminal: "no", end of input, Ctrl-C.
        for (answer, why) in [
            (&b"no\n"[..], "answered no"),
            (b"\x04", "end of input"),
            (b"\x03", "interrupted"),
        ] {
            let (code, t) = terminal::answer(&w.env(), &w.home.root, argv, answer);
            assert_eq!(code, Some(3), "{kind} {why}: {t}");
            assert!(
                t.contains(&format!("not confirmed ({why})")),
                "{kind} {why}: {t}"
            );
            assert!(
                t.contains(&format!("kind: {kind}")),
                "{kind}: the recorded decision: {t}"
            );
            assert_eq!(
                pending_of(&w, kind).len(),
                1,
                "{kind} {why}: nothing was sent"
            );
            w.deny_pending();
        }
    }
    // An abandonment's typed confirmation (no decision record).
    let out = w.cli(&["--non-interactive", "enroll", "abandon", &h_id]);
    assert_eq!(out.code, 3, "{out:?}");
    assert_eq!(w.record(&held.id).state, EnrollmentState::Held);
    let (code, t) = terminal::answer(
        &w.env(),
        &w.home.root,
        &["enroll", "abandon", &h_id],
        b"no\n",
    );
    assert_eq!(code, Some(3), "{t}");
    assert_eq!(w.record(&held.id).state, EnrollmentState::Held);
    let (code, t) = terminal::answer(
        &w.env(),
        &w.home.root,
        &["enroll", "abandon", &h_id],
        b"yes\n",
    );
    assert_eq!(code, Some(0), "{t}");
    assert_eq!(w.record(&held.id).state, EnrollmentState::Abandoned, "{t}");
}

/// m03-plan U12 (R3): a Ctrl-C between `Step` and `StepResult` aborts the running step
/// (its process group is killed), sends no result for it, and prints exactly "the change
/// may have been applied; run `heimdall enroll reconcile <op>`" with the real operation
/// (exit 7). The enrollment is approved with a typed `yes` first; its inspect runs for
/// real against the loopback sshd; the next step hangs before its ready line.
#[cfg(unix)]
#[test]
fn enroll_ctrl_c_between_step_and_result_prints_uncertain_message() {
    let w = World::new();
    let reg = w.registry_remote.clone();
    w.hang_at(2);
    let pty = terminal::Pty::open();
    let mut child = pty.start(
        &w.env(),
        &w.home.root,
        &["enroll", ALIAS, "--registry-path", &reg],
    );
    pty.wait_for("[y/N]", &mut child);
    pty.write(b"yes\n");
    pty.wait_for("step inspect: ", &mut child);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !w.ctl.join("hang-pid").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the second step never started: {}",
            pty.transcript()
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    pty.write(b"\x03");
    let (code, t) = pty.finish(&mut child);
    assert_eq!(code, Some(7), "{t}");
    let op = operation_in(&t[t.find("): running").unwrap() - 60..]);
    let expected =
        format!("the change may have been applied; run `heimdall enroll reconcile {op}`");
    assert!(t.contains(&expected), "{expected}: {t}");
    assert_eq!(w.step_runs(), 2, "{t}");
    assert_eq!(w.marker_lines(), 0, "the aborted step never ran its script");
    // No result was sent for the aborted step: the record is still `applying`.
    let records = w.tx(|tx| tx.open_enrollments());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, EnrollmentState::Applying, "{t}");
    // The hanging client is gone with its process group.
    let pid = std::fs::read_to_string(w.ctl.join("hang-pid")).unwrap();
    let ps = std::process::Command::new("/bin/ps")
        .args(["-o", "pid=", "-p", pid.trim()])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&ps.stdout).trim().is_empty(),
        "pid {pid} survived: {t}"
    );
}

/// m03-plan U12 ⟨r3⟩ (§17.4 item 12; ADR-0008 D5 §6.2, §6.7): `enroll status` lists every
/// record's state and marker, a verified one's `slot_free` command, the `late_write`
/// residual and a held record's next step; read-only (it never starts a runtime).
/// ⟨§17.25 item 4⟩ The held record's reason and next commands are the runtime's
/// `hold` (`inspect enrollments`), in both forms.
#[cfg(unix)]
#[test]
fn enroll_status_shows_slot_free_late_write_and_held_next_step() {
    let w = World::new();
    let verified = w.seed(
        EnrollmentState::Verified,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        false,
    );
    let (old, _) = w.old_target();
    let ca2 = w.add_ca();
    let held = w.seed_under(
        &ca2,
        EnrollmentState::Held,
        EnrollmentForm::Account,
        old,
        Some(HoldReason::HostKeyChanged),
        false,
    );
    let late = w.seed(
        EnrollmentState::Withdrawn,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        true,
    );
    let out = w.cli(&["enroll", "status"]);
    assert_eq!(out.code, 0, "{out:?}");
    let text = &out.stdout;
    for r in [&verified, &held, &late] {
        assert!(
            text.contains(&format!("{} {}", r.id, r.state.as_str())),
            "{text}"
        );
        assert!(text.contains(&r.marker), "{text}");
    }
    assert!(
        text.contains("slot_free: ordinary `ssh hm-e2e` works only while a binding holds this alias's managed slot; `heimdall run --profile <profile> -- ssh hm-e2e` holds one"),
        "{text}"
    );
    assert!(text.contains("possible_late_write"), "{text}");
    assert!(text.contains("held: reason host_key_changed"), "{text}");
    assert!(!text.contains("not reported by this runtime"), "{text}");
    assert!(
        text.contains(&format!(
            "  next step:\n    heimdall enroll verify {id} --approve-target-change\n    heimdall enroll remove {id}\n",
            id = held.id
        )),
        "{text}"
    );
    // The fallback's extra lines are gone: exactly the runtime's two commands.
    assert!(
        !text.contains(&format!("heimdall enroll abandon {}", held.id)),
        "{text}"
    );

    let out = w.cli(&["--json", "enroll", "status"]);
    assert_eq!(out.code, 0, "{out:?}");
    let v = one_envelope(&out);
    assert_eq!(v["data"]["enrollments"].as_array().unwrap().len(), 3, "{v}");
    let guidance = v["data"]["guidance"].as_array().unwrap();
    let of = |id: &str| {
        guidance
            .iter()
            .find(|g| g["enrollment_id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        of(verified.id.as_str())["slot_free_command"],
        "heimdall run --profile <profile> -- ssh hm-e2e"
    );
    // ⟨§17.25 item 4⟩ The runtime's `hold`: the reason and the app's next commands,
    // which the guidance repeats (no fallback).
    let held_view = v["data"]["enrollments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["enrollment_id"] == held.id.as_str())
        .unwrap();
    let expected_next = serde_json::json!([
        format!("heimdall enroll verify {} --approve-target-change", held.id),
        format!("heimdall enroll remove {}", held.id),
    ]);
    assert_eq!(held_view["hold"]["reason"], "host_key_changed", "{v}");
    assert_eq!(held_view["hold"]["next"], expected_next, "{v}");
    assert_eq!(of(held.id.as_str())["next_commands"], expected_next, "{v}");
    for e in v["data"]["enrollments"].as_array().unwrap() {
        if e["enrollment_id"] != held.id.as_str() {
            assert!(
                e.get("hold").is_none(),
                "only a held record has a hold: {e}"
            );
        }
    }
    let late_view = v["data"]["enrollments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["enrollment_id"] == late.id.as_str())
        .unwrap();
    assert_eq!(late_view["possible_late_write"], true, "{v}");
}

/// m03-plan U12 (ADR-0006 §2): `--json` prints exactly one envelope for every enroll
/// command, and the exit status is its code's class.
#[cfg(unix)]
#[test]
fn enroll_commands_print_one_json_envelope() {
    let w = World::new();
    let reg = w.registry_remote.clone();
    let check = |line: &[&str], code: &str| {
        let mut argv = vec!["--json", "--non-interactive"];
        argv.extend(line.iter().copied());
        let out = w.cli(&argv);
        let v = one_envelope(&out);
        assert_eq!(v["code"], code, "{line:?}: {v}");
        assert_eq!(out.code, exit_of(&v), "{line:?}: {v}");
        assert!(
            !out.stdout.contains("is not available in this build"),
            "{line:?}: {v}"
        );
        w.deny_pending();
    };
    check(&["enroll", "status"], "OK");
    check(
        &["enroll", ALIAS, "--registry-path", &reg],
        "INTERACTION_REQUIRED",
    );
    check(
        &["enroll", ALIAS, "--form", "system"],
        "INTERACTION_REQUIRED",
    );
    let verified = w.seed(
        EnrollmentState::Verified,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        false,
    );
    let id = verified.id.to_string();
    let unknown_op = "op_00112233445566778899aabbccddeeff";
    // A verification cannot conclude in this world (no verification endpoint).
    check(&["enroll", "verify", &id], "CAPABILITY_UNAVAILABLE");
    check(&["enroll", "verify", &id, "--absence"], "CONFIG_CONFLICT");
    // The served key is the approved one: no target change to approve.
    check(
        &["enroll", "verify", &id, "--approve-target-change"],
        "CAPABILITY_UNAVAILABLE",
    );
    check(&["enroll", "remove", &id], "INTERACTION_REQUIRED");
    check(&["enroll", "reconcile", unknown_op], "NOT_FOUND");
    check(
        &["enroll", "reconcile", unknown_op, "--after-manual-recovery"],
        "NOT_FOUND",
    );
    check(&["enroll", "abandon", &id], "INTERACTION_REQUIRED");
    check(&["enroll", "verify", "not-an-id"], "USAGE_ERROR");
    check(&["enroll", "status"], "OK");
}

/// ADR-0008 §17.25 item 3 (Q-E1 (b); D13 item 3): in a debug build the **runtime**
/// inserts the test form's pause points into the scripts it builds, from its own test
/// configuration (`ManagedOptions::script_pause_dir`); the CLI only validates
/// `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` and runs the script it receives. Through the testkit
/// pause protocol: the CLI drives a real enrollment (typed `yes`) against the loopback
/// sshd, the append's script stops at `before_write` with nothing written, and only the
/// release lets it write the line.
#[cfg(unix)]
#[test]
fn enroll_step_pauses_at_the_runtime_inserted_pause_point() {
    use heimdall_testkit::registry::hook;
    let (w, hooks) = World::with_pause();
    hooks.arm(hook::BEFORE_WRITE).unwrap();
    let reg = w.registry_remote.clone();
    let mut env = w.env();
    let (k, v) = hooks.env();
    env.push((k.into(), v));
    let pty = terminal::Pty::open();
    let mut child = pty.start(
        &env,
        &w.home.root,
        &["enroll", ALIAS, "--registry-path", &reg],
    );
    pty.wait_for("[y/N]", &mut child);
    pty.write(b"yes\n");
    let reached = hooks
        .wait_at_for(hook::BEFORE_WRITE, std::time::Duration::from_secs(90))
        .unwrap_or_else(|e| panic!("no pause at before_write ({e}): {}", pty.transcript()));
    assert!(
        reached.pid.is_some(),
        "the script reported its PID: {reached:?}"
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "the CLI waits on the paused step"
    );
    // Held at the point: the append has not written (and stays so while held).
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(w.marker_lines(), 0, "{}", pty.transcript());
    // A later reach (a rollback's remove) is no pause.
    hooks.disarm(hook::BEFORE_WRITE).unwrap();
    hooks.release(hook::BEFORE_WRITE).unwrap();
    let (code, t) = pty.finish(&mut child);
    assert!(t.contains("step append: "), "{t}");
    assert!(
        !t.contains("HEIMDALL_TEST_SCRIPT_PAUSE_DIR"),
        "the CLI no longer refuses the variable: {t}"
    );
    assert_eq!(w.marker_lines(), 1, "released, the append wrote: {t}");
    assert_ne!(code, Some(2), "{t}");
}

// =====================================================================================
// ⟨ADR-0008 §17.27 items 3 and 4⟩ consent text in every output mode; the runtime's
// conditional lock text (W5-S02, W5-R05/S03)
// =====================================================================================

/// The shared words of `kind` for this world's alias (`heimdall_issuer::ceremony::
/// disclosure_text`, §17.25 item 10), never retyped here.
#[cfg(unix)]
fn shared_text(kind: heimdall_contract::enrollment::DisclosureKind) -> String {
    heimdall_issuer::ceremony::disclosure_text(
        kind,
        &heimdall_issuer::ceremony::DisclosureContext {
            alias: Some(ALIAS),
            lock: None,
        },
    )
}

/// The general lock sentence (`DisclosureContext { lock: None }`): never what an
/// approval prompt shows for `lock_continuity_once`.
#[cfg(unix)]
fn general_lock_sentence() -> String {
    shared_text(heimdall_contract::enrollment::DisclosureKind::LockContinuityOnce)
}

/// Every enrollment disclosure but the lock one, in words.
#[cfg(unix)]
fn non_lock_disclosures() -> Vec<String> {
    use heimdall_contract::enrollment::DisclosureKind as K;
    [
        K::ConfigCommandsRunAsOrdinaryUse,
        K::CaTrustBlastRadius,
        K::RemoveWindow,
        K::ReconcileMayStopOwnStaleScript,
        K::OrdinarySshNeedsHeldSlot,
    ]
    .into_iter()
    .map(shared_text)
    .collect()
}

/// stdout of a `--json` pty case: exactly one envelope (its value).
#[cfg(unix)]
fn one_envelope_of(stdout: &str) -> serde_json::Value {
    one_envelope(&Out {
        code: 0,
        stdout: stdout.to_owned(),
        stderr: String::new(),
    })
}

/// m03-plan U12 ⟨ADR-0008 §17.27 item 3; W5-S02, the security reviewer's probe⟩ `--json
/// enroll` on a terminal shows the complete human preview and every disclosure's prose
/// on the terminal (stderr) **before** the typed-`yes` prompt: the exact line, each
/// shared disclosure text and the runtime's conditional lock text (never the general
/// sentence). stdout holds exactly one envelope, nothing else; answered "no", nothing
/// was sent (exit 3, the decision pending, no line written).
#[cfg(unix)]
#[test]
fn json_enroll_on_a_terminal_shows_disclosure_prose_before_the_prompt() {
    let w = World::new();
    let reg = w.registry_remote.clone();
    w.save_policy(
        "pol-d3",
        1,
        heimdall_contract::managed::LockBehavior::Continue,
        std::time::Duration::from_secs(2 * 3600),
        None,
    );
    let lock = w.lock_text();
    assert!(
        lock.contains("under your saved policy \"pol-d3\""),
        "{lock}"
    );
    let (code, before, t, stdout) = terminal::answer_split(
        &w.env(),
        &w.home.root,
        &["--json", "enroll", ALIAS, "--registry-path", &reg],
        b"no\n",
    );
    assert_eq!(code, Some(3), "{t}");
    let prefix = format!(
        "cert-authority,principals=\"hm:{DESTINATION}:{}\" {} heimdall:enr_",
        w.account,
        w.ca.public_line()
    );
    assert!(before.contains("exact line to be written:"), "{before}");
    assert!(before.contains(&prefix), "{before}");
    for text in non_lock_disclosures() {
        assert!(before.contains(&text), "{text}: {before}");
    }
    assert!(
        before.contains(&format!("lock_continuity_once: {lock}")),
        "the runtime's lock text before the prompt: {before}"
    );
    assert!(!t.contains(&general_lock_sentence()), "{t}");
    let v = one_envelope_of(&stdout);
    assert_eq!(v["code"], "INTERACTION_REQUIRED", "{v}");
    assert!(
        v["data"]["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("not confirmed (answered no)"),
        "{v}"
    );
    assert!(!stdout.contains("[y/N]"), "no prompt on stdout: {stdout}");
    assert_eq!(
        pending_of(&w, "enroll_account").len(),
        1,
        "nothing was sent"
    );
    assert_eq!(w.marker_lines(), 0);
    assert_eq!(w.lock_ack(), None, "nothing acknowledged");
}

/// m03-plan U12 ⟨ADR-0008 §17.27 item 4; W5-R05/S03, enrollment half⟩ The enrollment
/// confirmation shows the runtime's conditional lock text with the saved limits:
/// * a **continuing** configuration (policy `pol-d3`, at most 2 h, a cutoff): the text
///   names the window, the policy and the cutoff;
/// * a **revoke-on-lock** configuration (the same policy revised to `revoke_on_lock`,
///   beside a continuing `pol-d3-long` of 12 h): the text says `pol-d3`'s work ends at a
///   lock and names `pol-d3-long`'s window.
///
/// Each is exactly `inspect capabilities` `lock.disclosure`, shown before the prompt,
/// never the general sentence. Answered "no", the once-only acknowledgement stays
/// unrecorded; answered "yes" on the shown text, it is recorded.
#[cfg(unix)]
#[test]
fn enroll_consent_shows_the_runtimes_lock_text_with_saved_limits() {
    use heimdall_contract::managed::LockBehavior;
    let w = World::new();
    let reg = w.registry_remote.clone();
    let argv = ["enroll", ALIAS, "--registry-path", reg.as_str()];
    use heimdall_contract::Timestamp;
    let cutoff = Timestamp::from_second(Timestamp::now().as_second() + 30 * 86_400).unwrap();
    let hours = |h: u64| std::time::Duration::from_secs(h * 3600);

    // A continuing configuration with saved limits.
    w.save_policy("pol-d3", 1, LockBehavior::Continue, hours(2), Some(cutoff));
    let lock = w.lock_text();
    for limit in [
        "at most 2h after approval, under your saved policy \"pol-d3\"".to_owned(),
        format!("(no new work after {cutoff})"),
    ] {
        assert!(lock.contains(&limit), "{limit}: {lock}");
    }
    let (code, t) = terminal::answer(&w.env(), &w.home.root, &argv, b"no\n");
    assert_eq!(code, Some(3), "{t}");
    let prompt_at = t.find("[y/N]").unwrap();
    let lock_at = t.find(&lock).unwrap_or_else(|| panic!("{lock}: {t}"));
    assert!(lock_at < prompt_at, "shown before the prompt: {t}");
    assert!(!t.contains(&general_lock_sentence()), "{t}");
    assert_eq!(w.lock_ack(), None, "answered no: not acknowledged");
    w.deny_pending();

    // A revoke-on-lock configuration with saved limits.
    w.save_policy("pol-d3", 2, LockBehavior::RevokeOnLock, hours(2), None);
    w.save_policy("pol-d3-long", 1, LockBehavior::Continue, hours(12), None);
    let lock = w.lock_text();
    for limit in [
        "Work under your saved policy \"pol-d3\" ends when you lock the screen (revoke on lock).",
        "at most 12h after approval, under your saved policy \"pol-d3-long\"",
    ] {
        assert!(lock.contains(limit), "{limit}: {lock}");
    }
    let pty = terminal::Pty::open();
    let mut child = pty.start(&w.env(), &w.home.root, &argv);
    pty.wait_for("[y/N]", &mut child);
    let before = pty.transcript();
    assert!(
        before.contains(&format!("lock_continuity_once: {lock}")),
        "{before}"
    );
    assert!(!before.contains(&general_lock_sentence()), "{before}");
    assert_eq!(w.lock_ack(), None);
    pty.write(b"yes\n");
    let (code, t) = pty.finish(&mut child);
    assert!(code.is_some(), "{t}");
    assert!(
        pending_of(&w, "enroll_account").is_empty(),
        "approved on the shown text: {t}"
    );
    assert!(
        w.lock_ack().is_some(),
        "the once-only acknowledgement is recorded for the decision that showed it: {t}"
    );
}

/// m03-plan U12 ⟨ADR-0008 §17.27 item 3; W5-S02⟩ A removal path: `--json enroll remove`
/// on a terminal shows the removal's consent text (what is removed, the pinned remote
/// invocation, the affected grants) on the terminal before the prompt; stdout holds
/// exactly one envelope; answered "no", nothing was sent (exit 3, the record unchanged).
#[cfg(unix)]
#[test]
fn json_remove_on_a_terminal_shows_the_removal_consent_before_the_prompt() {
    let w = World::new();
    let r = w.seed(
        EnrollmentState::Verified,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        false,
    );
    let id = r.id.to_string();
    let (code, before, t, stdout) = terminal::answer_split(
        &w.env(),
        &w.home.root,
        &["--json", "enroll", "remove", &id],
        b"no\n",
    );
    assert_eq!(code, Some(3), "{t}");
    for needle in [
        format!("You are deciding the removal of enrollment {id}."),
        "Every remote step runs: ssh ".to_owned(),
        "Live grants under this CA for the pair, degraded on approval: none".to_owned(),
        "kind: remove_enrollment".to_owned(),
    ] {
        assert!(before.contains(&needle), "{needle}: {before}");
    }
    let v = one_envelope_of(&stdout);
    assert_eq!(v["code"], "INTERACTION_REQUIRED", "{v}");
    assert_eq!(
        pending_of(&w, "remove_enrollment").len(),
        1,
        "nothing was sent"
    );
    assert_eq!(w.record(&r.id).state, EnrollmentState::Verified);
}

/// m03-plan U12 ⟨ADR-0008 §17.27 items 3 and 4; W5-S02, generic decision completion⟩
/// `heimdall --json decision approve` of a pending `EnrollAccount` decision (made by a
/// `--non-interactive enroll`) shows the recorded enrollment in human form and every
/// disclosure's prose, the runtime's conditional lock text included, on the terminal
/// before the prompt; stdout holds exactly one envelope; answered "no", the decision
/// stays pending and nothing is acknowledged.
#[cfg(unix)]
#[test]
fn json_decision_approve_of_an_enrollment_shows_its_disclosures_before_the_prompt() {
    let w = World::new();
    let reg = w.registry_remote.clone();
    let out = w.cli(&[
        "--json",
        "--non-interactive",
        "enroll",
        ALIAS,
        "--registry-path",
        &reg,
    ]);
    assert_eq!(out.code, 3, "{out:?}");
    let decision = one_envelope(&out)["next"]["decision_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let lock = w.lock_text();
    let (code, before, t, stdout) = terminal::answer_split(
        &w.env(),
        &w.home.root,
        &["--json", "decision", "approve", &decision],
        b"no\n",
    );
    assert_eq!(code, Some(3), "{t}");
    assert!(
        before.contains(&format!(
            "Enrollment of {ALIAS} ({DESTINATION}), account {}, form account",
            w.account
        )),
        "{before}"
    );
    assert!(before.contains("every remote step runs: ssh "), "{before}");
    for text in non_lock_disclosures() {
        assert!(before.contains(&text), "{text}: {before}");
    }
    assert!(
        before.contains(&format!("lock_continuity_once: {lock}")),
        "{before}"
    );
    assert!(!t.contains(&general_lock_sentence()), "{t}");
    let v = one_envelope_of(&stdout);
    assert_eq!(v["code"], "INTERACTION_REQUIRED", "{v}");
    assert_eq!(
        pending_of(&w, "enroll_account"),
        vec![decision],
        "nothing was sent"
    );
    assert_eq!(w.lock_ack(), None);
}
