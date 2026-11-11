//! m03-plan U5 (U5-io): the step runner, target binding, host trust, the maintenance
//! invocation and the production verification (ADR-0008 D5 §6.1, §6.3, §6.5; hosted by
//! heimdall-enroll).
//!
//! **Fixtures** (m03-plan §0.2; ADR-0008 D13). Everything is disposable and in one
//! scratch directory per test: a loopback `sshd` run as this user on `127.0.0.1` with a
//! per-run host key and a scratch `AuthorizedKeysFile` (the explicit registry), a
//! [`FakeAgent`] holding a per-run existing-access key, the scratch home of
//! `heimdall_testkit::home::ScratchHome` (its decoy agent is every client's
//! `SSH_AUTH_SOCK`), and per-run CA and K_verify keys. The sshd here is this file's
//! own (`fx::TestSshd`, written before U11's fixtures landed): it applies the D13 item 2
//! faults in place (stop by exact PID between the attempts, a listener on the freed
//! port that closes or resets, `MaxStartups 1:100:1` with held connections, the
//! sessions' `SetEnv PATH` lagging `awk`, `TrustedUserCAKeys` with U11's echoing
//! `AuthorizedPrincipalsCommand`). U11's `sshd::{Faults, LaggingClock, WrongKey}` are
//! equivalent fixtures; switching is mechanical. U11's `RegistryGuard` checks every
//! step's registry, its `PauseHooks`/`PrincipalsNotEnforced` drive `nonce_known`, and its
//! `ManagedRunContext` is the managed `run` environment.
//!
//! **Product command lines are under test** (m03-plan §0.2 exception): the steps'
//! target, host-trust, existing-access and narrowing pins come from
//! `heimdall_registry::step` and run unchanged through `SshStepRunner`; the
//! verification's generated configuration is the Verifier's. The only test addition
//! is the client path: a scratch wrapper that execs the system `ssh` with `-F <scratch
//! user config>` (so the owner's `~/.ssh/config` is never read) and a fixture
//! environment (`SSH_AUTH_SOCK` = a decoy, `HOME` = the scratch home).
//!
//! Tests that need a later unit (U2's real `VerificationSession`, U10's drivers) test
//! their part against `fx::TestSession`, a counting fake of the frozen port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use heimdall_enroll::remote::{KILLED_EXIT_STATUS, SshStepRunner, StepEnd, StepRunError, TtyMode};
use heimdall_enroll::trace::{
    self, ClientFamily, ClientVersion, RECORDED, UNRECORDED_FINDING, patterns_for,
};

#[cfg(unix)]
mod fx {
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant, SystemTime};

    use heimdall_app::ports::{AdapterError, VerificationSession};
    use heimdall_contract::enrollment::{
        ApprovedHostKey, ApprovedTarget, BootstrapPlan, DisclosureKind, EndpointSource,
        EnrollmentForm, EnrollmentPlan, ExistingAccessPlan, NoProxy, RegistryCanonical,
        RegistryRef, RegistryResolvedBy, RemoteStep, RollbackPlan, VerificationPlan,
    };
    use heimdall_contract::ids::{
        AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId,
    };
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_contract::setup::PlanDigest;
    use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
    use heimdall_credential::vault::SystemRng;
    use heimdall_domain::enrollment::{Determinism, TargetEvaluation};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::target::LocalTargetEvaluator;
    use heimdall_registry::step::{
        StageInput, StepEnv, StepTarget, TrustPaths, access_pins, remote_step_for,
        render_invocation, render_pairs, trust_pins,
    };
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::home::{Scratch, ScratchHome, find_program};
    use ssh_key::{HashAlg, PrivateKey, PublicKey};

    /// The local account (a non-root sshd authenticates only its own account).
    pub fn me() -> String {
        heimdall_localenv::doctor::local_account().expect("the local account")
    }

    /// `n` random bytes as lowercase hex.
    pub fn hex(n: usize) -> String {
        heimdall_testkit::agent::random_hex(n)
    }

    pub fn now_secs() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    pub fn system_ssh() -> PathBuf {
        let p = PathBuf::from("/usr/bin/ssh");
        if p.exists() {
            p
        } else {
            find_program("ssh").expect("an ssh client")
        }
    }

    /// `ssh -V`'s first line (the client's own text, for observations).
    pub fn client_version_text(client: &Path) -> String {
        Command::new(client)
            .arg("-V")
            .stdin(Stdio::null())
            .output()
            .map(|o| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
            })
            .unwrap_or_default()
    }

    pub fn client_version(client: &Path) -> heimdall_enroll::trace::ClientVersion {
        let out = Command::new(client)
            .arg("-V")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        heimdall_enroll::trace::ClientVersion::parse(&text).expect("ssh -V parses")
    }

    pub fn write_mode(path: &Path, text: &str, mode: u32) {
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Whether some live process has exactly `pid` (kill -0 by exact PID).
    pub fn pid_alive(pid: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    // --- the loopback sshd ---------------------------------------------------------------

    /// A loopback sshd run as this user (module documentation of the file).
    pub struct TestSshd {
        pub port: u16,
        pub host_key: FixtureKey,
        pub log: PathBuf,
        config: PathBuf,
        child: Arc<Mutex<Option<Child>>>,
    }

    impl TestSshd {
        /// Start with `registry` as `AuthorizedKeysFile` and `extra` sshd_config lines.
        pub fn start(scratch: &Scratch, registry: &Path, extra: &str) -> TestSshd {
            TestSshd::start_with_key(scratch, registry, extra, FixtureKey::generate())
        }

        pub fn start_with_key(
            scratch: &Scratch,
            registry: &Path,
            extra: &str,
            host_key: FixtureKey,
        ) -> TestSshd {
            let program = find_program("sshd").expect("sshd is installed");
            let dir = scratch.subdir("sshd").unwrap();
            let key_file = dir.join("host_ed25519");
            host_key.write_private(&key_file).unwrap();
            let log = dir.join("sshd.log");
            let config = dir.join("sshd_config");
            // `PerSourcePenalties` exists only from OpenSSH 9.8 (the devbox runs 9.6p1):
            // as the testkit's `LoopbackSshd` does, it is offered first and dropped only
            // when `sshd -t` names it (wave-1 native run, item B1).
            let mut penalties = true;
            for _ in 0..5 {
                let port = heimdall_testkit::sshd::pick_loopback_port().unwrap();
                let render = |penalties: bool| {
                    format!(
                        "ListenAddress 127.0.0.1\nPort {port}\nAddressFamily inet\n\
                         HostKey {}\nAuthorizedKeysFile {}\nPidFile none\nStrictModes no\n\
                         UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
                         PubkeyAuthentication yes\nAuthenticationMethods publickey\n\
                         PermitRootLogin no\nPermitUserRC no\nPermitUserEnvironment no\n\
                         AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\n\
                         UseDNS no\nMaxAuthTries 6\nLogLevel VERBOSE\n{}{extra}",
                        key_file.display(),
                        registry.display(),
                        if penalties {
                            "PerSourcePenalties no\n"
                        } else {
                            ""
                        }
                    )
                };
                let sshd_t = || {
                    Command::new(&program)
                        .args(["-t", "-f"])
                        .arg(&config)
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::piped())
                        .output()
                        .unwrap()
                };
                fs::write(&config, render(penalties)).unwrap();
                let mut check = sshd_t();
                if !check.status.success()
                    && penalties
                    && String::from_utf8_lossy(&check.stderr).contains("PerSourcePenalties")
                {
                    penalties = false;
                    fs::write(&config, render(penalties)).unwrap();
                    check = sshd_t();
                }
                assert!(
                    check.status.success(),
                    "sshd -t: {}",
                    String::from_utf8_lossy(&check.stderr)
                );
                let sshd = TestSshd {
                    port,
                    host_key: host_key.clone(),
                    log: log.clone(),
                    config: config.clone(),
                    child: Arc::new(Mutex::new(None)),
                };
                if sshd.spawn() {
                    return sshd;
                }
            }
            panic!("the fixture sshd did not start");
        }

        fn spawn(&self) -> bool {
            let program = find_program("sshd").unwrap();
            let _ = fs::remove_file(&self.log);
            let mut child = Command::new(program)
                .arg("-D")
                .arg("-f")
                .arg(&self.config)
                .arg("-E")
                .arg(&self.log)
                .env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let ready = format!("Server listening on 127.0.0.1 port {}.", self.port);
            let end = Instant::now() + Duration::from_secs(10);
            while Instant::now() < end {
                if fs::read_to_string(&self.log).is_ok_and(|t| t.contains(&ready)) {
                    *self.child.lock().unwrap() = Some(child);
                    return true;
                }
                if let Ok(Some(_)) = child.try_wait() {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let _ = child.wait();
            false
        }

        /// Stop by exact PID (the child handle).
        pub fn stop(&self) {
            stop_child(&self.child);
        }

        /// A `'static` handle that stops this sshd (for fault hooks).
        pub fn stopper(&self) -> impl Fn() + Send + Sync + 'static {
            let child = Arc::clone(&self.child);
            move || stop_child(&child)
        }

        /// `[127.0.0.1]:<port> ssh-ed25519 <base64>`.
        pub fn host_key_line(&self) -> String {
            format!(
                "[127.0.0.1]:{} {}",
                self.port,
                self.host_key.public_line_without_comment()
            )
        }

        pub fn log_text(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }

        /// Every `Accepted publickey` line's key part (`<TYPE> SHA256:… [ID …]`).
        pub fn accepted(&self) -> Vec<String> {
            self.log_text()
                .lines()
                .filter(|l| l.contains("Accepted publickey for "))
                .filter_map(|l| l.split_once("ssh2: ").map(|(_, k)| k.to_owned()))
                .collect()
        }
    }

    fn stop_child(child: &Mutex<Option<Child>>) {
        if let Some(mut c) = child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    impl Drop for TestSshd {
        fn drop(&mut self) {
            self.stop();
        }
    }

    // --- the lab: one scratch home, one existing access, one sshd ------------------------

    pub const ALIAS: &str = "hm-lab";

    pub struct Lab {
        pub sshd: TestSshd,
        pub existing: FixtureKey,
        pub agent: FakeAgent,
        pub existing_pub: PathBuf,
        pub registry: PathBuf,
        pub etc: PathBuf,
        pub client: PathBuf,
        pub ca: SecretCaKey,
        pub line: String,
        pub destination: DestinationId,
        /// Declared last: everything above lives in it.
        pub home: ScratchHome,
    }

    impl Lab {
        pub fn new() -> Lab {
            Lab::with_sshd_extra("")
        }

        pub fn with_sshd_extra(extra: &str) -> Lab {
            Lab::build(extra, AgentMode::Normal)
        }

        /// The existing-access agent in `mode` (for example `ApprovalPending`, which
        /// holds every signature until released: ssh waits before the ready line).
        pub fn with_agent_mode(mode: AgentMode) -> Lab {
            Lab::build("", mode)
        }

        fn build(extra: &str, mode: AgentMode) -> Lab {
            let home = ScratchHome::new();
            let scratch = home.scratch();
            let etc = scratch.subdir("etc").unwrap();
            let existing = FixtureKey::generate();
            let existing_pub = home.ssh_dir.join("existing.pub");
            existing.write_public(&existing_pub).unwrap();
            let agent = FakeAgent::start(
                Endpoint::in_scratch(scratch, "ea").unwrap(),
                FakeAgentConfig {
                    keys: vec![existing.clone()],
                    mode,
                },
            );
            let registry = scratch.subdir("reg").unwrap().join("authorized_keys");
            write_mode(
                &registry,
                &format!("restrict {}\n", existing.public_line_without_comment()),
                0o600,
            );
            let sshd = TestSshd::start(scratch, &registry, extra);
            let ca = SecretCaKey::generate().unwrap();
            let destination = DestinationId::parse("dst_lab").unwrap();
            let principal = heimdall_registry::line::principal(
                &destination,
                &AccountName::parse(&me()).unwrap(),
            )
            .unwrap();
            let marker = format!(
                "heimdall:{}",
                EnrollmentId::from_random_bytes(rand16()).as_str()
            );
            let line = heimdall_registry::line::expected_line(
                &ca.public_openssh().unwrap(),
                &principal,
                &marker,
            )
            .unwrap();
            let client = scratch.subdir("bin").unwrap().join("ssh");
            let lab = Lab {
                sshd,
                existing,
                agent,
                existing_pub,
                registry,
                etc,
                client,
                ca,
                line,
                destination,
                home,
            };
            lab.write_config("");
            lab.home.trust_host_key(&lab.sshd.host_key_line()).unwrap();
            lab.write_client(&lab.decoy(), &[], None);
            lab
        }

        pub fn scratch(&self) -> &Scratch {
            self.home.scratch()
        }

        pub fn agent_sock(&self) -> String {
            self.agent
                .endpoint()
                .locator()
                .to_string_lossy()
                .into_owned()
        }

        pub fn decoy(&self) -> String {
            self.home
                .decoy_agent()
                .endpoint()
                .locator()
                .to_string_lossy()
                .into_owned()
        }

        /// The user's ordinary configuration for the alias (existing access adopted),
        /// with `extra` lines **before** the alias block (so they win, as first values).
        pub fn write_config(&self, extra: &str) {
            self.home
                .write_user_config(&self.config_text(extra))
                .unwrap();
        }

        /// [`Self::write_config`]'s text.
        pub fn config_text(&self, extra: &str) -> String {
            format!(
                "{extra}Host {ALIAS}\n  HostName 127.0.0.1\n  Port {}\n  User {}\n  \
                 IdentityFile {}\n  IdentityAgent {}\n  IdentitiesOnly yes\n",
                self.sshd.port,
                me(),
                self.existing_pub.display(),
                self.agent_sock(),
            )
        }

        /// The client wrapper: the system ssh with `-F <scratch config>`, the fixture
        /// environment (`SSH_AUTH_SOCK` = `auth_sock`, `HOME` = the scratch home), and
        /// `path_dirs` first on `PATH`.
        pub fn write_client(&self, auth_sock: &str, path_dirs: &[&Path], pid_file: Option<&Path>) {
            let mut path: Vec<String> = path_dirs.iter().map(|p| p.display().to_string()).collect();
            path.push("/usr/bin:/bin:/usr/sbin:/sbin".into());
            let pid = pid_file.map_or(String::new(), |p| format!("echo $$ > '{}'\n", p.display()));
            let text = format!(
                "#!/bin/sh\n{pid}SSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK\nHOME='{}'; export HOME\n\
                 PATH='{}'; export PATH\nunset SSH_ASKPASS SSH_ASKPASS_REQUIRE SSH_AGENT_PID DISPLAY\n\
                 exec '{}' -F '{}' \"$@\"\n",
                auth_sock,
                self.home.git_home.display(),
                path.join(":"),
                system_ssh().display(),
                self.home.user_config.display(),
            );
            let _ = fs::remove_file(&self.client);
            write_mode(&self.client, &text, 0o700);
        }

        pub fn evaluator(&self) -> LocalTargetEvaluator {
            LocalTargetEvaluator::new(
                SshPaths::with_test_override(self.home.git_home.clone(), self.etc.clone()),
                Env::from_vars([("SSH_AUTH_SOCK", self.decoy())]),
                Platform::current(),
            )
            .with_local_user(Some(me()))
        }

        pub fn evaluate(&self) -> TargetEvaluation {
            self.evaluator().evaluate_alias(ALIAS)
        }

        /// The approved target of the alias as it is now (the preview).
        pub fn approve(&self) -> ApprovedTarget {
            approved_from(&self.evaluate())
        }

        /// A step for `approved` (the runtime's part: the generated known-hosts file,
        /// the token; the pins come from `heimdall_registry::step`).
        pub fn step(
            &self,
            approved: &ApprovedTarget,
            stage: StageInput<'_>,
            not_after: Option<i64>,
        ) -> RemoteStep {
            self.step_with(approved, stage, not_after, &self.agent_sock(), false)
        }

        pub fn step_with(
            &self,
            approved: &ApprovedTarget,
            stage: StageInput<'_>,
            not_after: Option<i64>,
            endpoint: &str,
            interactive: bool,
        ) -> RemoteStep {
            self.step_with_gssapi(approved, stage, not_after, endpoint, interactive, false)
        }

        /// [`step_with`](Self::step_with), with `GSSAPIKeyExchange=no` pinned when the
        /// client's `ssh -G` lists the option (Q23; the second pass the runtime runs).
        pub fn step_with_gssapi(
            &self,
            approved: &ApprovedTarget,
            stage: StageInput<'_>,
            not_after: Option<i64>,
            endpoint: &str,
            interactive: bool,
            gssapi_key_exchange: bool,
        ) -> RemoteStep {
            // The registry guard (m03-plan §0.2): the target registry is in scratch.
            heimdall_testkit::registry::RegistryGuard::new(self.scratch())
                .unwrap()
                .check(&heimdall_testkit::registry::RegistryTarget::Path(
                    &self.registry,
                ))
                .expect("the registry guard holds");
            let tag = hex(8);
            let dir = self.scratch().subdir("e").unwrap();
            let user_known_hosts = dir.join("known_hosts");
            let global_known_hosts = dir.join("global_known_hosts");
            write_mode(
                &user_known_hosts,
                &format!(
                    "hm-target-{tag} {} {}\n",
                    approved.host_key.algorithm, approved.host_key.key
                ),
                0o600,
            );
            write_mode(&global_known_hosts, "", 0o600);
            let host_trust = render_pairs(
                &trust_pins(
                    approved,
                    &TrustPaths {
                        tag,
                        user_known_hosts: user_known_hosts.display().to_string(),
                        global_known_hosts: global_known_hosts.display().to_string(),
                    },
                )
                .unwrap(),
            );
            let invocation = render_invocation(
                &access_pins(endpoint, &self.existing_pub.display().to_string()).unwrap(),
            );
            let registry = RegistryCanonical {
                path: Some(self.registry.display().to_string()),
                resolved_by: RegistryResolvedBy::Explicit,
            };
            let client = self.client.display().to_string();
            remote_step_for(
                stage,
                &StepTarget {
                    alias: ALIAS,
                    target: approved,
                    host_trust: &host_trust,
                    invocation: &invocation,
                    registry: &registry,
                    line: &self.line,
                },
                &hex(16),
                180_000,
                not_after,
                &StepEnv {
                    client: &client,
                    timeout_ms: 60_000,
                    interactive,
                    gssapi_key_exchange,
                },
            )
            .unwrap()
        }

        pub fn registry_bytes(&self) -> Vec<u8> {
            fs::read(&self.registry).unwrap()
        }

        /// The approved target with another host key (a wrong-key approval).
        pub fn with_key(approved: &ApprovedTarget, key: &FixtureKey) -> ApprovedTarget {
            let line = key.public_line_without_comment();
            let b64 = line.split_whitespace().nth(1).unwrap().to_owned();
            ApprovedTarget {
                host_key: ApprovedHostKey {
                    algorithm: "ssh-ed25519".into(),
                    key: b64,
                    fingerprint: key.fingerprint(),
                },
                ..approved.clone()
            }
        }
    }

    pub fn rand16() -> [u8; 16] {
        let mut b = [0u8; 16];
        getrandom_fill(&mut b);
        b
    }

    fn getrandom_fill(b: &mut [u8]) {
        SystemRng::fill(b).unwrap();
    }

    pub fn approved_from(t: &TargetEvaluation) -> ApprovedTarget {
        assert_eq!(t.determinism, Determinism::Determined, "{t:?}");
        let live: Vec<_> = t.host_keys.iter().filter(|k| !k.revoked).collect();
        assert_eq!(live.len(), 1, "exactly one host key: {:?}", t.host_keys);
        ApprovedTarget {
            hostname: t.hostname.clone(),
            port: t.port,
            user: AccountName::parse(&t.user).unwrap(),
            proxy: NoProxy::None,
            host_key: live[0].approved(),
        }
    }

    /// The registry fields of an inspect, by key.
    pub fn hm1_values(stdout: &str, key: &str) -> Vec<String> {
        stdout
            .lines()
            .filter_map(|l| l.strip_prefix("HM1 "))
            .filter_map(|kv| kv.split_once('='))
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.to_owned())
            .collect()
    }

    // --- the verification side --------------------------------------------------------

    /// A plan whose only field the Verifier reads is the approved target.
    pub fn plan_for(
        target: &ApprovedTarget,
        line: &str,
        destination: &DestinationId,
    ) -> EnrollmentPlan {
        EnrollmentPlan {
            plan_digest: PlanDigest::parse(&"0".repeat(64)).unwrap(),
            destination_id: destination.clone(),
            alias: ALIAS.into(),
            account: target.user.clone(),
            form: EnrollmentForm::Account,
            registry: RegistryRef {
                path_display: "scratch".into(),
                resolved_by: RegistryResolvedBy::Explicit,
            },
            line: line.into(),
            line_sha256: "0".repeat(64),
            ca_fingerprint: CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap(),
            existing_access: ExistingAccessPlan {
                identity_id: IdentityId::from_random_bytes(rand16()),
                mechanism: "native_agent".into(),
                endpoint: "/unused".into(),
                endpoint_source: EndpointSource::CatalogRecord,
                invocation: Vec::new(),
            },
            host_trust: Vec::new(),
            approved_target: target.clone(),
            bootstrap: Some(BootstrapPlan::CreateRegistryDir0700IfAbsent),
            verification: VerificationPlan {
                positive_principal: String::new(),
                negative: true,
                max_validity_seconds: 300,
            },
            rollback: RollbackPlan::CompareThenRenameByMarker,
            disclosures: vec![DisclosureKind::CaTrustBlastRadius],
        }
    }

    /// A user certificate for `subject` with one principal, signed by `ca` (U1's
    /// `build_and_sign`), valid from `after` to `before` (Unix seconds).
    pub fn issue(
        ca: &SecretCaKey,
        subject: &PublicKey,
        principal: &str,
        after: i64,
        before: i64,
    ) -> String {
        let profile = CertificateProfile {
            serial: u64::from_be_bytes(rand16()[..8].try_into().unwrap()),
            key_id: format!("hm-test-{}", hex(4)),
            principal: principal.into(),
            valid_after: after,
            valid_before: before,
            extensions: BTreeSet::new(),
            subject_fingerprint: subject.fingerprint(HashAlg::Sha256).to_string(),
            ca_fingerprint: Some(ca.fingerprint().unwrap()),
        };
        build_and_sign(&profile, subject, ca)
            .unwrap()
            .to_openssh()
            .unwrap()
    }

    pub fn negative_principal() -> String {
        format!("hm:verify-negative:{}", hex(16))
    }

    type InstallHook = Box<dyn FnMut(usize, &str) + Send>;

    struct SessionShared {
        key: PrivateKey,
        extra: Vec<PrivateKey>,
        certs: Mutex<Vec<Vec<u8>>>,
        signatures: AtomicU32,
        extra_signatures: AtomicU32,
        binds: AtomicU32,
        installs: AtomicU32,
        hook: Mutex<Option<InstallHook>>,
    }

    /// A counting fake of `app::ports::VerificationSession` (U2's real one is not in
    /// wave 1): an in-process agent on a scratch socket holding K_verify (and the
    /// installed certificates), counting signatures per key and session-binds.
    pub struct TestSession {
        public: String,
        fingerprint: String,
        locator: EndpointRef,
        shared: Arc<SessionShared>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestSession {
        pub fn start(scratch: &Scratch) -> TestSession {
            TestSession::start_with_extra(scratch, Vec::new())
        }

        /// `extra` keys are listed (and signed for) too: canaries that must never sign.
        pub fn start_with_extra(scratch: &Scratch, extra: Vec<PrivateKey>) -> TestSession {
            let key = PrivateKey::random(&mut SystemRng, ssh_key::Algorithm::Ed25519).unwrap();
            let public = key.public_key().to_openssh().unwrap();
            let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
            let path = scratch.subdir("vs").unwrap().join("v.sock");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let shared = Arc::new(SessionShared {
                key,
                extra,
                certs: Mutex::new(Vec::new()),
                signatures: AtomicU32::new(0),
                extra_signatures: AtomicU32::new(0),
                binds: AtomicU32::new(0),
                installs: AtomicU32::new(0),
                hook: Mutex::new(None),
            });
            let stop = Arc::new(AtomicBool::new(false));
            let (s2, stop2) = (Arc::clone(&shared), Arc::clone(&stop));
            let thread = std::thread::spawn(move || {
                while !stop2.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((conn, _)) => {
                            let s3 = Arc::clone(&s2);
                            std::thread::spawn(move || serve(conn, &s3));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
            TestSession {
                public,
                fingerprint,
                locator: EndpointRef {
                    kind: EndpointKind::UnixSocket,
                    locator: path.display().to_string(),
                },
                shared,
                stop,
                thread: Some(thread),
            }
        }

        /// K_verify's public key.
        pub fn subject(&self) -> PublicKey {
            self.shared.key.public_key().clone()
        }

        pub fn fingerprint(&self) -> &str {
            &self.fingerprint
        }

        pub fn extra_signatures(&self) -> u32 {
            self.shared.extra_signatures.load(Ordering::SeqCst)
        }

        pub fn installs(&self) -> u32 {
            self.shared.installs.load(Ordering::SeqCst)
        }

        /// Run `hook(index, certificate_line)` at each install (0: positive, 1: negative),
        /// before the attempt starts: the fault injection point between attempts.
        pub fn on_install(&self, hook: impl FnMut(usize, &str) + Send + 'static) {
            *self.shared.hook.lock().unwrap() = Some(Box::new(hook));
        }
    }

    impl Drop for TestSession {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    impl VerificationSession for TestSession {
        fn public_key(&self) -> &str {
            &self.public
        }

        fn install(&self, certificate_line: &str) -> Result<(), AdapterError> {
            let cert = ssh_key::Certificate::from_openssh(certificate_line.trim())
                .map_err(|_| AdapterError::Protocol("certificate".into()))?;
            if cert.public_key() != self.shared.key.public_key().key_data() {
                return Err(AdapterError::Protocol("subject".into()));
            }
            let blob = cert.to_bytes().unwrap();
            let index = self.shared.installs.fetch_add(1, Ordering::SeqCst) as usize;
            self.shared.certs.lock().unwrap().push(blob);
            if let Some(hook) = self.shared.hook.lock().unwrap().as_mut() {
                hook(index, certificate_line);
            }
            Ok(())
        }

        fn locator(&self) -> &EndpointRef {
            &self.locator
        }

        fn signatures(&self, key_fingerprint: &str) -> u32 {
            if key_fingerprint == self.fingerprint {
                self.shared.signatures.load(Ordering::SeqCst)
            } else {
                0
            }
        }

        fn session_binds(&self) -> u32 {
            self.shared.binds.load(Ordering::SeqCst)
        }
    }

    fn put_string(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&u32::try_from(b.len()).unwrap().to_be_bytes());
        out.extend_from_slice(b);
    }

    fn take_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
        let len = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
        let s = b.get(4..4 + len)?;
        Some((s, &b[4 + len..]))
    }

    fn sign_with<K: ssh_key::SigningKey>(key: &K, data: &[u8]) -> Option<Vec<u8>> {
        let sig: ssh_key::Signature = key.try_sign(data).ok()?;
        let mut out = Vec::new();
        put_string(&mut out, sig.algorithm().as_str().as_bytes());
        put_string(&mut out, sig.as_bytes());
        Some(out)
    }

    fn serve(mut conn: UnixStream, s: &SessionShared) {
        // An accepted socket inherits the listener's non-blocking flag on some systems.
        let _ = conn.set_nonblocking(false);
        let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
        loop {
            let mut len = [0u8; 4];
            if conn.read_exact(&mut len).is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > 256 * 1024 {
                return;
            }
            let mut msg = vec![0u8; n];
            if conn.read_exact(&mut msg).is_err() {
                return;
            }
            let reply = respond(&msg, s);
            let mut framed = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            if conn.write_all(&framed).is_err() {
                return;
            }
        }
    }

    fn respond(msg: &[u8], s: &SessionShared) -> Vec<u8> {
        const FAILURE: u8 = 5;
        const SUCCESS: u8 = 6;
        let plain = s.key.public_key().key_data().clone();
        let plain_blob = ssh_key::PublicKey::from(plain).to_bytes().unwrap();
        match msg[0] {
            11 => {
                let certs = s.certs.lock().unwrap().clone();
                let extra: Vec<Vec<u8>> = s
                    .extra
                    .iter()
                    .map(|k| k.public_key().to_bytes().unwrap())
                    .collect();
                let mut out = vec![12u8];
                let all: Vec<&Vec<u8>> = certs.iter().chain([&plain_blob]).chain(&extra).collect();
                out.extend_from_slice(&u32::try_from(all.len()).unwrap().to_be_bytes());
                for b in all {
                    put_string(&mut out, b);
                    put_string(&mut out, b"");
                }
                out
            }
            13 => {
                let Some((blob, rest)) = take_string(&msg[1..]) else {
                    return vec![FAILURE];
                };
                let Some((data, _)) = take_string(rest) else {
                    return vec![FAILURE];
                };
                let ours = blob == plain_blob.as_slice()
                    || s.certs.lock().unwrap().iter().any(|c| c.as_slice() == blob);
                let signature = if ours {
                    s.signatures.fetch_add(1, Ordering::SeqCst);
                    sign_with(&s.key, data)
                } else if let Some(k) = s
                    .extra
                    .iter()
                    .find(|k| k.public_key().to_bytes().unwrap().as_slice() == blob)
                {
                    s.extra_signatures.fetch_add(1, Ordering::SeqCst);
                    sign_with(k, data)
                } else {
                    None
                };
                match signature {
                    Some(sig) => {
                        let mut out = vec![14u8];
                        put_string(&mut out, &sig);
                        out
                    }
                    None => vec![FAILURE],
                }
            }
            27 => match take_string(&msg[1..]) {
                Some((name, _)) if name == b"session-bind@openssh.com" => {
                    s.binds.fetch_add(1, Ordering::SeqCst);
                    vec![SUCCESS]
                }
                _ => vec![FAILURE],
            },
            _ => vec![FAILURE],
        }
    }

    /// A verification lab: the lab's sshd with `line` in its registry, a session, a
    /// Verifier over the system client, and both certificates.
    pub struct VerifyLab {
        pub session: TestSession,
        pub verifier: heimdall_enroll::verify::Verifier,
        pub runtime: PathBuf,
        pub approved: ApprovedTarget,
        pub positive: String,
        pub negative: String,
        pub plan: EnrollmentPlan,
        pub lab: Lab,
    }

    impl VerifyLab {
        pub fn new() -> VerifyLab {
            VerifyLab::with(Lab::new(), true)
        }

        /// With `write_line`, the enrollment's line is in the registry (applied).
        pub fn with(lab: Lab, write_line: bool) -> VerifyLab {
            if write_line {
                let mut text = String::from_utf8(lab.registry_bytes()).unwrap();
                text.push_str(&lab.line);
                text.push('\n');
                write_mode(&lab.registry, &text, 0o600);
            }
            let session = TestSession::start(lab.scratch());
            let runtime = lab.scratch().subdir("rt").unwrap();
            let client = system_ssh();
            let verifier = heimdall_enroll::verify::Verifier::with_client(
                heimdall_enroll::verify::VerifierClient {
                    version: client_version(&client),
                    path: client,
                },
                &runtime,
            );
            let approved = lab.approve();
            let now = now_secs();
            let principal = heimdall_registry::line::principal(
                &lab.destination,
                &AccountName::parse(&me()).unwrap(),
            )
            .unwrap();
            let positive = issue(&lab.ca, &session.subject(), &principal, now - 60, now + 300);
            let negative = issue(
                &lab.ca,
                &session.subject(),
                &negative_principal(),
                now - 60,
                now + 300,
            );
            let plan = plan_for(&approved, &lab.line, &lab.destination);
            VerifyLab {
                session,
                verifier,
                runtime,
                approved,
                positive,
                negative,
                plan,
                lab,
            }
        }

        pub fn run(&self) -> heimdall_enroll::verify::VerifierReport {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let report = rt.block_on(self.verifier.run_detailed(
                &self.plan,
                &self.positive,
                &self.negative,
                &self.session,
            ));
            if let Some(unrecorded) = report.unrecorded {
                // Wave-1 native run, item C: no row for this client yet, so the
                // verification rows cannot run (fail closed) until the row is recorded
                // from `verify_positive_one_signature_negative_zero`'s observation lines,
                // never from expectation.
                panic!(
                    "{}: this client has no recorded trace row, so the verification rows cannot run \
                     until it is recorded from the `m03 observation: client_trace_row` lines \
                     (inconclusive by design; not a pass)",
                    unrecorded
                );
            }
            report
        }

        /// Item C: run the same attempts once more under the recorded `10.5p1` label
        /// (its patterns only parse; the raw trace is what counts), dump the raw traces
        /// (`Verifier::with_test_trace_dump`, debug builds), and print each line a trace
        /// row's fields come from, redacted, as `m03 observation:` lines. Nothing of this
        /// run's report is used as evidence of a verification.
        pub fn observe_unrecorded_trace(&self, version: heimdall_enroll::trace::ClientVersion) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let dump = self.lab.scratch().subdir("trace-dump").unwrap();
            let label = heimdall_enroll::trace::RECORDED[0].from;
            let observer = heimdall_enroll::verify::Verifier::with_client(
                heimdall_enroll::verify::VerifierClient {
                    path: system_ssh(),
                    version: label,
                },
                &self.runtime,
            )
            .with_test_trace_dump(&dump);
            let r = rt.block_on(observer.run_detailed(
                &self.plan,
                &self.positive,
                &self.negative,
                &self.session,
            ));
            let family = version.family.as_str();
            let root = self.lab.scratch().path().to_string_lossy().into_owned();
            let user = me();
            let redact = |l: &str| {
                let t = l.replace(&root, "<scratch>");
                if user.len() >= 2 {
                    t.replace(&user, "<user>")
                } else {
                    t
                }
            };
            const MARKERS: &[&str] = &[
                "remote software version",
                "is known and matches",
                "Offering public key",
                "Server accepts key",
                "Authentications that can continue",
                "Authenticated to",
                "Permission denied",
                "Host key verification failed",
                "REMOTE HOST IDENTIFICATION HAS CHANGED",
                "host key is known for",
            ];
            #[allow(clippy::print_stderr)] // the observed facts for the client's trace row
            {
                eprintln!(
                    "m03 observation: client_trace_row family={family} version={version} client={:?} parsed_with={label} positive_events={:?} negative_events={:?} positive_exit={:?} negative_exit={:?} positive_signatures={} negative_signatures={}",
                    client_version_text(&system_ssh()),
                    r.positive.result.trace,
                    r.negative.result.trace,
                    r.positive.result.exit_status,
                    r.negative.result.exit_status,
                    r.positive.result.signatures,
                    r.negative.result.signatures
                );
                for which in ["positive", "negative"] {
                    let text = fs::read(dump.join(format!("{which}.trace")))
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    for line in text.lines() {
                        let line = line.trim_end_matches('\r');
                        if MARKERS.iter().any(|m| line.contains(m)) {
                            eprintln!(
                                "m03 observation: client_trace_row family={family} version={version} attempt={which} line={:?}",
                                redact(line)
                            );
                        }
                    }
                }
            }
            // The fixture sshd's own account of the attempts (refusal reasons), redacted.
            #[allow(clippy::print_stderr)]
            for line in self.lab.sshd.log_text().lines() {
                if [
                    "rror",
                    "efus",
                    "nvalid",
                    "ertificate",
                    "ccepted",
                    "Failed",
                    "uthentication",
                ]
                .iter()
                .any(|m| line.contains(m))
                {
                    eprintln!(
                        "m03 observation: client_trace_row family={family} version={version} sshd_log={:?}",
                        redact(line)
                    );
                }
            }
            let _ = fs::remove_dir_all(&dump);
        }

        /// Nothing generated is left behind.
        pub fn assert_no_generated_files(&self) {
            let v = self.runtime.join("v");
            let left: Vec<_> = fs::read_dir(&v)
                .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
                .unwrap_or_default();
            assert!(left.is_empty(), "left behind: {left:?}");
        }
    }
}

// --- trace patterns (every platform) ------------------------------------------------------

/// ADR-0008 D5 §6.5 item 5, §17.4 item 11: patterns are keyed by upstream release
/// family and carry only recorded ranges. This host's 10.5p1 row and the devbox's 9.6p1
/// row (observed in two devbox runs: at `5b36b3d8`, then the host-key-failure lines on
/// the round-4 tree) are recorded; the Windows rows are the orchestrator's native runs
/// and stay unrecorded.
#[test]
fn trace_patterns_keyed_by_release_family() {
    assert!(!RECORDED.is_empty());
    for row in RECORDED {
        assert_eq!(row.from.family, row.family);
        assert_eq!(row.to.family, row.family);
        assert!(row.from <= row.to);
        assert!(patterns_for(row.family, row.from).is_ok());
        assert!(patterns_for(row.family, row.to).is_ok());
    }
    let portable = ClientVersion::parse("OpenSSH_10.5p1, LibreSSL 3.3.6").unwrap();
    assert_eq!(portable.family, ClientFamily::Portable);
    assert!(patterns_for(ClientFamily::Portable, portable).is_ok());
    // The same version number in the other family is another client.
    let win = ClientVersion::parse("OpenSSH_for_Windows_10.5p1, LibreSSL 3.4.3").unwrap();
    assert_eq!(win.family, ClientFamily::Win32);
    assert!(patterns_for(ClientFamily::Win32, win).is_err());
    assert!(patterns_for(ClientFamily::Portable, win).is_err());
    // The devbox's 9.6p1, recorded from its observed run (any portable 9.6p1 build).
    let devbox = ClientVersion::parse("OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13").unwrap();
    assert!(patterns_for(devbox.family, devbox).is_ok());
    // Rows not observed yet: unrecorded until a native run records them.
    for text in [
        "OpenSSH_9.7p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13",
        "OpenSSH_for_Windows_10.3p1, LibreSSL 3.4.3",
        "OpenSSH_for_Windows_9.5p2, LibreSSL 3.4.3",
    ] {
        let v = ClientVersion::parse(text).unwrap();
        assert!(patterns_for(v.family, v).is_err(), "{text}");
    }
    // On this host, the system client is in a recorded row when it is 10.5p1.
    #[cfg(target_os = "macos")]
    {
        let v = fx::client_version(&fx::system_ssh());
        eprintln!("system client: {} {}", v.family.as_str(), v);
        if v == portable {
            assert!(patterns_for(v.family, v).is_ok());
        }
    }
}

/// ADR-0008 D5 §6.5 item 5: an unrecorded family or version names itself for the
/// doctor (`client_trace_family_unrecorded`, family and version).
#[test]
fn unrecorded_client_family_doctor_finding_names_version() {
    let v = ClientVersion::parse("OpenSSH_9.7p1 Ubuntu-3ubuntu13.5").unwrap();
    let e = patterns_for(v.family, v).unwrap_err();
    assert_eq!(e.finding(), UNRECORDED_FINDING);
    assert_eq!(e.detail(), "portable 9.7p1");
    assert!(e.to_string().contains("client_trace_family_unrecorded"));
    assert!(e.to_string().contains("9.7p1"));
    let w = ClientVersion::parse("OpenSSH_for_Windows_10.3p1").unwrap();
    assert_eq!(
        patterns_for(w.family, w).unwrap_err().detail(),
        "win32 10.3p1"
    );
    let _ = trace::UNRECORDED_FINDING;
}

/// The runner refuses before spawning anything when it has nothing it may run; on
/// Windows a runner without the CLI's containment refuses every step.
#[test]
fn runner_refuses_without_spawning() {
    use heimdall_contract::enrollment::{RemoteStage, RemoteStep, StepPins};
    let step = RemoteStep {
        stage: RemoteStage::Inspect,
        step_token: "0".repeat(32),
        client: "relative-ssh".into(),
        pins: StepPins::default(),
        alias: "hm-test".into(),
        remote_command: heimdall_enroll::remote::STEP_REMOTE_COMMAND.into(),
        script: "hm_main\n".into(),
        timeout_ms: 1000,
        hard_deadline_ms: 1000,
        not_after_remote: None,
    };
    let r = SshStepRunner::new().run(&step, TtyMode::Batch);
    assert_eq!(r, Err(StepRunError::InvalidStep("client_not_absolute")));
    let _ = (KILLED_EXIT_STATUS, StepEnd::Exited);
}

// --- shared helpers for the Unix tests ------------------------------------------------------

#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use heimdall_contract::enrollment::{ApprovedTarget, RemoteStep, SshOption};
#[cfg(unix)]
use heimdall_domain::enrollment::ProxyRoute;
#[cfg(unix)]
use heimdall_enroll::remote::{KillCause, StepReport};
#[cfg(unix)]
use heimdall_registry::classify::{
    Expected, NotAppliedReason, StepClass, StepResult, classify_step,
};
#[cfg(unix)]
use heimdall_registry::step::StageInput;
#[cfg(unix)]
use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey, msg};

#[cfg(unix)]
fn run(step: &RemoteStep) -> StepReport {
    SshStepRunner::new().run(step, TtyMode::Batch).unwrap()
}

#[cfg(unix)]
fn class_of(step: &RemoteStep, report: &StepReport, expected: &Expected) -> StepClass {
    classify_step(
        step.stage,
        &StepResult {
            exit_status: report.exit_status,
            stdout: report.stdout.clone(),
            stderr_excerpt: report.stderr_excerpt.clone(),
        },
        expected,
    )
}

#[cfg(unix)]
fn expected_for(lab: &fx::Lab, preimage: Option<Vec<u8>>) -> Expected {
    Expected {
        marker: heimdall_registry::line::marker_of(&lab.line)
            .unwrap()
            .to_owned(),
        line: Some(lab.line.clone()),
        preimage,
        post_image: None,
    }
}

/// A step without the pin `key` (a control run: what the inherited configuration
/// would do without that pin).
#[cfg(unix)]
fn without_pin(step: &RemoteStep, key: &str) -> RemoteStep {
    let mut s = step.clone();
    for group in [
        &mut s.pins.target.0,
        &mut s.pins.host_trust.0,
        &mut s.pins.existing_access.0,
        &mut s.pins.narrowing.0,
    ] {
        group.retain(|o: &SshOption| !o.key.eq_ignore_ascii_case(key));
    }
    s
}

#[cfg(unix)]
fn pin(step: &RemoteStep, key: &str) -> Option<String> {
    step.pins
        .target
        .0
        .iter()
        .chain(&step.pins.host_trust.0)
        .chain(&step.pins.existing_access.0)
        .chain(&step.pins.narrowing.0)
        .find(|o| o.key == key)
        .map(|o| o.value.clone())
}

/// An append step valid for 10 minutes on the (loopback, same-clock) destination.
#[cfg(unix)]
fn append_step(lab: &fx::Lab, approved: &ApprovedTarget) -> RemoteStep {
    lab.step(approved, StageInput::Append, Some(fx::now_secs() + 600))
}

/// No lock or temporary file of a script was left in the registry's directory.
#[cfg(unix)]
fn registry_dir_untouched(lab: &fx::Lab) {
    let dir = lab.registry.parent().unwrap();
    let names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["authorized_keys"], "registry dir: {names:?}");
}

/// A scratch program that records each run in `<dir>/<name>.ran` and prints `out`.
#[cfg(unix)]
fn recording_program(dir: &Path, name: &str, out: &str) -> (PathBuf, PathBuf) {
    let program = dir.join(name);
    let record = dir.join(format!("{name}.ran"));
    fx::write_mode(
        &program,
        &format!(
            "#!/bin/sh\necho ran >> '{}'\nprintf '%s\\n' '{}'\n",
            record.display(),
            out
        ),
        0o700,
    );
    (program, record)
}

#[cfg(unix)]
fn wrong_key_line(key: &FixtureKey) -> String {
    format!("* {}", key.public_line_without_comment())
}

// --- target binding (ADR-0008 §17.1 item 2; M03-R02) ------------------------------------------

/// The approved target comes from the passive evaluation (HostName, Port, User, the one
/// known host key with its raw blob), and every step pins exactly it: the step reaches
/// the approved server as the approved user, trusting only the approved key.
#[cfg(unix)]
#[test]
fn step_pins_hostname_port_user_and_host_key() {
    let lab = fx::Lab::new();
    lab.home.check_alias(fx::ALIAS).unwrap();
    let approved = lab.approve();
    assert_eq!(approved.hostname, "127.0.0.1");
    assert_eq!(approved.port, lab.sshd.port);
    assert_eq!(approved.user.as_str(), fx::me());
    let server_key = lab.sshd.host_key.public_line_without_comment();
    let server_b64 = server_key.split_whitespace().nth(1).unwrap();
    assert_eq!(approved.host_key.algorithm, "ssh-ed25519");
    assert_eq!(approved.host_key.key, server_b64);
    assert_eq!(
        approved.host_key.fingerprint,
        lab.sshd.host_key.fingerprint()
    );

    let step = lab.step(&approved, StageInput::Inspect, None);
    // The runner runs exactly the registry's argument list.
    assert_eq!(
        heimdall_enroll::remote::step_argv(&step, TtyMode::Batch).unwrap(),
        heimdall_registry::step::ssh_args(&step)
    );
    let port = lab.sshd.port.to_string();
    let me = fx::me();
    for (k, v) in [
        ("HostName", "127.0.0.1"),
        ("Port", port.as_str()),
        ("User", me.as_str()),
        ("ProxyCommand", "none"),
        ("ProxyJump", "none"),
        ("CanonicalizeHostname", "no"),
        ("HostKeyAlgorithms", "ssh-ed25519"),
        ("StrictHostKeyChecking", "yes"),
        ("KnownHostsCommand", "none"),
        ("BatchMode", "yes"),
        ("ForkAfterAuthentication", "no"),
        ("CertificateFile", "none"),
        ("IdentitiesOnly", "yes"),
    ] {
        assert_eq!(pin(&step, k).as_deref(), Some(v), "{k}");
    }
    assert!(
        pin(&step, "HostKeyAlias")
            .unwrap()
            .starts_with("hm-target-")
    );
    let before = lab.registry_bytes();
    let report = run(&step);
    assert_eq!(report.exit_status, 0, "{report:?}");
    assert!(report.ready_seen && report.script_sent);
    assert_eq!(report.ended, StepEnd::Exited);
    assert!(
        report.stdout.starts_with("HM1 ready\nHM1 v=1\n"),
        "{}",
        report.stdout
    );
    assert_eq!(
        fx::hm1_values(&report.stdout, "status"),
        ["ok"],
        "{}",
        report.stdout
    );
    assert_eq!(lab.registry_bytes(), before, "inspect writes nothing");
    assert_eq!(
        class_of(&step, &report, &expected_for(&lab, None)),
        StepClass::Confirmed
    );
    // The approved server accepted the existing identity, as the approved user.
    let accepted = lab.sshd.accepted();
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0].contains(&lab.existing.fingerprint()),
        "{accepted:?}"
    );
    assert!(
        lab.sshd
            .log_text()
            .contains(&format!("Accepted publickey for {me} "))
    );
    assert!(report.lifetime.process_group && report.lifetime.ready_handshake);
}

/// A `HostName` change after approval is a different evaluation (`route_changed` for the
/// runtime), and a step built from the approved target still reaches the approved
/// server: the change cannot redirect the append.
#[cfg(unix)]
#[test]
fn user_config_hostname_change_cannot_redirect_append() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    // A second server the changed configuration points at, trusted by the user too,
    // which would accept the same existing key.
    let other_registry = lab.scratch().subdir("reg").unwrap().join("authorized_keys");
    fx::write_mode(
        &other_registry,
        &format!("restrict {}\n", lab.existing.public_line_without_comment()),
        0o600,
    );
    let other = fx::TestSshd::start(lab.scratch(), &other_registry, "");
    lab.home.trust_host_key(&other.host_key_line()).unwrap();
    lab.write_config(&format!(
        "Host {}\n  HostName localhost\n  Port {}\n",
        fx::ALIAS,
        other.port
    ));
    let changed = lab.evaluate();
    assert_ne!(
        (changed.hostname.as_str(), changed.port),
        (approved.hostname.as_str(), approved.port),
        "the re-evaluation sees the change"
    );
    let other_before = std::fs::read(&other_registry).unwrap();
    let step = append_step(&lab, &approved);
    let report = run(&step);
    assert_eq!(report.exit_status, 0, "{report:?}");
    assert_eq!(fx::hm1_values(&report.stdout, "status"), ["written"]);
    let text = String::from_utf8(lab.registry_bytes()).unwrap();
    assert_eq!(
        text.matches(lab.line.as_str()).count(),
        1,
        "appended to the approved registry"
    );
    assert_eq!(
        std::fs::read(&other_registry).unwrap(),
        other_before,
        "never redirected"
    );
    assert!(other.accepted().is_empty(), "the other server saw no login");
}

/// A `ProxyCommand` added after approval changes the evaluated route (refused,
/// `route_changed`); a step from the approved target pins `ProxyCommand=none`, so the
/// added command never runs.
#[cfg(unix)]
#[test]
fn user_config_proxycommand_added_after_approval_refused() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let dir = lab.scratch().subdir("px").unwrap();
    let (proxy, record) = recording_program(&dir, "proxy", "");
    lab.write_config(&format!(
        "Host {}\n  ProxyCommand {} %h %p\n",
        fx::ALIAS,
        proxy.display()
    ));
    let changed = lab.evaluate();
    assert_eq!(changed.proxy, ProxyRoute::Command, "the change is seen");
    assert_ne!(changed.proxy, ProxyRoute::None);
    let step = lab.step(&approved, StageInput::Inspect, None);
    let report = run(&step);
    assert_eq!(report.exit_status, 0, "{report:?}");
    assert!(!record.exists(), "the added ProxyCommand never ran");
    // Control: without the pin the inherited ProxyCommand runs (and the step fails).
    let control = run(&without_pin(&step, "ProxyCommand"));
    assert!(
        record.exists(),
        "control: the fixture's ProxyCommand is live"
    );
    assert!(!control.ready_seen);
}

/// A known-hosts key change after approval changes the evaluation's key (refused,
/// `route_changed`); the step's trust is only the approved key.
#[cfg(unix)]
#[test]
fn known_host_key_changed_after_approval_refused() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let other = FixtureKey::generate();
    std::fs::write(
        &lab.home.known_hosts,
        format!(
            "[127.0.0.1]:{} {}\n",
            lab.sshd.port,
            other.public_line_without_comment()
        ),
    )
    .unwrap();
    let changed = lab.evaluate();
    assert_eq!(changed.host_keys.len(), 1);
    assert_ne!(
        changed.host_keys[0].approved(),
        approved.host_key,
        "the change is seen"
    );
    // The user's file no longer matters to a step: it trusts the generated file only.
    let report = run(&lab.step(&approved, StageInput::Inspect, None));
    assert_eq!(report.exit_status, 0, "{report:?}");
}

// --- host trust (§17.4 item 1; A R2-01): each refused before any remote mutation --------------

/// Approved key A, the server presents B, and an inherited `KnownHostsCommand` prints
/// B: the pinned `KnownHostsCommand=none` refuses before the script is sent. The
/// control run without that pin shows the fixture would have connected.
#[cfg(unix)]
#[test]
fn wrong_key_with_inherited_known_hosts_command_refused_before_mutation() {
    let lab = fx::Lab::new();
    let wrong = FixtureKey::generate();
    let approved = fx::Lab::with_key(&lab.approve(), &wrong);
    let dir = lab.scratch().subdir("khc").unwrap();
    let (khc, record) = recording_program(&dir, "khc", &wrong_key_line(&lab.sshd.host_key));
    lab.write_config(&format!("Host *\n  KnownHostsCommand {}\n", khc.display()));
    let before = lab.registry_bytes();
    let step = append_step(&lab, &approved);
    let report = run(&step);
    assert_eq!(report.exit_status, 255, "{report:?}");
    assert!(!report.ready_seen && !report.script_sent);
    assert!(
        report
            .stderr_excerpt
            .contains("Host key verification failed"),
        "{report:?}"
    );
    assert_eq!(lab.registry_bytes(), before);
    registry_dir_untouched(&lab);
    assert!(!record.exists(), "the inherited command never ran");
    assert_eq!(
        class_of(&step, &report, &expected_for(&lab, Some(before.clone()))),
        StepClass::HostTrustChanged
    );
    // Control (inspect, read-only): without the pin the command supplies B.
    let control = run(&without_pin(
        &lab.step(&approved, StageInput::Inspect, None),
        "KnownHostsCommand",
    ));
    assert!(record.exists(), "control: the inherited command ran");
    assert_eq!(control.exit_status, 0, "control connects: {control:?}");
}

/// Approved key A, the server presents B, and an inherited user (and, separately, a
/// global) known-hosts file lists B: the generated files are the only ones read.
#[cfg(unix)]
#[test]
fn wrong_key_with_inherited_known_hosts_file_refused_before_mutation() {
    for directive in ["UserKnownHostsFile", "GlobalKnownHostsFile"] {
        let lab = fx::Lab::new();
        let wrong = FixtureKey::generate();
        let approved = fx::Lab::with_key(&lab.approve(), &wrong);
        let file = lab
            .scratch()
            .subdir("kh")
            .unwrap()
            .join("inherited_known_hosts");
        std::fs::write(&file, format!("{}\n", wrong_key_line(&lab.sshd.host_key))).unwrap();
        lab.write_config(&format!("Host *\n  {directive} {}\n", file.display()));
        let before = lab.registry_bytes();
        let step = append_step(&lab, &approved);
        let report = run(&step);
        assert_eq!(report.exit_status, 255, "{directive}: {report:?}");
        assert!(!report.script_sent, "{directive}");
        assert!(
            report
                .stderr_excerpt
                .contains("Host key verification failed")
        );
        assert_eq!(lab.registry_bytes(), before, "{directive}");
        registry_dir_untouched(&lab);
        // Control: without the pin the inherited file trusts B.
        let control = run(&without_pin(
            &lab.step(&approved, StageInput::Inspect, None),
            directive,
        ));
        assert_eq!(control.exit_status, 0, "{directive} control: {control:?}");
    }
}

/// An inherited `NoHostAuthenticationForLocalhost yes` on a loopback destination: the
/// pin (`no`) and the generated `HostKeyAlias` keep host authentication on.
#[cfg(unix)]
#[test]
fn wrong_key_with_inherited_no_host_authentication_for_localhost_refused() {
    let lab = fx::Lab::new();
    let wrong = FixtureKey::generate();
    let approved = fx::Lab::with_key(&lab.approve(), &wrong);
    lab.write_config("Host *\n  NoHostAuthenticationForLocalhost yes\n");
    let before = lab.registry_bytes();
    let step = append_step(&lab, &approved);
    let report = run(&step);
    assert_eq!(report.exit_status, 255, "{report:?}");
    assert!(!report.script_sent);
    assert_eq!(lab.registry_bytes(), before);
    registry_dir_untouched(&lab);
    // Control: without the two pins that cover it, loopback host authentication is off.
    let control = run(&without_pin(
        &without_pin(
            &lab.step(&approved, StageInput::Inspect, None),
            "NoHostAuthenticationForLocalhost",
        ),
        "HostKeyAlias",
    ));
    assert_eq!(control.exit_status, 0, "control connects: {control:?}");
}

/// Q22 (§17.6 item 1): with the approved key, the step connects while a fixture program
/// named `none` on `PATH` (which would print a wrong key) never runs. Recorded for this
/// host's client; the Linux 9.6p1 and Windows rows are the orchestrator's.
#[cfg(unix)]
#[test]
fn known_hosts_command_none_is_a_keyword_per_client() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let dir = lab.scratch().subdir("pathnone").unwrap();
    let (_none, record) = recording_program(&dir, "none", &wrong_key_line(&FixtureKey::generate()));
    lab.write_client(&lab.decoy(), &[&dir], None);
    let step = lab.step(&approved, StageInput::Inspect, None);
    let report = run(&step);
    assert_eq!(report.exit_status, 0, "{report:?}");
    assert!(!record.exists(), "a program named `none` never ran");
    // `ssh -G` treats it as the keyword: no knownhostscommand is printed.
    let g = SshStepRunner::new().effective_config(&step).unwrap();
    assert!(
        !g.lines().any(|l| l.starts_with("knownhostscommand ")),
        "{g}"
    );
    assert!(!record.exists());
    eprintln!(
        "Q22 row: client {} — KnownHostsCommand=none is a keyword (PATH program never ran)",
        fx::client_version(&fx::system_ssh())
    );
}

/// `ssh -G` with exactly the step's pins and alias holds every host-trust pin, even
/// under an adversarial inherited configuration; a missing pin is `host_trust_unpinnable`.
#[cfg(unix)]
#[test]
fn effective_config_has_every_trust_pin() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    lab.write_config(
        "Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  \
         GlobalKnownHostsFile /dev/null\n  CheckHostIP yes\n  UpdateHostKeys yes\n  \
         VerifyHostKeyDNS yes\n  HostKeyAlgorithms +ssh-rsa\n  KnownHostsCommand /bin/true\n  \
         NoHostAuthenticationForLocalhost yes\n  ControlMaster auto\n  ControlPath /tmp/hm-%C\n  \
         ForkAfterAuthentication yes\n  CanonicalizeHostname yes\n",
    );
    let mut step = lab.step(&approved, StageInput::Inspect, None);
    let runner = SshStepRunner::new();
    let mut g = runner.effective_config(&step).unwrap();
    // Q23, the runtime's two passes (wave-1 native run: Ubuntu's 9.6p1 carries the
    // GSSAPI key-exchange patch): a client whose `ssh -G` lists `gssapikeyexchange` is
    // first reported `GssapiPinRequired`, then gets `GSSAPIKeyExchange=no` and is checked
    // again.
    if heimdall_registry::step::client_lists_gssapi_kex(&g) {
        assert!(
            matches!(
                heimdall_registry::step::check_effective(&g, &step.pins),
                Err(heimdall_registry::step::HostTrustUnpinnable {
                    kind: heimdall_registry::step::UnpinnableKind::GssapiPinRequired,
                    ..
                })
            ),
            "{g}"
        );
        step = lab.step_with_gssapi(
            &approved,
            StageInput::Inspect,
            None,
            &lab.agent_sock(),
            false,
            true,
        );
        g = runner.effective_config(&step).unwrap();
    }
    assert_eq!(
        heimdall_registry::step::check_effective(&g, &step.pins),
        Ok(()),
        "{g}"
    );
    for (k, v) in [
        ("stricthostkeychecking", "true"),
        ("checkhostip", "no"),
        ("updatehostkeys", "false"),
        ("verifyhostkeydns", "false"),
        ("hostkeyalgorithms", "ssh-ed25519"),
        ("nohostauthenticationforlocalhost", "no"),
        ("forkafterauthentication", "no"),
        ("canonicalizehostname", "false"),
    ] {
        assert!(g.lines().any(|l| l == format!("{k} {v}")), "{k} {v}: {g}");
    }
    // Without the StrictHostKeyChecking pin the inherited `no` shows, and the check
    // refuses.
    let g2 = runner
        .effective_config(&without_pin(&step, "StrictHostKeyChecking"))
        .unwrap();
    assert!(heimdall_registry::step::check_effective(&g2, &step.pins).is_err());
}

/// Q23 (§17.6 item 2): `GSSAPIKeyExchange=no` is pinned only where the client's `ssh -G`
/// lists the option; this host's client does not, and rejects the option.
#[cfg(unix)]
#[test]
fn gssapi_key_exchange_pinned_off_where_client_knows_it() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let step = lab.step(&approved, StageInput::Inspect, None);
    let runner = SshStepRunner::new();
    let g = runner.effective_config(&step).unwrap();
    let lists = heimdall_registry::step::client_lists_gssapi_kex(&g);
    let version = fx::client_version(&fx::system_ssh());
    eprintln!("Q23 row: client {version} lists gssapikeyexchange: {lists}");
    assert!(
        pin(&step, "GSSAPIKeyExchange").is_none(),
        "not added unless listed"
    );
    if !lists {
        // The client rejects the option: it is recorded as not having it.
        let mut with = step.clone();
        with.pins.host_trust.0.push(SshOption {
            key: "GSSAPIKeyExchange".into(),
            value: "no".into(),
        });
        assert!(matches!(
            runner.effective_config(&with),
            Err(StepRunError::EffectiveConfig(_))
        ));
    } else {
        let mut with = step.clone();
        with.pins.host_trust.0.push(SshOption {
            key: "GSSAPIKeyExchange".into(),
            value: "no".into(),
        });
        let g = runner.effective_config(&with).unwrap();
        assert!(g.lines().any(|l| l == "gssapikeyexchange no"));
    }
}

// --- maintenance invocation (§17.1 item 4, §17.4 item 4; M03-R04, A R2-04) --------------------

/// A Heimdall signer stand-in that **would** authenticate (its key is authorized), at
/// `SSH_AUTH_SOCK`, with P's managed files inherited: the step's pins never reach it.
#[cfg(unix)]
struct SignerDecoy {
    agent: FakeAgent,
    p_file: PathBuf,
}

#[cfg(unix)]
fn signer_decoy(lab: &fx::Lab, with_certificate: bool) -> SignerDecoy {
    let k_env = FixtureKey::generate();
    let agent = FakeAgent::start(
        Endpoint::in_scratch(lab.scratch(), "signer").unwrap(),
        FakeAgentConfig {
            keys: vec![k_env.clone()],
            mode: AgentMode::Normal,
        },
    );
    let dir = lab.scratch().subdir("managed").unwrap();
    let k_pub = dir.join("k_env.pub");
    k_env.write_public(&k_pub).unwrap();
    // The managed key would authenticate: plain in the registry, and (optionally) a
    // certificate under the lab's CA with the pair's principal, its line too.
    let mut registry = String::from_utf8(lab.registry_bytes()).unwrap();
    registry.push_str(&format!(
        "restrict {}\n",
        k_env.public_line_without_comment()
    ));
    let mut cert_line = String::new();
    if with_certificate {
        let principal = heimdall_registry::line::principal(
            &lab.destination,
            &heimdall_contract::ids::AccountName::parse(&fx::me()).unwrap(),
        )
        .unwrap();
        let now = fx::now_secs();
        let cert = fx::issue(&lab.ca, k_env.public(), &principal, now - 60, now + 600);
        let cert_file = dir.join("k_env-cert.pub");
        std::fs::write(&cert_file, format!("{cert}\n")).unwrap();
        registry.push_str(&format!("{}\n", lab.line));
        cert_line = format!("  CertificateFile {}\n", cert_file.display());
    }
    fx::write_mode(&lab.registry, &registry, 0o600);
    // P (the managed block, after the projection switch) comes first in the user file.
    let p_file = dir.join("heimdall.conf");
    std::fs::write(
        &p_file,
        format!(
            "Host {}\n  IdentityAgent {}\n  IdentityFile {}\n{cert_line}  IdentitiesOnly yes\n",
            fx::ALIAS,
            agent.endpoint().locator().to_string_lossy(),
            k_pub.display()
        ),
    )
    .unwrap();
    lab.write_config(&format!("Include {}\n", p_file.display()));
    lab.write_client(&agent.endpoint().locator().to_string_lossy(), &[], None);
    SignerDecoy { agent, p_file }
}

#[cfg(unix)]
fn assert_existing_identity_only(lab: &fx::Lab, decoy: &SignerDecoy, report: &StepReport) {
    assert_eq!(report.exit_status, 0, "{report:?}");
    assert!(report.script_sent);
    assert_eq!(
        decoy.agent.opens(),
        0,
        "the Heimdall endpoint was never opened"
    );
    assert_eq!(decoy.agent.contact_count(), 0);
    let accepted = lab.sshd.accepted();
    assert!(!accepted.is_empty());
    assert!(
        accepted
            .iter()
            .all(|a| a.contains(&lab.existing.fingerprint())),
        "only the existing identity was accepted: {accepted:?}"
    );
    let signs: Vec<_> = lab
        .agent
        .log()
        .into_iter()
        .filter(|c| c.msg_type == msg::SIGN_REQUEST)
        .collect();
    assert!(!signs.is_empty(), "the pinned existing-access agent signed");
    assert!(
        signs
            .iter()
            .all(|c| c.key_fp.as_deref() == Some(lab.existing.fingerprint().as_str()))
    );
    assert!(decoy.p_file.exists());
}

/// The client-level part of `maintenance_invocation_never_contacts_heimdall_signer`:
/// with the step's pins, a decoy signer endpoint at `SSH_AUTH_SOCK` and P's files
/// inherited, the signer records 0 requests. The rotation, removal, rollback and
/// reconcile flows that run these steps are U10's.
#[cfg(unix)]
#[test]
fn maintenance_invocation_never_contacts_heimdall_signer() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let decoy = signer_decoy(&lab, false);
    for stage in [StageInput::Inspect, StageInput::Bootstrap] {
        let report = run(&lab.step(&approved, stage, None));
        assert!(
            report.exit_status == 0 || report.exit_status == 11,
            "{report:?}"
        );
    }
    let report = run(&append_step(&lab, &approved));
    assert_existing_identity_only(&lab, &decoy, &report);
}

/// §17.4 item 4 (A R2-04): maintenance from inside a managed `run` (U11's
/// `managed::ManagedRunContext`: `SSH_AUTH_SOCK` = the binding endpoint, the managed
/// block first in the user file with the environment endpoint, the slot key and its
/// certificate, which **would** authenticate) records zero managed signatures on every
/// Heimdall endpoint.
#[cfg(unix)]
#[test]
fn maintenance_inside_managed_run_context_zero_managed_signatures() {
    use heimdall_testkit::managed::ManagedRunContext;
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let k_env = FixtureKey::generate();
    let endpoint = |name: &str| {
        FakeAgent::start(
            Endpoint::in_scratch(lab.scratch(), name).unwrap(),
            FakeAgentConfig {
                keys: vec![k_env.clone()],
                mode: AgentMode::Normal,
            },
        )
    };
    let (binding, environment) = (endpoint("binding"), endpoint("environment"));
    let principal = heimdall_registry::line::principal(
        &lab.destination,
        &heimdall_contract::ids::AccountName::parse(&fx::me()).unwrap(),
    )
    .unwrap();
    let now = fx::now_secs();
    let cert = fx::issue(&lab.ca, k_env.public(), &principal, now - 60, now + 600);
    // The enrollment is verified: its line trusts the slot certificate.
    let mut text = String::from_utf8(lab.registry_bytes()).unwrap();
    text.push_str(&format!("{}\n", lab.line));
    fx::write_mode(&lab.registry, &text, 0o600);
    let ctx = ManagedRunContext::new(
        &lab.home,
        fx::ALIAS,
        binding.endpoint(),
        environment.endpoint(),
        k_env.public(),
        Some(&cert),
    )
    .unwrap();
    ctx.write_user_config(&lab.home, &lab.config_text(""))
        .unwrap();
    lab.write_client(&ctx.binding_endpoint().to_string_lossy(), &[], None);
    for step in [
        lab.step(&approved, StageInput::Inspect, None),
        lab.step(&approved, StageInput::Bootstrap, None),
    ] {
        let report = run(&step);
        assert!(
            report.exit_status == 0 || report.exit_status == 11,
            "{report:?}"
        );
        assert!(report.script_sent);
    }
    for agent in [&binding, &environment] {
        assert_eq!(agent.opens(), 0, "a Heimdall endpoint was opened");
        assert_eq!(agent.contact_count(), 0);
    }
    let accepted = lab.sshd.accepted();
    assert!(!accepted.is_empty());
    assert!(
        accepted
            .iter()
            .all(|a| a.contains(&lab.existing.fingerprint())),
        "only the existing identity: {accepted:?}"
    );
    assert!(!accepted.iter().any(|a| a.starts_with("ED25519-CERT")));
}

/// §17.4 item 4, Q24: the endpoint is the catalog's, or the alias's own
/// `IdentityAgent` with P excluded, and never `SSH_AUTH_SOCK`; the step pins it, so a
/// decoy at `SSH_AUTH_SOCK` holding the same key is never contacted.
#[cfg(unix)]
#[test]
fn existing_access_endpoint_from_catalog_never_ssh_auth_sock() {
    use heimdall_contract::provider::EndpointKind;
    use heimdall_localenv::target::{IdentityAgentEvaluation, identity_agent_reason};
    let lab = fx::Lab::new();
    let e = lab.evaluator();
    // The alias's own IdentityAgent.
    match e.evaluate_identity_agent(fx::ALIAS, true) {
        IdentityAgentEvaluation::Determined(ep) => {
            assert_eq!(ep.kind, EndpointKind::UnixSocket);
            assert_eq!(ep.locator, lab.agent_sock());
        }
        other => panic!("{other:?}"),
    }
    // SSH_AUTH_SOCK in the configuration, or nothing at all: never the environment's.
    lab.write_config("Host other-sock\n  IdentityAgent SSH_AUTH_SOCK\n");
    assert_eq!(
        e.evaluate_identity_agent("other-sock", true),
        IdentityAgentEvaluation::Undetermined {
            reason: identity_agent_reason::SSH_AUTH_SOCK
        }
    );
    assert_eq!(
        e.evaluate_identity_agent("unconfigured", true),
        IdentityAgentEvaluation::Unset
    );
    // A decoy at SSH_AUTH_SOCK that holds the very same key: never contacted.
    let same = FakeAgent::start(
        Endpoint::in_scratch(lab.scratch(), "same").unwrap(),
        FakeAgentConfig {
            keys: vec![lab.existing.clone()],
            mode: AgentMode::Normal,
        },
    );
    lab.write_config("Host *\n  IdentityAgent SSH_AUTH_SOCK\n");
    lab.write_client(&same.endpoint().locator().to_string_lossy(), &[], None);
    let approved = lab.approve();
    let step = lab.step(&approved, StageInput::Inspect, None);
    assert_eq!(pin(&step, "IdentityAgent").unwrap(), lab.agent_sock());
    let report = run(&step);
    assert_eq!(report.exit_status, 0, "{report:?}");
    assert_eq!(same.opens(), 0, "SSH_AUTH_SOCK was never used");
}

/// A Heimdall endpoint is refused as existing access: the evaluator resolves the
/// alias's endpoint and its links, so a symlink into Heimdall's runtime directory is
/// seen for what it is; the step builder refuses `SSH_AUTH_SOCK` and `none`. (The plan
/// refusal `existing_access_endpoint_is_heimdall` is U5-pure's `plan::build`.)
#[cfg(unix)]
#[test]
fn heimdall_endpoint_refused_as_existing_access() {
    use heimdall_localenv::target::IdentityAgentEvaluation;
    let lab = fx::Lab::new();
    let runtime = lab.scratch().subdir("rt").unwrap();
    let signer = FakeAgent::start(
        Endpoint::UnixSocket(runtime.join("env.sock")),
        FakeAgentConfig {
            keys: Vec::new(),
            mode: AgentMode::Normal,
        },
    );
    let link = lab.scratch().subdir("lk").unwrap().join("agent.sock");
    std::os::unix::fs::symlink(runtime.join("env.sock"), &link).unwrap();
    lab.write_config(&format!(
        "Host {}\n  IdentityAgent {}\n",
        fx::ALIAS,
        link.display()
    ));
    let e = lab.evaluator();
    let IdentityAgentEvaluation::Determined(ep) = e.evaluate_identity_agent(fx::ALIAS, true) else {
        panic!("determined");
    };
    let check = e.check_endpoint(&ep);
    let resolved = PathBuf::from(check.resolved.expect("resolved"));
    assert!(
        resolved.starts_with(std::fs::canonicalize(&runtime).unwrap()),
        "{resolved:?} resolves into the runtime directory"
    );
    for refused in ["SSH_AUTH_SOCK", "none", "$SSH_AUTH_SOCK"] {
        assert!(
            heimdall_registry::step::access_pins(refused, "/k.pub").is_err(),
            "{refused}"
        );
    }
    assert_eq!(signer.opens(), 0, "nothing connected");
}

/// The approved endpoint is re-validated before a step: a stopped agent or a path that
/// now resolves elsewhere is a change (`existing_access_changed`, U10 refuses the step);
/// a step run anyway fails closed before any script.
#[cfg(unix)]
#[test]
fn existing_access_endpoint_change_refuses_step() {
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_localenv::agents::Presence;
    let mut lab = fx::Lab::new();
    let approved = lab.approve();
    let e = lab.evaluator();
    let ep = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: lab.agent_sock(),
    };
    let first = e.check_endpoint(&ep);
    assert_eq!(first.presence, Presence::Present);
    lab.agent.stop();
    let gone = e.check_endpoint(&ep);
    assert_ne!(gone, first, "the change is detected");
    assert_eq!(gone.presence, Presence::Absent);
    let before = lab.registry_bytes();
    let report = run(&append_step(&lab, &approved));
    assert_ne!(report.exit_status, 0);
    assert!(!report.script_sent, "{report:?}");
    assert_eq!(lab.registry_bytes(), before);
}

/// §17.3 item 2: what `CertificateFile=none` does on this client, with an inherited
/// managed `CertificateFile`: recorded from `ssh -G`, and the step never offers the
/// managed certificate to the signer (zero contacts).
#[cfg(unix)]
#[test]
fn certificate_file_none_behaviour_recorded_per_client() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let decoy = signer_decoy(&lab, true);
    let step = lab.step(&approved, StageInput::Inspect, None);
    let g = SshStepRunner::new().effective_config(&step).unwrap();
    let files: Vec<&str> = g
        .lines()
        .filter_map(|l| l.strip_prefix("certificatefile "))
        .collect();
    eprintln!(
        "§17.3 item 2 row: client {} — ssh -G certificatefile entries with the pin and an inherited managed file: {:?}",
        fx::client_version(&fx::system_ssh()),
        files
            .iter()
            .map(|f| if f.ends_with("k_env-cert.pub") {
                "<managed>"
            } else {
                f
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(files.first().copied(), Some("none"), "the pin is first");
    let report = run(&step);
    assert_existing_identity_only(&lab, &decoy, &report);
}

/// After the projection switch, P selects the managed agent, key and certificate; the
/// step's existing-identity pin is still the one used.
#[cfg(unix)]
#[test]
fn existing_identity_pin_used_after_projection_switch() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let decoy = signer_decoy(&lab, true);
    // The ordinary alias would now use the managed identity (P is first).
    use heimdall_localenv::target::IdentityAgentEvaluation;
    let e = lab.evaluator().with_managed_file(decoy.p_file.clone());
    assert!(matches!(
        e.evaluate_identity_agent(fx::ALIAS, false),
        IdentityAgentEvaluation::Determined(ref ep) if ep.locator == decoy.agent.endpoint().locator().to_string_lossy()
    ));
    // The enrollment is verified (its line is present): the steps after the switch are
    // inspect and remove-side reads; the existing identity pin is the one used.
    let report = run(&lab.step(&approved, StageInput::Inspect, None));
    assert_existing_identity_only(&lab, &decoy, &report);
    assert_eq!(fx::hm1_values(&report.stdout, "marker_lines"), ["1"]);
}

// --- negative ---------------------------------------------------------------------------------

/// A host-key mismatch is `HostTrustChanged`, and nothing is written.
#[cfg(unix)]
#[test]
fn host_key_mismatch_is_host_trust_changed_nothing_written() {
    let lab = fx::Lab::new();
    let approved = fx::Lab::with_key(&lab.approve(), &FixtureKey::generate());
    let before = lab.registry_bytes();
    let user_kh = std::fs::read(&lab.home.known_hosts).unwrap();
    let step = append_step(&lab, &approved);
    let report = run(&step);
    assert_eq!(report.exit_status, 255);
    assert!(
        report
            .stderr_excerpt
            .contains("Host key verification failed"),
        "{report:?}"
    );
    assert!(!report.script_sent);
    assert_eq!(lab.registry_bytes(), before);
    registry_dir_untouched(&lab);
    assert_eq!(std::fs::read(&lab.home.known_hosts).unwrap(), user_kh);
    assert_eq!(
        class_of(&step, &report, &expected_for(&lab, Some(before))),
        StepClass::HostTrustChanged
    );
}

/// An inherited `StrictHostKeyChecking accept-new` (or `no`) is overridden: an unknown
/// or changed key is refused and nothing is added to any known-hosts file.
#[cfg(unix)]
#[test]
fn strict_host_key_checking_overrides_user_accept_new() {
    for inherited in ["accept-new", "no"] {
        let lab = fx::Lab::new();
        let approved = fx::Lab::with_key(&lab.approve(), &FixtureKey::generate());
        lab.write_config(&format!("Host *\n  StrictHostKeyChecking {inherited}\n"));
        let step = append_step(&lab, &approved);
        let generated = PathBuf::from(pin(&step, "UserKnownHostsFile").unwrap());
        let gen_before = std::fs::read(&generated).unwrap();
        let user_before = std::fs::read(&lab.home.known_hosts).unwrap();
        let before = lab.registry_bytes();
        let report = run(&step);
        assert_eq!(report.exit_status, 255, "{inherited}: {report:?}");
        assert!(!report.script_sent);
        assert_eq!(lab.registry_bytes(), before);
        assert_eq!(
            std::fs::read(&generated).unwrap(),
            gen_before,
            "nothing added"
        );
        assert_eq!(std::fs::read(&lab.home.known_hosts).unwrap(), user_before);
    }
    // Control: an unknown key with the inherited accept-new and no pin is added.
    let lab = fx::Lab::new();
    let approved = lab.approve();
    lab.write_config("Host *\n  StrictHostKeyChecking accept-new\n");
    let step = lab.step(&approved, StageInput::Inspect, None);
    let generated = PathBuf::from(pin(&step, "UserKnownHostsFile").unwrap());
    std::fs::write(&generated, "").unwrap();
    let control = run(&without_pin(&step, "StrictHostKeyChecking"));
    assert_eq!(control.exit_status, 0, "{control:?}");
    assert!(
        !std::fs::read(&generated).unwrap().is_empty(),
        "control: accept-new adds"
    );
}

// --- the runner: ready handshake and lifetime (§17.4 item 2; B R2-04) -------------------------

#[cfg(unix)]
const CHILD_STEP: &str = "HM_U5IO_CHILD_STEP";

/// A step as a text file the child CLI reads (one value per line; all pins in order).
#[cfg(unix)]
fn write_child_step(dir: &Path, step: &RemoteStep) -> PathBuf {
    let script = dir.join("script.sh");
    std::fs::write(&script, &step.script).unwrap();
    let mut text = format!(
        "client {}\nalias {}\ntimeout {}\nscript {}\n",
        step.client,
        step.alias,
        step.timeout_ms,
        script.display()
    );
    for o in step
        .pins
        .target
        .0
        .iter()
        .chain(&step.pins.host_trust.0)
        .chain(&step.pins.existing_access.0)
        .chain(&step.pins.narrowing.0)
    {
        text.push_str(&format!("pin {}={}\n", o.key, o.value));
    }
    let path = dir.join("step.txt");
    std::fs::write(&path, text).unwrap();
    path
}

/// Child-process body (the "CLI") for the runner lifetime tests; a no-op in a normal
/// run.
#[test]
fn cli_child_entry() {
    #[cfg(unix)]
    {
        use heimdall_contract::enrollment::{RemoteStage, StepPins, TargetPins};
        let Ok(path) = std::env::var(CHILD_STEP) else {
            return;
        };
        let text = std::fs::read_to_string(path).unwrap();
        let mut step = RemoteStep {
            stage: RemoteStage::Append,
            step_token: "0".repeat(32),
            client: String::new(),
            pins: StepPins {
                target: TargetPins(Vec::new()),
                ..StepPins::default()
            },
            alias: String::new(),
            remote_command: heimdall_enroll::remote::STEP_REMOTE_COMMAND.into(),
            script: String::new(),
            timeout_ms: 0,
            hard_deadline_ms: 1,
            not_after_remote: None,
        };
        for line in text.lines() {
            let (k, v) = line.split_once(' ').unwrap();
            match k {
                "client" => step.client = v.into(),
                "alias" => step.alias = v.into(),
                "timeout" => step.timeout_ms = v.parse().unwrap(),
                "script" => step.script = std::fs::read_to_string(v).unwrap(),
                "pin" => {
                    let (key, value) = v.split_once('=').unwrap();
                    step.pins.target.0.push(SshOption {
                        key: key.into(),
                        value: value.into(),
                    });
                }
                _ => panic!("{k}"),
            }
        }
        let _ = SshStepRunner::new().run(&step, TtyMode::Batch);
        std::process::exit(7);
    }
}

#[cfg(unix)]
fn spawn_cli_child(step_file: &Path) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "cli_child_entry",
            "--exact",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_STEP, step_file)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

#[cfg(unix)]
fn wait_for(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    pred()
}

#[cfg(unix)]
fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The CLI is killed (SIGKILL) while ssh waits on a provider approval, before `HM1
/// ready`: when the approval is released later, the script is never delivered, nothing
/// is written, and ssh ends.
#[cfg(unix)]
#[test]
fn cli_killed_before_ready_never_sends_script() {
    let lab = fx::Lab::with_agent_mode(AgentMode::ApprovalPending);
    let approved = lab.approve();
    let pid_file = lab.scratch().path().join("ssh.pid");
    lab.write_client(&lab.decoy(), &[], Some(&pid_file));
    let step = append_step(&lab, &approved);
    let before = lab.registry_bytes();
    let dir = lab.scratch().subdir("child").unwrap();
    let mut cli = spawn_cli_child(&write_child_step(&dir, &step));
    assert!(
        wait_for(Duration::from_secs(30), || lab
            .agent
            .log()
            .iter()
            .any(|c| c.msg_type == msg::SIGN_REQUEST)),
        "ssh reached the pending approval"
    );
    let ssh_pid = read_pid(&pid_file).expect("ssh's pid");
    cli.kill().unwrap();
    let _ = cli.wait();
    lab.agent.release_pending();
    assert!(
        wait_for(Duration::from_secs(30), || !fx::pid_alive(ssh_pid)),
        "ssh ended after the CLI's death"
    );
    assert_eq!(lab.registry_bytes(), before, "no script was delivered");
    registry_dir_untouched(&lab);
}

/// ssh's lifetime is tied to the CLI's. Unix: its own process group, killed on abort
/// (the CLI's signal hook) and on drop. With the CLI killed by SIGKILL: on Linux
/// `PR_SET_PDEATHSIG(SIGKILL)` ends ssh at once, while the agent still holds its
/// request (ADR-0008 §17.17 item 5, the Linux-native regression); on macOS, which has
/// no parent-death signal, the ready handshake ends it once the agent answers.
#[cfg(unix)]
#[test]
fn cli_death_ends_ssh_step_process() {
    // In-process: the abort hook kills the group at once, while ssh is still waiting.
    let lab = fx::Lab::with_agent_mode(AgentMode::ApprovalPending);
    let approved = lab.approve();
    let pid_file = lab.scratch().path().join("ssh.pid");
    lab.write_client(&lab.decoy(), &[], Some(&pid_file));
    let step = append_step(&lab, &approved);
    let runner = SshStepRunner::new();
    let abort = runner.abort_handle();
    let before = lab.registry_bytes();
    let report = std::thread::scope(|s| {
        let h = s.spawn(|| runner.run(&step, TtyMode::Batch));
        assert!(wait_for(Duration::from_secs(30), || read_pid(&pid_file).is_some()));
        assert!(wait_for(Duration::from_secs(30), || lab
            .agent
            .log()
            .iter()
            .any(|c| c.msg_type == msg::SIGN_REQUEST)));
        abort.abort();
        h.join().unwrap().unwrap()
    });
    assert_eq!(report.ended, StepEnd::Killed(KillCause::Aborted));
    assert_eq!(report.exit_status, KILLED_EXIT_STATUS);
    assert!(!report.script_sent);
    assert!(
        !fx::pid_alive(read_pid(&pid_file).unwrap()),
        "the group was killed"
    );
    assert!(report.lifetime.process_group);
    assert_eq!(
        report.lifetime.parent_death_signal,
        heimdall_enroll::remote::PARENT_DEATH_SIGNAL_APPLIED
    );
    // The CLI killed by SIGKILL: ssh ends through the handshake (stdin and stdout gone).
    let _ = std::fs::remove_file(&pid_file);
    let lab2 = fx::Lab::with_agent_mode(AgentMode::ApprovalPending);
    let approved2 = lab2.approve();
    lab2.write_client(&lab2.decoy(), &[], Some(&pid_file));
    let step2 = append_step(&lab2, &approved2);
    let dir = lab2.scratch().subdir("child").unwrap();
    let mut cli = spawn_cli_child(&write_child_step(&dir, &step2));
    assert!(wait_for(Duration::from_secs(30), || lab2
        .agent
        .log()
        .iter()
        .any(|c| c.msg_type == msg::SIGN_REQUEST)));
    let ssh_pid = read_pid(&pid_file).unwrap();
    cli.kill().unwrap();
    let _ = cli.wait();
    // ADR-0008 §17.17 item 5: on Linux the parent-death signal ends ssh while it still
    // waits for the agent, before any handshake could.
    #[cfg(target_os = "linux")]
    assert!(
        wait_for(Duration::from_secs(10), || !fx::pid_alive(ssh_pid)),
        "PR_SET_PDEATHSIG ended ssh while the agent still held its request"
    );
    lab2.agent.release_pending();
    assert!(wait_for(Duration::from_secs(30), || !fx::pid_alive(
        ssh_pid
    )));
    assert_eq!(lab.registry_bytes(), before);
}

/// Windows: the kill-on-close job is the CLI's (`heimdall_localenv::sys::JobObject`);
/// a runner without it refuses, and with it the contained client ends with the job.
#[cfg(windows)]
#[test]
fn cli_death_ends_ssh_step_process() {
    use heimdall_contract::enrollment::{
        NarrowingPins, RemoteStage, RemoteStep, SshOption, StepPins,
    };
    use heimdall_enroll::remote::{Contained, StepContainment};
    struct Job;
    impl StepContainment for Job {
        fn spawn_contained(
            &self,
            command: &mut std::process::Command,
        ) -> std::io::Result<Contained> {
            let job = heimdall_localenv::sys::JobObject::kill_on_close()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let child = command.spawn()?;
            job.assign_child(&child)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(Contained {
                child,
                guard: Box::new(job),
            })
        }
        fn ends_with_parent(&self) -> bool {
            true
        }
    }
    let ssh = std::path::PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe");
    // A loopback port with no listener: the client is refused at once (no server).
    let port = heimdall_testkit::sshd::pick_loopback_port()
        .unwrap()
        .to_string();
    let opt = |k: &str, v: &str| SshOption {
        key: k.into(),
        value: v.into(),
    };
    let step = RemoteStep {
        stage: RemoteStage::Inspect,
        step_token: "0".repeat(32),
        client: ssh.display().to_string(),
        pins: StepPins {
            narrowing: NarrowingPins(vec![
                opt("HostName", "127.0.0.1"),
                opt("Port", &port),
                opt("BatchMode", "yes"),
                opt("ConnectTimeout", "2"),
            ]),
            ..StepPins::default()
        },
        alias: "hm-test".into(),
        remote_command: heimdall_enroll::remote::STEP_REMOTE_COMMAND.into(),
        script: "hm_main\n".into(),
        timeout_ms: 5_000,
        hard_deadline_ms: 5_000,
        not_after_remote: None,
    };
    assert_eq!(
        SshStepRunner::new().run(&step, TtyMode::Batch),
        Err(StepRunError::ContainmentUnavailable)
    );
    let report = SshStepRunner::new()
        .with_containment(Box::new(Job))
        .run(&step, TtyMode::Batch)
        .unwrap();
    assert!(report.lifetime.contained);
    assert!(!report.script_sent);
}

// --- lost response (the runner + classification part; the reconcile driver is U10's) ---------

/// The append's script with a pause after `hm_main` returns: the write is done and its
/// output printed, but the run does not end (so the CLI can lose the reply).
#[cfg(unix)]
fn linger_after_main(step: &RemoteStep) -> RemoteStep {
    let mut s = step.clone();
    assert!(s.script.ends_with("\nhm_main\n"));
    s.script.truncate(s.script.len() - "hm_main\n".len());
    // `hm_main` exits with its code; in a subshell it returns, and the shell lingers.
    s.script.push_str("(hm_main); sleep 30\n");
    s
}

#[cfg(unix)]
fn marker_lines(lab: &fx::Lab) -> usize {
    String::from_utf8(lab.registry_bytes())
        .unwrap()
        .lines()
        .filter(|l| l.contains(heimdall_registry::line::marker_of(&lab.line).unwrap()))
        .count()
}

/// ssh is killed after the append wrote: the report is a killed run with the script
/// sent, which classifies `Uncertain`; the reconcile's inspect then shows exactly one
/// exact line (applied).
#[cfg(unix)]
#[test]
fn ssh_killed_after_append_is_uncertain_then_reconciled_applied() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let before = lab.registry_bytes();
    let step = linger_after_main(&append_step(&lab, &approved));
    let runner = SshStepRunner::new();
    let abort = runner.abort_handle();
    let report = std::thread::scope(|s| {
        let h = s.spawn(|| runner.run(&step, TtyMode::Batch));
        assert!(wait_for(Duration::from_secs(30), || marker_lines(&lab) == 1));
        std::thread::sleep(Duration::from_millis(200));
        abort.abort();
        h.join().unwrap().unwrap()
    });
    assert_eq!(report.ended, StepEnd::Killed(KillCause::Aborted));
    assert!(report.script_sent);
    assert_eq!(
        class_of(&step, &report, &expected_for(&lab, Some(before))),
        StepClass::Uncertain
    );
    // Reconcile's inspect: exactly one exact line.
    let inspect = run(&lab.step(&approved, StageInput::Inspect, None));
    assert_eq!(inspect.exit_status, 0);
    assert_eq!(fx::hm1_values(&inspect.stdout, "marker_lines"), ["1"]);
    assert_eq!(marker_lines(&lab), 1);
}

/// ssh is killed before the ready line: no script was sent, `NotApplied` for every
/// stage; the reconcile's inspect shows the marker absent.
#[cfg(unix)]
#[test]
fn ssh_killed_before_append_reconciled_not_applied() {
    let lab = fx::Lab::with_agent_mode(AgentMode::ApprovalPending);
    let approved = lab.approve();
    let before = lab.registry_bytes();
    let step = append_step(&lab, &approved);
    let runner = SshStepRunner::new();
    let abort = runner.abort_handle();
    let report = std::thread::scope(|s| {
        let h = s.spawn(|| runner.run(&step, TtyMode::Batch));
        assert!(wait_for(Duration::from_secs(30), || lab
            .agent
            .log()
            .iter()
            .any(|c| c.msg_type == msg::SIGN_REQUEST)));
        abort.abort();
        h.join().unwrap().unwrap()
    });
    lab.agent.release_pending();
    assert!(!report.script_sent && !report.ready_seen);
    assert_eq!(
        class_of(&step, &report, &expected_for(&lab, Some(before.clone()))),
        StepClass::NotApplied(NotAppliedReason::Refused)
    );
    assert_eq!(lab.registry_bytes(), before);
    assert_eq!(marker_lines(&lab), 0);
}

/// After an uncertain append the destination is unreachable: the reconcile's inspect
/// learns nothing (no ready line), so the outcome stays unknown.
#[cfg(unix)]
#[test]
fn unreachable_after_append_stays_unknown() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let step = linger_after_main(&append_step(&lab, &approved));
    let runner = SshStepRunner::new();
    let abort = runner.abort_handle();
    let report = std::thread::scope(|s| {
        let h = s.spawn(|| runner.run(&step, TtyMode::Batch));
        assert!(wait_for(Duration::from_secs(30), || marker_lines(&lab) == 1));
        abort.abort();
        h.join().unwrap().unwrap()
    });
    assert!(report.script_sent);
    lab.sshd.stop();
    let inspect_step = lab.step(&approved, StageInput::Inspect, None);
    let inspect = run(&inspect_step);
    assert_eq!(inspect.exit_status, 255);
    assert!(!inspect.ready_seen);
    assert_eq!(
        class_of(&inspect_step, &inspect, &expected_for(&lab, None)),
        StepClass::NotApplied(NotAppliedReason::Refused)
    );
    assert!(
        heimdall_registry::hm1::parse(inspect.stdout.as_bytes()).is_err(),
        "nothing learned"
    );
}

/// A retry of an append whose reply was lost never appends twice: once the lost run's
/// script has finished (its lock released), the retry finds its marker (exit 10,
/// already present). (A run killed while its lock is still held leaves a `busy` lock,
/// exit 40, until reconcile's fence proves the holder gone: U10's driver.)
#[cfg(unix)]
#[test]
fn retry_after_lost_reply_never_appends_twice() {
    let lab = fx::Lab::new();
    let approved = lab.approve();
    let before = lab.registry_bytes();
    let step = linger_after_main(&append_step(&lab, &approved));
    let runner = SshStepRunner::new();
    let abort = runner.abort_handle();
    let lock_free = || {
        std::fs::read_dir(lab.registry.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .all(|e| !e.file_name().to_string_lossy().starts_with(".hm-lock."))
    };
    let lost = std::thread::scope(|s| {
        let h = s.spawn(|| runner.run(&step, TtyMode::Batch));
        assert!(wait_for(Duration::from_secs(30), || marker_lines(&lab)
            == 1
            && lock_free()));
        abort.abort();
        h.join().unwrap().unwrap()
    });
    assert_eq!(
        lost.ended,
        StepEnd::Killed(KillCause::Aborted),
        "the reply was lost"
    );
    let retry_step = append_step(&lab, &approved);
    let retry = run(&retry_step);
    assert_eq!(retry.exit_status, 10, "{retry:?}");
    assert_eq!(
        class_of(&retry_step, &retry, &expected_for(&lab, Some(before))),
        StepClass::AlreadyPresent
    );
    assert_eq!(marker_lines(&lab), 1);
}

// --- verification (ADR-0008 D5 §6.5) ----------------------------------------------------------

#[cfg(unix)]
use heimdall_domain::verification::{InconclusiveReason, VerificationVerdict};
#[cfg(unix)]
use heimdall_enroll::verify::{
    AttemptEnd, KnownOffset, LogAttestation, VerifierReport, classify_evidence,
};

#[cfg(unix)]
fn verdict(r: &VerifierReport, offset: Option<KnownOffset>) -> VerificationVerdict {
    let limits = heimdall_app::operations::Limits::default();
    classify_evidence(
        r,
        offset,
        u64::try_from(limits.verification_skew_lag.as_millis()).unwrap(),
        u64::try_from(limits.verification_skew_lead.as_millis()).unwrap(),
    )
}

#[cfg(unix)]
fn assert_positive_passed(r: &VerifierReport) {
    let p = &r.positive.result;
    assert_eq!(p.exit_status, Some(0), "{r:?}");
    assert_eq!(p.signatures, 1, "exactly one signature: {r:?}");
    assert!(
        p.trace
            .server_version
            .as_deref()
            .is_some_and(|v| v.starts_with("OpenSSH_"))
    );
    assert!(
        p.trace.host_key_matched && p.trace.offered_certificate && p.trace.accepted,
        "{r:?}"
    );
    assert!(p.remote_now.is_some());
}

#[cfg(unix)]
fn assert_negative_refused(r: &VerifierReport) {
    let n = &r.negative.result;
    assert_ne!(n.exit_status, Some(0), "{r:?}");
    assert_eq!(n.signatures, 0, "{r:?}");
    let t = &n.trace;
    assert!(
        t.server_version.is_some() && t.host_key_matched && t.offered_certificate,
        "{r:?}"
    );
    assert!(
        t.not_accepted && t.publickey_failure_final && !t.accepted,
        "{r:?}"
    );
}

#[cfg(unix)]
fn assert_negative_transport(r: &VerifierReport) {
    let n = &r.negative.result;
    assert_ne!(n.exit_status, Some(0), "{r:?}");
    assert_eq!(n.signatures, 0);
    assert!(
        !n.trace.publickey_failure_final,
        "a transport failure is never a refusal: {r:?}"
    );
    assert_eq!(
        verdict(r, None),
        VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::Transport
        }
    );
}

#[cfg(unix)]
fn transition(
    from: heimdall_contract::enrollment::EnrollmentState,
    kind: heimdall_domain::enrollment::EnrollmentEventKind,
) -> heimdall_contract::enrollment::EnrollmentState {
    use heimdall_contract::enrollment::EnrollmentForm;
    use heimdall_domain::enrollment::{EnrollmentEvent, RecordFacts};
    heimdall_domain::enrollment::transition(
        from,
        EnrollmentEvent {
            record: RecordFacts {
                form: EnrollmentForm::Account,
                foreign: false,
            },
            kind,
        },
    )
    .unwrap()
}

/// M-F1: the positive passes with exactly one signature on the verification endpoint
/// and the negative is refused with zero, with full refusal evidence in the trace. Per
/// client: this host's row (the Linux and Windows rows are native runs).
#[cfg(unix)]
#[test]
fn verify_positive_one_signature_negative_zero() {
    let v = fx::VerifyLab::new();
    // Wave-1 native run, item C: on a client with no recorded trace row, print the facts
    // the row needs from this (the ordinary positive and negative) lab, then fail below.
    let version = fx::client_version(&fx::system_ssh());
    if heimdall_enroll::trace::patterns_for(version.family, version).is_err() {
        v.observe_unrecorded_trace(version);
    }
    let r = v.run();
    assert_eq!(r.refused, None);
    assert_eq!(r.unrecorded, None);
    assert_positive_passed(&r);
    assert_negative_refused(&r);
    assert_eq!(verdict(&r, None), VerificationVerdict::Passed);
    assert_eq!(v.session.installs(), 2);
    assert!(r.clock.is_some());
    assert!(
        r.outcome
            .client
            .as_deref()
            .is_some_and(|c| c.contains("portable"))
    );
    eprintln!(
        "M-F1 row: client {} — positive 1 signature, negative 0, session-binds {}",
        fx::client_version(&fx::system_ssh()),
        r.session_binds
    );
    v.assert_no_generated_files();
    // The server accepted exactly the positive certificate (log oracle, test-only).
    let accepted = v.lab.sshd.accepted();
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0].starts_with("ED25519-CERT ") && accepted[0].contains(v.session.fingerprint())
    );
}

/// The negative attempt records zero signatures on the endpoint, also for the plain
/// K_verify the client offers after the refused certificate.
#[cfg(unix)]
#[test]
fn verify_negative_records_zero_signatures() {
    let v = fx::VerifyLab::new();
    let r = v.run();
    assert_eq!(r.negative.result.signatures, 0);
    assert_eq!(r.positive.result.signatures, 1);
    assert_eq!(r.negative.end, AttemptEnd::Exited);
    let log = v.lab.sshd.log_text();
    assert!(
        log.contains("Failed publickey for "),
        "the server refused the negative"
    );
}

/// An unrecorded client runs no attempt: inconclusive, and it names itself.
#[cfg(unix)]
#[test]
fn verify_unrecorded_client_trace_is_inconclusive() {
    let v = fx::VerifyLab::new();
    let unrecorded = heimdall_enroll::verify::Verifier::with_client(
        heimdall_enroll::verify::VerifierClient {
            path: fx::system_ssh(),
            version: ClientVersion::parse("OpenSSH_9.7p1 Ubuntu-3ubuntu13.5").unwrap(),
        },
        &v.runtime,
    );
    assert!(!unrecorded.available());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let r = rt.block_on(unrecorded.run_detailed(&v.plan, &v.positive, &v.negative, &v.session));
    let u = r.unrecorded.expect("unrecorded");
    assert_eq!(u.detail(), "portable 9.7p1");
    assert_eq!(r.positive.end, AttemptEnd::NotStarted);
    assert_eq!(v.session.installs(), 0);
    assert!(v.lab.sshd.accepted().is_empty() && !v.lab.sshd.log_text().contains("Connection from"));
    assert_eq!(
        verdict(&r, None),
        VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::UnrecordedClientFamily
        }
    );
    // The domain classification over the port's outcome (§17.17 item 14) agrees.
    assert!(r.outcome.unrecorded);
    assert_eq!(
        heimdall_domain::verification::classify(
            &r.outcome.positive,
            &r.outcome.negative,
            heimdall_domain::verification::VerificationPhase::Initial,
            heimdall_contract::enrollment::EnrollmentForm::Account,
            &heimdall_domain::verification::ClassifyContext {
                unrecorded: r.outcome.unrecorded,
                ..heimdall_domain::verification::ClassifyContext::recorded()
            },
        ),
        VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::UnrecordedClientFamily
        }
    );
}

/// Fault injection point: between the attempts (the negative certificate's install,
/// which runs just before the negative attempt starts).
#[cfg(unix)]
fn between_attempts(v: &fx::VerifyLab, fault: impl FnOnce() + Send + 'static) {
    let mut fault = Some(fault);
    v.session.on_install(move |index, _| {
        if index == 1
            && let Some(f) = fault.take()
        {
            f();
        }
    });
}

#[cfg(unix)]
#[test]
fn verify_negative_inconclusive_when_sshd_stopped_between_attempts() {
    let v = fx::VerifyLab::new();
    between_attempts(&v, v.lab.sshd.stopper());
    let r = v.run();
    assert_positive_passed(&r);
    assert_negative_transport(&r);
    assert!(
        r.negative.result.trace.server_version.is_none(),
        "connection refused"
    );
    v.assert_no_generated_files();
}

/// The port closes between the attempts: a listener on it accepts and closes at once.
#[cfg(unix)]
#[test]
fn verify_negative_inconclusive_when_port_closed_between_attempts() {
    let v = fx::VerifyLab::new();
    let port = v.lab.sshd.port;
    let stop = v.lab.sshd.stopper();
    let held: std::sync::Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>> =
        std::sync::Arc::default();
    let h2 = std::sync::Arc::clone(&held);
    between_attempts(&v, move || {
        stop();
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        h2.lock().unwrap().push(std::thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                drop(conn);
            }
        }));
    });
    let r = v.run();
    assert_positive_passed(&r);
    assert_negative_transport(&r);
    for h in held.lock().unwrap().drain(..) {
        let _ = h.join();
    }
}

/// `MaxStartups 1:100:1` with a held unauthenticated connection, opened between the
/// attempts: the negative's connection is dropped.
#[cfg(unix)]
#[test]
fn verify_negative_inconclusive_on_maxstartups_between_attempts() {
    let v = fx::VerifyLab::with(fx::Lab::with_sshd_extra("MaxStartups 1:100:1\n"), true);
    let port = v.lab.sshd.port;
    let held: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>> =
        std::sync::Arc::default();
    let h2 = std::sync::Arc::clone(&held);
    between_attempts(&v, move || {
        let c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        // Let sshd count it as a pending startup before the negative connects.
        std::thread::sleep(Duration::from_millis(300));
        h2.lock().unwrap().push(c);
    });
    let r = v.run();
    assert_positive_passed(&r);
    assert_negative_transport(&r);
    drop(held);
}

/// `MaxStartups` during the negative: held unauthenticated connections are opened
/// while the negative starts (a burst racing it), so the negative is dropped.
#[cfg(unix)]
#[test]
fn verify_negative_inconclusive_on_maxstartups_during_negative() {
    let v = fx::VerifyLab::with(fx::Lab::with_sshd_extra("MaxStartups 1:100:1\n"), true);
    let port = v.lab.sshd.port;
    let held: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>> =
        std::sync::Arc::default();
    let h2 = std::sync::Arc::clone(&held);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = std::sync::Arc::clone(&done);
    let burst: std::sync::Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> =
        std::sync::Arc::default();
    let b2 = std::sync::Arc::clone(&burst);
    between_attempts(&v, move || {
        // The first held connection exists before the negative connects; the burst keeps
        // the server at its limit for the whole attempt.
        h2.lock()
            .unwrap()
            .push(std::net::TcpStream::connect(("127.0.0.1", port)).unwrap());
        std::thread::sleep(Duration::from_millis(300));
        let h3 = std::sync::Arc::clone(&h2);
        *b2.lock().unwrap() = Some(std::thread::spawn(move || {
            while !d2.load(std::sync::atomic::Ordering::SeqCst) {
                if let Ok(c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                    h3.lock().unwrap().push(c);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }));
    });
    let r = v.run();
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(h) = burst.lock().unwrap().take() {
        let _ = h.join();
    }
    assert_positive_passed(&r);
    assert_negative_transport(&r);
    drop(held);
}

/// A reset after the version exchange: a listener on the port sends a version line and
/// closes with the client's data unread (a TCP reset).
#[cfg(unix)]
#[test]
fn verify_negative_inconclusive_on_reset() {
    let v = fx::VerifyLab::new();
    let port = v.lab.sshd.port;
    let stop = v.lab.sshd.stopper();
    let held: std::sync::Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>> =
        std::sync::Arc::default();
    let h2 = std::sync::Arc::clone(&held);
    between_attempts(&v, move || {
        stop();
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        h2.lock().unwrap().push(std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                use std::io::Write;
                let _ = conn.write_all(b"SSH-2.0-OpenSSH_10.5\r\n");
                std::thread::sleep(Duration::from_millis(300));
                drop(conn);
            }
        }));
    });
    let r = v.run();
    assert_positive_passed(&r);
    assert_negative_transport(&r);
    assert!(
        r.negative.result.trace.server_version.is_some(),
        "the version exchange happened: {r:?}"
    );
    for h in held.lock().unwrap().drain(..) {
        let _ = h.join();
    }
}

/// The destination clock measurement bounds the lag (§17.1 item 10): a destination
/// whose sessions' `awk` reads the time minus a fixed lag (the sshd's own `SetEnv
/// PATH`; no clock is changed) is measured behind by at least that lag, and the bound
/// is within the lag plus the round trip and the reading's resolution.
#[cfg(unix)]
#[test]
fn remote_clock_measurement_bounds_lag() {
    const LAG: u64 = 90;
    let scratch_probe = heimdall_testkit::home::Scratch::new().unwrap();
    let dir = scratch_probe.subdir("lag").unwrap();
    fx::write_mode(
        &dir.join("awk"),
        &format!(
            "#!/bin/sh\nnow=$(/usr/bin/awk 'BEGIN {{ srand(); print srand() }}')\n\
             echo \"HM1 now=$((now - {LAG}))\"\n"
        ),
        0o755,
    );
    let lab = fx::Lab::with_sshd_extra(&format!(
        "SetEnv PATH={}:/usr/bin:/bin:/usr/sbin:/sbin\n",
        dir.display()
    ));
    let v = fx::VerifyLab::with(lab, true);
    let r = v.run();
    assert_positive_passed(&r);
    let clock = r.clock.expect("measured");
    eprintln!(
        "clock row: lag {LAG} s measured behind_upper_ms {} rtt_ms {}",
        clock.behind_upper_ms, clock.rtt_ms
    );
    assert!(clock.behind_upper_ms >= LAG * 1000, "{clock:?}");
    assert!(
        clock.behind_upper_ms <= LAG * 1000 + clock.rtt_ms + 2000,
        "{clock:?}"
    );
    // Without a lag the bound is the resolution plus the round trip at most.
    let v0 = fx::VerifyLab::new();
    let r0 = v0.run();
    let c0 = r0.clock.unwrap();
    assert!(c0.behind_upper_ms <= c0.rtt_ms + 2000, "{c0:?}");
}

/// B R2-13: a positive refused while the destination's clock is skewed beyond the
/// allowance is inconclusive (`destination_clock_skew`), and nothing is changed: the
/// Verifier writes nothing, and the verdict is not a refusal (no rollback, U10).
/// The skew is reproduced as a certificate not yet valid at the destination (its
/// `valid_after` ahead of the server's clock, as a 10-minute lag would make it).
#[cfg(unix)]
#[test]
fn destination_clock_skew_beyond_allowance_inconclusive_no_rollback() {
    let mut v = fx::VerifyLab::new();
    let now = fx::now_secs();
    let principal = heimdall_registry::line::principal(
        &v.lab.destination,
        &heimdall_contract::ids::AccountName::parse(&fx::me()).unwrap(),
    )
    .unwrap();
    v.positive = fx::issue(
        &v.lab.ca,
        &v.session.subject(),
        &principal,
        now + 600,
        now + 900,
    );
    let before = v.lab.registry_bytes();
    let r = v.run();
    assert_ne!(r.positive.result.exit_status, Some(0));
    assert!(r.positive.result.trace.not_accepted, "{r:?}");
    let lagging = KnownOffset {
        remote_minus_local_ms: -660_000,
        uncertainty_ms: 1_500,
    };
    assert_eq!(
        verdict(&r, Some(lagging)),
        VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::DestinationClockSkew
        }
    );
    // Without a known offset the refusal is classified as refused.
    assert_eq!(verdict(&r, None), VerificationVerdict::PositiveRefused);
    assert_eq!(
        v.lab.registry_bytes(),
        before,
        "the verifier changes nothing"
    );
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::EnrollmentEventKind as K;
    assert_eq!(
        transition(
            S::Verifying,
            K::VerificationResult {
                verdict: verdict(&r, Some(lagging)),
                approval_valid: true
            }
        ),
        S::AppliedUnverified,
        "no rollback"
    );
}

/// The verification never reads the user's configuration (`-F` generated): an extra
/// key that **would** authenticate (authorized, and listed by the endpoint as a canary)
/// is never offered; the positive passes only through the certificate.
#[cfg(unix)]
#[test]
fn verify_never_reads_user_config() {
    use ssh_key::PrivateKey;
    let lab = fx::Lab::new();
    let canary = PrivateKey::random(
        &mut heimdall_credential::vault::SystemRng,
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let mut text = String::from_utf8(lab.registry_bytes()).unwrap();
    text.push_str(&format!("{}\n", lab.line));
    text.push_str(&format!(
        "restrict {}\n",
        canary.public_key().to_openssh().unwrap()
    ));
    fx::write_mode(&lab.registry, &text, 0o600);
    let mut v = fx::VerifyLab::with(lab, false);
    v.session = fx::TestSession::start_with_extra(v.lab.scratch(), vec![canary]);
    let now = fx::now_secs();
    let principal = heimdall_registry::line::principal(
        &v.lab.destination,
        &heimdall_contract::ids::AccountName::parse(&fx::me()).unwrap(),
    )
    .unwrap();
    v.positive = fx::issue(
        &v.lab.ca,
        &v.session.subject(),
        &principal,
        now - 60,
        now + 300,
    );
    v.negative = fx::issue(
        &v.lab.ca,
        &v.session.subject(),
        &fx::negative_principal(),
        now - 60,
        now + 300,
    );
    let r = v.run();
    assert_positive_passed(&r);
    assert_negative_refused(&r);
    assert_eq!(
        v.session.extra_signatures(),
        0,
        "the canary key never signed"
    );
    let accepted = v.lab.sshd.accepted();
    assert_eq!(accepted.len(), 1);
    assert!(
        accepted[0].starts_with("ED25519-CERT "),
        "only the certificate: {accepted:?}"
    );
}

/// `principals_not_enforced` (M-F27): at the verifier's `nonce_known` pause (test
/// configuration; U11's `PauseHooks`) a line listing **both** principals is added; the
/// negative is accepted, which is the high-severity finding. The initial verification
/// then goes to `rollback_pending` (the rollback itself is U10's driver).
#[cfg(unix)]
#[test]
fn principals_not_enforced_detected_and_rolled_back() {
    use heimdall_testkit::registry::{PauseHooks, hook};
    use heimdall_testkit::sshd::PrincipalsNotEnforced;
    let mut v = fx::VerifyLab::new();
    let hooks = PauseHooks::new(v.lab.scratch()).unwrap();
    hooks.arm(hook::NONCE_KNOWN).unwrap();
    let client = fx::system_ssh();
    v.verifier = heimdall_enroll::verify::Verifier::with_client(
        heimdall_enroll::verify::VerifierClient {
            version: fx::client_version(&client),
            path: client,
        },
        &v.runtime,
    )
    .with_test_pause_dir(hooks.dir());
    let positive_principal = heimdall_registry::line::principal(
        &v.lab.destination,
        &heimdall_contract::ids::AccountName::parse(&fx::me()).unwrap(),
    )
    .unwrap();
    let ca_line = v.lab.ca.public_openssh().unwrap();
    let registry = v.lab.registry.clone();
    let r = std::thread::scope(|s| {
        let writer = s.spawn(|| {
            PrincipalsNotEnforced::write_at_nonce_known(
                &hooks,
                &registry,
                &ca_line,
                &positive_principal,
            )
        });
        let r = v.run();
        let nonce = writer.join().unwrap().unwrap();
        assert_eq!(nonce.len(), 32);
        r
    });
    assert_positive_passed(&r);
    assert_eq!(r.negative.result.exit_status, Some(0), "{r:?}");
    assert!(r.negative.result.trace.accepted);
    assert_eq!(r.negative.result.signatures, 1);
    assert_eq!(
        verdict(&r, None),
        VerificationVerdict::PrincipalsNotEnforced
    );
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::EnrollmentEventKind as K;
    assert_eq!(
        transition(
            S::Verifying,
            K::VerificationResult {
                verdict: VerificationVerdict::PrincipalsNotEnforced,
                approval_valid: true
            }
        ),
        S::RollbackPending
    );
}

/// The system form: `TrustedUserCAKeys` with an `AuthorizedPrincipalsCommand` (`%k`)
/// that prints the presented certificate's principals (U11's fixture) accepts the
/// negative too: `principals_not_enforced`, and the system form goes `held`.
#[cfg(unix)]
#[test]
fn principals_not_enforced_system_form_via_echoing_principals_command() {
    use heimdall_testkit::sshd::PrincipalsNotEnforced;
    let probe = heimdall_testkit::home::Scratch::new().unwrap();
    let script = PrincipalsNotEnforced::echo_principals_command(&probe).unwrap();
    let ca = heimdall_credential::cert::SecretCaKey::generate().unwrap();
    let ca_file = probe.subdir("ca").unwrap().join("user_ca.pub");
    std::fs::write(&ca_file, format!("{}\n", ca.public_openssh().unwrap())).unwrap();
    let lab = fx::Lab::with_sshd_extra(&format!(
        "TrustedUserCAKeys {}\nAuthorizedPrincipalsCommand /bin/sh {} %t %k\n\
         AuthorizedPrincipalsCommandUser {}\n",
        ca_file.display(),
        script.display(),
        fx::me()
    ));
    let mut v = fx::VerifyLab::with(lab, false);
    let now = fx::now_secs();
    let principal = heimdall_registry::line::principal(
        &v.lab.destination,
        &heimdall_contract::ids::AccountName::parse(&fx::me()).unwrap(),
    )
    .unwrap();
    v.positive = fx::issue(&ca, &v.session.subject(), &principal, now - 60, now + 300);
    v.negative = fx::issue(
        &ca,
        &v.session.subject(),
        &fx::negative_principal(),
        now - 60,
        now + 300,
    );
    let r = v.run();
    assert_positive_passed(&r);
    assert_eq!(r.negative.result.exit_status, Some(0), "{r:?}");
    assert_eq!(
        verdict(&r, None),
        VerificationVerdict::PrincipalsNotEnforced
    );
    use heimdall_contract::enrollment::{EnrollmentForm, EnrollmentState as S};
    use heimdall_domain::enrollment::{EnrollmentEvent, EnrollmentEventKind as K, RecordFacts};
    assert_eq!(
        heimdall_domain::enrollment::transition(
            S::Verifying,
            EnrollmentEvent {
                record: RecordFacts {
                    form: EnrollmentForm::System,
                    foreign: false
                },
                kind: K::VerificationResult {
                    verdict: VerificationVerdict::PrincipalsNotEnforced,
                    approval_valid: true
                }
            }
        ),
        Ok(S::Held)
    );
}

/// The registry guard (U11) refuses a target outside the run's scratch before any
/// `ssh` runs, and holds for every step this file builds (`fx::Lab::step_with`).
#[cfg(unix)]
#[test]
fn registry_guard_refuses_non_scratch_target() {
    use heimdall_testkit::registry::{RegistryGuard, RegistryTarget};
    let lab = fx::Lab::new();
    let guard = RegistryGuard::new(lab.scratch()).unwrap();
    assert!(guard.check(&RegistryTarget::Path(&lab.registry)).is_ok());
    let home = heimdall_localenv::sys::account_home().unwrap();
    for outside in [
        home.join(".ssh").join("authorized_keys"),
        PathBuf::from("/etc/ssh/authorized_keys"),
        lab.scratch().path().join("..").join("authorized_keys"),
    ] {
        assert!(
            guard.check(&RegistryTarget::Path(&outside)).is_err(),
            "{outside:?}"
        );
    }
    let link = lab.scratch().subdir("lnk").unwrap().join("authorized_keys");
    // A link out of scratch (to a system directory; nothing of the owner's is followed).
    std::os::unix::fs::symlink("/etc", &link).unwrap();
    assert!(
        guard.check(&RegistryTarget::Path(&link)).is_err(),
        "a link out of scratch"
    );
    assert!(
        guard
            .check(&RegistryTarget::Container {
                name: "not-a-fixture-container",
                path: "/home/enroll/.ssh/authorized_keys"
            })
            .is_err()
    );
    // Nothing ran: the lab's sshd saw no login.
    assert!(lab.sshd.accepted().is_empty());
}

/// A bare `cert-authority` line without `principals=` (the revision-2 fixture): the
/// server then requires the user name as principal, so the positive is refused with
/// refusal evidence (`verification_failed`).
#[cfg(unix)]
#[test]
fn bare_cert_authority_line_is_verification_failed() {
    let lab = fx::Lab::new();
    let marker = heimdall_registry::line::marker_of(&lab.line)
        .unwrap()
        .to_owned();
    let bare = format!(
        "cert-authority {} {marker}",
        lab.ca.public_openssh().unwrap()
    );
    let mut text = String::from_utf8(lab.registry_bytes()).unwrap();
    text.push_str(&format!("{bare}\n"));
    fx::write_mode(&lab.registry, &text, 0o600);
    let v = fx::VerifyLab::with(lab, false);
    let r = v.run();
    assert_ne!(r.positive.result.exit_status, Some(0));
    assert_eq!(r.positive.result.signatures, 0);
    assert!(
        r.positive.result.trace.not_accepted && r.positive.result.trace.publickey_failure_final
    );
    assert_negative_refused(&r);
    assert_eq!(verdict(&r, None), VerificationVerdict::PositiveRefused);
}

/// The server reads another registry (`AuthorizedKeysFile` points elsewhere): the line
/// Heimdall wrote is not trusted, so the positive is refused (`verification_failed`).
#[cfg(unix)]
#[test]
fn verification_failed_when_server_reads_another_registry() {
    let lab = fx::Lab::new();
    // The line goes to a file the server does not read.
    let elsewhere = lab.registry.with_file_name("authorized_keys2");
    fx::write_mode(&elsewhere, &format!("{}\n", lab.line), 0o600);
    let v = fx::VerifyLab::with(lab, false);
    let r = v.run();
    assert!(r.positive.result.trace.not_accepted, "{r:?}");
    assert_eq!(verdict(&r, None), VerificationVerdict::PositiveRefused);
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::EnrollmentEventKind as K;
    assert_eq!(
        transition(
            S::Verifying,
            K::VerificationResult {
                verdict: VerificationVerdict::PositiveRefused,
                approval_valid: true
            }
        ),
        S::RollbackPending
    );
}

/// A host-key mismatch during verification is `HOST_TRUST_CHANGED`: `held`, never a
/// rollback over an untrusted host; nothing is signed.
#[cfg(unix)]
#[test]
fn verification_host_key_mismatch_holds_no_rollback() {
    let mut v = fx::VerifyLab::new();
    let wrong = fx::Lab::with_key(&v.approved, &FixtureKey::generate());
    v.plan = fx::plan_for(&wrong, &v.lab.line, &v.lab.destination);
    let before = v.lab.registry_bytes();
    let r = v.run();
    assert!(
        r.positive.host_key_failure && r.negative.host_key_failure,
        "{r:?}"
    );
    assert_eq!(
        r.positive.result.signatures + r.negative.result.signatures,
        0
    );
    assert_eq!(verdict(&r, None), VerificationVerdict::HostKeyMismatch);
    assert_eq!(v.lab.registry_bytes(), before);
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::EnrollmentEventKind as K;
    assert_eq!(
        transition(
            S::Verifying,
            K::VerificationResult {
                verdict: VerificationVerdict::HostKeyMismatch,
                approval_valid: true
            }
        ),
        S::Held
    );
}

/// An inconclusive initial verification (the server gone before the positive) leaves
/// the record `applied_unverified`: the line stays and no grant uses it.
#[cfg(unix)]
#[test]
fn verification_inconclusive_leaves_applied_unverified() {
    let v = fx::VerifyLab::new();
    v.lab.sshd.stop();
    let r = v.run();
    assert!(verdict(&r, None).is_inconclusive());
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::EnrollmentEventKind as K;
    assert_eq!(
        transition(
            S::Verifying,
            K::VerificationResult {
                verdict: verdict(&r, None),
                approval_valid: true
            }
        ),
        S::AppliedUnverified
    );
    v.assert_no_generated_files();
}

/// A failed re-verification holds and never removes: the line is still there, and
/// the record goes `held`.
#[cfg(unix)]
#[test]
fn reverification_failure_holds_never_removes() {
    let lab = fx::Lab::new();
    let v = fx::VerifyLab::with(lab, true);
    // The administrator removed the line since: the positive is refused.
    let text = String::from_utf8(v.lab.registry_bytes())
        .unwrap()
        .replace(&format!("{}\n", v.lab.line), "");
    fx::write_mode(&v.lab.registry, &text, 0o600);
    let before = v.lab.registry_bytes();
    let r = v.run();
    assert_eq!(verdict(&r, None), VerificationVerdict::PositiveRefused);
    assert_eq!(v.lab.registry_bytes(), before, "nothing removed or written");
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::{EnrollmentEventKind as K, ReverifyFrom};
    assert_eq!(
        transition(
            S::Reverifying,
            K::ReverificationResult {
                from: ReverifyFrom::Verified,
                verdict: VerificationVerdict::PositiveRefused
            }
        ),
        S::Held
    );
}

/// An inconclusive re-verification keeps the record `verified` (unchanged freshness and a
/// doctor finding `reverification_inconclusive`, U10).
#[cfg(unix)]
#[test]
fn reverification_inconclusive_keeps_verified_with_finding() {
    let v = fx::VerifyLab::new();
    between_attempts(&v, v.lab.sshd.stopper());
    let r = v.run();
    let verdict_now = verdict(&r, None);
    assert!(verdict_now.is_inconclusive());
    use heimdall_contract::enrollment::EnrollmentState as S;
    use heimdall_domain::enrollment::{EnrollmentEventKind as K, ReverifyFrom};
    assert_eq!(
        transition(
            S::Reverifying,
            K::ReverificationResult {
                from: ReverifyFrom::Verified,
                verdict: verdict_now
            }
        ),
        S::Verified
    );
}

/// Two known host keys for the target are ambiguous: the evaluation lists both, so no
/// single approved key exists (`host_trust_undetermined`, U5-pure's plan refusal).
#[cfg(unix)]
#[test]
fn verification_known_host_ambiguous_refused() {
    let lab = fx::Lab::new();
    let other = FixtureKey::generate();
    lab.home
        .trust_host_key(&format!(
            "[127.0.0.1]:{} {}",
            lab.sshd.port,
            other.public_line_without_comment()
        ))
        .unwrap();
    let t = lab.evaluate();
    assert_eq!(
        t.host_keys.iter().filter(|k| !k.revoked).count(),
        2,
        "both keys are reported"
    );
    // A revoked second key is not ambiguous.
    std::fs::write(
        &lab.home.known_hosts,
        format!(
            "{}\n@revoked [127.0.0.1]:{} {}\n",
            lab.sshd.host_key_line(),
            lab.sshd.port,
            other.public_line_without_comment()
        ),
    )
    .unwrap();
    let t = lab.evaluate();
    assert_eq!(t.host_keys.iter().filter(|k| !k.revoked).count(), 1);
    assert_eq!(t.host_keys.iter().filter(|k| k.revoked).count(), 1);
}

/// `log_attestation` is reported unavailable (ADR-0005 §3.3): the server log is only
/// the fixtures' oracle.
#[cfg(unix)]
#[test]
fn log_attestation_reported_unavailable() {
    let v = fx::VerifyLab::new();
    let r = v.run();
    assert_eq!(r.log_attestation, LogAttestation::Unavailable);
    let none = heimdall_enroll::verify::Verifier::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let r0 = rt.block_on(none.run_detailed(&v.plan, &v.positive, &v.negative, &v.session));
    assert_eq!(r0.log_attestation, LogAttestation::Unavailable);
    assert!(r0.refused.is_some());
}

/// The default-path production verification on an account that cannot read the sshd log
/// (ADR-0005 §9.3 R5; Docker `enrollable`, M00-T03 fixtures): the line goes into the
/// container's `~/.ssh/authorized_keys` (container-internal, disposable), and the
/// verification passes without any log oracle.
#[cfg(unix)]
#[test]
#[ignore = "docker: the M00-T03 fixtures (tests/fixtures/ssh/up.sh); run with HM_DOCKER_TESTS=1 cargo test -p heimdall-enroll --test integration_enroll_verify -- --ignored verify_on_account_without_log_access"]
fn verify_on_account_without_log_access() {
    use heimdall_contract::enrollment::{ApprovedHostKey, ApprovedTarget, NoProxy};
    use heimdall_contract::ids::{AccountName, DestinationId, EnrollmentId};
    use heimdall_testkit::registry::{RegistryGuard, RegistryTarget};
    assert_eq!(
        std::env::var("HM_DOCKER_TESTS").as_deref(),
        Ok("1"),
        "a docker test runs only with HM_DOCKER_TESTS=1"
    );
    const CONTAINER: &str = "hm-m00t03-enroll";
    const REGISTRY: &str = "/home/enroll/.ssh/authorized_keys";
    let runtime = heimdall_testkit::repo::repo_root().join("tests/fixtures/ssh/runtime");
    let ports = std::fs::read_to_string(runtime.join("ports.env")).expect("up.sh ran");
    let port: u16 = ports
        .lines()
        .find_map(|l| l.strip_prefix("PORT_enroll="))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let host_key =
        std::fs::read_to_string(runtime.join("hostkeys/enroll/ssh_host_ed25519_key.pub")).unwrap();
    let mut f = host_key.split_whitespace();
    let (alg, b64) = (f.next().unwrap().to_owned(), f.next().unwrap().to_owned());
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    RegistryGuard::new(&scratch)
        .unwrap()
        .check(&RegistryTarget::Container {
            name: CONTAINER,
            path: REGISTRY,
        })
        .expect("a running heimdall.fixture container");
    let docker = |args: &[&str], stdin: Option<&str>| -> std::process::Output {
        use std::io::Write;
        let mut c = std::process::Command::new("docker")
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = c.stdin.take().unwrap();
        if let Some(text) = stdin {
            input.write_all(text.as_bytes()).unwrap();
        }
        drop(input);
        c.wait_with_output().unwrap()
    };
    // The account cannot read the server's log.
    let probe = docker(
        &[
            "exec",
            "-u",
            "enroll",
            CONTAINER,
            "sh",
            "-c",
            "grep -rls 'Accepted publickey' /var/log 2>/dev/null | wc -l",
        ],
        None,
    );
    assert_eq!(
        String::from_utf8_lossy(&probe.stdout).trim(),
        "0",
        "the account reads no sshd log"
    );
    let ca = heimdall_credential::cert::SecretCaKey::generate().unwrap();
    let destination = DestinationId::parse("dst_docker").unwrap();
    let account = AccountName::parse("enroll").unwrap();
    let principal = heimdall_registry::line::principal(&destination, &account).unwrap();
    let marker = format!(
        "heimdall:{}",
        EnrollmentId::from_random_bytes(fx::rand16()).as_str()
    );
    let line =
        heimdall_registry::line::expected_line(&ca.public_openssh().unwrap(), &principal, &marker)
            .unwrap();
    let before = docker(&["exec", "-u", "enroll", CONTAINER, "cat", REGISTRY], None).stdout;
    let add = docker(
        &[
            "exec",
            "-i",
            "-u",
            "enroll",
            CONTAINER,
            "sh",
            "-c",
            &format!("cat >> {REGISTRY}"),
        ],
        Some(&format!("{line}\n")),
    );
    assert!(add.status.success());
    let approved = ApprovedTarget {
        hostname: "127.0.0.1".into(),
        port,
        user: account,
        proxy: NoProxy::None,
        host_key: ApprovedHostKey {
            algorithm: alg,
            key: b64,
            fingerprint: String::new(),
        },
    };
    let session = fx::TestSession::start(&scratch);
    let now = fx::now_secs();
    let positive = fx::issue(&ca, &session.subject(), &principal, now - 60, now + 300);
    let negative = fx::issue(
        &ca,
        &session.subject(),
        &fx::negative_principal(),
        now - 60,
        now + 300,
    );
    let client = fx::system_ssh();
    let verifier = heimdall_enroll::verify::Verifier::with_client(
        heimdall_enroll::verify::VerifierClient {
            version: fx::client_version(&client),
            path: client,
        },
        scratch.subdir("rt").unwrap(),
    );
    let plan = fx::plan_for(&approved, &line, &destination);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let r = rt.block_on(verifier.run_detailed(&plan, &positive, &negative, &session));
    // Restore the container's registry (it is disposable; down.sh removes it anyway).
    let restore = docker(
        &[
            "exec",
            "-i",
            "-u",
            "enroll",
            CONTAINER,
            "sh",
            "-c",
            &format!("cat > {REGISTRY}"),
        ],
        Some(&String::from_utf8_lossy(&before)),
    );
    assert!(restore.status.success());
    assert_positive_passed(&r);
    assert_negative_refused(&r);
    assert_eq!(verdict(&r, None), VerificationVerdict::Passed);
    assert_eq!(r.log_attestation, LogAttestation::Unavailable);
    eprintln!(
        "docker enrollable row: server {:?}, clock {:?}",
        r.positive.result.trace.server_version, r.clock
    );
}
