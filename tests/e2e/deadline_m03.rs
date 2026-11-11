//! M03-U7: the Windows contained launch of the verified `ssh` and its ownership
//! (m03-plan U7 "Tests", Windows ownership; ADR-0008 D8 item 2, §17.3 item 1, §17.4
//! item 8; A23).
//!
//! **Windows only, natively** (`platform_only`). Every `windows_*` test runs the in-box
//! `ssh.exe` against the harness's WSL fixture sshd (`HM_FIXTURE_SSHD_*`, adopted by
//! `heimdall_testkit::sshd::LoopbackSshd::start`), authenticating through a fixture
//! agent on a fixture pipe that holds one per-run key (the harness's authorized keys).
//! A test that finds no fixture **fails** with that reason.
//!
//! The launch is `heimdall_launch::windows::spawn_contained_and_wait` (the path `run`
//! takes for a managed launch of the verified client) with a registrar that calls the
//! real `ConnectionSupervisor::register` over a real `Operations` and store (an `ensure`
//! through a fixture credential adapter gives the grant and binding). `heimdall run`
//! itself cannot reach this path for a managed pair until U10 (`ensure` of a managed
//! pair is `driver_unavailable`, and `dispatch` refuses `Connections::Register`), so
//! the production registrar is covered only by its fail-closed answer.
//!
//! Processes are counted and stopped only by the exact PIDs the test started.
//!
//! On every host: `registration_failure_reasons_are_launch_failed_127` (the record and
//! exit status the contained path's refusals map to).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

/// m03-plan §5 item 14: both registration reasons are `LAUNCH_FAILED`, exit 127.
#[test]
fn registration_failure_reasons_are_launch_failed_127() {
    use heimdall_contract::Code;
    use heimdall_contract::envelope::reason;
    for r in [
        reason::CONNECTION_REGISTRATION_FAILED,
        reason::CONNECTION_REGISTRATION_REFUSED,
    ] {
        assert_eq!(
            Code::LaunchFailed.exit_code_for_reason(Some(r)).as_i32(),
            127,
            "{r}"
        );
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use heimdall_app::ports::{
        AdapterDescriptor, ConnectionControl, CredentialAdapter, InteractionRequirement,
        LockContinuity, PrepareOutcome,
    };
    use heimdall_app::{Caller, Operations, OperationsConfig};
    use heimdall_contract::Timestamp;
    use heimdall_contract::envelope::reason;
    use heimdall_contract::ids::{
        AccountName, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId, RequestId, WorkId,
    };
    use heimdall_contract::managed::{ConnectionPolicy, ExistingConnectionsMode};
    use heimdall_contract::request::{
        DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
        ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry, RefreshDependency,
        RequiredCapabilities, RevocationStatus, RevokeRequest, WaitMode, WorkloadIsolation,
    };
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::managed::OwnedConnectionState;
    use heimdall_domain::operation::AdapterIdentity;
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{AccessPair, Capability, Scope};
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_launch::env::EnvDelta;
    use heimdall_launch::resolve::{ProgramKind, ResolvedProgram, Via};
    use heimdall_launch::windows::{
        ContainedFailure, Registration, launch_uses_kill_on_close_job, spawn_and_wait,
        spawn_contained_and_wait,
    };
    use heimdall_localenv::env::Platform;
    use heimdall_localenv::sys::JobObject;
    use heimdall_runtime::connections::{BindingEndpoints, ConnectionConfig, ConnectionSupervisor};
    use heimdall_runtime::supervisor::FixedJitter;
    use heimdall_store::{NoFaults, Store};
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::home::{ScratchHome, find_program, ssh_config_quote};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
    use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync};

    const HOUR: i64 = 3600;
    const ALIAS: &str = "hm-u7-win";

    fn after(secs: i64) -> Timestamp {
        Timestamp::from_second(Timestamp::now().as_second() + secs).unwrap()
    }

    fn env_id() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn owner() -> Caller {
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        })
    }

    fn pair() -> AccessPair {
        AccessPair {
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

    fn enforcement() -> EnforcementEvidence {
        EnforcementEvidence {
            report: Enforcement {
                destination_scope: DestinationScopeEnforcement::ClientRouting,
                new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                workload_isolation: WorkloadIsolation::SharedOsUser,
                existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
                revocation: RevocationStatus::LocalApplied,
                identity_selection: None,
                new_signing_expiry: None,
                owned_multiplexing: None,
                remote_processes: None,
                unmanaged_connections: None,
                issuer_isolation: None,
            },
            evidence: Vec::new(),
        }
    }

    fn outcome() -> PrepareOutcome {
        PrepareOutcome {
            usable_until: after(12 * HOUR),
            offline_until: after(HOUR),
            refresh_dependency: RefreshDependency::None,
            enforcement: enforcement(),
            credential_ref: "fixture-ref".into(),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
        }
    }

    fn descriptor() -> AdapterDescriptor {
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            },
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        }
    }

    struct NoEndpoints;
    impl BindingEndpoints for NoEndpoints {
        fn endpoint(
            &self,
            _: &heimdall_contract::ids::BindingId,
        ) -> Option<heimdall_contract::provider::EndpointRef> {
            None
        }
    }

    /// The fixture: harness sshd, fixture agent, scratch config, real operations.
    struct World {
        home: ScratchHome,
        sshd: LoopbackSshd,
        _agent: FakeAgent,
        store: Arc<Store>,
        ops: Operations,
        sup: Arc<ConnectionSupervisor>,
        ssh: PathBuf,
        data: EnsureData,
    }

    fn world(existing: ExistingConnectionsMode) -> World {
        assert!(
            std::env::var_os("HM_FIXTURE_SSHD_HOST").is_some(),
            "the Windows ownership tests need the harness fixture sshd (HM_FIXTURE_SSHD_*)"
        );
        let home = ScratchHome::new();
        let key = FixtureKey::generate();
        let sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                authorized: vec![key.public().clone()],
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("the harness fixture sshd: {e}"));
        home.trust_host_key(&sshd.host_key_line).unwrap();
        let agent = FakeAgent::start(
            Endpoint::in_scratch(home.scratch(), "a").unwrap(),
            FakeAgentConfig {
                keys: vec![key],
                mode: AgentMode::Normal,
            },
        );
        let pipe = agent
            .endpoint()
            .locator()
            .to_string_lossy()
            .replace('\\', "/");
        let account = sshd
            .account()
            .expect("the WSL harness sshd names its account (HM_FIXTURE_SSHD_USER)")
            .to_owned();
        home.write_user_config(&format!(
            "Host {ALIAS}\n  HostName {}\n  Port {}\n  User {account}\n  IdentityAgent {}\n  ControlMaster no\n  ControlPath none\n",
            sshd.host,
            sshd.port,
            ssh_config_quote(&pipe)
        ))
        .unwrap();
        let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env_id(),
                    device: DeviceId::from_random_bytes([8; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: true,
                        managed_signing: true,
                        issuer_access: true,
                    },
                })?;
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse("dev").unwrap(),
                    revision: 1,
                    scope: scope(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("pol").unwrap(),
                        revision: PolicyRevision(1),
                        profile: ProfileId::parse("dev").unwrap(),
                        workspace: None,
                        scope: scope(),
                        environments: [env_id()].into_iter().collect(),
                        max_window: Duration::from_secs(2 * 3600),
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: Default::default(),
                        connection: ConnectionPolicy {
                            existing,
                            multiplexing: Default::default(),
                        },
                    },
                    false,
                )?;
                Ok(())
            })
            .unwrap();
        let fake = FakeCredentialAdapter::new(descriptor(), vec![FakeStep::Prepare(outcome())]);
        let rt = rt();
        let ops = rt
            .block_on(Operations::start(OperationsConfig {
                store: store.clone(),
                clock: Arc::new(heimdall_runtime::platform::SystemClock::new()),
                time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                time_policy: TimePolicy::default(),
                environment: env_id(),
                adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
                stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
                limits: Default::default(),
                default_window: Duration::from_secs(12 * 3600),
                projection: None,
            }))
            .unwrap();
        let data = rt
            .block_on(ops.ensure(
                &owner(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: [pair()].into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse("w-u7").unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse("r-u7").unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                },
            ))
            .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message))
            .data;
        let ssh = find_program("ssh").expect("the in-box ssh.exe");
        let mut config = ConnectionConfig::new(
            home.root.join("r"),
            ssh.clone(),
            Arc::new(NoEndpoints),
            Arc::new(FixedJitter(0.0)),
        );
        config.platform = Platform::Windows;
        let sup = Arc::new(ConnectionSupervisor::new(
            store.clone(),
            Some(ops.clone()),
            config,
        ));
        World {
            home,
            sshd,
            _agent: agent,
            store,
            ops,
            sup,
            ssh,
            data,
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    impl World {
        fn program(&self) -> ResolvedProgram {
            ResolvedProgram {
                path: self.ssh.clone(),
                kind: ProgramKind::Native,
                via: Via::Explicit,
            }
        }

        /// The client's arguments: the isolation arguments, the alias, `remote`.
        fn args(&self, remote: &[&str]) -> Vec<OsString> {
            let mut a = self.home.isolation_args();
            a.push(ALIAS.into());
            a.extend(remote.iter().map(OsString::from));
            a
        }

        fn auths(&self) -> usize {
            self.sshd.accepted_log().len()
        }

        /// The real registration: `ConnectionSupervisor::register` over the operations.
        fn register(&self, pid: u32, created_at: Timestamp, image: &Path) -> Registration {
            let r = rt().block_on(self.sup.register(
                &self.data.binding_id,
                pid,
                created_at,
                &image.to_string_lossy(),
            ));
            match r {
                Ok(_) => Registration::Registered,
                Err(heimdall_app::ports::ConnError::RegistrationRefused(_)) => {
                    Registration::Refused
                }
                Err(_) => Registration::Failed,
            }
        }

        fn rows(&self) -> Vec<heimdall_domain::managed::OwnedConnection> {
            let g = self.data.grant_id.clone();
            self.store
                .transaction(|tx| tx.owned_connections_for_grant(&g))
                .unwrap()
        }

        fn revoke(&self) {
            // The tombstone commits first (D7 item 2 step 1); the fixture adapter's
            // answer to its own revoke round does not matter here.
            let _ = rt().block_on(self.ops.revoke(
                &owner(),
                RevokeRequest {
                    grant_id: self.data.grant_id.clone(),
                    request_id: RequestId::parse("r-u7-revoke").unwrap(),
                },
            ));
        }
    }

    /// Whether the exact process `pid` with creation time `created` still runs.
    fn alive(pid: u32, created: &Timestamp) -> bool {
        matches!(
            heimdall_localenv::sys::ProcessPin::open(pid),
            Ok(Some(p)) if p.created_at().as_ref() == Some(created)
        )
    }

    fn wait_until(bound: Duration, mut f: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + bound;
        loop {
            if f() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// §17.4 item 8: the child is registered while still suspended (it has not reached
    /// the server), under the grant's gate (U0b row 26's transaction), and runs only
    /// after the successful reply.
    #[test]
    fn windows_register_while_suspended_under_gate() {
        let w = world(ExistingConnectionsMode::Graceful);
        let before = w.auths();
        let seen = Mutex::new(None);
        let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
            assert_eq!(w.auths(), before, "suspended: nothing reached the server");
            let r = w.register(pid, created, image);
            *seen.lock().unwrap() = Some((pid, created));
            r
        };
        let code = spawn_contained_and_wait(
            &w.program(),
            &w.args(&["exit", "0"]),
            &EnvDelta::default(),
            None,
            &mut registrar,
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(code, 0);
        assert_eq!(w.auths(), before + 1, "it ran after the reply");
        let (pid, created) = seen.lock().unwrap().unwrap();
        let rows = w.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, pid);
        assert_eq!(rows[0].start_token, created.to_string());
    }

    /// A refused registration (the grant ended) closes the job: the client dies
    /// suspended, never authenticating; `connection_registration_refused`.
    #[test]
    fn windows_register_refused_for_ended_grant_child_never_resumed() {
        let w = world(ExistingConnectionsMode::Graceful);
        w.revoke();
        let before = w.auths();
        let seen = Mutex::new(None);
        let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
            *seen.lock().unwrap() = Some((pid, created));
            w.register(pid, created, image)
        };
        let e = spawn_contained_and_wait(
            &w.program(),
            &w.args(&["exit", "0"]),
            &EnvDelta::default(),
            None,
            &mut registrar,
        )
        .unwrap_err();
        assert_eq!(e.reason(), Some(reason::CONNECTION_REGISTRATION_REFUSED));
        let (pid, created) = seen.lock().unwrap().unwrap();
        assert!(!alive(pid, &created), "the suspended child died");
        assert_eq!(w.auths(), before, "never resumed");
        assert!(w.rows().is_empty());
    }

    /// D8 item 2 step 4: a revocation that commits between the registration reply and
    /// the resume finds the row and terminates the registered process.
    #[test]
    fn windows_revoke_between_register_and_resume_kills_child() {
        let w = world(ExistingConnectionsMode::Graceful);
        let before = w.auths();
        let seen = Mutex::new(None);
        let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
            let r = w.register(pid, created, image);
            assert_eq!(r, Registration::Registered);
            // The pause after the reply: the revocation commits, then its cleanup closes
            // the owned connections (D7 item 2 step 4).
            w.revoke();
            let report = rt().block_on(
                w.sup
                    .revocation_close(std::slice::from_ref(&w.data.grant_id)),
            );
            assert_eq!(report.closed.len(), 1, "{report:?}");
            *seen.lock().unwrap() = Some((pid, created));
            r
        };
        let result = spawn_contained_and_wait(
            &w.program(),
            &w.args(&["exit", "0"]),
            &EnvDelta::default(),
            None,
            &mut registrar,
        );
        let (pid, created) = seen.lock().unwrap().unwrap();
        assert!(!alive(pid, &created));
        assert_eq!(w.auths(), before, "the client never authenticated");
        println!(
            "m03 observation: windows_resume_after_terminate result={:?}",
            result.as_ref().map_err(ContainedFailure::reason)
        );
        assert_eq!(w.rows()[0].state, OwnedConnectionState::Closed);
    }

    /// §17.4 item 8: a revocation before the registration refuses it (the pause is
    /// before `register`).
    #[test]
    fn windows_pause_before_register_then_revoke_refuses_registration() {
        let w = world(ExistingConnectionsMode::Graceful);
        let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
            w.revoke();
            w.register(pid, created, image)
        };
        let e = spawn_contained_and_wait(
            &w.program(),
            &w.args(&["exit", "0"]),
            &EnvDelta::default(),
            None,
            &mut registrar,
        )
        .unwrap_err();
        assert_eq!(e.reason(), Some(reason::CONNECTION_REGISTRATION_REFUSED));
        assert!(w.rows().is_empty());
    }

    /// Run a contained `sleep` session in a thread; wait until it authenticated.
    fn running(w: &Arc<World>) -> (u32, Timestamp, std::thread::JoinHandle<Result<u32, String>>) {
        let before = w.auths();
        let (tx, rx) = std::sync::mpsc::channel();
        let w2 = Arc::clone(w);
        let launcher = std::thread::spawn(move || {
            let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
                let r = w2.register(pid, created, image);
                let _ = tx.send((pid, created));
                r
            };
            spawn_contained_and_wait(
                &w2.program(),
                &w2.args(&["sleep", "120"]),
                &EnvDelta::default(),
                None,
                &mut registrar,
            )
            .map_err(|e| format!("{:?}", e.reason()))
        });
        let (pid, created) = rx.recv_timeout(Duration::from_secs(30)).unwrap();
        assert!(wait_until(Duration::from_secs(30), || w.auths() > before));
        (pid, created, launcher)
    }

    /// D8 item 2: revocation ends the exact registered `ssh.exe` (a handle opened on its
    /// PID, the creation time checked on it).
    #[test]
    fn windows_revoke_makes_exact_ssh_exe_pid_exit() {
        let w = Arc::new(world(ExistingConnectionsMode::Graceful));
        let (pid, created, launcher) = running(&w);
        w.revoke();
        let report = rt().block_on(
            w.sup
                .revocation_close(std::slice::from_ref(&w.data.grant_id)),
        );
        assert_eq!(report.closed.len(), 1, "{report:?}");
        assert!(wait_until(Duration::from_secs(10), || !alive(
            pid, &created
        )));
        assert!(
            launcher.join().unwrap().is_ok(),
            "the launcher saw its child exit"
        );
        assert_eq!(w.rows()[0].state, OwnedConnectionState::Closed);
    }

    /// D8 item 2 table: a strict policy's deadline ends the exact `ssh.exe`.
    #[test]
    fn windows_strict_deadline_closes_exact_ssh_exe() {
        let w = Arc::new(world(ExistingConnectionsMode::Strict));
        let (pid, created, launcher) = running(&w);
        let report = rt().block_on(
            w.sup
                .connection_deadline_pass(std::slice::from_ref(&w.data.grant_id)),
        );
        assert_eq!(report.closed.len(), 1, "{report:?}");
        assert!(wait_until(Duration::from_secs(10), || !alive(
            pid, &created
        )));
        assert!(launcher.join().unwrap().is_ok());
    }

    /// The fixture launcher of `windows_launcher_death_ends_ssh_through_job`: run only
    /// as a child of that test (`HM_U7_LAUNCHER_PIDFILE` set), it performs a contained
    /// launch with a fixture registrar that accepts, writes the client's PID and waits.
    #[test]
    #[ignore = "a fixture process of windows_launcher_death_ends_ssh_through_job"]
    fn windows_launcher_fixture_child() {
        let Some(pidfile) = std::env::var_os("HM_U7_LAUNCHER_PIDFILE") else {
            return;
        };
        let ssh = PathBuf::from(std::env::var_os("HM_U7_SSH").unwrap());
        let args: Vec<OsString> = std::env::var("HM_U7_ARGS")
            .unwrap()
            .split('\u{1f}')
            .map(OsString::from)
            .collect();
        let program = ResolvedProgram {
            path: ssh,
            kind: ProgramKind::Native,
            via: Via::Explicit,
        };
        let mut registrar = |pid: u32, created: Timestamp, _: &Path| {
            std::fs::write(&pidfile, format!("{pid} {created}")).unwrap();
            Registration::Registered
        };
        let _ =
            spawn_contained_and_wait(&program, &args, &EnvDelta::default(), None, &mut registrar);
    }

    /// D8 item 2: the launcher's death (terminated by exact PID) ends the client through
    /// the kill-on-close job.
    #[test]
    fn windows_launcher_death_ends_ssh_through_job() {
        let w = world(ExistingConnectionsMode::Graceful);
        let pidfile = w.home.root.join("client.pid");
        let args: Vec<String> = w
            .args(&["sleep", "120"])
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mut launcher = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "windows::windows_launcher_fixture_child",
                "--nocapture",
            ])
            .env("HM_U7_LAUNCHER_PIDFILE", &pidfile)
            .env("HM_U7_SSH", &w.ssh)
            .env("HM_U7_ARGS", args.join("\u{1f}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(wait_until(Duration::from_secs(30), || pidfile.exists()));
        std::thread::sleep(Duration::from_millis(200));
        let text = std::fs::read_to_string(&pidfile).unwrap();
        let (pid, created) = text.split_once(' ').unwrap();
        let (pid, created): (u32, Timestamp) = (pid.parse().unwrap(), created.parse().unwrap());
        assert!(alive(pid, &created), "the client runs");
        // The launcher, by its exact PID (our child).
        launcher.kill().unwrap();
        let _ = launcher.wait();
        assert!(
            wait_until(Duration::from_secs(10), || !alive(pid, &created)),
            "the job ended the client with its launcher"
        );
    }

    /// m03-plan §5 item 14: any registration failure (here the production answer of this
    /// build: the runtime does not accept `Connections::Register` until U10) fails closed:
    /// the child dies suspended; `connection_registration_failed`; `launching` is the
    /// only record before the caller's `prelaunch_failed`.
    #[test]
    fn windows_registration_failure_fails_closed() {
        let w = world(ExistingConnectionsMode::Graceful);
        let meta_path = w.home.root.join("meta");
        let meta = heimdall_launch::meta::SideChannel::create_exclusive(&meta_path).unwrap();
        let before = w.auths();
        let seen = Mutex::new(None);
        let mut registrar = |pid: u32, created: Timestamp, _: &Path| {
            *seen.lock().unwrap() = Some((pid, created));
            Registration::Failed
        };
        let e = spawn_contained_and_wait(
            &w.program(),
            &w.args(&["exit", "0"]),
            &EnvDelta::default(),
            Some(meta),
            &mut registrar,
        )
        .unwrap_err();
        assert_eq!(e.reason(), Some(reason::CONNECTION_REGISTRATION_FAILED));
        let ContainedFailure::Registration {
            refused: false,
            meta: Some(mut meta),
        } = e
        else {
            panic!("a registration failure returns the side channel");
        };
        meta.write_prelaunch_failed(
            heimdall_contract::Code::LaunchFailed,
            127,
            Some(reason::CONNECTION_REGISTRATION_FAILED),
        )
        .unwrap();
        let text = std::fs::read_to_string(&meta_path).unwrap();
        let types: Vec<&str> = text
            .lines()
            .map(|l| l.split('"').nth(3).unwrap_or(""))
            .collect();
        assert_eq!(types, ["launching", "prelaunch_failed"]);
        assert!(text.contains("connection_registration_failed"));
        let (pid, created) = seen.lock().unwrap().unwrap();
        assert!(!alive(pid, &created));
        assert_eq!(w.auths(), before);
    }

    /// Q18's residual, disclosed: an ssh helper (`ProxyCommand`) is inside the job.
    #[test]
    fn windows_ssh_grandchild_inside_job() {
        let w = world(ExistingConnectionsMode::Graceful);
        let pidfile = w.home.root.join("proxy.pid");
        let powershell = find_program("powershell").expect("powershell");
        let proxy = format!(
            "\"{}\" -NoProfile -Command \"$PID | Set-Content -NoNewline '{}'; Start-Sleep 60\"",
            powershell.display(),
            pidfile.display()
        );
        let mut command = Command::new(&w.ssh);
        command
            .args(w.home.isolation_args())
            .arg("-o")
            .arg(format!("ProxyCommand={proxy}"))
            .arg(ALIAS)
            .arg("exit")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let suspended = JobObject::spawn_suspended(command).unwrap();
        let contained = suspended.resume().unwrap();
        assert!(wait_until(Duration::from_secs(30), || {
            std::fs::read_to_string(&pidfile).is_ok_and(|t| !t.trim().is_empty())
        }));
        let helper: u32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            contained.job.contains_pid(helper).unwrap(),
            "the helper is in the job"
        );
        let created = heimdall_localenv::sys::ProcessPin::open(helper)
            .unwrap()
            .unwrap()
            .created_at()
            .unwrap();
        drop(contained);
        assert!(
            wait_until(Duration::from_secs(10), || !alive(helper, &created)),
            "closing the job ends the helper"
        );
    }

    /// §17.3 item 1 (Q18): only a managed launch of the verified ssh gets the job; `run`
    /// of anything else keeps M02's spawn (no job: a fresh job does not contain it).
    #[test]
    fn windows_non_ssh_run_has_no_job_object_by_default() {
        assert!(launch_uses_kill_on_close_job(true, true));
        assert!(!launch_uses_kill_on_close_job(true, false));
        assert!(!launch_uses_kill_on_close_job(false, true));
        assert!(!launch_uses_kill_on_close_job(false, false));
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let cmd = ResolvedProgram {
            path: Path::new(&system_root).join("System32").join("cmd.exe"),
            kind: ProgramKind::Native,
            via: Via::Explicit,
        };
        let code = spawn_and_wait(
            &cmd,
            &["/d".into(), "/c".into(), "exit 3".into()],
            &EnvDelta::default(),
            None,
        )
        .unwrap();
        assert_eq!(code, 3);
    }
}
