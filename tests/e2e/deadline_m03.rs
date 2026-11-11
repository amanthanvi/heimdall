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
//!
//! ⟨§17.20 item 12⟩ `windows_register_while_suspended_under_gate` registers the grant's
//! signing gate in the real `Operations`' `SigningGates` (`retain`, as a credential
//! instance's registration does) and contends on it with an exclusive holder;
//! `windows_non_ssh_run_has_no_job_object_by_default` launches through the real
//! `heimdall run` binary (`HEIMDALL_E2E_BIN`, else `CARGO_BIN_EXE_heimdall`, with the
//! debug build's test configuration as `e2e_run_m02` uses it).

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

    use heimdall_app::managed::Acquired;
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
        BindForm, BindRequest, DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
        ExistingConnectionsPolicy, InteractionMode, LaunchBinding, NewAuthenticationExpiry,
        ProcessHolder, RefreshDependency, RequiredCapabilities, RevocationStatus, RevokeRequest,
        WaitMode, WorkloadIsolation,
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
        ContainedFailure, Registration, launch_uses_kill_on_close_job, spawn_contained_and_wait,
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
        // A launch binding held by its launcher (U0b row 4), as `run` binds it: here the
        // launcher is this test process, which calls `spawn_contained_and_wait` itself
        // (§17.20 item 14: only such a binding registers a dedicated connection).
        let me = std::process::id();
        rt.block_on(
            ops.bind(
                &owner(),
                BindRequest {
                    binding_id: data.binding_id.clone(),
                    form: BindForm::Launch(LaunchBinding {
                        executable: ssh.to_string_lossy().into_owned(),
                        holder: Some(ProcessHolder {
                            pid: me,
                            started_at: heimdall_runtime::platform::process_start_time(me)
                                .expect("this process's start token"),
                        }),
                    }),
                    request_id: RequestId::parse("r-u7-bind").unwrap(),
                },
            ),
        )
        .unwrap_or_else(|e| panic!("bind: {} {}", e.code, e.message));
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

    /// §17.4 item 8, §17.20 item 12: the child is registered while still suspended (it
    /// has not reached the server), under the grant's **registered signing gate**
    /// (U0b row 26 takes it shared within `signing_gate_wait`), and runs only after the
    /// successful reply. The gate is registered in the real `Operations`' gates and
    /// contended: held exclusively past the wait, the registration is refused
    /// (`gate_timeout`) and the child dies suspended; held and released while the
    /// registration waits, the registration completes only after the release.
    #[test]
    fn windows_register_while_suspended_under_gate() {
        let w = world(ExistingConnectionsMode::Graceful);
        let grant = w.data.grant_id.clone();
        let gates = w.ops.signing_gates().clone();
        assert!(gates.retain(&grant, &[]), "the grant's gate is registered");
        let wait = w.ops.limits().signing_gate_wait;
        let rt = rt();
        // 1. Held exclusively for longer than the wait.
        let mut holder = gates.begin_narrowing(std::iter::empty());
        assert_eq!(rt.block_on(holder.acquire(&grant)).unwrap(), Acquired::Held);
        let before = w.auths();
        let seen = Mutex::new(None);
        let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
            assert_eq!(w.auths(), before, "suspended: nothing reached the server");
            let t = Instant::now();
            let r = w.register(pid, created, image);
            *seen.lock().unwrap() = Some((pid, created, t.elapsed()));
            r
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
        let (pid, created, waited) = seen.lock().unwrap().take().unwrap();
        assert!(
            waited >= wait,
            "the registration waited on the gate: {waited:?}"
        );
        assert!(!alive(pid, &created), "the suspended child died");
        assert_eq!(w.auths(), before, "never resumed");
        assert!(w.rows().is_empty());
        // 2. Held, and released while the registration waits for it.
        let hold = wait / 3;
        let held = Mutex::new(Some(holder));
        let seen = Mutex::new(None);
        let mut registrar = |pid: u32, created: Timestamp, image: &Path| {
            assert_eq!(w.auths(), before, "suspended: nothing reached the server");
            let holder = held.lock().unwrap().take();
            let release = std::thread::spawn(move || {
                std::thread::sleep(hold);
                drop(holder);
            });
            let t = Instant::now();
            let r = w.register(pid, created, image);
            let waited = t.elapsed();
            release.join().unwrap();
            *seen.lock().unwrap() = Some((pid, created, waited));
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
        let (pid, created, waited) = seen.lock().unwrap().take().unwrap();
        assert!(
            waited >= hold / 2,
            "the registration waited for the release: {waited:?}"
        );
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
            let report = rt()
                .block_on(
                    w.sup
                        .revocation_close(std::slice::from_ref(&w.data.grant_id)),
                )
                .unwrap();
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
        let report = rt()
            .block_on(
                w.sup
                    .revocation_close(std::slice::from_ref(&w.data.grant_id)),
            )
            .unwrap();
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
        let report = rt()
            .block_on(
                w.sup
                    .connection_deadline_pass(std::slice::from_ref(&w.data.grant_id)),
            )
            .unwrap();
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

    /// The `heimdall` binary under test (as `e2e_run_m02` finds it).
    fn heimdall_bin() -> PathBuf {
        std::env::var_os("HEIMDALL_E2E_BIN")
            .filter(|p| !p.is_empty())
            .map_or_else(
                || PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
                PathBuf::from,
            )
    }

    /// `heimdall` in a scratch `HEIMDALL_HOME` with the debug build's test
    /// configuration (the fake adapter and the fixture profile `ops`) and a cleared
    /// environment, as `e2e_run_m02` runs it; the runtime it starts is stopped on drop
    /// through `heimdall service stop` on the same home.
    struct RunRig {
        root: PathBuf,
    }

    impl RunRig {
        fn new(root: PathBuf) -> RunRig {
            for d in ["u", "w", "h"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            std::fs::write(root.join("u").join(".gitconfig"), b"").unwrap();
            RunRig { root }
        }

        fn command(&self, args: &[&std::ffi::OsStr]) -> Command {
            let user = self.root.join("u");
            let system_root =
                std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
            let mut path = PathBuf::from(&system_root)
                .join("System32")
                .into_os_string();
            path.push(";");
            path.push(&system_root);
            let mut cmd = Command::new(heimdall_bin());
            cmd.args(args)
                .env_clear()
                .current_dir(self.root.join("w"))
                .env("HOME", &user)
                .env("USERPROFILE", &user)
                .env("HEIMDALL_HOME", self.root.join("h"))
                .env("HEIMDALL_TEST_ADAPTER", "prepare")
                .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", user.join(".gitconfig"))
                .env("PATH", path)
                .env("SystemRoot", &system_root);
            for k in ["TEMP", "TMP", "SystemDrive"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
            cmd
        }
    }

    impl Drop for RunRig {
        fn drop(&mut self) {
            let _ = self
                .command(&["service".as_ref(), "stop".as_ref()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    /// The fixture child of `windows_non_ssh_run_has_no_job_object_by_default`: run only
    /// under `heimdall run` by that test (`HM_U7_JOB_PROBE` set). It records the job it
    /// is directly in (if any) with that job's process IDs, starts a grandchild
    /// (`ping`, no creation flags) and exits normally.
    #[test]
    #[ignore = "a fixture process of windows_non_ssh_run_has_no_job_object_by_default"]
    fn windows_job_probe_child() {
        let Some(out) = std::env::var_os("HM_U7_JOB_PROBE") else {
            return;
        };
        let job = heimdall_localenv::sys::current_job_process_ids().unwrap();
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let grandchild = Command::new(Path::new(&system_root).join("System32").join("PING.EXE"))
            .args(["-n", "120", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = grandchild.id();
        let created = heimdall_localenv::sys::ProcessPin::open(pid)
            .unwrap()
            .unwrap()
            .created_at()
            .unwrap();
        // Dropping a std `Child` neither waits for nor ends it.
        drop(grandchild);
        let job = job.map_or_else(
            || "none".to_owned(),
            |ids| ids.iter().map(u32::to_string).collect::<Vec<_>>().join(","),
        );
        std::fs::write(&out, format!("{job}\n{pid} {created}\n")).unwrap();
    }

    /// §17.3 item 1 (Q18), §17.20 item 12: only a managed launch of the verified ssh gets
    /// the job; `run` of anything else keeps M02's spawn. Launched through `run`'s
    /// launch path (the real `heimdall run` of a non-ssh program, here a copy of this
    /// test binary as the fixture child): the child is in **no job of Heimdall's** —
    /// `IsProcessInJob` is false for it, or, when the test itself already runs inside a
    /// job (cargo's, or the remote session's), the child's immediate job is that
    /// enclosing one, which also holds the launcher (a job made for the child would not)
    /// — and a deliberately surviving grandchild outlives the launcher's normal exit (a
    /// kill-on-close job held by the launcher would end it).
    #[test]
    fn windows_non_ssh_run_has_no_job_object_by_default() {
        assert!(launch_uses_kill_on_close_job(true, true));
        assert!(!launch_uses_kill_on_close_job(true, false));
        assert!(!launch_uses_kill_on_close_job(false, true));
        assert!(!launch_uses_kill_on_close_job(false, false));
        let home = ScratchHome::new();
        let rig = RunRig::new(home.root.join("rig"));
        let probe = rig.root.join("job-probe.txt");
        let exe = std::env::current_exe().unwrap();
        let args: Vec<OsString> = ["--json", "run", "--profile", "ops", "--"]
            .iter()
            .map(OsString::from)
            .chain([
                exe.into_os_string(),
                "--ignored".into(),
                "--exact".into(),
                "windows::windows_job_probe_child".into(),
                "--nocapture".into(),
            ])
            .collect();
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(OsString::as_os_str).collect();
        let mut launcher = rig
            .command(&refs)
            .env("HM_U7_JOB_PROBE", &probe)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let launcher_pid = launcher.id();
        let end = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = launcher.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                // Our own child, by its handle.
                let _ = launcher.kill();
                let _ = launcher.wait();
                panic!("heimdall run did not finish within 120 s");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(status.success(), "the launcher exited normally: {status:?}");
        let text = std::fs::read_to_string(&probe).expect("the fixture child ran under run");
        let mut lines = text.lines();
        let job = lines.next().unwrap();
        let (gpid, created) = lines.next().unwrap().split_once(' ').unwrap();
        let (gpid, created): (u32, Timestamp) = (gpid.parse().unwrap(), created.parse().unwrap());
        let ambient = heimdall_localenv::sys::current_job_process_ids().unwrap();
        println!(
            "m03 observation: windows_non_ssh_run child_job={} test_in_job={}",
            if job == "none" { "none" } else { "enclosing" },
            ambient.is_some()
        );
        if job != "none" {
            let ids: Vec<u32> = job.split(',').map(|i| i.parse().unwrap()).collect();
            assert!(
                ids.contains(&launcher_pid),
                "the child's immediate job also holds the launcher: no job of Heimdall's"
            );
        }
        let survived = alive(gpid, &created);
        // Stop the grandchild by its exact PID and creation time (the test caused it).
        if let Ok(Some(pin)) = heimdall_localenv::sys::ProcessPin::open(gpid)
            && pin.created_at().as_ref() == Some(&created)
            && let Some(image) = pin.image()
            && let Some(v) = pin.verify(true, &image)
        {
            let _ = v.signal(heimdall_localenv::sys::ProcessSignal::Kill);
        }
        assert!(
            survived,
            "a grandchild outlives the launcher's normal exit (no kill-on-close job)"
        );
    }
}
