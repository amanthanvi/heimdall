//! M03-U7: connection control (m03-plan U7 "Tests", A23; ADR-0008 D8).
//!
//! **What runs where.** The Unix tests start **real** owned masters and dedicated
//! connections with the host's OpenSSH client against `heimdall_testkit::sshd::
//! LoopbackSshd` (non-root, `127.0.0.1`, ephemeral port), in the account form: an
//! explicit scratch registry holding a `cert-authority` line for a per-run test CA, for
//! exactly the pair's principal `hm:<destination>:<account>`. A disposable `ssh-agent`
//! this test starts (and stops by exact PID) holds a per-run key and its certificate;
//! it is served at the binding endpoint's path `<runtime_dir>/b/<tag>/agent.sock`, and
//! the binding's certificate is written to `<runtime_dir>/b/<tag>/cert-<dest>.pub`
//! (where U6's `binding_files_for_endpoint` finds it). The store is a real in-memory
//! `heimdall_store::Store`, seeded with a grant, its origin (the connection policy under
//! test), the destination and the binding: a **fixture** stand-in for what the
//! operations write (U10 drives the passes in production).
//!
//! **Isolation.** Every client the test runs itself gets only the isolation arguments
//! (`ScratchHome::client_command`), with the managed alias defined in the scratch user
//! configuration in P's shape (D10 item 1 as amended by §17.19 item 4; the projection
//! is the thing under test, m03-plan §0.2). The product's own command lines (the owned
//! master and `-O exit`) get the same isolation arguments through
//! `ConnectionConfig::client_args`, and carry the binding's identity options themselves.
//!
//! **Processes.** The test counts and stops only the exact PIDs it started (fixture
//! sshd and agent through their fixtures, its own `ssh`/`sleep` children through their
//! `Child`), never by name. Observation tests print `m03 observation:` lines (INT-Q4).
//!
//! **Windows:** `windows_owned_multiplexing_reported_unavailable` runs natively only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

#[cfg(unix)]
mod unix {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use heimdall_app::TimeGate;
    use heimdall_app::ports::{ConnError, ConnectionControl};
    use heimdall_contract::ids::{
        AccountName, BindingId, DestinationId, EnvironmentId, GrantId, ProfileId, WorkId,
    };
    use heimdall_contract::managed::CloseReason;
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_contract::request::{Capability, DeadlineIntent};
    use heimdall_contract::{GrantState, Timestamp};
    use heimdall_domain::binding::{BindingRecord, BindingState};
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
    use heimdall_domain::connection::{
        ConnectionPolicy, ExistingConnectionsMode, MultiplexingMode,
    };
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantSnapshot};
    use heimdall_domain::managed::{
        ConnectionKind, OwnedConnection, OwnedConnectionState, SlotState,
    };
    use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::scope::{AccessPair, Scope};
    use heimdall_domain::time::{Deadline, SyncStatus, TimePolicy};
    use heimdall_runtime::connections::{
        BindingEndpoints, CloseOutcome, ConnectionConfig, ConnectionSupervisor, DiscoveryFailed,
        master_argv, owned_row_invariant, parse_check_pid, remove_socket_if_same_inode,
        socket_inode,
    };
    use heimdall_runtime::platform::process_start_time;
    use heimdall_runtime::supervisor::FixedJitter;
    use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store};
    use heimdall_testkit::ScriptedTimeSync;
    use heimdall_testkit::agent::FixtureKey;
    use heimdall_testkit::ca::{TestCa, UserCertSpec, unix_now};
    use heimdall_testkit::home::{ClientKind, ScratchHome, find_program, ssh_config_quote};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};

    // --- fixture -------------------------------------------------------------------------

    const CHILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

    fn env_id() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn policy(existing: ExistingConnectionsMode, masters: bool) -> ConnectionPolicy {
        ConnectionPolicy {
            existing,
            multiplexing: if masters {
                MultiplexingMode::OwnedMasters
            } else {
                MultiplexingMode::Disabled
            },
        }
    }

    /// The binding-endpoint lookup over a fixture table.
    #[derive(Default)]
    struct Endpoints(Mutex<BTreeMap<BindingId, EndpointRef>>);

    impl BindingEndpoints for Endpoints {
        fn endpoint(&self, binding: &BindingId) -> Option<EndpointRef> {
            self.0.lock().unwrap().get(binding).cloned()
        }
    }

    /// A store fault hook that fails every transaction while armed (§17.20 item 13).
    #[derive(Default)]
    struct Arm(AtomicBool);

    impl FaultHook for Arm {
        fn at(&self, point: FaultPoint) -> FaultAction {
            if point == FaultPoint::BeforeTransaction && self.0.load(Ordering::SeqCst) {
                FaultAction::Fail
            } else {
                FaultAction::Continue
            }
        }
    }

    /// A disposable `ssh-agent` this test starts, stopped by exact PID on drop.
    struct Agent {
        child: Child,
        socket: PathBuf,
    }

    impl Agent {
        fn start(socket: &Path, home: &Path) -> Agent {
            let child = Command::new(find_program("ssh-agent").expect("ssh-agent"))
                .arg("-D")
                .arg("-a")
                .arg(socket)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("HOME", home)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let end = Instant::now() + Duration::from_secs(10);
            while socket_inode(socket).is_none() {
                assert!(Instant::now() < end, "ssh-agent did not bind");
                std::thread::sleep(Duration::from_millis(10));
            }
            Agent {
                child,
                socket: socket.to_path_buf(),
            }
        }

        /// `ssh-add <identity>`: the key and `<identity>-cert.pub` beside it.
        fn add(&self, identity: &Path, home: &Path) {
            let st = Command::new(find_program("ssh-add").expect("ssh-add"))
                .arg("-q")
                .arg(identity)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("HOME", home)
                .env("SSH_AUTH_SOCK", &self.socket)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(st.success(), "ssh-add");
        }
    }

    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// One managed pair: its destination, alias, mux path and P-shaped config.
    #[derive(Clone)]
    struct Pair {
        dest: DestinationId,
        alias: String,
        mux: PathBuf,
    }

    struct World {
        home: ScratchHome,
        sshd: LoopbackSshd,
        ca: TestCa,
        account: String,
        runtime_dir: PathBuf,
        store: Arc<Store>,
        /// The store's fault hook (disarmed unless a test arms it).
        faults: Arc<Arm>,
        /// The time gate over the store (system clock, synchronized time).
        gate: Arc<TimeGate>,
        endpoints: Arc<Endpoints>,
        ssh: PathBuf,
        agent: Agent,
        identity: PathBuf,
        cert_line: String,
        pairs: Vec<Pair>,
        /// Children the test itself started (stopped by exact PID on drop).
        children: Mutex<Vec<Child>>,
        /// Every binding this world created: on drop, the masters the supervisors under
        /// test recorded for them are stopped by exact identity (a panicking test leaks
        /// none).
        bindings: Mutex<Vec<BindingId>>,
        /// Fixture-owned receipts (exact PID, start token, image) of every process this
        /// world started or recorded: its children, the masters it saw started, and the
        /// loopback server's commands ([`World::remote_sleep`]). Cleanup uses them even
        /// when the store cannot be read; the drop audit checks them all.
        receipts: Mutex<Vec<Receipt>>,
        /// Pidfiles of remote commands not yet read into a receipt.
        remote_pending: Mutex<Vec<PathBuf>>,
        next: Mutex<u8>,
    }

    /// What a receipt names.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Role {
        /// A child of the test, stopped by its handle.
        Child,
        /// A master a supervisor under test started, stopped by exact identity.
        Master,
        /// A loopback-server command (`exec /bin/sleep`), stopped by exact identity.
        Remote,
    }

    /// One process's exact identity, read when the fixture started or recorded it.
    #[derive(Debug, Clone)]
    struct Receipt {
        role: Role,
        pid: u32,
        token: String,
        image: PathBuf,
    }

    /// The bound of every fixture remote command (self-terminating even if cleanup
    /// never ran); no test needs a session longer than this.
    const REMOTE_SECS: u32 = 40;

    impl Drop for World {
        fn drop(&mut self) {
            // Remote commands whose pidfile appeared but was not read yet.
            self.collect_remote(Duration::ZERO);
            // The masters the supervisors under test started and recorded: the fixture's
            // own receipts, and the store's rows when it can be read (a failure never
            // drops a receipt). Then the server's commands. Each by its exact PID, start
            // token and image (`stop_exact`), never by name; before the fixture sshd goes.
            let bindings = self
                .bindings
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let store = self.store.clone();
            let rows = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.transaction(|tx| {
                    let mut out = Vec::new();
                    for b in &bindings {
                        out.extend(tx.owned_connections_for_binding(b)?);
                    }
                    Ok(out)
                })
            }))
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
            let mut receipts = self
                .receipts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            for c in rows.iter().filter(|c| c.kind == ConnectionKind::Master) {
                if !receipts
                    .iter()
                    .any(|r| r.pid == c.pid && r.token == c.start_token)
                {
                    receipts.push(Receipt {
                        role: Role::Master,
                        pid: c.pid,
                        token: c.start_token.clone(),
                        image: PathBuf::from(&c.image),
                    });
                }
            }
            for r in receipts.iter().filter(|r| r.role != Role::Child) {
                stop_exact(r.pid, &r.token, &r.image);
            }
            // The test's own children, by their handles.
            for mut c in self
                .children
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .drain(..)
            {
                let _ = c.kill();
                let _ = c.wait();
            }
            record_receipts(&receipts);
            // The audit (§W3-C01): none of the exact identities this world started or
            // recorded survives it. Skipped while unwinding (the panic is the report).
            if !std::thread::panicking() {
                let survivors: Vec<u32> = receipts
                    .iter()
                    .filter(|r| {
                        !wait_until(Duration::from_secs(5), || {
                            process_start_time(r.pid).as_deref() != Some(r.token.as_str())
                        })
                    })
                    .map(|r| r.pid)
                    .collect();
                assert!(
                    survivors.is_empty(),
                    "processes this test started or recorded survived it: {survivors:?}"
                );
            }
        }
    }

    /// `HM_U7_RECEIPTS`: append every receipt (`<pid> <start token>`) to that file, for
    /// an exact-PID audit after the whole target ran.
    fn record_receipts(receipts: &[Receipt]) {
        use std::io::Write as _;
        let Some(path) = std::env::var_os("HM_U7_RECEIPTS") else {
            return;
        };
        let text: String = receipts
            .iter()
            .map(|r| format!("{} {}\n", r.pid, r.token))
            .collect();
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(text.as_bytes());
        }
    }

    /// Stop `pid` only if it still is the process `token` names, running `image`: the
    /// start token compared before and after the pin, then the image, through
    /// `ProcessPin::verify` (the product's own verification path). Bounded wait.
    fn stop_exact(pid: u32, token: &str, image: &Path) {
        if process_start_time(pid).as_deref() != Some(token) {
            return;
        }
        let Ok(Some(pin)) = heimdall_localenv::sys::ProcessPin::open(pid) else {
            return;
        };
        let same = process_start_time(pid).as_deref() == Some(token);
        let Some(verified) = pin.verify(same, image) else {
            return;
        };
        let _ = verified.signal(heimdall_localenv::sys::ProcessSignal::Kill);
        let end = Instant::now() + Duration::from_secs(5);
        while process_start_time(pid).as_deref() == Some(token) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    struct Opts {
        dests: &'static [&'static str],
        valid_for: u64,
    }

    impl Default for Opts {
        fn default() -> Self {
            Opts {
                dests: &["d1"],
                valid_for: 300,
            }
        }
    }

    fn world() -> World {
        world_with(Opts::default())
    }

    fn world_with(o: Opts) -> World {
        let home = ScratchHome::new();
        let ca = TestCa::generate(home.scratch()).unwrap();
        let sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                registry_seed: Some(Vec::new()),
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let account = sshd
            .login_account()
            .or_else(current_account)
            .expect("the fixture login account");
        let principals: Vec<String> = o
            .dests
            .iter()
            .map(|d| format!("hm:{d}:{account}"))
            .collect();
        let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
        sshd.append_registry_line(&ca.cert_authority_line(&refs, None))
            .unwrap();
        home.trust_host_key(&sshd.host_key_line).unwrap();

        // One key, one certificate for every pair's principal.
        let keys = home.scratch().subdir("k").unwrap();
        let key = FixtureKey::generate();
        let mut spec = UserCertSpec::for_principal(&principals[0]);
        spec.principals = principals.clone();
        spec.valid_before = unix_now() + o.valid_for;
        let files = ca.issue_files(&key, &spec, &keys, "id").unwrap();
        let cert_line = fs::read_to_string(&files.certificate).unwrap();
        let runtime_dir = home.scratch().subdir("r").unwrap();
        let b = runtime_dir.join("b");
        fs::create_dir_all(&b).unwrap();
        let agent_dir = b.join("0000000000000000");
        fs::create_dir_all(&agent_dir).unwrap();
        let agent = Agent::start(&agent_dir.join("agent.sock"), &home.git_home);
        agent.add(&files.identity, &home.git_home);

        let faults = Arc::new(Arm::default());
        let store = Arc::new(Store::open_in_memory(faults.clone()).unwrap());
        let gate = Arc::new(TimeGate::new(
            store.clone(),
            Arc::new(heimdall_runtime::platform::SystemClock::new()),
            ScriptedTimeSync::new(SyncStatus::Synchronized),
            TimePolicy::default(),
        ));
        let mut pairs = Vec::new();
        let mut config = String::new();
        for d in o.dests {
            let dest = DestinationId::parse(d).unwrap();
            let alias = format!("hm-u7-{d}");
            let mux = runtime_dir.join("mux").join(d);
            let slot = home.root.join("managed").join(d);
            fs::create_dir_all(&slot).unwrap();
            fs::write(slot.join("cert.pub"), &cert_line).unwrap();
            // P's managed section (D10 item 1 with §17.19 item 4's identity form, owned
            // masters enabled: the slot's stable mux path).
            config.push_str(&format!(
                "Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  User {account}\n  IdentityAgent {agent}\n  IdentitiesOnly yes\n  IdentityFile {cert}\n  ControlMaster no\n  ControlPath {mux}\n",
                port = sshd.port,
                agent = ssh_config_quote(&agent.socket.to_string_lossy()),
                cert = ssh_config_quote(&slot.join("cert.pub").to_string_lossy()),
                mux = ssh_config_quote(&mux.to_string_lossy()),
            ));
            // The same alias as a dedicated connection's command line has it (`connect`:
            // `ControlMaster=no`, `ControlPath=none`).
            config.push_str(&format!(
                "Host {alias}-direct\n  HostName 127.0.0.1\n  Port {port}\n  User {account}\n  IdentityAgent {agent}\n  IdentitiesOnly yes\n  IdentityFile {cert}\n  ControlMaster no\n  ControlPath none\n",
                port = sshd.port,
                agent = ssh_config_quote(&agent.socket.to_string_lossy()),
                cert = ssh_config_quote(&slot.join("cert.pub").to_string_lossy()),
            ));
            store
                .transaction(|tx| {
                    tx.upsert_destination(&DestinationRecord {
                        id: dest.clone(),
                        alias: alias.clone(),
                        revision: 1,
                        definition: DestinationDefinition::Observed,
                        label: None,
                        updated_at: Timestamp::now(),
                    })
                })
                .unwrap();
            pairs.push(Pair { dest, alias, mux });
        }
        home.write_user_config(&config).unwrap();
        World {
            home,
            sshd,
            ca,
            account,
            runtime_dir,
            store,
            faults,
            gate,
            endpoints: Arc::new(Endpoints::default()),
            ssh: find_program("ssh").expect("ssh"),
            agent,
            identity: files.identity,
            cert_line,
            pairs,
            children: Mutex::new(Vec::new()),
            bindings: Mutex::new(Vec::new()),
            receipts: Mutex::new(Vec::new()),
            remote_pending: Mutex::new(Vec::new()),
            next: Mutex::new(1),
        }
    }

    impl World {
        fn n(&self) -> u8 {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        }

        /// Keep a receipt of `pid` (read now) in `role` with `image`.
        fn receipt(&self, role: Role, pid: u32, image: &Path) {
            if let Some(token) = process_start_time(pid) {
                self.receipts
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Receipt {
                        role,
                        pid,
                        token,
                        image: image.to_path_buf(),
                    });
            }
        }

        /// A master a supervisor under test started: its receipt, from the row.
        fn track(&self, m: &OwnedConnection) {
            self.receipts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Receipt {
                    role: Role::Master,
                    pid: m.pid,
                    token: m.start_token.clone(),
                    image: PathBuf::from(&m.image),
                });
        }

        /// A self-terminating remote command for the loopback server: it writes its
        /// own PID to a fixture pidfile, then `exec`s `/bin/sleep <REMOTE_SECS>` (same
        /// PID). [`World::collect_remote`] turns the pidfile into an exact receipt.
        fn remote_sleep(&self) -> String {
            let n = self.n();
            let pidfile = self.home.root.join(format!("remote-{n}.pid"));
            self.remote_pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(pidfile.clone());
            format!(
                "echo $$ > {}; exec /bin/sleep {REMOTE_SECS}",
                heimdall_testkit::home::sh_quote(pidfile.as_os_str())
            )
        }

        /// Read the pending remote pidfiles into receipts, waiting up to `bound` for
        /// each to appear (the command runs only once its session is admitted).
        fn collect_remote(&self, bound: Duration) {
            let pending: Vec<PathBuf> = self
                .remote_pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .drain(..)
                .collect();
            for f in pending {
                let mut pid = None;
                wait_until(bound, || {
                    pid = fs::read_to_string(&f)
                        .ok()
                        .and_then(|t| t.trim().parse::<u32>().ok());
                    pid.is_some()
                });
                match pid {
                    Some(pid) => {
                        // The pidfile is written just before the `exec`: wait (bounded)
                        // until the process runs the image the receipt names, so exact
                        // cleanup never meets the shell in its place.
                        let sleep = fs::canonicalize("/bin/sleep").ok();
                        wait_until(Duration::from_secs(5), || {
                            heimdall_localenv::sys::ProcessPin::open(pid)
                                .ok()
                                .flatten()
                                .and_then(|p| p.image())
                                == sleep
                        });
                        self.receipt(Role::Remote, pid, Path::new("/bin/sleep"));
                    }
                    None if bound.is_zero() => {}
                    None => self
                        .remote_pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(f),
                }
            }
        }

        /// A long-running ordinary client the test owns whose remote command is a
        /// tracked [`World::remote_sleep`]; returns the client's exact PID once the
        /// remote command runs.
        fn spawn_remote_sleep(&self, alias: &str) -> u32 {
            let command = self.remote_sleep();
            let pid = self.spawn_ordinary(alias, &[&command]);
            self.collect_remote(Duration::from_secs(20));
            pid
        }

        fn config(&self) -> ConnectionConfig {
            let mut c = ConnectionConfig::new(
                self.runtime_dir.clone(),
                self.ssh.clone(),
                self.endpoints.clone(),
                Arc::new(FixedJitter(0.0)),
            );
            c.client_args = self.home.isolation_args();
            c.client_env = Some(vec![
                (OsString::from("PATH"), OsString::from(CHILD_PATH)),
                (
                    OsString::from("HOME"),
                    self.home.git_home.clone().into_os_string(),
                ),
            ]);
            c.close_grace = Duration::from_secs(5);
            c.time_gate = Some(self.gate.clone());
            c
        }

        fn supervisor(&self) -> ConnectionSupervisor {
            ConnectionSupervisor::new(self.store.clone(), None, self.config())
        }

        /// A grant with `policy` in its origin and a binding on it whose endpoint (and
        /// certificate) are in `<runtime_dir>/b/<tag>/`. `endpoint: false` gives the
        /// binding an endpoint path where no agent listens.
        fn grant(&self, policy: ConnectionPolicy, endpoint: bool) -> (GrantId, BindingId) {
            let deadline = Timestamp::now()
                .checked_add(jiff::SignedDuration::from_hours(2))
                .unwrap();
            self.grant_until(policy, endpoint, deadline)
        }

        /// As [`World::grant`], with the grant's absolute deadline `deadline`; the grant
        /// is anchored by the time gate with that bound (as its first validation does).
        fn grant_until(
            &self,
            policy: ConnectionPolicy,
            endpoint: bool,
            deadline: Timestamp,
        ) -> (GrantId, BindingId) {
            let n = self.n();
            let g = GrantSnapshot {
                id: GrantId::from_random_bytes([n; 16]),
                environment: env_id(),
                scope: Scope {
                    pairs: self
                        .pairs
                        .iter()
                        .map(|p| AccessPair {
                            destination: p.dest.clone(),
                            account: AccountName::parse("u").unwrap(),
                        })
                        .collect(),
                    capabilities: [Capability::SshAuthentication].into_iter().collect(),
                },
                starts_at: Timestamp::now(),
                deadline: Deadline {
                    intent: DeadlineIntent::Duration("2h".into()),
                    resolved_at: Timestamp::now(),
                    effective: deadline,
                },
                parent: None,
                source: AuthorizationSource::StandingPolicy {
                    revision: PolicyRevision(1),
                },
                generation: AuthorityGeneration(0),
                state: GrantState::Active,
                enforcement: EnforcementEvidence::unknown(),
            };
            let caller = CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            };
            let b = BindingRecord {
                id: BindingId::from_random_bytes([n; 16]),
                environment: env_id(),
                grant: g.id.clone(),
                work_id: WorkId::parse(&format!("w{n}")).unwrap(),
                owner: caller.clone(),
                profile: ProfileId::parse("dev").unwrap(),
                profile_revision: 1,
                scope: g.scope.clone(),
                mechanism: "managed_certificate".into(),
                parent: None,
                created_at: Timestamp::now(),
                released_at: None,
                state: BindingState::Active,
            };
            let origin = GrantOrigin {
                profile: ProfileId::parse("dev").unwrap(),
                profile_revision: 1,
                policy_revision: None,
                caller,
                mechanism: "managed_certificate".into(),
                covered: None,
                adapter: None,
                lock_behavior: None,
                connection: (!policy.is_default()).then_some(policy),
            };
            let (gid, bid) = (g.id.clone(), b.id.clone());
            self.bindings
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(bid.clone());
            self.store
                .transaction(|tx| {
                    tx.insert_grant(&g)?;
                    tx.set_grant_origin(&g.id, &origin)?;
                    tx.insert_binding(&b)
                })
                .unwrap();
            let rt = rt();
            let safe = rt.block_on(self.gate.check()).unwrap();
            rt.block_on(self.gate.anchor_grant(&gid, &safe, deadline))
                .unwrap();
            let tag = format!("{n:016x}");
            let dir = self.runtime_dir.join("b").join(&tag);
            fs::create_dir_all(&dir).unwrap();
            for p in &self.pairs {
                fs::write(
                    dir.join(format!("cert-{}.pub", p.dest.as_str())),
                    &self.cert_line,
                )
                .unwrap();
            }
            fs::write(dir.join("key.pub"), "unused\n").unwrap();
            let socket = dir.join("agent.sock");
            if endpoint {
                std::os::unix::fs::symlink(&self.agent.socket, &socket).unwrap();
            }
            self.endpoints.0.lock().unwrap().insert(
                bid.clone(),
                EndpointRef {
                    kind: EndpointKind::UnixSocket,
                    locator: socket.to_string_lossy().into_owned(),
                },
            );
            (gid, bid)
        }

        /// Make `b` the holder of pair `i`'s environment slot (D10 item 2): a slot held
        /// by another binding is released and its files removed first (a transfer).
        fn hold(&self, b: &BindingId, i: usize) {
            let pair = self.pair(i);
            self.store
                .transaction(|tx| {
                    let now = Timestamp::now();
                    if let SlotState::Held {
                        binding,
                        generation,
                    } = tx.slot(&env_id(), &pair)?
                    {
                        if binding == *b {
                            return Ok(());
                        }
                        tx.release_slot(&env_id(), &pair, &binding, generation, now)?
                            .unwrap();
                        tx.slot_files_removed(&env_id(), &pair, generation, now)?
                            .unwrap();
                    }
                    tx.claim_slot(&env_id(), &pair, b, now)?.unwrap();
                    Ok(())
                })
                .unwrap();
        }

        /// `b` holds pair `i`'s slot, then its master starts.
        fn start(
            &self,
            sup: &ConnectionSupervisor,
            rt: &tokio::runtime::Runtime,
            b: &BindingId,
            i: usize,
        ) -> OwnedConnection {
            self.hold(b, i);
            let m = rt.block_on(sup.start_master(b, &self.pair(i))).unwrap();
            self.track(&m);
            m
        }

        /// The binding directory of `b` (its endpoint, `key.pub`, `cert-<dest>.pub`).
        fn binding_dir(&self, b: &BindingId) -> PathBuf {
            let endpoint = self.endpoints.0.lock().unwrap().get(b).cloned().unwrap();
            PathBuf::from(endpoint.locator)
                .parent()
                .unwrap()
                .to_path_buf()
        }

        /// A master **this test** starts at pair `i`'s stable path with `b`'s identity,
        /// outside the supervisor's ownership records (the probes' foreign master).
        /// Returns its exact PID once its control socket answers.
        fn foreign_master(&self, b: &BindingId, i: usize) -> u32 {
            let dir = self.binding_dir(b);
            let endpoint = self.endpoints.0.lock().unwrap().get(b).cloned().unwrap();
            let p = &self.pairs[i];
            let argv = master_argv(
                &p.mux,
                &p.alias,
                &endpoint,
                &dir.join("key.pub"),
                &dir.join(format!("cert-{}.pub", p.dest.as_str())),
                &self.home.isolation_args(),
            )
            .unwrap();
            let child = Command::new(&self.ssh)
                .args(&argv)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("HOME", &self.home.git_home)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            self.children.lock().unwrap().push(child);
            self.receipt(Role::Child, pid, &self.ssh);
            assert!(
                wait_until(Duration::from_secs(20), || self
                    .master_pid(&p.alias, &p.mux)
                    == Some(pid)),
                "the probe's own master answers at the stable path"
            );
            pid
        }

        fn pair(&self, i: usize) -> AccessPair {
            AccessPair {
                destination: self.pairs[i].dest.clone(),
                account: AccountName::parse("u").unwrap(),
            }
        }

        fn end_grant(&self, g: &GrantId, state: GrantState) {
            self.store
                .transaction(|tx| {
                    let mut s = tx.grant(g)?.unwrap();
                    s.state = state;
                    tx.update_grant_state(&s)
                })
                .unwrap();
        }

        fn row(&self, id: &heimdall_contract::ids::ConnectionId) -> OwnedConnection {
            self.store
                .transaction(|tx| tx.owned_connection(id))
                .unwrap()
                .unwrap()
        }

        /// The number of certificate authentications the fixture sshd accepted.
        fn auths(&self) -> usize {
            self.sshd.accepted_certificates().len()
        }

        /// An ordinary client run of `alias` with `remote`, through the isolation
        /// arguments only (P decides master or direct).
        fn ordinary(&self, alias: &str, remote: &[&str]) -> std::process::Output {
            let mut cmd = self.home.client_command(ClientKind::Ssh, alias).unwrap();
            cmd.args(remote).stdin(Stdio::null());
            let out = cmd.output().unwrap();
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
            out
        }

        /// A long-running ordinary client the test owns (exact PID).
        fn spawn_ordinary(&self, alias: &str, remote: &[&str]) -> u32 {
            let mut cmd = self.home.client_command(ClientKind::Ssh, alias).unwrap();
            cmd.args(remote)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child = cmd.spawn().unwrap();
            let pid = child.id();
            self.children.lock().unwrap().push(child);
            self.receipt(Role::Child, pid, &self.ssh);
            pid
        }

        /// Reap a child the test started, if it has exited.
        fn reap(&self, pid: u32) -> Option<std::process::ExitStatus> {
            let mut children = self.children.lock().unwrap();
            let i = children.iter().position(|c| c.id() == pid)?;
            children[i].try_wait().ok().flatten()
        }

        /// A dedicated connection: the verified client running `sleep <secs>` remotely,
        /// in the foreground, its row written as U0b row 19 writes it at bind (kind
        /// `dedicated`, the holder's PID and start token, the expected image). Waits
        /// until the server accepted its authentication.
        fn dedicated(&self, g: &GrantId, b: &BindingId, alias: &str) -> OwnedConnection {
            let before = self.auths();
            let pid = self.spawn_remote_sleep(alias);
            let end = Instant::now() + Duration::from_secs(20);
            while self.auths() == before {
                assert!(
                    Instant::now() < end,
                    "the dedicated connection never authenticated"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            self.row_for(
                g,
                b,
                pid,
                ConnectionKind::Dedicated,
                &self.ssh.to_string_lossy(),
            )
        }

        fn row_for(
            &self,
            g: &GrantId,
            b: &BindingId,
            pid: u32,
            kind: ConnectionKind,
            image: &str,
        ) -> OwnedConnection {
            let c = OwnedConnection {
                id: heimdall_contract::ids::ConnectionId::from_random_bytes([self.n(); 16]),
                kind,
                binding: b.clone(),
                grant: g.clone(),
                pid,
                start_token: process_start_time(pid).unwrap(),
                image: image.to_owned(),
                control_path: None,
                generation: 0,
                state: OwnedConnectionState::Up,
                started_at: Timestamp::now(),
            };
            self.store
                .transaction(|tx| {
                    // U0b row 19: the launch binding's holder is the row's own process,
                    // recorded before the row (U7-Q4: a dedicated row needs it).
                    tx.set_binding_holder(b, &holder_of(&c))?;
                    tx.insert_owned_connection(&c)
                })
                .unwrap();
            c
        }

        /// Spawn `program args` as a fixture child (exact PID).
        fn spawn(&self, program: &str, args: &[&str]) -> u32 {
            let child = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            self.children.lock().unwrap().push(child);
            self.receipt(Role::Child, pid, Path::new(program));
            pid
        }

        /// `ssh -O check` through `mux`: the PID of the master answering there.
        fn master_pid(&self, alias: &str, mux: &Path) -> Option<u32> {
            let mut fresh = Command::new(&self.ssh);
            fresh
                .args(self.home.isolation_args())
                .arg("-O")
                .arg("check")
                .arg("-o")
                .arg(format!("ControlPath={}", mux.display()))
                .arg(alias)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("HOME", &self.home.git_home)
                .stdin(Stdio::null());
            let out = fresh.output().ok()?;
            if !out.status.success() {
                return None;
            }
            parse_check_pid(&String::from_utf8_lossy(&out.stderr))
        }

        /// `ssh -O check` through `mux`: whether a master answers there.
        fn master_answers(&self, alias: &str, mux: &Path) -> bool {
            let mut cmd = self.home.client_command(ClientKind::Ssh, alias).unwrap();
            // `-O check` is a control command; it must precede the destination.
            let args: Vec<OsString> = cmd.get_args().map(OsString::from).collect();
            let mut fresh = Command::new(&self.ssh);
            fresh
                .args(&args[..args.len() - 1])
                .arg("-O")
                .arg("check")
                .arg("-o")
                .arg(format!("ControlPath={}", mux.display()))
                .arg(alias)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("HOME", &self.home.git_home)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = &mut cmd;
            fresh.status().map(|s| s.success()).unwrap_or(false)
        }
    }

    /// The grant's stored integration as `prepare` records it, naming `ssh` as the
    /// verified client (the input of U0b row 19's `verified_client_image`).
    fn prepared_facts(ssh: &Path) -> heimdall_domain::catalog::PreparedFacts {
        heimdall_domain::catalog::PreparedFacts {
            provider: None,
            executables: vec![heimdall_contract::request::ConsumerExecutable {
                consumer: heimdall_contract::request::ConsumerKind::Ssh,
                path: ssh.to_string_lossy().into_owned(),
                version: None,
                sha256: None,
                basis: heimdall_contract::provider::EvidenceBasis::Observed,
            }],
            overrides: Vec::new(),
            environment: Vec::new(),
            pairs: Vec::new(),
            recorded_at: Timestamp::now(),
        }
    }

    /// The launch binding's holder as U0b row 19 records it for a dedicated row: the
    /// row's own exact process (PID and start token).
    fn holder_of(c: &OwnedConnection) -> heimdall_domain::holder::ProcessHolder {
        heimdall_domain::holder::ProcessHolder {
            pid: c.pid,
            started_at: c.start_token.clone(),
        }
    }

    fn alive(pid: u32, token: &str) -> bool {
        process_start_time(pid).as_deref() == Some(token)
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

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn graceful_masters() -> ConnectionPolicy {
        policy(ExistingConnectionsMode::Graceful, true)
    }

    // --- positive ------------------------------------------------------------------------

    /// A23: an owned master admits ordinary sessions through P's mux path before the
    /// deadline, with no new authentication per session.
    #[test]
    fn owned_master_admits_sessions_before_deadline() {
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let before = w.auths();
        let m = w.start(&sup, &rt, &b, 0);
        assert_eq!(m.kind, ConnectionKind::Master);
        assert_eq!(w.auths(), before + 1, "the master authenticated once");
        for _ in 0..3 {
            let out = w.ordinary(&w.pairs[0].alias, &["true"]);
            assert!(out.status.success(), "a session through the master");
        }
        assert_eq!(w.auths(), before + 1, "sessions shared the master");
        let r = rt.block_on(sup.shutdown());
        assert_eq!(r.closed, vec![m.id.clone()]);
    }

    /// D8 item 2 table: under `graceful` the deadline keeps the owned dedicated
    /// connection; a new authentication after the certificate's `valid_before` is
    /// refused by the server (the server-side enforcement point, D7 item 1).
    #[test]
    fn graceful_keeps_dedicated_connection_after_deadline_and_new_auth_refused() {
        let w = world_with(Opts {
            valid_for: 8,
            ..Opts::default()
        });
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Graceful, false), true);
        let alias = format!("{}-direct", w.pairs[0].alias);
        let c = w.dedicated(&g, &b, &alias);
        // Past the certificate's validity, and the grant's deadline.
        std::thread::sleep(Duration::from_secs(9));
        w.end_grant(&g, GrantState::Expired);
        let sup = w.supervisor();
        let r = rt()
            .block_on(sup.connection_deadline_pass(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.kept, vec![c.id.clone()]);
        assert!(alive(c.pid, &c.start_token), "graceful keeps the session");
        assert_eq!(w.row(&c.id).state, OwnedConnectionState::Up);
        let out = w.ordinary(&alias, &["true"]);
        assert!(!out.status.success(), "a new authentication is refused");
    }

    /// D8 item 2 table: under `strict` the deadline closes the owned dedicated
    /// connection (SIGTERM to the verified PID).
    #[test]
    fn strict_closes_dedicated_connection_at_deadline() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        let c = w.dedicated(&g, &b, &format!("{}-direct", w.pairs[0].alias));
        w.end_grant(&g, GrantState::Expired);
        let r = rt()
            .block_on(
                w.supervisor()
                    .connection_deadline_pass(std::slice::from_ref(&g)),
            )
            .unwrap();
        assert_eq!(r.closed, vec![c.id.clone()]);
        assert!(wait_until(Duration::from_secs(5), || w
            .reap(c.pid)
            .is_some()));
        assert_eq!(w.row(&c.id).state, OwnedConnectionState::Closed);
    }

    /// D7 item 2 step 4: revocation closes owned dedicated connections under both
    /// policies.
    #[test]
    fn revocation_closes_dedicated_under_both_policies() {
        let w = world();
        let sup = w.supervisor();
        let rt = rt();
        for mode in [
            ExistingConnectionsMode::Graceful,
            ExistingConnectionsMode::Strict,
        ] {
            let (g, b) = w.grant(policy(mode, false), true);
            let c = w.dedicated(&g, &b, &format!("{}-direct", w.pairs[0].alias));
            w.end_grant(&g, GrantState::Revoked);
            let r = rt
                .block_on(sup.revocation_close(std::slice::from_ref(&g)))
                .unwrap();
            assert_eq!(r.closed, vec![c.id.clone()], "{mode:?}");
            assert!(wait_until(Duration::from_secs(5), || w
                .reap(c.pid)
                .is_some()));
            assert_eq!(w.row(&c.id).state, OwnedConnectionState::Closed);
        }
    }

    /// M-F5: an ordinary client uses the owned master when one is live at P's path,
    /// and connects directly (one new authentication) otherwise.
    #[test]
    fn ordinary_client_uses_owned_master_when_present_direct_otherwise() {
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let alias = w.pairs[0].alias.clone();
        let a0 = w.auths();
        assert!(w.ordinary(&alias, &["true"]).status.success());
        assert_eq!(w.auths(), a0 + 1, "no master: direct");
        let m = w.start(&sup, &rt, &b, 0);
        let a1 = w.auths();
        assert!(w.ordinary(&alias, &["true"]).status.success());
        assert_eq!(w.auths(), a1, "master present: multiplexed");
        rt.block_on(sup.close(&m, CloseReason::OwnerRequest))
            .unwrap();
        assert!(w.ordinary(&alias, &["true"]).status.success());
        assert_eq!(w.auths(), a1 + 1, "master gone: direct again");
    }

    /// §17.1 item 16: two successive bindings of one pair share the slot's stable mux
    /// path; the old master is closed before the new one starts, and ordinary ssh uses
    /// whichever master is live there.
    #[test]
    fn two_successive_bindings_share_the_slot_mux_path_through_ordinary_ssh() {
        let w = world();
        let sup = w.supervisor();
        let rt = rt();
        let (_g1, b1) = w.grant(graceful_masters(), true);
        let (_g2, b2) = w.grant(graceful_masters(), true);
        let m1 = w.start(&sup, &rt, &b1, 0);
        let path = w.pairs[0].mux.clone();
        assert_eq!(m1.control_path.as_deref(), Some(path.to_str().unwrap()));
        let m2 = w.start(&sup, &rt, &b2, 0);
        assert_eq!(m2.control_path, m1.control_path, "one stable path");
        assert!(m2.generation > m1.generation, "a new generation");
        assert_eq!(w.row(&m1.id).state, OwnedConnectionState::Closed);
        assert!(!alive(m1.pid, &m1.start_token), "the old master is gone");
        // The protocol, never inode numbers (W3-N01): the listener at the path is m2.
        assert_eq!(
            w.master_pid(&w.pairs[0].alias, &path),
            Some(m2.pid),
            "the new holder's master answers at the stable path"
        );
        let a = w.auths();
        assert!(w.ordinary(&w.pairs[0].alias, &["true"]).status.success());
        assert_eq!(w.auths(), a, "ordinary ssh used the new holder's master");
        rt.block_on(sup.shutdown());
    }

    /// D8 items 1 and 3: owned masters need the widening in **both** the grant's origin
    /// and every current policy (a decision record and `setup apply`); until then
    /// `start_master` refuses and P renders `ControlPath none`.
    #[test]
    fn enabling_masters_needs_decision_and_setup_apply() {
        use heimdall_sshconf::render::{
            AliasName, HostName, ManagedIdentityForm, PathStyle, RenderPath, Section,
            render_sections,
        };
        let w = world();
        let sup = w.supervisor();
        let rt = rt();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Graceful, false), true);
        assert_eq!(
            rt.block_on(sup.start_master(&b, &w.pair(0))).unwrap_err(),
            heimdall_app::ports::ConnError::Unavailable("owned_masters_disabled".into())
        );
        assert_eq!(
            rt.block_on(sup.effective_policy(&g)).multiplexing,
            MultiplexingMode::Disabled
        );
        // The widening as a policy action is a decision (U0b row 11).
        assert!(
            heimdall_contract::request::PolicyAction::SetConnectionPolicy {
                policy_id: heimdall_contract::ids::PolicyId::parse("p").unwrap(),
                existing: None,
                multiplexing: Some(MultiplexingMode::OwnedMasters),
            }
            .is_widening()
        );
        // P while masters are disabled: `ControlPath none`; once applied: the path.
        let section = |control_path: Option<RenderPath>| Section::ManagedCertificate {
            alias: AliasName::parse("hm-u7-d1").unwrap(),
            hostname: HostName::parse("127.0.0.1").unwrap(),
            port: Some(22),
            user: "u".into(),
            endpoint: RenderPath::unix(Path::new("/r/e.sock")).unwrap(),
            key_pub: RenderPath::unix(Path::new("/d/managed/d1/key.pub")).unwrap(),
            cert: RenderPath::unix(Path::new("/d/managed/d1/cert.pub")).unwrap(),
            control_path,
        };
        let off = String::from_utf8(
            render_sections(
                &[section(None)],
                PathStyle::Unix,
                ManagedIdentityForm::select(None),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(off.contains("ControlPath none"), "{off}");
        let on = String::from_utf8(
            render_sections(
                &[section(Some(
                    RenderPath::unix(Path::new("/r/mux/d1")).unwrap(),
                ))],
                PathStyle::Unix,
                ManagedIdentityForm::select(None),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(on.contains("ControlPath \"/r/mux/d1\""), "{on}");
        // With the widening recorded in the origin: started.
        let (_g2, b2) = w.grant(graceful_masters(), true);
        let m = w.start(&sup, &rt, &b2, 0);
        assert_eq!(m.kind, ConnectionKind::Master);
        rt.block_on(sup.shutdown());
    }

    // --- Unix ownership ------------------------------------------------------------------

    /// D8 item 2 (Unix): the connection row names the holder process itself (the launcher
    /// execs the client), with the verified client's image; the supervisor verifies that
    /// identity (start token from `platform.rs`, image by `proc_pidpath`/`/proc`) and
    /// would not verify any other image for the same process.
    #[test]
    fn unix_connection_row_is_holder_pid_with_verified_image() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        let c = w.dedicated(&g, &b, &format!("{}-direct", w.pairs[0].alias));
        let image = heimdall_app::operations::verified_client_image(
            Some(&prepared_facts(&w.ssh)),
            &w.ssh.to_string_lossy(),
        );
        assert_eq!(
            image.as_deref(),
            Some(c.image.as_str()),
            "the expected image"
        );
        let pin = heimdall_localenv::sys::ProcessPin::open(c.pid)
            .unwrap()
            .unwrap();
        assert_eq!(pin.image().unwrap(), fs::canonicalize(&w.ssh).unwrap());
        assert!(pin.verify(true, &w.ssh).is_some());
        let pin = heimdall_localenv::sys::ProcessPin::open(c.pid)
            .unwrap()
            .unwrap();
        assert!(
            pin.verify(true, Path::new("/bin/sh")).is_none(),
            "another image"
        );
        let r = rt()
            .block_on(w.supervisor().revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.closed, vec![c.id]);
    }

    /// D8 item 2 (Unix, §17.4 item 8): a launcher whose exec failed is still running its
    /// own image: the row's start token matches, the image does not, so it is never
    /// signalled (it stays `closing`, checked again by the next pass).
    #[test]
    fn unix_failed_exec_is_not_an_owned_connection() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        // A fixture process standing in for the launcher after a failed exec: its image
        // is not the client.
        let pid = w.spawn("/bin/sleep", &["30"]);
        assert!(wait_until(Duration::from_secs(2), || process_start_time(
            pid
        )
        .is_some()));
        let c = w.row_for(
            &g,
            &b,
            pid,
            ConnectionKind::Dedicated,
            &w.ssh.to_string_lossy(),
        );
        let sup = w.supervisor();
        let outcome = rt().block_on(sup.close_one(&c));
        assert_eq!(outcome, CloseOutcome::Pending);
        assert!(alive(c.pid, &c.start_token), "never signalled");
        assert_eq!(w.row(&c.id).state, OwnedConnectionState::Closing);
    }

    /// §17.4 item 8 (B R2-12): a revocation between bind and exec finds the row but does
    /// not signal the launcher (still `/bin/sh` here); once the exec has happened, the
    /// next pass verifies the client image and closes it.
    #[test]
    fn unix_revoke_between_bind_and_exec_not_signalled_then_closed_after_exec() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Graceful, false), true);
        let marker = w.home.root.join("exec-now");
        // The "launcher": waits for the marker, then execs the verified client (same PID,
        // same start time), as `run` does after its pause point.
        let mut client_words: Vec<String> = w
            .home
            .isolation_args()
            .iter()
            .map(|a| heimdall_testkit::home::sh_quote(a))
            .collect();
        client_words.push(format!("{}-direct", w.pairs[0].alias));
        client_words.push(heimdall_testkit::home::sh_quote(std::ffi::OsStr::new(
            &w.remote_sleep(),
        )));
        let script = format!(
            "while [ ! -e {m} ]; do sleep 0.05; done; exec {ssh} {args}",
            m = heimdall_testkit::home::sh_quote(marker.as_os_str()),
            ssh = heimdall_testkit::home::sh_quote(w.ssh.as_os_str()),
            args = client_words.join(" ")
        );
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &w.home.git_home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        w.children.lock().unwrap().push(child);
        w.receipt(Role::Child, pid, Path::new("/bin/sh"));
        assert!(wait_until(Duration::from_secs(2), || process_start_time(
            pid
        )
        .is_some()));
        let c = w.row_for(
            &g,
            &b,
            pid,
            ConnectionKind::Dedicated,
            &w.ssh.to_string_lossy(),
        );
        w.end_grant(&g, GrantState::Revoked);
        let sup = w.supervisor();
        let rt = rt();
        let r = rt
            .block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.pending, vec![c.id.clone()], "not signalled before exec");
        assert!(alive(pid, &c.start_token));
        let before = w.auths();
        fs::write(&marker, b"").unwrap();
        assert!(
            wait_until(Duration::from_secs(20), || w.auths() > before),
            "the exec'd client authenticated"
        );
        w.collect_remote(Duration::from_secs(20));
        let r = rt
            .block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.closed, vec![c.id.clone()], "closed after exec");
        assert!(wait_until(Duration::from_secs(5), || w.reap(pid).is_some()));
        assert_eq!(w.row(&c.id).state, OwnedConnectionState::Closed);
    }

    /// §17.4 item 7: the master's command line pins `ForkAfterAuthentication=no` first
    /// (`OWNED_LAUNCH_PINS[0..2]`, never retyped) and never carries `-f`; the running
    /// master is the supervisor's foreground child.
    #[test]
    fn owned_master_pins_fork_after_authentication_no() {
        let argv = master_argv(
            Path::new("/r/mux/d1"),
            "hm-u7-d1",
            &EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: "/r/b/0123456789abcdef/agent.sock".into(),
            },
            Path::new("/r/b/0123456789abcdef/key.pub"),
            Path::new("/r/b/0123456789abcdef/cert-d1.pub"),
            &[],
        )
        .unwrap();
        let words: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            words[..2],
            heimdall_sshconf::render::OWNED_LAUNCH_PINS[0..2]
        );
        assert_eq!(words[1], "ForkAfterAuthentication=no");
        assert!(
            !words
                .iter()
                .any(|w| w.starts_with("-f") || w.contains("ControlPersist=yes"))
        );
        for want in [
            "-M",
            "-N",
            "ControlMaster=yes",
            "ControlPersist=no",
            "ControlPath=\"/r/mux/d1\"",
            "IdentityAgent=\"/r/b/0123456789abcdef/agent.sock\"",
            "IdentitiesOnly=yes",
            "IdentityFile=\"/r/b/0123456789abcdef/cert-d1.pub\"",
            "ClearAllForwardings=yes",
            "ExitOnForwardFailure=yes",
            "BatchMode=yes",
        ] {
            assert!(words.iter().any(|w| w == want), "{want} in {words:?}");
        }
        assert!(
            !words.iter().any(|w| w.contains("key.pub")),
            "R3: never key.pub"
        );
        assert!(!words.iter().any(|w| w.starts_with("CertificateFile")));
        assert_eq!(words[words.len() - 2..], ["--", "hm-u7-d1"]);
        // And the live master stays the foreground child: its PID is the one recorded.
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &b, 0);
        assert_eq!(rt.block_on(sup.live_master_pids()), vec![m.pid]);
        assert!(alive(m.pid, &m.start_token));
        rt.block_on(sup.shutdown());
    }

    // --- negative ------------------------------------------------------------------------

    /// D8 item 3: at the deadline the master is closed under `graceful` too; a new
    /// session through the mux path finds no master.
    #[test]
    fn owned_master_closed_at_deadline_new_mux_session_refused() {
        let w = world();
        let (g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &b, 0);
        let mux = w.pairs[0].mux.clone();
        assert!(w.master_answers(&w.pairs[0].alias, &mux));
        w.end_grant(&g, GrantState::Expired);
        let r = rt
            .block_on(sup.connection_deadline_pass(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.closed, vec![m.id.clone()]);
        assert!(!alive(m.pid, &m.start_token));
        assert!(!mux.exists(), "socket removed (same inode)");
        assert!(!w.master_answers(&w.pairs[0].alias, &mux), "no mux session");
        assert_eq!(w.row(&m.id).state, OwnedConnectionState::Closed);
    }

    /// The E7P pattern (ADR-0005 §3.8): a session accepted through the master before the
    /// close ends with the master.
    #[test]
    fn preaccepted_control_connection_closed_with_master() {
        let w = world();
        let (g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &b, 0);
        let a = w.auths();
        let session = w.spawn_remote_sleep(&w.pairs[0].alias);
        std::thread::sleep(Duration::from_millis(800));
        assert!(
            w.reap(session).is_none(),
            "the session runs through the master"
        );
        assert_eq!(w.auths(), a, "multiplexed");
        rt.block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert!(
            wait_until(Duration::from_secs(10), || w.reap(session).is_some()),
            "the pre-accepted session ended with the master"
        );
        assert_eq!(w.row(&m.id).state, OwnedConnectionState::Closed);
    }

    /// D8 item 4: P is read first, so a user `Host * ControlMaster auto` creates no
    /// unmanaged master for a managed alias.
    #[test]
    fn user_controlmaster_ignored_for_managed_alias() {
        let w = world();
        let user_mux = w.home.root.join("um");
        let text = fs::read_to_string(&w.home.user_config).unwrap();
        fs::write(
            &w.home.user_config,
            format!(
                "{text}Host *\n  ControlMaster auto\n  ControlPersist 60\n  ControlPath {}\n",
                ssh_config_quote(&user_mux.to_string_lossy())
            ),
        )
        .unwrap();
        assert!(w.ordinary(&w.pairs[0].alias, &["true"]).status.success());
        assert!(!user_mux.exists(), "no user master for the managed alias");
        assert!(!w.pairs[0].mux.exists(), "and no master at P's path either");
    }

    /// D8 item 4: a master the user's configuration makes for an unmanaged alias is not
    /// an owned connection: no pass sees or touches it (reported
    /// `unmanaged_connections: not_controlled` by U6).
    #[test]
    fn unmanaged_alias_master_reported_not_controlled() {
        let w = world();
        let user_mux = w.home.root.join("um");
        let text = fs::read_to_string(&w.home.user_config).unwrap();
        fs::write(
            &w.home.user_config,
            format!(
                "{text}Host plain\n  HostName 127.0.0.1\n  Port {}\n  User {}\n  IdentityAgent {}\n  IdentitiesOnly yes\n  IdentityFile {}\n  ControlMaster yes\n  ControlPath {}\n",
                w.sshd.port,
                w.account,
                ssh_config_quote(&w.agent.socket.to_string_lossy()),
                ssh_config_quote(&w.home.root.join("managed/d1/cert.pub").to_string_lossy()),
                ssh_config_quote(&user_mux.to_string_lossy())
            ),
        )
        .unwrap();
        let unmanaged = w.spawn_ordinary("plain", &["-N"]);
        assert!(wait_until(Duration::from_secs(20), || user_mux.exists()));
        let (g, _b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let r1 = rt.block_on(sup.time_uncertain_close()).unwrap();
        let r2 = rt
            .block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        let r3 = rt.block_on(sup.connection_restart_pass()).unwrap();
        for r in [&r1, &r2, &r3] {
            assert!(r.closed.is_empty() && r.unverified.is_empty() && r.kept.is_empty());
        }
        assert!(
            w.reap(unmanaged).is_none(),
            "the unmanaged master is not controlled"
        );
        let reported = heimdall_contract::managed::UnmanagedConnections::NotControlled;
        println!("m03 observation: unmanaged_alias_master owned=false reported={reported:?}");
    }

    /// The ADR-0005 §3.4 `[I]`: a forward through the master is refused when the
    /// certificate carries no `permit-port-forwarding` (the fixture's has no
    /// extensions), besides the master's own `ClearAllForwardings=yes`.
    #[test]
    fn forward_through_master_refused_without_permit_port_forwarding() {
        use std::io::Read;
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let _m = w.start(&sup, &rt, &b, 0);
        let port = heimdall_testkit::sshd::pick_loopback_port().unwrap();
        let mut cmd = w
            .home
            .client_command(ClientKind::Ssh, &w.pairs[0].alias)
            .unwrap();
        let args: Vec<OsString> = cmd.get_args().map(OsString::from).collect();
        let _ = &mut cmd;
        let fwd = Command::new(&w.ssh)
            .args(&args[..args.len() - 1])
            .arg("-O")
            .arg("forward")
            .arg("-L")
            .arg(format!("127.0.0.1:{port}:127.0.0.1:{}", w.sshd.port))
            .arg(&w.pairs[0].alias)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &w.home.git_home)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let mut banner = Vec::new();
        let reached = std::net::TcpStream::connect(("127.0.0.1", port))
            .ok()
            .map(|mut s| {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).unwrap_or(0);
                banner.extend_from_slice(&buf[..n]);
            });
        let through = banner.starts_with(b"SSH-");
        println!(
            "m03 observation: forward_through_master control_exit={:?} listener={} banner_through_forward={}",
            fwd.status.code(),
            reached.is_some(),
            through
        );
        assert!(
            !through,
            "no forwarded channel without permit-port-forwarding"
        );
        let log = w.sshd.log_lines_containing("port forwarding");
        println!(
            "m03 observation: forward_through_master server_lines={}",
            log.len()
        );
        rt.block_on(sup.shutdown());
    }

    /// E7/E7P rerun (D8 item 3; M-F6): what `-O stop` and `-O exit` do on this client,
    /// as observations, each on its own master with a pre-accepted session. Only what
    /// D8 relies on is asserted: `-O exit` (as the supervisor sends it) ends the master
    /// and its sessions, and the supervisor's close ends a master `-O stop` left running
    /// (through the verified PID when the control socket no longer answers).
    #[test]
    fn o_stop_and_o_exit_behaviour_recorded_per_client() {
        let w = world();
        let sup = w.supervisor();
        let rt = rt();
        let alias = w.pairs[0].alias.clone();
        let mux = w.pairs[0].mux.clone();
        let version = Command::new(&w.ssh)
            .arg("-V")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
            .unwrap_or_default();
        let control = |op: &str| {
            let mut cmd = w.home.client_command(ClientKind::Ssh, &alias).unwrap();
            let args: Vec<OsString> = cmd.get_args().map(OsString::from).collect();
            let _ = &mut cmd;
            Command::new(&w.ssh)
                .args(&args[..args.len() - 1])
                .arg("-O")
                .arg(op)
                .arg("-o")
                .arg(format!("ControlPath={}", mux.display()))
                .arg(&alias)
                .env_clear()
                .env("PATH", CHILD_PATH)
                .env("HOME", &w.home.git_home)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        // `-O stop`.
        let (_g1, b1) = w.grant(graceful_masters(), true);
        let m = w.start(&sup, &rt, &b1, 0);
        let session = w.spawn_remote_sleep(&alias);
        std::thread::sleep(Duration::from_millis(800));
        let stop = control("stop");
        std::thread::sleep(Duration::from_millis(500));
        let a = w.auths();
        let after_stop = w.ordinary(&alias, &["true"]);
        let exit_after_stop = control("exit");
        println!(
            "m03 observation: o_stop client={version:?} exit={:?} master_alive={} preaccepted_alive={} socket_left={} new_session_exit={:?} new_session_new_auth={} o_exit_after_stop_exit={:?}",
            stop.status.code(),
            alive(m.pid, &m.start_token),
            w.reap(session).is_none(),
            mux.exists(),
            after_stop.status.code(),
            w.auths() > a,
            exit_after_stop.status.code()
        );
        let outcome = rt.block_on(sup.close_one(&m));
        assert_eq!(outcome, CloseOutcome::Closed);
        assert!(
            !alive(m.pid, &m.start_token),
            "the supervisor's close ends it"
        );
        assert!(
            wait_until(Duration::from_secs(10), || w.reap(session).is_some()),
            "and its pre-accepted session"
        );
        // `-O exit`.
        let (_g2, b2) = w.grant(graceful_masters(), true);
        let m = w.start(&sup, &rt, &b2, 0);
        let session = w.spawn_remote_sleep(&alias);
        std::thread::sleep(Duration::from_millis(800));
        let exit = control("exit");
        let gone = wait_until(Duration::from_secs(5), || !alive(m.pid, &m.start_token));
        let ended = wait_until(Duration::from_secs(10), || w.reap(session).is_some());
        println!(
            "m03 observation: o_exit client={version:?} exit={:?} master_gone={gone} preaccepted_ended={ended} socket_left={}",
            exit.status.code(),
            mux.exists()
        );
        assert!(gone && ended, "-O exit ends the master and its sessions");
        let r = rt.block_on(sup.reap_pass()).unwrap();
        assert_eq!(r.closed, vec![m.id.clone()]);
        assert!(!mux.exists());
    }

    /// D8 item 5: a remote process started through the master survives the close; it is
    /// reported `remote_processes: not_terminated` (never claimed to stop).
    #[test]
    fn remote_process_survives_close_reported_not_terminated() {
        let w = world();
        let (g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let _m = w.start(&sup, &rt, &b, 0);
        let pidfile = w.home.root.join("remote.pid");
        // The loopback server runs as this account, so the "remote" process is a local
        // PID this test started and stops itself.
        let remote = format!(
            "nohup /bin/sleep {REMOTE_SECS} >/dev/null 2>&1 < /dev/null & echo $! > {}",
            pidfile.display()
        );
        assert!(w.ordinary(&w.pairs[0].alias, &[&remote]).status.success());
        let pid: u32 = fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let token = process_start_time(pid).unwrap();
        w.receipt(Role::Remote, pid, Path::new("/bin/sleep"));
        rt.block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        let survived = alive(pid, &token);
        let reported = heimdall_contract::managed::RemoteProcesses::NotTerminated;
        println!(
            "m03 observation: remote_process_after_close alive={survived} reported={reported:?}"
        );
        assert!(survived, "[O:E7] the remote process outlives the master");
        // Stop exactly that PID (the test started it), verified by its start token.
        let pin = heimdall_localenv::sys::ProcessPin::open(pid)
            .unwrap()
            .unwrap();
        let v = pin.verify(true, Path::new("/bin/sleep"));
        if let Some(v) = v {
            v.signal(heimdall_localenv::sys::ProcessSignal::Kill)
                .unwrap();
        }
        assert!(wait_until(Duration::from_secs(5), || !alive(pid, &token)));
    }

    /// D8 item 2: `run` of a program other than the verified client owns nothing: no
    /// connection row is written at bind for it (U0b row 19), so no pass can close its
    /// children; the report says `existing_connections: not_controlled`. The end-to-end
    /// `run` of a managed binding needs U10 (`ensure` of a managed pair is
    /// `driver_unavailable` until then); this covers the rule's pieces in this build.
    #[test]
    fn run_of_non_ssh_program_reports_existing_connections_not_controlled() {
        let w = world();
        let prepared = prepared_facts(&w.ssh);
        assert!(
            heimdall_app::operations::verified_client_image(Some(&prepared), "/bin/sh").is_none()
        );
        assert!(!heimdall_app::operations::dedicated_at_bind(
            false, None, None
        ));
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        // A shell the launcher would run, with an ssh child of its own.
        let shell_child = w.spawn_remote_sleep(&format!("{}-direct", w.pairs[0].alias));
        let r = rt()
            .block_on(w.supervisor().revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert!(r.closed.is_empty() && r.kept.is_empty(), "nothing owned");
        assert!(w.reap(shell_child).is_none(), "its ssh is not closed");
        let _ = b;
        println!(
            "m03 observation: run_non_ssh existing_connections={:?}",
            heimdall_contract::request::ExistingConnectionsPolicy::NotControlled
        );
    }

    // --- interrupted ---------------------------------------------------------------------

    /// D8 item 3 "Restart": first at start, the masters of grants that ended while the
    /// runtime was down are closed by their persisted identity; a master of a still-valid
    /// grant is kept.
    #[test]
    fn runtime_restart_closes_masters_of_ended_grants_first() {
        let w = world_with(Opts {
            dests: &["d1", "d2"],
            ..Opts::default()
        });
        let rt = rt();
        let (g1, b1) = w.grant(graceful_masters(), true);
        let (_g2, b2) = w.grant(graceful_masters(), true);
        let (m1, m2) = {
            let before = w.supervisor();
            let m1 = w.start(&before, &rt, &b1, 0);
            let m2 = w.start(&before, &rt, &b2, 1);
            (m1, m2)
            // The runtime "stops" here: its masters keep running (no kill on drop).
        };
        assert!(alive(m1.pid, &m1.start_token) && alive(m2.pid, &m2.start_token));
        w.end_grant(&g1, GrantState::Expired);
        let after = w.supervisor();
        let r = rt.block_on(after.connection_restart_pass()).unwrap();
        assert_eq!(r.closed, vec![m1.id.clone()]);
        assert_eq!(r.kept, vec![m2.id.clone()]);
        assert!(!alive(m1.pid, &m1.start_token));
        assert!(!w.pairs[0].mux.exists());
        assert!(
            alive(m2.pid, &m2.start_token),
            "a valid grant's master is kept"
        );
        // Cleanup through its persisted identity, too.
        assert_eq!(rt.block_on(after.close_one(&m2)), CloseOutcome::Closed);
        assert!(!alive(m2.pid, &m2.start_token));
    }

    /// D8 item 2 "Closing": a PID now held by another process (another start time) is
    /// never signalled; the row is reported `unverified`.
    #[test]
    fn unverifiable_holder_never_signalled() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        let pid = w.spawn("/bin/sleep", &["30"]);
        assert!(wait_until(Duration::from_secs(2), || process_start_time(
            pid
        )
        .is_some()));
        // The row's process "was" another instance at this PID: same PID and image, a
        // different start token.
        let c2 = OwnedConnection {
            id: heimdall_contract::ids::ConnectionId::from_random_bytes([w.n(); 16]),
            kind: ConnectionKind::Dedicated,
            binding: b.clone(),
            grant: g.clone(),
            pid,
            start_token: format!("{}-earlier", process_start_time(pid).unwrap()),
            image: "/bin/sleep".into(),
            control_path: None,
            generation: 0,
            state: OwnedConnectionState::Up,
            started_at: Timestamp::now(),
        };
        w.store
            .transaction(|tx| {
                tx.set_binding_holder(&b, &holder_of(&c2))?;
                tx.insert_owned_connection(&c2)
            })
            .unwrap();
        let r = rt()
            .block_on(w.supervisor().revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.unverified, vec![c2.id.clone()], "{r:?}");
        assert!(w.reap(pid).is_none(), "never signalled");
        assert_eq!(w.row(&c2.id).state, OwnedConnectionState::Unverified);
    }

    /// D8 item 3 "Failure to start": bounded, jittered retries; then no master, and
    /// ordinary clients connect directly.
    #[test]
    fn master_start_failure_retried_bounded_jittered_and_clients_connect_directly() {
        let w = world();
        // The binding's endpoint has no agent: every master attempt fails to
        // authenticate (BatchMode), while P's agent serves ordinary clients.
        let (_g, b) = w.grant(graceful_masters(), false);
        w.hold(&b, 0);
        let mut config = w.config();
        config.start_backoff = heimdall_app::reconcile::Backoff {
            base: Duration::from_millis(200),
            max: Duration::from_secs(1),
            max_attempts: 3,
        };
        let sup = ConnectionSupervisor::new(w.store.clone(), None, config);
        let rt = rt();
        let t = Instant::now();
        let e = rt.block_on(sup.start_master(&b, &w.pair(0))).unwrap_err();
        let took = t.elapsed();
        assert_eq!(
            e,
            heimdall_app::ports::ConnError::Failed("master_start_failed".into())
        );
        assert_eq!(sup.master_start_attempts(), 3, "bounded");
        // Jitter 0: delays base * 0.5 for attempts 1 and 2 (`Backoff::jittered`).
        assert!(took >= Duration::from_millis(200), "{took:?}");
        assert!(rt.block_on(sup.live_master_pids()).is_empty());
        assert!(!w.pairs[0].mux.exists());
        let a = w.auths();
        assert!(w.ordinary(&w.pairs[0].alias, &["true"]).status.success());
        assert_eq!(w.auths(), a + 1, "direct");
    }

    /// D7 item 10: `TIME_UNCERTAIN` closes owned masters and keeps `graceful` dedicated
    /// connections.
    #[test]
    fn time_uncertain_closes_masters_keeps_graceful_dedicated() {
        let w = world();
        let (g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &b, 0);
        let d = w.dedicated(&g, &b, &format!("{}-direct", w.pairs[0].alias));
        let r = rt.block_on(sup.time_uncertain_close()).unwrap();
        assert_eq!(r.closed, vec![m.id.clone()]);
        assert_eq!(r.kept, vec![d.id.clone()]);
        assert!(!alive(m.pid, &m.start_token));
        assert!(alive(d.pid, &d.start_token));
    }

    /// A strict close racing the child's own exit ends cleanly: `closed`, no error, no
    /// signal to anything else.
    #[test]
    fn strict_close_races_child_exit_cleanly() {
        let w = world();
        let sup = w.supervisor();
        let rt = rt();
        for delay_ms in [0u64, 50, 150, 300] {
            let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
            let pid = w.spawn("/bin/sleep", &["0.3"]);
            assert!(wait_until(Duration::from_secs(2), || process_start_time(
                pid
            )
            .is_some()));
            let c = w.row_for(&g, &b, pid, ConnectionKind::Dedicated, "/bin/sleep");
            std::thread::sleep(Duration::from_millis(delay_ms));
            w.end_grant(&g, GrantState::Expired);
            let r = rt
                .block_on(sup.connection_deadline_pass(std::slice::from_ref(&g)))
                .unwrap();
            assert_eq!(r.closed, vec![c.id.clone()], "delay {delay_ms}: {r:?}");
            assert_eq!(w.row(&c.id).state, OwnedConnectionState::Closed);
            assert!(wait_until(Duration::from_secs(3), || w.reap(pid).is_some()));
        }
    }

    // --- cleanup -------------------------------------------------------------------------

    /// §17.20 items 3 and 6 (W3-N01): the protocol, never inode numbers. (1) An inode
    /// identity alone removes only a socket that is still that inode, and a fabricated
    /// or absent identity removes nothing. (2) A stale close of generation N, whose
    /// recorded inode **equals** the socket generation N+1 now has at the path (the
    /// devbox's ext4 reused the number at once; simulated here by recording N+1's
    /// number in N's locator), neither controls nor removes N+1: no newer generation's
    /// socket is removed while it is open. (3) An unproven listener at the stable path
    /// is never trusted or left to serve: its path entry is removed before Heimdall's
    /// own master starts, reported `mux_path_foreign_listener_removed`.
    #[test]
    fn master_socket_removed_only_if_same_inode() {
        let w = world();
        // (1)
        let path = w.runtime_dir.join("s");
        let _l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(!remove_socket_if_same_inode(&path, Some((0, 0))));
        assert!(!remove_socket_if_same_inode(&path, None));
        assert!(path.exists());
        assert!(remove_socket_if_same_inode(&path, socket_inode(&path)));
        assert!(!path.exists());
        // (2)
        let sup = w.supervisor();
        let rt = rt();
        let mux = w.pairs[0].mux.clone();
        let alias = w.pairs[0].alias.clone();
        let (_g1, b1) = w.grant(graceful_masters(), true);
        let (_g2, b2) = w.grant(graceful_masters(), true);
        let m1 = w.start(&sup, &rt, &b1, 0);
        let m2 = w.start(&sup, &rt, &b2, 0);
        assert!(m2.generation > m1.generation);
        let now = socket_inode(&mux).unwrap();
        let resource = heimdall_contract::ids::ResourceId::parse(&format!(
            "res_{}",
            m1.id.as_str().split_once('_').unwrap().1
        ))
        .unwrap();
        w.store
            .transaction(|tx| {
                let mut r = tx.resource(&resource)?.unwrap();
                let mut l: serde_json::Value = serde_json::from_str(&r.locator).unwrap();
                l["inode"] = serde_json::json!([now.0, now.1]);
                r.locator = l.to_string();
                let expected = r.generation;
                tx.upsert_resource(&r, Some(expected))
            })
            .unwrap();
        for stale in [&sup, &w.supervisor()] {
            assert_eq!(rt.block_on(stale.close_one(&m1)), CloseOutcome::Closed);
            assert!(mux.exists(), "generation N+1's socket kept");
            assert_eq!(w.master_pid(&alias, &mux), Some(m2.pid), "N+1 still serves");
        }
        rt.block_on(sup.shutdown());
        assert!(!mux.exists());
        // (3) A socket nobody proves to be the holder's master, at the stable path.
        let (_g3, b3) = w.grant(graceful_masters(), true);
        let squat = std::os::unix::net::UnixListener::bind(&mux).unwrap();
        let sup = w.supervisor();
        let m3 = w.start(&sup, &rt, &b3, 0);
        assert_eq!(sup.foreign_listeners_removed(), vec![mux.clone()]);
        assert_eq!(
            w.master_pid(&alias, &mux),
            Some(m3.pid),
            "Heimdall's own master"
        );
        drop(squat);
        rt.block_on(sup.shutdown());
    }

    /// §17.20 item 3 (W3-R03): two concurrent starts of one slot are serialized by the
    /// slot's lock and each reserves its own generation inside it: the first master is
    /// replaced by the second, never both recorded open with one generation.
    #[test]
    fn concurrent_starts_of_one_slot_are_serialized() {
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        w.hold(&b, 0);
        let sup = w.supervisor();
        let rt = rt();
        let pair = w.pair(0);
        let (a, c) = rt.block_on(async {
            tokio::join!(sup.start_master(&b, &pair), sup.start_master(&b, &pair))
        });
        let (a, c) = (a.unwrap(), c.unwrap());
        w.track(&a);
        w.track(&c);
        assert_ne!(
            a.generation, c.generation,
            "each start reserved its own generation"
        );
        let open: Vec<OwnedConnection> = w
            .store
            .transaction(|tx| tx.owned_connections_for_binding(&b))
            .unwrap()
            .into_iter()
            .filter(|r| r.state == OwnedConnectionState::Up)
            .collect();
        assert_eq!(open.len(), 1, "one open master: {open:?}");
        let newer = if a.generation > c.generation { &a } else { &c };
        assert_eq!(open[0].id, newer.id);
        assert_eq!(
            w.master_pid(&w.pairs[0].alias, &w.pairs[0].mux),
            Some(newer.pid)
        );
        rt.block_on(sup.shutdown());
    }

    /// W3-S03's probe (§17.20 item 3): a stale close never sends a control command to a
    /// listener it has not proven. An owned master is told `-O stop` (it removes its
    /// socket and keeps running with its session); an unrelated master the probe starts
    /// itself binds the same path; closing the old row ends the old master by its
    /// verified PID only, and the unrelated master is not killed.
    #[test]
    fn stale_close_never_controls_a_replacement_listener() {
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let alias = w.pairs[0].alias.clone();
        let mux = w.pairs[0].mux.clone();
        let m = w.start(&sup, &rt, &b, 0);
        let session = w.spawn_remote_sleep(&alias);
        std::thread::sleep(Duration::from_millis(800));
        assert!(w.reap(session).is_none(), "a session through the master");
        let stop = Command::new(&w.ssh)
            .args(w.home.isolation_args())
            .arg("-O")
            .arg("stop")
            .arg("-o")
            .arg(format!("ControlPath={}", mux.display()))
            .arg(&alias)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &w.home.git_home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(stop.success());
        assert!(wait_until(Duration::from_secs(5), || !mux.exists()));
        assert!(
            alive(m.pid, &m.start_token),
            "-O stop left the master running"
        );
        let replacement = w.foreign_master(&b, 0);
        assert_eq!(rt.block_on(sup.close_one(&m)), CloseOutcome::Closed);
        assert!(
            !alive(m.pid, &m.start_token),
            "the old master, by its verified PID"
        );
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            w.reap(replacement).is_none(),
            "the unrelated replacement master was not killed"
        );
        assert_eq!(w.row(&m.id).state, OwnedConnectionState::Closed);
    }

    /// W3-S02's probe (§17.20 item 6): a foreign master at the slot's stable path (the
    /// probe's own, outside the ownership records) is never trusted: `start_master`
    /// removes its path entry (`mux_path_foreign_listener_removed`) and starts
    /// Heimdall's own master; after the grant is revoked and its close pass ran, an
    /// ordinary `ssh <alias>` makes no session through the foreign master (it needs a
    /// new authentication). The foreign master is never signalled (the residual: its
    /// already open sessions are `not_controlled`). A listener planted after the close is
    /// removed when the slot is cleared.
    #[test]
    fn foreign_master_at_stable_path_never_serves_after_revocation() {
        let w = world();
        let (g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let alias = w.pairs[0].alias.clone();
        let mux = w.pairs[0].mux.clone();
        w.hold(&b, 0);
        // The stable path's directory as the runtime creates it (0700).
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(mux.parent().unwrap())
                .unwrap();
        }
        let foreign = w.foreign_master(&b, 0);
        let m = rt.block_on(sup.start_master(&b, &w.pair(0))).unwrap();
        w.track(&m);
        assert_eq!(sup.foreign_listeners_removed(), vec![mux.clone()]);
        assert_eq!(w.master_pid(&alias, &mux), Some(m.pid));
        w.end_grant(&g, GrantState::Revoked);
        let r = rt
            .block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.closed, vec![m.id.clone()]);
        assert_eq!(
            w.master_pid(&alias, &mux),
            None,
            "no master at the stable path"
        );
        let before = w.auths();
        let out = w.ordinary(&alias, &["true"]);
        println!(
            "m03 observation: foreign_master_after_revocation ordinary_exit={:?} new_auth={}",
            out.status.code(),
            w.auths() > before
        );
        assert!(
            w.auths() > before,
            "the ordinary client made no session through the foreign master"
        );
        assert!(
            w.reap(foreign).is_none(),
            "the foreign master is never signalled"
        );
        // A listener planted at the path after the close: removed when the slot clears.
        let planted = std::os::unix::net::UnixListener::bind(&mux).unwrap();
        assert!(rt.block_on(sup.clear_slot_path(&w.pairs[0].dest)).unwrap());
        assert!(!mux.exists());
        drop(planted);
    }

    /// §17.20 item 6: the mux directory is owner-only and re-verified; an existing one
    /// that is not (0755 here, or a symlink) refuses the start, `mux_dir_unsafe`, and
    /// nothing is repaired.
    #[test]
    fn unsafe_mux_directory_refuses_the_start_unrepaired() {
        use std::os::unix::fs::PermissionsExt;
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        w.hold(&b, 0);
        let rt = rt();
        let dir = w.pairs[0].mux.parent().unwrap().to_path_buf();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let sup = w.supervisor();
        assert_eq!(
            rt.block_on(sup.start_master(&b, &w.pair(0))).unwrap_err(),
            ConnError::Unavailable("mux_dir_unsafe".into())
        );
        assert_eq!(
            fs::symlink_metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "not repaired"
        );
        assert_eq!(sup.master_start_attempts(), 0);
        fs::remove_dir(&dir).unwrap();
        let elsewhere = w.home.root.join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert_eq!(
            rt.block_on(sup.start_master(&b, &w.pair(0))).unwrap_err(),
            ConnError::Unavailable("mux_dir_unsafe".into())
        );
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    /// §17.20 item 5: only the slot holder's master serves the stable path. A binding
    /// that does not hold the pair's slot is refused before anything starts, and so is a
    /// pair outside the binding's scope; the holder's master is untouched.
    #[test]
    fn start_master_refused_for_non_holder() {
        let w = world();
        let (_g1, holder) = w.grant(graceful_masters(), true);
        let (_g2, other) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &holder, 0);
        let attempts = sup.master_start_attempts();
        assert_eq!(
            rt.block_on(sup.start_master(&other, &w.pair(0)))
                .unwrap_err(),
            ConnError::Unavailable("managed_slot_not_held".into())
        );
        let outside = AccessPair {
            destination: w.pairs[0].dest.clone(),
            account: AccountName::parse("someone-else").unwrap(),
        };
        assert_eq!(
            rt.block_on(sup.start_master(&holder, &outside))
                .unwrap_err(),
            ConnError::Unavailable("pair_not_in_scope".into())
        );
        assert_eq!(sup.master_start_attempts(), attempts, "nothing was spawned");
        assert!(
            alive(m.pid, &m.start_token),
            "the holder's master is untouched"
        );
        assert_eq!(w.row(&m.id).state, OwnedConnectionState::Up);
        assert_eq!(
            w.master_pid(&w.pairs[0].alias, &w.pairs[0].mux),
            Some(m.pid)
        );
        rt.block_on(sup.shutdown());
    }

    /// §17.20 item 5: the holder, the slot generation and the policy are read again
    /// after the spawn's awaited work. A slot transfer while the master starts (after
    /// its readiness is proven, before it is recorded) leaves no recorded master: the new
    /// child is closed and nothing is written.
    #[test]
    fn slot_transfer_during_spawn_leaves_no_recorded_master() {
        let w = Arc::new(world());
        let (_g1, b1) = w.grant(graceful_masters(), true);
        let (_g2, b2) = w.grant(graceful_masters(), true);
        w.hold(&b1, 0);
        let mut config = w.config();
        let (w2, to) = (Arc::clone(&w), b2.clone());
        config.after_master_ready = Some(Arc::new(move || w2.hold(&to, 0)));
        let sup = ConnectionSupervisor::new(w.store.clone(), None, config);
        let rt = rt();
        assert_eq!(
            rt.block_on(sup.start_master(&b1, &w.pair(0))).unwrap_err(),
            ConnError::Unavailable("managed_slot_not_held".into())
        );
        assert!(rt.block_on(sup.live_master_pids()).is_empty());
        let rows = w
            .store
            .transaction(|tx| tx.owned_connections_for_binding(&b1))
            .unwrap();
        assert!(rows.is_empty(), "nothing recorded: {rows:?}");
        assert_eq!(w.master_pid(&w.pairs[0].alias, &w.pairs[0].mux), None);
        assert!(!w.pairs[0].mux.exists(), "the new child's socket is gone");
    }

    /// §17.20 item 4 (W3-S01's probe): the deadline passes while the runtime is absent
    /// and the stored state is still `Active`. The restart pass judges the recovered
    /// master by fresh admission facts and closes it; no session is admitted after the
    /// deadline (no master answers, and the server refuses the expired certificate).
    #[test]
    fn restart_closes_master_whose_deadline_passed_while_absent() {
        let w = world_with(Opts {
            valid_for: 6,
            ..Opts::default()
        });
        let rt = rt();
        let issued = Instant::now();
        let deadline = Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(2))
            .unwrap();
        let (g, b) = w.grant_until(graceful_masters(), true, deadline);
        let m = {
            let before = w.supervisor();
            w.start(&before, &rt, &b, 0)
            // The runtime stops here: its master keeps running (no kill on drop).
        };
        assert!(alive(m.pid, &m.start_token));
        // Past the deadline and the certificate's validity, with nobody running.
        let wait = Duration::from_secs(7).saturating_sub(issued.elapsed());
        std::thread::sleep(wait);
        assert!(Timestamp::now() > deadline);
        assert_eq!(
            w.store
                .transaction(|tx| tx.grant(&g))
                .unwrap()
                .unwrap()
                .state,
            GrantState::Active,
            "the stored state is still active"
        );
        let after = w.supervisor();
        let r = rt.block_on(after.connection_restart_pass()).unwrap();
        assert_eq!(r.closed, vec![m.id.clone()], "{r:?}");
        assert!(r.kept.is_empty());
        assert!(!alive(m.pid, &m.start_token));
        assert_eq!(w.master_pid(&w.pairs[0].alias, &w.pairs[0].mux), None);
        let out = w.ordinary(&w.pairs[0].alias, &["true"]);
        assert!(!out.status.success(), "no session after the deadline");
    }

    /// §17.20 item 4: without accepted time (no time gate here), the restart pass closes
    /// every recovered master, as `time_uncertain_close` does.
    #[test]
    fn restart_without_accepted_time_closes_masters() {
        let w = world();
        let rt = rt();
        let (_g, b) = w.grant(graceful_masters(), true);
        let m = w.start(&w.supervisor(), &rt, &b, 0);
        let mut config = w.config();
        config.time_gate = None;
        let after = ConnectionSupervisor::new(w.store.clone(), None, config);
        let r = rt.block_on(after.connection_restart_pass()).unwrap();
        assert_eq!(r.closed, vec![m.id.clone()]);
        assert!(!alive(m.pid, &m.start_token));
    }

    /// §17.20 item 11 (D8 item 2): before the second signal the identity and image are
    /// read again on every Unix. A process that survives SIGTERM by exec'ing another
    /// image during the grace (same PID and start time) is not SIGKILLed: `pending`.
    #[test]
    fn process_that_execs_another_image_during_grace_is_not_killed() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        let marker = w.home.root.join("trap-set");
        let script = format!(
            "trap 'exec /bin/sleep 30' TERM; : > {}; while :; do /bin/sleep 0.05; done",
            heimdall_testkit::home::sh_quote(marker.as_os_str())
        );
        let pid = w.spawn("/bin/sh", &["-c", &script]);
        assert!(wait_until(Duration::from_secs(5), || marker.exists()));
        let image = heimdall_localenv::sys::ProcessPin::open(pid)
            .unwrap()
            .unwrap()
            .image()
            .unwrap();
        let c = w.row_for(
            &g,
            &b,
            pid,
            ConnectionKind::Dedicated,
            &image.to_string_lossy(),
        );
        let mut config = w.config();
        config.close_grace = Duration::from_millis(1500);
        let sup = ConnectionSupervisor::new(w.store.clone(), None, config);
        let outcome = rt().block_on(sup.close_one(&c));
        assert_eq!(outcome, CloseOutcome::Pending, "never SIGKILLed");
        assert!(alive(pid, &c.start_token), "the exec'd process runs");
        let now = heimdall_localenv::sys::ProcessPin::open(pid)
            .unwrap()
            .unwrap()
            .image()
            .unwrap();
        assert_ne!(now, image, "it exec'd another image");
        assert_eq!(w.row(&c.id).state, OwnedConnectionState::Closing);
    }

    /// §17.20 item 13: a store failure while a pass enumerates its rows is an explicit
    /// failure, never an empty report; nothing was signalled.
    #[test]
    fn pass_discovery_failures_are_explicit() {
        let w = world();
        let (g, b) = w.grant(policy(ExistingConnectionsMode::Strict, false), true);
        let pid = w.spawn("/bin/sleep", &["30"]);
        assert!(wait_until(Duration::from_secs(2), || process_start_time(
            pid
        )
        .is_some()));
        let c = w.row_for(&g, &b, pid, ConnectionKind::Dedicated, "/bin/sleep");
        w.end_grant(&g, GrantState::Revoked);
        let sup = w.supervisor();
        let rt = rt();
        w.faults.0.store(true, Ordering::SeqCst);
        let revocation = rt.block_on(sup.revocation_close(std::slice::from_ref(&g)));
        let deadline = rt.block_on(sup.connection_deadline_pass(std::slice::from_ref(&g)));
        let uncertain = rt.block_on(sup.time_uncertain_close());
        let restart = rt.block_on(sup.connection_restart_pass());
        w.faults.0.store(false, Ordering::SeqCst);
        for r in [&revocation, &deadline] {
            assert_eq!(
                r,
                &Err(DiscoveryFailed {
                    report: Default::default(),
                    grants: vec![g.clone()],
                })
            );
        }
        for r in [&uncertain, &restart] {
            let e = r.as_ref().unwrap_err();
            assert!(
                e.grants.is_empty() && e.report == Default::default(),
                "{e:?}"
            );
            assert_eq!(e.word(), "connection_discovery_failed");
        }
        assert!(alive(pid, &c.start_token), "nothing was signalled");
        let r = rt
            .block_on(sup.revocation_close(std::slice::from_ref(&g)))
            .unwrap();
        assert_eq!(r.closed, vec![c.id.clone()], "the retry closes it");
    }

    /// U7-Q4 (§17.20 item 14): the invariant the enumeration relies on, checked where
    /// rows are inserted: a dedicated row only for a launch binding with a holder, a
    /// master only with its process resource (the supervisor's own insertion checks it
    /// in the inserting transaction).
    #[test]
    fn owned_row_invariant_checked_at_insertion() {
        let w = world();
        let (g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &b, 0);
        let mut dedicated = m.clone();
        dedicated.kind = ConnectionKind::Dedicated;
        dedicated.control_path = None;
        let mut orphan = m.clone();
        orphan.id = heimdall_contract::ids::ConnectionId::from_random_bytes([0xee; 16]);
        let (ok, without_holder, without_resource, with_holder) = w
            .store
            .transaction(|tx| {
                let ok = owned_row_invariant(tx, &m)?;
                let without_holder = owned_row_invariant(tx, &dedicated)?;
                let without_resource = owned_row_invariant(tx, &orphan)?;
                tx.set_binding_holder(
                    &b,
                    &heimdall_domain::holder::ProcessHolder {
                        pid: 4242,
                        started_at: "1730419200.5".into(),
                    },
                )?;
                let with_holder = owned_row_invariant(tx, &dedicated)?;
                Ok((ok, without_holder, without_resource, with_holder))
            })
            .unwrap();
        assert!(ok, "the supervisor's master has its resource");
        assert!(
            !without_holder,
            "a dedicated row needs a launch binding's holder"
        );
        assert!(!without_resource, "a master needs its resource");
        assert!(with_holder);
        let _ = g;
        rt.block_on(sup.shutdown());
    }

    /// W3-C01 (b): a test that panics while the store cannot be read leaks nothing. A
    /// world starts a master and a session through it (a tracked server command), arms
    /// the store's transaction failure and panics; its drop cannot read the rows, and
    /// stops the master and the server command from its own receipts, by exact
    /// identity.
    #[test]
    fn panic_with_store_failure_leaks_no_process() {
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = std::thread::spawn(move || {
            let w = world();
            let (_g, b) = w.grant(graceful_masters(), true);
            let sup = w.supervisor();
            let rt = rt();
            let m = w.start(&sup, &rt, &b, 0);
            let client = w.spawn_remote_sleep(&w.pairs[0].alias);
            let identities: Vec<(u32, String)> = w
                .receipts
                .lock()
                .unwrap()
                .iter()
                .map(|r| (r.pid, r.token.clone()))
                .collect();
            assert!(identities.iter().any(|(p, _)| *p == m.pid));
            assert!(identities.iter().any(|(p, _)| *p == client));
            assert!(identities.len() >= 3, "master, client and server command");
            tx.send(identities).unwrap();
            w.faults.0.store(true, Ordering::SeqCst);
            assert!(
                w.store
                    .transaction(|tx| tx.owned_connection(&m.id))
                    .is_err(),
                "the store fails"
            );
            panic!("forced panic with the master up and the store failing");
        });
        assert!(probe.join().is_err(), "the probe panicked");
        let identities = rx.recv().unwrap();
        let survivors: Vec<u32> = identities
            .iter()
            .filter(|(p, t)| !wait_until(Duration::from_secs(5), || !alive(*p, t)))
            .map(|(p, _)| *p)
            .collect();
        assert!(survivors.is_empty(), "survivors: {survivors:?}");
    }

    /// Every process the test (and the supervisor in it) started is gone after the
    /// closes, counted by exact PID and start token.
    #[test]
    fn no_leftover_processes() {
        let w = world();
        let sup = w.supervisor();
        let rt = rt();
        let mut started: Vec<(u32, String)> = Vec::new();
        let (g1, b1) = w.grant(graceful_masters(), true);
        let (_g2, b2) = w.grant(graceful_masters(), true);
        let m1 = w.start(&sup, &rt, &b1, 0);
        started.push((m1.pid, m1.start_token.clone()));
        let m2 = w.start(&sup, &rt, &b2, 0);
        started.push((m2.pid, m2.start_token.clone()));
        let d = w.dedicated(&g1, &b1, &format!("{}-direct", w.pairs[0].alias));
        started.push((d.pid, d.start_token.clone()));
        rt.block_on(sup.revocation_close(std::slice::from_ref(&g1)))
            .unwrap();
        rt.block_on(sup.shutdown());
        assert!(wait_until(Duration::from_secs(5), || w
            .reap(d.pid)
            .is_some()));
        let left: Vec<u32> = started
            .iter()
            .filter(|(p, t)| alive(*p, t))
            .map(|(p, _)| *p)
            .collect();
        assert!(left.is_empty(), "left over: {left:?}");
        assert!(!w.pairs[0].mux.exists());
    }

    /// Rows are cleared when their process exits: a master that exits by itself is
    /// observed exited by the reap pass, its row `closed`, its
    /// resource absent and its socket removed; `shutdown` closes the rest.
    #[test]
    fn owned_connections_rows_cleared_on_exit() {
        let w = world();
        let (_g, b) = w.grant(graceful_masters(), true);
        let sup = w.supervisor();
        let rt = rt();
        let m = w.start(&sup, &rt, &b, 0);
        // The master exits by itself (an ordinary `ssh -O exit`, not the supervisor).
        let mut cmd = w
            .home
            .client_command(ClientKind::Ssh, &w.pairs[0].alias)
            .unwrap();
        let args: Vec<OsString> = cmd.get_args().map(OsString::from).collect();
        let _ = &mut cmd;
        let st = Command::new(&w.ssh)
            .args(&args[..args.len() - 1])
            .arg("-O")
            .arg("exit")
            .arg(&w.pairs[0].alias)
            .env_clear()
            .env("PATH", CHILD_PATH)
            .env("HOME", &w.home.git_home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success());
        assert!(wait_until(Duration::from_secs(20), || !alive(
            m.pid,
            &m.start_token
        )));
        let r = rt.block_on(sup.reap_pass()).unwrap();
        assert_eq!(r.closed, vec![m.id.clone()]);
        assert_eq!(w.row(&m.id).state, OwnedConnectionState::Closed);
        assert!(!w.pairs[0].mux.exists());
        assert!(rt.block_on(sup.live_master_pids()).is_empty());
        assert!(rt.block_on(sup.shutdown()).closed.is_empty());
    }

    #[allow(dead_code)]
    fn _unused(w: &World) -> (&TestCa, &Path) {
        (&w.ca, &w.identity)
    }
}

/// M-F7 (Windows, natively): one `ssh -M` attempt against the fixture sshd, its outcome
/// recorded, then `owned_masters` refused `CAPABILITY_UNAVAILABLE`
/// `multiplexing_unsupported`.
#[cfg(windows)]
#[test]
fn windows_owned_multiplexing_reported_unavailable() {
    use std::process::{Command, Stdio};
    use std::sync::Arc;

    use heimdall_app::ports::{ConnError, ConnectionControl};
    use heimdall_contract::ids::{AccountName, BindingId, DestinationId};
    use heimdall_domain::scope::AccessPair;
    use heimdall_runtime::connections::{BindingEndpoints, ConnectionConfig, ConnectionSupervisor};
    use heimdall_runtime::supervisor::FixedJitter;
    use heimdall_testkit::home::{ScratchHome, find_program};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

    struct None_;
    impl BindingEndpoints for None_ {
        fn endpoint(&self, _: &BindingId) -> Option<heimdall_contract::provider::EndpointRef> {
            None
        }
    }
    assert!(
        std::env::var_os("HM_FIXTURE_SSHD_HOST").is_some(),
        "windows_owned_multiplexing_reported_unavailable needs the harness fixture sshd (HM_FIXTURE_SSHD_*)"
    );
    let home = ScratchHome::new();
    let sshd = LoopbackSshd::start(home.scratch(), SshdConfig::default())
        .unwrap_or_else(|e| panic!("the harness fixture sshd: {e}"));
    home.trust_host_key(&sshd.host_key_line).unwrap();
    home.write_user_config(&format!(
        "Host hm-u7-win\n  HostName {}\n  Port {}\n",
        sshd.host, sshd.port
    ))
    .unwrap();
    let ssh = find_program("ssh").expect("the in-box ssh.exe");
    let mux = home.root.join("mux-attempt");
    let out = Command::new(&ssh)
        .args(home.isolation_args())
        .arg("-M")
        .arg("-N")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg(format!("ControlPath={}", mux.display()))
        .arg("hm-u7-win")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let first = stderr
        .lines()
        .next()
        .unwrap_or("")
        .replace(&*home.root.to_string_lossy(), "<scratch>");
    println!(
        "m03 observation: windows_ssh_master_attempt exit={:?} socket={} first_line={first:?}",
        out.status.code(),
        mux.exists()
    );
    let store = Arc::new(
        heimdall_store::Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap(),
    );
    let config = ConnectionConfig::new(
        home.root.join("r"),
        ssh,
        Arc::new(None_),
        Arc::new(FixedJitter(0.0)),
    );
    let sup = ConnectionSupervisor::new(store, None, config);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let pair = AccessPair {
        destination: DestinationId::parse("d1").unwrap(),
        account: AccountName::parse("u").unwrap(),
    };
    let e = rt
        .block_on(sup.start_master(&BindingId::from_random_bytes([1; 16]), &pair))
        .unwrap_err();
    assert_eq!(e, ConnError::Unavailable("multiplexing_unsupported".into()));
}

/// The target runs at least one test on every host.
#[test]
fn closing_matrix_is_the_d8_table() {
    let m = heimdall_runtime::connections::closing_matrix();
    assert_eq!(m.len(), 24);
    assert!(m[&("master", "deadline", "graceful")]);
    assert!(!m[&("dedicated", "deadline", "graceful")]);
    assert!(m[&("dedicated", "revocation", "graceful")]);
    assert!(!m[&("dedicated", "time_uncertain", "graceful")]);
    assert!(m[&("dedicated", "time_uncertain", "strict")]);
}
