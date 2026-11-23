//! ⟨M06 U56⟩ The Iroh serve child's supervision and the runtime's admission authority
//! (ADR-0012 §2.3–§2.4, §5.5; m06-plan U56 "Tests"), against **real child processes** of this
//! test binary (`harness = false`: the binary dispatches on `HM_U56_ROLE` before any test runs,
//! so a child's standard output carries only supervision lines).
//!
//! Everything is on loopback: the serve endpoint binds `127.0.0.1`/`::1` under the minimal
//! policy, the target is a fake sshd on `127.0.0.1`, and the dialers are in-process. No relay,
//! no internet, no non-loopback bind, no container. K_iroh lives in a scratch-file fixture
//! store defined here ([`FileFixtureStore`], test-only, kind `file_fixture_test`): mechanism
//! evidence, never product persistence. Client keys are generated per run, in memory.
//!
//! Cases:
//! * `revocation_is_applied_only_after_the_child_closed_the_live_connection`;
//! * `rotation_replaces_the_child_under_a_new_endpoint`;
//! * `the_serve_port_is_stable_and_an_unbindable_one_fails_closed` (⟨M06 W3⟩ ADR-0012 §2.1);
//! * `route_connect_through_iroh_reaches_a_server_first_target` (M06-W1-R04);
//! * `an_invalid_or_silent_client_reaches_no_target_through_iroh` (ADR-0012 §5.5 item 5);
//! * `an_unacknowledged_suspend_stops_the_child_by_its_exact_pid` (pending meanwhile);
//! * `the_runtime_killed_mid_revocation_orphan_exits_and_closure_is_replayed` (Unix);
//! * `unreadable_authority_starts_no_child_and_stops_a_running_one`;
//! * `no_verified_store_is_transport_key_store_unavailable_and_direct_routes_still_work`;
//! * `the_route_helper_dials_iroh_with_identification_gating_and_fails_over`;
//! * `remote_exposure_widening_stays_pending` (classification) and
//!   `credential_and_transport_agree_on_the_endpoint_id`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_app::routes::failover::{ClientIdentification, FailoverConfig, run_failover};
use heimdall_app::routes::legs::{RouteLegDialer, TokioLegDialer};
use heimdall_app::routes::{LegPlan, PlannedRoute};
use heimdall_app::transport::{
    AdmissionReport, ApprovedWidening, StorePeerEnrollments, TransportOps,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, ClientId, DecisionId, DestinationId, EnvironmentId, InvitationId, IrohEndpointId,
    KeyFingerprint, RequestId, RouteId,
};
use heimdall_contract::remote::Role;
use heimdall_contract::request::Request;
use heimdall_contract::route::{
    BindScope, ExposurePolicy, InfrastructureProfile, RouteFailureClass, TransportRequest,
};
use heimdall_credential::iroh::{
    IrohKeyMaterial, IrohKeyStore, IrohStoreAvailability, IrohStoreError, IrohStoreKind,
    UnsupportedIrohStore, doctor_finding,
};
use heimdall_domain::time::BootId;
#[cfg(unix)]
use heimdall_runtime::supervise_transport::NoPeerEndpoints;
use heimdall_runtime::supervise_transport::read_authority;
use heimdall_runtime::supervise_transport::{
    CredentialKeys, IrohRouteLeg, KeyRef, PeerEndpoints, ServeSpawn, Serving, StoreKeySource,
    SupervisorConfig, TransportSupervisor, serve_child_stdio,
};
use heimdall_store::ext_m06::{
    AppliedLine, ClientState, InvitationState, JoinRecord, RemoteClientRecord,
    RemoteInvitationRecord, RevocationCause,
};
use heimdall_store::{NoFaults, Store, StoreError, Txn};
use heimdall_transport_iroh::dial::{DialError, DialRequest, PeerClose, PigeonsStream, dial};
use heimdall_transport_iroh::keys::{InMemoryKeySource, KeySource, KeySourceError, NoKeyStore};
use heimdall_transport_iroh::policy::RouteAddresses;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ROLE: &str = "HM_U56_ROLE";
const KEYDIR: &str = "HM_U56_KEYDIR";
const STORE: &str = "HM_U56_STORE";
const DB: &str = "HM_U56_DB";
const PEERS: &str = "HM_U56_PEERS";

// --- the fixture key store (test-only; mechanism evidence) ---------------------------------

const FILE_FIXTURE: &str = "file_fixture_test";

/// K_iroh in owner-only scratch files: the only way a separate child process can read the
/// key the test generated. Test-only, never a product store (spec §7.3).
struct FileFixtureStore {
    dir: PathBuf,
}

impl FileFixtureStore {
    fn path(&self, endpoint: &IrohEndpointId) -> PathBuf {
        self.dir.join(endpoint.as_str())
    }
}

impl IrohKeyStore for FileFixtureStore {
    fn kind(&self) -> IrohStoreKind {
        IrohStoreKind::Test(FILE_FIXTURE)
    }

    fn availability(&self) -> IrohStoreAvailability {
        if self.dir.is_dir() {
            IrohStoreAvailability::Available
        } else {
            IrohStoreAvailability::Missing
        }
    }

    fn store_ref(&self, endpoint: &IrohEndpointId) -> String {
        format!("heimdall-iroh/{FILE_FIXTURE}/{}", endpoint.as_str())
    }

    fn put(&self, endpoint: &IrohEndpointId, key: &IrohKeyMaterial) -> Result<(), IrohStoreError> {
        if &key.endpoint_id() != endpoint {
            return Err(IrohStoreError::Corrupt);
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(self.path(endpoint))
            .map_err(|_| IrohStoreError::AlreadyExists)?;
        std::io::Write::write_all(&mut file, key.expose()).map_err(|_| IrohStoreError::Failed)
    }

    fn load(&self, endpoint: &IrohEndpointId) -> Result<IrohKeyMaterial, IrohStoreError> {
        let bytes = std::fs::read(self.path(endpoint)).map_err(|_| IrohStoreError::NotFound)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| IrohStoreError::Corrupt)?;
        let key = IrohKeyMaterial::from_bytes(seed);
        if &key.endpoint_id() != endpoint {
            return Err(IrohStoreError::Corrupt);
        }
        Ok(key)
    }

    fn destroy(&self, endpoint: &IrohEndpointId) -> Result<(), IrohStoreError> {
        std::fs::remove_file(self.path(endpoint)).map_err(|_| IrohStoreError::NotFound)
    }
}

// --- child roles ------------------------------------------------------------------------------

/// The serve child: [`serve_child_stdio`] with this run's fixture store (or none).
fn child_role() -> i32 {
    let dir = PathBuf::from(std::env::var_os(KEYDIR).unwrap_or_default());
    let unsupported = std::env::var(STORE).as_deref() == Ok("unsupported");
    let factory = move |key: &KeyRef| -> Result<Arc<dyn KeySource>, KeySourceError> {
        let store: Arc<dyn IrohKeyStore> = if unsupported {
            Arc::new(UnsupportedIrohStore)
        } else if key.store_kind == FILE_FIXTURE {
            Arc::new(FileFixtureStore { dir: dir.clone() })
        } else {
            return Err(KeySourceError::StoreUnavailable);
        };
        Ok(Arc::new(StoreKeySource::new(store, key.endpoint.clone())))
    };
    serve_child_stdio(&factory)
}

/// A child that reports ready and then never acknowledges anything, and ignores EOF: only
/// the exact-PID stop ends it.
fn deaf_role() -> ! {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut line = String::new();
    let _ = stdin.lock().read_line(&mut line);
    let start: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
    let ready = serde_json::json!({
        "t": "ready",
        "endpoint": start["key"]["endpoint"],
        "generation": start["generation"],
    });
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{ready}");
    let _ = out.flush();
    let mut sink = String::new();
    while stdin.lock().read_line(&mut sink).is_ok_and(|n| n > 0) {
        sink.clear();
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The "runtime" for the kill case: opens the database, starts the supervisor (which
/// spawns a serve child), prints `ready <child pid>`, then waits to be killed.
fn runtime_role() -> ! {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let store = Arc::new(
            Store::open(
                Path::new(&std::env::var_os(DB).unwrap()),
                Arc::new(NoFaults),
            )
            .unwrap(),
        );
        let peers = Arc::new(StaticPeers(parse_peers(&std::env::var(PEERS).unwrap())));
        let keydir = std::env::var_os(KEYDIR).unwrap();
        let sup = TransportSupervisor::new(store, peers, config(&keydir, "child"));
        sup.start().await.unwrap();
        let serving = sup.serving().await.unwrap();
        println!(
            "ready {} {}",
            serving.pid.unwrap(),
            serving.addresses.join(",")
        );
        std::future::pending::<()>().await;
    });
    std::process::exit(3)
}

// --- shared fixtures --------------------------------------------------------------------------

struct StaticPeers(Vec<(ClientId, IrohEndpointId)>);

impl PeerEndpoints for StaticPeers {
    fn enrolled(&self, _: &mut Txn<'_>) -> heimdall_store::Result<Vec<(ClientId, IrohEndpointId)>> {
        Ok(self.0.clone())
    }
}

struct FailingPeers(Arc<Mutex<bool>>, Vec<(ClientId, IrohEndpointId)>);

impl PeerEndpoints for FailingPeers {
    fn enrolled(&self, _: &mut Txn<'_>) -> heimdall_store::Result<Vec<(ClientId, IrohEndpointId)>> {
        if *self.0.lock().unwrap() {
            Err(StoreError::Corrupt("fixture: unreadable enrollment".into()))
        } else {
            Ok(self.1.clone())
        }
    }
}

#[cfg(unix)]
fn peers_env(peers: &[(ClientId, IrohEndpointId)]) -> String {
    peers
        .iter()
        .map(|(c, e)| format!("{}={}", c.as_str(), e.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_peers(s: &str) -> Vec<(ClientId, IrohEndpointId)> {
    s.split(',')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (c, e) = p.split_once('=').unwrap();
            (
                ClientId::parse(c).unwrap(),
                IrohEndpointId::parse(e).unwrap(),
            )
        })
        .collect()
}

/// The supervisor's configuration. ⟨M06 W5⟩ The target's port is not part of it: it is the
/// serve policy's `sshd_port`, recorded by `transport enable` ([`World::enable_serving_at`]).
fn config(keydir: &std::ffi::OsStr, role: &str) -> SupervisorConfig {
    let mut c = SupervisorConfig::new(ServeSpawn {
        program: std::env::current_exe().unwrap(),
        args: Vec::new(),
        env: vec![
            (ROLE.into(), role.into()),
            (KEYDIR.into(), keydir.to_owned()),
        ],
    });
    c.start_bound = Duration::from_secs(20);
    c.ack_bound = Duration::from_secs(3);
    c.stop_bound = Duration::from_secs(5);
    c.watch_interval = Duration::from_secs(3600);
    c
}

fn now() -> Timestamp {
    "2026-11-21T12:00:00Z".parse().unwrap()
}

/// An active client of the role table (invited, then joined), with a distinct key.
fn seed_client(store: &Store, n: u8) -> ClientId {
    seed_client_admitting(store, n, false)
}

/// [`seed_client`], with the consumed invitation's Iroh admission as given.
fn seed_client_admitting(store: &Store, n: u8, iroh_admission: bool) -> ClientId {
    let at = now();
    let client = ClientId::from_random_bytes([n; 16]);
    let invitation = InvitationId::from_random_bytes([n; 16]);
    let fp = KeyFingerprint::parse(&format!(
        "SHA256:{}",
        char::from(b'A' + n).to_string().repeat(43)
    ))
    .unwrap();
    let record = RemoteClientRecord {
        client: client.clone(),
        role: Role::Owner,
        key_fingerprint: fp.clone(),
        public_key: "ssh-ed25519 AAAA".into(),
        state: ClientState::Pending,
        invitation: Some(invitation.clone()),
        revoked_generation: None,
        revocation: None,
        created_at: at,
        updated_at: at,
        line: AppliedLine::Absent,
    };
    let inv = RemoteInvitationRecord {
        invitation: invitation.clone(),
        client: client.clone(),
        role: Role::Owner,
        key_fingerprint: fp,
        generation: 1,
        created_wall: at,
        created_boot_id: BootId("boot-u56".into()),
        created_elapsed: Duration::from_secs(1),
        expires_wall: "2026-11-21T12:15:00Z".parse().unwrap(),
        elapsed_bound: Duration::from_secs(900),
        probe_nonce: "00".repeat(16),
        state: InvitationState::Pending,
        consumed_at: None,
        join: None,
        iroh_admission,
    };
    let join = JoinRecord {
        environment: EnvironmentId::from_random_bytes([9; 16]),
        invitation,
        client: client.clone(),
        role: Role::Owner,
        generation: 1,
        joined_at: at,
    };
    store
        .transaction(|tx| {
            tx.insert_remote_invitation(&record, &inv, at)?;
            tx.activate_remote_client(&join).map(drop)
        })
        .unwrap();
    client
}

/// A fake sshd on `127.0.0.1`: sends its identification at once, names the session by the
/// first line it receives, echoes, and records `open <name>` / `closed <name>`.
struct Target {
    port: u16,
    events: Arc<Mutex<Vec<String>>>,
}

impl Target {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let ev = ev.clone();
                tokio::spawn(async move {
                    let _ = sock.write_all(b"SSH-2.0-fake_sshd\r\n").await;
                    let mut line = Vec::new();
                    let mut byte = [0u8; 1];
                    while !line.ends_with(b"\n") && line.len() < 255 {
                        match sock.read(&mut byte).await {
                            Ok(1) => line.push(byte[0]),
                            _ => break,
                        }
                    }
                    let name = String::from_utf8_lossy(&line).trim().to_owned();
                    ev.lock().unwrap().push(format!("open {name}"));
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    ev.lock().unwrap().push(format!("closed {name}"));
                });
            }
        });
        Self { port, events }
    }

    fn has(&self, event: &str) -> bool {
        self.events.lock().unwrap().iter().any(|e| e == event)
    }

    async fn wait_for(&self, event: &str, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        while Instant::now() < deadline {
            if self.has(event) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.has(event)
    }
}

/// One test's world: a file database with two active clients, a scratch key directory, the
/// fake sshd, and two client keys.
struct World {
    _dir: tempfile::TempDir,
    #[cfg_attr(not(unix), allow(dead_code))]
    db: PathBuf,
    keydir: PathBuf,
    store: Arc<Store>,
    target: Target,
    c1: (ClientId, InMemoryKeySource, IrohEndpointId),
    c2: (ClientId, InMemoryKeySource, IrohEndpointId),
}

fn client_key() -> (InMemoryKeySource, IrohEndpointId) {
    let k = InMemoryKeySource::generate();
    let id = k.load().unwrap().endpoint_id().unwrap();
    (k, id)
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let keydir = dir.path().join("keys");
        std::fs::create_dir(&keydir).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&keydir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let store = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
        let a = seed_client(&store, 1);
        let b = seed_client(&store, 2);
        let (k1, e1) = client_key();
        let (k2, e2) = client_key();
        Self {
            _dir: dir,
            db,
            keydir,
            target: Target::start().await,
            store,
            c1: (a, k1, e1),
            c2: (b, k2, e2),
        }
    }

    fn peers(&self) -> Vec<(ClientId, IrohEndpointId)> {
        vec![
            (self.c1.0.clone(), self.c1.2.clone()),
            (self.c2.0.clone(), self.c2.2.clone()),
        ]
    }

    fn supervisor(&self, role: &str) -> Arc<TransportSupervisor> {
        Arc::new(TransportSupervisor::new(
            self.store.clone(),
            Arc::new(StaticPeers(self.peers())),
            config(self.keydir.as_os_str(), role),
        ))
    }

    fn keys(&self) -> CredentialKeys {
        CredentialKeys(Arc::new(FileFixtureStore {
            dir: self.keydir.clone(),
        }))
    }

    /// The serve policy whose target is this world's fixture target.
    fn target_policy(&self) -> ExposurePolicy {
        ExposurePolicy {
            sshd_port: self.target.port,
            ..ExposurePolicy::default()
        }
    }

    /// `transport enable --serve --sshd-port <the world's target>` ([`Self::enable_serving_at`]).
    async fn enable_serving(&self, serve: &TransportSupervisor) -> IrohEndpointId {
        self.enable_serving_at(serve, self.target.port).await
    }

    /// `transport enable --serve --sshd-port <sshd_port>` with its runner-local decision,
    /// through the application operation and `serve` as its supervision port.
    async fn enable_serving_at(
        &self,
        serve: &TransportSupervisor,
        sshd_port: u16,
    ) -> IrohEndpointId {
        let policy = ExposurePolicy {
            sshd_port,
            ..ExposurePolicy::default()
        };
        let keys = self.keys();
        let ops = TransportOps {
            store: &self.store,
            keys: &keys,
            serve,
            peers: &StorePeerEnrollments,
        };
        let delta = ops.enable_delta(true, Some(&policy)).unwrap();
        let approved = ApprovedWidening {
            decision: DecisionId::from_random_bytes([0x5e; 16]),
            delta,
        };
        ops.enable(true, Some(policy), Some(&approved), now())
            .await
            .unwrap()
            .endpoint
    }

    fn revoke(&self, client: &ClientId) {
        self.store
            .transaction(|tx| {
                tx.revoke_remote_client(client, RevocationCause::Revoked, now())
                    .map(drop)
            })
            .unwrap();
    }

    fn generation(&self) -> u64 {
        self.store
            .transaction(|tx| tx.remote_authority_generation())
            .unwrap()
    }
}

async fn dial_serving(
    keys: &InMemoryKeySource,
    serving: &Serving,
) -> Result<PigeonsStream, DialError> {
    let route = RouteAddresses {
        direct: serving
            .addresses
            .iter()
            .map(|a| a.parse().unwrap())
            .collect(),
        relay_hints: Vec::new(),
    };
    dial(
        DialRequest {
            policy: &ExposurePolicy::default(),
            peer: &serving.endpoint,
            route: &route,
            connect_timeout: Duration::from_secs(10),
        },
        keys,
    )
    .await
}

/// Identify as `name`, read the fake sshd's identification, then round-trip one message.
async fn session(stream: &mut PigeonsStream, name: &str) -> bool {
    let io = async {
        stream
            .write_all(format!("SSH-2.0-{name}\r\n").as_bytes())
            .await?;
        stream.flush().await?;
        let mut banner = [0u8; 19];
        stream.read_exact(&mut banner).await?;
        if &banner != b"SSH-2.0-fake_sshd\r\n" {
            return Ok::<bool, std::io::Error>(false);
        }
        let ping = format!("ping-{name}");
        stream.write_all(ping.as_bytes()).await?;
        stream.flush().await?;
        let mut back = vec![0u8; ping.len()];
        stream.read_exact(&mut back).await?;
        Ok(back == ping.as_bytes())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(10), io).await,
        Ok(Ok(true))
    )
}

/// Whether a new dial with `keys` is refused (at dial time or on first use).
async fn refused(keys: &InMemoryKeySource, serving: &Serving) -> bool {
    match dial_serving(keys, serving).await {
        Err(DialError::Failed(RouteFailureClass::AdmissionRefused)) => true,
        Err(_) => false,
        Ok(mut s) => {
            let ok = session(&mut s, "probe").await;
            let close = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(c) = s.peer_close() {
                        return c;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
            !ok && close == Ok(PeerClose::AdmissionRefused)
        }
    }
}

/// The serving side's close of a live stream, within `bound`.
async fn closed_by_peer(stream: &mut PigeonsStream, bound: Duration) -> Option<PeerClose> {
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(bound, stream.read(&mut buf)).await;
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if let Some(c) = stream.peer_close() {
            return Some(c);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stream.peer_close()
}

/// Whether a process with `pid` exists (a child this test started, or its orphan), read
/// with `ps -p` (no signal is sent).
#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// --- cases --------------------------------------------------------------------------------------

/// m06-plan U56 adapter row: revocation is reported applied only after the child has closed
/// the revoked endpoint's existing Iroh connection (its session, stream and target socket,
/// ended before the acknowledgement); the other client keeps its connection; a new dial by
/// the revoked endpoint is refused.
fn revocation_is_applied_only_after_the_child_closed_the_live_connection() {
    rt().block_on(async {
        let w = World::new().await;
        let sup = w.supervisor("child");
        let endpoint = w.enable_serving(&sup).await;
        let serving = sup.serving().await.unwrap();
        assert_eq!(serving.endpoint, endpoint);
        assert_eq!(serving.generation, w.generation());
        let mut s1 = dial_serving(&w.c1.1, &serving).await.unwrap();
        let mut s2 = dial_serving(&w.c2.1, &serving).await.unwrap();
        assert!(session(&mut s1, "c1").await, "c1 live");
        assert!(session(&mut s2, "c2").await, "c2 live");
        assert!(
            w.target
                .wait_for("open SSH-2.0-c1", Duration::from_secs(5))
                .await
        );

        w.revoke(&w.c1.0);
        let report = sup.apply_narrowing().await;
        assert_eq!(report, AdmissionReport::Applied);
        let ack = sup.last_acknowledgement().unwrap();
        assert_eq!(ack.generation, w.generation());
        assert_eq!(ack.closed, 1, "the child closed c1's live connection");
        assert!(
            ack.complete,
            "c1's session ended before the acknowledgement"
        );
        assert!(
            w.target
                .wait_for("closed SSH-2.0-c1", Duration::from_secs(2))
                .await,
            "the target socket of c1's session is closed"
        );
        assert_eq!(
            closed_by_peer(&mut s1, Duration::from_secs(3)).await,
            Some(PeerClose::Revoked)
        );
        // c2 keeps its connection; c1 cannot come back.
        let ping = b"still-here";
        s2.write_all(ping).await.unwrap();
        let mut back = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), s2.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&back, ping);
        assert!(!w.target.has("closed SSH-2.0-c2"));
        assert!(
            refused(&w.c1.1, &serving).await,
            "c1 refused after revocation"
        );
        assert_eq!(sup.serving().await.unwrap().pid, serving.pid, "same child");
        let _ = s2.close().await;
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

/// ADR-0012 §2.4 item 4: K_iroh rotation withdraws the old endpoint (the generation moves)
/// and replaces the child under the new endpoint ID; the old endpoint no longer answers and
/// the enrolled client reaches the new one.
fn rotation_replaces_the_child_under_a_new_endpoint() {
    rt().block_on(async {
        let w = World::new().await;
        let sup = w.supervisor("child");
        let first = w.enable_serving(&sup).await;
        let before = sup.serving().await.unwrap();
        let keys = w.keys();
        let ops = TransportOps {
            store: &w.store,
            keys: &keys,
            serve: sup.as_ref(),
            peers: &StorePeerEnrollments,
        };
        let g = w.generation();
        let rotated = ops.rotate(None, now()).await.unwrap();
        assert_eq!(rotated.previous, first);
        assert_ne!(rotated.endpoint, first);
        assert_eq!(rotated.admission, AdmissionReport::Applied);
        assert!(rotated.previous_destroyed);
        assert_eq!(w.generation(), g + 1);
        let after = sup.serving().await.unwrap();
        assert_eq!(after.endpoint, rotated.endpoint);
        assert_ne!(after.pid, before.pid, "the child was replaced");
        let mut s2 = dial_serving(&w.c2.1, &after).await.unwrap();
        assert!(session(&mut s2, "c2-rotated").await);
        let _ = s2.close().await;
        // The old endpoint ID is gone: nothing answers as it.
        let stale = Serving {
            endpoint: first,
            ..after.clone()
        };
        let reached = match dial_serving(&w.c2.1, &stale).await {
            Ok(mut s) => session(&mut s, "c2-stale").await,
            Err(_) => false,
        };
        assert!(!reached, "the withdrawn endpoint does not serve");
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

/// ⟨M06-W3-R01⟩ `transport disable` through the runtime's own form
/// (`RouteTransport::transport` with `TransportRequest::Disable`, wired as the product wires
/// it: the store's enrollments, and the store's `remote_client_endpoints` as the serve
/// allowlist) removes every client's recorded endpoint in the narrowing write, with the
/// admission authority generation. After a later `enable`, a client that did not record its
/// endpoint again is refused; one that did (its rotation form's write) is served.
fn transport_disable_clears_the_client_allowlist_before_any_re_enable() {
    use heimdall_runtime::paired_endpoints::StorePeerEndpoints;
    use heimdall_runtime::supervise_transport::RouteTransport;
    rt().block_on(async {
        let w = World::new().await;
        let c3 = seed_client_admitting(&w.store, 3, true);
        let c4 = seed_client_admitting(&w.store, 4, true);
        let (k3, e3) = client_key();
        let (k4, e4) = client_key();
        w.store
            .transaction(|tx| {
                tx.set_remote_client_endpoint(&c3, &e3, now())?;
                tx.set_remote_client_endpoint(&c4, &e4, now()).map(drop)
            })
            .unwrap();
        let sup = Arc::new(TransportSupervisor::new(
            w.store.clone(),
            Arc::new(StorePeerEndpoints),
            config(w.keydir.as_os_str(), "child"),
        ));
        w.enable_serving(&sup).await;
        let serving = sup.serving().await.unwrap();
        let mut s3 = dial_serving(&k3, &serving).await.unwrap();
        assert!(session(&mut s3, "c3").await, "c3 is admitted while enabled");
        let _ = s3.close().await;

        let service = RouteTransport::new(
            w.store.clone(),
            sup.clone(),
            Arc::new(w.keys()),
            Arc::new(StorePeerEnrollments),
        );
        let owner = heimdall_app::Caller::unattended(heimdall_domain::principal::CallerContext {
            principal: heimdall_domain::principal::PrincipalRef::UnixUser { uid: 501 },
            role: heimdall_domain::principal::ClientRole::Owner,
            remote_client: None,
        });
        let before = w.generation();
        let done = service
            .transport(&owner, &TransportRequest::Disable, now())
            .await
            .unwrap();
        assert_eq!(done["allowlist_entries_removed"], 2, "{done}");
        assert!(
            w.generation() > before,
            "the narrowing moved the generation"
        );
        let listed = w
            .store
            .transaction(|tx| tx.remote_client_endpoints())
            .unwrap();
        assert!(
            listed.is_empty(),
            "no endpoint survives disable: {listed:?}"
        );
        assert!(
            read_authority(&w.store, &StorePeerEndpoints)
                .unwrap()
                .admitted
                .is_empty(),
            "the allowlist's source is empty"
        );
        assert!(sup.serving().await.is_none(), "the child was stopped");

        // Re-enable. c4 records its endpoint again over its management session; c3 does not.
        w.store
            .transaction(|tx| tx.set_remote_client_endpoint(&c4, &e4, now()).map(drop))
            .unwrap();
        w.enable_serving(&sup).await;
        let serving = sup.serving().await.unwrap();
        let mut s4 = dial_serving(&k4, &serving).await.unwrap();
        assert!(
            session(&mut s4, "c4").await,
            "the re-recorded client is served"
        );
        let _ = s4.close().await;
        assert!(
            refused(&k3, &serving).await,
            "an endpoint enrolled before disable is refused after re-enable"
        );
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

/// The IPv4 port of a running child's bound sockets.
fn v4_port(serving: &Serving) -> u16 {
    serving
        .addresses
        .iter()
        .filter_map(|a| a.parse::<std::net::SocketAddr>().ok())
        .find(std::net::SocketAddr::is_ipv4)
        .map(|a| a.port())
        .unwrap()
}

/// ⟨M06 W3; ADR-0012 §2.1 ⟨2026-11-21⟩, ADR-0006 §18.7 item 5⟩ The serve port: a policy that
/// names none records the first successful bind's port, and a restarted supervisor binds it
/// again; a recorded port that another socket holds fails closed (`transport_unavailable`,
/// naming the port; no other port is tried) and is recorded for the doctor, until a start
/// binds it; `disable` forgets it; a named port is bound as named.
fn the_serve_port_is_stable_and_an_unbindable_one_fails_closed() {
    rt().block_on(async {
        let w = World::new().await;
        let sup = w.supervisor("child");
        w.enable_serving(&sup).await;
        let first = v4_port(&sup.serving().await.unwrap());
        let recorded = |w: &World| {
            w.store
                .transaction(|tx| {
                    Ok((
                        tx.transport_serve_port()?,
                        tx.transport_serve_bind_failure()?,
                    ))
                })
                .unwrap()
        };
        assert_eq!(recorded(&w), (Some(first), None));
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
        // A restart (a new supervisor over the same state) binds the same port.
        let again = w.supervisor("child");
        again.start().await.unwrap();
        assert_eq!(v4_port(&again.serving().await.unwrap()), first);
        assert_eq!(again.stop().await, AdmissionReport::Applied);
        // Another socket holds the port: fail closed, naming it; nothing else is bound.
        let blocker = std::net::UdpSocket::bind(("127.0.0.1", first)).unwrap();
        let held = w.supervisor("child");
        let err = held.start().await.unwrap_err();
        assert_eq!(err.reason.as_deref(), Some("transport_unavailable"));
        assert!(err.message.contains(&first.to_string()), "{}", err.message);
        assert!(held.serving().await.is_none());
        assert_eq!(recorded(&w), (Some(first), Some(first)));
        drop(blocker);
        held.start().await.unwrap();
        assert_eq!(v4_port(&held.serving().await.unwrap()), first);
        assert_eq!(
            recorded(&w),
            (Some(first), None),
            "a bind clears the failure"
        );
        // `disable` forgets the port; a named port is then bound as named.
        let keys = w.keys();
        let ops = TransportOps {
            store: &w.store,
            keys: &keys,
            serve: held.as_ref(),
            peers: &StorePeerEnrollments,
        };
        ops.disable(now()).await.unwrap();
        assert_eq!(recorded(&w), (None, None));
        let named = {
            let probe = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
            probe.local_addr().unwrap().port()
        };
        let policy = ExposurePolicy {
            port: Some(named),
            ..w.target_policy()
        };
        let delta = ops.enable_delta(true, Some(&policy)).unwrap();
        let approved = ApprovedWidening {
            decision: DecisionId::from_random_bytes([0x5f; 16]),
            delta,
        };
        ops.enable(true, Some(policy), Some(&approved), now())
            .await
            .unwrap();
        assert_eq!(v4_port(&held.serving().await.unwrap()), named);
        assert_eq!(recorded(&w), (None, None), "a named port is not recorded");
        assert_eq!(held.stop().await, AdmissionReport::Applied);
    });
}

/// m06-plan U56 / ADR-0012 §2.3 item 4.3: a child that never acknowledges is stopped by its
/// exact supervised PID, and only then is the revocation applied; meanwhile admission
/// reports `remote_pending` with `iroh_admission_closing`. Closure is replayed on a fresh
/// child.
fn an_unacknowledged_suspend_stops_the_child_by_its_exact_pid() {
    rt().block_on(async {
        let w = World::new().await;
        let sup = w.supervisor("deaf");
        w.enable_serving(&sup).await;
        let first = sup.serving().await.unwrap().pid.unwrap();
        w.revoke(&w.c1.0);
        let watcher = {
            let sup = sup.clone();
            tokio::spawn(async move {
                let mut seen = Vec::new();
                for _ in 0..200 {
                    seen.push(sup.admission());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                seen
            })
        };
        let started = Instant::now();
        let report = sup.apply_narrowing().await;
        let took = started.elapsed();
        assert_eq!(report, AdmissionReport::Applied);
        assert!(
            took >= Duration::from_secs(3),
            "waited the ack bound: {took:?}"
        );
        let seen = watcher.await.unwrap();
        assert!(
            seen.contains(&AdmissionReport::Pending {
                reason: "iroh_admission_closing"
            }),
            "pending while closing"
        );
        #[cfg(unix)]
        assert!(!pid_alive(first), "the deaf child is gone");
        let fresh = sup.serving().await.unwrap();
        assert_ne!(fresh.pid, Some(first), "a fresh child replays closure");
        assert_eq!(fresh.generation, w.generation());
        // The deaf child ignores EOF too: stop falls back to the exact-PID kill.
        let fresh_pid = fresh.pid.unwrap();
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
        #[cfg(unix)]
        assert!(!pid_alive(fresh_pid));
        let _ = fresh_pid;
        assert_eq!(sup.spawned(), 2);
    });
}

/// m06-plan U56 fault row: the runtime is killed between the tombstone commit and the
/// child's acknowledgement. The orphan child loses its lease (its channel reaches EOF):
/// every stream closes at once and it exits. After the restart, closure is replayed before
/// admission: the new child's allowlist excludes the tombstone.
#[cfg(unix)]
fn the_runtime_killed_mid_revocation_orphan_exits_and_closure_is_replayed() {
    rt().block_on(async {
        let w = World::new().await;
        // Record the key and the serving consent (no child yet: a supervisor that never
        // starts one is the enable's port here).
        let recorder = Arc::new(TransportSupervisor::new(
            w.store.clone(),
            Arc::new(NoPeerEndpoints),
            config(w.keydir.as_os_str(), "child"),
        ));
        let keys = w.keys();
        let ops = TransportOps {
            store: &w.store,
            keys: &keys,
            serve: recorder.as_ref(),
            peers: &StorePeerEnrollments,
        };
        let delta = ops.enable_delta(true, Some(&w.target_policy())).unwrap();
        let err = ops
            .enable(
                true,
                Some(w.target_policy()),
                Some(&ApprovedWidening {
                    decision: DecisionId::from_random_bytes([0x5f; 16]),
                    delta,
                }),
                now(),
            )
            .await
            .unwrap_err();
        // No enrolled client for the recorder: recorded, not served.
        assert_eq!(err.reason.as_deref(), Some("transport_unavailable"));
        assert_eq!(recorder.spawned(), 0);

        let mut runtime = heimdall_app::no_window!(tokio::process::Command::new(
            std::env::current_exe().unwrap()
        ));
        runtime
            .env(ROLE, "runtime")
            .env(DB, &w.db)
            .env(KEYDIR, &w.keydir)
            .env(PEERS, peers_env(&w.peers()))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        let mut runtime = runtime.spawn().unwrap();
        let mut out = tokio::io::BufReader::new(runtime.stdout.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(30),
            tokio::io::AsyncBufReadExt::read_line(&mut out, &mut line),
        )
        .await
        .unwrap()
        .unwrap();
        let mut words = line.split_whitespace();
        assert_eq!(words.next(), Some("ready"));
        let child_pid: u32 = words.next().unwrap().parse().unwrap();
        let addresses: Vec<String> = words
            .next()
            .unwrap_or_default()
            .split(',')
            .map(str::to_owned)
            .collect();
        assert!(pid_alive(child_pid));
        // The runtime's child serves c1 (its endpoint is the durable key's).
        let snapshot = read_authority(&w.store, &StaticPeers(w.peers())).unwrap();
        let serving = Serving {
            endpoint: snapshot.serve.unwrap().key.endpoint,
            generation: snapshot.generation,
            addresses,
            pid: Some(child_pid),
        };
        let mut s1 = dial_serving(&w.c1.1, &serving).await.unwrap();
        assert!(
            session(&mut s1, "c1").await,
            "c1 live through the runtime's child"
        );

        // The tombstone commits; the runtime dies before it can deliver anything.
        w.revoke(&w.c1.0);
        runtime.start_kill().unwrap();
        let _ = runtime.wait().await;
        // The orphan loses its lease: c1's stream closes at once, and the child exits.
        assert_eq!(
            closed_by_peer(&mut s1, Duration::from_secs(5)).await,
            Some(PeerClose::LeaseLost)
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while pid_alive(child_pid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!pid_alive(child_pid), "the orphan exited");

        // The restarted runtime replays closure before admission.
        let sup = w.supervisor("child");
        sup.start().await.unwrap();
        let fresh = sup.serving().await.unwrap();
        assert_eq!(fresh.generation, w.generation(), "the new generation");
        assert!(
            refused(&w.c1.1, &fresh).await,
            "the tombstone is not admitted"
        );
        let mut s2 = dial_serving(&w.c2.1, &fresh).await.unwrap();
        assert!(session(&mut s2, "c2").await, "c2 admitted");
        let _ = s2.close().await;
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

/// m06-plan U56 fault row: with the authority unreadable (here the enrollment source fails,
/// as a corrupt or unavailable store does), the child is not started
/// (`transport_authority_lost`); a running child whose authority becomes unreadable is
/// stopped (fail closed) and not replaced.
fn unreadable_authority_starts_no_child_and_stops_a_running_one() {
    rt().block_on(async {
        let w = World::new().await;
        let fail = Arc::new(Mutex::new(false));
        let sup = Arc::new(TransportSupervisor::new(
            w.store.clone(),
            Arc::new(FailingPeers(fail.clone(), w.peers())),
            config(w.keydir.as_os_str(), "child"),
        ));
        w.enable_serving(&sup).await;
        let pid = sup.serving().await.unwrap().pid.unwrap();
        assert_eq!(sup.spawned(), 1);
        *fail.lock().unwrap() = true;
        w.revoke(&w.c1.0);
        assert_eq!(sup.apply_narrowing().await, AdmissionReport::Applied);
        assert!(sup.serving().await.is_none(), "stopped, not replaced");
        #[cfg(unix)]
        assert!(!pid_alive(pid));
        let _ = pid;
        let err = sup.start().await.unwrap_err();
        assert_eq!(err.reason.as_deref(), Some("transport_authority_lost"));
        assert_eq!(
            sup.spawned(),
            1,
            "no child started on an unreadable authority"
        );
    });
}

/// m06-plan U56 adapter row: with no verified store, K_iroh is refused
/// `transport_key_store_unavailable` (nothing recorded) with a doctor finding; a serve child
/// whose store is unavailable refuses to start with the same reason; the route helper's Iroh
/// leg is refused and the direct route still works.
fn no_verified_store_is_transport_key_store_unavailable_and_direct_routes_still_work() {
    rt().block_on(async {
        let w = World::new().await;
        // The application refuses before recording anything.
        let finding = doctor_finding(&UnsupportedIrohStore).unwrap();
        assert_eq!(finding.reason, "transport_key_store_unavailable");
        assert_eq!(finding.detail, "unsupported");
        let none = CredentialKeys(Arc::new(UnsupportedIrohStore));
        let sup = w.supervisor("child");
        let ops = TransportOps {
            store: &w.store,
            keys: &none,
            serve: sup.as_ref(),
            peers: &StorePeerEnrollments,
        };
        let err = ops.enable(false, None, None, now()).await.unwrap_err();
        assert_eq!(
            err.reason.as_deref(),
            Some("transport_key_store_unavailable")
        );
        assert!(
            w.store
                .transaction(|tx| tx.transport_keys())
                .unwrap()
                .is_empty()
        );
        assert_eq!(sup.spawned(), 0);

        // A recorded key whose store is unavailable to the serve child (a host without a
        // verified store): `enable --serve` records the reference, and the child refuses to
        // start with the same reason; nothing serves.
        let unsupported = w.supervisor_unsupported();
        let keys = w.keys();
        let ops = TransportOps {
            store: &w.store,
            keys: &keys,
            serve: unsupported.as_ref(),
            peers: &StorePeerEnrollments,
        };
        let approved = ApprovedWidening {
            decision: DecisionId::from_random_bytes([0x60; 16]),
            delta: ops.enable_delta(true, None).unwrap(),
        };
        let err = ops
            .enable(true, None, Some(&approved), now())
            .await
            .unwrap_err();
        assert_eq!(
            err.reason.as_deref(),
            Some("transport_key_store_unavailable")
        );
        assert!(unsupported.serving().await.is_none());
        assert_eq!(unsupported.spawned(), 1);
        let err = unsupported.start().await.unwrap_err();
        assert_eq!(
            err.reason.as_deref(),
            Some("transport_key_store_unavailable")
        );

        // The route helper: an Iroh route with no key store is refused and failed over;
        // the direct route is established.
        let dialer = RouteLegDialer {
            base: TokioLegDialer {
                ssh_client: PathBuf::from("/nonexistent/ssh"),
                relay_jump_stderr: false,
            },
            iroh: Some(Arc::new(IrohRouteLeg::new(Arc::new(NoKeyStore)))),
        };
        let routes = vec![
            iroh_route(1, &IrohEndpointId::parse(&"ab".repeat(32)).unwrap(), vec![]),
            direct_route(2, w.target.port),
        ];
        let (outcome, received) = helper(&dialer, &routes, b"SSH-2.0-helper\r\nhello").await;
        assert_eq!(outcome.0, Some(RouteId::from_random_bytes([2; 16])));
        assert_eq!(outcome.1[0], Some(RouteFailureClass::Refused));
        assert!(received.starts_with(b"SSH-2.0-fake_sshd\r\n"));
    });
}

impl World {
    /// A supervisor whose children see no verified store.
    fn supervisor_unsupported(&self) -> Arc<TransportSupervisor> {
        let mut c = config(self.keydir.as_os_str(), "child");
        c.spawn.env.push((STORE.into(), "unsupported".into()));
        Arc::new(TransportSupervisor::new(
            self.store.clone(),
            Arc::new(StaticPeers(self.peers())),
            c,
        ))
    }
}

fn iroh_route(n: u8, endpoint: &IrohEndpointId, addresses: Vec<String>) -> PlannedRoute {
    PlannedRoute {
        id: RouteId::from_random_bytes([n; 16]),
        leg: LegPlan::Iroh {
            endpoint: endpoint.clone(),
            direct_addresses: addresses,
            exposure: ExposurePolicy::default(),
            external_roost: false,
        },
        identification_timeout: Duration::from_secs(10),
    }
}

fn direct_route(n: u8, port: u16) -> PlannedRoute {
    PlannedRoute {
        id: RouteId::from_random_bytes([n; 16]),
        leg: LegPlan::Direct {
            host: "127.0.0.1".into(),
            port,
        },
        identification_timeout: Duration::from_secs(10),
    }
}

type Outcome = (Option<RouteId>, Vec<Option<RouteFailureClass>>);

/// Run the helper's failover over `routes` with a client that writes `client` and reads
/// until EOF; the outcome (final route, each attempt's failure) and what the client got.
async fn helper(
    dialer: &RouteLegDialer<TokioLegDialer>,
    routes: &[PlannedRoute],
    client: &[u8],
) -> (Outcome, Vec<u8>) {
    let (client_side, helper_side) = tokio::io::duplex(64 * 1024);
    let (helper_in, helper_out) = tokio::io::split(helper_side);
    let (mut client_read, mut client_write) = tokio::io::split(client_side);
    client_write.write_all(client).await.unwrap();
    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        // The fake sshd echoes forever: read what arrives within a bound.
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(2), client_read.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    });
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let rec = recorded.clone();
    let record = move |p| {
        rec.lock().unwrap().push(p);
        async {}
    };
    let destination = DestinationId::parse("lab").unwrap();
    let account = AccountName::parse("deploy").unwrap();
    let failover = FailoverConfig::default();
    let run = run_failover(
        &destination,
        &account,
        routes,
        dialer,
        helper_in,
        helper_out,
        &failover,
        &record,
    );
    // The session ends when the client side is dropped after the reader's bound.
    let outcome = tokio::select! {
        o = run => Some(o),
        () = tokio::time::sleep(Duration::from_secs(4)) => None,
    };
    drop(client_write);
    let got = reader.await.unwrap();
    let first = recorded
        .lock()
        .unwrap()
        .first()
        .cloned()
        .or_else(|| outcome.as_ref().and_then(|o| o.health.first().cloned()))
        .unwrap();
    let failures = first.attempts.iter().map(|a| a.failure).collect();
    ((first.final_route, failures), got)
}

/// The route helper's Iroh leg end to end: an enrolled client's helper reaches the served
/// sshd through `/pigeons/0`, sending only its identification line before the server's; a
/// non-enrolled client's Iroh attempt is `admission_refused` and failed over to the direct
/// route, which then gets the identification line first.
fn the_route_helper_dials_iroh_with_identification_gating_and_fails_over() {
    rt().block_on(async {
        let w = World::new().await;
        let sup = w.supervisor("child");
        w.enable_serving(&sup).await;
        let serving = sup.serving().await.unwrap();
        let admitted = RouteLegDialer {
            base: TokioLegDialer {
                ssh_client: PathBuf::from("/nonexistent/ssh"),
                relay_jump_stderr: false,
            },
            iroh: Some(Arc::new(IrohRouteLeg::new(Arc::new(w.c2.1.clone())))),
        };
        let routes = vec![iroh_route(1, &serving.endpoint, serving.addresses.clone())];
        let ((final_route, failures), got) =
            helper(&admitted, &routes, b"SSH-2.0-helper_c2\r\nheld-bytes").await;
        assert_eq!(final_route, Some(RouteId::from_random_bytes([1; 16])));
        assert_eq!(failures, vec![None]);
        assert!(
            got.starts_with(b"SSH-2.0-fake_sshd\r\nheld-bytes"),
            "{got:?}"
        );
        assert!(w.target.has("open SSH-2.0-helper_c2"));

        let (stranger, _) = client_key();
        let refused = RouteLegDialer {
            base: admitted.base.clone(),
            iroh: Some(Arc::new(IrohRouteLeg::new(Arc::new(stranger)))),
        };
        let routes = vec![
            iroh_route(1, &serving.endpoint, serving.addresses.clone()),
            direct_route(2, w.target.port),
        ];
        let ((final_route, failures), got) =
            helper(&refused, &routes, b"SSH-2.0-helper_x\r\nheld").await;
        assert_eq!(final_route, Some(RouteId::from_random_bytes([2; 16])));
        assert_eq!(
            failures,
            vec![Some(RouteFailureClass::AdmissionRefused), None]
        );
        assert!(got.starts_with(b"SSH-2.0-fake_sshd\r\nheld"), "{got:?}");
        assert!(w.target.has("open SSH-2.0-helper_x"), "the line, replayed");
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

// --- ⟨M06-W1-R04⟩ the helper/serve establishment through a server-first target ---------

/// A server-first loopback target, as sshd: writes `SSH-2.0-Probe\r\n` at once on accept,
/// then expects the client's identification line (`SSH-2.0-…`), then echoes until EOF.
/// Counts accepted connections and records each client identification.
struct ProbeTarget {
    port: u16,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    idents: Arc<Mutex<Vec<String>>>,
}

impl ProbeTarget {
    async fn start() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let idents = Arc::new(Mutex::new(Vec::new()));
        let (acc, ids) = (accepted.clone(), idents.clone());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                acc.fetch_add(1, Ordering::SeqCst);
                let ids = ids.clone();
                tokio::spawn(async move {
                    if sock.write_all(b"SSH-2.0-Probe\r\n").await.is_err() {
                        return;
                    }
                    let mut line = Vec::new();
                    let mut byte = [0u8; 1];
                    while !line.ends_with(b"\n") && line.len() < 255 {
                        match sock.read(&mut byte).await {
                            Ok(1) => line.push(byte[0]),
                            _ => return,
                        }
                    }
                    if !line.starts_with(b"SSH-2.0-") {
                        return;
                    }
                    ids.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&line).trim().to_owned());
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        Self {
            port,
            accepted,
            idents,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The helper's ports for one destination whose only approved route is an Iroh route (the
/// catalog's stored list, so `plan_routes` builds the leg from the route record itself).
struct IrohRoutePorts {
    view: heimdall_domain::catalog::RouteCatalogView,
    binding: heimdall_app::routes::RouteBinding,
    health: Mutex<Vec<heimdall_contract::route::RouteHealthPayload>>,
}

#[async_trait::async_trait]
impl heimdall_app::routes::RouteHelperPorts for IrohRoutePorts {
    async fn resolve_route_binding(
        &self,
        _: &DestinationId,
        _: &AccountName,
        _: &str,
    ) -> Result<heimdall_app::routes::RouteBinding, heimdall_app::routes::RouteHelperError> {
        Ok(self.binding.clone())
    }

    async fn route_view(
        &self,
    ) -> Result<heimdall_domain::catalog::RouteCatalogView, heimdall_app::routes::RouteHelperError>
    {
        Ok(self.view.clone())
    }

    async fn jump_hop(
        &self,
        _: &heimdall_domain::catalog::ApprovedRoute,
        _: heimdall_contract::environment::JumpAccess,
        _: &heimdall_app::routes::RouteBinding,
    ) -> Result<heimdall_app::routes::JumpHop, heimdall_app::routes::RouteHelperError> {
        Err(heimdall_app::routes::RouteHelperError::Unavailable)
    }

    async fn record_health(&self, payload: heimdall_contract::route::RouteHealthPayload) {
        self.health.lock().unwrap().push(payload);
    }
}

const R04_ENDPOINT: &str = "/nonexistent/hm-u56-binding.sock";

fn iroh_route_ports(serving: &Serving) -> (IrohRoutePorts, heimdall_app::routes::HelperArgs) {
    use heimdall_contract::ids::{BindingId, GrantId, IdentityId};
    use heimdall_contract::route::{DestinationRoute, RouteSpec};
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord, RouteCatalogView};
    let destination = DestinationId::parse("lab").unwrap();
    let account = AccountName::parse("deploy").unwrap();
    let mut view = RouteCatalogView::default();
    view.destinations.insert(
        destination.clone(),
        DestinationRecord {
            id: destination.clone(),
            alias: "lab".into(),
            revision: 1,
            definition: DestinationDefinition::Managed {
                hostname: "127.0.0.1".into(),
                port: None,
                account: account.clone(),
                identity: IdentityId::from_random_bytes([4; 16]),
                jump: None,
            },
            label: None,
            updated_at: now(),
        },
    );
    view.routes.insert(
        destination.clone(),
        vec![DestinationRoute {
            id: RouteId::from_random_bytes([0x44; 16]),
            route: RouteSpec::Iroh {
                endpoint: serving.endpoint.clone(),
                direct_addresses: serving.addresses.clone(),
                external_roost: false,
            },
            exposure: None,
            consents: Vec::new(),
            // A short bound: the revert proof times out here.
            identification_timeout_ms: Some(3_000),
        }],
    );
    let pair = heimdall_domain::scope::AccessPair {
        destination: destination.clone(),
        account: account.clone(),
    };
    let ports = IrohRoutePorts {
        view,
        binding: heimdall_app::routes::RouteBinding {
            binding: BindingId::from_random_bytes([5; 16]),
            grant: GrantId::from_random_bytes([6; 16]),
            endpoint: R04_ENDPOINT.into(),
            pairs: [pair].into_iter().collect(),
        },
        health: Mutex::new(Vec::new()),
    };
    let args = heimdall_app::routes::HelperArgs {
        destination,
        account,
        endpoint: R04_ENDPOINT.into(),
    };
    (ports, args)
}

/// One `route connect` run through the Iroh leg with `keys`: an OpenSSH-like client that
/// identifies, waits for the server's identification, sends a payload, reads its echo and
/// closes. Returns the helper's outcome, the route-health results and what the client got.
async fn route_connect_session(
    keys: InMemoryKeySource,
    serving: &Serving,
) -> (
    Option<heimdall_app::routes::FailoverOutcome>,
    Vec<heimdall_contract::route::RouteHealthPayload>,
    Vec<u8>,
) {
    let (ports, args) = iroh_route_ports(serving);
    let dialer = RouteLegDialer {
        base: TokioLegDialer {
            ssh_client: PathBuf::from("/nonexistent/ssh"),
            relay_jump_stderr: false,
        },
        iroh: Some(Arc::new(IrohRouteLeg::new(Arc::new(keys)))),
    };
    let (client_side, helper_side) = tokio::io::duplex(64 * 1024);
    let (helper_in, helper_out) = tokio::io::split(helper_side);
    let (mut client_read, mut client_write) = tokio::io::split(client_side);
    let client = tokio::spawn(async move {
        let mut got = Vec::new();
        let io = async {
            client_write
                .write_all(b"SSH-2.0-OpenSSH_client\r\n")
                .await?;
            let mut banner = [0u8; 15];
            client_read.read_exact(&mut banner).await?;
            got.extend_from_slice(&banner);
            client_write.write_all(b"payload-bytes").await?;
            let mut echo = [0u8; 13];
            client_read.read_exact(&mut echo).await?;
            got.extend_from_slice(&echo);
            client_write.shutdown().await?;
            client_read.read_to_end(&mut got).await?;
            Ok::<(), std::io::Error>(())
        };
        let _ = tokio::time::timeout(Duration::from_secs(20), io).await;
        got
    });
    let mut diagnostics: Vec<u8> = Vec::new();
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        heimdall_app::routes::route_connect(
            &args,
            &ports,
            &dialer,
            helper_in,
            helper_out,
            &FailoverConfig::default(),
            &mut diagnostics,
        ),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let got = client.await.unwrap();
    let health = ports.health.lock().unwrap().clone();
    (outcome, health, got)
}

/// One `route connect` run through the Iroh leg whose client writes `bytes` and then stays
/// open and silent. Returns the helper's outcome and the route-health results.
async fn route_connect_raw_client(
    keys: InMemoryKeySource,
    serving: &Serving,
    bytes: &'static [u8],
) -> (
    Option<heimdall_app::routes::FailoverOutcome>,
    Vec<heimdall_contract::route::RouteHealthPayload>,
) {
    let (ports, args) = iroh_route_ports(serving);
    let dialer = RouteLegDialer {
        base: TokioLegDialer {
            ssh_client: PathBuf::from("/nonexistent/ssh"),
            relay_jump_stderr: false,
        },
        iroh: Some(Arc::new(IrohRouteLeg::new(Arc::new(keys)))),
    };
    let (client_side, helper_side) = tokio::io::duplex(64 * 1024);
    let (helper_in, helper_out) = tokio::io::split(helper_side);
    let (mut client_read, mut client_write) = tokio::io::split(client_side);
    client_write.write_all(bytes).await.unwrap();
    let mut diagnostics: Vec<u8> = Vec::new();
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        heimdall_app::routes::route_connect(
            &args,
            &ports,
            &dialer,
            helper_in,
            helper_out,
            &FailoverConfig::default(),
            &mut diagnostics,
        ),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), client_read.read_to_end(&mut got)).await;
    assert!(got.is_empty(), "nothing reached the client");
    drop(client_write);
    let health = ports.health.lock().unwrap().clone();
    (outcome, health)
}

/// ⟨ADR-0012 §5.5 item 5; ruling 3, 2026-11-21⟩ Through the real serve child: a first client
/// line that is not `SSH-2.0-` CRLF within 255 bytes and a 256-byte line with no CRLF end the
/// connect (malformed, overlong: terminal), and a silent client times out (route-local); none
/// is recorded against the Iroh route, and no stream ever reaches the serve side, so the
/// server-first target accepts nothing.
fn an_invalid_or_silent_client_reaches_no_target_through_iroh() {
    rt().block_on(async {
        let w = World::new().await;
        let probe = ProbeTarget::start().await;
        let sup = Arc::new(TransportSupervisor::new(
            w.store.clone(),
            Arc::new(StaticPeers(w.peers())),
            config(w.keydir.as_os_str(), "child"),
        ));
        w.enable_serving_at(&sup, probe.port).await;
        let serving = sup.serving().await.unwrap();
        const LONG: &[u8; 256] = &{
            let mut b = [b'x'; 256];
            let p = b"SSH-2.0-";
            let mut i = 0;
            while i < p.len() {
                b[i] = p[i];
                i += 1;
            }
            b
        };
        let cases: [(&str, &'static [u8], ClientIdentification); 3] = [
            (
                "not SSH-2.0",
                b"SSH-1.99-old\r\n",
                ClientIdentification::Malformed,
            ),
            ("256 bytes, no CRLF", LONG, ClientIdentification::Overlong),
            ("silent", b"", ClientIdentification::Timeout),
        ];
        for (what, bytes, why) in cases {
            let (outcome, health) = route_connect_raw_client(w.c2.1.clone(), &serving, bytes).await;
            let outcome = outcome.unwrap_or_else(|| panic!("{what}: the helper ran"));
            assert!(
                outcome.final_route.is_none(),
                "{what}: no route established"
            );
            assert_eq!(outcome.client_failure, Some(why), "{what}");
            assert!(
                health.last().unwrap().attempts.is_empty(),
                "{what}: not counted against the Iroh route"
            );
            assert_eq!(probe.accepted(), 0, "{what}: the target saw nothing");
        }
        // The same child still serves a valid client.
        let (outcome, _, got) = route_connect_session(w.c2.1.clone(), &serving).await;
        assert!(outcome.is_some_and(|o| o.succeeded()));
        assert_eq!(got, b"SSH-2.0-Probe\r\npayload-bytes");
        assert_eq!(probe.accepted(), 1);
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

/// ⟨M06-W1-R04⟩ The real `route connect` (binding, planning from the stored Iroh route
/// record, failover with the Iroh leg's identification gating) through the real supervised
/// serve child to a **server-first** loopback target: the session establishes and bytes
/// round-trip, with no stream preamble (raw `/pigeons/0`). The allowlist and the authority
/// generation are still checked before any target connect: a stranger and a revoked client
/// are `admission_refused` and the target accepts nothing for them.
fn route_connect_through_iroh_reaches_a_server_first_target() {
    rt().block_on(async {
        let w = World::new().await;
        let probe = ProbeTarget::start().await;
        let sup = Arc::new(TransportSupervisor::new(
            w.store.clone(),
            Arc::new(StaticPeers(w.peers())),
            config(w.keydir.as_os_str(), "child"),
        ));
        w.enable_serving_at(&sup, probe.port).await;
        let serving = sup.serving().await.unwrap();
        let route = RouteId::from_random_bytes([0x44; 16]);

        let (outcome, health, got) = route_connect_session(w.c2.1.clone(), &serving).await;
        let attempts: Vec<_> = health
            .first()
            .map(|h| h.attempts.iter().map(|a| a.failure).collect())
            .unwrap_or_default();
        assert!(
            outcome.as_ref().is_some_and(|o| o.succeeded()),
            "established through Iroh; attempts {attempts:?}"
        );
        assert_eq!(attempts, vec![None]);
        assert_eq!(health[0].final_route, Some(route.clone()));
        assert_eq!(got, b"SSH-2.0-Probe\r\npayload-bytes", "round trip");
        assert_eq!(
            *probe.idents.lock().unwrap(),
            vec!["SSH-2.0-OpenSSH_client".to_owned()],
            "the target got the client's identification line first"
        );
        assert_eq!(probe.accepted(), 1);

        // The allowlist: a stranger is refused before any target connect.
        let (stranger, _) = client_key();
        let (outcome, health, _) = route_connect_session(stranger, &serving).await;
        assert!(outcome.is_some_and(|o| o.final_route.is_none()));
        assert_eq!(
            health.last().unwrap().attempts[0].failure,
            Some(RouteFailureClass::AdmissionRefused)
        );
        assert_eq!(probe.accepted(), 1, "no target connect for a stranger");

        // The generation: c2 revoked (tombstone, generation moved, the child acknowledged)
        // is refused before any target connect; c1 still reaches the target.
        w.revoke(&w.c2.0);
        assert_eq!(sup.apply_narrowing().await, AdmissionReport::Applied);
        let (outcome, health, _) = route_connect_session(w.c2.1.clone(), &serving).await;
        assert!(outcome.is_some_and(|o| o.final_route.is_none()));
        assert_eq!(
            health.last().unwrap().attempts[0].failure,
            Some(RouteFailureClass::AdmissionRefused)
        );
        assert_eq!(
            probe.accepted(),
            1,
            "no target connect for a revoked client"
        );
        let (outcome, _, got) = route_connect_session(w.c1.1.clone(), &serving).await;
        assert!(outcome.is_some_and(|o| o.succeeded()));
        assert_eq!(got, b"SSH-2.0-Probe\r\npayload-bytes");
        assert_eq!(probe.accepted(), 2);
        assert_eq!(sup.stop().await, AdmissionReport::Applied);
    });
}

/// m06-plan U56 unit row (the remote half): a paired client's request for serving, a new
/// relay set, a broader bind, direct fallback, public infrastructure or a roost adoption is
/// a runner-local widening (a pending record only, never dispatched); `disable` narrows.
fn remote_exposure_widening_stays_pending() {
    use heimdall_remote::roles::{Effect, NoConsents, classify};
    let rid = || RequestId::parse("req-u56").unwrap();
    let enable = |serve, exposure: ExposurePolicy| {
        Request::Transport(TransportRequest::Enable {
            serve,
            exposure: Some(exposure),
            request_id: rid(),
        })
    };
    let relays = ExposurePolicy {
        infrastructure: InfrastructureProfile::Custom {
            relays: vec!["https://relay.example.invalid".into()],
        },
        ..ExposurePolicy::default()
    };
    let wildcard = ExposurePolicy {
        bind: BindScope::Wildcard,
        ..ExposurePolicy::default()
    };
    let fallback = ExposurePolicy {
        direct_fallback: true,
        ..ExposurePolicy::default()
    };
    let public = ExposurePolicy {
        infrastructure: InfrastructureProfile::N0Public,
        ..ExposurePolicy::default()
    };
    let widening = [
        enable(true, ExposurePolicy::default()),
        enable(false, relays),
        enable(false, wildcard),
        enable(false, fallback),
        enable(false, public),
        Request::Transport(TransportRequest::AdoptRoost {
            destination: DestinationId::parse("lab").unwrap(),
            endpoint: IrohEndpointId::parse(&"cd".repeat(32)).unwrap(),
            exposure: None,
            request_id: rid(),
        }),
    ];
    for r in &widening {
        assert_eq!(
            classify(r, &NoConsents).effect,
            Effect::WidenRunnerLocal,
            "{r:?}"
        );
    }
    assert_eq!(
        classify(&Request::Transport(TransportRequest::Disable), &NoConsents).effect,
        Effect::Narrow
    );
}

/// The credential crate derives K_iroh's endpoint ID without iroh; it equals iroh's.
fn credential_and_transport_agree_on_the_endpoint_id() {
    for _ in 0..8 {
        let key = IrohKeyMaterial::generate().unwrap();
        let secret = heimdall_transport_iroh::keys::IrohSecret::from_bytes(*key.expose());
        assert_eq!(Some(key.endpoint_id()), secret.endpoint_id());
    }
}

fn main() {
    match std::env::var(ROLE).as_deref() {
        Ok("child") => std::process::exit(child_role()),
        Ok("deaf") => deaf_role(),
        Ok("runtime") => runtime_role(),
        _ => {}
    }
    let mut cases: Vec<(&str, fn())> = vec![
        (
            "revocation_is_applied_only_after_the_child_closed_the_live_connection",
            revocation_is_applied_only_after_the_child_closed_the_live_connection,
        ),
        (
            "route_connect_through_iroh_reaches_a_server_first_target",
            route_connect_through_iroh_reaches_a_server_first_target,
        ),
        (
            "an_invalid_or_silent_client_reaches_no_target_through_iroh",
            an_invalid_or_silent_client_reaches_no_target_through_iroh,
        ),
        (
            "rotation_replaces_the_child_under_a_new_endpoint",
            rotation_replaces_the_child_under_a_new_endpoint,
        ),
        (
            "transport_disable_clears_the_client_allowlist_before_any_re_enable",
            transport_disable_clears_the_client_allowlist_before_any_re_enable,
        ),
        (
            "the_serve_port_is_stable_and_an_unbindable_one_fails_closed",
            the_serve_port_is_stable_and_an_unbindable_one_fails_closed,
        ),
        (
            "an_unacknowledged_suspend_stops_the_child_by_its_exact_pid",
            an_unacknowledged_suspend_stops_the_child_by_its_exact_pid,
        ),
        (
            "unreadable_authority_starts_no_child_and_stops_a_running_one",
            unreadable_authority_starts_no_child_and_stops_a_running_one,
        ),
        (
            "no_verified_store_is_transport_key_store_unavailable_and_direct_routes_still_work",
            no_verified_store_is_transport_key_store_unavailable_and_direct_routes_still_work,
        ),
        (
            "the_route_helper_dials_iroh_with_identification_gating_and_fails_over",
            the_route_helper_dials_iroh_with_identification_gating_and_fails_over,
        ),
        (
            "remote_exposure_widening_stays_pending",
            remote_exposure_widening_stays_pending,
        ),
        (
            "credential_and_transport_agree_on_the_endpoint_id",
            credential_and_transport_agree_on_the_endpoint_id,
        ),
    ];
    #[cfg(unix)]
    cases.push((
        "the_runtime_killed_mid_revocation_orphan_exits_and_closure_is_replayed",
        the_runtime_killed_mid_revocation_orphan_exits_and_closure_is_replayed,
    ));
    // The arguments libtest's callers pass (`integration_route_m06` has the same): name
    // filters, `--exact`, `--skip <name>` and `--list`; any other flag is ignored.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exact = args.iter().any(|a| a == "--exact");
    let list = args.iter().any(|a| a == "--list");
    let mut filters: Vec<&str> = Vec::new();
    let mut skips: Vec<&str> = Vec::new();
    let mut rest = args.iter().map(String::as_str);
    while let Some(arg) = rest.next() {
        if arg == "--skip" {
            skips.extend(rest.next());
        } else if let Some(name) = arg.strip_prefix("--skip=") {
            skips.push(name);
        } else if !arg.starts_with('-') {
            filters.push(arg);
        }
    }
    let matches = |name: &str, pattern: &str| {
        if exact {
            name == pattern
        } else {
            name.contains(pattern)
        }
    };
    cases.retain(|(name, _)| {
        (filters.is_empty() || filters.iter().any(|f| matches(name, f)))
            && !skips.iter().any(|s| matches(name, s))
    });
    if list {
        for (name, _) in &cases {
            println!("{name}: test");
        }
        return;
    }
    let mut passed = 0;
    let mut failed = Vec::new();
    for (name, case) in cases {
        let started = Instant::now();
        let ok = std::panic::catch_unwind(case).is_ok();
        println!(
            "test {name} ... {} ({:.1?})",
            if ok { "ok" } else { "FAILED" },
            started.elapsed()
        );
        if ok {
            passed += 1;
        } else {
            failed.push(name);
        }
    }
    println!(
        "test result: {}. {passed} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(101);
    }
}
