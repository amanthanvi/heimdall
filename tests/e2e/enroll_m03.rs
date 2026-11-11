//! ⟨M03⟩ wave 4 (U10-A): the enrollment stage driver end to end, fixture level
//! (m03-plan U10 "Tests"; ADR-0008 D5 §6.1–§6.10).
//!
//! **Fixtures** (m03-plan §0.2; ADR-0008 D13). Everything is disposable, in one scratch
//! directory per test: U11's `LoopbackSshd` (loopback only, a per-run host key, the
//! scratch `AuthorizedKeysFile` as the explicit registry), a `FakeAgent` holding a
//! per-run existing-access key, U11's `TestCa`, and an in-memory store. The driver
//! runs in-process (`Operations`), with:
//! * the **real** step protocol: `heimdall_registry::step` builds every step, and the
//!   test-local CLI loop runs it with `heimdall_enroll::remote::SshStepRunner` (R10),
//!   through a client wrapper that only adds `-F <scratch config>` and the scratch
//!   environment (the owner's `~/.ssh` is never read);
//! * the **real** Verifier (`heimdall_enroll::verify::Verifier`) over the system client;
//! * fakes of the frozen ports that later units own: the issuer (`TestIssuer`, signing
//!   the reserved entry's exact bounds with the `TestCa`), the verification endpoint
//!   (`TestSession`, an in-process agent holding a fresh K_verify that counts
//!   signatures), the target evaluator (`TestTarget`, the sshd's route and host key,
//!   which a test can change), and the [`EnrollmentHost`] over a scratch runtime dir.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

#[cfg(unix)]
mod fx {
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use async_trait_free::*;
    use heimdall_app::enrollment::{AgentReading, TrustPaths, effective_config_args};
    pub use heimdall_app::enrollment::{
        EnrollmentHost, GeneratedPaths, HostError, StepAnswer, StepRecorded,
    };
    use heimdall_app::ensure::NoStageHook;
    use heimdall_app::managed::ManagedWiring;
    use heimdall_app::operations::Limits;
    use heimdall_app::ports::{
        AdapterError, IssuanceRef, IssuerError, IssuerPort, IssuerStatusSnapshot, TargetEvaluator,
        VerificationEndpoints, VerificationSession,
    };
    pub use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
    pub use heimdall_contract::enrollment::{
        EnrollmentForm, EnrollmentPlan, EnrollmentRequest, EnrollmentResult, EnrollmentSpec,
        EnrollmentState, RemoteStage, RemoteStep, RemovalTarget, VerifyMode,
    };
    pub use heimdall_contract::ids::RequestId;
    use heimdall_contract::ids::{
        AccountName, CaFingerprint, DestinationId, DeviceId, EnvironmentId, IdentityId, OperationId,
    };
    use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    pub use heimdall_contract::request::{DecideRequest, InteractionMode, Verdict, WaitMode};
    pub use heimdall_contract::{Code, OperationState, Timestamp};
    use heimdall_domain::catalog::{
        DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
        InteractionProfile,
    };
    use heimdall_domain::enrollment::{Determinism, ProxyRoute, RawHostKey, TargetEvaluation};
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::time::{BootId, Clock, SyncStatus, TimePolicy};
    use heimdall_enroll::remote::{SshStepRunner, TtyMode};
    use heimdall_enroll::verify::{Verifier, VerifierClient};
    use heimdall_store::{IssuerRecord, Store};
    use heimdall_testkit::ScriptedTimeSync;
    pub use heimdall_testkit::agent::{
        AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey, blob_fingerprint,
    };
    use heimdall_testkit::ca::{TestCa, UserCertSpec};
    use heimdall_testkit::home::{ScratchHome, find_program};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};

    /// `async_trait` without the crate: the ports are `async_trait` traits, whose
    /// expanded form is `fn … -> Pin<Box<dyn Future + Send + 'a>>`.
    mod async_trait_free {
        pub use std::future::Future;
        pub use std::pin::Pin;
        pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
    }

    pub const ALIAS: &str = "hm-e2e";

    // --- a small base64 (the certificate blob; tests only) ----------------------------

    pub fn b64decode(s: &str) -> Option<Vec<u8>> {
        let val = |c: u8| -> Option<u32> {
            Some(match c {
                b'A'..=b'Z' => u32::from(c - b'A'),
                b'a'..=b'z' => u32::from(c - b'a') + 26,
                b'0'..=b'9' => u32::from(c - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            })
        };
        let s = s.trim_end_matches('=');
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0;
        for c in s.bytes() {
            acc = (acc << 6) | val(c)?;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            }
        }
        Some(out)
    }

    // --- the clock: real time, plus an offset a test may advance ---------------------

    #[derive(Debug)]
    pub struct TestClock {
        start: Instant,
        start_wall: Timestamp,
        offset_ms: AtomicI64,
    }

    impl TestClock {
        pub fn new() -> Arc<TestClock> {
            Arc::new(TestClock {
                start: Instant::now(),
                start_wall: Timestamp::now(),
                offset_ms: AtomicI64::new(0),
            })
        }

        pub fn advance(&self, by: Duration) {
            self.offset_ms
                .fetch_add(i64::try_from(by.as_millis()).unwrap(), Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn wall(&self) -> Timestamp {
            let elapsed = i64::try_from(self.start.elapsed().as_millis()).unwrap();
            let off = self.offset_ms.load(Ordering::SeqCst);
            Timestamp::from_millisecond(self.start_wall.as_millisecond() + elapsed + off).unwrap()
        }

        fn continuous(&self) -> Duration {
            let off = u64::try_from(self.offset_ms.load(Ordering::SeqCst)).unwrap_or(0);
            self.start.elapsed() + Duration::from_secs(3600) + Duration::from_millis(off)
        }

        fn boot_id(&self) -> BootId {
            BootId("boot-e2e".to_owned())
        }
    }

    // --- the target evaluator (changeable) -------------------------------------------

    pub struct TestTarget {
        pub evaluation: Mutex<TargetEvaluation>,
    }

    impl TargetEvaluator for TestTarget {
        fn evaluate(&self, _alias: &str) -> TargetEvaluation {
            self.evaluation.lock().unwrap().clone()
        }
    }

    /// `(type, base64)` of a known-hosts line.
    pub fn host_key_of(line: &str) -> (String, String) {
        let mut f = line.split_whitespace().skip(1);
        (f.next().unwrap().to_owned(), f.next().unwrap().to_owned())
    }

    pub fn raw_key(key_type: &str, b64: &str) -> RawHostKey {
        RawHostKey {
            key_type: key_type.to_owned(),
            key_b64: b64.to_owned(),
            fingerprint: blob_fingerprint(&b64decode(b64).unwrap()).unwrap(),
            origin_display: "known_hosts".to_owned(),
            revoked: false,
        }
    }

    // --- the host port over a scratch runtime dir -----------------------------------

    pub struct TestHost {
        pub runtime: PathBuf,
        pub client: PathBuf,
        pub version: Mutex<String>,
        pub agent_path: String,
        pub effective_calls: AtomicUsize,
    }

    fn write_mode(path: &Path, text: &[u8], mode: u32) {
        let _ = fs::remove_file(path);
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    pub fn owner_only_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    impl EnrollmentHost for TestHost {
        fn client(&self) -> Option<String> {
            Some(self.client.display().to_string())
        }

        fn client_version(&self) -> Option<String> {
            Some(self.version.lock().unwrap().clone())
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
            self.effective_calls.fetch_add(1, Ordering::SeqCst);
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

    // --- the verification endpoint: an in-process agent holding K_verify ------------

    struct SessionShared {
        key: FixtureKey,
        certs: Mutex<Vec<Vec<u8>>>,
        signatures: AtomicU32,
        binds: AtomicU32,
    }

    pub struct TestSession {
        public: String,
        fingerprint: String,
        locator: EndpointRef,
        shared: Arc<SessionShared>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        live: Arc<AtomicUsize>,
    }

    impl Drop for TestSession {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl VerificationSession for TestSession {
        fn public_key(&self) -> &str {
            &self.public
        }

        fn install(&self, certificate_line: &str) -> Result<(), AdapterError> {
            let blob = certificate_line
                .split_whitespace()
                .nth(1)
                .and_then(b64decode)
                .ok_or_else(|| AdapterError::Protocol("certificate".into()))?;
            self.shared.certs.lock().unwrap().push(blob);
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

    fn serve(mut conn: UnixStream, s: &SessionShared) {
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
        let plain = s.key.public_blob();
        match msg[0] {
            11 => {
                let certs = s.certs.lock().unwrap().clone();
                let all: Vec<&Vec<u8>> = certs.iter().chain([&plain]).collect();
                let mut out = vec![12u8];
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
                let ours = blob == plain.as_slice()
                    || s.certs.lock().unwrap().iter().any(|c| c.as_slice() == blob);
                if !ours {
                    return vec![FAILURE];
                }
                s.signatures.fetch_add(1, Ordering::SeqCst);
                match s.key.sign(data) {
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

    /// The verification factory: one `TestSession` per call; `live` counts sessions
    /// not yet dropped, `created` every creation.
    pub struct TestEndpoints {
        pub dir: PathBuf,
        pub keys: Arc<Mutex<HashMap<String, FixtureKey>>>,
        pub live: Arc<AtomicUsize>,
        pub created: AtomicUsize,
        pub plans: Mutex<Vec<EnrollmentPlan>>,
    }

    impl VerificationEndpoints for TestEndpoints {
        fn create<'a, 'b, 'c, 'd>(
            &'a self,
            operation: &'b OperationId,
            plan: &'c EnrollmentPlan,
        ) -> BoxFut<'d, Result<Box<dyn VerificationSession>, AdapterError>>
        where
            'a: 'd,
            'b: 'd,
            'c: 'd,
            Self: 'd,
        {
            let _ = operation;
            self.plans.lock().unwrap().push(plan.clone());
            Box::pin(async move {
                let key = FixtureKey::generate();
                let public = key.public_line_without_comment();
                let fingerprint = key.fingerprint();
                self.keys
                    .lock()
                    .unwrap()
                    .insert(public.clone(), key.clone());
                let n = self.created.fetch_add(1, Ordering::SeqCst);
                let dir = self.dir.join(format!("v{n}"));
                owner_only_dir(&dir);
                let path = dir.join("v.sock");
                let listener = UnixListener::bind(&path).unwrap();
                listener.set_nonblocking(true).unwrap();
                let shared = Arc::new(SessionShared {
                    key,
                    certs: Mutex::new(Vec::new()),
                    signatures: AtomicU32::new(0),
                    binds: AtomicU32::new(0),
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
                self.live.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(TestSession {
                    public,
                    fingerprint,
                    locator: EndpointRef {
                        kind: EndpointKind::UnixSocket,
                        locator: path.display().to_string(),
                    },
                    shared,
                    stop,
                    thread: Some(thread),
                    live: Arc::clone(&self.live),
                }) as Box<dyn VerificationSession>)
            })
        }
    }

    // --- the issuer: signs the reserved verification entry's exact bounds -----------

    pub struct TestIssuer {
        pub ca: TestCa,
        pub more: Mutex<Vec<TestCa>>,
        pub store: Arc<Store>,
        pub keys: Arc<Mutex<HashMap<String, FixtureKey>>>,
        pub signed: AtomicUsize,
        pub available: AtomicBool,
    }

    impl IssuerPort for TestIssuer {
        fn status(&self) -> IssuerStatusSnapshot {
            IssuerStatusSnapshot {
                status: IssuerStatus {
                    state: if self.available.load(Ordering::SeqCst) {
                        IssuerState::Ready
                    } else {
                        IssuerState::Unavailable
                    },
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
            entry: IssuanceRef,
            subject: &'b str,
        ) -> BoxFut<'c, Result<String, IssuerError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move {
                if !self.available.load(Ordering::SeqCst) {
                    return Err(IssuerError::Unavailable("issuer_restarting".into()));
                }
                let stored = self
                    .store
                    .transaction(|tx| tx.verification_entry(&entry.id))
                    .map_err(|_| IssuerError::Protocol("store".into()))?
                    .ok_or_else(|| IssuerError::Protocol("no entry".into()))?;
                let key = self
                    .keys
                    .lock()
                    .unwrap()
                    .get(subject.trim())
                    .cloned()
                    .ok_or_else(|| IssuerError::Protocol("subject".into()))?;
                let b = &stored.bounds;
                let spec = UserCertSpec {
                    key_id: b.key_id.clone(),
                    principals: vec![b.principal.clone()],
                    valid_after: u64::try_from(b.valid_after.as_second()).unwrap(),
                    valid_before: u64::try_from(b.valid_before.as_second()).unwrap(),
                    serial: b.serial,
                    extensions: Vec::new(),
                    critical_options: Vec::new(),
                };
                let cert = if b.ca_fingerprint.as_ref() == Some(self.ca.fingerprint()) {
                    self.ca.sign_user(key.public(), &spec)
                } else {
                    let more = self.more.lock().unwrap();
                    let ca = more
                        .iter()
                        .find(|c| b.ca_fingerprint.as_ref() == Some(c.fingerprint()))
                        .ok_or_else(|| IssuerError::Protocol("ca".into()))?;
                    ca.sign_user(key.public(), &spec)
                }
                .map_err(|_| IssuerError::Protocol("sign".into()))?;
                self.signed.fetch_add(1, Ordering::SeqCst);
                Ok(cert.to_openssh().unwrap())
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

    // --- the world ---------------------------------------------------------------------

    pub fn system_ssh() -> PathBuf {
        find_program("ssh").expect("an ssh client")
    }

    pub fn owner() -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        }
    }

    pub fn consumer() -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::LimitedConsumer,
        }
    }

    pub fn attended() -> Caller {
        Caller {
            context: owner(),
            attendance: Attendance::Attended {
                since: Timestamp::now(),
            },
            interaction: InteractionMode::Interactive,
        }
    }

    pub fn unattended() -> Caller {
        Caller::unattended(owner())
    }

    pub struct World {
        pub ops: Operations,
        pub store: Arc<Store>,
        pub clock: Arc<TestClock>,
        pub sshd: LoopbackSshd,
        pub agent: FakeAgent,
        pub target: Arc<TestTarget>,
        pub host: Arc<TestHost>,
        pub issuer: Arc<TestIssuer>,
        pub endpoints: Arc<TestEndpoints>,
        pub verifier: Arc<Verifier>,
        pub env: EnvironmentId,
        pub destination: DestinationId,
        pub account: AccountName,
        pub registry: PathBuf,
        pub existing: String,
        pub home: ScratchHome,
    }

    pub struct WorldOptions {
        pub form: EnrollmentForm,
        pub agent_mode: AgentMode,
        pub identity_key_type_ok: bool,
        pub limits: Limits,
    }

    impl Default for WorldOptions {
        fn default() -> Self {
            WorldOptions {
                form: EnrollmentForm::Account,
                agent_mode: AgentMode::Normal,
                identity_key_type_ok: true,
                limits: Limits::default(),
            }
        }
    }

    impl World {
        pub async fn new() -> World {
            World::with(WorldOptions::default()).await
        }

        pub async fn with(o: WorldOptions) -> World {
            let home = ScratchHome::new();
            let existing_key = FixtureKey::generate();
            let account_name = current_account().expect("the local account");
            let system = o.form == EnrollmentForm::System;
            let ca = TestCa::generate(home.scratch()).unwrap();
            let mut cfg = SshdConfig {
                authorized: vec![existing_key.public().clone()],
                registry_seed: Some(b"".to_vec()),
                ..SshdConfig::default()
            };
            if system {
                let ca_file = home.scratch().subdir("trusted").unwrap().join("ca_keys");
                fs::write(&ca_file, b"").unwrap();
                cfg.trusted_user_ca_keys = Some(ca_file);
                cfg.authorized_principals =
                    Some([(account_name.clone(), Vec::new())].into_iter().collect());
            }
            let sshd = LoopbackSshd::start(home.scratch(), cfg).unwrap_or_else(|e| panic!("{e}"));
            let registry = sshd
                .registry_path()
                .expect("a local registry")
                .to_path_buf();
            let agent = FakeAgent::start(
                Endpoint::in_scratch(home.scratch(), "existing").unwrap(),
                FakeAgentConfig {
                    keys: vec![existing_key.clone()],
                    mode: o.agent_mode,
                },
            );
            let agent_path = agent.endpoint().locator().to_string_lossy().into_owned();
            home.write_user_config(&format!(
                "Host {ALIAS}\n  HostName 127.0.0.1\n  Port {}\n  User {account_name}\n",
                sshd.port
            ))
            .unwrap();
            // The client wrapper: the system ssh with the scratch configuration and
            // environment only (the owner's ~/.ssh is never read).
            let bin = home.scratch().subdir("bin").unwrap();
            let client = bin.join("ssh");
            write_mode(
                &client,
                format!(
                    "#!/bin/sh\nHOME='{}'; export HOME\nSSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK\nunset SSH_ASKPASS SSH_ASKPASS_REQUIRE SSH_AGENT_PID DISPLAY\nexec '{}' -F '{}' \"$@\"\n",
                    home.git_home.display(),
                    home.decoy_agent().endpoint().locator().to_string_lossy(),
                    system_ssh().display(),
                    home.user_config.display(),
                )
                .as_bytes(),
                0o700,
            );
            let version_out = std::process::Command::new(system_ssh())
                .arg("-V")
                .output()
                .unwrap();
            let version = String::from_utf8_lossy(&version_out.stderr)
                .trim()
                .to_owned();
            let runtime = home.scratch().subdir("rt").unwrap();
            owner_only_dir(&runtime);
            let store =
                Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
            let env = EnvironmentId::from_random_bytes(rand16());
            let destination = DestinationId::parse("dst_e2e").unwrap();
            let account = AccountName::parse(&account_name).unwrap();
            let identity = IdentityId::from_random_bytes(rand16());
            let now = Timestamp::now();
            let existing_line = existing_key.public_line_without_comment();
            let identity_public = if o.identity_key_type_ok {
                existing_line.clone()
            } else {
                // A password-only account: the catalog has no key it can drive.
                "password-only none".to_owned()
            };
            let (ca_fp, ca_line) = (ca.fingerprint().clone(), ca.public_line().to_owned());
            store
                .transaction(|tx| {
                    tx.init_self_environment(&env)?;
                    tx.upsert_environment(&EnvironmentRecord {
                        id: env.clone(),
                        device: DeviceId::from_random_bytes(rand16()),
                        kind: EnvironmentKind::NativeSession,
                        label: None,
                        permissions: EnvironmentPermissions {
                            automatic_activation: true,
                            managed_signing: true,
                            issuer_access: true,
                        },
                    })?;
                    tx.upsert_identity(&IdentityRecord {
                        id: identity.clone(),
                        revision: 1,
                        source: IdentitySource::NativeAgent {
                            endpoint: EndpointRef {
                                kind: EndpointKind::UnixSocket,
                                locator: agent_path.clone(),
                            },
                        },
                        public_key: identity_public.clone(),
                        fingerprint: existing_key.fingerprint(),
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
                            port: Some(sshd.port),
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
                    })?;
                    Ok(())
                })
                .unwrap();
            let clock = TestClock::new();
            let ops = Operations::start(OperationsConfig {
                store: Arc::clone(&store),
                clock: clock.clone(),
                time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                time_policy: TimePolicy::default(),
                environment: env.clone(),
                adapters: Vec::new(),
                stage_hook: Arc::new(NoStageHook),
                limits: o.limits,
                default_window: Duration::from_secs(3600),
                projection: None,
            })
            .await
            .unwrap();
            let (kt, kb) = host_key_of(&sshd.host_key_line);
            let target = Arc::new(TestTarget {
                evaluation: Mutex::new(TargetEvaluation {
                    hostname: "127.0.0.1".to_owned(),
                    port: sshd.port,
                    user: account_name.clone(),
                    proxy: ProxyRoute::None,
                    determinism: Determinism::Determined,
                    host_keys: vec![raw_key(&kt, &kb)],
                }),
            });
            let keys = Arc::new(Mutex::new(HashMap::new()));
            let host = Arc::new(TestHost {
                runtime: runtime.clone(),
                client,
                version: Mutex::new(version),
                agent_path: agent_path.clone(),
                effective_calls: AtomicUsize::new(0),
            });
            let issuer = Arc::new(TestIssuer {
                ca,
                more: Mutex::new(Vec::new()),
                store: Arc::clone(&store),
                keys: Arc::clone(&keys),
                signed: AtomicUsize::new(0),
                available: AtomicBool::new(true),
            });
            let vdir = home.scratch().subdir("vs").unwrap();
            owner_only_dir(&vdir);
            let endpoints = Arc::new(TestEndpoints {
                dir: vdir,
                keys,
                live: Arc::new(AtomicUsize::new(0)),
                created: AtomicUsize::new(0),
                plans: Mutex::new(Vec::new()),
            });
            let verifier = Arc::new(Verifier::with_client(
                VerifierClient {
                    path: system_ssh(),
                    version: heimdall_enroll::trace::ClientVersion::parse(
                        &host.version.lock().unwrap(),
                    )
                    .expect("a parsable client version"),
                },
                runtime.clone(),
            ));
            let w = World {
                ops,
                store,
                clock,
                sshd,
                agent,
                target,
                host,
                issuer,
                endpoints,
                verifier,
                env,
                destination,
                account,
                registry,
                existing: existing_line,
                home,
            };
            w.wire();
            w
        }

        /// Wire the ports into the current `Operations`.
        pub fn wire(&self) {
            self.ops.set_managed_wiring(ManagedWiring {
                issuer: Some(self.issuer.clone() as Arc<dyn IssuerPort>),
                verification_endpoints: Some(
                    self.endpoints.clone() as Arc<dyn VerificationEndpoints>
                ),
                verification_runner: Some(self.verifier.clone()),
                target: Some(self.target.clone() as Arc<dyn TargetEvaluator>),
                ..ManagedWiring::default()
            });
            self.ops
                .set_enrollment_host(self.host.clone() as Arc<dyn EnrollmentHost>);
        }

        /// An in-process restart: a new `Operations` over the same store, wired again.
        pub async fn restart(&mut self) {
            self.ops = Operations::start(OperationsConfig {
                store: Arc::clone(&self.store),
                clock: self.clock.clone(),
                time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                time_policy: TimePolicy::default(),
                environment: self.env.clone(),
                adapters: Vec::new(),
                stage_hook: Arc::new(NoStageHook),
                limits: *self.ops.limits(),
                default_window: Duration::from_secs(3600),
                projection: None,
            })
            .await
            .unwrap();
            self.wire();
        }

        pub fn tx<R>(
            &self,
            f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<R>,
        ) -> R {
            self.store.transaction(f).unwrap()
        }

        pub fn spec(&self) -> EnrollmentSpec {
            EnrollmentSpec {
                destination: self.destination.clone(),
                account: None,
                form: EnrollmentForm::Account,
                registry_path: Some(self.registry.display().to_string()),
                ca_fingerprint: None,
            }
        }

        pub fn system_spec(&self) -> EnrollmentSpec {
            EnrollmentSpec {
                form: EnrollmentForm::System,
                registry_path: None,
                ..self.spec()
            }
        }

        pub async fn req(
            &self,
            caller: &Caller,
            r: EnrollmentRequest,
        ) -> OpResult<serde_json::Value> {
            self.ops.enrollment_request(caller, r).await
        }

        pub async fn preview(&self, spec: &EnrollmentSpec) -> EnrollmentPlan {
            let c = self
                .req(
                    &unattended(),
                    EnrollmentRequest::Preview { spec: spec.clone() },
                )
                .await
                .unwrap_or_else(|e| panic!("preview: {e:?}"));
            serde_json::from_value(c.data).unwrap()
        }

        /// Apply: the approval-needed answer (decision and operation).
        pub async fn apply(
            &self,
            caller: &Caller,
            spec: &EnrollmentSpec,
            plan: &EnrollmentPlan,
            request_id: &str,
            interaction: InteractionMode,
        ) -> OpError {
            self.req(
                caller,
                EnrollmentRequest::Apply {
                    spec: spec.clone(),
                    plan_digest: plan.plan_digest.clone(),
                    request_id: RequestId::parse(request_id).unwrap(),
                    interaction,
                    wait: WaitMode::default(),
                },
            )
            .await
            .expect_err("an apply waits for its decision")
        }

        pub async fn decide(&self, e: &OpError, verdict: Verdict) -> OpResult<serde_json::Value> {
            let id = e.next.decision_ref.clone().expect("a decision reference");
            self.ops
                .decide(
                    &attended(),
                    DecideRequest {
                        decision_id: heimdall_contract::ids::DecisionId::parse(&id).unwrap(),
                        verdict,
                    },
                )
                .await
        }

        /// Preview, apply and approve: the operation, ready for its steps.
        pub async fn approved(&self, spec: &EnrollmentSpec, rid: &str) -> OperationId {
            let plan = self.preview(spec).await;
            let e = self
                .apply(
                    &attended(),
                    spec,
                    &plan,
                    rid,
                    InteractionMode::NonInteractive,
                )
                .await;
            assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
            let op = e.operation_id.clone().unwrap();
            self.decide(&e, Verdict::Approve).await.unwrap();
            op
        }

        pub async fn step(&self, op: &OperationId) -> OpResult<serde_json::Value> {
            self.req(
                &unattended(),
                EnrollmentRequest::Step {
                    operation_id: op.clone(),
                },
            )
            .await
        }

        pub async fn step_answer(&self, op: &OperationId) -> StepAnswer {
            let c = self
                .step(op)
                .await
                .unwrap_or_else(|e| panic!("step: {e:?}"));
            serde_json::from_value(c.data).unwrap()
        }

        pub async fn result(
            &self,
            op: &OperationId,
            token: &str,
            exit_status: i32,
            stdout: &str,
            stderr: &str,
        ) -> OpResult<serde_json::Value> {
            self.req(
                &unattended(),
                EnrollmentRequest::StepResult {
                    operation_id: op.clone(),
                    step_token: token.to_owned(),
                    exit_status,
                    stdout: stdout.to_owned(),
                    stderr_excerpt: stderr.to_owned(),
                },
            )
            .await
        }

        /// Run `step` as the CLI does and report its result.
        pub async fn run_and_report(&self, op: &OperationId, step: &RemoteStep) -> StepRecorded {
            let report = run_step(step).await;
            let c = self
                .result(op, &step.step_token, report.0, &report.1, &report.2)
                .await
                .unwrap_or_else(|e| panic!("step result: {e:?}"));
            serde_json::from_value(c.data).unwrap()
        }

        /// The test-local CLI loop (R10): steps until the runtime needs none.
        pub async fn drive(&self, op: &OperationId) -> Result<EnrollmentResult, OpError> {
            for _ in 0..16 {
                let c = self.step(op).await?;
                let answer: StepAnswer = serde_json::from_value(c.data).unwrap();
                match answer {
                    StepAnswer::Step { step } => {
                        let r = self.run_and_report(op, &step).await;
                        if let (false, Some(result)) = (r.more, r.result) {
                            return Ok(*result);
                        }
                    }
                    StepAnswer::Done { result } => return Ok(*result),
                    _ => panic!("unknown answer"),
                }
            }
            panic!("the operation did not settle in 16 steps");
        }

        pub fn record(
            &self,
            id: &heimdall_contract::ids::EnrollmentId,
        ) -> heimdall_domain::enrollment::EnrollmentRecord {
            self.tx(|tx| tx.enrollment(id)).unwrap()
        }

        pub fn op(&self, id: &OperationId) -> heimdall_domain::operation::OperationRecord {
            self.tx(|tx| tx.operation(id)).unwrap()
        }

        pub fn records(&self) -> Vec<heimdall_domain::enrollment::EnrollmentRecord> {
            self.tx(|tx| {
                tx.enrollments_for_pair(&heimdall_domain::scope::AccessPair {
                    destination: self.destination.clone(),
                    account: self.account.clone(),
                })
            })
        }

        pub fn registry_text(&self) -> String {
            String::from_utf8(fs::read(&self.registry).unwrap()).unwrap()
        }

        pub fn marker_lines(&self) -> usize {
            self.registry_text()
                .lines()
                .filter(|l| l.contains("heimdall:enr_"))
                .count()
        }

        pub fn receipts(&self, op: &OperationId) -> Vec<heimdall_domain::operation::StageReceipt> {
            self.tx(|tx| tx.stage_receipts(op))
        }

        /// Register a second CA (a rotation's).
        pub fn add_ca(&self) -> CaFingerprint {
            let ca = TestCa::generate(self.home.scratch()).unwrap();
            let fp = ca.fingerprint().clone();
            let line = ca.public_line().to_owned();
            let now = Timestamp::now();
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
            self.issuer.more.lock().unwrap().push(ca);
            fp
        }

        /// A record seeded in `state` (model setup for states the fixtures cannot
        /// reach directly), with `target` as its approved target.
        pub fn seed(
            &self,
            state: EnrollmentState,
            form: EnrollmentForm,
            target: heimdall_contract::enrollment::ApprovedTarget,
            hold: Option<heimdall_domain::enrollment::EnrollmentHold>,
        ) -> heimdall_domain::enrollment::EnrollmentRecord {
            let id = heimdall_contract::ids::EnrollmentId::from_random_bytes(rand16());
            let marker = heimdall_domain::enrollment::marker_for(&id);
            let line = format!(
                "cert-authority,principals=\"hm:{}:{}\" {} {marker}",
                self.destination.as_str(),
                self.account.as_str(),
                self.issuer.ca.public_line()
            );
            let identity = self
                .tx(|tx| tx.destination(&self.destination))
                .map(|d| match d.definition {
                    DestinationDefinition::Managed { identity, .. } => identity,
                    DestinationDefinition::Observed => unreachable!(),
                })
                .unwrap();
            let now = Timestamp::now();
            let record = heimdall_domain::enrollment::EnrollmentRecord {
                id,
                destination: self.destination.clone(),
                account: self.account.clone(),
                ca_fingerprint: self.issuer.ca.fingerprint().clone(),
                form,
                marker,
                registry: heimdall_contract::enrollment::RegistryRef {
                    path_display: self.registry.display().to_string(),
                    resolved_by: heimdall_contract::enrollment::RegistryResolvedBy::Explicit,
                },
                registry_canonical: heimdall_contract::enrollment::RegistryCanonical {
                    path: Some(self.registry.display().to_string()),
                    resolved_by: heimdall_contract::enrollment::RegistryResolvedBy::Explicit,
                },
                line_sha256: heimdall_domain::projection::Sha256Hex::of(line.as_bytes())
                    .as_str()
                    .to_owned(),
                target,
                existing_access: heimdall_domain::enrollment::ExistingAccessRecord {
                    identity,
                    endpoint: Some(EndpointRef {
                        kind: EndpointKind::UnixSocket,
                        locator: self.host.agent_path.clone(),
                    }),
                    public_key_file: None,
                },
                hold,
                removal_origin: None,
                late_write: None,
                state,
                verified_at: None,
                evidence: None,
                created_at: now,
                updated_at: now,
            };
            self.tx(|tx| tx.seed_enrollment(&record));
            record
        }

        /// A foreign enrollment (another installation's CA and marker, another
        /// catalog's destination ID) present in this server's registry, and its
        /// bundle descriptor.
        pub fn foreign(
            &self,
            form: EnrollmentForm,
        ) -> heimdall_contract::enrollment::ForeignRemovalTarget {
            let ca = TestCa::generate(self.home.scratch()).unwrap();
            let marker = format!(
                "heimdall:{}",
                heimdall_contract::ids::EnrollmentId::from_random_bytes(rand16()).as_str()
            );
            let line = format!(
                "cert-authority,principals=\"hm:dst_other:{}\" {} {marker}",
                self.account.as_str(),
                ca.public_line()
            );
            if form == EnrollmentForm::Account {
                self.sshd.append_registry_line(&line).unwrap();
            }
            heimdall_contract::enrollment::ForeignRemovalTarget {
                local_alias: ALIAS.to_owned(),
                bundle_destination_id: "dst_other".to_owned(),
                bundle_hostname: "127.0.0.1".to_owned(),
                bundle_port: self.sshd.port,
                account: self.account.clone(),
                marker,
                ca_public_key: ca.public_line().to_owned(),
                line_sha256: heimdall_domain::projection::Sha256Hex::of(line.as_bytes())
                    .as_str()
                    .to_owned(),
                registry: heimdall_contract::enrollment::RegistryCanonical {
                    path: (form == EnrollmentForm::Account)
                        .then(|| self.registry.display().to_string()),
                    resolved_by: if form == EnrollmentForm::Account {
                        heimdall_contract::enrollment::RegistryResolvedBy::Explicit
                    } else {
                        heimdall_contract::enrollment::RegistryResolvedBy::RemoteHome
                    },
                },
                form,
            }
        }

        pub async fn remove_foreign(
            &self,
            t: &heimdall_contract::enrollment::ForeignRemovalTarget,
            rid: &str,
        ) -> OpResult<serde_json::Value> {
            self.req(
                &attended(),
                EnrollmentRequest::Remove {
                    target: RemovalTarget::Foreign(t.clone()),
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::default(),
                },
            )
            .await
        }

        pub fn foreign_records(
            &self,
            marker: &str,
        ) -> Vec<heimdall_domain::enrollment::ForeignRemovalRecord> {
            self.tx(|tx| tx.foreign_removals_by_marker(marker))
        }

        /// The approved target the sshd serves now.
        pub fn served_target(&self) -> heimdall_contract::enrollment::ApprovedTarget {
            let (kt, kb) = host_key_of(&self.sshd.host_key_line);
            heimdall_contract::enrollment::ApprovedTarget {
                hostname: "127.0.0.1".to_owned(),
                port: self.sshd.port,
                user: self.account.clone(),
                proxy: Default::default(),
                host_key: raw_key(&kt, &kb).approved(),
            }
        }

        pub async fn verify(
            &self,
            id: &heimdall_contract::ids::EnrollmentId,
            rid: &str,
            mode: VerifyMode,
        ) -> OpResult<serde_json::Value> {
            self.req(
                &attended(),
                EnrollmentRequest::Verify {
                    enrollment_id: id.clone(),
                    request_id: RequestId::parse(rid).unwrap(),
                    mode,
                    wait: WaitMode::default(),
                },
            )
            .await
        }

        pub async fn remove(
            &self,
            id: &heimdall_contract::ids::EnrollmentId,
            rid: &str,
        ) -> OpResult<serde_json::Value> {
            self.req(
                &attended(),
                EnrollmentRequest::Remove {
                    target: RemovalTarget::Enrollment {
                        enrollment_id: id.clone(),
                    },
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::default(),
                },
            )
            .await
        }

        pub async fn reconcile(
            &self,
            caller: &Caller,
            op: &OperationId,
            after_manual: bool,
        ) -> OpResult<serde_json::Value> {
            self.req(
                caller,
                EnrollmentRequest::Reconcile {
                    operation_id: op.clone(),
                    interaction: InteractionMode::NonInteractive,
                    after_manual_recovery: after_manual,
                },
            )
            .await
        }

        /// Inspect, then an append the CLI reports as killed after the ready line
        /// (`ran`: the append really ran first): the step is `Uncertain`.
        pub async fn uncertain_append(&self, op: &OperationId, ran: bool) {
            let StepAnswer::Step { step } = self.step_answer(op).await else {
                panic!("inspect");
            };
            self.run_and_report(op, &step).await;
            let StepAnswer::Step { step } = self.step_answer(op).await else {
                panic!("append");
            };
            assert_eq!(step.stage, RemoteStage::Append);
            if ran {
                let _ = run_step(&step).await;
            }
            self.result(
                op,
                &step.step_token,
                heimdall_enroll::remote::KILLED_EXIT_STATUS,
                "HM1 ready\n",
                "",
            )
            .await
            .unwrap();
        }

        /// A system-form enrollment, applied by the owner and verified.
        pub async fn system_verified(
            &self,
        ) -> (
            heimdall_domain::enrollment::EnrollmentRecord,
            EnrollmentPlan,
        ) {
            let spec = self.system_spec();
            let plan = self.preview(&spec).await;
            let e = self
                .apply(
                    &attended(),
                    &spec,
                    &plan,
                    "req_sysv",
                    InteractionMode::NonInteractive,
                )
                .await;
            self.decide(&e, Verdict::Approve).await.unwrap();
            let record = self.records().pop().unwrap();
            self.sshd
                .trust_user_ca(self.issuer.ca.public_line())
                .unwrap();
            self.sshd
                .set_principals(
                    self.account.as_str(),
                    &[plan.verification.positive_principal.as_str()],
                )
                .unwrap();
            let c = self
                .verify(&record.id, "req_sysv_v", VerifyMode::Presence)
                .await
                .unwrap_or_else(|e| panic!("verify: {e:?}"));
            let r: EnrollmentResult = serde_json::from_value(c.data).unwrap();
            assert_eq!(r.state, EnrollmentState::Verified, "{r:?}");
            (self.record(&record.id), plan)
        }
    }

    /// `(exit, stdout, stderr)` of a step run through the real runner.
    pub async fn run_step(step: &RemoteStep) -> (i32, String, String) {
        let s = step.clone();
        tokio::task::spawn_blocking(move || {
            let tty = if s
                .pins
                .narrowing
                .0
                .iter()
                .any(|o| o.key == "BatchMode" && o.value == "no")
            {
                TtyMode::Interactive
            } else {
                TtyMode::Batch
            };
            let r = SshStepRunner::new().run(&s, tty).expect("the step runs");
            (r.exit_status, r.stdout, r.stderr_excerpt)
        })
        .await
        .unwrap()
    }

    pub fn rand16() -> [u8; 16] {
        let hex = heimdall_testkit::agent::random_hex(16);
        let mut b = [0u8; 16];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        b
    }
}

#[cfg(unix)]
use fx::*;

/// m03-plan U10: the full flow on `LoopbackSshd`: preview, the attended `EnrollAccount`
/// decision, the client-executed inspect and append (the real scripts through
/// `SshStepRunner`), the runtime's own verification (one signature for the positive,
/// none for the negative), and E5: `verified`, the CA in the pair's issuing set, the
/// preference `managed_certificate` with `projection: pending`, `next: setup_apply`.
/// Decisions counted: exactly the enrollment's. (The setup apply and the managed
/// `ensure` legs need the integrated runtime: U10-C/U10-D.)
#[cfg(unix)]
#[tokio::test]
async fn enroll_preview_apply_verify_setup_apply_ensure_ssh() {
    let w = World::new().await;
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    assert_eq!(plan.approved_target.port, w.sshd.port);
    assert!(w.records().is_empty(), "the preview writes nothing");
    let e = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_full",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let op = e.operation_id.clone().unwrap();
    let record = w.records().pop().unwrap();
    assert_eq!(record.state, EnrollmentState::Planned);
    w.decide(&e, Verdict::Approve).await.unwrap();
    assert_eq!(w.record(&record.id).state, EnrollmentState::Applying);
    let result = w
        .drive(&op)
        .await
        .unwrap_or_else(|e| panic!("drive: {e:?}"));
    assert_eq!(result.state, EnrollmentState::Verified, "{result:?}");
    assert_eq!(
        result.next,
        Some(heimdall_contract::enrollment::EnrollmentNext::SetupApply)
    );
    assert_eq!(w.marker_lines(), 1);
    assert!(w.registry_text().contains(&plan.line));
    // The existing access is untouched (D5 §6.6).
    assert!(w.registry_text().contains(&w.existing));
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Verified);
    let evidence = r.evidence.expect("evidence");
    assert!(!evidence.server.is_empty());
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let pref = w
        .tx(|tx| {
            tx.pair_preference(&heimdall_domain::scope::AccessPair {
                destination: w.destination.clone(),
                account: w.account.clone(),
            })
        })
        .unwrap();
    assert_eq!(
        pref.mechanism,
        heimdall_contract::managed::PreferredMechanism::ManagedCertificate
    );
    assert!(pref.issuing_cas.contains(&r.ca_fingerprint));
    assert_eq!(
        w.endpoints.live.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    // Exactly one decision: the enrollment's.
    let decisions = w.tx(|tx| tx.pending_decisions()).len();
    assert_eq!(decisions, 0);
}

/// m03-plan U10 (D5 §6.10): an apply always needs the attended decision; an
/// unattended caller gets `INTERACTION_REQUIRED` with the decision reference, and an
/// unattended `Decide` is refused (nothing consumed).
#[cfg(unix)]
#[tokio::test]
async fn enroll_requires_attended_decision() {
    let w = World::new().await;
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    let e = w
        .apply(
            &unattended(),
            &spec,
            &plan,
            "req_un",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(e.code, Code::InteractionRequired, "{e:?}");
    let id = e.next.decision_ref.clone().unwrap();
    let refused = w
        .ops
        .decide(
            &unattended(),
            DecideRequest {
                decision_id: heimdall_contract::ids::DecisionId::parse(&id).unwrap(),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::InteractionRequired);
    assert_eq!(w.records().pop().unwrap().state, EnrollmentState::Planned);
    assert_eq!(w.tx(|tx| tx.pending_decisions()).len(), 1, "not consumed");
    // A step before the approval answers the pending decision, writing nothing.
    let op = e.operation_id.clone().unwrap();
    let before = w.receipts(&op).len();
    assert!(w.step(&op).await.is_err());
    assert_eq!(w.receipts(&op).len(), before);
}

/// m03-plan U10 (D5 §6.3 item 3): a result whose token is not the outstanding one is
/// `REQUEST_CONFLICT` (`step_token_mismatch`), and nothing is recorded.
#[cfg(unix)]
#[tokio::test]
async fn step_result_with_wrong_token_refused_nothing_recorded() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_tok").await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("a step");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    let before = w.receipts(&op);
    let state = w.records().pop().unwrap().state;
    let e = w
        .result(&op, &"0".repeat(32), 0, "HM1 ready\nHM1 v=1\n", "")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::RequestConflict);
    assert_eq!(e.reason.as_deref(), Some("step_token_mismatch"));
    assert_eq!(w.receipts(&op), before, "nothing recorded");
    assert_eq!(w.records().pop().unwrap().state, state);
    // The right token is still accepted.
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.class, "confirmed");
}

/// m03-plan U10 (§17.1 item 6): at most one step is outstanding per enrollment.
#[cfg(unix)]
#[tokio::test]
async fn second_step_refused_while_one_outstanding() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_two").await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("a step");
    };
    let before = w.receipts(&op).len();
    let e = w.step(&op).await.unwrap_err();
    assert_eq!(e.code, Code::RequestConflict);
    assert_eq!(e.reason.as_deref(), Some("step_outstanding"));
    assert_eq!(w.receipts(&op).len(), before, "no second receipt");
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.class, "confirmed");
    assert!(matches!(w.step_answer(&op).await, StepAnswer::Step { .. }));
}

/// m03-plan U10 (§17.1 item 2): the route is re-evaluated before every dispatch; a
/// different host key (or port) after the approval refuses the step with
/// `route_changed`, and no stage receipt is written.
#[cfg(unix)]
#[tokio::test]
async fn step_refused_when_route_changed_after_approval() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_route").await;
    let other = FixtureKey::generate();
    let line = other.public_line_without_comment();
    let (kt, kb) = (
        line.split_whitespace().next().unwrap().to_owned(),
        line.split_whitespace().nth(1).unwrap().to_owned(),
    );
    w.target.evaluation.lock().unwrap().host_keys = vec![raw_key(&kt, &kb)];
    let before = w.receipts(&op).len();
    let e = w.step(&op).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("route_changed"));
    assert_eq!(w.receipts(&op).len(), before, "no receipt");
    w.target.evaluation.lock().unwrap().port = 1;
    let e = w.step(&op).await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("route_changed"));
    assert_eq!(w.marker_lines(), 0);
}

/// m03-plan U10 (ADR-0006 §7): the same key with the same parameters replays the
/// operation; with different parameters it is `REQUEST_CONFLICT`, and no second
/// record is written.
#[cfg(unix)]
#[tokio::test]
async fn enroll_same_key_replays_different_params_conflict() {
    let w = World::new().await;
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    let mut other = spec.clone();
    other.registry_path = None;
    let plan2 = w.preview(&other).await;
    let first = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_same",
            InteractionMode::NonInteractive,
        )
        .await;
    let again = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_same",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(first.operation_id, again.operation_id);
    assert_eq!(again.code, Code::ApprovalRequired);
    let e = w
        .apply(
            &attended(),
            &other,
            &plan2,
            "req_same",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(e.code, Code::RequestConflict, "{e:?}");
    assert_eq!(w.records().len(), 1);
}

/// m03-plan U10 (D5 §6.1): a second enrollment of the same pair under the same CA is
/// `CONFIG_CONFLICT`, `already_enrolled`, before any write; an `abandoned` one is
/// outside the rule (Q25).
#[cfg(unix)]
#[tokio::test]
async fn enroll_second_for_same_pair_and_ca_already_enrolled() {
    let w = World::new().await;
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    let _ = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_a",
            InteractionMode::NonInteractive,
        )
        .await;
    let e = w
        .req(
            &unattended(),
            EnrollmentRequest::Preview { spec: spec.clone() },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(e.reason.as_deref(), Some("already_enrolled"));
    let ops_before = w.tx(|tx| tx.open_operations()).len();
    let e = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_b",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(
        w.tx(|tx| tx.open_operations()).len(),
        ops_before,
        "nothing written"
    );
    assert_eq!(w.records().len(), 1);
}

/// m03-plan U10 (F13; D5 §6.1): an account whose existing access the catalog cannot
/// drive (password only) is refused at preview, `existing_access_kind_unsupported`.
#[cfg(unix)]
#[tokio::test]
async fn enroll_password_only_account_refused_existing_access_kind_unsupported() {
    let w = World::with(WorldOptions {
        identity_key_type_ok: false,
        ..WorldOptions::default()
    })
    .await;
    let e = w
        .req(&unattended(), EnrollmentRequest::Preview { spec: w.spec() })
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        Some("existing_access_kind_unsupported")
    );
    assert!(w.records().is_empty());
}

/// m03-plan U10 (D5 §6.10): non-interactive, a provider that needs interaction (a
/// locked agent) fails the step before any write: the provider's code, and the record
/// `failed_unwritten`.
#[cfg(unix)]
#[tokio::test]
async fn enroll_noninteractive_provider_interaction_refused_before_write() {
    let w = World::with(WorldOptions {
        agent_mode: AgentMode::Locked,
        ..WorldOptions::default()
    })
    .await;
    let op = w.approved(&w.spec(), "req_lock").await;
    let e = w.drive(&op).await.unwrap_err();
    assert!(
        matches!(
            e.code,
            Code::ProviderLocked | Code::InteractionRequired | Code::CapabilityUnavailable
        ),
        "{e:?}"
    );
    let r = w.records().pop().unwrap();
    assert_eq!(r.state, EnrollmentState::FailedUnwritten);
    assert_eq!(w.marker_lines(), 0);
    assert_eq!(w.op(&op).state, OperationState::Failed);
}

/// m03-plan U10 (D5 §6.3): the CLI killed during the append (ssh ended after the ready
/// line, the outcome unknown) leaves the step `Uncertain`: the record and the
/// operation `outcome_unknown`, `next: reconcile`.
#[cfg(unix)]
#[tokio::test]
async fn cli_killed_during_append_step_leaves_outcome_unknown() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_kill").await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect");
    };
    w.run_and_report(&op, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("append");
    };
    assert_eq!(step.stage, RemoteStage::Append);
    let c = w
        .result(
            &op,
            &step.step_token,
            heimdall_enroll::remote::KILLED_EXIT_STATUS,
            "HM1 ready\n",
            "",
        )
        .await
        .unwrap();
    let r: StepRecorded = serde_json::from_value(c.data).unwrap();
    assert_eq!(r.class, "uncertain");
    assert_eq!(r.state, EnrollmentState::OutcomeUnknown);
    assert_eq!(w.op(&op).state, OperationState::OutcomeUnknown);
    let e = w.step(&op).await.unwrap_err();
    assert_eq!(e.code, Code::OutcomeUnknown);
    assert_eq!(e.next.action, "reconcile");
}

/// m03-plan U10: a result that never arrives makes a mutating stage `Uncertain` after
/// `enrollment_step_timeout`; a read stage is retryable (the pass clears it).
#[cfg(unix)]
#[tokio::test]
async fn step_result_timeout_marks_mutation_uncertain_and_read_retryable() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_to").await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    w.clock.advance(std::time::Duration::from_secs(121));
    assert_eq!(
        w.ops.enrollment_step_timeout_pass().await.unwrap(),
        vec![op.clone()]
    );
    assert_eq!(w.records().pop().unwrap().state, EnrollmentState::Applying);
    // Retryable: the next step is a fresh inspect.
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect again");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    w.run_and_report(&op, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("append");
    };
    assert_eq!(step.stage, RemoteStage::Append);
    w.clock.advance(std::time::Duration::from_secs(121));
    assert_eq!(
        w.ops.enrollment_step_timeout_pass().await.unwrap(),
        vec![op.clone()]
    );
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::OutcomeUnknown
    );
    assert_eq!(w.op(&op).state, OperationState::OutcomeUnknown);
    // The late result is refused: the step is no longer outstanding.
    let e = w
        .result(&op, &step.step_token, 0, "HM1 ready\n", "")
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("step_token_mismatch"));
}

/// m03-plan U10 (D5 §6.4 "At restart"): an open enrollment operation is never driven
/// at restart; it stays where it was and is reported (`owner_reconcile`), and the
/// owner resumes it.
#[cfg(unix)]
#[tokio::test]
async fn enroll_restart_leaves_operation_unresolved_and_reported() {
    let mut w = World::new().await;
    let op = w.approved(&w.spec(), "req_rs").await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect");
    };
    w.run_and_report(&op, &step).await;
    let before = (w.op(&op).state, w.records().pop().unwrap().state);
    w.restart().await;
    assert_eq!((w.op(&op).state, w.records().pop().unwrap().state), before);
    let env = w.env.clone();
    let reported = w
        .tx(|tx| tx.events_after(&env, 0, &Default::default(), 10_000))
        .events
        .iter()
        .any(|e| {
            e.operation_id.as_ref() == Some(&op)
                && e.payload.get("reason").and_then(|v| v.as_str()) == Some("owner_reconcile")
        });
    assert!(
        reported,
        "the restart reports the open enrollment operation"
    );
    // The owner resumes it.
    let result = w.drive(&op).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(result.state, EnrollmentState::Verified);
}

/// m03-plan U10 (§17.4 item 9): the verification session is dropped on every exit
/// path (here: a pass, and a run whose issuer is unavailable).
#[cfg(unix)]
#[tokio::test]
async fn verification_session_dropped_on_every_exit_path() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_drop").await;
    w.issuer
        .available
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let _ = w.drive(&op).await;
    use std::sync::atomic::Ordering;
    assert!(w.endpoints.created.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        w.endpoints.live.load(Ordering::SeqCst),
        0,
        "dropped after a failure"
    );
    w.issuer.available.store(true, Ordering::SeqCst);
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Reconcile {
                operation_id: op.clone(),
                interaction: InteractionMode::NonInteractive,
                after_manual_recovery: false,
            },
        )
        .await;
    let _ = c;
    assert_eq!(
        w.endpoints.live.load(Ordering::SeqCst),
        0,
        "dropped after a pass"
    );
}

/// m03-plan U10 (D5 §6.9; §17.1 items 7, 11): the system form. `EnrollSystemForm`
/// moves the record to `manual_pending` with the lines to apply; the owner applies
/// them; `enroll verify` runs the §6.5 verification (`verified`). `enroll remove` (the
/// typed confirmation, no decision) moves it to `manual_removal_pending` with the lines
/// to delete; once deleted, `enroll verify --absence` needs the positive certificate
/// **refused** with full evidence before the record is `removed`.
#[cfg(unix)]
#[tokio::test]
async fn enroll_system_form_manual_apply_verify_and_manual_removal_with_absence_check() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let spec = w.system_spec();
    let plan = w.preview(&spec).await;
    let e = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_sys",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let op = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let record = w.records().pop().unwrap();
    assert_eq!(record.state, EnrollmentState::ManualPending);
    let applied = w.op(&op);
    assert_eq!(applied.state, OperationState::Succeeded);
    let result: EnrollmentResult = serde_json::from_value(applied.result.unwrap()).unwrap();
    assert!(!result.instructions.is_empty());
    assert_eq!(w.marker_lines(), 0, "Heimdall wrote nothing remote");
    // The owner applies the lines.
    w.sshd.trust_user_ca(w.issuer.ca.public_line()).unwrap();
    let principal = plan.verification.positive_principal.clone();
    w.sshd
        .set_principals(w.account.as_str(), &[principal.as_str()])
        .unwrap();
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Verify {
                enrollment_id: record.id.clone(),
                request_id: RequestId::parse("req_sys_v").unwrap(),
                mode: VerifyMode::Presence,
                wait: WaitMode::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("verify: {e:?}"));
    let verified: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(verified.state, EnrollmentState::Verified, "{verified:?}");
    assert_eq!(w.record(&record.id).state, EnrollmentState::Verified);
    // The removal: the typed confirmation, no decision.
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Remove {
                target: RemovalTarget::Enrollment {
                    enrollment_id: record.id.clone(),
                },
                request_id: RequestId::parse("req_sys_rm").unwrap(),
                interaction: InteractionMode::NonInteractive,
                wait: WaitMode::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("remove: {e:?}"));
    let removing: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(removing.state, EnrollmentState::ManualRemovalPending);
    assert!(!removing.instructions.is_empty());
    let r = w.record(&record.id);
    assert_eq!(
        r.removal_origin.as_ref().map(|o| o.state),
        Some(EnrollmentState::Verified)
    );
    // Never reported removed without the absence check: an absence check while the
    // lines are still installed returns to `manual_removal_pending`.
    let still = w
        .req(
            &attended(),
            EnrollmentRequest::Verify {
                enrollment_id: record.id.clone(),
                request_id: RequestId::parse("req_sys_abs1").unwrap(),
                mode: VerifyMode::Absence,
                wait: WaitMode::default(),
            },
        )
        .await;
    assert!(still.is_err(), "{still:?}");
    assert_eq!(
        w.record(&record.id).state,
        EnrollmentState::ManualRemovalPending
    );
    // The owner deletes the lines; the absence check then passes.
    fs_clear(w.sshd.trusted_ca_keys_path().unwrap());
    w.sshd.set_principals(w.account.as_str(), &[]).unwrap();
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Verify {
                enrollment_id: record.id.clone(),
                request_id: RequestId::parse("req_sys_abs2").unwrap(),
                mode: VerifyMode::Absence,
                wait: WaitMode::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("absence: {e:?}"));
    let removed: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(removed.state, EnrollmentState::Removed);
    assert_eq!(
        w.endpoints.live.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[cfg(unix)]
fn fs_clear(path: &std::path::Path) {
    std::fs::write(path, b"").unwrap();
}

/// m03-plan U10 (D5 §6.7): an append whose result was lost but which landed: the
/// reconcile's client-executed inspect finds exactly one exact line (`Applied`), and the
/// record continues at E4 under the still-valid approval.
#[cfg(unix)]
#[tokio::test]
async fn enroll_reconcile_applied() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_ra").await;
    w.uncertain_append(&op, true).await;
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::OutcomeUnknown
    );
    assert_eq!(w.marker_lines(), 1, "the append landed");
    let c = w.reconcile(&attended(), &op, false).await.unwrap();
    assert_eq!(c.data["next"], "step");
    let _ = w.drive(&op).await;
    let r = w.records().pop().unwrap();
    // Applied: `applied_unverified`, then the initial verification (E4).
    assert!(
        matches!(
            r.state,
            EnrollmentState::AppliedUnverified | EnrollmentState::Verified
        ),
        "{:?}",
        r.state
    );
    assert_eq!(w.marker_lines(), 1, "never appended twice");
}

/// m03-plan U10 (D5 §6.7): an unreachable destination leaves the step unknown.
#[cfg(unix)]
#[tokio::test]
async fn enroll_reconcile_unreachable() {
    let mut w = World::new().await;
    let op = w.approved(&w.spec(), "req_ru").await;
    w.uncertain_append(&op, false).await;
    w.sshd.stop();
    w.reconcile(&attended(), &op, false).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("the reconcile's inspect");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.state, EnrollmentState::OutcomeUnknown);
    assert_eq!(w.op(&op).state, OperationState::OutcomeUnknown);
}

/// m03-plan U10 (D5 §6.2; §17.4 item 2): the owner abandons from `outcome_unknown`
/// (keeping the `late_write` residual), from `remove_unknown`, and from
/// `rollback_pending`; the record is `abandoned`, its open operation settled.
#[cfg(unix)]
#[tokio::test]
async fn abandon_from_outcome_unknown_remove_unknown_and_rollback_pending() {
    // outcome_unknown
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_ab1").await;
    w.uncertain_append(&op, false).await;
    let id = w.records().pop().unwrap().id;
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Abandon {
                enrollment_id: id.clone(),
            },
        )
        .await
        .unwrap();
    let res: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(res.state, EnrollmentState::Abandoned);
    let r = w.record(&id);
    assert!(
        r.late_write.is_some(),
        "the uncertain append's residual is kept"
    );
    assert!(w.op(&op).state.is_settled());
    // A non-owner cannot abandon.
    let e = w
        .req(
            &Caller::unattended(consumer()),
            EnrollmentRequest::Abandon { enrollment_id: id },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);

    // remove_unknown: a removal whose remove step's result was lost.
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_ab2").await;
    let _ = w.drive(&op).await;
    let id = w.records().pop().unwrap().id;
    assert_eq!(w.marker_lines(), 1);
    let e = w.remove(&id, "req_ab2_rm").await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let rm = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    assert_eq!(w.record(&id).state, EnrollmentState::Removing);
    let StepAnswer::Step { step } = w.step_answer(&rm).await else {
        panic!("inspect");
    };
    w.run_and_report(&rm, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&rm).await else {
        panic!("remove");
    };
    assert_eq!(step.stage, RemoteStage::Remove);
    w.result(
        &rm,
        &step.step_token,
        heimdall_enroll::remote::KILLED_EXIT_STATUS,
        "HM1 ready\n",
        "",
    )
    .await
    .unwrap();
    assert_eq!(w.record(&id).state, EnrollmentState::RemoveUnknown);
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Abandon {
                enrollment_id: id.clone(),
            },
        )
        .await
        .unwrap();
    let res: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(res.state, EnrollmentState::Abandoned);

    // rollback_pending (seeded: the initial verification's failure).
    let w = World::new().await;
    let seeded = w.seed(
        EnrollmentState::RollbackPending,
        EnrollmentForm::Account,
        w.served_target(),
        None,
    );
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Abandon {
                enrollment_id: seeded.id.clone(),
            },
        )
        .await
        .unwrap();
    let res: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(res.state, EnrollmentState::Abandoned);
}

/// m03-plan U10 (§17.1 item 4; F-R-CR-06): a rotation enrolls a second CA for the
/// pair beside the first; the first's removal runs with every managed binding
/// released and the issuer unavailable (maintenance never depends on the managed
/// credential), removes exactly its own line and leaves the second.
#[cfg(unix)]
#[tokio::test]
async fn rotation_and_removal_with_every_managed_binding_released_and_issuer_unavailable() {
    use std::sync::atomic::Ordering;
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_rot1").await;
    let _ = w.drive(&op).await;
    let first = w.records().pop().unwrap();
    let ca2 = w.add_ca();
    let mut spec2 = w.spec();
    spec2.ca_fingerprint = Some(ca2.clone());
    let op2 = w.approved(&spec2, "req_rot2").await;
    let _ = w.drive(&op2).await;
    assert_eq!(w.marker_lines(), 2, "both CAs' lines");
    let second = w
        .records()
        .into_iter()
        .find(|r| r.ca_fingerprint == ca2)
        .unwrap();
    // The issuer is unavailable; no binding exists.
    w.issuer.available.store(false, Ordering::SeqCst);
    let e = w.remove(&first.id, "req_rot_rm").await.unwrap_err();
    let rm = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let res = w
        .drive(&rm)
        .await
        .unwrap_or_else(|e| panic!("removal: {e:?}"));
    assert_eq!(res.state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 1);
    assert!(w.registry_text().contains(&second.marker));
    assert!(!w.registry_text().contains(&first.marker));
    assert!(
        w.registry_text().contains(&w.existing),
        "only owned lines change"
    );
    assert!(
        w.agent.log().iter().any(|c| c.msg_type == 13),
        "the existing access signed"
    );
}

/// m03-plan U10 (§17.4 item 12; B R2-18): a verified result discloses that ordinary
/// `ssh <alias>` works only while a binding holds the slot.
#[cfg(unix)]
#[tokio::test]
async fn enrollment_result_next_discloses_slot_free() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    let op = record.evidence.as_ref().unwrap().operation.clone();
    let result: EnrollmentResult = serde_json::from_value(w.op(&op).result.unwrap()).unwrap();
    assert!(
        result.notes.iter().any(|n| n.kind
            == heimdall_contract::enrollment::EnrollmentNoteKind::OrdinarySshNeedsHeldSlot
            && n.command.is_some()),
        "{result:?}"
    );
}

/// m03-plan U10 (D5 §6.5, F27): the supervisor re-verifies a `verified` pair before its
/// evidence lapses (here `reverify_after` is shortened), non-interactively; freshness
/// is renewed and nothing remote changes.
#[cfg(unix)]
#[tokio::test]
async fn supervisor_reverifies_before_freshness_lapses() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        limits: heimdall_app::operations::Limits {
            reverify_after: std::time::Duration::from_secs(1),
            ..heimdall_app::operations::Limits::default()
        },
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    let first = record.verified_at.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let done = w.ops.reverify_pass().await.unwrap();
    assert_eq!(done, vec![record.id.clone()]);
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Verified);
    assert!(r.verified_at.unwrap() > first, "freshness renewed");
    assert_eq!(w.marker_lines(), 0, "nothing remote");
}

/// m03-plan U10 (§17.4 item 11; B R2-09): a client change (not contrary evidence)
/// triggers a prompt re-verification; an unchanged client does not.
#[cfg(unix)]
#[tokio::test]
async fn client_change_triggers_prompt_reverification() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    assert!(
        w.ops.reverify_pass().await.unwrap().is_empty(),
        "fresh, same client"
    );
    *w.host.version.lock().unwrap() = "OpenSSH_10.6p1, LibreSSL 3.3.6".to_owned();
    assert_eq!(
        w.ops.reverify_pass().await.unwrap(),
        vec![record.id.clone()]
    );
}

/// m03-plan U10 (§17.4 item 5; B R2-05 … evidence-based holds): a re-verification that
/// finds the positive refused holds the record (evidence-based); after the owner
/// fixes the server, `enroll verify` re-verifies it from `held` to `verified`.
#[cfg(unix)]
#[tokio::test]
async fn held_evidence_hold_reverifies_on_owner_request() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let (record, plan) = w.system_verified().await;
    w.sshd.set_principals(w.account.as_str(), &[]).unwrap();
    let e = w
        .verify(&record.id, "req_hold_1", VerifyMode::Presence)
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("verification_failed"), "{e:?}");
    let held = w.record(&record.id);
    assert_eq!(held.state, EnrollmentState::Held);
    assert!(held.hold.unwrap().evidence_based);
    w.sshd
        .set_principals(
            w.account.as_str(),
            &[plan.verification.positive_principal.as_str()],
        )
        .unwrap();
    let c = w
        .verify(&record.id, "req_hold_2", VerifyMode::Presence)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let r: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(r.state, EnrollmentState::Verified);
    assert!(w.record(&record.id).hold.is_none());
}

/// m03-plan U10 (§17.7 item 5): a target change's verification takes its pins from the
/// operation's proposed target; a pass replaces the approved target atomically with the
/// move to `verified`.
#[cfg(unix)]
#[tokio::test]
async fn target_change_pins_come_from_proposed_target() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    // The owner's server trusts the CA for the pair (system form).
    w.sshd.trust_user_ca(w.issuer.ca.public_line()).unwrap();
    let principal = format!("hm:{}:{}", w.destination.as_str(), w.account.as_str());
    w.sshd
        .set_principals(w.account.as_str(), &[principal.as_str()])
        .unwrap();
    // A held host-key change (seeded): the approved key is an old one; the server's is
    // the proposed one.
    let old = FixtureKey::generate();
    let line = old.public_line_without_comment();
    let mut approved = w.served_target();
    approved.host_key = raw_key("ssh-ed25519", line.split_whitespace().nth(1).unwrap()).approved();
    let seeded = w.seed(
        EnrollmentState::Held,
        EnrollmentForm::System,
        approved.clone(),
        Some(heimdall_domain::enrollment::EnrollmentHold {
            reason: heimdall_domain::enrollment::HoldReason::HostKeyChanged,
            evidence_based: false,
        }),
    );
    let e = w
        .verify(&seeded.id, "req_tc", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    w.decide(&e, Verdict::Approve).await.unwrap();
    let plans = w.endpoints.plans.lock().unwrap().clone();
    let last = plans.last().expect("a verification ran");
    assert_eq!(
        last.approved_target,
        w.served_target(),
        "pins from the proposed target"
    );
    let r = w.record(&seeded.id);
    assert_eq!(r.state, EnrollmentState::Verified);
    assert_eq!(r.target, w.served_target(), "replaced on the pass");
}

/// m03-plan U10 (D4 item 5; §17.1 item 11, F07; §17.7 item 4): a foreign enrollment
/// (another installation's CA, marker and catalog destination ID) is removed from this
/// device: the approved `RemoveEnrollment` admits it `planned → removing`, the removal
/// sub-machine runs keyed by its marker, and only its line goes.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_from_second_installation_with_different_catalog() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    assert_eq!(w.marker_lines(), 1);
    let e = w.remove_foreign(&t, "req_fr").await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let rm = e.operation_id.clone().unwrap();
    assert_eq!(
        w.foreign_records(&t.marker)[0].state,
        EnrollmentState::Planned
    );
    w.decide(&e, Verdict::Approve).await.unwrap();
    assert_eq!(
        w.foreign_records(&t.marker)[0].state,
        EnrollmentState::Removing
    );
    let res = w.drive(&rm).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(res.state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 0);
    assert_eq!(
        w.foreign_records(&t.marker)[0].state,
        EnrollmentState::Removed
    );
}

/// m03-plan U10 (§17.7 item 4): the approval is the frozen `planned → removing` event.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_approved_planned_to_removing() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    let e = w.remove_foreign(&t, "req_fa").await.unwrap_err();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.state, EnrollmentState::Removing);
    assert_eq!(w.op(&f.operation).state, OperationState::Running);
}

/// m03-plan U10 (§17.7 item 4): a denial withdraws the record; nothing remote happens.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_denied_withdrawn_nothing_remote() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    let before = w.registry_text();
    let e = w.remove_foreign(&t, "req_fd").await.unwrap_err();
    w.decide(&e, Verdict::Deny).await.unwrap();
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.state, EnrollmentState::Withdrawn);
    assert_eq!(w.op(&f.operation).state, OperationState::Failed);
    assert_eq!(w.registry_text(), before);
}

/// m03-plan U10 (D4 item 5; F07): a redacted bundle and a descriptor whose line does
/// not hash to its `line_sha256` are refused before anything is written.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_refuses_redacted_bundle_and_line_hash_mismatch() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    let mut redacted = t.clone();
    redacted.bundle_hostname = String::new();
    let e = w.remove_foreign(&redacted, "req_fx1").await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("bundle_redacted"));
    let mut bad = t.clone();
    bad.line_sha256 = "0".repeat(64);
    let e = w.remove_foreign(&bad, "req_fx2").await.unwrap_err();
    assert_eq!(e.code, Code::UsageError);
    assert!(w.foreign_records(&t.marker).is_empty(), "nothing written");
    assert!(w.tx(|tx| tx.open_operations()).is_empty());
}

/// m03-plan U10 (§17.4 item 10): the local alias must evaluate to the bundle's exact
/// host name and port.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_refuses_bundle_host_mismatch() {
    let w = World::new().await;
    let mut t = w.foreign(EnrollmentForm::Account);
    t.bundle_port = t.bundle_port.wrapping_add(1);
    let e = w.remove_foreign(&t, "req_fh").await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("bundle_host_mismatch"));
    let mut t2 = w.foreign(EnrollmentForm::Account);
    t2.bundle_hostname = "localhost".to_owned();
    let e = w.remove_foreign(&t2, "req_fh2").await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("bundle_host_mismatch"));
    assert!(w.foreign_records(&t.marker).is_empty());
}

/// m03-plan U10 (§17.4 item 10; B R2-07): a lost reply of the foreign removal's remove
/// step is reconciled by marker.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_lost_reply_reconciled_by_marker() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    let e = w.remove_foreign(&t, "req_fl").await.unwrap_err();
    let rm = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(&rm).await else {
        panic!("inspect");
    };
    w.run_and_report(&rm, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&rm).await else {
        panic!("remove");
    };
    assert_eq!(step.stage, RemoteStage::Remove);
    let _ = run_step(&step).await; // it really removed the line
    w.result(
        &rm,
        &step.step_token,
        heimdall_enroll::remote::KILLED_EXIT_STATUS,
        "HM1 ready\n",
        "",
    )
    .await
    .unwrap();
    assert_eq!(
        w.foreign_records(&t.marker).pop().unwrap().state,
        EnrollmentState::RemoveUnknown
    );
    w.reconcile(&attended(), &rm, false).await.unwrap();
    let _ = w.drive(&rm).await;
    assert_eq!(
        w.foreign_records(&t.marker).pop().unwrap().state,
        EnrollmentState::Removed
    );
    assert_eq!(w.marker_lines(), 0);
}

/// m03-plan U10 (§17.7 item 4; Q28 default): a foreign system-form record takes the
/// manual route (`planned → manual_removal_pending` on the typed confirmation); its
/// absence check ends `ca_not_held`, so it is never reported removed.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_system_form_manual_route_never_reported_removed() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::System);
    let c = w.remove_foreign(&t, "req_fs").await.unwrap();
    assert_eq!(c.data["state"], "manual_removal_pending");
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.state, EnrollmentState::ManualRemovalPending);
    let id =
        heimdall_contract::ids::EnrollmentId::parse(t.marker.strip_prefix("heimdall:").unwrap())
            .unwrap();
    let e = w
        .verify(&id, "req_fs_abs", VerifyMode::Absence)
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("ca_not_held"), "{e:?}");
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.state, EnrollmentState::ManualRemovalPending);
    assert!(f.removal_origin.unwrap().ca_not_held_seen);
}

/// m03-plan U10 (§17.10 item 2): a foreign system-form record can be abandoned from
/// `manual_removal_pending`, keeping `pending_until_line_removed`.
#[cfg(unix)]
#[tokio::test]
async fn foreign_system_form_abandon_keeps_pending_until_line_removed() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::System);
    w.remove_foreign(&t, "req_fab").await.unwrap();
    let id =
        heimdall_contract::ids::EnrollmentId::parse(t.marker.strip_prefix("heimdall:").unwrap())
            .unwrap();
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Abandon { enrollment_id: id },
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(c.data["state"], "abandoned");
    assert_eq!(c.data["residual"], "pending_until_line_removed");
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.state, EnrollmentState::Abandoned);
    assert!(w.op(&f.operation).state.is_settled());
}

/// m03-plan U10 (§17.10 item 2): once a `ca_not_held` result exists, cancelling the
/// manual removal leaves it in `manual_removal_pending`, never `planned` or `withdrawn`.
#[cfg(unix)]
#[tokio::test]
async fn foreign_system_form_cancel_after_ca_not_held_never_planned_or_withdrawn() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::System);
    w.remove_foreign(&t, "req_fc").await.unwrap();
    let id =
        heimdall_contract::ids::EnrollmentId::parse(t.marker.strip_prefix("heimdall:").unwrap())
            .unwrap();
    let _ = w.verify(&id, "req_fc_abs", VerifyMode::Absence).await;
    let f = w.foreign_records(&t.marker).pop().unwrap();
    let r = w
        .ops
        .cancel(
            &attended(),
            heimdall_contract::request::CancelRequest {
                operation_id: f.operation.clone(),
            },
        )
        .await;
    let _ = r;
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.state, EnrollmentState::ManualRemovalPending);
}

/// m03-plan U10 (§17.4 item 5; A R2-05): cancelling a manual removal returns the
/// record to the state it began from, with that state's evidence.
#[cfg(unix)]
#[tokio::test]
async fn manual_removal_cancel_returns_to_origin_state_and_evidence() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    let evidence = record.evidence.clone().unwrap();
    let c = w.remove(&record.id, "req_mc").await.unwrap();
    let rm = c.operation_id.clone().unwrap();
    assert_eq!(
        w.record(&record.id).state,
        EnrollmentState::ManualRemovalPending
    );
    w.ops
        .cancel(
            &attended(),
            heimdall_contract::request::CancelRequest { operation_id: rm },
        )
        .await
        .ok();
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Verified);
    assert_eq!(r.evidence, Some(evidence), "the origin's evidence restored");
    assert!(r.removal_origin.is_none());
}

/// m03-plan U10 (D5 §6.9): a system-form enrollment is never reported removed without
/// its absence check; one whose lines are still installed stays in
/// `manual_removal_pending`.
#[cfg(unix)]
#[tokio::test]
async fn system_form_never_reported_removed_without_absence_check() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    w.remove(&record.id, "req_nr").await.unwrap();
    assert_eq!(
        w.record(&record.id).state,
        EnrollmentState::ManualRemovalPending
    );
    let r = w
        .verify(&record.id, "req_nr_abs", VerifyMode::Absence)
        .await;
    assert!(r.is_err(), "the lines are still installed: {r:?}");
    assert_eq!(
        w.record(&record.id).state,
        EnrollmentState::ManualRemovalPending
    );
    assert!(
        w.records()
            .iter()
            .all(|r| r.state != EnrollmentState::Removed)
    );
}

/// m03-plan U10 (§17.4 item 5): cancelling a system-form enrollment from
/// `manual_pending` keeps it listed (`manual_removal_pending`, origin `manual_pending`)
/// until its absence is verified; then it is `withdrawn`.
#[cfg(unix)]
#[tokio::test]
async fn system_form_cancel_from_manual_pending_keeps_entry_until_absence_verified() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let spec = w.system_spec();
    let plan = w.preview(&spec).await;
    let e = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_cmp",
            InteractionMode::NonInteractive,
        )
        .await;
    w.decide(&e, Verdict::Approve).await.unwrap();
    let id = w.records().pop().unwrap().id;
    assert_eq!(w.record(&id).state, EnrollmentState::ManualPending);
    w.remove(&id, "req_cmp_rm").await.unwrap();
    let r = w.record(&id);
    assert_eq!(
        r.state,
        EnrollmentState::ManualRemovalPending,
        "still listed"
    );
    assert_eq!(
        r.removal_origin.map(|o| o.state),
        Some(EnrollmentState::ManualPending)
    );
    // Nothing was installed: the absence check passes and the record is withdrawn.
    let c = w
        .verify(&id, "req_cmp_abs", VerifyMode::Absence)
        .await
        .unwrap_or_else(|e| panic!("absence: {e:?}"));
    let res: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(res.state, EnrollmentState::Withdrawn);
}

/// Waits until the remote clock (this host's) is past the uncertain step's not-after
/// (the step timeout is 1 s here, so the not-after is the inspect's reading + ~61 s).
#[cfg(unix)]
async fn past_not_after() {
    tokio::time::sleep(std::time::Duration::from_secs(64)).await;
}

#[cfg(unix)]
fn short_steps() -> WorldOptions {
    WorldOptions {
        limits: heimdall_app::operations::Limits {
            enrollment_step_timeout: std::time::Duration::from_secs(1),
            ..heimdall_app::operations::Limits::default()
        },
        ..WorldOptions::default()
    }
}

/// m03-plan U10 (D5 §6.7; Q7 as amended): the append never ran; once its not-after has
/// passed (the old holder can no longer pass its own checks), an attended reconcile
/// within the approval's validity redispatches it, and exactly one line results.
#[cfg(unix)]
#[tokio::test]
async fn enroll_reconcile_not_applied_within_validity() {
    let w = World::with(short_steps()).await;
    let op = w.approved(&w.spec(), "req_rn").await;
    w.uncertain_append(&op, false).await;
    // Before the not-after: nothing is decided (an absence read alone never redispatches).
    w.reconcile(&attended(), &op, false).await.unwrap();
    let _ = w.drive(&op).await;
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::OutcomeUnknown
    );
    assert_eq!(w.marker_lines(), 0);
    past_not_after().await;
    w.reconcile(&attended(), &op, false).await.unwrap();
    let _ = w.drive(&op).await;
    let r = w.records().pop().unwrap();
    assert!(
        matches!(
            r.state,
            EnrollmentState::AppliedUnverified | EnrollmentState::Verified
        ),
        "{:?}",
        r.state
    );
    assert_eq!(w.marker_lines(), 1, "exactly one line");
}

/// m03-plan U10 (F20): a reconcile that would redispatch an append needs an attended
/// session; an unattended one leaves it uncertain.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_redispatch_requires_attended_session() {
    let w = World::with(short_steps()).await;
    let op = w.approved(&w.spec(), "req_rd").await;
    w.uncertain_append(&op, false).await;
    past_not_after().await;
    w.reconcile(&unattended(), &op, false).await.unwrap();
    let _ = w.drive(&op).await;
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::OutcomeUnknown
    );
    assert_eq!(w.marker_lines(), 0, "no redispatch");
}

/// m03-plan U10 (D5 §6.7): the line is absent after fencing but the approval lapsed:
/// `DECISION_STALE`, `approval_lapsed`, and the record `withdrawn`.
#[cfg(unix)]
#[tokio::test]
async fn enroll_reconcile_approval_lapsed() {
    let w = World::with(short_steps()).await;
    let op = w.approved(&w.spec(), "req_rl").await;
    w.uncertain_append(&op, false).await;
    past_not_after().await;
    w.clock.advance(std::time::Duration::from_secs(25 * 3600));
    w.reconcile(&attended(), &op, false).await.unwrap();
    let e = w.drive(&op).await.unwrap_err();
    assert_eq!(e.code, Code::DecisionStale, "{e:?}");
    assert_eq!(e.reason.as_deref(), Some("approval_lapsed"));
    assert_eq!(w.records().pop().unwrap().state, EnrollmentState::Withdrawn);
}

/// m03-plan U10 (§17.4 item 2): an uncertain append left for `withdrawn` keeps the
/// `late_write` residual (`possible_late_write`).
#[cfg(unix)]
#[tokio::test]
async fn uncertain_append_left_for_withdrawn_keeps_late_write_residual() {
    let w = World::with(short_steps()).await;
    let op = w.approved(&w.spec(), "req_lw").await;
    w.uncertain_append(&op, false).await;
    past_not_after().await;
    w.clock.advance(std::time::Duration::from_secs(25 * 3600));
    w.reconcile(&attended(), &op, false).await.unwrap();
    let _ = w.drive(&op).await;
    let r = w.records().pop().unwrap();
    assert_eq!(r.state, EnrollmentState::Withdrawn);
    let lw = r.late_write.expect("the late_write residual");
    assert!(lw.not_after_remote > 0);
}

/// m03-plan U10 (D4 item 3; §6.2): a CA is retired only once every enrollment under it
/// is final or `abandoned` (U10-B's retirement precondition over U10-A's records).
#[cfg(unix)]
#[tokio::test]
async fn ca_retirement_refused_until_every_enrollment_final_or_abandoned() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_ret").await;
    w.uncertain_append(&op, false).await;
    let id = w.records().pop().unwrap().id;
    let retire = heimdall_contract::issuer::IssuerRequest::Retire {
        ca_fingerprint: w.issuer.ca.fingerprint().clone(),
    };
    let e = w
        .ops
        .issuer_request(&attended(), retire.clone())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    w.req(
        &attended(),
        EnrollmentRequest::Abandon { enrollment_id: id },
    )
    .await
    .unwrap();
    let r = w.ops.issuer_request(&attended(), retire).await;
    match r {
        Ok(_) => {}
        Err(e) => assert_ne!(e.code, Code::ConfigConflict, "{e:?}"),
    }
}

/// m03-plan U10 (Q25; §17.4 item 5): `abandoned` is outside the uniqueness rule: a new
/// enrollment of the pair uses a new marker, and the abandoned record stays listed.
#[cfg(unix)]
#[tokio::test]
async fn reenroll_after_abandoned_uses_new_marker_old_residual_listed() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_re1").await;
    w.uncertain_append(&op, false).await;
    let old = w.records().pop().unwrap();
    w.req(
        &attended(),
        EnrollmentRequest::Abandon {
            enrollment_id: old.id.clone(),
        },
    )
    .await
    .unwrap();
    let plan = w.preview(&w.spec()).await;
    assert!(!plan.line.contains(&old.marker), "a new marker");
    let e = w
        .apply(
            &attended(),
            &w.spec(),
            &plan,
            "req_re2",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let all = w.records();
    assert_eq!(all.len(), 2);
    assert!(
        all.iter()
            .any(|r| r.id == old.id && r.state == EnrollmentState::Abandoned)
    );
}

/// m03-plan U10 (§17.7 item 4): a held foreign removal (a damaged line: two marker
/// lines) is recovered by a new `RemoveEnrollment` decision.
#[cfg(unix)]
#[tokio::test]
async fn foreign_removal_held_recovery_by_new_decision_or_abandon() {
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    // A second line with the same marker: damaged.
    let text = w.registry_text();
    let line = text
        .lines()
        .find(|l| l.contains(&t.marker))
        .unwrap()
        .to_owned();
    w.sshd.append_registry_line(&format!("{line} x")).unwrap();
    let e = w.remove_foreign(&t, "req_fhr1").await.unwrap_err();
    let rm = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let _ = w.drive(&rm).await;
    assert_eq!(
        w.foreign_records(&t.marker).pop().unwrap().state,
        EnrollmentState::Held
    );
    // A new decision recovers it.
    let e = w.remove_foreign(&t, "req_fhr2").await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    w.decide(&e, Verdict::Approve).await.unwrap();
    let records = w.foreign_records(&t.marker);
    assert_eq!(records.len(), 1, "the held record is reused");
    assert_eq!(records[0].state, EnrollmentState::Removing);
}
