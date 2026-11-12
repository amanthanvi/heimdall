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
//!
//! **Windows** (⟨W4-N01; ADR-0008 §17.22, §17.23 item 6⟩). The same flows run natively on
//! Windows wherever nothing Unix-only is needed (the table in
//! `.m03-wave4-r3b-worklog-W.md`): the client is the in-box `ssh.exe` (the verified
//! client; its `-F <scratch config>` and fixture environment are added by the test's
//! [`StepContainment`](heimdall_enroll::remote::StepContainment), the kill-on-close job a
//! Windows step needs anyway, since there is no `/bin/sh` wrapper), the server is the
//! harness's WSL fixture sshd (`HM_FIXTURE_SSHD_*`, adopted by `LoopbackSshd::start`),
//! whose account-form registry is its enrollment registry on the WSL file system
//! (`HM_FIXTURE_SSHD_REGISTRY` / `_REMOTE`; `heimdall_testkit::sshd` module docs), the
//! existing access is a fixture agent on a fixture pipe, the verification endpoint
//! (`TestSession`) is an owner-only pipe, and the managed endpoints use the Windows
//! layout (`\\.\pipe\heimdall-<token>-b<tag>`). **A test that finds no fixture fails with
//! that reason** (`World::with` panics; nothing returns early or is ignored). A test that
//! truly cannot run on Windows stays `#[cfg(unix)]`, with a `Unix only:` comment naming
//! the reason above it. The Windows-only tests are in `enroll_m03/windows.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]
#![cfg_attr(not(any(unix, windows)), allow(dead_code, unused_imports))]
// Helpers only the Unix-gated tests use are compiled on Windows too.
#![cfg_attr(windows, allow(dead_code))]

/// ⟨W4-N01⟩ The Windows-only tests (the binding endpoint's pipe form).
#[cfg(windows)]
#[path = "enroll_m03/windows.rs"]
mod windows;

#[cfg(any(unix, windows))]
mod fx {
    use std::collections::HashMap;
    use std::fs;
    #[cfg(unix)]
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use async_trait_free::*;
    pub use heimdall_app::enrollment::Journal;
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
    use heimdall_contract::canonical::RequestHash;
    pub use heimdall_contract::enrollment::{
        EnrollmentForm, EnrollmentPlan, EnrollmentRequest, EnrollmentResult, EnrollmentSpec,
        EnrollmentState, RemoteStage, RemoteStep, RemovalTarget, VerifyMode,
    };
    pub use heimdall_contract::ids::OperationId;
    pub use heimdall_contract::ids::RequestId;
    use heimdall_contract::ids::{
        AccountName, CaFingerprint, DestinationId, DeviceId, EnvironmentId, IdentityId,
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
    use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
    pub use heimdall_domain::operation::{
        AdapterIdentity, EffectClass, EffectReceipt, OperationKind, OperationRecord,
        RecoveryIntent, RecoveryMetadata, StageReceipt, enrollment_stage,
    };
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    pub use heimdall_domain::time::Clock;
    use heimdall_domain::time::{BootId, SyncStatus, TimePolicy};
    use heimdall_enroll::remote::{SshStepRunner, TtyMode};
    use heimdall_enroll::verify::{Verifier, VerifierClient};
    use heimdall_store::{IssuerRecord, Store};
    use heimdall_testkit::ScriptedTimeSync;
    pub use heimdall_testkit::agent::{
        AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey, blob_fingerprint,
    };
    use heimdall_testkit::ca::{TestCa, UserCertSpec};
    use heimdall_testkit::home::{ScratchHome, find_program};
    #[cfg(unix)]
    use heimdall_testkit::sshd::current_account;
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

    // ⟨round 2, R2-E⟩ the managed legs: the production adapter, effects, signer table
    // and endpoint registry, and the runtime's store-backed sources (§17.21 item 1).
    use heimdall_adapters::managed::ManagedCertificateAdapter;
    use heimdall_adapters::managed::effects::{BindingEndpoints, ManagedEffectsImpl};
    use heimdall_adapters::managed::files::{SlotRoot, binding_files_for_endpoint};
    use heimdall_adapters::managed::prepare::{EvidenceFeed, TargetAndClient, WithEvidenceFeed};
    use heimdall_app::ports::{CredentialAdapter, IssuanceTable, ManagedEffects, SignerEndpoint};
    use heimdall_contract::ids::{BindingId, PolicyId, ProfileId, WorkId};
    use heimdall_contract::request::{EnsureData, EnsureRequest, RequiredCapabilities};
    use heimdall_contract::setup::ProjectionItem;
    pub use heimdall_contract::setup::SetupPlan;
    use heimdall_credential::cert::{CertificateProfile, build_and_sign};
    use heimdall_credential::endpoints::{EndpointLayout, EndpointRegistry};
    use heimdall_credential::signer::{HookFuture, SignHook, SignStep, SignerLimits};
    use heimdall_credential::table::SignerTable;
    use heimdall_credential::vault::KeyVault;
    use heimdall_runtime::managed_store::{OpsInstallView, StoreCleanup, StoreSources};
    use std::sync::RwLock;
    use tokio_util::sync::CancellationToken;

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
        /// ⟨W4-N01⟩ While set, the clock reads this `(wall, continuous)` ([`Self::hold`]).
        held: Mutex<Option<(Timestamp, Duration)>>,
    }

    impl TestClock {
        pub fn new() -> Arc<TestClock> {
            Arc::new(TestClock {
                start: Instant::now(),
                start_wall: Timestamp::now(),
                offset_ms: AtomicI64::new(0),
                held: Mutex::new(None),
            })
        }

        /// ⟨W4-N01⟩ Stop the clock at its current reading until [`Self::release`] (two
        /// requests that must resolve the same instant, as a virtual clock gives them).
        #[cfg_attr(not(windows), allow(dead_code))]
        pub fn hold(&self) {
            let now = (self.read_wall(), self.read_continuous());
            *self.held.lock().unwrap() = Some(now);
        }

        /// Let the clock run again (from real time, as before the hold).
        #[cfg_attr(not(windows), allow(dead_code))]
        pub fn release(&self) {
            *self.held.lock().unwrap() = None;
        }

        fn read_wall(&self) -> Timestamp {
            let elapsed = i64::try_from(self.start.elapsed().as_millis()).unwrap();
            let off = self.offset_ms.load(Ordering::SeqCst);
            Timestamp::from_millisecond(self.start_wall.as_millisecond() + elapsed + off).unwrap()
        }

        fn read_continuous(&self) -> Duration {
            let off = u64::try_from(self.offset_ms.load(Ordering::SeqCst)).unwrap_or(0);
            self.start.elapsed() + Duration::from_secs(3600) + Duration::from_millis(off)
        }

        pub fn advance(&self, by: Duration) {
            self.offset_ms
                .fetch_add(i64::try_from(by.as_millis()).unwrap(), Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn wall(&self) -> Timestamp {
            match *self.held.lock().unwrap() {
                Some((wall, _)) => wall,
                None => self.read_wall(),
            }
        }

        fn continuous(&self) -> Duration {
            match *self.held.lock().unwrap() {
                Some((_, continuous)) => continuous,
                None => self.read_continuous(),
            }
        }

        fn boot_id(&self) -> BootId {
            BootId("boot-e2e".to_owned())
        }
    }

    // --- the target evaluator (changeable) -------------------------------------------

    pub struct TestTarget {
        pub evaluation: Mutex<TargetEvaluation>,
        /// Other aliases' evaluations (a second destination).
        pub per_alias: Mutex<HashMap<String, TargetEvaluation>>,
    }

    impl TargetEvaluator for TestTarget {
        fn evaluate(&self, alias: &str) -> TargetEvaluation {
            if let Some(e) = self.per_alias.lock().unwrap().get(alias) {
                return e.clone();
            }
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
        /// ⟨W4-N01⟩ Windows: the scratch user configuration `ssh -G` reads (`-F`); on
        /// Unix the client wrapper adds it (`None`).
        pub config: Option<PathBuf>,
        pub version: Mutex<String>,
        pub agent_path: String,
        pub effective_calls: AtomicUsize,
    }

    #[cfg(unix)]
    fn write_mode(path: &Path, text: &[u8], mode: u32) {
        let _ = fs::remove_file(path);
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Windows: the file, then Heimdall's owner-only DACL (`chmod 600`'s faithful form;
    /// `heimdall_testkit::win`). `mode` is the Unix mode this stands for.
    #[cfg(windows)]
    fn write_mode(path: &Path, text: &[u8], mode: u32) {
        let _ = mode;
        let _ = fs::remove_file(path);
        fs::write(path, text).unwrap();
        heimdall_testkit::win::set_owner_only(path).unwrap();
    }

    #[cfg(unix)]
    pub fn owner_only_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// Windows: the directory, then the owner-only directory DACL (`chmod 700`).
    #[cfg(windows)]
    pub fn owner_only_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        heimdall_testkit::win::set_owner_only(path).unwrap();
    }

    /// A path as the enrollment port names it: absolute, `/` separators on Windows (as
    /// the runtime's `slash_path`), unchanged on Unix.
    pub fn port_path(p: &Path) -> String {
        if cfg!(windows) {
            p.to_string_lossy().replace('\\', "/")
        } else {
            p.display().to_string()
        }
    }

    /// The existing-access agent's catalog endpoint: its socket (Unix) or pipe
    /// (Windows), as the catalog records it.
    pub fn agent_ref(locator: &str) -> EndpointRef {
        EndpointRef {
            kind: if cfg!(windows) {
                EndpointKind::NamedPipe
            } else {
                EndpointKind::UnixSocket
            },
            locator: locator.to_owned(),
        }
    }

    /// The agent-protocol locator of an endpoint the runtime named (a binding
    /// endpoint): a socket path (Unix) or a pipe name (Windows).
    pub fn agent_locator(locator: &str) -> heimdall_ipc::agent_client::AgentLocator {
        if cfg!(windows) {
            heimdall_ipc::agent_client::AgentLocator::NamedPipe(locator.to_owned())
        } else {
            heimdall_ipc::agent_client::AgentLocator::UnixSocket(PathBuf::from(locator))
        }
    }

    impl EnrollmentHost for TestHost {
        fn client(&self) -> Option<String> {
            Some(port_path(&self.client))
        }

        fn client_version(&self) -> Option<String> {
            Some(self.version.lock().unwrap().clone())
        }

        fn paths(&self, tag: &str) -> Option<GeneratedPaths> {
            let dir = self.runtime.join("e").join(tag);
            Some(GeneratedPaths {
                trust: TrustPaths {
                    tag: tag.to_owned(),
                    user_known_hosts: port_path(&dir.join("known_hosts")),
                    global_known_hosts: port_path(&dir.join("global_known_hosts")),
                },
                identity_file: port_path(&dir.join("identity.pub")),
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
            // Windows: the rendered pipe (`//./pipe/<name>`) only. Probing a pipe's
            // existence opens a client instance (an agent contact), which a passive check
            // must not do; the fixture agent lives as long as the world.
            endpoint == self.agent_path && (cfg!(windows) || Path::new(endpoint).exists())
        }

        fn heimdall_endpoints(&self) -> Vec<String> {
            vec![port_path(&self.runtime)]
        }

        fn effective_config(&self, step: &RemoteStep) -> Result<String, HostError> {
            self.effective_calls.fetch_add(1, Ordering::SeqCst);
            let mut cmd = std::process::Command::new(&self.client);
            // Windows: the scratch configuration the Unix client wrapper adds.
            if let Some(config) = &self.config {
                cmd.arg("-F").arg(config);
            }
            let out = cmd
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

    #[cfg(unix)]
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

    /// ⟨W4-N01⟩ Windows: the verification endpoint's pipe server, on its own thread and
    /// current-thread runtime: `heimdall_ipc::windows::Listener` (the reviewed listener:
    /// first-instance flag, the owner-only DACL, a client identified as this user after
    /// its first write), each connection served by [`respond`] until it closes. It stops
    /// within a tick of `stop`; dropping the runtime closes every instance.
    #[cfg(windows)]
    fn serve_pipe(
        name: String,
        shared: Arc<SessionShared>,
        stop: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let sid = heimdall_ipc::windows::current_user_sid().unwrap();
                let listener = match heimdall_ipc::windows::Listener::bind(
                    &name,
                    heimdall_ipc::EndpointKind::Signing,
                    &sid,
                ) {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(format!("{:?}", e.kind())));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                while !stop.load(Ordering::SeqCst) {
                    let accepted =
                        tokio::time::timeout(Duration::from_millis(20), listener.accept()).await;
                    let Ok(Ok((mut conn, _peer))) = accepted else {
                        continue;
                    };
                    let s = Arc::clone(&shared);
                    tokio::spawn(async move {
                        loop {
                            let mut len = [0u8; 4];
                            if conn.read_exact(&mut len).await.is_err() {
                                return;
                            }
                            let n = u32::from_be_bytes(len) as usize;
                            if n == 0 || n > 256 * 1024 {
                                return;
                            }
                            let mut msg = vec![0u8; n];
                            if conn.read_exact(&mut msg).await.is_err() {
                                return;
                            }
                            let reply = respond(&msg, &s);
                            let mut framed =
                                u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                            framed.extend_from_slice(&reply);
                            if conn.write_all(&framed).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
        });
        match ready_rx.recv() {
            Ok(Ok(())) => thread,
            Ok(Err(why)) => panic!("the verification pipe could not be bound: {why}"),
            Err(_) => panic!("the verification pipe thread ended before binding"),
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
        /// The store, read at each creation (what the records look like while an
        /// attempt runs).
        pub store: Arc<Store>,
        /// Per creation: every open record's `(id, state, approved target)`.
        pub seen: Mutex<Vec<Vec<SeenRecord>>>,
    }

    /// A record as a verification attempt saw it.
    pub type SeenRecord = (
        heimdall_contract::ids::EnrollmentId,
        EnrollmentState,
        heimdall_contract::enrollment::ApprovedTarget,
    );

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
            let seen = self
                .store
                .transaction(|tx| tx.open_enrollments())
                .unwrap()
                .into_iter()
                .map(|r| (r.id, r.state, r.target))
                .collect();
            self.seen.lock().unwrap().push(seen);
            Box::pin(async move {
                let key = FixtureKey::generate();
                let public = key.public_line_without_comment();
                let fingerprint = key.fingerprint();
                self.keys
                    .lock()
                    .unwrap()
                    .insert(public.clone(), key.clone());
                let n = self.created.fetch_add(1, Ordering::SeqCst);
                let shared = Arc::new(SessionShared {
                    key,
                    certs: Mutex::new(Vec::new()),
                    signatures: AtomicU32::new(0),
                    binds: AtomicU32::new(0),
                });
                let stop = Arc::new(AtomicBool::new(false));
                #[cfg(unix)]
                let (thread, locator) = {
                    let dir = self.dir.join(format!("v{n}"));
                    owner_only_dir(&dir);
                    let path = dir.join("v.sock");
                    let listener = UnixListener::bind(&path).unwrap();
                    listener.set_nonblocking(true).unwrap();
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
                    (
                        thread,
                        EndpointRef {
                            kind: EndpointKind::UnixSocket,
                            locator: path.display().to_string(),
                        },
                    )
                };
                // ⟨W4-N01⟩ Windows: a fixture pipe (`\\.\pipe\heimdall-hmtest-<random>-v<n>`,
                // which the harness counts before and after the run).
                #[cfg(windows)]
                let (thread, locator) = {
                    let name = format!(
                        r"\\.\pipe\heimdall-hmtest-{}-v{n}",
                        heimdall_testkit::agent::random_hex(8)
                    );
                    let thread = serve_pipe(name.clone(), Arc::clone(&shared), Arc::clone(&stop));
                    (
                        thread,
                        EndpointRef {
                            kind: EndpointKind::NamedPipe,
                            locator: name,
                        },
                    )
                };
                self.live.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(TestSession {
                    public,
                    fingerprint,
                    locator,
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
        /// ⟨R2-E⟩ The managed world's signer table: a grant entry is signed for the
        /// grant's live K_env, read from it (the subject the driver names must be that
        /// key's line). `None` outside a managed world: grant entries are refused.
        pub table: Mutex<Option<SignerTable>>,
        /// Grant certificates signed (the managed issuance, not the verification).
        pub grant_signed: AtomicUsize,
    }

    impl TestIssuer {
        /// A grant-table entry: K_ca of the entry's bounds signs exactly those bounds
        /// for the grant's K_env (`build_and_sign`, the issuer child's code path).
        fn sign_grant(&self, entry: &IssuanceRef, subject: &str) -> Result<String, IssuerError> {
            let refused = |why: &str| IssuerError::Protocol(why.to_owned());
            let e = self
                .store
                .transaction(|tx| tx.issuance_entry(&entry.id))
                .map_err(|_| refused("store"))?
                .ok_or_else(|| refused("no entry"))?;
            let table = self
                .table
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| refused("no signer table"))?;
            let info = table
                .public_key(&e.grant)
                .ok_or_else(|| refused("no K_env"))?;
            if info.openssh_line.trim() != subject.trim() {
                return Err(refused("subject"));
            }
            let key = info.public_key().map_err(|_| refused("key"))?;
            let profile = CertificateProfile::from_bounds(&e.bounds);
            let cert = if e.bounds.ca_fingerprint.as_ref() == Some(self.ca.fingerprint()) {
                build_and_sign(&profile, &key, self.ca.secret())
            } else {
                let more = self.more.lock().unwrap();
                let ca = more
                    .iter()
                    .find(|c| e.bounds.ca_fingerprint.as_ref() == Some(c.fingerprint()))
                    .ok_or_else(|| refused("ca"))?;
                build_and_sign(&profile, &key, ca.secret())
            }
            .map_err(|_| refused("sign"))?;
            self.signed.fetch_add(1, Ordering::SeqCst);
            self.grant_signed.fetch_add(1, Ordering::SeqCst);
            cert.to_openssh().map_err(|_| refused("encode"))
        }
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
                if entry.table == IssuanceTable::Grant {
                    return self.sign_grant(&entry, subject);
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
        /// The account-form registry as this process reaches it.
        pub registry: PathBuf,
        /// ⟨W4-N01⟩ The same registry as the server's account names it (the spec's
        /// `registry_path`; equal to `registry` for a local server).
        pub registry_remote: String,
        pub existing: String,
        pub existing_key: FixtureKey,
        pub identity: IdentityId,
        /// ⟨R2-E⟩ The managed credential pieces ([`WorldOptions::managed`]).
        pub managed: Option<Managed>,
        /// [`WorldOptions::default_window`].
        pub default_window: Duration,
        /// ⟨W4-N01⟩ The verified client's parsed version.
        pub client_version: heimdall_enroll::trace::ClientVersion,
        /// ⟨W4-N01⟩ Where the verifier dumps each attempt's raw trace
        /// ([`WorldOptions::observe_trace`]).
        #[cfg_attr(not(windows), allow(dead_code))]
        pub trace_dump: Option<PathBuf>,
        pub home: ScratchHome,
    }

    pub struct WorldOptions {
        pub form: EnrollmentForm,
        pub agent_mode: AgentMode,
        pub identity_key_type_ok: bool,
        pub limits: Limits,
        /// The account registry's first bytes (the server owner's lines).
        pub registry_seed: Vec<u8>,
        /// ⟨R2-E⟩ Register the production managed adapter and wire the production
        /// effects, signer table and endpoint registry ([`Managed`]); seed profile
        /// `dev` with a standing policy over this world's pair.
        pub managed: bool,
        /// ⟨W4-N01⟩ `OperationsConfig::default_window` (the longest window a request
        /// may ask for; one hour unless a test needs more).
        pub default_window: Duration,
        /// ⟨W4-N01⟩ An observation world: the verifier parses under the first recorded
        /// row's label and dumps each attempt's raw trace ([`World::trace_dump`]), so a
        /// client without a recorded row is observed, never verified (its report is no
        /// evidence of a verification).
        pub observe_trace: bool,
    }

    impl Default for WorldOptions {
        fn default() -> Self {
            WorldOptions {
                form: EnrollmentForm::Account,
                agent_mode: AgentMode::Normal,
                identity_key_type_ok: true,
                limits: Limits::default(),
                registry_seed: Vec::new(),
                managed: false,
                default_window: Duration::from_secs(3600),
                observe_trace: false,
            }
        }
    }

    // --- ⟨R2-E⟩ the managed credential pieces --------------------------------------

    /// The endpoint registry, set after `Operations::start` (its authority is the
    /// `Operations`), as the runtime's late registry is (`service.rs` `LateRegistry`,
    /// R2-C's `live_tests::Late`): forwards all three `BindingEndpoints` methods.
    #[derive(Default)]
    pub struct LateRegistry(RwLock<Option<EndpointRegistry>>);

    impl LateRegistry {
        fn get(&self) -> Option<EndpointRegistry> {
            self.0.read().unwrap().clone()
        }
    }

    impl BindingEndpoints for LateRegistry {
        fn binding_endpoint(&self, binding: &BindingId) -> Option<EndpointRef> {
            self.get()
                .and_then(|r| BindingEndpoints::binding_endpoint(&r, binding))
        }
        fn create_binding_endpoint(
            &self,
            binding: &BindingId,
            generation: u64,
        ) -> Result<EndpointRef, AdapterError> {
            self.get()
                .ok_or_else(|| AdapterError::Unavailable("no registry".into()))?
                .create_binding_endpoint(binding, generation)
        }
        fn remove_binding_endpoint(
            &self,
            binding: &BindingId,
            generation: u64,
        ) -> Result<bool, AdapterError> {
            match self.get() {
                Some(r) => r.remove_binding_endpoint(binding, generation),
                None => Ok(false),
            }
        }
    }

    /// Every sign step the registry's signers reached, per endpoint (the signer's
    /// test-only pause hook, which waits for nothing here). `Admitted` is reached only
    /// with the permit held (D2 item 3a steps 3–4); `Signed` after K_env signed.
    #[derive(Default)]
    pub struct SignLog(Mutex<Vec<(SignerEndpoint, SignStep)>>);

    impl SignLog {
        /// The sign requests on `endpoint` that reached `step`.
        pub fn count(&self, endpoint: &SignerEndpoint, step: SignStep) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(e, s)| e == endpoint && *s == step)
                .count()
        }
    }

    impl SignHook for SignLog {
        fn at<'a>(&'a self, endpoint: &'a SignerEndpoint, step: SignStep) -> HookFuture<'a> {
            self.0.lock().unwrap().push((endpoint.clone(), step));
            Box::pin(async {})
        }
    }

    /// The production managed pieces of one in-process runtime (R2-C's `live_tests`
    /// construction, `crates/runtime/src/managed_store.rs`): the store-backed
    /// [`StoreSources`], a [`SignerTable`] over a fresh vault, `ManagedEffectsImpl`
    /// over the late [`EndpointRegistry`] (real Unix sockets in the scratch runtime
    /// dir, owner-only), the `ManagedCertificateAdapter` with the runtime's
    /// [`StoreCleanup`], and [`OpsInstallView`]. Stopped on drop.
    pub struct Managed {
        pub table: SignerTable,
        pub registry: EndpointRegistry,
        pub effects: ManagedEffectsImpl,
        pub run_dir: PathBuf,
        pub signs: Arc<SignLog>,
        /// ⟨W4-N01⟩ The slot data directory and the endpoint layout, kept for a restart
        /// of this runtime process ([`World::restart_managed`]).
        #[cfg_attr(not(windows), allow(dead_code))]
        pub data_dir: PathBuf,
        #[cfg_attr(not(windows), allow(dead_code))]
        pub layout: EndpointLayout,
        shutdown: CancellationToken,
    }

    impl Drop for Managed {
        fn drop(&mut self) {
            self.registry.stop_all();
            self.shutdown.cancel();
        }
    }

    /// The managed endpoints' layout: Unix sockets under the scratch runtime dir; ⟨W4-N01⟩
    /// on Windows named pipes under a per-run installation token (`hmt<16 hex>`), so the
    /// binding endpoint is `\\.\pipe\heimdall-hmt<…>-b<tag>`.
    #[cfg(unix)]
    pub fn managed_layout(run_dir: &Path) -> EndpointLayout {
        EndpointLayout::unix(run_dir).expect("a Unix endpoint layout")
    }

    #[cfg(windows)]
    pub fn managed_layout(run_dir: &Path) -> EndpointLayout {
        let _ = run_dir;
        let tag = heimdall_credential::endpoints::EndpointTag::generate().unwrap();
        EndpointLayout::windows(&format!("hmt{tag}")).expect("a Windows endpoint layout")
    }

    /// The managed endpoints' owner: this uid (Unix), this user's SID (Windows).
    #[cfg(unix)]
    pub fn endpoint_owner() -> heimdall_ipc::endpoint::ExpectedOwner {
        heimdall_ipc::endpoint::ExpectedOwner::Uid(heimdall_ipc::unix::current_uid())
    }

    #[cfg(windows)]
    pub fn endpoint_owner() -> heimdall_ipc::endpoint::ExpectedOwner {
        heimdall_ipc::endpoint::ExpectedOwner::Sid(
            heimdall_ipc::windows::current_user_sid().expect("this user's SID"),
        )
    }

    /// The parts built before `Operations::start` (the adapter is a start input).
    struct ManagedParts {
        sources: StoreSources,
        table: SignerTable,
        late: Arc<LateRegistry>,
        layout: EndpointLayout,
        data_dir: PathBuf,
        effects: ManagedEffectsImpl,
        adapter: Arc<dyn CredentialAdapter>,
        feed: Arc<LateFeed>,
    }

    /// ⟨R3-A; ADR-0008 §17.22 item 7⟩ The managed adapter's evidence comparison
    /// inputs, bound once the world's target evaluator and host exist (as the
    /// runtime's `sources::LateEvidenceFeed` is): the same [`TestTarget`] and
    /// [`TestHost`] the enrollment driver reads. Unset: no evaluation (fail closed).
    #[derive(Default)]
    pub struct LateFeed(Mutex<Option<Arc<dyn EvidenceFeed>>>);

    impl EvidenceFeed for LateFeed {
        fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation> {
            let feed = self.0.lock().unwrap().clone()?;
            feed.evaluate_target(alias)
        }

        fn client_version(&self) -> Option<String> {
            let feed = self.0.lock().unwrap().clone()?;
            feed.client_version()
        }
    }

    impl ManagedParts {
        fn new(store: &Arc<Store>, env: &EnvironmentId, run_dir: &Path, data_dir: &Path) -> Self {
            ManagedParts::with_layout(store, env, run_dir, data_dir, managed_layout(run_dir))
        }

        /// [`new`](Self::new) with an existing `layout` (a restarted process keeps its
        /// installation's endpoint layout).
        fn with_layout(
            store: &Arc<Store>,
            env: &EnvironmentId,
            run_dir: &Path,
            data_dir: &Path,
            layout: EndpointLayout,
        ) -> Self {
            let sources = StoreSources::new(Arc::clone(store), env.clone());
            let table = SignerTable::new(Arc::new(KeyVault::new()));
            let late = Arc::new(LateRegistry::default());
            let effects = ManagedEffectsImpl::new(
                table.clone(),
                late.clone(),
                Arc::new(sources.clone()),
                run_dir.to_path_buf(),
                SlotRoot {
                    data_dir: data_dir.to_path_buf(),
                    environment: env.clone(),
                },
            )
            .with_slot_store(Arc::new(sources.clone()));
            let feed = Arc::new(LateFeed::default());
            let adapter = ManagedCertificateAdapter::new(
                "managed-e2e",
                Arc::new(WithEvidenceFeed {
                    inner: Arc::new(sources.clone()),
                    feed: feed.clone(),
                }),
                Some(effects.clone()),
                Some(layout.clone()),
            )
            .with_cleanup(Arc::new(StoreCleanup::new(
                sources.clone(),
                effects.clone(),
                None,
            )));
            ManagedParts {
                sources,
                table,
                late,
                layout,
                data_dir: data_dir.to_path_buf(),
                effects,
                adapter: Arc::new(adapter),
                feed,
            }
        }

        /// After `Operations::start`: the registry under `ops`, the install view, and
        /// the issuer's view of K_env.
        fn finish(
            self,
            ops: &Operations,
            run_dir: &Path,
            issuer: &Arc<TestIssuer>,
            target: &Arc<TestTarget>,
            host: &Arc<TestHost>,
        ) -> Managed {
            *self.feed.0.lock().unwrap() = Some(Arc::new(TargetAndClient {
                target: target.clone() as Arc<dyn TargetEvaluator>,
                host: host.clone() as Arc<dyn EnrollmentHost>,
            }));
            let shutdown = CancellationToken::new();
            let signs = Arc::new(SignLog::default());
            let registry = EndpointRegistry::new(
                self.layout.clone(),
                endpoint_owner(),
                self.table.clone(),
                Arc::new(ops.clone()),
                SignerLimits::default(),
                shutdown.clone(),
            )
            .with_hook(signs.clone());
            *self.late.0.write().unwrap() = Some(registry.clone());
            self.table
                .set_install_view(Arc::new(OpsInstallView::new(ops.clone())));
            self.sources
                .set_issuer(issuer.clone() as Arc<dyn IssuerPort>);
            *issuer.table.lock().unwrap() = Some(self.table.clone());
            Managed {
                table: self.table,
                registry,
                effects: self.effects,
                run_dir: run_dir.to_path_buf(),
                signs,
                data_dir: self.data_dir,
                layout: self.layout,
                shutdown,
            }
        }
    }

    /// ⟨R2-F; R2E-Q1⟩ A managed world's projection writer, for the **setup-apply** leg
    /// through the real `setup` path: the runtime's own writer
    /// (`heimdall_runtime::service::wire_runtime_projection`: the catalog's public keys,
    /// `LocalProjection::writing`) with the runtime's store-backed `ManagedPairSource`
    /// (`store_pair_source`, as `Service` wires it: this world's store, the managed
    /// layout's environment endpoint, the slot data directory and the runtime directory).
    /// It writes into a **separate** scratch account home (`setup-home*`, its own
    /// `.ssh/config`), configuration directory and backup directory, all owner-only, so
    /// the apply's P and include block never reach the configuration the ssh leg's client
    /// reads (`-F home.user_config`).
    fn setup_writer(
        home: &ScratchHome,
        store: &Arc<Store>,
        env: &EnvironmentId,
        layout: &EndpointLayout,
        data_dir: &Path,
        runtime: &Path,
    ) -> Arc<dyn heimdall_app::ports::ProjectionWriter> {
        use heimdall_localenv::env::{Env, Platform};
        use heimdall_localenv::paths::SshPaths;
        use heimdall_localenv::projection::ProjectionConfig;
        let account_home = home.scratch().subdir("setup-home").unwrap();
        owner_only_dir(&account_home.join(".ssh"));
        write_mode(&account_home.join(".ssh").join("config"), b"", 0o600);
        let etc = home.scratch().subdir("setup-etc").unwrap();
        let config_dir = home.scratch().subdir("setup-config").unwrap();
        let state_dir = home.scratch().subdir("setup-state").unwrap();
        let mut c = ProjectionConfig::new(
            SshPaths::with_test_override(account_home.clone(), etc),
            Platform::current(),
            config_dir,
        )
        .with_state_dir(state_dir);
        c.env = Env::from_vars([
            ("HOME", account_home.display().to_string()),
            ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ]);
        c.managed = Some(heimdall_runtime::service::store_pair_source(
            Arc::clone(store),
            env.clone(),
            layout.environment(),
            data_dir.to_path_buf(),
            runtime.to_path_buf(),
        ));
        heimdall_runtime::service::wire_runtime_projection(Arc::clone(store), c)
            .expect("a writer with a state directory")
            .writer
    }

    /// Profile `dev` and a standing policy (setup default, `continue` on lock, the
    /// default connection policy) over `pairs`, for this world's environment.
    pub fn seed_profile(
        tx: &mut heimdall_store::Txn<'_>,
        env: &EnvironmentId,
        pairs: &[heimdall_domain::scope::AccessPair],
    ) -> heimdall_store::Result<()> {
        use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
        use heimdall_domain::profile::ProfileDefinition;
        use heimdall_domain::scope::{Capability, Scope};
        let scope = Scope {
            pairs: pairs.iter().cloned().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        };
        tx.upsert_profile(&ProfileDefinition {
            id: ProfileId::parse("dev").unwrap(),
            revision: 1,
            scope: scope.clone(),
            label: None,
        })?;
        tx.upsert_policy(
            &StandingPolicy {
                id: PolicyId::parse("pol-e2e").unwrap(),
                revision: PolicyRevision(1),
                profile: ProfileId::parse("dev").unwrap(),
                workspace: None,
                scope,
                environments: [env.clone()].into_iter().collect(),
                max_window: Duration::from_secs(2 * 3600),
                pause: PauseState::Active,
                cutoff_at: None,
                source: PolicySource::SetupDefault,
                lock_behavior: heimdall_contract::managed::LockBehavior::Continue,
                connection: heimdall_contract::managed::ConnectionPolicy::default(),
            },
            false,
        )
        .map(|_| ())
    }

    impl World {
        pub async fn new() -> World {
            World::with(WorldOptions::default()).await
        }

        pub async fn with(o: WorldOptions) -> World {
            let home = ScratchHome::new();
            let existing_key = FixtureKey::generate();
            #[cfg(unix)]
            let account_name = current_account().expect("the local account");
            // ⟨W4-N01⟩ Windows: the harness's WSL fixture sshd, or a failure naming it
            // (never a skip); its account is the WSL one (`HM_FIXTURE_SSHD_USER`).
            #[cfg(windows)]
            let account_name = {
                assert!(
                    std::env::var_os("HM_FIXTURE_SSHD_PORT").is_some(),
                    "the Windows enrollment e2e tests need the harness fixture sshd \
                     (HM_FIXTURE_SSHD_*; tests/native/m02/run-windows-local.ps1)"
                );
                std::env::var("HM_FIXTURE_SSHD_USER")
                    .expect("the WSL harness sshd names its account (HM_FIXTURE_SSHD_USER)")
            };
            let system = o.form == EnrollmentForm::System;
            let ca = TestCa::generate(home.scratch()).unwrap();
            let mut cfg = SshdConfig {
                authorized: vec![existing_key.public().clone()],
                registry_seed: Some(o.registry_seed.clone()),
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
            #[cfg(windows)]
            assert_eq!(
                sshd.account(),
                Some(account_name.as_str()),
                "the adopted harness sshd authenticates the WSL account"
            );
            let registry = sshd
                .registry_path()
                .expect("a local registry")
                .to_path_buf();
            // ⟨W4-N01⟩ The registry as the server's account names it (the spec's explicit
            // `registry_path`): the same path for a local server; the WSL path of the
            // harness's enrollment registry on Windows.
            let registry_remote = sshd
                .registry_remote_path()
                .expect(
                    "an account-form registry the server's account can name (on Windows the \
                     harness's enrollment registry: HM_FIXTURE_SSHD_REGISTRY and \
                     HM_FIXTURE_SSHD_REGISTRY_REMOTE)",
                )
                .to_owned();
            let agent = FakeAgent::start(
                Endpoint::in_scratch(home.scratch(), "existing").unwrap(),
                FakeAgentConfig {
                    keys: vec![existing_key.clone()],
                    mode: o.agent_mode,
                },
            );
            // The catalog's locator (a socket path, or `\\.\pipe\<name>`), and the
            // concrete endpoint the plan renders and the host re-validates (the same
            // socket path, or `//./pipe/<name>`).
            let agent_locator = agent.endpoint().locator().to_string_lossy().into_owned();
            let agent_path = if cfg!(windows) {
                agent_locator.replace('\\', "/")
            } else {
                agent_locator.clone()
            };
            home.write_user_config(&format!(
                "Host {ALIAS}\n  HostName 127.0.0.1\n  Port {}\n  User {account_name}\n",
                sshd.port
            ))
            .unwrap();
            // The client wrapper: the system ssh with the scratch configuration and
            // environment only (the owner's ~/.ssh is never read).
            #[cfg(unix)]
            let client = {
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
                client
            };
            // ⟨W4-N01⟩ Windows: the in-box `ssh.exe` itself; the scratch configuration and
            // environment are added where it is spawned ([`run_step`]'s containment,
            // [`TestHost::effective_config`]).
            #[cfg(windows)]
            let client = system_ssh();
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
                            endpoint: agent_ref(&agent_locator),
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
                    if o.managed {
                        seed_profile(
                            tx,
                            &env,
                            &[heimdall_domain::scope::AccessPair {
                                destination: destination.clone(),
                                account: account.clone(),
                            }],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            let parts = o.managed.then(|| {
                let data_dir = home.scratch().subdir("state").unwrap();
                owner_only_dir(&data_dir);
                let parts = ManagedParts::new(&store, &env, &runtime, &data_dir);
                let projection =
                    setup_writer(&home, &store, &env, &parts.layout, &data_dir, &runtime);
                (parts, projection)
            });
            let (parts, projection) = match parts {
                Some((p, w)) => (Some(p), Some(w)),
                None => (None, None),
            };
            let clock = TestClock::new();
            let ops = Operations::start(OperationsConfig {
                store: Arc::clone(&store),
                clock: clock.clone(),
                time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                time_policy: TimePolicy::default(),
                environment: env.clone(),
                adapters: parts.iter().map(|p| Arc::clone(&p.adapter)).collect(),
                stage_hook: Arc::new(NoStageHook),
                limits: o.limits,
                default_window: o.default_window,
                projection,
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
                per_alias: Mutex::new(HashMap::new()),
            });
            let keys = Arc::new(Mutex::new(HashMap::new()));
            let host = Arc::new(TestHost {
                runtime: runtime.clone(),
                client,
                config: cfg!(windows).then(|| home.user_config.clone()),
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
                table: Mutex::new(None),
                grant_signed: AtomicUsize::new(0),
            });
            let managed = parts.map(|p| p.finish(&ops, &runtime, &issuer, &target, &host));
            let vdir = home.scratch().subdir("vs").unwrap();
            owner_only_dir(&vdir);
            let endpoints = Arc::new(TestEndpoints {
                dir: vdir,
                keys,
                live: Arc::new(AtomicUsize::new(0)),
                created: AtomicUsize::new(0),
                plans: Mutex::new(Vec::new()),
                store: Arc::clone(&store),
                seen: Mutex::new(Vec::new()),
            });
            let client_version =
                heimdall_enroll::trace::ClientVersion::parse(&host.version.lock().unwrap())
                    .expect("a parsable client version");
            // ⟨W4-N01⟩ An observation world parses under the first recorded row's label
            // and dumps each attempt's raw trace (debug builds; `observe_trace`).
            let (label, trace_dump) = if o.observe_trace {
                let dump = home.scratch().subdir("trace-dump").unwrap();
                (heimdall_enroll::trace::RECORDED[0].from, Some(dump))
            } else {
                (client_version, None)
            };
            let verifier = Verifier::with_client(
                VerifierClient {
                    path: system_ssh(),
                    version: label,
                },
                runtime.clone(),
            );
            #[cfg(debug_assertions)]
            let verifier = match &trace_dump {
                Some(dump) => verifier.with_test_trace_dump(dump),
                None => verifier,
            };
            let verifier = Arc::new(verifier);
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
                registry_remote,
                existing: existing_line,
                existing_key,
                identity,
                managed,
                default_window: o.default_window,
                client_version,
                trace_dump,
                home,
            };
            w.wire();
            w
        }

        /// ⟨W4-N01⟩ A test that needs a conclusive verification (a pass, or a refusal with
        /// its evidence) needs the verified client's recorded trace row
        /// (`heimdall_enroll::trace::RECORDED`): without one every verification is
        /// inconclusive by design. The in-box Windows client has none until it is
        /// recorded from `enroll_m03/windows.rs`'s `windows_client_trace_row_observation`
        /// lines, so on Windows such a test **fails** here with that reason (never a
        /// pass, never a skip). Unix: no check (the macOS and devbox clients are
        /// recorded; their runs are unchanged).
        pub fn require_recorded_client(&self) {
            if cfg!(windows) {
                let v = self.client_version;
                assert!(
                    heimdall_enroll::trace::patterns_for(v.family, v).is_ok(),
                    "{}: the verified client ({}) has no recorded trace row (heimdall_enroll::trace::RECORDED), so every verification is inconclusive until it is recorded from the `m03 observation: client_trace_row` lines of windows_client_trace_row_observation (not a pass)",
                    heimdall_enroll::trace::UNRECORDED_FINDING,
                    v
                );
            }
        }

        /// Wire the ports into the current `Operations`.
        pub fn wire(&self) {
            self.ops.set_managed_wiring(ManagedWiring {
                effects: self
                    .managed
                    .as_ref()
                    .map(|m| Arc::new(m.effects.clone()) as Arc<dyn ManagedEffects>),
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
            assert!(
                self.managed.is_none(),
                "a managed world's registry serves the first Operations"
            );
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

        /// ⟨W4-N01⟩ A managed world's runtime restarts in the same boot: the first
        /// process's endpoints stop (its signer table, with K_env, goes with it), and a
        /// new process (an empty vault and signer table, a new endpoint registry over
        /// the same layout, the production managed pieces again, `Operations::start`
        /// over the same store) is wired in its place, as
        /// `live_tests::pipeline::reissue_restores_…`'s second process.
        #[cfg_attr(not(windows), allow(dead_code))]
        pub async fn restart_managed(&mut self) {
            let first = self.managed.take().expect("a managed world");
            let (run_dir, data_dir, layout) = (
                first.run_dir.clone(),
                first.data_dir.clone(),
                first.layout.clone(),
            );
            drop(first);
            let parts =
                ManagedParts::with_layout(&self.store, &self.env, &run_dir, &data_dir, layout);
            self.ops = Operations::start(OperationsConfig {
                store: Arc::clone(&self.store),
                clock: self.clock.clone(),
                time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                time_policy: TimePolicy::default(),
                environment: self.env.clone(),
                adapters: vec![Arc::clone(&parts.adapter)],
                stage_hook: Arc::new(NoStageHook),
                limits: *self.ops.limits(),
                default_window: self.default_window,
                projection: None,
            })
            .await
            .unwrap();
            self.managed =
                Some(parts.finish(&self.ops, &run_dir, &self.issuer, &self.target, &self.host));
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
                registry_path: Some(self.registry_remote.clone()),
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
            let report = run_step(&self.home, step).await;
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
            self.seed_with(state, form, target, hold, |_| {})
        }

        /// The registry line of a record of this world's pair under its first CA.
        pub fn line_of(&self, r: &heimdall_domain::enrollment::EnrollmentRecord) -> String {
            format!(
                "cert-authority,principals=\"hm:{}:{}\" {} {}",
                r.destination.as_str(),
                r.account.as_str(),
                self.issuer.ca.public_line(),
                r.marker
            )
        }

        /// [`seed`](Self::seed), with `f` adjusting the record before it is stored.
        pub fn seed_with(
            &self,
            state: EnrollmentState,
            form: EnrollmentForm,
            target: heimdall_contract::enrollment::ApprovedTarget,
            hold: Option<heimdall_domain::enrollment::EnrollmentHold>,
            f: impl FnOnce(&mut heimdall_domain::enrollment::EnrollmentRecord),
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
                    path_display: self.registry_remote.clone(),
                    resolved_by: heimdall_contract::enrollment::RegistryResolvedBy::Explicit,
                },
                registry_canonical: heimdall_contract::enrollment::RegistryCanonical {
                    path: Some(self.registry_remote.clone()),
                    resolved_by: heimdall_contract::enrollment::RegistryResolvedBy::Explicit,
                },
                line_sha256: heimdall_domain::projection::Sha256Hex::of(line.as_bytes())
                    .as_str()
                    .to_owned(),
                target,
                existing_access: heimdall_domain::enrollment::ExistingAccessRecord {
                    identity,
                    endpoint: Some(agent_ref(&self.host.agent_path)),
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
            let mut record = record;
            f(&mut record);
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
                    path: (form == EnrollmentForm::Account).then(|| self.registry_remote.clone()),
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
        pub async fn uncertain_append(&self, op: &OperationId, ran: bool) -> String {
            let StepAnswer::Step { step } = self.step_answer(op).await else {
                panic!("inspect");
            };
            self.run_and_report(op, &step).await;
            let StepAnswer::Step { step } = self.step_answer(op).await else {
                panic!("append");
            };
            assert_eq!(step.stage, RemoteStage::Append);
            if ran {
                let _ = run_step(&self.home, &step).await;
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
            step.step_token.clone()
        }

        // --- round 2 (R2-A): forged operations, decisions and scans --------------

        /// A journal receipt (`enroll.journal`, the driver's current journal).
        pub fn journal_receipt(j: &Journal) -> StageReceipt {
            StageReceipt {
                stage: "enroll.journal".into(),
                recorded_at: Timestamp::now(),
                effect: EffectReceipt::Confirmed {
                    adapter: AdapterIdentity {
                        mechanism: "enrollment".into(),
                        instance: "journal".into(),
                    },
                    credential_ref: serde_json::to_string(j).unwrap(),
                },
                local: None,
            }
        }

        /// A receipt of `stage` with `effect`.
        pub fn receipt(stage: &str, effect: EffectReceipt) -> StageReceipt {
            StageReceipt {
                stage: stage.into(),
                recorded_at: Timestamp::now(),
                effect,
                local: None,
            }
        }

        /// The `enroll.append` `Confirmed` receipt of `marker`.
        pub fn append_confirmed(marker: &str) -> StageReceipt {
            World::receipt(
                enrollment_stage::APPEND,
                EffectReceipt::Confirmed {
                    adapter: AdapterIdentity {
                        mechanism: "enrollment".into(),
                        instance: "x".into(),
                    },
                    credential_ref: marker.into(),
                },
            )
        }

        /// An `enroll.verify.started` receipt.
        pub fn verify_started() -> StageReceipt {
            World::receipt(
                enrollment_stage::VERIFY_STARTED,
                EffectReceipt::NotAttempted,
            )
        }

        /// A forged operation of `kind` in `state` (model setup for the verification
        /// authority's regressions): its stored request, journal and receipts.
        pub fn forge_op(
            &self,
            kind: OperationKind,
            state: OperationState,
            request: Option<heimdall_contract::request::Request>,
            journal: &Journal,
            receipts: &[StageReceipt],
        ) -> OperationId {
            let id = OperationId::from_random_bytes(rand16());
            let key = IdempotencyKey {
                caller: owner(),
                kind,
                request_id: RequestId::parse(&format!(
                    "forged_{}",
                    heimdall_testkit::agent::random_hex(8)
                ))
                .unwrap(),
            };
            let now = self.clock.wall();
            let op = OperationRecord {
                id: id.clone(),
                kind,
                environment: self.env.clone(),
                key: key.clone(),
                request_hash: RequestHash(rand32()),
                effect_class: EffectClass::Local,
                state,
                code: None,
                effect_status: heimdall_contract::envelope::EffectStatus::None,
                result: None,
                created_at: now,
                updated_at: now,
                cancellation: None,
                recovery: RecoveryMetadata::default(),
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
                if let Some(r) = &request {
                    tx.set_recovery_intent(
                        &id,
                        &RecoveryIntent {
                            request: serde_json::to_value(r).unwrap(),
                            resolved: None,
                            local: None,
                        },
                    )?;
                }
                tx.append_stage_receipt(&id, &World::journal_receipt(journal))?;
                for r in receipts {
                    tx.append_stage_receipt(&id, r)?;
                }
                Ok(())
            });
            id
        }

        /// Append `j` as `op`'s current journal.
        pub fn put_journal(&self, op: &OperationId, j: &Journal) {
            self.tx(|tx| tx.append_stage_receipt(op, &World::journal_receipt(j)));
        }

        /// Settle a forged operation (`failed`), so it no longer drives its record.
        pub fn settle_forged(&self, op: &OperationId) {
            let mut o = self.op(op);
            o.state = OperationState::Failed;
            self.tx(|tx| tx.update_operation(&o));
        }

        /// An approved decision of `kind` (inserted pending, then completed).
        pub fn approved_decision(
            &self,
            kind: heimdall_domain::decision::DecisionKind,
        ) -> heimdall_contract::ids::DecisionId {
            let id = heimdall_contract::ids::DecisionId::from_random_bytes(rand16());
            let now = self.clock.wall();
            self.tx(|tx| {
                let generation = tx.authority_generation()?;
                tx.insert_decision(&heimdall_domain::decision::DecisionRecord {
                    id: id.clone(),
                    kind: kind.clone(),
                    generation,
                    created_at: now,
                    expires_at: Timestamp::from_second(now.as_second() + 3600).unwrap(),
                    state: heimdall_domain::decision::DecisionState::Pending,
                    decided_at: None,
                })?;
                tx.complete_decision(&id, Verdict::Approve, now).map(|_| ())
            });
            id
        }

        /// The stored `enrollment.verify` request of `e` in `mode`.
        pub fn verify_request(
            e: &heimdall_contract::ids::EnrollmentId,
            mode: VerifyMode,
        ) -> heimdall_contract::request::Request {
            heimdall_contract::request::Request::Enrollment(EnrollmentRequest::Verify {
                enrollment_id: e.clone(),
                request_id: RequestId::parse("forged_verify").unwrap(),
                mode,
                wait: WaitMode::default(),
            })
        }

        /// Reserve a positive verification certificate for `op` and `e` (the
        /// predicate's answer; the entry is voided again on success).
        pub async fn reserve(
            &self,
            op: &OperationId,
            e: &heimdall_contract::ids::EnrollmentId,
        ) -> Result<(), heimdall_domain::verification::VerificationRefusal> {
            let now = self.clock.wall();
            let r = self
                .ops
                .reserve_verification(heimdall_app::operations::VerificationRequest {
                    operation: op.clone(),
                    enrollment: e.clone(),
                    pair: heimdall_domain::scope::AccessPair {
                        destination: self.destination.clone(),
                        account: self.account.clone(),
                    },
                    ca_fingerprint: self.issuer.ca.fingerprint().clone(),
                    purpose: heimdall_domain::verification::VerificationPurpose::Positive,
                    principal: format!(
                        "hm:{}:{}",
                        self.destination.as_str(),
                        self.account.as_str()
                    ),
                    key_id: "verify-key".into(),
                    valid_after: Timestamp::from_second(now.as_second() - 60).unwrap(),
                    valid_before: Timestamp::from_second(now.as_second() + 240).unwrap(),
                    extensions: std::collections::BTreeSet::new(),
                    subject_fingerprint: "SHA256:kverify".into(),
                    subject_registered: true,
                })
                .await
                .unwrap();
            r.map(|_| ())
        }

        /// The current journal of `op`.
        pub fn journal(&self, op: &OperationId) -> Journal {
            self.receipts(op)
                .iter()
                .rev()
                .find_map(|r| match (&r.stage[..], &r.effect) {
                    ("enroll.journal", EffectReceipt::Confirmed { credential_ref, .. }) => {
                        serde_json::from_str(credential_ref).ok()
                    }
                    _ => None,
                })
                .expect("a journal")
        }

        /// Every operation the events name, with its receipts and stored result,
        /// as JSON text (what a scan for foreign bytes reads).
        pub fn stored_operation_text(&self) -> Vec<(OperationId, String)> {
            let env = self.env.clone();
            let events = self.tx(|tx| tx.events_after(&env, 0, &Default::default(), 100_000));
            let mut ids: Vec<OperationId> = Vec::new();
            for e in &events.events {
                if let Some(id) = &e.operation_id
                    && !ids.contains(id)
                {
                    ids.push(id.clone());
                }
            }
            ids.into_iter()
                .map(|id| {
                    let receipts = self.receipts(&id);
                    let op = self.op(&id);
                    let text = format!(
                        "{}\n{}",
                        serde_json::to_string(&receipts).unwrap(),
                        serde_json::to_string(&op.result).unwrap()
                    );
                    (id, text)
                })
                .collect()
        }

        /// The lock path of this world's registry (`<dir>/.hm-lock.<name>`).
        pub fn lock_path(&self) -> PathBuf {
            let name = self
                .registry
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            self.registry
                .parent()
                .unwrap()
                .join(format!(".hm-lock.{name}"))
        }

        /// Plant a holder-recording lock on this world's registry, as a writer that
        /// took it and never released it (D5 §6.3): `ln -s <record> <lock>`.
        #[cfg(unix)]
        pub fn plant_lock(&self, token: &str, pid: u32, start_hex: &str, not_after: i64) {
            let record = format!("hm1-{token}-{pid}-{start_hex}-{}-{not_after}", boot_hex());
            std::os::unix::fs::symlink(&record, self.lock_path()).unwrap();
        }

        pub fn lock_present(&self) -> bool {
            fs::symlink_metadata(self.lock_path()).is_ok()
        }

        /// Seed a live managed grant for this world's pair holding a `published`
        /// certificate under `ca` (U0b row 20's set).
        pub fn seed_grant_under(
            &self,
            ca: &CaFingerprint,
            n: u8,
        ) -> heimdall_contract::ids::GrantId {
            use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantSnapshot};
            use heimdall_domain::issuance::{CertificateBounds, IssuanceEntry, IssuanceState};
            use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
            use heimdall_domain::scope::{AccessPair, Capability, Scope};
            let now = self.clock.wall();
            let later = Timestamp::from_second(now.as_second() + 3600).unwrap();
            let pair = AccessPair {
                destination: self.destination.clone(),
                account: self.account.clone(),
            };
            let g = GrantSnapshot {
                id: heimdall_contract::ids::GrantId::from_random_bytes(rand16()),
                environment: self.env.clone(),
                scope: Scope {
                    pairs: [pair.clone()].into_iter().collect(),
                    capabilities: [Capability::SshAuthentication].into_iter().collect(),
                },
                starts_at: now,
                deadline: heimdall_domain::time::Deadline {
                    intent: heimdall_contract::request::DeadlineIntent::Duration("1h".into()),
                    resolved_at: now,
                    effective: later,
                },
                parent: None,
                source: AuthorizationSource::StandingPolicy {
                    revision: PolicyRevision(1),
                },
                generation: AuthorityGeneration(0),
                state: heimdall_contract::GrantState::Active,
                enforcement: heimdall_domain::evidence::EnforcementEvidence::unknown(),
            };
            let origin = GrantOrigin {
                profile: heimdall_contract::ids::ProfileId::parse("dev").unwrap(),
                profile_revision: 1,
                policy_revision: None,
                caller: owner(),
                mechanism: "managed_certificate".into(),
                covered: None,
                adapter: None,
                lock_behavior: None,
                connection: None,
            };
            let entry = IssuanceEntry {
                id: heimdall_contract::ids::IssuanceId::from_random_bytes(rand16()),
                grant: g.id.clone(),
                generation: AuthorityGeneration(0),
                pair: pair.clone(),
                bounds: CertificateBounds {
                    serial: u64::from(n),
                    key_id: format!("grant-{n}"),
                    principal: format!("hm:{}:{}", pair.destination, pair.account),
                    valid_after: now,
                    valid_before: later,
                    extensions: std::collections::BTreeSet::new(),
                    subject_fingerprint: "SHA256:grantkey".into(),
                    ca_fingerprint: Some(ca.clone()),
                },
                state: IssuanceState::Reserved,
                reserved_at: now,
                settled_at: None,
                void_reason: None,
                continuing: false,
            };
            self.tx(|tx| {
                tx.insert_grant(&g)?;
                tx.set_grant_origin(&g.id, &origin)?;
                tx.reserve_issuance(&entry)?;
                tx.publish_issuance(&entry.id, now).map(|_| ())
            });
            g.id
        }

        /// A second destination on its own loopback sshd (same account, same
        /// existing access), with its alias in the scratch configuration.
        pub fn add_destination(&self, n: u8) -> Second {
            self.add_destination_with(n, EnrollmentForm::Account)
        }

        /// [`add_destination`](Self::add_destination) in `form`: the system form's sshd
        /// also reads `TrustedUserCAKeys` (empty) and an `AuthorizedPrincipalsFile` per
        /// account (empty for this world's account), as [`World::with`] sets it up.
        pub fn add_destination_with(&self, n: u8, form: EnrollmentForm) -> Second {
            let mut cfg = SshdConfig {
                authorized: vec![self.existing_key.public().clone()],
                registry_seed: Some(Vec::new()),
                ..SshdConfig::default()
            };
            if form == EnrollmentForm::System {
                let ca_file = self
                    .home
                    .scratch()
                    .subdir(&format!("trusted{n}"))
                    .unwrap()
                    .join("ca_keys");
                fs::write(&ca_file, b"").unwrap();
                cfg.trusted_user_ca_keys = Some(ca_file);
                cfg.authorized_principals = Some(
                    [(self.account.as_str().to_owned(), Vec::new())]
                        .into_iter()
                        .collect(),
                );
            }
            let sshd =
                LoopbackSshd::start(self.home.scratch(), cfg).unwrap_or_else(|e| panic!("{e}"));
            let registry = sshd.registry_path().unwrap().to_path_buf();
            let alias = format!("{ALIAS}-{n}");
            let destination = DestinationId::parse(&format!("dst_e2e{n}")).unwrap();
            let text = fs::read_to_string(&self.home.user_config).unwrap_or_default();
            fs::write(
                &self.home.user_config,
                format!(
                    "{text}\nHost {alias}\n  HostName 127.0.0.1\n  Port {}\n  User {}\n",
                    sshd.port,
                    self.account.as_str()
                ),
            )
            .unwrap();
            let now = Timestamp::now();
            self.tx(|tx| {
                tx.upsert_destination(&DestinationRecord {
                    id: destination.clone(),
                    alias: alias.clone(),
                    revision: 1,
                    definition: DestinationDefinition::Managed {
                        hostname: "127.0.0.1".to_owned(),
                        port: Some(sshd.port),
                        account: self.account.clone(),
                        identity: self.identity.clone(),
                    },
                    label: None,
                    updated_at: now,
                })
            });
            let (kt, kb) = host_key_of(&sshd.host_key_line);
            self.target.per_alias.lock().unwrap().insert(
                alias.clone(),
                TargetEvaluation {
                    hostname: "127.0.0.1".to_owned(),
                    port: sshd.port,
                    user: self.account.as_str().to_owned(),
                    proxy: ProxyRoute::None,
                    determinism: Determinism::Determined,
                    host_keys: vec![raw_key(&kt, &kb)],
                },
            );
            Second {
                sshd,
                destination,
                registry,
            }
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

        // --- ⟨R2-E⟩ the setup-apply, ensure and ssh legs ---------------------------

        /// This world's pair.
        pub fn pair(&self) -> heimdall_domain::scope::AccessPair {
            heimdall_domain::scope::AccessPair {
                destination: self.destination.clone(),
                account: self.account.clone(),
            }
        }

        /// The managed pieces (a [`WorldOptions::managed`] world).
        pub fn managed(&self) -> &Managed {
            self.managed.as_ref().expect("a managed world")
        }

        /// A system-form enrollment of `(destination, this account)` on `sshd` (the
        /// second destination's), applied by the owner as [`Self::system_verified`]
        /// applies it (the CA trusted, the account's principals file naming the plan's
        /// positive principal), and verified.
        pub async fn system_verified_on(
            &self,
            destination: &DestinationId,
            sshd: &LoopbackSshd,
            rid: &str,
        ) -> heimdall_domain::enrollment::EnrollmentRecord {
            let spec = EnrollmentSpec {
                destination: destination.clone(),
                ..self.system_spec()
            };
            let plan = self.preview(&spec).await;
            let e = self
                .apply(
                    &attended(),
                    &spec,
                    &plan,
                    rid,
                    InteractionMode::NonInteractive,
                )
                .await;
            self.decide(&e, Verdict::Approve).await.unwrap();
            let pair = heimdall_domain::scope::AccessPair {
                destination: destination.clone(),
                account: self.account.clone(),
            };
            let record = self.tx(|tx| tx.enrollments_for_pair(&pair)).pop().unwrap();
            sshd.trust_user_ca(self.issuer.ca.public_line()).unwrap();
            sshd.set_principals(
                self.account.as_str(),
                &[plan.verification.positive_principal.as_str()],
            )
            .unwrap();
            let c = self
                .verify(&record.id, &format!("{rid}_v"), VerifyMode::Presence)
                .await
                .unwrap_or_else(|e| panic!("verify: {e:?}"));
            let r: EnrollmentResult = serde_json::from_value(c.data).unwrap();
            assert_eq!(r.state, EnrollmentState::Verified, "{r:?}");
            self.record(&record.id)
        }

        /// ⟨R2-F; R2E-Q1⟩ **The setup-apply leg, through the real `setup` path** (M02's
        /// journaled setup driver over this managed world's projection writer,
        /// [`setup_writer`]): preview `apply`, then `apply` with the previewed digest; the
        /// owner's `ApplyProjection` decision is approved when the driver asks for one, and
        /// the replay of the same request answers the settled result. Returns the plan and
        /// the result. The SSH item's commit records the preference switch (D5 §6.6; U0b
        /// row 9) in its own transaction. The third value counts the decisions approved
        /// (the `ApplyProjection` decision, when the driver asked for one).
        pub async fn setup_apply(&self, tag: &str) -> (SetupPlan, serde_json::Value, usize) {
            use heimdall_contract::setup::{PreviewIntent, SetupRequest};
            let plan: SetupPlan = serde_json::from_value(
                self.ops
                    .setup(
                        &attended(),
                        SetupRequest::Preview {
                            intent: PreviewIntent::Apply { include_git: false },
                        },
                    )
                    .await
                    .unwrap_or_else(|e| panic!("setup preview: {e:?}"))
                    .data,
            )
            .unwrap();
            let apply = || SetupRequest::Apply {
                plan_digest: plan.plan_digest.clone(),
                request_id: RequestId::parse(&format!("req_setup_{tag}")).unwrap(),
            };
            let (data, decided) = match self.ops.setup(&attended(), apply()).await {
                Ok(c) => (c.data, 0),
                Err(e) => {
                    assert!(
                        matches!(e.code, Code::ApprovalRequired | Code::InteractionRequired),
                        "setup apply: {e:?}"
                    );
                    self.decide(&e, Verdict::Approve)
                        .await
                        .unwrap_or_else(|e| panic!("approve the projection: {e:?}"));
                    let data = self
                        .ops
                        .setup(&attended(), apply())
                        .await
                        .unwrap_or_else(|e| panic!("setup apply (replay): {e:?}"))
                        .data;
                    (data, 1)
                }
            };
            (plan, data, decided)
        }

        /// The SSH item's committed projection generation in this world's environment.
        pub fn ssh_generation(&self) -> Option<u64> {
            self.tx(|tx| tx.projection_record(&self.env))
                .and_then(|r| r.items.get(&ProjectionItem::Ssh).map(|i| i.generation))
        }

        /// A managed `ensure` of profile `dev` over this world's pair, through the real
        /// pipeline (resolve, the managed effect driver, `prepare_from`, commit).
        /// **Interactive**: a non-interactive one passes the commit only when the
        /// alias's D10 item 6 selection is observed `exclusive`, which needs the
        /// runtime's observing source over a projected configuration (R2C-Q1's fix);
        /// this harness's `StoreSources` observes nothing (`undetermined`).
        pub async fn ensure_managed(&self, tag: &str) -> Result<EnsureData, OpError> {
            self.ensure_managed_with(tag, RequiredCapabilities::default())
                .await
        }

        /// [`ensure_managed`](Self::ensure_managed) with `required` minimums.
        pub async fn ensure_managed_with(
            &self,
            tag: &str,
            required: RequiredCapabilities,
        ) -> Result<EnsureData, OpError> {
            self.ops
                .ensure(
                    &unattended(),
                    EnsureRequest {
                        profile: ProfileId::parse("dev").unwrap(),
                        profile_revision: None,
                        scope: [self.pair()].into_iter().collect(),
                        environment: None,
                        work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
                        until: None,
                        required_capabilities: required,
                        request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
                        interaction: InteractionMode::Interactive,
                        wait: WaitMode::Sync { timeout_ms: 30_000 },
                        connection: None,
                    },
                )
                .await
                .map(|c| c.data)
        }

        /// The binding endpoint `data` names, and the binding's files beside it for
        /// `destination` (`<run>/b/<16 hex>/{agent.sock, key.pub, cert-<dest>.pub}`),
        /// derived as `connect` derives them.
        pub fn binding_files(
            &self,
            data: &EnsureData,
            destination: &DestinationId,
        ) -> (String, PathBuf, PathBuf) {
            let endpoint = data
                .consumer
                .signing_endpoint
                .clone()
                .expect("the ensure result names the binding endpoint");
            let files = binding_files_for_endpoint(
                &self.managed().run_dir,
                &EndpointRef {
                    kind: if cfg!(windows) {
                        EndpointKind::NamedPipe
                    } else {
                        EndpointKind::UnixSocket
                    },
                    locator: endpoint.clone(),
                },
                std::slice::from_ref(destination),
            )
            .expect("the binding endpoint is under the runtime dir");
            let cert = files.certificate(destination).unwrap().to_path_buf();
            (endpoint, files.key_pub, cert)
        }

        /// **The ssh leg**: the real system `ssh` to `alias`, with the fixture home's
        /// isolation arguments (`-F` the scratch configuration, the scratch known-hosts
        /// files, `BatchMode=yes`; `HOME` the scratch home, `SSH_AUTH_SOCK` the decoy
        /// agent; see below for the default-identity guard) and the binding's identity options
        /// exactly as `connect` renders them
        /// (`heimdall_sshconf::render::managed_identity_options`, the selected form:
        /// `IdentityAgent=<endpoint>`, `IdentitiesOnly=yes`, `IdentityFile=<cert>`),
        /// running `echo <marker>`. `host_key_line` is the server's known-hosts line.
        pub async fn managed_ssh(
            &self,
            alias: &str,
            host_key_line: &str,
            (endpoint, key_pub, cert): &(String, PathBuf, PathBuf),
            marker: &str,
        ) -> std::process::Output {
            use heimdall_sshconf::render::{
                ManagedIdentityForm, PathStyle, RenderPath, managed_identity_options,
            };
            let known = fs::read_to_string(&self.home.known_hosts).unwrap_or_default();
            if !known.lines().any(|l| l == host_key_line) {
                fs::write(&self.home.known_hosts, format!("{known}{host_key_line}\n")).unwrap();
            }
            #[cfg(unix)]
            let options = managed_identity_options(
                &RenderPath::unix(Path::new(endpoint)).unwrap(),
                &RenderPath::unix(key_pub).unwrap(),
                &RenderPath::unix(cert).unwrap(),
                PathStyle::Unix,
                ManagedIdentityForm::select(None),
            )
            .unwrap();
            // ⟨W4-N01⟩ Windows: the pipe as `//./pipe/<name>`, the files with `/`.
            #[cfg(windows)]
            let options = managed_identity_options(
                &RenderPath::pipe(endpoint).unwrap(),
                &RenderPath::windows(key_pub).unwrap(),
                &RenderPath::windows(cert).unwrap(),
                PathStyle::Windows,
                ManagedIdentityForm::select(None),
            )
            .unwrap();
            // The fixture home's default-identity guard (`check_alias`) evaluates the
            // configuration file only, where this alias has no identity directives (they
            // are on the command line, as `connect` passes them), so it would refuse.
            // Isolation holds without it: `HOME` is the scratch home (its `~/.ssh` holds
            // nothing of the owner's), `IdentitiesOnly=yes` with the one certificate as
            // the identity file, and the agent is the binding endpoint.
            let mut cmd = std::process::Command::new(system_ssh());
            cmd.args(self.home.isolation_args())
                .args(&options)
                .args(["-o", "PreferredAuthentications=publickey"])
                .arg(alias)
                .arg(format!("echo {marker}"))
                .env(
                    "SSH_AUTH_SOCK",
                    self.home.decoy_agent().endpoint().locator(),
                )
                .env("HOME", &self.home.git_home)
                .env_remove("SSH_ASKPASS")
                .env_remove("SSH_ASKPASS_REQUIRE")
                .env_remove("SSH_AGENT_PID")
                .env_remove("DISPLAY")
                .stdin(std::process::Stdio::null());
            let out = tokio::task::spawn_blocking(move || cmd.output())
                .await
                .unwrap()
                .unwrap();
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
            out
        }

        /// The tail of an ssh run's stderr with the scratch root and account
        /// redacted (a failure message).
        pub fn why(&self, out: &std::process::Output) -> String {
            let root = self.home.root.to_string_lossy().into_owned();
            let text = String::from_utf8_lossy(&out.stderr);
            let tail: Vec<&str> = text.lines().rev().take(12).collect();
            let s = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
            let s = s.replace(&root, "<scratch>");
            let refusals = self
                .managed
                .as_ref()
                .map(|m| {
                    m.registry
                        .signer(&SignerEndpoint::Environment)
                        .map(|s| s.refusals())
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            format!(
                "exit {:?}: {}; environment signer refusals {refusals:?}",
                out.status.code(),
                s.replace(self.account.as_str(), "<user>")
            )
        }
    }

    /// `(exit, stdout, stderr)` of a step run through the real runner.
    /// `home` is the world's scratch home: on Windows the step's client gets its
    /// configuration and environment from it ([`ScratchClientJob`]); on Unix the client
    /// wrapper already has them.
    pub async fn run_step(home: &ScratchHome, step: &RemoteStep) -> (i32, String, String) {
        let s = step.clone();
        #[cfg(unix)]
        let runner = {
            let _ = home;
            SshStepRunner::new()
        };
        #[cfg(windows)]
        let runner = SshStepRunner::new().with_containment(Box::new(ScratchClientJob::of(home)));
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
            let r = runner.run(&s, tty).expect("the step runs");
            #[cfg(windows)]
            assert!(
                r.lifetime.contained,
                "the step ran inside the kill-on-close job"
            );
            (r.exit_status, r.stdout, r.stderr_excerpt)
        })
        .await
        .unwrap()
    }

    /// ⟨W4-N01⟩ The Windows step containment the CLI supplies
    /// (`heimdall_localenv::sys::JobObject::kill_on_close`, as
    /// `integration_enroll_verify`'s `cli_death_ends_ssh_step_process`), which also does
    /// what the Unix client wrapper does: the in-box `ssh.exe` gets `-F <scratch config>`
    /// before the step's own arguments (unchanged, in order), `SSH_AUTH_SOCK` the decoy
    /// agent and `HOME` the scratch home, and no askpass or agent variable, so the owner's
    /// configuration and agent are never read. The command is rebuilt for that (a
    /// `Command`'s arguments cannot be prefixed): the same program, the step's arguments
    /// and environment, and piped standard streams as the runner sets them.
    #[cfg(windows)]
    pub struct ScratchClientJob {
        config: PathBuf,
        decoy: std::ffi::OsString,
        home: PathBuf,
    }

    #[cfg(windows)]
    impl ScratchClientJob {
        pub fn of(home: &ScratchHome) -> ScratchClientJob {
            ScratchClientJob {
                config: home.user_config.clone(),
                decoy: home.decoy_agent().endpoint().locator(),
                home: home.git_home.clone(),
            }
        }
    }

    #[cfg(windows)]
    impl heimdall_enroll::remote::StepContainment for ScratchClientJob {
        fn spawn_contained(
            &self,
            command: &mut std::process::Command,
        ) -> std::io::Result<heimdall_enroll::remote::Contained> {
            use std::process::Stdio;
            let mut cmd = std::process::Command::new(command.get_program());
            cmd.arg("-F").arg(&self.config).args(command.get_args());
            for (k, v) in command.get_envs() {
                match v {
                    Some(v) => cmd.env(k, v),
                    None => cmd.env_remove(k),
                };
            }
            cmd.env("SSH_AUTH_SOCK", &self.decoy)
                .env("HOME", &self.home)
                .env_remove("SSH_ASKPASS")
                .env_remove("SSH_ASKPASS_REQUIRE")
                .env_remove("SSH_AGENT_PID")
                .env_remove("DISPLAY")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let job = heimdall_localenv::sys::JobObject::kill_on_close()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let mut child = cmd.spawn()?;
            if let Err(e) = job.assign_child(&child) {
                // Never leave an uncontained child running: it is ours, by its handle.
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::other(e.to_string()));
            }
            Ok(heimdall_enroll::remote::Contained {
                child,
                guard: Box::new(job),
            })
        }

        fn ends_with_parent(&self) -> bool {
            true
        }
    }

    /// A second destination of a [`World`].
    pub struct Second {
        pub sshd: LoopbackSshd,
        pub destination: DestinationId,
        pub registry: PathBuf,
    }

    impl Second {
        pub fn marker_lines(&self) -> usize {
            String::from_utf8(fs::read(&self.registry).unwrap())
                .unwrap()
                .lines()
                .filter(|l| l.contains("heimdall:enr_"))
                .count()
        }
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// This host's boot identity as the scripts render it (`hm_identity`: Linux
    /// `/proc/sys/kernel/random/boot_id`, macOS `sysctl -n kern.bootsessionuuid`, the
    /// shell's `$(…)` dropping trailing newlines; then hex).
    pub fn boot_hex() -> String {
        let raw = if cfg!(target_os = "linux") {
            fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap()
        } else {
            let out = std::process::Command::new("sysctl")
                .args(["-n", "kern.bootsessionuuid"])
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        hex_lower(raw.trim_end_matches('\n').as_bytes())
    }

    /// A stand-in for a writer that took the registry lock and never let go: a
    /// `/bin/sleep` child of this test leading its own process group. A reaper
    /// thread waits on it (a dead holder is never a zombie that still looks alive),
    /// and `Drop` stops it by its exact child handle. Unix only: the fence reads the
    /// holder on the server's host, which is this host only for a local sshd.
    #[cfg(unix)]
    pub struct Holder {
        pub pid: u32,
        child: Arc<Mutex<std::process::Child>>,
        exited: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        reaper: Option<JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl Holder {
        pub fn start() -> Holder {
            use std::os::unix::process::CommandExt as _;
            let child = std::process::Command::new("/bin/sleep")
                .arg("300")
                .process_group(0)
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            let child = Arc::new(Mutex::new(child));
            let exited = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let (c, e, st) = (Arc::clone(&child), Arc::clone(&exited), Arc::clone(&stop));
            let reaper = std::thread::spawn(move || {
                while !st.load(Ordering::SeqCst) {
                    if let Ok(Some(_)) = c.lock().unwrap().try_wait() {
                        e.store(true, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            Holder {
                pid,
                child,
                exited,
                stop,
                reaper: Some(reaper),
            }
        }

        pub fn alive(&self) -> bool {
            !self.exited.load(Ordering::SeqCst)
        }

        /// The start identity the fence reads for this PID (macOS: `ps -o lstart=`
        /// with its spaces collapsed, under the scripts' `LC_ALL=C TZ=UTC0`; Linux:
        /// `/proc/<pid>/stat` token 20 after the last `)`), in hex.
        pub fn start_hex(&self) -> String {
            let raw = if cfg!(target_os = "linux") {
                let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid)).unwrap();
                let after = &stat[stat.rfind(')').unwrap() + 1..];
                after.split_whitespace().nth(19).unwrap().to_owned()
            } else {
                // As the scripts read it: `LC_ALL=C`, `TZ=UTC0` (`hm_main`).
                let out = std::process::Command::new("/bin/ps")
                    .env("LC_ALL", "C")
                    .env("TZ", "UTC0")
                    .args(["-o", "lstart=", "-p", &self.pid.to_string()])
                    .output()
                    .unwrap();
                String::from_utf8(out.stdout)
                    .unwrap()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            hex_lower(raw.as_bytes())
        }
    }

    #[cfg(unix)]
    impl Drop for Holder {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(r) = self.reaper.take() {
                let _ = r.join();
            }
            if !self.exited.load(Ordering::SeqCst) {
                let mut c = self.child.lock().unwrap();
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// This host's remote clock (the fixture sshd is local): epoch seconds.
    pub fn remote_now() -> i64 {
        Timestamp::now().as_second()
    }

    pub fn rand32() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(&rand16());
        b[16..].copy_from_slice(&rand16());
        b
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

#[cfg(any(unix, windows))]
use fx::*;

/// What the managed legs established (see [`managed_legs`]).
#[cfg(any(unix, windows))]
struct ManagedLegs {
    data: heimdall_contract::request::EnsureData,
    files: (String, std::path::PathBuf, std::path::PathBuf),
    entry: heimdall_domain::issuance::IssuanceEntry,
}

/// ⟨R2-E; ADR-0008 §17.21 items 1, 11⟩ The setup-apply, ensure and ssh legs over a
/// managed world whose pair is `verified` under its first CA (E5 done):
/// 1. **setup apply** ([`World::setup_apply`], ⟨R2-F⟩ the real `setup` path: preview,
///    the owner's `ApplyProjection` decision, the journaled apply): the plan renders the
///    pair's managed section (its `slot_free` disclosure names the destination), the SSH
///    item is applied, and the commit records the pair's preference `managed_certificate`
///    with `projection: applied` at the committed generation, its issuing-CA set unchanged
///    (it was `pending` before: E5's);
/// 2. **ensure** (the real pipeline: resolve mints the binding, the managed effect
///    driver generates K_env, reserves, has the fixture issuer sign exactly the reserved
///    bounds under the enrolled CA, publishes, installs and materializes the binding
///    endpoint and files, `prepare_from`, commit): the result's
///    `consumer.signing_endpoint` names the binding endpoint (generation 1), which lists
///    exactly the grant's one certificate; one published entry for the pair under the
///    CA with principal `hm:<destination>:<account>`;
/// 3. **ssh** ([`World::managed_ssh`]): the server accepts exactly that certificate
///    (key ID, serial, CA), the remote command's marker comes back, and the binding
///    endpoint's signer admitted (permit held) and signed exactly one request, with no
///    refusal.
#[cfg(any(unix, windows))]
async fn managed_legs(w: &World, tag: &str) -> ManagedLegs {
    use heimdall_contract::managed::PreferredMechanism;
    use heimdall_credential::signer::SignStep;
    use heimdall_domain::enrollment::ProjectionStatus;
    let pair = w.pair();
    let ca = w.issuer.ca.fingerprint().clone();
    // 1. setup apply, through the real setup path.
    let before = w
        .tx(|tx| tx.pair_preference(&pair))
        .expect("E5 wrote the preference");
    assert_eq!(
        before.projection,
        ProjectionStatus::Pending,
        "E5 leaves it pending"
    );
    let (plan, result, decided) = w.setup_apply(tag).await;
    assert_eq!(
        decided, 1,
        "the first managed projection needs the owner's decision"
    );
    assert!(
        plan.findings.iter().any(|f| {
            f.code == heimdall_contract::doctor::finding::SLOT_FREE
                && f.subject.id.as_deref() == Some(pair.destination.as_str())
        }),
        "the plan renders the pair's managed section: {:?}",
        plan.findings
    );
    assert_eq!(result["items"][0]["outcome"], "applied", "{result}");
    let generation = w.ssh_generation().expect("the SSH item is committed");
    let pref = w.tx(|tx| tx.pair_preference(&pair)).unwrap();
    assert_eq!(pref.mechanism, PreferredMechanism::ManagedCertificate);
    assert_eq!(pref.projection, ProjectionStatus::Applied { generation });
    assert_eq!(pref.issuing_cas, before.issuing_cas);
    assert!(pref.issuing_cas.contains(&ca));
    // 2. ensure.
    let issued_before = w
        .issuer
        .grant_signed
        .load(std::sync::atomic::Ordering::SeqCst);
    let data = w
        .ensure_managed(tag)
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {:?} {}", e.code, e.reason, e.message));
    let m = w.managed();
    let (endpoint, generation) = m
        .registry
        .binding_endpoint(&data.binding_id)
        .expect("the binding endpoint was created during the preparation");
    assert_eq!(generation, heimdall_domain::resource::ResourceGeneration(1));
    assert_eq!(
        data.consumer.signing_endpoint.as_deref(),
        Some(endpoint.locator.as_str()),
        "the ensure result names the binding endpoint"
    );
    let listed = heimdall_ipc::agent_client::list_identities(
        &agent_locator(&endpoint.locator),
        &heimdall_ipc::agent_client::ClientBounds::default(),
    )
    .await
    .expect("the binding endpoint answers");
    assert_eq!(listed.identities.len(), 1, "the grant's one certificate");
    assert_eq!(
        w.issuer
            .grant_signed
            .load(std::sync::atomic::Ordering::SeqCst),
        issued_before + 1,
        "the issuer signed the grant's one certificate"
    );
    let entries = w.tx(|tx| tx.issuance_entries(&data.grant_id));
    let published: Vec<_> = entries
        .iter()
        .filter(|e| e.state == heimdall_domain::issuance::IssuanceState::Published)
        .collect();
    assert_eq!(published.len(), 1, "{entries:?}");
    let entry = published[0].clone();
    assert_eq!(entry.pair, pair);
    assert_eq!(entry.bounds.ca_fingerprint.as_ref(), Some(&ca));
    assert_eq!(
        entry.bounds.principal,
        format!("hm:{}:{}", pair.destination.as_str(), pair.account.as_str())
    );
    // 3. ssh.
    let files = w.binding_files(&data, &pair.destination);
    let marker = format!("hm-r2e-{}", heimdall_testkit::agent::random_hex(6));
    let before = w.sshd.accepted_certificates().len();
    let out = w
        .managed_ssh(ALIAS, &w.sshd.host_key_line, &files, &marker)
        .await;
    let binding = heimdall_app::ports::SignerEndpoint::Binding(data.binding_id.clone());
    let signer = m.registry.signer(&binding).expect("the binding's signer");
    assert!(
        out.status.success(),
        "{}; binding signer refusals {:?}",
        w.why(&out),
        signer.refusals()
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&marker),
        "the remote command ran"
    );
    let accepted = w.sshd.accepted_certificates();
    assert_eq!(accepted.len(), before + 1, "one login");
    let cert = accepted.last().unwrap();
    assert_eq!(cert.key_id, entry.bounds.key_id, "the grant's certificate");
    assert_eq!(cert.serial, entry.bounds.serial);
    assert_eq!(cert.ca_fingerprint, ca.as_str());
    assert_eq!(cert.fingerprint, entry.bounds.subject_fingerprint, "K_env");
    assert_eq!(
        m.signs.count(&binding, SignStep::Admitted),
        1,
        "permit held"
    );
    assert_eq!(
        m.signs.count(&binding, SignStep::Signed),
        1,
        "one signature"
    );
    assert!(signer.refusals().is_empty(), "{:?}", signer.refusals());
    ManagedLegs { data, files, entry }
}

/// m03-plan U10: the full flow on `LoopbackSshd`: preview, the attended `EnrollAccount`
/// decision, the client-executed inspect and append (the real scripts through
/// `SshStepRunner`), the runtime's own verification (one signature for the positive,
/// none for the negative), and E5: `verified`, the CA in the pair's issuing set, the
/// preference `managed_certificate` with `projection: pending`, `next: setup_apply`.
/// ⟨R2-E; ADR-0008 §17.21 items 1, 11⟩ Then [`managed_legs`]: the **setup-apply** leg
/// (⟨R2-F⟩ the real `setup` path over the runtime's projection writer and store-backed
/// pair source: preview, the `ApplyProjection` decision, the journaled apply, whose
/// commit records the preference `applied`), the **ensure** leg (the real ensure pipeline with the production
/// `ManagedCertificateAdapter`, `ManagedEffectsImpl`, `EndpointRegistry` and
/// `SignerTable`; the fixture issuer signs under the enrolled CA; interactive, see
/// [`World::ensure_managed`]), whose result names the binding endpoint, and the **ssh**
/// leg (the real `ssh` with `connect`'s identity options logs in to the account the
/// enrollment's `cert-authority` line authorizes, through the binding endpoint's
/// permit). Decisions counted: exactly the enrollment's and the projection's (the
/// ensure and ssh legs need none).
/// The existing access (the agent) is not contacted by the managed legs; the decoy
/// agent never.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn enroll_preview_apply_verify_setup_apply_ensure_ssh() {
    let w = World::with(WorldOptions {
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    w.require_recorded_client();
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
    // ⟨R2-E⟩ setup apply, ensure, ssh.
    let existing_contacts = w.agent.contact_count();
    let decoy_contacts = w.home.decoy_agent().contact_count();
    let legs = managed_legs(&w, "full").await;
    assert_eq!(
        w.agent.contact_count(),
        existing_contacts,
        "the managed legs never contact the existing access"
    );
    assert_eq!(
        w.home.decoy_agent().contact_count(),
        decoy_contacts,
        "nor the decoy agent"
    );
    assert_eq!(
        w.tx(|tx| tx.pending_decisions()).len(),
        0,
        "the managed legs left no decision pending (the projection's was approved)"
    );
    assert_eq!(
        w.tx(|tx| tx.grant(&legs.data.grant_id)).map(|g| g.state),
        Some(heimdall_contract::GrantState::Active)
    );
    assert_eq!(
        w.managed().table.vault().len(),
        1,
        "one K_env, in the vault"
    );
}

/// ⟨R2-E⟩ A10's negative half on a second destination: the managed certificate of
/// `legs` (pair (h1, account), principal `hm:<h1>:<account>`) presented to `h2` (alias
/// `alias`, a server that trusts the same CA for `hm:<h2>:<account>` only) is refused:
/// the login fails (exit 255, `Permission denied (publickey)`), h2's log shows it
/// refusing exactly this certificate ("does not contain an authorized principal"), the
/// remote command never runs, h2 accepts no certificate, and the binding endpoint
/// signs nothing for it (the server refuses the certificate before asking for a
/// signature). Then the same certificate is accepted
/// by h1 again (the control: the refusal is h2's, not a broken binding).
// Unix only: needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread.
#[cfg(unix)]
async fn assert_refused_on_other_host(
    w: &World,
    legs: &ManagedLegs,
    alias: &str,
    h2: &heimdall_testkit::sshd::LoopbackSshd,
    h2_principal: &str,
) {
    use heimdall_credential::signer::SignStep;
    let m = w.managed();
    let binding = heimdall_app::ports::SignerEndpoint::Binding(legs.data.binding_id.clone());
    assert_ne!(
        legs.entry.bounds.principal, h2_principal,
        "a narrow certificate"
    );
    let (h2_before, signed_before) = (
        h2.accepted_certificates().len(),
        m.signs.count(&binding, SignStep::Signed),
    );
    let marker = format!("hm-r2e-{}", heimdall_testkit::agent::random_hex(6));
    let mark = h2.log_mark();
    let out = w
        .managed_ssh(alias, &h2.host_key_line, &legs.files, &marker)
        .await;
    assert_eq!(out.status.code(), Some(255), "{}", w.why(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Permission denied (publickey)"),
        "refused at authentication (not a transport or host-key failure): {}",
        w.why(&out)
    );
    // The server's own word, in what this attempt logged: it refused the certificate's
    // principal. OpenSSH 10.x names the certificate (`Refusing certificate ID "<key id>"
    // … does not contain an authorized principal`); 9.6p1 (Ubuntu 24.04, the devbox)
    // logs the bare `Certificate does not contain an authorized principal`. Either way it
    // is this attempt's line (logged after `mark`), and h2 accepted no certificate of
    // this grant.
    let refused = h2.log_lines_since(mark, "does not contain an authorized principal");
    let named = refused.iter().any(|l| {
        l.contains(&format!(
            "Refusing certificate ID \"{}\"",
            legs.entry.bounds.key_id
        ))
    });
    let bare = refused
        .iter()
        .any(|l| l.contains("Certificate does not contain an authorized principal"));
    assert!(
        named || bare,
        "h2 refused the grant's certificate for its principal (this attempt's certificate lines: {:?})",
        h2.log_lines_since(mark, "ertificate")
    );
    assert!(
        !h2.log_lines_since(mark, "Accepted certificate ID")
            .iter()
            .any(|l| l.contains(&legs.entry.bounds.key_id)),
        "h2 accepted no certificate of this grant"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(&marker),
        "nothing ran on h2"
    );
    assert_eq!(
        h2.accepted_certificates().len(),
        h2_before,
        "h2 accepted no certificate"
    );
    assert_eq!(
        m.signs.count(&binding, SignStep::Signed),
        signed_before,
        "no signature was released for h2"
    );
    // The control: h1 accepts the same certificate.
    let h1_before = w.sshd.accepted_certificates().len();
    let marker = format!("hm-r2e-{}", heimdall_testkit::agent::random_hex(6));
    let out = w
        .managed_ssh(ALIAS, &w.sshd.host_key_line, &legs.files, &marker)
        .await;
    assert!(out.status.success(), "{}", w.why(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains(&marker));
    let accepted = w.sshd.accepted_certificates();
    assert_eq!(accepted.len(), h1_before + 1);
    assert_eq!(accepted.last().unwrap().key_id, legs.entry.bounds.key_id);
}

/// m03-plan U10 (A10, account form; ADR-0005 A10: "only the intended access succeeds
/// where enforcement is claimed"): h1 and h2 are both enrolled through the real flow
/// under the **same** CA, each registry holding its own
/// `cert-authority,principals="hm:<dest>:<account>"` line. The managed certificate
/// ensured for (h1, account) logs in to h1 and is refused by h2 (no login, no
/// signature released), while h1 keeps accepting it.
// Unix only: needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread.
#[cfg(unix)]
#[tokio::test]
async fn a10_narrow_certificate_refused_on_other_host_account_form() {
    let w = World::with(WorldOptions {
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    let second = w.add_destination(2);
    let h1 = w.approved(&w.spec(), "req_a10a_h1").await;
    assert_eq!(w.drive(&h1).await.unwrap().state, EnrollmentState::Verified);
    let spec_h2 = EnrollmentSpec {
        destination: second.destination.clone(),
        account: None,
        form: EnrollmentForm::Account,
        registry_path: Some(second.registry.display().to_string()),
        ca_fingerprint: None,
    };
    let h2 = w.approved(&spec_h2, "req_a10a_h2").await;
    assert_eq!(w.drive(&h2).await.unwrap().state, EnrollmentState::Verified);
    let h2_principal = format!("hm:{}:{}", second.destination.as_str(), w.account.as_str());
    let h2_registry = std::fs::read_to_string(&second.registry).unwrap();
    assert!(
        h2_registry.contains(&format!(
            "cert-authority,principals=\"{h2_principal}\" {}",
            w.issuer.ca.public_line()
        )),
        "h2 trusts the same CA, for its own principal only"
    );
    let legs = managed_legs(&w, "a10a").await;
    assert_refused_on_other_host(
        &w,
        &legs,
        &format!("{ALIAS}-2"),
        &second.sshd,
        &h2_principal,
    )
    .await;
}

/// m03-plan U10 (A10, system form): h1 and h2 are both enrolled in the system form under
/// the **same** CA (each sshd's `TrustedUserCAKeys` holds it; each account's
/// `AuthorizedPrincipalsFile` names only its own `hm:<dest>:<account>`), applied by the
/// owner and verified as [`World::system_verified`] does. The managed certificate
/// ensured for (h1, account) logs in to h1 and is refused by h2, while h1 keeps
/// accepting it.
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`); and needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread.
#[cfg(unix)]
#[tokio::test]
async fn a10_narrow_certificate_refused_on_other_host_system_form() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    let (h1, _) = w.system_verified().await;
    assert_eq!(h1.form, EnrollmentForm::System);
    let second = w.add_destination_with(2, EnrollmentForm::System);
    let h2 = w
        .system_verified_on(&second.destination, &second.sshd, "req_a10s_h2")
        .await;
    assert_eq!(h2.form, EnrollmentForm::System);
    assert_eq!(h2.ca_fingerprint, h1.ca_fingerprint, "the same CA");
    let h2_principal = format!("hm:{}:{}", second.destination.as_str(), w.account.as_str());
    let principals = second.sshd.principals_path(w.account.as_str()).unwrap();
    assert_eq!(
        std::fs::read_to_string(principals).unwrap(),
        format!("{h2_principal}\n"),
        "h2's account admits its own principal only"
    );
    let trusted = second.sshd.trusted_ca_keys_path().unwrap();
    assert!(
        std::fs::read_to_string(trusted)
            .unwrap()
            .contains(w.issuer.ca.public_line()),
        "h2 trusts the same CA"
    );
    let legs = managed_legs(&w, "a10s").await;
    assert_refused_on_other_host(
        &w,
        &legs,
        &format!("{ALIAS}-2"),
        &second.sshd,
        &h2_principal,
    )
    .await;
}

/// m03-plan U10 (D5 §6.10): an apply always needs the attended decision; an
/// unattended caller gets `INTERACTION_REQUIRED` with the decision reference, and an
/// unattended `Decide` is refused (nothing consumed).
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
#[tokio::test]
async fn enroll_restart_leaves_operation_unresolved_and_reported() {
    let mut w = World::new().await;
    w.require_recorded_client();
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
#[cfg(any(unix, windows))]
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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

// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
fn fs_clear(path: &std::path::Path) {
    std::fs::write(path, b"").unwrap();
}

/// m03-plan U10 (D5 §6.7): an append whose result was lost but which landed: the
/// reconcile's client-executed inspect finds exactly one exact line (`Applied`), and the
/// record continues at E4 under the still-valid approval.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn enroll_reconcile_applied() {
    let w = World::new().await;
    w.require_recorded_client();
    let op = w.approved(&w.spec(), "req_ra").await;
    w.uncertain_append(&op, true).await;
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::OutcomeUnknown
    );
    assert_eq!(w.marker_lines(), 1, "the append landed");
    let c = w.reconcile(&attended(), &op, false).await.unwrap();
    assert_eq!(c.data["next"], "step");
    let result = w
        .drive(&op)
        .await
        .unwrap_or_else(|e| panic!("drive: {e:?}"));
    // Applied: `applied_unverified`, then the initial verification (E4) under the
    // apply's own authority (ADR-0008 §17.21 item 5): `verified`.
    assert_eq!(result.state, EnrollmentState::Verified, "{result:?}");
    let r = w.records().pop().unwrap();
    assert_eq!(r.state, EnrollmentState::Verified);
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    assert_eq!(w.marker_lines(), 1, "never appended twice");
}

/// m03-plan U10 (D5 §6.7): an unreachable destination leaves the step unknown.
// Unix only: it stops the server; the harness sshd is shared by the run and is not this test's to stop (`LoopbackSshd::stop` leaves a harness server running).
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
#[cfg(any(unix, windows))]
#[tokio::test]
async fn abandon_from_outcome_unknown_remove_unknown_and_rollback_pending() {
    // outcome_unknown
    let w = World::new().await;
    w.require_recorded_client();
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
    // One world at a time: a harness sshd is leased once per thread (Windows).
    drop(w);
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
    // One world at a time: a harness sshd is leased once per thread (Windows).
    drop(w);
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
#[cfg(any(unix, windows))]
#[tokio::test]
async fn rotation_and_removal_with_every_managed_binding_released_and_issuer_unavailable() {
    use std::sync::atomic::Ordering;
    let w = World::new().await;
    w.require_recorded_client();
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
    let _ = run_step(&w.home, &step).await; // it really removed the line
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
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
#[cfg(any(unix, windows))]
async fn past_not_after() {
    tokio::time::sleep(std::time::Duration::from_secs(64)).await;
}

#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
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
#[cfg(any(unix, windows))]
#[tokio::test]
async fn ca_retirement_refused_until_every_enrollment_final_or_abandoned() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_ret").await;
    w.uncertain_append(&op, false).await;
    let id = w.records().pop().unwrap().id;
    let retire = heimdall_contract::issuer::IssuerRequest::Retire {
        ca_fingerprint: w.issuer.ca.fingerprint().clone(),
        deleted_locator: None,
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
#[cfg(any(unix, windows))]
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

/// A foreign record held for a damaged line (two marker lines).
#[cfg(any(unix, windows))]
async fn held_foreign(w: &World, rid: &str) -> heimdall_contract::enrollment::ForeignRemovalTarget {
    let t = w.foreign(EnrollmentForm::Account);
    // A second line with the same marker: damaged.
    let text = w.registry_text();
    let line = text
        .lines()
        .find(|l| l.contains(&t.marker))
        .unwrap()
        .to_owned();
    w.sshd.append_registry_line(&format!("{line} x")).unwrap();
    let e = w.remove_foreign(&t, rid).await.unwrap_err();
    let rm = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let _ = w.drive(&rm).await;
    assert_eq!(
        w.foreign_records(&t.marker).pop().unwrap().state,
        EnrollmentState::Held
    );
    t
}

/// m03-plan U10 (§17.7 item 4): a held foreign removal (a damaged line: two marker
/// lines) is recovered by a new `RemoveEnrollment` decision, ⟨round 2⟩ or abandoned:
/// `abandoned`, `pending_until_line_removed`, the lines left as they are, nothing
/// remote touched.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn foreign_removal_held_recovery_by_new_decision_or_abandon() {
    let w = World::new().await;
    let t = held_foreign(&w, "req_fhr1").await;
    // A new decision recovers it.
    let e = w.remove_foreign(&t, "req_fhr2").await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    w.decide(&e, Verdict::Approve).await.unwrap();
    let records = w.foreign_records(&t.marker);
    assert_eq!(records.len(), 1, "the held record is reused");
    assert_eq!(records[0].state, EnrollmentState::Removing);

    // The abandon path.
    // One world at a time: a harness sshd is leased once per thread (Windows).
    drop(w);
    let w = World::new().await;
    let t = held_foreign(&w, "req_fha1").await;
    let before = w.registry_text();
    let held = w.foreign_records(&t.marker).pop().unwrap();
    let id =
        heimdall_contract::ids::EnrollmentId::parse(t.marker.strip_prefix("heimdall:").unwrap())
            .unwrap();
    let c = w
        .req(
            &attended(),
            EnrollmentRequest::Abandon {
                enrollment_id: id.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(c.data["state"], "abandoned");
    assert_eq!(c.data["residual"], "pending_until_line_removed");
    let f = w.foreign_records(&t.marker).pop().unwrap();
    assert_eq!(f.id, held.id);
    assert_eq!(f.state, EnrollmentState::Abandoned);
    assert!(w.op(&f.operation).state.is_settled());
    assert_eq!(w.registry_text(), before, "nothing remote touched");
    // A non-owner cannot abandon it.
    let e = w
        .req(
            &Caller::unattended(consumer()),
            EnrollmentRequest::Abandon { enrollment_id: id },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
}

// =====================================================================================
// Round 2 (R2-A): ADR-0008 §17.21 items 4 and 5
// =====================================================================================

/// A distinctive comment string of the server owner's (§17.21 item 4).
#[cfg(any(unix, windows))]
const FOREIGN_COMMENT: &str = "hm-owner-note-q7zv-do-not-store";

/// ADR-0008 §17.21 item 4: the journal never stores the inspected registry's foreign
/// bytes. After an enrollment **and** its removal against a registry holding another
/// key's line with a comment and a comment line, no stored receipt of any operation
/// and no operation result contains those bytes; the removal still removes exactly
/// our line (its post-image comes from this runtime's memory of the reading).
#[cfg(any(unix, windows))]
#[tokio::test]
async fn journal_never_stores_foreign_registry_bytes() {
    let other = FixtureKey::generate();
    let foreign_key_line = format!(
        "{} {FOREIGN_COMMENT}-key",
        other.public_line_without_comment()
    );
    let seed = format!("# {FOREIGN_COMMENT} line\n{foreign_key_line}\n");
    let w = World::with(WorldOptions {
        registry_seed: seed.clone().into_bytes(),
        ..WorldOptions::default()
    })
    .await;
    w.require_recorded_client();
    assert!(w.registry_text().contains(FOREIGN_COMMENT));
    let op = w.approved(&w.spec(), "req_min").await;
    let r = w.drive(&op).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.state, EnrollmentState::Verified);
    let id = w.records().pop().unwrap().id;
    let e = w.remove(&id, "req_min_rm").await.unwrap_err();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let rm = e.operation_id.clone().unwrap();
    let r = w.drive(&rm).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 0);
    assert!(
        w.registry_text().starts_with(&seed),
        "the owner's lines kept"
    );
    let other_b64 = foreign_key_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let scanned = w.stored_operation_text();
    assert!(scanned.iter().any(|(o, _)| *o == op) && scanned.iter().any(|(o, _)| *o == rm));
    for (o, text) in &scanned {
        for needle in [FOREIGN_COMMENT, other_b64.as_str()] {
            assert!(!text.contains(needle), "operation {o} stores foreign bytes");
            let hex: String = needle.bytes().map(|b| format!("{b:02x}")).collect();
            assert!(
                !text.contains(&hex),
                "operation {o} stores foreign bytes (hex)"
            );
        }
    }
    // The journal kept the registry's digest and Heimdall's own lines only.
    let j = w.journal(&op);
    let i = j.inspection.expect("the latest reading");
    assert!(i.registry.is_some());
}

/// ADR-0008 §17.21 item 5, `enrollment.apply`'s initial verification: authorized only
/// by an **approved `EnrollAccount` that names this operation**, and only at its own
/// stage (the record `verifying` after a confirmed append, nothing outstanding).
#[cfg(any(unix, windows))]
#[tokio::test]
async fn verification_authority_apply_initial_needs_its_own_approval_and_stage() {
    use heimdall_domain::verification::VerificationRefusal as R;
    let w = World::new().await;
    // A real apply A's `EnrollAccount` (denied, so its record is final): the plan
    // summary the forged decisions reuse, and an operation to borrow from.
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    let pending = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_va",
            InteractionMode::NonInteractive,
        )
        .await;
    let a = pending.operation_id.clone().unwrap();
    let a_decision =
        heimdall_contract::ids::DecisionId::parse(pending.next.decision_ref.as_deref().unwrap())
            .unwrap();
    let summary = match w.tx(|tx| tx.decision(&a_decision)).unwrap().kind {
        heimdall_domain::decision::DecisionKind::EnrollAccount {
            plan_digest,
            summary,
            ..
        } => (plan_digest, summary),
        k => panic!("{k:?}"),
    };
    w.decide(&pending, Verdict::Deny).await.unwrap();
    let a_approval = heimdall_app::enrollment::ApprovalFact {
        decision: w.approved_decision(heimdall_domain::decision::DecisionKind::EnrollAccount {
            operation: a.clone(),
            plan_digest: summary.0.clone(),
            summary: summary.1.clone(),
        }),
        at: w.clock.wall(),
    };
    let y = w.seed(
        EnrollmentState::Verifying,
        EnrollmentForm::Account,
        w.served_target(),
        None,
    );
    let mut journal = Journal {
        enrollment: Some(y.id.clone()),
        ..Journal::default()
    };
    let b = w.forge_op(
        OperationKind::EnrollmentApply,
        OperationState::Running,
        None,
        &journal,
        &[World::append_confirmed(&y.marker), World::verify_started()],
    );
    // B's own approved decision: authorized at its stage.
    let own = w.approved_decision(heimdall_domain::decision::DecisionKind::EnrollAccount {
        operation: b.clone(),
        plan_digest: summary.0.clone(),
        summary: summary.1.clone(),
    });
    journal.approval = Some(heimdall_app::enrollment::ApprovalFact {
        decision: own.clone(),
        at: w.clock.wall(),
    });
    w.put_journal(&b, &journal);
    assert_eq!(w.reserve(&b, &y.id).await, Ok(()), "its own approval");
    // Borrowing A's approval (a decision naming another operation): refused.
    journal.approval = Some(a_approval.clone());
    w.put_journal(&b, &journal);
    assert_eq!(w.reserve(&b, &y.id).await, Err(R::OperationNotVerifying));
    // Its own approval but another enrollment: refused.
    journal.approval = Some(heimdall_app::enrollment::ApprovalFact {
        decision: own.clone(),
        at: w.clock.wall(),
    });
    w.put_journal(&b, &journal);
    let ca2 = w.add_ca();
    let z = w.seed_with(
        EnrollmentState::Verifying,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        |r| r.ca_fingerprint = ca2,
    );
    assert_eq!(w.reserve(&b, &z.id).await, Err(R::OperationNotVerifying));
    // Its own stage only: an outstanding step, then no confirmed append.
    let mut out = journal.clone();
    out.outstanding = Some(heimdall_app::enrollment::IssuedStep {
        stage: RemoteStage::Inspect,
        token: "0".repeat(32),
        purpose: heimdall_app::enrollment::StepPurpose::Append,
        issued_continuous_ms: 0,
        issued_wall: w.clock.wall(),
        boot_id: "boot-e2e".into(),
        timeout_ms: 1,
        hard_deadline_ms: 1,
        hard_deadline_wall: w.clock.wall(),
        not_after_remote: None,
        terminate: false,
        preimage: None,
        post_image: None,
    });
    w.put_journal(&b, &out);
    assert_eq!(w.reserve(&b, &y.id).await, Err(R::OperationNotVerifying));
    w.put_journal(&b, &journal);
    assert_eq!(w.reserve(&b, &y.id).await, Ok(()));
    w.settle_forged(&b);
    let c = w.forge_op(
        OperationKind::EnrollmentApply,
        OperationState::Running,
        None,
        &journal,
        &[World::verify_started()],
    );
    assert_eq!(
        w.reserve(&c, &y.id).await,
        Err(R::OperationNotVerifying),
        "no confirmed append"
    );
    w.settle_forged(&c);
    // A record not at `verifying` (applied, not yet verifying): refused.
    let ca3 = w.add_ca();
    let q = w.seed_with(
        EnrollmentState::AppliedUnverified,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        |r| r.ca_fingerprint = ca3,
    );
    let mut jq = journal.clone();
    jq.enrollment = Some(q.id.clone());
    let d = w.forge_op(
        OperationKind::EnrollmentApply,
        OperationState::Running,
        None,
        &jq,
        &[World::append_confirmed(&q.marker), World::verify_started()],
    );
    assert_eq!(w.reserve(&d, &q.id).await, Err(R::OperationNotVerifying));
}

/// The world of the verification-authority tests over **seeded** system-form records
/// (forged operations and `reserve_verification` only; no step, no login): the system
/// form's sshd on Unix, as before; ⟨W4-N01⟩ on Windows the harness's account-form server,
/// since the harness cannot honour `TrustedUserCAKeys` and these tests never contact a
/// server.
#[cfg(any(unix, windows))]
fn seeded_system_world_options() -> WorldOptions {
    WorldOptions {
        form: if cfg!(windows) {
            EnrollmentForm::Account
        } else {
            EnrollmentForm::System
        },
        ..WorldOptions::default()
    }
}

/// ADR-0008 §17.21 item 5, a target change's verification: authorized only by an
/// **approved `ApproveTargetChange` naming this operation, this enrollment, the
/// journal's proposed target and the record's approved target**, at its own stage
/// (`reverifying` from `held`); a presence verification never borrows that stage.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn verification_authority_target_change_needs_its_own_decision_and_stage() {
    use heimdall_domain::decision::DecisionKind;
    use heimdall_domain::verification::VerificationRefusal as R;
    let w = World::with(seeded_system_world_options()).await;
    let mut old = w.served_target();
    let k = FixtureKey::generate().public_line_without_comment();
    old.host_key = raw_key("ssh-ed25519", k.split_whitespace().nth(1).unwrap()).approved();
    let proposed = w.served_target();
    let h = w.seed(
        EnrollmentState::Reverifying,
        EnrollmentForm::System,
        old.clone(),
        Some(heimdall_domain::enrollment::EnrollmentHold {
            reason: heimdall_domain::enrollment::HoldReason::HostKeyChanged,
            evidence_based: false,
        }),
    );
    let mut journal = Journal {
        enrollment: Some(h.id.clone()),
        mode: Some(VerifyMode::TargetChange),
        proposed_target: Some(proposed.clone()),
        reverify_from: Some(heimdall_domain::enrollment::ReverifyFrom::Held),
        ..Journal::default()
    };
    let t = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&h.id, VerifyMode::TargetChange)),
        &journal,
        &[World::verify_started()],
    );
    let decision = |operation: &OperationId,
                    proposed: &heimdall_contract::enrollment::ApprovedTarget| {
        DecisionKind::ApproveTargetChange {
            operation: operation.clone(),
            enrollment: h.id.clone(),
            approved: old.clone(),
            proposed: proposed.clone(),
        }
    };
    let approve = |d| heimdall_app::enrollment::ApprovalFact {
        decision: d,
        at: w.clock.wall(),
    };
    // No approval recorded: refused.
    assert_eq!(w.reserve(&t, &h.id).await, Err(R::OperationNotVerifying));
    // Its own decision: authorized.
    let own = w.approved_decision(decision(&t, &proposed));
    journal.approval = Some(approve(own.clone()));
    w.put_journal(&t, &journal);
    assert_eq!(w.reserve(&t, &h.id).await, Ok(()));
    // A decision naming another operation: refused.
    let other_op = OperationId::from_random_bytes(rand16());
    let borrowed = w.approved_decision(decision(&other_op, &proposed));
    journal.approval = Some(approve(borrowed));
    w.put_journal(&t, &journal);
    assert_eq!(w.reserve(&t, &h.id).await, Err(R::OperationNotVerifying));
    // A decision for another proposed target: refused.
    let mut elsewhere = proposed.clone();
    elsewhere.port = elsewhere.port.wrapping_add(1);
    let wrong = w.approved_decision(decision(&t, &elsewhere));
    journal.approval = Some(approve(wrong));
    w.put_journal(&t, &journal);
    assert_eq!(w.reserve(&t, &h.id).await, Err(R::OperationNotVerifying));
    // Its own decision again; a presence verification of the same record while the
    // target change drives it borrows neither its authority nor its stage.
    journal.approval = Some(approve(own));
    w.put_journal(&t, &journal);
    let p = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&h.id, VerifyMode::Presence)),
        &Journal {
            enrollment: Some(h.id.clone()),
            mode: Some(VerifyMode::Presence),
            ..Journal::default()
        },
        &[World::verify_started()],
    );
    assert_eq!(w.reserve(&p, &h.id).await, Err(R::OperationNotVerifying));
    // ... and the target change is not at its stage while another operation drives it.
    assert_eq!(w.reserve(&t, &h.id).await, Err(R::OperationNotVerifying));
    w.settle_forged(&p);
    assert_eq!(w.reserve(&t, &h.id).await, Ok(()));
    // A presence operation whose journal carries a proposed target is not a target
    // change (and a target change never runs as a presence check).
    w.settle_forged(&t);
    let p2 = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&h.id, VerifyMode::Presence)),
        &Journal {
            enrollment: Some(h.id.clone()),
            mode: Some(VerifyMode::Presence),
            proposed_target: Some(proposed.clone()),
            ..Journal::default()
        },
        &[World::verify_started()],
    );
    assert_eq!(w.reserve(&p2, &h.id).await, Err(R::OperationNotVerifying));
}

/// ADR-0008 §17.21 item 5, the system form's absence check: only an `absence`
/// verification of a **system-form** record at `removal_verifying` (beside its own
/// manual removal operation); a presence verification never borrows that stage.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn verification_authority_system_absence_own_stage() {
    use heimdall_domain::verification::VerificationRefusal as R;
    let w = World::with(seeded_system_world_options()).await;
    let origin = heimdall_domain::enrollment::RemovalOrigin {
        state: EnrollmentState::Verified,
        evidence: None,
        hold: None,
        ca_not_held_seen: false,
    };
    let o2 = origin.clone();
    let s = w.seed_with(
        EnrollmentState::RemovalVerifying,
        EnrollmentForm::System,
        w.served_target(),
        None,
        move |r| r.removal_origin = Some(o2),
    );
    let journal = |mode| Journal {
        enrollment: Some(s.id.clone()),
        mode: Some(mode),
        ..Journal::default()
    };
    // The manual removal's own operation stays open beside the check.
    let manual = w.forge_op(
        OperationKind::EnrollmentRemove,
        OperationState::Running,
        None,
        &Journal {
            enrollment: Some(s.id.clone()),
            ..Journal::default()
        },
        &[],
    );
    let ab = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&s.id, VerifyMode::Absence)),
        &journal(VerifyMode::Absence),
        &[World::verify_started()],
    );
    assert_eq!(w.reserve(&ab, &s.id).await, Ok(()), "its own stage");
    w.settle_forged(&ab);
    // Without the manual removal open, nothing else drives the record: only the
    // presence predicate itself can refuse below.
    w.settle_forged(&manual);
    // A presence verification at `removal_verifying`: refused.
    let pr = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&s.id, VerifyMode::Presence)),
        &journal(VerifyMode::Presence),
        &[World::verify_started()],
    );
    assert_eq!(w.reserve(&pr, &s.id).await, Err(R::OperationNotVerifying));
    w.settle_forged(&pr);
    // A journal whose mode is not the stored request's: refused.
    let mixed = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&s.id, VerifyMode::Absence)),
        &journal(VerifyMode::Presence),
        &[World::verify_started()],
    );
    assert_eq!(
        w.reserve(&mixed, &s.id).await,
        Err(R::OperationNotVerifying)
    );
    w.settle_forged(&mixed);
    // Another kind of open operation driving the record: refused.
    let apply = w.forge_op(
        OperationKind::EnrollmentApply,
        OperationState::Running,
        None,
        &Journal {
            enrollment: Some(s.id.clone()),
            ..Journal::default()
        },
        &[],
    );
    let ab2 = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&s.id, VerifyMode::Absence)),
        &journal(VerifyMode::Absence),
        &[World::verify_started()],
    );
    assert_eq!(w.reserve(&ab2, &s.id).await, Err(R::OperationNotVerifying));
    w.settle_forged(&apply);
    assert_eq!(w.reserve(&ab2, &s.id).await, Ok(()));
    w.settle_forged(&ab2);
    // An account-form record at `removal_verifying` (no such path): refused.
    let o3 = origin.clone();
    let q = w.seed_with(
        EnrollmentState::RemovalVerifying,
        EnrollmentForm::Account,
        w.served_target(),
        None,
        move |r| r.removal_origin = Some(o3),
    );
    let aq = w.forge_op(
        OperationKind::EnrollmentVerify,
        OperationState::Running,
        Some(World::verify_request(&q.id, VerifyMode::Absence)),
        &Journal {
            enrollment: Some(q.id.clone()),
            mode: Some(VerifyMode::Absence),
            ..Journal::default()
        },
        &[World::verify_started()],
    );
    assert_eq!(w.reserve(&aq, &q.id).await, Err(R::OperationNotVerifying));
}

// =====================================================================================
// Round 2 (R2-A): ADR-0008 §17.21 item 11, the enrollment plan tests
// =====================================================================================

/// One reconcile round against our planted lock: the reconcile, its inspect, its
/// `fence` (both real, through `SshStepRunner`); returns the fence's record.
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
async fn reconcile_round(w: &World, op: &OperationId) -> StepRecorded {
    w.reconcile(&attended(), op, false).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(op).await else {
        panic!("the reconcile's inspect");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    let r = w.run_and_report(op, &step).await;
    assert!(r.more, "a fence follows: {r:?}");
    let StepAnswer::Step { step } = w.step_answer(op).await else {
        panic!("the fence");
    };
    assert_eq!(step.stage, RemoteStage::Fence);
    w.run_and_report(op, &step).await
}

/// Enter a reconcile of `op` and plant this step's lock held by `holder` (its exact
/// start identity, `not_after`); returns the reconcile's inspect step, not yet run.
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
async fn reconcile_with_live_lock(
    w: &World,
    op: &OperationId,
    token: &str,
    holder: &Holder,
    not_after: i64,
) -> (RemoteStep, String) {
    w.reconcile(&attended(), op, false).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(op).await else {
        panic!("the reconcile's inspect");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    let start = holder.start_hex();
    w.plant_lock(token, holder.pid, &start, not_after);
    (*step, start)
}

/// The `enroll.fence` audit receipts of `op` (§17.10 item 4), as JSON.
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
fn fence_audits(w: &World, op: &OperationId) -> Vec<serde_json::Value> {
    w.receipts(op)
        .into_iter()
        .filter_map(|r| match (&r.stage[..], r.effect) {
            ("enroll.fence", EffectReceipt::Confirmed { credential_ref, .. }) => {
                Some(serde_json::from_str(&credential_ref).unwrap())
            }
            _ => None,
        })
        .collect()
}

/// m03-plan U10 ⟨r4⟩ (D5 §6.3, §6.7; §17.7 item 1): a lock of this step whose holder
/// cannot be proven gone (a live group whose leader has another start identity: the
/// real fence answers `unproven`, exit 44) is never unlocked, never signalled, and
/// counts an attempt; after `holder_termination_attempts` (3) the record is `held`
/// (`lock_holder_unresolved`). Nothing is ever redispatched.
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
#[tokio::test]
async fn fence_unproven_never_unlocks_and_counts_attempt() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_fu").await;
    let token = w.uncertain_append(&op, false).await;
    let holder = Holder::start();
    w.plant_lock(&token, holder.pid, "00", remote_now() + 3600);
    let before = w.registry_text();
    for attempt in 1..=3u32 {
        let r = reconcile_round(&w, &op).await;
        assert_eq!(r.class, "not_applied", "exit 44, nothing signalled: {r:?}");
        assert!(w.lock_present(), "never unlocked (attempt {attempt})");
        assert!(holder.alive(), "never signalled (attempt {attempt})");
        assert_eq!(w.registry_text(), before, "nothing written");
        assert_eq!(w.journal(&op).fence_attempts, attempt, "the attempt counts");
        let audit = fence_audits(&w, &op).pop().unwrap();
        assert_eq!(audit["exit_status"], 44);
        assert_eq!(audit["signals"], "");
        let record = w.records().pop().unwrap();
        if attempt < 3 {
            assert_eq!(record.state, EnrollmentState::OutcomeUnknown);
            assert!(!r.more, "nothing more in this reconcile");
            let e = w.step(&op).await.unwrap_err();
            assert_eq!(e.code, Code::OutcomeUnknown, "no redispatch: {e:?}");
        } else {
            assert_eq!(record.state, EnrollmentState::Held);
            assert_eq!(
                record.hold.unwrap().reason,
                heimdall_domain::enrollment::HoldReason::LockHolderUnresolved
            );
        }
    }
    let appends = w
        .receipts(&op)
        .iter()
        .filter(|r| {
            r.stage == enrollment_stage::APPEND
                && matches!(r.effect, EffectReceipt::Attempted { .. })
        })
        .count();
    assert_eq!(appends, 1, "the one original append, never redispatched");
    assert_eq!(w.marker_lines(), 0);
}

/// m03-plan U10 ⟨r5⟩ (§17.10 item 4): a `fence --terminate` that sent TERM and KILL
/// and still could not prove the holder gone (exit 44) keeps the signals it sent in
/// the step's class (`uncertain`, never "nothing changed") and the `enroll.fence`
/// audit, counts the attempt, and sends nothing further. The first fence is real
/// (`alive`, past the holder's not-after); the terminating run's report is the CLI's
/// (the real script reaching `unproven` after signals needs U5's pause hooks).
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
#[tokio::test]
async fn fence_audit_keeps_signals_sent_on_unproven() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_fa").await;
    let token = w.uncertain_append(&op, false).await;
    let holder = Holder::start();
    let not_after = remote_now() - 30;
    let (inspect, start) = reconcile_with_live_lock(&w, &op, &token, &holder, not_after).await;
    let r = w.run_and_report(&op, &inspect).await;
    assert!(r.more, "a fence follows: {r:?}");
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("the fence");
    };
    assert_eq!(step.stage, RemoteStage::Fence);
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.class, "not_applied", "alive, exit 43: {r:?}");
    assert_eq!(fence_audits(&w, &op)[0]["exit_status"], 43);
    assert!(r.more, "the terminating fence follows");
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("fence --terminate");
    };
    assert_eq!(step.stage, RemoteStage::Fence);
    let rec = format!(
        "hm1-{token}-{}-{start}-{}-{not_after}",
        holder.pid,
        boot_hex()
    );
    let stdout = format!(
        "HM1 ready\nHM1 v=1\nHM1 remote_now={now}\nHM1 lock=held\nHM1 lock_holder={rec}\n\
         HM1 pgid={pid}\nHM1 group_control=0\nHM1 group_probe=0\nHM1 group_listed=yes\nHM1 fence=alive\n\
         HM1 pgid={pid}\nHM1 group_control=0\nHM1 group_probe=0\nHM1 group_listed=no\nHM1 fence=unproven\n\
         HM1 fence_signals=TERM,KILL\nHM1 status=unproven\n",
        now = remote_now(),
        pid = holder.pid,
    );
    let c = w
        .result(&op, &step.step_token, 44, &stdout, "")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let r: StepRecorded = serde_json::from_value(c.data).unwrap();
    assert_eq!(r.class, "uncertain", "signals were sent: {r:?}");
    assert!(!r.more, "no further signal");
    let audit = fence_audits(&w, &op).pop().unwrap();
    assert_eq!(audit["signals"], "TERM,KILL");
    assert_eq!(audit["terminate"], true);
    assert_eq!(audit["exit_status"], 44);
    assert_eq!(audit["decisions"], serde_json::json!(["alive", "unproven"]));
    assert_eq!(audit["holder"], rec);
    assert_eq!(w.journal(&op).fence_attempts, 1, "the attempt counts");
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::OutcomeUnknown
    );
    assert!(w.lock_present(), "no unlock");
    let e = w.step(&op).await.unwrap_err();
    assert_eq!(e.code, Code::OutcomeUnknown, "no further step: {e:?}");
    assert_eq!(w.marker_lines(), 0);
}

/// m03-plan U10 ⟨r3⟩ (§17.4 item 2; D5 §6.7): the uncertain append's writer still holds
/// its lock past its not-after. The reconcile fences (real: `alive`), terminates the
/// exact process group (real: TERM), proves it gone and removes the lock, inspects
/// again, and only then redispatches the append (attended, approval valid): exactly
/// one line, then `verified`.
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_terminates_stale_holder_then_redispatches() {
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_tr").await;
    let token = w.uncertain_append(&op, false).await;
    let holder = Holder::start();
    let (inspect, _) = reconcile_with_live_lock(&w, &op, &token, &holder, remote_now() - 30).await;
    let r = w.run_and_report(&op, &inspect).await;
    assert!(r.more, "{r:?}");
    let result = w.drive(&op).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(result.state, EnrollmentState::Verified, "{result:?}");
    assert!(!holder.alive(), "the stale holder was terminated");
    assert!(!w.lock_present(), "its lock removed by the fence");
    assert_eq!(w.marker_lines(), 1, "exactly one line");
    let audits = fence_audits(&w, &op);
    assert_eq!(audits.len(), 2, "{audits:?}");
    assert_eq!(audits[0]["terminate"], false);
    assert_eq!(audits[0]["exit_status"], 43);
    assert_eq!(audits[1]["terminate"], true);
    assert_eq!(audits[1]["signals"], "TERM");
    assert_eq!(audits[1]["exit_status"], 0);
    let appends = w
        .receipts(&op)
        .iter()
        .filter(|r| {
            r.stage == enrollment_stage::APPEND
                && matches!(r.effect, EffectReceipt::Attempted { .. })
        })
        .count();
    assert_eq!(appends, 2, "the lost append and its one redispatch");
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
}

/// Three unproven reconciles: the record `held`, `lock_holder_unresolved`.
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
async fn to_lock_holder_unresolved(w: &World, op: &OperationId, token: &str, holder: &Holder) {
    w.plant_lock(token, holder.pid, "00", remote_now() + 3600);
    for _ in 0..3 {
        reconcile_round(w, op).await;
    }
    let r = w.records().pop().unwrap();
    assert_eq!(r.state, EnrollmentState::Held);
    assert_eq!(
        r.hold.unwrap().reason,
        heimdall_domain::enrollment::HoldReason::LockHolderUnresolved
    );
}

/// m03-plan U10 ⟨r3⟩ (D5 §6.7): after `lock_holder_unresolved`, `--after-manual-recovery`
/// only classifies: refused while the lock is still there; once the owner removed it,
/// no line gives `withdrawn` with the `late_write` residual and one exact line gives
/// `applied_unverified`. Never a redispatch (no new append).
// Unix only: the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_after_manual_recovery_classifies_without_redispatch() {
    // The append never ran: absent.
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_mr1").await;
    let token = w.uncertain_append(&op, false).await;
    let holder = Holder::start();
    to_lock_holder_unresolved(&w, &op, &token, &holder).await;
    // Still locked: nothing decided, the record stays held.
    w.reconcile(&attended(), &op, true).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("the manual-recovery inspect");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
    let r = w.run_and_report(&op, &step).await;
    assert!(!r.more, "never a fence after manual recovery: {r:?}");
    assert_eq!(w.records().pop().unwrap().state, EnrollmentState::Held);
    // The owner checked the process and removed the link by hand.
    drop(holder);
    std::fs::remove_file(w.lock_path()).unwrap();
    w.reconcile(&attended(), &op, true).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("the manual-recovery inspect");
    };
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.state, EnrollmentState::Withdrawn, "{r:?}");
    let rec = w.records().pop().unwrap();
    assert!(rec.late_write.is_some(), "the late_write residual");
    assert!(w.op(&op).state.is_settled());
    assert_eq!(w.marker_lines(), 0, "no redispatch");
    let appends = |w: &World, op: &OperationId| {
        w.receipts(op)
            .iter()
            .filter(|r| {
                r.stage == enrollment_stage::APPEND
                    && matches!(r.effect, EffectReceipt::Attempted { .. })
            })
            .count()
    };
    assert_eq!(appends(&w, &op), 1);

    // The append did run: one exact line.
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_mr2").await;
    let token = w.uncertain_append(&op, true).await;
    assert_eq!(w.marker_lines(), 1);
    let holder = Holder::start();
    to_lock_holder_unresolved(&w, &op, &token, &holder).await;
    drop(holder);
    std::fs::remove_file(w.lock_path()).unwrap();
    w.reconcile(&attended(), &op, true).await.unwrap();
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("the manual-recovery inspect");
    };
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.state, EnrollmentState::AppliedUnverified, "{r:?}");
    assert!(w.records().pop().unwrap().hold.is_none());
    // D5 §6.7: one exact line is `Confirmed`, then `applied_unverified`.
    let marker = w.records().pop().unwrap().marker;
    assert!(
        w.receipts(&op).iter().any(|r| r.stage == enrollment_stage::APPEND
            && matches!(&r.effect, EffectReceipt::Confirmed { credential_ref, .. } if *credential_ref == marker)),
        "the append's confirmation"
    );
    assert_eq!(w.marker_lines(), 1, "never appended twice");
    assert_eq!(appends(&w, &op), 1);
    // The initial verification then runs through `enroll verify`.
    let id = w.records().pop().unwrap().id;
    let c = w
        .verify(&id, "req_mr2_v", VerifyMode::Presence)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let v: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(v.state, EnrollmentState::Verified);
}

/// m03-plan U10 (D5 §6.8; U0b row 20; §17.3 item 3): the `RemoveEnrollment` decision
/// lists every live grant holding a certificate under the removed CA for the pair (not
/// one under another CA), and its approval degrades exactly those, `pair_unenrolled`,
/// through the narrowing protocol; the removal then runs.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn enroll_remove_lists_affected_grants_and_degrades_them() {
    use heimdall_domain::decision::DecisionKind;
    let w = World::new().await;
    w.require_recorded_client();
    let op = w.approved(&w.spec(), "req_rg").await;
    let r = w.drive(&op).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.state, EnrollmentState::Verified);
    let rec = w.records().pop().unwrap();
    let under = w.seed_grant_under(&rec.ca_fingerprint, 1);
    let ca2 = w.add_ca();
    let other = w.seed_grant_under(&ca2, 2);
    let e = w.remove(&rec.id, "req_rg_rm").await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let did =
        heimdall_contract::ids::DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
    let d = w.tx(|tx| tx.decision(&did)).unwrap();
    let DecisionKind::RemoveEnrollment {
        affected_grants,
        pair_residual_until,
        ..
    } = d.kind
    else {
        panic!("{:?}", d.kind);
    };
    assert_eq!(
        affected_grants,
        vec![under.clone()],
        "the grants under this CA"
    );
    assert!(pair_residual_until.is_some(), "the pair residual is shown");
    // The `inspect enrollments` view lists it too.
    let view = w.tx(|tx| {
        tx.open_enrollments()
            .map(|v| v.into_iter().map(|r| r.id).collect::<Vec<_>>())
    });
    assert!(view.contains(&rec.id));
    w.decide(&e, Verdict::Approve).await.unwrap();
    let g = w.tx(|tx| tx.grant(&under)).unwrap();
    assert_eq!(g.state, heimdall_contract::GrantState::Degraded);
    assert_eq!(
        w.tx(|tx| tx.grant_degradation(&under)),
        Some(heimdall_domain::grant::DegradedReason::PairUnenrolled)
    );
    assert_eq!(
        w.tx(|tx| tx.grant(&other)).unwrap().state,
        heimdall_contract::GrantState::Active,
        "a grant under another CA is not affected"
    );
    let rm = e.operation_id.clone().unwrap();
    let res = w.drive(&rm).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(res.state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 0);
}

/// A system-form world whose server trusts the CA for the pair, and a record held
/// for a host-key change: its approved key is an old one, the server's is the one
/// the evaluator now finds.
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
fn held_host_key_world_record(
    w: &World,
    state: EnrollmentState,
) -> (
    heimdall_domain::enrollment::EnrollmentRecord,
    heimdall_contract::enrollment::ApprovedTarget,
) {
    held_host_key_world_record_with(w, state, |_| {})
}

// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
fn held_host_key_world_record_with(
    w: &World,
    state: EnrollmentState,
    f: impl FnOnce(&mut heimdall_domain::enrollment::EnrollmentRecord),
) -> (
    heimdall_domain::enrollment::EnrollmentRecord,
    heimdall_contract::enrollment::ApprovedTarget,
) {
    w.sshd.trust_user_ca(w.issuer.ca.public_line()).unwrap();
    let principal = format!("hm:{}:{}", w.destination.as_str(), w.account.as_str());
    w.sshd
        .set_principals(w.account.as_str(), &[principal.as_str()])
        .unwrap();
    let mut old = w.served_target();
    let k = FixtureKey::generate().public_line_without_comment();
    old.host_key = raw_key("ssh-ed25519", k.split_whitespace().nth(1).unwrap()).approved();
    let hold =
        (state == EnrollmentState::Held).then_some(heimdall_domain::enrollment::EnrollmentHold {
            reason: heimdall_domain::enrollment::HoldReason::HostKeyChanged,
            evidence_based: false,
        });
    let record = w.seed_with(state, EnrollmentForm::System, old.clone(), hold, f);
    (record, old)
}

// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
fn system_world_options() -> WorldOptions {
    WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    }
}

/// m03-plan U10 ⟨r4⟩ (§17.7 item 5; D5 §6.2 `reverifying` row): a target change's pass
/// replaces the approved target **in the same transaction** as the move to
/// `verified`: while its attempt runs the record is `reverifying` with the old
/// approved target; after it, `verified` with the proposed one, its evidence and no
/// hold. Never `verified` with the old target, nor the new target before a pass.
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
#[tokio::test]
async fn target_change_pass_replaces_approved_target_atomically() {
    let w = World::with(system_world_options()).await;
    let (record, old) = held_host_key_world_record(&w, EnrollmentState::Held);
    let e = w
        .verify(&record.id, "req_tca", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    assert_eq!(w.record(&record.id).target, old, "unchanged while awaiting");
    let op = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let seen = w.endpoints.seen.lock().unwrap().clone();
    let during = seen
        .last()
        .unwrap()
        .iter()
        .find(|(id, _, _)| *id == record.id)
        .cloned()
        .unwrap();
    assert_eq!(during.1, EnrollmentState::Reverifying);
    assert_eq!(
        during.2, old,
        "the approved target unchanged during the attempt"
    );
    let after = w.record(&record.id);
    assert_eq!(after.state, EnrollmentState::Verified);
    assert_eq!(after.target, w.served_target(), "replaced with the pass");
    assert!(after.hold.is_none());
    let evidence = after.evidence.expect("the pass's evidence");
    assert_eq!(evidence.operation, op);
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
}

/// m03-plan U10 ⟨r4⟩ (§17.7 item 5): a target change whose verification is
/// inconclusive (the issuer unavailable), fails (the server refuses the positive
/// certificate), or finds yet another key (the proposed one is not the server's)
/// leaves the approved target unchanged and the record `held`, reason unchanged.
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
#[tokio::test]
async fn target_change_failure_or_inconclusive_keeps_approved_target_and_held() {
    use std::sync::atomic::Ordering;
    let w = World::with(system_world_options()).await;
    let (record, old) = held_host_key_world_record(&w, EnrollmentState::Held);
    let check = |w: &World, op: &OperationId, why: &str| {
        let r = w.record(&record.id);
        assert_eq!(r.state, EnrollmentState::Held, "{why}");
        assert_eq!(
            r.hold.map(|h| h.reason),
            Some(heimdall_domain::enrollment::HoldReason::HostKeyChanged),
            "{why}: reason unchanged"
        );
        assert_eq!(r.target, old, "{why}: the approved target unchanged");
        assert_eq!(w.op(op).state, OperationState::Failed, "{why}");
    };
    // Inconclusive: the issuer is unavailable.
    w.issuer.available.store(false, Ordering::SeqCst);
    let e = w
        .verify(&record.id, "req_tcf1", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let _ = w.decide(&e, Verdict::Approve).await;
    check(&w, &op, "inconclusive");
    w.issuer.available.store(true, Ordering::SeqCst);
    // Failure: the server no longer lists the pair's principal.
    w.sshd.set_principals(w.account.as_str(), &[]).unwrap();
    let e = w
        .verify(&record.id, "req_tcf2", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let _ = w.decide(&e, Verdict::Approve).await;
    check(&w, &op, "positive refused");
    let principal = format!("hm:{}:{}", w.destination.as_str(), w.account.as_str());
    w.sshd
        .set_principals(w.account.as_str(), &[principal.as_str()])
        .unwrap();
    // Another key again: the proposed target is not what the server presents.
    let k = FixtureKey::generate().public_line_without_comment();
    w.target.evaluation.lock().unwrap().host_keys =
        vec![raw_key("ssh-ed25519", k.split_whitespace().nth(1).unwrap())];
    let e = w
        .verify(&record.id, "req_tcf3", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let _ = w.decide(&e, Verdict::Approve).await;
    check(&w, &op, "host key mismatch");
}

/// m03-plan U10 ⟨r3⟩ (§17.4 item 5; B R2-05): a `host_key_changed` hold is never
/// re-verified by `enroll verify` nor by the supervisor; only `ApproveTargetChange`
/// re-approves the target, and the decision shows the new key as a diff against the
/// approved one (same `HostName`, `Port`, `User`). A denial changes nothing.
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`).
#[cfg(unix)]
#[tokio::test]
async fn held_host_key_change_needs_target_reapproval_with_key_diff() {
    use heimdall_domain::decision::DecisionKind;
    let w = World::with(system_world_options()).await;
    let (record, old) = held_host_key_world_record(&w, EnrollmentState::Held);
    let e = w
        .verify(&record.id, "req_hk1", VerifyMode::Presence)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(e.reason.as_deref(), Some("enrollment_state"));
    assert!(
        w.ops.reverify_pass().await.unwrap().is_empty(),
        "never automatic"
    );
    assert_eq!(w.record(&record.id).state, EnrollmentState::Held);
    let e = w
        .verify(&record.id, "req_hk2", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let did =
        heimdall_contract::ids::DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
    let DecisionKind::ApproveTargetChange {
        approved,
        proposed,
        enrollment,
        ..
    } = w.tx(|tx| tx.decision(&did)).unwrap().kind
    else {
        panic!("an ApproveTargetChange");
    };
    assert_eq!(enrollment, record.id);
    assert_eq!(approved, old);
    assert_eq!(proposed, w.served_target());
    assert_ne!(approved.host_key, proposed.host_key, "the key diff");
    assert_ne!(approved.host_key.fingerprint, proposed.host_key.fingerprint);
    assert_eq!(
        (&approved.hostname, approved.port, &approved.user),
        (&proposed.hostname, proposed.port, &proposed.user)
    );
    // Denied: nothing changes.
    w.decide(&e, Verdict::Deny).await.unwrap();
    let r = w.record(&record.id);
    assert_eq!(
        (r.state, r.target.clone()),
        (EnrollmentState::Held, old.clone())
    );
    // Approved: the target is re-approved by the pass.
    let e = w
        .verify(&record.id, "req_hk3", VerifyMode::TargetChange)
        .await
        .unwrap_err();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Verified);
    assert_eq!(r.target, w.served_target());
}

/// m03-plan U10 ⟨r3⟩ (D5 §6.8; §17.4 item 5): removing an account-form record held for
/// a host-key change carries the **freshly evaluated target** in its
/// `RemoveEnrollment` (a diff against the approved one), and every removal step runs
/// against it (with the approved target each would be refused `route_changed`).
#[cfg(any(unix, windows))]
#[tokio::test]
async fn held_removal_with_freshly_evaluated_target() {
    use heimdall_domain::decision::DecisionKind;
    let w = World::new().await;
    let mut old = w.served_target();
    let k = FixtureKey::generate().public_line_without_comment();
    old.host_key = raw_key("ssh-ed25519", k.split_whitespace().nth(1).unwrap()).approved();
    let record = w.seed(
        EnrollmentState::Held,
        EnrollmentForm::Account,
        old.clone(),
        Some(heimdall_domain::enrollment::EnrollmentHold {
            reason: heimdall_domain::enrollment::HoldReason::HostKeyChanged,
            evidence_based: false,
        }),
    );
    w.sshd.append_registry_line(&w.line_of(&record)).unwrap();
    assert_eq!(w.marker_lines(), 1);
    let e = w.remove(&record.id, "req_hr").await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let did =
        heimdall_contract::ids::DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
    let DecisionKind::RemoveEnrollment { fresh_target, .. } =
        w.tx(|tx| tx.decision(&did)).unwrap().kind
    else {
        panic!("a RemoveEnrollment");
    };
    let fresh = fresh_target.expect("the freshly evaluated target");
    assert_eq!(fresh, w.served_target());
    assert_ne!(fresh.host_key, old.host_key, "shown as a diff");
    w.decide(&e, Verdict::Approve).await.unwrap();
    let rm = e.operation_id.clone().unwrap();
    let res = w.drive(&rm).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(res.state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 0);
    // The steps' generated known-hosts file pinned the fresh key.
    let paths = w.host.paths(&heimdall_registry_tag(&record.id)).unwrap();
    let kh = std::fs::read_to_string(&paths.trust.user_known_hosts).unwrap();
    assert!(kh.contains(&fresh.host_key.key), "{kh}");
    assert!(!kh.contains(&old.host_key.key));
}

/// The 16-hex tag of an enrollment's generated files.
#[cfg(any(unix, windows))]
fn heimdall_registry_tag(id: &heimdall_contract::ids::EnrollmentId) -> String {
    heimdall_app::enrollment::tag_of(id)
}

/// m03-plan U10 ⟨r3⟩ (B R2-06; D5 §6.5 inconclusive row): an inconclusive initial
/// verification leaves the record `applied_unverified` under the **still-open**
/// `enrollment.apply`; while its approval is valid `enroll verify` refuses and points
/// at `enroll reconcile`, which retries the verification under that same operation.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn initial_verification_retry_under_open_apply_via_reconcile() {
    use std::sync::atomic::Ordering;
    let w = World::new().await;
    w.require_recorded_client();
    let op = w.approved(&w.spec(), "req_iv").await;
    w.issuer.available.store(false, Ordering::SeqCst);
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect");
    };
    w.run_and_report(&op, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("append");
    };
    assert_eq!(step.stage, RemoteStage::Append);
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.state, EnrollmentState::AppliedUnverified, "{r:?}");
    assert_eq!(
        w.op(&op).state,
        OperationState::Running,
        "the apply stays open"
    );
    let id = w.records().pop().unwrap().id;
    let e = w
        .verify(&id, "req_iv_v", VerifyMode::Presence)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(e.next.action, "reconcile");
    assert_eq!(e.next.operation_id.as_ref(), Some(&op));
    w.issuer.available.store(true, Ordering::SeqCst);
    let c = w
        .reconcile(&attended(), &op, false)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let res: EnrollmentResult = serde_json::from_value(c.data).unwrap();
    assert_eq!(res.state, EnrollmentState::Verified, "{res:?}");
    assert_eq!(
        w.op(&op).state,
        OperationState::Succeeded,
        "the same operation"
    );
    let starts = w
        .receipts(&op)
        .iter()
        .filter(|r| r.stage == enrollment_stage::VERIFY_STARTED)
        .count();
    assert_eq!(starts, 2, "the retry ran under the apply");
    assert_eq!(w.marker_lines(), 1);
}

/// m03-plan U10 ⟨r3⟩ (B R2-06; D5 §6.2 `verifying` row): after the apply's approval
/// lapsed, the retry is `enroll verify` (the lapsed apply ends there), and a failure
/// with refusal evidence then **holds** the record (no rollback under a lapsed
/// approval); its removal needs `RemoveEnrollment`.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn initial_verification_failure_after_approval_lapsed_holds() {
    use std::sync::atomic::Ordering;
    let w = World::with(WorldOptions {
        limits: heimdall_app::operations::Limits {
            enrollment_approval_validity: std::time::Duration::from_secs(4),
            ..heimdall_app::operations::Limits::default()
        },
        ..WorldOptions::default()
    })
    .await;
    w.require_recorded_client();
    let op = w.approved(&w.spec(), "req_il").await;
    w.issuer.available.store(false, Ordering::SeqCst);
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect");
    };
    w.run_and_report(&op, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("append");
    };
    let r = w.run_and_report(&op, &step).await;
    assert_eq!(r.state, EnrollmentState::AppliedUnverified, "{r:?}");
    let record = w.records().pop().unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    // The registry turns out not to be the server's authoritative one: our line is no
    // longer what sshd reads (here: the owner removed it by hand).
    let line = w.line_of(&record);
    let text = w.registry_text().replace(&format!("{line}\n"), "");
    std::fs::write(&w.registry, text).unwrap();
    assert_eq!(w.marker_lines(), 0);
    w.issuer.available.store(true, Ordering::SeqCst);
    let e = w
        .verify(&record.id, "req_il_v", VerifyMode::Presence)
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("verification_failed"), "{e:?}");
    let held = w.record(&record.id);
    assert_eq!(held.state, EnrollmentState::Held);
    assert!(held.hold.unwrap().evidence_based);
    assert!(w.op(&op).state.is_settled(), "the lapsed apply ended");
    assert!(
        !w.receipts(&op)
            .iter()
            .chain(w.receipts(e.operation_id.as_ref().unwrap()).iter())
            .any(|r| r.stage == enrollment_stage::ROLLBACK),
        "no rollback under a lapsed approval"
    );
    let e = w.remove(&record.id, "req_il_rm").await.unwrap_err();
    assert_eq!(
        e.code,
        Code::ApprovalRequired,
        "removal needs RemoveEnrollment: {e:?}"
    );
}

/// m03-plan U10 ⟨r2⟩ (F05; D5 §6.4 E5, §6.6): a rotation's verified enrollment only adds
/// its CA to the pair's issuing set. A pair already managed with its projection
/// applied keeps the projection (no `setup_apply`); a first enrollment sets it pending.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn e5_rotation_keeps_projection_and_adds_issuing_ca() {
    use heimdall_domain::enrollment::ProjectionStatus;
    let w = World::new().await;
    w.require_recorded_client();
    let pair = heimdall_domain::scope::AccessPair {
        destination: w.destination.clone(),
        account: w.account.clone(),
    };
    let op = w.approved(&w.spec(), "req_e5a").await;
    let first = w.drive(&op).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        first.next,
        Some(heimdall_contract::enrollment::EnrollmentNext::SetupApply)
    );
    let mut pref = w.tx(|tx| tx.pair_preference(&pair)).unwrap();
    assert_eq!(pref.projection, ProjectionStatus::Pending);
    // `setup apply` applied the projection.
    pref.projection = ProjectionStatus::Applied { generation: 7 };
    w.tx(|tx| tx.set_pair_preference(&pref, Timestamp::now()));
    let ca1 = w.issuer.ca.fingerprint().clone();
    let ca2 = w.add_ca();
    let mut spec = w.spec();
    spec.ca_fingerprint = Some(ca2.clone());
    let op2 = w.approved(&spec, "req_e5b").await;
    let second = w.drive(&op2).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(second.state, EnrollmentState::Verified);
    assert_eq!(
        second.next, None,
        "no setup_apply: the projection is applied"
    );
    let after = w.tx(|tx| tx.pair_preference(&pair)).unwrap();
    assert_eq!(
        after.mechanism,
        heimdall_contract::managed::PreferredMechanism::ManagedCertificate
    );
    assert_eq!(
        after.projection,
        ProjectionStatus::Applied { generation: 7 }
    );
    assert_eq!(
        after.issuing_cas,
        [ca1, ca2].into_iter().collect(),
        "the rotation's CA joins the issuing set"
    );
    assert_eq!(w.marker_lines(), 2);
    assert!(
        w.registry_text().contains(&w.existing),
        "existing access untouched"
    );
}

/// m03-plan U10 (A09, the rotate exercise): two pairs enrolled under CA1 rotate to
/// CA2 while one destination is unreachable. The reachable pair verifies CA2 (both
/// CAs issuing) and then retires CA1 there, removing exactly its line; the unreachable
/// pair is refused before any write and keeps CA1 verified and issuing, its registry
/// untouched. The existing access survives on both.
// Unix only: needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread; and it stops the second server.
#[cfg(unix)]
#[tokio::test]
async fn rotation_two_accounts_one_unreachable() {
    let w = World::new().await;
    let mut second = w.add_destination(2);
    let spec_b = |ca: Option<heimdall_contract::ids::CaFingerprint>| EnrollmentSpec {
        destination: second.destination.clone(),
        account: None,
        form: EnrollmentForm::Account,
        registry_path: Some(second.registry.display().to_string()),
        ca_fingerprint: ca,
    };
    let pair_b = heimdall_domain::scope::AccessPair {
        destination: second.destination.clone(),
        account: w.account.clone(),
    };
    let pair_a = heimdall_domain::scope::AccessPair {
        destination: w.destination.clone(),
        account: w.account.clone(),
    };
    // Both pairs under CA1.
    let a1 = w.approved(&w.spec(), "req_rt_a1").await;
    assert_eq!(w.drive(&a1).await.unwrap().state, EnrollmentState::Verified);
    let b1 = w.approved(&spec_b(None), "req_rt_b1").await;
    assert_eq!(w.drive(&b1).await.unwrap().state, EnrollmentState::Verified);
    assert_eq!((w.marker_lines(), second.marker_lines()), (1, 1));
    let ca1 = w.issuer.ca.fingerprint().clone();
    let ca2 = w.add_ca();
    // B's destination goes away.
    let b_before = std::fs::read(&second.registry).unwrap();
    second.sshd.stop();
    let b2 = w.approved(&spec_b(Some(ca2.clone())), "req_rt_b2").await;
    let e = w.drive(&b2).await.unwrap_err();
    assert_ne!(e.code, Code::Ok);
    let b_records = w.tx(|tx| tx.enrollments_for_pair(&pair_b));
    let b_ca2 = b_records.iter().find(|r| r.ca_fingerprint == ca2).unwrap();
    assert_eq!(
        b_ca2.state,
        EnrollmentState::FailedUnwritten,
        "refused before any write"
    );
    let b_ca1 = b_records.iter().find(|r| r.ca_fingerprint == ca1).unwrap();
    assert_eq!(b_ca1.state, EnrollmentState::Verified, "CA1 stays verified");
    assert_eq!(
        std::fs::read(&second.registry).unwrap(),
        b_before,
        "untouched"
    );
    let pref_b = w.tx(|tx| tx.pair_preference(&pair_b)).unwrap();
    assert_eq!(pref_b.issuing_cas, [ca1.clone()].into_iter().collect());
    // A rotates: CA2 verified beside CA1, then CA1 retired there.
    let mut spec_a = w.spec();
    spec_a.ca_fingerprint = Some(ca2.clone());
    let a2 = w.approved(&spec_a, "req_rt_a2").await;
    assert_eq!(w.drive(&a2).await.unwrap().state, EnrollmentState::Verified);
    let pref_a = w.tx(|tx| tx.pair_preference(&pair_a)).unwrap();
    assert_eq!(
        pref_a.issuing_cas,
        [ca1.clone(), ca2.clone()].into_iter().collect()
    );
    let a_ca1 = w
        .tx(|tx| tx.enrollments_for_pair(&pair_a))
        .into_iter()
        .find(|r| r.ca_fingerprint == ca1)
        .unwrap();
    let e = w.remove(&a_ca1.id, "req_rt_a1_rm").await.unwrap_err();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let rm = e.operation_id.clone().unwrap();
    assert_eq!(w.drive(&rm).await.unwrap().state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 1, "only CA1's line went");
    assert!(!w.registry_text().contains(&a_ca1.marker));
    let pref_a = w.tx(|tx| tx.pair_preference(&pair_a)).unwrap();
    assert_eq!(pref_a.issuing_cas, [ca2].into_iter().collect());
    assert!(
        w.registry_text().contains(&w.existing),
        "existing access survives"
    );
    assert!(
        String::from_utf8(b_before).unwrap().contains(&w.existing),
        "existing access survives on B"
    );
}

/// m03-plan U10 ⟨round 3⟩ (D5 §6.5; ADR-0008 §17.22 item 7, W4-R04 + R2A-Q1): a
/// verified pair whose approved host key the evaluator no longer finds has its
/// evidence invalidated **at the comparison** (an `ensure` before any pass reads
/// `destination_scope: unknown`; `ensure_scope_minimum_refused_before_any_pass`), and
/// a host-key change **never triggers a login**: the supervisor's pass records the
/// mismatch from the evaluation alone (no verification session, no certificate, no
/// `enroll.verify.started`, nothing accepted by the server), so the record is `held`
/// (`host_key_changed`, not evidence-based), the grants under its CA for the pair are
/// degraded, and the new key is never accepted automatically (a second pass does
/// nothing; the approved target is unchanged; only an attended `ApproveTargetChange`
/// verification can accept it). (The client half is
/// `client_change_triggers_prompt_reverification` and
/// `inconclusive_reverification_after_client_change_keeps_scope_unknown`.)
// Unix only: the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`) (`held_host_key_world_record_with` trusts the CA and writes the principals file).
#[cfg(unix)]
#[tokio::test]
async fn evidence_invalidated_on_host_key_or_client_change() {
    let w = World::with(system_world_options()).await;
    // Fresh evidence for the approved (old) key, from the current client, an hour old.
    let version = w.host.version.lock().unwrap().clone();
    let token = version
        .split([',', ' '])
        .next()
        .unwrap()
        .rsplit('_')
        .next()
        .unwrap()
        .to_owned();
    let now = Timestamp::now();
    let evidence = heimdall_domain::enrollment::EnrollmentEvidence {
        client: format!("{} portable {token}", system_ssh().display()),
        server: "SSH-2.0-OpenSSH".into(),
        operation: OperationId::from_random_bytes(rand16()),
        verified_at: Timestamp::from_second(now.as_second() - 3600).unwrap(),
        fresh_until: Timestamp::from_second(now.as_second() + 80 * 86400).unwrap(),
        clock: None,
    };
    let e2 = evidence.clone();
    let (record, old) = held_host_key_world_record_with(&w, EnrollmentState::Verified, move |r| {
        r.verified_at = Some(e2.verified_at);
        r.evidence = Some(e2);
    });
    let ca = record.ca_fingerprint.clone();
    assert!(w.record(&record.id).evidence.is_some());
    // Control: with the approved key still evaluated, nothing is due.
    let served = w.target.evaluation.lock().unwrap().clone();
    let (kt, kb) = (old.host_key.algorithm.clone(), old.host_key.key.clone());
    w.target.evaluation.lock().unwrap().host_keys = vec![raw_key(&kt, &kb)];
    assert!(
        w.ops.reverify_pass().await.unwrap().is_empty(),
        "fresh, same key, same client"
    );
    // The evaluator now finds the server's (new) key, not the approved one.
    *w.target.evaluation.lock().unwrap() = served;
    let grant = w.seed_grant_under(&ca, 3);
    assert_ne!(w.served_target().host_key, old.host_key);
    let sessions = w
        .endpoints
        .created
        .load(std::sync::atomic::Ordering::SeqCst);
    let accepted = w.sshd.accepted_certificates().len();
    let signed = w.issuer.signed.load(std::sync::atomic::Ordering::SeqCst);
    let done = w.ops.reverify_pass().await.unwrap();
    assert_eq!(done, vec![record.id.clone()], "invalidated at once");
    // No login: no verification session, no certificate signed, nothing accepted, no
    // attempt started.
    assert_eq!(
        w.endpoints
            .created
            .load(std::sync::atomic::Ordering::SeqCst),
        sessions,
        "no verification session"
    );
    assert_eq!(
        w.issuer.signed.load(std::sync::atomic::Ordering::SeqCst),
        signed,
        "no verification certificate"
    );
    assert_eq!(w.sshd.accepted_certificates().len(), accepted, "no login");
    let ops: Vec<OperationId> = w
        .stored_operation_text()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(!ops.is_empty(), "the pass opened the record's verification");
    for o in &ops {
        assert!(
            !w.receipts(o)
                .iter()
                .any(|r| r.stage == heimdall_domain::operation::enrollment_stage::VERIFY_STARTED),
            "no verification attempt started"
        );
    }
    let r = w.record(&record.id);
    assert_eq!(
        r.state,
        EnrollmentState::Held,
        "the evidence no longer counts"
    );
    assert_eq!(
        r.hold.map(|h| (h.reason, h.evidence_based)),
        Some((
            heimdall_domain::enrollment::HoldReason::HostKeyChanged,
            false
        ))
    );
    assert_eq!(r.target, old, "the new key is never accepted automatically");
    assert_eq!(
        w.tx(|tx| tx.grant_degradation(&grant)),
        Some(heimdall_domain::grant::DegradedReason::PairUnenrolled)
    );
    assert!(
        w.ops.reverify_pass().await.unwrap().is_empty(),
        "never again by itself"
    );
    assert_eq!(w.record(&record.id).state, EnrollmentState::Held);
    assert_eq!(
        w.endpoints
            .created
            .load(std::sync::atomic::Ordering::SeqCst),
        sessions,
        "still no verification session"
    );
}

// =====================================================================================
// Round 3 (R3-A): ADR-0008 §17.22 items 1, 2 and 7
// =====================================================================================

/// The reason a mismatched descriptor is refused with (§17.22 item 1 names
/// `descriptor_mismatch`, registered by the integrator as §17.22 item 1 names it).
#[cfg(any(unix, windows))]
const DESCRIPTOR_MISMATCH_REASON: &str = "descriptor_mismatch";

/// `t` with its line hash recomputed from its own fields (the bundle's line).
#[cfg(any(unix, windows))]
fn rehashed(
    mut t: heimdall_contract::enrollment::ForeignRemovalTarget,
) -> heimdall_contract::enrollment::ForeignRemovalTarget {
    let line = format!(
        "cert-authority,principals=\"hm:{}:{}\" {} {}",
        t.bundle_destination_id,
        t.account.as_str(),
        t.ca_public_key,
        t.marker
    );
    t.line_sha256 = heimdall_domain::projection::Sha256Hex::of(line.as_bytes())
        .as_str()
        .to_owned();
    t
}

/// ADR-0008 §17.22 item 1 (W4-S01, the security review's probe): a held foreign
/// removal executes only the descriptor that was approved.
/// 1. A's removal is held (a damaged line: two marker lines); the server owner then
///    repairs A's line (drops the duplicate; bootstrap access kept).
/// 2. Requests B with A's marker and host but another principal, another CA or
///    another registry (each with a correctly recomputed line hash) are refused before
///    anything is written: no operation, no decision, the held record unchanged.
/// 3. A decision showing B for the held record (as a pre-fix runtime would have issued
///    it) is refused at approval by the precheck (`DECISION_STALE`): nothing remote
///    runs, A's line stays on the registry.
/// 4. A's own descriptor is still approvable and removes exactly A's line.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn foreign_removal_held_reuse_needs_the_exact_descriptor() {
    let w = World::new().await;
    let a = held_foreign(&w, "req_fdm0").await;
    let repaired: String = w
        .registry_text()
        .lines()
        .filter(|l| !(l.contains(&a.marker) && l.ends_with(" x")))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&w.registry, &repaired).unwrap();
    assert_eq!(w.marker_lines(), 1, "A's line repaired");
    let a_line = repaired
        .lines()
        .find(|l| l.contains(&a.marker))
        .unwrap()
        .to_owned();
    let held = w.foreign_records(&a.marker).pop().unwrap();
    assert_eq!(held.state, EnrollmentState::Held);
    let open_before = w.tx(|tx| tx.open_operations()).len();

    let mut principal = a.clone();
    principal.bundle_destination_id = "dst_elsewhere".to_owned();
    let principal = rehashed(principal);
    let mut ca = a.clone();
    ca.ca_public_key = heimdall_testkit::ca::TestCa::generate(w.home.scratch())
        .unwrap()
        .public_line()
        .to_owned();
    let ca = rehashed(ca);
    let mut registry = a.clone();
    registry.registry.path = Some(format!("{}.b", w.registry_remote));
    for (i, b) in [&principal, &ca, &registry].into_iter().enumerate() {
        assert_ne!(b, &a);
        let e = w
            .remove_foreign(b, &format!("req_fdm_b{i}"))
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
        assert_eq!(
            e.reason.as_deref(),
            Some(DESCRIPTOR_MISMATCH_REASON),
            "{e:?}"
        );
        assert!(e.message.contains("held removal"), "{e:?}");
        assert!(e.operation_id.is_none(), "no operation written: {e:?}");
        assert!(e.next.decision_ref.is_none(), "no decision: {e:?}");
        let records = w.foreign_records(&a.marker);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, EnrollmentState::Held);
        assert_eq!(records[0].target, a, "the held descriptor is unchanged");
        assert_eq!(records[0].operation, held.operation);
        assert!(w.tx(|tx| tx.pending_decisions()).is_empty());
        assert_eq!(w.tx(|tx| tx.open_operations()).len(), open_before);
        assert_eq!(w.registry_text(), repaired, "nothing remote ran");
    }

    // A's own descriptor is admitted; a decision showing B for the same operation is
    // refused at approval.
    let ea = w.remove_foreign(&a, "req_fdm_a").await.unwrap_err();
    assert_eq!(ea.code, Code::ApprovalRequired, "{ea:?}");
    let rm = ea.operation_id.clone().unwrap();
    let da = heimdall_contract::ids::DecisionId::parse(ea.next.decision_ref.as_deref().unwrap())
        .unwrap();
    for (i, b) in [&principal, &ca, &registry].into_iter().enumerate() {
        let mut forged = w.tx(|tx| tx.decision(&da)).unwrap();
        forged.id = heimdall_contract::ids::DecisionId::from_random_bytes(rand16());
        match &mut forged.kind {
            heimdall_domain::decision::DecisionKind::RemoveEnrollment { target, .. } => {
                *target = RemovalTarget::Foreign(b.clone());
            }
            k => panic!("unexpected decision {k:?}"),
        }
        w.tx(|tx| tx.insert_decision(&forged));
        let e = w
            .ops
            .decide(
                &attended(),
                DecideRequest {
                    decision_id: forged.id.clone(),
                    verdict: Verdict::Approve,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::DecisionStale, "variant {i}: {e:?}");
        let f = w.foreign_records(&a.marker).pop().unwrap();
        assert_eq!(f.state, EnrollmentState::Held, "variant {i}");
        assert_eq!(f.target, a);
        assert_eq!(w.op(&rm).state, OperationState::AwaitingApproval);
        assert!(w.step(&rm).await.is_err(), "no remote step for B");
        assert!(w.registry_text().contains(&a_line), "A's line stays");
        assert_eq!(w.registry_text(), repaired, "nothing remote ran");
    }
    // A's own decision removes exactly A's line.
    w.decide(&ea, Verdict::Approve).await.unwrap();
    let res = w.drive(&rm).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(res.state, EnrollmentState::Removed);
    assert_eq!(w.marker_lines(), 0);
}

/// Standard base64 (tests only).
#[cfg(any(unix, windows))]
fn b64encode(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, x)| acc | (u32::from(*x) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(
                    A[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap()],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Every way `needle`'s bytes could appear in stored text: as text, lower- and
/// upper-case hex, and base64 at each of the three alignments (the complete
/// quadruples only, so a needle inside a larger encoded blob is found too).
#[cfg(any(unix, windows))]
fn encodings(needle: &str) -> Vec<String> {
    let b = needle.as_bytes();
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let mut v = vec![needle.to_owned(), hex.clone(), hex.to_ascii_uppercase()];
    for k in 0..3 {
        let rest = &b[k..];
        let whole = rest.len() / 3 * 3;
        v.push(b64encode(&rest[..whole]));
    }
    v
}

/// Assert that no stored receipt or operation result of `w` holds any of `needles`
/// in any encoding; returns how many operations were scanned.
#[cfg(any(unix, windows))]
fn assert_no_stored(w: &World, needles: &[&str]) -> usize {
    let scanned = w.stored_operation_text();
    for (o, text) in &scanned {
        for needle in needles {
            for enc in encodings(needle) {
                assert!(
                    !text.contains(&enc),
                    "operation {o} stores foreign marker-line bytes ({needle:?} as {enc:?})"
                );
            }
        }
    }
    scanned.len()
}

/// Distinctive strings of the server owner's marker-bearing lines (§17.22 item 2).
#[cfg(any(unix, windows))]
const MARKER_NOTE: &str = "hm-owner-marker-note-k3p9-never-stored";
#[cfg(any(unix, windows))]
const MARKER_KEY_NOTE: &str = "hm-owner-marker-key-w5r2";
#[cfg(any(unix, windows))]
const MARKER_DAMAGE: &str = "hm-appended-damage-z8q1";

/// ADR-0008 §17.22 item 2 (W4-S02): the journal stores no foreign bytes, even on
/// lines that carry the marker. Through the **real** inspect and `StepResult` path:
/// 1. an enrollment whose registry gains, before its inspect, an owner's comment and
///    an unrelated key whose comment carry the enrollment's marker;
/// 2. a foreign removal whose registry holds its exact line, a damaged copy with
///    appended data, an owner's comment and an unrelated key carrying its marker.
///
/// No stored receipt and no operation result holds those lines' bytes as text, hex
/// or base64; the journal keeps parsed facts only (counts, the classification, a
/// SHA-256) and Heimdall's exact canonical entry only when it matched.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn journal_never_stores_marker_bearing_foreign_lines() {
    let other = FixtureKey::generate();
    let other_b64 = other
        .public_line_without_comment()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();

    // 1. The enrollment's inspect.
    let w = World::new().await;
    let op = w.approved(&w.spec(), "req_mb1").await;
    let marker = w.records().pop().unwrap().marker;
    w.sshd
        .append_registry_line(&format!("# {MARKER_NOTE} {marker}"))
        .unwrap();
    w.sshd
        .append_registry_line(&format!(
            "{} {MARKER_KEY_NOTE}-{marker}",
            other.public_line_without_comment()
        ))
        .unwrap();
    let _ = w.drive(&op).await;
    assert!(assert_no_stored(&w, &[MARKER_NOTE, MARKER_KEY_NOTE, &other_b64]) >= 1);
    let i = w.journal(&op).inspection.expect("the inspect reading");
    assert_eq!(i.reading.marker_lines, 2);
    assert_eq!(i.reading.own_entries, Some(0));
    assert_eq!(i.reading.own_entry_hex, None, "no canonical entry matched");
    assert_eq!(i.reading.other_marker_lines, Some(2));
    assert_eq!(i.reading.marker_class.as_deref(), Some("damaged"));
    assert!(i.reading.other_marker_sha256.is_some());
    assert!(
        w.registry_text().contains(MARKER_NOTE),
        "the owner's lines kept"
    );

    // 2. A foreign removal's inspect (held: the registry is damaged).
    // One world at a time: a harness sshd is leased once per thread (Windows).
    drop(w);
    let w = World::new().await;
    let t = w.foreign(EnrollmentForm::Account);
    let ours = w
        .registry_text()
        .lines()
        .find(|l| l.contains(&t.marker))
        .unwrap()
        .to_owned();
    for extra in [
        format!("{ours} {MARKER_DAMAGE}"),
        format!("# {MARKER_NOTE} {}", t.marker),
        format!(
            "{} {MARKER_KEY_NOTE}-{}",
            other.public_line_without_comment(),
            t.marker
        ),
    ] {
        w.sshd.append_registry_line(&extra).unwrap();
    }
    let before = w.registry_text();
    let e = w.remove_foreign(&t, "req_mb2").await.unwrap_err();
    let rm = e.operation_id.clone().unwrap();
    w.decide(&e, Verdict::Approve).await.unwrap();
    let _ = w.drive(&rm).await;
    assert_eq!(
        w.foreign_records(&t.marker).pop().unwrap().state,
        EnrollmentState::Held
    );
    assert_eq!(
        w.registry_text(),
        before,
        "nothing removed from a damaged registry"
    );
    assert!(
        assert_no_stored(
            &w,
            &[MARKER_NOTE, MARKER_KEY_NOTE, MARKER_DAMAGE, &other_b64]
        ) >= 1
    );
    let i = w.journal(&rm).inspection.expect("the inspect reading");
    assert_eq!(i.reading.marker_lines, 4);
    assert_eq!(i.reading.own_entries, Some(1));
    let own_hex: String = ours.bytes().map(|b| format!("{b:02x}")).collect();
    assert_eq!(i.reading.own_entry_hex.as_deref(), Some(own_hex.as_str()));
    assert_eq!(i.reading.other_marker_lines, Some(3));
    assert_eq!(i.reading.marker_class.as_deref(), Some("damaged"));
}

/// A managed world's pair verified through the real flow (preview, the attended
/// decision, inspect, append, the runtime's verification) with the managed
/// projection applied through the real `setup` path; returns the record.
#[cfg(any(unix, windows))]
async fn managed_verified(w: &World, tag: &str) -> heimdall_domain::enrollment::EnrollmentRecord {
    w.require_recorded_client();
    let op = w.approved(&w.spec(), &format!("req_{tag}")).await;
    let r = w.drive(&op).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.state, EnrollmentState::Verified);
    let (_, result, _) = w.setup_apply(tag).await;
    assert_eq!(result["items"][0]["outcome"], "applied", "{result}");
    let record = w.records().pop().unwrap();
    assert!(record.evidence.is_some());
    record
}

/// The minimum that needs the destination scope.
#[cfg(any(unix, windows))]
fn scope_minimum() -> heimdall_contract::request::RequiredCapabilities {
    heimdall_contract::request::RequiredCapabilities {
        destination_scope_at_least: Some(
            heimdall_contract::request::DestinationScopeEnforcement::VerifiedServerPrincipals,
        ),
        ..heimdall_contract::request::RequiredCapabilities::default()
    }
}

/// `ensure` with the scope minimum is refused, and without it reports
/// `destination_scope: unknown`; the record is untouched (still `verified`, the same
/// evidence: the comparison writes nothing).
#[cfg(any(unix, windows))]
async fn assert_scope_unknown(
    w: &World,
    record: &heimdall_domain::enrollment::EnrollmentRecord,
    tag: &str,
) {
    use heimdall_contract::request::DestinationScopeEnforcement as S;
    let e = w
        .ensure_managed_with(&format!("{tag}-min"), scope_minimum())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable, "{tag}: {e:?}");
    let plain = w
        .ensure_managed(&format!("{tag}-plain"))
        .await
        .unwrap_or_else(|e| panic!("{tag}: {e:?}"));
    assert_eq!(plain.enforcement.destination_scope, S::Unknown, "{tag}");
    let now = w.record(&record.id);
    assert_eq!(
        now.state,
        EnrollmentState::Verified,
        "{tag}: the state is not the judge"
    );
    assert_eq!(now.evidence, record.evidence, "{tag}: nothing written");
}

/// ADR-0008 §17.22 item 7 (W4-R04; D5 §6.5): through the real managed `ensure`
/// pipeline, **before any re-verification pass**, the evidence is invalid at the
/// comparison: after a host-key change (the alias evaluates to another key for the same
/// route), after a client change, and for a certificate prepared under a different CA
/// than the evidence's, the managed report of an `ensure` gives `destination_scope:
/// unknown`, and an `ensure` whose minimum needs `verified_server_principals` is
/// refused, while the record stays `verified` with its evidence. The control
/// (approved target, same client, same CA) reports `verified_server_principals`,
/// before and between the cases. (Through `ensure` a scope minimum is refused at
/// resolution as well, whatever the evidence: the managed descriptor advertises
/// `destination_scope: unknown`, R3A-Q2; the adapter's own refusal of the minimum is
/// `integration_managed_adapter`'s `evidence_invalidated_at_the_comparison_before_any_pass`.)
#[cfg(any(unix, windows))]
#[tokio::test]
async fn ensure_scope_minimum_refused_before_any_pass() {
    use heimdall_contract::request::DestinationScopeEnforcement as S;
    let w = World::with(WorldOptions {
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    let record = managed_verified(&w, "scp").await;
    let ok = w
        .ensure_managed("scp-ctl")
        .await
        .unwrap_or_else(|e| panic!("control: {e:?}"));
    assert_eq!(
        ok.enforcement.destination_scope,
        S::VerifiedServerPrincipals
    );
    // 1. A host-key change.
    let served = w.target.evaluation.lock().unwrap().clone();
    let other = FixtureKey::generate().public_line_without_comment();
    w.target.evaluation.lock().unwrap().host_keys = vec![raw_key(
        "ssh-ed25519",
        other.split_whitespace().nth(1).unwrap(),
    )];
    assert_scope_unknown(&w, &record, "scp-hk").await;
    *w.target.evaluation.lock().unwrap() = served;
    let ok = w
        .ensure_managed("scp-ctl2")
        .await
        .unwrap_or_else(|e| panic!("control 2: {e:?}"));
    assert_eq!(
        ok.enforcement.destination_scope,
        S::VerifiedServerPrincipals
    );
    // 2. A client change.
    let version = w.host.version.lock().unwrap().clone();
    *w.host.version.lock().unwrap() = "OpenSSH_10.99p9, LibreSSL 3.3.6".to_owned();
    assert_scope_unknown(&w, &record, "scp-cl").await;
    *w.host.version.lock().unwrap() = version;
    let ok = w
        .ensure_managed("scp-ctl3")
        .await
        .unwrap_or_else(|e| panic!("control 3: {e:?}"));
    assert_eq!(
        ok.enforcement.destination_scope,
        S::VerifiedServerPrincipals
    );
    // 3. A different CA: a newer CA verified for the pair without evidence of its own
    // issues the certificate; the first CA's evidence is not this certificate's.
    let ca2 = w.add_ca();
    let pair = w.pair();
    w.seed_with(
        EnrollmentState::Verified,
        EnrollmentForm::Account,
        record.target.clone(),
        None,
        |r| {
            r.ca_fingerprint = ca2.clone();
            r.evidence = None;
            r.verified_at = Some(Timestamp::now());
        },
    );
    w.tx(|tx| tx.add_issuing_ca(&pair, &ca2, Timestamp::now()));
    let e = w
        .ensure_managed_with("scp-ca-min", scope_minimum())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
    let plain = w
        .ensure_managed("scp-ca-plain")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let entries = w.tx(|tx| tx.issuance_entries(&plain.grant_id));
    assert!(
        entries
            .iter()
            .any(|e| e.bounds.ca_fingerprint.as_ref() == Some(&ca2)),
        "issued under the second CA: {entries:?}"
    );
    assert_eq!(plain.enforcement.destination_scope, S::Unknown);
    assert_eq!(w.record(&record.id).evidence, record.evidence);
}

/// ADR-0008 §17.22 item 7 (§17.4 item 11): a client change prompts a re-verification;
/// an **inconclusive** attempt (the issuer does not sign the verification certificate)
/// keeps the evidence invalid: the record stays `verified` with its old evidence
/// (never a renewed freshness), and an `ensure` still reports `unknown` and refuses a
/// minimum that needs the scope.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn inconclusive_reverification_after_client_change_keeps_scope_unknown() {
    let w = World::with(WorldOptions {
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    let record = managed_verified(&w, "inc").await;
    *w.host.version.lock().unwrap() = "OpenSSH_10.99p9, LibreSSL 3.3.6".to_owned();
    w.issuer
        .available
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let done = w.ops.reverify_pass().await.unwrap();
    assert_eq!(
        done,
        vec![record.id.clone()],
        "the client change prompts it"
    );
    w.issuer
        .available
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Verified, "inconclusive: not held");
    assert_eq!(
        r.evidence, record.evidence,
        "the old freshness is not renewed"
    );
    assert_scope_unknown(&w, &record, "inc").await;
}
