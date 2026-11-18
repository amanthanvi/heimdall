//! The channel's own tests: the client and the real helper loop (`helper::serve`) over a
//! socket pair, with no process. The tests that start the real `heimdall` binary as the helper
//! are `tests/integration/wsl_helper_channel.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ports::{
    DistributionHost, DistributionStart, DistributionTarget, ProjectionWriter, ReconcileError,
    RunningState, SinkError, StageSink,
};
use heimdall_contract::environment::DistributionGuid;
use heimdall_contract::ids::EnvironmentId;
use heimdall_localenv::env::Env;
use heimdall_localenv::paths::SshPaths;

use crate::client::{ChildControl, Expected, HelperSession, SessionError, Transport};
use crate::helper::identity::Identity;
use crate::helper::{self, HelperEnv, SshExe};
use crate::host::{DirectLauncher, WslExeLauncher, WslHost};
use crate::proto::{self, ErrorKind, HelperFrame, Inbound, WindowsFrame};

struct NoChild;

impl ChildControl for NoChild {
    fn id(&self) -> u32 {
        0
    }
    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(Some(0))
    }
    fn kill(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn helper_env(root: &Path, distribution: Option<&str>) -> HelperEnv {
    HelperEnv {
        identity: Identity {
            uid: 1000,
            account: "alice".to_owned(),
            distribution: distribution.map(str::to_owned),
            interop: true,
            append_windows_path: Some(true),
        },
        ssh_paths: SshPaths::with_test_override(root.to_path_buf(), root.join("etc-ssh")),
        config_base: root.join("cfg"),
        state_base: root.join("state"),
        env: Env::from_vars(Vec::<(String, String)>::new()),
        ssh_exe: SshExe::Fixed(PathBuf::from("/usr/bin/ssh")),
        hook: None,
        lock_wait: Duration::from_millis(200),
    }
}

/// The real helper loop on one end of a socket pair, as a thread; the other end as a
/// [`Transport`]. The thread's value is the helper's exit status.
fn serve_in_thread(env: HelperEnv) -> (Transport, std::thread::JoinHandle<i32>) {
    let (windows, helper_end) = UnixStream::pair().unwrap();
    let reader = helper_end.try_clone().unwrap();
    let thread = std::thread::spawn(move || helper::serve(&env, reader, helper_end));
    let transport = Transport {
        reader: Box::new(windows.try_clone().unwrap()),
        writer: Box::new(windows),
        stderr: None,
        child: Box::new(NoChild),
    };
    (transport, thread)
}

fn expected(name: &str, account: &str, uid: Option<u32>) -> Expected {
    Expected {
        name: name.to_owned(),
        account: account.to_owned(),
        uid,
    }
}

/// `helper_hello_mismatch_ends_session`: a hello that names another distribution, another
/// account, another uid, or no distribution at all is answered `bye` and the helper exits
/// without serving anything; a matching hello opens the session.
#[test]
fn helper_hello_mismatch_ends_session() {
    let dir = tempfile::tempdir().unwrap();
    for (distribution, want) in [
        (Some("Ubuntu"), expected("Debian", "alice", None)),
        (Some("Ubuntu"), expected("Ubuntu", "bob", None)),
        (Some("Ubuntu"), expected("Ubuntu", "alice", Some(0))),
        // `$WSL_DISTRO_NAME` unset: Windows refuses.
        (None, expected("Ubuntu", "alice", None)),
    ] {
        let (transport, helper) = serve_in_thread(helper_env(dir.path(), distribution));
        let err = HelperSession::open(transport, &want)
            .err()
            .expect("refused");
        assert_eq!(
            err,
            SessionError::HelloMismatch,
            "{distribution:?} {want:?}"
        );
        assert_eq!(err.code(), "wsl_helper_unavailable");
        assert_eq!(helper.join().unwrap(), 0, "the helper ended on `bye`");
    }
    let (transport, helper) = serve_in_thread(helper_env(dir.path(), Some("Ubuntu")));
    let session = HelperSession::open(transport, &expected("Ubuntu", "alice", Some(1000))).unwrap();
    assert_eq!(session.hello().uid, 1000);
    assert_eq!(session.hello().distribution.as_deref(), Some("Ubuntu"));
    assert_eq!(session.hello().version, proto::VERSION);
    session.close();
    assert_eq!(helper.join().unwrap(), 0);
    // Nothing was created in the account: no request was served.
    assert!(!dir.path().join("state").exists());
}

/// Mode B's requests are served on any session and change nothing until a binding is realized:
/// a `realize` that names a path component, `withdraw` of what is not served and `realized` are
/// answered and the session continues, with nothing created in the account; a frame that is not
/// valid in the state (a stray `sink_ack`, then bytes that are no frame) ends the helper with the
/// protocol status.
#[test]
fn helper_answers_mode_b_requests_and_ends_on_a_protocol_error() {
    let dir = tempfile::tempdir().unwrap();
    let (transport, helper) = serve_in_thread(helper_env(dir.path(), Some("Ubuntu")));
    let mut s = HelperSession::open(transport, &expected("Ubuntu", "alice", None)).unwrap();
    assert!(
        s.hello()
            .run_dir
            .as_deref()
            .is_some_and(|d| d.starts_with('/')),
        "the hello names the run directory"
    );
    s.send(&WindowsFrame::Realize {
        id: 3,
        binding_tag: "../escape".to_owned(),
        generation: 1,
        public: proto::ModeBPublic {
            files: Vec::new(),
            ssh_config: String::new(),
            known_hosts: String::new(),
        },
        deadline: "2026-11-18T10:00:00Z".to_owned(),
    })
    .unwrap();
    assert!(matches!(
        s.recv(Duration::from_secs(5)).unwrap(),
        HelperFrame::Error {
            id: 3,
            kind: ErrorKind::IntentInvalid,
            ..
        }
    ));
    s.send(&WindowsFrame::Withdraw {
        id: 4,
        binding_tag: "b".to_owned(),
        generation: 1,
    })
    .unwrap();
    assert_eq!(
        s.recv(Duration::from_secs(5)).unwrap(),
        HelperFrame::WithdrawOk { id: 4 }
    );
    s.send(&WindowsFrame::Realized { id: 5 }).unwrap();
    assert_eq!(
        s.recv(Duration::from_secs(5)).unwrap(),
        HelperFrame::RealizedOk {
            id: 5,
            bindings: Vec::new()
        }
    );
    assert!(!dir.path().join("state").exists(), "nothing was created");
    // A stream that was never opened is a protocol violation, not a late frame.
    s.send(&WindowsFrame::Close { stream: 9 }).unwrap();
    assert!(matches!(
        s.recv(Duration::from_secs(5)).unwrap(),
        HelperFrame::Error {
            kind: ErrorKind::Protocol,
            ..
        }
    ));
    assert_eq!(helper.join().unwrap(), proto::EXIT_PROTOCOL);

    let (transport, helper) = serve_in_thread(helper_env(dir.path(), Some("Ubuntu")));
    let mut s = HelperSession::open(transport, &expected("Ubuntu", "alice", None)).unwrap();
    // The session continued; now a sink acknowledgment with no request in flight.
    s.send(&WindowsFrame::SinkAck { id: 1, seq: 0 }).unwrap();
    assert!(matches!(
        s.recv(Duration::from_secs(5)).unwrap(),
        HelperFrame::Error {
            kind: ErrorKind::Protocol,
            ..
        }
    ));
    assert_eq!(helper.join().unwrap(), proto::EXIT_PROTOCOL);

    // Bytes that are no frame end it the same way.
    let (windows, helper_end) = UnixStream::pair().unwrap();
    let env = helper_env(dir.path(), Some("Ubuntu"));
    let reader = helper_end.try_clone().unwrap();
    let thread = std::thread::spawn(move || helper::serve(&env, reader, helper_end));
    let mut rx = proto::spawn_reader::<HelperFrame, _>(windows.try_clone().unwrap());
    assert!(matches!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Inbound::Frame(HelperFrame::Hello(_))
    ));
    let mut w = windows;
    proto::write_frame(
        &mut w,
        &WindowsFrame::Welcome {
            version: proto::VERSION.to_owned(),
        },
    )
    .unwrap();
    std::io::Write::write_all(&mut w, &[0, 0, 0, 3, b'x', b'y', b'z']).unwrap();
    assert_eq!(thread.join().unwrap(), proto::EXIT_PROTOCOL);
    let _ = &mut rx;
}

fn target(name: &str) -> DistributionTarget {
    DistributionTarget {
        guid: DistributionGuid::parse("0b1c2d3e-1111-4222-8333-abcdef012345").unwrap(),
        name: name.to_owned(),
        account: "alice".to_owned(),
        namespace: EnvironmentId::from_random_bytes([5; 16]),
    }
}

struct NoSink;

impl StageSink for NoSink {
    fn append(&mut self, _: &heimdall_domain::operation::LocalReceipt) -> Result<(), SinkError> {
        Err(SinkError("no sink in this test".to_owned()))
    }
    fn commit_item(&mut self, _: heimdall_domain::projection::ItemCommit) -> Result<(), SinkError> {
        Err(SinkError("no sink in this test".to_owned()))
    }
}

/// `helper_unavailable_when_no_linux_path_resolves`: the Windows path of the helper is never
/// handed to Linux `--exec`: a resolver that fails, or answers an empty, a Windows or a
/// relative path, is `wsl_helper_unavailable` (ADR-0010 §9 item 8), for the writer, and for a
/// hello that never comes (a helper that is not one).
#[test]
fn helper_unavailable_when_no_linux_path_resolves() {
    let t = target("Ubuntu");
    let answers: [Result<String, SessionError>; 5] = [
        Err(SessionError::HelperUnavailable("wslpath failed".to_owned())),
        Ok(String::new()),
        Ok("C:\\Users\\a\\heimdall".to_owned()),
        Ok("relative/heimdall".to_owned()),
        Ok("/mnt/c/a\n/b".to_owned()),
    ];
    for answer in answers {
        let launcher = Arc::new(
            WslExeLauncher::new(PathBuf::from("wsl.exe"), PathBuf::from("C:\\h\\heimdall"))
                .with_resolver(Box::new(move |_, windows| {
                    assert_eq!(windows, "C:\\h\\heimdall");
                    answer.clone()
                })),
        );
        assert!(matches!(
            crate::client::HelperLauncher::launch(launcher.as_ref(), &t),
            Err(SessionError::HelperUnavailable(_))
        ));
        let writer = crate::DistributionWriter::new(
            launcher,
            t.clone(),
            DistributionStart::Allowed,
            crate::spawn::SSH_EXE_DEFAULT.to_owned(),
        );
        let intent = proto::tests::intent_with(&[], 1);
        assert_eq!(
            writer.apply(&intent, &mut NoSink).unwrap_err(),
            ReconcileError::Unavailable("wsl_helper_unavailable".to_owned())
        );
    }
    // A process that is not a helper never says hello: the same code (here `true`, which
    // exits at once). Explicitly allowed to start, so the launch is attempted.
    let launcher = DirectLauncher::new(PathBuf::from("/usr/bin/true"), vec![], vec![]);
    let writer = crate::DistributionWriter::new(
        launcher.clone(),
        t,
        DistributionStart::Allowed,
        crate::spawn::SSH_EXE_DEFAULT.to_owned(),
    );
    assert_eq!(
        writer
            .apply(&proto::tests::intent_with(&[], 1), &mut NoSink)
            .unwrap_err(),
        ReconcileError::Unavailable("wsl_helper_unavailable".to_owned())
    );
    assert_eq!(launcher.spawned(), 1);
}

/// A stopped (or unknown) distribution under `Forbidden` starts nothing and answers
/// `wsl_distribution_not_running` through the host, the writer and the cleaner: the
/// obligation stays (ADR-0010 §3 item 9, §9 item 2).
#[test]
fn a_stopped_distribution_is_never_started_in_the_background() {
    let t = target("Ubuntu");
    let launcher = DirectLauncher::new(PathBuf::from("/usr/bin/true"), vec![], vec![]);
    let host = WslHost::with_direct_helper(
        launcher.clone(),
        vec![heimdall_app::ports::DiscoveredDistribution {
            guid: t.guid.clone(),
            name: "Ubuntu".to_owned(),
            version: 2,
            default_uid: Some(1000),
        }],
    );
    assert_eq!(host.running(&t.guid), RunningState::Running);
    let not_running = || {
        heimdall_app::ports::AdapterError::Unavailable("wsl_distribution_not_running".to_owned())
    };
    for state in [RunningState::NotRunning, RunningState::Unknown] {
        launcher.set_running(state);
        assert_eq!(host.running(&t.guid), state);
        assert_eq!(
            host.writer(&t, DistributionStart::Forbidden).err(),
            Some(not_running())
        );
        assert_eq!(
            host.cleaner(&t, DistributionStart::Forbidden).err(),
            Some(not_running())
        );
        // A writer obtained while it ran still refuses once it stopped.
        launcher.set_running(RunningState::Running);
        let writer = host.writer(&t, DistributionStart::Forbidden).unwrap();
        let cleaner = host.cleaner(&t, DistributionStart::Forbidden).unwrap();
        launcher.set_running(state);
        assert_eq!(
            writer
                .apply(&proto::tests::intent_with(&[], 1), &mut NoSink)
                .unwrap_err(),
            ReconcileError::Unavailable("wsl_distribution_not_running".to_owned())
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let locator = heimdall_domain::projection::ProjectionLocator {
            role: heimdall_domain::projection::FileRole::GitManaged,
            path: "/home/alice/.config/heimdall/gitconfig".to_owned(),
            identity: heimdall_domain::projection::FileIdentity::Unix {
                dev: 1,
                ino: 2,
                birth: None,
            },
            sha256: heimdall_domain::projection::Sha256Hex::parse(&"a".repeat(64)).unwrap(),
        };
        let resource = heimdall_domain::resource::ManagedResource {
            id: heimdall_domain::projection::projection_resource_id(
                &t.namespace,
                locator.role,
                &locator.path,
            ),
            kind: heimdall_domain::resource::ResourceKind::ConfigProjection,
            owner: heimdall_domain::resource::OwnerRef::Projection {
                environment: t.namespace.clone(),
            },
            generation: heimdall_domain::resource::ResourceGeneration(1),
            desired: heimdall_domain::resource::ResourceState::Absent,
            observed: heimdall_domain::resource::ResourceState::Present,
            last_operation: None,
            locator: locator.canonical().unwrap(),
            updated_at: heimdall_contract::Timestamp::now(),
        };
        assert_eq!(
            rt.block_on(cleaner.delete(&resource)).unwrap_err(),
            not_running()
        );
    }
    assert_eq!(launcher.spawned(), 0, "nothing was started");
}

/// A host with no WSL answers `wsl_unavailable`.
#[test]
fn a_host_without_wsl_answers_wsl_unavailable() {
    let host = WslHost::unavailable();
    assert_eq!(
        host.discover().unwrap_err(),
        heimdall_app::ports::AdapterError::Unavailable("wsl_unavailable".to_owned())
    );
    let t = target("Ubuntu");
    assert_eq!(host.running(&t.guid), RunningState::Unknown);
    assert!(host.writer(&t, DistributionStart::Forbidden).is_err());
}

// --- Mode B: the bridge over the real helper loop -------------------------------------------------

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::bridge::{Bridge, BridgePublic, StreamHandler, realized_paths};
use crate::client::HelperLauncher;

/// The "process" of a helper thread: it has exited once the helper loop returned.
struct ThreadChild(Arc<std::sync::atomic::AtomicBool>);

impl ChildControl for ThreadChild {
    fn id(&self) -> u32 {
        0
    }
    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self.0.load(Ordering::SeqCst).then_some(0))
    }
    fn kill(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Launches the real helper loop on a thread (one per launch) over a socket pair.
struct InProcess {
    env: HelperEnv,
    helpers: Mutex<Vec<std::thread::JoinHandle<i32>>>,
}

impl HelperLauncher for InProcess {
    fn running(&self, _name: &str) -> RunningState {
        RunningState::Running
    }
    fn launch(&self, _target: &DistributionTarget) -> Result<Transport, SessionError> {
        let (windows, helper_end) = UnixStream::pair().unwrap();
        let reader = helper_end.try_clone().unwrap();
        let env = self.env.clone();
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&exited);
        let thread = std::thread::spawn(move || {
            let code = helper::serve(&env, reader, helper_end);
            flag.store(true, Ordering::SeqCst);
            code
        });
        self.helpers.lock().unwrap().push(thread);
        Ok(Transport {
            reader: Box::new(windows.try_clone().unwrap()),
            writer: Box::new(windows),
            stderr: None,
            child: Box::new(ThreadChild(exited)),
        })
    }
}

/// Counts the streams it is given and accepts or refuses them all.
struct CountingHandler {
    accept: bool,
    served: AtomicUsize,
}

impl StreamHandler for CountingHandler {
    fn serve(&self, _tag: &str, stream: tokio::io::DuplexStream) -> bool {
        self.served.fetch_add(1, Ordering::SeqCst);
        drop(stream);
        self.accept
    }
}

fn public(run_dir: &str, tag: &str, files: &[&str]) -> BridgePublic {
    BridgePublic {
        files: files
            .iter()
            .map(|n| ((*n).to_owned(), format!("ssh-ed25519 AAAA{n}")))
            .collect(),
        ssh_config: format!(
            "Host *\n  IdentityAgent {}\n  IdentitiesOnly yes\n",
            realized_paths(run_dir, tag).socket
        ),
        known_hosts: "h1 ssh-ed25519 AAAAhost\n".to_owned(),
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn in_one_hour() -> heimdall_contract::Timestamp {
    heimdall_contract::Timestamp::now()
        .checked_add(Duration::from_secs(3600))
        .unwrap()
}

/// `helper_withdraw_of_old_generation_keeps_replacement`, with the files and the stale-socket
/// rule: a stopped distribution starts nothing under `Forbidden`; the first `realize` removes a
/// dead leftover endpoint of this uid and leaves a live one (refusing that tag); the binding
/// directory is 0700, the socket 0600; the same generation is idempotent and recreates a deleted
/// socket; a newer generation replaces the files at the same path and drops what it no longer
/// carries; an older one is refused; `withdraw` removes exactly the generation it names, so the
/// old generation's withdrawal keeps the replacement; a refused stream ends at once on the Linux
/// client; and ending the session removes every endpoint and the helper exits 0.
#[test]
fn helper_withdraw_of_old_generation_keeps_replacement() {
    let root = tempfile::Builder::new()
        .prefix("hw")
        .tempdir_in("/tmp")
        .unwrap();
    // The account's own tree whatever the umask (Mode B refuses a replaceable run base).
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let env = helper_env(root.path(), Some("Ubuntu"));
    let launcher = Arc::new(InProcess {
        env,
        helpers: Mutex::new(Vec::new()),
    });
    let t = target("Ubuntu");
    let handler = Arc::new(CountingHandler {
        accept: false,
        served: AtomicUsize::new(0),
    });

    // A stopped distribution under `Forbidden` starts nothing.
    let stopped = DirectLauncher::new(PathBuf::from("/usr/bin/true"), vec![], vec![]);
    stopped.set_running(RunningState::NotRunning);
    assert_eq!(
        Bridge::start(
            stopped.clone(),
            &t,
            DistributionStart::Forbidden,
            handler.clone()
        )
        .unwrap_err(),
        SessionError::NotRunning
    );
    assert_eq!(stopped.spawned(), 0);

    // Leftovers of an earlier helper: a dead socket (and a file beside it), and a live one.
    let run = root.path().join("state/heimdall/run");
    let b = run.join("b");
    for tag in ["dead1", "live1"] {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(b.join(tag))
            .unwrap();
    }
    drop(std::os::unix::net::UnixListener::bind(b.join("dead1/agent.sock")).unwrap());
    std::fs::write(b.join("dead1/known_hosts"), b"x").unwrap();
    let live = std::os::unix::net::UnixListener::bind(b.join("live1/agent.sock")).unwrap();

    let bridge = Bridge::start(
        launcher.clone(),
        &t,
        DistributionStart::Forbidden,
        handler.clone(),
    )
    .unwrap();
    assert_eq!(bridge.run_dir(), run.to_str().unwrap());
    assert!(bridge.alive());
    let run_dir = bridge.run_dir().to_owned();
    let paths = realized_paths(&run_dir, "b1");
    let at = in_one_hour();

    // generation 1.
    assert_eq!(
        bridge
            .realize(
                "b1",
                1,
                public(&run_dir, "b1", &["a-cert.pub", "b-cert.pub"]),
                at
            )
            .unwrap(),
        paths
    );
    assert!(!b.join("dead1").exists(), "the dead leftover was removed");
    assert!(b.join("live1/agent.sock").exists(), "the live one was left");
    assert_eq!(
        bridge
            .realize("live1", 1, public(&run_dir, "live1", &[]), at)
            .unwrap_err()
            .code(),
        "wsl_endpoint_in_use"
    );
    assert!(b.join("live1/agent.sock").exists());
    assert_eq!(
        std::fs::read_dir(b.join("live1")).unwrap().count(),
        1,
        "nothing was written into a directory that is not ours"
    );
    drop(live);

    let dir = b.join("b1");
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("agent.sock")), 0o600);
    assert_eq!(
        std::fs::read_to_string(dir.join(".generation")).unwrap(),
        "1"
    );
    assert!(dir.join("a-cert.pub").exists() && dir.join("b-cert.pub").exists());
    assert!(
        std::fs::read_to_string(dir.join("ssh_config"))
            .unwrap()
            .contains(&paths.socket)
    );
    assert_eq!(bridge.realized().unwrap(), vec![("b1".to_owned(), 1)]);

    // The same generation is idempotent and recreates a deleted socket.
    std::fs::remove_file(dir.join("agent.sock")).unwrap();
    bridge
        .realize(
            "b1",
            1,
            public(&run_dir, "b1", &["a-cert.pub", "b-cert.pub"]),
            at,
        )
        .unwrap();
    assert_eq!(mode(&dir.join("agent.sock")), 0o600);

    // A refused stream (the handler says no) ends at once on the Linux client.
    let mut client = std::os::unix::net::UnixStream::connect(dir.join("agent.sock")).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(&[0, 0, 0, 1, 11]).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(client.read(&mut buf).unwrap(), 0, "closed, no reply");
    assert_eq!(handler.served.load(Ordering::SeqCst), 1);

    // generation 2 replaces the files at the same path.
    bridge
        .realize(
            "b1",
            2,
            public(&run_dir, "b1", &["a-cert.pub", "c-cert.pub"]),
            at,
        )
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join(".generation")).unwrap(),
        "2"
    );
    assert!(dir.join("c-cert.pub").exists());
    assert!(!dir.join("b-cert.pub").exists(), "no longer carried");
    assert_eq!(mode(&dir.join("agent.sock")), 0o600);
    // An older generation is refused and changes nothing.
    assert_eq!(
        bridge
            .realize("b1", 1, public(&run_dir, "b1", &["z.pub"]), at)
            .unwrap_err()
            .code(),
        "wsl_binding_generation_stale"
    );
    assert!(!dir.join("z.pub").exists());
    assert_eq!(bridge.realized().unwrap(), vec![("b1".to_owned(), 2)]);

    // The old generation's withdrawal keeps the replacement; the current one's removes it.
    bridge.withdraw("b1", 1).unwrap();
    assert!(dir.join("agent.sock").exists() && dir.join("c-cert.pub").exists());
    assert_eq!(bridge.realized().unwrap(), vec![("b1".to_owned(), 2)]);
    bridge.withdraw("b1", 3).unwrap();
    assert!(
        dir.exists(),
        "a generation that is not served is not removed"
    );
    // A second binding, disjoint from the first.
    bridge
        .realize("b2", 1, public(&run_dir, "b2", &[]), at)
        .unwrap();
    bridge.withdraw("b1", 2).unwrap();
    assert!(!dir.exists(), "the whole directory is removed");
    bridge.withdraw("b1", 2).unwrap();
    assert_eq!(bridge.realized().unwrap(), vec![("b2".to_owned(), 1)]);
    assert!(b.join("b2/agent.sock").exists());

    // Ending the session (EOF) removes every endpoint and the helper exits 0.
    drop(bridge);
    let helper = launcher.helpers.lock().unwrap().pop().unwrap();
    assert_eq!(helper.join().unwrap(), 0);
    assert!(!b.join("b2").exists());
    assert!(b.join("live1").exists(), "what was not ours stays");
}

/// ⟨M04 W2 review, M04-W2-R01⟩ The review's probe, inverted: Mode B answers paths (the socket,
/// the `ssh_config` the owner runs `ssh -F` with) only through a tree no other principal can
/// replace, and only when they name the directory the files were written through.
/// 1. A run base that another principal could rename entries in (world-writable, not sticky)
///    is refused before anything is created.
/// 2. With a safe base, a binding is realized; then its anchor is renamed aside and a
///    configuration is planted at the binding's path (what another principal could do in a
///    replaceable base, done here by the test's own account). The next realize of that binding
///    is refused: the planted configuration is never answered and is left as it was, no socket
///    is bound beside it, and the legitimate files stay in the displaced tree.
#[test]
fn mode_b_answers_paths_only_through_a_verified_unreplaced_tree() {
    let root = tempfile::Builder::new()
        .prefix("hwr")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = helper_env(root.path(), Some("Ubuntu"));
    std::fs::create_dir(&env.state_base).unwrap();
    std::fs::set_permissions(&env.state_base, std::fs::Permissions::from_mode(0o777)).unwrap();
    let base = env.state_base.clone();
    let launcher = Arc::new(InProcess {
        env,
        helpers: Mutex::new(Vec::new()),
    });
    let handler = Arc::new(CountingHandler {
        accept: false,
        served: AtomicUsize::new(0),
    });
    let bridge = Bridge::start(
        launcher.clone(),
        &target("Ubuntu"),
        DistributionStart::Forbidden,
        handler,
    )
    .unwrap();
    let run = bridge.run_dir().to_owned();
    let at = in_one_hour();

    // 1. A replaceable base: refused, nothing created under it.
    assert_eq!(
        bridge
            .realize("b1", 1, public(&run, "b1", &[]), at)
            .unwrap_err()
            .code(),
        "wsl_bridge_run_dir_unsafe"
    );
    assert!(!Path::new(&run).join("b").exists(), "nothing created");

    // 2. A safe base: realized; then the anchor is replaced and the next realize is refused.
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let first = bridge
        .realize("b1", 1, public(&run, "b1", &[]), at)
        .unwrap();
    assert!(UnixStream::connect(&first.socket).is_ok());
    std::fs::rename(base.join("heimdall"), base.join("displaced")).unwrap();
    let replacement = base.join("heimdall/run/b/b1");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&replacement)
        .unwrap();
    let planted = "Host *\n  ProxyCommand /usr/bin/touch /nonexistent/hm-planted\n";
    std::fs::write(replacement.join("ssh_config"), planted).unwrap();
    assert_eq!(
        bridge
            .realize("b1", 1, public(&run, "b1", &[]), at)
            .unwrap_err()
            .code(),
        "wsl_bridge_run_dir_unsafe"
    );
    assert_eq!(
        std::fs::read_to_string(replacement.join("ssh_config")).unwrap(),
        planted,
        "the planted configuration is never answered, and left as it was"
    );
    assert!(
        !replacement.join("agent.sock").exists(),
        "no socket is bound beside it"
    );
    let displaced = base.join("displaced/run/b/b1/ssh_config");
    assert_ne!(std::fs::read_to_string(&displaced).unwrap(), planted);
    drop(bridge);
    assert_eq!(
        launcher
            .helpers
            .lock()
            .unwrap()
            .pop()
            .unwrap()
            .join()
            .unwrap(),
        0
    );
}

/// ⟨M04 fix re-check, M04-FX-RC01⟩ The re-check's probe, inverted: a run base reached through
/// a symbolic link that is not root's (here `<root>/link -> <shared>/pivot -> <root>/good`,
/// `<shared>` writable by anyone and not sticky) is refused before anything is created, with
/// its own reason, so a later swap of the intermediate link can never redirect an answered
/// `ssh_config`. (A root-owned link whose target chain is secure passes: on macOS every
/// fixture here sits under `/tmp`, a root-owned link to `/private/tmp`.)
#[test]
fn mode_b_refuses_a_run_base_reached_through_a_replaceable_link() {
    use std::os::unix::fs::symlink;
    let root = tempfile::Builder::new()
        .prefix("hwl")
        .tempdir_in("/tmp")
        .unwrap();
    let r = root.path();
    for (name, mode) in [
        ("", 0o755),
        ("shared", 0o777),
        ("good", 0o755),
        ("good/state", 0o755),
    ] {
        let d = r.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let pivot = r.join("shared/pivot");
    symlink(r.join("good"), &pivot).unwrap();
    symlink(&pivot, r.join("link")).unwrap();
    let mut env = helper_env(r, Some("Ubuntu"));
    env.state_base = r.join("link/state");
    let launcher = Arc::new(InProcess {
        env,
        helpers: Mutex::new(Vec::new()),
    });
    let bridge = Bridge::start(
        launcher.clone(),
        &target("Ubuntu"),
        DistributionStart::Forbidden,
        Arc::new(CountingHandler {
            accept: false,
            served: AtomicUsize::new(0),
        }),
    )
    .unwrap();
    let run = bridge.run_dir().to_owned();
    assert_eq!(
        bridge
            .realize("b1", 1, public(&run, "b1", &[]), in_one_hour())
            .unwrap_err()
            .code(),
        "wsl_bridge_run_dir_linked"
    );
    assert!(
        !r.join("good/state/heimdall/run/b").exists(),
        "nothing created behind the link"
    );
    drop(bridge);
    assert_eq!(
        launcher
            .helpers
            .lock()
            .unwrap()
            .pop()
            .unwrap()
            .join()
            .unwrap(),
        0
    );
}
