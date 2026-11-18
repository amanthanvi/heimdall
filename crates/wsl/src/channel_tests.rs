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

/// Mode B's frames are defined, answered `unsupported` and the session continues; a frame that
/// is not valid in the state (a stray `sink_ack`, then bytes that are no frame) ends the helper
/// with the protocol status.
#[test]
fn helper_answers_mode_b_unsupported_and_ends_on_a_protocol_error() {
    let dir = tempfile::tempdir().unwrap();
    let (transport, helper) = serve_in_thread(helper_env(dir.path(), Some("Ubuntu")));
    let mut s = HelperSession::open(transport, &expected("Ubuntu", "alice", None)).unwrap();
    for (frame, id) in [
        (
            WindowsFrame::Withdraw {
                id: 4,
                binding_tag: "b".to_owned(),
                generation: 1,
            },
            4,
        ),
        (
            WindowsFrame::Open {
                stream: 9,
                binding_tag: "b".to_owned(),
            },
            9,
        ),
    ] {
        s.send(&frame).unwrap();
        match s.recv(Duration::from_secs(5)).unwrap() {
            HelperFrame::Error {
                id: rid,
                kind: ErrorKind::Unsupported,
                ..
            } => assert_eq!(rid, id),
            other => panic!("{other:?}"),
        }
    }
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
