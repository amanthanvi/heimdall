//! M02-U7 fixture tests (m02-plan U7 "Tests"; ADR-0007 §9, F21, F23). Hosted by
//! `heimdall-testkit` as `integration_testkit_fixtures`.
//!
//! Disposable fixtures only: every key is generated per run, every path is in a
//! scratch directory this test created, every server binds `127.0.0.1` or an
//! owner-only socket, every process is stopped by its exact PID. No test reads the
//! owner's `~/.ssh`, agents or keys. Unix-only cases need the host's OpenSSH
//! (`ssh`, `sshd`, `ssh-agent`, `ssh-add`, `ssh-keygen`); Windows runs them through
//! the native harness (m02-plan §4).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_testkit::agent::{
    AgentConnection, AgentContact, AgentMode, AskpassAnswer, CountingProxy, Endpoint, FakeAgent,
    FakeAgentConfig, FixtureKey, is_fixture_pipe_name, msg, parse_identities_answer,
    parse_sign_response, request_identities, sign_request,
};
use heimdall_testkit::home::{
    ClientKind, FixtureUnsafe, Scratch, ScratchHome, sh_join, ssh_option_path,
};
use heimdall_testkit::hook::{HookBinary, HookMode, exit};
use heimdall_testkit::sshd::pick_loopback_port;
// The process cases need the host's OpenSSH tools (m02-plan §4: Unix rows).
#[cfg(unix)]
use heimdall_testkit::agent::{
    AgentOptions, DisposableSshAgent, KeyConstraints, SignControl, StallPoint,
};
#[cfg(unix)]
use heimdall_testkit::assert_no_canary;
#[cfg(unix)]
use heimdall_testkit::sshd::{AcceptedKey, LoopbackSshd, SshdConfig};

const T: Duration = Duration::from_secs(5);

fn hook() -> HookBinary {
    HookBinary::at(env!("CARGO_BIN_EXE_hm-fixture-hook"))
}

fn fake(scratch: &Scratch, name: &str, mode: AgentMode, keys: &[FixtureKey]) -> FakeAgent {
    FakeAgent::start(
        Endpoint::in_scratch(scratch, name).unwrap(),
        FakeAgentConfig {
            keys: keys.to_vec(),
            mode,
        },
    )
}

fn connect(endpoint: &Endpoint) -> AgentConnection {
    AgentConnection::connect(endpoint, T).unwrap()
}

fn types(log: &[AgentContact]) -> Vec<u8> {
    log.iter().map(|c| c.msg_type).collect()
}

fn blobs(list: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    list.iter().map(|(b, _)| b.clone()).collect()
}

// --- ScratchHome ---------------------------------------------------------------------

#[test]
fn scratch_home_cleans_up() {
    let home = ScratchHome::new();
    let root = home.root.clone();
    for f in [
        &home.user_config,
        &home.known_hosts,
        &home.global_known_hosts,
    ] {
        assert!(f.starts_with(&root));
        assert_eq!(fs::read(f).unwrap(), b"", "created empty");
    }
    for d in [
        &home.ssh_dir,
        &home.config_dir,
        &home.state_dir,
        &home.git_home,
    ] {
        assert!(d.is_dir() && d.starts_with(&root));
    }
    match home.decoy_agent().endpoint() {
        Endpoint::UnixSocket(p) => assert!(p.starts_with(&root)),
        Endpoint::NamedPipe(n) => assert!(is_fixture_pipe_name(n)),
    }

    // Only what was created here goes: material outside, reached through a symlink
    // inside the scratch root, survives the removal.
    let outside = Scratch::new().unwrap();
    fs::write(outside.path().join("keep"), b"outside").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.join("link-out")).unwrap();
    fs::write(root.join("created-by-test"), b"x").unwrap();
    drop(home);
    assert!(!root.exists(), "scratch root removed on drop");
    assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"outside");

    // Fail: a panicking test still removes its scratch home (and stops the decoy).
    let seen: Arc<Mutex<Option<(PathBuf, Endpoint)>>> = Arc::default();
    let inner = Arc::clone(&seen);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let h = ScratchHome::new();
        *inner.lock().unwrap() = Some((h.root.clone(), h.decoy_agent().endpoint().clone()));
        panic!("a test failure inside a fixture");
    }));
    assert!(result.is_err());
    let (root, decoy) = seen.lock().unwrap().clone().unwrap();
    assert!(!root.exists(), "scratch root removed while unwinding");
    assert!(
        AgentConnection::connect(&decoy, T).is_err(),
        "decoy agent stopped"
    );
}

// --- FakeAgent mode semantics -----------------------------------------------------------

#[test]
fn fake_agent_modes_behave_as_documented() {
    let scratch = Scratch::new().unwrap();
    let keys = FixtureKey::generate_many(2);
    let stranger = FixtureKey::generate();

    // Normal: lists its keys in order with their canary comments; signs with them.
    let normal = fake(&scratch, "normal", AgentMode::Normal, &keys);
    let mut c = connect(normal.endpoint());
    let listed = c.list().unwrap();
    assert_eq!(
        blobs(&listed),
        vec![keys[0].public_blob(), keys[1].public_blob()]
    );
    assert_eq!(listed[0].1, keys[0].comment().as_bytes());
    assert!(
        keys[0]
            .comment()
            .starts_with(heimdall_testkit::CANARY_PREFIX)
    );
    let reply = c
        .request(&sign_request(&keys[1].public_blob(), b"data", 0))
        .unwrap();
    let (alg, sig) = parse_sign_response(&reply).unwrap();
    assert_eq!((alg.as_str(), sig.len()), ("ssh-ed25519", 64));
    let reply = c
        .request(&sign_request(&stranger.public_blob(), b"data", 0))
        .unwrap();
    assert_eq!(reply, [msg::FAILURE], "unknown key refused");
    assert_eq!(c.request(&[msg::ADD_IDENTITY]).unwrap(), [msg::FAILURE]);
    assert_eq!(c.request(&[msg::EXTENSION]).unwrap(), [msg::FAILURE]);
    assert_eq!(
        normal.log(),
        vec![
            AgentContact {
                msg_type: msg::REQUEST_IDENTITIES,
                key_fp: None
            },
            AgentContact {
                msg_type: msg::SIGN_REQUEST,
                key_fp: Some(keys[1].fingerprint())
            },
            AgentContact {
                msg_type: msg::SIGN_REQUEST,
                key_fp: Some(stranger.fingerprint())
            },
            AgentContact {
                msg_type: msg::ADD_IDENTITY,
                key_fp: None
            },
            AgentContact {
                msg_type: msg::EXTENSION,
                key_fp: None
            },
        ]
    );
    assert_eq!(normal.connections(), 1);

    // Locked: lists nothing, refuses to sign.
    let locked = fake(&scratch, "locked", AgentMode::Locked, &keys);
    let mut c = connect(locked.endpoint());
    assert!(c.list().unwrap().is_empty());
    assert_eq!(
        c.request(&sign_request(&keys[0].public_blob(), b"d", 0))
            .unwrap(),
        [msg::FAILURE]
    );

    // Deny: lists, refuses to sign.
    let deny = fake(&scratch, "deny", AgentMode::Deny, &keys);
    let mut c = connect(deny.endpoint());
    assert_eq!(c.list().unwrap().len(), 2);
    assert_eq!(
        c.request(&sign_request(&keys[0].public_blob(), b"d", 0))
            .unwrap(),
        [msg::FAILURE]
    );
    assert_eq!(
        types(&deny.log()),
        [msg::REQUEST_IDENTITIES, msg::SIGN_REQUEST]
    );

    // ManyKeys(10): ten generated keys first, then the configured ones; signs with any.
    let many = fake(&scratch, "many", AgentMode::ManyKeys(10), &keys);
    let mut c = connect(many.endpoint());
    let listed = c.list().unwrap();
    assert_eq!(listed.len(), 12);
    assert_eq!(
        blobs(&listed)[10..],
        [keys[0].public_blob(), keys[1].public_blob()]
    );
    let extra = &many.listed_keys()[0];
    assert_eq!(listed[0].0, extra.public_blob());
    let reply = c
        .request(&sign_request(&extra.public_blob(), b"d", 0))
        .unwrap();
    assert!(parse_sign_response(&reply).is_some());

    // ApprovalPending: a signature waits for release_pending, later ones do not.
    let pending = fake(&scratch, "pending", AgentMode::ApprovalPending, &keys);
    let mut c = connect(pending.endpoint());
    assert_eq!(c.list().unwrap().len(), 2, "listing needs no approval");
    let (tx, rx) = mpsc::channel();
    let blob = keys[0].public_blob();
    let worker = std::thread::spawn(move || {
        let r = c.request(&sign_request(&blob, b"d", 0));
        tx.send(r.map(|reply| (reply, c))).unwrap();
    });
    assert!(
        pending.wait_until(T, |a| a.contact_count() == 2),
        "request received"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "held while pending"
    );
    pending.release_pending();
    let (reply, mut c) = rx.recv_timeout(T).unwrap().unwrap();
    worker.join().unwrap();
    assert!(
        parse_sign_response(&reply).is_some(),
        "signed after release"
    );
    let reply = c
        .request(&sign_request(&keys[0].public_blob(), b"d", 0))
        .unwrap();
    assert!(
        parse_sign_response(&reply).is_some(),
        "the release covers later requests"
    );
}

#[cfg(unix)]
#[test]
fn fake_agent_stall_points_hold_the_connection_until_the_peer_closes() {
    use std::os::unix::net::UnixStream;
    let scratch = Scratch::new().unwrap();
    let keys = FixtureKey::generate_many(1);
    for point in [StallPoint::BeforeReply, StallPoint::MidReply] {
        let agent = fake(&scratch, "stall", AgentMode::Stall(point), &keys);
        let Endpoint::UnixSocket(path) = agent.endpoint() else {
            unreachable!()
        };
        let mut s = UnixStream::connect(path).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        s.write_all(&heimdall_testkit::agent::frame(&request_identities()))
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let err = loop {
            match s.read(&mut buf) {
                Ok(0) => panic!("the stalled agent closed the connection"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => break e,
            }
        };
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        match point {
            StallPoint::BeforeReply => assert!(got.is_empty()),
            StallPoint::MidReply => {
                assert_eq!(got.len(), 5, "length and first payload byte only");
                let declared = u32::from_be_bytes([got[0], got[1], got[2], got[3]]);
                assert!(declared > 1);
                assert_eq!(got[4], msg::IDENTITIES_ANSWER);
            }
        }
        assert_eq!(types(&agent.log()), [msg::REQUEST_IDENTITIES]);
        assert_eq!(agent.open_connections(), 1);
        drop(s);
        assert!(
            agent.wait_until(T, |a| a.open_connections() == 0),
            "closed after the peer"
        );
    }
}

#[cfg(unix)]
#[test]
fn fake_agent_signatures_verify_with_ssh_keygen() {
    let scratch = Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let agent = fake(
        &scratch,
        "kg",
        AgentMode::Normal,
        std::slice::from_ref(&key),
    );
    let dir = scratch.subdir("kg").unwrap();
    let public = dir.join("k.pub");
    key.write_public(&public).unwrap();
    fs::write(
        dir.join("allowed"),
        format!("hm-fixture {}\n", key.public_line_without_comment()),
    )
    .unwrap();
    fs::write(dir.join("msg"), b"fixture challenge").unwrap();
    let keygen = |args: &[&OsStr], stdin: &Path, stdout: Option<&Path>| {
        let mut cmd = Command::new("ssh-keygen");
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", scratch.path())
            .env("SSH_AUTH_SOCK", agent.endpoint().locator())
            .stdin(fs::File::open(stdin).unwrap())
            .stderr(Stdio::null());
        match stdout {
            Some(p) => cmd.stdout(fs::File::create(p).unwrap()),
            None => cmd.stdout(Stdio::null()),
        };
        cmd.status().unwrap()
    };
    let sig = dir.join("msg.sig");
    let signed = keygen(
        &[
            "-Y".as_ref(),
            "sign".as_ref(),
            "-n".as_ref(),
            "hm-fixture".as_ref(),
            "-f".as_ref(),
            public.as_os_str(),
        ],
        &dir.join("msg"),
        Some(&sig),
    );
    assert!(signed.success(), "ssh-keygen signed through the FakeAgent");
    let verified = keygen(
        &[
            "-Y".as_ref(),
            "verify".as_ref(),
            "-f".as_ref(),
            dir.join("allowed").as_os_str(),
            "-I".as_ref(),
            "hm-fixture".as_ref(),
            "-n".as_ref(),
            "hm-fixture".as_ref(),
            "-s".as_ref(),
            sig.as_os_str(),
        ],
        &dir.join("msg"),
        None,
    );
    assert!(
        verified.success(),
        "the FakeAgent's Ed25519 signature verifies"
    );
    assert!(types(&agent.log()).contains(&msg::SIGN_REQUEST));
}

// --- CountingProxy -----------------------------------------------------------------------

#[test]
fn counting_proxy_counts_frames() {
    let scratch = Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let upstream = fake(
        &scratch,
        "up",
        AgentMode::Normal,
        std::slice::from_ref(&key),
    );
    let proxy = CountingProxy::start(
        upstream.endpoint(),
        Endpoint::in_scratch(&scratch, "px").unwrap(),
    );

    let direct = connect(upstream.endpoint())
        .request(&request_identities())
        .unwrap();
    let mut c = connect(proxy.endpoint());
    let via = c.request(&request_identities()).unwrap();
    assert_eq!(via, direct, "replies are forwarded unchanged");
    let reply = c
        .request(&sign_request(&key.public_blob(), b"x", 0))
        .unwrap();
    assert!(parse_sign_response(&reply).is_some());
    assert_eq!(c.request(&[msg::LOCK]).unwrap(), [msg::FAILURE]);
    assert_eq!(
        parse_identities_answer(&c.request(&request_identities()).unwrap())
            .unwrap()
            .len(),
        1
    );

    let want = [
        msg::REQUEST_IDENTITIES,
        msg::SIGN_REQUEST,
        msg::LOCK,
        msg::REQUEST_IDENTITIES,
    ];
    assert_eq!(proxy.log(), want);
    assert_eq!(proxy.count(), 4);
    assert_eq!(proxy.connections(), 1);
    // The upstream saw the direct request plus exactly the forwarded ones.
    assert_eq!(types(&upstream.log())[1..], want);
    assert_eq!(
        upstream.log()[2].key_fp.as_deref(),
        Some(key.fingerprint().as_str())
    );
    drop(c);
    let _ = connect(proxy.endpoint());
    assert!(upstream.wait_until(T, |_| proxy.connections() == 2));
    assert_eq!(
        proxy.count(),
        4,
        "a connection that sends nothing forwards nothing"
    );
}

#[cfg(unix)]
#[test]
fn counting_proxy_in_front_of_a_disposable_ssh_agent() {
    let scratch = Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let agent =
        DisposableSshAgent::start_with_hook(&scratch, AgentOptions::default(), &hook()).unwrap();
    agent.add_key(&key, KeyConstraints::default()).unwrap();
    let proxy = CountingProxy::start(
        &agent.endpoint(),
        Endpoint::in_scratch(&scratch, "px").unwrap(),
    );
    let Endpoint::UnixSocket(socket) = proxy.endpoint() else {
        unreachable!()
    };
    let control = agent
        .sign_control_through(socket, &key, b"through the proxy")
        .unwrap();
    assert!(control.signed);
    let log = proxy.log();
    assert!(
        log.contains(&msg::REQUEST_IDENTITIES) && log.contains(&msg::SIGN_REQUEST),
        "{log:?}"
    );
}

// --- loopback only -----------------------------------------------------------------------

#[cfg(unix)]
fn assert_owner_only_socket_in(path: &Path, root: &Path) {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    assert!(path.starts_with(root));
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let parent = fs::metadata(path.parent().unwrap()).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);
}

#[test]
fn nothing_listens_beyond_loopback() {
    let home = ScratchHome::new();
    let agent = fake(home.scratch(), "fa", AgentMode::Normal, &[]);
    let proxy = CountingProxy::start(
        agent.endpoint(),
        Endpoint::in_scratch(home.scratch(), "px").unwrap(),
    );
    for endpoint in [
        home.decoy_agent().endpoint(),
        agent.endpoint(),
        proxy.endpoint(),
    ] {
        match endpoint {
            #[cfg(unix)]
            Endpoint::UnixSocket(p) => assert_owner_only_socket_in(p, &home.root),
            Endpoint::NamedPipe(n) => assert!(is_fixture_pipe_name(n), "local pipe namespace only"),
            #[allow(unreachable_patterns)]
            other => panic!("unexpected endpoint {other:?}"),
        }
    }

    #[cfg(unix)]
    {
        let sshd = LoopbackSshd::start(home.scratch(), SshdConfig::default())
            .unwrap_or_else(|e| panic!("{e}"));
        // The server's own report of what it bound: one address, loopback.
        assert_eq!(sshd.listening(), [format!("127.0.0.1:{}", sshd.port)]);
        assert_eq!(sshd.host, "127.0.0.1");
        // Readiness is detected at LogLevel INFO too.
        let quiet = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                log_level_verbose: false,
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(quiet.listening(), [format!("127.0.0.1:{}", quiet.port)]);
        drop(quiet);
        // The bound sockets as the OS reports them, when lsof is present.
        if let Some(lsof) = heimdall_testkit::home::find_program("lsof") {
            let out = Command::new(lsof)
                .args(["-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-Fn", "-p"])
                .arg(sshd.pid().unwrap().to_string())
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .unwrap();
            let names: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.strip_prefix('n').map(str::to_owned))
                .collect();
            assert_eq!(
                names,
                [format!("127.0.0.1:{}", sshd.port)],
                "lsof listening sockets"
            );
        }
        let mut s = std::net::TcpStream::connect(("127.0.0.1", sshd.port)).unwrap();
        s.set_read_timeout(Some(T)).unwrap();
        let mut banner = [0u8; 8];
        s.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-2.0-");
    }
    let port = pick_loopback_port().unwrap();
    assert!(port > 0);
}

// --- the hook --------------------------------------------------------------------------

fn run_hook(mode: &HookMode, stdin: &[u8]) -> (i32, Vec<u8>) {
    let mut child = hook()
        .command(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap(), out.stdout)
}

#[test]
fn hook_modes_behave_as_documented() {
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("hook").unwrap();

    // The program is found next to the test executable as well.
    if std::env::var_os(HookBinary::ENV_OVERRIDE).is_none() {
        assert!(
            fs::canonicalize(HookBinary::locate().unwrap().path()).unwrap()
                == fs::canonicalize(hook().path()).unwrap(),
            "locate finds the built hook"
        );
    }

    // connect: a ProxyCommand relay to a loopback server (one accept, echoed bytes).
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        s.write_all(&got).unwrap();
        got
    });
    let (code, out) = run_hook(&HookMode::Connect { port }, b"ping\x00\xff\n");
    assert_eq!(code, exit::OK);
    assert_eq!(out, b"ping\x00\xff\n");
    assert_eq!(server.join().unwrap(), b"ping\x00\xff\n");
    let closed = pick_loopback_port().unwrap();
    assert_eq!(
        run_hook(&HookMode::Connect { port: closed }, b"").0,
        exit::FAILED
    );

    // agent-list: one listing, the count on stdout, no comment.
    let agent = fake(
        &scratch,
        "hk",
        AgentMode::Normal,
        &FixtureKey::generate_many(2),
    );
    let (code, out) = run_hook(
        &HookMode::AgentList {
            endpoint: agent.endpoint().clone(),
        },
        b"",
    );
    assert_eq!((code, out.as_slice()), (exit::OK, &b"2\n"[..]));
    assert_eq!(types(&agent.log()), [msg::REQUEST_IDENTITIES]);
    let absent = Endpoint::in_scratch(&scratch, "absent").unwrap();
    assert_eq!(
        run_hook(&HookMode::AgentList { endpoint: absent }, b"").0,
        exit::FAILED
    );

    // touch: one line per run.
    let marker = dir.join("touched");
    assert_eq!(
        run_hook(
            &HookMode::Touch {
                path: marker.clone()
            },
            b""
        )
        .0,
        exit::OK
    );
    assert_eq!(fs::read_to_string(&marker).unwrap(), "ran\n");

    // askpass: approve exits 0, deny exits 1, each logs exactly once.
    let log = dir.join("askpass.log");
    let ask = |answer| HookMode::Askpass {
        log: log.clone(),
        answer,
    };
    assert_eq!(
        run_hook(&ask(AskpassAnswer::Approve), b""),
        (exit::OK, Vec::new())
    );
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1);
    assert_eq!(
        run_hook(&ask(AskpassAnswer::Deny), b""),
        (exit::FAILED, Vec::new())
    );
    assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 2);

    // revert: <path> becomes byte-equal to <original>, then the marker exists.
    let original = dir.join("original");
    let target = dir.join("target");
    let reverted = dir.join("reverted");
    fs::write(&original, b"Host a\r\n\xef\xbb\xbf\x00").unwrap();
    fs::write(&target, b"Match exec inserted\n").unwrap();
    let mode = HookMode::Revert {
        path: target.clone(),
        original: original.clone(),
        marker: reverted.clone(),
    };
    assert_eq!(run_hook(&mode, b"").0, exit::OK);
    assert_eq!(fs::read(&target).unwrap(), fs::read(&original).unwrap());
    assert!(reverted.is_file());

    // Usage errors.
    let usage = Command::new(hook().path())
        .arg("no-such-mode")
        .status()
        .unwrap();
    assert_eq!(usage.code(), Some(exit::USAGE));
    let usage = Command::new(hook().path())
        .args(["touch"])
        .status()
        .unwrap();
    assert_eq!(usage.code(), Some(exit::USAGE));

    // escape: the child leaves the caller's session and records its exact PID.
    let pidfile = dir.join("escape.pid");
    let started = Instant::now();
    assert_eq!(
        run_hook(
            &HookMode::Escape {
                pidfile: pidfile.clone()
            },
            b""
        )
        .0,
        exit::OK
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the caller does not wait for the child"
    );
    let record = fs::read_to_string(&pidfile).unwrap();
    let mut lines = record.lines();
    let pid: i32 = lines.next().unwrap().parse().unwrap();
    let how = lines.next().unwrap().to_owned();
    #[cfg(unix)]
    {
        use rustix::process::{Pid, Signal, getsid, kill_process};
        assert_eq!(how, "setsid");
        let escaped = Pid::from_raw(pid).unwrap();
        assert_eq!(getsid(Some(escaped)).unwrap(), escaped, "a session leader");
        assert_ne!(getsid(None).unwrap(), escaped);
        kill_process(escaped, Signal::KILL).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(how == "breakaway" || how == "in_job", "{how}");
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    // Through a shell, with a path that needs quoting (Match exec runs `sh -c`).
    #[cfg(unix)]
    {
        let odd = dir.join("it's a $(path)");
        let line = hook().shell_command(&HookMode::Touch { path: odd.clone() });
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(&line)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(exit::OK));
        assert_eq!(fs::read_to_string(&odd).unwrap(), "ran\n");
    }
}

// --- DisposableSshAgent and F23 -------------------------------------------------------------

#[cfg(unix)]
#[test]
fn disposable_agent_runs_with_scratch_home() {
    let scratch = Scratch::new().unwrap();
    let log = scratch.path().join("askpass.log");
    let options = AgentOptions {
        askpass_log: Some(log),
        askpass_answer: AskpassAnswer::Approve,
    };
    let launch = DisposableSshAgent::prepare(&scratch, &options, &hook()).unwrap();

    let envs: BTreeMap<OsString, Option<OsString>> = launch
        .command
        .get_envs()
        .map(|(k, v)| (k.to_owned(), v.map(OsStr::to_owned)))
        .collect();
    let keys: Vec<&str> = envs.keys().map(|k| k.to_str().unwrap()).collect();
    assert_eq!(keys, ["HOME", "PATH", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"]);
    assert_eq!(
        envs[OsStr::new("HOME")].as_deref(),
        Some(launch.home.as_os_str())
    );
    assert!(launch.home.starts_with(scratch.path()) && launch.home.is_dir());
    let askpass = launch.askpass.clone().unwrap();
    assert!(askpass.starts_with(scratch.path()));
    assert_eq!(
        envs[OsStr::new("SSH_ASKPASS")].as_deref(),
        Some(askpass.as_os_str())
    );
    assert_eq!(
        envs[OsStr::new("SSH_ASKPASS_REQUIRE")].as_deref(),
        Some(OsStr::new("force"))
    );
    let args: Vec<&OsStr> = launch.command.get_args().collect();
    assert_eq!(
        args,
        [
            OsStr::new("-D"),
            OsStr::new("-a"),
            launch.socket.as_os_str()
        ]
    );
    assert!(launch.socket.starts_with(scratch.path()));

    // Started: the socket is the scratch one; keys go in and the private file leaves.
    let mut agent =
        DisposableSshAgent::start_with_hook(&scratch, AgentOptions::default(), &hook()).unwrap();
    assert!(agent.socket.starts_with(scratch.path()));
    assert!(agent.home().starts_with(scratch.path()));
    let key = FixtureKey::generate();
    agent.add_key(&key, KeyConstraints::default()).unwrap();
    let listed = connect(&agent.endpoint()).list().unwrap();
    assert_eq!(blobs(&listed), [key.public_blob()]);
    let leftovers: Vec<_> = fs::read_dir(agent.socket.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('k'))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no private key file left: {leftovers:?}"
    );
    // A locked native agent lists nothing (ADR-0007 §7 [I]; also U6's case).
    agent.lock().unwrap();
    assert!(connect(&agent.endpoint()).list().unwrap().is_empty());
    agent.unlock().unwrap();
    assert_eq!(connect(&agent.endpoint()).list().unwrap().len(), 1);
    let socket = agent.socket.clone();
    agent.stop();
    assert!(!socket.exists(), "the agent removed its socket on SIGTERM");
}

/// ADR-0007 F23 (M2-R08): the authorized disposable signing control.
#[cfg(unix)]
#[test]
fn f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed() {
    let scratch = Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let challenge = b"hm-fixture F23 challenge";

    // Installation: confirm-constrained, approve; one prompt per signature.
    let constrained = DisposableSshAgent::start_with_hook(
        &scratch,
        AgentOptions {
            askpass_log: Some(scratch.path().join("askpass-constrained.log")),
            askpass_answer: AskpassAnswer::Approve,
        },
        &hook(),
    )
    .unwrap();
    constrained
        .add_key(&key, KeyConstraints { confirm: true })
        .unwrap();
    for _ in 0..3 {
        assert_eq!(
            constrained.sign_control(&key, challenge).unwrap(),
            SignControl {
                signed: true,
                askpass_delta: 1
            }
        );
    }
    constrained.set_askpass_answer(AskpassAnswer::Deny).unwrap();
    assert_eq!(
        constrained.sign_control(&key, challenge).unwrap(),
        SignControl {
            signed: false,
            askpass_delta: 1
        }
    );

    // Negative control: the same key without the constraint never prompts.
    let unconstrained = DisposableSshAgent::start_with_hook(
        &scratch,
        AgentOptions {
            askpass_log: Some(scratch.path().join("askpass-unconstrained.log")),
            askpass_answer: AskpassAnswer::Approve,
        },
        &hook(),
    )
    .unwrap();
    unconstrained
        .add_key(&key, KeyConstraints { confirm: false })
        .unwrap();
    assert_eq!(
        unconstrained.sign_control(&key, challenge).unwrap(),
        SignControl {
            signed: true,
            askpass_delta: 0
        }
    );

    // Not passively visible: both listings carry the same key blobs and count.
    let a = connect(&constrained.endpoint()).list().unwrap();
    let b = connect(&unconstrained.endpoint()).list().unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(blobs(&a), blobs(&b));
}

// --- client commands and the default-identity guard -----------------------------------------

fn config_path(p: &Path) -> String {
    ssh_option_path(p)
}

#[test]
fn client_command_never_adds_selection_options() {
    let home = ScratchHome::new();
    let pubkey = home.ssh_dir.join("id_fixture.pub");
    FixtureKey::generate().write_public(&pubkey).unwrap();
    home.write_user_config(&format!(
        "Host fx\n  IdentityFile {}\n",
        config_path(&pubkey)
    ))
    .unwrap();
    let isolation = home.isolation_args();
    let forbidden = [
        "identityagent",
        "identityfile",
        "identitiesonly",
        "hostname",
        "user",
        "port",
    ];
    let allowed_o = [
        "UserKnownHostsFile=",
        "GlobalKnownHostsFile=",
        "BatchMode=yes",
    ];
    // Failure messages name the option only, never its value (a scratch path can
    // carry the account name on Windows).
    let check = |args: &[OsString]| {
        let mut it = args.iter().map(|a| a.to_string_lossy().into_owned());
        while let Some(a) = it.next() {
            let flag = ["-i", "-l", "-p", "-P", "-J", "-A", "-a", "-I"]
                .into_iter()
                .find(|f| *f == a);
            assert_eq!(flag, None, "selection flag on the command line");
            if a == "-o" {
                let v = it.next().unwrap();
                let key = v.split('=').next().unwrap().to_ascii_lowercase();
                assert!(
                    allowed_o.iter().any(|p| v.starts_with(p)),
                    "-o {key} is not an isolation option"
                );
                assert!(!forbidden.contains(&key.as_str()), "-o {key} selects");
            } else if a == "-F" {
                let named = it.next().unwrap();
                assert!(
                    Path::new(&named) == home.user_config,
                    "-F names the scratch user config"
                );
            }
        }
    };
    check(&isolation);
    assert_eq!(isolation.len(), 8, "-F, three -o options");

    for kind in ClientKind::ALL {
        let cmd = home.client_command(kind, "fx").unwrap();
        let args: Vec<OsString> = cmd.get_args().map(OsStr::to_owned).collect();
        let envs: BTreeMap<OsString, Option<OsString>> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(OsStr::to_owned)))
            .collect();
        let env = |k: &str| envs.get(OsStr::new(k)).cloned().flatten();
        // Values hold scratch paths: compare without printing them.
        assert!(
            env("SSH_AUTH_SOCK") == Some(home.decoy_agent().endpoint().locator()),
            "SSH_AUTH_SOCK is the decoy agent"
        );
        assert!(
            env("HOME") == Some(home.git_home.clone().into_os_string()),
            "HOME is the scratch home"
        );
        assert_eq!(env("GIT_CONFIG_NOSYSTEM").as_deref(), Some(OsStr::new("1")));
        match kind {
            ClientKind::Ssh => {
                let mut want = isolation.clone();
                want.push("fx".into());
                assert!(args == want, "ssh: isolation arguments, then the alias");
            }
            ClientKind::Scp | ClientKind::Sftp => {
                assert!(args == isolation, "{kind:?}: isolation arguments only");
            }
            ClientKind::Git => {
                assert!(args.is_empty());
                let ssh = env("GIT_SSH_COMMAND").unwrap();
                let ssh_program = heimdall_testkit::home::find_program("ssh")
                    .map_or_else(|| OsString::from("ssh"), PathBuf::into_os_string);
                let mut words = vec![ssh_program];
                words.extend(isolation.clone());
                assert!(
                    ssh.to_string_lossy() == sh_join(&words),
                    "GIT_SSH_COMMAND is ssh with the isolation arguments only"
                );
            }
        }
        check(&args);
    }
}

#[test]
fn default_identity_guard_refuses_alias_without_scratch_identities() {
    let home = ScratchHome::new();
    let inside = home.ssh_dir.join("id_fixture.pub");
    FixtureKey::generate().write_public(&inside).unwrap();
    let inside = config_path(&inside);
    let outside_dir = Scratch::new().unwrap();
    let outside = outside_dir.path().join("id_elsewhere.pub");
    FixtureKey::generate().write_public(&outside).unwrap();
    let outside = config_path(&outside);
    let outside_conf = outside_dir.path().join("extra.conf");
    fs::write(&outside_conf, format!("Host fx\n  IdentityFile {inside}\n")).unwrap();

    let cases: Vec<(String, Result<(), FixtureUnsafe>)> = vec![
        // No IdentityFile: ssh would add the account home's defaults.
        (
            "Host fx\n  HostName 127.0.0.1\n".to_owned(),
            Err(FixtureUnsafe::DefaultIdentities),
        ),
        // A home-relative identity.
        (
            "Host fx\n  IdentityFile ~/.ssh/id_ed25519\n".to_owned(),
            Err(FixtureUnsafe::NonScratchIdentity { index: 0 }),
        ),
        // A scratch identity plus one inherited from `Host *` outside scratch.
        (
            format!("Host fx\n  IdentityFile {inside}\nHost *\n  IdentityFile {outside}\n"),
            Err(FixtureUnsafe::NonScratchIdentity { index: 1 }),
        ),
        // Only an identity behind `Match exec`: the list may be empty at run time.
        (
            format!("Match exec \"exit 0\"\n  IdentityFile {inside}\n"),
            Err(FixtureUnsafe::DefaultIdentities),
        ),
        // An agent outside scratch.
        (
            format!("Host fx\n  IdentityFile {inside}\n  IdentityAgent ~/.agent.sock\n"),
            Err(FixtureUnsafe::NonScratchAgent { index: 0 }),
        ),
        // An include the fixture refuses to read (outside scratch).
        (
            format!(
                "Include {}\nHost fx\n  IdentityFile {inside}\n",
                config_path(&outside_conf)
            ),
            Err(FixtureUnsafe::Unreadable),
        ),
        // Control: a scratch identity, the decoy agent by name.
        (
            format!("Host fx\n  IdentityFile {inside}\n  IdentityAgent SSH_AUTH_SOCK\n"),
            Ok(()),
        ),
    ];
    // Failure messages name the case index, not the text (it holds scratch paths).
    for (case, (text, want)) in cases.into_iter().enumerate() {
        home.write_user_config(&text).unwrap();
        assert_eq!(home.check_alias("fx"), want, "case {case}");
        assert_eq!(
            home.client_command(ClientKind::Ssh, "fx").err(),
            want.err(),
            "case {case}"
        );
    }
    assert_eq!(
        home.check_alias("-oProxyCommand=x"),
        Err(FixtureUnsafe::BadAlias)
    );
    assert_eq!(home.check_alias("a b"), Err(FixtureUnsafe::BadAlias));
}

/// Y02 (ADR-0007 §12.16 item 2): the guard evaluates the alias under every invocation
/// (`Shell`, `Exec(None)`, `Exec(Some(sentinel))`, `Subsystem("sftp")`) and every
/// session type a `SessionType` directive in the tree can give, and refuses when any
/// evaluation fails. The first case is the reviewer's reproducer: a scratch identity
/// for the shell and an outside identity behind `Match sessiontype exec`. A second
/// scratch directory stands in for outside material; nothing outside scratch is read.
#[test]
fn default_identity_guard_covers_every_invocation_and_session_type() {
    let home = ScratchHome::new();
    let inside = home.ssh_dir.join("id_fixture.pub");
    FixtureKey::generate().write_public(&inside).unwrap();
    let inside = config_path(&inside);
    let outside_dir = Scratch::new().unwrap();
    let outside = config_path(&outside_dir.path().join("id_elsewhere"));
    let outside_agent = config_path(&outside_dir.path().join("agent.sock"));
    let identity = |index| Err(FixtureUnsafe::NonScratchIdentity { index });
    let agent = Err(FixtureUnsafe::NonScratchAgent { index: 0 });
    let cases: Vec<(&str, String, Result<(), FixtureUnsafe>)> = vec![
        (
            "exec-only identity (reviewer)",
            format!("IdentityFile {inside}\nMatch sessiontype exec\n    IdentityFile {outside}\n"),
            identity(1),
        ),
        (
            "subsystem-only identity",
            format!(
                "IdentityFile {inside}\nMatch sessiontype subsystem\n    IdentityFile {outside}\n"
            ),
            identity(1),
        ),
        (
            "Git remote command identity",
            format!(
                "IdentityFile {inside}\nMatch command \"git-upload-pack*\"\n    IdentityFile {outside}\n"
            ),
            identity(1),
        ),
        (
            "identity selected by the SessionType in force",
            format!(
                "IdentityFile {inside}\nSessionType none\nMatch sessiontype none\n    IdentityFile {outside}\n"
            ),
            identity(1),
        ),
        (
            "identity selected by a SessionType value the tree can give",
            format!(
                "Host other\n    SessionType none\nHost *\n    IdentityFile {inside}\nMatch sessiontype none\n    IdentityFile {outside}\n"
            ),
            identity(1),
        ),
        (
            "exec-only agent",
            format!(
                "IdentityFile {inside}\nMatch sessiontype exec\n    IdentityAgent {outside_agent}\n"
            ),
            agent.clone(),
        ),
        (
            "subsystem-only agent",
            format!(
                "IdentityFile {inside}\nMatch sessiontype subsystem\n    IdentityAgent {outside_agent}\n"
            ),
            agent.clone(),
        ),
        (
            "Git remote command agent",
            format!(
                "IdentityFile {inside}\nMatch command \"git-*\"\n    IdentityAgent {outside_agent}\n"
            ),
            agent.clone(),
        ),
        (
            "agent selected by the SessionType in force",
            format!(
                "IdentityFile {inside}\nSessionType none\nMatch sessiontype none\n    IdentityAgent {outside_agent}\n"
            ),
            agent.clone(),
        ),
        (
            "agent selected by a SessionType value the tree can give",
            format!(
                "Host other\n    SessionType none\nHost *\n    IdentityFile {inside}\nMatch sessiontype none\n    IdentityAgent {outside_agent}\n"
            ),
            agent.clone(),
        ),
        (
            "an agent read from a variable (ADR-0007 §12.16 item 1)",
            format!("IdentityFile {inside}\nIdentityAgent $HM_FIXTURE_OTHER_AGENT\n"),
            agent.clone(),
        ),
        (
            "control: every invocation and session type stays in scratch",
            format!(
                "IdentityFile {inside}\nIdentityAgent SSH_AUTH_SOCK\nHost other\n    SessionType none\n\
                 Match sessiontype exec,subsystem,none\n    IdentityFile {inside}\n"
            ),
            Ok(()),
        ),
    ];
    // Messages name the case, not the text (it holds scratch paths).
    for (name, text, want) in cases {
        home.write_user_config(&text).unwrap();
        assert_eq!(home.check_alias("fx"), want, "{name}");
        for kind in ClientKind::ALL {
            assert_eq!(
                home.client_command(kind, "fx").err(),
                want.clone().err(),
                "{name}: {kind:?}"
            );
        }
    }
    // The invocations the guard covers.
    let invocations = heimdall_testkit::home::guard_invocations();
    assert_eq!(invocations.len(), 4);
}

// --- real logins through the FakeAgent ------------------------------------------------------

#[cfg(unix)]
struct Login {
    home: ScratchHome,
    sshd: LoopbackSshd,
    key: FixtureKey,
}

#[cfg(unix)]
impl Login {
    fn new(max_auth_tries: u32) -> Login {
        let home = ScratchHome::new();
        let key = FixtureKey::generate();
        let sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                authorized: vec![key.public().clone()],
                max_auth_tries,
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        home.trust_host_key(&sshd.host_key_line).unwrap();
        key.write_public(&home.ssh_dir.join("authorized_fixture.pub"))
            .unwrap();
        Login { home, sshd, key }
    }

    fn alias(
        &self,
        name: &str,
        agent: &FakeAgent,
        identity: &Path,
        identities_only: bool,
    ) -> String {
        format!(
            "Host {name}\n  HostName 127.0.0.1\n  Port {}\n  IdentityAgent {}\n  IdentityFile {}\n{}",
            self.sshd.port,
            config_path(Path::new(&agent.endpoint().locator())),
            config_path(identity),
            if identities_only {
                "  IdentitiesOnly yes\n"
            } else {
                ""
            },
        )
    }

    fn ssh(&self, alias: &str) -> Command {
        let mut cmd = self.home.client_command(ClientKind::Ssh, alias).unwrap();
        cmd.arg("echo hm-fixture-login-ok").stdin(Stdio::null());
        cmd
    }
}

#[cfg(unix)]
#[test]
fn fake_agent_round_trip_with_real_ssh_login() {
    let login = Login::new(6);
    let identity = login.home.ssh_dir.join("authorized_fixture.pub");
    let mut text = String::new();
    let mut agents = Vec::new();
    for (name, mode) in [
        ("normal", AgentMode::Normal),
        ("locked", AgentMode::Locked),
        ("deny", AgentMode::Deny),
        ("pending", AgentMode::ApprovalPending),
    ] {
        let agent = fake(
            login.home.scratch(),
            name,
            mode,
            std::slice::from_ref(&login.key),
        );
        text.push_str(&login.alias(name, &agent, &identity, true));
        agents.push(agent);
    }
    login.home.write_user_config(&text).unwrap();

    // Normal: a real login, signed by the FakeAgent.
    let out = login.ssh("normal").output().unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_canary(&all);
    assert!(out.status.success(), "ssh exit {:?}", out.status.code());
    assert_eq!(out.stdout, b"hm-fixture-login-ok\n");
    // ssh may also send extension requests (27), which the FakeAgent refuses.
    let log = agents[0].log();
    assert!(types(&log).contains(&msg::REQUEST_IDENTITIES));
    assert!(log.contains(&AgentContact {
        msg_type: msg::SIGN_REQUEST,
        key_fp: Some(login.key.fingerprint())
    }));
    assert_eq!(
        login.sshd.accepted_log(),
        [AcceptedKey {
            key_type: "ED25519".to_owned(),
            fingerprint: login.key.fingerprint()
        }]
    );

    // Locked and Deny: no login.
    for i in [1, 2] {
        let out = login.ssh(["locked", "deny"][i - 1]).output().unwrap();
        assert_eq!(out.status.code(), Some(255));
        assert!(out.stdout.is_empty());
    }
    assert!(
        types(&agents[1].log())
            .iter()
            .all(|&t| t != msg::SIGN_REQUEST),
        "nothing listed, nothing to sign"
    );
    assert!(
        types(&agents[2].log()).contains(&msg::SIGN_REQUEST),
        "asked, refused"
    );
    assert_eq!(login.sshd.accepted_log().len(), 1);

    // ApprovalPending: the login waits for the release, then completes.
    let mut child = login
        .ssh("pending")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(agents[3].wait_until(Duration::from_secs(10), |a| {
        types(&a.log()).contains(&msg::SIGN_REQUEST)
    }));
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        child.try_wait().unwrap().is_none(),
        "held while approval is pending"
    );
    agents[3].release_pending();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"hm-fixture-login-ok\n");
    assert_eq!(login.sshd.accepted_log().len(), 2);

    // The decoy at SSH_AUTH_SOCK was never contacted (ADR-0007 §9 item 2).
    assert_eq!(login.home.decoy_agent().connections(), 0);
    assert!(login.home.decoy_agent().log().is_empty());
}

#[cfg(unix)]
#[test]
fn many_keys_exhaust_max_auth_tries_without_identities_only() {
    let login = Login::new(3);
    let agent = fake(
        login.home.scratch(),
        "many",
        AgentMode::ManyKeys(10),
        std::slice::from_ref(&login.key),
    );
    let absent = login.home.ssh_dir.join("absent.pub");
    let authorized = login.home.ssh_dir.join("authorized_fixture.pub");
    let text = format!(
        "{}{}",
        login.alias("many", &agent, &absent, false),
        login.alias("only", &agent, &authorized, true)
    );
    login.home.write_user_config(&text).unwrap();

    // Without IdentitiesOnly ssh offers the agent's keys in order; the authorized one
    // is eleventh and the server gives up after three.
    let out = login.ssh("many").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_no_canary(&stderr);
    assert_eq!(out.status.code(), Some(255));
    assert!(
        stderr.contains("Too many authentication failures"),
        "client reports the server's limit"
    );
    assert!(login.sshd.accepted_log().is_empty());
    assert!(
        !agent
            .log()
            .iter()
            .any(|c| c.key_fp.as_deref() == Some(&login.key.fingerprint()))
    );

    // Control: IdentitiesOnly with the authorized public key selects it at once.
    let out = login.ssh("only").output().unwrap();
    assert!(out.status.success());
    assert_eq!(login.sshd.accepted_log().len(), 1);
    assert_eq!(login.home.decoy_agent().connections(), 0);
}

// --- properties (m02-plan §0: 256 cases, fixed seed, `PROPTEST_RNG_SEED` reproduces) ------

mod properties {
    use super::*;
    use heimdall_testkit::agent::identities_answer;
    use heimdall_testkit::home::GuardScope;
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x484d_5537_4649_5854);
        }
        c
    }

    proptest! {
        #![proptest_config(config())]

        /// The identities answer the FakeAgent sends parses back exactly, and no strict
        /// prefix of it parses (a truncated reply is never a shorter listing).
        #[test]
        fn identities_answer_round_trips_and_prefixes_never_parse(
            keys in prop::collection::vec(
                (prop::collection::vec(any::<u8>(), 0..48), "[ -~]{0,24}"),
                0..6,
            )
        ) {
            let payload = identities_answer(&keys);
            let want: Vec<(Vec<u8>, Vec<u8>)> =
                keys.iter().map(|(b, c)| (b.clone(), c.as_bytes().to_vec())).collect();
            prop_assert_eq!(parse_identities_answer(&payload), Some(want));
            for cut in 0..payload.len() {
                prop_assert_eq!(parse_identities_answer(&payload[..cut]), None);
            }
        }

        /// The guard's scratch-path rule: under the root, accepted exactly when no
        /// component is `..` and none carries a `%` or `${` token.
        #[test]
        fn scratch_path_rule(
            parts in prop::collection::vec(
                prop::sample::select(vec!["a", "b c", "..", ".", "%u", "~", "${HOME}", "x$y", "k.pub"]),
                1..6,
            )
        ) {
            let scratch = Scratch::new().unwrap();
            let scope = GuardScope::new(scratch.path()).unwrap();
            let mut path = scratch.path().to_path_buf();
            for p in &parts {
                path.push(p);
            }
            let expected = !parts.iter().any(|p| *p == ".." || p.contains('%') || p.contains("${"));
            prop_assert_eq!(scope.is_scratch_path(path.to_str().unwrap()), expected, "{:?}", parts);
            let outside = std::env::temp_dir().join("hm-never-scratch").join(parts.join("-"));
            prop_assert!(!scope.is_scratch_path(outside.to_str().unwrap()));
        }
    }
}
