import os
from pathlib import Path
import subprocess

base = Path(__file__).parent
src = base / "source"
env = os.environ.copy()
env["CARGO_HOME"] = env.get("CARGO_HOME", str(Path.home() / ".cargo"))
env["RUSTUP_HOME"] = env.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
env.update(HOME=str(base / "home"), HEIMDALL_HOME=str(base / "heimdall-home"),
           HEIMDALL_TEST_SSH_HOME=str(base / "ssh-home"), TMPDIR=str(base / "tmp"),
           CARGO_BUILD_JOBS="4")
env.pop("SSH_AUTH_SOCK", None)
env.pop("CARGO_TARGET_DIR", None)

def probe(label, path, extra, args):
    path = src / path
    original = path.read_text()
    try:
        path.write_text(original + extra)
        log_path = base / (label + ".log")
        with log_path.open("w") as log:
            cp = subprocess.run(["cargo", "test", "--locked", "--offline", *args, "reviewer_"],
                                cwd=src, env=env, stdout=log, stderr=subprocess.STDOUT)
        lines = log_path.read_text().splitlines()
        print(label, cp.returncode, flush=True)
        for line in lines:
            if line.startswith(("test reviewer_", "test e2e_tests::reviewer_", "test result:", "error:","error[")):
                print(line.replace(str(Path.home()), "<home>"), flush=True)
    finally:
        path.write_text(original)

probe("invitation-probes", "tests/model/remote_roles.rs", r"""
struct ReviewerLines<'a> {
    inner: &'a MemoryLines,
    entered: &'a std::sync::Barrier,
    release: &'a std::sync::Barrier,
    pause_read: bool,
}
impl heimdall_remote::line::ManagementLines for ReviewerLines<'_> {
    fn read_all(&self) -> Result<Vec<heimdall_remote::line::KeysFile>, heimdall_remote::line::LineIoError> {
        if self.pause_read {
            self.entered.wait();
            self.release.wait();
        }
        self.inner.read_all()
    }
    fn put(&self, c: &ClientId, line: &str) -> Result<(), heimdall_remote::line::LineIoError> {
        if !self.pause_read {
            self.entered.wait();
            self.release.wait();
        }
        self.inner.put(c, line)
    }
    fn remove(&self, c: &ClientId) -> Result<(), heimdall_remote::line::LineIoError> {
        self.inner.remove(c)
    }
}

#[test]
fn reviewer_concurrent_join_commits_once() {
    let mut w = World::new();
    let inv = w.invite(Role::Owner, 1, ManagementPolicy::OwnerOnly).unwrap();
    let now = w.read();
    let req = w.join_req(&inv);
    let gate = std::sync::Barrier::new(2);
    let join = || {
        gate.wait();
        w.svc().join(&inv.client.client, &req, &now).unwrap()
    };
    let (a,b) = std::thread::scope(|s| {
        let a = s.spawn(join);
        let b = join();
        (a.join().unwrap(),b)
    });
    assert_ne!(a.replayed, b.replayed);
    assert_eq!(a.join, b.join);
}

#[test]
fn reviewer_reconcile_can_write_active_line_after_revocation() {
    let mut w = World::new();
    let inv = w.invite(Role::Owner, 2, ManagementPolicy::OwnerOnly).unwrap();
    let now = w.read();
    let cid = &inv.client.client;
    w.lines.set_fail_writes(true);
    w.svc().join(cid, &w.join_req(&inv), &now).unwrap();
    w.lines.set_fail_writes(false);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let port = ReviewerLines { inner: &w.lines, entered: &entered, release: &release, pause_read: false };
    let service = Invitations { lines: &port, ..w.svc() };
    std::thread::scope(|s| {
        let reconcile = s.spawn(|| service.reconcile(&now).unwrap());
        entered.wait();
        let revoked = w.svc().revoke(cid, w.clock.wall);
        release.wait();
        reconcile.join().unwrap();
        assert!(revoked.unwrap().line_removed);
    });
    assert_eq!(w.client(cid).state, ClientState::Revoked);
    let lines = w.lines_for(cid);
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].contains("expiry-time"));
}

#[test]
fn reviewer_join_uses_time_sample_captured_before_blocking_io() {
    let mut w = World::new();
    let inv = w.invite(Role::Owner, 3, ManagementPolicy::OwnerOnly).unwrap();
    let cid = &inv.client.client;
    w.advance(899);
    let early = w.read();
    let mut clock = w.clock.clone();
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let port = ReviewerLines { inner: &w.lines, entered: &entered, release: &release, pause_read: true };
    let service = Invitations { lines: &port, ..w.svc() };
    let req = w.join_req(&inv);
    std::thread::scope(|s| {
        let join = s.spawn(|| service.join(cid, &req, &early));
        entered.wait();
        clock.wall = plus(clock.wall, 1);
        clock.continuous += Duration::from_secs(1);
        assert_eq!(heimdall_remote::invitations::liveness(&inv.invitation,
            &TimeReading::safe(&clock.anchor())), heimdall_remote::invitations::Liveness::Expired);
        release.wait();
        // The second port read is the post-commit rewrite. The active row proves the stale read won.
        entered.wait();
        let state = w.client(cid).state;
        release.wait();
        assert!(join.join().unwrap().is_ok());
        assert_eq!(state, ClientState::Active);
    });
}
""", ["-p", "heimdall-remote", "--test", "model_remote_roles"])

probe("iroh-server-first", "crates/transport-iroh/src/e2e_tests.rs", r"""
#[tokio::test]
async fn reviewer_server_first_waits_for_client_byte() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        count.fetch_add(1, Ordering::SeqCst);
        stream.write_all(b"SSH-2.0-fixture\r\n").await.unwrap();
        let mut one = [0; 1];
        stream.read_exact(&mut one).await.unwrap();
    });
    let target = Echo { addr, accepted, task };
    let a = client();
    let (server, _authority) = serve(&[&a.id], &[&a.id], &target).await;
    let mut stream = dial_to(&server.target, &a, STEP).await.unwrap();
    let mut banner = [0u8; 17];
    assert!(tokio::time::timeout(Duration::from_millis(250), stream.read_exact(&mut banner)).await.is_err());
    assert_eq!(target.accepted(), 0);
    stream.write_all(b"x").await.unwrap();
    tokio::time::timeout(STEP, stream.read_exact(&mut banner)).await.unwrap().unwrap();
    assert_eq!(&banner, b"SSH-2.0-fixture\r\n");
    let _ = stream.close().await;
    assert_eq!(stop(server).await, ServeExit::Shutdown);
}
""", ["-p", "heimdall-transport-iroh", "--features", "iroh", "--lib"])
