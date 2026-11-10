//! M03-U11 fixture self-tests (m03-plan U11 "Tests"; ADR-0008 D13). Hosted by
//! `heimdall-testkit` as `integration_testkit_m03` (features `fixtures` and `managed`).
//!
//! Disposable fixtures only: every key and CA is generated per run, every path is in a
//! scratch directory this test created, every server binds `127.0.0.1`, every process
//! is stopped by its exact PID or group, and every container a test starts is
//! `--network none`, labelled `heimdall.fixture` and removed by its exact name. Clients
//! get only the isolation arguments (`ScratchHome::client_command`); identities and
//! certificates reach them only through the scratch user configuration. The one test
//! that reads the owner's material (`owner_digest_detects_change`) only digests it.
//!
//! Docker cases are `#[ignore]`d and assert `HM_DOCKER_TESTS=1` first (brief §4): they
//! need the M00-T03 fixtures from a clean `tests/fixtures/ssh/up.sh` (and `down.sh`
//! after), or start their own shell containers. `test_ca_ceremony_captures_passphrase_
//! only_from_pty` is not here: it needs U12's `issuer init` handler.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// The process cases need Unix (FIFOs, process groups, the host's OpenSSH): on Windows
// only the platform-neutral cases run, so the shared helpers are unused there.
#![cfg_attr(not(unix), allow(unused_imports, dead_code))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use heimdall_contract::enrollment::EnrollmentForm;
use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::ca::{TestCa, UserCertSpec};
use heimdall_testkit::home::{ClientKind, Scratch, ScratchHome, ssh_option_path};
use heimdall_testkit::installation::{FIRST_PREFIX, SECOND_PREFIX, SecondInstallation};
use heimdall_testkit::lock::FakeSessionLockSource;
use heimdall_testkit::managed::{ManagedRunContext, contains_secret, seeded_k_env};
use heimdall_testkit::owner_digest::OwnerDigest;
use heimdall_testkit::procstat::{COMM_NAMES, Fixtures};
use heimdall_testkit::registry::{
    FixtureUnsafe, LocalScript, PauseHooks, RegistryGuard, RegistryTarget, hook, pause_snippet,
};
use heimdall_testkit::shells::{Listing, ProbeShim};
use heimdall_testkit::sshd::{
    FaultKind, Faults, LaggingClock, LoopbackSshd, PrincipalsNotEnforced, REMOTE_CLOCK_COMMAND,
    SshdConfig, ThreeHosts, TwoHosts, WrongKey, WrongKeyVariant, current_account,
    negative_principal,
};

const T: Duration = Duration::from_secs(30);

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A scratch user-configuration block for `alias` at `127.0.0.1:<port>`: the scratch
/// key (and certificate), no agent, `IdentitiesOnly yes`, plus `extra` lines.
fn alias_block(
    alias: &str,
    port: u16,
    identity: &Path,
    certificate: Option<&Path>,
    extra: &[String],
) -> String {
    let mut s = format!(
        "Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  IdentityAgent none\n  IdentityFile {}\n  IdentitiesOnly yes\n",
        ssh_option_path(identity)
    );
    if let Some(c) = certificate {
        s.push_str(&format!("  CertificateFile {}\n", ssh_option_path(c)));
    }
    for line in extra {
        s.push_str(&format!("  {line}\n"));
    }
    s
}

/// `ssh <isolation> <alias> <cmd>` (stdin closed), bounded.
fn ssh(home: &ScratchHome, alias: &str, cmd: &str) -> Output {
    let mut c = home.client_command(ClientKind::Ssh, alias).unwrap();
    c.arg(cmd).stdin(Stdio::null());
    output_within(c, T)
}

fn output_within(mut c: Command, timeout: Duration) -> Output {
    let mut child = c
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let o = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let e = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let end = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: o.join().unwrap(),
        stderr: e.join().unwrap(),
    }
}

fn account() -> String {
    current_account().expect("the current account name is readable (`id -un`)")
}

/// A user key and its certificate for `principal` from `ca`, in a fresh scratch subdir.
fn cert_files(
    home: &ScratchHome,
    ca: &TestCa,
    principal: &str,
    key_id: &str,
) -> heimdall_testkit::ca::CertFiles {
    let dir = home.scratch().subdir("id").unwrap();
    let mut spec = UserCertSpec::for_principal(principal);
    spec.key_id = key_id.to_owned();
    ca.issue_files(&FixtureKey::generate(), &spec, &dir, "id")
        .unwrap()
}

/// The system-form server config: `TrustedUserCAKeys` = the CA's scratch file, and
/// the current account's principals.
fn system_config(ca: &TestCa, principals: &[&str]) -> SshdConfig {
    let mut map = BTreeMap::new();
    map.insert(
        account(),
        principals.iter().map(|p| (*p).to_owned()).collect(),
    );
    SshdConfig {
        trusted_user_ca_keys: Some(ca.pub_file().to_path_buf()),
        authorized_principals: Some(map),
        ..SshdConfig::default()
    }
}

fn require_docker() {
    assert_eq!(
        std::env::var("HM_DOCKER_TESTS").as_deref(),
        Ok("1"),
        "a docker test needs HM_DOCKER_TESTS=1 (brief §4); it never passes vacuously"
    );
}

// --- the registry guard -------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn registry_guard_refuses_non_scratch_paths() {
    let scratch = Scratch::new().unwrap();
    let guard = RegistryGuard::new(&scratch).unwrap();
    let inside = scratch.path().join("home/.ssh/authorized_keys");
    assert_eq!(guard.check(&RegistryTarget::Path(&inside)), Ok(()));
    let existing = scratch.subdir("reg").unwrap().join("authorized_keys");
    fs::write(&existing, b"").unwrap();
    assert_eq!(guard.check(&RegistryTarget::Path(&existing)), Ok(()));

    // Outside scratch, relative, `..`, or a symlink out: refused before anything runs.
    let other = Scratch::new().unwrap();
    for (path, want) in [
        (
            other.path().join("authorized_keys"),
            FixtureUnsafe::NotScratch,
        ),
        (
            PathBuf::from("/etc/ssh/authorized_keys"),
            FixtureUnsafe::NotScratch,
        ),
        (
            PathBuf::from(".ssh/authorized_keys"),
            FixtureUnsafe::BadPath,
        ),
        (
            scratch.path().join("../x/authorized_keys"),
            FixtureUnsafe::BadPath,
        ),
    ] {
        assert_eq!(
            guard.check(&RegistryTarget::Path(&path)),
            Err(want),
            "{path:?}"
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        let owner = PathBuf::from(home).join(".ssh/authorized_keys");
        assert_eq!(
            guard.check(&RegistryTarget::Path(&owner)),
            Err(FixtureUnsafe::NotScratch),
            "the owner's registry is never a target"
        );
    }
    let link = scratch.path().join("link-out");
    std::os::unix::fs::symlink(other.path(), &link).unwrap();
    assert_eq!(
        guard.check(&RegistryTarget::Path(&link.join("authorized_keys"))),
        Err(FixtureUnsafe::NotScratch),
        "a symlink out of scratch is refused"
    );

    // Containers: a bad name, an unsafe path, and a container that is not a running,
    // labelled fixture.
    for (name, path, want) in [
        (
            "-rm",
            "/home/enroll/.ssh/authorized_keys",
            FixtureUnsafe::BadContainerName,
        ),
        (
            "hm x",
            "/home/enroll/.ssh/authorized_keys",
            FixtureUnsafe::BadContainerName,
        ),
        ("hm-m00t03-enroll", "home/enroll", FixtureUnsafe::BadPath),
        (
            "hm-m00t03-enroll",
            "/home/../root/x",
            FixtureUnsafe::BadPath,
        ),
        (
            "hm-u11-no-such-container-zz",
            "/home/enroll/.ssh/authorized_keys",
            FixtureUnsafe::ContainerNotFixture,
        ),
    ] {
        assert_eq!(
            guard.check(&RegistryTarget::Container { name, path }),
            Err(want),
            "{name}"
        );
    }

    // WSL: only the run's disposable distribution.
    for distribution in ["Ubuntu", "Ubuntu-24.04", "hm-m03-notregistered"] {
        if std::env::var("WSL_DISTRO_NAME").as_deref() == Ok(distribution)
            || std::env::var("HM_FIXTURE_WSL_DISTRO").as_deref() == Ok(distribution)
        {
            continue;
        }
        assert_eq!(
            guard.check(&RegistryTarget::Wsl {
                distribution,
                path: "/home/u/.ssh/authorized_keys"
            }),
            Err(FixtureUnsafe::WslNotDisposable),
            "{distribution}"
        );
    }
    assert_no_canary(&FixtureUnsafe::NotScratch.to_string());
}

// --- the owner digest ---------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn owner_digest_detects_change() {
    let scratch = Scratch::new().unwrap();
    let root = scratch.path();
    fs::create_dir_all(root.join(".ssh/sub")).unwrap();
    fs::create_dir_all(root.join(".config/git")).unwrap();
    fs::write(root.join(".ssh/config"), b"Host x\n").unwrap();
    fs::write(root.join(".ssh/known_hosts"), b"").unwrap();
    fs::write(root.join(".ssh/sub/f"), b"1").unwrap();
    fs::write(root.join(".gitconfig"), b"[user]\n").unwrap();
    let before = OwnerDigest::capture_tree(root);
    assert!(before.changes().is_empty());
    before.assert_unchanged();
    let shown = format!("{before:?}");
    assert!(
        !shown.contains(&root.to_string_lossy().into_owned()),
        "digests only"
    );
    assert!(!shown.contains("config"), "no file names: {shown}");

    let changed = |f: &dyn Fn()| {
        f();
        let c = before.changes();
        c.iter().map(|d| d.name).collect::<Vec<_>>()
    };
    assert_eq!(
        changed(&|| fs::write(root.join(".ssh/known_hosts"), b"h k\n").unwrap()),
        ["ssh_tree"]
    );
    fs::write(root.join(".ssh/known_hosts"), b"").unwrap();
    assert!(
        before.changes().is_empty(),
        "restored content digests equal"
    );
    assert_eq!(
        changed(&|| fs::write(root.join(".ssh/new"), b"").unwrap()),
        ["ssh_tree"]
    );
    fs::remove_file(root.join(".ssh/new")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            changed(&|| fs::set_permissions(
                root.join(".ssh/config"),
                fs::Permissions::from_mode(0o600)
            )
            .unwrap()),
            ["ssh_tree"]
        );
    }
    assert_eq!(
        changed(&|| fs::write(root.join(".config/git/config"), b"[x]\n").unwrap()),
        ["ssh_tree", "git_global"]
    );
    let panicked = std::panic::catch_unwind(|| before.assert_unchanged());
    let msg = panicked
        .err()
        .and_then(|p| p.downcast_ref::<String>().cloned())
        .unwrap();
    assert!(msg.contains("ssh_tree") && msg.contains("git_global"));
    assert!(!msg.contains(&root.to_string_lossy().into_owned()));

    // The owner's real material: read-only digests, captured twice back to back.
    let owner = OwnerDigest::capture().unwrap();
    let names: Vec<_> = owner.components().iter().map(|c| c.name).collect();
    if cfg!(target_os = "macos") {
        assert_eq!(names, ["ssh_tree", "git_global", "keychain_list"]);
    } else {
        assert_eq!(names, ["ssh_tree", "git_global"]);
    }
    owner.assert_unchanged();
}

// --- certificates through the loopback sshd ------------------------------------------------

#[cfg(unix)]
#[test]
fn loopback_system_form_accepts_test_ca_certificate() {
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    assert!(ca.public_line().starts_with("ssh-ed25519 "));
    assert!(ca.fingerprint().as_str().starts_with("SHA256:"));
    assert_eq!(
        fs::read_to_string(ca.pub_file()).unwrap(),
        format!("{}\n", ca.public_line())
    );
    let principal = format!("hm:hm-fx-sys:{}", account());
    let sshd = LoopbackSshd::start(home.scratch(), system_config(&ca, &[&principal])).unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();
    let good = cert_files(&home, &ca, &principal, "heimdall:env_t:grant_t:7");
    let wrong = cert_files(&home, &ca, "hm:other:x", "hm-fixture-wrong");
    let rogue_ca = TestCa::generate(home.scratch()).unwrap();
    let rogue = cert_files(&home, &rogue_ca, &principal, "hm-fixture-rogue");
    let plain = home.scratch().subdir("plain").unwrap().join("id");
    FixtureKey::generate().write_private(&plain).unwrap();
    home.write_user_config(&format!(
        "{}{}{}{}",
        alias_block(
            "good",
            sshd.port,
            &good.identity,
            Some(&good.certificate),
            &[]
        ),
        alias_block(
            "wrong",
            sshd.port,
            &wrong.identity,
            Some(&wrong.certificate),
            &[]
        ),
        alias_block(
            "rogue",
            sshd.port,
            &rogue.identity,
            Some(&rogue.certificate),
            &[]
        ),
        alias_block("plain", sshd.port, &plain, None, &[]),
    ))
    .unwrap();

    let out = ssh(&home, "good", "echo hm-cert-ok");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, b"hm-cert-ok\n");
    let certs = sshd.accepted_certificates();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].key_id, "heimdall:env_t:grant_t:7");
    assert_eq!(certs[0].serial, 1);
    assert_eq!(certs[0].ca_fingerprint, ca.fingerprint().as_str());
    assert_eq!(certs[0].key_type, "ED25519-CERT");
    for refused in ["wrong", "rogue", "plain"] {
        let out = ssh(&home, refused, "true");
        assert_eq!(out.status.code(), Some(255), "{refused}");
    }
    assert_eq!(sshd.accepted_log().len(), 1, "only the good certificate");
    assert_eq!(home.decoy_agent().connections(), 0);
}

#[cfg(unix)]
#[test]
fn two_hosts_have_distinct_principals() {
    // System form: each host trusts the CA and maps only its own principal.
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    let (a, b) = TwoHosts::start(home.scratch(), EnrollmentForm::System).unwrap();
    assert_ne!(a.destination_id(), b.destination_id());
    let (pa, pb) = (
        a.managed_principal().unwrap(),
        b.managed_principal().unwrap(),
    );
    assert_ne!(pa, pb);
    assert!(pa.starts_with(&format!("hm:{}:", a.destination_id().unwrap())));
    for h in [&a, &b] {
        h.trust_user_ca(ca.public_line()).unwrap();
        home.trust_host_key(&h.host_key_line).unwrap();
        assert_eq!(
            fs::read_to_string(h.principals_path(&account()).unwrap()).unwrap(),
            format!("{}\n", h.managed_principal().unwrap())
        );
    }
    let ca_ = cert_files(&home, &ca, &pa, "kid-a");
    let cb = cert_files(&home, &ca, &pb, "kid-b");
    let mut cfg = String::new();
    for (name, host, c) in [
        ("aa", &a, &ca_),
        ("ab", &b, &ca_),
        ("ba", &a, &cb),
        ("bb", &b, &cb),
    ] {
        cfg.push_str(&alias_block(
            name,
            host.port,
            &c.identity,
            Some(&c.certificate),
            &[],
        ));
    }
    home.write_user_config(&cfg).unwrap();
    for (alias, ok) in [("aa", true), ("ab", false), ("ba", false), ("bb", true)] {
        let out = ssh(&home, alias, "true");
        assert_eq!(out.status.success(), ok, "{alias}: {}", text(&out.stderr));
    }
    assert_eq!(a.accepted_key_ids(), ["kid-a"]);
    assert_eq!(b.accepted_key_ids(), ["kid-b"]);

    // Account form: the explicit registry is seeded like `enrollable`; each host gets
    // a `cert-authority` line for its own principal.
    let home2 = ScratchHome::new();
    let (c, d) = TwoHosts::start(home2.scratch(), EnrollmentForm::Account).unwrap();
    assert_ne!(c.managed_principal(), d.managed_principal());
    let seed = fs::read_to_string(c.registry_path().unwrap()).unwrap();
    assert!(
        seed.contains("cert-authority,principals=\"ops\" "),
        "a foreign CA line"
    );
    assert!(seed.contains("command=\"/bin/echo restricted\""));
    assert!(seed.contains("caf\u{e9}"));
    assert_ne!(
        seed,
        fs::read_to_string(d.registry_path().unwrap()).unwrap(),
        "each seed has its own unrelated keys"
    );
    for h in [&c, &d] {
        h.append_registry_line(&ca.cert_authority_line(&[&h.managed_principal().unwrap()], None))
            .unwrap();
        home2.trust_host_key(&h.host_key_line).unwrap();
    }
    let cc = cert_files(&home2, &ca, &c.managed_principal().unwrap(), "kid-c");
    home2
        .write_user_config(&format!(
            "{}{}",
            alias_block("cc", c.port, &cc.identity, Some(&cc.certificate), &[]),
            alias_block("cd", d.port, &cc.identity, Some(&cc.certificate), &[]),
        ))
        .unwrap();
    assert!(ssh(&home2, "cc", "true").status.success());
    assert_eq!(ssh(&home2, "cd", "true").status.code(), Some(255));
    assert_eq!(c.accepted_key_ids(), ["kid-c"]);
    assert!(d.accepted_key_ids().is_empty());
    assert!(
        fs::read_to_string(c.registry_path().unwrap())
            .unwrap()
            .starts_with(&seed)
    );
}

#[cfg(unix)]
#[test]
fn three_hosts_key_ids_attributed_per_host() {
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    let three = ThreeHosts::start(home.scratch(), EnrollmentForm::System).unwrap();
    let ids: Vec<_> = three
        .hosts
        .iter()
        .map(|h| h.destination_id().unwrap().to_owned())
        .collect();
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    let mut cfg = String::new();
    let mut files = Vec::new();
    for (i, h) in three.hosts.iter().enumerate() {
        h.trust_user_ca(ca.public_line()).unwrap();
        home.trust_host_key(&h.host_key_line).unwrap();
        let kid = format!("heimdall:env_lock:grant_{}:{}", ["c", "r", "n"][i], 100 + i);
        let f = cert_files(&home, &ca, &h.managed_principal().unwrap(), &kid);
        cfg.push_str(&alias_block(
            &format!("h{i}"),
            h.port,
            &f.identity,
            Some(&f.certificate),
            &[],
        ));
        files.push((kid, f));
    }
    // Host 1's certificate offered to host 2: refused (disjoint pairs).
    cfg.push_str(&alias_block(
        "cross",
        three.hosts[1].port,
        &files[0].1.identity,
        Some(&files[0].1.certificate),
        &[],
    ));
    home.write_user_config(&cfg).unwrap();
    for i in 0..3 {
        for _ in 0..2 {
            assert!(ssh(&home, &format!("h{i}"), "true").status.success());
        }
    }
    assert_eq!(ssh(&home, "cross", "true").status.code(), Some(255));
    let per_host = three.accepted_key_ids();
    for (i, (kid, _)) in files.iter().enumerate() {
        assert_eq!(per_host[i], [kid.clone(), kid.clone()], "host {i}");
    }
}

// --- pause hooks ---------------------------------------------------------------------------

/// A local script: an optional background ticker, an armed or unarmed pause point, then
/// a marker file.
fn paused_script(hooks: &PauseHooks, name: &str, marker: &Path, ticks: Option<&Path>) -> String {
    let mut s = String::from("set -u\n");
    if let Some(t) = ticks {
        s.push_str(&format!(
            "( while :; do printf x >> '{}'; sleep 0.05; done ) &\nhm_ticker=$!\n",
            t.display()
        ));
    }
    s.push_str(&pause_snippet(&hooks.dir().to_string_lossy(), name));
    s.push('\n');
    if ticks.is_some() {
        s.push_str("kill \"$hm_ticker\"\n");
    }
    s.push_str(&format!("printf done > '{}'\nexit 0\n", marker.display()));
    s
}

#[cfg(unix)]
#[test]
fn pause_hook_blocks_and_releases() {
    let scratch = Scratch::new().unwrap();
    let hooks = PauseHooks::new(&scratch).unwrap();
    hooks.arm(hook::BEFORE_WRITE).unwrap();
    assert!(hooks.arm(hook::BEFORE_WRITE).is_err(), "armed once");
    let marker = scratch.path().join("written");
    let script = paused_script(&hooks, hook::BEFORE_WRITE, &marker, None);
    let mut run =
        LocalScript::spawn(Path::new("/bin/sh"), script.as_bytes(), &[], scratch.path()).unwrap();
    let reached = hooks.wait_at(hook::BEFORE_WRITE).unwrap();
    assert_eq!(reached.pid, run.pid());
    assert_eq!(
        reached.process_group,
        run.pid(),
        "the script leads its group"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "blocked at the point");
    assert!(!run.has_exited());
    assert!(
        hooks.wait_at_for(hook::BEFORE_WRITE, T).is_err(),
        "already held"
    );
    hooks.release(hook::BEFORE_WRITE).unwrap();
    let done = run.wait(T).unwrap();
    assert_eq!(done.status, Some(0), "{}", text(&done.stderr));
    assert_eq!(fs::read(&marker).unwrap(), b"done");
    assert!(
        hooks.release(hook::BEFORE_WRITE).is_err(),
        "not held any more"
    );

    // An unarmed point is a no-op; a wait on it times out.
    let marker2 = scratch.path().join("written2");
    let script = paused_script(&hooks, hook::AFTER_LOCK, &marker2, None);
    let done = LocalScript::spawn(Path::new("/bin/sh"), script.as_bytes(), &[], scratch.path())
        .unwrap()
        .wait(T)
        .unwrap();
    assert_eq!(done.status, Some(0));
    assert!(marker2.exists());
    let err = hooks
        .wait_at_for(hook::BEFORE_LN, Duration::from_millis(200))
        .unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "an unarmed point has no FIFO"
    );

    // The same point reached twice: each reach is waited for and released.
    let marker3 = scratch.path().join("written3");
    let twice = format!(
        "{p}\n{p}\nprintf done > '{}'\n",
        marker3.display(),
        p = pause_snippet(&hooks.dir().to_string_lossy(), hook::BEFORE_WRITE)
    );
    let run =
        LocalScript::spawn(Path::new("/bin/sh"), twice.as_bytes(), &[], scratch.path()).unwrap();
    for _ in 0..2 {
        hooks.wait_at(hook::BEFORE_WRITE).unwrap();
        hooks.release(hook::BEFORE_WRITE).unwrap();
    }
    assert_eq!(run.wait(T).unwrap().status, Some(0));
    assert!(marker3.exists());
    hooks.disarm(hook::BEFORE_WRITE).unwrap();
    assert!(!hooks.dir().join(hook::BEFORE_WRITE).exists());
}

fn len_of(p: &Path) -> u64 {
    fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn grows(p: &Path) -> bool {
    let before = len_of(p);
    std::thread::sleep(Duration::from_millis(400));
    len_of(p) > before
}

#[cfg(unix)]
#[test]
fn pause_hooks_stop_and_continue_exact_group() {
    let scratch = Scratch::new().unwrap();
    let hooks = PauseHooks::new(&scratch).unwrap();
    hooks.arm(hook::BEFORE_WRITE).unwrap();
    assert!(
        hooks.stop_holder().is_err(),
        "no holder yet: nothing is signalled"
    );
    let (ticks, other_ticks) = (scratch.path().join("ticks"), scratch.path().join("other"));
    let marker = scratch.path().join("done");
    let script = paused_script(&hooks, hook::BEFORE_WRITE, &marker, Some(&ticks));
    let run =
        LocalScript::spawn(Path::new("/bin/sh"), script.as_bytes(), &[], scratch.path()).unwrap();
    // A bystander in its own group keeps running throughout.
    let bystander = format!(
        "while :; do printf x >> '{}'; sleep 0.05; done\n",
        other_ticks.display()
    );
    let other = LocalScript::spawn(
        Path::new("/bin/sh"),
        bystander.as_bytes(),
        &[],
        scratch.path(),
    )
    .unwrap();
    let reached = hooks.wait_at(hook::BEFORE_WRITE).unwrap();
    let holder = hooks.holder().unwrap();
    assert_eq!(Some(holder.pid), run.pid());
    assert_eq!(holder.process_group, holder.pid);
    assert_eq!(reached.process_group, Some(holder.pid));
    assert!(
        grows(&ticks),
        "the holder's ticker runs while paused at the hook"
    );

    hooks.stop_holder().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !grows(&ticks),
        "SIGSTOP of the holder's group stops its ticker"
    );
    assert!(grows(&other_ticks), "another group is untouched");
    let stat = Command::new("ps")
        .args(["-o", "stat=", "-p", &holder.pid.to_string()])
        .output()
        .unwrap();
    assert!(
        text(&stat.stdout).contains('T'),
        "stopped: {}",
        text(&stat.stdout)
    );

    hooks.continue_holder().unwrap();
    assert!(grows(&ticks), "SIGCONT resumes the group");
    hooks.release(hook::BEFORE_WRITE).unwrap();
    assert_eq!(run.wait(T).unwrap().status, Some(0));
    assert_eq!(fs::read(&marker).unwrap(), b"done");
    drop(other);
}

// --- faults -------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn faults_each_produce_the_intended_transport_failure() {
    for kind in FaultKind::ALL {
        let home = ScratchHome::new();
        let key = FixtureKey::generate();
        let identity = home.scratch().subdir("id").unwrap().join("id");
        key.write_private(&identity).unwrap();
        let faults = Faults::start(
            home.scratch(),
            SshdConfig {
                authorized: vec![key.public().clone()],
                ..SshdConfig::default()
            },
            kind,
        )
        .unwrap();
        home.trust_host_key(faults.host_key_line()).unwrap();
        home.write_user_config(&alias_block("f", faults.port(), &identity, None, &[]))
            .unwrap();
        let first = ssh(&home, "f", "echo positive-ok");
        assert!(first.status.success(), "{kind:?}: {}", text(&first.stderr));
        assert_eq!(first.stdout, b"positive-ok\n");
        assert!(faults.applied() || kind == FaultKind::MaxStartupsDuringNegative);
        let second = ssh(&home, "f", "echo negative");
        let err = text(&second.stderr);
        assert_eq!(second.status.code(), Some(255), "{kind:?}: {err}");
        assert!(second.stdout.is_empty());
        assert!(
            !err.contains("Permission denied"),
            "never a refusal: {kind:?}: {err}"
        );
        assert!(faults.applied(), "{kind:?}");
        let expected: &[&str] = match kind {
            FaultKind::StopBetweenAttempts => &["Connection closed", "Connection reset"],
            FaultKind::ClosePortBetweenAttempts => &["Connection refused"],
            FaultKind::MaxStartupsBetweenAttempts | FaultKind::MaxStartupsDuringNegative => {
                &["Connection closed", "Connection reset"]
            }
            FaultKind::ResetAfterVersionExchange => &["Connection reset", "Broken pipe"],
        };
        assert!(expected.iter().any(|e| err.contains(e)), "{kind:?}: {err}");
        if matches!(
            kind,
            FaultKind::MaxStartupsBetweenAttempts | FaultKind::MaxStartupsDuringNegative
        ) {
            // `… past MaxStartups` (9.x) or `… Maxstartups` (10.5).
            let dropped = faults
                .sshd()
                .log_lines_containing("drop connection #")
                .iter()
                .any(|l| l.to_ascii_lowercase().contains("maxstartups"));
            assert!(dropped, "{kind:?}: sshd logged the MaxStartups drop");
        }
        if kind == FaultKind::StopBetweenAttempts {
            assert!(faults.sshd().pid().is_none(), "the sshd was stopped");
        }
        assert_eq!(home.decoy_agent().connections(), 0);
    }
}

// --- the lagging clock ----------------------------------------------------------------------

fn now_secs() -> i64 {
    i64::try_from(heimdall_testkit::ca::unix_now()).unwrap()
}

fn hm1_now(out: &[u8]) -> i64 {
    text(out)
        .lines()
        .find_map(|l| l.strip_prefix("HM1 now="))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no HM1 now= line: {}", text(out)))
}

#[cfg(unix)]
#[test]
fn lagging_clock_fixture_reports_offset_and_changes_no_clock() {
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    let lag = Duration::from_secs(3600);
    let clock = LaggingClock::new(home.scratch(), lag).unwrap();
    let principal = format!("hm:hm-fx-lag:{}", account());
    let sshd = clock
        .start_sshd(home.scratch(), system_config(&ca, &[&principal]))
        .unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();
    // valid now-60 .. now+300 on the real clock: a server reading the lagged clock
    // would find it not yet valid.
    let c = cert_files(&home, &ca, &principal, "hm-fixture-lag");
    home.write_user_config(&alias_block(
        "lag",
        sshd.port,
        &c.identity,
        Some(&c.certificate),
        &[],
    ))
    .unwrap();
    let wall_before = std::time::SystemTime::now();
    let t1 = now_secs();
    let out = ssh(&home, "lag", REMOTE_CLOCK_COMMAND);
    let t2 = now_secs();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let reported = hm1_now(&out.stdout);
    let lag_s = i64::try_from(lag.as_secs()).unwrap();
    assert!(
        reported >= t1 - lag_s - 2 && reported <= t2 - lag_s + 2,
        "reported {reported}, local {t1}..{t2}"
    );
    // The behind-upper bound of ADR-0008 D5 §6.5 item 4 covers the lag.
    let behind_upper = (t2 - reported + 1).max(0);
    assert!(behind_upper >= lag_s && behind_upper <= lag_s + 3);

    // The scripts' reading (`date -u +<format>`) lags too.
    let out = ssh(&home, "lag", "printf 'HM1 now=%s\\n' \"$(date -u +%s)\"");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let scripts = hm1_now(&out.stdout);
    assert!(
        (scripts - (now_secs() - lag_s)).abs() <= 2,
        "date -u lagged: {scripts}"
    );
    // No clock changed: the real awk (absolute path) reports the real time remotely,
    // and the local wall clock moved forward only.
    let real_awk = heimdall_testkit::home::find_program("awk").unwrap();
    let out = ssh(
        &home,
        "lag",
        &format!(
            "'{}' 'BEGIN {{ srand(); print \"HM1 now=\" srand() }}'",
            real_awk.display()
        ),
    );
    assert!(out.status.success());
    let real = hm1_now(&out.stdout);
    assert!((real - now_secs()).abs() <= 2, "remote real clock {real}");
    assert!(std::time::SystemTime::now() >= wall_before);
    assert_eq!(sshd.accepted_key_ids(), ["hm-fixture-lag"; 3]);
    assert!(
        fs::read_to_string(clock.path_dir().join("awk"))
            .unwrap()
            .contains(&format!("lag={}", lag.as_secs()))
    );
}

// --- the session-lock source ----------------------------------------------------------------

#[test]
fn fake_lock_source_pauses_consumer_and_latches() {
    use heimdall_app::ports::{LockState, SessionLockSource};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let src = FakeSessionLockSource::default();
    rt.block_on(async {
        // Not paused: a change wakes the consumer.
        let w = src.changed();
        src.set_state(LockState::Locked);
        tokio::time::timeout(Duration::from_secs(5), w)
            .await
            .unwrap();
        src.set_state(LockState::Unlocked);
        src.acknowledge(src.lock_epoch().epoch);
        // Drain the stored permits.
        let _ = tokio::time::timeout(Duration::from_millis(50), src.changed()).await;
        let _ = tokio::time::timeout(Duration::from_millis(50), src.changed()).await;

        // Paused: lock and unlock wake nobody, but the lock latches.
        src.pause_consumer();
        assert!(src.consumer_paused());
        let w = src.changed();
        src.set_state(LockState::Locked);
        src.set_state(LockState::Unlocked);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), w)
                .await
                .is_err(),
            "no wake-up while the consumer is paused"
        );
        let w = src.changed();
        src.resume_consumer();
        tokio::time::timeout(Duration::from_secs(5), w)
            .await
            .expect("one wake-up on resume");
        assert_eq!(src.state(), LockState::Unlocked);
        let e = src.lock_epoch();
        assert_eq!(e.epoch, 2);
        assert!(e.observed, "the lock while paused is still observed");
        src.acknowledge(e.epoch);
        assert!(!src.lock_epoch().observed);

        // Resuming with nothing changed wakes nobody.
        let _ = tokio::time::timeout(Duration::from_millis(50), src.changed()).await;
        src.pause_consumer();
        src.resume_consumer();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), src.changed())
                .await
                .is_err()
        );
    });
}

// --- the second installation -----------------------------------------------------------------

#[test]
fn second_installation_has_distinct_catalog_and_ids() {
    let scratch = Scratch::new().unwrap();
    let a = SecondInstallation::new(&scratch).unwrap();
    let b = SecondInstallation::new(&scratch).unwrap();
    assert_ne!(a.heimdall_home(), b.heimdall_home());
    for (x, y) in [(&a, &b), (&b, &a)] {
        assert!(!x.heimdall_home().starts_with(y.heimdall_home()));
        assert!(!x.state_dir().starts_with(y.heimdall_home()));
        assert!(x.state_dir().starts_with(x.heimdall_home()));
        assert!(x.runtime_dir().starts_with(x.heimdall_home()));
        assert!(scratch.contains_lexically(x.heimdall_home()));
        assert!(scratch.contains_lexically(x.ssh_home()));
    }
    let ids_a: Vec<_> = (0..50).map(|_| a.destination_id()).collect();
    let ids_b: Vec<_> = (0..50).map(|_| b.destination_id()).collect();
    for id in ids_a.iter().chain(&ids_b) {
        assert!(id.starts_with(SECOND_PREFIX) && !id.starts_with(FIRST_PREFIX));
        heimdall_contract::ids::DestinationId::parse(id).unwrap();
    }
    assert!(ids_a.iter().all(|i| !ids_b.contains(i)));
    let mut all = ids_a.clone();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 50);
    // The first installation's hosts use another prefix.
    #[cfg(unix)]
    {
        let home = ScratchHome::new();
        let (h1, _) = TwoHosts::start(home.scratch(), EnrollmentForm::Account).unwrap();
        assert!(h1.destination_id().unwrap().starts_with(FIRST_PREFIX));
    }
    let env: BTreeMap<_, _> = a.env().into_iter().collect();
    assert_eq!(
        env[&OsString::from("HEIMDALL_HOME")],
        a.heimdall_home().as_os_str()
    );
    assert_eq!(
        env[&OsString::from("HEIMDALL_TEST_SECRET_STORE")],
        "scratch"
    );
    let args = SecondInstallation::destination_add_args(
        "work2",
        &ids_a[0],
        "127.0.0.1",
        2222,
        "acct",
        "idn_x",
    );
    assert_eq!(args[..3], ["destination", "add", "work2"]);
    assert!(args.iter().any(|a| a == ids_a[0].as_str()));
}

// --- wrong-key destinations ------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn wrong_key_fixture_variants_each_present_the_wrong_key() {
    let server = Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let wk = WrongKey::start(
        &server,
        SshdConfig {
            authorized: vec![key.public().clone()],
            ..SshdConfig::default()
        },
    )
    .unwrap();
    assert_ne!(wk.served_host_key_line(), wk.approved_host_key_line());
    let client = |approved_known: bool| {
        let home = ScratchHome::new();
        let id = home.scratch().subdir("id").unwrap().join("id");
        key.write_private(&id).unwrap();
        if approved_known {
            home.trust_host_key(&wk.approved_host_key_line()).unwrap();
        }
        (home, id)
    };
    let run = |home: &ScratchHome, id: &Path, extra: &[String], path: Option<&Path>| {
        home.write_user_config(&alias_block("wk", wk.sshd.port, id, None, extra))
            .unwrap();
        let mut c = home.client_command(ClientKind::Ssh, "wk").unwrap();
        c.arg("echo wrong-key-trusted").stdin(Stdio::null());
        if let Some(p) = path {
            c.env(
                "PATH",
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", p.display()),
            );
        }
        output_within(c, T)
    };

    // Control: the approved key only, or nothing: host key verification fails.
    for approved in [true, false] {
        let (home, id) = client(approved);
        let out = run(&home, &id, &[], None);
        assert_eq!(out.status.code(), Some(255));
        assert!(text(&out.stderr).contains("Host key verification failed"));
    }
    // Each inherited source makes an unpinned client trust the served (wrong) key.
    for variant in WrongKeyVariant::ALL {
        let home = ScratchHome::new();
        let id = home.scratch().subdir("id").unwrap().join("id");
        key.write_private(&id).unwrap();
        let extra = wk.inherit(variant, &home).unwrap();
        let out = run(&home, &id, &extra, None);
        assert!(out.status.success(), "{variant:?}: {}", text(&out.stderr));
        assert_eq!(out.stdout, b"wrong-key-trusted\n", "{variant:?}");
    }
    // Q22: `KnownHostsCommand none` is a keyword: the `none` program on PATH never runs.
    let (home, id) = client(false);
    let out = run(
        &home,
        &id,
        &["KnownHostsCommand none".to_owned()],
        Some(wk.none_program_dir()),
    );
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(wk.none_invocations(), 0, "the none program was never run");
    let direct = Command::new(wk.none_program_dir().join("none"))
        .arg("probe")
        .output()
        .unwrap();
    assert!(direct.status.success());
    assert_eq!(wk.none_invocations(), 1, "the recorder works");
    assert_eq!(text(&direct.stdout).trim(), wk.served_host_key_line());
}

// --- principals_not_enforced --------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn principals_not_enforced_fixture_accepts_both_principals() {
    // Account form: the line listing both principals, written at `nonce_known`.
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    let sshd = LoopbackSshd::start(
        home.scratch(),
        SshdConfig {
            registry_seed: Some(heimdall_testkit::sshd::enrollable_like_seed()),
            ..SshdConfig::default()
        },
    )
    .unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();
    let positive = format!("hm:hm-fx-pne:{}", account());
    let hooks = PauseHooks::new(home.scratch()).unwrap();
    hooks.arm(hook::NONCE_KNOWN).unwrap();
    let nonce = heimdall_testkit::agent::random_hex(16);
    // The verifier's side of the protocol: report the nonce, read the FIFO to EOF.
    let dir = hooks.dir();
    let verifier_nonce = nonce.clone();
    let verifier = std::thread::spawn(move || {
        fs::write(dir.join("nonce_known.nonce"), format!("{verifier_nonce}\n")).unwrap();
        let mut f = fs::File::open(dir.join("nonce_known")).unwrap();
        let mut sink = Vec::new();
        f.read_to_end(&mut sink).unwrap();
    });
    let got = PrincipalsNotEnforced::write_at_nonce_known(
        &hooks,
        sshd.registry_path().unwrap(),
        ca.public_line(),
        &positive,
    )
    .unwrap();
    verifier.join().unwrap();
    assert_eq!(got, nonce);
    let registry = fs::read_to_string(sshd.registry_path().unwrap()).unwrap();
    assert!(registry.ends_with(&format!(
        "{}\n",
        PrincipalsNotEnforced::account_line(ca.public_line(), &positive, &nonce)
    )));
    let neg = cert_files(&home, &ca, &negative_principal(&nonce), "kid-neg");
    let pos = cert_files(&home, &ca, &positive, "kid-pos");
    let other = cert_files(&home, &ca, "hm:hm-fx-other:x", "kid-other");
    home.write_user_config(&format!(
        "{}{}{}",
        alias_block("neg", sshd.port, &neg.identity, Some(&neg.certificate), &[]),
        alias_block("pos", sshd.port, &pos.identity, Some(&pos.certificate), &[]),
        alias_block(
            "other",
            sshd.port,
            &other.identity,
            Some(&other.certificate),
            &[]
        ),
    ))
    .unwrap();
    assert!(
        ssh(&home, "neg", "true").status.success(),
        "the negative is accepted"
    );
    assert!(ssh(&home, "pos", "true").status.success());
    assert_eq!(ssh(&home, "other", "true").status.code(), Some(255));
    assert_eq!(sshd.accepted_key_ids(), ["kid-neg", "kid-pos"]);

    // System form: an AuthorizedPrincipalsCommand echoing the presented principals.
    let home2 = ScratchHome::new();
    let script = PrincipalsNotEnforced::echo_principals_command(home2.scratch()).unwrap();
    let sys = LoopbackSshd::start(
        home2.scratch(),
        SshdConfig {
            trusted_user_ca_keys: Some(ca.pub_file().to_path_buf()),
            authorized_principals_command: Some(script),
            ..SshdConfig::default()
        },
    )
    .unwrap();
    home2.trust_host_key(&sys.host_key_line).unwrap();
    let nonce2 = heimdall_testkit::agent::random_hex(16);
    let n2 = cert_files(&home2, &ca, &negative_principal(&nonce2), "kid-sys-neg");
    let p2 = cert_files(&home2, &ca, &positive, "kid-sys-pos");
    let rogue_ca = TestCa::generate(home2.scratch()).unwrap();
    let r2 = cert_files(&home2, &rogue_ca, &positive, "kid-rogue");
    home2
        .write_user_config(&format!(
            "{}{}{}",
            alias_block("n2", sys.port, &n2.identity, Some(&n2.certificate), &[]),
            alias_block("p2", sys.port, &p2.identity, Some(&p2.certificate), &[]),
            alias_block("r2", sys.port, &r2.identity, Some(&r2.certificate), &[]),
        ))
        .unwrap();
    for alias in ["n2", "p2"] {
        let out = ssh(&home2, alias, "true");
        assert!(out.status.success(), "{alias}: {}", text(&out.stderr));
    }
    assert_eq!(
        ssh(&home2, "r2", "true").status.code(),
        Some(255),
        "the CA still matters"
    );
    assert_eq!(sys.accepted_key_ids(), ["kid-sys-neg", "kid-sys-pos"]);
}

// --- the managed run context ------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn managed_run_context_sets_binding_endpoint() {
    let home = ScratchHome::new();
    let agent = |name: &str| {
        FakeAgent::start(
            Endpoint::in_scratch(home.scratch(), name).unwrap(),
            FakeAgentConfig {
                keys: Vec::new(),
                mode: AgentMode::Normal,
            },
        )
    };
    let (binding, environment) = (agent("bind"), agent("envr"));
    let slot = FixtureKey::generate();
    let ctx = ManagedRunContext::new(
        &home,
        "work",
        binding.endpoint(),
        environment.endpoint(),
        slot.public(),
        None,
    )
    .unwrap();
    assert_eq!(ctx.binding_endpoint(), binding.endpoint().locator());
    assert!(ctx.slot_public().is_file() && ctx.slot_certificate().is_file());
    assert!(home.scratch().contains_lexically(ctx.slot_public()));
    ctx.write_user_config(&home, "Host other\n  HostName 192.0.2.1\n")
        .unwrap();
    let cfg = fs::read_to_string(&home.user_config).unwrap();
    assert!(
        cfg.starts_with(ctx.managed_block()),
        "the managed block comes first"
    );
    assert!(cfg.contains(&*environment.endpoint().locator().to_string_lossy()));
    assert!(!cfg.contains(&*binding.endpoint().locator().to_string_lossy()));

    // A child run in the context sees the binding endpoint at SSH_AUTH_SOCK.
    let mut child = Command::new("/bin/sh");
    child
        .args(["-c", "printf '%s\\n%s\\n' \"$SSH_AUTH_SOCK\" \"$HOME\""])
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    ctx.apply(&mut child);
    let out = child.output().unwrap();
    assert_eq!(
        text(&out.stdout),
        format!(
            "{}\n{}\n",
            binding.endpoint().locator().to_string_lossy(),
            home.git_home.display()
        )
    );
    // The managed files are what ordinary ssh would read for the alias (static `-G`).
    let mut g = home.client_command(ClientKind::Ssh, "work").unwrap();
    g.arg("-G");
    let out = output_within(g, T);
    let effective = text(&out.stdout);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(effective.lines().any(|l| l.starts_with("identityagent ")
        && l.contains(&*environment.endpoint().locator().to_string_lossy())));
    assert!(effective.lines().any(|l| l.starts_with("certificatefile ")
        && l.contains(&*ctx.slot_certificate().to_string_lossy())));
    assert_eq!(binding.connections() + environment.connections(), 0);

    // The seeded K_env, for scanning: deterministic, and found in every encoding.
    let k = seeded_k_env(b"\x00\x11\x22");
    let mut out = b"log: ".to_vec();
    out.extend(
        k.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .bytes(),
    );
    assert!(contains_secret(&out, &k));
    assert!(!contains_secret(b"log: nothing", &k));
}

// --- probe shims ---------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn probe_shims_produce_syntax_error_and_disagreement() {
    let scratch = Scratch::new().unwrap();
    let shim = ProbeShim::local(&scratch).unwrap();
    let probe = b"kill -s 0 -- -$$; printf 'control=%s\\n' \"$?\"\n";
    let real = LocalScript::spawn(Path::new("/bin/sh"), probe, &[], scratch.path())
        .unwrap()
        .wait(T)
        .unwrap();
    assert_eq!(text(&real.stdout), "control=0\n", "{}", text(&real.stderr));
    let shimmed = LocalScript::spawn(Path::new(&shim.shell()), probe, &[], scratch.path())
        .unwrap()
        .wait(T)
        .unwrap();
    assert_eq!(text(&shimmed.stdout), "control=2\n");
    assert!(text(&shimmed.stderr).contains("Illegal number"));
    // The shim keeps `$$` and leaves other kill forms alone.
    let other = LocalScript::spawn(
        Path::new(&shim.shell()),
        b"kill -s 0 $$; printf 'k=%s\\n' \"$?\"; printf 'pid=%s\\n' \"$$\"\n",
        &[],
        scratch.path(),
    )
    .unwrap();
    let pid = other.pid().unwrap();
    let other = other.wait(T).unwrap();
    assert_eq!(text(&other.stdout), format!("k=0\npid={pid}\n"));

    // The listing shim: hide the shell's own group, add a foreign one, or pass through.
    let path = vec![(OsString::from("PATH"), OsString::from(shim.path_env()))];
    let listing = |l: Listing| {
        shim.set_listing(l).unwrap();
        let run = LocalScript::spawn(
            Path::new("/bin/sh"),
            b"printf 'own=%s\\n' \"$$\"; ps -A -o pgid=\n",
            &path,
            scratch.path(),
        )
        .unwrap()
        .wait(T)
        .unwrap();
        assert_eq!(run.status, Some(0));
        let out = text(&run.stdout);
        let own = out
            .lines()
            .next()
            .unwrap()
            .trim_start_matches("own=")
            .to_owned();
        let groups: Vec<String> = out.lines().skip(1).map(|l| l.trim().to_owned()).collect();
        (own, groups)
    };
    let (own, groups) = listing(Listing::PassThrough);
    assert!(
        groups.contains(&own),
        "the real listing has the shell's group"
    );
    let (_, groups) = listing(Listing::Add(424_242));
    assert!(
        groups.iter().any(|g| g == "424242"),
        "an added group is listed"
    );
    // Hide: list the hidden group from a long-running bystander group.
    let bystander = LocalScript::spawn(
        Path::new("/bin/sh"),
        b"while :; do sleep 1; done\n",
        &[],
        scratch.path(),
    )
    .unwrap();
    let gone = bystander.pid().unwrap();
    let (_, groups) = listing(Listing::PassThrough);
    assert!(
        groups.contains(&gone.to_string()),
        "the bystander group is listed"
    );
    let (_, groups) = listing(Listing::Hide(gone));
    assert!(
        !groups.contains(&gone.to_string()),
        "a hidden live group disagrees"
    );
    drop(bystander);
}

// --- procstat fixtures -------------------------------------------------------------------------

#[test]
fn procstat_fixtures_cover_spaces_parentheses_and_newline() {
    use heimdall_domain::procstat::{ProcStatError, parse};
    let all = Fixtures::synthetic();
    let comms: Vec<&[u8]> = COMM_NAMES.to_vec();
    for want in [
        &b"plain"[..],
        b"has space",
        b"a ) b ( c",
        b")(",
        b"new\nline",
    ] {
        assert!(comms.contains(&want), "{want:?}");
        assert!(
            all.iter().any(|f| f.expected.is_ok()
                && f.text.windows(want.len() + 2).any(|w| {
                    w[0] == b'(' && &w[1..=want.len()] == want && w[want.len() + 1] == b')'
                })),
            "a valid synthetic line has comm {want:?}"
        );
    }
    assert!(comms.iter().any(|c| c.len() == 15));
    for f in &all {
        assert_eq!(parse(&f.text), f.expected, "{}", f.label);
        assert!(f.text.ends_with(b"\n"));
    }
    let rejections: Vec<_> = all.iter().filter_map(|f| f.expected.err()).collect();
    for want in [
        ProcStatError::NoCloseParen,
        ProcStatError::TooFewFields { found: 5 },
        ProcStatError::BadProcessGroup,
        ProcStatError::BadStartTime,
    ] {
        assert!(rejections.contains(&want), "{want:?}");
    }
    assert!(
        all.iter()
            .filter(|f| f.label.starts_with("malformed:process_group"))
            .any(|f| f.label.ends_with("zero"))
    );
    // Wave 0's committed set reads the same way (U0b row 28).
    let committed = Fixtures::committed().unwrap();
    assert!(committed.len() >= 17);
    for c in &committed {
        let got = parse(&c.text).map_err(|e| heimdall_testkit::procstat::error_code(&e).to_owned());
        assert_eq!(got, c.expected, "{}", c.file);
    }
    // A whitespace field count reads the wrong token once comm holds whitespace.
    for f in all.iter().filter(|f| {
        f.expected.is_ok()
            && ["has space", "a ) b ( c", "new\\nline"]
                .iter()
                .any(|c| f.label == format!("comm:{c}"))
    }) {
        let truth = f.expected.unwrap().process_group.to_string();
        assert_ne!(
            Fixtures::naive_field5(&f.text).as_deref(),
            Some(truth.as_str()),
            "{}",
            f.label
        );
    }
}

// --- Docker (M00-T03 fixtures and the shell containers) ------------------------------------------

/// `tests/fixtures/ssh/runtime/<rel>` of a running `up.sh`.
fn fixture_runtime(rel: &str) -> PathBuf {
    heimdall_testkit::repo::repo_path("tests/fixtures/ssh/runtime").join(rel)
}

fn fixture_port(role: &str) -> u16 {
    let ports = fs::read_to_string(fixture_runtime("ports.env")).expect("up.sh has run");
    ports
        .lines()
        .find_map(|l| l.strip_prefix(&format!("PORT_{role}=")))
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("no port for {role}"))
}

/// The fixture's `<alias> <key>` known-hosts line for `alias`, as a scratch line.
fn fixture_known_host(alias: &str) -> String {
    let kh = fs::read_to_string(fixture_runtime("known_hosts")).unwrap();
    kh.lines()
        .find(|l| l.split_whitespace().next() == Some(alias))
        .unwrap_or_else(|| panic!("no known host {alias}"))
        .to_owned()
}

fn docker(args: &[&str]) -> Output {
    let docker = heimdall_testkit::home::find_program("docker").expect("docker");
    output_within(
        {
            let mut c = Command::new(docker);
            c.args(args).stdin(Stdio::null());
            c
        },
        Duration::from_secs(120),
    )
}

#[cfg(unix)]
#[test]
#[ignore = "docker: the M00-T03 fixtures after a clean up.sh; run with HM_DOCKER_TESTS=1 cargo test -p heimdall-testkit --features fixtures,managed --test integration_testkit_m03 -- --ignored docker_enrollable2_seeded_like_enrollable"]
fn docker_enrollable2_seeded_like_enrollable() {
    require_docker();
    let seed1 = fs::read(fixture_runtime("seed/enroll_authorized_keys")).unwrap();
    let seed2 = fs::read(fixture_runtime("seed/enroll2_authorized_keys")).unwrap();
    assert_ne!(seed1, seed2, "its own keys");
    // The same shape: every line of one has the same kind (comment, options, CA, key)
    // as the other's; only the keys and comments' run IDs differ.
    let shape = |s: &[u8]| -> Vec<String> {
        text(s)
            .lines()
            .map(|l| {
                if l.starts_with('#') {
                    l.to_owned()
                } else if l.is_empty() {
                    String::new()
                } else if l.starts_with("ssh-ed25519 ") {
                    "KEY".to_owned()
                } else {
                    l.split(" ssh-ed25519 ").next().unwrap_or("").to_owned()
                }
            })
            .collect()
    };
    assert_eq!(shape(&seed1), shape(&seed2));
    assert!(text(&seed2).contains("cert-authority,principals=\"ops\" ssh-ed25519 "));

    // Log in through a scratch configuration with the fixture's working-path key copy.
    let home = ScratchHome::new();
    let id = home.scratch().subdir("id").unwrap().join("user_enroll2");
    fs::copy(fixture_runtime("keys/user_enroll2"), &id).unwrap();
    home.trust_host_key(&fixture_known_host("hm-enroll2"))
        .unwrap();
    home.write_user_config(&alias_block(
        "e2",
        fixture_port("enroll2"),
        &id,
        None,
        &[
            "User enroll".to_owned(),
            "HostKeyAlias hm-enroll2".to_owned(),
        ],
    ))
    .unwrap();
    let out = ssh(&home, "e2", "cat ~/.ssh/authorized_keys");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, seed2, "the registry is the seed, byte for byte");
    let sha = fs::read_to_string(fixture_runtime("seed/enroll2_authorized_keys.sha256")).unwrap();
    assert_eq!(sha.trim().len(), 64);
    // The account cannot read the sshd log: sshd logs to the container's stderr only.
    let out = ssh(
        &home,
        "e2",
        "id -un; ls /proc/1/fd >/dev/null 2>&1 && echo fd-readable || echo fd-denied; \
         grep -rls 'Accepted publickey' /var/log 2>/dev/null | head -1; echo end",
    );
    assert!(out.status.success());
    assert_eq!(text(&out.stdout), "enroll\nfd-denied\nend\n");
    let logs = docker(&["logs", "hm-m00t03-enroll2"]);
    assert!(text(&logs.stderr).contains("Accepted publickey for enroll"));
    // Live comm processes on the Docker Debian target (dash), as the account.
    let live = heimdall_testkit::procstat::LiveComm::spawn_in_container(
        "hm-m00t03-enroll2",
        Some("enroll"),
    )
    .unwrap();
    for p in live.procs() {
        let stat = heimdall_domain::procstat::parse(live.read_stat(p.pid).unwrap()).unwrap();
        assert_eq!(
            stat.process_group, p.expected_process_group,
            "{:?}",
            p.requested
        );
        assert_eq!(stat.start_time, p.expected_start_time, "{:?}", p.requested);
    }
}

#[cfg(unix)]
#[test]
#[ignore = "docker: the M00-T03 ca1/ca2 fixtures after a clean up.sh; run with HM_DOCKER_TESTS=1 cargo test -p heimdall-testkit --features fixtures,managed --test integration_testkit_m03 -- --ignored docker_ca_hook_is_container_internal_only"]
fn docker_ca_hook_is_container_internal_only() {
    require_docker();
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    let runtime_before: Vec<PathBuf> = walk(&fixture_runtime(""));
    let ca_file_before = docker(&["exec", "hm-m00t03-ca1", "cat", "/etc/ssh/user_ca.pub"]);
    let up = heimdall_testkit::repo::repo_path("tests/fixtures/ssh/up.sh");
    let hook = |pub_file: &Path| {
        output_within(
            {
                let mut c = Command::new("/bin/bash");
                c.arg(&up)
                    .arg("ca-trust-test-ca")
                    .arg(pub_file)
                    .stdin(Stdio::null());
                c
            },
            Duration::from_secs(120),
        )
    };
    // A malformed line is refused and changes nothing.
    let bad = home.scratch().path().join("bad.pub");
    fs::write(&bad, "cert-authority ssh-ed25519 AAAA x\n").unwrap();
    let out = hook(&bad);
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(
        docker(&["exec", "hm-m00t03-ca1", "cat", "/etc/ssh/user_ca.pub"]).stdout,
        ca_file_before.stdout
    );
    let out = hook(ca.pub_file());
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    for c in ["hm-m00t03-ca1", "hm-m00t03-ca2"] {
        let trusted = docker(&["exec", c, "cat", "/etc/ssh/user_ca.pub"]);
        assert!(
            text(&trusted.stdout).lines().any(|l| l == ca.public_line()),
            "{c}"
        );
    }
    for c in ["hm-m00t03-fixed", "hm-m00t03-enroll", "hm-m00t03-enroll2"] {
        let out = docker(&[
            "exec",
            c,
            "sh",
            "-c",
            "cat /etc/ssh/user_ca.pub 2>/dev/null; true",
        ]);
        assert!(
            !text(&out.stdout).contains(ca.public_line()),
            "{c} untouched"
        );
    }
    // Nothing was written on the host: the runtime tree is unchanged and holds no copy.
    let runtime_after = walk(&fixture_runtime(""));
    assert_eq!(runtime_before, runtime_after);
    for f in &runtime_after {
        if let Ok(t) = fs::read_to_string(f) {
            assert!(
                !t.contains(ca.public_line()),
                "the CA line is not on the host"
            );
        }
    }
    // The run's CA now authenticates on each host with that host's principal only.
    let mut cfg = String::new();
    for (alias, role, hka, principal) in [
        ("c1", "ca1", "hm-ca1", "p-host1"),
        ("c2", "ca2", "hm-ca2", "p-host2"),
        ("x1", "ca1", "hm-ca1", "p-host2"),
    ] {
        let f = cert_files(&home, &ca, principal, &format!("kid-{alias}"));
        cfg.push_str(&alias_block(
            alias,
            fixture_port(role),
            &f.identity,
            Some(&f.certificate),
            &["User cert".to_owned(), format!("HostKeyAlias {hka}")],
        ));
    }
    home.trust_host_key(&fixture_known_host("hm-ca1")).unwrap();
    home.trust_host_key(&fixture_known_host("hm-ca2")).unwrap();
    home.write_user_config(&cfg).unwrap();
    for (alias, ok) in [("c1", true), ("c2", true), ("x1", false)] {
        let out = ssh(&home, alias, "true");
        assert_eq!(out.status.success(), ok, "{alias}: {}", text(&out.stderr));
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[cfg(unix)]
#[test]
#[ignore = "docker: disposable shell containers (pinned debian and alpine); run with HM_DOCKER_TESTS=1 cargo test -p heimdall-testkit --features fixtures,managed --test integration_testkit_m03 -- --ignored shell_containers_run_each_shell_as_group_leader"]
fn shell_containers_run_each_shell_as_group_leader() {
    use heimdall_testkit::shells::{ShellContainers, ShellKind};
    require_docker();
    let shells = ShellContainers::start().unwrap();
    let mut names = Vec::new();
    for c in shells.each() {
        names.push(c.name().to_owned());
        // The script's shell leads its own session and group, and its exit status is kept.
        let run = c
            .run_script(
                b"printf 'pid=%s\\n' \"$$\"; awk '{ print \"pgrp=\" $5; print \"sid=\" $6 }' /proc/$$/stat; \
                  ls /sys/class/net; exit 7\n",
                &[],
                T,
            )
            .unwrap();
        assert_eq!(run.status, Some(7), "{}", text(&run.stderr));
        let out = text(&run.stdout);
        let field = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .unwrap()
                .to_owned()
        };
        assert_eq!(field("pid"), field("pgrp"), "{}", c.name());
        assert_eq!(field("pid"), field("sid"), "{}", c.name());
        assert!(out.lines().any(|l| l == "lo"), "loopback only");
        assert!(!out.lines().any(|l| l.starts_with("eth")), "no network");
        // Which shell runs as /bin/sh.
        let id = c
            .run_script(
                b"echo \"bash=${BASH_VERSION:-none}\"; ls -l /bin/sh\n",
                &[],
                T,
            )
            .unwrap();
        let id = text(&id.stdout);
        match c.kind() {
            ShellKind::BashAsSh => {
                assert!(id.contains("bash=5.2"), "{id}");
                assert!(id.contains("-> bash"));
            }
            ShellKind::BusyBoxAsh => {
                assert!(id.contains("bash=none"));
                assert!(id.contains("busybox"));
            }
        }
        let labels = docker(&[
            "inspect",
            "--format",
            "{{index .Config.Labels \"heimdall.fixture\"}} {{.HostConfig.NetworkMode}}",
            c.name(),
        ]);
        assert_eq!(text(&labels.stdout).trim(), "m03-shells none");
        // Live comm processes: the shared parser reads the right group and start time.
        let live =
            heimdall_testkit::procstat::LiveComm::spawn_in_container(c.name(), None).unwrap();
        for p in live.procs() {
            let stat = heimdall_domain::procstat::parse(live.read_stat(p.pid).unwrap()).unwrap();
            assert_eq!(
                stat.process_group, p.expected_process_group,
                "{:?}",
                p.requested
            );
            assert_eq!(stat.start_time, p.expected_start_time, "{:?}", p.requested);
        }
        // A paused script inside the container: the hooks hold it, stop its group,
        // continue it and release it.
        let hooks = c.pause_hooks("/tmp/hm-pause").unwrap();
        hooks.arm(hook::BEFORE_WRITE).unwrap();
        let script = format!(
            "{}\necho after\n",
            pause_snippet("/tmp/hm-pause", hook::BEFORE_WRITE)
        );
        let bg = c.spawn_script(script.as_bytes(), &[], None).unwrap();
        let reached = hooks.wait_at(hook::BEFORE_WRITE).unwrap();
        assert_eq!(reached.process_group, reached.pid, "{}", c.name());
        hooks.stop_holder().unwrap();
        let st = c
            .exec(&["cat", &format!("/proc/{}/stat", reached.pid.unwrap())], T)
            .unwrap();
        assert_eq!(
            heimdall_domain::procstat::parse(&st.stdout).unwrap().state,
            'T'
        );
        hooks.continue_holder().unwrap();
        hooks.release(hook::BEFORE_WRITE).unwrap();
        let done = bg.wait(T).unwrap();
        assert_eq!(done.status, Some(0));
        assert_eq!(text(&done.stdout), "after\n");
        // Every prefix of a small script, run in-container.
        let runs = c
            .run_prefixes(b"hm_main() { echo ran; }\nhm_main\n", &[], T)
            .unwrap();
        // 32 bytes: cut points 0..=32. Only the whole script and the whole script
        // without its final newline run it.
        assert_eq!(runs.len(), 33);
        assert!(
            runs[..31].iter().all(|r| r.stdout.is_empty()),
            "no shorter prefix runs it"
        );
        assert_eq!(runs[31].stdout, b"ran\n");
        assert_eq!(runs[32].stdout, b"ran\n");
        // The probe shims inside the container.
        let shim = ProbeShim::in_container(c, "/tmp/hm-shim").unwrap();
        let probe = c
            .exec(
                &[
                    "/bin/sh",
                    "-c",
                    &format!(
                        "printf 'kill -s 0 -- -$$; echo c=$?\\n' | {} -s",
                        shim.shell()
                    ),
                ],
                T,
            )
            .unwrap();
        assert!(
            text(&probe.stdout).contains("c=2"),
            "{}",
            text(&probe.stdout)
        );
    }
    drop(shells);
    for n in names {
        let ps = docker(&[
            "ps",
            "-a",
            "--filter",
            &format!("name=^{n}$"),
            "--format",
            "{{.Names}}",
        ]);
        assert!(
            text(&ps.stdout).trim().is_empty(),
            "{n} removed by exact name"
        );
    }
}
