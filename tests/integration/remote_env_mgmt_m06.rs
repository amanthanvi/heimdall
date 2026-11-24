//! ⟨M06 U2⟩ The controller's management leg against a loopback fixture sshd (m06-plan U2
//! "Tests"; ADR-0012 §3.3, §3.4, §5.2). Real `ssh`, disposable fixtures only:
//!
//! * `isolated_config_is_effective_at_every_hop`: `ssh -G -F <rendered>` reads back every
//!   ADR-0012 §5.2 setting of the rendered isolated configuration for the runner hop and the
//!   jump hop (the golden is `heimdall_sshconf::mgmt`'s; this is the effective half).
//! * `k_mgmt_authenticates_only_through_its_session_agent`: a per-session K_mgmt agent and
//!   the rendered configuration log in to a fixture sshd that authorizes K_mgmt; the same
//!   configuration with another pinned key is refused at host-key verification. (The runner
//!   side, `heimdall remote serve` behind the forced command, is not served in this wave: the
//!   fixture's session runs `true`, never the bridge.)
//! * `bootstrap_refuses_an_unverified_host_key_and_never_scans`: the bootstrap adapter's
//!   host-key preflight against the fixture sshd refuses a key that is not pinned
//!   (`HOST_TRUST_CHANGED`, `enrollment_host_key_mismatch`) and starts no session; with the
//!   pinned key it passes. The `ssh` client is a logging wrapper: every program the adapter
//!   ran is that client, and no invocation scans or accepts a key.
//!
//! **Isolation (AGENTS.md, RULES.md).** `SSH_AUTH_SOCK` is removed from every child; every
//! `ssh` reads only a scratch `-F` file, with `IdentitiesOnly yes`, the named fixture agent
//! (the subject) or no agent, `CertificateFile none`, a scratch known-hosts file, no global
//! known-hosts file and no multiplexing. The fixture sshd is unprivileged, listens on
//! 127.0.0.1 only, and has per-run host keys. Fixture keys are generated per run. Where no
//! sshd can start, each case reports `blocked` with the reason and passes vacuously.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use heimdall_app::remote_env::ssh::BootstrapSsh;
use heimdall_app::remote_env::{
    BootstrapPlan, BootstrapRunner as _, ManagementHop, ManagementRoute, MgmtKeyInfo,
    VerifiedAccess,
};
use heimdall_contract::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{AccountName, ClientId, DestinationId};
use heimdall_credential::mgmt::{MgmtKey, MgmtSigner, SessionAgent};
use heimdall_sshconf::mgmt::{
    HopIdentity, MgmtHop, MgmtJump, MgmtTarget, PinnedKey, render_mgmt_config, render_mgmt_pin_file,
};
use heimdall_sshconf::render::{HostName, PathStyle, RenderPath};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::{Scratch, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};

fn ssh() -> PathBuf {
    find_program("ssh").expect("an OpenSSH client")
}

fn rpath(p: &Path) -> RenderPath {
    RenderPath::absolute(p, PathStyle::Unix).unwrap()
}

/// `<type> <base64>` of the fixture's `[127.0.0.1]:<port> <type> <base64>` known-hosts line.
fn host_key(sshd: &LoopbackSshd) -> String {
    let mut words = sshd.host_key_line.split_ascii_whitespace().skip(1);
    format!("{} {}", words.next().unwrap(), words.next().unwrap())
}

fn other_key() -> String {
    let line = MgmtKey::generate().unwrap().public().unwrap().openssh_line;
    line.rsplit_once(' ').unwrap().0.to_owned()
}

/// Run an isolated fixture `ssh` (no agent in the environment; the scratch `-F` file).
fn run_ssh(args: &[&std::ffi::OsStr]) -> Output {
    let out = Command::new(ssh())
        .args(args)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_no_canary(&String::from_utf8_lossy(&out.stdout));
    assert_no_canary(&String::from_utf8_lossy(&out.stderr));
    out
}

fn start_sshd(scratch: &Scratch, config: SshdConfig) -> Option<LoopbackSshd> {
    match LoopbackSshd::start(scratch, config) {
        Ok(s) => Some(s),
        Err(e) => {
            #[allow(clippy::print_stderr)] // the blocked row's reason
            {
                eprintln!("m06 controller: blocked (no fixture sshd: {e})");
            }
            None
        }
    }
}

struct Rendered {
    config: PathBuf,
    target: MgmtTarget,
}

/// Render and write the isolated configuration, its pins and the K_mgmt public key file
/// into `dir`, the runner hop at the fixture with `pin` pinned.
fn render(
    dir: &Path,
    sshd: &LoopbackSshd,
    account: &str,
    pin: &str,
    public_line: &str,
    jump: bool,
) -> Rendered {
    let pub_file = dir.join("k_mgmt.pub");
    std::fs::write(&pub_file, format!("{public_line}\n")).unwrap();
    let identity = HopIdentity::new(rpath(&dir.join("a.sock")), rpath(&pub_file)).unwrap();
    let hop = |pin: &str| MgmtHop {
        hostname: HostName::parse(&sshd.host).unwrap(),
        port: Some(sshd.port),
        user: account.to_owned(),
        pins: vec![PinnedKey::parse(pin).unwrap()],
        identity: identity.clone(),
    };
    let target = MgmtTarget {
        environment: "env_fixture".into(),
        hop: hop(pin),
        jump: jump.then(|| MgmtJump {
            destination: "bastion".into(),
            hop: hop(pin),
        }),
    };
    let pins = dir.join("known_hosts");
    std::fs::write(&pins, render_mgmt_pin_file(&target).unwrap()).unwrap();
    let config = dir.join("mgmt.conf");
    std::fs::write(
        &config,
        render_mgmt_config(&target, &rpath(&pins), PathStyle::Unix).unwrap(),
    )
    .unwrap();
    Rendered { config, target }
}

/// `ssh -G` prints the effective configuration: every ADR-0012 §5.2 setting holds for the
/// runner hop and for the jump hop.
#[test]
fn isolated_config_is_effective_at_every_hop() {
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("g").unwrap();
    let Some(sshd) = start_sshd(&scratch, SshdConfig::default()) else {
        return;
    };
    let account = current_account().unwrap_or_else(|| "runner".into());
    let key = MgmtKey::generate().unwrap();
    let r = render(
        &dir,
        &sshd,
        &account,
        &host_key(&sshd),
        &key.public().unwrap().openssh_line,
        true,
    );
    let pins = dir.join("known_hosts");
    for (alias, expected_alias) in [
        (r.target.alias(), "hm-env-env_fixture"),
        ("hm-dest-bastion".to_owned(), "hm-dest-bastion"),
    ] {
        let out = run_ssh(&[
            "-G".as_ref(),
            "-F".as_ref(),
            r.config.as_os_str(),
            alias.as_ref(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The `user` line names the fixture account: dropped before anything is printed.
        let text: String = String::from_utf8_lossy(&out.stdout)
            .to_ascii_lowercase()
            .lines()
            .filter(|l| !l.starts_with("user "))
            .map(|l| format!("{l}\n"))
            .collect();
        let has = |line: &str| text.lines().any(|l| l.trim() == line);
        // `ssh -G` prints no `controlpath` line for `none`.
        assert!(
            text.lines()
                .all(|l| !l.starts_with("controlpath ") || l.trim() == "controlpath none"),
            "{alias}: a control path is effective"
        );
        for line in [
            "stricthostkeychecking true",
            "globalknownhostsfile none",
            "verifyhostkeydns false",
            "updatehostkeys false",
            "checkhostip no",
            "controlmaster false",
            "controlpersist no",
            "forwardagent no",
            "clearallforwardings yes",
            "identitiesonly yes",
            "permitlocalcommand no",
            "requesttty false",
            &format!("hostkeyalias {expected_alias}"),
            &format!(
                "userknownhostsfile {}",
                pins.to_string_lossy().to_ascii_lowercase()
            ),
            "hostkeyalgorithms ssh-ed25519",
        ] {
            assert!(has(line), "{alias}: `{line}` not effective in:\n{text}");
        }
        assert!(
            !text
                .lines()
                .any(|l| l.starts_with("sendenv ") || l.starts_with("setenv "))
        );
        assert!(!text.lines().any(|l| l.trim() == "identityagent none"));
    }
    // The runner hop names the jump; the jump hop names no proxy.
    let out = run_ssh(&[
        "-G".as_ref(),
        "-F".as_ref(),
        r.config.as_os_str(),
        r.target.alias().as_ref(),
    ]);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .to_ascii_lowercase()
            .lines()
            .any(|l| l.trim() == "proxyjump hm-dest-bastion")
    );
}

/// The per-session K_mgmt agent and the isolated configuration log in to a fixture sshd that
/// authorizes K_mgmt (`restrict`); the same configuration pinning another key is refused at
/// host-key verification, before authentication.
#[tokio::test]
async fn k_mgmt_authenticates_only_through_its_session_agent() {
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("k").unwrap();
    let key = MgmtKey::generate().unwrap();
    let public = key.public().unwrap();
    let authorized = ssh_key::PublicKey::from_openssh(&public.openssh_line).unwrap();
    let Some(sshd) = start_sshd(
        &scratch,
        SshdConfig {
            authorized: vec![authorized],
            ..SshdConfig::default()
        },
    ) else {
        return;
    };
    let account = sshd
        .login_account()
        .or_else(current_account)
        .expect("the fixture account");
    let pin = host_key(&sshd);
    let r = render(&dir, &sshd, &account, &pin, &public.openssh_line, false);
    let signer =
        MgmtSigner::with_host_key_lines(key, [account.clone()], std::slice::from_ref(&pin))
            .unwrap();
    let agent = SessionAgent::start(&dir.join("a.sock"), signer).unwrap();
    let config = r.config.clone();
    let alias = r.target.alias();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh(&[
            "-F".as_ref(),
            config.as_os_str(),
            "-o".as_ref(),
            "BatchMode=yes".as_ref(),
            "-o".as_ref(),
            "CertificateFile=none".as_ref(),
            alias.as_ref(),
            "true".as_ref(),
        ])
    })
    .await
    .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "login: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        sshd.accepted_log()
            .iter()
            .any(|k| k.fingerprint == public.fingerprint.as_str()),
        "the fixture accepted K_mgmt"
    );

    // Another pinned key: refused at host-key verification, before authentication.
    let wrong_dir = scratch.subdir("w").unwrap();
    let wrong = render(
        &wrong_dir,
        &sshd,
        &account,
        &other_key(),
        &public.openssh_line,
        false,
    );
    let config = wrong.config.clone();
    let alias = wrong.target.alias();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh(&[
            "-F".as_ref(),
            config.as_os_str(),
            "-o".as_ref(),
            "BatchMode=yes".as_ref(),
            "-o".as_ref(),
            "CertificateFile=none".as_ref(),
            alias.as_ref(),
            "true".as_ref(),
        ])
    })
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(255));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Host key verification failed") || stderr.contains("host key"),
        "{stderr}"
    );
    agent.stop().await;
}

/// A logging `ssh` wrapper: records each argument vector, then runs the real client.
fn logging_wrapper(dir: &Path) -> (PathBuf, PathBuf) {
    let log = dir.join("ssh-argv.log");
    let wrapper = dir.join("ssh-wrapper");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
            log.display(),
            ssh().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    (wrapper, log)
}

/// m06-plan U2 "adapter: bootstrap refuses an unverified host key, and no `ssh-keyscan` is
/// ever run": against the fixture sshd, a key that is not the pinned one is refused by the
/// preflight (`HOST_TRUST_CHANGED`, `enrollment_host_key_mismatch`) and the interactive
/// session never starts; the pinned key passes the preflight. Every program the adapter ran
/// is the `ssh` client, and no argument scans or accepts a key.
#[tokio::test]
async fn bootstrap_refuses_an_unverified_host_key_and_never_scans() {
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("b").unwrap();
    let Some(sshd) = start_sshd(&scratch, SshdConfig::default()) else {
        return;
    };
    let account = sshd
        .login_account()
        .or_else(current_account)
        .expect("the fixture account");
    let user_config = dir.join("user.conf");
    std::fs::write(
        &user_config,
        format!(
            "Host runner-lab\n    HostName {}\n    Port {}\n    IdentityFile none\n    IdentitiesOnly yes\n    IdentityAgent none\n",
            sshd.host, sshd.port
        ),
    )
    .unwrap();
    let (wrapper, log) = logging_wrapper(&dir);
    let adapter = BootstrapSsh {
        ssh_client: wrapper,
        scratch_dir: dir.clone(),
        config: Some(user_config),
        extra_options: vec!["CertificateFile=none".into()],
        stderr_file: None,
        issuer_ca: None,
        iroh_endpoint: None,
        // No fill: this suite runs on Unix, where the fill does nothing.
        fill: |_, _| {},
    };
    let mgmt_key = MgmtKey::generate().unwrap().public().unwrap();
    let plan = |pin: String| BootstrapPlan {
        access: VerifiedAccess {
            destination: DestinationId::parse("lab").unwrap(),
            alias: "runner-lab".into(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: AccountName::parse(&account).unwrap(),
                    host_keys: vec![pin],
                },
                jump: None,
            },
        },
        runner_program: "/opt/heimdall/bin/heimdall".into(),
        runner_home: None,
        runner_sha256: None,
        owner_key: MgmtKeyInfo {
            openssh_line: mgmt_key.openssh_line.clone(),
            fingerprint: mgmt_key.fingerprint.clone(),
        },
        owner_client: ClientId::from_random_bytes([7; 16]),
    };

    // Not the pinned key: refused, and only the preflight ran.
    let err = adapter.run(&plan(other_key())).await.unwrap_err();
    assert_eq!(err.code, Code::HostTrustChanged, "{err:?}");
    assert_eq!(
        err.reason.as_deref(),
        Some(reason::ENROLLMENT_HOST_KEY_MISMATCH)
    );
    let lines: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 1, "only the preflight ran: {lines:?}");
    assert!(lines[0].contains("PreferredAuthentications=none"));
    assert!(!lines[0].contains("remote init"));
    assert!(
        !dir.join("bootstrap_known_hosts").exists(),
        "the pin file is removed"
    );

    // The pinned key: the preflight passes (authentication then refused, as intended).
    let pins_dir = scratch.subdir("p").unwrap();
    let pin_file = pins_dir.join("bootstrap_known_hosts");
    let good = plan(host_key(&sshd));
    std::fs::write(
        &pin_file,
        heimdall_app::remote_env::ssh::pin_file_text("lab", &good.access.route.runner).unwrap(),
    )
    .unwrap();
    adapter.preflight(&good, &pin_file).await.unwrap();

    let all = std::fs::read_to_string(&log).unwrap();
    assert_eq!(all.lines().count(), 2);
    for line in all.lines() {
        let lower = line.to_ascii_lowercase();
        for forbidden in [
            "keyscan",
            "accept-new",
            "stricthostkeychecking=no",
            "stricthostkeychecking=ask",
        ] {
            assert!(!lower.contains(forbidden), "{forbidden}: {line}");
        }
        assert!(line.contains("StrictHostKeyChecking=yes"));
        assert!(line.contains("HostKeyAlias=hm-dest-lab"));
    }
    assert_no_canary(&all);
}
