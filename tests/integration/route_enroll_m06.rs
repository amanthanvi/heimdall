//! ⟨M06 U5a⟩ Verification through an approved single-hop jump, with the final-key rule
//! (ADR-0012 §5.7; ADR-0010 §5 item 5, §9 item 4, §10 item 6; m06-plan U5a "a jump enrollment
//! with a changed final key is held").
//!
//! The Verifier's generated configuration through the catalog's jump
//! (`heimdall_enroll::routes::generated_routed_config`) against two loopback sshds: the jump
//! host (forwarding only to the final host's port) and the final host. Each hop's host key is
//! pinned from its own file only (`-F <generated file>`; the user's configuration is never
//! read). With the approved final key, both hops authenticate through the jump. With the final
//! host's key changed, the client refuses it **before any authentication at the final host**,
//! the jump having authenticated and forwarded, and the trace's host-key failure classifies as
//! `host_key_mismatch`: the verdict that holds the enrollment (`host_key_changed`), as on the
//! direct route.
//!
//! Fixtures (AGENTS.md): a per-run `FixtureKey` in a scratch `FakeAgent`, `LoopbackSshd`s on
//! 127.0.0.1 with per-run host keys, `SSH_AUTH_SOCK` removed. Unix only: a harness sshd (the
//! Windows run's WSL server) cannot honour the jump host's forwarding settings, so the Windows
//! row is `blocked` on that, never counted as a pass.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    missing_docs
)]

#[test]
fn a_jump_verification_with_a_changed_final_key_is_held() {
    #[cfg(not(unix))]
    println!(
        "blocked: a local sshd with forwarding settings (the harness server cannot honour the \
         jump host's `AllowTcpForwarding`/`PermitOpen`)"
    );
    #[cfg(unix)]
    jump_verification_unix();
}

#[cfg(unix)]
fn jump_verification_unix() {
    use heimdall_contract::enrollment::{ApprovedHostKey, ApprovedTarget, EnrollmentForm};
    use heimdall_contract::ids::AccountName;
    use heimdall_domain::verification::{
        AttemptResult, ClassifyContext, VerificationPhase, VerificationVerdict, classify,
    };
    use heimdall_enroll::routes::{VerifyJump, generated_routed_config};
    use heimdall_enroll::trace::{self, ClientVersion, TraceContext};
    use heimdall_enroll::verify::GeneratedConfig;
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::home::{Scratch, find_program};
    use heimdall_testkit::sshd::{LOOPBACK, LoopbackSshd, SshdConfig};
    use std::path::PathBuf;

    let Some(ssh) = find_program("ssh") else {
        println!("skipped: no ssh client found");
        return;
    };
    let scratch = Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let canary = key.comment().to_owned();
    let redact = |s: &str| s.replace(&canary, "<fixture-comment>");
    let final_host = match LoopbackSshd::start(
        &scratch,
        SshdConfig {
            authorized: vec![key.public().clone()],
            ..SshdConfig::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            println!("skipped: {e:?}");
            return;
        }
    };
    let jump_host = LoopbackSshd::start(
        &scratch,
        SshdConfig {
            authorized: vec![key.public().clone()],
            tcp_forwarding_permit_open: Some(vec![format!("{LOOPBACK}:{}", final_host.port)]),
            ..SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("blocked: {e:?}"));
    let account = final_host
        .login_account()
        .expect("the fixture sshd's account");
    let agent = FakeAgent::start(
        Endpoint::in_scratch(&scratch, "a").unwrap(),
        FakeAgentConfig {
            keys: vec![key.clone()],
            mode: AgentMode::Normal,
        },
    );
    let endpoint = PathBuf::from(agent.endpoint().locator());
    let dir = scratch.subdir("v").unwrap();
    let id_pub = dir.join("id.pub");
    std::fs::write(&id_pub, format!("{}\n", key.public_line_without_comment())).unwrap();
    let words = |line: &str| -> (String, String) {
        let mut w = line.split_whitespace().skip(1);
        (w.next().unwrap().to_owned(), w.next().unwrap().to_owned())
    };
    let (final_alg, final_b64) = words(&final_host.host_key_line);
    let jump_line = words(&jump_host.host_key_line);
    let alias = "hm-verify-0123456789abcdef";
    let known_hosts = dir.join("known_hosts");
    let global = dir.join("global_known_hosts");
    std::fs::write(&global, "").unwrap();
    let pins = dir.join("pins");
    std::fs::write(
        &pins,
        format!("hm-dest-bastion {} {}\n", jump_line.0, jump_line.1),
    )
    .unwrap();
    let target = ApprovedTarget {
        hostname: LOOPBACK.into(),
        port: final_host.port,
        user: AccountName::parse(&account).unwrap(),
        proxy: Default::default(),
        host_key: ApprovedHostKey {
            algorithm: final_alg.clone(),
            key: final_b64.clone(),
            fingerprint: "SHA256:unused".into(),
        },
    };
    let agent_arg = format!("\"{}\"", endpoint.display());
    let config_text = generated_routed_config(
        &GeneratedConfig {
            target: &target,
            alias,
            known_hosts: &known_hosts,
            global_known_hosts: &global,
            identity_agent: &agent_arg,
            identity_file: &id_pub,
            // Not a certificate: OpenSSH skips it, and the fixture key authenticates.
            certificate_file: &id_pub,
        },
        &VerifyJump {
            hostname: LOOPBACK,
            port: jump_host.port,
            user: &account,
            host_key_alias: "hm-dest-bastion",
            known_hosts: &pins,
            host_key_algorithm: &jump_line.0,
            identity_agent: &agent_arg,
            identity_file: &id_pub,
        },
    )
    .unwrap();
    let config = dir.join("ssh_config");
    std::fs::write(&config, &config_text).unwrap();
    let run = |marker: &str| {
        let out = std::process::Command::new(&ssh)
            .args(["-F".as_ref(), config.as_os_str()])
            .args(["-v", "-T", "hm-verify"])
            .arg(format!("echo {marker}"))
            .env_remove("SSH_AUTH_SOCK")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            redact(&String::from_utf8_lossy(&out.stderr)),
        )
    };
    let attempts = |s: &LoopbackSshd, mark: u64| -> usize {
        [
            "Accepted publickey",
            "Failed publickey",
            "Postponed publickey",
            "Invalid user",
        ]
        .iter()
        .map(|n| s.log_lines_since(mark, n).len())
        .sum()
    };
    let accepted =
        |s: &LoopbackSshd, mark: u64| s.log_lines_since(mark, "Accepted publickey").len();

    // The approved final key: the verification connects through the jump.
    std::fs::write(&known_hosts, format!("{alias} {final_alg} {final_b64}\n")).unwrap();
    let (j, f) = (jump_host.log_mark(), final_host.log_mark());
    let (code, stdout, stderr) = run("hm-routed-ok");
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stdout.contains("hm-routed-ok"));
    assert_eq!(
        accepted(&jump_host, j),
        1,
        "the jump hop authenticated with its own access"
    );
    assert_eq!(
        accepted(&final_host, f),
        1,
        "the final host was reached through the jump"
    );

    // The final host's key changed (the approved key is no longer the one served).
    let wrong = FixtureKey::generate().public_line_without_comment();
    let (wrong_alg, wrong_b64) = {
        let mut w = wrong.split_whitespace();
        (w.next().unwrap().to_owned(), w.next().unwrap().to_owned())
    };
    std::fs::write(&known_hosts, format!("{alias} {wrong_alg} {wrong_b64}\n")).unwrap();
    let (j, f) = (jump_host.log_mark(), final_host.log_mark());
    let (code, stdout, stderr) = run("hm-routed-changed");
    assert_ne!(code, Some(0));
    assert!(!stdout.contains("hm-routed-changed"));
    assert!(stderr.contains("Host key verification failed"), "{stderr}");
    assert_eq!(
        accepted(&jump_host, j),
        1,
        "the jump authenticated and forwarded"
    );
    assert_eq!(
        attempts(&final_host, f),
        0,
        "no authentication attempt at the changed final host"
    );

    // The trace classifies as `host_key_mismatch`: the verdict that holds the enrollment.
    let version_out = std::process::Command::new(&ssh).arg("-V").output().unwrap();
    let version = ClientVersion::parse(&String::from_utf8_lossy(&version_out.stderr)).unwrap();
    let patterns = trace::patterns_for(version.family, version).expect("a recorded client");
    let parsed = trace::parse(
        patterns,
        &stderr,
        &TraceContext {
            host_key_alias: alias,
            cert_type: "ED25519-CERT",
            key_fingerprint: "SHA256:unused",
        },
    );
    assert!(
        parsed.host_key_failure,
        "the trace shows the final host's key refused"
    );
    let mut events = parsed.events;
    events.host_key_failure = parsed.host_key_failure;
    let positive = AttemptResult {
        exit_status: code,
        signatures: 0,
        trace: events,
        remote_now: None,
    };
    let verdict = classify(
        &positive,
        &AttemptResult::default(),
        VerificationPhase::Reverify,
        EnrollmentForm::Account,
        &ClassifyContext {
            unrecorded: false,
            not_run: false,
            offset: None,
            skew_lag_ms: 60_000,
            skew_lead_ms: 300_000,
        },
    );
    assert_eq!(verdict, VerificationVerdict::HostKeyMismatch);
    drop(agent);
}
