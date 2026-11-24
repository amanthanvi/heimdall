//! ⟨M06 W2 wiring⟩ A controller's management session to a real runner, end to end (m06-plan
//! U2/U3 wiring; ADR-0012 §3.3, §3.5, §3.6, §5.2):
//!
//! 1. **The runner side, through the real binary.** `heimdall --home <runner home> remote
//!    init --owner-client <cid> --owner-key <K_mgmt.pub>` on a pseudo-terminal, confirmed
//!    with a typed `yes` (the runner-local confirmation): the runner marker and the owner
//!    client are written, and the management line is answered. A retried bootstrap of the
//!    same key under another client ID answers the first client (`created: false`). Then
//!    `heimdall service run --runner` serves the runner home.
//! 2. **The management line.** ⟨W2 fixes⟩ The runner runtime's own writer
//!    (`heimdall_runtime::paired_lines`) reconciles the owner's line into the runner
//!    account's `~/.ssh/authorized_keys` (the scratch `HEIMDALL_TEST_SSH_HOME`) at start:
//!    exactly the line `remote init` rendered, `restrict,command="exec \"<heimdall>\" remote
//!    serve --client <cid> --home \"<home>\"" <K_mgmt.pub> heimdall-mgmt:<cid>`. The fixture
//!    sshd's `AuthorizedKeysFile` resolves to that file.
//! 3. **The controller side.** The isolated `-F` configuration (`heimdall_sshconf::mgmt`),
//!    the per-session K_mgmt agent (`heimdall_credential::mgmt::SessionAgent`), the
//!    management `ssh` (`heimdall_app::remote_env::ssh::spawn_management`) and the IPC client
//!    over its standard streams requiring `remote-control/1`. The runner's hello reports its
//!    environment ID, the `owner` role and ⟨rev6.2⟩ the bound client; an `inspect
//!    environments` over the paired session answers the runner's own `remote_runner`
//!    environment ("status"); a `Decide` the paired session sends is refused before dispatch.
//!    A key the runner never enrolled is refused at authentication.
//!
//! 4. ⟨W2 fixes⟩ **Invite, runner-local approval, activation probe, join.** The owner's
//!    session submits an `invite` for a second K_mgmt: `APPROVAL_REQUIRED` with the runner's
//!    decision reference; an attended session local to the runner approves it (the
//!    invitation and its pending line, with `expiry-time`, are written); the owner's replay
//!    returns the recorded result. The new key's first session negotiates only
//!    `remote-control/1`, echoes the probe's nonce and joins; its line is rewritten without
//!    `expiry-time`; its next session is an ordinary owner session. Revoking it removes the
//!    line, and the key is refused at authentication.
//!
//! Not covered here (and why): the controller CLI's `environment add` needs a verified M03 enrollment in
//! the controller catalog and a terminal, so the controller half is driven at the library
//! level with the same adapters the CLI wires.
//!
//! ⟨M06 W5 U7⟩ The installations, sessions and fixture calls these cases use live in
//! `exit_m06/world.rs`, shared with the exit suite (`exit_m06.rs`); nothing else changed.
//!
//! **Isolation.** The runner processes get a cleared environment with a scratch `HOME`,
//! `HEIMDALL_HOME` and `HEIMDALL_TEST_SSH_HOME`; the fixture sshd is unprivileged on
//! 127.0.0.1 with per-run host keys; the controller's `ssh` reads only the rendered scratch
//! `-F` file (strict pin, no agent but the named session agent, `IdentitiesOnly`,
//! `CertificateFile none`, no multiplexing), with `SSH_AUTH_SOCK` removed. Keys are generated
//! per run. Only the runtime this test started is stopped (`service stop` on its scratch
//! home, then the child is waited for). Where no sshd can start the case reports `blocked`.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
#![cfg(unix)]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "exit_m06/world.rs"]
mod world;
use world::*;

use heimdall_contract::ids::ClientId;
use heimdall_contract::ipc::{PeerInfo, capability};
use heimdall_contract::remote::Role;
use heimdall_contract::request::{
    DecideRequest, InspectRequest, InspectSubject, InteractionMode, Request, Verdict,
};
use heimdall_credential::mgmt::{MgmtKey, MgmtSigner, SessionAgent};
use heimdall_ipc::session::ControlClient;
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::{Scratch, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use serde_json::Value;

#[tokio::test]
async fn a_controller_reaches_a_real_runner_through_its_management_line() {
    let scratch = Scratch::new().unwrap();
    let mut runner = Runner::new(&scratch);
    let key = MgmtKey::generate().unwrap();
    let public = key.public().unwrap();
    let key_text = public
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let client = ClientId::from_random_bytes([0x5a; 16]);

    // 1. The runner-local bootstrap enrollment, confirmed on the runner's terminal.
    let refused = runner.remote_init(&client, &key_text, "no");
    assert_eq!(
        envelope(&refused)["code"],
        "INTERACTION_REQUIRED",
        "{refused}"
    );
    assert!(
        !runner.account.join(".ssh").exists(),
        "declined: nothing created"
    );
    let first = envelope(&runner.remote_init(&client, &key_text, "yes"));
    assert_eq!(first["code"], "OK", "{first}");
    let environment = first["data"]["environment"].as_str().unwrap().to_owned();
    assert_eq!(first["data"]["client"], client.as_str());
    assert_eq!(first["data"]["created"], true);
    assert_eq!(
        first["data"]["key_fingerprint"],
        public.fingerprint.as_str()
    );
    let line = first["data"]["management_line"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(line.starts_with("restrict,command=\"exec \\\""), "{line}");
    assert!(line.contains(&format!("remote serve --client {}", client.as_str())));
    assert!(line.ends_with(&format!(" heimdall-mgmt:{}", client.as_str())));
    // ⟨M06-W2-R02⟩ The account had no `~/.ssh`: the declined run created nothing; the
    // confirmed one created it owner-only (the scratch `HEIMDALL_TEST_SSH_HOME`) and wrote
    // the owner's line there.
    let ssh_dir = runner.account.join(".ssh");
    let keys_file = ssh_dir.join("authorized_keys");
    assert_eq!(first["data"]["line_written"], true, "{first}");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&ssh_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
        // The shared module's exclusive create: owner-only.
        let mode = std::fs::metadata(&keys_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n")
    );
    // A retried bootstrap of the same key, under a new client ID: the first client stands,
    // and ⟨M06-W2-R02⟩ `remote init` itself writes the owner's line now (no runtime runs).
    let retry =
        envelope(&runner.remote_init(&ClientId::from_random_bytes([0x6b; 16]), &key_text, "yes"));
    assert_eq!(retry["code"], "OK", "{retry}");
    assert_eq!(retry["data"]["created"], false);
    assert_eq!(retry["data"]["client"], client.as_str());
    assert_eq!(retry["data"]["environment"], environment.as_str());
    assert_eq!(retry["data"]["line_written"], true, "{retry}");
    assert!(
        retry["data"]["iroh_admission"].is_null(),
        "no token, no admission"
    );
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "remote init wrote exactly the rendered owner line"
    );
    runner.start();
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "the runtime's reconciler leaves the line as it is"
    );
    // ⟨M06-W2-R02; ADR-0006 §18.7 item 8⟩ The repair while the runtime runs (it holds the
    // instance lock): the same confirmation, through the attended runner-local form. With
    // the controller's endpoint ID it adds the owner's Iroh admission and first endpoint; a
    // second repair with another endpoint never replaces it. (Two RFC 8032 test-vector
    // public keys: valid endpoint IDs for the Iroh library's own parser too.)
    let (ep_a, ep_b) = (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    // Anything but an endpoint ID is refused before the confirmation is asked.
    let refused = runner
        .command()
        .args([
            "--json",
            "remote",
            "init",
            "--owner-client",
            client.as_str(),
        ])
        .args([
            "--owner-key",
            &key_text,
            "--iroh-endpoint",
            "not-an-endpoint",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let refused = envelope(&String::from_utf8_lossy(&refused.stdout));
    assert_eq!(refused["code"], "USAGE_ERROR", "{refused}");
    let declined =
        envelope(&runner.remote_init_with(&client, &key_text, "no", &["--iroh-endpoint", ep_a]));
    assert_eq!(declined["code"], "INTERACTION_REQUIRED", "{declined}");
    let transcript = runner.remote_init_with(&client, &key_text, "yes", &["--iroh-endpoint", ep_a]);
    assert!(
        transcript.contains(ep_a) && transcript.contains(public.fingerprint.as_str()),
        "the confirmation shows the endpoint ID next to the key's fingerprint: {transcript}"
    );
    let repaired = envelope(&transcript);
    assert_eq!(repaired["code"], "OK", "{repaired}");
    assert_eq!(repaired["data"]["created"], false);
    assert_eq!(repaired["data"]["client"], client.as_str());
    assert_eq!(repaired["data"]["line_written"], true, "{repaired}");
    assert_eq!(repaired["data"]["management_line"], line.as_str());
    assert_eq!(repaired["data"]["iroh_admission"]["endpoint"], "recorded");
    let again =
        envelope(&runner.remote_init_with(&client, &key_text, "yes", &["--iroh-endpoint", ep_b]));
    assert_eq!(again["code"], "OK", "{again}");
    assert_eq!(
        again["data"]["iroh_admission"]["endpoint"], "kept",
        "{again}"
    );
    assert_eq!(again["data"]["iroh_admission"]["kept_endpoint"], ep_a);
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n"),
        "the repairs left exactly the owner's line"
    );

    // 2. The fixture sshd reads the runner account's authorized_keys (its registry resolves
    //    to that file).
    let sshd = match LoopbackSshd::start(
        &scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            // ⟨ADR-0006 §18.7 items 16–17⟩ The daemon itself allows agent forwarding, so
            // it is the runner's line (`restrict`) that refuses it to a management key,
            // and a line without that restriction really forwards (the last step).
            agent_forwarding: true,
            ..SshdConfig::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            #[allow(clippy::print_stderr)] // the blocked row's reason
            {
                eprintln!("m06 controller->runner: blocked (no fixture sshd: {e})");
            }
            return;
        }
    };
    let account = sshd
        .login_account()
        .or_else(current_account)
        .expect("the fixture account");
    let Some(registry) = sshd.registry_path().map(Path::to_path_buf) else {
        #[allow(clippy::print_stderr)] // the blocked row's reason
        {
            eprintln!("m06 controller->runner: blocked (the fixture sshd has no local registry)");
        }
        return;
    };
    std::fs::remove_file(&registry).unwrap();
    std::os::unix::fs::symlink(&keys_file, &registry).unwrap();

    // 3. The controller's management session.
    let dir = scratch.subdir("c").unwrap();
    let mut session = open_session(&dir, &sshd, &account, key, &environment)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let hello = session.client.server().clone();
    assert_eq!(hello.environment_id.as_str(), environment);
    assert_eq!(hello.role, Some(Role::Owner));
    assert_eq!(
        hello.remote_client.as_ref(),
        Some(&client),
        "rev6.2: the bound client"
    );
    assert!(hello.capabilities.contains(capability::REMOTE_CONTROL_V1));

    // "Status": the runner's own environment, read over the paired session.
    let inspected = session
        .client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Environments,
            preview: None,
            cwd: None,
            redact: false,
        }))
        .await
        .unwrap();
    let text = serde_json::to_string(&inspected).unwrap();
    assert_no_canary(&text);
    assert_eq!(inspected.code.as_str(), "OK", "{text}");
    assert!(text.contains(&environment), "{text}");
    assert!(text.contains("remote_runner"), "{text}");

    // A paired session never decides (ADR-0012 §3.10): refused before dispatch.
    let decided = session
        .client
        .request(Request::Decide(DecideRequest {
            decision_id: heimdall_contract::ids::DecisionId::from_random_bytes([1; 16]),
            verdict: Verdict::Approve,
        }))
        .await
        .unwrap();
    assert_eq!(decided.code.as_str(), "INTERACTION_REQUIRED", "{decided:?}");

    // 4. ⟨W2 fixes⟩ Invite a second K_mgmt (role owner: this runner's sshd policy is not
    //    verified, so limited roles are refused), approve it at the runner, activate it.
    let second = MgmtKey::generate().unwrap();
    let second_public = second.public().unwrap();
    let second_text = second_public
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let invite: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "invite", "environment": environment,
        "role": "owner", "key_fingerprint": second_public.fingerprint,
        "public_key": second_text, "request_id": "e2e-invite-1",
    }))
    .unwrap();
    let pending = session.client.request(invite.clone()).await.unwrap();
    assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
    let decision = pending.next.unwrap().decision_ref.unwrap();
    // The runner-local confirmation: an attended session on the runner's own endpoint.
    let info = heimdall_runtime::instance::InstanceInfo::read_valid(
        &heimdall_runtime::Paths::under(&runner.home).runtime_dir,
    )
    .unwrap()
    .expect("the runner runtime's advertisement");
    let stream = heimdall_ipc::unix::connect(Path::new(&info.control_endpoint))
        .await
        .unwrap();
    let mut at_runner = ControlClient::handshake(
        stream,
        PeerInfo {
            name: "heimdall-cli".into(),
            version: "test".into(),
        },
        BTreeSet::new(),
        InteractionMode::Interactive,
    )
    .await
    .unwrap();
    assert_eq!(at_runner.attend().await.unwrap().code.as_str(), "OK");
    let approved = at_runner
        .request(Request::Decide(DecideRequest {
            decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
            verdict: Verdict::Approve,
        }))
        .await
        .unwrap();
    assert_eq!(approved.code.as_str(), "OK", "{approved:?}");
    let invited: ClientId = serde_json::from_value(approved.data["client"].clone()).unwrap();
    let nonce = approved.data["probe_nonce"].as_str().unwrap().to_owned();
    let pending_line = std::fs::read_to_string(&keys_file).unwrap();
    assert!(pending_line.contains(&format!("heimdall-mgmt:{}", invited.as_str())));
    assert!(pending_line.contains("expiry-time="), "{pending_line}");
    assert!(
        pending_line.starts_with(&format!("{line}\n")),
        "the owner's line kept"
    );
    // The owner's replay returns the recorded terminal result.
    let replayed = session.client.request(invite).await.unwrap();
    assert_eq!(replayed.data, approved.data);
    // The new key's first session: pending, so only the probe and join.
    let joining = scratch.subdir("j").unwrap();
    let signer =
        MgmtSigner::with_host_key_lines(second, [account.clone()], &[host_key(&sshd)]).unwrap();
    let agent = SessionAgent::start(&joining.join("a.sock"), signer).unwrap();
    let (mut first_session, child) = connect(
        &joining,
        &sshd,
        &account,
        &second_public.openssh_line,
        &environment,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let caps: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
    assert_eq!(first_session.server().capabilities, caps);
    assert_eq!(
        first_session.server().remote_client.as_ref(),
        Some(&invited)
    );
    let probe: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "activation_probe",
        "environment": environment, "nonce": nonce,
    }))
    .unwrap();
    let echoed = first_session.request(probe).await.unwrap();
    assert_eq!(echoed.code.as_str(), "OK", "{echoed:?}");
    assert_eq!(echoed.data["client"], invited.as_str());
    // ⟨ADR-0006 §18.7 item 16; ADR-0012 §3.2⟩ The four confirming probes with the enrolled
    // key, on the real connection: this sshd refuses the line's key a PTY, a `-W` forward
    // and agent forwarding (a disposable agent, never the one holding the key), and does
    // not deliver the `SetEnv` variable. The join reports exactly that.
    let ssh = find_program("ssh").expect("an OpenSSH client");
    let alias = format!("hm-env-{environment}");
    let disposable =
        heimdall_app::remote_env::ssh::DisposableAgent::start(&joining.join("p.sock")).unwrap();
    let observed = heimdall_app::remote_env::ssh::run_probes(
        &ssh,
        &joining.join("mgmt.conf"),
        &alias,
        &disposable,
        heimdall_localenv::sys::openssh_env::fill_openssh_environment,
    )
    .await;
    drop(disposable);
    assert_eq!(
        observed,
        Some(heimdall_contract::remote::ProbeObservation {
            pty_refused: true,
            forward_refused: true,
            agent_forward_refused: true,
            setenv_canary_delivered: false,
        })
    );
    assert_eq!(
        recorded_downgrade(&runner.home),
        None,
        "restricted sessions record nothing"
    );
    let join: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "join", "environment": environment,
        "invitation": approved.data["invitation"], "role": "owner",
        "generation": approved.data["generation"], "probe": observed,
    }))
    .unwrap();
    let joined = first_session.request(join).await.unwrap();
    assert_eq!(joined.code.as_str(), "OK", "{joined:?}");
    drop(first_session);
    drop(child);
    let active_text = std::fs::read_to_string(&keys_file).unwrap();
    let active: Vec<&str> = active_text
        .lines()
        .filter(|l| l.ends_with(&format!(" heimdall-mgmt:{}", invited.as_str())))
        .collect();
    assert_eq!(active.len(), 1, "{active_text}");
    assert!(
        !active[0].contains("expiry-time="),
        "rewritten without expiry-time"
    );
    // Its next session is an ordinary owner session.
    let (mut ordinary, child) = connect(
        &joining,
        &sshd,
        &account,
        &second_public.openssh_line,
        &environment,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ordinary.server().role, Some(Role::Owner));
    assert!(
        ordinary
            .server()
            .capabilities
            .contains(capability::OPERATIONS_V1)
    );
    let status = ordinary
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Environments,
            preview: None,
            cwd: None,
            redact: false,
        }))
        .await
        .unwrap();
    assert_eq!(status.code.as_str(), "OK", "{status:?}");
    drop(ordinary);
    drop(child);
    // Revoking it removes its line; the key is then refused at authentication.
    let revoke: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "revoke_client", "environment": environment,
        "client": invited,
    }))
    .unwrap();
    let revoked = session.client.request(revoke).await.unwrap();
    assert_eq!(revoked.code.as_str(), "OK", "{revoked:?}");
    assert_eq!(revoked.data["line_removed"], true);
    assert_eq!(
        std::fs::read_to_string(&keys_file).unwrap(),
        format!("{line}\n")
    );
    let after = connect(
        &joining,
        &sshd,
        &account,
        &second_public.openssh_line,
        &environment,
    )
    .await;
    assert!(after.is_err(), "a revoked key opened a session");
    agent.stop().await;
    drop(at_runner);
    drop(session.client);
    session.agent.stop().await;

    // A key the runner never enrolled is refused at authentication.
    let other = scratch.subdir("o").unwrap();
    let refused = open_session(
        &other,
        &sshd,
        &account,
        MgmtKey::generate().unwrap(),
        &environment,
    )
    .await;
    let Err(why) = refused else {
        panic!("an unenrolled key opened a management session");
    };
    assert!(
        why.contains("Permission denied") || why.contains("handshake failed"),
        "{why}"
    );

    // ⟨ADR-0006 §18.7 items 16–17; ADR-0012 §3.2 "Limits"⟩ A session that is NOT restricted
    // as the runner's line says. The fixture stands in for an sshd whose real connections
    // get another policy: two more keys reach the same forced command through lines that
    // also grant a PTY, or agent forwarding (written by the test; the runner never writes
    // such a line). Asked for neither, such a session works. Asked by the probes:
    // * sshd allocates the PTY, the bridge finds `SSH_TTY` and refuses the session, and the
    //   probe reads that refusal: `pty_refused: false`; the runner is recorded owner-only;
    // * sshd forwards the disposable agent, the bridge finds `SSH_AUTH_SOCK` and refuses:
    //   `agent_forward_refused: false`.
    assert_eq!(recorded_downgrade(&runner.home), None);
    let options = line
        .split_once(" ssh-ed25519 ")
        .map(|(options, _)| options.to_owned())
        .unwrap();
    let mut unrestricted = Vec::new();
    for (tag, grant) in [
        ("pty", "restrict,pty,"),
        ("agt", "restrict,agent-forwarding,"),
    ] {
        let extra = MgmtKey::generate().unwrap();
        let extra_public = extra.public().unwrap();
        let extra_text = extra_public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let mut keys = std::fs::read_to_string(&keys_file).unwrap();
        keys.push_str(&format!(
            "{} {extra_text} fixture-{tag}\n",
            options.replacen("restrict,", grant, 1)
        ));
        std::fs::write(&keys_file, keys).unwrap();
        let dir = scratch.subdir(tag).unwrap();
        let session = open_session(&dir, &sshd, &account, extra, &environment)
            .await
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
        assert_eq!(
            session.client.server().remote_client.as_ref(),
            Some(&client)
        );
        let disposable =
            heimdall_app::remote_env::ssh::DisposableAgent::start(&dir.join("p.sock")).unwrap();
        let observed = heimdall_app::remote_env::ssh::run_probes(
            &ssh,
            &dir.join("mgmt.conf"),
            &alias,
            &disposable,
            heimdall_localenv::sys::openssh_env::fill_openssh_environment,
        )
        .await
        .unwrap_or_else(|| panic!("{tag}: a probe was inconclusive"));
        drop(disposable);
        unrestricted.push(observed);
        assert!(
            recorded_downgrade(&runner.home).is_some(),
            "{tag}: the bridge recorded it"
        );
        drop(session.client);
        session.agent.stop().await;
    }
    let restricted = heimdall_contract::remote::ProbeObservation {
        pty_refused: true,
        forward_refused: true,
        agent_forward_refused: true,
        setenv_canary_delivered: false,
    };
    assert_eq!(
        unrestricted,
        [
            heimdall_contract::remote::ProbeObservation {
                pty_refused: false,
                ..restricted
            },
            heimdall_contract::remote::ProbeObservation {
                agent_forward_refused: false,
                ..restricted
            },
        ]
    );
    // The first cause stands (a row of the running runner's own database, written by the
    // bridge's own connection; §18.7 item 18).
    assert_eq!(
        recorded_downgrade(&runner.home).as_deref(),
        Some("session_pty")
    );
}

/// ⟨ADR-0006 §18.7 item 17; ADR-0012 §3.2 "Limits"⟩ The bridge checks its own session at
/// start, through the real binary (the forced command, started directly with a cleared
/// environment, so nothing of the test's own session reaches it):
///
/// * neither variable: the session is served (here the remote side closes at once: exit 0),
///   and nothing is recorded;
/// * **`SSH_TTY`** set (sshd allocated a PTY), on one runner, and **`SSH_AUTH_SOCK`** set
///   (sshd forwarded an agent), on another: the session is refused before any frame is read
///   (one `Goodbye`, `CAPABILITY_UNAVAILABLE`, a failing exit), the runner's owner-only
///   record names the cause, and `doctor` reports `runner_sshd_policy_unverifiable`;
/// * the `SetEnv` probe's variable alone: refused, and nothing recorded (the prober's `join`
///   reports it).
#[test]
fn the_bridge_refuses_a_session_with_a_terminal_or_a_forwarded_agent() {
    let scratch = Scratch::new().unwrap();
    let key = MgmtKey::generate().unwrap().public().unwrap();
    let key_text = key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let owner = ClientId::from_random_bytes([0x33; 16]);
    let cases = [
        (
            "t",
            "SSH_TTY",
            "/dev/ttys999",
            Some("session_pty"),
            "allocated a terminal",
        ),
        (
            "a",
            "SSH_AUTH_SOCK",
            "/nonexistent/hm-fixture/agent.sock",
            Some("session_agent_forwarded"),
            "forwarded an agent",
        ),
        (
            "e",
            "HEIMDALL_SETENV_PROBE",
            "1",
            None,
            "delivered a client variable",
        ),
    ];
    for (tag, variable, value, recorded, said) in cases {
        let runner = Runner::named(&scratch, tag);
        let init = envelope(&runner.remote_init(&owner, &key_text, "yes"));
        assert_eq!(init["code"], "OK", "{tag}: {init}");
        // ⟨§18.7 item 18⟩ The downgrade is a row of the runner's state database.
        let record = || recorded_downgrade(&runner.home);
        let bridge = |set: Option<(&str, &str)>| {
            let mut cmd = Command::new(bin());
            cmd.env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &runner.account)
                .args(["remote", "serve", "--client", owner.as_str(), "--home"])
                .arg(&runner.home)
                .stdin(Stdio::null());
            if let Some((name, value)) = set {
                cmd.env(name, value);
            }
            cmd.output().unwrap()
        };
        let served = bridge(None);
        assert!(served.status.success(), "{tag}: {served:?}");
        assert!(served.stdout.is_empty() && record().is_none(), "{tag}");

        let refused = bridge(Some((variable, value)));
        let out = String::from_utf8_lossy(&refused.stdout).into_owned();
        let err = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert_no_canary(&out);
        assert_no_canary(&err);
        assert!(!refused.status.success(), "{tag}: {refused:?}");
        // One frame: a four-byte length, then the goodbye.
        let goodbye: Value = serde_json::from_slice(&refused.stdout[4..]).unwrap();
        assert_eq!(goodbye["type"], "goodbye", "{tag}: {goodbye}");
        assert_eq!(
            goodbye["code"], "CAPABILITY_UNAVAILABLE",
            "{tag}: {goodbye}"
        );
        assert!(
            goodbye["message"].as_str().unwrap().contains(said),
            "{goodbye}"
        );
        assert!(err.contains(said) && !err.contains(value), "{tag}: {err}");

        let doctor = runner
            .command()
            .args(["--json", "doctor"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let report = String::from_utf8_lossy(&doctor.stdout).into_owned();
        assert_no_canary(&report);
        let report = envelope(&report);
        let finding = report["data"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["code"] == "runner_sshd_policy_unverifiable");
        match recorded {
            Some(token) => {
                assert_eq!(record().as_deref(), Some(token), "{tag}");
                assert!(
                    !heimdall_runtime::Paths::under(&runner.home)
                        .state_dir
                        .join("runner-owner-only")
                        .exists(),
                    "{tag}: no marker file"
                );
                let finding = finding.unwrap_or_else(|| panic!("{tag}: no finding: {report}"));
                assert_eq!(finding["severity"], "problem", "{finding}");
                assert!(
                    finding["message"].as_str().unwrap().contains(said),
                    "{finding}"
                );
            }
            None => {
                assert!(
                    record().is_none(),
                    "{tag}: a probe variable records nothing"
                );
                assert!(finding.is_none(), "{tag}: {report}");
            }
        }
    }
}

// --- ⟨M06 W3 `driver`⟩ the controller's sync and issuance driver over a real session --------

/// ⟨M06 W3 `driver`; ADR-0012 §4.2, §7.4; ADR-0006 §18.7 items 11–13⟩ The controller's
/// driver (`heimdall_app::remote_status_driver`) against a real runner runtime, over the
/// fixture sshd and the runner's management line:
///
/// 1. **Pair.** `remote init --issuer-ca` on the runner's terminal enrolls the owner, trusts
///    its CA and designates it time source. The runner holds one grant under a standing
///    policy (seeded in its store before the runtime starts: admission is the runner's).
/// 2. **Reconnect and issue.** The owner session negotiates `runner/1`; the driver runs the
///    reconnect order, the barrier opens, and the grant is issued remotely: prepare on the
///    runner, reserve and publish in the controller's ledger, install on the runner.
/// 3. **Disconnect, revoke while disconnected.** The owner's local revoke of the runner's
///    grant is an outbox row: `remote_pending`, issuance gated, the residual stated.
/// 4. **Reconnect.** The effect is delivered before the report and acknowledged with its
///    enforcement state; the report shows the tombstone; the barrier opens; the view shows
///    it; the revoked grant is never issued for again.
///
/// The controller half is driven at the library level with the adapters the CLI wires (as
/// in the case above). ⟨M06 W3 host⟩ The issuer is the **production** one: the real
/// `heimdall internal issuer` child over the controller's own state database, signing a
/// reservation of kind `remote` (ADR-0005 §3.5 "Remote reservations") with a per-run K_ca
/// held in a scratch secret store (`HEIMDALL_TEST_SECRET_STORE=scratch`; no platform key
/// store is touched). The certificate's content is the controller's record of the grant it
/// delivered; the runner's answer only narrows it.
mod driver_e2e {
    use std::sync::Arc;

    use heimdall_app::OpError;
    use heimdall_app::remote_env::{ManagementCall, ManagementSession, SessionHello};
    use heimdall_app::remote_status::{IssuanceGate, status_of};
    use heimdall_app::remote_status_barrier::CountedResidual;
    use heimdall_app::remote_status_driver::{
        ControllerSync, RemoteIssueInput, SessionChannel, deliver_runner_grant, narrow_runner_grant,
    };
    use heimdall_contract::controller_record::{
        ManagementHop, ManagementRoute, RemoteEnvironmentPin,
    };
    use heimdall_contract::envelope::{Envelope, reason};
    use heimdall_contract::ids::{
        AccountName, DestinationId, EnvironmentId, GrantId, PolicyId, ProfileId,
    };
    use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
    use heimdall_contract::remote::Connectivity;
    use heimdall_contract::request::{
        AccessPairRef, DeadlineIntent, DestinationScopeEnforcement, Enforcement,
        ExistingConnectionsPolicy, NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
    };
    use heimdall_contract::{Code, GrantState, Timestamp};
    use heimdall_credential::cert::SecretCaKey;
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantSnapshot};
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{Capability, Scope};
    use heimdall_domain::time::{Clock, Deadline};
    use heimdall_issuer::client::{ChildCommand, ChildIssuer, ClientConfig};
    use heimdall_issuer::remote::ChildRemoteIssuer;
    use heimdall_issuer::store::SecretStore as _;
    use heimdall_store::ext_effects::AppliedRecord;
    use heimdall_store::{NoFaults, Store};

    use super::*;

    fn pair() -> AccessPairRef {
        AccessPairRef {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn scope() -> Scope {
        Scope {
            pairs: [pair()].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        }
    }

    /// Admission is the runner's: one grant under a standing policy of the runner, written
    /// to its store while no runtime runs (as a covering policy's activation leaves it).
    fn seed_runner_grant(home: &Path, now: Timestamp) -> (EnvironmentId, GrantId) {
        let store = Store::open(&state_db(home), Arc::new(NoFaults)).unwrap();
        let grant = GrantId::from_random_bytes([0x71; 16]);
        let profile = ProfileId::parse("runner-profile").unwrap();
        let env = store
            .transaction(|tx| {
                let env = tx.self_environment()?.expect("a runner environment");
                let mut e = tx.environment(&env)?.unwrap();
                e.permissions = heimdall_domain::environment::EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                };
                tx.upsert_environment(&e)?;
                tx.upsert_profile(&ProfileDefinition {
                    id: profile.clone(),
                    revision: 1,
                    scope: scope(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("runner-pol").unwrap(),
                        revision: PolicyRevision(1),
                        profile: profile.clone(),
                        workspace: None,
                        scope: scope(),
                        environments: [env.clone()].into_iter().collect(),
                        max_window: 4 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: LockBehavior::Continue,
                        connection: ConnectionPolicy::default(),
                        default: false,
                    },
                    false,
                )?;
                tx.upsert_destination(&DestinationRecord {
                    id: DestinationId::parse("h1").unwrap(),
                    alias: "h1".into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: now,
                })?;
                let generation = tx.authority_generation()?;
                tx.insert_grant(&GrantSnapshot {
                    id: grant.clone(),
                    environment: env.clone(),
                    scope: scope(),
                    starts_at: now,
                    deadline: Deadline {
                        intent: DeadlineIntent::Duration("2h".into()),
                        resolved_at: now,
                        effective: plus(now, 2 * HOUR),
                    },
                    parent: None,
                    source: AuthorizationSource::StandingPolicy {
                        revision: PolicyRevision(1),
                    },
                    generation,
                    state: GrantState::Active,
                    enforcement: EnforcementEvidence {
                        report: Enforcement {
                            destination_scope: DestinationScopeEnforcement::ClientRouting,
                            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                            workload_isolation: WorkloadIsolation::SharedOsUser,
                            existing_connections:
                                ExistingConnectionsPolicy::GracefulDedicatedConnections,
                            revocation: RevocationStatus::LocalApplied,
                            identity_selection: None,
                            new_signing_expiry: None,
                            owned_multiplexing: None,
                            remote_processes: None,
                            unmanaged_connections: None,
                            issuer_isolation: None,
                            ordinary_aliases: None,
                            owner_functions: None,
                        },
                        evidence: Vec::new(),
                    },
                })?;
                tx.set_grant_origin(
                    &grant,
                    &GrantOrigin {
                        profile,
                        profile_revision: 1,
                        policy_revision: Some(PolicyRevision(1)),
                        caller: CallerContext {
                            principal: PrincipalRef::UnixUser { uid: 1000 },
                            role: ClientRole::Owner,
                            remote_client: None,
                        },
                        mechanism: "managed_certificate".into(),
                        covered: None,
                        adapter: None,
                        lock_behavior: None,
                        connection: None,
                        workspace: None,
                        policy_id: None,
                    },
                )?;
                Ok(env)
            })
            .unwrap();
        (env, grant)
    }

    /// The controller's production issuer over `home`: K_ca registered `active` in `store`
    /// and held in the scratch secret store, the runtime's time anchor persisted, and the
    /// real `heimdall internal issuer` child started and ready.
    async fn production_issuer(
        home: &Path,
        account: &Path,
        store: &Arc<Store>,
        clock: &Arc<dyn Clock>,
        ca: SecretCaKey,
    ) -> ChildIssuer {
        let paths = heimdall_runtime::Paths::under(home);
        let fingerprint = ca.fingerprint().unwrap();
        let scratch = paths.state_dir.join(SCRATCH_STORE_DIR);
        std::fs::create_dir_all(&scratch).unwrap();
        heimdall_testkit::scratch_store::ScratchSecretStore::new(scratch)
            .put(&fingerprint, &ca)
            .unwrap();
        let now = clock.wall();
        store
            .transaction(|tx| {
                tx.insert_issuer(&heimdall_store::IssuerRecord {
                    ca_fingerprint: fingerprint.clone(),
                    public_key: ca.public_openssh().unwrap(),
                    state: heimdall_contract::issuer::CaState::Active,
                    store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })
            })
            .unwrap();
        drop(ca);
        // The same-boot anchor the issuer child's read-only time assessment needs (the
        // runtime persists it at start).
        heimdall_app::timegate::TimeGate::new(
            store.clone(),
            clock.clone(),
            heimdall_testkit::ScriptedTimeSync::new(
                heimdall_domain::time::SyncStatus::Synchronized,
            ),
            heimdall_domain::time::TimePolicy::default(),
        )
        .check()
        .await
        .unwrap();
        let env = |k: &str, v: &std::ffi::OsStr| (k.into(), v.to_owned());
        let issuer = ChildIssuer::new(ClientConfig::new(
            ChildCommand {
                program: bin().into(),
                args: vec![
                    "--home".into(),
                    home.as_os_str().to_owned(),
                    "internal".into(),
                    "issuer".into(),
                ],
                env: vec![
                    env("HOME", account.as_os_str()),
                    env("HEIMDALL_HOME", home.as_os_str()),
                    env("HEIMDALL_TEST_SSH_HOME", account.as_os_str()),
                    env("HEIMDALL_TEST_SECRET_STORE", "scratch".as_ref()),
                ],
            },
            Arc::new(heimdall_runtime::platform::process_start_time),
        ));
        issuer.start().await.unwrap_or_else(|e| panic!("{e}"));
        let start = Instant::now();
        while issuer.state() != heimdall_contract::issuer::IssuerState::Ready {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "the issuer child did not become ready: {:?}",
                issuer.state()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        issuer
    }

    /// A real management session as the driver's port.
    struct DriverSession {
        inner: Session,
        hello: SessionHello,
    }

    #[async_trait::async_trait]
    impl ManagementSession for DriverSession {
        fn hello(&self) -> &SessionHello {
            &self.hello
        }

        fn runner_negotiated(&self) -> bool {
            self.inner
                .client
                .server()
                .capabilities
                .contains(capability::RUNNER_V1)
        }

        async fn call(&mut self, call: ManagementCall) -> Result<Envelope<Value>, OpError> {
            self.inner
                .client
                .request(call.into_request())
                .await
                .map_err(|_| OpError::new(Code::OutcomeUnknown, "the management session ended"))
        }
    }

    async fn open(
        dir: &Path,
        sshd: &LoopbackSshd,
        account: &str,
        key: &MgmtKey,
        environment: &str,
    ) -> DriverSession {
        let key = MgmtKey::from_store_bytes(&key.to_store_bytes()).unwrap();
        let public = key.public().unwrap();
        let signer =
            MgmtSigner::with_host_key_lines(key, [account.to_owned()], &[host_key(sshd)]).unwrap();
        let agent = SessionAgent::start(&dir.join("a.sock"), signer).unwrap();
        let (client, child) =
            connect_offering(dir, sshd, account, &public.openssh_line, environment, true)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        let hello = SessionHello {
            environment: client.server().environment_id.clone(),
            role: client.server().role,
            client: client.server().remote_client.clone(),
        };
        DriverSession {
            inner: Session {
                client,
                _child: child,
                agent,
            },
            hello,
        }
    }

    async fn close(session: DriverSession) {
        let DriverSession { inner, .. } = session;
        let Session {
            client,
            _child: mut child,
            agent,
        } = inner;
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
        agent.stop().await;
    }

    #[tokio::test]
    async fn the_driver_issues_revokes_while_disconnected_and_resynchronizes() {
        let scratch = Scratch::new().unwrap();
        let mut runner = Runner::new(&scratch);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let client = ClientId::from_random_bytes([0x5c; 16]);
        let ca = SecretCaKey::generate().unwrap();
        let ca_line = ca.public_openssh().unwrap();

        // 1. Pair: the runner-local bootstrap, with the controller's CA (issuer_trust and
        // the time-source designation, confirmed on the runner's terminal).
        let first = envelope(&runner.remote_init_with(
            &client,
            &key_text,
            "yes",
            &["--issuer-ca", ca_line.trim()],
        ));
        assert_eq!(first["code"], "OK", "{first}");
        let clock: Arc<dyn Clock> = Arc::new(heimdall_runtime::platform::SystemClock);
        let seeded_at = clock.wall();
        let (environment, grant) = seed_runner_grant(&runner.home, seeded_at);
        assert_eq!(first["data"]["environment"], environment.as_str());
        runner.start();

        // The fixture sshd reads the runner account's authorized_keys, as in the case above.
        let sshd = match LoopbackSshd::start(
            &scratch,
            SshdConfig {
                registry_seed: Some(Vec::new()),
                ..SshdConfig::default()
            },
        ) {
            Ok(s) => s,
            Err(e) => {
                #[allow(clippy::print_stderr)] // the blocked row's reason
                {
                    eprintln!("m06 driver e2e: blocked (no fixture sshd: {e})");
                }
                return;
            }
        };
        let account = sshd
            .login_account()
            .or_else(current_account)
            .expect("the fixture account");
        let Some(registry) = sshd.registry_path().map(Path::to_path_buf) else {
            #[allow(clippy::print_stderr)] // the blocked row's reason
            {
                eprintln!("m06 driver e2e: blocked (the fixture sshd has no local registry)");
            }
            return;
        };
        std::fs::remove_file(&registry).unwrap();
        std::os::unix::fs::symlink(runner.account.join(".ssh/authorized_keys"), &registry).unwrap();

        // The controller: its own store (where a controller home keeps it, so its issuer
        // child reads the same database), its pin of the runner, and the driver.
        let controller_home = scratch.subdir("ch").unwrap();
        let controller_account = scratch.subdir("ca").unwrap();
        let controller_paths = heimdall_runtime::Paths::under(&controller_home);
        controller_paths.ensure().unwrap();
        let store = Arc::new(
            Store::open(
                &controller_paths
                    .state_dir
                    .join(heimdall_runtime::service::STATE_DB_FILE),
                Arc::new(NoFaults),
            )
            .unwrap(),
        );
        let pin = RemoteEnvironmentPin {
            environment: environment.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: AccountName::parse(&account).unwrap(),
                    host_keys: vec![host_key(&sshd)],
                },
                jump: None,
            },
            client: client.clone(),
            role: Role::Owner,
            key_fingerprint: public.fingerprint.clone(),
            label: None,
            pinned_at: clock.wall(),
        };
        store
            .transaction(|tx| {
                tx.init_self_environment(&EnvironmentId::from_random_bytes([0x2c; 16]))?;
                tx.put_remote_environment_pin(
                    &pin.environment,
                    &pin.destination,
                    &pin.route.runner.account,
                    &pin.key_fingerprint,
                    &serde_json::to_string(&pin).unwrap(),
                    pin.pinned_at,
                )
            })
            .unwrap();
        let driver = ControllerSync::new(store.clone(), clock.clone());
        let ca_fingerprint = ca.fingerprint().unwrap();
        let child =
            production_issuer(&controller_home, &controller_account, &store, &clock, ca).await;
        let issuer = ChildRemoteIssuer::new(store.clone(), Arc::new(child.clone()));
        // Nothing is issued for a grant this controller holds no record of delivering; the
        // record is the certificate's content (pairs, extensions, expiry).
        let delivered_until = plus(seeded_at, 2 * HOUR);
        store
            .transaction(|tx| {
                deliver_runner_grant(
                    tx,
                    &pin,
                    &grant,
                    &[pair()].into(),
                    &["permit-pty".to_owned()].into(),
                    delivered_until,
                    clock.wall(),
                )
            })
            .unwrap()
            .unwrap();
        let view = |open: bool| {
            store
                .transaction(|tx| {
                    status_of(tx, &environment, open, Some(driver.barrier()), clock.wall())
                })
                .unwrap()
        };
        let never = view(false);
        assert!(matches!(
            never.connectivity,
            Connectivity::Unreachable { .. }
        ));
        assert_eq!(never.issuance, IssuanceGate::AwaitingResync);

        // 2. Reconnect: the owner session has runner/1; the reconnect order opens the barrier.
        let dir = scratch.subdir("cs1").unwrap();
        let mut session = open(&dir, &sshd, &account, &key, environment.as_str()).await;
        assert!(
            session.runner_negotiated(),
            "an owner session negotiates runner/1"
        );
        let first_sync = driver.on_session(&pin, &mut session).await.unwrap();
        assert!(first_sync.acknowledged.is_empty());
        assert!(
            first_sync.time_bounded,
            "the designated time source's sample was accepted"
        );
        assert!(first_sync.report.tombstones.is_empty());
        let connected = view(true);
        assert_eq!(connected.connectivity, Connectivity::Connected);
        assert_eq!(connected.issuance, IssuanceGate::Reconciled);

        // Issue remotely: prepare (runner), reserve and publish (this ledger), install (runner).
        let issued = {
            let mut channel = SessionChannel::new(&mut session).unwrap();
            driver
                .issue(
                    &pin,
                    &mut channel,
                    &issuer,
                    &RemoteIssueInput {
                        grant: grant.clone(),
                        grant_generation: first_sync.report.authority_generation,
                        lifetime: Duration::from_secs(30 * 60),
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
        };
        assert_eq!(issued.certificates.len(), 1);
        let valid_before = issued.certificates[0].valid_before;
        // The ledger entry was signed by the production issuer child as a reservation of
        // kind `remote`: published, under this controller's CA, with exactly the delivered
        // content (one principal, the delivered extension), inside the delivered expiry,
        // and whole seconds (a certificate carries no fraction: the runner's report below
        // states the same instant).
        let entry = store
            .transaction(|tx| tx.issuance_entry(&issued.certificates[0].issuance))
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.state,
            heimdall_domain::issuance::IssuanceState::Published
        );
        assert_eq!(entry.bounds.ca_fingerprint.as_ref(), Some(&ca_fingerprint));
        assert_eq!(
            entry.bounds.principal,
            heimdall_domain::issuance::principal_for(&pair())
        );
        assert_eq!(
            entry.bounds.extensions,
            ["permit-pty".to_owned()].into_iter().collect()
        );
        assert!(valid_before <= delivered_until);
        assert_eq!(valid_before.subsec_nanosecond(), 0);
        assert!(entry.bounds.key_id.contains(environment.as_str()));
        // The runner reports the certificate installed, issued by this controller.
        let after_issue = driver.on_session(&pin, &mut session).await.unwrap();
        assert_eq!(after_issue.report.certificates.len(), 1);
        assert_eq!(after_issue.report.certificates[0].grant, grant);
        assert_eq!(after_issue.report.certificates[0].issuer, client);
        assert_eq!(
            after_issue.report.certificates[0].valid_before,
            valid_before
        );

        // 3. Disconnect; the owner's local revoke of the runner's grant while disconnected.
        close(session).await;
        driver.session_closed(&environment);
        let narrowed = store
            .transaction(|tx| narrow_runner_grant(tx, &grant, clock.wall()))
            .unwrap()
            .expect("the ledger ties the grant to the runner")
            .unwrap();
        assert!(narrowed.produced);
        assert_eq!(narrowed.environment, environment);
        assert_eq!(
            narrowed.residual,
            Some(CountedResidual::Until(valid_before))
        );
        let away = view(false);
        assert!(matches!(
            away.connectivity,
            Connectivity::Disconnected { .. }
        ));
        assert_eq!(away.remote_pending.len(), 1);
        assert_eq!(away.issuance, IssuanceGate::AwaitingResync);
        assert_eq!(away.residuals.len(), 1);
        assert!(!away.residuals[0].acknowledged);
        assert!(away.last_known_readiness.iter().any(|r| r.grant == grant));

        // 4. Reconnect: delivered before the report, acknowledged with its enforcement
        // state; the report shows the tombstone; the barrier opens; the view shows it.
        let dir = scratch.subdir("cs2").unwrap();
        let mut session = open(&dir, &sshd, &account, &key, environment.as_str()).await;
        let resynced = driver.on_session(&pin, &mut session).await.unwrap();
        assert_eq!(resynced.acknowledged.len(), 1);
        assert_eq!(resynced.acknowledged[0].key, narrowed.key);
        assert!(matches!(
            &resynced.acknowledged[0].record,
            AppliedRecord::GrantTombstone {
                grant: g,
                known: true,
                key_destroyed: true,
                ..
            } if *g == grant
        ));
        assert!(resynced.report.tombstones.iter().any(|t| t.grant == grant));
        assert!(
            resynced.report.certificates.is_empty(),
            "K_env and its certificate are gone"
        );
        assert!(
            resynced
                .revoked
                .iter()
                .any(|r| r.grant == grant && r.residual == CountedResidual::Until(valid_before))
        );
        let back = view(true);
        assert_eq!(back.connectivity, Connectivity::Connected);
        assert!(back.remote_pending.is_empty());
        assert_eq!(back.issuance, IssuanceGate::Reconciled);
        assert!(back.residuals[0].acknowledged);
        assert!(
            back.residuals[0]
                .statement
                .contains("plus an unmeasured destination-clock error"),
            "{}",
            back.residuals[0].statement
        );
        // `environment status --json`: the remote fields sit in the environment's entry.
        let entry = serde_json::to_value(heimdall_app::remote_env::EnvironmentStatus {
            record: pin.clone(),
            remote: Some(back),
        })
        .unwrap();
        assert_eq!(entry["environment"], environment.as_str());
        assert_eq!(entry["connectivity"]["state"], "connected");
        assert_eq!(entry["issuance"], "reconciled");
        assert_eq!(entry["residuals"][0]["acknowledged"], true);

        // A revoked grant is never issued for again: refused by the barrier, nothing sent.
        let e = {
            let mut channel = SessionChannel::new(&mut session).unwrap();
            driver
                .issue(
                    &pin,
                    &mut channel,
                    &issuer,
                    &RemoteIssueInput {
                        grant: grant.clone(),
                        grant_generation: resynced.report.authority_generation,
                        lifetime: Duration::from_secs(60),
                    },
                )
                .await
                .unwrap_err()
        };
        assert_eq!(e.code, Code::CredentialExpired, "{e:?}");
        assert_ne!(e.reason.as_deref(), Some(reason::RESYNC_PENDING));
        close(session).await;
        driver.session_closed(&environment);
        assert_eq!(view(false).issuance, IssuanceGate::AwaitingResync);
        child.stop().await;
        drop(sshd);
    }

    /// ⟨M06 W3 host⟩ Remote issuance in the product: the controller's **runtime** hosts the
    /// driver. A real `heimdall service run` on the controller (scratch home, K_mgmt in a
    /// fixture file store, K_ca in the scratch secret store) reconnects to the recorded
    /// runner over its management line, runs the reconnect order, and issues for the grant
    /// this controller delivered: its own issuer child signs the `remote` reservation and
    /// the runner installs the certificate. `environment status` (a one-shot CLI read)
    /// reports it: connected, issuance open, the grant's last-known readiness. The owner's
    /// local `revoke` of the runner's grant then answers `OK` with `local_applied: false`
    /// and the grant `remote_pending`, the hosted driver delivers it at once, and the status
    /// shows the revoke applied on the runner.
    #[tokio::test]
    async fn the_controllers_runtime_hosts_the_driver_and_reports_through_environment_status() {
        let scratch = Scratch::new().unwrap();
        let mut runner = Runner::new(&scratch);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let client = ClientId::from_random_bytes([0x5d; 16]);
        let ca = SecretCaKey::generate().unwrap();
        let ca_line = ca.public_openssh().unwrap();
        let first = envelope(&runner.remote_init_with(
            &client,
            &key_text,
            "yes",
            &["--issuer-ca", ca_line.trim()],
        ));
        assert_eq!(first["code"], "OK", "{first}");
        let clock: Arc<dyn Clock> = Arc::new(heimdall_runtime::platform::SystemClock);
        let seeded_at = clock.wall();
        let (environment, grant) = seed_runner_grant(&runner.home, seeded_at);
        runner.start();
        let sshd = match LoopbackSshd::start(
            &scratch,
            SshdConfig {
                registry_seed: Some(Vec::new()),
                ..SshdConfig::default()
            },
        ) {
            Ok(s) => s,
            Err(e) => {
                #[allow(clippy::print_stderr)] // the blocked row's reason
                {
                    eprintln!("m06 hosted driver e2e: blocked (no fixture sshd: {e})");
                }
                return;
            }
        };
        let account = sshd
            .login_account()
            .or_else(current_account)
            .expect("the fixture account");
        let Some(registry) = sshd.registry_path().map(Path::to_path_buf) else {
            #[allow(clippy::print_stderr)] // the blocked row's reason
            {
                eprintln!(
                    "m06 hosted driver e2e: blocked (the fixture sshd has no local registry)"
                );
            }
            return;
        };
        std::fs::remove_file(&registry).unwrap();
        std::os::unix::fs::symlink(runner.account.join(".ssh/authorized_keys"), &registry).unwrap();

        // The controller installation, written while no runtime runs: its K_mgmt (fixture
        // file store), its CA (registered; the key in the scratch secret store), its record
        // of the runner and of the grant it delivered there.
        let mut controller = ControllerRuntime {
            home: scratch.subdir("ch").unwrap(),
            account: scratch.subdir("ca").unwrap(),
            mgmt: scratch.subdir("cm").unwrap().join("k_mgmt.fixture"),
            runtime: None,
        };
        {
            use heimdall_credential::mgmt::MgmtKeyStore as _;
            heimdall_credential::mgmt::fixture::FixtureMgmtStore::file(controller.mgmt.clone())
                .put(&key)
                .unwrap();
        }
        let paths = heimdall_runtime::Paths::under(&controller.home);
        paths.ensure().unwrap();
        let pin = RemoteEnvironmentPin {
            environment: environment.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: sshd.host.clone(),
                    port: Some(sshd.port),
                    account: AccountName::parse(&account).unwrap(),
                    host_keys: vec![host_key(&sshd)],
                },
                jump: None,
            },
            client: client.clone(),
            role: Role::Owner,
            key_fingerprint: public.fingerprint.clone(),
            label: None,
            pinned_at: seeded_at,
        };
        {
            let store = Store::open(
                &paths
                    .state_dir
                    .join(heimdall_runtime::service::STATE_DB_FILE),
                Arc::new(NoFaults),
            )
            .unwrap();
            let fingerprint = ca.fingerprint().unwrap();
            let secrets = paths.state_dir.join(SCRATCH_STORE_DIR);
            std::fs::create_dir_all(&secrets).unwrap();
            heimdall_testkit::scratch_store::ScratchSecretStore::new(secrets)
                .put(&fingerprint, &ca)
                .unwrap();
            store
                .transaction(|tx| {
                    tx.init_self_environment(&EnvironmentId::from_random_bytes([0x2d; 16]))?;
                    tx.insert_issuer(&heimdall_store::IssuerRecord {
                        ca_fingerprint: fingerprint.clone(),
                        public_key: ca.public_openssh().unwrap(),
                        state: heimdall_contract::issuer::CaState::Active,
                        store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
                        backup_sha256: "ab".repeat(32),
                        backup_created_at: seeded_at,
                        restored_without_log: false,
                        created_at: seeded_at,
                        retired_at: None,
                    })?;
                    tx.put_remote_environment_pin(
                        &pin.environment,
                        &pin.destination,
                        &pin.route.runner.account,
                        &pin.key_fingerprint,
                        &serde_json::to_string(&pin).unwrap(),
                        pin.pinned_at,
                    )?;
                    Ok(deliver_runner_grant(
                        tx,
                        &pin,
                        &grant,
                        &[pair()].into(),
                        &["permit-pty".to_owned()].into(),
                        plus(seeded_at, 2 * HOUR),
                        seeded_at,
                    )?
                    .map(drop))
                })
                .unwrap()
                .unwrap();
        }
        drop(ca);

        // Before any runtime: never reached, issuance gated.
        let never = controller.status(&environment);
        assert_eq!(never["connectivity"]["state"], "unreachable", "{never}");
        assert_eq!(never["issuance"], "awaiting_resync");

        controller.start();
        // The hosted driver reconnected, resynchronized and issued; the status shows it.
        let ready = controller.wait_for(&environment, "the hosted driver did not issue", |e| {
            e["last_known_readiness"]
                .as_array()
                .is_some_and(|r| r.iter().any(|g| g["grant"] == grant.as_str()))
        });
        assert_eq!(ready["connectivity"]["state"], "connected", "{ready}");
        assert_eq!(ready["issuance"], "reconciled");
        assert!(ready.get("issuance_failures").is_none(), "{ready}");
        assert_eq!(ready["last_known_readiness"][0]["state"], "within_bound");
        // The runner holds exactly one certificate, issued by this controller.
        let readiness = &ready["last_known_readiness"][0];
        let until: Timestamp = readiness["offline_until"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            until,
            plus(seeded_at, 2 * HOUR),
            "valid to the delivered bound"
        );

        // The owner's local revoke of the runner's grant.
        let revoked = controller.json(&["access", "revoke", grant.as_str()]);
        assert_eq!(revoked["code"], "OK", "{revoked}");
        assert_eq!(revoked["data"]["local_applied"], false);
        assert_eq!(revoked["data"]["remote_pending"][0], grant.as_str());
        let applied = controller.wait_for(&environment, "the revoke was not delivered", |e| {
            e["residuals"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x["acknowledged"] == true))
        });
        assert!(applied["remote_pending"].as_array().unwrap().is_empty());
        assert_eq!(applied["residuals"][0]["grant"], grant.as_str());
        // The certificate is gone from the runner's next report, and nothing is issued for
        // the revoked grant again.
        let gone = controller.wait_for(
            &environment,
            "the runner still reports the certificate",
            |e| e.get("last_known_readiness").is_none(),
        );
        assert!(gone.get("issuance_failures").is_none(), "{gone}");
        drop(controller);
        drop(sshd);
    }

    // --- ⟨M06 W4 grant-e2e⟩ the journey with real binaries -----------------------------------

    /// ⟨M06 W4 `grant-e2e`; m06-plan §2 "What W3 carries" items 1 and 4; ADR-0012 §4 item 2
    /// ⟨2026-11-21⟩, §7; ADR-0005 §3.5 "Remote reservations"; spec A24's core⟩ **The journey,
    /// with real binaries on both sides.**
    ///
    /// 1. On the controller: `heimdall access ensure --environment <runner>` names no pair.
    ///    The controller's runtime resolves the scope from its own copy of the profile,
    ///    forwards the request (each pair naming the CA it will issue from), and records
    ///    what it asked. The runner admits the grant under its own standing policy, resolves
    ///    the pair to a managed certificate under its `issuer_trust` for that controller, and
    ///    waits. The controller's production issuer child signs the `remote` reservation; the
    ///    runner installs the certificate and its waiting `ensure` settles. The local caller
    ///    gets the runner's result, or the pending state and then `operation wait`.
    /// 2. On the runner: a local `access ensure` covered by that live grant attaches to it
    ///    (a new binding on the same grant). Its endpoint lists exactly one identity: the
    ///    certificate of the runner's K_env for that grant, signed by the controller's CA.
    /// 3. **The controller is stopped.** An onward `ssh` from the runner through that
    ///    endpoint to a fixture destination that trusts the CA succeeds.
    /// 4. The controller comes back while the runner cannot be reached; the owner's
    ///    `access revoke` answers `remote_pending`, and the runner still serves the grant.
    ///    Once the runner is reachable again the revoke is applied: acknowledged in
    ///    `environment status`, the endpoint lists nothing, and an onward login fails.
    #[tokio::test]
    async fn a_forwarded_ensure_reaches_onward_ssh_from_the_runner_with_the_controller_stopped() {
        let Some(mut j) = journey(|_| Vec::new(), 4 * HOUR) else {
            return;
        };
        let environment = j.environment.clone();
        let account = j.account.clone();
        let principal = j.principal.clone();
        let ca_fingerprint = j.ca_fingerprint.clone();

        // 1. The owner's `ensure --environment <runner>`, naming no pair.
        let forward = [
            "access",
            "ensure",
            "--profile",
            "runner-profile",
            "--environment",
            environment.as_str(),
            "--work-id",
            "job-1",
            "--for",
            "1h",
            "--request-id",
            "fwd-1",
        ];
        let mut answer = j.controller.json(&forward);
        if answer["code"] == "ACCEPTED" {
            // The pending state: no reason, the refresh dependency, the grant pending; the
            // operation it names is driven by `operation wait`.
            let data = &answer["data"];
            assert!(data["error"].get("reason").is_none(), "{answer}");
            assert_eq!(data["refresh_dependency"], "controller", "{answer}");
            assert_eq!(
                data["remote_pending"][0], data["error"]["resource"]["id"],
                "{answer}"
            );
            let operation = answer["operation_id"]
                .as_str()
                .unwrap_or_else(|| panic!("the pending answer names no operation: {answer}"))
                .to_owned();
            answer = j
                .controller
                .json(&["operation", "wait", &operation, "--timeout-ms", "60000"]);
        }
        assert_eq!(
            answer["code"],
            "OK",
            "{answer}\n{}\n{}\n{}",
            j.controller.stderr(),
            std::fs::read_to_string(j.runner.account.join("runtime.stderr")).unwrap_or_default(),
            j.controller.status(&environment)
        );
        let ready = answer["data"].clone();
        let grant = GrantId::parse(ready["grant_id"].as_str().unwrap()).unwrap();
        assert_eq!(ready["environment_id"], environment.as_str());
        assert_eq!(ready["credential_mechanism"], "managed_certificate");
        assert_eq!(ready["refresh_dependency"], "controller");
        // The same request again reads the same grant and reserves nothing more.
        let again = j.controller.json(&forward);
        assert_eq!(again["code"], "OK", "{again}");
        assert_eq!(again["data"]["grant_id"], grant.as_str());
        let status = j
            .controller
            .wait_for(&environment, "the grant is not reported", |e| {
                e["last_known_readiness"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|g| g["grant"] == grant.as_str()))
            });
        assert_eq!(status["connectivity"]["state"], "connected", "{status}");
        assert!(status.get("issuance_failures").is_none(), "{status}");

        // 2. On the runner: a local `ensure` covered by the live grant attaches to it.
        let local = j
            .runner
            .command()
            .args([
                "--json",
                "access",
                "ensure",
                "--profile",
                "runner-profile",
                "--pair",
                &format!("h1:{account}"),
                "--work-id",
                "job-local",
                "--for",
                "30m",
                "--request-id",
                "local-1",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let local: Value = serde_json::from_slice(&local.stdout).unwrap_or_else(|_| {
            panic!(
                "{} {}",
                String::from_utf8_lossy(&local.stdout),
                String::from_utf8_lossy(&local.stderr)
            )
        });
        assert!(
            matches!(local["code"].as_str(), Some("OK" | "ACCESS_READY")),
            "{local}"
        );
        assert_eq!(local["data"]["grant_id"], grant.as_str(), "the same grant");
        assert_ne!(local["data"]["binding_id"], ready["binding_id"], "{local}");
        assert_eq!(local["data"]["refresh_dependency"], "controller");
        let endpoint = local["data"]["consumer"]["signing_endpoint"]
            .as_str()
            .unwrap_or_else(|| panic!("the binding names no endpoint: {local}"))
            .to_owned();
        // The endpoint lists exactly the runner's K_env certificate for that grant.
        let listed = listed_identities(&endpoint);
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert!(listed[0].starts_with("ssh-ed25519-cert-v01@openssh.com "));
        let facts =
            heimdall_issuer::remote::read_certificate(&listed[0]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(facts.ca_fingerprint, ca_fingerprint);
        assert_eq!(facts.principals, vec![principal.clone()]);
        assert!(
            facts.key_id.contains(environment.as_str()),
            "{}",
            facts.key_id
        );
        assert!(facts.key_id.contains(grant.as_str()), "{}", facts.key_id);
        assert_ne!(
            facts.subject_fingerprint,
            j.mgmt_fingerprint.as_str(),
            "never K_mgmt"
        );
        // The binding the forwarded request created lists the same single identity.
        let forwarded_endpoint = ready["consumer"]["signing_endpoint"].as_str().unwrap();
        assert_eq!(listed_identities(forwarded_endpoint), listed);

        // 3. The controller is stopped; the runner goes on.
        j.controller.runtime_stop();
        let dir = j.scratch.subdir("onward").unwrap();
        let mark = j.destination.log_mark();
        let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
        assert!(
            ok,
            "onward ssh with the controller stopped: {out}\n{}",
            std::fs::read_to_string(j.runner.account.join("runtime.stderr")).unwrap_or_default()
        );
        let accepted = j.destination.accepted_certificates();
        assert!(
            accepted.iter().any(|c| c.key_id == facts.key_id
                && c.serial == facts.serial
                && c.ca_fingerprint == ca_fingerprint.as_str()),
            "{accepted:?} {:?}",
            j.destination.log_lines_since(mark, "Accepted")
        );

        // 4. The controller is back, the runner unreachable: the revoke is pending.
        j.reachable(false);
        j.controller.start();
        let away = j
            .controller
            .wait_for(&environment, "the runner is still reachable", |e| {
                e["connectivity"]["state"] != "connected"
            });
        assert_eq!(away["issuance"], "awaiting_resync", "{away}");
        let revoked = j.controller.json(&["access", "revoke", grant.as_str()]);
        assert_eq!(revoked["code"], "OK", "{revoked}");
        assert_eq!(revoked["data"]["local_applied"], false);
        assert_eq!(revoked["data"]["remote_pending"][0], grant.as_str());
        let pending = j.controller.status(&environment);
        assert_eq!(
            pending["remote_pending"].as_array().unwrap().len(),
            1,
            "{pending}"
        );
        // Not applied yet: the runner still serves the grant.
        assert_eq!(listed_identities(&endpoint), listed);
        let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
        assert!(ok, "the revoke is only pending: {out}");

        // Reachable again: an owner-awaited pass (the same forwarded request) reconnects
        // at once; the reconnect order delivers the revoke before anything else.
        j.reachable(true);
        let _ = j.controller.json(&forward);
        let applied = j
            .controller
            .wait_for(&environment, "the revoke was not applied", |e| {
                e["residuals"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|x| x["acknowledged"] == true))
            });
        assert!(
            applied["remote_pending"].as_array().unwrap().is_empty(),
            "{applied}"
        );
        assert_eq!(applied["residuals"][0]["grant"], grant.as_str());
        assert!(
            listed_identities(&endpoint).is_empty(),
            "nothing after the revoke"
        );
        let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
        assert!(!ok, "no onward login after the revoke: {out}");
        drop(j);
    }

    /// ⟨M06 W5 `sourceb`; m06-plan §2 item 3 "Record source (b)"; ADR-0005 §3.5 condition 8
    /// (b); ADR-0012 §4 item 2 ⟨2026-11-21⟩; spec A07's unattended shape⟩ **Record source
    /// (b), with real binaries on both sides and no forwarded `ensure`.**
    ///
    /// 1. On the controller, the owner at a terminal reviews and approves a personal policy
    ///    that names the runner (`access allow --profile <p> --environment <runner>`). The
    ///    same command without a terminal applies nothing. The policy activates nothing on
    ///    the controller: a local `ensure` for the profile there is not covered by it.
    /// 2. On the runner, its local owner at a terminal makes `ensure` requests that name the
    ///    controller's CA (`--issuer-ca`, a CA in the runner's `issuer_trust`); the runner
    ///    admits each under its own standing policy as a **pending** grant. Without a
    ///    terminal the flag sends nothing. Three of them are outside the controller's
    ///    policy: a pair it does not hold, a principal it does not hold, and a deadline
    ///    later than its expiry (the cutoff the owner set on it). One is inside. (A
    ///    deadline later than the policy's maximum lifetime cannot be produced here: both
    ///    runtimes cap a window at 12 h. `integration_controller_driver_m06` covers it.)
    /// 3. The controller's host, which forwarded nothing, signs for the grant inside its
    ///    policy, and only for that one: the runner installs the certificate and the
    ///    waiting `ensure` settles. The three outside are never recorded, reserved or
    ///    signed, and stay pending.
    /// 4. **The controller is stopped.** An onward `ssh` from the runner through the
    ///    binding's endpoint to the fixture destination succeeds.
    #[tokio::test]
    async fn a_controller_policy_naming_the_runner_issues_for_a_runner_originated_grant() {
        // The runner's own policy admits more than the controller's copy of the profile
        // holds: a second destination, a second account, and a day's window.
        let Some(mut j) = journey(
            |account| {
                vec![
                    AccessPairRef {
                        destination: DestinationId::parse("h2").unwrap(),
                        account: AccountName::parse(account).unwrap(),
                    },
                    AccessPairRef {
                        destination: DestinationId::parse("h1").unwrap(),
                        account: AccountName::parse("hm-other").unwrap(),
                    },
                ]
            },
            24 * HOUR,
        ) else {
            return;
        };
        let environment = j.environment.clone();
        let account = j.account.clone();
        let ca = j.ca_fingerprint.as_str().to_owned();
        let inside_pair = format!(
            "{}:{}",
            j.pair.destination.as_str(),
            j.pair.account.as_str()
        );

        // 1. The controller's policy naming the runner. Without a terminal: a decision to
        // approve, nothing applied.
        let allow = [
            "access",
            "allow",
            "--profile",
            "runner-profile",
            "--environment",
            environment.as_str(),
        ];
        let unattended = j.controller.json(&allow);
        assert!(
            matches!(
                unattended["code"].as_str(),
                Some("INTERACTION_REQUIRED" | "APPROVAL_REQUIRED")
            ),
            "{unattended}"
        );
        let policies = |c: &ControllerRuntime| {
            let store = Store::open_read_only(&state_db(&c.home), Arc::new(NoFaults)).unwrap();
            // The debug build seeds its own environment's fixture policies: only the
            // policies for this profile count here.
            let mut all = store.transaction(|tx| tx.policies()).unwrap();
            all.retain(|p| p.profile.as_str() == "runner-profile");
            all
        };
        assert!(
            policies(&j.controller).is_empty(),
            "nothing applied unattended: {unattended} {:?}",
            policies(&j.controller)
        );
        // Declined at the terminal: nothing applied either.
        let (_, declined) = j.controller.attended(&allow, Some("no"));
        assert_ne!(declined["code"], "OK", "{declined}");
        assert!(
            policies(&j.controller).is_empty(),
            "nothing applied on `no`"
        );
        // Reviewed and approved by the owner at the terminal.
        let (code, allowed) = j.controller.attended(&allow, Some("yes"));
        assert_eq!(allowed["code"], "OK", "exit {code}: {allowed}");
        let held = policies(&j.controller);
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0].environments, BTreeSet::from([environment.clone()]));
        assert_eq!(held[0].scope.pairs, BTreeSet::from([j.pair.clone()]));
        assert!(!held[0].default && held[0].workspace.is_none());
        // The owner bounds it: no grant may run past this instant under it.
        let expiry = plus(
            heimdall_runtime::platform::SystemClock.wall(),
            Duration::from_secs(20 * 60),
        );
        let cut = j.controller.json(&[
            "access",
            "cutoff",
            held[0].id.as_str(),
            "--at",
            &expiry.to_string(),
        ]);
        assert_eq!(cut["code"], "OK", "{cut}");
        assert!(policies(&j.controller)[0].cutoff_at.is_some(), "{cut}");
        // It activates nothing here: the controller's own environment has no policy for
        // the profile, so a local `ensure` is not covered.
        let local = j.controller.json(&[
            "access",
            "ensure",
            "--profile",
            "runner-profile",
            "--work-id",
            "job-controller-local",
            "--for",
            "10m",
            "--request-id",
            "ctl-local-1",
        ]);
        assert!(
            !matches!(
                local["code"].as_str(),
                Some("OK" | "ACCESS_READY" | "ACCEPTED")
            ),
            "{local}"
        );

        // 2. The runner's local owner names the controller's CA. Never without a terminal.
        let ensure = |work: &str, request: &str, pair: &str, lifetime: &str| {
            [
                "access",
                "ensure",
                "--profile",
                "runner-profile",
                "--pair",
                pair,
                "--work-id",
                work,
                "--for",
                lifetime,
                "--request-id",
                request,
                "--issuer-ca",
                ca.as_str(),
            ]
            .map(str::to_owned)
        };
        let refs = |args: &[String]| -> Vec<String> { args.to_vec() };
        let no_terminal = j
            .runner
            .command()
            .arg("--json")
            .args(refs(&ensure("job-nt", "nt-1", &inside_pair, "30m")))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let no_terminal: Value = serde_json::from_slice(&no_terminal.stdout).unwrap();
        assert_eq!(no_terminal["code"], "INTERACTION_REQUIRED", "{no_terminal}");
        let attended = |args: [String; 14]| {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            runner_attended(&j.runner, &args)
        };
        // Outside the controller's policy: a pair, a principal, a deadline.
        let (_, a) = attended(ensure(
            "job-pair",
            "out-pair",
            &format!("h2:{account}"),
            "10m",
        ));
        let outside_pair = pending_grant(&a);
        let (_, a) = attended(ensure(
            "job-principal",
            "out-principal",
            "h1:hm-other",
            "10m",
        ));
        let outside_principal = pending_grant(&a);
        let (_, a) = attended(ensure("job-deadline", "out-deadline", &inside_pair, "30m"));
        let outside_deadline = pending_grant(&a);
        // Inside it.
        let (_, mut answer) = attended(ensure("job-b", "b-1", &inside_pair, "10m"));
        let grant = if answer["code"] == "ACCEPTED" {
            let grant = pending_grant(&answer);
            let operation = answer["operation_id"]
                .as_str()
                .unwrap_or_else(|| panic!("the pending answer names no operation: {answer}"))
                .to_owned();
            // 3. Nothing was forwarded: the controller's host adopts and signs on its own
            // pass (every 30 s).
            let waited = j
                .runner
                .command()
                .args(["--json", "operation", "wait", &operation])
                .args(["--timeout-ms", "120000"])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            answer = serde_json::from_slice(&waited.stdout).unwrap_or_else(|_| {
                panic!(
                    "{} {}",
                    String::from_utf8_lossy(&waited.stdout),
                    String::from_utf8_lossy(&waited.stderr)
                )
            });
            grant
        } else {
            GrantId::parse(answer["data"]["grant_id"].as_str().unwrap_or_default()).unwrap()
        };
        assert!(
            matches!(answer["code"].as_str(), Some("OK" | "ACCESS_READY")),
            "{answer}\n{}\n{}\n{}",
            j.controller.stderr(),
            std::fs::read_to_string(j.runner.account.join("runtime.stderr")).unwrap_or_default(),
            j.controller.status(&environment)
        );
        // `operation wait` answers the operation, with the `ensure` result inside.
        let ready = match answer["data"].get("result") {
            Some(result) => result.clone(),
            None => answer["data"].clone(),
        };
        assert_eq!(ready["grant_id"], grant.as_str(), "{answer}");
        assert_eq!(ready["credential_mechanism"], "managed_certificate");
        assert_eq!(ready["refresh_dependency"], "controller");
        let endpoint = ready["consumer"]["signing_endpoint"]
            .as_str()
            .unwrap_or_else(|| panic!("the binding names no endpoint: {ready}"))
            .to_owned();
        let listed = listed_identities(&endpoint);
        assert_eq!(listed.len(), 1, "{listed:?}");
        let facts =
            heimdall_issuer::remote::read_certificate(&listed[0]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(facts.ca_fingerprint, j.ca_fingerprint);
        assert_eq!(facts.principals, vec![j.principal.clone()]);
        assert!(facts.key_id.contains(grant.as_str()), "{}", facts.key_id);
        assert_ne!(
            facts.subject_fingerprint, j.mgmt_fingerprint,
            "never K_mgmt"
        );

        // The pass that adopted this grant read a report listing all four (the three
        // outside were admitted first). The controller is stopped.
        j.controller.runtime_stop();

        // The controller's records: the one grant, from its policy, and nothing reserved
        // for the three outside it.
        {
            let store =
                Store::open_read_only(&state_db(&j.controller.home), Arc::new(NoFaults)).unwrap();
            let records = store
                .transaction(|tx| tx.delivered_grants(Some(&environment)))
                .unwrap();
            assert_eq!(records.len(), 1, "{records:?}");
            assert_eq!(records[0].grant, grant);
            assert_eq!(records[0].policy, Some(held[0].id.clone()));
            assert_eq!(records[0].pairs, BTreeSet::from([j.pair.clone()]));
            for (what, outside) in [
                ("pair", &outside_pair),
                ("principal", &outside_principal),
                ("deadline", &outside_deadline),
            ] {
                let entries = store
                    .transaction(|tx| tx.issuance_entries(outside))
                    .unwrap();
                assert!(entries.is_empty(), "{what} outside the policy: {entries:?}");
            }
            assert_eq!(
                store
                    .transaction(|tx| tx.issuance_entries(&grant))
                    .unwrap()
                    .len(),
                1
            );
        }
        // ⟨M06 W5 ruling, 2026-11-22⟩ The owner reads why the grant with the late
        // deadline was refused: `environment status` names the limit it exceeds (the
        // cutoff the owner set), and nothing for the two no policy holds.
        let status = j.controller.status(&environment);
        let failures = status["issuance_failures"]
            .as_array()
            .unwrap_or_else(|| panic!("no refusal is shown: {status}"));
        assert_eq!(failures.len(), 1, "{status}");
        assert_eq!(failures[0]["grant"], outside_deadline.as_str(), "{status}");
        let said = failures[0]["reason"].as_str().unwrap();
        assert!(
            said.starts_with("deadline_exceeds_policy_cutoff: ")
                && said.contains(&format!("of policy {}", held[0].id.as_str())),
            "{said}"
        );
        // On the runner they are still waiting for their issuer.
        for (request, work, pair, lifetime) in [
            ("out-pair", "job-pair", format!("h2:{account}"), "10m"),
            (
                "out-principal",
                "job-principal",
                "h1:hm-other".to_owned(),
                "10m",
            ),
            ("out-deadline", "job-deadline", inside_pair.clone(), "30m"),
        ] {
            let (_, still) = attended(ensure(work, request, &pair, lifetime));
            assert_eq!(still["code"], "ACCEPTED", "{request}: {still}");
        }

        // 4. The controller is stopped; the runner goes on.
        let dir = j.scratch.subdir("onward-b").unwrap();
        let mark = j.destination.log_mark();
        let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
        assert!(
            ok,
            "onward ssh with the controller stopped: {out}\n{}",
            std::fs::read_to_string(j.runner.account.join("runtime.stderr")).unwrap_or_default()
        );
        let accepted = j.destination.accepted_certificates();
        assert!(
            accepted.iter().any(|c| c.key_id == facts.key_id
                && c.serial == facts.serial
                && c.ca_fingerprint == j.ca_fingerprint.as_str()),
            "{accepted:?} {:?}",
            j.destination.log_lines_since(mark, "Accepted")
        );

        // ⟨M06 W5 ruling, 2026-11-22⟩ `environment remove` forgets the runner and, in the
        // same transaction, the policy that names it; its last history row says why.
        let removed = j
            .controller
            .json(&["environment", "remove", environment.as_str()]);
        assert_eq!(removed["code"], "OK", "{removed}");
        assert!(
            policies(&j.controller).is_empty(),
            "the policy went with the record: {removed}"
        );
        let store =
            Store::open_read_only(&state_db(&j.controller.home), Arc::new(NoFaults)).unwrap();
        let (pins, history) = store
            .transaction(|tx| {
                Ok((
                    tx.remote_environment_pins()?,
                    tx.policy_history(&held[0].id)?,
                ))
            })
            .unwrap();
        assert!(pins.is_empty(), "the record is gone");
        assert_eq!(
            history.last().map(|h| h.cause.clone()),
            Some(
                heimdall_domain::workspace::PolicyChangeCause::EnvironmentRemoved {
                    environment: environment.clone()
                }
            ),
            "{history:?}"
        );
        drop(j);
    }
}

/// ⟨M06 W3; ADR-0012 §3.2; ADR-0006 §18.7 "Also ruled"⟩ The runner's effective sshd policy
/// reaches the runner through `service run --runner`, over a fixture configuration
/// (`HEIMDALL_TEST_RUNNER_SSHD_CONFIG`: the real `sshd -T`, nothing listens):
///
/// * a **verified non-default** policy (one keys file instead of sshd's default pair):
///   limited roles are available, so a `viewer` invitation approved at the runner is
///   created and its pending line is written to that one file;
/// * an **unverifiable** one (an `AuthorizedKeysCommand`): the runner is owner-only, so the
///   same approved invitation is refused `management_sshd_unverified` and no line is written.
///
/// The owner's paired session is the bridge itself (`heimdall remote serve --client <cid>
/// --home <home>`, the forced command, started directly with a cleared environment): no
/// daemon is needed for this row. Where the host has no `/usr/sbin/sshd` the case reports
/// `blocked`.
#[tokio::test]
async fn the_runners_sshd_policy_reaches_the_runner_and_gates_limited_roles() {
    const SSHD: &str = "/usr/sbin/sshd";
    if !Path::new(SSHD).exists() {
        #[allow(clippy::print_stderr)] // the blocked row's reason
        {
            eprintln!("m06 runner sshd policy: blocked ({SSHD} is absent on this host)");
        }
        return;
    }
    const RESTRICTED: &str = "AuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\n\
                              PermitUserEnvironment no\nAcceptEnv LANG LC_*\n\
                              AuthenticationMethods any\nPubkeyAuthentication yes\n";
    let verified = format!("AuthorizedKeysFile .ssh/authorized_keys\n{RESTRICTED}");
    let unverifiable = verified.replace(
        "AuthorizedKeysCommand none",
        "AuthorizedKeysCommand /usr/bin/false\nAuthorizedKeysCommandUser nobody",
    );
    let scratch = Scratch::new().unwrap();
    for (tag, config, limited) in [("v", verified, true), ("u", unverifiable, false)] {
        let mut runner = Runner::named(&scratch, tag);
        let config_path = scratch.path().join(format!("sshd_config_{tag}"));
        std::fs::write(&config_path, config).unwrap();
        runner.sshd_config = Some(config_path);
        let key = MgmtKey::generate().unwrap();
        let public = key.public().unwrap();
        let key_text = public
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let owner = ClientId::from_random_bytes([0x71; 16]);
        let init = envelope(&runner.remote_init(&owner, &key_text, "yes"));
        assert_eq!(init["code"], "OK", "{tag}: {init}");
        let environment = init["data"]["environment"].as_str().unwrap().to_owned();
        let keys_file = runner.account.join(".ssh").join("authorized_keys");
        let owner_line = std::fs::read_to_string(&keys_file).unwrap();
        runner.start();

        // The owner's paired session: the bridge over its own standard streams.
        let mut bridge = tokio::process::Command::new(bin());
        bridge
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &runner.account)
            .args(["remote", "serve", "--client", owner.as_str(), "--home"])
            .arg(&runner.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut bridge = bridge.spawn().unwrap();
        let streams = tokio::io::join(bridge.stdout.take().unwrap(), bridge.stdin.take().unwrap());
        let required: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
        let mut paired = tokio::time::timeout(
            Duration::from_secs(30),
            ControlClient::handshake(
                streams,
                PeerInfo {
                    name: "heimdall-cli".into(),
                    version: "test".into(),
                },
                required,
                InteractionMode::NonInteractive,
            ),
        )
        .await
        .expect("the bridge's hello")
        .unwrap_or_else(|e| panic!("{tag}: {e}"));
        assert_eq!(paired.server().role, Some(Role::Owner));
        assert_eq!(paired.server().remote_client.as_ref(), Some(&owner));

        // A viewer's invitation: submitted by the paired owner, approved at the runner.
        let invited_key = MgmtKey::generate().unwrap().public().unwrap();
        let invited_text = invited_key
            .openssh_line
            .rsplit_once(' ')
            .map(|(k, _)| k.to_owned())
            .unwrap();
        let invite: Request = serde_json::from_value(serde_json::json!({
            "op": "remote_environment", "action": "invite", "environment": environment,
            "role": "viewer", "key_fingerprint": invited_key.fingerprint,
            "public_key": invited_text, "request_id": format!("e2e-policy-{tag}"),
        }))
        .unwrap();
        let pending = paired.request(invite).await.unwrap();
        assert_eq!(
            pending.code.as_str(),
            "APPROVAL_REQUIRED",
            "{tag}: {pending:?}"
        );
        let decision = pending.next.unwrap().decision_ref.unwrap();
        let mut at_runner = attend_at(&runner).await;
        let decided = at_runner
            .request(Request::Decide(DecideRequest {
                decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
                verdict: Verdict::Approve,
            }))
            .await
            .unwrap();
        let text = serde_json::to_string(&decided).unwrap();
        assert_no_canary(&text);
        let now = std::fs::read_to_string(&keys_file).unwrap();
        if limited {
            assert_eq!(decided.code.as_str(), "OK", "{text}");
            assert_eq!(decided.data["role"], "viewer", "{text}");
            let invited = decided.data["client"].as_str().unwrap();
            assert!(now.starts_with(&owner_line), "the owner's line kept: {now}");
            assert!(
                now.contains(&format!("heimdall-mgmt:{invited}")) && now.contains("expiry-time="),
                "the pending line is in the verified policy's one file: {now}"
            );
            assert!(
                !runner
                    .account
                    .join(".ssh")
                    .join("authorized_keys2")
                    .exists(),
                "the verified list names one file"
            );
            // ⟨ADR-0006 §18.7 item 17⟩ A management session in which sshd allocated a PTY:
            // its bridge refuses it, and this running runner is owner-only from then on
            // (no restart): the next limited invitation is refused at its approval.
            let unrestricted = std::process::Command::new(bin())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &runner.account)
                .env("SSH_TTY", "/dev/ttys999")
                .args(["remote", "serve", "--client", owner.as_str(), "--home"])
                .arg(&runner.home)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(!unrestricted.status.success(), "{unrestricted:?}");
            let late_key = MgmtKey::generate().unwrap().public().unwrap();
            let late_text = late_key
                .openssh_line
                .rsplit_once(' ')
                .map(|(k, _)| k.to_owned())
                .unwrap();
            let late: Request = serde_json::from_value(serde_json::json!({
                "op": "remote_environment", "action": "invite", "environment": environment,
                "role": "viewer", "key_fingerprint": late_key.fingerprint,
                "public_key": late_text, "request_id": "e2e-policy-late",
            }))
            .unwrap();
            let pending = paired.request(late).await.unwrap();
            assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
            let decision = pending.next.unwrap().decision_ref.unwrap();
            let refused = at_runner
                .request(Request::Decide(DecideRequest {
                    decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
                    verdict: Verdict::Approve,
                }))
                .await
                .unwrap();
            assert_eq!(
                refused.data["error"]["reason"], "management_sshd_unverified",
                "{refused:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&keys_file).unwrap(),
                now,
                "no line was written for it"
            );

            // ⟨ADR-0006 §18.7 items 18–19⟩ Lifting it, on this running runner. The lift
            // needs a terminal: without one nothing is asked or changed.
            assert_eq!(
                recorded_downgrade(&runner.home).as_deref(),
                Some("session_pty")
            );
            let unattended = runner
                .command()
                .args(["--json", "remote", "policy", "recheck"])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let refused = envelope(&String::from_utf8_lossy(&unattended.stdout));
            assert_eq!(refused["code"], "INTERACTION_REQUIRED", "{refused}");
            // With a terminal but no evidence: refused before anything is asked.
            let no_evidence = envelope(&runner.on_terminal(
                &[
                    "remote".to_owned(),
                    "policy".to_owned(),
                    "recheck".to_owned(),
                ],
                NEVER_ASKED,
            ));
            assert_eq!(
                no_evidence["code"], "CAPABILITY_UNAVAILABLE",
                "{no_evidence}"
            );
            assert_eq!(
                no_evidence["data"]["error"]["reason"], "management_sshd_unverified",
                "{no_evidence}"
            );
            // The owner's controller reports its probes over its management session; the
            // runner runs the real `sshd -T` over the fixture configuration again and
            // records the evidence. Nothing is lifted by it.
            let recheck: Request = serde_json::from_value(serde_json::json!({
                "op": "remote_environment", "action": "runner_policy_recheck",
                "environment": environment,
                "probe": {
                    "pty_refused": true, "forward_refused": true,
                    "agent_forward_refused": true, "setenv_canary_delivered": false,
                },
            }))
            .unwrap();
            let recorded = paired.request(recheck).await.unwrap();
            assert_eq!(recorded.code.as_str(), "OK", "{recorded:?}");
            assert_eq!(recorded.data["recorded"], true, "{recorded:?}");
            assert_eq!(recorded.data["controller"], owner.as_str());
            assert!(recorded_downgrade(&runner.home).is_some());
            // The owner at the runner's terminal: shown the evidence, typed `yes`, lifted
            // through the running runtime's attended local form.
            let transcript = runner.on_terminal(
                &[
                    "remote".to_owned(),
                    "policy".to_owned(),
                    "recheck".to_owned(),
                ],
                "yes",
            );
            assert!(
                transcript.contains(owner.as_str())
                    && transcript.contains("sshd allocated a terminal"),
                "the evidence is shown: {transcript}"
            );
            let lifted = envelope(&transcript);
            assert_eq!(lifted["code"], "OK", "{lifted}");
            assert_eq!(lifted["data"]["lifted"], true, "{lifted}");
            assert_eq!(recorded_downgrade(&runner.home), None);
            // Limited roles are admitted again, with no restart.
            let again_key = MgmtKey::generate().unwrap().public().unwrap();
            let again_text = again_key
                .openssh_line
                .rsplit_once(' ')
                .map(|(k, _)| k.to_owned())
                .unwrap();
            let again: Request = serde_json::from_value(serde_json::json!({
                "op": "remote_environment", "action": "invite", "environment": environment,
                "role": "viewer", "key_fingerprint": again_key.fingerprint,
                "public_key": again_text, "request_id": "e2e-policy-again",
            }))
            .unwrap();
            let pending = paired.request(again).await.unwrap();
            assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
            let decision = pending.next.unwrap().decision_ref.unwrap();
            let approved = at_runner
                .request(Request::Decide(DecideRequest {
                    decision_id: heimdall_contract::ids::DecisionId::parse(&decision).unwrap(),
                    verdict: Verdict::Approve,
                }))
                .await
                .unwrap();
            assert_eq!(approved.code.as_str(), "OK", "{approved:?}");
        } else {
            assert_eq!(decided.code.as_str(), "CAPABILITY_UNAVAILABLE", "{text}");
            assert_eq!(
                decided.data["error"]["reason"], "management_sshd_unverified",
                "{text}"
            );
            assert_eq!(now, owner_line, "owner-only: no line was written");
        }
        drop(at_runner);
        drop(paired);
        let _ = bridge.kill().await;
        // Nothing of the check is left in the runner's state directory.
        let left: Vec<_> =
            std::fs::read_dir(heimdall_runtime::Paths::under(&runner.home).state_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| n.to_string_lossy().starts_with("hm-sshd-policy-"))
                .collect();
        assert!(left.is_empty(), "{tag}: {left:?}");
    }
}

/// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ `remote init` and what is not its to change,
/// through the real binary on a pseudo-terminal:
///
/// * the account's `~/.ssh` is a **symbolic link**: refused (`CONFIG_CONFLICT`, effect
///   `none`) before the confirmation is asked; no state, nothing behind the link;
/// * a **first** `remote init` while a runtime that is not a runner's holds the home:
///   `driver_unavailable`, and the message says to stop the local runtime first;
/// * a **group-writable home**: the enrollment succeeds, the answer says what sshd's
///   `StrictModes` would refuse (`strict_modes`), the mode is left as it was, and `doctor`
///   reports the same finding.
#[tokio::test]
async fn remote_init_refuses_and_reports_what_it_never_changes() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new().unwrap();
    let key = MgmtKey::generate().unwrap().public().unwrap();
    let key_text = key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let client = ClientId::from_random_bytes([0x33; 16]);

    // A symbolic link at ~/.ssh.
    let linked = Runner::named(&scratch, "l");
    let elsewhere = scratch.subdir("elsewhere").unwrap();
    std::os::unix::fs::symlink(&elsewhere, linked.account.join(".ssh")).unwrap();
    let transcript = linked.remote_init(&client, &key_text, NEVER_ASKED);
    let refused = envelope(&transcript);
    assert_eq!(refused["code"], "CONFIG_CONFLICT", "{transcript}");
    assert_eq!(refused["data"]["error"]["effect_status"], "none");
    let message = refused["data"]["error"]["message"].as_str().unwrap();
    assert!(message.contains("is a symbolic link"), "{message}");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    assert!(
        !heimdall_runtime::Paths::under(&linked.home)
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE)
            .exists(),
        "no state was written"
    );

    // A first `remote init` under a runtime that is not a runner's.
    let mut plain = Runner::named(&scratch, "p");
    plain.start();
    let transcript = plain.remote_init(&client, &key_text, NEVER_ASKED);
    let refused = envelope(&transcript);
    assert_eq!(refused["code"], "CAPABILITY_UNAVAILABLE", "{transcript}");
    assert_eq!(refused["data"]["error"]["reason"], "driver_unavailable");
    assert_eq!(refused["data"]["error"]["effect_status"], "none");
    let message = refused["data"]["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("stop the local runtime first")
            && message.contains("`heimdall service stop`"),
        "{message}"
    );
    assert!(!plain.account.join(".ssh").exists(), "nothing was created");
    drop(plain);

    // A home sshd's StrictModes would refuse: said, and left as it is.
    let loose = Runner::named(&scratch, "g");
    std::fs::set_permissions(&loose.account, std::fs::Permissions::from_mode(0o775)).unwrap();
    let transcript = loose.remote_init(&client, &key_text, "yes");
    let done = envelope(&transcript);
    assert_eq!(done["code"], "OK", "{transcript}");
    assert_eq!(done["data"]["line_written"], true, "{done}");
    assert_eq!(
        done["data"]["strict_modes"],
        serde_json::json!([{ "path": "home", "problem": "group_or_other_writable" }]),
        "{done}"
    );
    let mode = std::fs::metadata(&loose.account)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o775, "the home's mode is not changed");
    let doctor = loose
        .command()
        .args(["--json", "doctor"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&doctor.stdout).into_owned();
    assert_no_canary(&report);
    let report = envelope(&report);
    let findings = report["data"]["findings"].as_array().unwrap();
    let finding = findings
        .iter()
        .find(|f| f["code"] == "runner_ssh_strict_modes")
        .unwrap_or_else(|| panic!("no StrictModes finding: {report}"));
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("the home directory is writable by group or others"),
        "{finding}"
    );
    let mode = std::fs::metadata(&loose.account)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o775, "doctor changes nothing");
}

/// Stops, through `service stop` on its own scratch home, the runtime a bootstrap offer
/// started (the test holds no child handle for it), pass or fail.
struct StopOnDrop<'a>(&'a Runner);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self
            .0
            .command()
            .args(["--json", "service", "stop"])
            .stdin(Stdio::null())
            .output();
    }
}

/// ⟨M06 W5k; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The bootstrap's offer, on a
/// pseudo-terminal, through the real binary (`remote init --offer-runtime-start`, the
/// command a controller's `environment add` runs in its attended session):
///
/// * the runner's runtime does not run: the session says so plainly and offers to start
///   it; **declined**, nothing is started, no runtime serves, and the next step (the exact
///   start command, then `environment add` again) is on the terminal;
/// * the repair, **accepted with a typed yes**: the runtime is started in that same
///   session, serves when the command returns, and the session says so;
/// * with the runtime running the session says it runs and asks nothing more;
/// * a `remote init` without the flag (the runner's owner by hand) offers nothing.
///
/// The started runtime is a debug build under a scratch home, account home and SSH home,
/// stopped through `service stop` on that home.
#[test]
fn the_bootstrap_offers_to_start_the_runner_runtime_in_its_attended_session() {
    const CONFIRM: &str = "Type yes to continue";
    const OFFER: &str = "Type yes to start it";
    let scratch = Scratch::new().unwrap();
    let key = MgmtKey::generate().unwrap().public().unwrap();
    let key_text = key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let client = ClientId::from_random_bytes([0x51; 16]);
    let runner = Runner::named(&scratch, "o");
    let _stop = StopOnDrop(&runner);
    let init = |offer: bool| -> Vec<String> {
        let mut args: Vec<String> = [
            "remote",
            "init",
            "--owner-client",
            client.as_str(),
            "--owner-key",
            &key_text,
        ]
        .map(str::to_owned)
        .into();
        if offer {
            args.push("--offer-runtime-start".to_owned());
        }
        args
    };
    let serving = || {
        runner
            .command()
            .args(["--json", "service", "status"])
            .stdin(Stdio::null())
            .output()
            .unwrap()
            .status
            .code()
    };
    let start_line = format!(
        "--home {} service run --runner --detach",
        runner.home.display()
    );

    // Declined: said plainly, nothing started, the next step left on the terminal.
    let declined = runner.on_terminal_dialog(&init(true), &[(CONFIRM, "yes"), (OFFER, "no")]);
    let flat = declined.replace(['\r', '\n'], " ");
    assert!(
        flat.contains("The runner's runtime is NOT running on this installation"),
        "{declined}"
    );
    assert!(flat.contains("Start it now"), "{declined}");
    assert!(
        flat.contains("The runner's runtime was not started. Next step:"),
        "{declined}"
    );
    assert!(flat.contains(&start_line), "{declined}");
    assert!(flat.contains("`heimdall environment add`"), "{declined}");
    assert!(
        flat.contains("this installation is remote runner"),
        "the enrollment itself stands: {declined}"
    );
    assert_eq!(
        serving(),
        Some(5),
        "no runtime serves after a declined offer"
    );

    // The repair, accepted: started in the same session, serving when it returns.
    let accepted = runner.on_terminal_dialog(&init(true), &[(CONFIRM, "yes"), (OFFER, "yes")]);
    let flat = accepted.replace(['\r', '\n'], " ");
    assert!(
        flat.contains("The runner's runtime is running on this installation (started now)."),
        "{accepted}"
    );
    assert!(!flat.contains("was not started"), "{accepted}");
    assert_eq!(serving(), Some(0), "the runtime serves: {accepted}");

    // Running: said, and nothing more is asked (one prompt only; a second would time out).
    let running = runner.on_terminal_dialog(&init(true), &[(CONFIRM, "yes")]);
    let flat = running.replace(['\r', '\n'], " ");
    assert!(
        flat.contains("The runner's runtime is running on this installation."),
        "{running}"
    );
    assert!(!flat.contains(OFFER), "{running}");
    assert_eq!(serving(), Some(0));

    // Without the flag nothing is said about the runtime and nothing is offered.
    let other = Runner::named(&scratch, "p");
    let by_hand = other.on_terminal_dialog(&init(false), &[(CONFIRM, "yes")]);
    assert!(
        by_hand.contains("this installation is remote runner"),
        "{by_hand}"
    );
    assert!(
        !by_hand.contains("runtime is") && !by_hand.contains(OFFER),
        "{by_hand}"
    );
    assert_eq!(
        other
            .command()
            .args(["--json", "service", "status"])
            .stdin(Stdio::null())
            .output()
            .unwrap()
            .status
            .code(),
        Some(5)
    );
    #[allow(clippy::print_stdout)]
    {
        println!(
            "m06 observation: bootstrap runtime-offer: declined=not_started_next_step_named \
             accepted=started_in_session_serving running=stated_no_offer by_hand=no_offer"
        );
    }
}
