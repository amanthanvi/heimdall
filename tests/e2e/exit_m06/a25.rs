//! ⟨M06 W5 U7⟩ **A25: pairing and management role boundaries** (m06-plan §3 rows "A25" and
//! "Remote access and owner control distinct"; spec A25; R-EN-08, R-SE-06), with the real
//! runner binary, the real bridge and the system `ssh` on one host.
//!
//! **How the controller side is driven.** Every management request here is sent at the
//! session level: the isolated `-F` configuration, the K_mgmt session agent, the real
//! management `ssh` and the IPC client the CLI wires (`world::connect_with`), against a
//! fixture sshd whose keys file is the runner account's and whose line runs the real
//! `heimdall remote serve`. The controller CLI's `environment invite` and `environment
//! join` are not driven. The runner side is the product: `remote init` on a
//! pseudo-terminal, `service run --runner`, and its attended local session for decisions.
//!
//! Driven here, one observation line each:
//!
//! * `sshd-policy-unverified`: on a runner whose effective sshd policy (`sshd -T` over a
//!   fixture configuration) has an `AuthorizedKeysCommand`, a `ForceCommand` or `AcceptEnv
//!   *`, a limited role's invitation is refused `management_sshd_unverified` at its
//!   approval and no line is written;
//! * `t-ra1` … `t-ra4` (ADR-0012 §3.10): an unattended paired owner's widening is a pending
//!   record only; a paired `Decide` or `Attend` is refused before dispatch; the decided
//!   request replayed returns the recorded terminal result; a limited client's widening is
//!   `role_insufficient`;
//! * `unattended-local`: an unattended local session at the runner cannot decide either;
//! * `pending-key`: an invited key's pending session negotiates only `remote-control/1`
//!   and reaches only the activation probe and `join`;
//! * ⟨w5j⟩ `limited-product-view`, `limited-product-request`, `requester-no-owner-record`,
//!   `requester-owner-record`, `limited-rotate-endpoint`, `limited-product-cli`: the limited
//!   roles through the product CLI (`a25_limited.rs`);
//! * `limited-session-hello`: a joined viewer's session negotiates neither
//!   `remote-control/1` nor `runner/1`; what the product session opener's hello (which
//!   requires `remote-control/1`) gets is **recorded, not judged** (the unit's DONE, D1);
//! * `invitation-wrong-key`, `invitation-consumed`: another key cannot join with an
//!   invitation, and a consumed invitation cannot be used again;
//! * `limited-client`: a viewer's line refuses a shell command, a PTY, a `-W` forward and
//!   agent forwarding (the four confirming probes), and its session cannot obtain issuance;
//! * `collision`: two clients using the same request ID get their own results;
//! * `host-key-replaced`: a management sshd presenting another host key is refused by the
//!   pinned configuration, the pin file is unchanged, and the genuine one still works;
//! * `old-client`, `missing-capability`: a client with an unsupported schema version, and
//!   one requiring a capability the runner does not have, are refused explicitly;
//! * `positive-control`: a key whose line (written by the test, never by the runner) also
//!   grants agent forwarding really gets the agent forwarded: the probe reports it, the
//!   bridge refuses the session, the runner records the downgrade, and from then on a
//!   limited role is refused (`management_sshd_unverified`) without a restart.
//!
//! **Not driven here** (`NOT-COVERED.md`): an expired invitation, a delayed join, a
//! wall-clock rollback between authentication and `join`, and a crash between the commit
//! and the line rewrite (they need a controlled clock or an injected fault: the model
//! suites); the confirming probes against a **live** sshd with the three unsupported
//! configurations (the fixture sshd cannot be started with them); a replaced Iroh endpoint
//! key (A26); the limited-client container, the Windows rows, a separate runner host.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use heimdall_contract::ids::{
    AccountName, CaFingerprint, ClientId, DecisionId, DestinationId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::ipc::{PeerInfo, capability};
use heimdall_contract::remote::{ProbeObservation, Role};
use heimdall_contract::request::{
    AccessPairRef, DeadlineIntent, DecideRequest, EnsureRequest, InspectRequest, InspectSubject,
    InteractionMode, PairIssuer, Request, RequiredCapabilities, Verdict, WaitMode,
};
use heimdall_credential::cert::SecretCaKey;
use heimdall_credential::mgmt::{MgmtKey, MgmtSigner, SessionAgent};
use heimdall_domain::time::Clock as _;
use heimdall_ipc::session::ControlClient;
use heimdall_testkit::home::{Scratch, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use serde_json::Value;

use super::m06::{blocked, observe, runner_stderr};
use super::world::{
    HOUR, MgmtClient, Runner, attend_at, bin, client_hello, connect_with, envelope, host_key,
    recorded_downgrade, seed_runner_catalog_with,
};

#[path = "a25_limited.rs"]
mod limited;

const CASE: &str = "a25";
const SSHD: &str = "/usr/sbin/sshd";
pub(crate) const RESTRICTED: &str = "AuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\n\
                          PermitUserEnvironment no\nAcceptEnv LANG LC_*\n\
                          AuthenticationMethods any\nPubkeyAuthentication yes\n";

const ALL_REFUSED: ProbeObservation = ProbeObservation {
    pty_refused: true,
    forward_refused: true,
    agent_forward_refused: true,
    setenv_canary_delivered: false,
};

fn key_text(key: &MgmtKey) -> String {
    key.public()
        .unwrap()
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap()
}

/// One management key with its session agent and scratch directory.
struct Peer {
    dir: PathBuf,
    public_line: String,
    fingerprint: String,
    text: String,
    agent: SessionAgent,
}

impl Peer {
    fn new(scratch: &Scratch, tag: &str, key: MgmtKey, sshd: &LoopbackSshd, account: &str) -> Peer {
        let dir = scratch.subdir(tag).unwrap();
        let public = key.public().unwrap();
        let text = key_text(&key);
        let signer =
            MgmtSigner::with_host_key_lines(key, [account.to_owned()], &[host_key(sshd)]).unwrap();
        let agent = SessionAgent::start(&dir.join("a.sock"), signer).unwrap();
        Peer {
            dir,
            public_line: public.openssh_line.clone(),
            fingerprint: public.fingerprint.as_str().to_owned(),
            text,
            agent,
        }
    }
}

/// The world of the journey's main runner.
struct World {
    scratch: Scratch,
    runner: Runner,
    sshd: LoopbackSshd,
    account: String,
    environment: String,
    keys_file: PathBuf,
}

impl World {
    /// A session with the hello the product's session opener sends (it requires
    /// `remote-control/1`).
    async fn session(&self, peer: &Peer) -> Result<(MgmtClient, tokio::process::Child), String> {
        self.session_with(peer, client_hello(false)).await
    }

    /// A session whose hello requires nothing: the capabilities are whatever the runner
    /// grants the key's role.
    async fn limited_session(
        &self,
        peer: &Peer,
    ) -> Result<(MgmtClient, tokio::process::Child), String> {
        let mut hello = client_hello(false);
        hello.required.clear();
        self.session_with(peer, hello).await
    }

    async fn session_with(
        &self,
        peer: &Peer,
        hello: heimdall_contract::ipc::ClientHello,
    ) -> Result<(MgmtClient, tokio::process::Child), String> {
        connect_with(
            &peer.dir,
            &self.sshd,
            &host_key(&self.sshd),
            &self.account,
            &peer.public_line,
            &self.environment,
            hello,
        )
        .await
    }

    async fn probes(&self, peer: &Peer) -> ProbeObservation {
        let disposable =
            heimdall_app::remote_env::ssh::DisposableAgent::start(&peer.dir.join("p.sock"))
                .unwrap();
        let observed = heimdall_app::remote_env::ssh::run_probes(
            &find_program("ssh").expect("an OpenSSH client"),
            &peer.dir.join("mgmt.conf"),
            &format!("hm-env-{}", self.environment),
            &disposable,
            heimdall_localenv::sys::openssh_env::fill_openssh_environment,
        )
        .await
        .expect("the probes were conclusive");
        drop(disposable);
        observed
    }

    fn invite(&self, role: &str, peer: &Peer, request: &str) -> Request {
        invite_request(
            &self.environment,
            role,
            &peer.fingerprint,
            &peer.text,
            request,
        )
    }

    fn join(&self, approved: &Value, role: &str, probe: ProbeObservation) -> Request {
        serde_json::from_value(serde_json::json!({
            "op": "remote_environment", "action": "join", "environment": self.environment,
            "invitation": approved["invitation"], "role": role,
            "generation": approved["generation"], "probe": probe,
        }))
        .unwrap()
    }
}

fn invite_request(
    environment: &str,
    role: &str,
    fingerprint: &str,
    text: &str,
    id: &str,
) -> Request {
    serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "invite", "environment": environment,
        "role": role, "key_fingerprint": fingerprint, "public_key": text, "request_id": id,
    }))
    .unwrap()
}

fn decide(decision: &str) -> Request {
    Request::Decide(DecideRequest {
        decision_id: DecisionId::parse(decision).unwrap(),
        verdict: Verdict::Approve,
    })
}

fn inspect() -> Request {
    Request::Inspect(InspectRequest {
        subject: InspectSubject::Environments,
        preview: None,
        cwd: None,
        redact: false,
    })
}

/// `code` and the error's reason of an answer.
fn refusal(v: &heimdall_contract::envelope::Envelope<Value>) -> (String, String) {
    (
        v.code.as_str().to_owned(),
        v.data["error"]["reason"]
            .as_str()
            .unwrap_or("none")
            .to_owned(),
    )
}

pub(crate) fn journey() {
    if !Path::new(SSHD).exists() {
        blocked(
            CASE,
            "no /usr/sbin/sshd for the runner's `sshd -T` policy check",
        );
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run());
}

/// `sshd-policy-unverified`: the three unsupported configurations, each on its own runner.
/// The owner's paired session is the bridge itself over its standard streams.
async fn unverified_policies(scratch: &Scratch) {
    let verified = format!("AuthorizedKeysFile .ssh/authorized_keys\n{RESTRICTED}");
    let variants = [
        (
            "kc",
            verified.replace(
                "AuthorizedKeysCommand none",
                "AuthorizedKeysCommand /usr/bin/false\nAuthorizedKeysCommandUser nobody",
            ),
        ),
        ("fc", format!("{verified}ForceCommand /usr/bin/true\n")),
        ("ae", verified.replace("AcceptEnv LANG LC_*", "AcceptEnv *")),
    ];
    for (tag, config) in variants {
        let mut runner = Runner::named(scratch, tag);
        let config_path = scratch.path().join(format!("sshd_config_{tag}"));
        std::fs::write(&config_path, config).unwrap();
        runner.sshd_config = Some(config_path);
        let key = MgmtKey::generate().unwrap();
        let owner = ClientId::from_random_bytes([0x61; 16]);
        let init = envelope(&runner.remote_init(&owner, &key_text(&key), "yes"));
        assert_eq!(init["code"], "OK", "{tag}: {init}");
        let environment = init["data"]["environment"].as_str().unwrap().to_owned();
        let keys_file = runner.account.join(".ssh").join("authorized_keys");
        let owner_line = std::fs::read_to_string(&keys_file).unwrap();
        runner.start();
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
        let invited = MgmtKey::generate().unwrap();
        let public = invited.public().unwrap();
        let pending = paired
            .request(invite_request(
                &environment,
                "viewer",
                public.fingerprint.as_str(),
                &key_text(&invited),
                &format!("a25-unverified-{tag}"),
            ))
            .await
            .unwrap();
        assert_eq!(
            pending.code.as_str(),
            "APPROVAL_REQUIRED",
            "{tag}: {pending:?}"
        );
        let decision = pending.next.unwrap().decision_ref.unwrap();
        let mut at_runner = attend_at(&runner).await;
        let decided = at_runner.request(decide(&decision)).await.unwrap();
        assert_eq!(
            refusal(&decided),
            (
                "CAPABILITY_UNAVAILABLE".to_owned(),
                "management_sshd_unverified".to_owned()
            ),
            "{tag}: {decided:?}\n{}",
            runner_stderr(&runner)
        );
        assert_eq!(
            std::fs::read_to_string(&keys_file).unwrap(),
            owner_line,
            "{tag}: owner-only, no line was written"
        );
        drop(at_runner);
        drop(paired);
        let _ = bridge.kill().await;
    }
    observe(
        CASE,
        "sshd-policy-unverified",
        "authorized_keys_command=management_sshd_unverified \
         force_command=management_sshd_unverified accept_env_all=management_sshd_unverified \
         lines_written=0",
    );
}

async fn run() {
    let scratch = Scratch::new().unwrap();
    unverified_policies(&scratch).await;

    // The main runner: a verified effective policy, a real management sshd.
    let mut runner = Runner::named(&scratch, "v");
    let config_path = scratch.path().join("sshd_config_v");
    std::fs::write(
        &config_path,
        format!("AuthorizedKeysFile .ssh/authorized_keys\n{RESTRICTED}"),
    )
    .unwrap();
    runner.sshd_config = Some(config_path);
    let owner_key = MgmtKey::generate().unwrap();
    let owner_client = ClientId::from_random_bytes([0x62; 16]);
    let ca = SecretCaKey::generate().unwrap();
    let ca_fingerprint: CaFingerprint = ca.fingerprint().unwrap();
    let init = envelope(&runner.remote_init_with(
        &owner_client,
        &key_text(&owner_key),
        "yes",
        &["--issuer-ca", ca.public_openssh().unwrap().trim()],
    ));
    assert_eq!(init["code"], "OK", "{init}");
    let environment = init["data"]["environment"].as_str().unwrap().to_owned();
    let pair = AccessPairRef {
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    };
    seed_runner_catalog_with(
        &runner.home,
        heimdall_runtime::platform::SystemClock.wall(),
        std::slice::from_ref(&pair),
        4 * HOUR,
    );
    let sshd = match LoopbackSshd::start(
        &scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            // The daemon allows agent forwarding, so it is the runner's line (`restrict`)
            // that refuses it, and the positive control's line really forwards.
            agent_forwarding: true,
            ..SshdConfig::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            blocked(CASE, &format!("no fixture sshd: {}", e.reason));
            return;
        }
    };
    let (Some(account), Some(registry)) = (
        sshd.login_account().or_else(current_account),
        sshd.registry_path().map(Path::to_path_buf),
    ) else {
        blocked(CASE, "the fixture sshd has no local account or registry");
        return;
    };
    let keys_file = runner.account.join(".ssh").join("authorized_keys");
    let _ = std::fs::remove_file(&registry);
    std::os::unix::fs::symlink(&keys_file, &registry).unwrap();
    runner.start();
    let owner_line = std::fs::read_to_string(&keys_file).unwrap();
    let w = World {
        scratch,
        runner,
        sshd,
        account,
        environment,
        keys_file,
    };
    // ⟨w5j; ADR-0006 §18.9 item 6⟩ The owner's own controller installation (its K_mgmt,
    // its issuer, its record of the runner as owner; no policy naming the runner yet), for
    // the block that shows a requester's pending request is signed only under an owner
    // controller's record (`limited::journey`). Not started here.
    let owner_controller = super::world::install_controller(
        &w.scratch,
        "oc",
        0xb4,
        &owner_key,
        &owner_client,
        Some(&ca),
        &heimdall_contract::ids::EnvironmentId::parse(&w.environment).unwrap(),
        &w.sshd,
        &w.account,
        &pair,
    );
    drop(ca);
    let owner = Peer::new(&w.scratch, "o", owner_key, &w.sshd, &w.account);
    // ⟨w5e⟩ Each limited key is also kept in a fixture store file, for the product
    // controller that stands for its device (`limited::journey`).
    let (viewer_key, requester_key) = (MgmtKey::generate().unwrap(), MgmtKey::generate().unwrap());
    let viewer_store = limited::store_key(&w.scratch, "vwm", &viewer_key);
    let requester_store = limited::store_key(&w.scratch, "rqm", &requester_key);
    let viewer = Peer::new(&w.scratch, "vw", viewer_key, &w.sshd, &w.account);
    let requester = Peer::new(&w.scratch, "rq", requester_key, &w.sshd, &w.account);
    let (mut owner_session, _owner_child) =
        w.session(&owner).await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(owner_session.server().role, Some(Role::Owner));
    assert_eq!(
        owner_session.server().remote_client.as_ref(),
        Some(&owner_client)
    );

    // t-ra1: an unattended paired owner's widening is a pending record; nothing executes.
    let invite_viewer = w.invite("viewer", &viewer, "a25-invite-viewer");
    let pending = owner_session.request(invite_viewer.clone()).await.unwrap();
    assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
    let viewer_decision = pending.next.unwrap().decision_ref.unwrap();
    assert_eq!(
        std::fs::read_to_string(&w.keys_file).unwrap(),
        owner_line,
        "nothing is written before the runner-local decision"
    );
    observe(
        CASE,
        "t-ra1",
        "paired_owner_widening=APPROVAL_REQUIRED executed=nothing lines_written=0",
    );

    // t-ra2: a paired session never decides or attends.
    let decided = owner_session
        .request(decide(&viewer_decision))
        .await
        .unwrap();
    assert_eq!(decided.code.as_str(), "INTERACTION_REQUIRED", "{decided:?}");
    let attended = owner_session.attend().await.unwrap();
    assert_eq!(
        attended.code.as_str(),
        "INTERACTION_REQUIRED",
        "{attended:?}"
    );
    assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), owner_line);
    observe(
        CASE,
        "t-ra2",
        "paired_decide=INTERACTION_REQUIRED paired_attend=INTERACTION_REQUIRED",
    );

    // unattended-local: a local session the owner does not attend cannot decide either.
    {
        let info = heimdall_runtime::instance::InstanceInfo::read_valid(
            &heimdall_runtime::Paths::under(&w.runner.home).runtime_dir,
        )
        .unwrap()
        .expect("the runner runtime's advertisement");
        let stream = heimdall_ipc::unix::connect(Path::new(&info.control_endpoint))
            .await
            .unwrap();
        let mut local = ControlClient::handshake(
            stream,
            PeerInfo {
                name: "heimdall-cli".into(),
                version: "test".into(),
            },
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let refused = local.request(decide(&viewer_decision)).await.unwrap();
        assert_eq!(refused.code.as_str(), "INTERACTION_REQUIRED", "{refused:?}");
        assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), owner_line);
    }
    observe(
        CASE,
        "unattended-local",
        "unattended_local_decide=INTERACTION_REQUIRED lines_written=0",
    );

    // The runner-local confirmation: the attended local owner approves both invitations.
    let mut at_runner = attend_at(&w.runner).await;
    let approved = at_runner.request(decide(&viewer_decision)).await.unwrap();
    assert_eq!(approved.code.as_str(), "OK", "{approved:?}");
    assert_eq!(approved.data["role"], "viewer", "{approved:?}");
    let viewer_client: ClientId = serde_json::from_value(approved.data["client"].clone()).unwrap();
    let viewer_approved = approved.data.clone();
    let pending = owner_session
        .request(w.invite("requester", &requester, "a25-invite-requester"))
        .await
        .unwrap();
    assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
    let approved = at_runner
        .request(decide(&pending.next.unwrap().decision_ref.unwrap()))
        .await
        .unwrap();
    assert_eq!(approved.code.as_str(), "OK", "{approved:?}");
    let requester_approved = approved.data.clone();

    // t-ra3: the decided request replayed returns the recorded terminal result.
    let lines_before = std::fs::read_to_string(&w.keys_file).unwrap();
    let replayed = owner_session.request(invite_viewer).await.unwrap();
    assert_eq!(replayed.data, viewer_approved, "{replayed:?}");
    assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), lines_before);
    observe(
        CASE,
        "t-ra3",
        "replay_after_runner_local_decision=recorded_terminal_result new_record=false \
         reexecuted=false",
    );

    // pending-key: only the activation probe and `join`.
    let (mut viewer_pending, viewer_child) =
        w.session(&viewer).await.unwrap_or_else(|e| panic!("{e}"));
    let only: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
    assert_eq!(viewer_pending.server().capabilities, only);
    let other = viewer_pending.request(inspect()).await.unwrap();
    assert!(
        !other.code.is_success(),
        "a pending key read state: {other:?}"
    );
    let probe: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "activation_probe",
        "environment": w.environment, "nonce": viewer_approved["probe_nonce"],
    }))
    .unwrap();
    let echoed = viewer_pending.request(probe).await.unwrap();
    assert_eq!(echoed.code.as_str(), "OK", "{echoed:?}");
    observe(
        CASE,
        "pending-key",
        format!(
            "capabilities=remote-control/1_only other_request={} activation_probe=OK",
            other.code.as_str()
        ),
    );

    // limited-client (the line): the four confirming probes, and a shell command.
    let observed = w.probes(&viewer).await;
    assert_eq!(observed, ALL_REFUSED);
    // (Asynchronous, with a bound: the key's session agent is served by this runtime.)
    let shell = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(find_program("ssh").unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &viewer.dir)
            .arg("-F")
            .arg(viewer.dir.join("mgmt.conf"))
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "CertificateFile=none",
                "--",
            ])
            .arg(format!("hm-env-{}", w.environment))
            .arg("echo hm-shell-ran")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the shell-command session ended")
    .unwrap();
    assert!(
        !String::from_utf8_lossy(&shell.stdout).contains("hm-shell-ran"),
        "a management key ran a shell command"
    );

    // invitation-wrong-key: the requester's pending session with the viewer's invitation.
    let (mut requester_pending, requester_child) = w
        .session(&requester)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let wrong = requester_pending
        .request(w.join(&viewer_approved, "viewer", observed))
        .await
        .unwrap();
    assert!(!wrong.code.is_success(), "{wrong:?}");
    observe(
        CASE,
        "invitation-wrong-key",
        format!(
            "join_with_another_keys_invitation={} reason={}",
            wrong.code.as_str(),
            refusal(&wrong).1
        ),
    );

    // The viewer joins; its invitation is consumed.
    let joined = viewer_pending
        .request(w.join(&viewer_approved, "viewer", observed))
        .await
        .unwrap();
    assert_eq!(
        joined.code.as_str(),
        "OK",
        "{joined:?}\n{}",
        runner_stderr(&w.runner)
    );
    drop(viewer_pending);
    drop(viewer_child);
    // limited-session-hello: what a joined viewer's next session negotiates. A hello that
    // requires `remote-control/1` (what the product's session opener sends for an owner
    // record) is refused: the role table gives it to no limited role. ⟨w5e; D1⟩ For a
    // limited record the opener requires nothing (`limited-product-hello`, below).
    let product_hello = match w.session(&viewer).await {
        Ok(_) => "served".to_owned(),
        Err(e) => ["CAPABILITY_UNAVAILABLE", "SCHEMA_UNSUPPORTED"]
            .into_iter()
            .find(|c| e.contains(c))
            .map_or_else(
                || panic!("no explicit refusal: {e}"),
                |c| format!("refused_{c}"),
            ),
    };
    let (mut viewer_session, _viewer_child) = w
        .limited_session(&viewer)
        .await
        .unwrap_or_else(|e| panic!("{e}\n{}", runner_stderr(&w.runner)));
    assert_eq!(viewer_session.server().role, Some(Role::Viewer));
    assert!(
        !viewer_session
            .server()
            .capabilities
            .contains(capability::REMOTE_CONTROL_V1)
            && !viewer_session
                .server()
                .capabilities
                .contains(capability::RUNNER_V1),
        "a viewer negotiated an owner capability"
    );
    observe(
        CASE,
        "limited-session-hello",
        format!(
            "joined_viewer_hello_requiring_nothing=served role=viewer \
             remote_control=not_negotiated runner=not_negotiated \
             joined_viewer_hello_requiring_remote_control={product_hello}"
        ),
    );
    assert_eq!(
        viewer_session.server().remote_client.as_ref(),
        Some(&viewer_client)
    );
    let again = viewer_session
        .request(w.join(&viewer_approved, "viewer", observed))
        .await
        .unwrap();
    assert!(!again.code.is_success(), "{again:?}");
    let replay = requester_pending
        .request(w.join(&viewer_approved, "viewer", observed))
        .await
        .unwrap();
    assert!(!replay.code.is_success(), "{replay:?}");
    observe(
        CASE,
        "invitation-consumed",
        format!(
            "join_again_by_its_key={} join_by_another_key={}",
            again.code.as_str(),
            replay.code.as_str()
        ),
    );
    // The requester joins with its own invitation.
    let joined = requester_pending
        .request(w.join(&requester_approved, "requester", w.probes(&requester).await))
        .await
        .unwrap();
    assert_eq!(joined.code.as_str(), "OK", "{joined:?}");
    drop(requester_pending);
    drop(requester_child);
    let (mut requester_session, _requester_child) = w
        .limited_session(&requester)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(requester_session.server().role, Some(Role::Requester));

    // t-ra4 and limited-client (the session): no widening, no issuance.
    let outsider = Peer::new(
        &w.scratch,
        "x",
        MgmtKey::generate().unwrap(),
        &w.sshd,
        &w.account,
    );
    // A widening of the client set (an invitation) is not even dispatched for it: the
    // form needs `remote-control/1`. A widening of a standing policy is refused by role.
    let invites = viewer_session
        .request(w.invite("owner", &outsider, "a25-viewer-invites"))
        .await
        .unwrap();
    assert!(!invites.code.is_success(), "{invites:?}");
    let widening: Request = serde_json::from_value(serde_json::json!({
        "op": "policy", "action": "clear_cutoff", "policy_id": "runner-pol",
    }))
    .unwrap();
    let widening = viewer_session.request(widening).await.unwrap();
    assert_eq!(refusal(&widening).1, "role_insufficient", "{widening:?}");
    assert_eq!(
        std::fs::read_to_string(&w.keys_file)
            .unwrap()
            .lines()
            .count(),
        3
    );
    observe(
        CASE,
        "t-ra4",
        format!(
            "limited_client_policy_widening={} reason=role_insufficient \
             limited_client_invitation={} lines_written=0",
            widening.code.as_str(),
            invites.code.as_str()
        ),
    );
    let ensure = |request: &str, work: &str, named: bool| {
        Request::Ensure(EnsureRequest {
            profile: Some(ProfileId::parse("runner-profile").unwrap()),
            profile_revision: None,
            scope: [pair.clone()].into_iter().collect(),
            environment: None,
            work_id: WorkId::parse(work).unwrap(),
            until: Some(DeadlineIntent::Duration("10m".into())),
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse(request).unwrap(),
            interaction: InteractionMode::NonInteractive,
            wait: WaitMode::Async,
            connection: None,
            context: None,
            covered_only: false,
            pair_issuers: if named {
                vec![PairIssuer {
                    pair: pair.clone(),
                    ca_fingerprint: ca_fingerprint.clone(),
                }]
            } else {
                Vec::new()
            },
        })
    };
    let viewer_issue = viewer_session
        .request(ensure("a25-viewer-ensure", "job-viewer", true))
        .await
        .unwrap();
    assert!(
        !matches!(
            viewer_issue.code.as_str(),
            "OK" | "ACCESS_READY" | "ACCEPTED"
        ),
        "a viewer obtained a grant: {viewer_issue:?}"
    );
    observe(
        CASE,
        "limited-client",
        format!(
            "shell_command=not_run pty=refused forward=refused agent_forwarding=refused \
             setenv=not_delivered viewer_ensure={} reason={}",
            viewer_issue.code.as_str(),
            refusal(&viewer_issue).1
        ),
    );

    // collision: the owner and the requester use the same request ID.
    let same = "a25-same-request-id";
    let by_owner = owner_session
        .request(ensure(same, "job-owner", true))
        .await
        .unwrap();
    let by_requester = requester_session
        .request(ensure(same, "job-requester", true))
        .await
        .unwrap();
    // Asynchronous requests: each is accepted as its own operation.
    assert_eq!(by_owner.code.as_str(), "ACCEPTED", "{by_owner:?}");
    assert_eq!(by_requester.code.as_str(), "ACCEPTED", "{by_requester:?}");
    assert!(by_owner.operation_id.is_some() && by_requester.operation_id.is_some());
    assert_ne!(
        by_requester.operation_id, by_owner.operation_id,
        "the requester was answered with the owner's operation"
    );
    // Each client's replay reads its own operation: the owner's grant waits for its
    // issuer; the requester's is refused (the CA is trusted for the owner's client only).
    let mut requester_again = requester_session
        .request(ensure(same, "job-requester", true))
        .await
        .unwrap();
    for _ in 0..50 {
        if requester_again.code.as_str() != "ACCEPTED" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        requester_again = requester_session
            .request(ensure(same, "job-requester", true))
            .await
            .unwrap();
    }
    assert_eq!(requester_again.operation_id, by_requester.operation_id);
    assert_eq!(
        refusal(&requester_again),
        (
            "CAPABILITY_UNAVAILABLE".to_owned(),
            "issuer_untrusted".to_owned()
        ),
        "{requester_again:?}"
    );
    let owner_again = owner_session
        .request(ensure(same, "job-owner", true))
        .await
        .unwrap();
    assert_eq!(owner_again.operation_id, by_owner.operation_id);
    assert_eq!(owner_again.code.as_str(), "ACCEPTED", "{owner_again:?}");
    observe(
        CASE,
        "collision",
        "same_request_id operations=2 owner=ACCEPTED_pending_its_issuer \
         requester=CAPABILITY_UNAVAILABLE reason=issuer_untrusted each_replays_its_own=true",
    );

    // ⟨w5e; D1⟩ The limited roles from the product client (`a25_limited.rs`).
    let requester_client: ClientId =
        serde_json::from_value(requester_approved["client"].clone()).unwrap();
    limited::journey(
        &w,
        &limited::Limited {
            peer: &viewer,
            client: &viewer_client,
            role: Role::Viewer,
            store: &viewer_store,
        },
        &limited::Limited {
            peer: &requester,
            client: &requester_client,
            role: Role::Requester,
            store: &requester_store,
        },
        limited::Owner {
            peer: &owner,
            client: &owner_client,
            controller: owner_controller,
        },
        &pair,
    )
    .await;

    // host-key-replaced: another daemon, another host key, behind the same pin.
    let other_scratch = Scratch::new().unwrap();
    let impostor = LoopbackSshd::start(
        &other_scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            ..SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("the second fixture sshd: {}", e.reason));
    let impostor_registry = impostor.registry_path().unwrap().to_path_buf();
    let _ = std::fs::remove_file(&impostor_registry);
    std::os::unix::fs::symlink(&w.keys_file, &impostor_registry).unwrap();
    assert_ne!(host_key(&impostor), host_key(&w.sshd));
    let refused = connect_with(
        &owner.dir,
        &impostor,
        &host_key(&w.sshd),
        &w.account,
        &owner.public_line,
        &w.environment,
        client_hello(false),
    )
    .await;
    assert!(
        refused.is_err(),
        "a session opened to a host presenting another key"
    );
    // Why, from the same isolated configuration (the session opener's kept stderr may
    // not be complete when the handshake fails): the system `ssh` refuses the host key.
    let direct = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(find_program("ssh").unwrap())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &owner.dir)
            .arg("-F")
            .arg(owner.dir.join("mgmt.conf"))
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "CertificateFile=none",
                "--",
            ])
            .arg(format!("hm-env-{}", w.environment))
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the refused session ended")
    .unwrap();
    let why = String::from_utf8_lossy(&direct.stderr).into_owned();
    assert!(
        !direct.status.success() && why.contains("Host key verification failed"),
        "{why}"
    );
    let pins = std::fs::read_to_string(owner.dir.join("known_hosts")).unwrap();
    assert!(
        pins.contains(&host_key(&w.sshd)) && !pins.contains(&host_key(&impostor)),
        "the pin file holds the recorded key only"
    );
    assert!(
        impostor.accepted_log().is_empty(),
        "nothing authenticated there"
    );
    drop(impostor);
    let (genuine, _genuine_child) = w.session(&owner).await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(genuine.server().role, Some(Role::Owner));
    drop(genuine);
    observe(
        CASE,
        "host-key-replaced",
        "session=refused_host_key_verification authenticated=nothing pin=unchanged \
         genuine_host=ok",
    );

    // old-client and missing-capability: refused explicitly at the hello.
    let mut old = client_hello(false);
    old.schema_version = heimdall_contract::SchemaVersion("0".to_owned());
    let Err(old) = connect_with(
        &owner.dir,
        &w.sshd,
        &host_key(&w.sshd),
        &w.account,
        &owner.public_line,
        &w.environment,
        old,
    )
    .await
    else {
        panic!("an unsupported schema version was served");
    };
    assert!(old.contains("SCHEMA_UNSUPPORTED"), "{old}");
    observe(CASE, "old-client", "hello=refused code=SCHEMA_UNSUPPORTED");
    let mut wanting = client_hello(false);
    let missing = "a25-no-such-capability/1".to_owned();
    wanting.capabilities.insert(missing.clone());
    wanting.required.insert(missing);
    let Err(wanting) = connect_with(
        &owner.dir,
        &w.sshd,
        &host_key(&w.sshd),
        &w.account,
        &owner.public_line,
        &w.environment,
        wanting,
    )
    .await
    else {
        panic!("a session requiring an unknown capability was served");
    };
    let named = ["SCHEMA_UNSUPPORTED", "CAPABILITY_UNAVAILABLE"]
        .into_iter()
        .find(|c| wanting.contains(c))
        .unwrap_or_else(|| panic!("no explicit refusal: {wanting}"));
    observe(
        CASE,
        "missing-capability",
        format!("hello=refused code={named}"),
    );

    // positive-control: a line that also grants agent forwarding really forwards.
    assert_eq!(recorded_downgrade(&w.runner.home), None);
    let control = Peer::new(
        &w.scratch,
        "pc",
        MgmtKey::generate().unwrap(),
        &w.sshd,
        &w.account,
    );
    let options = owner_line
        .split_once(" ssh-ed25519 ")
        .map(|(options, _)| options.to_owned())
        .unwrap();
    let mut keys = std::fs::read_to_string(&w.keys_file).unwrap();
    keys.push_str(&format!(
        "{} {} fixture-positive-control\n",
        options.replacen("restrict,", "restrict,agent-forwarding,", 1),
        control.text
    ));
    std::fs::write(&w.keys_file, keys).unwrap();
    let (control_session, _control_child) =
        w.session(&control).await.unwrap_or_else(|e| panic!("{e}"));
    let forwarded = w.probes(&control).await;
    assert_eq!(
        forwarded,
        ProbeObservation {
            agent_forward_refused: false,
            ..ALL_REFUSED
        }
    );
    drop(control_session);
    assert_eq!(
        recorded_downgrade(&w.runner.home).as_deref(),
        Some("session_agent_forwarded")
    );
    // Limited roles only after verification: the running runner is owner-only now.
    let late = Peer::new(
        &w.scratch,
        "lt",
        MgmtKey::generate().unwrap(),
        &w.sshd,
        &w.account,
    );
    let pending = owner_session
        .request(w.invite("viewer", &late, "a25-invite-late"))
        .await
        .unwrap();
    assert_eq!(pending.code.as_str(), "APPROVAL_REQUIRED", "{pending:?}");
    let refused = at_runner
        .request(decide(&pending.next.unwrap().decision_ref.unwrap()))
        .await
        .unwrap();
    assert_eq!(
        refusal(&refused).1,
        "management_sshd_unverified",
        "{refused:?}"
    );
    observe(
        CASE,
        "positive-control",
        "restricted_line_agent_forwarding=refused control_line_agent_forwarding=forwarded \
         bridge=refused_session downgrade=session_agent_forwarded \
         limited_role_after=management_sshd_unverified",
    );

    drop(at_runner);
    drop(owner_session);
    drop(viewer_session);
    drop(requester_session);
    for peer in [owner, viewer, requester, outsider, control, late] {
        peer.agent.stop().await;
    }
    drop(w);
}
