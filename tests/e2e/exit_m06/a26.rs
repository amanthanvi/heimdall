//! ⟨M06 W5 U7; W5 `w5d`⟩ **A26: Iroh, route failover and trust** (m06-plan §3 row "A26";
//! spec A26), with the real `--features iroh` binary and **real Iroh traffic on loopback**.
//!
//! **Fixture key store: mechanism evidence only.** The product keeps K_iroh only in the
//! account's verified platform store, which a test in the owner's account must never touch.
//! Every installation of this journey therefore runs with the debug build's
//! `HEIMDALL_TEST_IROH_KEY_STORE` (a scratch directory per installation, store kind
//! `fixture_store`). The serving runner's serve child forwards to a fixture sshd through
//! the **product's own serve setting**, the serve policy's `sshd_port` (`transport enable
//! --serve --sshd-port <n>`, ADR-0006 §18.9 item 1; no test variable names the target):
//! the paired owner's serve request carries it, the runner-local approval is bound to it,
//! and it is read back from durable state at every start. **Every observation
//! line of this journey ends with `key_store=fixture_store`**: it shows the mechanism with
//! the product binary, never product persistence of K_iroh. No relay, no container, no
//! non-loopback bind, no public network.
//!
//! **The installations** (one host):
//! * the *dialing* side is the runner of the shared grant world (`world::journey`): it holds
//!   a live managed grant issued by the controller's issuer child, so its binding endpoint
//!   offers a K_env certificate the fixture destination accepts. Its K_iroh comes from the
//!   real `transport enable` (a minimal dialer endpoint needs no decision). Its catalog
//!   destination is **seeded** as a managed destination (routes need one), with a per-run
//!   fixture public key as the pair's catalog identity;
//! * the *serving* side is a second runner (`remote init --iroh-endpoint <dialer>` on a
//!   pseudo-terminal, a typed `yes`, `service run --runner`) whose serve child forwards to
//!   the same fixture destination sshd.
//!
//! Driven here, one observation line each:
//!
//! * `store-unusable`: with the variable naming a directory that does not exist,
//!   `transport enable` is refused `transport_key_store_unavailable` and records nothing
//!   (the fixture store never falls back to the platform store);
//! * `dialer-key`: the dialing installation's endpoint key is created by `transport enable`;
//! * `build`, `exposure-serve`, `exposure-relay`, `no-remote-decision`, `nothing-exposed`:
//!   the paired owner's widenings (serve; a relay nobody approved; the `n0-public` profile)
//!   stay pending decisions of the runner's local owner, no paired or unattended session
//!   decides one, and nothing is created or started meanwhile;
//! * `sshd-port-flag`: the real `transport enable --serve --sshd-port` refuses `0` and a
//!   value past 65535 before any contact, and the runner's own **unattended** owner naming
//!   the fixture sshd's port is answered `INTERACTION_REQUIRED`: nothing is recorded (only
//!   an attended local session submits a local widening);
//! * `serve-local-submit`, `serve-local-approve` (⟨W5 `w5m`; ADR-0006 §18.9 item 8⟩): the
//!   serve widening is the runner's **local owner's own**, through the product CLI on a
//!   terminal: `transport enable --serve --sshd-port <n>` answers `APPROVAL_REQUIRED` with
//!   a local decision record (no client) bound to the serve and sshd-port delta; the same
//!   command again returns that record; neither the paired owner nor a non-interactive
//!   `decision approve` approves it; `decision approve` on a terminal with a typed `yes`
//!   applies it;
//! * `paired-after-local`: the paired owner's earlier serve request stays a record of its
//!   own with its client, and an attended local approval of it after the local serve is
//!   refused and applies nothing (the delta it was bound to no longer holds);
//! * `serve`: after that approval the key is created, the serve child runs, bound to
//!   loopback with no relay, and the recorded policy names the fixture sshd's port;
//! * `route-iroh`: on the dialing side the real `route add --iroh` approves the route and
//!   the destination's own address is removed, so the Iroh route is the only one; an
//!   onward `ssh` whose `ProxyCommand` is the real `route connect` logs in at the fixture
//!   destination with the pinned host key and the K_env certificate;
//! * `serve-restart`: the serving runtime is stopped (a login is then refused) and started
//!   again: a new serve child, the same endpoint ID and port, the same recorded sshd port
//!   (its only source after the restart is durable state), and the unchanged route logs in
//!   again;
//! * `unapproved-hint`: a route carrying a relay nobody approved is, for the attended local
//!   owner, a pending local decision that is never approved here, and for the same owner
//!   unattended it is `INTERACTION_REQUIRED`, naming the relay; either way nothing is written;
//! * `failover-before-identification`: with the Iroh route first and a direct route second,
//!   and no server behind the Iroh route, the helper moves on before any identification
//!   string and the login succeeds over the direct route;
//! * `late-refusal-terminal`: a live session over the Iroh route (the direct route still
//!   approved after it) is closed by the serving side after forwarding began: the session
//!   fails and its command never completes over the other route;
//! * `revocation`: that close is the serving runner's local owner revoking the client the
//!   dialing endpoint was admitted with. The answer reports `iroh_admission: applied`, and
//!   the live session has ended by then; the endpoint is no longer enrolled; a new dial is
//!   refused before identification (the helper fails over to the direct route) and, with
//!   the Iroh route alone, nothing connects;
//! * `disable`: `transport disable` stops the serve child and leaves no active key, no
//!   store item and no recorded port.
//! * `paired-approve` (⟨W5 `w5o`⟩): on a serving runner of its own that serves nothing yet
//!   (on the first one the owner client is revoked by then), the **paired owner's** serve
//!   request is a pending record naming its client; a non-interactive `decision approve`
//!   sends nothing; the runner's local owner approves it on a terminal with a typed `yes`,
//!   and the effect is installed (the key, the recorded sshd port, the serve child); the
//!   paired owner's replay returns the recorded result. Serving is disabled at the end.
//!
//! **Not driven here** (`NOT-COVERED.md`): product persistence of K_iroh in a verified
//! store; the relay path and the profile's traffic capture; containers; the devbox;
//! Windows; real NATs; `n0-public`; a crash mid-revocation and a session killed mid-route
//! (mechanism: `integration_transport_supervise_m06`); a key rotation; jump routes.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::ids::{ClientId, DecisionId};
use heimdall_contract::ipc::{PeerInfo, capability};
use heimdall_contract::request::{DecideRequest, InteractionMode, Request, Verdict};
use heimdall_credential::mgmt::{MgmtKey, MgmtSigner, SessionAgent};
use heimdall_ipc::session::ControlClient;
use heimdall_store::ext_transport::TransportKeyRecord;
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::find_program;
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;

use super::m06::{blocked, children_of, forwarded_ensure, logs, runner_json};
use super::world::{
    HOUR, Journey, MgmtClient, Runner, attend_at, bin, client_hello, connect_with, envelope,
    host_key, journey as start, listed_identities, state_db,
};

const CASE: &str = "a26";

/// The label every observation of this journey carries: all of it runs with the fixture
/// K_iroh store (mechanism evidence, never product persistence).
const FIXTURE: &str = "key_store=fixture_store";

/// One step's result, labelled [`FIXTURE`].
fn observe(case: &str, step: &str, result: impl std::fmt::Display) {
    super::m06::observe(case, step, format!("{result} {FIXTURE}"));
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn transport(body: Value) -> Request {
    serde_json::from_value(body).unwrap()
}

pub(crate) fn read<T>(
    home: &Path,
    f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<T>,
) -> T {
    Store::open_read_only(&state_db(home), Arc::new(NoFaults))
        .unwrap()
        .transaction(f)
        .unwrap()
}

fn keys_recorded(runner: &Runner) -> Vec<TransportKeyRecord> {
    read(&runner.home, |tx| tx.transport_keys())
}

/// The sshd port of the runner's recorded serve policy (durable state).
fn recorded_sshd_port(runner: &Runner) -> Option<u16> {
    read(&runner.home, |tx| {
        heimdall_app::transport::endpoint_state(tx).map(|e| Some(e.policy.sshd_port))
    })
}

fn active_key(runner: &Runner) -> Option<TransportKeyRecord> {
    read(&runner.home, |tx| tx.active_transport_key())
}

/// Wait up to `bound` for `f` to answer.
pub(crate) fn wait_for<T>(what: &str, bound: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(start.elapsed() < bound, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The owner's management session to the serving runner: the session and what keeps it.
struct Owner {
    session: MgmtClient,
    _child: tokio::process::Child,
    agent: SessionAgent,
}

/// The serving runner's world: its management sshd and its owner.
pub(crate) struct Serving {
    pub(crate) runner: Runner,
    sshd: LoopbackSshd,
    account: String,
    owner: ClientId,
    key: MgmtKey,
    environment: String,
}

impl Serving {
    async fn owner_session(&self, dir: &Path) -> Owner {
        let key = MgmtKey::from_store_bytes(&self.key.to_store_bytes()).unwrap();
        let public = key.public().unwrap();
        let signer =
            MgmtSigner::with_host_key_lines(key, [self.account.clone()], &[host_key(&self.sshd)])
                .unwrap();
        let agent = SessionAgent::start(&dir.join("a.sock"), signer).unwrap();
        let mut hello = client_hello(true);
        hello
            .capabilities
            .insert(capability::TRANSPORT_IROH_V1.to_owned());
        hello.capabilities.insert(capability::ROUTES_V1.to_owned());
        let (session, child) = connect_with(
            dir,
            &self.sshd,
            &host_key(&self.sshd),
            &self.account,
            &public.openssh_line,
            &self.environment,
            hello,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        Owner {
            session,
            _child: child,
            agent,
        }
    }
}

/// A local owner session on `runner`'s own control endpoint offering `capabilities`,
/// attended when `attended`.
async fn local_session(
    runner: &Runner,
    capabilities: &[&str],
    attended: bool,
) -> ControlClient<tokio::net::UnixStream> {
    let info = heimdall_runtime::instance::InstanceInfo::read_valid(
        &heimdall_runtime::Paths::under(&runner.home).runtime_dir,
    )
    .unwrap()
    .expect("the runtime's advertisement");
    let stream = heimdall_ipc::unix::connect(Path::new(&info.control_endpoint))
        .await
        .unwrap();
    let mut client = ControlClient::handshake(
        stream,
        PeerInfo {
            name: "heimdall-cli".into(),
            version: "test".into(),
        },
        capabilities.iter().map(|c| (*c).to_owned()).collect(),
        if attended {
            InteractionMode::Interactive
        } else {
            InteractionMode::NonInteractive
        },
    )
    .await
    .unwrap();
    if attended {
        assert_eq!(client.attend().await.unwrap().code.as_str(), "OK");
    }
    client
}

/// One onward `ssh` from the dialing installation to the destination **through the route
/// helper** (`ProxyCommand heimdall route connect`), with the fixture isolation options and
/// the binding's endpoint as the only agent. `remote` is the command run there.
fn route_ssh(
    j: &Journey,
    dir: &Path,
    endpoint: &str,
    certificate_line: &str,
    remote: &str,
) -> Command {
    std::fs::create_dir_all(dir).unwrap();
    let config = dir.join("ssh_config");
    std::fs::write(&config, "").unwrap();
    let known = dir.join("known_hosts");
    std::fs::write(&known, format!("{}\n", j.destination.host_key_line)).unwrap();
    let identity = dir.join("id-cert.pub");
    std::fs::write(&identity, format!("{certificate_line}\n")).unwrap();
    let helper = format!(
        "{} --home {} route connect --destination {} --account {} --endpoint {}",
        bin(),
        j.runner.home.display(),
        j.pair.destination.as_str(),
        j.account,
        endpoint
    );
    let mut cmd = Command::new(find_program("ssh").expect("an OpenSSH client"));
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &j.runner.account)
        .env("HEIMDALL_HOME", &j.runner.home)
        .env("HEIMDALL_TEST_SSH_HOME", &j.runner.account)
        .env(
            "HEIMDALL_TEST_IROH_KEY_STORE",
            j.runner.iroh_store.as_ref().unwrap(),
        )
        .arg("-F")
        .arg(&config)
        .args(["-T", "-o", "BatchMode=yes"])
        .args(["-o", &format!("ProxyCommand={helper}")])
        .args(["-o", &format!("IdentityFile={}", identity.display())])
        .args(["-o", "IdentitiesOnly=yes"])
        .args(["-o", &format!("IdentityAgent={endpoint}")])
        .args(["-o", "CertificateFile=none"])
        .args(["-o", &format!("UserKnownHostsFile={}", known.display())])
        .args(["-o", "GlobalKnownHostsFile=/dev/null"])
        .args(["-o", "StrictHostKeyChecking=yes"])
        .args(["-o", "ControlMaster=no", "-o", "ControlPath=none"])
        .args(["-o", "PreferredAuthentications=publickey"])
        .args(["-o", "ConnectTimeout=60"])
        .args(["-p", &j.destination.port.to_string()])
        .arg(format!("{}@{}", j.account, j.destination.host))
        .arg(remote)
        .stdin(Stdio::null());
    cmd
}

/// [`route_ssh`] run to its end with `echo hm-onward`: `(succeeded, output)`.
fn route_login(j: &Journey, dir: &Path, endpoint: &str, certificate_line: &str) -> (bool, String) {
    let out = route_ssh(j, dir, endpoint, certificate_line, "echo hm-onward")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_canary(&text);
    (out.status.success() && text.contains("hm-onward"), text)
}

pub(crate) fn journey() {
    // --- the dialing side: a runner installation with a live managed grant ----------------
    let Some(mut j) = start(|_| Vec::new(), 4 * HOUR) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let account = j.account.clone();
    // Its K_iroh lives in a fixture store from here on (the runtime restarts with it).
    j.runner.runtime_stop();
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    j.runner.with_iroh_fixture_store(&scratch, "dk");
    // **Seeded** while no runtime runs: the destination becomes a managed catalog
    // destination at the fixture sshd's address for the pair's account, as the routes of a
    // destination need; its catalog identity (the pair's "existing access", never used
    // here) is a per-run fixture public key at an agent path that does not exist.
    {
        use heimdall_domain::catalog::{
            DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
            InteractionProfile,
        };
        let existing = heimdall_testkit::agent::FixtureKey::generate();
        let identity = heimdall_contract::ids::IdentityId::from_random_bytes([0x26; 16]);
        let now = heimdall_contract::Timestamp::now();
        let store = Store::open(&state_db(&j.runner.home), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.upsert_identity(&IdentityRecord {
                    id: identity.clone(),
                    revision: 1,
                    source: IdentitySource::NativeAgent {
                        endpoint: heimdall_contract::provider::EndpointRef {
                            kind: heimdall_contract::provider::EndpointKind::UnixSocket,
                            locator: scratch
                                .path()
                                .join("no-such-agent.sock")
                                .to_string_lossy()
                                .into_owned(),
                        },
                    },
                    public_key: existing.public_line_without_comment(),
                    fingerprint: existing.fingerprint(),
                    interaction: InteractionProfile {
                        interaction: heimdall_contract::provider::InteractionKind::None,
                        basis: heimdall_contract::provider::EvidenceBasis::Observed,
                    },
                    label: None,
                    adopted_at: now,
                    updated_at: now,
                })?;
                tx.upsert_destination(&DestinationRecord {
                    id: j.pair.destination.clone(),
                    alias: j.pair.destination.as_str().to_owned(),
                    revision: 2,
                    definition: DestinationDefinition::Managed {
                        hostname: j.destination.host.clone(),
                        port: Some(j.destination.port),
                        account: j.pair.account.clone(),
                        identity: identity.clone(),
                        jump: None,
                    },
                    label: None,
                    updated_at: now,
                })
            })
            .unwrap();
    }
    // First with the variable naming a directory that does not exist: the fixture store is
    // still the only store selected, so the key is refused and nothing is recorded.
    let good = j
        .runner
        .iroh_store
        .replace(scratch.path().join("no-such-store"));
    j.runner.start();
    let refused = runner_json(&j.runner, &["transport", "enable"]);
    assert_eq!(refused["code"], "CAPABILITY_UNAVAILABLE", "{refused}");
    assert_eq!(
        refused["data"]["error"]["reason"], "transport_key_store_unavailable",
        "{refused}"
    );
    assert!(keys_recorded(&j.runner).is_empty());
    assert!(!scratch.path().join("no-such-store").exists());
    observe(
        CASE,
        "store-unusable",
        "variable=names_a_missing_directory transport_enable=CAPABILITY_UNAVAILABLE \
         reason=transport_key_store_unavailable transport_keys_recorded=0 \
         directory_created=false",
    );
    j.runner.runtime_stop();
    j.runner.iroh_store = good;
    j.runner.start();
    let enabled = runner_json(&j.runner, &["transport", "enable"]);
    assert_eq!(enabled["code"], "OK", "{enabled}\n{}", logs(&j));
    assert_eq!(enabled["data"]["store_kind"], "fixture_store", "{enabled}");
    assert_eq!(enabled["data"]["serve"], false, "{enabled}");
    let dialer = enabled["data"]["endpoint"].as_str().unwrap().to_owned();
    observe(
        CASE,
        "dialer-key",
        "command=transport_enable decision=none_needed serve=false store_kind=fixture_store",
    );
    let (answer, _) = forwarded_ensure(&j, "job-a26", "a26-fwd-1", "1h");
    assert_eq!(answer["code"], "OK", "{answer}\n{}", logs(&j));
    let local = runner_json(
        &j.runner,
        &[
            "access",
            "ensure",
            "--profile",
            "runner-profile",
            "--pair",
            &format!("h1:{account}"),
            "--work-id",
            "job-a26-local",
            "--for",
            "30m",
            "--request-id",
            "a26-local-1",
        ],
    );
    assert!(
        matches!(local["code"].as_str(), Some("OK" | "ACCESS_READY")),
        "{local}\n{}",
        logs(&j)
    );
    let endpoint = local["data"]["consumer"]["signing_endpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    let listed = listed_identities(&endpoint);
    assert_eq!(listed.len(), 1, "{listed:?}");

    // --- the serving side: a second runner whose serve child forwards to the fixture sshd --
    let Some((mut s, runtime)) = serving_runner(&scratch, "s", [0x26; 16], &dialer, &account)
    else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    assert!(keys_recorded(&s.runner).is_empty());

    // --- widenings: pending, undecidable remotely, then approved at the runner ------------
    let dir = scratch.subdir("c").unwrap();
    let served = rt().block_on(widenings(&s, &dir, runtime, j.destination.port));
    assert_eq!(served["store_kind"], "fixture_store", "{served}");
    assert_eq!(served["serve"], true, "{served}");
    assert_eq!(
        served["exposure"]["sshd_port"], j.destination.port,
        "{served}"
    );
    assert_eq!(recorded_sshd_port(&s.runner), Some(j.destination.port));
    let serving = served["endpoint"].as_str().unwrap().to_owned();
    assert_ne!(serving, dialer);
    let key_row = active_key(&s.runner).expect("the serving key's record");
    assert_eq!(key_row.endpoint.as_str(), serving);
    assert_eq!(key_row.store_kind, "fixture_store");
    let port = wait_for(
        "the serve child bound no port",
        Duration::from_secs(30),
        || read(&s.runner.home, |tx| tx.transport_serve_port()),
    );
    let child = wait_for("no serve child", Duration::from_secs(30), || {
        children_of(runtime).first().copied()
    });
    observe(
        CASE,
        "serve",
        "submitted_by=runner_local_owner_on_a_terminal approved_by=the_same_owner_attended \
             serve_child=running bind=loopback relays=none target=fixture_sshd_on_loopback \
             target_port_from=serve_policy_sshd_port",
    );

    // --- a route over Iroh, and an onward login through the route helper ------------------
    let added = runner_json(
        &j.runner,
        &[
            "route",
            "add",
            "h1",
            "--iroh",
            &serving,
            "--address",
            &format!("127.0.0.1:{port}"),
        ],
    );
    assert_eq!(added["code"], "OK", "{added}\n{}", logs(&j));
    let routes = || {
        read(&j.runner.home, |tx| {
            tx.destination_routes(&j.pair.destination)
        })
    };
    let iroh_route = added["data"]["route"].as_str().unwrap().to_owned();
    // Adding a second route made the destination's own address an explicit direct route.
    // It is removed, so the Iroh route is the only approved one.
    let direct_route = routes()
        .iter()
        .find(|r| matches!(r.route, heimdall_contract::route::RouteSpec::Direct { .. }))
        .map(|r| r.id.as_str().to_owned())
        .expect("the destination's own address as a route");
    let removed = runner_json(&j.runner, &["route", "remove", "h1", &direct_route]);
    assert_eq!(removed["code"], "OK", "{removed}");
    assert_eq!(routes().len(), 1, "{:?}", routes());
    let login_dir = scratch.subdir("l").unwrap();
    let login = || route_login(&j, &login_dir, &endpoint, &listed[0]);
    let before = j.destination.accepted_certificates().len();
    let (ok, out) = login();
    assert!(ok, "the login over Iroh: {out}\n{}", logs(&j));
    assert_eq!(j.destination.accepted_certificates().len(), before + 1);
    observe(
        CASE,
        "route-iroh",
        "approved_routes=iroh_only helper=route_connect_as_proxy_command login=ok \
             destination=fixture_sshd credential=dialer_k_env_certificate host_key=pinned \
             catalog=seeded",
    );

    // --- the serve child restarts with the same endpoint identity -------------------------
    s.runner.runtime_stop();
    wait_for(
        "the serve child outlived its runtime",
        Duration::from_secs(30),
        || (!super::m06::alive(child)).then_some(()),
    );
    let (ok, out) = login();
    assert!(!ok, "a login with the serving runtime stopped: {out}");
    s.runner.start();
    let restarted = s
        .runner
        .runtime
        .as_ref()
        .map(std::process::Child::id)
        .unwrap();
    let new_child = wait_for(
        "no serve child after the restart",
        Duration::from_secs(30),
        || children_of(restarted).first().copied(),
    );
    assert_ne!(new_child, child);
    let again = active_key(&s.runner).expect("the serving key's record");
    assert_eq!(again, key_row, "the same key record");
    assert_eq!(
        read(&s.runner.home, |tx| tx.transport_serve_port()),
        Some(port)
    );
    assert_eq!(
        recorded_sshd_port(&s.runner),
        Some(j.destination.port),
        "the sshd port is durable"
    );
    // The route on the dialing side is untouched: it still names that endpoint and port.
    let (ok, out) = wait_for(
        "no login after the restart",
        Duration::from_secs(60),
        || {
            let (ok, out) = login();
            ok.then_some((ok, out))
        },
    );
    assert!(ok, "{out}");
    observe(
        CASE,
        "serve-restart",
        "serving_runtime=stopped_then_started login_while_stopped=refused \
             serve_child=new_process endpoint_id=unchanged serve_port=unchanged \
             sshd_port=unchanged_from_durable_state route=unchanged login_after_restart=ok",
    );

    // --- an unapproved relay hint on a route is refused ------------------------------------
    let hinted = rt().block_on(async {
        let mut at_dialer = local_session(&j.runner, &[capability::ROUTES_V1], true).await;
        at_dialer
            .request(transport(serde_json::json!({
                "op": "route", "action": "add", "destination": "h1",
                "route": {
                    "kind": "iroh", "endpoint": serving,
                    "direct_addresses": [format!("127.0.0.1:{}", port.wrapping_add(1).max(1))],
                },
                "exposure": {
                    "bind": {"kind": "loopback"},
                    "infrastructure": {"kind": "custom", "relays": ["https://relay.invalid./"]},
                    "direct_fallback": false,
                },
                "request_id": "a26-hint-1",
            })))
            .await
            .unwrap()
    });
    // ⟨W5 `w5m`⟩ For the attended local owner it is a pending local decision, never an
    // applied route; for the same owner unattended it is refused outright.
    assert_eq!(hinted.code.as_str(), "APPROVAL_REQUIRED", "{hinted:?}");
    assert_eq!(hinted.data["error"]["effect_status"], "none", "{hinted:?}");
    assert!(
        hinted
            .next
            .as_ref()
            .is_some_and(|n| n.decision_ref.is_some()),
        "{hinted:?}"
    );
    let unattended_hint = rt().block_on(async {
        let mut at_dialer = local_session(&j.runner, &[capability::ROUTES_V1], false).await;
        at_dialer
            .request(transport(serde_json::json!({
                "op": "route", "action": "add", "destination": "h1",
                "route": {
                    "kind": "iroh", "endpoint": serving,
                    "direct_addresses": [format!("127.0.0.1:{}", port.wrapping_add(1).max(1))],
                },
                "exposure": {
                    "bind": {"kind": "loopback"},
                    "infrastructure": {"kind": "custom", "relays": ["https://relay.invalid./"]},
                    "direct_fallback": false,
                },
                "request_id": "a26-hint-2",
            })))
            .await
            .unwrap()
    });
    assert_eq!(
        unattended_hint.code.as_str(),
        "INTERACTION_REQUIRED",
        "{unattended_hint:?}"
    );
    assert!(
        unattended_hint.data["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("the relay https://relay.invalid./")),
        "{unattended_hint:?}"
    );
    assert_eq!(routes().len(), 1, "{:?}", routes());
    observe(
        CASE,
        "unapproved-hint",
        "route_with_unapproved_relay asked_by_attended_local_owner=APPROVAL_REQUIRED_pending \
         asked_by_unattended_local_owner=INTERACTION_REQUIRED_names_the_relay \
         approved=never written=nothing",
    );

    // --- failover only before the identification string ------------------------------------
    let direct = runner_json(
        &j.runner,
        &[
            "route",
            "add",
            "h1",
            "--direct",
            &format!("{}:{}", j.destination.host, j.destination.port),
        ],
    );
    assert_eq!(direct["code"], "OK", "{direct}");
    let order: Vec<String> = routes().iter().map(|r| r.id.as_str().to_owned()).collect();
    assert_eq!(
        order.first(),
        Some(&iroh_route),
        "the Iroh route is tried first"
    );
    assert_eq!(order.len(), 2);
    s.runner.runtime_stop();
    wait_for(
        "the serve child outlived its runtime",
        Duration::from_secs(30),
        || (!super::m06::alive(new_child)).then_some(()),
    );
    let started = Instant::now();
    let (ok, out) = login();
    assert!(ok, "no failover to the direct route: {out}");
    assert!(
        started.elapsed() < Duration::from_secs(45),
        "the failover took {:?}",
        started.elapsed()
    );
    s.runner.start();
    let runtime = s
        .runner
        .runtime
        .as_ref()
        .map(std::process::Child::id)
        .unwrap();
    wait_for(
        "no serve child after the restart",
        Duration::from_secs(30),
        || children_of(runtime).first().copied(),
    );
    observe(
        CASE,
        "failover-before-identification",
        "approved_routes=iroh_then_direct iroh_leg=no_server_before_identification \
         next_route=direct login=ok",
    );
    // The serving side is back when a login over the Iroh route alone succeeds again; then
    // the direct route is approved again, after the Iroh one.
    let removed = runner_json(&j.runner, &["route", "remove", "h1", order[1].as_str()]);
    assert_eq!(removed["code"], "OK", "{removed}");
    wait_for(
        "no login over Iroh after the restart",
        Duration::from_secs(60),
        || login().0.then_some(()),
    );
    let direct = runner_json(
        &j.runner,
        &[
            "route",
            "add",
            "h1",
            "--direct",
            &format!("{}:{}", j.destination.host, j.destination.port),
        ],
    );
    assert_eq!(direct["code"], "OK", "{direct}");
    let order: Vec<String> = routes().iter().map(|r| r.id.as_str().to_owned()).collect();
    assert_eq!(order.first(), Some(&iroh_route));
    assert_eq!(order.len(), 2);

    // --- a late refusal is terminal; revocation closes the live connection ----------------
    let live_dir = scratch.subdir("v").unwrap();
    let (mut live, mut live_out) =
        wait_for("no live session over Iroh", Duration::from_secs(60), || {
            use std::io::BufRead as _;
            let mut child = route_ssh(
                &j,
                &live_dir,
                &endpoint,
                &listed[0],
                "echo hm-live; sleep 120; echo hm-done",
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
            let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            out.read_line(&mut line).unwrap();
            if line.trim() == "hm-live" {
                Some((child, out))
            } else {
                let _ = child.kill();
                let _ = child.wait();
                None
            }
        });
    assert!(live.try_wait().unwrap().is_none(), "the session is live");
    // The runner's local owner revokes the client the dialing endpoint was admitted with.
    let revoked = rt().block_on(async {
        let mut at_runner = local_session(&s.runner, &[capability::REMOTE_CONTROL_V1], false).await;
        at_runner
            .request(transport(serde_json::json!({
                "op": "remote_environment", "action": "revoke_client",
                "environment": s.environment, "client": s.owner,
            })))
            .await
            .unwrap()
    });
    assert_eq!(revoked.code.as_str(), "OK", "{revoked:?}");
    assert_eq!(revoked.data["state"], "revoked", "{revoked:?}");
    assert_eq!(
        revoked.data["iroh_admission"]["state"], "applied",
        "{revoked:?}"
    );
    // The answer said `applied`: the live connection is closed by then. The `ssh` client
    // needs a moment to see its proxy end, so its exit is awaited for a short bound.
    let status = wait_for(
        "the live session outlived a revocation reported applied",
        Duration::from_secs(5),
        || live.try_wait().unwrap(),
    );
    assert!(!status.success(), "the revoked session ended as a success");
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut live_out, &mut rest).unwrap();
    assert!(
        !rest.contains("hm-done"),
        "the session's command completed: it moved to another route"
    );
    assert!(
        read(&s.runner.home, |tx| tx.remote_client_endpoints()).is_empty(),
        "the revoked client's endpoint is still enrolled"
    );
    observe(
        CASE,
        "late-refusal-terminal",
        "approved_routes=iroh_then_direct live_session=over_iroh \
             closed_by=serving_side_after_forwarding session=failed \
             moved_to_direct_route=false",
    );
    // A new connection: the revoked endpoint is refused at admission, before any
    // identification, so the next approved route is taken; with the Iroh route alone
    // nothing connects.
    let (ok, out) = login();
    assert!(ok, "no failover after the admission refusal: {out}");
    let removed = runner_json(&j.runner, &["route", "remove", "h1", order[1].as_str()]);
    assert_eq!(removed["code"], "OK", "{removed}");
    let (ok, out) = login();
    assert!(!ok, "a revoked endpoint was admitted: {out}");
    observe(
        CASE,
        "revocation",
        "revoked_by=runner_local_owner answer=OK iroh_admission=applied \
             live_connection=closed_by_the_answer enrolled_endpoints=0 \
             new_dial=refused_before_identification failover_to_direct=ok \
             iroh_route_alone=refused",
    );

    // --- disable: nothing is left ------------------------------------------------------------
    let disabled = rt().block_on(async {
        let mut at_runner = local_session(&s.runner, &[capability::TRANSPORT_IROH_V1], false).await;
        at_runner
            .request(transport(serde_json::json!({
                "op": "transport", "action": "disable",
            })))
            .await
            .unwrap()
    });
    assert_eq!(disabled.code.as_str(), "OK", "{disabled:?}");
    let runtime = s
        .runner
        .runtime
        .as_ref()
        .map(std::process::Child::id)
        .unwrap();
    wait_for(
        "the serve child outlived disable",
        Duration::from_secs(30),
        || children_of(runtime).is_empty().then_some(()),
    );
    assert!(active_key(&s.runner).is_none());
    let left: Vec<_> = std::fs::read_dir(s.runner.iroh_store.as_ref().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    assert!(left.is_empty(), "the fixture store still holds {left:?}");
    assert!(read(&s.runner.home, |tx| tx.transport_serve_port()).is_none());
    observe(
        CASE,
        "disable",
        "asked_by=runner_local_owner serve_child=stopped active_key=none \
             store_items=0 serve_port=forgotten",
    );

    // --- a paired owner's serve request, approved at the runner (ADR-0012 §3.10) -----------
    // ⟨W5 `w5o` item 3⟩ On a serving runner that serves nothing yet, a PAIRED owner's serve
    // request is approved and executed with real binaries: the paired owner asks, the
    // record names its client, the runner's attended local owner approves it on a
    // terminal, and the effect is installed. A runner of its own: on the first one the
    // owner client was revoked above (`revocation`), and there the local serve came first.
    let Some((s, runtime)) = serving_runner(&scratch, "p", [0x27; 16], &dialer, &account) else {
        blocked(CASE, "no fixture sshd for the second serving runner");
        return;
    };
    let dir = scratch.subdir("pa").unwrap();
    let sshd_port = j.destination.port;
    let serve_request = move || {
        transport(serde_json::json!({
            "op": "transport", "action": "enable", "serve": true,
            "exposure": {
                "bind": {"kind": "loopback"},
                "infrastructure": {"kind": "none"},
                "sshd_port": sshd_port,
            },
            "request_id": "a26-serve-paired-2",
        }))
    };
    let asked = rt().block_on(async {
        let mut owner = s.owner_session(&dir).await;
        let asked = owner.session.request(serve_request()).await.unwrap();
        let Owner { session, agent, .. } = owner;
        drop(session);
        agent.stop().await;
        asked
    });
    assert_eq!(asked.code.as_str(), "APPROVAL_REQUIRED", "{asked:?}");
    let paired_ref = asked
        .next
        .as_ref()
        .and_then(|n| n.decision_ref.clone())
        .expect("the paired serve request names its decision");
    let record = pending_widening(&s.runner, &paired_ref);
    assert_eq!(
        record.origin,
        heimdall_domain::decision::WideningOrigin::Paired
    );
    assert_eq!(record.client.as_ref(), Some(&s.owner));
    assert_eq!(
        record.exposure.as_ref().map(|d| d["serve_after"].clone()),
        Some(serde_json::json!(true))
    );
    assert!(
        active_key(&s.runner).is_none(),
        "applied before the approval"
    );
    assert!(children_of(runtime).is_empty(), "a serve child before it");
    // Not from a non-interactive session; on the runner's terminal, with a typed yes.
    let silent = runner_json(
        &s.runner,
        &["--non-interactive", "decision", "approve", &paired_ref],
    );
    assert_eq!(silent["code"], "INTERACTION_REQUIRED", "{silent}");
    assert!(active_key(&s.runner).is_none());
    let (code, approved) = local_owner_terminal(
        &s.runner,
        &["decision", "approve", &paired_ref],
        Some("yes"),
    );
    assert_eq!(approved["code"], "OK", "{approved}");
    assert_eq!(code, 0, "{approved}");
    // The effect is installed: the key, the recorded policy, the serve child.
    let installed = active_key(&s.runner).expect("the approved serve created the key");
    assert_eq!(installed.store_kind, "fixture_store");
    assert_eq!(recorded_sshd_port(&s.runner), Some(sshd_port));
    wait_for(
        "the approved paired request started no serve child",
        Duration::from_secs(30),
        || children_of(runtime).first().copied(),
    );
    wait_for("no serve port", Duration::from_secs(30), || {
        read(&s.runner.home, |tx| tx.transport_serve_port())
    });
    assert!(
        pending_widenings(&s.runner)
            .iter()
            .all(|(id, _)| id.as_str() != paired_ref),
        "the approved record is still pending"
    );
    // The paired owner's own replay of the same request returns the recorded result and
    // runs nothing again (one key, the same endpoint).
    let dir = scratch.subdir("pb").unwrap();
    let replay = rt().block_on(async {
        let mut owner = s.owner_session(&dir).await;
        let replay = owner.session.request(serve_request()).await.unwrap();
        let Owner { session, agent, .. } = owner;
        drop(session);
        agent.stop().await;
        replay
    });
    assert_eq!(replay.code.as_str(), "OK", "{replay:?}");
    assert_eq!(
        replay.data["endpoint"],
        installed.endpoint.as_str(),
        "{replay:?}"
    );
    assert_eq!(
        active_key(&s.runner).map(|k| k.endpoint),
        Some(installed.endpoint.clone())
    );
    observe(
        CASE,
        "paired-approve",
        "runner=a_serving_runner_of_its_own_serving_nothing \
         asked_by=paired_owner_over_its_management_session answer=APPROVAL_REQUIRED \
         record_origin=paired record_client=the_paired_owner \
         non_interactive_decision_approve=INTERACTION_REQUIRED \
         approved_by=runner_local_owner_on_a_terminal typed=yes answer_after=OK \
         installed=key,serve_policy_sshd_port,serve_child \
         paired_replay=the_recorded_result_same_endpoint",
    );
    // Left as the journey found it: nothing serving, no key.
    let disabled = rt().block_on(async {
        let mut at_runner = local_session(&s.runner, &[capability::TRANSPORT_IROH_V1], false).await;
        at_runner
            .request(transport(serde_json::json!({
                "op": "transport", "action": "disable",
            })))
            .await
            .unwrap()
    });
    assert_eq!(disabled.code.as_str(), "OK", "{disabled:?}");
    wait_for(
        "the serve child outlived the second disable",
        Duration::from_secs(30),
        || children_of(runtime).is_empty().then_some(()),
    );
    assert!(active_key(&s.runner).is_none());
    drop(s);
    drop(j);
}

/// A serving runner named `name` (module docs): `remote init --iroh-endpoint <dialer>` on a
/// pseudo-terminal with a typed `yes` enrolls the owner client `owner` with a fresh
/// management key; its management sshd is a fixture sshd whose registry is the runner's
/// own `authorized_keys`; `service run --runner` is started. Returns it with its runtime's
/// PID, or `None` without a fixture sshd.
pub(crate) fn serving_runner(
    scratch: &heimdall_testkit::home::Scratch,
    name: &str,
    owner: [u8; 16],
    dialer: &str,
    account: &str,
) -> Option<(Serving, u32)> {
    let mut runner = Runner::named(scratch, name);
    runner.with_iroh_fixture_store(scratch, &format!("{name}k"));
    let key = MgmtKey::generate().unwrap();
    let public = key.public().unwrap();
    let key_text = public
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let owner = ClientId::from_random_bytes(owner);
    // The dialing device's endpoint is admitted with the owner client, in the runner-local
    // confirmation of `remote init`.
    let init =
        envelope(&runner.remote_init_with(&owner, &key_text, "yes", &["--iroh-endpoint", dialer]));
    assert_eq!(init["code"], "OK", "{init}");
    let environment = init["data"]["environment"].as_str().unwrap().to_owned();
    let sshd = LoopbackSshd::start(
        scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            ..SshdConfig::default()
        },
    )
    .ok()?;
    let registry = sshd.registry_path().map(Path::to_path_buf)?;
    let _ = std::fs::remove_file(&registry);
    std::os::unix::fs::symlink(runner.account.join(".ssh/authorized_keys"), &registry).unwrap();
    runner.start();
    let runtime = runner
        .runtime
        .as_ref()
        .map(std::process::Child::id)
        .unwrap();
    Some((
        Serving {
            runner,
            sshd,
            account: account.to_owned(),
            owner,
            key,
            environment,
        },
        runtime,
    ))
}

/// The serving runner's exposure widenings (module docs): the owner's requests stay
/// pending, no remote or unattended session decides one, nothing is exposed meanwhile; then
/// the serve widening alone is approved by the runner's attended local owner. Returns that
/// approval's result. The serve request names `sshd_port`, the fixture sshd's port, in its
/// policy: the field `transport enable --serve --sshd-port` sets.
async fn widenings(s: &Serving, dir: &Path, runtime: u32, sshd_port: u16) -> Value {
    let runner = &s.runner;
    sshd_port_flag(runner, sshd_port);
    let mut owner = s.owner_session(dir).await;
    let session = &mut owner.session;
    assert!(
        session
            .server()
            .capabilities
            .contains(capability::TRANSPORT_IROH_V1),
        "the owner session did not negotiate transport-iroh/1"
    );

    let serve = session
        .request(transport(serde_json::json!({
            "op": "transport", "action": "enable", "serve": true,
            "exposure": {
                "bind": {"kind": "loopback"},
                "infrastructure": {"kind": "none"},
                "sshd_port": sshd_port,
            },
            "request_id": "a26-serve-1",
        })))
        .await
        .unwrap();
    assert_eq!(serve.code.as_str(), "APPROVAL_REQUIRED", "{serve:?}");
    assert!(keys_recorded(runner).is_empty());
    // The target is built only with the feature; a harness-supplied binary is the
    // harness's to build with it (the session above negotiated `transport-iroh/1`).
    observe(
        CASE,
        "build",
        format!(
            "test_target_feature=iroh binary={} transport_capability=negotiated",
            if std::env::var_os("HEIMDALL_E2E_BIN").is_some_and(|v| !v.is_empty()) {
                "harness_supplied"
            } else {
                "cargo_built_with_feature"
            }
        ),
    );
    observe(
        CASE,
        "exposure-serve",
        "paired_owner_serve_widening=APPROVAL_REQUIRED_pending_runner_local_decision \
         applied=nothing",
    );

    let relay = session
        .request(transport(serde_json::json!({
            "op": "transport", "action": "enable", "serve": true,
            "exposure": {
                "bind": {"kind": "loopback"},
                "infrastructure": {"kind": "custom", "relays": ["https://relay.invalid./"]},
                "direct_fallback": false,
            },
            "request_id": "a26-relay-1",
        })))
        .await
        .unwrap();
    assert_eq!(relay.code.as_str(), "APPROVAL_REQUIRED", "{relay:?}");
    let public_profile = session
        .request(transport(serde_json::json!({
            "op": "transport", "action": "enable", "serve": true,
            "exposure": {
                "bind": {"kind": "loopback"},
                "infrastructure": {"kind": "n0_public"},
                "direct_fallback": false,
            },
            "request_id": "a26-n0-1",
        })))
        .await
        .unwrap();
    assert_eq!(
        public_profile.code.as_str(),
        "APPROVAL_REQUIRED",
        "{public_profile:?}"
    );
    assert!(keys_recorded(runner).is_empty());
    observe(
        CASE,
        "exposure-relay",
        "unapproved_relay=APPROVAL_REQUIRED_pending n0_public=APPROVAL_REQUIRED_pending \
         applied=nothing",
    );

    // no-remote-decision: no remote or unattended session completes a widening.
    let decide = |id: &str| {
        Request::Decide(DecideRequest {
            decision_id: DecisionId::parse(id).unwrap(),
            verdict: Verdict::Approve,
        })
    };
    let target = serve
        .next
        .as_ref()
        .and_then(|n| n.decision_ref.clone())
        .expect("the pending serve widening names its decision");
    let paired = session.request(decide(&target)).await.unwrap();
    assert_eq!(paired.code.as_str(), "INTERACTION_REQUIRED", "{paired:?}");
    let info = heimdall_runtime::instance::InstanceInfo::read_valid(
        &heimdall_runtime::Paths::under(&runner.home).runtime_dir,
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
    let unattended = local.request(decide(&target)).await.unwrap();
    assert_eq!(
        unattended.code.as_str(),
        "INTERACTION_REQUIRED",
        "{unattended:?}"
    );
    drop(local);
    assert!(keys_recorded(runner).is_empty());
    observe(
        CASE,
        "no-remote-decision",
        "paired_decide=INTERACTION_REQUIRED unattended_local_decide=INTERACTION_REQUIRED",
    );
    assert!(
        children_of(runtime).is_empty(),
        "the runner runtime runs a child: a serve child was started"
    );
    assert_eq!(
        std::fs::read_dir(runner.iroh_store.as_ref().unwrap())
            .unwrap()
            .count(),
        0,
        "a key was created before any approval"
    );
    observe(
        CASE,
        "nothing-exposed",
        "before_approval transport_keys_recorded=0 serve_child=none serving_store_items=0",
    );

    // ⟨W5 `w5m`; ADR-0006 §18.9 item 8⟩ The serve widening as the runner's **local** owner
    // submits it, through the product CLI on a terminal: a local decision record (no
    // client), which a retry returns, which no paired or unattended session approves, and
    // which `decision approve` on a terminal applies after the typed `yes`.
    let port = sshd_port.to_string();
    let enable = [
        "transport",
        "enable",
        "--serve",
        "--sshd-port",
        port.as_str(),
    ];
    let (code, submitted) = local_owner_terminal(runner, &enable, None);
    assert_eq!(submitted["code"], "APPROVAL_REQUIRED", "{submitted}");
    assert_eq!(code, 3, "{submitted}");
    let local_ref = submitted["next"]["decision_ref"]
        .as_str()
        .expect("the local serve widening names its decision")
        .to_owned();
    assert_ne!(local_ref, target, "the local record is the paired owner's");
    let record = pending_widening(runner, &local_ref);
    assert_eq!(
        record.origin,
        heimdall_domain::decision::WideningOrigin::Local
    );
    assert_eq!(record.client, None);
    let delta = record
        .exposure
        .clone()
        .expect("the record carries its delta");
    assert_eq!(delta["serve_after"], true, "{delta}");
    assert_eq!(delta["after"]["sshd_port"], sshd_port, "{delta}");
    let (_, again) = local_owner_terminal(runner, &enable, None);
    assert_eq!(again["next"]["decision_ref"], local_ref.as_str(), "{again}");
    assert_eq!(
        pending_widenings(runner)
            .iter()
            .filter(|(_, w)| w.client.is_none())
            .count(),
        1,
        "a retry made a second local record"
    );
    let paired = session.request(decide(&local_ref)).await.unwrap();
    assert_eq!(paired.code.as_str(), "INTERACTION_REQUIRED", "{paired:?}");
    let silent = runner_json(
        runner,
        &["--non-interactive", "decision", "approve", &local_ref],
    );
    assert_eq!(silent["code"], "INTERACTION_REQUIRED", "{silent}");
    assert!(keys_recorded(runner).is_empty());
    assert!(
        children_of(runtime).is_empty(),
        "a serve child runs before the local approval"
    );
    observe(
        CASE,
        "serve-local-submit",
        "command=transport_enable_serve_sshd_port session=terminal answer=APPROVAL_REQUIRED \
         exit=3 record_origin=local record_client=none delta=serve_and_sshd_port \
         same_command_again=the_same_record paired_decide=INTERACTION_REQUIRED \
         non_interactive_decision_approve=nothing_sent applied=nothing",
    );
    let (code, approved) =
        local_owner_terminal(runner, &["decision", "approve", &local_ref], Some("yes"));
    assert_eq!(approved["code"], "OK", "{approved}");
    assert_eq!(code, 0, "{approved}");
    observe(
        CASE,
        "serve-local-approve",
        "command=decision_approve session=terminal typed=yes answer=OK \
         applied=the_recorded_request_once",
    );

    // The paired-owner case, kept: its earlier serve request is still a pending record of
    // its own (its client named), and it is not what was approved. The attended local owner
    // approving it now is refused: the delta it was bound to (from not serving to serving)
    // is no longer the delta the request would apply.
    let paired_record = pending_widening(runner, &target);
    assert_eq!(
        paired_record.origin,
        heimdall_domain::decision::WideningOrigin::Paired
    );
    assert_eq!(paired_record.client.as_ref(), Some(&s.owner));
    let keys_before = keys_recorded(runner);
    let mut at_runner = attend_at(runner).await;
    let late = at_runner.request(decide(&target)).await.unwrap();
    drop(at_runner);
    assert_eq!(late.code.as_str(), "CAPABILITY_UNAVAILABLE", "{late:?}");
    assert_eq!(
        late.data["error"]["reason"], "decision_binding_mismatch",
        "{late:?}"
    );
    assert_eq!(keys_recorded(runner), keys_before, "{late:?}");
    observe(
        CASE,
        "paired-after-local",
        format!(
            "paired_owner_serve_record=still_its_own_record_with_its_client \
             attended_local_approve_after_the_local_serve={} reason={} applied=nothing",
            late.code.as_str(),
            late.data["error"]["reason"].as_str().unwrap_or("none")
        ),
    );
    let Owner { session, agent, .. } = owner;
    drop(session);
    agent.stop().await;
    approved["data"].clone()
}

/// `heimdall --json <args…>` as `runner`'s local owner **on a terminal** (an attended
/// session), with the runner's fixture key store named as every other command of this
/// journey names it. `answer` is typed at the `[y/N]` prompt.
pub(crate) fn local_owner_terminal(
    runner: &Runner,
    args: &[&str],
    answer: Option<&str>,
) -> (i32, Value) {
    let path = |p: &Path| p.to_string_lossy().into_owned();
    let mut env = vec![
        ("HOME", path(&runner.account)),
        ("HEIMDALL_HOME", path(&runner.home)),
        ("HEIMDALL_TEST_SSH_HOME", path(&runner.account)),
        ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
    ];
    if let Some(store) = &runner.iroh_store {
        env.push(("HEIMDALL_TEST_IROH_KEY_STORE", path(store)));
    }
    super::world::on_terminal(&runner.home, &env, args, answer)
}

/// The pending widening records in `runner`'s state.
fn pending_widenings(
    runner: &Runner,
) -> Vec<(DecisionId, heimdall_domain::decision::RemoteWidening)> {
    read(&runner.home, |tx| tx.pending_decisions())
        .into_iter()
        .filter_map(|d| match d.kind {
            heimdall_domain::decision::DecisionKind::RemoteWidening(w) => Some((d.id, *w)),
            _ => None,
        })
        .collect()
}

fn pending_widening(runner: &Runner, id: &str) -> heimdall_domain::decision::RemoteWidening {
    pending_widenings(runner)
        .into_iter()
        .find(|(d, _)| d.as_str() == id)
        .map(|(_, w)| w)
        .unwrap_or_else(|| panic!("no pending widening record {id}"))
}

/// `sshd-port-flag` (module docs): the product flag through the real binary, on the serving
/// runner, before anything is enabled.
fn sshd_port_flag(runner: &Runner, sshd_port: u16) {
    for bad in ["0", "65536"] {
        let out = runner
            .command()
            .args([
                "--json",
                "--non-interactive",
                "transport",
                "enable",
                "--serve",
            ])
            .args(["--sshd-port", bad])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "--sshd-port {bad}: {out:?}");
    }
    let port = sshd_port.to_string();
    let local = runner_json(
        runner,
        &[
            "--non-interactive",
            "transport",
            "enable",
            "--serve",
            "--sshd-port",
            &port,
        ],
    );
    assert_eq!(local["code"], "INTERACTION_REQUIRED", "{local}");
    assert!(
        local["data"]["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("`transport.enable` widens")),
        "{local}"
    );
    assert!(keys_recorded(runner).is_empty());
    observe(
        CASE,
        "sshd-port-flag",
        "flag=transport_enable_serve_sshd_port zero=usage_error past_65535=usage_error \
         unattended_local_owner=INTERACTION_REQUIRED recorded=nothing",
    );
}
