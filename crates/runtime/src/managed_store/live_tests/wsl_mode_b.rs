//! ⟨M04 U4b⟩ ADR-0010 §3 and §10 item 2, live over the real `Operations`, managed adapter,
//! [`StoreSources`], `ManagedEffectsImpl`, signer table and `EndpointRegistry` of
//! [`super::Live`], with the **bridge supervisor** ([`BridgeRegistry`]) over an in-process fake
//! helper and a fake WSL host: no helper binary and no distribution is involved. The real
//! helper over `DirectLauncher` (the transport itself) is U4a's, and the native rows are
//! `tests/e2e/windows_m04.rs`'s A13 tests.
//!
//! * [`wsl_mode_b_enable_decision_views_and_a_second_enable`]: the `AddEnvironment` decision
//!   (pending, coalesced, denied, approved with its three disclosures), the row, the record
//!   and the distribution's `mode_b`, `inspect environments` with the helper state, and the
//!   idempotent and conflicting second enable. The request refusals are in
//!   [`super::container`]'s one table.
//! * [`wsl_mode_b_ensure_realizes_serves_and_withdraws_by_generation`]: `ensure` in the
//!   environment returns the descriptor and nothing else of a path, the realized files are
//!   exactly the public material with in-distribution paths, a relayed stream is served by
//!   the binding's signer, a withdrawal of another generation removes nothing, and the end
//!   of the binding withdraws exactly its generation.
//! * [`wsl_mode_b_disable_retires_and_keeps_the_cleanup_of_a_stopped_distribution`]: `wsl
//!   disable` of a running and of a stopped distribution (with and without `start`).
//! * [`wsl_mode_b_supervisor_not_running_respawn_and_gone`]: the re-check (never a
//!   background start), the respawn and re-realization, and an unregistered GUID going `gone`.
//! * [`wsl_mode_b_ensure_is_the_only_start_and_reports_the_helper`]: only an `ensure` starts a
//!   stopped distribution, and an unavailable helper is reported with nothing written.

use super::container::{
    claim_reasons, container_rows, decide, decisions_pending, ensure_in, inspect_environments,
    operations_recorded, permit_ensures, reasons_naming,
};
use super::*;
use crate::wsl_bridge::{BridgeApi, BridgeFactory};
use heimdall_app::ports::{
    DiscoveredDistribution, DistributionHost, DistributionStart, DistributionTarget, RunningState,
};
use heimdall_contract::environment::{DistributionGuid, EnvironmentRequest};
use heimdall_contract::ids::DecisionId;
use heimdall_contract::request::Verdict;
use heimdall_domain::decision::{DecisionKind, DecisionState};
use heimdall_domain::environment::{EnvironmentDisclosure, EnvironmentRealization, ManagedState};
use heimdall_wsl::{BridgePublic, Realized, SessionError, StreamHandler};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const RUN_DIR: &str = "/run/user/1000/heimdall";
/// ⟨M04-MC3-R01⟩ Another helper's run base (the home fallback, when `XDG_RUNTIME_DIR` was
/// refused at that helper's start).
const HOME_RUN_DIR: &str = "/home/ubuntu/.local/state/heimdall/run";

pub(super) fn guid() -> DistributionGuid {
    DistributionGuid::parse("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0").unwrap()
}

pub(super) fn other_guid() -> DistributionGuid {
    DistributionGuid::parse("1c2d3e4f-5061-7283-94a5-b6c7d8e9f0a1").unwrap()
}

// --- the fakes ---------------------------------------------------------------------------

/// The fake WSL host: the distributions it lists and whether the one runs.
pub(super) struct FakeHost {
    listed: Mutex<Vec<DiscoveredDistribution>>,
    running: Mutex<RunningState>,
}

impl FakeHost {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            listed: Mutex::new(vec![DiscoveredDistribution {
                guid: guid(),
                name: "Debian".to_owned(),
                version: 2,
                default_uid: Some(1000),
            }]),
            running: Mutex::new(RunningState::Running),
        })
    }
    fn set_running(&self, state: RunningState) {
        *self.running.lock().unwrap() = state;
    }
    fn unregister(&self) {
        self.listed.lock().unwrap().clear();
    }
}

impl DistributionHost for FakeHost {
    fn discover(&self) -> Result<Vec<DiscoveredDistribution>, AdapterError> {
        Ok(self.listed.lock().unwrap().clone())
    }
    fn running(&self, g: &DistributionGuid) -> RunningState {
        if self.listed.lock().unwrap().iter().any(|d| d.guid == *g) {
            *self.running.lock().unwrap()
        } else {
            RunningState::NotRunning
        }
    }
    fn writer(
        &self,
        _: &DistributionTarget,
        _: DistributionStart,
    ) -> Result<Arc<dyn heimdall_app::ports::ProjectionWriter>, AdapterError> {
        Err(AdapterError::Unavailable("wsl_unavailable".to_owned()))
    }
    fn cleaner(
        &self,
        _: &DistributionTarget,
        _: DistributionStart,
    ) -> Result<Arc<dyn heimdall_app::ports::ResourceCleaner>, AdapterError> {
        Err(AdapterError::Unavailable("wsl_unavailable".to_owned()))
    }
}

/// What the fake helper was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Realize {
        tag: String,
        generation: u64,
        public: BridgePublic,
    },
    Withdraw {
        tag: String,
        generation: u64,
    },
}

/// ⟨M04-W2-R02⟩ A hook run once, inside the next fake `realize`, before it takes effect.
type RealizeHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// The fake helper session: it serves what it was realized with, removes exactly the
/// generation it is asked to, and relays a stream into the handler it was started with.
struct FakeBridge {
    /// ⟨M04-W2-R02⟩ Runs once, inside the next `realize`, before it takes effect.
    on_realize: RealizeHook,
    /// ⟨M04-MC3-R01⟩ The run directory its hello advertised.
    run_dir: String,
    /// ⟨M04-MC3-R01⟩ The helper is lost right after the next read of its run directory.
    lose_on_run_dir: AtomicBool,
    alive: AtomicBool,
    calls: Mutex<Vec<Call>>,
    served: Mutex<BTreeMap<String, u64>>,
    streams: Arc<dyn StreamHandler>,
}

impl BridgeApi for FakeBridge {
    fn run_dir(&self) -> String {
        if self.lose_on_run_dir.swap(false, Ordering::SeqCst) {
            self.alive.store(false, Ordering::SeqCst);
        }
        self.run_dir.clone()
    }
    fn realize(
        &self,
        tag: &str,
        generation: u64,
        public: BridgePublic,
        _deadline: Timestamp,
    ) -> Result<Realized, SessionError> {
        if !self.alive() {
            return Err(SessionError::Gone);
        }
        let hook = self.on_realize.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.calls.lock().unwrap().push(Call::Realize {
            tag: tag.to_owned(),
            generation,
            public,
        });
        let mut served = self.served.lock().unwrap();
        if served.get(tag).is_none_or(|g| *g <= generation) {
            served.insert(tag.to_owned(), generation);
        }
        let run = &self.run_dir;
        Ok(Realized {
            socket: format!("{run}/b/{tag}/agent.sock"),
            ssh_config: format!("{run}/b/{tag}/ssh_config"),
        })
    }
    fn withdraw(&self, tag: &str, generation: u64) -> Result<(), SessionError> {
        if !self.alive() {
            return Err(SessionError::Gone);
        }
        self.calls.lock().unwrap().push(Call::Withdraw {
            tag: tag.to_owned(),
            generation,
        });
        let mut served = self.served.lock().unwrap();
        // A newer generation is never removed.
        if served.get(tag) == Some(&generation) {
            served.remove(tag);
        }
        Ok(())
    }
    fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn realized(&self) -> Result<Vec<(String, u64)>, SessionError> {
        Ok(self
            .served
            .lock()
            .unwrap()
            .iter()
            .map(|(t, g)| (t.clone(), *g))
            .collect())
    }
}

impl FakeBridge {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn withdrawals(&self) -> Vec<(String, u64)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Withdraw { tag, generation } => Some((tag, generation)),
                Call::Realize { .. } => None,
            })
            .collect()
    }

    /// A Linux client connects to `tag`'s endpoint: the helper hands the handler a stream.
    /// `None` when the handler refuses it (no signer for the tag).
    fn open(&self, tag: &str) -> Option<tokio::io::DuplexStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.streams.serve(tag, server).then_some(client)
    }
}

/// The fake factory: it enforces `Bridge::start`'s rule (a stopped distribution without
/// `Allowed` is `NotRunning`), starts the distribution for `Allowed`, and records every start.
pub(super) struct FakeFactory {
    /// ⟨M04-W2-R02⟩ Handed to every bridge it starts (`FakeBridge::on_realize`).
    on_realize: RealizeHook,
    host: Arc<FakeHost>,
    starts: Mutex<Vec<DistributionStart>>,
    current: Mutex<Option<Arc<FakeBridge>>>,
    fail: Mutex<Option<SessionError>>,
    spawned: AtomicUsize,
    /// ⟨M04-W2-R03⟩ The distribution stops just before the launcher's own pre-launch
    /// listing of the next `Forbidden` start (the stop the background relaunch can race).
    stop_before_launch: AtomicBool,
    /// ⟨M04 Windows fix round 5⟩ The next helper started is lost at once, and its
    /// distribution stops with it (WSL stops a distribution whose last process ended).
    lose_next: AtomicBool,
    /// ⟨M04-MC3-R01⟩ The run directories of the next helpers started, in order
    /// ([`RUN_DIR`] once it is empty).
    run_dirs: Mutex<std::collections::VecDeque<String>>,
}

impl FakeFactory {
    fn new(host: &Arc<FakeHost>) -> Arc<Self> {
        Arc::new(Self {
            on_realize: Arc::new(Mutex::new(None)),
            host: host.clone(),
            starts: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            fail: Mutex::new(None),
            stop_before_launch: AtomicBool::new(false),
            lose_next: AtomicBool::new(false),
            run_dirs: Mutex::new(std::collections::VecDeque::new()),
            spawned: AtomicUsize::new(0),
        })
    }
    fn starts(&self) -> Vec<DistributionStart> {
        self.starts.lock().unwrap().clone()
    }
    fn bridge(&self) -> Arc<FakeBridge> {
        self.current.lock().unwrap().clone().expect("a bridge")
    }
}

impl BridgeFactory for FakeFactory {
    fn start(
        &self,
        _target: &DistributionTarget,
        start: DistributionStart,
        streams: Arc<dyn StreamHandler>,
    ) -> Result<Arc<dyn BridgeApi>, SessionError> {
        self.starts.lock().unwrap().push(start);
        if start == DistributionStart::Forbidden
            && self.stop_before_launch.swap(false, Ordering::SeqCst)
        {
            self.host.set_running(RunningState::NotRunning);
        }
        // The launcher's pre-launch listing (`HelperLauncher::launch_under`).
        if start == DistributionStart::Forbidden
            && self.host.running(&guid()) != RunningState::Running
        {
            return Err(SessionError::NotRunning);
        }
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        if start == DistributionStart::Allowed {
            self.host.set_running(RunningState::Running);
        }
        let lost = self.lose_next.swap(false, Ordering::SeqCst);
        if lost {
            self.host.set_running(RunningState::NotRunning);
        }
        let run_dir = self
            .run_dirs
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| RUN_DIR.to_owned());
        let bridge = Arc::new(FakeBridge {
            on_realize: self.on_realize.clone(),
            run_dir,
            lose_on_run_dir: AtomicBool::new(false),
            alive: AtomicBool::new(!lost),
            calls: Mutex::new(Vec::new()),
            served: Mutex::new(BTreeMap::new()),
            streams,
        });
        *self.current.lock().unwrap() = Some(Arc::clone(&bridge));
        self.spawned.fetch_add(1, Ordering::SeqCst);
        Ok(bridge)
    }
}

/// What [`Opts::wsl`] carries.
pub(super) struct WslFixture {
    pub(super) host: Arc<FakeHost>,
    pub(super) factory: Option<Arc<dyn BridgeFactory>>,
}

/// A process with the fake host and, unless `bridge` is false, the fake factory.
pub(super) async fn process(w: &Live, bridge: bool) -> (Process, Arc<FakeHost>, Arc<FakeFactory>) {
    let host = FakeHost::new();
    let factory = FakeFactory::new(&host);
    let fixture = WslFixture {
        host: host.clone(),
        factory: bridge.then(|| factory.clone() as Arc<dyn BridgeFactory>),
    };
    let p = w
        .process_opts(
            Arc::new(NoStageHook),
            Opts {
                wsl: Some(fixture),
                ..Opts::default()
            },
        )
        .await;
    (p, host, factory)
}

// --- helpers ---------------------------------------------------------------------------

fn enable(account: &str) -> EnvironmentRequest {
    EnvironmentRequest::WslEnable {
        distribution_guid: guid(),
        account: account.to_owned(),
        mode_a: false,
        mode_b: true,
    }
}

async fn enable_decision(p: &Process, account: &str) -> DecisionId {
    let e = p
        .ops
        .environment_request(&caller(), enable(account))
        .await
        .expect_err("Mode B answers with a decision");
    assert_eq!(e.code, Code::InteractionRequired, "{}", e.message);
    DecisionId::parse(e.next.decision_ref.as_deref().expect("a decision ref")).unwrap()
}

/// An approved Mode B environment: its ID and the answered view.
async fn approved(p: &Process) -> (EnvironmentId, serde_json::Value) {
    let d = enable_decision(p, "ubuntu").await;
    let data = decide(p, &d, Verdict::Approve).await;
    let view = data["environment"].clone();
    (
        EnvironmentId::parse(view["environment_id"].as_str().unwrap()).unwrap(),
        view,
    )
}

fn row(w: &Live, id: &EnvironmentId) -> heimdall_domain::environment::ManagedEnvironment {
    w.store
        .transaction(|tx| tx.managed_environment(id))
        .unwrap()
        .expect("the managed row")
}

fn mode_b_of(w: &Live) -> Option<EnvironmentId> {
    w.store
        .transaction(|tx| tx.wsl_distribution(&guid()))
        .unwrap()
        .and_then(|r| r.mode_b)
}

/// The tag of the endpoint `socket` names (`<run>/b/<tag>/agent.sock`).
fn tag_of(socket: &str) -> String {
    tag_under(RUN_DIR, socket)
}

/// The tag of the endpoint `socket` names under the run directory `run`.
fn tag_under(run: &str, socket: &str) -> String {
    socket
        .strip_prefix(&format!("{run}/b/"))
        .and_then(|r| r.strip_suffix("/agent.sock"))
        .unwrap_or_else(|| panic!("not a Mode B socket under {run}: {socket}"))
        .to_owned()
}

/// One SSH agent `REQUEST_IDENTITIES` over a relayed stream: how many identities it lists.
async fn list_over(stream: &mut tokio::io::DuplexStream) -> u32 {
    stream.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(body[0], 12, "IDENTITIES_ANSWER");
    u32::from_be_bytes(body[1..5].try_into().unwrap())
}

async fn eventually<F: Fn() -> bool>(what: &str, f: F) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{what}");
}

// --- the cases -------------------------------------------------------------------------

/// ADR-0010 §3 item 1 and the `AddEnvironment` decision of Mode B: a pending decision is
/// joined, carries the three disclosures and writes nothing else; a denial writes nothing;
/// an approval inserts the row, the record (`managed_signing` only) and the distribution's
/// `mode_b`; `inspect environments` shows the row with its helper `stopped` (no binding, so
/// no helper); a second enable for the same account answers `OK` with the same environment,
/// another account is a conflict, and a stale decision is refused.
#[tokio::test]
async fn wsl_mode_b_enable_decision_views_and_a_second_enable() {
    let w = Live::new();
    let (p, _host, factory) = process(&w, true).await;

    let d = enable_decision(&p, "ubuntu").await;
    assert_eq!(
        enable_decision(&p, "ubuntu").await,
        d,
        "an equal request is joined"
    );
    assert_eq!(decisions_pending(&w), 1);
    let rec = w.store.transaction(|tx| tx.decision(&d)).unwrap().unwrap();
    let DecisionKind::AddEnvironment {
        realization:
            EnvironmentRealization::Wsl {
                guid: g,
                name,
                account,
            },
        disclosures,
        ..
    } = &rec.kind
    else {
        panic!("not a Mode B AddEnvironment: {:?}", rec.kind);
    };
    assert_eq!(
        (g, name.as_str(), account.as_str()),
        (&guid(), "Debian", "ubuntu")
    );
    assert_eq!(disclosures, &EnvironmentDisclosure::MODE_B.to_vec());
    assert_eq!(
        serde_json::to_value(disclosures).unwrap(),
        serde_json::json!([
            "same_windows_user_and_distribution_root_can_use_endpoint",
            "interop_user_can_become_owner",
            "binding_keeps_distribution_running"
        ])
    );
    assert!(
        container_rows(&w).is_empty(),
        "a pending decision creates nothing"
    );
    assert_eq!(mode_b_of(&w), None);

    // Denied: consumed, nothing else written.
    decide(&p, &d, Verdict::Deny).await;
    assert_eq!(
        w.store
            .transaction(|tx| tx.decision(&d))
            .unwrap()
            .unwrap()
            .state,
        DecisionState::Denied
    );
    assert!(container_rows(&w).is_empty());
    assert_eq!(mode_b_of(&w), None);

    // Approved: the row, the record, `mode_b`.
    let (id, view) = approved(&p).await;
    assert_eq!(view["kind"], "wsl_distribution");
    assert_eq!(view["state"], "active");
    assert_eq!(view["realization"]["guid"], guid().as_str());
    assert_eq!(view["realization"]["account"], "ubuntu");
    assert_eq!(view["realization"]["modes"], serde_json::json!(["b"]));
    assert_eq!(view["realization"]["helper"], "stopped");
    assert_eq!(row(&w, &id).state, ManagedState::Active);
    assert_eq!(mode_b_of(&w), Some(id.clone()));
    let record = w
        .store
        .transaction(|tx| tx.environment(&id))
        .unwrap()
        .unwrap();
    assert_eq!(
        record.kind,
        heimdall_domain::environment::EnvironmentKind::WslDistribution
    );
    assert_eq!(
        record.permissions,
        EnvironmentPermissions {
            automatic_activation: false,
            managed_signing: true,
            issuer_access: false,
        }
    );
    assert_eq!(factory.starts(), vec![], "enabling starts no helper");

    // `inspect environments`: the owner sees the row once (not a second Mode A entry).
    let listing = inspect_environments(&p, &caller()).await;
    let items = listing["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{listing}");
    assert_eq!(items[1]["environment_id"], id.as_str());
    assert_eq!(items[1]["realization"]["helper"], "stopped");

    // Idempotent for the same account; another account is a conflict.
    let again = p
        .ops
        .environment_request(&caller(), enable("ubuntu"))
        .await
        .unwrap()
        .data;
    assert_eq!(again["environment"]["environment_id"], id.as_str());
    let e = p
        .ops
        .environment_request(&caller(), enable("root"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{}", e.message);
    assert_eq!(decisions_pending(&w), 0, "no further decision was created");
    p.shutdown.cancel();
}

/// ADR-0010 §3 items 5, 6 and 12 through the real pipeline. `ensure` in the Mode B
/// environment: the helper starts (the one `Allowed` start), the binding's endpoint is
/// realized inside the distribution with exactly the public material (the public key, one
/// certificate per pair, the `ssh_config` and `known_hosts` rendered with the
/// in-distribution paths), the result's descriptor names the Linux socket and config and no
/// mount, a relayed stream is served by the binding's signer (two certificates, nothing
/// else), a withdrawal of another generation removes nothing, a stream for an unknown tag is
/// refused, and releasing the binding withdraws exactly its generation and stops the helper.
#[tokio::test]
async fn wsl_mode_b_ensure_realizes_serves_and_withdraws_by_generation() {
    let w = Live::new();
    let (p, _host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);

    let a = ensure_in(&p, &id, "w-a", "r-a")
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    assert_eq!(
        a.environment_id, id,
        "the binding is pinned to its environment"
    );
    assert_eq!(
        factory.starts(),
        vec![DistributionStart::Allowed],
        "the ensure is the one start"
    );
    let bridge = factory.bridge();

    // The descriptor: the Linux socket and config, no mount, no native path.
    let c = &a.consumer;
    assert_eq!(
        (c.signing_endpoint.as_ref(), c.ssh_config_include.as_ref()),
        (None, None)
    );
    let r = c.realization.as_ref().expect("a realization descriptor");
    assert_eq!(
        r.environment_kind,
        heimdall_contract::environment::EnvironmentKindView::WslDistribution
    );
    let socket = r.endpoint.clone().unwrap();
    let tag = tag_of(&socket);
    let dir = format!("{RUN_DIR}/b/{tag}");
    let config = r.config.clone().unwrap();
    assert_eq!(config, format!("{dir}/ssh_config"));
    assert!(r.mount.is_none());
    assert_eq!(
        r.environment,
        vec![
            ("SSH_AUTH_SOCK".to_owned(), socket.clone()),
            ("GIT_SSH_COMMAND".to_owned(), format!("ssh -F {config}")),
        ]
    );
    assert!(
        c.pairs
            .iter()
            .all(|p| p.endpoint.as_ref().is_none_or(|e| e.locator == socket))
    );

    // The realized public material.
    let calls = bridge.calls();
    let [
        Call::Realize {
            tag: t,
            generation,
            public,
        },
    ] = calls.as_slice()
    else {
        panic!("one realize expected: {calls:?}");
    };
    assert_eq!((t.as_str(), *generation), (tag.as_str(), 1));
    let names: Vec<&str> = public.files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["key.pub", "cert-h1.pub", "cert-h2.pub"]);
    assert!(
        public
            .files
            .iter()
            .all(|(_, l)| l.starts_with("ssh-ed25519") && !l.contains('\n')),
        "one OpenSSH public line each: {:?}",
        public.files
    );
    assert!(
        public
            .files
            .iter()
            .all(|(_, l)| !l.to_ascii_uppercase().contains("PRIVATE")),
        "no private key"
    );
    let cfg = &public.ssh_config;
    assert!(cfg.contains("StrictHostKeyChecking yes"), "{cfg}");
    assert!(
        cfg.contains(&format!("IdentityAgent \"{dir}/agent.sock\"")),
        "{cfg}"
    );
    assert!(
        cfg.contains(&format!("UserKnownHostsFile \"{dir}/known_hosts\"")),
        "{cfg}"
    );
    assert!(
        cfg.contains(&format!("IdentityFile \"{dir}/cert-h1.pub\"")),
        "{cfg}"
    );
    assert!(
        cfg.contains("IdentitiesOnly yes") && cfg.contains("ControlPath none"),
        "{cfg}"
    );
    assert!(!cfg.to_ascii_lowercase().contains("forwardagent"), "{cfg}");
    assert!(
        !cfg.contains(w.run_dir().to_str().unwrap()),
        "no Windows-side path in the distribution's file"
    );
    assert_eq!(
        public.known_hosts,
        "h1.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture\nh2.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture\n"
    );

    // A relayed stream is served by the binding's signer: its two certificates.
    let mut s = bridge.open(&tag).expect("the tag's stream is served");
    assert_eq!(list_over(&mut s).await, 2);
    assert!(
        bridge.open("deadbeefdeadbeef").is_none(),
        "an unknown tag has no signer"
    );

    // Withdrawal is by generation: another generation removes nothing.
    heimdall_app::ports::ManagedEffects::clear(&p.effects, &a.binding_id, 2).unwrap();
    assert_eq!(
        bridge.withdrawals(),
        vec![],
        "generation 2 is not this endpoint's"
    );
    assert!(bridge.open(&tag).is_some(), "the endpoint still serves");

    // The binding ends: the signer refuses at once, then exactly its generation withdraws,
    // and the helper stops with the last binding.
    p.ops
        .release(
            &caller(),
            heimdall_contract::request::ReleaseRequest {
                binding_id: a.binding_id.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("release: {} {}", e.code, e.message));
    eventually("the endpoint is withdrawn", || {
        bridge.withdrawals() == vec![(tag.clone(), 1)]
    })
    .await;
    assert!(bridge.open(&tag).is_none(), "no signer once withdrawn");
    assert!(p.registry.binding_endpoint(&a.binding_id).is_none());
    let helper = p.bridge.as_ref().unwrap();
    eventually("the helper stops with the last binding", || {
        heimdall_credential::endpoints::wsl::WslRealizer::helper_state(helper, &id)
            == Some(heimdall_contract::environment::HelperState::Stopped)
    })
    .await;
    p.shutdown.cancel();
}

/// ADR-0010 §3 item 13 and §9 item 2: `wsl disable` takes the environment out of the set
/// (its grant ends, its endpoint withdraws, the helper stops, `mode_b` clears). A **running**
/// distribution is cleaned at once; a **stopped** one is never started without `start`: the
/// leftovers are reported (`cleanup_pending`) and the helper is not started, while the binding
/// has already ended on this side. With `start` the explicit authorized start removes them
/// (the one `Allowed` start of this case).
#[tokio::test]
async fn wsl_mode_b_disable_retires_and_keeps_the_cleanup_of_a_stopped_distribution() {
    for (stopped, start) in [(false, false), (true, false), (true, true)] {
        let w = Live::new();
        let (p, host, factory) = process(&w, true).await;
        let (id, _) = approved(&p).await;
        permit_ensures(&w, &id);
        let a = ensure_in(&p, &id, "w-a", "r-a").await.unwrap();
        let tag = tag_of(
            a.consumer
                .realization
                .as_ref()
                .unwrap()
                .endpoint
                .as_ref()
                .unwrap(),
        );
        let bridge = factory.bridge();
        let starts_before = factory.starts();
        assert_eq!(starts_before, vec![DistributionStart::Allowed]);
        if stopped {
            // The distribution stops: the helper dies with it.
            host.set_running(RunningState::NotRunning);
            bridge.alive.store(false, Ordering::SeqCst);
        }
        let done = p
            .ops
            .environment_request(
                &caller(),
                EnvironmentRequest::WslDisable {
                    distribution_guid: guid(),
                    start,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("disable ({stopped}, {start}): {} {}", e.code, e.message))
            .data;
        assert_eq!(done["environment"]["state"], "removed");
        assert_eq!(done["environment"]["environment_id"], id.as_str());
        assert_eq!(
            done["cleanup_pending"],
            stopped && !start,
            "stopped={stopped} start={start}: {done}"
        );
        assert_eq!(row(&w, &id).state, ManagedState::Removed);
        assert_eq!(mode_b_of(&w), None, "mode_b clears");
        // What a stopped distribution is owed is never started for without `start`.
        let expected_starts = if stopped && start {
            vec![DistributionStart::Allowed, DistributionStart::Allowed]
        } else {
            starts_before
        };
        assert_eq!(
            factory.starts(),
            expected_starts,
            "stopped={stopped} start={start}"
        );
        if !stopped {
            assert_eq!(bridge.withdrawals(), vec![(tag.clone(), 1)]);
        }
        // The grant ended on this side whatever the distribution's state.
        eventually("the grant ends", || {
            w.store
                .transaction(|tx| tx.grant(&a.grant_id))
                .unwrap()
                .is_some_and(|g| !g.state.permits_use())
        })
        .await;
        assert!(p.registry.binding_endpoint(&a.binding_id).is_none());
        // A removed environment is refused as a target and stays listed as removed.
        let e = ensure_in(&p, &id, "w-b", "r-b").await.unwrap_err();
        assert_eq!(
            (e.code, e.reason.as_deref()),
            (Code::NotFound, Some("environment_removed"))
        );
        let listing = inspect_environments(&p, &caller()).await;
        assert_eq!(listing["items"][1]["state"], "removed");
        // Idempotent, and ⟨M04 W2⟩ the leftovers a stopped distribution is owed are still
        // reported by the next disable, and removed by one that carries `start`.
        let disable = |start: bool| {
            let p = &p;
            async move {
                p.ops
                    .environment_request(
                        &caller(),
                        EnvironmentRequest::WslDisable {
                            distribution_guid: guid(),
                            start,
                        },
                    )
                    .await
                    .unwrap()
                    .data
            }
        };
        let again = disable(false).await;
        assert_eq!(again["environment"]["state"], "removed");
        assert_eq!(again["cleanup_pending"], stopped && !start, "{again}");
        assert_eq!(factory.starts(), expected_starts, "still nothing started");
        if stopped && !start {
            let cleaned = disable(true).await;
            assert_eq!(cleaned["cleanup_pending"], false, "{cleaned}");
            assert_eq!(
                factory.starts(),
                vec![DistributionStart::Allowed, DistributionStart::Allowed],
                "the owner's start removes the leftovers"
            );
            assert_eq!(disable(false).await["cleanup_pending"], false);
        }
        p.shutdown.cancel();
    }
}

/// ⟨M04 W2 review, M04-W2-R03; the contract owner's ruling, ADR-0010 §11 item 1⟩ After the
/// helper is lost, the supervisor relaunches it in the background only after two consecutive
/// listings, at least one re-check apart, show the distribution running, and the launch is
/// itself preceded by a fresh listing (the fake factory's `Forbidden` check stands for the
/// launcher's, made before each `wsl.exe` call). A stopped answer at any listing, the tick's
/// or the pre-launch one, launches nothing and blocks the relaunch until the owner's next
/// `ensure` naming the environment, which is the explicit start.
#[tokio::test]
async fn wsl_mode_b_lost_helper_relaunches_only_after_two_running_listings() {
    let w = Live::new();
    let (p, host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    ensure_in(&p, &id, "w-a", "r-a").await.unwrap();
    let supervisor = p.bridge.clone().unwrap();
    let spawned = || factory.spawned.load(Ordering::SeqCst);
    let recheck = std::time::Duration::from_millis(120);
    assert_eq!(spawned(), 1);

    // Lost while the distribution runs: one listing records it; a second one less than a
    // re-check later is not enough; a second one a re-check later relaunches (`Forbidden`).
    factory.bridge().alive.store(false, Ordering::SeqCst);
    supervisor.tick(&p.ops).await;
    supervisor.tick(&p.ops).await;
    assert_eq!(spawned(), 1, "two listings less than a re-check apart");
    tokio::time::sleep(recheck).await;
    supervisor.tick(&p.ops).await;
    assert_eq!(
        spawned(),
        2,
        "relaunched after two running listings a re-check apart"
    );
    assert_eq!(factory.starts().last(), Some(&DistributionStart::Forbidden));

    // Lost again; the distribution stops just before the pre-launch listing: nothing is
    // launched, and running listings afterwards relaunch nothing.
    factory.bridge().alive.store(false, Ordering::SeqCst);
    supervisor.tick(&p.ops).await;
    tokio::time::sleep(recheck).await;
    factory.stop_before_launch.store(true, Ordering::SeqCst);
    supervisor.tick(&p.ops).await;
    assert_eq!(
        spawned(),
        2,
        "a stopped pre-launch listing launches nothing"
    );
    host.set_running(RunningState::Running);
    for _ in 0..3 {
        tokio::time::sleep(recheck).await;
        supervisor.tick(&p.ops).await;
    }
    assert_eq!(spawned(), 2, "blocked until the owner's ensure");

    // A stopped listing at the tick blocks the same way; the owner's `ensure` lifts it.
    host.set_running(RunningState::NotRunning);
    supervisor.tick(&p.ops).await;
    host.set_running(RunningState::Running);
    tokio::time::sleep(recheck).await;
    supervisor.tick(&p.ops).await;
    tokio::time::sleep(recheck).await;
    supervisor.tick(&p.ops).await;
    assert_eq!(spawned(), 2);
    ensure_in(&p, &id, "w-b", "r-b").await.unwrap();
    assert_eq!(spawned(), 3, "the owner's ensure is the explicit start");
    assert_eq!(factory.starts().last(), Some(&DistributionStart::Allowed));
    // Lost after that: the two-listing rule applies again (the block was lifted).
    factory.bridge().alive.store(false, Ordering::SeqCst);
    supervisor.tick(&p.ops).await;
    tokio::time::sleep(recheck).await;
    supervisor.tick(&p.ops).await;
    assert_eq!(spawned(), 4);
    p.shutdown.cancel();
}

/// ADR-0010 §3 items 9, 10 and 13 through the supervisor's re-check ([`BridgeRegistry::tick`],
/// what runs every 10 s): a distribution that stopped moves the row to `not_running` and starts
/// **nothing**; when it runs again the helper respawns with `Forbidden` and the current
/// generation is realized again at the same endpoint (the old streams' signer is the same);
/// an unregistered GUID retires the environment as `gone`: its grant ends and its endpoint
/// withdraws, and `mode_b` clears.
#[tokio::test]
async fn wsl_mode_b_supervisor_not_running_respawn_and_gone() {
    let w = Live::new();
    let (p, host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    let a = ensure_in(&p, &id, "w-a", "r-a").await.unwrap();
    let tag = tag_of(
        a.consumer
            .realization
            .as_ref()
            .unwrap()
            .endpoint
            .as_ref()
            .unwrap(),
    );
    let supervisor = p.bridge.clone().unwrap();
    let first = factory.bridge();
    assert_eq!(factory.starts(), vec![DistributionStart::Allowed]);

    // The distribution stops (`wsl --terminate`): the helper dies, the row says so, and the
    // re-check starts nothing.
    host.set_running(RunningState::NotRunning);
    first.alive.store(false, Ordering::SeqCst);
    supervisor.tick(&p.ops).await;
    assert_eq!(row(&w, &id).state, ManagedState::NotRunning);
    assert_eq!(
        factory.starts(),
        vec![DistributionStart::Allowed],
        "no background start"
    );
    let listing = inspect_environments(&p, &caller()).await;
    assert_eq!(listing["items"][1]["state"], "not_running");
    assert_eq!(listing["items"][1]["realization"]["helper"], "stopped");
    assert!(
        w.store
            .transaction(|tx| tx.grant(&a.grant_id))
            .unwrap()
            .unwrap()
            .state
            .permits_use(),
        "the grant is not ended by the distribution stopping"
    );

    // It runs again (a user restart). ⟨M04-W2-R03⟩ A listing showed it stopped, so nothing
    // relaunches the helper in the background, however many running listings follow, until
    // the owner's next `ensure` naming the environment, which is the explicit start; then the
    // current generation is realized again at the same tag.
    host.set_running(RunningState::Running);
    for _ in 0..3 {
        supervisor.tick(&p.ops).await;
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
    assert_eq!(
        factory.starts(),
        vec![DistributionStart::Allowed],
        "no background relaunch after a stopped listing"
    );
    assert_eq!(row(&w, &id).state, ManagedState::Active);
    ensure_in(&p, &id, "w-a2", "r-a2").await.unwrap();
    assert_eq!(
        factory.starts(),
        vec![DistributionStart::Allowed, DistributionStart::Allowed]
    );
    let second = factory.bridge();
    assert!(!Arc::ptr_eq(&first, &second));
    // The started helper realizes the current generation of the existing binding again
    // first, then the new `ensure`'s binding.
    match second.calls().first() {
        Some(Call::Realize {
            tag: t,
            generation: 1,
            ..
        }) => assert_eq!(*t, tag),
        other => panic!("the endpoint is realized again: {other:?}"),
    }
    let mut s = second.open(&tag).expect("served again");
    assert_eq!(list_over(&mut s).await, 2);
    let listing = inspect_environments(&p, &caller()).await;
    assert_eq!(listing["items"][1]["state"], "active");
    assert_eq!(listing["items"][1]["realization"]["helper"], "running");

    // The distribution is unregistered: `gone`, its binding released, `mode_b` cleared.
    host.unregister();
    supervisor.tick(&p.ops).await;
    assert_eq!(
        row(&w, &id).state,
        ManagedState::Active,
        "one listing without it is not enough: `gone` is terminal"
    );
    supervisor.tick(&p.ops).await;
    assert_eq!(row(&w, &id).state, ManagedState::Gone);
    assert_eq!(mode_b_of(&w), None);
    eventually("the grant ends", || {
        w.store
            .transaction(|tx| tx.grant(&a.grant_id))
            .unwrap()
            .is_some_and(|g| !g.state.permits_use())
    })
    .await;
    assert!(p.registry.binding_endpoint(&a.binding_id).is_none());
    let e = ensure_in(&p, &id, "w-b", "r-b").await.unwrap_err();
    assert_eq!(
        (e.code, e.reason.as_deref()),
        (Code::NotFound, Some("environment_removed"))
    );
    let listing = inspect_environments(&p, &caller()).await;
    assert_eq!(listing["items"][1]["state"], "gone");
    p.shutdown.cancel();
}

/// ADR-0010 §3 item 9 and §10 item 2: only the owner's own `ensure` naming the environment
/// starts a stopped distribution (the `Allowed` start), and it moves the row back to
/// `active`; a helper that cannot start is reported as `wsl_helper_unavailable` with nothing
/// written and `inspect environments` showing the helper `unavailable`.
#[tokio::test]
async fn wsl_mode_b_ensure_is_the_only_start_and_reports_the_helper() {
    let w = Live::new();
    let (p, host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);

    // A helper that cannot start: the ensure is refused before anything is recorded.
    *factory.fail.lock().unwrap() = Some(SessionError::HelperUnavailable("no helper".to_owned()));
    let ops_before = operations_recorded(&w);
    let e = ensure_in(&p, &id, "w-a", "r-a").await.unwrap_err();
    assert_eq!(
        (e.code, e.reason.as_deref()),
        (Code::CapabilityUnavailable, Some("wsl_helper_unavailable")),
        "{}",
        e.message
    );
    assert_eq!(
        operations_recorded(&w),
        ops_before,
        "nothing written for the refusal"
    );
    let listing = inspect_environments(&p, &caller()).await;
    assert_eq!(listing["items"][1]["realization"]["helper"], "unavailable");

    // A stopped distribution: the ensure starts it, no one else does.
    *factory.fail.lock().unwrap() = None;
    host.set_running(RunningState::NotRunning);
    p.bridge.as_ref().unwrap().tick(&p.ops).await;
    assert_eq!(
        factory.spawned.load(Ordering::SeqCst),
        0,
        "the re-check started nothing"
    );
    let a = ensure_in(&p, &id, "w-a", "r-a2")
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    assert!(a.consumer.realization.is_some());
    assert_eq!(
        factory.starts().last(),
        Some(&DistributionStart::Allowed),
        "the ensure's start"
    );
    assert_eq!(
        factory
            .starts()
            .iter()
            .filter(|s| **s == DistributionStart::Allowed)
            .count(),
        2,
        "the failed attempt and this one are the only explicit starts: {:?}",
        factory.starts()
    );
    assert_eq!(row(&w, &id).state, ManagedState::Active);
    p.shutdown.cancel();
}

/// ⟨M04 W2 review, M04-W2-R02⟩ The review's probe, inverted: a binding withdrawn while the
/// relaunched helper realizes it again is withdrawn again at once, so the helper never keeps
/// an ended binding's endpoint (the claim of ADR-0010 §11 item 2), and a later re-check
/// finds nothing to sweep. Binding B keeps the helper alive throughout.
#[tokio::test]
async fn wsl_mode_b_withdrawal_during_a_relaunch_leaves_no_endpoint() {
    let w = Live::new();
    let (p, _host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    let a = ensure_in(&p, &id, "race-a", "race-ra").await.unwrap();
    let b = ensure_in(&p, &id, "race-b", "race-rb").await.unwrap();
    let tag_a = tag_of(
        a.consumer
            .realization
            .as_ref()
            .unwrap()
            .endpoint
            .as_ref()
            .unwrap(),
    );
    let tag_b = tag_of(
        b.consumer
            .realization
            .as_ref()
            .unwrap()
            .endpoint
            .as_ref()
            .unwrap(),
    );
    let supervisor = p.bridge.clone().unwrap();
    factory.bridge().alive.store(false, Ordering::SeqCst);
    let effects = p.effects.clone();
    let binding = a.binding_id.clone();
    *factory.on_realize.lock().unwrap() = Some(Box::new(move || {
        heimdall_app::ports::ManagedEffects::clear(&effects, &binding, 1).unwrap();
    }));
    // The two-listing relaunch (M04-W2-R03), whose replay realizes A first and meets the
    // withdrawal inside that call.
    supervisor.tick(&p.ops).await;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    supervisor.tick(&p.ops).await;
    let bridge = factory.bridge();
    assert!(p.registry.binding_endpoint(&a.binding_id).is_none());
    let served = bridge.realized().unwrap();
    assert!(
        !served.contains(&(tag_a.clone(), 1)),
        "A is withdrawn again: {served:?}"
    );
    assert!(
        served.contains(&(tag_b.clone(), 1)),
        "B is served: {served:?}"
    );
    assert!(bridge.open(&tag_a).is_none());
    supervisor.tick(&p.ops).await;
    assert!(!bridge.realized().unwrap().contains(&(tag_a, 1)));
    p.shutdown.cancel();
}

/// ⟨M04 fix re-check, M04-FX-RC02⟩ The re-check's two probes, inverted.
/// 1. **An absent listing blocks.** A lost helper's first running listing is recorded; one
///    discovery that omits the distribution, then the same distribution listed running again,
///    a re-check apart: nothing is relaunched in the background, however many running listings
///    follow, until the owner's `ensure`. (An unreadable discovery takes the same blocking path
///    in the supervisor; the fake host has no failing listing.)
/// 2. **Every background start passes the same admission.** With the block set by a stopped
///    listing and the distribution running again, the `Forbidden` endpoint entry point
///    (`WslRealizer::run_dir`, which continuing work's endpoint creation uses) starts nothing
///    either.
#[tokio::test]
async fn wsl_mode_b_absent_or_unreadable_listings_and_endpoint_starts_respect_the_relaunch_block() {
    use heimdall_credential::endpoints::wsl::WslRealizer;
    let recheck = std::time::Duration::from_millis(120);
    let w = Live::new();
    let (p, host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    ensure_in(&p, &id, "w-a", "r-a").await.unwrap();
    let supervisor = p.bridge.clone().unwrap();
    let spawned = || factory.spawned.load(Ordering::SeqCst);

    // 1. Absent once, then listed again.
    factory.bridge().alive.store(false, Ordering::SeqCst);
    supervisor.tick(&p.ops).await;
    let listed = host.listed.lock().unwrap().clone();
    host.unregister();
    supervisor.tick(&p.ops).await;
    *host.listed.lock().unwrap() = listed;
    for _ in 0..3 {
        tokio::time::sleep(recheck).await;
        supervisor.tick(&p.ops).await;
    }
    assert_eq!(spawned(), 1, "no relaunch after an absent listing");
    ensure_in(&p, &id, "w-b", "r-b").await.unwrap();
    assert_eq!(spawned(), 2, "the owner's ensure is the explicit start");
    assert_eq!(factory.starts().last(), Some(&DistributionStart::Allowed));

    // 2. A stopped listing sets the block; the distribution runs again; the endpoint entry
    //    point starts nothing.
    factory.bridge().alive.store(false, Ordering::SeqCst);
    host.set_running(RunningState::NotRunning);
    supervisor.tick(&p.ops).await;
    host.set_running(RunningState::Running);
    tokio::time::sleep(recheck).await;
    assert!(WslRealizer::run_dir(&supervisor, &id, DistributionStart::Forbidden).is_err());
    tokio::time::sleep(recheck).await;
    assert!(WslRealizer::run_dir(&supervisor, &id, DistributionStart::Forbidden).is_err());
    assert_eq!(
        spawned(),
        2,
        "no background start through the endpoint entry point"
    );
    p.shutdown.cancel();
}

/// ⟨M04 Windows run at 66e6e40f; fix round 5⟩ The owner's `ensure` is never a background
/// start. The distribution reads stopped, and the helper the owner's start brings up is lost,
/// its distribution stopping with it, before the `ensure` creates its endpoint. The `ensure`
/// still succeeds: its endpoint creation and realization carry the owner's authority
/// (`Allowed`) and start the helper again as the owner's start does, never through the
/// background admission (which the stopped listing blocks: at 66e6e40f they went through it
/// and the `ensure` failed `SERVICE_UNAVAILABLE`, as on the PC). A background path stays
/// blocked: after a stopped listing the supervisor's re-checks start nothing, however many
/// running listings follow, and continuing work's entry point (`Forbidden`) is refused.
#[tokio::test]
async fn wsl_mode_b_owner_ensure_is_never_a_background_start() {
    use heimdall_credential::endpoints::wsl::WslRealizer;
    let recheck = std::time::Duration::from_millis(120);
    let w = Live::new();
    let (p, host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    let spawned = || factory.spawned.load(Ordering::SeqCst);
    host.set_running(RunningState::NotRunning);
    factory.lose_next.store(true, Ordering::SeqCst);
    let a = ensure_in(&p, &id, "w-s", "r-s").await.unwrap_or_else(|e| {
        panic!(
            "the owner's ensure into a stopped distribution: {} {:?} {}",
            e.code, e.reason, e.message
        )
    });
    assert!(a.consumer.realization.is_some());
    assert_eq!(
        factory.starts(),
        vec![DistributionStart::Allowed, DistributionStart::Allowed],
        "the owner's start, then its endpoint creation's own: no background start"
    );
    assert_eq!(spawned(), 2);
    assert_eq!(
        factory.bridge().realized().unwrap().len(),
        1,
        "the endpoint is realized on the helper the owner's request started"
    );

    // A background path stays blocked.
    let supervisor = p.bridge.clone().unwrap();
    factory.bridge().alive.store(false, Ordering::SeqCst);
    host.set_running(RunningState::NotRunning);
    supervisor.tick(&p.ops).await;
    host.set_running(RunningState::Running);
    for _ in 0..3 {
        tokio::time::sleep(recheck).await;
        supervisor.tick(&p.ops).await;
    }
    assert!(WslRealizer::run_dir(&supervisor, &id, DistributionStart::Forbidden).is_err());
    assert_eq!(spawned(), 2, "no background start after a stopped listing");
    assert_eq!(factory.starts().len(), 2);
    p.shutdown.cancel();
}

/// ⟨M04-MC3-R01⟩ A helper replaced by one with another run base (its `XDG_RUNTIME_DIR` was
/// refused at the replacement's start, so the home fallback) never realizes, nor replays, an
/// endpoint rendered for the first helper's base. Binding `b`'s helper is lost right after
/// it gave `b`'s endpoint its locator (between the endpoint's creation and its realization):
/// `b`'s `ensure` is refused, never ready at the old paths, and nothing reaches the
/// replacement; `a`, realized on the first helper, is not replayed at the new locator but
/// invalidated. The next `ensure` of each publishes the new base's paths, realized there.
#[tokio::test]
async fn wsl_mode_b_a_replacement_with_another_run_base_realizes_nothing_rendered_for_the_old() {
    let w = Live::new();
    let (p, _host, factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    factory
        .run_dirs
        .lock()
        .unwrap()
        .extend([RUN_DIR.to_owned(), HOME_RUN_DIR.to_owned()]);
    let socket_of = |d: &EnsureData| {
        d.consumer
            .realization
            .as_ref()
            .and_then(|r| r.endpoint.clone())
            .expect("a Mode B endpoint")
    };
    let a = ensure_in(&p, &id, "w-a", "r-a").await.unwrap();
    let old_tag = tag_of(&socket_of(&a));
    let first = factory.bridge();

    first.lose_on_run_dir.store(true, Ordering::SeqCst);
    let e = ensure_in(&p, &id, "w-b", "r-b")
        .await
        .expect_err("an endpoint rendered for the lost helper's run base is never ready");
    assert_eq!(e.code, Code::ServiceUnavailable, "{}", e.message);
    let second = factory.bridge();
    assert!(!Arc::ptr_eq(&first, &second), "the helper was replaced");
    assert_eq!(
        second.calls(),
        vec![],
        "the replacement realizes nothing rendered for the old run base"
    );
    assert!(
        p.registry.binding_endpoint(&a.binding_id).is_none(),
        "a's endpoint (the old run base) is invalidated, not replayed"
    );
    assert!(
        second.open(&old_tag).is_none(),
        "no signer stays behind the old base's tag"
    );

    let b = ensure_in(&p, &id, "w-b", "r-b2").await.unwrap();
    let a2 = ensure_in(&p, &id, "w-a", "r-a2").await.unwrap();
    for d in [&b, &a2] {
        let socket = socket_of(d);
        let tag = tag_under(HOME_RUN_DIR, &socket);
        let r = d.consumer.realization.as_ref().unwrap();
        assert_eq!(
            r.config.as_deref(),
            Some(format!("{HOME_RUN_DIR}/b/{tag}/ssh_config").as_str())
        );
        assert!(second.realized().unwrap().iter().any(|(t, _)| *t == tag));
    }
    for c in second.calls() {
        if let Call::Realize { public, .. } = c {
            assert!(
                !public.ssh_config.contains(RUN_DIR),
                "nothing realized on the replacement names the old run base"
            );
        }
    }
    p.shutdown.cancel();
}

/// ⟨M04 I-28⟩ A Mode B binding's result carries one `endpoint_kind_not_covered` reason per
/// claim-table field naming `wsl_mode_b` (the grant's recorded terms, from its environment)
/// and no claim-table entry. (The report on a qualifying Windows host is
/// `integration_managed_adapter`'s
/// `wsl_mode_b_binding_reads_every_claim_field_unknown_on_a_qualifying_windows_host`.)
#[tokio::test]
async fn wsl_mode_b_binding_result_names_its_endpoint_kind_for_the_claim_table() {
    let w = Live::new();
    let (p, _host, _factory) = process(&w, true).await;
    let (id, _) = approved(&p).await;
    permit_ensures(&w, &id);
    let a = ensure_in(&p, &id, "w-a", "r-a")
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    assert_eq!(a.environment_id, id);
    assert_eq!(
        claim_reasons(&a),
        reasons_naming(heimdall_contract::managed::BindingEndpointKind::WslModeB)
    );
    assert!(
        a.evidence
            .iter()
            .all(|x| x.source != heimdall_contract::managed::EvidenceSource::ClaimTable)
    );
}
