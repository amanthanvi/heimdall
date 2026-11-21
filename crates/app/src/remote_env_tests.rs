//! Unit tests of the controller's environment management over fakes of every port
//! (m06-plan U2 "Tests"). The runner side is not served in this wave: the management
//! session is a recording fake that answers as the runner's contract says (`OK`, or
//! `APPROVAL_REQUIRED` with the runner's `decision_ref` for a widening).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use heimdall_contract::envelope::{
    EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, reason,
};
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, KeyFingerprint, RequestId,
};
use heimdall_contract::remote::{RemoteEnvironmentRequest, Role};
use heimdall_contract::request::Request;
use heimdall_contract::{Code, OperationState};

use super::*;

const HOST: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVqmTNbwT7nI0Fk7RzD4mgwA0ke2pRDCgUNQ0FHb8xn";
const NEW_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb new";

fn fp(c: char) -> KeyFingerprint {
    KeyFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
}

fn env_id(n: u8) -> EnvironmentId {
    EnvironmentId::from_random_bytes([n; 16])
}

fn dest(s: &str) -> DestinationId {
    DestinationId::parse(s).unwrap()
}

fn account() -> AccountName {
    AccountName::parse("runner").unwrap()
}

fn route(keys: &[&str]) -> ManagementRoute {
    ManagementRoute {
        runner: ManagementHop {
            hostname: "10.0.0.7".into(),
            port: None,
            account: account(),
            host_keys: keys.iter().map(|k| (*k).to_owned()).collect(),
        },
        jump: None,
    }
}

fn record(n: u8) -> RemoteEnvironmentRecord {
    RemoteEnvironmentRecord {
        environment: env_id(n),
        destination: dest(&format!("lab{n}")),
        route: route(&[HOST]),
        client: ClientId::from_random_bytes([n; 16]),
        role: Role::Owner,
        key_fingerprint: fp('K'),
        label: None,
        pinned_at: Timestamp::UNIX_EPOCH,
    }
}

// --- fakes -------------------------------------------------------------------------------

#[derive(Default)]
struct KeyState {
    locked: bool,
    exists: bool,
    created: u32,
    destroyed: u32,
}

#[derive(Default)]
struct FakeKey(Mutex<KeyState>);

impl FakeKey {
    fn existing() -> Self {
        let k = FakeKey::default();
        k.0.lock().unwrap().exists = true;
        k
    }
    fn lock(&self) {
        self.0.lock().unwrap().locked = true;
    }
    fn destroyed(&self) -> u32 {
        self.0.lock().unwrap().destroyed
    }
}

impl MgmtKeyPort for FakeKey {
    fn check(&self) -> Result<(), MgmtKeyUnavailable> {
        if self.0.lock().unwrap().locked {
            Err(MgmtKeyUnavailable::Locked)
        } else {
            Ok(())
        }
    }
    fn public_key(&self, create: bool) -> Result<MgmtKeyInfo, MgmtKeyUnavailable> {
        let mut s = self.0.lock().unwrap();
        if s.locked {
            return Err(MgmtKeyUnavailable::Locked);
        }
        if !s.exists {
            if !create {
                return Err(MgmtKeyUnavailable::NotFound);
            }
            s.exists = true;
            s.created += 1;
        }
        Ok(MgmtKeyInfo {
            openssh_line: format!("{HOST} heimdall-mgmt"),
            fingerprint: fp('K'),
        })
    }
    fn destroy(&self) -> Result<(), MgmtKeyUnavailable> {
        let mut s = self.0.lock().unwrap();
        if s.locked {
            return Err(MgmtKeyUnavailable::Locked);
        }
        s.exists = false;
        s.destroyed += 1;
        Ok(())
    }
    fn fingerprint_of(&self, line: &str) -> Option<KeyFingerprint> {
        // A deterministic stand-in (the real computation is heimdall-credential's).
        if line.starts_with("ssh-ed25519 ") {
            Some(if line.contains("Bbbb") {
                fp('N')
            } else {
                fp('H')
            })
        } else {
            None
        }
    }
}

#[derive(Default)]
struct FakeRegistry(Mutex<BTreeMap<EnvironmentId, RemoteEnvironmentRecord>>);

impl FakeRegistry {
    fn with(records: &[RemoteEnvironmentRecord]) -> Self {
        let r = FakeRegistry::default();
        for rec in records {
            r.0.lock()
                .unwrap()
                .insert(rec.environment.clone(), rec.clone());
        }
        r
    }
    fn ids(&self) -> Vec<EnvironmentId> {
        self.0.lock().unwrap().keys().cloned().collect()
    }
}

impl EnvironmentRegistry for FakeRegistry {
    fn list(&self) -> Result<Vec<RemoteEnvironmentRecord>, OpError> {
        Ok(self.0.lock().unwrap().values().cloned().collect())
    }
    fn put(&self, record: &RemoteEnvironmentRecord) -> Result<(), OpError> {
        self.0
            .lock()
            .unwrap()
            .insert(record.environment.clone(), record.clone());
        Ok(())
    }
    fn remove(&self, environment: &EnvironmentId) -> Result<bool, OpError> {
        Ok(self.0.lock().unwrap().remove(environment).is_some())
    }
}

struct FakeCatalog(Option<VerifiedAccess>);

impl AccessCatalog for FakeCatalog {
    fn verified_access(
        &self,
        _destination: &DestinationId,
        _account: &AccountName,
    ) -> Result<Option<VerifiedAccess>, OpError> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct FakeBootstrap(Mutex<Vec<BootstrapPlan>>);

#[async_trait::async_trait]
impl BootstrapRunner for FakeBootstrap {
    async fn run(&self, plan: &BootstrapPlan) -> Result<(), OpError> {
        self.0.lock().unwrap().push(plan.clone());
        Ok(())
    }
}

/// What the fake runner answers to one request.
type Responder = Box<dyn Fn(&Request) -> Envelope<serde_json::Value> + Send + Sync>;

/// The recording management sessions: every request sent, by session name.
struct FakeSessions {
    /// The environment ID each session's hello reports.
    hello: EnvironmentId,
    role: Option<Role>,
    /// The client each session's hello reports.
    client: Option<ClientId>,
    responder: Arc<Responder>,
    sent: Arc<Mutex<Vec<(SessionName, Request)>>>,
    opened: Arc<Mutex<Vec<SessionTarget>>>,
    /// Environments whose sessions fail to open.
    unreachable: Vec<EnvironmentId>,
    /// When set, the hello reports the session's own recorded environment.
    echo_name: bool,
}

impl FakeSessions {
    fn new(hello: EnvironmentId, responder: Responder) -> Self {
        FakeSessions {
            hello,
            role: Some(Role::Owner),
            client: None,
            responder: Arc::new(responder),
            sent: Arc::default(),
            opened: Arc::default(),
            unreachable: Vec::new(),
            echo_name: false,
        }
    }
    fn sent(&self) -> Vec<(SessionName, Request)> {
        self.sent.lock().unwrap().clone()
    }
}

struct FakeSession {
    name: SessionName,
    hello: SessionHello,
    responder: Arc<Responder>,
    sent: Arc<Mutex<Vec<(SessionName, Request)>>>,
}

#[async_trait::async_trait]
impl ManagementSession for FakeSession {
    fn hello(&self) -> &SessionHello {
        &self.hello
    }
    async fn call(&mut self, call: ManagementCall) -> Result<Envelope<serde_json::Value>, OpError> {
        let request = call.into_request();
        let answer = (self.responder)(&request);
        self.sent.lock().unwrap().push((self.name.clone(), request));
        Ok(answer)
    }
}

#[async_trait::async_trait]
impl ManagementSessions for FakeSessions {
    async fn open(&self, target: &SessionTarget) -> Result<Box<dyn ManagementSession>, OpError> {
        self.opened.lock().unwrap().push(target.clone());
        if let SessionName::Environment(e) = &target.name
            && self.unreachable.contains(e)
        {
            return Err(OpError::new(Code::DestinationUnreachable, "unreachable"));
        }
        let environment = match (&target.name, self.echo_name) {
            (SessionName::Environment(e), true) => e.clone(),
            _ => self.hello.clone(),
        };
        let responder = self.responder.clone();
        Ok(Box::new(FakeSession {
            name: target.name.clone(),
            hello: SessionHello {
                environment,
                role: self.role,
                client: self.client.clone(),
            },
            responder,
            sent: self.sent.clone(),
        }))
    }
}

struct FakeConfirm {
    answer: bool,
    asked: Mutex<Vec<Confirmation>>,
}

impl FakeConfirm {
    fn yes() -> Self {
        FakeConfirm {
            answer: true,
            asked: Mutex::default(),
        }
    }
    fn no() -> Self {
        FakeConfirm {
            answer: false,
            asked: Mutex::default(),
        }
    }
}

impl LocalConfirm for FakeConfirm {
    fn confirm(&self, what: &Confirmation) -> bool {
        self.asked.lock().unwrap().push(what.clone());
        self.answer
    }
}

fn ok(data: serde_json::Value) -> Envelope<serde_json::Value> {
    Envelope::ok(data)
}

fn approval_required(decision_ref: &str) -> Envelope<serde_json::Value> {
    let detail = ErrorDetail {
        code: Code::ApprovalRequired,
        effect_status: EffectStatus::None,
        retryable: false,
        resource: None,
        next: NextAction {
            action: "observe".into(),
            decision_ref: Some(decision_ref.into()),
            ..NextAction::default()
        },
        message: "pending runner-local decision".into(),
        reason: None,
        entries: Vec::new(),
    };
    Envelope {
        state: OperationState::AwaitingApproval,
        code: Code::ApprovalRequired,
        next: Some(detail.next.clone()),
        ..Envelope::ok(
            serde_json::to_value(ErrorData {
                error: detail,
                setup: None,
            })
            .unwrap(),
        )
    }
}

fn always_ok() -> Responder {
    Box::new(|_| ok(serde_json::json!({})))
}

struct World {
    key: FakeKey,
    registry: FakeRegistry,
    catalog: FakeCatalog,
    bootstrap: FakeBootstrap,
    sessions: FakeSessions,
    confirm: FakeConfirm,
}

impl World {
    fn controller(&self) -> RemoteEnvController<'_> {
        RemoteEnvController::new(ControllerPorts {
            key: &self.key,
            registry: &self.registry,
            catalog: &self.catalog,
            bootstrap: &self.bootstrap,
            sessions: &self.sessions,
            confirm: &self.confirm,
            now: Timestamp::UNIX_EPOCH,
        })
    }
}

fn access(keys: &[&str]) -> VerifiedAccess {
    VerifiedAccess {
        destination: dest("lab"),
        alias: "lab".into(),
        route: route(keys),
    }
}

fn add_input() -> AddInput {
    AddInput {
        destination: dest("lab"),
        account: account(),
        label: Some("build box".into()),
        runner_program: "/opt/heimdall/bin/heimdall".into(),
        runner_home: None,
        runner_sha256: None,
    }
}

// --- tests -------------------------------------------------------------------------------

/// m06-plan U2 "bootstrap refuses an unverified host key" (the controller half): a
/// destination with no catalog-pinned host key is refused `host_trust_undetermined` before
/// K_mgmt is created, before the bootstrap runs and before any session opens.
#[tokio::test]
async fn add_refuses_an_unverified_host_key_before_anything_runs() {
    let w = World {
        key: FakeKey::default(),
        registry: FakeRegistry::default(),
        catalog: FakeCatalog(Some(access(&[]))),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(1), always_ok()),
        confirm: FakeConfirm::yes(),
    };
    let err = w.controller().add(&add_input()).await.unwrap_err();
    assert_eq!(err.code, Code::CapabilityUnavailable);
    assert_eq!(err.reason.as_deref(), Some(reason::HOST_TRUST_UNDETERMINED));
    assert_eq!(w.key.0.lock().unwrap().created, 0);
    assert!(w.bootstrap.0.lock().unwrap().is_empty());
    assert!(w.sessions.opened.lock().unwrap().is_empty());
    assert!(w.registry.ids().is_empty());
}

/// `add`: K_mgmt created once, the bootstrap plan carries the catalog pins, the owner key and
/// a fresh client, the first session is rendered under the destination with the same pins,
/// and the record takes the environment ID the runner's hello reported. A repair keeps the
/// client; a runner that reports another environment is held.
#[tokio::test]
async fn add_bootstraps_then_records_the_runner_reported_environment() {
    let w = World {
        key: FakeKey::default(),
        registry: FakeRegistry::default(),
        catalog: FakeCatalog(Some(access(&[HOST]))),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(9), always_ok()),
        confirm: FakeConfirm::yes(),
    };
    let record = w.controller().add(&add_input()).await.unwrap();
    assert_eq!(record.environment, env_id(9));
    assert_eq!(record.role, Role::Owner);
    assert_eq!(record.route.runner.host_keys, vec![HOST.to_owned()]);
    assert_eq!(w.key.0.lock().unwrap().created, 1);
    let plans = w.bootstrap.0.lock().unwrap().clone();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].owner_client, record.client);
    assert_eq!(plans[0].owner_key.fingerprint, fp('K'));
    let opened = w.sessions.opened.lock().unwrap().clone();
    assert_eq!(opened[0].name, SessionName::Bootstrap(dest("lab")));
    assert_eq!(opened[0].route.runner.host_keys, vec![HOST.to_owned()]);
    assert!(w.sessions.sent().is_empty(), "add sends no request");
    // Repair: the same client is kept.
    let again = w.controller().add(&add_input()).await.unwrap();
    assert_eq!(again.client, record.client);
    // ⟨rev6.2⟩ A client reported by the runner's hello wins (a retried first bootstrap the
    // runner answered with the owner it enrolled first).
    let enrolled_first = ClientId::from_random_bytes([0x77; 16]);
    let mut reporting = FakeSessions::new(env_id(6), always_ok());
    reporting.client = Some(enrolled_first.clone());
    let w_report = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::default(),
        catalog: FakeCatalog(Some(access(&[HOST]))),
        bootstrap: FakeBootstrap::default(),
        sessions: reporting,
        confirm: FakeConfirm::yes(),
    };
    assert_eq!(
        w_report
            .controller()
            .add(&add_input())
            .await
            .unwrap()
            .client,
        enrolled_first
    );
    // A re-initialized runner (another environment ID) is held, not re-pinned.
    let w2 = World {
        sessions: FakeSessions::new(env_id(8), always_ok()),
        registry: FakeRegistry::with(&[RemoteEnvironmentRecord {
            destination: dest("lab"),
            ..record.clone()
        }]),
        ..w
    };
    let err = w2.controller().add(&add_input()).await.unwrap_err();
    assert_eq!(
        err.reason.as_deref(),
        Some(reason::ENVIRONMENT_IDENTITY_MISMATCH)
    );
    assert_eq!(w2.registry.ids(), vec![env_id(9)]);
    // A runner that did not enroll this device as owner.
    let mut s = FakeSessions::new(env_id(7), always_ok());
    s.role = Some(Role::Viewer);
    let w3 = World {
        sessions: s,
        registry: FakeRegistry::default(),
        ..w2
    };
    let err = w3.controller().add(&add_input()).await.unwrap_err();
    assert_eq!(err.reason.as_deref(), Some(reason::ROLE_INSUFFICIENT));
    assert!(w3.registry.ids().is_empty());
}

/// m06-plan U2 "K_mgmt in a locked store gives `mgmt_key_store_locked`, and runner work is
/// unaffected": every management operation refuses before a session opens (so nothing is
/// sent to any runner and no record changes), while `status` still answers, reporting the
/// locked store.
#[tokio::test]
async fn locked_store_refuses_management_and_leaves_runners_alone() {
    let w = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::with(&[record(1), record(2)]),
        catalog: FakeCatalog(Some(access(&[HOST]))),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(1), always_ok()),
        confirm: FakeConfirm::yes(),
    };
    w.key.lock();
    let c = w.controller();
    let locked = |e: OpError| {
        assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
        assert_eq!(e.reason.as_deref(), Some(reason::MGMT_KEY_STORE_LOCKED));
    };
    locked(c.add(&add_input()).await.unwrap_err());
    locked(
        c.invite(&InviteInput {
            environment: env_id(1),
            role: Role::Viewer,
            public_key: NEW_KEY.into(),
            key_fingerprint: fp('N'),
            request_id: RequestId::parse("req_1").unwrap(),
        })
        .await
        .unwrap_err(),
    );
    locked(
        c.revoke_client(&env_id(1), &ClientId::from_random_bytes([5; 16]))
            .await
            .unwrap_err(),
    );
    locked(c.update(&env_id(1)).await.unwrap_err());
    locked(c.remove(&env_id(1)).await.unwrap_err());
    locked(c.retire().await.unwrap_err());
    assert!(
        w.sessions.opened.lock().unwrap().is_empty(),
        "no session opened"
    );
    assert!(w.bootstrap.0.lock().unwrap().is_empty());
    assert_eq!(
        w.registry.ids(),
        vec![env_id(1), env_id(2)],
        "records untouched"
    );
    assert_eq!(w.key.destroyed(), 0);
    let status = c.status(None).unwrap();
    assert_eq!(status.management, reason::MGMT_KEY_STORE_LOCKED);
    assert_eq!(status.environments.len(), 2);
}

/// m06-plan U2 "the controller never sends `Decide` over a management session; a widening
/// request returns `APPROVAL_REQUIRED` with the runner's `decision_ref`": an invitation the
/// runner holds for its local confirmation is returned pending with the runner's own
/// reference and the request ID to replay; the replay after the runner-local decision reads
/// the terminal result. Every request sent is a `remote_environment` form; none is `Decide`
/// or `Attend` (the call type cannot express them), and an unexpected decision on a
/// non-widening call is surfaced unchanged, never answered.
#[tokio::test]
async fn controller_never_sends_decide_and_returns_the_runners_decision_ref() {
    let decided = Arc::new(Mutex::new(false));
    let flag = decided.clone();
    let responder: Responder = Box::new(move |r: &Request| match r {
        Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite { .. }) => {
            if *flag.lock().unwrap() {
                ok(serde_json::json!({
                    "invitation": "inv_0001",
                    "client": format!("cl_{}", "0a".repeat(16)),
                    "generation": 3,
                    "nonce": "n0nce",
                    "expires_wall": "2026-11-21T12:15:00Z",
                }))
            } else {
                approval_required("dec_runner_0001")
            }
        }
        Request::RemoteEnvironment(RemoteEnvironmentRequest::Update { .. }) => {
            approval_required("dec_runner_0002")
        }
        _ => ok(serde_json::json!({})),
    });
    let w = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::with(&[record(1)]),
        catalog: FakeCatalog(None),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(1), responder),
        confirm: FakeConfirm::yes(),
    };
    let c = w.controller();
    let input = InviteInput {
        environment: env_id(1),
        role: Role::Requester,
        public_key: NEW_KEY.into(),
        key_fingerprint: fp('N'),
        request_id: RequestId::parse("req_invite_1").unwrap(),
    };
    match c.invite(&input).await.unwrap() {
        InviteOutcome::Pending {
            decision_ref,
            request_id,
        } => {
            assert_eq!(decision_ref, "dec_runner_0001");
            assert_eq!(request_id, input.request_id);
        }
        other => panic!("{other:?}"),
    }
    // The owner confirmed the fingerprint locally first.
    assert!(matches!(
        w.confirm.asked.lock().unwrap()[0],
        Confirmation::InviteKey { .. }
    ));
    // The owner confirms at the runner; the replay with the same request ID reads the
    // terminal result.
    *decided.lock().unwrap() = true;
    let InviteOutcome::Created(bundle) = c.invite(&input).await.unwrap() else {
        panic!("not created");
    };
    assert_eq!(bundle.environment, env_id(1));
    assert_eq!(bundle.generation, 3);
    assert_eq!(bundle.key_fingerprint, fp('N'));
    assert_eq!(bundle.nonce.as_deref(), Some("n0nce"));
    assert_eq!(bundle.route.runner.host_keys, vec![HOST.to_owned()]);
    // A decision on a non-widening call is surfaced, not answered.
    let err = c.update(&env_id(1)).await.unwrap_err();
    assert_eq!(err.code, Code::ApprovalRequired);
    assert_eq!(err.next.decision_ref.as_deref(), Some("dec_runner_0002"));
    let sent = w.sessions.sent();
    assert_eq!(sent.len(), 3);
    for (_, request) in &sent {
        assert!(
            request.kind().starts_with("remote_environment."),
            "{}",
            request.kind()
        );
        assert!(!matches!(request, Request::Decide(_)));
    }
    // Both invite attempts carried the same request ID (terminal replay, T-RA3).
    let ids: Vec<_> = sent
        .iter()
        .filter_map(|(_, r)| match r {
            Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite { request_id, .. }) => {
                Some(request_id.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        ids,
        vec![input.request_id.clone(), input.request_id.clone()]
    );
    // An unconfirmed fingerprint sends nothing; a fingerprint that is not the key's is a
    // usage error.
    let w2 = World {
        confirm: FakeConfirm::no(),
        sessions: FakeSessions::new(env_id(1), always_ok()),
        ..w
    };
    let err = w2.controller().invite(&input).await.unwrap_err();
    assert_eq!(err.code, Code::InteractionRequired);
    let wrong = InviteInput {
        key_fingerprint: fp('Z'),
        ..input
    };
    assert_eq!(
        w2.controller().invite(&wrong).await.unwrap_err().code,
        Code::UsageError
    );
    assert!(w2.sessions.sent().is_empty());
}

/// m06-plan U2 "device retirement is separate from revoking one runner": revoking a client
/// on one runner, and removing one environment, never destroy K_mgmt; retirement needs the
/// local confirmation, revokes this device's own client on every runner, and destroys K_mgmt
/// only after all of them succeeded (an unreachable runner keeps K_mgmt so the retirement can
/// be retried, and the runners already revoked are forgotten).
#[tokio::test]
async fn device_retirement_is_separate_from_one_runner_revocation() {
    let w = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::with(&[record(1), record(2), record(3)]),
        catalog: FakeCatalog(None),
        bootstrap: FakeBootstrap::default(),
        sessions: {
            let mut s = FakeSessions::new(env_id(1), always_ok());
            s.echo_name = true;
            s
        },
        confirm: FakeConfirm::yes(),
    };
    let c = w.controller();
    let other = ClientId::from_random_bytes([0x55; 16]);
    c.revoke_client(&env_id(1), &other).await.unwrap();
    assert_eq!(w.key.destroyed(), 0);
    assert_eq!(w.registry.ids().len(), 3);
    // Removing one environment revokes this device's own client there, forgets it, and
    // keeps K_mgmt for the other runners.
    c.remove(&env_id(1)).await.unwrap();
    assert_eq!(w.key.destroyed(), 0);
    assert_eq!(w.registry.ids(), vec![env_id(2), env_id(3)]);
    let sent = w.sessions.sent();
    assert!(matches!(
        &sent[1].1,
        Request::RemoteEnvironment(RemoteEnvironmentRequest::RevokeClient { client, .. })
            if *client == record(1).client
    ));

    // Not confirmed: nothing revoked, nothing destroyed.
    let w = World {
        confirm: FakeConfirm::no(),
        ..w
    };
    assert_eq!(
        w.controller().retire().await.unwrap_err().code,
        Code::InteractionRequired
    );
    assert_eq!(w.sessions.sent().len(), 2);
    assert_eq!(w.key.destroyed(), 0);

    // One runner unreachable: the reachable one before it is revoked and forgotten, K_mgmt
    // is kept, and the error names the environment.
    let mut sessions = FakeSessions::new(env_id(1), always_ok());
    sessions.echo_name = true;
    sessions.unreachable = vec![env_id(3)];
    let w = World {
        confirm: FakeConfirm::yes(),
        sessions,
        ..w
    };
    let err = w.controller().retire().await.unwrap_err();
    assert_eq!(err.code, Code::OutcomeUnknown);
    assert_eq!(
        w.key.destroyed(),
        0,
        "K_mgmt kept while a revocation is incomplete"
    );
    assert_eq!(w.registry.ids(), vec![env_id(3)]);
    let asked = w.confirm.asked.lock().unwrap().clone();
    assert!(
        matches!(&asked[0], Confirmation::RetireDevice { environments, .. }
        if *environments == vec![env_id(2), env_id(3)])
    );

    // Reachable again: the retry revokes the rest, then destroys K_mgmt.
    let mut sessions = FakeSessions::new(env_id(1), always_ok());
    sessions.echo_name = true;
    let w = World { sessions, ..w };
    let outcome = w.controller().retire().await.unwrap();
    assert_eq!(outcome.revoked_on, vec![env_id(3)]);
    assert!(outcome.key_destroyed);
    assert_eq!(w.key.destroyed(), 1);
    assert!(w.registry.ids().is_empty());
    for (_, r) in w.sessions.sent() {
        assert!(matches!(
            r,
            Request::RemoteEnvironment(RemoteEnvironmentRequest::RevokeClient { .. })
        ));
    }
}

/// Rotation is invite-then-revoke (ADR-0012 §3.4): the new key is invited (a widening the
/// runner holds for its local confirmation), and the old client is then revoked; neither
/// step destroys or overwrites the stored K_mgmt.
#[tokio::test]
async fn rotation_is_invite_then_revoke() {
    let responder: Responder = Box::new(|r: &Request| match r {
        Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite { .. }) => {
            ok(serde_json::json!({
                "invitation": "inv_rot",
                "client": format!("cl_{}", "0b".repeat(16)),
                "generation": 1,
            }))
        }
        _ => ok(serde_json::json!({})),
    });
    let w = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::with(&[record(1)]),
        catalog: FakeCatalog(None),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(1), responder),
        confirm: FakeConfirm::yes(),
    };
    let c = w.controller();
    let InviteOutcome::Created(bundle) = c
        .invite(&InviteInput {
            environment: env_id(1),
            role: Role::Owner,
            public_key: NEW_KEY.into(),
            key_fingerprint: fp('N'),
            request_id: RequestId::parse("req_rotate").unwrap(),
        })
        .await
        .unwrap()
    else {
        panic!("not created");
    };
    assert_eq!(bundle.role, Role::Owner);
    c.revoke_client(&env_id(1), &record(1).client)
        .await
        .unwrap();
    assert_eq!(w.key.destroyed(), 0);
    assert_eq!(w.key.0.lock().unwrap().created, 0);
}

/// `join`: the user confirms the runner's host-key fingerprints and environment ID from the
/// bundle (nothing is sent otherwise); the bundle must name this device's K_mgmt; the
/// pending client then sends only the activation probe and `join`; the record keeps the
/// bundle's client and role. A runner presenting another environment is refused.
#[tokio::test]
async fn join_confirms_the_runner_then_sends_only_probe_and_join() {
    let bundle = InvitationBundle {
        environment: env_id(4),
        route: route(&[HOST]),
        destination: dest("lab4"),
        invitation: heimdall_contract::ids::InvitationId::parse("inv_4").unwrap(),
        client: ClientId::from_random_bytes([4; 16]),
        role: Role::Viewer,
        generation: 2,
        key_fingerprint: fp('K'),
        nonce: Some("abc".into()),
    };
    let w = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::default(),
        catalog: FakeCatalog(None),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(4), always_ok()),
        confirm: FakeConfirm::no(),
    };
    assert_eq!(
        w.controller().join(&bundle).await.unwrap_err().code,
        Code::InteractionRequired
    );
    assert!(w.sessions.opened.lock().unwrap().is_empty());
    let asked = w.confirm.asked.lock().unwrap().clone();
    assert!(
        matches!(&asked[0], Confirmation::JoinRunner { environment, host_fingerprints, role }
        if *environment == env_id(4) && host_fingerprints == &vec![fp('H').as_str().to_owned()] && *role == Role::Viewer)
    );
    let w = World {
        confirm: FakeConfirm::yes(),
        ..w
    };
    let other_key = InvitationBundle {
        key_fingerprint: fp('Q'),
        ..bundle.clone()
    };
    assert_eq!(
        w.controller().join(&other_key).await.unwrap_err().code,
        Code::UsageError
    );
    let record = w.controller().join(&bundle).await.unwrap();
    assert_eq!(record.client, bundle.client);
    assert_eq!(record.role, Role::Viewer);
    let kinds: Vec<&str> = w.sessions.sent().iter().map(|(_, r)| r.kind()).collect();
    assert_eq!(
        kinds,
        [
            "remote_environment.activation_probe",
            "remote_environment.join"
        ]
    );
    let w = World {
        sessions: FakeSessions::new(env_id(5), always_ok()),
        registry: FakeRegistry::default(),
        ..w
    };
    assert_eq!(
        w.controller()
            .join(&bundle)
            .await
            .unwrap_err()
            .reason
            .as_deref(),
        Some(reason::ENVIRONMENT_IDENTITY_MISMATCH)
    );
    assert!(w.sessions.sent().is_empty());
    assert!(w.registry.ids().is_empty());
}

/// A recorded environment whose runner now reports another environment ID is held: nothing
/// is sent (ADR-0012 §7.5).
#[tokio::test]
async fn a_changed_environment_id_is_held() {
    let w = World {
        key: FakeKey::existing(),
        registry: FakeRegistry::with(&[record(1)]),
        catalog: FakeCatalog(None),
        bootstrap: FakeBootstrap::default(),
        sessions: FakeSessions::new(env_id(2), always_ok()),
        confirm: FakeConfirm::yes(),
    };
    let err = w.controller().update(&env_id(1)).await.unwrap_err();
    assert_eq!(
        err.reason.as_deref(),
        Some(reason::ENVIRONMENT_IDENTITY_MISMATCH)
    );
    assert!(w.sessions.sent().is_empty());
    // ⟨rev6.2⟩ The right environment, but the runner bound another client: held too.
    let mut sessions = FakeSessions::new(env_id(1), always_ok());
    sessions.client = Some(ClientId::from_random_bytes([0x99; 16]));
    let w = World { sessions, ..w };
    let err = w.controller().update(&env_id(1)).await.unwrap_err();
    assert_eq!(
        err.reason.as_deref(),
        Some(reason::ENVIRONMENT_IDENTITY_MISMATCH)
    );
    assert!(w.sessions.sent().is_empty());
    // Its own client reported: served.
    let mut sessions = FakeSessions::new(env_id(1), always_ok());
    sessions.client = Some(record(1).client);
    let w = World { sessions, ..w };
    w.controller().update(&env_id(1)).await.unwrap();
}

#[test]
fn runner_errors_pass_through_and_bundles_round_trip() {
    let detail = ErrorDetail {
        code: Code::CapabilityUnavailable,
        effect_status: EffectStatus::None,
        retryable: false,
        resource: None,
        next: NextAction {
            action: "narrow_request".into(),
            ..NextAction::default()
        },
        message: "role".into(),
        reason: Some(reason::ROLE_INSUFFICIENT.into()),
        entries: Vec::new(),
    };
    let envelope = Envelope {
        state: OperationState::Failed,
        code: Code::CapabilityUnavailable,
        ..Envelope::ok(
            serde_json::to_value(ErrorData {
                error: detail,
                setup: None,
            })
            .unwrap(),
        )
    };
    let err = runner_result(envelope).unwrap_err();
    assert_eq!(err.reason.as_deref(), Some(reason::ROLE_INSUFFICIENT));
    let bundle = InvitationBundle {
        environment: env_id(4),
        route: route(&[HOST]),
        destination: dest("lab4"),
        invitation: heimdall_contract::ids::InvitationId::parse("inv_4").unwrap(),
        client: ClientId::from_random_bytes([4; 16]),
        role: Role::Viewer,
        generation: 2,
        key_fingerprint: fp('K'),
        nonce: None,
    };
    let text = serde_json::to_string(&bundle).unwrap();
    assert_eq!(
        serde_json::from_str::<InvitationBundle>(&text).unwrap(),
        bundle
    );
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["grants_everything"] = serde_json::json!(true);
    assert!(serde_json::from_value::<InvitationBundle>(value).is_err());
    assert!(matches!(
        ManagementCall::Environment(RemoteEnvironmentRequest::Status { environment: None })
            .into_request(),
        Request::RemoteEnvironment(_)
    ));
}
