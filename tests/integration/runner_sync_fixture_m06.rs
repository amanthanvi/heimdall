//! ⟨M06 U4⟩ The resynchronization fixture shared by `integration_runner_effects_m06` and
//! `model_remote_sync` (included with `#[path]` beside `runner_fixture_m06.rs`; no tests of
//! its own).
//!
//! * [`Rig`]: the runner world of `runner_fixture_m06` with the runner's real operations and
//!   its sync service over the same in-memory store and virtual clock, so a delivered effect
//!   runs the runner's own narrowing machinery.
//! * [`Session`]: one management session to that runner as a controller sees it (the
//!   `RunnerChannel` port), in process: it can report another environment or client than the
//!   runner's (a substituted route), and lose a reply after the runner applied the request.
//! * [`Controller`]: a controller's own store (its outbox and its issuer's ledger), its
//!   issuer barrier and its pin of the runner.
//!
//! Disposable state only: in-memory stores, fixture IDs, public fixture key text.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use heimdall_app::context::Caller;
use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::remote_status::{
    Narrowing, RemoteStatus, ResyncOutcome, RunnerChannel, produce_effect, resync, status_of,
};
use heimdall_app::remote_status_barrier::{BarrierRefusal, IssuerBarrier};
use heimdall_app::{OpError, Operations, OperationsConfig};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::controller_record::{ManagementHop, ManagementRoute, RemoteEnvironmentPin};
use heimdall_contract::envelope::Envelope;
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EffectId, EnvironmentId, GrantId, IssuanceId,
    KeyFingerprint, PolicyId,
};
use heimdall_contract::remote::{EffectTarget, Role, RunnerRequest};
use heimdall_domain::issuance::{CertificateBounds, IssuanceEntry, IssuanceState, principal_for};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_remote::sync::RunnerSync;
use heimdall_store::ext_effects::{EffectAck, EffectKey};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::ScriptedTimeSync;

use super::fixture::*;

/// The runner world with its operations and sync service (module docs).
pub struct Rig {
    pub w: World,
    pub ops: Operations,
    pub sync: RunnerSync,
    pub time_sync: Arc<ScriptedTimeSync>,
}

pub async fn rig() -> Rig {
    rig_with(world(), Limits::default()).await
}

/// ⟨M08 W4 SEC-3b⟩ [`rig`] over the world `w`, with the runner's operations limits `limits`
/// (a shorter `operation_retention` for the history-growth workload).
pub async fn rig_with(w: World, limits: Limits) -> Rig {
    // The runner's own environment permits automatic work under its standing policies (the
    // owner's setup choice on a real runner), so the fixture grant's re-validation holds and
    // a narrowing shows only its own effect.
    w.store
        .transaction(|tx| {
            let mut e = tx.environment(&w.env)?.unwrap();
            e.permissions = heimdall_domain::environment::EnvironmentPermissions {
                automatic_activation: true,
                managed_signing: true,
                issuer_access: true,
            };
            tx.upsert_environment(&e)
        })
        .unwrap();
    let time_sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let ops = Operations::start(OperationsConfig {
        store: w.store.clone(),
        clock: w.clock.clone(),
        time_sync: time_sync.clone(),
        time_policy: TimePolicy::default(),
        environment: w.env.clone(),
        adapters: Vec::new(),
        stage_hook: Arc::new(NoStageHook),
        limits,
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap();
    let sync = RunnerSync::new(w.store.clone(), ops.clone(), w.clock.clone());
    Rig {
        w,
        ops,
        sync,
        time_sync,
    }
}

pub fn effect(n: u8) -> EffectId {
    EffectId::from_random_bytes([n; 16])
}

pub fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

impl Rig {
    /// The paired session caller of controller `c` (owner).
    pub fn caller(c: &ClientId) -> Caller {
        Caller::unattended(World::caller(c))
    }

    /// Deliver one effect from controller `c`, as its session would.
    pub async fn deliver(
        &self,
        c: &ClientId,
        e: &EffectId,
        target: &EffectTarget,
    ) -> Result<EffectAck, OpError> {
        self.sync
            .deliver(self.w.runner.as_ref(), &Self::caller(c), e, target)
            .await
    }

    /// A session of controller `c` to this runner.
    pub fn session(&self, c: &ClientId) -> Session<'_> {
        Session {
            rig: self,
            client: c.clone(),
            environment: self.w.env.clone(),
            reported_client: Some(c.clone()),
            connection: 7,
            calls: AtomicUsize::new(0),
            lose_reply_of: None,
        }
    }

    /// Make the runner's time uncertain: the wall clock jumps an hour back, below the
    /// persisted high-water mark (the gate accepted the current reading first).
    pub async fn make_time_uncertain(&self) {
        self.ops.timegate().check().await.unwrap();
        let back = self
            .w
            .clock
            .wall()
            .checked_sub(jiff::SignedDuration::from_hours(1))
            .unwrap();
        self.w.clock.set_wall(back);
        assert_eq!(
            self.ops.timegate().check().await.unwrap_err().code,
            Code::TimeUncertain
        );
    }

    /// The runner's policy `pol` as stored now.
    pub fn policy(&self) -> heimdall_domain::policy::StandingPolicy {
        self.w
            .store
            .transaction(|tx| tx.policy(&policy_id()))
            .unwrap()
            .unwrap()
    }

    /// The fixture grant's state now.
    pub fn grant_state(&self) -> heimdall_contract::GrantState {
        self.w
            .store
            .transaction(|tx| tx.grant(&self.w.grant))
            .unwrap()
            .unwrap()
            .state
    }
}

/// One management session as a controller sees it (module docs).
pub struct Session<'a> {
    pub rig: &'a Rig,
    /// The client the runner authenticated (the effect's producer).
    pub client: ClientId,
    /// The environment ID the hello reports.
    pub environment: EnvironmentId,
    /// The client the hello reports.
    pub reported_client: Option<ClientId>,
    pub connection: u64,
    /// Requests sent so far.
    pub calls: AtomicUsize,
    /// The zero-based index of a request whose reply is lost after the runner served it.
    pub lose_reply_of: Option<usize>,
}

impl Session<'_> {
    pub fn sent(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RunnerChannel for Session<'_> {
    fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    fn client(&self) -> Option<&ClientId> {
        self.reported_client.as_ref()
    }

    async fn call(
        &mut self,
        request: RunnerRequest,
    ) -> Result<Envelope<serde_json::Value>, OpError> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let caller = Rig::caller(&self.client);
        let runner = &self.rig.w.runner;
        let result = if heimdall_runtime::runner::RunnerRuntime::is_sync_request(&request) {
            runner
                .serve_sync(&self.rig.sync, &caller, self.connection, &request)
                .await
        } else {
            runner.handle(&caller.context, self.connection, &request)
        };
        if self.lose_reply_of == Some(index) {
            return Err(OpError::new(
                Code::OutcomeUnknown,
                "the session was lost before the reply arrived",
            ));
        }
        Ok(heimdall_runtime::dispatch::render(result))
    }
}

/// A controller: its own store, barrier and pin (module docs).
pub struct Controller {
    pub store: Arc<Store>,
    pub barrier: IssuerBarrier,
    pub pin: RemoteEnvironmentPin,
    pub clock: Arc<heimdall_testkit::VirtualClock>,
    serial: AtomicUsize,
}

/// The controller whose client on the runner is `client`, with role `role` there. It reads
/// the same virtual clock as the runner (a designated time source that agrees with it).
pub fn controller(rig: &Rig, client: &ClientId, role: Role) -> Controller {
    let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
    let seed = client.as_str().as_bytes()[5];
    store
        .transaction(|tx| tx.init_self_environment(&EnvironmentId::from_random_bytes([seed; 16])))
        .unwrap();
    Controller {
        store,
        barrier: IssuerBarrier::new(),
        pin: RemoteEnvironmentPin {
            environment: rig.w.env.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: "runner1.example".into(),
                    port: None,
                    account: AccountName::parse("deploy").unwrap(),
                    host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
                },
                jump: None,
            },
            client: client.clone(),
            role,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "K".repeat(43))).unwrap(),
            label: None,
            pinned_at: t0(),
        },
        clock: rig.w.clock.clone(),
        serial: AtomicUsize::new(1),
    }
}

impl Controller {
    pub fn now(&self) -> Timestamp {
        self.clock.wall()
    }

    /// Put a narrowing in the outbox.
    pub fn produce(&self, narrowing: &Narrowing) -> Result<EffectKey, OpError> {
        let now = self.now();
        self.store
            .transaction(|tx| produce_effect(tx, &self.pin, narrowing, now))
            .unwrap()
    }

    pub async fn resync(&self, session: &mut Session<'_>) -> Result<ResyncOutcome, OpError> {
        resync(
            &self.store,
            self.clock.as_ref(),
            &self.barrier,
            &self.pin,
            session,
        )
        .await
    }

    pub fn status(&self, session_open: bool) -> RemoteStatus {
        let now = self.now();
        self.store
            .transaction(|tx| {
                status_of(
                    tx,
                    &self.pin.environment,
                    session_open,
                    Some(&self.barrier),
                    now,
                )
            })
            .unwrap()
    }

    /// A ledger entry for `grant` and pair `h1`, valid until `valid_before`. ⟨M08 W4 SEC-1,
    /// S2-04⟩ Its key ID names the runner's environment and the grant, as a remote issuance's
    /// does (`heimdall:<environment>:<grant>:<serial>`): this ledger's record of issuing for
    /// that runner's grant, which a reconciliation reads as the grant's delivery there.
    pub fn entry(&self, grant: &GrantId, valid_before: Timestamp) -> IssuanceEntry {
        let n = self.serial.fetch_add(1, Ordering::SeqCst) as u8;
        IssuanceEntry {
            id: IssuanceId::from_random_bytes([n; 16]),
            grant: grant.clone(),
            generation: AuthorityGeneration(0),
            pair: pair("h1"),
            bounds: CertificateBounds {
                serial: u64::from(n),
                key_id: format!(
                    "heimdall:{}:{}:{n}",
                    self.pin.environment.as_str(),
                    grant.as_str()
                ),
                principal: principal_for(&pair("h1")),
                valid_after: t0(),
                valid_before,
                extensions: Default::default(),
                subject_fingerprint: format!("SHA256:{}", "s".repeat(43)),
                ca_fingerprint: None,
            },
            state: IssuanceState::Reserved,
            reserved_at: self.now(),
            settled_at: None,
            void_reason: None,
            continuing: false,
        }
    }

    /// Reserve directly in the ledger, as an issuance before the disconnect did (no barrier:
    /// the history the barrier later reconciles).
    pub fn reserved_earlier(
        &self,
        grant: &GrantId,
        valid_before: Timestamp,
        publish: bool,
    ) -> IssuanceId {
        let entry = self.entry(grant, valid_before);
        let now = self.now();
        self.store
            .transaction(|tx| {
                tx.reserve_issuance(&entry)?;
                if publish {
                    tx.publish_issuance(&entry.id, now)?;
                }
                Ok(())
            })
            .unwrap();
        entry.id
    }

    /// Reserve behind the barrier.
    pub fn reserve(
        &self,
        grant: &GrantId,
        policy: Option<&PolicyId>,
        valid_before: Timestamp,
    ) -> Result<IssuanceId, BarrierRefusal> {
        let entry = self.entry(grant, valid_before);
        let now = self.now();
        self.store
            .transaction(|tx| {
                self.barrier
                    .reserve(tx, &self.pin.environment, policy, &entry, now)
            })
            .unwrap()
            .map(|()| entry.id)
    }

    /// Publish behind the barrier.
    pub fn publish(
        &self,
        id: &IssuanceId,
        policy: Option<&PolicyId>,
    ) -> Result<IssuanceEntry, BarrierRefusal> {
        let now = self.now();
        self.store
            .transaction(|tx| {
                self.barrier
                    .publish(tx, &self.pin.environment, policy, id, now)
            })
            .unwrap()
    }

    pub fn entry_state(&self, id: &IssuanceId) -> IssuanceState {
        self.store
            .transaction(|tx| tx.issuance_entry(id))
            .unwrap()
            .unwrap()
            .state
    }

    pub fn pending(&self) -> usize {
        self.store
            .transaction(|tx| tx.remote_effect_outbox(Some(&self.pin.environment), true))
            .unwrap()
            .len()
    }
}
