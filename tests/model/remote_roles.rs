//! ⟨M06⟩ U1 (m06-plan U1; ADR-0012 §3.2, §3.5, §3.9, §3.10): the invitation state machine,
//! its focused fault test and the runner-side denial cases, through `heimdall-remote`'s
//! production functions over an in-memory store and in-memory authorized_keys files.
//!
//! * `no_sequence_activates_a_dead_invitation`: proptest over {invite, join (correct and
//!   mismatched), expire, revoke, re-invite, crash, clock rollback, reboot, sleep, sync
//!   changes, reconcile}. The oracle is the continuous clock (which a wall-clock change
//!   cannot move): no join activates an invitation that is expired, consumed, revoked or
//!   from another boot; a tombstone never becomes active again; a pending line always
//!   carries the invitation's `expiry-time`; a reconcile pass that writes makes the files
//!   match the database.
//! * `focused_fault_*` (R03, RC-R01): a delayed join past expiry; a wall-clock rollback
//!   between SSH authentication and `join`; a crash between the database commit and the
//!   line rewrite (and one before the commit).
//! * the pending-key rule, the retried join's identity check, the limited-role gate and
//!   `key_already_authorized` at the service level;
//! * the runner-side denial test (T-RA1–T-RA4, the terminal result replay and the
//!   unattended exposure-widening negative case, RC-R03).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use base64ct::{Base64, Encoding as _};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::ids::{
    ClientId, DecisionId, DestinationId, EnvironmentId, IrohEndpointId, KeyFingerprint, RequestId,
    RouteId,
};
use heimdall_contract::remote::{ManagementPolicy, RemoteEnvironmentRequest, Role};
use heimdall_contract::request::{Request, Verdict as DecideVerdict};
use heimdall_contract::route::{
    BindScope, ExposurePolicy, InfrastructureProfile, RouteRequest, RouteSpec, TransportRequest,
};
use heimdall_domain::decision::DecisionState;
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::time::{
    BootId, GateInput, SyncStatus, TimeAnchor, TimePolicy, TimeStatus, gate, next_high_water,
    next_runtime_anchor,
};
use heimdall_remote::Refusal;
use heimdall_remote::invitations::{
    BootReading, Invitations, Invited, JoinRequest, NewInvitation, ProbeRequest, TimeReading,
};
use heimdall_remote::line::{KeysFile, PublicKeyText, ServeCommand, expiry_time, marked_lines};
use heimdall_remote::roles::{ConsentLookup, NoConsents, SessionFrame, Verdict, check};
use heimdall_remote::testing::{MemoryLines, MemoryWidening};
use heimdall_remote::widening::{DecidingSession, Submitted, WideningRecords, decide, submit};
use heimdall_store::ext_m06::{ClientState, InvitationState};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store};
use proptest::prelude::*;

const T0: &str = "2026-11-20T10:00:00Z";
const FIFTEEN_MIN: Duration = Duration::from_secs(15 * 60);

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn plus(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

/// A disposable Ed25519 public key (32 fixed bytes; generated per call, public text only).
fn key(n: u32) -> (String, KeyFingerprint) {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&n.to_be_bytes());
    k[31] = 0x5a;
    blob.extend_from_slice(&k);
    let text = format!("ssh-ed25519 {}", Base64::encode_string(&blob));
    let fp = PublicKeyText::parse(&text).unwrap().fingerprint();
    (text, fp)
}

/// A store fault hook that fails the next commit once when armed.
#[derive(Debug, Default)]
struct FailNextCommit(AtomicBool);

impl FaultHook for FailNextCommit {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point == FaultPoint::BeforeCommit && self.0.swap(false, Ordering::SeqCst) {
            FaultAction::Fail
        } else {
            FaultAction::Continue
        }
    }
}

/// The virtual clocks: a manipulable wall clock, the continuous clock (the oracle) and the
/// boot.
#[derive(Debug, Clone)]
struct Clock {
    wall: Timestamp,
    continuous: Duration,
    boot: u64,
}

impl Clock {
    fn anchor(&self) -> TimeAnchor {
        TimeAnchor {
            boot_id: BootId(format!("boot-{}", self.boot)),
            continuous: self.continuous,
            wall: self.wall,
        }
    }
}

/// The shared time gate as `heimdall_app::TimeGate::check` runs it (the pure domain rules,
/// persisting the anchor and high-water mark on `Safe`).
#[derive(Debug, Clone)]
struct Gate {
    previous: Option<TimeAnchor>,
    high_water: Option<Timestamp>,
    sync: SyncStatus,
    policy: TimePolicy,
}

impl Gate {
    fn new() -> Self {
        Self {
            previous: None,
            high_water: None,
            sync: SyncStatus::Synchronized,
            policy: TimePolicy::default(),
        }
    }

    fn read(&mut self, clock: &Clock) -> TimeReading {
        let now = clock.anchor();
        let status = gate(&GateInput {
            previous: self.previous.as_ref(),
            high_water: self.high_water,
            now: &now,
            sync: self.sync,
            confirmation: None,
            policy: &self.policy,
        });
        match status {
            TimeStatus::Safe => {
                self.high_water = Some(next_high_water(self.high_water, now.wall));
                self.previous = Some(next_runtime_anchor(self.previous.as_ref(), &now, self.sync));
                TimeReading::safe(&now)
            }
            TimeStatus::Uncertain(_) => TimeReading::uncertain(Some(BootReading {
                boot_id: now.boot_id,
                continuous: now.continuous,
            })),
        }
    }
}

/// The clock the invitation service reads at a join's commit point: a shared reading that
/// `World::svc` refreshes from the world's clock, and that a test may move while a call is
/// paused.
#[derive(Debug)]
struct LiveClock(std::sync::Mutex<TimeAnchor>);

impl LiveClock {
    fn set(&self, a: TimeAnchor) {
        *self.0.lock().unwrap() = a;
    }

    fn get(&self) -> TimeAnchor {
        self.0.lock().unwrap().clone()
    }
}

impl heimdall_domain::time::Clock for LiveClock {
    fn wall(&self) -> Timestamp {
        self.get().wall
    }
    fn continuous(&self) -> Duration {
        self.get().continuous
    }
    fn boot_id(&self) -> BootId {
        self.get().boot_id
    }
    fn observe(&self) -> TimeAnchor {
        self.get()
    }
}

struct World {
    faults: Arc<FailNextCommit>,
    store: Store,
    lines: MemoryLines,
    env: EnvironmentId,
    cmd: ServeCommand,
    clock: Clock,
    gate: Gate,
    live: LiveClock,
    serial: heimdall_remote::invitations::LineSerial,
}

impl World {
    fn new() -> Self {
        let faults = Arc::new(FailNextCommit::default());
        let store = Store::open_in_memory(Arc::clone(&faults) as Arc<dyn FaultHook>).unwrap();
        Self {
            faults,
            store,
            lines: MemoryLines::default_pair(),
            env: EnvironmentId::from_random_bytes([0xee; 16]),
            cmd: ServeCommand::new("/opt/heimdall/bin/heimdall", "/srv/runner/heimdall").unwrap(),
            clock: Clock {
                wall: ts(T0),
                continuous: Duration::from_secs(5000),
                boot: 1,
            },
            gate: Gate::new(),
            live: LiveClock(std::sync::Mutex::new(TimeAnchor {
                boot_id: BootId("boot-1".into()),
                continuous: Duration::from_secs(5000),
                wall: ts(T0),
            })),
            serial: heimdall_remote::invitations::LineSerial::default(),
        }
    }

    fn svc(&self) -> Invitations<'_> {
        self.live.set(self.clock.anchor());
        Invitations {
            store: &self.store,
            lines: &self.lines,
            environment: &self.env,
            command: &self.cmd,
            clock: &self.live,
            serial: &self.serial,
        }
    }

    fn read(&mut self) -> TimeReading {
        self.gate.read(&self.clock)
    }

    fn advance(&mut self, secs: u64) {
        self.clock.wall = plus(self.clock.wall, i64::try_from(secs).unwrap());
        self.clock.continuous += Duration::from_secs(secs);
    }

    fn invite(&mut self, role: Role, n: u32, policy: ManagementPolicy) -> Result<Invited, Refusal> {
        let (text, fp) = key(n);
        let now = self.read();
        self.svc().invite(
            &NewInvitation {
                role,
                public_key: &text,
                key_fingerprint: &fp,
                lifetime: FIFTEEN_MIN,
            },
            policy,
            &now,
        )
    }

    fn join_req(&self, inv: &Invited) -> JoinRequest {
        JoinRequest {
            environment: self.env.clone(),
            invitation: inv.invitation.invitation.clone(),
            role: inv.invitation.role,
            generation: inv.invitation.generation,
        }
    }

    fn client(&self, c: &ClientId) -> heimdall_store::ext_m06::RemoteClientRecord {
        self.store
            .transaction(|tx| tx.remote_client(c))
            .unwrap()
            .unwrap()
    }

    fn lines_for(&self, c: &ClientId) -> Vec<String> {
        marked_lines(&self.lines.files(), c)
    }

    fn generations(&self) -> (u64, u64) {
        self.store
            .transaction(|tx| {
                Ok((
                    tx.authority_generation()?.0,
                    tx.remote_authority_generation()?,
                ))
            })
            .unwrap()
    }
}

fn inspect() -> Request {
    serde_json::from_str(r#"{"op":"inspect","subject":"capabilities"}"#).unwrap()
}

/// ⟨Gemini R03⟩ An activation probe as it arrives on the wire.
fn wire_probe(environment: &EnvironmentId, nonce: &str) -> Request {
    serde_json::from_value(serde_json::json!({
        "op": "remote_environment",
        "action": "activation_probe",
        "environment": environment,
        "nonce": nonce,
    }))
    .unwrap()
}

/// ⟨Gemini R03⟩ The rev-6.1 golden's activation probe.
fn golden_probe() -> Request {
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/contracts/golden/rev6-requests.golden.json"
    ))
    .unwrap();
    let form = golden["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["kind"] == "remote_environment.activation_probe")
        .unwrap();
    serde_json::from_value(form["json"].clone()).unwrap()
}

// --- the proptest -------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    Invite { owner: bool },
    ReInvite { which: u8 },
    Join { which: u8, wrong: u8 },
    Advance { secs: u16 },
    Sleep { secs: u16 },
    Rollback { secs: u16 },
    Reboot { back: u16 },
    Revoke { which: u8 },
    Expire,
    Reconcile,
    Crash,
    Sync { on: bool },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => any::<bool>().prop_map(|owner| Op::Invite { owner }),
        1 => any::<u8>().prop_map(|which| Op::ReInvite { which }),
        5 => (any::<u8>(), 0u8..8).prop_map(|(which, wrong)| Op::Join {
            which,
            wrong: if wrong > 4 { 0 } else { wrong },
        }),
        3 => (0u16..=1200).prop_map(|secs| Op::Advance { secs }),
        1 => (0u16..=300).prop_map(|secs| Op::Sleep { secs }),
        2 => (1u16..=3600).prop_map(|secs| Op::Rollback { secs }),
        1 => (0u16..=3600).prop_map(|back| Op::Reboot { back }),
        1 => any::<u8>().prop_map(|which| Op::Revoke { which }),
        1 => Just(Op::Expire),
        1 => Just(Op::Reconcile),
        1 => Just(Op::Crash),
        1 => any::<bool>().prop_map(|on| Op::Sync { on }),
    ]
}

/// What the oracle knows of one invitation.
#[derive(Debug, Clone)]
struct Tracked {
    inv: Invited,
    key: u32,
    boot: u64,
    created: Duration,
    bound: Duration,
    revoked: bool,
    swept: bool,
    joined: bool,
}

impl Tracked {
    /// Live by the oracle: never consumed, revoked or swept, same boot, and the continuous
    /// clock (which no wall-clock change moves) inside the bound.
    fn truly_live(&self, clock: &Clock) -> bool {
        !self.joined
            && !self.revoked
            && !self.swept
            && clock.boot == self.boot
            && clock
                .continuous
                .checked_sub(self.created)
                .is_some_and(|e| e < self.bound)
    }
}

fn run(ops: &[Op]) {
    let mut w = World::new();
    let mut tracked: Vec<Tracked> = Vec::new();
    let mut next_key = 1u32;
    let mut crash_next = false;
    for op in ops {
        let crashed = std::mem::take(&mut crash_next);
        w.lines.set_fail_writes(crashed);
        let mut reconciled_cleanly = false;
        match op.clone() {
            Op::Invite { owner } => {
                let role = if owner { Role::Owner } else { Role::Requester };
                let n = next_key;
                next_key += 1;
                let reading_safe = w.gate.clone().read(&w.clock).checked_wall.is_some();
                match w.invite(role, n, ManagementPolicy::Verified) {
                    Ok(inv) => tracked.push(Tracked {
                        inv,
                        key: n,
                        boot: w.clock.boot,
                        created: w.clock.continuous,
                        bound: FIFTEEN_MIN,
                        revoked: false,
                        swept: false,
                        joined: false,
                    }),
                    Err(Refusal::TimeUncertain) => assert!(!reading_safe),
                    Err(e) => panic!("a fresh key's invitation was refused: {e:?}"),
                }
            }
            Op::ReInvite { which } if !tracked.is_empty() => {
                let i = usize::from(which) % tracked.len();
                let prior = tracked[i].clone();
                if let Ok(inv) =
                    w.invite(prior.inv.client.role, prior.key, ManagementPolicy::Verified)
                {
                    // Only a tombstoned holder's key may be invited again.
                    assert_eq!(
                        w.client(&prior.inv.client.client).state,
                        ClientState::Revoked
                    );
                    tracked.push(Tracked {
                        inv,
                        key: prior.key,
                        boot: w.clock.boot,
                        created: w.clock.continuous,
                        bound: FIFTEEN_MIN,
                        revoked: false,
                        swept: false,
                        joined: false,
                    });
                }
            }
            Op::Join { which, wrong } if !tracked.is_empty() => {
                let i = usize::from(which) % tracked.len();
                let t = tracked[i].clone();
                let mut req = w.join_req(&t.inv);
                let mut session = t.inv.client.client.clone();
                match wrong {
                    1 => {
                        req.role = if req.role == Role::Owner {
                            Role::Viewer
                        } else {
                            Role::Owner
                        }
                    }
                    2 => req.generation += 1,
                    3 => {
                        session = if tracked.len() > 1 {
                            tracked[(i + 1) % tracked.len()].inv.client.client.clone()
                        } else {
                            ClientId::from_random_bytes([0x77; 16])
                        }
                    }
                    4 => req.environment = EnvironmentId::from_random_bytes([0x01; 16]),
                    _ => {}
                }
                let now = w.read();
                let live = t.truly_live(&w.clock);
                match w.svc().join(&session, &req, &now) {
                    Ok(j) if !j.replayed => {
                        assert_eq!(wrong, 0, "a mismatched join activated: {j:?}");
                        assert!(
                            live,
                            "a dead invitation was activated: {t:?} at {:?}",
                            w.clock
                        );
                        assert!(now.checked_wall.is_some(), "activated on unchecked time");
                        assert_eq!(j.join.client, t.inv.client.client);
                        tracked[i].joined = true;
                    }
                    Ok(j) => {
                        assert!(t.joined, "a replay of a join that never happened");
                        assert_eq!(session, t.inv.client.client, "a replay to another session");
                        assert_eq!(j.join.invitation, t.inv.invitation.invitation);
                    }
                    Err(r) => {
                        if wrong == 3 && session != t.inv.client.client {
                            assert_eq!(r, Refusal::InvitationExpired, "a mismatch says nothing");
                        }
                    }
                }
            }
            Op::Advance { secs } => w.advance(u64::from(secs)),
            Op::Sleep { secs } => w.clock.continuous += Duration::from_secs(u64::from(secs)),
            Op::Rollback { secs } => w.clock.wall = plus(w.clock.wall, -i64::from(secs)),
            Op::Reboot { back } => {
                w.clock.boot += 1;
                w.clock.continuous = Duration::from_secs(30);
                w.clock.wall = plus(w.clock.wall, 60 - i64::from(back));
            }
            Op::Revoke { which } if !tracked.is_empty() => {
                let i = usize::from(which) % tracked.len();
                let c = tracked[i].inv.client.client.clone();
                let wall = w.clock.wall;
                w.svc().revoke(&c, wall).unwrap();
                tracked[i].revoked = true;
            }
            Op::Expire => {
                let now = w.read();
                for c in w.svc().expire_due(&now).unwrap() {
                    let t = tracked
                        .iter_mut()
                        .find(|t| t.inv.client.client == c)
                        .unwrap();
                    assert!(!t.joined, "a consumed invitation was swept");
                    t.swept = true;
                }
            }
            Op::Reconcile => {
                let now = w.read();
                let report = w.svc().reconcile(&now).unwrap();
                reconciled_cleanly = !crashed && report.failed == 0;
            }
            Op::Crash => crash_next = true,
            Op::Sync { on } => {
                w.gate.sync = if on {
                    SyncStatus::Synchronized
                } else {
                    SyncStatus::Unknown
                };
            }
            _ => {}
        }
        w.lines.set_fail_writes(false);

        // Invariants after every step.
        let files = w.lines.files();
        for t in &tracked {
            let rec = w.client(&t.inv.client.client);
            let inv = w
                .store
                .transaction(|tx| tx.remote_invitation(&t.inv.invitation.invitation))
                .unwrap()
                .unwrap();
            if t.revoked || t.swept {
                assert_eq!(
                    rec.state,
                    ClientState::Revoked,
                    "a tombstone came back: {t:?}"
                );
            }
            if rec.state == ClientState::Active {
                assert!(t.joined, "active without a join: {t:?}");
                assert_eq!(inv.state, InvitationState::Consumed);
                assert!(inv.join.is_some());
            }
            if inv.state == InvitationState::Consumed {
                assert!(t.joined, "consumed without the oracle's join");
            }
            if rec.state != ClientState::Active {
                assert!(
                    matches!(
                        check(Some(&rec), SessionFrame::Request(&inspect()), &NoConsents),
                        Verdict::Refuse(_)
                    ),
                    "a non-active client was admitted: {rec:?}"
                );
            }
            let lines = marked_lines(&files, &t.inv.client.client);
            if rec.state == ClientState::Pending {
                let want = format!("expiry-time=\"{}\"", expiry_time(inv.expires_wall).unwrap());
                for l in &lines {
                    assert!(l.contains(&want), "a pending line without its expiry: {l}");
                }
            }
            if reconciled_cleanly {
                match rec.state {
                    ClientState::Revoked => assert!(lines.is_empty(), "a tombstone kept its line"),
                    ClientState::Active => {
                        assert_eq!(lines.len(), 1);
                        assert!(!lines[0].contains("expiry-time"));
                    }
                    ClientState::Pending => assert!(lines.len() <= 1),
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// No sequence of {invite, join, expire, revoke, re-invite, crash, clock rollback,
    /// reboot} reaches `active` for an expired, consumed or revoked record (module docs).
    #[test]
    fn no_sequence_activates_a_dead_invitation(ops in proptest::collection::vec(op(), 1..48)) {
        run(&ops);
    }
}

// --- the focused fault test (R03, RC-R01) --------------------------------------------------

/// A delayed `join` past expiry is refused, by the elapsed bound and by the wall deadline,
/// at exactly the bound; one second earlier it is live.
#[test]
fn focused_fault_delayed_join_past_expiry() {
    let mut w = World::new();
    let late = w
        .invite(Role::Owner, 1, ManagementPolicy::OwnerOnly)
        .unwrap();
    let early = w
        .invite(Role::Owner, 2, ManagementPolicy::OwnerOnly)
        .unwrap();
    w.advance(FIFTEEN_MIN.as_secs() - 1);
    let now = w.read();
    let j = w
        .svc()
        .join(&early.client.client, &w.join_req(&early), &now)
        .unwrap();
    assert!(!j.replayed);
    w.advance(1);
    let now = w.read();
    assert_eq!(
        w.svc().join(&late.client.client, &w.join_req(&late), &now),
        Err(Refusal::InvitationExpired)
    );
    assert_eq!(w.client(&late.client.client).state, ClientState::Pending);
    // The sweep tombstones it; the session is then refused everything.
    assert_eq!(
        w.svc().expire_due(&now).unwrap(),
        vec![late.client.client.clone()]
    );
    let rec = w.client(&late.client.client);
    assert_eq!(rec.state, ClientState::Revoked);
    assert_eq!(
        check(
            Some(&rec),
            SessionFrame::Request(&wire_probe(&w.env, &late.invitation.probe_nonce)),
            &NoConsents
        ),
        Verdict::Refuse(Refusal::InvitationExpired)
    );
    assert!(w.lines_for(&late.client.client).is_empty());
}

/// A wall-clock rollback between SSH authentication and `join`: the session authenticated
/// while sshd's `expiry-time` still held, the wall clock was then set back, and the join
/// arrives after the elapsed bound. Refused whether or not the gate accepts the
/// rolled-back wall clock: the elapsed bound runs on the continuous clock.
#[test]
fn focused_fault_wall_clock_rollback_between_authentication_and_join() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 1, ManagementPolicy::OwnerOnly)
        .unwrap();
    // SSH authentication at +10 min: before `expiry-time`, so sshd lets the key in.
    w.advance(600);
    let auth_wall = w.clock.wall;
    assert!(auth_wall < inv.invitation.expires_wall);
    // The wall clock is rolled back by 30 min; six more minutes pass in truth.
    w.clock.wall = plus(w.clock.wall, -1800);
    w.clock.continuous += Duration::from_secs(360);
    w.clock.wall = plus(w.clock.wall, 360);
    assert!(
        w.clock.wall < inv.invitation.expires_wall,
        "the wall deadline alone would pass"
    );
    // (a) Through the shared gate: the rollback is uncertain time, refused.
    let gated = w.read();
    assert!(gated.checked_wall.is_none());
    assert_eq!(
        w.svc().join(&inv.client.client, &w.join_req(&inv), &gated),
        Err(Refusal::InvitationExpired)
    );
    // (b) Even if the rolled-back wall clock were accepted as checked: the elapsed bound
    // from the same boot anchor has passed.
    let accepted = TimeReading::safe(&w.clock.anchor());
    assert_eq!(
        w.svc()
            .join(&inv.client.client, &w.join_req(&inv), &accepted),
        Err(Refusal::InvitationExpired)
    );
    // (c) A reboot loses the anchor: refused even with the wall clock inside the deadline.
    let mut rebooted = w.clock.clone();
    rebooted.boot += 1;
    rebooted.continuous = Duration::from_secs(10);
    assert_eq!(
        w.svc().join(
            &inv.client.client,
            &w.join_req(&inv),
            &TimeReading::safe(&rebooted.anchor())
        ),
        Err(Refusal::InvitationExpired)
    );
    assert_eq!(w.client(&inv.client.client).state, ClientState::Pending);
}

/// A crash between the database commit and the line rewrite: the join is committed, the
/// pending line keeps its `expiry-time` (fail closed), the retried join returns the
/// recorded result after its identity check and the reconciler rewrites the line. A crash
/// before the commit persists nothing. A revocation whose line removal fails stays refused.
#[test]
fn focused_fault_crash_between_commit_and_line_rewrite() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 1, ManagementPolicy::OwnerOnly)
        .unwrap();
    assert!(inv.line_written);
    let c = inv.client.client.clone();
    w.advance(60);

    // Before the commit: nothing persists.
    w.faults.0.store(true, Ordering::SeqCst);
    let now = w.read();
    assert_eq!(
        w.svc().join(&c, &w.join_req(&inv), &now),
        Err(Refusal::State)
    );
    assert_eq!(w.client(&c).state, ClientState::Pending);

    // Between the commit and the rewrite.
    w.lines.set_fail_writes(true);
    let now = w.read();
    let j = w.svc().join(&c, &w.join_req(&inv), &now).unwrap();
    assert!(!j.replayed && !j.line_written);
    w.lines.set_fail_writes(false);
    assert_eq!(w.client(&c).state, ClientState::Active);
    let lines = w.lines_for(&c);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("expiry-time="),
        "the pending backstop stays until reconciled"
    );

    // The lost reply: the retried join returns the recorded result and rewrites the line.
    w.advance(30);
    let now = w.read();
    let again = w.svc().join(&c, &w.join_req(&inv), &now).unwrap();
    assert!(again.replayed && again.line_written);
    assert_eq!(again.join, j.join);
    let lines = w.lines_for(&c);
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].contains("expiry-time"));
    assert_eq!(w.svc().reconcile(&now).unwrap().changed, 0, "idempotent");

    // Ordinary connections consume nothing.
    let before = w.generations();
    for _ in 0..3 {
        let rec = w.client(&c);
        assert!(matches!(
            check(Some(&rec), SessionFrame::Request(&inspect()), &NoConsents),
            Verdict::Dispatch { .. }
        ));
        let probe = ProbeRequest {
            environment: w.env.clone(),
            nonce: inv.invitation.probe_nonce.clone(),
        };
        w.svc().probe(&c, &probe, &now).unwrap();
    }
    assert_eq!(w.generations(), before);

    // A revocation whose line removal fails: the tombstone is authoritative.
    w.lines.set_fail_writes(true);
    let r = w.svc().revoke(&c, w.clock.wall).unwrap();
    w.lines.set_fail_writes(false);
    assert!(!r.line_removed);
    assert_eq!(w.lines_for(&c).len(), 1, "the line is still there");
    let rec = w.client(&c);
    assert_eq!(
        check(Some(&rec), SessionFrame::Request(&inspect()), &NoConsents),
        Verdict::Refuse(Refusal::ClientRevoked)
    );
    let now = w.read();
    assert_eq!(
        w.svc().join(&c, &w.join_req(&inv), &now),
        Err(Refusal::ClientRevoked)
    );
    assert_eq!(w.svc().reconcile(&now).unwrap().changed, 1);
    assert!(w.lines_for(&c).is_empty());
}

// --- the service-level unit cases -----------------------------------------------------------

/// A pending key's session reaches only the activation probe and `join`.
#[test]
fn pending_key_reaches_only_probe_and_join() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Requester, 1, ManagementPolicy::Verified)
        .unwrap();
    let c = inv.client.client.clone();
    let rec = w.client(&c);
    assert_eq!(rec.state, ClientState::Pending);
    for frame in [
        SessionFrame::Request(&inspect()),
        SessionFrame::Subscribe,
        SessionFrame::Attend,
    ] {
        assert_eq!(
            check(Some(&rec), frame, &NoConsents),
            Verdict::Refuse(Refusal::InvitationPending)
        );
    }
    // ⟨Gemini R03⟩ The wire probe (deserialized) reaches the probe, which checks this
    // runner's environment, the pending record's nonce and liveness.
    let probe = wire_probe(&w.env, &inv.invitation.probe_nonce);
    assert_eq!(
        check(Some(&rec), SessionFrame::Request(&probe), &NoConsents),
        Verdict::Probe
    );
    let now = w.read();
    let fields = ProbeRequest::from_request(&probe).unwrap();
    let echo = w.svc().probe(&c, &fields, &now).unwrap();
    assert_eq!(echo.client, c);
    assert_eq!(echo.nonce, inv.invitation.probe_nonce);
    let golden = ProbeRequest::from_request(&golden_probe()).unwrap();
    assert_eq!(
        w.svc().probe(&c, &golden, &now),
        Err(Refusal::BindingMismatch),
        "the golden names another environment"
    );
    let other_runner = ProbeRequest::from_request(&wire_probe(
        &EnvironmentId::from_random_bytes([0x0d; 16]),
        &inv.invitation.probe_nonce,
    ))
    .unwrap();
    assert_eq!(
        w.svc().probe(&c, &other_runner, &now),
        Err(Refusal::BindingMismatch),
        "the right nonce for another runner"
    );
    let wrong_nonce = ProbeRequest::from_request(&wire_probe(&w.env, "not-the-nonce")).unwrap();
    assert_eq!(
        w.svc().probe(&c, &wrong_nonce, &now),
        Err(Refusal::BindingMismatch)
    );
    let join = Request::RemoteEnvironment(RemoteEnvironmentRequest::Join {
        environment: w.env.clone(),
        invitation: inv.invitation.invitation.clone(),
        role: Role::Requester,
        generation: inv.invitation.generation,
    });
    assert_eq!(
        check(Some(&rec), SessionFrame::Request(&join), &NoConsents),
        Verdict::Join
    );
    let now = w.read();
    let req = JoinRequest::from_request(&join).unwrap();
    w.svc().join(&c, &req, &now).unwrap();
    let rec = w.client(&c);
    assert!(matches!(
        check(Some(&rec), SessionFrame::Request(&inspect()), &NoConsents),
        Verdict::Dispatch {
            role: Role::Requester,
            ..
        }
    ));
}

/// A retried `join` checks identity (the argv cid, the invitation ID and the key on the
/// cid's line) before it returns the recorded result; a mismatch says nothing about it.
#[test]
fn retried_join_checks_identity_before_the_recorded_result() {
    let mut w = World::new();
    let a = w
        .invite(Role::Owner, 1, ManagementPolicy::OwnerOnly)
        .unwrap();
    let b = w
        .invite(Role::Owner, 2, ManagementPolicy::OwnerOnly)
        .unwrap();
    let now = w.read();
    let first = w
        .svc()
        .join(&a.client.client, &w.join_req(&a), &now)
        .unwrap();
    // Another pending client replays a's join: nothing about a's record.
    assert_eq!(
        w.svc().join(&b.client.client, &w.join_req(&a), &now),
        Err(Refusal::InvitationExpired)
    );
    // An unknown invitation answers the same.
    let mut unknown = w.join_req(&a);
    unknown.invitation = heimdall_contract::ids::InvitationId::from_random_bytes([0x42; 16]);
    assert_eq!(
        w.svc().join(&a.client.client, &unknown, &now),
        Err(Refusal::InvitationExpired)
    );
    // a's line now carries another key (a user's edit): the identity no longer matches.
    let files = w.lines.files();
    let (other, _) = key(99);
    let swapped: Vec<KeysFile> = files
        .iter()
        .map(|f| KeysFile {
            name: f.name.clone(),
            text: f.text.replace(&a.client.public_key, &other),
        })
        .collect();
    let edited = MemoryLines::new(swapped);
    let svc = Invitations {
        lines: &edited,
        ..w.svc()
    };
    assert_eq!(
        svc.join(&a.client.client, &w.join_req(&a), &now),
        Err(Refusal::InvitationExpired)
    );
    // The right identity gets the recorded result.
    let again = w
        .svc()
        .join(&a.client.client, &w.join_req(&a), &now)
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.join, first.join);
    // The right identity with another role: consumed, not replayed.
    let mut other_role = w.join_req(&a);
    other_role.role = Role::Viewer;
    assert_eq!(
        w.svc().join(&a.client.client, &other_role, &now),
        Err(Refusal::InvitationConsumed)
    );
    // A pending invitation joined with the wrong generation: a binding mismatch, and the
    // invitation stays joinable.
    let mut wrong_gen = w.join_req(&b);
    wrong_gen.generation += 1;
    assert_eq!(
        w.svc().join(&b.client.client, &wrong_gen, &now),
        Err(Refusal::BindingMismatch)
    );
    assert!(
        w.svc()
            .join(&b.client.client, &w.join_req(&b), &now)
            .is_ok()
    );
}

/// Limited roles need a verified sshd policy; owners do not. A key already authorized
/// under another line, in either authorized_keys file, or held by a live client, is
/// refused. A key that does not match the confirmed fingerprint is a binding mismatch.
#[test]
fn invitation_gates() {
    let mut w = World::new();
    for role in [Role::Requester, Role::Viewer] {
        assert_eq!(
            w.invite(role, 1, ManagementPolicy::OwnerOnly).map(|_| ()),
            Err(Refusal::ManagementSshdUnverified)
        );
    }
    assert!(
        w.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .is_empty(),
        "nothing was written"
    );
    let (k2, _) = key(2);
    w.lines.append(1, &format!("no-pty {k2} user@laptop"));
    assert_eq!(
        w.invite(Role::Owner, 2, ManagementPolicy::OwnerOnly)
            .map(|_| ()),
        Err(Refusal::KeyAlreadyAuthorized)
    );
    w.invite(Role::Owner, 3, ManagementPolicy::OwnerOnly)
        .unwrap();
    assert_eq!(
        w.invite(Role::Owner, 3, ManagementPolicy::OwnerOnly)
            .map(|_| ()),
        Err(Refusal::KeyAlreadyAuthorized)
    );
    let (k4, _) = key(4);
    let (_, fp5) = key(5);
    let now = w.read();
    assert_eq!(
        w.svc()
            .invite(
                &NewInvitation {
                    role: Role::Owner,
                    public_key: &k4,
                    key_fingerprint: &fp5,
                    lifetime: FIFTEEN_MIN,
                },
                ManagementPolicy::OwnerOnly,
                &now,
            )
            .map(|_| ()),
        Err(Refusal::BindingMismatch)
    );
    // Uncertain time creates nothing.
    w.clock.wall = plus(w.clock.wall, -3600);
    assert_eq!(
        w.invite(Role::Owner, 6, ManagementPolicy::OwnerOnly)
            .map(|_| ()),
        Err(Refusal::TimeUncertain)
    );
}

// --- the runner-side denial test (T-RA1–T-RA4, RC-R03) --------------------------------------

fn rid(s: &str) -> RequestId {
    RequestId::parse(s).unwrap()
}

fn dest() -> DestinationId {
    DestinationId::parse("dest-1").unwrap()
}

fn invite_req(id: &str) -> Request {
    Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite {
        environment: EnvironmentId::from_random_bytes([0xee; 16]),
        role: Role::Requester,
        key_fingerprint: key(7).1,
        public_key: key(7).0,
        request_id: rid(id),
    })
}

fn route_add(id: &str) -> Request {
    Request::Route(RouteRequest::Add {
        destination: dest(),
        route: RouteSpec::Direct {
            host: "runner.example".into(),
            port: None,
        },
        exposure: None,
        request_id: rid(id),
    })
}

fn enable(id: &str, serve: bool, exposure: Option<ExposurePolicy>) -> Request {
    Request::Transport(TransportRequest::Enable {
        serve,
        exposure,
        request_id: rid(id),
    })
}

fn adopt(id: &str) -> Request {
    Request::Transport(TransportRequest::AdoptRoost {
        destination: dest(),
        endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
        exposure: None,
        request_id: rid(id),
    })
}

fn prefer(id: &str) -> Request {
    Request::Route(RouteRequest::Prefer {
        destination: dest(),
        route: RouteId::from_random_bytes([3; 16]),
        request_id: Some(rid(id)),
    })
}

fn relays() -> ExposurePolicy {
    ExposurePolicy {
        infrastructure: InfrastructureProfile::Custom {
            relays: vec!["https://relay.example".into()],
        },
        ..ExposurePolicy::default()
    }
}

fn wildcard() -> ExposurePolicy {
    ExposurePolicy {
        bind: BindScope::Wildcard,
        ..ExposurePolicy::default()
    }
}

fn json(s: &str) -> Request {
    serde_json::from_str(s).unwrap()
}

fn active(role: Role) -> heimdall_store::ext_m06::RemoteClientRecord {
    let mut w = World::new();
    let inv = w.invite(role, 1, ManagementPolicy::Verified).unwrap();
    let now = w.read();
    w.svc()
        .join(&inv.client.client, &w.join_req(&inv), &now)
        .unwrap();
    w.client(&inv.client.client)
}

struct Consented;

impl ConsentLookup for Consented {
    fn preference_consented(&self, _: &DestinationId, _: &RouteId) -> bool {
        true
    }
}

/// T-RA1 and RC-R03: an unattended paired owner's widening request, including new
/// exposure (a new relay set, a broader bind, serving, roost adoption) and route approval,
/// stays a pending record; nothing executes. The minimal-exposure enable and a consented
/// preference change are not widenings (positive controls).
#[test]
fn t_ra1_owner_widening_stays_pending_including_exposure() {
    let owner = active(Role::Owner);
    let ledger = MemoryWidening::new();
    let now = ts(T0);
    let widening = [
        invite_req("r-invite"),
        route_add("r-route"),
        prefer("r-prefer"),
        enable("r-relays", false, Some(relays())),
        enable("r-wildcard", false, Some(wildcard())),
        enable("r-serve", true, None),
        adopt("r-roost"),
    ];
    for req in &widening {
        assert_eq!(
            check(Some(&owner), SessionFrame::Request(req), &NoConsents),
            Verdict::PendingRunnerLocal { role: Role::Owner },
            "{req:?}"
        );
        let (s, answer) = submit(&ledger, &owner.client, req, AuthorityGeneration(1), now).unwrap();
        assert!(matches!(s, Submitted::Created(_)));
        assert_eq!(answer.code, Code::ApprovalRequired);
        let next = answer.next.unwrap();
        assert!(next.decision_ref.unwrap().starts_with("dec_"));
    }
    assert_eq!(ledger.all().len(), widening.len());
    assert!(
        ledger
            .all()
            .iter()
            .all(|r| r.state == DecisionState::Pending && r.result.is_none())
    );
    // Positive controls.
    for req in [
        enable("r-min", false, None),
        enable("r-min2", false, Some(ExposurePolicy::default())),
    ] {
        assert!(matches!(
            check(Some(&owner), SessionFrame::Request(&req), &NoConsents),
            Verdict::Dispatch { .. }
        ));
    }
    assert!(matches!(
        check(
            Some(&owner),
            SessionFrame::Request(&prefer("r-p2")),
            &Consented
        ),
        Verdict::Dispatch { .. }
    ));
    // The widening policy actions reach only the application's decision record path.
    let resume = json(r#"{"op":"policy","action":"resume","policy_id":"p"}"#);
    assert!(matches!(
        check(Some(&owner), SessionFrame::Request(&resume), &NoConsents),
        Verdict::Dispatch { class: Some(c), .. } if c.effect == heimdall_remote::roles::Effect::WidenViaDecision
    ));
}

/// T-RA2: `Decide`, `confirm_time` and `Attend` from a paired session are refused before
/// dispatch; a runner-local record cannot be decided from a paired or unattended session.
#[test]
fn t_ra2_decide_and_attend_refused_before_dispatch() {
    let owner = active(Role::Owner);
    for frame in [
        SessionFrame::Request(&json(
            r#"{"op":"decide","decision_id":"dec_00","verdict":"approve"}"#,
        )),
        SessionFrame::Request(&json(
            r#"{"op":"confirm_time","observed_wall":"2026-11-20T10:00:00Z"}"#,
        )),
        SessionFrame::Request(&json(r#"{"op":"device","action":"retire"}"#)),
        SessionFrame::Attend,
    ] {
        assert_eq!(
            check(Some(&owner), frame, &NoConsents),
            Verdict::Refuse(Refusal::InteractionRequired)
        );
    }
    let ledger = MemoryWidening::new();
    let now = ts(T0);
    let (Submitted::Created(id), _) = submit(
        &ledger,
        &owner.client,
        &route_add("r1"),
        AuthorityGeneration(1),
        now,
    )
    .unwrap() else {
        panic!("created");
    };
    let ran = AtomicUsize::new(0);
    for session in [
        DecidingSession {
            remote_client: Some(&owner.client),
            attended: true,
        },
        DecidingSession {
            remote_client: None,
            attended: false,
        },
    ] {
        let r = decide(
            &ledger,
            session,
            &id,
            DecideVerdict::Approve,
            AuthorityGeneration(1),
            now,
            |_| {
                ran.fetch_add(1, Ordering::SeqCst);
                heimdall_contract::envelope::Envelope::ok(serde_json::json!({}))
            },
        );
        assert_eq!(r, Err(Refusal::InteractionRequired));
    }
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(
        ledger.by_decision(&id).unwrap().unwrap().state,
        DecisionState::Pending
    );
}

/// T-RA3: after a runner-local decision, the replayed request returns the recorded
/// terminal result with no new record and no re-execution; a different request under the
/// same ID is a conflict; a denial and a stale record replay their own results.
#[test]
fn t_ra3_terminal_result_replay() {
    let owner = active(Role::Owner);
    let ledger = MemoryWidening::new();
    let now = ts(T0);
    let local = DecidingSession {
        remote_client: None,
        attended: true,
    };
    let req = adopt("r-adopt");
    let (Submitted::Created(id), pending) =
        submit(&ledger, &owner.client, &req, AuthorityGeneration(4), now).unwrap()
    else {
        panic!("created");
    };
    // A replay while pending: the same reference, no new record.
    let (s, again) = submit(&ledger, &owner.client, &req, AuthorityGeneration(4), now).unwrap();
    assert_eq!(s, Submitted::Replayed(id.clone()));
    assert_eq!(again, pending);
    assert_eq!(ledger.all().len(), 1);

    let ran = AtomicUsize::new(0);
    let result = decide(
        &ledger,
        local,
        &id,
        DecideVerdict::Approve,
        AuthorityGeneration(4),
        plus(now, 30),
        |r| {
            assert_eq!(r.request, req, "the recorded request, exactly");
            ran.fetch_add(1, Ordering::SeqCst);
            heimdall_contract::envelope::Envelope::ok(serde_json::json!({"route": "route_01"}))
        },
    )
    .unwrap();
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    for _ in 0..2 {
        let (s, replay) = submit(
            &ledger,
            &owner.client,
            &req,
            AuthorityGeneration(9),
            plus(now, 60),
        )
        .unwrap();
        assert_eq!(s, Submitted::Replayed(id.clone()));
        assert_eq!(replay, result);
    }
    assert_eq!(ledger.all().len(), 1, "no new record");
    // Deciding again is stale; nothing re-executes.
    assert_eq!(
        decide(
            &ledger,
            local,
            &id,
            DecideVerdict::Approve,
            AuthorityGeneration(4),
            plus(now, 61),
            |_| {
                ran.fetch_add(1, Ordering::SeqCst);
                heimdall_contract::envelope::Envelope::ok(serde_json::json!({}))
            }
        ),
        Err(Refusal::DecisionStale)
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    // The same request ID with other content.
    let mut other = adopt("r-adopt");
    if let Request::Transport(TransportRequest::AdoptRoost { exposure, .. }) = &mut other {
        *exposure = Some(relays());
    }
    assert_eq!(
        submit(&ledger, &owner.client, &other, AuthorityGeneration(9), now).map(|_| ()),
        Err(Refusal::RequestConflict)
    );
    // Another client's identical request ID is a different key.
    let other_client = ClientId::from_random_bytes([0x99; 16]);
    assert!(matches!(
        submit(&ledger, &other_client, &req, AuthorityGeneration(9), now)
            .unwrap()
            .0,
        Submitted::Created(_)
    ));
    // A denial replays as the denial.
    let deny_req = route_add("r-deny");
    let (Submitted::Created(deny_id), _) = submit(
        &ledger,
        &owner.client,
        &deny_req,
        AuthorityGeneration(4),
        now,
    )
    .unwrap() else {
        panic!("created");
    };
    let denied = decide(
        &ledger,
        local,
        &deny_id,
        DecideVerdict::Deny,
        AuthorityGeneration(4),
        now,
        |_| panic!("a denial never executes"),
    )
    .unwrap();
    assert_eq!(denied.code, Code::CapabilityUnavailable);
    assert_eq!(
        submit(
            &ledger,
            &owner.client,
            &deny_req,
            AuthorityGeneration(4),
            now
        )
        .unwrap()
        .1,
        denied
    );
    // A record issued under an older generation is stale, and replays as stale.
    let stale_req = invite_req("r-stale");
    let (Submitted::Created(stale_id), _) = submit(
        &ledger,
        &owner.client,
        &stale_req,
        AuthorityGeneration(4),
        now,
    )
    .unwrap() else {
        panic!("created");
    };
    assert_eq!(
        decide(
            &ledger,
            local,
            &stale_id,
            DecideVerdict::Approve,
            AuthorityGeneration(5),
            now,
            |_| { panic!("a stale record never executes") }
        ),
        Err(Refusal::DecisionStale)
    );
    assert_eq!(
        ledger.by_decision(&stale_id).unwrap().unwrap().state,
        DecisionState::Stale
    );
    assert_eq!(
        submit(
            &ledger,
            &owner.client,
            &stale_req,
            AuthorityGeneration(5),
            now
        )
        .unwrap()
        .1
        .code,
        Code::DecisionStale
    );
    // A claimed record whose result was never recorded (a crash in between) replays as
    // OUTCOME_UNKNOWN and never runs again.
    let lost_req = route_add("r-lost");
    let (Submitted::Created(lost_id), _) = submit(
        &ledger,
        &owner.client,
        &lost_req,
        AuthorityGeneration(4),
        now,
    )
    .unwrap() else {
        panic!("created");
    };
    ledger
        .settle(&lost_id, DecisionState::Approved, now, None)
        .unwrap();
    assert_eq!(
        submit(
            &ledger,
            &owner.client,
            &lost_req,
            AuthorityGeneration(4),
            now
        )
        .unwrap()
        .1
        .code,
        Code::OutcomeUnknown
    );
    let _: DecisionId = lost_id;
}

/// T-RA4: a limited client's widening request is `role_insufficient`, before any record.
#[test]
fn t_ra4_limited_widening_is_role_insufficient() {
    let ensure: Request =
        serde_json::from_str(include_str!("../../schemas/examples/request.ensure.json")).unwrap();
    for role in [Role::Requester, Role::Viewer] {
        let limited = active(role);
        for req in [
            invite_req("r1"),
            route_add("r2"),
            enable("r3", false, Some(relays())),
            adopt("r4"),
            json(r#"{"op":"policy","action":"resume","policy_id":"p"}"#),
            json(r#"{"op":"policy","action":"pause","policy_id":"p"}"#),
            json(
                r#"{"op":"remote_environment","action":"revoke_client","environment":"env_00","client":"cl_00"}"#,
            ),
        ] {
            assert_eq!(
                check(Some(&limited), SessionFrame::Request(&req), &NoConsents),
                Verdict::Refuse(Refusal::RoleInsufficient),
                "{role:?} {req:?}"
            );
        }
        // An ensure beyond standing policy: the application's approval path refuses a
        // limited caller (the model function it calls).
        assert_eq!(
            heimdall_remote::roles::approval_needed(role),
            Err(Refusal::RoleInsufficient)
        );
        let verdict = check(Some(&limited), SessionFrame::Request(&ensure), &NoConsents);
        match role {
            Role::Viewer => assert_eq!(verdict, Verdict::Refuse(Refusal::RoleInsufficient)),
            _ => assert!(matches!(verdict, Verdict::Dispatch { .. })),
        }
    }
}

// --- W0 review fixes (M06-W0-R07, reading 16) -------------------------------------------------

/// ⟨M06-W0-R07⟩ The runner recomputes the fingerprint of `Invite.public_key`: a mismatched
/// key and fingerprint (or a key that is not one Ed25519 key) yields no runner-local record,
/// so no decision capable of enrollment and no line. A matching invite's record binds the
/// exact (canonical) key and the role, and the approved executor enrolls exactly those.
#[test]
fn invite_decision_binds_the_exact_key_and_role() {
    let owner = active(Role::Owner);
    let ledger = MemoryWidening::new();
    let now = ts(T0);
    let mismatched = |public_key: String| {
        Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite {
            environment: EnvironmentId::from_random_bytes([0xee; 16]),
            role: Role::Requester,
            key_fingerprint: key(7).1,
            public_key,
            request_id: rid("r-mismatch"),
        })
    };
    for bad in [
        key(8).0,
        "ssh-rsa AAAAB3NzaC1yc2E".to_owned(),
        String::new(),
    ] {
        assert_eq!(
            submit(
                &ledger,
                &owner.client,
                &mismatched(bad),
                AuthorityGeneration(1),
                now
            )
            .map(|_| ()),
            Err(Refusal::BindingMismatch)
        );
    }
    assert!(ledger.all().is_empty(), "no decision exists");

    // A matching invite (with a comment and the key re-padded) binds the canonical key.
    let mut w = World::new();
    let (text, fp) = key(7);
    let req = Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite {
        environment: w.env.clone(),
        role: Role::Viewer,
        key_fingerprint: fp.clone(),
        public_key: format!("{} new-device", text.trim_end_matches('=')),
        request_id: rid("r-bound"),
    });
    let (Submitted::Created(id), _) =
        submit(&ledger, &owner.client, &req, AuthorityGeneration(1), now).unwrap()
    else {
        panic!("created");
    };
    let rec = ledger.by_decision(&id).unwrap().unwrap();
    let bound = rec.invite.clone().unwrap();
    assert_eq!(bound.role, Role::Viewer);
    assert_eq!(bound.public_key, text, "the canonical key, no comment");
    assert_eq!(bound.key_fingerprint, fp);
    assert!(
        w.lines.files().iter().all(|f| f.text.is_empty()),
        "no line before approval"
    );

    // The runner-local approval enrolls exactly the bound key and role.
    let local = DecidingSession {
        remote_client: None,
        attended: true,
    };
    let reading = w.read();
    let mut invited = None;
    decide(
        &ledger,
        local,
        &id,
        DecideVerdict::Approve,
        AuthorityGeneration(1),
        now,
        |r| {
            let b = r
                .invite
                .as_ref()
                .expect("an invite record carries its binding");
            invited = Some(
                w.svc()
                    .invite_bound(b, ManagementPolicy::Verified, &reading)
                    .unwrap(),
            );
            heimdall_contract::envelope::Envelope::ok(serde_json::json!({}))
        },
    )
    .unwrap();
    let invited = invited.unwrap();
    assert_eq!(invited.client.role, Role::Viewer);
    assert_eq!(invited.client.public_key, text);
    assert_eq!(invited.client.key_fingerprint, fp);
    let lines = w.lines_for(&invited.client.client);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains(&text));
    // The service itself refuses a mismatched binding too: nothing is enrolled.
    let forged = heimdall_remote::widening::InviteBinding {
        role: Role::Owner,
        public_key: key(9).0,
        key_fingerprint: fp,
    };
    let before = w.lines.files();
    let reading = w.read();
    assert_eq!(
        w.svc()
            .invite_bound(&forged, ManagementPolicy::Verified, &reading)
            .map(|_| ()),
        Err(Refusal::BindingMismatch)
    );
    assert_eq!(w.lines.files(), before);
}

/// ⟨Reading 16, amended⟩ Key uniqueness is scoped per runner and its role table: one
/// runner refuses a key a live client of its own holds, while another runner (its own store
/// and authorized_keys files) enrolls the same key; a tombstoned holder's key may be
/// invited again once its line is gone.
#[test]
fn key_uniqueness_is_per_runner_and_role_table() {
    let mut runner1 = World::new();
    let mut runner2 = World::new();
    let first = runner1
        .invite(Role::Owner, 42, ManagementPolicy::OwnerOnly)
        .unwrap();
    assert_eq!(
        runner1
            .invite(Role::Owner, 42, ManagementPolicy::OwnerOnly)
            .map(|_| ()),
        Err(Refusal::KeyAlreadyAuthorized)
    );
    assert!(
        runner2
            .invite(Role::Owner, 42, ManagementPolicy::OwnerOnly)
            .is_ok()
    );
    let wall = runner1.clock.wall;
    runner1.svc().revoke(&first.client.client, wall).unwrap();
    assert!(
        runner1
            .invite(Role::Owner, 42, ManagementPolicy::OwnerOnly)
            .is_ok()
    );
}

// --- W1 review probes, inverted (M06 W1 review; the reviewer's probes against 82158dee) ------

/// The reviewer's port: pauses once, inside the first `put` (or the first `read_all`), until
/// the test releases it. One-shot, so code that writes again never deadlocks the test.
struct ReviewerLines<'a> {
    inner: &'a MemoryLines,
    entered: &'a std::sync::Barrier,
    release: &'a std::sync::Barrier,
    pause_read: bool,
    paused: std::sync::atomic::AtomicBool,
    /// Matching calls to let through before the pause.
    skip: AtomicUsize,
}

impl<'a> ReviewerLines<'a> {
    /// Pause on the `nth` (1-based) `read_all` (`pause_read`) or `put`.
    fn nth(
        inner: &'a MemoryLines,
        entered: &'a std::sync::Barrier,
        release: &'a std::sync::Barrier,
        pause_read: bool,
        nth: usize,
    ) -> Self {
        Self {
            inner,
            entered,
            release,
            pause_read,
            paused: std::sync::atomic::AtomicBool::new(false),
            skip: AtomicUsize::new(nth - 1),
        }
    }

    fn pause(&self) {
        if self
            .skip
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return;
        }
        if !self.paused.swap(true, Ordering::SeqCst) {
            self.entered.wait();
            self.release.wait();
        }
    }
}

impl heimdall_remote::line::ManagementLines for ReviewerLines<'_> {
    fn read_all(&self) -> Result<Vec<KeysFile>, heimdall_remote::line::LineIoError> {
        if self.pause_read {
            self.pause();
        }
        self.inner.read_all()
    }
    fn put(&self, c: &ClientId, line: &str) -> Result<(), heimdall_remote::line::LineIoError> {
        if !self.pause_read {
            self.pause();
        }
        self.inner.put(c, line)
    }
    fn remove(&self, c: &ClientId) -> Result<(), heimdall_remote::line::LineIoError> {
        self.inner.remove(c)
    }
}

/// Two joins of one invitation racing: exactly one commits, the other returns the recorded
/// result (the reviewer's `reviewer_concurrent_join_commits_once`, kept: no other test races
/// two joins).
#[test]
fn concurrent_join_commits_once() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 1, ManagementPolicy::OwnerOnly)
        .unwrap();
    let now = w.read();
    let req = w.join_req(&inv);
    let gate = std::sync::Barrier::new(2);
    let join = || {
        gate.wait();
        w.svc().join(&inv.client.client, &req, &now).unwrap()
    };
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(join);
        let b = join();
        (a.join().unwrap(), b)
    });
    assert_ne!(a.replayed, b.replayed);
    assert_eq!(a.join, b.join);
}

/// ⟨BLOCKING, inverted `reviewer_reconcile_can_write_active_line_after_revocation`⟩ A join
/// commits while its line write fails; the reconciler starts and pauses inside `put` with the
/// active line; a revocation commits its tombstone meanwhile. The revocation's removal waits
/// for the reconcile and wins: the client ends revoked with no line.
#[test]
fn revocation_wins_over_an_in_flight_reconcile() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 2, ManagementPolicy::OwnerOnly)
        .unwrap();
    let now = w.read();
    let cid = &inv.client.client;
    w.lines.set_fail_writes(true);
    w.svc().join(cid, &w.join_req(&inv), &now).unwrap();
    w.lines.set_fail_writes(false);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let port = ReviewerLines {
        inner: &w.lines,
        entered: &entered,
        release: &release,
        pause_read: false,
        paused: std::sync::atomic::AtomicBool::new(false),
        skip: AtomicUsize::new(0),
    };
    let service = Invitations {
        lines: &port,
        ..w.svc()
    };
    let wall = w.clock.wall;
    let world = &w;
    std::thread::scope(|s| {
        let reconcile = s.spawn(|| service.reconcile(&now).unwrap());
        entered.wait();
        let revoke = s.spawn(move || world.svc().revoke(cid, wall));
        // The tombstone commits while the reconcile is still inside `put`.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while world.client(cid).state != ClientState::Revoked {
            assert!(
                std::time::Instant::now() < deadline,
                "the tombstone never committed"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        release.wait();
        reconcile.join().unwrap();
        assert!(revoke.join().unwrap().unwrap().line_removed);
    });
    assert_eq!(w.client(cid).state, ClientState::Revoked);
    assert!(
        w.lines_for(cid).is_empty(),
        "a revoked client kept a line: {:?}",
        w.lines_for(cid)
    );
}

/// ⟨BLOCKING, inverted `reviewer_join_uses_time_sample_captured_before_blocking_io`⟩ An
/// invitation one second from expiry; the join's checked sample is taken, then the join
/// blocks reading the key files while the invitation expires. Liveness is re-checked at the
/// commit point: the join is refused and the client stays pending.
#[test]
fn join_rechecks_liveness_at_its_commit_point() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 3, ManagementPolicy::OwnerOnly)
        .unwrap();
    let cid = &inv.client.client;
    w.advance(899);
    let early = w.read();
    let mut clock = w.clock.clone();
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let port = ReviewerLines {
        inner: &w.lines,
        entered: &entered,
        release: &release,
        pause_read: true,
        paused: std::sync::atomic::AtomicBool::new(false),
        skip: AtomicUsize::new(0),
    };
    let service = Invitations {
        lines: &port,
        ..w.svc()
    };
    let req = w.join_req(&inv);
    std::thread::scope(|s| {
        let join = s.spawn(|| service.join(cid, &req, &early));
        entered.wait();
        clock.wall = plus(clock.wall, 1);
        clock.continuous += Duration::from_secs(1);
        w.live.set(clock.anchor());
        assert_eq!(
            heimdall_remote::invitations::liveness(
                &inv.invitation,
                &TimeReading::safe(&clock.anchor())
            ),
            heimdall_remote::invitations::Liveness::Expired
        );
        release.wait();
        assert_eq!(
            join.join().unwrap().map(|j| j.join),
            Err(Refusal::InvitationExpired)
        );
    });
    assert_eq!(w.client(cid).state, ClientState::Pending);
    // Also a reboot while the join blocks: the anchor is lost at the commit point.
    let mut rebooted = w.clock.clone();
    rebooted.boot += 1;
    rebooted.continuous = Duration::from_secs(1);
    let inv2 = w
        .invite(Role::Owner, 4, ManagementPolicy::OwnerOnly)
        .unwrap();
    let sample = w.read();
    let svc = w.svc();
    w.live.set(rebooted.anchor());
    assert_eq!(
        svc.join(&inv2.client.client, &w.join_req(&inv2), &sample)
            .map(|j| j.join),
        Err(Refusal::InvitationExpired)
    );
}

// --- Gemini W1 review (M06-W1-R01, R03) --------------------------------------------------------

/// Wait (bounded) until `cid`'s row is a tombstone: the revoking or expiring thread committed
/// it and queued on the line lock.
fn until_tombstoned(w: &World, cid: &ClientId) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while w.client(cid).state != ClientState::Revoked {
        assert!(
            std::time::Instant::now() < deadline,
            "the tombstone never committed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// ⟨Gemini R01 probe⟩ A revocation committed while a join's line write is in flight (paused in
/// the join's post-commit read, after its re-read under the line lock): the join's active line
/// is removed by the revocation, the bookkeeping never marks the tombstone with a line.
#[test]
fn revocation_wins_over_a_join_line_write() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 11, ManagementPolicy::OwnerOnly)
        .unwrap();
    let cid = inv.client.client.clone();
    let now = w.read();
    let (entered, release) = (std::sync::Barrier::new(2), std::sync::Barrier::new(2));
    // Read 1: the join's line fingerprint; read 2: its line write.
    let port = ReviewerLines::nth(&w.lines, &entered, &release, true, 2);
    let service = Invitations {
        lines: &port,
        ..w.svc()
    };
    let req = w.join_req(&inv);
    let (wall, world) = (w.clock.wall, &w);
    std::thread::scope(|s| {
        let join = s.spawn(|| service.join(&cid, &req, &now));
        entered.wait();
        let revoke = s.spawn(|| world.svc().revoke(&cid, wall));
        until_tombstoned(world, &cid);
        release.wait();
        assert!(!join.join().unwrap().unwrap().replayed);
        assert!(revoke.join().unwrap().unwrap().line_removed);
    });
    let row = w.client(&cid);
    assert_eq!(row.state, ClientState::Revoked);
    assert_eq!(row.line, heimdall_store::ext_m06::AppliedLine::Absent);
    assert!(w.lines_for(&cid).is_empty(), "{:?}", w.lines_for(&cid));
}

/// ⟨Gemini R01⟩ The same for an invitation: its pending line write is in flight when the
/// client is revoked; the revocation's removal wins.
#[test]
fn revocation_wins_over_an_invite_line_write() {
    let mut w = World::new();
    let (text, fp) = key(12);
    let now = w.read();
    let (entered, release) = (std::sync::Barrier::new(2), std::sync::Barrier::new(2));
    let port = ReviewerLines::nth(&w.lines, &entered, &release, false, 1);
    let service = Invitations {
        lines: &port,
        ..w.svc()
    };
    let (wall, world) = (w.clock.wall, &w);
    std::thread::scope(|s| {
        let invite = s.spawn(|| {
            service.invite(
                &NewInvitation {
                    role: Role::Owner,
                    public_key: &text,
                    key_fingerprint: &fp,
                    lifetime: FIFTEEN_MIN,
                },
                ManagementPolicy::OwnerOnly,
                &now,
            )
        });
        entered.wait();
        let cid = world
            .store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .pop()
            .unwrap()
            .client;
        let c2 = cid.clone();
        let revoke = s.spawn(move || world.svc().revoke(&c2, wall));
        until_tombstoned(world, &cid);
        release.wait();
        let invited = invite.join().unwrap().unwrap();
        assert!(revoke.join().unwrap().unwrap().line_removed);
        let row = world.client(&invited.client.client);
        assert_eq!(row.state, ClientState::Revoked);
        assert_eq!(row.line, heimdall_store::ext_m06::AppliedLine::Absent);
        assert!(world.lines_for(&invited.client.client).is_empty());
    });
}

/// ⟨Gemini R01⟩ `expire_due` against an in-flight reconcile: the reconcile (on a reading
/// taken while the invitation was live) is writing the pending line when the invitation
/// expires and the sweep tombstones it; the sweep's removal wins.
#[test]
fn expiry_wins_over_an_in_flight_reconcile() {
    let mut w = World::new();
    w.lines.set_fail_writes(true);
    let inv = w
        .invite(Role::Owner, 13, ManagementPolicy::OwnerOnly)
        .unwrap();
    w.lines.set_fail_writes(false);
    assert!(!inv.line_written);
    let cid = inv.client.client.clone();
    // The reconcile runs while the invitation is live (the shared clock, too)...
    let live = w.read();
    let (entered, release) = (std::sync::Barrier::new(2), std::sync::Barrier::new(2));
    let port = ReviewerLines::nth(&w.lines, &entered, &release, false, 1);
    let service = Invitations {
        lines: &port,
        ..w.svc()
    };
    // ...and the sweep after the deadline, over the same shared clock and lock.
    let sweeper = Invitations {
        lines: &w.lines,
        ..service
    };
    let mut expired = w.clock.clone();
    expired.wall = plus(
        expired.wall,
        i64::try_from(FIFTEEN_MIN.as_secs()).unwrap() + 1,
    );
    expired.continuous += FIFTEEN_MIN + Duration::from_secs(1);
    let later = TimeReading::safe(&expired.anchor());
    let world = &w;
    std::thread::scope(|s| {
        let reconcile = s.spawn(|| service.reconcile(&live).unwrap());
        entered.wait();
        world.live.set(expired.anchor());
        let sweep = s.spawn(|| sweeper.expire_due(&later).unwrap());
        until_tombstoned(world, &cid);
        release.wait();
        reconcile.join().unwrap();
        assert_eq!(sweep.join().unwrap(), vec![cid.clone()]);
    });
    let row = w.client(&cid);
    assert_eq!(row.state, ClientState::Revoked);
    assert_eq!(
        row.revocation,
        Some(heimdall_store::ext_m06::RevocationCause::InvitationExpired)
    );
    assert!(w.lines_for(&cid).is_empty(), "{:?}", w.lines_for(&cid));
}

/// ⟨Gemini R01⟩ `invite` samples time at its committing transaction: while it blocks reading
/// the key files, two minutes pass; the record's creation time, boot anchor and deadline are
/// the commit's. A reboot during the read refuses the invitation and writes nothing.
#[test]
fn invite_samples_time_at_its_commit() {
    let mut w = World::new();
    let (text, fp) = key(14);
    let sample = w.read();
    let mut later = w.clock.clone();
    later.wall = plus(later.wall, 120);
    later.continuous += Duration::from_secs(120);
    let (entered, release) = (std::sync::Barrier::new(2), std::sync::Barrier::new(2));
    let port = ReviewerLines::nth(&w.lines, &entered, &release, true, 1);
    let service = Invitations {
        lines: &port,
        ..w.svc()
    };
    let new = NewInvitation {
        role: Role::Owner,
        public_key: &text,
        key_fingerprint: &fp,
        lifetime: FIFTEEN_MIN,
    };
    let invited = std::thread::scope(|s| {
        let invite = s.spawn(|| service.invite(&new, ManagementPolicy::OwnerOnly, &sample));
        entered.wait();
        w.live.set(later.anchor());
        release.wait();
        invite.join().unwrap().unwrap()
    });
    assert_eq!(invited.invitation.created_wall, later.wall);
    assert_eq!(invited.invitation.created_elapsed, later.continuous);
    assert_eq!(
        invited.invitation.expires_wall,
        plus(later.wall, i64::try_from(FIFTEEN_MIN.as_secs()).unwrap())
    );
    // Its pending line was written (judged at the commit's time, not the older sample's).
    assert!(invited.line_written);
    let lines = w.lines_for(&invited.client.client);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("expiry-time="));
    // A reboot between the sample and the commit.
    let (text2, fp2) = key(15);
    let sample = w.read();
    let mut rebooted = w.clock.clone();
    rebooted.boot += 1;
    rebooted.continuous = Duration::from_secs(1);
    let before = w.store.transaction(|tx| tx.remote_clients()).unwrap().len();
    let svc = w.svc();
    w.live.set(rebooted.anchor());
    assert_eq!(
        svc.invite(
            &NewInvitation {
                role: Role::Owner,
                public_key: &text2,
                key_fingerprint: &fp2,
                lifetime: FIFTEEN_MIN,
            },
            ManagementPolicy::OwnerOnly,
            &sample,
        )
        .map(|_| ()),
        Err(Refusal::TimeUncertain)
    );
    assert_eq!(
        w.store.transaction(|tx| tx.remote_clients()).unwrap().len(),
        before,
        "nothing was written"
    );
}

/// ⟨Gemini R03⟩ The wire probe of a pending client needs a live invitation: past its expiry,
/// on uncertain time, or once swept, the probe is refused `invitation_expired`; an active
/// client's probe still echoes.
#[test]
fn the_wire_probe_needs_a_live_pending_invitation() {
    let mut w = World::new();
    let inv = w
        .invite(Role::Owner, 16, ManagementPolicy::OwnerOnly)
        .unwrap();
    let cid = inv.client.client.clone();
    let probe =
        ProbeRequest::from_request(&wire_probe(&w.env, &inv.invitation.probe_nonce)).unwrap();
    let uncertain = TimeReading::uncertain(None);
    assert_eq!(
        w.svc().probe(&cid, &probe, &uncertain),
        Err(Refusal::InvitationExpired)
    );
    w.advance(FIFTEEN_MIN.as_secs());
    let now = w.read();
    assert_eq!(
        w.svc().probe(&cid, &probe, &now),
        Err(Refusal::InvitationExpired)
    );
    w.svc().expire_due(&now).unwrap();
    assert_eq!(
        w.svc().probe(&cid, &probe, &now),
        Err(Refusal::InvitationExpired)
    );
    // An active client's probe echoes (its invitation is consumed).
    let other = w
        .invite(Role::Owner, 17, ManagementPolicy::OwnerOnly)
        .unwrap();
    let now = w.read();
    w.svc()
        .join(&other.client.client, &w.join_req(&other), &now)
        .unwrap();
    let probe =
        ProbeRequest::from_request(&wire_probe(&w.env, &other.invitation.probe_nonce)).unwrap();
    assert_eq!(
        w.svc()
            .probe(&other.client.client, &probe, &now)
            .unwrap()
            .nonce,
        other.invitation.probe_nonce
    );
}
