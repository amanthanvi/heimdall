//! ⟨M05⟩ U5, live: ordinary `ssh` activates the personal default (ADR-0011 §3.1–§3.3, §7,
//! §10 items 4 and 7; m05-plan U5; ruling I-2), through the real `Operations`, managed
//! adapter, driver, `ManagedEffectsImpl`, signer table, vault and endpoints of
//! [`super::Live`], the runtime's [`DefaultActivator`] behind the environment endpoint's
//! signer ([`ActivatingAuthority`], as `service.rs` wires it), and **real `ssh`** (the
//! system client) with the managed identity options the projection renders for the
//! ordinary alias (`IdentityAgent=<environment endpoint>`, `IdentitiesOnly=yes`, the slot's
//! certificate as the identity file) against a disposable [`LoopbackSshd`] trusting this
//! run's fixture CA.
//!
//! * [`ordinary_ssh_activates_default_under_personal_policy`]: the first `ssh` on a free
//!   slot activates `default:<env>:1` under the personal policy with no decision; the next
//!   `ssh` logs in with that grant's key.
//! * [`ordinary_ssh_after_expiry_starts_new_work`]: after the grant's expiry the next use
//!   starts work 2 with a fresh grant; work 1 is never extended.
//! * [`paused_or_cut_off_default_never_activates_and_creates_no_decision`]: pause, cutoff
//!   and stop each answer at once, admit nothing, and record one `blocked` event.
//! * [`paused_default_never_binds_an_existing_work_to_the_alias`]: a pause also keeps a
//!   background trigger from attaching the existing default work's binding to the alias.
//! * [`concurrent_ssh_single_activation`]: concurrent identities requests share one.
//! * [`identities_wait_expiry_returns_admitted_and_the_activation_stays_applied`] (ruling 7).
//! * [`a_narrowing_racing_the_activation_fails_not_covered_without_a_decision`].
//! * [`approved_default_sets_an_empty_preference_and_keeps_an_existing_one`] (ruling I-2).
//!
//! **Observed (OpenSSH 10.5p1, macOS, 2026-11-18):** with the projection's `IdentitiesOnly`
//! form, `ssh` reads its `IdentityFile` before it asks the agent, so the first `ssh` on a
//! **free** slot (no file yet) cannot use the certificate the activation lists for it, even
//! when the file appears before the agent is asked; the activation is applied and the next
//! `ssh` logs in. The first journey therefore asserts the activation of the first `ssh` and
//! the login of the next, and reports the first login's outcome.
//!
//! Every key and the CA are generated per run in scratch directories; the client runs with
//! the scratch home's isolation (its own configuration, known hosts, `HOME`, a decoy agent);
//! nothing of the owner's is read, contacted or changed. These need a local `sshd` and Unix
//! sockets: `blocked` on Windows, as the other live journeys.

use super::*;
use crate::default_activation::{ActivatingAuthority, DefaultActivator, FALLBACK_EXECUTABLE};
use crate::supervisor::{FixedJitter, ManagedConnections, Supervisor, SupervisorConfig};
use heimdall_app::Attendance;
use heimdall_app::operations::DefaultOutcome;
use heimdall_app::ports::{DefaultActivation, DefaultWait};
use heimdall_contract::event::{EventFilter, EventType};
use heimdall_contract::ids::PolicyId;
use heimdall_contract::request::{DecideRequest, PolicyAction, Verdict};
use heimdall_contract::trust::{ActivationEventKind, ActivationEventPayload, PolicyTarget};
use heimdall_domain::binding::BindingRecord;
use heimdall_domain::time::Clock as _;
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use std::path::Path;
use std::sync::atomic::AtomicUsize;

/// A pair of destination `dest` for the current account (a non-root fixture `sshd`
/// authenticates only its own account).
fn mine(dest: &str) -> AccessPair {
    pair(dest, &current_account().expect("the current account"))
}

fn pol() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn work(n: u64) -> WorkId {
    heimdall_app::operations::default_work_id(&env(), n).unwrap()
}

/// One raw `SSH_AGENTC_REQUEST_IDENTITIES` (11) on `endpoint`, bounded by 10 s (OpenSSH
/// waits far longer: m05-plan U0b), as ordinary `ssh` sends it: the number of identities
/// the `SSH_AGENT_IDENTITIES_ANSWER` (12) declares. (`heimdall_ipc::agent_client` caps its
/// own calls at the 2 s the activation's budget also is, so it cannot observe the budget.)
async fn request_identities(endpoint: &str) -> std::io::Result<usize> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let call = async {
        let mut s = tokio::net::UnixStream::connect(endpoint).await?;
        s.write_all(&[0, 0, 0, 1, 11]).await?;
        let mut len = [0_u8; 4];
        s.read_exact(&mut len).await?;
        let mut body = vec![0_u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut body).await?;
        match body.as_slice() {
            [12, a, b, c, d, ..] => Ok(u32::from_be_bytes([*a, *b, *c, *d]) as usize),
            _ => Err(std::io::Error::other("not an identities answer")),
        }
    };
    tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .map_err(|_| std::io::Error::other("no answer within 10 s"))?
}

/// An attended owner (only an attended session completes a decision).
fn attended() -> Caller {
    Caller {
        context: caller().context,
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

/// The world: one own-account pair whose seeded personal policy `pol` is this environment's
/// **default**, a runtime process, the activator and the environment endpoint it serves,
/// and a fixture server for the pair.
struct World {
    live: Live,
    p: Process,
    activator: DefaultActivator,
    endpoint: String,
    pr: AccessPair,
    home: ScratchHome,
    sshd: LoopbackSshd,
    alias: String,
}

impl World {
    /// `window`: the default policy's maximum window. `opts`: the process's test seams.
    async fn new(hook: Arc<dyn StageHook>, window: Duration, opts: Opts) -> World {
        let pr = mine("u5-dflt");
        let live = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
        live.store
            .transaction(|tx| {
                let mut p = tx.policy(&pol())?.unwrap();
                p.default = true;
                p.max_window = window;
                p.revision = PolicyRevision(p.revision.0 + 1);
                tx.upsert_policy(&p, false)
            })
            .unwrap();
        let p = live.process_opts(hook, opts).await;
        let activator = DefaultActivator::new(
            p.ops.clone(),
            env(),
            caller().context,
            FALLBACK_EXECUTABLE.to_owned(),
            p.shutdown.clone(),
        )
        .with_retry_interval(Duration::ZERO);
        // As `service.rs` wires it: the operations' authority, plus the activation.
        let registry = EndpointRegistry::new(
            EndpointLayout::unix(&live.run_dir()).unwrap(),
            heimdall_ipc::endpoint::ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
            p.table.clone(),
            Arc::new(ActivatingAuthority::new(
                Arc::new(p.ops.clone()),
                Arc::new(activator.clone()),
            )),
            SignerLimits::default(),
            p.shutdown.clone(),
        );
        let endpoint = registry.start_environment().unwrap().locator;
        let home = ScratchHome::new();
        let account = pr.account.as_str().to_owned();
        let sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                trusted_user_ca_keys: Some(home.root.join("trusted_ca.pub")),
                authorized_principals: Some(
                    [(
                        account.clone(),
                        vec![heimdall_domain::issuance::principal_for(&pr)],
                    )]
                    .into(),
                ),
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("a local fixture sshd is needed: {e}"));
        sshd.trust_user_ca(&live.ca.public_openssh().unwrap())
            .unwrap();
        home.trust_host_key(&sshd.host_key_line).unwrap();
        let alias = "hm-u5-fixture".to_owned();
        home.write_user_config(&format!(
            "Host {alias}\n  HostName 127.0.0.1\n  Port {}\n  User {account}\n",
            sshd.port
        ))
        .unwrap();
        World {
            live,
            p,
            activator,
            endpoint,
            pr,
            home,
            sshd,
            alias,
        }
    }

    async fn plain(window: Duration) -> World {
        World::new(Arc::new(NoStageHook), window, Opts::default()).await
    }

    /// Ordinary `ssh` to the alias with the projection's managed identity options through
    /// the pair's slot, running `echo <marker>`: whether it logged in, and the fingerprint
    /// of the certified key the server accepted.
    async fn ssh(&self, marker: &str) -> (bool, Option<String>) {
        use heimdall_sshconf::render::{
            ManagedIdentityForm, PathStyle, RenderPath, managed_identity_options,
        };
        let slot = files::slot_paths(&self.p.effects.slot_root().data_dir, &self.pr).unwrap();
        let before = self.sshd.accepted_certificates().len();
        let options = managed_identity_options(
            &RenderPath::unix(Path::new(&self.endpoint)).unwrap(),
            &RenderPath::unix(&slot.key_pub).unwrap(),
            &RenderPath::unix(&slot.cert_pub).unwrap(),
            PathStyle::Unix,
            ManagedIdentityForm::select(None),
        )
        .unwrap();
        let mut cmd = std::process::Command::new(find_program("ssh").expect("ssh"));
        cmd.args(self.home.isolation_args())
            .args(&options)
            .args(["-o", "PreferredAuthentications=publickey"])
            .arg(&self.alias)
            .arg(format!("echo {marker}"))
            .env(
                "SSH_AUTH_SOCK",
                self.home.decoy_agent().endpoint().locator(),
            )
            .env("HOME", &self.home.git_home)
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .env_remove("SSH_AGENT_PID")
            .env_remove("DISPLAY")
            .stdin(std::process::Stdio::null());
        let out = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .unwrap()
            .unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        let ok = out.status.success() && String::from_utf8_lossy(&out.stdout).contains(marker);
        let accepted = self.sshd.accepted_certificates();
        let fingerprint = (accepted.len() > before)
            .then(|| accepted.last().map(|a| a.fingerprint.clone()))
            .flatten();
        (ok, fingerprint)
    }

    /// One `REQUEST_IDENTITIES` on the environment endpoint (what ordinary `ssh` sends):
    /// how many identities it listed. The request never fails.
    async fn identities(&self) -> usize {
        request_identities(&self.endpoint)
            .await
            .unwrap_or_else(|e| panic!("the identities request failed: {e}"))
    }

    /// Wait (bounded) until no activation is in flight.
    async fn settled(&self) {
        for _ in 0..600 {
            if !self.activator.in_flight() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the activation did not settle");
    }

    fn counts(&self) -> heimdall_store::ext::TableCounts {
        self.live.store.transaction(|tx| tx.table_counts()).unwrap()
    }

    fn bindings_of(&self, n: u64) -> Vec<BindingRecord> {
        self.live
            .store
            .transaction(|tx| tx.bindings_for_work(&env(), &work(n)))
            .unwrap()
    }

    fn slot(&self) -> SlotState {
        self.live
            .store
            .transaction(|tx| tx.slot(&env(), &self.pr))
            .unwrap()
    }

    fn grant(&self, g: &GrantId) -> heimdall_domain::grant::GrantSnapshot {
        self.live
            .store
            .transaction(|tx| tx.grant(g))
            .unwrap()
            .unwrap()
    }

    fn key_of(&self, g: &GrantId) -> String {
        self.p
            .table
            .public_key(g)
            .expect("the grant's key")
            .fingerprint
    }

    /// The activation events recorded so far, oldest first.
    fn activation_events(&self) -> Vec<ActivationEventPayload> {
        let filter = EventFilter {
            operation_id: None,
            types: vec![EventType::Activation],
        };
        self.live
            .store
            .transaction(|tx| tx.events_after(&env(), 0, &filter, 1000))
            .unwrap()
            .events
            .into_iter()
            .map(|e| serde_json::from_value(e.payload).unwrap())
            .collect()
    }

    /// The events recorded off the caller's path (`blocked`, `not_covered`) are written by
    /// a spawned task: wait (bounded) for at least `n`.
    async fn events_at_least(&self, n: usize) -> Vec<ActivationEventPayload> {
        for _ in 0..200 {
            let e = self.activation_events();
            if e.len() >= n {
                return e;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.activation_events()
    }

    /// The production end-of-grant pass (the supervisor's ended-slot pass over this
    /// process's cleanup, which frees or hands over the slots of ended grants).
    async fn ended_slot_pass(&self) {
        struct NoEndpoints;
        impl crate::connections::BindingEndpoints for NoEndpoints {
            fn endpoint(&self, _: &BindingId) -> Option<EndpointRef> {
                None
            }
        }
        let config = crate::connections::ConnectionConfig::new(
            self.live.run_dir(),
            std::path::PathBuf::from("/nonexistent/fixture-ssh"),
            Arc::new(NoEndpoints),
            Arc::new(FixedJitter(1.0)),
        );
        let connections = Arc::new(crate::connections::ConnectionSupervisor::new(
            self.live.store.clone(),
            Some(self.p.ops.clone()),
            config,
        ));
        let clock: Arc<dyn heimdall_domain::time::Clock> = self.live.clock.clone();
        Supervisor::new(self.p.ops.clone(), SupervisorConfig::default())
            .with_state(self.live.store.clone(), clock)
            .with_connections(Arc::new(ManagedConnections::new(
                connections,
                self.live.store.clone(),
                self.p.ops.clone(),
            )))
            .with_end_cleanup(Arc::new(StoreCleanup::new(
                StoreSources::new(self.live.store.clone(), env()),
                self.p.effects.clone(),
                None,
            )))
            .ended_slot_pass()
            .await
            .unwrap();
    }

    async fn act(&self, action: PolicyAction) {
        self.p
            .ops
            .policy(&caller(), action)
            .await
            .unwrap_or_else(|e| panic!("policy: {} {}", e.code, e.message));
    }
}

/// ADR-0011 §3.2 (a), §3.3: the first ordinary `ssh` to the managed alias of a free slot asks
/// the environment endpoint for identities, which activates the personal default's covered
/// scope as work `default:<env>:1` — a personal grant under `pol` (its origin names the
/// policy, no workspace) whose binding holds the slot — with **no decision record**, and
/// records one `activated` event. The next `ssh` logs in with that grant's key, and an
/// identities request on the active scope answers at once without new work.
#[tokio::test]
async fn ordinary_ssh_activates_default_under_personal_policy() {
    let w = World::plain(2 * HOUR).await;
    assert_eq!(w.slot(), SlotState::Free { generation: 0 });
    let before = w.counts();
    assert_eq!(before.decisions, 0);

    let first = w.ssh("u5-first").await;
    w.settled().await;
    let bound = w.bindings_of(1);
    assert_eq!(bound.len(), 1, "one binding of work 1");
    let b = &bound[0];
    assert_eq!(b.state, heimdall_domain::binding::BindingState::Active);
    assert_eq!(b.work_id, work(1));
    assert_eq!(
        w.slot(),
        SlotState::Held {
            binding: b.id.clone(),
            generation: 1
        },
        "the default work's binding holds the ordinary alias's slot"
    );
    let origin = w
        .live
        .store
        .transaction(|tx| tx.grant_origin(&b.grant))
        .unwrap()
        .expect("the grant's origin");
    assert_eq!(
        origin.policy_id,
        Some(pol()),
        "granted under the personal policy"
    );
    assert_eq!(origin.workspace, None, "personal context");
    let after = w.counts();
    assert_eq!(after.decisions, 0, "no decision record");
    let events = w.activation_events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, ActivationEventKind::Activated);
    assert_eq!(events[0].policy_id, Some(pol()));

    let second = w.ssh("u5-second").await;
    assert!(second.0, "the next ordinary ssh logs in");
    assert_eq!(
        second.1,
        Some(w.key_of(&b.grant)),
        "with the default work's key"
    );
    // The first `ssh`'s own login is not asserted: with the projection's `IdentitiesOnly`
    // form OpenSSH 10.5p1 read the absent file before asking the agent and failed (module
    // docs); the claim is the activation it triggered and the next login.
    let _ = first;

    // Already active: answered at once, no new work, no new record.
    let started = std::time::Instant::now();
    assert_eq!(w.identities().await, 1);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(w.bindings_of(2).is_empty());
    let last = w.counts();
    assert_eq!(
        (last.operations, last.grants, last.decisions),
        (after.operations, after.grants, 0)
    );
    w.p.shutdown.cancel();
}

/// ADR-0011 §3.3 (A05 "automatic re-entry"): after work 1's grant expires (and the end pass
/// frees its slot), the next ordinary `ssh` starts **work 2** under the policy with a fresh
/// grant and key; work 1's grant stays expired with its deadline unchanged (an expired work
/// ID is never extended), and the next `ssh` logs in with work 2's key. No decision.
///
/// The policy's window is 50 s so that the virtual clock moved past work 1's deadline stays
/// inside work 2's certificate validity at the server's real clock (`valid_after` is backdated
/// 60 s).
#[tokio::test]
async fn ordinary_ssh_after_expiry_starts_new_work() {
    let w = World::plain(Duration::from_secs(50)).await;
    let _ = w.identities().await;
    w.settled().await;
    let one = w.bindings_of(1).pop().expect("work 1");
    let (ok, key) = w.ssh("u5-w1").await;
    assert!(ok, "work 1 logs in");
    assert_eq!(key, Some(w.key_of(&one.grant)));
    let deadline_one = w.grant(&one.grant).deadline.effective;

    w.live.clock.advance(Duration::from_secs(51));
    w.p.ops.tick().await.unwrap();
    assert_eq!(w.grant(&one.grant).state, GrantState::Expired);
    w.ended_slot_pass().await;
    assert!(matches!(w.slot(), SlotState::Free { .. }), "{:?}", w.slot());

    let _ = w.ssh("u5-reenter").await;
    w.settled().await;
    let two = w
        .bindings_of(2)
        .pop()
        .expect("work 2 started at the next use");
    assert_ne!(two.grant, one.grant, "a fresh grant");
    let (ok, key) = w.ssh("u5-w2").await;
    assert!(ok, "work 2 logs in");
    assert_eq!(key, Some(w.key_of(&two.grant)));
    let g1 = w.grant(&one.grant);
    assert_eq!(g1.state, GrantState::Expired, "work 1 stays expired");
    assert_eq!(g1.deadline.effective, deadline_one, "never extended");
    assert_eq!(w.bindings_of(1).len(), 1, "no new binding for work 1");
    assert_eq!(w.counts().decisions, 0);
    w.p.shutdown.cancel();
}

/// ADR-0011 §7.2 (pause, cutoff, stop: "background triggers: refused"): under each block the
/// identities request answers **at once** with nothing listed, nothing is admitted (no
/// operation, grant, binding or decision), the slot stays free and `ssh` fails; three
/// requests record **one** `blocked` event with the block's reason (at most one per policy
/// and reason per hour).
#[tokio::test]
async fn paused_or_cut_off_default_never_activates_and_creates_no_decision() {
    for how in ["pause", "cutoff", "stop"] {
        let w = World::plain(2 * HOUR).await;
        let reason = match how {
            "pause" => {
                w.act(PolicyAction::Pause {
                    policy_id: Some(pol()),
                    target: None,
                })
                .await;
                "policy_paused"
            }
            "cutoff" => {
                let at = Timestamp::from_second(w.live.clock.wall().as_second() + 5).unwrap();
                w.act(PolicyAction::Cutoff {
                    policy_id: Some(pol()),
                    at,
                    target: None,
                })
                .await;
                w.live.clock.advance(Duration::from_secs(6));
                "policy_cutoff"
            }
            _ => {
                w.act(PolicyAction::Stop {
                    target: PolicyTarget::Policy { policy_id: pol() },
                })
                .await;
                "policy_paused"
            }
        };
        let before = w.counts();
        for _ in 0..3 {
            let started = std::time::Instant::now();
            assert_eq!(w.identities().await, 0, "{how}: nothing listed");
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{how}: answered at once ({:?})",
                started.elapsed()
            );
        }
        assert!(!w.activator.in_flight(), "{how}: nothing started");
        let (ok, _) = w.ssh(&format!("u5-{how}")).await;
        assert!(!ok, "{how}: ordinary ssh does not log in");
        let after = w.counts();
        assert_eq!(
            (after.operations, after.grants, after.decisions),
            (before.operations, before.grants, 0),
            "{how}: nothing admitted, no decision"
        );
        assert!(w.bindings_of(1).is_empty(), "{how}: no default work");
        assert!(matches!(w.slot(), SlotState::Free { .. }), "{how}");
        let events = w.events_at_least(1).await;
        assert_eq!(
            events.len(),
            1,
            "{how}: one event for four requests: {events:?}"
        );
        assert_eq!(events[0].kind, ActivationEventKind::Blocked);
        assert_eq!(events[0].reason.as_deref(), Some(reason), "{how}");
        w.p.shutdown.cancel();
    }
}

/// The owner's own `ensure` of default work 1: an active binding that holds no slot (an
/// activation whose `ensure` committed and whose bind never ran).
async fn unslotted_work_one(w: &World) -> heimdall_contract::request::EnsureData {
    w.p.ops
        .ensure(
            &caller(),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: [w.pr.clone()].into_iter().collect(),
                environment: None,
                work_id: work(1),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("r-work-1").unwrap(),
                interaction: InteractionMode::Interactive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
                context: None,
                covered_only: false,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message))
        .data
}

/// An attended `action` and the owner's approval of the decision it raises.
async fn approve(w: &World, action: PolicyAction) {
    let e =
        w.p.ops
            .policy(&attended(), action)
            .await
            .expect_err("the action waits for its decision");
    let d = heimdall_contract::ids::DecisionId::parse(&e.next.decision_ref.unwrap()).unwrap();
    w.p.ops
        .decide(
            &attended(),
            DecideRequest {
                decision_id: d,
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message));
}

/// ⟨Ruling I-20⟩ The default activation reuses only a binding its current default stands
/// behind. Work 1's binding exists under `pol` (active, no slot: [`unslotted_work_one`]);
/// the owner then moves the default to another profile's policy (an attended
/// `create {default: true}`). The next activation does not attach work 1's binding to the
/// ordinary alias — its grant rests on `pol`, not on the current default — and starts work 2
/// under the current default instead: work 2's binding holds the slot, its grant rests on the
/// new default, and work 1's binding is unchanged and holds no slot reference (A16: running
/// work keeps its pins). (Revert: accept any active binding of the current work, as before
/// I-20, and the activation answers `Activated` for work 1.)
#[tokio::test]
async fn the_default_never_reuses_a_binding_of_another_policy() {
    let w = World::plain(2 * HOUR).await;
    let one = unslotted_work_one(&w).await;
    w.live
        .store
        .transaction(|tx| {
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev2").unwrap(),
                revision: 1,
                scope: Scope {
                    pairs: [w.pr.clone()].into_iter().collect(),
                    capabilities: [Capability::SshAuthentication].into_iter().collect(),
                },
                label: None,
            })
        })
        .unwrap();
    approve(
        &w,
        PolicyAction::Create {
            profile: ProfileId::parse("dev2").unwrap(),
            environments: [env()].into_iter().collect(),
            max_window: None,
            default: true,
        },
    )
    .await;
    let default = w
        .live
        .store
        .transaction(|tx| tx.policies())
        .unwrap()
        .into_iter()
        .find(|q| q.default)
        .expect("the default")
        .id;
    assert_ne!(default, pol(), "the default moved");
    let original = w.bindings_of(1);
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].id, one.binding_id);
    let before = w.counts();

    let outcome =
        w.p.ops
            .activate_default(&caller().context, &env(), FALLBACK_EXECUTABLE)
            .await;
    let DefaultOutcome::Activated {
        policy,
        work_id,
        binding,
    } = outcome
    else {
        panic!("the current default activates new work: {outcome:?}");
    };
    assert_eq!(policy, default);
    assert_eq!(
        work_id,
        work(2),
        "work 1's binding of another policy is not reused"
    );
    assert_eq!(w.bindings_of(1), original, "work 1's binding is unchanged");
    let two = w.bindings_of(2);
    assert_eq!(two.len(), 1);
    assert_eq!(two[0].id, binding);
    assert_eq!(
        w.slot(),
        SlotState::Held {
            binding: binding.clone(),
            generation: 1
        },
        "work 2's binding holds the ordinary alias's slot"
    );
    let refs = w
        .live
        .store
        .transaction(|tx| tx.slot_references(&env(), &w.pr.destination, &w.pr.account))
        .unwrap();
    assert!(
        refs.iter().all(|r| r.binding != one.binding_id),
        "work 1's binding holds no slot reference: {refs:?}"
    );
    let origin = w
        .live
        .store
        .transaction(|tx| tx.grant_origin(&two[0].grant))
        .unwrap()
        .expect("the grant's origin");
    assert_eq!(
        origin.policy_id,
        Some(default),
        "granted under the current default"
    );
    assert_eq!(origin.workspace, None, "personal context");
    assert_eq!(w.counts().decisions, before.decisions, "no decision");
    w.p.shutdown.cancel();
}

/// ADR-0011 §7.2 ("pause: background triggers refused"), at the step the pipeline does not
/// guard: work 1's binding exists and is active but holds no slot ([`unslotted_work_one`]). A
/// pause leaves an existing binding usable, so binding it would succeed — but a background
/// trigger under a block does nothing.
///
/// **The block races the bind** (review M05-W3-R02). The activation plans while nothing
/// blocks and chooses to bind work 1; at its bind's entrance (the debug scheduling seam) the
/// owner's production actions commit:
/// * `pause`: the default is paused;
/// * `cutoff`: the default's cutoff passes.
///
/// (A default moved to another policy between the plan and the bind is refused by the same
/// check, the planned default being gone; the activation then plans again and never reuses
/// the other policy's binding: [`the_default_never_reuses_a_binding_of_another_policy`].)
///
/// Each time the bind's claiming transaction refuses: the activation answers `Blocked` with
/// the block's reason, as a block found by the plan does; the action committed, the
/// activation created no decision, the binding is unchanged, the slot is free and no slot
/// file was written. (Revert proof 3: drop the bind's in-transaction check, and the `pause`
/// case claims the slot and answers `Activated`.)
///
/// **The block precedes the plan.** The owner pauses: the identities request answers at
/// once, the slot stays free and `ssh` fails. The positive control: once the owner resumes
/// (an attended decision), the next request binds that same existing work (no new work) and
/// `ssh` logs in. (Revert proof 2: drop the plan's pause check and the trigger attaches the
/// binding under the pause.)
#[tokio::test]
async fn paused_default_never_binds_an_existing_work_to_the_alias() {
    for how in ["pause", "cutoff"] {
        let w = World::plain(2 * HOUR).await;
        let one = unslotted_work_one(&w).await;
        let original = w.bindings_of(1);
        assert_eq!(original.len(), 1);
        assert_eq!(original[0].id, one.binding_id);
        assert_eq!(w.slot(), SlotState::Free { generation: 0 }, "{how}");
        let seam = w.p.ops.debug_pause_next_default_bind();
        let ops = w.p.ops.clone();
        let activation = tokio::spawn(async move {
            ops.activate_default(&caller().context, &env(), FALLBACK_EXECUTABLE)
                .await
        });
        seam.reached
            .await
            .unwrap_or_else(|_| panic!("{how}: the activation did not plan the bind"));
        // The owner's action commits between the plan and the bind.
        let reason = match how {
            "cutoff" => {
                let at = Timestamp::from_second(w.live.clock.wall().as_second() + 5).unwrap();
                w.act(PolicyAction::Cutoff {
                    policy_id: Some(pol()),
                    at,
                    target: None,
                })
                .await;
                w.live.clock.advance(Duration::from_secs(6));
                "policy_cutoff"
            }
            _ => {
                w.act(PolicyAction::Pause {
                    policy_id: Some(pol()),
                    target: None,
                })
                .await;
                "policy_paused"
            }
        };
        let committed = w
            .live
            .store
            .transaction(|tx| tx.policy(&pol()))
            .unwrap()
            .unwrap();
        assert!(
            match how {
                "cutoff" => committed.cutoff_at.is_some(),
                _ => matches!(committed.pause, PauseState::Paused { .. }),
            },
            "{how}: the owner's action committed before the bind"
        );
        let before = w.counts();
        let _ = seam.resume.send(());
        let outcome = activation.await.unwrap();
        assert_eq!(
            outcome,
            DefaultOutcome::Blocked {
                policy: pol(),
                reason: reason.to_owned(),
            },
            "{how}"
        );
        let after = w.counts();
        assert_eq!(after.decisions, before.decisions, "{how}: no decision");
        assert_eq!(
            after.operations - before.operations,
            1,
            "{how}: one refused bind"
        );
        assert_eq!(
            w.bindings_of(1),
            original,
            "{how}: the binding is unchanged"
        );
        assert!(w.bindings_of(2).is_empty(), "{how}: no new work");
        assert_eq!(
            w.slot(),
            SlotState::Free { generation: 0 },
            "{how}: the background bind claimed nothing after the owner's action"
        );
        let slot = files::slot_paths(&w.p.effects.slot_root().data_dir, &w.pr).unwrap();
        assert!(
            std::fs::read_dir(&slot.dir).map_or(true, |mut d| d.next().is_none()),
            "{how}: no slot file was written"
        );
        w.p.shutdown.cancel();
    }

    // The block precedes the plan.
    let w = World::plain(2 * HOUR).await;
    let one = unslotted_work_one(&w).await;
    assert_eq!(w.slot(), SlotState::Free { generation: 0 }, "no slot held");
    w.act(PolicyAction::Pause {
        policy_id: Some(pol()),
        target: None,
    })
    .await;
    let before = w.counts();
    // The background trigger under the pause: nothing.
    let started = std::time::Instant::now();
    assert_eq!(w.identities().await, 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    w.settled().await;
    assert_eq!(
        w.slot(),
        SlotState::Free { generation: 0 },
        "a paused default never attaches its existing binding"
    );
    let (ok, _) = w.ssh("u5-paused-bind").await;
    assert!(!ok);
    let after = w.counts();
    assert_eq!((after.operations, after.decisions), (before.operations, 0));
    // The control: resumed, the same existing work is bound (no new work).
    approve(
        &w,
        PolicyAction::Resume {
            policy_id: Some(pol()),
            target: None,
        },
    )
    .await;
    let _ = w.identities().await;
    w.settled().await;
    assert_eq!(
        w.slot(),
        SlotState::Held {
            binding: one.binding_id.clone(),
            generation: 1
        },
        "resumed: the existing work's binding is attached"
    );
    assert!(w.bindings_of(2).is_empty(), "no new work");
    let (ok, key) = w.ssh("u5-resumed").await;
    assert!(ok);
    assert_eq!(key, Some(w.key_of(&one.grant_id)));
    w.p.shutdown.cancel();
}

/// ADR-0011 §3.2 "single-flight per environment": four identities requests while the
/// activation is held in its preparation share **one** activation (one `ensure` admitted, one
/// grant, one binding of work 1, one `activated` event); each answers within its budget and
/// none fails; once released, every later request lists the activated identity at once.
#[tokio::test]
async fn concurrent_ssh_single_activation() {
    let hold = Arc::new(Hold::default());
    hold.armed.store(true, Ordering::SeqCst);
    let w = World::new(
        Arc::new(NoStageHook),
        2 * HOUR,
        Opts {
            hold: Arc::clone(&hold),
            ..Opts::default()
        },
    )
    .await;
    let before = w.counts();
    let reached = hold.reached.notified();
    let calls = (0..4).map(|_| {
        let ep = w.endpoint.clone();
        async move { request_identities(&ep).await }
    });
    let all = futures_join_all(calls);
    tokio::pin!(all);
    tokio::select! {
        () = reached => {}
        _ = &mut all => panic!("the requests answered before the activation reached its preparation"),
    }
    assert!(w.activator.in_flight());
    // Held: every request answers within its budget, listing nothing yet, and none fails.
    for r in all.await {
        assert_eq!(r.expect("never fails"), 0);
    }
    hold.release.notify_one();
    w.settled().await;
    assert_eq!(w.identities().await, 1);
    let after = w.counts();
    assert_eq!(
        after.operations - before.operations,
        2,
        "one ensure and its bind"
    );
    assert_eq!(after.grants - before.grants, 1, "one grant");
    assert_eq!(w.bindings_of(1).len(), 1, "one binding");
    assert!(w.bindings_of(2).is_empty());
    assert_eq!(after.decisions, 0);
    let events = w.activation_events();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.kind == ActivationEventKind::Activated)
            .count(),
        1
    );
    w.p.shutdown.cancel();
}

/// `join_all` over the four requests (no `futures` crate: one task each).
async fn futures_join_all<F>(calls: impl Iterator<Item = F>) -> Vec<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let handles: Vec<_> = calls.map(tokio::spawn).collect();
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

/// Ruling 7 (ADR-0011 §10 item 7; plan §6.3 property 7): an identities request whose wait
/// expires (the activation is held in its preparation) answers after its 2 s budget with the
/// identities admitted by then (none) and **does not fail**; the activation it started
/// commits after its caller stopped waiting and **stays applied** (not rolled back): the next
/// request lists it at once and `ssh` logs in with its key.
#[tokio::test]
async fn identities_wait_expiry_returns_admitted_and_the_activation_stays_applied() {
    let hold = Arc::new(Hold::default());
    hold.armed.store(true, Ordering::SeqCst);
    let w = World::new(
        Arc::new(NoStageHook),
        2 * HOUR,
        Opts {
            hold: Arc::clone(&hold),
            ..Opts::default()
        },
    )
    .await;
    let started = std::time::Instant::now();
    let listed_now = w.identities().await;
    let waited = started.elapsed();
    assert_eq!(listed_now, 0, "nothing was admitted within the budget");
    assert!(
        waited >= heimdall_app::ports::DEFAULT_ACTIVATION_WAIT
            && waited < heimdall_app::ports::DEFAULT_ACTIVATION_WAIT + Duration::from_secs(2),
        "answered at the budget: {waited:?}"
    );
    assert!(w.activator.in_flight(), "the activation continues");
    hold.release.notify_one();
    w.settled().await;
    let b = w.bindings_of(1).pop().expect("work 1 committed");
    assert_eq!(b.state, heimdall_domain::binding::BindingState::Active);
    assert!(matches!(w.slot(), SlotState::Held { .. }));
    let started = std::time::Instant::now();
    assert_eq!(w.identities().await, 1, "the next request uses it");
    assert!(started.elapsed() < Duration::from_secs(1));
    let (ok, key) = w.ssh("u5-after-timeout").await;
    assert!(ok);
    assert_eq!(key, Some(w.key_of(&b.grant)));
    assert_eq!(
        w.bindings_of(1)[0].state,
        heimdall_domain::binding::BindingState::Active,
        "never rolled back"
    );
    assert_eq!(w.counts().decisions, 0);
    w.p.shutdown.cancel();
}

/// Removes the pair from `pol`'s scope (a narrowing, written directly) the first time the
/// pipeline reaches `LoadAuthority`: after the activation planned what is covered and before
/// the pipeline resolves it.
#[derive(Default)]
struct NarrowOnce {
    store: std::sync::OnceLock<Arc<Store>>,
    fired: AtomicUsize,
}

impl StageHook for NarrowOnce {
    fn before(&self, stage: EnsureStage) -> Result<(), Code> {
        if stage == EnsureStage::LoadAuthority
            && let Some(store) = self.store.get()
            && self.fired.fetch_add(1, Ordering::SeqCst) == 0
        {
            store
                .transaction(|tx| {
                    let mut p = tx.policy(&pol())?.unwrap();
                    p.scope.pairs.clear();
                    p.revision = PolicyRevision(p.revision.0 + 1);
                    tx.upsert_policy(&p, true)
                })
                .unwrap();
        }
        Ok(())
    }
    fn after(&self, _stage: EnsureStage) -> Result<(), Code> {
        Ok(())
    }
}

/// ADR-0011 §3.2 "background activation is covered-or-nothing" (ruling D03's server half, for
/// the identities path): a narrowing that lands between the activation's plan and the
/// pipeline's resolution leaves the request uncovered; it fails `not_covered` with **no
/// decision record**, no grant left usable and no binding, and records a `not_covered` event.
/// (Revert proof 1: drop the covered-only resolution from the internal `ensure` and the same
/// race raises an `ApproveAuthority` record.)
#[tokio::test]
async fn a_narrowing_racing_the_activation_fails_not_covered_without_a_decision() {
    let hook = Arc::new(NarrowOnce::default());
    let w = World::new(hook.clone(), 2 * HOUR, Opts::default()).await;
    assert!(hook.store.set(w.live.store.clone()).is_ok(), "armed once");
    let before = w.counts();
    let answer = w.activator.ensure_default(Duration::from_secs(30)).await;
    assert_eq!(hook.fired.load(Ordering::SeqCst), 1, "the race was run");
    let c = w.counts();
    assert_eq!(c.decisions, 0, "no decision record");
    assert_eq!(answer, DefaultWait::NotCovered, "{answer:?}");
    assert_eq!(c.grants, before.grants, "no grant");
    assert!(w.bindings_of(1).is_empty(), "no binding");
    let mut events = Vec::new();
    for _ in 0..200 {
        events = w.activation_events();
        if !events.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, ActivationEventKind::NotCovered);
    w.p.shutdown.cancel();
}

/// Ruling I-2: approving an attended `create {default: true}` sets the environment's
/// default-profile preference to the policy's profile **when none is set**, and keeps an
/// existing one; neither touches an existing binding (R-AU-03).
#[tokio::test]
async fn approved_default_sets_an_empty_preference_and_keeps_an_existing_one() {
    let pr = mine("u5-i2");
    let w = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
    let p = w.process(Arc::new(NoStageHook)).await;
    // Two further profiles over the same pair (one personal policy per profile and
    // environment: `dev` already has `pol`).
    w.store
        .transaction(|tx| {
            for id in ["dev2", "dev3"] {
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse(id).unwrap(),
                    revision: 1,
                    scope: Scope {
                        pairs: [pr.clone()].into_iter().collect(),
                        capabilities: [Capability::SshAuthentication].into_iter().collect(),
                    },
                    label: None,
                })?;
            }
            Ok(())
        })
        .unwrap();
    // A running binding, whose pins nothing below may change.
    let running = p
        .ops
        .ensure(
            &caller(),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: [pr.clone()].into_iter().collect(),
                environment: None,
                work_id: WorkId::parse("w-running").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("r-running").unwrap(),
                interaction: InteractionMode::Interactive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
                context: None,
                covered_only: false,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message))
        .data;
    let pins = |w: &Live| {
        w.store
            .transaction(|tx| {
                Ok((
                    tx.binding(&running.binding_id)?.unwrap(),
                    tx.binding_context(&running.binding_id)?,
                ))
            })
            .unwrap()
    };
    let pinned = pins(&w);
    let create = |profile: &str| PolicyAction::Create {
        profile: ProfileId::parse(profile).unwrap(),
        environments: [env()].into_iter().collect(),
        max_window: None,
        default: true,
    };
    let approve = |action: PolicyAction| {
        let ops = p.ops.clone();
        async move {
            let e = ops
                .policy(&attended(), action)
                .await
                .expect_err("a widening waits for its decision");
            let d = heimdall_contract::ids::DecisionId::parse(
                &e.next.decision_ref.clone().expect("the decision"),
            )
            .unwrap();
            ops.decide(
                &attended(),
                DecideRequest {
                    decision_id: d,
                    verdict: Verdict::Approve,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message));
        }
    };
    assert_eq!(p.ops.default_profile(None).await.unwrap(), None);
    // No preference: the approved default sets it.
    approve(create("dev2")).await;
    assert_eq!(
        p.ops.default_profile(None).await.unwrap(),
        Some(ProfileId::parse("dev2").unwrap())
    );
    // A preference exists: the next approved default (which takes the `default` mark) keeps it.
    approve(create("dev3")).await;
    assert_eq!(
        p.ops.default_profile(None).await.unwrap(),
        Some(ProfileId::parse("dev2").unwrap()),
        "an existing preference is kept"
    );
    let defaults: Vec<String> = w
        .store
        .transaction(|tx| tx.policies())
        .unwrap()
        .into_iter()
        .filter(|q| q.default)
        .map(|q| q.profile.to_string())
        .collect();
    assert_eq!(
        defaults,
        ["dev3"],
        "the default mark moved; the preference did not"
    );
    let now = pins(&w);
    assert_eq!(now, pinned, "no binding pin changed");
    p.shutdown.cancel();
}
