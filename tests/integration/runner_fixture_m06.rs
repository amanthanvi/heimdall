//! ⟨M06 U3⟩ The runner fixture shared by `integration_runner_runtime_m06` and
//! `model_runner_delivery` (included with `#[path]`; no tests of its own).
//!
//! A runner store in memory (`paired::init_runner`), two paired owner controllers (`A`, `B`) and
//! a third active owner (`S`), one grant under a covering standing policy for two pairs, and
//! two disposable CAs generated per run (never committed). The clock is the testkit's
//! `VirtualClock`.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, GrantId, KeyFingerprint, OperationId,
    PolicyId, ProfileId,
};
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::remote::{Role, RunnerLifetime};
use heimdall_contract::request::{
    AccessPairRef, DeadlineIntent, DestinationScopeEnforcement, Enforcement,
    ExistingConnectionsPolicy, NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
};
use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantSnapshot};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::scope::{Capability, Scope};
use heimdall_domain::time::{Clock, Deadline};
use heimdall_issuer::remote::PreparedRemoteGrant;
use heimdall_runtime::runner::RunnerRuntime;
use heimdall_runtime::runner::time::{RunnerTimePolicy, TimeSampleAccepted, TimeSession};
use heimdall_store::ext_m06::{AppliedLine, ClientState, RemoteClientRecord};
use heimdall_store::ext_runner::TrustedIssuer;
use heimdall_store::{FaultHook, NoFaults, Store};
use heimdall_testkit::VirtualClock;

pub const HOUR: Duration = Duration::from_secs(3600);

pub fn t0() -> Timestamp {
    "2026-11-21T09:00:00Z".parse().unwrap()
}

pub fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(jiff::SignedDuration::try_from(d).unwrap())
        .unwrap()
}

pub fn client(b: u8) -> ClientId {
    ClientId::from_random_bytes([b; 16])
}

/// Controller A (trusted with CA A, designated as the time source by default).
pub fn controller_a() -> ClientId {
    client(0xa1)
}

/// Controller B (a second owner controller; trusted with CA B when a case says so).
pub fn controller_b() -> ClientId {
    client(0xb2)
}

/// An active owner that is neither trusted nor designated.
pub fn stranger() -> ClientId {
    client(0x5e)
}

pub fn pair(d: &str) -> AccessPairRef {
    AccessPairRef {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

pub fn profile() -> ProfileId {
    ProfileId::parse("dev").unwrap()
}

fn scope() -> Scope {
    Scope {
        pairs: [pair("h1"), pair("h2")].into_iter().collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    }
}

fn enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::ClientRouting,
            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
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
    }
}

pub fn policy(env: &EnvironmentId, cutoff: Option<Timestamp>, revision: u64) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse("pol").unwrap(),
        revision: PolicyRevision(revision),
        profile: profile(),
        workspace: None,
        scope: scope(),
        environments: [env.clone()].into_iter().collect(),
        max_window: 4 * HOUR,
        pause: PauseState::Active,
        cutoff_at: cutoff,
        source: PolicySource::SetupDefault,
        lock_behavior: LockBehavior::Continue,
        connection: ConnectionPolicy::default(),
        default: false,
    }
}

fn owner_record(c: &ClientId, b: char) -> RemoteClientRecord {
    RemoteClientRecord {
        client: c.clone(),
        role: Role::Owner,
        key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", b.to_string().repeat(43)))
            .unwrap(),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{b}"),
        state: ClientState::Active,
        invitation: None,
        revoked_generation: None,
        revocation: None,
        created_at: t0(),
        updated_at: t0(),
        line: AppliedLine::Absent,
    }
}

pub struct World {
    pub store: Arc<Store>,
    pub clock: Arc<VirtualClock>,
    /// Shared: the runner's binding endpoints hold it too (⟨M06 W3⟩ runner Q7).
    pub runner: Arc<RunnerRuntime>,
    pub env: EnvironmentId,
    pub grant: GrantId,
    pub ca_a: SecretCaKey,
    pub ca_b: SecretCaKey,
    pub serial: std::sync::atomic::AtomicU64,
}

/// The grant's deadline: two hours after `t0`.
pub fn deadline() -> Timestamp {
    plus(t0(), 2 * HOUR)
}

/// A runner world (module docs). The clock's continuous reading starts at 1000 s.
pub fn world() -> World {
    world_with_faults(Arc::new(NoFaults))
}

pub fn world_with_faults(faults: Arc<dyn FaultHook>) -> World {
    let store = Arc::new(Store::open_in_memory(faults).unwrap());
    let clock = VirtualClock::at(t0());
    clock.advance_continuous_only(Duration::from_secs(1000));
    let env = heimdall_runtime::paired::init_runner(&store).unwrap();
    let grant = GrantId::from_random_bytes([0x61; 16]);
    store
        .transaction(|tx| {
            for (c, b) in [
                (controller_a(), 'A'),
                (controller_b(), 'B'),
                (stranger(), 'S'),
            ] {
                tx.enroll_bootstrap_owner(&owner_record(&c, b), t0())?;
            }
            tx.upsert_profile(&ProfileDefinition {
                id: profile(),
                revision: 1,
                scope: scope(),
                label: None,
            })?;
            tx.upsert_policy(&policy(&env, None, 1), false)?;
            for d in ["h1", "h2"] {
                tx.upsert_destination(&DestinationRecord {
                    id: DestinationId::parse(d).unwrap(),
                    alias: d.into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: t0(),
                })?;
            }
            let generation = tx.authority_generation()?;
            tx.insert_grant(&GrantSnapshot {
                id: grant.clone(),
                environment: env.clone(),
                scope: scope(),
                starts_at: t0(),
                deadline: Deadline {
                    intent: DeadlineIntent::Absolute("2026-11-21T11:00:00Z".into()),
                    resolved_at: t0(),
                    effective: deadline(),
                },
                parent: None,
                source: AuthorizationSource::StandingPolicy {
                    revision: PolicyRevision(1),
                },
                generation,
                state: GrantState::Active,
                enforcement: enforcement(),
            })?;
            tx.set_grant_origin(
                &grant,
                &GrantOrigin {
                    profile: profile(),
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
            Ok(())
        })
        .unwrap();
    let runner = RunnerRuntime::new(
        Arc::clone(&store),
        clock.clone(),
        Arc::new(KeyVault::new()),
        RunnerTimePolicy::default(),
        RunnerLifetime::SessionScope,
    );
    World {
        store,
        clock,
        runner: Arc::new(runner),
        env,
        grant,
        ca_a: SecretCaKey::generate().unwrap(),
        ca_b: SecretCaKey::generate().unwrap(),
        serial: std::sync::atomic::AtomicU64::new(100),
    }
}

impl World {
    /// The runner's current authority generation.
    pub fn generation(&self) -> u64 {
        self.store
            .transaction(|tx| tx.authority_generation())
            .unwrap()
            .0
    }

    /// Put `ca` in `issuer_trust` for `controller` (a runner-local widening).
    pub fn trust(&self, ca: &SecretCaKey, controller: &ClientId) {
        let entry = TrustedIssuer {
            ca_fingerprint: ca.fingerprint().unwrap(),
            ca_public_key: ca.public_openssh().unwrap(),
            controller: controller.clone(),
            trusted_at: self.clock.wall(),
        };
        self.store
            .transaction(|tx| tx.trust_remote_issuer(&entry))
            .unwrap();
    }

    /// Designate `c` as the time source (a runner-local widening).
    pub fn designate(&self, c: &ClientId) {
        let now = self.clock.wall();
        self.store
            .transaction(|tx| {
                Ok(heimdall_runtime::runner::time::designate_time_source(
                    tx, c, now,
                ))
            })
            .unwrap()
            .unwrap();
    }

    /// One time exchange from `c` on connection `conn`: challenge, `rtt` on the continuous
    /// clock only, then the answer with `controller_time`.
    pub fn exchange(
        &self,
        c: &ClientId,
        conn: u64,
        rtt: Duration,
        controller_time: Timestamp,
    ) -> Result<TimeSampleAccepted, heimdall_runtime::runner::time::TimeRefusal> {
        let session = TimeSession {
            client: c.clone(),
            connection: conn,
        };
        let time = self.runner.time();
        let nonce = self
            .store
            .transaction(|tx| Ok(time.challenge(tx, &session)))
            .unwrap()?
            .nonce;
        self.clock.advance(rtt);
        time.respond(&session, &nonce, controller_time)
    }

    /// A good sample from controller A (designated first): RTT 100 ms, the controller's clock
    /// equal to the runner's.
    pub fn good_sample(&self) -> TimeSampleAccepted {
        self.designate(&controller_a());
        let tc = self.clock.wall();
        self.exchange(&controller_a(), 1, Duration::from_millis(100), tc)
            .unwrap()
    }

    /// The runner's K_env public half for the grant (after a prepare).
    pub fn k_env(&self) -> PublicKeyInfo {
        self.runner
            .issuance()
            .keys()
            .public_key(&self.grant)
            .unwrap()
            .1
    }

    /// Sign a certificate for `prepared`'s key and `pair` with `ca`, valid until
    /// `valid_before`, with `permit-pty`.
    pub fn sign(
        &self,
        ca: &SecretCaKey,
        prepared: &PreparedRemoteGrant,
        pair: &AccessPairRef,
        valid_before: Timestamp,
    ) -> String {
        self.sign_with(
            ca,
            &self.k_env(),
            prepared,
            pair,
            valid_before,
            &["permit-pty"],
            None,
        )
    }

    /// Sign for `subject` (any key), with `extensions` and an optional principal override.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with(
        &self,
        ca: &SecretCaKey,
        subject: &PublicKeyInfo,
        prepared: &PreparedRemoteGrant,
        pair: &AccessPairRef,
        valid_before: Timestamp,
        extensions: &[&str],
        principal: Option<&str>,
    ) -> String {
        let serial = self
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let profile = CertificateProfile {
            serial,
            key_id: heimdall_credential::cert::key_id(
                &prepared.environment,
                &prepared.grant,
                serial,
            ),
            principal: principal
                .map(str::to_owned)
                .unwrap_or_else(|| heimdall_domain::issuance::principal_for(pair)),
            valid_after: self.clock.wall().as_second() - 60,
            valid_before: valid_before.as_second(),
            extensions: extensions
                .iter()
                .map(|e| (*e).to_owned())
                .collect::<BTreeSet<_>>(),
            subject_fingerprint: subject.fingerprint.clone(),
            ca_fingerprint: Some(ca.fingerprint().unwrap()),
        };
        build_and_sign(&profile, &subject.public_key().unwrap(), ca)
            .unwrap()
            .to_openssh()
            .unwrap()
    }

    /// Another key (not the grant's K_env), from a vault of its own.
    pub fn other_key() -> PublicKeyInfo {
        KeyVault::new().generate_ed25519().unwrap().1
    }

    /// Tombstone the grant on the runner (a delivered `grant_revoke`, or a local revoke): the
    /// tombstone and the generation move in one transaction, and the grant ends.
    pub fn tombstone(&self) {
        let now = self.clock.wall();
        let grant = self.grant.clone();
        self.store
            .transaction(|tx| {
                let generation = tx.authority_generation()?.next();
                tx.insert_tombstone(&Tombstone {
                    grant: grant.clone(),
                    cascade: Vec::new(),
                    generation,
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })?;
                let mut g = tx.grant(&grant)?.unwrap();
                g.state = GrantState::Revoked;
                tx.update_grant_state(&g)
            })
            .unwrap();
    }

    /// The paired caller of controller `c`.
    pub fn caller(c: &ClientId) -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid: 1000 },
            role: ClientRole::Owner,
            remote_client: Some(c.clone()),
        }
    }
}

/// An operation ID for fixtures that need one.
pub fn op() -> OperationId {
    OperationId::from_random_bytes([3; 16])
}
