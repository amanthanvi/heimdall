//! ⟨M03 wave 4, round 3 (ADR-0008 §17.22 item 11; W4-R09)⟩ One deterministic
//! existing-access `ensure` through the real `heimdall_app::Operations` and the real state
//! store, rendered as the bytes the byte-identity goldens pin
//! (`tests/contracts/golden/m02-existing-access-ensure/`).
//!
//! **The same file runs at the base commit.** The goldens were produced by compiling
//! exactly this file into the base tree `d6593a7c` (M03 wave 3, before wave 4) and
//! writing [`produce`]'s output; the current tree runs the same scenario and compares
//! byte for byte (`e2e_consumer_m03`'s `existing_access_ensure_bytes_match_base_goldens`).
//! It therefore uses only API both trees have.
//!
//! **How the goldens were made** (2026-11-11; nothing in this worktree's checkout was
//! touched): `git archive d6593a7c | tar -x -C <owner-only scratch dir S>`; this file
//! copied unchanged to `S/tests/e2e/m02_ensure_golden.rs` (SHA-256
//! `abfee06bdd82a005975b11be1e327cef0da832135aef9214de67621cea718af6` at recording);
//! `S/tests/e2e/consumer_m03.rs` given a scratch-only `#[tokio::test] record_base_goldens`
//! that writes [`produce`]'s four strings (each plus `\n`) to `$HM_R3D_GOLDEN_OUT`; then,
//! in `S` (its own `S/target`), `HM_R3D_GOLDEN_OUT=S/out cargo test -p heimdall --test
//! e2e_consumer_m03 record_base_goldens` (exit 0; a second run into `S/out2` was
//! byte-identical), and `S/out/*` copied to the golden directory. `S` was deleted
//! afterwards.
//!
//! **Determinism.** A `VirtualClock` at a fixed instant, a fixed environment, profile,
//! policy, destination, work ID and request ID, and a fixture existing-access adapter
//! (mechanism `native_agent`, fixed outcome). The only values that are random by design
//! are the IDs the runtime mints from its CSPRNG; each is replaced by a fixed
//! placeholder ([`NORMALIZED`]), and nothing else is touched.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs, dead_code)]

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot,
    InteractionRequirement, LockContinuity, PrepareOutcome, PreparePair, PrepareRequest,
    ReconcileOutcome, RevokeOutcome,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnvironmentId, GrantId, PolicyId, ProfileId, RequestId,
    WorkId,
};
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::provider::CredentialAvailability;
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, EnsureRequest, ExistingConnectionsPolicy,
    InteractionMode, NewAuthenticationExpiry, RefreshDependency, RequiredCapabilities,
    RevocationStatus, WaitMode, WorkloadIsolation,
};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_store::{RawDocuments, Store};
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The fields replaced before comparison: each is minted from the CSPRNG by design
/// (`heimdall_app::ids`), and each placeholder replaces exactly that ID's string.
pub const NORMALIZED: [&str; 3] = ["<operation_id>", "<grant_id>", "<binding_id>"];

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-02T09:00:00Z".parse().unwrap()
}

fn pair() -> AccessPair {
    AccessPair {
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::Unknown,
            new_authentication_expiry: NewAuthenticationExpiry::Unknown,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::Unknown,
            revocation: RevocationStatus::Unknown,
            identity_selection: None,
            new_signing_expiry: None,
            owned_multiplexing: None,
            remote_processes: None,
            unmanaged_connections: None,
            issuer_isolation: None,
        },
        evidence: Vec::new(),
    }
}

/// The existing-access fixture: a fixed outcome for every `prepare`.
struct Existing {
    descriptor: AdapterDescriptor,
}

fn outcome(req: &PrepareRequest<'_>) -> PrepareOutcome {
    PrepareOutcome {
        usable_until: req.grant.deadline.effective,
        offline_until: req.grant.deadline.effective,
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture".into(),
        availability: CredentialAvailability::ThroughDeadline,
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

impl CredentialAdapter for Existing {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    fn prepare<'a, 'b, 'c>(
        &'a self,
        req: PrepareRequest<'b>,
    ) -> BoxFut<'c, Result<PrepareOutcome, AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move { Ok(outcome(&req)) })
    }

    fn read_sources(&self, _pairs: &[PreparePair]) -> IntegrationSnapshot {
        IntegrationSnapshot::default()
    }

    fn prepare_from<'a, 'b, 'c, 'd>(
        &'a self,
        req: PrepareRequest<'b>,
        _sources: &'c IntegrationSnapshot,
    ) -> BoxFut<'d, Result<PrepareOutcome, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        Box::pin(async move { Ok(outcome(&req)) })
    }

    fn renew<'a, 'b, 'c>(
        &'a self,
        req: PrepareRequest<'b>,
    ) -> BoxFut<'c, Result<PrepareOutcome, AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move { Ok(outcome(&req)) })
    }

    fn reconcile<'a, 'b, 'c, 'd>(
        &'a self,
        _grant: &'b GrantId,
        _effect_token: &'c str,
    ) -> BoxFut<'d, Result<ReconcileOutcome, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        Box::pin(async move { Ok(ReconcileOutcome::Unknown) })
    }

    fn revoke<'a, 'b, 'c>(
        &'a self,
        _grant: &'b GrantId,
        _now: Timestamp,
    ) -> BoxFut<'c, Result<RevokeOutcome, AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            Ok(RevokeOutcome {
                remote_pending: Vec::new(),
                latest_possible_credential_expiry: None,
                remote_effects: Vec::new(),
            })
        })
    }
}

fn seed(store: &Store) {
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: false,
                    issuer_access: false,
                },
            })?;
            let scope = Scope {
                pairs: [pair()].into_iter().collect(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            };
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope,
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                },
                false,
            )?;
            tx.upsert_destination(&DestinationRecord {
                id: pair().destination,
                alias: "h1".into(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: t0(),
            })?;
            Ok(())
        })
        .unwrap();
}

/// The pinned bytes of one existing-access `ensure`, normalized ([`NORMALIZED`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Produced {
    /// `serde_json::to_string` of the returned `EnsureData`.
    pub result: String,
    /// The wire envelope the runtime's dispatcher renders for it.
    pub envelope: String,
    /// `recovery_intents.record_json`, exactly as stored.
    pub intent: String,
    /// The operation's stored request hash (hex).
    pub request_hash: String,
}

/// Run the scenario in a fresh owner-only scratch store under `dir`.
pub async fn produce(dir: &Path) -> Produced {
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store =
        Arc::new(Store::open(&state.join("state.db"), Arc::new(heimdall_store::NoFaults)).unwrap());
    seed(&store);
    let adapter = Arc::new(Existing {
        descriptor: AdapterDescriptor {
            identity: heimdall_domain::operation::AdapterIdentity {
                mechanism: "native_agent".to_owned(),
                instance: "fixture-1".to_owned(),
            },
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        },
    });
    let ops = Operations::start(OperationsConfig {
        store: Arc::clone(&store),
        clock: VirtualClock::at(t0()),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![adapter as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap();
    let caller = Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    });
    let done = ops
        .ensure(
            &caller,
            EnsureRequest {
                profile: ProfileId::parse("dev").unwrap(),
                profile_revision: None,
                scope: [pair()].into_iter().collect(),
                environment: None,
                work_id: WorkId::parse("w-golden").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("r-golden").unwrap(),
                interaction: InteractionMode::NonInteractive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    let op = done.operation_id.clone().expect("an operation");
    let data = done.data.clone();
    let (record, intents) = store
        .transaction(|tx| {
            Ok((
                tx.operation(&op)?,
                tx.raw_documents(RawDocuments::RecoveryIntents)?,
            ))
        })
        .unwrap();
    let record = record.expect("the operation record");
    let intent = intents
        .into_iter()
        .find(|(k, _)| k == op.as_str())
        .map(|(_, v)| v)
        .expect("the stored recovery intent");
    let result = serde_json::to_string(&data).unwrap();
    let envelope = serde_json::to_string(&heimdall_runtime::dispatch::render(Ok(done))).unwrap();
    let normalize = |s: String| {
        s.replace(op.as_str(), NORMALIZED[0])
            .replace(data.grant_id.as_str(), NORMALIZED[1])
            .replace(data.binding_id.as_str(), NORMALIZED[2])
    };
    Produced {
        result: normalize(result),
        envelope: normalize(envelope),
        intent: normalize(intent),
        request_hash: record.request_hash.to_hex(),
    }
}
