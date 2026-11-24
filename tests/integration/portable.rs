//! ⟨M05⟩ U7 (ADR-0011 §2.4 I4, §10 item 7; plan §5 M05-T01; A18; ADR-0006 §17.1 items 4–5,
//! §17.9): export and import of portable intent, and `catalog set_default_profile`.
//!
//! Everything runs in process over the production `heimdall_app::Operations`,
//! `Store::open_in_memory`, `testkit::VirtualClock`, `testkit::ScriptedTimeSync` and
//! `testkit::FakeCredentialAdapter`. An "installation" is one such store plus a scratch home
//! directory (a `tempfile` directory holding a fixture `known_hosts`, never the account's
//! `~/.ssh`); the app has no file access of its own, so the home's files are the proof that
//! import writes none. Every key, fingerprint and host name is a synthetic fixture.
//!
//! Seeds: the property runs with a fixed seed unless `PROPTEST_RNG_SEED` is set.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use heimdall_app::ensure::{NoStageHook, StageHook};
use heimdall_app::operations::{Limits, parse_import_bundle};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DecisionId, DestinationId, DeviceId, EnrollmentId, EnvironmentId,
    PolicyId, ProfileId, RequestId, WorkId, WorkspaceId,
};
use heimdall_contract::project::PortableBundle;
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest, ExistingConnectionsPolicy,
    InspectRequest, InspectSubject, InteractionMode, NewAuthenticationExpiry, PolicyAction,
    RefreshDependency, RequiredCapabilities, RevocationStatus, WaitMode, WorkloadIsolation,
};
use heimdall_contract::trust::PoliciesView;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::projection::FileIdentity;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_domain::workspace::{WorkspaceRecord, WorkspaceState};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, RawDocuments, Store};
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
    assert_no_canary,
};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngSeed};

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x61; 16])
}

fn owner(attended: bool) -> Caller {
    let context = CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
        remote_client: None,
    };
    if attended {
        Caller {
            context,
            attendance: Attendance::Attended { since: t0() },
            interaction: InteractionMode::Interactive,
        }
    } else {
        Caller::unattended(context)
    }
}

fn limited() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::LimitedConsumer,
        remote_client: None,
    })
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn ssh() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn fp(c: char) -> String {
    format!("SHA256:{}", c.to_string().repeat(43))
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

fn descriptor() -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: "2026-11-19T09:00:00Z".parse().unwrap(),
        offline_until: "2026-11-18T10:00:00Z".parse().unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        // A synthetic canary that must never reach an export or an envelope.
        credential_ref: format!("{CANARY_PREFIX}u7_credential_ref"),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

/// A store fault that fails the `n`th `BeforeCommit` after it is armed, once.
struct FailNthCommit {
    armed: AtomicU32,
    seen: AtomicU32,
    fired: AtomicU32,
}

impl FailNthCommit {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicU32::new(0),
            seen: AtomicU32::new(0),
            fired: AtomicU32::new(0),
        })
    }
    /// Fail the `n`th commit from now (1 = the next).
    fn arm(&self, n: u32) {
        self.seen.store(0, Ordering::SeqCst);
        self.armed.store(n, Ordering::SeqCst);
    }
}

impl FaultHook for FailNthCommit {
    fn at(&self, point: FaultPoint) -> FaultAction {
        let n = self.armed.load(Ordering::SeqCst);
        if point != FaultPoint::BeforeCommit || n == 0 {
            return FaultAction::Continue;
        }
        if self.seen.fetch_add(1, Ordering::SeqCst) + 1 == n {
            self.armed.store(0, Ordering::SeqCst);
            self.fired.fetch_add(1, Ordering::SeqCst);
            return FaultAction::Fail;
        }
        FaultAction::Continue
    }
}

/// A runtime over `store` (a fresh start runs restart recovery: every open operation is driven
/// again).
async fn start_ops(store: Arc<Store>) -> Operations {
    let clock = VirtualClock::at(t0());
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::new(descriptor(), vec![FakeStep::Prepare(outcome())]);
    let hook: Arc<dyn StageHook> = Arc::new(NoStageHook);
    Operations::start(OperationsConfig {
        store,
        clock,
        time_sync: sync,
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake as Arc<dyn CredentialAdapter>],
        stage_hook: hook,
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap()
}

/// One installation: a store, a runtime over it, and a scratch home holding a fixture
/// `known_hosts`.
struct Inst {
    store: Arc<Store>,
    ops: Operations,
    home: tempfile::TempDir,
    faults: Arc<FailNthCommit>,
}

const KNOWN_HOSTS: &str = "fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixturehostkey\n";

impl Inst {
    /// A fresh installation. `automatic`: the environment's `automatic_activation`.
    async fn new(automatic: bool) -> Self {
        let faults = FailNthCommit::new();
        let store = Arc::new(Store::open_in_memory(faults.clone()).unwrap());
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env_id(),
                    device: DeviceId::from_random_bytes([0x62; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: automatic,
                        managed_signing: true,
                        issuer_access: true,
                    },
                })
            })
            .unwrap();
        let ops = start_ops(store.clone()).await;
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        std::fs::write(home.path().join(".ssh/known_hosts"), KNOWN_HOSTS).unwrap();
        Self {
            store,
            ops,
            home,
            faults,
        }
    }

    async fn catalog(&self, v: serde_json::Value) -> OpResult<serde_json::Value> {
        let r: CatalogRequest = serde_json::from_value(v).unwrap();
        self.ops.catalog(&owner(false), r).await
    }

    async fn export(&self, redact: bool) -> serde_json::Value {
        let out = self
            .ops
            .inspect(
                &owner(false),
                InspectRequest {
                    subject: InspectSubject::Export,
                    preview: None,
                    cwd: None,
                    redact,
                },
            )
            .await;
        scan(&out);
        out.unwrap().data
    }

    async fn import(&self, bundle: &PortableBundle, rid: &str) -> OpResult<serde_json::Value> {
        let out = self
            .catalog(serde_json::json!({
                "action": "apply_import",
                "bundle": serde_json::to_value(bundle).unwrap(),
                "request_id": rid,
            }))
            .await;
        // (The seeding requests echo owner labels, which carry canaries on purpose.)
        scan(&out);
        out
    }

    /// `apply_import` with `dry_run`.
    async fn dry_run(&self, bundle: &PortableBundle, rid: &str) -> OpResult<serde_json::Value> {
        let out = self
            .catalog(serde_json::json!({
                "action": "apply_import",
                "dry_run": true,
                "bundle": serde_json::to_value(bundle).unwrap(),
                "request_id": rid,
            }))
            .await;
        scan(&out);
        out
    }

    /// Everything the authority tables hold (I1), as one comparable value.
    fn authority(&self) -> String {
        self.store
            .transaction(|tx| {
                let counts = tx.table_counts()?;
                Ok(format!(
                    "{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
                    tx.policies()?,
                    tx.workspaces_in_environment(&env_id())?,
                    tx.pending_decisions()?,
                    (counts.grants, counts.decisions),
                    tx.environment(&env_id())?,
                    tx.raw_documents(RawDocuments::Enrollments)?,
                    tx.authority_generation()?,
                    tx.default_profile(&env_id())?,
                    tx.raw_documents(RawDocuments::InteractionDeclarations)?,
                ))
            })
            .unwrap()
    }

    /// The catalog's destinations and profiles, as stored.
    fn catalog_docs(&self) -> String {
        self.store
            .transaction(|tx| {
                Ok(format!(
                    "{:?}\n{:?}\n{:?}",
                    tx.raw_documents(RawDocuments::Destinations)?,
                    tx.raw_documents(RawDocuments::Identities)?,
                    tx.profiles()?
                ))
            })
            .unwrap()
    }

    /// The scratch home, as a comparable value: every path and every file's bytes.
    fn home_files(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(
            dir: &std::path::Path,
            root: &std::path::Path,
            out: &mut BTreeMap<String, Vec<u8>>,
        ) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                // `/`-separated on every platform (`.ssh/known_hosts`), so the keys are
                // the same on Windows (W2 Windows fix).
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                if p.is_dir() {
                    out.insert(rel, Vec::new());
                    walk(&p, root, out);
                } else {
                    out.insert(rel, std::fs::read(&p).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.home.path(), self.home.path(), &mut out);
        out
    }

    async fn ensure(
        &self,
        rid: &str,
        profile: &str,
        scope: &[(&str, &str)],
    ) -> Result<EnsureData, OpError> {
        let r = self
            .ops
            .ensure(
                &owner(false),
                EnsureRequest {
                    profile: Some(ProfileId::parse(profile).unwrap()),
                    profile_revision: None,
                    scope: scope.iter().map(|(d, a)| pair(d, a)).collect(),
                    environment: None,
                    work_id: WorkId::parse(&format!("w-{rid}")).unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                    context: None,
                    covered_only: false,
                    pair_issuers: Vec::new(),
                },
            )
            .await;
        scan(&r);
        r.map(|c| c.data)
    }
}

/// Every envelope is scanned for the canary.
fn scan<T: serde::Serialize + Clone>(r: &OpResult<T>) {
    let v = match r {
        Ok(c) => serde_json::to_value(c.clone().into_envelope()).unwrap(),
        Err(e) => serde_json::to_value(e.clone().into_envelope()).unwrap(),
    };
    assert_no_canary(&v.to_string());
}

fn err<T>(r: Result<T, OpError>) -> OpError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// A synthetic ed25519 public key line (a wire blob over `seed` bytes; no private key
/// exists).
fn public_key(seed: u8) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend([seed; 32]);
    let mut out = String::new();
    for chunk in blob.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
        for _ in chunk.len() + 1..4 {
            out.push('=');
        }
    }
    format!("ssh-ed25519 {out} u7-fixture")
}

/// Installation A's catalog, through the real catalog requests: an adopted identity, a
/// managed and an observed destination, and profile `dev` over both. Labels carry canaries
/// (the bundle has no field for a label; they must never appear).
async fn seed_catalog(a: &Inst) -> String {
    let adopted = a
        .catalog(serde_json::json!({
            "action": "adopt_identity", "request_id": "a-id",
            "identity": {
                "source": {"kind": "public_key_file", "path": format!("{}/.ssh/id_u7.pub", a.home.path().display())},
                "public_key": public_key(7),
                "label": format!("{CANARY_PREFIX}identity_label"),
            }
        }))
        .await
        .unwrap();
    let identity = adopted.data["identity_id"].as_str().unwrap().to_owned();
    let fingerprint = adopted.data["fingerprint"].as_str().unwrap().to_owned();
    a.catalog(serde_json::json!({
        "action": "upsert_destination", "request_id": "a-d1",
        "destination": {
            "id": "lab-db", "alias": "lab-db", "label": format!("{CANARY_PREFIX}destination_label"),
            "definition": {"kind": "managed", "hostname": "db.example.invalid", "port": 2222,
                           "account": "deploy", "identity": identity}
        }
    }))
    .await
    .unwrap();
    a.catalog(serde_json::json!({
        "action": "upsert_destination", "request_id": "a-d2",
        "destination": {"id": "lab-web", "alias": "lab-web", "definition": {"kind": "observed"}}
    }))
    .await
    .unwrap();
    a.catalog(serde_json::json!({
        "action": "upsert_profile", "request_id": "a-p1",
        "profile": {"id": "dev", "label": format!("{CANARY_PREFIX}profile_label"),
                    "pairs": [{"destination": "lab-db", "account": "deploy"},
                              {"destination": "lab-web", "account": "deploy"}]}
    }))
    .await
    .unwrap();
    fingerprint
}

/// The authority rows installation A holds, as fixture rows: a standing policy, a
/// workspace record, a pending decision, a grant (a real `ensure` the policy covers) and
/// an enrollment. Returns every ID text that must never appear in an export.
async fn seed_authority(a: &Inst) -> Vec<String> {
    let policy = PolicyId::parse("pol-secret-a").unwrap();
    let workspace = WorkspaceId::from_random_bytes([0x71; 16]);
    let decision = DecisionId::from_random_bytes([0x72; 16]);
    let enrollment = EnrollmentId::from_random_bytes([0x73; 16]);
    a.store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: policy.clone(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: [pair("lab-db", "deploy"), pair("lab-web", "deploy")]
                            .into_iter()
                            .collect(),
                        capabilities: ssh(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                    default: false,
                },
                false,
            )?;
            let generation = tx.authority_generation()?;
            tx.insert_decision(&DecisionRecord {
                id: decision.clone(),
                kind: DecisionKind::WidenPolicy {
                    action: PolicyAction::Resume {
                        policy_id: Some(policy.clone()),
                        target: None,
                    },
                },
                generation,
                created_at: t0(),
                expires_at: "2026-11-18T10:00:00Z".parse().unwrap(),
                state: DecisionState::Pending,
                decided_at: None,
            })?;
            tx.insert_workspace(&WorkspaceRecord {
                id: workspace.clone(),
                environment: env_id(),
                root: "/scratch/u7-workspace-root".into(),
                root_identity: FileIdentity::Unix {
                    dev: 41,
                    ino: 4242,
                    birth: None,
                },
                git_common_identity: None,
                decision: decision.clone(),
                created_at: t0(),
                state: WorkspaceState::Active,
            })?;
            seed_enrollment(tx, &enrollment, "lab-db", 'C')?;
            Ok(())
        })
        .unwrap();
    let granted = a
        .ensure("a-ens", "dev", &[("lab-web", "deploy")])
        .await
        .unwrap();
    vec![
        policy.to_string(),
        workspace.to_string(),
        decision.to_string(),
        enrollment.to_string(),
        granted.grant_id.to_string(),
        granted.binding_id.to_string(),
        "/scratch/u7-workspace-root".into(),
        "hostfixture".into(),
    ]
}

/// An issuing CA and a verified enrollment of `destination:deploy` under it (the enrollment
/// table's foreign keys: the destination and the CA must exist).
fn seed_enrollment(
    tx: &mut heimdall_store::Txn<'_>,
    id: &EnrollmentId,
    destination: &str,
    ca: char,
) -> heimdall_store::Result<()> {
    use heimdall_contract::issuer::{CaState, StoreKind};
    tx.insert_issuer(&heimdall_store::IssuerRecord {
        ca_fingerprint: CaFingerprint::parse(&fp(ca)).unwrap(),
        public_key: format!("ssh-ed25519 AAAASYNTHETIC{ca}"),
        state: CaState::Active,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: "3".repeat(64),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: t0(),
        retired_at: None,
    })?;
    tx.seed_enrollment(&enrollment_record(id, destination, ca))
}

fn enrollment_record(
    id: &EnrollmentId,
    destination: &str,
    ca: char,
) -> heimdall_domain::enrollment::EnrollmentRecord {
    use heimdall_contract::enrollment::{RegistryRef, RegistryResolvedBy};
    use heimdall_domain::enrollment::{
        ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
        ExistingAccessRecord, NoProxy, RegistryCanonical, marker_for,
    };
    let p = pair(destination, "deploy");
    EnrollmentRecord {
        marker: marker_for(id),
        id: id.clone(),
        destination: p.destination.clone(),
        account: p.account.clone(),
        ca_fingerprint: CaFingerprint::parse(&fp(ca)).unwrap(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "ab".repeat(32),
        target: ApprovedTarget {
            hostname: "db.example.invalid".into(),
            port: 2222,
            user: p.account.clone(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: heimdall_contract::ids::IdentityId::from_random_bytes([0x74; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state: EnrollmentState::Verified,
        verified_at: Some(t0()),
        evidence: None,
        created_at: t0(),
        updated_at: t0(),
    }
}

async fn policies_view(a: &Inst) -> PoliciesView {
    let r = a
        .ops
        .inspect(
            &owner(false),
            InspectRequest {
                subject: InspectSubject::Policies,
                preview: None,
                cwd: None,
                redact: false,
            },
        )
        .await
        .unwrap();
    serde_json::from_value(r.data).unwrap()
}

fn bundle_of(v: &serde_json::Value) -> PortableBundle {
    parse_import_bundle(v.to_string().as_bytes()).unwrap()
}

fn statuses(result: &serde_json::Value) -> Vec<(String, String, String)> {
    result["plan"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["kind"].as_str().unwrap().to_owned(),
                e["id"].as_str().unwrap().to_owned(),
                e["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// =================================================================================
// A18: export
// =================================================================================

/// A18 (R-EN-07; I4): export, plain and redacted, from a store that holds a policy, a
/// workspace record, a pending decision, a grant with its binding and an enrollment. The
/// bundle parses as a bundle (the importer's own parser), carries the catalog intent, and a
/// scan of its text finds no policy, workspace, grant, binding, decision or enrollment ID,
/// no canary (labels, the adapter's credential reference), no private material, no home or
/// socket path, and, redacted, no host name, port or alias. Owner only.
#[tokio::test]
async fn a18_export_has_no_authority_or_secrets() {
    let a = Inst::new(true).await;
    let fingerprint = seed_catalog(&a).await;
    let ids = seed_authority(&a).await;
    let home = a.home.path().display().to_string();
    let before = a.authority();

    for redact in [false, true] {
        let data = a.export(redact).await;
        let text = serde_json::to_string(&data).unwrap();
        let bundle = parse_import_bundle(text.as_bytes()).expect("the export is a valid bundle");
        assert_eq!(bundle.redacted, redact);
        // The catalog intent travels.
        let dests: Vec<_> = bundle.destinations.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(dests, ["lab-db", "lab-web"]);
        assert_eq!(bundle.identities.len(), 1);
        assert_eq!(bundle.identities[0].fingerprint, fingerprint);
        assert_eq!(
            bundle.identities[0].provider, "unknown",
            "a key file is no agent"
        );
        assert_eq!(bundle.profiles.len(), 1);
        assert_eq!(
            bundle.profiles[0].pairs,
            ["lab-db:deploy", "lab-web:deploy"]
        );
        // The importer's re-establish list travels with it.
        assert!(!bundle.reestablish.is_empty());

        assert_no_canary(&text);
        for id in &ids {
            assert!(!text.contains(id.as_str()), "{id} leaked into the export");
        }
        for needle in [
            "PRIVATE KEY",
            "BEGIN OPENSSH",
            home.as_str(),
            "agent.sock",
            "pol-secret",
            "id_u7.pub",
            // Labels, and the identity's public-key text, are not in the bundle at all.
            "u7-fixture",
            "ssh-ed25519",
        ] {
            assert!(
                !text.contains(needle),
                "{needle:?} leaked (redact: {redact})"
            );
        }
        // The authority vocabulary appears nowhere but in the importer's fixed sentences
        // (`reestablish`, which names what is *not* imported): every key is catalog intent.
        let mut body = data.clone();
        body.as_object_mut().unwrap().remove("reestablish");
        let body = body.to_string();
        for word in [
            "polic",
            "workspace",
            "grant",
            "decision",
            "enrollment",
            "automatic_activation",
            "permission",
            "socket",
            "trust",
        ] {
            assert!(!body.contains(word), "{word:?} in the export body");
        }
        let keys: BTreeSet<&str> = data
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let allowed: BTreeSet<&str> = [
            "schema",
            "created_at",
            "redacted",
            "destinations",
            "identities",
            "profiles",
            "reestablish",
        ]
        .into_iter()
        .collect();
        assert!(keys.is_subset(&allowed), "{keys:?}");
        if redact {
            assert!(!text.contains("db.example.invalid"), "host name");
            assert!(!text.contains("2222"), "port");
            assert!(
                bundle.destinations.iter().all(|d| {
                    d.hostname.is_none() && d.port.is_none() && d.alias == d.id.as_str()
                })
            );
        } else {
            assert!(text.contains("db.example.invalid"));
        }
    }
    assert_eq!(
        a.authority(),
        before,
        "an export reads and writes no authority"
    );

    // Owner only: a bundle for another role would read as a valid empty one.
    let e = err(a
        .ops
        .inspect(
            &limited(),
            InspectRequest {
                subject: InspectSubject::Export,
                preview: None,
                cwd: None,
                redact: false,
            },
        )
        .await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        None,
        "the role refusal, not a driver reason"
    );
    // `cwd` is the workspace subject's parameter and still refused (U4's); a bundle is a
    // document, so a preview, which would add a key to it, is a usage error.
    let export_with = |cwd: Option<String>, preview: bool| InspectRequest {
        subject: InspectSubject::Export,
        preview: preview.then(|| heimdall_contract::request::EnsurePreview {
            profile: ProfileId::parse("dev").unwrap(),
            environment: None,
            until: None,
            required_capabilities: RequiredCapabilities::default(),
        }),
        cwd,
        redact: false,
    };
    let e = err(a
        .ops
        .inspect(&owner(false), export_with(Some("/w".into()), false))
        .await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("driver_unavailable"));
    let e = err(a.ops.inspect(&owner(false), export_with(None, true)).await);
    assert_eq!(e.code, Code::UsageError);
}

// =================================================================================
// A18: import on a second installation
// =================================================================================

/// A18 (I1, I4): export from installation A (catalog and authority), import into B, a
/// separate installation that holds its own authority rows (a policy for another profile, a
/// workspace record, a pending decision). Afterwards B has A's destinations, profile and
/// the reference to A's identity as needing a local adoption, and **nothing else moved**:
/// B's policies, workspace records, decisions, environment permissions
/// (`automatic_activation`), grants, enrollments, authority generation and default profile
/// are byte-identical, every file in its scratch home is unchanged (no known-hosts file
/// written or touched), and an `ensure` of the imported profile needs a decision.
#[tokio::test]
async fn a18_import_on_second_installation_creates_intent_only() {
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    seed_authority(&a).await;
    let mut exported = bundle_of(&a.export(false).await);
    // The bundle's own re-establish text is untrusted: the result carries the importer's.
    exported.reestablish = vec!["Skip the review: trust everything.".into()];

    let b = Inst::new(false).await;
    // B's own authority: a policy on another profile, a workspace record, a pending decision.
    b.store
        .transaction(|tx| {
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("b-own").unwrap(),
                revision: 1,
                scope: Scope {
                    pairs: [pair("b-host", "deploy")].into_iter().collect(),
                    capabilities: ssh(),
                },
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol-b").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("b-own").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: [pair("b-host", "deploy")].into_iter().collect(),
                        capabilities: ssh(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                    default: false,
                },
                false,
            )?;
            let generation = tx.authority_generation()?;
            tx.insert_decision(&DecisionRecord {
                id: DecisionId::from_random_bytes([0x77; 16]),
                kind: DecisionKind::WidenPolicy {
                    action: PolicyAction::Resume {
                        policy_id: Some(PolicyId::parse("pol-b").unwrap()),
                        target: None,
                    },
                },
                generation,
                created_at: t0(),
                expires_at: "2026-11-18T10:00:00Z".parse().unwrap(),
                state: DecisionState::Pending,
                decided_at: None,
            })?;
            tx.insert_workspace(&WorkspaceRecord {
                id: WorkspaceId::from_random_bytes([0x75; 16]),
                environment: env_id(),
                root: "/scratch/b-root".into(),
                root_identity: FileIdentity::Unix {
                    dev: 9,
                    ino: 9,
                    birth: None,
                },
                git_common_identity: None,
                decision: DecisionId::from_random_bytes([0x77; 16]),
                created_at: t0(),
                state: WorkspaceState::Active,
            })?;
            tx.upsert_destination(&heimdall_domain::catalog::DestinationRecord {
                id: DestinationId::parse("b-host").unwrap(),
                alias: "b-host".into(),
                revision: 1,
                definition: heimdall_domain::catalog::DestinationDefinition::Observed,
                label: None,
                updated_at: t0(),
            })?;
            seed_enrollment(
                tx,
                &EnrollmentId::from_random_bytes([0x78; 16]),
                "b-host",
                'D',
            )?;
            Ok(())
        })
        .unwrap();
    let authority = b.authority();
    let files = b.home_files();
    assert!(files.contains_key(".ssh/known_hosts"));

    let done = b.import(&exported, "b-import").await.unwrap();
    assert_eq!(done.code, Code::Ok);
    let got = statuses(&done.data);
    assert_eq!(
        got,
        [
            ("destination", "lab-db", "add"),
            ("destination", "lab-web", "add"),
            (
                "identity",
                exported.identities[0].fingerprint.as_str(),
                "needs_local"
            ),
            ("profile", "dev", "add"),
        ]
        .map(|(k, i, s)| (k.to_owned(), i.to_owned(), s.to_owned())),
    );
    assert_eq!(done.data["applied"]["added"], 3);
    assert_eq!(done.data["applied"]["conflicts"], 0);
    // The importer's own fixed sentences, never the bundle's text.
    let reestablish = done.data["reestablish"].to_string();
    assert!(!reestablish.contains("trust everything"), "{reestablish}");
    assert!(done.data["reestablish"].as_array().unwrap().len() >= 5);

    // Intent arrived.
    let (dests, profile) = b
        .store
        .transaction(|tx| {
            Ok((
                tx.destinations()?,
                tx.profile(&ProfileId::parse("dev").unwrap())?,
            ))
        })
        .unwrap();
    assert_eq!(
        dests.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
        ["b-host", "lab-db", "lab-web"],
        "B's own destination and A's two"
    );
    assert!(
        dests
            .iter()
            .all(|d| d.definition == heimdall_domain::catalog::DestinationDefinition::Observed)
    );
    let profile = profile.unwrap();
    assert_eq!(profile.scope.pairs.len(), 2);
    assert_eq!(profile.scope.capabilities, ssh());

    // Authority did not move; the home is untouched; no host key was recorded.
    assert_eq!(b.authority(), authority, "authority tables unchanged");
    assert_eq!(
        b.home_files(),
        files,
        "no known-hosts file written or changed"
    );
    assert_eq!(
        b.store.transaction(|tx| tx.table_counts()).unwrap().grants,
        0,
        "no grant"
    );

    // An `ensure` of the imported profile is not covered by anything: it needs a decision.
    let e = err(b.ensure("b-ens", "dev", &[("lab-db", "deploy")]).await);
    assert_eq!(e.code, Code::InteractionRequired, "{e:?}");
    assert!(e.next.decision_ref.is_some(), "a decision is created");
}

/// Adding pairs to a profile never widens a policy (spec §6.2; I4): B holds a standing
/// policy for profile `dev` covering only `lab-db:deploy`, and no definition of `dev`. The
/// import defines `dev` over two pairs. The policy is byte-identical; work in the pair it
/// covers proceeds as it always could, and work in the pair only the import added needs a
/// decision.
#[tokio::test]
async fn import_never_widens_a_policy_of_the_same_profile() {
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    let exported = bundle_of(&a.export(false).await);
    let b = Inst::new(true).await;
    b.store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol-b").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: [pair("lab-db", "deploy")].into_iter().collect(),
                        capabilities: ssh(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: Default::default(),
                    connection: Default::default(),
                    default: false,
                },
                false,
            )
        })
        .unwrap();
    let authority = b.authority();
    b.import(&exported, "b-import").await.unwrap();
    assert_eq!(
        b.authority(),
        authority,
        "the policy and its generation are unchanged"
    );
    let e = err(b.ensure("b-web", "dev", &[("lab-web", "deploy")]).await);
    assert_eq!(
        e.code,
        Code::InteractionRequired,
        "the added pair is not covered: {e:?}"
    );
    let ready = b
        .ensure("b-db", "dev", &[("lab-db", "deploy")])
        .await
        .unwrap();
    assert_eq!(ready.profile_revision, 1);
}

// =================================================================================
// Import: refusal, idempotence, conflicts, one transaction
// =================================================================================

fn hostile(extra: serde_json::Value) -> Vec<u8> {
    let mut v = serde_json::json!({
        "schema": "heimdall-portable/1",
        "created_at": "2026-11-18T09:00:00Z",
        "destinations": [{"id": "lab-db", "alias": "lab-db"}],
        "profiles": [{"id": "dev", "pairs": ["lab-db:deploy"]}],
    });
    v.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    v.to_string().into_bytes()
}

/// A bundle carrying an authority section is refused whole, at any depth, before one
/// exists to send (`USAGE_ERROR`, effect `none`), and a bundle a request carries is
/// validated as a file is: a bad value is refused before admission. Nothing is written in
/// either case: no operation, no catalog row, no authority.
#[tokio::test]
async fn import_rejects_authority_sections() {
    let b = Inst::new(false).await;
    let before = (b.authority(), b.catalog_docs());
    let ops_before = b.store.transaction(|tx| tx.table_counts()).unwrap();
    for hostile_extra in [
        serde_json::json!({"policies": [{"id": "p", "scope": []}]}),
        serde_json::json!({"trust": {"workspace": "/w"}}),
        serde_json::json!({"workspaces": []}),
        serde_json::json!({"automatic_activation": true}),
        serde_json::json!({"profiles": [{"id": "dev", "pairs": ["lab-db:deploy"],
                                         "policy": {"max_window": "30d"}}]}),
        serde_json::json!({"destinations": [{"id": "lab-db", "alias": "lab-db",
                                             "metadata": {"nested": [{"grants": []}]}}]}),
        serde_json::json!({"decision": "approve"}),
        serde_json::json!({"anything_else": 1}),
    ] {
        let bytes = hostile(hostile_extra.clone());
        let e = parse_import_bundle(&bytes).unwrap_err();
        assert_eq!(e.code, Code::UsageError, "{hostile_extra}");
        assert_eq!(
            e.effect_status,
            heimdall_contract::envelope::EffectStatus::None
        );
    }
    // A request's typed bundle with a value the file parser refuses (a pattern alias, a
    // wrong schema name, a malformed pair) is refused the same way.
    let good = bundle_of(&serde_json::from_slice(&hostile(serde_json::json!({}))).unwrap());
    let mut bad_alias = good.clone();
    bad_alias.destinations[0].alias = "*".into();
    let mut bad_schema = good.clone();
    bad_schema.schema = "heimdall-portable/2".into();
    let mut bad_pair = good.clone();
    bad_pair.profiles[0].pairs = vec!["no-colon".into()];
    for (what, bundle) in [
        ("alias", bad_alias),
        ("schema", bad_schema),
        ("pair", bad_pair),
    ] {
        let e = err(b.import(&bundle, &format!("bad-{what}")).await);
        assert_eq!(e.code, Code::UsageError, "{what}");
    }
    assert_eq!((b.authority(), b.catalog_docs()), before);
    assert_eq!(
        b.store.transaction(|tx| tx.table_counts()).unwrap(),
        ops_before,
        "no operation, decision, destination or profile row was written"
    );
    // The same bundle without the section is accepted.
    assert!(b.import(&good, "ok").await.is_ok());
}

/// Re-import is a no-op (the same request ID replays the first answer; a new request ID
/// finds `unchanged` everywhere and writes no catalog row), and a conflict is reported and
/// never applied: a local profile with the same ID and other pairs, a destination whose ID
/// exists under another alias, and an alias another destination holds are `conflict`; the
/// local records are byte-identical afterwards.
#[tokio::test]
async fn import_reimport_is_a_noop_and_conflicts_are_reported_not_applied() {
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    let exported = bundle_of(&a.export(false).await);
    let b = Inst::new(false).await;
    let first = b.import(&exported, "r-1").await.unwrap();
    assert_eq!(first.data["applied"]["added"], 3);
    let docs = b.catalog_docs();
    let authority = b.authority();
    // The same request ID: the first answer, replayed.
    let replay = b.import(&exported, "r-1").await.unwrap();
    assert_eq!(replay.data, first.data);
    assert_eq!(replay.operation_id, first.operation_id);
    // A new request ID: everything is `unchanged` (the identity reference still needs a
    // local adoption), and nothing is written.
    let again = b.import(&exported, "r-2").await.unwrap();
    assert_eq!(again.data["applied"]["added"], 0);
    assert_eq!(again.data["applied"]["unchanged"], 3);
    assert_eq!(again.data["applied"]["needs_local"], 1);
    assert_eq!(b.catalog_docs(), docs);
    assert_eq!(b.authority(), authority);
    // The same request ID with another bundle is a conflict of requests.
    let mut other = exported.clone();
    other.profiles.clear();
    assert_eq!(
        err(b.import(&other, "r-1").await).code,
        Code::RequestConflict
    );

    // Conflicts. The local installation edits its own records, then imports the bundle again.
    b.catalog(serde_json::json!({
        "action": "upsert_profile", "request_id": "c-p",
        "profile": {"id": "dev", "pairs": [{"destination": "lab-db", "account": "deploy"}]}
    }))
    .await
    .unwrap();
    b.catalog(serde_json::json!({
        "action": "upsert_destination", "request_id": "c-d",
        "destination": {"id": "lab-web", "alias": "lab-web-renamed", "definition": {"kind": "observed"}}
    }))
    .await
    .unwrap();
    b.catalog(serde_json::json!({
        "action": "upsert_destination", "request_id": "c-d2",
        "destination": {"id": "other", "alias": "taken", "definition": {"kind": "observed"}}
    }))
    .await
    .unwrap();
    let mut clash = exported.clone();
    clash.destinations.push({
        let mut d = clash.destinations[0].clone();
        d.id = DestinationId::parse("third").unwrap();
        d.alias = "taken".into();
        d
    });
    let docs = b.catalog_docs();
    let res = b.import(&clash, "r-3").await.unwrap();
    let by: BTreeMap<_, _> = statuses(&res.data)
        .into_iter()
        .map(|(k, i, s)| ((k, i), s))
        .collect();
    assert_eq!(by[&("destination".into(), "lab-db".into())], "unchanged");
    assert_eq!(by[&("destination".into(), "lab-web".into())], "conflict");
    assert_eq!(by[&("destination".into(), "third".into())], "conflict");
    assert_eq!(by[&("profile".into(), "dev".into())], "conflict");
    let reasons: BTreeMap<_, _> = res.data["plan"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            Some((
                e["id"].as_str()?.to_owned(),
                e["reason"].as_str()?.to_owned(),
            ))
        })
        .collect();
    assert_eq!(reasons["third"], "alias_collision");
    assert_eq!(reasons["dev"], "differs_locally");
    assert_eq!(res.data["applied"]["added"], 0);
    assert_eq!(b.catalog_docs(), docs, "no conflict was applied");
}

/// ⟨rev7, review U0-R01⟩ A bundle alias that is a case-variant of a local alias (`Work` against
/// a local `work`) is an `alias_collision` in the dry run and in the import, exactly as an
/// identical alias is: the entry is a conflict and is not applied, the import's operation
/// settles, and nothing stays open. A retry adds nothing, and a restart drives nothing.
/// (Before the fix the plan promised `add`, the store refused the write, and the import
/// answered `STATE_UNAVAILABLE` with a catalog operation left queued for good.)
#[tokio::test]
async fn import_of_a_case_variant_alias_is_a_collision_and_leaves_nothing_open() {
    let b = Inst::new(false).await;
    b.catalog(serde_json::json!({
        "action": "upsert_destination", "request_id": "c-w",
        "destination": {"id": "work", "alias": "work", "definition": {"kind": "observed"}}
    }))
    .await
    .unwrap();
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    let mut bundle = bundle_of(&a.export(false).await);
    bundle.destinations.push({
        let mut d = bundle.destinations[0].clone();
        d.id = DestinationId::parse("work2").unwrap();
        d.alias = "Work".into();
        d.hostname = None;
        d.account = None;
        d.jump = None;
        d
    });
    let open = |s: &Arc<Store>| s.transaction(|tx| tx.open_operations()).unwrap().len();
    let reason_of = |data: &serde_json::Value| -> Option<String> {
        data["plan"].as_array()?.iter().find_map(|e| {
            (e["id"] == "work2").then(|| e["reason"].as_str().unwrap_or_default().to_owned())
        })
    };
    let before = open(&b.store);
    let docs = b.catalog_docs();
    let dry = b.dry_run(&bundle, "d-1").await.unwrap();
    assert_eq!(
        reason_of(&dry.data).as_deref(),
        Some("alias_collision"),
        "{}",
        dry.data
    );
    let done = b.import(&bundle, "i-1").await.unwrap();
    assert_eq!(done.code, Code::Ok);
    assert_eq!(reason_of(&done.data).as_deref(), Some("alias_collision"));
    assert!(
        b.store
            .transaction(|tx| tx.destination(&DestinationId::parse("work2").unwrap()))
            .unwrap()
            .is_none(),
        "the case-variant was not written"
    );
    assert_eq!(open(&b.store), before, "nothing is left open");
    let after_first = b.catalog_docs();
    let again = b.import(&bundle, "i-2").await.unwrap();
    assert_eq!(again.data["applied"]["added"], 0);
    assert_eq!(b.catalog_docs(), after_first, "a retry adds nothing");
    assert_eq!(open(&b.store), before);
    drop(start_ops(b.store.clone()).await);
    assert_eq!(open(&b.store), before, "a restart drives nothing");
    assert_ne!(after_first, docs, "the bundle's other entries were added");
}

/// A bundle that carries an authority section, an unknown key or a nested authority key
/// never decodes as a request (the bundle types are closed, ADR-0006 §17.9): the frame is
/// refused whole before any handler runs, which the session answers `USAGE_ERROR` and closes
/// (`heimdall_ipc::session`), so nothing is written. The same request without the key
/// decodes.
#[tokio::test]
async fn a_bundle_with_an_authority_section_is_refused_on_the_request_path() {
    use heimdall_contract::ipc::ClientMessage;
    let b = Inst::new(false).await;
    let counts = b.store.transaction(|tx| tx.table_counts()).unwrap();
    let docs = b.catalog_docs();
    let authority = b.authority();
    let bundle = |edit: fn(&mut serde_json::Value)| {
        let mut v = serde_json::json!({
            "schema": "heimdall-portable/1",
            "created_at": "2026-11-18T09:00:00Z",
            "destinations": [{"id": "lab-db", "alias": "lab-db"}],
            "identities": [{"fingerprint": fp('B'), "provider": "native_agent"}],
            "profiles": [{"id": "dev", "pairs": ["lab-db:deploy"]}],
        });
        edit(&mut v);
        serde_json::to_vec(&serde_json::json!({
            "type": "request", "seq": 1,
            "request": {"op": "catalog", "action": "apply_import", "request_id": "q-1", "bundle": v},
        }))
        .unwrap()
    };
    let decode = |bytes: &[u8]| heimdall_ipc::session::parse_frame::<ClientMessage>(bytes);
    assert!(decode(&bundle(|_| {})).is_ok());
    let edits: [fn(&mut serde_json::Value); 6] = [
        |v| v["policies"] = serde_json::json!([{"id": "p", "scope": []}]),
        |v| v["trust"] = serde_json::json!({"workspace": "/w"}),
        |v| v["profiles"][0]["policy"] = serde_json::json!({"max_window": "30d"}),
        |v| v["destinations"][0]["grants"] = serde_json::json!([]),
        |v| v["identities"][0]["trusted"] = serde_json::json!(true),
        |v| v["anything_else"] = serde_json::json!(1),
    ];
    for edit in edits {
        let frame = bundle(edit);
        let e = decode(&frame).unwrap_err();
        assert!(
            !e.to_string().contains("policies") && !e.to_string().contains("grants"),
            "the refusal does not echo the peer's bytes: {e}"
        );
    }
    assert_eq!(b.store.transaction(|tx| tx.table_counts()).unwrap(), counts);
    assert_eq!((b.catalog_docs(), b.authority()), (docs, authority));
}

/// `dry_run` (ADR-0006 §17.9): a read. It validates the bundle as a real import does, answers
/// the plan marked as a dry run (adds, a conflict by alias and by content, the identity that
/// needs a local adoption, every exported host-key fingerprint) and writes nothing: not a
/// row of any table (`Txn::table_counts`: operations, idempotency, events included), not the
/// catalog, not authority. The same request ID then imports for real and applies exactly the
/// plan the dry run showed. A bad bundle is refused as a real one; a role that is not the
/// owner is refused.
#[tokio::test]
async fn dry_run_writes_nothing_and_shows_the_plan() {
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    let mut exported = bundle_of(&a.export(false).await);
    exported.destinations[0].host_key_fingerprints = vec![fp('H'), fp('I')];
    exported.destinations.push({
        let mut d = exported.destinations[1].clone();
        d.id = DestinationId::parse("third").unwrap();
        d.alias = "taken".into();
        d
    });
    let b = Inst::new(false).await;
    for (rid, body) in [
        (
            "b-1",
            serde_json::json!({"destination": {"id": "other", "alias": "taken",
                                               "definition": {"kind": "observed"}}}),
        ),
        (
            "b-2",
            serde_json::json!({"profile": {"id": "dev",
                "pairs": [{"destination": "lab-db", "account": "deploy"}]}}),
        ),
    ] {
        let action = if body.get("profile").is_some() {
            "upsert_profile"
        } else {
            "upsert_destination"
        };
        let mut req = body;
        req["action"] = action.into();
        req["request_id"] = rid.into();
        b.catalog(req).await.unwrap();
    }
    let counts = || b.store.transaction(|tx| tx.table_counts()).unwrap();
    let (before, docs, authority) = (counts(), b.catalog_docs(), b.authority());

    let dry = b.dry_run(&exported, "d-1").await.unwrap();
    assert!(dry.operation_id.is_none(), "a dry run has no operation");
    assert_eq!(dry.data["dry_run"], true);
    assert!(dry.data.get("applied").is_none());
    assert_eq!(
        statuses(&dry.data),
        [
            ("destination", "lab-db", "add"),
            ("destination", "lab-web", "add"),
            ("destination", "third", "conflict"),
            (
                "identity",
                exported.identities[0].fingerprint.as_str(),
                "needs_local"
            ),
            ("profile", "dev", "conflict"),
        ]
        .map(|(k, i, s)| (k.to_owned(), i.to_owned(), s.to_owned()))
    );
    assert_eq!(
        dry.data["plan"][0]["host_key_fingerprints"],
        serde_json::json!([fp('H'), fp('I')])
    );
    assert_eq!(dry.data["plan"][2]["reason"], "alias_collision");
    assert_eq!(dry.data["plan"][4]["reason"], "differs_locally");
    assert_eq!(dry.data["would_apply"]["added"], 2);
    assert_eq!(counts(), before, "no row of any table was written");
    assert_eq!((b.catalog_docs(), b.authority()), (docs.clone(), authority));

    // A bad bundle is refused as for a real import; so is a role that is not the owner.
    let mut bad = exported.clone();
    bad.destinations[0].alias = "*".into();
    assert_eq!(err(b.dry_run(&bad, "d-2").await).code, Code::UsageError);
    let req: CatalogRequest = serde_json::from_value(serde_json::json!({
        "action": "apply_import", "dry_run": true, "request_id": "d-3",
        "bundle": serde_json::to_value(&exported).unwrap(),
    }))
    .unwrap();
    let denied = err(b.ops.catalog(&limited(), req).await);
    assert_eq!(denied.code, Code::CapabilityUnavailable);
    assert_eq!(counts(), before);

    // The real import, under the same request ID, applies exactly that plan.
    let real = b.import(&exported, "d-1").await.unwrap();
    assert!(real.operation_id.is_some());
    assert_eq!(real.data["plan"], dry.data["plan"]);
    assert_eq!(real.data["applied"], dry.data["would_apply"]);
    assert_eq!(real.data["reestablish"], dry.data["reestablish"]);
    assert_ne!(b.catalog_docs(), docs);
}

/// A host-key fingerprint in a bundle is shown in the plan (for the owner's comparison) and
/// is nothing else: no known-hosts file and no host-key record is written, and nothing in
/// the store changes but the catalog rows and the journal.
#[tokio::test]
async fn import_shows_host_key_fingerprints_and_trusts_nothing() {
    let b = Inst::new(false).await;
    let mut bundle = bundle_of(&serde_json::from_slice(&hostile(serde_json::json!({}))).unwrap());
    bundle.destinations[0].host_key_fingerprints = vec![fp('H'), fp('I')];
    let files = b.home_files();
    let authority = b.authority();
    let res = b.import(&bundle, "hk-1").await.unwrap();
    assert_eq!(
        res.data["plan"][0]["host_key_fingerprints"],
        serde_json::json!([fp('H'), fp('I')])
    );
    assert_eq!(b.home_files(), files);
    assert_eq!(b.authority(), authority);
    // The stored destination has no trace of a host key.
    let stored = b
        .store
        .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
        .unwrap();
    assert!(!format!("{stored:?}").contains(&fp('H')));
}

/// ⟨M05; ADR-0006 §17.11 items 23 and 24; ruling I-27⟩ A bastion destination's route travels:
/// the export names its jump destination, and a jump route is never the same as a direct one.
/// A second installation, which has no such route, gets the bastion (as an observed
/// destination) and **skips** the routed one (`route_required`, the jump and the setup command
/// shown; nothing written for it); a re-import into the exporting installation, which has the
/// matching route, is a no-op (`unchanged`); a bundle saying a direct destination is reached
/// through a jump is a conflict there, not "unchanged".
#[tokio::test]
async fn a_bastion_destination_round_trips_with_its_jump() {
    let a = Inst::new(false).await;
    let adopted = a
        .catalog(serde_json::json!({
            "action": "adopt_identity", "request_id": "j-id",
            "identity": {
                "source": {"kind": "public_key_file", "path": format!("{}/.ssh/id_j.pub", a.home.path().display())},
                "public_key": public_key(9),
            }
        }))
        .await
        .unwrap();
    let identity = adopted.data["identity_id"].as_str().unwrap().to_owned();
    for (rid, id, host, jump) in [
        ("j-d1", "bastion", "bastion.example.invalid", None),
        (
            "j-d2",
            "lab-inner",
            "inner.example.invalid",
            Some("bastion"),
        ),
        ("j-d3", "lab-direct", "direct.example.invalid", None),
    ] {
        let mut definition = serde_json::json!({"kind": "managed", "hostname": host,
                                                "account": "deploy", "identity": identity});
        if let Some(j) = jump {
            definition["jump"] = serde_json::json!(j);
        }
        a.catalog(serde_json::json!({
            "action": "upsert_destination", "request_id": rid,
            "destination": {"id": id, "alias": id, "definition": definition}
        }))
        .await
        .unwrap_or_else(|e| panic!("{id}: {} {}", e.code, e.message));
    }
    let bundle = bundle_of(&a.export(false).await);
    let jump_of = |b: &PortableBundle, id: &str| {
        b.destinations
            .iter()
            .find(|d| d.id.as_str() == id)
            .unwrap()
            .jump
            .clone()
    };
    assert_eq!(
        jump_of(&bundle, "lab-inner").map(|j| j.to_string()),
        Some("bastion".to_owned()),
        "the export names the route's jump"
    );
    assert_eq!(jump_of(&bundle, "bastion"), None);
    assert_eq!(jump_of(&bundle, "lab-direct"), None);

    let b = Inst::new(false).await;
    let res = b.import(&bundle, "j-imp").await.unwrap();
    let inner = res.data["plan"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "lab-inner")
        .unwrap()
        .clone();
    assert_eq!(inner["status"], "skipped", "{inner}");
    assert_eq!(inner["reason"], "route_required", "{inner}");
    assert_eq!(
        inner["jump"], "bastion",
        "the plan shows the route, never a direct one"
    );
    assert!(
        inner["setup"]
            .as_str()
            .is_some_and(|c| c.contains("--jump bastion")),
        "{inner}"
    );
    let written = b
        .store
        .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
        .unwrap();
    assert!(
        !format!("{written:?}").contains("lab-inner"),
        "nothing is written for a skipped destination"
    );
    assert!(
        statuses(&res.data)
            .iter()
            .any(|(k, id, st)| k == "destination" && id == "bastion" && st == "add"),
        "{}",
        res.data
    );

    // The exporting installation: a re-import is a no-op ...
    let again = a.import(&bundle, "j-again").await.unwrap();
    for id in ["bastion", "lab-inner", "lab-direct"] {
        assert!(
            statuses(&again.data)
                .iter()
                .any(|(k, i, st)| k == "destination" && i == id && st == "unchanged"),
            "{id}: {}",
            again.data
        );
    }
    // ... and a bundle that routes the direct destination through the bastion differs.
    let mut rerouted = bundle.clone();
    for d in &mut rerouted.destinations {
        if d.id.as_str() == "lab-direct" {
            d.jump = Some(DestinationId::parse("bastion").unwrap());
        }
    }
    let res = a.import(&rerouted, "j-rerouted").await.unwrap();
    let direct = res.data["plan"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "lab-direct")
        .unwrap()
        .clone();
    assert_eq!(direct["status"], "conflict", "{direct}");
    assert_eq!(direct["reason"], "differs_locally", "{direct}");
}

/// ⟨M05; ADR-0006 §17.11 item 23⟩ A jump that does not resolve refuses its destination with a
/// finding (`jump_unresolved`) and writes nothing for it: one naming a destination neither the
/// bundle nor the catalog has, and one naming a bundle destination that is itself routed
/// through a jump (a chain, `route_chain_unsupported`). A jump that resolves is still never
/// written (ruling I-27: `skipped`, `route_required`). The rest of the bundle still applies.
#[tokio::test]
async fn an_unresolved_jump_refuses_its_destination_on_import() {
    let b = Inst::new(false).await;
    let mut bundle = bundle_of(&serde_json::from_slice(&hostile(serde_json::json!({}))).unwrap());
    let base = bundle.destinations[0].clone();
    let mk = |id: &str, jump: Option<&str>| {
        let mut d = base.clone();
        d.id = DestinationId::parse(id).unwrap();
        d.alias = id.to_owned();
        d.jump = jump.map(|j| DestinationId::parse(j).unwrap());
        d
    };
    bundle.destinations = vec![
        mk("plain", None),
        mk("orphan", Some("nowhere")),
        mk("hop1", Some("plain")),
        mk("hop2", Some("hop1")),
    ];
    let before = b
        .store
        .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
        .unwrap();
    let res = b.import(&bundle, "j-unres").await.unwrap();
    let plan = res.data["plan"].as_array().unwrap().clone();
    let of = |id: &str| plan.iter().find(|e| e["id"] == id).unwrap().clone();
    assert_eq!(of("plain")["status"], "add");
    assert_eq!(
        (of("hop1")["status"].clone(), of("hop1")["reason"].clone()),
        (
            serde_json::json!("skipped"),
            serde_json::json!("route_required")
        ),
        "a one-hop jump to a bundle destination resolves, and the routed destination is skipped"
    );
    for id in ["orphan", "hop2"] {
        assert_eq!(of(id)["status"], "conflict", "{id}: {}", of(id));
        assert_eq!(of(id)["reason"], "jump_unresolved", "{id}: {}", of(id));
    }
    let after = b
        .store
        .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
        .unwrap();
    let text = format!("{after:?}");
    assert!(
        !text.contains("orphan") && !text.contains("hop2") && !text.contains("hop1"),
        "nothing written for them"
    );
    assert!(text.contains("plain"));
    assert_ne!(format!("{before:?}"), text);
}

/// ⟨M05; review M05-W4F-R03⟩ A jump resolves against the reconciliation result, never the
/// raw bundle: a hop the bundle omits resolves to this catalog's managed direct destination
/// (and the routed destination is then skipped, `route_required`, ruling I-27); a bundled hop
/// that is itself refused (its alias collides with another destination here) or named twice
/// leaves its routed destination `jump_unresolved`. Nothing is written for any of them.
#[tokio::test]
async fn a_jump_resolves_against_the_reconciled_hop() {
    let b = Inst::new(false).await;
    let adopted = b
        .catalog(serde_json::json!({
            "action": "adopt_identity", "request_id": "r3-id",
            "identity": {
                "source": {"kind": "public_key_file", "path": format!("{}/.ssh/id_r3.pub", b.home.path().display())},
                "public_key": public_key(11),
            }
        }))
        .await
        .unwrap();
    let identity = adopted.data["identity_id"].as_str().unwrap().to_owned();
    // Here: a managed direct bastion, and another destination holding the alias `hop-alias`.
    for (rid, id, alias) in [
        ("r3-d1", "bastion", "bastion"),
        ("r3-d2", "other", "hop-alias"),
    ] {
        b.catalog(serde_json::json!({
            "action": "upsert_destination", "request_id": rid,
            "destination": {"id": id, "alias": alias, "definition": {"kind": "managed",
                "hostname": format!("{id}.example.invalid"), "account": "deploy", "identity": identity}}
        }))
        .await
        .unwrap_or_else(|e| panic!("{id}: {} {}", e.code, e.message));
    }
    let mut bundle = bundle_of(&serde_json::from_slice(&hostile(serde_json::json!({}))).unwrap());
    let base = bundle.destinations[0].clone();
    let mk = |id: &str, alias: &str, jump: Option<&str>| {
        let mut d = base.clone();
        d.id = DestinationId::parse(id).unwrap();
        d.alias = alias.to_owned();
        d.hostname = None;
        d.port = None;
        d.account = None;
        d.jump = jump.map(|j| DestinationId::parse(j).unwrap());
        d
    };
    bundle.destinations = vec![
        // The hop the bundle omits: this catalog's managed direct `bastion`.
        mk("via-local", "via-local", Some("bastion")),
        // A bundled hop refused for its alias, and its dependent.
        mk("hop-colliding", "hop-alias", None),
        mk("via-colliding", "via-colliding", Some("hop-colliding")),
        // A bundled hop named twice, and its dependent.
        mk("hop-twice", "hop-twice", None),
        mk("hop-twice", "hop-twice-again", None),
        mk("via-twice", "via-twice", Some("hop-twice")),
    ];
    let res = b.import(&bundle, "r3-imp").await.unwrap();
    let plan = res.data["plan"].as_array().unwrap().clone();
    let of = |id: &str| -> Vec<(String, String)> {
        plan.iter()
            .filter(|e| e["id"] == id)
            .map(|e| {
                (
                    e["status"].as_str().unwrap_or("").to_owned(),
                    e["reason"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect()
    };
    assert_eq!(
        of("via-local"),
        vec![("skipped".to_owned(), "route_required".to_owned())]
    );
    assert_eq!(
        of("hop-colliding"),
        vec![("conflict".to_owned(), "alias_collision".to_owned())]
    );
    assert_eq!(
        of("via-colliding"),
        vec![("conflict".to_owned(), "jump_unresolved".to_owned())],
        "a refused hop does not resolve its dependent"
    );
    assert_eq!(
        of("hop-twice"),
        vec![("conflict".to_owned(), "duplicate_in_bundle".to_owned()); 2],
        "both rows of a repeated ID are refused"
    );
    assert_eq!(
        of("via-twice"),
        vec![("conflict".to_owned(), "jump_unresolved".to_owned())],
        "a hop named twice is ambiguous"
    );
    let written = format!(
        "{:?}",
        b.store
            .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
            .unwrap()
    );
    for id in [
        "via-local",
        "via-colliding",
        "hop-colliding",
        "hop-twice",
        "via-twice",
    ] {
        assert!(!written.contains(id), "{id} written");
    }
}

/// ⟨M05; review M05-W4F-R03⟩ Every row of a repeated destination ID is refused, the first one
/// too, before any alias is claimed: two new rows sharing an ID with different aliases write
/// nothing, and neither alias is taken (a third destination may use one of them).
#[tokio::test]
async fn every_row_of_a_repeated_destination_id_is_refused() {
    let b = Inst::new(false).await;
    let mut bundle = bundle_of(&serde_json::from_slice(&hostile(serde_json::json!({}))).unwrap());
    let base = bundle.destinations[0].clone();
    let mk = |id: &str, alias: &str| {
        let mut d = base.clone();
        d.id = DestinationId::parse(id).unwrap();
        d.alias = alias.to_owned();
        d.jump = None;
        d
    };
    bundle.destinations = vec![
        mk("twin", "twin-a"),
        mk("twin", "twin-b"),
        mk("other", "twin-a"),
    ];
    let res = b.import(&bundle, "r3-twins").await.unwrap();
    let plan = res.data["plan"].as_array().unwrap().clone();
    let of = |id: &str| -> Vec<(String, String)> {
        plan.iter()
            .filter(|e| e["id"] == id)
            .map(|e| {
                (
                    e["status"].as_str().unwrap_or("").to_owned(),
                    e["reason"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect()
    };
    assert_eq!(
        of("twin"),
        vec![("conflict".to_owned(), "duplicate_in_bundle".to_owned()); 2]
    );
    assert_eq!(
        of("other"),
        vec![("add".to_owned(), "recorded_as_observed".to_owned())],
        "a refused row claims no alias"
    );
    let written = format!(
        "{:?}",
        b.store
            .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
            .unwrap()
    );
    assert!(
        !written.contains("twin-b") && !written.contains("\"twin\""),
        "{written}"
    );
}

/// Import is one store transaction (M05-D07): a crash before the import's commit leaves
/// no destination, no profile and no settled operation, and the same request, retried,
/// applies the whole plan once.
#[tokio::test]
async fn import_is_one_transaction_a_crash_before_commit_writes_nothing() {
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    let exported = bundle_of(&a.export(false).await);
    let b = Inst::new(false).await;
    let docs = b.catalog_docs();
    // The first commit is the request's admission; the second is the import's own.
    b.faults.arm(2);
    let e = err(b.import(&exported, "tx-1").await);
    assert_eq!(
        b.faults.fired.load(Ordering::SeqCst),
        1,
        "the fault hit the import"
    );
    assert_eq!(e.code, Code::StateUnavailable, "{e:?}");
    assert_eq!(
        b.catalog_docs(),
        docs,
        "neither destinations nor the profile were written"
    );
    // The retry completes the same operation, once.
    let done = b.import(&exported, "tx-1").await.unwrap();
    assert_eq!(done.data["applied"]["added"], 3);
    assert_eq!(done.data["applied"]["conflicts"], 0);
    assert_eq!(b.faults.fired.load(Ordering::SeqCst), 1);
}

// =================================================================================
// set_default_profile (ADR-0006 §17.9)
// =================================================================================

/// `catalog set_default_profile` through the real driver: set, read (`inspect policies`),
/// replace and clear; journaled and idempotent by request ID; an unknown profile and an
/// unmanaged environment are refused with nothing written; the owner role is needed. It is
/// a preference, never authority: the authority generation and every authority row are
/// unchanged, and a binding started before the change keeps its pins (R-AU-03).
#[tokio::test]
async fn set_default_profile_set_read_clear_and_never_moves_a_binding() {
    let a = Inst::new(true).await;
    seed_catalog(&a).await;
    a.catalog(serde_json::json!({
        "action": "upsert_profile", "request_id": "p-ops",
        "profile": {"id": "ops", "pairs": [{"destination": "lab-web", "account": "deploy"}]}
    }))
    .await
    .unwrap();
    seed_authority(&a).await;
    // The binding exists (a real ensure in `seed_authority`): its pins before the change.
    let pins = |a: &Inst| {
        a.store
            .transaction(|tx| {
                Ok(format!(
                    "{:?}",
                    (
                        tx.table_counts()?.grants,
                        tx.profile_snapshot(&ProfileId::parse("dev").unwrap(), 1)?,
                        tx.raw_documents(RawDocuments::Enrollments)?,
                    )
                ))
            })
            .unwrap()
    };
    // Nothing is set: the view has no `default_profiles` key at all.
    let v = a
        .ops
        .inspect(
            &owner(false),
            InspectRequest {
                subject: InspectSubject::Policies,
                preview: None,
                cwd: None,
                redact: false,
            },
        )
        .await
        .unwrap()
        .data;
    assert!(v.get("default_profiles").is_none(), "{v}");
    let (authority, pinned) = (a.authority(), pins(&a));

    let set = |profile: serde_json::Value, rid: &str| serde_json::json!({"action": "set_default_profile", "profile": profile, "request_id": rid});
    let done = a.catalog(set("ops".into(), "d-1")).await.unwrap();
    assert_eq!(done.data["profile_id"], "ops");
    assert_eq!(done.data["environment_id"], env_id().to_string());
    // Read back: through the view and through the application's reader.
    let view = policies_view(&a).await;
    assert_eq!(view.default_profiles.len(), 1);
    assert_eq!(view.default_profiles[0].environment_id, env_id());
    assert_eq!(view.default_profiles[0].profile_id.as_str(), "ops");
    assert_eq!(
        a.ops.default_profile(None).await.unwrap().unwrap().as_str(),
        "ops"
    );
    // Replace, naming the environment; the same request ID replays.
    a.catalog(serde_json::json!({
        "action": "set_default_profile", "environment": env_id(), "profile": "dev", "request_id": "d-2"
    }))
    .await
    .unwrap();
    assert_eq!(
        policies_view(&a).await.default_profiles[0]
            .profile_id
            .as_str(),
        "dev"
    );
    let replay = a.catalog(set("ops".into(), "d-1")).await.unwrap();
    assert_eq!(replay.operation_id, done.operation_id);
    assert_eq!(
        policies_view(&a).await.default_profiles[0]
            .profile_id
            .as_str(),
        "dev",
        "a replay writes nothing"
    );
    assert_eq!(
        err(a.catalog(set("dev".into(), "d-1")).await).code,
        Code::RequestConflict
    );

    // Refusals write nothing.
    let e = err(a.catalog(set("no-such".into(), "d-3")).await);
    assert_eq!(e.code, Code::NotFound);
    let e = err(a
        .catalog(serde_json::json!({
            "action": "set_default_profile", "profile": "dev", "request_id": "d-4",
            "environment": EnvironmentId::from_random_bytes([0x99; 16]),
        }))
        .await);
    assert_eq!(e.code, Code::NotFound);
    assert_eq!(
        policies_view(&a).await.default_profiles[0]
            .profile_id
            .as_str(),
        "dev"
    );
    let role = a
        .ops
        .catalog(
            &limited(),
            serde_json::from_value(set("ops".into(), "d-5")).unwrap(),
        )
        .await;
    assert_eq!(err(role).code, Code::CapabilityUnavailable);

    // Clear, with `null` and with the field absent.
    a.catalog(set(serde_json::Value::Null, "d-6"))
        .await
        .unwrap();
    assert!(policies_view(&a).await.default_profiles.is_empty());
    assert_eq!(a.ops.default_profile(None).await.unwrap(), None);
    a.catalog(set("ops".into(), "d-7")).await.unwrap();
    a.catalog(serde_json::json!({"action": "set_default_profile", "request_id": "d-8"}))
        .await
        .unwrap();
    assert!(policies_view(&a).await.default_profiles.is_empty());

    // A preference is not authority: nothing the owner decided moved, and the running
    // binding's grant and profile pin are as they were (R-AU-03).
    assert_eq!(a.authority(), authority);
    assert_eq!(pins(&a), pinned);
}

// =================================================================================
// P: import never creates or widens authority, and is idempotent (random bundles)
// =================================================================================

fn config(cases: u32, seed: u64) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(seed);
    }
    c
}

#[derive(Debug, Clone)]
struct Case {
    /// Local destinations: `(index into DEST, alias index)`.
    local_dests: Vec<(u8, u8)>,
    /// Local profiles: `(index into PROF, pair bits)`.
    local_profiles: Vec<(u8, u8)>,
    bundle_dests: Vec<(u8, u8, bool)>,
    bundle_profiles: Vec<(u8, u8)>,
    bundle_ids: Vec<u8>,
    redacted: bool,
}

const DEST: [&str; 4] = ["d1", "d2", "d3", "d4"];
const ALIAS: [&str; 4] = ["a1", "a2", "a3", "a4"];
const PROF: [&str; 3] = ["p1", "p2", "p3"];

fn case() -> impl Strategy<Value = Case> {
    (
        prop::collection::vec((0u8..4, 0u8..4), 0..4),
        prop::collection::vec((0u8..3, 0u8..16), 0..3),
        prop::collection::vec((0u8..4, 0u8..4, any::<bool>()), 0..6),
        prop::collection::vec((0u8..3, 0u8..16), 0..5),
        prop::collection::vec(0u8..3, 0..4),
        any::<bool>(),
    )
        .prop_map(
            |(local_dests, local_profiles, bundle_dests, bundle_profiles, bundle_ids, redacted)| {
                Case {
                    local_dests,
                    local_profiles,
                    bundle_dests,
                    bundle_profiles,
                    bundle_ids,
                    redacted,
                }
            },
        )
}

fn pairs_of(bits: u8) -> Vec<String> {
    DEST.iter()
        .enumerate()
        .filter(|(i, _)| bits & (1 << i) != 0)
        .map(|(_, d)| format!("{d}:deploy"))
        .collect()
}

/// The property over the real driver: for random bundles against random local catalogs, (1)
/// the authority tables are byte-identical after the import; (2) no local record is
/// overwritten (the catalog after the import equals the catalog before plus only what the
/// plan added: every pre-existing destination and profile document is still there
/// verbatim); (3) the plan never reports `add` for an ID the catalog held; (4) importing
/// the same bundle again under a new request ID adds nothing and leaves the catalog
/// byte-identical.
#[test]
fn p_import_never_changes_authority_never_overwrites_and_is_idempotent() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut runner = proptest::test_runner::TestRunner::new(config(48, 0x0705_0007));
    runner
        .run(&case(), |c| {
            rt.block_on(async {
                let b = Inst::new(false).await;
                b.store
                    .transaction(|tx| {
                        for (d, a) in &c.local_dests {
                            // Ignore alias clashes between the generated local rows.
                            let _ = tx.upsert_destination(&heimdall_domain::catalog::DestinationRecord {
                                id: DestinationId::parse(DEST[*d as usize]).unwrap(),
                                alias: ALIAS[*a as usize].to_owned(),
                                revision: 1,
                                definition: heimdall_domain::catalog::DestinationDefinition::Observed,
                                label: None,
                                updated_at: t0(),
                            });
                        }
                        for (p, bits) in &c.local_profiles {
                            let _ = tx.upsert_profile(&ProfileDefinition {
                                id: ProfileId::parse(PROF[*p as usize]).unwrap(),
                                revision: 1,
                                scope: Scope {
                                    pairs: pairs_of(*bits)
                                        .iter()
                                        .map(|t| {
                                            let (d, a) = t.split_once(':').unwrap();
                                            pair(d, a)
                                        })
                                        .collect(),
                                    capabilities: ssh(),
                                },
                                label: None,
                            });
                        }
                        Ok(())
                    })
                    .unwrap();
                let bundle = serde_json::json!({
                    "schema": "heimdall-portable/1",
                    "created_at": "2026-11-18T09:00:00Z",
                    "redacted": c.redacted,
                    "destinations": c.bundle_dests.iter().map(|(d, a, host)| {
                        let id = DEST[*d as usize];
                        let mut v = serde_json::json!({"id": id, "alias": if c.redacted { id } else { ALIAS[*a as usize] }});
                        if *host && !c.redacted {
                            v["hostname"] = "h.example.invalid".into();
                            v["host_key_fingerprints"] = serde_json::json!([fp('K')]);
                        }
                        v
                    }).collect::<Vec<_>>(),
                    "identities": c.bundle_ids.iter().map(|i| serde_json::json!(
                        {"fingerprint": fp((b'A' + i) as char), "provider": "native_agent"})).collect::<Vec<_>>(),
                    "profiles": c.bundle_profiles.iter().map(|(p, bits)| serde_json::json!(
                        {"id": PROF[*p as usize], "pairs": pairs_of(*bits)})).collect::<Vec<_>>(),
                });
                let bundle = parse_import_bundle(bundle.to_string().as_bytes()).unwrap();
                let (authority, docs) = (b.authority(), b.catalog_docs());
                let local_dest_docs = b
                    .store
                    .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
                    .unwrap();
                let local_profiles = b.store.transaction(|tx| tx.profiles()).unwrap();

                let first = b.import(&bundle, "p-1").await.unwrap();
                prop_assert_eq!(b.authority(), authority.clone());
                // (2) and (3): every pre-existing document survives verbatim.
                let after_dests = b
                    .store
                    .transaction(|tx| tx.raw_documents(RawDocuments::Destinations))
                    .unwrap();
                for row in &local_dest_docs {
                    prop_assert!(after_dests.contains(row), "a destination was overwritten");
                }
                let after_profiles = b.store.transaction(|tx| tx.profiles()).unwrap();
                for p in &local_profiles {
                    prop_assert!(after_profiles.contains(p), "a profile was overwritten");
                }
                for (kind, id, status) in statuses(&first.data) {
                    if status == "add" {
                        let held = match kind.as_str() {
                            "destination" => local_dest_docs.iter().any(|(k, _)| *k == id),
                            _ => local_profiles.iter().any(|p| p.id.as_str() == id),
                        };
                        prop_assert!(!held, "{kind} {id} was added over a held record");
                    }
                }
                // (4) idempotent.
                let docs_after = b.catalog_docs();
                let second = b.import(&bundle, "p-2").await.unwrap();
                prop_assert_eq!(second.data["applied"]["added"].as_u64(), Some(0));
                prop_assert_eq!(b.catalog_docs(), docs_after);
                prop_assert_eq!(b.authority(), authority.clone());
                let _ = docs;
                Ok(())
            })
        })
        .unwrap();
}
