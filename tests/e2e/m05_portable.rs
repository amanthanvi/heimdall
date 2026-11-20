//! ⟨M05⟩ U7 end-to-end journey (ADR-0011 §2.4 I4; plan §5 M05-T01): two installations
//! exchange portable intent through the real runtime dispatcher, as the CLI's `export` and
//! `import` (wave 3) will, and the importing side stays inside its authority.
//!
//! Everything runs in process: each installation is the production `heimdall_app::Operations`
//! over `Store::open_in_memory`, answered through `OperationsDispatcher::handle_as` (the
//! request decoded from JSON, the answer an envelope, as on the control endpoint). Sessions
//! cannot negotiate the declared-not-offered `trusted-work/1` yet, so the capability gate is
//! the contract's (`tests/contracts/rev5.rs`) and the fail-closed session case of
//! `model_operations::wave0_fail_closed`, which now covers `set_default_profile` too.
//!
//! The journey: A (a catalog, an automatic-activation policy and a grant) exports with
//! redaction; the bytes pass the importer's parser; B (fresh) imports them and answers the
//! plan; B's catalog views show the intent, B's authority is untouched, an `ensure` there
//! needs a decision, B's default profile is set and read through the dispatcher, and a
//! re-import is a no-op.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::{NoStageHook, StageHook};
use heimdall_app::operations::{Limits, parse_import_bundle};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::envelope::Envelope;
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId,
};
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy, InteractionMode,
    NewAuthenticationExpiry, RefreshDependency, Request, RevocationStatus, WorkloadIsolation,
};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
use heimdall_store::Store;
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
    assert_no_canary,
};
use tokio_util::sync::CancellationToken;

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x41; 16])
}

fn owner() -> Caller {
    Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        },
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn consumer() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::LimitedConsumer,
    })
}

fn ssh() -> std::collections::BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
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

struct Inst {
    store: Arc<Store>,
    dispatcher: OperationsDispatcher,
}

impl Inst {
    async fn new(automatic: bool, with_policy: bool) -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env_id(),
                    device: DeviceId::from_random_bytes([0x42; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: automatic,
                        managed_signing: true,
                        issuer_access: true,
                    },
                })?;
                if with_policy {
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: PolicyId::parse("pol-e2e-a").unwrap(),
                            revision: PolicyRevision(1),
                            profile: ProfileId::parse("dev").unwrap(),
                            workspace: None,
                            scope: Scope {
                                pairs: [AccessPair {
                                    destination: DestinationId::parse("lab-db").unwrap(),
                                    account: AccountName::parse("deploy").unwrap(),
                                }]
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
                }
                Ok(())
            })
            .unwrap();
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let descriptor = AdapterDescriptor {
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
        };
        let outcome = PrepareOutcome {
            usable_until: "2026-11-19T09:00:00Z".parse().unwrap(),
            offline_until: "2026-11-18T10:00:00Z".parse().unwrap(),
            refresh_dependency: RefreshDependency::None,
            enforcement: enforcement(),
            credential_ref: format!("{CANARY_PREFIX}e2e_credential_ref"),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
            managed: None,
        };
        let fake = FakeCredentialAdapter::new(descriptor, vec![FakeStep::Prepare(outcome)]);
        let hook: Arc<dyn StageHook> = Arc::new(NoStageHook);
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
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
        .unwrap();
        let relay = EventRelay::spawn(&ops, CancellationToken::new());
        Self {
            store,
            dispatcher: OperationsDispatcher::new(ops, relay, clock),
        }
    }

    /// One request as the control endpoint would hand it over: decoded from JSON, answered
    /// as an envelope.
    async fn send(&self, caller: &Caller, v: serde_json::Value) -> Envelope<serde_json::Value> {
        let r: Request = serde_json::from_value(v).unwrap();
        let env = self.dispatcher.handle_as(caller, r).await;
        assert_no_canary(&serde_json::to_string(&env).unwrap());
        env
    }

    async fn ok(&self, v: serde_json::Value) -> serde_json::Value {
        let env = self.send(&owner(), v).await;
        assert_eq!(env.code, Code::Ok, "{:?}", env.data);
        env.data
    }

    fn authority(&self) -> String {
        self.store
            .transaction(|tx| {
                Ok(format!(
                    "{:?}|{:?}|{:?}|{:?}|{:?}",
                    tx.policies()?,
                    tx.pending_decisions()?,
                    tx.table_counts()?.grants,
                    tx.environment(&env_id())?,
                    tx.authority_generation()?,
                ))
            })
            .unwrap()
    }
}

/// The journey (module docs), with the exit claims it proves: the bundle that leaves A
/// carries intent only and, redacted, no host name; B ends with the intent, the plan says
/// what happened, B's authority is exactly what it was, the imported profile needs a
/// decision, the default profile is a preference read back through `inspect policies`, and
/// a re-import writes nothing. A role that is not the owner can neither export nor import.
#[tokio::test]
async fn export_import_journey_never_creates_authority() {
    let a = Inst::new(true, true).await;
    a.ok(serde_json::json!({
        "op": "catalog", "action": "upsert_destination", "request_id": "e-d1",
        "destination": {"id": "lab-db", "alias": "lab-db", "definition": {"kind": "observed"}}
    }))
    .await;
    a.ok(serde_json::json!({
        "op": "catalog", "action": "upsert_profile", "request_id": "e-p1",
        "profile": {"id": "dev", "pairs": [{"destination": "lab-db", "account": "deploy"}]}
    }))
    .await;
    // A has live authority: a grant from its standing policy.
    let granted = a
        .send(
            &owner(),
            serde_json::json!({
                "op": "ensure", "profile": "dev", "request_id": "e-ens", "work_id": "e-work",
                "scope": [{"destination": "lab-db", "account": "deploy"}],
                "interaction": "non_interactive"
            }),
        )
        .await;
    assert_eq!(granted.code, Code::AccessReady, "{:?}", granted.data);
    assert_eq!(
        a.store.transaction(|tx| tx.table_counts()).unwrap().grants,
        1
    );

    // Export, redacted; the bytes are what a file would hold.
    let exported = a
        .ok(serde_json::json!({"op": "inspect", "subject": "export", "redact": true}))
        .await;
    let bytes = serde_json::to_vec_pretty(&exported).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    for needle in ["pol-e2e-a", "grant_", "binding_", "automatic_activation"] {
        assert!(!text.contains(needle), "{needle} in the export");
    }
    let bundle = parse_import_bundle(&bytes).unwrap();
    assert!(bundle.redacted);

    // B: a fresh installation with nothing automatic and no policy.
    let b = Inst::new(false, false).await;
    let authority = b.authority();
    let req = |rid: &str| {
        serde_json::json!({
            "op": "catalog", "action": "apply_import", "request_id": rid,
            "bundle": serde_json::to_value(&bundle).unwrap()
        })
    };
    // A role that is not the owner cannot import.
    let refused = b.send(&consumer(), req("e-imp")).await;
    assert_eq!(refused.code, Code::CapabilityUnavailable);
    assert_eq!(
        b.store
            .transaction(|tx| tx.table_counts())
            .unwrap()
            .operations,
        0
    );

    let plan = b.ok(req("e-imp")).await;
    assert_eq!(plan["applied"]["added"], 2, "{plan}");
    assert_eq!(plan["applied"]["conflicts"], 0);
    assert!(
        !plan["reestablish"].as_array().unwrap().is_empty(),
        "what to set up locally is listed"
    );
    // The intent is visible through B's own catalog views.
    let dests = b
        .ok(serde_json::json!({"op": "inspect", "subject": "destinations"}))
        .await;
    assert_eq!(dests["items"].as_array().unwrap().len(), 1);
    assert_eq!(dests["items"][0]["destination_id"], "lab-db");
    let profiles = b
        .ok(serde_json::json!({"op": "inspect", "subject": "profiles"}))
        .await;
    assert_eq!(profiles["items"][0]["profile_id"], "dev");
    // B's authority is exactly what it was, and the imported profile needs a decision.
    assert_eq!(b.authority(), authority);
    let ensure = b
        .send(
            &owner(),
            serde_json::json!({
                "op": "ensure", "profile": "dev", "request_id": "e-b-ens", "work_id": "e-b-work",
                "scope": [{"destination": "lab-db", "account": "deploy"}],
                "interaction": "interactive"
            }),
        )
        .await;
    assert_eq!(ensure.code, Code::ApprovalRequired, "{:?}", ensure.data);

    // The default profile: a preference, set and read back, never a decision.
    b.ok(serde_json::json!({
        "op": "catalog", "action": "set_default_profile", "profile": "dev", "request_id": "e-def"
    }))
    .await;
    let policies = b
        .ok(serde_json::json!({"op": "inspect", "subject": "policies"}))
        .await;
    assert_eq!(policies["default_profiles"][0]["profile_id"], "dev");
    assert_eq!(policies["items"], serde_json::json!([]));

    // A re-import is a no-op.
    let again = b.ok(req("e-imp-2")).await;
    assert_eq!(again["applied"]["added"], 0);
    assert_eq!(again["applied"]["unchanged"], 2);

    // Export is the owner's.
    let denied = b
        .send(
            &consumer(),
            serde_json::json!({"op": "inspect", "subject": "export"}),
        )
        .await;
    assert_eq!(denied.code, Code::CapabilityUnavailable);
}
