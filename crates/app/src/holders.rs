//! Launch-binding holder release (m02-plan U8; ADR-0007 §8 "Holder process"; Q5 as
//! qualified).
//!
//! `run` binds with a holder: its own PID and OS start time on Unix (that PID becomes
//! the child), the launcher on Windows. [`Operations::release_exited_holders`] drops
//! the reference of every active launch binding whose exact holder process (PID **and**
//! start-time token, so a reused PID never counts) the [`ProcessLiveness`] port
//! observes **exited**. `Alive` and `Unknown` keep the binding: unknown liveness never
//! counts as an exit. The PID is lifecycle metadata, never authorization (spec §4.2,
//! §13.2).
//!
//! The release is M01's `release` primitive, run as the binding's own owner (so the
//! ownership rule, idempotency, the last-reference grant ending and its events are
//! exactly M01's, and release never revokes). It is the supervisor's pass
//! (`heimdall_runtime::supervisor::Supervisor::holder_pass`), never a client request.
//!
//! **Bounds.** One pass observes at most [`MAX_HOLDERS_PER_PASS`] active held bindings.
//! When more are active, the pass starts at a rotating offset (the runtime's wall
//! seconds), so every binding is observed within a bounded number of passes without
//! any state between passes. Each observation is one platform query.
//!
//! **Readings applied.**
//! * A holder row whose binding is already released, or missing, is skipped.
//! * The release checks, in its own transaction, that the binding is still active and
//!   its holder row still names the process that was observed exited
//!   (`Operations::release_if_held_by`): if a later `bind` of the same binding replaced
//!   the holder, nothing is released.
//! * A failed release of one binding does not stop the pass; the next pass retries.

use std::sync::Arc;

use heimdall_contract::Code;
use heimdall_contract::ids::BindingId;
use heimdall_contract::request::ReleaseRequest;
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome};
use heimdall_domain::holder::{HolderState, ProcessHolder};
use heimdall_store::Store;

use crate::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::operations::Operations;
use crate::ports::ProcessLiveness;

/// The most active held bindings one pass observes.
pub const MAX_HOLDERS_PER_PASS: usize = 256;

/// `items` rotated to start at `offset` (modulo their count) and cut to
/// [`MAX_HOLDERS_PER_PASS`]; unchanged when they fit.
fn rotate_bounded<T>(mut items: Vec<T>, offset: u64) -> Vec<T> {
    if items.len() > MAX_HOLDERS_PER_PASS {
        let len = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let start = usize::try_from(offset % len).unwrap_or(0);
        items.rotate_left(start);
        items.truncate(MAX_HOLDERS_PER_PASS);
    }
    items
}

/// The active held bindings, in binding order, bounded and rotated by `offset`.
fn active_holders(
    store: &Store,
    offset: u64,
) -> heimdall_store::Result<Vec<(BindingRecord, ProcessHolder)>> {
    store.transaction(|tx| {
        let mut active = Vec::new();
        for (binding, holder) in tx.binding_holders()? {
            if let Some(record) = tx.binding(&binding)?
                && record.state == BindingState::Active
            {
                active.push((record, holder));
            }
        }
        Ok(rotate_bounded(active, offset))
    })
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> heimdall_store::Result<T> + Send + 'static,
) -> Result<T, OpError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(OpError::new(
            Code::StateUnavailable,
            format!("state store: {e}"),
        )),
        Err(_) => Err(OpError::new(
            Code::InternalError,
            "the holder pass was interrupted",
        )),
    }
}

impl Operations {
    /// ⟨M02⟩ Release every active launch binding whose exact holder process
    /// `liveness` observes exited (module docs). Returns the bindings released by this
    /// pass, in the order observed.
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` when the store cannot be read; a failed release of one
    /// binding is skipped, not an error.
    pub async fn release_exited_holders(
        &self,
        liveness: &dyn ProcessLiveness,
    ) -> OpResult<Vec<BindingId>> {
        let store: Arc<Store> = self.local_store();
        let offset = u64::try_from(self.local_clock().wall().as_second()).unwrap_or(0);
        let held = {
            let store = Arc::clone(&store);
            blocking(move || active_holders(&store, offset)).await?
        };
        let mut released = Vec::new();
        for (binding, holder) in held {
            if liveness.state(&holder) != HolderState::Exited {
                continue;
            }
            let caller = Caller::unattended(binding.owner.clone());
            let request = ReleaseRequest {
                binding_id: binding.id.clone(),
            };
            match self.release_if_held_by(&caller, request, holder).await {
                Ok(done)
                    if serde_json::from_value::<ReleaseOutcome>(done.data["outcome"].clone())
                        .is_ok_and(|o| matches!(o, ReleaseOutcome::Released { .. })) =>
                {
                    tracing::info!(binding = %binding.id, "released a binding whose holder exited");
                    released.push(binding.id.clone());
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        binding = %binding.id,
                        code = %e.code,
                        "holder release failed; the next pass retries"
                    );
                }
            }
        }
        Ok(Completed::ok(Code::Ok, released))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;
    use std::time::Duration;

    use heimdall_contract::ids::{
        AccountName, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId, RequestId, WorkId,
    };
    use heimdall_contract::request::{
        BindForm, BindRequest, DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
        ExistingConnectionsPolicy, InteractionMode, LaunchBinding, NewAuthenticationExpiry,
        RefreshDependency, RequiredCapabilities, RevocationStatus, WaitMode, WorkloadIsolation,
    };
    use heimdall_contract::{GrantState, Timestamp};
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::operation::AdapterIdentity;
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{AccessPair, Capability, Scope};
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

    use super::*;
    use crate::ensure::NoStageHook;
    use crate::operations::{Limits, OperationsConfig};
    use crate::ports::{
        AdapterDescriptor, AdapterError, CredentialAdapter, InteractionRequirement, LockContinuity,
        PrepareOutcome, PrepareRequest, ReconcileOutcome, RevokeOutcome,
    };

    /// An adapter that prepares every time (this crate's own port: the testkit fake
    /// is built against the library outside its unit-test build).
    struct Prepares(AdapterDescriptor);

    #[async_trait::async_trait]
    impl CredentialAdapter for Prepares {
        fn descriptor(&self) -> &AdapterDescriptor {
            &self.0
        }
        async fn prepare(&self, _req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
            Ok(outcome())
        }
        async fn renew(&self, _req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
            Ok(outcome())
        }
        async fn reconcile(
            &self,
            _grant: &heimdall_contract::ids::GrantId,
            _effect_token: &str,
        ) -> Result<ReconcileOutcome, AdapterError> {
            Ok(ReconcileOutcome::NotApplied)
        }
        async fn revoke(
            &self,
            _grant: &heimdall_contract::ids::GrantId,
            _now: Timestamp,
        ) -> Result<RevokeOutcome, AdapterError> {
            Ok(RevokeOutcome {
                remote_pending: Vec::new(),
                latest_possible_credential_expiry: None,
            })
        }
    }

    const HOUR: Duration = Duration::from_secs(3600);

    fn t0() -> Timestamp {
        "2026-11-03T09:00:00Z".parse().unwrap()
    }

    fn env_id() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn pair(d: &str) -> AccessPair {
        AccessPair {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn ssh() -> BTreeSet<Capability> {
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
            },
            evidence: Vec::new(),
        }
    }

    fn outcome() -> PrepareOutcome {
        PrepareOutcome {
            usable_until: t0().checked_add(12 * HOUR).unwrap(),
            offline_until: t0().checked_add(HOUR).unwrap(),
            refresh_dependency: RefreshDependency::None,
            enforcement: enforcement(),
            credential_ref: "fixture".to_owned(),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
        }
    }

    fn owner() -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        }
    }

    /// One runtime over an in-memory store with the fake adapter, profile `dev` (h1,
    /// h2) fully covered by policy `pol`.
    async fn ops() -> (Operations, Arc<Store>) {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
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
                        managed_signing: true,
                        issuer_access: true,
                    },
                })?;
                let scope = Scope {
                    pairs: [pair("h1"), pair("h2")].into_iter().collect(),
                    capabilities: ssh(),
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
                    },
                    false,
                )?;
                Ok(())
            })
            .unwrap();
        let fake = Arc::new(Prepares(AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "holders".into(),
            },
            capabilities: ssh(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
        }));
        let ops = Operations::start(OperationsConfig {
            store: Arc::clone(&store),
            clock: VirtualClock::at(t0()),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: vec![fake as Arc<dyn CredentialAdapter>],
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        (ops, store)
    }

    /// `ensure` for work `work`, then `bind(launch)` with `holder`; the binding.
    async fn launch_binding(
        ops: &Operations,
        work: &str,
        holder: Option<ProcessHolder>,
    ) -> EnsureData {
        let caller = Caller::unattended(owner());
        let ensured = ops
            .ensure(
                &caller,
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: BTreeSet::new(),
                    environment: None,
                    work_id: WorkId::parse(work).unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(&format!("r-{work}")).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                },
            )
            .await
            .unwrap();
        let bound = ops
            .bind(
                &caller,
                BindRequest {
                    binding_id: ensured.data.binding_id.clone(),
                    form: BindForm::Launch(LaunchBinding {
                        executable: "/bin/sh".to_owned(),
                        holder,
                    }),
                    request_id: RequestId::parse(&format!("b-{work}")).unwrap(),
                },
            )
            .await
            .unwrap();
        bound.data
    }

    fn holder(pid: u32, started: &str) -> ProcessHolder {
        ProcessHolder {
            pid,
            started_at: started.to_owned(),
        }
    }

    /// A process table: PID → the start token of the process now at that PID. A PID
    /// absent from the table has no process; `unknown` PIDs cannot be queried.
    #[derive(Default)]
    struct Table {
        running: Mutex<BTreeMap<u32, String>>,
        unknown: Mutex<BTreeSet<u32>>,
        observed: Mutex<Vec<ProcessHolder>>,
    }

    impl ProcessLiveness for Table {
        fn state(&self, h: &ProcessHolder) -> HolderState {
            self.observed.lock().unwrap().push(h.clone());
            if self.unknown.lock().unwrap().contains(&h.pid) {
                return HolderState::Unknown;
            }
            match self.running.lock().unwrap().get(&h.pid) {
                Some(start) if *start == h.started_at => HolderState::Alive,
                // Nothing at that PID, or another process (a reused PID).
                _ => HolderState::Exited,
            }
        }
    }

    fn binding_state(store: &Store, id: &BindingId) -> BindingState {
        store
            .transaction(|tx| tx.binding(id))
            .unwrap()
            .unwrap()
            .state
    }

    async fn pass(ops: &Operations, table: &Table) -> Vec<BindingId> {
        ops.release_exited_holders(table).await.unwrap().data
    }

    /// m02-plan U8 `holder_exit_releases_reference_and_reused_pid_does_not_keep_it`
    /// (Q5 as qualified): while the exact holder runs, nothing is released; a new
    /// process at the same PID (another start token) does not keep the binding; the
    /// grant's last reference ends it locally (release is never revoke), and a later
    /// pass releases nothing more.
    #[tokio::test]
    async fn holder_exit_releases_reference_and_reused_pid_does_not_keep_it() {
        let (ops, store) = ops().await;
        let data = launch_binding(&ops, "w1", Some(holder(4242, "100.000001"))).await;
        let table = Table::default();
        table
            .running
            .lock()
            .unwrap()
            .insert(4242, "100.000001".to_owned());
        assert!(pass(&ops, &table).await.is_empty(), "the holder runs");
        assert_eq!(
            binding_state(&store, &data.binding_id),
            BindingState::Active
        );
        // The holder exited and its PID was reused by another process.
        table
            .running
            .lock()
            .unwrap()
            .insert(4242, "200.000002".to_owned());
        assert_eq!(pass(&ops, &table).await, vec![data.binding_id.clone()]);
        assert_eq!(
            binding_state(&store, &data.binding_id),
            BindingState::Released
        );
        let grant = store
            .transaction(|tx| tx.grant(&data.grant_id))
            .unwrap()
            .unwrap();
        assert_ne!(grant.state, GrantState::Revoked, "release is never revoke");
        assert!(pass(&ops, &table).await.is_empty(), "idempotent");
        // A holder whose PID is gone entirely is released too.
        let other = launch_binding(&ops, "w2", Some(holder(4343, "300.000003"))).await;
        assert_eq!(pass(&ops, &table).await, vec![other.binding_id.clone()]);
    }

    /// m02-plan U8 `holder_unknown_liveness_never_releases` (ADR-0007 §8: `Unknown`
    /// liveness never counts as an exit); a binding without a holder is never observed.
    #[tokio::test]
    async fn holder_unknown_liveness_never_releases() {
        let (ops, store) = ops().await;
        let held = launch_binding(&ops, "w1", Some(holder(5151, "1.000001"))).await;
        let unheld = launch_binding(&ops, "w2", None).await;
        let table = Table::default();
        table.unknown.lock().unwrap().insert(5151);
        for _ in 0..3 {
            assert!(pass(&ops, &table).await.is_empty());
        }
        assert_eq!(
            binding_state(&store, &held.binding_id),
            BindingState::Active
        );
        assert_eq!(
            binding_state(&store, &unheld.binding_id),
            BindingState::Active
        );
        assert!(
            table.observed.lock().unwrap().iter().all(|h| h.pid == 5151),
            "only the held binding's holder is observed"
        );
        // Once the query answers, the observed exit releases it.
        table.unknown.lock().unwrap().clear();
        assert_eq!(pass(&ops, &table).await, vec![held.binding_id.clone()]);
        assert_eq!(
            binding_state(&store, &unheld.binding_id),
            BindingState::Active
        );
    }

    /// A later `bind` of the same binding replaces its holder: the old holder's exit
    /// no longer releases it, the new holder's does.
    #[tokio::test]
    async fn a_replaced_holder_decides_and_the_old_ones_exit_does_not() {
        let (ops, store) = ops().await;
        let first = launch_binding(&ops, "w1", Some(holder(6001, "1.000001"))).await;
        let caller = Caller::unattended(owner());
        ops.bind(
            &caller,
            BindRequest {
                binding_id: first.binding_id.clone(),
                form: BindForm::Launch(LaunchBinding {
                    executable: "/bin/sh".to_owned(),
                    holder: Some(holder(6002, "2.000002")),
                }),
                request_id: RequestId::parse("b-w1-again").unwrap(),
            },
        )
        .await
        .unwrap();
        let table = Table::default();
        table
            .running
            .lock()
            .unwrap()
            .insert(6002, "2.000002".to_owned());
        assert!(
            pass(&ops, &table).await.is_empty(),
            "the current holder runs"
        );
        assert_eq!(
            binding_state(&store, &first.binding_id),
            BindingState::Active
        );
        table.running.lock().unwrap().clear();
        assert_eq!(pass(&ops, &table).await, vec![first.binding_id.clone()]);
    }

    /// A holder replaced after the pass observed the old one exited, and before the
    /// release, keeps the binding: the release checks the holder row in its own
    /// transaction (the residual the two-transaction re-read left open).
    #[tokio::test]
    async fn a_holder_replaced_after_the_observation_keeps_the_binding() {
        /// Observes every holder exited, and replaces the binding's holder with a
        /// running one while it answers (a `bind` landing inside the pass).
        struct ReplacesWhileObserving {
            store: Arc<Store>,
            binding: BindingId,
        }
        impl ProcessLiveness for ReplacesWhileObserving {
            fn state(&self, _h: &ProcessHolder) -> HolderState {
                self.store
                    .transaction(|tx| tx.set_binding_holder(&self.binding, &holder(7002, "2.0")))
                    .unwrap();
                HolderState::Exited
            }
        }
        let (ops, store) = ops().await;
        let first = launch_binding(&ops, "w1", Some(holder(7001, "1.0"))).await;
        let liveness = ReplacesWhileObserving {
            store: Arc::clone(&store),
            binding: first.binding_id.clone(),
        };
        let released = ops.release_exited_holders(&liveness).await.unwrap().data;
        assert!(released.is_empty(), "{released:?}");
        assert_eq!(
            binding_state(&store, &first.binding_id),
            BindingState::Active
        );
    }

    /// One pass observes at most `MAX_HOLDERS_PER_PASS` held bindings, starting at
    /// the rotating offset, so the others are reached by later passes.
    #[test]
    fn a_pass_is_bounded_and_rotates() {
        let small: Vec<u32> = (0..10).collect();
        assert_eq!(rotate_bounded(small.clone(), 7), small, "fits: unchanged");
        let n = u32::try_from(MAX_HOLDERS_PER_PASS).unwrap() + 44;
        let many: Vec<u32> = (0..n).collect();
        let first = rotate_bounded(many.clone(), 0);
        assert_eq!(first.len(), MAX_HOLDERS_PER_PASS);
        assert_eq!(first[0], 0);
        let later = rotate_bounded(many.clone(), 100);
        assert_eq!(later.len(), MAX_HOLDERS_PER_PASS);
        assert_eq!(later[0], 100);
        // Wraps: the tail is followed by the head.
        assert_eq!(later[MAX_HOLDERS_PER_PASS - 1], (100 + 255) % n);
        let mut seen = BTreeSet::new();
        for offset in [0u64, 256] {
            seen.extend(rotate_bounded(many.clone(), offset));
        }
        assert_eq!(seen.len(), many.len(), "two rotations cover every binding");
    }
}
