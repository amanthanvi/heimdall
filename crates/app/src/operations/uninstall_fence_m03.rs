//! ⟨M03; ADR-0008 §17.27 item 2, §17.28 item 1 (W5-S01)⟩ The uninstall fence: while
//! one control connection holds it, every **other** connection's request that can start
//! or advance remote or CA work is refused `SERVICE_UNAVAILABLE`, reason
//! `uninstall_in_progress` (`heimdall_contract::request::UninstallFenceRequest`).
//!
//! **Where the gate lives.** The runtime's dispatcher knows the connection, so it
//! classifies each request (`heimdall_runtime::dispatch`'s table, also in
//! `.m03-wave5-r3-api.md` § U3) and, for a fenced one from a connection that is not the
//! holder, takes the shared admission guard ([`Operations::uninstall_fence_admission`]),
//! refuses while another connection holds the fence, and otherwise keeps the guard
//! until the request has been handled. The holder's requests run inside
//! [`as_fence_holder`] and are never refused. Two checks stay here, for work no request
//! carries: every certificate reservation (`Operations::reserve_issuance_with`, the
//! one choke point; refused unless it runs in the holder's scope) and the supervisor
//! passes `Operations::reverify_pass` and `Operations::managed_reissue_pass` (they do
//! nothing while it is held).
//!
//! **Serialization.** `acquire` takes the admission guard exclusively, so it completes
//! only after every fenced request already past its check has been handled (bounded by
//! [`ACQUIRE_WAIT`]), and none passes its check after it. An inventory read after
//! `acquire` therefore sees every obligation admitted before it.
//!
//! **Revalidation input.** [`unresolved_remote_steps`]: the enrollment operations with
//! a dispatched step whose result is not recorded, or whose remote effect is unknown.
//!
//! **Lifetime** (held by one connection, identified by the runtime's dispatcher):
//! released by `release` on that connection, when that connection ends for any reason
//! (the dispatcher's per-connection guard), and with the runtime (it is never stored).

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use heimdall_contract::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::OperationId;
use heimdall_store::Txn;

use super::Operations;
use crate::error::OpError;

/// How long `acquire` waits for fenced requests already past their check.
pub const ACQUIRE_WAIT: Duration = Duration::from_secs(20);

/// The fence's state (one per runtime, in `Operations`).
#[derive(Debug, Default)]
pub(crate) struct UninstallFence {
    /// The holding connection, if any.
    holder: Mutex<Option<u64>>,
    /// Shared by each fenced request from its check to its end; exclusive for
    /// `acquire`.
    admissions: tokio::sync::RwLock<()>,
}

tokio::task_local! {
    /// Set while the holder's own request is handled ([`as_fence_holder`]).
    static FENCE_HOLDER: ();
}

/// Run `f` as the fence holder's request: the checks in this crate never refuse it.
/// (Work it spawns runs outside this scope, as any background work.)
pub async fn as_fence_holder<F: std::future::Future>(f: F) -> F::Output {
    FENCE_HOLDER.scope((), f).await
}

fn in_holder_scope() -> bool {
    FENCE_HOLDER.try_with(|()| ()).is_ok()
}

/// The refusal of fenced work (`SERVICE_UNAVAILABLE`, `uninstall_in_progress`).
#[must_use]
pub fn uninstall_in_progress() -> OpError {
    OpError::new(
        Code::ServiceUnavailable,
        "an uninstall is in progress: no new or continued enrollment, CA or issuance work, and no approval, is admitted until it ends",
    )
    .with_reason(reason::UNINSTALL_IN_PROGRESS)
}

/// What [`Operations::uninstall_fence_acquire`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FenceAcquired {
    /// This connection now holds it (or already did).
    Held,
}

impl UninstallFence {
    fn holder(&self) -> Option<u64> {
        *self.holder.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Held by a fenced request from its check until it has been handled.
pub type FenceAdmission<'a> = tokio::sync::RwLockReadGuard<'a, ()>;

impl Operations {
    /// The shared admission guard a fenced request holds from its check (against
    /// [`Self::uninstall_fence_holder`]) until it has been handled.
    pub async fn uninstall_fence_admission(&self) -> FenceAdmission<'_> {
        self.inner.uninstall_fence.admissions.read().await
    }

    /// The connection holding the uninstall fence, if any.
    #[must_use]
    pub fn uninstall_fence_holder(&self) -> Option<u64> {
        self.inner.uninstall_fence.holder()
    }

    /// Whether the uninstall fence is held (by any connection).
    #[must_use]
    pub fn uninstall_fence_held(&self) -> bool {
        self.uninstall_fence_holder().is_some()
    }

    /// The check of work no request carries (a certificate reservation): refused while
    /// the fence is held, unless it runs in the holder's scope ([`as_fence_holder`]).
    pub(crate) fn fence_check(&self) -> Result<(), OpError> {
        if self.uninstall_fence_held() && !in_holder_scope() {
            return Err(uninstall_in_progress());
        }
        Ok(())
    }

    /// `uninstall_fence.acquire` for `connection` (the dispatcher's per-connection
    /// identity): waits (bounded by [`ACQUIRE_WAIT`]) until every fenced request already
    /// past its check has been handled, then holds the fence. Idempotent on the holding
    /// connection.
    ///
    /// # Errors
    /// `SERVICE_UNAVAILABLE` / `uninstall_in_progress` while another connection holds
    /// it, or when fenced requests did not drain in time (nothing changed).
    pub async fn uninstall_fence_acquire(&self, connection: u64) -> Result<FenceAcquired, OpError> {
        let fence = &self.inner.uninstall_fence;
        let Ok(_exclusive) = tokio::time::timeout(ACQUIRE_WAIT, fence.admissions.write()).await
        else {
            return Err(OpError::new(
                Code::ServiceUnavailable,
                "work being admitted did not settle in time, so the uninstall fence was not taken; nothing was changed",
            )
            .with_reason(reason::UNINSTALL_IN_PROGRESS));
        };
        let mut holder = fence.holder.lock().unwrap_or_else(PoisonError::into_inner);
        match *holder {
            Some(h) if h != connection => Err(OpError::new(
                Code::ServiceUnavailable,
                "another uninstall holds the fence; nothing was changed",
            )
            .with_reason(reason::UNINSTALL_IN_PROGRESS)),
            _ => {
                *holder = Some(connection);
                Ok(FenceAcquired::Held)
            }
        }
    }

    /// `uninstall_fence.release` for `connection`, and the release when that
    /// connection ends: lifts the fence if `connection` holds it, else does nothing.
    /// Returns whether the fence is still held (by another connection).
    pub fn uninstall_fence_release(&self, connection: u64) -> bool {
        let mut holder = self
            .inner
            .uninstall_fence
            .holder
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *holder == Some(connection) {
            *holder = None;
        }
        holder.is_some()
    }
}

/// ⟨ADR-0008 §17.28 item 1⟩ The enrollment operations (open or `outcome_unknown`) whose
/// current journal has a dispatched step without its recorded result (`outstanding`)
/// or an uncertain remote mutation (`uncertain`: its remote effect is unknown), oldest
/// first. Read-only (it runs on a store opened read-only); an operation without a
/// journal has none.
///
/// # Errors
/// A store failure.
pub fn unresolved_remote_steps(tx: &mut Txn<'_>) -> heimdall_store::Result<Vec<OperationId>> {
    let mut ops = tx.open_operations()?;
    ops.extend(tx.unresolved_operations()?);
    ops.retain(|o| o.kind.is_enrollment());
    ops.sort_by(|a, b| (a.created_at, a.id.as_str()).cmp(&(b.created_at, b.id.as_str())));
    ops.dedup_by(|a, b| a.id == b.id);
    let mut out = Vec::new();
    for op in ops {
        let receipts = tx.stage_receipts(&op.id)?;
        if super::enrollment_m03::journal_of(&receipts)
            .is_some_and(|j| j.outstanding.is_some() || j.uncertain.is_some())
        {
            out.push(op.id);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, GrantId};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::scope::AccessPair;
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_store::Store;
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

    use super::*;
    use crate::Caller;
    use crate::ensure::NoStageHook;
    use crate::operations::{IssuanceFacts, IssuanceRequest, Limits, OperationsConfig};

    fn t0() -> Timestamp {
        "2026-11-13T09:00:00Z".parse().unwrap()
    }

    async fn ops() -> Operations {
        let env = EnvironmentId::from_random_bytes([9; 16]);
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        store
            .transaction(|tx| tx.init_self_environment(&env))
            .unwrap();
        Operations::start(OperationsConfig {
            store,
            clock: VirtualClock::at(t0()),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env,
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: Duration::from_secs(3600),
            projection: None,
        })
        .await
        .unwrap()
    }

    fn owner() -> Caller {
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        })
    }

    fn issuance() -> IssuanceRequest {
        IssuanceRequest {
            grant: GrantId::from_random_bytes([3; 16]),
            pair: AccessPair {
                destination: DestinationId::parse("dst-lab").unwrap(),
                account: AccountName::parse("deploy").unwrap(),
            },
            principal: "hm:dst-lab:deploy".to_owned(),
            key_id: "k".to_owned(),
            valid_after: t0(),
            valid_before: t0(),
            extensions: BTreeSet::new(),
            subject_fingerprint: "SHA256:x".to_owned(),
            facts: IssuanceFacts {
                new_activation: true,
                subject_registered: true,
                critical_option: false,
            },
        }
    }

    fn is_fenced(e: &OpError) -> bool {
        e.code == Code::ServiceUnavailable
            && e.reason.as_deref() == Some(reason::UNINSTALL_IN_PROGRESS)
    }

    /// `uninstall_fence_checks_work_no_request_carries` (ADR-0008 §17.27 item 2,
    /// §17.28 item 1): while the fence is held, a certificate reservation outside the
    /// holder's scope is refused `SERVICE_UNAVAILABLE` / `uninstall_in_progress` before
    /// anything is written, and the supervisor passes do nothing; the holder's own
    /// reservation is not refused for the fence. A second connection's `acquire` is
    /// refused; its `release` does not lift the fence; the holder's does.
    #[tokio::test]
    async fn uninstall_fence_checks_work_no_request_carries() {
        let ops = ops().await;
        if let Err(e) = ops.reserve_issuance(issuance()).await {
            assert!(!is_fenced(&e), "{e:?}");
        }
        assert_eq!(
            ops.uninstall_fence_acquire(1).await.unwrap(),
            FenceAcquired::Held
        );
        assert_eq!(
            ops.uninstall_fence_acquire(1).await.unwrap(),
            FenceAcquired::Held,
            "idempotent"
        );
        assert!(is_fenced(
            &ops.uninstall_fence_acquire(2).await.unwrap_err()
        ));
        assert_eq!(ops.uninstall_fence_holder(), Some(1));
        assert!(is_fenced(
            &ops.reserve_issuance(issuance()).await.unwrap_err()
        ));
        if let Err(e) = as_fence_holder(ops.reserve_issuance(issuance())).await {
            assert!(!is_fenced(&e), "the holder's own: {e:?}");
        }
        assert!(ops.reverify_pass().await.unwrap().is_empty());
        assert!(ops.managed_reissue_pass().await.unwrap().is_empty());
        assert!(ops.uninstall_fence_release(2), "still held by 1");
        assert!(!ops.uninstall_fence_release(1));
        assert!(!ops.uninstall_fence_held());
        if let Err(e) = ops.reserve_issuance(issuance()).await {
            assert!(!is_fenced(&e), "{e:?}");
        }
        assert_eq!(
            ops.uninstall_fence_acquire(2).await.unwrap(),
            FenceAcquired::Held
        );
    }

    /// The fence serializes with fenced requests: `acquire` waits for one already past
    /// its check (holding the admission guard).
    #[tokio::test]
    async fn uninstall_fence_acquire_waits_for_admissions_in_progress() {
        let ops = ops().await;
        let admission = ops.uninstall_fence_admission().await;
        let o2 = ops.clone();
        let acquiring = tokio::spawn(async move { o2.uninstall_fence_acquire(7).await });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!acquiring.is_finished(), "acquire waits for the admission");
        assert!(!ops.uninstall_fence_held());
        drop(admission);
        assert_eq!(acquiring.await.unwrap().unwrap(), FenceAcquired::Held);
        assert_eq!(ops.uninstall_fence_holder(), Some(7));
    }

    /// `unresolved_remote_steps_lists_dispatched_and_uncertain_steps` (ADR-0008 §17.28
    /// item 1): an open enrollment operation whose journal has a dispatched step without
    /// its result, or an uncertain mutation, is listed; one with neither, or with no
    /// journal, is not.
    #[tokio::test]
    async fn unresolved_remote_steps_lists_dispatched_and_uncertain_steps() {
        use crate::enrollment::{IssuedStep, Journal, StepPurpose, UncertainStep};
        use heimdall_contract::enrollment::RemoteStage;
        let ops = ops().await;
        let issued = IssuedStep {
            stage: RemoteStage::Append,
            token: "ab".repeat(16),
            purpose: StepPurpose::Append,
            issued_continuous_ms: 0,
            issued_wall: t0(),
            boot_id: "boot".into(),
            timeout_ms: 1,
            hard_deadline_ms: 1,
            hard_deadline_wall: t0(),
            not_after_remote: None,
            terminate: false,
            preimage: None,
            post_image: None,
        };
        let uncertain = UncertainStep {
            stage: RemoteStage::Append,
            token: "cd".repeat(16),
            not_after_remote: None,
            purpose: StepPurpose::Append,
            hard_deadline_ms: 0,
            hard_deadline_wall: t0(),
            boot_id: "boot".into(),
        };
        let journals = [
            Some(Journal {
                outstanding: Some(issued),
                ..Journal::default()
            }),
            Some(Journal {
                uncertain: Some(uncertain),
                ..Journal::default()
            }),
            Some(Journal::default()),
            None,
        ];
        let mut ids = Vec::new();
        for (n, journal) in (1u8..).zip(journals) {
            ids.push(seed_op(&ops, n, journal));
        }
        let found = ops
            .inner
            .config
            .store
            .transaction(unresolved_remote_steps)
            .unwrap();
        assert_eq!(found, ids[..2].to_vec());
    }

    /// Seed a running `enrollment.apply` operation `n` with `journal` (if any).
    fn seed_op(
        ops: &Operations,
        n: u8,
        journal: Option<crate::enrollment::Journal>,
    ) -> heimdall_contract::ids::OperationId {
        use heimdall_contract::canonical::RequestHash;
        use heimdall_contract::ids::{OperationId, RequestId};
        use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
        use heimdall_domain::operation::{
            EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
        };
        let id = OperationId::from_random_bytes([n; 16]);
        let key = IdempotencyKey {
            caller: owner().context,
            kind: OperationKind::EnrollmentApply,
            request_id: RequestId::parse(&format!("seed-{n}")).unwrap(),
        };
        let at = t0().checked_add(Duration::from_secs(u64::from(n))).unwrap();
        let op = OperationRecord {
            id: id.clone(),
            kind: OperationKind::EnrollmentApply,
            environment: ops.inner.config.environment.clone(),
            key: key.clone(),
            request_hash: RequestHash([n; 32]),
            effect_class: EffectClass::RemoteMutation,
            state: heimdall_contract::OperationState::Running,
            code: None,
            effect_status: heimdall_contract::envelope::EffectStatus::Unknown,
            result: None,
            created_at: at,
            updated_at: at,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        ops.inner
            .config
            .store
            .transaction(|tx| {
                tx.insert_operation(
                    &op,
                    &IdempotencyRecord {
                        key: key.clone(),
                        request_hash: op.request_hash,
                        operation_id: id.clone(),
                        created_at: at,
                        expires_at: None,
                    },
                )?;
                if let Some(j) = &journal {
                    super::super::enrollment_m03::put_journal(tx, &id, j, at)?;
                }
                Ok(())
            })
            .unwrap();
        id
    }
}
