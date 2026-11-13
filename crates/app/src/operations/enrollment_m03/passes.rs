//! The supervisor's enrollment passes (m03-plan U10): the step timeout (a result
//! that never arrives makes a mutating stage `Uncertain`, and a read retryable) and
//! the re-verification (ADR-0008 D5 §6.5, F27; §17.4 item 11).

use heimdall_contract::enrollment::{EnrollmentRequest, EnrollmentState, RemoteStage, VerifyMode};
use heimdall_contract::ids::{EnrollmentId, OperationId, RequestId};
use heimdall_domain::operation::enrollment_stage;
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_registry::fence::{DeadlineNow, HardDeadline, hard_deadline_passed};

use super::super::Operations;
use super::steps::{load_ctx, mark_uncertain};
use super::{journal_of, put_journal};
use crate::context::Caller;
use crate::enrollment::{StepPurpose, host_key_changed, version_token};
use crate::error::OpError;

impl Operations {
    /// The step-timeout pass (module docs). Returns the operations it moved.
    pub(super) async fn step_timeouts(&self) -> Result<Vec<OperationId>, OpError> {
        let clock = self.clock();
        let (boot, now_ms) = (clock.boot_id().0, super::steps::ms(clock.continuous()));
        let safe = self.timegate().check().await.ok().map(|s| s.wall());
        let now = self.narrowing_now().await;
        self.write(move |tx, emit| {
            let mut moved = Vec::new();
            let mut ops = tx.open_operations()?;
            for o in tx.unresolved_operations()? {
                if ops.iter().all(|x| x.id != o.id) {
                    ops.push(o);
                }
            }
            for op in ops {
                if !op.kind.is_enrollment() || op.state.is_settled() {
                    continue;
                }
                let receipts = tx.stage_receipts(&op.id)?;
                let Some(j) = journal_of(&receipts) else {
                    continue;
                };
                let Some(issued) = j.outstanding.clone() else {
                    continue;
                };
                // The step's own timeout, on the continuous clock of its boot; after a
                // reboot, only once safe wall time passed it (Q13).
                let timeout_deadline = HardDeadline {
                    continuous: std::time::Duration::from_millis(
                        issued
                            .issued_continuous_ms
                            .saturating_add(issued.timeout_ms),
                    ),
                    wall: super::super::plus(
                        issued.issued_wall,
                        std::time::Duration::from_millis(issued.timeout_ms),
                    ),
                    boot_id: issued.boot_id.clone(),
                };
                let passed = hard_deadline_passed(
                    &timeout_deadline,
                    &DeadlineNow {
                        boot_id: &boot,
                        continuous: std::time::Duration::from_millis(now_ms),
                        safe_wall: safe,
                    },
                );
                if !passed {
                    continue;
                }
                let Ok(mut ctx) = load_ctx(tx, &op.id)? else {
                    continue;
                };
                let marker = ctx.record.marker.clone();
                match issued.stage {
                    RemoteStage::Append | RemoteStage::Bootstrap | RemoteStage::Remove => {
                        let (token, stage) = match (issued.stage, issued.purpose) {
                            (RemoteStage::Append, _) => (marker.clone(), enrollment_stage::APPEND),
                            (RemoteStage::Bootstrap, _) => {
                                (format!("{marker}:dir"), enrollment_stage::BOOTSTRAP)
                            }
                            (_, StepPurpose::Rollback) => {
                                (format!("{marker}:rm"), enrollment_stage::ROLLBACK)
                            }
                            _ => (format!("{marker}:rm"), enrollment_stage::REMOVE),
                        };
                        if matches!(
                            ctx.record.state,
                            EnrollmentState::Applying
                                | EnrollmentState::RollbackPending
                                | EnrollmentState::Removing
                        ) {
                            mark_uncertain(tx, emit, &mut ctx, &issued, &token, stage, now)?;
                            moved.push(op.id.clone());
                        }
                    }
                    _ => {
                        // A read can be retried; a reconcile's lapsed fence ends the
                        // reconcile and counts as an attempt (it may have signalled).
                        ctx.journal.outstanding = None;
                        if issued.stage == RemoteStage::Fence {
                            ctx.journal.reconcile = None;
                            ctx.journal.fence_attempts =
                                ctx.journal.fence_attempts.saturating_add(1);
                        }
                        put_journal(tx, &op.id, &ctx.journal, now)?;
                        moved.push(op.id.clone());
                    }
                }
            }
            Ok(moved)
        })
        .await
    }

    /// The re-verification pass: every `verified` record whose evidence is older
    /// than `reverify_after` (80 days), or whose verifying client is not the current
    /// one (a prompt re-verification, §17.4 item 11), gets a non-interactive
    /// `enrollment.verify` (presence) that changes nothing remotely.
    ///
    /// ⟨round 3⟩ **A host-key change** (the `TargetEvaluator` now finds another key for
    /// the approved `HostName`, `Port` and `User`; D5 §6.5, ADR-0008 §17.22 item 7)
    /// already invalidated the evidence at the comparison (`ensure`'s managed report
    /// reads `destination_scope: unknown`). It **never triggers a login**: the pass
    /// opens the record's `enrollment.verify` at once, and that operation records the
    /// host-key mismatch from the evaluation alone, before any session or certificate
    /// exists (`verify_operation`), so the record is `held` (`host_key_changed`, not
    /// evidence-based) and the pair's grants under its CA are degraded. Only an
    /// attended, approved `ApproveTargetChange` verification can accept the new key;
    /// the pass never touches a `held` record.
    pub(super) async fn reverify_due(&self) -> Result<Vec<EnrollmentId>, OpError> {
        let Ok(ports) = self.verification_ports() else {
            return Ok(Vec::new());
        };
        let client = ports.host.client_version();
        let now = self.clock().wall();
        let after = self.limits().reverify_after;
        let (candidates, resume) = self
            .write(move |tx, _| {
                let mut out = Vec::new();
                let mut resume = Vec::new();
                for r in tx.open_enrollments()? {
                    let open = super::open_operation_of(tx, &r.id)?;
                    // ⟨ADR-0008 §17.31 items 8-9⟩ This pass's own re-verification left
                    // without a verdict (its reservation was refused by the uninstall
                    // fence, which records nothing): resumed once the fence is lifted,
                    // the deferral rule of §17.31 item 2. "Its own": the supervisor's
                    // principal and request namespace; "no verdict": still
                    // `reverifying`, the operation open, no verification entry reserved
                    // (so it runs at most once: a resumed run reserves, then settles).
                    if r.state == EnrollmentState::Reverifying
                        && let Some((op, _)) = &open
                        && op.kind == heimdall_domain::operation::OperationKind::EnrollmentVerify
                        && op.key.caller.principal == supervisor_principal()
                        && op
                            .key
                            .request_id
                            .as_str()
                            .starts_with(REVERIFY_REQUEST_PREFIX)
                        && tx.verification_entries(&op.id)?.is_empty()
                    {
                        resume.push((r.id.clone(), op.id.clone()));
                        continue;
                    }
                    if r.state != EnrollmentState::Verified || open.is_some() {
                        continue;
                    }
                    let alias = tx.destination(&r.destination)?.map(|d| d.alias);
                    out.push((r, alias));
                }
                Ok((out, resume))
            })
            .await?;
        let mut done = Vec::new();
        for (enrollment, op) in resume {
            if self.verify_operation(&op).await.is_ok() {
                done.push(enrollment);
            }
        }
        let mut due = Vec::new();
        for (r, alias) in candidates {
            let key_changed = match (&alias, ports.wiring.target.as_ref()) {
                (Some(a), Some(t)) => host_key_changed(&r.target, &t.evaluate(a)),
                _ => false,
            };
            let Some(e) = &r.evidence else {
                due.push(r.id.clone());
                continue;
            };
            let old = super::super::plus(e.verified_at, after) <= now;
            // A known current client the evidence does not name (§17.4 item 11).
            let changed = client
                .as_deref()
                .is_some_and(|c| !version_token(c).is_empty())
                && !crate::enrollment::evidence_client_current(&e.client, client.as_deref());
            if old || changed || key_changed {
                due.push(r.id.clone());
            }
        }
        // The supervisor's own idempotency namespace (no session: unattended,
        // non-interactive; a re-verification needs no decision).
        let caller = Caller::unattended(CallerContext {
            principal: supervisor_principal(),
            role: ClientRole::Owner,
        });
        for id in due {
            let request_id = RequestId::parse(&format!(
                "{REVERIFY_REQUEST_PREFIX}{}_{}",
                id.as_str(),
                now.as_second()
            ))
            .map_err(|_| super::super::internal("request id"))?;
            let r = self
                .enrollment_request(
                    &caller,
                    EnrollmentRequest::Verify {
                        enrollment_id: id.clone(),
                        request_id,
                        mode: VerifyMode::Presence,
                        wait: heimdall_contract::request::WaitMode::default(),
                    },
                )
                .await;
            if r.is_ok() || r.as_ref().is_err_and(|e| e.operation_id.is_some()) {
                done.push(id);
            }
        }
        Ok(done)
    }
}

/// The re-verification pass's own principal (no session: unattended; a fixed
/// supervisor identity, A-Q4).
fn supervisor_principal() -> PrincipalRef {
    PrincipalRef::UnixUser { uid: u32::MAX }
}

/// The request-ID namespace of the re-verification pass's own operations.
const REVERIFY_REQUEST_PREFIX: &str = "reverify_";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::enrollment::version_token;

    #[test]
    fn version_token_of_client_lines() {
        assert_eq!(version_token("OpenSSH_10.5p1, LibreSSL 3.3.6"), "10.5p1");
        assert_eq!(
            version_token("OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2"),
            "9.5p2"
        );
        assert_eq!(version_token("10.5p1"), "10.5p1");
    }
}
