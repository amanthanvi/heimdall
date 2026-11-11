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
use crate::enrollment::StepPurpose;
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
    /// ⟨round 2⟩ **A host-key change** (the `TargetEvaluator` now finds another key for
    /// the approved `HostName`, `Port` and `User`; D5 §6.5 freshness) invalidates the
    /// evidence at once: with [`HOST_KEY_CHANGE_PROMPT_REVERIFY`] the pass runs the
    /// presence re-verification promptly (at most once per `reverify_prompt_delay`),
    /// **with the approved target's pins**, so the server's other key ends it `held`
    /// (`host_key_changed`) and the pair's evidence stops counting. The new key is
    /// never accepted automatically: only an approved `ApproveTargetChange` does that,
    /// and the pass never touches a `held` record.
    pub(super) async fn reverify_due(&self) -> Result<Vec<EnrollmentId>, OpError> {
        let Ok(ports) = self.verification_ports() else {
            return Ok(Vec::new());
        };
        let client = ports.host.client_version();
        let now = self.clock().wall();
        let after = self.limits().reverify_after;
        let prompt = self.limits().reverify_prompt_delay;
        let candidates = self
            .write(move |tx, _| {
                let mut out = Vec::new();
                for r in tx.open_enrollments()? {
                    if r.state != EnrollmentState::Verified
                        || super::open_operation_of(tx, &r.id)?.is_some()
                    {
                        continue;
                    }
                    let alias = tx.destination(&r.destination)?.map(|d| d.alias);
                    out.push((r, alias));
                }
                Ok(out)
            })
            .await?;
        let mut due = Vec::new();
        for (r, alias) in candidates {
            let key_changed = HOST_KEY_CHANGE_PROMPT_REVERIFY
                && match (&alias, ports.wiring.target.as_ref()) {
                    (Some(a), Some(t)) => host_key_changed(&r.target, &t.evaluate(a)),
                    _ => false,
                };
            let Some(e) = &r.evidence else {
                due.push(r.id.clone());
                continue;
            };
            let old = super::super::plus(e.verified_at, after) <= now;
            let changed = client
                .as_deref()
                .map(version_token)
                .is_some_and(|v| !v.is_empty() && !e.client.split_whitespace().any(|t| t == v));
            // A host-key change re-verifies at most once per `reverify_prompt_delay`
            // (the approved key may still be the server's: a pass then renews it).
            let key_changed = key_changed && super::super::plus(e.verified_at, prompt) <= now;
            if old || changed || key_changed {
                due.push(r.id.clone());
            }
        }
        // The supervisor's own idempotency namespace (no session: unattended,
        // non-interactive; a re-verification needs no decision).
        let caller = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: u32::MAX },
            role: ClientRole::Owner,
        });
        let mut done = Vec::new();
        for id in due {
            let request_id =
                RequestId::parse(&format!("reverify_{}_{}", id.as_str(), now.as_second()))
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

/// ⟨round 2⟩ The fail-closed reading of D5 §6.5's host-key invalidation (questions
/// file R2-A-Q1): a verified pair whose approved host key the evaluator no longer
/// finds is re-verified at once with the approved pins (ending `held`,
/// `host_key_changed`), instead of keeping its evidence until it ages out.
pub(super) const HOST_KEY_CHANGE_PROMPT_REVERIFY: bool = true;

/// Whether `eval` finds the approved `HostName`, `Port` and `User`, directly and
/// determined, but not exactly the approved host key (a host-key change; a route
/// change is not one).
fn host_key_changed(
    approved: &heimdall_contract::enrollment::ApprovedTarget,
    eval: &heimdall_domain::enrollment::TargetEvaluation,
) -> bool {
    use heimdall_domain::enrollment::{Determinism, ProxyRoute};
    eval.determinism == Determinism::Determined
        && eval.proxy == ProxyRoute::None
        && eval.hostname == approved.hostname
        && eval.port == approved.port
        && eval.user == approved.user.as_str()
        && !crate::enrollment::route_matches(approved, eval)
}

/// The version token of a client version line: `OpenSSH_10.5p1, LibreSSL …` →
/// `10.5p1` (the Verifier's evidence names the client as `<path> <family> <version>`).
fn version_token(line: &str) -> &str {
    let first = line.split([',', ' ']).next().unwrap_or("");
    first.rsplit_once('_').map_or(first, |(_, v)| v).trim()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn version_token_of_client_lines() {
        assert_eq!(
            super::version_token("OpenSSH_10.5p1, LibreSSL 3.3.6"),
            "10.5p1"
        );
        assert_eq!(
            super::version_token("OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2"),
            "9.5p2"
        );
        assert_eq!(super::version_token("10.5p1"), "10.5p1");
    }
}
