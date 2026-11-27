//! ⟨M06 U4⟩ The runner runtime's side of typed narrowing effects and the authority report
//! (ADR-0012 §7.2, §7.4 step 3; m06-plan U4).
//!
//! `runner.deliver_effect` and `runner.authority_report` are applied by
//! `heimdall_remote::sync::RunnerSync` over this runtime's operations (the runner's own
//! narrowing machinery). This module gives it the runner runtime's process state
//! ([`RunnerSide`]): K_env and the installed certificates live in [`super::issuance`]'s
//! memory, and the bound on now comes from the designated time source's last qualifying
//! sample ([`super::time`]).
//!
//! * **Grant end** (a delivered `grant_revoke`): after the tombstone commits, K_env of the
//!   grant and of each descendant is zeroized and its certificates dropped, also from the
//!   runner's signer table with its bindings (`RunnerKeys::destroy`), so nothing signs for it
//!   after the acknowledgement.
//! * **The upper bound of now** for a cutoff under uncertain time: with a qualifying sample
//!   of this boot, now is at most `T_c + rtt + (continuous now − t2)`; without one there is no
//!   bound and the cutoff fires at once.

use heimdall_app::context::Caller;
use heimdall_app::{OpError, OpResult};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::GrantId;
use heimdall_contract::remote::RunnerRequest;
use heimdall_remote::sync::{RunnerSide, RunnerSync};
use heimdall_store::ext_effects::{AuthorityReport, ReportedCertificate};

use super::RunnerRuntime;

impl RunnerSide for RunnerRuntime {
    fn destroy_keys(&self, grant: &GrantId) -> bool {
        self.issuance.destroy(grant)
    }

    fn now_upper_bound(&self) -> Option<Timestamp> {
        let sample = self.time().sample()?;
        let e = &sample.exchange;
        // Elapsed on the continuous clock since the challenge was issued: the whole round
        // trip and everything after the answer.
        let since = self.clock.continuous().checked_sub(e.t1)?;
        let since = jiff::SignedDuration::try_from(since).ok()?;
        e.controller_time.checked_add(since).ok()
    }

    fn keyed_grants(&self) -> Vec<GrantId> {
        self.issuance.keys().grants()
    }

    fn installed_certificates(&self) -> Vec<ReportedCertificate> {
        let installed = self.issuance.keys().installed();
        if installed.is_empty() {
            return Vec::new();
        }
        // The issuing controller is the grant's pin. A certificate whose pin cannot be read
        // is not reported with a guessed issuer: it is left out, and the issuer's barrier
        // treats a counted certificate missing from the report as still counted.
        let pins = self
            .store
            .transaction(|tx| tx.remote_grant_issuers())
            .unwrap_or_default();
        installed
            .into_iter()
            .filter_map(|(grant, generation, pair, c)| {
                let issuer = pins
                    .iter()
                    .find(|p| p.grant == grant)?
                    .issuer_client
                    .clone();
                Some(ReportedCertificate {
                    grant,
                    grant_generation: generation,
                    pair,
                    serial: c.serial,
                    valid_before: c.valid_before,
                    issuer,
                })
            })
            .collect()
    }
}

/// ⟨M08 W4 SEC-3b, R5; ADR-0012 §7.4 as amended 2026-11-27⟩ The serialized budget of one
/// authority report: the page budget, 256 KiB below one control frame
/// (`heimdall_contract::page::PAGE_BUDGET_BYTES`).
pub const REPORT_BUDGET_BYTES: usize = heimdall_contract::page::PAGE_BUDGET_BYTES;

/// ⟨M08 W4 SEC-3b, R5⟩ A report whose serialized form is over [`REPORT_BUDGET_BYTES`] is
/// refused whole, `USAGE_ERROR` / `response_too_large`, effect none: never paged, never
/// truncated (a truncated report would hide tombstones and in-force revisions). The pruning
/// of the runner's history brings it back under the budget.
///
/// # Errors
/// The refusal.
pub fn report_within_budget(report: &AuthorityReport) -> Result<(), OpError> {
    let size = serde_json::to_vec(report)
        .map_err(|_| {
            OpError::new(
                Code::InternalError,
                "the authority report cannot be encoded",
            )
        })?
        .len();
    if size > REPORT_BUDGET_BYTES {
        return Err(OpError::new(
            Code::UsageError,
            format!(
                "the runner's authority report is over its size limit ({size} bytes, limit \
                 {REPORT_BUDGET_BYTES}); remote issuance stays closed until history ages out \
                 (retention)"
            ),
        )
        .with_reason(reason::RESPONSE_TOO_LARGE)
        .with_effect(EffectStatus::None));
    }
    Ok(())
}

impl RunnerRuntime {
    /// ⟨M06 W4; ADR-0005 §3.5 condition 8 (b)⟩ The grants this runner admitted that wait
    /// for their issuer, for the authority report: the grant of every open, running
    /// operation whose mechanism is `managed_certificate`, still `preparing`, for which
    /// the runner's signer holds no complete set of certificates. A store failure reports
    /// none (nothing is then issued for them: fail closed).
    #[must_use]
    pub fn pending_grants(&self) -> Vec<heimdall_store::ext_effects::ReportedPendingGrant> {
        use heimdall_app::operations::{MANAGED_CERTIFICATE, RunnerGrants as _};
        use heimdall_contract::state::OperationState;
        let listed = self.store.transaction(|tx| {
            let mut out = std::collections::BTreeMap::new();
            for op in tx.open_operations()? {
                if op.state != OperationState::Running {
                    continue;
                }
                let Some(resolved) = tx.recovery_intent(&op.id)?.and_then(|i| i.resolved) else {
                    continue;
                };
                let (Some(grant), Some(adapter)) = (resolved.grant, resolved.adapter) else {
                    continue;
                };
                if adapter.mechanism != MANAGED_CERTIFICATE {
                    continue;
                }
                let Some(g) = tx.grant(&grant)? else {
                    continue;
                };
                if g.state != heimdall_contract::GrantState::Preparing {
                    continue;
                }
                let Some(origin) = tx.grant_origin(&grant)? else {
                    continue;
                };
                out.insert(
                    grant.clone(),
                    heimdall_store::ext_effects::ReportedPendingGrant {
                        grant,
                        profile: origin.profile,
                        pairs: g.scope.pairs,
                        expires_at: g.deadline.effective,
                    },
                );
            }
            Ok(out)
        });
        listed
            .unwrap_or_default()
            .into_values()
            .filter(|p| !self.issued(&p.grant))
            .collect()
    }

    /// ⟨M06 U4⟩ Whether `request` is one of the forms [`Self::serve_sync`] serves.
    #[must_use]
    pub fn is_sync_request(request: &RunnerRequest) -> bool {
        matches!(
            request,
            RunnerRequest::DeliverEffect { .. } | RunnerRequest::AuthorityReport
        )
    }

    /// ⟨M06 U4⟩ Serve a paired controller's `runner.deliver_effect` or
    /// `runner.authority_report` (module docs) with `sync`, the runner's sync service over
    /// its operations. `caller` is the paired session's caller: its client is the effect's
    /// producer; `connection` is the session's serial (the issuance gate is per session).
    ///
    /// # Errors
    ///
    /// The request's refusal (`heimdall_remote::sync`); `driver_unavailable` for another
    /// form.
    pub async fn serve_sync(
        &self,
        sync: &RunnerSync,
        caller: &Caller,
        connection: u64,
        request: &RunnerRequest,
    ) -> OpResult<serde_json::Value> {
        let controller = caller.context.remote_client.clone();
        match request {
            RunnerRequest::DeliverEffect { effect, target } => {
                // ⟨M06 W3⟩ The session's view is stale from here: gated until it reads a
                // fresh report (`super`, "The per-session issuance gate").
                if let Some(c) = &controller {
                    self.note_effect_delivered(c, connection);
                }
                super::ok(sync.deliver(self, caller, effect, target).await?)
            }
            RunnerRequest::AuthorityReport => {
                let mut report = sync.authority_report(self, caller).await?;
                // ⟨M06 W4⟩ The grants that wait for their issuer (condition 8 (b)).
                report.pending_grants = self.pending_grants();
                // ⟨M08 W4 SEC-3b, R5⟩ No paging and no truncation: a report over its budget is
                // refused whole, and the session is not resynchronized (its issuance gate
                // stays closed, and the controller's barrier with it).
                report_within_budget(&report)?;
                if let Some(c) = &controller {
                    self.note_report_served(c, connection);
                    // ⟨M08 W4 SEC-3b, R2⟩ What this complete report showed the controller of
                    // its own lifted revisions (`super`, "Lift confirmation").
                    let shown = report
                        .policy_revisions
                        .iter()
                        .filter(|r| !r.in_force && r.producer == *c)
                        .map(|r| (r.scope_key.clone(), r.revision))
                        .collect();
                    self.note_lifts_shown(c, connection, shown);
                }
                super::ok(report)
            }
            _ => Err(OpError::driver_unavailable(
                "this runner request is not served by the sync service",
            )),
        }
    }
}
