//! ⟨M06 U3⟩ The runner runtime (ADR-0012 §4; ADR-0005 §3.5–§3.7, §4.2–§4.3; m06-plan U3).
//!
//! A `remote_runner` installation (`crate::paired::init_runner`) owns its signer (K_env in
//! memory), its grants, tombstones and readiness, and cannot issue. This module serves the
//! controller's `runner/1` requests and computes the runner's readiness:
//!
//! * [`issuance`]: `prepare_remote_grant` and `install_certificate`, pinned to the issuing
//!   controller and CA, with ADR-0005 §3.5's install checks;
//! * [`time`]: the designated time source (`time_challenge` / `time_response`): fresh,
//!   nonce-bound, RTT-bounded samples that only move anchors earlier and never act as
//!   `confirm_time`;
//! * [`RunnerRuntime::readiness`]: the earliest-bound `offline_until`, the conditions and the
//!   per-component residuals (`heimdall_app::readiness`);
//! * [`launch`]: the clean-environment launch of runner work and the provenance of agents
//!   (`dependency_provenance_unknown`, `controller_dependency`);
//! * [`lifetime`]: a verified `systemd --user` unit where linger is on, else `session_scope`.
//!
//! **Wiring** (the integrator's): a runner runtime builds one [`RunnerRuntime`] over its store,
//! clock and the signer's vault, and the dispatcher hands every paired `Request::Runner` that
//! passed `heimdall_remote::roles::check` to [`RunnerRuntime::handle`] with the session's caller
//! and a connection serial (in place of `Operations::revision_6_request`). `deliver_effect` and
//! `authority_report` stay U4's (`driver_unavailable` here).

#[path = "runner_issuance.rs"]
pub mod issuance;
#[path = "runner_launch.rs"]
pub mod launch;
#[path = "runner_lifetime.rs"]
pub mod lifetime;
#[path = "runner_time.rs"]
pub mod time;

use std::sync::Arc;

use heimdall_app::readiness::{RunnerReadiness, RunnerReadinessInput, runner_readiness};
use heimdall_app::readiness_runner::runner_bound;
use heimdall_app::{OpError, OpResult};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::ids::GrantId;
use heimdall_contract::managed::DestinationClock;
use heimdall_contract::remote::{RunnerLifetime, RunnerRequest};
use heimdall_credential::vault::KeyVault;
use heimdall_domain::principal::CallerContext;
use heimdall_domain::time::Clock;
use heimdall_store::Store;

use self::issuance::RunnerIssuance;
use self::time::{RunnerTime, RunnerTimePolicy, TimeSession};

/// The runner runtime's issuance, time source and readiness (module docs).
pub struct RunnerRuntime {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    issuance: RunnerIssuance,
    lifetime: RunnerLifetime,
}

impl std::fmt::Debug for RunnerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerRuntime")
            .field("issuance", &self.issuance)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

fn ok(data: impl serde::Serialize) -> OpResult<serde_json::Value> {
    let data = serde_json::to_value(data)
        .map_err(|_| OpError::new(Code::InternalError, "result encoding failed"))?;
    Ok(heimdall_app::error::Completed::ok(Code::Ok, data))
}

impl RunnerRuntime {
    /// A runner runtime over `store` and `clock`, holding K_env in `vault`, with the time
    /// policy `policy` and the detected `lifetime` (`lifetime::detect`).
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        vault: Arc<KeyVault>,
        policy: RunnerTimePolicy,
        lifetime: RunnerLifetime,
    ) -> Self {
        let time = Arc::new(RunnerTime::new(Arc::clone(&clock), policy));
        Self {
            issuance: RunnerIssuance::new(Arc::clone(&store), Arc::clone(&clock), time, vault),
            store,
            clock,
            lifetime,
        }
    }

    /// Issuance.
    #[must_use]
    pub fn issuance(&self) -> &RunnerIssuance {
        &self.issuance
    }

    /// The time-sample state.
    #[must_use]
    pub fn time(&self) -> &Arc<RunnerTime> {
        self.issuance.time()
    }

    /// The lifetime reported.
    #[must_use]
    pub fn lifetime(&self) -> RunnerLifetime {
        self.lifetime
    }

    /// Serve one paired `runner/1` request (module docs, "Wiring"). `caller` is the paired
    /// session's (its `remote_client` is the controller); `connection` the session's serial.
    /// A caller without a paired client is refused: these requests come only from a
    /// controller. Synchronous store and vault work: call it on the blocking pool.
    ///
    /// # Errors
    ///
    /// The request's refusal.
    pub fn handle(
        &self,
        caller: &CallerContext,
        connection: u64,
        request: &RunnerRequest,
    ) -> OpResult<serde_json::Value> {
        let Some(controller) = caller.remote_client.clone() else {
            return Err(OpError::driver_unavailable(
                "runner requests are served to a paired controller only",
            ));
        };
        let session = TimeSession {
            client: controller.clone(),
            connection,
        };
        match request {
            RunnerRequest::PrepareRemoteGrant {
                grant,
                grant_generation,
            } => ok(self
                .issuance
                .prepare(&controller, grant, *grant_generation)
                .map_err(|e| e.to_error())?),
            RunnerRequest::InstallCertificate {
                grant,
                grant_generation,
                certificate,
            } => ok(self
                .issuance
                .install(&controller, grant, *grant_generation, certificate)
                .map_err(|e| e.to_error())?),
            RunnerRequest::TimeChallenge => {
                let time = self.time();
                let data = self
                    .store
                    .transaction(|tx| Ok(time.challenge(tx, &session)))?
                    .map_err(time::TimeRefusal::to_error)?;
                ok(data)
            }
            RunnerRequest::TimeResponse {
                nonce,
                controller_time,
            } => {
                let time = self.time();
                let data = self
                    .store
                    .transaction(|tx| Ok(time.respond(tx, &session, nonce, *controller_time)))?
                    .map_err(time::TimeRefusal::to_error)?;
                ok(data)
            }
            _ => Err(OpError::driver_unavailable(
                "this runner request is not available in this build",
            )),
        }
    }

    /// A runner grant's readiness (ADR-0012 §4.5; `heimdall_app::readiness`): `destination_clock`
    /// is the weakest of its pairs' measurements, `counted_expiry` the counted issuance
    /// history's latest `valid_before` when the caller knows it (`None`: `unknown`).
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for an unknown grant; `STATE_UNAVAILABLE`.
    pub fn readiness(
        &self,
        grant: &GrantId,
        destination_clock: DestinationClock,
        counted_expiry: Option<Timestamp>,
    ) -> Result<RunnerReadiness, OpError> {
        let (snapshot, parts, anchor) = self
            .store
            .transaction(|tx| {
                let Some(g) = tx.grant(grant)? else {
                    return Ok(None);
                };
                let parts = runner_bound(tx, &g)?;
                let anchor = tx.grant_anchor(grant)?;
                Ok(Some((g, parts, anchor)))
            })?
            .ok_or_else(|| {
                OpError::new(Code::NotFound, "no such grant").with_resource("grant", None)
            })?;
        let now = self.clock.observe();
        let certificate_valid_before = self
            .issuance
            .keys()
            .certificates(&snapshot.id)
            .values()
            .map(|c| c.valid_before)
            .min();
        Ok(runner_readiness(&RunnerReadinessInput {
            now: &now,
            deadline: parts.deadline,
            parent_deadline: parts.parent_deadline,
            cutoff: parts.cutoff,
            anchor: anchor.as_ref(),
            time_bounded: self.time().bounded(),
            certificate_valid_before,
            destination_clock,
            counted_expiry,
            lifetime: self.lifetime,
        }))
    }
}
