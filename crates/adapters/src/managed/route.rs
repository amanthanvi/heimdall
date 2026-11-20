//! ⟨M04 U6⟩ The managed adapter's route-aware parts (ADR-0010 §5; reading I-4, I-5;
//! review finding M04-D04): what a single-hop `ProxyJump` changes in a preparation.
//! Pure over the snapshot; nothing here reads the store or runs an effect.
//!
//! * **Evidence through a route.** [`evidence_survives`]: a pair's verified-scope
//!   evidence holds through the route the catalog approves
//!   (`heimdall_app::enrollment::route_matches_via`) and is **withheld from the
//!   snapshot** while the jump hop is unusable (`jump_hop_usable`: its own host key
//!   changed, or it is undetermined). The stored record is untouched, so the evidence
//!   returns with the hop; an `ensure` requiring verified scope refuses meanwhile
//!   (`destination_scope` reads `unknown`).
//! * **Readiness.** [`apply_to_report`]: a routed pair adds
//!   `ReadinessCondition::RouteDependency`; the pair's lock continuity is the weaker of
//!   its two hops, and a jump hop on existing access has its provider's lock
//!   continuity, which the managed adapter does not know: it caps the route at
//!   `not_verified` (never claims more than it observed).
//! * **The pair's route** ([`route_view`]) for `PairIntegration.route`.

use heimdall_app::enrollment::{evidence_holds, jump_hop_usable};
use heimdall_app::ports::{PairRoute, PreparePair};
use heimdall_contract::environment::{JumpAccess, RouteView};
use heimdall_contract::managed::{LockContinuityReport, ReadinessCondition};
use heimdall_domain::enrollment::{EnrollmentRecord, TargetEvaluation};

use super::report::ManagedReport;

/// `PairIntegration.route` of a pair: its jump, the alias `ProxyJump` renders, and how
/// the jump hop is accessed.
#[must_use]
pub fn route_view(pair: &PreparePair) -> Option<RouteView> {
    pair.route.as_ref().map(|r| RouteView {
        jump: r.approved.jump.clone(),
        jump_alias: r.approved.jump_alias.clone(),
        jump_access: r.access,
    })
}

/// Whether `record`'s evidence still holds for its pair, given the evaluations of the
/// pair's alias (`eval`) and of its jump alias (`jump_eval`), and the current client.
/// A pair without a route is exactly `evidence_holds` over a direct evaluation.
#[must_use]
pub fn evidence_survives(
    record: &EnrollmentRecord,
    route: Option<&PairRoute>,
    eval: Option<&TargetEvaluation>,
    jump_eval: Option<&TargetEvaluation>,
    client_version: Option<&str>,
) -> bool {
    if !evidence_holds(record, eval, client_version, route.map(|r| &r.approved)) {
        return false;
    }
    // The evidence compared with a direct evaluation (the enrolled target) needs no
    // jump hop; one compared through the approved jump needs the hop usable. A pair
    // with a catalog route whose alias still evaluates direct holds on the enrolled
    // target: the route is not rendered yet.
    match (route, eval) {
        (Some(_), Some(e)) if e.proxy == heimdall_domain::enrollment::ProxyRoute::Jump => {
            jump_eval.is_some_and(jump_hop_usable)
        }
        _ => true,
    }
}

/// A routed pair's effect on the report (module docs).
pub fn apply_to_report(report: &mut ManagedReport, pairs: &[PreparePair]) {
    let routes: Vec<&PairRoute> = pairs.iter().filter_map(|p| p.route.as_ref()).collect();
    if routes.is_empty() {
        return;
    }
    if !report
        .conditions
        .contains(&ReadinessCondition::RouteDependency)
    {
        report.conditions.push(ReadinessCondition::RouteDependency);
    }
    if routes.iter().any(|r| r.access == JumpAccess::Existing) {
        if report.lock_continuity == LockContinuityReport::Verified {
            report.lock_continuity = LockContinuityReport::NotVerified;
        }
        report.lock_claim_verified = false;
    }
}
