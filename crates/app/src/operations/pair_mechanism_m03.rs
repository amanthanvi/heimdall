//! ⟨M03⟩ U0b row 9 (ADR-0008 D5 §6.6, D6 item 7; m03-plan §5 items 5 and 12): the
//! per-pair mechanism of `ensure` resolution, `EnsureRequest.connection`, and the
//! `required.unattended` refusal reasons.
//!
//! **Per pair** ([`resolve_pairs`]):
//! * no stored preference, or preference `existing`: the catalog identity's
//!   mechanism (M02, unchanged);
//! * preference `managed_certificate` without a `verified` enrollment for the pair:
//!   `CAPABILITY_UNAVAILABLE`, reason `pair_not_enrolled` (fail closed);
//! * preference `managed_certificate`, a `verified` enrollment, projection
//!   `applied`: `managed_certificate`;
//! * the same with the projection `pending`: the existing mechanism, with the warning
//!   `managed_projection_pending` and `next: setup_apply` on the result; a request
//!   whose minimums the existing mechanism cannot meet fails `projection_pending`.
//!
//! Managed pairs together with any other pair are `mixed_mechanisms` (unchanged,
//! ADR-0008 Q5). ⟨wave 4⟩ Unless the runtime wired the managed effect driver (effects
//! and issuer, `Operations::managed_driver_wired`) and configured the managed adapter,
//! a request that resolves to `managed_certificate` is refused
//! `CAPABILITY_UNAVAILABLE`, `driver_unavailable`, before any record is written
//! ([`Operations::ensure_precheck`]).
//!
//! **`connection`** (§5 item 5): only `existing: strict` narrows; `graceful` in a request
//! is `USAGE_ERROR` before anything is written. It enters the canonical hash only when
//! present ([`ensure_hash_extra`]), so M01/M02 hashes are unchanged.

use std::collections::BTreeSet;

use heimdall_contract::Code;
use heimdall_contract::envelope::{EffectStatus, NextAction, Warning, m03_warning, reason};
use heimdall_contract::managed::{ExistingConnectionsMode, LockBehavior, PreferredMechanism};
use heimdall_contract::request::{EnsureData, EnsureRequest, RequiredCapabilities};
use heimdall_domain::enrollment::ProjectionStatus;
use heimdall_domain::scope::AccessPair;
use heimdall_store::Txn;

use super::ca_issuance_m03::MANAGED_CERTIFICATE;
use super::{Operations, catalog_mechanism, catalog_pairs, mixed_mechanisms};
use crate::error::{OpError, OpResult};

/// How one pair resolves (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairKind {
    Existing,
    Managed,
    PendingProjection,
}

/// The mechanism a set of pairs resolves to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PairsResolution {
    /// The one mechanism the pairs name (`None`: none named, the M01 selection).
    pub(super) mechanism: Option<&'static str>,
    /// At least one pair resolved to its existing mechanism because its managed
    /// projection is pending.
    pub(super) pending_projection: bool,
}

fn pair_not_enrolled(pair: &AccessPair) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the pair prefers managed certificates but has no verified enrollment",
    )
    .with_reason(reason::PAIR_NOT_ENROLLED)
    .with_effect(EffectStatus::None)
    .with_resource("destination", Some(pair.destination.to_string()))
}

fn pair_kind(
    tx: &mut Txn<'_>,
    pair: &AccessPair,
) -> heimdall_store::Result<Result<PairKind, OpError>> {
    let Some(pref) = tx.pair_preference(pair)? else {
        return Ok(Ok(PairKind::Existing));
    };
    if pref.mechanism != PreferredMechanism::ManagedCertificate {
        return Ok(Ok(PairKind::Existing));
    }
    if tx.verified_cas_for_pair(pair)?.is_empty() {
        return Ok(Err(pair_not_enrolled(pair)));
    }
    Ok(Ok(match pref.projection {
        ProjectionStatus::Applied { .. } => PairKind::Managed,
        // `pending`, and any status this build does not know: not rendered.
        _ => PairKind::PendingProjection,
    }))
}

/// ⟨M06 W4 grant-e2e; ADR-0012 §4 item 2 ⟨2026-11-21⟩; m06-plan §2 item 1⟩ The CAs an
/// `ensure` names per pair (`EnsureRequest::pair_issuers`), with the paired controller that
/// forwarded it (`None`: a local caller).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NamedIssuers {
    /// The CA named for each pair.
    pub(super) cas: std::collections::BTreeMap<AccessPair, heimdall_contract::ids::CaFingerprint>,
    /// The paired client the request came from.
    pub(super) controller: Option<heimdall_contract::ids::ClientId>,
    /// ⟨M06 W4; ADR-0006 §18.8 item 1⟩ The request came from this installation's local
    /// owner (no paired client, the owner role): on a runner it may name a CA already in
    /// the runner's `issuer_trust`.
    pub(super) local_owner: bool,
    /// ⟨M06 W4⟩ On a runner: a live grant the controller issued covers the request's
    /// pairs for this caller (`runner_m06::covering_grant`), so the pairs are the
    /// controller's managed ones; the request attaches to that grant or waits as it does.
    pub(super) attach: bool,
    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ A paired client whose role is not the owner's (a
    /// requester) sent the request and named no CA: its pairs are the managed ones of an
    /// owner controller, never this runner's own existing access. Admission is unchanged
    /// (the runner's standing policy, or a decision confirmed at the runner); the grant
    /// then waits for an owner controller whose own record covers it. Nothing is signed,
    /// and nothing of the runner's own is used, on the requester's word.
    pub(super) awaits_owner: bool,
}

/// [`NamedIssuers::awaits_owner`]. `runner`: this installation is a remote runner (its
/// runtime set the runner's signer view, `runner_m06::RunnerGrants`); every other
/// installation takes the paths it took before.
pub(super) fn awaits_owner_record(
    runner: bool,
    caller: &heimdall_domain::principal::CallerContext,
    names_a_ca: bool,
) -> bool {
    runner && caller.remote_client.is_some() && !caller.is_owner() && !names_a_ca
}

impl NamedIssuers {
    /// What `request`, sent by `caller`, names. `runner`: this installation is a remote
    /// runner.
    pub(super) fn of(
        request: &EnsureRequest,
        caller: &heimdall_domain::principal::CallerContext,
        runner: bool,
    ) -> Self {
        Self {
            cas: request
                .pair_issuers
                .iter()
                .map(|i| (i.pair.clone(), i.ca_fingerprint.clone()))
                .collect(),
            controller: caller.remote_client.clone(),
            local_owner: caller.remote_client.is_none() && caller.has_global_access(),
            attach: false,
            awaits_owner: awaits_owner_record(runner, caller, !request.pair_issuers.is_empty()),
        }
    }
}

fn issuer_untrusted(pair: &AccessPair) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the CA named for the pair is not in this runner's issuer_trust for the party that \
         named it",
    )
    .with_reason(reason::ISSUER_UNTRUSTED)
    .with_effect(EffectStatus::None)
    .with_resource("destination", Some(pair.destination.to_string()))
}

/// A pair an `ensure` names a CA for: `managed_certificate` only when that CA is in this
/// runner's `issuer_trust`
///
/// * for the forwarding controller, when a paired client sent the request; or
/// * ⟨M06 W4; ADR-0006 §18.8 item 1⟩ for any controller, when this runner's **local
///   owner** sent it. That admits a pending grant only: the runner never issues, and the
///   trusted controller's host signs for it only under its own record (ADR-0005 §3.5
///   condition 8).
///
/// `issuer_untrusted` otherwise: a paired client naming a CA trusted for another
/// controller, a local caller that is not the owner, a CA no entry names, an installation
/// that trusts no issuer. The runner's own catalog, preference and enrollment are not read.
fn named_pair_kind(
    tx: &mut Txn<'_>,
    pair: &AccessPair,
    ca: &heimdall_contract::ids::CaFingerprint,
    named: &NamedIssuers,
) -> heimdall_store::Result<Result<PairKind, OpError>> {
    let entry = tx.trusted_remote_issuer(ca)?;
    let trusted = match (&named.controller, &entry) {
        (Some(c), Some(e)) => &e.controller == c,
        (None, Some(_)) => named.local_owner,
        (_, None) => false,
    };
    Ok(if trusted {
        Ok(PairKind::Managed)
    } else {
        Err(issuer_untrusted(pair))
    })
}

/// The per-pair resolution of `pairs` (module docs). With no stored preference this
/// is exactly M02's `catalog_mechanism(catalog_pairs(pairs))`.
pub(super) fn resolve_pairs(
    tx: &mut Txn<'_>,
    pairs: &BTreeSet<AccessPair>,
) -> heimdall_store::Result<Result<PairsResolution, OpError>> {
    resolve_pairs_named(tx, pairs, &NamedIssuers::default())
}

/// [`resolve_pairs`] for a request that may name its pairs' issuing CAs (`named`): a named
/// pair resolves through [`named_pair_kind`] only; a CA named for a pair outside `pairs`
/// is `USAGE_ERROR`.
pub(super) fn resolve_pairs_named(
    tx: &mut Txn<'_>,
    pairs: &BTreeSet<AccessPair>,
    named: &NamedIssuers,
) -> heimdall_store::Result<Result<PairsResolution, OpError>> {
    if named.cas.keys().any(|p| !pairs.contains(p)) {
        return Ok(Err(OpError::new(
            Code::UsageError,
            "the request names an issuing CA for a pair outside its scope",
        )
        .with_effect(EffectStatus::None)));
    }
    // ⟨M04 U6; ADR-0010 §5 item 2⟩ A routed pair's jump hop must be a managed pair in
    // this scope or existing access: `route_dependency_out_of_scope` before anything
    // is admitted.
    let routes = crate::catalog::route_view(tx)?;
    for p in pairs {
        if let Err(e) = super::pair_route(&routes, p, pairs) {
            return Ok(Err(e));
        }
    }
    let mut managed = false;
    let mut pending_projection = false;
    let mut existing = BTreeSet::new();
    for p in pairs {
        let kind = match named.cas.get(p) {
            Some(ca) => named_pair_kind(tx, p, ca, named)?,
            None if named.attach || named.awaits_owner => Ok(PairKind::Managed),
            None => pair_kind(tx, p)?,
        };
        match kind {
            Err(e) => return Ok(Err(e)),
            Ok(PairKind::Managed) => managed = true,
            Ok(PairKind::PendingProjection) => {
                pending_projection = true;
                existing.insert(p.clone());
            }
            Ok(PairKind::Existing) => {
                existing.insert(p.clone());
            }
        }
    }
    if managed {
        if !existing.is_empty() {
            return Ok(Err(mixed_mechanisms()));
        }
        return Ok(Ok(PairsResolution {
            mechanism: Some(MANAGED_CERTIFICATE),
            pending_projection: false,
        }));
    }
    let mechanism = match catalog_pairs(tx, &existing)?.and_then(|named| catalog_mechanism(&named))
    {
        Ok(m) => m,
        Err(e) => return Ok(Err(e)),
    };
    Ok(Ok(PairsResolution {
        mechanism,
        pending_projection,
    }))
}

/// ADR-0008 D6 item 7's third reason. Not yet in `envelope::reason::M03` (questions
/// file O, Q4); never produced in wave 0 (no managed mechanism is configured).
const INTERACTION_REQUIRED: &str = "interaction_required";

/// The wave-0 refusal of a request that resolves to `managed_certificate`.
fn managed_driver_unavailable() -> OpError {
    OpError::driver_unavailable("the managed-certificate mechanism is not available in this build")
}

/// ⟨M03⟩ ADR-0008 D6 item 7: the reason `required.unattended` is not met, or `None`
/// when it is: the mechanism is `managed_certificate` and the claim table holds
/// `lock_continuity: verified` (else `lock_continuity_unverified`), the grant's lock
/// behaviour is `continue` (else `lock_revokes_chosen`), and the binding needs no
/// interaction (else `interaction_required`). Checked in that order.
#[must_use]
pub fn unattended_refusal(
    managed: bool,
    claim_verified: bool,
    lock: LockBehavior,
    needs_interaction: bool,
) -> Option<&'static str> {
    if !managed || !claim_verified {
        Some(reason::LOCK_CONTINUITY_UNVERIFIED)
    } else if lock != LockBehavior::Continue {
        Some(reason::LOCK_REVOKES_CHOSEN)
    } else if needs_interaction {
        Some(INTERACTION_REQUIRED)
    } else {
        None
    }
}

/// The refusal of a resolution that found no configured adapter (pin's
/// `CAPABILITY_UNAVAILABLE`), with its M03 reason: `driver_unavailable` for
/// `managed_certificate` while no managed adapter is configured (`managed: None`),
/// `projection_pending` (`next: setup_apply`) while a pair's managed projection is
/// pending, the D6 item 7 reason for `unattended`, and otherwise M01's refusal
/// unchanged. ⟨wave 4⟩ With a configured managed adapter (`managed: Some(meets
/// unattended)`, wired: `Operations::ensure_precheck` refused before admission
/// otherwise) a managed resolution that met no adapter is M01's refusal with the D6
/// item 7 reason.
pub(super) fn no_mechanism(
    required: &RequiredCapabilities,
    resolution: PairsResolution,
    lock: LockBehavior,
    managed: Option<bool>,
) -> OpError {
    let is_managed = resolution.mechanism == Some(MANAGED_CERTIFICATE);
    let claim_verified = match (is_managed, managed) {
        (true, None) => return managed_driver_unavailable(),
        (true, Some(verified)) => verified,
        (false, _) => false,
    };
    let e = OpError::new(
        Code::CapabilityUnavailable,
        "no configured credential mechanism meets the requested minimums",
    );
    if resolution.pending_projection {
        return e
            .with_reason(reason::PROJECTION_PENDING)
            .with_next(NextAction {
                action: "setup_apply".to_owned(),
                ..NextAction::default()
            });
    }
    if required.unattended
        && let Some(why) = unattended_refusal(is_managed, claim_verified, lock, false)
    {
        return e.with_reason(why);
    }
    e
}

/// ⟨M05⟩ What resolving a request's `context` established (ADR-0006 revision 5 §17
/// item 4): the workspace it matched and the access digest of the manifest it read. M05
/// U4 fills it; joint wave 0 refuses every request with a `context` before hashing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ContextHashExtras<'a> {
    /// The workspace the observation matched (`Trusted` or `Member`).
    pub(crate) workspace: Option<&'a heimdall_contract::ids::WorkspaceId>,
    /// The manifest's access digest (lowercase hex).
    pub(crate) access_digest: Option<&'a str>,
}

/// The canonical hash's kind-specific extra for `ensure`: `null` without
/// `connection` (M01/M02 hashes unchanged), `{"connection": …}` with it.
///
/// ⟨M05⟩ ADR-0006 revision 5 §17 item 4 (ADR-0011 §10 item 5): the revision-5 extras
/// (`context`, `covered_only`, and the resolved workspace and access digest) enter
/// **only when `context` is present**, so a request without `context` keeps its
/// M01–M03 hash byte for byte; with `context`, the same request ID with a different
/// resolved workspace or digest is another request (`REQUEST_CONFLICT`).
pub(crate) fn ensure_hash_extra(
    req: &EnsureRequest,
    resolved: Option<&ContextHashExtras<'_>>,
) -> serde_json::Value {
    let mut extra = serde_json::Map::new();
    if let Some(c) = &req.connection {
        extra.insert("connection".to_owned(), serde_json::json!(c));
    }
    // ⟨M06 W4⟩ Only when present: the same request ID naming another CA is another request.
    if !req.pair_issuers.is_empty() {
        extra.insert(
            "pair_issuers".to_owned(),
            serde_json::json!(req.pair_issuers),
        );
    }
    if let Some(context) = &req.context {
        extra.insert("context".to_owned(), serde_json::json!(context));
        if req.covered_only {
            extra.insert("covered_only".to_owned(), serde_json::Value::Bool(true));
        }
        if let Some(r) = resolved {
            if let Some(w) = r.workspace {
                extra.insert("workspace".to_owned(), serde_json::json!(w));
            }
            if let Some(d) = r.access_digest {
                extra.insert("access_digest".to_owned(), serde_json::json!(d));
            }
        }
    }
    if extra.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(extra)
    }
}

/// What the pre-admission check found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct EnsurePrecheck {
    pending_projection: bool,
}

impl EnsurePrecheck {
    /// A successful result of a request one of whose pairs resolved to its existing
    /// mechanism while its managed projection is pending carries the warning
    /// `managed_projection_pending` and `next: setup_apply` (keeping the binding).
    pub(super) fn decorate(self, r: OpResult<EnsureData>) -> OpResult<EnsureData> {
        let mut done = r?;
        if self.pending_projection {
            done.warnings.push(Warning {
                code: m03_warning::MANAGED_PROJECTION_PENDING.to_owned(),
                message: "a managed projection is pending for a requested pair; the existing \
                          identity was used (run setup apply)"
                    .to_owned(),
                reason: None,
            });
            let binding_id = done.next.take().and_then(|n| n.binding_id);
            done.next = Some(NextAction {
                action: "setup_apply".to_owned(),
                binding_id,
                ..NextAction::default()
            });
        }
        Ok(done)
    }
}

impl Operations {
    /// ⟨M03⟩ U0b row 9: the checks of an `ensure` that come before admission, so a
    /// refusal writes nothing: `connection.existing: graceful` is `USAGE_ERROR`, and a
    /// request whose pairs resolve to `managed_certificate` is `CAPABILITY_UNAVAILABLE`,
    /// `driver_unavailable` unless the managed driver is wired and its adapter
    /// configured (wave 4). Every other outcome of the per-pair resolution
    /// (`pair_not_enrolled`, `mixed_mechanisms`, …) is left to resolution, as in M02.
    pub(super) async fn ensure_precheck(
        &self,
        caller: &heimdall_domain::principal::CallerContext,
        req: &EnsureRequest,
    ) -> Result<EnsurePrecheck, OpError> {
        if req
            .connection
            .as_ref()
            .is_some_and(|c| c.existing == Some(ExistingConnectionsMode::Graceful))
        {
            return Err(OpError::new(
                Code::UsageError,
                "a request may only narrow existing connections to strict; graceful is a policy setting",
            )
            .with_effect(EffectStatus::None));
        }
        // ⟨M05⟩ A request without a profile is a revision-5 form, refused before here.
        let Some(profile) = req.profile.clone() else {
            return Err(OpError::driver_unavailable(
                "trusted-work requests are not available in this build",
            ));
        };
        let revision = req.profile_revision;
        let scope = req.scope.clone();
        let named = NamedIssuers::of(req, caller, self.runner_grants().is_some());
        let resolution = self
            .write(move |tx, _| {
                let pairs = if scope.is_empty() {
                    let revision = match revision {
                        Some(r) => Some(r),
                        None => tx.profile(&profile)?.map(|p| p.revision),
                    };
                    match revision {
                        Some(r) => tx
                            .profile_snapshot(&profile, r)?
                            .map(|s| s.scope.pairs)
                            .unwrap_or_default(),
                        None => BTreeSet::new(),
                    }
                } else {
                    scope
                };
                resolve_pairs_named(tx, &pairs, &named)
            })
            .await?;
        // ⟨wave 4⟩ Open only with the managed wiring (effects and issuer) and the
        // managed adapter configured; otherwise refused before any record.
        // ⟨M06 W3 grant-path⟩ On a remote runner the mechanism needs no issuer here: the
        // grant waits for the controller's (`super::runner_m06`).
        let managed_available = (self.managed_driver_wired() || self.runner_grants().is_some())
            && self
                .adapter_infos()
                .iter()
                .any(|a| a.identity.mechanism == MANAGED_CERTIFICATE);
        match resolution {
            Ok(r) if r.mechanism == Some(MANAGED_CERTIFICATE) && !managed_available => {
                Err(managed_driver_unavailable())
            }
            Ok(r) => Ok(EnsurePrecheck {
                pending_projection: r.pending_projection,
            }),
            Err(_) => Ok(EnsurePrecheck::default()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::ids::{ProfileId, RequestId, WorkId, WorkspaceId};
    use heimdall_contract::managed::ConnectionRequest;
    use heimdall_contract::request::{InteractionMode, RequiredCapabilities, WaitMode};
    use heimdall_contract::trust::WorkContext;

    fn request(connection: Option<ConnectionRequest>) -> EnsureRequest {
        EnsureRequest {
            profile: Some(ProfileId::parse("dev").unwrap()),
            profile_revision: None,
            scope: std::collections::BTreeSet::new(),
            environment: None,
            work_id: WorkId::parse("w").unwrap(),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse("r").unwrap(),
            interaction: InteractionMode::NonInteractive,
            wait: WaitMode::default(),
            connection,
            context: None,
            covered_only: false,
            pair_issuers: Vec::new(),
        }
    }

    /// ⟨M05⟩ ADR-0006 revision 5 §17 item 4 (ADR-0011 §10 item 5): without `context`
    /// the extra is exactly M03's (`null`, or `{"connection": …}`), whatever
    /// `covered_only` says and whatever resolution found; with `context` the resolved
    /// workspace and access digest are part of the request's identity.
    #[test]
    fn revision_5_extras_enter_the_ensure_hash_only_with_context() {
        let strict = Some(ConnectionRequest {
            existing: Some(ExistingConnectionsMode::Strict),
        });
        let ws = WorkspaceId::from_random_bytes([3; 16]);
        let resolved = ContextHashExtras {
            workspace: Some(&ws),
            access_digest: Some("ab"),
        };
        for connection in [None, strict] {
            let m03 = match &connection {
                None => serde_json::Value::Null,
                Some(c) => serde_json::json!({ "connection": c }),
            };
            let mut plain = request(connection);
            assert_eq!(ensure_hash_extra(&plain, None), m03);
            assert_eq!(ensure_hash_extra(&plain, Some(&resolved)), m03);
            plain.covered_only = true;
            assert_eq!(ensure_hash_extra(&plain, Some(&resolved)), m03);
            let mut with = plain.clone();
            with.context = Some(WorkContext { cwd: "/w".into() });
            let a = ensure_hash_extra(&with, Some(&resolved));
            assert_ne!(a, m03);
            assert_eq!(a["workspace"], serde_json::json!(ws));
            assert_eq!(a["access_digest"], "ab");
            assert_eq!(a["covered_only"], true);
            let other = ContextHashExtras {
                access_digest: Some("cd"),
                ..resolved
            };
            assert_ne!(
                ensure_hash_extra(&with, Some(&other)),
                a,
                "a changed digest is another request"
            );
        }
    }
}
