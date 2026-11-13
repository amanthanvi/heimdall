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

/// The per-pair resolution of `pairs` (module docs). With no stored preference this
/// is exactly M02's `catalog_mechanism(catalog_pairs(pairs))`.
pub(super) fn resolve_pairs(
    tx: &mut Txn<'_>,
    pairs: &BTreeSet<AccessPair>,
) -> heimdall_store::Result<Result<PairsResolution, OpError>> {
    let mut managed = false;
    let mut pending_projection = false;
    let mut existing = BTreeSet::new();
    for p in pairs {
        match pair_kind(tx, p)? {
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

/// The canonical hash's kind-specific extra for `ensure`: `null` without
/// `connection` (M01/M02 hashes unchanged), `{"connection": …}` with it.
pub(super) fn ensure_hash_extra(req: &EnsureRequest) -> serde_json::Value {
    match &req.connection {
        None => serde_json::Value::Null,
        Some(c) => serde_json::json!({ "connection": c }),
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
        let profile = req.profile.clone();
        let revision = req.profile_revision;
        let scope = req.scope.clone();
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
                resolve_pairs(tx, &pairs)
            })
            .await?;
        // ⟨wave 4⟩ Open only with the managed wiring (effects and issuer) and the
        // managed adapter configured; otherwise refused before any record.
        let managed_available = self.managed_driver_wired()
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
