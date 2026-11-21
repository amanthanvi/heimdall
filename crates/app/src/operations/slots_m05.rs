//! ⟨M05⟩ U6: slot references and handover, the store side (ADR-0011 §5.2 as ruled in §10
//! item 6; m05-plan U6).
//!
//! M03 refused a second launch bind on a held pair (`managed_slot_held`, ADR-0008 D10
//! item 2). M05 replaces that refusal, for **compatible** binds only, with reference
//! accounting and handover. The decisions are the pure ones of
//! `heimdall_domain::managed` ([`slot_bind`], [`handover_target`], the
//! [`SlotEvent::HandOver`] transition); this module reads and writes the store rows they
//! govern (`managed_slots`, `slot_references`) inside the caller's transaction.
//!
//! * **Join** ([`claim_or_join_in`]): a managed launch bind whose active grant covers the
//!   pair, with the same mechanism, while another binding materializes the slot, adds a
//!   [`SlotReference`] and changes nothing else (no slot state, generation, file, or pin
//!   of either binding). The bind's result carries `ordinary_aliases:
//!   shared_environment_default` and the warning `slot_shared`
//!   ([`label_shared_in`], [`label_shared`]). An incompatible holder is still refused
//!   `CONFIG_CONFLICT` `managed_slot_held`, next `release_binding`. A claim of a free slot
//!   records the materializer's own reference, so the materializer is one of them.
//! * **Leave**: a released binding drops every reference it holds in its release
//!   transaction ([`leave_all_in`]); a slot it materializes moves `held → clearing` as in
//!   M03 (`managed_driver_m03::release_binding_slots_in`).
//! * **Handover** ([`slot_files_removed_or_hand_over_in`]): where M03's cleanup frees a
//!   clearing slot (its old generation's key unlisted and files removed, its mux path
//!   cleared), the slot passes instead to the remaining referencer with the latest
//!   deadline, at the **next** generation, in the same transaction; referencers whose
//!   grant is no longer usable are dropped, never handed the slot. The runtime then
//!   re-materializes it from that referencer's own grant (`heimdall_runtime::
//!   slot_handover`), through the existing slot write and its CAS and generation fencing:
//!   a cleanup of generation `g` never removes `g + 1`. With no usable referencer left the
//!   slot clears (`clearing → free`) and every reference row goes with it.
//!
//! **The claim, exactly** (ruling D06): one pair and one materializer grant; the slot's
//! certificate (its principals and `valid_before`) comes from that grant only; the slot
//! ends when the last referencer drops. A shorter sibling's deadline is enforced on its
//! bound contexts (`connect`, delegated endpoints), not on the ordinary alias (R3). Plan
//! §6.3 property 8's most-restrictive clause is **not** claimed.

use heimdall_contract::Timestamp;
use heimdall_contract::envelope::Warning;
use heimdall_contract::ids::{BindingId, EnvironmentId};
use heimdall_contract::request::EnsureData;
use heimdall_contract::trust::OrdinaryAliases;
use heimdall_domain::binding::{BindingRecord, BindingState};
use heimdall_domain::managed::{
    SlotBind, SlotEvent, SlotReferencer, SlotRefusal, SlotState, handover_target, slot_bind,
    slot_transition,
};
use heimdall_domain::scope::AccessPair;
use heimdall_domain::workspace::SlotReference;
use heimdall_store::Txn;

use crate::error::{Completed, OpError};

use super::ca_issuance_m03::MANAGED_CERTIFICATE;

/// ⟨M05⟩ A handover committed by [`slot_files_removed_or_hand_over_in`]: the slot of
/// `pair` in `environment` is now `held(to, generation)`, and the runtime re-materializes
/// it from `to`'s own grant at that generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotHandover {
    /// The slot's environment.
    pub environment: EnvironmentId,
    /// The slot's pair.
    pub pair: AccessPair,
    /// The referencer that took the slot.
    pub to: BindingId,
    /// The new generation (the cleared one plus one).
    pub generation: u64,
}

fn references_of(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    pair: &AccessPair,
) -> heimdall_store::Result<Vec<SlotReference>> {
    tx.slot_references(environment, &pair.destination, &pair.account)
}

/// Whether `b` may share a slot of `pair` (ADR-0011 §5.2): a managed binding whose
/// active grant covers the pair, with the same mechanism as the slot's materializer
/// (`holder`, when the slot is held).
fn compatible_in(
    tx: &mut Txn<'_>,
    b: &BindingRecord,
    pair: &AccessPair,
    holder: Option<&BindingId>,
) -> heimdall_store::Result<bool> {
    if b.mechanism != MANAGED_CERTIFICATE || !b.scope.pairs.contains(pair) {
        return Ok(false);
    }
    let covers = tx
        .grant(&b.grant)?
        .is_some_and(|g| g.state.permits_use() && g.scope.pairs.contains(pair));
    if !covers {
        return Ok(false);
    }
    Ok(match holder {
        Some(h) => tx.binding(h)?.is_some_and(|m| m.mechanism == b.mechanism),
        None => true,
    })
}

/// The reference `b` records for a slot of `environment`: its grant's effective
/// deadline now (handover goes to the latest one) and when it joined.
fn reference_of(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    pair: &AccessPair,
    b: &BindingRecord,
    now: Timestamp,
) -> heimdall_store::Result<SlotReference> {
    let deadline = match tx.grant(&b.grant)? {
        Some(g) => super::bound_of(tx, &g, Some(&b.profile))?,
        None => now,
    };
    Ok(SlotReference {
        environment: environment.clone(),
        destination: pair.destination.clone(),
        account: pair.account.clone(),
        binding: b.id.clone(),
        deadline,
        joined_at: now,
    })
}

/// ⟨M05⟩ ADR-0011 §5.2, in the launch bind's transaction (replacing M03's
/// claim-or-refuse, `managed_driver_m03::claim_bind_slots_in`): every pair of the
/// managed binding `b` is decided first ([`slot_bind`]: claim a free slot, keep a held
/// one, join a compatible holder's, refuse an incompatible holder or a clearing slot it
/// does not reference) and nothing is written unless every pair is admitted. Then each
/// free slot is claimed (CAS `free(g) → held(b, g + 1)`) and every slot `b` claims,
/// holds or joins gets `b`'s [`SlotReference`] (added once). No binding row, pin, slot
/// generation or file of another binding is touched.
///
/// # Errors
/// A store failure (the whole transaction rolls back).
pub(super) fn claim_or_join_in(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    b: &BindingRecord,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    let mut decided = Vec::with_capacity(b.scope.pairs.len());
    for pair in &b.scope.pairs {
        let state = tx.slot(environment, pair)?;
        let references = references_of(tx, environment, pair)?
            .iter()
            .any(|r| r.binding == b.id);
        let holder = match &state {
            SlotState::Held { binding, .. } => Some(binding.clone()),
            _ => None,
        };
        let compatible = compatible_in(tx, b, pair, holder.as_ref())?;
        match slot_bind(&state, &b.id, references, compatible) {
            Ok(decision) => decided.push((pair.clone(), decision, references)),
            Err(_) => {
                return Ok(Err(super::managed_driver_m03::slot_refusal(&b.id, &state)));
            }
        }
    }
    for (pair, decision, references) in decided {
        if decision == SlotBind::Claim && tx.claim_slot(environment, &pair, &b.id, now)?.is_err() {
            return Err(heimdall_store::StoreError::Corrupt(
                "a checked slot claim was refused".into(),
            ));
        }
        if !references {
            let r = reference_of(tx, environment, &pair, b, now)?;
            tx.add_slot_reference(&r)?;
        }
    }
    Ok(Ok(()))
}

/// ⟨M05⟩ In a managed binding's release transaction: `binding` drops every slot
/// reference it holds (a slot it only joined keeps its materializer; a slot it
/// materializes moves `held → clearing` in the same transaction, M03's path, and is
/// handed over when its old generation's files are gone).
///
/// # Errors
/// A store failure.
pub(super) fn leave_all_in(tx: &mut Txn<'_>, binding: &BindingId) -> heimdall_store::Result<()> {
    for r in tx.slot_references_for_binding(binding)? {
        tx.remove_slot_reference(&r.environment, &r.destination, &r.account, binding)?;
    }
    Ok(())
}

/// ⟨M05⟩ Whether `binding` references a slot it does not hold (it joined a slot another
/// binding materializes, or waits for a handover): its ordinary aliases are then
/// environment-level (`shared_environment_default`).
///
/// # Errors
/// A store failure.
pub(super) fn shares_a_slot_in(
    tx: &mut Txn<'_>,
    binding: &BindingId,
) -> heimdall_store::Result<bool> {
    Ok(referenced_not_held_in(tx, binding)? > 0)
}

/// ⟨M05⟩ How many slots `binding` references without holding them (a re-issue restores
/// only the slots a binding holds; the ones it joined belong to their materializer).
///
/// # Errors
/// A store failure.
pub(super) fn referenced_not_held_in(
    tx: &mut Txn<'_>,
    binding: &BindingId,
) -> heimdall_store::Result<usize> {
    let mut n = 0;
    for r in tx.slot_references_for_binding(binding)? {
        let pair = AccessPair {
            destination: r.destination.clone(),
            account: r.account.clone(),
        };
        let held = matches!(
            tx.slot(&r.environment, &pair)?,
            SlotState::Held { binding: holder, .. } if holder == *binding
        );
        if !held {
            n += 1;
        }
    }
    Ok(n)
}

/// ⟨M05⟩ The label of a launch bind that shares a slot, in its settling transaction:
/// `enforcement.ordinary_aliases: shared_environment_default` on the stored result (so a
/// replay carries it too). Nothing else of the result changes.
///
/// # Errors
/// A store failure.
pub(super) fn label_shared_in(
    tx: &mut Txn<'_>,
    binding: &BindingId,
    data: &mut EnsureData,
) -> heimdall_store::Result<()> {
    if shares_a_slot_in(tx, binding)? {
        data.enforcement.ordinary_aliases = Some(OrdinaryAliases::SharedEnvironmentDefault);
    }
    Ok(())
}

/// ⟨M05⟩ The warning `slot_shared` on a bind result labelled
/// `shared_environment_default` ([`label_shared_in`]), first or replayed.
pub(super) fn label_shared(done: &mut Completed<EnsureData>) {
    if done.data.enforcement.ordinary_aliases == Some(OrdinaryAliases::SharedEnvironmentDefault)
        && !done
            .warnings
            .iter()
            .any(|w| w.code == heimdall_contract::envelope::m05_warning::SLOT_SHARED)
    {
        done.warnings.push(Warning {
            code: heimdall_contract::envelope::m05_warning::SLOT_SHARED.to_owned(),
            message: "another binding materializes this pair's ordinary alias; the alias is \
                      shared at environment level and your own deadline is enforced on your \
                      bound contexts (connect, delegated endpoints), not on the alias"
                .to_owned(),
            reason: None,
        });
    }
}

/// One `slot_references` row as the handover reads it now ([`SlotReferencer`]): usable
/// while its binding is active in the slot's environment with the managed mechanism and
/// the pair in its scope, and its grant permits use, has no denied ancestor and has not
/// reached its effective deadline (cutoffs included).
fn referencer_in(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    pair: &AccessPair,
    r: &SlotReference,
    now: Timestamp,
) -> heimdall_store::Result<SlotReferencer> {
    let unusable = SlotReferencer {
        binding: r.binding.clone(),
        deadline: r.deadline,
        usable: false,
    };
    let Some(b) = tx.binding(&r.binding)? else {
        return Ok(unusable);
    };
    if b.state != BindingState::Active
        || b.environment != *environment
        || b.mechanism != MANAGED_CERTIFICATE
        || !b.scope.pairs.contains(pair)
    {
        return Ok(unusable);
    }
    let Some(g) = tx.grant(&b.grant)? else {
        return Ok(unusable);
    };
    if !g.state.permits_use() || tx.denied_ancestor(&g.id)?.is_some() {
        return Ok(unusable);
    }
    let bound = super::bound_of(tx, &g, Some(&b.profile))?;
    Ok(SlotReferencer {
        binding: r.binding.clone(),
        deadline: bound,
        usable: !heimdall_domain::time::is_expired(now, bound),
    })
}

/// ⟨M05⟩ ADR-0011 §5.2 handover, in the transaction where the runtime's cleanup frees a
/// clearing slot (replacing `Txn::slot_files_removed` there): the files of `generation`
/// were removed (and its key unlisted, its mux path cleared). Every referencer that can
/// no longer carry the slot is dropped; then, when a usable referencer remains, the slot
/// passes to the one with the latest deadline ([`handover_target`]) at `generation + 1`
/// (the [`SlotEvent::HandOver`] transition, as the store's two CAS steps `clearing(g) →
/// free(g) → held(n, g + 1)` in this one transaction) and the handover is returned for
/// the runtime to re-materialize; otherwise the slot is `free(g)` and its reference rows
/// are gone. A slot not `clearing` at `generation` is refused as the M03 call refuses it
/// (inner [`SlotRefusal`], or a [`heimdall_store::StoreError::GenerationConflict`] for
/// another generation), so a stale cleanup of `g` never moves a slot at `g + 1`.
///
/// # Errors
/// A store failure.
pub fn slot_files_removed_or_hand_over_in(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    pair: &AccessPair,
    generation: u64,
    at: Timestamp,
) -> heimdall_store::Result<Result<Option<SlotHandover>, SlotRefusal>> {
    // Refused exactly as M03's call refuses (another generation, or not clearing),
    // before anything is read or written.
    let current = tx.slot(environment, pair)?;
    if current.generation() != generation {
        return Err(heimdall_store::StoreError::GenerationConflict(format!(
            "slot {environment}/{}/{} is not at generation {generation}",
            pair.destination, pair.account
        )));
    }
    if !matches!(current, SlotState::Clearing { .. }) {
        return Ok(Err(SlotRefusal::NotApplicable));
    }
    let rows = references_of(tx, environment, pair)?;
    let mut referencers = Vec::with_capacity(rows.len());
    for r in &rows {
        referencers.push(referencer_in(tx, environment, pair, r, at)?);
    }
    // Dropped, never handed the slot.
    for r in referencers.iter().filter(|r| !r.usable) {
        tx.remove_slot_reference(environment, &pair.destination, &pair.account, &r.binding)?;
    }
    let target = handover_target(&referencers).map(|r| r.binding.clone());
    let freed = match tx.slot_files_removed(environment, pair, generation, at)? {
        Ok(s) => s,
        Err(refused) => return Ok(Err(refused)),
    };
    let Some(to) = target else {
        return Ok(Ok(None));
    };
    let expected = slot_transition(
        &SlotState::Clearing { generation },
        &SlotEvent::HandOver {
            generation,
            to: to.clone(),
        },
    );
    let held = match tx.claim_slot(environment, pair, &to, at)? {
        Ok(s) => s,
        Err(refused) => return Ok(Err(refused)),
    };
    if expected.as_ref() != Ok(&held) || freed.generation() != generation {
        return Err(heimdall_store::StoreError::Corrupt(
            "a handover did not land at the next generation".into(),
        ));
    }
    Ok(Ok(Some(SlotHandover {
        environment: environment.clone(),
        pair: pair.clone(),
        to,
        generation: held.generation(),
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! The store side over a real (in-memory) store: the join, the refusals that write
    //! nothing, and the handover's choice, drop and generation (ADR-0011 §5.2).
    use std::sync::Arc;

    use heimdall_contract::ids::{AccountName, DestinationId, GrantId, ProfileId, WorkId};
    use heimdall_contract::request::{
        DeadlineIntent, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
        NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
    };
    use heimdall_contract::{Code, GrantState};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
    use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::scope::{Capability, Scope};
    use heimdall_domain::time::Deadline;
    use heimdall_store::{NoFaults, Store};

    use super::*;

    fn t0() -> Timestamp {
        "2026-11-18T09:00:00Z".parse().unwrap()
    }

    fn at(minutes: i64) -> Timestamp {
        Timestamp::from_second(t0().as_second() + minutes * 60).unwrap()
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn pr() -> AccessPair {
        AccessPair {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn owner() -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: None,
        }
    }

    fn scope() -> Scope {
        Scope {
            pairs: [pr()].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        }
    }

    /// A grant ending `minutes` after `t0`, and its binding of `mechanism`.
    fn job(tx: &mut Txn<'_>, n: u8, minutes: i64, mechanism: &str) -> BindingRecord {
        let g = GrantSnapshot {
            id: GrantId::from_random_bytes([n; 16]),
            environment: env(),
            scope: scope(),
            starts_at: t0(),
            deadline: Deadline {
                intent: DeadlineIntent::Duration(format!("{minutes}m")),
                resolved_at: t0(),
                effective: at(minutes),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(0),
            state: GrantState::Active,
            enforcement: EnforcementEvidence {
                report: Enforcement::new(
                    DestinationScopeEnforcement::Unknown,
                    NewAuthenticationExpiry::Unknown,
                    WorkloadIsolation::SharedOsUser,
                    ExistingConnectionsPolicy::Unknown,
                    RevocationStatus::Unknown,
                ),
                evidence: Vec::new(),
            },
        };
        tx.insert_grant(&g).unwrap();
        let b = BindingRecord {
            id: BindingId::from_random_bytes([n; 16]),
            environment: env(),
            grant: g.id,
            work_id: WorkId::parse(&format!("w{n}")).unwrap(),
            owner: owner(),
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope: scope(),
            mechanism: mechanism.to_owned(),
            parent: None,
            created_at: t0(),
            released_at: None,
            state: BindingState::Active,
        };
        tx.insert_binding(&b).unwrap();
        b
    }

    fn refs(tx: &mut Txn<'_>) -> Vec<BindingId> {
        references_of(tx, &env(), &pr())
            .unwrap()
            .into_iter()
            .map(|r| r.binding)
            .collect()
    }

    /// A compatible bind joins (a reference, nothing else); an incompatible holder and a
    /// clearing slot the binding does not reference are refused `managed_slot_held` and
    /// write nothing; the materializer's end hands the slot to the latest-deadline
    /// **usable** referencer at the next generation (a revoked one with a later deadline
    /// is dropped, never handed it); a stale finish of the old generation is refused; the
    /// last referencer's end frees the slot and leaves no reference.
    #[test]
    fn join_refusals_and_handover_in_the_store() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.init_self_environment(&env())?;
                let now = at(1);
                let a = job(tx, 1, 60, MANAGED_CERTIFICATE);
                let b = job(tx, 2, 90, MANAGED_CERTIFICATE);
                let c = job(tx, 3, 120, "native_agent");
                let d = job(tx, 4, 150, MANAGED_CERTIFICATE);
                let e = job(tx, 5, 100, MANAGED_CERTIFICATE);
                // a claims; b and d join; the slot does not move.
                claim_or_join_in(tx, &env(), &a, now)?.unwrap();
                let held_a = SlotState::Held {
                    binding: a.id.clone(),
                    generation: 1,
                };
                claim_or_join_in(tx, &env(), &b, now)?.unwrap();
                claim_or_join_in(tx, &env(), &b, now)?.unwrap();
                claim_or_join_in(tx, &env(), &d, now)?.unwrap();
                assert_eq!(tx.slot(&env(), &pr())?, held_a);
                assert_eq!(refs(tx), vec![a.id.clone(), b.id.clone(), d.id.clone()]);
                assert!(shares_a_slot_in(tx, &b.id)? && !shares_a_slot_in(tx, &a.id)?);
                // An incompatible bind: refused, nothing written.
                let refused = claim_or_join_in(tx, &env(), &c, now)?.unwrap_err();
                assert_eq!(refused.code, Code::ConfigConflict);
                assert_eq!(refused.reason.as_deref(), Some("managed_slot_held"));
                assert_eq!(tx.slot(&env(), &pr())?, held_a);
                assert_eq!(refs(tx).len(), 3);
                // d's grant is revoked; a is released (its slot clears, it leaves).
                let mut gd = tx.grant(&d.grant)?.unwrap();
                gd.state = GrantState::Revoked;
                tx.update_grant_state(&gd)?;
                tx.release_binding(&a.id, &owner(), now)?;
                let a_released = tx.binding(&a.id)?.unwrap();
                super::super::managed_driver_m03::release_binding_slots_in(tx, &a_released, now)?;
                assert_eq!(
                    tx.slot(&env(), &pr())?,
                    SlotState::Clearing { generation: 1 }
                );
                // A compatible bind that does not reference the clearing slot: refused.
                let refused = claim_or_join_in(tx, &env(), &e, now)?.unwrap_err();
                assert_eq!(refused.reason.as_deref(), Some("managed_slot_held"));
                // b (a referencer) re-binds: it waits for the handover.
                claim_or_join_in(tx, &env(), &b, now)?.unwrap();
                // The handover: d (later deadline, revoked) dropped; b takes generation 2.
                let h = slot_files_removed_or_hand_over_in(tx, &env(), &pr(), 1, now)?
                    .unwrap()
                    .expect("a handover");
                assert_eq!((h.to.clone(), h.generation), (b.id.clone(), 2));
                assert_eq!(
                    tx.slot(&env(), &pr())?,
                    SlotState::Held {
                        binding: b.id.clone(),
                        generation: 2
                    }
                );
                assert_eq!(refs(tx), vec![b.id.clone()]);
                // A stale finish of generation 1 is refused; the slot does not move.
                assert!(matches!(
                    slot_files_removed_or_hand_over_in(tx, &env(), &pr(), 1, now),
                    Err(heimdall_store::StoreError::GenerationConflict(_))
                ));
                // b, the last referencer, ends: the slot frees and no reference stays.
                tx.release_binding(&b.id, &owner(), now)?;
                let b_released = tx.binding(&b.id)?.unwrap();
                super::super::managed_driver_m03::release_binding_slots_in(tx, &b_released, now)?;
                assert_eq!(
                    slot_files_removed_or_hand_over_in(tx, &env(), &pr(), 2, now)?,
                    Ok(None)
                );
                assert_eq!(tx.slot(&env(), &pr())?, SlotState::Free { generation: 2 });
                assert!(refs(tx).is_empty());
                Ok(())
            })
            .unwrap();
    }
}
