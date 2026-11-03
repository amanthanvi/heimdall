//! The total recovery function (m02-plan U4; ADR-0007 §5.7; M2-S01, M2-T04, M2-T05).
//!
//! **Frozen in wave 0** (m02-plan U0): [`decide`], [`decide_item`] and the effect
//! alphabet [`Effect`]. The inputs `StepShape`, `RecoveryState`, `StepObservation`,
//! `EntryObs` and `HoldReason`, and the result [`StepDecision`] with its step types,
//! live in `heimdall-domain` because they cross the `ProjectionWriter` port (wave-0
//! verifier E8; ADR-0007 §12.14 item 2); they are re-exported here.
//!
//! [`decide`] is pure: no I/O and no clock. It is ADR-0007 §5.7's rows, with a final
//! `_ => Hold(Unmatched)` in every block; every `Unobservable` input is `Hold` before
//! any row is tried. `reconcile` is `observe_step`, then `decide`, then the action,
//! repeated until a step is final or held.
//!
//! # Readings (M02-W2-U4b)
//!
//! These fix what the table leaves to the encoding. Each is the fail-closed reading;
//! the ones that touch another unit's code are escalated in the unit report.
//!
//! * **One transition per decision.** An action performs at most one receipt-bounded
//!   transition and the next round of `observe_step` and `decide` continues it, so
//!   every move is decided from an observation taken after the last receipt. For
//!   example F8b writes `file.settled` and F9 then removes; F2c records the mismatch
//!   and F5 then restores.
//! * **F0x and K0x.** Before any receipt no identity is recorded, so the classifier
//!   names an entry at the step's random staged name that has Heimdall's shape (a
//!   regular file owned by the user, link count 1) `Recorded { S, .. }`, with its
//!   content compared against the target digest. Every other entry there is
//!   `Foreign` (F0z, K0z). The evidence is the name, never the content.
//! * **The removal shape.** The locator's entry L is `Recorded { V, .. }`: a removal's
//!   base is present and its digest is the locator's, so L is the validated base and
//!   L′ is V′. `Recorded { S, .. }` is accepted as L too. A removal has no aside
//!   name, so its aside is `Absent`; anything else there is `Unmatched`. R6 (L or L′
//!   with a foreign entry in the cleaner's slot: nothing moved, the executor retries)
//!   is `Hold(ThirdWriter)`; the cleaner writes no receipt, so its holds have no
//!   effect at all.
//! * **The item state in the rows.** The rows before the exchange (F0–F2k, C1–C4h,
//!   K0–K0z and K1) run under T0, so they apply only while the item is open (no item
//!   receipt) and no restore is in the step's context. Otherwise a step that was never
//!   exchanged contradicts the item rows and is `Hold(Unmatched)`. The rows that
//!   recognize a completed exchange (F2b, F2c, F2d, F2h, C2) apply whatever the item
//!   state. No restore row applies under `item.committed` or `item.finished` (T2:
//!   never restore).
//! * **K1 with the release due** settles K from its staged name as
//!   `Abort(SettleStaged)`: K was never claimed, so the Git item's commit step was
//!   never exchanged. K2's release from the lock is `Settle(Begin)`. Their effects
//!   differ by the name moved ([`Effect::MoveToSlot`] of the aside or of the path).
//!   `RecoveryState::build` sets `release_due` only from receipts; when the item
//!   aborts before its siblings have a final receipt (`decide_item` decided the abort
//!   in this run), the caller sets it on K's state once those siblings reached their
//!   abort's end (wave-0 verifier E7, accepted by ADR-0007 §12.14 item 1).
//! * **Settlement sources.** A `path` source belongs to a create's restore or to K's
//!   release, a `displaced` source to a replace; any other pairing of source and shape
//!   is `Hold(Unmatched)`, so the path moves only as property 5 allows.
//! * **A create's restore** ends its settlement block (F9b, F9c, F9d) with
//!   `Restore(RecognizeRestored)`, which writes `file.restored` only; C8 is then
//!   `Settle(Done)`.
//! * **Abort rows that leave nothing to settle** (F0z, F1a, F2g, F2k, C4, C4b, K0z)
//!   are `Abort(NothingToSettle)` and write no receipt; an `X` there is left in place
//!   and reported.

use heimdall_contract::setup::ConflictKind;
use heimdall_domain::operation::{HoldReason, PostVerdict, SettleSource};
use heimdall_domain::projection::{
    ContentState, EffectivePhase, EntryObs, ItemState, RecordedRole, RecoveryState, RestoreCtx,
    StepObservation, StepShape,
};

pub use heimdall_domain::projection::{
    AbortStep, ForwardStep, RestoreStep, SettleStep, StepDecision,
};

/// The concrete effects an action is made of; the generated tests assert over these,
/// never over the action's name (ADR-0007 §5.7, M2-T05).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Write a receipt; moves nothing.
    Receipt(&'static str),
    /// The commit-point exchange of path and aside.
    ForwardExchange,
    /// The commit-point no-replace create (aside → path).
    ForwardCreate,
    /// The restore exchange.
    RestoreExchange,
    /// K's no-replace claim (staged → lock).
    Claim,
    /// No-replace move of a name into the slot.
    MoveToSlot(Name),
    /// Removal from the slot: the only removal.
    RemoveFromSlot,
    /// No-replace move from the slot back to a name.
    PutBack(Name),
    /// No-replace rename of a name to `*.hm-conflict-*`.
    KeepAsConflict(Name),
}

/// A name an effect acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Name {
    /// The step's path (the lock name for `git_lock`).
    Path,
    /// The aside name.
    Aside,
    /// The slot.
    Slot,
}

/// Receipt kinds, as [`Effect::Receipt`] names them (the `file.*` phase kinds).
mod kind {
    pub(super) const STAGED: &str = "staged";
    pub(super) const VALIDATED: &str = "validated";
    pub(super) const EXCHANGED: &str = "exchanged";
    pub(super) const POST_VALIDATED: &str = "post_validated";
    pub(super) const RESTORE_STARTED: &str = "restore_started";
    pub(super) const RESTORED: &str = "restored";
    pub(super) const HELD: &str = "held";
    pub(super) const SETTLING: &str = "settling";
    pub(super) const SETTLED: &str = "settled";
    pub(super) const SETTLE_CONFLICT: &str = "settle_conflict";
}

/// The effects of `decision` for a step in `state` (the property checker's input).
///
/// The sequence is in execution order. [`SettleStep::PutBackForeign`] lists both
/// outcomes of its one no-replace attempt, [`Effect::PutBack`] to the source name and
/// [`Effect::KeepAsConflict`] of the slot, because which of them happens is decided
/// by the filesystem. `H` writes `file.held` only when the observation changed; its
/// one effect is that receipt. The cleaner (the removal shape) writes no receipts.
#[must_use]
pub fn effects(decision: StepDecision, shape: StepShape, state: &RecoveryState) -> Vec<Effect> {
    let removal = shape == StepShape::Removal;
    let phase = state.phase.as_ref();
    let restore_started = matches!(phase, Some(EffectivePhase::RestoreStarted { .. }));
    let source = match state.settlement {
        _ if removal => Name::Path,
        Some(c) if c.source == SettleSource::Path => Name::Path,
        Some(_) | None => Name::Aside,
    };
    let receipt = |k: &'static str| (!removal).then_some(Effect::Receipt(k));
    let mut out: Vec<Option<Effect>> = Vec::new();
    match decision {
        StepDecision::Forward(step) => match step {
            ForwardStep::Stage | ForwardStep::RecordStaged => out.push(receipt(kind::STAGED)),
            ForwardStep::Revalidate => {
                if matches!(phase, Some(EffectivePhase::Staged { .. })) {
                    out.push(receipt(kind::VALIDATED));
                } else {
                    out.push(Some(if shape == StepShape::Create {
                        Effect::ForwardCreate
                    } else {
                        Effect::ForwardExchange
                    }));
                    out.push(receipt(kind::EXCHANGED));
                }
            }
            ForwardStep::RecordExchanged => out.push(receipt(kind::EXCHANGED)),
            ForwardStep::PostValidate => out.push(receipt(kind::POST_VALIDATED)),
            ForwardStep::TransactionCheck | ForwardStep::KeepLock => {}
            ForwardStep::ClaimLock => out.push(Some(Effect::Claim)),
            ForwardStep::NothingDisplaced => out.push(receipt(kind::SETTLED)),
        },
        StepDecision::Restore(step) => match step {
            RestoreStep::Exchange => {
                if !restore_started {
                    out.push(receipt(kind::RESTORE_STARTED));
                }
                out.push(Some(Effect::RestoreExchange));
                out.push(receipt(kind::RESTORED));
            }
            RestoreStep::RecognizeRestored => out.push(receipt(kind::RESTORED)),
            RestoreStep::CreateRollback => {
                if !restore_started {
                    out.push(receipt(kind::RESTORE_STARTED));
                }
                out.push(receipt(kind::SETTLING));
                out.push(Some(Effect::MoveToSlot(Name::Path)));
            }
            RestoreStep::RecordMismatch => {
                if matches!(phase, Some(EffectivePhase::Validated { .. })) {
                    out.push(receipt(kind::EXCHANGED));
                }
                out.push(receipt(kind::POST_VALIDATED));
            }
        },
        StepDecision::Abort(step) => match step {
            AbortStep::SettleStaged => {
                out.push(receipt(kind::SETTLING));
                out.push(Some(Effect::MoveToSlot(Name::Aside)));
            }
            AbortStep::NothingToSettle => {}
        },
        StepDecision::Settle(step) => match step {
            SettleStep::Begin => {
                out.push(receipt(kind::SETTLING));
                out.push(Some(Effect::MoveToSlot(
                    if shape == StepShape::GitLock || removal {
                        Name::Path
                    } else {
                        Name::Aside
                    },
                )));
            }
            SettleStep::Move => out.push(Some(Effect::MoveToSlot(source))),
            SettleStep::RecordSettled => out.push(receipt(kind::SETTLED)),
            SettleStep::Remove => out.push(Some(Effect::RemoveFromSlot)),
            SettleStep::PutBackForeign => {
                out.push(Some(Effect::PutBack(source)));
                out.push(Some(Effect::KeepAsConflict(Name::Slot)));
                out.push(receipt(kind::SETTLE_CONFLICT));
            }
            SettleStep::RecordConflict => out.push(receipt(kind::SETTLE_CONFLICT)),
            SettleStep::Done => {}
        },
        StepDecision::Hold(_) => out.push(receipt(kind::HELD)),
    }
    out.into_iter().flatten().collect()
}

// --- symbols ------------------------------------------------------------------------

/// One name's symbol, as the rows write it (ADR-0007 §5.7: ∅, S/S′, V/V′, D, Q/Q′, X,
/// ?). D has no content part. For `git_lock`, S is K; for a removal, V is L.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sym {
    Absent,
    S,
    Sm,
    V,
    Vm,
    D,
    Q,
    Qm,
    X,
    Unobservable,
}

use Sym::{Qm, Sm, Vm};

fn sym(e: EntryObs) -> Sym {
    let modified = |c: ContentState| c == ContentState::Modified;
    match e {
        EntryObs::Absent => Sym::Absent,
        EntryObs::Foreign => Sym::X,
        EntryObs::Unobservable => Sym::Unobservable,
        EntryObs::Recorded { which, content } => match which {
            RecordedRole::S if modified(content) => Sym::Sm,
            RecordedRole::S => Sym::S,
            RecordedRole::V if modified(content) => Sym::Vm,
            RecordedRole::V => Sym::V,
            RecordedRole::D => Sym::D,
            RecordedRole::Q if modified(content) => Sym::Qm,
            RecordedRole::Q => Sym::Q,
        },
    }
}

/// The symbols the forward rows name. An "any other" row covers combinations of
/// these; a combination with another symbol falls through to `Unmatched`.
fn plain(s: Sym) -> bool {
    matches!(s, Sym::Absent | Sym::S | Sm | Sym::V | Vm | Sym::X)
}

/// The symbols the restore rows name: the forward ones and D.
fn restore_symbol(s: Sym) -> bool {
    plain(s) || s == Sym::D
}

fn fwd(step: ForwardStep) -> StepDecision {
    StepDecision::Forward(step)
}

fn rst(step: RestoreStep) -> StepDecision {
    StepDecision::Restore(step)
}

fn abort(step: AbortStep) -> StepDecision {
    StepDecision::Abort(step)
}

fn settle(step: SettleStep) -> StepDecision {
    StepDecision::Settle(step)
}

fn hold(reason: HoldReason) -> StepDecision {
    StepDecision::Hold(reason)
}

/// The rows before the exchange run under T0: the item is open and no restore is in
/// its context.
fn pre_exchange(state: &RecoveryState) -> bool {
    state.item == ItemState::Open && state.restore == RestoreCtx::NotDue
}

/// A restore is due or started, and the item does not forbid it (T2).
fn restore_due(state: &RecoveryState) -> bool {
    matches!(state.restore, RestoreCtx::Due(_) | RestoreCtx::Started(_))
        && !matches!(state.item, ItemState::Committed | ItemState::Finished)
}

fn in_settlement(state: &RecoveryState) -> bool {
    matches!(
        state.phase,
        Some(
            EffectivePhase::Settling { .. }
                | EffectivePhase::Settled { .. }
                | EffectivePhase::SettleConflict { .. }
        )
    )
}

// --- decide -------------------------------------------------------------------------

/// Decide a step's action. Pure and total.
#[must_use]
pub fn decide(shape: StepShape, state: &RecoveryState, obs: &StepObservation) -> StepDecision {
    let (p, a, s) = (sym(obs.path()), sym(obs.aside()), sym(obs.slot()));
    if [p, a, s].contains(&Sym::Unobservable) {
        return hold(HoldReason::Unobservable);
    }
    if state.release_due && shape != StepShape::GitLock {
        return hold(HoldReason::Unmatched);
    }
    match shape {
        StepShape::Removal => removal(p, a, s),
        _ if in_settlement(state) => settlement(shape, state, p, a, s),
        StepShape::Replace => replace(state, p, a),
        StepShape::Create => create(state, p, a),
        StepShape::GitLock => git_lock(state, p, a),
    }
}

/// F0, F0x, F0z (phase none; the aside is the random staged name).
fn not_staged(a: Sym) -> StepDecision {
    match a {
        Sym::Absent => fwd(ForwardStep::Stage),
        Sym::S | Sm => fwd(ForwardStep::RecordStaged),
        Sym::X => abort(AbortStep::NothingToSettle),
        _ => hold(HoldReason::Unmatched),
    }
}

/// F1, F1a (phase `staged`): resume continues with an unchanged S; an S′ cannot be
/// continued, so the step aborts and settlement keeps it.
fn staged(a: Sym) -> StepDecision {
    match a {
        Sym::S => fwd(ForwardStep::Revalidate),
        Sm => abort(AbortStep::SettleStaged),
        Sym::Absent | Sym::X => abort(AbortStep::NothingToSettle),
        _ => hold(HoldReason::Unmatched),
    }
}

/// The replace step's rows (F0–F6a, without the settlement block).
fn replace(state: &RecoveryState, p: Sym, a: Sym) -> StepDecision {
    use Sym::{Absent, S, V, X};
    let open = pre_exchange(state);
    match &state.phase {
        None if open => not_staged(a),
        Some(EffectivePhase::Staged { .. }) if open => staged(a),
        Some(EffectivePhase::Validated { .. }) => match (p, a) {
            (S | Sm, V) => fwd(ForwardStep::RecordExchanged), // F2b
            (S | Sm, Vm | X) => rst(RestoreStep::RecordMismatch), // F2c
            (S | Sm, Absent) => hold(HoldReason::DisplacedMissing), // F2d
            (X | Absent, V) => hold(HoldReason::ActiveEntryReplaced), // F2h
            _ if !open => hold(HoldReason::Unmatched),
            (V, S) => fwd(ForwardStep::Revalidate), // F2a, resume
            (V | Vm, S | Sm) => abort(AbortStep::SettleStaged), // F2a, abort
            (X, S | Sm) => abort(AbortStep::SettleStaged), // F2e
            (V | Vm, Absent) => abort(AbortStep::NothingToSettle), // F2g
            (Absent, S | Sm) => abort(AbortStep::SettleStaged), // F2j
            (V | Vm, X) => abort(AbortStep::NothingToSettle), // F2k
            _ if plain(p) && plain(a) => hold(HoldReason::AmbiguousExchange), // F2f
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::Exchanged) => match (p, a) {
            (S | Sm, V) => fwd(ForwardStep::PostValidate), // F3
            (S | Sm, Vm | X) => rst(RestoreStep::RecordMismatch), // F3a
            (S | Sm, Absent) => hold(HoldReason::DisplacedMissing), // F3b
            _ if plain(p) && plain(a) => hold(HoldReason::ActiveEntryReplaced), // F3c
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::PostValidated { .. } | EffectivePhase::RestoreStarted { .. })
            if restore_due(state) =>
        {
            replace_restore(state, p, a)
        }
        Some(EffectivePhase::PostValidated {
            verdict: PostVerdict::Valid,
            ..
        }) => match (state.item, p, a) {
            (ItemState::Open, S | Sm, V) => fwd(ForwardStep::TransactionCheck), // F4
            (ItemState::Open, S | Sm, Absent) => hold(HoldReason::DisplacedMissing), // F4a
            (ItemState::Open, S | Sm, Vm | X) => hold(HoldReason::DisplacedReplaced), // F4c
            (ItemState::Open, _, _) if plain(p) && plain(a) => {
                hold(HoldReason::ActiveEntryReplaced) // F4b
            }
            (ItemState::Committed, _, V | Vm) => settle(SettleStep::Begin), // F4d
            (ItemState::Committed, _, Absent | X) => settle(SettleStep::RecordConflict), // F4e
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::Restored) => match a {
            S | Sm => settle(SettleStep::Begin),              // F6
            Absent | X => settle(SettleStep::RecordConflict), // F6a
            _ => hold(HoldReason::Unmatched),
        },
        _ => hold(HoldReason::Unmatched),
    }
}

/// F5–F5d: a restore is due (`post_validated{mismatch}`, or `post_validated{valid}`
/// with `item.rolling_back`) or started. D is V or V′ after a forward exchange, or the
/// identity a mismatch recorded. Performing the restore needs S with the target digest
/// at the path; recognizing a completed one (F5b, F5c) moves nothing.
fn replace_restore(state: &RecoveryState, p: Sym, a: Sym) -> StepDecision {
    use Sym::{D, S, V, X};
    let started = matches!(state.phase, Some(EffectivePhase::RestoreStarted { .. }));
    match (p, a) {
        (S, D | V | Vm) => rst(RestoreStep::Exchange), // F5
        (Sm, D | V | Vm) => hold(HoldReason::ActiveEntryModified), // F5a
        (D | V | Vm, S | Sm) if started => rst(RestoreStep::RecognizeRestored), // F5b
        (X, S | Sm) if started => rst(RestoreStep::RecognizeRestored), // F5c
        _ if restore_symbol(p) && restore_symbol(a) => hold(HoldReason::ThirdWriter), // F5d
        _ => hold(HoldReason::Unmatched),
    }
}

/// The create step's rows (F0–F1a, C1–C8, without the settlement block).
fn create(state: &RecoveryState, p: Sym, a: Sym) -> StepDecision {
    use Sym::{Absent, S, X};
    let open = pre_exchange(state);
    match &state.phase {
        None if open => not_staged(a),
        Some(EffectivePhase::Staged { .. }) if open => staged(a),
        Some(EffectivePhase::Validated { .. }) => match (p, a) {
            (S | Sm, Absent) => fwd(ForwardStep::RecordExchanged), // C2
            _ if !open => hold(HoldReason::Unmatched),
            (Absent, S) => fwd(ForwardStep::Revalidate), // C1, resume
            (Absent, Sm) => abort(AbortStep::SettleStaged), // C1, abort
            (X, S | Sm) => abort(AbortStep::SettleStaged), // C3
            (Absent, Absent) => abort(AbortStep::NothingToSettle), // C4
            (Absent, X) => abort(AbortStep::NothingToSettle), // C4b
            _ if plain(p) && plain(a) => hold(HoldReason::AmbiguousExchange), // C4h
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::Exchanged) => match p {
            S | Sm => fwd(ForwardStep::PostValidate), // C6
            _ if plain(p) => hold(HoldReason::ActiveEntryReplaced), // C6a
            _ => hold(HoldReason::Unmatched),
        },
        Some(
            EffectivePhase::PostValidated {
                verdict: PostVerdict::Valid,
                ..
            }
            | EffectivePhase::RestoreStarted { .. },
        ) if restore_due(state) => create_restore(p),
        Some(EffectivePhase::PostValidated {
            verdict: PostVerdict::Valid,
            ..
        }) => match (state.item, p) {
            (ItemState::Open, S | Sm) => fwd(ForwardStep::TransactionCheck), // C5
            (ItemState::Open, _) if plain(p) => hold(HoldReason::ActiveEntryReplaced), // C5a
            (ItemState::Committed, _) => fwd(ForwardStep::NothingDisplaced), // C5b
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::Restored) => settle(SettleStep::Done), // C8
        _ => hold(HoldReason::Unmatched),
    }
}

/// C7–C7b: a create's restore settles the path entry through the quarantine, and
/// only an unchanged S (QR13).
fn create_restore(p: Sym) -> StepDecision {
    match p {
        Sym::S => rst(RestoreStep::CreateRollback),  // C7
        Sm => hold(HoldReason::ActiveEntryModified), // C7a
        _ if plain(p) => hold(HoldReason::ActiveEntryReplaced), // C7b
        _ => hold(HoldReason::Unmatched),
    }
}

/// K0–K4: `p` is the lock name, `a` is K's random staged name, and S is K. A K that is
/// not provable is already `X` at the lock (the classifier's birth-time rule).
fn git_lock(state: &RecoveryState, p: Sym, a: Sym) -> StepDecision {
    use Sym::{Absent, S, X};
    let open = pre_exchange(state);
    match &state.phase {
        None if open => match a {
            Absent => fwd(ForwardStep::Stage),        // K0
            S | Sm => fwd(ForwardStep::RecordStaged), // K0x
            X => abort(AbortStep::NothingToSettle),   // K0z
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::Staged { .. }) => match (p, a) {
            (_, S | Sm) if !open => hold(HoldReason::Unmatched),
            (_, S | Sm) if state.release_due => abort(AbortStep::SettleStaged), // K1, release due
            (Absent, S) => fwd(ForwardStep::ClaimLock),                         // K1, resume
            (Absent, Sm) => abort(AbortStep::SettleStaged), // K1, K′ cannot be continued
            (X, S | Sm) => abort(AbortStep::SettleStaged),  // K1, the claim fails
            (S | Sm, Absent | X) if state.release_due => settle(SettleStep::Begin), // K2, release
            (S | Sm, Absent | X) => fwd(ForwardStep::KeepLock), // K2
            (Absent, Absent | X) => settle(SettleStep::RecordConflict), // K3
            (X, Absent | X) => settle(SettleStep::RecordConflict), // K4
            _ => hold(HoldReason::Unmatched),
        },
        _ => hold(HoldReason::Unmatched),
    }
}

/// R1–R6, the cleaner's rows: L is the locator's entry with its digest.
fn removal(p: Sym, a: Sym, s: Sym) -> StepDecision {
    use Sym::{Absent, X};
    let l = |x: Sym| matches!(x, Sym::S | Sym::V);
    let l_modified = |x: Sym| matches!(x, Sm | Vm);
    if a != Absent {
        return hold(HoldReason::Unmatched);
    }
    match (p, s) {
        _ if l(p) && s == Absent => settle(SettleStep::Move), // R1
        _ if l_modified(p) && s == Absent => settle(SettleStep::Done), // R1a
        (Absent | X, _) if l(s) => settle(SettleStep::Remove), // R2
        (Absent | X, _) if l_modified(s) => settle(SettleStep::RecordConflict), // R2a
        (Absent | X, Absent) => settle(SettleStep::Done),     // R3, R4
        (Absent | X, X) => settle(SettleStep::PutBackForeign), // R5
        _ if (l(p) || l_modified(p)) && s == X => hold(HoldReason::ThirdWriter), // R6
        _ => hold(HoldReason::Unmatched),
    }
}

/// F8a–F9d, for every shape. The source is the name `file.settling` recorded: the path
/// for a `path` source (a create's restore, K's release from the lock), the aside name
/// otherwise.
fn settlement(shape: StepShape, state: &RecoveryState, p: Sym, a: Sym, s: Sym) -> StepDecision {
    use Sym::{Absent, Q, X};
    let create_restore = state.settlement.is_some_and(|c| c.create_restore);
    let end = if create_restore {
        rst(RestoreStep::RecognizeRestored)
    } else {
        settle(SettleStep::Done)
    };
    match &state.phase {
        Some(EffectivePhase::Settling { .. }) => {
            let Some(ctx) = state.settlement else {
                return hold(HoldReason::Unmatched);
            };
            let consistent = match ctx.source {
                SettleSource::Path => {
                    (shape == StepShape::Create && ctx.create_restore)
                        || (shape == StepShape::GitLock && !ctx.create_restore)
                }
                SettleSource::Displaced => shape == StepShape::Replace && !ctx.create_restore,
                SettleSource::Staged => !ctx.create_restore,
            };
            if !consistent {
                return hold(HoldReason::Unmatched);
            }
            let source = if ctx.source == SettleSource::Path {
                p
            } else {
                a
            };
            match (source, s) {
                (_, X) => settle(SettleStep::PutBackForeign),  // F8d
                (_, Q) => settle(SettleStep::RecordSettled),   // F8b
                (_, Qm) => settle(SettleStep::RecordConflict), // F8f
                (Q, Absent) => settle(SettleStep::Move),       // F8a
                (Qm, Absent) if ctx.create_restore => hold(HoldReason::ActiveEntryModified), // F8a
                (Qm, Absent) => settle(SettleStep::Move),      // F8a
                (X | Absent, Absent) => settle(SettleStep::RecordConflict), // F8e, F8c
                _ => hold(HoldReason::Unmatched),
            }
        }
        Some(EffectivePhase::Settled { .. }) => match s {
            Q if state.settlement.is_some() => settle(SettleStep::Remove), // F9
            Qm => settle(SettleStep::RecordConflict),                      // F9a
            Absent | X => end,                                             // F9b, F9c
            _ => hold(HoldReason::Unmatched),
        },
        Some(EffectivePhase::SettleConflict { .. }) => end, // F9d
        _ => hold(HoldReason::Unmatched),
    }
}

// --- the item rows ------------------------------------------------------------------

/// A step's state as the item rows see it.
///
/// The caller (`apply::reconcile`) drives each step by its own rows first and asks
/// [`decide_item`] once no step's row can continue without the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepState {
    /// Its row continues it, or it waits for the item without being exchanged (K2
    /// keeping the lock).
    Open,
    /// It is the commit step and was never exchanged (T0). This takes precedence over
    /// `Final` for the commit step: an aborted commit step stays this.
    CommitNeverExchanged,
    /// Exchanged; observes path S or S′ and, for a replace step, aside V (T1). Used
    /// only while the commit step is at `post_validated{valid}` with no item receipt.
    ExchangedConsistent,
    /// Exchanged; observes anything else (T1h). As `ExchangedConsistent`, only at T1.
    ExchangedInconsistent,
    /// Final for the step.
    Final,
    /// Held (TH).
    Held,
}

/// The item's own receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ItemReceipts {
    /// `item.committed` is on record.
    pub committed: bool,
    /// `item.rolling_back` is on record, with its reason.
    pub rolling_back: Option<ConflictKind>,
    /// `item.finished` is on record.
    pub finished: bool,
}

/// The item rows' decision (T0–TH).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemDecision {
    /// T0: resume forward under the same plan, or abort when a precondition fails.
    ResumeOrAbort,
    /// T1: re-run the transaction check, then commit or roll back.
    TransactionCheck,
    /// T2: finish forward, settle, release K last; never restore.
    FinishForward,
    /// T3: finish the restore, settle, release K, hand inactive files to the cleaner.
    FinishRestore,
    /// T4: settle the operation with the recorded outcomes.
    Settle,
    /// TH: hold the item.
    Hold(HoldReason),
}

/// Decide the item's action from its steps' states and its own receipts. Pure.
///
/// The rows are tried in this order:
///
/// 1. TH: `item.committed` and `item.rolling_back` both on record →
///    `Hold(ContradictoryReceipts)`;
/// 2. T4: `item.finished` → `Settle` (the recorded outcome stands, also after
///    `keep_held` left steps where they were);
/// 3. TH: a step is held → `Hold`;
/// 4. T2: `item.committed` → `FinishForward`;
/// 5. T3: `item.rolling_back` → `FinishRestore`;
/// 6. T0: the commit step was never exchanged → `ResumeOrAbort`;
/// 7. T1h: an exchanged step is inconsistent → `Hold`;
/// 8. T1: exchanged steps are consistent → `TransactionCheck`;
/// 9. T3, the commit step's file-level restore: no item receipt and every step final.
///    The commit step is then exchanged (it is not `CommitNeverExchanged`) and final
///    with no item receipt, which only its own restore after
///    `post_validated{mismatch}` gives → `FinishRestore`;
/// 10. anything else → `Hold(Unmatched)`.
///
/// A held item reports each held step with its own reason (`HeldStep`). The item rows
/// add a reason of their own only for contradictory receipts; for a held or
/// inconsistent step, whose reason [`StepState`] does not carry, the item's reason is
/// `Unmatched`: no forward, restore or abort row of the item matches.
#[must_use]
pub fn decide_item(steps: &[StepState], receipts: &ItemReceipts) -> ItemDecision {
    let any = |s: StepState| steps.contains(&s);
    if receipts.committed && receipts.rolling_back.is_some() {
        return ItemDecision::Hold(HoldReason::ContradictoryReceipts); // TH
    }
    if receipts.finished {
        return ItemDecision::Settle; // T4
    }
    if any(StepState::Held) {
        return ItemDecision::Hold(HoldReason::Unmatched); // TH
    }
    if receipts.committed {
        return ItemDecision::FinishForward; // T2
    }
    if receipts.rolling_back.is_some() {
        return ItemDecision::FinishRestore; // T3
    }
    if any(StepState::CommitNeverExchanged) {
        return ItemDecision::ResumeOrAbort; // T0
    }
    if any(StepState::ExchangedInconsistent) {
        return ItemDecision::Hold(HoldReason::Unmatched); // T1h
    }
    if any(StepState::ExchangedConsistent) {
        return ItemDecision::TransactionCheck; // T1
    }
    if !steps.is_empty() && steps.iter().all(|s| *s == StepState::Final) {
        return ItemDecision::FinishRestore; // T3, file-level
    }
    ItemDecision::Hold(HoldReason::Unmatched)
}

#[cfg(test)]
mod wave0_review {
    /// Wave-0 review Z03: localenv's `StepDecision` is the domain type, re-exported,
    /// not a copy (compile-checked identity of the two paths).
    #[test]
    fn wave0_z03_localenv_reexports_the_domain_step_decision() {
        fn same(d: heimdall_domain::projection::StepDecision) -> super::StepDecision {
            d
        }
        let d = same(super::StepDecision::Abort(
            super::AbortStep::NothingToSettle,
        ));
        assert!(matches!(d, super::StepDecision::Abort(_)));
    }
}
