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

use heimdall_contract::setup::ConflictKind;
use heimdall_domain::operation::HoldReason;
use heimdall_domain::projection::{RecoveryState, StepObservation, StepShape};

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

/// The effects of `decision` for a step in `state` (the property checker's input).
#[must_use]
pub fn effects(decision: StepDecision, shape: StepShape, state: &RecoveryState) -> Vec<Effect> {
    let _ = (decision, shape, state);
    todo!("M02-U4 recovery::effects")
}

/// Decide a step's action. Pure and total.
#[must_use]
pub fn decide(shape: StepShape, state: &RecoveryState, obs: &StepObservation) -> StepDecision {
    let _ = (shape, state, obs);
    todo!("M02-U4 recovery::decide")
}

/// A step's state as the item rows see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepState {
    /// Its row continues it.
    Open,
    /// It is the commit step and was never exchanged (T0).
    CommitNeverExchanged,
    /// Exchanged; observes path S or S′ and, for a replace step, aside V (T1).
    ExchangedConsistent,
    /// Exchanged; observes anything else (T1h).
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
#[must_use]
pub fn decide_item(steps: &[StepState], receipts: &ItemReceipts) -> ItemDecision {
    let _ = (steps, receipts);
    todo!("M02-U4 recovery::decide_item")
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
