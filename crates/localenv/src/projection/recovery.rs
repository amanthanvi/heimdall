//! The total recovery function (m02-plan U4; ADR-0007 §5.7; M2-S01, M2-T04, M2-T05).
//!
//! **Frozen in wave 0** (m02-plan U0): [`decide`], [`decide_item`], [`StepDecision`]
//! and its step types, and the effect alphabet [`Effect`]. The inputs `StepShape`,
//! `RecoveryState`, `StepObservation`, `EntryObs` and `HoldReason` live in
//! `heimdall-domain` because they cross the `ProjectionWriter` port (wave-0 verifier
//! E8).
//!
//! [`decide`] is pure: no I/O and no clock. It is ADR-0007 §5.7's rows, with a final
//! `_ => Hold(Unmatched)` in every block; every `Unobservable` input is `Hold` before
//! any row is tried. `reconcile` is `observe_step`, then `decide`, then the action,
//! repeated until a step is final or held.

use heimdall_contract::setup::ConflictKind;
use heimdall_domain::operation::HoldReason;
use heimdall_domain::projection::{RecoveryState, StepObservation, StepShape};

/// A forward action (continues the approved plan; ends in `applied`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardStep {
    /// F0/T0: stage the step (from the intent's content).
    Stage,
    /// F0x/K0x: record `file.staged` for the entry found at the random staged name.
    RecordStaged,
    /// Resume at validation (T0): revalidate the path, then continue.
    Revalidate,
    /// F2b/C2: write the lost `file.exchanged`.
    RecordExchanged,
    /// F3/C6: post-validate.
    PostValidate,
    /// T1: re-run the item's transaction check.
    TransactionCheck,
    /// K1: claim the Git lock with K (no-replace).
    ClaimLock,
    /// K2 before the release is due: keep the lock; no effect.
    KeepLock,
    /// C5/C5b: write `file.settled{nothing_displaced}`.
    NothingDisplaced,
}

/// A restore action (ends in `restored`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreStep {
    /// F5: write `file.restore_started` (unless it is the effective phase), exchange
    /// back, verify, write `file.restored`.
    Exchange,
    /// F5b/F5c: the restore exchange already happened; write `file.restored` only.
    RecognizeRestored,
    /// C7: settle the created entry from the path, then `file.restored`.
    CreateRollback,
    /// F2c/F3a: record `file.post_validated{mismatch}`, then restore.
    RecordMismatch,
}

/// An abort action (the commit step was never exchanged; ends in `not_applied`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbortStep {
    /// Settle Heimdall's own staged entry, then hand inactive files to the cleaner.
    SettleStaged,
    /// Nothing of the step is left (F1a, F2g, C4, K0z …); report and continue.
    NothingToSettle,
}

/// A settlement action (the settlement block F8–F9d, and K's release).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettleStep {
    /// Write `file.settling`, then move into the slot.
    Begin,
    /// F8a: move the source into the slot.
    Move,
    /// F8b: moved, receipt lost; write `file.settled`.
    RecordSettled,
    /// F9: remove from the slot after re-checking.
    Remove,
    /// F8d/R5: put a foreign entry back, or keep it as a conflict.
    PutBackForeign,
    /// F4e/F6a/F8c/F8e/F8f/F9a/K3/K4: write `file.settle_conflict`; nothing moves.
    RecordConflict,
    /// F9b/F9d: final for the step.
    Done,
}

/// `decide`'s result: exactly one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepDecision {
    /// Continue forward.
    Forward(ForwardStep),
    /// Restore.
    Restore(RestoreStep),
    /// Abort.
    Abort(AbortStep),
    /// Settle.
    Settle(SettleStep),
    /// Outcome H: move nothing, write `file.held` when the observation changed.
    Hold(HoldReason),
}

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
