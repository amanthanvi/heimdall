//! Consent classification (m02-plan U2; ADR-0007 §5.2, M2-D04, M2-R03).
//!
//! A decision is needed for any state the owner has not consented to. Only
//! **determined** states are compared: an affected item whose current or after state is
//! undetermined always needs a decision, reason `undetermined_state`, whatever the
//! digests say.

use heimdall_domain::projection::BehaviorState;

/// An item whose behaviour a setup action can change (an alias, the Git selection).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsentItemId(pub String);

/// The states the owner consented to for an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentedStates {
    /// The managed state.
    pub managed: BehaviorState,
    /// The state a rollback restores.
    pub restore: BehaviorState,
}

/// One affected item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentItem {
    /// The item.
    pub item: ConsentItemId,
    /// Its state now.
    pub current: BehaviorState,
    /// Its state after the action.
    pub after: BehaviorState,
    /// What the owner consented to, if anything.
    pub consented: Option<ConsentedStates>,
}

/// Why a decision is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsentReasonKind {
    /// The after state was never consented to.
    NewState,
    /// The action exposes an inherited value (for example a rollback exposing a user
    /// `Host *` `HostName`).
    ExposesInherited,
    /// The current or after state is undetermined (M2-R03).
    UndeterminedState,
    /// Git's effective SSH selection changes.
    GitSelectionChanged,
}

/// One reason, with its item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentReason {
    /// The item.
    pub item: ConsentItemId,
    /// Why.
    pub kind: ConsentReasonKind,
}

/// The classification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsentNeed {
    /// Whether an `ApplyProjection` decision is required.
    pub required: bool,
    /// Every reason.
    pub reasons: Vec<ConsentReason>,
}

/// Classify the affected items.
#[must_use]
pub fn classify(items: &[ConsentItem]) -> ConsentNeed {
    let _ = items;
    todo!("M02-U2 consent::classify")
}
