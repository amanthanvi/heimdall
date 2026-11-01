//! Consent classification (m02-plan U2; ADR-0007 §5.2, M2-D04, M2-R03).
//!
//! A decision is needed for any state the owner has not consented to. Only
//! **determined** states are compared: an affected item whose current or after state is
//! undetermined always needs a decision, reason `undetermined_state`, whatever the
//! digests say.

use heimdall_domain::projection::{BehaviorState, ItemId};

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

/// Classify the affected items (ADR-0007 §5.2; M2-D04, M2-R03).
///
/// For each item, in order:
/// 1. its *current* or *after* state is undetermined: a decision is required, reason
///    [`ConsentReasonKind::UndeterminedState`], whatever the digests say (an equal
///    digest proves nothing for an undetermined state, §12.5 item 3);
/// 2. *after* equals *current* (a byte-identical re-render): nothing is needed;
/// 3. *after* equals a consented state that was **determined when recorded** (the
///    approved managed state, or the restore state the decision showed): nothing is
///    needed;
/// 4. otherwise a decision is required. The reason is
///    [`ConsentReasonKind::GitSelectionChanged`] for Git's selection (item `git`),
///    [`ConsentReasonKind::NewState`] for an item with no determined consented state
///    (first adoption, a new alias), and [`ConsentReasonKind::ExposesInherited`] for
///    an item whose determined consent no longer covers the after state (for example
///    a rollback that would expose a `HostName` or agent the user's configuration
///    gained after the decision).
///
/// `required` is true exactly when some item has a reason. The classification is
/// static and executes nothing.
#[must_use]
pub fn classify(items: &[ConsentItem]) -> ConsentNeed {
    let mut reasons = Vec::new();
    for it in items {
        let kind = if !it.current.determined || !it.after.determined {
            Some(ConsentReasonKind::UndeterminedState)
        } else if it.after.digest == it.current.digest {
            None
        } else {
            let usable: Vec<&BehaviorState> = it
                .consented
                .iter()
                .flat_map(|c| [&c.managed, &c.restore])
                .filter(|s| s.determined)
                .collect();
            if usable.iter().any(|s| s.digest == it.after.digest) {
                None
            } else if it.item.0 == ItemId::git_selection().0 {
                Some(ConsentReasonKind::GitSelectionChanged)
            } else if usable.is_empty() {
                Some(ConsentReasonKind::NewState)
            } else {
                Some(ConsentReasonKind::ExposesInherited)
            }
        };
        if let Some(kind) = kind {
            reasons.push(ConsentReason {
                item: it.item.clone(),
                kind,
            });
        }
    }
    ConsentNeed {
        required: !reasons.is_empty(),
        reasons,
    }
}
