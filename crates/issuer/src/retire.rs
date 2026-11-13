//! CA retirement (ADR-0008 D4 item 3; §17.1 items 7, 11; m03-plan U4 `retire::step`)
//! and the uninstall fate of a K_ca store item (D4 item 6; F08).
//!
//! **Retirement is a durable transition**, each state persisted before the next
//! action: `active | pending → retiring` (the `RetireIssuer` decision, the runtime's
//! transaction) `→ unloaded` (the issuer child confirmed it zeroized the key) `→
//! deleted` (the store item deleted by exact identity and a re-read finds it absent)
//! `→ retired`. [`step`] performs the external effect of the next transition and
//! returns the event and state the caller persists (`Txn::set_issuer_state`, a
//! compare-and-swap); it never persists anything itself, and it is idempotent: run
//! again from the same state (a crash after the effect, before the persist), it
//! repeats an effect that is already done, which succeeds (an unloaded key unloads
//! again; an absent store item counts as deleted).
//!
//! [`admissible`] is the precondition (§17.1 item 7): every enrollment of the CA is
//! final or `abandoned`.
//!
//! ⟨ADR-0008 §17.22 item 12; D3⟩ **Who deletes the store item.** Neither the runtime
//! nor the issuer child ever writes or deletes the platform store (the child only
//! reads it). The `unloaded → deleted` effect is the **owner-present CLI's**:
//! [`delete_awaiting`] deletes exactly the locator `issuer.status` names for an
//! `unloaded` CA (`CaStatus::store_locator`) or for a displaced item
//! (`orphan_store_items`), re-reads the store, and only then does the CLI confirm it
//! on `issuer.retire` with `deleted_locator` (the runtime then records `deleted` and
//! `retired`). Round 2's runtime-side port (`StoreItemDeletion` over
//! `app::operations::CaStoreItemDeletion`) is removed.
//!
//! **Exact identity** (ADR-0008 §17.17 item 3; D1). `put` returns the item's
//! [`StoreItemRef`]; this installation records it, and retirement deletes **only that
//! locator** ([`delete_recorded`]), then re-reads the store and requires that locator
//! to be absent. It never deletes everything `list()` reports for a fingerprint, so a
//! second installation of the same OS user holding the same (restored) CA keeps its
//! item. A CA with **no recorded locator** is refused, with nothing deleted: its item
//! stays, as an orphan to report. ⟨ADR-0008 §17.21 item 3; §17.22 item 12⟩ The
//! runtime records the locator the ceremony reported in the CA's `issuers` row and
//! names it in `issuer.status`; a CA without one stops at `unloaded`
//! (`issuer_store_locator_unrecorded`) and nothing here is called. [`StoreEffects`]
//! takes its locators from a [`RecordedItems`] instead ([`NoRecordedItems`] refuses
//! every deletion).
//!
//! [`uninstall_store_plan`] is D4 item 6's rule for U12's uninstall: the item is kept,
//! with its reason, while any enrollment under its CA is not final; otherwise deleting
//! it (the retirement steps run to `retired`) is offered behind a typed confirmation.

use heimdall_contract::enrollment::{EnrollmentState, EnrollmentView};
use heimdall_contract::ids::{CaFingerprint, EnrollmentId};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_domain::issuance::{CaEvent, ca_transition};

use crate::store::{SecretStore, SecretStoreKind, StoreError, StoreItemRef};

/// ⟨ADR-0008 §17.25 item 7 (d)⟩ Whether [`delete_awaiting`] deletes a test-configuration
/// store's item by its exact locator: debug builds only (`cfg!(debug_assertions)`). A
/// release build never selects a test store (every `HEIMDALL_TEST_*` variable is refused
/// first), and refuses one here too.
pub const TEST_STORE_DELETION: bool = cfg!(debug_assertions);

/// A retirement step's failure (nonsecret).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RetireError {
    /// The CA is not in a retirement state (`active`, `pending`: the decision has
    /// not been applied; `retired`: nothing is left).
    #[error("CA is {0:?}: no retirement step to take")]
    NoStep(CaState),
    /// The issuer child did not confirm the unload (nonsecret reason).
    #[error("the issuer did not confirm the unload: {0}")]
    Unload(String),
    /// The store item could not be deleted, or a re-read still finds it.
    #[error("the store item could not be deleted: {0}")]
    Store(StoreError),
    /// No store item was recorded for this CA at `put` (ADR-0008 §17.17 item 3):
    /// nothing is deleted, and the item stays as an orphan to report.
    #[error("no store item was recorded for this CA: nothing deleted")]
    LocatorNotRecorded,
    /// The recorded item names another CA or another store kind: nothing deleted.
    #[error("the recorded store item does not match this CA and store: nothing deleted")]
    LocatorMismatch,
}

/// The store items this installation recorded at `put` (ADR-0008 §17.17 item 3): the
/// only items retirement may delete.
pub trait RecordedItems {
    /// The item recorded for `ca`, if any.
    fn recorded(&self, ca: &CaFingerprint) -> Option<StoreItemRef>;
}

/// No recorded items (production until the runtime persists them, U10): every
/// deletion is refused, nothing is deleted.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRecordedItems;

impl RecordedItems for NoRecordedItems {
    fn recorded(&self, _ca: &CaFingerprint) -> Option<StoreItemRef> {
        None
    }
}

impl RecordedItems for [StoreItemRef] {
    fn recorded(&self, ca: &CaFingerprint) -> Option<StoreItemRef> {
        self.iter().find(|i| i.fingerprint == *ca).cloned()
    }
}

impl RecordedItems for Vec<StoreItemRef> {
    fn recorded(&self, ca: &CaFingerprint) -> Option<StoreItemRef> {
        self.as_slice().recorded(ca)
    }
}

/// The external effects of the retirement steps.
pub trait RetireEffects {
    /// Ask the issuer child to unload (zeroize) `ca`; `Ok` once it confirmed. A CA
    /// it does not hold is confirmed at once.
    ///
    /// # Errors
    /// [`RetireError::Unload`].
    fn unload(&mut self, ca: &CaFingerprint) -> Result<(), RetireError>;

    /// Delete `ca`'s store item by exact identity (the locator recorded at `put`);
    /// `Ok` only when a re-read no longer finds that locator (one already absent
    /// counts as deleted).
    ///
    /// # Errors
    /// [`RetireError::Store`].
    fn delete_store_item(&mut self, ca: &CaFingerprint) -> Result<(), RetireError>;
}

/// One retirement step: the event to persist and the state it leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// The event (`Txn::set_issuer_state(ca, from, event, at)`).
    pub event: CaEvent,
    /// The state after it.
    pub next: CaState,
}

/// Take the retirement step from the durable `state` of `ca`: perform its external
/// effect, then return the event and next state for the caller to persist.
///
/// # Errors
/// [`RetireError::NoStep`] outside `retiring`, `unloaded` and `deleted`; the
/// effect's error otherwise (the state stays as it is).
pub fn step(
    ca: &CaFingerprint,
    state: CaState,
    effects: &mut dyn RetireEffects,
) -> Result<Step, RetireError> {
    let event = match state {
        CaState::Retiring => {
            effects.unload(ca)?;
            CaEvent::UnloadConfirmed
        }
        CaState::Unloaded => {
            effects.delete_store_item(ca)?;
            CaEvent::StoreItemDeleted
        }
        CaState::Deleted => CaEvent::RetirementRecorded,
        other => return Err(RetireError::NoStep(other)),
    };
    let next = ca_transition(state, event).map_err(|e| RetireError::NoStep(e.from))?;
    Ok(Step { event, next })
}

/// Why a retirement is refused (§17.1 item 7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{} enrollment(s) of that CA are neither final nor abandoned", .open.len())]
pub struct RetireRefusal {
    /// The enrollments that block it.
    pub open: Vec<EnrollmentId>,
}

/// Whether `ca` may be retired: every enrollment of it in `enrollments` is final or
/// `abandoned`. Returns the abandoned ones (their lines stay,
/// `pending_until_line_removed`; the `RetireIssuer` decision lists them).
///
/// # Errors
/// [`RetireRefusal`] naming every enrollment that is neither.
pub fn admissible(
    ca: &CaFingerprint,
    enrollments: &[EnrollmentView],
) -> Result<Vec<EnrollmentId>, RetireRefusal> {
    let mine = enrollments.iter().filter(|e| e.ca_fingerprint == *ca);
    let (mut open, mut abandoned) = (Vec::new(), Vec::new());
    for e in mine {
        if e.state == EnrollmentState::Abandoned {
            abandoned.push(e.enrollment_id.clone());
        } else if !e.state.is_final() {
            open.push(e.enrollment_id.clone());
        }
    }
    if open.is_empty() {
        Ok(abandoned)
    } else {
        Err(RetireRefusal { open })
    }
}

/// Delete exactly `recorded`, the item this installation recorded for `ca` at `put`,
/// then re-read the store: `Ok` only when that locator is absent (an item already
/// absent counts as deleted). Items of the same CA under other locators (another
/// installation's) are never touched, and the absence check looks only for this one.
///
/// # Errors
/// [`RetireError::LocatorNotRecorded`] without a recorded item and
/// [`RetireError::LocatorMismatch`] when it names another CA or store kind (nothing is
/// deleted in either case); [`RetireError::Store`] when the store cannot delete or
/// list, or the locator is still there.
pub fn delete_recorded<S: SecretStore + ?Sized>(
    store: &S,
    ca: &CaFingerprint,
    recorded: Option<&StoreItemRef>,
) -> Result<(), RetireError> {
    let Some(item) = recorded else {
        return Err(RetireError::LocatorNotRecorded);
    };
    if item.fingerprint != *ca || item.kind != store.kind() {
        return Err(RetireError::LocatorMismatch);
    }
    match store.delete(item) {
        Ok(()) | Err(StoreError::NotFound) => {}
        Err(e) => return Err(RetireError::Store(e)),
    }
    let still = store
        .list()
        .map_err(RetireError::Store)?
        .iter()
        .any(|i| i.kind == item.kind && i.locator == item.locator);
    if still {
        return Err(RetireError::Store(StoreError::Failed));
    }
    Ok(())
}

/// ⟨ADR-0008 §17.22 item 12⟩ The owner-present CLI's deletion (U12's `issuer retire`
/// after the child unloaded the CA, and the resolution of a displaced item): delete
/// exactly `locator`, the store item `issuer.status` names for `ca` in a store of kind
/// `store` (`CaStatus::store_locator` while `unloaded`, or an `orphan_store_items`
/// entry's `locator`), then re-read the store. `Ok` only when the re-read no longer
/// finds that locator (an item already absent counts as deleted); the CLI then sends
/// `issuer.retire` with `deleted_locator: locator`.
///
/// Refused, deleting nothing: `store` is not this store's product kind (another store),
/// an empty locator, or a store listing that shows `locator` holding **another** CA
/// ([`RetireError::LocatorMismatch`]). Items of `ca` under other locators (another
/// installation's) are never touched.
///
/// ⟨ADR-0008 §17.25 item 7 (d)⟩ **Debug builds only**, a test-configuration store (a
/// [`SecretStoreKind::Test`] kind: the testkit's scratch store, which only a
/// test-configured debug build selects) is deleted by the same exact-locator rule,
/// whatever product kind its CA's record names (a test kind is never on the wire, so the
/// record names a stand-in). That proves the R2B order where no disposable product store
/// exists (Linux). A release build refuses a test kind ([`TEST_STORE_DELETION`]).
///
/// # Errors
/// [`RetireError::LocatorMismatch`] as above; [`RetireError::Store`] when the store
/// cannot list or delete, or the locator is still there.
pub fn delete_awaiting<S: SecretStore + ?Sized>(
    secret_store: &S,
    ca: &CaFingerprint,
    store: StoreKind,
    locator: &str,
) -> Result<(), RetireError> {
    let kind = secret_store.kind();
    let kind_matches = match kind {
        SecretStoreKind::Product(k) => k == store,
        SecretStoreKind::Test(_) => TEST_STORE_DELETION,
    };
    if !kind_matches || locator.is_empty() {
        return Err(RetireError::LocatorMismatch);
    }
    let listed = secret_store.list().map_err(RetireError::Store)?;
    if listed
        .iter()
        .any(|i| i.kind == kind && i.locator == locator && i.fingerprint != *ca)
    {
        return Err(RetireError::LocatorMismatch);
    }
    let item = StoreItemRef {
        kind,
        fingerprint: ca.clone(),
        locator: locator.to_owned(),
    };
    delete_recorded(secret_store, ca, Some(&item))
}

/// [`RetireEffects`] over a store, with the unload left to `unload` (U3's issuer
/// client in production; a test double in tests).
pub struct StoreEffects<'a, U: FnMut(&CaFingerprint) -> Result<(), RetireError>> {
    store: &'a dyn SecretStore,
    recorded: &'a dyn RecordedItems,
    unload: U,
}

impl<'a, U: FnMut(&CaFingerprint) -> Result<(), RetireError>> StoreEffects<'a, U> {
    /// The effects: `unload` for `retiring → unloaded`, [`delete_recorded`] on `store`
    /// with the item `recorded` holds for the CA for `unloaded → deleted`.
    pub fn new(store: &'a dyn SecretStore, recorded: &'a dyn RecordedItems, unload: U) -> Self {
        Self {
            store,
            recorded,
            unload,
        }
    }
}

impl<U: FnMut(&CaFingerprint) -> Result<(), RetireError>> RetireEffects for StoreEffects<'_, U> {
    fn unload(&mut self, ca: &CaFingerprint) -> Result<(), RetireError> {
        (self.unload)(ca)
    }

    fn delete_store_item(&mut self, ca: &CaFingerprint) -> Result<(), RetireError> {
        delete_recorded(self.store, ca, self.recorded.recorded(ca).as_ref())
    }
}

/// Why uninstall keeps a store item (D4 item 6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeepReason {
    /// Enrollments under the item's CA are not final; their markers.
    LiveEnrollments(Vec<String>),
}

/// What uninstall does with a K_ca store item (D4 item 6; F08).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreFate {
    /// Keep it, naming the item and the reason.
    Keep(KeepReason),
    /// Offer deleting it (the retirement steps run to `retired`) behind a typed
    /// confirmation, and remind the owner to destroy the offline backup.
    OfferDelete,
}

/// D4 item 6: while any enrollment under `item`'s CA is not final, keep the item;
/// when every one is final, or there are none, offer deleting it. (`abandoned` is
/// not final: its line may still trust the CA.)
#[must_use]
pub fn uninstall_store_plan(enrollments: &[EnrollmentView], item: &StoreItemRef) -> StoreFate {
    let live: Vec<String> = enrollments
        .iter()
        .filter(|e| e.ca_fingerprint == item.fingerprint && !e.state.is_final())
        .map(|e| e.marker.clone())
        .collect();
    if live.is_empty() {
        StoreFate::OfferDelete
    } else {
        StoreFate::Keep(KeepReason::LiveEnrollments(live))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::store::StoreAvailability;
    use heimdall_credential::cert::SecretCaKey;

    /// A test-configuration store in memory (a `SecretStoreKind::Test` kind, like the
    /// testkit's scratch store, which this crate's unit tests cannot name).
    #[derive(Default)]
    struct TestKindStore(Mutex<Vec<StoreItemRef>>);

    impl SecretStore for TestKindStore {
        fn kind(&self) -> SecretStoreKind {
            SecretStoreKind::Test("unit_test")
        }
        fn availability(&self) -> StoreAvailability {
            StoreAvailability::Available
        }
        fn put(&self, fp: &CaFingerprint, _key: &SecretCaKey) -> Result<StoreItemRef, StoreError> {
            let item = StoreItemRef {
                kind: self.kind(),
                fingerprint: fp.clone(),
                locator: format!("unit/{}", fp.as_str()),
            };
            self.0.lock().unwrap().push(item.clone());
            Ok(item)
        }
        fn get(&self, _fp: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
            Err(StoreError::NotFound)
        }
        fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
            let mut items = self.0.lock().unwrap();
            let before = items.len();
            items.retain(|i| i != item);
            if items.len() == before {
                Err(StoreError::NotFound)
            } else {
                Ok(())
            }
        }
        fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }
    /// ⟨ADR-0008 §17.25 item 7 (d)⟩ In a debug build a test-configuration store's item is
    /// deleted by its exact recorded locator (whatever stand-in product kind the record
    /// names), and only that item; a locator holding another CA and an empty locator are
    /// refused with nothing deleted. A release build refuses the test kind outright.
    #[test]
    fn test_store_item_deleted_by_exact_locator_in_debug_builds_only() {
        let store = TestKindStore::default();
        let (k1, k2) = (
            SecretCaKey::generate().unwrap(),
            SecretCaKey::generate().unwrap(),
        );
        let (f1, f2) = (k1.fingerprint().unwrap(), k2.fingerprint().unwrap());
        let i1 = store.put(&f1, &k1).unwrap();
        let i2 = store.put(&f2, &k2).unwrap();
        assert!(matches!(store.kind(), SecretStoreKind::Test(_)));
        let kind = StoreKind::LinuxSecretService;
        // Another CA's locator, and an empty one: refused, nothing deleted.
        assert_eq!(
            delete_awaiting(&store, &f1, kind, &i2.locator),
            Err(RetireError::LocatorMismatch)
        );
        assert_eq!(
            delete_awaiting(&store, &f1, kind, ""),
            Err(RetireError::LocatorMismatch)
        );
        assert_eq!(store.list().unwrap().len(), 2);
        let got = delete_awaiting(&store, &f1, kind, &i1.locator);
        if cfg!(debug_assertions) {
            const { assert!(TEST_STORE_DELETION) };
            assert_eq!(got, Ok(()));
            assert_eq!(store.list().unwrap(), vec![i2.clone()], "only i1 went");
            // Again: an absent item counts as deleted.
            assert_eq!(delete_awaiting(&store, &f1, kind, &i1.locator), Ok(()));
        } else {
            assert_eq!(got, Err(RetireError::LocatorMismatch));
            assert_eq!(store.list().unwrap().len(), 2);
        }
    }
}
