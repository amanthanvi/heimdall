//! ⟨M05⟩ U6: managed-slot handover between bindings, the runtime step (ADR-0011 §5.2 as
//! ruled in §10 item 6; m05-plan U6). Owner: the M05 track.
//!
//! A slot shared by reference keeps one materializer. When it ends (release, its
//! grant's expiry, revocation, cutoff or withdrawal, or restart recovery finding its
//! grant ended), M03's path moves the slot `held(m, g) → clearing(g)`, and the
//! runtime's end cleanup (`managed_store::StoreCleanup`) unlists `m`'s key at `g`,
//! removes the files of `g` (fenced by their marker) and clears the mux path. Where that
//! cleanup frees the slot, [`finish_clearing`] runs instead: one store transaction
//! (`heimdall_app::operations::slot_files_removed_or_hand_over_in`) drops the
//! referencers that can no longer carry the slot and passes it to the usable one with
//! the latest deadline at generation `g + 1`; then the slot is re-materialized **from
//! that referencer's own grant** (its own key and certificate) through the existing slot
//! write (`ManagedEffectsImpl::materialize_slot`): the store CAS is re-read under the
//! slot's lock, the files are written fenced by their generation marker, and only then
//! does the environment endpoint list the key. So the slot's certificate (principals and
//! `valid_before`) always comes from its current materializer's grant only, and a
//! cleanup of generation `g` (a stale pass included) never removes `g + 1`'s files or
//! listing. With no usable referencer the slot is `free(g)`.
//!
//! A re-materialization that fails (the new holder's key is not in this process, as
//! after a restart; or its grant ended meanwhile) leaves the slot held with no files: the
//! alias fails closed until the holder's re-issue or its next launch bind writes it (both
//! write a held slot at its store generation), or until its own end clears it.

use std::sync::Arc;

use heimdall_adapters::managed::effects::ManagedEffectsImpl;
use heimdall_app::ports::AdapterError;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::EnvironmentId;
use heimdall_domain::scope::AccessPair;
use heimdall_store::Store;

/// Free the clearing slot of `pair` in `environment` at `generation` (its files are
/// removed), or hand it over to the latest-deadline usable referencer and re-materialize
/// it from that referencer's own grant (module docs). A slot not `clearing` at
/// `generation` is left as it is (a stale cleanup): the store refuses it.
///
/// # Errors
/// [`AdapterError::Unavailable`] when the store transaction failed (the `clearing` row
/// stays the obligation; the next pass retries). A failed re-materialization is not an
/// error of the cleanup (module docs).
pub fn finish_clearing(
    store: &Arc<Store>,
    effects: &ManagedEffectsImpl,
    environment: &EnvironmentId,
    pair: &AccessPair,
    generation: u64,
    at: Timestamp,
) -> Result<(), AdapterError> {
    let handover = store
        .transaction(|tx| {
            heimdall_app::operations::slot_files_removed_or_hand_over_in(
                tx,
                environment,
                pair,
                generation,
                at,
            )
        })
        .map_err(|_| AdapterError::Unavailable("store".to_owned()))?;
    if let Ok(Some(h)) = handover
        && effects
            .materialize_slot(&h.to, &h.pair, h.generation)
            .is_err()
    {
        tracing::warn!(
            generation = h.generation,
            "a handed-over managed slot could not be re-materialized; its alias fails closed until the holder's re-issue or next bind"
        );
    }
    Ok(())
}
