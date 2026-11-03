//! The cleaner for projection resources (m02-plan U4; ADR-0007 §5.8, rows R1–R6).
//!
//! It deletes only when the generation matches **and** the entry has the identity and
//! digest in the `ProjectionLocator`, through the quarantine at the slot derived from
//! the locator (so a retry finds an entry moved before a crash), re-checking the
//! digest in the slot before removal. Otherwise it returns `Ok` with nothing deleted.
//!
//! The generation guard itself is the executor's (`reconcile::guard_cleanup`, run
//! right before the call); the cleaner binds the deletion to the resource's
//! generation through the slot name and to the file through the locator's identity
//! and digest. Rows:
//!
//! | Row | Path | Slot | Action |
//! |---|---|---|---|
//! | R2 / R2a | any | L / L′ | remove after the re-check; an L′ stays (`Ok`) |
//! | R5 | ∅, X | X | left in the quarantine, reported (`Ok`) |
//! | R6 | L, L′ | X | nothing moved, not confirmed absent (`Err`, retried) |
//! | R1 | L | ∅ | move into the slot, check, remove |
//! | R1a | L′ | ∅ | left at the path (`Ok`, `projection_edited`) |
//! | R3 | ∅ | ∅ | absent (`Ok`) |
//! | R4 | X | ∅ | left alone (`Ok`) |
//!
//! A swap between the pre-check and the move is caught by the primitive's identity
//! check in the slot: the foreign entry is put back or kept, never deleted.

use std::path::Path;

use async_trait::async_trait;
use heimdall_app::ports::{AdapterError, ResourceCleaner};
use heimdall_domain::projection::{ContentState, ProjectionLocator};
use heimdall_domain::resource::ManagedResource;
use sha2::{Digest as _, Sha256};

use super::replace::{
    self, DirHandle, Expected, HookAt, NameState, Quarantine, SettleOutcome, check_name,
};
use super::{CLEANER_STEP, ProjectionConfig, ReplacePoint};

/// The `ResourceCleaner` for `config_projection` resources.
#[derive(Debug, Clone)]
pub struct ProjectionCleaner {
    config: ProjectionConfig,
}

impl ProjectionCleaner {
    /// A cleaner over `config`.
    #[must_use]
    pub fn new(config: ProjectionConfig) -> Self {
        Self { config }
    }
}

/// The deterministic quarantine slot of a locator at a generation (ADR-0007 §5.8):
/// `<role>-<generation>-<first 16 hex of the SHA-256 of the canonical locator>`.
///
/// # Errors
/// [`AdapterError::Protocol`] when the locator cannot be canonicalized.
pub fn slot_name(locator: &ProjectionLocator, generation: u64) -> Result<String, AdapterError> {
    let canonical = locator
        .canonical()
        .map_err(|_| AdapterError::Protocol("projection locator not canonical".to_owned()))?;
    let digest = Sha256::digest(canonical.as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{}-{generation}-{hex}", locator.role.as_str()))
}

#[async_trait]
impl ResourceCleaner for ProjectionCleaner {
    async fn delete(&self, resource: &ManagedResource) -> Result<(), AdapterError> {
        let locator: ProjectionLocator = serde_json::from_str(&resource.locator)
            .map_err(|_| AdapterError::Protocol("unreadable projection locator".to_owned()))?;
        delete_locator(&self.config, &locator, resource.generation.0)
    }
}

/// Remove the file `locator` names at `generation`, by the rows above. Synchronous
/// file work; the async port wraps it.
///
/// # Errors
/// [`AdapterError`]: `Unavailable` when the directory or quarantine cannot be used, an
/// observation failed, or a foreign entry occupies the slot while the resource is
/// still present (R6), so the executor retries on its back-off; `Protocol` for an
/// unusable locator.
pub fn delete_locator(
    config: &ProjectionConfig,
    locator: &ProjectionLocator,
    generation: u64,
) -> Result<(), AdapterError> {
    let path = Path::new(&locator.path);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return Err(AdapterError::Protocol("projection locator path".to_owned()));
    };
    if matches!(std::fs::symlink_metadata(parent), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        // R3: the directory, and so the file, is gone.
        return Ok(());
    }
    let unavailable = |e: &dyn std::fmt::Display| AdapterError::Unavailable(e.to_string());
    let dir = DirHandle::open_with(parent, config.test.identity).map_err(|e| unavailable(&e))?;
    let expected = Expected {
        identity: locator.identity.clone(),
        sha256: locator.sha256.clone(),
    };
    let slot = slot_name(locator, generation)?;
    let quarantine = Quarantine::open_or_create(&dir).map_err(|e| unavailable(&e))?;
    let hook = HookAt::new(config.hook.as_deref(), CLEANER_STEP);
    let at_path = check_name(&dir, name, &expected);
    let in_slot = quarantine.check_slot(&slot, &expected);
    let result = match (at_path, in_slot) {
        (NameState::Unobservable, _) | (_, NameState::Unobservable) => Err(
            AdapterError::Unavailable("projection file not observable".to_owned()),
        ),
        // R6: the resource is still at its path and a foreign entry is in the slot.
        (NameState::Expected(_), NameState::Foreign | NameState::Expected(_)) => Err(
            AdapterError::Unavailable("the cleanup slot is occupied".to_owned()),
        ),
        // R2: a crash after the move; re-check and remove.
        (NameState::Absent | NameState::Foreign, NameState::Expected(ContentState::Unchanged)) => {
            config.fire(ReplacePoint::BeforeQuarantineRemove, CLEANER_STEP);
            quarantine
                .remove_verified_with(&slot, &expected, hook)
                .map(|_| ())
                .map_err(|e| unavailable(&e))
        }
        // R2a: kept in the quarantine as a conflict artifact.
        (NameState::Absent | NameState::Foreign, NameState::Expected(ContentState::Modified)) => {
            Ok(())
        }
        // R5: a foreign entry in the slot goes back with no-replace, or is kept.
        (NameState::Absent | NameState::Foreign, NameState::Foreign) => quarantine
            .put_back(&dir, &slot, name)
            .map(|_| ())
            .map_err(|e| unavailable(&e)),
        // R3, R4: absent or foreign at the path; R1a: edited in place. Nothing removed.
        (NameState::Absent | NameState::Foreign, NameState::Absent)
        | (NameState::Expected(ContentState::Modified), NameState::Absent) => Ok(()),
        // R1: move into the slot, check identity and digest, remove.
        (NameState::Expected(ContentState::Unchanged), NameState::Absent) => {
            config.fire(ReplacePoint::BeforeSettleMove, CLEANER_STEP);
            match replace::settle_with(&dir, &quarantine, name, &expected, &slot, hook) {
                Ok(SettleOutcome::Settled) => {
                    config.fire(ReplacePoint::BeforeQuarantineRemove, CLEANER_STEP);
                    quarantine
                        .remove_verified_with(&slot, &expected, hook)
                        .map(|_| ())
                        .map_err(|e| unavailable(&e))
                }
                // Modified after the move (kept), vanished, or a swapped-in foreign entry
                // put back or kept: nothing of this generation remains at the path, and
                // nothing foreign was deleted.
                Ok(_) => Ok(()),
                Err(e) => Err(unavailable(&e)),
            }
        }
    };
    let _ = quarantine.rmdir_if_empty();
    result
}
