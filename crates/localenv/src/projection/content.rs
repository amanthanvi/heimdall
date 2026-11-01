//! The materializer: the only source of the bytes `replace::stage` writes (m02-plan
//! U4; ADR-0007 §5.7 "The materializer checks both digests itself"; M2-S05, M2-T02).
//!
//! **Frozen in wave 0** (m02-plan U0): the signature of [`materialize`] and the
//! [`ContentError`] variants.
//!
//! It takes the whole [`FileStep`] and the base bytes `replace::validate` returned in
//! the same run (`None` when the base is absent) and checks, before anything is
//! written:
//! * **base:** `Base::Present { sha256 }` needs `Some(bytes)` with that digest
//!   ([`ContentError::BaseMismatch`], mapped to `CONFIG_CONFLICT`
//!   `user_config_changed`/`managed_file_edited`; [`ContentError::BaseMissing`] when
//!   `None`). `Base::Absent` needs `None` ([`ContentError::BaseUnexpected`]) and the
//!   splice input is then the empty slice;
//! * **splice:** `usize::try_from` on `offset` and `remove_len`, a checked
//!   `offset + remove_len`, `end <= input.len()`, `removed_sha256` present exactly
//!   when `remove_len > 0` and equal to the removed range's digest. Over an absent
//!   base only `offset == 0`, `remove_len == 0` and a non-empty insert pass. The
//!   output length is a checked sum within the bounds;
//! * **whole:** the bytes as they are; the base is still checked when present;
//! * **lock holder:** only for the `git_lock` step, with an absent base and the exact
//!   one-line form;
//! * **target:** `Target::Present { sha256 }` equals the output's digest;
//!   `Target::Absent` with any variant but the lock holder is a shape mismatch.
//!
//! Every error except `BaseMismatch` becomes `ReconcileError::IntentInvalid` before
//! any write (`BaseMissing` included: missing bytes for a present base are a caller
//! error, never a user edit; wave-0 verifier E12, U4's reading).

use heimdall_domain::projection::{FileStep, Sha256Hex};

/// The bytes to stage, with their digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialized {
    /// The full target bytes.
    pub bytes: Vec<u8>,
    /// Their SHA-256.
    pub sha256: Sha256Hex,
}

/// Why a step's bytes cannot be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ContentError {
    /// The validated base's digest is not `base.sha256` (`CONFIG_CONFLICT`).
    #[error("base digest mismatch")]
    BaseMismatch,
    /// A present base but no base bytes were given.
    #[error("base bytes missing")]
    BaseMissing,
    /// Base bytes were given for an absent base.
    #[error("base bytes given for an absent base")]
    BaseUnexpected,
    /// `offset`, `remove_len` or their sum does not fit.
    #[error("splice range overflows")]
    RangeOverflow,
    /// The splice range ends past the input.
    #[error("splice range out of bounds")]
    RangeOutOfBounds,
    /// `remove_len > 0` without `removed_sha256`.
    #[error("removed digest missing")]
    RemovedDigestMissing,
    /// `removed_sha256` with `remove_len == 0`.
    #[error("removed digest unexpected")]
    RemovedDigestUnexpected,
    /// The removed range's digest is not `removed_sha256`.
    #[error("removed digest mismatch")]
    RemovedDigestMismatch,
    /// A splice over an absent base that is not insert-only.
    #[error("splice over an absent base is not insert-only")]
    NotInsertOnly,
    /// A splice over an absent base with an empty insert.
    #[error("empty insert over an absent base")]
    EmptyInsert,
    /// The output exceeds the role's bound.
    #[error("output exceeds its bound")]
    TooLarge,
    /// The content variant does not fit the step's role or target.
    #[error("content does not fit the step's shape")]
    ShapeMismatch,
    /// The output's digest is not `target.sha256`.
    #[error("target digest mismatch")]
    TargetMismatch,
}

/// Produce the bytes of `step` over `base`.
///
/// # Errors
/// [`ContentError`].
pub fn materialize(step: &FileStep, base: Option<&[u8]>) -> Result<Materialized, ContentError> {
    let _ = (step, base);
    todo!("M02-U4 projection::content::materialize")
}
