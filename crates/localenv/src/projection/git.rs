//! The Git item under Git's lock (m02-plan U4; ADR-0007 §5.6; M2-S03, M2-T01).
//!
//! The Git item's steps are P_git, the `git_lock` step and B_git, in that order. K,
//! the lock holder, is created at its random staged name and receipted
//! (`file.staged`), then [`claim_lock`] renames it onto `<file>.lock` with no-replace.
//! B_git is an ordinary replace or create step under the lock. K is released last, by
//! `settle` from the lock name with `Expected { identity: K, sha256: holder digest }`.
//! An entry at the lock name counts as Heimdall's only by K's identity (rows K0–K4).

use heimdall_domain::projection::{Rendered, lock_holder_line};

use super::replace::{DirHandle, Staged};

/// The lock is held: by Git, another writer, or an entry that is not provably K.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockRefusal {
    /// The lock name exists (`git_config_locked`).
    #[error("git configuration lock held")]
    Held,
}

/// K now holds Git's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    /// The lock name.
    pub lock_name: String,
}

/// Claim Git's lock with K by a no-replace rename. Called only after the `git_lock`
/// step's `file.staged` is durable; never with B_git's S.
///
/// # Errors
/// [`LockRefusal::Held`].
pub fn claim_lock(
    dir: &DirHandle,
    holder: &Staged,
    lock_name: &str,
) -> Result<Claimed, LockRefusal> {
    let _ = (dir, holder, lock_name);
    todo!("M02-U4 projection::git::claim_lock")
}

/// K's one line: `heimdall setup lock, generation <N>, <32 lowercase hex>`. The nonce
/// is fixed at admission and is not part of `plan_digest`. Complete: it only renders
/// the domain's line.
#[must_use]
pub fn lock_holder(generation: u64, nonce: [u8; 16]) -> Rendered {
    Rendered::from_renderer(lock_holder_line(generation, nonce))
}
