//! The Git item under Git's lock (m02-plan U4; ADR-0007 §5.6; M2-S03, M2-T01).
//!
//! The Git item's steps are P_git, the `git_lock` step and B_git, in that order. K,
//! the lock holder, is created at its random staged name and receipted
//! (`file.staged`), then [`claim_lock`] renames it onto `<file>.lock` with no-replace.
//! B_git is an ordinary replace or create step under the lock. K is released last, by
//! `settle` from the lock name with `Expected { identity: K, sha256: holder digest }`.
//! An entry at the lock name counts as Heimdall's only by K's identity (rows K0–K4).

use std::path::Path;

use heimdall_domain::projection::{Rendered, lock_holder_line};

use super::replace::{DirHandle, Staged, rename_noreplace};
use crate::env::{Env, Platform};
use crate::local_query::{LOCAL_QUERY_OUTPUT_BYTES, LOCAL_QUERY_TIMEOUT, Spec, run_contained};

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
/// The rename is `replace::rename_noreplace` inside the validated directory (Linux
/// `RENAME_NOREPLACE`, macOS `RENAME_EXCL`, Windows `MoveFileExW` without
/// `MOVEFILE_REPLACE_EXISTING`): the lock name appears atomically, and only if it was
/// absent, exactly as Git's own exclusive create (F22). Any failure (an entry at the
/// lock name, K gone from its staged name, an I/O error) is a refusal: nothing was
/// moved, and the caller settles K from its staged name. Ownership of whatever ends up
/// at the lock name is decided by K's recorded identity at every later observation,
/// never here.
///
/// # Errors
/// [`LockRefusal::Held`].
pub fn claim_lock(
    dir: &DirHandle,
    holder: &Staged,
    lock_name: &str,
) -> Result<Claimed, LockRefusal> {
    if lock_name == holder.name {
        return Err(LockRefusal::Held);
    }
    rename_noreplace(dir, &holder.name, lock_name).map_err(|_| LockRefusal::Held)?;
    Ok(Claimed {
        lock_name: lock_name.to_owned(),
    })
}

/// K's one line: `heimdall setup lock, generation <N>, <32 lowercase hex>`. The nonce
/// is fixed at admission and is not part of `plan_digest`. Complete: it only renders
/// the domain's line.
#[must_use]
pub fn lock_holder(generation: u64, nonce: [u8; 16]) -> Rendered {
    Rendered::from_renderer(lock_holder_line(generation, nonce))
}

/// ADR-0007 §5.6 step 3: whether B_git's staged bytes parse as Git configuration,
/// `git config --file <staged> --no-includes --list`, a local query (bounded at 2 s,
/// no shell, stdin null, the environment snapshot `env` only, the filesystem root as
/// working directory, so no repository's configuration is read). Only exit 0 within
/// the bound is a pass: a failure, a timeout or a tool that cannot start is `false`
/// (fail closed), and the caller aborts before the commit point. The output is
/// discarded unread; it is the user's configuration.
#[must_use]
pub fn parses(git: &Path, staged: &Path, env: &Env) -> bool {
    parse_check(git, staged, env) == ParseCheck::Parses
}

/// Additive (W2c-U4; ADR-0007 §12.19 item 8): what [`parse_check`] established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseCheck {
    /// The query exited 0 within its bound.
    Parses,
    /// The query ran and did not: a non-zero exit, a signal or a timeout.
    Refused,
    /// The query could not run: the program could not be started, or its run could
    /// not be contained or observed.
    CannotRun,
}

/// Additive (W2c-U4): [`parses`], telling a check that could not run
/// ([`ParseCheck::CannotRun`]: the caller's reason is `verified_client_unavailable`,
/// ADR-0007 §12.19 item 8) from one that ran and refused the bytes. Either way the
/// bytes are not shown to parse.
#[must_use]
pub fn parse_check(git: &Path, staged: &Path, env: &Env) -> ParseCheck {
    let root = if Platform::current().is_windows() {
        std::env::var_os("SystemDrive").map_or_else(
            || std::path::PathBuf::from(r"C:\"),
            |d| std::path::PathBuf::from(format!("{}\\", d.to_string_lossy())),
        )
    } else {
        std::path::PathBuf::from("/")
    };
    let Ok(out) = run_contained(&Spec {
        program: git,
        args: vec![
            "config".into(),
            "--file".into(),
            staged.as_os_str().to_owned(),
            "--no-includes".into(),
            "--list".into(),
        ],
        env: Some(env),
        cwd: Some(&root),
        timeout: LOCAL_QUERY_TIMEOUT,
        max_output: LOCAL_QUERY_OUTPUT_BYTES,
    }) else {
        return ParseCheck::CannotRun;
    };
    if !out.timed_out && out.status.is_some_and(|s| s.success()) {
        ParseCheck::Parses
    } else {
        ParseCheck::Refused
    }
}
