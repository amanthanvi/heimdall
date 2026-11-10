//! The Git item under Git's lock (m02-plan U4; ADR-0007 §5.6; M2-S03, M2-T01).
//!
//! The Git item's steps are P_git, the `git_lock` step and B_git, in that order. K,
//! the lock holder, is created at its random staged name and receipted
//! (`file.staged`), then [`claim_lock`] renames it onto `<file>.lock` with no-replace.
//! B_git is an ordinary replace or create step under the lock. K is released last, by
//! `settle` from the lock name with `Expected { identity: K, sha256: holder digest }`.
//! An entry at the lock name counts as Heimdall's only by K's identity (rows K0–K4).

use std::path::Path;

use heimdall_domain::projection::{Base, Rendered, Sha256Hex, lock_holder_line};

use super::replace::{self, DirHandle, Quarantine, ReplaceRefusal, Staged, rename_noreplace};
use crate::env::{Env, Platform};
use crate::local_query::{LOCAL_QUERY_OUTPUT_BYTES, LOCAL_QUERY_TIMEOUT, Spec, run_contained};

/// What [`check_global_file`] established about the file B_git would be written into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalFileCheck {
    /// The writer's step-1 and step-2 checks accept the directory and the file (or the
    /// file or its directory is absent, and the writer creates it owner-only).
    Manageable,
    /// The directory or the file fails a step-1 or step-2 check (ADR-0007 §5.3 item 9):
    /// a symlink, a foreign owner, a group or other write bit on the directory or the
    /// file, a hard link, or a quarantine that does not validate.
    Unmanageable,
    /// The file is not the one the caller read (it changed, or appeared or vanished,
    /// while it was checked).
    Changed,
}

/// ADR-0007 §5.3 item 9 and §5.6 for the Git item: whether the writer will accept
/// `path`, the global Git file B_git is inserted into, and its directory. The writer
/// refuses a directory that is not owned by the user or that group or others can
/// write to, and a file that is a link, is owned by another user, has a second hard
/// link, or has a group or other write bit (§5.3 steps 1 and 2); it then refuses the
/// whole operation before the first commit point (§5.4 step 3), the SSH item with it.
/// So a preview that offered the Git item over such a file would be approved and
/// then refused. This is the same check the SSH user file gets at preview
/// (`unmanageable_file`), run through the writer's own `DirHandle` and `validate`, so
/// the two cannot drift. `bytes` is what the caller read from `path` (`None`: absent).
/// Nothing is written and no quarantine is created.
///
/// Why this exists (M02 wave 5c, ADR-0007 §12.32 item 13): the devbox's session umask
/// is 0002, so a `~/.config/git` made by the owner's own `mkdir -p` is group-writable
/// there, and the preview offered a Git item that the apply then refused as
/// `unmanageable_file` for both items. The Git version was not involved.
#[must_use]
pub fn check_global_file(path: &Path, bytes: Option<&[u8]>) -> GlobalFileCheck {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return GlobalFileCheck::Unmanageable;
    };
    // A missing directory is created owner-only by the writer (a step that creates its
    // file), exactly as the SSH check treats it.
    match std::fs::symlink_metadata(parent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return GlobalFileCheck::Manageable,
        _ => {}
    }
    let Ok(dir) = DirHandle::open(parent) else {
        return GlobalFileCheck::Unmanageable;
    };
    // The directory still is the one validated, and an existing quarantine must
    // validate; a preview never creates one (ADR-0007 §12.51 item 4).
    if Quarantine::validate_existing(&dir).is_err() {
        return GlobalFileCheck::Unmanageable;
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if bytes.is_none() {
                GlobalFileCheck::Manageable
            } else {
                GlobalFileCheck::Changed
            };
        }
        Err(_) => return GlobalFileCheck::Unmanageable,
        Ok(m) if m.file_type().is_symlink() || !m.is_file() => {
            return GlobalFileCheck::Unmanageable;
        }
        Ok(_) => {}
    }
    let Some(bytes) = bytes else {
        return GlobalFileCheck::Changed;
    };
    let base = Base::Present {
        sha256: Sha256Hex::of(bytes),
    };
    match replace::validate(&dir, name, &base) {
        Ok(_) => GlobalFileCheck::Manageable,
        Err(ReplaceRefusal::BaseChanged) => GlobalFileCheck::Changed,
        Err(_) => GlobalFileCheck::Unmanageable,
    }
}

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
