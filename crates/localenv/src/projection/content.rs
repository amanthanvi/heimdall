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

use heimdall_domain::projection::{
    Base, FileRole, FileStep, Sha256Hex, StepContentView, Target, bounds, is_lock_holder_line,
};

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

/// The most bytes any step reads or writes: the base read of `replace::validate`, every
/// content check of post-validation, restore and settlement, and a splice's output
/// (ADR-0007 §5.3 steps 2 and 8: "≤ 1 MiB"). A splice whose output is longer could
/// never be read back as S, so it is refused here ([`ContentError::TooLarge`]).
pub const READ_MAX: usize = 1 << 20;

/// Produce the bytes of `step` over `base`.
///
/// The checks run in a fixed order, so every input has exactly one answer:
/// 1. the variant against the role and target ([`ContentError::ShapeMismatch`]);
/// 2. the base ([`ContentError::BaseMismatch`], [`ContentError::BaseMissing`],
///    [`ContentError::BaseUnexpected`]);
/// 3. for a splice over an absent base, insert-only ([`ContentError::NotInsertOnly`],
///    [`ContentError::EmptyInsert`]);
/// 4. for a splice, the range with checked arithmetic ([`ContentError::RangeOverflow`],
///    [`ContentError::RangeOutOfBounds`]), then the removed digest
///    ([`ContentError::RemovedDigestMissing`], [`ContentError::RemovedDigestUnexpected`],
///    [`ContentError::RemovedDigestMismatch`]);
/// 5. the bounds ([`ContentError::TooLarge`]);
/// 6. the target digest ([`ContentError::TargetMismatch`]); the `git_lock` step has
///    no target digest and is checked against the exact holder-line form instead.
///
/// Pure: no I/O. Nothing is written by anyone until this returns `Ok`.
///
/// # Errors
/// [`ContentError`].
pub fn materialize(step: &FileStep, base: Option<&[u8]>) -> Result<Materialized, ContentError> {
    let view = step.content.view();
    check_shape(step, &view)?;
    let input = checked_base(&step.base, base)?;
    let bytes = match view {
        StepContentView::Whole { bytes } => {
            if bytes.len() > whole_max(step.role) {
                return Err(ContentError::TooLarge);
            }
            bytes.to_vec()
        }
        StepContentView::Splice {
            offset,
            remove_len,
            removed_sha256,
            insert,
        } => splice(
            input,
            step.base == Base::Absent,
            offset,
            remove_len,
            removed_sha256,
            insert,
        )?,
        StepContentView::LockHolder { bytes } => {
            if bytes.len() > bounds::LOCK_HOLDER_MAX {
                return Err(ContentError::TooLarge);
            }
            if !is_holder_line(bytes) {
                return Err(ContentError::ShapeMismatch);
            }
            bytes.to_vec()
        }
        // `check_shape` refused it: a target-absent step has nothing to materialize.
        StepContentView::Absent => return Err(ContentError::ShapeMismatch),
    };
    let sha256 = Sha256Hex::of(&bytes);
    match &step.target {
        Target::Present { sha256: target } if *target != sha256 => {
            Err(ContentError::TargetMismatch)
        }
        _ => Ok(Materialized { bytes, sha256 }),
    }
}

/// The variant must fit the role and the target (m02-plan U4 "lock holder",
/// "target"): a whole target for P, P_git and key files; a splice for the user file
/// and the global Git file; the holder line only for the `git_lock` step, whose base
/// and target are both absent; `absent` never materializes.
fn check_shape(step: &FileStep, view: &StepContentView<'_>) -> Result<(), ContentError> {
    let target_present = matches!(step.target, Target::Present { .. });
    let fits = match view {
        StepContentView::Whole { .. } => {
            target_present
                && matches!(
                    step.role,
                    FileRole::ManagedSsh | FileRole::Key | FileRole::GitManaged
                )
        }
        StepContentView::Splice { .. } => {
            target_present && matches!(step.role, FileRole::UserSsh | FileRole::GitInclude)
        }
        StepContentView::LockHolder { .. } => {
            step.role == FileRole::GitLock
                && step.base == Base::Absent
                && step.target == Target::Absent
        }
        StepContentView::Absent => false,
    };
    if fits {
        Ok(())
    } else {
        Err(ContentError::ShapeMismatch)
    }
}

/// The splice input: the validated base bytes, or the empty slice for an absent base.
fn checked_base<'a>(base: &Base, bytes: Option<&'a [u8]>) -> Result<&'a [u8], ContentError> {
    match (base, bytes) {
        (Base::Present { sha256 }, Some(b)) => {
            if Sha256Hex::of(b) == *sha256 {
                Ok(b)
            } else {
                Err(ContentError::BaseMismatch)
            }
        }
        (Base::Present { .. }, None) => Err(ContentError::BaseMissing),
        (Base::Absent, None) => Ok(&[]),
        (Base::Absent, Some(_)) => Err(ContentError::BaseUnexpected),
    }
}

fn whole_max(role: FileRole) -> usize {
    match role {
        FileRole::ManagedSsh => bounds::MANAGED_SSH_MAX,
        FileRole::Key => bounds::KEY_FILE_MAX,
        FileRole::GitManaged => bounds::GIT_MANAGED_MAX,
        // `check_shape` admits a whole target only for the three roles above.
        FileRole::UserSsh | FileRole::GitInclude | FileRole::GitLock => 0,
    }
}

/// Apply a splice with checked arithmetic only: `usize::try_from`, `checked_add`,
/// `checked_sub`; no index can be out of range once the checks pass.
fn splice(
    input: &[u8],
    base_absent: bool,
    offset: u64,
    remove_len: u64,
    removed_sha256: Option<&Sha256Hex>,
    insert: &[u8],
) -> Result<Vec<u8>, ContentError> {
    if base_absent {
        // An absent base is an empty input that admits only an insert at offset 0
        // that removes nothing (ADR-0007 §5.7 "Bound to the digests").
        if offset != 0 || remove_len != 0 || removed_sha256.is_some() {
            return Err(ContentError::NotInsertOnly);
        }
        if insert.is_empty() {
            return Err(ContentError::EmptyInsert);
        }
    }
    let start = usize::try_from(offset).map_err(|_| ContentError::RangeOverflow)?;
    let len = usize::try_from(remove_len).map_err(|_| ContentError::RangeOverflow)?;
    let end = start.checked_add(len).ok_or(ContentError::RangeOverflow)?;
    if end > input.len() {
        return Err(ContentError::RangeOutOfBounds);
    }
    let removed = input
        .get(start..end)
        .ok_or(ContentError::RangeOutOfBounds)?;
    match (len > 0, removed_sha256) {
        (true, None) => return Err(ContentError::RemovedDigestMissing),
        (false, Some(_)) => return Err(ContentError::RemovedDigestUnexpected),
        (true, Some(expected)) if Sha256Hex::of(removed) != *expected => {
            return Err(ContentError::RemovedDigestMismatch);
        }
        _ => {}
    }
    if insert.len() > bounds::INSERT_MAX {
        return Err(ContentError::TooLarge);
    }
    let out_len = input
        .len()
        .checked_sub(len)
        .and_then(|kept| kept.checked_add(insert.len()))
        .ok_or(ContentError::TooLarge)?;
    if out_len > READ_MAX {
        return Err(ContentError::TooLarge);
    }
    let head = input.get(..start).ok_or(ContentError::RangeOutOfBounds)?;
    let tail = input.get(end..).ok_or(ContentError::RangeOutOfBounds)?;
    let mut out = Vec::with_capacity(out_len);
    out.extend_from_slice(head);
    out.extend_from_slice(insert);
    out.extend_from_slice(tail);
    Ok(out)
}

/// The exact holder-line form for some generation (ADR-0007 §5.7 "The `git_lock`
/// step"). `FileStep` does not carry the generation, so it is read from the line
/// itself; `SetupIntent::validate` has already bound it to the intent's generation.
fn is_holder_line(bytes: &[u8]) -> bool {
    const PREFIX: &[u8] = b"heimdall setup lock, generation ";
    let Some(rest) = bytes.strip_prefix(PREFIX) else {
        return false;
    };
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let Some(n) = rest
        .get(..digits)
        .and_then(|d| std::str::from_utf8(d).ok())
        .and_then(|d| d.parse::<u64>().ok())
    else {
        return false;
    };
    is_lock_holder_line(bytes, n)
}

// --- ⟨M03⟩ managed slot paths (ADR-0008 D10 items 1-2, D8 item 3; reading R7) -----------

/// A managed pair slot's public files (ADR-0008 D10 item 2): written atomically by
/// generation (U6's `ManagedEffects::materialize`), absent while the slot is free.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlotPaths {
    /// `<data_dir>/managed/<destination-id>`.
    pub dir: std::path::PathBuf,
    /// `<dir>/key.pub`: the holder's K_env public key.
    pub key_pub: std::path::PathBuf,
    /// `<dir>/cert.pub`: the holder's certificate for this pair.
    pub cert_pub: std::path::PathBuf,
}

/// A destination ID that cannot name a slot's directory (U8-Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the destination ID cannot name a managed slot directory")]
pub struct SlotPathRefused;

/// The Windows device names a path component must never be (with or without an
/// extension), on every platform, so a slot directory means the same everywhere.
const DEVICE_NAMES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// The destination ID as one path component of a slot path (U8-Q3, fail closed). The
/// contract's token rule allows `.`, `:` and upper case, which a path cannot take as is:
/// `.` and `..` traverse, `:` names an NTFS stream, a trailing `.` is dropped by Win32,
/// a device name is not a file, and two IDs that differ only in case share one directory
/// on a case-insensitive file system (APFS and NTFS by default). So the component must
/// be lower case `[a-z0-9._-]`, start with `[a-z0-9_-]`, not end with `.`, and not be a
/// device name; anything else is refused, never rewritten.
///
/// # Errors
/// [`SlotPathRefused`].
pub fn slot_component(
    destination: &heimdall_contract::ids::DestinationId,
) -> Result<&str, SlotPathRefused> {
    let id = destination.as_str();
    let b = id.as_bytes();
    let ok = !b.is_empty()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
        && b[0] != b'.'
        && b[b.len() - 1] != b'.'
        && !DEVICE_NAMES.contains(&id.split('.').next().unwrap_or(id));
    if ok { Ok(id) } else { Err(SlotPathRefused) }
}

/// **The one function for a slot's file paths** (reading R7): `<data_dir>/managed/
/// <destination-id>/key.pub` and `cert.pub`. P renders them (m03-plan U8) and U6's
/// `ManagedEffects::materialize` writes them, from this function alone.
///
/// `data_dir` is the caller's: M01's `Paths` has no `data_dir`, and which directory it
/// is stays with the integrator (U8-Q2; provisional reading: `Paths.state_dir`).
///
/// # Errors
/// [`SlotPathRefused`]: the destination ID is not a safe path component
/// ([`slot_component`]).
pub fn managed_slot_paths(
    data_dir: &std::path::Path,
    destination: &heimdall_contract::ids::DestinationId,
) -> Result<SlotPaths, SlotPathRefused> {
    let dir = data_dir.join("managed").join(slot_component(destination)?);
    Ok(SlotPaths {
        key_pub: dir.join("key.pub"),
        cert_pub: dir.join("cert.pub"),
        dir,
    })
}

/// The slot's **stable** multiplex path, `<runtime_dir>/mux/<destination-id>` (ADR-0008
/// D8 item 3): fixed for the slot's life, rendered in P once owned masters are enabled
/// and applied.
///
/// # Errors
/// [`SlotPathRefused`], as [`managed_slot_paths`].
pub fn managed_mux_path(
    runtime_dir: &std::path::Path,
    destination: &heimdall_contract::ids::DestinationId,
) -> Result<std::path::PathBuf, SlotPathRefused> {
    Ok(runtime_dir.join("mux").join(slot_component(destination)?))
}

/// The longest Unix socket path, in bytes without the terminating NUL (`sun_path` is
/// 104 bytes on macOS and 108 on Linux, NUL included; the M02 `SUN_LEN` lesson).
#[cfg(target_os = "macos")]
pub const SOCKET_PATH_MAX: usize = 103;
/// The longest Unix socket path, in bytes without the terminating NUL (`sun_path` is
/// 104 bytes on macOS and 108 on Linux, NUL included; the M02 `SUN_LEN` lesson).
#[cfg(not(target_os = "macos"))]
pub const SOCKET_PATH_MAX: usize = 107;

/// [`managed_mux_path`], refused with `mux_path_too_long` (ADR-0008 D8 item 3) when it
/// would not fit the platform's socket-path limit, so `owned_masters` is refused there.
///
/// # Errors
/// `heimdall_contract::envelope::reason::MUX_PATH_TOO_LONG`, or [`SlotPathRefused`]'s
/// text for an unsafe destination ID.
pub fn checked_mux_path(
    runtime_dir: &std::path::Path,
    destination: &heimdall_contract::ids::DestinationId,
) -> Result<std::path::PathBuf, &'static str> {
    let path = managed_mux_path(runtime_dir, destination).map_err(|_| "slot_path_refused")?;
    if path.as_os_str().as_encoded_bytes().len() > SOCKET_PATH_MAX {
        return Err(heimdall_contract::envelope::reason::MUX_PATH_TOO_LONG);
    }
    Ok(path)
}
