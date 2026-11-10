//! The runtime's pure classification of a reported remote step result (ADR-0008 D5
//! §6.3, §6.7; m03-plan §5 item 19 comment, U5 "Interfaces").
//!
//! The signature of [`classify_step`] and the class set are frozen in wave 0 (U0);
//! the body is U5's. **Fail closed:** a result is `Confirmed` or `AlreadyPresent`
//! only when the script's own output proves it ([`crate::hm1::parse`], the exit code
//! and, for `append` and `remove`, the post-write check of
//! [`crate::post_image`]). Anything else is `NotApplied` only where nothing can have
//! changed, and `Uncertain` for a mutating stage otherwise.
//!
//! **The handshake rules** (m03-plan U5):
//! * a run that never printed `HM1 ready` sent no script: `NotApplied` for every
//!   stage. A `ssh` failure (exit 255) there may name its remedy from the redacted
//!   stderr excerpt: `HostTrustChanged` ("Host key verification failed"),
//!   `ProviderLocked`, `InteractionRequired`; the excerpt never decides anything else;
//! * `HM1 ready` without `HM1 v=1`: `NotApplied(refused)` for `inspect` and `fence`;
//!   for `bootstrap`, `append` and `remove` `Uncertain` unless the remote shell
//!   completed (exit status 0–127, which a dropped connection, exit 255, or a killed
//!   client never reports), when it is `NotApplied(refused)` (`registry_unsupported`:
//!   the script's first statement never ran);
//! * after `HM1 v=1`, an output that does not parse, a status outside the stage's
//!   documented exit codes, or exit 255: `Uncertain` for a mutating stage and
//!   `NotApplied(refused)` for a read stage.
//!
//! [`Inspection`] is the typed reading of an `inspect` result and [`HolderRecord`] the
//! lock's holder record; both are used by [`crate::fence`] as well.

use heimdall_contract::enrollment::RemoteStage;

use crate::hm1::{self, ExitCode, Handshake, Hm1Key, Hm1Record};
use crate::line::marker_lines;
use crate::post_image::{check_post_append, check_post_remove};

/// Why a step was not applied (nothing changed on the remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NotAppliedReason {
    /// Exit 40: a lock exists.
    Busy,
    /// Exit 41: the remote not-after had passed.
    NotAfterPassed,
    /// Exit 42: the lock was lost before the write.
    LockLost,
    /// Exit 32: the registry's directory is absent.
    DirAbsent,
    /// Exit 33 from `bootstrap`: the parent is absent.
    ParentAbsent,
    /// Exit 33 from a locking script: the shell is not its own group leader.
    NoProcessGroup,
    /// Refused before any effect (exit 30, or no script sent).
    Refused,
    /// ⟨U5⟩ Exit 20 from `remove`: the registry changed since it was read; nothing was
    /// renamed, and the removal restarts from `inspect` (D5 §6.8 step 4).
    ChangedSinceRead,
    /// ⟨U5⟩ Exit 31: the registry is too large (`registry_too_large`).
    TooLarge,
}

/// The class of one step result (m03-plan U5 `classify_step`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StepClass {
    /// The effect happened and the post-write check passed.
    Confirmed,
    /// The effect was already present (exit 10 or 11).
    AlreadyPresent,
    /// Nothing changed.
    NotApplied(NotAppliedReason),
    /// The outcome is unknown: a later `inspect` and reconcile decide.
    Uncertain,
    /// Host trust failed (`HOST_TRUST_CHANGED`).
    HostTrustChanged,
    /// The existing-access provider is locked.
    ProviderLocked,
    /// The step needs the owner's interaction.
    InteractionRequired,
    /// The record goes to `held` (damaged line, concurrent change).
    Held,
}

/// A step result as the runtime received it (`Enrollment::StepResult`; ADR-0008 D5
/// §6.3 item 2). The bounds are enforced before classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    /// The client's exit status.
    pub exit_status: i32,
    /// At most 512 KiB of output (HM1 lines after the ready line).
    pub stdout: String,
    /// At most 4 KiB, redacted, diagnostics only.
    pub stderr_excerpt: String,
}

/// What the runtime expected of the step (the journal's facts at dispatch).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expected {
    /// The enrollment's marker (`heimdall:<enrollment-id>`).
    pub marker: String,
    /// The exact registry line (`append`, `remove`).
    pub line: Option<String>,
    /// The inspected preimage (`append`'s post-write check; `remove`'s compare).
    pub preimage: Option<Vec<u8>>,
    /// The expected post-image (`remove`).
    pub post_image: Option<Vec<u8>>,
}

// --- typed readings ------------------------------------------------------------------

/// The registry directory as `inspect` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DirState {
    /// Present.
    Present,
    /// Absent.
    Absent,
}

/// The registry file's kind as `inspect` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKind {
    /// A regular file.
    Regular,
    /// Absent.
    Absent,
    /// A symlink.
    Symlink,
    /// Anything else.
    Other,
}

/// A lock's holder record, `hm1-<token>-<pid>-<start hex>-<boot hex>-<not_after>`
/// (D5 §6.3 fencing item 1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HolderRecord {
    /// The holding step's token (32 lowercase hex).
    pub token: String,
    /// The holder shell's PID (its process group).
    pub pid: u32,
    /// The start identity, lowercase hex.
    pub start_hex: String,
    /// The boot identity, lowercase hex.
    pub boot_hex: String,
    /// The holder's remote not-after (epoch seconds).
    pub not_after: i64,
}

/// Whether `s` is a step token: 32 lowercase hex characters (128 bits).
#[must_use]
pub fn token_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex_ok(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && hm1::decode_hex(s).is_some()
}

fn decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl HolderRecord {
    /// Parse a holder record (the `ln -s` target).
    #[must_use]
    pub fn parse(text: &str) -> Option<HolderRecord> {
        let mut parts = text.split('-');
        let (Some("hm1"), Some(token), Some(pid), Some(start), Some(boot), Some(not_after), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        let pid: u32 = decimal(pid).filter(|p| *p >= 1)?;
        let not_after: i64 = decimal(not_after)?;
        (token_ok(token) && hex_ok(start) && hex_ok(boot)).then(|| HolderRecord {
            token: token.to_owned(),
            pid,
            start_hex: start.to_owned(),
            boot_hex: boot.to_owned(),
            not_after,
        })
    }

    /// The record's text.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "hm1-{}-{}-{}-{}-{}",
            self.token, self.pid, self.start_hex, self.boot_hex, self.not_after
        )
    }
}

/// The lock as `inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LockReading {
    /// No lock.
    None,
    /// A lock with its holder record.
    Held(HolderRecord),
    /// A lock whose record is not a holder record (`lock=held` without
    /// `lock_holder`): `busy` for every enrollment, never touched.
    HeldForeign,
}

/// Why an HM1 record is not a usable reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ReadingError {
    /// A required key is absent.
    #[error("the reading lacks {0}")]
    Missing(Hm1Key),
    /// A key that must appear once repeats.
    #[error("the reading repeats {0}")]
    Repeated(Hm1Key),
    /// A value is inconsistent (size against content, marker count, holder record).
    #[error("the reading's {0} is inconsistent")]
    Inconsistent(Hm1Key),
}

fn one(rec: &Hm1Record, key: Hm1Key) -> Result<Option<&str>, ReadingError> {
    rec.single(key).map_err(|_| ReadingError::Repeated(key))
}

fn need(rec: &Hm1Record, key: Hm1Key) -> Result<&str, ReadingError> {
    one(rec, key)?.ok_or(ReadingError::Missing(key))
}

fn flag(v: Option<&str>) -> Option<bool> {
    v.map(|v| v == "yes")
}

/// An `inspect` reading (D5 §6.3 script table; §6.4 E2 `enroll.inspect.observed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// The resolved registry path's bytes (`path_hex`).
    pub path: Vec<u8>,
    /// The directory.
    pub dir: DirState,
    /// The directory's `ls -ldn` mode string, when reported.
    pub dir_mode: Option<String>,
    /// The directory is owned by `id -u`, when reported.
    pub dir_owner_self: Option<bool>,
    /// The file's kind.
    pub file: FileKind,
    /// The file's link count, when reported.
    pub links: Option<u64>,
    /// The file's mode string, when reported.
    pub mode: Option<String>,
    /// The file is owned by `id -u`, when reported.
    pub owner_self: Option<bool>,
    /// The file's content (a regular file only; `size` and `content_hex` agree).
    pub content: Option<Vec<u8>>,
    /// The file's last byte is `0a`, when reported.
    pub last_byte_newline: Option<bool>,
    /// Lines containing the marker as the script counted them (0 for no file).
    pub marker_lines: u64,
    /// The lock.
    pub lock: LockReading,
    /// The remote clock reading (epoch seconds; M-F23).
    pub remote_now: i64,
}

impl Inspection {
    /// Read an `inspect` record. `marker`, when not empty, is re-counted over the
    /// content and must equal the script's `marker_lines`.
    ///
    /// Required: `path_hex`, `dir`, `file`, `lock`, `remote_now`; for a regular file
    /// also `size`, `content_hex` and `marker_lines`; for a held lock `lock_holder`.
    /// Every key at most once.
    ///
    /// # Errors
    /// [`ReadingError`].
    pub fn from_record(rec: &Hm1Record, marker: &str) -> Result<Inspection, ReadingError> {
        let path = hm1::decode_hex(need(rec, Hm1Key::PathHex)?)
            .ok_or(ReadingError::Inconsistent(Hm1Key::PathHex))?;
        let dir = match need(rec, Hm1Key::Dir)? {
            "present" => DirState::Present,
            _ => DirState::Absent,
        };
        let file = match need(rec, Hm1Key::File)? {
            "regular" => FileKind::Regular,
            "absent" => FileKind::Absent,
            "symlink" => FileKind::Symlink,
            _ => FileKind::Other,
        };
        let remote_now: i64 = decimal(need(rec, Hm1Key::RemoteNow)?)
            .ok_or(ReadingError::Inconsistent(Hm1Key::RemoteNow))?;
        let lock = match need(rec, Hm1Key::Lock)? {
            "held" => match one(rec, Hm1Key::LockHolder)? {
                Some(text) => LockReading::Held(
                    HolderRecord::parse(text)
                        .ok_or(ReadingError::Inconsistent(Hm1Key::LockHolder))?,
                ),
                None => LockReading::HeldForeign,
            },
            _ => {
                if one(rec, Hm1Key::LockHolder)?.is_some() {
                    return Err(ReadingError::Inconsistent(Hm1Key::LockHolder));
                }
                LockReading::None
            }
        };
        let reported_lines: Option<u64> = match one(rec, Hm1Key::MarkerLines)? {
            Some(v) => Some(decimal(v).ok_or(ReadingError::Inconsistent(Hm1Key::MarkerLines))?),
            None => None,
        };
        let content = if file == FileKind::Regular {
            let content = hm1::decode_hex(need(rec, Hm1Key::ContentHex)?)
                .ok_or(ReadingError::Inconsistent(Hm1Key::ContentHex))?;
            let size: u64 = decimal(need(rec, Hm1Key::Size)?)
                .ok_or(ReadingError::Inconsistent(Hm1Key::Size))?;
            if u64::try_from(content.len()).ok() != Some(size) {
                return Err(ReadingError::Inconsistent(Hm1Key::Size));
            }
            Some(content)
        } else {
            if one(rec, Hm1Key::ContentHex)?.is_some() {
                return Err(ReadingError::Inconsistent(Hm1Key::ContentHex));
            }
            None
        };
        let marker_count = match (&content, reported_lines) {
            (Some(c), Some(n)) => {
                if !marker.is_empty() && u64::try_from(marker_lines(c, marker)).ok() != Some(n) {
                    return Err(ReadingError::Inconsistent(Hm1Key::MarkerLines));
                }
                n
            }
            (Some(_), None) => return Err(ReadingError::Missing(Hm1Key::MarkerLines)),
            (None, Some(0) | None) => 0,
            (None, Some(_)) => return Err(ReadingError::Inconsistent(Hm1Key::MarkerLines)),
        };
        let links = match one(rec, Hm1Key::Links)? {
            Some(v) => Some(decimal(v).ok_or(ReadingError::Inconsistent(Hm1Key::Links))?),
            None => None,
        };
        Ok(Inspection {
            path,
            dir,
            dir_mode: one(rec, Hm1Key::DirMode)?.map(str::to_owned),
            dir_owner_self: flag(one(rec, Hm1Key::DirOwnerSelf)?),
            file,
            links,
            mode: one(rec, Hm1Key::Mode)?.map(str::to_owned),
            owner_self: flag(one(rec, Hm1Key::OwnerSelf)?),
            content,
            last_byte_newline: flag(one(rec, Hm1Key::LastByteNewline)?),
            marker_lines: marker_count,
            lock,
            remote_now,
        })
    }

    /// The registry content as a preimage: the file's bytes, or empty when the file
    /// is absent. `None` for a symlink or another kind (not manageable).
    #[must_use]
    pub fn preimage(&self) -> Option<&[u8]> {
        match self.file {
            FileKind::Regular => self.content.as_deref(),
            FileKind::Absent => Some(&[]),
            _ => None,
        }
    }

    /// The holder record of a held lock.
    #[must_use]
    pub fn holder(&self) -> Option<&HolderRecord> {
        match &self.lock {
            LockReading::Held(h) => Some(h),
            LockReading::None | LockReading::HeldForeign => None,
        }
    }
}

// --- the step classification ---------------------------------------------------------

/// Whether the remote shell reported its own exit (0–127): a dropped connection
/// (255), a remote signal (255) or a killed client never does.
fn remote_completed(status: i32) -> bool {
    (0..=127).contains(&status)
}

fn mutating(stage: RemoteStage) -> bool {
    matches!(
        stage,
        RemoteStage::Bootstrap | RemoteStage::Append | RemoteStage::Remove
    )
}

/// The remedy a `ssh` failure before the ready line names, from the redacted stderr
/// excerpt (diagnostics only: it never makes anything applied).
fn ssh_failure(stderr: &str) -> StepClass {
    const HOST_TRUST: &[&str] = &[
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
    ];
    const PROVIDER_LOCKED: &[&str] = &["agent refused operation"];
    const INTERACTION: &[&str] = &[
        "read_passphrase: can't open /dev/tty",
        "Confirm user presence",
    ];
    let has = |list: &[&str]| list.iter().any(|p| stderr.contains(p));
    if has(HOST_TRUST) {
        StepClass::HostTrustChanged
    } else if has(PROVIDER_LOCKED) {
        StepClass::ProviderLocked
    } else if has(INTERACTION) {
        StepClass::InteractionRequired
    } else {
        StepClass::NotApplied(NotAppliedReason::Refused)
    }
}

/// The content an `append` or `remove` (or an `append` exiting 10) reported.
fn reported_content(rec: &Hm1Record) -> Option<Vec<u8>> {
    rec.single(Hm1Key::ContentHex)
        .ok()
        .flatten()
        .and_then(hm1::decode_hex)
}

fn classify_inspect(code: ExitCode, rec: &Hm1Record, expected: &Expected) -> StepClass {
    match code {
        ExitCode::Ok => match Inspection::from_record(rec, &expected.marker) {
            Ok(_) => StepClass::Confirmed,
            Err(_) => StepClass::NotApplied(NotAppliedReason::Refused),
        },
        ExitCode::TooLarge => StepClass::NotApplied(NotAppliedReason::TooLarge),
        _ => StepClass::NotApplied(NotAppliedReason::Refused),
    }
}

fn classify_bootstrap(code: ExitCode, rec: &Hm1Record) -> StepClass {
    match code {
        ExitCode::Ok | ExitCode::BootstrapAlreadyPresent => {
            let checked = rec.single(Hm1Key::Dir) == Ok(Some("present"))
                && matches!(rec.single(Hm1Key::DirMode), Ok(None | Some("drwx------")))
                && matches!(rec.single(Hm1Key::DirOwnerSelf), Ok(None | Some("yes")));
            match (checked, code) {
                (false, _) => StepClass::Uncertain,
                (true, ExitCode::Ok) => StepClass::Confirmed,
                (true, _) => StepClass::AlreadyPresent,
            }
        }
        ExitCode::ParentAbsentOrNoProcessGroup => {
            StepClass::NotApplied(NotAppliedReason::ParentAbsent)
        }
        ExitCode::NotManageable => StepClass::NotApplied(NotAppliedReason::Refused),
        _ => StepClass::Uncertain,
    }
}

/// The lock codes shared by `append` and `remove` (nothing changed).
fn lock_refusal(code: ExitCode) -> Option<NotAppliedReason> {
    Some(match code {
        ExitCode::NotManageable => NotAppliedReason::Refused,
        ExitCode::TooLarge => NotAppliedReason::TooLarge,
        ExitCode::DirAbsent => NotAppliedReason::DirAbsent,
        ExitCode::ParentAbsentOrNoProcessGroup => NotAppliedReason::NoProcessGroup,
        ExitCode::Busy => NotAppliedReason::Busy,
        ExitCode::NotAfterPassed => NotAppliedReason::NotAfterPassed,
        ExitCode::LockLost => NotAppliedReason::LockLost,
        _ => return None,
    })
}

/// Exit 30 whose `reason` says a write was attempted (`write_failed`): the line may
/// be partly there, so it is never "nothing changed" (U5-scripts' output contract).
fn write_attempted(code: ExitCode, rec: &Hm1Record) -> bool {
    code == ExitCode::NotManageable && rec.all(Hm1Key::Reason).any(|r| r == "write_failed")
}

fn classify_append(code: ExitCode, rec: &Hm1Record, expected: &Expected) -> StepClass {
    if write_attempted(code, rec) {
        return StepClass::Uncertain;
    }
    if let Some(reason) = lock_refusal(code) {
        return StepClass::NotApplied(reason);
    }
    let (Some(line), Some(content)) = (expected.line.as_deref(), reported_content(rec)) else {
        return StepClass::Uncertain;
    };
    match code {
        ExitCode::Ok => {
            let Some(pre) = expected.preimage.as_deref() else {
                return StepClass::Uncertain;
            };
            match check_post_append(pre, &content, line) {
                Ok(()) => StepClass::Confirmed,
                Err(_) => StepClass::Held,
            }
        }
        ExitCode::AlreadyPresent => {
            let Some(marker) = crate::line::marker_of(line) else {
                return StepClass::Uncertain;
            };
            let exact = crate::line::lines(&content)
                .filter(|l| *l == line.as_bytes())
                .count();
            match (marker_lines(&content, marker), exact) {
                (1, 1) => StepClass::AlreadyPresent,
                (0, _) => StepClass::Uncertain,
                _ => StepClass::Held,
            }
        }
        _ => StepClass::Uncertain,
    }
}

fn classify_remove(code: ExitCode, rec: &Hm1Record, expected: &Expected) -> StepClass {
    if write_attempted(code, rec) {
        return StepClass::Uncertain;
    }
    if let Some(reason) = lock_refusal(code) {
        return StepClass::NotApplied(reason);
    }
    match code {
        ExitCode::ChangedSinceRead => StepClass::NotApplied(NotAppliedReason::ChangedSinceRead),
        ExitCode::Ok => {
            let (Some(post_image), Some(content)) =
                (expected.post_image.as_deref(), reported_content(rec))
            else {
                return StepClass::Uncertain;
            };
            if expected.marker.is_empty() {
                return StepClass::Uncertain;
            }
            match check_post_remove(post_image, &content, &expected.marker) {
                Ok(()) => StepClass::Confirmed,
                Err(_) => StepClass::Held,
            }
        }
        _ => StepClass::Uncertain,
    }
}

fn classify_fence(code: ExitCode, rec: &Hm1Record) -> StepClass {
    // One `fence` line per decision round; the last is the final decision.
    let decision = rec.all(Hm1Key::Fence).last();
    let signalled = match rec.single(Hm1Key::FenceSignals) {
        Ok(None | Some("")) => false,
        // Repeated or non-empty: a signal may have been sent.
        _ => true,
    };
    let class = match (code, decision) {
        (ExitCode::Ok, Some("gone" | "none")) => return StepClass::Confirmed,
        (ExitCode::HolderAlive, Some("alive"))
        | (ExitCode::Unproven, Some("unproven"))
        | (ExitCode::Busy, _) => StepClass::NotApplied(NotAppliedReason::Busy),
        (ExitCode::ParentAbsentOrNoProcessGroup, _) => {
            StepClass::NotApplied(NotAppliedReason::NoProcessGroup)
        }
        _ => StepClass::NotApplied(NotAppliedReason::Refused),
    };
    if signalled {
        // A signal was sent and the lock was not proven free: never "nothing
        // changed" (§17.10 item 4).
        StepClass::Uncertain
    } else {
        class
    }
}

/// Classify one step result (module docs for the rules).
#[must_use]
pub fn classify_step(stage: RemoteStage, result: &StepResult, expected: &Expected) -> StepClass {
    let stdout = result.stdout.as_bytes();
    // After `HM1 v=1` the script ran: a mutating stage may have written, and a fence
    // may have signalled (its output can be cut before `fence_signals`).
    let unsettled = if mutating(stage) || stage == RemoteStage::Fence {
        StepClass::Uncertain
    } else {
        StepClass::NotApplied(NotAppliedReason::Refused)
    };
    match hm1::handshake(stdout) {
        Handshake::NoReady => {
            return if result.exit_status == ExitCode::Ssh.status() {
                ssh_failure(&result.stderr_excerpt)
            } else {
                StepClass::NotApplied(NotAppliedReason::Refused)
            };
        }
        Handshake::Ready => {
            return if mutating(stage) && !remote_completed(result.exit_status) {
                StepClass::Uncertain
            } else {
                StepClass::NotApplied(NotAppliedReason::Refused)
            };
        }
        _ => {}
    }
    let Ok(rec) = hm1::parse(stdout) else {
        return unsettled;
    };
    let code = match ExitCode::from_status(result.exit_status) {
        Some(ExitCode::Ssh) | None => return unsettled,
        Some(code) => code,
    };
    match stage {
        RemoteStage::Inspect => classify_inspect(code, &rec, expected),
        RemoteStage::Bootstrap => classify_bootstrap(code, &rec),
        RemoteStage::Append => classify_append(code, &rec, expected),
        RemoteStage::Remove => classify_remove(code, &rec, expected),
        RemoteStage::Fence => classify_fence(code, &rec),
        // A stage this build does not know: fail closed.
        _ => StepClass::Uncertain,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn result(exit_status: i32, body: &str) -> StepResult {
        StepResult {
            exit_status,
            stdout: format!("HM1 ready\nHM1 v=1\n{body}"),
            stderr_excerpt: String::new(),
        }
    }

    #[test]
    fn no_ready_is_never_applied_and_255_rules_hold() {
        let stages = [
            RemoteStage::Inspect,
            RemoteStage::Bootstrap,
            RemoteStage::Append,
            RemoteStage::Remove,
            RemoteStage::Fence,
        ];
        for stage in stages {
            let none = StepResult {
                exit_status: 255,
                stdout: String::new(),
                stderr_excerpt: String::new(),
            };
            assert_eq!(
                classify_step(stage, &none, &Expected::default()),
                StepClass::NotApplied(NotAppliedReason::Refused)
            );
            let ready = StepResult {
                exit_status: 255,
                stdout: "HM1 ready\n".into(),
                stderr_excerpt: String::new(),
            };
            let want = if mutating(stage) {
                StepClass::Uncertain
            } else {
                StepClass::NotApplied(NotAppliedReason::Refused)
            };
            assert_eq!(classify_step(stage, &ready, &Expected::default()), want);
        }
        let hk = StepResult {
            exit_status: 255,
            stdout: String::new(),
            stderr_excerpt: "Host key verification failed.\n".into(),
        };
        assert_eq!(
            classify_step(RemoteStage::Append, &hk, &Expected::default()),
            StepClass::HostTrustChanged
        );
    }

    #[test]
    fn holder_record_round_trips() {
        let text = "hm1-00112233445566778899aabbccddeeff-4242-0a0b-ff00-1700000000";
        let h = HolderRecord::parse(text).unwrap();
        assert_eq!(h.pid, 4242);
        assert_eq!(h.render(), text);
        assert!(HolderRecord::parse("hm1-00-1-0a-0b-1").is_none());
        assert!(HolderRecord::parse(&format!("{text}-x")).is_none());
    }

    /// ADR-0008 §17.17 item 6 (U5S-Q5): an append or remove exit 30 with
    /// `reason=write_failed` attempted a write, so it is `Uncertain`, never
    /// `NotApplied`; any other exit-30 reason stays "nothing changed".
    #[test]
    fn write_failed_exit_30_is_uncertain_for_append_and_remove() {
        let expected = Expected {
            marker: "heimdall:enr_0123456789abcdef0123456789abcdef".into(),
            line: Some("cert-authority x heimdall:enr_0123456789abcdef0123456789abcdef".into()),
            preimage: Some(b"a\n".to_vec()),
            post_image: Some(b"a\n".to_vec()),
        };
        for stage in [RemoteStage::Append, RemoteStage::Remove] {
            let failed = result(30, "HM1 status=refused\nHM1 reason=write_failed\n");
            assert_eq!(
                classify_step(stage, &failed, &expected),
                StepClass::Uncertain,
                "{stage:?}"
            );
            // With the content still reported, it is no less uncertain.
            let with_content = result(
                30,
                "HM1 content_hex=610a\nHM1 status=refused\nHM1 reason=write_failed\n",
            );
            assert_eq!(
                classify_step(stage, &with_content, &expected),
                StepClass::Uncertain,
                "{stage:?}"
            );
            let refused = result(30, "HM1 status=refused\nHM1 reason=registry_hardlinked\n");
            assert_eq!(
                classify_step(stage, &refused, &expected),
                StepClass::NotApplied(NotAppliedReason::Refused),
                "{stage:?}"
            );
        }
    }

    #[test]
    fn fence_signals_are_never_nothing_changed() {
        let r = result(44, "HM1 fence=unproven\nHM1 fence_signals=TERM\n");
        assert_eq!(
            classify_step(RemoteStage::Fence, &r, &Expected::default()),
            StepClass::Uncertain
        );
        let r = result(44, "HM1 fence=unproven\nHM1 fence_signals=\n");
        assert_eq!(
            classify_step(RemoteStage::Fence, &r, &Expected::default()),
            StepClass::NotApplied(NotAppliedReason::Busy)
        );
        let r = result(0, "HM1 fence=gone\n");
        assert_eq!(
            classify_step(RemoteStage::Fence, &r, &Expected::default()),
            StepClass::Confirmed
        );
    }
}
