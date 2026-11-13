//! The owner-present ceremonies (ADR-0008 D4 items 1–4; m03-plan U4
//! `ceremony::{init, rotate_begin, restore, unlock, replace_orphan}`) on the
//! controlling terminal.
//!
//! **Init and rotate-begin** follow D4 item 1's steps in order:
//! 1. **generate** K_ca (Ed25519, OS CSPRNG) and the passphrase (26 base32 symbols);
//! 2. **prepare** the exact backup bytes B and `backup_sha256` in memory
//!    ([`crate::backup::prepare`]); nothing is written;
//! 3. **disclose and decide**: `Attend`, then [`OwnerSession::register`]
//!    (`IssuerRequest::Register` with the public key, the store kind and the digest);
//!    the decision must name this CA and this digest; the disclosure is shown and
//!    only a typed `yes` continues. Anything else sends nothing more, zeroizes K_ca
//!    and B, and ends [`CeremonyError::NotConfirmed`] (exit 3);
//! 4. **write** B exactly to `--backup-out` ([`crate::backup::write_exact`]);
//! 5. **show the passphrase once** on the terminal, wait for `written`, clear it;
//! 6. **store** K_ca ([`SecretStore::put`]), read it back by identity and compare;
//!    then ⟨ADR-0008 §17.22 item 12⟩ **report** the item: the same registration again
//!    with `store_locator` (the put's exact locator), which joins the same decision;
//! 7. **approve**: [`OwnerSession::approve`] (`Decide approve`; the runtime records
//!    the CA and the environment permissions in one transaction);
//! 8. K_ca, B and the passphrase are zeroized on drop.
//!
//! The crash points are D4 item 1's: before step 4 nothing is written; between 4 and
//! 6 a backup file whose CA nothing trusts; between 6 and 7 an **orphan** store item
//! ([`orphans`]); after 7 registered. [`CeremonyProbe`] is the test seam that stops a
//! ceremony at each point as a crash would (no further step, no cleanup).
//!
//! **Terminal only.** Every ceremony refuses `--non-interactive`
//! ([`CeremonyError::NonInteractive`]), and [`ControllingTerminal::open`] refuses a
//! process without a controlling terminal ([`CeremonyError::NotATerminal`]). The
//! passphrase is written only through [`Tty`], never to stdout, stderr, a log, an
//! argument, the store or a request.
//!
//! ⟨ADR-0008 §17.27 items 6, 7⟩ **Every read is bounded and cancellable.** Each prompt
//! ([`Tty::read_answer`]) ends in one of four outcomes: a typed line, end of input, a
//! cancellation (Ctrl-C) or no answer within the bound the caller gave
//! [`ControllingTerminal::open`] (the CLI's 120 s prompt timeout). Only a typed line other
//! than the confirmation word is an ordinary wrong answer, which `written` may ask again;
//! the other three end the ceremony at once, with no retry: the passphrase's screen region
//! is cleared, the terminal's mode was already restored by the read, the key material
//! drops (zeroized), nothing more is sent, and the result is
//! [`CeremonyError::NotConfirmed`] (exit 3). A terminal whose read timed out answers no
//! later read, so a late `yes` is never honoured.
//!
//! ⟨§17.26 item 6; §17.27 item 4⟩ **The lock disclosure.** A decision carrying
//! `lock_continuity_once` shows the runtime's conditional text
//! ([`RegisterDecision::lock_text`], from `inspect capabilities` `lock.disclosure`); without
//! it nothing is asked and the ceremony ends [`CeremonyError::DisclosureUnavailable`]
//! (exit 3), so the once-only acknowledgement is recorded only for a decision whose text
//! was shown. A disclosure kind this build cannot show is refused the same way.
//!
//! **S3 (wave-1 escalation U4-Q1).** The public `StoreKind` has no test variant, so
//! a test-configuration store cannot be put in `IssuerRequest::Register`.
//! [`RegisterRequest`] carries the full [`SecretStoreKind`];
//! [`RegisterRequest::to_issuer_request`], the conversion a wire session (U12's CLI)
//! uses, **refuses** a test kind ([`CeremonyError::TestStoreNotRegistrable`]) until
//! the orchestrator rules on the test-only registration path.

use std::io;
use std::path::Path;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::enrollment::DisclosureKind;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{CaFingerprint, DecisionId};
use heimdall_contract::issuer::{CaState, IssuerRequest, IssuerStatus, RecoveryBundle};
use heimdall_credential::cert::SecretCaKey;
/// The zeroizing buffer [`Tty`] returns lines in (re-exported for implementors).
pub use zeroize::Zeroizing;

use crate::backup::{self, BackupError, BackupInfo, NoProbe, Passphrase, WriteProbe};
use crate::store::{SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef};

/// The longest line read from the terminal.
const LINE_MAX: usize = 1024;
/// How many times `written` is asked for before the ceremony gives up.
const WRITTEN_ATTEMPTS: usize = 20;

/// The owner's terminal (the controlling terminal, or a pty in tests). The only
/// place a ceremony writes the passphrase.
pub trait Tty {
    /// Write `text` to the terminal.
    ///
    /// # Errors
    /// The terminal cannot be written.
    fn write_text(&mut self, text: &str) -> io::Result<()>;

    /// Read one line typed by the owner (echo on), without its line ending; `None`
    /// at end of input.
    ///
    /// # Errors
    /// The terminal cannot be read.
    fn read_line(&mut self) -> io::Result<Option<Zeroizing<String>>>;

    /// Read one line with echo off (a passphrase for a restore); `None` at end of
    /// input.
    ///
    /// # Errors
    /// The terminal cannot be read, or echo cannot be turned off (nothing is read
    /// then).
    fn read_hidden(&mut self) -> io::Result<Option<Zeroizing<String>>>;

    /// Clear the last `lines` lines written (the passphrase's screen region).
    ///
    /// # Errors
    /// The terminal cannot be written.
    fn clear_lines(&mut self, lines: usize) -> io::Result<()>;

    /// ⟨ADR-0008 §17.27 items 6, 7⟩ Read one answer (echo off when `hidden`), keeping
    /// end of input, a cancellation and a timeout apart from a typed line. The
    /// ceremonies read only through this. The default (a terminal with no cancellation
    /// or bound of its own, such as a scripted one) is [`Tty::read_line`] or
    /// [`Tty::read_hidden`], `None` being end of input.
    ///
    /// # Errors
    /// The terminal cannot be read.
    fn read_answer(&mut self, hidden: bool) -> io::Result<TtyRead> {
        let line = if hidden {
            self.read_hidden()?
        } else {
            self.read_line()?
        };
        Ok(line.map_or(TtyRead::Eof, TtyRead::Line))
    }
}

/// ⟨ADR-0008 §17.27 items 6, 7⟩ The outcome of one terminal read ([`Tty::read_answer`]).
/// Its `Debug` never shows a typed line.
#[non_exhaustive]
pub enum TtyRead {
    /// A typed line, without its line ending.
    Line(Zeroizing<String>),
    /// End of input (Ctrl-D at the start of a line; the terminal closed).
    Eof,
    /// Ctrl-C.
    Cancelled,
    /// No answer within the bound.
    TimedOut,
}

impl std::fmt::Debug for TtyRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TtyRead::Line(_) => "Line(<typed>)",
            TtyRead::Eof => "Eof",
            TtyRead::Cancelled => "Cancelled",
            TtyRead::TimedOut => "TimedOut",
        })
    }
}

impl TtyRead {
    /// The typed line; `None` for every other outcome.
    #[must_use]
    pub fn into_line(self) -> Option<Zeroizing<String>> {
        match self {
            TtyRead::Line(l) => Some(l),
            _ => None,
        }
    }
}

/// The process's controlling terminal: `/dev/tty` on Unix, `CONIN$`/`CONOUT$` on
/// Windows. Never stdin, stdout or stderr.
///
/// ⟨ADR-0008 §17.27 items 6, 7⟩ Each read is bounded by the `prompt_timeout` given to
/// [`ControllingTerminal::open`]: the blocking read runs on a thread of its own, on a
/// clone of the terminal's handle, and no line within the bound is
/// [`TtyRead::TimedOut`]. The terminal is then **spent**: every later read answers
/// `TimedOut` at once, and whatever the abandoned read still receives is dropped
/// (zeroized), never returned.
#[derive(Debug)]
pub struct ControllingTerminal {
    #[cfg(unix)]
    tty: std::fs::File,
    #[cfg(windows)]
    input: std::fs::File,
    #[cfg(windows)]
    output: std::fs::File,
    /// The bound on each read.
    timeout: Duration,
    /// A read timed out: nothing more is read.
    spent: bool,
}

impl ControllingTerminal {
    /// Open the controlling terminal, each read bounded by `prompt_timeout` (the CLI
    /// gives its prompt timeout, `prompt::PROMPT_TIMEOUT`, 120 s; a test a short one).
    ///
    /// # Errors
    /// [`CeremonyError::NotATerminal`] when the process has none (a daemon, a pipe,
    /// an agent's process without a terminal).
    pub fn open(prompt_timeout: Duration) -> Result<Self, CeremonyError> {
        use std::io::IsTerminal;
        #[cfg(unix)]
        {
            let tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .map_err(|_| CeremonyError::NotATerminal)?;
            if !tty.is_terminal() {
                return Err(CeremonyError::NotATerminal);
            }
            Ok(Self {
                tty,
                timeout: prompt_timeout,
                spent: false,
            })
        }
        #[cfg(windows)]
        {
            let input = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("CONIN$")
                .map_err(|_| CeremonyError::NotATerminal)?;
            let output = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("CONOUT$")
                .map_err(|_| CeremonyError::NotATerminal)?;
            if !input.is_terminal() || !output.is_terminal() {
                return Err(CeremonyError::NotATerminal);
            }
            // Best effort: escape sequences for clearing the passphrase's region.
            if let Ok(mode) = crate::sys::windows::console_mode(&output) {
                const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
                let _ = crate::sys::windows::set_console_mode(
                    &output,
                    mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                );
            }
            Ok(Self {
                input,
                output,
                timeout: prompt_timeout,
                spent: false,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = prompt_timeout;
            Err(CeremonyError::NotATerminal)
        }
    }

    #[cfg(unix)]
    fn reader(&mut self) -> &mut std::fs::File {
        &mut self.tty
    }

    #[cfg(windows)]
    fn reader(&mut self) -> &mut std::fs::File {
        &mut self.input
    }

    #[cfg(unix)]
    fn writer(&mut self) -> &mut std::fs::File {
        &mut self.tty
    }

    #[cfg(windows)]
    fn writer(&mut self) -> &mut std::fs::File {
        &mut self.output
    }

    /// One bounded read (type docs): the line is read on a thread of its own from a
    /// clone of the terminal's handle; no answer within the bound spends the terminal.
    #[cfg(any(unix, windows))]
    fn bounded_read(&mut self) -> io::Result<TtyRead> {
        if self.spent {
            return Ok(TtyRead::TimedOut);
        }
        let mut reader = self.reader().try_clone()?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("heimdall-ceremony-read".into())
            .spawn(move || {
                // A receiver that stopped waiting drops the line (zeroized).
                let _ = tx.send(read_line_from(&mut reader));
            })?;
        match rx.recv_timeout(self.timeout) {
            Ok(read) => read,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.spent = true;
                Ok(TtyRead::TimedOut)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("the terminal read stopped"))
            }
        }
    }
}

/// Read one line from `reader` a byte at a time: up to `\n` (a trailing `\r` dropped);
/// Ctrl-C ([`CTRL_C`]) is a cancellation, and nothing typed so far counts; end of input
/// with nothing typed is [`TtyRead::Eof`].
#[cfg(any(unix, windows))]
fn read_line_from(reader: &mut impl io::Read) -> io::Result<TtyRead> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(LINE_MAX));
    let mut one = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(&mut one[..]) {
            Ok(0) => {
                if bytes.is_empty() {
                    return Ok(TtyRead::Eof);
                }
                break;
            }
            Ok(_) if one[0] == b'\n' => break,
            Ok(_) if one[0] == CTRL_C => return Ok(TtyRead::Cancelled),
            Ok(_) => {
                if bytes.len() < LINE_MAX {
                    bytes.push(one[0]);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    while bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    Ok(TtyRead::Line(text))
}

/// Ctrl-C (ETX). ⟨M03 wave 5, round 2⟩ While a ceremony reads a line, Ctrl-C ends it as a
/// cancellation instead of raising `SIGINT` (Unix: `ISIG` off and `VEOL` = ETX for the
/// read, restored after it), so the typed confirmation's "Ctrl-C sends nothing" ends
/// `NotConfirmed` (exit 3) like end of input, rather than killing the process.
const CTRL_C: u8 = 0x03;

#[cfg(unix)]
impl ControllingTerminal {
    /// Read one line with Ctrl-C as a cancelling line end ([`CTRL_C`]); `hidden` turns
    /// echo off (a typed passphrase). The terminal's mode is restored after the read,
    /// whatever its outcome (a timeout included).
    fn read_in_mode(&mut self, hidden: bool) -> io::Result<TtyRead> {
        use rustix::termios::{
            LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr,
        };
        if self.spent {
            return Ok(TtyRead::TimedOut);
        }
        let original = tcgetattr(&self.tty)?;
        let mut mode = original.clone();
        mode.local_modes.remove(LocalModes::ISIG);
        mode.special_codes[SpecialCodeIndex::VEOL] = CTRL_C;
        if hidden {
            mode.local_modes.remove(LocalModes::ECHO);
            mode.local_modes.insert(LocalModes::ECHONL);
        }
        let when = if hidden {
            OptionalActions::Flush
        } else {
            OptionalActions::Now
        };
        tcsetattr(&self.tty, when, &mode)?;
        let line = self.bounded_read();
        let restored = tcsetattr(&self.tty, OptionalActions::Now, &original);
        let line = line?;
        restored?;
        Ok(line)
    }
}

#[cfg(any(unix, windows))]
impl Tty for ControllingTerminal {
    fn write_text(&mut self, text: &str) -> io::Result<()> {
        use std::io::Write;
        let w = self.writer();
        w.write_all(text.as_bytes())?;
        w.flush()
    }

    fn read_line(&mut self) -> io::Result<Option<Zeroizing<String>>> {
        Ok(self.read_answer(false)?.into_line())
    }

    fn read_hidden(&mut self) -> io::Result<Option<Zeroizing<String>>> {
        Ok(self.read_answer(true)?.into_line())
    }

    fn read_answer(&mut self, hidden: bool) -> io::Result<TtyRead> {
        #[cfg(unix)]
        {
            self.read_in_mode(hidden)
        }
        #[cfg(windows)]
        {
            if !hidden {
                return self.bounded_read();
            }
            if self.spent {
                return Ok(TtyRead::TimedOut);
            }
            const ENABLE_ECHO_INPUT: u32 = 0x0004;
            let original = crate::sys::windows::console_mode(&self.input)?;
            crate::sys::windows::set_console_mode(&self.input, original & !ENABLE_ECHO_INPUT)?;
            let line = self.bounded_read();
            let restored = crate::sys::windows::set_console_mode(&self.input, original);
            let line = line?;
            restored?;
            self.write_text("\r\n")?;
            Ok(line)
        }
    }

    fn clear_lines(&mut self, lines: usize) -> io::Result<()> {
        // Cursor up `lines`, to column 1, clear to the end of the screen.
        self.write_text(&format!("\x1b[{lines}A\r\x1b[J"))
    }
}

/// A failure the owner session reports (from the runtime, over IPC in the CLI).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The runtime refused: its code and stable sub-reason.
    #[error("the runtime refused ({code:?})")]
    Refused {
        /// The envelope code.
        code: Code,
        /// `data.error.reason`.
        reason: Option<String>,
    },
    /// No runtime could be reached.
    #[error("the runtime is unavailable")]
    Unavailable,
}

/// A `RegisterIssuer` registration request, before it is put on the wire (module
/// docs, S3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    /// OpenSSH one-line Ed25519 public key, no comment.
    pub ca_public_key: String,
    /// The store the key will live in.
    pub store: SecretStoreKind,
    /// Hex SHA-256 of the exact D5 backup bytes.
    pub backup_sha256: String,
    /// When the backup bytes were prepared.
    pub backup_created_at: Timestamp,
    /// Rotate-begin: the CA this one rotates.
    pub rotation_of: Option<CaFingerprint>,
    /// A key-only restore (D4 item 4).
    pub restored_without_log: bool,
    /// ⟨ADR-0008 §17.22 item 12⟩ The store item's exact locator, once written (the
    /// report after step 6; absent at step 3).
    pub store_locator: Option<String>,
    /// ⟨ADR-0008 §17.22 item 12⟩ A log-intact restore that wrote a new store item:
    /// the locator `issuer.status` names for the CA now (absent: none), compared and
    /// swapped by the runtime.
    pub expected_store_locator: Option<String>,
}

impl RegisterRequest {
    /// The wire request, `IssuerRequest::Register`.
    ///
    /// # Errors
    /// [`CeremonyError::TestStoreNotRegistrable`] for a test-configuration store kind
    /// (S3; the fail-closed choice of U4-Q1).
    pub fn to_issuer_request(&self) -> Result<IssuerRequest, CeremonyError> {
        let store = self
            .store
            .product()
            .ok_or(CeremonyError::TestStoreNotRegistrable)?;
        Ok(IssuerRequest::Register {
            ca_public_key: self.ca_public_key.clone(),
            store,
            backup_sha256: self.backup_sha256.clone(),
            backup_created_at: self.backup_created_at,
            rotation_of: self.rotation_of.clone(),
            restored_without_log: self.restored_without_log,
            store_locator: self.store_locator.clone(),
            expected_store_locator: self.expected_store_locator.clone(),
        })
    }

    /// ⟨ADR-0008 §17.22 item 12⟩ This registration with the store item's report.
    #[must_use]
    pub fn with_store_item(&self, item: &StoreItemRef) -> Self {
        Self {
            store_locator: Some(item.locator.clone()),
            ..self.clone()
        }
    }
}

/// ⟨ADR-0008 §17.22 item 12⟩ Report `item` on the pending registration `decision`
/// (`issuer.register` again, with its locator): the runtime must answer with the same
/// decision, else nothing more is sent.
fn report_store_item(
    client: &mut dyn OwnerSession,
    request: &RegisterRequest,
    decision: &RegisterDecision,
    item: &StoreItemRef,
) -> Result<(), CeremonyError> {
    let reported = client.register(&request.with_store_item(item))?;
    if reported.decision_id != decision.decision_id {
        return Err(CeremonyError::DecisionMismatch);
    }
    Ok(())
}

/// The runtime's answer to a registration: `APPROVAL_REQUIRED` with the
/// `RegisterIssuer` decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDecision {
    /// The decision to approve.
    pub decision_id: DecisionId,
    /// The CA the decision names.
    pub ca_fingerprint: CaFingerprint,
    /// The backup digest the decision names.
    pub backup_sha256: String,
    /// The disclosures to show.
    pub disclosures: Vec<DisclosureKind>,
    /// ⟨ADR-0008 §17.26 item 6, §17.27 item 4⟩ The runtime's conditional lock disclosure
    /// (`inspect capabilities` `lock.disclosure`, ADR-0008 D9 item 1), the text of
    /// `lock_continuity_once`. `None`: not obtained; a decision carrying
    /// `lock_continuity_once` without it is never offered for approval
    /// ([`CeremonyError::DisclosureUnavailable`]).
    pub lock_text: Option<String>,
}

/// The owner's attended session with the runtime, as the ceremonies use it. U12's
/// CLI implements it over IPC (`Attend`, `Request::Issuer`, `Decide`); tests use a
/// fake.
pub trait OwnerSession {
    /// Make the session attended (`Attend`; ADR-0006 §13.6 item 7).
    ///
    /// # Errors
    /// [`SessionError`].
    fn attend(&mut self) -> Result<(), SessionError>;

    /// `issuer.status`.
    ///
    /// # Errors
    /// [`SessionError`].
    fn status(&mut self) -> Result<IssuerStatus, SessionError>;

    /// `issuer.register` ([`RegisterRequest::to_issuer_request`] on the wire): the
    /// runtime answers `APPROVAL_REQUIRED` with a `RegisterIssuer` decision.
    ///
    /// # Errors
    /// [`SessionError`].
    fn register(&mut self, request: &RegisterRequest) -> Result<RegisterDecision, SessionError>;

    /// `Decide approve` for `decision`.
    ///
    /// # Errors
    /// [`SessionError`].
    fn approve(&mut self, decision: &DecisionId) -> Result<(), SessionError>;

    /// `issuer.unlock`: the issuer reloads its store.
    ///
    /// # Errors
    /// [`SessionError`].
    fn unlock(&mut self) -> Result<IssuerStatus, SessionError>;
}

/// A point at which [`CeremonyProbe`] can stop a ceremony as a crash would (D4 item
/// 1's crash points).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CrashPoint {
    /// After the decision was created and confirmed, before the backup is written.
    Registered,
    /// After the backup was written, before the passphrase is shown.
    BackupWritten,
    /// After the passphrase was shown and acknowledged, before the store write.
    PassphraseShown,
    /// After the store write and read-back, before `Decide approve`.
    Stored,
}

/// The test seam of a ceremony: [`WriteProbe`] inside the backup write, and a stop
/// at each [`CrashPoint`]. Production passes [`NoProbe`].
pub trait CeremonyProbe: WriteProbe {
    /// Called at `point`; `Err` stops the ceremony there (no further step, no
    /// cleanup).
    ///
    /// # Errors
    /// [`backup::Interrupted`] to stop.
    fn at(&mut self, point: CrashPoint) -> Result<(), backup::Interrupted> {
        let _ = point;
        Ok(())
    }
}

impl CeremonyProbe for NoProbe {}

/// Why a ceremony stopped. Messages carry no key or passphrase material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CeremonyError {
    /// `--non-interactive`: ceremonies are owner-present only.
    #[error("the issuer ceremonies need the owner at a terminal (not --non-interactive)")]
    NonInteractive,
    /// No controlling terminal.
    #[error("the issuer ceremonies need a terminal")]
    NotATerminal,
    /// The terminal failed.
    #[error("the terminal could not be read or written")]
    Terminal,
    /// The owner did not type the confirmation (`yes`, `written`, `delete`): another
    /// answer, end of input, Ctrl-C, or no answer within the prompt timeout.
    #[error("not confirmed: nothing more was sent")]
    NotConfirmed,
    /// ⟨ADR-0008 §17.27 item 4⟩ A disclosure the decision carries cannot be shown (the
    /// runtime's lock text was not obtained, or a kind this build does not know): nothing
    /// was asked, approved or written.
    #[error(
        "a disclosure of this decision could not be shown (the runtime's lock disclosure was not obtained, or this version cannot show it): nothing was approved"
    )]
    DisclosureUnavailable,
    /// The store is not available; nothing was written (no plaintext fallback).
    #[error("the CA key store is unavailable ({})", .0.as_str())]
    StoreUnavailable(StoreAvailability),
    /// A store operation failed.
    #[error("the CA key store refused: {0}")]
    Store(StoreError),
    /// The backup step failed.
    #[error("the backup failed: {0}")]
    Backup(BackupError),
    /// `--backup-out` names an existing entry.
    #[error("the backup path already exists; Heimdall never overwrites it")]
    BackupOutExists,
    /// The owner session failed.
    #[error("the runtime request failed: {0}")]
    Session(SessionError),
    /// The runtime's decision does not name this CA and this backup digest.
    #[error("the decision does not match this CA and backup")]
    DecisionMismatch,
    /// The key read back from the store is not the key written.
    #[error("the store returned a different key")]
    KeyMismatch,
    /// A CA is already registered (init) or none is active (rotate-begin, restore of
    /// a registered CA in a final state).
    #[error("the issuer is already initialized")]
    AlreadyInitialized,
    /// No active CA to rotate.
    #[error("the issuer is not initialized")]
    NotInitialized,
    /// Store items no registration names exist: `--replace-orphan` or `restore`.
    #[error("{0} store item(s) no registration names exist")]
    OrphansPresent(usize),
    /// The fingerprint is not an orphan (absent from the store, or registered).
    #[error("that CA key is not an orphan store item")]
    NotAnOrphan,
    /// The bundle lists live enrollments trusting the orphan: restore it instead.
    #[error("the bundle lists {0} live enrollment(s) trusting that CA; restore it instead")]
    OrphanStillTrusted(usize),
    /// Neither `--bundle` nor `--no-bundle-available`.
    #[error("--replace-orphan needs --bundle <file> or --no-bundle-available")]
    BundleOrFlagRequired,
    /// `restore` without `--not-stolen`.
    #[error("restore needs --not-stolen (if the backup may be stolen, rotate instead)")]
    NotStolenRequired,
    /// The backup's CA is registered in a state that cannot be restored.
    #[error("that CA is retiring or retired")]
    CaRetired,
    /// A test-configuration store kind cannot be registered on the wire (S3).
    #[error("a test-configuration store cannot be registered")]
    TestStoreNotRegistrable,
    /// A key or passphrase could not be generated.
    #[error("the CA key could not be generated")]
    Generation,
    /// A [`CeremonyProbe`] stopped the ceremony (tests only).
    #[error("the ceremony was interrupted")]
    Interrupted,
}

impl CeremonyError {
    /// The envelope code the CLI reports.
    #[must_use]
    pub fn code(&self) -> Code {
        match self {
            CeremonyError::NonInteractive
            | CeremonyError::NotATerminal
            | CeremonyError::NotConfirmed
            | CeremonyError::DisclosureUnavailable => Code::InteractionRequired,
            CeremonyError::StoreUnavailable(_)
            | CeremonyError::NotInitialized
            | CeremonyError::TestStoreNotRegistrable => Code::CapabilityUnavailable,
            CeremonyError::Store(StoreError::Unavailable(_)) => Code::CapabilityUnavailable,
            CeremonyError::BackupOutExists
            | CeremonyError::NotStolenRequired
            | CeremonyError::BundleOrFlagRequired
            | CeremonyError::Backup(
                BackupError::WrongPassphrase | BackupError::Malformed | BackupError::Exists,
            ) => Code::UsageError,
            CeremonyError::AlreadyInitialized
            | CeremonyError::OrphansPresent(_)
            | CeremonyError::OrphanStillTrusted(_)
            | CeremonyError::CaRetired
            | CeremonyError::Store(StoreError::AlreadyExists) => Code::ConfigConflict,
            CeremonyError::NotAnOrphan => Code::NotFound,
            CeremonyError::Session(SessionError::Refused { code, .. }) => code.clone(),
            CeremonyError::Session(SessionError::Unavailable)
            // ⟨round 3, K3-Q2⟩ Retryable: the update that replaced the executable finishes,
            // then the command is run again (nothing was stored).
            | CeremonyError::Store(StoreError::ExecutableChanged) => Code::ServiceUnavailable,
            _ => Code::InternalError,
        }
    }

    /// The stable sub-reason (`data.error.reason`), when there is one.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            CeremonyError::StoreUnavailable(a)
            | CeremonyError::Store(StoreError::Unavailable(a)) => {
                a.refusal_reason().map(str::to_owned)
            }
            CeremonyError::TestStoreNotRegistrable => {
                Some(reason::ISSUER_STORE_UNAVAILABLE.to_owned())
            }
            CeremonyError::NotInitialized => Some(reason::ISSUER_NOT_INITIALIZED.to_owned()),
            CeremonyError::Session(SessionError::Refused { reason, .. }) => reason.clone(),
            _ => None,
        }
    }
}

impl From<StoreError> for CeremonyError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Unavailable(a) => CeremonyError::StoreUnavailable(a),
            other => CeremonyError::Store(other),
        }
    }
}

impl From<BackupError> for CeremonyError {
    fn from(e: BackupError) -> Self {
        match e {
            BackupError::Exists => CeremonyError::BackupOutExists,
            BackupError::Interrupted => CeremonyError::Interrupted,
            BackupError::RandomnessUnavailable => CeremonyError::Generation,
            other => CeremonyError::Backup(other),
        }
    }
}

impl From<SessionError> for CeremonyError {
    fn from(e: SessionError) -> Self {
        CeremonyError::Session(e)
    }
}

impl From<backup::Interrupted> for CeremonyError {
    fn from(_: backup::Interrupted) -> Self {
        CeremonyError::Interrupted
    }
}

/// `issuer init` / `issuer rotate begin` options.
#[derive(Debug, Clone, Copy)]
pub struct InitOptions<'a> {
    /// `--backup-out`: where the D5 backup is written (never proposed by Heimdall).
    pub backup_out: &'a Path,
    /// `--non-interactive` was given (refused).
    pub non_interactive: bool,
}

/// `issuer restore` options.
#[derive(Debug, Clone, Copy)]
pub struct RestoreOptions<'a> {
    /// `--backup`: the D5 backup file.
    pub backup: &'a Path,
    /// `--not-stolen`.
    pub not_stolen: bool,
    /// `--non-interactive` was given (refused).
    pub non_interactive: bool,
}

/// `issuer init --replace-orphan` options.
#[derive(Debug, Clone, Copy)]
pub struct ReplaceOrphanOptions<'a> {
    /// The orphan's fingerprint.
    pub fingerprint: &'a CaFingerprint,
    /// `--bundle`: the recovery bundle (parsed by the CLI).
    pub bundle: Option<&'a RecoveryBundle>,
    /// `--no-bundle-available`.
    pub no_bundle_available: bool,
    /// `--non-interactive` was given (refused).
    pub non_interactive: bool,
}

/// A registered CA (init, rotate-begin, a key-only restore).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The CA.
    pub fingerprint: CaFingerprint,
    /// Its store item.
    pub item: StoreItemRef,
    /// The backup written (init, rotate-begin).
    pub backup: Option<BackupInfo>,
    /// The approved decision.
    pub decision: DecisionId,
}

/// What a restore did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Restored {
    /// The CA was registered; its store item was written again and the issuer told
    /// to reload (D4 item 4, log intact).
    StoreItemRewritten {
        /// The CA.
        fingerprint: CaFingerprint,
        /// Its store item.
        item: StoreItemRef,
    },
    /// No registration matched: registered through the full decision with
    /// `restored_without_log: true` (D4 item 4, log lost).
    RegisteredWithoutLog(Registered),
}

fn write(tty: &mut dyn Tty, text: &str) -> Result<(), CeremonyError> {
    tty.write_text(text).map_err(|_| CeremonyError::Terminal)
}

/// Ask for the exact word `word` (case-insensitive, surrounding blanks ignored):
/// `Ok(false)` is an ordinary wrong answer. ⟨ADR-0008 §17.27 items 6, 7⟩ End of input,
/// Ctrl-C and no answer within the bound are [`CeremonyError::NotConfirmed`] at once (the
/// cursor moved to a new line first), never a retry.
fn confirm(tty: &mut dyn Tty, prompt: &str, word: &str) -> Result<bool, CeremonyError> {
    write(tty, prompt)?;
    match tty
        .read_answer(false)
        .map_err(|_| CeremonyError::Terminal)?
    {
        TtyRead::Line(line) => Ok(line.trim().eq_ignore_ascii_case(word)),
        _ => {
            let _ = tty.write_text("\n");
            Err(CeremonyError::NotConfirmed)
        }
    }
}

fn preflight(non_interactive: bool, store: &dyn SecretStore) -> Result<(), CeremonyError> {
    if non_interactive {
        return Err(CeremonyError::NonInteractive);
    }
    match store.availability() {
        StoreAvailability::Available => Ok(()),
        other => Err(CeremonyError::StoreUnavailable(other)),
    }
}

/// The `SHA256:` fingerprint of a one-line OpenSSH Ed25519 public key (the
/// `ca_public_key` of a registration); `None` when it does not parse as one. The
/// runtime's `RegisterIssuer` decision names this fingerprint.
#[must_use]
pub fn public_key_fingerprint(openssh: &str) -> Option<CaFingerprint> {
    let key = ssh_key::PublicKey::from_openssh(openssh).ok()?;
    key.key_data().ed25519()?;
    CaFingerprint::parse(&key.fingerprint(ssh_key::HashAlg::Sha256).to_string()).ok()
}

/// The store items no registration names (D4 item 1, the crash point between steps
/// 6 and 7): every Heimdall item in `store` whose fingerprint is not among
/// `status.cas`.
///
/// # Errors
/// The store cannot be listed.
pub fn orphans(
    store: &dyn SecretStore,
    status: &IssuerStatus,
) -> Result<Vec<StoreItemRef>, StoreError> {
    Ok(store
        .list()?
        .into_iter()
        .filter(|item| !status.cas.iter().any(|c| c.fingerprint == item.fingerprint))
        .collect())
}

/// ⟨ADR-0008 §17.25 item 10⟩ What a disclosure's text names where it depends on the
/// decision. Every field is optional: an absent one is worded generally, never guessed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisclosureContext<'a> {
    /// The managed alias the decision names (the enrollment disclosures
    /// `config_commands_run_as_ordinary_use` and `ordinary_ssh_needs_held_slot`).
    pub alias: Option<&'a str>,
    /// The runtime's own lock disclosure (`inspect capabilities` `lock.disclosure`, from
    /// `Operations::lock_disclosure`), which is conditional on the policies, the floor and
    /// the platform (ADR-0008 D9 item 1). When present it **is** the
    /// `lock_continuity_once` text; absent, the general sentence is shown.
    pub lock: Option<&'a str>,
}

/// The text shown for an unknown disclosure kind (a newer runtime's): never a
/// substitute for a kind this build knows (`disclosure_text_covers_every_kind`).
pub const UNKNOWN_DISCLOSURE: &str = "This decision carries a disclosure this version of Heimdall cannot show: update Heimdall before approving it.";

/// ⟨ADR-0008 §17.25 item 10⟩ The one text of each disclosure kind, for every surface that
/// shows a decision (the issuer ceremonies, `heimdall enroll`'s preview, the TUI), so no
/// surface retypes one. Every [`DisclosureKind`] has its own text; only a kind this build
/// does not know (the enum is `non_exhaustive`) gets [`UNKNOWN_DISCLOSURE`], and a surface
/// that sees it must not offer approval.
///
/// The slot disclosure names the command that holds a slot,
/// `heimdall_domain::managed::slot_free_command` (the preview's, `enroll status`'s and the
/// doctor's own).
#[must_use]
pub fn disclosure_text(kind: DisclosureKind, context: &DisclosureContext<'_>) -> String {
    let alias = context.alias;
    match kind {
        DisclosureKind::SameUserIssuerBoundary => "The issuer runs as your own OS user: any program running as you can ask it to sign or read its key store. The boundary is your OS account.".to_owned(),
        DisclosureKind::CaTrustBlastRadius => "Every account you enroll will trust this CA: whoever holds its key can reach all of them.".to_owned(),
        DisclosureKind::LockContinuityOnce => match context.lock {
            Some(text) => text.to_owned(),
            None => "Managed signing continues while your desktop is locked, within each grant's deadline, unless a policy or your configuration ends work at a lock.".to_owned(),
        },
        DisclosureKind::BackupInstructions => "The backup file and its passphrase together restore this CA. Keep them apart, offline, and never in a synchronized folder.".to_owned(),
        DisclosureKind::RestoredWithoutLogResidualsUnknown => "Key-only restore: the issuance log is lost, so every residual under this CA is unknown (unbounded). Rotate this CA soon.".to_owned(),
        DisclosureKind::ConfigCommandsRunAsOrdinaryUse => match alias {
            Some(a) => format!("Every step connects with your ssh configuration for `{a}` for everything that is not pinned, so its `Match exec` and similar entries run as in ordinary use."),
            None => "Every step connects with your ssh configuration for the alias for everything that is not pinned, so its `Match exec` and similar entries run as in ordinary use.".to_owned(),
        },
        DisclosureKind::RemoveWindow => "The enrollment can be removed early (`heimdall enroll remove`); certificates already issued under this CA stay valid until they expire (the pair residual).".to_owned(),
        DisclosureKind::ReconcileMayStopOwnStaleScript => "`heimdall enroll reconcile` may stop Heimdall's own stale script on the destination (TERM, then KILL, of the exact process group its lock recorded); nothing else is ever signalled.".to_owned(),
        DisclosureKind::OrdinarySshNeedsHeldSlot => {
            let a = alias.unwrap_or("<alias>");
            format!(
                "Ordinary `ssh {a}` works only while a binding holds this alias's managed slot; `{}` holds one while it runs.",
                heimdall_domain::managed::slot_free_command(a)
            )
        }
        _ => UNKNOWN_DISCLOSURE.to_owned(),
    }
}

/// Show the decision and every disclosure's text (the whole text first, then the
/// caller asks). ⟨ADR-0008 §17.27 item 4⟩ `lock_continuity_once` is the runtime's own
/// conditional text ([`RegisterDecision::lock_text`]); without it, or with a kind this
/// build cannot show, the decision is shown without that text and refused
/// ([`CeremonyError::DisclosureUnavailable`]): nothing is asked. A terminal that strips
/// control characters is the CLI's (`issuer_cmd`), so every string here reaches the
/// screen sanitized.
fn show_decision(
    tty: &mut dyn Tty,
    decision: &RegisterDecision,
    backup_out: Option<&Path>,
) -> Result<(), CeremonyError> {
    let lock = decision
        .lock_text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let context = DisclosureContext { alias: None, lock };
    let mut text = format!(
        "\nRegister CA {}\n  backup SHA-256 {}\n",
        decision.ca_fingerprint, decision.backup_sha256
    );
    if let Some(path) = backup_out {
        text.push_str(&format!("  backup file    {}\n", path.display()));
    }
    let mut unavailable = false;
    for kind in &decision.disclosures {
        if *kind == DisclosureKind::LockContinuityOnce && lock.is_none() {
            unavailable = true;
            continue;
        }
        let shown = disclosure_text(*kind, &context);
        unavailable |= shown == UNKNOWN_DISCLOSURE;
        text.push_str("  * ");
        text.push_str(&shown);
        text.push('\n');
    }
    if unavailable {
        text.push_str("  This decision cannot be approved here: one of its disclosures could not be shown. Nothing was approved; run the command again.\n");
    }
    write(tty, &text)?;
    if unavailable {
        return Err(CeremonyError::DisclosureUnavailable);
    }
    Ok(())
}

/// Show the passphrase once, wait for `written`, then clear its screen region.
fn show_passphrase(tty: &mut dyn Tty, passphrase: &Passphrase) -> Result<(), CeremonyError> {
    let grouped = passphrase.grouped();
    // Sized once, so no reallocation leaves a copy of the passphrase behind.
    let mut text = Zeroizing::new(String::with_capacity(256));
    text.push_str(
        "\nBackup passphrase (shown once; type its 26 characters without the spaces):\n\n    ",
    );
    text.push_str(&grouped);
    text.push_str("\n\nWrite it down and keep it apart from the backup file.\n");
    write(tty, &text)?;
    drop(text);
    let mut lines = 6;
    for _ in 0..WRITTEN_ATTEMPTS {
        lines += 1;
        match confirm(
            tty,
            "Type 'written' when you have written it down: ",
            "written",
        ) {
            Ok(true) => {
                tty.clear_lines(lines)
                    .map_err(|_| CeremonyError::Terminal)?;
                return Ok(());
            }
            // An ordinary wrong answer: asked again.
            Ok(false) => {}
            // ⟨§17.27 items 6, 7⟩ End of input, Ctrl-C, the timeout (or a terminal
            // failure): the passphrase is cleared, and the ceremony ends at once.
            Err(e) => {
                let _ = tty.clear_lines(lines);
                return Err(e);
            }
        }
    }
    let _ = tty.clear_lines(lines);
    Err(CeremonyError::NotConfirmed)
}

/// Write `key` to `store`, read it back by identity and compare. An item already
/// holding the same key (an orphan being adopted by a restore) is accepted when
/// `adopt` is set.
///
/// ⟨§17.17 item 3; wave-1 review W1-R01, W1-R02⟩ The adopted item's identity comes from
/// the store's own, installation-scoped `list` (the same scope its `get` reads back),
/// and exactly one item must hold the CA there: another installation's item is never
/// adopted, and more than one is refused rather than guessed.
fn store_and_check(
    store: &dyn SecretStore,
    fingerprint: &CaFingerprint,
    key: &SecretCaKey,
    adopt: bool,
) -> Result<StoreItemRef, CeremonyError> {
    let item = match store.put(fingerprint, key) {
        Ok(item) => item,
        Err(StoreError::AlreadyExists) if adopt => {
            let mut mine: Vec<StoreItemRef> = store
                .list()?
                .into_iter()
                .filter(|i| i.fingerprint == *fingerprint && i.kind == store.kind())
                .collect();
            match mine.len() {
                1 => mine.swap_remove(0),
                0 => return Err(CeremonyError::Store(StoreError::NotFound)),
                _ => return Err(CeremonyError::Store(StoreError::Corrupt)),
            }
        }
        Err(e) => return Err(e.into()),
    };
    let back = store.get(fingerprint)?;
    if !back.same_key(key) {
        return Err(CeremonyError::KeyMismatch);
    }
    Ok(item)
}

/// D4 item 1, steps 1–8 (init and rotate-begin).
fn create_ca(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    backup_out: &Path,
    rotation_of: Option<CaFingerprint>,
    probe: &mut dyn CeremonyProbe,
) -> Result<Registered, CeremonyError> {
    if std::fs::symlink_metadata(backup_out).is_ok() {
        return Err(CeremonyError::BackupOutExists);
    }
    // 1. Generate.
    let key = SecretCaKey::generate().map_err(|_| CeremonyError::Generation)?;
    let passphrase = Passphrase::generate()?;
    let fingerprint = key.fingerprint().map_err(|_| CeremonyError::Generation)?;
    // 2. Prepare the exact backup bytes.
    let prepared = backup::prepare(&key, &passphrase)?;
    let prepared_at = Timestamp::now();
    // 3. Disclose and decide.
    let request = RegisterRequest {
        ca_public_key: key
            .public_openssh()
            .map_err(|_| CeremonyError::Generation)?,
        store: store.kind(),
        backup_sha256: prepared.sha256.clone(),
        backup_created_at: prepared_at,
        rotation_of,
        restored_without_log: false,
        store_locator: None,
        expected_store_locator: None,
    };
    client.attend()?;
    let decision = client.register(&request)?;
    if decision.ca_fingerprint != fingerprint || decision.backup_sha256 != prepared.sha256 {
        return Err(CeremonyError::DecisionMismatch);
    }
    show_decision(tty, &decision, Some(backup_out))?;
    if !confirm(tty, "Type 'yes' to register this CA: ", "yes")? {
        return Err(CeremonyError::NotConfirmed);
    }
    probe.at(CrashPoint::Registered)?;
    // 4. Write the backup exactly.
    let info = backup::write_exact_probed(backup_out, &prepared, probe)?;
    write(tty, &format!("Backup written: {}\n", backup_out.display()))?;
    probe.at(CrashPoint::BackupWritten)?;
    // 5. Show the passphrase once.
    show_passphrase(tty, &passphrase)?;
    probe.at(CrashPoint::PassphraseShown)?;
    // 6. Store, read back, compare.
    let item = store_and_check(store, &fingerprint, &key, false)?;
    probe.at(CrashPoint::Stored)?;
    // 6b. Report the store item on the same decision (§17.22 item 12).
    report_store_item(client, &request, &decision, &item)?;
    // 7. Register.
    client.approve(&decision.decision_id)?;
    write(tty, &format!("CA {fingerprint} registered.\n"))?;
    // 8. K_ca, B and the passphrase are zeroized as they drop here.
    drop((key, passphrase, prepared));
    Ok(Registered {
        fingerprint,
        item,
        backup: Some(info),
        decision: decision.decision_id,
    })
}

/// `heimdall issuer init --backup-out <path>` (D4 item 1).
///
/// # Errors
/// [`CeremonyError`]; on any error after step 3 nothing more is sent.
pub fn init(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    options: &InitOptions<'_>,
) -> Result<Registered, CeremonyError> {
    init_probed(tty, client, store, options, &mut NoProbe)
}

/// [`init`] with a [`CeremonyProbe`].
///
/// # Errors
/// As [`init`]; [`CeremonyError::Interrupted`] when the probe stopped it.
pub fn init_probed(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    options: &InitOptions<'_>,
    probe: &mut dyn CeremonyProbe,
) -> Result<Registered, CeremonyError> {
    preflight(options.non_interactive, store)?;
    let status = client.status()?;
    if status.cas.iter().any(|c| c.state != CaState::Retired) {
        return Err(CeremonyError::AlreadyInitialized);
    }
    let orphaned = orphans(store, &status)?;
    if !orphaned.is_empty() {
        write(
            tty,
            "A CA key no registration names is in the store. Restore it (`heimdall issuer restore --backup <file> --not-stolen`), or replace it (`heimdall issuer init --replace-orphan <fingerprint>`).\n",
        )?;
        return Err(CeremonyError::OrphansPresent(orphaned.len()));
    }
    create_ca(tty, client, store, options.backup_out, None, probe)
}

/// `heimdall issuer rotate begin --backup-out <path>` (D4 item 3): the init ceremony
/// for a new CA in state `pending`, rotating the newest `active` CA.
///
/// # Errors
/// [`CeremonyError::NotInitialized`] without an active CA; otherwise as [`init`].
pub fn rotate_begin(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    options: &InitOptions<'_>,
) -> Result<Registered, CeremonyError> {
    rotate_begin_probed(tty, client, store, options, &mut NoProbe)
}

/// [`rotate_begin`] with a [`CeremonyProbe`].
///
/// # Errors
/// As [`rotate_begin`]; [`CeremonyError::Interrupted`] when the probe stopped it.
pub fn rotate_begin_probed(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    options: &InitOptions<'_>,
    probe: &mut dyn CeremonyProbe,
) -> Result<Registered, CeremonyError> {
    preflight(options.non_interactive, store)?;
    let status = client.status()?;
    let current = status
        .cas
        .iter()
        .filter(|c| c.state == CaState::Active)
        .max_by_key(|c| c.backup_created_at)
        .map(|c| c.fingerprint.clone())
        .ok_or(CeremonyError::NotInitialized)?;
    write(
        tty,
        &format!("Rotating CA {current}: the new CA starts pending.\n"),
    )?;
    create_ca(tty, client, store, options.backup_out, Some(current), probe)
}

/// The guidance shown before a restore (ADR-0005 §5.3).
const RESTORE_GUIDANCE: &str = "Restore only if the backup and this device are not believed stolen. If they may be, do not restore: rotate the CA instead (`heimdall issuer rotate begin`).\n";

/// `heimdall issuer restore --backup <file> --not-stolen` (D4 item 4). The
/// passphrase is typed with echo off.
///
/// # Errors
/// [`CeremonyError::NotStolenRequired`] without `--not-stolen` (nothing is read);
/// a wrong passphrase is [`CeremonyError::Backup`] with
/// [`BackupError::WrongPassphrase`] (nothing is stored); otherwise [`CeremonyError`].
pub fn restore(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    options: &RestoreOptions<'_>,
) -> Result<Restored, CeremonyError> {
    if options.non_interactive {
        return Err(CeremonyError::NonInteractive);
    }
    write(tty, RESTORE_GUIDANCE)?;
    if !options.not_stolen {
        return Err(CeremonyError::NotStolenRequired);
    }
    preflight(false, store)?;
    let file = backup::read(options.backup)?;
    write(tty, "Backup passphrase: ")?;
    // ⟨§17.27 items 6, 7⟩ End of input, Ctrl-C or the timeout: nothing is decrypted.
    let Some(typed) = tty
        .read_answer(true)
        .map_err(|_| CeremonyError::Terminal)?
        .into_line()
    else {
        let _ = tty.write_text("\n");
        return Err(CeremonyError::NotConfirmed);
    };
    let passphrase = Passphrase::new(typed);
    let key = file.decrypt(&passphrase)?;
    drop(passphrase);
    let fingerprint = key.fingerprint().map_err(|_| CeremonyError::Generation)?;
    let status = client.status()?;
    if let Some(ca) = status.cas.iter().find(|c| c.fingerprint == fingerprint) {
        // The issuance log is intact: only the store item was lost.
        if !matches!(ca.state, CaState::Active | CaState::Pending) {
            return Err(CeremonyError::CaRetired);
        }
        let item = store_and_check(store, &fingerprint, &key, true)?;
        client.attend()?;
        // ⟨§17.22 item 12⟩ A new store item (another locator than the recorded one):
        // registered again, compare-and-swap against the recorded locator; the
        // displaced item is listed as an orphan until its deletion is confirmed.
        if ca.store_locator.as_deref() != Some(item.locator.as_str()) {
            let request = RegisterRequest {
                ca_public_key: key
                    .public_openssh()
                    .map_err(|_| CeremonyError::Generation)?,
                store: store.kind(),
                backup_sha256: file.sha256.clone(),
                backup_created_at: modified_at(options.backup),
                rotation_of: None,
                restored_without_log: false,
                store_locator: Some(item.locator.clone()),
                expected_store_locator: ca.store_locator.clone(),
            };
            let decision = client.register(&request)?;
            if decision.ca_fingerprint != fingerprint || decision.backup_sha256 != file.sha256 {
                return Err(CeremonyError::DecisionMismatch);
            }
            show_decision(tty, &decision, None)?;
            if !confirm(tty, "Type 'yes' to record the restored store item: ", "yes")? {
                return Err(CeremonyError::NotConfirmed);
            }
            client.approve(&decision.decision_id)?;
        }
        client.unlock()?;
        write(
            tty,
            &format!("CA {fingerprint} restored to the store and reloaded.\n"),
        )?;
        return Ok(Restored::StoreItemRewritten { fingerprint, item });
    }
    // The log is lost: the full decision, `restored_without_log: true`.
    let request = RegisterRequest {
        ca_public_key: key
            .public_openssh()
            .map_err(|_| CeremonyError::Generation)?,
        store: store.kind(),
        backup_sha256: file.sha256.clone(),
        backup_created_at: modified_at(options.backup),
        rotation_of: None,
        restored_without_log: true,
        store_locator: None,
        expected_store_locator: None,
    };
    client.attend()?;
    let decision = client.register(&request)?;
    if decision.ca_fingerprint != fingerprint || decision.backup_sha256 != file.sha256 {
        return Err(CeremonyError::DecisionMismatch);
    }
    show_decision(tty, &decision, None)?;
    write(
        tty,
        &format!(
            "  * {}\n",
            disclosure_text(
                DisclosureKind::RestoredWithoutLogResidualsUnknown,
                &DisclosureContext::default()
            )
        ),
    )?;
    if !confirm(tty, "Type 'yes' to register this restored CA: ", "yes")? {
        return Err(CeremonyError::NotConfirmed);
    }
    let item = store_and_check(store, &fingerprint, &key, true)?;
    report_store_item(client, &request, &decision, &item)?;
    client.approve(&decision.decision_id)?;
    write(
        tty,
        &format!("CA {fingerprint} registered (restored without its log). Rotate it soon.\n"),
    )?;
    Ok(Restored::RegisteredWithoutLog(Registered {
        fingerprint,
        item,
        backup: None,
        decision: decision.decision_id,
    }))
}

/// The backup file's modification time (its creation as far as this device can
/// tell), or now.
fn modified_at(path: &Path) -> Timestamp {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| Timestamp::try_from(t).ok())
        .unwrap_or_else(Timestamp::now)
}

/// `heimdall issuer unlock` (D4 item 2), owner-present: when the store reads
/// `available`, the issuer is told to reload it. A store that is still locked is
/// reported with what to unlock; Heimdall itself triggers no store prompt (the
/// fail-closed reading of "a prompt may appear").
///
/// # Errors
/// [`CeremonyError::StoreUnavailable`] while the store is not available; otherwise
/// [`CeremonyError`].
pub fn unlock(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    non_interactive: bool,
) -> Result<IssuerStatus, CeremonyError> {
    if non_interactive {
        return Err(CeremonyError::NonInteractive);
    }
    match store.availability() {
        StoreAvailability::Available => {}
        other => {
            write(
                tty,
                &format!(
                    "The CA key store is {}. Unlock it (the login keychain, or your desktop's keyring), then run `heimdall issuer unlock` again.\n",
                    other.as_str()
                ),
            )?;
            return Err(CeremonyError::StoreUnavailable(other));
        }
    }
    client.attend()?;
    let status = client.unlock()?;
    write(tty, "The issuer reloaded its CA keys.\n")?;
    Ok(status)
}

/// `heimdall issuer init --replace-orphan <fingerprint>` (D4 item 1, F08): warn
/// that deleting a K_ca is irreversible; with `--bundle`, refuse when the bundle
/// lists live enrollments trusting that CA and offer restore instead; without one,
/// require `--no-bundle-available`; then delete exactly that store item after the
/// typed confirmation `delete`. The CLI runs [`init`] afterwards.
///
/// # Errors
/// [`CeremonyError::NotAnOrphan`], [`CeremonyError::OrphanStillTrusted`],
/// [`CeremonyError::BundleOrFlagRequired`], [`CeremonyError::NotConfirmed`];
/// otherwise [`CeremonyError`].
pub fn replace_orphan(
    tty: &mut dyn Tty,
    client: &mut dyn OwnerSession,
    store: &dyn SecretStore,
    options: &ReplaceOrphanOptions<'_>,
) -> Result<StoreItemRef, CeremonyError> {
    preflight(options.non_interactive, store)?;
    let status = client.status()?;
    let item = orphans(store, &status)?
        .into_iter()
        .find(|i| i.fingerprint == *options.fingerprint)
        .ok_or(CeremonyError::NotAnOrphan)?;
    write(
        tty,
        &format!(
            "Deleting CA key {} is irreversible: any line that still trusts it can then never be removed with it.\n",
            item.fingerprint
        ),
    )?;
    match (options.bundle, options.no_bundle_available) {
        (Some(bundle), _) => {
            let live = bundle
                .enrollments
                .iter()
                .filter(|e| e.ca_fingerprint == item.fingerprint && !e.state.is_final())
                .count();
            if live > 0 {
                write(
                    tty,
                    &format!(
                        "The bundle lists {live} enrollment(s) that still trust this CA. Restore it instead: `heimdall issuer restore --backup <file> --not-stolen` (registered with restored_without_log).\n"
                    ),
                )?;
                return Err(CeremonyError::OrphanStillTrusted(live));
            }
        }
        (None, true) => {
            write(
                tty,
                "No bundle: remote lines may still trust this CA, and nothing here can tell.\n",
            )?;
        }
        (None, false) => {
            write(
                tty,
                "Give the recovery bundle (--bundle <file>) to check which accounts still trust this CA, or --no-bundle-available.\n",
            )?;
            return Err(CeremonyError::BundleOrFlagRequired);
        }
    }
    if !confirm(tty, "Type 'delete' to delete this CA key: ", "delete")? {
        return Err(CeremonyError::NotConfirmed);
    }
    store.delete(&item)?;
    if store.list()?.contains(&item) {
        return Err(CeremonyError::Store(StoreError::Failed));
    }
    write(tty, "Deleted.\n")?;
    Ok(item)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Every `DisclosureKind` wire name in the exported public schema.
    fn every_kind() -> Vec<DisclosureKind> {
        let path =
            heimdall_testkit::repo::repo_path("schemas/public-api/enrollment-plan.schema.json");
        let schema: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let names = schema["$defs"]["DisclosureKind"]["oneOf"]
            .as_array()
            .map(|v| {
                v.iter()
                    .filter_map(|o| o["const"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .or_else(|| {
                schema["$defs"]["DisclosureKind"]["enum"]
                    .as_array()
                    .map(|v| {
                        v.iter()
                            .filter_map(|o| o.as_str().map(str::to_owned))
                            .collect()
                    })
            })
            .expect("the schema lists DisclosureKind");
        names
            .iter()
            .map(|n| serde_json::from_value(serde_json::Value::String(n.clone())).unwrap())
            .collect()
    }

    /// ⟨ADR-0008 §17.25 item 10⟩ Every kind in the public schema has its own text, none
    /// is the unknown-kind text, and each names what its context gives it.
    #[test]
    fn disclosure_text_covers_every_kind() {
        let kinds = every_kind();
        assert!(kinds.len() >= 9, "{kinds:?}");
        let mut seen = std::collections::BTreeSet::new();
        for kind in &kinds {
            let general = disclosure_text(*kind, &DisclosureContext::default());
            assert_ne!(general, UNKNOWN_DISCLOSURE, "{kind:?}");
            assert!(!general.is_empty(), "{kind:?}");
            assert!(seen.insert(general), "{kind:?} shares a text");
        }
        let ctx = DisclosureContext {
            alias: Some("lab"),
            lock: Some("RUNTIME LOCK TEXT"),
        };
        let slot = disclosure_text(DisclosureKind::OrdinarySshNeedsHeldSlot, &ctx);
        assert!(slot.contains("`ssh lab`"), "{slot}");
        assert!(
            slot.contains(&heimdall_domain::managed::slot_free_command("lab")),
            "{slot}"
        );
        assert!(
            disclosure_text(DisclosureKind::ConfigCommandsRunAsOrdinaryUse, &ctx).contains("`lab`")
        );
        assert_eq!(
            disclosure_text(DisclosureKind::LockContinuityOnce, &ctx),
            "RUNTIME LOCK TEXT"
        );
    }

    /// ⟨ADR-0008 §17.27 item 7⟩ The terminal line reader keeps Ctrl-C and end of input
    /// apart from a typed line: Ctrl-C cancels whatever was typed before it, end of input
    /// with nothing typed is `Eof`, and a line drops its `\r\n`.
    #[cfg(any(unix, windows))]
    #[test]
    fn terminal_reads_keep_cancellation_and_end_of_input_apart() {
        let read = |bytes: &[u8]| read_line_from(&mut &bytes[..]).unwrap();
        assert!(matches!(read(b"yes\r\n"), TtyRead::Line(l) if l.as_str() == "yes"));
        assert!(matches!(read(b"yes\x03"), TtyRead::Cancelled));
        assert!(matches!(read(b"\x03yes\n"), TtyRead::Cancelled));
        assert!(matches!(read(b""), TtyRead::Eof));
        assert!(matches!(read(b"partial"), TtyRead::Line(l) if l.as_str() == "partial"));
        assert_eq!(format!("{:?}", read(b"secret\n")), "Line(<typed>)");
    }

    /// A terminal answering from a script (`None`: end of input), recording what was shown.
    struct Script {
        answers: std::collections::VecDeque<TtyRead>,
        shown: String,
    }

    impl Tty for Script {
        fn write_text(&mut self, text: &str) -> io::Result<()> {
            self.shown.push_str(text);
            Ok(())
        }
        fn read_line(&mut self) -> io::Result<Option<Zeroizing<String>>> {
            Ok(self.read_answer(false)?.into_line())
        }
        fn read_hidden(&mut self) -> io::Result<Option<Zeroizing<String>>> {
            Ok(self.read_answer(true)?.into_line())
        }
        fn read_answer(&mut self, _hidden: bool) -> io::Result<TtyRead> {
            Ok(self.answers.pop_front().unwrap_or(TtyRead::Eof))
        }
        fn clear_lines(&mut self, lines: usize) -> io::Result<()> {
            self.shown.push_str(&format!("<clear {lines}>"));
            Ok(())
        }
    }

    fn decision(kinds: Vec<DisclosureKind>, lock_text: Option<&str>) -> RegisterDecision {
        RegisterDecision {
            decision_id: DecisionId::from_random_bytes([7; 16]),
            ca_fingerprint: CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap(),
            backup_sha256: "ab".repeat(32),
            disclosures: kinds,
            lock_text: lock_text.map(str::to_owned),
        }
    }

    /// ⟨ADR-0008 §17.26 item 6, §17.27 item 4⟩ A decision carrying `lock_continuity_once`
    /// shows the runtime's conditional text; without that text (absent or blank) it is shown
    /// without the general sentence and refused before anything is asked.
    #[test]
    fn register_decision_needs_the_runtime_lock_text() {
        let kinds = vec![
            DisclosureKind::SameUserIssuerBoundary,
            DisclosureKind::LockContinuityOnce,
        ];
        let general = disclosure_text(
            DisclosureKind::LockContinuityOnce,
            &DisclosureContext::default(),
        );
        let mut tty = Script {
            answers: Default::default(),
            shown: String::new(),
        };
        show_decision(
            &mut tty,
            &decision(kinds.clone(), Some("RUNTIME TEXT")),
            None,
        )
        .unwrap();
        assert!(tty.shown.contains("  * RUNTIME TEXT\n"), "{}", tty.shown);
        assert!(!tty.shown.contains(&general));
        for missing in [None, Some("  ")] {
            let mut tty = Script {
                answers: Default::default(),
                shown: String::new(),
            };
            assert_eq!(
                show_decision(&mut tty, &decision(kinds.clone(), missing), None),
                Err(CeremonyError::DisclosureUnavailable)
            );
            assert!(!tty.shown.contains(&general), "{}", tty.shown);
            assert!(
                tty.shown.contains("cannot be approved here"),
                "{}",
                tty.shown
            );
            assert_eq!(
                CeremonyError::DisclosureUnavailable.code(),
                Code::InteractionRequired
            );
        }
        // No lock disclosure on the decision: no text needed.
        let mut tty = Script {
            answers: Default::default(),
            shown: String::new(),
        };
        show_decision(
            &mut tty,
            &decision(vec![DisclosureKind::BackupInstructions], None),
            None,
        )
        .unwrap();
    }

    /// ⟨ADR-0008 §17.27 items 6, 7⟩ At `written`, only an ordinary wrong answer is asked
    /// again; end of input, Ctrl-C and the timeout end at once with the region cleared.
    #[test]
    fn written_retries_only_a_wrong_answer() {
        let line = |s: &str| TtyRead::Line(Zeroizing::new(s.to_owned()));
        let passphrase = Passphrase::generate().unwrap();
        for stop in [TtyRead::Eof, TtyRead::Cancelled, TtyRead::TimedOut] {
            let label = format!("{stop:?}");
            let mut tty = Script {
                answers: [line("nope"), stop, line("written")].into_iter().collect(),
                shown: String::new(),
            };
            assert_eq!(
                show_passphrase(&mut tty, &passphrase),
                Err(CeremonyError::NotConfirmed),
                "{label}"
            );
            assert_eq!(tty.shown.matches("Type 'written'").count(), 2, "{label}");
            assert!(tty.shown.ends_with("\n<clear 8>"), "{label}: {}", tty.shown);
            assert_eq!(
                tty.answers.len(),
                1,
                "{label}: the later `written` was never read"
            );
        }
        let mut tty = Script {
            answers: [line("nope"), line(" Written ")].into_iter().collect(),
            shown: String::new(),
        };
        show_passphrase(&mut tty, &passphrase).unwrap();
        assert!(tty.shown.ends_with("<clear 8>"));
    }
}
