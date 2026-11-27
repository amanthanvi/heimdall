//! The request ledger (ADR-0014 §3.6, fence step 4): an append-only file of fixed-size
//! records in the state directory, outside every generation.
//!
//! Before a request's first durable store write the runtime appends one record and waits
//! for [`Ledger::append`] to return: the restore epoch and a SHA-256 over the canonically
//! encoded full idempotency key. The record holds no request content and no identifier in
//! the clear. At a restore, every entry without a terminal record in the staged generation
//! becomes a fence record there ([`unfenced`]).
//!
//! The caller holds the instance lock around [`Ledger::append`] and [`Ledger::trim`].
//!
//! ⟨M08 U2b-3a⟩ **A caller that keeps the entries in memory** (the runtime's request fence)
//! reads the ledger once ([`Ledger::load`]) and then appends with [`Ledger::append_at`], which
//! checks the file's length against the length it last saw and reads nothing. The damaged-ledger
//! check is then made where the ledger is read whole: at that load, whenever the length is not
//! the expected one (a torn tail, or a change the caller did not make), and at each trim. An
//! append's cost does not grow with the ledger's history ([`Ledger::bytes_read`] counts what
//! this value has read).

use std::cell::Cell;
use std::path::PathBuf;

use jiff::{SignedDuration, Timestamp};
use sha2::{Digest, Sha256};

use crate::fs::{Fs, Kind, Point};

/// The ledger's file name in the state directory.
pub const LEDGER: &str = "REQUEST-LEDGER";
/// The replacement written during a trim.
pub const LEDGER_TMP: &str = "REQUEST-LEDGER.tmp";
/// One record: a 4-byte tag, the epoch (8 bytes, big-endian), the digest (32 bytes) and a
/// 4-byte check (the first bytes of the SHA-256 of the 44 before it).
pub const RECORD_LEN: usize = 48;
/// The expired-key marker window of ADR-0006 §7.4.
pub const MARKER_WINDOW: SignedDuration = SignedDuration::from_hours(30 * 24);

const TAG: &[u8; 4] = b"HRL1";
/// The most the ledger is read at once (about 5.5 million entries). A longer ledger is
/// unreadable, which a restore treats as "keep and fence everything": nothing is dropped.
const READ_LIMIT: u64 = 256 * 1024 * 1024;

/// One ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Entry {
    /// The restore epoch the request was accepted under.
    pub epoch: u64,
    /// The digest of the request's full idempotency key ([`key_digest`]).
    pub digest: [u8; 32],
}

impl Entry {
    fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[..4].copy_from_slice(TAG);
        out[4..12].copy_from_slice(&self.epoch.to_be_bytes());
        out[12..44].copy_from_slice(&self.digest);
        let check = Sha256::digest(&out[..44]);
        out[44..].copy_from_slice(&check[..4]);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let check = Sha256::digest(bytes.get(..44)?);
        if bytes.len() != RECORD_LEN || &bytes[..4] != TAG || bytes[44..] != check[..4] {
            return None;
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&bytes[4..12]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[12..44]);
        Some(Self {
            epoch: u64::from_be_bytes(epoch),
            digest,
        })
    }
}

/// The digest of a request's **canonically encoded full idempotency key**: principal,
/// caller role, `remote_client`, operation kind and request ID (ADR-0006 §7.1 as extended
/// by ADR-0012 §3.7). The canonical bytes are the domain's; this crate does not define the
/// encoding. Two clients, two roles or two operation kinds with the same request ID have
/// different canonical bytes and so different digests.
pub fn key_digest(canonical_key: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical_key).into()
}

/// What a read of the ledger found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRead {
    /// Every complete record, in the order appended.
    pub entries: Vec<Entry>,
    /// Bytes after the last complete record: an append that a stop cut short. The request
    /// it belonged to made no store write, because the append had not returned.
    pub torn_tail: usize,
}

impl LedgerRead {
    /// ⟨M08 U2b-3a⟩ The length of the complete records: where the next record goes once the
    /// torn tail is cut ([`Ledger::append_at`]'s `expected`).
    #[must_use]
    pub fn aligned_len(&self) -> u64 {
        (self.entries.len() as u64).saturating_mul(RECORD_LEN as u64)
    }
}

/// ⟨M08 U2b-3b; ADR-0006 §19.4, the ruling on U0-Q8⟩ What [`Ledger::scan`] found in a ledger
/// that may be damaged: what the attended `state repair` keeps, carries into the store as fence
/// records, and drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerScan {
    /// The records before the first damaged one, in order: the ledger is cut after them.
    pub intact: Vec<Entry>,
    /// The index of the first damaged record, or `None` when the ledger is whole (a torn tail
    /// aside).
    pub damaged_at: Option<usize>,
    /// Every record after the damage that still decodes (its tag and its check), found by
    /// reading on byte by byte from the damage, so a record shifted out of alignment is found
    /// too. These are carried into the store as fence records before the cut.
    pub after: Vec<Entry>,
    /// What after the damage did not decode, in records of [`RECORD_LEN`] bytes (rounded up),
    /// a torn tail included: dropped by the cut.
    pub dropped_records: u64,
    /// A torn tail of a whole ledger (`damaged_at` is `None`); 0 otherwise.
    pub torn_tail: usize,
}

impl LedgerScan {
    /// Every decodable entry: the intact ones and those after the damage.
    #[must_use]
    pub fn all_decodable(&self) -> Vec<Entry> {
        self.intact.iter().chain(&self.after).copied().collect()
    }

    /// Where the cut goes: the length of the intact records.
    #[must_use]
    pub fn cut_len(&self) -> u64 {
        (self.intact.len() as u64).saturating_mul(RECORD_LEN as u64)
    }
}

/// ⟨M08 U2b-3a⟩ What [`Ledger::trim_entries`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trimmed {
    /// The entries dropped, in the order they were in the ledger.
    pub dropped: Vec<Entry>,
    /// The ledger's length afterwards. When nothing was dropped the file was not rewritten,
    /// and this is its length as read (a torn tail included).
    pub len: u64,
}

/// An error from the ledger.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    /// A complete record does not check. The ledger is unreadable: a restore then treats
    /// every pre-restore request as possibly unfinished.
    #[error("the request ledger is damaged at record {0}")]
    Damaged(usize),
    /// The ledger is not a regular file, or is longer than the read limit.
    #[error("the request ledger cannot be read")]
    Unreadable,
    /// An I/O call failed. After a failed [`Ledger::append`] the request must not proceed.
    #[error("i/o error at {point:?}: {kind:?}")]
    Io {
        /// The step.
        point: Point,
        /// The error's kind.
        kind: std::io::ErrorKind,
    },
}

/// The request ledger of one state directory.
#[derive(Debug)]
pub struct Ledger<F> {
    fs: F,
    root: PathBuf,
    /// Whether this value has seen the state directory synced since the ledger file's
    /// entry last changed. Until then every append syncs it.
    dir_synced: Cell<bool>,
    /// ⟨M08 U2b-3a⟩ Bytes this value has read from the ledger file ([`Self::bytes_read`]).
    bytes_read: Cell<u64>,
}

impl<F: Fs> Ledger<F> {
    /// The ledger in the state directory `root`.
    pub fn new(fs: F, root: impl Into<PathBuf>) -> Self {
        Self {
            fs,
            root: root.into(),
            dir_synced: Cell::new(false),
            bytes_read: Cell::new(0),
        }
    }

    /// ⟨M08 U2b-3a⟩ Every byte this value has read from the ledger file so far: the cost an
    /// append adds is what this grows by (nothing, for [`Self::append_at`] at the expected
    /// length).
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.get()
    }

    fn bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let path = self.root.join(LEDGER);
        match self.fs.kind(&path) {
            Ok(Kind::Missing) => Ok(Vec::new()),
            Ok(Kind::File) => {
                let bytes = self
                    .fs
                    .read(&path, READ_LIMIT)
                    .map_err(|_| LedgerError::Unreadable)?;
                self.bytes_read
                    .set(self.bytes_read.get().saturating_add(bytes.len() as u64));
                Ok(bytes)
            }
            _ => Err(LedgerError::Unreadable),
        }
    }

    /// Every entry. A missing ledger is an empty one.
    pub fn read(&self) -> Result<LedgerRead, LedgerError> {
        let bytes = self.bytes()?;
        Self::parse(&bytes)
    }

    /// ⟨M08 U2b-3b; ADR-0006 §19.4, the ruling on U0-Q8⟩ Read the ledger **whatever its
    /// damage**, writing nothing: the records before the first damaged one, and every record
    /// after it that still decodes ([`LedgerScan`]). A ledger that is not a regular file, or is
    /// longer than the read limit, is [`LedgerError::Unreadable`]. A missing ledger is empty.
    pub fn scan(&self) -> Result<LedgerScan, LedgerError> {
        let bytes = self.bytes()?;
        if let Ok(read) = Self::parse(&bytes) {
            return Ok(LedgerScan {
                intact: read.entries,
                damaged_at: None,
                after: Vec::new(),
                dropped_records: 0,
                torn_tail: read.torn_tail,
            });
        }
        let (records, _) = bytes.as_chunks::<RECORD_LEN>();
        let mut intact = Vec::new();
        for record in records {
            match Entry::decode(record) {
                Some(entry) => intact.push(entry),
                None => break,
            }
        }
        let damaged_at = intact.len();
        let mut after = Vec::new();
        let mut undecoded = 0usize;
        let mut at = damaged_at * RECORD_LEN;
        while at < bytes.len() {
            match bytes.get(at..at + RECORD_LEN).and_then(Entry::decode) {
                Some(entry) => {
                    after.push(entry);
                    at += RECORD_LEN;
                }
                None => {
                    undecoded += 1;
                    at += 1;
                }
            }
        }
        Ok(LedgerScan {
            intact,
            damaged_at: Some(damaged_at),
            after,
            dropped_records: undecoded.div_ceil(RECORD_LEN) as u64,
            torn_tail: 0,
        })
    }

    /// ⟨M08 U2b-3b; ADR-0006 §19.4⟩ Cut the ledger to `len` bytes and sync it, then sync the
    /// state directory: the attended repair's last step, after the decodable records past the
    /// damage are fence records in the store. `len` must be a whole number of records no
    /// longer than the file. A missing ledger is left missing.
    pub fn cut(&self, len: u64) -> Result<(), LedgerError> {
        let path = self.root.join(LEDGER);
        let found = self
            .fs
            .file_len(&path)
            .map_err(|_| LedgerError::Unreadable)?;
        let Some(found) = found else {
            return Ok(());
        };
        if !len.is_multiple_of(RECORD_LEN as u64) || len > found {
            return Err(LedgerError::Unreadable);
        }
        if len != found {
            self.fs
                .truncate_sync(Point::LedgerRepair, &path, len)
                .map_err(io_at(Point::LedgerRepair))?;
        }
        self.fs
            .sync_dir(Point::LedgerDirSync, &self.root)
            .map_err(io_at(Point::LedgerDirSync))?;
        self.dir_synced.set(true);
        Ok(())
    }

    /// ⟨M08 U2b-3a⟩ The whole ledger, read and checked once, for a caller that keeps its
    /// entries in memory and appends with [`Self::append_at`] from
    /// [`LedgerRead::aligned_len`]. The same as [`Self::read`]; a damaged or unreadable
    /// ledger is refused.
    pub fn load(&self) -> Result<LedgerRead, LedgerError> {
        self.read()
    }

    /// M08-W1-R03: a final record that is all zero bytes is a torn tail too. A stop during
    /// an append, before its sync, can leave the file extended by a full record of zeros
    /// (some file systems do this after a crash). That append never returned, so its request
    /// made no store write. Only the last record, and only all zeros: any other record that
    /// does not decode is damage.
    fn parse(bytes: &[u8]) -> Result<LedgerRead, LedgerError> {
        let (records, tail) = bytes.as_chunks::<RECORD_LEN>();
        let (records, torn_record) = match records.split_last() {
            Some((last, rest)) if last.iter().all(|b| *b == 0) => (rest, RECORD_LEN),
            _ => (records, 0),
        };
        let mut entries = Vec::with_capacity(records.len());
        for (index, record) in records.iter().enumerate() {
            entries.push(Entry::decode(record).ok_or(LedgerError::Damaged(index))?);
        }
        Ok(LedgerRead {
            entries,
            torn_tail: torn_record + tail.len(),
        })
    }

    /// Append one entry and sync it. **The request's first store write comes only after
    /// this returns `Ok`.** A torn tail left by an earlier stop is cut off first, so
    /// records stay aligned. **A damaged ledger is refused** with [`LedgerError::Damaged`]
    /// and nothing is written: the request must not proceed. Returns the ledger's length
    /// afterwards.
    pub fn append(&self, entry: Entry) -> Result<u64, LedgerError> {
        let path = self.root.join(LEDGER);
        let bytes = self.bytes()?;
        let len = bytes.len();
        // Cut a torn tail (a short one, or a final record of zeros) before appending, so
        // records stay aligned and the ledger stays readable. A damaged ledger refuses the
        // append and nothing is written (ruled 2026-11-23): with damage before the tail a
        // lookup can miss an earlier record, and its request would run again. Recovery is
        // U0's attended path, as for `state_corrupt`.
        let aligned = len - Self::parse(&bytes)?.torn_tail;
        if aligned != len {
            self.fs
                .truncate_sync(Point::LedgerRepair, &path, aligned as u64)
                .map_err(io_at(Point::LedgerRepair))?;
        }
        self.write_record(&path, entry)?;
        Ok((aligned + RECORD_LEN) as u64)
    }

    /// ⟨M08 U2b-3a⟩ Append one entry to a ledger the caller last saw `expected` bytes long
    /// (by [`Self::load`]'s [`LedgerRead::aligned_len`], or an earlier append), **reading
    /// nothing**: the file's length is compared with `expected` and the record appended and
    /// synced. As for [`Self::append`], the request's first store write comes only after
    /// this returns `Ok(Some(_))`.
    ///
    /// `Ok(Some(len))`: appended; the ledger is now `len` bytes. `Ok(None)`: the file is not
    /// `expected` bytes long (a torn tail left by a failed append, or a change the caller
    /// did not make). Nothing was written; the caller loads the ledger again, which checks
    /// it whole, and appends with [`Self::append`].
    pub fn append_at(&self, entry: Entry, expected: u64) -> Result<Option<u64>, LedgerError> {
        let path = self.root.join(LEDGER);
        let found = self
            .fs
            .file_len(&path)
            .map_err(|_| LedgerError::Unreadable)?
            .unwrap_or(0);
        if found != expected || !expected.is_multiple_of(RECORD_LEN as u64) {
            return Ok(None);
        }
        self.write_record(&path, entry)?;
        Ok(Some(expected + RECORD_LEN as u64))
    }

    /// Append and sync one record, then make the file's directory entry durable once.
    fn write_record(&self, path: &std::path::Path, entry: Entry) -> Result<(), LedgerError> {
        self.fs
            .append_sync(Point::LedgerAppend, path, &entry.encode())
            .map_err(io_at(Point::LedgerAppend))?;
        // The file's directory entry must be durable too, or a later stop could lose the
        // whole ledger with entries the store has already acted on. Whether an earlier
        // process synced it cannot be known, so each value syncs the directory until one
        // sync has succeeded: a failed sync is retried by the next append, never skipped.
        if !self.dir_synced.get() {
            self.fs
                .sync_dir(Point::LedgerDirSync, &self.root)
                .map_err(io_at(Point::LedgerDirSync))?;
            self.dir_synced.set(true);
        }
        Ok(())
    }

    /// Rewrite the ledger without the entries `ended` says have ended their marker window
    /// ([`may_trim`]), by a temporary file and a rename. Returns how many were dropped. A
    /// damaged or unreadable ledger is not trimmed.
    pub fn trim(&self, ended: impl Fn(&Entry) -> bool) -> Result<usize, LedgerError> {
        self.trim_entries(ended).map(|t| t.dropped.len())
    }

    /// ⟨M08 U2b-3a⟩ [`Self::trim`], reporting which entries were dropped and the ledger's
    /// length afterwards, for a caller that keeps the entries in memory. The whole ledger is
    /// read and checked: a damaged or unreadable ledger is not trimmed.
    pub fn trim_entries(&self, ended: impl Fn(&Entry) -> bool) -> Result<Trimmed, LedgerError> {
        let read = self.read()?;
        let (dropped, kept): (Vec<Entry>, Vec<Entry>) =
            read.entries.iter().copied().partition(|e| ended(e));
        if dropped.is_empty() {
            return Ok(Trimmed {
                dropped,
                len: read.aligned_len() + read.torn_tail as u64,
            });
        }
        let kept: Vec<u8> = kept.iter().flat_map(Entry::encode).collect();
        let len = kept.len() as u64;
        self.rewrite(&kept)?;
        Ok(Trimmed { dropped, len })
    }

    /// The trim's replacement: a temporary file, synced, renamed over the ledger, and the
    /// state directory synced.
    fn rewrite(&self, kept: &[u8]) -> Result<(), LedgerError> {
        let (tmp, path) = (self.root.join(LEDGER_TMP), self.root.join(LEDGER));
        if matches!(self.fs.kind(&tmp), Ok(Kind::File)) {
            self.fs
                .remove_file(Point::Cleanup, &tmp)
                .map_err(io_at(Point::Cleanup))?;
        }
        self.fs
            .write_new(Point::LedgerRewrite, &tmp, kept)
            .map_err(io_at(Point::LedgerRewrite))?;
        self.fs
            .sync_file(Point::LedgerRewriteSync, &tmp)
            .map_err(io_at(Point::LedgerRewriteSync))?;
        self.dir_synced.set(false);
        self.fs
            .rename_over(Point::LedgerRename, &tmp, &path)
            .map_err(io_at(Point::LedgerRename))?;
        self.fs
            .sync_dir(Point::LedgerDirSync, &self.root)
            .map_err(io_at(Point::LedgerDirSync))?;
        self.dir_synced.set(true);
        Ok(())
    }
}

fn io_at(point: Point) -> impl Fn(std::io::Error) -> LedgerError {
    move |e| LedgerError::Io {
        point,
        kind: e.kind(),
    }
}

/// The entries a restore must write as fence records (`REQUEST_STALE`, reason
/// `restored_before_completion`): those with no terminal record in the staged generation
/// after the carry-forward.
pub fn unfenced(entries: &[Entry], has_terminal_record: impl Fn(&Entry) -> bool) -> Vec<Entry> {
    entries
        .iter()
        .filter(|e| !has_terminal_record(e))
        .copied()
        .collect()
}

/// What is known of a key's settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// The key is pending or its outcome is unknown: kept indefinitely.
    Unresolved,
    /// No readable store says anything about it (only the ledger survived): treated as
    /// unresolved, and kept.
    Unknown,
    /// Settled at `at`, with the retention configured for operations.
    Settled {
        /// When the operation became terminal.
        at: Timestamp,
        /// The retention that runs from settlement.
        retention: SignedDuration,
    },
}

/// Whether an entry's marker window has ended, so that a trim may drop it (ADR-0006 §7.4):
/// only a settled key, and only after its retention **and** the 30-day marker window.
pub fn may_trim(settlement: Settlement, now: Timestamp) -> bool {
    match settlement {
        Settlement::Unresolved | Settlement::Unknown => false,
        Settlement::Settled { at, retention } => at
            .checked_add(retention)
            .and_then(|expired| expired.checked_add(MARKER_WINDOW))
            .is_ok_and(|until| now >= until),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fs::{Action, Fault, FaultFs, RealFs, When};

    fn entry(epoch: u64, key: &[u8]) -> Entry {
        Entry {
            epoch,
            digest: key_digest(key),
        }
    }

    #[test]
    fn append_read_and_a_torn_tail() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        assert_eq!(
            ledger.read().expect("empty"),
            LedgerRead {
                entries: vec![],
                torn_tail: 0
            }
        );
        ledger.append(entry(1, b"a")).expect("append");
        ledger.append(entry(1, b"b")).expect("append");
        // A stop cut the third append short.
        let path = dir.path().join(LEDGER);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&entry(2, b"c").encode()[..17]);
        std::fs::write(&path, &bytes).expect("write");
        let read = ledger.read().expect("a torn tail is not damage");
        assert_eq!(
            (read.entries.clone(), read.torn_tail),
            (vec![entry(1, b"a"), entry(1, b"b")], 17)
        );
        // The next append cuts the tail off and stays aligned.
        ledger.append(entry(2, b"d")).expect("append");
        let read = ledger.read().expect("read");
        assert_eq!(
            (read.entries, read.torn_tail),
            (vec![entry(1, b"a"), entry(1, b"b"), entry(2, b"d")], 0)
        );
    }

    #[test]
    fn an_append_to_a_damaged_ledger_is_refused_and_writes_nothing() {
        // Ruled 2026-11-23: damage is anything but a torn tail. A lookup past it could miss
        // an earlier record, so no request may proceed on it.
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        for key in [b"a", b"b"] {
            ledger.append(entry(1, key)).expect("append");
        }
        let path = dir.path().join(LEDGER);
        for damage in [
            Damage::FirstRecordAltered,
            Damage::ZeroRecordNotLast,
            Damage::FinalRecordNotZero,
        ] {
            let mut bytes = std::fs::read(&path).expect("read");
            match damage {
                Damage::FirstRecordAltered => bytes[20] ^= 1,
                Damage::ZeroRecordNotLast => bytes.splice(0..0, [0u8; RECORD_LEN]).for_each(drop),
                Damage::FinalRecordNotZero => {
                    let mut last = [0u8; RECORD_LEN];
                    last[3] = 7;
                    bytes.extend_from_slice(&last);
                }
            }
            let damaged = std::fs::read(&path).map(|_| bytes.clone()).expect("read");
            std::fs::write(&path, &damaged).expect("write");
            assert!(
                matches!(ledger.append(entry(2, b"c")), Err(LedgerError::Damaged(_))),
                "{damage:?}"
            );
            assert_eq!(
                std::fs::read(&path).expect("read"),
                damaged,
                "{damage:?}: nothing was written"
            );
            // Put the healthy ledger back for the next kind of damage.
            let healthy: Vec<u8> = [entry(1, b"a"), entry(1, b"b")]
                .iter()
                .flat_map(Entry::encode)
                .collect();
            std::fs::write(&path, healthy).expect("write");
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Damage {
        FirstRecordAltered,
        ZeroRecordNotLast,
        FinalRecordNotZero,
    }

    #[test]
    fn a_final_record_of_zeros_is_a_torn_tail() {
        // Review M08-W1-R03: a stop during an append, before its sync, can leave the file
        // extended by a whole record of zeros.
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        ledger.append(entry(1, b"a")).expect("append");
        ledger.append(entry(1, b"b")).expect("append");
        let path = dir.path().join(LEDGER);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&[0u8; RECORD_LEN]);
        std::fs::write(&path, &bytes).expect("write");
        let read = ledger
            .read()
            .expect("a zero record at the end is not damage");
        assert_eq!((read.entries.len(), read.torn_tail), (2, RECORD_LEN));
        // The next append cuts it off; the ledger stays readable and can be trimmed.
        ledger.append(entry(2, b"c")).expect("append");
        let read = ledger.read().expect("read");
        assert_eq!(
            (read.entries, read.torn_tail),
            (vec![entry(1, b"a"), entry(1, b"b"), entry(2, b"c")], 0)
        );
        assert_eq!(ledger.trim(|e| e.digest == key_digest(b"a")), Ok(1));
        // A zero record that is not the last one is damage, and so is a final record that
        // is not all zeros.
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.splice(0..0, [0u8; RECORD_LEN]);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(ledger.read(), Err(LedgerError::Damaged(0)));
        let mut bytes = std::fs::read(&path).expect("read")[RECORD_LEN..].to_vec();
        let mut last = [0u8; RECORD_LEN];
        last[RECORD_LEN - 1] = 1;
        bytes.extend_from_slice(&last);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(ledger.read(), Err(LedgerError::Damaged(2)));
    }

    #[test]
    fn a_damaged_record_makes_the_ledger_unreadable_and_untrimmed() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        for key in [b"a", b"b", b"c"] {
            ledger.append(entry(1, key)).expect("append");
        }
        let path = dir.path().join(LEDGER);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[RECORD_LEN + 20] ^= 1;
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(ledger.read(), Err(LedgerError::Damaged(1)));
        assert_eq!(ledger.trim(|_| true), Err(LedgerError::Damaged(1)));
        assert_eq!(std::fs::read(&path).expect("read"), bytes);
    }

    #[test]
    fn a_failed_append_is_an_error_so_the_request_does_not_proceed() {
        for when in [When::Before, When::After] {
            let dir = tempfile::tempdir().expect("a scratch directory");
            let fault = Fault {
                point: Point::LedgerAppend,
                nth: 0,
                when,
                action: Action::Dead,
            };
            let ledger = Ledger::new(FaultFs::new(RealFs, Some(fault)), dir.path());
            assert!(matches!(
                ledger.append(entry(1, b"a")),
                Err(LedgerError::Io {
                    point: Point::LedgerAppend,
                    ..
                })
            ));
            // After a restart the entry is there or it is not; either way no store write
            // was made, and a restore fences an entry that has no record.
            let after = Ledger::new(RealFs, dir.path())
                .read()
                .expect("read")
                .entries;
            assert_eq!(after.len(), usize::from(when == When::After));
        }
    }

    #[test]
    fn the_directory_is_synced_until_one_sync_has_succeeded() {
        let syncs = |ledger: &Ledger<FaultFs<RealFs>>| {
            ledger
                .fs
                .seen()
                .iter()
                .filter(|p| **p == Point::LedgerDirSync)
                .count()
        };
        let dir = tempfile::tempdir().expect("a scratch directory");
        let fault = Fault {
            point: Point::LedgerDirSync,
            nth: 0,
            when: When::Before,
            action: Action::Error,
        };
        let ledger = Ledger::new(FaultFs::new(RealFs, Some(fault)), dir.path());
        // The record is written, the directory sync fails: the request must not proceed.
        assert!(matches!(
            ledger.append(entry(1, b"a")),
            Err(LedgerError::Io {
                point: Point::LedgerDirSync,
                ..
            })
        ));
        // The ledger is no longer empty, and the next append still syncs the directory.
        ledger.append(entry(1, b"b")).expect("append");
        assert_eq!(syncs(&ledger), 2);
        // Once it has succeeded it is not repeated.
        ledger.append(entry(1, b"c")).expect("append");
        assert_eq!(syncs(&ledger), 2);
        // A new process cannot know what an earlier one synced: it syncs once.
        let later = Ledger::new(FaultFs::new(RealFs, None), dir.path());
        later.append(entry(1, b"d")).expect("append");
        later.append(entry(1, b"e")).expect("append");
        assert_eq!(syncs(&later), 1);
        // A trim replaces the file's entry; a trim whose sync failed leaves it to the next append.
        let fault = Fault {
            point: Point::LedgerDirSync,
            nth: 0,
            when: When::Before,
            action: Action::Error,
        };
        let trimming = Ledger::new(FaultFs::new(RealFs, Some(fault)), dir.path());
        assert!(trimming.trim(|e| e.digest == key_digest(b"a")).is_err());
        trimming.append(entry(1, b"f")).expect("append");
        assert_eq!(syncs(&trimming), 2);
        assert_eq!(
            Ledger::new(RealFs, dir.path())
                .read()
                .expect("read")
                .entries
                .len(),
            5
        );
    }

    #[test]
    fn trim_drops_only_what_ended_and_survives_a_stop_at_each_step() {
        let all = [entry(1, b"a"), entry(1, b"b"), entry(2, b"c")];
        let ended = |e: &Entry| e.digest == key_digest(b"b");
        let kept = vec![all[0], all[2]];
        let points = [
            Point::LedgerRewrite,
            Point::LedgerRewriteSync,
            Point::LedgerRename,
            Point::LedgerDirSync,
        ];
        for (point, when) in points
            .into_iter()
            .flat_map(|p| [(p, When::Before), (p, When::After)])
        {
            let dir = tempfile::tempdir().expect("a scratch directory");
            for e in all {
                Ledger::new(RealFs, dir.path()).append(e).expect("append");
            }
            let fault = Fault {
                point,
                nth: 0,
                when,
                action: Action::Dead,
            };
            assert!(
                Ledger::new(FaultFs::new(RealFs, Some(fault)), dir.path())
                    .trim(ended)
                    .is_err()
            );
            // Whole before or whole after, never a mix; and a later trim finishes it.
            let ledger = Ledger::new(RealFs, dir.path());
            let now = ledger.read().expect("read").entries;
            assert!(now == all || now == kept, "{point:?} {when:?}");
            ledger.trim(ended).expect("trim");
            assert_eq!(ledger.read().expect("read").entries, kept);
        }
    }

    #[test]
    fn digests_separate_keys_and_unfenced_selects_by_record() {
        // Stand-in canonical encodings; the real one is the domain's.
        let keys: [&[u8]; 4] = [
            b"p1|owner|-|ensure|r1",
            b"p1|owner|c2|ensure|r1",
            b"p1|limited|-|ensure|r1",
            b"p1|owner|-|stop|r1",
        ];
        let entries: Vec<Entry> = keys.iter().map(|k| entry(4, k)).collect();
        let distinct: std::collections::HashSet<_> = entries.iter().map(|e| e.digest).collect();
        assert_eq!(distinct.len(), 4);
        let terminal = entries[2];
        assert_eq!(
            unfenced(&entries, |e| *e == terminal),
            vec![entries[0], entries[1], entries[3]]
        );
    }

    #[test]
    fn retention_follows_the_idempotency_contract() {
        let at: Timestamp = "2026-01-01T00:00:00Z".parse().expect("a time");
        let retention = SignedDuration::from_hours(7 * 24);
        let settled = Settlement::Settled { at, retention };
        let day = |n: i64| {
            at.checked_add(SignedDuration::from_hours(24 * n))
                .expect("in range")
        };
        let far = day(10_000);
        assert!(!may_trim(Settlement::Unresolved, far));
        assert!(!may_trim(Settlement::Unknown, far));
        assert!(!may_trim(settled, day(7)));
        assert!(!may_trim(
            settled,
            day(37)
                .checked_sub(SignedDuration::from_secs(1))
                .expect("in range")
        ));
        assert!(may_trim(settled, day(37)));
        // A retention that overflows the time range never trims.
        assert!(!may_trim(
            Settlement::Settled {
                at: Timestamp::MAX,
                retention
            },
            Timestamp::MAX
        ));
    }

    /// ⟨M08 U2b-3a⟩ An append at the expected length reads nothing, however long the ledger
    /// is; one at another length (a torn tail, a change made from outside) writes nothing and
    /// says so, and the caller's load then checks the ledger whole.
    #[test]
    fn an_append_at_the_known_length_reads_nothing() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        let loaded = ledger.load().expect("an empty ledger");
        assert_eq!(loaded.aligned_len(), 0);
        let mut len = loaded.aligned_len();
        for n in 0..300u32 {
            let before = ledger.bytes_read();
            len = ledger
                .append_at(entry(1, &n.to_be_bytes()), len)
                .expect("append")
                .expect("at the expected length");
            assert_eq!(ledger.bytes_read(), before, "append {n} read nothing");
        }
        assert_eq!(len, 300 * RECORD_LEN as u64);
        // A torn tail: nothing is written, and the caller is told to load again.
        let path = dir.path().join(LEDGER);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes.extend_from_slice(&entry(2, b"torn").encode()[..9]);
        std::fs::write(&path, &bytes).expect("write");
        assert_eq!(ledger.append_at(entry(2, b"x"), len), Ok(None));
        assert_eq!(
            std::fs::read(&path).expect("read"),
            bytes,
            "nothing was written"
        );
        let reloaded = ledger.load().expect("a torn tail is not damage");
        assert_eq!(
            (
                reloaded.entries.len(),
                reloaded.torn_tail,
                reloaded.aligned_len()
            ),
            (300, 9, len)
        );
        assert_eq!(ledger.append(entry(2, b"x")), Ok(len + RECORD_LEN as u64));
        assert_eq!(ledger.read().expect("read").torn_tail, 0);
        // A misaligned expectation is never appended at.
        assert_eq!(ledger.append_at(entry(2, b"y"), 7), Ok(None));
    }

    /// ⟨M08 U2b-3b; the ruling on U0-Q8⟩ The repair's read: the records before the damage,
    /// every record after it that still decodes (also one shifted out of alignment), and
    /// what is dropped; the cut keeps the intact records only and writes nothing else.
    #[test]
    fn scan_finds_every_decodable_record_after_the_damage_and_the_cut_keeps_the_rest() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        // A whole ledger scans as intact.
        for key in [b"a", b"b"] {
            ledger.append(entry(1, key)).expect("append");
        }
        let whole = ledger.scan().expect("scan");
        assert_eq!(
            (whole.intact.len(), whole.damaged_at, whole.after.len()),
            (2, None, 0)
        );
        // Damage the second record, then add one aligned record and one shifted by 5 bytes.
        let path = dir.path().join(LEDGER);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[RECORD_LEN + 20] ^= 1;
        bytes.extend_from_slice(&entry(2, b"c").encode());
        bytes.extend_from_slice(&[9u8; 5]);
        bytes.extend_from_slice(&entry(2, b"d").encode());
        bytes.extend_from_slice(&entry(2, b"torn").encode()[..11]);
        std::fs::write(&path, &bytes).expect("write");
        assert!(matches!(ledger.read(), Err(LedgerError::Damaged(1))));
        let scan = ledger.scan().expect("a damaged ledger still scans");
        assert_eq!(scan.intact, vec![entry(1, b"a")]);
        assert_eq!(scan.damaged_at, Some(1));
        assert_eq!(scan.after, vec![entry(2, b"c"), entry(2, b"d")]);
        // The damaged record, the 5 stray bytes and the torn 11: 64 bytes, two records.
        assert_eq!(scan.dropped_records, 2);
        assert_eq!(scan.all_decodable().len(), 3);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            bytes,
            "the scan wrote nothing"
        );
        // The cut keeps the intact records only; the ledger is whole again.
        ledger.cut(scan.cut_len()).expect("cut");
        assert_eq!(
            ledger.read().expect("whole after the cut").entries,
            vec![entry(1, b"a")]
        );
        // A cut longer than the file, or off a record boundary, writes nothing.
        assert_eq!(
            ledger.cut(RECORD_LEN as u64 * 3),
            Err(LedgerError::Unreadable)
        );
        assert_eq!(ledger.cut(7), Err(LedgerError::Unreadable));
        assert_eq!(ledger.read().expect("read").entries.len(), 1);
    }

    /// ⟨M08 U2b-3a⟩ The trim reports what it dropped and the ledger's length afterwards; with
    /// nothing to drop it rewrites nothing.
    #[test]
    fn trim_entries_reports_what_it_dropped() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let ledger = Ledger::new(RealFs, dir.path());
        for key in [b"a", b"b", b"c"] {
            ledger.append(entry(1, key)).expect("append");
        }
        let none = ledger.trim_entries(|_| false).expect("trim");
        assert_eq!((none.dropped.len(), none.len), (0, 3 * RECORD_LEN as u64));
        let trimmed = ledger
            .trim_entries(|e| e.digest != key_digest(b"b"))
            .expect("trim");
        assert_eq!(trimmed.dropped, vec![entry(1, b"a"), entry(1, b"c")]);
        assert_eq!(trimmed.len, RECORD_LEN as u64);
        assert_eq!(ledger.read().expect("read").entries, vec![entry(1, b"b")]);
        // The next append at the reported length reads nothing.
        let before = ledger.bytes_read();
        assert_eq!(
            ledger.append_at(entry(1, b"d"), trimmed.len),
            Ok(Some(2 * RECORD_LEN as u64))
        );
        assert_eq!(ledger.bytes_read(), before);
    }
}
