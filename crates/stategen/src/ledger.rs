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
}

impl<F: Fs> Ledger<F> {
    /// The ledger in the state directory `root`.
    pub fn new(fs: F, root: impl Into<PathBuf>) -> Self {
        Self {
            fs,
            root: root.into(),
            dir_synced: Cell::new(false),
        }
    }

    fn bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let path = self.root.join(LEDGER);
        match self.fs.kind(&path) {
            Ok(Kind::Missing) => Ok(Vec::new()),
            Ok(Kind::File) => self
                .fs
                .read(&path, READ_LIMIT)
                .map_err(|_| LedgerError::Unreadable),
            _ => Err(LedgerError::Unreadable),
        }
    }

    /// Every entry. A missing ledger is an empty one.
    pub fn read(&self) -> Result<LedgerRead, LedgerError> {
        let bytes = self.bytes()?;
        Self::parse(&bytes)
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
    /// records stay aligned.
    pub fn append(&self, entry: Entry) -> Result<(), LedgerError> {
        let path = self.root.join(LEDGER);
        let bytes = self.bytes()?;
        let len = bytes.len();
        // Cut a torn tail (a short one, or a final record of zeros) before appending, so
        // records stay aligned and the ledger stays readable. A damaged ledger is not
        // repaired here and does not stop the append (as before): only its short tail is
        // cut, and a restore treats the ledger as unreadable, behind the epoch fence.
        let torn = Self::parse(&bytes).map_or(len % RECORD_LEN, |r| r.torn_tail);
        let aligned = len - torn;
        if aligned != len {
            self.fs
                .truncate_sync(Point::LedgerRepair, &path, aligned as u64)
                .map_err(io_at(Point::LedgerRepair))?;
        }
        self.fs
            .append_sync(Point::LedgerAppend, &path, &entry.encode())
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
        let before = self.read()?.entries;
        let kept: Vec<u8> = before
            .iter()
            .filter(|e| !ended(e))
            .flat_map(Entry::encode)
            .collect();
        let dropped = before.len() - kept.len() / RECORD_LEN;
        if dropped == 0 {
            return Ok(0);
        }
        let (tmp, path) = (self.root.join(LEDGER_TMP), self.root.join(LEDGER));
        if matches!(self.fs.kind(&tmp), Ok(Kind::File)) {
            self.fs
                .remove_file(Point::Cleanup, &tmp)
                .map_err(io_at(Point::Cleanup))?;
        }
        self.fs
            .write_new(Point::LedgerRewrite, &tmp, &kept)
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
        Ok(dropped)
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
}
