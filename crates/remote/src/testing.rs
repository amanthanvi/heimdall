//! In-memory implementations of this crate's ports, for this crate's tests and the
//! `model_remote_roles` target. Not a supported API (hidden from the docs).
//!
//! * [`MemoryLines`]: authorized_keys files in memory. The first file is the one Heimdall
//!   writes; edits preserve every other line verbatim; writes can be made to fail, which
//!   stands in for a crash between a database commit and the file write.
//! * [`MemoryWidening`]: runner-local widening records in memory, with the compare-and-set
//!   the port requires.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use heimdall_contract::Timestamp;
use heimdall_contract::envelope::Envelope;
use heimdall_contract::ids::{ClientId, DecisionId};
use heimdall_domain::decision::DecisionState;

use crate::line::{KeysFile, LineIoError, ManagementLines, parse_key_line};
use crate::widening::{LedgerError, WideningKey, WideningRecord, WideningRecords};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Authorized_keys files in memory (module docs).
#[derive(Debug)]
pub struct MemoryLines {
    files: Mutex<Vec<KeysFile>>,
    fail_writes: AtomicBool,
    writes: AtomicUsize,
}

impl MemoryLines {
    /// Files named `names`, each starting with `seed` lines (`seed[i]` for file `i`).
    #[must_use]
    pub fn new(files: Vec<KeysFile>) -> Self {
        Self {
            files: Mutex::new(files),
            fail_writes: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
        }
    }

    /// The default pair sshd consults: `authorized_keys` (written) and `authorized_keys2`.
    #[must_use]
    pub fn default_pair() -> Self {
        Self::new(vec![
            KeysFile {
                name: "authorized_keys".into(),
                text: String::new(),
            },
            KeysFile {
                name: "authorized_keys2".into(),
                text: String::new(),
            },
        ])
    }

    /// Make every later write fail (`true`) or succeed again (`false`).
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }

    /// Successful writes so far.
    #[must_use]
    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    /// The current files.
    #[must_use]
    pub fn files(&self) -> Vec<KeysFile> {
        lock(&self.files).clone()
    }

    /// Append a raw line to file `index` (a user's own edit).
    pub fn append(&self, index: usize, line: &str) {
        if let Some(f) = lock(&self.files).get_mut(index) {
            f.text.push_str(line);
            f.text.push('\n');
        }
    }

    fn strip(text: &str, client: &ClientId) -> String {
        text.lines()
            .filter(|l| !parse_key_line(l).is_some_and(|k| k.is_marked_for(client)))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    fn write(&self, edit: impl FnOnce(&mut Vec<KeysFile>)) -> Result<(), LineIoError> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(LineIoError::Io);
        }
        let mut files = lock(&self.files);
        if files.is_empty() {
            return Err(LineIoError::Unavailable);
        }
        edit(&mut files);
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl ManagementLines for MemoryLines {
    fn read_all(&self) -> Result<Vec<KeysFile>, LineIoError> {
        Ok(self.files())
    }

    fn put(&self, client: &ClientId, line: &str) -> Result<(), LineIoError> {
        self.write(|files| {
            for f in files.iter_mut() {
                f.text = Self::strip(&f.text, client);
            }
            files[0].text.push_str(line);
            files[0].text.push('\n');
        })
    }

    fn remove(&self, client: &ClientId) -> Result<(), LineIoError> {
        self.write(|files| {
            for f in files.iter_mut() {
                f.text = Self::strip(&f.text, client);
            }
        })
    }
}

/// Runner-local widening records in memory (module docs).
#[derive(Debug, Default)]
pub struct MemoryWidening {
    records: Mutex<BTreeMap<String, WideningRecord>>,
}

impl MemoryWidening {
    /// Empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every record, by decision ID.
    #[must_use]
    pub fn all(&self) -> Vec<WideningRecord> {
        lock(&self.records).values().cloned().collect()
    }
}

impl WideningRecords for MemoryWidening {
    fn pending_counts(
        &self,
        client: &ClientId,
        now: Timestamp,
    ) -> Result<(usize, usize), LedgerError> {
        let map = lock(&self.records);
        let pending = map
            .values()
            .filter(|r| {
                !r.key.submitter.is_local()
                    && r.state == DecisionState::Pending
                    && now < r.expires_at
            })
            .collect::<Vec<_>>();
        let mine = pending
            .iter()
            .filter(|r| r.key.submitter.client() == Some(client))
            .count();
        Ok((mine, pending.len()))
    }

    fn expired_marker(&self, _key: &WideningKey, _now: Timestamp) -> Result<bool, LedgerError> {
        // Nothing is purged from memory.
        Ok(false)
    }

    fn by_key(&self, key: &WideningKey) -> Result<Option<WideningRecord>, LedgerError> {
        if key.submitter.is_local() {
            return Ok(None);
        }
        Ok(lock(&self.records)
            .values()
            .find(|r| &r.key == key)
            .cloned())
    }

    fn by_decision(&self, id: &DecisionId) -> Result<Option<WideningRecord>, LedgerError> {
        Ok(lock(&self.records).get(id.as_str()).cloned())
    }

    fn pending_local(
        &self,
        kind: &str,
        delta_digest: &str,
    ) -> Result<Option<WideningRecord>, LedgerError> {
        Ok(lock(&self.records)
            .values()
            .find(|r| {
                r.key.submitter.is_local()
                    && r.key.kind == kind
                    && r.delta_digest.as_deref() == Some(delta_digest)
                    && r.state == DecisionState::Pending
            })
            .cloned())
    }

    fn insert(&self, record: WideningRecord) -> Result<(), LedgerError> {
        let mut map = lock(&self.records);
        let taken = if record.key.submitter.is_local() {
            map.values().any(|r| {
                r.key.submitter.is_local()
                    && r.key.kind == record.key.kind
                    && r.delta_digest == record.delta_digest
                    && r.state == DecisionState::Pending
            })
        } else {
            map.values().any(|r| r.key == record.key)
        };
        if map.contains_key(record.decision.as_str()) || taken {
            return Err(LedgerError::Exists);
        }
        map.insert(record.decision.as_str().to_owned(), record);
        Ok(())
    }

    fn settle(
        &self,
        id: &DecisionId,
        state: DecisionState,
        at: Timestamp,
        result: Option<Envelope<serde_json::Value>>,
    ) -> Result<WideningRecord, LedgerError> {
        let mut map = lock(&self.records);
        let rec = map.get_mut(id.as_str()).ok_or(LedgerError::Missing)?;
        if rec.state != DecisionState::Pending {
            return Err(LedgerError::Moved);
        }
        rec.state = state;
        rec.decided_at = Some(at);
        rec.result = result;
        Ok(rec.clone())
    }

    fn record_result(
        &self,
        id: &DecisionId,
        result: Envelope<serde_json::Value>,
    ) -> Result<WideningRecord, LedgerError> {
        let mut map = lock(&self.records);
        let rec = map.get_mut(id.as_str()).ok_or(LedgerError::Missing)?;
        if rec.state != DecisionState::Approved || rec.result.is_some() {
            return Err(LedgerError::Moved);
        }
        rec.result = Some(result);
        Ok(rec.clone())
    }
}
