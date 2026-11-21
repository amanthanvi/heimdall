//! **Test store** for K_mgmt (fixture custody; mechanism evidence only). It reports
//! [`MgmtStoreKind::Test`] (`fixture_test`), so it can never satisfy a product-store claim.
//! In memory by default; [`FixtureMgmtStore::file`] (debug builds only, the test
//! configuration's `HEIMDALL_TEST_MGMT_STORE=fixture-file:<abs path>`) keeps the item in a
//! scratch file so separate processes of one test share it. A lock flag stands in for a
//! locked platform store.

#[cfg(debug_assertions)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use super::{MgmtKey, MgmtKeyStore, MgmtStoreAvailability, MgmtStoreError, MgmtStoreKind};

/// The fixture store's kind name.
pub const FIXTURE_KIND: &str = "fixture_test";

#[derive(Debug)]
enum Backing {
    Memory(Mutex<Option<Zeroizing<Vec<u8>>>>),
    #[cfg(debug_assertions)]
    File(PathBuf),
}

/// The fixture K_mgmt store (module docs).
#[derive(Debug)]
pub struct FixtureMgmtStore {
    backing: Backing,
    locked: AtomicBool,
}

impl FixtureMgmtStore {
    /// An empty, unlocked store in memory.
    #[must_use]
    pub fn in_memory() -> FixtureMgmtStore {
        FixtureMgmtStore {
            backing: Backing::Memory(Mutex::new(None)),
            locked: AtomicBool::new(false),
        }
    }

    /// **Debug builds only**: a store whose item is the scratch file `path` (absolute).
    /// The lock flag is the sibling file `<path>.locked`, so a test can lock the store of
    /// another process.
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn file(path: PathBuf) -> FixtureMgmtStore {
        FixtureMgmtStore {
            backing: Backing::File(path),
            locked: AtomicBool::new(false),
        }
    }

    /// Lock the store: every read and write is refused as a locked platform store's.
    pub fn lock(&self) {
        self.locked.store(true, Ordering::SeqCst);
    }

    /// Unlock the store.
    pub fn unlock(&self) {
        self.locked.store(false, Ordering::SeqCst);
    }

    /// Whether an item is stored (read regardless of the lock, for tests).
    #[must_use]
    pub fn holds_item(&self) -> bool {
        matches!(self.read_raw(), Ok(Some(_)))
    }

    fn is_locked(&self) -> bool {
        if self.locked.load(Ordering::SeqCst) {
            return true;
        }
        match &self.backing {
            Backing::Memory(_) => false,
            #[cfg(debug_assertions)]
            Backing::File(path) => {
                let mut flag = path.clone().into_os_string();
                flag.push(".locked");
                std::fs::symlink_metadata(PathBuf::from(flag)).is_ok()
            }
        }
    }

    fn read_raw(&self) -> Result<Option<Zeroizing<Vec<u8>>>, MgmtStoreError> {
        match &self.backing {
            Backing::Memory(m) => Ok(m.lock().unwrap_or_else(PoisonError::into_inner).clone()),
            #[cfg(debug_assertions)]
            Backing::File(path) => match std::fs::read(path) {
                Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(MgmtStoreError::Failed),
            },
        }
    }

    fn check_unlocked(&self) -> Result<(), MgmtStoreError> {
        if self.is_locked() {
            Err(MgmtStoreError::Unavailable(MgmtStoreAvailability::Locked))
        } else {
            Ok(())
        }
    }
}

impl MgmtKeyStore for FixtureMgmtStore {
    fn kind(&self) -> MgmtStoreKind {
        MgmtStoreKind::Test(FIXTURE_KIND)
    }

    fn availability(&self) -> MgmtStoreAvailability {
        if self.is_locked() {
            MgmtStoreAvailability::Locked
        } else {
            MgmtStoreAvailability::Available
        }
    }

    fn put(&self, key: &MgmtKey) -> Result<(), MgmtStoreError> {
        self.check_unlocked()?;
        let bytes = key.to_store_bytes();
        match &self.backing {
            Backing::Memory(m) => {
                let mut slot = m.lock().unwrap_or_else(PoisonError::into_inner);
                if slot.is_some() {
                    return Err(MgmtStoreError::AlreadyExists);
                }
                *slot = Some(bytes);
                Ok(())
            }
            #[cfg(debug_assertions)]
            Backing::File(path) => {
                use std::io::Write as _;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                let mut file = options.open(path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        MgmtStoreError::AlreadyExists
                    } else {
                        MgmtStoreError::Failed
                    }
                })?;
                file.write_all(&bytes).map_err(|_| MgmtStoreError::Failed)?;
                file.sync_all().map_err(|_| MgmtStoreError::Failed)
            }
        }
    }

    fn load(&self) -> Result<MgmtKey, MgmtStoreError> {
        self.check_unlocked()?;
        let bytes = self.read_raw()?.ok_or(MgmtStoreError::NotFound)?;
        MgmtKey::from_store_bytes(&bytes).map_err(|_| MgmtStoreError::Corrupt)
    }

    fn destroy(&self) -> Result<(), MgmtStoreError> {
        self.check_unlocked()?;
        match &self.backing {
            Backing::Memory(m) => {
                let mut slot = m.lock().unwrap_or_else(PoisonError::into_inner);
                match slot.take() {
                    Some(_) => Ok(()),
                    None => Err(MgmtStoreError::NotFound),
                }
            }
            #[cfg(debug_assertions)]
            Backing::File(path) => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(MgmtStoreError::NotFound),
                Err(_) => Err(MgmtStoreError::Failed),
            },
        }
    }
}
