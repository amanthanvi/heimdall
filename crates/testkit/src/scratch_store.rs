//! `ScratchSecretStore`: the test-configuration K_ca store (ADR-0008 D1 "Test K_ca";
//! m03-plan U0 "Frozen in wave 0", U4; F23). Feature `managed`.
//!
//! It implements the issuer's frozen [`SecretStore`] trait with the testkit-side kind
//! [`SCRATCH_TEST`], which is **not** a variant of the public `StoreKind`: fixture
//! custody never appears in the public schema and never satisfies a product-store
//! claim (ADR-0008 D12).
//!
//! **Format.** Each item is one file, `<dir>/<fingerprint stem>.key`
//! (`heimdall_issuer::backup::fingerprint_file_stem`), holding K_ca in the D5 form
//! (OpenSSH, bcrypt-pbkdf + aes256-ctr) under the run's passphrase. The per-run
//! passphrase is generated from the operating system's CSPRNG on the store's first
//! write and kept in `<dir>/scratch-store.passphrase` (created exclusively, mode 0600
//! on Unix), so another process of the same run (the issuer child) can read the items.
//! It is fixture custody: the passphrase sits beside the items, inside the run's
//! scratch directory, which the run removes. Nothing is ever written in plaintext.
//!
//! [`ScratchSecretStore::with_availability`] makes a store that reports a chosen
//! unavailability and refuses every operation with it, writing nothing (the
//! `no_plaintext_when_store_unavailable` rows).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use heimdall_contract::ids::CaFingerprint;
use heimdall_credential::cert::SecretCaKey;
use heimdall_issuer::backup::{Passphrase, fingerprint_file_stem, fingerprint_from_file_stem};
use heimdall_issuer::store::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef,
};

/// The testkit-side store kind name (`scratch_test`; F23).
pub const SCRATCH_TEST: &str = "scratch_test";

/// The per-run passphrase file's name inside the store directory.
pub const PASSPHRASE_FILE: &str = "scratch-store.passphrase";

/// The item files' extension.
const EXTENSION: &str = "key";

/// The largest item or passphrase file read.
const FILE_MAX_BYTES: u64 = 64 * 1024;

/// The scratch K_ca store, rooted at a directory the test run created.
#[derive(Debug)]
pub struct ScratchSecretStore {
    dir: PathBuf,
    forced: Option<StoreAvailability>,
}

impl ScratchSecretStore {
    /// A store whose items live under `dir` (the run's scratch state directory).
    /// Nothing is created until the first [`SecretStore::put`].
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            forced: None,
        }
    }

    /// A store under `dir` that reports `availability` and, unless it is
    /// `Available`, refuses every operation with it and touches nothing.
    #[must_use]
    pub fn with_availability(dir: impl Into<PathBuf>, availability: StoreAvailability) -> Self {
        Self {
            dir: dir.into(),
            forced: Some(availability),
        }
    }

    /// The scratch directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The item file of `fingerprint`.
    #[must_use]
    pub fn item_path(&self, fingerprint: &CaFingerprint) -> PathBuf {
        self.dir.join(format!(
            "{}.{EXTENSION}",
            fingerprint_file_stem(fingerprint)
        ))
    }

    fn refused(&self) -> Option<StoreError> {
        match self.forced {
            Some(StoreAvailability::Available) | None => None,
            Some(a) => Some(StoreError::Unavailable(a)),
        }
    }

    fn reference(&self, fingerprint: &CaFingerprint) -> StoreItemRef {
        StoreItemRef {
            kind: self.kind(),
            fingerprint: fingerprint.clone(),
            locator: self.item_path(fingerprint).to_string_lossy().into_owned(),
        }
    }

    fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(FILE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > FILE_MAX_BYTES {
            return Err(std::io::Error::other("too large"));
        }
        Ok(bytes)
    }

    fn create_new(path: &Path) -> std::io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }

    /// The run's passphrase: read, or (when `create`) generated and written
    /// exclusively; a concurrent creator's file wins.
    fn passphrase(&self, create: bool) -> Result<Passphrase, StoreError> {
        let path = self.dir.join(PASSPHRASE_FILE);
        match Self::read_bounded(&path) {
            Ok(bytes) => return Passphrase::from_utf8(bytes).ok_or(StoreError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound);
            }
            Err(_) => return Err(StoreError::Failed),
        }
        let fresh = Passphrase::generate().map_err(|_| StoreError::Failed)?;
        // ⟨integrator, wave-1 review⟩ Publish atomically: write a private temporary file
        // completely, then hard-link it into place (which fails if the name exists), so
        // a concurrent reader never sees a created-but-empty passphrase file and never
        // encrypts or decrypts under an empty passphrase.
        let mut nonce = [0u8; 8];
        heimdall_credential::vault::SystemRng::fill(&mut nonce).map_err(|_| StoreError::Failed)?;
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = self.dir.join(format!("{PASSPHRASE_FILE}.{suffix}.tmp"));
        let written = Self::create_new(&tmp).and_then(|mut file| {
            file.write_all(fresh.expose().as_bytes())
                .and_then(|()| file.sync_all())
        });
        let linked = written.and_then(|()| std::fs::hard_link(&tmp, &path));
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(fresh),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => self.passphrase(false),
            Err(_) => Err(StoreError::Failed),
        }
    }
}

impl SecretStore for ScratchSecretStore {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Test(SCRATCH_TEST)
    }

    fn availability(&self) -> StoreAvailability {
        if let Some(a) = self.forced {
            return a;
        }
        match std::fs::symlink_metadata(&self.dir) {
            Ok(m) if m.is_dir() => StoreAvailability::Available,
            Ok(_) => StoreAvailability::Corrupt,
            Err(_) => StoreAvailability::Missing,
        }
    }

    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        if let Some(e) = self.refused() {
            return Err(e);
        }
        match self.availability() {
            StoreAvailability::Available => {}
            other => return Err(StoreError::Unavailable(other)),
        }
        if key.fingerprint().map_err(|_| StoreError::Failed)? != *fingerprint {
            return Err(StoreError::Failed);
        }
        let path = self.item_path(fingerprint);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(StoreError::AlreadyExists);
        }
        let passphrase = self.passphrase(true)?;
        let sealed = key
            .encrypt_openssh(passphrase.expose().as_bytes())
            .map_err(|_| StoreError::Failed)?;
        let mut file = Self::create_new(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::AlreadyExists
            } else {
                StoreError::Failed
            }
        })?;
        file.write_all(&sealed)
            .and_then(|()| file.sync_all())
            .map_err(|_| StoreError::Failed)?;
        Ok(self.reference(fingerprint))
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        if let Some(e) = self.refused() {
            return Err(e);
        }
        let sealed = match Self::read_bounded(&self.item_path(fingerprint)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(_) => return Err(StoreError::Failed),
        };
        let passphrase = match self.passphrase(false) {
            Ok(p) => p,
            Err(StoreError::NotFound) => return Err(StoreError::Corrupt),
            Err(e) => return Err(e),
        };
        let key = SecretCaKey::decrypt_openssh(&sealed, passphrase.expose().as_bytes())
            .map_err(|_| StoreError::Corrupt)?;
        if key.fingerprint().map_err(|_| StoreError::Corrupt)? != *fingerprint {
            return Err(StoreError::Corrupt);
        }
        Ok(key)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        if let Some(e) = self.refused() {
            return Err(e);
        }
        if *item != self.reference(&item.fingerprint) {
            return Err(StoreError::Failed);
        }
        let path = self.item_path(&item.fingerprint);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(_) => return Err(StoreError::Failed),
        }
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(StoreError::Failed);
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        if let Some(e) = self.refused() {
            return Err(e);
        }
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(StoreError::Failed),
        };
        let mut items = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| StoreError::Failed)?;
            let name = entry.file_name();
            let Some(stem) = name
                .to_str()
                .and_then(|n| n.strip_suffix(&format!(".{EXTENSION}")))
            else {
                continue;
            };
            if let Some(fp) = fingerprint_from_file_stem(stem) {
                items.push(self.reference(&fp));
            }
        }
        items.sort_by(|a, b| a.fingerprint.as_str().cmp(b.fingerprint.as_str()));
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_store_is_test_kind_and_an_unavailable_one_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ScratchSecretStore::new(dir.path());
        assert_eq!(store.kind(), SecretStoreKind::Test(SCRATCH_TEST));
        assert_eq!(store.kind().product(), None);
        assert_eq!(store.availability(), StoreAvailability::Available);
        assert_eq!(store.list(), Ok(Vec::new()));
        let fp = CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
        let locked = ScratchSecretStore::with_availability(dir.path(), StoreAvailability::Locked);
        assert_eq!(locked.availability(), StoreAvailability::Locked);
        let key = SecretCaKey::generate().unwrap();
        let kfp = key.fingerprint().unwrap();
        assert_eq!(
            locked.put(&kfp, &key).err(),
            Some(StoreError::Unavailable(StoreAvailability::Locked))
        );
        // Nothing was written into the scratch directory.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
