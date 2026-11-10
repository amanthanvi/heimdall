//! `WindowsDpapi` (ADR-0008 D1; m03-plan U4): K_ca protected with DPAPI for the
//! current user (`CryptProtectData`, no `CRYPTPROTECT_LOCAL_MACHINE`), with Heimdall
//! entropy bound to the fingerprint and `CRYPTPROTECT_UI_FORBIDDEN`, in one blob file
//! per CA, `<dir>\<fingerprint stem>.dpapi`, created exclusively with a **protected
//! owner-only DACL**. The product directory is `%LOCALAPPDATA%\Heimdall\issuer`
//! ([`WindowsDpapi::default_dir`], the local, non-roaming application data); a run
//! with `HEIMDALL_HOME` in scratch passes a scratch directory, which is still the
//! product store kind (ADR-0008 D1 "Test K_ca", D12).
//!
//! There is no plaintext fallback: an unprotect that fails is an error, never a file.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use heimdall_contract::ids::{CaFingerprint, EnvironmentId};
use heimdall_contract::issuer::StoreKind;
use heimdall_credential::cert::SecretCaKey;

use super::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef, item_label,
};
use crate::backup::{fingerprint_file_stem, fingerprint_from_file_stem};
use crate::sys::windows as sys;

/// The blob files' extension.
const EXTENSION: &str = "dpapi";
/// The fixed part of the DPAPI entropy (the fingerprint follows it).
const ENTROPY_PREFIX: &[u8] = b"heimdall-issuer/1 K_ca dpapi entropy\0";
/// The largest blob read (a protected Ed25519 OpenSSH key is well under 2 KiB).
const BLOB_MAX_BYTES: u64 = 64 * 1024;

/// The Windows DPAPI K_ca store.
#[derive(Debug, Clone)]
pub struct WindowsDpapi {
    dir: PathBuf,
    environment: String,
}

impl WindowsDpapi {
    /// The product directory, `%LOCALAPPDATA%\Heimdall\issuer`.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] (`missing`) when `LOCALAPPDATA` is unset or not
    /// absolute.
    pub fn default_dir() -> Result<PathBuf, StoreError> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(StoreError::Unavailable(StoreAvailability::Missing))?;
        Ok(base.join("Heimdall").join("issuer"))
    }

    /// The store whose blobs live in `dir` ([`Self::default_dir`], or a directory
    /// under a scratch `HEIMDALL_HOME`).
    #[must_use]
    pub fn in_dir(dir: impl Into<PathBuf>, environment: &EnvironmentId) -> Self {
        Self {
            dir: dir.into(),
            environment: environment.as_str().to_owned(),
        }
    }

    /// The blob directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The environment this store's items are recorded for.
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// The blob file of `fingerprint`.
    #[must_use]
    pub fn blob_path(&self, fingerprint: &CaFingerprint) -> PathBuf {
        self.dir.join(format!(
            "{}.{EXTENSION}",
            fingerprint_file_stem(fingerprint)
        ))
    }

    /// The DACL of `path` as SDDL, read without following a reparse point (for the
    /// owner-only check and `doctor`).
    ///
    /// # Errors
    /// The OS error.
    pub fn dacl_sddl(path: &Path) -> std::io::Result<String> {
        sys::dacl_sddl(path)
    }

    /// The protected owner-only DACL a blob carries (`D:P(A;;FA;;;<user SID>)`).
    ///
    /// # Errors
    /// The OS error (the process token cannot be read).
    pub fn expected_blob_dacl() -> std::io::Result<String> {
        Ok(sys::owner_only_dacl(&sys::current_user_sid()?, false))
    }

    fn entropy(fingerprint: &CaFingerprint) -> Vec<u8> {
        let mut e = ENTROPY_PREFIX.to_vec();
        e.extend_from_slice(fingerprint.as_str().as_bytes());
        e
    }

    fn ensure_dir(&self) -> Result<(), StoreError> {
        if self.dir.is_dir() {
            return Ok(());
        }
        if let Some(parent) = self.dir.parent() {
            std::fs::create_dir_all(parent).map_err(|_| StoreError::Failed)?;
        }
        match sys::create_owner_only_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && self.dir.is_dir() => Ok(()),
            Err(_) => Err(StoreError::Failed),
        }
    }

    fn reference(&self, fingerprint: &CaFingerprint) -> StoreItemRef {
        StoreItemRef {
            kind: self.kind(),
            fingerprint: fingerprint.clone(),
            locator: self.blob_path(fingerprint).to_string_lossy().into_owned(),
        }
    }
}

impl SecretStore for WindowsDpapi {
    fn kind(&self) -> SecretStoreKind {
        SecretStoreKind::Product(StoreKind::WindowsDpapi)
    }

    fn availability(&self) -> StoreAvailability {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(m) if m.is_dir() => StoreAvailability::Available,
            Ok(_) => StoreAvailability::Corrupt,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreAvailability::Available,
            Err(_) => StoreAvailability::Missing,
        }
    }

    fn put(
        &self,
        fingerprint: &CaFingerprint,
        key: &SecretCaKey,
    ) -> Result<StoreItemRef, StoreError> {
        if key.fingerprint().map_err(|_| StoreError::Failed)? != *fingerprint {
            return Err(StoreError::Failed);
        }
        match self.availability() {
            StoreAvailability::Available => {}
            other => return Err(StoreError::Unavailable(other)),
        }
        self.ensure_dir()?;
        let path = self.blob_path(fingerprint);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(StoreError::AlreadyExists);
        }
        let secret = key.to_secret_bytes().map_err(|_| StoreError::Failed)?;
        // The blob's description carries the label and the environment ID attribute.
        let description = format!("{} {}", item_label(fingerprint), self.environment);
        let sealed = sys::protect(&secret, &Self::entropy(fingerprint), &description)
            .map_err(|_| StoreError::Failed)?;
        drop(secret);
        let mut file = sys::create_owner_only_new(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StoreError::AlreadyExists
            } else {
                StoreError::Failed
            }
        })?;
        file.write_all(&sealed).map_err(|_| StoreError::Failed)?;
        file.sync_all().map_err(|_| StoreError::Failed)?;
        Ok(self.reference(fingerprint))
    }

    fn get(&self, fingerprint: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        let path = self.blob_path(fingerprint);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(_) => return Err(StoreError::Failed),
        };
        let mut sealed = Vec::new();
        file.take(BLOB_MAX_BYTES + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| StoreError::Failed)?;
        if u64::try_from(sealed.len()).unwrap_or(u64::MAX) > BLOB_MAX_BYTES {
            return Err(StoreError::Corrupt);
        }
        let secret = sys::unprotect(&sealed, &Self::entropy(fingerprint))
            .map_err(|_| StoreError::Corrupt)?;
        let key = SecretCaKey::from_secret_bytes(&secret).map_err(|_| StoreError::Corrupt)?;
        if key.fingerprint().map_err(|_| StoreError::Corrupt)? != *fingerprint {
            return Err(StoreError::Corrupt);
        }
        Ok(key)
    }

    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        let expected = self.reference(&item.fingerprint);
        if *item != expected {
            return Err(StoreError::Failed);
        }
        let path = self.blob_path(&item.fingerprint);
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
