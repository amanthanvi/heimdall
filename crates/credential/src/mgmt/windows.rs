//! `WindowsDpapiMgmt` (ADR-0012 §3.4; ADR-0005 §5.1/§5.2; m06-plan U2): K_mgmt protected
//! with DPAPI for the current user (`CryptProtectData`, never `CRYPTPROTECT_LOCAL_MACHINE`),
//! with Heimdall entropy bound to the environment ID and `CRYPTPROTECT_UI_FORBIDDEN`, in
//! one blob file [`BLOB_FILE`] created exclusively with a **protected owner-only DACL**.
//! The product directory is `%LOCALAPPDATA%\Heimdall\mgmt\<environment ID>`
//! ([`WindowsDpapiMgmt::default_dir`], the local, non-roaming application data, one
//! directory per installation); a run with `HEIMDALL_HOME` in scratch passes a scratch
//! directory ([`WindowsDpapiMgmt::in_dir`]), which is still the product store kind.
//!
//! DPAPI never prompts here, and there is no plaintext fallback: an unprotect that fails
//! is an error, never a file. `put` never overwrites, and `destroy` removes exactly the
//! blob file of this installation.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::issuer::StoreKind;

use super::{
    MgmtKey, MgmtKeyStore, MgmtStoreAvailability, MgmtStoreError, MgmtStoreKind, item_label,
};
use crate::sys::windows as sys;

/// The blob file's name.
pub const BLOB_FILE: &str = "k_mgmt.dpapi";
/// The fixed part of the DPAPI entropy (the environment ID follows it).
const ENTROPY_PREFIX: &[u8] = b"heimdall-mgmt/1 K_mgmt dpapi entropy\0";
/// The largest blob read (a protected 56-byte secret is a few hundred bytes).
const BLOB_MAX_BYTES: u64 = 64 * 1024;

/// The Windows DPAPI K_mgmt store of one installation.
#[derive(Debug, Clone)]
pub struct WindowsDpapiMgmt {
    dir: PathBuf,
    environment: String,
    label: String,
}

impl WindowsDpapiMgmt {
    /// The product directory of the installation `environment`,
    /// `%LOCALAPPDATA%\Heimdall\mgmt\<environment ID>` (one per installation).
    ///
    /// # Errors
    /// [`MgmtStoreError::Unavailable`] (`missing`) when `LOCALAPPDATA` is unset or not
    /// absolute.
    pub fn default_dir(environment: &EnvironmentId) -> Result<PathBuf, MgmtStoreError> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(MgmtStoreError::Unavailable(MgmtStoreAvailability::Missing))?;
        Ok(base
            .join("Heimdall")
            .join("mgmt")
            .join(environment.as_str()))
    }

    /// The store whose blob lives in `dir` ([`Self::default_dir`], or a directory under a
    /// scratch `HEIMDALL_HOME`).
    #[must_use]
    pub fn in_dir(dir: impl Into<PathBuf>, environment: &EnvironmentId) -> Self {
        Self {
            dir: dir.into(),
            environment: environment.as_str().to_owned(),
            label: item_label(environment),
        }
    }

    /// The blob directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The blob file.
    #[must_use]
    pub fn blob_path(&self) -> PathBuf {
        self.dir.join(BLOB_FILE)
    }

    /// The DACL of `path` as SDDL, read without following a reparse point (for the
    /// owner-only check and `doctor`).
    ///
    /// # Errors
    /// The OS error.
    pub fn dacl_sddl(path: &Path) -> std::io::Result<String> {
        sys::dacl_sddl(path)
    }

    /// The protected owner-only DACL the blob carries (`D:P(A;;FA;;;<user SID>)`).
    ///
    /// # Errors
    /// The OS error (the process token cannot be read).
    pub fn expected_blob_dacl() -> std::io::Result<String> {
        Ok(sys::owner_only_dacl(&sys::current_user_sid()?, false))
    }

    fn entropy(&self) -> Vec<u8> {
        let mut e = ENTROPY_PREFIX.to_vec();
        e.extend_from_slice(self.environment.as_bytes());
        e
    }

    fn ensure_dir(&self) -> Result<(), MgmtStoreError> {
        if self.dir.is_dir() {
            return Ok(());
        }
        if let Some(parent) = self.dir.parent() {
            std::fs::create_dir_all(parent).map_err(|_| MgmtStoreError::Failed)?;
        }
        match sys::create_owner_only_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && self.dir.is_dir() => Ok(()),
            Err(_) => Err(MgmtStoreError::Failed),
        }
    }
}

impl MgmtKeyStore for WindowsDpapiMgmt {
    fn kind(&self) -> MgmtStoreKind {
        MgmtStoreKind::Product(StoreKind::WindowsDpapi)
    }

    fn availability(&self) -> MgmtStoreAvailability {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(m) if m.is_dir() => MgmtStoreAvailability::Available,
            Ok(_) => MgmtStoreAvailability::Corrupt,
            // The directory is created, owner-only, by the first `put`.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => MgmtStoreAvailability::Available,
            Err(_) => MgmtStoreAvailability::Missing,
        }
    }

    fn put(&self, key: &MgmtKey) -> Result<(), MgmtStoreError> {
        match self.availability() {
            MgmtStoreAvailability::Available => {}
            other => return Err(MgmtStoreError::Unavailable(other)),
        }
        self.ensure_dir()?;
        let path = self.blob_path();
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(MgmtStoreError::AlreadyExists);
        }
        let secret = key.to_store_bytes();
        // The blob's description carries the label (the item's identity).
        let sealed = sys::protect(&secret, &self.entropy(), &self.label)
            .map_err(|_| MgmtStoreError::Failed)?;
        drop(secret);
        let mut file = sys::create_owner_only_new(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                MgmtStoreError::AlreadyExists
            } else {
                MgmtStoreError::Failed
            }
        })?;
        let written = file.write_all(&sealed).and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() {
            // Our own just-created, incomplete blob: leave no half-written item behind.
            let _ = std::fs::remove_file(&path);
            return Err(MgmtStoreError::Failed);
        }
        Ok(())
    }

    fn load(&self) -> Result<MgmtKey, MgmtStoreError> {
        let file = match std::fs::File::open(self.blob_path()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(MgmtStoreError::NotFound);
            }
            Err(_) => return Err(MgmtStoreError::Failed),
        };
        let mut sealed = Vec::new();
        file.take(BLOB_MAX_BYTES + 1)
            .read_to_end(&mut sealed)
            .map_err(|_| MgmtStoreError::Failed)?;
        if u64::try_from(sealed.len()).unwrap_or(u64::MAX) > BLOB_MAX_BYTES {
            return Err(MgmtStoreError::Corrupt);
        }
        let secret =
            sys::unprotect(&sealed, &self.entropy()).map_err(|_| MgmtStoreError::Corrupt)?;
        MgmtKey::from_store_bytes(&secret).map_err(|_| MgmtStoreError::Corrupt)
    }

    fn destroy(&self) -> Result<(), MgmtStoreError> {
        let path = self.blob_path();
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(MgmtStoreError::NotFound);
            }
            Err(_) => return Err(MgmtStoreError::Failed),
        }
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(MgmtStoreError::Failed);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn environment() -> EnvironmentId {
        EnvironmentId::from_random_bytes([6; 16])
    }

    /// Fixture/mechanism evidence only (a scratch directory standing in for
    /// `%LOCALAPPDATA%\Heimdall\mgmt\<environment ID>`; the owner's DPAPI items are never
    /// touched): put, load and destroy round trip, `put` never overwrites, the blob holds
    /// no plaintext key and carries the protected owner-only DACL, and another
    /// installation's entropy does not decrypt it. Compile-checked on non-Windows hosts;
    /// run only on native Windows.
    #[test]
    fn dpapi_round_trip_owner_only_and_environment_bound() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("mgmt").join(environment().as_str());
        let store = WindowsDpapiMgmt::in_dir(&dir, &environment());
        assert_eq!(
            store.kind(),
            MgmtStoreKind::Product(StoreKind::WindowsDpapi)
        );
        assert_eq!(store.availability(), MgmtStoreAvailability::Available);
        assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::NotFound));
        assert_eq!(store.destroy(), Err(MgmtStoreError::NotFound));

        let key = MgmtKey::generate().unwrap();
        store.put(&key).unwrap();
        assert_eq!(
            store.put(&MgmtKey::generate().unwrap()),
            Err(MgmtStoreError::AlreadyExists)
        );
        assert_eq!(
            store.load().unwrap().public().unwrap(),
            key.public().unwrap()
        );

        let blob = std::fs::read(store.blob_path()).unwrap();
        let secret = key.to_store_bytes();
        assert!(!blob.windows(secret.len()).any(|w| w == secret.as_slice()));
        assert_eq!(
            WindowsDpapiMgmt::dacl_sddl(&store.blob_path()).unwrap(),
            WindowsDpapiMgmt::expected_blob_dacl().unwrap()
        );

        // The entropy is bound to the environment ID: another installation's store over
        // the same blob cannot read it.
        let other_env = EnvironmentId::from_random_bytes([7; 16]);
        let other = WindowsDpapiMgmt::in_dir(&dir, &other_env);
        assert_eq!(other.load().map(|_| ()), Err(MgmtStoreError::Corrupt));

        store.destroy().unwrap();
        assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::NotFound));
    }
}
