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
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};

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

    /// ⟨M06-W2-R04⟩ The store directory itself, never what a reparse point names: an
    /// existing entry must be a plain directory ([`dir_state`]); a symlink, junction or
    /// any other reparse point there is refused.
    fn ensure_dir(&self) -> Result<(), MgmtStoreError> {
        match dir_state(&self.dir) {
            DirState::Plain => return Ok(()),
            DirState::Refused => return Err(MgmtStoreError::Failed),
            DirState::Absent => {}
        }
        if let Some(parent) = self.dir.parent() {
            std::fs::create_dir_all(parent).map_err(|_| MgmtStoreError::Failed)?;
        }
        match sys::create_owner_only_dir(&self.dir) {
            Ok(()) => Ok(()),
            Err(e)
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    && dir_state(&self.dir) == DirState::Plain =>
            {
                Ok(())
            }
            Err(_) => Err(MgmtStoreError::Failed),
        }
    }
}

/// What is at a store directory's path, read without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirState {
    /// A directory that is not a reparse point.
    Plain,
    /// Nothing.
    Absent,
    /// Anything else: a file, a symlink, a junction, another reparse point, or an entry
    /// that cannot be read.
    Refused,
}

/// ⟨M06-W2-R04⟩ [`DirState`] of `dir` (`symlink_metadata`: the entry itself).
pub(crate) fn dir_state(dir: &Path) -> DirState {
    use std::os::windows::fs::MetadataExt as _;
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 => {
            DirState::Plain
        }
        Ok(_) => DirState::Refused,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DirState::Absent,
        Err(_) => DirState::Refused,
    }
}

/// Why a blob was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobOpenError {
    /// No entry at the path.
    NotFound,
    /// The entry is not a regular file: a reparse point (never followed), a directory.
    NotRegular,
    /// Any other failure.
    Failed,
}

/// ⟨M06-W2-R04⟩ Open a sealed blob for reading: the entry itself
/// (`FILE_FLAG_OPEN_REPARSE_POINT`, so a symlink or junction at the name is opened as the
/// link, not its target), which must be a regular file and not a reparse point, judged on
/// the opened handle.
pub(crate) fn open_blob(path: &Path) -> Result<std::fs::File, BlobOpenError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BlobOpenError::NotFound
            } else {
                BlobOpenError::Failed
            }
        })?;
    let meta = file.metadata().map_err(|_| BlobOpenError::Failed)?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(BlobOpenError::NotRegular);
    }
    Ok(file)
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
        // ⟨M06-W2-R04⟩ The directory and the blob themselves, never through a link.
        if dir_state(&self.dir) == DirState::Refused {
            return Err(MgmtStoreError::Failed);
        }
        let file = match open_blob(&self.blob_path()) {
            Ok(f) => f,
            Err(BlobOpenError::NotFound) => return Err(MgmtStoreError::NotFound),
            Err(BlobOpenError::NotRegular) => return Err(MgmtStoreError::Corrupt),
            Err(BlobOpenError::Failed) => return Err(MgmtStoreError::Failed),
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

    /// ⟨M06-W2-R04⟩ Fixture/mechanism evidence only (scratch directories; run only on
    /// native Windows, compile-checked elsewhere): a blob path that is not a regular file
    /// is `Corrupt`, a store path that is not a plain directory is refused, and, where
    /// this account may create symbolic links, neither a linked store directory nor a
    /// linked blob is followed.
    #[test]
    fn reparse_points_and_non_regular_entries_are_never_followed() {
        let scratch = tempfile::tempdir().unwrap();
        let key = MgmtKey::generate().unwrap();
        // A real store elsewhere, holding a valid blob for the same environment.
        let real = scratch.path().join("real");
        WindowsDpapiMgmt::in_dir(&real, &environment())
            .put(&key)
            .unwrap();
        // A directory where the blob should be.
        let odd = scratch.path().join("odd");
        std::fs::create_dir_all(odd.join(BLOB_FILE)).unwrap();
        let store = WindowsDpapiMgmt::in_dir(&odd, &environment());
        assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::Corrupt));
        // A file where the store directory should be.
        let file = scratch.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(dir_state(&file), DirState::Refused);
        assert_eq!(dir_state(&real), DirState::Plain);
        assert_eq!(dir_state(&scratch.path().join("absent")), DirState::Absent);
        // Links, where the account may create them (developer mode or the privilege).
        let linked_dir = scratch.path().join("linked");
        if std::os::windows::fs::symlink_dir(&real, &linked_dir).is_ok() {
            let store = WindowsDpapiMgmt::in_dir(&linked_dir, &environment());
            assert_eq!(dir_state(&linked_dir), DirState::Refused);
            assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::Failed));
            assert_eq!(store.ensure_dir(), Err(MgmtStoreError::Failed));
        }
        let via = scratch.path().join("via");
        std::fs::create_dir(&via).unwrap();
        if std::os::windows::fs::symlink_file(real.join(BLOB_FILE), via.join(BLOB_FILE)).is_ok() {
            let store = WindowsDpapiMgmt::in_dir(&via, &environment());
            assert_eq!(store.load().map(|_| ()), Err(MgmtStoreError::Corrupt));
        }
    }
}
